"""Attribute a byte offset inside a volume to a file, file slack, unallocated space or file system metadata.

Built from the run map written by the file system indexer, the volume allocation
bitmap ($Bitmap / FAT) and the fs_entries table.
"""

from __future__ import annotations

import os
import struct
from array import array
from bisect import bisect_right

RUN_FMT = struct.Struct("<qqqqqB")
KIND_DATA, KIND_ADS, KIND_INDEX, KIND_OTHER = 0, 1, 2, 3
SPECIAL_NTFS = {0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume", 4: "$AttrDef", 6: "$Bitmap", 7: "$Boot", 8: "$BadClus",
                9: "$Secure", 10: "$UpCase", 11: "$Extend"}

AREA_FILE = "Allocated file"
AREA_SLACK = "File slack"
AREA_UNALLOC = "Unallocated space"
AREA_DELETED = "Unallocated (deleted file remnant)"
AREA_MFT = "MFT record (resident data / metadata)"
AREA_LOGFILE = "$LogFile (NTFS transaction log)"
AREA_USN = "$UsnJrnl (change journal)"
AREA_INDEX = "$I30 directory index (incl. index slack)"
AREA_PAGEFILE = "pagefile.sys"
AREA_HIBERFIL = "hiberfil.sys"
AREA_SWAPFILE = "swapfile.sys"
AREA_VSS = "Volume Shadow Copy store"
AREA_META = "File system metadata"
AREA_UNPART = "Unpartitioned disk space"
AREA_FAT_META = "FAT reserved / FAT tables / root directory"

MEMORY_FILES = {"pagefile.sys": AREA_PAGEFILE, "hiberfil.sys": AREA_HIBERFIL, "swapfile.sys": AREA_SWAPFILE}


class _Runs:
    def __init__(self):
        self.lcn = array("q")
        self.length = array("q")
        self.rec = array("q")
        self.vcn = array("q")
        self.size = array("q")
        self.kind = array("b")

    def build(self, rows: list[tuple]):
        rows.sort(key=lambda r: r[0])
        for lcn, ln, rec, vcn, size, kind in rows:
            self.lcn.append(lcn)
            self.length.append(ln)
            self.rec.append(rec)
            self.vcn.append(vcn)
            self.size.append(size)
            self.kind.append(kind)

    def find(self, cluster: int):
        i = bisect_right(self.lcn, cluster) - 1
        # a few overlapping / adjacent runs can precede - walk back a little
        for j in range(i, max(-1, i - 8), -1):
            if self.lcn[j] <= cluster < self.lcn[j] + self.length[j]:
                return j
        return None


class ClusterMap:
    def __init__(self, ctx, vol_row: dict, vol):
        self.ctx = ctx
        self.vol_row = vol_row
        self.vol = vol
        self.name = vol_row["name"]
        self.fs = (vol_row.get("fs") or "").upper()
        self.cs = vol_row.get("cluster_size") or 4096
        info = vol_row.get("info") or {}
        self.record_size = info.get("record_size", 1024)
        self.first_data = info.get("first_data_offset", 0)
        self.alloc = _Runs()
        self.deleted = _Runs()
        self.records: dict[int, dict] = {}
        self.bitmap: bytes | None = None
        self.fat = None
        self._load()

    # ------------------------------------------------------------------ loading
    def _load(self):
        deleted_recs = set()
        special = {}
        for r in self.ctx.db.iquery("SELECT record, name, path, deleted, size, is_dir FROM fs_entries WHERE evidence_id=? AND volume=?",
                                    (self.ctx.evidence_id, self.name)):
            if r["deleted"]:
                deleted_recs.add(r["record"])
            low = (r["name"] or "").lower()
            if (r["path"] or "").count("\\") == 1 and low in MEMORY_FILES:
                special[r["record"]] = MEMORY_FILES[low]
            elif low == "$usnjrnl":
                special[r["record"]] = AREA_USN
            elif "\\system volume information\\" in (r["path"] or "").lower() and "{3808876b-c176-4e48-b7ae-04046e6cc752}" in low:
                special[r["record"]] = AREA_VSS
        self.special = special
        self.deleted_recs = deleted_recs
        alloc_rows, del_rows = [], []
        path = self.vol_row.get("runs_file")
        if path and os.path.exists(path):
            with open(path, "rb") as fh:
                data = fh.read()
            for t in RUN_FMT.iter_unpack(data[: len(data) - len(data) % RUN_FMT.size]):
                (del_rows if t[2] in deleted_recs else alloc_rows).append(t)
        self.alloc.build(alloc_rows)
        self.deleted.build(del_rows)
        try:
            if self.fs == "NTFS":
                self.bitmap = self.vol.fs.ntfs.mft.get(6).open().read()
            elif self.fs.startswith("FAT"):
                from ..core.fatwalk import FatVolume

                self.vol.seek(0)
                self.fat = FatVolume(self.vol, self.vol.size)
                self.first_data = self.fat.first_data_sector * self.fat.bps
                self.cs = self.fat.cluster_size
        except Exception:
            self.bitmap = None

    def is_allocated(self, cluster: int) -> bool | None:
        if self.bitmap is not None:
            byte = cluster >> 3
            if byte >= len(self.bitmap):
                return None
            return bool(self.bitmap[byte] & (1 << (cluster & 7)))
        if self.fat is not None:
            if cluster < 2 or cluster >= self.fat.cluster_count + 2:
                return None
            return not self.fat.is_free(cluster)
        return None

    def unallocated_ranges(self):
        """Yield (byte offset, length) of unallocated cluster ranges (used by the carver)."""
        if self.bitmap is not None:
            import re

            total = self.vol.size // self.cs
            bm = self.bitmap
            pending = None  # (start cluster, end cluster)
            for m in re.finditer(rb"[^\xff]+", bm):
                c0, c1 = m.start() * 8, m.end() * 8
                # refine the edges bit by bit, the middle bytes may still contain allocated bits
                c = c0
                while c < min(c1, total):
                    b = bm[c >> 3]
                    if b == 0 and (c & 7) == 0 and c + 8 <= c1:
                        free, step = True, 8
                    elif b == 0xFF and (c & 7) == 0:
                        free, step = False, 8
                    else:
                        free, step = not (b & (1 << (c & 7))), 1
                    if free:
                        if pending and pending[1] == c:
                            pending = (pending[0], c + step)
                        else:
                            if pending:
                                yield pending[0] * self.cs, (pending[1] - pending[0]) * self.cs
                            pending = (c, c + step)
                    c += step
            if pending:
                end = min(pending[1], total)
                if end > pending[0]:
                    yield pending[0] * self.cs, (end - pending[0]) * self.cs
        elif self.fat is not None:
            start = None
            last = self.fat.cluster_count + 2
            for c in range(2, last):
                free = self.fat.is_free(c)
                if free and start is None:
                    start = c
                elif not free and start is not None:
                    yield self.first_data + (start - 2) * self.cs, (c - start) * self.cs
                    start = None
            if start is not None:
                yield self.first_data + (start - 2) * self.cs, (last - start) * self.cs

    # ------------------------------------------------------------------ classification
    def classify(self, offset: int) -> dict:
        """Area + attribution for a volume relative byte offset."""
        if self.fs.startswith("FAT"):
            if offset < self.first_data:
                return {"area": AREA_FAT_META}
            cluster = (offset - self.first_data) // self.cs + 2
            in_cluster = (offset - self.first_data) % self.cs
        else:
            cluster = offset // self.cs
            in_cluster = offset % self.cs
        j = self.alloc.find(cluster)
        if j is not None:
            rec = self.alloc.rec[j]
            file_off = (self.alloc.vcn[j] + (cluster - self.alloc.lcn[j])) * self.cs + in_cluster
            kind = self.alloc.kind[j]
            size = self.alloc.size[j]
            out = {"record": rec, "file_offset": file_off}
            if self.fs == "NTFS" and rec in SPECIAL_NTFS:
                if rec == 0:
                    out["area"] = AREA_MFT
                    out["mft_record"] = file_off // self.record_size
                elif rec == 2:
                    out["area"] = AREA_LOGFILE
                else:
                    out["area"] = f"{AREA_META} ({SPECIAL_NTFS[rec]})"
                return out
            if rec in self.special:
                out["area"] = self.special[rec]
                return out
            if kind == KIND_INDEX:
                out["area"] = AREA_INDEX
            elif kind == KIND_OTHER:
                out["area"] = AREA_META
            elif size and file_off >= size:
                out["area"] = AREA_SLACK
            else:
                out["area"] = AREA_FILE if kind == KIND_DATA else AREA_FILE + " (alternate data stream)"
            return out
        alloc = self.is_allocated(cluster)
        j = self.deleted.find(cluster)
        if j is not None and alloc is not True:
            rec = self.deleted.rec[j]
            file_off = (self.deleted.vcn[j] + (cluster - self.deleted.lcn[j])) * self.cs + in_cluster
            return {"area": AREA_DELETED, "record": rec, "file_offset": file_off, "deleted": True}
        if alloc is False:
            return {"area": AREA_UNALLOC}
        if alloc is True:
            return {"area": AREA_META + " (allocated, unattributed)"}
        return {"area": AREA_UNALLOC if self.fs.startswith("FAT") else AREA_META}

    def describe_record(self, rec: int) -> dict:
        if rec in self.records:
            return self.records[rec]
        r = self.ctx.db.query("SELECT path, name, deleted, size, si_created, si_modified FROM fs_entries WHERE evidence_id=? AND volume=? "
                              "AND record=? LIMIT 1", (self.ctx.evidence_id, self.name, rec))
        d = r[0] if r else {"path": f"\\<record {rec}>", "name": "", "deleted": 0}
        self.records[rec] = d
        return d
