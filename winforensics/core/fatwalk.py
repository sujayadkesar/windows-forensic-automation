"""Minimal FAT12/16/32 directory walker that also returns *deleted* entries.

dissect.fat only exposes allocated entries; for removable media investigations
deleted directory entries (0xE5) and their long file names matter, so this walker
parses the directory structures itself.  Deleted files are assumed contiguous from
their first cluster (classic FAT recovery heuristic).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class FatEntry:
    path: str
    name: str
    short_name: str
    is_dir: bool
    deleted: bool
    size: int
    first_cluster: int
    attrs: int
    created: datetime | None
    modified: datetime | None
    accessed: datetime | None
    clusters: list[tuple[int, int]] = field(default_factory=list)  # [(first cluster, count)]
    dirent_offset: int = 0  # byte offset of the 8.3 entry inside the volume


def _dos_dt(date: int, time: int = 0, tenth: int = 0) -> datetime | None:
    if not date:
        return None
    try:
        return datetime(1980 + (date >> 9), (date >> 5) & 0xF, date & 0x1F, time >> 11, (time >> 5) & 0x3F,
                        min(59, (time & 0x1F) * 2 + tenth // 100), (tenth % 100) * 10000)
    except ValueError:
        return None


class FatVolume:
    def __init__(self, fh, size: int):
        self.fh = fh
        self.size = size
        fh.seek(0)
        bs = fh.read(512)
        self.bps, self.spc, self.reserved, self.nfats, self.root_entries, tot16, _media, fatsz16 = struct.unpack_from(
            "<HBHBHHBH", bs, 11)
        tot32 = struct.unpack_from("<I", bs, 32)[0]
        fatsz32 = struct.unpack_from("<I", bs, 36)[0]
        self.fat_size = fatsz16 or fatsz32
        self.total_sectors = tot16 or tot32
        self.root_dir_sectors = ((self.root_entries * 32) + (self.bps - 1)) // self.bps if self.bps else 0
        self.first_data_sector = self.reserved + self.nfats * self.fat_size + self.root_dir_sectors
        data_sectors = self.total_sectors - self.first_data_sector
        self.cluster_count = data_sectors // self.spc if self.spc else 0
        if self.cluster_count < 4085:
            self.fat_type = 12
        elif self.cluster_count < 65525:
            self.fat_type = 16
        else:
            self.fat_type = 32
        self.root_cluster = struct.unpack_from("<I", bs, 44)[0] if self.fat_type == 32 else 0
        self.cluster_size = self.bps * self.spc
        if self.fat_type == 32:
            self.serial = struct.unpack_from("<I", bs, 67)[0]
            self.label = bs[71:82].decode("ascii", "replace").strip()
        else:
            self.serial = struct.unpack_from("<I", bs, 39)[0]
            self.label = bs[43:54].decode("ascii", "replace").strip()
        fh.seek(self.reserved * self.bps)
        self.fat = fh.read(self.fat_size * self.bps)

    # -------------------------------------------------------------- cluster helpers
    def cluster_offset(self, cluster: int) -> int:
        return (self.first_data_sector + (cluster - 2) * self.spc) * self.bps

    def next_cluster(self, c: int) -> int:
        if self.fat_type == 32:
            return struct.unpack_from("<I", self.fat, c * 4)[0] & 0x0FFFFFFF if c * 4 + 4 <= len(self.fat) else 0x0FFFFFFF
        if self.fat_type == 16:
            return struct.unpack_from("<H", self.fat, c * 2)[0] if c * 2 + 2 <= len(self.fat) else 0xFFFF
        off = c + c // 2
        if off + 2 > len(self.fat):
            return 0xFFF
        v = struct.unpack_from("<H", self.fat, off)[0]
        return (v >> 4) if c & 1 else (v & 0xFFF)

    def is_eoc(self, c: int) -> bool:
        return c >= {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.fat_type] or c < 2

    def is_free(self, c: int) -> bool:
        return self.next_cluster(c) == 0

    def chain(self, first: int, limit: int = 10_000_000) -> list[int]:
        out, c = [], first
        seen = set()
        while 2 <= c < self.cluster_count + 2 and c not in seen and len(out) < limit:
            out.append(c)
            seen.add(c)
            n = self.next_cluster(c)
            if self.is_eoc(n) or n == 0:
                break
            c = n
        return out

    @staticmethod
    def runs(clusters: list[int]) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for c in clusters:
            if out and out[-1][0] + out[-1][1] == c:
                out[-1] = (out[-1][0], out[-1][1] + 1)
            else:
                out.append((c, 1))
        return out

    def read_clusters(self, clusters: list[int]) -> bytes:
        parts = []
        for start, cnt in self.runs(clusters):
            self.fh.seek(self.cluster_offset(start))
            parts.append(self.fh.read(cnt * self.cluster_size))
        return b"".join(parts)

    # -------------------------------------------------------------- directory walking
    def walk(self, max_entries: int = 2_000_000):
        out: list[FatEntry] = []
        if self.fat_type == 32:
            root_clusters = self.chain(self.root_cluster)
            root = [(self.cluster_offset(s), cnt * self.cluster_size) for s, cnt in self.runs(root_clusters)]
        else:
            off = (self.reserved + self.nfats * self.fat_size) * self.bps
            root = [(off, self.root_dir_sectors * self.bps)]
        stack = [("", root, False)]
        visited = set()
        while stack and len(out) < max_entries:
            prefix, extents, parent_deleted = stack.pop()
            for ent in self._parse_dir(prefix, extents, parent_deleted):
                out.append(ent)
                if ent.is_dir and ent.name not in (".", "..") and ent.first_cluster >= 2 and ent.first_cluster not in visited:
                    visited.add(ent.first_cluster)
                    if ent.deleted:
                        clusters = [ent.first_cluster]
                    else:
                        clusters = self.chain(ent.first_cluster, 65536)
                    ext = [(self.cluster_offset(s), cnt * self.cluster_size) for s, cnt in self.runs(clusters)]
                    stack.append((ent.path, ext, ent.deleted))
        return out

    def _parse_dir(self, prefix: str, extents, parent_deleted: bool):
        lfn_parts: list[tuple[int, str]] = []
        for base, length in extents:
            self.fh.seek(base)
            data = self.fh.read(length)
            for i in range(0, len(data) - 31, 32):
                e = data[i:i + 32]
                first = e[0]
                if first == 0x00:
                    lfn_parts = []
                    # end-of-directory marker; deleted entries may still follow in slack - keep scanning a little
                    continue
                attr = e[11]
                if attr == 0x0F:
                    seq = e[0]
                    name = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "replace")
                    name = name.split("\x00")[0].replace("￿", "")
                    lfn_parts.append((seq & 0x1F if seq != 0xE5 else 0, name))
                    continue
                if attr & 0x08 and not attr & 0x10:  # volume label
                    lfn_parts = []
                    continue
                deleted = first == 0xE5
                short = e[0:8].decode("ascii", "replace").rstrip()
                ext = e[8:11].decode("ascii", "replace").rstrip()
                if deleted:
                    short = "_" + short[1:]
                if first == 0x05:
                    short = "\xe5" + short[1:]
                short_name = short + ("." + ext if ext else "")
                long_name = ""
                if lfn_parts:
                    if all(seq for seq, _ in lfn_parts):
                        long_name = "".join(p for _, p in sorted(lfn_parts, key=lambda x: x[0]))
                    else:  # deleted LFN entries lose their sequence numbers - they are stored in reverse order
                        long_name = "".join(p for _, p in reversed(lfn_parts))
                lfn_parts = []
                name = long_name or short_name
                if name in (".", ".."):
                    continue
                ctime_tenth, ctime, cdate, adate, hi, mtime, mdate, lo, size = struct.unpack_from("<BHHHHHHHI", e, 13)
                cluster = (hi << 16 | lo) if self.fat_type == 32 else lo
                is_dir = bool(attr & 0x10)
                if not (0 <= cluster < self.cluster_count + 2):
                    continue
                if deleted and not name.strip("_ "):
                    continue
                ent = FatEntry(path=f"{prefix}\\{name}", name=name, short_name=short_name, is_dir=is_dir,
                               deleted=deleted or parent_deleted, size=0 if is_dir else size, first_cluster=cluster,
                               attrs=attr, created=_dos_dt(cdate, ctime, ctime_tenth), modified=_dos_dt(mdate, mtime),
                               accessed=_dos_dt(adate), dirent_offset=base + i)
                if not is_dir and cluster >= 2 and size:
                    need = (size + self.cluster_size - 1) // self.cluster_size
                    if deleted:
                        ent.clusters = [(cluster, need)]
                    else:
                        ent.clusters = self.runs(self.chain(cluster, need + 1)[:need])
                elif is_dir and cluster >= 2 and not deleted:
                    ent.clusters = self.runs(self.chain(cluster, 65536))
                yield ent
