"""File system index.

For every volume of the evidence:

* NTFS - every MFT record (allocated **and deleted**), $STANDARD_INFORMATION and
  $FILE_NAME timestamps, alternate data streams (Zone.Identifier download origin),
  copy / timestomp indicators, the $UsnJrnl:$J change journal, and a cluster run map
  used later by the raw search engine to attribute hits to files, slack or
  unallocated space.
* FAT12/16/32 - full directory walk including deleted entries (long names recovered).
* Other file systems - allocated entries via dissect.

Everything lands in the ``fs_entries`` / ``usn`` / ``volumes`` tables.
"""

from __future__ import annotations

import bisect
import os
import struct
from datetime import datetime, timedelta

from ..core.fatwalk import FatVolume
from ..core.timeutil import UTC, db_ts, get_tz
from ..knowledge import document_extensions, executable_extensions
from .base import ArtifactModule, ArtifactType, C, register

RUN_FMT = struct.Struct("<qqqqqB")  # lcn, length, record, vcn, data_size, kind
KIND_DATA, KIND_ADS, KIND_INDEX, KIND_OTHER = 0, 1, 2, 3
FILE_ATTR = {0x1: "readonly", 0x2: "hidden", 0x4: "system", 0x20: "archive", 0x100: "temporary", 0x200: "sparse",
             0x400: "reparse", 0x800: "compressed", 0x1000: "offline", 0x2000: "not_indexed", 0x4000: "encrypted",
             0x400000: "recall_on_access", 0x40000: "pinned", 0x80000: "unpinned"}
USN_REASONS = [(0x1, "DataOverwrite"), (0x2, "DataExtend"), (0x4, "DataTruncation"), (0x10, "NamedDataOverwrite"),
               (0x20, "NamedDataExtend"), (0x40, "NamedDataTruncation"), (0x100, "FileCreate"), (0x200, "FileDelete"),
               (0x400, "EaChange"), (0x800, "SecurityChange"), (0x1000, "RenameOldName"), (0x2000, "RenameNewName"),
               (0x4000, "IndexableChange"), (0x8000, "BasicInfoChange"), (0x10000, "HardLinkChange"),
               (0x20000, "CompressionChange"), (0x40000, "EncryptionChange"), (0x80000, "ObjectIdChange"),
               (0x100000, "ReparsePointChange"), (0x200000, "StreamChange"), (0x400000, "TransactedChange"),
               (0x800000, "IntegrityChange"), (0x80000000, "Close")]
STD_ADS = {"zone.identifier", "smartscreen", "$dsc", "ms-properties", "wofcompresseddata", "encryptable",
           "favicon", "afp_afpinfo", "afp_resource", "com.dropbox.attrs", "com.dropbox.attributes", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
           "$kernel.purge.esbcache", "$kernel.purge.apprepcache", "$kernel.purge.cipcache", "sec.endpointdlp", "ofbkspec"}


def usn_reason_text(v: int) -> str:
    return "|".join(n for b, n in USN_REASONS if v & b)


def _ref(r) -> tuple[int, int]:
    try:
        return (r.SegmentNumberLowPart | (r.SegmentNumberHighPart << 32)), r.SequenceNumber
    except AttributeError:
        v = int(r)
        return v & 0xFFFFFFFFFFFF, v >> 48


@register
class FilesystemModule(ArtifactModule):
    id = "filesystem"
    title = "File system index (MFT / FAT / USN)"
    category = "File System"
    description = ("Indexes every file record including deleted ones, alternate data streams (download origin), "
                   "timestamp anomalies, the USN change journal and a cluster map for slack/unallocated attribution.")
    weight = 6.0
    order = 10
    windows_only = False
    locations = ["$MFT (all records)", "$UsnJrnl:$J", "Alternate data streams (Zone.Identifier)", "FAT directory entries (incl. deleted)"]
    artifact_types = [
        ArtifactType("volume_info", "Volumes", "File System",
                     [C("volume"), C("fs", "File System"), C("label"), C("serial"), C("size", kind="size"),
                      C("cluster_size", kind="int"), C("files", kind="int"), C("deleted_files", "Deleted", "int"),
                      C("offset", kind="int"), C("notes", width=300)]),
        ArtifactType("zone_identifier", "Downloaded Files (Zone.Identifier)", "Browser Activity",
                     [C("file", kind="path", width=420), C("zone"), C("host_url", "Host URL", "url", 380),
                      C("referrer_url", "Referrer URL", "url", 300), C("created", "File Created", "datetime"),
                      C("deleted"), C("app")], ts_label="File created",
                     description="Mark-of-the-Web streams record where a file was downloaded / saved from."),
        ArtifactType("ads", "Alternate Data Streams (non-standard)", "File System",
                     [C("file", kind="path", width=420), C("stream"), C("size", kind="size"), C("preview", width=300)]),
        ArtifactType("timestamp_anomaly", "Timestamp Anomalies (timestomp indicators)", "Anti-Forensics",
                     [C("file", kind="path", width=420), C("anomaly", width=300), C("si_created", "$SI Created", "datetime"),
                      C("fn_created", "$FN Created", "datetime"), C("si_modified", "$SI Modified", "datetime"),
                      C("fn_modified", "$FN Modified", "datetime")], ts_label="$SI created"),
        ArtifactType("usn_summary", "USN Journal", "File System",
                     [C("volume"), C("records", kind="int"), C("first", kind="datetime"), C("last", kind="datetime"),
                      C("creates", kind="int"), C("deletes", kind="int"), C("renames", kind="int")]),
    ]

    def estimate(self, ctx) -> float:
        total = 0
        for vol in ctx.target.volumes:
            fs = getattr(vol, "fs", None)
            if getattr(fs, "__type__", "") == "ntfs":
                try:
                    total += fs.ntfs.mft.get(0).size() // 1024
                except Exception:
                    total += 100_000
            elif fs is not None:
                total += 5000
        ctx.cache["fs_record_estimate"] = total
        return 1.0 + total / 25_000

    def run(self, ctx) -> None:
        t = ctx.target
        letters = {}
        try:
            for name, fs in t.fs.mounts.items():
                if len(name) == 2 and name[1] == ":":
                    letters[id(fs)] = name.upper()
        except Exception:
            pass
        vols = [v for v in t.volumes]
        est_total = max(1, ctx.cache.get("fs_record_estimate") or 1)
        self.done_records = 0
        self.est_total = est_total
        fat_tz_name = ctx.options.get("fat_timezone") or (ctx.evidence.get("options") or {}).get("fat_timezone")
        self.fat_tz = get_tz(fat_tz_name) if fat_tz_name else (ctx.evidence_tz or UTC)
        any_fs = False
        for idx, vol in enumerate(vols):
            fs = getattr(vol, "fs", None)
            vname = letters.get(id(fs)) if fs is not None else None
            vname = vname or f"Vol{getattr(vol, 'number', idx + 1) or idx + 1}"
            fstype = getattr(fs, "__type__", None) if fs is not None else None
            try:
                if fstype == "ntfs":
                    any_fs = True
                    self._ntfs(ctx, vol, vname)
                elif fstype == "fat":
                    any_fs = True
                    self._fat(ctx, vol, vname)
                elif fs is not None:
                    any_fs = True
                    self._generic(ctx, vol, vname, fstype)
                else:
                    head = b""
                    try:
                        vol.seek(0)
                        head = vol.read(16)
                    except Exception:
                        pass
                    note = "BitLocker encrypted (no key supplied)" if head[3:11] == b"-FVE-FS-" else "no recognized file system"
                    ctx.db.add_volume(ctx.evidence_id, name=vname, number=getattr(vol, "number", None), offset=vol.offset,
                                      size=vol.size, fs=None, info={"note": note})
                    ctx.emit("volume_info", None, {"volume": vname, "fs": "-", "size": vol.size, "offset": vol.offset,
                                                   "notes": note}, summary=f"{vname}: {note}", source="partition table")
            except Exception as e:
                ctx.error(f"filesystem index {vname}: {e}")
                ctx.coverage("File system index", vname, "error", 0, str(e)[:200])
        ctx.flush()
        if not any_fs:
            ctx.coverage("File system index", "all volumes", "not_found", 0, "no readable file system")

    # ------------------------------------------------------------------ NTFS
    def _ntfs(self, ctx, vol, vname: str) -> None:
        ntfs = vol.fs.ntfs
        mft = ntfs.mft
        cs = ntfs.cluster_size
        try:
            nrec = max(1, mft.get(0).size() // ntfs._record_size)
        except Exception:
            nrec = 1
        runs_path = ctx.case.sub("temp", f"E{ctx.evidence_id:02d}_{vname.replace(':', '')}_runs.bin")
        runs_fh = open(runs_path, "wb")
        names: dict[int, tuple[int, int, str, bool]] = {}  # seg -> (parent, parent_seq, name, is_dir)
        seqs: dict[int, int] = {}
        inuse_map: dict[int, bool] = {}
        files = deleted_files = 0
        zone, ads_list, anomalies = [], [], []
        rows_batch: list[tuple] = []
        for rec in self._iter_records(mft, nrec):
            self.done_records += 1
            if self.done_records % 5000 == 0:
                ctx.progress(min(0.95, self.done_records / self.est_total), f"{vname}: MFT record {rec.segment:,} / {nrec:,}")
            try:
                hdr = rec.header
                if hdr is None:
                    continue
                base_seg, _ = _ref(hdr.BaseFileRecordSegment)
                if base_seg:
                    continue  # extension record
                inuse = bool(hdr.Flags & 1)
                is_dir = bool(hdr.Flags & 2)
                attrs = rec.attributes
            except Exception:
                continue
            seg = rec.segment
            seqs[seg] = hdr.SequenceNumber
            inuse_map[seg] = inuse
            fn_attr = None
            fn_best = None
            for a in attrs.get(0x30, []) or []:
                try:
                    fa = a.attribute
                    ns = fa.attr.Flags
                except Exception:
                    continue
                if fn_best is None or ns in (1, 3) or (ns == 0 and fn_best.attr.Flags == 2):
                    fn_best = fa
            fn_attr = fn_best
            if fn_attr is None:
                continue
            name = fn_attr.attr.FileName
            parent, pseq = _ref(fn_attr.attr.ParentDirectory)
            names[seg] = (parent, pseq, name, is_dir)
            si = None
            try:
                si = attrs[0x10][0].attribute
            except Exception:
                pass
            si_t = _times(si)
            fn_t = _times(fn_attr)
            fattr = getattr(si, "file_attributes", 0) or 0 if si is not None else 0
            # data streams
            streams: dict[str, dict] = {}
            for a in attrs.get(0x80, []) or []:
                sname = a.name or ""
                st = streams.setdefault(sname, {"size": None, "resident": a.resident, "attrs": []})
                st["attrs"].append(a)
                try:
                    if a.resident:
                        st["size"] = len(a.data())
                    elif a.header.lowest_vcn == 0:
                        st["size"] = a.header.size
                except Exception:
                    pass
            main = streams.get("", {})
            size = main.get("size") or 0
            resident = bool(main.get("resident"))
            for sname, st in streams.items():
                kind = KIND_DATA if sname == "" else KIND_ADS
                for a in st["attrs"]:
                    if a.resident:
                        continue
                    try:
                        vcn = a.header.lowest_vcn or 0
                        for lcn, length in a.dataruns():
                            if lcn is not None and length:
                                runs_fh.write(RUN_FMT.pack(lcn, length, seg, vcn, st["size"] or 0, kind))
                            vcn += length
                    except Exception:
                        pass
            for at, kind in ((0xA0, KIND_INDEX), (0x100, KIND_OTHER), (0xB0, KIND_OTHER)):
                for a in attrs.get(at, []) or []:
                    if a.resident:
                        continue
                    try:
                        vcn = a.header.lowest_vcn or 0
                        dsz = a.header.size if a.header.lowest_vcn == 0 else 0
                        for lcn, length in a.dataruns():
                            if lcn is not None and length:
                                runs_fh.write(RUN_FMT.pack(lcn, length, seg, vcn, dsz or length * cs, kind))
                            vcn += length
                    except Exception:
                        pass
            ads_names = [n for n in streams if n]
            flags = [v for b, v in FILE_ATTR.items() if fattr & b]
            # anomalies / indicators
            if si_t[0] and fn_t[0] and not is_dir:
                if si_t[0] < fn_t[0] - timedelta(seconds=2):
                    flags.append("si_created_before_fn")
                    anomalies.append((seg, "$SI created earlier than $FN created (possible timestomping)", si_t, fn_t))
                elif si is not None and _zero_fraction(si) and not _zero_fraction(fn_attr) and inuse:
                    flags.append("si_zero_fraction")
                    anomalies.append((seg, "$SI timestamps have zero sub-second precision while $FN do not", si_t, fn_t))
            if si_t[0] and si_t[1] and si_t[1] < si_t[0] - timedelta(seconds=2) and not is_dir:
                flags.append("modified_before_created")  # typical of copied / extracted files
            ext = os.path.splitext(name)[1][1:].lower()[:12] if not is_dir else ""
            rows_batch.append((ctx.evidence_id, vname, seg, hdr.SequenceNumber, parent, None, name, ext, size,
                               int(is_dir), int(not inuse), db_ts(si_t[0]), db_ts(si_t[1]), db_ts(si_t[2]), db_ts(si_t[3]),
                               db_ts(fn_t[0]), db_ts(fn_t[1]), db_ts(fn_t[2]), db_ts(fn_t[3]),
                               ",".join(f"{n}:{streams[n]['size'] or 0}" for n in ads_names), int(resident), ",".join(flags)))
            if len(rows_batch) >= 10000:
                ctx.db.insert_fs(rows_batch)
                rows_batch = []
            if not is_dir:
                files += 1
                if not inuse:
                    deleted_files += 1
            for n in ads_names:
                low = n.lower()
                if low == "zone.identifier":
                    try:
                        data = _read_stream(rec, streams[n]["attrs"], n)
                        zone.append((seg, inuse, si_t[0], data))
                    except Exception:
                        pass
                elif seg >= 24 and low not in STD_ADS and not low.startswith(("{", "$kernel", "sec.endpoint", "ms-", "$")):
                    preview = ""
                    try:
                        data = _read_stream(rec, streams[n]["attrs"], n, 256)
                        preview = data[:200].decode("utf-8", "replace") if data else ""
                        if data[:2] == b"MZ":
                            preview = "[PE executable] " + preview[:40]
                    except Exception:
                        pass
                    ads_list.append((seg, n, streams[n]["size"], preview))
        if rows_batch:
            ctx.db.insert_fs(rows_batch)
        runs_fh.close()
        ctx.progress(min(0.96, self.done_records / self.est_total), f"{vname}: resolving paths")
        paths = _resolve_paths(names, seqs, inuse_map)
        # the change journal often still knows the deleted / reused parent folders: recover those paths
        usn_dirs = self._usn(ctx, ntfs, vname, paths, seqs, inuse_map)
        recovered = _recover_paths_from_usn(names, paths, usn_dirs, seqs, inuse_map)
        ctx.db.executemany(
            "UPDATE fs_entries SET path=?, flags=CASE WHEN ? THEN trim(coalesce(flags,'') || ',path_from_usn', ',') ELSE flags END "
            "WHERE evidence_id=? AND volume=? AND record=?",
            [(paths.get(seg), int(seg in recovered), ctx.evidence_id, vname, seg) for seg in names])
        full = lambda seg: f"{vname}{paths.get(seg, '')}" if vname.endswith(":") else f"[{vname}]{paths.get(seg, '')}"  # noqa: E731
        # artifacts
        for seg, inuse, created, data in zone:
            z = _parse_zone(data)
            ctx.emit("zone_identifier", created, {"file": full(seg), "zone": z.get("zone"), "zone_id": z.get("ZoneId"),
                                                  "host_url": z.get("HostUrl"), "referrer_url": z.get("ReferrerUrl"),
                                                  "app": z.get("LastWriterPackageFamilyName") or z.get("AppZoneId") or "",
                                                  "created": db_ts(created), "deleted": "" if inuse else "Yes (deleted file)",
                                                  "raw": data[:2000].decode("utf-8", "replace") if data else ""},
                     user=ctx.user_for_path(full(seg)), summary=f"Downloaded: {full(seg)} from {z.get('HostUrl') or z.get('ReferrerUrl') or z.get('zone')}",
                     source=f"{full(seg)}:Zone.Identifier", ts_label="File created")
        for seg, n, size, preview in ads_list[:5000]:
            ctx.emit("ads", None, {"file": full(seg), "stream": n, "size": size, "preview": preview},
                     summary=f"ADS {full(seg)}:{n}", source=f"{full(seg)}:{n}",
                     tags=["suspicious"] if preview.startswith("[PE") else None)
        interesting = [a for a in anomalies if _interesting_path(paths.get(a[0], ""))]
        for seg, why, si_t, fn_t in interesting[:3000]:
            ctx.emit("timestamp_anomaly", si_t[0], {"file": full(seg), "anomaly": why, "si_created": db_ts(si_t[0]),
                                                    "fn_created": db_ts(fn_t[0]), "si_modified": db_ts(si_t[1]),
                                                    "fn_modified": db_ts(fn_t[1])},
                     summary=f"{why}: {full(seg)}", source=f"$MFT record {seg}", ts_label="$SI created")
        serial = f"{ntfs.serial:016X}" if getattr(ntfs, "serial", None) else ""
        ctx.db.add_volume(ctx.evidence_id, name=vname, number=getattr(vol, "number", None), offset=vol.offset, size=vol.size,
                          fs="NTFS", label=getattr(ntfs, "volume_name", ""), serial=serial, cluster_size=cs, letter=vname
                          if vname.endswith(":") else None, runs_file=runs_path,
                          info={"records": nrec, "record_size": ntfs._record_size, "files": files, "deleted": deleted_files})
        ctx.emit("volume_info", None, {"volume": vname, "fs": "NTFS", "label": getattr(ntfs, "volume_name", ""),
                                       "serial": f"{serial[-8:-4]}-{serial[-4:]}" if serial else "", "size": vol.size,
                                       "cluster_size": cs, "files": files, "deleted_files": deleted_files, "offset": vol.offset,
                                       "notes": f"{nrec:,} MFT records"}, summary=f"{vname} NTFS '{getattr(ntfs, 'volume_name', '')}'",
                 source="NTFS boot sector / $Volume")
        ctx.coverage("MFT (incl. deleted records)", f"{vname} $MFT", "found", files, f"{deleted_files:,} deleted file records")
        ctx.coverage("Zone.Identifier streams", f"{vname} alternate data streams", "found" if zone else "not_found", len(zone))
        ctx.coverage("Timestamp anomalies", f"{vname} $SI vs $FN", "found" if interesting else "not_found", len(interesting))

    @staticmethod
    def _iter_records(mft, nrec):
        for seg in range(nrec):
            try:
                rec = mft.get(seg)
            except Exception:
                continue
            yield rec

    def _usn(self, ctx, ntfs, vname, paths, seqs, inuse) -> dict:
        """Parse $UsnJrnl:$J.  Parent folders are resolved by MFT reference *and sequence number*: when the parent record
        was reused, the folder is rebuilt from the journal's own directory records, never from the record's new owner."""
        j = getattr(ntfs, "usnjrnl", None)
        if j is None:
            ctx.coverage("USN change journal", f"{vname} $Extend\\$UsnJrnl:$J", "absent", 0, "journal not present / disabled")
            return {}
        raw, n, first, last = [], 0, None, None
        counts = {"creates": 0, "deletes": 0, "renames": 0}
        dirs: dict[tuple, list] = {}
        try:
            for r in j.records():
                n += 1
                try:
                    rec = r.record
                    seg, seq = _ref(rec.FileReferenceNumber)
                    pseg, pseq = _ref(rec.ParentFileReferenceNumber)
                    reason = int(rec.Reason)
                    ts = r.timestamp
                    usn = int(rec.Usn)
                    fattr = int(rec.FileAttributes)
                except Exception:
                    continue
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
                if reason & 0x100:
                    counts["creates"] += 1
                if reason & 0x200:
                    counts["deletes"] += 1
                if reason & 0x2000:
                    counts["renames"] += 1
                raw.append((usn, ts, seg, seq, pseg, pseq, r.filename, reason, fattr))
                if fattr & 0x10:
                    dirs.setdefault((seg, seq), []).append((usn, r.filename, pseg, pseq))
                if n % 50000 == 0:
                    ctx.progress(0.97, f"{vname}: USN journal {n:,} records")
        except Exception as e:
            ctx.warn(f"USN journal {vname}: {e}")
        for v in dirs.values():
            v.sort()
        resolver = _UsnPathResolver(paths, dirs, seqs, inuse)
        rows = []
        for usn, ts, seg, seq, pseg, pseq, name, reason, fattr in raw:
            parent_path = resolver.dir_path(pseg, pseq, usn)
            rows.append((ctx.evidence_id, vname, usn, db_ts(ts), seg, seq, pseg, name, f"{vname}{parent_path}\\{name}",
                         usn_reason_text(reason), reason, fattr))
            if len(rows) >= 20000:
                ctx.db.insert_usn(rows)
                rows = []
        if rows:
            ctx.db.insert_usn(rows)
        ctx.emit("usn_summary", last, {"volume": vname, "records": n, "first": db_ts(first), "last": db_ts(last), **counts},
                 summary=f"{vname} USN journal: {n:,} records {db_ts(first)} .. {db_ts(last)}", source=f"{vname}\\$Extend\\$UsnJrnl:$J")
        ctx.coverage("USN change journal", f"{vname} $Extend\\$UsnJrnl:$J", "found" if n else "not_found", n,
                     f"{resolver.unresolved:,} records whose parent folder could not be identified" if resolver.unresolved else "")
        return dirs

    # ------------------------------------------------------------------ FAT
    def _fat(self, ctx, vol, vname: str) -> None:
        vol.seek(0)
        fv = FatVolume(vol, vol.size)
        entries = fv.walk()
        runs_path = ctx.case.sub("temp", f"E{ctx.evidence_id:02d}_{vname.replace(':', '')}_runs.bin")
        rows = []
        files = deleted = 0
        tz = self.fat_tz
        with open(runs_path, "wb") as rfh:
            for i, e in enumerate(entries, start=1):
                def conv(dt):
                    return dt.replace(tzinfo=tz).astimezone(UTC) if dt else None

                c, m, a = conv(e.created), conv(e.modified), conv(e.accessed)
                flags = ["fat_local_time:" + getattr(tz, "key", str(tz))]
                if e.attrs & 0x02:
                    flags.append("hidden")
                if e.attrs & 0x04:
                    flags.append("system")
                if c and m and m < c - timedelta(seconds=2) and not e.is_dir:
                    flags.append("modified_before_created")
                ext = os.path.splitext(e.name)[1][1:].lower()[:12] if not e.is_dir else ""
                rows.append((ctx.evidence_id, vname, i, e.first_cluster, 0, e.path, e.name, ext, e.size, int(e.is_dir), int(e.deleted),
                             db_ts(c), db_ts(m), db_ts(a), None, None, None, None, None, "", 0, ",".join(flags)))
                vcn = 0
                for start, cnt in e.clusters:
                    rfh.write(RUN_FMT.pack(start, cnt, i, vcn, e.size, KIND_DATA if not e.is_dir else KIND_INDEX))
                    vcn += cnt
                if not e.is_dir:
                    files += 1
                    deleted += int(e.deleted)
        ctx.db.insert_fs(rows)
        serial = f"{fv.serial:08X}"
        ctx.db.add_volume(ctx.evidence_id, name=vname, number=getattr(vol, "number", None), offset=vol.offset, size=vol.size,
                          fs=f"FAT{fv.fat_type}", label=fv.label, serial=serial, cluster_size=fv.cluster_size,
                          letter=vname if vname.endswith(":") else None, runs_file=runs_path,
                          info={"first_data_offset": fv.first_data_sector * fv.bps, "cluster_count": fv.cluster_count,
                                "files": files, "deleted": deleted, "time_zone_assumed": getattr(tz, "key", str(tz))})
        ctx.emit("volume_info", None, {"volume": vname, "fs": f"FAT{fv.fat_type}", "label": fv.label,
                                       "serial": f"{serial[:4]}-{serial[4:]}", "size": vol.size, "cluster_size": fv.cluster_size,
                                       "files": files, "deleted_files": deleted, "offset": vol.offset,
                                       "notes": f"FAT times are local; interpreted as {getattr(tz, 'key', tz)}"},
                 summary=f"{vname} FAT{fv.fat_type} '{fv.label}' VSN {serial[:4]}-{serial[4:]}", source="FAT boot sector")
        ctx.coverage("FAT directory entries (incl. deleted)", f"{vname} FAT{fv.fat_type}", "found" if files else "not_found",
                     files, f"{deleted} deleted entries")

    # ------------------------------------------------------------------ others
    def _generic(self, ctx, vol, vname: str, fstype: str) -> None:
        rows = []
        n = 0
        try:
            root = vol.fs.path("/")
            for p in root.rglob("*"):
                n += 1
                try:
                    st = p.lstat()
                    is_dir = p.is_dir()
                    mt = datetime.fromtimestamp(st.st_mtime, UTC) if st.st_mtime else None
                except Exception:
                    st, is_dir, mt = None, False, None
                path = "\\" + str(p).lstrip("/").replace("/", "\\")
                ext = os.path.splitext(p.name)[1][1:].lower()[:12] if not is_dir else ""
                rows.append((ctx.evidence_id, vname, n, 0, 0, path, p.name, ext, getattr(st, "st_size", 0) or 0, int(is_dir), 0,
                             None, db_ts(mt), None, None, None, None, None, None, "", 0, fstype))
                if len(rows) >= 5000:
                    ctx.db.insert_fs(rows)
                    rows = []
                if n > 2_000_000:
                    break
        except Exception as e:
            ctx.warn(f"walk {vname}: {e}")
        if rows:
            ctx.db.insert_fs(rows)
        ctx.db.add_volume(ctx.evidence_id, name=vname, number=getattr(vol, "number", None), offset=vol.offset, size=vol.size,
                          fs=fstype, info={"files": n})
        ctx.emit("volume_info", None, {"volume": vname, "fs": fstype, "size": vol.size, "files": n, "offset": vol.offset,
                                       "notes": "allocated entries only"}, summary=f"{vname} {fstype}", source="volume")
        ctx.coverage("File system entries", f"{vname} {fstype}", "found" if n else "not_found", n, "allocated entries only")


# ---------------------------------------------------------------------- helpers
def _times(a):
    if a is None:
        return (None, None, None, None)
    out = []
    for attr in ("creation_time", "last_modification_time", "last_access_time", "last_change_time"):
        try:
            out.append(getattr(a, attr))
        except Exception:
            out.append(None)
    return tuple(out)


def _zero_fraction(a) -> bool:
    try:
        return all(getattr(a, f).microsecond == 0 for f in ("creation_time", "last_modification_time"))
    except Exception:
        return False


def _read_stream(rec, attrs, name: str, limit: int | None = None) -> bytes:
    a = attrs[0]
    if a.resident:
        d = a.data()
        return d[:limit] if limit else d
    fh = rec.open(name)
    return fh.read(limit or 65536)


def _parse_zone(data: bytes) -> dict:
    out = {}
    text = data.decode("utf-8", "replace") if data else ""
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    zid = out.get("ZoneId")
    out["zone"] = {"0": "0 - Local machine", "1": "1 - Local intranet", "2": "2 - Trusted sites", "3": "3 - Internet",
                   "4": "4 - Restricted sites"}.get(zid, zid or "")
    return out


def _interesting_path(path: str) -> bool:
    low = (path or "").lower()
    if low.startswith(("\\windows\\winsxs", "\\windows\\servicing", "\\$", "\\windows\\installer", "\\program files\\windowsapps")):
        return False
    ext = os.path.splitext(low)[1][1:]
    return ext in executable_extensions() or ext in document_extensions() or "\\users\\" in low


UNKNOWN_DIR = "<unknown folder: MFT record {seg}, sequence {seq}>"


def _parent_ok(pseg: int, pseq: int, seqs: dict, inuse: dict) -> bool:
    """True when the parent reference still points at the same directory: same sequence number, or the directory was
    deleted (sequence incremented on deletion) and the record has not been reused."""
    cur = seqs.get(pseg)
    if cur is None:
        return False
    if pseq == 0 or cur == pseq:
        return True
    return cur == pseq + 1 and not inuse.get(pseg, True)


def _resolve_paths(names: dict, seqs: dict, inuse: dict | None = None) -> dict[int, str]:
    """Full path of every MFT record.  A parent whose record was reused is *not* followed (that would attach the file to
    an unrelated folder); the path then starts with an explicit '<unknown folder ...>' placeholder."""
    inuse = inuse or {}
    paths: dict[int, str] = {5: ""}
    for seg in list(names.keys()):
        if seg in paths:
            continue
        chain = []
        cur = seg
        base = None
        for _guard in range(512):
            if cur in paths:
                base = paths[cur]
                break
            ent = names.get(cur)
            if ent is None:
                base = "\\" + UNKNOWN_DIR.format(seg=cur, seq="?")
                break
            parent, pseq, name, _ = ent
            if parent == cur:
                base = ""
                break
            chain.append((cur, name))
            if parent == 5:
                base = ""
                break
            if not _parent_ok(parent, pseq, seqs, inuse):
                base = "\\" + UNKNOWN_DIR.format(seg=parent, seq=pseq)
                break
            cur = parent
        if base is None:
            base = "\\<path loop>"
        for c, name in reversed(chain):
            base = f"{base}\\{name}"
            paths[c] = base
    paths[5] = "\\"
    return paths


class _UsnPathResolver:
    """Parent folder path for a USN record at a given point of the journal."""

    def __init__(self, paths, dirs, seqs, inuse):
        self.paths, self.dirs, self.seqs, self.inuse = paths, dirs, seqs, inuse
        self.cache: dict = {}
        self.unresolved = 0

    def dir_path(self, seg: int, seq: int, usn: int, depth: int = 0) -> str:
        if seg == 5:
            return ""
        if depth > 64:
            return "\\<path loop>"
        mft_ok = _parent_ok(seg, seq, self.seqs, self.inuse)
        p = self.paths.get(seg) if mft_ok else None
        ents = self.dirs.get((seg, seq))
        if ents:
            # the journal knows this folder: use its name *at that time* (folders renamed later, e.g. by wipers that
            # rename before deleting, keep their original name for earlier records)
            i = max(0, bisect.bisect_right(ents, (usn, "\uffff", 1 << 62, 1 << 62)) - 1)
            key = (seg, seq, i)
            if key not in self.cache:
                _u, name, pseg, pseq = ents[i]
                self.cache[key] = f"{self.dir_path(pseg, pseq, usn, depth + 1)}\\{name}"
            return self.cache[key]
        if p is not None:
            return p
        self.unresolved += 1
        return "\\" + UNKNOWN_DIR.format(seg=seg, seq=seq)


def _recover_paths_from_usn(names: dict, paths: dict, dirs: dict, seqs: dict, inuse: dict) -> set:
    """Replace '<unknown folder ...>' prefixes of MFT paths with the folder path the change journal recorded."""
    if not dirs:
        return set()
    resolver = _UsnPathResolver(paths, dirs, seqs, inuse)
    fixes = {}
    for seg, (parent, pseq, _name, _d) in names.items():
        p = paths.get(seg) or ""
        if not p.startswith("\\<unknown folder"):
            continue
        ph = "\\" + UNKNOWN_DIR.format(seg=parent, seq=pseq)
        if p.startswith(ph) and (parent, pseq) in dirs and ph not in fixes:
            new = resolver.dir_path(parent, pseq, 1 << 62)
            if "<unknown folder" not in new:
                fixes[ph] = new
    recovered = set()
    if fixes:
        for seg, p in list(paths.items()):
            for ph, new in fixes.items():
                if p.startswith(ph):
                    paths[seg] = new + p[len(ph):]
                    recovered.add(seg)
                    break
    return recovered
