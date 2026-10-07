"""Program execution evidence: Prefetch, Amcache, PCA, Shimcache, BAM/DAM, SRUM, MUICache."""

from __future__ import annotations

import io
import re
import struct

from ..core.timeutil import db_ts, filetime
from ..knowledge import tool_for_exe
from ._regutil import iter_keys, key_user, subkeys, values
from .base import ArtifactModule, ArtifactType, C, register

RX_VOLPATH = re.compile(r"^\\VOLUME\{([0-9a-f]+)-([0-9a-f]{8})\}", re.I)


def _tool_tags(path: str) -> list[str]:
    return sorted({f"tool:{fam}" for fam, _ in tool_for_exe(path)})


@register
class ExecutionModule(ArtifactModule):
    id = "execution"
    title = "Program execution"
    category = "Program Execution"
    description = "Prefetch (run times, files and volumes referenced), Amcache, PCA, Shimcache, BAM/DAM, SRUM, MUICache."
    weight = 4.0
    order = 30
    locations = ["C:\\Windows\\Prefetch\\*.pf", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
                 "C:\\Windows\\appcompat\\pca\\*.txt", "SYSTEM\\...\\Session Manager\\AppCompatCache",
                 "SYSTEM\\...\\Services\\bam\\State\\UserSettings", "C:\\Windows\\System32\\sru\\SRUDB.dat",
                 "UsrClass.dat\\...\\Shell\\MuiCache"]
    artifact_types = [
        ArtifactType("prefetch", "Prefetch", "Program Execution",
                     [C("executable", width=200), C("path", "Executable path (from the file list)", "path", width=380),
                      C("run_count", kind="int"), C("last_run", kind="datetime"),
                      C("previous_runs", width=300), C("files_referenced", "Files", "int"), C("volumes", width=260),
                      C("prefetch_file", width=220), C("tools")], ts_label="Last run"),
        ArtifactType("prefetch_file_ref", "Prefetch - files referenced", "Program Execution",
                     [C("executable"), C("file", kind="path", width=520), C("volume_serial", "Volume Serial"),
                      C("last_run", kind="datetime")], ts_label="Last run of executable",
                     description="Files loaded/opened by a program in its first seconds (documents opened from removable media appear here)."),
        ArtifactType("amcache", "Amcache (InventoryApplicationFile / File)", "Program Execution",
                     [C("path", kind="path", width=420), C("sha1", "SHA1", "hash", 300), C("size", kind="size"),
                      C("publisher"), C("product"), C("version"), C("link_date", kind="datetime"),
                      C("key_last_written", "First Seen (key)", "datetime")], ts_label="Key last written"),
        ArtifactType("amcache_program", "Amcache (InventoryApplication)", "Program Execution",
                     [C("name", width=260), C("version"), C("publisher"), C("install_date"), C("root_dir", kind="path", width=300),
                      C("source"), C("key_last_written", kind="datetime")], ts_label="Key last written"),
        ArtifactType("pca", "Program Compatibility Assistant (PCA)", "Program Execution",
                     [C("path", kind="path", width=460), C("run_time", kind="datetime"), C("details", width=300),
                      C("file")], ts_label="Execution time"),
        ArtifactType("shimcache", "Shimcache (AppCompatCache)", "Program Execution",
                     [C("position", kind="int"), C("path", kind="path", width=480), C("last_modified", kind="datetime"),
                      C("executed"), C("control_set")], ts_label="File last modified",
                     description="Presence = file existed / was evaluated; the timestamp is the file's $SI modified time, not execution."),
        ArtifactType("bam", "BAM / DAM (Background Activity Moderator)", "Program Execution",
                     [C("path", kind="path", width=480), C("last_execution", kind="datetime"), C("user"), C("sid", "SID")],
                     ts_label="Last execution"),
        ArtifactType("srum_network", "SRUM Network Usage", "Network",
                     [C("application", width=360), C("user"), C("bytes_sent", kind="size"), C("bytes_received", kind="size"),
                      C("interface"), C("network_profile"), C("timestamp", kind="datetime")], ts_label="SRUM interval"),
        ArtifactType("srum_app", "SRUM Application Resource Usage", "Program Execution",
                     [C("application", width=360), C("user"), C("foreground_bytes_read", "FG Bytes Read", "size"),
                      C("foreground_bytes_written", "FG Bytes Written", "size"),
                      C("background_bytes_written", "BG Bytes Written", "size"), C("timestamp", kind="datetime")],
                     ts_label="SRUM interval"),
        ArtifactType("muicache", "MUICache (executed program display names)", "Program Execution",
                     [C("path", kind="path", width=460), C("description", width=260)]),
    ]

    def run(self, ctx) -> None:
        steps = [self._prefetch, self._amcache, self._pca, self._shimcache, self._bam, self._srum, self._muicache]
        for i, fn in enumerate(steps):
            try:
                fn(ctx)
            except Exception as e:
                ctx.warn(f"execution {fn.__name__}: {e}")
                ctx.coverage(fn.__name__.strip("_"), "", "error", 0, str(e)[:200])
            ctx.progress((i + 1) / len(steps))

    # ------------------------------------------------------------------ prefetch
    def _prefetch(self, ctx) -> None:
        from dissect.target.plugins.os.windows.prefetch import Prefetch, c_prefetch

        files = [p for p in ctx.glob("C:/Windows/Prefetch/*") if p.name.lower().endswith(".pf")]
        if not files:
            enabled = None
            try:
                enabled = ctx.target.registry.key(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
                ).value("EnablePrefetcher").value
            except Exception:
                pass
            ctx.coverage("Prefetch", "C:\\Windows\\Prefetch", "absent", 0,
                         "no .pf files" + (f" (EnablePrefetcher={enabled})" if enabled is not None else ""))
            return
        n = 0
        for p in files:
            try:
                self._one_prefetch(ctx, p, Prefetch, c_prefetch)
                n += 1
            except Exception as e:
                ctx.warn(f"Prefetch {p.name}: {e}")
        ctx.coverage("Prefetch", "C:\\Windows\\Prefetch\\*.pf", "found" if n else "not_found", n)

    def _one_prefetch(self, ctx, p, Prefetch, c_prefetch):
        pf = Prefetch(io.BytesIO(ctx.read_bytes(p)))
        exe = pf.header.name.decode("utf-16-le", "ignore").split("\x00")[0]
        run_count = pf.fn.run_count
        if pf.version in (17, 23):
            # Windows XP / 2003 (17) and Vista / 7 (23) record one last-run FILETIME and the run count at fixed offsets
            # (libscca format): 17 -> 0x78 / 0x90, 23 -> 0x80 / 0x98.  dissect's version-17 layout reads both from the
            # wrong place, and the bytes after the version-23 time are not earlier run times.
            pf.fh.seek(0x78 if pf.version == 17 else 0x80)
            last = struct.unpack("<Q", pf.fh.read(8))[0]
            pf.fh.seek(0x90 if pf.version == 17 else 0x98)
            run_count = struct.unpack("<I", pf.fh.read(4))[0]
            runs = [t for t in [filetime(last) if last else None] if t and db_ts(t)]
        else:
            runs = [t for t in [pf.latest_timestamp, *pf.previous_timestamps] if t and db_ts(t)]
        vols = []
        try:
            vol_struct = c_prefetch.VOLUME_INFORMATION_30 if pf.version >= 30 else c_prefetch.VOLUME_INFORMATION_17
            stride = {17: 40, 23: 104, 26: 104}.get(pf.version, len(vol_struct))
            base = pf.fn.volumes_information_offset
            for i in range(pf.fn.number_of_volumes):
                pf.fh.seek(base + i * stride)
                vi = vol_struct(pf.fh)
                pf.fh.seek(base + vi.device_path_offset)
                dev = pf.fh.read(vi.device_path_number_of_characters * 2).decode("utf-16-le", "ignore")
                vols.append({"device": dev, "serial": f"{vi.serial_number:08X}", "created": db_ts(filetime(vi.creation_time))})
        except Exception:
            pass
        metrics = list(pf.metrics or [])
        vol_serials = {m.group(2).upper() for f in metrics for m in [RX_VOLPATH.match(f)] if m}
        # the header keeps only the file name (truncated to 29 characters); the executable's full path is the
        # entry of the referenced-file list with that name
        low = exe.lower()
        path = next((f for f in metrics if f.lower().rsplit("\\", 1)[-1] == low), "") or \
            (next((f for f in metrics if f.lower().rsplit("\\", 1)[-1].startswith(low)), "") if len(exe) >= 29 else "")
        rec = {
            "executable": exe, "path": path, "hash": f"{pf.header.hash:08X}", "version": pf.version, "run_count": run_count,
            "last_run": db_ts(runs[0]) if runs else None, "run_times": [db_ts(t) for t in runs],
            "previous_runs": ", ".join((db_ts(t) or "")[:19] for t in runs[1:] if db_ts(t)), "files_referenced": len(metrics),
            "volumes": ", ".join(f"{v['device']} ({v['serial'][:4]}-{v['serial'][4:]})" for v in vols),
            "volume_list": vols, "volume_serials_in_paths": sorted(vol_serials), "prefetch_file": p.name,
            "files": metrics[:2000], "tools": ", ".join(t for _, t in tool_for_exe(exe)),
        }
        ctx.emit("prefetch", runs[0] if runs else None, rec, summary=f"{exe} ran {run_count}x, last {rec['last_run']}",
                 source=f"C:\\Windows\\Prefetch\\{p.name}", ts_label="Last run", tags=_tool_tags(exe))
        for t in runs[1:]:
            ctx.emit("prefetch", t, {**rec, "files": [], "is_previous_run": True},
                     summary=f"{exe} previous run", source=f"C:\\Windows\\Prefetch\\{p.name}", ts_label="Previous run")
        sys_serials = {v["serial"] for v in vols[:1]}
        for f in metrics:
            m = RX_VOLPATH.match(f)
            low = f.lower()
            interesting = (m and m.group(2).upper() not in sys_serials) or not low.endswith((".dll", ".mui", ".nls", ".sys", ".dat", ".db", ".ttf", ".ttc", ".fon", ".etl", ".log", ".ini", ".manifest", ".exe", ".cpl", ".drv", ".tlb", ".olb", ".ocx", ".winmd", ".pri", ".tmp", ".bin", ".config", ".json", ".xml", ".cat", ".sdb", ".otf", ".ax", ".ime", ".rll", ".msi", ".tlb", ".pnf", ".inf"))
            if interesting:
                ctx.emit("prefetch_file_ref", runs[0] if runs else None, {
                    "executable": exe, "file": f, "volume_serial": (m.group(2).upper() if m else ""),
                    "last_run": rec["last_run"], "prefetch_file": p.name},
                    summary=f"{exe} referenced {f}", source=f"C:\\Windows\\Prefetch\\{p.name}",
                    ts_label="Last run of executable")

    # ------------------------------------------------------------------ amcache
    def _amcache(self, ctx) -> None:
        from dissect.regf import RegistryHive

        path = ctx.path("C:/Windows/AppCompat/Programs/Amcache.hve")
        if not path.exists():
            ctx.coverage("Amcache", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "absent", 0)
            return
        hive = RegistryHive(io.BytesIO(ctx.read_bytes(path)))
        n = m = 0

        def key(p):
            try:
                return hive.open(p)
            except Exception:
                return None

        def v(k, name, default=None):
            try:
                return k.value(name).value
            except Exception:
                return default

        iaf = key("Root\\InventoryApplicationFile")
        for k in (iaf.subkeys() if iaf else []):
            fid = v(k, "FileId") or ""
            sha1 = fid[4:] if isinstance(fid, str) and fid.startswith("0000") else fid
            p = v(k, "LowerCaseLongPath") or v(k, "Name")
            ld = v(k, "LinkDate")
            rec = {"path": p, "name": v(k, "Name"), "sha1": (sha1 or "").lower(), "size": v(k, "Size"),
                   "publisher": v(k, "Publisher"), "product": v(k, "ProductName"), "version": v(k, "Version") or v(k, "BinFileVersion"),
                   "link_date": ld, "program_id": v(k, "ProgramId"), "is_os_component": v(k, "IsOsComponent"),
                   "key_last_written": db_ts(k.timestamp), "source_key": "InventoryApplicationFile"}
            ctx.emit("amcache", k.timestamp, rec, summary=f"Amcache: {p} sha1={rec['sha1'][:12]}", ts_label="Key last written",
                     source=f"Amcache.hve\\Root\\InventoryApplicationFile\\{k.name}", tags=_tool_tags(p or ""))
            n += 1
        legacy = key("Root\\File")
        for vol in (legacy.subkeys() if legacy else []):
            for k in vol.subkeys():
                p = v(k, "15")
                sha1 = v(k, "101") or ""
                rec = {"path": p, "sha1": sha1[4:].lower() if sha1.startswith("0000") else sha1.lower(), "size": v(k, "6"),
                       "publisher": v(k, "1"), "product": v(k, "0"), "version": v(k, "5"),
                       "link_date": db_ts(filetime(v(k, "f"))) if isinstance(v(k, "f"), int) else None,
                       "key_last_written": db_ts(k.timestamp), "source_key": "File (legacy)"}
                ctx.emit("amcache", k.timestamp, rec, summary=f"Amcache (legacy): {p}", ts_label="Key last written",
                         source=f"Amcache.hve\\Root\\File\\{vol.name}\\{k.name}", tags=_tool_tags(p or ""))
                n += 1
        ia = key("Root\\InventoryApplication")
        for k in (ia.subkeys() if ia else []):
            rec = {"name": v(k, "Name"), "version": v(k, "Version"), "publisher": v(k, "Publisher"),
                   "install_date": v(k, "InstallDate"), "root_dir": v(k, "RootDirPath"), "source": v(k, "Source"),
                   "uninstall": v(k, "UninstallString"), "key_last_written": db_ts(k.timestamp)}
            ctx.emit("amcache_program", k.timestamp, rec, summary=f"Amcache program: {rec['name']} {rec['version'] or ''}",
                     ts_label="Key last written", source=f"Amcache.hve\\Root\\InventoryApplication\\{k.name}")
            m += 1
        ctx.coverage("Amcache", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "found" if n + m else "not_found", n + m)

    def _pca(self, ctx) -> None:
        files = ctx.glob("C:/Windows/appcompat/pca/*.txt")
        if not files:
            ctx.coverage("Program Compatibility Assistant", "C:\\Windows\\appcompat\\pca", "absent", 0)
            return
        from ..core.timeutil import parse_any

        n = 0
        for f in files:
            raw = ctx.read_bytes(f)
            text = raw.decode("utf-16-le", "replace") if raw[:2] == b"\xff\xfe" or b"\x00" in raw[:20] else raw.decode("utf-8", "replace")
            for line in text.splitlines():
                line = line.strip("\ufeff\r\n ")
                if not line:
                    continue
                parts = line.split("|")
                if f.name.lower().startswith("pcaapplaunchdic"):
                    path, ts = parts[0], parse_any(parts[1]) if len(parts) > 1 else None
                    details = ""
                else:
                    ts = parse_any(parts[0]) if parts else None
                    path = parts[2] if len(parts) > 2 else line
                    details = " | ".join(parts[3:])[:300]
                ctx.emit("pca", ts, {"path": path, "run_time": db_ts(ts), "details": details, "file": f.name},
                         summary=f"PCA: {path}", source=f"C:\\Windows\\appcompat\\pca\\{f.name}", ts_label="Execution time",
                         tags=_tool_tags(path))
                n += 1
        ctx.coverage("Program Compatibility Assistant", "C:\\Windows\\appcompat\\pca\\*.txt", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ shimcache
    def _shimcache(self, ctx) -> None:
        reg = ctx.target.registry
        n = 0
        seen_blobs = set()
        for root in iter_keys(reg, "HKLM\\SYSTEM"):
            for cs in subkeys(root):
                if not cs.name.lower().startswith("controlset"):
                    continue
                for sub in ("Control\\Session Manager\\AppCompatCache", "Control\\Session Manager\\AppCompatibility"):
                    try:
                        k = cs
                        for part in sub.split("\\"):
                            k = k.subkey(part)
                        data = k.value("AppCompatCache").value
                    except Exception:
                        continue
                    data = bytes(data)
                    h = hash(data)
                    if h in seen_blobs:
                        continue
                    seen_blobs.add(h)
                    for pos, (path, ts, executed) in enumerate(parse_shimcache(data)):
                        ctx.emit("shimcache", ts, {"position": pos, "path": path, "last_modified": db_ts(ts),
                                                   "executed": executed, "control_set": cs.name},
                                 summary=f"Shimcache #{pos}: {path}", source=f"SYSTEM\\{cs.name}\\{sub}",
                                 ts_label="File last modified", tags=_tool_tags(path))
                        n += 1
        ctx.coverage("Shimcache", "SYSTEM\\ControlSet00x\\Control\\Session Manager\\AppCompatCache",
                     "found" if n else "not_found", n)

    # ------------------------------------------------------------------ BAM/DAM
    def _bam(self, ctx) -> None:
        reg = ctx.target.registry
        users = {p.get("sid"): p["name"] for p in ctx.user_profiles() if p.get("sid")}
        n = 0
        for svc in ("bam", "dam"):
            for base in (f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc}\\State\\UserSettings",
                         f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc}\\UserSettings"):
                for k in iter_keys(reg, base):
                    for sk in subkeys(k):
                        for v in values(sk):
                            data = v.value
                            if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
                                continue
                            ts = filetime(struct.unpack("<Q", bytes(data[:8]))[0])
                            path = v.name
                            ctx.emit("bam", ts, {"path": path, "last_execution": db_ts(ts), "user": users.get(sk.name, ""),
                                                 "sid": sk.name, "service": svc.upper()},
                                     user=users.get(sk.name), summary=f"{svc.upper()}: {path}", ts_label="Last execution",
                                     source=f"SYSTEM\\...\\Services\\{svc}\\State\\UserSettings\\{sk.name}", tags=_tool_tags(path))
                            n += 1
        ctx.coverage("BAM / DAM", "SYSTEM\\...\\Services\\bam\\State\\UserSettings", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ SRUM
    def _srum(self, ctx) -> None:
        if not ctx.exists("C:/Windows/System32/sru/SRUDB.dat"):
            ctx.coverage("SRUM", "C:\\Windows\\System32\\sru\\SRUDB.dat", "absent", 0)
            return
        users = {p.get("sid"): p["name"] for p in ctx.user_profiles() if p.get("sid")}
        n = 0
        if ctx.options.get("export_srum", True):
            try:
                import io

                from ..core.exporter import dump_srum

                data = ctx.read_bytes(ctx.path("C:/Windows/System32/sru/SRUDB.dat"))
                res = dump_srum(io.BytesIO(data), ctx.parsed_dir("SRUM - all tables"), users)
                ctx.info(f"SRUM: {len(res)} tables exported ({sum(v[1] for v in res.values()):,} rows)")
            except Exception as e:
                ctx.warn(f"SRUM full export failed: {e}")
        try:
            for r in ctx.plugin("sru.network_data"):
                sid = str(r.get("user") or "")
                ts = r.get("ts")
                rec = {"application": str(r.get("app") or ""), "user": users.get(sid, sid), "bytes_sent": r.get("bytes_sent"),
                       "bytes_received": r.get("bytes_recvd"), "interface": str(r.get("interface_luid") or ""),
                       "network_profile": str(r.get("l2_profile_id") or ""), "timestamp": db_ts(ts)}
                ctx.emit("srum_network", ts, rec, user=rec["user"] or None,
                         summary=f"SRUM net: {rec['application']} sent {rec['bytes_sent']} recv {rec['bytes_received']}",
                         source="C:\\Windows\\System32\\sru\\SRUDB.dat", ts_label="SRUM interval")
                n += 1
            for r in ctx.plugin("sru.application"):
                sid = str(r.get("user") or "")
                ts = r.get("ts")
                rec = {"application": str(r.get("app") or ""), "user": users.get(sid, sid),
                       "foreground_bytes_read": r.get("foreground_bytes_read"),
                       "foreground_bytes_written": r.get("foreground_bytes_written"),
                       "background_bytes_written": r.get("background_bytes_written"), "timestamp": db_ts(ts)}
                ctx.emit("srum_app", ts, rec, user=rec["user"] or None, summary=f"SRUM app: {rec['application']}",
                         source="C:\\Windows\\System32\\sru\\SRUDB.dat", ts_label="SRUM interval")
                n += 1
        except Exception as e:
            ctx.coverage("SRUM", "C:\\Windows\\System32\\sru\\SRUDB.dat", "error", n, str(e)[:200])
            return
        ctx.coverage("SRUM", "C:\\Windows\\System32\\sru\\SRUDB.dat", "found" if n else "not_found", n)

    def _muicache(self, ctx) -> None:
        reg = ctx.target.registry
        n = 0
        for base in ("HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                     "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"):
            for k in iter_keys(reg, base):
                user = key_user(reg, k)
                for v in values(k):
                    name = v.name
                    if name.lower().startswith("langid") or "@" in name[:2]:
                        continue
                    path = re.sub(r"\.(FriendlyAppName|ApplicationCompany)$", "", name)
                    if not re.search(r"[a-z]:\\", path, re.I):
                        continue
                    ctx.emit("muicache", None, {"path": path, "description": str(v.value)}, user=user,
                             summary=f"MUICache: {path}", source="UsrClass.dat\\...\\Shell\\MuiCache", tags=_tool_tags(path))
                    n += 1
        ctx.coverage("MUICache", "UsrClass.dat\\...\\Shell\\MuiCache", "found" if n else "not_found", n)


def parse_shimcache(data: bytes):
    """Yield (path, last_modified, executed) from an AppCompatCache blob (Win7 - Win11)."""
    if len(data) < 16:
        return
    sig = struct.unpack_from("<I", data, 0)[0]
    # Windows 10 / 11: header size 0x30 or 0x34, entries tagged "10ts"
    if sig in (0x30, 0x34) and data[sig:sig + 4] == b"10ts":
        off = sig
        while off + 12 <= len(data) and data[off:off + 4] == b"10ts":
            entry_size = struct.unpack_from("<I", data, off + 8)[0]
            p = off + 12
            plen = struct.unpack_from("<H", data, p)[0]
            path = data[p + 2:p + 2 + plen].decode("utf-16-le", "replace")
            q = p + 2 + plen
            ts = filetime(struct.unpack_from("<Q", data, q)[0]) if q + 8 <= len(data) else None
            dsize = struct.unpack_from("<I", data, q + 8)[0] if q + 12 <= len(data) else 0
            blob = data[q + 12:q + 12 + dsize]
            executed = ""
            if len(blob) >= 4:
                executed = "Yes" if struct.unpack_from("<I", blob, len(blob) - 4)[0] == 1 else "No"
            yield path, ts, executed
            off += 12 + entry_size
        return
    # Windows 8 / 8.1: signature "00ts" / "10ts" after 0x80 header
    if sig in (0x80,) and data[0x80:0x84] in (b"00ts", b"10ts"):
        off = 0x80
        while off + 12 <= len(data) and data[off:off + 4] in (b"00ts", b"10ts"):
            entry_size = struct.unpack_from("<I", data, off + 8)[0]
            p = off + 12
            plen = struct.unpack_from("<H", data, p)[0]
            path = data[p + 2:p + 2 + plen].decode("utf-16-le", "replace")
            q = p + 2 + plen + 10
            ts = filetime(struct.unpack_from("<Q", data, q)[0]) if q + 8 <= len(data) else None
            yield path, ts, ""
            off += 12 + entry_size
        return
    # Windows 7 / 2008R2
    if sig == 0xBADC0FEE:
        count = struct.unpack_from("<I", data, 4)[0]
        x64 = len(data) >= 0x80 + 48 and struct.unpack_from("<I", data, 0x80 + 4)[0] == 0
        size = 48 if x64 else 32
        for i in range(count):
            e = 0x80 + i * size
            if e + size > len(data):
                break
            if x64:
                ln, _mx, _pad, poff, ft, flags = struct.unpack_from("<HHIQQI", data, e)
            else:
                ln, _mx, poff, ft, flags = struct.unpack_from("<HHIQI", data, e)
            path = data[poff:poff + ln].decode("utf-16-le", "replace")
            yield path, filetime(ft), "Yes" if flags & 0x2 else "No"
        return
