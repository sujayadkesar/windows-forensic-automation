"""File and folder access: LNK shortcuts, jump lists, Recycle Bin, Windows Timeline (ActivitiesCache)."""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct

from ..core.timeutil import db_ts, filetime, parse_any
from ._usbutil import norm_vsn
from .base import ArtifactModule, ArtifactType, C, register

LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
APPIDS = {
    "1b4dd67f29cb1962": "Windows Explorer", "f01b4d95cf55d32a": "Windows Explorer (8.1/10)", "5f7b5f1e01b83767": "Quick Access",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)", "918e0ecb43d17e23": "Notepad (32-bit)", "7e4dca80246863e3": "Control Panel",
    "12dc1ea8e34b5a6": "Microsoft Paint", "fb3b0dbfee58fac8": "Microsoft Word 365", "a7bd71699cd38d1c": "Microsoft Word 2010",
    "d00655d2aa12ff6d": "Microsoft PowerPoint 365", "9c7cc110ff56d1bd": "Microsoft PowerPoint 2010",
    "b8ab77100df80ab2": "Microsoft Excel 365", "12c1a2f43ddba3a8": "Microsoft Excel 2010", "adecfb853d77462a": "Microsoft Word 2007",
    "5d6f13ed567aa2da": "Microsoft Office Outlook", "d38adec6953449ba": "Microsoft OneNote", "23646679aaccfae0": "Adobe Acrobat Reader",
    "ee462c3b81abb6f6": "Adobe Acrobat Reader DC", "5c450709f7ae4396": "Firefox", "6d2bac8f1edf6668": "Microsoft Outlook",
    "28c8b86deab549a1": "Internet Explorer", "f4c3f8f2c69c1e5f": "Microsoft Edge", "9839aec31243a928": "Microsoft Edge (Chromium)",
    "a4a5324453625195": "Microsoft Edge", "5da8f997fd5f9428": "Chrome", "7cb0735d45243070": "VLC media player",
    "b74736c2bd8cc8a5": "WinZip", "290532160612e071": "WinRAR", "e0532b20aa26a0c9": "7-Zip",
    "1bc392b8e104a00e": "Remote Desktop (mstsc)", "6e855c85de07bc6a": "Microsoft Excel 365", "69639df789022856": "Google Chrome",
    "4cb9c5750d51c07f": "Windows Media Player", "3dc02b55e44d6697": "7-Zip File Manager", "b91050d8b077a4e8": "Windows Media Center",
    "ae069d21df1c57df": "mIRC", "c71ef2c372d322d7": "PGP Desktop", "bc0c37e84e063727": "Windows Command Processor",
    "17d3eb086439f0d7": "TrueCrypt", "fc999f29bc5c3560": "Robocopy", "f82607a219af2999": "Cyberduck",
    "5b186fc4a0b40504": "FileZilla", "8e4e81d9adc545b8": "WinSCP", "f001ea668c0aa916": "Skype", "4975d6798a8bdf66": "Total Commander",
}


def parse_lnk(data: bytes) -> dict:
    import LnkParse3

    lnk = LnkParse3.lnk_file(io.BytesIO(data))
    j = lnk.get_json()
    h = j.get("header", {})
    li = j.get("link_info", {}) or {}
    loc = li.get("location_info", {}) or {}
    net = li.get("common_network_relative_link", {}) or li.get("network_info", {}) or {}
    if not net and (loc.get("net_name") or li.get("location") == "Network"):
        net = loc  # LnkParse3 reports the CommonNetworkRelativeLink inside location_info
    extra = j.get("extra", {}) or {}
    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK", {}) or {}
    d = j.get("data", {}) or {}
    target = li.get("local_base_path") or ""
    if not target and net:
        # network target: the mapped drive letter only when the ValidDevice flag (0x1) is set (MS-SHLLINK 2.3.2) -
        # otherwise the device name field is not meaningful - else the UNC share name
        flags = net.get("common_network_relative_link_flags") or 0
        try:
            flags = int(str(flags), 0)
        except ValueError:
            flags = 0
        dev = net.get("device_name") or ""
        dev = dev if flags & 1 and re.fullmatch(r"[A-Za-z]:", dev or "") else ""
        target = dev or net.get("net_name") or net.get("network_share_name") or ""
    if li.get("common_path_suffix"):
        target = target.rstrip("\\") + "\\" + li["common_path_suffix"] if target else li["common_path_suffix"]
    if not target:
        items = (j.get("target", {}) or {}).get("items", [])
        parts = []
        for it in items:
            name = it.get("volume_name") or it.get("primary_name") or it.get("long_name") or ""
            if it.get("class") == "Root Folder":
                continue
            if name:
                parts.append(name.rstrip("\\"))
        target = "\\".join(parts)
    netname = net.get("net_name") or net.get("network_share_name") or ""
    if not target and netname:
        target = netname + ("\\" + li.get("common_path_suffix", "") if li.get("common_path_suffix") else "")
    serial = loc.get("drive_serial_number") or ""
    if isinstance(serial, str) and serial.startswith("0x"):
        serial = serial[2:].upper().zfill(8)
    env = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}) or {}
    return {
        "target_path": target, "arguments": d.get("command_line_arguments") or "", "working_dir": d.get("working_directory") or "",
        "relative_path": d.get("relative_path") or "", "icon": d.get("icon_location") or "", "description": d.get("description") or "",
        "target_created": db_ts(parse_any(h.get("creation_time"))), "target_modified": db_ts(parse_any(h.get("modified_time"))),
        "target_accessed": db_ts(parse_any(h.get("accessed_time"))), "target_size": h.get("file_size"),
        "drive_type": loc.get("drive_type") or ("NETWORK" if netname else ""), "volume_serial": norm_vsn(serial) if serial else "",
        "volume_label": loc.get("volume_label") or "", "network_share": netname, "machine_id": tracker.get("machine_identifier") or "",
        "droid_volume": tracker.get("droid_volume_identifier") or "", "droid_file": tracker.get("droid_file_identifier") or "",
        "birth_droid_file": tracker.get("birth_droid_file_identifier") or "", "env_target": env.get("target_unicode") or env.get("target_ansi") or "",
    }


def _vsn_fmt(v: str) -> str:
    return f"{v[:4]}-{v[4:]}" if v and len(v) == 8 else v or ""


@register
class FilesModule(ArtifactModule):
    id = "files"
    title = "Shortcuts, jump lists, Recycle Bin, Timeline"
    category = "File & Folder Access"
    description = ("LNK shortcut files (incl. deleted / resident ones), jump lists (automatic + custom destinations), "
                   "Recycle Bin $I/$R pairs and the Windows Timeline (ActivitiesCache.db).")
    weight = 3.0
    order = 35
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk", "Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent",
                 "Users\\*\\...\\Recent\\AutomaticDestinations", "Users\\*\\...\\Recent\\CustomDestinations", "*.lnk anywhere",
                 "$Recycle.Bin\\<SID>\\$I*", "Users\\*\\AppData\\Local\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db"]
    artifact_types = [
        ArtifactType("lnk", "Shortcut (LNK) Files", "File & Folder Access",
                     [C("target_path", "Target", "path", 380), C("drive_type", "Drive Type"), C("volume_serial", "Volume Serial"),
                      C("volume_label", "Volume Label"), C("lnk_created", "LNK Created (first opened)", "datetime"),
                      C("lnk_modified", "LNK Modified (last opened)", "datetime"), C("target_created", kind="datetime"),
                      C("target_modified", kind="datetime"), C("target_size", kind="size"), C("arguments", width=260),
                      C("machine_id", "Machine ID"), C("lnk_path", "LNK File", "path", 360), C("deleted")],
                     ts_label="LNK modified"),
        ArtifactType("jumplist", "Jump Lists", "File & Folder Access",
                     [C("application"), C("target_path", "Target", "path", 380), C("last_accessed", kind="datetime"),
                      C("access_count", kind="int"), C("pinned"), C("drive_type", "Drive Type"),
                      C("volume_serial", "Volume Serial"), C("volume_label", "Volume Label"), C("target_modified", kind="datetime"),
                      C("arguments", width=220), C("jumplist_file", width=300)], ts_label="Last accessed"),
        ArtifactType("recycle_bin", "Recycle Bin", "File & Folder Access",
                     [C("original_path", "Original Path", "path", 420), C("size", kind="size"), C("deleted_time", kind="datetime"),
                      C("r_file", "$R File", width=200), C("r_present", "Content Present"), C("sha256", "SHA256", "hash", 300),
                      C("sid", "SID")], ts_label="Deleted"),
        ArtifactType("timeline_activity", "Windows Timeline (ActivitiesCache)", "File & Folder Access",
                     [C("application", width=220), C("display_text", width=260), C("content", width=360),
                      C("start_time", kind="datetime"), C("end_time", kind="datetime"), C("activity_type"),
                      C("clipboard", width=220)], ts_label="Start"),
    ]

    def run(self, ctx) -> None:
        for i, fn in enumerate([self._lnk, self._jumplists, self._recycle, self._activities]):
            try:
                fn(ctx)
            except Exception as e:
                ctx.warn(f"files {fn.__name__}: {e}")
                ctx.coverage(fn.__name__.strip("_"), "", "error", 0, str(e)[:200])
            ctx.progress((i + 1) / 4)

    # ------------------------------------------------------------------ LNK
    def _lnk(self, ctx) -> None:
        rows = ctx.fs_files("ext='lnk'", include_deleted=True, limit=50_000)
        n = deleted_ok = 0
        for row in rows:
            path = ctx.display_path(row["volume"], row["path"] or "")
            try:
                data = ctx.read_entry(row, 1 << 20)
                if not data.startswith(LNK_MAGIC[:4]):
                    continue
                rec = parse_lnk(data)
            except Exception:
                continue
            lower = path.lower()
            location = ("Recent" if "\\recent\\" in lower else "Office Recent" if "\\office\\recent" in lower else
                        "Desktop" if "\\desktop\\" in lower else "Startup" if "\\startup\\" in lower else
                        "Start Menu" if "\\start menu\\" in lower else "Other")
            rec.update(lnk_path=path, lnk_created=row.get("si_created"), lnk_modified=row.get("si_modified"),
                       location=location, deleted="Yes (recovered)" if row.get("deleted") else "")
            tags = []
            if rec["drive_type"] == "DRIVE_REMOVABLE":
                tags.append("removable")
            if rec["network_share"]:
                tags.append("network")
            if row.get("deleted"):
                deleted_ok += 1
            ctx.emit("lnk", row.get("si_modified"), rec, user=ctx.user_for_path(path),
                     summary=f"LNK -> {rec['target_path']} ({rec['drive_type'] or '?'} {_vsn_fmt(rec['volume_serial'])})",
                     source=path, ts_label="LNK modified", tags=tags)
            n += 1
        ctx.coverage("Shortcut (LNK) files", "all *.lnk (incl. deleted MFT records)", "found" if n else "not_found", n,
                     f"{deleted_ok} recovered from deleted records" if deleted_ok else "")

    # ------------------------------------------------------------------ jump lists
    def _jumplists(self, ctx) -> None:
        import olefile

        rows = ctx.fs_files("lower(name) LIKE '%.automaticdestinations-ms' OR lower(name) LIKE '%.customdestinations-ms'",
                            include_deleted=False)
        n = 0
        for row in rows:
            path = ctx.display_path(row["volume"], row["path"] or "")
            appid = row["name"].split(".")[0].lower()
            app = APPIDS.get(appid, appid)
            user = ctx.user_for_path(path)
            try:
                data = ctx.read_entry(row)
            except Exception:
                continue
            if row["name"].lower().endswith("automaticdestinations-ms"):
                try:
                    ole = olefile.OleFileIO(io.BytesIO(data))
                except Exception:
                    continue
                dest = {}
                if ole.exists("DestList"):
                    dest = _parse_destlist(ole.openstream("DestList").read())
                for entry in ole.listdir():
                    sname = entry[0]
                    if sname == "DestList":
                        continue
                    try:
                        lnk = parse_lnk(ole.openstream(sname).read())
                    except Exception:
                        continue
                    try:
                        num = int(sname, 16)
                    except ValueError:
                        num = -1
                    d = dest.get(num, {})
                    rec = {**lnk, "application": app, "appid": appid, "last_accessed": d.get("last_accessed"),
                           "access_count": d.get("access_count"), "pinned": "Yes" if d.get("pinned") else "",
                           "dest_path": d.get("path"), "hostname": d.get("hostname"), "jumplist_file": path, "entry": num}
                    if not rec["target_path"] and d.get("path"):
                        rec["target_path"] = d["path"]
                    ctx.emit("jumplist", rec["last_accessed"] or lnk.get("target_accessed"), rec, user=user,
                             summary=f"Jump list [{app}] {rec['target_path']}", source=path, ts_label="Last accessed",
                             tags=["removable"] if rec.get("drive_type") == "DRIVE_REMOVABLE" else None)
                    n += 1
            else:
                for off in [m.start() for m in re.finditer(re.escape(LNK_MAGIC), data)]:
                    try:
                        lnk = parse_lnk(data[off:off + 65536])
                    except Exception:
                        continue
                    rec = {**lnk, "application": app, "appid": appid, "last_accessed": None, "access_count": None,
                           "pinned": "custom", "jumplist_file": path}
                    ctx.emit("jumplist", lnk.get("target_accessed"), rec, user=user,
                             summary=f"Custom jump list [{app}] {rec['target_path']}", source=path, ts_label="Target accessed")
                    n += 1
        ctx.coverage("Jump lists", "Recent\\AutomaticDestinations + CustomDestinations", "found" if n else
                     ("not_found" if rows else "absent"), n)

    # ------------------------------------------------------------------ recycle bin
    def _recycle(self, ctx) -> None:
        rows = ctx.fs_files("lower(path) LIKE '%\\$recycle.bin\\%' AND name LIKE '$I%'", include_deleted=True)
        all_r = {(r["volume"], r["path"].lower()): r for r in ctx.fs_files("lower(path) LIKE '%\\$recycle.bin\\%' AND name LIKE '$R%'",
                                                                              include_deleted=True)}
        n = 0
        for row in rows:
            try:
                data = ctx.read_entry(row, 8192)
            except Exception:
                continue
            if len(data) < 24:
                continue
            ver, size, ft = struct.unpack_from("<QQQ", data, 0)
            if ver == 2 and len(data) >= 28:
                plen = struct.unpack_from("<I", data, 24)[0]
                orig = data[28:28 + plen * 2].decode("utf-16-le", "replace").rstrip("\x00")
            else:
                orig = data[24:24 + 520].decode("utf-16-le", "replace").split("\x00")[0]
            deleted = filetime(ft)
            sid = row["path"].split("\\")[2] if row["path"].count("\\") >= 3 else ""
            rname = "$R" + row["name"][2:]
            rpath = row["path"][: -len(row["name"])] + rname
            rrow = all_r.get((row["volume"], rpath.lower()))
            sha = ""
            if rrow and not rrow["is_dir"] and (rrow.get("size") or 0) <= 512 * 1024 * 1024:
                try:
                    sha = hashlib.sha256(ctx.read_entry(rrow)).hexdigest()
                except Exception:
                    sha = ""
            user = None
            for p in ctx.user_profiles():
                if p.get("sid") == sid:
                    user = p["name"]
            rec = {"original_path": orig, "size": size, "deleted_time": db_ts(deleted), "r_file": rname,
                   "r_present": ("Yes" if not rrow.get("deleted") else "Deleted (emptied)") if rrow else "No",
                   "sha256": sha, "sid": sid, "i_file": ctx.display_path(row["volume"], row["path"]),
                   "i_deleted": bool(row.get("deleted"))}
            ctx.emit("recycle_bin", deleted, rec, user=user, summary=f"Recycled {orig} ({size} bytes) at {rec['deleted_time']}",
                     source=rec["i_file"], ts_label="Deleted")
            n += 1
        ctx.coverage("Recycle Bin ($I files)", "<drive>\\$Recycle.Bin\\<SID>", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ ActivitiesCache
    def _activities(self, ctx) -> None:
        n = 0
        try:
            recs = list(ctx.plugin("activitiescache"))
        except Exception:
            recs = []
        types = {5: "App in focus", 6: "User engaged", 10: "Clipboard", 16: "Copy/Paste", 2: "Notification", 3: "Mobile backup",
                 11: "System", 12: "System", 15: "Install"}
        for r in recs:
            try:
                apps = json.loads(r.get("app_id") or "[]")
                app = next((a.get("application") for a in apps if a.get("platform") in ("windows_win32", "x_exe_path",
                                                                                        "packageId")), None) or (apps[0].get("application") if apps else "")
            except Exception:
                app = str(r.get("app_id"))[:200]
            payload = {}
            try:
                payload = json.loads(r.get("payload") or "{}")
            except Exception:
                pass
            clip = ""
            if r.get("clipboard_payload"):
                try:
                    cp = json.loads(r["clipboard_payload"])
                    import base64

                    for item in cp if isinstance(cp, list) else []:
                        if item.get("formatName") == "Text":
                            clip = base64.b64decode(item.get("content", "")).decode("utf-8", "replace")[:2000]
                except Exception:
                    clip = str(r["clipboard_payload"])[:500]
            at = int(r.get("activity_type") or 0)
            rec = {"application": app, "display_text": payload.get("displayText") or payload.get("appDisplayName") or "",
                   "content": r.get("app_activity_id") or payload.get("contentUri") or payload.get("activationUri") or "",
                   "start_time": db_ts(r.get("start_time")), "end_time": db_ts(r.get("end_time")),
                   "activity_type": types.get(at, str(at)), "clipboard": clip, "source_db": str(r.get("source"))}
            ctx.emit("timeline_activity", r.get("start_time"), rec, user=r.get("username"),
                     summary=f"Timeline: {app} {rec['display_text']} {rec['content']}"[:300], source=str(r.get("source")),
                     ts_label="Start", tags=["clipboard"] if clip else None)
            n += 1
        ctx.coverage("Windows Timeline", "ConnectedDevicesPlatform\\*\\ActivitiesCache.db", "found" if n else
                     ("not_found" if ctx.glob("C:/Users/*/AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db") else "absent"), n)


def _parse_destlist(data: bytes) -> dict:
    out = {}
    if len(data) < 32:
        return out
    version, count = struct.unpack_from("<II", data, 0)
    off = 32
    hdr = 130 if version >= 3 else 114
    for _ in range(min(count, 5000)):
        if off + hdr > len(data):
            break
        try:
            hostname = data[off + 64:off + 80].split(b"\x00")[0].decode("ascii", "replace")
            num = struct.unpack_from("<I", data, off + 88)[0]
            ft = struct.unpack_from("<Q", data, off + 100)[0]
            pin = struct.unpack_from("<i", data, off + 108)[0]
            if version >= 3:
                cnt = struct.unpack_from("<I", data, off + 116)[0]
                plen = struct.unpack_from("<H", data, off + 128)[0]
                p0 = off + 130
            else:
                cnt = None
                plen = struct.unpack_from("<H", data, off + 112)[0]
                p0 = off + 114
            path = data[p0:p0 + plen * 2].decode("utf-16-le", "replace")
            out[num] = {"hostname": hostname, "last_accessed": db_ts(filetime(ft)), "pinned": pin != -1, "access_count": cnt,
                        "path": path}
            off = p0 + plen * 2 + (4 if version >= 3 else 0)
        except Exception:
            break
    return out
