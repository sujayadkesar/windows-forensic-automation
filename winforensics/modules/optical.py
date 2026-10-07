"""Optical media (CD / DVD / BD) writing: Windows Explorer burn staging area and CD Burning registry keys.

Explorer's "Burn to disc" copies files into ``AppData\\Local\\Microsoft\\Windows\\Burn\\Burn`` before writing them; the
staging copies are deleted after a successful burn but remain in the MFT (deleted records) and the USN journal.
"""

from __future__ import annotations

from ._regutil import iter_keys, key_user, subkeys, ts_of, val, values
from .base import ArtifactModule, ArtifactType, C, register


@register
class OpticalMediaModule(ArtifactModule):
    id = "optical"
    title = "CD / DVD burning"
    category = "USB & Removable Media"
    description = "Files staged for disc burning (allocated and deleted), CD Burning registry state per user, optical volumes."
    weight = 0.3
    order = 41
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Local\\Microsoft\\Windows\\Burn\\Burn\\*",
                 "NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CD Burning"]
    artifact_types = [
        ArtifactType("burn_staging", "Files Staged for CD/DVD Burning", "USB & Removable Media",
                     [C("name", width=260), C("path", "Path (last recorded)", "path", 420), C("staged_path", "Path when staged", "path", 420),
                      C("size", kind="size"), C("created", kind="datetime"), C("last_record", "Last journal record", "datetime"),
                      C("status"), C("user")], ts_label="Staged (created)"),
        ArtifactType("burn_registry", "CD Burning Registry", "USB & Removable Media",
                     [C("user"), C("item", width=260), C("value", width=360), C("key_last_written", kind="datetime")],
                     ts_label="Key last written"),
    ]

    def run(self, ctx) -> None:
        n = 0
        for row in ctx.fs_files("lower(path) LIKE '%\\appdata\\local\\microsoft\\windows\\burn\\burn\\%' AND is_dir=0",
                                include_deleted=True):
            if row["name"].lower() == "desktop.ini":
                continue
            path = ctx.display_path(row["volume"], row["path"])
            user = ctx.user_for_path(path)
            status = "deleted (burned or discarded)" if row.get("deleted") else "still staged"
            ctx.emit("burn_staging", row.get("si_created") or row.get("fn_created"),
                     {"name": row["name"], "path": path, "size": row.get("size"), "created": row.get("si_created"),
                      "modified": row.get("si_modified"), "status": status, "user": user, "record": row.get("record")},
                     user=user, summary=f"Staged for burning: {row['name']} ({status})", source=path, ts_label="Staged (created)",
                     tags=["optical", "exfil_channel"])
            n += 1
        # $UsnJrnl keeps the staging history even when the MFT records of the staged files were reused.  One record per
        # staged file: the path when it was staged and the path at its last journal record (folders are often renamed
        # in the staging area before the disc is written, e.g. 'design' -> 'de').
        files: dict[tuple, list] = {}
        for u in ctx.db.query("SELECT usn, ts, record, seq, path, name, reason, attributes FROM usn WHERE evidence_id=? "
                              "AND lower(path) LIKE ? ORDER BY usn",
                              (ctx.evidence_id, "%\\appdata\\local\\microsoft\\windows\\burn\\burn\\%")):
            if (u["attributes"] or 0) & 0x10 or u["name"].lower() == "desktop.ini":
                continue  # folders and desktop.ini
            files.setdefault((u["record"], u["seq"]), []).append(u)
        for (_rec, _seq), hist in sorted(files.items(), key=lambda kv: kv[1][0]["usn"]):
            created = next((h for h in hist if "FileCreate" in h["reason"]), hist[0])
            last = hist[-1]
            deleted = any("FileDelete" in h["reason"] for h in hist)
            user = ctx.user_for_path(last["path"])
            status = "staged ($UsnJrnl)" + ("; deleted from the staging folder" if deleted else "")
            ctx.emit("burn_staging", created["ts"], {"name": last["name"], "path": last["path"],
                                                      "staged_path": created["path"] if created["path"] != last["path"] else "",
                                                      "size": None, "created": created["ts"], "modified": None,
                                                      "last_record": last["ts"], "status": status, "user": user},
                     user=user, summary=f"Staged for burning: {last['path']}" + (f" (staged as {created['path']})"
                                                                                 if created["path"] != last["path"] else ""),
                     source="$UsnJrnl:$J", ts_label="Staged (created)", tags=["optical", "exfil_channel"])
            n += 1
        # IMAPI writes DAT#####.tmp / FIL#####.tmp / POST#####.tmp image files while mastering a disc
        sessions = []
        for u in ctx.db.query("SELECT ts, name FROM usn WHERE evidence_id=? AND reason LIKE '%FileCreate%' AND "
                              "(name GLOB 'DAT[0-9][0-9][0-9][0-9][0-9].tmp' OR name GLOB 'FIL[0-9][0-9][0-9][0-9][0-9].tmp' "
                              "OR name GLOB 'POST[0-9][0-9][0-9][0-9][0-9].tmp') ORDER BY ts", (ctx.evidence_id,)):
            if sessions and u["ts"][:16] == sessions[-1][0][:16]:
                sessions[-1][1].add(u["name"])
            else:
                sessions.append((u["ts"], {u["name"]}))
        for ts, files in sessions:
            ctx.emit("burn_registry", ts, {"user": "", "item": "IMAPI mastering session ($UsnJrnl)",
                                           "value": ", ".join(sorted(files)), "key_last_written": None},
                     summary=f"Disc mastering temporary files created: {', '.join(sorted(files))}", source="$UsnJrnl:$J",
                     ts_label="Files created", tags=["optical"])
        ctx.coverage("CD/DVD burn staging area", self.locations[0] + " (MFT + $UsnJrnl)", "found" if n else "not_found", n,
                     f"{len(sessions)} IMAPI mastering session(s) in $UsnJrnl" if sessions else "")
        m = 0
        try:
            reg = ctx.target.registry
            for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CD Burning"):
                user = key_user(reg, k)
                for key in [k] + list(subkeys(k)):
                    for v in values(key):
                        data = v.value
                        if isinstance(data, (bytes, bytearray)):
                            data = bytes(data).decode("utf-16-le", "replace").rstrip("\x00") if len(data) % 2 == 0 else data.hex()
                        item = v.name if key is k else f"{key.name}\\{v.name}"
                        if v.name == "DefaultToMastered":
                            data = f"{data} ({'Mastered - burn with a CD/DVD player' if str(data) == '1' else 'Live File System - like a USB flash drive'})"
                        ctx.emit("burn_registry", ts_of(key), {"user": user, "item": item, "value": str(data)[:500],
                                                               "key_last_written": ts_of(key)},
                                 user=user, summary=f"CD Burning {item} = {str(data)[:120]}",
                                 source=f"NTUSER\\...\\Explorer\\CD Burning\\{'' if key is k else key.name}",
                                 ts_label="Key last written", tags=["optical"])
                        m += 1
                for sk in subkeys(k):
                    if sk.name.lower() == "drives":
                        for drv in subkeys(sk):
                            if val(drv, "Drive Type") is not None:
                                m += 1
        except Exception as e:
            ctx.warn(f"CD Burning registry: {e}")
        ctx.coverage("CD Burning registry", self.locations[1], "found" if m else "not_found", m)
