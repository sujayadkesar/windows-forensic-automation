"""PowerShell console history, transcripts and script files dropped in user-writable locations."""

from __future__ import annotations

import re

from ..core.timeutil import parse_any
from ..knowledge import score_command
from .base import ArtifactModule, ArtifactType, C, register

SCRIPT_EXT = ("ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "bat", "cmd", "lnk", "url", "scr", "iso", "img", "vhd",
              "vhdx", "msi", "msix", "appx", "jar", "py", "chm", "xll", "one", "library-ms", "searchconnector-ms")
USER_WRITABLE = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\appdata\\roaming\\", "\\users\\public\\", "\\programdata\\",
                 "\\windows\\temp\\", "\\desktop\\", "\\appdata\\local\\")


@register
class ScriptsModule(ArtifactModule):
    id = "scripts"
    title = "PowerShell history & scripts"
    category = "Program Execution"
    description = ("PSReadLine console history per user, PowerShell transcripts, and script / container files "
                   "(ps1, vbs, js, hta, bat, iso, msi, lnk...) in user-writable folders, each scored for malicious traits.")
    weight = 1.5
    order = 40
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\*_history.txt",
                 "PowerShell_transcript.*.txt", "Temp / Downloads / AppData / ProgramData / Public script files"]
    artifact_types = [
        ArtifactType("ps_history", "PowerShell Console History (PSReadLine)", "Program Execution",
                     [C("line_no", "#", "int", 50), C("command", width=620), C("score", kind="int"), C("indicators", width=280),
                      C("history_file", width=300)], ts_label="History file last modified (last line)"),
        ArtifactType("ps_transcript", "PowerShell Transcripts", "Program Execution",
                     [C("file", kind="path", width=360), C("start_time", kind="datetime"), C("user"), C("host_application", width=300),
                      C("commands", width=420), C("score", kind="int")], ts_label="Start"),
        ArtifactType("script_file", "Scripts / Containers in User-Writable Folders", "Malware",
                     [C("path", kind="path", width=460), C("size", kind="size"), C("created", kind="datetime"),
                      C("modified", kind="datetime"), C("deleted"), C("score", kind="int"), C("indicators", width=260),
                      C("preview", width=300)], ts_label="Created"),
    ]

    def run(self, ctx) -> None:
        self._history(ctx)
        ctx.progress(0.4)
        self._transcripts(ctx)
        ctx.progress(0.6)
        self._scripts(ctx)
        ctx.progress(1.0)

    def _history(self, ctx) -> None:
        rows = ctx.fs_files("lower(name) LIKE '%_history.txt' AND lower(path) LIKE '%\\psreadline\\%'", include_deleted=True)
        n = 0
        for row in rows:
            path = ctx.display_path(row["volume"], row["path"])
            try:
                text = ctx.read_entry(row, 50 * 1024 * 1024).decode("utf-8", "replace")
            except Exception:
                continue
            lines = text.splitlines()
            user = ctx.user_for_path(path)
            for i, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                sc = score_command(line)
                ts = parse_any(row.get("si_modified")) if i == len(lines) else None
                ctx.emit("ps_history", ts, {"line_no": i, "command": line[:8000], "score": sc["score"],
                                            "indicators": ", ".join(m["title"] for m in sc["matches"]), "mitre": sc["mitre"],
                                            "history_file": path, "file_modified": row.get("si_modified"), "total_lines": len(lines)},
                         user=user, summary=f"PS> {line[:200]}", source=f"{path} line {i}", ts_label="History file modified",
                         tags=["suspicious"] if sc["score"] >= 6 else None)
                n += 1
        ctx.coverage("PowerShell console history", "...\\PSReadLine\\ConsoleHost_history.txt", "found" if n else
                     ("not_found" if rows else "absent"), n)

    def _transcripts(self, ctx) -> None:
        rows = ctx.fs_files("lower(name) LIKE 'powershell_transcript.%.txt'", include_deleted=True, limit=5000)
        for row in rows:
            path = ctx.display_path(row["volume"], row["path"])
            try:
                text = ctx.read_entry(row, 20 * 1024 * 1024).decode("utf-8", "replace")
            except Exception:
                continue
            m = re.search(r"Start time:\s*(\d{14})", text)
            ts = parse_any(f"{m.group(1)[:4]}-{m.group(1)[4:6]}-{m.group(1)[6:8]} {m.group(1)[8:10]}:{m.group(1)[10:12]}:{m.group(1)[12:]}") if m else None
            u = re.search(r"Username:\s*(\S+)", text)
            h = re.search(r"Host Application:\s*(.+)", text)
            cmds = re.findall(r"(?:PS [^>]*>|Command start time: \d+)\s*(.+)", text)
            sc = score_command(text)
            ctx.emit("ps_transcript", ts or parse_any(row.get("si_created")), {
                "file": path, "start_time": ts, "user": u.group(1) if u else "", "host_application": h.group(1).strip() if h else "",
                "commands": " | ".join(cmds)[:4000], "score": sc["score"], "indicators": ", ".join(x["title"] for x in sc["matches"])},
                user=ctx.user_for_path(path), summary=f"Transcript {path}", source=path, ts_label="Start",
                tags=["suspicious"] if sc["score"] >= 6 else None)
        ctx.coverage("PowerShell transcripts", "PowerShell_transcript.*.txt", "found" if rows else "not_found", len(rows))

    def _scripts(self, ctx) -> None:
        ph = ",".join("?" * len(SCRIPT_EXT))
        rows = ctx.fs_files(f"ext IN ({ph})", SCRIPT_EXT, include_deleted=True, limit=200_000)
        n = 0
        for row in rows:
            low = (row["path"] or "").lower()
            if not any(w in low for w in USER_WRITABLE):
                continue
            if "\\microsoft\\windows\\start menu\\" in low or "\\recent\\" in low or "\\appdata\\local\\microsoft\\" in low and row["ext"] == "lnk":
                continue
            if row["ext"] == "lnk":
                continue  # handled by the LNK parser
            path = ctx.display_path(row["volume"], row["path"])
            preview, sc = "", {"score": 0, "matches": [], "mitre": []}
            if row["ext"] not in ("iso", "img", "vhd", "vhdx", "msi", "msix", "appx", "jar", "scr", "chm", "one", "xll") and \
                    (row.get("size") or 0) < 5 * 1024 * 1024:
                try:
                    data = ctx.read_entry(row, 2 * 1024 * 1024)
                    text = data.decode("utf-16-le", "replace") if data[:2] == b"\xff\xfe" else data.decode("utf-8", "replace")
                    sc = score_command(text)
                    preview = text[:300].replace("\r", " ").replace("\n", " ")
                except Exception:
                    pass
            base = 2 if row["ext"] in ("hta", "vbs", "js", "jse", "wsf", "vbe", "iso", "img", "scr", "chm", "xll", "one") else 0
            score = min(100, sc["score"] + base)
            ctx.emit("script_file", row.get("si_created"), {
                "path": path, "size": row.get("size"), "created": row.get("si_created"), "modified": row.get("si_modified"),
                "deleted": "Yes" if row.get("deleted") else "", "score": score,
                "indicators": ", ".join(m["title"] for m in sc["matches"]), "mitre": sc["mitre"], "preview": preview,
                "extension": row["ext"]}, user=ctx.user_for_path(path), summary=f"{row['ext'].upper()} file {path}", source=path,
                ts_label="Created", tags=["suspicious"] if score >= 6 else None)
            n += 1
        ctx.coverage("Scripts / containers in user-writable folders", "Temp, Downloads, AppData, ProgramData, Public, Desktop",
                     "found" if n else "not_found", n)
