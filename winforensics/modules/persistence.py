"""Persistence mechanisms: Run keys, services, scheduled tasks, startup folders, Winlogon, IFEO, WMI subscriptions."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..core.paths import PROTECTED_DATA, command_paths, norm_path
from ..core.timeutil import db_ts, parse_any
from ..knowledge import score_command, tool_for_exe
from ._regutil import iter_keys, key_user, subkeys, ts_of, val, values
from .base import ArtifactModule, ArtifactType, C, register

RUN_KEYS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
]
START = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
SVC_TYPE = {1: "Kernel driver", 2: "File system driver", 16: "Own process", 32: "Shared process", 272: "Own process (interactive)",
            288: "Shared process (interactive)"}
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def parse_task_xml(raw: bytes):
    """Task Scheduler XML.  Windows writes UTF-16 with a BOM and `encoding="UTF-16"` in the declaration; the text is
    decoded here and the declaration dropped, so the parser does not reject re-encoded input."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw[3:].decode("utf-8", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text.lstrip("﻿"))
    return ET.fromstring(text)


def _score(cmd: str) -> tuple[int, str, list]:
    sc = score_command(cmd)
    low = (cmd or "").lower()
    extra = 0
    reasons = [m["title"] for m in sc["matches"]]
    # judged on the program the entry starts (and scripts it passes to an interpreter), not on other arguments
    if any(re.search(r"\\(appdata|temp|programdata|users\\public|downloads)\\", p) and not PROTECTED_DATA.search(p)
           for p in map(norm_path, command_paths(cmd))):
        extra += 3
        reasons.append("Runs from user-writable folder")
    if any(fam == "remote_access" for fam, _ in tool_for_exe(re.split(r"\s", low.strip('"'))[0] if low else "")):
        extra += 4
        reasons.append("Remote access tool")
    return min(100, sc["score"] + extra), ", ".join(dict.fromkeys(reasons)), sc["mitre"]


@register
class PersistenceModule(ArtifactModule):
    id = "persistence"
    title = "Persistence mechanisms"
    category = "Persistence"
    description = ("Run/RunOnce keys, services, scheduled tasks (XML), startup folders, Winlogon shell/userinit, IFEO debuggers, "
                   "AppInit DLLs and WMI event subscriptions - each command scored for suspicious traits.")
    weight = 2.5
    order = 30
    requires = ["filesystem"]
    locations = RUN_KEYS[:2] + ["SYSTEM\\CurrentControlSet\\Services", "C:\\Windows\\System32\\Tasks",
                                "...\\Start Menu\\Programs\\Startup", "SOFTWARE\\...\\Winlogon", "SOFTWARE\\...\\Image File Execution Options",
                                "C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA"]
    artifact_types = [
        ArtifactType("autorun", "Autostart Entries (Run keys / Winlogon / IFEO / Startup)", "Persistence",
                     [C("location", width=300), C("name", width=200), C("command", width=420), C("user"),
                      C("key_last_written", kind="datetime"), C("score", kind="int"), C("indicators", width=260)],
                     ts_label="Key last written"),
        ArtifactType("service", "Services", "Persistence",
                     [C("name", width=180), C("display_name", width=200), C("image_path", kind="path", width=380),
                      C("service_dll", "ServiceDll", "path", 260), C("start"), C("type"), C("account"),
                      C("key_last_written", kind="datetime"), C("score", kind="int"), C("indicators", width=240)],
                     ts_label="Key last written"),
        ArtifactType("scheduled_task", "Scheduled Tasks", "Persistence",
                     [C("name", width=260), C("command", width=420), C("author"), C("run_as", "Run As"), C("triggers", width=220),
                      C("registered", kind="datetime"), C("hidden"), C("enabled"), C("file_modified", kind="datetime"),
                      C("score", kind="int"), C("indicators", width=240)], ts_label="Registered / file modified"),
        ArtifactType("wmi_subscription", "WMI Event Subscriptions", "Persistence",
                     [C("kind"), C("name", width=200), C("content", width=520)]),
    ]

    def run(self, ctx) -> None:
        reg = ctx.target.registry
        for i, fn in enumerate([self._runkeys, self._winlogon, self._services, self._tasks, self._startup, self._wmi]):
            try:
                fn(ctx, reg)
            except Exception as e:
                ctx.warn(f"persistence {fn.__name__}: {e}")
                ctx.coverage(fn.__name__.strip("_"), "", "error", 0, str(e)[:200])
            ctx.progress((i + 1) / 6)

    def _emit_autorun(self, ctx, location, name, cmd, user, ts, source):
        score, ind, mitre = _score(str(cmd))
        ctx.emit("autorun", ts, {"location": location, "name": name, "command": str(cmd), "user": user,
                                 "key_last_written": db_ts(ts), "score": score, "indicators": ind, "mitre": mitre},
                 user=user, summary=f"Autorun {name}: {str(cmd)[:200]}", source=source, ts_label="Key last written",
                 tags=["suspicious"] if score >= 6 else None)

    def _runkeys(self, ctx, reg) -> None:
        n = 0
        for path in RUN_KEYS:
            for k in iter_keys(reg, path):
                user = key_user(reg, k) if path.startswith("HKCU") else None
                for v in values(k):
                    self._emit_autorun(ctx, path, v.name, v.value, user, ts_of(k), path)
                    n += 1
                for sk in subkeys(k):  # RunOnceEx style
                    for v in values(sk):
                        self._emit_autorun(ctx, f"{path}\\{sk.name}", v.name, v.value, user, ts_of(sk), path)
                        n += 1
        ctx.coverage("Run / RunOnce keys", "HKLM + HKCU ...\\CurrentVersion\\Run*", "found" if n else "not_found", n)

    def _winlogon(self, ctx, reg) -> None:
        n = 0
        defaults = {"shell": "explorer.exe", "userinit": "c:\\windows\\system32\\userinit.exe,"}
        for path in ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"):
            for k in iter_keys(reg, path):
                for name in ("Shell", "Userinit", "Taskman", "AppSetup"):
                    v = val(k, name)
                    if v and str(v).strip().lower() != defaults.get(name.lower(), "").lower():
                        self._emit_autorun(ctx, path, name, v, key_user(reg, k) if "HKCU" in path else None, ts_of(k), path)
                        n += 1
        for k in iter_keys(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"):
            for sk in subkeys(k):
                dbg = val(sk, "Debugger")
                if dbg:
                    self._emit_autorun(ctx, "IFEO Debugger", sk.name, dbg, None, ts_of(sk), "Image File Execution Options")
                    n += 1
                try:
                    gf = int(val(sk, "GlobalFlag") or 0)
                except (TypeError, ValueError):
                    gf = 0
                if gf & 0x200:
                    self._emit_autorun(ctx, "IFEO SilentProcessExit", sk.name, f"GlobalFlag={gf:#x}", None, ts_of(sk), "IFEO")
                    n += 1
        for path in ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                     "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"):
            for k in iter_keys(reg, path):
                v = val(k, "AppInit_DLLs")
                if v:
                    self._emit_autorun(ctx, "AppInit_DLLs", "AppInit_DLLs", v, None, ts_of(k), path)
                    n += 1
        for k in iter_keys(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"):
            v = val(k, "BootExecute")
            if v and (v if isinstance(v, list) else [v]) != ["autocheck autochk *"]:
                self._emit_autorun(ctx, "BootExecute", "BootExecute", v, None, ts_of(k), "Session Manager")
                n += 1
        for k in iter_keys(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"):
            for name in ("Security Packages", "Authentication Packages", "Notification Packages"):
                v = val(k, name)
                vals = [x for x in (v if isinstance(v, list) else [v]) if x]
                odd = [x for x in vals if x.lower() not in ("kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u",
                                                             "cloudap", "scecli", "rassfm", '""', "negoexts", "livessp")]
                if odd:
                    self._emit_autorun(ctx, f"LSA {name}", name, ", ".join(vals), None, ts_of(k), "Control\\Lsa")
                    n += 1
        ctx.coverage("Winlogon / IFEO / AppInit / LSA", "SOFTWARE\\...\\Winlogon, IFEO, AppInit_DLLs, Control\\Lsa", "found" if n else "not_found", n)

    def _services(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Services"):
            for s in subkeys(k):
                img = val(s, "ImagePath")
                if not img:
                    continue
                dll = None
                try:
                    dll = val(s.subkey("Parameters"), "ServiceDll")
                except Exception:
                    pass
                start = val(s, "Start")
                typ = val(s, "Type")
                score, ind, mitre = _score(f"{img} {dll or ''}")
                if typ in (1, 2):
                    score = max(0, score - 2)
                rec = {"name": s.name, "display_name": val(s, "DisplayName"), "image_path": img, "service_dll": dll,
                       "start": START.get(start, start), "type": SVC_TYPE.get(typ, typ), "account": val(s, "ObjectName"),
                       "description": val(s, "Description"), "key_last_written": db_ts(ts_of(s)), "score": score,
                       "indicators": ind, "mitre": mitre}
                ctx.emit("service", ts_of(s), rec, summary=f"Service {s.name}: {img}", ts_label="Key last written",
                         source=f"SYSTEM\\CurrentControlSet\\Services\\{s.name}", tags=["suspicious"] if score >= 6 else None)
                n += 1
        ctx.coverage("Services", "SYSTEM\\CurrentControlSet\\Services", "found" if n else "not_found", n)

    def _tasks(self, ctx, reg) -> None:
        rows = ctx.fs_files("lower(path) LIKE '\\windows\\system32\\tasks\\%'", limit=20000)
        n, bad = 0, 0
        for row in rows:
            try:
                root = parse_task_xml(ctx.read_entry(row, 1_000_000))
            except Exception:
                bad += 1
                continue

            def f(path):
                el = root.find(path, NS)
                return el.text.strip() if el is not None and el.text else ""

            cmds = []
            for ex in root.findall(".//t:Actions/t:Exec", NS):
                c = ex.find("t:Command", NS)
                a = ex.find("t:Arguments", NS)
                cmds.append(((c.text or "") if c is not None else "") + (" " + a.text if a is not None and a.text else ""))
            for ch in root.findall(".//t:Actions/t:ComHandler", NS):
                cid = ch.find("t:ClassId", NS)
                cmds.append(f"COM {cid.text if cid is not None else ''}")
            trig = [t.tag.split("}")[-1] for t in (root.find("t:Triggers", NS) or [])]
            cmd = " | ".join(cmds)
            score, ind, mitre = _score(cmd)
            name = row["path"][len("\\Windows\\System32\\Tasks"):]
            if name.lower().startswith("\\microsoft\\") and score < 6:
                score = max(0, score - 2)
            reg_date = parse_any(f(".//t:RegistrationInfo/t:Date"))
            rec = {"name": name, "command": cmd, "author": f(".//t:RegistrationInfo/t:Author"),
                   "description": f(".//t:RegistrationInfo/t:Description")[:300], "run_as": f(".//t:Principals/t:Principal/t:UserId"),
                   "triggers": ", ".join(trig), "registered": db_ts(reg_date), "hidden": f(".//t:Settings/t:Hidden"),
                   "enabled": f(".//t:Settings/t:Enabled") or "true", "file_created": row.get("si_created"),
                   "file_modified": row.get("si_modified"), "score": score, "indicators": ind, "mitre": mitre}
            ctx.emit("scheduled_task", reg_date or row.get("si_modified"), rec, summary=f"Task {name}: {cmd[:200]}",
                     source=ctx.display_path(row["volume"], row["path"]), ts_label="Registered",
                     tags=["suspicious"] if score >= 6 else None)
            n += 1
        ctx.coverage("Scheduled tasks", "C:\\Windows\\System32\\Tasks", "found" if n else ("not_found" if rows else "absent"), n,
                     f"{bad} task file(s) could not be parsed" if bad else "")

    def _startup(self, ctx, reg) -> None:
        rows = ctx.fs_files("lower(path) LIKE '%\\start menu\\programs\\startup\\%' AND lower(name) <> 'desktop.ini'")
        for row in rows:
            p = ctx.display_path(row["volume"], row["path"])
            self._emit_autorun(ctx, "Startup folder", row["name"], p, ctx.user_for_path(p), parse_any(row.get("si_created")), p)
        ctx.coverage("Startup folders", "...\\Start Menu\\Programs\\Startup", "found" if rows else "not_found", len(rows))

    # bound consumers that ship with Windows
    WMI_BENIGN = ("SCM Event Log Consumer", "BVTConsumer", "NTEventLogEventConsumer")

    def _wmi(self, ctx, reg) -> None:
        """Event consumers bound to a filter (__FilterToConsumerBinding) - the WMI persistence mechanism - parsed from the CIM
        repository.  Class definitions present on every system are not reported."""
        n = ignored = 0
        if not ctx.exists("C:/Windows/System32/wbem/Repository/OBJECTS.DATA"):
            ctx.coverage("WMI subscriptions", "wbem\\Repository (CIM)", "absent", 0, "no WMI repository on this system")
            return
        try:
            for r in ctx.plugin("cim.consumerbindings"):
                script = r.get("script_text") or r.get("script_file_name")
                kind = "ActiveScriptEventConsumer" if script or r.get("scripting_engine") else "CommandLineEventConsumer"
                content = r.get("command_line_template") or r.get("executable_path") or script or ""
                name = r.get("name") or r.get("consumer_name") or ""
                if any(b.lower() in f"{name} {r.get('filter_name') or ''}".lower() for b in self.WMI_BENIGN) or (
                        (r.get("filter_name") or "") == "BVTFilter" and "kerncap.vbs" in str(content).lower()):
                    ignored += 1  # subscriptions that ship with Windows (e.g. Windows 7 BVTFilter -> cscript KernCap.vbs)
                    continue
                sc = score_command(str(content))
                ctx.emit("wmi_subscription", None, {
                    "kind": kind, "name": name, "content": str(content)[:2000], "filter_name": r.get("filter_name"),
                    "filter_query": r.get("filter_query"), "creator_sid": r.get("creator_sid"),
                    "working_directory": r.get("working_directory"), "scripting_engine": r.get("scripting_engine"),
                    "score": max(60, sc["score"]), "indicators": ", ".join(m["title"] for m in sc["matches"]) or "WMI event subscription",
                    "mitre": sorted(set(["T1546.003"] + sc["mitre"]))},
                    summary=f"WMI {kind} '{name}' bound to filter '{r.get('filter_name')}': {str(content)[:160]}",
                    source="C:\\Windows\\System32\\wbem\\Repository", tags=["suspicious", "persistence"])
                n += 1
        except Exception as e:
            if type(e).__name__ == "UnsupportedPluginError":
                ctx.coverage("WMI subscriptions", "wbem\\Repository (CIM)", "absent", 0, "WMI repository not present / not readable")
                return
            ctx.warn(f"WMI repository: {type(e).__name__}: {e}")
            ctx.coverage("WMI subscriptions", "wbem\\Repository (CIM)", "error", 0, str(e)[:200])
            return
        ctx.coverage("WMI subscriptions", "wbem\\Repository (CIM: __FilterToConsumerBinding)", "found" if n else "not_found", n,
                     f"{ignored} default Windows subscription(s) not reported" if ignored else "")
