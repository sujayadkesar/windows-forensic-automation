"""System overview and suspicious execution / persistence review (used by most profiles)."""

from __future__ import annotations

import re

from ..core.paths import PROTECTED_DATA
from ..knowledge import dual_use_tools, tool_for_exe, tool_for_program
from .base import INDICATED, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import basename, classify, command_paths, eqid, in_installed_program, norm_path, ref, short

USER_WRITABLE = re.compile(r"\\(appdata\\local\\temp|windows\\temp|users\\public|programdata|appdata\\roaming|downloads|"
                           r"appdata\\local(?!\\microsoft\\windowsapps)|desktop|\$recycle\.bin|recycler|"
                           r"local settings\\temp|local settings\\application data|application data)\\", re.I)
# binaries an ordinary user rarely runs; their execution is worth a look even without a command line.  Common admin
# binaries (net, regsvr32, wmic, msiexec, whoami, curl, tar) and the help viewer (hh.exe opens every .chm file) run
# routinely and are only reported when a logged command line matches a malicious pattern (scored commands).
RARE_LOLBINS = {"mshta.exe", "certutil.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe", "installutil.exe", "regasm.exe",
                "regsvcs.exe", "msbuild.exe", "cmstp.exe", "odbcconf.exe", "pcalua.exe", "finger.exe", "forfiles.exe",
                "psexec.exe", "psexec64.exe", "paexec.exe", "ntdsutil.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe",
                "nltest.exe", "sdelete.exe", "sdelete64.exe", "procdump.exe", "procdump64.exe", "rclone.exe", "ngrok.exe",
                "wevtutil.exe", "cipher.exe", "fsutil.exe"}


@analyzer
class SystemOverviewAnalyzer(Analyzer):
    id = "system_overview"
    title = "System overview"
    description = "Operating system, accounts, last logons, network configuration and installed software of each system."
    weight = 0.5

    def run(self, actx):
        for e in actx.windows_evidence():
            eid = e["id"]
            osd = e.get("os") or {}
            info = e.get("info") or {}
            rows = [["Computer name", osd.get("hostname") or osd.get("computer_name")],
                    ["Operating system", f"{osd.get('product_name') or ''} {osd.get('display_version') or ''} (build {osd.get('build')})"],
                    ["Installed (UTC)", short(osd.get("install_date"))], ["Registered owner", osd.get("registered_owner")],
                    ["Time zone", f"{osd.get('timezone_name')} ({osd.get('timezone_iana')})"],
                    ["Last shutdown (UTC)", short(osd.get("last_shutdown"))], ["IP address(es)", ", ".join(osd.get("ips") or [])],
                    ["Domain", osd.get("domain") or "-"]]
            for a in actx.artifacts("sys_info", eid):
                if a["data"].get("property") in ("Last logged on user", "ClearPageFileAtShutdown", "HibernateEnabled"):
                    rows.append([a["data"]["property"], a["data"].get("value")])
            rows = [r for r in rows if r[1] not in (None, "", " (build None)")]
            figs = [table_figure(f"{actx.ev_label(eid)} - system details", ["Property", "Value"], rows, style="app",
                                 col_widths=[220, 520], window_title="WFA - System Information")]
            acc = actx.artifacts("user_account", eid)
            profiles = info.get("users") or []
            urows = []
            for a in acc:
                d = a["data"]
                urows.append([d.get("name"), d.get("rid"), short(d.get("created")), short(d.get("last_logon")), d.get("logon_count"),
                              short(d.get("password_last_set")), d.get("flags")])
            if urows:
                figs.append(table_figure("Local user accounts (SAM)", ["Account", "RID", "Created", "Last logon", "Logons",
                                                                       "Password set", "Flags"], urows, style="table",
                                         sheet="Accounts", col_widths=[130, 50, 140, 140, 60, 140, 200]))
            progs = actx.artifacts("installed_program", eid)
            desc = (f"{actx.ev_label(eid)} runs {osd.get('product_name') or 'Windows'} (build {osd.get('build')}), installed "
                    f"{actx.t(osd.get('install_date'))}, configured for time zone {osd.get('timezone_name')}. "
                    f"User profiles: {', '.join(u.get('name', '') for u in profiles if not u.get('name', '').endswith('Service') and u.get('name') != 'systemprofile') or '-'}. "
                    f"{len(acc)} local accounts and {len(progs)} installed programs were recorded.")
            actx.finding(f"System overview - {actx.ev_label(eid)}", desc, evidence_id=eid, severity="info", confidence="high",
                         category="System", figures=figs, refs=[ref(a) for a in acc], tags=["overview"], sort_key=1)


BROWSER_CACHE = re.compile(r"\\(temporary internet files|inetcache|cache2|cache\\cache_data|code cache|"
                           r"service worker\\cachestorage|webcache)\\|\\user data\\[^\\]+\\cache\\|"
                           r"\\microsoft\.microsoftedge_8wekyb3d8bbwe\\ac\\(#!\d+|inetcache|microsoftedge\\cache)\\", re.I)
# installers unpack into Temp and run from there - normal software installation, not a finding on its own (WiX Burn
# bundles run their clean-room / engine copies from Temp\{GUID}\.cr and .be)
INSTALLER_TEMP = re.compile(r"\\temp\\(\{?[0-9a-f-]{36}\}?\\dismhost\.exe|\{[0-9a-f-]{36}\}\\\.(cr|be|ba)\\|"
                            r"ixp\d{3}\.tmp\\|~nsu\.tmp\\au_\.exe|ose\d{5}\.exe|"
                            r"[^\\]*setup[^\\]*\\|[^\\]*bootstrapper\\|msi[0-9a-f]+\.tmp|is-[a-z0-9]+\.tmp\\|ie[0-9a-f]+\.tmp\\|"
                            r"\{[0-9a-f-]{36}\}\\[^\\]*(setup|install|update)[^\\]*\.exe)", re.I)


DEFENDER_WEAKENING = re.compile(r"\\exclusions\\|\\disable\w*\s*=\s*0x1\b|disableantispyware\s*=\s*0x1|disableantivirus\s*=\s*0x1|"
                                r"spynetreporting\s*=\s*0x0\b|submitsamplesconsent\s*=\s*0x[02]\b|"
                                r"\\features\\tamperprotection\s*=\s*0x[04]\b", re.I)
RX_IP_URL = re.compile(r"^(?:https?|ftp)://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/", re.I)
EXE_EXT = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd")
SCRIPT_EXT = EXE_EXT + (".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".dll", ".cpl")


def user_writable_program(actx, eid, path, motw=None, ext=EXE_EXT) -> bool:
    """A program in a user-writable folder that is not part of a registered installed program (per-user apps such as
    OneDrive, Teams or VS Code live in AppData), not an installer unpacking itself in Temp, and not an installer run
    from Downloads that was downloaded from the vendor's own site (Mark of the Web)."""
    p = str(path or "")
    if not (USER_WRITABLE.search(p) and basename(p).lower().endswith(ext)) or INSTALLER_TEMP.search(p) or PROTECTED_DATA.search(p):
        return False
    if in_installed_program(actx, eid, p):
        return False
    n = norm_path(p)
    if motw is not None and "\\downloads\\" in n and classify(motw.get(n, ""))[0] == "Software vendor":
        return False
    return True


def writable_target(actx, eid, command) -> str:
    """The user-writable, unregistered program or script a persistence command starts ('' if none)."""
    return next((p for p in command_paths(command) if user_writable_program(actx, eid, p, ext=SCRIPT_EXT)), "")


@analyzer
class SuspiciousActivityAnalyzer(Analyzer):
    id = "suspicious_activity"
    title = "Suspicious execution and persistence"
    description = ("Scored commands (Run box, PowerShell, process creation, tasks, services, autoruns), living-off-the-land binaries, "
                   "programs run from user-writable folders, Defender detections and tampering.")
    weight = 1.2

    def run(self, actx):
        any_exec = any_persist = any_def = False
        for e in actx.windows_evidence():
            eid = e["id"]
            # ---------------------------------------------------------- scored commands
            rows, refs, mitre = [], [], set()
            for typ, field, label in (("run_mru", "command", "Run box (Win+R)"), ("ps_history", "command", "PowerShell history"),
                                      ("evt_powershell", "script", "PowerShell event"), ("evt_process", "command_line", "Process creation"),
                                      ("scheduled_task", "command", "Scheduled task"), ("service", "image_path", "Service"),
                                      ("autorun", "command", "Autostart entry"), ("script_file", "path", "Script file"),
                                      ("ps_transcript", "commands", "PowerShell transcript")):
                for a in actx.artifacts(typ, eid):
                    d = a["data"]
                    sc = d.get("score") or 0
                    if sc < 6:
                        continue
                    if typ == "script_file" and BROWSER_CACHE.search(str(d.get(field) or "")):
                        continue  # web page scripts cached by a browser were never run by the host's script engines
                    rows.append([short(a["ts"]), label, (d.get(field) or "")[:300], d.get("indicators") or "", a["user"] or ""])
                    refs.append(ref(a))
                    m = d.get("mitre") or []
                    mitre.update(m if isinstance(m, list) else [x.strip() for x in str(m).split(",") if x.strip()])
                    actx.timeline(eid, a["ts"], label, "Suspicious command", (d.get(field) or "")[:300], user=a["user"],
                                  ref_kind="artifact", ref_id=a["id"])
            if rows:
                any_exec = True
                rows.sort(key=lambda r: r[0] or "9999")
                fid = actx.finding(f"Suspicious commands and scripts on {actx.ev_label(eid)}",
                                   f"{len(rows)} commands or scripts match known malicious techniques (encoded PowerShell, download "
                                   "cradles, LOLBin abuse, defense tampering, persistence creation, log clearing, ...). Each entry shows "
                                   "the matching technique.", evidence_id=eid, severity="high", confidence="medium",
                                   category="Execution", ts=rows[0][0] or None, refs=refs[:200],
                                   figures=[table_figure(f"Suspicious commands - {actx.ev_label(eid)}",
                                                         ["Time (UTC)", "Source", "Command / script", "Technique(s)", "User"], rows[:30],
                                                         style="app", highlight_rows=list(range(min(30, len(rows)))),
                                                         col_widths=[140, 130, 430, 260, 80],
                                                         callouts=[callout(0, 2, 1, "Command matching a known attack technique")])],
                                   questions=["exec.suspicious"], tags=["execution"], mitre=sorted(mitre))
                actx.answer("exec.suspicious", YES, f"{actx.ev_label(eid)}: {len(rows)} suspicious commands / scripts.", [fid])
            # ---------------------------------------------------------- user-writable execution & LOLBins
            ex, exrefs = [], []
            seen = set()
            dual = dual_use_tools()
            motw = {norm_path(a["data"].get("file")): a["data"].get("host_url") or a["data"].get("referrer_url") or ""
                    for a in actx.artifacts("zone_identifier", eid)}
            # execution evidence only (Shimcache / Amcache record presence and file times, not runs); the time column
            # states what each source's timestamp means
            for typ, field, tlabel in (("prefetch", "path", "last run"), ("bam", "path", "last run"),
                                       ("userassist", "program", "last run"), ("evt_process", "process", "process start"),
                                       ("pca", "path", "run"), ("muicache", "path", "registered")):
                for a in actx.artifacts(typ, eid):
                    if a["data"].get("is_previous_run"):
                        continue
                    path = str(a["data"].get(field) or (a["data"].get("executable") if typ == "prefetch" else "") or "")
                    name = re.split(r"[\\/]", path)[-1].lower()
                    why = ""
                    if user_writable_program(actx, eid, path, motw):
                        why = "Executable in a user-writable folder"
                    elif name in RARE_LOLBINS and typ in ("prefetch", "evt_process", "bam", "userassist"):
                        why = "Living-off-the-land / dual-use binary"
                    tools = [t for _, t in tool_for_exe(name) if t in dual]
                    if tools and not why:
                        why = f"Dual-use tool ({tools[0]})"
                    if not why or (name, typ) in seen:
                        continue
                    seen.add((name, typ))
                    ex.append([short(a["ts"]), f"{typ} ({tlabel})", path[:200], why, a["user"] or ""])
                    exrefs.append(ref(a))
            # dual-use tools registered as installed programs (Uninstall keys), whether or not a run was recorded
            for a in actx.artifacts("installed_program", eid):
                tools = [t for _, t in tool_for_program(a["data"].get("name")) if t in dual]
                if tools and ("installed", tools[0]) not in seen:
                    seen.add(("installed", tools[0]))
                    ex.append([short(a["ts"]), "installed program (key last written)",
                               f"{a['data'].get('name')} {a['data'].get('version') or ''}".strip(),
                               f"Dual-use tool installed ({tools[0]})", a["user"] or ""])
                    exrefs.append(ref(a))
            # programs and scripts fetched straight from an IP address (no domain name) - how payloads are staged
            for typ, pfield, ufield, tlabel in (("web_download", "target_path", "url", "browser download"),
                                                ("zone_identifier", "file", "host_url", "Mark of the Web")):
                for a in actx.artifacts(typ, eid):
                    p, u = str(a["data"].get(pfield) or ""), str(a["data"].get(ufield) or "")
                    if RX_IP_URL.match(u) and basename(p).lower().endswith(SCRIPT_EXT + (".msi", ".zip", ".7z", ".rar", ".iso")) \
                            and (basename(p).lower(), "ipdl") not in seen:
                        seen.add((basename(p).lower(), "ipdl"))
                        ex.append([short(a["ts"]), f"{typ.replace('_', ' ')} ({tlabel})", p[:200],
                                   f"Downloaded directly from an IP address ({u[:120]})", a["user"] or ""])
                        exrefs.append(ref(a))
            if ex:
                any_exec = True
                ex.sort(key=lambda r: r[0] or "9999")
                fid = actx.finding(f"Programs of interest executed or present on {actx.ev_label(eid)}",
                                   f"{len(ex)} execution or installation records concern programs in user-writable folders "
                                   "that do not belong to an installed program, living-off-the-land binaries rarely used by "
                                   "ordinary users, or dual-use tools (remote access, credential theft, network scanning, "
                                   "wiping, data transfer).",
                                   evidence_id=eid, severity="medium", confidence="medium", category="Execution",
                                   ts=ex[0][0] or None, refs=exrefs[:200],
                                   figures=[table_figure(f"Programs of interest - {actx.ev_label(eid)}",
                                                         ["Time (UTC)", "Artifact (time meaning)", "Program", "Why it is of interest",
                                                          "User"], ex[:30],
                                                         style="app", col_widths=[140, 170, 400, 220, 80])],
                                   questions=["exec.suspicious"], tags=["execution"])
                actx.answer("exec.suspicious", INDICATED, f"{actx.ev_label(eid)}: {len(ex)} programs of interest were run.", [fid])
            # ---------------------------------------------------------- persistence
            pr, prefs = [], []
            # Mark of the Web from the Internet / untrusted zone: installers never leave it on the files they install, and
            # a move within the volume keeps it (a payload moved from Downloads to System32 still carries its origin)
            inet = {norm_path(a["data"].get("file")): a["data"].get("host_url") or a["data"].get("referrer_url") or "Internet zone"
                    for a in actx.artifacts("zone_identifier", eid) if str(a["data"].get("zone_id") or "") in ("3", "4")}
            # executables saved by a browser, by name: a payload copied to System32 loses its Mark of the Web but keeps its name
            fetched = {basename(a["data"].get("target_path")).lower(): a["data"].get("url") or ""
                       for a in actx.artifacts("web_download", eid)
                       if basename(a["data"].get("target_path")).lower().endswith(SCRIPT_EXT)}

            def downloaded(cmd):
                paths = command_paths(cmd)
                hit = next((inet[n] for n in map(norm_path, paths) if n in inet), "")
                if hit:
                    return f"Mark of the Web: {hit}"
                name = next((basename(p).lower() for p in paths if basename(p).lower() in fetched), "")
                return f"same name as a browser download from {fetched[name]}" if name else ""

            for typ, field, label in (("autorun", "command", "Autostart"), ("service", "image_path", "Service"),
                                      ("scheduled_task", "command", "Scheduled task"), ("wmi_subscription", "content", "WMI subscription")):
                for a in actx.artifacts(typ, eid):
                    d = a["data"]
                    sc = d.get("score") or 0
                    recent = actx.in_window(a["ts"]) if any(actx.window) else False
                    target = writable_target(actx, eid, d.get(field))
                    origin = downloaded(d.get(field))
                    if typ == "wmi_subscription" or sc >= 4 or target or origin or (recent and typ != "service"):
                        why = [d.get("indicators") or ""]
                        if target:
                            why.append("Starts a program from a user-writable folder that is not part of an installed program")
                        if origin:
                            why.append(f"Starts a program downloaded from the internet ({origin[:160]})")
                        pr.append([short(a["ts"]), label, d.get("name") or "", (d.get(field) or "")[:260],
                                   "; ".join(filter(None, why))])
                        prefs.append(ref(a))
            for a in actx.artifacts("evt_service", eid):
                d = a["data"]
                target = writable_target(actx, eid, d.get("image_path"))
                origin = downloaded(d.get("image_path"))
                if eqid(d) in (7045, 4697) and ((d.get("score") or 0) >= 4 or target or origin):
                    why = [d.get("indicators") or "", "Service program in a user-writable folder" if target else "",
                           f"Service program downloaded from the internet ({origin[:160]})" if origin else ""]
                    pr.append([short(a["ts"]), "Service installed (event)", d.get("service_name"), (d.get("image_path") or "")[:260],
                               "; ".join(filter(None, why))])
                    prefs.append(ref(a))
            if pr:
                any_persist = True
                pr.sort(key=lambda r: r[0] or "9999")
                fid = actx.finding(f"Persistence mechanisms of interest on {actx.ev_label(eid)}",
                                   f"{len(pr)} autostart entries, services, scheduled tasks or WMI subscriptions run commands from "
                                   "unusual locations, use suspicious techniques or were created in the period of interest.",
                                   evidence_id=eid, severity="high", confidence="medium", category="Persistence", ts=pr[0][0] or None,
                                   refs=prefs, figures=[table_figure(f"Persistence of interest - {actx.ev_label(eid)}",
                                                                     ["Registered / modified (UTC)", "Mechanism", "Name", "Command",
                                                                      "Technique(s)"], pr[:30], style="app",
                                                                     col_widths=[150, 120, 160, 400, 220])],
                                   questions=["persist.found"], tags=["persistence"], mitre=["T1547", "T1543", "T1053"])
                actx.answer("persist.found", YES, f"{actx.ev_label(eid)}: {len(pr)} persistence entries of interest.", [fid])
            # ---------------------------------------------------------- defender
            # detections, and configuration changes that weaken protection.  Event 5007 is also logged for every routine
            # setting written by platform / signature updates (product type, engine ring, service state, ...): only
            # exclusions, Disable* switched on, cloud protection or sample submission off and tamper protection off count.
            dv = [a for a in actx.artifacts("evt_defender", eid)
                  if a["data"].get("event_id") not in (5007, 5004) or DEFENDER_WEAKENING.search(str(a["data"].get("new_value") or ""))]
            if dv:
                any_def = True
                rows = [[short(a["ts"]), a["data"].get("event_id"), a["data"].get("description"), a["data"].get("threat") or
                         a["data"].get("new_value") or "", (a["data"].get("path") or "")[:200], a["data"].get("action") or ""] for a in dv]
                tamper = [r for r in rows if r[1] in (5001, 5004, 5007, 5010, 5012, 5013)]
                fid = actx.finding(f"Microsoft Defender detections / configuration changes on {actx.ev_label(eid)}",
                                   f"{len(rows) - len(tamper)} detection events and {len(tamper)} configuration changes (protection "
                                   "disabled, exclusions added) were logged by Microsoft Defender.", evidence_id=eid, severity="high",
                                   confidence="high", category="Malware", ts=rows[0][0] or None, refs=[ref(a) for a in dv],
                                   figures=[table_figure("Microsoft Defender events", ["Time (UTC)", "Event ID", "Description",
                                                                                       "Threat / setting", "Path", "Action"], rows[:25],
                                                         style="eventlog", highlight_rows=list(range(min(25, len(rows)))),
                                                         col_widths=[140, 70, 210, 230, 300, 110])],
                                   questions=["defender"], tags=["defender"], mitre=["T1562.001"] if tamper else [])
                actx.answer("defender", YES, f"{actx.ev_label(eid)}: {len(rows) - len(tamper)} detections, {len(tamper)} configuration changes.",
                            [fid])
        if not any_exec:
            actx.answer("exec.suspicious", NO, "No suspicious commands, programs in user-writable folders or dual-use tools were found.", [])
        if not any_persist:
            actx.answer("persist.found", NO, "No autostart entries, services, tasks or WMI subscriptions of interest were found.", [])
        if not any_def:
            st = "No evidence found"
            actx.answer("defender", st, "No Microsoft Defender detection or tampering events were found (the log may be absent).", [])
