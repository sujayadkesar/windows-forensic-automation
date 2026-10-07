"""Scenario analyzers: ClickFix, phishing, remote access / RMM, account activity, ransomware."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta

from ..core.timeutil import from_db
from ..knowledge import clickfix_terms, score_command
from .base import INCONCLUSIVE, INDICATED, NA, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import basename, classify, ref, short

RISKY_ATTACH = re.compile(r"\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|iso|img|vhdx?|zip|rar|7z|r\d\d|ace|gz|"
                          r"docm|xlsm|pptm|xlsb|xll|one|html?|svg|msi|jar|cab|chm|url|library-ms)$", re.I)
OFFICE_APPS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe")
CHILD_SUSPECT = ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
                 "certutil.exe", "bitsadmin.exe", "msiexec.exe", "curl.exe")


# ============================================================================ ClickFix
@analyzer
class ClickFixAnalyzer(Analyzer):
    id = "clickfix"
    title = "ClickFix / paste-and-run"
    description = ("Commands pasted into the Run box / terminal (RunMRU, PowerShell history, script-block logs), the lure page "
                   "visited just before, and what was downloaded, executed and persisted just after.")
    weight = 1.0

    def run(self, actx):
        terms = clickfix_terms()
        found = False
        for e in actx.windows_evidence():
            eid = e["id"]
            label = actx.ev_label(eid)
            cmds = []
            for typ, field in (("run_mru", "command"), ("ps_history", "command"), ("evt_powershell", "script"), ("evt_process", "command_line")):
                for a in actx.artifacts(typ, eid):
                    v = a["data"].get(field) or ""
                    sc = a["data"].get("score") or score_command(v)["score"]
                    paste_like = typ == "run_mru" and re.search(r"powershell|pwsh|mshta|cmd(\.exe)?\s+/c|curl|bitsadmin|certutil|"
                                                                 r"rundll32|regsvr32|msiexec|wscript|finger", v, re.I)
                    lure = any(t in v.lower() for t in terms)
                    if (typ == "run_mru" and (paste_like or sc >= 4)) or lure or (typ != "evt_process" and sc >= 8):
                        cmds.append((a, typ, v, sc))
            if not cmds:
                continue
            found = True
            rows = []
            fids = []
            for a, typ, v, sc in cmds:
                t = a["ts"] or a["data"].get("key_last_written")
                rows.append([short(t), {"run_mru": "Run box (Win+R)", "ps_history": "PowerShell history", "evt_powershell": "Script block log",
                                        "evt_process": "Process creation"}[typ], v[:300], a["data"].get("indicators") or "", a["user"] or ""])
                actx.timeline(eid, t, "ClickFix", "Command pasted / run", v[:300], user=a["user"], ref_kind="artifact", ref_id=a["id"])
            calls = [callout(0, 2, 1, "Command typed / pasted by the user (MRU #0 key time = when it was run)")]
            fids.append(actx.finding(f"Command(s) pasted into the Run box or a terminal on {label}",
                                     f"{len(rows)} commands that match the ClickFix / fake-CAPTCHA pattern were found. In this attack the "
                                     "web page silently places a command on the clipboard and instructs the user to press Win+R, "
                                     "Ctrl+V and Enter; the Run box history (RunMRU) keeps the pasted command.",
                                     evidence_id=eid, severity="high", confidence="high", category="ClickFix", ts=rows[0][0] or None,
                                     refs=[ref(c[0]) for c in cmds],
                                     figures=[table_figure(f"Pasted commands - {label}", ["Time (UTC)", "Source", "Command", "Technique(s)",
                                                                                          "User"], rows[:20], style="app",
                                                           highlight_rows=list(range(min(20, len(rows)))), col_widths=[140, 130, 470, 220, 80],
                                                           callouts=calls)],
                                     questions=["clickfix.command"], tags=["clickfix"], mitre=["T1204.004", "T1059.001"]))
            actx.answer("clickfix.command", YES, f"{label}: {len(rows)} pasted / typed commands of the ClickFix pattern.", fids[-1:])
            anchor = min((from_db(r[0]) for r in rows if r[0]), default=None)
            if anchor is None:
                continue
            # lure page(s): browser visits in the 30 minutes before the command
            lure = []
            for a in actx.artifacts("web_visit", eid):
                t = from_db(a["ts"])
                if t and anchor - timedelta(minutes=30) <= t <= anchor + timedelta(minutes=2):
                    title = (a["data"].get("title") or "") + " " + (a["data"].get("url") or "")
                    hit = any(term in title.lower() for term in terms)
                    lure.append([short(a["ts"]), a["data"].get("title") or "", a["data"].get("url"), "lure wording" if hit else "",
                                 a["data"].get("browser")])
            if lure:
                hl = [i for i, r in enumerate(lure) if r[3]]
                fid = actx.finding(f"Web pages visited just before the pasted command on {label}",
                                   "Browser history in the 30 minutes before the command shows the page that most likely delivered the "
                                   "lure (fake CAPTCHA / 'verify you are human' / fake browser update).", evidence_id=eid,
                                   severity="high", confidence="medium", category="ClickFix",
                                   figures=[table_figure("Browser history before the command", ["Visited (UTC)", "Title", "URL",
                                                                                                 "Lure wording", "Browser"],
                                                         lure[-25:], style="app", highlight_rows=[i - max(0, len(lure) - 25) for i in hl if i >= len(lure) - 25],
                                                         col_widths=[140, 260, 420, 100, 80])],
                                   questions=["clickfix.lure"], tags=["clickfix", "web"], mitre=["T1189"])
                actx.answer("clickfix.lure", YES if hl else INDICATED, f"{label}: {len(lure)} page(s) visited before the command"
                                                                       + (f", {len(hl)} with lure wording" if hl else "") + ".", [fid])
            # aftermath: files created, executions, persistence in the next 60 minutes
            after = []
            window_end = anchor + timedelta(minutes=60)
            for r in actx.db.query("SELECT path, volume, si_created, name FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND si_created>=? "
                                   "AND si_created<=? AND (lower(path) LIKE '%\\appdata\\%' OR lower(path) LIKE '%\\temp\\%' OR "
                                   "lower(path) LIKE '%\\programdata\\%' OR lower(path) LIKE '%\\users\\public\\%' OR lower(path) LIKE "
                                   "'%\\downloads\\%') ORDER BY si_created LIMIT 200",
                                   (eid, anchor.strftime("%Y-%m-%d %H:%M:%S"), window_end.strftime("%Y-%m-%d %H:%M:%S"))):
                if r["name"].lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".zip", ".msi", ".lnk",
                                               ".scr", ".jar", ".py", ".dat", ".bin", ".tmp")):
                    after.append([short(r["si_created"]), "File created", actx.ev_label(eid).split(" (")[0], f"{r['volume']}{r['path']}"])
            for typ, field in (("prefetch", "executable"), ("bam", "path"), ("evt_process", "process"), ("autorun", "command"),
                               ("scheduled_task", "command"), ("evt_service", "image_path"), ("web_download", "target_path")):
                for a in actx.artifacts(typ, eid):
                    t = from_db(a["ts"])
                    if t and anchor - timedelta(seconds=30) <= t <= window_end and not a["data"].get("is_previous_run"):
                        after.append([short(a["ts"]), typ.replace("_", " "), "", str(a["data"].get(field) or "")[:240]])
            if after:
                after.sort(key=lambda r: r[0])
                fid = actx.finding(f"Activity in the hour after the pasted command on {label}",
                                   f"{len(after)} files created in user-writable folders, programs executed, downloads and persistence "
                                   "entries in the 60 minutes after the command - the payload chain started by the command.",
                                   evidence_id=eid, severity="high", confidence="medium", category="ClickFix",
                                   figures=[table_figure("After the command (60 minutes)", ["Time (UTC)", "Activity", "", "Detail"],
                                                         after[:30], style="app", col_widths=[140, 140, 10, 640])],
                                   questions=["clickfix.payload"], tags=["clickfix"])
                actx.answer("clickfix.payload", YES, f"{label}: {len(after)} follow-on activities within 60 minutes.", [fid])
        if not found:
            for q in ("clickfix.command", "clickfix.lure", "clickfix.payload"):
                actx.answer(q, NO, "No pasted / typed command matching the ClickFix pattern was found in RunMRU, PowerShell history "
                                   "or script-block logs.", [])


# ============================================================================ phishing
@analyzer
class PhishingAnalyzer(Analyzer):
    id = "phishing"
    title = "Phishing"
    description = ("Risky e-mail attachments, files downloaded from mail, Office documents with macros enabled, Office applications "
                   "spawning interpreters, disk images mounted, credential-harvest pages.")
    weight = 1.0

    def run(self, actx):
        ioc = actx.inputs.get("iocs") or {}
        senders = {e.lower() for e in ioc.get("emails", [])}
        any_mail = any_open = any_exec = False
        for e in actx.windows_evidence():
            eid = e["id"]
            label = actx.ev_label(eid)
            att = [a for a in actx.artifacts("email_attachment", eid) if RISKY_ATTACH.search(a["data"].get("filename") or "")
                   or any(s in (a["data"].get("sender") or "").lower() for s in senders)]
            msgs = [m for m in actx.artifacts("email_message", eid) if any(s in (m["data"].get("sender") or "").lower() for s in senders)]
            # Windows Search index: messages / attachments that may since have been deleted from the mailbox
            idx = [a for a in actx.artifacts("search_index_item", eid) if a["data"].get("sent")]
            idx_att = [a for a in idx if " : " in (a["data"].get("path") or "") and
                       RISKY_ATTACH.search(a["data"]["path"].rsplit(" : ", 1)[-1])]
            idx_msgs = [a for a in idx if senders and any(s in (a["data"].get("from") or "").lower() for s in senders)]
            if att or msgs or idx_att or idx_msgs:
                any_mail = True
                rows = [[short(a["ts"]), a["data"].get("sender"), a["data"].get("subject"), a["data"].get("filename"),
                         (a["data"].get("sha256") or "")[:16], "Mailbox"] for a in att] + \
                       [[short(m["ts"]), m["data"].get("sender"), m["data"].get("subject"), m["data"].get("attachment_names"), "",
                         "Mailbox"] for m in msgs] + \
                       [[short(a["data"].get("sent")), a["data"].get("from") or "", a["data"].get("subject"),
                         a["data"]["path"].rsplit(" : ", 1)[-1] if " : " in a["data"]["path"] else "", "", "Windows Search index"]
                        for a in idx_att + idx_msgs]
                att = att + idx_att
                msgs = msgs + idx_msgs
                fid = actx.finding(f"E-mails with risky attachments / from the reported sender on {label}",
                                   f"{len(rows)} messages carry executable, script, archive, disk-image or macro-enabled attachments, or "
                                   "come from the sender(s) named in the case inputs.", evidence_id=eid, severity="high", confidence="high",
                                   category="Phishing", refs=[ref(a) for a in att + msgs],
                                   figures=[table_figure("Suspicious e-mails", ["Time (UTC)", "From", "Subject", "Attachment", "SHA-256",
                                                                                "Source"],
                                                         rows[:30], style="table", col_widths=[140, 220, 260, 220, 140, 150])],
                                   questions=["phish.email"], tags=["phishing", "email"], mitre=["T1566.001"])
                actx.answer("phish.email", YES, f"{label}: {len(rows)} suspicious messages.", [fid])
            # opened / enabled content
            opened = []
            for a in actx.artifacts("trusted_doc", eid):
                opened.append([short(a["ts"]), "Office 'Enable content' (Trusted Documents)", a["data"].get("path"),
                               "macros enabled" if a["data"].get("macros_enabled") == "Yes" else "editing enabled"])
            sample_names = {(t.get("name") or "").lower() for t in actx.inputs.get("targets") or [] if t.get("name")}
            for a in actx.artifacts("zone_identifier", eid):
                c, svc = classify(a["data"].get("host_url") or a["data"].get("referrer_url") or "")
                f = a["data"].get("file") or ""
                # a downloaded program is not phishing on its own: it must come from mail, or be a supplied sample / IOC
                from_mail = c in ("Webmail", "Mail attachment") or re.search(r"content\.outlook|\\olk[0-9a-f]+\\", f, re.I)
                named = f.rsplit("\\", 1)[-1].lower() in sample_names
                if from_mail or (named and RISKY_ATTACH.search(f)):
                    opened.append([short(a["ts"]), f"Downloaded file ({svc or 'internet'})", a["data"].get("file"),
                                   a["data"].get("host_url") or a["data"].get("referrer_url")])
            for a in actx.artifacts("usb_event", eid):
                if "virtual_disk" in (a.get("tags") or "") or "Virtual disk" in (a["data"].get("event") or "").title():
                    opened.append([short(a["ts"]), "Disk image mounted (VHDMP)", a["data"].get("product"), a["data"].get("details")])
            for a in actx.artifacts(("office_mru", "recent_doc"), eid):
                v = a["data"].get("path") or a["data"].get("name") or ""
                if re.search(r"content\.outlook|inetcache|\\temp\\|\\downloads\\", v, re.I):
                    opened.append([short(a["ts"]), "Document opened from mail cache / downloads", v, ""])
            if opened:
                any_open = True
                opened.sort(key=lambda r: r[0] or "9999")
                fid = actx.finding(f"Attachments / downloads opened and active content enabled on {label}",
                                   f"{len(opened)} records show documents from e-mail or the internet being opened, active content "
                                   "enabled, or disk images mounted.", evidence_id=eid, severity="high", confidence="medium",
                                   category="Phishing", figures=[table_figure("Opened content", ["Time (UTC)", "Record", "File", "Detail"],
                                                                              opened[:30], style="app", col_widths=[140, 260, 380, 260])],
                                   questions=["phish.opened"], tags=["phishing"], mitre=["T1204.002"])
                actx.answer("phish.opened", YES, f"{label}: {len(opened)} records of opened attachments / enabled content.", [fid])
            # office spawning interpreters
            kids = []
            for a in actx.artifacts("evt_process", eid):
                par = basename(a["data"].get("parent")).lower()
                child = basename(a["data"].get("process")).lower()
                if par in OFFICE_APPS + ("acrord32.exe", "foxitreader.exe") and child in CHILD_SUSPECT:
                    kids.append([short(a["ts"]), par, child, (a["data"].get("command_line") or "")[:300]])
            if kids:
                any_exec = True
                fid = actx.finding(f"Office / PDF application launched an interpreter on {label}",
                                   f"{len(kids)} process-creation events show a document application starting a command interpreter or "
                                   "LOLBin - the typical result of a malicious macro or exploit.", evidence_id=eid, severity="high",
                                   confidence="high", category="Phishing",
                                   figures=[table_figure("Suspicious child processes", ["Time (UTC)", "Parent", "Child", "Command line"],
                                                         kids[:25], style="eventlog", col_widths=[140, 130, 130, 520])],
                                   questions=["phish.executed"], tags=["phishing", "execution"], mitre=["T1204.002", "T1059"])
                actx.answer("phish.executed", YES, f"{label}: {len(kids)} interpreter launches by document applications.", [fid])
            # credential harvesting pages
            harv = []
            for a in actx.artifacts("web_visit", eid):
                t = (a["data"].get("title") or "").lower()
                u = (a["data"].get("url") or "").lower()
                if re.search(r"sign ?in|log ?in|verify|account|password|office ?365|microsoft 365|outlook|onedrive|sharepoint|docusign", t) and \
                        not re.search(r"(microsoft(online)?|live|office|google|outlook|apple|amazon|linkedin|facebook)\.com/", u) and \
                        not u.startswith(("https://login.", "https://accounts.google")):
                    harv.append([short(a["ts"]), a["data"].get("title"), a["data"].get("url")])
            if harv:
                fid = actx.finding(f"Possible credential-harvesting pages visited on {label}",
                                   f"{len(harv)} visits to pages titled like sign-in / verification pages but hosted outside the genuine "
                                   "service domains.", evidence_id=eid, severity="medium", confidence="low", category="Phishing",
                                   figures=[table_figure("Sign-in-like pages on other domains", ["Visited (UTC)", "Title", "URL"], harv[:25],
                                                         style="app", col_widths=[140, 300, 560])],
                                   questions=["phish.credentials"], tags=["phishing"], mitre=["T1566.002"])
                actx.answer("phish.credentials", INDICATED, f"{label}: {len(harv)} sign-in-like pages on unusual domains.", [fid])
        if not any_mail:
            actx.answer("phish.email", NO, "No risky attachment or message from the reported sender was found in the mail stores examined.", [])
        if not any_open:
            actx.answer("phish.opened", NO, "No opened attachment, enabled content or mounted disk image was found.", [])
        if not any_exec:
            actx.answer("phish.executed", NO, "No document application launching an interpreter was recorded (process auditing may be off).", [])
        actx.answer("phish.credentials", NO, "No sign-in-like pages on unusual domains were found.", [])


# ============================================================================ remote access / RMM
@analyzer
class RemoteAccessAnalyzer(Analyzer):
    id = "remote_access_review"
    title = "Remote access and RMM"
    description = "Remote tools present / installed / run, their connection logs, RDP and network logons, new accounts."
    weight = 1.0

    def run(self, actx):
        any_tool = any_conn = False
        for e in actx.windows_evidence():
            eid = e["id"]
            label = actx.ev_label(eid)
            tools = actx.artifacts("rmm_tool", eid)
            if tools:
                any_tool = True
                rows = [[t["data"].get("tool"), t["data"].get("installed") or "", t["data"].get("executed") or "", t["data"].get("service") or "",
                         short(t["data"].get("first_seen")), short(t["data"].get("last_seen")), (t["data"].get("evidence") or "")[:220]]
                        for t in tools]
                fid = actx.finding(f"Remote access tools on {label}: {', '.join(t['data'].get('tool') for t in tools)}",
                                   "Remote control / RMM software was found (files, installation records, services, execution traces). "
                                   "These tools are legitimate but are routinely abused for initial access, tech-support scams and data theft.",
                                   evidence_id=eid, severity="high", confidence="high", category="Remote access", refs=[ref(t) for t in tools],
                                   figures=[table_figure("Remote access tools", ["Tool", "Installed", "Executed", "Service", "First seen",
                                                                                 "Last seen", "Evidence"], rows, style="table",
                                                         sheet="Remote tools", col_widths=[160, 70, 70, 60, 140, 140, 360])],
                                   questions=["rmm.tools"], tags=["remote_access"], mitre=["T1219"])
                actx.answer("rmm.tools", YES, f"{label}: {', '.join(t['data'].get('tool') for t in tools)}.", [fid])
            conns = actx.artifacts("rmm_connection", eid)
            # console sessions are logged by the same Terminal Services channel with the address 'LOCAL' - not remote
            rdp = [a for a in actx.artifacts("evt_rdp", eid) if a["data"].get("event_id") in (1149, 21, 22, 24, 25, 4778, 131, 1024)
                   and str(a["data"].get("source_ip") or "").strip().upper() not in ("", "LOCAL", "-", "::1", "127.0.0.1")]
            netlog = [a for a in actx.artifacts("evt_logon", eid) if a["data"].get("event_id") == 4624 and
                      (a["data"].get("logon_type") or "").split(" ")[0] in ("10", "3") and a["data"].get("source_ip") not in ("", "-", "::1", "127.0.0.1")]
            rows = [[short(a["ts"]), a["data"].get("tool"), a["data"].get("direction"), a["data"].get("remote_id"), a["data"].get("remote_ip"),
                     (a["data"].get("details") or "")[:160]] for a in conns] + \
                   [[short(a["ts"]), "RDP / Terminal Services", f"event {a['data'].get('event_id')}", a["data"].get("user"),
                     a["data"].get("source_ip"), a["data"].get("description")] for a in rdp] + \
                   [[short(a["ts"]), "Network logon", a["data"].get("logon_type"), a["data"].get("target_user"), a["data"].get("source_ip"),
                     a["data"].get("workstation")] for a in netlog]
            if rows:
                any_conn = True
                rows.sort(key=lambda r: r[0] or "9999")
                ips = Counter(r[4] for r in rows if r[4])
                fid = actx.finding(f"Remote sessions and connections on {label}",
                                   f"{len(rows)} remote connection records (tool logs, RDP / Terminal Services events, network logons). "
                                   f"Remote addresses: {', '.join(f'{ip} ({n})' for ip, n in ips.most_common(8)) or '-'}.",
                                   evidence_id=eid, severity="high", confidence="high", category="Remote access", ts=rows[0][0] or None,
                                   figures=[table_figure("Remote connections", ["Time (UTC)", "Source", "Type / direction", "ID / user",
                                                                                "Remote address", "Details"], rows[:30], style="app",
                                                         col_widths=[140, 170, 120, 150, 120, 320])],
                                   questions=["rmm.connections"], tags=["remote_access"], mitre=["T1021.001", "T1219"])
                actx.answer("rmm.connections", YES, f"{label}: {len(rows)} remote connection records.", [fid])
                for r in rows:
                    actx.timeline(eid, r[0], "Remote access", r[1], f"{r[2]} {r[3]} {r[4]} {r[5]}")
        if not any_tool:
            actx.answer("rmm.tools", NO, "None of the 25+ remote access / RMM tools in the knowledge base were found.", [])
        if not any_conn:
            actx.answer("rmm.connections", NO, "No remote tool connection logs, RDP sessions or remote network logons were found.", [])


# ============================================================================ accounts / logons
@analyzer
class AccountActivityAnalyzer(Analyzer):
    id = "account_activity"
    title = "Accounts and logons"
    description = "Logon summary per account, failed-logon bursts (password guessing), account creation / group changes, explicit credentials."
    weight = 1.0

    def run(self, actx):
        for e in actx.windows_evidence():
            eid = e["id"]
            label = actx.ev_label(eid)
            logons = actx.artifacts("evt_logon", eid)
            if not logons:
                actx.answer("acct.logons", NO if actx.count("evtx_log", eid) else NA,
                            f"{label}: no logon events (Security log empty, cleared or auditing disabled).", [])
                continue
            per = defaultdict(lambda: Counter())
            first, last = {}, {}
            for a in logons:
                d = a["data"]
                if d.get("event_id") != 4624:
                    continue
                u = d.get("target_user") or "?"
                if u.endswith("$") or u in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0", "UMFD-1"):
                    continue
                per[u][(d.get("logon_type") or "?")] += 1
                first[u] = min(filter(None, [first.get(u), a["ts"]]))
                last[u] = max(filter(None, [last.get(u), a["ts"]]))
            rows = [[u, sum(c.values()), ", ".join(f"{k.split(' - ')[-1]}: {v}" for k, v in c.most_common()), short(first.get(u)),
                     short(last.get(u))] for u, c in sorted(per.items(), key=lambda kv: -sum(kv[1].values()))]
            fids = []
            if rows:
                fids.append(actx.finding(f"Logon activity per account on {label}",
                                         f"Successful logons (event 4624) by {len(rows)} accounts, broken down by logon type, with the first "
                                         "and last occurrence in the retained log.", evidence_id=eid, severity="info", confidence="high",
                                         category="Accounts", figures=[table_figure("Successful logons by account", ["Account", "Logons",
                                                                                                                   "By type", "First",
                                                                                                                   "Last"], rows[:25],
                                                                                    style="table", sheet="Logons",
                                                                                    col_widths=[160, 70, 380, 140, 140])],
                                         questions=["acct.logons"], tags=["accounts"]))
            fails = [a for a in logons if a["data"].get("event_id") == 4625]
            bursts = []
            by_src = defaultdict(list)
            for a in fails:
                by_src[(a["data"].get("source_ip") or a["data"].get("workstation") or "local")].append(from_db(a["ts"]))
            for src, ts in by_src.items():
                ts = sorted(t for t in ts if t)
                i = 0
                for j in range(len(ts)):
                    while ts[j] - ts[i] > timedelta(minutes=10):
                        i += 1
                    if j - i + 1 >= 10:
                        bursts.append([src, len(ts), short(ts[0]), short(ts[-1])])
                        break
            if fails:
                fr = [[short(a["ts"]), a["data"].get("target_user"), a["data"].get("logon_type"), a["data"].get("source_ip"),
                       a["data"].get("status")] for a in fails[:30]]
                fids.append(actx.finding(f"Failed logons on {label}" + (" - password guessing pattern" if bursts else ""),
                                         f"{len(fails)} failed logons (event 4625)" + (
                                             f"; {len(bursts)} source(s) produced 10 or more failures within 10 minutes: "
                                             + ", ".join(f"{b[0]} ({b[1]} failures)" for b in bursts) if bursts else "") + ".",
                                         evidence_id=eid, severity="high" if bursts else "low", confidence="high", category="Accounts",
                                         figures=[table_figure("Failed logons", ["Time (UTC)", "Account", "Logon type", "Source", "Reason"], fr,
                                                               style="eventlog", col_widths=[140, 150, 170, 130, 200])],
                                         questions=["acct.bruteforce"], tags=["accounts"], mitre=["T1110"] if bursts else []))
                actx.answer("acct.bruteforce", YES if bursts else NO, f"{label}: {len(fails)} failed logons, {len(bursts)} burst source(s).", fids[-1:])
            else:
                actx.answer("acct.bruteforce", NO, f"{label}: no failed logons recorded.", [])
            changes = actx.artifacts("evt_account", eid)
            if changes:
                cr = [[short(a["ts"]), a["data"].get("event_id"), a["data"].get("description"), a["data"].get("target_user"),
                       a["data"].get("subject_user"), a["data"].get("group")] for a in changes]
                fids.append(actx.finding(f"Account management events on {label}",
                                         f"{len(cr)} account creations, enable/disable, password resets and group membership changes.",
                                         evidence_id=eid, severity="medium", confidence="high", category="Accounts",
                                         figures=[table_figure("Account changes", ["Time (UTC)", "Event", "Description", "Account",
                                                                                   "Changed by", "Group"], cr[:30], style="eventlog",
                                                               col_widths=[140, 60, 230, 140, 140, 140])],
                                         questions=["acct.changes"], tags=["accounts"], mitre=["T1136", "T1098"]))
                actx.answer("acct.changes", YES, f"{label}: {len(cr)} account management events.", fids[-1:])
            else:
                actx.answer("acct.changes", NO, f"{label}: no account management events.", [])
            # winlogon / consent (UAC) to localhost accompany every interactive logon - not alternate credential use
            explicit = [a for a in logons if a["data"].get("event_id") == 4648 and not (
                re.search(r"\\(winlogon|consent|lsass|svchost)\.exe$", str(a["data"].get("process") or ""), re.I)
                and str(a["data"].get("target_server") or "").lower() in ("localhost", "127.0.0.1", "", "-"))]
            if explicit:
                er = [[short(a["ts"]), a["data"].get("subject_user"), a["data"].get("target_user"), a["data"].get("target_server"),
                       a["data"].get("process")] for a in explicit[:30]]
                actx.finding(f"Logons with explicit credentials on {label}",
                             f"{len(explicit)} uses of alternate credentials (runas, mapped drives, lateral movement tools - event 4648).",
                             evidence_id=eid, severity="low", confidence="high", category="Accounts",
                             figures=[table_figure("Explicit credential use", ["Time (UTC)", "By", "As", "Target", "Process"], er,
                                                   style="eventlog", col_widths=[140, 130, 130, 160, 300])],
                             questions=["acct.logons"], tags=["accounts"], mitre=["T1078"])
            actx.answer("acct.logons", YES, f"{label}: logons by {len(rows)} accounts.", fids[:1])


# ============================================================================ ransomware
SYSTEM_DIRS = re.compile(r"^[a-z]:\\(windows|program files( \(x86\))?|programdata\\microsoft|\$recycle\.bin|system volume information|"
                         r"config\.msi)\\|\\appdata\\local\\(microsoft|google|mozilla|packages)\\")
KNOWN_EXT = re.compile(r"(dll|exe|mui|manifest|cat|png|jpg|jpeg|xml|js|json|txt|html?|css|svg|gif|ico|pyc|py|ttf|otf|woff2?|cab|msi|"
                       r"pdb|etl|inf|pnf|sys|dat|log|db|tmp|ini|cfg|lnk|mof|nls|winmd|resx|mum|xsl|xaml|jar|class|resources|config|"
                       r"appx|xrm-ms|sqlite|docx|xlsx|pptx|docm|xlsm|pdf|zip|ps1|psd1|psm1|admx|adml|dotx|thmx|bmp|wav|mp3|mp4|tlb|"
                       r"ocx|cpl|drv|scr|chm|hlp|rbf|cdf-ms|inf_loc|mp4|avi|mov|wmv|webp|tif|tiff|heic|eml|msg|pst|ost|vhd|vhdx|iso|"
                       r"csv|md|rtf|odt|ods|odp|doc|xls|ppt|one|rar|7z|gz|tar|bin|map|ts|tsx|lock|pak|bak|cache|crx|vbs|bat|cmd|"
                       r"dmp|evtx|reg|pol|mkv|flac|m4a|aac|ogg|psd|ai|indd|dwg|key|pages|numbers|py[dw]?|whl|nupkg)", re.I)


@analyzer
class RansomwareAnalyzer(Analyzer):
    id = "ransomware"
    title = "Ransomware"
    description = ("Mass rename / creation bursts with a new extension (USN journal + file system), ransom notes in many folders, "
                   "shadow copy / backup deletion, the encryption window and what ran just before it.")
    weight = 1.2

    def run(self, actx):
        hit = False
        for e in actx.windows_evidence():
            eid = e["id"]
            label = actx.ev_label(eid)
            # 1) $UsnJrnl: files renamed by appending an extension ('budget.xlsx' -> 'budget.xlsx.lockbit') outside system
            #    folders - at least 50 renames with the same appended extension within two hours
            rows = actx.db.query("SELECT usn, ts, record, seq, name, path, reason FROM usn WHERE evidence_id=? AND reason LIKE "
                                 "'%Rename%' ORDER BY usn", (eid,))
            old_name, ext_times = {}, defaultdict(list)
            for r in rows:
                key = (r["record"], r["seq"])
                if "RenameOldName" in r["reason"]:
                    old_name[key] = r["name"]
                    continue
                if "RenameNewName" not in r["reason"] or key not in old_name:
                    continue
                o, nn = old_name.pop(key), r["name"]
                if SYSTEM_DIRS.search((r["path"] or "").lower()) or not nn.lower().startswith(o.lower() + "."):
                    continue
                ext = nn[len(o) + 1:].rsplit(".", 1)[-1].lower()
                if 1 <= len(ext) <= 30 and ext not in ("tmp", "bak", "old", "orig", "partial", "crdownload", "download"):
                    ext_times[ext].append(r["ts"])
            bursts = []
            for ext, ts in ext_times.items():
                ts.sort()
                i = 0
                for j in range(len(ts)):
                    while from_db(ts[j]) - from_db(ts[i]) > timedelta(hours=2):
                        i += 1
                    if j - i + 1 >= 50:
                        bursts.append([f".{ext} appended (renamed)", len(ts), short(ts[0]), short(ts[-1])])
                        break
            # 2) file system (journal wrapped): one unknown extension on >= 300 files in user profiles, written within 24 hours
            for r in actx.db.query("SELECT ext, COUNT(*) n, MIN(si_modified) a, MAX(si_modified) b FROM fs_entries WHERE evidence_id=? "
                                   "AND is_dir=0 AND deleted=0 AND lower(path) LIKE '\\users\\%' AND length(ext) BETWEEN 3 AND 25 "
                                   "GROUP BY ext HAVING n >= 300", (eid,)):
                if KNOWN_EXT.fullmatch(r["ext"]) or not (r["a"] and r["b"]):
                    continue
                if from_db(r["b"]) - from_db(r["a"]) <= timedelta(hours=24):
                    bursts.append([f".{r['ext']} (files in user profiles)", r["n"], short(r["a"]), short(r["b"])])
            notes = actx.db.query("SELECT lower(name) name, COUNT(DISTINCT substr(path, 1, length(path) - length(name))) dirs, MIN(si_created) "
                                  "first FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND ext IN ('txt','html','hta','htm','url') AND "
                                  "(lower(name) LIKE '%readme%' OR lower(name) LIKE '%decrypt%' OR lower(name) LIKE '%restore%' OR "
                                  "lower(name) LIKE '%recover%' OR lower(name) LIKE '%how_to%' OR lower(name) LIKE '%ransom%' OR "
                                  "lower(name) LIKE '%instruction%') GROUP BY lower(name) HAVING dirs >= 5 ORDER BY dirs DESC LIMIT 10", (eid,))
            shadow = [a for a in actx.artifacts(("evt_process", "evt_powershell", "ps_history", "run_mru", "scheduled_task"), eid)
                      if re.search(r"vssadmin.*delete|shadowcopy.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|"
                                   r"delete\s+shadows", str(a["data"]), re.I)]
            if not (bursts or notes or shadow):
                continue
            hit = True
            precursor_answered = False
            figs = []
            if bursts:
                figs.append(table_figure("File extensions appearing in bulk", ["Extension", "Files", "First (UTC)", "Last (UTC)"], bursts[:15],
                                         style="table", sheet="Extensions", highlight_rows=list(range(min(15, len(bursts)))),
                                         col_widths=[160, 90, 160, 160]))
            if notes:
                figs.append(table_figure("Probable ransom notes", ["File name", "Folders containing it", "First created (UTC)"],
                                         [[n["name"], n["dirs"], short(n["first"])] for n in notes], style="table", sheet="Notes",
                                         col_widths=[260, 140, 160]))
            if shadow:
                figs.append(table_figure("Shadow copy / recovery deletion", ["Time (UTC)", "Artifact", "Command"],
                                         [[short(a["ts"]), a["type"], str(a["data"].get("command_line") or a["data"].get("command") or
                                                                         a["data"].get("script") or "")[:300]] for a in shadow[:20]],
                                         style="app", col_widths=[140, 140, 620]))
            start = min([b[2] for b in bursts if b[2]] + [n["first"][:19] for n in notes if n["first"]], default=None)
            desc = ("Indicators of file encryption: " + "; ".join(
                ([f"{len(bursts)} new file extension(s) applied to large numbers of files ({', '.join(b[0] for b in bursts[:5])})"] if bursts else [])
                + ([f"identical note files in {notes[0]['dirs']} folders ('{notes[0]['name']}')"] if notes else [])
                + ([f"{len(shadow)} shadow copy / recovery deletion commands"] if shadow else []))
                + (f". The earliest encryption-related activity is {actx.t(start)}." if start else "."))
            fid = actx.finding(f"Ransomware indicators on {label}", desc, evidence_id=eid, severity="critical", confidence="medium",
                               category="Ransomware", ts=start, figures=figs, questions=["ransom.encryption"], tags=["ransomware"],
                               mitre=["T1486", "T1490"])
            actx.answer("ransom.encryption", YES if (bursts and notes) else INDICATED, f"{label}: {desc[:300]}", [fid])
            if start:
                s = from_db(start)
                pre = []
                for typ, field in (("prefetch", "executable"), ("evt_process", "command_line"), ("evt_service", "image_path"),
                                   ("rmm_connection", "details"), ("evt_rdp", "description"), ("evt_logon", "target_user")):
                    for a in actx.artifacts(typ, eid):
                        t = from_db(a["ts"])
                        if t and s - timedelta(hours=6) <= t <= s and not a["data"].get("is_previous_run"):
                            pre.append([short(a["ts"]), typ, str(a["data"].get(field) or "")[:260]])
                if pre:
                    pre.sort(key=lambda r: r[0])
                    actx.finding(f"Activity in the six hours before encryption on {label}",
                                 "Programs, services, logons and remote sessions immediately preceding the first encryption activity "
                                 "- typically the operator's access path and the encryptor launch.", evidence_id=eid, severity="high",
                                 confidence="medium", category="Ransomware",
                                 figures=[table_figure("Six hours before encryption", ["Time (UTC)", "Artifact", "Detail"], pre[-30:],
                                                       style="app", col_widths=[140, 140, 620])],
                                 questions=["ransom.precursor"], tags=["ransomware"])
                    actx.answer("ransom.precursor", YES, f"{label}: {len(pre)} activities in the six hours before encryption.", [])
                    precursor_answered = True
            if not precursor_answered:
                actx.answer("ransom.precursor", INCONCLUSIVE, f"{label}: no program, service, logon or remote session was recorded in "
                                                              "the six hours before the first encryption indicator.", [])
        if not hit:
            actx.answer("ransom.encryption", NO, "No bulk extension changes, ransom notes or shadow copy deletion were found.", [])
            actx.answer("ransom.precursor", NA, "No encryption activity was identified.", [])
