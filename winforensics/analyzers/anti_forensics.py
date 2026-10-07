"""Anti-forensics and evidence tampering indicators (shared by every profile)."""

from __future__ import annotations

import re

from ..knowledge import tool_for_exe
from ..modules._usbutil import serial_key
from .base import INDICATED, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import mentions_target, ref, short

SEARCH_TERMS = re.compile(r"clear (usb|history|logs?|traces?)|delete (usb|history|logs?|browsing)|remove usb|usb ?oblivion|"
                          r"ccleaner|bleachbit|wipe (disk|drive|free space|history)|shred|anti.?forensic|hide (files|folder)|"
                          r"erase (history|evidence|traces)|how to (delete|remove|erase)|secure delete|sdelete|"
                          r"event ?log (clear|delete)|timestomp|change file date", re.I)


@analyzer
class AntiForensicsAnalyzer(Analyzer):
    id = "anti_forensics"
    title = "Anti-forensics"
    description = ("Log clearing, cleaner / wiper / USB-history-removal tools, searches about hiding traces, destructive "
                   "commands, timestamp manipulation, deleted files of interest, removed device history, time changes.")
    weight = 1.0

    def run(self, actx):
        found_any = False
        wins = actx.windows_evidence()
        for k, e in enumerate(wins):
            eid = e["id"]
            actx.progress(k / max(1, len(wins)), f"Anti-forensics on {e['label']}")
            rows, refs = [], []

            def add(when, what, detail, a=None, strong=True):
                rows.append([short(when), what, str(detail)[:260], "strong" if strong else "weak"])
                if a:
                    refs.append(ref(a))
                    actx.timeline(eid, when, "Anti-forensics", what, str(detail)[:300], user=a.get("user"), ref_kind="artifact",
                                  ref_id=a["id"], flagged=strong)

            for a in actx.artifacts("evt_clear", eid):
                add(a["ts"], f"Event {a['data'].get('event_id')}: {a['data'].get('description')}",
                    f"{a['data'].get('log')} cleared by {a['data'].get('subject_user')}", a)
            for typ, field in (("prefetch", "executable"), ("userassist", "program"), ("bam", "path"), ("amcache", "path"),
                               ("evt_process", "process"), ("installed_program", "name"), ("shimcache", "path"), ("pca", "path")):
                for a in actx.artifacts(typ, eid):
                    if a["data"].get("is_previous_run"):
                        continue
                    val = a["data"].get(field) or ""
                    tools = [t for fam, t in tool_for_exe(val) if fam == "anti_forensics"]
                    if typ == "installed_program":
                        low = val.lower()
                        tools = [t for t in ("CCleaner", "BleachBit", "Eraser", "PrivaZer", "VeraCrypt", "USBOblivion",
                                             "Wise Disk Cleaner", "Glary") if t.lower() in low]
                    for t in tools:
                        if t in ("Cipher wipe", "Event log clearing (wevtutil)") and typ not in ("evt_process",):
                            continue
                        add(a["ts"], f"{t} ({typ})", val, a, strong=typ not in ("shimcache", "amcache"))
            for typ, field in (("web_search", "term"), ("web_visit", "title"), ("search_term", "term")):
                for a in actx.artifacts(typ, eid):
                    val = a["data"].get(field) or ""
                    if SEARCH_TERMS.search(val) or (typ == "web_visit" and SEARCH_TERMS.search(a["data"].get("url") or "")):
                        add(a["ts"], f"Search / page about hiding traces ({typ.replace('_', ' ')})", val, a)
            for typ, field in (("ps_history", "command"), ("evt_powershell", "script"), ("run_mru", "command"),
                               ("evt_process", "command_line"), ("scheduled_task", "command")):
                for a in actx.artifacts(typ, eid):
                    txt = a["data"].get(field) or ""
                    if re.search(r"wevtutil\s+(cl|clear-log)|clear-eventlog|fsutil\s+usn\s+deletejournal|cipher(\.exe)?\s+/w|"
                                 r"sdelete|vssadmin.*delete|wmic.*shadowcopy.*delete|remove-item.*-recurse.*(prefetch|recent)|"
                                 r"del\s.*\\prefetch\\|clear-recyclebin|rd\s+/s.*recycle", txt, re.I):
                        add(a["ts"], f"Destructive / cleanup command ({typ.replace('_', ' ')})", txt, a)
            for a in actx.artifacts("timestamp_anomaly", eid):
                f = (a["data"].get("file") or "").lower()
                # $SI earlier than $FN is normal for files laid down by Windows setup / installers
                if re.match(r"^[a-z]:\\(windows|program files|programdata\\microsoft|\$recycle|system volume information)", f) \
                        and not mentions_target(actx, f):
                    continue
                if mentions_target(actx, a["data"].get("file")) or len(rows) < 200:
                    add(a["ts"], "Timestamp anomaly ($SI vs $FN)", f"{a['data'].get('file')}: {a['data'].get('anomaly')}", a,
                        strong=bool(mentions_target(actx, a["data"].get("file"))))
            for a in actx.artifacts("evt_system", eid):
                if "time changed" in (a["data"].get("description") or "").lower():
                    add(a["ts"], "System time changed", a["data"].get("details"), a, strong=False)
            for a in actx.artifacts("recycle_bin", eid):
                if (a["data"].get("r_present") or "").startswith("Deleted") or mentions_target(actx, a["data"].get("original_path")):
                    add(a["ts"], "File deleted via Recycle Bin" + (" (bin emptied)" if (a["data"].get("r_present") or "").startswith("Deleted") else ""),
                        a["data"].get("original_path"), a, strong=bool(mentions_target(actx, a["data"].get("original_path"))))
            for a in actx.artifacts("target_match", eid):
                if a["data"].get("deleted") or "Deleted" in (a["data"].get("area") or ""):
                    add(a["ts"], "File of interest deleted", a["data"].get("location"), a)
            # secure-deletion pattern in $UsnJrnl: the same file record renamed to several random names within seconds and
            # then deleted (Eraser, SDelete, CCleaner wipe ...). Normal applications rename a record at most once or twice.
            for w in actx.db.query(
                    "SELECT volume, record, seq FROM usn WHERE evidence_id=? AND reason LIKE '%RenameNewName%' "
                    "GROUP BY volume, record, seq HAVING COUNT(DISTINCT name) >= 4 LIMIT 20000", (eid,)):
                hist = actx.db.query("SELECT ts, name, path, reason FROM usn WHERE evidence_id=? AND volume=? AND record=? AND seq=? "
                                     "ORDER BY usn", (eid, w["volume"], w["record"], w["seq"]))
                burst = _rename_burst(hist)
                if burst:
                    before, names, t0, t1, deleted_at = burst
                    add(deleted_at, "Secure deletion pattern ($UsnJrnl: renamed to random names, then deleted)",
                        f"{before} - renamed {len(names)} times ({', '.join(names[:4])}...) between {t0[:19]} and "
                        f"{t1[:19]} UTC, then deleted", None)
            # device history removed from the registry while still in event logs
            reg = {serial_key(d["data"].get("serial")) for d in actx.artifacts("usb_device", eid) if "Enum" in (d["data"].get("sources") or "")}
            evt = {serial_key(u["data"].get("serial")) for u in actx.artifacts("usb_event", eid)
                   if u["data"].get("event_id") in (1006, 400, 410) and u["data"].get("serial")}
            missing = sorted(s for s in evt - reg if s)
            for s in missing:
                add(None, "USB device in event logs but absent from registry (device history cleaned?)", s, None)
            # logs that do not cover the period of interest
            start, end = actx.window
            for a in actx.artifacts("evtx_log", eid):
                d = a["data"]
                if d.get("channel") in ("Security", "System", "Microsoft-Windows-Partition/Diagnostic") and start and d.get("first_event") \
                        and d["first_event"] > str(start)[:19]:
                    add(d.get("first_event"), f"{d['channel']} log begins after the period of interest", f"first event {d['first_event']}",
                        a, strong=False)
            for a in actx.artifacts("sys_info", eid):
                if a["data"].get("property") == "ClearPageFileAtShutdown" and a["data"].get("value") not in ("0", "", None):
                    add(None, "Pagefile cleared at shutdown", "ClearPageFileAtShutdown=" + a["data"]["value"], a, strong=False)
            if not rows:
                continue
            found_any = True
            rows.sort(key=lambda r: r[0] or "9999")
            strong = [r for r in rows if r[3] == "strong"]
            # figure: every strong indicator first (chronological), then weak ones to fill the table
            shown = strong[:30] + [r for r in rows if r[3] != "strong"][:max(0, 30 - len(strong[:30]))]
            hl = [i for i, r in enumerate(shown) if r[3] == "strong"]
            first_ts = (strong[0][0] if strong and strong[0][0] else None) or rows[0][0] or None
            fid = actx.finding(f"Anti-forensic activity indicators on {actx.ev_label(eid)}",
                               f"{len(rows)} indicators of attempts to remove or obscure traces were identified ({len(strong)} strong): "
                               + "; ".join(sorted({r[1].split(' (')[0] for r in rows}))[:600] + ".",
                               evidence_id=eid, severity="high" if strong else "medium", confidence="medium", category="Anti-forensics",
                               ts=first_ts, refs=refs[:150],
                               figures=[table_figure(f"Anti-forensics indicators - {actx.ev_label(eid)}",
                                                     ["Time (UTC)", "Indicator", "Detail", "Strength"], shown, style="app",
                                                     highlight_rows=hl, col_widths=[150, 330, 430, 80],
                                                     callouts=[callout(hl[0], 1, 1, "Attempt to remove traces")] if hl else [])],
                               questions=["anti_forensics"], tags=["anti_forensics"], mitre=["T1070"])
            actx.answer("anti_forensics", YES if strong else INDICATED,
                        f"{actx.ev_label(eid)}: " + "; ".join(sorted({r[1].split(' (')[0] for r in strong or rows}))[:300] + ".", [fid])
        if not found_any:
            actx.answer("anti_forensics", NO, "No log clearing, cleaner/wiper tools, trace-removal searches, destructive commands "
                                              "or timestamp manipulation were identified.", [])


_ESE_LOG = re.compile(r"^(edb|res|tmp|jet)\w*\.(log|jrs|chk|edb)$", re.I)


def _rename_burst(hist: list[dict]):
    """Wiper signature in one file record's journal history: >= 4 renames to different names inside 3 seconds, followed
    by deletion within 10 seconds.  Returns (path before the burst, new names, burst start, burst end, deletion time)."""
    from datetime import datetime

    def t(x):
        return datetime.fromisoformat(x["ts"][:26])

    renames = [h for h in hist if "RenameNewName" in h["reason"]]
    for i in range(len(renames)):
        j = i
        names = []
        while j < len(renames) and (t(renames[j]) - t(renames[i])).total_seconds() <= 3:
            if renames[j]["name"] not in names:
                names.append(renames[j]["name"])
            j += 1
        if len(names) < 4 or all(_ESE_LOG.match(n) for n in names):
            continue
        end = renames[j - 1]
        dele = next((h for h in hist if "FileDelete" in h["reason"] and 0 <= (t(h) - t(end)).total_seconds() <= 10), None)
        if dele is None:
            continue
        start = next(k for k, h in enumerate(hist) if h is renames[i])
        olds = [h for h in hist[:start] if "RenameOldName" in h["reason"]]  # journal order, not timestamps (they tie)
        before = olds[-1]["path"] if olds else hist[0]["path"]
        return before, names, renames[i]["ts"], end["ts"], dele["ts"]
    return None
