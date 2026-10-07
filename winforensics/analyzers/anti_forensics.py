"""Anti-forensics and evidence tampering indicators (shared by every profile)."""

from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta

from ..core.timeutil import from_db
from ..knowledge import tool_for_exe
from ..modules.filesystem import TIMESTOMP_STRONG
from .base import INCONCLUSIVE, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import in_installed_program, mentions_target, ref, short

# folders archive tools extract into (XP compressed folders, Windows 7+ zip, WinRAR, 7-Zip, WinZip, InstallShield)
EXTRACTED = re.compile(r"\\temporary directory \d+ for [^\\]+\\|\\temp\d+_[^\\]+\.zip\\|\\rar\$ex[a-z0-9.]+\\|\\7z[a-z0-9]{3,}\\|"
                       r"\\wz[0-9a-f]{3,}\\|\\_ir_sf_temp_\d+\\", re.I)

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
            anomalies = actx.artifacts("timestamp_anomaly", eid)
            # installers and app packages lay down whole folders with archived times in one go; a timestamp tool is
            # pointed at individual files - so the same signature on many files of one folder within a minute is a copy
            batch = Counter(((a["data"].get("file") or "").lower().rsplit("\\", 1)[0], str(a["data"].get("fn_created"))[:16])
                            for a in anomalies)
            # files Windows Setup (or a feature update) lays down keep their media times: $FN created on the install day
            installed = from_db((e.get("os") or {}).get("install_date"))
            for a in anomalies:
                f = (a["data"].get("file") or "").lower()
                # $SI earlier than $FN is normal for files laid down by Windows setup / installers, and for files extracted
                # from an archive (the extractor restores the archived file times)
                if (re.match(r"^[a-z]:\\(windows|program files|programdata\\microsoft|\$recycle|system volume information)", f)
                        or EXTRACTED.search(f)) and not mentions_target(actx, f):
                    continue
                single = batch[(f.rsplit("\\", 1)[0], str(a["data"].get("fn_created"))[:16])] < 3
                fn_c = from_db(a["data"].get("fn_created"))
                setup = bool(installed and fn_c and abs(fn_c - installed) <= timedelta(days=1))
                tool_like = a["data"].get("anomaly") == TIMESTOMP_STRONG and single and not setup \
                    and "\\appdata\\local\\packages\\" not in f and not in_installed_program(actx, eid, f)
                if mentions_target(actx, a["data"].get("file")) or tool_like or len(rows) < 200:
                    add(a["ts"], "Timestamp anomaly ($SI vs $FN)", f"{a['data'].get('file')}: {a['data'].get('anomaly')}", a,
                        strong=bool(mentions_target(actx, a["data"].get("file"))) or tool_like)
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
            # device history removed from the registry while still in event logs.  Only removable devices with a real serial
            # count, and only when the SYSTEM hive on disk was written after the device was last seen (a hive flushed
            # before the connection simply predates it).  Windows' Plug and Play cleanup task removes devices unused for
            # 30 days, so older absences are weak.
            hive = actx.db.query("SELECT si_modified FROM fs_entries WHERE evidence_id=? AND lower(path)=? AND deleted=0",
                                 (eid, "\\windows\\system32\\config\\system"))
            hive_t = from_db(hive[0]["si_modified"]) if hive else None
            for d in actx.artifacts("usb_device", eid):
                dd = d["data"]
                if "Enum" in (dd.get("sources") or "") or dd.get("serial_generated") or "EVTX" not in (dd.get("sources") or ""):
                    continue
                last = from_db(dd.get("last_connected") or dd.get("first_seen"))
                if not (hive_t and last) or last >= hive_t:
                    continue
                label = f"{dd.get('vendor') or ''} {dd.get('product') or ''} S/N {dd.get('serial')}".strip()
                add(dd.get("last_connected") or dd.get("first_seen"),
                    "USB device in event logs but absent from the registry (device history removed?)",
                    f"{label}; last seen {str(last)[:19]} UTC, SYSTEM hive written {str(hive_t)[:19]} UTC", d,
                    strong=hive_t - last <= timedelta(days=30))
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
            # weak indicators (timestamp anomalies, time changes, emptied Recycle Bin, ...) each have common benign
            # explanations: on their own they leave the question open rather than indicating anti-forensics
            actx.answer("anti_forensics", YES if strong else INCONCLUSIVE,
                        f"{actx.ev_label(eid)}: " + "; ".join(sorted({r[1].split(' (')[0] for r in strong or rows}))[:300]
                        + ("." if strong else " - weak indicators only, each with common benign explanations; review them."), [fid])
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
