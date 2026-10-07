"""Consolidated case timeline: flagged events from every analyzer plus core activity in the period of interest."""

from __future__ import annotations

from datetime import timedelta

from ..core.timeutil import from_db
from .base import Analyzer, analyzer, table_figure, timeline_figure
from .common import eqid, short

CORE = [("evt_logon", lambda d: eqid(d) in (4647, 4800, 4801, 7001, 7002) or
         (eqid(d) in (4624, 4634) and (d.get("logon_type") or "").split(" ")[0] in ("2", "7", "10", "11")), "Logon"),
        ("evt_system", lambda d: True, "System"), ("evt_rdp", lambda d: True, "Remote session"),
        ("prefetch", lambda d: not d.get("is_previous_run"), "Program run"), ("userassist", lambda d: True, "Program run (GUI)"),
        ("web_search", lambda d: True, "Web search"), ("recent_doc", lambda d: True, "Document opened"),
        ("office_mru", lambda d: True, "Office document"), ("lnk", lambda d: True, "File opened (LNK)"),
        ("timeline_activity", lambda d: True, "Windows Timeline")]


@analyzer
class CaseTimelineAnalyzer(Analyzer):
    id = "case_timeline"
    title = "Case timeline"
    description = "Merges flagged events from all analyzers with core user activity in the period of interest."
    weight = 0.8

    def run(self, actx):
        start, end = actx.window
        rows = actx.db.query("SELECT * FROM timeline ORDER BY ts")
        pending = actx.cache.get("_timeline", [])
        if not start and not end:
            times = [from_db(r[1]) for r in pending if r[1]] + [from_db(r["ts"]) for r in rows if r["ts"]]
            times = [t for t in times if t]
            if times:
                start, end = min(times) - timedelta(hours=2), max(times) + timedelta(hours=2)
        if start or end:
            for typ, pred, label in CORE:
                for a in actx.artifacts(typ):
                    t = from_db(a["ts"]) if a["ts"] else None
                    if t is None or (start and t < start) or (end and t > end):
                        continue
                    try:
                        if not pred(a["data"]):
                            continue
                    except Exception:
                        continue
                    actx.timeline(a["evidence_id"], a["ts"], label, a["type"], a["summary"], user=a["user"],
                                  ref_kind="artifact", ref_id=a["id"], flagged=False)
        actx.flush_timeline()
        allrows = actx.db.query("SELECT * FROM timeline ORDER BY ts")
        flagged = [r for r in allrows if r["flagged"]]
        if not allrows:
            return
        show = flagged[:60] if flagged else allrows[:60]
        trows = [[short(r["ts"]), actx.ev_label(r["evidence_id"]), r["source"], r["event"], (r["description"] or "")[:150]]
                 for r in show]
        lanes = {}
        for r in flagged:
            lane = lanes.setdefault(actx.ev_label(r["evidence_id"]), {"label": actx.ev_label(r["evidence_id"]), "spans": [], "events": []})
            kind = ("usb" if r["source"] == "USB" else "web" if r["source"].startswith(("Web", "Download")) else
                    "file" if r["source"] in ("LNK", "Jump list", "Files", "USN") else "alert" if r["source"] == "DLP alert" else "other")
            if r["source"] == "USB" and r["event"] == "USB connected":
                continue
            desc = (r["description"] or "").replace("\\", "/")
            short_desc = desc.split(" (")[0].split(" [")[0]
            short_desc = short_desc if len(short_desc) <= 48 else "..." + short_desc[-45:]
            lane["events"].append({"ts": r["ts"], "label": f"{r['event']}: {short_desc}", "kind": kind})
        for lane_label, lane in lanes.items():
            for s in actx.artifacts("usb_session"):
                if actx.ev_label(s["evidence_id"]) == lane_label and s["data"].get("connected"):
                    lane["spans"].append({"start": s["data"]["connected"], "end": s["data"].get("disconnected") or s["data"]["connected"],
                                          "label": f"USB {s['data'].get('serial', '')[-6:]}"})
        figs = [table_figure("Consolidated timeline of key events", ["Time (UTC)", "System", "Source", "Event", "Description"], trows,
                             style="table", sheet="Timeline", col_widths=[150, 170, 120, 180, 470])]
        if lanes:
            figs.insert(0, timeline_figure("Timeline of key events per system", list(lanes.values())))
        actx.finding("Consolidated timeline of key events",
                     f"{len(allrows):,} events were placed on the case timeline ({len(flagged):,} flagged as relevant by the analyzers)"
                     + (f" for the period {short(start)} to {short(end)} UTC" if start and end else "") + ". "
                     "The full timeline is available in the Excel workbook and in the application.",
                     severity="info", confidence="high", category="Timeline", figures=figs, tags=["timeline"])
