"""Excel workbook with every parsed artifact, the findings, the timeline, search hits and coverage."""

from __future__ import annotations

import json
import re

from .. import __app_title__, __version__

MAX_ROWS = 300_000


def _sheet_name(title: str, used: set) -> str:
    name = re.sub(r"[\[\]:*?/\\]", "", title)[:31].strip() or "Sheet"
    base, i = name, 2
    while name.lower() in used:
        suffix = f" ({i})"
        name = base[: 31 - len(suffix)] + suffix
        i += 1
    used.add(name.lower())
    return name


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        s = json.dumps(v, ensure_ascii=False, default=str)
    else:
        s = v if isinstance(v, (int, float)) else str(v)
    if isinstance(s, str) and len(s) > 32000:
        s = s[:32000] + "..."
    return s


def build_workbook(case, path: str, progress=None) -> str:
    import xlsxwriter

    progress = progress or (lambda f, s: None)
    db = case.db
    wb = xlsxwriter.Workbook(path, {"strings_to_urls": False, "strings_to_formulas": False, "constant_memory": False})
    wb.set_properties({"title": f"{case.title} - artifacts", "author": case.info.examiner or __app_title__,
                       "comments": f"{__app_title__} {__version__}"})
    H = wb.add_format({"bold": True, "font_color": "#FFFFFF", "bg_color": "#1F3864", "border": 1, "border_color": "#8EA9DB",
                       "valign": "vcenter", "text_wrap": True, "font_name": "Calibri", "font_size": 10})
    T = wb.add_format({"bold": True, "font_size": 14, "font_color": "#1F3864", "font_name": "Calibri"})
    SUB = wb.add_format({"italic": True, "font_color": "#595959", "font_size": 9})
    C = wb.add_format({"font_name": "Calibri", "font_size": 10, "valign": "top"})
    W = wb.add_format({"font_name": "Calibri", "font_size": 10, "valign": "top", "text_wrap": True})
    MONO = wb.add_format({"font_name": "Consolas", "font_size": 9, "valign": "top"})
    STATUS = {k: wb.add_format({"bold": True, "bg_color": bg, "font_color": fg, "border": 1, "border_color": "#D9D9D9"})
              for k, (bg, fg) in {"Yes": ("#C00000", "#FFFFFF"), "Indicated": ("#ED7D31", "#FFFFFF"),
                                  "No evidence found": ("#C6EFCE", "#006100"), "Not applicable": ("#EDEDED", "#595959"),
                                  "Inconclusive": ("#BDD7EE", "#1F3864"), "found": ("#C6EFCE", "#006100"),
                                  "not_found": ("#F2F2F2", "#404040"), "absent": ("#EDEDED", "#7F7F7F"),
                                  "error": ("#FFC7CE", "#9C0006"), "skipped": ("#FFF2CC", "#7F6000"),
                                  "high": ("#C00000", "#FFFFFF"), "critical": ("#7B0000", "#FFFFFF"),
                                  "medium": ("#ED7D31", "#FFFFFF"), "low": ("#FFD966", "#3F3F00"), "info": ("#BDD7EE", "#1F3864")}.items()}
    used = set()
    ev_label = {e["id"]: e["label"] for e in db.evidence()}

    def table(ws, start_row, headers, rows, widths, wrap_cols=(), mono_cols=(), status_col=None):
        for i, h in enumerate(headers):
            ws.write(start_row, i, h, H)
            ws.set_column(i, i, widths[i] if i < len(widths) else 18, W if i in wrap_cols else (MONO if i in mono_cols else C))
        for r, row in enumerate(rows, start=start_row + 1):
            for i, v in enumerate(row):
                if status_col is not None and i == status_col and str(v) in STATUS:
                    ws.write(r, i, _cell(v), STATUS[str(v)])
                else:
                    ws.write(r, i, _cell(v))
        ws.freeze_panes(start_row + 1, 0)
        if rows:
            ws.autofilter(start_row, 0, start_row + len(rows), len(headers) - 1)
        ws.set_row(start_row, 30)

    # ---------------------------------------------------------------- summary
    from ..profiles import get_profile

    profile = get_profile(case.info.profile)
    ws = wb.add_worksheet(_sheet_name("Summary", used))
    ws.write(0, 0, f"{profile.title}", T)
    ws.write(1, 0, f"Case {case.info.case_number}  {case.info.case_name}  -  examiner {case.info.examiner}  -  all times UTC", SUB)
    answers = db.answers()
    rows = [[f"Q{i}", q["text"], answers.get(q["id"], {}).get("status", ""), answers.get(q["id"], {}).get("summary", "")]
            for i, q in enumerate(profile.questions, 1)]
    table(ws, 3, ["#", "Investigative question", "Conclusion", "Basis"], rows, [6, 60, 18, 110], wrap_cols=(1, 3), status_col=2)
    # ---------------------------------------------------------------- findings
    ws = wb.add_worksheet(_sheet_name("Findings", used))
    fr = [[f"F-{i:02d}", ev_label.get(f.get("evidence_id"), "Case-wide"), f.get("category") or "", f.get("ts") and f["ts"][:19],
           f["title"], f["description"], ", ".join(f.get("mitre") or [])] for i, f in enumerate(db.findings(), 1)]
    table(ws, 0, ["#", "System", "Category", "Time (UTC)", "Title", "Description", "MITRE ATT&CK"], fr,
          [7, 26, 18, 19, 60, 110, 16], wrap_cols=(4, 5))
    # ---------------------------------------------------------------- timeline
    ws = wb.add_worksheet(_sheet_name("Timeline", used))
    tl = [[(r["ts"] or "")[:19], ev_label.get(r["evidence_id"], ""), r["source"], r["event"], r["description"], r["user"] or "",
           "Yes" if r["flagged"] else ""] for r in db.query("SELECT * FROM timeline ORDER BY ts")]
    table(ws, 0, ["Time (UTC)", "System", "Source", "Event", "Description", "User", "Flagged"], tl, [19, 22, 18, 30, 110, 14, 8])
    # ---------------------------------------------------------------- evidence
    ws = wb.add_worksheet(_sheet_name("Evidence", used))
    er = []
    for e in db.evidence():
        osd = e.get("os") or {}
        er.append([e["id"], e["label"], e["role"], e["path"], e["format"], e.get("size"), osd.get("hostname"),
                   osd.get("product_name"), osd.get("timezone_name"), (e.get("hashes") or {}).get("md5"),
                   ((e.get("info") or {}).get("ewf") or {}).get("stored_hashes", {}).get("md5", "")])
    table(ws, 0, ["#", "Label", "Role", "Path", "Format", "Size", "Host", "OS", "Time zone", "MD5 (verified)", "MD5 (acquisition)"],
          er, [5, 24, 12, 60, 8, 14, 18, 22, 22, 34, 34], mono_cols=(9, 10))
    # ---------------------------------------------------------------- artifact sheets
    types = db.artifact_types()
    counts = {}
    for r in db.query("SELECT type, COUNT(*) n FROM artifacts GROUP BY type"):
        counts[r["type"]] = r["n"]
    ordered = sorted(counts, key=lambda t: (types.get(t, {}).get("category", "zz"), types.get(t, {}).get("title", t)))
    for k, t in enumerate(ordered):
        progress(k / max(1, len(ordered)), f"Workbook: {types.get(t, {}).get('title', t)}")
        meta = types.get(t, {"title": t, "columns": []})
        cols = [c["name"] for c in meta.get("columns", [])]
        titles = [c["title"] for c in meta.get("columns", [])]
        ws = wb.add_worksheet(_sheet_name(meta.get("title", t), used))
        headers = ["System", "Time (UTC)", "User"] + titles + ["Summary", "Source"]
        rows = []
        for a in db.iquery("SELECT evidence_id, ts, user, data_json, summary, source FROM artifacts WHERE type=? ORDER BY evidence_id, ts "
                           f"LIMIT {MAX_ROWS}", (t,)):
            d = json.loads(a["data_json"] or "{}")
            rows.append([ev_label.get(a["evidence_id"], ""), (a["ts"] or "")[:19], a["user"] or ""] + [d.get(c) for c in cols]
                        + [a["summary"], a["source"]])
        widths = [20, 19, 14] + [max(10, min(60, (c.get("width") or 0) // 7 or 18)) for c in meta.get("columns", [])] + [60, 50]
        table(ws, 0, headers, rows, widths)
    # ---------------------------------------------------------------- hits / coverage / fs
    ws = wb.add_worksheet(_sheet_name("Keyword hits", used))
    hits = [[ev_label.get(h["evidence_id"], ""), h["term"], h["term_kind"], h["area"], h["volume"], h["offset"], h["encoding"],
             h["file_path"], h["context_text"]] for h in db.query("SELECT * FROM hits ORDER BY evidence_id, term, area LIMIT 200000")]
    table(ws, 0, ["System", "Term", "Origin", "Area", "Volume", "Offset", "Encoding", "Attributed to", "Context"], hits,
          [20, 26, 16, 30, 8, 14, 10, 60, 70])
    ws = wb.add_worksheet(_sheet_name("Coverage", used))
    cov = [[ev_label.get(c["evidence_id"], ""), c["module"], c["artifact"], c["location"], c["status"], c["count"], c["detail"]]
           for c in db.query("SELECT * FROM coverage ORDER BY evidence_id, id")]
    table(ws, 0, ["System", "Module", "Artifact", "Location", "Result", "Records", "Notes"], cov, [20, 14, 34, 60, 12, 9, 60],
          status_col=4)
    ws = wb.add_worksheet(_sheet_name("Deleted files", used))
    dele = [[ev_label.get(r["evidence_id"], ""), r["volume"], r["path"], r["size"], (r["si_created"] or "")[:19],
             (r["si_modified"] or "")[:19], r["sha256"] or ""]
            for r in db.query("SELECT * FROM fs_entries WHERE deleted=1 AND is_dir=0 ORDER BY evidence_id, path LIMIT 200000")]
    table(ws, 0, ["System", "Volume", "Path", "Size", "Created (UTC)", "Modified (UTC)", "SHA-256 (if recovered)"], dele,
          [20, 8, 90, 12, 19, 19, 66], mono_cols=(6,))
    wb.close()
    progress(1.0, "Workbook written")
    return path
