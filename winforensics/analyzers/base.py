"""Analyzer framework.

Analyzers run after every evidence item has been processed.  They read the
normalized artifacts of *all* evidence items, correlate them with the examiner's
inputs and produce:

* findings  - a titled, explained conclusion with severity / confidence, references
              to the supporting artifacts and *figure specifications* (tables, hex
              views, registry views, timelines) that the report renders as annotated
              screenshots;
* answers   - the status of each investigative question of the profile;
* timeline  - flagged events for the consolidated case timeline.

Drop a module containing a class decorated with ``@analyzer`` into this package
(or ``%APPDATA%/WindowsForensicAutomation/plugins``) to add one.  See ``docs/writing-analyzers.md``.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from datetime import timedelta

from ..core.timeutil import UTC, db_ts, fmt, from_db, get_tz, parse_any

log = logging.getLogger("winforensics.analyzers")

ANALYZERS: dict[str, type] = {}

YES, INDICATED, NO, NA, INCONCLUSIVE = "Yes", "Indicated", "No evidence found", "Not applicable", "Inconclusive"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def analyzer(cls):
    ANALYZERS[cls.id] = cls
    return cls


def discover() -> dict[str, type]:
    import winforensics.analyzers as pkg

    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name.startswith("_") or m.name == "base":
            continue
        try:
            importlib.import_module(f"winforensics.analyzers.{m.name}")
        except Exception:
            log.exception("failed to import analyzer %s", m.name)
    return ANALYZERS


class Analyzer:
    id = ""
    title = ""
    description = ""
    weight = 1.0

    def run(self, actx: "AnalyzerContext") -> None:  # pragma: no cover - interface
        raise NotImplementedError


class AnalyzerContext:
    def __init__(self, case, db, inputs: dict, profile, progress_cb=None, log_cb=None, cancel_event=None):
        self.case = case
        self.db = db
        self.inputs = inputs or {}
        self.profile = profile
        self.evidence = db.evidence()
        self.tz = get_tz(case.info.display_timezone)
        self._progress = progress_cb
        self._log = log_cb
        self._cancel = cancel_event
        self.analyzer_id = ""
        self.cache: dict = {}
        self.answers_pending: dict[str, dict] = {}

    # ------------------------------------------------------------------ evidence helpers
    def ev(self, evidence_id: int) -> dict:
        for e in self.evidence:
            if e["id"] == evidence_id:
                return e
        return {}

    def ev_label(self, evidence_id: int | None) -> str:
        if evidence_id is None:
            return "case"
        e = self.ev(evidence_id)
        host = (e.get("os") or {}).get("hostname") or (e.get("info") or {}).get("os", {}).get("hostname")
        return f"{e.get('label', '?')}" + (f" ({host})" if host and host not in e.get("label", "") else "")

    def role(self, evidence_id: int) -> str:
        return self.ev(evidence_id).get("role", "other")

    def by_role(self, *roles) -> list[dict]:
        return [e for e in self.evidence if e.get("role") in roles]

    def windows_evidence(self) -> list[dict]:
        return [e for e in self.evidence if (e.get("os") or {}).get("family") == "windows"]

    def ev_tz(self, evidence_id: int):
        osd = self.ev(evidence_id).get("os") or {}
        name = osd.get("timezone_iana") or osd.get("timezone_name")
        return get_tz(name) if name else None

    # ------------------------------------------------------------------ data access
    def artifacts(self, type_, evidence_id=None, where="", params=(), order="ts", limit=None):
        return self.db.artifacts(evidence_id, type_, where=where, params=params, order=order, limit=limit)

    def count(self, type_, evidence_id=None) -> int:
        sql = "SELECT COUNT(*) FROM artifacts WHERE type=?"
        args = [type_]
        if evidence_id is not None:
            sql += " AND evidence_id=?"
            args.append(evidence_id)
        return self.db.scalar(sql, args) or 0

    def coverage_status(self, evidence_id, artifact_like: str) -> str | None:
        r = self.db.query("SELECT status FROM coverage WHERE evidence_id=? AND artifact LIKE ? LIMIT 1", (evidence_id, artifact_like))
        return r[0]["status"] if r else None

    @property
    def window(self):
        tw = self.inputs.get("time_window") or {}
        return parse_any(tw.get("start")), parse_any(tw.get("end"))

    def in_window(self, ts, pad_minutes: int = 0) -> bool:
        start, end = self.window
        t = from_db(ts) if isinstance(ts, str) else ts
        if t is None:
            return False
        if start and t < start - timedelta(minutes=pad_minutes):
            return False
        if end and t > end + timedelta(minutes=pad_minutes):
            return False
        return True

    # ------------------------------------------------------------------ formatting
    def t(self, ts, tz=None) -> str:
        """Timestamp as 'YYYY-MM-DD HH:MM:SS UTC' (+ local in the display zone)."""
        from ..core.timeutil import fmt_dual

        if not ts:
            return "-"
        return fmt_dual(ts, tz or self.tz)

    def ts_short(self, ts) -> str:
        return fmt(ts, UTC, with_zone=False) if ts else ""

    # ------------------------------------------------------------------ outputs
    def finding(self, title: str, description: str, *, evidence_id=None, severity="medium", confidence="medium",
                category="", ts=None, details: dict | None = None, refs: list | None = None, figures: list | None = None,
                questions: list | None = None, tags: list | None = None, mitre: list | None = None, sort_key: float = 0) -> int:
        fid = self.db.add_finding({
            "evidence_id": evidence_id, "analyzer": self.analyzer_id, "category": category or self.analyzer_id,
            "title": title, "severity": severity, "confidence": confidence, "ts": db_ts(parse_any(ts)) if ts else None,
            "description": description, "details": details or {}, "refs": refs or [], "figures": figures or [],
            "questions": questions or [], "tags": tags or [], "mitre": mitre or [],
            "sort_key": sort_key or SEV_ORDER.get(severity, 5) * 1000 + self._next_seq() * 0.001,
        })
        return fid

    def _next_seq(self) -> int:
        self.cache["_seq"] = self.cache.get("_seq", 0) + 1
        return self.cache["_seq"]

    def answer(self, qid: str, status: str, summary: str, finding_ids: list[int] | None = None, priority: int = 0) -> None:
        """Answers from several analyzers are merged: the strongest status wins, summaries are concatenated."""
        rank = {YES: 4, INDICATED: 3, INCONCLUSIVE: 2, NO: 1, NA: 0}
        cur = self.answers_pending.get(qid)
        if cur is None:
            self.answers_pending[qid] = {"status": status, "summary": [summary] if summary else [], "fids": list(finding_ids or [])}
            return
        if rank.get(status, 0) > rank.get(cur["status"], 0):
            cur["status"] = status
            if summary:
                cur["summary"].insert(0, summary)
        elif summary and summary not in cur["summary"] and not (status in (NO, NA) and cur["status"] in (YES, INDICATED, INCONCLUSIVE)):
            cur["summary"].append(summary)
        cur["fids"] += [f for f in finding_ids or [] if f not in cur["fids"]]

    def flush_answers(self) -> None:
        for qid, a in self.answers_pending.items():
            self.db.set_answer(qid, a["status"], "\n".join(a["summary"]), a["fids"])

    def timeline(self, evidence_id, ts, source: str, event: str, description: str, user=None, ref_kind="", ref_id=None,
                 flagged: bool = True) -> None:
        self.cache.setdefault("_timeline", []).append(
            (evidence_id, db_ts(parse_any(ts)) if not isinstance(ts, str) else ts, source, event, description, user, ref_kind,
             ref_id, 1 if flagged else 0))

    def flush_timeline(self) -> None:
        rows = [r for r in self.cache.pop("_timeline", []) if r[1]]
        if rows:
            seen = set()
            uniq = []
            for r in rows:
                k = (r[0], r[1], r[3], r[4][:200])
                if k not in seen:
                    seen.add(k)
                    uniq.append(r)
            self.db.insert_timeline(uniq)

    # ------------------------------------------------------------------ feedback
    def progress(self, fraction: float, status: str = "") -> None:
        if self._progress:
            self._progress(fraction, status)
        if self._cancel is not None and self._cancel.is_set():
            from ..core.context import Cancelled

            raise Cancelled()

    def info(self, msg: str) -> None:
        if self._log:
            self._log("info", msg)

    def warn(self, msg: str) -> None:
        if self._log:
            self._log("warning", msg)


# ---------------------------------------------------------------------- figure helpers
def table_figure(title: str, columns: list[str], rows: list[list], *, style: str = "app", highlight_rows=None,
                 highlight_cells=None, callouts=None, caption: str = "", source: str = "", col_widths=None,
                 window_title: str = "", sheet: str = "") -> dict:
    """Specification of a table 'screenshot' (rendered by winforensics.report.figures)."""
    return {"kind": "table", "style": style, "title": title, "columns": columns,
            "rows": [[("" if v is None else str(v)) for v in r] for r in rows], "highlight_rows": highlight_rows or [],
            "highlight_cells": highlight_cells or [], "callouts": callouts or [], "caption": caption, "source": source,
            "col_widths": col_widths or [], "window_title": window_title, "sheet": sheet}


def hex_figure(title: str, data_hex: str, base_offset: int, hit_start: int, hit_len: int, meta: dict, caption: str = "",
               callout: str = "") -> dict:
    return {"kind": "hex", "title": title, "data_hex": data_hex, "base_offset": base_offset, "hit_start": hit_start,
            "hit_len": hit_len, "meta": meta, "caption": caption, "callout": callout}


def registry_figure(title: str, key_path: str, values: list[list], *, highlight=None, last_write: str = "", caption: str = "",
                    callouts=None, tree: list[str] | None = None) -> dict:
    return {"kind": "registry", "title": title, "key_path": key_path, "values": values, "highlight": highlight or [],
            "last_write": last_write, "caption": caption, "callouts": callouts or [], "tree": tree or []}


def timeline_figure(title: str, lanes: list[dict], caption: str = "", start=None, end=None) -> dict:
    """lanes: [{label, spans:[{start,end,label}], events:[{ts,label,kind}]}]"""
    return {"kind": "timeline", "title": title, "lanes": lanes, "caption": caption, "start": start, "end": end}


def callout(row: int, col: int, n: int, text: str) -> dict:
    return {"row": row, "col": col, "n": n, "text": text}
