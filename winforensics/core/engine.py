"""Processing engine.

``Engine.run()`` executes a complete case job:

1. **Evidence phase** - one worker *process* per evidence item (several in
   parallel).  A worker opens the image, optionally verifies its hash, then runs
   the profile's artifact modules and search engines in dependency order and
   streams progress / log messages back.
2. **Analysis phase** - the profile's analyzers correlate everything across all
   evidence items and write findings, answers and the case timeline.
3. **Report phase** - the Word report, Excel workbook and figures are produced.

Progress is tracked with :class:`ProgressModel` (weighted tasks, ETA) and pushed
to a listener callable (GUI or CLI).  A ``threading.Event``/``multiprocessing.Event``
cancels the job cooperatively.
"""

from __future__ import annotations

import json
import logging
import multiprocessing as mp
import os
import queue
import time
import traceback
from datetime import datetime

from .progress import DONE, FAILED, PENDING, RUNNING, SKIPPED, WARNING, ProgressModel, Task
from .timeutil import UTC, db_ts

log = logging.getLogger("winforensics.engine")

DEFAULT_OPTIONS = {
    "verify_hash": False, "carve": True, "vss": True, "raw_scope": "full", "hash_scope": "candidates", "doc_max_mb": 50,
    "max_hits_per_term_area": 500, "max_workers": 0, "fat_timezone": "", "generate_report": True,
}


def resolve_modules(selection, registry: dict) -> list[str]:
    """Expand a profile module selection with dependencies and order by ``order``."""
    if selection in (None, "all", ["all"]):
        wanted = set(registry)
    else:
        wanted = {m for m in selection if m in registry}
    changed = True
    while changed:
        changed = False
        for m in list(wanted):
            for dep in getattr(registry[m], "requires", []) or []:
                if dep in registry and dep not in wanted:
                    wanted.add(dep)
                    changed = True
    return sorted(wanted, key=lambda m: (registry[m].order, m))


# ============================================================================ worker process
def evidence_worker(case_path: str, evidence_id: int, module_ids: list[str], options: dict, inputs: dict, q, cancel_event):
    """Runs inside a child process."""
    import logging as _logging

    from .case import Case
    from .context import Cancelled, ModuleContext
    from .evidence import open_evidence, probe_target, verify_image
    from ..modules.base import MODULES, discover

    import warnings

    warnings.filterwarnings("ignore")
    case = Case.open(case_path)
    logfile = case.sub("logs", f"evidence_{evidence_id:02d}.log")
    _logging.basicConfig(filename=logfile, level=_logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                         force=True)
    db = case.db

    def send(*msg):
        try:
            # round-trip through JSON: dissect returns cstruct integer subclasses that cannot be pickled
            q.put(json.loads(json.dumps(msg, default=str)))
        except Exception:
            pass

    def logcb(level, msg):
        send("log", evidence_id, level, msg)

    status = "completed"
    try:
        discover()
        ev = db.evidence(evidence_id)
        db.update_evidence(evidence_id, status="processing")
        if options.get("rerun", True):
            db.clear_evidence_results(evidence_id)
            # outputs written by the previous run of this evidence item (parsed CSVs, collected files, exports)
            import shutil

            from .exporter import evidence_folder

            for kind in ("Parsed", "Collected"):
                shutil.rmtree(evidence_folder(case, ev, kind), ignore_errors=True)
            shutil.rmtree(os.path.join(case.path, "exports", f"E{evidence_id:02d}"), ignore_errors=True)
        logcb("info", f"Opening {ev['path']}")
        opened = open_evidence(ev["path"], (ev.get("options") or {}).get("keys"))
        for w in opened.warnings:
            logcb("warning", w)
        info = probe_target(opened.target)
        if opened.ewf_meta:
            info["ewf"] = opened.ewf_meta
        try:
            info["media_size"] = sum(d.size for d in opened.target.disks)
        except Exception:
            pass
        merged = dict(ev.get("info") or {})
        merged.update(info)
        db.update_evidence(evidence_id, info=merged, os=info.get("os") or {})
        ev = db.evidence(evidence_id)
        send("evinfo", evidence_id, {"os": info.get("os"), "volumes": len(info.get("volumes", [])),
                                     "media_size": info.get("media_size")})
        ctx = ModuleContext(case=case, evidence=ev, opened=opened, db=db, inputs=inputs, options=options,
                            log_cb=logcb, cancel_event=cancel_event)
        # plan
        plan = []
        if options.get("verify_hash"):
            size = info.get("media_size") or 0
            plan.append(("verify", "Verify image hash", 1.0 + size / (180 * 1024 * 1024), "Integrity"))
        mods = []
        for mid in module_ids:
            cls = MODULES[mid]
            inst = cls()
            try:
                applicable = inst.applicable(ctx)
            except Exception:
                applicable = False
            if not applicable:
                send("skip", evidence_id, mid, cls.title, "not applicable to this evidence (no Windows installation)")
                db.add_coverage(evidence_id, mid, cls.title, "-", "skipped", 0, "not applicable to this evidence")
                continue
            try:
                w = float(inst.estimate(ctx))
            except Exception:
                w = cls.weight
            mods.append((mid, inst))
            plan.append((mid, cls.title, max(0.2, w), cls.category))
        if options.get("export_parsed", True):
            plan.append(("export", "Export parsed artifacts (CSV) for manual analysis", 2.0, "Export"))
        send("plan", evidence_id, plan)
        if options.get("verify_hash"):
            send("task", evidence_id, "verify", RUNNING, 0.0, "Hashing", 0, "")

            def vprog(f, s):
                send("task", evidence_id, "verify", RUNNING, f, s, 0, "")

            res = verify_image(ev["path"], vprog, lambda: cancel_event.is_set())
            if res.get("cancelled"):
                raise Cancelled()
            db.update_evidence(evidence_id, hashes=res)
            note = ("verified - matches acquisition hash" if res.get("verified") else
                    "MISMATCH with acquisition hash" if res.get("verified") is False else "computed (no stored hash to compare)")
            send("task", evidence_id, "verify", DONE if res.get("verified") is not False else WARNING, 1.0, note, 0, note)
            logcb("info" if res.get("verified") is not False else "error", f"Image hash {note}: MD5 {res.get('md5')}")
        for mid, inst in mods:
            ctx.check_cancel()
            ctx.module_id = mid
            ctx.counts = {}
            started = time.time()
            send("task", evidence_id, mid, RUNNING, 0.0, "starting", 0, "")

            def prog(f, s, _mid=mid):
                send("task", evidence_id, _mid, RUNNING, f, s, sum(ctx.counts.values()), "")

            ctx._progress_cb = prog
            try:
                inst.run(ctx)
                ctx.flush()
                items = sum(ctx.counts.values())
                send("task", evidence_id, mid, DONE, 1.0, f"{items:,} records" if items else "nothing found", items,
                     f"{time.time() - started:.1f}s")
            except Cancelled:
                raise
            except Exception as e:
                ctx.flush()
                logcb("error", f"{mid}: {type(e).__name__}: {e}")
                _logging.getLogger("winforensics").exception("module %s failed", mid)
                db.add_coverage(evidence_id, mid, inst.title, "-", "error", 0, f"{type(e).__name__}: {e}"[:300])
                send("task", evidence_id, mid, FAILED, 1.0, f"error: {e}"[:200], sum(ctx.counts.values()), "")
        if options.get("export_parsed", True):
            from .exporter import export_parsed

            send("task", evidence_id, "export", RUNNING, 0.0, "writing CSV files", 0, "")
            try:
                written = export_parsed(case, evidence_id, lambda f, s: send("task", evidence_id, "export", RUNNING, f, s, 0, ""))
                send("task", evidence_id, "export", DONE, 1.0, f"{len(written)} CSV files", len(written), "")
            except Exception as e:
                logcb("error", f"parsed export: {e}")
                send("task", evidence_id, "export", FAILED, 1.0, f"error: {e}"[:200], 0, "")
        db.update_evidence(evidence_id, status="processed")
    except Cancelled:
        status = "cancelled"
        db.update_evidence(evidence_id, status="cancelled")
    except Exception as e:
        status = "failed"
        _logging.getLogger("winforensics").exception("evidence worker failed")
        send("log", evidence_id, "error", f"Evidence processing failed: {type(e).__name__}: {e}")
        db.update_evidence(evidence_id, status="failed")
        send("end", evidence_id, status, traceback.format_exc()[-2000:])
        return
    send("end", evidence_id, status, "")


# ============================================================================ engine
class Engine:
    def __init__(self, case_path: str, listener=None, cancel_event=None):
        from .case import Case

        self.case = Case.open(case_path)
        self.listener = listener or (lambda ev: None)
        self.mp = mp.get_context("spawn")
        self.cancel = cancel_event or self.mp.Event()
        self.progress = ProgressModel()
        self.logs: list[dict] = []
        self._last_emit = 0.0
        self.status = "idle"

    # ------------------------------------------------------------------ events
    def emit(self, ev: dict, force: bool = False) -> None:
        try:
            self.listener(ev)
        except Exception:
            log.exception("listener failed")

    def log(self, level: str, msg: str, evidence_id=None) -> None:
        rec = {"type": "log", "level": level, "msg": msg, "evidence_id": evidence_id, "ts": time.time()}
        self.logs.append(rec)
        getattr(log, "error" if level == "error" else "warning" if level == "warning" else "info")(msg)
        self.emit(rec)

    def push_progress(self, force: bool = False, stage: str = "") -> None:
        now = time.time()
        if force or now - self._last_emit > 0.25:
            self._last_emit = now
            snap = self.progress.snapshot()
            snap["stage"] = stage or self.stage
            self.emit({"type": "progress", **snap})

    # ------------------------------------------------------------------ run
    def run(self, phases=("evidence", "analysis", "report"), evidence_ids: list[int] | None = None) -> dict:
        from ..modules.base import MODULES, discover
        from ..analyzers.base import discover as discover_analyzers
        from ..profiles import get_profile
        from .inputs import normalize

        self.status = "running"
        self.stage = "Preparing"
        started = time.time()
        case = self.case
        db = case.db
        discover()
        analyzers = discover_analyzers()
        profile = get_profile(case.info.profile)
        options = {**DEFAULT_OPTIONS, **(profile.options or {}), **(case.info.options or {})}
        inputs = normalize(case.info.inputs or {})
        db.meta("inputs_normalized", inputs)
        for cls in MODULES.values():
            for at in cls.artifact_types:
                db.register_type(at.id, at.title, at.category, cls.id, [c.to_dict() for c in at.columns], at.description)
        job_id = db.execute("INSERT INTO jobs(started, status, profile, options_json) VALUES (?,?,?,?)",
                            (db_ts(datetime.now(UTC)), "running", profile.id, json.dumps(options))).lastrowid
        db.commit()
        evidence = [e for e in db.evidence() if evidence_ids is None or e["id"] in evidence_ids]
        modules = resolve_modules(profile.modules, MODULES)
        self.log("info", f"Profile: {profile.name}; {len(evidence)} evidence item(s); {len(modules)} artifact modules")
        # placeholder tasks so the bar is meaningful from the start
        if "evidence" in phases:
            for e in evidence:
                size = e.get("size") or 1
                self.progress.add(Task(f"E{e['id']}:open", f"{e['label']}: open evidence", 1.0, group=f"E{e['id']}"))
                self.progress.add(Task(f"E{e['id']}:all", f"{e['label']}: artifacts & search", 5.0 + size / 8e7,
                                       group=f"E{e['id']}"))
        an_list = [a for a in profile.analyzers if a in analyzers]
        if "analysis" in phases:
            for a in an_list:
                self.progress.add(Task(f"A:{a}", f"Analysis: {analyzers[a].title or a}", max(0.5, analyzers[a].weight),
                                       group="Analysis"))
        if "report" in phases and options.get("generate_report", True):
            self.progress.add(Task("R:report", "Report: figures, Word report, Excel workbook", 6.0, group="Report"))
        self.push_progress(True)
        result = {"status": "completed"}
        try:
            if "evidence" in phases and evidence:
                self.stage = "Processing evidence"
                self._evidence_phase(evidence, modules, options, inputs)
            if self.cancel.is_set():
                raise _Cancel()
            if "analysis" in phases:
                self.stage = "Correlating & analyzing"
                self._analysis_phase(profile, an_list, analyzers, inputs)
            if self.cancel.is_set():
                raise _Cancel()
            if "report" in phases and options.get("generate_report", True):
                self.stage = "Building report"
                result["report"] = self._report_phase(profile)
        except _Cancel:
            result["status"] = "cancelled"
            self.log("warning", "Job canceled by user")
        except Exception as e:
            result["status"] = "failed"
            result["error"] = f"{type(e).__name__}: {e}"
            self.log("error", f"Job failed: {e}")
            log.exception("job failed")
        result["elapsed"] = time.time() - started
        db.execute("UPDATE jobs SET finished=?, status=?, log=? WHERE id=?",
                   (db_ts(datetime.now(UTC)), result["status"], json.dumps(self.logs[-500:], default=str), job_id))
        db.commit()
        self.status = result["status"]
        self.stage = {"completed": "Completed", "cancelled": "Canceled", "failed": "Failed"}[result["status"]]
        self.push_progress(True)
        self.emit({"type": "done", **result})
        return result

    # ------------------------------------------------------------------ evidence phase
    def _evidence_phase(self, evidence, modules, options, inputs):
        q = self.mp.Queue()
        max_workers = int(options.get("max_workers") or 0) or max(1, min(len(evidence), (os.cpu_count() or 2) // 2, 4))
        pending = list(evidence)
        running: dict[int, mp.Process] = {}
        ended: set[int] = set()
        planned: set[int] = set()

        def start_next():
            while pending and len(running) < max_workers:
                e = pending.pop(0)
                p = self.mp.Process(target=evidence_worker, name=f"winforensics-E{e['id']}",
                                    args=(self.case.path, e["id"], modules, options, inputs, q, self.cancel), daemon=True)
                p.start()
                running[e["id"]] = p
                t = self.progress.tasks.get(f"E{e['id']}:open")
                if t:
                    t.state, t.started = RUNNING, time.time()
                self.log("info", f"[{e['label']}] worker started (pid {p.pid})", e["id"])

        start_next()
        while running:
            try:
                msg = q.get(timeout=0.2)
            except queue.Empty:
                msg = None
            if msg:
                self._handle(msg, planned, ended)
            for eid, p in list(running.items()):
                if eid in ended and not p.is_alive():
                    p.join(0.1)
                    del running[eid]
                elif not p.is_alive() and eid not in ended:
                    # drain remaining messages
                    while True:
                        try:
                            self._handle(q.get(timeout=0.5), planned, ended)
                        except queue.Empty:
                            break
                    if eid not in ended:
                        self.log("error", f"Worker for evidence {eid} terminated unexpectedly (exit code {p.exitcode})", eid)
                        self._finish_group(eid, FAILED)
                        ended.add(eid)
                    del running[eid]
            if not self.cancel.is_set():
                start_next()
            else:
                pending.clear()
            self.push_progress()
        self.push_progress(True)

    def _handle(self, msg, planned, ended):
        kind, eid = msg[0], msg[1]
        grp = f"E{eid}"
        label = next((e["label"] for e in self.case.db.evidence() if e["id"] == eid), f"E{eid}") if kind in ("plan", "log", "end") else ""
        if kind == "log":
            self.log(msg[2], f"[{label}] {msg[3]}", eid)
        elif kind == "evinfo":
            t = self.progress.tasks.get(f"{grp}:open")
            if t:
                t.state, t.fraction, t.finished = DONE, 1.0, time.time()
                osd = msg[2].get("os") or {}
                t.status = f"{osd.get('hostname') or ''} {osd.get('version') or ''}".strip() or "opened"
            self.emit({"type": "evidence", "evidence_id": eid, **msg[2]})
        elif kind == "plan":
            placeholder = self.progress.tasks.pop(f"{grp}:all", None)
            if placeholder and f"{grp}:all" in self.progress.order:
                self.progress.order.remove(f"{grp}:all")
            for tid, title, weight, cat in msg[2]:
                self.progress.add(Task(f"{grp}:{tid}", f"{label}: {title}", weight, group=grp, status=cat))
            planned.add(eid)
        elif kind == "skip":
            pass
        elif kind == "task":
            _, _, tid, state, frac, status, items, note = msg
            t = self.progress.tasks.get(f"{grp}:{tid}")
            if t:
                if t.started is None:
                    t.started = time.time()
                t.state, t.fraction, t.status, t.items = state, frac, status, items
                if note:
                    t.note = note
                if state in (DONE, FAILED, WARNING, SKIPPED):
                    t.finished = time.time()
        elif kind == "end":
            status, err = msg[2], msg[3]
            ended.add(eid)
            self._finish_group(eid, DONE if status == "completed" else (SKIPPED if status == "cancelled" else FAILED))
            if err:
                self.log("error", f"[{label}] {err.strip().splitlines()[-1] if err.strip() else status}", eid)
            self.log("info" if status == "completed" else "warning", f"[{label}] evidence processing {status}", eid)

    def _finish_group(self, eid, state):
        for t in self.progress.tasks.values():
            if t.group == f"E{eid}" and t.state in (PENDING, RUNNING):
                t.state = state if t.state == RUNNING or state != DONE else SKIPPED
                t.finished = time.time()

    # ------------------------------------------------------------------ analysis phase
    def _analysis_phase(self, profile, an_list, analyzers, inputs):
        from ..analyzers.base import AnalyzerContext
        from .context import Cancelled

        db = self.case.db
        db.clear_case_findings()
        actx = AnalyzerContext(self.case, db, inputs, profile, log_cb=lambda lvl, m: self.log(lvl, f"[analysis] {m}"),
                               cancel_event=self.cancel)
        for aid in an_list:
            t = self.progress.tasks[f"A:{aid}"]
            t.state, t.started = RUNNING, time.time()

            def prog(f, s, _t=t):
                _t.fraction, _t.status = f, s
                self.push_progress()

            actx._progress = prog
            actx.analyzer_id = aid
            try:
                analyzers[aid]().run(actx)
                actx.flush_timeline()
                t.state, t.status = DONE, "done"
            except Cancelled:
                raise _Cancel()
            except Exception as e:
                t.state, t.status = FAILED, f"error: {e}"[:200]
                self.log("error", f"Analyzer {aid} failed: {type(e).__name__}: {e}")
                log.exception("analyzer %s failed", aid)
            t.fraction, t.finished = 1.0, time.time()
            self.push_progress(True)
        actx.flush_answers()
        n = len(db.findings())
        self.log("info", f"Analysis complete: {n} findings")

    # ------------------------------------------------------------------ report phase
    def _report_phase(self, profile):
        from ..report.builder import build_report

        t = self.progress.tasks["R:report"]
        t.state, t.started = RUNNING, time.time()

        def prog(f, s):
            t.fraction, t.status = f, s
            self.push_progress()

        try:
            out = build_report(self.case, progress=prog, cancel_event=self.cancel)
            t.state, t.status = DONE, os.path.basename(out.get("docx", ""))
            self.log("info", f"Report written: {out.get('docx')}")
            return out
        except Exception as e:
            t.state, t.status = FAILED, f"error: {e}"[:200]
            self.log("error", f"Report generation failed: {type(e).__name__}: {e}")
            log.exception("report failed")
            return {"error": str(e)}
        finally:
            t.fraction, t.finished = 1.0, time.time()
            self.push_progress(True)


class _Cancel(Exception):
    pass
