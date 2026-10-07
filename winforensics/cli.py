"""Command line interface (headless processing, automation, CI).

    winforensics profiles
    winforensics new  --case DIR --profile dlp_exfiltration --evidence IMG.E01:source:"Corporate laptop" ...
                 [--dlp-export alerts.csv] [--hash-list hashes.txt] [--reference DIR] [--keyword K] [--usb-serial S]
                 [--user U] [--start ISO] [--end ISO] [--domain D] [--sample FILE] [--ioc-file iocs.txt] [--option k=v]
    winforensics run  --case DIR [--no-report] [--phases evidence,analysis,report]
    winforensics report --case DIR
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading

from . import __app_title__, __version__


def _bar(f: float, width: int = 36) -> str:
    n = int(f * width)
    return "#" * n + "-" * (width - n)


class ConsoleListener:
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.last = ""
        self.lock = threading.Lock()

    def __call__(self, ev):
        with self.lock:
            if ev["type"] == "log":
                if ev["level"] in ("warning", "error") or not self.quiet:
                    sys.stdout.write("\r" + " " * 120 + "\r")
                    print(f"[{ev['level'].upper():7}] {ev['msg']}")
            elif ev["type"] == "progress":
                f = ev["fraction"]
                eta = ev.get("eta")
                eta_s = f"ETA {int(eta // 60)}m{int(eta % 60):02d}s" if eta else "ETA --"
                running = [t for t in ev["tasks"] if t["state"] == "running"]
                cur = (running[0]["title"] + " - " + (running[0]["status"] or ""))[:60] if running else ev.get("stage", "")
                line = f"\r[{_bar(f)}] {f * 100:5.1f}% {eta_s:>12}  {cur:<60}"
                sys.stdout.write(line)
                sys.stdout.flush()
            elif ev["type"] == "done":
                print(f"\nJob {ev['status']} in {ev.get('elapsed', 0):.1f}s")
                if ev.get("report"):
                    for k, v in ev["report"].items():
                        print(f"  {k}: {v}")


def parse_evidence(spec: str) -> dict:
    parts = spec.split(":")
    # Windows paths contain a drive colon - rebuild path
    if len(parts) >= 2 and len(parts[0]) == 1:
        parts = [parts[0] + ":" + parts[1]] + parts[2:]
    path = parts[0]
    role = parts[1] if len(parts) > 1 and parts[1] else "other"
    label = parts[2] if len(parts) > 2 and parts[2] else os.path.splitext(os.path.basename(path))[0]
    return {"path": path, "role": role, "label": label}


def cmd_profiles(args):
    from .profiles import load_profiles

    for p in load_profiles().values():
        print(f"{p.id:24} {p.name:44} {p.summary}")


def cmd_new(args):
    from .core.case import CaseInfo
    from .core.caseops import create_case
    from .profiles import get_profile

    profile = get_profile(args.profile)
    options = {}
    for o in args.option or []:
        k, _, v = o.partition("=")
        options[k] = json.loads(v) if v.lower() in ("true", "false") or v.replace(".", "").isdigit() else v
    info = CaseInfo(case_number=args.case_number or "", case_name=args.name or os.path.basename(os.path.abspath(args.case)),
                    examiner=args.examiner or "", organization=args.organization or "", description=args.description or "",
                    profile=profile.id, display_timezone=args.timezone or "UTC", options=options)
    iocs = {}
    if args.ioc_file:
        from .knowledge import extract_iocs

        with open(args.ioc_file, encoding="utf-8", errors="replace") as fh:
            found = extract_iocs(fh.read())
        iocs = {"domains": found["domains"], "ips": found["ips"], "urls": found["urls"], "emails": found["emails"]}
    window = {"start": args.start, "end": args.end} if args.start or args.end else {}
    evidence = [parse_evidence(e) for e in args.evidence or []]
    print(f"Creating case in {args.case} with profile '{profile.name}' and {len(evidence)} evidence item(s)...")
    for e in evidence:
        print(f"  probing {e['path']} ...")
    case = create_case(args.case, info, evidence, dict(
        dlp_exports=args.dlp_export or [], hash_lists=args.hash_list or [], reference_paths=args.reference or [],
        usb_serials=args.usb_serial or [], users=args.user or [], window=window, domains=args.domain or [],
        keywords=args.keyword or [], background=args.background or "", iocs=iocs, samples=args.sample or [],
        yara_rules=args.yara or []), overwrite=args.force)
    for e in case.db.evidence():
        osd = e.get("os") or {}
        print(f"  E{e['id']} {e['label']:28} {e['role']:10} {e['format']:8} {osd.get('hostname') or '-':16} {osd.get('version') or ''}")
    print("Case created.")
    if args.run:
        args.phases = None
        args.no_report = False
        cmd_run(args)


def cmd_run(args):
    from .core.engine import Engine

    listener = ConsoleListener(quiet=getattr(args, "quiet", False))
    eng = Engine(args.case, listener=listener)
    phases = tuple(args.phases.split(",")) if getattr(args, "phases", None) else ("evidence", "analysis", "report")
    if getattr(args, "no_report", False):
        phases = tuple(p for p in phases if p != "report")
    res = eng.run(phases)
    return 0 if res["status"] == "completed" else 1


def cmd_rerun_module(args):
    """Re-run artifact modules on an already processed case (e.g. after a parser update) without reprocessing everything."""
    import time

    from .core.case import Case
    from .core.context import ModuleContext
    from .core.engine import DEFAULT_OPTIONS
    from .core.evidence import open_evidence
    from .core.inputs import normalize
    from .modules.base import MODULES, discover
    from .profiles import get_profile

    discover()
    case = Case.open(args.case)
    db = case.db
    mods = [m.strip() for m in args.module.split(",") if m.strip()]
    unknown = [m for m in mods if m not in MODULES]
    if unknown:
        print(f"Unknown module(s): {', '.join(unknown)}. Available: {', '.join(sorted(MODULES))}")
        return 2
    profile = get_profile(case.info.profile)
    options = {**DEFAULT_OPTIONS, **(profile.options or {}), **(case.info.options or {})}
    inputs = normalize(case.info.inputs or {})
    for cls in MODULES.values():
        for at in cls.artifact_types:
            db.register_type(at.id, at.title, at.category, cls.id, [c.to_dict() for c in at.columns], at.description)
    evs = [e for e in db.evidence() if not args.evidence or e["id"] == args.evidence]
    for ev in evs:
        opened = open_evidence(ev["path"], (ev.get("options") or {}).get("keys"))
        ctx = ModuleContext(case=case, evidence=ev, opened=opened, db=db, inputs=inputs, options=options,
                            log_cb=lambda level, msg: print(f"  [{level}] {msg}"))
        for mid in mods:
            cls = MODULES[mid]
            types = [at.id for at in cls.artifact_types]
            with db.conn:
                if types:
                    db.conn.execute(f"DELETE FROM artifacts WHERE evidence_id=? AND type IN ({','.join('?' * len(types))})",
                                    (ev["id"], *types))
                db.conn.execute("DELETE FROM coverage WHERE evidence_id=? AND module=?", (ev["id"], mid))
            ctx.module_id = mid
            t = time.time()
            inst = cls()
            if not inst.applicable(ctx):
                print(f"E{ev['id']:02d} {mid}: not applicable")
                continue
            before = dict(ctx.counts)
            inst.run(ctx)
            ctx.flush()
            new = {k: v - before.get(k, 0) for k, v in ctx.counts.items() if v - before.get(k, 0)}
            print(f"E{ev['id']:02d} {mid}: {time.time() - t:.1f}s {new}")
    print("Done. Re-run the analysis and report:  run --case <case> --phases analysis,report")
    return 0


def cmd_report(args):
    from .core.case import Case
    from .report.builder import build_report

    case = Case.open(args.case)

    def prog(f, s):
        sys.stdout.write(f"\r[{_bar(f)}] {f * 100:5.1f}% {s[:60]:<60}")
        sys.stdout.flush()

    out = build_report(case, progress=prog)
    print()
    for k, v in out.items():
        print(f"  {k}: {v}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="winforensics", description=f"{__app_title__} {__version__} - automated Windows forensics")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("profiles", help="list investigation profiles")
    n = sub.add_parser("new", help="create a case")
    n.add_argument("--case", required=True)
    n.add_argument("--profile", required=True)
    n.add_argument("--evidence", action="append", help="PATH[:role[:label]]")
    n.add_argument("--name")
    n.add_argument("--case-number")
    n.add_argument("--examiner")
    n.add_argument("--organization")
    n.add_argument("--description")
    n.add_argument("--background")
    n.add_argument("--timezone")
    n.add_argument("--dlp-export", action="append")
    n.add_argument("--hash-list", action="append")
    n.add_argument("--reference", action="append")
    n.add_argument("--keyword", action="append")
    n.add_argument("--usb-serial", action="append")
    n.add_argument("--user", action="append")
    n.add_argument("--domain", action="append")
    n.add_argument("--sample", action="append")
    n.add_argument("--yara", action="append")
    n.add_argument("--ioc-file")
    n.add_argument("--start")
    n.add_argument("--end")
    n.add_argument("--option", action="append", help="key=value processing option")
    n.add_argument("--force", action="store_true", help="overwrite an existing case")
    n.add_argument("--run", action="store_true", help="process immediately")
    n.add_argument("--quiet", action="store_true")
    r = sub.add_parser("run", help="process a case")
    r.add_argument("--case", required=True)
    r.add_argument("--phases")
    r.add_argument("--no-report", action="store_true")
    r.add_argument("--quiet", action="store_true")
    rp = sub.add_parser("report", help="(re)build the report")
    rp.add_argument("--case", required=True)
    rm = sub.add_parser("rerun-module", help="re-run artifact module(s) on a processed case (after a parser update)")
    rm.add_argument("--case", required=True)
    rm.add_argument("--module", required=True, help="module id(s), comma separated")
    rm.add_argument("--evidence", type=int, help="evidence id (default: all)")
    args = ap.parse_args(argv)
    if args.cmd == "profiles":
        return cmd_profiles(args)
    if args.cmd == "new":
        return cmd_new(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "rerun-module":
        return cmd_rerun_module(args)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
