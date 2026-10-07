"""Process every public reference image from scratch, then run the validation suites.

    python -m tests.validation.reprocess_all --data D:\\WFA-datasets --cases D:\\WFA-cases

Expects the images where ``python -m tests.validation.datasets`` puts them (``<data>/<dataset>/...``), or pass the CFReDS
data leakage image folder with ``--leakage``.  Each case is created with the profile its validation uses and no prior
information.
"""

from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def first(pattern: str) -> str:
    hits = sorted(glob.glob(pattern))
    if not hits:
        raise FileNotFoundError(pattern)
    return hits[0]


def main(argv=None) -> int:
    home = os.path.expanduser("~")
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(home, "Documents", "WFA-datasets"))
    ap.add_argument("--cases", default=os.path.join(home, "Documents", "WFA-cases"))
    ap.add_argument("--leakage", help="folder of cfreds_2015_data_leakage_pc.E01 (default: <data>/cfreds_data_leakage)")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args(argv)
    d = a.data
    plan = {
        "CFReDS-DataLeakage": ("dlp_exfiltration", "WFA_CFREDS_CASE",
                               [first(os.path.join(a.leakage or os.path.join(d, "cfreds_data_leakage"), "*.E01")) + ":source:PC"]),
        "CFReDS-Hacking": ("general_triage", "WFA_HACKING_CASE",
                           [first(os.path.join(d, "cfreds_hacking", "*.E01")) + ":source:Dell CPi"]),
        "M57-Jean": ("dlp_exfiltration", "WFA_M57_CASE", [first(os.path.join(d, "m57_jean", "*.E01")) + ":source:Jean laptop"]),
        "Szechuan": ("general_triage", "WFA_SZECHUAN_CASE",
                     [first(os.path.join(d, "szechuan_dc", "**", "*.E01")) + ":source:DC01",
                      first(os.path.join(d, "szechuan_desktop", "*.E01")) + ":source:DESKTOP-SDN1RPT"]),
    }
    env = dict(os.environ)
    for name, (profile, var, evidence) in plan.items():
        case = os.path.join(a.cases, name)
        env[var] = case
        if a.only and name not in a.only:
            continue
        cmd = [sys.executable, "-m", "winforensics", "new", "--case", case, "--profile", profile, "--name", name,
               "--examiner", "validation", "--quiet", "--force", "--run"]
        for e in evidence:
            cmd += ["--evidence", e]
        t = time.time()
        print(f"[{name}] processing ({profile}) ...", flush=True)
        res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        print(f"[{name}] exit {res.returncode} in {time.time() - t:.0f} s", flush=True)
        if res.returncode:
            print(res.stdout[-2000:], res.stderr[-2000:])
            return res.returncode
    return subprocess.run([sys.executable, "-m", "pytest", "tests/validation", "-v", "-p", "no:cacheprovider"], cwd=ROOT,
                          env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
