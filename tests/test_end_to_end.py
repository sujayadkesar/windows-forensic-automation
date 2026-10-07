"""End-to-end DLP case on the synthetic test images (tests/fixtures/build_all.py creates them).

    python -m pytest tests -m slow
"""

import csv
import glob
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(ROOT, "test_data", "evidence")
INP = os.path.join(ROOT, "test_data", "inputs")

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(not os.path.exists(os.path.join(EV, "WKSTN-TEST-01.E01")),
                                 reason="test images missing - run tests/fixtures/build_all.py")]


@pytest.fixture(scope="module")
def dlp_case(tmp_path_factory):
    case = str(tmp_path_factory.mktemp("dlp") / "case")
    cmd = [sys.executable, "-m", "winforensics", "new", "--case", case, "--profile", "dlp_exfiltration", "--quiet",
           "--name", "Pytest DLP", "--examiner", "pytest",
           "--evidence", f"{os.path.join(EV, 'WKSTN-TEST-01.E01')}:source:Corporate laptop",
           "--evidence", f"{os.path.join(EV, 'HOME-TEST-02.E01')}:personal:Personal laptop",
           "--evidence", f"{os.path.join(EV, 'USB-TEST.dd')}:removable:USB drive",
           "--dlp-export", os.path.join(INP, "dlp_alerts.csv"),
           "--option", "raw_threads=2", "--run"]
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=3600)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]
    from winforensics.core.case import Case

    c = Case.open(case)
    yield c
    c.close()


def test_questions_answered(dlp_case):
    answers = dlp_case.db.answers()
    assert answers["dlp.usb"]["status"] == "Yes"
    assert answers["dlp.device_match"]["status"] in ("Yes", "Indicated")
    assert answers["dlp.targets_present"]["status"] == "Yes"
    assert answers["dlp.alert_corroboration"]["status"] in ("Yes", "Indicated")


def test_usb_serial_found_on_both_laptops(dlp_case):
    serials = {}
    for a in dlp_case.db.query("SELECT evidence_id, data_json FROM artifacts WHERE type='usb_device'"):
        if "TESTSN000000000001" in (a["data_json"] or ""):
            serials[a["evidence_id"]] = True
    assert len(serials) >= 2


def test_parsed_exports_written(dlp_case):
    parsed = os.path.join(dlp_case.path, "Parsed")
    fs = glob.glob(os.path.join(parsed, "E01_*", "File System", "FileSystem_*.csv"))
    assert fs, os.listdir(parsed)
    with open(fs[0], encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    assert any("test_doc_alpha" in (r.get("Path") or r.get("FullPath") or "") for r in rows)
    assert glob.glob(os.path.join(parsed, "E01_*", "Event Logs - all records", "*.csv"))
    st = glob.glob(os.path.join(parsed, "E01_*", "SuperTimeline.csv"))
    assert st
    with open(st[0], encoding="utf-8-sig") as fh:
        times = [r["TimeUTC"] for r in csv.DictReader(fh)]
    assert times and times == sorted(times)


def test_raw_collection_with_manifest(dlp_case):
    man = glob.glob(os.path.join(dlp_case.path, "Collected", "E01_*", "_manifest.csv"))
    assert man
    with open(man[0], encoding="utf-8-sig") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("CollectedAs")]
    names = " ".join(r.get("SourcePath", "") for r in rows).lower()
    assert "$mft" in names and "system" in names
    assert all(len(r.get("SHA256") or "") == 64 for r in rows)


def test_report_files(dlp_case):
    rep = os.listdir(os.path.join(dlp_case.path, "reports"))
    assert any(f.endswith(".docx") for f in rep)
    assert any(f.endswith(".xlsx") for f in rep)
    assert any(f.endswith(".txt") for f in rep)
