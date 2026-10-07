"""Threat scenarios with exact ground truth (tests/fixtures/build_threats.py builds the images).

Each image is processed once and then analyzed with every profile listed in its ground truth; every question must be
answered with exactly the expected status.  CLEAN-01 is the negative control: no threat question may be answered Yes.

    python -m tests.fixtures.build_threats
    python -m pytest tests/test_scenarios.py -m slow
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCEN = os.path.join(ROOT, "test_data", "scenarios")
GT_FILE = os.path.join(SCEN, "ground_truth.json")

pytestmark = [pytest.mark.slow, pytest.mark.skipif(not os.path.exists(GT_FILE),
                                                   reason="scenario images missing - run tests/fixtures/build_threats.py")]
GT = json.load(open(GT_FILE)) if os.path.exists(GT_FILE) else {"answers": {}, "facts": {}}
CASES = [(m, p, q, s) for m, profiles in GT["answers"].items() for p, qs in profiles.items() for q, s in qs.items()]


def _cli(*args):
    res = subprocess.run([sys.executable, "-m", "winforensics", *args], cwd=ROOT, capture_output=True, text=True, timeout=3600)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-3000:]


@pytest.fixture(scope="session")
def results(tmp_path_factory):
    from winforensics.core.case import Case

    out = {}
    for machine, profiles in GT["answers"].items():
        case = str(tmp_path_factory.mktemp(machine) / "case")
        first, *rest = list(profiles)
        _cli("new", "--case", case, "--profile", first, "--quiet", "--name", machine, "--examiner", "pytest",
             "--evidence", f"{os.path.join(SCEN, machine + '.E01')}:source:{machine}", "--run")
        c = Case.open(case)
        out[(machine, first)] = c.db.answers()
        out[(machine, "_case")] = case
        c.close()
        for p in rest:
            _cli("run", "--case", case, "--profile", p, "--phases", "analysis", "--quiet")
            c = Case.open(case)
            out[(machine, p)] = c.db.answers()
            c.close()
    return out


@pytest.mark.parametrize("machine,profile,question,expected", CASES, ids=[f"{m}-{p}-{q}" for m, p, q, _ in CASES])
def test_answer(results, machine, profile, question, expected):
    got = results[(machine, profile)].get(question)
    assert got, f"{question} was not answered"
    assert got["status"] == expected, f"{machine} / {profile} / {question}: {got['status']} - {got['summary']}"


def _db(results, machine):
    from winforensics.core.case import Case

    return Case.open(results[(machine, "_case")]).db


def _artifacts(db, typ):
    return [json.loads(r["data_json"] or "{}") | {"_ts": r["ts"], "_user": r["user"]}
            for r in db.query("SELECT ts, user, data_json FROM artifacts WHERE type=?", (typ,))]


def test_clickfix_facts(results):
    db = _db(results, "CLICKFIX-01")
    f = GT["facts"]["CLICKFIX-01"]
    run = [a for a in _artifacts(db, "run_mru") if f["c2"] in a["command"]]
    assert len(run) == 1 and run[0]["mru_position"] == 0 and not run[0]["command"].endswith("\\1")
    assert any(a.get("name") == f["run_key"] and f["payload"] in a.get("command", "") for a in _artifacts(db, "autorun"))
    assert any(a["executable"].lower().endswith(f["payload"]) for a in _artifacts(db, "prefetch"))


def test_phish_facts(results):
    db = _db(results, "PHISH-01")
    f = GT["facts"]["PHISH-01"]
    td = _artifacts(db, "trusted_doc")
    assert len(td) == 1 and td[0]["macros_enabled"] == "Yes" and td[0]["path"].endswith(f["document"])
    assert "\\Users\\asmith\\" in td[0]["path"]
    proc = [a for a in _artifacts(db, "evt_process") if a["process"].lower().endswith("powershell.exe")]
    assert len(proc) == 1 and proc[0]["parent"].upper().endswith("WINWORD.EXE")


def test_rmm_facts(results):
    db = _db(results, "RMM-01")
    f = GT["facts"]["RMM-01"]
    tools = _artifacts(db, "rmm_tool")
    assert [t["tool"] for t in tools] == ["AnyDesk"] and tools[0]["executed"] == "Yes"
    conns = _artifacts(db, "rmm_connection")
    assert any(c["remote_id"] == f["remote_id"] for c in conns)
    assert any(c["remote_ip"] == f["remote_ip"] and c["direction"] == "incoming" for c in conns)
    # connection_trace.txt: one incoming session, remote ID in the ID column (not the authorization column "User")
    trace = [c for c in conns if c["log_file"].lower().endswith("connection_trace.txt")]
    assert len(trace) == 1 and trace[0]["remote_id"] == f["remote_id"] and trace[0]["direction"] == "incoming"


def test_ransom_facts(results):
    db = _db(results, "RANSOM-01")
    f = GT["facts"]["RANSOM-01"]
    fails = [a for a in _artifacts(db, "evt_logon") if a["event_id"] == 4625]
    assert len(fails) == 42 and {a["source_ip"] for a in fails} == {f["attacker_ip"]}
    acct = _artifacts(db, "evt_account")
    assert any(a["event_id"] == 4720 and a["target_user"] == f["new_account"] for a in acct)
    grp = [a for a in acct if a["event_id"] == 4732]
    assert len(grp) == 1 and grp[0]["group"] == "Administrators"
    enc = db.query("SELECT COUNT(*) n FROM fs_entries WHERE ext=? AND deleted=0", (f["extension"],))[0]["n"]
    assert enc == f["encrypted_files"]


def test_clean_control_has_no_threat_findings(results):
    """Ordinary software (OneDrive, Teams, Zoom, Slack, VS Code, installers, updater tasks) must not be reported."""
    db = _db(results, "CLEAN-01")
    # the ordinary software must actually have been parsed (UTF-16 task XML, per-user installs, services)
    assert len(_artifacts(db, "scheduled_task")) == 3
    assert {"OneDrive", "com.squirrel.Teams.Teams"} <= {a.get("name") for a in _artifacts(db, "autorun")}
    titles = [r["title"] for r in db.query("SELECT title FROM findings")]
    bad = [t for t in titles if any(w in t.lower() for w in ("suspicious", "programs of interest", "persistence", "remote",
                                                              "ransomware", "pasted", "phishing", "credential"))]
    assert not bad, bad
