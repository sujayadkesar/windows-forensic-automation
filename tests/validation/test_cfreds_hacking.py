"""Validation against the NIST CFReDS "Hacking Case" answer key (Windows XP).

Image and answers: https://cfreds-archive.nist.gov/ ("4Dell Latitude CPi.E01/.E02", TestAnswers.pdf).
``python -m tests.validation.datasets cfreds_hacking`` downloads both.  Process the image with the general_triage
profile, then:

    set WFA_HACKING_CASE=C:\\Cases\\CFReDS-Hacking
    python -m pytest tests/validation/test_cfreds_hacking.py -v

NIST quotes local time (CDT, UTC-5); every value here is converted to UTC.  Questions about file contents (IRC logs,
newsgroup lists, the intercepted traffic) are answered by reading the files the tool indexes and are not asserted.
"""

import json
import os
from datetime import datetime

import pytest

CASE = os.environ.get("WFA_HACKING_CASE", os.path.join(os.path.expanduser("~"), "Documents", "WFA-cases", "CFReDS-Hacking"))

pytestmark = [pytest.mark.cfreds,
              pytest.mark.skipif(not os.path.exists(os.path.join(CASE, "case.json")),
                                 reason="processed CFReDS hacking case not found (set WFA_HACKING_CASE)")]


@pytest.fixture(scope="module")
def db():
    from winforensics.core.case import Case

    c = Case.open(CASE)
    yield c.db
    c.close()


def arts(db, typ):
    return [dict(json.loads(r["data_json"] or "{}"), _ts=r["ts"], _user=r["user"])
            for r in db.query("SELECT ts, user, data_json FROM artifacts WHERE type=?", (typ,))]


def props(db):
    out = {}
    for a in arts(db, "sys_info"):
        out.setdefault(a["property"], []).append(a["value"])
    return out


def near(a, b, seconds=2):
    return bool(a and b) and abs((datetime.fromisoformat(str(a)[:26]) - datetime.fromisoformat(b)).total_seconds()) <= seconds


def test_q1_acquisition_hash(db):
    info = db.evidence()[0]["info"]
    assert info["ewf"]["stored_hashes"]["md5"].upper() == "AEE4FCD9301C03B3B054623CA261959A"


def test_q2_operating_system(db):
    assert "Windows XP" in props(db)["Operating system"][0]


def test_q3_install_date(db):
    # 08/19/04 05:48:27 PM CDT
    assert near(props(db)["Install date (UTC)"][0], "2004-08-19 22:48:27")


def test_q4_time_zone(db):
    assert "Central" in props(db)["Time zone"][0]


def test_q5_registered_owner(db):
    assert props(db)["Registered owner"][0] == "Greg Schardt"


def test_q6_computer_name(db):
    assert props(db)["Computer name"][0] == "N-1A9ODN6ZXK4LQ"


def test_q7_primary_domain(db):
    assert props(db)["Primary domain / workgroup (LSA)"][0].upper() == "EVIL"


def test_q8_last_shutdown(db):
    # 08/27/04 10:46:33 AM CDT
    assert near(props(db)["Last shutdown (UTC)"][0], "2004-08-27 15:46:33")


def test_q9_q10_q11_accounts(db):
    acc = arts(db, "user_account")
    assert len(acc) == 5
    most = max(acc, key=lambda a: a.get("logon_count") or 0)
    last = max((a for a in acc if a.get("last_logon")), key=lambda a: a["last_logon"])
    assert most["name"] == "Mr. Evil" and last["name"] == "Mr. Evil"


def test_q13_network_cards(db):
    cards = " | ".join(props(db)["Network adapter"])
    assert "Xircom CardBus Ethernet 100 + Modem 56" in cards and "Compaq WL110 Wireless LAN PC Card" in cards


def test_q14_ip_address(db):
    assert any(a.get("ip_address") == "192.168.1.111" for a in arts(db, "network_interface"))


def test_q16_hacking_programs(db):
    rows = []
    for f in db.query("SELECT figures_json FROM findings WHERE title LIKE 'Programs of interest%'"):
        for fig in json.loads(f["figures_json"] or "[]"):
            rows += [" ".join(str(c) for c in r) for r in (fig.get("spec") or fig).get("rows", [])]
    text = "\n".join(rows)
    for tool in ("Cain & Abel", "Ethereal", "123 Write All Stored Passwords", "Anonymizer", "CuteFTP", "Look@LAN",
                 "NetStumbler"):
        assert tool in text, tool


def test_q17_q18_q19_mail_and_news_accounts(db):
    acc = arts(db, "email_account")
    assert any(a["email"] == "whoknowsme@sbcglobal.net" and a["smtp_server"] == "smtp.sbcglobal.net" for a in acc)
    assert any(a["nntp_server"].lower() == "news.dallas.sbcglobal.net" for a in acc)
    assert all(a["client"].startswith("Outlook Express") for a in acc)


def test_q23_interception_capture_file(db):
    assert db.query("SELECT 1 FROM fs_entries WHERE lower(path)=? AND deleted=0",
                    ("\\documents and settings\\mr. evil\\interception",))


def test_q26_q27_yahoo_mail(db):
    assert any("mrevil" in (a.get("url") or "").lower() and "yahoo.com" in a["url"] for a in arts(db, "web_visit"))
    assert len(db.query("SELECT 1 FROM fs_entries WHERE lower(name)='showletter[1].htm' AND lower(path) LIKE '%content.ie5%'")) == 2


def test_q28_q29_recycle_bin(db):
    rb = arts(db, "recycle_bin")
    exes = [a for a in rb if a["original_path"].lower().endswith(".exe")]
    assert len(exes) == 4
    assert all(a["r_present"] == "Yes" for a in exes)  # Q29: not really deleted - the content is still in RECYCLER
    assert sorted(a["r_file"] for a in exes) == ["Dc1.exe", "Dc2.exe", "Dc3.exe", "Dc4.exe"]


def test_q30_files_deleted_in_file_system(db):
    assert db.query("SELECT COUNT(*) n FROM fs_entries WHERE deleted=1")[0]["n"] == 3


def test_xp_prefetch_run_data(db):
    """Version-17 prefetch: every file has a run count and a last-run time within the system's life."""
    pf = [a for a in arts(db, "prefetch") if not a.get("is_previous_run")]
    assert pf and all(a["version"] == 17 for a in pf)
    assert all(a["run_count"] >= 1 for a in pf)
    assert all("2004-08-19" <= (a["last_run"] or "")[:10] <= "2004-08-27" for a in pf)
    cain = [a for a in pf if a["executable"] == "CAIN.EXE"]
    assert cain and cain[0]["path"].endswith("\\PROGRAM FILES\\CAIN\\CAIN.EXE")


def test_xp_event_logs_parsed(db):
    logs = {a["file"].lower(): a for a in arts(db, "evtx_log")}
    assert logs["sysevent.evt"]["records"] > 0 and logs["secevent.evt"]["records"] == 0
    assert any(a["event_id"] == 6005 for a in arts(db, "evt_system"))


def test_no_false_positive_threat_answers(db):
    ans = db.answers()
    for q in ("ransom.encryption", "anti_forensics", "clickfix.command", "phish.executed", "persist.found"):
        assert ans[q]["status"] == "No evidence found", (q, ans[q]["summary"])
