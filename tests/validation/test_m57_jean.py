"""Validation on the Digital Corpora M57-Jean scenario (Windows XP laptop; a salary spreadsheet leaked).

Image: https://digitalcorpora.org/corpora/scenarios/m57-jean/ (``python -m tests.validation.datasets m57_jean``).
The official solution is restricted to teaching staff, so every expected value below is a fact corroborated by two
independent records on the image (mail store and file system, recipient table and file hash).  Process the image with
the dlp_exfiltration profile and no prior information, then:

    set WFA_M57_CASE=C:\\Cases\\M57-Jean
    python -m pytest tests/validation/test_m57_jean.py -v

Storyline: Jean received "Please send me the information now" from a sender whose display name is alison@m57.biz but
whose address is tuckgorge@gmail.com, and replied with m57biz.xls attached - the reply went to tuckgorge@gmail.com.
"""

import json
import os

import pytest

CASE = os.environ.get("WFA_M57_CASE", os.path.join(os.path.expanduser("~"), "Documents", "WFA-cases", "M57-Jean"))
SHA = "34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f"

pytestmark = [pytest.mark.cfreds,
              pytest.mark.skipif(not os.path.exists(os.path.join(CASE, "case.json")),
                                 reason="processed M57-Jean case not found (set WFA_M57_CASE)")]


@pytest.fixture(scope="module")
def db():
    from winforensics.core.case import Case

    c = Case.open(CASE)
    yield c.db
    c.close()


def arts(db, typ):
    return [dict(json.loads(r["data_json"] or "{}"), _ts=r["ts"]) for r in db.query("SELECT ts, data_json FROM artifacts WHERE type=?", (typ,))]


def test_lure_message_has_impersonated_sender(db):
    from winforensics.analyzers.common import sender_impersonation

    lure = [m for m in arts(db, "email_message") if m["subject"] == "Please send me the information now"]
    assert len(lure) == 1 and lure[0]["_ts"].startswith("2008-07-20 01:22:45")
    assert sender_impersonation(lure[0]["sender"]) == ("alison@m57.biz", "tuckgorge@gmail.com")
    assert db.query("SELECT 1 FROM findings WHERE title LIKE 'Sender impersonation in received e-mail%'")


def test_reply_with_spreadsheet_went_to_the_impostor(db):
    reply = [m for m in arts(db, "email_message") if m["subject"] == "RE: Please send me the information now"]
    assert len(reply) == 1 and "Sent Items" in reply[0]["folder"] and reply[0]["_ts"].startswith("2008-07-20 01:28")
    assert reply[0]["to"] == "alison@m57.biz <tuckgorge@gmail.com>"  # display name, then the real address
    assert reply[0]["attachment_names"] == "m57biz.xls"


def test_sent_attachment_is_the_desktop_file(db):
    att = [a for a in arts(db, "email_attachment") if a["filename"] == "m57biz.xls"]
    assert len(att) == 1 and att[0]["sha256"] == SHA
    assert att[0]["local_copies"] == "C:\\Documents and Settings\\Jean\\Desktop\\m57biz.xls"
    fs = db.query("SELECT si_created, size FROM fs_entries WHERE lower(path)=? AND deleted=0",
                  ("\\documents and settings\\jean\\desktop\\m57biz.xls",))
    assert fs and fs[0]["size"] == 291840 and fs[0]["si_created"].startswith("2008-07-20 01:28:03")


def test_dlp_answer_names_file_destination_and_copy(db):
    s = db.answers()["dlp.other_channels"]["summary"]
    assert "m57biz.xls to alison@m57.biz <tuckgorge@gmail.com>" in s
    assert "byte-identical to C:\\Documents and Settings\\Jean\\Desktop\\m57biz.xls" in s


def test_no_false_anti_forensics(db):
    assert db.answers()["anti_forensics"]["status"] in ("No evidence found", "Inconclusive")
