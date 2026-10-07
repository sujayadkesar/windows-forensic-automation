"""Validation against DFIR Madness case 001 "The Stolen Szechuan Sauce" (Windows Server 2012 R2 DC + Windows 10 desktop).

Images and answers: https://dfirmadness.com/case001/ and https://dfirmadness.com/answers-to-szechuan-case-001/.
``python -m tests.validation.datasets szechuan_dc szechuan_desktop`` downloads both (MD5-verified).  Process both images
in one case with the general_triage profile and no prior information, then:

    set WFA_SZECHUAN_CASE=C:\\Cases\\Szechuan
    python -m pytest tests/validation/test_szechuan_case001.py -v

Clock: the official timeline is taken from the packet capture.  Every time recorded on both disks (event logs, $MFT,
$UsnJrnl, LNK, registry) is exactly one hour later than the official time - for example the service install the
answers give as 02:27:49 UTC is 03:27:49 UTC in the System log.  The two systems agree with each other to within
seconds (checked below), so the offset lies between the systems' clocks and the capture.  Expected values are the
official times plus CLOCK.
"""

import json
import os
from datetime import datetime, timedelta

import pytest

CASE = os.environ.get("WFA_SZECHUAN_CASE", os.path.join(os.path.expanduser("~"), "Documents", "WFA-cases", "Szechuan"))
CLOCK = timedelta(hours=1)
DC, DESKTOP = "DC01", "DESKTOP-SDN1RPT"
ATTACKER, C2_DOWNLOAD = "194.61.24.102", "http://194.61.24.102/"

pytestmark = [pytest.mark.cfreds,
              pytest.mark.skipif(not os.path.exists(os.path.join(CASE, "case.json")),
                                 reason="processed Szechuan case not found (set WFA_SZECHUAN_CASE)")]


@pytest.fixture(scope="module")
def db():
    from winforensics.core.case import Case

    c = Case.open(CASE)
    yield c.db
    c.close()


@pytest.fixture(scope="module")
def ev(db):
    return {e["label"]: e["id"] for e in db.evidence()}


def arts(db, typ, eid=None):
    sql = "SELECT ts, user, evidence_id, data_json FROM artifacts WHERE type=?" + (" AND evidence_id=?" if eid else "")
    return [dict(json.loads(r["data_json"] or "{}"), _ts=r["ts"], _user=r["user"], _ev=r["evidence_id"])
            for r in db.query(sql, (typ, eid) if eid else (typ,))]


def official(hms: str) -> datetime:
    """Official answer time on 19 Sep 2020 (UTC per the packet capture) on the systems' clock."""
    return datetime.fromisoformat(f"2020-09-19 {hms}") + CLOCK


def at(ts, hms, seconds=2):
    return ts is not None and abs((datetime.fromisoformat(str(ts)[:26]) - official(hms)).total_seconds()) <= seconds


def rows_of(db, title_like, eid=None):
    out = []
    sql = "SELECT figures_json FROM findings WHERE title LIKE ?" + (" AND evidence_id=?" if eid else "")
    for f in db.query(sql, (title_like, eid) if eid else (title_like,)):
        for fig in json.loads(f["figures_json"] or "[]"):
            out += [[str(c) for c in r] for r in (fig.get("spec") or fig).get("rows", [])]
    return out


# --------------------------------------------------------------------------- systems (Q1 - Q3, Q9)
def test_q1_q2_operating_systems(db, ev):
    os_ = {a["_ev"]: a["value"] for a in arts(db, "sys_info") if a["property"] == "Operating system"}
    assert os_[ev[DC]].startswith("Windows Server 2012 R2")
    assert os_[ev[DESKTOP]].startswith("Windows 10")


def test_q3_registry_time_zone(db, ev):
    # the answers note the server's registry says Pacific Standard Time (the lab ran in Mountain time)
    tz = {a["_ev"]: a["value"] for a in arts(db, "sys_info") if a["property"] == "Time zone"}
    assert tz[ev[DC]] == "Pacific Standard Time" and tz[ev[DESKTOP]] == "Pacific Standard Time"


def test_q9_network_layout(db, ev):
    ips = {(a["_ev"], a.get("ip_address")) for a in arts(db, "network_interface")}
    assert (ev[DC], "10.42.85.10") in ips and (ev[DESKTOP], "10.42.85.115") in ips


def test_systems_agree_on_time(db, ev):
    """DC's outgoing RDP multi-transport event and the desktop's incoming 1149 for the same connection."""
    out = [a for a in arts(db, "evt_rdp", ev[DC]) if a["event_id"] == 1102 and a.get("source_ip") == "10.42.85.115"]
    inc = [a for a in arts(db, "evt_rdp", ev[DESKTOP]) if a["event_id"] == 1149 and a.get("source_ip") == "10.42.85.10"]
    assert out and inc
    gap = min(abs((datetime.fromisoformat(o["_ts"][:26]) - datetime.fromisoformat(i["_ts"][:26])).total_seconds())
              for o in out for i in inc)
    assert gap < 2


# --------------------------------------------------------------------------- initial access (Q5)
def test_q5_rdp_brute_force(db, ev):
    fails = sorted(a["_ts"] for a in arts(db, "evt_logon", ev[DC]) if a["event_id"] == 4625 and a.get("workstation") == "kali")
    assert len(fails) >= 90 and at(fails[0], "02:21:25") and at(fails[-1], "02:21:46")
    ans = db.answers()["acct.bruteforce"]
    assert ans["status"] == "Yes" and ATTACKER in ans["summary"]


def test_q5_attacker_rdp_logon(db, ev):
    ok = sorted(a["_ts"] for a in arts(db, "evt_logon", ev[DC]) if a["event_id"] == 4624 and a.get("source_ip") == ATTACKER
                and a.get("target_user") == "Administrator" and a.get("logon_type", "").startswith("10"))
    assert ok and at(ok[0], "02:21:48")


# --------------------------------------------------------------------------- malware (Q6)
def test_q6b_payload_downloaded_with_internet_explorer(db, ev):
    for name, hms in ((DC, "02:24:12"), (DESKTOP, "02:40:01")):
        dl = [a for a in arts(db, "web_download", ev[name]) if a.get("url") == C2_DOWNLOAD]
        assert dl and dl[0]["target_path"].lower().endswith("\\downloads\\coreupdater.exe") and at(dl[0]["_ts"], hms), name


def test_q6d_q6f_payload_moved_to_system32(db, ev):
    for name in (DC, DESKTOP):
        assert db.query("SELECT 1 FROM fs_entries WHERE evidence_id=? AND lower(path)=? AND deleted=0",
                        (ev[name], "\\windows\\system32\\coreupdater.exe")), name


def test_q6i_persistence_service_and_registry(db, ev):
    for name, svc_time in ((DC, "02:27:49"), (DESKTOP, "02:42:42")):
        svc = [a for a in arts(db, "evt_service", ev[name]) if a["event_id"] == 7045 and a.get("service_name") == "coreupdater"]
        assert svc and svc[0]["image_path"].lower() == "c:\\windows\\system32\\coreupdater.exe" and at(svc[0]["_ts"], svc_time), name
        run = [a for a in arts(db, "autorun", ev[name]) if a.get("name") == "coreupdate"]
        assert run and "-w hidden" in run[0]["command"] and "FromBase64String" in run[0]["command"], name
        rows = rows_of(db, "Persistence mechanisms of interest%", ev[name])
        assert any("coreupdater" in r[2] and "downloaded from the internet" in r[4] for r in rows), name
        assert any(r[2] == "coreupdate" for r in rows), name


def test_q6_malicious_powershell_reported(db, ev):
    for name in (DC, DESKTOP):
        rows = rows_of(db, "Suspicious commands and scripts%", ev[name])
        assert any("powershell -nop -w hidden" in r[2] for r in rows), name


def test_q7_attacker_address_reported(db, ev):
    rows = rows_of(db, "Programs of interest%", ev[DC])
    assert any("coreupdater.exe" in r[2] and ATTACKER in r[3] for r in rows)


# --------------------------------------------------------------------------- lateral movement (Q8)
def test_q8_lateral_movement_dc_to_desktop(db, ev):
    rows = rows_of(db, "Lateral movement between the examined systems")
    hit = [r for r in rows if r[1] == DC and r[2] == DESKTOP and r[3].lower().endswith("administrator")]
    assert hit and at(hit[0][0], "02:35:55", seconds=60)  # official 02:35:55 from the capture


# --------------------------------------------------------------------------- data theft (Q8d, Q11, Q12)
def test_q8d_secret_zip_created_and_deleted_on_dc(db, ev):
    u = db.query("SELECT ts, reason FROM usn WHERE evidence_id=? AND lower(path)=? ORDER BY usn",
                 (ev[DC], "c:\\fileshare\\secret.zip"))
    created = [r["ts"] for r in u if "FileCreate" in r["reason"]]
    deleted = [r["ts"] for r in u if "FileDelete" in r["reason"]]
    assert created and deleted and created[0] < deleted[-1]
    assert at(created[0], "02:30:00", seconds=300) and at(deleted[-1], "02:31:00", seconds=300)  # answers: ~02:30 / ~02:31


def test_q8d_loot_zip_created_and_deleted_on_desktop(db, ev):
    u = db.query("SELECT ts, reason FROM usn WHERE evidence_id=? AND lower(name)='loot.zip' ORDER BY usn", (ev[DESKTOP],))
    assert u and any("FileDelete" in r["reason"] for r in u)
    assert at(u[0]["ts"], "02:46:00", seconds=120) and at(u[-1]["ts"], "02:48:00", seconds=120)  # answers: ~02:46 / ~02:48


def test_q11_szechuan_sauce_opened(db, ev):
    lnk = [a for a in arts(db, "lnk", ev[DC]) if a.get("target_path") == "C:\\FileShare\\Secret\\Szechuan Sauce.txt"]
    assert lnk and at(lnk[0]["_ts"], "02:32:21")


# --------------------------------------------------------------------------- timestomping (advanced Q8)
def test_beth_secret_timestomped(db, ev):
    from winforensics.modules.filesystem import TIMESTOMP_STRONG

    an = [a for a in arts(db, "timestamp_anomaly", ev[DC]) if a["file"] == "C:\\FileShare\\Secret\\Beth_Secret.txt"]
    assert an and an[0]["anomaly"] == TIMESTOMP_STRONG
    assert at(an[0]["fn_created"], "02:34:56", seconds=1)  # created 02:34 per the answers; $SI set back to 18 Sep
    rows = rows_of(db, "Anti-forensic activity indicators%", ev[DC])
    assert any("Beth_Secret.txt" in r[2] and r[3] == "strong" for r in rows)


# --------------------------------------------------------------------------- accounts (advanced Q4, Q5)
def test_interactive_users(db, ev):
    def users(eid):
        return {a["target_user"].lower() for a in arts(db, "evt_logon", eid) if a["event_id"] == 4624 and
                (a.get("logon_type") or "").split(" ")[0] in ("2", "10", "11")}
    assert "administrator" in users(ev[DC])
    assert {"administrator", "ricksanchez"} <= users(ev[DESKTOP])


# --------------------------------------------------------------------------- no false conclusions
def test_no_false_threat_answers(db):
    ans = db.answers()
    for q in ("clickfix.command", "ransom.encryption", "phish.executed", "phish.credentials"):
        assert ans[q]["status"] == "No evidence found", (q, ans[q]["summary"])


def test_no_virtual_hardware_or_builtin_tools_reported(db):
    devs = arts(db, "usb_device")
    assert devs and all("vmware" not in f"{d.get('vendor')} {d.get('product')}".lower() for d in devs)
    assert {d["serial"] for d in devs} == {"4C530000261130109435"}  # the responder's "Incident_drive" only
    assert not [t for t in arts(db, "rmm_tool") if t["tool"] == "Quick Assist"]
