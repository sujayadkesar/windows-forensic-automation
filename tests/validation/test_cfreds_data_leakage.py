"""Validation against the NIST CFReDS "Data Leakage Case" answer key.

The public image (cfreds_2015_data_leakage_pc) and NIST's answers (leakage-answers.pdf, 2018-07-23) are available at
https://cfreds-archive.nist.gov/data_leakage_case/.  Process the PC image with the dlp_exfiltration profile, then:

    set WFA_CFREDS_CASE=C:\\Cases\\CFReDS-DataLeakage
    python -m pytest tests/validation -v

Every expected value below is quoted from the answer key (question number in the test name / comment).  NIST mixes
time zones (some tables use UTC-4 EDT, the account table uses UTC-5); all values here are converted to UTC.
"""

import json
import os
from datetime import datetime

import pytest

CASE = os.environ.get("WFA_CFREDS_CASE", os.path.join(os.path.expanduser("~"), "Documents", "Forensic Cases",
                                                       "CFReDS-DataLeakage"))

pytestmark = [pytest.mark.cfreds,
              pytest.mark.skipif(not os.path.exists(os.path.join(CASE, "case.json")),
                                 reason="processed CFReDS data leakage case not found (set WFA_CFREDS_CASE)")]


@pytest.fixture(scope="module")
def db():
    from winforensics.core.case import Case

    c = Case.open(CASE)
    yield c.db
    c.close()


def arts(db, typ):
    return [dict(json.loads(r["data_json"] or "{}"), _ts=r["ts"], _user=r["user"])
            for r in db.query("SELECT ts, user, data_json FROM artifacts WHERE type=?", (typ,))]


def near(a, b, seconds=2):
    if not a or not b:
        return False
    fa = datetime.fromisoformat(str(a)[:26])
    fb = datetime.fromisoformat(str(b)[:26])
    return abs((fa - fb).total_seconds()) <= seconds


# --------------------------------------------------------------------------- system (Q3 - Q9)
def test_q3_q5_os_and_computer_name(db):
    props = {a["property"]: a["value"] for a in arts(db, "sys_info")}
    assert props.get("Computer name") == "INFORMANT-PC"
    assert "Windows 7 Ultimate" in props.get("Operating system", "")
    assert props.get("Build", "").startswith("7601")


def test_q4_time_zone(db):
    props = {a["property"]: a["value"] for a in arts(db, "sys_info")}
    assert "Eastern" in " ".join(str(v) for k, v in props.items() if "zone" in k.lower())


def test_q6_q7_accounts_and_logon_counts(db):
    acc = {a["name"].lower(): a for a in arts(db, "user_account")}
    # NIST: informant 10, admin11 2, ITechTeam 0, temporary 1
    assert acc["informant"]["logon_count"] == 10
    assert acc["admin11"]["logon_count"] == 2
    assert acc["itechteam"]["logon_count"] == 0
    assert acc["temporary"]["logon_count"] == 1
    # last logon of informant: 2015-03-25 09:45:59 (UTC-5 in the NIST table)
    assert near(acc["informant"]["last_logon"], "2015-03-25 14:45:59")


def test_q9_network_interface(db):
    ips = {a.get("ip_address") for a in arts(db, "network_interface")}
    assert "10.11.11.129" in ips


# --------------------------------------------------------------------------- applications, browsing (Q10, Q16, Q17)
def test_q10_installed_applications(db):
    names = " | ".join(a.get("name", "") for a in arts(db, "installed_program")).lower()
    for app in ("microsoft office professional plus 2013", "google chrome", "google drive", "eraser", "bonjour"):
        assert app in names, app


def test_q16_web_search_keywords(db):
    terms = {(a.get("term") or "").lower() for a in arts(db, "web_search")}
    for kw in ("data leakage methods", "leaking confidential information", "information leakage cases",
               "intellectual property theft", "how to leak a secret", "cloud storage", "digital forensics",
               "how to delete data", "anti-forensics", "how to recover data", "data recovery tools",
               "security checkpoint cd-r"):
        assert kw in terms, kw


def test_q17_explorer_search_keyword(db):
    hits = [a for a in arts(db, "search_term") if (a.get("term") or "").lower() == "secret"]
    assert hits and near(hits[0]["key_last_written"], "2015-03-23 18:40:17")  # NIST: 14:40:17 EDT


# --------------------------------------------------------------------------- USB devices (Q22)
def test_q22_usb_devices(db):
    dev = {a["serial"]: a for a in arts(db, "usb_device")}
    rm1, rm2 = dev["4C530012450531101593"], dev["4C530012550531106501"]
    # first connected (setupapi.dev.log): RM#1 2015-03-23 14:31:10 EDT, RM#2 2015-03-24 09:58:32 EDT
    assert near(rm1["first_seen"], "2015-03-23 18:31:10")
    assert near(rm2["first_seen"], "2015-03-24 13:58:32")
    # 'connected time after reboot': RM#1 2015-03-24 09:38:00, RM#2 09:58:33 EDT
    assert near(rm1["connected_after_boot"], "2015-03-24 13:38:00")
    assert near(rm2["connected_after_boot"], "2015-03-24 13:58:33")
    # Windows 7 has no last-arrival property: the tool must not claim a 'last connected' time from DeviceClasses
    assert not rm1.get("last_connected") and not rm2.get("last_connected")
    # RM#2 volume name 'IAMAN $_@' (VolumeInfoCache\E:)
    assert "IAMAN $_@" in (rm2.get("volume_label") or "")
    assert len([d for d in dev.values()]) == 2, "only the two SanDisk sticks are removable storage"


# --------------------------------------------------------------------------- network drive (Q24, Q27, Q28)
def test_q24_network_drive_address(db):
    runmru = [a for a in arts(db, "run_mru") if a.get("command") == "\\\\10.11.11.128\\secured_drive"]
    assert runmru and near(runmru[0]["key_last_written"], "2015-03-23 20:23:28")
    mapped = [a for a in arts(db, "network_drive_mru") if "10.11.11.128\\secured_drive" in (a.get("path") or "")]
    assert mapped and near(mapped[0]["key_last_written"], "2015-03-23 20:26:04")


def test_q28_files_opened_on_network_drive(db):
    targets = {(a.get("target_path") or "").lower() for a in arts(db, "lnk") + arts(db, "jumplist")}
    assert ("\\\\10.11.11.128\\secured_drive\\secret project data\\pricing decision\\(secret_project)_pricing_decision.xlsx"
            in targets)
    assert "v:\\secret project data\\final\\[secret_project]_final_meeting.pptx" in targets
    assert not any(t.startswith("1\\") for t in targets), "device name used without the ValidDevice flag"


# --------------------------------------------------------------------------- removable media traversal (Q25, Q26)
def test_q25_directories_traversed_on_rm2(db):
    bags = {(a.get("path") or "").lower() for a in arts(db, "shellbag")}
    for d in ("e:\\secret project data\\technical review", "e:\\secret project data\\proposal",
              "e:\\secret project data\\progress", "e:\\secret project data\\pricing decision", "e:\\secret project data\\design"):
        assert d in bags, d


def test_q26_file_opened_on_rm2(db):
    targets = " | ".join((a.get("target_path") or "").lower() for a in arts(db, "lnk") + arts(db, "jumplist"))
    assert "e:\\secret project data\\design\\winter_whether_advisory.zip" in targets


# --------------------------------------------------------------------------- Google Drive (Q29 - Q31)
def test_q31_google_drive_account(db):
    accts = {(a.get("account") or "").lower() for a in arts(db, "cloud_account")}
    assert "iaman.informant.personal@gmail.com" in accts


def test_q30_files_deleted_from_google_drive(db):
    items = arts(db, "cloud_item")
    dele = {a["name"] for a in items if "deleted from google drive" in (a.get("event") or "").lower()}
    assert {"happy_holiday.jpg", "do_u_wanna_build_a_snow_man.mp3"} <= dele
    ups = {a["name"] for a in items if a.get("event") == "uploaded to Google Drive"}
    assert {"happy_holiday.jpg", "do_u_wanna_build_a_snow_man.mp3"} <= ups
    # NIST: deleted 2015-03-23 16:42:17 EDT (local delete); sync completed within seconds
    for a in items:
        if "deleted from google drive" in (a.get("event") or "").lower() and a["name"] == "happy_holiday.jpg":
            assert near(a["_ts"], "2015-03-23 20:42:17", 10)


# --------------------------------------------------------------------------- CD burning (Q32 - Q35)
def test_q33_burn_times_from_system_log(db):
    times = sorted(a["_ts"] for a in arts(db, "evt_optical"))
    for t in ("2015-03-24 19:47:47", "2015-03-24 19:56:11", "2015-03-24 20:24:46", "2015-03-24 20:41:21"):
        assert any(near(x, t) for x in times), t


def test_q33_burn_method_registry(db):
    mode = [a for a in arts(db, "burn_registry") if a.get("item") == "DefaultToMastered"]
    assert mode and str(mode[0]["value"]).startswith("0")  # last selection: type 1 (like a USB flash drive)
    assert near(mode[0]["key_last_written"], "2015-03-24 20:53:16")


def test_q34_files_copied_to_cd(db):
    staged = {(a.get("path") or "").lower() for a in arts(db, "burn_staging")}
    base = "c:\\users\\informant\\appdata\\local\\microsoft\\windows\\burn\\burn\\"
    for f in ("de\\winter_storm.amr", "de\\winter_whether_advisory.zip", "pd\\my_favorite_cars.db", "pd\\new_years_day.jpg",
              "prog\\my_friends.svg", "prop\\landscape.png", "tr\\diary_#1d.txt", "tr\\diary_#3p.txt", "penguins.jpg",
              "koala.jpg", "tulips.jpg"):
        assert base + f in staged, f


def test_q35_files_opened_from_cd(db):
    targets = {(a.get("target_path") or "").lower() for a in arts(db, "lnk") + arts(db, "jumplist")
               if a.get("drive_type") == "DRIVE_CDROM"}
    for t in ("d:\\de\\winter_whether_advisory.zip", "d:\\penguins.jpg", "d:\\koala.jpg", "d:\\tulips.jpg"):
        assert t in targets, t


# --------------------------------------------------------------------------- e-mail (Q21, Q45)
def test_q21_q45_emails_including_deleted(db):
    idx = arts(db, "search_index_item")
    paths = {(a.get("path") or "") for a in idx}
    assert "/iaman.informant@nist.gov/Sent Items/RE: Good job, buddy. : space_and_earth.mp4" in paths  # attachment
    sent = {a.get("subject"): a.get("sent") for a in idx if a.get("sent")}
    assert near(sent.get("It's me"), "2015-03-23 20:38:47")      # NIST 16:38 EDT
    assert near(sent.get("Done"), "2015-03-24 21:05:09")         # NIST 17:05 EDT
    assert any(s == "Hello, Iaman" for s in sent)


# --------------------------------------------------------------------------- file system accuracy (Q23, Q36, Q37, Q52)
def test_usn_paths_follow_sequence_numbers(db):
    """Parent folders whose MFT records were reused must not be resolved to the record's new owner."""
    paths = {r["path"].lower() for r in db.query("SELECT path FROM usn WHERE name='winter_storm.amr'")}
    assert "c:\\users\\informant\\appdata\\local\\microsoft\\windows\\burn\\burn\\de\\winter_storm.amr" in paths
    assert not any("\\chrome\\user data\\default\\cache\\" in p for p in paths)
    peng = {r["path"].lower() for r in db.query("SELECT path FROM usn WHERE name='Penguins.jpg' AND reason LIKE 'FileCreate%'")}
    assert "c:\\users\\informant\\desktop\\temp\\penguins.jpg" in peng  # folder name at that time (later wiped by Eraser)


def test_q36_resignation_letter_timestamps(db):
    r = db.query("SELECT * FROM fs_entries WHERE lower(name)=lower(?) AND deleted=0",
                 ("Resignation_Letter_(Iaman_Informant).docx",))
    assert r, "resignation letter not indexed"
    assert near(r[0]["si_created"], "2015-03-24 18:48:40")   # NIST 14:48:40 EDT
    assert near(r[0]["si_modified"], "2015-03-24 18:59:30")


def test_q37_printed_to_xps(db):
    assert db.query("SELECT 1 FROM fs_entries WHERE lower(name)=lower(?)", ("Resignation_Letter_(Iaman_Informant).xps",))


def test_q52_eraser_wipe_of_desktop_temp(db):
    f = [x for x in db.findings() if x["category"] == "Anti-forensics"]
    assert f
    rows = json.dumps(f[0].get("figures") or f[0].get("figures_json") or "")
    assert "Desktop\\\\temp" in rows or "Desktop\\temp" in rows
    assert "Secure deletion pattern" in rows
