"""Regression tests for accuracy-critical logic (each case reproduces a real-world pitfall)."""

from winforensics.analyzers.anti_forensics import _rename_burst
from winforensics.analyzers.scenarios import KNOWN_EXT, SYSTEM_DIRS
from winforensics.analyzers.triage import BROWSER_CACHE, INSTALLER_TEMP, RARE_LOLBINS
from winforensics.modules.filesystem import _resolve_paths, _UsnPathResolver


# --------------------------------------------------------------------------- MFT / USN path resolution
def test_reused_parent_record_is_not_followed():
    # record 100 was 'S data' (seq 3); it was deleted and reused as 'Cache' (seq 5). File 200 still references (100, 3).
    names = {5: (5, 5, ".", True), 50: (5, 5, "Users", True), 100: (50, 1, "Cache", True), 200: (100, 3, "secret.docx", False)}
    seqs = {5: 5, 50: 1, 100: 5, 200: 7}
    inuse = {5: True, 50: True, 100: True, 200: False}
    paths = _resolve_paths(names, seqs, inuse)
    assert paths[100] == "\\Users\\Cache"
    assert "Cache" not in paths[200] and paths[200].startswith("\\<unknown folder: MFT record 100, sequence 3>")


def test_deleted_parent_not_reused_is_followed():
    # deletion increments the sequence by one; the record is free (not in use) -> same folder
    names = {5: (5, 5, ".", True), 100: (5, 5, "Project", True), 200: (100, 3, "plan.docx", False)}
    paths = _resolve_paths(names, {5: 5, 100: 4, 200: 9}, {5: True, 100: False, 200: False})
    assert paths[200] == "\\Project\\plan.docx"


def test_usn_uses_folder_name_at_that_time():
    # folder (100, 9) was 'temp' when the file was created (usn 10) and renamed to '[QAT' before deletion (usn 50)
    dirs = {(100, 9): [(5, "temp", 60, 2), (40, "[QAT", 60, 2)]}
    paths = {5: "", 60: "\\Users\\informant\\Desktop"}
    r = _UsnPathResolver(paths, dirs, {5: 5, 60: 2, 100: 10}, {5: True, 60: True, 100: False})
    assert r.dir_path(100, 9, 10) == "\\Users\\informant\\Desktop\\temp"
    assert r.dir_path(100, 9, 60) == "\\Users\\informant\\Desktop\\[QAT"


# --------------------------------------------------------------------------- wiper detection
def _h(ts, name, reason, path=None):
    return {"ts": f"2015-03-25 15:13:{ts}", "name": name, "reason": reason, "path": path or f"C:\\Users\\u\\Desktop\\{name}"}


def test_eraser_rename_burst_detected():
    hist = [_h("10.000000", "New folder", "FileCreate"), _h("12.000000", "New folder", "RenameOldName"),
            _h("12.000000", "temp", "RenameNewName")]
    names = ["t6uk", "2FDM", "hA_t", "KR15", "f2hz", "enV7", "[QAT"]
    prev = "temp"
    for n in names:
        hist += [_h("49.637403", prev, "RenameOldName"), _h("49.637403", n, "RenameNewName")]
        prev = n
    hist.append(_h("49.699804", "[QAT", "FileDelete|Close"))
    b = _rename_burst(hist)
    assert b is not None
    assert b[0].endswith("\\temp") and len(b[1]) == 7


def test_office_save_is_not_a_wipe():
    # Office save: original renamed to a temp name and back - at most two renames, no burst
    hist = [_h("10.000000", "report.docx", "RenameOldName"), _h("10.000000", "~WRL0001.tmp", "RenameNewName"),
            _h("11.000000", "~WRL0001.tmp", "FileDelete|Close")]
    assert _rename_burst(hist) is None


def test_ese_log_rotation_is_not_a_wipe():
    hist = []
    for i in range(5):
        hist += [_h(f"1{i}.000000", "edbtmp.log", "RenameOldName"), _h(f"1{i}.000000", f"edb0000{i}.log", "RenameNewName")]
    hist.append(_h("19.000000", "edb00004.log", "FileDelete|Close"))
    assert _rename_burst(hist) is None


# --------------------------------------------------------------------------- noise filters keep true positives
def test_browser_cache_scripts_excluded_but_user_scripts_kept():
    assert BROWSER_CACHE.search(r"C:\Users\a\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\X\x.js")
    assert BROWSER_CACHE.search(r"C:\Users\a\AppData\Local\Microsoft\Windows\INetCache\IE\X\x.js")
    assert not BROWSER_CACHE.search(r"C:\Users\a\Downloads\invoice.js")
    assert not BROWSER_CACHE.search(r"C:\Users\a\AppData\Roaming\update.ps1")


def test_installer_temp_excluded_but_payloads_kept():
    assert INSTALLER_TEMP.search(r"C:\Users\a\AppData\Local\Temp\IXP001.TMP\setup.exe")
    assert not INSTALLER_TEMP.search(r"C:\Users\a\AppData\Local\Temp\svchost.exe")
    assert not INSTALLER_TEMP.search(r"C:\Users\a\AppData\Local\Temp\7zS1234\payload.exe")
    assert {"mshta.exe", "certutil.exe", "wevtutil.exe", "psexec.exe"} <= RARE_LOLBINS
    assert not {"msiexec.exe", "net.exe", "regsvr32.exe"} & RARE_LOLBINS


def test_ransomware_extension_filters():
    assert SYSTEM_DIRS.search(r"c:\windows\winsxs\amd64_x\a.dll")
    assert SYSTEM_DIRS.search(r"c:\program files (x86)\app\a.dat")
    assert not SYSTEM_DIRS.search(r"c:\users\bob\documents\q3.xlsx.lockbit")
    assert KNOWN_EXT.fullmatch("mum") and KNOWN_EXT.fullmatch("rbf")
    assert not KNOWN_EXT.fullmatch("lockbit") and not KNOWN_EXT.fullmatch("akira")


# --------------------------------------------------------------------------- Google Drive legacy log
def test_google_drive_batched_changes_all_reported():
    from winforensics.modules.cloud import CloudModule

    line = ("2015-03-23 16:32:45,415 -0400 INFO pid=2576 608:Worker-2        common.workers:199 Worker successfully completed "
            "[ImmutableChange(Direction.UPLOAD, Action.CREATE, ino=1, path=u'\\\\\\\\?\\\\C:\\\\Users\\\\u\\\\Google Drive', "
            "name=u'a.jpg', parent_ino=2), ImmutableChange(Direction.UPLOAD, Action.CREATE, ino=3, path=u'\\\\\\\\?\\\\C:\\\\Users"
            "\\\\u\\\\Google Drive', name=u'b.mp3', parent_ino=2)]")
    out = []

    class Ctx:
        def emit(self, typ, ts, d, **k):
            out.append((str(ts), d["event"], d["name"]))

    CloudModule()._gdrive_log(Ctx(), line, "x@example.com", "u", "sync_log.log")
    assert [o[2] for o in out] == ["a.jpg", "b.mp3"]
    assert all(o[1] == "uploaded to Google Drive" for o in out)
    assert out[0][0].startswith("2015-03-23 16:32:45.415000-04:00")
