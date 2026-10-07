"""Synthetic removable-media test scenario (all values are placeholders).

Machines:
  * WKSTN-TEST-01  - "source" workstation (NTFS, GPT) used with a test USB stick
  * HOME-TEST-02   - second workstation where the same stick is later attached
  * USB-TEST       - FAT32 image of the stick itself

Every document contains the marker ``VESTIGE-TEST-MARKER-001`` so keyword search
across allocated, unallocated, slack and pagefile areas can be verified.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import struct

from . import artifacts as A
from .evtxwriter import Event, utc
from .lnkwriter import DRIVE_FIXED, DRIVE_REMOVABLE, build_lnk
from .machine import Machine, plus
from .prefetchwriter import build_prefetch
from .shellitems import root_folder, volume

MARKER = "VESTIGE-TEST-MARKER-001"
USB = dict(vendor="Generic", product="Flash_Disk", rev="8.07", serial="TESTSN000000000001",
           vid="058F", pid="6387", friendly="Generic Flash Disk", label="TESTUSB", vsn=0x1A2B3C4D,
           volume_guid="{11111111-2222-3333-4444-555555555555}")
SID_A = "S-1-5-21-1111111111-2222222222-3333333333-1001"
SID_B = "S-1-5-21-4444444444-5555555555-6666666666-1001"
DOCS = ["test_doc_alpha.docx", "test_sheet_beta.xlsx", "test_report_gamma.pdf", "test_list_delta.csv"]


def fat32_vbr(vsn: int, label: str) -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xeb\x58\x90"
    b[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHB", b, 11, 512, 8, 32, 2)
    b[66] = 0x29
    struct.pack_into("<I", b, 67, vsn)
    b[71:82] = label.ljust(11).encode()[:11]
    b[82:90] = b"FAT32   "
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def make_documents(out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    A.make_docx(os.path.join(out_dir, DOCS[0]), "Test Document Alpha",
                [f"Reference: {MARKER}", "Lorem ipsum placeholder paragraph."], author="testuser")
    A.make_xlsx(os.path.join(out_dir, DOCS[1]), [["Item", "Value"], ["marker", MARKER], ["a", 1], ["b", 2]],
                author="testuser")
    A.make_pdf(os.path.join(out_dir, DOCS[2]), ["Test Report Gamma", f"Reference: {MARKER}", "Placeholder text."])
    with open(os.path.join(out_dir, DOCS[3]), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "label", "ref"])
        for i in range(40):
            w.writerow([i, f"row-{i}", MARKER])
    hashes = {}
    for d in DOCS:
        with open(os.path.join(out_dir, d), "rb") as fh:
            data = fh.read()
        hashes[d] = {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
                     "size": len(data)}
    return hashes


def _tz(m: Machine, key_name: str, bias: int, daylight_bias: int = 0, active: int | None = None):
    k = r"ControlSet001\Control\TimeZoneInformation"
    m.system.sz(k, "TimeZoneKeyName", key_name)
    m.system.dword(k, "Bias", bias)
    m.system.dword(k, "ActiveTimeBias", bias if active is None else active)
    m.system.dword(k, "DaylightBias", daylight_bias)
    m.system.sz(k, "StandardName", key_name)


def _base(m: Machine, computer: str, product: str, build: str, display: str):
    m.system.dword("Select", "Current", 1)
    m.system.sz(r"ControlSet001\Control\ComputerName\ComputerName", "ComputerName", computer)
    m.system.binary(r"ControlSet001\Control\Windows", "ShutdownTime", A.filetime_bytes(plus(m.install_time, days=40)))
    cv = r"Microsoft\Windows NT\CurrentVersion"
    m.software.sz(cv, "ProductName", product)
    m.software.sz(cv, "CurrentBuild", build)
    m.software.sz(cv, "CurrentBuildNumber", build)
    m.software.sz(cv, "DisplayVersion", display)
    m.software.sz(cv, "EditionID", "Professional")
    m.software.sz(cv, "RegisteredOwner", "test")
    m.software.dword(cv, "InstallDate", int(m.install_time.timestamp()))
    m.software.dword(cv, "CurrentMajorVersionNumber", 10)
    m.software.dword(cv, "CurrentMinorVersionNumber", 0)
    m.software.sz(cv, "SystemRoot", "C:\\Windows")
    for name, ver in [("Google Chrome", "128.0.6613.120"), ("7-Zip 24.08 (x64)", "24.08")]:
        k = rf"Microsoft\Windows\CurrentVersion\Uninstall\{name}"
        m.software.sz(k, "DisplayName", name)
        m.software.sz(k, "DisplayVersion", ver)
        m.software.sz(k, "InstallDate", m.install_time.strftime("%Y%m%d"))
    for d in ["C:\\Windows\\System32\\drivers\\etc", "C:\\Program Files", "C:\\ProgramData", "C:\\Windows\\Prefetch",
              "C:\\Windows\\INF"]:
        os.makedirs(m.path(d), exist_ok=True)
    m.add_file("C:\\Windows\\System32\\drivers\\etc\\hosts", "# hosts\r\n127.0.0.1 localhost\r\n")


def _usb_events(m: Machine, computer: str, connect, disconnect, disk_no=1):
    inst = f"USBSTOR\\Disk&Ven_{USB['vendor']}&Prod_{USB['product']}&Rev_{USB['rev']}\\{USB['serial']}&0"
    common = dict(provider="Microsoft-Windows-Partition", channel="Microsoft-Windows-Partition/Diagnostic",
                  computer=computer, provider_guid="412bdff2-a8c4-470d-8f33-63fe0d8c20e2", version=8,
                  user_sid="S-1-5-18")
    for t, cap, vbr in [(connect, 8019509248, fat32_vbr(USB["vsn"], USB["label"])), (disconnect, 0, b"")]:
        m.event("Microsoft-Windows-Partition%4Diagnostic.evtx", Event(
            event_id=1006, time=t, data={
                "DiskNumber": str(disk_no), "Characteristics": "0", "IsSystem": "false", "IsBoot": "false",
                "BusType": "7", "Manufacturer": USB["vendor"], "Model": USB["friendly"].split(" ", 1)[1],
                "Revision": USB["rev"], "SerialNumber": USB["serial"], "ParentId": f"USB\\VID_{USB['vid']}&PID_{USB['pid']}\\{USB['serial']}",
                "Capacity": str(cap), "PartitionStyle": "0", "PartitionCount": "1" if cap else "0",
                "Vbr0Bytes": str(len(vbr)), "Vbr0": vbr}, **common))
    for eid in (400, 410):
        m.event("Microsoft-Windows-Kernel-PnP%4Configuration.evtx", Event(
            provider="Microsoft-Windows-Kernel-PnP", event_id=eid, channel="Microsoft-Windows-Kernel-PnP/Configuration",
            computer=computer, time=plus(connect, seconds=1), user_sid="S-1-5-18",
            data={"DeviceInstanceId": inst, "DriverName": "disk.inf", "ClassGuid": "{4d36e967-e325-11ce-bfc1-08002be10318}",
                  "DriverDate": "6/21/2006", "DriverVersion": "10.0.19041.3636", "DriverProvider": "Microsoft",
                  "DriverInbox": "true", "DriverSection": "disk_install.NT", "DriverRank": "0xff0006",
                  "MatchingDeviceId": "GenDisk", "OutrankedDrivers": "", "DeviceUpdated": "false", "Status": "0x0",
                  "ParentDeviceInstanceId": f"USB\\VID_{USB['vid']}&PID_{USB['pid']}\\{USB['serial']}"}))


def _logon(m: Machine, computer: str, user: str, sid: str, t, logon_type=2, ip="-"):
    m.event("Security.evtx", Event(
        provider="Microsoft-Windows-Security-Auditing", event_id=4624, channel="Security", computer=computer, time=t,
        provider_guid="54849625-5478-4994-a5ba-3e3b0328c30d", version=2, task=12544, keywords=0x8020000000000000,
        data={"SubjectUserSid": "S-1-5-18", "SubjectUserName": computer + "$", "TargetUserSid": sid,
              "TargetUserName": user, "TargetDomainName": computer, "TargetLogonId": "0x3e7a1", "LogonType": str(logon_type),
              "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate", "WorkstationName": computer,
              "IpAddress": ip, "IpPort": "0", "ProcessName": "C:\\Windows\\System32\\svchost.exe"}))


def build_source(staging: str, docs_dir: str) -> Machine:
    t0 = utc(2026, 8, 3, 4, 0, 0)
    m = Machine(staging, "WKSTN-TEST-01", t0, disk={
        "size_mb": 384, "scheme": "gpt",
        "partitions": [{"type": "efi", "size_mb": 64, "fs": "fat32", "label": "SYSTEM"},
                       {"type": "basic", "fs": "ntfs", "label": "Windows", "serial": "2C8A7F1E4B6D3A90"}],
        "pagefile_mb": 8, "hiberfil_mb": 4})
    pc = "WKSTN-TEST-01"
    _base(m, pc, "Windows 10 Pro", "19045", "22H2")
    _tz(m, "India Standard Time", (-330) & 0xFFFFFFFF)
    u = m.add_user("testuser", SID_A, t0)
    prof = u["profile"]
    nt, uc = u["ntuser"], u["usrclass"]

    connect = utc(2026, 9, 14, 5, 32, 13)
    removal = utc(2026, 9, 14, 5, 52, 40)
    _logon(m, pc, "testuser", SID_A, utc(2026, 9, 14, 5, 30, 2))
    m.usb_registry(USB["vendor"], USB["product"], USB["rev"], USB["serial"], USB["vid"], USB["pid"], USB["friendly"],
                   connect, connect, removal, USB["volume_guid"], "E", USB["label"], USB["vsn"])
    _usb_events(m, pc, connect, removal)
    m.add_file("C:\\Windows\\INF\\setupapi.dev.log", (
        ">>>  [Device Install (Hardware initiated) - USB\\VID_058F&PID_6387\\TESTSN000000000001]\r\n"
        ">>>  Section start 2026/09/14 11:02:13.456\r\n<<<  Section end 2026/09/14 11:02:14.101\r\n"
        "<<<  [Exit status: SUCCESS]\r\n\r\n"
        ">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07\\TESTSN000000000001&0]\r\n"
        ">>>  Section start 2026/09/14 11:02:14.220\r\n<<<  Section end 2026/09/14 11:02:15.002\r\n"
        "<<<  [Exit status: SUCCESS]\r\n"), ctime=t0, mtime=connect)
    nt.key(rf"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{USB['volume_guid']}", ts=plus(connect, seconds=5))

    # originals
    conf = f"{prof}\\Documents\\Project"
    created = utc(2026, 9, 2, 6, 0, 0)
    for i, d in enumerate(DOCS):
        m.add_existing(f"{conf}\\{d}", os.path.join(docs_dir, d), ctime=plus(created, hours=i),
                       mtime=plus(created, hours=i, minutes=30), atime=plus(connect, minutes=3))
    m.add_file(f"{prof}\\Desktop\\notes.txt", "meeting notes placeholder\r\n" * 190, ctime=created)
    m.slack_inject(f"{prof}\\Desktop\\notes.txt", f"{MARKER} slack-fragment test_list_delta.csv".encode())
    m.delete_later(f"{conf}\\{DOCS[3]}", utc(2026, 9, 14, 6, 40, 0))

    # files opened from the removable volume (LNK + RecentDocs + Office-style MRU)
    lnk_dir = f"{prof}\\AppData\\Roaming\\Microsoft\\Windows\\Recent"
    opened = [(DOCS[1], plus(connect, minutes=8)), (DOCS[0], plus(connect, minutes=12))]
    for name, t in opened:
        size = os.path.getsize(os.path.join(docs_dir, name))
        data = build_lnk(f"E:\\Export\\{name}", ctime=plus(connect, minutes=4), mtime=plus(created, minutes=30),
                         atime=t, size=size, drive_type=DRIVE_REMOVABLE, volume_serial=USB["vsn"],
                         volume_label=USB["label"], machine_id="wkstn-test-01")
        m.add_file(f"{lnk_dir}\\{name}.lnk", data, ctime=t, mtime=t)
    data = build_lnk(f"C:\\Users\\testuser\\Documents\\Project\\{DOCS[2]}", ctime=created, mtime=created,
                     atime=utc(2026, 9, 10, 9, 0), size=os.path.getsize(os.path.join(docs_dir, DOCS[2])),
                     drive_type=DRIVE_FIXED, volume_serial=0x4B6D3A90, machine_id="wkstn-test-01")
    m.add_file(f"{lnk_dir}\\{DOCS[2]}.lnk", data, ctime=utc(2026, 9, 10, 9, 0))

    rd = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    for i, (name, t) in enumerate(opened):
        nt.binary(rd, str(i), A.recentdocs_value(name, name + ".lnk"), ts=t)
    nt.binary(rd, "MRUListEx", A.mru_list_ex(len(opened)), ts=opened[-1][1])
    times = {"mtime": created, "ctime": created, "atime": created}
    osm = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    upload_time = utc(2026, 9, 14, 6, 12, 0)
    nt.binary(osm + r"\OpenSavePidlMRU\docx", "0", A.opensave_pidl(f"C:\\Users\\testuser\\Documents\\Project\\{DOCS[0]}", times), ts=upload_time)
    nt.binary(osm + r"\OpenSavePidlMRU\docx", "MRUListEx", A.mru_list_ex(1), ts=upload_time)
    nt.binary(osm + r"\LastVisitedPidlMRU", "0", A.lastvisited_pidl("chrome.exe", "C:\\Users\\testuser\\Documents\\Project", times), ts=upload_time)
    nt.binary(osm + r"\LastVisitedPidlMRU", "MRUListEx", A.mru_list_ex(1), ts=upload_time)
    nt.sz(r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "url1", "E:\\Export", ts=plus(connect, minutes=1))
    ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    nt.binary(ua, A.rot13("{6D809377-6AF0-444B-8957-A3773F02200E}\\Google\\Chrome\\Application\\chrome.exe"),
              A.userassist_data(14, 30, 600000, utc(2026, 9, 14, 6, 5)), ts=utc(2026, 9, 14, 6, 5))
    nt.binary(ua, A.rot13("{6D809377-6AF0-444B-8957-A3773F02200E}\\7-Zip\\7zFM.exe"),
              A.userassist_data(1, 1, 20000, utc(2026, 9, 14, 6, 25)))

    # shellbags: My Computer -> E:\ -> Export ; My Computer -> C:\ -> Users -> testuser -> Documents -> Project
    bag = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
    ft = {"mtime": created, "ctime": created, "atime": created}
    from .shellitems import file_entry
    uc.binary(bag, "0", root_folder() + b"\x00\x00", ts=plus(connect, minutes=1))
    uc.binary(bag, "MRUListEx", A.mru_list_ex(1))
    uc.binary(bag + r"\0", "0", volume("C") + b"\x00\x00")
    uc.binary(bag + r"\0", "1", volume("E") + b"\x00\x00", ts=plus(connect, minutes=1))
    uc.binary(bag + r"\0", "MRUListEx", A.mru_list_ex(2))
    uc.binary(bag + r"\0\1", "0", file_entry("Export", mtime=plus(connect, minutes=2), ctime=plus(connect, minutes=2)) + b"\x00\x00",
              ts=plus(connect, minutes=3))
    uc.binary(bag + r"\0\1", "MRUListEx", A.mru_list_ex(1))
    path = bag + r"\0\0"
    for i, part in enumerate(["Users", "testuser", "Documents", "Project"]):
        uc.binary(path, "0", file_entry(part, **ft) + b"\x00\x00")
        uc.binary(path, "MRUListEx", A.mru_list_ex(1))
        path += r"\0"

    # program execution
    for exe, dev, runs, files in [
        ("CHROME.EXE", r"\VOLUME{01dc0f00a1b2c3d4-4b6d3a90}\PROGRAM FILES\GOOGLE\CHROME\APPLICATION\CHROME.EXE",
         [utc(2026, 9, 14, 6, 5)], [r"\VOLUME{01dc0f00a1b2c3d4-4b6d3a90}\WINDOWS\SYSTEM32\NTDLL.DLL"]),
        ("7ZG.EXE", r"\VOLUME{01dc0f00a1b2c3d4-4b6d3a90}\PROGRAM FILES\7-ZIP\7ZG.EXE", [utc(2026, 9, 14, 6, 25)],
         [r"\VOLUME{01dc0f00a1b2c3d4-4b6d3a90}\USERS\TESTUSER\DOCUMENTS\PROJECT\TEST_DOC_ALPHA.DOCX"]),
        ("EXCEL.EXE", r"\VOLUME{01dc0f00a1b2c3d4-4b6d3a90}\PROGRAM FILES\MICROSOFT OFFICE\ROOT\OFFICE16\EXCEL.EXE",
         [opened[0][1]], [r"\VOLUME{01dd2463a8b1c000-1a2b3c4d}\EXPORT\TEST_SHEET_BETA.XLSX"]),
    ]:
        fname, blob = build_prefetch(exe, dev, runs, len(runs), files)
        m.add_file(f"C:\\Windows\\Prefetch\\{fname}", blob, ctime=runs[0], mtime=runs[-1])
    bam = rf"ControlSet001\Services\bam\State\UserSettings\{SID_A}"
    m.system.binary(bam, r"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe",
                    A.bam_value(utc(2026, 9, 14, 6, 30)))
    m.system.binary(r"ControlSet001\Control\Session Manager\AppCompatCache", "AppCompatCache", A.shimcache_win10([
        ("C:\\Program Files\\7-Zip\\7zG.exe", utc(2026, 7, 1, 10, 0)),
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", utc(2026, 8, 28, 21, 0)),
    ]))
    ac = r"Root\InventoryApplicationFile\7zg.exe|1a2b3c4d5e6f7a8b"
    m.amcache.sz(ac, "LowerCaseLongPath", "c:\\program files\\7-zip\\7zg.exe", ts=utc(2026, 8, 5, 9, 0))
    m.amcache.sz(ac, "Name", "7zG.exe")
    m.amcache.sz(ac, "FileId", "0000" + "ab" * 20)
    m.amcache.qword(ac, "Size", 692736)
    m.amcache.sz(ac, "Publisher", "igor pavlov")

    # browser: webmail compose + upload site + search
    chrome = f"{prof}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
    visits = [
        dict(url="https://mail.google.com/mail/u/1/#inbox", title="Inbox - test.user@example.test", time=utc(2026, 9, 14, 6, 8)),
        dict(url="https://mail.google.com/mail/u/1/#inbox?compose=new", title="Inbox - test.user@example.test", time=utc(2026, 9, 14, 6, 11)),
        dict(url="https://mail.google.com/mail/u/1/#sent", title="Sent Mail - test.user@example.test", time=utc(2026, 9, 14, 6, 14)),
        dict(url="https://upload.example.test/", title="Upload files", time=utc(2026, 9, 14, 6, 28)),
        dict(url="https://www.google.com/search?q=clear+usb+history", title="clear usb history - Google Search", time=utc(2026, 9, 14, 6, 20)),
    ]
    A.chrome_history(m.path(f"{chrome}\\History"), visits,
                     searches=[{"url": visits[4]["url"], "term": "clear usb history"}])
    m._register(f"{chrome}\\History", t0, utc(2026, 9, 14, 6, 30), None)
    A.activities_cache(m.path(f"{prof}\\AppData\\Local\\ConnectedDevicesPlatform\\L.testuser\\ActivitiesCache.db"), [
        dict(app="Microsoft.Office.EXCEL.EXE.15", app_name="Excel", display=DOCS[1], uri=f"file:///E:/Export/{DOCS[1]}",
             start=opened[0][1], end=plus(opened[0][1], minutes=3)),
    ])
    m._register(f"{prof}\\AppData\\Local\\ConnectedDevicesPlatform\\L.testuser\\ActivitiesCache.db", t0, opened[0][1], None)

    # staged archive in recycle bin
    zip_path = os.path.join(m.dir, "_staged.zip")
    A.make_zip(zip_path, {d: open(os.path.join(docs_dir, d), "rb").read() for d in DOCS[:2]})
    rb = f"C:\\$Recycle.Bin\\{SID_A}"
    m.add_existing(f"{rb}\\$RAB12CD.zip", zip_path, ctime=utc(2026, 9, 14, 6, 25), mtime=utc(2026, 9, 14, 6, 25))
    m.add_file(f"{rb}\\$IAB12CD.zip", A.recycle_i_file("C:\\Users\\testuser\\AppData\\Local\\Temp\\backup.zip",
                                                       os.path.getsize(zip_path), utc(2026, 9, 14, 6, 35)),
               ctime=utc(2026, 9, 14, 6, 35))
    os.remove(zip_path)

    # memory files with marker strings
    m.manifest["pagefile"] = [
        {"offset": 1_000_000, "data_hex": MARKER.encode().hex()},
        {"offset": 3_000_000, "data_hex": A.utf16(f"E:\\Export\\{DOCS[2]}").hex()},
        {"offset": 5_000_000, "data_hex": b"https://mail.google.com/mail/u/1/?ui=2&attid=0.1&disp=safe".hex()},
    ]
    m.manifest["hiberfil"] = [{"offset": 500_000, "data_hex": A.utf16(DOCS[0]).hex()}]
    m.finalize()
    return m


def build_second(staging: str, docs_dir: str) -> Machine:
    t0 = utc(2026, 6, 1, 10, 0, 0)
    m = Machine(staging, "HOME-TEST-02", t0, disk={
        "size_mb": 256, "scheme": "mbr",
        "partitions": [{"type": "basic", "fs": "ntfs", "label": "OS", "serial": "7A1B2C3D4E5F6071"}],
        "pagefile_mb": 4})
    pc = "HOME-TEST-02"
    _base(m, pc, "Windows 11 Home", "22631", "23H2")
    _tz(m, "India Standard Time", (-330) & 0xFFFFFFFF)
    u = m.add_user("homeuser", SID_B, t0)
    prof = u["profile"]
    nt, uc = u["ntuser"], u["usrclass"]
    connect = utc(2026, 9, 14, 15, 10, 0)
    removal = utc(2026, 9, 14, 15, 30, 0)
    m.usb_registry(USB["vendor"], USB["product"], USB["rev"], USB["serial"], USB["vid"], USB["pid"], USB["friendly"],
                   connect, connect, removal, "{99999999-8888-7777-6666-555555555555}", "D", USB["label"], USB["vsn"])
    _usb_events(m, pc, connect, removal, disk_no=2)
    _logon(m, pc, "homeuser", SID_B, utc(2026, 9, 14, 15, 0))
    nt.key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{99999999-8888-7777-6666-555555555555}",
           ts=plus(connect, seconds=4))
    # copy from stick (same hash) and renamed copy
    m.add_existing(f"{prof}\\Documents\\Work\\{DOCS[1]}", os.path.join(docs_dir, DOCS[1]),
                   ctime=plus(connect, minutes=3), mtime=utc(2026, 9, 2, 7, 30))
    m.add_existing(f"{prof}\\Documents\\Work\\renamed_copy.docx", os.path.join(docs_dir, DOCS[0]),
                   ctime=plus(connect, minutes=4), mtime=utc(2026, 9, 2, 6, 30))
    data = build_lnk(f"D:\\Export\\{DOCS[2]}", ctime=plus(connect, minutes=1), mtime=utc(2026, 9, 2, 8, 30),
                     atime=plus(connect, minutes=6), size=os.path.getsize(os.path.join(docs_dir, DOCS[2])),
                     drive_type=DRIVE_REMOVABLE, volume_serial=USB["vsn"], volume_label=USB["label"],
                     machine_id="home-test-02")
    m.add_file(f"{prof}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\{DOCS[2]}.lnk", data, ctime=plus(connect, minutes=6))
    # downloaded attachment, later deleted (deleted MFT entry + unallocated content)
    dl = f"{prof}\\Downloads\\{DOCS[0]}"
    m.add_existing(dl, os.path.join(docs_dir, DOCS[0]), ctime=utc(2026, 9, 15, 3, 2))
    m.add_ads(dl, "Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://mail.google.com/\r\n"
              "HostUrl=https://mail-attachment.googleusercontent.com/attachment/u/0/?ui=2&attid=0.1\r\n")
    m.delete_later(dl, utc(2026, 9, 15, 3, 20))
    m.add_existing(f"{prof}\\Documents\\{DOCS[2]}", os.path.join(docs_dir, DOCS[2]), ctime=plus(connect, minutes=5))
    m.delete_later(f"{prof}\\Documents\\{DOCS[2]}", utc(2026, 9, 16, 9, 0))
    bag = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
    from .shellitems import file_entry
    uc.binary(bag, "0", root_folder() + b"\x00\x00", ts=plus(connect, minutes=1))
    uc.binary(bag, "MRUListEx", A.mru_list_ex(1))
    uc.binary(bag + r"\0", "0", volume("D") + b"\x00\x00", ts=plus(connect, minutes=1))
    uc.binary(bag + r"\0", "MRUListEx", A.mru_list_ex(1))
    uc.binary(bag + r"\0\0", "0", file_entry("Export", mtime=utc(2026, 9, 14, 5, 34)) + b"\x00\x00", ts=plus(connect, minutes=2))
    uc.binary(bag + r"\0\0", "MRUListEx", A.mru_list_ex(1))
    ff = f"{prof}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\ab12cd34.default-release"
    A.firefox_places(m.path(f"{ff}\\places.sqlite"), [
        dict(url="https://mail.google.com/mail/u/0/#inbox", title="Inbox - test.user@example.test", time=utc(2026, 9, 15, 3, 0)),
    ], downloads=[dict(url="https://mail-attachment.googleusercontent.com/attachment/u/0/?ui=2&attid=0.1",
                       target_path=dl, start=utc(2026, 9, 15, 3, 1, 50), end=utc(2026, 9, 15, 3, 2),
                       size=os.path.getsize(os.path.join(docs_dir, DOCS[0])))])
    m._register(f"{ff}\\places.sqlite", t0, utc(2026, 9, 15, 3, 2), None)
    fname, blob = build_prefetch("CCLEANER64.EXE", r"\VOLUME{01dc}\PROGRAM FILES\CCLEANER\CCLEANER64.EXE",
                                 [utc(2026, 9, 16, 9, 5)], 1, [r"\VOLUME{01dc}\WINDOWS\SYSTEM32\NTDLL.DLL"])
    m.add_file(f"C:\\Windows\\Prefetch\\{fname}", blob, ctime=utc(2026, 9, 16, 9, 5))
    m.manifest["pagefile"] = [{"offset": 2_000_000, "data_hex": A.utf16(MARKER).hex()}]
    m.finalize()
    return m


def build_usb(staging: str, docs_dir: str) -> dict:
    d = os.path.join(staging, "USB-TEST")
    os.makedirs(os.path.join(d, "root", "Export"), exist_ok=True)
    import shutil
    files = []
    for i, name in enumerate(DOCS):
        shutil.copyfile(os.path.join(docs_dir, name), os.path.join(d, "root", "Export", name))
        files.append({"path": f"Export/{name}", "local_time": f"2026-09-14 11:0{5 + i}:00"})
    with open(os.path.join(d, "root", "Export", "scratch.tmp"), "w") as fh:
        fh.write(MARKER + " deleted scratch file\n")
    manifest = {"name": "USB-TEST", "disk": {"size_mb": 64, "scheme": "mbr",
                "partitions": [{"type": "fat32", "fs": "fat32", "label": USB["label"], "serial": f"{USB['vsn']:08X}"}]},
                "files": files, "delete": [{"path": "Export/scratch.tmp"}]}
    with open(os.path.join(d, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1)
    return manifest


def write_inputs(out_dir: str, hashes: dict) -> None:
    """Write a DLP-style alert export that the tool will import as case input."""
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "dlp_alerts.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Activity", "Happened (UTC)", "User", "Device name", "File name", "File path", "File size",
                    "SHA256", "Removable media serial", "Target domain", "Policy"])
        for i, name in enumerate(DOCS):
            w.writerow(["FileCopiedToRemovableMedia", f"2026-09-14T05:3{5 + i}:00Z", "testuser", "WKSTN-TEST-01", name,
                        f"C:\\Users\\testuser\\Documents\\Project\\{name}", hashes[name]["size"],
                        hashes[name]["sha256"], USB["serial"], "", "Test Policy"])
        w.writerow(["FileUploadedToCloud", "2026-09-14T06:12:00Z", "testuser", "WKSTN-TEST-01", DOCS[0],
                    f"C:\\Users\\testuser\\Documents\\Project\\{DOCS[0]}", hashes[DOCS[0]]["size"],
                    hashes[DOCS[0]]["sha256"], "", "mail.google.com", "Test Policy"])
    with open(os.path.join(out_dir, "hashes.json"), "w") as fh:
        json.dump(hashes, fh, indent=1)
