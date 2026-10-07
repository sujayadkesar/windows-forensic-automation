"""Windows event logs (EVTX).

Every ``*.evtx`` file in ``System32\\winevt\\Logs`` is parsed once with the Rust
``evtx`` parser.  Only events listed in :data:`CATALOG` are stored (grouped into
analyst friendly artifact types); all other events are counted so the coverage
matrix can show what each log contained and the time span it covers.
"""

from __future__ import annotations

import json
import os
import re

from ..core.timeutil import db_ts, parse_any
from ..knowledge import score_command
from ._evtxutil import iter_records
from ._usbutil import BUS_TYPES, decode_hex_field, parse_instance_id, parse_vbr
from .base import ArtifactModule, ArtifactType, C, register

LOGON_TYPES = {"0": "System", "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
               "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive (RDP)", "11": "CachedInteractive",
               "12": "CachedRemoteInteractive", "13": "CachedUnlock"}
STATUS = {"0xc000006a": "Wrong password", "0xc0000064": "Unknown user name", "0xc000006d": "Bad user name or password",
          "0xc000006f": "Outside logon hours", "0xc0000070": "Workstation restriction", "0xc0000072": "Account disabled",
          "0xc0000234": "Account locked out", "0xc0000193": "Account expired", "0xc0000071": "Password expired",
          "0xc0000224": "Password must change", "0xc000015b": "Logon type not granted", "0xc0000133": "Clock skew"}

# channel (lower case) -> {event id: (artifact type, description)}
CATALOG: dict[str, dict[int, tuple[str, str]]] = {
    "security": {
        4624: ("evt_logon", "Successful logon"), 4625: ("evt_logon", "Failed logon"), 4634: ("evt_logon", "Logoff"),
        4647: ("evt_logon", "User initiated logoff"), 4648: ("evt_logon", "Logon with explicit credentials"),
        4672: ("evt_logon", "Special privileges assigned (admin logon)"), 4776: ("evt_logon", "NTLM credential validation"),
        4768: ("evt_logon", "Kerberos TGT requested"), 4769: ("evt_logon", "Kerberos service ticket requested"),
        4771: ("evt_logon", "Kerberos pre-authentication failed"), 4800: ("evt_logon", "Workstation locked"),
        4801: ("evt_logon", "Workstation unlocked"), 4802: ("evt_logon", "Screen saver invoked"),
        4803: ("evt_logon", "Screen saver dismissed"), 4778: ("evt_rdp", "Session reconnected"),
        4779: ("evt_rdp", "Session disconnected"), 4688: ("evt_process", "Process created"),
        4697: ("evt_service", "Service installed"), 4698: ("evt_task", "Scheduled task created"),
        4699: ("evt_task", "Scheduled task deleted"), 4700: ("evt_task", "Scheduled task enabled"),
        4701: ("evt_task", "Scheduled task disabled"), 4702: ("evt_task", "Scheduled task updated"),
        4720: ("evt_account", "User account created"), 4722: ("evt_account", "User account enabled"),
        4723: ("evt_account", "Password change attempted"), 4724: ("evt_account", "Password reset"),
        4725: ("evt_account", "User account disabled"), 4726: ("evt_account", "User account deleted"),
        4738: ("evt_account", "User account changed"), 4740: ("evt_account", "User account locked out"),
        4728: ("evt_account", "Member added to global group"), 4732: ("evt_account", "Member added to local group"),
        4756: ("evt_account", "Member added to universal group"), 4733: ("evt_account", "Member removed from local group"),
        4781: ("evt_account", "Account name changed"), 1102: ("evt_clear", "Security audit log cleared"),
        4719: ("evt_clear", "System audit policy changed"), 4616: ("evt_system", "System time changed"),
        4663: ("evt_file_access", "Object access attempt"), 4656: ("evt_file_access", "Handle to object requested"),
        4660: ("evt_file_access", "Object deleted"), 5140: ("evt_share", "Network share accessed"),
        5145: ("evt_share", "Network share object checked"), 5142: ("evt_share", "Network share added"),
        6416: ("usb_event", "New external device recognized"), 4657: ("evt_persistence", "Registry value modified"),
        5156: ("evt_network", "WFP connection permitted"),
    },
    "system": {
        7045: ("evt_service", "Service installed"), 7034: ("evt_service", "Service terminated unexpectedly"),
        7040: ("evt_service", "Service start type changed"), 104: ("evt_clear", "Event log cleared"),
        6005: ("evt_system", "Event log service started (boot)"), 6006: ("evt_system", "Event log service stopped (shutdown)"),
        6008: ("evt_system", "Unexpected shutdown"), 6009: ("evt_system", "OS version at boot"),
        6013: ("evt_system", "System uptime"), 1074: ("evt_system", "Shutdown / restart initiated"),
        41: ("evt_system", "Kernel-Power: rebooted without clean shutdown"), 42: ("evt_system", "System entering sleep"),
        107: ("evt_system", "Resumed from sleep"), 1: ("evt_system", "Power / time event"), 12: ("evt_system", "OS started"),
        13: ("evt_system", "OS shutdown"), 20001: ("usb_event", "Driver installation (UserPnp)"),
        20003: ("usb_event", "Service added for device (UserPnp)"), 24576: ("usb_event", "Driver installed (WPD)"),
        1014: ("evt_network", "DNS name resolution timed out"), 10016: None,
        133: ("evt_optical", "CD/DVD write operation logged by the cdrom driver"),
    },
    "application": {
        1000: ("evt_app", "Application crash"), 1001: ("evt_app", "Windows Error Reporting"),
        1002: ("evt_app", "Application hang"), 11707: ("evt_app", "MSI product installed"),
        11724: ("evt_app", "MSI product removed"), 1033: ("evt_app", "MSI product installed"),
        1034: ("evt_app", "MSI product removed"), 0: ("evt_app", "Application event"), 216: None,
        1116: ("evt_defender", "Antivirus detection"), 4097: ("evt_app", "Application event"),
    },
    "windows powershell": {
        400: ("evt_powershell", "PowerShell engine started"), 403: ("evt_powershell", "PowerShell engine stopped"),
        600: ("evt_powershell", "PowerShell provider started"), 800: ("evt_powershell", "Pipeline execution details"),
    },
    "microsoft-windows-powershell/operational": {
        4103: ("evt_powershell", "Module logging (command invocation)"), 4104: ("evt_powershell", "Script block logged"),
        40961: ("evt_powershell", "PowerShell console starting"), 40962: ("evt_powershell", "PowerShell console ready"),
        53504: ("evt_powershell", "PowerShell IPC listening"),
    },
    "powershellcore/operational": {
        4104: ("evt_powershell", "Script block logged (pwsh)"), 4103: ("evt_powershell", "Module logging (pwsh)"),
    },
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": {
        1149: ("evt_rdp", "RDP user authentication succeeded"), 261: ("evt_rdp", "RDP listener received connection"),
    },
    "microsoft-windows-terminalservices-localsessionmanager/operational": {
        21: ("evt_rdp", "Session logon succeeded"), 22: ("evt_rdp", "Shell start notification"),
        23: ("evt_rdp", "Session logoff succeeded"), 24: ("evt_rdp", "Session disconnected"),
        25: ("evt_rdp", "Session reconnection succeeded"), 39: ("evt_rdp", "Session disconnected by another session"),
        40: ("evt_rdp", "Session disconnected (reason code)"), 41: ("evt_rdp", "Begin session arbitration"),
    },
    "microsoft-windows-terminalservices-rdpclient/operational": {
        1024: ("evt_rdp", "Outbound RDP connection attempt"), 1102: ("evt_rdp", "Outbound RDP multi-transport"),
        1026: ("evt_rdp", "Outbound RDP disconnected"), 1029: ("evt_rdp", "Outbound RDP user name hash"),
    },
    "microsoft-windows-remotedesktopservices-rdpcorets/operational": {
        131: ("evt_rdp", "RDP connection accepted (transport)"), 98: ("evt_rdp", "RDP TCP connection established"),
        140: ("evt_rdp", "RDP connection failed (bad credentials)"),
    },
    "microsoft-windows-taskscheduler/operational": {
        106: ("evt_task", "Task registered"), 140: ("evt_task", "Task updated"), 141: ("evt_task", "Task deleted"),
        200: ("evt_task", "Task action started"), 201: ("evt_task", "Task action completed"),
        129: ("evt_task", "Task launched process"), 100: None, 102: None,
    },
    "microsoft-windows-windows defender/operational": {
        1116: ("evt_defender", "Malware detected"), 1117: ("evt_defender", "Action taken on malware"),
        1118: ("evt_defender", "Remediation failed"), 1119: ("evt_defender", "Critical remediation error"),
        1006: ("evt_defender", "Malware detected (legacy)"), 1007: ("evt_defender", "Action taken (legacy)"),
        1015: ("evt_defender", "Suspicious behavior detected"), 1013: ("evt_defender", "Malware history deleted"),
        5001: ("evt_defender", "Real-time protection disabled"), 5004: ("evt_defender", "RTP configuration changed"),
        5007: ("evt_defender", "Defender configuration changed"), 5010: ("evt_defender", "Scanning for malware disabled"),
        5012: ("evt_defender", "Virus scanning disabled"), 5013: ("evt_defender", "Tamper protection blocked change"),
        1121: ("evt_defender", "ASR rule blocked"), 1122: ("evt_defender", "ASR rule audited"),
        1125: ("evt_defender", "Network protection audit"), 1126: ("evt_defender", "Network protection block"),
    },
    "microsoft-windows-sysmon/operational": {
        1: ("evt_process", "Sysmon process create"), 3: ("evt_sysmon", "Network connection"),
        8: ("evt_sysmon", "CreateRemoteThread"), 10: ("evt_sysmon", "Process access"), 11: ("evt_sysmon", "File created"),
        12: ("evt_sysmon", "Registry object added/deleted"), 13: ("evt_sysmon", "Registry value set"),
        15: ("evt_sysmon", "File stream created (Zone.Identifier/ADS)"), 22: ("evt_sysmon", "DNS query"),
        23: ("evt_sysmon", "File deleted (archived)"), 25: ("evt_sysmon", "Process tampering"),
        26: ("evt_sysmon", "File delete logged"), 2: ("evt_sysmon", "File creation time changed"),
        6: ("evt_sysmon", "Driver loaded"), 19: ("evt_persistence", "WMI event filter"),
        20: ("evt_persistence", "WMI event consumer"), 21: ("evt_persistence", "WMI consumer-to-filter binding"),
    },
    "microsoft-windows-bits-client/operational": {
        3: ("evt_network", "BITS job created"), 59: ("evt_network", "BITS transfer started"),
        60: ("evt_network", "BITS transfer stopped"), 4: ("evt_network", "BITS job completed"),
    },
    "microsoft-windows-wmi-activity/operational": {
        5857: ("evt_persistence", "WMI provider loaded"), 5860: ("evt_persistence", "WMI temporary event registration"),
        5861: ("evt_persistence", "WMI permanent event subscription"), 5858: None,
    },
    "microsoft-windows-winrm/operational": {
        6: ("evt_rdp", "WinRM session created"), 91: ("evt_rdp", "WinRM shell created"), 168: ("evt_rdp", "WinRM authentication"),
    },
    "microsoft-windows-shell-core/operational": {
        9707: ("evt_process", "Run/RunOnce key command started"), 9708: ("evt_process", "Run/RunOnce key command finished"),
        28115: ("evt_app", "Application shortcut added to app list"),
    },
    "microsoft-windows-applocker/exe and dll": {
        8002: ("evt_process", "AppLocker allowed"), 8003: ("evt_process", "AppLocker would block (audit)"),
        8004: ("evt_process", "AppLocker blocked"),
    },
    "microsoft-windows-partition/diagnostic": {1006: ("usb_event", "Disk connected/disconnected (partition table + VBR)")},
    "microsoft-windows-kernel-pnp/configuration": {
        400: ("usb_event", "Device configured"), 410: ("usb_event", "Device started"), 420: ("usb_event", "Device deleted"),
        430: ("usb_event", "Device requires further installation"),
    },
    "microsoft-windows-kernel-pnp/device configuration": {
        400: ("usb_event", "Device configured"), 410: ("usb_event", "Device started"),
    },
    "microsoft-windows-driverframeworks-usermode/operational": {
        2003: ("usb_event", "UMDF host loading drivers (device connected)"), 2004: ("usb_event", "UMDF loading driver"),
        2010: ("usb_event", "UMDF driver loaded"), 2100: ("usb_event", "UMDF PnP/power operation"),
        2101: ("usb_event", "UMDF PnP/power operation completed"), 2105: ("usb_event", "UMDF forwarded request"),
        2106: ("usb_event", "UMDF request completed"),
    },
    "microsoft-windows-devicesetupmanager/admin": {
        112: ("usb_event", "Device setup completed"), 100: None, 101: None,
    },
    "microsoft-windows-storsvc/diagnostic": {1001: ("usb_event", "Storage device information")},
    "microsoft-windows-ntfs/operational": {
        98: ("usb_event", "NTFS volume mounted / health checked"), 142: ("usb_event", "NTFS volume summary"),
        145: ("usb_event", "NTFS volume information"),
    },
    "microsoft-windows-vhdmp-operational": {
        1: ("usb_event", "Virtual disk (VHD/ISO) surfaced"), 2: ("usb_event", "Virtual disk (VHD/ISO) removed"),
        12: ("usb_event", "Virtual disk opened"), 22: ("usb_event", "Virtual disk surfaced"),
        23: ("usb_event", "Virtual disk unsurfaced"), 25: ("usb_event", "Virtual disk attached"),
    },
    "microsoft-windows-vhdmp/operational": {
        1: ("usb_event", "Virtual disk (VHD/ISO) surfaced"), 2: ("usb_event", "Virtual disk (VHD/ISO) removed"),
        12: ("usb_event", "Virtual disk opened"), 22: ("usb_event", "Virtual disk surfaced"),
        23: ("usb_event", "Virtual disk unsurfaced"), 25: ("usb_event", "Virtual disk attached"),
    },
    "microsoft-windows-wlan-autoconfig/operational": {
        8001: ("evt_network", "Wi-Fi connected"), 8003: ("evt_network", "Wi-Fi disconnected"),
        8002: ("evt_network", "Wi-Fi connection failed"), 11001: ("evt_network", "Wi-Fi association succeeded"),
    },
    "microsoft-windows-networkprofile/operational": {
        10000: ("evt_network", "Network connected"), 10001: ("evt_network", "Network disconnected"),
    },
    "microsoft-windows-printservice/operational": {307: ("evt_print", "Document printed")},
    "oalerts": {300: ("evt_app", "Microsoft Office alert dialog")},
    "microsoft office alerts": {300: ("evt_app", "Microsoft Office alert dialog")},
    "microsoft-windows-windows firewall with advanced security/firewall": {
        2004: ("evt_persistence", "Firewall rule added"), 2005: ("evt_persistence", "Firewall rule modified"),
        2006: ("evt_persistence", "Firewall rule deleted"), 2097: ("evt_persistence", "Firewall rule added"),
        2052: ("evt_persistence", "Firewall rule deleted"), 2003: ("evt_persistence", "Firewall profile setting changed"),
    },
    "microsoft-windows-winlogon/operational": {
        7001: ("evt_logon", "User logon notification (CEIP)"), 7002: ("evt_logon", "User logoff notification (CEIP)"),
        811: None, 812: None,
    },
    "microsoft-windows-user profile service/operational": {
        5: ("evt_logon", "User registry hive loaded"), 67: None,
    },
    "microsoft-windows-codeintegrity/operational": {
        3033: ("evt_process", "Code integrity: image did not meet signing level"),
        3077: ("evt_process", "Code integrity: blocked (WDAC)"),
    },
    "microsoft-windows-smbclient/security": {31001: ("evt_share", "SMB client logon failure")},
    "microsoft-windows-smbserver/security": {551: ("evt_share", "SMB session authentication failure")},
    "microsoft-windows-dns-client/operational": {3008: ("evt_network", "DNS query completed"), 3020: ("evt_network", "DNS query response")},
}

_CHANNEL_ALIASES = {"microsoft-windows-vhdmp-operational": "microsoft-windows-vhdmp/operational"}

# Windows 2000 / XP / Server 2003 (.evt): records carry positional insertion strings only.  (log, event id) ->
# (Vista+ equivalent id, description, names of the insertion strings in order).  Records keep their own event id; the
# equivalent id lets the analyzers treat 528 like 4624.  Layouts follow the Windows Server 2003 security event
# reference; older builds log a prefix of the same strings.
_LOGON = ["TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName",
          "WorkstationName", "LogonGuid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ProcessId",
          "TransmittedServices", "IpAddress", "IpPort"]
_FAILED = ["TargetUserName", "TargetDomainName", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
           "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ProcessId", "TransmittedServices", "IpAddress", "IpPort"]
_ACCT = ["TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList"]
_GROUP = ["MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserName", "SubjectDomainName",
          "SubjectLogonId", "PrivilegeList"]
_FAIL_REASON = {529: "Unknown user name or bad password", 530: "Outside logon hours", 531: "Account disabled",
                532: "Account expired", 533: "Workstation restriction", 534: "Logon type not granted", 535: "Password expired",
                536: "NetLogon component not active", 537: "Unexpected error during logon", 539: "Account locked out"}
LEGACY: dict[tuple[str, int], tuple[int, str, list[str]]] = {
    ("security", 528): (4624, "Successful logon", _LOGON),
    ("security", 540): (4624, "Successful network logon", _LOGON),
    **{("security", k): (4625, f"Failed logon - {v.lower()}", _FAILED) for k, v in _FAIL_REASON.items()},
    ("security", 538): (4634, "Logoff", ["TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType"]),
    ("security", 551): (4647, "User initiated logoff", ["TargetUserName", "TargetDomainName", "TargetLogonId"]),
    ("security", 552): (4648, "Logon with explicit credentials",
                        ["SubjectUserName", "SubjectDomainName", "SubjectLogonId", "LogonGuid", "TargetUserName", "TargetDomainName",
                         "TargetLogonGuid", "TargetServerName", "TargetInfo", "ProcessId", "IpAddress", "IpPort"]),
    ("security", 592): (4688, "Process created",
                        ["NewProcessId", "NewProcessName", "ProcessId", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"]),
    ("security", 601): (4697, "Service installed",
                        ["ServiceFileName", "ServiceName", "ServiceType", "ServiceStartType", "ServiceAccount", "SubjectUserName",
                         "SubjectDomainName", "SubjectLogonId"]),
    ("security", 624): (4720, "User account created", _ACCT),
    ("security", 626): (4722, "User account enabled", _ACCT),
    ("security", 627): (4723, "Password change attempted", _ACCT),
    ("security", 628): (4724, "Password reset", _ACCT),
    ("security", 629): (4725, "User account disabled", _ACCT),
    ("security", 630): (4726, "User account deleted", _ACCT),
    ("security", 632): (4728, "Member added to global group", _GROUP),
    ("security", 636): (4732, "Member added to local group", _GROUP),
    ("security", 637): (4733, "Member removed from local group", _GROUP),
    ("security", 660): (4756, "Member added to universal group", _GROUP),
    ("security", 517): (1102, "Audit log cleared",
                        ["PrimaryUserName", "PrimaryDomainName", "PrimaryLogonId", "SubjectUserName", "SubjectDomainName",
                         "SubjectLogonId"]),
    ("system", 6005): (6005, "Event log service started (boot)", []),
    ("system", 6006): (6006, "Event log service stopped (shutdown)", []),
    ("system", 6008): (6008, "Unexpected shutdown", []),
    ("system", 6009): (6009, "OS version at boot", []),
    ("system", 1074): (1074, "Shutdown / restart initiated", []),
    ("application", 1000): (1000, "Application crash", []),
    ("application", 1001): (1001, "Windows Error Reporting", []),
    ("application", 1002): (1002, "Application hang", []),
}
_LEGACY_TYPE = {4624: "evt_logon", 4625: "evt_logon", 4634: "evt_logon", 4647: "evt_logon", 4648: "evt_logon",
                4688: "evt_process", 4697: "evt_service", 1102: "evt_clear", 6005: "evt_system", 6006: "evt_system",
                6008: "evt_system", 6009: "evt_system", 1074: "evt_system", 1000: "evt_app", 1001: "evt_app", 1002: "evt_app",
                **{k: "evt_account" for k in (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4733, 4756)}}
_LEGACY_LOG = {"secevent.evt": "security", "sysevent.evt": "system", "appevent.evt": "application"}

RX_EID = re.compile(r'"EventID":\s*(?:\{"#attributes":\{[^}]*\},"#text":\s*)?(\d+)')
RX_CHANNEL = re.compile(r'"Channel":\s*"([^"]*)"')

TYPE_COLUMNS = {
    "evt_logon": [C("event_id", "Event ID", "int", 70), C("description", width=230), C("target_user", "User"),
                  C("target_domain", "Domain"), C("logon_type", "Logon Type"), C("source_ip", "Source IP"),
                  C("workstation"), C("logon_id", "Logon ID"), C("process"), C("auth_package", "Auth Package"), C("status")],
    "evt_rdp": [C("event_id", "Event ID", "int", 70), C("description", width=230), C("user"), C("source_ip", "Source / Target"),
                C("session_id", "Session"), C("channel", width=200)],
    "evt_process": [C("event_id", "Event ID", "int", 70), C("description"), C("process", kind="path", width=280),
                    C("command_line", width=420), C("parent", kind="path"), C("user"), C("pid", "PID"), C("score", kind="int")],
    "evt_service": [C("event_id", "Event ID", "int", 70), C("description"), C("service_name", "Service"),
                    C("image_path", "Image Path", "path", 380), C("start_type", "Start Type"), C("account"), C("score", kind="int")],
    "evt_task": [C("event_id", "Event ID", "int", 70), C("description"), C("task_name", "Task", width=260),
                 C("action", width=320), C("user"), C("result")],
    "evt_powershell": [C("event_id", "Event ID", "int", 70), C("description"), C("script", "Script / Command", width=480),
                       C("path", kind="path"), C("user"), C("score", kind="int"), C("indicators", width=260)],
    "evt_defender": [C("event_id", "Event ID", "int", 70), C("description"), C("threat"), C("severity"),
                     C("path", kind="path", width=320), C("process", kind="path"), C("action"), C("user")],
    "evt_account": [C("event_id", "Event ID", "int", 70), C("description"), C("target_user", "Target Account"),
                    C("subject_user", "Changed By"), C("group"), C("details", width=260)],
    "evt_clear": [C("event_id", "Event ID", "int", 70), C("description"), C("log", "Log"), C("subject_user", "Cleared By")],
    "evt_system": [C("event_id", "Event ID", "int", 70), C("description", width=260), C("details", width=420)],
    "evt_network": [C("event_id", "Event ID", "int", 70), C("description"), C("name", "Network / Host / URL", width=320),
                    C("details", width=300)],
    "evt_app": [C("event_id", "Event ID", "int", 70), C("description"), C("application", width=260), C("details", width=420)],
    "evt_print": [C("document", width=260), C("user"), C("printer"), C("pages", kind="int"), C("size", kind="size"), C("port")],
    "evt_optical": [C("device", width=200), C("event_id", "Event ID", "int", 70), C("provider"), C("details", width=380)],
    "evt_share": [C("event_id", "Event ID", "int", 70), C("description"), C("share"), C("path", kind="path"), C("user"),
                  C("source_ip", "Source IP")],
    "evt_file_access": [C("event_id", "Event ID", "int", 70), C("description"), C("object", kind="path", width=360),
                        C("process", kind="path"), C("user"), C("access")],
    "evt_sysmon": [C("event_id", "Event ID", "int", 70), C("description"), C("image", kind="path", width=260),
                   C("target", width=380), C("user")],
    "evt_persistence": [C("event_id", "Event ID", "int", 70), C("description"), C("name", width=240), C("details", width=420)],
}
TYPE_TITLES = {
    "evt_logon": ("Logon / Logoff Events", "Users & Accounts"), "evt_rdp": ("Remote Desktop / Remote Session Events", "Remote Access"),
    "evt_process": ("Process Execution Events", "Program Execution"), "evt_service": ("Service Events", "Persistence"),
    "evt_task": ("Scheduled Task Events", "Persistence"), "evt_powershell": ("PowerShell Events", "Program Execution"),
    "evt_defender": ("Microsoft Defender Events", "Malware"), "evt_account": ("Account Management Events", "Users & Accounts"),
    "evt_clear": ("Log Clearing / Audit Policy Events", "Anti-Forensics"), "evt_system": ("System Power / Time Events", "System Information"),
    "evt_network": ("Network Events", "Network"), "evt_app": ("Application Events", "Program Execution"),
    "evt_print": ("Print Jobs", "File & Folder Access"), "evt_optical": ("Optical Disc Write Events", "USB & Removable Media"), "evt_share": ("Network Share Events", "Network"),
    "evt_file_access": ("File Object Access (Audit)", "File & Folder Access"), "evt_sysmon": ("Sysmon Events", "Program Execution"),
    "evt_persistence": ("Persistence / Configuration Events", "Persistence"),
}


def _flatten(d, prefix="") -> dict:
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            if k == "#attributes":
                if isinstance(v, dict):
                    for ak, av in v.items():
                        out[f"{prefix}{ak}"] = av
                continue
            if k == "#text":
                if isinstance(v, list):
                    for i, x in enumerate(v):
                        out[f"{prefix}Data{i}"] = x
                else:
                    out[prefix.rstrip(".") or "text"] = v
                continue
            if isinstance(v, (dict, list)):
                out.update(_flatten(v, f"{k}."))
            else:
                out[f"{prefix}{k}"] = v
    elif isinstance(d, list):
        for i, x in enumerate(d):
            if isinstance(x, (dict, list)):
                out.update(_flatten(x, f"{prefix}{i}."))
            else:
                out[f"{prefix}Data{i}"] = x
    return out


def event_payload(ev: dict) -> dict:
    """EventData / UserData flattened to a simple {name: value} dict."""
    body = ev.get("EventData")
    if body is None:
        ud = ev.get("UserData")
        if isinstance(ud, dict) and len(ud) == 1:
            body = next(iter(ud.values()))
        else:
            body = ud
    if body is None:
        return {}
    if isinstance(body, dict) and set(body.keys()) <= {"Data", "#attributes", "Binary"}:
        data = body.get("Data")
        out = {}
        if isinstance(data, dict) and "#text" in data:
            t = data["#text"]
            if isinstance(t, list):
                out = {f"Data{i}": x for i, x in enumerate(t)}
            else:
                out = {"Data0": t}
        elif isinstance(data, list):
            out = {f"Data{i}": x for i, x in enumerate(data)}
        elif data is not None:
            out = {"Data0": data}
        if body.get("Binary"):
            out["Binary"] = body["Binary"]
        return out
    flat = _flatten(body)
    return {k.split(".")[-1] if k.count(".") <= 1 else k: v for k, v in flat.items()}


def g(d: dict, *names, default=""):
    for n in names:
        v = d.get(n)
        if v not in (None, "", "-"):
            return v
    return default


@register
class EventLogModule(ArtifactModule):
    id = "eventlogs"
    title = "Windows event logs"
    category = "Event Logs"
    description = ("Parses every EVTX log (Security, System, Application, PowerShell, RDP, Task Scheduler, Defender, "
                   "Sysmon, WLAN, Print, Partition, Kernel-PnP, ...) and keeps forensically relevant events.")
    weight = 8.0
    order = 20
    locations = ["C:\\Windows\\System32\\winevt\\Logs\\*.evtx"]
    artifact_types = [
        ArtifactType("evtx_log", "Event Log Files", "Event Logs",
                     [C("file", width=360), C("channel", width=280), C("records", kind="int"), C("kept", "Relevant", "int"),
                      C("first_event", kind="datetime"), C("last_event", kind="datetime"), C("size", kind="size")],
                     description="Every EVTX file with its record count and time span (log retention)."),
        ArtifactType("usb_event", "USB / Device Events", "USB & Removable Media",
                     [C("event"), C("description", width=260), C("vendor"), C("product"), C("serial", width=180),
                      C("details", width=380), C("event_id", "Event ID", "int", 70), C("channel", width=220)]),
    ] + [ArtifactType(t, TYPE_TITLES[t][0], TYPE_TITLES[t][1], cols) for t, cols in TYPE_COLUMNS.items()]

    def estimate(self, ctx) -> float:
        total = 0
        for p in ctx.glob("C:/Windows/System32/winevt/Logs/*.evtx"):
            try:
                total += p.stat().st_size
            except Exception:
                pass
        ctx.cache["evtx_bytes"] = total
        return 1.0 + total / 4_000_000

    def run(self, ctx) -> None:
        try:
            pass
        except ImportError:
            ctx.coverage("Event logs", "winevt\\Logs", "error", 0, "evtx parser not available")
            return
        files = sorted(ctx.glob("C:/Windows/System32/winevt/Logs/*.evtx"), key=lambda p: p.name.lower())
        legacy = {}
        for pat in ("C:/Windows/System32/config/*.[Ee][Vv][Tt]", "C:/WINNT/system32/config/*.[Ee][Vv][Tt]"):
            for p in ctx.glob(pat):
                legacy.setdefault(p.name.lower(), p)
        if not files and not legacy:
            ctx.coverage("Event logs", "C:\\Windows\\System32\\winevt\\Logs", "absent", 0)
            return
        total = sum(_size(p) for p in files) or 1
        done = 0
        self.ps_blocks: dict[str, dict] = {}
        self.channels_seen: set[str] = set()
        if legacy:
            self._legacy_logs(ctx, [legacy[k] for k in sorted(legacy)])
        dump_all = ctx.options.get("export_all_events", True)
        from ..core.exporter import CsvOut, safe_name

        for p in files:
            size = _size(p)
            stem = p.name[:-5]
            dump = None  # created on the first record, so empty logs leave no file
            channel_guess = stem.replace("%4", "/").lower()
            if channel_guess.startswith("archive-"):
                channel_guess = re.sub(r"^archive-(.+?)-\d{4}-\d{2}-\d{2}.*$", r"\1", channel_guess)
            channel_guess = _CHANNEL_ALIASES.get(channel_guess, channel_guess)
            stats = {"records": 0, "kept": 0, "first": None, "last": None, "channel": None}
            parse_stats = {}
            try:
                with p.open("rb") as fh:
                    raw = fh.read()
                parse_stats: dict = {}
                for rec in iter_records(raw, parse_stats):
                    stats["records"] += 1
                    if stats["records"] % 2000 == 0:
                        ctx.progress((done + size * 0.5) / total, f"{p.name}: {stats['records']:,} records")
                    data = rec.get("data") or ""
                    ts = rec.get("timestamp", "")
                    if ts:
                        if stats["first"] is None or ts < stats["first"]:
                            stats["first"] = ts
                        if stats["last"] is None or ts > stats["last"]:
                            stats["last"] = ts
                    m = RX_EID.search(data)
                    if not m:
                        continue
                    eid = int(m.group(1))
                    cm = RX_CHANNEL.search(data)
                    channel = (cm.group(1) if cm else channel_guess).lower()
                    stats["channel"] = stats["channel"] or (cm.group(1) if cm else None)
                    ev = None
                    if dump is None and dump_all:
                        dump = CsvOut(os.path.join(ctx.parsed_dir("Event Logs - all records"), safe_name(stem) + ".csv"),
                                      ["TimeCreatedUTC", "RecordId", "EventId", "Level", "Provider", "Channel", "Computer", "UserSid",
                                       "Payload"])
                    if dump is not None:
                        try:
                            ev = json.loads(data)["Event"]
                            self._dump_row(dump, ev, ts, rec.get("event_record_id"), eid)
                        except Exception:
                            ev = None
                    cat = CATALOG.get(_CHANNEL_ALIASES.get(channel, channel)) or CATALOG.get(channel_guess)
                    if not cat:
                        continue
                    spec = cat.get(eid)
                    if not spec:
                        continue
                    if ev is None:
                        try:
                            ev = json.loads(data)["Event"]
                        except Exception:
                            continue
                    if self._handle(ctx, spec, eid, ev, p):
                        stats["kept"] += 1
            except Exception as e:
                ctx.warn(f"EVTX {p.name}: {e}")
                ctx.coverage("Event log", str(p).replace("/", "\\"), "error", stats["kept"], str(e)[:200])
            if dump is not None:
                dump.close()
            if parse_stats.get("first_error") and parse_stats.get("recovered_records"):
                note = (f"damaged / uninitialized chunk(s) ({parse_stats['first_error']}); "
                        f"{parse_stats.get('recovered_records', 0):,} records recovered chunk-by-chunk")
                ctx.coverage("Event log (recovered)", str(p).replace("/", "\\"), "partial", stats["kept"], note)
            self._flush_ps(ctx)
            if stats["records"]:
                self.channels_seen.add(_CHANNEL_ALIASES.get((stats["channel"] or channel_guess).lower(),
                                                            (stats["channel"] or channel_guess).lower()))
            ctx.emit("evtx_log", parse_any(stats["last"].replace(" UTC", "")) if stats["last"] else None, {
                "file": p.name, "channel": stats["channel"] or channel_guess, "records": stats["records"], "kept": stats["kept"],
                "first_event": db_ts(parse_any(stats["first"].replace(" UTC", ""))) if stats["first"] else None,
                "last_event": db_ts(parse_any(stats["last"].replace(" UTC", ""))) if stats["last"] else None, "size": size,
            }, summary=f"{p.name}: {stats['records']:,} records", source=str(p), ts_label="Last event")
            done += size
            ctx.progress(done / total, f"Parsed {p.name}")
        present = {c.lower() for c in self.channels_seen}
        for t in TYPE_COLUMNS:
            n = ctx.counts.get(t, 0)
            chans = sorted({ch for ch, ids in CATALOG.items() if any(v and v[0] == t for v in ids.values())})
            have = [c for c in chans if c in present]
            if n:
                status = "found"
            elif have:
                status = "not_found"
            else:
                status = "absent"
            loc = ", ".join(_nice_channel(c) for c in (have or chans))[:400]
            ctx.coverage(TYPE_TITLES[t][0], loc, status, n,
                         "" if have or n else "none of the source logs exist on this system")
        ctx.coverage("USB / device events", "Partition, Kernel-PnP, DriverFrameworks, Storsvc, Ntfs, VHDMP, Security 6416",
                     "found" if ctx.counts.get("usb_event") else "not_found", ctx.counts.get("usb_event", 0))

    def _legacy_logs(self, ctx, files) -> None:
        """Windows 2000 / XP / 2003 event logs (.evt): every record to the all-records export, mapped events to artifacts."""
        import io

        from dissect.eventlog.evt import Evt

        from ..core.exporter import CsvOut, safe_name

        types = {1: "Error", 2: "Warning", 4: "Information", 8: "Audit Success", 16: "Audit Failure"}
        for p in files:
            log = _LEGACY_LOG.get(p.name.lower(), p.name.rsplit(".", 1)[0].lower())
            stats = {"records": 0, "kept": 0, "first": None, "last": None}
            dump = None
            try:
                with p.open("rb") as fh:
                    raw = fh.read()
                for r in Evt(io.BytesIO(raw)):
                    stats["records"] += 1
                    ts = r.TimeGenerated
                    stats["first"] = min(stats["first"] or ts, ts)
                    stats["last"] = max(stats["last"] or ts, ts)
                    strings = [str(s) for s in (r.Strings or [])]
                    if dump is None and ctx.options.get("export_all_events", True):
                        dump = CsvOut(os.path.join(ctx.parsed_dir("Event Logs - all records"), safe_name(p.name.rsplit(".", 1)[0]) + ".csv"),
                                      ["TimeCreatedUTC", "RecordId", "EventId", "Level", "Provider", "Channel", "Computer", "UserSid",
                                       "Payload"])
                    if dump is not None:
                        dump.row([db_ts(ts)[:19], r.RecordNumber, r.EventCode, types.get(r.EventType, r.EventType), r.SourceName,
                                  log.title(), r.Computername, r.UserSid or "",
                                  " | ".join(f"String{i + 1}: {s}" for i, s in enumerate(strings) if s not in ("", "-"))[:30000]])
                    spec = LEGACY.get((log, r.EventCode))
                    if not spec or (log == "security" and r.SourceName != "Security"):
                        continue
                    modern, desc, names = spec
                    if modern in (1000, 1001, 1002) and r.SourceName not in ("Application Error", "Application Hang", "DrWatson"):
                        continue
                    d = dict(zip(names, strings)) if names else {f"Data{i}": v for i, v in enumerate(strings)}
                    if modern == 4625:
                        d["Status"] = _FAIL_REASON.get(r.EventCode, "")
                    typ = _LEGACY_TYPE[modern]
                    base = {"event_id": r.EventCode, "equivalent_id": modern, "description": desc, "channel": log.title(),
                            "provider": r.SourceName, "record_id": r.RecordNumber, "computer": r.Computername,
                            "user_sid": r.UserSid}
                    rec = getattr(self, f"_h_{typ}")(modern, d, base, r.SourceName)
                    if rec is False:
                        continue
                    out = {**base, **(rec or {}), "event_data": {k: str(v)[:4000] for k, v in d.items()}}
                    summary = out.pop("_summary", None) or f"{r.EventCode} {desc}"
                    tags = out.pop("_tags", None)
                    ctx.emit(typ, ts, out, summary=summary, user=out.get("user") or out.get("target_user") or None,
                             source=f"{p.name} (record {r.RecordNumber})", ts_label="Event time", tags=tags)
                    stats["kept"] += 1
            except Exception as e:
                ctx.warn(f"EVT {p.name}: {e}")
                ctx.coverage("Event log (legacy .evt)", str(p).replace("/", "\\"), "error", stats["kept"], str(e)[:200])
            if dump is not None:
                dump.close()
            if stats["records"]:
                self.channels_seen.add(log)
            ctx.emit("evtx_log", stats["last"], {
                "file": p.name, "channel": f"{log.title()} (Windows 2000 / XP / 2003 .evt)", "records": stats["records"],
                "kept": stats["kept"], "first_event": db_ts(stats["first"]), "last_event": db_ts(stats["last"]), "size": _size(p),
            }, summary=f"{p.name}: {stats['records']:,} records", source=str(p), ts_label="Last event")

    @staticmethod
    def _dump_row(dump, ev, ts, record_id, eid):
        sysd = ev.get("System") or {}
        sec = sysd.get("Security")
        pay = event_payload(ev)
        dump.row([str(ts).replace(" UTC", "").replace("T", " ").rstrip("Z"), record_id, eid, sysd.get("Level"),
                  ((sysd.get("Provider") or {}).get("#attributes") or {}).get("Name"), sysd.get("Channel"), sysd.get("Computer"),
                  ((sec or {}).get("#attributes") or {}).get("UserID") if isinstance(sec, dict) else "",
                  " | ".join(f"{k}: {v}" for k, v in pay.items() if v not in (None, "", "-"))[:30000]])

    # ------------------------------------------------------------------ handlers
    def _handle(self, ctx, spec, eid: int, ev: dict, path) -> bool:
        typ, desc = spec
        sysd = ev.get("System", {}) or {}
        d = event_payload(ev)
        ts_raw = ((sysd.get("TimeCreated") or {}).get("#attributes") or {}).get("SystemTime")
        ts = parse_any(ts_raw)
        provider = ((sysd.get("Provider") or {}).get("#attributes") or {}).get("Name", "")
        channel = sysd.get("Channel", "")
        rid = sysd.get("EventRecordID")
        sid = ((sysd.get("Security") or {}).get("#attributes") or {}).get("UserID") if isinstance(sysd.get("Security"), dict) else None
        base = {"event_id": eid, "description": desc, "channel": channel, "provider": provider, "record_id": rid,
                "computer": sysd.get("Computer"), "user_sid": sid}
        src = f"{path.name} (record {rid})"
        handler = getattr(self, f"_h_{typ}", None)
        rec = handler(eid, d, base, provider) if handler else None
        if rec is False:
            return False
        rec = rec or {}
        out = {**base, **rec, "event_data": {k: (str(v)[:4000] if v is not None else None) for k, v in d.items()}}
        if typ == "evt_powershell" and eid == 4104:
            return self._ps_block(ctx, ts, out, src)
        summary = out.pop("_summary", None) or f"{eid} {desc}"
        user = out.get("user") or out.get("target_user") or None
        ctx.emit(typ, ts, out, summary=summary, user=user if user not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") else user,
                 source=src, ts_label="Event time", tags=out.pop("_tags", None))
        return True

    def _h_evt_logon(self, eid, d, base, provider):
        lt = str(g(d, "LogonType"))
        user = g(d, "TargetUserName", "UserName", "AccountName", "Param1", "Data0" if eid in (7001, 7002) else "")
        if eid in (7001, 7002):
            user = g(d, "UserSid", "Data1")
        if eid in (4672, 4634, 4647, 4800, 4801, 4802, 4803):
            user = g(d, "SubjectUserName", "TargetUserName")
        status = g(d, "SubStatus", "Status", "FailureCode").lower()
        rec = {
            "target_user": user, "target_domain": g(d, "TargetDomainName", "SubjectDomainName", "Domain"),
            "logon_type": f"{lt} - {LOGON_TYPES.get(lt, '?')}" if lt else "", "source_ip": g(d, "IpAddress", "Client_Address"),
            "workstation": g(d, "WorkstationName", "Workstation"), "logon_id": g(d, "TargetLogonId", "SubjectLogonId"),
            "process": g(d, "ProcessName"), "auth_package": g(d, "AuthenticationPackageName", "LmPackageName"),
            "status": STATUS.get(status, status) if eid in (4625, 4771, 4776) and status not in ("0x0", "") else "",
            "elevated": g(d, "ElevatedToken"), "target_server": g(d, "TargetServerName", "TargetInfo"),
            "subject_user": g(d, "SubjectUserName"),
        }
        if eid == 4648:
            rec["target_user"] = g(d, "TargetUserName")
            rec["process"] = g(d, "ProcessName")
        if lt == "5" and eid in (4624, 4634):
            rec["_tags"] = ["service_logon"]
        ip = rec["source_ip"]
        rec["_summary"] = f"{eid} {base['description']}: {rec['target_user']}" + (f" type {lt}" if lt else "") + (
            f" from {ip}" if ip and ip not in ("::1", "127.0.0.1") else "")
        return rec

    def _h_evt_rdp(self, eid, d, base, provider):
        user = g(d, "User", "Param1", "AccountName", "TargetUserName", "UserName")
        dom = g(d, "Domain", "Param2", "AccountDomain")
        ip = g(d, "Address", "Param3", "IpAddress", "ClientAddress", "Value", "ServerName", "ClientIP", "clientIP")
        if base["channel"].lower().endswith("rdpclient/operational") and eid == 1024:
            ip = g(d, "Value", "ServerName")
        rec = {"user": f"{dom}\\{user}" if dom and user and "\\" not in user else user, "source_ip": ip,
               "session_id": g(d, "SessionID", "Session", "TargetSession")}
        rec["_summary"] = f"{eid} {base['description']}: {rec['user'] or ''} {ip or ''}".strip()
        return rec

    def _h_evt_process(self, eid, d, base, provider):
        proc = g(d, "NewProcessName", "Image", "FilePath", "FullFilePath", "PolicyName", "File", "Command")
        cmd = g(d, "CommandLine", "Command", "Data0")
        parent = g(d, "ParentProcessName", "ParentImage")
        user = g(d, "TargetUserName", "SubjectUserName", "User")
        sc = score_command(cmd or proc)
        rec = {"process": proc, "command_line": cmd, "parent": parent, "user": user,
               "pid": g(d, "NewProcessId", "ProcessId"), "parent_command_line": g(d, "ParentCommandLine"),
               "hashes": g(d, "Hashes"), "score": sc["score"], "indicators": ", ".join(m["title"] for m in sc["matches"])}
        rec["_summary"] = f"{proc} {('- ' + cmd[:160]) if cmd and cmd != proc else ''}".strip()
        if sc["score"] >= 6:
            rec["_tags"] = ["suspicious"]
        return rec

    def _h_evt_service(self, eid, d, base, provider):
        image = g(d, "ImagePath", "ServiceFileName", "param2")
        name = g(d, "ServiceName", "param1", "Data0")
        if eid in (7034, 7040):
            image = ""
            name = g(d, "param1", "Data0")
        sc = score_command(image)
        rec = {"service_name": name, "image_path": image, "start_type": g(d, "StartType", "ServiceStartType", "param4", "param3"),
               "account": g(d, "AccountName", "ServiceAccount", "param5"), "service_type": g(d, "ServiceType", "param3"),
               "score": sc["score"], "indicators": ", ".join(m["title"] for m in sc["matches"])}
        rec["_summary"] = f"{base['description']}: {name} {image}".strip()
        return rec

    def _h_evt_task(self, eid, d, base, provider):
        content = g(d, "TaskContent", "TaskContentNew")
        action = g(d, "ActionName", "Path", "ProcessID")
        if content:
            m = re.search(r"<Command>(.*?)</Command>", content, re.S)
            a = re.search(r"<Arguments>(.*?)</Arguments>", content, re.S)
            if m:
                action = (m.group(1) + (" " + a.group(1) if a else "")).strip()
        rec = {"task_name": g(d, "TaskName", "Name"), "action": action, "user": g(d, "SubjectUserName", "UserName", "UserContext"),
               "result": g(d, "ResultCode", "ReturnCode"), "content": content[:8000] if content else ""}
        sc = score_command(action + " " + (content or ""))
        rec["score"] = sc["score"]
        rec["_summary"] = f"{base['description']}: {rec['task_name']} {action}".strip()
        return rec

    def _h_evt_powershell(self, eid, d, base, provider):
        script = ""
        if eid == 4104:
            script = g(d, "ScriptBlockText")
        elif eid in (400, 403, 600, 800):
            ctxt = " ".join(str(v) for v in d.values() if isinstance(v, str))
            m = re.search(r"HostApplication=(.*?)(?:\r?\n|\s+EngineVersion=|$)", ctxt)
            script = m.group(1).strip() if m else ""
            if eid == 800:
                m2 = re.search(r"CommandLine=(.*?)(?:\r?\n|$)", ctxt)
                if m2 and m2.group(1).strip():
                    script = m2.group(1).strip()
            if not script:
                return False if eid in (403, 600) else {"script": ""}
        elif eid == 4103:
            script = g(d, "Payload", "ContextInfo")[:4000]
        rec = {"script": script, "path": g(d, "Path"), "script_block_id": g(d, "ScriptBlockId"),
               "message_number": g(d, "MessageNumber"), "message_total": g(d, "MessageTotal"), "user": None}
        return rec

    def _h_evt_defender(self, eid, d, base, provider):
        rec = {"threat": g(d, "Threat Name", "ThreatName", "Data0" if eid == 1116 and provider != "Microsoft-Windows-Windows Defender" else ""),
               "severity": g(d, "Severity Name", "SeverityName"), "path": g(d, "Path", "PathName"),
               "process": g(d, "Process Name", "ProcessName"), "action": g(d, "Action Name", "ActionName"),
               "user": g(d, "Detection User", "DetectionUser"), "category": g(d, "Category Name"),
               "origin": g(d, "Origin Name"), "source_name": g(d, "Source Name"),
               "new_value": g(d, "New Value", "NewValue"), "old_value": g(d, "Old Value", "OldValue")}
        if eid in (5007, 5004, 5001, 5010, 5012, 5013):
            rec["path"] = rec["new_value"] or rec["path"]
        rec["_summary"] = f"{base['description']}: {rec['threat'] or rec['new_value'] or ''} {rec['path'] or ''}".strip()
        return rec

    def _h_evt_account(self, eid, d, base, provider):
        rec = {"target_user": g(d, "TargetUserName", "MemberName", "MemberSid", "NewTargetUserName"),
               "subject_user": g(d, "SubjectUserName"), "group": g(d, "TargetUserName") if eid in (4728, 4732, 4733, 4756) else "",
               "details": g(d, "OldTargetUserName", "DisplayName", "UserAccountControl")}
        if eid in (4728, 4732, 4733, 4756):
            rec["target_user"] = g(d, "MemberName", "MemberSid")
        rec["_summary"] = f"{base['description']}: {rec['target_user']} by {rec['subject_user']}"
        return rec

    def _h_evt_clear(self, eid, d, base, provider):
        rec = {"log": base["channel"] if eid == 1102 else g(d, "Channel", "BackupPath", "Data0") or base["channel"],
               "subject_user": g(d, "SubjectUserName", "SubjectUserSid")}
        rec["_summary"] = f"{base['description']}: {rec['log']} by {rec['subject_user']}"
        rec["_tags"] = ["anti_forensics"]
        return rec

    def _h_evt_system(self, eid, d, base, provider):
        if eid == 1 and "Kernel-General" not in base["provider"] and "Power-Troubleshooter" not in base["provider"]:
            return False
        if eid in (12, 13) and "Kernel-General" not in base["provider"]:
            return False
        if eid == 1 and "Kernel-General" in base["provider"]:
            base = dict(base)
            details = f"Time changed from {g(d, 'OldTime')} to {g(d, 'NewTime')} ({g(d, 'Reason')})"
            return {"description": "System time changed", "details": details, "_summary": details}
        details = "; ".join(f"{k}={v}" for k, v in d.items() if v not in (None, "", "-") and not k.startswith("Binary"))[:600]
        return {"details": details, "_summary": f"{base['description']}" + (f": {details[:120]}" if details else "")}

    def _h_evt_network(self, eid, d, base, provider):
        name = g(d, "SSID", "ProfileName", "Name", "QueryName", "url", "RemoteName", "jobTitle", "DestAddress", "transferId")
        if eid in (59, 60, 3, 4):
            name = g(d, "url", "jobTitle", "name", "Data0")
        if eid == 5156:
            return False  # extremely noisy - counted only
        details = "; ".join(f"{k}={v}" for k, v in d.items() if v not in (None, "", "-") and k not in ("Binary",))[:600]
        return {"name": name, "details": details, "_summary": f"{base['description']}: {name}"}

    def _h_evt_app(self, eid, d, base, provider):
        if eid == 0 and not re.search(r"screenconnect|connectwise|anydesk|teamviewer|splashtop|atera|vnc", provider, re.I):
            return False
        if eid == 4097 and "screenconnect" not in provider.lower():
            return False
        if eid == 1116:
            return False
        # 1000 / 1001 / 1002 are crash / WER / hang only from these providers (LoadPerf and others reuse the numbers)
        if eid in (1000, 1001, 1002) and provider not in ("Application Error", "Windows Error Reporting", "Application Hang"):
            return False
        vals = [str(v) for v in d.values() if v not in (None, "", "-")]
        app = g(d, "Data0", "AppName", "ProductName")
        if eid in (11707, 11724, 1033, 1034):
            app = g(d, "Data0", "ProductName")
        details = " | ".join(vals)[:800]
        return {"application": app or provider, "details": details,
                "_summary": f"{base['description']}: {(app or provider)[:120]}"}

    def _h_evt_print(self, eid, d, base, provider):
        rec = {"document": g(d, "Param2"), "user": g(d, "Param3"), "computer_name": g(d, "Param4"),
               "printer": g(d, "Param5"), "port": g(d, "Param6"), "size": g(d, "Param7"), "pages": g(d, "Param8")}
        rec["_summary"] = f"Printed '{rec['document']}' on {rec['printer']} ({rec['pages']} pages) by {rec['user']}"
        return rec

    def _h_evt_optical(self, eid, d, base, provider):
        if provider.lower() != "cdrom":
            return False  # event 133 is used by other providers too
        dev = g(d, "Data0", "DeviceName", default="")
        return {"device": dev, "details": f"cdrom event {eid} on {dev}",
                "_summary": f"Optical disc written: cdrom event {eid} ({dev})"}

    def _h_evt_share(self, eid, d, base, provider):
        rec = {"share": g(d, "ShareName"), "path": g(d, "RelativeTargetName", "ShareLocalPath", "ServerName"),
               "user": g(d, "SubjectUserName", "UserName"), "source_ip": g(d, "IpAddress", "ClientName", "Address")}
        rec["_summary"] = f"{base['description']}: {rec['share']} {rec['path']} by {rec['user']}"
        return rec

    def _h_evt_file_access(self, eid, d, base, provider):
        obj = g(d, "ObjectName")
        if eid in (4663, 4656) and g(d, "ObjectType") not in ("File", ""):
            return False
        rec = {"object": obj, "process": g(d, "ProcessName"), "user": g(d, "SubjectUserName"),
               "access": g(d, "AccessList", "AccessMask"), "handle": g(d, "HandleId")}
        rec["_summary"] = f"{base['description']}: {obj} by {rec['user']} via {rec['process']}"
        return rec

    def _h_evt_sysmon(self, eid, d, base, provider):
        if eid == 10 and "lsass" not in str(g(d, "TargetImage")).lower():
            return False
        target = g(d, "TargetFilename", "TargetObject", "QueryName", "DestinationIp", "TargetImage", "ImageLoaded")
        if eid == 3:
            target = f"{g(d, 'DestinationIp')}:{g(d, 'DestinationPort')} ({g(d, 'DestinationHostname')})"
        if eid == 15:
            target = f"{g(d, 'TargetFilename')} | {g(d, 'Contents')}"
        rec = {"image": g(d, "Image", "SourceImage"), "target": target, "user": g(d, "User"),
               "details": g(d, "Details", "QueryResults", "Hashes", "CommandLine")}
        rec["_summary"] = f"Sysmon {eid} {base['description']}: {rec['image']} -> {target}"
        return rec

    def _h_evt_persistence(self, eid, d, base, provider):
        name = g(d, "RuleName", "ObjectName", "Consumer", "Name", "PossibleCause", "Operation", "ESS", "Data0")
        details = "; ".join(f"{k}={v}" for k, v in d.items() if v not in (None, "", "-"))[:1500]
        return {"name": name, "details": details, "_summary": f"{base['description']}: {name}"}

    def _h_usb_event(self, eid, d, base, provider):
        ch = base["channel"].lower()
        rec: dict = {"event": "", "vendor": "", "product": "", "serial": "", "details": ""}
        if "partition/diagnostic" in ch:
            cap = int(g(d, "Capacity", default="0") or 0)
            rec.update(event="connected" if cap else "disconnected", vendor=g(d, "Manufacturer"), product=g(d, "Model"),
                       serial=g(d, "SerialNumber"), revision=g(d, "Revision"), capacity=cap, disk_number=g(d, "DiskNumber"),
                       bus_type=BUS_TYPES.get(int(g(d, "BusType", default="0") or 0), g(d, "BusType")),
                       parent_id=g(d, "ParentId"), disk_id=g(d, "DiskId"), partition_style=g(d, "PartitionStyle"),
                       partition_count=g(d, "PartitionCount"))
            pid = parse_instance_id(rec["parent_id"])
            rec.update({k: v for k, v in pid.items() if k in ("vid", "pid")})
            vols = []
            for i in range(4):
                vbr = decode_hex_field(d.get(f"Vbr{i}"))
                if vbr:
                    info = parse_vbr(vbr)
                    if info:
                        vols.append(info)
            if vols:
                rec["volumes"] = vols
            bits = [f"capacity {cap / 1e9:.2f} GB" if cap else "removed", f"bus {rec['bus_type']}"]
            for v in vols:
                bits.append(f"{v.get('fs')} VSN {v.get('serial_dashed', v.get('serial'))}" + (f" label '{v['label']}'" if v.get("label") else ""))
            rec["details"] = ", ".join(bits)
            if rec["bus_type"] not in ("USB", "SD", "MMC", "IEEE 1394") and not vols:
                rec["_tags"] = ["internal_disk"]
        elif "kernel-pnp" in ch:
            inst = g(d, "DeviceInstanceId")
            if not re.search(r"usbstor|usb\\|scsi\\disk|wpdbusenum|storage\\volume|swd\\|sd\\|mtp|bth", inst, re.I):
                return False
            info = parse_instance_id(inst)
            rec.update(event={400: "configured", 410: "started", 420: "deleted", 430: "needs install"}.get(eid, str(eid)),
                       vendor=info.get("vendor", ""), product=info.get("product", ""), serial=info.get("serial", ""),
                       instance_id=inst, vid=info.get("vid"), pid=info.get("pid"),
                       details=f"{inst} driver={g(d, 'DriverName')} parent={g(d, 'ParentDeviceInstanceId')}")
        elif "driverframeworks" in ch:
            inst = g(d, "InstanceId", "DeviceInstanceId", "Data0")
            info = parse_instance_id(inst)
            rec.update(event={2003: "connected", 2100: "pnp", 2101: "pnp", 2105: "request", 2106: "request"}.get(eid, "umdf"),
                       vendor=info.get("vendor", ""), product=info.get("product", ""), serial=info.get("serial", ""),
                       instance_id=inst, details=inst)
        elif "storsvc" in ch:
            rec.update(event="device info", vendor=g(d, "Vendor", "VendorId"), product=g(d, "Product", "ProductId"),
                       serial=g(d, "SerialNumber"), details="; ".join(f"{k}={v}" for k, v in d.items() if v)[:600])
        elif "devicesetupmanager" in ch:
            rec.update(event="setup completed", product=g(d, "Prop_DeviceName", "DeviceName"),
                       details="; ".join(f"{k}={v}" for k, v in d.items() if v)[:600])
            info = parse_instance_id(g(d, "Prop_ContainerId") + " " + " ".join(str(v) for v in d.values()))
            rec["serial"] = info.get("serial", "")
        elif "ntfs" in ch:
            rec.update(event="ntfs volume", product=g(d, "VolumeName", "DriveName", "VolumeCorrelationId"),
                       details="; ".join(f"{k}={v}" for k, v in d.items() if v)[:600])
            if not re.search(r"usb|removable|\\device\\harddiskvolume", rec["details"], re.I) and eid != 98:
                return False
        elif "vhdmp" in ch:
            f = g(d, "VhdFileName", "VhdFile", "FileName", "Data0")
            rec.update(event="virtual disk", product=f, details=f"{base['description']}: {f}")
            rec["_tags"] = ["virtual_disk"]
        elif ch == "security":
            ids = g(d, "DeviceId", "DeviceDescription")
            info = parse_instance_id(" ".join(str(v) for v in d.values()))
            rec.update(event="recognized", product=g(d, "DeviceDescription"), vendor=info.get("vendor", ""),
                       serial=info.get("serial", ""), details=f"{ids} class={g(d, 'ClassName')}")
        elif ch == "system":
            clean = {k: v for k, v in d.items() if v not in (None, "") and "xmlns" not in k.lower()
                     and not str(v).startswith(("http://schemas.microsoft.com", "http://manifests.microsoft.com"))}
            inst = g(clean, "DeviceInstanceID", "DeviceInstanceId", "DeviceInstance")
            text = inst or " ".join(str(v) for v in clean.values())
            if not re.search(r"usbstor|usb\\|wpdbusenum|vid_", text, re.I):
                return False
            info = parse_instance_id(text)
            extra = "; ".join(f"{k}={clean[k]}" for k in ("DriverName", "ServiceName", "SetupClass", "InstallStatus",
                                                          "AddServiceStatus", "DriverProvider") if clean.get(k))
            rec.update(event={20001: "driver install", 20003: "service added"}.get(eid, "driver install"),
                       vendor=info.get("vendor", ""), product=info.get("product", ""), serial=info.get("serial", ""),
                       instance_id=inst, details=(f"{inst}  {extra}" if inst else text)[:600])
        rec["_summary"] = f"{base['description']}: {rec.get('vendor', '')} {rec.get('product', '')} {rec.get('serial', '')}".strip()
        return rec

    # ------------------------------------------------------------------ powershell 4104 reassembly
    def _ps_block(self, ctx, ts, out, src) -> bool:
        bid = out.get("script_block_id") or f"r{out.get('record_id')}"
        total = int(out.get("message_total") or 1)
        ent = self.ps_blocks.setdefault(bid, {"parts": {}, "ts": ts, "out": out, "src": src})
        ent["parts"][int(out.get("message_number") or 1)] = out.get("script") or ""
        if ts and (ent["ts"] is None or ts < ent["ts"]):
            ent["ts"] = ts
        if len(ent["parts"]) >= total:
            self._emit_ps(ctx, bid)
        return True

    def _emit_ps(self, ctx, bid) -> None:
        ent = self.ps_blocks.pop(bid)
        script = "".join(ent["parts"][k] for k in sorted(ent["parts"]))
        out = dict(ent["out"])
        out["script"] = script[:200_000]
        out["script_length"] = len(script)
        out["parts"] = len(ent["parts"])
        sc = score_command(script)
        out["score"] = sc["score"]
        out["indicators"] = ", ".join(m["title"] for m in sc["matches"])
        out["mitre"] = sc["mitre"]
        first = script.strip().splitlines()[0][:160] if script.strip() else ""
        ctx.emit("evt_powershell", ent["ts"], out, summary=f"Script block: {first}", source=ent["src"],
                 ts_label="Event time", tags=["suspicious"] if sc["score"] >= 6 else None)

    def _flush_ps(self, ctx) -> None:
        for bid in list(getattr(self, "ps_blocks", {}).keys()):
            self._emit_ps(ctx, bid)


def _nice_channel(c: str) -> str:
    return "/".join(w if w.isupper() else w.title().replace("Microsoft-Windows-", "") for w in c.split("/"))


def _size(p) -> int:
    try:
        return p.stat().st_size
    except Exception:
        return 0
