"""System information, local accounts (SAM), networks and installed software."""

from __future__ import annotations

import struct
from datetime import datetime

from ..core.timeutil import UTC, db_ts, filetime, unix
from ._regutil import iter_keys, key_user, subkeys, ts_of, val
from .base import ArtifactModule, ArtifactType, C, register

ACB_FLAGS = {
    0x0001: "Disabled", 0x0002: "Home dir required", 0x0004: "Password not required", 0x0010: "Normal account",
    0x0040: "Workstation trust", 0x0080: "Server trust", 0x0200: "Password does not expire", 0x0400: "Auto locked",
}


def systemtime(data) -> datetime | None:
    """SYSTEMTIME (16 bytes) as stored by NetworkList (local time, returned naive)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16:
        return None
    y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", bytes(data[:16]))
    try:
        return datetime(y, mo, d, h, mi, s, ms * 1000)
    except ValueError:
        return None


@register
class SystemInfoModule(ArtifactModule):
    id = "system"
    title = "System information & accounts"
    category = "System Information"
    description = "OS build, time zone, shutdown time, local accounts (SAM), network profiles, interfaces, installed software."
    weight = 2.0
    locations = ["SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SYSTEM\\...\\TimeZoneInformation",
                 "SAM\\Domains\\Account\\Users", "SOFTWARE\\...\\NetworkList", "SYSTEM\\...\\Tcpip\\Parameters\\Interfaces",
                 "SOFTWARE\\...\\Uninstall", "NTUSER\\...\\Uninstall"]
    artifact_types = [
        ArtifactType("sys_info", "System Information", "System Information",
                     [C("property", width=180), C("value", width=420), C("source", width=300)]),
        ArtifactType("user_account", "Local User Accounts", "Users & Accounts",
                     [C("name"), C("rid", "RID", "int"), C("sid", "SID"), C("full_name"), C("created", kind="datetime"),
                      C("last_logon", kind="datetime"), C("password_last_set", kind="datetime"),
                      C("last_failed_logon", kind="datetime"), C("logon_count", kind="int"), C("flags"), C("comment")],
                     ts_label="Last logon"),
        ArtifactType("network_profile", "Network Profiles (Wi-Fi / LAN)", "Network",
                     [C("profile_name"), C("description"), C("type"), C("category"), C("first_connected_local", "First Connected (local)"),
                      C("last_connected_local", "Last Connected (local)"), C("gateway_mac", "Gateway MAC"), C("dns_suffix", "DNS Suffix")],
                     ts_label="Last connected"),
        ArtifactType("network_interface", "Network Interfaces", "Network",
                     [C("interface"), C("ip_address", "IP Address"), C("dhcp_server", "DHCP Server"), C("gateway"),
                      C("domain"), C("lease_obtained", kind="datetime"), C("lease_expires", kind="datetime")]),
        ArtifactType("installed_program", "Installed Programs", "System Information",
                     [C("name", width=260), C("version"), C("publisher"), C("install_date"), C("install_location", kind="path"),
                      C("key_modified", kind="datetime"), C("scope")], ts_label="Key last written"),
    ]

    def run(self, ctx) -> None:
        reg = ctx.target.registry
        self._sysinfo(ctx, reg)
        ctx.progress(0.2)
        self._sam(ctx, reg)
        ctx.progress(0.45)
        self._networks(ctx, reg)
        ctx.progress(0.7)
        self._programs(ctx, reg)
        ctx.progress(1.0)

    # ----------------------------------------------------------------- system info
    def _sysinfo(self, ctx, reg) -> None:
        osd = ctx.evidence.get("os") or {}
        rows = [
            ("Computer name", osd.get("computer_name") or osd.get("hostname"), "SYSTEM\\ControlSet\\Control\\ComputerName"),
            ("Operating system", osd.get("product_name"), "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName"),
            ("Version", osd.get("display_version"), "SOFTWARE\\...\\CurrentVersion\\DisplayVersion"),
            ("Build", osd.get("build"), "SOFTWARE\\...\\CurrentVersion\\CurrentBuild + UBR"),
            ("Edition", osd.get("edition"), "SOFTWARE\\...\\CurrentVersion\\EditionID"),
            ("Registered owner", osd.get("registered_owner"), "SOFTWARE\\...\\CurrentVersion\\RegisteredOwner"),
            ("Registered organization", osd.get("registered_org"), "SOFTWARE\\...\\CurrentVersion\\RegisteredOrganization"),
            ("Install date (UTC)", osd.get("install_date"), "SOFTWARE\\...\\CurrentVersion\\InstallDate"),
            ("Time zone", osd.get("timezone_name"), "SYSTEM\\...\\TimeZoneInformation\\TimeZoneKeyName"),
            ("Time zone (IANA)", osd.get("timezone_iana"), "derived"),
            ("Last shutdown (UTC)", osd.get("last_shutdown"), "SYSTEM\\...\\Control\\Windows\\ShutdownTime"),
            ("Domain", osd.get("domain"), "SYSTEM / SECURITY"),
        ]
        for k in ("ProductId", "BuildLab", "PathName"):
            v = val_path(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", k)
            if v:
                rows.append((k, v, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"))
        lastuser = val_path(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI",
                            "LastLoggedOnUser")
        if lastuser:
            rows.append(("Last logged on user", lastuser, "SOFTWARE\\...\\Authentication\\LogonUI"))
        prof = val_path(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles")
        if prof:
            rows.append(("Paging files", " | ".join(prof) if isinstance(prof, list) else prof,
                         "SYSTEM\\...\\Memory Management\\PagingFiles"))
        clear = val_path(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                         "ClearPageFileAtShutdown")
        if clear is not None:
            rows.append(("ClearPageFileAtShutdown", str(clear), "SYSTEM\\...\\Memory Management"))
        hib = val_path(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power", "HibernateEnabled")
        if hib is not None:
            rows.append(("HibernateEnabled", str(hib), "SYSTEM\\...\\Control\\Power"))
        for name, value, src in rows:
            if value in (None, ""):
                continue
            ctx.emit("sys_info", None, {"property": name, "value": str(value), "source": src},
                     summary=f"{name}: {value}", source=src)
        ctx.coverage("System information", "SOFTWARE / SYSTEM hives", "found" if rows else "not_found", len(rows))

    # ----------------------------------------------------------------- SAM
    def _sam(self, ctx, reg) -> None:
        base = "HKLM\\SAM\\SAM\\Domains\\Account\\Users"
        try:
            users_key = reg.key(base)
        except Exception:
            try:
                ctx.target.registry.key(r"HKLM\SAM")
                ctx.coverage("Local accounts", r"SAM\Domains\Account\Users", "not_found", 0, "SAM hive has no user keys")
            except Exception:
                ctx.coverage("Local accounts", "SAM hive", "absent", 0, "SAM hive not available")
            return
        names = {}
        try:
            for nk in subkeys(users_key.subkey("Names")):
                try:
                    rid = nk.value("(default)").type
                except Exception:
                    rid = None
                if rid is None:
                    try:
                        rid = list(nk.values())[0].type
                    except Exception:
                        rid = None
                names[rid] = (nk.name, ts_of(nk))
        except Exception:
            pass
        sids = {}
        for p in ctx.user_profiles():
            if p.get("sid"):
                sids[p["sid"].rsplit("-", 1)[-1]] = p["sid"]
        n = 0
        for k in subkeys(users_key):
            if k.name.lower() == "names":
                continue
            try:
                rid = int(k.name, 16)
            except ValueError:
                continue
            f = val(k, "F")
            v = val(k, "V")
            rec = {"rid": rid, "name": None, "full_name": None, "comment": None}
            if isinstance(v, (bytes, bytearray)) and len(v) > 0xCC:
                rec["name"] = _v_string(v, 0x0C)
                rec["full_name"] = _v_string(v, 0x18)
                rec["comment"] = _v_string(v, 0x24)
            if isinstance(f, (bytes, bytearray)) and len(f) >= 0x44:
                fb = bytes(f)
                rec["last_logon"] = db_ts(filetime(struct.unpack_from("<Q", fb, 0x08)[0]))
                rec["password_last_set"] = db_ts(filetime(struct.unpack_from("<Q", fb, 0x18)[0]))
                rec["last_failed_logon"] = db_ts(filetime(struct.unpack_from("<Q", fb, 0x28)[0]))
                acb = struct.unpack_from("<H", fb, 0x38)[0]
                rec["flags"] = ", ".join(t for b, t in ACB_FLAGS.items() if acb & b)
                rec["failed_count"] = struct.unpack_from("<H", fb, 0x40)[0]
                rec["logon_count"] = struct.unpack_from("<H", fb, 0x42)[0]
            if rid in names:
                rec["name"] = rec["name"] or names[rid][0]
                rec["created"] = db_ts(names[rid][1])
            rec["sid"] = sids.get(str(rid))
            ctx.emit("user_account", rec.get("last_logon"), rec, user=rec["name"],
                     summary=f"Account {rec['name']} (RID {rid}) logons={rec.get('logon_count')}",
                     source=f"SAM\\Domains\\Account\\Users\\{k.name}", ts_label="Last logon")
            n += 1
        ctx.coverage("Local accounts", "SAM\\Domains\\Account\\Users", "found" if n else "not_found", n)

    # ----------------------------------------------------------------- networks
    def _networks(self, ctx, reg) -> None:
        n = 0
        sigs = {}
        for kind in ("Managed", "Unmanaged"):
            for k in iter_keys(reg, f"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\{kind}"):
                for s in subkeys(k):
                    guid = val(s, "ProfileGuid")
                    if guid:
                        mac = val(s, "DefaultGatewayMac")
                        sigs[guid.lower()] = {
                            "gateway_mac": ":".join(f"{b:02X}" for b in bytes(mac)) if isinstance(mac, (bytes, bytearray)) else None,
                            "dns_suffix": val(s, "DnsSuffix"), "first_network": val(s, "FirstNetwork"), "managed": kind,
                        }
        for k in iter_keys(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"):
            for p in subkeys(k):
                first = systemtime(val(p, "DateCreated"))
                last = systemtime(val(p, "DateLastConnected"))
                nametype = val(p, "NameType")
                sig = sigs.get(p.name.lower(), {})
                rec = {
                    "profile_name": val(p, "ProfileName"), "description": val(p, "Description"),
                    "type": {0x47: "Wireless", 0x06: "Wired", 0x17: "Broadband (3G/4G)", 0xF3: "Mobile"}.get(nametype, str(nametype)),
                    "category": {0: "Public", 1: "Private", 2: "Domain"}.get(val(p, "Category"), str(val(p, "Category"))),
                    "first_connected_local": first.strftime("%Y-%m-%d %H:%M:%S") if first else None,
                    "last_connected_local": last.strftime("%Y-%m-%d %H:%M:%S") if last else None,
                    "guid": p.name, **sig,
                }
                ts = None
                if last:
                    ts = last.replace(tzinfo=ctx.evidence_tz).astimezone(UTC) if ctx.evidence_tz else last.replace(tzinfo=UTC)
                ctx.emit("network_profile", ts, rec, summary=f"Network '{rec['profile_name']}' ({rec['type']})",
                         source=f"NetworkList\\Profiles\\{p.name}", ts_label="Last connected")
                n += 1
        ctx.coverage("Network profiles", "SOFTWARE\\...\\NetworkList\\Profiles", "found" if n else "not_found", n)
        m = 0
        for k in iter_keys(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"):
            for i in subkeys(k):
                ip = val(i, "DhcpIPAddress") or val(i, "IPAddress")
                if isinstance(ip, list):
                    ip = ", ".join(x for x in ip if x)
                if not ip or ip == "0.0.0.0":
                    continue
                gw = val(i, "DhcpDefaultGateway") or val(i, "DefaultGateway")
                if isinstance(gw, list):
                    gw = ", ".join(gw)
                lo, le = val(i, "LeaseObtainedTime"), val(i, "LeaseTerminatesTime")
                rec = {"interface": i.name, "ip_address": ip, "dhcp_server": val(i, "DhcpServer"), "gateway": gw,
                       "domain": val(i, "DhcpDomain") or val(i, "Domain"),
                       "lease_obtained": db_ts(unix(lo)) if lo else None, "lease_expires": db_ts(unix(le)) if le else None}
                ctx.emit("network_interface", rec["lease_obtained"], rec, summary=f"Interface {ip}",
                         source=f"Tcpip\\Parameters\\Interfaces\\{i.name}")
                m += 1
        ctx.coverage("Network interfaces", "SYSTEM\\...\\Tcpip\\Parameters\\Interfaces", "found" if m else "not_found", m)

    # ----------------------------------------------------------------- programs
    def _programs(self, ctx, reg) -> None:
        n = 0
        for path, scope in [("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "machine"),
                            ("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "machine (x86)"),
                            ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "user")]:
            for k in iter_keys(reg, path):
                user = key_user(reg, k) if scope == "user" else None
                for p in subkeys(k):
                    name = val(p, "DisplayName")
                    if not name:
                        continue
                    rec = {"name": name, "version": val(p, "DisplayVersion"), "publisher": val(p, "Publisher"),
                           "install_date": val(p, "InstallDate"), "install_location": val(p, "InstallLocation"),
                           "uninstall": val(p, "UninstallString"), "key_modified": db_ts(ts_of(p)),
                           "scope": scope + (f" ({user})" if user else ""), "key": p.name}
                    ctx.emit("installed_program", ts_of(p), rec, user=user, summary=f"Installed: {name}",
                             source=f"{path}\\{p.name}", ts_label="Key last written")
                    n += 1
        ctx.coverage("Installed programs", "Uninstall keys (machine + user)", "found" if n else "not_found", n)


def val_path(reg, path: str, name: str):
    try:
        return reg.key(path).value(name).value
    except Exception:
        return None


def _v_string(v: bytes, entry: int) -> str | None:
    try:
        off, ln = struct.unpack_from("<II", v, entry)
        start = 0xCC + off
        return bytes(v[start:start + ln]).decode("utf-16-le", "replace") or None
    except Exception:
        return None
