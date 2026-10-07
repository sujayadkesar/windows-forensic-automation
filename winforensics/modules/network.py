"""Network configuration artifacts: Wi-Fi profiles, hosts file, proxy settings, VPN phonebooks, RDP cache presence."""

from __future__ import annotations

import re

from ._regutil import iter_keys, key_user, ts_of, val
from .base import ArtifactModule, ArtifactType, C, register


@register
class NetworkModule(ArtifactModule):
    id = "network"
    title = "Network configuration"
    category = "Network"
    description = "Wi-Fi profiles (SSID, authentication), hosts file entries, proxy / PAC settings, VPN phonebooks."
    weight = 0.8
    order = 40
    requires = ["filesystem"]
    locations = ["C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\*\\*.xml", "C:\\Windows\\System32\\drivers\\etc\\hosts",
                 "NTUSER\\...\\Internet Settings", "AppData\\Roaming\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk"]
    artifact_types = [
        ArtifactType("wifi_profile", "Wi-Fi Profiles", "Network",
                     [C("ssid", "SSID", width=220), C("authentication"), C("encryption"), C("connection_mode"),
                      C("file_created", "Profile Created", "datetime"), C("file_modified", kind="datetime"), C("interface", width=260)],
                     ts_label="Profile created"),
        ArtifactType("net_config", "Network Settings (hosts / proxy / VPN)", "Network",
                     [C("kind"), C("name", width=260), C("value", width=420), C("user"), C("source", width=280)]),
    ]

    def run(self, ctx) -> None:
        n = 0
        for row in ctx.fs_files("lower(path) LIKE '\\programdata\\microsoft\\wlansvc\\profiles\\interfaces\\%' AND ext='xml'"):
            try:
                text = ctx.read_entry(row).decode("utf-8", "replace")
            except Exception:
                continue

            def tag(t):
                m = re.search(rf"<{t}>(.*?)</{t}>", text, re.S)
                return m.group(1).strip() if m else ""

            ssid = tag("name")
            m = re.search(r"<SSID>.*?<name>(.*?)</name>", text, re.S)
            ssid = m.group(1) if m else ssid
            ctx.emit("wifi_profile", row.get("si_created"), {
                "ssid": ssid, "authentication": tag("authentication"), "encryption": tag("encryption"),
                "connection_mode": tag("connectionMode"), "file_created": row.get("si_created"), "file_modified": row.get("si_modified"),
                "interface": row["path"].split("\\")[-2]}, summary=f"Wi-Fi profile {ssid}", ts_label="Profile created",
                source=ctx.display_path(row["volume"], row["path"]))
            n += 1
        ctx.coverage("Wi-Fi profiles", "ProgramData\\Microsoft\\Wlansvc\\Profiles", "found" if n else "not_found", n)
        m = 0
        hosts = ctx.path("C:/Windows/System32/drivers/etc/hosts")
        if hosts.exists():
            for line in ctx.read_bytes(hosts).decode("utf-8", "replace").splitlines():
                s = line.strip()
                if s and not s.startswith("#") and not re.match(r"^(127\.0\.0\.1|::1)\s+localhost\s*$", s):
                    ctx.emit("net_config", None, {"kind": "hosts entry", "name": s.split()[-1] if s.split() else s, "value": s,
                                                  "source": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
                             summary=f"hosts: {s}", source="C:\\Windows\\System32\\drivers\\etc\\hosts")
                    m += 1
        reg = ctx.target.registry
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"):
            user = key_user(reg, k)
            for name in ("ProxyServer", "AutoConfigURL", "ProxyOverride"):
                v = val(k, name)
                if v:
                    ctx.emit("net_config", ts_of(k), {"kind": "proxy", "name": name, "value": str(v), "user": user,
                                                      "proxy_enabled": val(k, "ProxyEnable"), "source": "NTUSER\\...\\Internet Settings"},
                             user=user, summary=f"Proxy {name}={v}", source="NTUSER\\...\\Internet Settings")
                    m += 1
        for row in ctx.fs_files("lower(name)='rasphone.pbk'"):
            try:
                text = ctx.read_entry(row).decode("utf-8", "replace")
            except Exception:
                continue
            for entry in re.findall(r"^\[(.+?)\]", text, re.M):
                ph = re.search(rf"\[{re.escape(entry)}\][^\[]*?PhoneNumber=(.*)", text, re.S)
                ctx.emit("net_config", row.get("si_modified"), {"kind": "VPN / dial-up", "name": entry,
                                                                "value": ph.group(1).strip() if ph else "",
                                                                "source": ctx.display_path(row["volume"], row["path"])},
                         user=ctx.user_for_path(row["path"]), summary=f"VPN entry {entry}", source=ctx.display_path(row["volume"], row["path"]))
                m += 1
        ctx.coverage("Hosts / proxy / VPN settings", "hosts, Internet Settings, rasphone.pbk", "found" if m else "not_found", m)
