"""USB / removable media device history.

Consolidates every Windows source of removable device evidence into one device
table keyed by serial number, plus a list of connection sessions:

* SYSTEM  Enum\\USBSTOR, Enum\\SCSI, Enum\\USB, Enum\\SWD\\WPDBUSENUM (+ Properties 0064/0065/0066/0067)
* SYSTEM  MountedDevices, DeviceClasses
* SOFTWARE  EMDMgmt (volume serial + label), Windows Portable Devices, Windows Search\\VolumeInfoCache
* NTUSER  MountPoints2 (which user mounted the volume)
* setupapi.dev.log (first install, local time)
* Event logs (collected by the event log module): Partition/Diagnostic 1006, Kernel-PnP 400/410/420,
  DriverFrameworks, Storsvc, Security 6416, System 20001/20003
"""

from __future__ import annotations

import re
import struct
from datetime import datetime

from ..core.timeutil import db_ts, filetime, from_db
from ._regutil import iter_keys, key_user, subkeys, ts_of, val, values
from ._usbutil import (NULL_CONTAINER, VIRTUAL_VENDORS, clean_serial, is_windows_generated, norm_vsn, parse_instance_id,
                       serial_key)
from .base import ArtifactModule, ArtifactType, C, register

DEVPROP = "{83da6326-97a6-4088-9453-a1923f573b29}"
PROP_NAMES = {"0064": "first_install", "0065": "install_date", "0066": "last_arrival", "0067": "last_removal"}
RX_SETUPAPI_HDR = re.compile(r">>>\s+\[Device Install[^\]]*?-\s*(?P<inst>[^\]]+)\]", re.I)
RX_SETUPAPI_START = re.compile(r">>>\s+Section start\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d+))?")
RX_EMD = re.compile(r"#(?P<serial>[^#]+)#\{[0-9a-f-]+\}(?P<label>.*?)_(?P<vsn>\d+)$", re.I)


def _prop_time(inst_key, prop: str):
    for path in (f"Properties\\{DEVPROP}\\{prop}", f"Properties\\{DEVPROP.upper()}\\{prop}"):
        try:
            k = inst_key.subkey(path.split("\\")[0])
            for part in path.split("\\")[1:]:
                k = k.subkey(part)
        except Exception:
            continue
        for v in values(k):
            data = v.value
            if isinstance(data, (bytes, bytearray)) and len(data) >= 8:
                return filetime(struct.unpack("<Q", bytes(data[:8]))[0])
            if isinstance(data, int):
                return filetime(data)
            if isinstance(data, datetime):
                return data
    return None


def _subkey_path(key, path: str):
    k = key
    for part in path.split("\\"):
        k = k.subkey(part)
    return k


@register
class UsbModule(ArtifactModule):
    id = "usb"
    title = "USB & removable media"
    category = "USB & Removable Media"
    description = ("Builds the removable device history (USB mass storage, UAS/SCSI, MTP phones, SD) with first/last "
                   "connection times, drive letters, volume serials/labels, users and connection sessions.")
    weight = 2.0
    order = 40
    requires = ["eventlogs"]
    locations = ["SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "SYSTEM\\CurrentControlSet\\Enum\\USB",
                 "SYSTEM\\CurrentControlSet\\Enum\\SCSI", "SYSTEM\\CurrentControlSet\\Enum\\SWD\\WPDBUSENUM",
                 "SYSTEM\\MountedDevices", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt",
                 "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices", "SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache",
                 "NTUSER.DAT\\...\\Explorer\\MountPoints2", "C:\\Windows\\INF\\setupapi.dev*.log"]
    artifact_types = [
        ArtifactType("usb_device", "USB / Removable Devices", "USB & Removable Media",
                     [C("vendor"), C("product"), C("serial", width=190), C("device_class", "Class"),
                      C("friendly_name", width=200), C("vid_pid", "VID:PID"), C("first_seen", kind="datetime"),
                      C("last_connected", kind="datetime"), C("connected_after_boot", "Connected After Last Reboot", "datetime"),
                      C("last_removed", kind="datetime"), C("connections", kind="int"),
                      C("drive_letter", "Drive"), C("volume_label", "Volume Label"), C("volume_serial", "Volume Serial"),
                      C("volume_guid", "Volume GUID", width=280), C("users"), C("capacity_gb", "Capacity (GB)"),
                      C("sources", width=300)], ts_label="Last connected / connected after last reboot"),
        ArtifactType("usb_session", "USB Connection Sessions", "USB & Removable Media",
                     [C("connected", kind="datetime"), C("disconnected", kind="datetime"), C("duration"),
                      C("vendor"), C("product"), C("serial", width=190), C("volume_serial", "Volume Serial"),
                      C("volume_label", "Volume Label"), C("source", width=240)], ts_label="Connected"),
        ArtifactType("usb_mountpoint", "User Mounted Volumes (MountPoints2)", "USB & Removable Media",
                     [C("user"), C("volume", width=300), C("key_last_written", "Last Mounted", "datetime"), C("kind"),
                      C("device", width=300)], ts_label="Key last written"),
        ArtifactType("volume_info_cache", "Windows Search VolumeInfoCache", "USB & Removable Media",
                     [C("drive_letter", "Drive"), C("volume_label", "Volume Label"), C("drive_type", "Drive Type"),
                      C("key_last_written", kind="datetime"), C("device", width=320)], ts_label="Key last written"),
        ArtifactType("mounted_device", "MountedDevices", "USB & Removable Media",
                     [C("name", width=260), C("kind"), C("device", width=420), C("serial", width=180)]),
    ]

    def run(self, ctx) -> None:
        reg = ctx.target.registry
        self.dev: dict[str, dict] = {}
        self.events: list[tuple] = []
        self._enum(ctx, reg)
        ctx.progress(0.2)
        self._device_classes(ctx, reg)
        self._mounted(ctx, reg)
        self._emd(ctx, reg)
        self._wpd(ctx, reg)
        ctx.progress(0.4)
        self._mountpoints(ctx, reg)
        self._setupapi(ctx)
        self._volume_info_cache(ctx)
        ctx.progress(0.6)
        self._event_logs(ctx)
        ctx.progress(0.8)
        self._emit(ctx)
        ctx.progress(1.0)

    # ------------------------------------------------------------------ helpers
    def _device(self, serial: str, **fields) -> dict:
        k = serial_key(serial)
        d = self.dev.setdefault(k, {"serial": clean_serial(serial), "sources": set(), "users": set(), "drive_letters": set(),
                                    "volume_guids": set(), "volume_serials": set(), "volume_labels": set(),
                                    "connect_times": set(), "remove_times": set(), "instance_ids": set()})
        for key, v in fields.items():
            if v in (None, "", set()):
                continue
            if key in ("sources", "users", "drive_letters", "volume_guids", "volume_serials", "volume_labels",
                       "connect_times", "remove_times", "instance_ids"):
                d[key] |= set(v) if isinstance(v, (set, list, tuple)) else {v}
            elif key in ("first_install", "install_date", "first_seen"):
                d[key] = min(filter(None, [d.get(key), v]))
            elif key in ("last_arrival", "last_removal", "last_seen"):
                d[key] = max(filter(None, [d.get(key), v]))
            elif not d.get(key):
                d[key] = v
        return d

    def _event(self, ts, event, d: dict, source: str, details: str = "") -> None:
        if ts:
            self.events.append((ts, event, d, source, details))

    # ------------------------------------------------------------------ Enum keys
    def _enum(self, ctx, reg) -> None:
        n = 0
        for enum_name, cls_default in (("USBSTOR", "USB mass storage"), ("SCSI", "SCSI/UAS storage"), ("SD", "SD card"),
                                       ("STORAGE", "Storage")):
            for root in iter_keys(reg, f"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\{enum_name}"):
                for devk in subkeys(root):
                    if enum_name == "SCSI" and not re.search(r"ven_", devk.name, re.I):
                        continue
                    if enum_name == "STORAGE" and not devk.name.lower().startswith("volume"):
                        continue
                    for inst in subkeys(devk):
                        instance = f"{enum_name}\\{devk.name}\\{inst.name}"
                        info = parse_instance_id(instance)
                        if enum_name == "STORAGE":
                            continue
                        serial = info.get("serial") or inst.name
                        container = str(val(inst, "ContainerID") or "").lower()
                        if enum_name == "SCSI" and (not container or container == NULL_CONTAINER
                                                    or (info.get("vendor") or "").lower().startswith(VIRTUAL_VENDORS)):
                            continue  # internal / virtual SCSI disk; USB attached SCSI (UAS) devices carry a real container id
                        friendly = val(inst, "FriendlyName") or val(inst, "DeviceDesc") or ""
                        friendly = friendly.split(";")[-1] if isinstance(friendly, str) else str(friendly)
                        times = {name: _prop_time(inst, p) for p, name in PROP_NAMES.items()}
                        disk_id = None
                        try:
                            disk_id = val(_subkey_path(inst, "Device Parameters\\Partmgr"), "DiskId")
                        except Exception:
                            pass
                        if enum_name == "SCSI" and not info.get("vendor"):
                            continue
                        reg_vals = {nm: str(val(inst, nm)) for nm in ("FriendlyName", "DeviceDesc", "ContainerID", "Mfg", "Service")
                                    if val(inst, nm) not in (None, "")}
                        d = self._device(serial, vendor=info.get("vendor"), product=info.get("product"),
                                         revision=info.get("revision"), friendly_name=friendly,
                                         device_class=cls_default if enum_name != "USBSTOR" else
                                         ("USB mass storage" if info.get("device_class", "").lower() == "disk" else
                                          f"USB {info.get('device_class', '')}".strip()),
                                         container_id=val(inst, "ContainerID"), disk_id=disk_id,
                                         first_install=times["first_install"], install_date=times["install_date"],
                                         last_arrival=times["last_arrival"], last_removal=times["last_removal"],
                                         instance_ids={instance}, sources={f"Enum\\{enum_name}"},
                                         serial_generated=is_windows_generated(serial))
                        if instance == next(iter(sorted(d["instance_ids"])), instance) or not d.get("enum_values"):
                            d["enum_values"] = reg_vals
                            d["enum_key"] = instance
                        d["enum_key_ts"] = max(filter(None, [d.get("enum_key_ts"), ts_of(inst)]), default=None)
                        for name, t in times.items():
                            if t:
                                self._event(t, {"first_install": "first install", "install_date": "install",
                                                "last_arrival": "last connected", "last_removal": "last removed"}[name],
                                            d, f"Enum\\{enum_name} Properties {[k for k, v in PROP_NAMES.items() if v == name][0]}")
                        n += 1
        # USB parent devices give VID/PID (serial is the same as the USBSTOR instance when unique)
        for root in iter_keys(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"):
            for devk in subkeys(root):
                m = re.match(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(&MI_\d+)?", devk.name, re.I)
                if not m:
                    continue
                for inst in subkeys(devk):
                    k = serial_key(inst.name)
                    svc = (val(inst, "Service") or "").lower()
                    friendly = val(inst, "FriendlyName") or val(inst, "DeviceDesc") or ""
                    friendly = friendly.split(";")[-1] if isinstance(friendly, str) else ""
                    cls = (val(inst, "Class") or "").lower()
                    mtp = svc in ("wudfrd", "wpdupfltr", "usbccgp") and ("mtp" in str(val(inst, "CompatibleIDs")).lower()
                                                                       or cls == "wpd")
                    times = {name: _prop_time(inst, p) for p, name in PROP_NAMES.items()}
                    if k in self.dev:
                        d = self._device(inst.name, vid=m.group(1).upper(), pid=m.group(2).upper(),
                                         sources={"Enum\\USB"}, first_install=times["first_install"],
                                         last_arrival=times["last_arrival"], last_removal=times["last_removal"],
                                         location=val(inst, "LocationInformation"))
                    elif mtp or cls == "wpd" or svc == "wudfrd":
                        d = self._device(inst.name, vid=m.group(1).upper(), pid=m.group(2).upper(), friendly_name=friendly,
                                         product=friendly, device_class="Portable device (MTP/PTP)",
                                         first_install=times["first_install"], last_arrival=times["last_arrival"],
                                         last_removal=times["last_removal"], sources={"Enum\\USB"},
                                         instance_ids={f"USB\\{devk.name}\\{inst.name}"},
                                         serial_generated=is_windows_generated(inst.name))
                        n += 1
                    else:
                        continue
                    for name, t in times.items():
                        if t:
                            self._event(t, {"first_install": "first install", "install_date": "install",
                                            "last_arrival": "last connected", "last_removal": "last removed"}[name],
                                        d, "Enum\\USB Properties")
        # WPDBUSENUM: friendly name = volume label or drive letter
        for root in iter_keys(reg, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SWD\\WPDBUSENUM"):
            for inst in subkeys(root):
                info = parse_instance_id(inst.name.replace("#", "\\"))
                if not info.get("serial"):
                    continue
                fn = val(inst, "FriendlyName") or ""
                fields = {"sources": {"Enum\\SWD\\WPDBUSENUM"}}
                if re.fullmatch(r"[A-Z]:\\?", fn or "", re.I):
                    fields["drive_letters"] = {fn[0].upper() + ":"}
                elif fn:
                    fields["volume_labels"] = {fn}
                if serial_key(info["serial"]) in self.dev:
                    self._device(info["serial"], **fields)
        ctx.coverage("USB device enumeration", "SYSTEM\\Enum\\USBSTOR, SCSI, USB, SWD\\WPDBUSENUM",
                     "found" if n else "not_found", n)

    # ------------------------------------------------------------------ DeviceClasses (Windows 7 connection after reboot)
    def _device_classes(self, ctx, reg) -> None:
        """Device interface keys are written when the device is first connected after a reboot; reconnecting it during
        the same boot session does not update them. On systems without the Properties 0066 value (Windows 7) this is the
        'connected after the last reboot' time - not necessarily the last connection."""
        n = 0
        for guid in ("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", "{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
                     "{6ac27878-a6fa-4155-ba85-f98f491d4f33}", "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"):
            for root in iter_keys(reg, f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{guid}"):
                for k in subkeys(root):
                    info = parse_instance_id(k.name.replace("#", "\\"))
                    serial = info.get("serial")
                    if not serial or serial_key(serial) not in self.dev:
                        continue
                    ts = ts_of(k)
                    d = self.dev[serial_key(serial)]
                    if ts and (not d.get("deviceclass_ts") or ts > d["deviceclass_ts"]):
                        d["deviceclass_ts"] = ts
                        d["deviceclass_key"] = f"{guid}\\{k.name}"
                        d["deviceclass_instance"] = str(val(k, "DeviceInstance") or "")
                    d["sources"].add("DeviceClasses")
                    n += 1
        for d in self.dev.values():
            if d.get("deviceclass_ts"):
                self._event(d["deviceclass_ts"], "connected after the last reboot (DeviceClasses key last written)", d,
                            "SYSTEM\\Control\\DeviceClasses")
        ctx.coverage("DeviceClasses (interface keys)", "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses",
                     "found" if n else "not_found", n)

    # ------------------------------------------------------------------ MountedDevices
    def _mounted(self, ctx, reg) -> None:
        n = 0
        self.guid_to_serial: dict[str, str] = {}
        self.guid_to_sig: dict[str, tuple] = {}
        self.letter_sig: dict[str, tuple] = {}
        entries, seen = [], set()
        for k in iter_keys(reg, "HKLM\\SYSTEM\\MountedDevices"):
            for v in values(k):
                if isinstance(v.value, (bytes, bytearray)) and (v.name, bytes(v.value)) not in seen:
                    seen.add((v.name, bytes(v.value)))
                    entries.append((v.name, bytes(v.value)))
        sys_sig = None
        for name, data in entries:
            if name.upper() == "\\DOSDEVICES\\C:" and len(data) == 12:
                sys_sig = struct.unpack("<I", data[:4])[0]
        for name, data in entries:
            external = False
            if data[:8] in (b"_\x00?\x00?\x00_\x00", b"\\\x00?\x00?\x00\\\x00"):
                dev = data.decode("utf-16-le", "replace").rstrip("\x00")
                kind = "device path"
            elif data.startswith(b"DMIO:ID:"):
                dev = "GPT partition " + _guid(data[8:24])
                kind = "GPT partition GUID"
            elif len(data) == 12:
                sig, off = struct.unpack("<IQ", data)
                dev = f"MBR disk signature {sig:08X}, partition offset {off}"
                kind = "MBR signature + offset"
                external = sys_sig is not None and sig != sys_sig
                m = re.search(r"Volume(\{[0-9a-f-]+\})", name, re.I)
                if m:
                    self.guid_to_sig[m.group(1).lower()] = (sig, off)
                m = re.match(r"\\DosDevices\\([A-Z]:)", name, re.I)
                if m:
                    self.letter_sig[m.group(1).upper()] = (sig, off)
            else:
                dev = data[:64].hex()
                kind = "other"
            if kind == "device path" and re.search(r"cdrom", dev, re.I):
                kind = "device path (optical drive)"
            info = parse_instance_id(dev.replace("#", "\\"))
            serial = info.get("serial", "")
            ctx.emit("mounted_device", None, {"name": name, "kind": kind + (" - non-system disk" if external else ""), "device": dev,
                                              "serial": serial, "external": external},
                     summary=f"{name} -> {dev[:120]}", source="SYSTEM\\MountedDevices")
            n += 1
            if serial:
                fields = {"sources": {"MountedDevices"}}
                m = re.match(r"\\DosDevices\\([A-Z]:)", name, re.I)
                if m:
                    fields["drive_letters"] = {m.group(1).upper()}
                m = re.search(r"Volume(\{[0-9a-f-]+\})", name, re.I)
                if m:
                    fields["volume_guids"] = {m.group(1).lower()}
                    self.guid_to_serial[m.group(1).lower()] = serial_key(serial)
                self._device(serial, **fields)
        ctx.coverage("MountedDevices", "SYSTEM\\MountedDevices", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ EMDMgmt / WPD / VolumeInfoCache
    def _emd(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"):
            for e in subkeys(k):
                m = RX_EMD.search(e.name)
                if not m:
                    continue
                serial = clean_serial(m.group("serial"))
                vsn = norm_vsn(int(m.group("vsn")))
                fields = {"sources": {"EMDMgmt"}, "volume_serials": {vsn} if vsn else set()}
                if m.group("label"):
                    fields["volume_labels"] = {m.group("label")}
                if serial_key(serial) in self.dev or "usbstor" in e.name.lower():
                    self._device(serial, **fields)
                n += 1
        ctx.coverage("EMDMgmt (ReadyBoost volume history)", "SOFTWARE\\...\\EMDMgmt", "found" if n else "not_found", n)
        self.vic_entries = []
        seen = set()
        for k in iter_keys(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache"):
            for e in subkeys(k):
                ent = (e.name.upper(), val(e, "VolumeLabel") or "", val(e, "DriveType"), ts_of(e))
                if ent not in seen:
                    seen.add(ent)
                    self.vic_entries.append(ent)

    def _wpd(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"):
            for e in subkeys(k):
                fn = val(e, "FriendlyName")
                info = parse_instance_id(e.name.replace("#", "\\"))
                if not info.get("serial"):
                    continue
                fields = {"sources": {"Windows Portable Devices"}}
                if fn and re.fullmatch(r"[A-Z]:\\?", fn, re.I):
                    fields["drive_letters"] = {fn[0].upper() + ":"}
                elif fn:
                    fields["volume_labels"] = {fn} if serial_key(info["serial"]) in self.dev else set()
                    if serial_key(info["serial"]) not in self.dev:
                        fields.update(friendly_name=fn, product=fn, device_class="Portable device (MTP/PTP)",
                                      vid=info.get("vid"), pid=info.get("pid"))
                self._device(info["serial"], **fields)
                n += 1
        ctx.coverage("Windows Portable Devices", "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices",
                     "found" if n else "not_found", n)

    # ------------------------------------------------------------------ MountPoints2
    def _mountpoints(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"):
            user = key_user(reg, k)
            for e in subkeys(k):
                name = e.name
                ts = ts_of(e)
                correlated = False
                if name.startswith("{"):
                    kind = "volume"
                    serial = self.guid_to_serial.get(name.lower())
                    if not serial and ts and name.lower() in self.guid_to_sig:
                        # fixed-disk style USB volumes (MBR signature in MountedDevices) carry no serial: link the volume to
                        # the one device whose arrival time matches the MountPoints2 key write (within 10 s)
                        cands = [k2 for k2, d2 in self.dev.items()
                                 if any(t and abs((t - ts).total_seconds()) <= 10
                                        for t in [d2.get("deviceclass_ts"), d2.get("last_arrival"), *d2["connect_times"]])]
                        if len(cands) == 1:
                            serial, correlated = cands[0], True
                elif name.startswith("##"):
                    kind = "network share"
                    serial = None
                else:
                    kind = "drive letter"
                    serial = None
                device = ""
                if serial and serial in self.dev:
                    d = self.dev[serial]
                    d["users"].add(user or "?")
                    d["sources"].add("MountPoints2 (time-correlated)" if correlated else "MountPoints2")
                    d.setdefault("user_mounts", []).append((user, ts))
                    if correlated:
                        d["volume_guids"].add(name.lower())
                    device = f"{d.get('vendor', '')} {d.get('product', '')} {d['serial']}".strip() + \
                        (" (linked by arrival time)" if correlated else "")
                    self._event(ts, f"mounted by {user}", d, "NTUSER MountPoints2 key last written")
                ctx.emit("usb_mountpoint", ts, {"user": user, "volume": name.replace("#", "\\") if kind == "network share" else name,
                                                "key_last_written": db_ts(ts), "kind": kind, "device": device},
                         user=user, summary=f"{user} mounted {name} ({kind})", ts_label="Key last written",
                         source="NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
                n += 1
        ctx.coverage("MountPoints2 (per user)", "NTUSER\\...\\Explorer\\MountPoints2", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ setupapi
    def _setupapi(self, ctx) -> None:
        files = ctx.glob("C:/Windows/INF/setupapi.dev*.log") + ctx.glob("C:/Windows/setupapi.log")
        if not files:
            ctx.coverage("setupapi device install log", "C:\\Windows\\INF\\setupapi.dev*.log", "absent", 0)
            return
        n = 0
        for f in files:
            try:
                text = ctx.read_bytes(f).decode("utf-8", "replace")
            except Exception as e:
                ctx.coverage("setupapi device install log", str(f), "error", 0, str(e))
                continue
            cur = None
            for line in text.splitlines():
                m = RX_SETUPAPI_HDR.search(line)
                if m:
                    cur = m.group("inst").strip()
                    continue
                m = RX_SETUPAPI_START.search(line)
                if m and cur:
                    local = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
                    if m.group(2):
                        local = local.replace(microsecond=int(m.group(2).ljust(6, "0")[:6]))
                    utc = ctx.local_to_utc(local)
                    info = parse_instance_id(cur)
                    if info.get("serial") and re.search(r"usbstor|usb\\vid|scsi\\disk|wpdbusenum|sd\\", cur, re.I):
                        known = serial_key(info["serial"]) in self.dev
                        if known or "usbstor" in cur.lower():
                            d = self._device(info["serial"], vendor=info.get("vendor"), product=info.get("product"),
                                             vid=info.get("vid"), pid=info.get("pid"), sources={"setupapi.dev.log"},
                                             setupapi_first_install=utc, instance_ids={cur})
                            if not d.get("setupapi_first_install") or utc < d["setupapi_first_install"]:
                                d["setupapi_first_install"] = utc
                            self._event(utc, "first install (setupapi)", d, f"{f.name} (local time {local})", cur)
                            n += 1
                    cur = None
        ctx.coverage("setupapi device install log", "C:\\Windows\\INF\\setupapi.dev*.log", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ event logs (already parsed)
    def _event_logs(self, ctx) -> None:
        rows = ctx.db.artifacts(ctx.evidence_id, "usb_event", order="ts")
        sessions: dict[str, list] = {}
        for r in rows:
            d = r["data"]
            serial = d.get("serial")
            if not serial:
                continue
            ts = from_db(r["ts"])
            key = serial_key(serial)
            fields = {"sources": {f"EVTX {d.get('channel', '').split('/')[0].replace('Microsoft-Windows-', '')} {d.get('event_id')}"}}
            if d.get("vendor"):
                fields["vendor"] = d["vendor"]
            if d.get("product"):
                fields["product"] = d["product"]
            if d.get("vid"):
                fields.update(vid=d.get("vid"), pid=d.get("pid"))
            vols = d.get("volumes") or []
            for v in vols:
                if v.get("serial_short"):
                    fields.setdefault("volume_serials", set()).add(v["serial_short"])
                if v.get("label"):
                    fields.setdefault("volume_labels", set()).add(v["label"])
                if v.get("fs"):
                    fields["filesystem"] = v["fs"]
            if d.get("capacity"):
                fields["capacity"] = d["capacity"]
            if d.get("bus_type"):
                fields["bus_type"] = d["bus_type"]
            if key not in self.dev:
                # event-only devices: keep storage devices (bus type from Partition/Storsvc or a USBSTOR id), not hubs / HID
                if d.get("bus_type") not in ("USB", "SD", "MMC", "IEEE 1394") and not (d.get("vendor") and d.get("product")):
                    continue
            dev = self._device(serial, first_seen=ts, last_seen=ts, **fields)
            if d.get("event") == "connected" or d.get("event_id") in (2003,):
                dev["connect_times"].add(ts)
                sessions.setdefault(key, []).append(("c", ts, r))
            elif d.get("event") == "disconnected" or d.get("event_id") in (2100, 2102):
                dev["remove_times"].add(ts)
                sessions.setdefault(key, []).append(("d", ts, r))
            elif d.get("event_id") in (400, 410):
                dev["connect_times"].add(ts)
        self.sessions = sessions

    # ------------------------------------------------------------------ VolumeInfoCache
    def _volume_info_cache(self, ctx) -> None:
        """Windows Search keeps one key per drive letter (label, drive type) written when a volume is mounted.  The key
        is linked to a device only when exactly one device arrived within 10 seconds of the key write."""
        types = {0: "unknown", 1: "no root", 2: "removable", 3: "fixed", 4: "network", 5: "optical", 6: "RAM disk"}
        for letter, label, dtype, ts in getattr(self, "vic_entries", []):
            device = ""
            if ts and letter[:1] != "C":
                cands = [k for k, d in self.dev.items()
                         if any(t and abs((t - ts).total_seconds()) <= 10 for t in
                                [d.get("deviceclass_ts"), d.get("last_arrival"), d.get("setupapi_first_install"),
                                 *d["connect_times"]])]
                if len(cands) == 1:
                    d = self.dev[cands[0]]
                    if label:
                        d["volume_labels"].add(label)
                    d["drive_letters"].add(letter.rstrip("\\")[:2])
                    d["sources"].add("VolumeInfoCache (time-correlated)")
                    device = f"{d.get('vendor', '')} {d.get('product', '')} {d['serial']} (linked by arrival time)".strip()
            ctx.emit("volume_info_cache", ts, {"drive_letter": letter, "volume_label": label,
                                               "drive_type": types.get(dtype, str(dtype)), "key_last_written": ts,
                                               "device": device},
                     summary=f"VolumeInfoCache {letter} label '{label}' ({types.get(dtype, dtype)})",
                     source=f"SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache\\{letter}", ts_label="Key last written")
        ctx.coverage("Windows Search VolumeInfoCache", "SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache",
                     "found" if getattr(self, "vic_entries", None) else "not_found", len(getattr(self, "vic_entries", [])))

    # ------------------------------------------------------------------ output
    def _emit(self, ctx) -> None:
        n = 0
        for key, d in sorted(self.dev.items(), key=lambda kv: kv[0]):
            conn = sorted(t for t in d["connect_times"] if t)
            rem = sorted(t for t in d["remove_times"] if t)
            first_candidates = [d.get("first_install"), d.get("setupapi_first_install"), d.get("install_date"),
                                d.get("first_seen")] + conn[:1]
            first = min([t for t in first_candidates if t], default=None)
            # 'last connected' is only stated when a source records the last arrival (Properties 0066, connect events)
            last_conn = max([t for t in [d.get("last_arrival")] + conn if t], default=None)
            last_conn_src = ("Properties 0066" if d.get("last_arrival") and d.get("last_arrival") == last_conn
                             else "event logs") if last_conn else ""
            after_boot = d.get("deviceclass_ts")
            mounts = [t for _u, t in d.get("user_mounts", []) if t]
            last_rem = max([t for t in [d.get("last_removal")] + rem if t], default=None)
            vsns = sorted({norm_vsn(v) for v in d["volume_serials"] if norm_vsn(v)})
            rec = {
                "vendor": d.get("vendor"), "product": d.get("product"), "revision": d.get("revision"), "serial": d["serial"],
                "serial_generated": bool(d.get("serial_generated")), "device_class": d.get("device_class") or "Removable device",
                "friendly_name": d.get("friendly_name"), "vid": d.get("vid"), "pid": d.get("pid"),
                "vid_pid": f"{d['vid']}:{d['pid']}" if d.get("vid") else "",
                "first_seen": db_ts(first), "first_install": db_ts(d.get("first_install")),
                "setupapi_first_install": db_ts(d.get("setupapi_first_install")), "install_date": db_ts(d.get("install_date")),
                "last_connected": db_ts(last_conn), "last_connected_source": last_conn_src,
                "connected_after_boot": db_ts(after_boot), "volume_last_mounted": db_ts(max(mounts)) if mounts else None,
                "last_removed": db_ts(last_rem),
                "connections": len(conn) if conn else (1 if last_conn or after_boot or first else 0),
                "connection_times": [db_ts(t) for t in conn], "removal_times": [db_ts(t) for t in rem],
                "drive_letter": ", ".join(sorted(d["drive_letters"])), "volume_label": ", ".join(sorted(d["volume_labels"])),
                "volume_serial": ", ".join(f"{v[:4]}-{v[4:]}" for v in vsns), "volume_serials": vsns,
                "volume_guid": ", ".join(sorted(d["volume_guids"])), "users": ", ".join(sorted(u for u in d["users"] if u)),
                "user_mounts": [(u, db_ts(t)) for u, t in d.get("user_mounts", [])],
                "capacity": d.get("capacity"), "capacity_gb": f"{d['capacity'] / 1e9:.2f}" if d.get("capacity") else "",
                "filesystem": d.get("filesystem"), "bus_type": d.get("bus_type"), "container_id": d.get("container_id"),
                "disk_id": d.get("disk_id"), "instance_ids": sorted(d["instance_ids"]),
                "prop_first_install": db_ts(d.get("first_install")), "prop_last_arrival": db_ts(d.get("last_arrival")),
                "prop_last_removal": db_ts(d.get("last_removal")), "deviceclass_last_written": db_ts(d.get("deviceclass_ts")),
                "enum_key_last_written": db_ts(d.get("enum_key_ts")), "enum_key": d.get("enum_key"),
                "enum_values": d.get("enum_values") or {}, "deviceclass_key": d.get("deviceclass_key"),
                "deviceclass_instance": d.get("deviceclass_instance"),
                "sources": ", ".join(sorted(d["sources"])),
            }
            label = " ".join(x for x in [rec["vendor"], rec["product"]] if x) or rec["friendly_name"] or "device"
            ctx.emit("usb_device", last_conn or after_boot or first, rec, user=rec["users"] or None,
                     summary=f"{label} S/N {rec['serial']} first connected {rec['first_seen'] or 'unknown'}; "
                             + (f"last connected {rec['last_connected']}" if rec["last_connected"] else
                                f"connected after the last reboot {rec['connected_after_boot']}" if rec["connected_after_boot"]
                                else "no later connection time recorded"),
                     source=rec["sources"], ts_label="Last connected" if last_conn else
                     ("Connected after last reboot" if after_boot else "First connected"))
            n += 1
            # registry derived timeline events (event-log ones were already emitted by the event log module)
            for ts, event, dd, source, details in [e for e in self.events if e[2] is d]:
                ctx.emit("usb_event", ts, {"event": event, "description": f"{event} ({source})", "vendor": rec["vendor"],
                                           "product": rec["product"], "serial": rec["serial"], "details": details or source,
                                           "channel": "registry/setupapi", "derived": True},
                         summary=f"USB {event}: {label} {rec['serial']}", source=source, ts_label="Event time")
            # sessions
            evs = sorted(self.sessions.get(key, []), key=lambda x: x[1])
            i = 0
            while i < len(evs):
                kind, t, r = evs[i]
                if kind == "c":
                    end = None
                    if i + 1 < len(evs) and evs[i + 1][0] == "d":
                        end = evs[i + 1][1]
                        i += 1
                    self._session(ctx, rec, label, t, end, "Partition/Diagnostic 1006" if r["data"].get("event_id") == 1006
                                  else r["data"].get("channel", ""))
                i += 1
            if not evs and (last_conn or after_boot):
                start = last_conn or after_boot
                end = last_rem if last_rem and last_rem >= start else None
                self._session(ctx, rec, label, start, end, f"{last_conn_src} (last session)" if last_conn else
                              "DeviceClasses key last written (first connection after the last reboot)")
        ctx.coverage("USB device history", "Consolidated (registry + setupapi + event logs)", "found" if n else "not_found", n)

    def _session(self, ctx, rec, label, start, end, source) -> None:
        dur = ""
        if start and end:
            s = int((end - start).total_seconds())
            dur = f"{s // 3600}h {(s % 3600) // 60:02d}m {s % 60:02d}s" if s >= 3600 else f"{s // 60}m {s % 60:02d}s"
        ctx.emit("usb_session", start, {"connected": db_ts(start), "disconnected": db_ts(end), "duration": dur,
                                        "vendor": rec["vendor"], "product": rec["product"], "serial": rec["serial"],
                                        "volume_serial": rec["volume_serial"], "volume_label": rec["volume_label"],
                                        "drive_letter": rec["drive_letter"], "source": source},
                 summary=f"{label} {rec['serial']} connected {db_ts(start)} -> {db_ts(end) or 'unknown'}",
                 source=source, ts_label="Connected")


def _guid(b: bytes) -> str:
    if len(b) < 16:
        return b.hex()
    a, b1, c = struct.unpack("<IHH", b[:8])
    return f"{{{a:08x}-{b1:04x}-{c:04x}-{b[8:10].hex()}-{b[10:16].hex()}}}"
