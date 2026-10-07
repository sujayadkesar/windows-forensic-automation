"""A staged Windows machine: file tree + hives + event logs + build manifest."""

from __future__ import annotations

import json
import os
import shutil
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .evtxwriter import Event, write_evtx
from .regwriter import REG_DEVPROP_FILETIME, HiveBuilder


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


class Machine:
    def __init__(self, staging_root: str, name: str, install_time: datetime, disk: dict):
        self.name = name
        self.dir = os.path.join(staging_root, name)
        shutil.rmtree(self.dir, ignore_errors=True)
        self.root = os.path.join(self.dir, "root")
        os.makedirs(self.root)
        self.install_time = install_time
        self.system = HiveBuilder(install_time)
        self.software = HiveBuilder(install_time)
        self.sam = HiveBuilder(install_time)
        self.security = HiveBuilder(install_time)
        self.amcache = HiveBuilder(install_time)
        self.users: dict[str, dict] = {}
        self.events: dict[str, list[Event]] = defaultdict(list)
        self.manifest = {
            "name": name,
            "disk": disk,
            "files": [],  # ordered creation list
            "delete": [],  # (path, time) deleted after creation (unallocated)
            "ads": [],
            "slack": [],
            "timestomp": [],
            "install_time": iso(install_time),
            "inject_after": [],  # raw blobs written into special files
        }

    # ------------------------------------------------------------ files
    def path(self, win_path: str) -> str:
        rel = win_path.replace("C:\\", "").replace("\\", "/")
        return os.path.join(self.root, rel)

    def add_file(
        self,
        win_path: str,
        data: bytes | str,
        ctime: datetime | None = None,
        mtime: datetime | None = None,
        atime: datetime | None = None,
    ) -> str:
        p = self.path(win_path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(p, "wb") as fh:
            fh.write(data)
        self._register(win_path, ctime, mtime, atime)
        return p

    def add_existing(self, win_path: str, src: str, ctime=None, mtime=None, atime=None) -> str:
        p = self.path(win_path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        shutil.copyfile(src, p)
        self._register(win_path, ctime, mtime, atime)
        return p

    def _register(self, win_path, ctime, mtime, atime):
        ctime = ctime or self.install_time
        mtime = mtime or ctime
        atime = atime or mtime
        rel = win_path.replace("C:\\", "").replace("\\", "/")
        self.manifest["files"] = [f for f in self.manifest["files"] if f["path"] != rel]
        self.manifest["files"].append({"path": rel, "ctime": iso(ctime), "mtime": iso(mtime), "atime": iso(atime)})

    def delete_later(self, win_path: str, when: datetime) -> None:
        rel = win_path.replace("C:\\", "").replace("\\", "/")
        self.manifest["delete"].append({"path": rel, "time": iso(when)})

    def add_ads(self, win_path: str, stream: str, data: str) -> None:
        rel = win_path.replace("C:\\", "").replace("\\", "/")
        self.manifest["ads"].append({"path": rel, "stream": stream, "data": data})

    def slack_inject(self, win_path: str, data: bytes) -> None:
        rel = win_path.replace("C:\\", "").replace("\\", "/")
        self.manifest["slack"].append({"path": rel, "data_hex": data.hex()})

    def timestomp(self, win_path: str, fake: datetime) -> None:
        rel = win_path.replace("C:\\", "").replace("\\", "/")
        self.manifest["timestomp"].append({"path": rel, "time": iso(fake)})

    # ------------------------------------------------------------ users
    def add_user(self, username: str, sid: str, created: datetime) -> dict:
        u = {
            "name": username,
            "sid": sid,
            "ntuser": HiveBuilder(created),
            "usrclass": HiveBuilder(created),
            "profile": f"C:\\Users\\{username}",
        }
        self.users[username] = u
        self.software.expand_sz(
            rf"Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", "ProfileImagePath", f"C:\\Users\\{username}"
        )
        self.software.dword(rf"Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", "Flags", 0)
        for d in ["Desktop", "Documents", "Downloads", "Pictures", "AppData\\Local\\Temp",
                  "AppData\\Roaming\\Microsoft\\Windows\\Recent"]:
            os.makedirs(self.path(f"C:\\Users\\{username}\\{d}"), exist_ok=True)
        return u

    def event(self, logfile: str, ev: Event) -> None:
        self.events[logfile].append(ev)

    # ------------------------------------------------------------ USB helper
    def usb_registry(
        self,
        vendor: str,
        product: str,
        rev: str,
        serial: str,
        vid: str,
        pid: str,
        friendly: str,
        first: datetime,
        last_connect: datetime,
        last_removal: datetime,
        volume_guid: str,
        drive_letter: str,
        label: str,
        vsn: int,
        disk_guid: str = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
    ) -> None:
        cs = "ControlSet001"
        dev_class = f"Disk&Ven_{vendor}&Prod_{product}&Rev_{rev}"
        inst = f"{serial}&0"
        k = rf"{cs}\Enum\USBSTOR\{dev_class}\{inst}"
        self.system.key(k, ts=last_connect)
        self.system.sz(k, "FriendlyName", friendly.replace("_", " ") + " USB Device")
        self.system.sz(k, "DeviceDesc", "@disk.inf,%disk_devdesc%;Disk drive")
        self.system.sz(k, "Mfg", "@disk.inf,%genmanufacturer%;(Standard disk drives)")
        self.system.sz(k, "Service", "disk")
        self.system.sz(k, "ContainerID", "{" + volume_guid.strip("{}")[::-1][:8] + "-1111-2222-3333-444455556666}")
        props = rf"{k}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}"
        self.system.set(props + r"\0064", "", REG_DEVPROP_FILETIME, first, ts=first)
        self.system.set(props + r"\0065", "", REG_DEVPROP_FILETIME, first, ts=first)
        self.system.set(props + r"\0066", "", REG_DEVPROP_FILETIME, last_connect, ts=last_connect)
        self.system.set(props + r"\0067", "", REG_DEVPROP_FILETIME, last_removal, ts=last_removal)
        usb = rf"{cs}\Enum\USB\VID_{vid}&PID_{pid}\{serial}"
        self.system.key(usb, ts=last_connect)
        self.system.sz(usb, "DeviceDesc", "@usb.inf,%usb.massstoragedevicedesc%;USB Mass Storage Device")
        self.system.sz(usb, "LocationInformation", "Port_#0002.Hub_#0001")
        self.system.set(rf"{usb}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}\0064", "", REG_DEVPROP_FILETIME, first)
        self.system.set(rf"{usb}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}\0066", "", REG_DEVPROP_FILETIME, last_connect)
        self.system.set(rf"{usb}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}\0067", "", REG_DEVPROP_FILETIME, last_removal)
        dev_path = f"_??_USBSTOR#{dev_class}#{inst}#{disk_guid}"
        wpd = rf"{cs}\Enum\SWD\WPDBUSENUM\{dev_path}"
        self.system.sz(wpd, "FriendlyName", label, ts=last_connect)
        self.system.sz(wpd, "DeviceDesc", label)
        # MountedDevices
        mounted = ("\\" + dev_path.replace("_??_", "??\\")).replace("\\??\\", "_??_").encode("utf-16-le")
        mounted = ("_??_" + dev_path[4:]).encode("utf-16-le")
        self.system.binary("MountedDevices", f"\\DosDevices\\{drive_letter}:", mounted, ts=last_connect)
        self.system.binary("MountedDevices", f"\\??\\Volume{volume_guid}", mounted, ts=last_connect)
        # SOFTWARE: Windows Portable Devices, EMDMgmt, VolumeInfoCache
        wpd_sw = rf"Microsoft\Windows Portable Devices\Devices\SWD#WPDBUSENUM#{dev_path.upper()}"
        self.software.sz(wpd_sw, "FriendlyName", label, ts=last_connect)
        emd = rf"Microsoft\Windows NT\CurrentVersion\EMDMgmt\{dev_path}{label}_{vsn}"
        self.software.dword(emd, "DeviceStatus", 2, ts=first)
        self.software.qword(emd, "LastTestedTime", 0)
        vic = rf"Microsoft\Windows Search\VolumeInfoCache\{drive_letter}:"
        self.software.sz(vic, "VolumeLabel", label, ts=last_connect)
        self.software.dword(vic, "DriveType", 2)

    # ------------------------------------------------------------ finalize
    def finalize(self) -> None:
        cfg = "C:\\Windows\\System32\\config"
        os.makedirs(self.path(cfg), exist_ok=True)
        for name, hive in [("SYSTEM", self.system), ("SOFTWARE", self.software), ("SAM", self.sam),
                           ("SECURITY", self.security)]:
            out = self.path(f"{cfg}\\{name}")
            hive.save(out)
            self._register(f"{cfg}\\{name}", self.install_time, _latest(hive) or self.install_time, None)
        am = "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"
        self.amcache.save(self.path(am))
        self._register(am, self.install_time, _latest(self.amcache) or self.install_time, None)
        for u in self.users.values():
            nt = f"{u['profile']}\\NTUSER.DAT"
            u["ntuser"].save(self.path(nt))
            self._register(nt, u["ntuser"].default_ts, _latest(u["ntuser"]) or u["ntuser"].default_ts, None)
            uc = f"{u['profile']}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
            u["usrclass"].save(self.path(uc))
            self._register(uc, u["usrclass"].default_ts, _latest(u["usrclass"]) or u["usrclass"].default_ts, None)
        logs = "C:\\Windows\\System32\\winevt\\Logs"
        os.makedirs(self.path(logs), exist_ok=True)
        for fname, evs in self.events.items():
            p = self.path(f"{logs}\\{fname}")
            write_evtx(p, evs)
            last = max(e.time for e in evs) if evs else self.install_time
            self._register(f"{logs}\\{fname}", self.install_time, last, None)
        # sort files by creation time so the WSL builder creates them chronologically
        self.manifest["files"].sort(key=lambda f: f["ctime"])
        with open(os.path.join(self.dir, "manifest.json"), "w") as fh:
            json.dump(self.manifest, fh, indent=1)


def _latest(h: HiveBuilder):
    from .regwriter import _all_times

    t = _all_times(h.root)
    return max(t) if t else None


def plus(dt: datetime, **kw) -> datetime:
    return dt + timedelta(**kw)
