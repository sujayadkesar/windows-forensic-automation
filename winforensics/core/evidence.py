"""Evidence loading, probing and integrity verification.

Supported inputs
    * EWF: E01/Ex01/L01/Lx01/S01 (libewf via pyewf, falling back to dissect.evidence)
    * Raw: dd/raw/img/bin/mem-less disk dumps, split raw (.001, .002 ...)
    * Virtual disks: VMDK, VHD, VHDX, VDI, QCOW2
    * Logical/triage: AD1, KAPE / Velociraptor / other collection folders and ZIP archives
    * BitLocker protected volumes (recovery password, passphrase or BEK file)
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger("winforensics.evidence")

FORMATS = {
    "ewf": "Expert Witness (EnCase E01)",
    "ewf2": "Expert Witness v2 (EnCase Ex01)",
    "ewf_logical": "EWF logical evidence (L01/Lx01)",
    "smart": "SMART (S01)",
    "raw": "Raw disk image (dd)",
    "split_raw": "Split raw image",
    "vmdk": "VMware VMDK",
    "vhd": "Microsoft VHD",
    "vhdx": "Microsoft VHDX",
    "vdi": "VirtualBox VDI",
    "qcow2": "QEMU QCOW2",
    "ad1": "AccessData AD1 (logical)",
    "directory": "Folder / triage collection",
    "zip": "ZIP triage collection",
    "unknown": "Unknown (auto-detect)",
}

IMAGE_EXTENSIONS = (
    "*.E01 *.Ex01 *.L01 *.Lx01 *.S01 *.dd *.raw *.img *.bin *.001 *.vmdk *.vhd *.vhdx *.vdi *.qcow2 *.ad1 *.zip"
)


def detect_format(path: str) -> str:
    if os.path.isdir(path):
        return "directory"
    low = path.lower()
    ext = os.path.splitext(low)[1]
    if re.search(r"\.e\d\d$", low) or ext == ".e01":
        return "ewf"
    if re.search(r"\.ex\d\d$", low):
        return "ewf2"
    if re.search(r"\.lx?\d\d$", low):
        return "ewf_logical"
    if re.search(r"\.s\d\d$", low):
        return "smart"
    if re.search(r"\.\d{3}$", low):
        return "split_raw"
    mapping = {".dd": "raw", ".raw": "raw", ".img": "raw", ".bin": "raw", ".vmdk": "vmdk", ".vhd": "vhd",
               ".vhdx": "vhdx", ".vdi": "vdi", ".qcow2": "qcow2", ".ad1": "ad1", ".zip": "zip"}
    if ext in mapping:
        return mapping[ext]
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
        if head.startswith(b"EVF\x09") or head.startswith(b"LVF"):
            return "ewf"
        if head.startswith(b"EVF2"):
            return "ewf2"
        if head.startswith(b"KDMV") or head.startswith(b"# Disk Desc"):
            return "vmdk"
        if head.startswith(b"vhdxfile"):
            return "vhdx"
        if head.startswith(b"QFI\xfb"):
            return "qcow2"
        if head.startswith(b"PK\x03\x04"):
            return "zip"
    except OSError:
        pass
    return "raw"


def segment_files(path: str) -> list[str]:
    """All files that make up a (possibly segmented) image."""
    fmt = detect_format(path)
    if fmt == "directory":
        return []
    folder = os.path.dirname(os.path.abspath(path))
    base = os.path.basename(path)
    stem, ext = os.path.splitext(base)
    if fmt in ("ewf", "ewf2", "ewf_logical", "smart"):
        prefix = ext[:2] if fmt == "ewf" else ext[:3]
        pat = re.compile(re.escape(stem) + re.escape(prefix) + r"[0-9A-Za-z]{2}$", re.I)
        files = sorted(os.path.join(folder, f) for f in os.listdir(folder) if pat.match(f))
        return files or [os.path.abspath(path)]
    if fmt == "split_raw":
        pat = re.compile(re.escape(stem) + r"\.\d{3}$", re.I)
        return sorted(os.path.join(folder, f) for f in os.listdir(folder) if pat.match(f))
    return [os.path.abspath(path)]


# --------------------------------------------------------------------------- pyewf stream
class EwfStream(io.RawIOBase):
    """Seekable, thread-safe file object on top of a libewf handle."""

    def __init__(self, path: str):
        import pyewf

        self._lock = threading.Lock()
        files = pyewf.glob(os.path.abspath(path))
        self.handle = pyewf.handle()
        self.handle.open(files)
        self.size = self.handle.get_media_size()
        self._pos = 0
        self.files = files

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = self.size + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self.size - self._pos
        if self._pos >= self.size or n == 0:
            return b""
        n = min(n, self.size - self._pos)
        with self._lock:
            self.handle.seek(self._pos)
            data = self.handle.read(n)
        self._pos += len(data)
        return data

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)

    def metadata(self) -> dict:
        info = {}
        try:
            info["headers"] = {k: v for k, v in self.handle.get_header_values().items() if v}
        except Exception:
            info["headers"] = {}
        try:
            info["stored_hashes"] = {k.lower(): v.lower() for k, v in self.handle.get_hash_values().items() if v}
        except Exception:
            info["stored_hashes"] = {}
        for attr, key in [("get_bytes_per_sector", "bytes_per_sector"), ("get_number_of_sectors", "sectors"),
                          ("get_media_type", "media_type"), ("get_format", "ewf_format"),
                          ("get_compression_method", "compression"), ("get_error_granularity", "error_granularity")]:
            try:
                info[key] = getattr(self.handle, attr)()
            except Exception:
                pass
        try:
            n = self.handle.get_number_of_checksum_errors()
            info["checksum_errors"] = n
        except Exception:
            pass
        info["segments"] = [os.path.basename(f) for f in self.files]
        return info

    def close(self) -> None:
        try:
            self.handle.close()
        except Exception:
            pass
        super().close()


class _ConcatStream(io.RawIOBase):
    """Read-only concatenation of split raw files (used for hashing)."""

    def __init__(self, files: list[str]):
        self.files = files
        self.sizes = [os.path.getsize(f) for f in files]
        self.size = sum(self.sizes)

    def iter_chunks(self, chunk: int):
        for f in self.files:
            with open(f, "rb") as fh:
                while True:
                    b = fh.read(chunk)
                    if not b:
                        break
                    yield b


# --------------------------------------------------------------------------- target opening
@dataclass
class OpenedEvidence:
    target: object
    format: str
    stream: object | None = None
    ewf_meta: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


def register_keys(keys: list[dict] | None) -> None:
    """keys: [{type: recovery_key|passphrase|file|raw, value: str}]"""
    if not keys:
        return
    from dissect.target.helpers import keychain

    for k in keys:
        value = (k.get("value") or "").strip()
        if not value:
            continue
        kt = {"recovery_key": keychain.KeyType.RECOVERY_KEY, "passphrase": keychain.KeyType.PASSPHRASE,
              "file": keychain.KeyType.FILE, "raw": keychain.KeyType.RAW}.get(k.get("type", "recovery_key"))
        already = [x for x in keychain.get_all_keys() if x.value == value]
        if not already:
            keychain.register_key(kt, value, provider="bitlocker", is_wildcard=True)


def open_evidence(path: str, keys: list[dict] | None = None, prefer_libewf: bool = True) -> OpenedEvidence:
    from dissect.target import Target

    register_keys(keys)
    fmt = detect_format(path)
    warnings: list[str] = []
    if fmt in ("ewf", "ewf2", "smart") and prefer_libewf:
        try:
            from dissect.target.containers.raw import RawContainer

            stream = EwfStream(path)
            t = Target(path)
            t.disks.add(RawContainer(stream))
            t.apply()
            return OpenedEvidence(t, fmt, stream, stream.metadata(), warnings)
        except ImportError:
            warnings.append("libewf (pyewf) not available, using built-in EWF reader")
        except Exception as e:  # pragma: no cover - depends on evidence
            warnings.append(f"libewf failed ({e}); falling back to built-in EWF reader")
    t = Target.open(path)
    return OpenedEvidence(t, fmt, None, {}, warnings)


# --------------------------------------------------------------------------- probing
def _fs_details(vol) -> dict:
    d = {"fs": None}
    fs = getattr(vol, "fs", None)
    if fs is None:
        return d
    d["fs"] = getattr(fs, "__type__", type(fs).__name__)
    try:
        if d["fs"] == "ntfs":
            n = fs.ntfs
            d["label"] = n.volume_name
            d["serial"] = f"{n.serial:016X}"
            d["serial_short"] = f"{n.serial & 0xFFFFFFFF:08X}"
            d["cluster_size"] = n.cluster_size
        elif d["fs"] in ("fat", "exfat"):
            inner = getattr(fs, "fatfs", None) or getattr(fs, "exfat", None)
            for attr in ("volume_label", "volume_name"):
                v = getattr(inner, attr, None)
                if v:
                    d["label"] = str(v).strip()
            for attr in ("volume_id", "volume_serial", "serial"):
                v = getattr(inner, attr, None)
                if isinstance(v, int):
                    d["serial"] = f"{v:08X}"
                elif isinstance(v, (bytes, bytearray)):
                    d["serial"] = bytes(v)[::-1].hex().upper()
                elif v:
                    d["serial"] = str(v)
    except Exception:
        pass
    return d


def probe_target(t) -> dict:
    """Collect evidence summary: volumes, OS, users, timezone."""
    info: dict = {"volumes": [], "os": {}, "users": []}
    for vol in t.volumes:
        try:
            head = b""
            try:
                vol.seek(0)
                head = vol.read(16)
                vol.seek(0)
            except Exception:
                pass
            entry = {
                "name": vol.name, "number": vol.number, "offset": vol.offset, "size": vol.size,
                "type": str(vol.type) if vol.type is not None else None, "guid": str(vol.guid) if vol.guid else None,
                "drive_letter": getattr(vol, "drive_letter", None),
                "encrypted": head[3:11] == b"-FVE-FS-",
            }
            entry.update(_fs_details(vol))
            info["volumes"].append(entry)
        except Exception as e:
            info["volumes"].append({"name": getattr(vol, "name", "?"), "error": str(e)})
    os_name = None
    try:
        os_name = t.os
    except Exception:
        pass
    info["os"]["family"] = os_name
    for key, getter in [("hostname", lambda: t.hostname), ("version", lambda: t.version),
                        ("domain", lambda: t.domain), ("ips", lambda: [str(i) for i in t.ips]),
                        ("architecture", lambda: t.architecture)]:
        try:
            info["os"][key] = getter()
        except Exception:
            info["os"][key] = None
    if os_name == "windows":
        info["os"].update(windows_details(t))
        try:
            for ud in t.user_details.all():
                u = ud.user
                info["users"].append({"name": u.name, "sid": getattr(u, "sid", None), "home": str(getattr(u, "home", ""))})
        except Exception:
            pass
    info["mounts"] = sorted(str(m) for m in getattr(t.fs, "mounts", {}).keys())
    return info


def windows_details(t) -> dict:
    from .timeutil import resolve_windows_tz, unix, db_ts, filetime
    import struct

    d: dict = {}
    reg = t.registry

    def val(key, name):
        try:
            return reg.key(key).value(name).value
        except Exception:
            return None

    cv = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    d["product_name"] = val(cv, "ProductName")
    d["display_version"] = val(cv, "DisplayVersion") or val(cv, "ReleaseId")
    # Windows XP / 2003 keep a placeholder in CurrentBuild ("1.511.1 () (Obsolete data - do not use)")
    cb = val(cv, "CurrentBuild")
    d["build"] = cb if cb and str(cb).isdigit() else val(cv, "CurrentBuildNumber") or cb
    ubr = val(cv, "UBR")
    if ubr is not None and d["build"]:
        d["build"] = f"{d['build']}.{ubr}"
    try:
        if d["build"] and int(str(d["build"]).split(".")[0]) >= 22000 and d["product_name"]:
            d["product_name"] = d["product_name"].replace("Windows 10", "Windows 11")
    except ValueError:
        pass
    d["edition"] = val(cv, "EditionID")
    d["registered_owner"] = val(cv, "RegisteredOwner")
    d["registered_org"] = val(cv, "RegisteredOrganization")
    inst = val(cv, "InstallDate")
    d["install_date"] = db_ts(unix(inst)) if inst else None
    tzk = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"
    tz_name = val(tzk, "TimeZoneKeyName")
    bias = val(tzk, "Bias")
    active = val(tzk, "ActiveTimeBias")
    d["timezone_name"] = tz_name or val(tzk, "StandardName")
    d["timezone_bias"] = bias
    tz = resolve_windows_tz(tz_name, active if active is not None else bias)
    d["timezone_iana"] = getattr(tz, "key", None) or str(tz)
    sd = val("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows", "ShutdownTime")
    if isinstance(sd, (bytes, bytearray)) and len(sd) >= 8:
        d["last_shutdown"] = db_ts(filetime(struct.unpack("<Q", bytes(sd[:8]))[0]))
    d["computer_name"] = val("HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", "ComputerName")
    return d


def probe(path: str, keys: list[dict] | None = None) -> dict:
    """Quick look at an evidence item used by the New Case wizard."""
    started = time.time()
    fmt = detect_format(path)
    result = {"path": os.path.abspath(path), "format": fmt, "format_label": FORMATS.get(fmt, fmt),
              "segments": [os.path.basename(f) for f in segment_files(path)], "warnings": [], "error": None}
    try:
        result["file_size"] = sum(os.path.getsize(f) for f in segment_files(path)) if fmt != "directory" else 0
    except OSError:
        result["file_size"] = 0
    try:
        ev = open_evidence(path, keys)
        result["warnings"] += ev.warnings
        result["ewf"] = ev.ewf_meta
        t = ev.target
        try:
            result["media_size"] = sum(d.size for d in t.disks)
        except Exception:
            result["media_size"] = None
        result.update(probe_target(t))
        enc = [v for v in result["volumes"] if v.get("encrypted")]
        if enc and not any(v.get("fs") for v in result["volumes"] if v.get("offset") == enc[0].get("offset")):
            result["warnings"].append("BitLocker encrypted volume detected - supply a recovery key to analyze it")
        if result["os"].get("family") not in ("windows",):
            result["warnings"].append("No Windows installation detected; volume level analysis will still be performed")
    except Exception as e:
        log.exception("probe failed")
        result["error"] = f"{type(e).__name__}: {e}"
    result["probe_seconds"] = round(time.time() - started, 2)
    return result


# --------------------------------------------------------------------------- verification
def verify_image(path: str, progress: Callable[[float, str], None] | None = None,
                 cancelled: Callable[[], bool] | None = None, algorithms=("md5", "sha1")) -> dict:
    """Hash the acquired media and compare with hashes stored in the container (EWF)."""
    fmt = detect_format(path)
    hashers = {a: hashlib.new(a) for a in algorithms}
    stored: dict = {}
    chunk = 8 * 1024 * 1024
    started = time.time()
    done = 0
    if fmt in ("ewf", "ewf2", "smart"):
        s = EwfStream(path)
        stored = s.metadata().get("stored_hashes", {})
        total = s.size

        def chunks():
            s.seek(0)
            while True:
                b = s.read(chunk)
                if not b:
                    break
                yield b
        source = "media (decompressed EWF stream)"
    elif fmt in ("raw", "split_raw"):
        files = segment_files(path)
        cs = _ConcatStream(files)
        total = cs.size
        chunks = lambda: cs.iter_chunks(chunk)  # noqa: E731
        source = "image file(s)"
    elif fmt == "directory":
        return {"skipped": True, "reason": "logical folder evidence has no single media stream"}
    else:
        files = segment_files(path)
        cs = _ConcatStream(files)
        total = cs.size
        chunks = lambda: cs.iter_chunks(chunk)  # noqa: E731
        source = "container file(s)"
    for b in chunks():
        for h in hashers.values():
            h.update(b)
        done += len(b)
        if progress:
            rate = done / max(0.001, time.time() - started)
            progress(done / max(1, total), f"Hashing {source}: {done / 1e9:.2f}/{total / 1e9:.2f} GB ({rate / 1e6:.0f} MB/s)")
        if cancelled and cancelled():
            return {"cancelled": True}
    result = {k: h.hexdigest() for k, h in hashers.items()}
    result.update({"source": source, "bytes": done, "seconds": round(time.time() - started, 1), "stored": stored})
    matches = {k: (stored[k] == result[k]) for k in stored if k in result}
    result["verified"] = all(matches.values()) if matches else None
    result["matches"] = matches
    return result
