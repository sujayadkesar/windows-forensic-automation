"""Create genuine Windows registry hive (regf) files for test fixtures.

Uses the Win32 ``RegLoadAppKey`` API, which creates/loads a private application
hive without administrative privileges.  After the hive is written the key
LastWrite timestamps are patched to scenario times so the fixture behaves like a
real evidence hive (USB first/last connection, MRU ordering, ...).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import shutil
import struct
import time
from datetime import datetime, timezone

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11
# DEVPROP_TYPE_FILETIME as stored by PnP under Properties\{83da6326-...}
REG_DEVPROP_FILETIME = 0xFFFF0010
REG_DEVPROP_STRING = 0xFFFF0012

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_HKEY = wt.HKEY
_RegLoadAppKeyW = _advapi32.RegLoadAppKeyW
_RegLoadAppKeyW.argtypes = [wt.LPCWSTR, ctypes.POINTER(_HKEY), wt.DWORD, wt.DWORD, wt.DWORD]
_RegLoadAppKeyW.restype = wt.LONG
_RegCreateKeyExW = _advapi32.RegCreateKeyExW
_RegCreateKeyExW.argtypes = [
    _HKEY, wt.LPCWSTR, wt.DWORD, wt.LPWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
    ctypes.POINTER(_HKEY), ctypes.POINTER(wt.DWORD),
]
_RegCreateKeyExW.restype = wt.LONG
_RegSetValueExW = _advapi32.RegSetValueExW
_RegSetValueExW.argtypes = [_HKEY, wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_char_p, wt.DWORD]
_RegSetValueExW.restype = wt.LONG
_RegFlushKey = _advapi32.RegFlushKey
_RegFlushKey.argtypes = [_HKEY]
_RegCloseKey = _advapi32.RegCloseKey
_RegCloseKey.argtypes = [_HKEY]

KEY_ALL_ACCESS = 0xF003F


def filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def ft_bytes(dt: datetime) -> bytes:
    return struct.pack("<Q", filetime(dt))


def sz(s: str) -> bytes:
    return (s + "\x00").encode("utf-16-le")


def multi_sz(items: list[str]) -> bytes:
    return ("\x00".join(items) + "\x00\x00").encode("utf-16-le")


class _Key:
    def __init__(self, name: str):
        self.name = name
        self.subkeys: dict[str, _Key] = {}
        self.values: list[tuple[str, int, bytes]] = []
        self.ts: datetime | None = None


class HiveBuilder:
    """In-memory description of a hive which is materialised with ``save``."""

    def __init__(self, default_ts: datetime):
        self.root = _Key("")
        self.default_ts = default_ts

    def key(self, path: str, ts: datetime | None = None) -> _Key:
        node = self.root
        for part in [p for p in path.split("\\") if p]:
            lower = part.lower()
            found = None
            for k, v in node.subkeys.items():
                if k.lower() == lower:
                    found = v
                    break
            if found is None:
                found = _Key(part)
                node.subkeys[part] = found
            node = found
        if ts is not None:
            node.ts = ts
        return node

    def set(self, path: str, name: str, vtype: int, data, ts: datetime | None = None) -> None:
        k = self.key(path, ts)
        if isinstance(data, str):
            data = sz(data)
        elif isinstance(data, int) and vtype == REG_DWORD:
            data = struct.pack("<I", data & 0xFFFFFFFF)
        elif isinstance(data, int) and vtype == REG_QWORD:
            data = struct.pack("<Q", data)
        elif isinstance(data, datetime):
            data = ft_bytes(data)
        k.values = [v for v in k.values if v[0].lower() != name.lower()]
        k.values.append((name, vtype, bytes(data)))

    def sz(self, path, name, value, ts=None):
        self.set(path, name, REG_SZ, value, ts)

    def expand_sz(self, path, name, value, ts=None):
        self.set(path, name, REG_EXPAND_SZ, value, ts)

    def dword(self, path, name, value, ts=None):
        self.set(path, name, REG_DWORD, value, ts)

    def qword(self, path, name, value, ts=None):
        self.set(path, name, REG_QWORD, value, ts)

    def binary(self, path, name, value: bytes, ts=None):
        self.set(path, name, REG_BINARY, value, ts)

    # ------------------------------------------------------------------ save
    def save(self, out_path: str) -> None:
        out_path = os.path.abspath(out_path)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        tmp_dir = out_path + ".build"
        shutil.rmtree(tmp_dir, ignore_errors=True)
        os.makedirs(tmp_dir)
        tmp_hive = os.path.join(tmp_dir, "hive")

        root = _HKEY()
        rc = _RegLoadAppKeyW(tmp_hive, ctypes.byref(root), KEY_ALL_ACCESS, 0, 0)
        if rc != 0:
            raise OSError(f"RegLoadAppKeyW failed: {rc}")
        try:
            self._write(root, self.root)
            _RegFlushKey(root)
        finally:
            _RegCloseKey(root)

        # App hives are unloaded asynchronously once the last handle is closed.
        for _ in range(100):
            try:
                with open(tmp_hive, "r+b"):
                    pass
                break
            except PermissionError:
                time.sleep(0.1)
        shutil.copyfile(tmp_hive, out_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        patch_timestamps(out_path, self)

    def _write(self, hkey, node: _Key) -> None:
        for name, vtype, data in node.values:
            buf = ctypes.create_string_buffer(data, len(data)) if data else None
            rc = _RegSetValueExW(hkey, name, 0, vtype, buf, len(data))
            if rc != 0:
                raise OSError(f"RegSetValueExW({name}) failed: {rc}")
        for name, child in node.subkeys.items():
            sub = _HKEY()
            disp = wt.DWORD()
            rc = _RegCreateKeyExW(hkey, name, 0, None, 0, KEY_ALL_ACCESS, None, ctypes.byref(sub), ctypes.byref(disp))
            if rc != 0:
                raise OSError(f"RegCreateKeyExW({name}) failed: {rc}")
            try:
                self._write(sub, child)
            finally:
                _RegCloseKey(sub)


# ---------------------------------------------------------------- regf patch
def _cell(buf: bytearray, off: int) -> int:
    return 0x1000 + off


def patch_timestamps(path: str, builder: HiveBuilder) -> None:
    """Rewrite nk LastWrite timestamps according to the builder's key times.

    Keys without an explicit time inherit their parent's time (or the default).
    """
    with open(path, "rb") as fh:
        buf = bytearray(fh.read())
    if buf[:4] != b"regf":
        raise ValueError("not a regf file")
    root_off = struct.unpack_from("<I", buf, 0x24)[0]

    def subkey_offsets(list_off: int) -> list[int]:
        pos = _cell(buf, list_off) + 4
        sig = bytes(buf[pos:pos + 2])
        count = struct.unpack_from("<H", buf, pos + 2)[0]
        out = []
        if sig in (b"lf", b"lh"):
            for i in range(count):
                out.append(struct.unpack_from("<I", buf, pos + 4 + i * 8)[0])
        elif sig == b"li":
            for i in range(count):
                out.append(struct.unpack_from("<I", buf, pos + 4 + i * 4)[0])
        elif sig == b"ri":
            for i in range(count):
                out.extend(subkey_offsets(struct.unpack_from("<I", buf, pos + 4 + i * 4)[0]))
        return out

    def walk(nk_off: int, node: _Key | None, inherited: datetime) -> None:
        pos = _cell(buf, nk_off) + 4
        if bytes(buf[pos:pos + 2]) != b"nk":
            return
        ts = (node.ts if node is not None and node.ts else None) or inherited
        struct.pack_into("<Q", buf, pos + 4, filetime(ts))
        n_sub = struct.unpack_from("<I", buf, pos + 0x14)[0]
        if not n_sub:
            return
        list_off = struct.unpack_from("<I", buf, pos + 0x1C)[0]
        for child_off in subkey_offsets(list_off):
            cpos = _cell(buf, child_off) + 4
            flags = struct.unpack_from("<H", buf, cpos + 2)[0]
            name_len = struct.unpack_from("<H", buf, cpos + 0x48)[0]
            raw = bytes(buf[cpos + 0x4C:cpos + 0x4C + name_len])
            name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le")
            child = None
            if node is not None:
                for k, v in node.subkeys.items():
                    if k.lower() == name.lower():
                        child = v
                        break
            walk(child_off, child, ts)

    root_ts = builder.root.ts or builder.default_ts
    walk(root_off, builder.root, root_ts)

    # header: last written timestamp, make sequence numbers consistent, checksum
    latest = max(_all_times(builder.root) + [builder.default_ts])
    struct.pack_into("<Q", buf, 0x0C, filetime(latest))
    seq = struct.unpack_from("<I", buf, 0x04)[0]
    struct.pack_into("<I", buf, 0x08, seq)
    csum = 0
    for i in range(127):
        csum ^= struct.unpack_from("<I", buf, i * 4)[0]
    if csum == 0:
        csum = 1
    elif csum == 0xFFFFFFFF:
        csum = 0xFFFFFFFE
    struct.pack_into("<I", buf, 0x1FC, csum)
    with open(path, "wb") as fh:
        fh.write(buf)


def _all_times(node: _Key) -> list[datetime]:
    out = [node.ts] if node.ts else []
    for c in node.subkeys.values():
        out.extend(_all_times(c))
    return out
