"""Registry helpers shared by the registry-based modules."""

from __future__ import annotations

import struct
from datetime import datetime

from ..core.timeutil import filetime


def reg_val(reg, key_path: str, name: str, default=None):
    try:
        return reg.key(key_path).value(name).value
    except Exception:
        return default


def iter_keys(reg, path: str):
    """Yield every key matching ``path`` across hives (HKCU expands to all users)."""
    try:
        yield from reg.keys(path)
    except Exception:
        return


def subkeys(key):
    try:
        return list(key.subkeys())
    except Exception:
        return []


def values(key):
    try:
        return list(key.values())
    except Exception:
        return []


def val(key, name, default=None):
    try:
        return key.value(name).value
    except Exception:
        return default


def key_user(reg, key):
    try:
        u = reg.get_user(key)
        return u.name if u else None
    except Exception:
        return None


def hive_path(key) -> str:
    try:
        return str(key.hive.filepath)
    except Exception:
        return ""


def ts_of(key):
    try:
        return key.ts
    except Exception:
        return None


def mru_order(data: bytes) -> list[int]:
    out = []
    if not data:
        return out
    for i in range(0, len(data) - 3, 4):
        v = struct.unpack_from("<i", data, i)[0]
        if v == -1:
            break
        out.append(v)
    return out


def parse_filetime_bytes(data) -> datetime | None:
    if isinstance(data, (bytes, bytearray)) and len(data) >= 8:
        return filetime(struct.unpack("<Q", bytes(data[:8]))[0])
    if isinstance(data, int):
        return filetime(data)
    return None


def rot13(s: str) -> str:
    import codecs

    return codecs.decode(s, "rot_13")
