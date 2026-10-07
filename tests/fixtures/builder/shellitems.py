"""Shell item (PIDL) construction used by ShellBags, OpenSave MRUs and LNK files."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime

MY_COMPUTER = uuid.UUID("20D04FE0-3AEA-1069-A2D8-08002B30309D")
USERS_FILES = uuid.UUID("59031A47-3F72-44A7-89C5-5595FE6B30EE")


def fat_datetime(dt: datetime | None) -> bytes:
    if dt is None:
        return b"\x00\x00\x00\x00"
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    tm = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return struct.pack("<HH", date, tm)


def root_folder(guid: uuid.UUID = MY_COMPUTER, sort_index: int = 0x50) -> bytes:
    body = bytes([0x1F, sort_index]) + guid.bytes_le
    return struct.pack("<H", len(body) + 2) + body


def volume(letter: str) -> bytes:
    name = f"{letter.upper()}:\\".encode("ascii")
    body = bytes([0x2F]) + name.ljust(22, b"\x00")
    return struct.pack("<H", len(body) + 2) + body


def _short_name(name: str, is_dir: bool) -> str:
    base, _, ext = name.rpartition(".") if (not is_dir and "." in name) else (name, "", "")
    clean = "".join(c for c in base.upper() if c.isalnum())
    if len(clean) > 8 or clean != base.upper():
        clean = clean[:6] + "~1"
    if ext:
        return f"{clean}.{ext.upper()[:3]}"
    return clean


def file_entry(
    name: str,
    is_dir: bool = True,
    size: int = 0,
    mtime: datetime | None = None,
    ctime: datetime | None = None,
    atime: datetime | None = None,
    mft_entry: int = 0,
    mft_seq: int = 0,
) -> bytes:
    """Create a Windows 7+ style file entry shell item with a BEEF0004 extension."""
    item_type = 0x31 if is_dir else 0x32
    attrs = 0x10 if is_dir else 0x20
    short = _short_name(name, is_dir).encode("ascii") + b"\x00"
    head = struct.pack("<BBI", item_type, 0, size) + fat_datetime(mtime) + struct.pack("<H", attrs) + short
    # offset relative to item start (2 bytes size prefix)
    if (len(head) + 2) % 2:
        head += b"\x00"
    ext_offset = len(head) + 2

    file_ref = (mft_seq << 48) | mft_entry
    ext = struct.pack("<HI", 9, 0xBEEF0004)  # version, signature (size prepended later)
    ext += fat_datetime(ctime) + fat_datetime(atime)
    ext += struct.pack("<H", 0x2E)  # identifier
    ext += struct.pack("<HQQ", 0, file_ref, 0)
    ext += struct.pack("<H", 0)  # localized name offset
    ext += struct.pack("<I", 0)  # v9 unknown
    ext += struct.pack("<I", 0)  # v8 unknown
    ext += (name + "\x00").encode("utf-16-le")
    ext += struct.pack("<H", ext_offset)
    ext = struct.pack("<H", len(ext) + 2) + ext

    body = head + ext
    return struct.pack("<H", len(body) + 2) + body


def id_list(*items: bytes) -> bytes:
    """Concatenate items into an ITEMIDLIST (terminated by a zero size)."""
    return b"".join(items) + b"\x00\x00"


def path_items(path: str, times: dict | None = None, final_is_file: bool = False, size: int = 0) -> list[bytes]:
    """Turn ``E:\\Dir\\File.ext`` into [MyComputer, Volume, entries...]."""
    times = times or {}
    drive, _, rest = path.partition(":\\")
    parts = [p for p in rest.split("\\") if p]
    items = [root_folder(), volume(drive)]
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        is_file = last and final_is_file
        items.append(
            file_entry(
                part,
                is_dir=not is_file,
                size=size if is_file else 0,
                mtime=times.get("mtime"),
                ctime=times.get("ctime"),
                atime=times.get("atime"),
                mft_entry=1000 + i,
                mft_seq=1,
            )
        )
    return items
