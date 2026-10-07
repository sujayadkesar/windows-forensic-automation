"""Minimal but specification-correct [MS-SHLLINK] writer for test fixtures."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime

from .regwriter import filetime
from .shellitems import id_list, path_items

LINK_CLSID = uuid.UUID("00021401-0000-0000-C000-000000000046")

HasLinkTargetIDList = 0x1
HasLinkInfo = 0x2
HasName = 0x4
HasRelativePath = 0x8
HasWorkingDir = 0x10
HasArguments = 0x20
HasIconLocation = 0x40
IsUnicode = 0x80

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3


def _str(s: str) -> bytes:
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def build_lnk(
    target: str,
    *,
    ctime: datetime,
    mtime: datetime,
    atime: datetime,
    size: int,
    drive_type: int = DRIVE_FIXED,
    volume_serial: int = 0,
    volume_label: str = "",
    machine_id: str = "",
    mac: bytes = b"\x00\x0c\x29\x3a\x4b\x5c",
    arguments: str | None = None,
    working_dir: str | None = None,
    icon_location: str | None = None,
    name: str | None = None,
    is_dir: bool = False,
) -> bytes:
    flags = HasLinkTargetIDList | HasLinkInfo | HasRelativePath | IsUnicode
    if working_dir:
        flags |= HasWorkingDir
    if arguments:
        flags |= HasArguments
    if icon_location:
        flags |= HasIconLocation
    if name:
        flags |= HasName

    attrs = 0x10 if is_dir else 0x20
    header = struct.pack("<I", 0x4C) + LINK_CLSID.bytes_le
    header += struct.pack("<II", flags, attrs)
    header += struct.pack("<QQQ", filetime(ctime), filetime(atime), filetime(mtime))
    header += struct.pack("<IiIHHII", size & 0xFFFFFFFF, 0, 1, 0, 0, 0, 0)
    assert len(header) == 0x4C

    # LinkTargetIDList
    items = path_items(target, {"mtime": mtime, "ctime": ctime, "atime": atime}, final_is_file=not is_dir, size=size)
    idl = id_list(*items)
    out = header + struct.pack("<H", len(idl)) + idl

    # LinkInfo with VolumeID + LocalBasePath
    label = volume_label.encode("ascii") + b"\x00"
    volume_id = struct.pack("<IIII", 0x10 + len(label), drive_type, volume_serial & 0xFFFFFFFF, 0x10) + label
    base_path = target.encode("ascii", errors="replace") + b"\x00"
    suffix = b"\x00"
    hdr_size = 0x1C
    vol_off = hdr_size
    base_off = vol_off + len(volume_id)
    suffix_off = base_off + len(base_path)
    total = suffix_off + len(suffix)
    linkinfo = struct.pack("<IIIIIII", total, hdr_size, 1, vol_off, base_off, 0, suffix_off)
    linkinfo += volume_id + base_path + suffix
    out += linkinfo

    # StringData
    if name:
        out += _str(name)
    rel = "..\\..\\..\\..\\..\\" + target.split(":\\", 1)[-1]
    out += _str(rel)
    if working_dir:
        out += _str(working_dir)
    if arguments:
        out += _str(arguments)
    if icon_location:
        out += _str(icon_location)

    # TrackerDataBlock (machine id + droids; file droid is a v1 UUID embedding MAC + time)
    if machine_id:
        mid = machine_id.encode("ascii")[:15].ljust(16, b"\x00")
        vol_droid = uuid.uuid4()
        node = int.from_bytes(mac, "big")
        ts100 = filetime(ctime) - filetime(datetime(1582, 10, 15, tzinfo=ctime.tzinfo)) if ctime.tzinfo else 0
        time_low = ts100 & 0xFFFFFFFF
        time_mid = (ts100 >> 32) & 0xFFFF
        time_hi = ((ts100 >> 48) & 0x0FFF) | (1 << 12)
        file_droid = uuid.UUID(fields=(time_low, time_mid, time_hi, 0x80 | 0x12, 0x34, node))
        tracker = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + mid
        tracker += vol_droid.bytes_le + file_droid.bytes_le + vol_droid.bytes_le + file_droid.bytes_le
        out += tracker
    out += struct.pack("<I", 0)
    return out
