"""Uncompressed Windows 10 (version 30) prefetch (SCCA) writer."""

from __future__ import annotations

import struct
from datetime import datetime

from .regwriter import filetime


def scca_hash(path: str) -> int:
    """Vista+ prefetch path hash (SCCA_HASH_V2) over the upper-cased device path."""
    h = 314159
    data = path.upper().encode("utf-16-le")
    i = 0
    n = len(data)
    while i + 8 <= n:
        c = data[i + 1] * 37 + data[i + 2] * 37 * 37 + data[i + 3] * 37 ** 3 + data[i + 4] * 37 ** 4 \
            + data[i + 5] * 37 ** 5 + data[i + 6] * 37 ** 6 + data[i] * 37 ** 7 + data[i + 7]
        h = (37 ** 8 * h + c) % 0x100000000  # approximation; only used as an identifier
        i += 8
    while i < n:
        h = (37 * h + data[i]) % 0x100000000
        i += 1
    return h


def build_prefetch(
    exe_name: str,
    exe_device_path: str,
    run_times: list[datetime],
    run_count: int,
    files: list[str],
    volume_device: str = "\\VOLUME{01d8f5a1c2b3e4f5-1a2b3c4d}",
    volume_serial: int = 0x1A2B3C4D,
    volume_created: datetime | None = None,
    directories: list[str] | None = None,
) -> tuple[str, bytes]:
    """Return (prefetch filename, bytes)."""
    pf_hash = scca_hash(exe_device_path)
    name_field = exe_name.upper().encode("utf-16-le")[:58].ljust(60, b"\x00")

    # filename strings
    strings = b""
    metrics = b""
    for f in files:
        off = len(strings)
        enc = f.encode("utf-16-le") + b"\x00\x00"
        metrics += struct.pack("<IIIIIIQ", 0, 0, 0, off, len(f), 0x200, 0)
        strings += enc

    metrics_off = 312
    strings_off = metrics_off + len(metrics)
    vol_off = strings_off + len(strings)
    vol_off = (vol_off + 7) & ~7

    dirs = directories or []
    dev_enc = volume_device.encode("utf-16-le") + b"\x00\x00"
    vol_struct_size = 96
    dev_rel = vol_struct_size
    dir_rel = dev_rel + len(dev_enc)
    dir_blob = b""
    for d in dirs:
        dir_blob += struct.pack("<H", len(d)) + d.encode("utf-16-le") + b"\x00\x00"
    vol = struct.pack(
        "<IIQIIIII",
        dev_rel,
        len(volume_device),
        filetime(volume_created or run_times[-1]),
        volume_serial,
        0,
        0,
        dir_rel,
        len(dirs),
    )
    vol = vol.ljust(vol_struct_size, b"\x00") + dev_enc + dir_blob
    total = vol_off + len(vol)

    runs = sorted(run_times, reverse=True)[:8]
    run_fts = [filetime(r) for r in runs] + [0] * (8 - len(runs))
    info = struct.pack(
        "<IIIIIIIII",
        metrics_off,
        len(files),
        0,
        0,
        strings_off,
        len(strings),
        vol_off,
        1,
        len(vol),
    )
    info += struct.pack("<II", 0, 0)
    info += struct.pack("<8Q", *run_fts)
    info += struct.pack("<QQ", 0, 0)
    info += struct.pack("<III", run_count, 0, 0)
    info += b"\x00" * 88
    header = struct.pack("<I4sII", 30, b"SCCA", 0x11, total) + name_field + struct.pack("<II", pf_hash, 0)
    assert len(header) == 84
    body = bytearray(total)
    body[0:84] = header
    body[84:84 + len(info)] = info
    body[metrics_off:metrics_off + len(metrics)] = metrics
    body[strings_off:strings_off + len(strings)] = strings
    body[vol_off:vol_off + len(vol)] = vol
    fname = f"{exe_name.upper()}-{pf_hash:08X}.pf"
    return fname, bytes(body)
