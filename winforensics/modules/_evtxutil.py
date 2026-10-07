"""Robust EVTX record iteration.

The Rust ``evtx`` parser stops at the first damaged / uninitialized chunk, which
is common in logs acquired from live or uncleanly shut down systems.  When that
happens every remaining chunk carrying the ``ElfChnk`` signature is parsed on its
own (wrapped in a repaired file header), so records after a bad chunk - and
records in dirty, partially written chunks - are still recovered.  The same
routine carves chunks out of arbitrary data (e.g. unallocated space).
"""

from __future__ import annotations

import io
import struct
import zlib

CHUNK = 65536
HEADER = 4096


def _single_chunk_file(header: bytes, chunk: bytes) -> bytes:
    h = bytearray(header[:HEADER].ljust(HEADER, b"\x00"))
    if h[:8] != b"ElfFile\x00":
        h[:8] = b"ElfFile\x00"
        struct.pack_into("<I", h, 32, 128)
        struct.pack_into("<HHH", h, 36, 1, 3, 4096)
    struct.pack_into("<QQ", h, 8, 0, 0)          # first / last chunk number
    struct.pack_into("<H", h, 42, 1)             # number of chunks
    struct.pack_into("<I", h, 120, 0)            # flags: clean
    struct.pack_into("<I", h, 124, zlib.crc32(bytes(h[:120])) & 0xFFFFFFFF)
    return bytes(h) + chunk


def iter_records(data: bytes, stats: dict | None = None):
    """Yield evtx-rs record dicts ({event_record_id, timestamp, data}) from a whole EVTX file."""
    from evtx import PyEvtxParser

    stats = stats if stats is not None else {}
    seen = set()
    failed = False
    try:
        it = PyEvtxParser(io.BytesIO(data)).records_json()
        while True:
            try:
                rec = next(it)
            except StopIteration:
                break
            except Exception as e:  # damaged chunk - switch to chunk-by-chunk recovery
                failed = True
                stats["first_error"] = str(e)[:200]
                break
            seen.add(rec.get("event_record_id"))
            yield rec
    except Exception as e:
        failed = True
        stats["first_error"] = str(e)[:200]
    if not failed:
        return
    recovered = 0
    header = data[:HEADER]
    for off in range(HEADER, len(data) - 512, CHUNK):
        if data[off:off + 8] != b"ElfChnk\x00":
            continue
        for rec in _parse_chunk(header, data[off:off + CHUNK]):
            rid = rec.get("event_record_id")
            if rid in seen:
                continue
            seen.add(rid)
            recovered += 1
            yield rec
    stats["recovered_records"] = recovered


def _parse_chunk(header: bytes, chunk: bytes):
    from evtx import PyEvtxParser

    try:
        it = PyEvtxParser(io.BytesIO(_single_chunk_file(header, chunk))).records_json()
        while True:
            try:
                rec = next(it)
            except StopIteration:
                return
            except Exception:
                return
            yield rec
    except Exception:
        return


def carve_chunks(data: bytes):
    """Yield records from any ``ElfChnk`` structures found in arbitrary data (slack / unallocated)."""
    pos = 0
    while True:
        i = data.find(b"ElfChnk\x00", pos)
        if i < 0:
            return
        yield from _parse_chunk(b"", data[i:i + CHUNK])
        pos = i + 8
