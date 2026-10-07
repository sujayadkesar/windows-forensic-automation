"""Signature based file carving with structural size determination.

Each signature has a lower-cased search pattern (the raw scanner works on
lower-cased data), the real magic used for verification and a sizing function
that parses just enough of the format to know where the file ends, so carved
files hash identically to the original whenever the clusters are contiguous.
"""

from __future__ import annotations

import re
import struct

MB = 1024 * 1024


def _grow(read, off, limit, first=256 * 1024):
    """Yield buffers of increasing size (x4) starting at *off*, so a small file costs a small read."""
    n = first
    while True:
        want = min(n, limit)
        buf = read(off, want)
        yield buf
        if len(buf) < want or want >= limit:
            return
        n *= 4


def _zip_size(read, off, limit=200 * MB):
    """Walk local file headers, then the central directory, to the end-of-central-directory record.

    Only headers are read (a few dozen bytes per member) so a hit costs kilobytes, not megabytes.
    """
    pos = 0
    for _ in range(100000):
        h = read(off + pos, 30)
        if len(h) < 30:
            return None
        sig = h[:4]
        if sig == b"PK\x03\x04":
            flags, _m, _t, _d, _crc, csize, _usize, nlen, xlen = struct.unpack_from("<HHHHIIIHH", h, 6)
            if flags & 0x08 and csize == 0:
                # sizes in a trailing data descriptor - search forward for the next header
                m = None
                for buf in _grow(read, off + pos + 30, 16 * MB, 64 * 1024):
                    m = re.search(rb"PK\x07\x08|PK\x03\x04|PK\x01\x02", buf[nlen + xlen:])
                    if m:
                        break
                if not m:
                    return None
                nxt = pos + 30 + nlen + xlen + m.start()
                if buf[nlen + xlen + m.start():nlen + xlen + m.start() + 4] == b"PK\x07\x08":
                    nxt += 16
                pos = nxt
            else:
                pos += 30 + nlen + xlen + csize
        elif sig == b"PK\x01\x02":
            nlen, xlen, clen = struct.unpack_from("<HHH", read(off + pos + 28, 6), 0)
            pos += 46 + nlen + xlen + clen
        elif sig == b"PK\x05\x06":
            clen = struct.unpack_from("<H", h, 20)[0]
            return pos + 22 + clen
        elif sig == b"PK\x06\x06":  # zip64 end of central directory
            size = struct.unpack_from("<Q", read(off + pos + 4, 8), 0)[0]
            pos += 12 + size
        elif sig == b"PK\x06\x07":
            pos += 20
        else:
            return None
        if pos > limit:
            return None
    return None


def _pdf_size(read, off, limit=100 * MB):
    """Read forward in 1 MB steps; the file ends at the last %%EOF before the data stops looking like PDF."""
    step = MB
    pos = 0
    last_eof = None
    while pos < limit:
        buf = read(off + pos, step + 8)
        if not buf:
            break
        for m in re.finditer(rb"%%EOF\s{0,2}", buf[:step]):
            last_eof = pos + m.end()
        nxt = buf.find(b"%PDF-", 8 if pos == 0 else 0)
        if nxt >= 0 and pos + nxt > (last_eof or 0):
            break
        if last_eof is not None and buf[:4096].count(b"\x00") > 3500 and pos > (last_eof or 0):
            break
        if last_eof is not None and pos > last_eof + 4 * MB:
            break
        pos += step
    return last_eof


def _ole_size(read, off, limit=200 * MB):
    hdr = read(off, 512)
    if len(hdr) < 512:
        return None
    ssz = 1 << struct.unpack_from("<H", hdr, 30)[0]
    nfat = struct.unpack_from("<I", hdr, 44)[0]
    difat = list(struct.unpack_from("<109I", hdr, 76))[:nfat]
    if ssz not in (512, 4096) or nfat == 0 or nfat > 50000:
        return None
    max_sector = 0
    per = ssz // 4
    for idx, fs in enumerate(difat):
        if fs >= 0xFFFFFFFA:
            continue
        data = read(off + (fs + 1) * ssz, ssz)
        if len(data) < ssz:
            break
        vals = struct.unpack(f"<{per}I", data)
        for k, v in enumerate(vals):
            if v != 0xFFFFFFFF:
                max_sector = max(max_sector, idx * per + k)
    size = (max_sector + 2) * ssz
    return size if size <= limit else None


def _7z_size(read, off, limit=500 * MB):
    h = read(off, 32)
    if len(h) < 32:
        return None
    nho, nhs = struct.unpack_from("<QQ", h, 12)
    size = 32 + nho + nhs
    return size if 32 < size <= limit else None


def _sqlite_size(read, off, limit=500 * MB):
    h = read(off, 100)
    if len(h) < 100:
        return None
    ps = struct.unpack_from(">H", h, 16)[0]
    ps = 65536 if ps == 1 else ps
    pages = struct.unpack_from(">I", h, 28)[0]
    size = ps * pages
    return size if 0 < size <= limit and ps in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) else None


def _png_size(read, off, limit=50 * MB):
    """Walk the chunk headers (length + type) to IEND - a few bytes per chunk instead of reading the image."""
    pos = 8
    for _ in range(200000):
        h = read(off + pos, 8)
        if len(h) < 8:
            return None
        ln = struct.unpack_from(">I", h, 0)[0]
        typ = h[4:8]
        if not typ.isalpha() or ln > limit:
            return None
        pos += 12 + ln
        if typ == b"IEND":
            return pos
        if pos > limit:
            return None
    return None


_JPG_NEXT = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")


def _jpg_parse(buf: bytes):
    """Size of a complete JPEG in *buf*, -1 when the structure is invalid, None when more data is needed."""
    pos = 2
    n = len(buf)
    while pos + 4 <= n:
        if buf[pos] != 0xFF:
            return -1
        marker = buf[pos + 1]
        if marker == 0xD9:
            return pos + 2
        if marker == 0xFF:  # fill byte
            pos += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack_from(">H", buf, pos + 2)[0]
        if seglen < 2:
            return -1
        if marker == 0xDA:  # start of scan: entropy coded data until the next non-RST marker
            pos += 2 + seglen
            m = _JPG_NEXT.search(buf, pos)
            if not m:
                return None
            pos = m.start()
            continue
        pos += 2 + seglen
    return None


def _jpg_size(read, off, limit=30 * MB):
    for buf in _grow(read, off, limit, 512 * 1024):
        r = _jpg_parse(buf)
        if r is not None:
            return r if r > 0 else None
    return None


def _lnk_size(read, off, limit=64 * 1024):
    data = read(off, limit)
    try:
        import io

        import LnkParse3

        lnk = LnkParse3.lnk_file(io.BytesIO(data))
        j = lnk.get_json()
        return int(j.get("size") or 0) or None
    except Exception:
        return None


def _pe_size(read, off, limit=100 * MB):
    h = read(off, 4096)
    if h[:2] != b"MZ" or len(h) < 0x40:
        return None
    pe = struct.unpack_from("<I", h, 0x3C)[0]
    if pe + 24 > len(h) or h[pe:pe + 4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack_from("<H", h, pe + 6)[0]
    optsz = struct.unpack_from("<H", h, pe + 20)[0]
    sec = pe + 24 + optsz
    end = 0
    for i in range(min(nsec, 96)):
        s = sec + i * 40
        if s + 40 > len(h):
            break
        rawsz, rawptr = struct.unpack_from("<II", h, s + 16)
        end = max(end, rawptr + rawsz)
    # certificate table (overlay)
    magic = struct.unpack_from("<H", h, pe + 24)[0]
    dd = pe + 24 + (96 if magic == 0x10B else 112)
    if dd + 40 <= len(h):
        cert_off, cert_len = struct.unpack_from("<II", h, dd + 32)
        if cert_off and cert_len:
            end = max(end, cert_off + cert_len)
    return end if 0 < end <= limit else None


# id, search pattern (lower-cased), verify magic at (offset from match), magic, extension, size function, start delta
SIGNATURES = [
    ("pdf", b"%pdf-1.", 0, b"%PDF-1.", "pdf", _pdf_size),
    ("zip", b"pk\x03\x04\x14\x00", 0, b"PK\x03\x04", "zip", _zip_size),
    ("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", _ole_size),
    ("7z", b"7z\xbc\xaf\x27\x1c", 0, b"7z\xbc\xaf\x27\x1c", "7z", _7z_size),
    ("sqlite", b"sqlite format 3\x00", 0, b"SQLite format 3\x00", "sqlite", _sqlite_size),
    ("png", b"\x89png\r\n\x1a\n", 0, b"\x89PNG\r\n\x1a\n", "png", _png_size),
    ("jpg", b"\xff\xd8\xff\xe0\x00\x10jfif", 0, b"\xff\xd8\xff", "jpg", _jpg_size),
    ("jpg_exif", b"\xff\xd8\xff\xe1", 0, b"\xff\xd8\xff\xe1", "jpg", _jpg_size),
    ("lnk", b"l\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0", 0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", _lnk_size),
    ("pe", b"this program cannot be run in dos mode", -0x4E, b"MZ", "exe", _pe_size),
]
SIG_BY_ID = {s[0]: s for s in SIGNATURES}


def refine_extension(data: bytes, ext: str) -> str:
    """docx/xlsx/pptx for OOXML zips, doc/xls/ppt/msg for OLE."""
    if ext == "zip":
        head = data[:4096]
        if b"word/" in data[:65536] or b"[Content_Types].xml" in head and b"word" in data[:200000]:
            return "docx"
        if b"xl/" in data[:65536]:
            return "xlsx"
        if b"ppt/" in data[:65536]:
            return "pptx"
        return "zip"
    if ext == "ole":
        if b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t" in data[:200000]:
            return "doc"
        if b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k" in data[:200000]:
            return "xls"
        if b"P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t" in data[:200000]:
            return "ppt"
        if b"__substg1.0_" in data[:200000] or b"_\x00_\x00s\x00u\x00b\x00s\x00t\x00g" in data[:200000]:
            return "msg"
        return "ole"
    return ext
