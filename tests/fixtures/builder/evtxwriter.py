"""EVTX writer producing template-based Binary XML records (like Windows does).

Every record carries its own inline template definition followed by typed
substitution values, which is valid per [MS-EVEN6] and parses with dissect,
python-evtx, EvtxECmd and Windows Event Viewer style parsers.
"""

from __future__ import annotations

import binascii
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .regwriter import filetime

T_NULL = 0x00
T_STRING = 0x01
T_UINT8 = 0x04
T_UINT16 = 0x06
T_UINT32 = 0x08
T_UINT64 = 0x0A
T_BINARY = 0x0E
T_GUID = 0x0F
T_FILETIME = 0x11
T_SID = 0x13
T_HEXINT64 = 0x15

CHUNK_SIZE = 0x10000


def _name_hash(name: str) -> int:
    h = 0
    for ch in name:
        h = (h * 65599 + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


def _sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    rev = int(parts[1])
    auth = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    return struct.pack("<BB", rev, len(subs)) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def _encode_value(vtype: int, value) -> bytes:
    if value is None:
        return b""
    if vtype == T_STRING:
        return str(value).encode("utf-16-le")
    if vtype == T_UINT8:
        return struct.pack("<B", int(value))
    if vtype == T_UINT16:
        return struct.pack("<H", int(value))
    if vtype == T_UINT32:
        return struct.pack("<I", int(value))
    if vtype in (T_UINT64, T_HEXINT64):
        return struct.pack("<Q", int(value))
    if vtype == T_BINARY:
        return bytes(value)
    if vtype == T_GUID:
        return uuid.UUID(str(value)).bytes_le
    if vtype == T_FILETIME:
        return struct.pack("<Q", filetime(value))
    if vtype == T_SID:
        return _sid_bytes(value)
    raise ValueError(vtype)


@dataclass
class Event:
    provider: str
    event_id: int
    channel: str
    computer: str
    time: datetime
    data: dict = field(default_factory=dict)  # Data Name -> value (str/int/bytes)
    provider_guid: str | None = None
    level: int = 4
    task: int = 0
    opcode: int = 0
    version: int = 0
    keywords: int = 0x8000000000000000
    user_sid: str | None = None
    process_id: int = 4
    thread_id: int = 128
    user_data: dict | None = None  # rendered as <UserData><EventXML>..</EventXML></UserData>
    user_data_name: str = "EventXML"


class _BinXml:
    """Builds BinXML for one record; offsets are chunk-relative."""

    def __init__(self, base_offset: int):
        self.base = base_offset
        self.buf = bytearray()

    @property
    def off(self) -> int:
        return self.base + len(self.buf)

    def u8(self, v):
        self.buf += struct.pack("<B", v)

    def u16(self, v):
        self.buf += struct.pack("<H", v)

    def u32(self, v):
        self.buf += struct.pack("<I", v)

    def name(self, name: str) -> None:
        # name offset pointing right after itself -> inline name definition
        self.u32(self.off + 4)
        self.u32(0)
        self.u16(_name_hash(name))
        self.u16(len(name))
        self.buf += name.encode("utf-16-le") + b"\x00\x00"


class _Template:
    """Template element tree with substitution slots."""

    def __init__(self):
        self.values: list[tuple[int, object]] = []

    def sub(self, vtype: int, value) -> int:
        self.values.append((vtype, value))
        return len(self.values) - 1


def _element(bx: _BinXml, name: str, attrs: list[tuple[str, int]] | None, content) -> None:
    """Write an element inside a template.

    ``attrs`` is a list of (attr_name, substitution_index).  ``content`` is None
    (empty element), an int substitution index, or a callable writing children.
    """
    token = 0x41 if attrs else 0x01
    bx.u8(token)
    bx.u16(0xFFFF)  # dependency identifier
    size_pos = len(bx.buf)
    bx.u32(0)  # data size placeholder
    start = len(bx.buf)
    bx.name(name)
    if attrs:
        attr_size_pos = len(bx.buf)
        bx.u32(0)
        attr_start = len(bx.buf)
        for i, (aname, sub_idx) in enumerate(attrs):
            bx.u8(0x46 if i < len(attrs) - 1 else 0x06)
            bx.name(aname)
            bx.u8(0x0E)  # optional substitution
            bx.u16(sub_idx)
            bx.u8(_TYPES_IN_TEMPLATE[sub_idx])
        struct.pack_into("<I", bx.buf, attr_size_pos, len(bx.buf) - attr_start)
    if content is None:
        bx.u8(0x03)
    else:
        bx.u8(0x02)
        if callable(content):
            content()
        else:
            bx.u8(0x0E)
            bx.u16(content)
            bx.u8(_TYPES_IN_TEMPLATE[content])
        bx.u8(0x04)
    struct.pack_into("<I", bx.buf, size_pos, len(bx.buf) - start)


_TYPES_IN_TEMPLATE: dict[int, int] = {}


def _record_binxml(ev: Event, record_id: int, base_offset: int) -> bytes:
    global _TYPES_IN_TEMPLATE
    tpl = _Template()

    def s(vtype, value):
        idx = tpl.sub(vtype, value)
        _TYPES_IN_TEMPLATE[idx] = vtype
        return idx

    _TYPES_IN_TEMPLATE = {}
    bx = _BinXml(base_offset)
    bx.buf += b"\x0f\x01\x01\x00"  # fragment header
    bx.u8(0x0C)  # template instance
    bx.u8(0x01)
    tpl_id = binascii.crc32(f"{ev.provider}{ev.event_id}{sorted(ev.data)}".encode())
    bx.u32(tpl_id)
    bx.u32(bx.off + 4)  # definition follows inline
    def_hdr_pos = len(bx.buf)
    bx.u32(0)  # next template offset
    bx.buf += uuid.uuid5(uuid.NAMESPACE_DNS, f"{tpl_id}").bytes_le
    bx.u32(0)  # data size placeholder
    def_start = len(bx.buf)
    bx.buf += b"\x0f\x01\x01\x00"

    provider_attrs = [("Name", s(T_STRING, ev.provider))]
    if ev.provider_guid:
        provider_attrs.append(("Guid", s(T_GUID, ev.provider_guid)))
    i_eventid = s(T_UINT16, ev.event_id)
    i_version = s(T_UINT8, ev.version)
    i_level = s(T_UINT8, ev.level)
    i_task = s(T_UINT16, ev.task)
    i_opcode = s(T_UINT8, ev.opcode)
    i_keywords = s(T_HEXINT64, ev.keywords)
    i_time = s(T_FILETIME, ev.time)
    i_recid = s(T_UINT64, record_id)
    i_pid = s(T_UINT32, ev.process_id)
    i_tid = s(T_UINT32, ev.thread_id)
    i_channel = s(T_STRING, ev.channel)
    i_computer = s(T_STRING, ev.computer)
    i_user = s(T_SID, ev.user_sid) if ev.user_sid else None

    data_items = []
    for k, v in ev.data.items():
        if isinstance(v, (bytes, bytearray)):
            data_items.append((k, s(T_BINARY, v)))
        else:
            data_items.append((k, s(T_STRING, "" if v is None else str(v))))
    user_items = []
    if ev.user_data:
        for k, v in ev.user_data.items():
            user_items.append((k, s(T_STRING, str(v))))

    def system_children():
        _element(bx, "Provider", provider_attrs, None)
        _element(bx, "EventID", None, i_eventid)
        _element(bx, "Version", None, i_version)
        _element(bx, "Level", None, i_level)
        _element(bx, "Task", None, i_task)
        _element(bx, "Opcode", None, i_opcode)
        _element(bx, "Keywords", None, i_keywords)
        _element(bx, "TimeCreated", [("SystemTime", i_time)], None)
        _element(bx, "EventRecordID", None, i_recid)
        _element(bx, "Correlation", None, None)
        _element(bx, "Execution", [("ProcessID", i_pid), ("ThreadID", i_tid)], None)
        _element(bx, "Channel", None, i_channel)
        _element(bx, "Computer", None, i_computer)
        if i_user is not None:
            _element(bx, "Security", [("UserID", i_user)], None)
        else:
            _element(bx, "Security", None, None)

    def eventdata_children():
        for name, idx in data_items:
            _element(bx, "Data", [("Name", s_name[name])], idx)

    # names for Data elements are literal attribute values, not substitutions
    s_name: dict[str, int] = {}

    def data_element(name: str, idx: int):
        bx.u8(0x41)
        bx.u16(0xFFFF)
        size_pos = len(bx.buf)
        bx.u32(0)
        start = len(bx.buf)
        bx.name("Data")
        attr_size_pos = len(bx.buf)
        bx.u32(0)
        attr_start = len(bx.buf)
        bx.u8(0x06)
        bx.name("Name")
        bx.u8(0x05)  # literal value
        bx.u8(0x01)
        bx.u16(len(name))
        bx.buf += name.encode("utf-16-le")
        struct.pack_into("<I", bx.buf, attr_size_pos, len(bx.buf) - attr_start)
        bx.u8(0x02)
        bx.u8(0x0E)
        bx.u16(idx)
        bx.u8(_TYPES_IN_TEMPLATE[idx])
        bx.u8(0x04)
        struct.pack_into("<I", bx.buf, size_pos, len(bx.buf) - start)

    def literal_element(name: str, idx: int):
        _element(bx, name, None, idx)

    def event_children():
        _element(bx, "System", None, system_children)
        if ev.user_data is not None:
            def ud():
                def inner():
                    for name, idx in user_items:
                        literal_element(name, idx)
                _element(bx, ev.user_data_name, None, inner)
            _element(bx, "UserData", None, ud)
        else:
            def ed():
                for name, idx in data_items:
                    data_element(name, idx)
            _element(bx, "EventData", None, ed)

    # <Event xmlns=...> : the xmlns attribute is a literal value
    bx.u8(0x41)
    bx.u16(0xFFFF)
    size_pos = len(bx.buf)
    bx.u32(0)
    start = len(bx.buf)
    bx.name("Event")
    attr_size_pos = len(bx.buf)
    bx.u32(0)
    attr_start = len(bx.buf)
    bx.u8(0x06)
    bx.name("xmlns")
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    bx.u8(0x05)
    bx.u8(0x01)
    bx.u16(len(ns))
    bx.buf += ns.encode("utf-16-le")
    struct.pack_into("<I", bx.buf, attr_size_pos, len(bx.buf) - attr_start)
    bx.u8(0x02)
    event_children()
    bx.u8(0x04)
    struct.pack_into("<I", bx.buf, size_pos, len(bx.buf) - start)
    bx.u8(0x00)  # end of template fragment
    struct.pack_into("<I", bx.buf, def_hdr_pos + 20, len(bx.buf) - def_start)

    # substitution value descriptors + data
    encoded = [_encode_value(t, v) for t, v in tpl.values]
    bx.u32(len(encoded))
    for (t, _), data in zip(tpl.values, encoded):
        bx.u16(len(data))
        bx.u8(t if data else T_NULL)
        bx.u8(0)
    for data in encoded:
        bx.buf += data
    bx.u8(0x00)  # end of stream
    return bytes(bx.buf)


def write_evtx(path: str, events: list[Event]) -> None:
    events = sorted(events, key=lambda e: e.time)
    chunks: list[bytes] = []
    record_id = 1
    i = 0
    while i < len(events) or not chunks:
        chunk = bytearray(CHUNK_SIZE)
        pos = 512
        first_id = record_id
        last_rec_off = 0
        while i < len(events):
            ev = events[i]
            binxml = _record_binxml(ev, record_id, pos + 24)
            size = 24 + len(binxml) + 4
            size = (size + 7) & ~7
            if pos + size > CHUNK_SIZE:
                break
            rec = struct.pack("<IIQQ", 0x2A2A, size, record_id, filetime(ev.time)) + binxml
            rec = rec.ljust(size - 4, b"\x00") + struct.pack("<I", size)
            chunk[pos:pos + size] = rec
            last_rec_off = pos
            pos += size
            record_id += 1
            i += 1
        last_id = record_id - 1
        hdr = struct.pack("<8sQQQQIIII", b"ElfChnk\x00", first_id, last_id, first_id, last_id, 128, last_rec_off, pos, 0)
        chunk[0:len(hdr)] = hdr
        struct.pack_into("<I", chunk, 0x34, binascii.crc32(bytes(chunk[512:pos])) & 0xFFFFFFFF)
        crc = binascii.crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])) & 0xFFFFFFFF
        struct.pack_into("<I", chunk, 0x7C, crc)
        chunks.append(bytes(chunk))
        if not events:
            break

    header = bytearray(4096)
    struct.pack_into("<8sQQQIHHHH", header, 0, b"ElfFile\x00", 0, len(chunks) - 1, record_id, 128, 2, 3, 4096, len(chunks))
    struct.pack_into("<I", header, 0x78, 0)
    struct.pack_into("<I", header, 0x7C, binascii.crc32(bytes(header[:120])) & 0xFFFFFFFF)
    with open(path, "wb") as fh:
        fh.write(header)
        for c in chunks:
            fh.write(c)


def utc(*a) -> datetime:
    return datetime(*a, tzinfo=timezone.utc)
