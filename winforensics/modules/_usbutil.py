"""Helpers shared by the USB / removable media parsers."""

from __future__ import annotations

import re
import struct

RX_USBSTOR = re.compile(r"(?:USBSTOR|SCSI|STORAGE)[\\#](?P<cls>[^\\#&]+)&Ven_(?P<ven>[^&\\#]*)&Prod_(?P<prod>[^&\\#]*)(?:&Rev_(?P<rev>[^\\#\s]*))?[\\#](?P<serial>[^\\#{\s]+)", re.I)
RX_VIDPID = re.compile(r"VID_(?P<vid>[0-9A-F]{4})&PID_(?P<pid>[0-9A-F]{4})(?:[^\\#\s]*)[\\#](?P<serial>[^\\#{\s]+)", re.I)
NULL_CONTAINER = "{00000000-0000-0000-ffff-ffffffffffff}"
VIRTUAL_VENDORS = ("vmware", "vbox", "virtual", "qemu", "red hat", "msft", "xen", "parallels")
BUS_TYPES = {1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "IEEE 1394", 5: "SSA", 6: "Fibre Channel", 7: "USB", 8: "RAID", 9: "iSCSI",
             10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual", 15: "File-backed virtual", 16: "Storage Spaces",
             17: "NVMe", 18: "SCM", 19: "UFS"}


def clean_serial(serial: str | None) -> str:
    """Strip the instance suffix Windows appends to device serials (``ABC123&0`` -> ``ABC123``)."""
    if not serial:
        return ""
    s = str(serial).strip()
    if re.search(r"&\d+$", s) and not is_windows_generated(s):
        s = s.rsplit("&", 1)[0]
    return s


def is_windows_generated(serial: str) -> bool:
    """Windows generates an instance id (second character '&') when the device has no unique serial."""
    return bool(serial) and len(serial) > 1 and serial[1] == "&"


def serial_key(serial: str | None) -> str:
    return clean_serial(serial).upper()


def parse_instance_id(instance: str) -> dict:
    """Decode a USBSTOR / USB / SWD\\WPDBUSENUM instance id into its parts."""
    out: dict = {}
    if not instance:
        return out
    m = RX_USBSTOR.search(instance)
    if m:
        out.update(device_class=m.group("cls"), vendor=m.group("ven").replace("_", " ").strip(),
                   product=m.group("prod").replace("_", " ").strip(), revision=(m.group("rev") or "").strip(),
                   serial=clean_serial(m.group("serial")))
    m = RX_VIDPID.search(instance)
    if m:
        out.setdefault("serial", clean_serial(m.group("serial")))
        out.update(vid=m.group("vid").upper(), pid=m.group("pid").upper())
    return out


def parse_vbr(vbr: bytes) -> dict:
    """Identify the file system in a volume boot record and pull serial number + label."""
    out: dict = {}
    if not vbr or len(vbr) < 90:
        return out
    oem = vbr[3:11]
    if oem == b"NTFS    ":
        serial = struct.unpack_from("<Q", vbr, 0x48)[0]
        out.update(fs="NTFS", serial=f"{serial:016X}", serial_short=f"{serial & 0xFFFFFFFF:08X}")
    elif oem == b"EXFAT   ":
        if len(vbr) >= 0x68:
            serial = struct.unpack_from("<I", vbr, 0x64)[0]
            out.update(fs="exFAT", serial=f"{serial:08X}", serial_short=f"{serial:08X}")
    elif vbr[3:11] == b"-FVE-FS-":
        out.update(fs="BitLocker")
    elif vbr[82:90].startswith(b"FAT32") or vbr[0x42] in (0x28, 0x29) and vbr[0x52:0x57] == b"FAT32":
        serial = struct.unpack_from("<I", vbr, 0x43)[0]
        label = vbr[0x47:0x52].decode("ascii", "replace").strip()
        out.update(fs="FAT32", serial=f"{serial:08X}", serial_short=f"{serial:08X}", label=label if label != "NO NAME" else "")
    elif vbr[54:59] in (b"FAT12", b"FAT16") or vbr[0x26] == 0x29:
        serial = struct.unpack_from("<I", vbr, 0x27)[0]
        label = vbr[0x2B:0x36].decode("ascii", "replace").strip()
        out.update(fs=vbr[54:59].decode("ascii", "replace").strip() or "FAT", serial=f"{serial:08X}",
                   serial_short=f"{serial:08X}", label=label if label != "NO NAME" else "")
    if "serial_short" in out:
        out["serial_dashed"] = out["serial_short"][:4] + "-" + out["serial_short"][4:]
    return out


def vsn_variants(vsn) -> set[str]:
    """All textual forms a volume serial number takes across artifacts."""
    if vsn is None or vsn == "":
        return set()
    if isinstance(vsn, int):
        v = vsn & 0xFFFFFFFF
    else:
        s = str(vsn).strip().replace("-", "").upper()
        if s.startswith("0X"):
            s = s[2:]
        try:
            v = int(s[-8:], 16) if len(s) >= 8 else int(s, 16)
        except ValueError:
            return set()
    h = f"{v:08X}"
    return {h, h[:4] + "-" + h[4:], str(v), h.lower()}


def norm_vsn(vsn) -> str:
    """Canonical 8 hex char volume serial (``1A2B3C4D``)."""
    for v in vsn_variants(vsn):
        if len(v) == 8 and all(c in "0123456789ABCDEF" for c in v):
            return v
    return ""


def decode_hex_field(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        s = value.strip()
        try:
            return bytes.fromhex(s)
        except ValueError:
            return b""
    return b""
