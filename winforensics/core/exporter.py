"""Parsed-artifact exports for manual analysis.

Every evidence item gets ``<case>/Parsed/E##_<label>/`` containing a CSV per
artifact type (like the per-tool CSV outputs examiners are used to), the full
MFT / FAT listing, the USN journal, keyword hits and the coverage list.  The
event log and SRUM modules add complete dumps (every event, every SRUM table) to
the same folder while they run.
"""

from __future__ import annotations

import csv
import json
import os
import re
import struct
from datetime import timedelta

from .timeutil import from_db, get_tz

csv.field_size_limit(2 ** 31 - 1)


def safe_name(s: str, maxlen: int = 80) -> str:
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", str(s or "")).strip(" ._")
    return (s or "item")[:maxlen]


def evidence_folder(case, ev: dict, kind: str) -> str:
    return case.sub(kind, f"E{ev['id']:02d}_{safe_name(ev.get('label'))}")


class CsvOut:
    """Excel friendly CSV writer (UTF-8 with BOM)."""

    def __init__(self, path: str, headers: list[str]):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.fh = open(path, "w", newline="", encoding="utf-8-sig")
        self.w = csv.writer(self.fh)
        self.w.writerow(headers)
        self.rows = 0

    def row(self, values):
        self.w.writerow([_cell(v) for v in values])
        self.rows += 1

    def close(self):
        self.fh.close()


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list, tuple)):
        s = json.dumps(v, ensure_ascii=False, default=str)
    else:
        s = str(v)
    return s if len(s) < 32000 else s[:32000] + "..."


def local_ts(ts: str | None, tz) -> str:
    if not ts or tz is None:
        return ""
    t = from_db(ts)
    return t.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S") if t else ""


def export_parsed(case, evidence_id: int, progress=None) -> dict:
    progress = progress or (lambda f, s: None)
    db = case.db
    ev = db.evidence(evidence_id)
    out = evidence_folder(case, ev, "Parsed")
    osd = ev.get("os") or {}
    tz = get_tz(osd.get("timezone_iana") or osd.get("timezone_name")) if (osd.get("timezone_iana") or osd.get("timezone_name")) else None
    tzname = getattr(tz, "key", "") if tz else ""
    written = {}
    types = db.artifact_types()
    counts = {r["type"]: r["n"] for r in db.query("SELECT type, COUNT(*) n FROM artifacts WHERE evidence_id=? GROUP BY type", (evidence_id,))}
    total = max(1, len(counts) + 3)
    done = 0
    # ---------------------------------------------------------------- artifact types
    for t, n in sorted(counts.items()):
        meta = types.get(t, {"title": t, "category": "Other", "columns": []})
        cols = [c["name"] for c in meta.get("columns", [])]
        # union of keys actually present, defined columns first
        extra = []
        seen = set(cols)
        for r in db.iquery("SELECT data_json FROM artifacts WHERE evidence_id=? AND type=? LIMIT 2000", (evidence_id, t)):
            for k in json.loads(r["data_json"] or "{}"):
                if k not in seen and k not in ("event_data",):
                    seen.add(k)
                    extra.append(k)
        keys = cols + extra
        titles = [c["title"] for c in meta.get("columns", [])] + extra
        path = os.path.join(out, safe_name(meta.get("category") or "Other"), safe_name(meta.get("title") or t) + ".csv")
        w = CsvOut(path, ["TimeUTC", f"TimeLocal ({tzname or 'n/a'})", "TimeMeaning", "User"] + titles + ["Summary", "Source", "Tags"]
                   + (["EventData"] if t.startswith("evt_") or t == "usb_event" else []))
        for r in db.iquery("SELECT * FROM artifacts WHERE evidence_id=? AND type=? ORDER BY ts", (evidence_id, t)):
            d = json.loads(r["data_json"] or "{}")
            row = [(r["ts"] or "")[:23], local_ts(r["ts"], tz), r["ts_label"], r["user"]] + [d.get(k) for k in keys] + \
                  [r["summary"], r["source"], r["tags"]]
            if t.startswith("evt_") or t == "usb_event":
                row.append(d.get("event_data"))
            w.row(row)
        w.close()
        written[t] = path
        done += 1
        progress(done / total, f"Parsed export: {meta.get('title')}")
    # ---------------------------------------------------------------- file system listing
    for v in db.volumes(evidence_id):
        path = os.path.join(out, "File System", f"FileSystem_{safe_name(v['name'])}_{v.get('fs') or 'fs'}.csv")
        w = CsvOut(path, ["Volume", "EntryNumber", "Sequence", "ParentEntry", "Path", "Name", "Extension", "Size", "IsDirectory",
                          "InUse", "SI_Created", "SI_Modified", "SI_Accessed", "SI_RecordChanged", "FN_Created", "FN_Modified",
                          "FN_Accessed", "FN_RecordChanged", "AlternateDataStreams", "Resident", "Flags", "MD5", "SHA1", "SHA256",
                          "Recovery"])
        for r in db.iquery("SELECT * FROM fs_entries WHERE evidence_id=? AND volume=? ORDER BY path", (evidence_id, v["name"])):
            w.row([r["volume"], r["record"], r["seq"], r["parent"], r["path"], r["name"], r["ext"], r["size"], r["is_dir"],
                   0 if r["deleted"] else 1, r["si_created"], r["si_modified"], r["si_accessed"], r["si_changed"], r["fn_created"],
                   r["fn_modified"], r["fn_accessed"], r["fn_changed"], r["ads"], r["resident"], r["flags"], r["md5"], r["sha1"],
                   r["sha256"], r["recover"]])
        w.close()
        written[f"fs:{v['name']}"] = path
    progress((done + 1) / total, "Parsed export: file system")
    n_usn = db.scalar("SELECT COUNT(*) FROM usn WHERE evidence_id=?", (evidence_id,)) or 0
    if n_usn:
        path = os.path.join(out, "File System", "UsnJrnl_J.csv")
        w = CsvOut(path, ["Volume", "UpdateTimestampUTC", "USN", "EntryNumber", "Sequence", "ParentEntry", "Name", "Path",
                          "UpdateReasons", "ReasonFlags", "FileAttributes"])
        for r in db.iquery("SELECT * FROM usn WHERE evidence_id=? ORDER BY usn", (evidence_id,)):
            w.row([r["volume"], r["ts"], r["usn"], r["record"], r["seq"], r["parent"], r["name"], r["path"], r["reason"],
                   f"0x{r['reason_flags']:08X}" if r["reason_flags"] is not None else "", f"0x{r['attributes']:X}" if r["attributes"] else ""])
        w.close()
        written["usn"] = path
    # ---------------------------------------------------------------- hits / coverage
    path = os.path.join(out, "Search", "Keyword_Hits.csv")
    w = CsvOut(path, ["Term", "Origin", "Search", "Area", "Volume", "VolumeOffset", "Length", "Encoding", "AttributedTo", "Context",
                      "ContextHex", "Detail"])
    for h in db.iquery("SELECT * FROM hits WHERE evidence_id=? ORDER BY term, area", (evidence_id,)):
        w.row([h["term"], h["term_kind"], h["search"], h["area"], h["volume"], h["offset"], h["length"], h["encoding"], h["file_path"],
               h["context_text"], h["context_hex"], h["detail_json"]])
    w.close()
    # ---------------------------------------------------------------- super timeline (every dated artifact, one file)
    path = os.path.join(out, "SuperTimeline.csv")
    w = CsvOut(path, ["TimeUTC", f"TimeLocal ({tzname or 'n/a'})", "TimeMeaning", "Category", "Artifact", "User", "Summary",
                      "Source", "Tags"])
    for r in db.iquery("SELECT ts, ts_label, type, user, summary, source, tags FROM artifacts WHERE evidence_id=? AND ts IS NOT NULL "
                       "AND ts <> '' ORDER BY ts", (evidence_id,)):
        meta = types.get(r["type"], {})
        w.row([(r["ts"] or "")[:23], local_ts(r["ts"], tz), r["ts_label"], meta.get("category") or "", meta.get("title") or r["type"],
               r["user"], r["summary"], r["source"], r["tags"]])
    w.close()
    written["supertimeline"] = path
    path = os.path.join(out, "Coverage.csv")
    w = CsvOut(path, ["Module", "Artifact", "LocationChecked", "Result", "Records", "Notes"])
    for c in db.iquery("SELECT * FROM coverage WHERE evidence_id=? ORDER BY id", (evidence_id,)):
        w.row([c["module"], c["artifact"], c["location"], c["status"], c["count"], c["detail"]])
    w.close()
    with open(os.path.join(out, "README.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Parsed artifacts for evidence E{evidence_id:02d} '{ev.get('label')}' ({osd.get('hostname') or ''})\n"
                 f"Image: {ev.get('path')}\n\nAll times are UTC unless the column says otherwise; local time column uses {tzname or 'n/a'}.\n"
                 "Folders are named after the artifact category; every CSV opens directly in Excel / Timeline Explorer.\n"
                 "File System\\FileSystem_*.csv  - every MFT / FAT entry incl. deleted ones, $SI and $FN timestamps\n"
                 "File System\\UsnJrnl_J.csv     - NTFS change journal\n"
                 "Event Logs - all records\\     - every record of every EVTX file (flattened payload)\n"
                 "SRUM\\                          - every table of SRUDB.dat with application / user ids resolved\n"
                 "Search\\Keyword_Hits.csv       - physical and logical keyword hits with area attribution\n"
                 "SuperTimeline.csv             - every dated artifact of every type in one chronological list\n"
                 "Coverage.csv                  - every location examined and the result\n")
    progress(1.0, "Parsed export complete")
    return written


# ---------------------------------------------------------------------- generic ESE dump (SRUM)
def _sid(b: bytes) -> str:
    try:
        rev, n = b[0], b[1]
        auth = int.from_bytes(b[2:8], "big")
        subs = struct.unpack_from(f"<{n}I", b, 8)
        return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs)
    except Exception:
        return b.hex()


SRUM_TABLES = {
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "Network Usage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "Application Resource Usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Connectivity",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "Energy Usage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "Energy Usage (long term)",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": "Application Timeline",
    "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}": "VFU Provider",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "Push Notifications",
    "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "Energy Estimator",
    "SruDbIdMapTable": "Id Map",
}


def dump_srum(fh, out_dir: str, users: dict | None = None) -> dict:
    """Write every table of SRUDB.dat to CSV with AppId / UserId resolved."""
    from dissect.database.ese import ESE

    from .timeutil import db_ts, filetime

    db = ESE(fh)
    idmap = {}
    try:
        t = db.table("SruDbIdMapTable")
        for rec in t.records():
            d = rec.as_dict()
            blob = d.get("IdBlob") or b""
            typ = d.get("IdType")
            if typ == 3:
                val = _sid(blob)
                val = f"{val} ({users[val]})" if users and val in users else val
            else:
                try:
                    val = blob.decode("utf-16-le").rstrip("\x00")
                except Exception:
                    val = blob.hex() if isinstance(blob, bytes) else str(blob)
            idmap[d.get("IdIndex")] = val
    except Exception:
        pass
    out = {}
    for table in db.tables():
        name = table.name
        if name.startswith("MSys"):
            continue
        title = SRUM_TABLES.get(name, name)
        cols = table.column_names
        path = os.path.join(out_dir, f"SRUM_{safe_name(title)}.csv")
        extra = [f"{c}_Resolved" for c in cols if c in ("AppId", "UserId")]
        w = CsvOut(path, cols + extra)
        n = 0
        for rec in table.records():
            try:
                d = rec.as_dict()
            except Exception:
                continue
            row = []
            for c in cols:
                v = d.get(c)
                if c == "TimeStamp" and isinstance(v, float):
                    v = db_ts(_ole_date(v))
                elif isinstance(v, int) and c.lower().endswith(("time", "starttime", "endtime")) and v > 1e17:
                    v = db_ts(filetime(v))
                elif isinstance(v, bytes):
                    v = v.hex() if len(v) < 512 else v[:512].hex() + "..."
                row.append(v)
            for c in cols:
                if c in ("AppId", "UserId"):
                    row.append(idmap.get(d.get(c), ""))
            w.row(row)
            n += 1
        w.close()
        out[title] = (path, n)
    return out


def _ole_date(v: float):
    from datetime import datetime, timezone

    try:
        return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=v)
    except Exception:
        return None
