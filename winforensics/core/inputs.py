"""Case inputs supplied by the examiner and their normalization.

Everything the examiner knows about the case background is optional - a DLP
export, a list of target files / hashes, the actual reference documents, USB
serial numbers, suspect users, a time window, keywords, IOCs, malware samples.
:func:`normalize` turns whatever was supplied into a uniform structure that the
search engines and analyzers consume.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from datetime import timedelta

from .timeutil import db_ts, parse_any

HEX = {32: "md5", 40: "sha1", 64: "sha256"}

DLP_COLUMNS = {
    "time": ["happened (utc)", "happened", "timestamp", "event time", "eventtime", "time (utc)", "date (utc)", "occurred",
             "detected", "date/time", "datetime", "creation time", "creationtime", "time", "date", "created", "utc time", "event date"],
    "activity": ["activity", "action", "operation", "event type", "eventtype", "event", "activity type", "type", "channel"],
    "user": ["user principal name", "upn", "user", "username", "user name", "account", "actor", "userid", "user id", "user email",
             "sender", "initiator"],
    "device": ["device name", "devicename", "device", "computer name", "computer", "hostname", "host name", "host", "endpoint",
               "machine", "workstation", "client name"],
    "file_name": ["file name", "filename", "object name", "document name", "document", "file", "name", "object"],
    "file_path": ["file path", "filepath", "source path", "source file path", "full path", "object path", "path", "location",
                  "source location"],
    "target_path": ["target file path", "destination file path", "target path", "destination path", "copied to"],
    "size": ["file size", "filesize", "size (bytes)", "size", "bytes"],
    "sha256": ["sha256", "sha-256", "sha256 hash", "file sha256", "sha 256"],
    "sha1": ["sha1", "sha-1", "sha1 hash", "file sha1"],
    "md5": ["md5", "md5 hash", "file md5"],
    "usb_serial": ["removable media serial", "removable media device serial number", "removable media serial number",
                   "device serial", "usb serial", "media serial", "serial number", "serialnumber", "serial"],
    "usb_name": ["removable media", "removable media device model", "removable media device name", "media name", "usb device",
                 "device model", "removable media device manufacturer"],
    "destination": ["target domain", "destination domain", "target url", "destination url", "url", "domain", "destination",
                    "cloud app", "cloud application", "service", "recipients", "recipient", "to", "website"],
    "policy": ["policy", "policy name", "policy matches", "rule name", "rule", "matched policy", "dlp policy", "sensitive info type"],
}


def _norm_header(h: str) -> str:
    return re.sub(r"\s+", " ", str(h or "").strip().lower().replace("_", " "))


def map_columns(headers: list[str]) -> dict[str, str]:
    """Best-effort mapping of export column headers to normalized fields."""
    norm = {_norm_header(h): h for h in headers}
    used = set()
    mapping = {}
    for field, cands in DLP_COLUMNS.items():
        for c in cands:
            if c in norm and norm[c] not in used:
                mapping[field] = norm[c]
                used.add(norm[c])
                break
        else:
            for nh, orig in norm.items():
                if orig in used:
                    continue
                if any(c in nh for c in cands if len(c) > 4):
                    mapping[field] = orig
                    used.add(orig)
                    break
    return mapping


def read_table(path: str) -> list[dict]:
    """Rows of a CSV / TSV / XLSX / JSON export as dicts."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xlsm", ".xls"):
        import openpyxl

        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        ws = wb.worksheets[0]
        rows = list(ws.iter_rows(values_only=True))
        hdr_idx = 0
        for i, r in enumerate(rows[:20]):
            if sum(1 for c in r if c not in (None, "")) >= 2:
                hdr_idx = i
                break
        headers = [str(c or f"col{i}") for i, c in enumerate(rows[hdr_idx])]
        return [dict(zip(headers, r)) for r in rows[hdr_idx + 1:] if any(c not in (None, "") for c in r)]
    if ext == ".json":
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            for k in ("value", "items", "events", "data", "results", "records"):
                if isinstance(data.get(k), list):
                    data = data[k]
                    break
            else:
                data = [dict(v, name=k) if isinstance(v, dict) else {"name": k, "value": v} for k, v in data.items()]
        return [_flatten(r) for r in data if isinstance(r, dict)]
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", "replace")
    sample = text[:5000]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    lines = text.splitlines()
    # skip preamble lines (some products prepend report titles)
    start = 0
    for i, line in enumerate(lines[:30]):
        if line.count(dialect.delimiter) >= 2:
            start = i
            break
    return list(csv.DictReader(io.StringIO("\n".join(lines[start:])), dialect=dialect))


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        elif isinstance(v, list):
            out[key] = ", ".join(str(x) for x in v)
        else:
            out[key] = v
    return out


def channel_of(activity: str, destination: str = "", usb: str = "") -> str:
    a = f"{activity} {destination}".lower()
    if usb or re.search(r"removable|usb|external drive|copytoremovable|copiedtoremovable", a):
        return "removable_media"
    if re.search(r"print", a):
        return "print"
    if re.search(r"e-?mail|smtp|outlook|exchange|mail ", a):
        return "email"
    if re.search(r"clipboard", a):
        return "clipboard"
    if re.search(r"bluetooth", a):
        return "bluetooth"
    if re.search(r"share|smb|unc|network", a):
        return "network_share"
    if re.search(r"cloud|upload|browser|web|http|domain|url|gmail|drive|dropbox|onedrive", a) or destination:
        return "web_upload"
    return "other"


def load_dlp_export(path: str, mapping: dict | None = None) -> dict:
    rows = read_table(path)
    headers = list(rows[0].keys()) if rows else []
    mapping = mapping or map_columns(headers)
    events = []
    for r in rows:
        def get(field):
            col = mapping.get(field)
            v = r.get(col) if col else None
            return "" if v is None else str(v).strip()

        ev = {f: get(f) for f in DLP_COLUMNS}
        ts = parse_any(ev["time"])
        ev["time"] = db_ts(ts) if ts else ev["time"]
        if not ev["file_name"] and ev["file_path"]:
            ev["file_name"] = re.split(r"[\\/]", ev["file_path"])[-1]
        for h in ("sha256", "sha1", "md5"):
            ev[h] = ev[h].lower()
        # hash in an unnamed column?
        if not (ev["sha256"] or ev["sha1"] or ev["md5"]):
            for v in r.values():
                s = str(v or "").strip().lower()
                if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", s):
                    ev[HEX[len(s)]] = s
        try:
            ev["size"] = int(float(ev["size"])) if ev["size"] else None
        except ValueError:
            ev["size"] = None
        ev["channel"] = channel_of(ev["activity"], ev["destination"], ev["usb_serial"])
        ev["raw"] = {str(k): str(v) for k, v in r.items() if v not in (None, "")}
        events.append(ev)
    return {"source": path, "mapping": mapping, "headers": headers, "events": events}


def load_hash_list(path: str) -> list[dict]:
    """Targets from a hash list (txt / csv / json / xlsx)."""
    ext = os.path.splitext(path)[1].lower()
    out = []
    if ext in (".txt", ".hash", ".md5", ".sha256", ".sha1", ".lst"):
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                m = re.search(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b", line)
                if not m:
                    continue
                h = m.group(1).lower()
                rest = (line[:m.start()] + line[m.end():]).strip(" \t*,;|")
                out.append({"name": os.path.basename(rest) if rest else "", HEX[len(h)]: h, "source": os.path.basename(path)})
        return out
    if ext == ".json":
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
            for name, d in data.items():
                out.append({"name": name, "sha256": (d.get("sha256") or "").lower(), "md5": (d.get("md5") or "").lower(),
                            "sha1": (d.get("sha1") or "").lower(), "size": d.get("size"), "source": os.path.basename(path)})
            return out
    rows = read_table(path)
    mapping = map_columns(list(rows[0].keys())) if rows else {}
    for r in rows:
        t = {"source": os.path.basename(path)}
        for f in ("file_name", "file_path", "size", "sha256", "sha1", "md5"):
            col = mapping.get(f)
            if col and r.get(col) not in (None, ""):
                t[{"file_name": "name", "file_path": "path"}.get(f, f)] = str(r[col]).strip()
        for v in r.values():
            s = str(v or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", s):
                t.setdefault(HEX[len(s)], s)
        if any(t.get(h) for h in ("sha256", "sha1", "md5")) or t.get("name"):
            out.append(t)
    return out


def hash_file(path: str) -> dict:
    h = {a: hashlib.new(a) for a in ("md5", "sha1", "sha256")}
    size = 0
    with open(path, "rb") as fh:
        while True:
            b = fh.read(4 * 1024 * 1024)
            if not b:
                break
            size += len(b)
            for x in h.values():
                x.update(b)
    return {"size": size, **{k: v.hexdigest() for k, v in h.items()}}


def reference_file(path: str) -> dict:
    """Target description from an examiner supplied copy of the sensitive file (hash + metadata + text sample)."""
    t = {"name": os.path.basename(path), "path": path, "source": "reference file", **hash_file(path)}
    try:
        from ..modules.documents import extract

        with open(path, "rb") as fh:
            data = fh.read(100 * 1024 * 1024)
        meta, text = extract(data, os.path.splitext(path)[1][1:])
        t["meta"] = {k: str(v)[:200] for k, v in meta.items()}
        t["text_sample"] = re.sub(r"\s+", " ", text)[:20000]
    except Exception:
        pass
    return t


# --------------------------------------------------------------------------- normalization
def _clean_hash(v) -> str:
    s = str(v or "").strip().lower()
    return s if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", s) else ""


def normalize(raw: dict) -> dict:
    """Merge every examiner input into a single consumable structure."""
    raw = raw or {}
    targets: list[dict] = []

    def add_target(t: dict):
        t = dict(t)
        for h in ("md5", "sha1", "sha256"):
            t[h] = _clean_hash(t.get(h))
        t["name"] = (t.get("name") or (re.split(r"[\\/]", t.get("path") or "")[-1] if t.get("path") else "")).strip()
        try:
            t["size"] = int(t["size"]) if t.get("size") not in (None, "") else None
        except (TypeError, ValueError):
            t["size"] = None
        if not (t["name"] or t["md5"] or t["sha1"] or t["sha256"]):
            return
        for ex in targets:
            same_hash = any(t[h] and t[h] == ex.get(h) for h in ("md5", "sha1", "sha256"))
            if same_hash or (t["name"] and t["name"].lower() == (ex.get("name") or "").lower() and
                             not any(t[h] and ex.get(h) and t[h] != ex[h] for h in ("md5", "sha1", "sha256"))):
                for k, v in t.items():
                    if v and not ex.get(k):
                        ex[k] = v
                ex["sources"] = sorted(set(ex.get("sources", [])) | set(t.get("sources", [t.get("source", "")])) - {""})
                return
        t["sources"] = sorted(set(t.get("sources", [t.get("source", "")])) - {""})
        targets.append(t)

    dlp_events = []
    for d in raw.get("dlp_exports", []) or []:
        for ev in d.get("events", []):
            dlp_events.append(ev)
            add_target({"name": ev.get("file_name"), "path": ev.get("file_path"), "size": ev.get("size"), "md5": ev.get("md5"),
                        "sha1": ev.get("sha1"), "sha256": ev.get("sha256"), "source": "DLP export"})
    for t in raw.get("targets", []) or []:
        add_target({**t, "source": t.get("source") or "examiner"})
    for t in raw.get("reference_files", []) or []:
        add_target({**t, "source": "reference file"})
    sample_reports = [r for r in raw.get("sample_reports", []) or [] if r.get("sha256")]
    for r in sample_reports:
        add_target({"name": r["name"], "size": r["size"], "md5": r["md5"], "sha1": r["sha1"], "sha256": r["sha256"],
                    "source": "malware sample"})
        for ch in r.get("children", []):
            if ch.get("type") in ("PE", "Windows shortcut (LNK)") or str(ch.get("type", "")).startswith("Script"):
                add_target({"name": re.split(r"[\\/]", ch["name"])[-1], "size": ch["size"], "md5": ch["md5"], "sha1": ch["sha1"],
                            "sha256": ch["sha256"], "source": "malware sample (archive member)"})

    usb_serials = {s.strip() for s in raw.get("usb_serials", []) or [] if str(s).strip()}
    users = {s.strip() for s in raw.get("suspect_users", []) or [] if str(s).strip()}
    domains = {s.strip().lower() for s in raw.get("domains", []) or [] if str(s).strip()}
    devices = set()
    for ev in dlp_events:
        if ev.get("usb_serial"):
            usb_serials.add(ev["usb_serial"])
        if ev.get("user"):
            users.add(ev["user"].split("@")[0].split("\\")[-1])
        if ev.get("device"):
            devices.add(ev["device"])
        if ev.get("destination") and ev["channel"] == "web_upload":
            for d in re.split(r"[;, ]+", ev["destination"]):
                if "." in d:
                    domains.add(d.lower().strip())

    # time window: explicit, otherwise derived from DLP events (+/- padding)
    tw = raw.get("time_window") or {}
    start, end = parse_any(tw.get("start")), parse_any(tw.get("end"))
    derived = False
    ev_times = sorted(t for t in (parse_any(e.get("time")) for e in dlp_events) if t)
    if not start and not end and ev_times:
        pad = timedelta(hours=float(raw.get("window_padding_hours", 24)))
        start, end = ev_times[0] - pad, ev_times[-1] + pad
        derived = True

    keywords: list[dict] = []

    def kw(term, label, source, regex=False, case=False):
        term = str(term or "").strip()
        if len(term) < 3:
            return
        if any(k["term"].lower() == term.lower() and k["regex"] == regex for k in keywords):
            return
        keywords.append({"term": term, "label": label, "source": source, "regex": regex, "case": case})

    for k in raw.get("keywords", []) or []:
        if isinstance(k, dict):
            kw(k.get("term"), k.get("label") or "keyword", "examiner", k.get("regex", False), k.get("case", False))
        else:
            kw(k, "keyword", "examiner")
    if raw.get("auto_keywords", True):
        for t in targets:
            if t.get("name"):
                kw(t["name"], "target file name", "derived")
                stem = os.path.splitext(t["name"])[0]
                if len(stem) >= 6 and stem.lower() not in ("document", "untitled", "report", "invoice", "new folder"):
                    kw(stem, "target file stem", "derived")
        for s in usb_serials:
            if len(s) >= 6:
                kw(s, "USB serial", "derived")
        for d in domains:
            kw(d, "destination domain", "derived")
    iocs = {k: list(v) for k, v in (raw.get("iocs") or {}).items()}
    from ..knowledge import BENIGN_DOMAINS

    for r in sample_reports:
        si = r.get("iocs") or {}
        for kind in ("urls", "ips", "domains"):
            for v in si.get(kind, [])[:40]:
                if kind == "domains" and v.endswith(BENIGN_DOMAINS):
                    continue
                if v not in iocs.setdefault(kind, []):
                    iocs[kind].append(v)
    for kind in ("domains", "urls", "ips", "emails", "filenames", "mutexes", "strings"):
        for v in iocs.get(kind, []) or []:
            kw(v, f"IOC {kind[:-1]}", "IOC")
    return {
        "background": raw.get("background", ""),
        "scenario": raw.get("scenario", {}),
        "targets": targets,
        "dlp_events": dlp_events,
        "usb_serials": sorted(usb_serials),
        "users": sorted(users),
        "devices": sorted(devices),
        "domains": sorted(domains),
        "time_window": {"start": db_ts(start), "end": db_ts(end), "derived": derived} if (start or end) else {},
        "keywords": keywords,
        "iocs": {k: list(v) for k, v in iocs.items()},
        "samples": raw.get("samples", []) or [],
        "sample_reports": sample_reports,
        "yara_rules": raw.get("yara_rules", []) or [],
        "extra": raw.get("extra", {}),
    }
