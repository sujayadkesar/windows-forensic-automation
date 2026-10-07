"""Internet Explorer / Edge (legacy) history: WebCacheV01.dat (IE10+, ESE) and index.dat (IE 5-9).

Besides web history, WinInet records local and network files opened through the shell as ``file:///`` URLs
("Visited: user@file:///E:/Project/plan.docx").  On Windows 7/8 this is one of the best records of which documents
a user opened from a USB drive or a network share, so those entries are emitted separately as ``ie_file_access``.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import tempfile
from urllib.parse import unquote

from ..core.timeutil import db_ts, filetime
from ..knowledge import category_title, classify_url, host_of
from .base import ArtifactModule, ArtifactType, C, register

SKIP_CONTAINERS = ("content", "cookies", "domstore", "emiecompatibility", "emiesitelist", "dnttrackingprotection", "feedplat",
                   "iecompat", "iecompatua", "iestatic", "prefetch", "rootiecompat", "userdata", "xusagepath", "appcache",
                   "iecookies", "ietld")
_PREFIX = re.compile(r"^:\d{16}:\s*")
_VISITED = re.compile(r"^(?:Visited:)?\s*([^@/]+)@(.+)$")
ALLOWED = ("http://", "https://", "ftp://", "file:")


def _split(url: str) -> tuple[str, str]:
    """'Visited: user@http://x' -> (user, url)."""
    if not url:
        return "", ""
    url = _PREFIX.sub("", url.strip())  # MSHist containers: ':2015032320150324: user@url'
    m = _VISITED.match(url)
    if m and m.group(2).lower().startswith(ALLOWED):
        return m.group(1).strip(), m.group(2)
    return "", url


def file_url_to_path(url: str) -> str:
    u = unquote(url)
    if u.lower().startswith("file:///"):
        return u[8:].replace("/", "\\")
    if u.lower().startswith("file://"):
        return "\\\\" + u[7:].replace("/", "\\")
    return u


def _classify(url):
    c = classify_url(url or "")
    return (category_title(c[0]), c[1]) if c else ("", "")


def _ft(v):
    try:
        return filetime(int(v)) if v else None
    except (TypeError, ValueError, OverflowError):
        return None


@register
class IEHistoryModule(ArtifactModule):
    id = "ie_history"
    title = "Internet Explorer / Edge (legacy) history"
    category = "Browser Activity"
    description = ("WebCacheV01.dat (IE 10/11, Edge legacy) and index.dat (IE 5-9) history and downloads, including file:/// "
                   "records of documents opened from local, removable and network drives.")
    weight = 1.5
    order = 36
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat",
                 "Users\\*\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\**\\index.dat"]
    artifact_types = [
        ArtifactType("ie_file_access", "Files Opened (IE / WinInet file:/// history)", "File & Folder Access",
                     [C("accessed", kind="datetime"), C("path", width=420), C("drive_kind"), C("access_count", "Count", "int"),
                      C("modified", kind="datetime"), C("container"), C("source_db", width=300)], ts_label="Last opened"),
    ]

    def run(self, ctx) -> None:
        self.seen: set = set()
        tmp = tempfile.mkdtemp(prefix="ie_", dir=ctx.case.sub("temp"))
        try:
            wc = ctx.fs_files("lower(name) IN ('webcachev01.dat', 'webcachev24.dat')")
            n_wc = 0
            for i, row in enumerate(wc):
                ctx.progress(i / max(1, len(wc) + 1), f"WebCache {row['path']}")
                try:
                    n_wc += self._webcache(ctx, row, tmp)
                except Exception as e:
                    ctx.warn(f"WebCache {row['path']}: {type(e).__name__}: {e}")
            ctx.coverage("IE / Edge legacy WebCache", self.locations[0], "found" if n_wc else ("not_found" if wc else "absent"), n_wc,
                         f"{len(wc)} database(s)")
            idx = ctx.fs_files("lower(name)='index.dat' AND lower(path) LIKE '%\\history.ie5\\%'")
            n_idx = 0
            for row in idx:
                try:
                    n_idx += self._index_dat(ctx, row)
                except Exception as e:
                    ctx.warn(f"index.dat {row['path']}: {type(e).__name__}: {e}")
            ctx.coverage("IE 5-9 history (index.dat)", self.locations[1], "found" if n_idx else ("not_found" if idx else "absent"),
                         n_idx, f"{len(idx)} file(s)")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ------------------------------------------------------------------ shared emit
    def _emit(self, ctx, user, url, accessed, modified, count, container, src, browser):
        if not url or not url.lower().startswith(ALLOWED):
            return 0
        key = (src, user, url, db_ts(accessed)[:19] if accessed else "")
        if key in self.seen:  # the same visit is kept in History and in the daily / weekly MSHist containers
            return 0
        self.seen.add(key)
        if url.lower().startswith("file:"):
            path = file_url_to_path(url)
            kind = "network share" if path.startswith("\\\\") else ("system drive" if path[:2].upper() == "C:" else "other drive")
            ctx.emit("ie_file_access", accessed, {"accessed": db_ts(accessed), "path": path, "drive_kind": kind,
                                                  "access_count": count, "modified": db_ts(modified), "container": container,
                                                  "url": url, "source_db": src},
                     user=user, summary=f"Opened {path}", source=src, ts_label="Last opened", tags=["file_access"])
            return 1
        cat, svc = _classify(url)
        ctx.emit("web_visit", accessed, {"browser": browser, "profile": user or "", "visit_time": db_ts(accessed), "url": url,
                                         "title": "", "visit_count": count, "transition": container, "domain": host_of(url),
                                         "category": cat, "service": svc, "db": src},
                 user=user, summary=f"{browser}: {url}"[:300], source=src, ts_label="Visited",
                 tags=["exfil_destination"] if cat in ("Webmail", "Cloud storage", "File transfer service", "Paste site",
                                                       "AI assistant") else None)
        return 1

    # ------------------------------------------------------------------ WebCacheV01.dat
    def _webcache(self, ctx, row, tmp) -> int:
        from dissect.database.ese import ESE

        src = ctx.display_path(row["volume"], row["path"])
        owner = ctx.user_for_path(src)
        local = os.path.join(tmp, f"{row['record']}_{row['name']}")
        with open(local, "wb") as fh:
            fh.write(ctx.read_entry(row))
        n = 0
        with open(local, "rb") as fh:
            db = ESE(fh)
            containers = {}
            for rec in db.table("Containers").records():
                d = rec.as_dict()
                name = (d.get("Name") or "")
                name = name.decode("utf-16-le", "replace") if isinstance(name, bytes) else str(name)
                containers[d.get("ContainerId")] = name.rstrip("\x00")
            for cid, cname in containers.items():
                low = cname.lower()
                if low.startswith(SKIP_CONTAINERS) and not low.startswith("iedownload"):
                    continue
                try:
                    table = db.table(f"Container_{cid}")
                except Exception:
                    continue
                for rec in table.records():
                    try:
                        d = rec.as_dict()
                    except Exception:
                        continue
                    url = d.get("Url") or ""
                    url = url.decode("utf-16-le", "replace") if isinstance(url, bytes) else str(url)
                    url = url.rstrip("\x00")
                    accessed, modified = _ft(d.get("AccessedTime")), _ft(d.get("ModifiedTime"))
                    if low.startswith("iedownload"):
                        n += self._download(ctx, d, url, accessed, owner, src)
                        continue
                    user, real = _split(url)
                    n += self._emit(ctx, user or owner, real, accessed, modified, d.get("AccessCount"), cname, src,
                                    "Internet Explorer / Edge (legacy)")
        return n

    def _download(self, ctx, d, url, ts, owner, src) -> int:
        blob = d.get("ResponseHeaders") or b""
        target = ""
        if isinstance(blob, bytes) and blob:
            # the iedownload response blob holds UTF-16 strings: source URL, referrer and the saved path
            strs = [s.decode("utf-16-le", "replace") for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", blob)]
            paths = [s for s in strs if re.match(r"^[A-Za-z]:\\", s) or s.startswith("\\\\")]
            urls = [s for s in strs if s.startswith(("http", "ftp"))]
            target = paths[-1] if paths else ""
            url = urls[0] if urls else url
        _u, real = _split(url)
        real = real or url
        ctx.emit("web_download", ts, {"browser": "Internet Explorer / Edge (legacy)", "start_time": db_ts(ts), "target_path": target,
                                      "url": real, "tab_url": "", "referrer": "", "size": d.get("FileSize"), "state": "",
                                      "danger": "", "opened": "", "mime_type": "", "db": src},
                 user=owner, summary=f"IE download {target} <- {real}"[:300], source=src, ts_label="Download start")
        return 1

    # ------------------------------------------------------------------ index.dat (MSIECF)
    def _index_dat(self, ctx, row) -> int:
        data = ctx.read_entry(row)
        if not data.startswith(b"Client UrlCache MMF Ver"):
            return 0
        src = ctx.display_path(row["volume"], row["path"])
        owner = ctx.user_for_path(src)
        folder = row["path"].lower().split("\\history.ie5\\")[-1]
        local_times = folder.startswith("mshist")  # daily / weekly containers store local times
        container = "History (daily/weekly)" if local_times else "History"
        n = 0
        pos = 0x4000
        size = len(data)
        while pos + 0x68 <= size:
            sig = data[pos:pos + 4]
            if sig not in (b"URL ", b"LEAK"):
                pos += 0x80
                continue
            blocks = struct.unpack_from("<I", data, pos + 4)[0]
            if blocks <= 0 or blocks > 0x10000:
                pos += 0x80
                continue
            t2, t1 = struct.unpack_from("<QQ", data, pos + 8)
            url_off = struct.unpack_from("<I", data, pos + 0x34)[0]
            hits = struct.unpack_from("<I", data, pos + 0x54)[0]
            if 0 < url_off < blocks * 0x80:
                s = pos + url_off
                e = data.find(b"\x00", s, pos + blocks * 0x80)
                url = data[s:e if e > 0 else s + 2048].decode("latin-1", "replace")
                accessed, modified = _ft(t1), _ft(t2)
                if local_times:
                    accessed = ctx.local_to_utc(accessed.replace(tzinfo=None)) if accessed else None
                    modified = ctx.local_to_utc(modified.replace(tzinfo=None)) if modified else None
                user, real = _split(url)
                n += self._emit(ctx, user or owner, real, accessed, modified, hits,
                                container + (" (deleted record)" if sig == b"LEAK" else ""), src, "Internet Explorer")
            pos += blocks * 0x80
        return n
