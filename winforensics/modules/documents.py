"""Document metadata and text extraction (feeds the full-text index used by keyword search and near-match)."""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from xml.etree import ElementTree as ET

from ..core.timeutil import db_ts, parse_any
from .base import ArtifactModule, ArtifactType, C, register

TEXT_EXT = ("txt", "csv", "log", "json", "xml", "md", "ini", "cfg", "yaml", "yml", "sql", "html", "htm", "py", "ps1", "bat",
            "cmd", "js", "vbs", "eml", "tsv")
OOXML_EXT = ("docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx")
ODF_EXT = ("odt", "ods", "odp")
OLE_EXT = ("doc", "xls", "ppt", "msg", "vsd", "pub")
DOC_EXT = TEXT_EXT + OOXML_EXT + ODF_EXT + OLE_EXT + ("pdf", "rtf")
MAX_TEXT = 300_000
NS_CP = {"cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
         "dc": "http://purl.org/dc/elements/1.1/", "dcterms": "http://purl.org/dc/terms/",
         "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}


def _strip_xml(data: bytes) -> str:
    text = re.sub(rb"<w:tab/>|<w:br/>|</w:p>|</a:p>|</si>|</row>|<text:line-break/>|</text:p>", b"\n", data)
    text = re.sub(rb"<[^>]+>", b" ", text)
    s = text.decode("utf-8", "replace")
    s = re.sub(r"&lt;", "<", re.sub(r"&gt;", ">", re.sub(r"&amp;", "&", s)))
    return re.sub(r"[ \t]+", " ", s)


def extract(data: bytes, ext: str) -> tuple[dict, str]:
    """Return (metadata, text) for a document."""
    meta: dict = {}
    text = ""
    ext = ext.lower()
    if ext in OOXML_EXT or ext in ODF_EXT or (data[:2] == b"PK" and ext not in ("zip", "jar", "apk")):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return {"error": "corrupt zip container"}, ""
        names = z.namelist()
        if "docProps/core.xml" in names:
            try:
                root = ET.fromstring(z.read("docProps/core.xml"))
                for tag, key in (("dc:title", "title"), ("dc:subject", "subject"), ("dc:creator", "author"),
                                 ("cp:lastModifiedBy", "last_modified_by"), ("dcterms:created", "created"),
                                 ("dcterms:modified", "modified"), ("cp:revision", "revision"), ("cp:lastPrinted", "last_printed"),
                                 ("cp:keywords", "keywords"), ("dc:description", "comments")):
                    el = root.find(tag, NS_CP)
                    if el is not None and el.text:
                        meta[key] = el.text.strip()
            except Exception:
                pass
        if "docProps/app.xml" in names:
            try:
                root = ET.fromstring(z.read("docProps/app.xml"))
                for tag, key in (("ep:Application", "application"), ("ep:Company", "company"), ("ep:TotalTime", "edit_minutes"),
                                 ("ep:Pages", "pages"), ("ep:Words", "words"), ("ep:AppVersion", "app_version"),
                                 ("ep:Template", "template")):
                    el = root.find(tag, NS_CP)
                    if el is not None and el.text:
                        meta[key] = el.text.strip()
            except Exception:
                pass
        if "meta.xml" in names:
            try:
                t = z.read("meta.xml").decode("utf-8", "replace")
                for key, rx in (("author", r"<meta:initial-creator>(.*?)<"), ("last_modified_by", r"<dc:creator>(.*?)<"),
                                ("created", r"<meta:creation-date>(.*?)<"), ("modified", r"<dc:date>(.*?)<"),
                                ("title", r"<dc:title>(.*?)<")):
                    m = re.search(rx, t)
                    if m:
                        meta[key] = m.group(1)
            except Exception:
                pass
        parts = []
        for n in names:
            if n in ("word/document.xml", "xl/sharedStrings.xml", "content.xml") or re.match(r"ppt/slides/slide\d+\.xml", n) or \
                    re.match(r"word/(header|footer|footnotes|comments)\d*\.xml", n) or re.match(r"xl/worksheets/sheet\d+\.xml", n):
                try:
                    parts.append(_strip_xml(z.read(n)[:5_000_000]))
                except Exception:
                    pass
            if sum(len(p) for p in parts) > MAX_TEXT:
                break
        meta["has_macros"] = any(n.lower().endswith("vbaproject.bin") for n in names)
        text = "\n".join(parts)
    elif ext == "pdf" or data[:5] == b"%PDF-":
        try:
            from pypdf import PdfReader

            r = PdfReader(io.BytesIO(data))
            info = r.metadata or {}
            for k, key in (("/Title", "title"), ("/Author", "author"), ("/Creator", "application"), ("/Producer", "producer"),
                           ("/CreationDate", "created"), ("/ModDate", "modified"), ("/Subject", "subject")):
                if info.get(k):
                    meta[key] = str(info.get(k))
            meta["pages"] = len(r.pages)
            parts = []
            for page in r.pages[:60]:
                try:
                    parts.append(page.extract_text() or "")
                except Exception:
                    break
                if sum(len(p) for p in parts) > MAX_TEXT:
                    break
            text = "\n".join(parts)
            meta["has_javascript"] = b"/JavaScript" in data or b"/JS" in data
        except Exception as e:
            meta["error"] = f"pdf: {str(e)[:80]}"
            text = " ".join(re.findall(rb"\(([\x20-\x7e]{3,})\)", data[:2_000_000])[:5000]).decode("latin-1") if data else ""
    elif ext in OLE_EXT or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        try:
            import olefile

            ole = olefile.OleFileIO(io.BytesIO(data))
            m = ole.get_metadata()
            for attr, key in (("title", "title"), ("author", "author"), ("last_saved_by", "last_modified_by"),
                              ("create_time", "created"), ("last_saved_time", "modified"), ("creating_application", "application"),
                              ("company", "company"), ("revision_number", "revision"), ("num_pages", "pages")):
                v = getattr(m, attr, None)
                if v:
                    meta[key] = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
            meta["has_macros"] = ole.exists("Macros") or ole.exists("_VBA_PROJECT_CUR") or any("vba" in "/".join(e).lower() for e in ole.listdir())
        except Exception:
            pass
        strings = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data[:20_000_000])
        text = " ".join(s.decode("utf-16-le", "replace") for s in strings[:20000])[:MAX_TEXT]
    elif ext == "rtf":
        s = data[:5_000_000].decode("latin-1", "replace")
        s = re.sub(r"\\'[0-9a-f]{2}", " ", s)
        s = re.sub(r"\\[a-z]+-?\d* ?|[{}]", " ", s)
        text = re.sub(r"\s+", " ", s)[:MAX_TEXT]
    else:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", "replace")
        else:
            text = data.decode("utf-8", "replace")
        text = text[:MAX_TEXT]
    return meta, text


@register
class DocumentsModule(ArtifactModule):
    id = "documents"
    title = "Documents (metadata + full text)"
    category = "Documents"
    description = ("Office/ODF/PDF/RTF/text documents in user profiles and on non-system volumes: author / last saved by / "
                   "internal timestamps / macros, SHA-256, and full text into the case search index.")
    weight = 4.0
    order = 50
    windows_only = False
    requires = ["filesystem"]
    locations = ["Users\\** documents", "all files on removable / non-system volumes", "deleted documents (where recoverable)"]
    artifact_types = [
        ArtifactType("document_meta", "Document Metadata", "Documents",
                     [C("path", kind="path", width=420), C("title", width=200), C("author"), C("last_modified_by", "Last Saved By"),
                      C("created_meta", "Created (internal)", "datetime"), C("modified_meta", "Modified (internal)", "datetime"),
                      C("application"), C("company"), C("revision"), C("macros"), C("size", kind="size"),
                      C("sha256", "SHA256", "hash", 300), C("deleted")], ts_label="Internal modified"),
    ]

    def estimate(self, ctx) -> float:
        return 3.0

    def run(self, ctx) -> None:
        max_size = int(ctx.options.get("doc_max_mb", 50)) * 1024 * 1024
        max_docs = int(ctx.options.get("doc_max_count", 60000))
        ph = ",".join("?" * len(DOC_EXT))
        sysvol = [v["name"] for v in ctx.db.volumes(ctx.evidence_id) if v.get("letter") == "C:"]
        vol_cond = ("volume NOT IN (" + ",".join("?" * len(sysvol)) + ")") if sysvol else "1=1"
        rows = ctx.db.query(
            f"SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND ext IN ({ph}) AND size>0 AND size<=? "
            f"AND (lower(path) LIKE '\\users\\%' OR {vol_cond}) "
            "AND lower(path) NOT LIKE '%\\appdata\\local\\microsoft\\%' AND lower(path) NOT LIKE '%\\appdata\\local\\packages\\%' "
            "AND lower(path) NOT LIKE '%\\node_modules\\%' AND lower(path) NOT LIKE '%\\appdata\\local\\google\\chrome\\user data\\%\\cache%' "
            f"ORDER BY deleted, size LIMIT {max_docs}", (ctx.evidence_id, *DOC_EXT, max_size, *sysvol))
        total = max(1, len(rows))
        n = 0
        hashes = []
        for i, row in enumerate(rows):
            if i % 50 == 0:
                ctx.progress(i / total, f"Documents: {i:,}/{total:,}")
            low = (row["path"] or "").lower()
            if row["ext"] in TEXT_EXT and ("\\appdata\\" in low and "\\microsoft\\windows\\powershell" not in low):
                continue
            try:
                data = ctx.read_entry(row)
            except Exception:
                continue
            if row.get("deleted") and not data.strip(b"\x00"):
                continue
            md5, sha1, sha256 = hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest()
            hashes.append((md5, sha1, sha256, "recovered" if row.get("deleted") else "", row["id"]))
            try:
                meta, text = extract(data, row["ext"])
            except Exception as e:
                meta, text = {"error": str(e)[:100]}, ""
            path = ctx.display_path(row["volume"], row["path"])
            if text.strip():
                ctx.writer.doc((ctx.evidence_id, path, f"fs:{row['id']}", text[:MAX_TEXT]))
            created = parse_any(meta.get("created"))
            modified = parse_any(meta.get("modified"))
            if row["ext"] in OOXML_EXT + ODF_EXT + OLE_EXT + ("pdf",) or meta:
                rec = {"path": path, "title": meta.get("title"), "author": meta.get("author"),
                       "last_modified_by": meta.get("last_modified_by"), "created_meta": db_ts(created),
                       "modified_meta": db_ts(modified), "application": meta.get("application") or meta.get("producer"),
                       "company": meta.get("company"), "revision": meta.get("revision"),
                       "macros": "Yes" if meta.get("has_macros") else "", "size": row.get("size"), "sha256": sha256, "md5": md5,
                       "deleted": "Yes (recovered)" if row.get("deleted") else "", "fs_created": row.get("si_created"),
                       "fs_modified": row.get("si_modified"), "meta": {k: str(v)[:300] for k, v in meta.items()},
                       "fs_id": row["id"], "text_chars": len(text)}
                ctx.emit("document_meta", modified or parse_any(row.get("si_modified")), rec, user=ctx.user_for_path(path),
                         summary=f"{path} author={meta.get('author') or '-'} saved-by={meta.get('last_modified_by') or '-'}",
                         source=path, ts_label="Internal modified", tags=["macro"] if meta.get("has_macros") else None)
            n += 1
            if len(hashes) >= 500:
                ctx.db.set_fs_hashes(hashes)
                hashes = []
        if hashes:
            ctx.db.set_fs_hashes(hashes)
        ctx.flush()
        ctx.coverage("Documents (metadata + text)", "user profiles + non-system volumes", "found" if n else "not_found", n,
                     f"{len(rows):,} candidate files <= {max_size // 1024 // 1024} MB")
