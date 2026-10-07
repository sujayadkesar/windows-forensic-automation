"""Windows Search index (Windows.edb): files, folders, e-mails and web items the indexer recorded.

The index outlives the items: messages deleted from Outlook, files deleted from the disk and documents opened from
removable or network drives that were indexed while present keep their properties here.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import tempfile

from ..core.timeutil import db_ts, filetime
from .base import ArtifactModule, ArtifactType, C, register

WANTED = {
    "System_ItemPathDisplay": "path", "System_ItemUrl": "url", "System_ItemTypeText": "item_type", "System_ItemType": "ext",
    "System_FileName": "file_name", "System_Size": "size", "System_DateModified": "modified", "System_DateCreated": "created",
    "System_DateAccessed": "accessed", "System_Search_GatherTime": "gathered", "System_Subject": "subject",
    "System_Message_FromAddress": "from", "System_Message_FromName": "from_name", "System_Message_ToAddress": "to",
    "System_Message_ToName": "to_name", "System_Message_DateSent": "sent", "System_Message_DateReceived": "received",
    "System_Message_HasAttachments": "has_attachments", "System_Message_AttachmentNames": "attachments",
    "System_ItemFolderPathDisplay": "folder", "System_Author": "author", "System_Title": "title",
    "Microsoft_IE_TargetUrlPath": "target_url", "System_Link_TargetUrl": "target_url2", "System_Computer": "computer",
}
TIME_FIELDS = ("modified", "created", "accessed", "gathered", "sent", "received")


def _norm(col: str) -> str:
    """Windows 10 property store columns are prefixed with an id: '4447-System_ItemPathDisplay'."""
    return re.sub(r"^\d+-", "", col)


def _time(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 8:
        # stored big-endian in the index
        return filetime(struct.unpack(">Q", bytes(v))[0])
    if isinstance(v, int) and v > 10 ** 16:
        return filetime(v)
    return None


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return "; ".join(_text(x) for x in v)
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        try:
            t = b.decode("utf-16-le").rstrip("\x00") if len(b) % 2 == 0 and b[1:2] == b"\x00" else b.decode("utf-8")
        except UnicodeDecodeError:
            return b.hex()[:200]
        return t.rstrip("\x00")
    return str(v)


@register
class WindowsSearchModule(ArtifactModule):
    id = "windows_search"
    title = "Windows Search index"
    category = "Windows Search"
    description = ("Windows.edb (Windows Search): indexed files, folders, Outlook e-mails and web shortcuts, including items "
                   "that were later deleted.")
    weight = 1.0
    order = 46
    requires = ["filesystem"]
    locations = ["C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"]
    artifact_types = [
        ArtifactType("search_index_item", "Windows Search Index Items", "Windows Search",
                     [C("item_type", "Item Type"), C("path", "Path / Item", "path", 420), C("modified", kind="datetime"),
                      C("created", kind="datetime"), C("accessed", kind="datetime"), C("size", kind="size"),
                      C("subject", width=240), C("from", width=220), C("to", width=220), C("sent", kind="datetime"),
                      C("gathered", "Indexed", "datetime"), C("url", "Item URL", width=300)], ts_label="Modified"),
    ]

    def run(self, ctx) -> None:
        rows = ctx.fs_files("lower(path) LIKE '%\\programdata\\microsoft\\search\\data\\applications\\%' AND lower(name)='windows.edb'")
        if not rows:
            sqlite_db = ctx.fs_files("lower(path) LIKE '%\\programdata\\microsoft\\search\\data\\applications\\%' "
                                     "AND lower(name) LIKE 'windows%.db'")
            ctx.coverage("Windows Search index", self.locations[0], "absent" if not sqlite_db else "skipped", 0,
                         "Windows 11 SQLite index (Windows.db) is not parsed yet" if sqlite_db else "")
            return
        tmp = tempfile.mkdtemp(prefix="wsearch_", dir=ctx.case.sub("temp"))
        n = 0
        try:
            for row in rows:
                local = os.path.join(tmp, f"{row['record']}_Windows.edb")
                try:
                    with ctx.open_entry_stream(row) as src, open(local, "wb") as out:
                        shutil.copyfileobj(src, out, 8 * 1024 * 1024)
                    n += self._parse(ctx, local, ctx.display_path(row["volume"], row["path"]))
                except Exception as e:
                    ctx.warn(f"Windows Search index {row['path']}: {type(e).__name__}: {e}")
                    ctx.coverage("Windows Search index", row["path"], "error", 0, str(e)[:200])
                    continue
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        ctx.coverage("Windows Search index", self.locations[0], "found" if n else "not_found", n)

    def _parse(self, ctx, local: str, src: str) -> int:
        from dissect.database.ese import ESE

        n = 0
        with open(local, "rb") as fh:
            db = ESE(fh)
            names = [t.name for t in db.tables()]
            table = next((t for t in ("SystemIndex_0A", "SystemIndex_PropertyStore") if t in names), None)
            if table is None:
                return 0
            tb = db.table(table)
            colmap = {c: WANTED[_norm(c)] for c in tb.column_names if _norm(c) in WANTED}
            for rec in tb.records():
                try:
                    raw = rec.as_dict()
                except Exception:
                    continue
                d = {}
                for col, field in colmap.items():
                    v = raw.get(col)
                    if v in (None, b"", ""):
                        continue
                    d[field] = db_ts(_time(v)) if field in TIME_FIELDS else _text(v)
                if not (d.get("path") or d.get("url") or d.get("subject")):
                    continue
                d["target_url"] = d.get("target_url") or d.pop("target_url2", "")
                kind = d.get("item_type") or d.get("ext") or ""
                ts = d.get("modified") or d.get("sent") or d.get("gathered")
                user = None
                m = re.search(r"\{(S-1-5-21-[\d-]+)\}", d.get("url") or "")
                if m:
                    user = ctx.user_for_sid(m.group(1))
                user = user or ctx.user_for_path(d.get("path") or "")
                summary = (f"Indexed e-mail '{d.get('subject')}' from {d.get('from', '')} to {d.get('to', '')}"
                           if "mail" in kind.lower() or d.get("sent") else f"Indexed {kind or 'item'}: {d.get('path') or d.get('url')}")
                ctx.emit("search_index_item", ts, d, user=user, summary=summary[:300], source=src, ts_label="Modified",
                         tags=["email"] if d.get("sent") else None)
                n += 1
        return n
