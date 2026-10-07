"""Sticky Notes: StickyNotes.snt (Windows 7 / 8, OLE compound file) and plum.sqlite (Windows 10 / 11)."""

from __future__ import annotations

import io
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

from ..core.timeutil import db_ts
from .base import ArtifactModule, ArtifactType, C, register

_TICKS_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


def _ticks(v):
    """.NET ticks (100 ns since 0001-01-01) used by plum.sqlite."""
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return _TICKS_EPOCH + timedelta(microseconds=v / 10)
    except OverflowError:
        return None


def _plum_text(t: str) -> str:
    # plum.sqlite stores '\id=<guid> text' paragraphs
    return "\n".join(re.sub(r"^\\id=[0-9a-f-]+\s?", "", line) for line in (t or "").splitlines()).strip()


@register
class StickyNotesModule(ArtifactModule):
    id = "sticky_notes"
    title = "Sticky Notes"
    category = "Documents"
    description = "Text of Windows Sticky Notes with creation / modification times (StickyNotes.snt, plum.sqlite)."
    weight = 0.2
    order = 47
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Roaming\\Microsoft\\Sticky Notes\\StickyNotes.snt",
                 "Users\\*\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite"]
    artifact_types = [
        ArtifactType("sticky_note", "Sticky Notes", "Documents",
                     [C("text", width=480), C("created", kind="datetime"), C("modified", kind="datetime"), C("note_id", width=260),
                      C("store", width=360)], ts_label="Modified"),
    ]

    def run(self, ctx) -> None:
        n = 0
        for row in ctx.fs_files("lower(name)='stickynotes.snt'"):
            try:
                n += self._snt(ctx, row)
            except Exception as e:
                ctx.warn(f"StickyNotes.snt {row['path']}: {e}")
        tmp = tempfile.mkdtemp(prefix="notes_", dir=ctx.case.sub("temp"))
        try:
            for row in ctx.fs_files("lower(name)='plum.sqlite' AND lower(path) LIKE '%microsoftstickynotes%'"):
                try:
                    n += self._plum(ctx, row, tmp)
                except Exception as e:
                    ctx.warn(f"plum.sqlite {row['path']}: {e}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        ctx.coverage("Sticky Notes", "StickyNotes.snt / plum.sqlite", "found" if n else "not_found", n)

    def _snt(self, ctx, row) -> int:
        import olefile

        src = ctx.display_path(row["volume"], row["path"])
        user = ctx.user_for_path(src)
        ole = olefile.OleFileIO(io.BytesIO(ctx.read_entry(row)))
        notes = {e[0] for e in ole.listdir(storages=True, streams=False) if len(e) == 1}
        n = 0
        for nid in sorted(notes):
            text = ""
            if ole.exists(f"{nid}/3"):
                text = ole.openstream(f"{nid}/3").read().decode("utf-16-le", "replace").rstrip("\x00").strip()
            elif ole.exists(f"{nid}/0"):
                rtf = ole.openstream(f"{nid}/0").read().decode("latin-1", "replace")
                text = re.sub(r"\\[a-z]+-?\d* ?|[{}]", "", rtf).strip()
            created, modified = ole.getctime(nid), ole.getmtime(nid)
            created = created.replace(tzinfo=timezone.utc) if created else None
            modified = modified.replace(tzinfo=timezone.utc) if modified else None
            ts = modified or created or row.get("si_modified")
            ctx.emit("sticky_note", ts, {"text": text, "created": db_ts(created), "modified": db_ts(modified), "note_id": nid,
                                         "store": src, "store_modified": row.get("si_modified")},
                     user=user, summary=f"Sticky note: {text[:120]}", source=src, ts_label="Modified" if modified else "Store modified")
            n += 1
        return n

    def _plum(self, ctx, row, tmp) -> int:
        src = ctx.display_path(row["volume"], row["path"])
        user = ctx.user_for_path(src)
        local = os.path.join(tmp, f"{row['record']}_plum.sqlite")
        with open(local, "wb") as fh:
            fh.write(ctx.read_entry(row))
        db = sqlite3.connect(local)
        db.row_factory = sqlite3.Row
        n = 0
        try:
            for r in db.execute("SELECT * FROM Note"):
                d = dict(r)
                created, modified = _ticks(d.get("CreatedAt")), _ticks(d.get("UpdatedAt"))
                text = _plum_text(d.get("Text") or "")
                ctx.emit("sticky_note", modified or created, {"text": text, "created": db_ts(created), "modified": db_ts(modified),
                                                              "note_id": d.get("Id"), "store": src},
                         user=user, summary=f"Sticky note: {text[:120]}", source=src, ts_label="Modified")
                n += 1
        finally:
            db.close()
        return n
