"""Execution context handed to artifact modules and search engines."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any

from .db import BatchWriter, CaseDB
from .timeutil import UTC, db_ts, from_db, parse_any, to_utc

log = logging.getLogger("winforensics")


class Cancelled(Exception):
    pass


def jsonable(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, datetime):
        return db_ts(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return b.hex() if len(b) <= 4096 else b[:4096].hex() + "..."
    if isinstance(v, dict):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [jsonable(x) for x in v]
    if hasattr(v, "value") and v.__class__.__name__.endswith("Enum"):
        return str(v.value)
    return str(v)


class ModuleContext:
    def __init__(self, *, case, evidence: dict, opened, db: CaseDB, inputs: dict, options: dict,
                 progress_cb=None, log_cb=None, cancel_event=None, tz=None, profile=None):
        self.case = case
        self.evidence = evidence
        self.evidence_id = evidence["id"]
        self.opened = opened
        self.target = opened.target if opened else None
        self.db = db
        self.writer = BatchWriter(db)
        self.inputs = inputs or {}
        self.options = options or {}
        self.profile = profile
        self._progress_cb = progress_cb
        self._log_cb = log_cb
        self._cancel = cancel_event
        self.tz = tz or UTC
        self.module_id = ""
        self._last_progress = 0.0
        self.counts: dict[str, int] = {}
        self.cache: dict[str, Any] = {}

    # ------------------------------------------------------------ properties
    @property
    def is_windows(self) -> bool:
        try:
            return self.target is not None and self.target.os == "windows"
        except Exception:
            return False

    @property
    def evidence_tz(self):
        """Time zone configured on the examined system (used for local-time artifacts)."""
        if "evidence_tz" not in self.cache:
            from .timeutil import get_tz

            osd = self.evidence.get("os") or {}
            name = osd.get("timezone_iana") or osd.get("timezone_name")
            self.cache["evidence_tz"] = get_tz(name) if name else None
        return self.cache["evidence_tz"]

    def local_to_utc(self, dt: datetime | None) -> datetime | None:
        """Interpret a naive local timestamp (setupapi, NetworkList...) in the evidence time zone."""
        if dt is None:
            return None
        if dt.tzinfo is not None:
            return to_utc(dt)
        tz = self.evidence_tz or UTC
        return dt.replace(tzinfo=tz).astimezone(UTC)

    def plugin(self, name: str):
        """Yield dissect.target plugin records as plain dicts (``name`` like ``mru.opensave``)."""
        fn = self.target
        for part in name.split("."):
            fn = getattr(fn, part)
        for rec in fn():
            self.check_cancel()
            try:
                yield {k: v for k, v in rec._asdict().items() if not k.startswith("_")}
            except Exception:
                continue

    @property
    def window(self) -> tuple[datetime | None, datetime | None]:
        w = self.inputs.get("time_window") or {}
        return parse_any(w.get("start")), parse_any(w.get("end"))

    # ------------------------------------------------------------ output
    def emit(self, type_id: str, ts: datetime | str | None = None, data: dict | None = None, summary: str = "",
             user: str | None = None, source: str = "", ts_label: str = "", tags: list[str] | None = None) -> None:
        if isinstance(ts, str):
            ts = from_db(ts) or parse_any(ts)
        row = (
            self.evidence_id, type_id, db_ts(ts) if ts else None, ts_label, user, str(source or ""), summary,
            json.dumps(jsonable(data or {}), ensure_ascii=False), ",".join(tags or []),
        )
        self.writer.artifact(row)
        self.counts[type_id] = self.counts.get(type_id, 0) + 1

    def coverage(self, artifact: str, location: str, status: str, count: int = 0, detail: str = "") -> None:
        """status: found | not_found | absent | error | skipped | partial"""
        self.db.add_coverage(self.evidence_id, self.module_id, artifact, location, status, count, detail)

    def flush(self) -> None:
        self.writer.flush()

    # ------------------------------------------------------------ feedback
    def progress(self, fraction: float, status: str = "") -> None:
        now = time.time()
        if self._progress_cb and (now - self._last_progress > 0.15 or fraction >= 1.0):
            self._last_progress = now
            self._progress_cb(max(0.0, min(1.0, fraction)), status)
        self.check_cancel()

    def info(self, msg: str) -> None:
        log.info(msg)
        if self._log_cb:
            self._log_cb("info", msg)

    def warn(self, msg: str) -> None:
        log.warning(msg)
        if self._log_cb:
            self._log_cb("warning", msg)

    def error(self, msg: str) -> None:
        log.error(msg)
        if self._log_cb:
            self._log_cb("error", msg)

    def check_cancel(self) -> None:
        if self._cancel is not None and self._cancel.is_set():
            raise Cancelled()

    # ------------------------------------------------------------ filesystem helpers
    def path(self, p: str):
        return self.target.fs.path(p)

    def exists(self, p: str) -> bool:
        try:
            return self.target.fs.path(p).exists()
        except Exception:
            return False

    def glob(self, pattern: str) -> list:
        """Glob relative to the target root; ``pattern`` like ``C:/Users/*/NTUSER.DAT``."""
        try:
            root = self.target.fs.path("/")
            if re.match(r"^[a-zA-Z]:", pattern):
                drive, rest = pattern[:2].lower(), pattern[3:]
                root = self.target.fs.path(drive)
                pattern = rest
            return list(root.glob(pattern))
        except Exception:
            return []

    def read_bytes(self, p, limit: int | None = None) -> bytes:
        path = p if hasattr(p, "open") else self.target.fs.path(p)
        with path.open("rb") as fh:
            return fh.read(limit) if limit else fh.read()

    def user_profiles(self) -> list[dict]:
        """[{name, sid, home(path obj), home_str}] using the OS user list (falls back to C:/Users/*)."""
        if "user_profiles" in self.cache:
            return self.cache["user_profiles"]
        out = []
        seen = set()
        try:
            for ud in self.target.user_details.all():
                home = ud.home_path
                if home is None:
                    continue
                key = str(home).lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append({"name": ud.user.name, "sid": getattr(ud.user, "sid", None), "home": home,
                            "home_str": str(getattr(ud.user, "home", home))})
        except Exception:
            pass
        for d in self.glob("C:/Users/*"):
            try:
                if d.is_dir() and str(d).lower() not in seen and d.name.lower() not in ("public", "default", "all users",
                                                                                         "default user"):
                    seen.add(str(d).lower())
                    out.append({"name": d.name, "sid": None, "home": d, "home_str": f"C:\\Users\\{d.name}"})
            except Exception:
                continue
        self.cache["user_profiles"] = out
        return out

    def user_for_path(self, path: str) -> str | None:
        m = re.search(r"[\\/]users[\\/]([^\\/]+)", str(path), re.I)
        return m.group(1) if m else None

    def user_for_sid(self, sid: str) -> str | None:
        """Account name of a SID from the profile list (None when unknown)."""
        for p in self.user_profiles():
            if p.get("sid") and str(p["sid"]).upper() == str(sid).upper():
                return p["name"]
        return None

    # ------------------------------------------------------------ volumes / fs index access
    def volume_map(self) -> dict:
        """{volume name: dissect volume} using the same naming as the file system index (``C:``, ``Vol2``...)."""
        if "volume_map" in self.cache:
            return self.cache["volume_map"]
        letters = {}
        try:
            for name, fs in self.target.fs.mounts.items():
                if len(name) == 2 and name[1] == ":":
                    letters[id(fs)] = name.upper()
        except Exception:
            pass
        out = {}
        for idx, vol in enumerate(self.target.volumes):
            fs = getattr(vol, "fs", None)
            vname = letters.get(id(fs)) if fs is not None else None
            vname = vname or f"Vol{getattr(vol, 'number', idx + 1) or idx + 1}"
            out[vname] = vol
        self.cache["volume_map"] = out
        return out

    @staticmethod
    def display_path(volume: str, path: str) -> str:
        return f"{volume}{path}" if volume.endswith(":") else f"[{volume}]{path}"

    def fs_files(self, where: str = "", params: tuple = (), include_deleted: bool = False, limit: int | None = None):
        sql = "SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0"
        args: list = [self.evidence_id]
        if not include_deleted:
            sql += " AND deleted=0"
        if where:
            sql += f" AND ({where})"
            args.extend(params)
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self.db.query(sql, args)

    def read_entry(self, row: dict, limit: int | None = None) -> bytes:
        """Read file content for an fs_entries row (works for deleted NTFS records and FAT entries)."""
        vol = self.volume_map().get(row["volume"])
        if vol is None:
            raise FileNotFoundError(row["volume"])
        fs = getattr(vol, "fs", None)
        ftype = getattr(fs, "__type__", "")
        if ftype == "ntfs":
            rec = fs.ntfs.mft.get(row["record"])
            fh = rec.open()
            return fh.read(limit) if limit else fh.read()
        if not row.get("deleted"):
            p = fs.path(row["path"].replace("\\", "/"))
            with p.open("rb") as fh:
                return fh.read(limit) if limit else fh.read()
        if ftype == "fat":
            from .fatwalk import FatVolume

            fv = self.cache.get(("fatvol", row["volume"]))
            if fv is None:
                vol.seek(0)
                fv = FatVolume(vol, vol.size)
                self.cache[("fatvol", row["volume"])] = fv
            # deleted FAT entry (first cluster stored in ``seq``): classic contiguous recovery
            first = row.get("seq") or 0
            if first < 2:
                raise FileNotFoundError("deleted FAT entry without a start cluster")
            size = row.get("size") or 0
            vol.seek(fv.cluster_offset(first))
            return vol.read(min(size, limit) if limit else size)
        raise FileNotFoundError(row["path"])

    def open_entry_stream(self, row: dict):
        """Streaming file object for an fs_entries row (allocated or deleted NTFS, allocated FAT/other)."""
        vol = self.volume_map().get(row["volume"])
        if vol is None:
            raise FileNotFoundError(row["volume"])
        fs = getattr(vol, "fs", None)
        if getattr(fs, "__type__", "") == "ntfs":
            return fs.ntfs.mft.get(row["record"]).open()
        if row.get("deleted"):
            import io

            return io.BytesIO(self.read_entry(row))
        return fs.path(row["path"].replace("\\", "/")).open("rb")

    def parsed_dir(self, *parts) -> str:
        from .exporter import evidence_folder

        base = evidence_folder(self.case, self.evidence, "Parsed")
        p = os.path.join(base, *parts) if parts else base
        os.makedirs(p, exist_ok=True)
        return p

    def collected_dir(self) -> str:
        from .exporter import evidence_folder

        return evidence_folder(self.case, self.evidence, "Collected")

    def open_entry_path(self, row: dict):
        """dissect path object for an allocated fs_entries row."""
        vol = self.volume_map().get(row["volume"])
        return vol.fs.path(row["path"].replace("\\", "/"))

    # ------------------------------------------------------------ export
    def export(self, src_path, reason: str, data: bytes | None = None) -> dict:
        """Copy a file out of the evidence into the case export folder and hash it."""
        name = os.path.basename(str(src_path).replace("\\", "/")) or "unnamed"
        safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)[:150]
        out_dir = self.case.sub("exports", f"E{self.evidence_id:02d}")
        dst = os.path.join(out_dir, safe)
        i = 1
        while os.path.exists(dst):
            stem, ext = os.path.splitext(safe)
            dst = os.path.join(out_dir, f"{stem}_{i}{ext}")
            i += 1
        h = {a: hashlib.new(a) for a in ("md5", "sha1", "sha256")}
        size = 0
        with open(dst, "wb") as out:
            if data is not None:
                out.write(data)
                for x in h.values():
                    x.update(data)
                size = len(data)
            else:
                path = src_path if hasattr(src_path, "open") else self.target.fs.path(str(src_path))
                with path.open("rb") as fh:
                    while True:
                        b = fh.read(4 * 1024 * 1024)
                        if not b:
                            break
                        out.write(b)
                        size += len(b)
                        for x in h.values():
                            x.update(b)
        rec = {"local_path": dst, "size": size, **{k: v.hexdigest() for k, v in h.items()}}
        self.db.execute(
            "INSERT INTO exported(evidence_id, source_path, local_path, size, md5, sha1, sha256, reason, exported_utc)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (self.evidence_id, str(src_path), dst, size, rec["md5"], rec["sha1"], rec["sha256"], reason,
             db_ts(datetime.now(UTC))),
        )
        self.db.commit()
        return rec
