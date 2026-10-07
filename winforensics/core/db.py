"""SQLite case database.

One database per case (``case.db``).  Worker processes (one per evidence item)
write concurrently using WAL mode and batched transactions.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable, Iterator

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY, label TEXT, role TEXT, path TEXT, format TEXT, size INTEGER,
    status TEXT DEFAULT 'added', added_utc TEXT, info_json TEXT, hashes_json TEXT,
    os_json TEXT, notes TEXT, options_json TEXT);

CREATE TABLE IF NOT EXISTS artifact_types(
    type TEXT PRIMARY KEY, title TEXT, category TEXT, module TEXT, columns_json TEXT, description TEXT);

CREATE TABLE IF NOT EXISTS artifacts(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, type TEXT, ts TEXT, ts_label TEXT, user TEXT,
    source TEXT, summary TEXT, data_json TEXT, tags TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_art_type ON artifacts(evidence_id, type);
CREATE INDEX IF NOT EXISTS ix_art_ts ON artifacts(ts);

CREATE TABLE IF NOT EXISTS fs_entries(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, volume TEXT, record INTEGER, seq INTEGER, parent INTEGER,
    path TEXT, name TEXT, ext TEXT, size INTEGER, is_dir INTEGER, deleted INTEGER,
    si_created TEXT, si_modified TEXT, si_accessed TEXT, si_changed TEXT,
    fn_created TEXT, fn_modified TEXT, fn_accessed TEXT, fn_changed TEXT,
    ads TEXT, resident INTEGER, md5 TEXT, sha1 TEXT, sha256 TEXT, flags TEXT, recover TEXT);
CREATE INDEX IF NOT EXISTS ix_fs_name ON fs_entries(evidence_id, name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_fs_size ON fs_entries(evidence_id, size);
CREATE INDEX IF NOT EXISTS ix_fs_sha256 ON fs_entries(sha256);
CREATE INDEX IF NOT EXISTS ix_fs_md5 ON fs_entries(md5);
CREATE INDEX IF NOT EXISTS ix_fs_path ON fs_entries(evidence_id, path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_fs_rec ON fs_entries(evidence_id, volume, record);

CREATE TABLE IF NOT EXISTS coverage(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, module TEXT, artifact TEXT, location TEXT,
    status TEXT, count INTEGER, detail TEXT, duration REAL);

CREATE TABLE IF NOT EXISTS hits(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, search TEXT, term TEXT, term_kind TEXT, area TEXT,
    volume TEXT, offset INTEGER, length INTEGER, encoding TEXT, file_path TEXT, record INTEGER,
    context_hex TEXT, context_text TEXT, detail_json TEXT);
CREATE INDEX IF NOT EXISTS ix_hits_term ON hits(evidence_id, term);

CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, analyzer TEXT, category TEXT, title TEXT,
    severity TEXT, confidence TEXT, ts TEXT, description TEXT, details_json TEXT, refs_json TEXT,
    figures_json TEXT, questions TEXT, include INTEGER DEFAULT 1, tags TEXT, mitre TEXT, sort_key REAL DEFAULT 0);

CREATE TABLE IF NOT EXISTS answers(
    question_id TEXT PRIMARY KEY, status TEXT, summary TEXT, finding_ids TEXT, updated TEXT);

CREATE TABLE IF NOT EXISTS timeline(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, ts TEXT, source TEXT, event TEXT, description TEXT,
    user TEXT, ref_kind TEXT, ref_id INTEGER, flagged INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_tl_ts ON timeline(ts);

CREATE TABLE IF NOT EXISTS exported(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, source_path TEXT, local_path TEXT, size INTEGER,
    md5 TEXT, sha1 TEXT, sha256 TEXT, reason TEXT, exported_utc TEXT);

CREATE TABLE IF NOT EXISTS malware_reports(
    id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT, score INTEGER, verdict TEXT, report_json TEXT);

CREATE TABLE IF NOT EXISTS jobs(
    id INTEGER PRIMARY KEY, started TEXT, finished TEXT, status TEXT, profile TEXT, options_json TEXT, log TEXT);

CREATE TABLE IF NOT EXISTS volumes(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, name TEXT, number INTEGER, offset INTEGER, size INTEGER, fs TEXT,
    label TEXT, serial TEXT, cluster_size INTEGER, letter TEXT, runs_file TEXT, info_json TEXT);

CREATE TABLE IF NOT EXISTS usn(
    id INTEGER PRIMARY KEY, evidence_id INTEGER, volume TEXT, usn INTEGER, ts TEXT, record INTEGER, seq INTEGER,
    parent INTEGER, name TEXT, path TEXT, reason TEXT, reason_flags INTEGER, attributes INTEGER);
CREATE INDEX IF NOT EXISTS ix_usn_name ON usn(evidence_id, name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_usn_ts ON usn(ts);

CREATE VIRTUAL TABLE IF NOT EXISTS doc_text USING fts5(
    evidence_id UNINDEXED, path, source UNINDEXED, content, tokenize='unicode61 remove_diacritics 2');
"""


def _json(v: Any) -> str | None:
    if v is None:
        return None
    return json.dumps(v, default=str, ensure_ascii=False)


class CaseDB:
    """Thin, thread-aware wrapper around the case SQLite database."""

    def __init__(self, path: str, readonly: bool = False):
        self.path = path
        self.readonly = readonly
        self._local = threading.local()
        if not readonly:
            with self.conn:
                self.conn.executescript(SCHEMA)
                self.conn.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
                )

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            uri = f"file:{self.path}?mode=ro" if self.readonly else f"file:{self.path}"
            c = sqlite3.connect(uri, uri=True, timeout=120, check_same_thread=False)
            c.row_factory = sqlite3.Row
            if not self.readonly:
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=120000")
            c.execute("PRAGMA temp_store=MEMORY")
            self._local.conn = c
        return c

    def close(self) -> None:
        c = getattr(self._local, "conn", None)
        if c is not None:
            c.close()
            self._local.conn = None

    # ------------------------------------------------------------- generic
    def execute(self, sql: str, params: Iterable = ()) -> sqlite3.Cursor:
        for attempt in range(20):
            try:
                return self.conn.execute(sql, tuple(params))
            except sqlite3.OperationalError as e:
                if "locked" not in str(e) or attempt == 19:
                    raise
                time.sleep(0.25)
        raise RuntimeError("unreachable")

    def executemany(self, sql: str, rows: list) -> None:
        if not rows:
            return
        for attempt in range(20):
            try:
                with self.conn:
                    self.conn.executemany(sql, rows)
                return
            except sqlite3.OperationalError as e:
                if "locked" not in str(e) or attempt == 19:
                    raise
                time.sleep(0.25)

    def commit(self) -> None:
        self.conn.commit()

    def query(self, sql: str, params: Iterable = ()) -> list[dict]:
        return [dict(r) for r in self.execute(sql, params).fetchall()]

    def iquery(self, sql: str, params: Iterable = ()) -> Iterator[dict]:
        cur = self.conn.execute(sql, tuple(params))
        for r in cur:
            yield dict(r)

    def scalar(self, sql: str, params: Iterable = ()) -> Any:
        r = self.execute(sql, params).fetchone()
        return r[0] if r else None

    def meta(self, key: str, value: Any = None) -> Any:
        if value is None:
            v = self.scalar("SELECT value FROM meta WHERE key=?", (key,))
            return json.loads(v) if v else None
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, _json(value)))
        return value

    # ------------------------------------------------------------- evidence
    def add_evidence(self, label: str, role: str, path: str, fmt: str, size: int, info: dict, notes: str = "",
                     options: dict | None = None) -> int:
        from .timeutil import UTC, db_ts
        from datetime import datetime

        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO evidence(label, role, path, format, size, added_utc, info_json, notes, options_json)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (label, role, path, fmt, size, db_ts(datetime.now(UTC)), _json(info), notes, _json(options or {})),
            )
        return cur.lastrowid

    def update_evidence(self, evidence_id: int, **fields) -> None:
        cols, vals = [], []
        for k, v in fields.items():
            if k in ("info", "hashes", "os", "options"):
                k = f"{k}_json"
                v = _json(v)
            cols.append(f"{k}=?")
            vals.append(v)
        with self.conn:
            self.conn.execute(f"UPDATE evidence SET {', '.join(cols)} WHERE id=?", (*vals, evidence_id))

    def evidence(self, evidence_id: int | None = None) -> list[dict] | dict | None:
        rows = self.query("SELECT * FROM evidence" + (" WHERE id=?" if evidence_id else " ORDER BY id"),
                          (evidence_id,) if evidence_id else ())
        for r in rows:
            for k in ("info_json", "hashes_json", "os_json", "options_json"):
                r[k[:-5]] = json.loads(r[k]) if r.get(k) else {}
        if evidence_id:
            return rows[0] if rows else None
        return rows

    # ------------------------------------------------------------- artifacts
    def register_type(self, type_id: str, title: str, category: str, module: str, columns: list, description: str):
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO artifact_types VALUES (?,?,?,?,?,?)",
                (type_id, title, category, module, _json(columns), description),
            )

    def artifact_types(self) -> dict[str, dict]:
        out = {}
        for r in self.query("SELECT * FROM artifact_types"):
            r["columns"] = json.loads(r["columns_json"] or "[]")
            out[r["type"]] = r
        return out

    def insert_artifacts(self, rows: list[tuple]) -> None:
        """rows: (evidence_id, type, ts, ts_label, user, source, summary, data_json, tags)."""
        self.executemany(
            "INSERT INTO artifacts(evidence_id, type, ts, ts_label, user, source, summary, data_json, tags)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )

    def artifacts(self, evidence_id: int | None = None, type_: str | None = None, where: str = "",
                  params: Iterable = (), order: str = "ts", limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM artifacts WHERE 1=1"
        args: list = []
        if evidence_id is not None:
            sql += " AND evidence_id=?"
            args.append(evidence_id)
        if type_:
            if isinstance(type_, (list, tuple)):
                sql += f" AND type IN ({','.join('?' * len(type_))})"
                args.extend(type_)
            else:
                sql += " AND type=?"
                args.append(type_)
        if where:
            sql += f" AND ({where})"
            args.extend(params)
        if order:
            sql += f" ORDER BY {order}"
        if limit:
            sql += f" LIMIT {int(limit)}"
        rows = self.query(sql, args)
        for r in rows:
            r["data"] = json.loads(r["data_json"]) if r.get("data_json") else {}
        return rows

    def count_artifacts(self, evidence_id: int | None = None) -> dict[str, int]:
        sql = "SELECT type, COUNT(*) AS n FROM artifacts"
        args = ()
        if evidence_id is not None:
            sql += " WHERE evidence_id=?"
            args = (evidence_id,)
        sql += " GROUP BY type"
        return {r["type"]: r["n"] for r in self.query(sql, args)}

    def tag_artifact(self, artifact_id: int, tag: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE artifacts SET tags = CASE WHEN tags IS NULL OR tags='' THEN ? "
                "WHEN instr(','||tags||',', ','||?||',')>0 THEN tags ELSE tags||','||? END WHERE id=?",
                (tag, tag, tag, artifact_id),
            )

    # ------------------------------------------------------------- filesystem entries
    FS_COLS = ("evidence_id", "volume", "record", "seq", "parent", "path", "name", "ext", "size", "is_dir",
               "deleted", "si_created", "si_modified", "si_accessed", "si_changed", "fn_created", "fn_modified",
               "fn_accessed", "fn_changed", "ads", "resident", "flags")

    def insert_fs(self, rows: list[tuple]) -> None:
        self.executemany(
            f"INSERT INTO fs_entries({', '.join(self.FS_COLS)}) VALUES ({','.join('?' * len(self.FS_COLS))})", rows
        )

    def insert_usn(self, rows: list[tuple]) -> None:
        """rows: (evidence_id, volume, usn, ts, record, seq, parent, name, path, reason, reason_flags, attributes)."""
        self.executemany("INSERT INTO usn(evidence_id, volume, usn, ts, record, seq, parent, name, path, reason, reason_flags,"
                         " attributes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_volume(self, evidence_id: int, **f) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO volumes(evidence_id, name, number, offset, size, fs, label, serial, cluster_size, letter,"
                " runs_file, info_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (evidence_id, f.get("name"), f.get("number"), f.get("offset"), f.get("size"), f.get("fs"), f.get("label"),
                 f.get("serial"), f.get("cluster_size"), f.get("letter"), f.get("runs_file"), _json(f.get("info") or {})))
        return cur.lastrowid

    def volumes(self, evidence_id: int) -> list[dict]:
        rows = self.query("SELECT * FROM volumes WHERE evidence_id=? ORDER BY id", (evidence_id,))
        for r in rows:
            r["info"] = json.loads(r["info_json"]) if r.get("info_json") else {}
        return rows

    def set_fs_hashes(self, rows: list[tuple]) -> None:
        """rows: (md5, sha1, sha256, recover, id)."""
        self.executemany("UPDATE fs_entries SET md5=?, sha1=?, sha256=?, recover=? WHERE id=?", rows)

    # ------------------------------------------------------------- coverage / hits / findings
    def add_coverage(self, evidence_id, module, artifact, location, status, count=0, detail="", duration=0.0):
        with self.conn:
            self.conn.execute(
                "INSERT INTO coverage(evidence_id, module, artifact, location, status, count, detail, duration)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (evidence_id, module, artifact, location, status, count, detail, duration),
            )

    def insert_hits(self, rows: list[tuple]) -> None:
        self.executemany(
            "INSERT INTO hits(evidence_id, search, term, term_kind, area, volume, offset, length, encoding,"
            " file_path, record, context_hex, context_text, detail_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    def add_finding(self, f: dict) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO findings(evidence_id, analyzer, category, title, severity, confidence, ts, description,"
                " details_json, refs_json, figures_json, questions, include, tags, mitre, sort_key)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    f.get("evidence_id"), f.get("analyzer"), f.get("category"), f.get("title"),
                    f.get("severity", "info"), f.get("confidence", "medium"), f.get("ts"), f.get("description"),
                    _json(f.get("details")), _json(f.get("refs")), _json(f.get("figures")),
                    ",".join(f.get("questions") or []), 1 if f.get("include", True) else 0,
                    ",".join(f.get("tags") or []), ",".join(f.get("mitre") or []), f.get("sort_key", 0),
                ),
            )
        return cur.lastrowid

    def findings(self, include_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM findings"
        if include_only:
            sql += " WHERE include=1"
        sql += " ORDER BY sort_key, id"
        rows = self.query(sql)
        for r in rows:
            r["details"] = json.loads(r["details_json"]) if r.get("details_json") else {}
            r["refs"] = json.loads(r["refs_json"]) if r.get("refs_json") else []
            r["figures"] = json.loads(r["figures_json"]) if r.get("figures_json") else []
            r["questions"] = [q for q in (r.get("questions") or "").split(",") if q]
            r["tags"] = [t for t in (r.get("tags") or "").split(",") if t]
            r["mitre"] = [t for t in (r.get("mitre") or "").split(",") if t]
        return rows

    def update_finding(self, finding_id: int, **fields) -> None:
        cols, vals = [], []
        for k, v in fields.items():
            if k in ("details", "refs", "figures"):
                k, v = f"{k}_json", _json(v)
            cols.append(f"{k}=?")
            vals.append(v)
        with self.conn:
            self.conn.execute(f"UPDATE findings SET {', '.join(cols)} WHERE id=?", (*vals, finding_id))

    def set_answer(self, question_id: str, status: str, summary: str, finding_ids: list[int]):
        from datetime import datetime
        from .timeutil import UTC, db_ts

        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO answers VALUES (?,?,?,?,?)",
                (question_id, status, summary, ",".join(str(i) for i in finding_ids), db_ts(datetime.now(UTC))),
            )

    def answers(self) -> dict[str, dict]:
        out = {}
        for r in self.query("SELECT * FROM answers"):
            r["finding_ids"] = [int(x) for x in (r.get("finding_ids") or "").split(",") if x]
            out[r["question_id"]] = r
        return out

    def insert_timeline(self, rows: list[tuple]) -> None:
        """rows: (evidence_id, ts, source, event, description, user, ref_kind, ref_id, flagged)."""
        self.executemany(
            "INSERT INTO timeline(evidence_id, ts, source, event, description, user, ref_kind, ref_id, flagged)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )

    def insert_doc_text(self, rows: list[tuple]) -> None:
        self.executemany("INSERT INTO doc_text(evidence_id, path, source, content) VALUES (?,?,?,?)", rows)

    def clear_evidence_results(self, evidence_id: int) -> None:
        with self.conn:
            for table in ("artifacts", "fs_entries", "coverage", "hits", "findings", "timeline", "exported", "volumes", "usn"):
                self.conn.execute(f"DELETE FROM {table} WHERE evidence_id=?", (evidence_id,))
            self.conn.execute("DELETE FROM doc_text WHERE evidence_id=?", (evidence_id,))

    def clear_case_findings(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM findings")
            self.conn.execute("DELETE FROM answers")
            self.conn.execute("DELETE FROM timeline")


class BatchWriter:
    """Buffers inserts and flushes them in transactions."""

    def __init__(self, db: CaseDB, flush_every: int = 2000):
        self.db = db
        self.flush_every = flush_every
        self._art: list[tuple] = []
        self._fs: list[tuple] = []
        self._hits: list[tuple] = []
        self._docs: list[tuple] = []
        self.counts: dict[str, int] = {}

    def artifact(self, row: tuple) -> None:
        self._art.append(row)
        self.counts[row[1]] = self.counts.get(row[1], 0) + 1
        if len(self._art) >= self.flush_every:
            self.flush()

    def fs(self, row: tuple) -> None:
        self._fs.append(row)
        if len(self._fs) >= self.flush_every * 5:
            self.flush()

    def hit(self, row: tuple) -> None:
        self._hits.append(row)
        if len(self._hits) >= self.flush_every:
            self.flush()

    def doc(self, row: tuple) -> None:
        self._docs.append(row)
        if len(self._docs) >= 200:
            self.flush()

    def flush(self) -> None:
        if self._art:
            self.db.insert_artifacts(self._art)
            self._art = []
        if self._fs:
            self.db.insert_fs(self._fs)
            self._fs = []
        if self._hits:
            self.db.insert_hits(self._hits)
            self._hits = []
        if self._docs:
            self.db.insert_doc_text(self._docs)
            self._docs = []
