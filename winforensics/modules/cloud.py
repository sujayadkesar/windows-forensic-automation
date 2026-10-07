"""Cloud storage / sync clients: accounts, sync folders and (where recorded) synced items."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile

from ..core.timeutil import db_ts, unix
from ._regutil import iter_keys, key_user, subkeys, ts_of, val
from .base import ArtifactModule, ArtifactType, C, register

RX_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+")


@register
class CloudModule(ArtifactModule):
    id = "cloud"
    title = "Cloud storage clients"
    category = "Cloud & Sync"
    description = ("OneDrive, Google Drive for desktop, Dropbox, Box, MEGA, iCloud, pCloud, Nextcloud: signed-in accounts, "
                   "local sync folders and synced item databases.")
    weight = 1.5
    order = 45
    requires = ["filesystem"]
    locations = ["NTUSER\\Software\\Microsoft\\OneDrive\\Accounts", "AppData\\Local\\Microsoft\\OneDrive\\settings",
                 "AppData\\Local\\Google\\DriveFS", "AppData\\Local\\Dropbox\\info.json", "AppData\\Local\\Mega Limited\\MEGAsync",
                 "AppData\\Roaming\\Nextcloud\\nextcloud.cfg"]
    artifact_types = [
        ArtifactType("cloud_account", "Cloud Storage Accounts", "Cloud & Sync",
                     [C("service"), C("account", width=260), C("local_folder", "Sync Folder", "path", 320), C("details", width=300),
                      C("source", width=300), C("last_modified", kind="datetime")], ts_label="Config last modified"),
        ArtifactType("cloud_item", "Cloud Synced Items", "Cloud & Sync",
                     [C("service"), C("name", width=300), C("path", kind="path", width=320), C("size", kind="size"),
                      C("modified", kind="datetime"), C("event"), C("trashed"), C("account")], ts_label="Modified / event"),
    ]

    def run(self, ctx) -> None:
        tmp = tempfile.mkdtemp(dir=ctx.case.sub("temp"))
        try:
            for i, fn in enumerate([self._onedrive, self._gdrive, self._gdrive_legacy, self._dropbox, self._others]):
                try:
                    fn(ctx, tmp)
                except Exception as e:
                    ctx.warn(f"cloud {fn.__name__}: {e}")
                ctx.progress((i + 1) / 5)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        n = ctx.counts.get("cloud_account", 0) + ctx.counts.get("cloud_item", 0)
        ctx.coverage("Cloud storage clients", "OneDrive, Google Drive, Dropbox, Box, MEGA, iCloud, pCloud, Nextcloud",
                     "found" if n else "not_found", n)

    def _acct(self, ctx, service, account, folder, details, source, ts, user=None):
        ctx.emit("cloud_account", ts, {"service": service, "account": account, "local_folder": folder, "details": details,
                                       "source": source, "last_modified": db_ts(ts) if not isinstance(ts, str) else ts},
                 user=user, summary=f"{service} account {account or '(not recorded)'} - sync folder {folder or '(not recorded)'}",
                 source=source,
                 ts_label="Config last modified", tags=["cloud"])

    def _onedrive(self, ctx, tmp):
        reg = ctx.target.registry
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\OneDrive\\Accounts"):
            user = key_user(reg, k)
            for a in subkeys(k):
                email = val(a, "UserEmail")
                folder = val(a, "UserFolder")
                if not (email or folder):
                    continue
                kind = "OneDrive Personal" if a.name.lower() == "personal" else f"OneDrive for Business ({a.name})"
                self._acct(ctx, kind, email, folder, f"cid={val(a, 'cid') or ''} tenant={val(a, 'DisplayName') or ''}",
                           f"NTUSER\\Software\\Microsoft\\OneDrive\\Accounts\\{a.name}", ts_of(a), user)

    def _gdrive_legacy(self, ctx, tmp):
        """Google Drive (2014-2018) / Backup and Sync: sync_config.db, snapshot.db (cloud + local entries), sync_log.log."""
        rows = ctx.fs_files(r"lower(path) LIKE '%\google\drive\%' AND lower(name) IN ('sync_config.db', "
                            "'snapshot.db', 'sync_log.log')", include_deleted=True)
        rows.sort(key=lambda r: r["deleted"])  # prefer the allocated copy when both exist
        by_dir: dict[str, dict] = {}
        for row in rows:
            by_dir.setdefault(row["path"].rsplit("\\", 1)[0].lower(), {}).setdefault(row["name"].lower(), row)

        def copy(row):
            local = os.path.join(tmp, f"gdl_{row['record']}_{row['name']}")
            with open(local, "wb") as fh:
                fh.write(ctx.read_entry(row))
            return local

        for _d, files in by_dir.items():
            any_row = next(iter(files.values()))
            src_dir = ctx.display_path(any_row["volume"], any_row["path"].rsplit("\\", 1)[0])
            user = ctx.user_for_path(src_dir)
            email, root = "", ""
            log_text = ""
            if "sync_log.log" in files:
                try:
                    log_text = ctx.read_entry(files["sync_log.log"]).decode("utf-8", "replace")
                except Exception:
                    log_text = ""
            # the client logs the signed-in account when it starts a session
            acc = re.findall(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ ([+-]\d{4}) .*?Initializing User instance with new "
                             r"credentials\.\s*([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", log_text, re.M)
            log_email = acc[0][2] if acc else ""
            if "sync_config.db" in files:
                try:
                    db = sqlite3.connect(copy(files["sync_config.db"]))
                    for k, v in db.execute("SELECT entry_key, data_value FROM data"):
                        if k == "user_email":
                            email = str(v)
                        elif k == "local_sync_root_path":
                            root = str(v).replace("\\?\\", "")
                    db.close()
                except Exception as e:
                    ctx.warn(f"Google Drive sync_config.db: {e}")
                deleted = bool(files["sync_config.db"].get("deleted"))
                cfg_note = "sync_config.db" + ((" (deleted record; contents not recoverable)" if not (email or root) else
                                                " (deleted record)") if deleted else "")
                if not email and log_email:
                    cfg_note += "; account from sync_log.log"
                self._acct(ctx, "Google Drive (legacy client)", email or log_email, root, cfg_note, src_dir + "\\sync_config.db",
                           files["sync_config.db"].get("si_modified"), user)
            elif log_email:
                from datetime import datetime as _dt

                first = _dt.strptime(f"{acc[0][0]} {acc[0][1]}", "%Y-%m-%d %H:%M:%S %z")
                self._acct(ctx, "Google Drive (legacy client)", log_email, "", "signed-in account recorded in sync_log.log",
                           src_dir + "\\sync_log.log", first, user)
            email = email or log_email
            if "snapshot.db" in files:
                try:
                    db = sqlite3.connect(copy(files["snapshot.db"]))
                    db.row_factory = sqlite3.Row
                    n = 0
                    for r in db.execute("SELECT * FROM cloud_entry"):
                        d = dict(r)
                        if d.get("doc_type") == 0 or d.get("resource_type") == "folder":
                            continue
                        ts = unix(d.get("modified")) if d.get("modified") else None
                        ctx.emit("cloud_item", ts, {"service": "Google Drive (legacy)", "name": d.get("filename"), "path": "",
                                                    "size": d.get("size"), "modified": db_ts(ts), "created": db_ts(unix(d["created"]))
                                                    if d.get("created") else None, "event": "item in cloud",
                                                    "trashed": "Yes" if d.get("removed") else "", "account": email,
                                                    "md5": d.get("checksum"), "shared": d.get("shared")},
                                 user=user, summary=f"Google Drive item {d.get('filename')}", source=src_dir + r"\snapshot.db",
                                 ts_label="Modified")
                        n += 1
                    for r in db.execute("SELECT * FROM local_entry"):
                        d = dict(r)
                        if d.get("is_folder"):
                            continue
                        ts = unix(d.get("modified")) if d.get("modified") else None
                        ctx.emit("cloud_item", ts, {"service": "Google Drive (legacy)", "name": d.get("filename"),
                                                    "path": root, "size": d.get("size"), "modified": db_ts(ts),
                                                    "event": "item in local sync folder", "trashed": "", "account": email,
                                                    "md5": d.get("checksum")},
                                 user=user, summary=f"Google Drive local item {d.get('filename')}",
                                 source=src_dir + r"\snapshot.db", ts_label="Modified")
                        n += 1
                    db.close()
                except Exception as e:
                    ctx.warn(f"Google Drive snapshot.db: {e}")
            if log_text:
                self._gdrive_log(ctx, log_text, email, user, src_dir + "\\sync_log.log")

    GD_EVENTS = {("upload", "create"): "uploaded to Google Drive", ("upload", "modify"): "modified file uploaded to Google Drive",
                 ("upload", "delete"): "deleted from Google Drive (local deletion synchronized)",
                 ("upload", "move"): "moved / renamed in Google Drive", ("upload", "rename"): "renamed in Google Drive",
                 ("download", "create"): "downloaded from Google Drive", ("download", "modify"): "cloud change downloaded",
                 ("download", "delete"): "deleted locally (cloud deletion synchronized)",
                 ("download", "move"): "moved locally (cloud change)", ("download", "change_acl"): "sharing settings changed in the cloud"}
    RX_GD_DONE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3}) ([+-]\d{4}) .*?Worker (successfully completed|failed on|"
                            r"failed to complete) \[(.*)$")
    RX_GD_CHANGE = re.compile(r"(?:Immutable|FS)Change\(Direction\.(\w+), Action\.(\w+), ")

    def _gdrive_log(self, ctx, text, email, user, src) -> None:
        """Completed sync operations: Direction.UPLOAD = local change sent to Google Drive, DOWNLOAD = cloud change applied.
        A worker line can carry a batch of several changes; each one is reported."""
        from datetime import datetime as _dt

        for line in text.splitlines():
            m = self.RX_GD_DONE.match(line)
            if not m:
                continue
            try:
                ts = _dt.strptime(f"{m.group(1)}.{m.group(2)}000 {m.group(3)}", "%Y-%m-%d %H:%M:%S.%f %z")
            except ValueError:
                ts = None
            body = m.group(5)
            starts = [c for c in self.RX_GD_CHANGE.finditer(body)]
            for k, c in enumerate(starts):
                rest = body[c.end():starts[k + 1].start() if k + 1 < len(starts) else len(body)]
                nm = re.search(r"name=u?'([^']*)'", rest) or re.search(r"name=([^,]*)", rest)
                pm = re.search(r"path=u?'([^']*)'", rest)
                name = nm.group(1) if nm else ""
                folder = (pm.group(1) if pm else "").replace("\\\\", "\\").replace("\\\\?\\", "").replace("\\?\\", "")
                direction, action = c.group(1).lower(), c.group(2).lower()
                event = self.GD_EVENTS.get((direction, action), f"{direction} / {action}")
                if m.group(4) != "successfully completed":
                    event += " - failed"
                ctx.emit("cloud_item", ts, {"service": "Google Drive (legacy)", "name": name, "path": folder, "size": None,
                                            "modified": db_ts(ts), "event": event, "trashed": "Yes" if action == "delete" else "",
                                            "account": email, "direction": direction, "action": action},
                         user=user, summary=f"Google Drive {event}: {name}", source=src, ts_label="Sync completed",
                         tags=["cloud"] + (["cloud_upload"] if direction == "upload" else []))

    def _gdrive(self, ctx, tmp):
        rows = ctx.fs_files("lower(path) LIKE '%\\google\\drivefs\\%' AND (name='metadata_sqlite_db' OR lower(name) LIKE 'drive_fs%.txt')")
        accounts = set()
        for row in rows:
            path = ctx.display_path(row["volume"], row["path"])
            user = ctx.user_for_path(path)
            if row["name"].lower().startswith("drive_fs"):
                try:
                    text = ctx.read_entry(row, 20 * 1024 * 1024).decode("utf-8", "replace")
                except Exception:
                    continue
                for e in set(RX_EMAIL.findall(text)):
                    if not e.endswith(("google.com", "gserviceaccount.com")) and e not in accounts:
                        accounts.add(e)
                        self._acct(ctx, "Google Drive for desktop", e, "", "from DriveFS log", path, row.get("si_modified"), user)
                continue
            local = os.path.join(tmp, f"gd_{row['record']}.db")
            try:
                with open(local, "wb") as fh:
                    fh.write(ctx.read_entry(row))
                db = sqlite3.connect(local)
                db.row_factory = sqlite3.Row
                cols = [r[1] for r in db.execute("PRAGMA table_info(items)").fetchall()]
                if not cols:
                    continue
                q = "SELECT * FROM items WHERE is_folder=0" if "is_folder" in cols else "SELECT * FROM items"
                n = 0
                for r in db.execute(q):
                    d = dict(r)
                    ts = unix((d.get("modified_date") or 0) / 1000) if d.get("modified_date") else None
                    ctx.emit("cloud_item", ts, {"service": "Google Drive", "name": d.get("local_title"), "path": "",
                                                "size": d.get("file_size"), "modified": db_ts(ts), "event": "synced item",
                                                "trashed": "Yes" if d.get("trashed") else "", "account": path.split("\\DriveFS\\")[-1].split("\\")[0]},
                             user=user, summary=f"Google Drive item {d.get('local_title')}", source=path, ts_label="Modified")
                    n += 1
                    if n > 200_000:
                        break
                db.close()
            except Exception:
                continue

    def _dropbox(self, ctx, tmp):
        for row in ctx.fs_files("lower(path) LIKE '%\\dropbox\\info.json'"):
            path = ctx.display_path(row["volume"], row["path"])
            try:
                info = json.loads(ctx.read_entry(row))
            except Exception:
                continue
            for kind, d in info.items():
                if isinstance(d, dict):
                    self._acct(ctx, f"Dropbox ({kind})", str(d.get("subscription_type", "")), d.get("path"),
                               f"host={d.get('host')} team={d.get('is_team')}", path, row.get("si_modified"), ctx.user_for_path(path))
        for row in ctx.fs_files("lower(path) LIKE '%\\dropbox\\%' AND lower(name)='sync_history.db'"):
            path = ctx.display_path(row["volume"], row["path"])
            local = os.path.join(tmp, f"db_{row['record']}.db")
            try:
                with open(local, "wb") as fh:
                    fh.write(ctx.read_entry(row))
                db = sqlite3.connect(local)
                db.row_factory = sqlite3.Row
                for r in db.execute("SELECT * FROM sync_history"):
                    d = dict(r)
                    ts = unix(d.get("timestamp") or 0)
                    ctx.emit("cloud_item", ts, {"service": "Dropbox", "name": os.path.basename(str(d.get("local_path") or "")),
                                                "path": d.get("local_path"), "size": d.get("file_size"), "modified": db_ts(ts),
                                                "event": f"{d.get('direction', '')} {d.get('file_event_type', '')}".strip(),
                                                "trashed": "", "account": ""},
                             user=ctx.user_for_path(path), summary=f"Dropbox {d.get('direction')} {d.get('local_path')}",
                             source=path, ts_label="Event")
                db.close()
            except Exception:
                continue

    def _others(self, ctx, tmp):
        checks = [
            ("MEGA (MEGAsync)", "%\\mega limited\\megasync\\megasync.cfg"), ("Box Drive", "%\\appdata\\local\\box\\box\\data\\%.db"),
            ("pCloud Drive", "%\\appdata\\roaming\\pcloud\\%"), ("Nextcloud", "%\\appdata\\roaming\\nextcloud\\nextcloud.cfg"),
            ("ownCloud", "%\\appdata\\roaming\\owncloud\\owncloud.cfg"), ("iCloud Drive", "%\\appleinc.icloud%"),
            ("Sync.com", "%\\appdata\\roaming\\sync app settings\\%"), ("Tresorit", "%\\appdata\\local\\tresorit\\%"),
            ("Yandex Disk", "%\\appdata\\roaming\\yandex\\yandex.disk%"), ("Amazon Photos/Drive", "%\\appdata\\local\\amazon drive\\%"),
            ("Microsoft OneDrive (settings)", "%\\appdata\\local\\microsoft\\onedrive\\settings\\%.ini"),
        ]
        for service, pattern in checks:
            rows = ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND lower(path) LIKE ? AND deleted=0 LIMIT 20",
                                (ctx.evidence_id, pattern))
            if not rows:
                continue
            row = rows[0]
            path = ctx.display_path(row["volume"], row["path"])
            account, folder = "", ""
            if row["name"].lower().endswith((".cfg", ".ini")) and not row["is_dir"]:
                try:
                    text = ctx.read_entry(row, 2 * 1024 * 1024).decode("utf-16" if b"\x00" in ctx.read_entry(row, 64) else "utf-8", "replace")
                    m = RX_EMAIL.search(text)
                    account = m.group(0) if m else ""
                    f = re.search(r"(?:localPath|LocalPath|library_path|dataPath)\s*=\s*(.+)", text)
                    folder = f.group(1).strip() if f else ""
                except Exception:
                    pass
            self._acct(ctx, service, account, folder, f"{len(rows)} artifact(s) found", path, row.get("si_modified"),
                       ctx.user_for_path(path))
