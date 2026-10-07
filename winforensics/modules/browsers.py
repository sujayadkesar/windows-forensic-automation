"""Web browser artifacts for Chromium based browsers (Chrome, Edge, Brave, Opera, Vivaldi, ...) and Firefox."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile

from ..core.timeutil import db_ts, prtime, unix, webkit
from ..knowledge import category_title, classify_url, host_of
from .base import ArtifactModule, ArtifactType, C, register

TRANSITIONS = {0: "Link", 1: "Typed", 2: "Auto bookmark", 3: "Auto subframe", 4: "Manual subframe", 5: "Generated",
               6: "Auto toplevel", 7: "Form submit", 8: "Reload", 9: "Keyword", 10: "Keyword generated"}
FF_VISIT = {1: "Link", 2: "Typed", 3: "Bookmark", 4: "Embed", 5: "Redirect (permanent)", 6: "Redirect (temporary)",
            7: "Download", 8: "Framed link", 9: "Reload"}
DL_STATE = {0: "In progress", 1: "Complete", 2: "Canceled", 3: "Interrupted", 4: "Interrupted"}
DANGER = {0: "", 1: "Dangerous file", 2: "Dangerous URL", 3: "Dangerous content", 4: "Maybe dangerous", 5: "Uncommon",
          6: "User validated", 7: "Dangerous host", 8: "Potentially unwanted", 9: "Allowlisted by policy",
          10: "Async scanning", 11: "Blocked password protected", 12: "Blocked too large", 13: "Sensitive content warning",
          14: "Sensitive content block", 15: "Deep scanned safe", 16: "Deep scanned opened dangerous"}


def browser_name(path: str) -> str:
    low = path.lower()
    for key, name in (("\\microsoft\\edge\\", "Edge"), ("\\google\\chrome\\", "Chrome"), ("\\bravesoftware\\", "Brave"),
                      ("\\opera software\\opera gx", "Opera GX"), ("\\opera software\\", "Opera"), ("\\vivaldi\\", "Vivaldi"),
                      ("\\yandex\\", "Yandex"), ("\\chromium\\", "Chromium"), ("\\mozilla\\firefox\\", "Firefox"),
                      ("\\waterfox\\", "Waterfox"), ("\\librewolf\\", "LibreWolf"), ("\\tor browser\\", "Tor Browser"),
                      ("\\thunderbird\\", "Thunderbird"), ("\\arc\\", "Arc"), ("\\comodo\\dragon", "Comodo Dragon"),
                      ("\\epic privacy browser", "Epic"), ("\\coccoc\\", "CocCoc"), ("\\360chrome", "360 Browser")):
        if key in low:
            return name
    return "Chromium-based"


def _profile(path: str) -> str:
    parts = path.replace("/", "\\").split("\\")
    return parts[-2] if len(parts) >= 2 else ""


def _classify(url: str) -> tuple[str, str]:
    c = classify_url(url or "")
    return (category_title(c[0]), c[1]) if c else ("", "")


@register
class BrowsersModule(ArtifactModule):
    id = "browsers"
    title = "Web browsers"
    category = "Browser Activity"
    description = ("History, downloads, search terms, saved-login user names, autofill entries, cookie hosts and extensions "
                   "for Chrome, Edge, Brave, Opera, Vivaldi, Firefox and other Chromium/Gecko browsers.")
    weight = 3.0
    order = 35
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Local\\<vendor>\\User Data\\<profile>\\History / Login Data / Web Data / Cookies",
                 "Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite / formhistory.sqlite / cookies.sqlite",
                 "Users\\*\\AppData\\Roaming\\Opera Software\\*"]
    artifact_types = [
        ArtifactType("web_visit", "Web History", "Browser Activity",
                     [C("visit_time", kind="datetime"), C("url", kind="url", width=420), C("title", width=260),
                      C("category"), C("service"), C("transition"), C("visit_count", "Visits", "int"), C("browser"),
                      C("profile")], ts_label="Visited"),
        ArtifactType("web_download", "Web Downloads", "Browser Activity",
                     [C("start_time", kind="datetime"), C("target_path", "Saved To", "path", 360), C("url", kind="url", width=360),
                      C("tab_url", "Page URL", "url", 260), C("referrer", kind="url", width=200), C("size", kind="size"),
                      C("state"), C("danger"), C("opened"), C("mime_type", "MIME"), C("browser")], ts_label="Download start"),
        ArtifactType("web_search", "Web Search Terms", "Browser Activity",
                     [C("time", kind="datetime"), C("term", width=320), C("engine"), C("url", kind="url", width=360),
                      C("browser")], ts_label="Searched"),
        ArtifactType("web_login", "Saved Logins (user names only)", "Browser Activity",
                     [C("origin", kind="url", width=320), C("username", width=220), C("created", kind="datetime"),
                      C("last_used", kind="datetime"), C("times_used", kind="int"), C("category"), C("browser")],
                     ts_label="Created"),
        ArtifactType("web_autofill", "Autofill / Form History", "Browser Activity",
                     [C("field"), C("value", width=320), C("first_used", kind="datetime"), C("last_used", kind="datetime"),
                      C("count", kind="int"), C("browser")], ts_label="Last used"),
        ArtifactType("web_cookie_host", "Cookie Hosts (sessions with sites)", "Browser Activity",
                     [C("host", width=280), C("cookies", kind="int"), C("first_created", kind="datetime"),
                      C("last_accessed", kind="datetime"), C("category"), C("service"), C("browser")],
                     ts_label="Last accessed"),
        ArtifactType("browser_extension", "Browser Extensions", "Browser Activity",
                     [C("name", width=260), C("id", "Extension ID", width=260), C("version"), C("permissions", width=300),
                      C("installed", kind="datetime"), C("browser"), C("profile")], ts_label="Folder created"),
    ]

    def run(self, ctx) -> None:
        tmp = tempfile.mkdtemp(prefix="vb_", dir=ctx.case.sub("temp"))
        try:
            hist = ctx.fs_files("name='History' AND ext='' AND (lower(path) LIKE '%\\user data\\%' OR lower(path) LIKE '%\\opera%')")
            places = ctx.fs_files("lower(name)='places.sqlite'")
            total = max(1, len(hist) + len(places))
            done = 0
            nvis = 0
            for row in hist:
                nvis += self._chromium(ctx, row, tmp)
                done += 1
                ctx.progress(done / total)
            for row in places:
                nvis += self._firefox(ctx, row, tmp)
                done += 1
                ctx.progress(done / total)
            self._extensions(ctx)
            ctx.coverage("Chromium browser history", "User Data\\<profile>\\History", "found" if hist else "absent", len(hist),
                         ", ".join(sorted({browser_name(r['path']) for r in hist})))
            ctx.coverage("Firefox history", "Profiles\\*\\places.sqlite", "found" if places else "absent", len(places))
            for t in ("web_visit", "web_download", "web_search", "web_login", "web_autofill", "web_cookie_host"):
                n = ctx.counts.get(t, 0)
                ctx.coverage(t.replace("web_", "Web ").replace("_", " "), "browser profiles",
                             "found" if n else ("not_found" if hist or places else "absent"), n)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ------------------------------------------------------------------ helpers
    def _copy_db(self, ctx, row, tmp) -> str | None:
        """Copy an SQLite DB (+ WAL / journal) out of the image and return the local path."""
        base = os.path.join(tmp, f"{row['volume'].strip(':')}_{row['record']}_{row['name']}")
        try:
            with open(base, "wb") as fh:
                fh.write(ctx.read_entry(row))
        except Exception:
            return None
        folder = row["path"].rsplit("\\", 1)[0]
        for suffix in ("-wal", "-journal"):
            side = ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND volume=? AND path=? AND deleted=0 LIMIT 1",
                                (ctx.evidence_id, row["volume"], f"{folder}\\{row['name']}{suffix}"))
            if side:
                try:
                    with open(base + suffix, "wb") as fh:
                        fh.write(ctx.read_entry(side[0]))
                except Exception:
                    pass
        return base

    def _sibling(self, ctx, row, name):
        folder = row["path"].rsplit("\\", 1)[0]
        r = ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND volume=? AND path=? AND deleted=0 LIMIT 1",
                         (ctx.evidence_id, row["volume"], f"{folder}\\{name}"))
        return r[0] if r else None

    @staticmethod
    def _q(db, sql):
        try:
            return db.execute(sql).fetchall()
        except sqlite3.Error:
            return []

    # ------------------------------------------------------------------ chromium
    def _chromium(self, ctx, row, tmp) -> int:
        full = ctx.display_path(row["volume"], row["path"])
        browser = browser_name(full)
        profile = _profile(full)
        user = ctx.user_for_path(full)
        local = self._copy_db(ctx, row, tmp)
        if not local:
            return 0
        n = 0
        try:
            db = sqlite3.connect(local)
            db.row_factory = sqlite3.Row
        except sqlite3.Error:
            return 0
        common = {"browser": browser, "profile": profile, "db": full}
        visits = self._q(db, "SELECT v.id, v.visit_time, v.transition, v.from_visit, v.visit_duration, u.url, u.title, "
                             "u.visit_count, u.typed_count FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time")
        for v in visits:
            ts = webkit(v["visit_time"])
            cat, svc = _classify(v["url"])
            rec = {**common, "visit_time": db_ts(ts), "url": v["url"], "title": v["title"], "visit_count": v["visit_count"],
                   "typed_count": v["typed_count"], "transition": TRANSITIONS.get((v["transition"] or 0) & 0xFF, ""),
                   "duration_s": round((v["visit_duration"] or 0) / 1e6, 1), "domain": host_of(v["url"]),
                   "category": cat, "service": svc}
            ctx.emit("web_visit", ts, rec, user=user, summary=f"{browser}: {v['title'] or ''} {v['url']}"[:300], source=full,
                     ts_label="Visited", tags=["exfil_destination"] if cat in ("Webmail", "Cloud storage", "File transfer service",
                                                                                 "Paste site", "AI assistant") else None)
            n += 1
        if not visits:  # very old / damaged DBs: fall back to urls table
            for u in self._q(db, "SELECT url, title, visit_count, last_visit_time FROM urls"):
                ts = webkit(u["last_visit_time"])
                cat, svc = _classify(u["url"])
                ctx.emit("web_visit", ts, {**common, "visit_time": db_ts(ts), "url": u["url"], "title": u["title"],
                                           "visit_count": u["visit_count"], "transition": "(last visit)", "domain": host_of(u["url"]),
                                           "category": cat, "service": svc},
                         user=user, summary=f"{browser}: {u['url']}"[:300], source=full, ts_label="Last visited")
                n += 1
        chains = {}
        for c in self._q(db, "SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
            chains.setdefault(c["id"], []).append(c["url"])
        for d in self._q(db, "SELECT * FROM downloads"):
            keys = d.keys()
            ts = webkit(d["start_time"])
            url = (chains.get(d["id"]) or [None])[-1] or (d["url"] if "url" in keys else "")
            rec = {**common, "start_time": db_ts(ts), "end_time": db_ts(webkit(d["end_time"])) if "end_time" in keys else None,
                   "target_path": d["target_path"] or d["current_path"], "url": url, "url_chain": chains.get(d["id"], []),
                   "tab_url": d["tab_url"] if "tab_url" in keys else "", "referrer": d["referrer"] if "referrer" in keys else "",
                   "site_url": d["site_url"] if "site_url" in keys else "", "size": d["total_bytes"],
                   "received": d["received_bytes"], "state": DL_STATE.get(d["state"], str(d["state"])),
                   "danger": DANGER.get(d["danger_type"], str(d["danger_type"])) if "danger_type" in keys else "",
                   "opened": "Yes" if "opened" in keys and d["opened"] else "", "mime_type": d["mime_type"] if "mime_type" in keys else "",
                   "last_access": db_ts(webkit(d["last_access_time"])) if "last_access_time" in keys else None}
            ctx.emit("web_download", ts, rec, user=user, summary=f"{browser} download {rec['target_path']} <- {url}"[:300],
                     source=full, ts_label="Download start")
        for s in self._q(db, "SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id"):
            ts = webkit(s["last_visit_time"])
            ctx.emit("web_search", ts, {**common, "time": db_ts(ts), "term": s["term"], "url": s["url"],
                                        "engine": host_of(s["url"])}, user=user, summary=f"{browser} search: {s['term']}",
                     source=full, ts_label="Searched")
        db.close()
        # Login Data / Web Data / Cookies
        for name, fn in (("Login Data", self._ch_logins), ("Web Data", self._ch_autofill), ("Cookies", self._ch_cookies)):
            srow = self._sibling(ctx, row, name)
            if srow is None and name == "Cookies":
                folder = row["path"].rsplit("\\", 1)[0] + "\\Network"
                r = ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND volume=? AND path=? AND deleted=0 LIMIT 1",
                                 (ctx.evidence_id, row["volume"], f"{folder}\\Cookies"))
                srow = r[0] if r else None
            if srow is None:
                continue
            p = self._copy_db(ctx, srow, tmp)
            if p:
                try:
                    sdb = sqlite3.connect(p)
                    sdb.row_factory = sqlite3.Row
                    fn(ctx, sdb, common, user, ctx.display_path(srow["volume"], srow["path"]))
                    sdb.close()
                except sqlite3.Error:
                    pass
        return n

    def _ch_logins(self, ctx, db, common, user, src):
        for r in self._q(db, "SELECT origin_url, username_value, date_created, date_last_used, times_used FROM logins"):
            if not r["username_value"]:
                continue
            cat, svc = _classify(r["origin_url"])
            ts = webkit(r["date_created"])
            ctx.emit("web_login", ts, {**common, "origin": r["origin_url"], "username": r["username_value"],
                                       "created": db_ts(ts), "last_used": db_ts(webkit(r["date_last_used"])),
                                       "times_used": r["times_used"], "category": cat, "service": svc},
                     user=user, summary=f"{common['browser']} saved login {r['username_value']} @ {r['origin_url']}", source=src,
                     ts_label="Created")

    def _ch_autofill(self, ctx, db, common, user, src):
        for r in self._q(db, "SELECT name, value, date_created, date_last_used, count FROM autofill"):
            ts = unix(r["date_last_used"])
            ctx.emit("web_autofill", ts, {**common, "field": r["name"], "value": r["value"], "first_used": db_ts(unix(r["date_created"])),
                                          "last_used": db_ts(ts), "count": r["count"]},
                     user=user, summary=f"Autofill {r['name']}={r['value']}"[:200], source=src, ts_label="Last used")

    def _ch_cookies(self, ctx, db, common, user, src):
        for r in self._q(db, "SELECT host_key, COUNT(*) n, MIN(creation_utc) c, MAX(last_access_utc) a FROM cookies GROUP BY host_key"):
            host = (r["host_key"] or "").lstrip(".")
            cat, svc = _classify(host)
            ts = webkit(r["a"])
            ctx.emit("web_cookie_host", ts, {**common, "host": host, "cookies": r["n"], "first_created": db_ts(webkit(r["c"])),
                                             "last_accessed": db_ts(ts), "category": cat, "service": svc},
                     user=user, summary=f"Cookies for {host} ({r['n']})", source=src, ts_label="Last accessed")

    # ------------------------------------------------------------------ firefox
    def _firefox(self, ctx, row, tmp) -> int:
        full = ctx.display_path(row["volume"], row["path"])
        browser = browser_name(full)
        profile = _profile(full)
        user = ctx.user_for_path(full)
        local = self._copy_db(ctx, row, tmp)
        if not local:
            return 0
        n = 0
        try:
            db = sqlite3.connect(local)
            db.row_factory = sqlite3.Row
        except sqlite3.Error:
            return 0
        common = {"browser": browser, "profile": profile, "db": full}
        for v in self._q(db, "SELECT v.visit_date, v.visit_type, p.url, p.title, p.visit_count, p.typed FROM moz_historyvisits v "
                             "JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"):
            ts = prtime(v["visit_date"])
            cat, svc = _classify(v["url"])
            ctx.emit("web_visit", ts, {**common, "visit_time": db_ts(ts), "url": v["url"], "title": v["title"],
                                       "visit_count": v["visit_count"], "typed_count": v["typed"],
                                       "transition": FF_VISIT.get(v["visit_type"], str(v["visit_type"])),
                                       "domain": host_of(v["url"]), "category": cat, "service": svc},
                     user=user, summary=f"{browser}: {v['title'] or ''} {v['url']}"[:300], source=full, ts_label="Visited",
                     tags=["exfil_destination"] if cat in ("Webmail", "Cloud storage", "File transfer service", "Paste site",
                                                           "AI assistant") else None)
            n += 1
        # downloads (annotations, Firefox 26+)
        attrs = {r["id"]: r["name"] for r in self._q(db, "SELECT id, name FROM moz_anno_attributes")}
        dl: dict[int, dict] = {}
        for a in self._q(db, "SELECT place_id, anno_attribute_id, content, dateAdded FROM moz_annos"):
            name = attrs.get(a["anno_attribute_id"], "")
            if not name.startswith("downloads/"):
                continue
            d = dl.setdefault(a["place_id"], {})
            if name == "downloads/destinationFileURI":
                d["target"] = a["content"]
                d["added"] = a["dateAdded"]
            elif name == "downloads/metaData":
                try:
                    d["meta"] = json.loads(a["content"])
                except Exception:
                    d["meta"] = {}
        urls = {r["id"]: r["url"] for r in self._q(db, "SELECT id, url FROM moz_places")} if dl else {}
        for pid, d in dl.items():
            ts = prtime(d.get("added"))
            meta = d.get("meta") or {}
            target = (d.get("target") or "").replace("file:///", "").replace("/", "\\")
            rec = {**common, "start_time": db_ts(ts), "end_time": db_ts(unix(meta.get("endTime", 0) / 1000)) if meta.get("endTime") else None,
                   "target_path": target, "url": urls.get(pid, ""), "size": meta.get("fileSize"),
                   "state": {1: "Complete", 3: "Canceled", 0: "In progress", 4: "Paused"}.get(meta.get("state"), str(meta.get("state", ""))),
                   "tab_url": "", "referrer": "", "danger": "", "opened": "", "mime_type": ""}
            ctx.emit("web_download", ts, rec, user=user, summary=f"{browser} download {target} <- {rec['url']}"[:300], source=full,
                     ts_label="Download start")
        db.close()
        for name, fn in (("formhistory.sqlite", self._ff_forms), ("cookies.sqlite", self._ff_cookies)):
            srow = self._sibling(ctx, row, name)
            if srow is None:
                continue
            p = self._copy_db(ctx, srow, tmp)
            if p:
                try:
                    sdb = sqlite3.connect(p)
                    sdb.row_factory = sqlite3.Row
                    fn(ctx, sdb, common, user, ctx.display_path(srow["volume"], srow["path"]))
                    sdb.close()
                except sqlite3.Error:
                    pass
        lj = self._sibling(ctx, row, "logins.json")
        if lj is not None:
            try:
                data = json.loads(ctx.read_entry(lj))
                for lg in data.get("logins", []):
                    ts = unix((lg.get("timeCreated") or 0) / 1000)
                    cat, svc = _classify(lg.get("hostname", ""))
                    ctx.emit("web_login", ts, {**common, "origin": lg.get("hostname"), "username": "(encrypted)",
                                               "created": db_ts(ts), "last_used": db_ts(unix((lg.get("timeLastUsed") or 0) / 1000)),
                                               "times_used": lg.get("timesUsed"), "category": cat, "service": svc},
                             user=user, summary=f"Firefox saved login for {lg.get('hostname')}", source=ctx.display_path(lj["volume"], lj["path"]),
                             ts_label="Created")
            except Exception:
                pass
        return n

    def _ff_forms(self, ctx, db, common, user, src):
        for r in self._q(db, "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory"):
            ts = prtime(r["lastUsed"])
            ctx.emit("web_autofill", ts, {**common, "field": r["fieldname"], "value": r["value"], "first_used": db_ts(prtime(r["firstUsed"])),
                                          "last_used": db_ts(ts), "count": r["timesUsed"]},
                     user=user, summary=f"Form history {r['fieldname']}={r['value']}"[:200], source=src, ts_label="Last used")

    def _ff_cookies(self, ctx, db, common, user, src):
        for r in self._q(db, "SELECT host, COUNT(*) n, MIN(creationTime) c, MAX(lastAccessed) a FROM moz_cookies GROUP BY host"):
            host = (r["host"] or "").lstrip(".")
            cat, svc = _classify(host)
            ts = prtime(r["a"])
            ctx.emit("web_cookie_host", ts, {**common, "host": host, "cookies": r["n"], "first_created": db_ts(prtime(r["c"])),
                                             "last_accessed": db_ts(ts), "category": cat, "service": svc},
                     user=user, summary=f"Cookies for {host} ({r['n']})", source=src, ts_label="Last accessed")

    # ------------------------------------------------------------------ extensions
    def _extensions(self, ctx) -> None:
        rows = ctx.fs_files("lower(name)='manifest.json' AND lower(path) LIKE '%\\extensions\\%'", limit=5000)
        n = 0
        for row in rows:
            full = ctx.display_path(row["volume"], row["path"])
            m = re.search(r"\\([^\\]+)\\Extensions\\([a-p]{32})\\([^\\]+)\\manifest\.json$", full, re.I)
            if not m:
                continue
            try:
                man = json.loads(ctx.read_entry(row, 2_000_000).decode("utf-8-sig", "replace"))
            except Exception:
                continue
            name = man.get("name", "")
            if name.startswith("__MSG_"):
                name = f"{name} ({man.get('short_name', '')})"
            perms = man.get("permissions", []) + man.get("host_permissions", [])
            ctx.emit("browser_extension", row.get("si_created"), {
                "name": name, "id": m.group(2), "version": m.group(3), "permissions": ", ".join(str(p) for p in perms)[:600],
                "installed": row.get("si_created"), "browser": browser_name(full), "profile": m.group(1),
                "description": str(man.get("description", ""))[:300]},
                user=ctx.user_for_path(full), summary=f"Extension {name} {m.group(2)}", source=full, ts_label="Folder created")
            n += 1
        ctx.coverage("Browser extensions", "User Data\\<profile>\\Extensions\\*\\manifest.json", "found" if n else "not_found", n)
