"""Per-user registry activity: MRU lists, Run box, UserAssist, Office MRU, shellbags, typed paths/URLs."""

from __future__ import annotations

import codecs
import re
import struct

from ..core.timeutil import db_ts, filetime
from ..knowledge import score_command
from ._regutil import iter_keys, key_user, mru_order, subkeys, ts_of, val, values
from .base import ArtifactModule, ArtifactType, C, register

UA_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable files",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut files",
    "{75048700-EF1F-11D0-9888-006097DEACF9}": "Active Desktop (legacy)",
    "{5E6AB780-7743-11CF-A12B-00AA004AE837}": "IE favorites (legacy)",
}
KNOWN_FOLDERS = {
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "C:\\Program Files", "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "C:\\Program Files (x86)",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "C:\\Windows\\System32", "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "C:\\Windows\\SysWOW64",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "C:\\Windows", "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "Common Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "Programs", "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "User Pinned",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads", "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop", "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "%LOCALAPPDATA%",
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "%APPDATA%", "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "C:\\ProgramData",
}
RX_OFFICE_ITEM = re.compile(r"\[F[0-9A-F]{8}\]\[T([0-9A-F]{16})\](?:\[O[0-9A-F]{8}\])?\*(.+)", re.I)


def _rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def _expand_known(path: str) -> str:
    for guid, real in KNOWN_FOLDERS.items():
        if path.upper().startswith(guid):
            return real + path[len(guid):]
    return path


@register
class UserActivityModule(ArtifactModule):
    id = "user_activity"
    title = "User activity (registry)"
    category = "File & Folder Access"
    description = ("RecentDocs, Open/Save and LastVisited MRU, Run box (Win+R) history, typed paths, Explorer searches, "
                   "UserAssist, Office file MRU, trusted documents, typed URLs, RDP client MRU and shellbags.")
    weight = 2.5
    order = 30
    locations = ["NTUSER\\...\\Explorer\\RecentDocs", "NTUSER\\...\\ComDlg32\\OpenSavePidlMRU",
                 "NTUSER\\...\\ComDlg32\\LastVisitedPidlMRU", "NTUSER\\...\\Explorer\\RunMRU", "NTUSER\\...\\Explorer\\TypedPaths",
                 "NTUSER\\...\\Explorer\\WordWheelQuery", "NTUSER\\...\\Explorer\\UserAssist", "NTUSER\\Software\\Microsoft\\Office\\*\\*\\File MRU",
                 "NTUSER\\...\\TrustRecords", "NTUSER\\...\\Internet Explorer\\TypedURLs", "NTUSER\\...\\Terminal Server Client",
                 "UsrClass.dat\\...\\Shell\\BagMRU", "NTUSER\\Software\\Microsoft\\Windows\\Shell\\BagMRU"]
    artifact_types = [
        ArtifactType("recent_doc", "Recent Documents (RecentDocs)", "File & Folder Access",
                     [C("name", width=280), C("extension"), C("mru_position", "MRU #", "int"), C("key_last_written", kind="datetime"),
                      C("note", width=260)], ts_label="Key last written (MRU #0 only)"),
        ArtifactType("opensave_mru", "Open / Save Dialog MRU", "File & Folder Access",
                     [C("path", kind="path", width=420), C("extension"), C("mru_position", "MRU #", "int"),
                      C("key_last_written", kind="datetime")], ts_label="Key last written"),
        ArtifactType("lastvisited_mru", "Last Visited Folder MRU (by application)", "File & Folder Access",
                     [C("application"), C("folder", kind="path", width=420), C("mru_position", "MRU #", "int"),
                      C("key_last_written", kind="datetime")], ts_label="Key last written"),
        ArtifactType("run_mru", "Run Box History (RunMRU / Win+R)", "Program Execution",
                     [C("command", width=520), C("mru_position", "MRU #", "int"), C("key_last_written", kind="datetime"),
                      C("score", kind="int"), C("indicators", width=300)], ts_label="Key last written (MRU #0 only)"),
        ArtifactType("typed_path", "Explorer Typed Paths", "File & Folder Access",
                     [C("path", kind="path", width=420), C("position", "#", "int"), C("key_last_written", kind="datetime")]),
        ArtifactType("search_term", "Explorer Search Terms (WordWheelQuery)", "File & Folder Access",
                     [C("term", width=300), C("mru_position", "MRU #", "int"), C("key_last_written", kind="datetime")]),
        ArtifactType("userassist", "UserAssist (GUI program execution)", "Program Execution",
                     [C("program", kind="path", width=420), C("run_count", kind="int"), C("focus_count", kind="int"),
                      C("focus_time", "Focus Time"), C("last_run", kind="datetime"), C("type")], ts_label="Last run"),
        ArtifactType("office_mru", "Microsoft Office File MRU", "File & Folder Access",
                     [C("application"), C("path", kind="path", width=420), C("last_opened", kind="datetime"),
                      C("version")], ts_label="Last opened"),
        ArtifactType("trusted_doc", "Office Trusted Documents (Enable Content / Macros)", "File & Folder Access",
                     [C("path", kind="path", width=420), C("application"), C("trusted_time", kind="datetime"),
                      C("macros_enabled", "Macros Enabled")], ts_label="Trusted"),
        ArtifactType("typed_url", "Typed URLs (IE / Edge legacy / Explorer)", "Browser Activity",
                     [C("url", kind="url", width=420), C("position", "#"), C("typed_time", kind="datetime")]),
        ArtifactType("rdp_client_mru", "RDP Client History (mstsc)", "Remote Access",
                     [C("server", width=260), C("username_hint", "Username Hint"), C("mru_position", "MRU #"),
                      C("key_last_written", kind="datetime")]),
        ArtifactType("network_drive_mru", "Mapped Network Drives", "Network",
                     [C("path", kind="path", width=360), C("source"), C("key_last_written", kind="datetime")]),
        ArtifactType("shellbag", "Shellbags (folders browsed)", "File & Folder Access",
                     [C("path", kind="path", width=460), C("type"), C("last_interacted", "Key Last Written", "datetime"),
                      C("folder_modified", kind="datetime"), C("folder_created", kind="datetime"),
                      C("folder_accessed", kind="datetime"), C("hive", width=200)], ts_label="Key last written"),
        ArtifactType("email_account", "E-mail / News Accounts (mail client settings)", "E-mail",
                     [C("email", "E-mail Address", width=220), C("display_name"), C("account_name", width=200),
                      C("incoming_server", width=200), C("smtp_server", "SMTP Server", width=180),
                      C("nntp_server", "NNTP (news) Server", width=180), C("user_name", width=200), C("password_saved"),
                      C("client", width=200), C("key_modified", kind="datetime")], ts_label="Key last written",
                     description="Accounts configured in Outlook Express / Windows Mail / Outlook (registry). Saved "
                                 "passwords are only flagged, never decoded."),
    ]

    def run(self, ctx) -> None:
        reg = ctx.target.registry
        steps = [self._recentdocs, self._opensave, self._lastvisited, self._runmru, self._typedpaths, self._wordwheel,
                 self._userassist, self._office, self._trusted, self._typedurls, self._mstsc, self._netdrives, self._shellbags,
                 self._mail_accounts]
        for i, fn in enumerate(steps):
            try:
                fn(ctx, reg)
            except Exception as e:
                ctx.warn(f"user_activity {fn.__name__}: {e}")
                ctx.coverage(fn.__name__.strip("_"), "registry", "error", 0, str(e)[:200])
            ctx.progress((i + 1) / len(steps))

    # ------------------------------------------------------------------ mail client accounts
    def _mail_accounts(self, ctx, reg) -> None:
        """Internet Account Manager (Outlook Express, Outlook 2002/2003, Windows Mail) and Outlook profile accounts
        (Outlook 2007+, values stored as UTF-16 binary)."""
        def text(v):
            if isinstance(v, (bytes, bytearray)):
                return bytes(v).decode("utf-16-le", "ignore").split("\x00")[0] if len(v) % 2 == 0 else ""
            return "" if v is None else str(v)

        n = 0
        sources = [("HKCU\\Software\\Microsoft\\Internet Account Manager\\Accounts", "Outlook Express / Internet Account Manager"),
                   ("HKCU\\Software\\Microsoft\\Windows Mail\\Accounts", "Windows Mail")]
        for path, client in sources:
            for k in iter_keys(reg, path):
                user = key_user(reg, k)
                for acc in subkeys(k):
                    v = {x.name: x.value for x in values(acc)}
                    email = text(v.get("SMTP Email Address") or v.get("NNTP Email Address") or v.get("POP3 User Name")
                                 or v.get("IMAP User Name") or v.get("HTTPMail User Name"))
                    servers = {s: text(v.get(f"{s} Server")) for s in ("POP3", "IMAP", "HTTPMail", "SMTP", "NNTP")}
                    if not (email or any(servers[s] for s in ("POP3", "IMAP", "HTTPMail", "NNTP"))):
                        continue  # directory (LDAP) services and empty entries
                    self._emit_account(ctx, acc, user, client, path, email=email,
                                       display_name=text(v.get("SMTP Display Name") or v.get("NNTP Display Name")),
                                       account_name=text(v.get("Account Name")),
                                       incoming_server=servers["POP3"] or servers["IMAP"] or servers["HTTPMail"],
                                       smtp_server=servers["SMTP"], nntp_server=servers["NNTP"],
                                       user_name=text(v.get("POP3 User Name") or v.get("IMAP User Name") or
                                                      v.get("NNTP User Name") or v.get("HTTPMail User Name")),
                                       password_saved="Yes" if any(x.endswith(("Password", "Password2")) for x in v) else "")
                    n += 1
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Office"):
            user = key_user(reg, k)
            for ver in subkeys(k):
                try:
                    profiles = ver.subkey("Outlook").subkey("Profiles")
                except Exception:
                    continue
                for prof in subkeys(profiles):
                    try:
                        accounts = prof.subkey("9375CFF0413111d3B88A00104B2A6676")
                    except Exception:
                        continue
                    for acc in subkeys(accounts):
                        v = {x.name: x.value for x in values(acc)}
                        svc = text(v.get("Service Name")).upper()
                        if svc in ("CONTAB", "EMABLT", "MSPST MS", "MSUPST MS"):
                            continue  # address books and data files, not mail accounts
                        name = text(v.get("Account Name"))
                        email = text(v.get("Email") or v.get("SMTP Email Address")) or (name if "@" in name else "")
                        servers = [text(v.get(s)) for s in ("IMAP Server", "POP3 Server", "SMTP Server")]
                        if not email and not any(servers):
                            continue
                        kind = " - Exchange" if svc == "MSEMS" else ""
                        self._emit_account(ctx, acc, user, f"Outlook {ver.name} (profile {prof.name}){kind}",
                                           f"HKCU\\Software\\Microsoft\\Office\\{ver.name}\\Outlook\\Profiles\\{prof.name}",
                                           email=email, display_name=text(v.get("Display Name")),
                                           account_name=text(v.get("Account Name")),
                                           incoming_server=text(v.get("IMAP Server") or v.get("POP3 Server")),
                                           smtp_server=text(v.get("SMTP Server")), nntp_server="",
                                           user_name=text(v.get("IMAP User") or v.get("POP3 User")),
                                           password_saved="Yes" if any("password" in x.lower() for x in v) else "")
                        n += 1
        ctx.coverage("E-mail / news accounts", "NTUSER\\...\\Internet Account Manager, Windows Mail, Outlook profiles",
                     "found" if n else "not_found", n)

    def _emit_account(self, ctx, key, user, client, path, **rec) -> None:
        ts = ts_of(key)
        rec.update(client=client, key_modified=db_ts(ts))
        ctx.emit("email_account", ts, rec, user=user, summary=f"{client}: {rec.get('email') or rec.get('account_name')}",
                 source=f"NTUSER\\{path.split(chr(92), 1)[-1]}\\{key.name}", ts_label="Key last written")

    # ------------------------------------------------------------------ dissect backed MRUs
    def _recentdocs(self, ctx, reg) -> None:
        n = 0
        seen_mru0 = set()
        for r in ctx.plugin("mru.recentdocs"):
            keyp = str(r.get("regf_key_path") or "")
            ext = keyp.rsplit("\\", 1)[-1] if not keyp.lower().endswith("recentdocs") else ""
            idx = int(r.get("index") or 0)
            ts = r.get("regf_mtime")
            kid = (r.get("username"), keyp)
            is_first = idx == 0 and kid not in seen_mru0
            if is_first:
                seen_mru0.add(kid)
            ctx.emit("recent_doc", ts if idx == 0 else None, {
                "name": r.get("value"), "extension": ext or "(all)", "mru_position": idx, "key_last_written": db_ts(ts),
                "note": "Most recently opened item of this key - key time = last open" if idx == 0 else "",
                "hive": str(r.get("regf_hive_path")), "key": keyp,
            }, user=r.get("username"), summary=f"RecentDocs [{ext or 'all'}] #{idx}: {r.get('value')}",
                source=f"{r.get('regf_hive_path')}\\{keyp}", ts_label="Key last written")
            n += 1
        ctx.coverage("RecentDocs", "NTUSER\\...\\Explorer\\RecentDocs", "found" if n else "not_found", n)

    def _opensave(self, ctx, reg) -> None:
        n = 0
        for r in ctx.plugin("mru.opensave"):
            keyp = str(r.get("regf_key_path") or "")
            idx = int(r.get("index") or 0)
            path = str(r.get("value") or "")
            path = re.sub(r"^(My Computer|This PC)\\", "", path)
            ctx.emit("opensave_mru", r.get("regf_mtime") if idx == 0 else None, {
                "path": path, "extension": keyp.rsplit("\\", 1)[-1], "mru_position": idx,
                "key_last_written": db_ts(r.get("regf_mtime")), "key": keyp, "hive": str(r.get("regf_hive_path")),
            }, user=r.get("username"), summary=f"Open/Save dialog #{idx}: {path}",
                source=f"{r.get('regf_hive_path')}\\{keyp}", ts_label="Key last written")
            n += 1
        ctx.coverage("Open/Save dialog MRU", "NTUSER\\...\\ComDlg32\\OpenSavePidlMRU", "found" if n else "not_found", n)

    def _lastvisited(self, ctx, reg) -> None:
        n = 0
        for r in ctx.plugin("mru.lastvisited"):
            idx = int(r.get("index") or 0)
            folder = re.sub(r"^(My Computer|This PC)\\", "", str(r.get("path") or ""))
            ctx.emit("lastvisited_mru", r.get("regf_mtime") if idx == 0 else None, {
                "application": r.get("filename"), "folder": folder, "mru_position": idx,
                "key_last_written": db_ts(r.get("regf_mtime")), "hive": str(r.get("regf_hive_path")),
            }, user=r.get("username"), summary=f"{r.get('filename')} last used folder {folder}",
                source=f"{r.get('regf_hive_path')}\\{r.get('regf_key_path')}", ts_label="Key last written")
            n += 1
        ctx.coverage("Last visited folder MRU", "NTUSER\\...\\ComDlg32\\LastVisitedPidlMRU", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ RunMRU (ClickFix!)
    def _runmru(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"):
            user = key_user(reg, k)
            order = (val(k, "MRUList") or "")
            entries = {v.name: v.value for v in values(k) if v.name not in ("MRUList",)}
            for pos, letter in enumerate(order or sorted(entries)):
                cmd = entries.get(letter)
                if cmd is None:
                    continue
                cmd = str(cmd)
                if cmd.endswith("\\1"):
                    cmd = cmd[:-2]
                sc = score_command(cmd)
                ctx.emit("run_mru", ts_of(k) if pos == 0 else None, {
                    "command": cmd, "mru_position": pos, "value_name": letter, "key_last_written": db_ts(ts_of(k)),
                    "score": sc["score"], "indicators": ", ".join(m["title"] for m in sc["matches"]), "mitre": sc["mitre"],
                }, user=user, summary=f"Run box #{pos}: {cmd[:200]}", ts_label="Key last written",
                    source="NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
                    tags=["suspicious"] if sc["score"] >= 6 else None)
                n += 1
        ctx.coverage("Run box history (RunMRU)", "NTUSER\\...\\Explorer\\RunMRU", "found" if n else "not_found", n)

    def _typedpaths(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"):
            user = key_user(reg, k)
            for v in values(k):
                m = re.match(r"url(\d+)", v.name, re.I)
                pos = int(m.group(1)) if m else 0
                ctx.emit("typed_path", ts_of(k) if pos == 1 else None, {
                    "path": v.value, "position": pos, "key_last_written": db_ts(ts_of(k))},
                    user=user, summary=f"Typed path: {v.value}", source="NTUSER\\...\\Explorer\\TypedPaths",
                    ts_label="Key last written")
                n += 1
        ctx.coverage("Explorer typed paths", "NTUSER\\...\\Explorer\\TypedPaths", "found" if n else "not_found", n)

    def _wordwheel(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"):
            user = key_user(reg, k)
            order = mru_order(val(k, "MRUListEx") or b"")
            vals = {v.name: v.value for v in values(k)}
            for pos, idx in enumerate(order or [int(x) for x in vals if x.isdigit()]):
                data = vals.get(str(idx))
                if not isinstance(data, (bytes, bytearray)):
                    continue
                term = bytes(data).decode("utf-16-le", "replace").rstrip("\x00")
                ctx.emit("search_term", ts_of(k) if pos == 0 else None, {
                    "term": term, "mru_position": pos, "key_last_written": db_ts(ts_of(k))},
                    user=user, summary=f"Explorer search: {term}", source="NTUSER\\...\\Explorer\\WordWheelQuery",
                    ts_label="Key last written")
                n += 1
        ctx.coverage("Explorer search terms", "NTUSER\\...\\Explorer\\WordWheelQuery", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ UserAssist
    def _userassist(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"):
            user = key_user(reg, k)
            for g in subkeys(k):
                kind = UA_GUIDS.get(g.name.upper(), g.name)
                version = val(g, "Version")
                try:
                    count_key = g.subkey("Count")
                except Exception:
                    continue
                for v in values(count_key):
                    data = v.value
                    if not isinstance(data, (bytes, bytearray)):
                        continue
                    data = bytes(data)
                    name = _expand_known(_rot13(v.name))
                    if name.startswith("UEME_"):
                        continue
                    rc = fc = ft = 0
                    last = None
                    if len(data) >= 72 and version in (5, None):
                        rc, fc, ft = struct.unpack_from("<III", data, 4)
                        last = filetime(struct.unpack_from("<Q", data, 60)[0])
                    elif len(data) == 16:
                        rc = max(0, struct.unpack_from("<I", data, 4)[0] - 5)
                        last = filetime(struct.unpack_from("<Q", data, 8)[0])
                    secs = ft // 1000
                    ctx.emit("userassist", last, {
                        "program": name, "run_count": rc, "focus_count": fc,
                        "focus_time": f"{secs // 3600}h {(secs % 3600) // 60}m {secs % 60}s" if ft else "",
                        "focus_ms": ft, "last_run": db_ts(last), "type": kind},
                        user=user, summary=f"UserAssist: {name} (runs {rc})", ts_label="Last run",
                        source=f"NTUSER\\...\\UserAssist\\{g.name}\\Count")
                    n += 1
        ctx.coverage("UserAssist", "NTUSER\\...\\Explorer\\UserAssist", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ Office
    def _office(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Office"):
            user = key_user(reg, k)
            for ver in subkeys(k):
                if not re.match(r"\d+\.\d", ver.name):
                    continue
                for app in subkeys(ver):
                    for mru_parent in [app] + [x for x in subkeys(app) if x.name.lower() == "user mru"]:
                        targets = []
                        if mru_parent is app:
                            for name in ("File MRU", "Place MRU"):
                                try:
                                    targets.append(app.subkey(name))
                                except Exception:
                                    pass
                        else:
                            for acct in subkeys(mru_parent):
                                for name in ("File MRU", "Place MRU"):
                                    try:
                                        targets.append(acct.subkey(name))
                                    except Exception:
                                        pass
                        for t in targets:
                            for v in values(t):
                                m = RX_OFFICE_ITEM.search(str(v.value))
                                if not m:
                                    continue
                                ts = filetime(int(m.group(1), 16))
                                path = m.group(2)
                                ctx.emit("office_mru", ts, {"application": app.name, "path": path, "last_opened": db_ts(ts),
                                                            "version": ver.name, "list": t.name},
                                         user=user, summary=f"Office {app.name} opened {path}", ts_label="Last opened",
                                         source=f"NTUSER\\Software\\Microsoft\\Office\\{ver.name}\\{app.name}\\{t.name}")
                                n += 1
        ctx.coverage("Office file MRU", "NTUSER\\Software\\Microsoft\\Office\\<ver>\\<app>\\File MRU", "found" if n else "not_found", n)

    def _trusted(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Office"):
            user = key_user(reg, k)
            for ver in subkeys(k):
                for app in subkeys(ver):
                    try:
                        tr = app.subkey("Security").subkey("Trusted Documents").subkey("TrustRecords")
                    except Exception:
                        continue
                    for v in values(tr):
                        data = v.value
                        if not isinstance(data, (bytes, bytearray)) or len(data) < 24:
                            continue
                        data = bytes(data)
                        ts = filetime(struct.unpack_from("<Q", data, 0)[0])
                        macros = struct.unpack_from("<I", data, len(data) - 4)[0] == 0x7FFFFFFF
                        path = _expand_known(v.name).replace("%USERPROFILE%", f"C:\\Users\\{user}" if user else "%USERPROFILE%")
                        if "://" not in path:  # local paths are stored with forward slashes; URLs (SharePoint) stay as they are
                            path = path.replace("/", "\\")
                        ctx.emit("trusted_doc", ts, {"path": path, "application": app.name, "trusted_time": db_ts(ts),
                                                     "macros_enabled": "Yes" if macros else "No"},
                                 user=user, summary=f"Trusted document ({app.name}): {path}" + (" [macros enabled]" if macros else ""),
                                 ts_label="Trusted", source=f"NTUSER\\...\\Office\\{ver.name}\\{app.name}\\Security\\Trusted Documents\\TrustRecords",
                                 tags=["macro_enabled"] if macros else None)
                        n += 1
        ctx.coverage("Office trusted documents", "NTUSER\\...\\Trusted Documents\\TrustRecords", "found" if n else "not_found", n)

    def _typedurls(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs"):
            user = key_user(reg, k)
            times = {}
            for tk in iter_keys(reg, "HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLsTime"):
                if key_user(reg, tk) == user:
                    for v in values(tk):
                        if isinstance(v.value, (bytes, bytearray)) and len(v.value) >= 8:
                            times[v.name] = filetime(struct.unpack("<Q", bytes(v.value[:8]))[0])
            for v in values(k):
                ts = times.get(v.name)
                ctx.emit("typed_url", ts, {"url": v.value, "position": v.name, "typed_time": db_ts(ts)}, user=user,
                         summary=f"Typed URL: {v.value}", source="NTUSER\\...\\Internet Explorer\\TypedURLs", ts_label="Typed")
                n += 1
        ctx.coverage("Typed URLs", "NTUSER\\...\\Internet Explorer\\TypedURLs", "found" if n else "not_found", n)

    def _mstsc(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default"):
            user = key_user(reg, k)
            for v in values(k):
                m = re.match(r"MRU(\d+)", v.name, re.I)
                ctx.emit("rdp_client_mru", ts_of(k) if v.name.upper() == "MRU0" else None, {
                    "server": v.value, "mru_position": m.group(1) if m else v.name, "username_hint": "",
                    "key_last_written": db_ts(ts_of(k))}, user=user, summary=f"RDP client connected to {v.value}",
                    source="NTUSER\\Software\\Microsoft\\Terminal Server Client\\Default", ts_label="Key last written")
                n += 1
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"):
            user = key_user(reg, k)
            for s in subkeys(k):
                ctx.emit("rdp_client_mru", ts_of(s), {"server": s.name, "username_hint": val(s, "UsernameHint"),
                                                      "mru_position": "", "key_last_written": db_ts(ts_of(s))},
                         user=user, summary=f"RDP server {s.name} as {val(s, 'UsernameHint')}", ts_label="Key last written",
                         source=f"NTUSER\\Software\\Microsoft\\Terminal Server Client\\Servers\\{s.name}")
                n += 1
        ctx.coverage("RDP client history", "NTUSER\\...\\Terminal Server Client", "found" if n else "not_found", n)

    def _netdrives(self, ctx, reg) -> None:
        n = 0
        for k in iter_keys(reg, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU"):
            user = key_user(reg, k)
            for v in values(k):
                if v.name.lower() == "mrulist":
                    continue
                ctx.emit("network_drive_mru", ts_of(k), {"path": v.value, "source": "Map Network Drive MRU",
                                                         "key_last_written": db_ts(ts_of(k))}, user=user,
                         summary=f"Mapped network drive {v.value}", source="NTUSER\\...\\Map Network Drive MRU")
                n += 1
        for k in iter_keys(reg, "HKCU\\Network"):
            user = key_user(reg, k)
            for d in subkeys(k):
                ctx.emit("network_drive_mru", ts_of(d), {"path": f"{d.name}: -> {val(d, 'RemotePath')}",
                                                         "source": "HKCU\\Network (persistent)", "key_last_written": db_ts(ts_of(d))},
                         user=user, summary=f"Persistent drive {d.name}: {val(d, 'RemotePath')}", source="NTUSER\\Network")
                n += 1
        ctx.coverage("Mapped network drives", "NTUSER\\...\\Map Network Drive MRU, NTUSER\\Network", "found" if n else "not_found", n)

    # ------------------------------------------------------------------ shellbags
    def _shellbags(self, ctx, reg) -> None:
        from dissect.target.plugins.os.windows.regf.shellbags import parse_shell_item_list

        n = 0
        seen = set()
        roots = ["HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                 "HKCU\\Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                 "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"]

        def walk(key, prefix, user, hive, depth):
            nonlocal n
            if depth > 40:
                return
            order = mru_order(val(key, "MRUListEx") or b"")
            for v in values(key):
                if not v.name.isdigit():
                    continue
                path, typ, item = prefix, "", None
                try:
                    for it in parse_shell_item_list(bytes(v.value)):
                        item = it
                        name = str(it.name).rstrip("\\") if it.name else "?"
                        path = f"{path}\\{name}" if path else name
                        typ = it.__class__.__name__
                except Exception:
                    path = f"{prefix}\\<unparsed item>" if prefix else "<unparsed item>"
                try:
                    sub = key.subkey(v.name)
                except Exception:
                    sub = None
                own_ts = ts_of(sub) if sub is not None else None
                pos = order.index(int(v.name)) if int(v.name) in order else None
                last = own_ts or (ts_of(key) if pos == 0 else None)
                clean = re.sub(r"^(My Computer|This PC)\\", "", path)
                dedup = (user, hive, clean)
                if dedup not in seen:
                    seen.add(dedup)

                    def _t(attr):
                        try:
                            return db_ts(getattr(item, attr)) if item is not None else None
                        except Exception:
                            return None

                    ctx.emit("shellbag", last, {
                        "path": clean, "type": typ, "last_interacted": db_ts(last), "mru_position": pos,
                        "folder_modified": _t("modification_time"), "folder_created": _t("creation_time"),
                        "folder_accessed": _t("access_time"), "hive": hive, "key": getattr(sub, "path", "") or "",
                    }, user=user, summary=f"Shellbag: {clean}", ts_label="Key last written", source=f"{hive} BagMRU")
                    n += 1
                if sub is not None:
                    walk(sub, path, user, hive, depth + 1)

        for root in roots:
            for k in iter_keys(reg, root):
                user = key_user(reg, k)
                hive = "UsrClass.dat" if "classes" in root.lower() else "NTUSER.DAT"
                try:
                    walk(k, "", user, hive, 0)
                except Exception as e:
                    ctx.warn(f"shellbags {user}: {e}")
        ctx.coverage("Shellbags", "UsrClass.dat / NTUSER.DAT BagMRU", "found" if n else "not_found", n)
