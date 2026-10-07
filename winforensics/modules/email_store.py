"""E-mail: Outlook PST/OST stores (libpff), standalone .eml and .msg files - messages and hashed attachments."""

from __future__ import annotations

import email
import email.policy
import hashlib
import io
import os
import shutil
import tempfile
from email.utils import parsedate_to_datetime

from ..core.timeutil import db_ts
from .base import ArtifactModule, ArtifactType, C, register

PR_DISPLAY_TO, PR_DISPLAY_CC, PR_SENDER_EMAIL, PR_SENT_REPR_EMAIL = 0x0E04, 0x0E03, 0x0C1F, 0x0065
MAX_ATTACH = 200 * 1024 * 1024


def _entry(item, entry_type: int):
    try:
        for rs in item.record_sets:
            for e in rs.entries:
                if e.entry_type == entry_type:
                    try:
                        return e.data_as_string
                    except Exception:
                        return None
    except Exception:
        return None
    return None


def _recipients(m) -> dict[int, list[str]]:
    """Recipient table of a message: {1: To, 2: Cc, 3: Bcc} -> ["display <address>"].  The display name and the address
    can differ ("alison@m57.biz <tuckgorge@gmail.com>"): the address is where the message went.  Bcc recipients exist
    only here."""
    out: dict[int, list[str]] = {1: [], 2: [], 3: []}
    try:
        rec = m.recipients
        sets = rec.record_sets if rec is not None else []
    except Exception:
        return out
    for rs in sets:
        vals = {}
        for e in rs.entries:
            try:
                if e.entry_type in (0x3001, 0x3003, 0x39FE, 0x5FF6):
                    vals[e.entry_type] = e.data_as_string or ""
                elif e.entry_type == 0x0C15:
                    vals[e.entry_type] = e.data_as_integer
            except Exception:
                continue
        addr = vals.get(0x39FE) or vals.get(0x3003) or ""
        if addr.upper().startswith("/O="):  # Exchange legacy DN: only the SMTP property is an address
            addr = vals.get(0x39FE) or ""
        name = vals.get(0x3001) or vals.get(0x5FF6) or ""
        text = f"{name} <{addr}>" if name and addr and name.strip("'\" ").lower() != addr.lower() else (addr or name)
        if text:
            out.setdefault(vals.get(0x0C15) or 1, []).append(text)
    return out


def _hdr(headers: str, name: str) -> str:
    if not headers:
        return ""
    msg = email.message_from_string(headers)
    return str(msg.get(name, "") or "")


@register
class EmailModule(ArtifactModule):
    id = "email"
    title = "E-mail stores"
    category = "Email"
    description = "Outlook PST/OST mailboxes, .eml and .msg files: message metadata and every attachment (name, size, MD5/SHA-256)."
    weight = 3.0
    order = 45
    requires = ["filesystem"]
    locations = ["Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.ost", "Users\\*\\Documents\\Outlook Files\\*.pst", "*.pst / *.ost anywhere",
                 "*.eml / *.msg files"]
    artifact_types = [
        ArtifactType("email_message", "E-mail Messages", "Email",
                     [C("time", kind="datetime"), C("folder", width=160), C("sender", width=220), C("to", width=240),
                      C("cc", "Cc", width=180), C("bcc", "Bcc", width=180), C("reply_to", "Reply-To", width=180),
                      C("subject", width=320), C("attachments", kind="int"), C("attachment_names", width=300),
                      C("store", width=260)], ts_label="Sent / received"),
        ArtifactType("email_attachment", "E-mail Attachments", "Email",
                     [C("time", kind="datetime"), C("filename", width=260), C("size", kind="size"), C("sha256", "SHA256", "hash", 300),
                      C("md5", "MD5", "hash", 240), C("local_copies", "Identical file on this system", "path", 320),
                      C("sender", width=200), C("to", width=220), C("subject", width=260),
                      C("folder"), C("store", width=240)], ts_label="Message time"),
    ]

    def run(self, ctx) -> None:
        stores = ctx.fs_files("ext IN ('pst','ost')", include_deleted=False)
        msgs = ctx.fs_files("ext IN ('eml','msg')", include_deleted=True, limit=20000)
        total = max(1, len(stores) + 1)
        for i, row in enumerate(stores):
            try:
                self._pff(ctx, row, i, total)
            except Exception as e:
                ctx.coverage("Outlook store", ctx.display_path(row["volume"], row["path"]), "error", 0, str(e)[:200])
            ctx.progress((i + 1) / total)
        n = 0
        for row in msgs:
            try:
                n += self._single(ctx, row)
            except Exception:
                continue
        ctx.coverage("Outlook PST/OST", "*.pst / *.ost", "found" if stores else "absent", len(stores),
                     f"{ctx.counts.get('email_message', 0):,} messages")
        ctx.coverage("Standalone e-mail files", "*.eml / *.msg", "found" if n else ("not_found" if msgs else "absent"), n)

    # ------------------------------------------------------------------ PST / OST
    def _pff(self, ctx, row, idx, total) -> None:
        import pypff

        path = ctx.display_path(row["volume"], row["path"])
        user = ctx.user_for_path(path)
        tmpdir = None
        pf = pypff.file()
        try:
            fh = ctx.open_entry_path(row).open("rb")
            pf.open_file_object(fh)
        except Exception:
            if (row.get("size") or 0) > 8 * 1024 ** 3:
                raise
            tmpdir = tempfile.mkdtemp(dir=ctx.case.sub("temp"))
            local = os.path.join(tmpdir, row["name"])
            with open(local, "wb") as out, ctx.open_entry_path(row).open("rb") as src:
                shutil.copyfileobj(src, out, 8 * 1024 * 1024)
            pf.open(local)
        count = 0

        def walk(folder, fpath):
            nonlocal count
            try:
                name = folder.name or ""
            except Exception:
                name = ""
            here = f"{fpath}/{name}" if name else fpath
            try:
                for i in range(folder.number_of_sub_messages):
                    try:
                        self._message(ctx, folder.get_sub_message(i), here, path, user)
                    except Exception:
                        continue
                    count += 1
                    if count % 500 == 0:
                        ctx.progress((idx + 0.5) / total, f"{os.path.basename(path)}: {count:,} messages")
                for i in range(folder.number_of_sub_folders):
                    walk(folder.get_sub_folder(i), here)
            except Exception:
                return

        walk(pf.root_folder, "")
        pf.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        ctx.coverage("Outlook store", path, "found" if count else "not_found", count)

    def _message(self, ctx, m, folder, store, user) -> None:
        headers = m.transport_headers or ""
        sender = m.sender_name or ""
        addr = _hdr(headers, "From") or _entry(m, PR_SENDER_EMAIL) or _entry(m, PR_SENT_REPR_EMAIL) or ""
        if addr.upper().startswith("/O="):
            # Exchange legacy DN (sent items have no transport headers): prefer the SMTP address properties
            addr = _entry(m, 0x5D01) or _entry(m, 0x5D02) or ""
            if not addr:
                sender = f"{sender} (Exchange mailbox)" if sender else "(Exchange mailbox)"
        if addr and addr not in sender:
            sender = f"{sender} <{addr}>" if sender else addr
        rcpt = _recipients(m)
        to = ", ".join(rcpt[1]) or _hdr(headers, "To") or _entry(m, PR_DISPLAY_TO) or ""
        cc = ", ".join(rcpt[2]) or _hdr(headers, "Cc") or _entry(m, PR_DISPLAY_CC) or ""
        bcc = ", ".join(rcpt[3])
        ts = m.delivery_time or m.client_submit_time or m.creation_time
        atts = []
        for i in range(m.number_of_attachments):
            try:
                a = m.get_attachment(i)
                fname = a.long_filename or _entry(a, 0x3704) or f"attachment_{i}"
                size = a.size or 0
                md5 = sha = ""
                if 0 < size <= MAX_ATTACH:
                    a.seek_offset(0)
                    data = a.read_buffer(size)
                    md5, sha = hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()
                atts.append({"filename": fname, "size": size, "md5": md5, "sha256": sha,
                             "local_copies": self._local_copies(ctx, fname, size, sha)})
            except Exception:
                continue
        body = ""
        try:
            body = (m.plain_text_body or b"")[:2000].decode("utf-8", "replace") if isinstance(m.plain_text_body, bytes) else str(m.plain_text_body or "")[:2000]
        except Exception:
            pass
        rec = {"time": db_ts(ts), "folder": folder, "sender": sender, "to": to, "cc": cc, "bcc": bcc, "subject": m.subject or "",
               "reply_to": _hdr(headers, "Reply-To"),
               "attachments": len(atts), "attachment_names": ", ".join(a["filename"] for a in atts), "store": store,
               "attachment_list": atts, "message_id": _hdr(headers, "Message-ID"), "body_preview": body[:500]}
        ctx.emit("email_message", ts, rec, user=user, summary=f"[{folder}] {m.subject or ''} from {sender} to {to}"[:300],
                 source=store, ts_label="Sent / received")
        for a in atts:
            ctx.emit("email_attachment", ts, {"time": db_ts(ts), **a, "sender": sender, "to": to, "subject": m.subject or "",
                                              "folder": folder, "store": store},
                     user=user, summary=f"Attachment {a['filename']} ({a['size']} bytes) in '{m.subject or ''}'", source=store,
                     ts_label="Message time")

    @staticmethod
    def _local_copies(ctx, fname, size, sha) -> str:
        """Files on the system that are byte-identical to an attachment (same name and size, then SHA-256)."""
        if not (sha and fname and size):
            return ""
        out = []
        for r in ctx.fs_files("lower(name)=? AND size=?", (fname.lower(), size), include_deleted=True, limit=10):
            try:
                if hashlib.sha256(ctx.read_entry(r, MAX_ATTACH)).hexdigest() == sha:
                    out.append(ctx.display_path(r["volume"], r["path"]) + (" (deleted)" if r.get("deleted") else ""))
            except Exception:
                continue
        return " | ".join(out)

    # ------------------------------------------------------------------ eml / msg
    def _single(self, ctx, row) -> int:
        path = ctx.display_path(row["volume"], row["path"])
        data = ctx.read_entry(row, 100 * 1024 * 1024)
        user = ctx.user_for_path(path)
        atts = []
        if row["ext"] == "eml":
            msg = email.message_from_bytes(data, policy=email.policy.default)
            subject, sender, to = str(msg.get("Subject", "")), str(msg.get("From", "")), str(msg.get("To", ""))
            try:
                ts = parsedate_to_datetime(msg.get("Date")) if msg.get("Date") else None
            except Exception:
                ts = None
            for part in msg.iter_attachments():
                payload = part.get_payload(decode=True) or b""
                atts.append({"filename": part.get_filename() or "attachment", "size": len(payload),
                             "md5": hashlib.md5(payload).hexdigest(), "sha256": hashlib.sha256(payload).hexdigest()})
        else:
            import olefile

            ole = olefile.OleFileIO(io.BytesIO(data))

            def s(stream):
                for suffix, enc in (("001F", "utf-16-le"), ("001E", "latin-1")):
                    name = f"__substg1.0_{stream}{suffix}"
                    if ole.exists(name):
                        return ole.openstream(name).read().decode(enc, "replace").rstrip("\x00")
                return ""

            subject, sender, to = s("0037"), s("0C1F") or s("0042"), s("0E04")
            ts = None
            for entry in ole.listdir():
                if entry[0].startswith("__attach_version1.0_") and len(entry) == 2 and entry[1].startswith("__substg1.0_37010102"):
                    payload = ole.openstream(entry).read()
                    base = entry[0]
                    fname = ""
                    for suf in ("3707001F", "3704001F"):
                        if ole.exists(f"{base}/__substg1.0_{suf}"):
                            fname = ole.openstream(f"{base}/__substg1.0_{suf}").read().decode("utf-16-le", "replace").rstrip("\x00")
                            break
                    atts.append({"filename": fname or "attachment", "size": len(payload), "md5": hashlib.md5(payload).hexdigest(),
                                 "sha256": hashlib.sha256(payload).hexdigest()})
        ts = ts or row.get("si_created")
        rec = {"time": db_ts(ts) if not isinstance(ts, str) else ts, "folder": "(file)", "sender": sender, "to": to, "subject": subject,
               "attachments": len(atts), "attachment_names": ", ".join(a["filename"] for a in atts), "store": path,
               "attachment_list": atts}
        ctx.emit("email_message", ts, rec, user=user, summary=f"{row['ext'].upper()} {subject} from {sender}", source=path,
                 ts_label="Sent / received")
        for a in atts:
            ctx.emit("email_attachment", ts, {"time": rec["time"], **a, "sender": sender, "to": to, "subject": subject,
                                              "folder": "(file)", "store": path},
                     user=user, summary=f"Attachment {a['filename']} in {path}", source=path, ts_label="Message time")
        return 1
