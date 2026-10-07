"""Strings of interest in memory-backed files: pagefile.sys, swapfile.sys, hiberfil.sys, crash dumps.

Paged-out memory routinely contains URLs of web sessions (webmail compose / attachment
URLs, cloud uploads), e-mail addresses and paths of documents that were open, long
after browser history was cleared.  This module streams each file and extracts:
URLs (ASCII + UTF-16LE), e-mail addresses and Windows paths of documents/executables,
keeping what is relevant (classified destinations, case keywords, target names).
"""

from __future__ import annotations

import re

from ..knowledge import category_title, classify_url, document_extensions, executable_extensions
from ..modules.base import ArtifactModule, ArtifactType, C, register

CHUNK = 32 * 1024 * 1024
RX_URL_A = re.compile(rb"(?:https?|ftp)://[\x21-\x7e]{4,600}")
RX_URL_W = re.compile(rb"(?:h\x00t\x00t\x00p\x00(?:s\x00)?|f\x00t\x00p\x00):\x00/\x00/\x00(?:[\x21-\x7e]\x00){4,600}")
RX_MAIL_A = re.compile(rb"[a-zA-Z0-9._%+-]{2,64}@[a-zA-Z0-9.-]{2,190}\.[a-zA-Z]{2,12}")
RX_PATH_W = re.compile(rb"[A-Za-z]\x00:\x00\\\x00(?:[\x20-\x7e]\x00){3,400}?\.\x00(?:[A-Za-z0-9]\x00){2,5}")
RX_PATH_A = re.compile(rb"[A-Za-z]:\\[\x20-\x7e]{3,400}?\.[A-Za-z0-9]{2,5}\b")
BENIGN_HOSTS = ("microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com", "w3.org", "digicert.com",
                "verisign.com", "msn.com", "bing.com", "live.net", "office.net", "office.com", "akamaized.net", "gstatic.com",
                "googleapis.com", "xmlsoap.org", "openxmlformats.org", "symcd.com", "symcb.com", "globalsign.com", "sectigo.com",
                "letsencrypt.org", "lencr.org", "adobe.com", "mozilla.org", "mozilla.net", "apple.com", "schemas.microsoft.com")
MEMORY_FILES = ("pagefile.sys", "swapfile.sys", "hiberfil.sys", "memory.dmp")


@register
class MemoryFilesModule(ArtifactModule):
    id = "memory_files"
    title = "Pagefile / hiberfil / swapfile strings"
    category = "Memory Artifacts"
    description = ("Streams pagefile.sys, swapfile.sys, hiberfil.sys and crash dumps and extracts URLs, e-mail addresses and "
                   "document paths, keeping webmail / cloud / file-transfer / remote-access destinations, case keywords and "
                   "target file names.")
    weight = 3.0
    order = 75
    windows_only = False
    requires = ["filesystem"]
    locations = ["C:\\pagefile.sys", "C:\\swapfile.sys", "C:\\hiberfil.sys", "C:\\Windows\\MEMORY.DMP", "C:\\Windows\\Minidump\\*.dmp"]
    artifact_types = [
        ArtifactType("memory_string", "Memory File Strings (pagefile / hiberfil)", "Memory Artifacts",
                     [C("kind"), C("value", width=520), C("category"), C("service"), C("count", kind="int"),
                      C("first_offset", "First Offset", "int"), C("file"), C("encoding"), C("reason", width=220)]),
    ]

    def estimate(self, ctx) -> float:
        rows = ctx.db.query("SELECT SUM(size) s FROM fs_entries WHERE evidence_id=? AND lower(name) IN ('pagefile.sys','swapfile.sys',"
                            "'hiberfil.sys','memory.dmp') AND deleted=0", (ctx.evidence_id,))
        return 0.5 + ((rows[0]["s"] or 0) / (150 * 1024 * 1024) if rows else 0)

    def run(self, ctx) -> None:
        rows = ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND deleted=0 AND (lower(name) IN "
                            "('pagefile.sys','swapfile.sys','hiberfil.sys','memory.dmp') OR (ext='dmp' AND lower(path) LIKE "
                            "'%\\minidump\\%'))", (ctx.evidence_id,))
        if not rows:
            ctx.coverage("Memory files", "pagefile.sys / swapfile.sys / hiberfil.sys / crash dumps", "absent", 0)
            return
        kw = [k["term"].lower() for k in ctx.inputs.get("keywords") or [] if not k.get("regex")]
        targets = [(t.get("name") or "").lower() for t in ctx.inputs.get("targets") or [] if t.get("name")]
        domains = [d.lower() for d in ctx.inputs.get("domains") or []] + \
                  [d.lower() for d in (ctx.inputs.get("iocs") or {}).get("domains", [])]
        total = sum(r["size"] or 0 for r in rows) or 1
        done = 0
        for row in rows:
            path = ctx.display_path(row["volume"], row["path"])
            found: dict[tuple, dict] = {}
            note = ""
            try:
                fh = ctx.open_entry_path(row).open("rb")
            except Exception as e:
                ctx.coverage("Memory file", path, "error", 0, str(e)[:200])
                continue
            head = fh.read(8)
            fh.seek(0)
            if row["name"].lower() == "hiberfil.sys":
                sig = head[:4].lower()
                if sig in (b"hibr", b"wake", b"rstr", b"hord"):
                    note = f"hibernation header '{head[:4].decode('latin-1')}' - Win8+ files are Xpress compressed; raw strings only"
                elif head.strip(b"\x00") == b"":
                    note = "header zeroed (resumed / cleared hibernation file) - remnants searched"
            pos = 0
            tail = b""
            while True:
                ctx.check_cancel()
                data = fh.read(CHUNK)
                if not data:
                    break
                buf = tail + data
                base = pos - len(tail)
                self._extract(buf, base, found, kw, targets, domains)
                tail = buf[-1300:]
                pos += len(data)
                done += len(data)
                ctx.progress(min(0.99, done / total), f"{row['name']}: {pos / 1e9:.2f} GB, {len(found):,} relevant strings")
            n = 0
            for (kind, value), d in sorted(found.items(), key=lambda kv: kv[1]["offset"]):
                ctx.emit("memory_string", None, {"kind": kind, "value": value, "category": d.get("category", ""),
                                                 "service": d.get("service", ""), "count": d["count"], "first_offset": d["offset"],
                                                 "file": row["name"], "encoding": d["enc"], "reason": d["reason"]},
                         summary=f"{row['name']}: {kind} {value}"[:300], source=f"{path} @ {d['offset']:#x}",
                         tags=["memory"] + (["exfil_destination"] if d.get("category") in ("Webmail", "Mail attachment", "Cloud storage",
                                                                                         "File transfer service", "Paste site") else []))
                n += 1
            ctx.coverage("Memory file strings", path, "found" if n else "not_found", n, note)

    def _add(self, found, kind, value, off, enc, reason, category="", service=""):
        key = (kind, value)
        d = found.get(key)
        if d is None:
            if len(found) > 50000:
                return
            found[key] = {"count": 1, "offset": off, "enc": enc, "reason": reason, "category": category, "service": service}
        else:
            d["count"] += 1

    def _extract(self, buf, base, found, kw, targets, domains):
        for rx, enc in ((RX_URL_A, "ascii"), (RX_URL_W, "utf16le")):
            for m in rx.finditer(buf):
                raw = m.group(0)
                url = raw.decode("utf-16-le", "replace") if enc == "utf16le" else raw.decode("latin-1")
                url = re.split(r"[\s\"'<>\\^`{|}]", url)[0].rstrip(".,);]")
                if len(url) < 12:
                    continue
                low = url.lower()
                host = re.sub(r"^[a-z]+://", "", low).split("/")[0].split(":")[0]
                c = classify_url(url)
                reason = ""
                if c and c[0] not in ("anti_forensics",):
                    reason = f"{category_title(c[0])} destination"
                elif any(d and d in host for d in domains):
                    reason = "case domain"
                elif any(k in low for k in kw):
                    reason = "case keyword"
                if not reason or host.endswith(BENIGN_HOSTS) and not c:
                    continue
                self._add(found, "URL", url[:600], base + m.start(), enc, reason,
                          category_title(c[0]) if c else "", c[1] if c else "")
        for m in RX_MAIL_A.finditer(buf):
            v = m.group(0).decode("latin-1").lower()
            if v.endswith((".png", ".jpg", ".gif", ".dll", ".exe")) or "@microsoft.com" in v or "@w3.org" in v:
                continue
            dom = v.split("@", 1)[1]
            c = classify_url(dom)
            reason = "case keyword" if any(k in v for k in kw) else ("webmail provider address" if dom in (
                "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com", "live.com",
                "aol.com", "gmx.com", "yandex.com", "zoho.com", "mail.com", "tutanota.com", "rediffmail.com") else "")
            if reason:
                self._add(found, "E-mail address", v, base + m.start(), "ascii", reason, category_title(c[0]) if c else "")
        exts = document_extensions() | executable_extensions()
        for rx, enc in ((RX_PATH_W, "utf16le"), (RX_PATH_A, "ascii")):
            for m in rx.finditer(buf):
                raw = m.group(0)
                p = raw.decode("utf-16-le", "replace") if enc == "utf16le" else raw.decode("latin-1")
                ext = p.rsplit(".", 1)[-1].lower()
                if ext not in exts:
                    continue
                low = p.lower()
                name = low.rsplit("\\", 1)[-1]
                reason = ""
                if name in targets or any(t and t in low for t in targets):
                    reason = "target file name"
                elif any(k in low for k in kw):
                    reason = "case keyword"
                elif not low.startswith("c:") and ext in document_extensions():
                    reason = "document on non-system drive"
                if reason:
                    self._add(found, "File path", p[:400], base + m.start(), enc, reason)
