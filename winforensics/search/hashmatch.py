"""Target file search: find the files of interest by hash, name, size, content and document lineage.

Searched locations
    * every allocated and deleted file entry (NTFS records / FAT directory entries)
    * Recycle Bin $R content, carved files, e-mail attachments
    * members of ZIP archives (staging archives)
    * Volume Shadow Copies (files that were deleted or changed since the snapshot)
Match types
    * hash (MD5 / SHA1 / SHA256) - identical content, whatever the name
    * name + size, name only (content differs - modified copy or different file)
    * near duplicate - extracted text is >= 80 % similar to the reference document
    * document lineage - same internal title / author / creation time as the reference
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from difflib import SequenceMatcher

from ..core.timeutil import db_ts
from ..modules.base import ArtifactModule, ArtifactType, C, register

MAX_HASH = 512 * 1024 * 1024


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def _stem(name: str) -> str:
    stem = os.path.splitext(name or "")[0].lower()
    stem = re.sub(r"(\s*-\s*copy(\s*\(\d+\))?|\s*\(\d+\)|^copy of\s+|^~\$|_copy\d*|\s+copy\s*\d*)", "", stem)
    return stem.strip()


@register
class TargetSearchModule(ArtifactModule):
    id = "target_search"
    title = "Target file search (hash / name / content)"
    category = "Search"
    description = ("Looks for every file of interest supplied by the examiner (DLP export, hash list, reference copies) in "
                   "allocated and deleted files, the Recycle Bin, carved files, e-mail attachments, ZIP archives and Volume "
                   "Shadow Copies, by hash, name, size, text similarity and document metadata.")
    weight = 4.0
    order = 80
    windows_only = False
    requires = ["filesystem"]
    locations = ["All file entries incl. deleted", "Recycle Bin", "Carved files", "E-mail attachments", "ZIP archive members",
                 "Volume Shadow Copies"]
    artifact_types = [
        ArtifactType("target_match", "Target File Matches", "Search",
                     [C("target", width=220), C("match", "Match Type", width=180), C("location", kind="path", width=420),
                      C("area", width=180), C("name_on_disk", "Name on Disk", width=200), C("size", kind="size"),
                      C("created", kind="datetime"), C("modified", kind="datetime"), C("sha256", "SHA256", "hash", 300),
                      C("confidence")], ts_label="Created on this system"),
    ]

    def run(self, ctx) -> None:
        targets = [t for t in (ctx.inputs.get("targets") or [])]
        if not targets:
            ctx.coverage("Target file search", "all locations", "skipped", 0, "no target files / hashes supplied")
            return
        self.ctx = ctx
        self.targets = targets
        self.by_hash = {}
        for i, t in enumerate(targets):
            for h in ("md5", "sha1", "sha256"):
                if t.get(h):
                    self.by_hash[t[h]] = i
        self.names = {(t.get("name") or "").lower(): i for i, t in enumerate(targets) if t.get("name")}
        self.stems = {_stem(t.get("name")): i for i, t in enumerate(targets) if t.get("name") and len(_stem(t.get("name"))) >= 4}
        self.sizes = {}
        for i, t in enumerate(targets):
            if t.get("size"):
                self.sizes.setdefault(int(t["size"]), []).append(i)
        self.found: dict[int, list] = {}
        self.emitted = set()
        steps = [self._fs_entries, self._artifact_hashes, self._archives, self._content_similarity, self._vss]
        for k, fn in enumerate(steps):
            try:
                fn()
            except Exception as e:
                ctx.warn(f"target search {fn.__name__}: {e}")
            ctx.progress((k + 1) / len(steps))
        for i, t in enumerate(targets):
            hits = self.found.get(i, [])
            ctx.coverage(f"Target: {t.get('name') or t.get('sha256') or t.get('md5')}", "all locations",
                         "found" if hits else "not_found", len(hits), "; ".join(sorted({h for h in hits}))[:300])

    # ------------------------------------------------------------------ emit
    def _emit(self, i, match, location, area, name, size, created, modified, sha256, confidence, extra=None, ts=None):
        key = (i, match.split(" (")[0], location)
        if key in self.emitted:
            return
        self.emitted.add(key)
        t = self.targets[i]
        self.found.setdefault(i, []).append(f"{match} @ {area}")
        rec = {"target": t.get("name") or t.get("sha256") or t.get("md5"), "match": match, "location": location, "area": area,
               "name_on_disk": name, "size": size, "created": created, "modified": modified, "sha256": sha256,
               "confidence": confidence, "target_sha256": t.get("sha256"), "target_md5": t.get("md5"),
               "target_sources": t.get("sources"), "target_index": i, **(extra or {})}
        self.ctx.emit("target_match", ts or created, rec, user=self.ctx.user_for_path(location),
                      summary=f"{match}: {rec['target']} -> {location}", source=location, ts_label="Created",
                      tags=["target_match", f"confidence:{confidence}"])

    def _check(self, md5, sha1, sha256, name, size, location, area, created, modified, extra=None, ts=None):
        hit = None
        for h in (sha256, sha1, md5):
            if h and h in self.by_hash:
                hit = self.by_hash[h]
                break
        lname = (name or "").lower()
        if hit is not None:
            t = self.targets[hit]
            renamed = lname and t.get("name") and lname != t["name"].lower()
            self._emit(hit, "Hash match" + (" (renamed copy)" if renamed else ""), location, area, name, size, created, modified,
                       sha256, "high", extra, ts)
            return True
        i = self.names.get(lname)
        if i is not None:
            t = self.targets[i]
            if t.get("size") and size == t["size"] and not (t.get("sha256") or t.get("md5")):
                self._emit(i, "Name + size match", location, area, name, size, created, modified, sha256, "medium", extra, ts)
            elif t.get("sha256") or t.get("md5"):
                if sha256 or md5:
                    self._emit(i, "Name match - content differs (modified / different version)", location, area, name, size,
                               created, modified, sha256, "low", extra, ts)
                else:
                    self._emit(i, "Name match (content not recoverable)", location, area, name, size, created, modified, sha256,
                               "low", extra, ts)
            else:
                self._emit(i, "Name match", location, area, name, size, created, modified, sha256, "medium", extra, ts)
            return True
        st = _stem(name)
        if st and st in self.stems and lname not in self.names:
            i = self.stems[st]
            self._emit(i, "Similar name (copy / renamed variant)", location, area, name, size, created, modified, sha256, "low",
                       extra, ts)
            return True
        return False

    # ------------------------------------------------------------------ file entries
    def _fs_entries(self):
        ctx = self.ctx
        scope = ctx.options.get("hash_scope", "candidates")
        size_list = list(self.sizes)
        clauses, args = [], []
        if size_list:
            clauses.append(f"size IN ({','.join('?' * len(size_list))})")
            args += size_list
        if self.names:
            clauses.append(f"lower(name) IN ({','.join('?' * len(self.names))})")
            args += list(self.names)
        for st in list(self.stems)[:200]:
            clauses.append("lower(name) LIKE ?")
            args.append(f"%{st}%")
        if scope == "all":
            where = f"size <= {MAX_HASH}"
        else:
            where = " OR ".join(clauses) or "0"
            where = f"({where}) OR (md5 IS NOT NULL)"
        rows = ctx.db.query(f"SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND ({where})", (ctx.evidence_id, *args))
        total = max(1, len(rows))
        updates = []
        for k, row in enumerate(rows):
            if k % 200 == 0:
                ctx.progress(0.3 * k / total, f"Hashing candidate files {k:,}/{total:,}")
            location = ctx.display_path(row["volume"], row["path"] or "")
            area = ("Deleted file" if row["deleted"] else "Allocated file")
            if "\\$recycle.bin\\" in location.lower():
                area = "Recycle Bin" + (" (emptied)" if row["deleted"] else "")
            md5, sha1, sha256 = row.get("md5"), row.get("sha1"), row.get("sha256")
            if not sha256 and (row.get("size") or 0) <= MAX_HASH and (row.get("size") or 0) > 0:
                try:
                    data = ctx.read_entry(row)
                    if row["deleted"] and not data.strip(b"\x00"):
                        data = b""
                    if data:
                        md5, sha1, sha256 = hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest()
                        updates.append((md5, sha1, sha256, "recovered" if row["deleted"] else "", row["id"]))
                except Exception:
                    pass
            self._check(md5, sha1, sha256, row["name"], row.get("size"), location, area, row.get("si_created"),
                        row.get("si_modified"), {"fs_id": row["id"], "deleted": bool(row["deleted"]),
                                                 "fn_created": row.get("fn_created"), "flags": row.get("flags")})
            if len(updates) >= 500:
                ctx.db.set_fs_hashes(updates)
                updates = []
        if updates:
            ctx.db.set_fs_hashes(updates)

    # ------------------------------------------------------------------ hashes already computed by other modules
    def _artifact_hashes(self):
        ctx = self.ctx
        for a in ctx.db.artifacts(ctx.evidence_id, "recycle_bin"):
            d = a["data"]
            name = re.split(r"[\\/]", d.get("original_path") or "")[-1]
            self._check(None, None, d.get("sha256"), name, d.get("size"), d.get("i_file"), "Recycle Bin", d.get("deleted_time"),
                        None, {"original_path": d.get("original_path")}, ts=d.get("deleted_time"))
        for a in ctx.db.artifacts(ctx.evidence_id, "carved_file"):
            d = a["data"]
            self._check(d.get("md5"), None, d.get("sha256"), "", d.get("size"), f"{d.get('volume')} offset {d.get('offset'):#x}",
                        f"Carved from {d.get('area', 'unallocated')}", None, None, {"saved_as": d.get("saved_as")})
        for a in ctx.db.artifacts(ctx.evidence_id, "email_attachment"):
            d = a["data"]
            self._check(d.get("md5"), None, d.get("sha256"), d.get("filename"), d.get("size"),
                        f"{d.get('store')} :: {d.get('folder')} :: {d.get('subject')}", "E-mail attachment", d.get("time"), None,
                        {"sender": d.get("sender"), "to": d.get("to")}, ts=d.get("time"))
        for a in ctx.db.artifacts(ctx.evidence_id, "web_download"):
            d = a["data"]
            name = re.split(r"[\\/]", d.get("target_path") or "")[-1]
            if name.lower() in self.names or _stem(name) in self.stems:
                self._check(None, None, None, name, d.get("size"), d.get("target_path"), "Browser download record",
                            d.get("start_time"), None, {"url": d.get("url"), "browser": d.get("browser")}, ts=d.get("start_time"))

    # ------------------------------------------------------------------ archives
    def _archives(self):
        ctx = self.ctx
        rows = ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND ext IN ('zip') AND size < ?",
                            (ctx.evidence_id, 2 * 1024 ** 3))
        for row in rows:
            location = ctx.display_path(row["volume"], row["path"] or "")
            try:
                data = ctx.read_entry(row)
                z = zipfile.ZipFile(io.BytesIO(data))
            except Exception:
                continue
            for zi in z.infolist()[:20000]:
                if zi.is_dir():
                    continue
                base = zi.filename.rsplit("/", 1)[-1]
                interesting = zi.file_size in self.sizes or base.lower() in self.names or _stem(base) in self.stems
                if not interesting:
                    continue
                md5 = sha256 = None
                if not zi.flag_bits & 0x1:
                    try:
                        content = z.read(zi)
                        md5, sha256 = hashlib.md5(content).hexdigest(), hashlib.sha256(content).hexdigest()
                    except Exception:
                        pass
                area = "Inside ZIP archive" + (" (encrypted)" if zi.flag_bits & 0x1 else "") + (" (deleted archive)" if row["deleted"] else "")
                self._check(md5, None, sha256, base, zi.file_size, f"{location} :: {zi.filename}", area,
                            row.get("si_created"), db_ts(_zipdt(zi.date_time)), {"archive": location})

    # ------------------------------------------------------------------ near duplicates / lineage
    def _content_similarity(self):
        ctx = self.ctx
        refs = [(i, t) for i, t in enumerate(self.targets) if t.get("text_sample") or t.get("meta")]
        if not refs:
            return
        already = {(k[0], k[2]) for k in self.emitted}
        docs = ctx.db.artifacts(ctx.evidence_id, "document_meta")
        for a in docs:
            d = a["data"]
            meta = d.get("meta") or {}
            for i, t in refs:
                if (i, d["path"]) in already:
                    continue
                tm = t.get("meta") or {}
                lineage = False
                if tm.get("title") and meta.get("title") and _norm(tm["title"]) == _norm(meta["title"]) and \
                        tm.get("created") and tm.get("created") == meta.get("created"):
                    lineage = True
                ratio = 0.0
                if t.get("text_sample") and d.get("text_chars"):
                    rows = ctx.db.query("SELECT content FROM doc_text WHERE evidence_id=? AND path=? LIMIT 1", (ctx.evidence_id, d["path"]))
                    if rows:
                        a_txt = _norm(t["text_sample"])[:20000]
                        b_txt = _norm(rows[0]["content"])[:20000]
                        if a_txt and b_txt:
                            sm = SequenceMatcher(None, a_txt, b_txt, autojunk=False)
                            if sm.real_quick_ratio() >= 0.6 and sm.quick_ratio() >= 0.6:
                                ratio = sm.ratio()
                if ratio >= 0.8 or lineage:
                    match = (f"Near-duplicate content ({ratio:.0%} text similarity)" if ratio >= 0.8 else
                             "Same document lineage (title + creation time)")
                    self._emit(i, match, d["path"], "Allocated file" if not d.get("deleted") else "Deleted file",
                               re.split(r"[\\/]", d["path"])[-1], d.get("size"), d.get("fs_created"), d.get("fs_modified"),
                               d.get("sha256"), "medium", {"similarity": round(ratio, 3)})

    # ------------------------------------------------------------------ volume shadow copies
    def _vss(self):
        ctx = self.ctx
        if not ctx.options.get("vss", True):
            ctx.coverage("Volume Shadow Copies", "System Volume Information", "skipped", 0, "disabled in options")
            return
        try:
            import pyvshadow
            from dissect.ntfs import NTFS
        except ImportError:
            ctx.coverage("Volume Shadow Copies", "System Volume Information", "error", 0, "libvshadow not available")
            return
        total_stores = 0
        for v in ctx.db.volumes(ctx.evidence_id):
            if v.get("fs") != "NTFS":
                continue
            vol = ctx.volume_map().get(v["name"])
            if vol is None:
                continue
            vs = pyvshadow.volume()
            try:
                vol.seek(0)
                vs.open_file_object(_FileWrap(vol))
            except Exception:
                continue
            for si in range(vs.number_of_stores):
                store = vs.get_store(si)
                total_stores += 1
                created = None
                try:
                    created = db_ts(store.creation_time)
                except Exception:
                    pass
                try:
                    fs = NTFS(_StoreWrap(store))
                except Exception as e:
                    ctx.warn(f"VSS store {si}: {e}")
                    continue
                self._scan_ntfs(fs, f"{v['name']} VSS #{si + 1} ({created or 'unknown date'})")
            vs.close()
        ctx.coverage("Volume Shadow Copies", "System Volume Information (all NTFS volumes)", "found" if total_stores else "not_found",
                     total_stores, f"{total_stores} snapshot(s) searched for target files")

    def _scan_ntfs(self, fs, label):
        mft = fs.mft
        try:
            nrec = mft.get(0).size() // fs._record_size
        except Exception:
            return
        for seg in range(nrec):
            try:
                rec = mft.get(seg)
                if not rec.header or not (rec.header.Flags & 1) or rec.header.Flags & 2:
                    continue
                name = rec.filename
                if not name:
                    continue
                size = rec.size()
            except Exception:
                continue
            low = name.lower()
            if not (size in self.sizes or low in self.names or _stem(name) in self.stems):
                continue
            md5 = sha256 = None
            try:
                data = rec.open().read() if size <= MAX_HASH else b""
                if data:
                    md5, sha256 = hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()
            except Exception:
                pass
            try:
                path = rec.full_path()
            except Exception:
                path = name
            self._check(md5, None, sha256, name, size, f"{label}: \\{path}", "Volume Shadow Copy", None, None)


def _zipdt(t):
    from datetime import datetime

    try:
        return datetime(*t)
    except Exception:
        return None


class _FileWrap:
    """Adapter exposing the libyal file-object protocol for a dissect stream."""

    def __init__(self, fh):
        self.fh = fh
        self.size = fh.size

    def read(self, n=-1):
        return self.fh.read(n)

    def seek(self, off, whence=0):
        return self.fh.seek(off, whence)

    def tell(self):
        return self.fh.tell()

    def get_size(self):
        return self.size


class _StoreWrap:
    """File-like wrapper around a pyvshadow store (for dissect.ntfs)."""

    def __init__(self, store):
        self.store = store
        self.pos = 0
        self.size = store.volume_size

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        self.store.seek_offset(self.pos)
        data = self.store.read_buffer(n)
        self.pos += len(data)
        return data

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        else:
            self.pos = self.size + off
        return self.pos

    def tell(self):
        return self.pos
