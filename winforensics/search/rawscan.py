"""Physical (raw) keyword search across every byte of the evidence + file carving.

One streaming pass per volume (and over unpartitioned disk space) using an
Aho-Corasick automaton holding every keyword in ASCII/UTF-8 and UTF-16LE form
plus the carving signatures.  Every hit is attributed by :class:`ClusterMap` to an
allocated file, file slack, unallocated space, a deleted file remnant, an MFT
record, $LogFile, the USN journal, a directory index, pagefile/hiberfil/swapfile,
a shadow copy store or unpartitioned space.  Keywords are also run against the
logical full-text index (document contents that are compressed on disk, e.g.
DOCX/XLSX/PDF, cannot be found by a physical search alone).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import queue
import time

from ..modules.base import ArtifactModule, ArtifactType, C, register
from .carve import SIGNATURES, SIG_BY_ID, refine_extension
from .clustermap import AREA_DELETED, AREA_UNALLOC, AREA_UNPART, ClusterMap

CHUNK = 16 * 1024 * 1024
CONTEXT = 64


def _printable(b: bytes) -> str:
    if b.count(b"\x00") > len(b) // 3:
        try:
            s = b.decode("utf-16-le", "replace")
        except Exception:
            s = b.decode("latin-1")
    else:
        s = b.decode("latin-1")
    return "".join(ch if 32 <= ord(ch) < 127 or ch in "äöü" else "." for ch in s)


class Automaton:
    def __init__(self, keywords: list[dict], carve: bool):
        import ahocorasick

        self.A = ahocorasick.Automaton()
        self.regex = []
        self.max_len = 64
        self.terms = keywords
        for i, k in enumerate(keywords):
            term = k["term"]
            if k.get("regex"):
                try:
                    self.regex.append((i, re.compile(term.encode("utf-8").decode("latin-1"), re.I)))
                except re.error:
                    pass
                continue
            for enc, data in (("ascii/utf8", term.encode("utf-8")), ("utf16le", term.encode("utf-16-le"))):
                key = data.lower().decode("latin-1")
                self.max_len = max(self.max_len, len(key))
                existing = self.A.get(key, None)
                if existing is None:
                    self.A.add_word(key, [("kw", i, enc, len(key))])
                else:
                    existing.append(("kw", i, enc, len(key)))
        if carve:
            for sig in SIGNATURES:
                key = sig[1].decode("latin-1")
                existing = self.A.get(key, None)
                if existing is None:
                    self.A.add_word(key, [("sig", sig[0], "", len(key))])
                else:
                    existing.append(("sig", sig[0], "", len(key)))
        self.empty = len(self.A) == 0 and not self.regex
        if len(self.A):
            self.A.make_automaton()

    def search(self, text: str):
        if len(self.A):
            for end, vals in self.A.iter(text):
                for kind, ident, enc, ln in vals:
                    yield kind, ident, enc, end - ln + 1, ln
        for i, rx in self.regex:
            for m in rx.finditer(text):
                yield "kw", i, "regex", m.start(), max(1, m.end() - m.start())


@register
class RawSearchModule(ArtifactModule):
    id = "raw_search"
    title = "Physical keyword search & carving"
    category = "Search"
    description = ("Every keyword is searched across every byte of every volume (allocated files, file slack, unallocated "
                   "clusters, MFT, $LogFile, USN journal, directory indexes, pagefile/hiberfil/swapfile, shadow copy stores) "
                   "and unpartitioned space, in ASCII/UTF-8 and UTF-16LE.  Deleted documents, shortcuts, databases and "
                   "executables are carved from unallocated space.  Keywords are also matched against document text.")
    weight = 10.0
    order = 70
    windows_only = False
    requires = ["filesystem"]
    locations = ["Whole volume (allocated, slack, unallocated)", "Unpartitioned disk space", "Document full-text index"]
    artifact_types = [
        ArtifactType("keyword_summary", "Keyword Search Summary", "Search",
                     [C("term", width=260), C("label"), C("total_hits", kind="int"), C("areas", width=420),
                      C("files", width=300)]),
        ArtifactType("carved_file", "Carved Files (unallocated space)", "Search",
                     [C("type"), C("volume"), C("offset", kind="int"), C("size", kind="size"), C("area", width=200),
                      C("sha256", "SHA256", "hash", 300), C("md5", "MD5", "hash", 240), C("details", width=300),
                      C("saved_as", width=300)]),
    ]

    def estimate(self, ctx) -> float:
        total = 0
        try:
            for d in ctx.target.disks:
                total += d.size
        except Exception:
            pass
        ctx.cache["raw_total"] = total
        return 1.0 + total / (120 * 1024 * 1024)

    def run(self, ctx) -> None:
        opts = ctx.options
        keywords = list(ctx.inputs.get("keywords") or [])
        carve = bool(opts.get("carve", True))
        if not keywords and not carve:
            ctx.coverage("Physical keyword search", "all volumes", "skipped", 0, "no keywords supplied and carving disabled")
            return
        self.auto = Automaton(keywords, carve)
        self.keywords = keywords
        self.max_per = int(opts.get("max_hits_per_term_area", 500))
        self.counts: dict[tuple, int] = {}
        self.term_files: dict[int, set] = {}
        self.carve_candidates: list[tuple] = []
        self.started = time.time()
        vols = ctx.db.volumes(ctx.evidence_id)
        vmap = ctx.volume_map()
        self.total = 0
        plan = []
        for v in vols:
            vol = vmap.get(v["name"])
            if vol is None or (v["info"] or {}).get("note", "").startswith("BitLocker"):
                continue
            plan.append((v, vol))
            self.total += vol.size
        gaps = self._gaps(ctx, vols)
        self.total += sum(g[2] for g in gaps)
        self.total = max(1, self.total)
        self.done = 0
        # progress budget: physical scan, then carving (weighted by each volume's share of the bytes)
        self.scan_share = 0.85 if carve else 0.97
        self.carve_progress = 0.0
        mode = opts.get("raw_scope", "full")
        for v, vol in plan:
            ctx.check_cancel()
            try:
                cmap = ClusterMap(ctx, v, vol)
            except Exception as e:
                ctx.warn(f"cluster map {v['name']}: {e}")
                continue
            ranges = [(0, vol.size)] if mode == "full" else self._fast_ranges(ctx, cmap, vol)
            self._scan(ctx, vol, v["name"], cmap, ranges, getattr(vol, "offset", 0) or 0)
            ctx.coverage("Physical search", f"{v['name']} ({v.get('fs') or '?'}, {vol.size / 1e9:.2f} GB)", "found"
                         if any(k[1] == v["name"] for k in self.counts) else "not_found",
                         sum(n for k, n in self.counts.items() if k[1] == v["name"]),
                         "full volume" if mode == "full" else "unallocated + slack + memory/metadata files")
            if carve:
                self._carve(ctx, vol, v["name"], cmap, getattr(vol, "offset", 0) or 0)
            self.carve_progress += vol.size / self.total
        for disk, start, length in gaps:
            self._scan(ctx, disk, "Unpartitioned", None, [(start, length)], 0)
            ctx.coverage("Physical search", f"Unpartitioned space ({length / 1e6:.1f} MB)", "found"
                         if any(k[1] == "Unpartitioned" for k in self.counts) else "not_found",
                         sum(n for k, n in self.counts.items() if k[1] == "Unpartitioned"))
        ctx.writer.flush()
        self._logical(ctx)
        self._summary(ctx)

    # ------------------------------------------------------------------ helpers
    def _gaps(self, ctx, vols):
        out = []
        try:
            disk = ctx.target.disks[0]
            exts = sorted((v["offset"] or 0, (v["offset"] or 0) + (v["size"] or 0)) for v in vols if v.get("offset") is not None)
            pos = 0
            for s, e in exts:
                if s - pos > 1024 * 1024:  # ignore alignment gaps < 1 MB except the very start
                    out.append((disk, pos, s - pos))
                elif pos == 0 and s > 0:
                    out.append((disk, 0, s))
                pos = max(pos, e)
            if disk.size - pos > 64 * 1024:
                out.append((disk, pos, disk.size - pos))
        except Exception:
            pass
        return out

    def _fast_ranges(self, ctx, cmap, vol):
        ranges = list(cmap.unallocated_ranges())
        cs = cmap.cs
        # file slack: last cluster of every non-resident file, plus memory / metadata files in full
        rows = ctx.db.query("SELECT record, name, size FROM fs_entries WHERE evidence_id=? AND volume=? AND is_dir=0 AND deleted=0",
                            (ctx.evidence_id, cmap.name))
        big = {r["record"] for r in rows if (r["name"] or "").lower() in ("pagefile.sys", "hiberfil.sys", "swapfile.sys", "$mft",
                                                                             "$logfile", "$usnjrnl")} | {0, 2}
        runs = cmap.alloc
        for i in range(len(runs.lcn)):
            rec = runs.rec[i]
            start = runs.lcn[i] * cs if not cmap.fs.startswith("FAT") else cmap.first_data + (runs.lcn[i] - 2) * cs
            if rec in big:
                ranges.append((start, runs.length[i] * cs))
            else:
                last_vcn = runs.vcn[i] + runs.length[i] - 1
                size = runs.size[i]
                if size and last_vcn * cs < size <= (last_vcn + 1) * cs and size % cs:
                    ranges.append((start + (runs.length[i] - 1) * cs, cs))
        ranges.sort()
        merged = []
        for s, ln in ranges:
            if merged and s <= merged[-1][0] + merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], s + ln - merged[-1][0]))
            else:
                merged.append((s, ln))
        return merged

    # ------------------------------------------------------------------ parallel reading
    def _source_factory(self, ctx, vol, disk_offset: int):
        """Factory of independent handles reading *volume* coordinates straight from the container.

        Each handle has its own decoder (libewf decompression is the bottleneck and scales across handles).
        Returns (factory, workers).  Falls back to the shared dissect stream (1 worker) when the container
        cannot be read directly (VMDK / VHDX / BitLocker...) or the direct bytes differ from the volume's.
        """
        from ..core.evidence import EwfStream, segment_files

        opened = ctx.opened
        fmt = getattr(opened, "format", "")
        path = ctx.evidence.get("path")
        factory = None
        if fmt in ("ewf", "ewf2", "smart") and getattr(opened, "stream", None) is not None:
            factory = lambda: _Offset(EwfStream(path), disk_offset)  # noqa: E731
        elif fmt in ("raw", "split_raw"):
            files = segment_files(path)
            factory = lambda: _Offset(_MultiFile(files), disk_offset)  # noqa: E731
        workers = max(1, int(ctx.options.get("raw_threads") or min(4, os.cpu_count() or 2)))
        if factory is not None:
            try:
                h = factory()
                ok = True
                for probe_off in (0, min(vol.size - 4096, vol.size // 2) // 4096 * 4096):
                    h.seek(probe_off)
                    a = h.read(4096)
                    vol.seek(probe_off)
                    b = vol.read(4096)
                    ok = ok and a == b
                h.close()
                if ok:
                    return factory, workers
            except Exception:
                pass
        lock = threading.Lock()
        return (lambda: _Locked(vol, lock)), 1

    def _chunks(self, factory, workers, ranges, overlap):
        """Yield (chunk_start, data, accept_len) from several reader threads (order not guaranteed)."""
        work = []
        for start, length in ranges:
            end = start + length
            pos = start
            while pos < end:
                work.append((pos, min(CHUNK, end - pos), min(CHUNK + overlap, end - pos)))
                pos += CHUNK
        q: queue.Queue = queue.Queue(maxsize=workers * 2)
        idx = [0]
        lock = threading.Lock()
        stop = threading.Event()

        def reader():
            fh = factory()
            try:
                while not stop.is_set():
                    with lock:
                        if idx[0] >= len(work):
                            break
                        item = work[idx[0]]
                        idx[0] += 1
                    pos, accept, n = item
                    fh.seek(pos)
                    data = fh.read(n)
                    q.put((pos, data, accept))
            except Exception as e:  # pragma: no cover - device errors
                q.put(e)
            finally:
                q.put(None)
                try:
                    fh.close()
                except Exception:
                    pass

        threads = [threading.Thread(target=reader, daemon=True) for _ in range(workers)]
        for t in threads:
            t.start()
        finished = 0
        try:
            while finished < workers:
                item = q.get()
                if item is None:
                    finished += 1
                    continue
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            stop.set()

    def _scan(self, ctx, src, vname, cmap, ranges, disk_offset: int = 0):
        overlap = self.auto.max_len + CONTEXT
        factory, workers = self._source_factory(ctx, src, disk_offset)
        if workers > 1:
            ctx.info(f"{vname}: physical search with {workers} parallel readers")
        for pos0, buf, accept in self._chunks(factory, workers, ranges, overlap):
            ctx.check_cancel()
            if not buf:
                continue
            text = buf.lower().decode("latin-1")
            for kind, ident, enc, pos, ln in self.auto.search(text):
                if pos >= accept:
                    continue  # reported by the next chunk
                abs_off = pos0 + pos
                if kind == "sig":
                    if cmap is not None:
                        sig = SIG_BY_ID[ident]
                        delta = sig[2] if sig[2] < 0 else 0
                        b0 = pos + delta
                        if b0 >= 0 and buf[b0:b0 + len(sig[3])] != sig[3]:
                            continue
                        if cmap.classify(abs_off + delta)["area"] in (AREA_UNALLOC, AREA_DELETED):
                            self.carve_candidates.append((abs_off, ident))
                    continue
                self._hit(ctx, vname, cmap, ident, enc, abs_off, ln, buf, pos)
            self.done += accept
            el = time.time() - self.started
            rate = self.done / el if el > 0 else 0
            ctx.progress(self._frac(),
                         f"{vname}: {self.done / 1e9:.2f} / {self.total / 1e9:.2f} GB scanned ({rate / 1e6:.0f} MB/s), "
                         f"{sum(self.counts.values()):,} hits")

    def _frac(self) -> float:
        return min(0.97, self.scan_share * self.done / self.total + (0.97 - self.scan_share) * self.carve_progress)

    def _hit(self, ctx, vname, cmap, idx, enc, off, ln, buf, pos):
        info = cmap.classify(off) if cmap is not None else {"area": AREA_UNPART}
        area = info["area"]
        key = (idx, vname, area)
        n = self.counts.get(key, 0)
        self.counts[key] = n + 1
        if n >= self.max_per:
            return
        path = ""
        rec = info.get("record")
        if rec is not None and cmap is not None:
            d = cmap.describe_record(rec)
            path = ctx.display_path(vname, d.get("path") or "")
            if d.get("deleted") and area not in (AREA_DELETED,):
                info["record_deleted"] = True
            self.term_files.setdefault(idx, set()).add(path)
        if info.get("mft_record") is not None and cmap is not None:
            d = cmap.describe_record(info["mft_record"])
            path = f"MFT record {info['mft_record']}: " + ctx.display_path(vname, d.get("path") or "")
            info["mft_path"] = d.get("path")
        ctx_start = max(0, pos - CONTEXT)
        ctx_bytes = buf[ctx_start:pos + ln + CONTEXT]
        k = self.keywords[idx]
        detail = {**{x: y for x, y in info.items() if x != "area"}, "context_start": off - (pos - ctx_start),
                  "hit_in_context": pos - ctx_start, "volume_offset": off}
        ctx.writer.hit((ctx.evidence_id, "physical", k["term"], k.get("label", ""), area, vname, off, ln, enc, path,
                        rec, ctx_bytes.hex(), _printable(ctx_bytes), json.dumps(detail, default=str)))

    # ------------------------------------------------------------------ carving
    def _carve(self, ctx, vol, vname, cmap, disk_offset: int = 0):
        cands = sorted(set(self.carve_candidates))
        self.carve_candidates = []
        share = vol.size / self.total
        base = self.carve_progress
        if not cands:
            ctx.coverage("File carving", f"{vname} unallocated space", "not_found", 0)
            return
        max_files = int(ctx.options.get("carve_max_files", 20000))
        save_types = set(ctx.options.get("carve_save_types", ["pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "msg", "lnk", "exe",
                                                               "zip", "7z", "sqlite"]))
        out_dir = ctx.case.sub("exports", f"E{ctx.evidence_id:02d}", "carved")
        done_until = -1
        n = 0
        factory, _workers = self._source_factory(ctx, vol, disk_offset)
        fh = factory()

        def read(o, ln):
            fh.seek(o)
            return fh.read(ln)

        last = 0.0
        ctx.info(f"{vname}: {len(cands):,} carving candidates in unallocated space / deleted files")
        for ci, (off, sig_id) in enumerate(cands):
            if n >= max_files:
                break
            now = time.time()
            if now - last > 0.5:
                last = now
                ctx.check_cancel()
                self.carve_progress = base + share * ci / len(cands)
                ctx.progress(self._frac(), f"{vname}: carving {ci:,} / {len(cands):,} candidates, {n:,} files recovered")
            sig = SIG_BY_ID[sig_id]
            start = off + (sig[2] if sig[2] < 0 else 0)
            if start <= done_until or start < 0:
                continue
            info = cmap.classify(start)
            if info["area"] not in (AREA_UNALLOC, AREA_DELETED):
                continue
            try:
                head = read(start, len(sig[3]))
                if head != sig[3]:
                    continue
                size = sig[5](read, start)
            except Exception:
                size = None
            if not size or size < 32:
                continue
            data = read(start, size)
            if len(data) != size:
                continue
            ext = refine_extension(data, sig[4])
            md5, sha256 = hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()
            details = ""
            text = ""
            if ext in ("pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt"):
                try:
                    from ..modules.documents import extract

                    meta, text = extract(data, ext)
                    details = ", ".join(f"{k}={v}" for k, v in meta.items() if k in ("title", "author", "last_modified_by",
                                                                                   "created", "modified"))[:300]
                except Exception:
                    pass
            elif ext == "lnk":
                try:
                    from ..modules.files import parse_lnk

                    l = parse_lnk(data)
                    details = f"-> {l['target_path']} ({l['drive_type']} {l['volume_serial']} {l['volume_label']})"
                    text = json.dumps(l)
                except Exception:
                    pass
            saved = ""
            if ext in save_types and size <= 100 * 1024 * 1024:
                saved = os.path.join(out_dir, f"{vname.strip(':')}_{start:012X}.{ext}")
                with open(saved, "wb") as fh:
                    fh.write(data)
            rec = {"type": ext, "volume": vname, "offset": start, "size": size, "area": info["area"], "sha256": sha256, "md5": md5,
                   "details": details, "saved_as": saved, "deleted_record": cmap.describe_record(info["record"]).get("path")
                   if info.get("record") is not None else ""}
            ctx.emit("carved_file", None, rec, summary=f"Carved {ext} at {vname}+{start:#x} ({size} bytes) {details}"[:300],
                     source=f"{vname} offset {start:#x}", tags=["carved"])
            if text.strip():
                ctx.writer.doc((ctx.evidence_id, f"[carved] {vname}+{start:#x}.{ext}", f"carved:{sha256}", text[:300_000]))
            done_until = start + size - 1
            n += 1
        try:
            fh.close()
        except Exception:
            pass
        self.carve_progress = base
        ctx.coverage("File carving", f"{vname} unallocated space", "found" if n else "not_found", n,
                     f"{len(cands):,} signature candidates")

    # ------------------------------------------------------------------ logical search
    def _logical(self, ctx):
        n = 0
        for i, k in enumerate(self.keywords):
            if k.get("regex"):
                continue
            words = re.findall(r"\w+", k["term"].lower())
            if not words:
                continue
            q = 'content : "' + " ".join(words) + '"'
            try:
                rows = ctx.db.query("SELECT rowid, path, source, snippet(doc_text, 3, '[[', ']]', ' ... ', 16) AS snip FROM doc_text "
                                    "WHERE evidence_id=? AND doc_text MATCH ? LIMIT 2000", (ctx.evidence_id, q))
            except Exception:
                rows = []
            for r in rows:
                area = "Document text (carved, unallocated)" if r["source"].startswith("carved") else "Document text (logical)"
                key = (i, "logical", area)
                self.counts[key] = self.counts.get(key, 0) + 1
                self.term_files.setdefault(i, set()).add(r["path"])
                ctx.writer.hit((ctx.evidence_id, "logical", k["term"], k.get("label", ""), area, "", None, None, "text",
                                r["path"], None, "", r["snip"], json.dumps({"source": r["source"]})))
                n += 1
        ctx.writer.flush()
        ctx.coverage("Document text search", "full-text index of documents (incl. carved)", "found" if n else "not_found", n)

    def _summary(self, ctx):
        for i, k in enumerate(self.keywords):
            per_area: dict[str, int] = {}
            for (idx, vname, area), n in self.counts.items():
                if idx == i:
                    label = f"{area}" if vname in ("logical",) else f"{area} [{vname}]"
                    per_area[label] = per_area.get(label, 0) + n
            total = sum(per_area.values())
            files = sorted(self.term_files.get(i, set()))
            ctx.emit("keyword_summary", None, {"term": k["term"], "label": k.get("label"), "total_hits": total,
                                               "areas": "; ".join(f"{a}: {n}" for a, n in sorted(per_area.items(), key=lambda x: -x[1])),
                                               "files": "; ".join(files[:15]) + (" ..." if len(files) > 15 else ""),
                                               "area_counts": per_area, "regex": k.get("regex", False)},
                     summary=f"'{k['term']}': {total} hits", source="raw search")
        ctx.flush()


class _Offset:
    """File object view shifted by a fixed offset (volume coordinates on top of a disk stream)."""

    def __init__(self, fh, base: int):
        self.fh, self.base = fh, base

    def seek(self, off, whence=0):
        return self.fh.seek(self.base + off)

    def read(self, n=-1):
        return self.fh.read(n)

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


class _Locked:
    def __init__(self, fh, lock):
        self.fh, self.lock, self.pos = fh, lock, 0

    def seek(self, off, whence=0):
        self.pos = off

    def read(self, n=-1):
        with self.lock:
            self.fh.seek(self.pos)
            d = self.fh.read(n)
        self.pos += len(d)
        return d

    def close(self):
        pass


class _MultiFile:
    """Read-only concatenation of split raw segments with seek."""

    def __init__(self, files):
        self.files = files
        self.sizes = [os.path.getsize(f) for f in files]
        self.handles = [None] * len(files)
        self.pos = 0

    def seek(self, off, whence=0):
        self.pos = off

    def read(self, n=-1):
        out = []
        while n:
            acc = 0
            for i, sz in enumerate(self.sizes):
                if self.pos < acc + sz:
                    break
                acc += sz
            else:
                break
            if self.handles[i] is None:
                self.handles[i] = open(self.files[i], "rb")
            fh = self.handles[i]
            fh.seek(self.pos - acc)
            want = min(n, acc + self.sizes[i] - self.pos) if n > 0 else acc + self.sizes[i] - self.pos
            d = fh.read(want)
            if not d:
                break
            out.append(d)
            self.pos += len(d)
            n -= len(d) if n > 0 else 0
            if n < 0:
                n = 0
        return b"".join(out)

    def close(self):
        for h in self.handles:
            if h:
                h.close()
