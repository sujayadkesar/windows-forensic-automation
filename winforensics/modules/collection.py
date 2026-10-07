"""Raw artifact collection: copies the original artifact files out of the image (KAPE style) for manual analysis
with other tools, with a hash manifest.  Deleted files are not collected here (they are in the parsed exports)."""

from __future__ import annotations

import hashlib
import os

from ..core.exporter import CsvOut, safe_name
from .base import ArtifactModule, ArtifactType, C, register

# (group, SQL LIKE pattern on the lower-case path relative to the volume root)
TARGETS = [
    ("Registry", r"\windows\system32\config\sam%"), ("Registry", r"\windows\system32\config\security%"),
    ("Registry", r"\windows\system32\config\software%"), ("Registry", r"\windows\system32\config\system%"),
    ("Registry", r"\windows\system32\config\default%"), ("Registry", r"\windows\system32\config\regback\%"),
    ("Registry", r"\users\%\ntuser.dat%"), ("Registry", r"\users\%\appdata\local\microsoft\windows\usrclass.dat%"),
    ("Registry", r"\documents and settings\%\ntuser.dat%"), ("Registry", r"\windows\appcompat\programs\amcache.hve%"),
    ("Registry", r"\windows\serviceprofiles\%\ntuser.dat%"),
    ("Event logs", r"\windows\system32\winevt\logs\%.evtx"), ("Event logs", r"\windows\system32\config\%.evt"),
    ("Execution", r"\windows\prefetch\%.pf"), ("Execution", r"\windows\appcompat\pca\%"), ("Execution", r"\windows\system32\sru\%"),
    ("Execution", r"\windows\appcompat\programs\recentfilecache.bcf"), ("Execution", r"\windows\system32\tasks\%"),
    ("Execution", r"\windows\tasks\%"),
    ("File access", r"\users\%\appdata\roaming\microsoft\windows\recent\%"),
    ("File access", r"\users\%\appdata\roaming\microsoft\office\recent\%"),
    ("File access", r"\$recycle.bin\%\$i%"), ("File access", r"\users\%\appdata\local\connecteddevicesplatform\%"),
    ("File access", r"\users\%\appdata\local\microsoft\windows\explorer\thumbcache_%"),
    ("File access", r"\users\%\appdata\local\microsoft\windows\burn\%"),
    ("Browsers", r"\users\%\appdata\local\%\user data\%\history%"), ("Browsers", r"\users\%\appdata\local\%\user data\%\cookies%"),
    ("Browsers", r"\users\%\appdata\local\%\user data\%\web data%"), ("Browsers", r"\users\%\appdata\local\%\user data\%\login data%"),
    ("Browsers", r"\users\%\appdata\local\%\user data\%\bookmarks%"), ("Browsers", r"\users\%\appdata\local\%\user data\%\preferences"),
    ("Browsers", r"\users\%\appdata\local\%\user data\%\shortcuts%"), ("Browsers", r"\users\%\appdata\local\%\user data\%\top sites%"),
    ("Browsers", r"\users\%\appdata\roaming\opera software\%\history%"),
    ("Browsers", r"\users\%\appdata\roaming\mozilla\firefox\profiles\%\places.sqlite%"),
    ("Browsers", r"\users\%\appdata\roaming\mozilla\firefox\profiles\%\cookies.sqlite%"),
    ("Browsers", r"\users\%\appdata\roaming\mozilla\firefox\profiles\%\formhistory.sqlite%"),
    ("Browsers", r"\users\%\appdata\roaming\mozilla\firefox\profiles\%\downloads.sqlite%"),
    ("Browsers", r"\users\%\appdata\roaming\mozilla\firefox\profiles\%\sessionstore%"),
    ("Browsers", r"\users\%\appdata\local\microsoft\windows\webcache\%"),
    ("Browsers", r"\users\%\appdata\local\microsoft\windows\history\%index.dat"),
    ("Browsers", r"\users\%\appdata\roaming\microsoft\windows\cookies\%"),
    ("Devices", r"\windows\inf\setupapi%.log"), ("Devices", r"\windows\setupapi%.log"),
    ("System", r"\windows\system32\drivers\etc\hosts"), ("System", r"\windows\system32\wbem\repository\%"),
    ("System", r"\programdata\microsoft\wlansvc\profiles\%"), ("System", r"\programdata\microsoft\windows defender\support\%"),
    ("System", r"\windows\system32\logfiles\%\%.log"),
    ("PowerShell", r"\users\%\appdata\roaming\microsoft\windows\powershell\psreadline\%"),
    ("PowerShell", r"\users\%\documents\powershell_transcript%"),
    ("Startup", r"\users\%\appdata\roaming\microsoft\windows\start menu\programs\startup\%"),
    ("Startup", r"\programdata\microsoft\windows\start menu\programs\startup\%"),
    ("Cloud", r"\users\%\appdata\local\google\drive\%"), ("Cloud", r"\users\%\appdata\local\google\drivefs\%.db"),
    ("Cloud", r"\users\%\appdata\local\google\drivefs\%metadata_sqlite_db%"), ("Cloud", r"\users\%\appdata\local\dropbox\%"),
    ("Cloud", r"\users\%\appdata\local\microsoft\onedrive\settings\%"), ("Cloud", r"\users\%\appdata\local\microsoft\onedrive\logs\%"),
    ("E-mail", r"\users\%.pst"), ("E-mail", r"\users\%.ost"), ("E-mail", r"\users\%\appdata\local\microsoft\outlook\%"),
    ("E-mail", r"\users\%\appdata\roaming\thunderbird\profiles\%"),
    ("Remote access", r"\programdata\anydesk\%"), ("Remote access", r"\users\%\appdata\roaming\anydesk\%"),
    ("Remote access", r"\program files%\teamviewer\%.txt"), ("Remote access", r"\program files%\teamviewer\%.log"),
    ("Remote access", r"\users\%\appdata\local\microsoft\terminal server client\cache\%"),
    ("Search index", r"\programdata\microsoft\search\data\applications\windows\windows.edb"),
    ("Sticky Notes", r"\users\%\appdata\roaming\microsoft\sticky notes\stickynotes.snt"),
    ("Sticky Notes", r"\users\%\appdata\local\packages\microsoft.microsoftstickynotes%\localstate\plum.sqlite%"),
]
SKIP_NAMES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys")


@register
class CollectionModule(ArtifactModule):
    id = "collection"
    title = "Raw artifact collection (for manual analysis)"
    category = "Collection"
    description = ("Copies registry hives (+ transaction logs), $MFT, $LogFile, $UsnJrnl:$J, event logs, Prefetch, SRUM, Amcache, "
                   "LNK / jump lists, browser databases, e-mail stores, scheduled tasks, setupapi logs, WMI repository, PowerShell "
                   "history and more into the case folder, hashing every file into a manifest.")
    weight = 3.0
    order = 95
    requires = ["filesystem"]
    windows_only = False
    locations = ["See Collected\\<evidence>\\_manifest.csv"]
    artifact_types = [
        ArtifactType("collected_file", "Collected Raw Artifact Files", "Collection",
                     [C("group"), C("source", width=420), C("size", kind="size"), C("sha256", "SHA256", "hash", 300),
                      C("collected_as", width=380)]),
    ]

    def estimate(self, ctx) -> float:
        return 3.0

    def run(self, ctx) -> None:
        if not ctx.options.get("collect_raw", True):
            ctx.coverage("Raw artifact collection", "-", "skipped", 0, "disabled in options")
            return
        max_bytes = int(ctx.options.get("collect_max_file_mb", 4096)) * 1024 * 1024
        out_root = ctx.collected_dir()
        manifest = CsvOut(os.path.join(out_root, "_manifest.csv"),
                          ["Group", "SourcePath", "CollectedAs", "Size", "MD5", "SHA1", "SHA256", "SI_Created", "SI_Modified",
                           "SI_Accessed", "Note"])
        rows = []
        seen = set()
        for group, pattern in TARGETS:
            for r in ctx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0 AND deleted=0 AND lower(path) LIKE ?",
                                  (ctx.evidence_id, pattern)):
                key = (r["volume"], r["record"], r["path"])
                if key in seen or (r["name"] or "").lower() in SKIP_NAMES:
                    continue
                seen.add(key)
                rows.append((group, r))
        # NTFS metadata files
        meta = []
        for v in ctx.db.volumes(ctx.evidence_id):
            if v.get("fs") == "NTFS":
                for name, rec in (("$MFT", 0), ("$LogFile", 2), ("$Boot", 7)):
                    meta.append((v["name"], name, rec, None))
                meta.append((v["name"], "$UsnJrnl_$J", None, "$J"))
        total = len(rows) + len(meta)
        n = 0
        copied_bytes = 0
        for vname, name, rec, stream in meta:
            vol = ctx.volume_map().get(vname)
            try:
                ntfs = vol.fs.ntfs
                if stream:
                    if ntfs.usnjrnl is None:
                        continue
                    fh = ntfs.usnjrnl.fh
                else:
                    fh = ntfs.mft.get(rec).open()
                dst = os.path.join(out_root, safe_name(vname.rstrip(":")), name)
                note = self._copy(fh, dst, max_bytes, trim_sparse=bool(stream))
                self._manifest(ctx, manifest, "NTFS metadata", f"{vname}\\{name.replace('_$J', ':$J')}", dst, None, note)
                n += 1
            except Exception as e:
                ctx.warn(f"collection {vname}\\{name}: {e}")
            ctx.progress(n / max(1, total), f"Collecting {name}")
        for group, r in rows:
            ctx.check_cancel()
            src = ctx.display_path(r["volume"], r["path"])
            rel = r["path"].lstrip("\\").replace("\\", os.sep)
            dst = os.path.join(out_root, safe_name(r["volume"].rstrip(":")), *[safe_name(p, 120) for p in rel.split(os.sep)])
            try:
                if (r.get("size") or 0) > max_bytes:
                    self._manifest(ctx, manifest, group, src, "", r, f"not collected: larger than {max_bytes // 1048576} MB")
                    continue
                note = self._copy(ctx.open_entry_stream(r), dst, max_bytes)
                copied_bytes += r.get("size") or 0
                self._manifest(ctx, manifest, group, src, dst, r, note)
                n += 1
            except Exception as e:
                self._manifest(ctx, manifest, group, src, "", r, f"error: {e}"[:200])
            if n % 25 == 0:
                ctx.progress(n / max(1, total), f"Collecting {group}: {n:,}/{total:,} files ({copied_bytes / 1e6:.0f} MB)")
        manifest.close()
        ctx.coverage("Raw artifact collection", out_root, "found" if n else "not_found", n, f"{copied_bytes / 1e6:.0f} MB copied")

    def _copy(self, fh, dst, max_bytes, trim_sparse=False) -> str:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(dst):
            base, ext = os.path.splitext(dst)
            i = 2
            while os.path.exists(f"{base}_{i}{ext}"):
                i += 1
            dst = f"{base}_{i}{ext}"
        self._last_dst = dst
        h = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        written = 0
        note = ""
        start = 0
        if trim_sparse:
            # $J is mostly a sparse prefix - start at the first allocated run like other collectors do
            try:
                off = 0
                for run_offset, run_size in getattr(fh, "runlist", []):
                    if run_offset is not None:
                        break
                    off += run_size * fh.block_size
                start = off
                note = f"sparse prefix of {start:,} bytes skipped"
            except Exception:
                start = 0
        fh.seek(start)
        with open(dst, "wb") as out:
            while True:
                b = fh.read(8 * 1024 * 1024)
                if not b:
                    break
                out.write(b)
                for x in h:
                    x.update(b)
                written += len(b)
                if written > max_bytes:
                    note = (note + "; " if note else "") + "truncated at size limit"
                    break
        self._hashes = [x.hexdigest() for x in h]
        self._size = written
        return note

    def _manifest(self, ctx, manifest, group, src, dst, r, note):
        hashes = getattr(self, "_hashes", ["", "", ""]) if dst else ["", "", ""]
        size = getattr(self, "_size", 0) if dst else (r or {}).get("size")
        dst = getattr(self, "_last_dst", dst) if dst else ""
        manifest.row([group, src, os.path.relpath(dst, ctx.collected_dir()) if dst else "", size, *hashes,
                      (r or {}).get("si_created"), (r or {}).get("si_modified"), (r or {}).get("si_accessed"), note])
        if dst:
            ctx.emit("collected_file", None, {"group": group, "source": src, "size": size, "sha256": hashes[2], "md5": hashes[0],
                                              "collected_as": dst, "note": note}, summary=f"Collected {src}", source=src)
        self._hashes, self._size = ["", "", ""], 0
