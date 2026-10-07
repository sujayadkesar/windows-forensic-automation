"""Where were the files of interest found (or not found) on each evidence item."""

from __future__ import annotations

from .base import INCONCLUSIVE, NA, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import ref, short, targets


@analyzer
class TargetFilesAnalyzer(Analyzer):
    id = "target_files"
    title = "Files of interest"
    description = "Presence, deletion, renaming, archiving and copies of the files of interest on every evidence item."
    weight = 1.0

    def run(self, actx):
        tlist = targets(actx)
        if not tlist:
            actx.answer("dlp.targets_present", NA, "No files of interest were supplied; see the document access findings.", [])
            if actx.by_role("personal", "secondary"):
                actx.answer("dlp.personal_device", INCONCLUSIVE, "No files of interest were supplied, so copies could not be identified "
                                                                 "by hash; see the cross-device findings (same removable device or "
                                                                 "same file names on both systems).", [])
            else:
                actx.answer("dlp.personal_device", NA, "No personal / secondary device was examined.", [])
            return
        any_found = False
        for k, e in enumerate(actx.evidence):
            eid = e["id"]
            actx.progress(k / max(1, len(actx.evidence)), f"Target files on {e['label']}")
            matches = actx.artifacts("target_match", eid, order="ts")
            if not matches:
                fid = actx.finding(f"Files of interest not found on {actx.ev_label(eid)}",
                                   f"None of the {len(tlist)} files of interest were found on {actx.ev_label(eid)} by hash, name, "
                                   "size or content - in allocated or deleted files, the Recycle Bin, archives, e-mail attachments, "
                                   "carved data or Volume Shadow Copies.", evidence_id=eid, severity="info", confidence="high",
                                   category="Files of interest", questions=["dlp.targets_present"])
                actx.answer("dlp.targets_present", NO, f"{actx.ev_label(eid)}: no copies found.", [fid])
                continue
            any_found = True
            rows = []
            hl, calls = [], []
            by_target = {}
            for m in matches:
                d = m["data"]
                by_target.setdefault(d.get("target"), []).append(m)
            n = 1
            used_msgs = set()
            for m in matches[:40]:
                d = m["data"]
                rows.append([d.get("target"), d.get("match"), d.get("location"), d.get("area"), short(d.get("created")),
                             short(d.get("modified")), (d.get("sha256") or "")[:16] + ("..." if d.get("sha256") else "")])
                i = len(rows) - 1
                if d.get("confidence") == "high":
                    hl.append(i)
                if "renamed" in (d.get("match") or "") and n <= 6 and "ren" not in used_msgs:
                    used_msgs.add("ren")
                    calls.append(callout(i, 2, n, "Same content (hash) under a different name"))
                    n += 1
                elif "Deleted" in (d.get("area") or "") and n <= 6 and "del" not in used_msgs:
                    used_msgs.add("del")
                    calls.append(callout(i, 3, n, "Deleted file - content recovered and hashed"))
                    n += 1
                elif "ZIP" in (d.get("area") or "") and n <= 6 and "zip" not in used_msgs:
                    used_msgs.add("zip")
                    calls.append(callout(i, 2, n, "Copy inside an archive (staging)"))
                    n += 1
                elif "Recycle" in (d.get("area") or "") and n <= 6 and "rec" not in used_msgs:
                    used_msgs.add("rec")
                    calls.append(callout(i, 3, n, "In the Recycle Bin"))
                    n += 1
            fig = table_figure(f"Files of interest located on {actx.ev_label(eid)}",
                               ["Target", "Match", "Location", "Area", "Created (UTC)", "Modified (UTC)", "SHA-256"], rows,
                               style="table", highlight_rows=hl, callouts=calls, sheet="Target matches",
                               col_widths=[150, 170, 330, 140, 130, 130, 140],
                               caption="Hash / name / content matches of the files of interest (green = identical content)")
            parts = []
            fids = []
            for tname, ms in by_target.items():
                kinds = sorted({m["data"].get("match", "").split(" (")[0] for m in ms})
                areas = sorted({m["data"].get("area") for m in ms})
                parts.append(f"'{tname}' - {len(ms)} location(s) ({', '.join(areas)}; {', '.join(kinds)})")
            deleted = [m for m in matches if "Deleted" in (m["data"].get("area") or "") or "emptied" in (m["data"].get("area") or "")]
            renamed = [m for m in matches if "renamed" in (m["data"].get("match") or "")]
            archived = [m for m in matches if "ZIP" in (m["data"].get("area") or "")]
            recycled = [m for m in matches if "Recycle" in (m["data"].get("area") or "")]
            sev = "high" if e.get("role") in ("personal", "removable", "secondary") else "medium"
            desc = (f"{len(by_target)} of {len(tlist)} files of interest were found on {actx.ev_label(eid)}: " + "; ".join(parts) + ". "
                    + (f"{len(deleted)} copies exist only as deleted files (content recovered from the file system). " if deleted else "")
                    + (f"{len(renamed)} copies carry a different file name (renamed copy, identical content). " if renamed else "")
                    + (f"{len(archived)} copies are stored inside archive files. " if archived else "")
                    + (f"{len(recycled)} copies are in the Recycle Bin. " if recycled else ""))
            fid = actx.finding(f"Files of interest present on {actx.ev_label(eid)} ({len(by_target)}/{len(tlist)})", desc,
                               evidence_id=eid, severity=sev, confidence="high", category="Files of interest",
                               ts=matches[0]["ts"], refs=[ref(m) for m in matches[:200]], figures=[fig],
                               questions=["dlp.targets_present"] + (["dlp.personal_device"] if e.get("role") in ("personal", "secondary") else []),
                               tags=["target_match"])
            fids.append(fid)
            actx.answer("dlp.targets_present", YES, f"{actx.ev_label(eid)}: {len(by_target)}/{len(tlist)} files found"
                        + (f" ({len(deleted)} deleted, {len(renamed)} renamed, {len(archived)} archived)" if deleted or renamed or archived else "")
                        + ".", fids)
            if e.get("role") in ("personal", "secondary"):
                actx.answer("dlp.personal_device", YES, f"Copies of {len(by_target)} file(s) of interest exist on {actx.ev_label(eid)}.", fids)
            for m in matches:
                d = m["data"]
                actx.timeline(eid, d.get("created"), "Files", "File of interest created",
                              f"{d.get('target')} present as {d.get('location')} [{d.get('match')}]", ref_kind="artifact", ref_id=m["id"])
            # USN journal history of the target names
            names = {(t.get("name") or "").lower() for t in tlist if t.get("name")}
            if names:
                ph = ",".join("?" * len(names))
                usn = actx.db.query(f"SELECT ts, path, reason FROM usn WHERE evidence_id=? AND lower(name) IN ({ph}) ORDER BY ts LIMIT 300",
                                    (eid, *names))
                if usn:
                    ur = [[short(u["ts"]), u["path"], u["reason"]] for u in usn[:30]]
                    hlu = [i for i, r in enumerate(ur) if "Delete" in r[2] or "Rename" in r[2]]
                    actx.finding(f"USN journal history of the files of interest on {actx.ev_label(eid)}",
                                 f"The NTFS change journal recorded {len(usn)} operations on file names of interest (creation, "
                                 "modification, rename, deletion), giving a precise sequence of file system activity.",
                                 evidence_id=eid, severity="medium", confidence="high", category="Files of interest", ts=usn[0]["ts"],
                                 figures=[table_figure("$UsnJrnl:$J records for the files of interest", ["Time (UTC)", "Path",
                                                                                                         "Reason"], ur,
                                                       style="app", highlight_rows=hlu, col_widths=[150, 470, 300])],
                                 questions=["dlp.targets_present", "anti_forensics"])
                    for u in usn:
                        if "FileDelete" in u["reason"] or "RenameNewName" in u["reason"] or "FileCreate" in u["reason"]:
                            actx.timeline(eid, u["ts"], "USN", u["reason"].split("|")[0], u["path"])
        if not any_found:
            actx.answer("dlp.personal_device", NO if actx.by_role("personal", "secondary") else NA,
                        "No copies of the files of interest were found on the personal / secondary device(s)." if actx.by_role(
                            "personal", "secondary") else "No personal / secondary device was examined.", [])
