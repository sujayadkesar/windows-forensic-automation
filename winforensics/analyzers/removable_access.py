"""Evidence that files were opened from / copied to removable media."""

from __future__ import annotations

import re

from ..modules._usbutil import norm_vsn
from .base import INDICATED, NA, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import (basename, drive_letter_of, mentions_target, ref, removable_vsns, session_for, short, target_names,
                     usb_devices, usb_sessions)



def network_letters(actx, eid) -> set:
    """Drive letters mapped to network shares (HKCU\\Network, LNK / jump lists with a network target)."""
    out = set()
    for a in actx.artifacts("network_drive_mru", eid):
        m = re.match(r"^([A-Za-z]):\s*->", a["data"].get("path") or "")
        if m:
            out.add(m.group(1).upper() + ":")
    for t in ("lnk", "jumplist"):
        for a in actx.artifacts(t, eid):
            d = a["data"]
            if (d.get("drive_type") or "").upper() in ("NETWORK", "DRIVE_REMOTE") or d.get("network_share"):
                m = re.match(r"^([A-Za-z]):", d.get("target_path") or "")
                if m:
                    out.add(m.group(1).upper() + ":")
    return out


def optical_letters(actx, eid) -> set:
    out = set()
    for t in ("lnk", "jumplist"):
        for a in actx.artifacts(t, eid):
            d = a["data"]
            if d.get("drive_type") == "DRIVE_CDROM":
                m = re.match(r"^([A-Za-z]):", d.get("target_path") or "")
                if m:
                    out.add(m.group(1).upper() + ":")
    for a in actx.artifacts("shellbag", eid):
        m = re.match(r"^([A-Za-z]):\\<CDBURN>", a["data"].get("path") or "", re.I)
        if m:
            out.add(m.group(1).upper() + ":")
    return out


@analyzer
class RemovableAccessAnalyzer(Analyzer):
    id = "removable_access"
    title = "Removable media file activity"
    description = ("Shortcut files, jump lists, shellbags, MRU lists, Windows Timeline and prefetch records that reference "
                   "removable volumes; copy indicators; content of examined removable media.")
    weight = 1.5

    def run(self, actx):
        vsns = removable_vsns(actx)
        strong, indicated = [], []
        wins = actx.windows_evidence()
        for k, e in enumerate(wins):
            eid = e["id"]
            actx.progress(k / max(1, len(wins) + 1), f"Removable media activity on {e['label']}")
            letters = set()
            for d in usb_devices(actx, eid):
                for l in (d["data"].get("drive_letter") or "").split(","):
                    if l.strip():
                        letters.add(l.strip().upper())
            sysletter = "C:"
            nonremovable = network_letters(actx, eid) | optical_letters(actx, eid)
            external = {m.group(1).upper() for a in actx.artifacts("mounted_device", eid) if a["data"].get("external")
                        for m in [re.match(r"\\DosDevices\\([A-Z]:)", a["data"].get("name") or "", re.I)] if m}
            letters |= external - nonremovable

            def removable_path(p):
                dl = drive_letter_of(p)
                return bool(dl) and dl != sysletter and dl not in nonremovable and (dl in letters or not letters)

            # ---------------------------------------------------------- LNK + jump lists
            rows, refs, hl, calls = [], [], [], []
            n = 1
            for typ in ("lnk", "jumplist"):
                for a in actx.artifacts(typ, eid):
                    d = a["data"]
                    vsn = norm_vsn(d.get("volume_serial")) if d.get("volume_serial") else ""
                    is_rem = d.get("drive_type") == "DRIVE_REMOVABLE" or (vsn and vsn in vsns and vsns[vsn]["evidence_id"] != eid) \
                        or (vsn in vsns and vsns[vsn].get("serial"))
                    dl = drive_letter_of(d.get("target_path"))
                    is_rem = is_rem or (dl in external and d.get("drive_type") == "DRIVE_FIXED")
                    if not is_rem and not (removable_path(d.get("target_path")) and d.get("drive_type") not in ("DRIVE_FIXED", "NETWORK")):
                        continue
                    tgt = mentions_target(actx, d.get("target_path"))
                    dev = vsns.get(vsn, {})
                    rows.append([basename(d.get("lnk_path") or d.get("jumplist_file")), d.get("target_path"), d.get("drive_type", "").replace("DRIVE_", ""),
                                 f"{vsn[:4]}-{vsn[4:]}" if vsn else "", d.get("volume_label"),
                                 short(d.get("lnk_created") or d.get("last_accessed")), short(d.get("lnk_modified") or d.get("last_accessed")),
                                 d.get("application") or "LNK"])
                    i = len(rows) - 1
                    refs.append(ref(a))
                    if tgt:
                        hl.append(i)
                        strong.append((eid, a, tgt))
                    else:
                        indicated.append((eid, a, None))
                    if n <= 4 and (tgt or n == 1):
                        msg = (f"Opened '{basename(d.get('target_path'))}' from the removable volume" if tgt else
                               "Document opened from removable media")
                        if dev.get("serial"):
                            msg += f" (USB S/N {dev['serial']})"
                        calls.append(callout(i, 1, n, msg))
                        n += 1
                    actx.timeline(eid, d.get("lnk_modified") or d.get("last_accessed") or a["ts"], "LNK" if typ == "lnk" else "Jump list",
                                  "File opened from removable media", f"{d.get('target_path')} (VSN {vsn}, label {d.get('volume_label')})",
                                  ref_kind="artifact", ref_id=a["id"])
            if rows:
                vs_call = next((i for i, r in enumerate(rows) if r[3]), None)
                if vs_call is not None and len(calls) < 6:
                    calls.append(callout(vs_call, 3, n, "Volume serial of the removable volume"))
                fig = table_figure(f"Shortcut / jump list entries pointing to removable media - {actx.ev_label(eid)}",
                                   ["Shortcut", "Target path", "Drive", "Vol. serial", "Label", "First opened (UTC)",
                                    "Last opened (UTC)", "Source"], rows[:30], style="app", highlight_rows=hl, callouts=calls,
                                   col_widths=[190, 300, 80, 95, 90, 140, 140, 110],
                                   caption="LNK files are created when a file is opened; their link-info block records the drive type, "
                                           "volume serial number and label of the volume the file was on.",
                                   window_title="WFA - File & Folder Access")
                tnames = sorted({t for _, _, t in strong if t})
                fid = actx.finding(
                    f"Files opened from removable media on {actx.ev_label(eid)}"
                    + (f" incl. {len(tnames)} file(s) of interest" if tnames else ""),
                    f"{len(rows)} shortcut / jump list entries reference files on removable volumes"
                    + (f"; files of interest among them: {', '.join(tnames)}" if tnames else "") + ". "
                    "Windows creates these records when the user opens a file, so the files existed on the removable volume "
                    "at the recorded times; the volume serial numbers tie them to the specific device.",
                    evidence_id=eid, severity="high" if tnames else "medium", confidence="high", category="Removable media",
                    ts=rows[0][6] or rows[0][5], refs=refs[:100], figures=[fig],
                    questions=["dlp.removable_access"], tags=["usb", "file_access"], mitre=["T1052.001"] if tnames else [])
                actx.answer("dlp.removable_access", YES if tnames else INDICATED,
                            f"{actx.ev_label(eid)}: {len(rows)} shortcut/jump-list records of files on removable media"
                            + (f" including {', '.join(tnames)}" if tnames else "") + ".", [fid])
            # ---------------------------------------------------------- shellbags / MRUs / timeline / prefetch
            other, orefs, ohl = [], [], []
            for typ, field, label in (("shellbag", "path", "Shellbag (folder browsed)"), ("typed_path", "path", "Typed path"),
                                      ("opensave_mru", "path", "Open/Save dialog"), ("office_mru", "path", "Office MRU"),
                                      ("timeline_activity", "content", "Windows Timeline"), ("recent_doc", "name", "RecentDocs"),
                                      ("prefetch_file_ref", "file", "Prefetch file reference"), ("trusted_doc", "path", "Trusted document"),
                                      ("ie_file_access", "path", "IE / WinInet history (file opened)")):
                for a in actx.artifacts(typ, eid):
                    d = a["data"]
                    val = str(d.get(field) or "")
                    v2 = val.replace("file:///", "").replace("/", "\\")
                    hit = removable_path(v2)
                    if typ == "prefetch_file_ref":
                        vsn = norm_vsn(d.get("volume_serial"))
                        hit = vsn in vsns
                    if typ == "recent_doc":
                        hit = False
                        if mentions_target(actx, val):
                            sess = session_for(actx, eid, a["ts"]) if a["ts"] else None
                            hit = True if sess or a["ts"] is None else hit
                    if not hit:
                        continue
                    tgt = mentions_target(actx, val)
                    other.append([label, val, short(a["ts"]), a["user"] or ""])
                    orefs.append(ref(a))
                    if tgt:
                        ohl.append(len(other) - 1)
                        strong.append((eid, a, tgt))
                    actx.timeline(eid, a["ts"], label, "Removable media path", val, user=a["user"], ref_kind="artifact", ref_id=a["id"],
                                  flagged=bool(tgt) or typ in ("shellbag", "typed_path"))
            if other:
                fig = table_figure(f"Other records referencing removable volumes - {actx.ev_label(eid)}",
                                   ["Artifact", "Path / item", "Time (UTC)", "User"], other[:30], style="app", highlight_rows=ohl,
                                   col_widths=[190, 470, 150, 110],
                                   callouts=[callout(ohl[0], 1, 1, "File of interest on the removable volume")] if ohl else
                                   [callout(0, 1, 1, "Folder / file on the removable drive")],
                                   caption="Shellbags record folders browsed in Explorer; MRU lists and the Timeline record files opened.")
                actx.finding(f"Folder browsing and file use on removable drives - {actx.ev_label(eid)}",
                             f"{len(other)} shellbag, MRU, Timeline or prefetch records reference paths on removable volumes "
                             f"({', '.join(sorted(letters)) or 'non-system drives'}), showing the user browsed and used content on them.",
                             evidence_id=eid, severity="medium", confidence="high", category="Removable media",
                             refs=orefs[:100], figures=[fig], questions=["dlp.removable_access"], tags=["usb"])
                actx.answer("dlp.removable_access", INDICATED, f"{actx.ev_label(eid)}: {len(other)} shellbag/MRU/Timeline records "
                                                               "reference removable drives.", [])
            # ---------------------------------------------------------- copy inference: originals accessed during a session
            sessions = usb_sessions(actx, eid)
            if sessions:
                acc = []
                for m in actx.artifacts("target_match", eid):
                    fsid = m["data"].get("fs_id")
                    if not fsid:
                        continue
                    r = actx.db.query("SELECT path, volume, si_accessed, si_created FROM fs_entries WHERE id=?", (fsid,))
                    if not r or not r[0]["si_accessed"]:
                        continue
                    s = session_for(actx, eid, r[0]["si_accessed"])
                    if s:
                        acc.append([m["data"]["target"], f"{r[0]['volume']}{r[0]['path']}", short(r[0]["si_accessed"]),
                                    f"{short(s['data'].get('connected'))} - {short(s['data'].get('disconnected'))}",
                                    s["data"].get("serial")])
                if acc:
                    fid = actx.finding(f"Files of interest accessed while the USB device was connected - {actx.ev_label(eid)}",
                                       "The $STANDARD_INFORMATION last-access timestamp of these files falls inside a USB connection "
                                       "session. Reading a file to copy it updates the access time, so this is consistent with the "
                                       "files being copied to the device (access-time updates are not by themselves proof of copying).",
                                       evidence_id=eid, severity="high", confidence="medium", category="Removable media",
                                       figures=[table_figure("Last access of files of interest vs USB sessions",
                                                             ["Target", "File", "Last accessed (UTC)", "USB session (UTC)", "USB serial"],
                                                             acc, style="table", highlight_rows=list(range(len(acc))),
                                                             col_widths=[170, 330, 150, 280, 160], sheet="Access vs USB",
                                                             callouts=[callout(0, 2, 1, "Access time inside the connection window")])],
                                       questions=["dlp.removable_access"], tags=["usb", "copy_indicator"], mitre=["T1052.001"])
                    actx.answer("dlp.removable_access", INDICATED, f"{actx.ev_label(eid)}: {len(acc)} file(s) of interest were last "
                                                                   "accessed during a USB connection session.", [fid])
        # -------------------------------------------------------------- removable evidence images
        for e in actx.by_role("removable"):
            eid = e["id"]
            vols = actx.db.volumes(eid)
            files = actx.db.query("SELECT * FROM fs_entries WHERE evidence_id=? AND is_dir=0 ORDER BY deleted, path", (eid,))
            vs = [norm_vsn((v.get("serial") or "")[-8:]) for v in vols if v.get("serial")]
            linked = []
            for other_e in wins:
                for a in actx.artifacts("lnk", other_e["id"]) + actx.artifacts("jumplist", other_e["id"]):
                    if norm_vsn(a["data"].get("volume_serial")) in vs:
                        linked.append((other_e, a))
            rows = []
            hl = []
            tn = target_names(actx)
            for f in files[:60]:
                rows.append([f"{f['path']}", f.get("size"), short(f.get("si_created")), short(f.get("si_modified")),
                             "Deleted" if f["deleted"] else "", (f.get("sha256") or "")[:16]])
                if (f["name"] or "").lower() in tn:
                    hl.append(len(rows) - 1)
            calls = [callout(hl[0], 0, 1, "File of interest on the device")] if hl else []
            tz_note = next((v["info"].get("time_zone_assumed") for v in vols if (v.get("info") or {}).get("time_zone_assumed")), "")
            figs = [table_figure(f"Content of removable media {e['label']}", ["Path", "Size", "Created", "Modified", "State", "SHA-256"],
                                 rows, style="table", highlight_rows=hl, callouts=calls, sheet="USB content",
                                 col_widths=[330, 80, 150, 150, 80, 150],
                                 caption=f"File system listing incl. deleted entries (FAT times are local; interpreted as {tz_note or 'UTC'}).")]
            desc = (f"The removable media image {e['label']} holds volume(s) with serial {', '.join(f'{v[:4]}-{v[4:]}' for v in vs if v)} "
                    f"and {len(files)} file entries ({sum(1 for f in files if f['deleted'])} deleted). ")
            if linked:
                hosts = sorted({actx.ev_label(o['id']) for o, _ in linked})
                desc += (f"{len(linked)} shortcut / jump list records on {', '.join(hosts)} point to files on a volume with the same "
                         "serial number, proving this device was used on those systems.")
            fid = actx.finding(f"Examined removable media {e['label']}" + (" is the device used on " + ", ".join(sorted({o['label'] for o, _ in linked}))
                                                                          if linked else ""),
                               desc, evidence_id=eid, severity="high" if linked or hl else "medium", confidence="high",
                               category="Removable media", figures=figs, questions=["dlp.removable_access"], tags=["usb"])
            if hl:
                actx.answer("dlp.removable_access", YES, f"Files of interest are present on the removable media {e['label']}.", [fid])
        if not strong and not indicated and not actx.answers_pending.get("dlp.removable_access"):
            actx.answer("dlp.removable_access", NO if wins else NA,
                        "No shortcut, jump list, shellbag, MRU or Timeline record references removable media." if wins else
                        "No Windows system was examined.", [])


@analyzer
class NetworkShareAnalyzer(Analyzer):
    id = "network_access"
    title = "Network share access"
    description = ("Mapped network drives and files / folders opened on network shares (LNK, jump lists, shellbags, "
                   "IE / WinInet file history, MountPoints2) - typically where the confidential data was taken from.")
    weight = 0.6

    def run(self, actx):
        for e in actx.windows_evidence():
            eid = e["id"]
            netl = network_letters(actx, eid)

            def is_net(p):
                p = (p or "").replace("file:///", "").replace("/", "\\")
                return p.startswith("\\\\") or (drive_letter_of(p) in netl if drive_letter_of(p) else False)

            rows, refs, hl = [], [], []
            for a in actx.artifacts("network_drive_mru", eid):
                rows.append(["Mapped network drive", a["data"].get("path"), short(a["ts"]), a["user"] or ""])
                refs.append(ref(a))
            for a in actx.artifacts("usb_mountpoint", eid):
                if a["data"].get("kind") == "network share":
                    rows.append(["MountPoints2 (share opened by user)", a["data"].get("volume"), short(a["ts"]), a["user"] or ""])
                    refs.append(ref(a))
            for typ, field, label in (("ie_file_access", "path", "IE / WinInet history (file opened)"),
                                      ("lnk", "target_path", "Shortcut (LNK)"), ("jumplist", "target_path", "Jump list"),
                                      ("shellbag", "path", "Shellbag (folder browsed)"), ("opensave_mru", "path", "Open/Save dialog"),
                                      ("office_mru", "path", "Office MRU")):
                for a in actx.artifacts(typ, eid):
                    val = a["data"].get(field) or ""
                    if typ in ("lnk", "jumplist") and (a["data"].get("network_share") or "").startswith("\\\\"):
                        val = val or a["data"]["network_share"]
                    if not is_net(val):
                        continue
                    rows.append([label, val, short(a["ts"]), a["user"] or ""])
                    refs.append(ref(a))
                    if mentions_target(actx, val):
                        hl.append(len(rows) - 1)
                    actx.timeline(eid, a["ts"], label, "Network share item accessed", val, user=a["user"], ref_kind="artifact",
                                  ref_id=a["id"], flagged=bool(mentions_target(actx, val)))
            if not rows:
                continue
            rows.sort(key=lambda r: r[2] or "")
            hl = [i for i, r in enumerate(rows) if mentions_target(actx, r[1])]
            shares = sorted({m.group(0) for r in rows for m in [re.match(r"^\\\\[^\\]+\\[^\\]+", (r[1] or "").replace("/", "\\"))]
                             if m}, key=str.lower)
            desc = (f"{len(rows)} records show network shares being mapped or browsed, or files on them being opened"
                    + (f"; shares: {', '.join(shares[:6])}" if shares else "")
                    + (f"; drive letters mapped to shares: {', '.join(sorted(netl))}" if netl else "") + ". "
                    "Files opened from a share and later seen on removable media or in a sync folder identify where the data "
                    "was taken from.")
            first = next((r for r in rows if "Mapped" not in r[0]), rows[0])
            actx.finding(f"Network share access on {actx.ev_label(eid)}", desc, evidence_id=eid, confidence="high",
                         category="Network shares", ts=rows[0][2] or None, refs=refs[:200],
                         figures=[table_figure(f"Network share activity - {actx.ev_label(eid)}", ["Artifact", "Share / path", "Time (UTC)",
                                                                                                "User"], rows[:30], style="app",
                                               highlight_rows=hl[:30] or [rows.index(first)], col_widths=[230, 470, 150, 100],
                                               callouts=[callout((hl or [rows.index(first)])[0], 1, 1,
                                                                 "File / folder on a network share")])],
                         tags=["network_share"], sort_key=40)
