"""Network exfiltration channels: webmail / cloud / file-transfer sites, browser file dialogs, downloads,
e-mail clients, cloud sync clients, printing, archiving and transfer tools."""

from __future__ import annotations

import re

from ..knowledge import document_extensions, tool_for_exe
from .base import INDICATED, NA, NO, YES, Analyzer, analyzer, callout, table_figure
from .common import (BROWSER_EXES, EXFIL_CATS, basename, classify, mentions_target, near, ref, sender_impersonation, short,
                     target_names)

UPLOAD_HINT = re.compile(r"compose|upload|attach|#sent|/sent|share|send|transfer|new\?|/new|drop|paste|create", re.I)


@analyzer
class ExfilChannelsAnalyzer(Analyzer):
    id = "exfil_channels"
    title = "Exfiltration channels"
    description = ("Webmail, cloud storage, file transfer and AI sites; browser file-dialog use; downloads of the files; "
                   "e-mail attachments; cloud sync clients; printing; archivers and transfer tools.")
    weight = 1.5

    def run(self, actx):
        web_events = [e for e in actx.inputs.get("dlp_events") or [] if e.get("channel") == "web_upload"]
        wins = actx.windows_evidence()
        for k, e in enumerate(wins):
            eid = e["id"]
            actx.progress(k / max(1, len(wins)), f"Exfiltration channels on {e['label']}")
            self._web(actx, eid, web_events)
            self._dialogs(actx, eid)
            self._downloads(actx, eid)
            self._email(actx, eid)
            self._cloud(actx, eid)
            self._print(actx, eid)
            self._optical(actx, eid)
            self._tools(actx, eid)
            self._memory(actx, eid)
        if "dlp.web" not in actx.answers_pending:
            actx.answer("dlp.web", NO if wins else NA, "No browser, memory or registry evidence of webmail / cloud / file-sharing "
                                                       "use was found." if wins else "No Windows system was examined.", [])
        if "dlp.other_channels" not in actx.answers_pending:
            actx.answer("dlp.other_channels", NO if wins else NA, "No e-mail client, cloud sync, print, CD/DVD burning, archive or "
                                                                  "transfer-tool activity involving the files was found." if wins else "",
                        [])

    # ------------------------------------------------------------------ browser visits
    def _web(self, actx, eid, web_events):
        visits = actx.artifacts("web_visit", eid, where="json_extract(data_json,'$.category') IN (" +
                                ",".join("?" * len(EXFIL_CATS)) + ")", params=EXFIL_CATS)
        if not visits:
            return
        start, end = actx.window
        rows, hl, refs = [], [], []
        services = {}
        for v in visits:
            d = v["data"]
            services.setdefault(f"{d.get('service')} ({d.get('category')})", []).append(v)
        for v in visits:
            d = v["data"]
            if (start or end) and not actx.in_window(v["ts"], pad_minutes=60) and len(visits) > 40:
                continue
            upload = bool(UPLOAD_HINT.search(f"{d.get('url')} {d.get('title')}"))
            near_alert = any(near(v["ts"], we.get("time"), 15) for we in web_events)
            rows.append([short(v["ts"]), d.get("service"), d.get("title") or "", d.get("url"), d.get("browser"), v["user"] or ""])
            if upload or near_alert:
                hl.append(len(rows) - 1)
            refs.append(ref(v))
            actx.timeline(eid, v["ts"], f"Web ({d.get('browser')})", f"{d.get('category')}: {d.get('service')}",
                          f"{d.get('title') or ''} {d.get('url')}", user=v["user"], ref_kind="artifact", ref_id=v["id"],
                          flagged=upload or near_alert)
        rows = rows[:40]
        calls = []
        for n, i in enumerate([i for i in hl if i < len(rows)][:4], start=1):
            calls.append(callout(i, 3, n, "Compose / sent / upload page" if UPLOAD_HINT.search(rows[i][3] + rows[i][2]) else
                                 "Visit close to the DLP upload alert"))
        fig = table_figure(f"Browser history - webmail / cloud / file-sharing destinations ({actx.ev_label(eid)})",
                           ["Visited (UTC)", "Service", "Page title", "URL", "Browser", "User"], rows, style="app", highlight_rows=hl,
                           callouts=calls, col_widths=[150, 110, 220, 380, 80, 90], window_title="WFA - Browser Activity")
        svc_txt = "; ".join(f"{s}: {len(vs)} visit(s)" for s, vs in services.items())
        uploads = [r for r in rows if UPLOAD_HINT.search(r[3] + r[2])]
        fid = actx.finding(f"Web destinations capable of receiving files visited on {actx.ev_label(eid)}",
                           f"The browser history shows {len(visits)} visits to webmail, cloud storage, file-transfer, paste, "
                           f"messaging or AI services ({svc_txt}). {len(uploads)} of the listed visits are compose / sent / upload "
                           "pages. Browser history alone does not prove a file was attached or uploaded; see the file-dialog and "
                           "memory findings for corroboration.",
                           evidence_id=eid, severity="medium" if uploads else "low", confidence="medium", category="Web activity",
                           ts=rows[0][0] if rows else None, refs=refs[:150], figures=[fig], questions=["dlp.web"],
                           tags=["web"], mitre=["T1567"] if uploads else [])
        actx.answer("dlp.web", INDICATED if uploads else NO,
                    f"{actx.ev_label(eid)}: {len(visits)} visits to file-receiving web services ({len(uploads)} compose/upload pages).",
                    [fid])

    # ------------------------------------------------------------------ browser file dialogs (upload indicator)
    def _dialogs(self, actx, eid):
        lv = [a for a in actx.artifacts("lastvisited_mru", eid) if (a["data"].get("application") or "").lower() in BROWSER_EXES]
        os_mru = actx.artifacts("opensave_mru", eid)
        if not lv:
            return
        tn = target_names(actx)
        rows, hl, refs, calls = [], [], [], []
        strong = []
        for a in lv:
            d = a["data"]
            folder = (d.get("folder") or "").rstrip("\\")
            in_folder = actx.db.query("SELECT name FROM fs_entries WHERE evidence_id=? AND lower(path)=lower(?) || '\\' || lower(name) "
                                      "AND is_dir=0 LIMIT 500", (eid, folder[2:] if folder[1:2] == ":" else folder))
            tf = [r["name"] for r in in_folder if r["name"].lower() in tn]
            picked = [o for o in os_mru if (o["data"].get("path") or "").lower().startswith(folder.lower()) and
                      near(o["data"].get("key_last_written"), d.get("key_last_written"), 2)]
            rows.append([d.get("application"), d.get("folder"), short(d.get("key_last_written")), ", ".join(tf),
                         ", ".join(basename(p["data"].get("path")) for p in picked)])
            if tf or picked:
                hl.append(len(rows) - 1)
                strong.append((a, tf, picked))
            refs.append(ref(a))
        for n, i in enumerate(hl[:3], start=1):
            calls.append(callout(i, 1, n, "Folder used by the browser's file dialog (upload / save)"))
        figs = [table_figure(f"Browser file-dialog usage - {actx.ev_label(eid)}",
                             ["Application", "Last folder used", "Key last written (UTC)", "Files of interest in folder",
                              "File picked (OpenSave MRU)"], rows, style="app", highlight_rows=hl, callouts=calls,
                             col_widths=[110, 340, 160, 250, 230])]
        if strong:
            # decoded registry entries exactly as parsed (MRU position, decoded content, key last-written time)
            ent = []
            for a, _tf, picked in strong[:6]:
                d = a["data"]
                ent.append(["LastVisitedPidlMRU", d.get("mru_position"), f"{d.get('application')} | {d.get('folder')}",
                            short(d.get("key_last_written"))])
                for p in picked[:3]:
                    pd = p["data"]
                    ent.append([f"OpenSavePidlMRU\\{pd.get('extension') or '*'}", pd.get("mru_position"), pd.get("path"),
                                short(pd.get("key_last_written"))])
            figs.append(table_figure("Registry - ComDlg32 MRU entries (decoded)",
                                     ["Key (HKCU\\...\\Explorer\\ComDlg32)", "MRU position", "Decoded entry", "Key last written (UTC)"],
                                     ent, style="table", highlight_rows=list(range(len(ent))), col_widths=[260, 100, 520, 170],
                                     callouts=[callout(0, 2, 1, "Application and folder of its last Open/Save dialog")]
                                     + ([callout(1, 2, 2, "File selected in a dialog at the same time")] if len(ent) > 1 and
                                        ent[1][0].startswith("OpenSave") else []),
                                     caption="LastVisitedPidlMRU records the last folder each application used in an Open/Save "
                                             "dialog; OpenSavePidlMRU records the files selected, per extension. MRU position 0 is "
                                             "the most recent entry, written at the key's last-written time."))
        tnames = sorted({t for _, tf, _ in strong for t in tf} | {basename(p["data"].get("path")).lower() for _, _, ps in strong for p in ps
                                                                 if basename(p["data"].get("path")).lower() in tn})
        sev = "high" if tnames else "medium"
        fid = actx.finding(f"Browser file dialog used on folders holding files of interest - {actx.ev_label(eid)}" if tnames else
                           f"Browser file dialog activity - {actx.ev_label(eid)}",
                           "LastVisitedPidlMRU shows a web browser opened a file dialog (used for uploading attachments or saving "
                           "downloads) in the listed folder(s)" + (f", which contain the files of interest ({', '.join(tnames)})"
                                                                     if tnames else "") +
                           ". Where OpenSavePidlMRU recorded a file selection at the same moment, the selected file is shown.",
                           evidence_id=eid, severity=sev, confidence="medium", category="Web activity",
                           ts=lv[0]["data"].get("key_last_written"), refs=refs, figures=figs, questions=["dlp.web"],
                           tags=["web", "upload_indicator"], mitre=["T1567"] if tnames else [])
        actx.answer("dlp.web", YES if tnames else INDICATED,
                    f"{actx.ev_label(eid)}: a browser file dialog was used in a folder containing {', '.join(tnames)}"
                    if tnames else f"{actx.ev_label(eid)}: browser file dialogs were used.", [fid])
        for a, tf, picked in strong:
            actx.timeline(eid, a["data"].get("key_last_written"), "Registry", "Browser file dialog",
                          f"{a['data'].get('application')} used {a['data'].get('folder')} ({', '.join(tf)})", ref_kind="artifact",
                          ref_id=a["id"])

    # ------------------------------------------------------------------ downloads / mark of the web
    def _downloads(self, actx, eid):
        rows, refs, hl = [], [], []
        for a in actx.artifacts("web_download", eid):
            d = a["data"]
            tgt = mentions_target(actx, d.get("target_path"))
            cat, svc = classify(d.get("url") or d.get("tab_url") or "")
            if not tgt and cat not in ("Mail attachment", "Webmail", "Cloud storage", "File transfer service"):
                continue
            rows.append([short(a["ts"]), d.get("target_path"), d.get("url"), svc or cat, d.get("browser"), d.get("state")])
            refs.append(ref(a))
            if tgt:
                hl.append(len(rows) - 1)
            actx.timeline(eid, a["ts"], f"Download ({d.get('browser')})", "File downloaded", f"{d.get('target_path')} <- {d.get('url')}",
                          user=a["user"], ref_kind="artifact", ref_id=a["id"], flagged=bool(tgt))
        for a in actx.artifacts("zone_identifier", eid):
            d = a["data"]
            tgt = mentions_target(actx, d.get("file"))
            cat, svc = classify(d.get("host_url") or d.get("referrer_url") or "")
            if not tgt and not cat:
                continue
            rows.append([short(a["ts"]), d.get("file"), d.get("host_url") or d.get("referrer_url"), (svc or cat) + " (Zone.Identifier)",
                         "", d.get("deleted") or ""])
            refs.append(ref(a))
            if tgt:
                hl.append(len(rows) - 1)
        if not rows:
            return
        tn = [r for i, r in enumerate(rows) if i in hl]
        fid = actx.finding(f"Files downloaded from webmail / cloud services on {actx.ev_label(eid)}"
                           + (" incl. files of interest" if tn else ""),
                           f"{len(rows)} downloads (browser download records and Mark-of-the-Web streams) came from webmail "
                           "attachment, cloud storage or file-transfer hosts" + (f"; {len(tn)} of them are files of interest, showing "
                                                                                  "the files arrived on this system through the web"
                                                                                  if tn else "") + ".",
                           evidence_id=eid, severity="high" if tn and actx.role(eid) in ("personal", "secondary") else "medium",
                           confidence="high", category="Web activity", ts=rows[0][0], refs=refs,
                           figures=[table_figure(f"Downloads from file-hosting services - {actx.ev_label(eid)}",
                                                 ["Time (UTC)", "Saved to", "Source URL", "Service", "Browser", "State"], rows,
                                                 style="app", highlight_rows=hl, col_widths=[150, 300, 380, 170, 80, 90],
                                                 callouts=[callout(hl[0], 2, 1, "Downloaded from a webmail attachment / cloud link")]
                                                 if hl else [])],
                           questions=["dlp.web", "dlp.personal_device"], tags=["web", "download"])
        if tn:
            if actx.role(eid) in ("personal", "secondary"):
                actx.answer("dlp.personal_device", YES, f"{actx.ev_label(eid)}: files of interest were downloaded from web services "
                                                        f"({', '.join(sorted({basename(r[1]) for r in tn}))}).", [fid])
            actx.answer("dlp.web", YES, f"{actx.ev_label(eid)}: files of interest were downloaded from webmail / cloud services.", [fid])

    # ------------------------------------------------------------------ e-mail
    def _email(self, actx, eid):
        atts = actx.artifacts("email_attachment", eid)
        hits = [a for a in atts if mentions_target(actx, a["data"].get("filename"))]
        hashed = {m["data"].get("location") for m in actx.artifacts("target_match", eid) if m["data"].get("area") == "E-mail attachment"}
        self._mailbox(actx, eid)
        if not hits and not hashed:
            return
        rows = [[short(a["ts"]), a["data"].get("filename"), a["data"].get("sender"), a["data"].get("to"), a["data"].get("subject"),
                 a["data"].get("folder")] for a in hits[:40]]
        fid = actx.finding(f"Files of interest sent / received as e-mail attachments - {actx.ev_label(eid)}",
                           f"{len(hits)} attachments in the mailbox(es) carry the names (or hashes) of files of interest.",
                           evidence_id=eid, severity="high", confidence="high", category="E-mail", ts=rows[0][0] if rows else None,
                           refs=[ref(a) for a in hits], figures=[table_figure("E-mail attachments matching files of interest",
                                                                              ["Time (UTC)", "Attachment", "From", "To", "Subject", "Folder"],
                                                                              rows, style="table", highlight_rows=list(range(len(rows))),
                                                                              sheet="E-mail", col_widths=[150, 200, 200, 200, 240, 120])],
                           questions=["dlp.other_channels"], tags=["email"], mitre=["T1048.003"])
        actx.answer("dlp.other_channels", YES, f"{actx.ev_label(eid)}: files of interest found as e-mail attachments.", [fid])

    def _mailbox(self, actx, eid):
        """Sent / deleted messages and messages with attachments, from the mail store and from the Windows Search index
        (which keeps messages that were later deleted from the mailbox)."""
        from datetime import datetime

        msgs = actx.artifacts("email_message", eid, order="ts")
        idx = [a for a in actx.artifacts("search_index_item", eid, order="ts") if a["data"].get("sent")]
        if not msgs and not idx:
            return

        def t(x):
            try:
                return datetime.fromisoformat(str(x)[:19])
            except ValueError:
                return None

        def norm(sub):
            return re.sub(r"\s+", " ", (sub or "").strip().lower())

        store = [(norm(a["data"].get("subject")), t(a["data"].get("time") or a["ts"])) for a in msgs]

        def in_store(subject, when):
            return any(sj == norm(subject) and w and when and abs((w - when).total_seconds()) <= 120 for sj, w in store)

        # Windows Search: '<folder path>/<subject>' items, attachments as '<subject> : <file name>'
        index_msgs, index_att = {}, {}
        for a in idx:
            d = a["data"]
            path = d.get("path") or ""
            folder, _, leaf = path.rpartition("/")
            if " : " in leaf:
                sub, att = leaf.split(" : ", 1)
                index_att.setdefault((norm(sub), d.get("sent", "")[:16]), set()).add(att)
                continue
            index_msgs[(norm(d.get("subject")), d.get("sent", "")[:16])] = (a, folder.rsplit("/", 1)[-1])
        rows, hl, refs, interesting = [], [], [], []
        for a in msgs:
            d = a["data"]
            folder = (d.get("folder") or "").split("/")[-1]
            if "sync issues" in folder.lower():
                continue
            if any(x in folder.lower() for x in ("sent", "deleted", "outbox", "drafts")) or (d.get("attachments") or 0) > 0 \
                    or mentions_target(actx, f"{d.get('subject')} {d.get('attachment_names')}"):
                rows.append([short(a["ts"]), folder, (d.get("sender") or "")[:60], (d.get("to") or "")[:60], d.get("subject") or "",
                             d.get("attachment_names") or (str(d.get("attachments")) if d.get("attachments") else ""), "Mailbox"])
                refs.append(ref(a))
                interesting.append(a)
                if d.get("attachments") or "deleted" in folder.lower():
                    hl.append(len(rows) - 1)
        deleted = []
        for (sub, sent), (a, folder) in sorted(index_msgs.items(), key=lambda kv: kv[0][1]):
            d = a["data"]
            if "sync issues" in folder.lower() or in_store(d.get("subject"), t(d.get("sent"))):
                continue
            atts = ", ".join(sorted(index_att.get((sub, sent), [])))
            deleted.append(a)
            rows.append([short(d.get("sent")), f"{folder} (not in mailbox)", d.get("from") or "(mailbox owner)",
                         d.get("to") or "", d.get("subject") or "", atts, "Windows Search index"])
            refs.append(ref(a))
            hl.append(len(rows) - 1)
        if not rows:
            return
        rows.sort(key=lambda r: r[0] or "")
        hl = [i for i, r in enumerate(rows) if r[6] != "Mailbox" or r[5] or "deleted" in r[1].lower()]
        corr = {}
        for a in msgs + idx:
            for addr in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", f"{a['data'].get('sender') or a['data'].get('from')} "
                                                                        f"{a['data'].get('to')}"):
                corr[addr.lower()] = corr.get(addr.lower(), 0) + 1
        top = ", ".join(f"{k} ({v})" for k, v in sorted(corr.items(), key=lambda kv: -kv[1])[:6])
        sent = [r for r in rows if "sent" in r[1].lower()]
        desc = (f"The mail store holds {len(msgs)} messages. Listed below are {len(rows)} sent, deleted or attachment-carrying "
                f"messages" + (f", including {len(deleted)} message(s) that the Windows Search index recorded but that are no longer "
                               "in the mailbox (deleted)" if deleted else "") + f". Addresses seen: {top or '-'}.")
        fid = actx.finding(f"E-mail correspondence on {actx.ev_label(eid)}", desc, evidence_id=eid, confidence="high",
                           category="E-mail", ts=rows[0][0] or None, refs=refs[:200],
                           figures=[table_figure("E-mail messages - sent, deleted or with attachments",
                                                 ["Time (UTC)", "Folder", "From", "To", "Subject", "Attachments", "Source"], rows[:30],
                                                 style="table", highlight_rows=hl,
                                                 col_widths=[140, 170, 170, 170, 200, 170, 150],
                                                 callouts=[callout(hl[0], 5 if rows[hl[0]][5] else 1, 1,
                                                                   "Attachment sent" if rows[hl[0]][5] else "Message deleted")]
                                                 if hl else [])],
                           questions=["dlp.other_channels"], tags=["email"])
        for a in interesting + deleted:
            d = a["data"]
            actx.timeline(eid, d.get("sent") or a["ts"], "E-mail", "E-mail sent / deleted / with attachment",
                          f"{d.get('subject')} - {d.get('sender') or d.get('from') or ''} -> {d.get('to') or ''}",
                          ref_kind="artifact", ref_id=a["id"], flagged=True)
        # attachments of sent messages with their destination (documents first; unnamed MIME parts are not files)
        docs = document_extensions()
        sent_files = sorted({(n, r[3], r[0]) for r in sent for n in str(r[5] or "").split(", ")
                             if n and not re.fullmatch(r"attachment(_\d+)?", n, re.I)},
                            key=lambda x: (x[0].rsplit(".", 1)[-1].lower() not in docs, x[2]))
        spoofed = [a for a in msgs if sender_impersonation(a["data"].get("sender"))]
        if spoofed:
            ex = sender_impersonation(spoofed[0]["data"].get("sender"))
            fid2 = actx.finding(f"Sender impersonation in received e-mail on {actx.ev_label(eid)}",
                                f"{len(spoofed)} received message(s) show an e-mail address in the sender's display name that is "
                                f"not the address they came from (for example '{ex[0]}' sent from {ex[1]}) - the pattern of "
                                "business e-mail compromise / CEO fraud.", evidence_id=eid, severity="high", confidence="high",
                                category="E-mail", ts=spoofed[0]["ts"], refs=[ref(a) for a in spoofed],
                                figures=[table_figure("Display name differs from the sender address",
                                                      ["Time (UTC)", "Folder", "Display name", "Real sender address", "Subject",
                                                       "Attachments"],
                                                      [[short(a["ts"]), a["data"].get("folder"), *sender_impersonation(a["data"].get("sender")),
                                                        a["data"].get("subject"), a["data"].get("attachment_names") or ""]
                                                       for a in spoofed[:30]], style="table", highlight_rows=list(range(min(30, len(spoofed)))),
                                                      col_widths=[140, 170, 170, 200, 260, 160])],
                                questions=["dlp.other_channels", "phish.email"], tags=["email", "phishing"], mitre=["T1566", "T1656"])
            actx.answer("dlp.other_channels", INDICATED, f"{actx.ev_label(eid)}: {len(spoofed)} received message(s) with an "
                                                         "impersonated sender address.", [fid2])
        copies = {(a["data"].get("filename"), short(a["ts"])): a["data"].get("local_copies")
                  for a in actx.artifacts("email_attachment", eid) if a["data"].get("local_copies")}
        if sent_files:
            actx.answer("dlp.other_channels", INDICATED, f"{actx.ev_label(eid)}: {len(sent)} sent e-mail(s); files sent: "
                                                         + "; ".join(f"{n} to {to} ({t})" + (f", byte-identical to {copies[(n, t)]}"
                                                                                             if copies.get((n, t)) else "")
                                                                     for n, to, t in sent_files[:5])
                                                         + f" (correspondents: {top}).", [fid])
        elif sent:
            actx.answer("dlp.other_channels", INDICATED, f"{actx.ev_label(eid)}: e-mail correspondence with {top}.", [fid])

    # ------------------------------------------------------------------ cloud sync
    def _cloud(self, actx, eid):
        accts = actx.artifacts("cloud_account", eid)
        self._cloud_sync(actx, eid)
        if not accts:
            return
        folders = [a["data"].get("local_folder") for a in accts if a["data"].get("local_folder")]
        in_sync = [m for m in actx.artifacts("target_match", eid)
                   if any(f and (m["data"].get("location") or "").lower().startswith(f.lower()) for f in folders)]
        rows = [[a["data"].get("service"), a["data"].get("account"), a["data"].get("local_folder"), short(a["ts"])] for a in accts]
        fid = actx.finding(f"Cloud storage clients configured on {actx.ev_label(eid)}" + (" - files of interest in sync folder" if in_sync else ""),
                           f"{len(accts)} cloud storage account(s) / clients were configured" + (
                               f"; {len(in_sync)} file(s) of interest are inside a synchronized folder, so they would have been "
                               "uploaded to the cloud account" if in_sync else "") + ".",
                           evidence_id=eid, severity="high" if in_sync else "low", confidence="medium", category="Cloud",
                           refs=[ref(a) for a in accts] + [ref(m) for m in in_sync],
                           figures=[table_figure("Cloud storage accounts", ["Service", "Account", "Local sync folder", "Config time (UTC)"],
                                                 rows, style="app", col_widths=[200, 250, 330, 150])],
                           questions=["dlp.other_channels"], tags=["cloud"], mitre=["T1567.002"] if in_sync else [])
        if in_sync:
            actx.answer("dlp.other_channels", YES, f"{actx.ev_label(eid)}: files of interest inside a cloud sync folder.", [fid])

    def _cloud_sync(self, actx, eid):
        """Files the sync client uploaded / shared / deleted, from its own logs and databases."""
        items = [a for a in actx.artifacts("cloud_item", eid, order="ts")
                 if a["data"].get("direction") or "upload" in (a["data"].get("event") or "").lower()]
        if not items:
            return
        rows, hl = [], []
        for a in items[:40]:
            d = a["data"]
            rows.append([short(a["ts"]), d.get("service"), d.get("event"), d.get("name"), d.get("path") or "", d.get("account") or ""])
            if d.get("direction") == "upload" and d.get("action") in ("create", "modify", "move"):
                hl.append(len(rows) - 1)
            actx.timeline(eid, a["ts"], d.get("service") or "Cloud", f"Cloud sync: {d.get('event')}", d.get("name"),
                          user=a["user"], ref_kind="artifact", ref_id=a["id"], flagged=d.get("direction") == "upload")
        ups = [a for a in items if a["data"].get("direction") == "upload" and a["data"].get("action") in ("create", "modify", "move")]
        names = sorted({a["data"].get("name") for a in ups if a["data"].get("name")})
        tn = [n for n in names if mentions_target(actx, n)]
        fid = actx.finding(f"Files synchronized to cloud storage from {actx.ev_label(eid)}",
                           f"The {items[0]['data'].get('service')} client recorded {len(items)} completed sync operations; "
                           f"{len(ups)} upload(s) of local files to the cloud account" + (f": {', '.join(names[:8])}" if names else "")
                           + ". Later deletions or sharing changes of the same files are listed with them.",
                           evidence_id=eid, confidence="high", category="Cloud", ts=items[0]["ts"], refs=[ref(a) for a in items[:200]],
                           figures=[table_figure("Cloud client sync log - completed operations",
                                                 ["Time (UTC)", "Service", "Operation", "File", "Local folder", "Account"], rows,
                                                 style="app", highlight_rows=hl, col_widths=[150, 150, 220, 230, 230, 150],
                                                 callouts=[callout(hl[0], 3, 1, "Local file uploaded to the cloud account")] if hl else [])],
                           questions=["dlp.other_channels", "dlp.web"], tags=["cloud"], mitre=["T1567.002"] if ups else [])
        if tn:
            actx.answer("dlp.other_channels", YES, f"{actx.ev_label(eid)}: files of interest uploaded by the cloud sync client "
                                                   f"({', '.join(tn[:4])}).", [fid])
        elif ups:
            actx.answer("dlp.other_channels", INDICATED, f"{actx.ev_label(eid)}: {len(ups)} file upload(s) by the "
                                                         f"{items[0]['data'].get('service')} client ({', '.join(names[:4])}).", [fid])

    # ------------------------------------------------------------------ printing
    def _print(self, actx, eid):
        pr = actx.artifacts("evt_print", eid)
        hits = [p for p in pr if mentions_target(actx, p["data"].get("document")) or actx.in_window(p["ts"])]
        if not hits:
            return
        rows = [[short(p["ts"]), p["data"].get("document"), p["data"].get("user"), p["data"].get("printer"), p["data"].get("pages")]
                for p in hits[:40]]
        tn = [r for r in rows if mentions_target(actx, r[1])]
        fid = actx.finding(f"Print jobs{' of files of interest' if tn else ''} on {actx.ev_label(eid)}",
                           f"{len(hits)} print jobs were logged (PrintService event 307)" + (f", {len(tn)} for files of interest" if tn else "") + ".",
                           evidence_id=eid, severity="high" if tn else "low", confidence="high", category="Printing",
                           refs=[ref(p) for p in hits],
                           figures=[table_figure("Print jobs", ["Time (UTC)", "Document", "User", "Printer", "Pages"], rows,
                                                 style="eventlog", highlight_rows=[i for i, r in enumerate(rows) if r in tn])],
                           questions=["dlp.other_channels"], tags=["print"])
        if tn:
            actx.answer("dlp.other_channels", YES, f"{actx.ev_label(eid)}: files of interest were printed.", [fid])

    # ------------------------------------------------------------------ CD / DVD
    def _optical(self, actx, eid):
        writes = actx.artifacts("evt_optical", eid, order="ts")
        regs = actx.artifacts("burn_registry", eid, order="ts")
        sessions = [a for a in regs if (a["data"].get("item") or "").startswith("IMAPI mastering session")]
        mode = next((a for a in regs if a["data"].get("item") == "DefaultToMastered"), None)
        staged = actx.artifacts("burn_staging", eid, order="ts")
        disc = [a for t in ("lnk", "jumplist") for a in actx.artifacts(t, eid) if a["data"].get("drive_type") == "DRIVE_CDROM"]
        burnbags = [a for a in actx.artifacts("shellbag", eid) if "<cdburn>" in (a["data"].get("path") or "").lower()]
        if not (writes or sessions or staged or disc or burnbags):
            return
        events = []  # (time, source, event, item, user, artifact, is_target)

        def add(a, ts, source, event, item, user=""):
            tgt = bool(mentions_target(actx, item))
            events.append((ts or "", source, event, item or "", user or "", a, tgt))
            actx.timeline(eid, ts, source, event, item, user=user or None, ref_kind="artifact", ref_id=a["id"], flagged=True)

        for a in writes:
            add(a, a["ts"], "System event log (cdrom 133)", "Disc write completed", a["data"].get("device"))
        for a in sessions:
            add(a, a["ts"], "$UsnJrnl", "Disc mastering temporary files", a["data"].get("value"))
        if mode is not None:
            add(mode, mode["ts"], "Registry (CD Burning)", "Burn method last selected", f"DefaultToMastered = {mode['data'].get('value')}",
                mode["data"].get("user"))
        for a in staged:
            d = a["data"]
            add(a, a["ts"], "Burn staging folder" + (" ($UsnJrnl)" if "UsnJrnl" in (d.get("status") or "") else " (MFT)"),
                "File staged for burning", d.get("path") or d.get("name"), d.get("user"))
        for a in burnbags:
            add(a, a["ts"], "Shellbag", "Explorer disc-burning view opened", a["data"].get("path"), a["user"])
        labels = set()
        for a in disc:
            d = a["data"]
            vol = " ".join(x for x in [d.get("volume_label") or "", f"VSN {d.get('volume_serial')}" if d.get("volume_serial") else ""] if x)
            labels.add(vol)
            add(a, d.get("lnk_modified") or d.get("last_accessed") or a["ts"], "Jump list" if a["type"] == "jumplist" else "Shortcut (LNK)",
                "Opened from optical disc" + (f" ({vol})" if vol else ""), d.get("target_path"), a["user"])
        events.sort(key=lambda e: e[0])
        # figure: every write / session / mode record, then staged and opened files up to 40 rows
        key_rows = [e for e in events if e[1].startswith(("System event", "$UsnJrnl", "Registry"))]
        other = [e for e in events if e not in key_rows]
        shown = sorted(key_rows + other[:max(0, 40 - len(key_rows))], key=lambda e: e[0])
        rows = [[short(e[0]), e[1], e[2], e[3], e[4]] for e in shown]
        hl = [i for i, e in enumerate(shown) if e[1].startswith("System event") or e[6]]
        desc = []
        if writes:
            desc.append(f"The cdrom driver logged {len(writes)} completed disc write(s) (System event 133) between "
                        f"{short(writes[0]['ts'])} and {short(writes[-1]['ts'])} UTC.")
        if sessions:
            desc.append(f"$UsnJrnl records {len(sessions)} disc-mastering session(s) (IMAPI DAT/FIL/POST temporary files).")
        if staged:
            desc.append(f"{len(staged)} file(s) were placed in the Explorer burn staging folder "
                        "(AppData\\Local\\Microsoft\\Windows\\Burn\\Burn).")
        if mode is not None:
            desc.append(f"The burn method last selected was {mode['data'].get('value')} (registry key written {short(mode['ts'])} UTC).")
        if burnbags:
            desc.append(f"Shellbags show the Explorer disc-burning view was opened ({len(burnbags)} record(s)).")
        if disc:
            desc.append(f"{len(disc)} shortcut / jump-list record(s) point to files on optical media"
                        + (f" (volume {', '.join(sorted(x for x in labels if x))})" if any(labels) else "") + ".")
        fid = actx.finding(f"CD / DVD burning and optical media on {actx.ev_label(eid)}", " ".join(desc), evidence_id=eid,
                           confidence="high", category="Optical media", refs=[ref(e[5]) for e in events][:300],
                           ts=events[0][0] or None,
                           figures=[table_figure("Disc writing activity and files opened from optical media",
                                                 ["Time (UTC)", "Source", "Event", "Item", "User"], rows, style="app",
                                                 highlight_rows=hl or [0], col_widths=[150, 210, 210, 440, 90],
                                                 callouts=[callout((hl or [0])[0], 2, 1, "Disc write recorded by the cdrom driver"
                                                                   if writes else "Disc burning trace")])],
                           questions=["dlp.other_channels"], tags=["optical"], mitre=["T1052"])
        tn = sorted({e[3] for e in events if e[6]})
        if tn:
            actx.answer("dlp.other_channels", YES, f"{actx.ev_label(eid)}: files of interest were staged for disc burning or "
                                                   f"opened from a disc ({', '.join(tn[:4])}).", [fid])
        else:
            actx.answer("dlp.other_channels", INDICATED, f"{actx.ev_label(eid)}: " + " ".join(desc[:3]), [fid])

    # ------------------------------------------------------------------ archivers / transfer tools
    def _tools(self, actx, eid):
        fams = ("archivers", "transfer_tools")
        rows, refs = [], []
        for typ, field in (("prefetch", "executable"), ("userassist", "program"), ("bam", "path"), ("amcache", "path"),
                           ("evt_process", "process")):
            for a in actx.artifacts(typ, eid):
                if a["data"].get("is_previous_run"):
                    continue
                tools = [t for fam, t in tool_for_exe(a["data"].get(field)) if fam in fams]
                if not tools:
                    continue
                if tools[0] in ("OneDrive client",) and not actx.in_window(a["ts"]):
                    continue
                rows.append([tools[0], typ, a["data"].get(field), short(a["ts"]), a["user"] or ""])
                refs.append(ref(a))
                actx.timeline(eid, a["ts"], typ, f"{tools[0]} executed", str(a["data"].get(field)), user=a["user"], ref_kind="artifact",
                              ref_id=a["id"], flagged=actx.in_window(a["ts"]))
        zips = [m for m in actx.artifacts("target_match", eid) if "ZIP" in (m["data"].get("area") or "")]
        if not rows and not zips:
            return
        rows.sort(key=lambda r: r[3] or "")
        hl = [i for i, r in enumerate(rows) if actx.in_window(r[3] or None)]
        fid = actx.finding(f"Archiving / data transfer tools used on {actx.ev_label(eid)}" + (" - files of interest archived" if zips else ""),
                           (f"Execution evidence exists for {', '.join(sorted({r[0] for r in rows}))}." if rows else "") +
                           (f" {len(zips)} file(s) of interest were found inside archives (data staging)." if zips else ""),
                           evidence_id=eid, severity="high" if zips else "medium", confidence="high", category="Staging",
                           refs=refs + [ref(m) for m in zips],
                           figures=[table_figure("Archiver / transfer tool execution", ["Tool", "Artifact", "Path", "Time (UTC)", "User"],
                                                 rows[:40], style="app", highlight_rows=hl, col_widths=[150, 100, 380, 150, 100])] if rows else [],
                           questions=["dlp.other_channels"], tags=["staging"], mitre=["T1560.001"] if zips else [])
        actx.answer("dlp.other_channels", YES if zips else INDICATED,
                    f"{actx.ev_label(eid)}: " + ("files of interest were archived" if zips else
                                                 f"{', '.join(sorted({r[0] for r in rows}))} executed") + ".", [fid])

    # ------------------------------------------------------------------ memory strings
    def _memory(self, actx, eid):
        ms = [m for m in actx.artifacts("memory_string", eid) if m["data"].get("category") in EXFIL_CATS or
              m["data"].get("reason") in ("target file name", "case keyword", "case domain")]
        if not ms:
            return
        rows = [[m["data"].get("file"), m["data"].get("kind"), m["data"].get("value"), m["data"].get("service") or m["data"].get("reason"),
                 m["data"].get("count"), f"{m['data'].get('first_offset'):#x}"] for m in ms[:40]]
        hl = [i for i, r in enumerate(rows) if re.search(r"attid|compose|upload|attach", r[2] or "", re.I) or
              mentions_target(actx, r[2])]
        fid = actx.finding(f"Web session / file traces in pagefile or hibernation file - {actx.ev_label(eid)}",
                           f"{len(ms)} relevant strings were recovered from memory-backed files (pagefile.sys / hiberfil.sys / "
                           "swapfile.sys), which persist after browser history is cleared: webmail and attachment URLs, cloud "
                           "destinations and paths of files of interest.",
                           evidence_id=eid, severity="medium" if hl else "low", confidence="medium", category="Memory artifacts",
                           refs=[ref(m) for m in ms[:100]],
                           figures=[table_figure("Strings recovered from memory files", ["File", "Kind", "Value", "Service / reason",
                                                                                         "Count", "Offset"], rows, style="app",
                                                 highlight_rows=hl, col_widths=[100, 90, 480, 170, 60, 100],
                                                 callouts=[callout(hl[0], 2, 1, "Attachment / upload URL or file of interest in paged memory")]
                                                 if hl else [])],
                           questions=["dlp.web", "residual"], tags=["memory"])
        if any(re.search(r"attid|attach|upload|compose", r[2] or "", re.I) for r in rows):
            actx.answer("dlp.web", INDICATED, f"{actx.ev_label(eid)}: webmail attachment / upload URLs recovered from paged memory.", [fid])
        actx.answer("residual", YES, f"{actx.ev_label(eid)}: {len(ms)} relevant strings in memory files.", [fid])
