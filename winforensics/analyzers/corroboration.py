"""Corroborate every DLP alert with independent artifacts, and correlate evidence items with each other."""

from __future__ import annotations

from ..modules._usbutil import serial_key
from .base import INDICATED, NA, NO, YES, Analyzer, analyzer, callout, table_figure, timeline_figure
from .common import basename, near, ref, session_for, short, usb_devices, usb_sessions


def _evidence_for_device(actx, device: str):
    dev = (device or "").lower().split(".")[0]
    for e in actx.evidence:
        osd = e.get("os") or {}
        names = {(osd.get("hostname") or "").lower(), (osd.get("computer_name") or "").lower(), (e.get("label") or "").lower()}
        if dev and dev in names:
            return e
    src = actx.by_role("source", "primary")
    return src[0] if src else (actx.windows_evidence() or [None])[0]


@analyzer
class DlpCorroborationAnalyzer(Analyzer):
    id = "dlp_corroboration"
    title = "DLP alert corroboration"
    description = "Checks every DLP alert against independent artifacts on the reported device (and the removable media)."
    weight = 1.0

    def run(self, actx):
        events = actx.inputs.get("dlp_events") or []
        if not events:
            actx.answer("dlp.alert_corroboration", NA, "No DLP alert export was supplied.", [])
            return
        rows, hl, refs = [], [], []
        summary = {"Corroborated": 0, "Partially corroborated": 0, "Not corroborated": 0}
        removable_ev = actx.by_role("removable")
        for i, ev in enumerate(events):
            actx.progress(i / len(events), "Corroborating DLP alerts")
            e = _evidence_for_device(actx, ev.get("device"))
            support = []
            name = (ev.get("file_name") or "").lower()
            t = ev.get("time")
            if e is None:
                rows.append([i + 1, short(t), ev.get("activity"), ev.get("file_name"), ev.get("device"), "device not examined", "Not examined"])
                continue
            eid = e["id"]
            if ev.get("channel") == "removable_media":
                s = session_for(actx, eid, t, pad_minutes=5)
                if s:
                    match = not ev.get("usb_serial") or serial_key(ev["usb_serial"]) in serial_key(s["data"].get("serial")) or \
                        serial_key(s["data"].get("serial")) in serial_key(ev["usb_serial"])
                    support.append(f"USB session {short(s['data'].get('connected'))}-{short(s['data'].get('disconnected'))[11:]}"
                                   + (" (serial matches)" if match and ev.get("usb_serial") else ""))
                    refs.append(ref(s))
                for typ in ("lnk", "jumplist"):
                    for a in actx.artifacts(typ, eid):
                        d = a["data"]
                        if basename(d.get("target_path")).lower() == name and d.get("drive_type") == "DRIVE_REMOVABLE":
                            support.append(f"{typ.upper()} -> {d.get('target_path')} (VSN {d.get('volume_serial')})")
                            refs.append(ref(a))
                            break
                for a in actx.artifacts("target_match", eid):
                    d = a["data"]
                    if (d.get("target") or "").lower() == name and d.get("fs_id"):
                        r = actx.db.query("SELECT si_accessed FROM fs_entries WHERE id=?", (d["fs_id"],))
                        if r and r[0]["si_accessed"] and near(r[0]["si_accessed"], t, 30):
                            support.append(f"source file last accessed {short(r[0]['si_accessed'])}")
                            break
                for re_ in removable_ev:
                    hit = [m for m in actx.artifacts("target_match", re_["id"]) if (m["data"].get("target") or "").lower() == name]
                    if hit:
                        support.append(f"present on {re_['label']} ({hit[0]['data'].get('match')})")
                        refs.append(ref(hit[0]))
            elif ev.get("channel") == "web_upload":
                dest = (ev.get("destination") or "").lower()
                for v in actx.artifacts("web_visit", eid):
                    if near(v["ts"], t, 15) and ((dest and dest in (v["data"].get("url") or "").lower()) or
                                                 (not dest and v["data"].get("category"))):
                        support.append(f"browser visit {short(v['ts'])[11:]} {v['data'].get('service') or v['data'].get('domain')}")
                        refs.append(ref(v))
                        break
                for a in actx.artifacts("lastvisited_mru", eid):
                    if near(a["data"].get("key_last_written"), t, 10) and (a["data"].get("application") or "").lower().endswith(".exe"):
                        support.append(f"{a['data'].get('application')} file dialog in {a['data'].get('folder')}")
                        refs.append(ref(a))
                        break
                for a in actx.artifacts("opensave_mru", eid):
                    if basename(a["data"].get("path")).lower() == name:
                        support.append(f"file selected in dialog ({short(a['data'].get('key_last_written'))[11:]})")
                        refs.append(ref(a))
                        break
                for m in actx.artifacts("memory_string", eid):
                    if dest and dest in (m["data"].get("value") or "").lower():
                        support.append(f"{m['data'].get('file')}: {m['data'].get('value')[:60]}")
                        refs.append(ref(m))
                        break
            else:
                for a in actx.artifacts(("recent_doc", "lnk", "jumplist", "office_mru"), eid):
                    if name and name in str(a["data"]).lower() and near(a["ts"], t, 60):
                        support.append(f"{a['type']} {short(a['ts'])}")
                        refs.append(ref(a))
                        break
            status = "Corroborated" if len(support) >= 2 else ("Partially corroborated" if support else "Not corroborated")
            summary[status] += 1
            rows.append([i + 1, short(t), ev.get("activity"), ev.get("file_name"),
                         ev.get("usb_serial") or ev.get("destination") or ev.get("channel"), "; ".join(support) or "-", status])
            if status != "Not corroborated":
                hl.append(len(rows) - 1)
            actx.timeline(eid, t, "DLP alert", ev.get("activity") or "DLP event",
                          f"{ev.get('file_name')} -> {ev.get('usb_serial') or ev.get('destination') or ''} [{status}]", user=ev.get("user"))
        calls = []
        for n, i in enumerate(hl[:3], start=1):
            calls.append(callout(i, 5, n, "Independent artifacts supporting this alert"))
        fig = table_figure("DLP alert corroboration matrix", ["#", "Alert time (UTC)", "Activity", "File", "Device / destination",
                                                               "Corroborating artifacts", "Assessment"], rows, style="table",
                           highlight_rows=hl, callouts=calls, sheet="DLP corroboration",
                           col_widths=[35, 140, 190, 160, 170, 420, 150])
        total = len(events)
        fid = actx.finding("Corroboration of the DLP alerts",
                           f"Each of the {total} DLP alerts was checked against independent artifacts on the reported device: "
                           f"{summary['Corroborated']} corroborated (two or more independent sources), "
                           f"{summary['Partially corroborated']} partially corroborated (one source), "
                           f"{summary['Not corroborated']} not corroborated by the system artifacts.",
                           severity="high" if summary["Corroborated"] else "medium", confidence="high", category="DLP",
                           refs=refs[:200], figures=[fig], questions=["dlp.alert_corroboration"], tags=["dlp"])
        actx.answer("dlp.alert_corroboration", YES if summary["Corroborated"] == total else (INDICATED if summary["Corroborated"] or
                                                                                            summary["Partially corroborated"] else NO),
                    f"{summary['Corroborated']}/{total} alerts corroborated, {summary['Partially corroborated']} partially, "
                    f"{summary['Not corroborated']} not corroborated.", [fid])


@analyzer
class CrossDeviceAnalyzer(Analyzer):
    id = "cross_device"
    title = "Cross-device correlation"
    description = "Same removable device / same files seen on several evidence items; reconstructs the transfer path."
    weight = 1.0

    def run(self, actx):
        if len(actx.evidence) < 2:
            return
        # same USB device on several systems
        seen: dict[str, list] = {}
        for d in usb_devices(actx):
            seen.setdefault(serial_key(d["data"].get("serial")), []).append(d)
        lanes = []
        for sk, devs in seen.items():
            evs = sorted({d["evidence_id"] for d in devs})
            if len(evs) < 2 or not sk:
                continue
            rows = []
            for d in devs:
                for s in usb_sessions(actx, d["evidence_id"]):
                    if serial_key(s["data"].get("serial")) == sk:
                        rows.append([actx.ev_label(d["evidence_id"]), short(s["data"].get("connected")),
                                     short(s["data"].get("disconnected")), s["data"].get("drive_letter"), s["data"].get("volume_serial"),
                                     d["data"].get("users")])
            rows.sort(key=lambda r: r[1] or "")
            name = f"{devs[0]['data'].get('vendor') or ''} {devs[0]['data'].get('product') or ''}".strip()
            fig = table_figure(f"Device S/N {devs[0]['data'].get('serial')} on multiple systems",
                               ["System", "Connected (UTC)", "Removed (UTC)", "Drive", "Volume serial", "User"], rows, style="table",
                               highlight_rows=list(range(len(rows))), sheet="Cross-device",
                               callouts=[callout(0, 0, 1, "First system"), callout(len(rows) - 1, 0, 2, "Later system")] if len(rows) > 1 else [],
                               col_widths=[220, 150, 150, 60, 110, 120])
            fid = actx.finding(f"The same USB device ({name}, S/N {devs[0]['data'].get('serial')}) was used on {len(evs)} systems",
                               "The removable device with this serial number appears in the device history of: " +
                               ", ".join(actx.ev_label(x) for x in evs) + ". The connection order is: " +
                               " -> ".join(f"{r[0]} at {r[1]}" for r in rows) + ".",
                               severity="high", confidence="high", category="Cross-device", figures=[fig],
                               refs=[ref(d) for d in devs], questions=["dlp.personal_device", "dlp.usb"], tags=["usb", "cross_device"])
            if actx.by_role("personal", "secondary"):
                actx.answer("dlp.personal_device", INDICATED, f"The USB device S/N {devs[0]['data'].get('serial')} was connected to "
                                                              f"{', '.join(actx.ev_label(x) for x in evs)}.", [fid])
        # identical files across evidence items
        hashes: dict[str, list] = {}
        for m in actx.artifacts("target_match"):
            if m["data"].get("sha256"):
                hashes.setdefault(m["data"]["sha256"], []).append(m)
        rows = []
        for h, ms in hashes.items():
            evs = sorted({m["evidence_id"] for m in ms})
            if len(evs) < 2:
                continue
            for m in sorted(ms, key=lambda m: m["data"].get("created") or ""):
                rows.append([m["data"].get("target"), actx.ev_label(m["evidence_id"]), m["data"].get("location"),
                             short(m["data"].get("created")), m["data"].get("area"), h[:16] + "..."])
        if rows:
            fig = table_figure("Identical files of interest across evidence items", ["Target", "System", "Location", "Created (UTC)",
                                                                                     "Area", "SHA-256"], rows[:50], style="table",
                               sheet="Same hash", col_widths=[160, 190, 330, 150, 140, 140],
                               highlight_rows=[i for i, r in enumerate(rows[:50]) if "personal" in r[1].lower() or "home" in r[1].lower()])
            fid = actx.finding("Identical copies of the files of interest exist on several evidence items",
                               f"{len({r[0] for r in rows})} file(s) of interest with identical SHA-256 hashes were found on more than one "
                               "evidence item; the creation times show the order in which the copies were made.",
                               severity="high", confidence="high", category="Cross-device", figures=[fig],
                               questions=["dlp.personal_device"], tags=["cross_device"])
            if actx.by_role("personal", "secondary"):
                actx.answer("dlp.personal_device", YES, "Identical copies (same SHA-256) of files of interest exist on the source "
                                                        "and the personal / secondary device.", [fid])
        # combined session lanes for the timeline figure
        lanes = actx.cache.get("usb_lanes") or []
        if lanes:
            events = []
            for e in actx.evidence:
                for m in actx.artifacts("target_match", e["id"]):
                    if m["ts"]:
                        events.append({"lane": actx.ev_label(e["id"]), "ts": m["ts"], "label": m["data"].get("target"), "kind": "file"})
            for lane in lanes:
                lane["events"] = [x for x in events if x["lane"] == lane["label"]][:20]
            actx.finding("Removable media sessions across systems", "Timeline of USB connection sessions on each examined system "
                         "with the creation times of copies of the files of interest.", severity="info", confidence="high",
                         category="Cross-device", figures=[timeline_figure("USB sessions and file copies", lanes)],
                         questions=["dlp.usb"], tags=["timeline"])
