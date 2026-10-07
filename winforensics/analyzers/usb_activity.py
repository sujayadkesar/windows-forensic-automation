"""Removable media connection history per evidence item."""

from __future__ import annotations

from ..modules._usbutil import serial_key
from .base import NA, NO, YES, Analyzer, analyzer, callout, registry_figure, table_figure
from .common import dlp_serials, ref, short, usb_devices, usb_sessions


@analyzer
class UsbActivityAnalyzer(Analyzer):
    id = "usb_activity"
    title = "Removable media history"
    description = "Every removable device connected to each system, connection sessions, users and DLP serial matching."
    weight = 1.0

    def run(self, actx):
        wanted = dlp_serials(actx)
        any_dev = False
        matched_on = []
        wins = actx.windows_evidence()
        for k, e in enumerate(wins):
            actx.progress(k / max(1, len(wins)), f"USB history {e['label']}")
            eid = e["id"]
            devs = [d for d in usb_devices(actx, eid)]
            if not devs:
                status = actx.coverage_status(eid, "USB device enumeration")
                fid = actx.finding(
                    f"No removable storage history on {actx.ev_label(eid)}",
                    "No USB mass storage, UAS, SD or MTP device records were found in the SYSTEM/SOFTWARE hives, setupapi "
                    "logs or device event logs of this system" + (" (registry hives were not available)." if status in
                                                                  ("absent", "error") else "."),
                    evidence_id=eid, severity="info", confidence="high", category="Removable media",
                    questions=["dlp.usb"])
                actx.answer("dlp.usb", NO, f"{actx.ev_label(eid)}: no removable storage history found.", [fid])
                continue
            any_dev = True
            sessions = usb_sessions(actx, eid)
            for d in devs:
                dd = d["data"]
                sk = serial_key(dd.get("serial"))
                is_match = bool(wanted) and (sk in wanted or any(w and (w in sk or sk in w) for w in wanted if len(w) >= 8))
                in_window = any(actx.in_window(s["data"].get("connected")) for s in sessions
                                if serial_key(s["data"].get("serial")) == sk) or actx.in_window(dd.get("last_connected")) \
                    or actx.in_window(dd.get("connected_after_boot"))
                dev_sessions = [s for s in sessions if serial_key(s["data"].get("serial")) == sk]
                name = " ".join(x for x in [dd.get("vendor"), dd.get("product")] if x) or dd.get("friendly_name") or "Removable device"
                sev = "high" if is_match else ("medium" if in_window else "low")
                rows = [
                    ["Device", name], ["Device class", dd.get("device_class")], ["Serial number", dd.get("serial")],
                    ["VID:PID", dd.get("vid_pid")], ["Friendly name", dd.get("friendly_name")],
                    ["First connected (UTC)", short(dd.get("first_seen"))], ["Last connected (UTC)", short(dd.get("last_connected"))],
                    ["Connected after last reboot (UTC)", short(dd.get("connected_after_boot"))],
                    ["Volume last mounted by user (UTC)", short(dd.get("volume_last_mounted"))],
                    ["Last removed (UTC)", short(dd.get("last_removed"))], ["Connections observed", dd.get("connections")],
                    ["Drive letter", dd.get("drive_letter")], ["Volume label", dd.get("volume_label")],
                    ["Volume serial number", dd.get("volume_serial")], ["Volume GUID", dd.get("volume_guid")],
                    ["Mounted by user(s)", dd.get("users")], ["Capacity", (dd.get("capacity_gb") + " GB") if dd.get("capacity_gb") else ""],
                    ["Sources", dd.get("sources")],
                ]
                rows = [r for r in rows if r[1] not in (None, "", 0)]
                hl = [i for i, r in enumerate(rows) if r[0] in ("Serial number", "Volume serial number", "Mounted by user(s)",
                                                                  "Last connected (UTC)", "Connected after last reboot (UTC)")]
                calls = []
                n = 1
                for i, r in enumerate(rows):
                    if r[0] == "Serial number":
                        calls.append(callout(i, 1, n, "Matches the serial reported in the DLP alert" if is_match else "Device serial number"))
                        n += 1
                    elif r[0] == "Volume serial number":
                        calls.append(callout(i, 1, n, "Links shortcut (LNK) / prefetch records to this device"))
                        n += 1
                    elif r[0] == "Mounted by user(s)":
                        calls.append(callout(i, 1, n, "User profile that mounted the volume (MountPoints2)"))
                        n += 1
                figs = [table_figure(f"{actx.ev_label(eid)} - removable device details", ["Property", "Value"], rows,
                                     style="app", highlight_rows=hl, callouts=calls, col_widths=[230, 520],
                                     caption=f"USB device history reconstructed from {dd.get('sources')}",
                                     window_title="WFA - USB & Removable Media")]
                inst = dd.get("enum_key") or (dd.get("instance_ids") or [""])[0]
                if inst and inst.split("\\")[0].upper() in ("USBSTOR", "SCSI", "USB", "SD"):
                    # only values read from the hive (exact value names); key path as read (CurrentControlSet)
                    vals = [[nm, "REG_SZ", v] for nm, v in (dd.get("enum_values") or {}).items()]
                    calls_r = [callout(i, 2, 1, "Device description") for i, v in enumerate(vals)
                               if v[0] in ("FriendlyName", "DeviceDesc")][:1]
                    hl_r = []
                    for prop, field, meaning in (("0064", "prop_first_install", "First install"),
                                                 ("0066", "prop_last_arrival", "Last arrival (last connection)"),
                                                 ("0067", "prop_last_removal", "Last removal")):
                        if dd.get(field):
                            vals.append([f"Properties\\{{83da6326-97a6-4088-9453-a1923f573b29}}\\{prop}", "DEVPROP FILETIME",
                                         short(dd[field]) + " UTC"])
                            hl_r.append(len(vals) - 1)
                            calls_r.append(callout(len(vals) - 1, 2, len(calls_r) + 1, meaning))
                    has_props = len(hl_r) > 0
                    if vals:
                        figs.append(registry_figure(f"Registry - {inst.split(chr(92))[0]} entry for the device",
                                                    f"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\{inst}", vals, highlight=hl_r,
                                                    last_write=short(dd.get("enum_key_last_written")),
                                                    caption="SYSTEM hive: device enumeration key" +
                                                            (" with its install / arrival / removal properties (UTC)" if has_props else
                                                             " (no arrival / removal properties are recorded on this Windows version)"),
                                                    tree=["SYSTEM", "CurrentControlSet", "Enum", inst.split("\\")[0]] + inst.split("\\")[1:],
                                                    callouts=calls_r))
                    if dd.get("deviceclass_key") and not dd.get("prop_last_arrival"):
                        guid, _, keyname = dd["deviceclass_key"].partition("\\")
                        dvals = [["DeviceInstance", "REG_SZ", dd["deviceclass_instance"]]] if dd.get("deviceclass_instance") else []
                        figs.append(registry_figure(
                            "Registry - device interface key (connected after the last reboot)",
                            f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{guid}\\{keyname}",
                            dvals, highlight=[0] if dvals else [], last_write=short(dd["deviceclass_last_written"]),
                            caption="SYSTEM hive: device interface keys are written when the device is first connected after a "
                                    "reboot; later reconnections during the same boot session do not update them",
                            tree=["SYSTEM", "CurrentControlSet", "Control", "DeviceClasses", guid, keyname[:44] + "..."],
                            callouts=([callout(0, 2, 1, "Device instance (vendor, product, serial)")] if dvals else [])
                            + [callout(-1, 0, 2 if dvals else 1, "Connected after the last reboot")]))
                ev_rows = actx.artifacts("usb_event", eid, where="json_extract(data_json,'$.serial') LIKE ? AND "
                                         "json_extract(data_json,'$.event_id') IS NOT NULL", params=(f"%{dd.get('serial')}%",))
                if ev_rows:
                    er = [[short(r["ts"]), r["data"].get("event_id"), (r["data"].get("channel") or "").replace("Microsoft-Windows-", ""),
                           r["data"].get("event"), r["data"].get("details", "")[:110]] for r in ev_rows[:14]]
                    hl2 = [i for i, r in enumerate(er) if r[3] in ("connected", "disconnected")] or \
                          [i for i, r in enumerate(er) if r[3] in ("driver install",)][:1]
                    figs.append(table_figure("Event logs - device connection events", ["Date / Time (UTC)", "Event ID", "Log",
                                                                                      "Event", "Details"], er,
                                             style="eventlog", highlight_rows=hl2, col_widths=[150, 70, 230, 100, 420],
                                             callouts=[callout(hl2[0], 4, 1, "Disk arrival with VBR (volume serial / label)"
                                                               if er[hl2[0]][3] in ("connected", "disconnected") and
                                                               "Partition" in str(er[hl2[0]][2]) else "Device connected"
                                                               if er[hl2[0]][3] in ("connected", "disconnected") else
                                                               "Driver installed for the device (first connection)")] if hl2 else [],
                                             caption="Device events from: " + ", ".join(sorted({str(r[2]) for r in er if r[2]}))))
                sess_txt = "; ".join(f"{short(s['data'].get('connected'))} - {short(s['data'].get('disconnected'))} "
                                     f"({s['data'].get('duration')})" if s["data"].get("disconnected") else
                                     f"{short(s['data'].get('connected'))} (disconnection time not recorded)"
                                     for s in dev_sessions[:8])
                desc = (f"The device '{name}' with serial number {dd.get('serial')} was connected to {actx.ev_label(eid)}. "
                        f"First connected {actx.t(dd.get('first_seen'))}"
                        + (f"; last connected {actx.t(dd.get('last_connected'))}" if dd.get("last_connected") else "")
                        + (f"; connected after the last reboot {actx.t(dd.get('connected_after_boot'))} (DeviceClasses key - "
                           "later reconnections during the same boot session are not recorded there)"
                           if dd.get("connected_after_boot") and not dd.get("last_connected") else "")
                        + (f"; volume last mounted by a user {actx.t(dd.get('volume_last_mounted'))}"
                           if dd.get("volume_last_mounted") else "")
                        + (f"; last removed {actx.t(dd.get('last_removed'))}" if dd.get("last_removed") else "") + ". "
                        + (f"It was assigned drive letter {dd.get('drive_letter')}. " if dd.get("drive_letter") else "")
                        + (f"Its volume carried label '{dd.get('volume_label')}' and volume serial {dd.get('volume_serial')}. "
                           if dd.get("volume_serial") or dd.get("volume_label") else "")
                        + (f"The volume was mounted by user(s): {dd.get('users')}" + (
                            " (MountPoints2 volume key linked to this device because it was written within seconds of the "
                            "device's arrival)" if "time-correlated" in (dd.get("sources") or "") else "") + ". "
                           if dd.get("users") else "")
                        + (f"Connection sessions: {sess_txt}. " if sess_txt else "")
                        + ("The serial number matches the removable media serial reported in the DLP alert(s)." if is_match else ""))
                fid = actx.finding(f"{'DLP-reported ' if is_match else ''}USB device {name} (S/N {dd.get('serial')}) connected to "
                                   f"{actx.ev_label(eid)}", desc, evidence_id=eid, severity=sev, confidence="high",
                                   category="Removable media", ts=dd.get("last_connected") or dd.get("connected_after_boot") or dd.get("first_seen"),
                                   details={"serial": dd.get("serial"), "volume_serial": dd.get("volume_serial"),
                                            "drive_letter": dd.get("drive_letter"), "users": dd.get("users"), "dlp_match": is_match},
                                   refs=[ref(d)] + [ref(s) for s in dev_sessions[:20]], figures=figs,
                                   questions=["dlp.usb"] + (["dlp.device_match"] if is_match else []),
                                   tags=["usb"] + (["dlp_match"] if is_match else []), mitre=["T1052.001"] if is_match else [])
                actx.answer("dlp.usb", YES, f"{actx.ev_label(eid)}: {name} S/N {dd.get('serial')} "
                                            f"(first connected {short(dd.get('first_seen'))} UTC"
                                            + (f", last connected {short(dd.get('last_connected'))} UTC" if dd.get("last_connected")
                                               else f", connected after the last reboot {short(dd.get('connected_after_boot'))} UTC"
                                               if dd.get("connected_after_boot") else "")
                                            + (f", user {dd.get('users')}" if dd.get("users") else "") + ").", [fid])
                if is_match:
                    matched_on.append((eid, fid))
                    actx.answer("dlp.device_match", YES, f"The DLP-reported device S/N {dd.get('serial')} was connected to "
                                                         f"{actx.ev_label(eid)}.", [fid])
                for s in dev_sessions:
                    sd = s["data"]
                    actx.timeline(eid, sd.get("connected"), "USB", "USB connected",
                                  f"{name} S/N {sd.get('serial')} connected"
                                  + (f" ({' '.join(x for x in [sd.get('drive_letter'), sd.get('volume_label')] if x)})"
                                     if sd.get("drive_letter") or sd.get("volume_label") else ""),
                                  ref_kind="artifact", ref_id=s["id"])
                    if sd.get("disconnected"):
                        actx.timeline(eid, sd.get("disconnected"), "USB", "USB removed", f"{name} S/N {sd.get('serial')} removed",
                                      ref_kind="artifact", ref_id=s["id"])
                if dd.get("first_seen"):
                    actx.timeline(eid, dd.get("first_seen"), "USB", "USB first seen", f"{name} S/N {dd.get('serial')} first connected",
                                  ref_kind="artifact", ref_id=d["id"])
        # sessions overview figure across evidence
        lanes = []
        for e in wins:
            spans = []
            for s in usb_sessions(actx, e["id"]):
                sd = s["data"]
                if sd.get("connected"):
                    spans.append({"start": sd["connected"], "end": sd.get("disconnected") or sd["connected"],
                                  "label": f"{sd.get('product') or 'USB'} {sd.get('serial', '')[-6:]}"})
            if spans:
                lanes.append({"label": actx.ev_label(e["id"]), "spans": spans, "events": []})
        if lanes and len([s for l in lanes for s in l["spans"]]) > 0:
            actx.cache["usb_lanes"] = lanes
        if wanted and not matched_on:
            fid = actx.finding("DLP-reported removable device not observed",
                               f"The removable media serial(s) reported by DLP ({', '.join(sorted(wanted))}) were not found in the "
                               "device history of any examined system. Device history can be removed with clean-up tools; see the "
                               "anti-forensics findings.", severity="medium", confidence="medium", category="Removable media",
                               questions=["dlp.device_match"])
            actx.answer("dlp.device_match", NO, "The DLP-reported serial was not observed on the examined systems.", [fid])
        elif not wanted:
            actx.answer("dlp.device_match", NA, "No removable media serial was supplied.", [])
        if not any_dev and not wins:
            actx.answer("dlp.usb", NA, "No Windows system image was examined.", [])
