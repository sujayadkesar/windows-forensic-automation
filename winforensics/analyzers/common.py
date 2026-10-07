"""Helpers shared by analyzers."""

from __future__ import annotations

import os
import re
from datetime import timedelta

from ..core.timeutil import from_db
from ..knowledge import category_title, classify_url
from ..modules._usbutil import norm_vsn, serial_key

BROWSER_EXES = ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "launcher.exe",
                "browser.exe", "arc.exe", "waterfox.exe", "tor.exe", "whale.exe")
EXFIL_CATS = ("Webmail", "Mail attachment", "Cloud storage", "File transfer service", "Paste site", "Messaging / collaboration",
              "Code hosting", "AI assistant")


def short(ts) -> str:
    if not ts:
        return ""
    return str(ts)[:19]


def basename(p: str) -> str:
    return re.split(r"[\\/]", str(p or ""))[-1]


_RX_MAIL = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")


def sender_impersonation(sender) -> tuple[str, str] | None:
    """(address shown in the display name, real sender address) when the display name of a sender is itself an e-mail
    address that is not the address the message came from: 'alison@m57.biz <tuckgorge@gmail.com>'."""
    s = str(sender or "")
    if "<" not in s:
        return None
    display, real_part = s.split("<", 1)
    shown = [a.lower() for a in _RX_MAIL.findall(display)]
    real = _RX_MAIL.findall(real_part)
    if not shown or not real:
        return None
    real_addr = real[0].lower()
    return (shown[0], real_addr) if real_addr not in shown else None


def eqid(d: dict):
    """Event ID in Vista+ terms: Windows XP / 2003 events (528, 529, 624, ...) carry their modern equivalent."""
    return d.get("equivalent_id") or d.get("event_id")


def targets(actx) -> list[dict]:
    return actx.inputs.get("targets") or []


def target_names(actx) -> set[str]:
    return {(t.get("name") or "").lower() for t in targets(actx) if t.get("name")}


def target_stems(actx) -> set[str]:
    return {os.path.splitext(n)[0] for n in target_names(actx) if len(os.path.splitext(n)[0]) >= 4}


def mentions_target(actx, text: str) -> str | None:
    """Return the target name mentioned in a path / text, if any."""
    low = str(text or "").lower()
    for n in sorted(target_names(actx), key=len, reverse=True):
        if n and n in low:
            return n
    for s in sorted(target_stems(actx), key=len, reverse=True):
        if s and s in low:
            return s
    return None


def dlp_serials(actx) -> set[str]:
    return {serial_key(s) for s in actx.inputs.get("usb_serials") or [] if s}


def usb_devices(actx, evidence_id=None) -> list[dict]:
    return actx.artifacts("usb_device", evidence_id)


def usb_sessions(actx, evidence_id) -> list[dict]:
    return actx.artifacts("usb_session", evidence_id)


def session_for(actx, evidence_id, ts, pad_minutes=2):
    """The USB session (if any) covering timestamp ``ts`` on an evidence item."""
    t = from_db(ts) if isinstance(ts, str) else ts
    if t is None:
        return None
    for s in usb_sessions(actx, evidence_id):
        d = s["data"]
        start = from_db(d.get("connected"))
        end = from_db(d.get("disconnected"))
        if start and start - timedelta(minutes=pad_minutes) <= t and (end is None or t <= end + timedelta(minutes=pad_minutes)):
            return s
    return None


def removable_vsns(actx) -> dict[str, dict]:
    """Volume serial -> description, from USB device history and from removable media evidence."""
    out: dict[str, dict] = {}
    for d in usb_devices(actx):
        for v in d["data"].get("volume_serials") or []:
            out.setdefault(norm_vsn(v), {"serial": d["data"].get("serial"), "label": d["data"].get("volume_label"),
                                         "device": f"{d['data'].get('vendor') or ''} {d['data'].get('product') or ''}".strip(),
                                         "evidence_id": d["evidence_id"], "source": "USB device history"})
    for e in actx.evidence:
        for v in actx.db.volumes(e["id"]):
            if v.get("fs") and v.get("serial") and (e.get("role") == "removable" or not (v.get("letter") or "").startswith("C")):
                vsn = norm_vsn(v["serial"][-8:])
                if vsn:
                    out.setdefault(vsn, {"serial": None, "label": v.get("label"), "device": f"{e['label']} {v['name']}",
                                         "evidence_id": e["id"], "source": "removable evidence volume"})
    return out


def classify(url: str) -> tuple[str, str]:
    c = classify_url(url or "")
    return (category_title(c[0]), c[1]) if c else ("", "")


def within(ts, start, end, pad_minutes=0) -> bool:
    t = from_db(ts) if isinstance(ts, str) else ts
    if t is None:
        return False
    s = from_db(start) if isinstance(start, str) else start
    e = from_db(end) if isinstance(end, str) else end
    if s and t < s - timedelta(minutes=pad_minutes):
        return False
    if e and t > e + timedelta(minutes=pad_minutes):
        return False
    return True


def near(ts_a, ts_b, minutes: float) -> bool:
    a = from_db(ts_a) if isinstance(ts_a, str) else ts_a
    b = from_db(ts_b) if isinstance(ts_b, str) else ts_b
    if a is None or b is None:
        return False
    return abs((a - b).total_seconds()) <= minutes * 60


def ref(a: dict) -> dict:
    return {"kind": "artifact", "id": a["id"], "type": a["type"], "evidence_id": a["evidence_id"], "source": a.get("source")}


def drive_letter_of(path: str) -> str:
    m = re.match(r"^([A-Za-z]):", str(path or ""))
    return m.group(1).upper() + ":" if m else ""


def fmt_size(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


# --------------------------------------------------------------------------- paths of programs
from ..core.paths import app_root, command_paths, norm_path  # noqa: E402,F401  (re-exported for analyzers)


def installed_roots(actx, evidence_id) -> set[str]:
    """Application folders of every registered installed program (machine and per-user Uninstall keys): install
    location, uninstaller and icon paths, reduced to the application's top folder."""
    key = f"_roots_{evidence_id}"
    if key not in actx.cache:
        roots = set()
        for a in actx.artifacts("installed_program", evidence_id):
            d = a["data"]
            paths = [str(d.get("install_location") or "").strip().strip('"').rstrip("\\") + "\\x"] if d.get("install_location") else []
            for v in (d.get("display_icon"), d.get("uninstall")):
                if v and not str(v).lower().lstrip('"').startswith("msiexec"):
                    paths += command_paths(str(v).split(",")[0])[:1]
            roots |= {r for r in map(app_root, paths) if r}
        actx.cache[key] = roots
    return actx.cache[key]


def in_installed_program(actx, evidence_id, path) -> bool:
    p = norm_path(path)
    return any(p == r or p.startswith(r + "\\") for r in installed_roots(actx, evidence_id))
