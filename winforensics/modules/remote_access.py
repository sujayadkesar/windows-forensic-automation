"""Remote access / RMM tooling: footprint of every known tool plus parsing of their connection logs."""

from __future__ import annotations

import re
from datetime import datetime

from ..core.timeutil import db_ts, parse_any
from ..knowledge import remote_access_tools
from .base import ArtifactModule, ArtifactType, C, register

RX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
COMPONENT_STORE = re.compile(r"^\\windows\\(winsxs|servicing|softwaredistribution)\\", re.I)


@register
class RemoteAccessModule(ArtifactModule):
    id = "remote_access"
    title = "Remote access & RMM tools"
    category = "Remote Access"
    description = ("Detects AnyDesk, TeamViewer, ScreenConnect, Splashtop, Atera, RustDesk, NetSupport, VNC and 20+ other "
                   "remote tools from files, services, installs and execution traces, and parses their connection logs.")
    weight = 2.0
    order = 60
    requires = ["filesystem", "execution", "persistence", "system"]
    locations = ["Tool install folders", "Services", "Uninstall keys", "Prefetch / Amcache / BAM", "AnyDesk ad.trace / connection_trace.txt",
                 "TeamViewer Connections_incoming.txt / logs", "ScreenConnect user.config", "RustDesk / Splashtop logs"]
    artifact_types = [
        ArtifactType("rmm_tool", "Remote Access Tools Present", "Remote Access",
                     [C("tool", width=200), C("evidence", width=520), C("first_seen", kind="datetime"), C("last_seen", kind="datetime"),
                      C("installed"), C("executed"), C("service"), C("connections", kind="int")], ts_label="First seen"),
        ArtifactType("rmm_connection", "Remote Access Connections (tool logs)", "Remote Access",
                     [C("tool"), C("direction"), C("start", kind="datetime"), C("end", kind="datetime"), C("remote_id", "Remote ID / Name", width=200),
                      C("remote_ip", "Remote IP"), C("user"), C("details", width=380), C("log_file", width=300)], ts_label="Start"),
    ]

    def run(self, ctx) -> None:
        tools = remote_access_tools()
        found: dict[str, dict] = {}

        def add(tool, kind, desc, ts=None):
            f = found.setdefault(tool, {"evidence": [], "times": [], "installed": False, "executed": False, "service": False,
                                        "connections": 0})
            if len(f["evidence"]) < 40:
                f["evidence"].append(desc)
            if ts:
                f["times"].append(ts)
            if kind == "install":
                f["installed"] = True
            elif kind == "exec":
                f["executed"] = True
            elif kind == "service":
                f["service"] = True

        for i, (tool, spec) in enumerate(tools.items()):
            exes = [e.lower() for e in spec.get("exe", [])]
            paths = [p.lower() for p in spec.get("paths", [])]
            svcs = [s.lower() for s in spec.get("services", [])]
            if exes:
                ph = ",".join("?" * len(exes))
                for r in ctx.db.query(f"SELECT path, volume, si_created, deleted FROM fs_entries WHERE evidence_id=? AND lower(name) IN ({ph})",
                                      (ctx.evidence_id, *exes)):
                    if COMPONENT_STORE.match(r["path"] or ""):
                        continue  # Windows component store copies are not installations
                    add(tool, "file", f"File {'(deleted) ' if r['deleted'] else ''}{ctx.display_path(r['volume'], r['path'])}",
                        r["si_created"])
            for p in paths:
                r = [x for x in ctx.db.query("SELECT path, volume, si_created FROM fs_entries WHERE evidence_id=? AND lower(path) LIKE ? "
                                             "LIMIT 50", (ctx.evidence_id, f"%{p}%")) if not COMPONENT_STORE.match(x["path"] or "")]
                if r:
                    add(tool, "file", f"Folder/file {ctx.display_path(r[0]['volume'], r[0]['path'])}", r[0]["si_created"])
            for typ, field in (("prefetch", "executable"), ("amcache", "path"), ("bam", "path"), ("shimcache", "path"),
                               ("userassist", "program"), ("pca", "path"), ("evt_process", "process")):
                for a in ctx.db.artifacts(ctx.evidence_id, typ, where="json_extract(data_json, '$." + field + "') IS NOT NULL"):
                    v = str(a["data"].get(field) or "").lower()
                    name = re.split(r"[\\/]", v)[-1]
                    if name in exes or any(p in v for p in paths):
                        add(tool, "exec" if typ not in ("shimcache", "amcache") else "file", f"{typ}: {a['data'].get(field)}", a["ts"])
            for a in ctx.db.artifacts(ctx.evidence_id, "service"):
                d = a["data"]
                if d.get("name", "").lower() in svcs or any(p in str(d.get("image_path", "")).lower() for p in paths) or \
                        re.split(r"[\\/]", str(d.get("image_path", "")).strip('"').lower().split('" ')[0])[-1] in exes:
                    add(tool, "service", f"Service {d.get('name')} -> {d.get('image_path')} ({d.get('start')})", a["ts"])
            names = [n.lower() for n in spec.get("names", [])] or                 [p.strip().lower() for p in re.split(r"[/(]", tool) if len(p.strip()) > 3]
            for a in ctx.db.artifacts(ctx.evidence_id, ("installed_program", "amcache_program")):
                nm = str(a["data"].get("name") or "").lower()
                if any(x in nm for x in names):
                    add(tool, "install", f"Installed: {a['data'].get('name')} {a['data'].get('version') or ''}", a["ts"])
            for a in ctx.db.artifacts(ctx.evidence_id, ("evt_service",)):
                d = a["data"]
                img = str(d.get("image_path") or "").lower()
                if any(p in img for p in paths) or str(d.get("service_name", "")).lower() in svcs or \
                        any(e in img for e in exes):
                    add(tool, "service", f"Event {d.get('event_id')}: service {d.get('service_name')} installed ({d.get('image_path')})", a["ts"])
            # logs
            for pattern in spec.get("logs", []) or []:
                for p in ctx.glob("C:/" + pattern):
                    try:
                        text = ctx.read_bytes(p, 64 * 1024 * 1024).decode("utf-8", "replace")
                    except Exception:
                        continue
                    add(tool, "file", f"Log {p}")
                    found[tool]["connections"] += self._parse_log(ctx, tool, str(p), p.name.lower(), text)
            ctx.progress((i + 1) / max(1, len(tools)))
        for tool, f in list(found.items()):
            if tools[tool].get("builtin") and not (f["executed"] or f["service"] or f["connections"]):
                del found[tool]  # part of Windows: only a run or a session is of interest
                continue
            times = sorted(t for t in f["times"] if t)
            ctx.emit("rmm_tool", times[0] if times else None, {
                "tool": tool, "evidence": " | ".join(dict.fromkeys(f["evidence"]))[:3000], "first_seen": times[0] if times else None,
                "last_seen": times[-1] if times else None, "installed": "Yes" if f["installed"] else "",
                "executed": "Yes" if f["executed"] else "", "service": "Yes" if f["service"] else "",
                "connections": f["connections"]}, summary=f"Remote access tool: {tool}", source="multiple", ts_label="First seen",
                tags=["remote_access"])
        ctx.coverage("Remote access tool footprint", f"{len(tools)} tools checked (files, services, installs, execution)",
                     "found" if found else "not_found", len(found), ", ".join(found))
        ctx.coverage("Remote access connection logs", "AnyDesk / TeamViewer / ScreenConnect / RustDesk / Splashtop logs",
                     "found" if ctx.counts.get("rmm_connection") else "not_found", ctx.counts.get("rmm_connection", 0))

    # ------------------------------------------------------------------ log parsers
    def _parse_log(self, ctx, tool, path, name, text) -> int:
        n = 0
        user = ctx.user_for_path(path)
        if tool == "AnyDesk" and "connection_trace" in name:
            # "Incoming    2026-09-14, 05:10    User        123456789    123456789"
            for line in text.splitlines():
                m = re.match(r"\s*(Incoming|Outgoing)\s+(\d{4}-\d{2}-\d{2}),\s*(\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(\S*)", line)
                if m:
                    ts = parse_any(f"{m.group(2)} {m.group(3)}")
                    n += self._emit(ctx, tool, m.group(1).lower(), ts, None, m.group(5), "", user, f"{m.group(4)} {line.strip()}", path)
        elif tool == "AnyDesk":
            for line in text.splitlines():
                if re.search(r"incoming session request|logged in from|remote os|accept request|client-id|external address", line, re.I):
                    m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                    ip = RX_IP.search(line)
                    rid = re.search(r"(?:client-id|from)\s*[:=]?\s*(\d{6,12})", line, re.I)
                    n += self._emit(ctx, tool, "incoming" if "incoming" in line.lower() or "logged in" in line.lower() else "info",
                                    parse_any(m.group(1)) if m else None, None, rid.group(1) if rid else "",
                                    ip.group(0) if ip else "", user, line.strip()[:400], path)
        elif tool == "TeamViewer" and "connections" in name:
            # ID  Name  start  end  user  type  guid  (tab separated, dd-mm-yyyy hh:mm:ss)
            for line in text.splitlines():
                parts = [p for p in line.split("\t") if p != ""]
                if len(parts) >= 4 and re.match(r"\d+", parts[0]):
                    st = _tv_time(parts[2]) if len(parts) > 2 else None
                    en = _tv_time(parts[3]) if len(parts) > 3 else None
                    n += self._emit(ctx, tool, "incoming" if "incoming" in name else "outgoing", st, en,
                                    f"{parts[0]} ({parts[1]})", "", parts[4] if len(parts) > 4 else user,
                                    " ".join(parts[5:6]), path)
        elif tool == "TeamViewer":
            for line in text.splitlines():
                if re.search(r"CPersistentParticipantManager::AddParticipant|punch received|Trying connection to|"
                             r"Connected to|incoming connection|LogonUI", line, re.I):
                    m = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
                    ip = RX_IP.search(line)
                    n += self._emit(ctx, tool, "info", parse_any(m.group(1).replace("/", "-")) if m else None, None, "",
                                    ip.group(0) if ip else "", user, line.strip()[:400], path)
        elif "screenconnect" in tool.lower():
            m = re.search(r"h=([^&\"']+)&p=(\d+)&s=([0-9a-f-]+)", text)
            if m:
                n += self._emit(ctx, tool, "relay", None, None, m.group(3), m.group(1), user, f"Relay {m.group(1)}:{m.group(2)}", path)
        else:
            for line in text.splitlines():
                if re.search(r"connect|session|login|logon|incoming|accepted", line, re.I) and RX_IP.search(line):
                    m = re.search(r"(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2})", line)
                    n += self._emit(ctx, tool, "info", parse_any(m.group(1).replace("/", "-")) if m else None, None, "",
                                    RX_IP.search(line).group(0), user, line.strip()[:400], path)
                    if n > 5000:
                        break
        return n

    def _emit(self, ctx, tool, direction, start, end, rid, ip, user, details, path) -> int:
        ctx.emit("rmm_connection", start, {"tool": tool, "direction": direction, "start": db_ts(start), "end": db_ts(end),
                                           "remote_id": rid, "remote_ip": ip, "user": user, "details": details, "log_file": path},
                 user=user, summary=f"{tool} {direction} {rid or ''} {ip or ''}".strip(), source=path, ts_label="Start",
                 tags=["remote_access"])
        return 1


def _tv_time(s: str):
    for fmt in ("%d-%m-%Y %H:%M:%S", "%m-%d-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return parse_any(s)
