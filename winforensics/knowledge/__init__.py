"""Knowledge base: destination domains, tool families and suspicious patterns.

The data lives in YAML files next to this module so investigators can extend it
without touching code.  Files with the same name in ``%APPDATA%/WindowsForensicAutomation/knowledge``
are merged on top of the built-in ones.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from urllib.parse import urlsplit

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def _user_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "WindowsForensicAutomation", "knowledge")


def _merge(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = _merge(a.get(k), v) if k in a else v
        return out
    if isinstance(a, list) and isinstance(b, list):
        return a + [x for x in b if x not in a]
    return b if b is not None else a


@lru_cache(maxsize=None)
def load(name: str) -> dict:
    with open(os.path.join(HERE, f"{name}.yaml"), encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    user = os.path.join(_user_dir(), f"{name}.yaml")
    if os.path.isfile(user):
        try:
            with open(user, encoding="utf-8") as fh:
                data = _merge(data, yaml.safe_load(fh) or {})
        except Exception:
            pass
    return data


# --------------------------------------------------------------------------- domains
CATEGORY_TITLES = {
    "webmail": "Webmail", "mail_attachment": "Mail attachment", "cloud_storage": "Cloud storage",
    "file_transfer": "File transfer service", "paste_site": "Paste site", "messaging": "Messaging / collaboration",
    "code_hosting": "Code hosting", "ai_assistant": "AI assistant", "job_search": "Job search",
    "remote_access": "Remote access / RMM", "anti_forensics": "Anti-forensics", "software_vendor": "Software vendor",
}

# categories that can receive data from the user (upload destinations)
EXFIL_CATEGORIES = ("webmail", "cloud_storage", "file_transfer", "paste_site", "messaging", "code_hosting", "ai_assistant")


@lru_cache(maxsize=1)
def _domain_index() -> list[tuple[str, str, str, str]]:
    """[(host_suffix, path_prefix, category, service)] longest first."""
    out = []
    for cat, services in load("domains").items():
        for service, entries in (services or {}).items():
            for e in entries or []:
                e = str(e).lower().strip()
                host, _, path = e.partition("/")
                out.append((host, "/" + path if path else "", cat, service))
    out.sort(key=lambda x: (-len(x[0]), -len(x[1])))
    return out


def host_of(url: str) -> str:
    if not url:
        return ""
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


@lru_cache(maxsize=65536)
def classify_url(url: str) -> tuple[str, str] | None:
    """Return (category, service) for a URL or host name, or None."""
    if not url:
        return None
    low = url.lower()
    host = host_of(low)
    if not host:
        return None
    try:
        path = urlsplit(low if "://" in low else "http://" + low).path or "/"
    except ValueError:
        path = "/"
    for suffix, pfx, cat, service in _domain_index():
        if host == suffix or host.endswith("." + suffix) or (not "." in suffix and host.startswith(suffix)):
            if pfx and not path.startswith(pfx):
                continue
            return cat, service
    return None


def category_title(cat: str) -> str:
    return CATEGORY_TITLES.get(cat, cat.replace("_", " ").title())


# --------------------------------------------------------------------------- tools
@lru_cache(maxsize=1)
def _exe_index() -> dict[str, list[tuple[str, str]]]:
    idx: dict[str, list[tuple[str, str]]] = {}
    tools = load("tools")
    for family in TOOL_FAMILIES:
        for name, spec in (tools.get(family) or {}).items():
            for exe in (spec or {}).get("exe", []) or []:
                idx.setdefault(exe.lower(), []).append((family, name))
    for exe in tools.get("lolbins", []) or []:
        idx.setdefault(exe.lower(), []).append(("lolbin", exe))
    return idx


TOOL_FAMILIES = ("remote_access", "archivers", "transfer_tools", "anti_forensics", "hacking_tools")


@lru_cache(maxsize=1)
def _name_index() -> list[tuple[re.Pattern, str, str]]:
    out = []
    tools = load("tools")
    for family in TOOL_FAMILIES:
        for name, spec in (tools.get(family) or {}).items():
            for n in (spec or {}).get("names", []) or []:
                out.append((re.compile(r"(?<![\w@&])" + re.escape(n) + r"(?![\w@&])", re.I), family, name))
    return out


def tool_for_program(display_name: str) -> list[tuple[str, str]]:
    """[(family, tool name)] for an installed-program name (whole-word match of the tool's ``names``)."""
    return [(fam, tool) for rx, fam, tool in _name_index() if rx.search(str(display_name or ""))]


@lru_cache(maxsize=1)
def dual_use_tools() -> frozenset:
    """Tool names reported as programs of interest in every case type."""
    tools = load("tools")
    out = set()
    for family in ("remote_access", "anti_forensics", "hacking_tools"):
        out |= set(tools.get(family) or {})
    out |= {n for n, spec in (tools.get("transfer_tools") or {}).items() if (spec or {}).get("dual_use")}
    return frozenset(out)


def tool_for_exe(path_or_name: str) -> list[tuple[str, str]]:
    """[(family, tool name)] for an executable path / name."""
    if not path_or_name:
        return []
    name = re.split(r"[\\/]", str(path_or_name).strip().strip('"'))[-1].lower()
    name = name.split(" ")[0] if not name.endswith(".exe") and " " in name else name
    return _exe_index().get(name, [])


def remote_access_tools() -> dict:
    return load("tools").get("remote_access", {})


def family_tools(family: str) -> dict:
    return load("tools").get(family, {})


# --------------------------------------------------------------------------- patterns
@lru_cache(maxsize=1)
def _compiled_patterns() -> list[tuple[re.Pattern, dict]]:
    out = []
    for p in load("patterns").get("commands", []):
        try:
            out.append((re.compile(p["regex"], re.I), p))
        except re.error:
            continue
    return out


def score_command(text: str) -> dict:
    """Score a command line / script against the suspicious pattern list."""
    if not text:
        return {"score": 0, "matches": [], "mitre": []}
    t = str(text)
    if len(t) > 200_000:
        t = t[:200_000]
    matches, mitre, score = [], [], 0
    for rx, p in _compiled_patterns():
        if rx.search(t):
            matches.append({"id": p["id"], "title": p["title"], "score": p["score"]})
            score += p["score"]
            for m in p.get("mitre", []):
                if m not in mitre:
                    mitre.append(m)
    return {"score": min(score, 100), "matches": matches, "mitre": mitre}


def clickfix_terms() -> list[str]:
    return [t.lower() for t in load("patterns").get("clickfix_lure_terms", [])]


@lru_cache(maxsize=1)
def document_extensions() -> frozenset:
    return frozenset(e.lower() for e in load("patterns").get("document_extensions", []))


@lru_cache(maxsize=1)
def executable_extensions() -> frozenset:
    return frozenset(e.lower() for e in load("patterns").get("executable_extensions", []))


# --------------------------------------------------------------------------- IOC extraction
RX_URL = re.compile(r"\b(?:https?|ftp|hxxps?)://[^\s\"'<>\x00-\x1f\\^`{|}]{4,2048}", re.I)
RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RX_DOMAIN = re.compile(r"\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I)
RX_EMAIL = re.compile(r"\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,24}\b", re.I)
RX_WINPATH = re.compile(r"\b[a-z]:\\(?:[^\\/:*?\"<>|\r\n\x00]{1,255}\\)*[^\\/:*?\"<>|\r\n\x00]{1,255}", re.I)
RX_REGKEY = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKU|HKEY_USERS)\\[^\s\"'\x00]{3,512}", re.I)
RX_B64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

COMMON_TLDS = {"com", "net", "org", "io", "co", "ru", "cn", "info", "biz", "xyz", "top", "in", "uk", "de", "me", "app", "dev",
               "us", "fr", "nl", "su", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "tv", "ws", "online", "site", "live", "shop",
               "club", "click", "link", "icu", "buzz", "cfd", "sbs", "lol", "zip", "mov", "eu", "jp", "kr", "br", "au", "ca",
               "edu", "gov", "mil", "int", "cloud", "store", "tech", "space", "fun", "pro", "ai", "gg", "ly", "to", "is"}
BENIGN_DOMAINS = ("microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "w3.org", "xmlsoap.org", "verisign.com",
                  "digicert.com", "globalsign.com", "symantec.com", "thawte.com", "sectigo.com", "comodoca.com", "usertrust.com",
                  "entrust.net", "godaddy.com", "letsencrypt.org", "identrust.com", "schemas.microsoft.com", "openxmlformats.org",
                  "purl.org", "adobe.com", "apache.org", "mozilla.org", "google.com", "gstatic.com", "live.com", "office.com")


def extract_iocs(text: str, limit: int = 500) -> dict:
    """Pull URLs, IPs, domains, e-mails, Windows paths and registry keys out of text."""
    out = {"urls": [], "ips": [], "domains": [], "emails": [], "paths": [], "registry": []}
    if not text:
        return out
    t = text if len(text) < 5_000_000 else text[:5_000_000]

    def add(key, v):
        if v not in out[key] and len(out[key]) < limit:
            out[key].append(v)

    for m in RX_URL.finditer(t):
        add("urls", m.group(0).rstrip(".,);]'\""))
    for m in RX_IPV4.finditer(t):
        ip = m.group(0)
        if not ip.startswith(("0.", "127.", "255.")) and ip.count(".") == 3 and not re.match(r"^\d+\.0\.0\.0$", ip):
            add("ips", ip)
    for m in RX_EMAIL.finditer(t):
        add("emails", m.group(0).lower())
    for m in RX_DOMAIN.finditer(t):
        d = m.group(0).lower()
        tld = d.rsplit(".", 1)[-1]
        if tld in COMMON_TLDS and not d.endswith(BENIGN_DOMAINS) and not re.match(r"^[\d.]+$", d):
            if not any(d in e for e in out["emails"]):
                add("domains", d)
    for m in RX_WINPATH.finditer(t):
        add("paths", m.group(0)[:300])
    for m in RX_REGKEY.finditer(t):
        add("registry", m.group(0)[:300])
    return out
