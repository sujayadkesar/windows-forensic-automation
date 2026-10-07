"""Path helpers shared by modules and analyzers: normalized comparison, the program a command starts, application roots."""

from __future__ import annotations

import re


# folders under ProgramData that only the system / installers can write: Defender's platform, the WiX / MSI package cache
PROTECTED_DATA = re.compile(r"\\programdata\\microsoft\\windows defender( advanced threat protection)?\\|"
                            r"\\programdata\\package cache\\", re.I)


def basename(p: str) -> str:
    return re.split(r"[\\/]", str(p or ""))[-1]


# --------------------------------------------------------------------------- paths of programs
_RX_PATH_PREFIX = re.compile(r"^(?:\\\\\?\\|\\\?\?\\)?(?:[a-z]:|\\volume\{[^}]*\}|\\device\\harddiskvolume\d+|%systemdrive%)", re.I)
_ENV_PREFIX = {"%systemroot%": "\\windows", "%windir%": "\\windows", "\\systemroot": "\\windows",
               "%programfiles%": "\\program files", "%programdata%": "\\programdata",
               "%programfiles(x86)%": "\\program files (x86)"}
_RX_EXE_IN_CMD = re.compile(r"""^\s*(?:"([^"]+)"|'([^']+)'|(.+?\.(?:exe|com|scr|bat|cmd|pif|dll|cpl|vbs|js|ps1|hta|msi))(?=\s|$|,)|(\S+))""",
                            re.I)
_RX_ARG_PATH = re.compile(r"""(?:[a-z]:|%\w+%|\\\\)[^"',|<>\r\n]*?\.(?:ps1|vbs|vbe|js|jse|wsf|hta|dll|bat|cmd|exe|scr)\b""", re.I)
INTERPRETERS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                "regsvr32.exe", "msiexec.exe", "conhost.exe", "explorer.exe")


def norm_path(p) -> str:
    r"""Lower-case path without drive letter / volume / device prefix, so C:\x, \VOLUME{..}\X and
    \Device\HarddiskVolume3\x compare equal."""
    s = str(p or "").strip().strip('"').replace("/", "\\").lower()
    for k, v in _ENV_PREFIX.items():
        if s.startswith(k):
            s = v + s[len(k):]
            break
    s = _RX_PATH_PREFIX.sub("", s)
    if s.startswith("system32\\"):
        s = "\\windows\\" + s
    return s if s.startswith("\\") or not s else "\\" + s


def command_paths(cmd) -> list[str]:
    """Executable of a command line / service image path first, then any script or library path in its arguments
    (an interpreter running a script from a user folder is judged by the script)."""
    s = str(cmd or "").strip()
    if not s:
        return []
    m = _RX_EXE_IN_CMD.match(s)
    exe = next((g for g in m.groups() if g), "") if m else ""
    out = [exe] if exe else []
    if basename(exe).lower() in INTERPRETERS:
        out += _RX_ARG_PATH.findall(s[m.end():])
    return out


_RX_APP_ROOT = re.compile(r"^(\\users\\[^\\]+\\appdata\\(?:local\\programs|local\\microsoft|roaming\\microsoft|local|roaming)\\[^\\]+)\\|"
                          r"^(\\documents and settings\\[^\\]+\\(?:local settings\\application data|application data)"
                          r"(?:\\microsoft)?\\[^\\]+)\\|"
                          r"^(\\program files(?: \(x86\))?\\common files\\[^\\]+)\\|^(\\programdata\\[^\\]+)\\|"
                          r"^(\\program files(?: \(x86\))?\\[^\\]+)\\", re.I)
_NOT_APP = ("microsoft", "programs", "temp", "packages", "common files", "windowsapps", "crashdumps", "microsoft help", "windows")


def app_root(path) -> str:
    r"""Top folder of an application installation under Program Files, ProgramData or a profile's AppData:
    C:\Users\u\AppData\Local\Microsoft\OneDrive\24.1\x.exe -> \users\u\appdata\local\microsoft\onedrive.
    Paths anywhere else (Windows, Downloads, Desktop, ...) have no application root ("")."""
    m = _RX_APP_ROOT.match(norm_path(path))
    if not m:
        return ""
    root = next(g for g in m.groups() if g)
    return "" if root.rsplit("\\", 1)[-1] in _NOT_APP else root
