"""Investigation profiles.

A profile is a YAML file describing one investigation scenario: which evidence
roles exist, which case inputs the examiner can provide, which artifact modules
and search engines run, which analyzers correlate the results, which
investigative questions the report must answer and how the report is titled.

Built-in profiles live next to this file; additional ones can be dropped into
``%APPDATA%/WindowsForensicAutomation/profiles``.  See ``docs/writing-profiles.md``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def user_profile_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "WindowsForensicAutomation", "profiles")


@dataclass
class Profile:
    id: str
    name: str
    category: str = "General"
    icon: str = "triage"
    summary: str = ""
    description: str = ""
    when_to_use: list = field(default_factory=list)
    evidence_roles: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    modules: list | str = "all"
    options: dict = field(default_factory=dict)
    analyzers: list = field(default_factory=list)
    questions: list = field(default_factory=list)
    report: dict = field(default_factory=dict)
    path: str = ""
    order: int = 50

    @property
    def title(self) -> str:
        return self.report.get("title") or f"{self.name} - Forensic Examination Report"

    def role(self, role_id: str) -> dict:
        for r in self.evidence_roles:
            if r.get("id") == role_id:
                return r
        return {"id": role_id, "label": role_id.title()}

    def input_spec(self, input_id: str) -> dict | None:
        for i in self.inputs:
            if i.get("id") == input_id:
                return i
        return None


def _load(path: str) -> Profile:
    with open(path, encoding="utf-8") as fh:
        d = yaml.safe_load(fh) or {}
    known = {k: v for k, v in d.items() if k in Profile.__dataclass_fields__}
    p = Profile(**known)
    p.path = path
    return p


_cache: dict[str, Profile] | None = None


def load_profiles(reload: bool = False) -> dict[str, Profile]:
    global _cache
    if _cache is not None and not reload:
        return _cache
    out: dict[str, Profile] = {}
    for folder in (HERE, user_profile_dir()):
        if not os.path.isdir(folder):
            continue
        for fn in sorted(os.listdir(folder)):
            if fn.endswith((".yaml", ".yml")):
                try:
                    p = _load(os.path.join(folder, fn))
                    out[p.id] = p
                except Exception as e:  # pragma: no cover - surfaced in UI
                    out[f"error:{fn}"] = Profile(id=f"error:{fn}", name=f"Broken profile {fn}", description=str(e))
    _cache = dict(sorted(out.items(), key=lambda kv: (kv[1].order, kv[1].name)))
    return _cache


def get_profile(pid: str) -> Profile:
    profiles = load_profiles()
    if pid not in profiles:
        raise KeyError(f"Unknown profile '{pid}'")
    return profiles[pid]
