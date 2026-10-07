"""Artifact module framework.

An *artifact module* knows how to find and parse one family of artifacts on a
Windows image and emits normalized records through :class:`ModuleContext`.
Modules are discovered automatically: drop a ``.py`` file into
``winforensics/modules`` (or the user plugin folder) containing a class decorated with
``@register``.  See ``docs/writing-modules.md``.
"""

from __future__ import annotations

import importlib
import logging
import os
import pkgutil
import sys
from dataclasses import asdict, dataclass

log = logging.getLogger("winforensics.modules")


@dataclass
class Column:
    name: str
    title: str
    kind: str = "text"  # text | datetime | int | size | bool | path | hash | url | json
    width: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ArtifactType:
    id: str
    title: str
    category: str
    columns: list[Column]
    description: str = ""
    ts_label: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "category": self.category, "description": self.description,
                "ts_label": self.ts_label, "columns": [c.to_dict() for c in self.columns]}


def C(name: str, title: str | None = None, kind: str = "text", width: int = 0) -> Column:
    return Column(name, title or name.replace("_", " ").title(), kind, width)


class ArtifactModule:
    id: str = ""
    title: str = ""
    category: str = "General"
    description: str = ""
    artifact_types: list[ArtifactType] = []
    weight: float = 2.0
    windows_only: bool = True
    # execution order (lower first) and hard dependencies (module ids that must also run, earlier)
    order: int = 50
    requires: list[str] = []
    # locations shown in the coverage matrix (purely descriptive)
    locations: list[str] = []

    def estimate(self, ctx) -> float:
        return self.weight

    def applicable(self, ctx) -> bool:
        return not self.windows_only or ctx.is_windows

    def run(self, ctx) -> None:  # pragma: no cover - interface
        raise NotImplementedError


MODULES: dict[str, type[ArtifactModule]] = {}
ARTIFACT_TYPES: dict[str, ArtifactType] = {}


def register(cls: type[ArtifactModule]) -> type[ArtifactModule]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} has no id")
    MODULES[cls.id] = cls
    for at in cls.artifact_types:
        ARTIFACT_TYPES[at.id] = at
    return cls


_discovered = False


def user_plugin_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "WindowsForensicAutomation", "plugins")


def discover() -> dict[str, type[ArtifactModule]]:
    """Import every module in this package plus user plugins (``%APPDATA%/WindowsForensicAutomation/plugins``)."""
    global _discovered
    if _discovered:
        return MODULES
    import winforensics.modules as pkg
    import winforensics.search as spkg

    for package, prefix in ((pkg, "winforensics.modules"), (spkg, "winforensics.search")):
        for m in pkgutil.iter_modules(package.__path__):
            if m.name.startswith("_") or m.name == "base":
                continue
            try:
                importlib.import_module(f"{prefix}.{m.name}")
            except Exception:
                log.exception("failed to import module %s", m.name)
    pdir = user_plugin_dir()
    if os.path.isdir(pdir):
        if pdir not in sys.path:
            sys.path.insert(0, pdir)
        for fn in sorted(os.listdir(pdir)):
            if fn.endswith(".py") and not fn.startswith("_"):
                try:
                    importlib.import_module(fn[:-3])
                except Exception:
                    log.exception("failed to import plugin %s", fn)
    _discovered = True
    return MODULES
