"""Case creation helpers shared by the GUI wizard and the CLI."""

from __future__ import annotations

import os

from .case import Case, CaseInfo
from .evidence import FORMATS, detect_format, probe, segment_files
from .inputs import load_dlp_export, load_hash_list, reference_file


def build_inputs(case: Case, *, dlp_exports=(), hash_lists=(), reference_paths=(), targets=(), usb_serials=(), users=(),
                 window=None, domains=(), keywords=(), background="", iocs=None, samples=(), yara_rules=(), extra=None,
                 dlp_mappings: dict | None = None) -> dict:
    """Copy examiner supplied files into the case and build the raw inputs structure."""
    raw: dict = {"dlp_exports": [], "targets": list(targets or []), "reference_files": [], "usb_serials": list(usb_serials or []),
                 "suspect_users": list(users or []), "time_window": window or {}, "domains": list(domains or []),
                 "keywords": list(keywords or []), "background": background or "", "iocs": iocs or {}, "samples": [],
                 "yara_rules": [], "extra": extra or {}}
    for p in dlp_exports or []:
        local = case.import_input_file(p, "dlp")
        raw["dlp_exports"].append(load_dlp_export(local, (dlp_mappings or {}).get(p)))
    for p in hash_lists or []:
        local = case.import_input_file(p, "hashes")
        raw["targets"] += load_hash_list(local)
    refs = []
    for p in reference_paths or []:
        if os.path.isdir(p):
            refs += [os.path.join(p, f) for f in sorted(os.listdir(p)) if os.path.isfile(os.path.join(p, f))]
        else:
            refs.append(p)
    for p in refs:
        local = case.import_input_file(p, "reference")
        raw["reference_files"].append(reference_file(local))
    for p in yara_rules or []:
        raw["yara_rules"].append(case.import_input_file(p, "yara"))
    raw["sample_reports"] = []
    if samples:
        from ..malware.static import analyze_file

        rules = builtin_yara() + raw["yara_rules"]
        for p in samples:
            local = case.import_input_file(p, "samples")
            raw["samples"].append(local)
            try:
                rep = analyze_file(local, rules)
                rep.pop("strings_sample", None)
                for ch in rep.get("children", []):
                    ch.pop("strings_sample", None)
                raw["sample_reports"].append(rep)
            except Exception as e:  # pragma: no cover
                raw["sample_reports"].append({"name": os.path.basename(p), "error": str(e)})
    return raw


def builtin_yara() -> list[str]:
    import glob

    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledge", "yara")
    return sorted(glob.glob(os.path.join(here, "*.yar")))


def add_evidence(case: Case, path: str, label: str, role: str, notes: str = "", keys: list | None = None, probe_info: dict | None = None,
                 options: dict | None = None) -> int:
    info = probe_info or probe(path, keys)
    fmt = info.get("format") or detect_format(path)
    size = info.get("file_size") or sum(os.path.getsize(f) for f in segment_files(path)) if fmt != "directory" else 0
    opts = dict(options or {})
    if keys:
        opts["keys"] = keys
    eid = case.db.add_evidence(label, role, os.path.abspath(path), fmt, size, info, notes, opts)
    case.db.update_evidence(eid, os=info.get("os") or {})
    return eid


def create_case(path: str, info: CaseInfo, evidence: list[dict], raw_inputs_kwargs: dict, overwrite: bool = False) -> Case:
    """evidence: [{path, label, role, notes, keys}]"""
    case = Case.create(path, info, overwrite=overwrite)
    for e in evidence:
        add_evidence(case, e["path"], e.get("label") or os.path.basename(e["path"]), e.get("role") or "other",
                     e.get("notes", ""), e.get("keys"), e.get("probe"), e.get("options"))
    case.info.inputs = build_inputs(case, **raw_inputs_kwargs)
    case.info.evidence_plan = [{k: v for k, v in e.items() if k != "probe"} for e in evidence]
    case.save()
    return case


def format_label(fmt: str) -> str:
    return FORMATS.get(fmt, fmt)
