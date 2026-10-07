"""Case container: a folder holding the case definition, database, exports and reports."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime

from .db import CaseDB
from .timeutil import UTC, db_ts

CASE_FILE = "case.json"


@dataclass
class CaseInfo:
    case_number: str = ""
    case_name: str = ""
    examiner: str = ""
    organization: str = ""
    client: str = ""
    description: str = ""
    classification: str = "CONFIDENTIAL"
    display_timezone: str = "UTC"
    profile: str = ""
    created_utc: str = ""
    inputs: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    evidence_plan: list = field(default_factory=list)  # [{path,label,role,notes,bitlocker:[...]}]


class Case:
    def __init__(self, path: str, info: CaseInfo):
        self.path = os.path.abspath(path)
        self.info = info
        self._db: CaseDB | None = None

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, path: str, info: CaseInfo, overwrite: bool = False) -> "Case":
        path = os.path.abspath(path)
        if os.path.exists(os.path.join(path, CASE_FILE)):
            if not overwrite:
                raise FileExistsError(f"A case already exists in {path}")
            # start clean: database and every generated output of the previous case
            for f in ("case.db", "case.db-wal", "case.db-shm", CASE_FILE):
                try:
                    os.remove(os.path.join(path, f))
                except FileNotFoundError:
                    pass
            for sub in ("exports", "figures", "reports", "temp", "Parsed", "Collected", "logs"):
                shutil.rmtree(os.path.join(path, sub), ignore_errors=True)
        os.makedirs(path, exist_ok=True)
        for sub in ("logs", "exports", "reports", "figures", "inputs", "temp"):
            os.makedirs(os.path.join(path, sub), exist_ok=True)
        if not info.created_utc:
            info.created_utc = db_ts(datetime.now(UTC))
        case = cls(path, info)
        case.save()
        case.db  # create schema
        return case

    @classmethod
    def open(cls, path: str) -> "Case":
        path = os.path.abspath(path)
        if os.path.isfile(path):
            path = os.path.dirname(path)
        with open(os.path.join(path, CASE_FILE), encoding="utf-8") as fh:
            data = json.load(fh)
        known = {k: v for k, v in data.items() if k in CaseInfo.__dataclass_fields__}
        return cls(path, CaseInfo(**known))

    def save(self) -> None:
        tmp = os.path.join(self.path, CASE_FILE + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(asdict(self.info), fh, indent=2, default=str)
        os.replace(tmp, os.path.join(self.path, CASE_FILE))

    @property
    def db(self) -> CaseDB:
        if self._db is None:
            self._db = CaseDB(self.db_path)
        return self._db

    @property
    def db_path(self) -> str:
        return os.path.join(self.path, "case.db")

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None

    # ------------------------------------------------------------ paths
    def sub(self, *parts: str) -> str:
        p = os.path.join(self.path, *parts)
        os.makedirs(os.path.dirname(p) if os.path.splitext(p)[1] else p, exist_ok=True)
        return p

    @property
    def title(self) -> str:
        return self.info.case_name or self.info.case_number or os.path.basename(self.path)

    def import_input_file(self, src: str, category: str) -> str:
        """Copy an examiner supplied input (DLP export, samples, rules) into the case folder."""
        dst_dir = self.sub("inputs", category)
        dst = os.path.join(dst_dir, os.path.basename(src))
        if os.path.abspath(src) != os.path.abspath(dst):
            shutil.copy2(src, dst)
        return dst
