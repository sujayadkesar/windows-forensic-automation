"""Weighted progress tracking with ETA, shared by the engine, GUI and CLI.

Work is split into *tasks*, each with an estimated cost in "work units"
(roughly seconds of work on a reference machine).  Every task reports its own
fraction; the overall progress is the weighted sum.  When a task's real size is
discovered (e.g. after enumerating the MFT) its weight can be re-estimated; the
overall fraction exposed to the UI never moves backwards.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

PENDING, RUNNING, DONE, SKIPPED, FAILED, WARNING = "pending", "running", "done", "skipped", "failed", "warning"


@dataclass
class Task:
    id: str
    title: str
    weight: float
    group: str = ""
    state: str = PENDING
    fraction: float = 0.0
    status: str = ""
    started: float | None = None
    finished: float | None = None
    items: int = 0
    note: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "weight": self.weight, "group": self.group, "state": self.state,
                "fraction": self.fraction, "status": self.status, "items": self.items, "note": self.note,
                "elapsed": (self.finished or time.time()) - self.started if self.started else 0.0}


@dataclass
class ProgressModel:
    tasks: dict = field(default_factory=dict)
    order: list = field(default_factory=list)
    started: float = field(default_factory=time.time)
    _shown: float = 0.0
    _rate_hist: list = field(default_factory=list)

    def add(self, task: Task) -> Task:
        if task.id not in self.tasks:
            self.order.append(task.id)
        self.tasks[task.id] = task
        return task

    def total_weight(self) -> float:
        return sum(t.weight for t in self.tasks.values()) or 1.0

    def done_weight(self) -> float:
        w = 0.0
        for t in self.tasks.values():
            if t.state in (DONE, SKIPPED, FAILED, WARNING):
                w += t.weight
            elif t.state == RUNNING:
                w += t.weight * max(0.0, min(1.0, t.fraction))
        return w

    def fraction(self) -> float:
        f = self.done_weight() / self.total_weight()
        self._shown = max(self._shown, min(f, 1.0))
        return self._shown

    def eta_seconds(self) -> float | None:
        f = self.fraction()
        elapsed = time.time() - self.started
        if f <= 0.02 or elapsed < 3:
            return None
        rate = f / elapsed
        self._rate_hist.append(rate)
        self._rate_hist = self._rate_hist[-30:]
        avg = sum(self._rate_hist) / len(self._rate_hist)
        return max(0.0, (1.0 - f) / avg) if avg > 0 else None

    def snapshot(self) -> dict:
        return {
            "fraction": self.fraction(),
            "eta": self.eta_seconds(),
            "elapsed": time.time() - self.started,
            "tasks": [self.tasks[i].to_dict() for i in self.order],
        }
