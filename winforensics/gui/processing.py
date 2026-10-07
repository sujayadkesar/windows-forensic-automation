"""Processing page: runs the engine in a background thread and shows live progress."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit, QProgressBar, QSplitter, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core.timeutil import duration_text
from . import theme
from .theme import C
from .widgets import Card, IconButton, label, stat_tile

STATE_ICON = {"pending": ("clock", C["faint"]), "running": ("play", C["accent2"]), "done": ("check", C["ok"]),
              "failed": ("error", C["err"]), "warning": ("warning", C["warn"]), "skipped": ("cancel", C["faint"])}


class EngineThread(QThread):
    event = Signal(dict)

    def __init__(self, case_path: str, phases=("evidence", "analysis", "report")):
        super().__init__()
        self.case_path = case_path
        self.phases = phases
        self.engine = None

    def run(self):
        from ..core.engine import Engine

        self.engine = Engine(self.case_path, listener=self.event.emit)
        try:
            self.engine.run(self.phases)
        except Exception as e:  # pragma: no cover
            self.event.emit({"type": "done", "status": "failed", "error": str(e)})

    def cancel(self):
        if self.engine is not None:
            self.engine.cancel.set()


class ProcessingPage(QWidget):
    finished = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.thread: EngineThread | None = None
        self.started = None
        self.items = {}
        self.groups = {}
        self.counts = {"log": 0, "warning": 0, "error": 0}
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 18)
        root.setSpacing(14)
        head = QHBoxLayout()
        col = QVBoxLayout()
        self.title = label("Processing", "h1")
        self.stage = label("Idle", "muted")
        col.addWidget(self.title)
        col.addWidget(self.stage)
        head.addLayout(col, 1)
        self.cancel_btn = IconButton("cancel", "Cancel job", "danger")
        self.cancel_btn.clicked.connect(self.cancel)
        self.cancel_btn.setEnabled(False)
        head.addWidget(self.cancel_btn)
        root.addLayout(head)
        # big progress card
        card = Card()
        row = QHBoxLayout()
        self.pct = QLabel("0%")
        self.pct.setStyleSheet(f"font-size: 30pt; font-weight: 700; color: {C['title']};")
        row.addWidget(self.pct)
        info = QVBoxLayout()
        self.current = label("", "")
        self.current.setStyleSheet(f"font-size: 10.5pt; color: {C['title']};")
        self.eta = label("", "muted")
        info.addWidget(self.current)
        info.addWidget(self.eta)
        row.addSpacing(16)
        row.addLayout(info, 1)
        card.lay.addLayout(row)
        self.bar = QProgressBar()
        self.bar.setProperty("role", "big")
        self.bar.setRange(0, 1000)
        self.bar.setTextVisible(False)
        card.lay.addWidget(self.bar)
        self.lanes_box = QVBoxLayout()
        card.lay.addLayout(self.lanes_box)
        root.addWidget(card)
        tiles = QHBoxLayout()
        self.t_tasks = stat_tile("Tasks completed", "0 / 0", C["accent2"], "list")
        self.t_records = stat_tile("Records parsed", "0", C["ok"], "database")
        self.t_warn = stat_tile("Warnings", "0", C["warn"], "warning")
        self.t_err = stat_tile("Errors", "0", C["err"], "error")
        for t in (self.t_tasks, self.t_records, self.t_warn, self.t_err):
            tiles.addWidget(t)
        root.addLayout(tiles)
        split = QSplitter(Qt.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["", "Task", "Status", "Records", "Time"])
        self.tree.setRootIsDecorated(True)
        hh = self.tree.header()
        hh.setSectionResizeMode(0, QHeaderView.Fixed)
        hh.resizeSection(0, 34)
        hh.setSectionResizeMode(1, QHeaderView.Interactive)
        hh.resizeSection(1, 380)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.resizeSection(3, 90)
        hh.resizeSection(4, 80)
        hh.setStretchLastSection(False)
        self.tree.setAlternatingRowColors(True)
        split.addWidget(self.tree)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setStyleSheet(f"font-family: Consolas; font-size: 9pt; background: {C['log_bg']}; border:1px solid {C['border']}; border-radius:8px;")
        split.addWidget(self.log)
        split.setSizes([420, 200])
        root.addWidget(split, 1)
        self.tick = QTimer(self)
        self.tick.timeout.connect(self._tick)
        self.last_snapshot = None

    # ------------------------------------------------------------------ control
    def start(self, case_path: str, phases=("evidence", "analysis", "report"), title="Processing"):
        if self.thread is not None and self.thread.isRunning():
            return False
        self.title.setText(title)
        self.tree.clear()
        self.items, self.groups = {}, {}
        self.counts = {"log": 0, "warning": 0, "error": 0}
        self.log.clear()
        for i in reversed(range(self.lanes_box.count())):
            w = self.lanes_box.itemAt(i).widget()
            if w:
                w.deleteLater()
        self.lanes = {}
        self.started = time.time()
        self.thread = EngineThread(case_path, phases)
        self.thread.event.connect(self._on_event)
        self.thread.start()
        self.cancel_btn.setEnabled(True)
        self.tick.start(1000)
        self._append("info", f"Job started: {', '.join(phases)}")
        return True

    def running(self) -> bool:
        return self.thread is not None and self.thread.isRunning()

    def cancel(self):
        if self.thread:
            self.thread.cancel()
            self.cancel_btn.setEnabled(False)
            self.stage.setText("Cancelling - waiting for workers to stop...")

    # ------------------------------------------------------------------ events
    def _on_event(self, ev: dict):
        t = ev.get("type")
        if t == "log":
            self._append(ev["level"], ev["msg"])
        elif t == "progress":
            self.last_snapshot = ev
            self._update(ev)
        elif t == "done":
            self.tick.stop()
            self.cancel_btn.setEnabled(False)
            st = ev.get("status")
            self.stage.setText({"completed": "Completed", "cancelled": "Canceled", "failed": "Failed"}.get(st, st) +
                               f" in {duration_text(ev.get('elapsed', 0))}")
            if st == "completed":
                self.bar.setValue(1000)
                self.pct.setText("100%")
            self._append("info" if st == "completed" else "error", f"Job {st}" + (f": {ev.get('error')}" if ev.get("error") else ""))
            self.finished.emit(ev)

    def _tick(self):
        if self.started:
            el = time.time() - self.started
            snap = self.last_snapshot or {}
            eta = snap.get("eta")
            self.eta.setText(f"Elapsed {duration_text(el)}" + (f"   -   about {duration_text(eta)} remaining" if eta else
                                                                "   -   estimating time remaining..."))

    def _update(self, snap):
        f = snap.get("fraction", 0)
        self.bar.setValue(int(f * 1000))
        self.pct.setText(f"{f * 100:.0f}%")
        self.stage.setText(snap.get("stage", ""))
        tasks = snap.get("tasks", [])
        running = [t for t in tasks if t["state"] == "running"]
        if running:
            r = running[0]
            self.current.setText(f"{r['title']}" + (f"  -  {r['status']}" if r.get("status") else ""))
        done = sum(1 for t in tasks if t["state"] in ("done", "failed", "warning", "skipped"))
        self.t_tasks.value_label.setText(f"{done} / {len(tasks)}")
        self.t_records.value_label.setText(f"{sum(t.get('items') or 0 for t in tasks):,}")
        lanes = {}
        for t in tasks:
            lanes.setdefault(t["group"], []).append(t)
        for gid, ts in lanes.items():
            if gid not in self.lanes:
                w = QWidget()
                hl = QHBoxLayout(w)
                hl.setContentsMargins(0, 2, 0, 0)
                name = QLabel(ts[0]["title"].split(":")[0] if ":" in ts[0]["title"] else gid)
                name.setFixedWidth(200)
                name.setStyleSheet(f"color:{C['muted']};")
                bar = QProgressBar()
                bar.setRange(0, 1000)
                bar.setTextVisible(False)
                bar.setFixedHeight(8)
                st = QLabel("")
                st.setFixedWidth(260)
                st.setStyleSheet(f"color:{C['faint']}; font-size:8.5pt;")
                hl.addWidget(name)
                hl.addWidget(bar, 1)
                hl.addWidget(st)
                self.lanes_box.addWidget(w)
                self.lanes[gid] = (name, bar, st)
            name, bar, st = self.lanes[gid]
            tw = sum(t["weight"] for t in ts) or 1
            dw = sum(t["weight"] * (1 if t["state"] in ("done", "failed", "warning", "skipped") else
                                    t["fraction"] if t["state"] == "running" else 0) for t in ts)
            bar.setValue(int(dw / tw * 1000))
            rn = [t for t in ts if t["state"] == "running"]
            st.setText((rn[0]["title"].split(": ", 1)[-1])[:42] if rn else ("done" if dw >= tw * 0.999 else ""))
        for t in tasks:
            gid = t["group"]
            if gid not in self.groups:
                g = QTreeWidgetItem(self.tree, ["", t["title"].split(":")[0] if ":" in t["title"] else gid, "", "", ""])
                g.setExpanded(True)
                f = g.font(1)
                f.setBold(True)
                g.setFont(1, f)
                self.groups[gid] = g
            it = self.items.get(t["id"])
            if it is None:
                it = QTreeWidgetItem(self.groups[gid], ["", t["title"].split(": ", 1)[-1], "", "", ""])
                it.setFont(0, theme.icon_font(10))
                self.items[t["id"]] = it
            icon, col = STATE_ICON.get(t["state"], STATE_ICON["pending"])
            it.setText(0, theme.glyph(icon))
            it.setForeground(0, QColor(col))
            status = t.get("status") or ""
            if t["state"] == "running" and t.get("fraction"):
                status = f"{t['fraction'] * 100:.0f}%  {status}"
            it.setText(2, status)
            it.setText(3, f"{t['items']:,}" if t.get("items") else "")
            it.setText(4, duration_text(t["elapsed"]) if t.get("elapsed") else "")
            if t["state"] == "failed":
                it.setForeground(2, QColor(C["err"]))
            elif t["state"] == "warning":
                it.setForeground(2, QColor(C["warn"]))

    def _append(self, level, msg):
        if level in ("warning", "error"):
            self.counts[level] += 1
            self.t_warn.value_label.setText(str(self.counts["warning"]))
            self.t_err.value_label.setText(str(self.counts["error"]))
        fmt = QTextCharFormat()
        fmt.setForeground(QColor({"error": C["err"], "warning": C["warn"]}.get(level, C["log_text"])))
        cur = self.log.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertText(f"{time.strftime('%H:%M:%S')}  {level.upper():7}  {msg}\n", fmt)
        self.log.setTextCursor(cur)
        self.log.ensureCursorVisible()
