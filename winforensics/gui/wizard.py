"""New case wizard."""

from __future__ import annotations

import os
import re
from datetime import datetime

from PySide6.QtCore import QDateTime, QObject, QRunnable, Qt, QThreadPool, QTimeZone, Signal
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDateTimeEdit, QDialog,
                               QFileDialog, QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QListWidget, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton,
                               QScrollArea, QSpinBox, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ..core.evidence import IMAGE_EXTENSIONS, probe
from ..profiles import load_profiles
from . import theme
from .theme import C
from .widgets import Card, IconButton, chip, icon_label, label

TIMEZONES = ["UTC", "Asia/Kolkata", "Asia/Dubai", "Asia/Singapore", "Asia/Tokyo", "Asia/Shanghai", "Europe/London", "Europe/Berlin",
             "Europe/Paris", "Europe/Amsterdam", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
             "America/Sao_Paulo", "Australia/Sydney", "Africa/Johannesburg"]
ROLE_DEFAULT = [{"id": "source", "label": "Primary system"}, {"id": "personal", "label": "Secondary system"},
                {"id": "removable", "label": "Removable media"}, {"id": "other", "label": "Other"}]


# ============================================================================ background probing
class _ProbeSignals(QObject):
    done = Signal(int, dict)


class ProbeTask(QRunnable):
    def __init__(self, row_id: int, path: str, keys=None):
        super().__init__()
        self.row_id, self.path, self.keys = row_id, path, keys
        self.signals = _ProbeSignals()

    def run(self):
        try:
            res = probe(self.path, self.keys)
        except Exception as e:
            res = {"error": f"{type(e).__name__}: {e}", "path": self.path}
        self.signals.done.emit(self.row_id, res)


# ============================================================================ input widgets
class StringList(QPlainTextEdit):
    def __init__(self, placeholder=""):
        super().__init__()
        self.setPlaceholderText(placeholder or "One per line")
        self.setFixedHeight(84)

    def value(self):
        return [x.strip() for x in self.toPlainText().splitlines() if x.strip()]


class TimeWindow(QWidget):
    def __init__(self):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.enabled = QCheckBox("Restrict to")
        self.start = QDateTimeEdit()
        self.end = QDateTimeEdit()
        now = QDateTime.currentDateTimeUtc()
        for w, dt in ((self.start, now.addDays(-7)), (self.end, now)):
            w.setTimeZone(QTimeZone.utc())
            w.setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'")
            w.setCalendarPopup(True)
            w.setDateTime(dt)
            w.setEnabled(False)
        self.enabled.toggled.connect(self.start.setEnabled)
        self.enabled.toggled.connect(self.end.setEnabled)
        lay.addWidget(self.enabled)
        lay.addWidget(self.start)
        lay.addWidget(QLabel("to"))
        lay.addWidget(self.end)
        lay.addStretch()

    def value(self):
        if not self.enabled.isChecked():
            return {}
        return {"start": self.start.dateTime().toUTC().toString("yyyy-MM-ddTHH:mm:ss") + "Z",
                "end": self.end.dateTime().toUTC().toString("yyyy-MM-ddTHH:mm:ss") + "Z"}


class FileList(QWidget):
    def __init__(self, folders=False, filt="All files (*.*)"):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.setFixedHeight(90)
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        row = QHBoxLayout()
        add = IconButton("add", "Add files")
        add.clicked.connect(lambda: self._add(QFileDialog.getOpenFileNames(self, "Select files", "", filt)[0]))
        row.addWidget(add)
        if folders:
            addf = IconButton("folder", "Add folder")
            addf.clicked.connect(lambda: self._add([QFileDialog.getExistingDirectory(self, "Select folder")]))
            row.addWidget(addf)
        rm = IconButton("delete", "Remove")
        rm.clicked.connect(lambda: [self.list.takeItem(self.list.row(i)) for i in self.list.selectedItems()])
        row.addWidget(rm)
        row.addStretch()
        lay.addWidget(self.list)
        lay.addLayout(row)

    def _add(self, paths):
        for p in paths:
            if p:
                self.list.addItem(p)

    def value(self):
        return [self.list.item(i).text() for i in range(self.list.count())]


class TargetTable(QWidget):
    COLS = ["File name", "Size (bytes)", "MD5", "SHA-1", "SHA-256", "Original path"]
    KEYS = ["name", "size", "md5", "sha1", "sha256", "path"]

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.t = QTableWidget(0, len(self.COLS))
        self.t.setHorizontalHeaderLabels(self.COLS)
        self.t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.t.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate((170, 90, 120, 120, 160)):
            self.t.setColumnWidth(i, w)
        self.t.setFixedHeight(150)
        self.t.verticalHeader().hide()
        row = QHBoxLayout()
        for icon, text, fn in (("add", "Add row", self.add_row), ("copy", "Paste names / hashes", self.paste),
                               ("open", "Import hash list", self.import_list), ("delete", "Remove", self.remove)):
            b = IconButton(icon, text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        self.hashlists: list[str] = []
        lay.addWidget(self.t)
        lay.addLayout(row)

    def add_row(self, values: dict | None = None):
        r = self.t.rowCount()
        self.t.insertRow(r)
        for i, k in enumerate(self.KEYS):
            self.t.setItem(r, i, QTableWidgetItem(str((values or {}).get(k) or "")))

    def paste(self):
        text = QApplication.clipboard().text()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            vals: dict = {}
            for h in re.findall(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b", line):
                vals[{32: "md5", 40: "sha1", 64: "sha256"}[len(h)]] = h.lower()
            rest = re.sub(r"\b[0-9a-fA-F]{32,64}\b", "", line).strip(" \t,;|")
            if rest:
                vals["name"] = re.split(r"[\\/]", rest)[-1]
                if "\\" in rest or "/" in rest:
                    vals["path"] = rest
            self.add_row(vals)

    def import_list(self):
        p, _ = QFileDialog.getOpenFileName(self, "Import hash list", "", "Hash lists (*.txt *.csv *.json *.xlsx *.md5 *.sha256);;All (*.*)")
        if not p:
            return
        from ..core.inputs import load_hash_list

        try:
            for t in load_hash_list(p):
                self.add_row(t)
        except Exception as e:
            QMessageBox.warning(self, "Import failed", str(e))

    def remove(self):
        for r in sorted({i.row() for i in self.t.selectedIndexes()}, reverse=True):
            self.t.removeRow(r)

    def value(self):
        out = []
        for r in range(self.t.rowCount()):
            d = {}
            for i, k in enumerate(self.KEYS):
                it = self.t.item(r, i)
                v = it.text().strip() if it else ""
                if v:
                    d[k] = v
            if d:
                d["source"] = "examiner"
                out.append(d)
        return out


class DlpExportWidget(QWidget):
    FIELDS = [("time", "Time"), ("activity", "Activity"), ("user", "User"), ("device", "Device"), ("file_name", "File name"),
              ("file_path", "File path"), ("size", "Size"), ("sha256", "SHA-256"), ("sha1", "SHA-1"), ("md5", "MD5"),
              ("usb_serial", "USB serial"), ("destination", "Destination")]

    def __init__(self):
        super().__init__()
        self.exports: dict[str, dict] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        self.combo = QComboBox()
        self.combo.setMinimumWidth(360)
        self.combo.currentTextChanged.connect(self._show)
        add = IconButton("add", "Load export...")
        add.clicked.connect(self._load)
        rm = IconButton("delete", "Remove")
        rm.clicked.connect(self._remove)
        top.addWidget(self.combo, 1)
        top.addWidget(add)
        top.addWidget(rm)
        lay.addLayout(top)
        self.mapbox = QGroupBox("Column mapping (auto-detected - adjust if needed)")
        g = QGridLayout(self.mapbox)
        self.maps: dict[str, QComboBox] = {}
        for i, (k, t) in enumerate(self.FIELDS):
            cb = QComboBox()
            cb.currentTextChanged.connect(self._remap)
            self.maps[k] = cb
            g.addWidget(QLabel(t), i // 3, (i % 3) * 2)
            g.addWidget(cb, i // 3, (i % 3) * 2 + 1)
        lay.addWidget(self.mapbox)
        self.preview = QTableWidget(0, 6)
        self.preview.setHorizontalHeaderLabels(["Time (UTC)", "Activity", "User", "Device", "File", "USB / destination"])
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.verticalHeader().hide()
        self.preview.setFixedHeight(150)
        self.status = label("", "faint")
        lay.addWidget(self.preview)
        lay.addWidget(self.status)
        self.mapbox.setVisible(False)
        self._busy = False

    def _load(self):
        p, _ = QFileDialog.getOpenFileName(self, "DLP alert export", "", "Exports (*.csv *.tsv *.xlsx *.json *.txt);;All (*.*)")
        if not p:
            return
        from ..core.inputs import load_dlp_export

        try:
            d = load_dlp_export(p)
        except Exception as e:
            QMessageBox.warning(self, "Cannot read export", f"{e}")
            return
        self.exports[p] = d
        self.combo.addItem(p)
        self.combo.setCurrentText(p)

    def _remove(self):
        p = self.combo.currentText()
        self.exports.pop(p, None)
        self.combo.removeItem(self.combo.currentIndex())

    def _show(self, p):
        d = self.exports.get(p)
        self.mapbox.setVisible(bool(d))
        if not d:
            self.preview.setRowCount(0)
            return
        self._busy = True
        for k, cb in self.maps.items():
            cb.clear()
            cb.addItems(["(none)"] + d["headers"])
            cb.setCurrentText(d["mapping"].get(k, "(none)"))
        self._busy = False
        self._fill(d)

    def _remap(self):
        if self._busy:
            return
        p = self.combo.currentText()
        if p not in self.exports:
            return
        from ..core.inputs import load_dlp_export

        mapping = {k: cb.currentText() for k, cb in self.maps.items() if cb.currentText() and cb.currentText() != "(none)"}
        self.exports[p] = load_dlp_export(p, mapping)
        self._fill(self.exports[p])

    def _fill(self, d):
        ev = d["events"]
        self.preview.setRowCount(min(len(ev), 50))
        for r, e in enumerate(ev[:50]):
            for c, v in enumerate([(e.get("time") or "")[:19], e.get("activity"), e.get("user"), e.get("device"), e.get("file_name"),
                                   e.get("usb_serial") or e.get("destination")]):
                self.preview.setItem(r, c, QTableWidgetItem(str(v or "")))
        chans = {}
        for e in ev:
            chans[e["channel"]] = chans.get(e["channel"], 0) + 1
        self.status.setText(f"{len(ev)} alerts - " + ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in chans.items()))

    def value(self):
        return list(self.exports.keys()), {p: d["mapping"] for p, d in self.exports.items()}


# ============================================================================ wizard
class NewCaseWizard(QDialog):
    created = Signal(str, bool)  # case path, start processing

    STEPS = ["Case details", "Investigation profile", "Evidence", "What do you know?", "Processing options", "Review & start"]

    def __init__(self, parent=None, profile_id: str | None = None):
        super().__init__(parent)
        self.setWindowTitle("New case - Windows Forensic Automation")
        self.resize(1180, 820)
        self.profiles = {k: v for k, v in load_profiles().items() if not k.startswith("error:")}
        self.profile_id = profile_id or next(iter(self.profiles))
        self.pool = QThreadPool.globalInstance()
        self.evidence: list[dict] = []
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        side = QFrame()
        side.setProperty("role", "sidebar")
        side.setFixedWidth(250)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(20, 26, 16, 20)
        t = label("New case", "h2")
        sl.addWidget(t)
        sl.addWidget(label("Set up the investigation in a few steps. Everything except the evidence is optional.", "muted", True))
        sl.addSpacing(18)
        self.step_labels = []
        for i, s in enumerate(self.STEPS):
            row = QHBoxLayout()
            num = QLabel(str(i + 1))
            num.setFixedSize(26, 26)
            num.setAlignment(Qt.AlignCenter)
            txt = QLabel(s)
            row.addWidget(num)
            row.addWidget(txt, 1)
            sl.addLayout(row)
            sl.addSpacing(6)
            self.step_labels.append((num, txt))
        sl.addStretch()
        sl.addWidget(label("Tip: drop image files anywhere on the Evidence step.", "faint", True))
        root.addWidget(side)
        main = QVBoxLayout()
        main.setContentsMargins(28, 22, 28, 18)
        self.stack = QStackedWidget()
        main.addWidget(self.stack, 1)
        nav = QHBoxLayout()
        self.back_btn = IconButton("back", "Back")
        self.next_btn = IconButton("next", "Next", "primary")
        self.cancel_btn = QPushButton("Cancel")
        self.back_btn.clicked.connect(lambda: self.go(self.stack.currentIndex() - 1))
        self.next_btn.clicked.connect(self._next)
        self.cancel_btn.clicked.connect(self.reject)
        nav.addWidget(self.cancel_btn)
        nav.addStretch()
        nav.addWidget(self.back_btn)
        nav.addWidget(self.next_btn)
        main.addLayout(nav)
        root.addLayout(main, 1)
        self.stack.addWidget(self._page_details())
        self.stack.addWidget(self._page_profile())
        self.stack.addWidget(self._page_evidence())
        self.inputs_page = QWidget()
        self.stack.addWidget(self.inputs_page)
        self.stack.addWidget(self._page_options())
        self.review_page = QWidget()
        self.stack.addWidget(self.review_page)
        self.setAcceptDrops(True)
        self.go(0)

    # ------------------------------------------------------------------ navigation
    def go(self, i):
        i = max(0, min(i, self.stack.count() - 1))
        if i == 3:
            self._build_inputs()
        if i == 5:
            self._build_review()
        self.stack.setCurrentIndex(i)
        for k, (num, txt) in enumerate(self.step_labels):
            if k < i:
                num.setText(theme.glyph("check") if theme.icon_family() else "v")
                num.setFont(theme.icon_font(9) if theme.icon_family() else num.font())
                num.setStyleSheet(f"background:{C['ok']}; color:white; border-radius:13px;")
                txt.setStyleSheet(f"color:{C['text']};")
            elif k == i:
                num.setText(str(k + 1))
                num.setFont(QApplication.font())
                num.setStyleSheet(f"background:{C['accent']}; color:white; border-radius:13px; font-weight:600;")
                txt.setStyleSheet("color:white; font-weight:600;")
            else:
                num.setText(str(k + 1))
                num.setFont(QApplication.font())
                num.setStyleSheet(f"background:{C['panel2']}; color:{C['muted']}; border-radius:13px;")
                txt.setStyleSheet(f"color:{C['muted']};")
        self.back_btn.setEnabled(i > 0)
        self.next_btn.setText("Create case & start processing" if i == 5 else "Next")

    def _next(self):
        i = self.stack.currentIndex()
        if i == 0 and not self.case_folder.text().strip():
            QMessageBox.information(self, "Case folder", "Choose a folder for the case.")
            return
        if i == 2 and not self.evidence:
            QMessageBox.information(self, "Evidence", "Add at least one evidence item.")
            return
        if i == 2 and any(e.get("probing") for e in self.evidence):
            QMessageBox.information(self, "Evidence", "Please wait until all evidence items have been probed.")
            return
        if i == 5:
            self._create()
            return
        self.go(i + 1)

    def _section(self, title, sub=""):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(label(title, "h1"))
        if sub:
            lay.addWidget(label(sub, "muted", True))
        lay.addSpacing(10)
        return w, lay

    # ------------------------------------------------------------------ step 1
    def _page_details(self):
        w, lay = self._section("Case details", "Identify the case. These details appear on the report cover and headers.")
        form = QFormLayout()
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(10)
        self.case_number = QLineEdit()
        self.case_number.setPlaceholderText("e.g. IR-2026-0142")
        self.case_name = QLineEdit()
        self.case_name.setPlaceholderText("e.g. Project Alpha data leak")
        self.examiner = QLineEdit(os.environ.get("USERNAME", ""))
        self.org = QLineEdit()
        self.client = QLineEdit()
        self.desc = QPlainTextEdit()
        self.desc.setFixedHeight(70)
        self.desc.setPlaceholderText("Short description / reason for examination")
        self.classification = QComboBox()
        self.classification.setEditable(True)
        self.classification.addItems(["CONFIDENTIAL", "STRICTLY CONFIDENTIAL", "PRIVILEGED & CONFIDENTIAL", "RESTRICTED", "INTERNAL"])
        self.tz = QComboBox()
        self.tz.setEditable(True)
        self.tz.addItems(TIMEZONES)
        frow = QHBoxLayout()
        self.case_folder = QLineEdit()
        base = os.path.join(os.path.expanduser("~"), "Documents", "Forensic Cases")
        self.case_folder.setText(os.path.join(base, f"Case_{datetime.now():%Y%m%d_%H%M}"))
        self.case_number.textChanged.connect(lambda t: self.case_folder.setText(os.path.join(base, re.sub(r"[^\w.-]+", "_", t) or "Case")))
        br = IconButton("folder", "Browse")
        br.clicked.connect(lambda: self.case_folder.setText(QFileDialog.getExistingDirectory(self, "Case folder", base) or self.case_folder.text()))
        frow.addWidget(self.case_folder, 1)
        frow.addWidget(br)
        for t, wdg in (("Case number", self.case_number), ("Case name", self.case_name), ("Examiner", self.examiner),
                       ("Organization", self.org), ("Client / requester", self.client), ("Description", self.desc),
                       ("Classification", self.classification), ("Report time zone", self.tz)):
            form.addRow(t, wdg)
        form.addRow("Case folder", frow)
        lay.addLayout(form)
        lay.addStretch()
        return w

    # ------------------------------------------------------------------ step 2
    def _page_profile(self):
        w, lay = self._section("Choose the investigation profile",
                               "The profile decides what is examined, how results are correlated and which questions the report answers.")
        split = QHBoxLayout()
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        inner = QWidget()
        grid = QGridLayout(inner)
        grid.setSpacing(12)
        self.profile_cards = {}
        for i, (pid, p) in enumerate(self.profiles.items()):
            card = Card(clickable=True)
            card.setMinimumHeight(120)
            top = QHBoxLayout()
            top.addWidget(icon_label(p.icon if p.icon in theme.GLYPH else "shield", 18, C["accent2"]))
            nm = label(p.name, "h3")
            top.addWidget(nm, 1)
            card.lay.addLayout(top)
            card.lay.addWidget(chip(p.category, C["panel2"], True))
            card.lay.addWidget(label(p.summary, "muted", True))
            card.clicked.connect(lambda pid=pid: self._select_profile(pid))
            grid.addWidget(card, i // 2, i % 2)
            self.profile_cards[pid] = card
        sa.setWidget(inner)
        split.addWidget(sa, 3)
        self.profile_detail = QLabel()
        self.profile_detail.setWordWrap(True)
        self.profile_detail.setAlignment(Qt.AlignTop)
        self.profile_detail.setTextFormat(Qt.RichText)
        det = QScrollArea()
        det.setWidgetResizable(True)
        box = QFrame()
        box.setProperty("role", "panel")
        bl = QVBoxLayout(box)
        bl.addWidget(self.profile_detail)
        bl.addStretch()
        det.setWidget(box)
        split.addWidget(det, 2)
        lay.addLayout(split, 1)
        self._select_profile(self.profile_id)
        return w

    def _select_profile(self, pid):
        self.profile_id = pid
        for k, c in self.profile_cards.items():
            c.setStyleSheet(f"QFrame[role='card'] {{ border: 2px solid {C['accent']}; background: {C['sel_card']}; }}" if k == pid else "")
        p = self.profiles[pid]
        qs = "".join(f"<li style='margin-bottom:4px'>{q['text']}</li>" for q in p.questions)
        use = "".join(f"<li>{u}</li>" for u in p.when_to_use)
        self.profile_detail.setText(
            f"<div style='font-size:13pt;font-weight:600;color:white'>{p.name}</div>"
            f"<p style='color:{C['muted']}'>{p.description}</p>"
            + (f"<div style='font-weight:600;margin-top:8px'>When to use</div><ul>{use}</ul>" if use else "")
            + f"<div style='font-weight:600;margin-top:8px'>Questions the report will answer</div><ol>{qs}</ol>")
        self.evidence_roles = p.evidence_roles or ROLE_DEFAULT

    # ------------------------------------------------------------------ step 3
    def _page_evidence(self):
        w, lay = self._section("Add evidence", "E01 / Ex01 (incl. split), raw / dd / split raw, VMDK, VHD, VHDX, VDI, QCOW2, AD1, "
                                               "and folders / ZIPs of triage collections (KAPE, Velociraptor). Each item is probed immediately.")
        row = QHBoxLayout()
        a = IconButton("add", "Add image file(s)", "primary")
        a.clicked.connect(self._add_files)
        f = IconButton("folder", "Add triage folder")
        f.clicked.connect(lambda: self._add_paths([QFileDialog.getExistingDirectory(self, "Triage collection folder")]))
        k = IconButton("key", "BitLocker key...")
        k.clicked.connect(self._bitlocker)
        r = IconButton("delete", "Remove")
        r.clicked.connect(self._remove_ev)
        for b in (a, f, k, r):
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        self.ev_table = QTableWidget(0, 7)
        self.ev_table.setHorizontalHeaderLabels(["Evidence file", "Format", "Size", "System", "Role", "Label", "Status"])
        hh = self.ev_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        for i, wdt in ((0, 210), (1, 130), (2, 75), (4, 205), (5, 135), (6, 90)):
            self.ev_table.setColumnWidth(i, wdt)
        self.ev_table.setTextElideMode(Qt.ElideMiddle)
        self.ev_table.verticalHeader().hide()
        self.ev_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ev_table.itemSelectionChanged.connect(self._ev_details)
        lay.addWidget(self.ev_table, 2)
        self.ev_info = QLabel()
        self.ev_info.setWordWrap(True)
        self.ev_info.setTextFormat(Qt.RichText)
        self.ev_info.setAlignment(Qt.AlignTop)
        box = QFrame()
        box.setProperty("role", "panel")
        bl = QVBoxLayout(box)
        bl.addWidget(self.ev_info)
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setWidget(box)
        lay.addWidget(sa, 1)
        return w

    def dragEnterEvent(self, e):  # noqa: N802
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):  # noqa: N802
        self._add_paths([u.toLocalFile() for u in e.mimeData().urls()])
        if self.stack.currentIndex() < 2:
            self.go(2)

    def _add_files(self):
        exts = IMAGE_EXTENSIONS
        paths, _ = QFileDialog.getOpenFileNames(self, "Add evidence", "", f"Forensic images ({exts});;All files (*.*)")
        self._add_paths(paths)

    def _add_paths(self, paths):
        known = {os.path.normcase(e["path"]) for e in self.evidence}
        for p in paths:
            if not p or os.path.normcase(p) in known:
                continue
            # skip secondary segments of a split image
            if re.search(r"\.(e|ex|l|s)(0[2-9]|[1-9]\d)$|\.0(0[2-9]|[1-9]\d)$", p, re.I):
                continue
            idx = len(self.evidence)
            roles = self.evidence_roles
            default_role = roles[min(idx, len(roles) - 1)]["id"] if roles else "other"
            lower = p.lower()
            if re.search(r"usb|pendrive|thumb|stick|flash", os.path.basename(lower)):
                default_role = next((r["id"] for r in roles if r["id"] == "removable"), default_role)
            ev = {"path": p, "label": os.path.splitext(os.path.basename(p))[0], "role": default_role, "probing": True, "probe": None,
                  "keys": [], "id": idx}
            self.evidence.append(ev)
            self._add_row(ev)
            task = ProbeTask(idx, p)
            task.signals.done.connect(self._probed)
            self.pool.start(task)

    def _add_row(self, ev):
        r = self.ev_table.rowCount()
        self.ev_table.insertRow(r)
        it = QTableWidgetItem(os.path.basename(ev["path"]))
        it.setData(Qt.UserRole, ev["path"])
        it.setToolTip(ev["path"])
        self.ev_table.setItem(r, 0, it)
        for c in (1, 2, 3):
            self.ev_table.setItem(r, c, QTableWidgetItem("..."))
        cb = QComboBox()
        for role in self.evidence_roles:
            cb.addItem(role.get("label", role["id"]), role["id"])
        cb.setCurrentIndex(max(0, [x["id"] for x in self.evidence_roles].index(ev["role"]) if ev["role"] in
                               [x["id"] for x in self.evidence_roles] else 0))
        cb.currentIndexChanged.connect(lambda _i, ev=ev, cb=cb: ev.__setitem__("role", cb.currentData()))
        self.ev_table.setCellWidget(r, 4, cb)
        le = QLineEdit(ev["label"])
        le.textChanged.connect(lambda t, ev=ev: ev.__setitem__("label", t))
        self.ev_table.setCellWidget(r, 5, le)
        bar = QProgressBar()
        bar.setRange(0, 0)
        bar.setFormat("probing")
        self.ev_table.setCellWidget(r, 6, bar)
        self.ev_table.setRowHeight(r, 36)

    def _row_of(self, ev_id):
        for r in range(self.ev_table.rowCount()):
            if self.ev_table.item(r, 0) and self.ev_table.item(r, 0).data(Qt.UserRole) == self.evidence[ev_id]["path"]:
                return r
        return None

    def _probed(self, ev_id, res):
        if ev_id >= len(self.evidence):
            return
        ev = self.evidence[ev_id]
        ev["probing"] = False
        ev["probe"] = res
        r = self._row_of(ev_id)
        if r is None:
            return
        osd = res.get("os") or {}
        self.ev_table.item(r, 1).setText(res.get("format_label") or res.get("format") or "?")
        from .widgets import human_size

        self.ev_table.item(r, 2).setText(human_size(res.get("media_size") or res.get("file_size") or 0))
        sysname = f"{osd.get('hostname') or ''}  {osd.get('product_name') or ''}".strip()
        if not sysname:
            vols = [v for v in res.get("volumes", []) if v.get("fs")]
            sysname = ", ".join(f"{str(v.get('fs')).upper()} '{v.get('label') or ''}'" for v in vols) or "-"
        self.ev_table.item(r, 3).setText(sysname)
        if osd.get("hostname") and ev["label"] == os.path.splitext(os.path.basename(ev["path"]))[0]:
            w = self.ev_table.cellWidget(r, 5)
            w.setText(f"{osd['hostname']}")
        if osd.get("family") != "windows" and any(r_["id"] == "removable" for r_ in self.evidence_roles) and \
                not any(v.get("fs") == "ntfs" and (v.get("size") or 0) > 20e9 for v in res.get("volumes", [])):
            cb = self.ev_table.cellWidget(r, 4)
            idx = cb.findData("removable")
            if idx >= 0:
                cb.setCurrentIndex(idx)
        status = QLabel(" Error" if res.get("error") else (" Warnings" if res.get("warnings") else " Ready"))
        status.setStyleSheet(f"color:{C['err'] if res.get('error') else C['warn'] if res.get('warnings') else C['ok']}; font-weight:600;")
        self.ev_table.setCellWidget(r, 6, status)
        self._ev_details()

    def _ev_details(self):
        rows = {i.row() for i in self.ev_table.selectedIndexes()}
        if not rows:
            return
        r = min(rows)
        path = self.ev_table.item(r, 0).data(Qt.UserRole)
        ev = next((e for e in self.evidence if e["path"] == path), None)
        if not ev or not ev.get("probe"):
            self.ev_info.setText("Probing...")
            return
        res = ev["probe"]
        osd = res.get("os") or {}
        vols = "".join(f"<li>{v.get('name')}: {str(v.get('fs') or 'unknown').upper()} '{v.get('label') or ''}' "
                       f"serial {v.get('serial') or '-'} - {(v.get('size') or 0) / 1e9:.2f} GB"
                       f"{' <b style=color:#F59E0B>BitLocker</b>' if v.get('encrypted') else ''}</li>" for v in res.get("volumes", []))
        users = ", ".join(u.get("name", "") for u in res.get("users", []))
        ewf = res.get("ewf") or {}
        warn = "".join(f"<li style='color:{C['warn']}'>{w}</li>" for w in res.get("warnings", []))
        err = f"<p style='color:{C['err']}'>{res['error']}</p>" if res.get("error") else ""
        self.ev_info.setText(
            f"<b style='font-size:11pt'>{os.path.basename(path)}</b> &nbsp; <span style='color:{C['muted']}'>{res.get('format_label')}"
            f" - {len(res.get('segments', []))} segment(s) - probed in {res.get('probe_seconds')} s</span>{err}"
            + (f"<p><b>{osd.get('hostname')}</b> - {osd.get('product_name')} {osd.get('display_version') or ''} build {osd.get('build')}"
               f" - time zone {osd.get('timezone_name')} - users: {users}</p>" if osd.get("family") == "windows" else "")
            + (f"<p>Acquisition: {', '.join(f'{k}: {v}' for k, v in (ewf.get('headers') or {}).items() if k in ('case_number', 'evidence_number', 'examiner_name', 'acquiry_date'))}"
               f"<br>Stored hash: {', '.join(f'{k.upper()} {v}' for k, v in (ewf.get('stored_hashes') or {}).items())}</p>" if ewf else "")
            + f"<div>Volumes</div><ul>{vols}</ul>" + (f"<ul>{warn}</ul>" if warn else ""))

    def _remove_ev(self):
        rows = sorted({i.row() for i in self.ev_table.selectedIndexes()}, reverse=True)
        for r in rows:
            path = self.ev_table.item(r, 0).data(Qt.UserRole)
            self.evidence = [e for e in self.evidence if e["path"] != path]
            self.ev_table.removeRow(r)
        for i, e in enumerate(self.evidence):
            e["id"] = i

    def _bitlocker(self):
        rows = sorted({i.row() for i in self.ev_table.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, "BitLocker", "Select the evidence item first.")
            return
        from PySide6.QtWidgets import QInputDialog

        key, ok = QInputDialog.getText(self, "BitLocker", "Recovery password (48 digits) or passphrase:")
        if ok and key.strip():
            path = self.ev_table.item(rows[0], 0).data(Qt.UserRole)
            ev = next(e for e in self.evidence if e["path"] == path)
            kt = "recovery_key" if re.fullmatch(r"[\d-]{48,55}", key.strip()) else "passphrase"
            ev["keys"] = [{"type": kt, "value": key.strip()}]
            ev["probing"] = True
            task = ProbeTask(ev["id"], path, ev["keys"])
            task.signals.done.connect(self._probed)
            self.pool.start(task)

    # ------------------------------------------------------------------ step 4 (dynamic per profile)
    def _build_inputs(self):
        p = self.profiles[self.profile_id]
        if getattr(self, "_inputs_for", None) == self.profile_id:
            return
        self._inputs_for = self.profile_id
        old = self.inputs_page.layout()
        if old is not None:
            QWidget().setLayout(old)
        lay = QVBoxLayout(self.inputs_page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(label("What do you know about the case?", "h1"))
        lay.addWidget(label("Provide whatever background you have - everything is optional. The analysis adapts: with a DLP export "
                            "each alert is corroborated; with only file names or hashes they are traced everywhere; with nothing "
                            "but a time window the activity in that window is reconstructed.", "muted", True))
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        inner = QWidget()
        form = QVBoxLayout(inner)
        form.setSpacing(14)
        self.input_widgets = {}
        for spec in p.inputs:
            box = QGroupBox(spec.get("label", spec["id"]))
            bl = QVBoxLayout(box)
            if spec.get("help"):
                bl.addWidget(label(spec["help"], "faint", True))
            typ = spec.get("type")
            if typ == "dlp_export":
                wdg = DlpExportWidget()
            elif typ == "target_files":
                wdg = TargetTable()
            elif typ in ("reference_files",):
                wdg = FileList(folders=True)
            elif typ in ("samples",):
                wdg = FileList(folders=False)
            elif typ == "yara":
                wdg = FileList(False, "YARA rules (*.yar *.yara);;All (*.*)")
            elif typ == "time_window":
                wdg = TimeWindow()
            elif typ == "keywords":
                wdg = StringList("One keyword per line. Wrap in /slashes/ for a regular expression.")
            elif typ == "iocs":
                wdg = StringList("Paste IOCs or a threat report: URLs, domains, IPs, hashes, file names - they are extracted automatically.")
                wdg.setFixedHeight(120)
            elif typ == "text":
                wdg = QPlainTextEdit()
                wdg.setFixedHeight(90)
                wdg.setPlaceholderText("What happened, what is suspected, what has been reported...")
            else:
                wdg = StringList(spec.get("placeholder", ""))
            bl.addWidget(wdg)
            form.addWidget(box)
            self.input_widgets[spec["id"]] = (typ, wdg)
        form.addStretch()
        sa.setWidget(inner)
        lay.addWidget(sa, 1)

    def _collect_inputs(self) -> dict:
        from ..knowledge import extract_iocs

        kw = dict(dlp_exports=[], dlp_mappings={}, hash_lists=[], reference_paths=[], targets=[], usb_serials=[], users=[],
                  window={}, domains=[], keywords=[], background="", iocs={}, samples=[], yara_rules=[])
        for iid, (typ, w) in getattr(self, "input_widgets", {}).items():
            if typ == "dlp_export":
                kw["dlp_exports"], kw["dlp_mappings"] = w.value()
            elif typ == "target_files":
                kw["targets"] += w.value()
            elif typ == "reference_files":
                kw["reference_paths"] += w.value()
            elif typ == "samples":
                kw["samples"] += w.value()
            elif typ == "yara":
                kw["yara_rules"] += w.value()
            elif typ == "time_window":
                kw["window"] = w.value()
            elif typ == "keywords":
                for line in w.value():
                    if len(line) > 2 and line.startswith("/") and line.endswith("/"):
                        kw["keywords"].append({"term": line[1:-1], "regex": True, "label": "regex"})
                    else:
                        kw["keywords"].append(line)
            elif typ == "iocs":
                text = "\n".join(w.value())
                found = extract_iocs(text)
                kw["iocs"] = {"domains": found["domains"], "ips": found["ips"], "urls": found["urls"], "emails": found["emails"],
                              "filenames": [x for x in re.findall(r"[\w.-]+\.(?:exe|dll|ps1|vbs|js|hta|bat|lnk|msi|scr|zip|iso)\b", text, re.I)]}
                for h in set(re.findall(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b", text)):
                    kw["targets"].append({{32: "md5", 40: "sha1", 64: "sha256"}[len(h)]: h.lower(), "name": "", "source": "IOC"})
            elif typ == "text":
                kw["background"] = w.toPlainText().strip()
            elif iid == "usb_serials":
                kw["usb_serials"] = w.value()
            elif iid == "suspect_users":
                kw["users"] = w.value()
            elif iid == "domains":
                kw["domains"] = w.value()
        return kw

    # ------------------------------------------------------------------ step 5
    def _page_options(self):
        w, lay = self._section("Processing options", "Defaults are chosen for thoroughness. Faster settings trade depth for time.")
        g1 = QGroupBox("Evidence processing")
        f1 = QFormLayout(g1)
        self.opt_verify = QCheckBox("Verify image hash against the acquisition hash (reads the whole image once more)")
        self.opt_carve = QCheckBox("Carve deleted documents, shortcuts, databases and executables from unallocated space")
        self.opt_carve.setChecked(True)
        self.opt_vss = QCheckBox("Search Volume Shadow Copies for the files of interest")
        self.opt_vss.setChecked(True)
        self.scope_full = QRadioButton("Full physical search - every byte of every volume (recommended)")
        self.scope_fast = QRadioButton("Fast - unallocated space, file slack, memory and metadata files only")
        self.scope_full.setChecked(True)
        grp = QButtonGroup(self)
        grp.addButton(self.scope_full)
        grp.addButton(self.scope_fast)
        self.hash_all = QCheckBox("Hash every file (not only candidates matching the size / name of a file of interest)")
        self.doc_mb = QSpinBox()
        self.doc_mb.setRange(1, 2000)
        self.doc_mb.setValue(50)
        self.doc_mb.setSuffix(" MB")
        self.workers = QSpinBox()
        self.workers.setRange(0, 16)
        self.workers.setSpecialValueText("Automatic")
        self.fat_tz = QComboBox()
        self.fat_tz.setEditable(True)
        self.fat_tz.addItems(["(time zone of the source system)"] + TIMEZONES)
        for wd in (self.opt_verify, self.opt_carve, self.opt_vss, self.scope_full, self.scope_fast, self.hash_all):
            f1.addRow(wd)
        f1.addRow("Max document size for text indexing", self.doc_mb)
        f1.addRow("Parallel evidence workers", self.workers)
        f1.addRow("Time zone for FAT / exFAT media", self.fat_tz)
        self.raw_threads = QSpinBox()
        self.raw_threads.setRange(1, 16)
        self.raw_threads.setValue(min(4, os.cpu_count() or 2))
        self.raw_threads.setToolTip("Parallel image readers for the physical search. E01 decompression is CPU bound, "
                                    "so more readers scan faster on multi-core machines.")
        f1.addRow("Physical search readers", self.raw_threads)
        g3 = QGroupBox("Manual analysis outputs")
        f3 = QFormLayout(g3)
        self.opt_export = QCheckBox("Keep a parsed CSV copy of every artifact (MFT, USN, SRUM tables, every event log, registry, "
                                    "browser, LNK / jump lists ...) in the Parsed folder")
        self.opt_export.setChecked(True)
        self.opt_evtx_all = QCheckBox("Export every event log record (not only the forensically relevant event IDs)")
        self.opt_evtx_all.setChecked(True)
        self.opt_collect = QCheckBox("Copy the raw artifact files out of the image (registry hives + logs, EVTX, Prefetch, SRUM, "
                                     "$MFT, $LogFile, $UsnJrnl, browser databases, ...) with an MD5/SHA-1/SHA-256 manifest")
        self.opt_collect.setChecked(True)
        self.collect_mb = QSpinBox()
        self.collect_mb.setRange(16, 65536)
        self.collect_mb.setValue(4096)
        self.collect_mb.setSuffix(" MB")
        for wd in (self.opt_export, self.opt_evtx_all, self.opt_collect):
            wd.setStyleSheet("QCheckBox { spacing: 8px; }")
            f3.addRow(wd)
        f3.addRow("Skip collected files larger than", self.collect_mb)
        for wd in (self.doc_mb, self.workers, self.raw_threads, self.collect_mb):
            wd.setMaximumWidth(220)
        self.fat_tz.setMaximumWidth(420)
        g2 = QGroupBox("Report")
        f2 = QFormLayout(g2)
        self.paper = QComboBox()
        self.paper.addItems(["A4", "Letter"])
        self.auto_report = QCheckBox("Generate the Word report and Excel workbook automatically when processing finishes")
        self.auto_report.setChecked(True)
        self.word_pdf = QCheckBox("Use Microsoft Word (if installed) to build the table of contents and a PDF copy")
        self.word_pdf.setChecked(True)
        self.paper.setMaximumWidth(220)
        f2.addRow("Paper size", self.paper)
        f2.addRow(self.auto_report)
        f2.addRow(self.word_pdf)
        lay.addWidget(g1)
        lay.addWidget(g3)
        lay.addWidget(g2)
        lay.addStretch()
        return w

    # ------------------------------------------------------------------ step 6
    def _build_review(self):
        old = self.review_page.layout()
        if old is not None:
            QWidget().setLayout(old)
        lay = QVBoxLayout(self.review_page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(label("Review", "h1"))
        p = self.profiles[self.profile_id]
        kw = self._collect_inputs()
        ev = "".join(f"<li><b>{e['label']}</b> - {next((r.get('label') for r in self.evidence_roles if r['id'] == e['role']), e['role'])}"
                     f" - <span style='color:{C['muted']}'>{e['path']}</span></li>" for e in self.evidence)
        known = []
        if kw["dlp_exports"]:
            known.append(f"{len(kw['dlp_exports'])} DLP export(s)")
        if kw["targets"]:
            known.append(f"{len(kw['targets'])} file(s) of interest")
        if kw["reference_paths"]:
            known.append(f"{len(kw['reference_paths'])} reference file/folder(s)")
        for k, t in (("usb_serials", "USB serial(s)"), ("users", "user(s)"), ("domains", "domain(s)"), ("keywords", "keyword(s)"),
                     ("samples", "sample(s)")):
            if kw[k]:
                known.append(f"{len(kw[k])} {t}")
        if kw["window"]:
            known.append(f"time window {kw['window']['start']} - {kw['window']['end']}")
        if kw["iocs"]:
            known.append(f"{sum(len(v) for v in kw['iocs'].values())} IOC(s)")
        txt = QLabel(f"<div style='font-size:10.5pt'><p><b>Case</b>: {self.case_number.text() or '-'} {self.case_name.text()} "
                     f"- examiner {self.examiner.text()}</p><p><b>Folder</b>: {self.case_folder.text()}</p>"
                     f"<p><b>Profile</b>: {p.name}</p><p><b>Evidence</b></p><ul>{ev}</ul>"
                     f"<p><b>Case inputs</b>: {', '.join(known) or 'none - the analysis will reconstruct activity without prior knowledge'}</p>"
                     f"<p><b>Processing</b>: {'full' if self.scope_full.isChecked() else 'fast'} physical search, "
                     f"carving {'on' if self.opt_carve.isChecked() else 'off'}, shadow copies {'on' if self.opt_vss.isChecked() else 'off'}, "
                     f"hash verification {'on' if self.opt_verify.isChecked() else 'off'}</p>"
                     f"<p><b>Manual analysis outputs</b>: parsed CSV copies {'on' if self.opt_export.isChecked() else 'off'}, "
                     f"raw artifact collection {'on' if self.opt_collect.isChecked() else 'off'}</p></div>")
        txt.setWordWrap(True)
        txt.setTextFormat(Qt.RichText)
        lay.addWidget(txt)
        lay.addStretch()

    def _create(self):
        from ..core.case import CaseInfo
        from ..core.caseops import create_case

        folder = self.case_folder.text().strip()
        if os.path.exists(os.path.join(folder, "case.json")):
            if QMessageBox.question(self, "Case exists", f"A case already exists in\n{folder}\n\nOverwrite it?") != QMessageBox.Yes:
                return
        fat_tz = self.fat_tz.currentText()
        options = {"verify_hash": self.opt_verify.isChecked(), "carve": self.opt_carve.isChecked(), "vss": self.opt_vss.isChecked(),
                   "raw_scope": "full" if self.scope_full.isChecked() else "fast",
                   "hash_scope": "all" if self.hash_all.isChecked() else "candidates", "doc_max_mb": self.doc_mb.value(),
                   "max_workers": self.workers.value(), "fat_timezone": "" if fat_tz.startswith("(") else fat_tz,
                   "generate_report": self.auto_report.isChecked(), "raw_threads": self.raw_threads.value(),
                   "export_parsed": self.opt_export.isChecked(), "export_all_events": self.opt_evtx_all.isChecked(),
                   "export_srum": self.opt_export.isChecked(), "collect_raw": self.opt_collect.isChecked(),
                   "collect_max_file_mb": self.collect_mb.value()}
        info = CaseInfo(case_number=self.case_number.text().strip(), case_name=self.case_name.text().strip(),
                        examiner=self.examiner.text().strip(), organization=self.org.text().strip(), client=self.client.text().strip(),
                        description=self.desc.toPlainText().strip(), classification=self.classification.currentText().strip(),
                        display_timezone=self.tz.currentText().strip() or "UTC", profile=self.profile_id, options=options,
                        report={"paper": self.paper.currentText(), "word_finalize": self.word_pdf.isChecked(),
                                "pdf": self.word_pdf.isChecked()})
        evidence = [{"path": e["path"], "label": e["label"], "role": e["role"], "keys": e.get("keys") or None, "probe": e.get("probe")}
                    for e in self.evidence]
        kw = self._collect_inputs()
        self.next_btn.setEnabled(False)
        self.next_btn.setText("Creating case...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            create_case(folder, info, evidence, kw, overwrite=True)
        except Exception as e:
            QApplication.restoreOverrideCursor()
            self.next_btn.setEnabled(True)
            self.next_btn.setText("Create case & start processing")
            QMessageBox.critical(self, "Case creation failed", f"{type(e).__name__}: {e}")
            return
        QApplication.restoreOverrideCursor()
        self.created.emit(folder, True)
        self.accept()
