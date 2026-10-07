"""Main window: navigation rail, home page and case pages."""

from __future__ import annotations

import os

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import (QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow,
                               QMessageBox, QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget)

from .. import __app_title__, __tagline__, __version__
from ..report.brand import draw_logo
from . import theme
from .pages import ArtifactsPage, CoveragePage, DashboardPage, FindingsPage, ReportPage, open_path
from .processing import ProcessingPage
from .theme import C
from .widgets import Card, IconButton, NavButton, icon_label, label


class Logo(QWidget):
    def __init__(self, size=40, parent=None):
        super().__init__(parent)
        self.s = size
        self.setFixedSize(size, size)

    def paintEvent(self, e):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        draw_logo(p, 0, 0, self.s)
        p.end()


class HomePage(QWidget):
    new_case = Signal(object)
    open_case = Signal(str)

    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.settings = settings
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        body = QWidget()
        self.lay = QVBoxLayout(body)
        self.lay.setContentsMargins(40, 34, 40, 30)
        self.lay.setSpacing(18)
        sa.setWidget(body)
        outer.addWidget(sa)
        hero = QHBoxLayout()
        hero.addWidget(Logo(84))
        col = QVBoxLayout()
        t = QLabel(__app_title__)
        t.setStyleSheet(f"font-size: 30pt; font-weight: 700; color: {C['title']};")
        col.addWidget(t)
        col.addWidget(label(f"{__tagline__}  -  load an image, choose what you are investigating, get a court-ready report.", "muted"))
        hero.addSpacing(10)
        hero.addLayout(col, 1)
        nb = IconButton("add", "New case", "primary", 12)
        nb.setMinimumHeight(44)
        nb.clicked.connect(lambda: self.new_case.emit(None))
        ob = IconButton("open", "Open case", None, 12)
        ob.setMinimumHeight(44)
        ob.clicked.connect(self._open)
        hero.addWidget(nb)
        hero.addWidget(ob)
        self.lay.addLayout(hero)
        steps = QHBoxLayout()
        for i, (icon, t1, t2) in enumerate((("hard_drive", "1. Load evidence", "E01, Ex01, raw/dd, VMDK, VHD(X), VDI, QCOW2, triage folders"),
                                            ("shield", "2. Pick a profile", "DLP, malware, phishing, ClickFix, RMM, ransomware, intrusion..."),
                                            ("lightning", "3. Automated examination", "Every artifact, every byte - allocated, slack, unallocated, pagefile"),
                                            ("report", "4. Professional report", "Annotated figures, conclusions per question, Excel workbook"))):
            c = Card()
            r = QHBoxLayout()
            r.addWidget(icon_label(icon, 20, C["accent2"]))
            r.addWidget(label(t1, "h3"), 1)
            c.lay.addLayout(r)
            c.lay.addWidget(label(t2, "muted", True))
            steps.addWidget(c)
        self.lay.addLayout(steps)
        mid = QHBoxLayout()
        left = QVBoxLayout()
        left.setAlignment(Qt.AlignTop)
        left.addWidget(label("Recent cases", "h2"))
        self.recent = QListWidget()
        self.recent.setMinimumHeight(260)
        self.recent.itemDoubleClicked.connect(lambda it: self.open_case.emit(it.data(Qt.UserRole)))
        left.addWidget(self.recent)
        mid.addLayout(left, 2)
        right = QVBoxLayout()
        right.addWidget(label("Start an investigation", "h2"))
        grid = QGridLayout()
        grid.setSpacing(10)
        from ..profiles import load_profiles

        for i, (pid, p) in enumerate((k, v) for k, v in load_profiles().items() if not k.startswith("error:")):
            c = Card(clickable=True)
            r = QHBoxLayout()
            r.addWidget(icon_label(p.icon if p.icon in theme.GLYPH else "shield", 16, C["accent2"]))
            r.addWidget(label(p.name, "h3"), 1)
            c.lay.addLayout(r)
            c.lay.addWidget(label(p.summary, "muted", True))
            c.clicked.connect(lambda pid=pid: self.new_case.emit(pid))
            grid.addWidget(c, i // 2, i % 2)
        right.addLayout(grid)
        right.addStretch()
        mid.addLayout(right, 3)
        self.lay.addLayout(mid)
        self.lay.addStretch()
        self.refresh()

    def refresh(self):
        self.recent.clear()
        for p in self.settings.value("recent", [], list) or []:
            if os.path.exists(os.path.join(p, "case.json")):
                try:
                    import json

                    with open(os.path.join(p, "case.json"), encoding="utf-8") as fh:
                        info = json.load(fh)
                    title = f"{info.get('case_name') or os.path.basename(p)}   [{info.get('case_number') or ''}]   - {info.get('profile')}"
                except Exception:
                    title = p
                it = QListWidgetItem(f"{title}\n{p}")
                it.setData(Qt.UserRole, p)
                self.recent.addItem(it)
        if not self.recent.count():
            self.recent.addItem("No recent cases - create one with 'New case'.")

    def _open(self):
        p = QFileDialog.getExistingDirectory(self, "Open case folder (contains case.json)")
        if p:
            self.open_case.emit(p)


class MainWindow(QMainWindow):
    PAGES = [("home", "home", "Home"), ("dashboard", "dashboard", "Dashboard"), ("processing", "lightning", "Processing"),
             ("findings", "flag", "Findings"), ("artifacts", "database", "Artifacts"), ("coverage", "coverage", "Coverage"),
             ("report", "report", "Report")]

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{__app_title__} {__version__}")
        self.resize(1500, 940)
        self.settings = QSettings("WindowsForensicAutomation", "Windows Forensic Automation")
        self.case = None
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        side = QFrame()
        side.setProperty("role", "sidebar")
        side.setFixedWidth(232)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(14, 18, 14, 14)
        sl.setSpacing(4)
        brand = QHBoxLayout()
        brand.addWidget(Logo(34))
        bt = QLabel(f"Windows Forensic<br><span style='color:{C['accent2']}'>Automation</span>")
        bt.setTextFormat(Qt.RichText)
        bt.setStyleSheet(f"font-size: 14pt; font-weight: 700; color: {C['title']};")
        brand.addWidget(bt, 1)
        sl.addLayout(brand)
        sl.addSpacing(18)
        self.nav = {}
        for key, icon, text in self.PAGES:
            b = NavButton(icon, text)
            b.clicked.connect(lambda _=False, k=key: self.show_page(k))
            sl.addWidget(b)
            self.nav[key] = b
        sl.addStretch()
        self.case_box = Card(role="panel")
        self.case_title = label("No case open", "h3", wrap=True)
        self.case_sub = label("", "faint", wrap=True)
        self.case_box.lay.addWidget(self.case_title)
        self.case_box.lay.addWidget(self.case_sub)
        sl.addWidget(self.case_box)
        foot = QHBoxLayout()
        foot.addWidget(label(f"v{__version__}", "faint"))
        foot.addStretch()
        self.theme_btn = QPushButton(("Dark theme" if theme.mode() == "light" else "Light theme"))
        self.theme_btn.setProperty("role", "ghost")
        self.theme_btn.setToolTip("Switch between the dark and the light theme")
        self.theme_btn.clicked.connect(self._toggle_theme)
        foot.addWidget(self.theme_btn)
        sl.addLayout(foot)
        root.addWidget(side)
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.home = HomePage(self.settings)
        self.home.new_case.connect(self.new_case)
        self.home.open_case.connect(self.open_case)
        self.dashboard = DashboardPage()
        self.dashboard.navigate.connect(self._navigate)
        self.dashboard.action.connect(self._action)
        self.processing = ProcessingPage()
        self.processing.finished.connect(self._job_done)
        self.findings = FindingsPage()
        self.artifacts = ArtifactsPage()
        self.findings.open_artifact.connect(self._open_artifact)
        self.coverage = CoveragePage()
        self.report = ReportPage()
        self.report.generate.connect(lambda: self._action("report"))
        self.pages = {"home": self.home, "dashboard": self.dashboard, "processing": self.processing, "findings": self.findings,
                      "artifacts": self.artifacts, "coverage": self.coverage, "report": self.report}
        for k, _, _ in self.PAGES:
            self.stack.addWidget(self.pages[k])
        self.statusBar().showMessage("Ready")
        self._update_nav()
        self.show_page("home")

    # ------------------------------------------------------------------ theme
    def _toggle_theme(self):
        if self.processing.running():
            QMessageBox.information(self, "Busy", "Switch the theme when the current job has finished.")
            return
        from PySide6.QtWidgets import QApplication

        new = "light" if theme.mode() == "dark" else "dark"
        self.settings.setValue("theme", new)
        theme.set_mode(new)
        theme.apply(QApplication.instance())
        # widgets read the palette when they are built: rebuild the window and reopen the case
        w = MainWindow()
        w.setGeometry(self.geometry())
        if self.isMaximized():
            w.showMaximized()
        else:
            w.show()
        if self.case is not None:
            path = self.case.path
            self.case.close()
            self.case = None
            w.open_case(path)
        QApplication.instance()._main_window = w
        self.close()

    # ------------------------------------------------------------------ navigation
    def _update_nav(self):
        has = self.case is not None
        for k in ("dashboard", "findings", "artifacts", "coverage", "report"):
            self.nav[k].setEnabled(has)
        self.nav["processing"].setEnabled(has or self.processing.running())

    def show_page(self, key, arg=None):
        for k, b in self.nav.items():
            b.setChecked(k == key)
        page = self.pages[key]
        if self.case is not None:
            try:
                if key == "dashboard":
                    page.load(self.case)
                elif key == "findings":
                    page.load(self.case, arg)
                elif key == "artifacts":
                    if arg:
                        page.load(self.case)
                        page.show_artifact(arg)
                    elif page.case is not self.case:
                        page.load(self.case)
                elif key in ("coverage", "report"):
                    page.load(self.case)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"{type(e).__name__}: {e}")
        if key == "home":
            self.home.refresh()
        self.stack.setCurrentWidget(page)

    def _navigate(self, key, arg):
        self.show_page(key, arg)

    def _open_artifact(self, aid):
        self.show_page("artifacts", aid)

    # ------------------------------------------------------------------ cases
    def _remember(self, path):
        rec = [p for p in (self.settings.value("recent", [], list) or []) if os.path.normcase(p) != os.path.normcase(path)]
        self.settings.setValue("recent", ([path] + rec)[:15])

    def new_case(self, profile_id=None):
        from .wizard import NewCaseWizard

        if self.processing.running():
            QMessageBox.information(self, "Busy", "A job is running. Wait for it to finish or cancel it first.")
            return
        w = NewCaseWizard(self, profile_id)
        w.created.connect(self._created)
        w.exec()

    def _created(self, path, start):
        self.open_case(path)
        if start:
            self._action("process")

    def open_case(self, path):
        from ..core.case import Case

        try:
            if self.case is not None:
                self.case.close()
            self.case = Case.open(path)
        except Exception as e:
            QMessageBox.warning(self, "Cannot open case", f"{path}\n\n{e}")
            return
        self._remember(self.case.path)
        self.case_title.setText(self.case.info.case_name or self.case.title)
        self.case_sub.setText(f"{self.case.info.case_number}\n{self.case.info.profile}")
        self.setWindowTitle(f"{self.case.title} - {__app_title__} {__version__}")
        self._update_nav()
        self.artifacts.case = None
        self.show_page("dashboard")

    def _action(self, act):
        if not self.case:
            return
        if act in ("folder", "parsed", "collected"):
            open_path(self.case.path if act == "folder" else self.case.sub({"parsed": "Parsed", "collected": "Collected"}[act]))
            return
        phases = {"process": ("evidence", "analysis", "report"), "analyze": ("analysis", "report"), "report": ("report",)}[act]
        opts = self.case.info.options or {}
        if act == "process" and not opts.get("generate_report", True):
            phases = ("evidence", "analysis")
        title = {"process": "Processing evidence", "analyze": "Re-running analysis", "report": "Building report"}[act]
        if self.processing.start(self.case.path, phases, title):
            self._update_nav()
            self.show_page("processing")
            self.nav["processing"].set_badge("running", C["accent"])
        else:
            QMessageBox.information(self, "Busy", "A job is already running.")

    def _job_done(self, ev):
        self.nav["processing"].set_badge(None)
        from ..core.case import Case

        if self.case:
            self.case.close()
            self.case = Case.open(self.case.path)
        self._update_nav()
        st = ev.get("status")
        rep = ev.get("report") or {}
        if st == "completed":
            self.statusBar().showMessage("Job completed", 10000)
            msg = QMessageBox(self)
            msg.setWindowTitle("Processing complete")
            n = len(self.case.db.findings()) if self.case else 0
            msg.setText(f"<b>Processing complete.</b><br>{n} findings were produced." +
                        (f"<br><br>Report: {os.path.basename(rep.get('docx', ''))}" if rep.get("docx") else ""))
            open_btn = msg.addButton("Open report", QMessageBox.AcceptRole) if rep.get("docx") else None
            dash = msg.addButton("Show results", QMessageBox.ActionRole)
            msg.addButton("Close", QMessageBox.RejectRole)
            msg.exec()
            if open_btn is not None and msg.clickedButton() == open_btn:
                open_path(rep.get("pdf") if rep.get("pdf") and os.path.exists(rep["pdf"]) else rep["docx"])
                self.show_page("dashboard")
            elif msg.clickedButton() == dash:
                self.show_page("dashboard")
        elif st == "failed":
            QMessageBox.warning(self, "Job failed", ev.get("error") or "See the processing log.")

    def closeEvent(self, e):  # noqa: N802
        if self.processing.running():
            if QMessageBox.question(self, "Job running", "A job is still running. Cancel it and quit?") != QMessageBox.Yes:
                e.ignore()
                return
            self.processing.cancel()
            self.processing.thread.wait(15000)
        e.accept()
