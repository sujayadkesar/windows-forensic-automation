"""Case pages: dashboard, findings, artifacts, timeline, search hits, coverage, report."""

from __future__ import annotations

import json
import os

from PySide6.QtCore import QObject, QRunnable, QSize, Qt, QThreadPool, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QScrollArea, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

from ..core.timeutil import fmt
from .grid import GridView, SqlGridModel
from .theme import C, COVERAGE, STATUS
from .widgets import (Card, DetailView, EmptyState, IconButton, chip, human_size, icon_label, label, separator, stat_tile)


def open_path(p: str):
    QDesktopServices.openUrl(QUrl.fromLocalFile(p))


def clear_layout(lay):
    while lay.count():
        it = lay.takeAt(0)
        w = it.widget()
        if w is not None:
            w.deleteLater()
        elif it.layout() is not None:
            clear_layout(it.layout())


def page_header(title: str, sub: str = "") -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 4)
    lay.setSpacing(2)
    lay.addWidget(label(title, "h1"))
    if sub:
        lay.addWidget(label(sub, "muted", True))
    return w


# ============================================================================ dashboard
class DashboardPage(QWidget):
    navigate = Signal(str, object)
    action = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        self.body = QWidget()
        self.lay = QVBoxLayout(self.body)
        self.lay.setContentsMargins(26, 22, 26, 22)
        self.lay.setSpacing(16)
        sa.setWidget(self.body)
        outer.addWidget(sa)

    def load(self, case):
        from ..profiles import get_profile

        self.case = case
        clear_layout(self.lay)
        db = case.db
        info = case.info
        try:
            prof = get_profile(info.profile)
        except KeyError:
            prof = None
        self.lay.addWidget(label(info.case_name or case.title, "h1"))
        meta = QHBoxLayout()
        if prof:
            meta.addWidget(chip(prof.name, C["accent_dark"]))
        if info.case_number:
            meta.addWidget(chip(info.case_number, C["panel2"]))
        ml = label(f"Examiner: {info.examiner or '-'}   |   Created {fmt(info.created_utc, with_zone=False)} UTC", "muted")
        meta.addWidget(ml)
        meta.addStretch()
        self.lay.addLayout(meta)
        pl = label(case.path, "faint", wrap=True)
        self.lay.addWidget(pl)
        head = QHBoxLayout()
        for icon, text, act, role in (("play", "Process evidence", "process", "primary"), ("refresh", "Re-run analysis", "analyze", None),
                                      ("report", "Generate report", "report", None), ("folder", "Open case folder", "folder", None),
                                      ("grid", "Parsed CSVs", "parsed", None), ("database", "Collected files", "collected", None)):
            b = IconButton(icon, text, role)
            b.clicked.connect(lambda _=False, a=act: self.action.emit(a))
            head.addWidget(b)
        head.addStretch()
        self.lay.addLayout(head)
        findings = db.findings()
        sev = {}
        for f in findings:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        tiles = QHBoxLayout()
        tiles.addWidget(stat_tile("Evidence items", str(len(db.evidence())), C["accent2"], "hard_drive"))
        tiles.addWidget(stat_tile("Findings", str(len(findings)), C["accent2"], "flag"))
        n_yes = sum(1 for a in db.answers().values() if a.get("status") in ("Yes", "Indicated"))
        tiles.addWidget(stat_tile("Questions answered", f"{n_yes}", C["warn"], "check"))
        tiles.addWidget(stat_tile("Artifacts parsed", f"{db.scalar('SELECT COUNT(*) FROM artifacts') or 0:,}", C["ok"], "database"))
        tiles.addWidget(stat_tile("Keyword hits", f"{db.scalar('SELECT COUNT(*) FROM hits') or 0:,}", C["warn"], "search"))
        self.lay.addLayout(tiles)
        # questions
        answers = db.answers()
        qcard = Card()
        qcard.lay.addWidget(label("Investigative questions", "h2"))
        if prof:
            for i, q in enumerate(prof.questions, 1):
                a = answers.get(q["id"], {})
                row = QHBoxLayout()
                st = a.get("status") or ("Pending" if not findings else "Inconclusive")
                c = chip(st, STATUS.get(st, C["faint"]))
                c.setFixedWidth(150)
                c.setAlignment(Qt.AlignCenter)
                row.addWidget(c)
                txt = QLabel(f"<b>Q{i}.</b> {q['text']}<br><span style='color:{C['muted']}'>{_clip(a.get('summary'), 330)}</span>")
                txt.setWordWrap(True)
                txt.setTextFormat(Qt.RichText)
                row.addWidget(txt, 1)
                go = IconButton("next", "")
                go.setFixedWidth(42)
                go.setToolTip("Show findings for this question")
                go.clicked.connect(lambda _=False, qid=q["id"]: self.navigate.emit("findings", qid))
                row.addWidget(go)
                qcard.lay.addLayout(row)
                qcard.lay.addWidget(separator())
        self.lay.addWidget(qcard)
        # evidence cards
        self.lay.addWidget(label("Evidence", "h2"))
        grid = QGridLayout()
        grid.setSpacing(12)
        for i, e in enumerate(db.evidence()):
            c = Card()
            osd = e.get("os") or {}
            top = QHBoxLayout()
            top.addWidget(icon_label("usb" if e["role"] == "removable" else "hard_drive", 20, C["accent2"]))
            top.addWidget(label(e["label"], "h3"), 1)
            stc = {"processed": C["ok"], "processing": C["accent"], "failed": C["err"], "cancelled": C["warn"]}.get(e.get("status"), C["faint"])
            top.addWidget(chip(e.get("status") or "added", stc))
            c.lay.addLayout(top)
            role = prof.role(e["role"]).get("label", e["role"]) if prof else e["role"]
            c.lay.addWidget(label(role, "muted"))
            lines = [f"{osd.get('hostname') or '-'}  -  {osd.get('product_name') or ''} {osd.get('display_version') or ''}".strip(),
                     f"{e.get('format')}  -  {human_size((e.get('info') or {}).get('media_size') or e.get('size') or 0)}",
                     f"Time zone: {osd.get('timezone_name') or '-'}"]
            hashes = e.get("hashes") or {}
            if hashes.get("md5"):
                lines.append("Hash: " + ("verified" if hashes.get("verified") else "MISMATCH" if hashes.get("verified") is False else "computed"))
            for l in lines:
                c.lay.addWidget(label(l, "faint"))
            cnt = db.scalar("SELECT COUNT(*) FROM artifacts WHERE evidence_id=?", (e["id"],)) or 0
            c.lay.addWidget(label(f"{cnt:,} artifacts  -  {db.scalar('SELECT COUNT(*) FROM findings WHERE evidence_id=?', (e['id'],)) or 0} findings", "muted"))
            grid.addWidget(c, i // 3, i % 3)
        self.lay.addLayout(grid)
        rep = db.meta("last_report")
        if rep:
            rc = Card()
            rc.lay.addWidget(label("Latest report", "h2"))
            row = QHBoxLayout()
            for k, icon, t in (("docx", "report", "Open Word report"), ("pdf", "page", "Open PDF"), ("xlsx", "grid", "Open Excel workbook")):
                if rep.get(k) and os.path.exists(rep[k]):
                    b = IconButton(icon, t, "primary" if k == "docx" else None)
                    b.clicked.connect(lambda _=False, p=rep[k]: open_path(p))
                    row.addWidget(b)
            row.addStretch()
            rc.lay.addLayout(row)
            rc.lay.addWidget(label(os.path.basename(rep.get("docx", "")), "faint"))
            self.lay.addWidget(rc)
        self.lay.addStretch()


# ============================================================================ findings
class _FigSignals(QObject):
    done = Signal(int, int, str)


class FigureTask(QRunnable):
    def __init__(self, fid, idx, spec, path):
        super().__init__()
        self.fid, self.idx, self.spec, self.path = fid, idx, spec, path
        self.signals = _FigSignals()

    def run(self):
        from ..report.figures import render

        try:
            if not os.path.exists(self.path):
                render(self.spec, self.path)
            self.signals.done.emit(self.fid, self.idx, self.path)
        except Exception:
            self.signals.done.emit(self.fid, self.idx, "")


class FindingsPage(QWidget):
    open_artifact = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self.pool = QThreadPool.globalInstance()
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 18)
        top = QHBoxLayout()
        top.addWidget(page_header("Findings", "Conclusions produced by the analyzers - each will appear in the report with its figures."), 1)
        self.qfilter = QComboBox()
        self.qfilter.setMinimumWidth(420)
        self.qfilter.currentIndexChanged.connect(self._refresh_list)
        top.addWidget(self.qfilter)
        root.addLayout(top)
        split = QSplitter(Qt.Horizontal)
        self.list = QListWidget()
        self.list.setSpacing(3)
        self.list.currentRowChanged.connect(self._show)
        split.addWidget(self.list)
        self.detail_area = QScrollArea()
        self.detail_area.setWidgetResizable(True)
        self.detail = QWidget()
        self.dlay = QVBoxLayout(self.detail)
        self.dlay.setContentsMargins(18, 8, 18, 8)
        self.detail_area.setWidget(self.detail)
        split.addWidget(self.detail_area)
        split.setSizes([430, 900])
        root.addWidget(split, 1)
        self.findings = []
        self.fig_labels = {}

    def load(self, case, question: str | None = None):
        from ..profiles import get_profile

        self.case = case
        self.qfilter.blockSignals(True)
        self.qfilter.clear()
        self.qfilter.addItem("All findings", None)
        try:
            for i, q in enumerate(get_profile(case.info.profile).questions, 1):
                self.qfilter.addItem(f"Q{i}: {q['text']}", q["id"])
        except KeyError:
            pass
        if question:
            idx = self.qfilter.findData(question)
            self.qfilter.setCurrentIndex(max(0, idx))
        self.qfilter.blockSignals(False)
        self._refresh_list()

    def _refresh_list(self):
        if not self.case:
            return
        q = self.qfilter.currentData()
        self.findings = [f for f in self.case.db.findings() if not q or q in (f.get("questions") or [])]
        self.list.clear()
        for i, f in enumerate(self.findings, 1):
            it = QListWidgetItem()
            w = QFrame()
            w.setStyleSheet(f"QFrame {{ border-left: 4px solid {C['accent']}; background: transparent; }}")
            l = QVBoxLayout(w)
            l.setContentsMargins(10, 6, 6, 6)
            l.setSpacing(2)
            t = QLabel(f"<b>F-{i:02d}</b>  {f['title']}")
            t.setWordWrap(True)
            t.setStyleSheet("border:none;")
            sub = QLabel(f"{f.get('category') or ''}  -  {(f.get('ts') or '')[:16]}")
            sub.setStyleSheet(f"color:{C['muted']}; font-size:8.5pt; border:none;")
            if not f.get("include"):
                t.setStyleSheet(f"border:none; color:{C['faint']};")
            l.addWidget(t)
            l.addWidget(sub)
            it.setSizeHint(QSize(380, max(58, w.sizeHint().height() + 8)))
            self.list.addItem(it)
            self.list.setItemWidget(it, w)
        if self.findings:
            self.list.setCurrentRow(0)
        else:
            clear_layout(self.dlay)
            self.dlay.addWidget(EmptyState("flag", "No findings yet", "Process the evidence to produce findings."))

    def _show(self, row):
        clear_layout(self.dlay)
        self.fig_labels = {}
        if row < 0 or row >= len(self.findings):
            return
        f = self.findings[row]
        t = label(f["title"], "h2", wrap=True)
        self.dlay.addWidget(t)
        chips = QHBoxLayout()
        if f.get("category"):
            chips.addWidget(chip(f["category"], C["panel2"]))
        if f.get("evidence_id"):
            e = self.case.db.evidence(f["evidence_id"])
            chips.addWidget(chip(e["label"] if e else "", C["accent_dark"]))
        for m in f.get("mitre") or []:
            chips.addWidget(chip(m, "#4C1D95"))
        chips.addStretch()
        inc = QCheckBox("Include in report")
        inc.setChecked(bool(f.get("include")))
        inc.toggled.connect(lambda on, fid=f["id"]: self.case.db.update_finding(fid, include=1 if on else 0))
        chips.addWidget(inc)
        self.dlay.addLayout(chips)
        d = label(f["description"], wrap=True, selectable=True)
        d.setStyleSheet("font-size: 10.5pt; line-height: 140%;")
        self.dlay.addWidget(d)
        figdir = self.case.sub("figures", "preview")
        for i, spec in enumerate(f.get("figures") or []):
            cap = label(f"Figure: {spec.get('title', '')}", "muted", wrap=True)
            self.dlay.addWidget(cap)
            img = QLabel("Rendering figure...")
            img.setAlignment(Qt.AlignCenter)
            img.setMinimumHeight(80)
            img.setStyleSheet(f"background:white; border-radius:8px; color:{C['faint']};")
            img.setCursor(Qt.PointingHandCursor)
            self.dlay.addWidget(img)
            self.fig_labels[(f["id"], i)] = img
            path = os.path.join(figdir, f"f{f['id']:04d}_{i}.png")
            task = FigureTask(f["id"], i, spec, path)
            task.signals.done.connect(self._fig_done)
            self.pool.start(task)
        refs = [r for r in f.get("refs") or [] if r.get("kind") == "artifact"]
        if refs:
            self.dlay.addWidget(label(f"Supporting artifacts ({len(refs)})", "h3"))
            lst = QListWidget()
            lst.setMaximumHeight(200)
            for r in refs[:200]:
                a = self.case.db.query("SELECT id, type, ts, summary FROM artifacts WHERE id=?", (r["id"],))
                if a:
                    a = a[0]
                    item = QListWidgetItem(f"{(a['ts'] or '')[:19]}   {a['type']}   {a['summary']}")
                    item.setData(Qt.UserRole, a["id"])
                    lst.addItem(item)
            lst.itemDoubleClicked.connect(lambda it: self.open_artifact.emit(it.data(Qt.UserRole)))
            self.dlay.addWidget(lst)
        self.dlay.addStretch()

    def _fig_done(self, fid, idx, path):
        lb = self.fig_labels.get((fid, idx))
        if lb is None:
            return
        try:
            lb.objectName()
        except RuntimeError:
            return
        if not path:
            lb.setText("Figure could not be rendered")
            return
        pm = QPixmap(path)
        w = max(400, self.detail_area.viewport().width() - 60)
        pm2 = pm.scaledToWidth(min(w, pm.width()), Qt.SmoothTransformation)
        lb.setPixmap(pm2)
        lb.setToolTip("Click to open the full-size image")
        lb.mousePressEvent = lambda e, p=path: open_path(p)


# ============================================================================ artifacts browser
SPECIAL = [("__fs__", "File system (all entries)", "File System"), ("__deleted__", "Deleted files", "File System"),
           ("__usn__", "USN journal", "File System"), ("__hits__", "Keyword hits", "Search"),
           ("__timeline__", "Case timeline", "Timeline")]


class ArtifactsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 18)
        top = QHBoxLayout()
        top.addWidget(page_header("Artifacts", "Every parsed record, grouped by category. Click a column title to sort, type under "
                                               "it to filter; export the current view as CSV, Excel, JSON or HTML."), 1)
        self.ev = QComboBox()
        self.ev.setMinimumWidth(240)
        self.ev.currentIndexChanged.connect(self._reload)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search all fields of this artifact type...")
        self.search.setMinimumWidth(320)
        self.search.returnPressed.connect(self._reload_table)
        top.addWidget(self.ev)
        top.addWidget(self.search)
        root.addLayout(top)
        split = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category / artifact", "Records"])
        self.tree.header().setStretchLastSection(False)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.Fixed)
        self.tree.header().resizeSection(1, 64)
        self.tree.itemSelectionChanged.connect(self._reload_table)
        split.addWidget(self.tree)
        right = QSplitter(Qt.Vertical)
        self.grid = GridView(export_name="artifacts")
        self.table = self.grid.table
        right.addWidget(self.grid)
        self.detail = DetailView()
        right.addWidget(self.detail)
        right.setSizes([520, 220])
        split.addWidget(right)
        split.setSizes([380, 1000])
        root.addWidget(split, 1)
        self.status = label("", "faint")
        root.addWidget(self.status)
        self.model = None
        self.types = {}

    def load(self, case, select_type: str | None = None):
        self.case = case
        self.model = SqlGridModel(case.db)
        self.grid.set_model(self.model)
        self.grid.export_dir = case.sub("exports")
        self.table.selectionModel().currentRowChanged.connect(self._row)
        self.types = case.db.artifact_types()
        self.ev.blockSignals(True)
        self.ev.clear()
        self.ev.addItem("All evidence", None)
        for e in case.db.evidence():
            self.ev.addItem(e["label"], e["id"])
        self.ev.blockSignals(False)
        self._reload(select_type)

    def _reload(self, select_type=None):
        if not self.case:
            return
        eid = self.ev.currentData()
        counts = {}
        sql = "SELECT type, COUNT(*) n FROM artifacts" + (" WHERE evidence_id=?" if eid else "") + " GROUP BY type"
        for r in self.case.db.query(sql, (eid,) if eid else ()):
            counts[r["type"]] = r["n"]
        self.tree.clear()
        cats = {}
        for t, n in sorted(counts.items(), key=lambda kv: self.types.get(kv[0], {}).get("title", kv[0])):
            meta = self.types.get(t, {"title": t, "category": "Other"})
            cat = meta.get("category") or "Other"
            if cat not in cats:
                ci = QTreeWidgetItem(self.tree, [cat, ""])
                f = ci.font(0)
                f.setBold(True)
                ci.setFont(0, f)
                ci.setExpanded(True)
                cats[cat] = [ci, 0]
            it = QTreeWidgetItem(cats[cat][0], [meta.get("title", t), f"{n:,}"])
            it.setData(0, Qt.UserRole, t)
            it.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            cats[cat][1] += n
            if select_type == t:
                self.tree.setCurrentItem(it)
        for cat, (ci, n) in cats.items():
            ci.setText(1, f"{n:,}")
            ci.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
        sp = QTreeWidgetItem(self.tree, ["Special views", ""])
        f = sp.font(0)
        f.setBold(True)
        sp.setFont(0, f)
        sp.setExpanded(True)
        for key, title, _ in SPECIAL:
            it = QTreeWidgetItem(sp, [title, ""])
            it.setData(0, Qt.UserRole, key)
        if not select_type and self.tree.topLevelItemCount() and not self.tree.currentItem():
            first = self.tree.topLevelItem(0)
            if first.childCount():
                self.tree.setCurrentItem(first.child(0))

    def _reload_table(self):
        it = self.tree.currentItem()
        if not it or not self.case:
            return
        t = it.data(0, Qt.UserRole)
        if not t:
            return
        eid = self.ev.currentData()
        q = self.search.text().strip()
        evl = {e["id"]: e["label"] for e in self.case.db.evidence()}
        ev_map = {"evidence": evl}
        where, params = [], []
        if eid:
            where.append("evidence_id=?")
            params.append(eid)
        if t in ("__fs__", "__deleted__"):
            cols = [("evidence", "System", "text"), ("volume", "Vol", "text"), ("path", "Path", "path"), ("size", "Size", "size"),
                    ("deleted", "Deleted", "text"), ("si_created", "$SI Created", "datetime"), ("si_modified", "$SI Modified", "datetime"),
                    ("si_accessed", "$SI Accessed", "datetime"), ("si_changed", "$SI Record Changed", "datetime"),
                    ("fn_created", "$FN Created", "datetime"), ("fn_modified", "$FN Modified", "datetime"),
                    ("record", "MFT Record", "int"), ("seq", "Sequence", "int"), ("flags", "Flags", "text"),
                    ("ads", "Streams", "text"), ("md5", "MD5", "hash"), ("sha256", "SHA-256", "hash")]
            where.append("is_dir=0")
            if t == "__deleted__":
                where.append("deleted=1")
            if q:
                where.append("path LIKE ?")
                params.append(f"%{q}%")
            self.model.set_source(cols, "fs_entries", " AND ".join(where), params,
                                  exprs={"evidence": "evidence_id"},
                                  value_maps={**{"evidence": evl}, "deleted": {1: "Yes", 0: "No"}},
                                  order="evidence_id, path", row_fn=lambda r: {**r, "evidence": r["evidence_id"]},
                                  color_fn=lambda r, k: C["err"] if r.get("deleted") and k == "path" else None)
        elif t == "__usn__":
            cols = [("evidence", "System", "text"), ("ts", "Time (UTC)", "datetime"), ("path", "Path", "path"), ("name", "Name", "text"),
                    ("reason", "Reason", "text"), ("record", "MFT Record", "int"), ("seq", "Sequence", "int"),
                    ("parent", "Parent Record", "int"), ("usn", "USN", "int")]
            if q:
                where.append("path LIKE ?")
                params.append(f"%{q}%")
            self.model.set_source(cols, "usn", " AND ".join(where) or "1=1", params, exprs={"evidence": "evidence_id"},
                                  value_maps=ev_map, order="ts", row_fn=lambda r: {**r, "evidence": r["evidence_id"]})
        elif t == "__hits__":
            cols = [("evidence", "System", "text"), ("term", "Term", "text"), ("area", "Area", "text"), ("volume", "Vol", "text"),
                    ("offset", "Offset", "int"), ("encoding", "Encoding", "text"), ("file_path", "Attributed to", "path"),
                    ("context_text", "Context", "text")]
            if q:
                where.append("(term LIKE ? OR file_path LIKE ? OR area LIKE ?)")
                params += [f"%{q}%"] * 3
            self.model.set_source(cols, "hits", " AND ".join(where) or "1=1", params, exprs={"evidence": "evidence_id"},
                                  value_maps=ev_map, order="term, area", row_fn=lambda r: {**r, "evidence": r["evidence_id"]})
        elif t == "__timeline__":
            cols = [("ts", "Time (UTC)", "datetime"), ("evidence", "System", "text"), ("source", "Source", "text"),
                    ("event", "Event", "text"), ("description", "Description", "text"), ("user", "User", "text"),
                    ("flagged", "Flagged", "text")]
            if q:
                where.append("(description LIKE ? OR event LIKE ?)")
                params += [f"%{q}%"] * 2
            self.model.set_source(cols, "timeline", " AND ".join(where) or "1=1", params, exprs={"evidence": "evidence_id"},
                                  value_maps={**ev_map, "flagged": {1: "Yes", 0: ""}}, order="ts",
                                  row_fn=lambda r: {**r, "evidence": r["evidence_id"]},
                                  color_fn=lambda r, k: C["warn"] if r.get("flagged") and k == "event" else None)
        else:
            meta = self.types.get(t, {"columns": []})
            cols = [("evidence", "System", "text"), ("ts", "Time (UTC)", "datetime"), ("user", "User", "text")] + \
                   [(c["name"], c["title"], c.get("kind", "text")) for c in meta.get("columns", [])] + \
                   [("_source", "Source", "path"), ("_summary", "Summary", "text")]
            exprs = {"evidence": "evidence_id", "ts": "ts", "user": "user", "_source": "source", "_summary": "summary"}
            for c in meta.get("columns", []):
                exprs[c["name"]] = "json_extract(data_json, '$.\"" + c["name"].replace('"', "") + "\"')"
            where.insert(0, "type=?")
            params.insert(0, t)
            if q:
                where.append("(summary LIKE ? OR data_json LIKE ? OR source LIKE ?)")
                params += [f"%{q}%"] * 3

            def row_fn(r):
                d = json.loads(r.get("data_json") or "{}")
                return {**d, "evidence": r["evidence_id"], "ts": r["ts"], "user": r["user"], "_source": r["source"],
                        "_summary": r["summary"], "_row": r}

            def color(r, k):
                tags = (r["_row"].get("tags") or "")
                if "suspicious" in tags or "target_match" in tags or "dlp_match" in tags:
                    return C["warn"]
                return None

            self.model.set_source(cols, "artifacts", " AND ".join(where), params, exprs=exprs, value_maps=ev_map, order="ts",
                                  row_fn=row_fn, color_fn=color)
        self.grid.export_name = (self.types.get(t, {}).get("title") or t.strip("_")).replace(" ", "_").replace("/", "-")
        self.grid.reset_columns()
        self.status.setText(f"{self.model.total:,} rows")
        if self.model.total:
            self.table.selectRow(0)

    def _row(self, cur, _prev):
        if not self.model or not cur.isValid():
            return
        r = self.model.row(cur.row())
        if r is None:
            return
        raw = r.get("_row")
        if raw:
            fields = [("Type", raw["type"]), ("Time (UTC)", raw["ts"]), ("Time label", raw["ts_label"]), ("User", raw["user"]),
                      ("Source", raw["source"]), ("Tags", raw["tags"])] + [(k, v) for k, v in r.items() if not k.startswith("_")
                                                                           and k not in ("evidence", "ts", "user")]
            self.detail.show_record(raw["summary"] or raw["type"], fields)
        else:
            evl = self.model.value_maps.get("evidence", {})
            items = [(k, evl.get(v, v) if k in ("evidence", "evidence_id") else v) for k, v in r.items()]
            self.detail.show_record(str(r.get("path") or r.get("term") or r.get("event") or ""), items)

    def show_artifact(self, artifact_id: int):
        a = self.case.db.query("SELECT type FROM artifacts WHERE id=?", (artifact_id,))
        if a:
            self.load(self.case, a[0]["type"])


# ============================================================================ coverage
class CoveragePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 18)
        root.addWidget(page_header("Coverage", "Every artifact location the profile examined on each evidence item, and the result."))
        self.ev = QComboBox()
        self.ev.currentIndexChanged.connect(self._fill)
        row = QHBoxLayout()
        row.addWidget(self.ev)
        row.addStretch()
        self.summary = label("", "muted")
        row.addWidget(self.summary)
        root.addLayout(row)
        self.grid = GridView(export_name="coverage")
        self.table = self.grid.table
        root.addWidget(self.grid, 1)
        self.case = None

    def load(self, case):
        self.case = case
        self.model = SqlGridModel(case.db)
        self.grid.set_model(self.model)
        self.grid.export_dir = case.sub("exports")
        self.ev.blockSignals(True)
        self.ev.clear()
        for e in case.db.evidence():
            self.ev.addItem(e["label"], e["id"])
        self.ev.blockSignals(False)
        self._fill()

    def _fill(self):
        if not self.case or self.ev.currentData() is None:
            return
        eid = self.ev.currentData()
        labels = {"found": "Found", "not_found": "Checked - nothing found", "absent": "Not present", "error": "Error", "skipped": "Skipped"}
        cols = [("module", "Module", "text"), ("artifact", "Artifact", "text"), ("location", "Location checked", "path"),
                ("status", "Result", "text"), ("count", "Records", "int"), ("detail", "Notes", "text")]
        self.model.set_source(cols, "coverage", "evidence_id=?", (eid,), value_maps={"status": labels}, order="id",
                              color_fn=lambda r, k: COVERAGE.get(r["status"]) if k == "status" else None)
        self.grid.reset_columns()
        for i, w in enumerate((110, 260, 420, 170, 80)):
            self.table.setColumnWidth(i, w)
        st = {r["status"]: r["n"] for r in self.case.db.query("SELECT status, COUNT(*) n FROM coverage WHERE evidence_id=? GROUP BY status", (eid,))}
        self.summary.setText("   ".join(f"{labels.get(k, k)}: {v}" for k, v in st.items()))


def _clip(text, n: int) -> str:
    """Single line, cut at a word boundary with an ellipsis."""
    t = " ".join((text or "").split())
    if len(t) <= n:
        return t
    return t[:n].rsplit(" ", 1)[0].rstrip(",;:") + " …"


# ============================================================================ report
class ReportPage(QWidget):
    generate = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 18)
        root.setSpacing(14)
        root.addWidget(page_header("Report", "Word report with annotated figures, Excel workbook of every artifact, and a PDF copy "
                                             "when Microsoft Word is available."))
        card = Card()
        row = QHBoxLayout()
        b = IconButton("report", "Generate report now", "primary")
        b.clicked.connect(self.generate.emit)
        row.addWidget(b)
        f = IconButton("folder", "Open reports folder")
        f.clicked.connect(lambda: self.case and open_path(self.case.sub("reports")))
        row.addWidget(f)
        f2 = IconButton("grid", "Parsed artifacts (CSV)")
        f2.setToolTip("Every parsed artifact as CSV for manual review: MFT, USN, SRUM, event logs, registry, browsers ...")
        f2.clicked.connect(lambda: self.case and open_path(self.case.sub("Parsed")))
        row.addWidget(f2)
        f3 = IconButton("database", "Collected raw files")
        f3.setToolTip("Original artifact files copied out of the image, with a hash manifest")
        f3.clicked.connect(lambda: self.case and open_path(self.case.sub("Collected")))
        row.addWidget(f3)
        row.addStretch()
        card.lay.addLayout(row)
        card.lay.addWidget(label("Findings can be excluded from the report on the Findings page. Re-generating creates a new, "
                                 "time-stamped file; earlier versions are kept.", "muted", True))
        root.addWidget(card)
        root.addWidget(label("Generated files", "h2"))
        self.files = QListWidget()
        self.files.itemDoubleClicked.connect(lambda it: open_path(it.data(Qt.UserRole)))
        root.addWidget(self.files, 1)
        self.case = None

    def load(self, case):
        self.case = case
        self.files.clear()
        d = case.sub("reports")
        for fn in sorted(os.listdir(d), reverse=True):
            p = os.path.join(d, fn)
            kind = {"docx": "Word report", "pdf": "PDF report", "xlsx": "Excel workbook", "txt": "Text summary"}.get(fn.rsplit(".", 1)[-1], "File")
            it = QListWidgetItem(f"{kind:16}  {fn}    ({human_size(os.path.getsize(p))})")
            it.setData(Qt.UserRole, p)
            self.files.addItem(it)
