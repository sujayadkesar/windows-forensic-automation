"""Artifact grid: per-column filters, column sorting and export of the current view (like commercial review tools).

Filtering and sorting are translated to SQL, so the grid stays fast on tables with millions of rows (MFT, USN journal).

Column filter syntax (case-insensitive):
    text        contains text                       !text       does not contain text
    =text       equals text                         =           empty
    >x  >=x     greater than (dates as YYYY-MM-DD)   <x  <=x     less than
    a | b       contains a OR contains b
"""

from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime, timezone

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox,
                               QPushButton, QTableView, QVBoxLayout, QWidget)


PAGE = 500


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class SqlGridModel(QAbstractTableModel):
    """Lazy SQLite model.  ``columns`` = [(key, title, kind)]; ``exprs`` maps a key to the SQL expression of that column
    (default: the key itself); ``value_maps`` maps a key to {raw value: display text} for derived columns."""

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.columns: list[tuple[str, str, str]] = []
        self.table = ""
        self.where = "1=1"
        self.params: list = []
        self.exprs: dict[str, str] = {}
        self.value_maps: dict[str, dict] = {}
        self.default_order = ""
        self.row_fn = None
        self.color_fn = None
        self.filters: dict[int, str] = {}
        self.sort_col: int | None = None
        self.sort_order = Qt.AscendingOrder
        self.total = 0
        self.cache: dict[int, list] = {}
        self.error = ""

    # ------------------------------------------------------------------ configuration
    def set_source(self, columns, table: str, where: str = "1=1", params=(), exprs=None, value_maps=None, order: str = "",
                   row_fn=None, color_fn=None):
        self.beginResetModel()
        self.columns = list(columns)
        self.table, self.where, self.params = table, where or "1=1", list(params)
        self.exprs = exprs or {}
        self.value_maps = value_maps or {}
        self.default_order = order
        self.row_fn, self.color_fn = row_fn, color_fn
        self.filters = {}
        self.sort_col = None
        self._refresh()
        self.endResetModel()

    def expr(self, key: str) -> str:
        return self.exprs.get(key) or key

    def set_filter(self, col: int, text: str):
        text = (text or "").strip()
        if text:
            self.filters[col] = text
        else:
            self.filters.pop(col, None)
        self.beginResetModel()
        self._refresh()
        self.endResetModel()

    def clear_filters(self):
        self.filters = {}
        self.beginResetModel()
        self._refresh()
        self.endResetModel()

    def sort(self, column: int, order=Qt.AscendingOrder):  # noqa: D401 - Qt override
        self.sort_col, self.sort_order = column, order
        self.beginResetModel()
        self.cache = {}
        self.endResetModel()

    # ------------------------------------------------------------------ SQL
    def _clause(self, key: str, kind: str, text: str):
        e = self.expr(key)
        vmap = self.value_maps.get(key)
        if vmap:
            t = text.lstrip("=!").lower()
            raws = [r for r, disp in vmap.items() if (disp or "").lower() == t] if text.startswith("=") else \
                [r for r, disp in vmap.items() if t in (disp or "").lower()]
            if not raws:
                return ("1=1", []) if text.startswith("!") else ("0=1", [])
            ph = ",".join("?" * len(raws))
            return (f"({e} NOT IN ({ph}) OR {e} IS NULL)" if text.startswith("!") else f"{e} IN ({ph})"), raws
        if "|" in text and not text.startswith(("=", "!", ">", "<")):
            parts = [p.strip() for p in text.split("|") if p.strip()]
            return "(" + " OR ".join(f"CAST({e} AS TEXT) LIKE ? ESCAPE '\\'" for _ in parts) + ")", \
                [f"%{_like_escape(p)}%" for p in parts]
        num = kind in ("int", "size")
        for op in (">=", "<=", ">", "<"):
            if text.startswith(op):
                v = text[len(op):].strip()
                if num:
                    try:
                        return f"CAST({e} AS REAL) {op} ?", [float(v)]
                    except ValueError:
                        return "0=1", []
                return f"{e} {op} ?", [v]
        if text == "=":
            return f"({e} IS NULL OR CAST({e} AS TEXT) = '')", []
        if text.startswith("="):
            return f"lower(CAST({e} AS TEXT)) = lower(?)", [text[1:].strip()]
        if text.startswith("!"):
            return f"({e} IS NULL OR CAST({e} AS TEXT) NOT LIKE ? ESCAPE '\\')", [f"%{_like_escape(text[1:].strip())}%"]
        return f"CAST({e} AS TEXT) LIKE ? ESCAPE '\\'", [f"%{_like_escape(text)}%"]

    def _where(self):
        parts, params = [f"({self.where})"], list(self.params)
        for col, text in self.filters.items():
            if col < len(self.columns):
                key, _t, kind = self.columns[col]
                sql, p = self._clause(key, kind, text)
                parts.append(sql)
                params += p
        return " AND ".join(parts), params

    def _order(self):
        if self.sort_col is not None and self.sort_col < len(self.columns):
            key, _t, kind = self.columns[self.sort_col]
            e = self.expr(key)
            if kind in ("int", "size"):
                e = f"CAST({e} AS REAL)"
            d = "ASC" if self.sort_order == Qt.AscendingOrder else "DESC"
            return f" ORDER BY {e} IS NULL, {e} {d}"
        return f" ORDER BY {self.default_order}" if self.default_order else ""

    def select_sql(self):
        w, p = self._where()
        return f"SELECT * FROM {self.table} WHERE {w}{self._order()}", p

    def _refresh(self):
        self.cache = {}
        self.error = ""
        w, p = self._where()
        try:
            self.total = self.db.scalar(f"SELECT COUNT(*) FROM {self.table} WHERE {w}", p) or 0
        except Exception as e:  # malformed filter value
            self.total = 0
            self.error = str(e)

    # ------------------------------------------------------------------ data
    def rowCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else self.total

    def columnCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(self.columns)

    def _page(self, n):
        if n not in self.cache:
            sql, p = self.select_sql()
            try:
                rows = self.db.query(sql + f" LIMIT {PAGE} OFFSET {n * PAGE}", p)
            except Exception as e:
                self.error = str(e)
                rows = []
            self.cache[n] = [self.row_fn(r) if self.row_fn else r for r in rows]
            if len(self.cache) > 40:
                self.cache.pop(next(iter(self.cache)))
        return self.cache[n]

    def row(self, r: int) -> dict | None:
        page = self._page(r // PAGE)
        i = r % PAGE
        return page[i] if i < len(page) else None

    def display(self, rec: dict, key: str, kind: str, full: bool = False) -> str:
        v = rec.get(key)
        if v is None:
            return ""
        if key in self.value_maps and not isinstance(v, str):
            v = self.value_maps[key].get(v, v)
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False, default=str)
        s = str(v)
        if not full:
            if kind == "datetime" and len(s) >= 19:
                s = s[:19]
            if kind == "size" and isinstance(v, (int, float)):
                from .widgets import human_size

                s = human_size(v)
        return s

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        rec = self.row(index.row())
        if rec is None:
            return None
        key, _, kind = self.columns[index.column()]
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            s = self.display(rec, key, kind, full=role == Qt.ToolTipRole)
            if role == Qt.DisplayRole and len(s) > 300:
                s = s[:300] + "..."
            return s
        if role == Qt.ForegroundRole and self.color_fn:
            col = self.color_fn(rec, key)
            if col:
                return QColor(col)
        if role == Qt.FontRole and kind == "hash":
            f = QFont("Consolas")
            f.setPointSizeF(9)
            return f
        if role == Qt.TextAlignmentRole and kind in ("int", "size"):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and section < len(self.columns):
            if role == Qt.DisplayRole:
                return self.columns[section][1] + ("  ●" if section in self.filters else "")
            if role == Qt.ToolTipRole:
                return f"{self.columns[section][1]} - click to sort; type in the box below to filter" + (
                    f"\nActive filter: {self.filters[section]}" if section in self.filters else "")
        return None

    def iter_all(self, batch: int = 5000):
        """Every row of the current view (filters + sort), for export."""
        sql, p = self.select_sql()
        off = 0
        while True:
            rows = self.db.query(sql + f" LIMIT {batch} OFFSET {off}", p)
            if not rows:
                return
            for r in rows:
                yield self.row_fn(r) if self.row_fn else r
            off += batch

    def describe_filters(self) -> str:
        return "; ".join(f"{self.columns[c][1]}: {t}" for c, t in sorted(self.filters.items()) if c < len(self.columns)) or "none"


class FilterHeader(QHeaderView):
    """Horizontal header with a filter box under every column title."""

    filterChanged = Signal(int, str)

    def __init__(self, view: QTableView):
        super().__init__(Qt.Horizontal, view)
        self.editors: list[QLineEdit] = []
        self.pad = 4
        self.setSectionsClickable(True)
        self.setSortIndicatorShown(True)
        self.setHighlightSections(False)
        self.setStretchLastSection(True)
        self.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.sectionResized.connect(self.adjust)
        self.sectionMoved.connect(self.adjust)
        view.horizontalScrollBar().valueChanged.connect(self.adjust)
        self._timers: dict[int, QTimer] = {}

    def set_columns(self, n: int, values: dict | None = None):
        for e in self.editors:
            e.hide()  # deleteLater only runs when the event loop is idle: hide/detach now so no stale box remains
            e.setParent(None)
            e.deleteLater()
        self.editors = []
        self._timers = {}
        for i in range(n):
            e = QLineEdit(self.viewport().parent())
            e.setProperty("role", "colfilter")
            e.setPlaceholderText("Filter")
            e.setToolTip(__doc__.split("Column filter syntax")[1].strip() if __doc__ else "")
            e.setClearButtonEnabled(True)
            if values and i in values:
                e.setText(values[i])
            t = QTimer(self)
            t.setSingleShot(True)
            t.setInterval(450)
            t.timeout.connect(lambda i=i: self.filterChanged.emit(i, self.editors[i].text()))
            e.textChanged.connect(t.start)
            e.returnPressed.connect(lambda i=i: (self._timers[i].stop(), self.filterChanged.emit(i, self.editors[i].text())))
            self._timers[i] = t
            e.show()
            self.editors.append(e)
        self.updateGeometries()
        self.adjust()

    def clear(self):
        for e in self.editors:
            e.blockSignals(True)
            e.clear()
            e.blockSignals(False)

    def sizeHint(self):  # noqa: N802
        s = super().sizeHint()
        if self.editors:
            s.setHeight(s.height() + self.editors[0].sizeHint().height() + self.pad)
        return s

    def updateGeometries(self):  # noqa: N802
        if self.editors:
            self.setViewportMargins(0, 0, 0, self.editors[0].sizeHint().height() + self.pad)
        else:
            self.setViewportMargins(0, 0, 0, 0)
        super().updateGeometries()
        self.adjust()

    def adjust(self, *_):
        if not self.editors:
            return
        base = super().sizeHint().height()
        for i, e in enumerate(self.editors):
            h = e.sizeHint().height()
            e.setGeometry(self.sectionViewportPosition(i) + 2, base + self.pad // 2, max(20, self.sectionSize(i) - 4), h)
            e.setVisible(not self.isSectionHidden(i))


class GridView(QWidget):
    """Table with filter header, sorting, column menu and export of the current view."""

    rowActivated = Signal(int)

    def __init__(self, parent=None, export_name: str = "artifacts"):
        super().__init__(parent)
        self.export_name = export_name
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        bar = QHBoxLayout()
        self.info = QLabel("")
        self.info.setProperty("role", "muted")
        bar.addWidget(self.info, 1)
        self.clear_btn = QPushButton("Clear filters")
        self.clear_btn.clicked.connect(self.clear_filters)
        bar.addWidget(self.clear_btn)
        self.cols_btn = QPushButton("Columns")
        self.cols_btn.clicked.connect(self._columns_menu)
        bar.addWidget(self.cols_btn)
        self.export_btn = QPushButton("Export view")
        m = QMenu(self)
        for label, fmt in (("CSV (.csv)", "csv"), ("Excel (.xlsx)", "xlsx"), ("JSON (.json)", "json"), ("HTML table (.html)", "html"),
                           ("Tab separated (.tsv)", "tsv")):
            m.addAction(label, lambda f=fmt: self.export(f))
        m.addSeparator()
        m.addAction("Selected rows to CSV", lambda: self.export("csv", selected_only=True))
        self.export_btn.setMenu(m)
        bar.addWidget(self.export_btn)
        lay.addLayout(bar)
        self.table = QTableView()
        self.header = FilterHeader(self.table)
        self.table.setHorizontalHeader(self.header)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.verticalHeader().hide()
        self.table.setWordWrap(False)
        self.table.setSortingEnabled(False)  # sorting handled by the SQL model through the header
        self.header.sectionClicked.connect(self._sort_clicked)
        self.header.filterChanged.connect(self._filter_changed)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(lambda idx: self.rowActivated.emit(idx.row()))
        lay.addWidget(self.table, 1)
        self.model: SqlGridModel | None = None
        self._sort = (None, Qt.AscendingOrder)

    def set_model(self, model: SqlGridModel):
        self.model = model
        self.table.setModel(model)
        self.reset_columns()

    def reset_columns(self):
        """Call after model.set_source(): new filter boxes, default widths."""
        if not self.model:
            return
        self.header.set_columns(len(self.model.columns))
        self.header.setSortIndicator(-1, Qt.AscendingOrder)
        self._sort = (None, Qt.AscendingOrder)
        widths = {"text": 140, "datetime": 150, "path": 360, "hash": 300, "int": 80, "size": 90, "url": 360}
        for i, (_k, _t, kind) in enumerate(self.model.columns):
            self.table.setColumnWidth(i, widths.get(kind, 140))
        self._update_info()

    def _update_info(self):
        if not self.model:
            return
        txt = f"{self.model.total:,} rows"
        if self.model.filters:
            txt += f"  -  filtered by {self.model.describe_filters()}"
        if self._sort[0] is not None:
            txt += f"  -  sorted by {self.model.columns[self._sort[0]][1]} ({'asc' if self._sort[1] == Qt.AscendingOrder else 'desc'})"
        if self.model.error:
            txt += f"  -  filter error: {self.model.error[:80]}"
        self.info.setText(txt)

    def _filter_changed(self, col, text):
        self.model.set_filter(col, text)
        self.header.adjust()
        self._update_info()
        self._select_first()

    def _select_first(self):
        if self.model and self.model.total:
            self.table.selectRow(0)

    def clear_filters(self):
        if self.model:
            self.header.clear()
            self.model.clear_filters()
            self._update_info()
            self._select_first()

    def _sort_clicked(self, col):
        cur, order = self._sort
        order = Qt.DescendingOrder if cur == col and order == Qt.AscendingOrder else Qt.AscendingOrder
        self._sort = (col, order)
        self.header.setSortIndicator(col, order)
        self.model.sort(col, order)
        self._update_info()
        self._select_first()

    def _columns_menu(self):
        if not self.model:
            return
        m = QMenu(self)
        for i, (_k, title, _kind) in enumerate(self.model.columns):
            a = m.addAction(title)
            a.setCheckable(True)
            a.setChecked(not self.table.isColumnHidden(i))
            a.toggled.connect(lambda on, i=i: (self.table.setColumnHidden(i, not on), self.header.adjust()))
        m.exec(self.cols_btn.mapToGlobal(self.cols_btn.rect().bottomLeft()))

    def _menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        from PySide6.QtWidgets import QApplication

        m = QMenu(self)
        key, title, kind = self.model.columns[idx.column()]
        rec = self.model.row(idx.row()) or {}
        val = self.model.display(rec, key, kind, full=True)
        m.addAction("Copy cell", lambda: QApplication.clipboard().setText(val))
        m.addAction("Copy selected rows", self._copy_rows)
        m.addSeparator()
        short = (val[:40] + "...") if len(val) > 40 else val
        m.addAction(f"Filter: {title} = '{short}'", lambda: self._set_filter(idx.column(), "=" + val))
        m.addAction(f"Filter: {title} contains '{short}'", lambda: self._set_filter(idx.column(), val))
        m.addAction(f"Exclude: {title} contains '{short}'", lambda: self._set_filter(idx.column(), "!" + val))
        m.addSeparator()
        m.addAction("Export selected rows to CSV", lambda: self.export("csv", selected_only=True))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _set_filter(self, col, text):
        if col < len(self.header.editors):
            self.header.editors[col].setText(text)
        self._filter_changed(col, text)

    def _copy_rows(self):
        from PySide6.QtWidgets import QApplication

        rows = sorted({i.row() for i in self.table.selectionModel().selectedIndexes()})
        out = ["\t".join(t for _k, t, _ in self.model.columns)]
        for r in rows:
            rec = self.model.row(r) or {}
            out.append("\t".join(self.model.display(rec, k, kind, full=True) for k, _t, kind in self.model.columns))
        QApplication.clipboard().setText("\n".join(out))

    # ------------------------------------------------------------------ export
    def export(self, fmt: str, selected_only: bool = False):
        if not self.model or not self.model.columns:
            return
        ext = {"xlsx": "xlsx", "json": "json", "html": "html", "tsv": "tsv"}.get(fmt, "csv")
        default = f"{self.export_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        start_dir = getattr(self, "export_dir", "") or os.path.expanduser("~")
        path, _ = QFileDialog.getSaveFileName(self, "Export current view", os.path.join(start_dir, default),
                                              f"{ext.upper()} (*.{ext})")
        if not path:
            return
        if selected_only:
            sel = sorted({i.row() for i in self.table.selectionModel().selectedIndexes()})
            rows = (self.model.row(r) for r in sel)
        else:
            rows = self.model.iter_all()
        visible = [i for i in range(len(self.model.columns)) if not self.table.isColumnHidden(i)]
        try:
            n = export_rows(path, fmt, [self.model.columns[i] for i in visible], rows, self.model,
                            title=self.export_name.replace("_", " "), filters=self.model.describe_filters())
        except Exception as e:
            QMessageBox.critical(self, "Export failed", f"{type(e).__name__}: {e}")
            return
        QMessageBox.information(self, "Export complete", f"{n:,} rows written to\n{path}")


def export_rows(path: str, fmt: str, columns, rows, model: SqlGridModel, title: str = "", filters: str = "none") -> int:
    """Write rows (dicts) with the given columns.  Values are exported in full (no truncation)."""
    titles = [t for _k, t, _kind in columns]

    def values(rec):
        return [model.display(rec, k, kind, full=True) for k, _t, kind in columns]

    n = 0
    if fmt in ("csv", "tsv"):
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh, delimiter="\t" if fmt == "tsv" else ",")
            w.writerow(titles)
            for rec in rows:
                if rec is None:
                    continue
                w.writerow(values(rec))
                n += 1
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("[\n")
            for rec in rows:
                if rec is None:
                    continue
                fh.write((",\n" if n else "") + json.dumps(dict(zip(titles, values(rec))), ensure_ascii=False))
                n += 1
            fh.write("\n]\n")
    elif fmt == "xlsx":
        import xlsxwriter

        wb = xlsxwriter.Workbook(path, {"constant_memory": True, "strings_to_urls": False})
        hdr = wb.add_format({"bold": True, "font_color": "#FFFFFF", "bg_color": "#1F3864", "border": 1, "border_color": "#A6A6A6"})
        cell = wb.add_format({"border": 1, "border_color": "#D9D9D9"})
        ws, r, sheet_no = None, 0, 0
        for rec in rows:
            if rec is None:
                continue
            if ws is None or r >= 1_048_575:
                sheet_no += 1
                ws = wb.add_worksheet(f"View{'' if sheet_no == 1 else f' {sheet_no}'}")
                for i, t in enumerate(titles):
                    ws.write(0, i, t, hdr)
                    ws.set_column(i, i, {"datetime": 20, "path": 60, "hash": 66, "int": 10, "size": 12}.get(columns[i][2], 24))
                ws.freeze_panes(1, 0)
                r = 1
            for i, v in enumerate(values(rec)):
                ws.write_string(r, i, v[:32000], cell)
            r += 1
            n += 1
        if ws is None:
            ws = wb.add_worksheet("View")
            for i, t in enumerate(titles):
                ws.write(0, i, t, hdr)
        else:
            ws.autofilter(0, 0, max(0, r - 1), len(titles) - 1)
        meta = wb.add_worksheet("Export info")
        for i, (k, v) in enumerate((("View", title), ("Filters", filters), ("Rows", str(n)),
                                    ("Exported (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))):
            meta.write(i, 0, k, hdr)
            meta.write(i, 1, v)
        meta.set_column(0, 0, 18)
        meta.set_column(1, 1, 80)
        wb.close()
    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("<!doctype html><html><head><meta charset='utf-8'><title>" + html.escape(title) + "</title><style>"
                     "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b2333}"
                     "h1{font-size:18px;color:#1f3864}p{color:#55627a;font-size:12px}"
                     "table{border-collapse:collapse;font-size:12px}"
                     "th{background:#1f3864;color:#fff;text-align:left;padding:6px 8px;border:1px solid #a6a6a6;position:sticky;top:0}"
                     "td{padding:4px 8px;border:1px solid #d9d9d9;vertical-align:top;white-space:pre-wrap}"
                     "tr:nth-child(even) td{background:#f2f6fc}</style></head><body>")
            fh.write(f"<h1>{html.escape(title)}</h1><p>Filters: {html.escape(filters)} &nbsp;|&nbsp; Exported "
                     f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</p><table><thead><tr>")
            fh.write("".join(f"<th>{html.escape(t)}</th>" for t in titles) + "</tr></thead><tbody>")
            for rec in rows:
                if rec is None:
                    continue
                fh.write("<tr>" + "".join(f"<td>{html.escape(v)}</td>" for v in values(rec)) + "</tr>\n")
                n += 1
            fh.write(f"</tbody></table><p>{n:,} rows</p></body></html>")
    return n
