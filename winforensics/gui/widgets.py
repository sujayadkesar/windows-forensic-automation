"""Reusable widgets and models."""

from __future__ import annotations

import json

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QTextBrowser, QVBoxLayout, QWidget)

from . import theme
from .theme import C


def label(text="", role=None, wrap=False, selectable=False) -> QLabel:
    lb = QLabel(text)
    if role:
        lb.setProperty("role", role)
    lb.setWordWrap(wrap)
    if selectable:
        lb.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lb


def icon_label(name: str, size: float = 14, color: str | None = None) -> QLabel:
    lb = QLabel(theme.glyph(name))
    lb.setFont(theme.icon_font(size))
    if color:
        lb.setStyleSheet(f"color: {color};")
    lb.setAlignment(Qt.AlignCenter)
    return lb


def button(text: str, icon: str | None = None, role: str | None = None, tooltip: str = "") -> QPushButton:
    """Plain text button; use :class:`IconButton` when a glyph is wanted."""
    if icon:
        return IconButton(icon, text, role)
    b = QPushButton(text)
    if role:
        b.setProperty("role", role)
    if tooltip:
        b.setToolTip(tooltip)
    b.setCursor(Qt.PointingHandCursor)
    return b


class IconButton(QPushButton):
    """Button with an icon glyph (icon font) and a text label."""

    def __init__(self, icon: str, text: str = "", role: str | None = None, size: float = 11, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(9)
        self.ic = QLabel(theme.glyph(icon))
        self.ic.setFont(theme.icon_font(size))
        self.ic.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.tx = QLabel(text)
        self.tx.setAttribute(Qt.WA_TransparentForMouseEvents)
        lay.addWidget(self.ic)
        if text:
            lay.addWidget(self.tx)
        lay.addStretch()
        if role:
            self.setProperty("role", role)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(36)
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        fm = self.fontMetrics()
        self.setMinimumWidth(fm.horizontalAdvance(text) + 60 if text else 40)

    def setText(self, text):  # noqa: N802
        self.tx.setText(text)

    def sizeHint(self):  # noqa: N802
        return QSize(self.fontMetrics().horizontalAdvance(self.tx.text()) + 64, 36)


class NavButton(QPushButton):
    def __init__(self, icon: str, text: str, parent=None):
        super().__init__(parent)
        self.setProperty("role", "nav")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 10, 0)
        lay.setSpacing(12)
        self.ic = QLabel(theme.glyph(icon))
        self.ic.setFont(theme.icon_font(13))
        self.ic.setFixedWidth(22)
        self.tx = QLabel(text)
        self.badge = QLabel("")
        self.badge.setStyleSheet(f"background:{C['accent']}; color:white; border-radius:8px; padding:1px 7px; font-size:8pt;")
        self.badge.hide()
        for w in (self.ic, self.tx, self.badge):
            w.setAttribute(Qt.WA_TransparentForMouseEvents)
        lay.addWidget(self.ic)
        lay.addWidget(self.tx)
        lay.addStretch()
        lay.addWidget(self.badge)
        self.setMinimumHeight(42)
        self.toggled.connect(self._restyle)
        self._restyle(False)

    def _restyle(self, on):
        col = C["title"] if on else C["muted"]
        self.ic.setStyleSheet(f"color:{C['accent2'] if on else C['muted']}; background:transparent;")
        self.tx.setStyleSheet(f"color:{col}; background:transparent; font-weight:{600 if on else 400};")

    def set_badge(self, text: str | None, color: str | None = None):
        if text:
            self.badge.setText(text)
            if color:
                self.badge.setStyleSheet(f"background:{color}; color:white; border-radius:8px; padding:1px 7px; font-size:8pt;")
            self.badge.show()
        else:
            self.badge.hide()

    def changeEvent(self, e):  # noqa: N802
        super().changeEvent(e)
        if not self.isEnabled():
            self.ic.setStyleSheet(f"color:{C['disabled_text']};")
            self.tx.setStyleSheet(f"color:{C['disabled_text']};")
        else:
            self._restyle(self.isChecked())


class Card(QFrame):
    clicked = Signal()

    def __init__(self, parent=None, role="card", clickable=False):
        super().__init__(parent)
        self.setProperty("role", role)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(8)
        self._clickable = clickable
        if clickable:
            self.setCursor(Qt.PointingHandCursor)

    def mouseReleaseEvent(self, e):  # noqa: N802
        if self._clickable and e.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(e)


def chip(text: str, color: str, filled=True) -> QLabel:
    lb = QLabel(text)
    lb.setProperty("role", "chip")
    if filled:
        lb.setStyleSheet(f"background:{color}; color:white; border-radius:9px; padding:2px 9px; font-size:8.5pt; font-weight:600;")
    else:
        lb.setStyleSheet(f"border:1px solid {color}; color:{color}; border-radius:9px; padding:1px 8px; font-size:8.5pt; font-weight:600;")
    lb.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
    return lb


def separator() -> QFrame:
    f = QFrame()
    f.setProperty("role", "sep")
    return f


def stat_tile(title: str, value: str, color: str = C["accent2"], icon: str = "chart") -> Card:
    c = Card()
    c.lay.setSpacing(2)
    top = QHBoxLayout()
    top.addWidget(label(title, "muted"))
    top.addStretch()
    top.addWidget(icon_label(icon, 12, color))
    c.lay.addLayout(top)
    v = QLabel(value)
    v.setStyleSheet(f"font-size: 22pt; font-weight: 600; color: {color};")
    c.lay.addWidget(v)
    c.value_label = v
    return c


# ============================================================================ SQL backed table model
class SqlTableModel(QAbstractTableModel):
    """Lazily fetches rows from SQLite in pages (handles millions of rows)."""

    PAGE = 500

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.columns: list[tuple[str, str, str]] = []  # (key, title, kind)
        self.sql = ""
        self.params: tuple = ()
        self.total = 0
        self.cache: dict[int, list] = {}
        self.row_fn = None
        self.color_fn = None

    def set_query(self, columns, sql_select: str, sql_count: str, params=(), row_fn=None, color_fn=None):
        self.beginResetModel()
        self.columns = columns
        self.sql = sql_select
        self.params = tuple(params)
        self.row_fn = row_fn
        self.color_fn = color_fn
        self.cache = {}
        try:
            self.total = self.db.scalar(sql_count, self.params) or 0
        except Exception:
            self.total = 0
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else self.total

    def columnCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(self.columns)

    def _page(self, p):
        if p not in self.cache:
            rows = self.db.query(self.sql + f" LIMIT {self.PAGE} OFFSET {p * self.PAGE}", self.params)
            self.cache[p] = [self.row_fn(r) if self.row_fn else r for r in rows]
            if len(self.cache) > 40:
                self.cache.pop(next(iter(self.cache)))
        return self.cache[p]

    def row(self, r: int) -> dict | None:
        page = self._page(r // self.PAGE)
        i = r % self.PAGE
        return page[i] if i < len(page) else None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        rec = self.row(index.row())
        if rec is None:
            return None
        key, _, kind = self.columns[index.column()]
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            v = rec.get(key)
            if v is None:
                return ""
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False, default=str)
            s = str(v)
            if kind == "datetime" and len(s) >= 19:
                s = s[:19]
            if kind == "size" and isinstance(v, (int, float)):
                s = human_size(v)
            if role == Qt.DisplayRole and len(s) > 300:
                s = s[:300] + "..."
            return s
        if role == Qt.ForegroundRole and self.color_fn:
            col = self.color_fn(rec, key)
            if col:
                return QColor(col)
        if role == Qt.FontRole and kind in ("hash",):
            f = QFont("Consolas")
            f.setPointSizeF(9)
            return f
        if role == Qt.TextAlignmentRole and kind in ("int", "size"):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal and section < len(self.columns):
            return self.columns[section][1]
        return None


def human_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


class DetailView(QTextBrowser):
    """Key / value rendering of a record."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(False)
        self.setStyleSheet(f"QTextBrowser {{ background:{C['panel']}; border:1px solid {C['border']}; border-radius:8px; padding:8px; }}")

    def show_record(self, title: str, fields: list[tuple[str, object]]):
        rows = []
        for k, v in fields:
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                v = json.dumps(v, indent=1, ensure_ascii=False, default=str)
                v = f"<pre style='margin:0;white-space:pre-wrap;font-family:Consolas;font-size:8.5pt'>{_esc(v)}</pre>"
            else:
                v = _esc(str(v))
            rows.append(f"<tr><td style='color:{C['muted']};padding:3px 12px 3px 0;vertical-align:top;white-space:nowrap'>{_esc(k)}</td>"
                        f"<td style='padding:3px 0;color:{C['text']}'>{v}</td></tr>")
        self.setHtml(f"<div style='font-family:Segoe UI;font-size:9.5pt'><div style='font-size:11pt;font-weight:600;color:white;"
                     f"margin-bottom:8px'>{_esc(title)}</div><table cellspacing=0>{''.join(rows)}</table></div>")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class EmptyState(QWidget):
    def __init__(self, icon: str, title: str, text: str, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.addStretch()
        ic = icon_label(icon, 34, C["faint"])
        lay.addWidget(ic)
        t = label(title, "h3")
        t.setAlignment(Qt.AlignCenter)
        lay.addWidget(t)
        d = label(text, "muted", wrap=True)
        d.setAlignment(Qt.AlignCenter)
        lay.addWidget(d)
        lay.addStretch()
