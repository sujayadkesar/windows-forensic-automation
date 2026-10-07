"""Dark and light themes, palette and icon glyphs.

``C`` is the active palette; it is updated in place by :func:`set_mode` so every module that imported it sees the
current colors.  Widgets read ``C`` when they are built, so the main window is rebuilt after a theme switch.
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette

DARK = {
    "bg": "#0B1220", "panel": "#111A2E", "panel2": "#16213A", "card": "#1A2642", "card_hover": "#22305A", "border": "#26345A",
    "text": "#E6ECF5", "title": "#FFFFFF", "muted": "#8EA0BF", "faint": "#5B6B8C", "accent": "#3B82F6", "accent2": "#60A5FA",
    "accent_dark": "#1D4ED8", "ok": "#22C55E", "warn": "#F59E0B", "err": "#EF4444", "info": "#38BDF8", "sel": "#1E3A8A",
    "sel_text": "#FFFFFF", "sidebar": "#0A1020", "disabled_text": "#34415F", "log_bg": "#070C18", "log_text": "#9FB2D4",
    "sel_card": "#1C2C55", "scroll": "#2C3B63", "scroll_hover": "#3B4F82", "primary_disabled": "#2A3B66",
    "danger_bg": "#3B1220", "danger_border": "#7F1D1D", "danger_text": "#FCA5A5", "danger_hover": "#5B1626",
    "filter_bg": "#0E1628",
}
LIGHT = {
    "bg": "#F3F5F9", "panel": "#FFFFFF", "panel2": "#F1F4F9", "card": "#FFFFFF", "card_hover": "#EEF3FC", "border": "#D5DCE8",
    "text": "#1B2333", "title": "#0F172A", "muted": "#55627A", "faint": "#8592A8", "accent": "#2563EB", "accent2": "#1D4ED8",
    "accent_dark": "#1E40AF", "ok": "#15803D", "warn": "#B45309", "err": "#DC2626", "info": "#0369A1", "sel": "#DBEAFE",
    "sel_text": "#0F172A", "sidebar": "#E9EEF6", "disabled_text": "#A3AEC2", "log_bg": "#FBFCFE", "log_text": "#334155",
    "sel_card": "#E0EBFF", "scroll": "#C3CCDB", "scroll_hover": "#9FAEC6", "primary_disabled": "#BFD0F5",
    "danger_bg": "#FDECEC", "danger_border": "#F5B5B5", "danger_text": "#B91C1C", "danger_hover": "#FADADA",
    "filter_bg": "#FFFFFF",
}
C = dict(DARK)
_mode = "dark"

STATUS = {"Yes": "#2563EB", "Indicated": "#0EA5E9", "No evidence found": "#64748B", "Not applicable": "#94A3B8",
          "Inconclusive": "#6366F1"}
COVERAGE = {"found": "#16A34A", "not_found": "#64748B", "absent": "#94A3B8", "error": "#DC2626", "skipped": "#D97706",
            "partial": "#D97706"}

# Segoe Fluent Icons / Segoe MDL2 Assets code points
GLYPH = {
    "home": "\ue80f", "add": "\ue710", "open": "\ue838", "play": "\ue768", "report": "\ue8a5", "search": "\ue721",
    "settings": "\ue713", "list": "\ue8fd", "clock": "\ue823", "shield": "\uea18", "flag": "\ue7c1",
    "folder": "\ue8b7", "usb": "\ue88e", "chart": "\ue9d9", "filter": "\ue71c", "refresh": "\ue72c",
    "cancel": "\ue711", "check": "\ue73e", "error": "\ue783", "warning": "\ue7ba", "info": "\ue946",
    "globe": "\ue774", "mail": "\ue715", "bug": "\uebe8", "lock": "\ue72e", "delete": "\ue74d", "copy": "\ue8c8",
    "view": "\ue890", "page": "\ue7c3", "library": "\ue8f1", "dashboard": "\uf246", "grid": "\ue80a",
    "database": "\ue1d3", "remote": "\ue8af", "fingerprint": "\ue928", "hard_drive": "\ueda2", "people": "\ue716",
    "export": "\uede1", "back": "\ue72b", "next": "\ue72a", "save": "\ue74e", "coverage": "\ue9f9",
    "evidence": "\ue7b8", "key": "\ue8d7", "lightning": "\ue945", "eye": "\ue7b3", "doc": "\ue8a5", "dlp": "\ue8d7",
    "malware": "\uebe8", "phishing": "\ue715", "clickfix": "\ue765", "rmm": "\ue8af", "ransomware": "\ue72e",
    "account": "\ue77b", "triage": "\ue9d9", "antiforensics": "\ue74d", "insider": "\ue716", "theme": "\ue793",
}

_icon_family = None


def icon_family() -> str:
    global _icon_family
    if _icon_family is None:
        fams = set(QFontDatabase.families())
        _icon_family = "Segoe Fluent Icons" if "Segoe Fluent Icons" in fams else (
            "Segoe MDL2 Assets" if "Segoe MDL2 Assets" in fams else "")
    return _icon_family


def icon_font(size: float = 14) -> QFont:
    f = QFont(icon_family() or "Segoe UI")
    f.setPointSizeF(size)
    return f


def glyph(name: str) -> str:
    return GLYPH.get(name, "") if icon_family() else {"home": "H", "add": "+", "open": "O", "play": ">"}.get(name, "*")


def mode() -> str:
    return _mode


def set_mode(m: str) -> None:
    """Switch the active palette ('dark' or 'light'); call :func:`apply` afterwards."""
    global _mode
    _mode = "light" if str(m).lower() == "light" else "dark"
    C.clear()
    C.update(LIGHT if _mode == "light" else DARK)


def apply(app):
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(C["bg"]))
    pal.setColor(QPalette.WindowText, QColor(C["text"]))
    pal.setColor(QPalette.Base, QColor(C["panel"]))
    pal.setColor(QPalette.AlternateBase, QColor(C["panel2"]))
    pal.setColor(QPalette.Text, QColor(C["text"]))
    pal.setColor(QPalette.Button, QColor(C["card"]))
    pal.setColor(QPalette.ButtonText, QColor(C["text"]))
    pal.setColor(QPalette.Highlight, QColor(C["sel"]))
    pal.setColor(QPalette.HighlightedText, QColor(C["sel_text"]))
    pal.setColor(QPalette.ToolTipBase, QColor(C["card"]))
    pal.setColor(QPalette.ToolTipText, QColor(C["text"]))
    pal.setColor(QPalette.PlaceholderText, QColor(C["faint"]))
    pal.setColor(QPalette.Link, QColor(C["accent2"]))
    app.setPalette(pal)
    f = QFont("Segoe UI")
    f.setPointSizeF(9.5)
    app.setFont(f)
    app.setStyleSheet(build_qss())


def build_qss() -> str:
    c = C
    return f"""
* {{ outline: 0; }}
QWidget {{ color: {c['text']}; }}
QMainWindow, QDialog {{ background: {c['bg']}; }}
QToolTip {{ background: {c['card']}; color: {c['text']}; border: 1px solid {c['border']}; padding: 6px; border-radius: 6px; }}
QLabel[role="h1"] {{ font-size: 22pt; font-weight: 600; color: {c['title']}; }}
QLabel[role="h2"] {{ font-size: 14pt; font-weight: 600; color: {c['title']}; }}
QLabel[role="h3"] {{ font-size: 11pt; font-weight: 600; color: {c['text']}; }}
QLabel[role="muted"] {{ color: {c['muted']}; }}
QLabel[role="faint"] {{ color: {c['faint']}; font-size: 8.5pt; }}
QLabel[role="chip"] {{ border-radius: 9px; padding: 2px 9px; font-size: 8.5pt; font-weight: 600; }}
QFrame[role="card"] {{ background: {c['card']}; border: 1px solid {c['border']}; border-radius: 12px; }}
QFrame[role="panel"] {{ background: {c['panel']}; border: 1px solid {c['border']}; border-radius: 10px; }}
QFrame[role="sidebar"] {{ background: {c['sidebar']}; border-right: 1px solid {c['border']}; }}
QFrame[role="topbar"] {{ background: {c['panel']}; border-bottom: 1px solid {c['border']}; }}
QFrame[role="sep"] {{ background: {c['border']}; max-height: 1px; min-height: 1px; }}
QPushButton {{ background: {c['card']}; border: 1px solid {c['border']}; border-radius: 8px; padding: 7px 14px; }}
QPushButton:hover {{ background: {c['card_hover']}; border-color: {c['accent']}; }}
QPushButton:pressed {{ background: {c['sel']}; }}
QPushButton:disabled {{ color: {c['faint']}; background: {c['panel']}; border-color: {c['panel2']}; }}
QPushButton[role="primary"] {{ background: {c['accent']}; border: 1px solid {c['accent']}; color: white; font-weight: 600; }}
QPushButton[role="primary"]:hover {{ background: {c['accent2']}; }}
QPushButton[role="primary"]:disabled {{ background: {c['primary_disabled']}; border-color: {c['primary_disabled']}; color: {c['muted']}; }}
QPushButton[role="danger"] {{ background: {c['danger_bg']}; border-color: {c['danger_border']}; color: {c['danger_text']}; }}
QPushButton[role="danger"]:hover {{ background: {c['danger_hover']}; }}
QPushButton[role="ghost"] {{ background: transparent; border: none; color: {c['muted']}; text-align: left; padding: 8px 10px; }}
QPushButton[role="ghost"]:hover {{ color: {c['title']}; background: {c['panel2']}; }}
QPushButton[role="nav"] {{ background: transparent; border: none; border-radius: 10px; color: {c['muted']}; padding: 9px 10px;
    text-align: left; font-size: 10pt; }}
QPushButton[role="nav"]:hover {{ background: {c['panel2']}; color: {c['title']}; }}
QPushButton[role="nav"]:checked {{ background: {c['sel']}; color: {c['sel_text']}; font-weight: 600; }}
QPushButton[role="nav"]:disabled {{ color: {c['disabled_text']}; }}
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDateTimeEdit, QComboBox {{ background: {c['panel']}; border: 1px solid {c['border']};
    border-radius: 7px; padding: 6px 8px; selection-background-color: {c['accent_dark']}; selection-color: white; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDateTimeEdit:focus {{ border-color: {c['accent']}; }}
QLineEdit[role="colfilter"] {{ background: {c['filter_bg']}; border: 1px solid {c['border']}; border-radius: 4px; padding: 2px 5px;
    font-size: 8.5pt; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {c['panel2']}; border: 1px solid {c['border']}; selection-background-color: {c['sel']};
    selection-color: {c['sel_text']}; }}
QCheckBox, QRadioButton {{ spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 16px; height: 16px; }}
QCheckBox::indicator:unchecked {{ border: 1px solid {c['faint']}; border-radius: 4px; background: {c['panel']}; }}
QCheckBox::indicator:checked {{ border: 1px solid {c['accent']}; border-radius: 4px; background: {c['accent']}; image: none; }}
QTableView, QTreeView, QListView, QTableWidget, QTreeWidget, QListWidget {{ background: {c['panel']}; alternate-background-color: {c['panel2']};
    border: 1px solid {c['border']}; border-radius: 8px; gridline-color: {c['border']}; selection-background-color: {c['sel']};
    selection-color: {c['sel_text']}; }}
QTableView::item, QTreeView::item {{ padding: 3px 6px; }}
QHeaderView::section {{ background: {c['panel2']}; color: {c['muted']}; border: none; border-right: 1px solid {c['border']};
    border-bottom: 1px solid {c['border']}; padding: 6px 8px; font-weight: 600; }}
QTableCornerButton::section {{ background: {c['panel2']}; border: none; }}
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {c['scroll']}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {c['scroll_hover']}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {c['scroll']}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QProgressBar {{ background: {c['panel2']}; border: none; border-radius: 6px; text-align: center; color: {c['title']}; height: 12px;
    font-size: 8pt; }}
QProgressBar::chunk {{ border-radius: 6px; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #38BDF8); }}
QProgressBar[role="big"] {{ height: 22px; border-radius: 11px; font-size: 10pt; font-weight: 600; }}
QProgressBar[role="big"]::chunk {{ border-radius: 11px; }}
QTabWidget::pane {{ border: 1px solid {c['border']}; border-radius: 8px; top: -1px; background: {c['panel']}; }}
QTabBar::tab {{ background: transparent; color: {c['muted']}; padding: 8px 16px; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {c['title']}; border-bottom: 2px solid {c['accent']}; }}
QTabBar::tab:hover {{ color: {c['title']}; }}
QSplitter::handle {{ background: {c['bg']}; }}
QSplitter::handle:horizontal {{ width: 6px; }}
QSplitter::handle:vertical {{ height: 6px; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QMenu {{ background: {c['panel2']}; border: 1px solid {c['border']}; padding: 4px; border-radius: 8px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 5px; }}
QMenu::item:selected {{ background: {c['sel']}; color: {c['sel_text']}; }}
QStatusBar {{ background: {c['panel']}; color: {c['muted']}; border-top: 1px solid {c['border']}; }}
QGroupBox {{ border: 1px solid {c['border']}; border-radius: 10px; margin-top: 14px; padding: 12px 10px 10px 10px; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {c['muted']}; }}
"""


# backwards compatible name
QSS = build_qss()
