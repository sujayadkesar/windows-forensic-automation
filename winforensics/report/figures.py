"""Render figure specifications into annotated, screenshot-like PNG images.

Styles
    app       - a Windows Forensic Automation results grid (window chrome, toolbar, grid, status bar)
    table     - a plain formatted table (colored header, cell borders, zebra rows) - 'excel' is an alias
    eventlog  - event log viewer (event list + every field of the selected record)
    registry  - registry viewer (key path, key tree, values read from the hive, key last-written time)

Every value drawn comes from the figure specification, which analyzers build from parsed records; renderers never
add rows, values or icons of their own.
    hex       - hex viewer with the keyword hit boxed
    timeline  - swim-lane chart of USB sessions and events per system

Annotations follow the hand-annotated screenshot convention (Flameshot / Snagit):
red rounded rectangles around the relevant cells, numbered red badges and callout
boxes in a gutter on the right with arrows pointing at the boxed cells.

Rendering uses QPainter on QImage (thread safe, no widgets needed); a
QGuiApplication (offscreen platform if needed) must exist.
"""

from __future__ import annotations

import os
from datetime import datetime

S = 3  # device pixel ratio of the output images (3x = ~450 dpi at print size)

RED = (225, 29, 42)
FONT_UI = "Segoe UI"
FONT_XL = "Calibri"
FONT_MONO = "Consolas"


def ensure_app():
    from PySide6.QtGui import QGuiApplication

    app = QGuiApplication.instance()
    if app is None:
        if os.name != "nt":
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        elif os.environ.get("QT_QPA_PLATFORM") == "offscreen":
            os.environ.setdefault("QT_QPA_FONTDIR", os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
        app = QGuiApplication(["winforensics-report"])
    return app


# ============================================================================ low level helpers
class Canvas:
    def __init__(self, w: int, h: int, bg=(255, 255, 255)):
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QColor, QImage, QPainter

        self.w, self.h = w, h
        self.img = QImage(w * S, h * S, QImage.Format_ARGB32)
        self.img.fill(QColor(*bg))
        self.p = QPainter(self.img)
        self.p.setRenderHint(QPainter.Antialiasing, True)
        self.p.setRenderHint(QPainter.TextAntialiasing, True)
        self.p.scale(S, S)
        self.Qt = Qt

    def font(self, family=FONT_UI, size=9.0, bold=False, italic=False):
        from PySide6.QtGui import QFont

        f = QFont(family)
        f.setPointSizeF(size)
        f.setBold(bold)
        f.setItalic(italic)
        f.setHintingPreference(QFont.PreferNoHinting)
        return f

    def rect(self, x, y, w, h, fill=None, border=None, width=1.0, radius=0):
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QBrush, QColor, QPen

        self.p.setPen(QPen(QColor(*border), width) if border else self.Qt.NoPen)
        self.p.setBrush(QBrush(QColor(*fill)) if fill else self.Qt.NoBrush)
        r = QRectF(x, y, w, h)
        if radius:
            self.p.drawRoundedRect(r, radius, radius)
        else:
            self.p.drawRect(r)

    def gradient(self, x, y, w, h, top, bottom):
        from PySide6.QtCore import QPointF, QRectF
        from PySide6.QtGui import QBrush, QColor, QLinearGradient

        g = QLinearGradient(QPointF(x, y), QPointF(x, y + h))
        g.setColorAt(0, QColor(*top))
        g.setColorAt(1, QColor(*bottom))
        self.p.setPen(self.Qt.NoPen)
        self.p.setBrush(QBrush(g))
        self.p.drawRect(QRectF(x, y, w, h))

    def line(self, x1, y1, x2, y2, color=(200, 200, 200), width=1.0):
        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QColor, QPen

        self.p.setPen(QPen(QColor(*color), width))
        self.p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

    def text(self, x, y, w, h, s, font=None, color=(30, 30, 30), align="left", elide=True, valign="center"):
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QColor, QFontMetricsF

        f = font or self.font()
        self.p.setFont(f)
        self.p.setPen(QColor(*color))
        s = "" if s is None else str(s).replace("\n", " ").replace("\r", " ")
        if elide:
            fm = QFontMetricsF(f)
            s = fm.elidedText(s, self.Qt.ElideRight, max(0.0, w))
        flags = {"left": self.Qt.AlignLeft, "right": self.Qt.AlignRight, "center": self.Qt.AlignHCenter}[align]
        flags |= {"center": self.Qt.AlignVCenter, "top": self.Qt.AlignTop}[valign]
        self.p.drawText(QRectF(x, y, w, h), int(flags), s)

    def wrapped(self, x, y, w, h, s, font=None, color=(30, 30, 30)):
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QColor

        self.p.setFont(font or self.font())
        self.p.setPen(QColor(*color))
        self.p.drawText(QRectF(x, y, w, h), int(self.Qt.AlignLeft | self.Qt.AlignTop | self.Qt.TextWordWrap), str(s or ""))

    def text_width(self, s, font) -> float:
        from PySide6.QtGui import QFontMetricsF

        return QFontMetricsF(font).horizontalAdvance(str(s or ""))

    def text_height(self, s, font, width) -> float:
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QFontMetricsF

        r = QFontMetricsF(font).boundingRect(QRectF(0, 0, width, 10000), int(self.Qt.TextWordWrap), str(s or ""))
        return r.height()

    def circle(self, cx, cy, r, fill, border=None):
        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QBrush, QColor, QPen

        self.p.setPen(QPen(QColor(*border), 1.5) if border else self.Qt.NoPen)
        self.p.setBrush(QBrush(QColor(*fill)))
        self.p.drawEllipse(QPointF(cx, cy), r, r)

    def arrow(self, x1, y1, x2, y2, color=RED, width=2.2):
        import math

        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QBrush, QColor, QPen, QPolygonF

        ang = math.atan2(y2 - y1, x2 - x1)
        head = 11
        bx, by = x2 - head * 0.8 * math.cos(ang), y2 - head * 0.8 * math.sin(ang)
        # white halo keeps the arrow readable where it crosses table text
        self.p.setPen(QPen(QColor(255, 255, 255, 230), width + 3.5, self.Qt.SolidLine, self.Qt.RoundCap))
        self.p.drawLine(QPointF(x1, y1), QPointF(bx, by))
        self.p.setPen(QPen(QColor(*color), width, self.Qt.SolidLine, self.Qt.RoundCap))
        self.p.drawLine(QPointF(x1, y1), QPointF(bx, by))
        pts = [QPointF(x2, y2), QPointF(x2 - head * math.cos(ang - 0.42), y2 - head * math.sin(ang - 0.42)),
               QPointF(x2 - head * math.cos(ang + 0.42), y2 - head * math.sin(ang + 0.42))]
        self.p.setBrush(QBrush(QColor(*color)))
        self.p.setPen(self.Qt.NoPen)
        self.p.drawPolygon(QPolygonF(pts))

    def badge(self, cx, cy, n, r=10):
        self.circle(cx + 1, cy + 1.5, r, (0, 0, 0, 60))
        self.circle(cx, cy, r, RED, (255, 255, 255))
        self.text(cx - r, cy - r, 2 * r, 2 * r, str(n), self.font(FONT_UI, 8.5, True), (255, 255, 255), "center", False)

    def save(self, path: str):
        self.p.end()
        self.img.setDotsPerMeterX(int(96 * S / 0.0254))
        self.img.setDotsPerMeterY(int(96 * S / 0.0254))
        self.img.save(path, "PNG", 20)
        return path


def window_chrome(c: Canvas, x, y, w, title, kind="app"):
    """Draws a Windows 11 style title bar; returns its height."""
    h = 32
    if kind == "excel":
        c.rect(x, y, w, h, fill=(33, 115, 70))
        fg = (255, 255, 255)
    else:
        c.rect(x, y, w, h, fill=(243, 243, 243))
        fg = (30, 30, 30)
    # app icon
    if kind == "excel":
        c.rect(x + 10, y + 8, 16, 16, fill=(255, 255, 255), radius=2)
        c.text(x + 10, y + 8, 16, 16, "X", c.font(FONT_UI, 8, True), (33, 115, 70), "center", False)
    elif kind == "registry":
        c.rect(x + 10, y + 9, 14, 14, fill=(0, 120, 212), radius=2)
        c.rect(x + 13, y + 12, 4, 4, fill=(255, 255, 255))
        c.rect(x + 18, y + 12, 4, 4, fill=(255, 255, 255))
        c.rect(x + 13, y + 17, 4, 4, fill=(255, 255, 255))
    elif kind == "eventlog":
        c.rect(x + 10, y + 9, 14, 14, fill=(200, 60, 40), radius=2)
        c.text(x + 10, y + 9, 14, 14, "!", c.font(FONT_UI, 8, True), (255, 255, 255), "center", False)
    elif kind == "hex":
        c.rect(x + 10, y + 9, 14, 14, fill=(80, 80, 90), radius=2)
        c.text(x + 10, y + 9, 14, 14, "0x", c.font(FONT_UI, 5.5, True), (255, 255, 255), "center", False)
    else:
        c.rect(x + 10, y + 8, 16, 16, fill=(37, 99, 235), radius=4)
        for i in range(2):
            for j in range(2):
                c.rect(x + 13 + i * 5.5, y + 11 + j * 5.5, 4.5, 4.5, fill=(255, 255, 255), radius=1)
    c.text(x + 34, y, w - 200, h, title, c.font(FONT_UI, 9), fg)
    # min / max / close
    bx = x + w - 138
    c.line(bx + 18, y + 16, bx + 28, y + 16, fg, 1)
    c.rect(bx + 64, y + 11, 10, 10, border=fg, width=1)
    c.line(bx + 110, y + 11, bx + 120, y + 21, fg, 1)
    c.line(bx + 120, y + 11, bx + 110, y + 21, fg, 1)
    return h


# ============================================================================ annotation layer
GUTTER = 290
MAX_W = 1080          # maximum logical width of a figure (fits a report page at a legible scale)
LEGEND_COL_W = 330


def plan_annotations(callouts: list, win_w: float) -> tuple[str, float, float]:
    """Decide where callout labels go. Returns (mode, extra width, extra height)."""
    if not callouts:
        return "none", 0, 0
    if win_w + GUTTER + 40 <= MAX_W:
        return "right", GUTTER, 0
    probe = Canvas(10, 10)
    f = probe.font(FONT_UI, 9.5, True)
    cols = max(1, int((win_w - 20) // LEGEND_COL_W))
    heights = [max(30, probe.text_height(co.get("text", ""), f, LEGEND_COL_W - 56) + 14) for co in callouts]
    probe.p.end()
    rows = [heights[i:i + cols] for i in range(0, len(heights), cols)]
    return "below", 0, 16 + sum(max(r) + 10 for r in rows)


def annotate(c: Canvas, cell_rects: dict, callouts: list, gutter_x: float, top: float, bottom: float, mode: str = "right",
             legend_x: float = 16, legend_w: float = 900):
    """Red boxes around target cells + numbered badges; labels in a right gutter (with arrows) or a legend below."""
    if not callouts or mode == "none":
        return
    targets = []
    for co in callouts:
        r = cell_rects.get((co.get("row"), co.get("col")))
        if r is not None:
            targets.append((co, r))
    if not targets:
        return
    lab_font = c.font(FONT_UI, 9.5, True)
    for co, (x, y, w, h) in targets:
        c.rect(x - 3, y - 3, w + 6, h + 6, border=RED, width=2.6, radius=4)
    if mode == "below":
        cols = max(1, int((legend_w - 20) // LEGEND_COL_W))
        cw = (legend_w - 20) / cols
        heights = [max(30, c.text_height(co["text"], lab_font, cw - 56) + 14) for co, _ in targets]
        y = bottom + 14
        for i in range(0, len(targets), cols):
            row = targets[i:i + cols]
            rh = max(heights[i:i + cols])
            for j, (co, _) in enumerate(row):
                lx = legend_x + j * cw
                c.rect(lx + 2, y + 2, cw - 12, rh, fill=(0, 0, 0, 22), radius=6)
                c.rect(lx, y, cw - 12, rh, fill=(255, 245, 245), border=RED, width=1.6, radius=6)
                c.badge(lx + 17, y + rh / 2, co.get("n", 1), 10.5)
                c.wrapped(lx + 34, y + 7, cw - 56, rh - 8, co["text"], lab_font, (150, 10, 20))
            y += rh + 10
        for co, (x, y0, w, h) in targets:
            c.badge(x - 3, y0 - 3, co.get("n", 1), 10)
        return
    body_w = GUTTER - 64
    heights = [max(34, c.text_height(co["text"], lab_font, body_w) + 16) for co, _ in targets]
    ys = [max(top, r[1] + r[3] / 2 - hgt / 2) for (co, r), hgt in zip(targets, heights)]
    for i in range(1, len(ys)):
        ys[i] = max(ys[i], ys[i - 1] + heights[i - 1] + 10)
    overflow = ys[-1] + heights[-1] - bottom
    if overflow > 0:
        ys = [max(top, y - overflow) for y in ys]
        for i in range(1, len(ys)):
            ys[i] = max(ys[i], ys[i - 1] + heights[i - 1] + 10)
    for (co, (x, y, w, h)), ly, lh in zip(targets, ys, heights):
        n = co.get("n", 1)
        lx = gutter_x + 26
        c.rect(lx + 2, ly + 2, GUTTER - 36, lh, fill=(0, 0, 0, 25), radius=6)
        c.rect(lx, ly, GUTTER - 36, lh, fill=(255, 245, 245), border=RED, width=1.6, radius=6)
        c.wrapped(lx + 32, ly + 8, body_w, lh - 10, co["text"], lab_font, (150, 10, 20))
        c.badge(lx + 15, ly + lh / 2, n, 10.5)
        c.arrow(lx - 2, ly + lh / 2, x + w + 6, y + h / 2)
        c.badge(x - 3, y - 3, n, 10)


# ============================================================================ table based styles
def _col_widths(c: Canvas, columns, rows, font, given, max_total):
    widths = []
    for i, col in enumerate(columns):
        sample = [col] + [r[i] if i < len(r) else "" for r in rows[:40]]
        natural = max(c.text_width(s, font) for s in sample) + 22
        if given and i < len(given) and given[i]:
            widths.append(float(min(given[i], max(natural, 48))))
        else:
            widths.append(min(max(natural, 50), 420))
    if sum(widths) > max_total:
        # cap the widest columns first so short columns (times, ids) stay fully readable
        lo, hi = 40.0, max(widths)
        for _ in range(40):
            mid = (lo + hi) / 2
            if sum(min(w, mid) for w in widths) > max_total:
                hi = mid
            else:
                lo = mid
        widths = [min(w, lo) for w in widths]
    return widths


def render_table(spec: dict, path: str) -> str:
    style = spec.get("style", "app")
    columns = spec.get("columns") or []
    rows = spec.get("rows") or []
    max_rows = 22 if style != "eventlog" else 12
    extra = max(0, len(rows) - max_rows)
    rows = rows[:max_rows]
    hl_rows = set(spec.get("highlight_rows") or [])
    callouts = [co for co in spec.get("callouts") or [] if co.get("row", 0) < len(rows)]
    probe = Canvas(10, 10)
    tbl = style in ("excel", "table")
    font = probe.font(FONT_XL if tbl else FONT_UI, 10.5 if tbl else 9.5)
    widths = _col_widths(probe, columns, rows, font, spec.get("col_widths"), (MAX_W - 80) if not tbl else (MAX_W - 60))
    probe.p.end()
    if style in ("excel", "table"):
        return _table(spec, path, columns, rows, widths, hl_rows, callouts, extra)
    if style == "eventlog":
        return _eventlog(spec, path, columns, rows, widths, hl_rows, callouts, extra)
    return _app(spec, path, columns, rows, widths, hl_rows, callouts, extra)


def _app(spec, path, columns, rows, widths, hl_rows, callouts, extra):
    rh, hh = 26, 30
    grid_w = sum(widths) + 1
    win_w = max(grid_w + 2, 640)
    win_h = 32 + 40 + hh + rh * len(rows) + 28
    mode, ew, eh = plan_annotations(callouts, win_w)
    W, H = int(win_w + 40 + ew), int(win_h + 40 + eh)
    c = Canvas(W, H, (255, 255, 255))
    x0, y0 = 16, 14
    c.rect(x0 + 3, y0 + 4, win_w, win_h, fill=(0, 0, 0, 40), radius=6)
    c.rect(x0, y0, win_w, win_h, fill=(255, 255, 255), border=(190, 190, 190), radius=6)
    th = window_chrome(c, x0 + 1, y0 + 1, win_w - 2, spec.get("window_title") or "Windows Forensic Automation - Artifact Viewer")
    ty = y0 + 1 + th
    # toolbar: breadcrumb + search box
    c.rect(x0 + 1, ty, win_w - 2, 40, fill=(250, 250, 251))
    c.line(x0 + 1, ty + 40, x0 + win_w - 1, ty + 40, (225, 225, 228))
    c.text(x0 + 14, ty, win_w * 0.6, 40, spec.get("title", ""), c.font(FONT_UI, 10, True), (25, 35, 60))
    sbx = x0 + win_w - 250
    c.rect(sbx, ty + 8, 230, 24, fill=(255, 255, 255), border=(200, 200, 205), radius=4)
    c.text(sbx + 26, ty + 8, 200, 24, "Filter rows...", c.font(FONT_UI, 8.5, italic=True), (150, 150, 155))
    c.circle(sbx + 13, ty + 19, 5, (255, 255, 255), (120, 120, 125))
    c.line(sbx + 16.5, ty + 22.5, sbx + 20, ty + 26, (120, 120, 125), 1.4)
    gy = ty + 41
    gx = x0 + 1
    # header
    c.gradient(gx, gy, grid_w, hh, (247, 248, 250), (234, 236, 240))
    cx = gx
    cell_rects = {}
    hf = c.font(FONT_UI, 9, True)
    for i, col in enumerate(columns):
        c.text(cx + 8, gy, widths[i] - 14, hh, col, hf, (55, 60, 75))
        c.line(cx + widths[i], gy + 5, cx + widths[i], gy + hh - 5, (205, 208, 214))
        cx += widths[i]
    c.line(gx, gy + hh, gx + grid_w, gy + hh, (200, 203, 210))
    f = c.font(FONT_UI, 9.5)
    fb = c.font(FONT_UI, 9.5, True)
    for r, row in enumerate(rows):
        ry = gy + hh + r * rh
        if r in hl_rows:
            c.rect(gx, ry, grid_w, rh, fill=(255, 243, 199))
            c.rect(gx, ry, 3, rh, fill=(245, 158, 11))
        elif r % 2:
            c.rect(gx, ry, grid_w, rh, fill=(248, 249, 251))
        cx = gx
        for i in range(len(columns)):
            v = row[i] if i < len(row) else ""
            c.text(cx + 8, ry, widths[i] - 14, rh, v, fb if (r in hl_rows and i == 0) else f, (25, 28, 35))
            cell_rects[(r, i)] = (cx + 2, ry + 2, widths[i] - 4, rh - 4)
            cx += widths[i]
        c.line(gx, ry + rh, gx + grid_w, ry + rh, (236, 237, 240))
    sy = y0 + win_h - 26
    c.rect(x0 + 1, sy, win_w - 2, 25, fill=(243, 244, 246))
    c.line(x0 + 1, sy, x0 + win_w - 1, sy, (220, 222, 226))
    st = f"{len(rows) + extra:,} rows" + (f"  (showing first {len(rows)})" if extra else "") + (
        f"   |   Source: {spec.get('source')}" if spec.get("source") else "") + f"   |   {len(hl_rows)} highlighted"
    c.text(x0 + 12, sy, win_w - 24, 25, st, c.font(FONT_UI, 8), (90, 95, 105))
    annotate(c, cell_rects, callouts, x0 + win_w + 4, y0 + 40, y0 + win_h, mode, x0, win_w)
    return c.save(path)


def _table(spec, path, columns, rows, widths, hl_rows, callouts, extra):
    """Plain formatted table (the way examiners format a table in a spreadsheet before taking a screenshot):
    colored header row, thin borders on every cell, zebra rows, highlighted rows - no application window around it."""
    rh, hh, title_h = 26, 28, 34
    grid_w = sum(widths)
    tbl_h = hh + rh * len(rows) + (rh if extra else 0)
    mode, ew, eh = plan_annotations(callouts, grid_w)
    W, H = int(grid_w + 34 + ew), int(title_h + tbl_h + 30 + eh)
    c = Canvas(W, H, (255, 255, 255))
    x0, y0 = 16, 10
    c.text(x0, y0, grid_w, title_h - 6, spec.get("title", ""), c.font(FONT_XL, 12.5, True), (31, 56, 100))
    y = y0 + title_h
    border = (166, 166, 166)
    # header
    cx = x0
    hf = c.font(FONT_XL, 10.5, True)
    for i, col in enumerate(columns):
        c.rect(cx, y, widths[i], hh, fill=(31, 56, 100))
        c.text(cx + 6, y, widths[i] - 12, hh, col, hf, (255, 255, 255))
        cx += widths[i]
    cell_rects = {}
    xf = c.font(FONT_XL, 10.5)
    xfb = c.font(FONT_XL, 10.5, True)
    yy = y + hh
    for r, row in enumerate(rows):
        fill = (255, 242, 204) if r in hl_rows else ((242, 246, 252) if r % 2 else (255, 255, 255))
        cx = x0
        for i in range(len(columns)):
            v = row[i] if i < len(row) else ""
            c.rect(cx, yy, widths[i], rh, fill=fill)
            num = isinstance(v, str) and v.replace(",", "").replace(".", "").isdigit()
            c.text(cx + 6, yy, widths[i] - 12, rh, v, xfb if (r in hl_rows and i == 0) else xf, (20, 20, 20),
                   "right" if num else "left")
            cell_rects[(r, i)] = (cx + 1, yy + 1, widths[i] - 2, rh - 2)
            cx += widths[i]
        yy += rh
    # borders: every cell, slightly darker outline
    cx = x0
    for w in widths:
        c.line(cx, y, cx, yy, border)
        cx += w
    c.line(x0 + grid_w, y, x0 + grid_w, yy, border)
    for k in range(len(rows) + 1):
        ly = y + hh + k * rh if k else y + hh
        c.line(x0, ly, x0 + grid_w, ly, border)
    c.line(x0, y, x0 + grid_w, y, (31, 56, 100))
    c.rect(x0, y, grid_w, yy - y, border=(110, 110, 110), width=1.2)
    if extra:
        c.text(x0 + 4, yy + 2, grid_w, rh, f"... {extra:,} more rows - see the Excel workbook / Parsed CSV",
               c.font(FONT_XL, 9.5, italic=True), (110, 110, 110))
    annotate(c, cell_rects, callouts, x0 + grid_w + 4, y + hh, yy + (rh if extra else 0), mode, x0, grid_w)
    return c.save(path)


def _eventlog(spec, path, columns, rows, widths, hl_rows, callouts, extra):
    rh, hh = 22, 24
    total_w = max(sum(widths) + 28, 860)
    _sel = min(hl_rows) if hl_rows else 0
    _srow = rows[_sel] if rows else []
    detail_h = max(110, 40 + 19 * sum(1 + len(str(v)) // 150 for v in _srow if str(v).strip()))
    win_h = 32 + 26 + 30 + hh + rh * len(rows) + 8 + detail_h + 24
    mode, ew, eh = plan_annotations(callouts, total_w)
    W, H = int(total_w + 40 + ew), int(win_h + 40 + eh)
    c = Canvas(W, H)
    x0, y0 = 16, 14
    c.rect(x0 + 3, y0 + 4, total_w, win_h, fill=(0, 0, 0, 40), radius=4)
    c.rect(x0, y0, total_w, win_h, fill=(255, 255, 255), border=(170, 170, 170), radius=4)
    th = window_chrome(c, x0 + 1, y0 + 1, total_w - 2, "WFA - Event Log Viewer", "eventlog")
    y = y0 + 1 + th
    c.rect(x0 + 1, y, total_w - 2, 26, fill=(250, 250, 250))
    c.text(x0 + 10, y, 400, 26, "File    Action    View    Help", c.font(FONT_UI, 9), (40, 40, 40))
    y += 26
    c.rect(x0 + 1, y, total_w - 2, 30, fill=(236, 241, 248))
    c.text(x0 + 10, y, total_w - 20, 30, f"{spec.get('title', '')}     Number of events: {len(rows) + extra:,}",
           c.font(FONT_UI, 9, True), (30, 50, 90))
    y += 30
    gx = x0 + 1
    levels = spec.get("levels") or []  # real record levels only - no icon is drawn when the level is not known
    lvl_w = 26 if levels else 0
    ws = [lvl_w] + widths
    cx = gx
    c.rect(gx, y, sum(ws), hh, fill=(245, 245, 245))
    for i, col in enumerate(["", *columns]):
        c.text(cx + 6, y, ws[i] - 10, hh, col, c.font(FONT_UI, 8.5), (60, 60, 60))
        c.line(cx + ws[i], y + 4, cx + ws[i], y + hh - 4, (210, 210, 210))
        cx += ws[i]
    c.line(gx, y + hh, gx + sum(ws), y + hh, (200, 200, 200))
    y += hh
    cell_rects = {}
    sel = min(hl_rows) if hl_rows else 0
    for r, row in enumerate(rows):
        selected = r == sel
        if selected:
            c.rect(gx, y, sum(ws), rh, fill=(204, 232, 255), border=(153, 209, 255))
        elif r in hl_rows:
            c.rect(gx, y, sum(ws), rh, fill=(229, 243, 255))
        lv = str(levels[r]).lower() if r < len(levels) else ""
        if lv:
            col, ch = {"error": ((200, 40, 40), "!"), "critical": ((150, 0, 0), "!"), "warning": ((230, 160, 0), "!"),
                       "audit failure": ((200, 40, 40), "x")}.get(lv, ((30, 110, 200), "i"))
            c.circle(gx + 13, y + rh / 2, 6.5, col)
            c.text(gx + 6.5, y, 13, rh, ch, c.font("Georgia", 7.5, True, True), (255, 255, 255), "center", False)
        cx = gx + lvl_w
        for i in range(len(columns)):
            c.text(cx + 6, y, ws[i + 1] - 10, rh, row[i] if i < len(row) else "", c.font(FONT_UI, 8.5), (20, 20, 20))
            cell_rects[(r, i)] = (cx + 2, y + 2, ws[i + 1] - 4, rh - 4)
            cx += ws[i + 1]
        y += rh
    y += 8
    c.rect(gx, y, total_w - 2, detail_h, fill=(255, 255, 255), border=(200, 200, 200))
    srow = rows[sel] if rows else []
    c.rect(gx, y, total_w - 2, 24, fill=(240, 240, 240))
    c.text(gx + 8, y, total_w - 20, 24, f"Selected record ({sel + 1} of {len(rows) + extra:,})", c.font(FONT_UI, 9, True))
    # every field of the selected row, by column name (no assumption about column order)
    details = "\n".join(f"{col}: {srow[i]}" for i, col in enumerate(columns) if i < len(srow) and str(srow[i]).strip())
    c.wrapped(gx + 12, y + 30, total_w - 30, detail_h - 36, details, c.font(FONT_UI, 9))
    c.rect(x0 + 1, y0 + win_h - 23, total_w - 2, 22, fill=(240, 240, 240))
    c.text(x0 + 10, y0 + win_h - 23, total_w, 22, spec.get("caption") or "", c.font(FONT_UI, 8), (90, 90, 90))
    annotate(c, cell_rects, callouts, x0 + total_w + 4, y0 + 60, y0 + win_h, mode, x0, total_w)
    return c.save(path)


# ============================================================================ registry editor
def render_registry(spec: dict, path: str) -> str:
    values = spec.get("values") or []
    tree = spec.get("tree") or spec.get("key_path", "").split("\\")
    callouts = spec.get("callouts") or []
    left_w, name_w, type_w = 250, 210, 105
    probe = Canvas(10, 10)
    data_w = min(420, max([probe.text_width(v[2] if len(v) > 2 else "", probe.font(FONT_UI, 9)) + 30 for v in values] + [260]))
    probe.p.end()
    win_w = left_w + name_w + type_w + data_w + 6
    rh = 22
    rows_n = max(len(values) + 1, len(tree) + 1, 8)
    win_h = 32 + 24 + 28 + 24 + rows_n * rh + 30
    mode, ew, eh = plan_annotations(callouts, win_w)
    c = Canvas(int(win_w + 40 + ew), int(win_h + 40 + eh))
    x0, y0 = 16, 14
    c.rect(x0 + 3, y0 + 4, win_w, win_h, fill=(0, 0, 0, 40), radius=4)
    c.rect(x0, y0, win_w, win_h, fill=(255, 255, 255), border=(170, 170, 170), radius=4)
    th = window_chrome(c, x0 + 1, y0 + 1, win_w - 2, "WFA - Registry Viewer", "registry")
    y = y0 + 1 + th
    c.rect(x0 + 1, y, win_w - 2, 24, fill=(250, 250, 250))
    c.text(x0 + 10, y, 400, 24, "File   Edit   View   Favorites   Help", c.font(FONT_UI, 9))
    y += 24
    c.rect(x0 + 6, y + 3, win_w - 12, 22, fill=(255, 255, 255), border=(190, 190, 190))
    c.text(x0 + 12, y + 3, win_w - 24, 22, "Computer\\" + spec.get("key_path", ""), c.font(FONT_UI, 8.8))
    y += 28
    # tree
    tx, ty = x0 + 1, y
    c.rect(tx, ty, left_w, rows_n * rh + 24, fill=(255, 255, 255))
    c.line(tx + left_w, ty, tx + left_w, ty + rows_n * rh + 24, (210, 210, 210))
    items = ["Computer"] + list(tree)
    shown = items if len(items) <= rows_n else items[:2] + ["..."] + items[-(rows_n - 3):]
    for i, name in enumerate(shown):
        ind = min(i, 9) * 14
        yy = ty + 4 + i * rh
        last = i == len(shown) - 1
        if last:
            c.rect(tx + 4 + ind, yy, left_w - 8 - ind, rh, fill=(204, 232, 255))
        c.text(tx + 6 + ind, yy, 10, rh, "˅" if not last else "", c.font(FONT_UI, 8), (90, 90, 90))
        c.rect(tx + 18 + ind, yy + 6, 14, 10, fill=(255, 205, 80), border=(220, 170, 40), radius=1)
        c.text(tx + 36 + ind, yy, left_w - 40 - ind, rh, name, c.font(FONT_UI, 8.8))
    # values
    vx = x0 + 1 + left_w + 1
    c.rect(vx, ty, name_w + type_w + data_w, 24, fill=(255, 255, 255))
    for i, (col, w) in enumerate((("Name", name_w), ("Type", type_w), ("Data", data_w))):
        off = [0, name_w, name_w + type_w][i]
        c.text(vx + off + 8, ty, w - 10, 24, col, c.font(FONT_UI, 8.8), (60, 60, 60))
        c.line(vx + off + w, ty + 4, vx + off + w, ty + 20, (220, 220, 220))
    c.line(vx, ty + 24, vx + name_w + type_w + data_w, ty + 24, (225, 225, 225))
    vals = list(values)  # only the values passed in (read from the hive) - nothing is added
    cell_rects = {}
    hl = set(spec.get("highlight") or [])
    for r, v in enumerate(vals):
        yy = ty + 26 + r * rh
        if r in hl:
            c.rect(vx, yy, name_w + type_w + data_w - 2, rh, fill=(204, 232, 255))
        is_sz = (v[1] or "").startswith("REG_SZ") or (v[1] or "") in ("REG_EXPAND_SZ", "REG_MULTI_SZ")
        c.rect(vx + 8, yy + 5, 16, 12, fill=(255, 255, 255), border=(200, 60, 60) if is_sz else (60, 120, 200), width=1)
        c.text(vx + 8, yy + 5, 16, 12, "ab" if is_sz else "01", c.font(FONT_UI, 5.5, True), (200, 60, 60) if is_sz else (60, 120, 200),
               "center", False)
        c.text(vx + 30, yy, name_w - 34, rh, v[0], c.font(FONT_UI, 8.8))
        c.text(vx + name_w + 8, yy, type_w - 10, rh, v[1] if len(v) > 1 else "", c.font(FONT_UI, 8.8))
        c.text(vx + name_w + type_w + 8, yy, data_w - 14, rh, v[2] if len(v) > 2 else "", c.font(FONT_UI, 8.8))
        for col, (xx, ww) in enumerate(((vx + 4, name_w - 6), (vx + name_w + 2, type_w - 4), (vx + name_w + type_w + 2, data_w - 6))):
            cell_rects[(r, col)] = (xx, yy + 2, ww, rh - 4)
    sy = y0 + win_h - 26
    c.rect(x0 + 1, sy, win_w - 2, 25, fill=(240, 240, 240))
    if spec.get("last_write"):
        lwt = f"Key last written: {spec['last_write']} UTC"
        lw_w = c.text_width(lwt, c.font(FONT_UI, 8, True)) + 16
        c.text(x0 + 10, sy, win_w - 30 - lw_w, 25, "Computer\\" + spec.get("key_path", ""), c.font(FONT_UI, 8), (70, 70, 70))
        c.text(x0 + win_w - lw_w - 10, sy, lw_w, 25, lwt, c.font(FONT_UI, 8, True), (40, 40, 40), "right")
        cell_rects[(-1, 0)] = (x0 + win_w - lw_w - 8, sy + 3, lw_w, 19)  # callout row -1 = key last-written time
    else:
        c.text(x0 + 10, sy, win_w - 20, 25, "Computer\\" + spec.get("key_path", ""), c.font(FONT_UI, 8), (70, 70, 70))
    annotate(c, cell_rects, callouts, x0 + win_w + 4, y0 + 60, y0 + win_h, mode, x0, win_w)
    return c.save(path)


# ============================================================================ hex viewer
def render_hex(spec: dict, path: str) -> str:
    data = bytes.fromhex(spec.get("data_hex") or "")
    base = int(spec.get("base_offset") or 0)
    hs = int(spec.get("hit_start") or 0)
    hl = int(spec.get("hit_len") or 1)
    start = base - (base % 16)
    pad = base - start
    buf = b"\x00" * pad + data
    nrows = max(1, (len(buf) + 15) // 16)
    meta = spec.get("meta") or {}
    rh = 20
    off_w, hex_w, asc_w = 120, 16 * 26 + 12, 16 * 10 + 16
    win_w = off_w + hex_w + asc_w + 24
    meta_h = 18 * ((len(meta) + 1) // 2) + 16
    win_h = 32 + meta_h + 26 + nrows * rh + 28
    hex_callouts = [{"row": 0, "col": 0, "n": 1, "text": spec.get("callout") or "Keyword hit"}]
    mode, ew, eh = plan_annotations(hex_callouts, win_w)
    c = Canvas(int(win_w + 40 + ew), int(win_h + 40 + eh))
    x0, y0 = 16, 14
    c.rect(x0 + 3, y0 + 4, win_w, win_h, fill=(0, 0, 0, 40), radius=4)
    c.rect(x0, y0, win_w, win_h, fill=(255, 255, 255), border=(170, 170, 170), radius=4)
    th = window_chrome(c, x0 + 1, y0 + 1, win_w - 2, f"Windows Forensic Automation - Hex View  [{meta.get('Area', '')}]", "hex")
    y = y0 + 1 + th
    c.rect(x0 + 1, y, win_w - 2, meta_h, fill=(247, 248, 250))
    items = list(meta.items())
    half = (len(items) + 1) // 2
    for i, (k, v) in enumerate(items):
        col = 0 if i < half else 1
        yy = y + 8 + (i % half) * 18
        xx = x0 + 12 + col * (win_w / 2)
        c.text(xx, yy, 110, 18, k + ":", c.font(FONT_UI, 8.5, True), (70, 75, 90))
        c.text(xx + 110, yy, win_w / 2 - 130, 18, v, c.font(FONT_UI, 8.5), (20, 20, 25))
    y += meta_h
    c.line(x0 + 1, y, x0 + win_w - 1, y, (215, 215, 220))
    c.rect(x0 + 1, y, win_w - 2, 26, fill=(238, 240, 244))
    mono = c.font(FONT_MONO, 9)
    monob = c.font(FONT_MONO, 9, True)
    c.text(x0 + 10, y, off_w, 26, "Offset", c.font(FONT_UI, 8.5, True), (70, 70, 80))
    for i in range(16):
        c.text(x0 + off_w + i * 26, y, 26, 26, f"{i:02X}", mono, (90, 90, 120), "center")
    c.text(x0 + off_w + hex_w, y, asc_w, 26, "Decoded text", c.font(FONT_UI, 8.5, True), (70, 70, 80))
    y += 26
    hit_lo, hit_hi = pad + hs, pad + hs + hl
    boxes = []
    for r in range(nrows):
        yy = y + r * rh
        if r % 2:
            c.rect(x0 + 1, yy, win_w - 2, rh, fill=(250, 250, 252))
        c.text(x0 + 10, yy, off_w - 14, rh, f"{start + r * 16:012X}", mono, (0, 90, 160))
        for i in range(16):
            idx = r * 16 + i
            if idx >= len(buf):
                break
            b = buf[idx]
            inhit = hit_lo <= idx < hit_hi
            if inhit:
                c.rect(x0 + off_w + i * 26 + 1, yy + 1, 24, rh - 2, fill=(255, 214, 214))
                c.rect(x0 + off_w + hex_w + 8 + i * 10, yy + 1, 10, rh - 2, fill=(255, 214, 214))
            dim = idx < pad
            c.text(x0 + off_w + i * 26, yy, 26, rh, "" if dim else f"{b:02X}", monob if inhit else mono,
                   (170, 20, 30) if inhit else ((40, 40, 50) if b else (170, 170, 178)), "center")
            ch = chr(b) if 32 <= b < 127 else "."
            c.text(x0 + off_w + hex_w + 8 + i * 10, yy, 10, rh, "" if dim else ch, monob if inhit else mono,
                   (170, 20, 30) if inhit else (60, 60, 70), "center", False)
        row_lo, row_hi = r * 16, r * 16 + 16
        lo, hi = max(hit_lo, row_lo), min(hit_hi, row_hi)
        if lo < hi:
            boxes.append((r, lo - row_lo, hi - row_lo, yy))
    cell_rects = {}
    if boxes:
        for k, (r, a, b, yy) in enumerate(boxes):
            c.rect(x0 + off_w + a * 26 - 1, yy, (b - a) * 26 + 2, rh, border=RED, width=2, radius=3)
            c.rect(x0 + off_w + hex_w + 8 + a * 10 - 1, yy, (b - a) * 10 + 2, rh, border=RED, width=2, radius=3)
        r, a, b, yy = boxes[0]
        cell_rects[(0, 0)] = (x0 + off_w + hex_w + 8 + a * 10, yy, (b - a) * 10, rh)
    sy = y0 + win_h - 26
    c.rect(x0 + 1, sy, win_w - 2, 25, fill=(240, 240, 242))
    c.text(x0 + 10, sy, win_w - 20, 25, f"Selection: {hl} bytes at {base + hs:,} ({base + hs:#x})   |   Encoding: "
           f"{meta.get('Encoding', '')}", c.font(FONT_UI, 8), (70, 70, 80))
    if cell_rects:
        annotate(c, cell_rects, hex_callouts, x0 + win_w + 4, y0 + 40, y0 + win_h, mode, x0, win_w)
    return c.save(path)


# ============================================================================ timeline chart
def _segments(stamps: list, px0: float, px1: float, gap_px: float = 30):
    """Broken time axis: clusters of activity get proportional space, long idle stretches collapse to a gap."""
    ts = sorted(stamps)
    thresh = 3600.0
    while True:
        clusters = [[ts[0], ts[0], 1]]
        for t in ts[1:]:
            if t - clusters[-1][1] > thresh:
                clusters.append([t, t, 1])
            else:
                clusters[-1][1] = t
                clusters[-1][2] += 1
        if len(clusters) <= 6:
            break
        thresh *= 2
    n = len(clusters)
    avail = (px1 - px0) - gap_px * (n - 1)
    dur_total = sum(max(b - a, 60) for a, b, _ in clusters)
    weights = [0.5 * (cnt / len(ts)) + 0.5 * (max(b - a, 60) / dur_total) for a, b, cnt in clusters]
    segs = []
    x = px0
    for (a, b, cnt), w in zip(clusters, weights):
        width = max(110, avail * w)
        pad = max((b - a) * 0.08, 120)
        segs.append({"t0": a - pad, "t1": b + pad, "x0": x, "x1": x + width})
        x += width + gap_px
    scale = (px1 - px0) / max(1.0, (x - gap_px - px0))
    for sg in segs:
        sg["x0"] = px0 + (sg["x0"] - px0) * scale
        sg["x1"] = px0 + (sg["x1"] - px0) * scale
    return segs


def render_timeline(spec: dict, path: str) -> str:
    from datetime import timezone

    from ..core.timeutil import from_db

    lanes = [l for l in spec.get("lanes") or [] if l.get("spans") or l.get("events")]
    marks, stamps = [], []
    for li, l in enumerate(lanes):
        for sp in l.get("spans", []):
            for k in ("start", "end"):
                t = from_db(sp.get(k))
                if t:
                    stamps.append(t.timestamp())
        for e in l.get("events", []):
            t = from_db(e.get("ts"))
            if t:
                stamps.append(t.timestamp())
                marks.append((t, li, e))
    if not stamps:
        stamps = [datetime.now(timezone.utc).timestamp()]
    marks.sort(key=lambda m: m[0])
    if len(marks) > 40:
        step = len(marks) / 40
        marks = [marks[int(i * step)] for i in range(40)]
    W, label_w, lane_h = 1060, 180, 104
    px0, px1 = label_w + 40, W - 30
    segs = _segments(stamps, px0, px1)

    def X(t):
        v = t.timestamp() if hasattr(t, "timestamp") else t
        for sg in segs:
            if v <= sg["t1"] or sg is segs[-1]:
                v2 = min(max(v, sg["t0"]), sg["t1"])
                return sg["x0"] + (v2 - sg["t0"]) / (sg["t1"] - sg["t0"]) * (sg["x1"] - sg["x0"])
        return px1

    cols = 2
    colw = (W - 40) / cols
    leg_rows = (len(marks) + cols - 1) // cols
    top = 52
    chart_h = lane_h * len(lanes)
    H = top + chart_h + 52 + 30 + (leg_rows * 20 + 36 if marks else 0)
    c = Canvas(W, int(H))
    lf = c.font(FONT_UI, 8.5)
    c.text(20, 12, W - 40, 28, spec.get("title", "Timeline"), c.font(FONT_UI, 12, True), (25, 35, 60))
    c.text(W - 470, 12, 450, 28, "Times in UTC  -  idle periods are collapsed (//)", c.font(FONT_UI, 8.5, italic=True),
           (110, 115, 125), "right")
    for li, lane in enumerate(lanes):
        y = top + li * lane_h
        c.rect(20, y + 4, W - 40, lane_h - 8, fill=(246, 248, 251) if li % 2 == 0 else (252, 252, 253), radius=6)
        c.wrapped(32, y + lane_h / 2 - 18, label_w - 4, 44, lane["label"], c.font(FONT_UI, 9.5, True), (30, 41, 59))
    for k, sg in enumerate(segs):
        if sg["x1"] - sg["x0"] < 230:
            a = datetime.fromtimestamp(sg["t0"], timezone.utc)
            b = datetime.fromtimestamp(sg["t1"], timezone.utc)
            mid = (sg["x0"] + sg["x1"]) / 2
            c.line(sg["x0"], top, sg["x0"], top + chart_h, (226, 229, 234), 1)
            c.text(mid - 90, top + chart_h + 4, 180, 18, f"{a:%H:%M}-{b:%H:%M}", c.font(FONT_UI, 8.5, True), (60, 65, 80), "center")
            c.text(mid - 90, top + chart_h + 20, 180, 16, a.strftime("%Y-%m-%d"), c.font(FONT_UI, 7.5), (130, 135, 145), "center")
            fracs = ()
        else:
            fracs = (0.0, 0.5, 1.0)
        for frac in fracs:
            tx = sg["x0"] + frac * (sg["x1"] - sg["x0"])
            tt = datetime.fromtimestamp(sg["t0"] + frac * (sg["t1"] - sg["t0"]), timezone.utc)
            c.line(tx, top, tx, top + chart_h, (226, 229, 234), 1)
            al = "left" if frac == 0 else ("right" if frac == 1 else "center")
            bx = tx if al == "left" else (tx - 120 if al == "right" else tx - 60)
            c.text(bx, top + chart_h + 4, 120, 18, tt.strftime("%H:%M"), c.font(FONT_UI, 8.5, True), (60, 65, 80), al)
            c.text(bx, top + chart_h + 20, 120, 16, tt.strftime("%Y-%m-%d"), c.font(FONT_UI, 7.5), (130, 135, 145), al)
        if k < len(segs) - 1:
            nxt = segs[k + 1]
            gx = (sg["x1"] + nxt["x0"]) / 2
            c.rect(sg["x1"] + 2, top, nxt["x0"] - sg["x1"] - 4, chart_h, fill=(255, 255, 255))
            for dx in (-4, 4):
                c.line(gx + dx - 5, top + chart_h + 2, gx + dx + 5, top + chart_h - 12, (120, 125, 135), 1.5)
                c.line(gx + dx - 5, top - 2, gx + dx + 5, top + 12, (120, 125, 135), 1.5)
            gap_h = (nxt["t0"] - sg["t1"]) / 3600
            c.text(gx - 40, top + chart_h + 34, 80, 14, f"{gap_h / 24:.1f} d" if gap_h >= 48 else f"{gap_h:.0f} h",
                   c.font(FONT_UI, 7, italic=True), (140, 140, 150), "center")
    colors = {"usb": (37, 99, 235), "file": (22, 163, 74), "web": (217, 119, 6), "alert": (220, 38, 38), "other": (100, 116, 139)}
    for li, lane in enumerate(lanes):
        y = top + li * lane_h
        for sp in lane.get("spans", []):
            a, b = from_db(sp["start"]), from_db(sp["end"])
            if not a:
                continue
            xa, xb = X(a), X(b or a)
            c.rect(xa, y + 12, max(8, xb - xa), 18, fill=(191, 219, 254), border=(37, 99, 235), width=1.2, radius=5)
            if xb - xa > 70:
                c.text(xa + 5, y + 12, xb - xa - 8, 18, sp.get("label", ""), c.font(FONT_UI, 7.5, True), (30, 64, 175))
    placed: dict = {}
    for n, (t, li, e) in enumerate(marks, start=1):
        x = X(t)
        y = top + li * lane_h
        level = 0
        while any(abs(px - x) < 19 and pl == level for px, pl in placed.get(li, [])) and level < 3:
            level += 1
        placed.setdefault(li, []).append((x, level))
        cy = y + 44 + level * 17
        col = colors.get(e.get("kind"), colors["other"])
        c.line(x, y + 30, x, cy - 8, col, 1)
        c.circle(x, cy, 8.5, col, (255, 255, 255))
        c.text(x - 9, cy - 9, 18, 18, str(n), c.font(FONT_UI, 6.8, True), (255, 255, 255), "center", False)
    ly = top + chart_h + 50
    lx = 24
    for k, v in (("USB session", "usb"), ("File", "file"), ("Web", "web"), ("DLP alert", "alert"), ("Other", "other")):
        if v == "usb":
            c.rect(lx, ly + 3, 22, 10, fill=(191, 219, 254), border=colors["usb"], radius=3)
        else:
            c.circle(lx + 10, ly + 8, 5, colors[v])
        c.text(lx + 28, ly, 120, 16, k, c.font(FONT_UI, 8), (70, 75, 90))
        lx += 130
    if marks:
        ly += 26
        for n, (t, li, e) in enumerate(marks, start=1):
            col_i, row_i = (n - 1) // leg_rows, (n - 1) % leg_rows
            x = 22 + col_i * colw
            yy = ly + row_i * 20
            c.circle(x + 9, yy + 9, 8, colors.get(e.get("kind"), colors["other"]))
            c.text(x, yy, 18, 18, str(n), c.font(FONT_UI, 6.8, True), (255, 255, 255), "center", False)
            c.text(x + 24, yy, 118, 18, t.strftime("%m-%d %H:%M:%S"), c.font(FONT_MONO, 8), (60, 65, 80))
            c.text(x + 140, yy, colw - 150, 18, f"{lanes[li]['label'].split(' (')[0]}: {e.get('label', '')}", lf, (30, 35, 45))
    return c.save(path)


# ============================================================================ dispatcher
def render(spec: dict, path: str) -> str:
    ensure_app()
    kind = spec.get("kind")
    if kind == "table":
        return render_table(spec, path)
    if kind == "registry":
        return render_registry(spec, path)
    if kind == "hex":
        return render_hex(spec, path)
    if kind == "timeline":
        return render_timeline(spec, path)
    raise ValueError(f"unknown figure kind {kind}")
