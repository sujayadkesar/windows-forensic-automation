"""Brand mark drawn with QPainter (no image files to ship): a four-pane window tile with a magnifier."""

from __future__ import annotations

NAVY = (23, 37, 84)
BLUE = (37, 99, 235)
ACCENT = (56, 189, 248)


def draw_logo(painter, x: float, y: float, size: float, mono: bool = False):
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import QBrush, QColor, QLinearGradient, QPen

    s = size
    g = QLinearGradient(QPointF(x, y), QPointF(x + s, y + s))
    g.setColorAt(0, QColor(*BLUE) if not mono else QColor(60, 60, 60))
    g.setColorAt(1, QColor(*NAVY) if not mono else QColor(20, 20, 20))
    painter.setPen(Qt.NoPen)
    painter.setBrush(QBrush(g))
    painter.drawRoundedRect(QRectF(x, y, s, s), s * 0.2, s * 0.2)
    # four window panes
    pane = s * 0.2
    gap = s * 0.05
    ox, oy = x + s * 0.17, y + s * 0.17
    painter.setBrush(QBrush(QColor(255, 255, 255, 235)))
    for i in range(2):
        for j in range(2):
            painter.drawRoundedRect(QRectF(ox + i * (pane + gap), oy + j * (pane + gap), pane, pane), s * 0.03, s * 0.03)
    # magnifier
    pen = QPen(QColor(*ACCENT), s * 0.075, Qt.SolidLine, Qt.RoundCap)
    painter.setPen(pen)
    painter.setBrush(QBrush(QColor(15, 30, 70, 210)))
    cx, cy, r = x + s * 0.62, y + s * 0.62, s * 0.17
    painter.drawEllipse(QPointF(cx, cy), r, r)
    painter.drawLine(QPointF(cx + r * 0.72, cy + r * 0.72), QPointF(x + s * 0.88, y + s * 0.88))


def logo_png(path: str, size: int = 256) -> str:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QImage, QPainter

    from .figures import ensure_app

    ensure_app()
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    draw_logo(p, size * 0.03, size * 0.03, size * 0.94)
    p.end()
    img.save(path, "PNG")
    return path


def logo_icon():
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QIcon, QPainter, QPixmap

    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(sz, sz)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        draw_logo(p, 0, 0, sz)
        p.end()
        icon.addPixmap(pm)
    return icon
