"""Look and feel: the system's light or dark palette, a few colour tokens, and the app icon (drawn, no files)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QIcon, QPainter, QPainterPath, QPalette, QPen, QPixmap

# tokens: readable on both light and dark backgrounds
GOOD = "#2e9d5b"
WARN = "#d08a16"
BAD = "#d1453b"
ACCENT = "#3d7be0"
SEVERITY_COLOR = {"high": BAD, "medium": WARN, "low": ACCENT, "info": "#8a8f98"}


def is_dark() -> bool:
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorScheme"):
        return hints.colorScheme() == Qt.ColorScheme.Dark
    return QGuiApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128


def stylesheet() -> str:
    # palette(...) follows the system theme, so cards stay readable in light and dark mode
    return f"""
    QFrame#card {{ background: palette(base); border: 1px solid palette(mid); border-radius: 10px; }}
    QLabel#hero {{ font-size: 22pt; font-weight: 600; }}
    QLabel#big {{ font-size: 20pt; font-weight: 600; }}
    QLabel#title {{ font-size: 11pt; font-weight: 600; }}
    QLabel#muted {{ color: palette(placeholder-text); }}
    QLabel#error {{ color: {BAD}; }}
    QLabel#banner {{ background: {WARN}; color: black; padding: 6px 10px; border-radius: 6px; }}
    QPushButton {{ padding: 5px 14px; border: 1px solid palette(mid); border-radius: 6px;
                  background: palette(button); color: palette(button-text); min-height: 20px; }}
    QPushButton:hover {{ border-color: {ACCENT}; }}
    QPushButton:pressed {{ background: palette(midlight); }}
    QPushButton:disabled {{ color: palette(placeholder-text); }}
    QPushButton:checked {{ background: palette(highlight); color: palette(highlighted-text);
                          border-color: palette(highlight); }}
    QPushButton#primary {{ background: {ACCENT}; color: white; border: 1px solid {ACCENT}; }}
    QPushButton#primary:hover {{ background: #2f6bd0; }}
    QPushButton#primary:disabled {{ background: palette(mid); border-color: palette(mid); }}
    QPushButton#link {{ border: none; background: transparent; color: {ACCENT}; text-align: left; padding: 0;
                       min-height: 0; }}
    QPushButton#nav {{ border: none; background: transparent; text-align: left; padding: 9px 14px;
                      font-size: 11pt; border-radius: 6px; }}
    QPushButton#nav:hover {{ background: palette(midlight); }}
    QPushButton#nav:checked {{ background: palette(highlight); color: palette(highlighted-text); }}
    QPushButton#fab {{ background: {ACCENT}; color: white; border: none; border-radius: 26px; font-size: 18pt;
                      padding: 0; min-height: 0; }}
    QPushButton#fab:hover {{ background: #2f6bd0; }}
    QFrame#quick {{ background: palette(base); border: 1px solid {ACCENT}; border-radius: 12px; }}
    QFrame#toast {{ background: palette(base); border: 1px solid {ACCENT}; border-radius: 8px; }}
    QLabel#lead {{ font-size: 12pt; font-weight: 600; }}
    """


def app_icon() -> QIcon:
    """A shield with a check mark."""
    icon = QIcon()
    for size in (16, 32, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = size / 64
        shield = QPainterPath()
        shield.moveTo(32 * s, 4 * s)
        shield.lineTo(56 * s, 13 * s)
        shield.cubicTo(56 * s, 38 * s, 46 * s, 52 * s, 32 * s, 60 * s)
        shield.cubicTo(18 * s, 52 * s, 8 * s, 38 * s, 8 * s, 13 * s)
        shield.closeSubpath()
        p.fillPath(shield, QColor(ACCENT))
        pen = QPen(QColor("white"), max(1.5, 6 * s), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                   Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawPolyline([QPointF(21 * s, 32 * s), QPointF(29 * s, 40 * s), QPointF(44 * s, 24 * s)])
        p.end()
        icon.addPixmap(pm)
    return icon


def icon_pixmap(size: int = 256) -> QPixmap:
    return app_icon().pixmap(size, size)


def ring_rect(w: int, h: int, thickness: int) -> QRectF:
    side = min(w, h) - thickness
    return QRectF((w - side) / 2, (h - side) / 2, side, side)
