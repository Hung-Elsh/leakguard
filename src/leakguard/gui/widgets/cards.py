"""Small building blocks: a card, the cleaned-up ring, and a pop-up message (toast) with an optional button."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPalette, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from .. import theme


def label(text: str = "", name: str = "", wrap: bool = True) -> QLabel:
    lb = QLabel(text)
    if name:
        lb.setObjectName(name)
    lb.setWordWrap(wrap)
    lb.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lb


class Card(QFrame):
    """Title, a big value, one line under it, and an optional 'See details' link."""
    clicked = Signal()

    def __init__(self, title: str, link: str = ""):
        super().__init__()
        self.setObjectName("card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(4)
        self.title = label(title, "title")
        self.value = label("", "big")
        self.line = label("", "muted")
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.line)
        lay.addStretch(1)
        if link:
            btn = QPushButton(link)
            btn.setObjectName("link")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(self.clicked)
            lay.addWidget(btn, alignment=Qt.AlignmentFlag.AlignLeft)

    def set(self, value: str, line: str = "", color: str | None = None) -> None:
        self.value.setText(value)
        self.value.setStyleSheet(f"color: {color};" if color else "")
        self.line.setText(line)


class Ring(QWidget):
    """How much is cleaned up, as a ring with the percentage in the middle."""

    def __init__(self, size: int = 132):
        super().__init__()
        self.pct = 0
        self.setFixedSize(size, size)

    def set(self, pct: int) -> None:
        self.pct = max(0, min(100, int(pct)))
        self.setAccessibleName(f"{self.pct} percent cleaned up")
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        thick = 13
        r = theme.ring_rect(self.width(), self.height(), thick)
        pen = QPen(self.palette().color(QPalette.ColorRole.Mid), thick)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(r, 0, 360 * 16)
        if self.pct:
            pen.setColor(QColor(theme.GOOD))
            p.setPen(pen)
            p.drawArc(r, 90 * 16, -int(360 * 16 * self.pct / 100))
        f = QFont(self.font())
        f.setPointSize(20)
        f.setBold(True)
        p.setFont(f)
        p.setPen(self.palette().color(QPalette.ColorRole.WindowText))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self.pct}%")


class Toast(QFrame):
    """A message at the bottom of the window that goes away by itself; one optional button (Undo, Details)."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)     # draw the background (not see-through)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 10, 10)
        self.text = label("")
        self.text.setMaximumWidth(560)
        self.button = QPushButton()
        self.button.setObjectName("link")
        self.button.setCursor(Qt.CursorShape.PointingHandCursor)
        close = QPushButton("✕")
        close.setObjectName("link")
        close.setAccessibleName("Close message")
        close.clicked.connect(self.hide)
        lay.addWidget(self.text, 1)
        lay.addWidget(self.button)
        lay.addWidget(close)
        self.timer = QTimer(self, singleShot=True, timeout=self.hide)
        self._action = None
        self.button.clicked.connect(self._clicked)
        self.hide()

    def show_message(self, text: str, button: str = "", action=None, seconds: int = 8) -> None:
        self.text.setText(text)
        self._action = action
        self.button.setVisible(bool(button))
        self.button.setText(button)
        self.adjustSize()
        self._place()
        self.show()
        self.raise_()
        self.timer.start(seconds * 1000)

    def _clicked(self) -> None:
        if self._action:
            self._action()
        self.hide()

    def _place(self) -> None:
        par = self.parentWidget()
        w = min(max(self.sizeHint().width(), 320), par.width() - 40)
        self.resize(w, self.sizeHint().height())
        self.move((par.width() - w) // 2, par.height() - self.height() - 24)
