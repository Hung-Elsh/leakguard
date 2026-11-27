"""Quick access: a round button in the corner that opens a small panel (like a chat box) with the everyday
actions: quick check, full check, check my mail, To do; and, while a check runs, its progress and Stop."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QFrame, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from ...wording import CHECK, QUICK
from .cards import label

MARGIN = 20


class QuickAccess(QWidget):
    def __init__(self, win, parent: QWidget):
        super().__init__(parent)
        self.win = win
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.fab = QPushButton("⚡", parent)
        self.fab.setObjectName("fab")
        self.fab.setFixedSize(52, 52)
        self.fab.setToolTip(QUICK["button"])
        self.fab.setAccessibleName(QUICK["button"])
        self.fab.setCursor(Qt.CursorShape.PointingHandCursor)
        self.fab.clicked.connect(self.toggle)

        self.panel = QFrame(parent)
        self.panel.setObjectName("quick")
        self.panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.panel.setFixedWidth(280)
        lay = QVBoxLayout(self.panel)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)
        head = QHBoxLayout()
        head.addWidget(label(QUICK["title"], "title"), 1)
        close = QPushButton("✕")
        close.setObjectName("link")
        close.setAccessibleName(QUICK["close"])
        close.clicked.connect(self.panel.hide)
        head.addWidget(close)
        lay.addLayout(head)
        self.status = label("", "muted")
        lay.addWidget(self.status)
        pick = QHBoxLayout()                           # everything, or one of your addresses / usernames
        pick.addWidget(label(QUICK["target"], wrap=False))
        self.target = QComboBox()
        self.target.setAccessibleName(QUICK["target"])
        self.target.addItem(CHECK["target_all"], None)
        pick.addWidget(self.target, 1)
        lay.addLayout(pick)
        self.buttons = {}
        for key in ("quick", "full", "mail", "todo", "stop"):
            b = QPushButton(QUICK[key] if key != "todo" else QUICK["todo_none"])
            b.setObjectName("primary" if key == "quick" else "")
            b.clicked.connect(lambda _=False, k=key: self._do(k))
            lay.addWidget(b)
            self.buttons[key] = b
        self.panel.hide()
        self.hide()                                    # this widget only holds the logic; fab + panel are shown
        self.place()

    def toggle(self) -> None:
        self.update_state()
        self.panel.setVisible(not self.panel.isVisible())
        self.place()
        self.panel.raise_()
        self.fab.raise_()

    def _do(self, key: str) -> None:
        if key == "todo":
            self.win.show_page("todo")
        elif key == "stop":
            if self.win.job:
                self.win._start_or_stop()
        else:
            self.win.start_check(key, identity=None if key == "mail" else self.target.currentData())
        self.panel.hide()

    def fill_targets(self, values: list[str]) -> None:
        current = self.target.currentData()
        self.target.clear()
        self.target.addItem(CHECK["target_all"], None)
        for v in values:
            self.target.addItem(v, v)
        self.target.setCurrentIndex(max(self.target.findData(current), 0))

    def update_state(self, needs_you: int | None = None) -> None:
        running = bool(self.win.job)
        for key in ("quick", "full", "mail"):
            self.buttons[key].setVisible(not running)
        self.target.setEnabled(not running)
        self.buttons["stop"].setVisible(running)
        if needs_you is not None:
            self.buttons["todo"].setText(QUICK["todo"].format(count=needs_you) if needs_you else QUICK["todo_none"])
        if running:
            self.status.setText(QUICK["running"].format(text=self.win.detail.text() or self.win.step.text()))
        else:
            self.status.setText(self.win.status.text().split("   ·   ")[0])

    def place(self) -> None:
        par = self.fab.parentWidget()
        self.fab.move(par.width() - self.fab.width() - MARGIN, par.height() - self.fab.height() - MARGIN)
        self.panel.adjustSize()
        self.panel.move(par.width() - self.panel.width() - MARGIN,
                        self.fab.y() - self.panel.height() - 10)
        self.fab.raise_()
