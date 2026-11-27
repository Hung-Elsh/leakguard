"""Clean-up: add a site no check found (always at the top), then every step in tabs by where it stands."""

from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLineEdit, QScrollArea, QTabWidget, QVBoxLayout,
                               QWidget)

from ... import service, wording
from ...wording import CLEANUP
from ..actions import ActionCard, button
from ..widgets.cards import label

GROUPS = (("your_turn", ("planned", "drafted")), ("waiting", ("requested", "acknowledged", "removed")),
          ("finished", ("verified", "done")), ("skipped", ("skipped",)))


class CleanupPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(8)
        lay.addWidget(label(wording.NAV["cleanup"], "hero"))
        lay.addWidget(label(CLEANUP["intro"], "muted"))
        self._add_form(lay)
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)

    def refresh(self, _overview=None) -> None:
        current = self.tabs.currentIndex()
        positions = [self.tabs.widget(i).verticalScrollBar().value() for i in range(self.tabs.count())]
        self.tabs.clear()
        actions = self.win.store.actions()
        self.who.clear()
        for i in self.win.store.identities("claimed"):
            if i.kind != "keyword":
                self.who.addItem(i.value)
        for n, (key, states) in enumerate(GROUPS):
            rows = [a for a in actions if a["state"] in states]
            body = QWidget()
            bl = QVBoxLayout(body)
            bl.setSpacing(8)
            if not rows:
                bl.addWidget(label(CLEANUP["empty"], "muted"))
            for a in rows:
                bl.addWidget(ActionCard(self.win.actions, a))
            bl.addStretch(1)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setWidget(body)
            self.tabs.addTab(scroll, CLEANUP[key])
            if n < len(positions):
                scroll.verticalScrollBar().setValue(positions[n])
        self.tabs.setCurrentIndex(max(current, 0))

    def _add_form(self, lay) -> None:
        box = QFrame()
        box.setObjectName("card")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(14, 10, 14, 10)
        bl.setSpacing(4)
        bl.addWidget(label(CLEANUP["add_title"], "title"))
        bl.addWidget(label(CLEANUP["add_help"], "muted"))
        row = QHBoxLayout()
        self.site = QLineEdit()
        self.site.setPlaceholderText(CLEANUP["add_site"])
        self.who = QComboBox()
        self.who.setAccessibleName(CLEANUP["add_who"])
        self.where = QLineEdit()
        self.where.setPlaceholderText(CLEANUP["add_page"])
        add = button(CLEANUP["add"], True)
        for w, stretch in ((self.site, 2), (self.who, 2), (self.where, 3)):
            row.addWidget(w, stretch)
        row.addWidget(add)
        bl.addLayout(row)
        lay.addWidget(box)
        add.clicked.connect(self._add)
        self.site.returnPressed.connect(self._add)

    def _add(self) -> None:
        name, contact = self.site.text().strip(), self.where.text().strip()
        if not name or not self.who.currentText():
            return
        email = contact if "@" in contact and "/" not in contact else ""
        url = "" if email or not contact else (contact if "://" in contact else "https://" + contact)
        service.add_site(self.win.settings, self.win.store, name, self.who.currentText(), url, email,
                         why="added in the desktop app")
        self.site.clear()
        self.where.clear()
        self.win.changed()
        self.win.toast.show_message(CLEANUP["added"].format(target=name))
