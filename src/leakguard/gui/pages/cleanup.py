"""Clean-up: every step, grouped by where it stands, and a way to add a site no check found."""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QFrame, QHBoxLayout, QLineEdit, QScrollArea, QVBoxLayout, QWidget

from ... import service, wording
from ...wording import CLEANUP
from ..actions import ActionCard, button
from ..widgets.cards import label

GROUPS = (("your_turn", ("planned", "drafted")), ("waiting", ("requested", "acknowledged", "removed")),
          ("finished", ("verified", "done")), ("skipped", ("skipped",)))


class CleanupPage(QScrollArea):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.body = QWidget()
        self.setWidget(self.body)

    def refresh(self, _overview=None) -> None:
        pos = self.verticalScrollBar().value()
        self.body = QWidget()
        lay = QVBoxLayout(self.body)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.setSpacing(10)
        lay.addWidget(label(wording.NAV["cleanup"], "hero"))
        lay.addWidget(label(CLEANUP["intro"], "muted"))
        actions = self.win.store.actions()
        if not actions:
            lay.addWidget(label(CLEANUP["empty"], "lead"))
        for key, states in GROUPS:
            rows = [a for a in actions if a["state"] in states]
            if not rows:
                continue
            lay.addSpacing(10)
            lay.addWidget(label(f"{CLEANUP[key]} ({len(rows)})", "big"))
            for a in rows:
                lay.addWidget(ActionCard(self.win.actions, a))
        self._add_form(lay)
        lay.addStretch(1)
        self.setWidget(self.body)                       # the scroll area deletes the previous body
        self.verticalScrollBar().setValue(pos)

    def _add_form(self, lay) -> None:
        lay.addSpacing(14)
        lay.addWidget(label(CLEANUP["add_title"], "big"))
        lay.addWidget(label(CLEANUP["add_help"], "muted"))
        row = QHBoxLayout()
        site = QLineEdit()
        site.setPlaceholderText(CLEANUP["add_site"])
        who = QComboBox()
        who.setAccessibleName(CLEANUP["add_who"])
        for i in self.win.store.identities("claimed"):
            if i.kind != "keyword":
                who.addItem(i.value)
        where = QLineEdit()
        where.setPlaceholderText(CLEANUP["add_page"])
        add = button(CLEANUP["add"], True)
        for w, stretch in ((site, 2), (who, 2), (where, 3)):
            row.addWidget(w, stretch)
        row.addWidget(add)
        lay.addLayout(row)

        def go():
            name, contact = site.text().strip(), where.text().strip()
            if not name or not who.currentText():
                return
            email = contact if "@" in contact and "/" not in contact else ""
            url = "" if email or not contact else (contact if "://" in contact else "https://" + contact)
            service.add_site(self.win.settings, self.win.store, name, who.currentText(), url, email,
                             why="added in the desktop app")
            self.win.changed()
            self.win.toast.show_message(CLEANUP["added"].format(target=name))
        add.clicked.connect(go)
