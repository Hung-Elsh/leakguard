"""To do: every decision in one place, most important first, one click each, with Undo.

1. Is this you?        identities a check proposed (Yes / No; Yes to all / No to all; add one of yours)
2. What should we do?  new finds, grouped per site/page/leak (Remove / Keep & secure / Not me / Ignore)
3. Your turn           clean-up steps only the owner can do or confirm
4. Waiting for sites   requests that are out (collapsed)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLineEdit, QScrollArea, QToolButton, QVBoxLayout, QWidget)

from ... import config, service, wording
from ...wording import TODO
from .. import theme
from ..actions import ActionCard, button
from ..widgets.cards import label

FIRST = 12                                   # questions shown before "Show N more"
VERDICT_ORDER = ("open", "protect", "false_positive", "accepted")


class TodoPage(QScrollArea):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.show_all = False
        self.waiting_open = False
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.body = QWidget()
        self.setWidget(self.body)

    # ---- build ------------------------------------------------------------------------------------
    def refresh(self, _overview=None) -> None:
        pos = self.verticalScrollBar().value()
        self.body = QWidget()
        lay = QVBoxLayout(self.body)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.setSpacing(10)
        t = service.todo(self.win.settings, self.win.store)
        groups = service.review_groups(t.review)
        lay.addWidget(label(wording.NAV["todo"], "hero"))
        if not (t.candidates or groups or t.your_turn):
            lay.addWidget(label(TODO["empty"], "lead"))
        self._who(lay, t.candidates)
        if groups:
            self._what(lay, groups)
        if t.your_turn:
            self._section(lay, TODO["turn_title"], len(t.your_turn), TODO["turn_help"])
            for a in t.your_turn:
                lay.addWidget(ActionCard(self.win.actions, a))
        if t.waiting:
            self._waiting(lay, t.waiting)
        lay.addStretch(1)
        self.setWidget(self.body)                       # the scroll area deletes the previous body
        self.verticalScrollBar().setValue(pos)

    def _section(self, lay, title: str, count: int, help_: str, extra: list | None = None) -> None:
        head = QHBoxLayout()
        head.addWidget(label(f"{title} ({count})" if count else title, "big"), 1)
        for b in extra or []:
            head.addWidget(b)
        lay.addSpacing(10)
        lay.addLayout(head)
        lay.addWidget(label(help_, "muted"))

    # ---- 1. Is this you? --------------------------------------------------------------------------
    def _who(self, lay, candidates) -> None:
        extra = []
        if len(candidates) > 1:
            yes_all, no_all = button(TODO["yes_all"]), button(TODO["no_all"])
            yes_all.clicked.connect(lambda: self._decide(candidates, True))
            no_all.clicked.connect(lambda: self._decide(candidates, False))
            extra = [yes_all, no_all]
        if candidates:
            self._section(lay, TODO["who_title"], len(candidates), TODO["who_help"], extra)
        for c in candidates:
            card = QFrame()
            card.setObjectName("card")
            row = QHBoxLayout(card)
            row.setContentsMargins(16, 10, 16, 10)
            text = QVBoxLayout()
            text.addWidget(label(c.value, "title"))
            text.addWidget(label(f"{wording.IDENTITY_KIND.get(c.kind, c.kind)} · {wording.origin_text(c.origin)}",
                                 "muted"))
            row.addLayout(text, 1)
            yes, no = button(TODO["yes"], True), button(TODO["no"])
            yes.clicked.connect(lambda _=False, c=c: self._decide([c], True))
            no.clicked.connect(lambda _=False, c=c: self._decide([c], False))
            row.addWidget(yes)
            row.addWidget(no)
            lay.addWidget(card)
        # always offered: an address or username of yours that no check has found
        add = QHBoxLayout()
        field = QLineEdit()
        field.setPlaceholderText(TODO["add_placeholder"])
        field.setAccessibleName(TODO["add_mine"])
        go = button(TODO["add"])
        add.addWidget(label(TODO["add_mine"] + ":", wrap=False))
        add.addWidget(field, 1)
        add.addWidget(go)
        go.clicked.connect(lambda: self._add_mine(field))
        field.returnPressed.connect(lambda: self._add_mine(field))
        lay.addLayout(add)

    def _decide(self, idents, yours: bool) -> None:
        before = [(i.id, i.status) for i in idents]
        try:
            service.decide_identities(self.win.settings, self.win.store, [str(i.id) for i in idents], yours)
        except (config.ConfigError, ValueError, KeyError) as e:
            self.win.show_details(str(e), str(e))
            return
        who = wording.join_names([i.value for i in idents])
        text = (TODO["decided_yes"].format(who=who, them="them" if len(idents) > 1 else "it") if yours
                else TODO["decided_no"].format(who=who))

        def undo():
            service.undo_identities(self.win.settings, self.win.store, before)
            self.win.changed()
        self.win.changed()
        self.win.toast.show_message(text, TODO["undo"], undo)

    def _add_mine(self, field: QLineEdit) -> None:
        value = field.text().strip()
        if not value:
            return
        try:
            d = service.decide_identities(self.win.settings, self.win.store, [value], True)[0]
        except (config.ConfigError, ValueError) as e:
            self.win.toast.show_message(str(e))
            return
        self.win.changed()
        self.win.toast.show_message(TODO["decided_yes"].format(who=d.identity.value, them="it"))

    # ---- 2. What should we do? -------------------------------------------------------------------
    def _what(self, lay, groups) -> None:
        remove_all = button(TODO["remove_all"].format(count=len(groups)))
        remove_all.clicked.connect(lambda: self._answer(groups, "open"))
        self._section(lay, TODO["what_title"], len(groups), TODO["what_help"], [remove_all])
        shown = groups if self.show_all else groups[:FIRST]
        for g in shown:
            lay.addWidget(self._question(g))
        if len(groups) > len(shown):
            more = button(TODO["show_more"].format(count=len(groups) - len(shown)))
            more.clicked.connect(self._more)
            lay.addWidget(more, alignment=Qt.AlignmentFlag.AlignLeft)

    def _question(self, g) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        row = QHBoxLayout(card)
        row.setContentsMargins(0, 0, 16, 0)
        strip = QFrame()
        strip.setFixedWidth(6)
        strip.setStyleSheet(f"background: {theme.SEVERITY_COLOR.get(g.severity, theme.ACCENT)};"
                            "border-top-left-radius: 10px; border-bottom-left-radius: 10px;")
        row.addWidget(strip)
        text = QVBoxLayout()
        text.setContentsMargins(12, 10, 0, 10)
        text.addWidget(label(wording.group_sentence(g.category, g.rows)))
        sources = sorted({wording.SOURCE.get(r["source"], r["source"]) for r in g.rows})
        text.addWidget(label(f"{wording.SEVERITY[g.severity]} · {wording.CATEGORY.get(g.category, g.category)} · "
                             f"{TODO['found_by'].format(how=wording.join_names(sources))}", "muted"))
        row.addLayout(text, 1)
        for verdict in VERDICT_ORDER:
            b = button(wording.VERDICT_BUTTON[verdict], verdict == "open")
            b.clicked.connect(lambda _=False, g=g, v=verdict: self._answer([g], v))
            row.addWidget(b)
        return card

    def _answer(self, groups, verdict: str) -> None:
        ids = [fid for g in groups for fid in g.finding_ids]
        before = service.set_verdict(self.win.store, ids, verdict)
        n = len(groups)

        def undo():
            service.undo_verdicts(self.win.store, before)
            self.win.changed()
        self.win.changed()
        text = wording.VERDICT_DONE[verdict] if n == 1 else TODO["answered"].format(
            answer=wording.VERDICT_DONE[verdict].rstrip("."), count=n, things=wording.plural(n, "thing"))
        self.win.toast.show_message(text, TODO["undo"], undo)

    def _more(self) -> None:
        self.show_all = True
        self.refresh()

    # ---- 4. Waiting -------------------------------------------------------------------------------
    def _waiting(self, lay, waiting) -> None:
        toggle = QToolButton()
        toggle.setText(f"{TODO['waiting_title']} ({len(waiting)})")
        toggle.setObjectName("link")
        toggle.setCheckable(True)
        toggle.setChecked(self.waiting_open)
        toggle.setArrowType(Qt.ArrowType.DownArrow if self.waiting_open else Qt.ArrowType.RightArrow)
        toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        toggle.setStyleSheet("font-size: 14pt; font-weight: 600; border: none;")
        toggle.toggled.connect(self._toggle_waiting)
        lay.addSpacing(10)
        lay.addWidget(toggle)
        if self.waiting_open:
            lay.addWidget(label(TODO["waiting_help"], "muted"))
            for a in waiting:
                lay.addWidget(ActionCard(self.win.actions, a))

    def _toggle_waiting(self, on: bool) -> None:
        self.waiting_open = on
        self.refresh()
