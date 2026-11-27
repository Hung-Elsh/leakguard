"""Clean-up actions in the app: the card that shows one, and what its buttons do (shared by To do and Clean-up).

Nothing leaves the computer without the owner pressing Send or Submit in a dialog that shows exactly what goes
out; that button is the only place `confirm=True` is passed to the removal tracker.
"""

from __future__ import annotations

import json

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication, QPixmap
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QPushButton, QScrollArea, QVBoxLayout, QWidget)

from .. import service, wording
from ..removal import tracker
from ..store import ACTION_FLOW
from ..wording import FORM, SEND, STEPS, TODO
from .widgets.cards import label

WAITING = ("requested", "acknowledged", "removed")
YOUR_TURN = ("planned", "drafted")


def button(text: str, primary: bool = False) -> QPushButton:
    b = QPushButton(text.replace("&", "&&"))            # "&" would otherwise mark a keyboard shortcut
    if primary:
        b.setObjectName("primary")
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def is_page(contact: str | None) -> bool:
    return bool(contact) and "://" in contact


class ActionCard(QFrame):
    """One clean-up step: what it is, where it stands, and the buttons that move it on."""

    def __init__(self, ctl: "ActionController", a):
        super().__init__()
        self.setObjectName("card")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        text = QVBoxLayout()
        text.setSpacing(3)
        text.addWidget(label(wording.action_title(a), "title"))
        meta = []
        if a["state"] in YOUR_TURN:
            meta.append(wording.ACTION_HELP.get(a["method"], ""))
        else:
            meta.append(wording.ACTION_STATE[a["state"]])
            if a["next_check"] and a["state"] in WAITING:
                meta.append(TODO["next_check"].format(date=wording.day(a["next_check"])))
        who = json.loads(a["identities"] or "[]")
        if who:
            meta.append(wording.join_names(who))
        text.addWidget(label(" · ".join(m for m in meta if m), "muted"))
        lay.addLayout(text, 1)

        row = QHBoxLayout()
        row.setSpacing(6)
        for b in ctl.buttons(a):
            row.addWidget(b)
        lay.addLayout(row)


class ActionController:
    """What the action buttons do. `win` is the main window (store, settings, toast, jobs, refresh)."""

    def __init__(self, win):
        self.win = win

    # ---- which buttons --------------------------------------------------------------------------
    def buttons(self, a) -> list[QPushButton]:
        out = []

        def add(text, fn, primary=False):
            b = button(text, primary)
            b.clicked.connect(lambda _=False, a=a: fn(a))
            out.append(b)

        if a["state"] in YOUR_TURN:
            if a["method"] == "email":
                add(wording.METHOD_BUTTON["email"], self.review_send, True)
            elif a["method"] == "form":
                add(wording.METHOD_BUTTON["form"], self.review_form, True)
            elif a["method"] == "checklist":
                add(wording.METHOD_BUTTON["checklist"], self.show_steps, True)
            else:
                if is_page(a["contact"]):
                    add(wording.METHOD_BUTTON["manual"], self.open_page, True)
                if a["steps"]:
                    add(TODO["steps"], self.show_steps)
            if a["method"] in ("manual", "checklist"):
                add(TODO["done"], self.mark_done)
            add(TODO["cant"], self.skip)
        elif a["state"] in WAITING:
            if a["state"] == "requested":
                add(TODO["replied"], self.replied)
            if a["finding_ids"] != "[]" and a["kind"] not in tracker.OWNER_CONFIRMED:
                add(TODO["check_now"], self.check_now)
            add(TODO["its_done"], self.mark_done)
        elif a["state"] == "skipped":
            add(TODO["put_back"], self.put_back)
        add(TODO["history"], self.show_history)
        return out

    # ---- simple state changes (with Undo where the flow allows it) ---------------------------------
    def _move(self, a, state: str, message: str, note: str) -> None:
        before = a["state"]
        service.record_progress(self.win.store, a["id"], state, note)
        after = self.win.store.action(a["id"])["state"]
        def undo():
            service.record_progress(self.win.store, a["id"], before, "undone by owner")
            self.win.changed()
        can_undo = before in ACTION_FLOW.get(after, ())   # e.g. done -> planned is allowed; requested is not
        self.win.changed()
        self.win.toast.show_message(message.format(target=a["target"]), TODO["undo"] if can_undo else "",
                                    undo if can_undo else None)

    def mark_done(self, a) -> None:
        self._move(a, "done", TODO["marked_done"], "done (desktop app)")

    def skip(self, a) -> None:
        self._move(a, "skipped", TODO["skipped"], "can't do it (desktop app)")

    def replied(self, a) -> None:
        self._move(a, "acknowledged", TODO["replied_done"], "the site replied (desktop app)")

    def put_back(self, a) -> None:
        self._move(a, "planned", TODO["put_back_done"], "put back (desktop app)")

    def open_page(self, a) -> None:
        QDesktopServices.openUrl(QUrl(a["contact"]))

    # ---- dialogs ----------------------------------------------------------------------------------
    def show_steps(self, a) -> None:
        d = StepsDialog(self.win, a)
        if d.exec() and d.did_it:
            self.mark_done(a)

    def show_history(self, a) -> None:
        lines = [f"{wording.day(h['ts'])}  {wording.ACTION_STATE.get(h['state'], h['state'])}  ·  {h['note']}"
                 for h in json.loads(a["history"] or "[]")]
        d = QDialog(self.win)
        d.setWindowTitle(TODO["history"])
        lay = QVBoxLayout(d)
        lay.addWidget(label(wording.action_title(a), "title"))
        box = QPlainTextEdit("\n".join(reversed(lines)))
        box.setReadOnly(True)
        box.setMinimumSize(560, 260)
        lay.addWidget(box)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        d.exec()

    def review_send(self, a) -> None:
        SendDialog(self.win, a["id"]).exec()
        self.win.changed()

    def review_form(self, a) -> None:
        FormDialog(self.win, a["id"]).exec()
        self.win.changed()

    # ---- network work in the background -----------------------------------------------------------
    def check_now(self, a) -> None:
        aid, target, profile = a["id"], a["target"], self.win.profile
        self.win.toast.show_message(TODO["checking"].format(target=target), seconds=60)

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            return tracker.check(s, st, aid), st.action(aid)["next_check"]

        def done(result):
            text, next_check = result
            self.win.changed()
            words = wording.check_result(text, target, wording.day(next_check))
            self.win.toast.show_message(words)
            if words == TODO["gone"].format(target=target):
                self.win.notifier.notify(wording.NOTIFY["removed"], words)
        self.win.run_job(run, done)


class StepsDialog(QDialog):
    def __init__(self, parent, a):
        super().__init__(parent)
        self.did_it = False
        self.setWindowTitle(STEPS["title"])
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.addWidget(label(wording.action_title(a), "title"))
        steps = QPlainTextEdit(a["steps"] or "")
        steps.setReadOnly(True)
        steps.setMinimumHeight(220)
        lay.addWidget(steps)
        bb = QDialogButtonBox()
        if is_page(a["contact"]):
            op = bb.addButton(SEND["open_page"], QDialogButtonBox.ButtonRole.ActionRole)
            op.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(a["contact"])))
        if a["state"] in YOUR_TURN:
            yes = button(STEPS["done"], True)
            bb.addButton(yes, QDialogButtonBox.ButtonRole.AcceptRole)
            yes.clicked.connect(self._done)
        bb.addButton(STEPS["close"], QDialogButtonBox.ButtonRole.RejectRole)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _done(self) -> None:
        self.did_it = True
        self.accept()


class SendDialog(QDialog):
    """Shows the exact email. Send is the owner's confirmation; without a checked address it asks for one."""

    def __init__(self, win, action_id: int):
        super().__init__(win)
        self.win, self.aid = win, action_id
        self.setWindowTitle(SEND["title"])
        self.setMinimumSize(900, 600)                     # the request's lines fit without wrapping twice
        self.lay = QVBoxLayout(self)
        self.body = QWidget()
        self.lay.addWidget(self.body, 1)
        self.build()

    def build(self) -> None:
        old = self.body
        self.body = QWidget()
        self.lay.replaceWidget(old, self.body)
        old.deleteLater()
        lay = QVBoxLayout(self.body)
        lay.setContentsMargins(0, 0, 0, 0)
        a = self.win.store.action(self.aid)
        lay.addWidget(label(wording.action_title(a), "title"))
        if a["method"] == "email" and not (a["contact_verified"] and a["contact"] and "@" in a["contact"]):
            self._ask_contact(lay)
        msg, _ = tracker.draft(self.win.settings, self.win.store, self.aid)
        page = a["method"] != "email" and is_page(a["contact"])
        if not page and msg["To"]:
            for key, value in (("from", msg["From"]), ("to", msg["To"]), ("subject", msg["Subject"])):
                lay.addWidget(label(f"<b>{SEND[key]}:</b> {_html(value)}"))
        elif page:
            lay.addWidget(label(SEND["page_only"]))
        text = QPlainTextEdit(msg.get_content())
        text.setReadOnly(True)
        lay.addWidget(text, 1)
        self.status = label("", "muted")
        lay.addWidget(self.status)
        bb = QDialogButtonBox()
        if page:
            cp = bb.addButton(SEND["copy"], QDialogButtonBox.ButtonRole.ActionRole)
            cp.clicked.connect(lambda: (QGuiApplication.clipboard().setText(msg.get_content()),
                                        self.status.setText(SEND["copied"])))
            op = bb.addButton(SEND["open_page"], QDialogButtonBox.ButtonRole.ActionRole)
            op.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(a["contact"])))
        elif msg["To"] and a["contact_verified"]:
            self.status.setText(wording.SEND_CONFIRM.format(sender=msg["From"], to=msg["To"]))
            self.send_btn = button(SEND["send"], True)
            bb.addButton(self.send_btn, QDialogButtonBox.ButtonRole.AcceptRole)
            self.send_btn.clicked.connect(self._send)
        bb.addButton(SEND["not_now"], QDialogButtonBox.ButtonRole.RejectRole)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ask_contact(self, lay) -> None:
        lay.addWidget(label(SEND["need_contact"]))
        row = QHBoxLayout()
        field = QLineEdit(self.win.store.action(self.aid)["contact"] or "")   # a guess, for the owner to check
        field.setPlaceholderText(SEND["contact_placeholder"])
        save = button(SEND["save_contact"])
        row.addWidget(field, 1)
        row.addWidget(save)
        lay.addLayout(row)

        def saved():
            if field.text().strip():
                service.set_contact(self.win.store, self.aid, field.text())
                self.build()
        save.clicked.connect(saved)
        field.returnPressed.connect(saved)

    def _send(self) -> None:
        self.send_btn.setEnabled(False)
        self.status.setText(SEND["sending"])
        aid, profile = self.aid, self.win.profile

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            tracker.send(s, st, aid, confirm=True)         # the owner pressed Send on the exact text above
            a = st.action(aid)
            return a["contact"], a["next_check"]

        def done(result):
            to, next_check = result
            self.win.toast.show_message(SEND["sent"].format(to=to, date=wording.day(next_check)))
            self.accept()

        def failed(detail):
            self.status.setText(SEND["failed"])
            self.send_btn.setEnabled(True)
            self.win.show_details(SEND["failed"], detail)
        self.win.run_job(run, done, failed)


class FormDialog(QDialog):
    """Fills the site's form in a hidden browser and shows a picture of it; Submit is the confirmation."""

    def __init__(self, win, action_id: int):
        super().__init__(win)
        self.win, self.aid = win, action_id
        a = win.store.action(action_id)
        self.target = a["target"]
        self.setWindowTitle(FORM["title"])
        self.setMinimumSize(920, 660)
        lay = QVBoxLayout(self)
        lay.addWidget(label(wording.action_title(a), "title"))
        self.status = label(FORM["filling"].format(target=self.target), "muted")
        lay.addWidget(self.status)
        self.picture = QLabel()
        self.picture.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.picture)
        lay.addWidget(scroll, 1)
        bb = QDialogButtonBox()
        self.submit = button(FORM["submit"], True)
        self.submit.setEnabled(False)
        self.submit.clicked.connect(self._submit)
        bb.addButton(self.submit, QDialogButtonBox.ButtonRole.AcceptRole)
        bb.addButton(FORM["not_now"], QDialogButtonBox.ButtonRole.RejectRole)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self._fill()

    def _job(self, confirm: bool):
        aid, profile = self.aid, self.win.profile

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            res = tracker.submit_form(s, st, aid, confirm)  # confirm only from the Submit button
            return res, st.action(aid)["next_check"]
        return run

    def _fill(self) -> None:
        def done(result):
            res, _ = result
            self.picture.setPixmap(QPixmap(str(res.filled)))   # full size (readable); the area scrolls
            self.status.setText(FORM["filled"])
            self.submit.setEnabled(True)

        def failed(detail):
            self.status.setText(FORM["failed"])
            self.win.show_details(FORM["failed"], detail)
        self.win.run_job(self._job(False), done, failed)

    def _submit(self) -> None:
        self.submit.setEnabled(False)
        self.status.setText(FORM["submitting"])

        def done(result):
            res, next_check = result
            key = "submitted" if res.success else "no_success"
            self.win.toast.show_message(FORM[key].format(date=wording.day(next_check)))
            self.accept()

        def failed(detail):
            self.status.setText(FORM["failed"])
            self.win.show_details(FORM["failed"], detail)
        self.win.run_job(self._job(True), done, failed)


def _html(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

