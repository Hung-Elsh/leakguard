"""Mail: connect the mailbox (one screen), check it (a preview, nothing changes), then move what the owner saw.

Moving mail is the only change, and it asks first. Nothing is ever deleted: messages go to Junk, Trash or a
review folder, where the owner can move them back.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
                               QHeaderView, QLineEdit, QMessageBox, QPlainTextEdit, QScrollArea, QSpinBox,
                               QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)

from ... import config, keystore, service, wording
from ...mail import connection
from ...wording import MAIL
from ..actions import button
from ..widgets.cards import label


class MailPage(QScrollArea):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.result = None                       # the last preview: (BlockResult) until moved
        self.editing = False
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.body = QWidget()
        self.setWidget(self.body)

    def refresh(self, _overview=None) -> None:
        self.body = QWidget()
        lay = QVBoxLayout(self.body)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.setSpacing(10)
        lay.addWidget(label(wording.NAV["mail"], "hero"))
        lay.addWidget(label(MAIL["intro"], "muted"))
        st = service.mail_status(self.win.settings)
        if st.connected and not self.editing:
            self._connected(lay, st)
            if self.result is not None:
                self._preview(lay)
        else:
            lay.addWidget(ConnectMail(self))
        lay.addStretch(1)
        self.setWidget(self.body)                # the scroll area deletes the previous body

    # ---- connected ------------------------------------------------------------------------------
    def _connected(self, lay, st) -> None:
        card = QFrame()
        card.setObjectName("card")
        row = QHBoxLayout(card)
        row.setContentsMargins(16, 12, 16, 12)
        text = MAIL[f"connected_{st.how}"].format(address=st.address, provider=st.provider)
        row.addWidget(label(text, "lead"), 1)
        self.check_btn = button(MAIL["check"], True)
        self.check_btn.clicked.connect(self.check)
        row.addWidget(self.check_btn)
        if st.how != "practice":
            change, disconnect = button(MAIL["change"]), button(MAIL["disconnect"])
            change.clicked.connect(self._change)
            disconnect.clicked.connect(self._disconnect)
            row.addWidget(change)
            row.addWidget(disconnect)
        lay.addWidget(card)
        self.status = label("", "muted")
        lay.addWidget(self.status)

    def _change(self) -> None:
        self.editing = True
        self.refresh()

    def _disconnect(self) -> None:
        service.disconnect_mail(self.win.store)
        self.win.settings = config.load(self.win.profile)
        self.result = None
        self.win.changed()
        self.win.toast.show_message(MAIL["disconnected"])

    def check(self) -> None:
        if not service.mail_status(self.win.settings).connected:
            self.win.show_page("mail")
            return
        self.check_btn.setEnabled(False)
        self.status.setText(MAIL["checking"])
        profile = self.win.profile

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            return service.check_mail(s, st)

        def done(res):
            self.result = res
            self.refresh()

        def failed(detail):
            self.check_btn.setEnabled(True)
            self.status.setText(MAIL["failed"])
            self.win.show_details(MAIL["failed"], detail)
        self.win.run_job(run, done, failed)

    # ---- preview and move -----------------------------------------------------------------------
    def _preview(self, lay) -> None:
        res = self.result
        moving = [(m, v) for m, v in res.rows if v.action != "keep"]
        counts = Counter(v.action for _, v in moving)
        lines = [MAIL["summary"].format(total=res.total)]
        lines += [wording.MAIL_WOULD[a].format(count=n) + "." for a, n in counts.most_common()]
        lines.append(MAIL["keep_rest"].format(count=res.total - len(moving)) if moving else MAIL["nothing"])
        lay.addWidget(label("\n".join(lines)))
        if not moving:
            return
        move = button(MAIL["move"].format(count=len(moving)), True)
        move.clicked.connect(lambda: self._move(moving, counts))
        lay.addWidget(move, alignment=Qt.AlignmentFlag.AlignLeft)
        table = QTableWidget(len(moving), 4)
        table.setHorizontalHeaderLabels([MAIL[c] for c in ("col_from", "col_subject", "col_action", "col_why")])
        table.verticalHeader().hide()
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        h = table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for r, (m, v) in enumerate(moving):
            for c, text in enumerate((m.from_addr, m.subject, wording.MAIL_ACTION.get(v.action, v.action),
                                      wording.MAIL_RULE.get(v.rule, v.rule))):
                item = QTableWidgetItem(text)
                if c == 3:
                    item.setToolTip("\n".join(v.reasons))     # the rule's own detail, for the curious
                table.setItem(r, c, item)
        table.setMinimumHeight(min(60 + 30 * len(moving), 520))
        lay.addWidget(table)

    def _move(self, moving, counts) -> None:
        breakdown = "\n".join(wording.MAIL_WOULD[a].format(count=n) for a, n in counts.most_common())
        ask = QMessageBox.question(self, MAIL["move"].format(count=len(moving)),
                                   MAIL["move_confirm"].format(count=len(moving), breakdown=breakdown))
        if ask != QMessageBox.StandardButton.Yes:
            return
        self.status.setText(MAIL["moving"])
        profile = self.win.profile

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            return service.apply_mail(s, st, moving)      # exactly what the owner saw

        def done(moved):
            self.result = None
            self.win.changed()
            self.win.toast.show_message(MAIL["moved"].format(count=sum(moved.values())))
        self.win.run_job(run, done)


class ConnectMail(QFrame):
    """One screen: address, the 3 steps for that mail service, app password, Test & save."""

    def __init__(self, page: MailPage):
        super().__init__()
        self.page, self.win = page, page.win
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.addWidget(label(MAIL["connect_title"], "big"))
        if self.win.settings.is_lab:
            lay.addWidget(label(wording.PRACTICE, "muted"))
            return
        lay.addWidget(label(MAIL["connect_intro"], "muted"))
        lay.addWidget(label(MAIL["email"], "title"))
        main = next((s["value"] for s in self.win.settings.seeds if s.get("kind") == "email"), "")
        self.address = QLineEdit((connection.load() or {}).get("address") or main)
        self.address.setAccessibleName(MAIL["email"])
        lay.addWidget(self.address)
        self.detected = label("", "muted")
        lay.addWidget(self.detected)
        self.steps = QPlainTextEdit()
        self.steps.setReadOnly(True)
        self.steps.setFixedHeight(82)
        lay.addWidget(self.steps)
        self.open_page = button(MAIL["open_page"])
        self.open_page.clicked.connect(self._open_page)
        lay.addWidget(self.open_page, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(label(MAIL["password"], "title"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setAccessibleName(MAIL["password"])
        lay.addWidget(self.password)

        # Other mail service (advanced): its own servers
        self.other_toggle = QToolButton()
        self.other_toggle.setText(MAIL["other"])
        self.other_toggle.setCheckable(True)
        self.other_toggle.setStyleSheet("border: none;")
        self.other_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.other_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        lay.addWidget(self.other_toggle)
        self.other = QWidget()
        grid = QGridLayout(self.other)
        grid.setContentsMargins(0, 0, 0, 0)
        self.servers = {}
        for r, key in enumerate(("incoming", "outgoing")):
            host, port, sec = QLineEdit(), QSpinBox(), QComboBox()
            port.setRange(1, 65535)
            port.setValue(993 if key == "incoming" else 465)
            sec.addItem("SSL/TLS", "ssl")
            sec.addItem("STARTTLS", "starttls")
            for c, w in enumerate((label(MAIL[key], wrap=False), host, label(MAIL["port"], wrap=False), port,
                                   label(MAIL["security"], wrap=False), sec)):
                grid.addWidget(w, r, c)
            self.servers[key] = (host, port, sec)
        self.other.hide()
        lay.addWidget(self.other)
        self.other_toggle.toggled.connect(self._toggle_other)

        self.error = label("", "error")
        self.error.hide()
        lay.addWidget(self.error)
        row = QHBoxLayout()
        self.save = button(MAIL["test_save"], True)
        self.save.clicked.connect(self._test_save)
        row.addWidget(self.save)
        if service.mail_status(self.win.settings).connected:
            back = button(wording.SEND["not_now"])
            back.clicked.connect(self._back)
            row.addWidget(back)
        row.addStretch(1)
        lay.addLayout(row)

        lay.addSpacing(8)
        lay.addWidget(label(MAIL["google"], "title"))
        lay.addWidget(label(MAIL["google_help"], "muted"))
        pick = button(MAIL["google_pick"])
        pick.clicked.connect(self._google)
        lay.addWidget(pick, alignment=Qt.AlignmentFlag.AlignLeft)

        self.address.textChanged.connect(self._detect)
        self._detect()

    def _provider(self) -> str | None:
        return None if self.other_toggle.isChecked() else connection.provider_for(self.address.text())

    def _detect(self) -> None:
        addr = self.address.text().strip()
        key = connection.provider_for(addr)
        self.open_page.setVisible(bool(key))
        if connection.unsupported(addr):
            self.detected.setText(MAIL["unsupported"])
            self.steps.setPlainText("")
        elif key:
            self.detected.setText(MAIL["detected"].format(name=connection.PROVIDERS[key]["name"]))
            self.steps.setPlainText(wording.MAIL_STEPS[key])
        else:
            self.detected.setText(MAIL["unknown_provider"] if "@" in addr else "")
            self.steps.setPlainText(wording.MAIL_STEPS["other"])
            if "@" in addr and not self.other_toggle.isChecked():
                self.other_toggle.setChecked(True)

    def _toggle_other(self, on: bool) -> None:
        self.other.setVisible(on)
        self.other_toggle.setArrowType(Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)

    def _open_page(self) -> None:
        key = connection.provider_for(self.address.text())
        if key:
            QDesktopServices.openUrl(QUrl(connection.PROVIDERS[key]["page"]))

    def _servers(self) -> tuple[tuple, tuple, str]:
        key = self._provider()
        if key:
            p = connection.PROVIDERS[key]
            return p["imap"], p["smtp"], key
        (ih, ip, isec), (oh, op, osec) = self.servers["incoming"], self.servers["outgoing"]
        return ((ih.text().strip(), ip.value(), isec.currentData()),
                (oh.text().strip(), op.value(), osec.currentData()), "other")

    def _test_save(self) -> None:
        addr, password = self.address.text().strip(), self.password.text()
        imap, smtp, provider = self._servers()
        if "@" not in addr or not password or not imap[0] or not smtp[0] or connection.unsupported(addr):
            self._show_error(MAIL["unsupported"] if connection.unsupported(addr) else MAIL["unknown_provider"]
                             if not imap[0] else wording.MAIL_PROBLEM["refused"])
            return
        self.save.setEnabled(False)
        self.error.setText(MAIL["testing"])
        self.error.setObjectName("muted")
        self.error.show()
        profile = self.win.profile

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            return service.connect_mail(s, st, addr, password, imap, smtp, provider)

        def done(result):
            self.save.setEnabled(True)
            if not result.ok:
                self._show_error(wording.MAIL_PROBLEM.get(result.problem, wording.MAIL_PROBLEM["other"]))
                if result.problem == "other":
                    self.win.show_details(wording.MAIL_PROBLEM["other"], result.detail)
                return
            self.win.settings = config.load(profile)
            self.page.editing = False
            self.win.changed()
            self.win.toast.show_message(MAIL["saved"].format(where=keystore.store().where()))
        self.win.run_job(run, done)

    def _show_error(self, text: str) -> None:
        self.error.setObjectName("error")
        self.error.setStyleSheet("")
        self.error.setText(text)
        self.error.show()
        self.error.style().unpolish(self.error)
        self.error.style().polish(self.error)

    def _back(self) -> None:
        self.page.editing = False
        self.page.refresh()

    def _google(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, MAIL["google_pick"], str(Path.home()), "JSON (*.json)")
        if not f:
            return
        service.connect_google(self.win.store, Path(f), self.address.text())
        self.win.settings = config.load(self.win.profile)
        self.page.editing = False
        self.win.changed()
        self.win.toast.show_message(MAIL["google_saved"])
