"""Settings: search services (keys, each tested before it's saved) and extra checks (tools, one-click installs,
the Google check's sign-in). Every part is optional; each card is one step on its own."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLineEdit,
                               QPlainTextEdit, QScrollArea, QTabWidget, QVBoxLayout, QWidget)

from .. import keystore, service, wording
from ..wording import AUTO, GHUNT, KEYS, SETTINGS, TOOLS
from .actions import button
from .widgets.cards import label


def _scroll(inner: QWidget) -> QScrollArea:
    s = QScrollArea()
    s.setWidgetResizable(True)
    s.setFrameShape(QFrame.Shape.NoFrame)
    s.setWidget(inner)
    return s


def _card() -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(16, 12, 16, 12)
    lay.setSpacing(4)
    return f, lay


class SettingsDialog(QDialog):
    def __init__(self, win, tab: str = "services"):
        super().__init__(win)
        self.win = win
        self.setWindowTitle(SETTINGS["title"])
        self.resize(820, 720)
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(label(SETTINGS["title"], "hero"), 1)
        if not win.settings.is_lab:
            about = button(SETTINGS["about_you"])
            about.clicked.connect(win._edit_identity)
            top.addWidget(about)
        lay.addLayout(top)
        self.tabs = QTabWidget()
        self.tabs.addTab(_scroll(ServicesTab(win)), SETTINGS["services"])
        self.tabs.addTab(_scroll(ToolsTab(win)), SETTINGS["tools"])
        self.tabs.addTab(_scroll(AutoTab(win)), AUTO["tab"])
        self.tabs.setCurrentIndex({"tools": 1, "auto": 2}.get(tab, 0))
        lay.addWidget(self.tabs, 1)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)


class ServicesTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.addWidget(label(KEYS["intro"], "muted"))
        if win.settings.is_lab:
            lay.addWidget(label(KEYS["practice"], "muted"))
        for name in service.SEARCH_KEYS:
            lay.addWidget(KeyCard(win, name))
        lay.addStretch(1)


class KeyCard(QFrame):
    def __init__(self, win, name: str):
        super().__init__()
        self.win, self.name = win, name
        self.info = wording.KEY_INFO[name]
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 12, 16, 12)
        self.lay.setSpacing(4)
        head = QHBoxLayout()
        head.addWidget(label(self.info["name"], "title"), 1)
        self.status = label("", "muted", wrap=False)
        head.addWidget(self.status)
        self.lay.addLayout(head)
        self.lay.addWidget(label(f"{self.info['adds']} {self.info['cost']}.", "muted"))
        origin = win.settings.key_origin(name)
        self.editable = origin in ("", "keyring", "file") and not win.settings.is_lab
        if self.editable and origin == "":
            self.lay.addWidget(label(self.info["steps"], "muted"))
        row = QHBoxLayout()
        self.field = QLineEdit()
        self.field.setEchoMode(QLineEdit.EchoMode.Password)
        self.field.setPlaceholderText(KEYS["key"])
        self.field.setAccessibleName(f"{self.info['name']} {KEYS['key']}")
        self.field.setEnabled(self.editable)
        get = button(KEYS["open_page"])
        get.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.info["page"])))
        self.test = button(KEYS["test_save"] if self.editable else KEYS["test"], True)
        self.test.clicked.connect(self._test)
        self.remove = button(KEYS["remove"])
        self.remove.clicked.connect(self._remove)
        for w in (self.field,):
            row.addWidget(w, 1)
        for w in (get, self.test, self.remove):
            row.addWidget(w)
        self.lay.addLayout(row)
        self.note = label("", "muted")
        self.note.hide()                                  # shown only when there's something to say
        self.lay.addWidget(self.note)
        if origin in ("environment", "profile") and not win.settings.is_lab:
            self._say(KEYS["from_outside"])
        self._status()

    def _say(self, text: str) -> None:
        self.note.setText(text)
        self.note.setVisible(bool(text))

    def _status(self) -> None:
        origin = self.win.settings.key_origin(self.name)
        self.status.setText(KEYS["connected"] if origin else KEYS["not_connected"])
        self.remove.setVisible(self.editable and origin in ("keyring", "file"))

    def _test(self) -> None:
        value = self.field.text().strip() if self.editable else self.win.settings.key(self.name)
        if not value:
            return
        self.test.setEnabled(False)
        self._say(KEYS["testing"])
        name, profile, save = self.name, self.win.profile, self.editable

        def run(_progress, _cancel):
            s, st = service.open_profile(profile)
            return service.save_key(s, st, name, value) if save else service.test_key(s, name, value)

        def done(result):
            self.test.setEnabled(True)
            if result.ok:
                self.field.clear()
                self._say(KEYS["saved"].format(where=keystore.store().where()) if save else KEYS["works"])
                self.win.changed()
            else:
                self._say(wording.KEY_PROBLEM.get(result.problem, wording.KEY_PROBLEM["other"]))
                if result.problem == "other":
                    self.win.show_details(wording.KEY_PROBLEM["other"], result.detail)
            self._status()
        self.win.run_job(run, done)

    def _remove(self) -> None:
        service.forget_key(self.win.store, self.name)
        self._say(KEYS["removed"].format(name=self.info["name"]))
        self._status()
        self.win.changed()


class ToolsTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.addWidget(label(TOOLS["intro"], "muted"))
        if win.settings.is_lab:
            lay.addWidget(label(TOOLS["practice"], "muted"))
        cards = service.tool_cards()
        if any(c.pipx and not c.installed for c in cards) and not service.pipx_path():
            f, cl = _card()
            cl.addWidget(label(TOOLS["need_pipx"]))
            cl.addWidget(_command("sudo apt install -y pipx && pipx ensurepath"))
            lay.addWidget(f)
        for c in cards:
            lay.addWidget(ToolCardWidget(win, c))
        self._custom(lay)
        lay.addStretch(1)

    def _custom(self, lay) -> None:
        """Your own tools: switch on/off, change, remove, or add one (custom_tools.py)."""
        from .. import custom_tools
        from ..wording import CUSTOM
        from .add_tool import AddToolDialog
        lay.addSpacing(12)
        head = QHBoxLayout()
        head.addWidget(label(CUSTOM["section"], "big"), 1)
        add = button(CUSTOM["add"], True)
        add.clicked.connect(lambda: self._edit(AddToolDialog(self.win)))
        head.addWidget(add)
        lay.addLayout(head)
        lay.addWidget(label(CUSTOM["section_help"], "muted"))
        mine = custom_tools.load("lab" if self.win.settings.is_lab else "user")
        if not mine:
            lay.addWidget(label(CUSTOM["none"], "muted"))
        for m in mine:
            f, cl = _card()
            row = QHBoxLayout()
            row.addWidget(label(m.get("name", m.get("id", "?")), "title"), 1)
            if m.get("_origin") == "user":
                on = QCheckBox(CUSTOM["on"])
                on.setChecked(bool(m.get("enabled")))
                on.toggled.connect(lambda checked, tid=m["id"]: (service.switch_tool(tid, checked), self.win.changed()))
                change, remove = button(CUSTOM["edit"]), button(CUSTOM["remove"])
                change.clicked.connect(lambda _=False, m=m: self._edit(AddToolDialog(self.win, m)))
                remove.clicked.connect(lambda _=False, m=m: self._remove(m))
                for w in (on, change, remove):
                    row.addWidget(w)
            cl.addLayout(row)
            cl.addWidget(label(m.get("about", ""), "muted"))
            problems = custom_tools.problems(m, service.builtin_ids())
            if problems:
                cl.addWidget(label("\n".join(problems), "error"))
            elif m.get("_origin") == "lab":
                cl.addWidget(label(CUSTOM["practice_example"], "muted"))
            lay.addWidget(f)

    def _edit(self, dialog) -> None:
        if dialog.exec():
            self._rebuild()

    def _remove(self, m) -> None:
        from ..wording import CUSTOM
        service.remove_tool(m["id"])
        self.win.toast.show_message(CUSTOM["removed"].format(name=m.get("name", m["id"])))
        self._rebuild()

    def _rebuild(self) -> None:
        self.win.changed()
        scroll = self.parentWidget().parentWidget()      # the tab's scroll area: show the new list
        scroll.setWidget(ToolsTab(self.win))


def _command(cmd: str) -> QWidget:
    w = QWidget()
    row = QHBoxLayout(w)
    row.setContentsMargins(0, 0, 0, 0)
    field = QLineEdit(cmd)
    field.setReadOnly(True)
    copy = button(TOOLS["copy"])
    copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(cmd))
    row.addWidget(field, 1)
    row.addWidget(copy)
    return w


class ToolCardWidget(QFrame):
    def __init__(self, win, card: service.ToolCard):
        super().__init__()
        self.win, self.card = win, card
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)
        head = QHBoxLayout()
        head.addWidget(label(card.name, "title"), 1)
        self.status = label(TOOLS["installed"] if card.installed else TOOLS["missing"], "muted", wrap=False)
        head.addWidget(self.status)
        if card.name == "ghunt" and card.installed and not win.settings.is_lab:
            signed = service.ghunt_signed_in()
            self.ghunt_status = label(GHUNT["signed_in"] if signed else GHUNT["not_signed_in"], "muted", wrap=False)
            head.addWidget(self.ghunt_status)
            sign = button(GHUNT["button"])
            sign.clicked.connect(lambda: GhuntDialog(win).exec())
            head.addWidget(sign)
        lay.addLayout(head)
        lay.addWidget(label(wording.TOOL_INFO.get(card.name, ""), "muted"))
        if not card.installed:
            if card.pipx and service.pipx_path():
                self.install = button(TOOLS["install"], True)
                self.install.clicked.connect(self._install)
                lay.addWidget(self.install, alignment=Qt.AlignmentFlag.AlignLeft)
            elif not card.pipx:
                lay.addWidget(label(TOOLS["by_hand"], "muted"))
                lay.addWidget(_command(card.install))
        self.note = label("", "muted")
        self.note.hide()
        lay.addWidget(self.note)

    def _install(self) -> None:
        name = self.card.name
        self.install.setEnabled(False)
        self.note.show()
        self.note.setText(TOOLS["installing"].format(name=name))

        def run(_progress, _cancel):
            return service.install_tool(name)

        def done(result):
            ok, output = result
            if ok:
                self.note.setText(TOOLS["installed_ok"].format(name=name))
                self.status.setText(TOOLS["installed"])
                self.install.hide()
                self.win.changed()
            else:
                self.install.setEnabled(True)
                self.note.setText(TOOLS["install_failed"].format(name=name))
                self.win.show_details(TOOLS["install_failed"].format(name=name), output)
        self.win.run_job(run, done)


class GhuntDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle(GHUNT["title"])
        self.setMinimumWidth(620)
        lay = QVBoxLayout(self)
        lay.addWidget(label(GHUNT["title"], "big"))
        lay.addWidget(label(GHUNT["intro"], "muted"))
        steps = QPlainTextEdit(GHUNT["steps"])
        steps.setReadOnly(True)
        steps.setFixedHeight(80)
        lay.addWidget(steps)
        page = button(GHUNT["open_page"])
        page.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(GHUNT["page"])))
        lay.addWidget(page, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(label(GHUNT["code"], "title"))
        self.code = QLineEdit()
        self.code.setEchoMode(QLineEdit.EchoMode.Password)      # it works like a password
        self.code.setAccessibleName(GHUNT["code"])
        lay.addWidget(self.code)
        self.note = label("", "muted")
        lay.addWidget(self.note)
        bb = QDialogButtonBox()
        self.go = button(GHUNT["sign_in"], True)
        self.go.clicked.connect(self._sign_in)
        bb.addButton(self.go, QDialogButtonBox.ButtonRole.AcceptRole)
        bb.addButton(wording.SEND["not_now"], QDialogButtonBox.ButtonRole.RejectRole)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _sign_in(self) -> None:
        code = self.code.text().strip()
        if not code:
            return
        self.go.setEnabled(False)
        self.note.setText(GHUNT["signing_in"])

        def run(_progress, _cancel):
            return service.ghunt_sign_in(code)

        def done(result):
            ok, who, detail = result
            self.go.setEnabled(True)
            if ok:
                self.win.toast.show_message(GHUNT["ok"].format(who=who or "your spare account"))
                self.accept()
            else:
                self.note.setText(GHUNT["failed"])
                self.win.show_details(GHUNT["failed"], detail)
        self.win.run_job(run, done)


class AutoTab(QWidget):
    """The weekly check: one switch. On writes and enables a user-level timer; off disables it."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        f, cl = _card()
        self.switch = QCheckBox(AUTO["switch"])
        self.switch.setStyleSheet("font-size: 12pt; font-weight: 600;")
        cl.addWidget(self.switch)
        cl.addWidget(label(AUTO["help"], "muted"))
        self.status = label("", "muted")
        cl.addWidget(self.status)
        lay.addWidget(f)
        lay.addStretch(1)
        if win.settings.is_lab:
            self.switch.setEnabled(False)
            self.status.setText(AUTO["practice"])
            return
        on, nxt = service.weekly_status()
        self.switch.setChecked(on)
        self._show(on, nxt)
        self.switch.toggled.connect(self._toggle)

    def _show(self, on: bool, nxt: str) -> None:
        self.status.setText((AUTO["on"].format(date=wording.day(nxt)) if nxt else AUTO["on_soon"]) if on
                            else AUTO["off"])

    def _toggle(self, on: bool) -> None:
        self.switch.setEnabled(False)
        profile = self.win.profile

        def run(_progress, _cancel):
            ok, detail = service.set_weekly(profile, on)
            return ok, detail, service.weekly_status()

        def done(result):
            ok, detail, (now_on, nxt) = result
            self.switch.setEnabled(True)
            if not ok:
                self.win.show_details(AUTO["failed"], detail)
            self.switch.blockSignals(True)
            self.switch.setChecked(now_on)
            self.switch.blockSignals(False)
            self._show(now_on, nxt)
        self.win.run_job(run, done)
