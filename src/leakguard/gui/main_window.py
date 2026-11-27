"""The main window, laid out like Zenmap: what to check and how at the top, Start, progress, pages below."""

from __future__ import annotations

import shlex

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (QButtonGroup, QHBoxLayout, QLineEdit, QMainWindow, QMessageBox,
                               QProgressBar, QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from .. import config, monitor, service, wording
from ..plugins import active
from ..wording import CHECK as C
from . import theme, worker
from .actions import ActionController
from .pages.cleanup import CleanupPage
from .pages.found import FoundPage
from .pages.mail import MailPage
from .pages.overview import OverviewPage
from .pages.reports import ReportsPage
from .pages.soon import SoonPage
from .pages.todo import TodoPage
from .widgets.cards import Toast, label
from .widgets.quick import QuickAccess
from .wizard.about_you import AboutYouDialog

PAGES = ("overview", "todo", "found", "cleanup", "mail", "reports")
PINNED_LAST = "reports"            # always at the bottom of the sidebar, whatever pages are added above it
M = wording.MENU


class MainWindow(QMainWindow):
    def __init__(self, profile: str):
        super().__init__()
        self.profile = profile
        self.settings, self.store = service.open_profile(profile)
        self.job: worker.Job | None = None              # the running check
        self.jobs: set[worker.Job] = set()              # other background work (send, form, re-check)
        self.actions = ActionController(self)
        self._refresh_pending = False
        self._stage, self._last_done = 1, 0
        self._first_run = False
        self.setWindowTitle("LeakGuard" + (" (practice mode)" if self.settings.is_lab else ""))
        self.setWindowIcon(theme.app_icon())
        self.resize(1180, 780)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 10, 12, 6)
        root.setSpacing(8)

        if self.settings.is_lab:
            root.addWidget(label(wording.PRACTICE, "banner"))

        # the equivalent command (View > Show the command line), like Zenmap's: the last check started
        self.command = QLineEdit(command_for("quick", None, self.profile, self.settings))
        self.command.setReadOnly(True)
        self.command.setAccessibleName("The same check from the command line")
        self.command.hide()
        root.addWidget(self.command)

        # progress, with Stop (only while a check runs); checks start from the Overview, the menu or quick access
        self.progress_box = QWidget()
        pl = QHBoxLayout(self.progress_box)
        pl.setContentsMargins(0, 0, 0, 0)
        words = QVBoxLayout()
        self.step = label("", "title")
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(10)
        self.detail = label("", "muted")
        for w in (self.step, self.bar, self.detail):
            words.addWidget(w)
        pl.addLayout(words, 1)
        self.stop_btn = QPushButton(C["stop"])
        self.stop_btn.clicked.connect(self.stop_check)
        pl.addWidget(self.stop_btn)
        self.progress_box.hide()
        root.addWidget(self.progress_box)
        self._ident: str | None = None                  # the running check's single address, if any

        # pages
        body = QHBoxLayout()
        side = QWidget()
        side.setFixedWidth(190)
        side.setAccessibleName("Pages")
        nav = QVBoxLayout(side)
        nav.setContentsMargins(0, 0, 0, 0)
        nav.setSpacing(2)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        self.stack = QStackedWidget()
        self.pages = {}
        for name in PAGES:
            page = {"overview": OverviewPage, "todo": TodoPage, "found": FoundPage,
                    "cleanup": CleanupPage, "mail": MailPage, "reports": ReportsPage}.get(name)
            page = (page() if name == "overview" else page(self)) if page else SoonPage(wording.NAV[name])
            if name == "overview":
                page.navigate.connect(self.show_page)
                page.check.connect(lambda kind: self.start_check(kind))
            self.pages[name] = page
            self.stack.addWidget(page)
            b = QPushButton(wording.NAV[name])
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _=False, n=name: self.show_page(n))
            self.nav_group.addButton(b)
            self.nav_buttons[name] = b
        for name in PAGES:
            if name != PINNED_LAST:
                nav.addWidget(self.nav_buttons[name])
        nav.addStretch(1)
        nav.addWidget(self.nav_buttons[PINNED_LAST])
        body.addWidget(side)
        body.addWidget(self.stack, 1)
        root.addLayout(body, 1)

        self.status = label("", "muted", wrap=False)
        self.statusBar().addWidget(self.status, 1)
        self.toast = Toast(central)
        from .notify import Notifier
        self.notifier = Notifier(self)
        self.quick = QuickAccess(self, central)
        self._menus()
        self.show_page("overview")

        self.refresh()

    # ---- menus: File, Edit, View, Settings, Add-ons, Help ---------------------------------------------
    def _menus(self) -> None:
        def act(menu, text, fn, shortcut=None, enabled=True):
            a = QAction(text, self, triggered=lambda *_: fn())
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            a.setEnabled(enabled)
            menu.addAction(a)
            return a
        bar, lab = self.menuBar(), self.settings.is_lab
        f = bar.addMenu(M["file"])
        act(f, M["quick"], lambda: self.start_check("quick"), "Ctrl+R")
        act(f, M["full"], lambda: self.start_check("full"), "Ctrl+Shift+R")
        act(f, M["mail"], lambda: self.start_check("mail"), "Ctrl+M")
        f.addSeparator()
        act(f, M["report"], self._save_report, "Ctrl+S")
        f.addSeparator()
        f.addAction(QAction(M["quit"], self, shortcut=QKeySequence.StandardKey.Quit, triggered=self.close))
        e = bar.addMenu(M["edit"])
        act(e, M["undo"], self._undo, QKeySequence.StandardKey.Undo)
        act(e, M["find"], self._find, QKeySequence.StandardKey.Find)
        v = bar.addMenu(M["view"])
        for n, name in enumerate(PAGES, 1):
            act(v, wording.NAV[name], lambda name=name: self.show_page(name), f"Ctrl+{n}")
        v.addSeparator()
        self.show_command = QAction(M["command"], self, checkable=True, toggled=self.command.setVisible)
        v.addAction(self.show_command)
        act(v, M["refresh"], self.refresh, QKeySequence.StandardKey.Refresh)
        s = bar.addMenu(M["settings"])
        act(s, M["about_you"], self._edit_identity, enabled=not lab)   # practice mode uses its made-up person
        act(s, M["mail_connection"], lambda: self.show_page("mail"))
        act(s, M["services"], lambda: self.open_settings("services"), "Ctrl+,")
        act(s, M["tools"], lambda: self.open_settings("tools"))
        act(s, M["auto"], lambda: self.open_settings("auto"))
        a = bar.addMenu(M["addons"])
        act(a, M["add_tool"], self._add_tool)
        act(a, M["my_tools"], lambda: self.open_settings("tools"))
        act(a, M["tool_guide"], lambda: self._open_doc("ADD_A_TOOL.md"))
        h = bar.addMenu(M["help"])
        act(h, M["manual"], lambda: self._open_doc("MANUAL.md"), QKeySequence.StandardKey.HelpContents)
        act(h, M["tool_guide"], lambda: self._open_doc("ADD_A_TOOL.md"))
        h.addSeparator()
        act(h, M["about"], self._about)

    def show_page(self, name: str) -> None:
        self.stack.setCurrentIndex(PAGES.index(name))
        self.nav_buttons[name].setChecked(True)

    def _undo(self) -> None:
        if not self.toast.undo_last():
            self.toast.show_message(M["nothing_to_undo"])

    def _find(self) -> None:
        self.show_page("found")
        self.pages["found"].search.setFocus()

    def _save_report(self) -> None:
        self.show_page("reports")
        self.pages["reports"].save_report()

    def _add_tool(self) -> None:
        from .add_tool import AddToolDialog
        if AddToolDialog(self).exec():
            self.changed()

    def _open_doc(self, name: str) -> None:
        from ..paths import ROOT
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(ROOT / "docs" / name)))

    def _about(self) -> None:
        from .. import __version__
        QMessageBox.about(self, M["about"].replace("&", ""), M["about_text"].format(version=__version__))

    # ---- data -------------------------------------------------------------------------------------
    def refresh(self) -> None:
        ov = service.overview(self.settings, self.store)
        for page in self.pages.values():
            page.refresh(ov)
        self.nav_buttons["todo"].setText(f"{wording.NAV['todo']} ({ov.needs_you})" if ov.needs_you
                                         else wording.NAV["todo"])
        parts = [wording.OVERVIEW["last_check"].format(when=wording.ago(ov.last_check))
                 if ov.last_check else wording.OVERVIEW["never"]]
        parts.append(wording.OVERVIEW["waiting"].format(count=ov.waiting, sites=wording.plural(ov.waiting, "site"),
                                                       date=wording.day(ov.next_follow_up) or "soon")
                     if ov.waiting else wording.OVERVIEW["waiting_none"])
        self.status.setText("   ·   ".join(parts))
        self.quick.fill_targets([i.value for i in self.store.identities("claimed") if i.kind != "keyword"])
        self.quick.update_state(ov.needs_you)

    # ---- checks -----------------------------------------------------------------------------------
    def stop_check(self) -> None:
        if self.job:
            self.job.cancel.set()
            self.stop_btn.setEnabled(False)
            self.detail.setText(C["stopping"])

    def _start_or_stop(self) -> None:                     # kept for the quick panel's Stop
        self.stop_check()

    def start_check(self, kind: str = "quick", first_run: bool = False, identity: str | None = None) -> None:
        """kind: quick | full | mail. identity: one claimed address or username (quick access), else everything."""
        if self.job:
            self.toast.show_message(C["running"])
            return
        kind = kind or "quick"
        self.command.setText(command_for(kind, identity, self.profile, self.settings))
        if kind == "mail":                                # the mail page runs it and shows the preview
            self.show_page("mail")
            self.pages["mail"].check()
            return
        profile, self._first_run, self._ident = self.profile, first_run, identity

        def run(progress, cancel):
            s, st = service.open_profile(profile)          # this thread's own connection
            return service.run_check(s, st, kind, progress, cancel, identity)

        self.job = worker.Job(run, self.settings.secret_values())
        self.job.signals.progress.connect(self._progress)
        self.job.signals.done.connect(self._done)
        self.job.signals.failed.connect(self._failed)
        self._stage, self._last_done = 1, 0
        self.step.setText(C["single"].format(value=identity) if identity else C["step_keyword"])
        self.detail.setText("")
        self.bar.setRange(0, 0)                            # busy until the first result arrives
        self.stop_btn.setEnabled(True)
        self.progress_box.show()
        self.pages["overview"].set_running(True)
        self.quick.update_state()
        worker.start(self.job)

    def _progress(self, done: int, total: int, source: str, _identity: str, _status: str) -> None:
        if done < self._last_done:                         # the second stage started
            self._stage = 2
            if not self._ident:
                self.step.setText(C["step_identities"])
        self._last_done = done
        self.bar.setRange(0, total)
        self.bar.setValue(done)
        self.detail.setText(C["progress"].format(done=done, total=total,
                                                 source=wording.SOURCE.get(source, source)))
        if done == total and (self._stage == 2 or self._ident):
            self.bar.setRange(0, 0)
            self.detail.setText(C["finishing"])
        if self.quick.panel.isVisible():
            self.quick.update_state()

    def _finish(self) -> None:
        self.job = None
        self._ident = None
        self.progress_box.hide()
        self.pages["overview"].set_running(False)
        self.refresh()
        self.quick.update_state()

    def _done(self, res: service.CheckResult) -> None:
        self._finish()
        words = " ".join(check_summary(res, self._first_run))
        if res.serious:
            self.notifier.notify(wording.NOTIFY["serious"], words, serious=True)
        else:
            self.notifier.notify(wording.NOTIFY["check_done"], words)
        self.toast.show_message(" ".join(check_summary(res, self._first_run)),
                                "Details" if res.problems else "",
                                (lambda: self._details(C["problems"].format(
                                    count=len(res.problems), services=wording.plural(len(res.problems), "service")),
                                    "\n".join(res.problems))) if res.problems else None,
                                seconds=14)

    def _failed(self, detail: str) -> None:
        self._finish()
        self.toast.show_message(C["failed"], "Details", lambda: self._details(C["failed"], detail), seconds=20)

    def open_settings(self, tab: str = "services") -> None:
        from .settings import SettingsDialog
        SettingsDialog(self, tab if isinstance(tab, str) else "services").exec()
        self.settings = config.load(self.profile)        # keys may have changed
        self.changed()

    def changed(self) -> None:
        """Something was answered or moved on: every page shows the new state. Deferred until the click that
        caused it has finished (rebuilding a page deletes the button being clicked), and merged into one."""
        if not self._refresh_pending:
            self._refresh_pending = True
            QTimer.singleShot(0, self._refresh_now)

    def _refresh_now(self) -> None:
        self._refresh_pending = False
        self.refresh()

    def run_job(self, fn, done, failed=None) -> None:
        """Background work other than a check (send, fill a form, re-check one removal)."""
        job = worker.Job(fn, self.settings.secret_values())
        self.jobs.add(job)

        def finish(handler, value):
            self.jobs.discard(job)
            if handler:
                handler(value)
        job.signals.done.connect(lambda r: finish(done, r))
        job.signals.failed.connect(lambda d: finish(failed or (lambda x: self.show_details(C["failed"], x)), d))
        worker.start(job)

    def show_details(self, text: str, detail: str) -> None:
        self._details(text, detail)

    def _details(self, text: str, detail: str) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("Details")
        box.setText(text)
        box.setDetailedText(detail)
        box.exec()

    # ---- other ------------------------------------------------------------------------------------
    def _edit_identity(self) -> None:
        if AboutYouDialog(self, first_run=False).exec():
            self.settings = config.load(self.profile)
            self.refresh()

    def closeEvent(self, event) -> None:
        if self.job:                                       # finished runs are saved; the rest is dropped
            self.job.cancel.set()
        self.notifier.hide()
        super().closeEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, "quick"):
            self.quick.place()
        if self.toast.isVisible():
            QTimer.singleShot(0, self.toast._place)


def command_for(kind: str, identity: str | None, profile: str, settings) -> str:
    """The same check as a leakguard command (View > Show the command line)."""
    p = ["-p", profile]
    if kind == "mail":
        cmd = ["leakguard", "block", *p]
    elif identity:
        cmd = ["leakguard", "scan", "--identity", identity, *p]
        if kind == "quick":
            cmd += [a for s in active(settings) if s.name not in monitor.SLOW_TOOLS for a in ("-s", s.name)]
    else:
        cmd = ["leakguard", "monitor", *(["--quick"] if kind == "quick" else []), *p]
    return shlex.join(cmd)


def check_summary(res: service.CheckResult, first_run: bool = False) -> list[str]:
    """The plain sentences shown when a check ends."""
    if res.cancelled:
        return [C["stopped"]]
    out = [C["new"].format(count=res.new, things=wording.plural(res.new, "thing")) if res.new else C["nothing_new"]]
    if res.serious:
        out.append(C["serious"].format(count=res.serious, look="looks" if res.serious == 1 else "look"))
    if res.gone:
        out.append(C["gone"].format(count=res.gone, things=wording.plural(res.gone, "thing")))
    if res.candidates:
        n = len(res.candidates)
        out.append(C["candidates"].format(count=n, addresses=wording.plural(n, "address or username",
                                                                             "addresses or usernames")))
    if res.problems:
        n = len(res.problems)
        out.append(C["problems"].format(count=n, services=wording.plural(n, "service")))
    if first_run:
        out.append(C["first_hint"])
    return out
