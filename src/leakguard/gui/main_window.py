"""The main window, laid out like Zenmap: what to check and how at the top, Start, progress, pages below."""

from __future__ import annotations

import shlex

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
                               QMessageBox, QProgressBar, QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from .. import config, monitor, service, wording
from ..plugins import ALL_PLUGINS
from ..wording import CHECK as C
from . import theme, worker
from .pages.overview import OverviewPage
from .pages.soon import SoonPage
from .widgets.cards import Toast, label
from .wizard.about_you import AboutYouDialog

PAGES = ("overview", "todo", "found", "cleanup", "mail", "reports")


class MainWindow(QMainWindow):
    def __init__(self, profile: str):
        super().__init__()
        self.profile = profile
        self.settings, self.store = service.open_profile(profile)
        self.job: worker.Job | None = None
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

        # what to check, how, Start
        bar = QHBoxLayout()
        bar.addWidget(label("Check:", wrap=False))
        self.target = QComboBox()
        self.target.setAccessibleName("What to check")
        self.target.setMinimumWidth(240)
        bar.addWidget(self.target)
        bar.addSpacing(12)
        bar.addWidget(label("How:", wrap=False))
        self.kind = QComboBox()
        self.kind.setAccessibleName("How to check")
        for k in service.CHECK_KINDS:
            self.kind.addItem(wording.CHECK_KIND[k], k)
            self.kind.setItemData(self.kind.count() - 1, wording.CHECK_KIND_HELP[k], Qt.ItemDataRole.ToolTipRole)
        bar.addWidget(self.kind)
        self.kind_help = label("", "muted", wrap=False)
        bar.addWidget(self.kind_help)
        bar.addStretch(1)
        self.start_btn = QPushButton(C["start"])
        self.start_btn.setObjectName("primary")
        self.start_btn.setShortcut(QKeySequence("Ctrl+R"))
        self.start_btn.clicked.connect(self._start_or_stop)
        bar.addWidget(self.start_btn)
        root.addLayout(bar)

        # the equivalent command (Advanced), like Zenmap's command line
        self.command = QLineEdit()
        self.command.setReadOnly(True)
        self.command.setAccessibleName("The same check from the command line")
        self.command.hide()
        root.addWidget(self.command)

        # progress (only while a check runs)
        self.progress_box = QWidget()
        pl = QVBoxLayout(self.progress_box)
        pl.setContentsMargins(0, 0, 0, 0)
        self.step = label("", "title")
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(10)
        self.detail = label("", "muted")
        for w in (self.step, self.bar, self.detail):
            pl.addWidget(w)
        self.progress_box.hide()
        root.addWidget(self.progress_box)

        # pages
        body = QHBoxLayout()
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(190)
        self.nav.setAccessibleName("Pages")
        self.stack = QStackedWidget()
        self.pages = {}
        for name in PAGES:
            page = OverviewPage() if name == "overview" else SoonPage(wording.NAV[name])
            if name == "overview":
                page.navigate.connect(self.show_page)
            self.pages[name] = page
            self.stack.addWidget(page)
            self.nav.addItem(QListWidgetItem(wording.NAV[name]))
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
        body.addWidget(self.nav)
        body.addWidget(self.stack, 1)
        root.addLayout(body, 1)

        self.status = label("", "muted", wrap=False)
        self.statusBar().addWidget(self.status, 1)
        self.toast = Toast(central)
        self._menus()

        self.target.currentIndexChanged.connect(self._update_command)
        self.kind.currentIndexChanged.connect(self._update_command)
        self.refresh()

    # ---- menus ------------------------------------------------------------------------------------
    def _menus(self) -> None:
        m = self.menuBar().addMenu("&LeakGuard")
        about = QAction("About you...", self, triggered=self._edit_identity)
        about.setEnabled(not self.settings.is_lab)          # practice mode uses its made-up person
        m.addAction(about)
        m.addSeparator()
        m.addAction(QAction("Quit", self, shortcut=QKeySequence.StandardKey.Quit, triggered=self.close))
        v = self.menuBar().addMenu("&View")
        self.show_command = QAction("Show the command line (advanced)", self, checkable=True,
                                    toggled=self.command.setVisible)
        v.addAction(self.show_command)
        v.addAction(QAction("Refresh", self, shortcut=QKeySequence.StandardKey.Refresh, triggered=self.refresh))

    def show_page(self, name: str) -> None:
        self.nav.setCurrentRow(PAGES.index(name))

    # ---- data -------------------------------------------------------------------------------------
    def refresh(self) -> None:
        ov = service.overview(self.settings, self.store)
        for page in self.pages.values():
            page.refresh(ov)
        self.nav.item(PAGES.index("todo")).setText(f"{wording.NAV['todo']} ({ov.needs_you})" if ov.needs_you
                                                    else wording.NAV["todo"])
        parts = [wording.OVERVIEW["last_check"].format(when=wording.ago(ov.last_check))
                 if ov.last_check else wording.OVERVIEW["never"]]
        parts.append(wording.OVERVIEW["waiting"].format(count=ov.waiting, sites=wording.plural(ov.waiting, "site"),
                                                       date=wording.day(ov.next_follow_up) or "soon")
                     if ov.waiting else wording.OVERVIEW["waiting_none"])
        self.status.setText("   ·   ".join(parts))
        self._fill_targets()

    def _fill_targets(self) -> None:
        current = self.target.currentData()
        self.target.blockSignals(True)
        self.target.clear()
        self.target.addItem(C["target_all"], None)
        for i in self.store.identities("claimed"):
            if i.kind != "keyword":
                self.target.addItem(i.value, i.value)
        idx = self.target.findData(current)
        self.target.setCurrentIndex(max(idx, 0))
        self.target.blockSignals(False)
        self._update_command()

    def _update_command(self) -> None:
        kind, ident = self.kind.currentData(), self.target.currentData()
        self.kind_help.setText(wording.CHECK_KIND_HELP.get(kind, ""))
        p = ["-p", self.profile]
        if ident:
            cmd = ["leakguard", "scan", "--identity", ident, *p]
            if kind == "quick":
                cmd += [a for s in ALL_PLUGINS if s.name not in monitor.SLOW_TOOLS for a in ("-s", s.name)]
        else:
            cmd = ["leakguard", "monitor", *(["--quick"] if kind == "quick" else []), *p]
        self.command.setText(shlex.join(cmd))

    # ---- checks -----------------------------------------------------------------------------------
    def _start_or_stop(self) -> None:
        if self.job:
            self.job.cancel.set()
            self.start_btn.setEnabled(False)
            self.detail.setText(C["stopping"])
        else:
            self.start_check()

    def start_check(self, kind: str | None = None, first_run: bool = False) -> None:
        if self.job:
            self.toast.show_message(C["running"])
            return
        if kind:
            self.kind.setCurrentIndex(self.kind.findData(kind))
        kind, ident, profile = self.kind.currentData(), self.target.currentData(), self.profile
        self._first_run = first_run

        def run(progress, cancel):
            s, st = service.open_profile(profile)          # this thread's own connection
            return service.run_check(s, st, kind, progress, cancel, ident)

        self.job = worker.Job(run, self.settings.secret_values())
        self.job.signals.progress.connect(self._progress)
        self.job.signals.done.connect(self._done)
        self.job.signals.failed.connect(self._failed)
        self._stage, self._last_done = 1, 0
        self.step.setText(C["single"].format(value=ident) if ident else C["step_keyword"])
        self.detail.setText("")
        self.bar.setRange(0, 0)                            # busy until the first result arrives
        self.progress_box.show()
        self.start_btn.setText(C["stop"])
        self.target.setEnabled(False)
        self.kind.setEnabled(False)
        worker.start(self.job)

    def _progress(self, done: int, total: int, source: str, _identity: str, _status: str) -> None:
        if done < self._last_done:                         # the second stage started
            self._stage = 2
            if not self.target.currentData():
                self.step.setText(C["step_identities"])
        self._last_done = done
        self.bar.setRange(0, total)
        self.bar.setValue(done)
        self.detail.setText(C["progress"].format(done=done, total=total,
                                                 source=wording.SOURCE.get(source, source)))
        if done == total and (self._stage == 2 or self.target.currentData()):
            self.bar.setRange(0, 0)
            self.detail.setText(C["finishing"])

    def _finish(self) -> None:
        self.job = None
        self.progress_box.hide()
        self.start_btn.setText(C["start"])
        self.start_btn.setEnabled(True)
        self.target.setEnabled(True)
        self.kind.setEnabled(True)
        self.refresh()

    def _done(self, res: service.CheckResult) -> None:
        self._finish()
        self.toast.show_message(" ".join(check_summary(res, self._first_run)),
                                "Details" if res.problems else "",
                                (lambda: self._details(C["problems"].format(
                                    count=len(res.problems), services=wording.plural(len(res.problems), "service")),
                                    "\n".join(res.problems))) if res.problems else None,
                                seconds=14)

    def _failed(self, detail: str) -> None:
        self._finish()
        self.toast.show_message(C["failed"], "Details", lambda: self._details(C["failed"], detail), seconds=20)

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
        super().closeEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            QTimer.singleShot(0, self.toast._place)


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
