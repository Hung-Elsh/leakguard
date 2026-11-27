"""Desktop notifications from a tray icon: when a check finishes, something serious turns up, or a removal is
confirmed. When the window is in front, the message inside the app is enough, so nothing pops up twice."""

from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ..wording import NOTIFY
from . import theme


class Notifier:
    def __init__(self, win):
        self.win = win
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return                                    # no tray on this desktop: in-app messages only
        self.tray = QSystemTrayIcon(theme.app_icon(), win)
        self.tray.setToolTip("LeakGuard")
        menu = QMenu(win)
        menu.addAction(QAction(NOTIFY["open"], menu, triggered=self.show_window))
        menu.addAction(QAction(NOTIFY["quick"], menu, triggered=lambda: win.start_check("quick")))
        menu.addSeparator()
        menu.addAction(QAction(NOTIFY["quit"], menu, triggered=win.close))
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.show_window()
                                    if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.messageClicked.connect(self.show_window)
        self.tray.show()

    def show_window(self) -> None:
        self.win.showNormal()
        self.win.raise_()
        self.win.activateWindow()

    def notify(self, title: str, text: str, serious: bool = False) -> bool:
        """Pop up a desktop notification unless the owner is looking at the window. Returns True if shown."""
        if not self.tray or self.win.isActiveWindow():
            return False
        icon = QSystemTrayIcon.MessageIcon.Warning if serious else QSystemTrayIcon.MessageIcon.Information
        self.tray.showMessage(title, text, icon, 15000)
        return True

    def hide(self) -> None:
        if self.tray:
            self.tray.hide()
