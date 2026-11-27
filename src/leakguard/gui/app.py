"""Start the desktop app: `leakguard-app` (your own data), `leakguard-app --practice` (made-up data, no internet).

`leakguard-app --add-to-menu` adds LeakGuard to your desktop's application menu (your user only, no admin).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

DESKTOP = """[Desktop Entry]
Type=Application
Name=LeakGuard
GenericName=Personal data clean-up
Comment=Find, block and remove your leaked personal data
Exec={exec}
Icon=leakguard
Terminal=false
Categories=Utility;Security;
"""


def add_to_menu() -> list[Path]:
    """Write ~/.local/share/applications/leakguard.desktop and its icon (user-level, no admin rights)."""
    from PySide6.QtGui import QGuiApplication
    from . import theme
    app = QGuiApplication.instance() or QGuiApplication([])    # a pixmap needs a running Qt application
    app.processEvents()
    exe = shutil.which("leakguard-app") or str(Path(sys.argv[0]).resolve())
    share = Path.home() / ".local" / "share"
    icon = share / "icons" / "hicolor" / "256x256" / "apps" / "leakguard.png"
    icon.parent.mkdir(parents=True, exist_ok=True)
    theme.icon_pixmap(256).save(str(icon), "PNG")
    entry = share / "applications" / "leakguard.desktop"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(DESKTOP.format(exec=exe))
    return [entry, icon]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="leakguard-app", description="LeakGuard desktop app")
    ap.add_argument("--practice", action="store_true", help="practice mode: made-up person, lab services only")
    ap.add_argument("--add-to-menu", action="store_true", help="add LeakGuard to your application menu and exit")
    args = ap.parse_args(argv)
    if args.add_to_menu:
        for p in add_to_menu():
            print(f"wrote {p}")
        return 0

    from PySide6.QtWidgets import QApplication
    from .. import service
    from . import theme
    from .main_window import MainWindow
    from .wizard.about_you import AboutYouDialog

    app = QApplication(sys.argv[:1])
    app.setApplicationName("LeakGuard")
    app.setDesktopFileName("leakguard")
    app.setStyle("Fusion")
    app.setWindowIcon(theme.app_icon())
    app.setStyleSheet(theme.stylesheet())

    profile = "lab" if args.practice else "internet"
    first_run = profile == "internet" and not service.has_identity("internet")
    if first_run and not AboutYouDialog(first_run=True).exec():
        return 0                                    # closed without saving: nothing to check yet
    win = MainWindow(profile)
    win.show()
    if first_run:
        win.start_check("quick", first_run=True)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
