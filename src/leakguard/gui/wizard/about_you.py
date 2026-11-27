"""The only required setup: one screen, one Save. Also used later to edit the same details."""

from __future__ import annotations

import re

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFrame, QLineEdit, QPlainTextEdit, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from ... import config, service
from ...wording import ABOUT_YOU as T
from ..widgets.cards import label


def _lines(text: str) -> list[str]:
    return [v.strip() for v in re.split(r"[\n,;]+", text) if v.strip()]


def problems(keyword: str, emails: list[str], usernames: list[str]) -> list[str]:
    """Plain-language problems with what was typed (empty: fine). Same rules as config.validate_identity."""
    out = []
    if not config.KEYWORD_RE.match(keyword.strip().lower()):
        out.append(T["bad_keyword"])
    if not emails:
        out.append(T["no_email"])
    out += [T["bad_email"].format(value=e) for e in emails if not config.EMAIL_RE.match(e.lower())]
    out += [T["bad_username"].format(value=u) for u in usernames
            if not config.USERNAME_RE.match(u.lower().lstrip("@"))]
    return out


class AboutYouDialog(QDialog):
    def __init__(self, parent=None, first_run: bool = True):
        super().__init__(parent)
        self.setWindowTitle(T["title"])
        self.setFixedWidth(600)          # a fixed width lets wrapped help text get its real height
        saved = service.identity_form("internet")
        outer = QVBoxLayout(self)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 8, 0)
        scroll = QScrollArea()           # small screens scroll instead of squeezing the form
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        lay.addWidget(label(T["intro"]))
        self.keyword = QLineEdit(saved["keyword"])
        self.keyword.setPlaceholderText("e.g. zorblat")
        self.emails = QPlainTextEdit("\n".join(saved["emails"]))
        self.emails.setPlaceholderText("you@example.com")
        self.emails.setFixedHeight(70)
        self.usernames = QPlainTextEdit("\n".join(saved["usernames"]))
        self.usernames.setFixedHeight(56)
        self.name = QLineEdit((saved.get("owner") or {}).get("full_name", ""))
        for title, widget, help_ in (("keyword", self.keyword, "keyword_help"), ("emails", self.emails, "emails_help"),
                                     ("usernames", self.usernames, "usernames_help"), ("name", self.name, "name_help")):
            widget.setAccessibleName(T[title])
            lay.addSpacing(6)
            lay.addWidget(label(T[title], "title", wrap=False))
            lay.addWidget(widget)
            lay.addWidget(label(T[help_], "muted"))
        self.error = label("", "error")
        self.error.hide()
        lay.addWidget(self.error)
        lay.addWidget(label(T["privacy"], "muted"))
        buttons = QDialogButtonBox()
        self.save = QPushButton((T["save_first"] if first_run else T["save"]).replace("&", "&&"))   # not a shortcut
        self.save.setObjectName("primary")
        self.save.setDefault(True)
        buttons.addButton(self.save, QDialogButtonBox.ButtonRole.AcceptRole)
        if not first_run:
            buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)
        self._body = body
        self._fit()

    def _fit(self) -> None:
        """As tall as the form needs, up to 90% of the screen (then it scrolls)."""
        need = self._body.layout().totalHeightForWidth(self.width() - 40) + 80
        screen = (self.screen() or QGuiApplication.primaryScreen()).availableGeometry().height()
        self.resize(self.width(), min(need, int(screen * 0.9)))

    def values(self) -> tuple[str, list[str], list[str], str]:
        return (self.keyword.text().strip(), _lines(self.emails.toPlainText()),
                _lines(self.usernames.toPlainText()), self.name.text().strip())

    def _save(self) -> None:
        keyword, emails, usernames, name = self.values()
        found = problems(keyword, emails, usernames)
        if not found:
            try:
                service.setup_identity(keyword, emails, usernames, name)
            except config.ConfigError as e:        # same rules, so this is unexpected: show it anyway
                found = [str(e)]
        if found:
            self.error.setText("\n".join(found))
            self.error.show()
            self._fit()
            return
        self.accept()
