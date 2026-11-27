"""Add a tool: one screen to describe a command-line tool, test it on your own email, and save it.
The definition is the same JSON as docs/ADD_A_TOOL.md (saved in ~/.config/leakguard/tools.d/)."""

from __future__ import annotations

import re
import shlex

from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLayout,
                               QLineEdit, QPlainTextEdit, QScrollArea, QStackedWidget, QVBoxLayout, QWidget)

from .. import custom_tools, service, wording
from ..wording import CUSTOM as T
from .actions import button
from .widgets.cards import label


class Rows:
    """Label above field, help text under it: reads top to bottom and never squeezes wrapped text."""

    def __init__(self, lay: QVBoxLayout):
        self.lay = lay

    def addRow(self, title: str, field) -> None:
        if title:
            self.lay.addSpacing(4)
            self.lay.addWidget(label(title, "title", wrap=False))
        if isinstance(field, QLayout):
            self.lay.addLayout(field)
        else:
            self.lay.addWidget(field)


def join_command(words: list[str]) -> str:
    """Like shlex.join, but {value} and other plain words stay unquoted (easier to read and edit)."""
    return " ".join(shlex.quote(w) if re.search(r"[\s'\"\\$`]", w) or not w else w for w in words)


class AddToolDialog(QDialog):
    def __init__(self, win, existing: dict | None = None):
        super().__init__(win)
        self.win = win
        self.existing = existing or {}
        self.setWindowTitle(T["title"])
        self.setFixedWidth(720)                # wrapped help text gets its real height at a fixed width
        self.resize(720, 800)
        outer = QVBoxLayout(self)
        body = QWidget()
        lay = QVBoxLayout(body)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        lay.addWidget(label(T["title"], "big"))
        lay.addWidget(label(T["intro"], "muted"))
        e, o = self.existing, self.existing.get("output", {})
        form = Rows(lay)
        self.name = QLineEdit(e.get("name", ""))
        self.about = QLineEdit(e.get("about", ""))
        checks = QHBoxLayout()
        self.check_email = QCheckBox(T["check_email"])
        self.check_user = QCheckBox(T["check_username"])
        self.check_email.setChecked("email" in e.get("checks", ["email"]))
        self.check_user.setChecked("username" in e.get("checks", []))
        checks.addWidget(self.check_email)
        checks.addWidget(self.check_user)
        checks.addStretch(1)
        self.command = QLineEdit(join_command(e["command"]) if e.get("command") else "")
        self.command.setPlaceholderText("mytool --json {value}")
        form.addRow(T["name"], self.name)
        form.addRow(T["about"], self.about)
        form.addRow(T["checks"], checks)
        form.addRow(T["command"], self.command)
        form.addRow("", label(T["command_help"], "muted"))

        self.format = QComboBox()
        for key in custom_tools.FORMATS:
            self.format.addItem(T[f"format_{key}"], key)
        self.format.setCurrentIndex(max(self.format.findData(o.get("format", "json")), 0))
        form.addRow(T["format"], self.format)
        self.pages = QStackedWidget()
        jpage = QWidget()
        jv = QVBoxLayout(jpage)
        jv.setContentsMargins(0, 0, 0, 0)
        jl = Rows(jv)
        self.items = QLineEdit(o.get("items", ""))
        self.items.setPlaceholderText("results")
        match = o.get("match") or {}
        mrow = QHBoxLayout()
        self.match_field = QLineEdit(match.get("field", ""))
        self.match_field.setPlaceholderText("exists")
        self.match_equals = QLineEdit("" if "equals" not in match else
                                      ("true" if match["equals"] is True else "false" if match["equals"] is False
                                       else str(match["equals"])))
        self.match_equals.setPlaceholderText("true")
        mrow.addWidget(self.match_field, 1)
        mrow.addWidget(label(T["equals"], wrap=False))
        mrow.addWidget(self.match_equals, 1)
        jl.addRow(T["items"], self.items)
        jl.addRow("", label(T["items_help"], "muted"))
        jl.addRow(T["match"], mrow)
        lpage = QWidget()
        lv = QVBoxLayout(lpage)
        lv.setContentsMargins(0, 0, 0, 0)
        ll = Rows(lv)
        self.pattern = QLineEdit(o.get("pattern", ""))
        ll.addRow(T["pattern"], self.pattern)
        ll.addRow("", label(T["pattern_help"], "muted"))
        self.pages.addWidget(jpage)
        self.pages.addWidget(lpage)
        form.addRow("", self.pages)
        self.format.currentIndexChanged.connect(
            lambda _: self.pages.setCurrentIndex(1 if self.format.currentData() == "lines" else 0))
        self.pages.setCurrentIndex(1 if self.format.currentData() == "lines" else 0)

        self.title_t = QLineEdit(o.get("title", "Account on {site}"))
        self.url_t = QLineEdit(o.get("url", "{url}"))
        self.site_t = QLineEdit(o.get("site", "{site}"))
        form.addRow(T["result_title"], self.title_t)
        form.addRow(T["result_link"], self.url_t)
        form.addRow(T["result_site"], self.site_t)
        form.addRow("", label(T["fields_help"], "muted"))
        self.kind = QComboBox()
        for c in custom_tools.CATEGORIES:
            self.kind.addItem(wording.CATEGORY.get(c, c), c)
        self.kind.setCurrentIndex(max(self.kind.findData(e.get("category", "account")), 0))
        self.severity = QComboBox()
        for s in custom_tools.SEVERITIES:
            self.severity.addItem(wording.SEVERITY[s], s)
        self.severity.setCurrentIndex(max(self.severity.findData(e.get("severity", "low")), 0))
        form.addRow(T["kind"], self.kind)
        form.addRow(T["seriousness"], self.severity)

        self.error = label("", "error")
        self.error.hide()
        lay.addWidget(self.error)
        test_row = QHBoxLayout()
        self.test_btn = button(T["test"])
        self.test_btn.clicked.connect(self._test)
        test_row.addWidget(self.test_btn)
        test_row.addStretch(1)
        lay.addLayout(test_row)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setFixedHeight(150)
        self.result.hide()
        lay.addWidget(self.result)
        lay.addStretch(1)

        bb = QDialogButtonBox()
        self.save_btn = button(T["save"], True)
        self.save_btn.clicked.connect(self._save)
        bb.addButton(self.save_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        bb.addButton(T["cancel"], QDialogButtonBox.ButtonRole.RejectRole)
        bb.rejected.connect(self.reject)
        outer.addWidget(bb)

    # ---- the definition --------------------------------------------------------------------------
    def definition(self) -> dict:
        try:
            command = shlex.split(self.command.text())
        except ValueError:
            command = []
        fmt = self.format.currentData()
        output = {"format": fmt, "title": self.title_t.text().strip(), "url": self.url_t.text().strip(),
                  "site": self.site_t.text().strip()}
        if fmt == "lines":
            output["pattern"] = self.pattern.text()
        else:
            if self.items.text().strip():
                output["items"] = self.items.text().strip()
            if self.match_field.text().strip():
                raw = self.match_equals.text().strip()
                value = {"true": True, "false": False}.get(raw.lower(), raw)
                output["match"] = {"field": self.match_field.text().strip(),
                                   **({"equals": value} if raw else {})}
        m = {"id": self.existing.get("id") or custom_tools.slug(self.name.text()), "name": self.name.text().strip(),
             "about": self.about.text().strip(),
             "checks": [k for k, box in (("email", self.check_email), ("username", self.check_user))
                        if box.isChecked()],
             "command": command, "output": output, "category": self.kind.currentData(),
             "severity": self.severity.currentData(), "timeout": int(self.existing.get("timeout", 300)),
             "enabled": self.existing.get("enabled", True)}
        if self.existing.get("_origin"):
            m["_origin"] = self.existing["_origin"]
        return m

    def _show_problems(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))

    def _test(self) -> None:
        m = self.definition()
        taken = service.builtin_ids()
        found = custom_tools.problems(m, taken)
        self._show_problems("\n".join(found))
        if found:
            return
        self.test_btn.setEnabled(False)
        self.result.show()
        self.result.setPlainText(T["testing"].format(value="..."))
        profile = self.win.profile

        def run(_progress, _cancel):
            s, _ = service.open_profile(profile)
            return service.try_tool(s, m)

        def done(t):
            self.test_btn.setEnabled(True)
            if t.ok:
                head = (T["test_found"].format(count=len(t.found), value=t.value) if t.found
                        else T["test_nothing"].format(value=t.value))
                self.result.setPlainText("\n".join([head, *[f"  - {x}" for x in t.found[:20]], "",
                                                    t.detail[:1500]]))
            elif t.problem == "not_installed":
                self.result.setPlainText(T["not_installed"].format(program=m["command"][0]))
            elif t.problem == "practice":
                self.result.setPlainText(T["test_practice"])
            else:
                self.result.setPlainText(T["test_failed"] + "\n\n" + t.detail[:2000])
        self.win.run_job(run, done)

    def _save(self) -> None:
        m = self.definition()
        try:
            service.save_tool(m)
        except ValueError as e:
            self._show_problems(str(e))
            return
        self.win.toast.show_message(T["saved"].format(name=m["name"]))
        self.accept()
