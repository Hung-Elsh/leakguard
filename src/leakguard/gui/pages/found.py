"""Found: everything the checks found, searchable; double-click to see one and change the answer."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QIcon
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView,
                               QLineEdit, QStyle, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout,
                               QWidget)

from ... import service, wording
from ...models import scrub
from ...wording import FOUND, TODO
from .. import theme
from ..actions import button
from ..widgets.cards import label

COLUMNS = ("col_seriousness", "col_what", "col_where", "col_first", "col_status", "col_answer")
WIDTHS = (100, 420, 150, 90, 90, 120)       # starting widths; drag a column edge to change one
RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


class SortItem(QTableWidgetItem):
    """Sorts by a hidden key (seriousness rank, date) instead of the shown text."""

    def __init__(self, text: str, key):
        super().__init__(text)
        self.key = key

    def __lt__(self, other):
        return self.key < getattr(other, "key", other.text())


class FoundPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.addWidget(label(wording.NAV["found"], "hero"))
        lay.addWidget(label(FOUND["intro"], "muted"))
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(FOUND["search"])
        self.search.setAccessibleName(FOUND["search"])
        go = QToolButton()
        go.setIcon(QIcon.fromTheme("edit-find", self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView)))
        go.setToolTip(FOUND["search_go"])
        go.setAccessibleName(FOUND["search_go"])
        go.clicked.connect(lambda: self._filter(self.search.text()))
        self.search.returnPressed.connect(lambda: self._filter(self.search.text()))
        self.show = QComboBox()
        for key in ("show_all", "show_open", "show_gone"):          # all by default
            self.show.addItem(FOUND[key], key)
        bar.addWidget(self.search, 1)
        bar.addWidget(go)
        bar.addWidget(self.show)
        lay.addLayout(bar)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([FOUND[c] for c in COLUMNS])
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setWordWrap(True)                      # long text goes on to the next line
        self.table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.table.setSortingEnabled(True)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)   # drag an edge; the window keeps its size
        h.setStretchLastSection(False)
        h.setMinimumSectionSize(60)
        for c, w in enumerate(WIDTHS):
            self.table.setColumnWidth(c, w)
        h.sectionResized.connect(lambda *_: self.table.resizeRowsToContents())
        self.table.doubleClicked.connect(self._open)
        lay.addWidget(self.table, 1)
        self.empty = label(FOUND["empty"], "muted")
        lay.addWidget(self.empty)
        self.search.textChanged.connect(self._filter)
        self.show.currentIndexChanged.connect(lambda _: self.refresh())
        self.rows = []

    def refresh(self, _overview=None) -> None:
        which = self.show.currentData()
        rows = [f for f in self.win.store.findings() if f["severity"] != "info"]
        if which == "show_open":
            rows = [f for f in rows if f["status"] != "gone"]
        elif which == "show_gone":
            rows = [f for f in rows if f["status"] == "gone"]
        self.rows = {f["id"]: f for f in rows}
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, f in enumerate(rows):
            sev = SortItem(wording.SEVERITY[f["severity"]], RANK.get(f["severity"], 0))
            sev.setForeground(QColor(theme.SEVERITY_COLOR.get(f["severity"], theme.ACCENT)))
            sev.setData(Qt.ItemDataRole.UserRole, f["id"])
            answer = (FOUND["answer_none"] if f["reviewed"] is None
                      else wording.VERDICT_LABEL.get(f["disposition"] or "open", ""))
            cells = [sev, QTableWidgetItem(wording.finding_sentence(f)), QTableWidgetItem(wording.site_of(f)),
                     SortItem(wording.day(f["first_seen"]), f["first_seen"] or ""),
                     QTableWidgetItem(FOUND["status_gone"] if f["status"] == "gone" else FOUND["status_there"]),
                     QTableWidgetItem(answer)]
            for c, item in enumerate(cells):
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.SortOrder.DescendingOrder)
        self.table.resizeRowsToContents()
        self.empty.setVisible(not rows)
        self._filter(self.search.text())

    def _filter(self, text: str) -> None:
        text = text.lower().strip()
        for r in range(self.table.rowCount()):
            hay = " ".join(self.table.item(r, c).text().lower() for c in range(self.table.columnCount()))
            self.table.setRowHidden(r, bool(text) and text not in hay)

    def _open(self, index) -> None:
        fid = self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        FindingDialog(self.win, self.rows[fid]).exec()


class FindingDialog(QDialog):
    def __init__(self, win, f):
        super().__init__(win)
        self.win = win
        self.setWindowTitle(wording.CATEGORY.get(f["category"], f["category"]))
        self.setMinimumWidth(620)
        lay = QVBoxLayout(self)
        lay.addWidget(label(wording.finding_sentence(f), "lead"))
        lay.addWidget(label(f"{wording.SEVERITY[f['severity']]}: {wording.SEVERITY_HELP[f['severity']]}", "muted"))
        same = [r for r in win.store.findings() if (r["url"] and r["url"] == f["url"]) or r["id"] == f["id"]]
        sources = sorted({wording.SOURCE.get(r["source"], r["source"]) for r in same})
        lay.addWidget(label(f"{FOUND['sources']}: {wording.join_names(sources)}", "muted"))
        lay.addWidget(label(f"{FOUND['col_first']}: {wording.day(f['first_seen'])} · "
                            f"{FOUND['col_status']}: {FOUND['status_gone'] if f['status'] == 'gone' else FOUND['status_there']}",
                            "muted"))
        if f["evidence"]:
            lay.addWidget(label(scrub(f["evidence"])[:600], "muted"))     # leaked passwords stay masked
        if f["url"]:
            link = button(FOUND["open_link"])
            link.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(f["url"])))
            lay.addWidget(link, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addSpacing(8)
        lay.addWidget(label(FOUND["change"], "title"))
        row = QHBoxLayout()
        current = f["disposition"] or "open"
        for verdict in ("open", "protect", "false_positive", "accepted"):
            b = button(wording.VERDICT_BUTTON[verdict], verdict == current and f["reviewed"] is not None)
            b.clicked.connect(lambda _=False, v=verdict: self._answer(f, v))
            row.addWidget(b)
        lay.addLayout(row)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _answer(self, f, verdict: str) -> None:
        before = service.set_verdict(self.win.store, [f["id"]], verdict)

        def undo():
            service.undo_verdicts(self.win.store, before)
            self.win.changed()
        self.win.changed()
        self.win.toast.show_message(wording.VERDICT_DONE[verdict], TODO["undo"], undo)
        self.accept()
