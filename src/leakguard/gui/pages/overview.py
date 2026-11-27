"""Overview: how much is cleaned up, what needs you, what we're waiting for, and recent changes."""

from __future__ import annotations

from PySide6.QtCharts import QChart, QChartView, QDateTimeAxis, QLineSeries, QValueAxis
from PySide6.QtCore import QDateTime, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from ... import service, wording
from ...wording import OVERVIEW as T
from .. import theme
from ..actions import button
from ..widgets.cards import Card, Ring, label


class OverviewPage(QScrollArea):
    navigate = Signal(str)                      # a page name from wording.NAV
    check = Signal(str)                         # start a check: "quick" or "full"

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        self.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.setSpacing(16)

        hero = QFrame()
        hero.setObjectName("card")
        h = QHBoxLayout(hero)
        h.setContentsMargins(20, 16, 20, 16)
        h.setSpacing(24)
        self.ring = Ring()
        h.addWidget(self.ring)
        words = QVBoxLayout()
        self.headline = label("", "hero")
        self.needs = label("", "lead")
        self.waiting_line = label("", "muted")
        for w in (self.headline, self.needs, self.waiting_line):
            words.addWidget(w)
        words.addStretch(1)
        h.addLayout(words, 1)
        checks = QVBoxLayout()                          # the everyday action, right where the status is
        self.check_now = button(T["check_now"], True)
        self.check_full = button(T["check_full"])
        self.check_now.clicked.connect(lambda: self.check.emit("quick"))
        self.check_full.clicked.connect(lambda: self.check.emit("full"))
        self.last_check = label("", "muted", wrap=False)
        checks.addStretch(1)
        for w in (self.check_now, self.check_full, self.last_check):
            checks.addWidget(w)
        checks.addStretch(1)
        h.addLayout(checks)
        lay.addWidget(hero)

        self.better = QFrame()
        self.better.setObjectName("card")
        bl = QHBoxLayout(self.better)
        bl.setContentsMargins(16, 10, 16, 10)
        bl.addWidget(label(wording.SETTINGS["better"], "title", wrap=False))
        self.better_line = label("", "muted")             # it says where: the Settings menu
        bl.addWidget(self.better_line, 1)
        lay.addWidget(self.better)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.card_needs = Card(T["card_needs"], T["details"])
        self.card_waiting = Card(T["card_waiting"], T["details"])
        self.card_open = Card(T["card_open"], T["details"])
        self.card_mail = Card(T["card_mail"], T["details"])
        for col, (card, page) in enumerate(((self.card_needs, "todo"), (self.card_waiting, "cleanup"),
                                            (self.card_open, "found"), (self.card_mail, "mail"))):
            card.clicked.connect(lambda p=page: self.navigate.emit(p))
            grid.addWidget(card, 0, col)
        lay.addLayout(grid)

        lower = QHBoxLayout()
        lower.setSpacing(12)
        trend = QFrame()
        trend.setObjectName("card")
        tl = QVBoxLayout(trend)
        tl.addWidget(label(T["trend"], "title"))
        self.chart = QChart()
        self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.chart.setBackgroundVisible(False)
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.chart_view.setMinimumHeight(230)
        self.chart_empty = label(T["trend_wait"], "muted")
        tl.addWidget(self.chart_view, 1)
        tl.addWidget(self.chart_empty)
        tl.addStretch(0)
        tl.setAlignment(Qt.AlignmentFlag.AlignTop)
        lower.addWidget(trend, 3)

        recent = QFrame()
        recent.setObjectName("card")
        self.recent_lay = QVBoxLayout(recent)
        self.recent_lay.addWidget(label(T["recent"], "title"))
        self.recent_items = QVBoxLayout()
        self.recent_lay.addLayout(self.recent_items)
        self.recent_lay.addStretch(1)
        lower.addWidget(recent, 2)
        lay.addLayout(lower, 1)

    def set_running(self, running: bool) -> None:
        self.check_now.setEnabled(not running)
        self.check_full.setEnabled(not running)
        self.check_now.setText(T["checking"] if running else T["check_now"])

    # ---- data -----------------------------------------------------------------------------------
    def refresh(self, ov: service.Overview) -> None:
        self.ring.set(ov.pct)
        self.headline.setText(T["cleaned"].format(gone=ov.gone, total=ov.total) if ov.total else T["cleaned_none"])
        self.needs.setText(T["needs_you"].format(count=ov.needs_you, things=wording.plural(ov.needs_you, "thing"))
                           if ov.needs_you else T["needs_you_none"])
        self.waiting_line.setText(
            T["waiting"].format(count=ov.waiting, sites=wording.plural(ov.waiting, "site"),
                                date=wording.day(ov.next_follow_up) or "soon")
            if ov.waiting else T["waiting_none"])

        self.card_needs.set(str(ov.needs_you), T["needs_you_none"] if not ov.needs_you else "",
                            theme.WARN if ov.needs_you else theme.GOOD)
        self.card_waiting.set(str(ov.waiting), wording.day(ov.next_follow_up))
        sev = {k: ov.open_by_severity.get(k, 0) for k in ("high", "medium", "low")}
        total_open = sum(sev.values())
        self.card_open.set(str(total_open), T["open_line"].format(**sev),
                           theme.BAD if sev["high"] else (theme.GOOD if not total_open else None))
        if ov.mail_connected:
            self.card_mail.set(str(ov.mail_blocked_7d))
        else:
            self.card_mail.set("-", T["mail_none"])
        self.last_check.setText(T["last_check"].format(when=wording.ago(ov.last_check)) if ov.last_check
                                else T["never"])
        self.better.setVisible(bool(ov.keys_missing or ov.tools_missing))
        S = wording.SETTINGS
        parts = ([S["better_keys"].format(count=ov.keys_missing, services=wording.plural(ov.keys_missing, "service"))]
                 if ov.keys_missing else []) + \
                ([S["better_tools"].format(count=ov.tools_missing, checks=wording.plural(ov.tools_missing, "check"))]
                 if ov.tools_missing else [])
        what = f" {S['and']} ".join(parts)
        self.better_line.setText(S["better_line"].format(what=what[:1].upper() + what[1:]) if parts else "")
        self._chart(ov.trend)
        self._recent(ov.recent)

    def _chart(self, trend: list[dict]) -> None:
        self.chart.removeAllSeries()
        for ax in self.chart.axes():
            self.chart.removeAxis(ax)
        points = [t for t in trend if t.get("open") is not None]
        enough = len({t["ts"] for t in points}) >= 2               # a line needs two different moments
        self.chart_view.setVisible(enough)
        self.chart_empty.setVisible(not enough)
        if not enough:
            return
        x = QDateTimeAxis()
        first = QDateTime.fromString(points[0]["ts"], "yyyy-MM-dd HH:mm")
        last = QDateTime.fromString(points[-1]["ts"], "yyyy-MM-dd HH:mm")
        days = first.daysTo(last)
        x.setFormat("HH:mm" if days < 1 else "d MMM")          # all within a day: the time is what differs
        x.setTickCount(max(2, min(5, len(points) if days < 1 else days + 1)))
        y = QValueAxis()
        y.setLabelFormat("%d")
        self.chart.addAxis(x, Qt.AlignmentFlag.AlignBottom)
        self.chart.addAxis(y, Qt.AlignmentFlag.AlignLeft)
        top = 0
        for key, name, color in (("open", T["trend_open"], theme.BAD), ("gone", T["trend_gone"], theme.GOOD)):
            s = QLineSeries()
            s.setName(name)
            s.setPen(QPen(QColor(color), 2.5))
            for t in points:
                when = QDateTime.fromString(t["ts"], "yyyy-MM-dd HH:mm")
                s.append(when.toMSecsSinceEpoch(), t.get(key) or 0)
                top = max(top, t.get(key) or 0)
            self.chart.addSeries(s)
            s.attachAxis(x)
            s.attachAxis(y)
        y.setRange(0, max(5, top + 1))
        y.applyNiceNumbers()
        fg = self.palette().color(self.foregroundRole())
        grid = self.palette().color(self.palette().ColorRole.Mid)
        for ax in (x, y):
            ax.setLabelsColor(fg)
            ax.setGridLineColor(grid)
            ax.setLinePenColor(grid)
        self.chart.legend().setLabelColor(fg)

    def _recent(self, events) -> None:
        while self.recent_items.count():
            item = self.recent_items.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not events:
            self.recent_items.addWidget(label(T["recent_none"], "muted"))
        for ts, kind, row in events:
            text = wording.finding_sentence(row) if kind == "found" else wording.action_title(row)
            line = QLabel(f"<span style='color:gray'>{wording.ago(ts)}</span>&nbsp;&nbsp;"
                          f"{_html(wording.EVENT[kind].format(text=text))}")
            line.setWordWrap(True)
            line.setTextFormat(Qt.TextFormat.RichText)
            self.recent_items.addWidget(line)


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
