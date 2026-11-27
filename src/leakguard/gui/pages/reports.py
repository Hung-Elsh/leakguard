"""Reports: what was found, the clean-up timeline, mail, check health (the logged runs, in plain words with the
full detail one double-click away), the trend, and the final report to keep or share."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCharts import (QBarCategoryAxis, QBarSet, QBarSeries, QChart, QChartView, QDateTimeAxis,
                              QHorizontalStackedBarSeries, QLineSeries, QValueAxis)
from PySide6.QtCore import QDateTime, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout,
                               QHeaderView, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout,
                               QWidget)

from ... import service, wording
from ...wording import REPORTS as R
from .. import theme
from ..actions import button
from ..widgets.cards import label

SEV_ORDER = (("high", "Serious"), ("medium", "Medium"), ("low", "Minor"), ("gone", R["gone"]))
SEV_COLOR = {"high": theme.BAD, "medium": theme.WARN, "low": theme.ACCENT, "gone": theme.GOOD}


def _table(headers: list[str], rows: list[list[str]], stretch: int = 1) -> QTableWidget:
    t = QTableWidget(len(rows), len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().hide()
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setWordWrap(True)
    h = t.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    h.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            t.setItem(r, c, QTableWidgetItem(str(text)))
    return t


def _chart_view(chart: QChart, height: int = 300) -> QChartView:
    chart.setBackgroundVisible(False)
    chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
    v = QChartView(chart)
    v.setRenderHint(QPainter.RenderHint.Antialiasing)
    v.setMinimumHeight(height)
    return v


def _style_axes(widget: QWidget, chart: QChart) -> None:
    fg = widget.palette().color(widget.foregroundRole())
    grid = widget.palette().color(widget.palette().ColorRole.Mid)
    for ax in chart.axes():
        ax.setLabelsColor(fg)
        ax.setGridLineColor(grid)
        ax.setLinePenColor(grid)
    chart.legend().setLabelColor(fg)


class ReportsPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.addWidget(label(wording.NAV["reports"], "hero"))
        lay.addWidget(label(R["intro"], "muted"))
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self.share = False

    def refresh(self, _overview=None) -> None:
        current = self.tabs.currentIndex()
        self.tabs.clear()
        st = self.win.store
        for build, title in ((self._found, "tab_found"), (self._cleanup, "tab_cleanup"), (self._mail, "tab_mail"),
                             (self._health, "tab_health"), (self._trend, "tab_trend"), (self._final, "tab_final")):
            page = QWidget()
            pl = QVBoxLayout(page)
            build(pl, st)
            self.tabs.addTab(page, R[title])
        self.tabs.setCurrentIndex(max(current, 0))

    # ---- what was found -------------------------------------------------------------------------
    def _found(self, lay, st) -> None:
        lay.addWidget(label(R["found_help"], "muted"))
        s = service.found_summary(st)
        kinds = sorted(s["by_kind"], key=lambda k: -sum(s["by_kind"][k].values()))
        if kinds:
            chart = QChart()
            series = QHorizontalStackedBarSeries()
            for key, name in SEV_ORDER:
                bar = QBarSet(name)
                bar.setColor(QColor(SEV_COLOR[key]))
                for k in kinds:
                    bar.append(s["by_kind"][k].get(key, 0))
                series.append(bar)
            chart.addSeries(series)
            y = QBarCategoryAxis()
            y.append([wording.CATEGORY.get(k, k) for k in kinds])
            x = QValueAxis()
            x.setLabelFormat("%d")
            chart.addAxis(y, Qt.AlignmentFlag.AlignLeft)
            chart.addAxis(x, Qt.AlignmentFlag.AlignBottom)
            series.attachAxis(y)
            series.attachAxis(x)
            x.applyNiceNumbers()
            _style_axes(self, chart)
            lay.addWidget(_chart_view(chart, 60 + 40 * len(kinds)))
        answers = ", ".join(f"{wording.VERDICT_LABEL.get(k, k)} {n}" for k, n in s["answers"].most_common())
        if answers:
            lay.addWidget(label(R["answers"].format(text=answers)))
        if s["unanswered"]:
            lay.addWidget(label(R["unanswered"].format(count=s["unanswered"]), "muted"))
        lay.addStretch(1)

    # ---- clean-up timeline ----------------------------------------------------------------------
    def _cleanup(self, lay, st) -> None:
        lay.addWidget(label(R["cleanup_help"], "muted"))
        states = [a["state"] for a in st.actions()]
        lay.addWidget(label(R["cleanup_counts"].format(
            out=sum(s in ("requested", "acknowledged", "removed") for s in states),
            gone=states.count("verified"), done=states.count("done"), skipped=states.count("skipped")), "lead"))
        rows = [[wording.day(ts), wording.action_title(a), wording.ACTION_STATE.get(h["state"], h["state"]),
                 h["note"]] for ts, a, h in service.cleanup_timeline(st)]
        lay.addWidget(_table([R["col_when"], R["col_step"], R["col_what"], R["col_note"]], rows, stretch=3), 1)

    # ---- mail -------------------------------------------------------------------------------------
    def _mail(self, lay, st) -> None:
        lay.addWidget(label(R["mail_help"], "muted"))
        m = service.mail_summary(st)
        if not m["total"]:
            lay.addWidget(label(R["mail_none"], "lead"))
            lay.addStretch(1)
            return
        chart = QChart()
        bar = QBarSet(R["col_count"])
        bar.setColor(QColor(theme.ACCENT))
        for _, n in m["weeks"]:
            bar.append(n)
        series = QBarSeries()
        series.append(bar)
        chart.addSeries(series)
        x = QBarCategoryAxis()
        x.append([f"{d.day} {d.strftime('%b')}" for d, _ in m["weeks"]])
        y = QValueAxis()
        y.setLabelFormat("%d")
        chart.addAxis(x, Qt.AlignmentFlag.AlignBottom)
        chart.addAxis(y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(x)
        series.attachAxis(y)
        y.applyNiceNumbers()
        chart.legend().hide()
        _style_axes(self, chart)
        lay.addWidget(_chart_view(chart, 260))
        rows = [[wording.MAIL_RULE.get(rule, rule), n] for rule, n in m["by_rule"].most_common()]
        lay.addWidget(_table([R["col_reason"], R["col_count"]], rows, stretch=0), 1)

    # ---- check health -----------------------------------------------------------------------------
    def _health(self, lay, st) -> None:
        lay.addWidget(label(R["health_help"], "muted"))
        health = service.check_health(st)
        if not health:
            lay.addWidget(label(R["health_none"], "lead"))
            lay.addStretch(1)
            return
        rows = []
        for h in health:
            w = h.worst
            src = wording.SOURCE.get(h.source, h.source)
            rows.append([f"{src[:1].upper()}{src[1:]} ({h.source})", wording.ago(h.when),
                         wording.RUN_STATUS.get(h.status, h.status),
                         wording.problem(w["status"], w["error"] or "", w["error_type"] or "", w["http_status"])
                         or wording.RUN_STATUS["ok"] + "."])
        t = _table([R["col_service"], R["col_last"], R["col_result"], R["col_happened"]], rows, stretch=3)
        colors = {"ok": theme.GOOD, "partial": theme.WARN, "error": theme.BAD, "scope_blocked": theme.BAD}
        for r, h in enumerate(health):
            if h.status in colors:
                t.item(r, 2).setForeground(QColor(colors[h.status]))
        t.doubleClicked.connect(lambda idx: HealthDialog(self, health[idx.row()]).exec())
        lay.addWidget(t, 1)

    # ---- trend ------------------------------------------------------------------------------------
    def _trend(self, lay, st) -> None:
        lay.addWidget(label(R["trend_help"], "muted"))
        snaps = [s for s in st.snapshots() if s.get("kind") == "monitor" and not s.get("invalid")]
        if len({s["ts"][:16] for s in snaps}) < 2:           # a line needs two different moments
            lay.addWidget(label(wording.OVERVIEW["trend_wait"], "lead"))
            lay.addStretch(1)
            return
        chart = QChart()
        x = QDateTimeAxis()
        x.setFormat("d MMM")
        y = QValueAxis()
        y.setLabelFormat("%d")
        chart.addAxis(x, Qt.AlignmentFlag.AlignBottom)
        chart.addAxis(y, Qt.AlignmentFlag.AlignLeft)
        top = 0
        for name, color, get in ((wording.OVERVIEW["trend_open"], theme.WARN, lambda s: s.get("open") or 0),
                                 (R["trend_serious"], theme.BAD, lambda s: (s.get("open_by_severity") or {}).get("high", 0)),
                                 (wording.OVERVIEW["trend_gone"], theme.GOOD, lambda s: s.get("gone") or 0)):
            line = QLineSeries()
            line.setName(name)
            line.setPen(QPen(QColor(color), 2.5))
            for s in snaps:
                when = QDateTime.fromString(s["ts"][:19], "yyyy-MM-dd'T'HH:mm:ss")
                line.append(when.toMSecsSinceEpoch(), get(s))
                top = max(top, get(s))
            chart.addSeries(line)
            line.attachAxis(x)
            line.attachAxis(y)
        x.setRange(QDateTime.fromString(snaps[0]["ts"][:19], "yyyy-MM-dd'T'HH:mm:ss"),
                   QDateTime.fromString(snaps[-1]["ts"][:19], "yyyy-MM-dd'T'HH:mm:ss"))
        y.setRange(0, max(5, top + 1))
        y.applyNiceNumbers()
        _style_axes(self, chart)
        lay.addWidget(_chart_view(chart, 380), 1)

    # ---- final report -----------------------------------------------------------------------------
    def _final(self, lay, st) -> None:
        lay.addWidget(label(R["final_help"], "muted"))
        row = QHBoxLayout()
        share = QCheckBox(R["share"])
        share.setChecked(self.share)
        save = button(R["save"], True)
        row.addWidget(share)
        row.addStretch(1)
        row.addWidget(save)
        lay.addLayout(row)
        view = QTextBrowser()
        view.setOpenExternalLinks(False)
        lay.addWidget(view, 1)

        def show():
            self.share = share.isChecked()
            view.setMarkdown(service.final_report(self.win.settings, self.win.store, self.share))
        share.toggled.connect(lambda _: show())
        save.clicked.connect(self._save)
        show()

    def _save(self) -> None:
        name = f"leakguard-report{'-shared' if self.share else ''}.md"
        f, _ = QFileDialog.getSaveFileName(self, R["save"], str(Path.home() / name), "Markdown (*.md)")
        if not f:
            return
        try:
            path = service.save_report(self.win.settings, self.win.store, self.share, Path(f))
        except RuntimeError as e:                         # a private term was left in the shareable copy
            self.win.show_details(R["refused"], str(e))
            return
        self.win.toast.show_message(R["saved"].format(path=path))


class HealthDialog(QDialog):
    """The full logged detail of one service's last run (secrets were removed before logging)."""

    def __init__(self, parent, h: service.HealthRow):
        super().__init__(parent)
        name = wording.SOURCE.get(h.source, h.source)
        self.setWindowTitle(R["health_detail"].format(service=name))
        self.resize(820, 460)
        lay = QVBoxLayout(self)
        lay.addWidget(label(f"{name[:1].upper()}{name[1:]} ({h.source}) · {wording.day(h.when)}", "title"))
        rows = []
        for r in h.runs:
            detail = " · ".join(str(x) for x in (r["error"], f"HTTP {r['http_status']}" if r["http_status"] else "",
                                                 r["url"], (r["detail"] or "")[:1500]) if x)
            rows.append([r["identity"] or "-", wording.RUN_STATUS.get(r["status"], r["status"]), detail or "-"])
        lay.addWidget(_table([R["col_for"], R["col_result"], R["col_detail"]], rows, stretch=2), 1)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
