"""Monitoring: one run = full scan + due removal checks + diff since the previous run + snapshot + alert.

The scorecard (before/after) is computed from findings, actions, snapshots and the mail log, so it can be
shown by `leakguard report` at any time, and the snapshots give the trend over runs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from collections import Counter
from dataclasses import dataclass, field
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import engine
from .config import Settings
from .paths import DATA, REPORTS, ROOT
from .scope import ScopeGuard
from .store import Store, now

SLOW_TOOLS = ("maigret", "spiderfoot", "sherlock", "blackbird")       # skipped by --quick
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
REMOVAL_DONE = ("removed", "verified", "done")


@dataclass
class MonitorResult:
    started: str
    new: list[dict] = field(default_factory=list)            # new or reappeared findings
    gone: list[dict] = field(default_factory=list)           # findings no longer seen
    candidates: list[str] = field(default_factory=list)
    action_changes: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)          # removal re-check results
    problems: list[str] = field(default_factory=list)        # sources that failed (e.g. GHunt login expired)
    reopened: list[str] = field(default_factory=list)        # removals undone: the data came back
    rerated: int = 0                                         # old search results re-rated by today's rules
    snapshot: dict = field(default_factory=dict)
    report: Path | None = None
    alerted: list[str] = field(default_factory=list)
    cancelled: bool = False                                  # stopped by the owner part way

    def grouped_new(self) -> list[dict]:
        """One entry per exposed page/record: the same leak is found once per identity and per search source."""
        groups: dict[str, dict] = {}
        for f in self.new:
            key = (f["url"] or f["title"]).lower()
            g = groups.setdefault(key, {"title": f["title"], "url": f["url"], "severity": f["severity"],
                                        "sources": set(), "identities": set(), "disposition": f["disposition"]})
            g["sources"].add(f["source"])
            g["identities"].add(f["identity"])
            if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[g["severity"]]:
                g["severity"] = f["severity"]
        return sorted(groups.values(), key=lambda g: -SEVERITY_RANK[g["severity"]])

    def alert_worthy(self, min_severity: str) -> list[dict]:
        return [g for g in self.grouped_new() if SEVERITY_RANK[g["severity"]] >= SEVERITY_RANK[min_severity]
                and (g["disposition"] or "open") == "open"]


# ---- numbers ------------------------------------------------------------------------------
def _counted(f) -> bool:
    """Exposures that count: not info-only, not judged false positive / accepted."""
    return f["severity"] != "info" and (f["disposition"] or "open") in ("open", "protect")


def snapshot(store: Store) -> dict:
    fs = store.findings()
    open_ = [f for f in fs if _counted(f) and f["status"] != "gone" and (f["disposition"] or "open") == "open"]
    return {
        "open": len(open_),
        "open_by_severity": dict(Counter(f["severity"] for f in open_)),
        "protect": sum(1 for f in fs if f["disposition"] == "protect" and f["status"] != "gone"),
        "gone": sum(1 for f in fs if _counted(f) and f["status"] == "gone" and (f["disposition"] or "open") == "open"),
        "actions": dict(Counter(a["state"] for a in store.actions())),
    }


def scorecard(store: Store) -> dict:
    fs, actions = store.findings(), store.actions()
    counted = [f for f in fs if _counted(f)]
    verified_ids = {fid for a in actions if a["state"] == "verified" for fid in json.loads(a["finding_ids"] or "[]")}
    scans = list(store.db.execute("SELECT min(started) AS first, max(started) AS last FROM scans"))[0]
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).replace(microsecond=0).isoformat()
    open_now = [f for f in counted if f["status"] != "gone" and (f["disposition"] or "open") == "open"]
    gone = [f for f in counted if f["status"] == "gone" and (f["disposition"] or "open") == "open"]
    removable = [f for f in counted if (f["disposition"] or "open") == "open"]
    accounts = [a for a in actions if a["kind"] == "account_delete"]
    return {
        "first_scan": scans["first"], "last_scan": scans["last"],
        "found": len(counted),
        "found_by_severity": dict(Counter(f["severity"] for f in counted)),
        "open": len(open_now),
        "open_by_severity": dict(Counter(f["severity"] for f in open_now)),
        "gone": len(gone),
        "verified_removed": len(verified_ids & {f["id"] for f in gone}),
        "cleaned_pct": round(100 * len(gone) / len(removable)) if removable else 0,
        "protect": sum(1 for f in fs if f["disposition"] == "protect"),
        "accounts": {"total": sum(a["state"] != "skipped" for a in accounts),
                     "deleted": sum(a["state"] in REMOVAL_DONE for a in accounts),
                     "in_progress": sum(a["state"] in ("requested", "acknowledged") for a in accounts),
                     "skipped": sum(a["state"] == "skipped" for a in accounts)},
        "actions": dict(Counter(a["state"] for a in actions)),
        "mail_blocked_total": sum(store.mail_stats().values()),
        "mail_blocked_7d": sum(store.mail_stats(week_ago).values()),
        "trend": [{"ts": s["ts"][:16].replace("T", " "), "open": s.get("open"), "gone": s.get("gone")}
                  for s in store.snapshots() if s.get("kind") == "monitor" and not s.get("invalid")],
    }


# ---- keep old findings rated by the current rules ---------------------------------------------
SEARCH_SOURCES = ("brave", "pse")


def rerate(settings: Settings, store: Store) -> int:
    """Re-apply today's match-level rating to stored search results (rules improve; a result that dropped out of
    the search before being re-rated must not keep an old, wrong severity). Returns how many changed."""
    from .net import Http
    from .plugins import Context
    from .plugins.apis import PASTE_HOSTS, SEVERITY_BY_MATCH
    from urllib.parse import urlsplit
    guard = ScopeGuard(settings)
    ctx = Context(settings, guard, Http(settings, guard), {i.value for i in store.identities("claimed")})
    changed = 0
    for f in store.findings():
        if f["source"] not in SEARCH_SOURCES or f["category"] not in ("web_page", "paste"):
            continue
        level = ctx.match_level(f"{f['title']} {f['evidence']} {f['url']}")
        sev = SEVERITY_BY_MATCH[level]
        if f["category"] == "paste" and level == "exact":
            sev = "medium"
        if sev != f["severity"]:
            store.db.execute("UPDATE findings SET severity=? WHERE id=?", (sev, f["id"]))
            changed += 1
    store.db.commit()
    return changed


# ---- the run ------------------------------------------------------------------------------
def run(settings: Settings, store: Store, sources: list[str] | None = None, quick: bool = False,
        workers: int = 4, progress: engine.Progress | None = None,
        cancel: threading.Event | None = None) -> MonitorResult:
    from .plugins import ALL_PLUGINS
    from .removal import tracker

    res = MonitorResult(started=now())
    res.rerated = rerate(settings, store)
    before = store.finding_states()
    before_actions = {a["id"]: a["state"] for a in store.actions()}
    only = sources or ([p.name for p in ALL_PLUGINS if p.name not in SLOW_TOOLS] if quick else None)

    summaries = [engine.expand(settings, store, only, workers, progress, cancel)]
    if not summaries[0].cancelled:
        summaries.append(engine.scan(settings, store, only, workers, progress, cancel))
    res.cancelled = any(s.cancelled for s in summaries)
    for s in summaries:
        res.candidates += s.new_candidates
        res.problems += [f"{src} / {ident}: {status}" for src, ident, status in s.runs if status.startswith("error")]

    # a removal that comes back is not a removal: reopen verified/removed actions whose findings are seen again
    for a in store.actions():
        if a["state"] in ("verified", "removed") and a["kind"] not in tracker.OWNER_CONFIRMED:
            back = [f for f in store.findings_by_ids(json.loads(a["finding_ids"] or "[]")) if f["status"] != "gone"]
            if back:
                store.set_action_state(a["id"], "requested", f"reopened: {len(back)} linked finding(s) seen again",
                                       next_check=tracker._due(a["method"]))
                res.reopened.append(f"#{a['id']} {a['target']}: {len(back)} linked finding(s) seen again")

    for a in store.actions():
        if res.cancelled:
            break                            # stopped by the owner: due re-checks wait for the next run
        if (a["next_check"] and a["next_check"] <= now() and a["kind"] not in tracker.OWNER_CONFIRMED
                and a["state"] in ("requested", "acknowledged", "removed", "done")):
            res.checks.append(f"#{a['id']} {a['target']}: {tracker.check(settings, store, a['id'])}")

    for f in store.findings():
        was = before.get(f["id"])
        if (was is None or was == "gone") and f["status"] != "gone":
            res.new.append(dict(f))
        elif was not in (None, "gone") and f["status"] == "gone":
            res.gone.append(dict(f))
    for a in store.actions():
        if before_actions.get(a["id"]) != a["state"]:
            res.action_changes.append(f"#{a['id']} {a['target']}: {before_actions.get(a['id'], 'new')} -> {a['state']}")

    res.snapshot = snapshot(store)
    store.add_snapshot("monitor", res.snapshot)
    res.report = write_report(settings, store, res)
    return res


def write_report(settings: Settings, store: Store, res: MonitorResult) -> Path:
    sc = scorecard(store)
    sev = lambda f: f"[{f['severity']}]"                                          # noqa: E731
    grouped = [g for g in res.grouped_new() if g["severity"] != "info"]
    info_new = len(res.grouped_new()) - len(grouped)
    gone = [f for f in res.gone if f["severity"] != "info"]
    lines = [f"# LeakGuard monitor ({settings.profile}), {res.started[:16].replace('T', ' ')} UTC", "",
             f"**New:** {len(grouped)} · **gone:** {len(gone)} · "
             f"**new candidates:** {len(res.candidates)} · **action changes:** {len(res.action_changes)} · "
             f"**open exposures:** {sc['open']}"
             + (f" · info-only changes (partial search matches): {info_new} new, {len(res.gone) - len(gone)} gone"
                if info_new or len(res.gone) > len(gone) else ""), ""]
    if grouped:
        lines += ["## New exposures", *[f"- {sev(g)} {g['title']}" + (f" ({g['url']})" if g["url"] else "")
                                        + f" · seen by {', '.join(sorted(g['sources']))}"
                                        + f" for {', '.join(sorted(g['identities']))}" for g in grouped], ""]
    if gone:
        lines += ["## No longer seen", *[f"- {f['source']}: {f['title']}" for f in gone], ""]
    if res.candidates:
        lines += ["## New candidates (claim or reject)", *[f"- {c}" for c in res.candidates], ""]
    if res.reopened:
        lines += ["## Came back after removal (actions reopened)", *[f"- {c}" for c in res.reopened], ""]
    if res.checks or res.action_changes:
        lines += ["## Removal", *[f"- {c}" for c in res.checks + res.action_changes], ""]
    if res.problems:
        lines += ["## Sources that failed (check logins / keys)", *[f"- {p}" for p in res.problems[:30]], ""]
    lines += scorecard_markdown(sc)
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / f"{settings.profile}-monitor-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.md"   # runs can be <1 s apart
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)
    return path


def scorecard_markdown(sc: dict) -> list[str]:
    acc = sc["accounts"]
    rows = [
        ("Exposures found (since first scan)", f"{sc['found']}  {_sev(sc['found_by_severity'])}"),
        ("Still open", f"{sc['open']}  {_sev(sc['open_by_severity'])}"),
        ("No longer seen by the sources", f"{sc['gone']} ({sc['cleaned_pct']}% of removable)"),
        ("... of which verified by a removal action", str(sc["verified_removed"])),
        ("Accounts to delete: deleted / in progress / total", f"{acc['deleted']} / {acc['in_progress']} / {acc['total']}"
                                                                 + (f" (+{acc['skipped']} skipped)" if acc.get("skipped") else "")),
        ("Protected (kept and secured)", str(sc["protect"])),
        ("Removal actions by state", ", ".join(f"{k} {v}" for k, v in sorted(sc["actions"].items())) or "-"),
        ("Mail blocked: last 7 days / total", f"{sc['mail_blocked_7d']} / {sc['mail_blocked_total']}"),
        ("First scan / last scan", f"{(sc['first_scan'] or '-')[:10]} / {(sc['last_scan'] or '-')[:10]}"),
    ]
    out = ["## Scorecard", "| | |", "|---|---|", *[f"| {k} | {v} |" for k, v in rows]]
    if len(sc["trend"]) > 1:
        out += ["", "| Monitor run | Open | Gone |", "|---|---|---|",
                *[f"| {t['ts']} | {t['open']} | {t['gone']} |" for t in sc["trend"][-12:]]]
    return out


def _sev(d: dict) -> str:
    return "(" + ", ".join(f"{k} {d[k]}" for k in ("high", "medium", "low") if d.get(k)) + ")" if d else ""


# ---- alerts --------------------------------------------------------------------------------
def summary_line(res: MonitorResult, min_severity: str) -> str | None:
    worth = res.alert_worthy(min_severity)
    verified = [c for c in res.action_changes if c.endswith("-> verified")]
    parts = []
    if worth:
        high = sum(f["severity"] == "high" for f in worth)
        parts.append(f"{len(worth)} new exposure(s)" + (f" ({high} high)" if high else ""))
    if res.candidates:
        parts.append(f"{len(res.candidates)} new candidate(s)")
    if verified:
        parts.append(f"{len(verified)} removal(s) verified")
    if res.reopened:
        parts.append(f"{len(res.reopened)} removal(s) came back")
    if res.problems:
        parts.append(f"{len(res.problems)} source error(s)")
    return ", ".join(parts) or None


def alert(settings: Settings, res: MonitorResult, desktop: bool, mail: bool, min_severity: str = "medium") -> None:
    line = summary_line(res, min_severity)
    if not line:
        return
    if desktop and shutil.which("notify-send"):
        r = subprocess.run(["notify-send", "--app-name=LeakGuard", "LeakGuard", f"{line}\n{res.report}"],
                           capture_output=True, timeout=15)
        res.alerted.append("desktop" if r.returncode == 0 else f"desktop failed ({r.stderr.decode()[:80]})")
    if mail:
        from .removal.drafts import sender_address
        from .removal.sender import send
        msg = EmailMessage()
        msg["From"] = msg["To"] = sender_address(settings)
        msg["Subject"] = f"LeakGuard: {line}"
        msg.set_content(res.report.read_text() if res.report else line)
        res.alerted.append(f"mail ({send(settings, ScopeGuard(settings), msg)})")


# ---- scheduling (files only; the owner enables them) ----------------------------------------
CALENDAR = {"daily": "*-*-* 09:00", "weekly": "Mon *-*-* 09:00", "monthly": "*-*-01 09:00"}


def schedule_files(profile: str, every: str, extra: str = "") -> dict[str, str]:
    if every not in CALENDAR:
        raise ValueError(f"--schedule must be one of {', '.join(CALENDAR)}")
    exe = ROOT / ".venv" / "bin" / "leakguard"
    service = f"""[Unit]
Description=LeakGuard monitor ({profile})

[Service]
Type=oneshot
WorkingDirectory={ROOT}
# notify-send needs the user's session bus
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus
ExecStart={exe} monitor -p {profile}{(' ' + extra) if extra else ''}
"""
    timer = f"""[Unit]
Description=Run the LeakGuard monitor {every}

[Timer]
OnCalendar={CALENDAR[every]}
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
"""
    return {"leakguard-monitor.service": service, "leakguard-monitor.timer": timer}


def write_schedule(profile: str, every: str, extra: str = "") -> Path:
    out = DATA / "systemd"
    out.mkdir(parents=True, exist_ok=True)
    for name, text in schedule_files(profile, every, extra).items():
        (out / name).write_text(text)
    return out
