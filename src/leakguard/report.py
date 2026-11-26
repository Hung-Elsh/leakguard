"""Markdown + JSON report of the current exposure state."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from .config import Settings
from .paths import REPORTS
from .store import Store

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _md_escape(s: str) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def build(settings: Settings, store: Store) -> dict:
    findings = [dict(r) for r in store.findings()]
    open_ = [f for f in findings if f["status"] != "gone" and (f["disposition"] or "open") == "open"]
    last = store.last_scan_id()
    return {
        "profile": settings.profile,
        "keyword": settings.keyword,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "identities": [vars(i) for i in store.identities()],
        "summary": {
            "open": sum(f["severity"] != "info" for f in open_),
            "open_info": sum(f["severity"] == "info" for f in open_),
            "new": sum(f["status"] == "new" for f in findings),
            "gone": sum(f["status"] == "gone" and (f["disposition"] or "open") == "open" for f in findings),
            "protect": sum(f["disposition"] == "protect" and f["status"] != "gone" for f in findings),
            "accepted": sum(f["disposition"] == "accepted" for f in findings),
            "false_positive": sum(f["disposition"] == "false_positive" for f in findings),
            "by_category": dict(Counter(f["category"] for f in open_)),
            "by_severity": dict(Counter(f["severity"] for f in open_)),
        },
        "findings": sorted(findings, key=lambda f: (["open", "protect", "accepted", "false_positive"].index(
                                                        f["disposition"] or "open"), f["status"] == "gone",
                                                    SEV_ORDER[f["severity"]], f["category"])),
        "last_scan_runs": [dict(r) for r in store.runs(last)] if last else [],
        "actions": [dict(a) for a in store.actions()],
    }


def to_markdown(rep: dict) -> str:
    s = rep["summary"]
    lines = [
        f"# LeakGuard report: `{rep['keyword']}` ({rep['profile']} profile)",
        f"Generated {rep['generated']}",
        "",
        f"**Open exposures to clean up:** {s['open']} (+{s['open_info']} info-only, e.g. partial search matches)"
        f" · **new (first seen this round):** {s['new']} · **gone (removed):** {s['gone']}"
        f" · **to protect:** {s['protect']} · accepted: {s['accepted']} · false positives: {s['false_positive']}",
        "",
        "| Severity | Count |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(s["by_severity"].items(), key=lambda kv: SEV_ORDER[kv[0]])],
        "",
        "| Category | Count |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(s["by_category"].items())],
        "",
        "## Identities",
        "| ID | Value | Kind | Status | Origin |", "|---|---|---|---|---|",
        *[f"| {i['id']} | `{i['value']}` | {i['kind']} | {i['status']} | {_md_escape(i['origin'])} |"
          for i in rep["identities"]],
    ]
    pending = [i for i in rep["identities"] if i["status"] == "candidate"]
    if pending:
        lines += ["", f"**{len(pending)} candidate(s) wait for your decision:** "
                  "`leakguard claim <id>` if it is yours, `leakguard reject <id>` if not."]
    if rep.get("actions"):
        by_state = Counter(a["state"] for a in rep["actions"])
        lines += ["", "## Removal progress", "| State | Actions |", "|---|---|",
                  *[f"| {k} | {v} |" for k, v in sorted(by_state.items())],
                  "", "| # | State | Kind | Target | Contact |", "|---|---|---|---|---|",
                  *[f"| {a['id']} | {a['state']} | {a['kind']} | {_md_escape(a['target'])} | "
                    f"{_md_escape(a['contact'] or 'needed')}{'' if a['contact_verified'] or not a['contact'] else ' (unverified)'} |"
                    for a in rep["actions"]]]
    protect = [f for f in rep["findings"] if f["disposition"] == "protect" and f["status"] != "gone"]
    if protect:
        lines += ["", "## Accounts to protect (keep and secure: change password, enable 2-step verification)",
                  "| ID | Sev | Identity | Source | Finding | Note |", "|---|---|---|---|---|---|",
                  *[f"| `{f['id'][:8]}` | {f['severity']} | `{f['identity']}` | {f['source']} | {_md_escape(f['title'])} "
                    f"| {_md_escape(f['note'])} |" for f in protect]]
    lines += ["", "## Findings",
              "| ID | Status | Verdict | Sev | Category | Identity | Source | Finding | Evidence |",
              "|---|---|---|---|---|---|---|---|---|"]
    for f in rep["findings"]:
        title = f"[{_md_escape(f['title'])}]({f['url']})" if f["url"] else _md_escape(f["title"])
        verdict = (f["disposition"] or "open") + (f": {_md_escape(f['note'])}" if f["note"] else "")
        lines.append(f"| `{f['id'][:8]}` | {f['status']} | {verdict} | {f['severity']} | {f['category']} | `{f['identity']}` "
                     f"| {f['source']} | {title} | {_md_escape(f['evidence'])[:160]} |")
    problems = [r for r in rep["last_scan_runs"] if r["status"] != "ok"]
    if problems:
        lines += ["", "## Sources that did not run fully (last scan)",
                  "| Source | Identity | Status | HTTP | Error |", "|---|---|---|---|---|",
                  *[f"| {r['source']} | `{r['identity']}` | {r['status'] or 'error'} | {r['http_status'] or ''} "
                    f"| {_md_escape(r['error'])} |" for r in problems]]
    return "\n".join(lines) + "\n"


def write(settings: Settings, store: Store) -> tuple[Path, Path]:
    from .monitor import scorecard
    rep = build(settings, store)
    rep["scorecard"] = scorecard(store)
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    md = REPORTS / f"{settings.profile}-{stamp}.md"
    js = REPORTS / f"{settings.profile}-{stamp}.json"
    from .monitor import scorecard_markdown
    md.write_text(to_markdown(rep) + "\n" + "\n".join(scorecard_markdown(rep["scorecard"])) + "\n")
    js.write_text(json.dumps(rep, indent=2, default=str))
    return md, js
