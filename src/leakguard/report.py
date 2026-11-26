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
    open_ = [f for f in findings if f["status"] != "gone"]
    last = store.last_scan_id()
    return {
        "profile": settings.profile,
        "keyword": settings.keyword,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "identities": [vars(i) for i in store.identities()],
        "summary": {
            "open": len(open_),
            "new": sum(f["status"] == "new" for f in findings),
            "gone": sum(f["status"] == "gone" for f in findings),
            "by_category": dict(Counter(f["category"] for f in open_)),
            "by_severity": dict(Counter(f["severity"] for f in open_)),
        },
        "findings": sorted(findings, key=lambda f: (f["status"] == "gone", SEV_ORDER[f["severity"]], f["category"])),
        "last_scan_runs": [dict(r) for r in store.runs(last)] if last else [],
    }


def to_markdown(rep: dict) -> str:
    s = rep["summary"]
    lines = [
        f"# LeakGuard report: `{rep['keyword']}` ({rep['profile']} profile)",
        f"Generated {rep['generated']}",
        "",
        f"**Open exposures:** {s['open']} · **new (first seen this round):** {s['new']} · **gone (removed):** {s['gone']}",
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
    lines += ["", "## Findings",
              "| Status | Sev | Category | Identity | Source | Finding | Evidence |", "|---|---|---|---|---|---|---|"]
    for f in rep["findings"]:
        title = f"[{_md_escape(f['title'])}]({f['url']})" if f["url"] else _md_escape(f["title"])
        lines.append(f"| {f['status']} | {f['severity']} | {f['category']} | `{f['identity']}` | {f['source']} "
                     f"| {title} | {_md_escape(f['evidence'])[:160]} |")
    problems = [r for r in rep["last_scan_runs"] if not r["ok"]]
    if problems:
        lines += ["", "## Sources that did not run (last scan)", "| Source | Identity | Reason |", "|---|---|---|",
                  *[f"| {r['source']} | `{r['identity']}` | {_md_escape(r['error'])} |" for r in problems]]
    return "\n".join(lines) + "\n"


def write(settings: Settings, store: Store) -> tuple[Path, Path]:
    rep = build(settings, store)
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    md = REPORTS / f"{settings.profile}-{stamp}.md"
    js = REPORTS / f"{settings.profile}-{stamp}.json"
    md.write_text(to_markdown(rep))
    js.write_text(json.dumps(rep, indent=2, default=str))
    return md, js
