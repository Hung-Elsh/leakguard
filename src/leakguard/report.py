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


# ---- final cleanup report (optionally masked for sharing) -----------------------------------------
import re as _re

KIND_LABEL = {"account_delete": "account deletion", "leak_removal": "leak-index removal", "broker_optout": "broker opt-out",
              "paste_report": "paste report", "protect_checklist": "protect checklist",
              "rotate_password": "password rotation", "hibp_optout": "HIBP opt-out", "manual": "manual step",
              "data_erasure": "data erasure"}


def _mask_value(v: str) -> str:
    """jane.doe42@example.com -> j********2@e*****e.com ; jane.doe42 -> j********2"""
    def part(x: str) -> str:
        return x if len(x) <= 2 else x[0] + "*" * (len(x) - 2) + x[-1]
    if "@" in v:
        local, _, dom = v.partition("@")
        name, _, tld = dom.rpartition(".")
        return f"{part(local)}@{part(name)}.{tld}" if name else f"{part(local)}@{part(dom)}"
    return part(v)


def masker(store: Store, settings: Settings):
    """A function that masks every private term (identities, keyword, owner name, Google IDs) in a text."""
    from .leaks import private_terms
    terms = {i.value for i in store.identities() if i.status != "rejected"} | {settings.keyword}
    terms |= private_terms() if not settings.is_lab else set()
    if (settings.owner or {}).get("full_name"):
        terms.add(settings.owner["full_name"])
    ordered = sorted({t for t in terms if len(t) >= 4}, key=len, reverse=True)
    patterns = [(_re.compile(_re.escape(t), _re.I), _mask_value(t.lower())) for t in ordered]

    def mask(text: str) -> str:
        text = str(text or "")
        for rx, rep in patterns:
            text = rx.sub(rep, text)
        return _re.sub(r"\b\d{15,}\b", lambda m: m.group(0)[:3] + "…", text)     # Google (Gaia) and similar IDs
    return mask, ordered


def final_markdown(settings: Settings, store: Store, share: bool) -> str:
    import json as _json
    from .monitor import scorecard, scorecard_markdown
    mask, _ = masker(store, settings) if share else (lambda t: str(t or ""), [])
    sc, actions, findings = scorecard(store), store.actions(), store.findings()
    counted = [f for f in findings if f["severity"] != "info" and (f["disposition"] or "open") in ("open", "protect")]
    lines = [f"# Cleanup report: `{mask(settings.keyword)}` ({settings.profile})",
             f"Period: {(sc['first_scan'] or '-')[:10]} to {datetime.now().date()}" + (" · identities masked for sharing" if share else ""),
             "", "## Summary"]
    lines += scorecard_markdown(sc)[1:]
    lines += ["", "## What was found", "| Category | High | Medium | Low | Verdicts |", "|---|---|---|---|---|"]
    by_cat: dict[str, Counter] = {}
    for f in counted:
        by_cat.setdefault(f["category"], Counter())[f["severity"]] += 1
        by_cat[f["category"]][f"v:{f['disposition'] or 'open'}"] += 1
    for cat, c in sorted(by_cat.items()):
        verdicts = ", ".join(f"{k[2:]} {v}" for k, v in sorted(c.items()) if k.startswith("v:"))
        lines.append(f"| {cat} | {c['high']} | {c['medium']} | {c['low']} | {verdicts} |")
    judged = Counter(f["disposition"] for f in findings if f["disposition"] in ("false_positive", "accepted"))
    if judged:
        lines += ["", f"Not counted: {judged.get('false_positive', 0)} false positives (e.g. sites that 'find' any "
                      f"username), {judged.get('accepted', 0)} accepted. Info-only search look-alikes are not counted either."]
    lines += ["", "## What was done", "| # | Target | Action | State | Requested | Last update | Outcome / note |",
              "|---|---|---|---|---|---|---|"]
    for a in actions:
        hist = _json.loads(a["history"] or "[]")
        req = next((h["ts"][:10] for h in hist if h["state"] in ("requested", "done")), "-")
        note = next((h["note"] for h in reversed(hist) if h["note"] not in ("plan", "draft written")), "")
        lines.append(f"| {a['id']} | {mask(a['target'])} | {KIND_LABEL.get(a['kind'], a['kind'])} | {a['state']} | {req} "
                     f"| {(a['updated'] or '')[:10]} | {_md_escape(mask(note))[:140]} |")
    waiting = [a for a in actions if a["state"] in ("requested", "acknowledged")]
    if waiting:
        lines += ["", "## Waiting on the sites", *[f"- #{a['id']} {mask(a['target'])}: follow-up {(a['next_check'] or '-')[:10]}"
                                                    for a in waiting]]
    lines += ["", "## How the numbers are kept honest",
              "- Only identities the owner claimed are scanned or cleaned; findings carry the owner's verdict.",
              "- A removal counts only when a re-scan of the sources that found it no longer sees it; one that comes "
              "back is reopened.",
              "- Breach records are permanent (never counted as removed); partial or failed source runs never mark "
              "anything gone; search results are re-rated with the current rules.",
              "- Leaked passwords and API keys never appear in reports, drafts or logs."]
    return "\n".join(lines) + "\n"


def write_final(settings: Settings, store: Store, share: bool) -> Path:
    text = final_markdown(settings, store, share)
    if share:
        _, terms = masker(store, settings)
        low = text.lower()
        left = [t for t in terms if t.lower() in low]
        if left:
            raise RuntimeError(f"refusing to write the shared report: {len(left)} private term(s) still present")
    REPORTS.mkdir(parents=True, exist_ok=True)
    kind = "final-shared" if share else "final"
    path = REPORTS / f"{settings.profile}-{kind}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(text)
    path.chmod(0o600)
    return path
