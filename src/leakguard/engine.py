"""Run plugins over identities. `expand` works from the keyword; `scan` only from claimed identities."""

from __future__ import annotations

import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

import httpx

from .config import Settings
from .models import Candidate, Identity, PluginResult, redact
from .net import Http
from .plugins import ALL_PLUGINS, Context, Plugin, SkipSource
from .runner import ToolError
from .scope import ScopeError, ScopeGuard
from .store import Store, now


class ClaimError(Exception):
    pass


@dataclass
class RunSummary:
    scan_id: int
    new_findings: int = 0
    gone_findings: int = 0
    new_candidates: list[str] = field(default_factory=list)
    runs: list[tuple[str, str, str]] = field(default_factory=list)   # (source, identity, status)
    cancelled: bool = False          # stopped by the owner: runs that had not started were dropped


@dataclass
class Outcome:
    plugin: Plugin
    ident: Identity
    status: str                              # ok | skipped | error | scope_blocked
    result: PluginResult | None = None
    error: str = ""                          # one-line summary
    log: dict = field(default_factory=dict)  # extra columns for source_runs


def _api_message(resp: httpx.Response) -> str:
    """The service's own error message (Google/GitHub/HIBP style JSON), else the start of the body."""
    try:
        body = resp.json()
        err = body.get("error") if isinstance(body, dict) else None
        msg = (err.get("message") if isinstance(err, dict) else err) or body.get("message")
        if msg:
            return str(msg)
    except ValueError:
        pass
    return resp.text[:200].strip()


def _run_one(ctx: Context, p: Plugin, i: Identity, secrets: list[str]) -> Outcome:
    started, t0 = now(), time.monotonic()
    out = Outcome(p, i, "ok")
    try:
        p.check(ctx)
        out.result = p.run(ctx, i)
    except SkipSource as e:
        out.status, out.error, out.log = "skipped", str(e), {"error_type": "SkipSource"}
    except ScopeError as e:
        out.status, out.error, out.log = "scope_blocked", str(e), {"error_type": "ScopeError"}
    except httpx.HTTPStatusError as e:
        out.status = "error"
        out.error = f"HTTP {e.response.status_code}: {_api_message(e.response)}"
        out.log = {"error_type": "HTTPStatusError", "http_status": e.response.status_code,
                   "url": str(e.request.url), "detail": e.response.text[:4000]}
    except httpx.HTTPError as e:
        out.status, out.error, out.log = "error", f"{type(e).__name__}: {e}", {"error_type": type(e).__name__}
        try:
            out.log["url"] = str(e.request.url)
        except RuntimeError:     # no request attached
            pass
    except ToolError as e:
        out.status, out.error = "error", str(e)
        out.log = {"error_type": "ToolError", "detail": e.detail[-4000:]}
    except Exception as e:  # noqa: BLE001 - a broken source must not stop the scan; it is logged in full
        out.status, out.error = "error", f"{type(e).__name__}: {e}"
        out.log = {"error_type": type(e).__name__, "detail": traceback.format_exc()[-4000:]}
    if out.status == "ok" and out.result is not None and out.result.notes:
        out.log["detail"] = json.dumps(out.result.notes, ensure_ascii=False)
    if out.status == "ok" and out.result is not None and out.result.checked:
        r = out.result
        out.log.update(checked=r.checked, failed=r.failed)
        if r.failed:
            out.status = "partial"
            out.error = f"{r.failed}/{r.checked} checks got no answer: " + ", ".join(
                f"{why} ({n})" for why, n in sorted(r.failures.items(), key=lambda kv: -kv[1]))
            out.log["detail"] = json.dumps({"failures": r.failures, "checked": r.checked, **r.notes}, ensure_ascii=False)
    out.error = redact(out.error, secrets)
    out.log = {k: redact(v, secrets) if isinstance(v, str) else v for k, v in out.log.items()}
    out.log.update(started=started, duration_ms=int((time.monotonic() - t0) * 1000))
    return out


def bootstrap(settings: Settings, store: Store) -> Identity:
    """Make sure the keyword and the profile's seeds are in the store. Returns the keyword identity."""
    store.seed(settings.keyword, "keyword", "owner-declared keyword")
    for s in settings.seeds:
        store.seed(s["value"], s.get("kind", "email"), s.get("proof", "owner seed"))
    return next(i for i in store.identities("claimed") if i.kind == "keyword")


def _derived_usernames(settings: Settings, store: Store) -> list[Candidate]:
    """The keyword itself and local parts of claimed emails are likely usernames."""
    out = [Candidate(settings.keyword, "username", "derived: keyword")]
    for i in store.identities("claimed"):
        if i.kind == "email":
            local = i.value.split("@")[0]
            if settings.keyword in local:
                out.append(Candidate(local, "username", f"derived: local part of {i.value}"))
    return out


def _select(plugins: list[Plugin], only: list[str] | None) -> list[Plugin]:
    if not only:
        return plugins
    unknown = set(only) - {p.name for p in plugins}
    if unknown:
        raise ValueError(f"unknown source(s): {', '.join(sorted(unknown))}")
    return [p for p in plugins if p.name in only]


# progress(done, total, source, identity, status): called after every finished source run (from this thread)
Progress = Callable[[int, int, str, str, str], None]


def _execute(settings: Settings, store: Store, stage: str, idents: list[Identity],
             only: list[str] | None, workers: int, progress: Progress | None = None,
             cancel: threading.Event | None = None) -> RunSummary:
    for i in idents:                      # the claim gate, enforced again right before any lookup
        if not i.claimed:
            raise ClaimError(f"{i.value} is not claimed; refusing to scan it")
    guard = ScopeGuard(settings)
    owned = {i.value for i in store.identities("claimed")}
    ctx = Context(settings, guard, Http(settings, guard), owned)
    scan_id = store.start_scan(stage)
    summary = RunSummary(scan_id)
    secrets = settings.secret_values()
    jobs = [(p, i) for i in idents for p in _select(ALL_PLUGINS, only) if i.kind in p.kinds]

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_run_one, ctx, p, i, secrets) for p, i in jobs]
        for fut in as_completed(futures):
            if cancel is not None and cancel.is_set():
                for other in futures:
                    other.cancel()                  # runs not started yet are dropped; finished ones are saved
            if fut.cancelled():
                continue
            o = fut.result()
            p, i = o.plugin, o.ident
            done += 1
            if progress:
                progress(done, len(jobs), p.name, i.value, o.status)
            if o.status not in ("ok", "partial"):
                store.record_run(scan_id, p.name, i, o.status, 0, o.error, **o.log)
                label = {"skipped": "skipped", "scope_blocked": "SCOPE BLOCKED", "error": "error"}[o.status]
                summary.runs.append((p.name, i.value, f"{label}: {o.error}"))
                continue
            result = o.result
            new, gone = store.save_findings(scan_id, i, p.name, result.findings, mark_gone=o.status == "ok")
            summary.new_findings += new
            summary.gone_findings += gone
            for c in result.candidates:
                if store.add_candidate(c):
                    summary.new_candidates.append(c.value)
            store.record_run(scan_id, p.name, i, o.status, len(result.findings), o.error, **o.log)
            note = f"; {o.error}" if o.status == "partial" else ""
            summary.runs.append((p.name, i.value, f"{o.status}, {len(result.findings)} finding(s){note}"))
    store.finish_scan(scan_id)
    summary.cancelled = bool(cancel is not None and cancel.is_set())
    return summary


def expand(settings: Settings, store: Store, only: list[str] | None = None, workers: int = 4,
           progress: Progress | None = None, cancel: threading.Event | None = None) -> RunSummary:
    kw = bootstrap(settings, store)
    derived = [c.value for c in _derived_usernames(settings, store) if store.add_candidate(c)]
    summary = _execute(settings, store, "expand", [kw], only, workers, progress, cancel)
    summary.new_candidates = derived + summary.new_candidates
    return summary


def scan(settings: Settings, store: Store, only: list[str] | None = None, workers: int = 4,
         progress: Progress | None = None, cancel: threading.Event | None = None) -> RunSummary:
    bootstrap(settings, store)
    idents = [i for i in store.identities("claimed") if i.kind != "keyword"]
    return _execute(settings, store, "scan", idents, only, workers, progress, cancel)


def rescan(settings: Settings, store: Store, sources: list[str], identity_values: set[str],
           workers: int = 4, progress: Progress | None = None, cancel: threading.Event | None = None) -> RunSummary:
    """Re-run only these sources for only these (claimed) identities, e.g. to verify a removal."""
    bootstrap(settings, store)
    idents = [i for i in store.identities("claimed") if i.value in identity_values]
    return _execute(settings, store, "recheck", idents, sources, workers, progress, cancel)
