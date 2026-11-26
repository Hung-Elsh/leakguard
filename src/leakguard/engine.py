"""Run plugins over identities. `expand` works from the keyword; `scan` only from claimed identities."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import httpx

from .config import Settings
from .models import Candidate, Identity
from .net import Http
from .plugins import ALL_PLUGINS, Context, Plugin, SkipSource
from .scope import ScopeError, ScopeGuard
from .store import Store


class ClaimError(Exception):
    pass


@dataclass
class RunSummary:
    scan_id: int
    new_findings: int = 0
    gone_findings: int = 0
    new_candidates: list[str] = field(default_factory=list)
    runs: list[tuple[str, str, str]] = field(default_factory=list)   # (source, identity, status)


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


def _execute(settings: Settings, store: Store, stage: str, idents: list[Identity],
             only: list[str] | None, workers: int) -> RunSummary:
    for i in idents:                      # the claim gate, enforced again right before any lookup
        if not i.claimed:
            raise ClaimError(f"{i.value} is not claimed; refusing to scan it")
    guard = ScopeGuard(settings)
    ctx = Context(settings, guard, Http(settings, guard))
    scan_id = store.start_scan(stage)
    summary = RunSummary(scan_id)
    jobs = [(p, i) for i in idents for p in _select(ALL_PLUGINS, only) if i.kind in p.kinds]

    def job(p: Plugin, i: Identity):
        p.check(ctx)
        return p.run(ctx, i)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(job, p, i): (p, i) for p, i in jobs}
        for fut in as_completed(futures):
            p, i = futures[fut]
            try:
                result = fut.result()
            except SkipSource as e:
                store.record_run(scan_id, p.name, i, False, f"skipped: {e}", 0)
                summary.runs.append((p.name, i.value, f"skipped: {e}"))
                continue
            except ScopeError as e:
                store.record_run(scan_id, p.name, i, False, f"SCOPE BLOCKED: {e}", 0)
                summary.runs.append((p.name, i.value, f"SCOPE BLOCKED: {e}"))
                continue
            except (httpx.HTTPError, ValueError, KeyError, OSError, RuntimeError) as e:
                msg = f"{type(e).__name__}: {e}"[:300]
                store.record_run(scan_id, p.name, i, False, msg, 0)
                summary.runs.append((p.name, i.value, f"error: {msg}"))
                continue
            new, gone = store.save_findings(scan_id, i, p.name, result.findings)
            summary.new_findings += new
            summary.gone_findings += gone
            for c in result.candidates:
                if store.add_candidate(c):
                    summary.new_candidates.append(c.value)
            store.record_run(scan_id, p.name, i, True, "", len(result.findings))
            summary.runs.append((p.name, i.value, f"ok, {len(result.findings)} finding(s)"))
    store.finish_scan(scan_id)
    return summary


def expand(settings: Settings, store: Store, only: list[str] | None = None, workers: int = 4) -> RunSummary:
    kw = bootstrap(settings, store)
    derived = [c.value for c in _derived_usernames(settings, store) if store.add_candidate(c)]
    summary = _execute(settings, store, "expand", [kw], only, workers)
    summary.new_candidates = derived + summary.new_candidates
    return summary


def scan(settings: Settings, store: Store, only: list[str] | None = None, workers: int = 4) -> RunSummary:
    bootstrap(settings, store)
    idents = [i for i in store.identities("claimed") if i.kind != "keyword"]
    return _execute(settings, store, "scan", idents, only, workers)
