"""`leakguard remove ...`: plan, act on and verify removal actions."""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import config
from .removal import drafts, tracker
from .store import ACTION_STATES, Store

app = typer.Typer(help="Removal workflow: plan actions from findings, send requests, verify they worked.",
                  no_args_is_help=True)
console = Console()
ProfileOpt = typer.Option(None, "--profile", "-p", help="lab | internet (default: LEAKGUARD_PROFILE or lab)")
STATE_COLOR = {"planned": "white", "drafted": "cyan", "requested": "yellow", "acknowledged": "yellow",
               "removed": "green", "verified": "bold green", "done": "green", "skipped": "dim"}


def _open(profile: Optional[str]) -> tuple[config.Settings, Store]:
    try:
        s = config.load(profile)
    except config.ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        raise typer.Exit(2)
    console.print(f"[dim]profile: [bold]{s.profile}[/bold][/]")
    return s, Store(s.db_path)


def _fail(e: Exception) -> None:
    console.print(f"[red]{e}[/]")
    raise typer.Exit(2)


def _table(rows, title: str) -> None:
    t = Table(title=title)
    for col in ("ID", "State", "Kind", "Method", "Target", "Findings", "Contact", "Next check"):
        t.add_column(col, overflow="fold")
    for a in rows:
        contact = a["contact"] or "[red]needed[/]"
        if a["contact"] and not a["contact_verified"]:
            contact += " [red](unverified)[/]"
        t.add_row(str(a["id"]), f"[{STATE_COLOR[a['state']]}]{a['state']}[/]", a["kind"], a["method"], a["target"],
                  str(len(json.loads(a["finding_ids"] or "[]"))), contact if a["method"] != "checklist" else "-",
                  (a["next_check"] or "")[:10])
    console.print(t)


@app.command()
def plan(profile: Optional[str] = ProfileOpt) -> None:
    """Build or refresh actions from open/protect findings (one action per site, index or broker)."""
    s, store = _open(profile)
    created, updated = tracker.plan(s, store)
    console.print(f"[green]{created} new[/], {updated} updated")
    _table(store.actions(), "Removal actions")


@app.command("list")
def list_(profile: Optional[str] = ProfileOpt, state: Optional[str] = typer.Option(None, help=" | ".join(ACTION_STATES)),
          due: bool = typer.Option(False, help="Only actions whose follow-up date has passed.")) -> None:
    """Show actions and their state."""
    from .store import now
    s, store = _open(profile)
    rows = store.actions(state)
    if due:
        rows = [a for a in rows if a["next_check"] and a["next_check"] <= now()]
    _table(rows, "Removal actions" + (" (due)" if due else ""))


@app.command()
def show(action_id: int, profile: Optional[str] = ProfileOpt) -> None:
    """Everything about one action: steps, contact, linked findings, history."""
    s, store = _open(profile)
    try:
        a = store.action(action_id)
    except KeyError as e:
        _fail(e)
    console.print(f"[bold]#{a['id']} {a['title']}[/]  ({a['kind']}, {a['method']}, [{STATE_COLOR[a['state']]}]{a['state']}[/])")
    if a["contact"]:
        console.print(f"contact: {a['contact']}" + ("" if a["contact_verified"] else " [red](unverified: check before use)[/]"))
    if a["steps"]:
        console.print(f"\n[bold]Steps[/]\n{a['steps']}")
    console.print("\n[bold]Linked findings[/]")
    for f in store.findings_by_ids(json.loads(a["finding_ids"] or "[]")):
        console.print(f"  {f['id'][:8]} [{f['status']}] {f['identity']} · {f['source']}: {f['title'][:70]}"
                      + (f"\n           {f['url']}" if f["url"] else ""))
    if a["key"].startswith("manual:"):
        console.print("  (added by you, no scan finding: verify by hand, then `leakguard remove done`)")
    console.print("\n[bold]History[/]")
    for h in json.loads(a["history"] or "[]"):
        console.print(f"  {h['ts']}  {h['state']:<12} {h['note']}")
    if a["draft_path"]:
        console.print(f"\ndraft: {a['draft_path']}")


@app.command()
def draft(action_id: int, profile: Optional[str] = ProfileOpt) -> None:
    """Write the email request for an action and print it (nothing is sent)."""
    s, store = _open(profile)
    try:
        msg, path = tracker.draft(s, store, action_id)
    except (drafts.DraftError, KeyError) as e:
        _fail(e)
    console.print(f"[dim]{path}[/]\n")
    for h in ("From", "To", "Subject"):
        console.print(f"[bold]{h}:[/] {msg[h]}")
    console.print("\n" + msg.get_content())


@app.command()
def send(action_id: int, confirm: bool = typer.Option(False, "--confirm", help="Really send it."),
         profile: Optional[str] = ProfileOpt) -> None:
    """Send an action's email request (preview unless --confirm). Lab: Mailpit. Internet: your Gmail."""
    s, store = _open(profile)
    try:
        console.print(tracker.send(s, store, action_id, confirm))
    except (drafts.DraftError, KeyError, ValueError) as e:
        _fail(e)


@app.command()
def form(action_id: int, confirm: bool = typer.Option(False, "--confirm", help="Click submit after filling."),
         profile: Optional[str] = ProfileOpt) -> None:
    """Fill an opt-out form in a headless browser and screenshot it; submits only with --confirm."""
    s, store = _open(profile)
    try:
        r = tracker.submit_form(s, store, action_id, confirm)
    except (drafts.DraftError, KeyError, ValueError) as e:
        _fail(e)
    console.print(f"filled form screenshot: {r.filled}")
    if r.blocked:
        console.print(f"[yellow]blocked {len(r.blocked)} out-of-scope request(s)[/] (e.g. {r.blocked[0][:80]})")
    if r.submitted:
        console.print(f"[green]submitted[/]; after screenshot: {r.after}; success text seen: {r.success}")
    else:
        console.print("not submitted: check the screenshot, then re-run with [cyan]--confirm[/]")


@app.command()
def contact(action_id: int, value: str = typer.Argument(..., help="Email address or URL you checked yourself."),
            profile: Optional[str] = ProfileOpt) -> None:
    """Set the contact of an action (you checked it, so it counts as verified)."""
    s, store = _open(profile)
    a = store.action(action_id)
    store.db.execute("UPDATE actions SET contact=?, contact_verified=1, method=? WHERE id=?",
                     (value, "email" if "@" in value and "/" not in value else ("manual" if a["method"] == "email" else a["method"]),
                      action_id))
    store.db.commit()
    store.set_action_state(action_id, a["state"], f"contact set by owner: {value}")
    console.print(f"[green]contact set[/] for #{action_id}: {value}")


@app.command()
def done(action_id: int, note: str = typer.Option("", help="What you did."), profile: Optional[str] = ProfileOpt) -> None:
    """Record that you did a manual step / checklist (e.g. deleted the account yourself)."""
    s, store = _open(profile)
    a = store.action(action_id)
    target = "done" if a["state"] in ("planned", "drafted", "skipped") else "removed"
    try:
        verifiable = a["finding_ids"] != "[]" and a["kind"] not in tracker.OWNER_CONFIRMED
        store.set_action_state(action_id, target, note or "done by owner",
                               next_check=tracker._due(a["method"]) if verifiable else None)
    except ValueError as e:
        _fail(e)
    hint = (" Run [cyan]leakguard remove check[/] later to verify."
            if json.loads(a["finding_ids"] or "[]") and a["kind"] not in tracker.OWNER_CONFIRMED else "")
    console.print(f"[green]{target}[/] #{action_id}.{hint}")


@app.command("add")
def add_action(target: str = typer.Argument(..., help="Site or service, e.g. 'Zing ID'."),
               identity: str = typer.Option(..., "--identity", "-i", help="Your email/username on it."),
               url: str = typer.Option("", help="Delete-account page you found, if any."),
               email: str = typer.Option("", help="Privacy/support address you found, if any."),
               why: str = typer.Option("", "--why", help="How you know about it (e.g. 'password-reset mail 2024-07')."),
               kind: str = typer.Option("account_delete", help="account_delete | data_erasure | manual"),
               profile: Optional[str] = ProfileOpt) -> None:
    """Add an action for something no scan found (e.g. an account you know you have)."""
    from .removal.catalog import Catalog, site_key
    s, store = _open(profile)
    e = Catalog(s).lookup(target)
    contact, verified = (email, True) if email else (url, True) if url else ((e.email or e.url, e.verified) if e else ("", False))
    method = "email" if email or (e and e.method == "email" and not url) else "manual"
    aid, created = store.upsert_action({
        "key": f"manual:{site_key(target)}", "kind": kind, "method": method, "target": e.name if e else target,
        "title": f"Delete / deactivate the account on {e.name if e else target}", "contact": contact or None,
        "contact_verified": verified, "template": "account_deletion" if method == "email" else None,
        "finding_ids": [], "identities": [identity],
        "steps": (e.steps if e else "") or "Find the site's account-deletion page or privacy contact."})
    store.set_action_state(aid, store.action(aid)["state"], f"added by owner: {why or 'known account'}")
    console.print(f"[green]{'added' if created else 'updated'}[/] action #{aid} for {target}"
                  + ("" if contact else " (no contact yet: `leakguard remove contact`)"))


@app.command("set")
def set_state(action_id: int, state: str = typer.Argument(..., help=" | ".join(ACTION_STATES)),
              note: str = typer.Option("", help="Why (e.g. 'site replied: deleted')."),
              profile: Optional[str] = ProfileOpt) -> None:
    """Move an action to a state by hand (e.g. acknowledged when the site replies)."""
    s, store = _open(profile)
    try:
        cur = store.action(action_id)
        extra = {"next_check": tracker._due(cur["method"])} if state in ("requested", "acknowledged", "removed") else {}
        a = store.set_action_state(action_id, state, note or "set by owner", **extra)
    except (ValueError, KeyError) as e:
        _fail(e)
    console.print(f"#{action_id} -> [{STATE_COLOR[a['state']]}]{a['state']}[/]")


@app.command()
def check(action_id: Optional[int] = typer.Argument(None, help="One action; default: all requested/removed/done."),
          profile: Optional[str] = ProfileOpt) -> None:
    """Re-run the sources behind an action; verified when every linked finding is gone."""
    s, store = _open(profile)
    ids = [action_id] if action_id else [a["id"] for a in store.actions()
                                         if a["state"] in ("requested", "acknowledged", "removed", "done")
                                         and a["kind"] not in tracker.OWNER_CONFIRMED]
    for i in ids:
        console.print(f"#{i}: {tracker.check(s, store, i)}")


@app.command("catalog-update")
def catalog_update() -> None:
    """Download the JustDeleteMe dataset (delete-account links for many sites) into your data folder."""
    from .net import Http
    from .removal.catalog import JDM_CACHE, JDM_URL
    from .scope import ScopeGuard
    s = config.load("internet")
    with Http(s, ScopeGuard(s)).client("justdeleteme") as c:
        r = c.get(JDM_URL)
        r.raise_for_status()
        sites = r.json()
    JDM_CACHE.parent.mkdir(parents=True, exist_ok=True)
    JDM_CACHE.write_text(json.dumps(sites))
    console.print(f"[green]saved[/] {len(sites)} sites to {JDM_CACHE}")
