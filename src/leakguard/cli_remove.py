"""`leakguard remove ...`: five commands for the whole removal workflow.

  status [ID]            refresh the plan from your findings and list actions (or show one in detail)
  do ID [--confirm]      perform an action by its method: email (draft / send), form (fill / submit), manual (steps)
  set ID [STATE] ...     record progress: a state, a note, a contact you checked
  add SITE -i IDENTITY   add an action for an account no scan found
  check [ID]             re-run the sources behind actions; verified when every linked finding is gone
"""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import config
from .removal import drafts, tracker
from .removal.catalog import ensure_jdm
from .store import ACTION_STATES, Store, now

app = typer.Typer(help="Removal workflow: plan from findings, act, verify.", no_args_is_help=True)
console = Console()
ProfileOpt = typer.Option(None, "--profile", "-p", help="lab | internet (default: LEAKGUARD_PROFILE or lab)")
STATE_COLOR = {"planned": "white", "drafted": "cyan", "requested": "yellow", "acknowledged": "yellow",
               "removed": "green", "verified": "bold green", "done": "green", "skipped": "dim"}
OUTGOING = {"email": "send the request", "form": "submit the form"}


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


def _details(store: Store, a) -> None:
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
        console.print("  (added by you, no scan finding: verify by hand)")
    console.print("\n[bold]History[/]")
    for h in json.loads(a["history"] or "[]"):
        console.print(f"  {h['ts']}  {h['state']:<12} {h['note']}")
    if a["draft_path"]:
        console.print(f"\ndraft: {a['draft_path']}")


@app.command()
def status(action_id: Optional[int] = typer.Argument(None, help="Show one action in detail."),
           state: Optional[str] = typer.Option(None, help=" | ".join(ACTION_STATES)),
           due: bool = typer.Option(False, help="Only actions whose follow-up date has passed."),
           profile: Optional[str] = ProfileOpt) -> None:
    """Refresh the plan from your findings, then list actions (or show one in detail).
    Open findings -> removal actions (one per site), protect -> one checklist, the rest skipped."""
    s, store = _open(profile)
    if note := ensure_jdm(s):
        console.print(f"[dim]{note}[/]")
    created, _ = tracker.plan(s, store)
    if created:
        console.print(f"[green]{created} new action(s)[/] from your findings")
    if action_id is not None:
        try:
            _details(store, store.action(action_id))
        except KeyError as e:
            _fail(e)
        return
    rows = store.actions(state)
    if due:
        rows = [a for a in rows if a["next_check"] and a["next_check"] <= now()]
    _table(rows, "Removal actions" + (" (due)" if due else ""))


@app.command("do")
def do_action(action_id: int,
              confirm: bool = typer.Option(False, "--confirm", help="Really send the email / submit the form."),
              profile: Optional[str] = ProfileOpt) -> None:
    """Perform an action. email: show the draft (--confirm sends it). form: fill and screenshot (--confirm
    submits). manual / checklist: show the steps, then record it with `set ID done`."""
    s, store = _open(profile)
    try:
        a = store.action(action_id)
        if a["method"] == "email":
            msg, path = tracker.draft(s, store, action_id)
            console.print(f"[dim]{path}[/]\n")
            for h in ("From", "To", "Subject"):
                console.print(f"[bold]{h}:[/] {msg[h] or '[red](no address: paste into the site contact form)[/]'}")
            console.print("\n" + msg.get_content())
            if confirm:
                console.print(tracker.send(s, store, action_id, True))
        elif a["method"] == "form":
            r = tracker.submit_form(s, store, action_id, confirm)
            console.print(f"filled form screenshot: {r.filled}")
            if r.blocked:
                console.print(f"[yellow]blocked {len(r.blocked)} out-of-scope request(s)[/] (e.g. {r.blocked[0][:80]})")
            if r.submitted:
                console.print(f"[green]submitted[/]; after screenshot: {r.after}; success text seen: {r.success}")
        else:
            _details(store, a)
            console.print(f"\nWhen you have done it: [cyan]leakguard remove set {action_id} done --note \"...\"[/]")
            return
    except (drafts.DraftError, KeyError, ValueError) as e:
        _fail(e)
    if not confirm and a["method"] in OUTGOING:
        console.print(f"\n[bold]Preview only.[/] Re-run with [cyan]--confirm[/] to {OUTGOING[a['method']]}.")


@app.command("set")
def set_action(action_id: int,
               state: Optional[str] = typer.Argument(None, help=" | ".join(ACTION_STATES) + " (done = you did it)"),
               note: str = typer.Option("", help="What happened (e.g. 'site replied: deleted')."),
               contact: Optional[str] = typer.Option(None, help="Email address or URL you checked yourself."),
               profile: Optional[str] = ProfileOpt) -> None:
    """Record progress on an action: a state, a note, and/or a contact you checked."""
    s, store = _open(profile)
    try:
        a = store.action(action_id)
        if contact:
            method = "email" if "@" in contact and "/" not in contact else ("manual" if a["method"] == "email" else a["method"])
            store.db.execute("UPDATE actions SET contact=?, contact_verified=1, method=? WHERE id=?",
                             (contact, method, action_id))
            store.db.commit()
            store.set_action_state(action_id, a["state"], f"contact set by owner: {contact}")
            console.print(f"[green]contact set[/]: {contact}")
            a = store.action(action_id)
        if state:
            if state == "done" and a["state"] in ("requested", "acknowledged"):
                state = "removed"                      # you finished something already requested
            verifiable = a["finding_ids"] != "[]" and a["kind"] not in tracker.OWNER_CONFIRMED
            extra = {}
            if state in ("requested", "acknowledged") or (state in ("done", "removed") and verifiable):
                extra["next_check"] = tracker._due(a["method"])
            elif state in ("done", "removed", "skipped", "verified"):
                extra["next_check"] = None
            a = store.set_action_state(action_id, state, note or "set by owner", **extra)
            hint = " Run [cyan]leakguard remove check[/] later to verify." if extra.get("next_check") and state in ("done", "removed") else ""
            console.print(f"#{action_id} -> [{STATE_COLOR[a['state']]}]{a['state']}[/].{hint}")
        elif note and not contact:
            store.set_action_state(action_id, a["state"], note)
            console.print(f"#{action_id}: note added")
    except (ValueError, KeyError) as e:
        _fail(e)


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
                  + ("" if contact else " (no contact yet: `leakguard remove set ID --contact ...`)"))


@app.command()
def check(action_id: Optional[int] = typer.Argument(None, help="One action; default: every action waiting on a site."),
          profile: Optional[str] = ProfileOpt) -> None:
    """Re-run the sources behind actions; verified when every linked finding is gone."""
    s, store = _open(profile)
    ids = [action_id] if action_id else [a["id"] for a in store.actions()
                                         if a["state"] in ("requested", "acknowledged", "removed", "done")
                                         and a["kind"] not in tracker.OWNER_CONFIRMED]
    if not ids:
        console.print("nothing waiting on a site")
    for i in ids:
        console.print(f"#{i}: {tracker.check(s, store, i)}")
