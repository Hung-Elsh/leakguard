"""`leakguard keys`: API keys, the mail app password and the Gmail sign-in, kept in the system keyring (or a
private fallback file). Values are never printed; the database only records that a connection exists."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import config, keystore, service
from .store import Store

app = typer.Typer(help="Keys and sign-ins: list, set, forget (stored in the system keyring).",
                  invoke_without_command=True)
console = Console()
ProfileOpt = typer.Option(None, "--profile", "-p", help="lab | internet (default: LEAKGUARD_PROFILE or lab)")


def _open(profile: Optional[str]) -> tuple[config.Settings, Store]:
    try:
        s = config.load(profile or "internet")
    except config.ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        raise typer.Exit(2)
    return s, Store(s.db_path)


def _name(name: str) -> str:
    name = name.upper()
    if name not in keystore.KNOWN:
        console.print(f"[red]unknown key {name}[/]; known: {', '.join(keystore.KNOWN)}")
        raise typer.Exit(2)
    return name


@app.callback()
def list_keys(ctx: typer.Context, profile: Optional[str] = ProfileOpt) -> None:
    """List the keys LeakGuard knows and where each one comes from (values are never shown)."""
    if ctx.invoked_subcommand:
        return
    s, store = _open(profile)
    t = Table(title=f"Keys · stored in {keystore.store().where()}")
    for col in ("Name", "Set", "From", "Added", "Last test"):
        t.add_column(col)
    for k in service.keys_status(s, store):
        t.add_row(k.name, "[green]yes[/]" if k.origin else "[dim]no[/]", k.origin or "-", (k.added or "")[:10],
                  f"{(k.last_test or '')[:10]} {k.last_result or ''}".strip() or "-")
    console.print(t)


@app.command("set")
def set_key(name: str = typer.Argument(..., help=", ".join(keystore.KNOWN[:-1])),
            profile: Optional[str] = ProfileOpt) -> None:
    """Save a key (typed hidden, or piped in: `echo KEY | leakguard keys set BRAVE_API_KEY`)."""
    name = _name(name)
    _, store = _open(profile)
    value = typer.prompt(f"{name}", hide_input=True)
    try:
        where = service.set_key(store, name, value)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2)
    console.print(f"[green]saved[/] {name} in {where}")


@app.command("forget")
def forget_key(name: str = typer.Argument(..., help=", ".join(keystore.KNOWN)),
               profile: Optional[str] = ProfileOpt) -> None:
    """Remove a key. GMAIL_TOKEN: the next Gmail command asks you to sign in again (choose the account then)."""
    name = _name(name)
    _, store = _open(profile)
    had = service.forget_key(store, name)
    console.print(f"[green]forgot[/] {name}" if had else f"{name} was not stored")
