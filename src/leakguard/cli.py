"""LeakGuard command line. Commands are added phase by phase (see .claude/PLAN.md)."""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, config, engine, leaks, report
from .models import mask
from .paths import CONFIG, USER_IDENTITY
from .plugins import ALL_PLUGINS
from .plugins.tools import ToolPlugin
from .runner import ToolError, find_binary
from .store import Store

app = typer.Typer(help="Find, block and remove your own leaked personal data.", no_args_is_help=True)
console = Console()

ProfileOpt = typer.Option(None, "--profile", "-p", help="lab | internet (default: LEAKGUARD_PROFILE or lab)")
SourceOpt = typer.Option(None, "--source", "-s", help="Only these sources (repeatable).")


def _open(profile: Optional[str]) -> tuple[config.Settings, Store]:
    try:
        s = config.load(profile)
    except config.ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        raise typer.Exit(2)
    console.print(f"[dim]profile: [bold]{s.profile}[/bold] · db: {s.db_path.name}[/]")
    return s, Store(s.db_path)


def _version(value: bool) -> None:
    if value:
        console.print(f"leakguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version."),
) -> None:
    pass


def _split(values: list[str] | None) -> list[str]:
    """Accept repeated options and comma-separated values."""
    return [v.strip() for item in values or [] for v in item.split(",") if v.strip()]


@app.command()
def init(
    keyword: Optional[str] = typer.Option(None, help="Your unique keyword (asked if omitted)."),
    email: Optional[list[str]] = typer.Option(None, "--email", "-e", help="Your email(s); repeatable or comma-separated."),
    username: Optional[list[str]] = typer.Option(None, "--username", "-u", help="Known username(s), optional."),
    full_name: Optional[str] = typer.Option(None, help="Name for removal requests (phase 3), optional."),
    force: bool = typer.Option(False, help="Overwrite an existing identity without asking."),
) -> None:
    """Enter your own identity. Stored privately in ~/.config/leakguard, never in the repository."""
    if USER_IDENTITY.exists() and not force:
        if not typer.confirm(f"{USER_IDENTITY} exists. Replace it?", default=False):
            raise typer.Exit()
    ident = {
        "keyword": keyword or typer.prompt("Keyword (the unique word you made up)"),
        "emails": _split(email) or _split([typer.prompt("Email address(es), comma-separated")]),
        "usernames": _split(username) if username is not None
                     else _split([typer.prompt("Known usernames, comma-separated (Enter to skip)", default="",
                                               show_default=False)]),
        "owner": {"full_name": full_name if full_name is not None
                  else typer.prompt("Full name for removal requests (Enter to skip)", default="", show_default=False),
                  "country": ""},
    }
    try:
        path = config.write_identity(ident)
    except config.ConfigError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2)
    saved = config.read_identity("internet")
    console.print(f"[green]saved[/] {path} (mode 600)")
    console.print(f"  keyword: {mask(saved['keyword'])} · emails: {len(saved['emails'])} · usernames: {len(saved['usernames'])}")
    console.print("Next: [cyan]leakguard install-hook[/] (blocks commits containing these), then "
                  "[cyan]leakguard expand -p internet[/]")


@app.command()
def leakcheck(staged: bool = typer.Option(False, help="Check staged changes only (used by the pre-commit hook).")) -> None:
    """Fail if any file git would commit contains your keyword, emails, usernames or found identities."""
    hits, n_terms = leaks.check(staged)
    if n_terms == 0:
        console.print("[yellow]no private identity found (run leakguard init); nothing to check against[/]")
        return
    if hits:
        console.print(f"[red bold]LEAK: {len(hits)} occurrence(s) of your private identity:[/]")
        for h in hits[:50]:
            console.print(f"  {leaks.describe(h)}")
        console.print("Remove them (or git-ignore the file) before committing.")
        raise typer.Exit(1)
    console.print(f"[green]clean[/]: no private term ({n_terms} checked) in {'staged changes' if staged else 'files git would commit'}")


@app.command("install-hook")
def install_hook() -> None:
    """Install a git pre-commit hook that runs `leakguard leakcheck --staged`."""
    try:
        hook = leaks.install_hook()
    except (FileNotFoundError, FileExistsError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"[green]installed[/] {hook}")


def _print_summary(summary: engine.RunSummary) -> None:
    t = Table(title=f"Scan #{summary.scan_id}")
    for col in ("Source", "Identity", "Result"):
        t.add_column(col)
    for src, ident, status in sorted(summary.runs):
        style = "green" if status.startswith("ok") else "yellow" if status.startswith("skipped") else "red"
        t.add_row(src, ident, f"[{style}]{status}[/]")
    console.print(t)
    console.print(f"new findings: [bold]{summary.new_findings}[/] · gone: [bold]{summary.gone_findings}[/]")
    if summary.new_candidates:
        console.print(f"[bold yellow]{len(summary.new_candidates)} new candidate(s):[/] "
                      + ", ".join(summary.new_candidates))
        console.print("Review them with [cyan]leakguard identities[/], then claim or reject.")


@app.command()
def expand(profile: Optional[str] = ProfileOpt, source: Optional[list[str]] = SourceOpt,
           workers: int = typer.Option(4, help="Parallel source runs.")) -> None:
    """Search for the keyword itself and propose candidate emails/usernames."""
    s, store = _open(profile)
    _print_summary(engine.expand(s, store, source, workers))


@app.command()
def scan(profile: Optional[str] = ProfileOpt, source: Optional[list[str]] = SourceOpt,
         workers: int = typer.Option(4, help="Parallel source runs.")) -> None:
    """Deep-scan every claimed email and username."""
    s, store = _open(profile)
    _print_summary(engine.scan(s, store, source, workers))


@app.command()
def identities(profile: Optional[str] = ProfileOpt,
               status: Optional[str] = typer.Option(None, help="claimed | candidate | rejected")) -> None:
    """List identities and their claim status."""
    s, store = _open(profile)
    engine.bootstrap(s, store)
    t = Table(title="Identities")
    for col in ("ID", "Value", "Kind", "Status", "Origin / proof"):
        t.add_column(col)
    colors = {"claimed": "green", "candidate": "yellow", "rejected": "dim"}
    for i in store.identities(status):
        t.add_row(str(i.id), i.value, i.kind, f"[{colors[i.status]}]{i.status}[/]", i.proof or i.origin)
    console.print(t)


@app.command()
def claim(ids: list[int], profile: Optional[str] = ProfileOpt,
          proof: str = typer.Option("owner-attested", help="How you know it is yours.")) -> None:
    """Confirm that candidate identities are yours. Only claimed identities are scanned or cleaned."""
    s, store = _open(profile)
    for i in ids:
        ident = store.decide(i, "claimed", proof)
        console.print(f"[green]claimed[/] {ident.value} ({ident.kind})")


@app.command()
def reject(ids: list[int], profile: Optional[str] = ProfileOpt) -> None:
    """Mark candidates as not yours. They are never scanned and not proposed again."""
    s, store = _open(profile)
    for i in ids:
        ident = store.decide(i, "rejected")
        console.print(f"[dim]rejected[/] {ident.value}")


@app.command()
def findings(profile: Optional[str] = ProfileOpt,
             status: Optional[str] = typer.Option(None, help="new | known | gone")) -> None:
    """Show findings."""
    s, store = _open(profile)
    t = Table(title="Findings")
    for col in ("Status", "Sev", "Category", "Identity", "Source", "Finding"):
        t.add_column(col, overflow="fold")
    sev = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    for f in store.findings(status):
        t.add_row(f["status"], f"[{sev[f['severity']]}]{f['severity']}[/]", f["category"], f["identity"],
                  f["source"], f["title"] + (f"\n[dim]{f['url']}[/]" if f["url"] else ""))
    console.print(t)


@app.command("report")
def report_cmd(profile: Optional[str] = ProfileOpt) -> None:
    """Write a Markdown + JSON report to reports/."""
    s, store = _open(profile)
    md, js = report.write(s, store)
    console.print(f"report: [cyan]{md}[/]\n  json: [cyan]{js}[/]")


@app.command()
def sources(profile: Optional[str] = ProfileOpt) -> None:
    """Show each source, what it handles and whether it can run in this profile."""
    s, _ = _open(profile)
    t = Table(title=f"Sources ({s.profile})")
    for col in ("Source", "Handles", "Allowed", "Ready"):
        t.add_column(col)
    for p in ALL_PLUGINS:
        allowed = s.source(p.name).get("allowed", False)
        missing = [k for k in p.needs if not s.key(k)]
        ready = "[red]missing " + ", ".join(missing) + "[/]" if missing else "[green]yes[/]"
        if s.tools_mode == "fixtures" and isinstance(p, ToolPlugin):
            ready = "[cyan]fixtures[/]"
        t.add_row(p.name, ", ".join(p.kinds), "yes" if allowed else "[red]no[/]", ready)
    console.print(t)


@app.command()
def doctor() -> None:
    """Show which external OSINT tools are installed, and how to install the rest."""
    catalogue = json.loads((CONFIG / "tools.json").read_text())["tools"]
    table = Table(title="External tools")
    for col in ("Tool", "Phase", "Status", "Purpose"):
        table.add_column(col)
    missing = []
    for tool in catalogue:
        try:
            where = find_binary(*tool["detect"])
        except ToolError:
            where = None
        status = f"[green]ok[/] {where}" if where else "[red]missing[/]"
        table.add_row(tool["name"], str(tool["phase"]), status, tool["purpose"])
        if not where:
            missing.append(tool)
    console.print(table)
    if missing:
        console.print("\n[bold]Install the missing tools (run these yourself):[/]")
        for tool in missing:
            console.print(f"  [cyan]{tool['name']}[/]: {tool['install']}", soft_wrap=True)


if __name__ == "__main__":
    app()
