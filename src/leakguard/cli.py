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


def _register_subcommands() -> None:
    from .cli_remove import app as remove_app
    app.add_typer(remove_app, name="remove")

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
                  "[cyan]leakguard scan -p internet[/]")


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
        style = ("green" if status.startswith("ok") else "yellow" if status.startswith(("skipped", "partial"))
                 else "red")
        t.add_row(src, ident, f"[{style}]{status}[/]")
    console.print(t)
    console.print(f"new findings: [bold]{summary.new_findings}[/] · gone: [bold]{summary.gone_findings}[/]")
    if summary.new_candidates:
        console.print(f"[bold yellow]{len(summary.new_candidates)} new candidate(s):[/] "
                      + ", ".join(summary.new_candidates))
        console.print("Review them with [cyan]leakguard identities[/], then [cyan]claim[/] or [cyan]reject[/] (ID or value).")


@app.command()
def scan(profile: Optional[str] = ProfileOpt, source: Optional[list[str]] = SourceOpt,
         stage: str = typer.Option("all", help="all | keyword (search the keyword, propose candidates) | "
                                               "identities (deep scan of claimed identities)"),
         workers: int = typer.Option(4, help="Parallel source runs.")) -> None:
    """Discover exposures: search the keyword, propose candidates, deep-scan every claimed identity."""
    if stage not in ("all", "keyword", "identities"):
        console.print("[red]--stage must be all, keyword or identities[/]")
        raise typer.Exit(2)
    s, store = _open(profile)
    if stage in ("all", "keyword"):
        console.print("[bold]Stage 1: keyword[/]")
        _print_summary(engine.expand(s, store, source, workers))
    if stage in ("all", "identities"):
        console.print("[bold]Stage 2: claimed identities[/]")
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


def _decide(tokens: list[str], status: str, profile: Optional[str], proof: str) -> None:
    from .identities import decide
    s, store = _open(profile)
    engine.bootstrap(s, store)
    for t in _split(tokens):
        try:
            d = decide(s, store, t, status, proof)
        except (config.ConfigError, KeyError, ValueError) as e:
            console.print(f"[red]{t}: {e}[/]")
            continue
        verb, color = ("claimed", "green") if status == "claimed" else ("rejected", "dim")
        console.print(f"[{color}]{verb}[/] {d.identity.value} ({d.identity.kind})" + (" [cyan]new[/]" if d.created else ""))


@app.command()
def claim(identities_: list[str] = typer.Argument(..., metavar="ID|VALUE...",
                                                  help="Identity IDs, or emails/usernames (new ones are added)."),
          profile: Optional[str] = ProfileOpt,
          proof: str = typer.Option("owner-attested", help="How you know it is yours.")) -> None:
    """Confirm identities are yours, by ID or value; a value not listed yet is added as yours.
    Only claimed identities are scanned or cleaned."""
    _decide(identities_, "claimed", profile, proof)


@app.command()
def reject(identities_: list[str] = typer.Argument(..., metavar="ID|VALUE...",
                                                   help="Identity IDs, or emails/usernames (new ones are added as rejected)."),
           profile: Optional[str] = ProfileOpt) -> None:
    """Mark identities as not yours, by ID or value. They are never scanned or proposed again."""
    _decide(identities_, "rejected", profile, "")


@app.command()
def findings(profile: Optional[str] = ProfileOpt,
             status: Optional[str] = typer.Option(None, help="new | known | gone"),
             verdict: Optional[str] = typer.Option(None, help="open | protect | accepted | false_positive")) -> None:
    """Show findings with their ID (use it with `leakguard mark`)."""
    s, store = _open(profile)
    t = Table(title="Findings")
    for col in ("ID", "Status", "Verdict", "Sev", "Category", "Identity", "Source", "Finding"):
        t.add_column(col, overflow="fold")
    sev = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    for f in store.findings(status):
        v = f["disposition"] or "open"
        if verdict and v != verdict:
            continue
        t.add_row(f["id"][:8], f["status"], v + (f"\n[dim]{f['note']}[/]" if f["note"] else ""),
                  f"[{sev[f['severity']]}]{f['severity']}[/]", f["category"], f["identity"], f["source"],
                  f["title"] + (f"\n[dim]{f['url']}[/]" if f["url"] else ""))
    console.print(t)


@app.command()
def mark(ids: list[str] = typer.Argument(..., help="Finding IDs (first 6+ characters are enough)."),
         as_: str = typer.Option(..., "--as",
                                 help="open (clean up) | protect (yours: keep and secure) | accepted | false_positive"),
         note: str = typer.Option("", help="Why, for the report/dashboard."),
         profile: Optional[str] = ProfileOpt) -> None:
    """Record your verdict. 'open' = clean up, 'protect' = your account to keep and secure."""
    s, store = _open(profile)
    try:
        for row in store.mark(ids, as_, note):
            console.print(f"[green]{as_}[/] {row['id'][:8]} {row['title'][:70]}")
    except (ValueError, KeyError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2)


@app.command("password-check")
def password_check() -> None:
    """Check if a password appears in known breaches (HIBP Pwned Passwords, k-anonymity).
    The password is hashed locally; only the first 5 hex characters of its SHA-1 leave this machine."""
    import getpass
    import hashlib

    from .net import Http
    from .scope import ScopeGuard
    s = config.load("internet")
    pw = getpass.getpass("Password to check (not shown, not stored): ")
    if not pw:
        raise typer.Exit()
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    del pw
    prefix, suffix = digest[:5], digest[5:]
    guard = ScopeGuard(s)
    with Http(s, guard).client("pwnedpasswords", {"Add-Padding": "true"}) as c:
        r = c.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        r.raise_for_status()
    count = 0
    for line in r.text.splitlines():
        h, _, n = line.partition(":")
        if h.strip() == suffix:
            count = int(n)
            break
    if count:
        console.print(f"[red bold]Found in breaches {count:,} times.[/] Treat it as public: change it everywhere it was used.")
    else:
        console.print("[green]Not found in Pwned Passwords.[/] (A breach can still hold it if it was never published.)")


@app.command()
def block(
    profile: Optional[str] = ProfileOpt,
    apply: bool = typer.Option(False, "--apply", help="Actually move/label mail. Without it: dry run."),
    filters: bool = typer.Option(False, "--filters", help="Also sync your blocklist to Gmail server-side filters."),
    folder: str = typer.Option("INBOX", help="Mailbox folder to check."),
    since: int = typer.Option(90, help="Only mail from the last N days (0 = all)."),
    limit: int = typer.Option(500, help="At most this many messages."),
    show: str = typer.Option("blocked", help="Rows to list: blocked | all | none."),
    owner_copy: bool = typer.Option(False, "--owner-copy",
                                    help="Lab only: run on the copy of your real mail loaded by `lab-import`."),
) -> None:
    """Classify your mail and block unwanted messages (dry run unless --apply)."""
    from .mail import service
    s, store = _open(profile)
    try:
        res = service.run(s, store, folder, since or None, limit, apply, filters, owner_copy)
    except config.ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        raise typer.Exit(2)
    colors = {"keep": "green", "label": "cyan", "archive": "blue", "spam": "yellow", "trash": "red"}
    if show != "none":
        t = Table(title=f"{folder}: {res.total} message(s) checked")
        for col in ("Action", "Rule", "From", "Subject", "Why"):
            t.add_column(col, overflow="fold")
        for m, v in sorted(res.rows, key=lambda r: list(colors).index(r[1].action), reverse=True):
            if show == "all" or v.action != "keep":
                t.add_row(f"[{colors[v.action]}]{v.action}[/]", v.rule, m.from_addr, m.subject[:60],
                          "; ".join(v.reasons))
        console.print(t)
    console.print("  ".join(f"[{colors[a]}]{a}[/]: {n}" for a, n in sorted(res.counts().items())))
    if apply:
        console.print(f"[bold green]applied[/]: " + ", ".join(f"{a} {n}" for a, n in res.applied.items() if a != "keep"))
    else:
        console.print("[bold]dry run[/]: nothing changed. Re-run with [cyan]--apply[/] to move these messages.")
    for line in res.filter_plan:
        console.print(f"  filter: {line}" + ("" if apply else " [dim](dry run)[/]"))
    if res.gmail:
        g = res.gmail
        console.print(f"\n[bold]Compared with Gmail's own Spam label[/] (from Takeout): "
                      f"both blocked {len(g['both'])} · [yellow]only LeakGuard blocks {len(g['leakguard_only'])}[/] "
                      f"· [cyan]only Gmail blocked {len(g['gmail_only'])}[/]")
        for title, key in (("Only LeakGuard blocks (check these are really unwanted)", "leakguard_only"),
                           ("Gmail spam that LeakGuard keeps (rule ideas)", "gmail_only")):
            if g[key]:
                console.print(f"[bold]{title}:[/]")
                for m in g[key][:25]:
                    console.print(f"  {m.from_addr}  {m.subject[:70]}")


@app.command("lab-import")
def lab_import(
    mbox: str = typer.Argument(..., help="Google Takeout .mbox file (keep it under ~/.local/share/leakguard/takeout)."),
    labels: Optional[list[str]] = typer.Option(None, "--label", "-l",
                                               help="Only messages with these Gmail labels, e.g. -l Inbox -l Spam."),
    since: int = typer.Option(365, help="Only mail from the last N days (0 = all)."),
    limit: int = typer.Option(2000, help="At most this many (newest) messages."),
    reset: bool = typer.Option(True, help="Empty the lab owner-copy mailbox first."),
) -> None:
    """Lab only: load a copy of your real mail into the GreenMail owner-copy mailbox. Gmail is not contacted."""
    from pathlib import Path

    from .mail.importer import import_mbox
    s, _ = _open("lab")
    path = Path(mbox).expanduser()
    if not path.is_file():
        console.print(f"[red]not a file:[/] {path}")
        raise typer.Exit(2)
    try:
        r = import_mbox(s, path, {x.lower() for x in _split(labels)}, since or None, limit, reset)
    except config.ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        raise typer.Exit(2)
    console.print(f"read {r.read} · [green]imported {r.imported}[/] · skipped: label {r.skipped_label}, "
                  f"older {r.skipped_old}, unreadable {r.skipped_bad}")
    console.print(f"Next: [cyan]leakguard block -p lab --owner-copy --since 0 --limit {max(r.imported, 1)}[/] (dry run)")


@app.command()
def monitor(profile: Optional[str] = ProfileOpt, source: Optional[list[str]] = SourceOpt,
            quick: bool = typer.Option(False, help="Skip the slow tools (Maigret, SpiderFoot, Sherlock, Blackbird)."),
            mail: bool = typer.Option(False, "--mail", help="Also email the alert to your own address."),
            desktop: bool = typer.Option(True, help="Desktop notification when something new appears."),
            min_severity: str = typer.Option("medium", help="Alert on new exposures from this severity up."),
            schedule: Optional[str] = typer.Option(None, help="daily | weekly | monthly: write systemd timer files "
                                                               "and print how to enable them (does not run a scan).")) -> None:
    """Full check-up: scan, re-check due removals, report what changed, alert, keep a snapshot for trends."""
    from . import monitor as mon
    if schedule:
        prof = profile or "internet"
        extra = " ".join(["--quick"] if quick else []) + (" --mail" if mail else "")
        try:
            out = mon.write_schedule(prof, schedule, extra.strip())
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(2)
        console.print(f"[green]timer files written[/] to {out}\nEnable them (run these yourself):\n")
        console.print(f"  mkdir -p ~/.config/systemd/user && cp {out}/leakguard-monitor.* ~/.config/systemd/user/\n"
                      "  systemctl --user daemon-reload && systemctl --user enable --now leakguard-monitor.timer\n"
                      "  systemctl --user list-timers leakguard-monitor.timer      # next run\n"
                      "  sudo loginctl enable-linger $USER   # optional: also run while you are logged out", soft_wrap=True)
        return
    s, store = _open(profile)
    res = mon.run(s, store, source, quick)
    mon.alert(s, res, desktop, mail, min_severity)
    counted_new = [g for g in res.grouped_new() if g["severity"] != "info"]
    console.print(f"new: [bold]{len(counted_new)}[/] · gone: [bold]{sum(f['severity'] != 'info' for f in res.gone)}[/]"
                  f" · new candidates: {len(res.candidates)}"
                  f" · action changes: {len(res.action_changes)} · source errors: {len(res.problems)}")
    for line in res.reopened:
        console.print(f"  [red]came back:[/] {line}")
    for line in res.checks:
        console.print(f"  {line}")
    console.print(f"report: [cyan]{res.report}[/]" + (f" · alerted: {', '.join(res.alerted)}" if res.alerted else ""))


@app.command("report")
def report_cmd(profile: Optional[str] = ProfileOpt) -> None:
    """Write a Markdown + JSON report to reports/."""
    s, store = _open(profile)
    md, js = report.write(s, store)
    console.print(f"report: [cyan]{md}[/]\n  json: [cyan]{js}[/]")


@app.command()
def doctor(profile: Optional[str] = ProfileOpt) -> None:
    """Setup check: external OSINT tools, and which sources can run in this profile (keys, allowed)."""
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
    try:
        s = config.load(profile)
    except config.ConfigError as e:
        console.print(f"\n[yellow]sources not checked: {e}[/]")
        return
    t = Table(title=f"Sources ({s.profile})")
    for col in ("Source", "Handles", "Allowed", "Ready"):
        t.add_column(col)
    for p in ALL_PLUGINS:
        allowed = s.source(p.name).get("allowed", False)
        missing_keys = [k for k in p.needs if not s.key(k)]
        ready = "[red]missing " + ", ".join(missing_keys) + "[/]" if missing_keys else "[green]yes[/]"
        if s.tools_mode == "fixtures" and isinstance(p, ToolPlugin):
            ready = "[cyan]fixtures[/]"
        t.add_row(p.name, ", ".join(p.kinds), "yes" if allowed else "[red]no[/]", ready)
    console.print(t)


_register_subcommands()

if __name__ == "__main__":
    app()
