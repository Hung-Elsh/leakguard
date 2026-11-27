"""What the desktop app (and parts of the CLI) do, without printing or prompting.

Every safety rule stays in the core modules this calls: the claim gate in engine, `confirm` in the removal
tracker, the scope guard everywhere, password masking in models.scrub. Nothing here can skip them.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import config, engine, identities, keystore, monitor
from .paths import CONFIG
from .plugins import ALL_PLUGINS
from .plugins.tools import ToolPlugin
from .runner import ToolError, find_binary
from .store import Store

CHECK_KINDS = ("quick", "full")         # "mail" arrives with the mail page (G3)
WAITING_STATES = ("requested", "acknowledged", "removed")
YOUR_TURN_STATES = ("planned", "drafted")


# ---- profile and identity --------------------------------------------------------------------------
def has_identity(profile: str = "internet") -> bool:
    try:
        config.read_identity(profile)
        return True
    except config.ConfigError:
        return False


def open_profile(profile: str | None = None) -> tuple[config.Settings, Store]:
    """Settings and a Store for this thread (sqlite connections are per thread)."""
    s = config.load(profile)
    return s, Store(s.db_path)


def setup_identity(keyword: str, emails: list[str], usernames: list[str] | None = None,
                   full_name: str = "") -> Path:
    """Save the owner's identity (internet profile). Raises config.ConfigError with a readable reason."""
    return config.write_identity({"keyword": keyword, "emails": emails, "usernames": usernames or [],
                                  "owner": {"full_name": full_name.strip(), "country": ""}})


# ---- the To do queue ---------------------------------------------------------------------------------
@dataclass
class Todo:
    candidates: list = field(default_factory=list)      # identities a check proposed: "Is this you?"
    review: list = field(default_factory=list)          # new findings without a verdict: "What should we do?"
    your_turn: list = field(default_factory=list)       # removal actions only the owner can move on
    waiting: list = field(default_factory=list)         # actions waiting on a site, soonest follow-up first

    @property
    def count(self) -> int:
        """What needs the owner, counted as the questions To do shows (waiting items don't count)."""
        return len(self.candidates) + len(review_groups(self.review)) + len(self.your_turn)


def todo(settings: config.Settings, store: Store) -> Todo:
    from .removal import tracker
    tracker.plan(settings, store)                       # local only: the catalog is not downloaded here
    t = Todo(candidates=store.identities("candidate"))
    sev = {"high": 0, "medium": 1, "low": 2}
    t.review = sorted((f for f in store.findings() if f["reviewed"] is None and f["status"] != "gone"
                       and f["severity"] != "info" and (f["disposition"] or "open") == "open"),
                      key=lambda f: sev.get(f["severity"], 3))
    actions = store.actions()
    t.your_turn = [a for a in actions if a["state"] in YOUR_TURN_STATES]
    t.waiting = sorted((a for a in actions if a["state"] in WAITING_STATES), key=lambda a: a["next_check"] or "~")
    return t


def decide_identities(settings: config.Settings, store: Store, tokens: list[str], yours: bool,
                      proof: str = "") -> list[identities.Decision]:
    """'Yes, it's me' / 'No' for one or many identities (IDs or values; an unknown value is added)."""
    status = "claimed" if yours else "rejected"
    return [identities.decide(settings, store, str(t), status, proof or "owner (desktop app)") for t in tokens]


# ---- checks ----------------------------------------------------------------------------------------
@dataclass
class CheckResult:
    """What a check changed, in counts the app can put into words."""
    new: int = 0                     # new exposures (one per page/record, not per tool)
    serious: int = 0                 # ...of which serious
    gone: int = 0
    candidates: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    cancelled: bool = False


def run_check(settings: config.Settings, store: Store, kind: str, progress: engine.Progress | None = None,
              cancel: threading.Event | None = None, identity: str | None = None) -> CheckResult:
    """quick / full: discovery + due removal re-checks (monitor.run), or every source for one claimed address
    or username when `identity` is given (CLI: `scan --identity`)."""
    if kind not in ("quick", "full"):
        raise ValueError("kind must be quick or full")
    if identity:
        quick = [p.name for p in ALL_PLUGINS if p.name not in monitor.SLOW_TOOLS] if kind == "quick" else None
        r = engine.rescan(settings, store, quick, {identity}, progress=progress, cancel=cancel)
        return CheckResult(new=r.new_findings, gone=r.gone_findings, candidates=r.new_candidates,
                           problems=[f"{src} / {i}: {st}" for src, i, st in r.runs if st.startswith("error")],
                           cancelled=r.cancelled)
    res = monitor.run(settings, store, quick=kind == "quick", progress=progress, cancel=cancel)
    groups = [g for g in res.grouped_new() if g["severity"] != "info"]
    return CheckResult(new=len(groups), serious=sum(g["severity"] == "high" for g in groups), gone=len(res.gone),
                       candidates=res.candidates, problems=res.problems, cancelled=res.cancelled)


# ---- the Overview ------------------------------------------------------------------------------------
@dataclass
class Overview:
    gone: int
    total: int                        # exposures to clean up (open + gone)
    pct: int
    open_by_severity: dict
    needs_you: int
    waiting: int
    next_follow_up: str | None
    mail_blocked_7d: int
    mail_connected: bool
    last_check: str | None
    trend: list[dict]
    recent: list[tuple[str, str, object]]        # (timestamp, event, finding or action row), newest first
    keys_missing: int = 0                        # search services not connected yet
    tools_missing: int = 0                       # extra checks not installed (practice mode: none needed)


def overview(settings: config.Settings, store: Store, recent: int = 8) -> Overview:
    sc = monitor.scorecard(store)
    t = todo(settings, store)
    follow = [a["next_check"] for a in t.waiting if a["next_check"]]
    return Overview(gone=sc["gone"], total=sc["open"] + sc["gone"], pct=sc["cleaned_pct"],
                    open_by_severity=sc["open_by_severity"], needs_you=t.count, waiting=len(t.waiting),
                    next_follow_up=min(follow) if follow else None, mail_blocked_7d=sc["mail_blocked_7d"],
                    mail_connected=sc["mail_blocked_total"] > 0 or bool(settings.key("GMAIL_TOKEN"))
                    or bool(settings.key("MAIL_APP_PASSWORD")) or settings.is_lab,
                    last_check=sc["last_scan"], trend=sc["trend"], recent=recent_changes(store, recent),
                    keys_missing=sum(not settings.key(k) for k in SEARCH_KEYS),
                    tools_missing=0 if settings.is_lab else sum(not c.installed for c in tool_cards()))


def recent_changes(store: Store, limit: int = 8) -> list[tuple[str, str, object]]:
    """New exposures and removal progress, newest first (one entry per action and state)."""
    events: dict[tuple, tuple[str, int, str, object]] = {}
    for f in store.findings():
        if f["severity"] != "info" and (f["disposition"] or "open") in ("open", "protect") and f["first_seen"]:
            events[("f", f["id"])] = (f["first_seen"], 0, "found", f)
    for a in store.actions():
        for n, h in enumerate(json.loads(a["history"] or "[]")):
            if h["state"] in ("requested", "acknowledged", "removed", "verified", "done"):
                events[("a", a["id"], h["state"])] = (h["ts"], n, h["state"], a)   # latest entry per state
    # same second (e.g. submitted, then verified right away): the later history entry comes first
    ordered = sorted(events.values(), key=lambda e: (e[0], e[1]), reverse=True)
    return [(ts, kind, row) for ts, _, kind, row in ordered[:limit]]


def identity_form(profile: str = "internet") -> dict:
    """The saved identity, for editing in the About-you screen (empty when there is none yet)."""
    try:
        return config.read_identity(profile)
    except config.ConfigError:
        return {"keyword": "", "emails": [], "usernames": [], "owner": {}}


# ---- setup status ------------------------------------------------------------------------------------
@dataclass
class ToolStatus:
    name: str
    phase: int
    purpose: str
    install: str
    path: str | None


def tool_status() -> list[ToolStatus]:
    out = []
    for tool in json.loads((CONFIG / "tools.json").read_text())["tools"]:
        try:
            where = find_binary(*tool["detect"])
        except ToolError:
            where = None
        out.append(ToolStatus(tool["name"], tool["phase"], tool["purpose"], tool["install"],
                              str(where) if where else None))
    return out


@dataclass
class SourceStatus:
    name: str
    kinds: tuple[str, ...]
    allowed: bool
    missing_keys: list[str]
    fixtures: bool                    # lab: the tool's recorded output is used instead of running it

    @property
    def ready(self) -> bool:
        return self.allowed and not self.missing_keys


def source_status(settings: config.Settings) -> list[SourceStatus]:
    return [SourceStatus(p.name, p.kinds, bool(settings.source(p.name).get("allowed", False)),
                         [k for k in p.needs if not settings.key(k)],
                         settings.tools_mode == "fixtures" and isinstance(p, ToolPlugin))
            for p in ALL_PLUGINS]


# ---- keys (the values go to keystore; the database only records that a connection exists) ------------
@dataclass
class KeyStatus:
    name: str
    origin: str                       # keyring | file | environment | profile | '' (not set)
    added: str | None
    last_test: str | None
    last_result: str | None


def keys_status(settings: config.Settings, store: Store) -> list[KeyStatus]:
    from .mail import gmail_backend
    if gmail_backend.OLD_TOKEN.exists() and not settings.is_lab:
        gmail_backend.load_token()                   # moves a sign-in saved before the keyring into it
        store.set_connection(gmail_backend.TOKEN_NAME)
    conns = store.connections()
    return [KeyStatus(n, settings.key_origin(n), *(conns[n]["added"], conns[n]["last_test"], conns[n]["last_result"])
                      if n in conns else (None, None, None))
            for n in keystore.KNOWN]


def set_key(store: Store, name: str, value: str) -> str:
    """Save a secret; returns where it went (the system keyring or the private file)."""
    if name not in keystore.KNOWN:
        raise ValueError(f"unknown key {name!r}; known: {', '.join(keystore.KNOWN)}")
    st = keystore.store()
    st.set(name, value)
    store.set_connection(name)
    return st.where()


def forget_key(store: Store, name: str) -> bool:
    if name not in keystore.KNOWN:
        raise ValueError(f"unknown key {name!r}; known: {', '.join(keystore.KNOWN)}")
    store.forget_connection(name)
    return keystore.store().delete(name)


# ---- To do: grouped questions, answers and undo ------------------------------------------------------
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
URL_GROUPED = ("web_page", "paste", "code")      # one page: one question, whoever it mentions


@dataclass
class ReviewGroup:
    """One question in To do: the same site, page or leak found for several identities or by several tools."""
    key: tuple
    category: str
    severity: str
    rows: list

    @property
    def finding_ids(self) -> list[str]:
        return [r["id"] for r in self.rows]

    @property
    def identities(self) -> list[str]:
        return sorted({r["identity"] for r in self.rows})


def review_groups(findings) -> list[ReviewGroup]:
    from . import wording
    from .removal.catalog import site_key
    groups: dict[tuple, ReviewGroup] = {}
    for f in findings:
        cat = f["category"]
        if cat == "leak":                                # one removal request per address covers them all
            key = (cat, f["identity"])
        elif cat in URL_GROUPED and f["url"]:
            key = (cat, f["url"].lower().rstrip("/"))
        else:                                            # the same site however a tool spells it
            key = (cat, site_key(wording.site_of(f)) or (f["title"] or "").lower())
        g = groups.setdefault(key, ReviewGroup(key, cat, f["severity"], []))
        g.rows.append(f)
        if SEVERITY_RANK.get(f["severity"], 0) > SEVERITY_RANK.get(g.severity, 0):
            g.severity = f["severity"]
    return sorted(groups.values(), key=lambda g: (-SEVERITY_RANK.get(g.severity, 0), g.category, g.key))


def set_verdict(store: Store, finding_ids: list[str], verdict: str, note: str = "") -> list[tuple]:
    """Record the owner's answer; returns what was there before (for Undo)."""
    ids = list(finding_ids)
    before = [(r["id"], r["disposition"], r["note"], r["reviewed"]) for r in
              store.db.execute(f"SELECT id, disposition, note, reviewed FROM findings WHERE id IN "
                               f"({','.join('?' * len(ids))})", ids)] if ids else []
    store.mark(ids, verdict, note)
    return before


def undo_verdicts(store: Store, before: list[tuple]) -> None:
    for fid, disposition, note, reviewed in before:
        store.db.execute("UPDATE findings SET disposition=?, note=?, reviewed=? WHERE id=?",
                         (disposition, note, reviewed, fid))
    store.db.commit()


def undo_identities(settings: config.Settings, store: Store, before: list[tuple[int, str]]) -> None:
    """Put identities back to their earlier status (e.g. candidate), keeping the private identity file in step."""
    for ident_id, status in before:
        cur = store.get_identity(ident_id)
        store.decide(ident_id, status)
        if (cur.status == "claimed") != (status == "claimed"):
            identities._sync_identity_file(settings, cur.value, cur.kind, status == "claimed")


# ---- clean-up actions (shared with `leakguard remove set / add`) -------------------------------------
def record_progress(store: Store, action_id: int, state: str, note: str = ""):
    """Move an action on (done, skipped, requested, acknowledged, removed...) and schedule its next check."""
    from .removal import tracker
    a = store.action(action_id)
    if state == "done" and a["state"] in ("requested", "acknowledged"):
        state = "removed"                                # finished something already requested
    verifiable = a["finding_ids"] != "[]" and a["kind"] not in tracker.OWNER_CONFIRMED
    extra = {}
    if state in ("requested", "acknowledged") or (state in ("done", "removed") and verifiable):
        extra["next_check"] = tracker._due(a["method"])
    elif state in ("done", "removed", "skipped", "verified", "planned"):
        extra["next_check"] = None
    return store.set_action_state(action_id, state, note or "set by owner", **extra)


def set_contact(store: Store, action_id: int, contact: str):
    """A contact the owner checked: an email address makes it an email request, a page makes it manual."""
    from .removal.planner import TEMPLATES
    contact = contact.strip()
    if not contact:
        raise ValueError("empty contact")
    a = store.action(action_id)
    is_email = "@" in contact and "/" not in contact
    if not is_email and "://" not in contact:
        contact = "https://" + contact                   # "example.com/privacy" typed without the scheme
    method = "email" if is_email else ("manual" if a["method"] == "email" else a["method"])
    template = a["template"] or (TEMPLATES.get(a["kind"]) if method == "email" else None)
    store.db.execute("UPDATE actions SET contact=?, contact_verified=1, method=?, template=? WHERE id=?",
                     (contact, method, template, action_id))
    store.db.commit()
    return store.set_action_state(action_id, a["state"], f"contact set by owner: {contact}")


def add_site(settings: config.Settings, store: Store, target: str, identity: str, url: str = "", email: str = "",
             why: str = "", kind: str = "account_delete") -> tuple[int, bool]:
    """An action for something no scan found (an account the owner knows about)."""
    from .removal.catalog import Catalog, site_key
    e = Catalog(settings).lookup(target)
    contact, verified = ((email, True) if email else (url, True) if url
                         else ((e.email or e.url, e.verified) if e else ("", False)))
    method = "email" if email or (e and e.method == "email" and not url) else "manual"
    aid, created = store.upsert_action({
        "key": f"manual:{site_key(target)}", "kind": kind, "method": method, "target": e.name if e else target,
        "title": f"Delete / deactivate the account on {e.name if e else target}", "contact": contact or None,
        "contact_verified": verified, "template": "account_deletion" if method == "email" else None,
        "finding_ids": [], "identities": [identity],
        "steps": (e.steps if e else "") or "Find the site's account-deletion page or privacy contact."})
    store.set_action_state(aid, store.action(aid)["state"], f"added by owner: {why or 'known account'}")
    return aid, created


# ---- mail: connect, check, move -------------------------------------------------------------------------
@dataclass
class MailStatus:
    connected: bool
    how: str                     # app_password | google | practice | ''
    address: str = ""
    provider: str = ""


def mail_status(settings: config.Settings) -> MailStatus:
    from .mail import connection
    if settings.is_lab:
        return MailStatus(True, "practice", settings.mail.get("user", ""), "practice mailbox")
    cfg = connection.load() or {}
    main = next((s["value"] for s in settings.seeds if s.get("kind") == "email"), "")
    if cfg.get("backend") == "imap":
        name = connection.PROVIDERS.get(cfg.get("provider", ""), {}).get("name", cfg["imap"]["host"])
        return MailStatus(bool(settings.key(connection.SECRET)), "app_password", cfg["address"], name)
    if (cfg.get("backend") or settings.mail.get("backend")) == "gmail":
        return MailStatus(bool(settings.key("GMAIL_TOKEN")), "google", cfg.get("address") or main, "Gmail")
    return MailStatus(False, "")


@dataclass
class MailTest:
    ok: bool
    problem: str = ""            # wording.MAIL_PROBLEM key
    detail: str = ""


def test_mail(settings: config.Settings, address: str, password: str, imap: tuple, smtp: tuple,
              provider: str = "other") -> MailTest:
    """Log in to read (IMAP) and to send (SMTP) with the app password. Nothing is read, moved or sent."""
    import dataclasses
    import smtplib
    import ssl

    from imapclient import IMAPClient
    from imapclient.exceptions import LoginError

    from .mail import connection
    from .removal.sender import smtp_connection
    from .scope import ScopeError, ScopeGuard
    cfg = connection.app_password_config(address, imap, smtp, provider)
    mail, removal = connection.profile_mail(cfg)
    trial = dataclasses.replace(settings, mail=mail, removal={**(settings.removal or {}), **removal})
    try:
        guard = ScopeGuard(trial)
        guard.check_host(mail["host"], "mail")
        guard.check_host(removal["smtp"]["host"], "mail")
        sec = cfg["imap"]["security"]
        c = IMAPClient(mail["host"], port=mail["port"], ssl=sec == "ssl",
                       ssl_context=ssl.create_default_context(), timeout=30)
        try:
            if sec == "starttls":
                c.starttls(ssl.create_default_context())
            c.login(cfg["address"], password)
            c.select_folder("INBOX", readonly=True)
        finally:
            try:
                c.logout()
            except Exception:
                pass
        with smtp_connection(removal["smtp"]) as s:
            s.login(cfg["address"], password)
    except (LoginError, smtplib.SMTPAuthenticationError) as e:
        return MailTest(False, "refused", f"{type(e).__name__}: {e}")
    except ScopeError as e:
        return MailTest(False, "blocked", str(e))
    except (OSError, smtplib.SMTPException) as e:
        return MailTest(False, "offline", f"{type(e).__name__}: {e}")
    except Exception as e:                            # anything else: plain message, full detail kept
        return MailTest(False, "other", f"{type(e).__name__}: {e}")
    return MailTest(True)


def connect_mail(settings: config.Settings, store: Store, address: str, password: str, imap: tuple, smtp: tuple,
                 provider: str = "other") -> MailTest:
    """Test, then save: the app password to the keyring, the servers to mail.yaml."""
    from .mail import connection
    password = password.replace(" ", "").strip()      # app passwords are shown in groups of four
    result = test_mail(settings, address, password, imap, smtp, provider)
    if result.ok:
        keystore.store().set(connection.SECRET, password)
        connection.save(connection.app_password_config(address, imap, smtp, provider))
        store.set_connection(connection.SECRET, "ok")
    return result


def connect_google(store: Store, client_secret: Path, address: str) -> Path:
    """Advanced: the owner's own Google project. The sign-in itself happens on the next mail check."""
    import shutil
    from . import paths
    from .mail import connection, gmail_backend
    dest = paths.USER_CONFIG / "client_secret.json"
    if Path(client_secret).resolve() != dest.resolve():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(client_secret, dest)
    dest.chmod(0o600)
    gmail_backend.sign_out()                          # sign in again, with the account chosen now
    keystore.store().delete(connection.SECRET)
    connection.save({"backend": "gmail", "address": address.strip().lower()})
    store.set_connection(gmail_backend.TOKEN_NAME)
    return dest


def disconnect_mail(store: Store) -> None:
    from .mail import connection, gmail_backend
    connection.remove()
    for name in (connection.SECRET, gmail_backend.TOKEN_NAME):
        keystore.store().delete(name)
        store.forget_connection(name)


def check_mail(settings: config.Settings, store: Store, since_days: int | None = 90, limit: int = 500):
    """A dry run of the mail rules: what would be moved, and why. Nothing changes."""
    from .mail import service as mail_service
    return mail_service.run(settings, store, since_days=since_days, limit=limit)


def apply_mail(settings: config.Settings, store: Store, rows: list) -> dict[str, int]:
    """Move exactly the messages the owner saw in the preview (rows: (message, verdict), not 'keep')."""
    from collections import defaultdict
    from .mail.backend import make_backend
    from .scope import ScopeGuard
    by_action: dict[str, list] = defaultdict(list)
    for m, v in rows:
        if v.action != "keep":
            by_action[v.action].append(m.uid)
    backend = make_backend(settings, ScopeGuard(settings))
    try:
        moved = {action: backend.apply(action, uids) for action, uids in by_action.items()}
    finally:
        backend.close()
    store.log_mail(settings.profile, [(m.message_id, m.from_addr, m.subject, v.rule, v.action)
                                      for m, v in rows if v.action != "keep"], applied=True)
    return moved


# ---- search services: test a key before saving it -------------------------------------------------------
SEARCH_KEYS = ("HIBP_API_KEY", "INTELX_API_KEY", "BRAVE_API_KEY", "GITHUB_TOKEN")
KEY_SOURCE = {"HIBP_API_KEY": "hibp", "INTELX_API_KEY": "intelx", "BRAVE_API_KEY": "brave", "GITHUB_TOKEN": "github"}


def test_key(settings: config.Settings, name: str, value: str) -> MailTest:
    """One small request with the key (no search of the owner's data, except Brave's one-word query)."""
    import httpx

    from .models import redact
    from .net import Http
    from .scope import ScopeError, ScopeGuard
    source = KEY_SOURCE[name]
    base = settings.endpoints.get(source, "")
    value = value.strip()
    req = {"hibp": ("/subscription/status", {"hibp-api-key": value}, None),
           "intelx": ("/authenticate/info", {"x-key": value}, None),
           "brave": ("/web/search", {"X-Subscription-Token": value, "Accept": "application/json"},
                     {"q": "leakguard", "count": 1}),
           "github": ("/rate_limit", {"Authorization": f"Bearer {value}"}, None)}[source]
    try:
        with Http(settings, ScopeGuard(settings)).client(source, req[1], timeout=20) as c:
            r = c.get(base + req[0], params=req[2])
    except ScopeError as e:
        return MailTest(False, "blocked", str(e))
    except httpx.HTTPError as e:
        return MailTest(False, "offline", redact(f"{type(e).__name__}: {e}", [value]))
    if r.status_code == 200:
        return MailTest(True)
    kind = "refused" if r.status_code in (401, 403) else "busy" if r.status_code == 429 else "other"
    return MailTest(False, kind, redact(f"HTTP {r.status_code}: {r.text[:300]}", [value]))


def save_key(settings: config.Settings, store: Store, name: str, value: str) -> MailTest:
    """Test, then save to the keyring (the database only records that it works)."""
    result = test_key(settings, name, value)
    if result.ok:
        set_key(store, name, value)
        store.set_connection(name, "ok")
    return result


# ---- extra checks (tools) ---------------------------------------------------------------------------------
APP_TOOLS = ("holehe", "h8mail", "ghunt", "mosint", "socialscan", "sherlock", "maigret", "blackbird", "spiderfoot",
             "chromium")                       # the tools the checks and opt-out forms use


@dataclass
class ToolCard:
    name: str
    path: str | None
    pipx: str                                  # pinned spec for a one-click install ('' = by hand)
    install: str                               # the command to run by hand

    @property
    def installed(self) -> bool:
        return bool(self.path)


def tool_cards() -> list[ToolCard]:
    by_name = {t["name"]: t for t in json.loads((CONFIG / "tools.json").read_text())["tools"]}
    out = []
    for status in tool_status():
        if status.name in APP_TOOLS:
            t = by_name[status.name]
            out.append(ToolCard(status.name, status.path, t.get("pipx", ""), t["install"]))
    return sorted(out, key=lambda c: APP_TOOLS.index(c.name))


def pipx_path() -> str | None:
    import shutil
    return shutil.which("pipx") or (str(p) if (p := Path.home() / ".local" / "bin" / "pipx").exists() else None)


def install_tool(name: str, timeout: int = 1800) -> tuple[bool, str]:
    """One-click install of a pinned tool with pipx (user-level: no admin rights). Returns (ok, output)."""
    import subprocess
    import sys

    from .paths import ROOT
    card = next(c for c in tool_cards() if c.name == name)
    pipx = pipx_path()
    if not card.pipx or not pipx:
        return False, "pipx is not installed" if card.pipx else "no one-click install for this tool"
    cmd = [pipx, "install", "--python", "3.12", "--fetch-missing-python", card.pipx]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = f"$ {' '.join(cmd)}\n{p.stdout}\n{p.stderr}".strip()
    if p.returncode != 0 and "already seems to be installed" not in out:
        return False, out
    if name == "ghunt":                        # GHunt 2.3.4 needs its crash fixes
        fix = subprocess.run([sys.executable, str(ROOT / "scripts" / "patch_ghunt.py")], capture_output=True,
                             text=True, timeout=120)
        out += f"\n$ patch_ghunt.py\n{fix.stdout}{fix.stderr}"
    return True, out


def ghunt_signed_in() -> bool:
    return (Path.home() / ".malfrats" / "ghunt" / "creds.m").exists()


def ghunt_sign_in(code: str, timeout: int = 180) -> tuple[bool, str, str]:
    """Sign GHunt in with the code copied from the GHunt Companion extension (fed on stdin, never logged).
    Returns (ok, signed-in address, detail with every token line removed)."""
    import re
    import subprocess

    from .runner import find_binary
    code = code.strip()
    answers = ("y\n" if ghunt_signed_in() else "") + "2\n" + code + "\n"   # 'new session?' only if one exists
    p = subprocess.run([find_binary("ghunt"), "login"], input=answers, capture_output=True, text=True,
                       timeout=timeout)
    out = f"{p.stdout}\n{p.stderr}"
    who = (m.group(1).strip() if (m := re.search(r"Email\s*:\s*(\S+)", out)) else "")
    ok = "Cookies and osids generated" in out
    safe = "\n".join(line for line in out.splitlines()
                     if not re.search(r"token|=>|aas_et|oauth2_4", line, re.I) and code[:12] not in line)
    return ok, who, safe.strip()


# ---- Reports ---------------------------------------------------------------------------------------------
RUN_RANK = {"ok": 0, "skipped": 1, "partial": 2, "scope_blocked": 3, "error": 4}


@dataclass
class HealthRow:
    """How one search service did the last time it ran (worst result across the identities it checked)."""
    source: str
    when: str
    status: str
    runs: list                                   # source_runs rows of that scan (full logged detail)

    @property
    def worst(self):
        return max(self.runs, key=lambda r: RUN_RANK.get(r["status"], 0))


def check_health(store: Store) -> list[HealthRow]:
    rows = list(store.db.execute(
        "SELECT r.*, s.started AS scan_started, i.value AS identity FROM source_runs r "
        "JOIN scans s ON s.id = r.scan_id LEFT JOIN identities i ON i.id = r.identity_id "
        "WHERE r.scan_id = (SELECT max(r2.scan_id) FROM source_runs r2 WHERE r2.source = r.source) "
        "ORDER BY r.source"))
    by_source: dict[str, list] = {}
    for r in rows:
        by_source.setdefault(r["source"], []).append(r)
    out = [HealthRow(src, runs[0]["scan_started"] or "", max((r["status"] or "ok" for r in runs),
                                                              key=lambda s: RUN_RANK.get(s, 0)), runs)
           for src, runs in by_source.items()]
    return sorted(out, key=lambda h: (-RUN_RANK.get(h.status, 0), h.source))


def found_summary(store: Store) -> dict:
    """Counted exposures by kind and seriousness, still there vs gone, and the owner's answers."""
    from collections import Counter
    fs = [f for f in store.findings() if f["severity"] != "info"]
    by_kind: dict[str, Counter] = {}
    for f in fs:
        if (f["disposition"] or "open") in ("open", "protect"):
            by_kind.setdefault(f["category"], Counter())[f["severity"] if f["status"] != "gone" else "gone"] += 1
    return {"by_kind": by_kind, "answers": Counter(f["disposition"] or "open" for f in fs if f["reviewed"]),
            "unanswered": sum(1 for f in fs if f["reviewed"] is None)}


def cleanup_timeline(store: Store, limit: int = 200) -> list[tuple[str, object, dict]]:
    """Every clean-up step's history, newest first: (timestamp, action row, history entry)."""
    events = [(h["ts"], a, h) for a in store.actions() for h in json.loads(a["history"] or "[]")
              if h["note"] not in ("plan",)]
    return sorted(events, key=lambda e: e[0], reverse=True)[:limit]


def mail_summary(store: Store, weeks: int = 12) -> dict:
    """Moved messages per week (oldest first) and per reason."""
    from collections import Counter
    from datetime import date, timedelta
    rows = list(store.db.execute("SELECT ts, rule, action FROM mail_log WHERE applied=1"))
    monday = date.today() - timedelta(days=date.today().weekday())
    starts = [monday - timedelta(weeks=n) for n in range(weeks - 1, -1, -1)]
    per_week = Counter()
    for r in rows:
        d = date.fromisoformat(r["ts"][:10])
        per_week[d - timedelta(days=d.weekday())] += 1
    return {"weeks": [(s, per_week.get(s, 0)) for s in starts], "by_rule": Counter(r["rule"] for r in rows),
            "total": len(rows)}


def final_report(settings: config.Settings, store: Store, share: bool) -> str:
    from . import report
    return report.final_markdown(settings, store, share)


def save_report(settings: config.Settings, store: Store, share: bool, dest: Path) -> Path:
    """Write the final report to `dest` (mode 600). A shareable copy is refused if a private term is left."""
    import shutil
    from . import report
    made = report.write_final(settings, store, share)        # does the private-term check for shared copies
    dest = Path(dest)
    shutil.copyfile(made, dest)
    dest.chmod(0o600)
    return dest


# ---- automatic weekly check (user-level systemd timer; only when the owner turns it on) ------------------
TIMER = "leakguard-monitor.timer"


def _user_units() -> Path:
    return Path.home() / ".config" / "systemd" / "user"


def _systemctl(*args: str, timeout: int = 30):
    import shutil
    import subprocess
    exe = shutil.which("systemctl")
    if not exe:
        raise RuntimeError("systemctl is not available")
    return subprocess.run([exe, "--user", *args], capture_output=True, text=True, timeout=timeout)


def weekly_status() -> tuple[bool, str]:
    """(on, next run as an ISO date or '')."""
    import re
    try:
        enabled = _systemctl("is-enabled", TIMER).stdout.strip() == "enabled"
        nxt = _systemctl("show", TIMER, "-p", "NextElapseUSecRealtime", "--value").stdout if enabled else ""
    except (RuntimeError, OSError):
        return False, ""
    m = re.search(r"\d{4}-\d{2}-\d{2}", nxt or "")
    return enabled, m.group(0) if m else ""


def set_weekly(profile: str, on: bool) -> tuple[bool, str]:
    """Turn the weekly check on (write the user units, enable the timer) or off (disable it; files stay).
    Returns (ok, detail)."""
    units = _user_units()
    if on:
        units.mkdir(parents=True, exist_ok=True)
        for name, text in monitor.schedule_files(profile, "weekly").items():
            (units / name).write_text(text)
        steps = [("daemon-reload",), ("enable", "--now", TIMER)]
    else:
        steps = [("disable", "--now", TIMER)]
    out = []
    for step in steps:
        try:
            p = _systemctl(*step)
        except (RuntimeError, OSError) as e:
            return False, str(e)
        out.append(f"$ systemctl --user {' '.join(step)}\n{p.stdout}{p.stderr}".strip())
        if p.returncode != 0:
            return False, "\n".join(out)
    return True, "\n".join(out)
