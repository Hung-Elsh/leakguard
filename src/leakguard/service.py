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


def overview(settings: config.Settings, store: Store, recent: int = 8) -> Overview:
    sc = monitor.scorecard(store)
    t = todo(settings, store)
    follow = [a["next_check"] for a in t.waiting if a["next_check"]]
    return Overview(gone=sc["gone"], total=sc["open"] + sc["gone"], pct=sc["cleaned_pct"],
                    open_by_severity=sc["open_by_severity"], needs_you=t.count, waiting=len(t.waiting),
                    next_follow_up=min(follow) if follow else None, mail_blocked_7d=sc["mail_blocked_7d"],
                    mail_connected=sc["mail_blocked_total"] > 0 or bool(settings.key("GMAIL_TOKEN"))
                    or bool(settings.key("MAIL_APP_PASSWORD")) or settings.is_lab,
                    last_check=sc["last_scan"], trend=sc["trend"], recent=recent_changes(store, recent))


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
