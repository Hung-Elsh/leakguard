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

CHECK_KINDS = ("quick", "full", "mail")
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
        """What needs the owner (waiting items don't)."""
        return len(self.candidates) + len(self.review) + len(self.your_turn)


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


def set_verdict(store: Store, finding_ids: list[str], verdict: str, note: str = "") -> list:
    return store.mark(list(finding_ids), verdict, note)


# ---- checks ----------------------------------------------------------------------------------------
def run_check(settings: config.Settings, store: Store, kind: str, progress: engine.Progress | None = None,
              cancel: threading.Event | None = None):
    """quick / full: discovery + due removal re-checks (monitor.run). mail: a dry run of the mail rules."""
    if kind not in CHECK_KINDS:
        raise ValueError(f"kind must be one of {CHECK_KINDS}")
    if kind == "mail":
        from .mail import service as mail_service
        return mail_service.run(settings, store)        # dry run: nothing is moved
    return monitor.run(settings, store, quick=kind == "quick", progress=progress, cancel=cancel)


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
