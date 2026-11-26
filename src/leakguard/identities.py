"""Claim / reject by ID or by value. A value with no exact match is added: claimed (claim) or rejected (reject).

In the internet profile, claimed values are also written to the private identity file (so they stay claimed),
and rejecting a value declared there removes it from the file (otherwise the next scan would re-claim it).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config
from .config import EMAIL_RE, USERNAME_RE, ConfigError, Settings
from .models import Identity
from .store import Store


@dataclass
class Decision:
    identity: Identity
    created: bool          # the value did not exist and was added


def _kind(value: str) -> str:
    v = value.strip().lower()
    if "@" in v and EMAIL_RE.match(v):
        return "email"
    if USERNAME_RE.match(v.lstrip("@")):
        return "username"
    raise ConfigError(f"{value!r} is neither an identity ID, an email address nor a username")


def _sync_identity_file(settings: Settings, value: str, kind: str, claimed: bool) -> None:
    """Keep ~/.config/leakguard/identities.yaml in step with the owner's decisions (internet profile only)."""
    if settings.is_lab:
        return
    ident = config.read_identity("internet")
    field = "emails" if kind == "email" else "usernames"
    values = ident[field]
    if claimed and value not in values:
        values.append(value)
    elif not claimed and value in values:
        if field == "emails" and len(values) == 1:
            raise ConfigError(f"{value} is your only declared email; change it with `leakguard init` instead")
        values.remove(value)
    else:
        return
    config.write_identity(ident)


def decide(settings: Settings, store: Store, token: str, status: str, proof: str = "") -> Decision:
    """status: 'claimed' or 'rejected'. token: an identity ID or a value (exact match, else added)."""
    token = token.strip()
    if token.isdigit():
        ident = store.decide(int(token), status, proof)
        _sync_identity_file(settings, ident.value, ident.kind, status == "claimed")
        return Decision(ident, False)
    value = token.lower().lstrip("@") if "@" not in token.lstrip("@") else token.lower()
    kind = _kind(value)
    match = [i for i in store.identities() if i.value == value and i.kind == kind]
    if match:
        ident = store.decide(match[0].id, status, proof)
        created = False
    else:
        origin = "owner (claimed by value)" if status == "claimed" else "owner (rejected by value)"
        ident = store.add_identity(value, kind, status, origin, proof)
        created = True
    _sync_identity_file(settings, ident.value, ident.kind, status == "claimed")
    return Decision(ident, created)
