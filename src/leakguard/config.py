"""Load the profile, identities and source catalogue."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from . import keystore
from .paths import CONFIG, DATA, LAB_IDENTITY, ROOT, USER_IDENTITY

PROFILES = ("lab", "internet")


class ConfigError(Exception):
    pass


KEYWORD_RE = re.compile(r"^[a-z0-9._-]{4,64}$")
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{2,64}$")


def identity_path(profile: str) -> Path:
    """lab: the fictional identity in the repo. internet: the owner's private file (outside the repo)."""
    return LAB_IDENTITY if profile == "lab" else USER_IDENTITY


def validate_identity(ident: dict) -> dict:
    """Normalise and check an identity document. Raises ConfigError."""
    keyword = str(ident.get("keyword") or "").strip().lower()
    if not KEYWORD_RE.match(keyword):
        raise ConfigError("keyword must be 4-64 characters: letters, digits, . _ -")
    emails = [str(e).strip().lower() for e in ident.get("emails") or [] if str(e).strip()]
    bad = [e for e in emails if not EMAIL_RE.match(e)]
    if bad:
        raise ConfigError(f"invalid email(s): {', '.join(bad)}")
    users = [str(u).strip().lower().lstrip("@") for u in ident.get("usernames") or [] if str(u).strip()]
    bad = [u for u in users if not USERNAME_RE.match(u)]
    if bad:
        raise ConfigError(f"invalid username(s): {', '.join(bad)}")
    if not emails:
        raise ConfigError("at least one email is required")
    return {"keyword": keyword, "emails": emails, "usernames": users, "owner": ident.get("owner") or {}}


def read_identity(profile: str) -> dict:
    path = identity_path(profile)
    if not path.exists():
        raise ConfigError(f"no identity for profile {profile!r} at {path}. Run: leakguard init")
    return validate_identity(yaml.safe_load(path.read_text()) or {})


def write_identity(ident: dict) -> Path:
    """Write the owner's identity (internet profile) with owner-only permissions."""
    ident = validate_identity(ident)
    USER_IDENTITY.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(USER_IDENTITY.parent, 0o700)
    fd = os.open(USER_IDENTITY, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# LeakGuard owner identity. Private: never copy this into the repository.\n")
        yaml.safe_dump(ident, f, sort_keys=False, allow_unicode=True)
    os.chmod(USER_IDENTITY, 0o600)
    return USER_IDENTITY


def _expand_env(value: Any) -> Any:
    """Replace ${VAR} in strings with environment values (empty if unset)."""
    if isinstance(value, str):
        return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass
class Settings:
    profile: str
    keyword: str
    seeds: list[dict]
    owner: dict
    endpoints: dict[str, str]
    brokers: list[dict]
    tools_mode: str                      # "fixtures" (lab) or "run" (internet)
    fixtures_dir: Path | None
    allowed_networks: list[str]          # lab only
    sources: dict[str, dict]
    mail: dict = field(default_factory=dict)
    removal: dict = field(default_factory=dict)
    keys: dict[str, str] = field(default_factory=dict)

    @property
    def db_path(self) -> Path:
        return DATA / f"{self.profile}.sqlite"

    @property
    def is_lab(self) -> bool:
        return self.profile == "lab"

    def key(self, name: str) -> str:
        """A secret: profile-defined (lab mocks) first, then the environment (and a developer's .env), then the
        secret store (system keyring, or the private fallback file). The lab never reads the owner's store."""
        value = self.keys.get(name) or os.environ.get(name, "")
        if not value and not self.is_lab:
            value = keystore.store().get(name)
        return value

    def key_origin(self, name: str) -> str:
        """Where a secret comes from: profile, environment, keyring, file, or '' (not set)."""
        if self.keys.get(name):
            return "profile"
        if os.environ.get(name):
            return "environment"
        if not self.is_lab and keystore.store().get(name):
            return keystore.store().backend
        return ""

    def secret_values(self) -> list[str]:
        """Every configured secret value (and the refresh token inside the Gmail sign-in), so messages and logs
        can be scrubbed of them."""
        out = []
        for n in {*keystore.KNOWN, *self.keys}:
            v = self.key(n)
            if n == "GMAIL_TOKEN" and v:
                try:
                    v = json.loads(v).get("refresh_token", "")
                except ValueError:
                    pass
            if v and len(v) >= 6:
                out.append(v)
        return out

    def source(self, source_id: str) -> dict:
        return self.sources.get(source_id, {})


def load(profile: str | None = None) -> Settings:
    load_dotenv(ROOT / ".env")
    profile = profile or os.environ.get("LEAKGUARD_PROFILE", "lab")
    if profile not in PROFILES:
        raise ConfigError(f"unknown profile {profile!r}; use one of {PROFILES}")

    prof = _expand_env(yaml.safe_load((CONFIG / "profiles" / f"{profile}.yaml").read_text()))
    ident = read_identity(profile)
    sources = {s["id"]: s for s in json.loads((CONFIG / "sources.json").read_text())["sources"]}
    seeds = ([{"value": e, "kind": "email", "proof": "owner-declared (leakguard init)"} for e in ident["emails"]]
             + [{"value": u, "kind": "username", "proof": "owner-declared (leakguard init)"} for u in ident["usernames"]])

    tools_mode = prof.get("tools_mode", "run")
    if profile == "lab" and tools_mode != "fixtures":
        raise ConfigError("lab profile must use tools_mode: fixtures (the tools contact real websites)")

    fixtures = prof.get("fixtures_dir")
    return Settings(
        profile=profile,
        keyword=ident["keyword"],
        seeds=seeds,
        owner=ident["owner"],
        endpoints={k: v.rstrip("/") for k, v in (prof.get("endpoints") or {}).items() if v},
        brokers=prof.get("brokers") or [],
        tools_mode=tools_mode,
        fixtures_dir=(ROOT / fixtures) if fixtures else None,
        allowed_networks=prof.get("allowed_networks") or [],
        sources=sources,
        mail=prof.get("mail") or {},
        removal=prof.get("removal") or {},
        keys=prof.get("keys") or {},
    )
