"""The owner's mail connection, set up in the desktop app (internet profile).

Two ways:
- app password (IMAP to read and move mail, SMTP to send removal requests): Gmail, Yahoo, iCloud presets, or
  the owner's own servers;
- the owner's own Google project (Gmail API, OAuth): the advanced path the CLI has used so far.

The choice lives in ~/.config/leakguard/mail.yaml (mode 600, no secrets); the app password is in the secret
store as MAIL_APP_PASSWORD. Without mail.yaml the profile's own mail settings apply (unchanged behaviour).
The scope guard allows exactly the servers configured here, nothing else.
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

import yaml

from .. import paths

SECRET = "MAIL_APP_PASSWORD"

# Presets: (host, port, security). security: ssl (implicit TLS) | starttls
PROVIDERS = {
    "gmail": {"name": "Gmail", "domains": ("gmail.com", "googlemail.com"),
              "imap": ("imap.gmail.com", 993, "ssl"), "smtp": ("smtp.gmail.com", 465, "ssl"),
              "page": "https://myaccount.google.com/apppasswords"},
    "yahoo": {"name": "Yahoo Mail", "domains": ("yahoo.com", "ymail.com", "rocketmail.com"),
              "imap": ("imap.mail.yahoo.com", 993, "ssl"), "smtp": ("smtp.mail.yahoo.com", 465, "ssl"),
              "page": "https://login.yahoo.com/account/security"},
    "icloud": {"name": "iCloud Mail", "domains": ("icloud.com", "me.com", "mac.com"),
               "imap": ("imap.mail.me.com", 993, "ssl"), "smtp": ("smtp.mail.me.com", 587, "starttls"),
               "page": "https://account.apple.com/account/manage"},
}
# Microsoft turned off app passwords for these consumer mailboxes: they need a sign-in LeakGuard doesn't have.
UNSUPPORTED = ("outlook.com", "hotmail.com", "live.com", "msn.com")


def path() -> Path:
    return paths.USER_CONFIG / "mail.yaml"


def provider_for(address: str) -> str | None:
    domain = address.rsplit("@", 1)[-1].lower().strip()
    return next((k for k, p in PROVIDERS.items() if domain in p["domains"]), None)


def unsupported(address: str) -> bool:
    return address.rsplit("@", 1)[-1].lower().strip() in UNSUPPORTED


def load() -> dict | None:
    f = path()
    return (yaml.safe_load(f.read_text()) or None) if f.exists() else None


def save(cfg: dict) -> Path:
    f = path()
    f.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(f.parent, 0o700)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write("# LeakGuard mail connection (written by the app). No passwords here: they are in the keyring.\n")
        yaml.safe_dump(cfg, out, sort_keys=False)
    return f


def remove() -> bool:
    f = path()
    if f.exists():
        f.unlink()
        return True
    return False


def app_password_config(address: str, imap: tuple, smtp: tuple, provider: str = "other") -> dict:
    return {"backend": "imap", "address": address.strip().lower(), "provider": provider,
            "imap": {"host": imap[0], "port": int(imap[1]), "security": imap[2]},
            "smtp": {"host": smtp[0], "port": int(smtp[1]), "security": smtp[2]}}


def profile_mail(cfg: dict) -> tuple[dict, dict]:
    """The profile's `mail` and `removal` sections for this connection."""
    if cfg.get("backend") == "gmail":
        return {"backend": "gmail", "address": cfg.get("address", "")}, {"sender": "gmail"}
    i, s = cfg["imap"], cfg["smtp"]
    mail = {"backend": "imap", "host": i["host"], "port": i["port"], "ssl": i.get("security", "ssl") == "ssl",
            "user": cfg["address"], "password_secret": SECRET, "owner_configured": True}
    smtp = {"host": s["host"], "port": s["port"], "security": s.get("security", "ssl"), "user": cfg["address"],
            "password_secret": SECRET, "owner_configured": True}
    return mail, {"sender": "smtp", "smtp": smtp}


def apply_to_profile(prof: dict) -> dict:
    """Overlay the owner's mail connection (if any) on the internet profile."""
    cfg = load()
    if not cfg:
        return prof
    prof = deepcopy(prof)
    mail, removal = profile_mail(cfg)
    prof["mail"] = mail
    prof["removal"] = {**(prof.get("removal") or {}), **removal}
    return prof
