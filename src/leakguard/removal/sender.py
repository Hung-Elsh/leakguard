"""Send a drafted request. lab: SMTP to Mailpit (never delivers). internet: the owner's Gmail (API)."""

from __future__ import annotations

import smtplib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from ..config import ConfigError, Settings
from ..scope import ScopeGuard


def load_draft(path: Path) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(path.read_bytes())


def send(settings: Settings, guard: ScopeGuard, msg: EmailMessage) -> str:
    how = settings.removal.get("sender")
    if how == "smtp":
        cfg = settings.removal["smtp"]
        guard.check_host(cfg["host"], "mail")              # lab: must be inside 192.168.1.248/29
        with smtplib.SMTP(cfg["host"], int(cfg.get("port", 25)), timeout=30) as s:
            refused = s.send_message(msg)
        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")
        return f"smtp {cfg['host']}:{cfg.get('port', 25)}"
    if how == "gmail":
        from ..mail.gmail_backend import GmailBackend
        gid = GmailBackend(settings, guard).send(msg)
        return f"gmail message {gid}"
    raise ConfigError(f"profile {settings.profile}: removal.sender must be smtp or gmail")
