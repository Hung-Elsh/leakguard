"""Send a drafted request. lab: SMTP to Mailpit (never delivers). internet: the owner's Gmail (API)."""

from __future__ import annotations

import smtplib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

from ..config import ConfigError, Settings
from ..scope import ScopeGuard
from .drafts import DraftError


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
        from ..mail.gmail_backend import TOKEN, GmailBackend
        gm = GmailBackend(settings, guard)
        want, can = parseaddr(msg["From"])[1].lower(), gm.send_as()
        if want not in can:                # Gmail would quietly send it from the signed-in account instead
            raise DraftError(f"this request must come from {want}, but Gmail is signed in as {', '.join(sorted(can))}. "
                             f"Delete {TOKEN} and run again to sign in as {want}, or send the draft yourself from it.")
        gid = gm.send(msg)
        return f"gmail message {gid} from {want}"
    raise ConfigError(f"profile {settings.profile}: removal.sender must be smtp or gmail")
