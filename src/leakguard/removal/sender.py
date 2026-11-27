"""Send a drafted request. lab: SMTP to Mailpit (never delivers). internet: the owner's Gmail (API)."""

from __future__ import annotations

import smtplib
import ssl
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


def smtp_connection(cfg: dict, timeout: int = 30) -> smtplib.SMTP:
    """SMTP with the configured security: ssl (implicit TLS), starttls, or plain (lab Mailpit only)."""
    host, port, security = cfg["host"], int(cfg.get("port", 25)), cfg.get("security", "")
    if security == "ssl":
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
    s = smtplib.SMTP(host, port, timeout=timeout)
    if security == "starttls":
        s.starttls(context=ssl.create_default_context())
    return s


def send(settings: Settings, guard: ScopeGuard, msg: EmailMessage) -> str:
    how = settings.removal.get("sender")
    if how == "smtp":
        cfg = settings.removal["smtp"]
        guard.check_host(cfg["host"], "mail")              # lab: inside 192.168.1.248/29; internet: the owner's server
        user = cfg.get("user", "")
        want = parseaddr(msg["From"])[1].lower()
        if user and want != user.lower():                  # the server would refuse or rewrite the sender
            raise DraftError(f"this request must come from {want}, but your mail is connected as {user}. "
                             "Connect that address under Mail, or send the draft yourself from it.")
        with smtp_connection(cfg) as s:
            if user:
                s.login(user, settings.key(cfg["password_secret"]) if cfg.get("password_secret") else "")
            refused = s.send_message(msg)
        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")
        return f"smtp {cfg['host']}:{cfg.get('port', 25)}"
    if how == "gmail":
        from ..mail.gmail_backend import GmailBackend
        gm = GmailBackend(settings, guard)
        want, can = parseaddr(msg["From"])[1].lower(), gm.send_as()
        if want not in can:                # Gmail would quietly send it from the signed-in account instead
            raise DraftError(f"this request must come from {want}, but Gmail is signed in as {', '.join(sorted(can))}. "
                             f"Run `leakguard keys forget GMAIL_TOKEN`, then run again and sign in as {want}, or send the draft "
                             "yourself from it.")
        gid = gm.send(msg)
        return f"gmail message {gid} from {want}"
    raise ConfigError(f"profile {settings.profile}: removal.sender must be smtp or gmail")
