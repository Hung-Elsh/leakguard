"""Load a Google Takeout .mbox into the lab owner-copy mailbox (lab profile only).

The real Gmail account is never contacted. Gmail's own labels stay in each message as X-Gmail-Labels,
so `block --owner-copy` can compare LeakGuard's verdicts with what Gmail decided.
"""

from __future__ import annotations

import mailbox
import ssl
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from imapclient import IMAPClient

from ..config import ConfigError, Settings
from ..scope import ScopeGuard
from .imap_backend import empty_mailbox
from .message import gmail_labels


def owner_copy_settings(settings: Settings) -> Settings:
    """The lab settings, with the mailbox switched to the owner-copy account."""
    if not settings.is_lab:
        raise ConfigError("the owner copy exists only in the lab profile")
    oc = settings.mail.get("owner_copy")
    if not oc:
        raise ConfigError("lab profile has no mail.owner_copy section")
    mail = {k: v for k, v in settings.mail.items() if k not in ("user_env", "password_env", "owner_copy")}
    return replace(settings, mail={**mail, **oc})


@dataclass
class ImportResult:
    read: int = 0
    imported: int = 0
    skipped_label: int = 0
    skipped_old: int = 0
    skipped_bad: int = 0


def _labels(msg) -> set[str]:
    return gmail_labels(msg.get("X-Gmail-Labels", ""))


def _date(msg) -> datetime | None:
    try:
        d = parsedate_to_datetime(str(msg.get("Date")))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def import_mbox(settings: Settings, path: Path, labels: set[str], since_days: int | None,
                limit: int, reset: bool) -> ImportResult:
    s = owner_copy_settings(settings)
    cfg = s.mail
    ScopeGuard(s).check_host(cfg["host"], "mail")
    ctx = None
    if cfg.get("ssl"):
        ctx = ssl.create_default_context()
        if cfg.get("insecure_tls"):
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days) if since_days else None
    res = ImportResult()
    box = mailbox.mbox(str(path), create=False)
    picked: list[tuple[datetime | None, str]] = []      # (date, key): message bodies stay on disk
    for key, msg in box.iteritems():
        res.read += 1
        if labels and not (_labels(msg) & labels):
            res.skipped_label += 1
            continue
        d = _date(msg)
        if cutoff and (d is None or d < cutoff):
            res.skipped_old += 1
            continue
        picked.append((d, key))
    picked.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc))
    picked = picked[-limit:]                                     # newest `limit` messages

    with IMAPClient(cfg["host"], port=int(cfg["port"]), ssl=bool(cfg.get("ssl")), ssl_context=ctx, timeout=60) as c:
        c.login(cfg["user"], cfg["password"])
        if reset:
            empty_mailbox(c)
        for d, key in picked:
            try:
                raw = box.get_bytes(key)
            except (KeyError, ValueError, OSError):
                res.skipped_bad += 1
                continue
            c.append("INBOX", raw, flags=(), msg_time=d)
            res.imported += 1
    return res
