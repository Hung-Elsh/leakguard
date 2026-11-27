"""IMAP backend (lab GreenMail; also usable for any IMAP mailbox). Moves mail to folders, never expunges."""

from __future__ import annotations

import os
import ssl
from datetime import date, timedelta

from imapclient import IMAPClient

from ..config import ConfigError, Settings
from ..scope import ScopeGuard
from .backend import MailBackend
from .message import MailMessage, parse

FOLDERS = {"spam": "Junk", "trash": "Trash", "archive": "Archive", "label": ("LeakGuard", "Review")}


def empty_mailbox(c: IMAPClient) -> None:
    """Lab helper: delete every message and every folder except INBOX. Children go before parents;
    container folders (\\Noselect) cannot be opened, only deleted."""
    folders = sorted(c.list_folders(), key=lambda f: f[2].count((f[1] or b".").decode()), reverse=True)
    for flags, _delim, name in folders:
        if b"\\Noselect" not in flags:
            c.select_folder(name)
            uids = c.search(["ALL"])
            if uids:
                c.add_flags(uids, [b"\\Deleted"])
                c.expunge()
            c.close_folder()
        if name.upper() != "INBOX":
            c.delete_folder(name)


class ImapBackend(MailBackend):
    name = "imap"

    def __init__(self, settings: Settings, guard: ScopeGuard):
        cfg = settings.mail
        host, port = cfg["host"], int(cfg.get("port", 993))
        guard.check_host(host, "mail")
        user = os.environ.get(cfg.get("user_env", ""), "") or cfg.get("user", "")
        password = (settings.key(cfg["password_secret"]) if cfg.get("password_secret")     # app password (keyring)
                    else os.environ.get(cfg.get("password_env", ""), "") or cfg.get("password", ""))
        if not user:
            raise ConfigError("IMAP user not set (profile mail.user or the env var in mail.user_env)")
        ctx = None
        if cfg.get("ssl"):
            ctx = ssl.create_default_context()
            if cfg.get("insecure_tls"):          # lab only: self-signed GreenMail certificate
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        self.c = IMAPClient(host, port=port, ssl=bool(cfg.get("ssl")), ssl_context=ctx, timeout=30)
        self.c.login(user, password)
        self.delim = (self.c.list_folders()[0][1] or b".").decode() if self.c.list_folders() else "."
        self._selected = "INBOX"            # apply() without a fetch first (the app moves what it previewed)

    def _folder(self, action: str) -> str:
        f = FOLDERS[action]
        name = self.delim.join(f) if isinstance(f, tuple) else f
        if not self.c.folder_exists(name):
            self.c.create_folder(name)
        return name

    def fetch(self, folder, since_days, limit):
        self.c.select_folder(folder, readonly=True)
        crit = ["SINCE", date.today() - timedelta(days=since_days)] if since_days else ["ALL"]
        uids = sorted(self.c.search(crit))[-limit:]
        out = []
        for uid, data in self.c.fetch(uids, ["BODY.PEEK[]"]).items():   # PEEK: does not mark as read
            out.append(parse(str(uid), data[b"BODY[]"]))
        self._selected = folder
        return out

    def apply(self, action, uids):
        if action == "keep" or not uids:
            return 0
        target = self._folder(action)
        self.c.select_folder(self._selected)
        ids = [int(u) for u in uids]
        if self.c.has_capability("MOVE"):
            self.c.move(ids, target)
        else:
            self.c.copy(ids, target)
            self.c.add_flags(ids, [b"\\Deleted"])
            self.c.uid_expunge(ids)          # removes only the copied originals
        return len(ids)

    def close(self):
        try:
            self.c.logout()
        except Exception:   # noqa: BLE001 - closing a dead connection is not an error worth raising
            pass
