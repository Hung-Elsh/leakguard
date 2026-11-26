"""Mail backend interface. Every action is reversible: messages are moved/labelled, never expunged for good."""

from __future__ import annotations

from ..config import ConfigError, Settings
from ..scope import ScopeGuard
from .message import MailMessage
from .rules import OwnerLists


class MailBackend:
    name = ""
    supports_filters = False

    def fetch(self, folder: str, since_days: int | None, limit: int) -> list[MailMessage]:
        raise NotImplementedError

    def known_correspondents(self) -> set[str]:
        """Addresses the owner has written to (sent mail). Empty if the backend cannot tell."""
        return set()

    def apply(self, action: str, uids: list[str]) -> int:
        """Move/label messages for one action. Returns how many were changed."""
        raise NotImplementedError

    def sync_filters(self, lists: OwnerLists, apply: bool) -> list[str]:
        """Server-side filters for the owner's blocklist. Returns a description of the changes."""
        return []

    def close(self) -> None:
        pass


def make_backend(settings: Settings, guard: ScopeGuard) -> MailBackend:
    cfg = settings.mail
    kind = cfg.get("backend")
    if kind == "imap":
        from .imap_backend import ImapBackend
        return ImapBackend(settings, guard)
    if kind == "gmail":
        from .gmail_backend import GmailBackend
        return GmailBackend(settings, guard)
    raise ConfigError(f"profile {settings.profile}: mail.backend must be imap or gmail")
