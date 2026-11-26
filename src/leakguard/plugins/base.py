"""Plugin interface. A plugin takes one claimed identity and returns findings + candidates."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config import Settings
from ..models import Identity, PluginResult
from ..net import Http
from ..scope import ScopeGuard


@dataclass
class Context:
    settings: Settings
    guard: ScopeGuard
    http: Http
    owned: set[str] = field(default_factory=set)      # claimed identity values (emails, usernames, keyword)

    @property
    def keyword(self) -> str:
        return self.settings.keyword

    def match_level(self, text: str) -> str:
        """How strongly a public text points at the owner:
        email   - one of the owner's claimed emails appears        (a real exposure)
        exact   - the keyword or a claimed username as a whole word
        variant - only a look-alike (keyword glued to other letters/digits)
        none    - the keyword does not appear (search engines also return similar pages)"""
        low = (text or "").lower()
        if any("@" in v and v in low for v in self.owned):
            return "email"
        names = {v for v in self.owned if "@" not in v} | {self.keyword}
        if any(re.search(rf"(?<![a-z0-9]){re.escape(v)}(?![a-z0-9])", low) for v in names):
            return "exact"
        return "variant" if self.keyword in low else "none"


class SkipSource(Exception):
    """The source cannot run right now (missing key, not installed...). Not a failure of the data."""


class Plugin:
    name: str = ""
    kinds: tuple[str, ...] = ()        # identity kinds handled: keyword | email | username
    needs: tuple[str, ...] = ()        # required API keys

    def check(self, ctx: Context) -> None:
        if not ctx.settings.is_lab and not ctx.settings.source(self.name).get("allowed"):
            raise SkipSource("disabled in config/sources.json (allowed: false)")
        missing = [k for k in self.needs if not ctx.settings.key(k)]
        if missing:
            raise SkipSource(f"missing key(s): {', '.join(missing)}")

    def run(self, ctx: Context, ident: Identity) -> PluginResult:
        raise NotImplementedError
