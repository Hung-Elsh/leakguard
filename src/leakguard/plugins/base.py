"""Plugin interface. A plugin takes one claimed identity and returns findings + candidates."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Settings
from ..models import Identity, PluginResult
from ..net import Http
from ..scope import ScopeGuard


@dataclass
class Context:
    settings: Settings
    guard: ScopeGuard
    http: Http

    @property
    def keyword(self) -> str:
        return self.settings.keyword


class SkipSource(Exception):
    """The source cannot run right now (missing key, not installed...). Not a failure of the data."""


class Plugin:
    name: str = ""
    kinds: tuple[str, ...] = ()        # identity kinds handled: keyword | email | username
    needs: tuple[str, ...] = ()        # required API keys

    def check(self, ctx: Context) -> None:
        missing = [k for k in self.needs if not ctx.settings.key(k)]
        if missing:
            raise SkipSource(f"missing key(s): {', '.join(missing)}")

    def run(self, ctx: Context, ident: Identity) -> PluginResult:
        raise NotImplementedError
