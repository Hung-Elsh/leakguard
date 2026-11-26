"""HTTP client with the scope guard on every request (redirects included) and per-host rate limits."""

from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

import httpx

from . import __version__
from .config import Settings
from .scope import ScopeGuard

USER_AGENT = f"leakguard/{__version__} (personal exposure cleanup)"


class Http:
    def __init__(self, settings: Settings, guard: ScopeGuard):
        self.s, self.guard = settings, guard
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def _wait(self, host: str, source: str) -> None:
        per_min = self.s.source(source).get("rate_per_min") or 30
        gap = 0 if self.s.is_lab else 60.0 / per_min
        with self._lock:
            delay = self._last.get(host, 0) + gap - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._last[host] = time.monotonic()

    def client(self, source: str, headers: dict | None = None, timeout: float = 25) -> httpx.Client:
        def hook(request: httpx.Request) -> None:
            url = str(request.url)
            self.guard.check_url(url, source)          # raises ScopeError -> request never sent
            self._wait(urlsplit(url).hostname or "", source)

        return httpx.Client(
            headers={"User-Agent": USER_AGENT, **(headers or {})},
            timeout=timeout,
            follow_redirects=True,
            event_hooks={"request": [hook]},
            trust_env=False,
        )
