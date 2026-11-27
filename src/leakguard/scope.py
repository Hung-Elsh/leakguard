"""Scope guard: decides which hosts a profile may contact.

lab:      every resolved address must be inside allowed_networks (127.0.0.0/8, 192.168.1.248/29).
internet: the host must belong to an allowed source in config/sources.json (or a profile broker).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from .config import Settings


class ScopeError(Exception):
    pass


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ScopeError(f"cannot resolve {host}: {e}") from e
    return [ipaddress.ip_address(i[4][0]) for i in infos]


def _host_matches(host: str, allowed: str) -> bool:
    host, allowed = host.lower().rstrip("."), allowed.lower().rstrip(".")
    return host == allowed or host.endswith("." + allowed)


class ScopeGuard:
    def __init__(self, settings: Settings):
        self.s = settings
        self.networks = [ipaddress.ip_network(n) for n in settings.allowed_networks]
        self.hosts_by_source: dict[str, list[str]] = {}
        for sid, src in settings.sources.items():
            if src.get("allowed") and src.get("type") in ("api", "mail"):
                self.hosts_by_source[sid] = list(src.get("hosts", []))
        # the owner's own mail servers, set up in the app (mail.yaml): exactly those, for the "mail" source
        for section in (settings.mail, (settings.removal or {}).get("smtp") or {}):
            if section.get("owner_configured") and section.get("host") and "mail" in self.hosts_by_source:
                self.hosts_by_source["mail"].append(section["host"])
        # broker search pages are allowed per broker entry in the profile
        broker_hosts = [urlsplit(b["search_url"]).hostname for b in settings.brokers if b.get("search_url")]
        self.hosts_by_source.setdefault("brokers", []).extend(h for h in broker_hosts if h)

    def check_url(self, url: str, source: str) -> None:
        """Raise ScopeError unless `source` may request `url` in this profile."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ScopeError(f"refused non-http url {url!r}")
        host = parts.hostname
        if self.s.is_lab:
            for addr in _resolve(host):
                if not any(addr in net for net in self.networks):
                    raise ScopeError(f"[lab] {host} -> {addr} is outside the lab scope")
            return
        if not self.s.source(source).get("allowed"):
            raise ScopeError(f"[internet] source {source!r} is not allowed in sources.json")
        if not any(_host_matches(host, h) for h in self.hosts_by_source.get(source, [])):
            raise ScopeError(f"[internet] {host} is not a listed host of source {source!r}")

    def check_host(self, host: str, source: str) -> None:
        """Same rules as check_url, for non-HTTP connections (IMAP, SMTP, Gmail client)."""
        self.check_url(f"https://{host}/", source)

    def check_tool(self, tool: str) -> None:
        """External tools may run only in the internet profile, and only if allowed."""
        if self.s.is_lab:
            raise ScopeError(f"[lab] {tool} contacts real websites; lab uses fixtures only")
        if not self.s.source(tool).get("allowed"):
            from . import custom_tools
            if not custom_tools.is_enabled(tool):         # your own tool runs only while switched on
                raise ScopeError(f"[internet] tool {tool!r} is not allowed in sources.json")
