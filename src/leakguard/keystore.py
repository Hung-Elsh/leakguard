"""Secrets: API keys, the mail app password and the Gmail sign-in.

They live in the system keyring (Secret Service: GNOME Keyring, KWallet), which is encrypted on disk and unlocked
when the owner logs in, so scheduled checks still work without an extra password. If no keyring is running (a
minimal desktop, a server), they fall back to a private file (~/.config/leakguard/secrets.env, mode 600).
Secrets never go in the database or reports: the database only records which connections exist (`connections`).

LEAKGUARD_SECRETS=file forces the file (tests, machines whose keyring should not be used).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from . import paths

SERVICE = "leakguard"
INDEX = "__names__"          # the keyring cannot list entries: keep the list of names (not values) beside them

# Every secret LeakGuard knows about. Redaction (Settings.secret_values) covers all of them.
KNOWN = ("HIBP_API_KEY", "INTELX_API_KEY", "BRAVE_API_KEY", "GITHUB_TOKEN", "GOOGLE_PSE_API_KEY",
         "MAIL_APP_PASSWORD", "GMAIL_TOKEN")


def _file() -> Path:
    return paths.USER_CONFIG / "secrets.env"


def _read_file() -> dict[str, str]:
    f = _file()
    if not f.exists():
        return {}
    out = {}
    for line in f.read_text().splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() and not name.lstrip().startswith("#"):
            out[name.strip()] = value.strip().replace("\\n", "\n")
    return out


def _write_file(values: dict[str, str]) -> None:
    f = _file()
    f.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(f.parent, 0o700)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write("# LeakGuard secrets (used only when no system keyring is available). Private.\n")
        for name, value in sorted(values.items()):
            out.write(f"{name}={value.replace(chr(10), chr(92) + 'n')}\n")
    os.chmod(f, 0o600)


def _keyring():
    """The keyring module if a real, working backend is available, else None."""
    if os.environ.get("LEAKGUARD_SECRETS") == "file":
        return None
    try:
        import keyring
        from keyring.backends import fail
        backend = keyring.get_keyring()
        if isinstance(backend, fail.Keyring) or "null" in type(backend).__module__ or backend.priority <= 0:
            return None
        keyring.get_password(SERVICE, INDEX)               # touches the service: raises if it is not running
        return keyring
    except Exception:                                       # no D-Bus, locked and dismissed, backend errors
        return None


class Secrets:
    def __init__(self):
        self._lock = threading.Lock()
        self._kr = _keyring()
        self._cache: dict[str, str] = {}

    @property
    def backend(self) -> str:
        return "keyring" if self._kr else "file"

    def where(self) -> str:
        return "the system keyring" if self._kr else str(_file())

    def _names(self) -> set[str]:
        if not self._kr:
            return set(_read_file())
        raw = self._kr.get_password(SERVICE, INDEX) or ""
        return {n for n in raw.split(",") if n}

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._names())

    def get(self, name: str) -> str:
        with self._lock:
            if name not in self._cache:
                if self._kr:
                    self._cache[name] = self._kr.get_password(SERVICE, name) or ""
                else:
                    self._cache[name] = _read_file().get(name, "")
            return self._cache[name]

    def set(self, name: str, value: str) -> None:
        value = value.strip()
        if not value:
            raise ValueError("empty secret")
        with self._lock:
            if self._kr:
                self._kr.set_password(SERVICE, name, value)
                self._kr.set_password(SERVICE, INDEX, ",".join(sorted(self._names() | {name})))
            else:
                values = _read_file()
                values[name] = value
                _write_file(values)
            self._cache[name] = value

    def delete(self, name: str) -> bool:
        with self._lock:
            had = name in self._names()
            if self._kr:
                try:
                    self._kr.delete_password(SERVICE, name)
                except Exception:
                    pass                                    # not there: nothing to delete
                self._kr.set_password(SERVICE, INDEX, ",".join(sorted(self._names() - {name})))
            else:
                values = _read_file()
                values.pop(name, None)
                _write_file(values)
            self._cache.pop(name, None)
            return had


_store: Secrets | None = None
_store_lock = threading.Lock()


def store() -> Secrets:
    """The process-wide secret store (keyring detection runs once)."""
    global _store
    with _store_lock:
        if _store is None:
            _store = Secrets()
        return _store


def reset() -> None:
    """Forget the cached store (tests, or after the keyring becomes available)."""
    global _store
    with _store_lock:
        _store = None
