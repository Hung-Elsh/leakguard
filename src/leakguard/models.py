"""Data model shared by plugins, store and reports."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

CATEGORIES = ("breach", "paste", "account", "profile", "web_page", "code", "keyserver", "broker", "leak")
SEVERITIES = ("info", "low", "medium", "high")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


@dataclass
class Identity:
    id: int
    value: str
    kind: str          # keyword | email | username
    status: str        # claimed | candidate | rejected
    origin: str = ""
    proof: str = ""

    @property
    def claimed(self) -> bool:
        return self.status == "claimed"


@dataclass
class Finding:
    source: str
    category: str
    title: str
    url: str = ""
    evidence: str = ""
    severity: str = "low"
    locator: str = ""                 # stable per-source key; defaults to url or title
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.title, self.evidence = scrub(self.title), scrub(self.evidence)
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity}")

    def fid(self, identity: Identity) -> str:
        key = "|".join([self.source, self.category, identity.value, self.locator or self.url or self.title])
        return hashlib.sha1(key.lower().encode()).hexdigest()[:16]


@dataclass
class Candidate:
    value: str
    kind: str          # email | username
    origin: str        # which source and where it was seen


@dataclass
class PluginResult:
    findings: list[Finding] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    checked: int = 0                                         # sub-checks attempted (sites, platforms...)
    failures: dict[str, int] = field(default_factory=dict)   # reason -> count of sub-checks with no answer
    notes: dict = field(default_factory=dict)                # extra facts for the run log (e.g. dropped sites)

    def fail(self, reason: str) -> None:
        self.failures[reason] = self.failures.get(reason, 0) + 1

    @property
    def failed(self) -> int:
        return sum(self.failures.values())


# Known credential compilations and file names typical of email:password lists
CREDENTIAL_DUMP_RE = re.compile(
    r"(?i)(cit0day|collection ?#? ?\d|anti-?public|exploit\.in|breach ?compilation|combo|\bulp\b|mail ?access"
    r"|pass(word)?s?\b|\bcreds?\b|(gmail|hotmail|yahoo|outlook|mail)[^/]*\.txt)")


def breach_severity(name: str, fields: list[str] | tuple[str, ...] = ()) -> str:
    """high: the source shows passwords, or the breach is a known credential compilation / combo list.
    medium: a breach listing whose contents are unknown (or known to hold no password)."""
    if any("pass" in str(f).lower() or "hash" in str(f).lower() for f in fields):
        return "high"
    return "high" if CREDENTIAL_DUMP_RE.search(name or "") else "medium"


def mask(secret: str) -> str:
    """Show only enough of a leaked secret to recognise it: 'hunter22' -> 'hu****22'."""
    s = str(secret)
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * max(2, len(s) - 4) + s[-2:]


_COMBO_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\s*[:;|]\s*(\S+)")
_PASSWORD_RE = re.compile(r"(?i)\b(pass(?:word)?|pwd|passwd)\b(\s*[:=]\s*)(\S+)")


def scrub(text: str) -> str:
    """Mask leaked secrets in free text: 'a@b.c:hunter22' and 'password=hunter22'."""
    text = _COMBO_RE.sub(lambda m: f"{m.group(1)}:{mask(m.group(2))}", str(text or ""))
    return _PASSWORD_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{mask(m.group(3))}", text)


_SECRET_PARAM_RE = re.compile(r"(?i)\b(key|api_?key|token|access_token|secret|password|x-key)=([^&\s'\"]+)")


def redact(text: str, secrets: list[str] | tuple[str, ...] = ()) -> str:
    """Remove credentials from messages before they are printed or stored: known secret values,
    and any key=/token=/secret= URL parameter."""
    text = str(text or "")
    for sec in sorted({x for x in secrets if x and len(x) >= 6}, key=len, reverse=True):
        text = text.replace(sec, "***")
    return _SECRET_PARAM_RE.sub(lambda m: f"{m.group(1)}=***", text)


def candidates_in_text(text: str, keyword: str, origin: str) -> list[Candidate]:
    """Emails and usernames in free text that contain the owner's keyword."""
    out: dict[str, Candidate] = {}
    low = text.lower()
    if keyword not in low:
        return []
    for m in EMAIL_RE.finditer(text):
        v = m.group(0).lower().strip(".")
        if keyword in v:
            out[v] = Candidate(v, "email", origin)
    for m in re.finditer(rf"(?<![A-Za-z0-9._@-])[A-Za-z0-9._-]*{re.escape(keyword)}[A-Za-z0-9._-]*", text, re.I):
        v = m.group(0).lower().strip("._-")
        if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,6}", v):
            continue  # a host name like keyword.example.com, not a username
        if v and "@" not in v and v not in out and not _is_email_part(text, m):
            out[v] = Candidate(v, "username", origin)
    return list(out.values())


def _is_email_part(text: str, m: re.Match) -> bool:
    end = m.end()
    return end < len(text) and text[end] == "@"
