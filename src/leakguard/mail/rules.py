"""Classify mail with the generic rules (config/block_rules.json) and the owner's private lists."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from ..paths import CONFIG
from .message import MailMessage

ACTIONS = ("keep", "label", "archive", "spam", "trash")


@dataclass
class OwnerLists:
    """Owner-specific mail settings (private file, or lab/mail_rules.yaml in the lab)."""
    me: set[str] = field(default_factory=set)              # the owner's own addresses
    allow_addresses: set[str] = field(default_factory=set)
    allow_domains: set[str] = field(default_factory=set)
    block_addresses: set[str] = field(default_factory=set)
    block_domains: set[str] = field(default_factory=set)
    leak_date: datetime | None = None
    known: set[str] = field(default_factory=set)            # senders seen before the leak / people you wrote to

    @classmethod
    def load(cls, path: Path, me: set[str]) -> "OwnerLists":
        d = (yaml.safe_load(path.read_text()) if path.exists() else None) or {}
        low = lambda xs: {str(x).strip().lower() for x in xs or [] if str(x).strip()}   # noqa: E731
        allow, block = d.get("allow") or {}, d.get("block") or {}
        leak = d.get("leak_date")
        if isinstance(leak, str):
            leak = date.fromisoformat(leak)
        leak_dt = datetime(leak.year, leak.month, leak.day, tzinfo=timezone.utc) if leak else None
        return cls(me=low(me), allow_addresses=low(allow.get("addresses")), allow_domains=low(allow.get("domains")),
                   block_addresses=low(block.get("addresses")), block_domains=low(block.get("domains")),
                   leak_date=leak_dt)

    def allowed(self, m: MailMessage) -> bool:
        return m.from_addr in self.allow_addresses or _domain_in(m.from_domain, self.allow_domains) \
            or m.from_addr in self.me

    def blocked(self, m: MailMessage) -> bool:
        return m.from_addr in self.block_addresses or _domain_in(m.from_domain, self.block_domains)

    def is_known(self, m: MailMessage) -> bool:
        return self.allowed(m) or m.from_addr in self.known


def _domain_in(domain: str, domains: set[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in domains)


def _base_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


_VOWELS = set("aeiouy")


def looks_random(domain: str) -> bool:
    """Machine-generated sender domains: a long label with few vowels or mixed digits,
    or three+ short random-looking subdomain labels (e.g. 4782v1.3mi3bm.ms5xjc.us)."""
    labels = [x for x in domain.lower().split(".")[:-1] if x]      # drop the TLD
    if not labels:
        return False

    def odd(label: str) -> bool:
        letters = [c for c in label if c.isalpha()]
        if len(label) >= 12 and letters and sum(c in _VOWELS for c in letters) / len(letters) < 0.25:
            return True
        # letters and digits interleaved (4782v1, 3mi3bm, u965et), not just a number prefix (16personalities)
        switches = sum(1 for a, b in zip(label, label[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())
        return len(label) >= 5 and switches >= 2
    return odd(labels[-1]) or (len(labels) >= 3 and sum(odd(x) for x in labels) >= 2)


def _auth_results(m: MailMessage) -> str:
    """Only the topmost Authentication-Results: the one added by the owner's own mail provider when the
    message arrived. Older ones and ARC sets come from relays on the way (e.g. an internal Microsoft 365
    hop) and can say 'fail' for mail the final receiver verified as genuine."""
    return m.header("Authentication-Results").split("\n")[0].lower()


def _field(m: MailMessage, name: str) -> str:
    values = {"subject": m.subject, "body": m.body, "from": m.from_addr, "display_name": m.display_name,
              "reply_to": m.reply_to, "to": " ".join(m.to + m.cc)}
    return " ".join(values[f] for f in name.split("+"))


def condition(cond: dict, m: MailMessage, lists: OwnerLists) -> str | None:
    """Return a short reason if the condition holds, else None."""
    t = cond["type"]
    if t == "unknown_sender":
        return None if lists.is_known(m) else "unknown sender"
    if t == "sender_in":
        return "on your blocklist" if cond["list"] == "block" and lists.blocked(m) else None
    if t == "regex":
        hit = re.search(cond["pattern"], _field(m, cond["field"]))
        return f"{cond['field']} matches '{hit.group(0)[:40]}'" if hit else None
    if t == "auth_fail":
        ar = _auth_results(m)
        bad = [c for c in cond["checks"] if re.search(rf"\b{c}=(fail|permerror)\b", ar)]
        return f"{'/'.join(bad).upper()} fail" if bad else None
    if t == "header_present":
        return f"has {cond['name']}" if m.header(cond["name"]) else None
    if t == "header_absent":
        return None if m.header(cond["name"]) else f"no {cond['name']}"
    if t == "reply_to_mismatch":
        if m.reply_to and "@" in m.reply_to and _base_domain(m.reply_to.split("@")[1]) != _base_domain(m.from_domain):
            return f"Reply-To {m.reply_to.split('@')[1]} differs from {m.from_domain}"
        return None
    if t == "brand_spoof":
        name = m.display_name.lower()
        for b in cond["brands"]:
            if b in name and b not in m.from_domain:
                return f"display name says '{b}' but sender is {m.from_domain}"
        return None
    if t == "not_addressed_to_me":
        rcpt = set(m.to + m.cc)
        return None if rcpt & lists.me else "you are not in To/Cc"
    if t == "first_contact_after_leak":
        if lists.leak_date and m.date and m.date >= lists.leak_date:
            return f"first seen after leak date {lists.leak_date.date()}"
        return None
    if t == "random_domain":
        return f"machine-generated sender domain {m.from_domain}" if looks_random(m.from_domain) else None
    if t == "not_authenticated_list":
        ar = _auth_results(m)
        is_list = bool(m.header("List-Id") or m.header("List-Unsubscribe"))
        if is_list and re.search(r"\bdkim=pass\b", ar) and re.search(r"\bdmarc=pass\b", ar):
            return None          # an authenticated mailing list (newsletter): scam word rules do not apply
        return "not an authenticated mailing list"
    raise ValueError(f"unknown condition type {t!r}")


@dataclass
class Verdict:
    action: str
    rule: str
    reasons: list[str]


class Classifier:
    def __init__(self, lists: OwnerLists, rules_path: Path = CONFIG / "block_rules.json"):
        self.lists = lists
        self.rules = [r for r in json.loads(rules_path.read_text())["rules"] if r.get("enabled", True)]
        for r in self.rules:
            if r["action"] not in ACTIONS:
                raise ValueError(f"rule {r['id']}: bad action {r['action']}")

    def learn_known(self, messages: list[MailMessage]) -> None:
        """Known correspondents: people the owner wrote to (sent mail in the set, e.g. a Takeout copy),
        and senders that wrote before the leak date."""
        for m in messages:
            if m.from_addr in self.lists.me:
                self.lists.known |= set(m.to + m.cc) - self.lists.me
        if self.lists.leak_date:
            self.lists.known |= {m.from_addr for m in messages if m.date and m.date < self.lists.leak_date}

    def classify(self, m: MailMessage) -> Verdict:
        if self.lists.allowed(m):
            return Verdict("keep", "allowlist", ["sender on your allowlist"])
        for r in self.rules:
            reasons = []
            for c in r["all"]:
                why = condition(c, m, self.lists)
                if why is None:
                    break
                reasons.append(why)
            else:
                return Verdict(r["action"], r["id"], reasons)
        return Verdict("keep", "", [])
