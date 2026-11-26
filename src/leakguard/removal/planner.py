"""Findings -> removal actions. One action per target (site, index, broker), merging every tool's evidence.

Driven by the owner's verdicts: open -> remove; protect -> one security checklist; accepted, false_positive
and info-only findings -> nothing.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..models import CREDENTIAL_DUMP_RE
from ..store import Store
from .catalog import Catalog, Entry, site_key

PROTECT_STEPS = """Keep these accounts, secure them (they are linked: the game account resets through the mailbox):
1. Gmail: new unique password, 2-step verification (authenticator or passkey), check recovery phone/email,
   sign out unknown devices (myaccount.google.com/security), remove unknown third-party access.
2. Linked account(s): new unique password (the old one is in breach data), 2-step verification if offered.
3. Any other site where the old password was reused: change it there too."""

RECOVERY_HINT = """
Forgot the password? Use the site's own "Forgot password" link: the reset goes to the address the account was
registered with. To find that address, search your mailbox for the site's welcome/verification mail, and check
myaccount.google.com/connections (accounts made with "Sign in with Google" need no site password). If it was an
address you can no longer read, use the site's support form and ask for deletion."""

ROTATE_STEPS = """Credential compilations cannot be taken down. Treat every password they may contain as public:
change it on every site where it was used, and use a password manager for unique passwords."""


@dataclass
class Plan:
    key: str
    kind: str
    method: str
    target: str
    title: str
    finding_ids: list[str] = field(default_factory=list)
    identities: set[str] = field(default_factory=set)
    contact: str | None = None
    contact_verified: bool = False
    template: str | None = None
    steps: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "kind": self.kind, "method": self.method, "target": self.target,
                "title": self.title, "finding_ids": self.finding_ids, "identities": sorted(self.identities),
                "contact": self.contact, "contact_verified": self.contact_verified, "template": self.template,
                "steps": self.steps}


DOMAIN_RE = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
PROFILE_SITES = {"ghunt": "Google", "gravatar": "Gravatar"}
COPIES = ("leak", "paste")          # copies of your data on someone else's index: removable even for kept accounts
# template for an email request, by action kind (used when you set an email contact on a manual action)
TEMPLATES = {"account_delete": "account_deletion", "leak_removal": "leak_removal", "paste_report": "paste_report",
             "broker_optout": "data_erasure"}


def _norm(name: str, domain: str) -> tuple[str, str]:
    """'spotify.com' and 'Spotify' are the same site: a domain-looking name becomes its main label."""
    if DOMAIN_RE.fullmatch((name or "").lower()):
        domain = domain or name.lower()
        parts = name.lower().split(".")
        name = parts[-3] if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net") else parts[-2]
    return name, domain


def _site_of(f: sqlite3.Row) -> tuple[str, str]:
    """(site name, domain) a finding points at."""
    return _norm(*_raw_site(f))


def _raw_site(f: sqlite3.Row) -> tuple[str, str]:
    data = json.loads(f["data"] or "{}")
    host = (urlsplit(f["url"] or "").hostname or "").removeprefix("www.")
    if f["category"] == "profile":
        return PROFILE_SITES.get(f["source"], f["source"]), ""
    if f["category"] == "account":
        if f["source"] == "github":
            return "GitHub", "github.com"
        m = re.search(r"External Site: (.+?) \(Category", f["title"])      # SpiderFoot
        name = data.get("site") or (m.group(1) if m else re.sub(r"^Account on ", "", f["title"]))
        return name, ""
    if f["category"] == "breach":
        m = re.search(r"\[([^\]]+)\]", f["title"])                     # SpiderFoot: "... [androidlista.com]"
        if m:
            return m.group(1).split(".")[0], m.group(1)
        if f["source"] == "mosint" and f["title"].startswith("EmailRep"):  # a reputation note, not a site
            return "", ""
        if f["source"] == "h8mail":                                     # title names the lookup service, not the site
            ev = (f["evidence"] or "").strip()
            return (ev.split(".")[0], ev) if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", ev) else ("", "")
        name = re.sub(r"\s+(breach|leak|hit)\b.*$", "", f["title"], flags=re.I)   # "LabShop breach (2019-04-02)"
        domain = data.get("domain") or (name if "." in name else "")
        return name.split(".")[0] if "." in name else name, domain
    return "", host


def _apply_entry(p: Plan, e: Entry | None, template: str) -> None:
    _apply_entry_base(p, e, template)
    if p.kind == "account_delete" and p.method == "manual":
        p.steps = (p.steps + "\n" + RECOVERY_HINT.strip()).strip()


def _apply_entry_base(p: Plan, e: Entry | None, template: str) -> None:
    if e is None:
        p.method, p.template, p.contact_verified = "email", template, False
        p.steps = "No catalog entry: find the site's privacy / account-deletion contact, then `leakguard remove set ID --contact ...`."
        return
    p.method, p.contact_verified = e.method, e.verified
    p.contact = e.email if e.method == "email" else e.url
    p.template = template if e.method == "email" else None
    p.steps = e.steps


def build(store: Store, catalog: Catalog) -> list[Plan]:
    plans: dict[str, Plan] = {}

    def plan(key: str, **kw) -> Plan:
        if key not in plans:
            plans[key] = Plan(key=key, **kw)
        return plans[key]

    for f in store.findings():
        verdict = f["disposition"] or "open"
        if f["status"] == "gone" or verdict in ("accepted", "false_positive"):
            continue
        if verdict == "protect":
            p = plan("protect", kind="protect_checklist", method="checklist", target="protected accounts",
                     title="Secure the protected accounts (password, 2-step verification, recovery)", steps=PROTECT_STEPS)
            if f["category"] in COPIES:          # you keep the account, but a copy of its data in a leak index or
                r = _plan_for(f, plan, catalog)  # paste still gets removed
                if r is not None:
                    r.finding_ids.append(f["id"])
                    r.identities.add(f["identity"])
        elif f["severity"] == "info":
            continue                                                    # partial search matches: not an exposure
        else:
            p = _plan_for(f, plan, catalog)
            if p is None:
                continue
        p.finding_ids.append(f["id"])
        p.identities.add(f["identity"])

    # every address with a breach can be hidden from HIBP's public search (confirmed by the owner: "done")
    hibp_by_ident: dict[str, list[str]] = {}
    for f in store.findings():
        if f["source"] == "hibp" and f["status"] != "gone":
            hibp_by_ident.setdefault(f["identity"], []).append(f["id"])
    breached = {i for p in plans.values() if p.kind in ("account_delete", "rotate_password") for i in p.identities}
    for ident in sorted(i for i in breached if "@" in i):
        h = plan(f"hibp_optout:{ident}", kind="hibp_optout", method="manual", target="haveibeenpwned.com",
                 title=f"Hide {ident} from HIBP public search")
        _apply_entry(h, catalog.lookup("hibp"), "")
        h.identities.add(ident)
        h.finding_ids = hibp_by_ident.get(ident, [])
    return list(plans.values())


def _plan_for(f: sqlite3.Row, plan, catalog: Catalog) -> Plan | None:
    cat = f["category"]
    host = (urlsplit(f["url"] or "").hostname or "").removeprefix("www.")
    if cat in ("account", "breach"):
        name, domain = _site_of(f)
        if cat == "breach" and (CREDENTIAL_DUMP_RE.search(f["title"]) or not (name or domain)):
            return plan("rotate:compilations", kind="rotate_password", method="manual", target="credential compilations",
                        title="Change passwords exposed in credential compilations", steps=ROTATE_STEPS)
        key = site_key(name) or site_key(domain)
        if not key:
            return None
        e = catalog.lookup(name, domain or host)
        p = plan(f"account:{key}", kind="account_delete", method="email", target=e.name if e else name,
                 title=f"Delete / deactivate the account on {e.name if e else name}")
        if p.contact is None and not p.steps:
            _apply_entry(p, e, "account_deletion")
        return p
    if cat == "leak":       # IntelX records: one request per address, sent from that address (they act only for it)
        p = plan(f"leakindex:intelx:{f['identity']}", kind="leak_removal", method="email", target="Intelligence X",
                 title=f"Ask Intelligence X to remove the records with {f['identity']}")
        if p.contact is None and not p.steps:
            _apply_entry(p, catalog.entries.get("intelxrecords"), "leak_removal")   # never JDM's account deletion
        return p
    if cat == "paste":
        e = catalog.lookup(domain=host) or catalog.lookup("pastebin")
        p = plan(f"paste:{site_key(e.name) if e else host}", kind="paste_report", method="email",
                 target=e.name if e else host, title=f"Report pastes with your data on {e.name if e else host}")
        if p.contact is None and not p.steps:
            _apply_entry(p, e, "paste_report")
        return p
    if cat == "broker":
        broker = json.loads(f["data"] or "{}").get("broker", host)
        e = catalog.lookup(broker, host)
        p = plan(f"broker:{site_key(broker)}", kind="broker_optout", method="form", target=e.name if e else broker,
                 title=f"Opt out of {e.name if e else broker}")
        if p.contact is None and not p.steps:
            _apply_entry(p, e, "data_erasure")
        return p
    if cat == "profile":
        name, _ = _site_of(f)
        e = catalog.lookup(name)
        p = plan(f"account:{site_key(name)}", kind="account_delete", method="manual", target=e.name if e else name,
                 title=f"Remove or hide the public {name} profile")
        if p.contact is None and not p.steps:
            _apply_entry(p, e, "account_deletion")
        return p
    if cat == "keyserver":
        e = catalog.lookup(domain=json.loads(f["data"] or "{}").get("server", "")) or catalog.lookup(f["title"].split()[-1])
        server = f["title"].removeprefix("PGP key on ")
        p = plan(f"keyserver:{site_key(server)}", kind="manual", method="manual", target=server,
                 title=f"Unpublish or revoke the PGP key on {server}")
        if not p.steps:
            if e:
                _apply_entry(p, e, "")
            else:
                p.steps = "This keyserver cannot delete keys: revoke the key and publish the revocation."
        return p
    if cat in ("code", "web_page"):
        if cat == "web_page" and host:
            target = host
        else:
            target = json.loads(f["data"] or "{}").get("repo") or host or "unknown"
        p = plan(f"page:{target}", kind="manual", method="manual", target=target,
                 title=f"Ask {target} to remove your data (then request search-engine removal)",
                 steps="Contact the page/repository owner and ask for removal. Once it is gone, use Google 'Results "
                       "about you' / Remove Outdated Content and Bing content removal for cached copies.")
        return p
    return None
