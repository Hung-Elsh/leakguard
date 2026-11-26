"""Render a removal request (email) from a template into a private .eml draft."""

from __future__ import annotations

import json
import os
from datetime import date
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from ..config import Settings
from ..models import scrub
from ..paths import CONFIG, DATA
from ..store import Store

DRAFTS = DATA / "drafts"


class DraftError(Exception):
    pass


def sender_address(settings: Settings, action=None) -> str:
    """Requests go out from the address the data is about: sites and indexes act only for the address a request
    comes from (Intelligence X removed nothing for an address listed in a request sent from another one). An
    action about exactly one email address uses it; anything else uses the owner's main (first) address."""
    if action is not None:
        addresses = [i for i in json.loads(action["identities"] or "[]") if "@" in i]
        if len(addresses) == 1:
            return addresses[0]
    emails = [s["value"] for s in settings.seeds if s.get("kind") == "email"]
    if not emails:
        raise DraftError("no owner email configured (leakguard init)")
    return emails[0]


def _evidence(findings) -> list[dict]:
    """One line per distinct item (the same record is often found for several identities), secrets masked."""
    seen, out = set(), []
    for f in findings:
        key = (f["url"] or "") or scrub(f["title"])
        if key not in seen:
            seen.add(key)
            out.append({"title": scrub(f["title"]), "url": f["url"]})
    return out


def render(settings: Settings, store: Store, action_id: int) -> tuple[EmailMessage, Path]:
    a = store.action(action_id)
    if a["method"] != "email" or not a["template"]:
        raise DraftError(f"action {action_id} is '{a['method']}', not an email request")
    has_address = bool(a["contact"]) and "@" in a["contact"]       # no address yet: still draftable (paste into a
                                                                     # contact form); `send` refuses it
    findings = store.findings_by_ids(json.loads(a["finding_ids"] or "[]"))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(CONFIG / "removal"), undefined=jinja2.StrictUndefined,
                             keep_trailing_newline=True, autoescape=False)
    text = env.get_template(f"{a['template']}.j2").render(
        target=a["target"],
        identities=json.loads(a["identities"] or "[]"),
        evidence=_evidence(findings),
        owner_name=(settings.owner or {}).get("full_name", ""),
        owner_email=sender_address(settings, a),
        today=date.today().isoformat(),
    )
    subject, _, body = text.partition("\n")
    msg = EmailMessage()
    msg["From"] = sender_address(settings, a)
    if has_address:
        msg["To"] = a["contact"]
    msg["Subject"] = subject.removeprefix("Subject:").strip()
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(idstring=f"leakguard-{action_id}")
    msg.set_content(scrub(body.lstrip("\n")))          # never let a leaked secret into a request
    DRAFTS.mkdir(parents=True, exist_ok=True)
    DRAFTS.chmod(0o700)
    path = DRAFTS / f"action-{action_id}.eml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(msg.as_bytes())
    return msg, path
