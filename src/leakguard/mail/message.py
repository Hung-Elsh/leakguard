"""A mail message reduced to what the classifier needs, built from raw RFC 822 bytes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

BODY_LIMIT = 6000


SPAM_LABELS = {"spam", "thư rác"}          # Gmail's Spam label in English / Vietnamese accounts


def gmail_labels(raw: str) -> set[str]:
    """Decode Takeout's X-Gmail-Labels: RFC 2047 encoded words, folded over lines, comma-separated."""
    value = re.sub(r"\r?\n[ \t]+", " ", str(raw or ""))
    try:
        value = str(make_header(decode_header(value)))
    except (UnicodeError, LookupError, ValueError):
        pass
    return {x.strip().lower() for x in value.split(",") if x.strip()}


@dataclass
class MailMessage:
    uid: str                         # backend id (IMAP UID or Gmail message id)
    message_id: str
    date: datetime | None
    from_addr: str
    display_name: str
    reply_to: str
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    headers: dict[str, str] = field(default_factory=dict)   # lower-case name -> all values joined
    body: str = ""

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1] if "@" in self.from_addr else ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _text_body(msg) -> str:
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    try:
        text = part.get_content()
    except (LookupError, ValueError):
        text = part.get_payload(decode=True).decode(errors="replace") if part.get_payload(decode=True) else ""
    return text[:BODY_LIMIT]


def parse(uid: str, raw: bytes) -> MailMessage:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers: dict[str, str] = {}
    for k, v in msg.items():
        headers[k.lower()] = (headers[k.lower()] + "\n" + str(v)) if k.lower() in headers else str(v)
    name, addr = parseaddr(str(msg.get("From", "")))
    _, reply = parseaddr(str(msg.get("Reply-To", "")))
    try:
        date = parsedate_to_datetime(str(msg.get("Date"))) if msg.get("Date") else None
        if date and date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        date = None
    return MailMessage(
        uid=uid,
        message_id=str(msg.get("Message-ID", "")).strip(),
        date=date,
        from_addr=addr.lower(),
        display_name=name,
        reply_to=reply.lower(),
        to=[a.lower() for _, a in getaddresses(msg.get_all("To", [])) if a],
        cc=[a.lower() for _, a in getaddresses(msg.get_all("Cc", [])) if a],
        subject=str(msg.get("Subject", "")),
        headers=headers,
        body=_text_body(msg),
    )
