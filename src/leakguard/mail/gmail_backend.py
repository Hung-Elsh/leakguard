"""Gmail API backend (internet profile). OAuth on first use; the token stays in ~/.config/leakguard.

Scopes: gmail.modify (read, label, spam, trash — never permanent delete), gmail.settings.basic (filters) and
gmail.send (removal requests sent from the owner's address after --confirm). Adding a scope asks for consent once.
"""

from __future__ import annotations

import base64
import os
import time
from pathlib import Path

from ..config import ConfigError, Settings
from ..paths import USER_CONFIG
from ..scope import ScopeGuard
from .backend import MailBackend
from .message import MailMessage, parse
from .rules import OwnerLists

SCOPES = ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.settings.basic",
          "https://www.googleapis.com/auth/gmail.send"]
TOKEN = USER_CONFIG / "gmail_token.json"
LABELS = {"label": "LeakGuard/Review", "blocked": "LeakGuard/Blocked"}
CHUNK = 20          # addresses per server-side filter (Gmail limits the criteria length)

# Gmail allows ~250 quota units per user per second; messages.get costs 5 units.
BATCH = 20          # 20 gets = 100 units per batch...
PAUSE = 0.6         # ...and a pause between batches keeps us well under the limit
RETRIES = 5         # single calls: googleapiclient retries 429/5xx and 403 rateLimitExceeded with backoff
SENT_SAMPLE = 300   # sent messages used to learn the owner's contacts


class GmailBackend(MailBackend):
    name = "gmail"
    supports_filters = True

    def __init__(self, settings: Settings, guard: ScopeGuard):
        for host in ("gmail.googleapis.com", "oauth2.googleapis.com", "accounts.google.com"):
            guard.check_host(host, "mail")
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build

        creds = Credentials.from_authorized_user_file(str(TOKEN), SCOPES) if TOKEN.exists() else None
        if creds and not creds.has_scopes(SCOPES):
            creds = None                       # a scope was added since consent: ask again
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        if not creds or not creds.valid:
            secret = Path(os.path.expanduser(os.environ.get("GMAIL_CLIENT_SECRET_FILE",
                                                            str(USER_CONFIG / "client_secret.json"))))
            if not secret.exists():
                raise ConfigError(f"Gmail OAuth client file not found: {secret} (see README, phase 5 setup)")
            creds = InstalledAppFlow.from_client_secrets_file(str(secret), SCOPES).run_local_server(port=0)
        TOKEN.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(TOKEN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(creds.to_json())
        self.svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
        self.users = self.svc.users()
        self._label_ids: dict[str, str] = {}

    # ---- reading ----------------------------------------------------------------
    def _ids(self, query: str, limit: int) -> list[str]:
        ids, token = [], None
        while len(ids) < limit:
            r = self.users.messages().list(userId="me", q=query, maxResults=min(500, limit - len(ids)),
                                           pageToken=token).execute(num_retries=RETRIES)
            ids += [m["id"] for m in r.get("messages", [])]
            token = r.get("nextPageToken")
            if not token:
                break
        return ids

    def _get_many(self, ids: list[str], fmt: str, **kw) -> list[dict]:
        """Batch-get messages, paced under the per-user quota. Failed items are retried with backoff;
        if some still fail, raise instead of silently classifying an incomplete mailbox."""
        out: dict[str, dict] = {}
        pending = list(ids)
        for attempt in range(RETRIES + 1):
            failed: list[str] = []

            def cb(rid, resp, exc):
                if exc is None:
                    out[rid] = resp
                else:
                    failed.append(rid)

            for i in range(0, len(pending), BATCH):
                batch = self.svc.new_batch_http_request(callback=cb)
                for mid in pending[i:i + BATCH]:
                    batch.add(self.users.messages().get(userId="me", id=mid, format=fmt, **kw), request_id=mid)
                batch.execute()
                time.sleep(PAUSE)
            if not failed:
                break
            pending = failed
            time.sleep(2 ** (attempt + 1))         # 2, 4, 8, 16, 32 s
        else:
            raise RuntimeError(f"Gmail kept refusing {len(pending)} message(s) (rate limit); try again in a minute")
        return [out[i] for i in ids if i in out]

    def fetch(self, folder, since_days, limit):
        q = f"in:{folder.lower()}" + (f" newer_than:{since_days}d" if since_days else "")
        msgs = self._get_many(self._ids(q, limit), "raw")
        return [parse(m["id"], base64.urlsafe_b64decode(m["raw"])) for m in msgs]

    def known_correspondents(self):
        from email.utils import getaddresses
        out: set[str] = set()
        for m in self._get_many(self._ids("in:sent", SENT_SAMPLE), "metadata", metadataHeaders=["To", "Cc"]):
            vals = [h["value"] for h in m.get("payload", {}).get("headers", [])]
            out |= {a.lower() for _, a in getaddresses(vals) if a}
        return out

    def send(self, msg) -> str:
        """Send an email from the owner's account (removal requests). Returns the Gmail message id."""
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        return self.users.messages().send(userId="me", body={"raw": raw}).execute(num_retries=RETRIES)["id"]

    # ---- changing -----------------------------------------------------------------
    def _labels(self) -> dict[str, str]:
        if not self._label_ids:
            self._label_ids = {lb["name"]: lb["id"] for lb in
                               self.users.labels().list(userId="me").execute(num_retries=RETRIES).get("labels", [])}
        return self._label_ids

    def _label(self, name: str) -> str:
        """Label id, created on first use (only called when changes are applied)."""
        if name not in self._labels():
            lb = self.users.labels().create(userId="me", body={"name": name, "labelListVisibility": "labelShow",
                                                                "messageListVisibility": "show"}).execute(num_retries=RETRIES)
            self._label_ids[name] = lb["id"]
        return self._label_ids[name]

    def apply(self, action, uids):
        if action == "keep" or not uids:
            return 0
        if action == "spam":
            body = {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]}
        elif action == "trash":
            body = {"addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}
        elif action == "archive":
            body = {"removeLabelIds": ["INBOX"]}
        else:  # label: out of the inbox into LeakGuard/Review
            body = {"addLabelIds": [self._label(LABELS["label"])], "removeLabelIds": ["INBOX"]}
        for i in range(0, len(uids), 1000):
            self.users.messages().batchModify(userId="me", body={"ids": uids[i:i + 1000], **body}).execute(num_retries=RETRIES)
        return len(uids)

    def sync_filters(self, lists: OwnerLists, apply: bool) -> list[str]:
        """One Gmail filter per CHUNK blocked senders: label LeakGuard/Blocked, skip inbox, move to trash.
        Existing LeakGuard filters are replaced, so the server matches the blocklist exactly."""
        blocked_id = self._labels().get(LABELS["blocked"])
        existing = [f for f in self.users.settings().filters().list(userId="me").execute(num_retries=RETRIES).get("filter", [])
                    if blocked_id and blocked_id in f.get("action", {}).get("addLabelIds", [])]
        senders = sorted(lists.block_addresses) + [f"@{d}" for d in sorted(lists.block_domains)]
        chunks = [senders[i:i + CHUNK] for i in range(0, len(senders), CHUNK)]
        plan = [f"delete old LeakGuard filter {f['id']}" for f in existing]
        plan += [f"create filter from:({' OR '.join(c)}) -> trash" for c in chunks]
        if apply:
            blocked_id = self._label(LABELS["blocked"])
            for f in existing:
                self.users.settings().filters().delete(userId="me", id=f["id"]).execute(num_retries=RETRIES)
            for c in chunks:
                self.users.settings().filters().create(userId="me", body={
                    "criteria": {"from": " OR ".join(c)},
                    "action": {"addLabelIds": [blocked_id, "TRASH"], "removeLabelIds": ["INBOX"]}}).execute(num_retries=RETRIES)
        return plan
