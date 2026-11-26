"""SQLite store: identities, scans, per-source runs and findings (new / known / gone)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Candidate, Finding, Identity

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
  id INTEGER PRIMARY KEY,
  value TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,          -- claimed | candidate | rejected
  origin TEXT, proof TEXT,
  created TEXT NOT NULL, decided TEXT,
  UNIQUE(value, kind)
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, stage TEXT, started TEXT, finished TEXT
);
CREATE TABLE IF NOT EXISTS source_runs (
  scan_id INTEGER, source TEXT, identity_id INTEGER,
  ok INTEGER, error TEXT, found INTEGER
);   -- more columns added by RUN_COLUMNS (migration-safe)
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  identity_id INTEGER NOT NULL, source TEXT, category TEXT, title TEXT,
  url TEXT, evidence TEXT, severity TEXT, data TEXT,
  status TEXT,                   -- new | known | gone
  first_seen TEXT, last_seen TEXT, last_scan INTEGER
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,      -- grouping key, e.g. account:twitch, leakindex:intelx, broker:lab-broker
  kind TEXT NOT NULL,            -- account_delete | data_erasure | leak_removal | broker_optout | paste_report
                                 -- | protect_checklist | rotate_password | hibp_optout | manual
  method TEXT NOT NULL,          -- email | form | manual | checklist
  target TEXT, title TEXT,
  contact TEXT,                  -- email address or URL
  contact_verified INTEGER,      -- 1 = from a vetted catalog entry, 0 = guessed / needs checking
  template TEXT,
  state TEXT NOT NULL,           -- see ACTION_STATES
  finding_ids TEXT,              -- JSON list
  identities TEXT,               -- JSON list of identity values involved
  draft_path TEXT, steps TEXT, notes TEXT,
  history TEXT,                  -- JSON list of {ts, state, note}
  created TEXT, updated TEXT, next_check TEXT
);
CREATE TABLE IF NOT EXISTS mail_log (
  ts TEXT, profile TEXT, message_id TEXT, sender TEXT, subject TEXT,
  rule TEXT, action TEXT, applied INTEGER
);
"""


# Per-run log for the dashboard. Secrets are redacted before they get here.
RUN_COLUMNS = {
    "status": "TEXT",        # ok | partial | skipped | error | scope_blocked
    "checked": "INTEGER",    # sub-checks attempted (sites/platforms), when the source reports it
    "failed": "INTEGER",     # sub-checks without an answer (rate limits, token errors...)
    "error_type": "TEXT",    # exception class
    "http_status": "INTEGER",
    "url": "TEXT",           # request URL (credentials redacted)
    "detail": "TEXT",        # service response body or traceback (credentials redacted)
    "started": "TEXT",
    "duration_ms": "INTEGER",
}


# Owner's verdict on a finding, kept separate from what the sources see (status new/known/gone).
FINDING_COLUMNS = {"disposition": "TEXT DEFAULT 'open'", "note": "TEXT"}
# open           exposure to clean up (deactivate/delete/remove)
# protect        the owner's own account to keep and secure (password change, 2FA), never deleted
# accepted       known, not a threat, no action
# false_positive not the owner / the source was wrong
DISPOSITIONS = ("open", "protect", "accepted", "false_positive")


# Removal action life cycle. "done" closes manual steps and checklists; "verified" needs a re-check
# showing the linked findings gone.
ACTION_STATES = ("planned", "drafted", "requested", "acknowledged", "removed", "verified", "done", "skipped")
ACTION_FLOW = {
    "planned": {"drafted", "requested", "done", "skipped"},
    "drafted": {"drafted", "requested", "skipped", "planned"},
    "requested": {"acknowledged", "removed", "verified", "requested", "skipped"},
    "acknowledged": {"removed", "verified", "requested", "skipped"},
    "removed": {"verified", "requested"},
    "verified": {"requested"},                 # a finding came back
    "done": {"planned", "verified"},
    "skipped": {"planned"},
}


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        for table, columns in (("source_runs", RUN_COLUMNS), ("findings", FINDING_COLUMNS)):
            have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
            for col, typ in columns.items():
                if col not in have:
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        self.db.commit()

    # ---- identities -------------------------------------------------------
    def _identity(self, row: sqlite3.Row) -> Identity:
        return Identity(row["id"], row["value"], row["kind"], row["status"], row["origin"] or "", row["proof"] or "")

    def seed(self, value: str, kind: str, proof: str) -> None:
        """Owner-declared identity: claimed from the start."""
        self.db.execute(
            "INSERT INTO identities(value, kind, status, origin, proof, created, decided) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(value, kind) DO UPDATE SET status='claimed', proof=excluded.proof",
            (value.lower(), kind, "claimed", "owner seed", proof, now(), now()),
        )
        self.db.commit()

    def add_identity(self, value: str, kind: str, status: str, origin: str, proof: str = "") -> Identity:
        """Owner decision on a value that may not exist yet (claim/reject by value)."""
        if status not in ("claimed", "rejected", "candidate"):
            raise ValueError(status)
        self.db.execute(
            "INSERT INTO identities(value, kind, status, origin, proof, created, decided) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(value, kind) DO UPDATE SET status=excluded.status, proof=excluded.proof, decided=excluded.decided",
            (value.lower(), kind, status, origin, proof, now(), now()))
        self.db.commit()
        row = self.db.execute("SELECT * FROM identities WHERE value=? AND kind=?", (value.lower(), kind)).fetchone()
        return self._identity(row)

    def add_candidate(self, c: Candidate) -> bool:
        """Insert a candidate; returns True if it is new. Never changes an existing decision."""
        cur = self.db.execute(
            "INSERT OR IGNORE INTO identities(value, kind, status, origin, created) VALUES(?,?,?,?,?)",
            (c.value.lower(), c.kind, "candidate", c.origin, now()),
        )
        self.db.commit()
        return cur.rowcount == 1

    def decide(self, ident_id: int, status: str, proof: str = "") -> Identity:
        if status not in ("claimed", "rejected", "candidate"):
            raise ValueError(status)
        row = self.db.execute("SELECT * FROM identities WHERE id=?", (ident_id,)).fetchone()
        if not row:
            raise KeyError(f"no identity with id {ident_id}")
        if row["kind"] == "keyword":
            raise ValueError("the keyword identity cannot be changed")
        self.db.execute("UPDATE identities SET status=?, proof=?, decided=? WHERE id=?",
                        (status, proof or row["proof"], now(), ident_id))
        self.db.commit()
        return self.get_identity(ident_id)

    def get_identity(self, ident_id: int) -> Identity:
        return self._identity(self.db.execute("SELECT * FROM identities WHERE id=?", (ident_id,)).fetchone())

    def identities(self, status: str | None = None) -> list[Identity]:
        q, args = "SELECT * FROM identities", ()
        if status:
            q, args = q + " WHERE status=?", (status,)
        return [self._identity(r) for r in self.db.execute(q + " ORDER BY id", args)]

    # ---- scans ----------------------------------------------------------
    def start_scan(self, stage: str) -> int:
        cur = self.db.execute("INSERT INTO scans(stage, started) VALUES(?,?)", (stage, now()))
        self.db.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int) -> None:
        self.db.execute("UPDATE scans SET finished=? WHERE id=?", (now(), scan_id))
        self.db.commit()

    def record_run(self, scan_id: int, source: str, ident: Identity, status: str, found: int = 0,
                   error: str = "", **extra) -> None:
        """Log one source run. extra: any of RUN_COLUMNS (error_type, http_status, url, detail, ...)."""
        unknown = set(extra) - set(RUN_COLUMNS)
        if unknown:
            raise ValueError(f"unknown run fields {unknown}")
        cols = ["scan_id", "source", "identity_id", "ok", "error", "found", "status", *extra]
        vals = [scan_id, source, ident.id, int(status == "ok"), error, found, status, *extra.values()]
        self.db.execute(f"INSERT INTO source_runs({','.join(cols)}) VALUES({','.join('?' * len(cols))})", vals)
        self.db.commit()

    def save_findings(self, scan_id: int, ident: Identity, source: str, findings: list[Finding],
                      mark_gone: bool = True) -> tuple[int, int]:
        """Upsert findings of one source run. If the run was complete (mark_gone), earlier findings of the
        same source+identity that were not seen again are marked gone. Returns (new, gone)."""
        ts, seen, new = now(), set(), 0
        for f in findings:
            fid = f.fid(ident)
            if fid in seen:
                continue
            seen.add(fid)
            row = self.db.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
            if row is None:
                new += 1
                self.db.execute(
                    "INSERT INTO findings(id, identity_id, source, category, title, url, evidence, severity, data, "
                    "status, first_seen, last_seen, last_scan) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, ident.id, f.source, f.category, f.title, f.url, f.evidence, f.severity,
                     json.dumps(f.data, default=str), "new", ts, ts, scan_id),
                )
            else:
                status = "new" if row["status"] == "gone" else "known"
                new += status == "new"
                self.db.execute(
                    "UPDATE findings SET title=?, url=?, evidence=?, severity=?, data=?, status=?, last_seen=?, last_scan=? WHERE id=?",
                    (f.title, f.url, f.evidence, f.severity, json.dumps(f.data, default=str), status, ts, scan_id, fid),
                )
        if not mark_gone:              # partial run: a site that did not answer is not proof of removal
            self.db.commit()
            return new, 0
        q = "UPDATE findings SET status='gone', last_scan=? WHERE identity_id=? AND source=? AND status!='gone'"
        if seen:  # note: "NOT IN (NULL)" would match nothing, so the clause is only added when needed
            q += f" AND id NOT IN ({','.join('?' * len(seen))})"
        cur = self.db.execute(q, (scan_id, ident.id, source, *seen))
        self.db.commit()
        return new, cur.rowcount

    def mark(self, id_prefixes: list[str], disposition: str, note: str = "") -> list[sqlite3.Row]:
        """Set the owner's verdict on findings (ids or unique prefixes of 6+ chars)."""
        if disposition not in DISPOSITIONS:
            raise ValueError(f"disposition must be one of {DISPOSITIONS}")
        done = []
        for pre in id_prefixes:
            if len(pre) < 6:
                raise ValueError(f"id prefix too short: {pre!r} (use 6+ characters)")
            rows = list(self.db.execute("SELECT id, title FROM findings WHERE id LIKE ?", (pre + "%",)))
            if len(rows) != 1:
                raise KeyError(f"{pre!r} matches {len(rows)} findings")
            self.db.execute("UPDATE findings SET disposition=?, note=? WHERE id=?", (disposition, note, rows[0]["id"]))
            done.append(rows[0])
        self.db.commit()
        return done

    def findings(self, status: str | None = None) -> list[sqlite3.Row]:
        q = ("SELECT f.*, i.value AS identity FROM findings f JOIN identities i ON i.id=f.identity_id")
        args: tuple = ()
        if status:
            q, args = q + " WHERE f.status=?", (status,)
        return list(self.db.execute(q + " ORDER BY f.category, f.severity DESC, f.source", args))

    def runs(self, scan_id: int) -> list[sqlite3.Row]:
        return list(self.db.execute(
            "SELECT r.*, i.value AS identity FROM source_runs r JOIN identities i ON i.id=r.identity_id WHERE scan_id=?",
            (scan_id,)))

    # ---- removal actions ---------------------------------------------------------------
    def upsert_action(self, a: dict) -> tuple[int, bool]:
        """Insert a planned action or merge new findings into an existing one (same key).
        Never resets the state of an action already in progress. Returns (id, created)."""
        row = self.db.execute("SELECT * FROM actions WHERE key=?", (a["key"],)).fetchone()
        ts = now()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO actions(key, kind, method, target, title, contact, contact_verified, template, state, "
                "finding_ids, identities, steps, notes, history, created, updated) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["key"], a["kind"], a["method"], a.get("target"), a.get("title"), a.get("contact"),
                 int(bool(a.get("contact_verified"))), a.get("template"), "planned",
                 json.dumps(sorted(a["finding_ids"])), json.dumps(sorted(a.get("identities", []))),
                 a.get("steps", ""), a.get("notes", ""), json.dumps([{"ts": ts, "state": "planned", "note": "plan"}]),
                 ts, ts))
            self.db.commit()
            return cur.lastrowid, True
        fids = sorted(set(json.loads(row["finding_ids"] or "[]")) | set(a["finding_ids"]))
        idents = sorted(set(json.loads(row["identities"] or "[]")) | set(a.get("identities", [])))
        self.db.execute("UPDATE actions SET finding_ids=?, identities=?, updated=? WHERE id=?",
                        (json.dumps(fids), json.dumps(idents), ts, row["id"]))
        owner_contact = any("contact set by owner" in h.get("note", "") for h in json.loads(row["history"] or "[]"))
        if row["state"] == "planned" and not owner_contact:
            # not started: take the catalog's current answer (links get fixed; never overrides an owner's contact)
            self.db.execute("UPDATE actions SET method=?, target=?, title=?, contact=?, contact_verified=?, template=?, "
                            "steps=? WHERE id=?",
                            (a["method"], a.get("target"), a.get("title"), a.get("contact"),
                             int(bool(a.get("contact_verified"))), a.get("template"), a.get("steps", ""), row["id"]))
        self.db.commit()
        return row["id"], False

    def actions(self, state: str | None = None) -> list[sqlite3.Row]:
        q, args = "SELECT * FROM actions", ()
        if state:
            q, args = q + " WHERE state=?", (state,)
        return list(self.db.execute(q + " ORDER BY id", args))

    def action(self, action_id: int) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if row is None:
            raise KeyError(f"no action {action_id}")
        return row

    def set_action_state(self, action_id: int, state: str, note: str = "", **fields) -> sqlite3.Row:
        """Move an action along ACTION_FLOW (refuses illegal jumps) and append to its history."""
        row = self.action(action_id)
        if state not in ACTION_STATES:
            raise ValueError(f"unknown state {state!r}")
        if state != row["state"] and state not in ACTION_FLOW[row["state"]]:
            raise ValueError(f"action {action_id}: cannot go from {row['state']} to {state}")
        allowed = {"draft_path", "contact", "next_check", "notes"}
        if set(fields) - allowed:
            raise ValueError(f"unknown fields {set(fields) - allowed}")
        hist = json.loads(row["history"] or "[]") + [{"ts": now(), "state": state, "note": note}]
        sets = ", ".join(["state=?", "history=?", "updated=?", *[f"{k}=?" for k in fields]])
        self.db.execute(f"UPDATE actions SET {sets} WHERE id=?",
                        (state, json.dumps(hist), now(), *fields.values(), action_id))
        self.db.commit()
        return self.action(action_id)

    def findings_by_ids(self, ids: list[str]) -> list[sqlite3.Row]:
        if not ids:
            return []
        q = ("SELECT f.*, i.value AS identity, i.kind AS identity_kind FROM findings f "
             f"JOIN identities i ON i.id=f.identity_id WHERE f.id IN ({','.join('?' * len(ids))})")
        return list(self.db.execute(q, ids))

    def log_mail(self, profile: str, rows: list[tuple[str, str, str, str, str]], applied: bool) -> None:
        """Record classified messages (only non-keep verdicts) for the scorecard."""
        ts = now()
        self.db.executemany("INSERT INTO mail_log VALUES(?,?,?,?,?,?,?,?)",
                            [(ts, profile, *r, int(applied)) for r in rows])
        self.db.commit()

    def last_scan_id(self) -> int | None:
        row = self.db.execute("SELECT max(id) AS id FROM scans").fetchone()
        return row["id"]
