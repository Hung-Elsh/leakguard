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

    def log_mail(self, profile: str, rows: list[tuple[str, str, str, str, str]], applied: bool) -> None:
        """Record classified messages (only non-keep verdicts) for the scorecard."""
        ts = now()
        self.db.executemany("INSERT INTO mail_log VALUES(?,?,?,?,?,?,?,?)",
                            [(ts, profile, *r, int(applied)) for r in rows])
        self.db.commit()

    def last_scan_id(self) -> int | None:
        row = self.db.execute("SELECT max(id) AS id FROM scans").fetchone()
        return row["id"]
