"""Stop the owner's identity from leaking into the repository.

The terms come from the private identity file (keyword, emails, usernames) and from every identity in
the internet store (claimed or candidate: old addresses found by scans are personal too).
`check()` scans the files git would commit; the pre-commit hook runs it on staged files.
"""

from __future__ import annotations

import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import mask
from .paths import DATA, ROOT, USER_IDENTITY


@dataclass
class Hit:
    path: str
    line: int
    term: str


def private_terms() -> set[str]:
    terms: set[str] = set()
    if USER_IDENTITY.exists():
        ident = yaml.safe_load(USER_IDENTITY.read_text()) or {}
        terms.add(str(ident.get("keyword") or ""))
        terms.update(map(str, ident.get("emails") or []))
        terms.update(map(str, ident.get("usernames") or []))
        terms.add(str((ident.get("owner") or {}).get("full_name") or ""))
    db = DATA / "internet.sqlite"
    if db.exists():
        with sqlite3.connect(db) as con:
            try:
                terms.update(r[0] for r in con.execute("SELECT value FROM identities WHERE status != 'rejected'"))
            except sqlite3.OperationalError:
                pass
    return {t.strip().lower() for t in terms if len(t.strip()) >= 4}


def _git(*args: str) -> list[str]:
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ln for ln in out.split("\0") if ln]


def candidate_files(staged: bool) -> list[str]:
    if staged:
        return _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return _git("ls-files", "--cached", "--others", "--exclude-standard", "-z")


def _read(path: str, staged: bool) -> str | None:
    if staged:   # check the staged content, not the working copy
        p = subprocess.run(["git", "show", f":{path}"], cwd=ROOT, capture_output=True)
        raw = p.stdout
    else:
        f = ROOT / path
        if not f.is_file():
            return None
        raw = f.read_bytes()
    if b"\0" in raw[:4096]:
        return None   # binary
    return raw.decode(errors="replace")


def check(staged: bool = False) -> tuple[list[Hit], int]:
    """Return (hits, number of private terms). Paths are also checked, not only contents."""
    terms = private_terms()
    hits: list[Hit] = []
    if not terms:
        return hits, 0
    for path in candidate_files(staged):
        low_path = path.lower()
        hits += [Hit(path, 0, t) for t in terms if t in low_path]
        text = _read(path, staged)
        if text is None:
            continue
        for n, line in enumerate(text.lower().splitlines(), 1):
            hits += [Hit(path, n, t) for t in terms if t in line]
    return hits, len(terms)


HOOK = """#!/bin/sh
# Installed by `leakguard install-hook`: block commits that contain the owner's private identity.
exec "{exe}" leakcheck --staged
"""


def install_hook() -> Path:
    hook = ROOT / ".git" / "hooks" / "pre-commit"
    if not hook.parent.exists():
        raise FileNotFoundError("not a git repository (no .git/hooks)")
    exe = Path(sys.argv[0]).resolve()
    if hook.exists() and "leakguard" not in hook.read_text():
        raise FileExistsError(f"{hook} exists and is not ours; not overwriting")
    hook.write_text(HOOK.format(exe=exe))
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook


def describe(hit: Hit) -> str:
    where = f"{hit.path}:{hit.line}" if hit.line else f"{hit.path} (file name)"
    return f"{where}: contains {mask(hit.term)}"
