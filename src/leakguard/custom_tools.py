"""Your own discovery tools, added without Python: one JSON definition per tool (docs/ADD_A_TOOL.md).

Where they live:
- ~/.config/leakguard/tools.d/<id>.json   your tools (internet profile; private, never in the repository)
- lab/tools.d/<id>.json                    practice-mode examples (lab profile; read recorded output only)

A definition says what the tool checks (emails and/or usernames), the command to run (a list of words; {value}
is replaced by one claimed email or username, as its own argument, never through a shell), and how to read
what it prints (JSON, one JSON per line, or lines matched by a pattern). The same safety rules as the built-in
tools apply: only claimed identities, the lab never runs tools, a timeout, raw output kept privately, and your
tool runs only while it is switched on.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import paths

ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
FORMATS = ("json", "jsonl", "lines")
CATEGORIES = ("account", "breach", "leak", "paste", "profile", "web_page", "code")
SEVERITIES = ("info", "low", "medium", "high")
EXT = {"json": "json", "jsonl": "jsonl", "lines": "txt"}


def user_dir() -> Path:
    return paths.USER_CONFIG / "tools.d"


def lab_dir() -> Path:
    return paths.ROOT / "lab" / "tools.d"


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:32]
    return s if s[:1].isalpha() else f"t-{s}"[:32]


def problems(m: dict, taken: set[str] = frozenset()) -> list[str]:
    """What is wrong with a definition, in plain words (empty: fine). `taken`: ids of built-in sources."""
    from .wording import CUSTOM as T
    out = []
    tid = m.get("id", "")
    if not ID_RE.match(tid):
        out.append(T["bad_id"])
    elif tid in taken:
        out.append(T["taken"].format(name=tid))
    if not str(m.get("name", "")).strip():
        out.append(T["no_name"])
    checks = m.get("checks") or []
    if not checks or set(checks) - {"email", "username"}:
        out.append(T["no_checks"])
    cmd = m.get("command") or []
    if not (isinstance(cmd, list) and cmd and all(isinstance(a, str) and a for a in cmd)):
        out.append(T["no_command"])
    elif not any("{value}" in a for a in cmd[1:]):
        out.append(T["no_value"])
    elif "/" in cmd[0] and not cmd[0].startswith(("/", "~")):
        out.append(T["bad_program"])
    o = m.get("output") or {}
    if o.get("format") not in FORMATS:
        out.append(T["no_format"])
    elif o["format"] == "lines":
        try:
            if not re.compile(o.get("pattern", "")).groupindex:
                out.append(T["pattern_names"])
        except re.error:
            out.append(T["bad_pattern"])
    if not str(o.get("title", "")).strip():
        out.append(T["no_title"])
    if m.get("category") not in CATEGORIES:
        out.append(T["no_category"])
    if m.get("severity") not in SEVERITIES:
        out.append(T["no_severity"])
    t = m.get("timeout", 300)
    if not isinstance(t, int) or not 10 <= t <= 3600:
        out.append(T["bad_timeout"])
    return out


def _read(path: Path, origin: str) -> dict | None:
    try:
        m = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(m, dict):
        return None
    m["_origin"], m["_path"] = origin, str(path)
    return m


def load(origin: str | None = None) -> list[dict]:
    """Every readable definition (origin 'user', 'lab', or both). Invalid ones are kept, flagged by problems()."""
    out = []
    for o, d in (("user", user_dir()), ("lab", lab_dir())):
        if origin in (None, o) and d.is_dir():
            out += [m for p in sorted(d.glob("*.json")) if (m := _read(p, o))]
    return out


def get(tid: str) -> dict | None:
    return next((m for m in load("user") if m.get("id") == tid), None)


def is_enabled(tid: str) -> bool:
    """Only your own tools, only while switched on (a definition file alone never makes a tool run)."""
    m = get(tid)
    return bool(m and m.get("enabled", False))


def save(m: dict) -> Path:
    clean = {k: v for k, v in m.items() if not k.startswith("_")}
    d = user_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    path = d / f"{clean['id']}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(clean, f, indent=2)
        f.write("\n")
    return path


def set_enabled(tid: str, on: bool) -> None:
    m = get(tid)
    if m:
        m["enabled"] = on
        save(m)


def remove(tid: str) -> bool:
    p = user_dir() / f"{tid}.json"
    if p.exists():
        p.unlink()
        return True
    return False
