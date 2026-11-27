"""ManifestTool: runs a tool described by a JSON definition (custom_tools.py, docs/ADD_A_TOOL.md).

The command is a list of words; {value} becomes the claimed email or username as one argument (no shell).
Output is read as JSON (a list of results, optionally inside the document), JSON lines, or lines matched by a
pattern with named groups. Each result that passes the optional filter becomes a finding, with title, link and
site filled from the result's fields ({field}, {field.sub}).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .. import custom_tools
from ..models import Finding, PluginResult, candidates_in_text
from ..runner import ToolError, expect_output, find_binary, run
from .base import SkipSource
from .tools import ToolPlugin


class _Fields(dict):
    def __missing__(self, key):
        return ""


def _dig(item, path: str):
    """'a.b.0.c' into nested dicts/lists; '' is the item itself."""
    cur = item
    for part in [p for p in (path or "").split(".") if p]:
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _flat(item, prefix: str = "") -> dict:
    """{'a': {'b': 1}} -> {'a.b': '1', ...}; templates use {a.b} (dots are fine in format keys)."""
    out = {}
    if isinstance(item, dict):
        for k, v in item.items():
            key = f"{prefix}{k}"
            if isinstance(v, (dict, list)):
                out.update(_flat(v, key + "."))
            out[key] = v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    elif isinstance(item, list):
        for i, v in enumerate(item):
            out.update(_flat(v, f"{prefix}{i}."))
    return out


def fill(template: str, item: dict) -> str:
    fields = _Fields(_flat(item))
    return re.sub(r"\{([^{}]+)\}", lambda m: str(fields[m.group(1)]), template or "").strip()


def results(output: dict, text: str) -> list[dict]:
    """The tool's results, as a list of dicts, before filtering."""
    fmt = output["format"]
    if fmt == "lines":
        rx = re.compile(output["pattern"])
        return [m.groupdict() for line in text.splitlines() if (m := rx.search(line))]
    if fmt == "jsonl":
        items = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except ValueError:
                    continue                          # progress lines mixed into the output
        return [i for i in items if isinstance(i, dict)]
    doc = _dig(json.loads(text), output.get("items", ""))
    if isinstance(doc, dict):
        doc = [{"key": k, **v} if isinstance(v, dict) else {"key": k, "value": v} for k, v in doc.items()] \
            if output.get("items_are") == "map" else [doc]
    return [i for i in (doc or []) if isinstance(i, dict)]


def keep(output: dict, item: dict) -> bool:
    rule = output.get("match")
    if not rule:
        return True
    value = _dig(item, rule.get("field", ""))
    if "equals" in rule:
        return value == rule["equals"] or str(value).lower() == str(rule["equals"]).lower()
    return bool(value)


class ManifestTool(ToolPlugin):
    def __init__(self, m: dict):
        self.m = m
        self.name = m["id"]
        self.kinds = tuple(m["checks"])
        self.ext = custom_tools.EXT[m["output"]["format"]]
        self.timeout = int(m.get("timeout", 300))
        self.binary = (m["command"][0],)
        self.origin = m.get("_origin", "user")

    def available(self, settings) -> bool:
        """Your tools join your real checks; the lab's example joins practice mode only."""
        return (self.origin == "lab") == settings.is_lab

    def check(self, ctx) -> None:
        if not self.available(ctx.settings):
            raise SkipSource("not part of this profile")
        if not ctx.settings.is_lab and not custom_tools.is_enabled(self.name):
            raise SkipSource("turned off (Settings, Extra checks)")
        if ctx.settings.tools_mode == "run":
            try:
                find_binary(*self.binary)
            except ToolError as e:
                raise SkipSource(str(e)) from e

    def command(self, value: str) -> list[str]:
        return [find_binary(*self.binary), *[a.replace("{value}", value) for a in self.m["command"][1:]]]

    def produce(self, ctx, value: str, kind: str, tmp: Path) -> Path | None:
        proc = run(self.command(value), tmp, self.timeout)
        out = tmp / f"out.{self.ext}"
        if proc.stdout.strip():
            out.write_text(proc.stdout)
        return expect_output(self.name, proc, out if out.exists() else None)

    def parse(self, ctx, text: str, value: str, kind: str) -> PluginResult:
        o, res = self.m["output"], PluginResult()
        for item in results(o, text):
            if not keep(o, item):
                continue
            title, url = fill(o["title"], item), fill(o.get("url", ""), item)
            site = fill(o.get("site", ""), item)
            if not title:
                continue
            res.findings.append(Finding(self.name, self.m["category"], title, url=url or None,
                                        evidence=fill(o.get("evidence", ""), item)[:500],
                                        severity=self.m["severity"], locator=(url or title).lower(),
                                        data={"site": site, "tool": self.name} if site else {"tool": self.name}))
            res.candidates += candidates_in_text(json.dumps(item), ctx.keyword, f"{self.name}:{value}")
        return res


def load_all() -> list[ManifestTool]:
    from ..paths import CONFIG
    taken = {s["id"] for s in json.loads((CONFIG / "sources.json").read_text())["sources"]}
    return [ManifestTool(m) for m in custom_tools.load() if not custom_tools.problems(m, taken)]
