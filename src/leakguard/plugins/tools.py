"""Plugins wrapping external OSINT tools. Lab: parse lab/fixtures. Internet: run the tool."""

from __future__ import annotations

import csv
import io
import json
import secrets
import threading
import time
from pathlib import Path

from ..models import Finding, PluginResult, breach_severity, candidates_in_text, mask
from ..runner import ToolError, expect_output, find_binary, run, tool_output
from .base import Context, Plugin, SkipSource


_LOCKS: dict[str, threading.Lock] = {}


class ToolPlugin(Plugin):
    """One instance of each tool at a time: parallel runs of the same tool trigger rate limits."""
    ext = "json"
    timeout = 600
    binary: tuple[str, ...] = ()

    def check(self, ctx: Context) -> None:
        if ctx.settings.tools_mode == "run":
            try:
                find_binary(*self.binary)
            except ToolError as e:
                raise SkipSource(str(e)) from e

    def produce(self, ctx: Context, value: str, kind: str, tmp: Path) -> Path | None:
        raise NotImplementedError

    def parse(self, ctx: Context, text: str, value: str, kind: str) -> PluginResult:
        raise NotImplementedError

    def run(self, ctx, ident):
        with _LOCKS.setdefault(self.name, threading.Lock()):
            text = tool_output(ctx.settings, ctx.guard, self.name, ident.value, self.ext,
                               lambda tmp: self.produce(ctx, ident.value, ident.kind, tmp))
        return self.parse(ctx, text, ident.value, ident.kind) if text else PluginResult()


def account(source: str, site: str, url: str, evidence: str = "", data: dict | None = None) -> Finding:
    return Finding(source, "account", f"Account on {site}", url=url, evidence=evidence,
                   severity="low", locator=site.lower(), data=data or {})


class Holehe(ToolPlugin):
    name, kinds, ext, timeout, binary = "holehe", ("email",), "csv", 600, ("holehe",)

    def produce(self, ctx, value, kind, tmp):
        # -NP: no password-recovery probes, so no reset mails are triggered
        proc = run([find_binary("holehe"), value, "--only-used", "--no-color", "--no-clear", "-NP", "-C"],
                   tmp, self.timeout)
        files = sorted(tmp.glob("holehe_*_results.csv"))
        return expect_output("holehe", proc, files[-1] if files else None)

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        for row in csv.DictReader(io.StringIO(text)):
            res.checked += 1
            if row.get("exists") != "True":
                if row.get("rateLimit") == "True":
                    res.fail("rate limited")             # unknown, not "no account"
                continue
            extra = {k: row[k] for k in ("emailrecovery", "phoneNumber", "others") if row.get(k) not in (None, "", "None")}
            res.findings.append(account(self.name, row["domain"] or row["name"], f"https://{row['domain']}",
                                        ", ".join(f"{k}: {v}" for k, v in extra.items()), extra))
            for v in extra.values():
                res.candidates += candidates_in_text(str(v), ctx.keyword, f"holehe:{row['domain']}")
        return res


class H8mail(ToolPlugin):
    name, kinds, timeout, binary = "h8mail", ("email",), 600, ("h8mail",)

    def produce(self, ctx, value, kind, tmp):
        out = tmp / "h8mail.json"
        return expect_output("h8mail", run([find_binary("h8mail"), "-t", value, "-j", str(out)], tmp, self.timeout), out)

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        for t in json.loads(text).get("targets", []):
            entries = t.get("data") or []
            flat = [e for group in entries for e in (group if isinstance(group, list) else [group])]
            for e in flat:
                if not isinstance(e, str) or ":" not in e:
                    continue
                src, val = e.split(":", 1)
                secret = "PASS" in src.upper() or "HASH" in src.upper() or "LOCAL" in src.upper()
                res.findings.append(Finding(
                    self.name, "breach", f"{src.strip()} hit", evidence=mask(val) if secret else val[:200],
                    severity="high" if secret else "medium", locator=f"{src}:{mask(val) if secret else val}"))
        return res


class GHunt(ToolPlugin):
    name, kinds, timeout, binary = "ghunt", ("email",), 300, ("ghunt",)

    def produce(self, ctx, value, kind, tmp):
        out = tmp / "ghunt.json"
        return expect_output("ghunt", run([find_binary("ghunt"), "email", value, "--json", str(out)], tmp, self.timeout), out)

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        for container, obj in json.loads(text).items():
            prof = obj.get("profile") or {}
            gaia = prof.get("personId", "")
            names = [n.get("fullname") for n in (prof.get("names") or {}).values() if n.get("fullname")]
            photos = [p.get("url") for p in (prof.get("profilePhotos") or {}).values() if not p.get("isDefault")]
            covers = [p.get("url") for p in (prof.get("coverPhotos") or {}).values() if not p.get("isDefault")]
            ev = [f"name: {', '.join(names)}" if names else "", "custom profile photo" if photos else "",
                  "custom cover photo" if covers else ""]
            res.findings.append(Finding(
                self.name, "profile", f"Google account (Gaia {gaia})", url=f"https://www.google.com/maps/contrib/{gaia}",
                evidence="; ".join(e for e in ev if e) or "account exists", severity="low", locator=f"gaia:{gaia}",
                data={"gaia_id": gaia, "names": names, "photos": photos, "covers": covers, "container": container}))
            stats = (obj.get("maps") or {}).get("stats") or {}
            if any(stats.values()):
                res.findings.append(Finding(
                    self.name, "profile", "Public Google Maps contributions",
                    url=f"https://www.google.com/maps/contrib/{gaia}/reviews",
                    evidence=", ".join(f"{k}: {v}" for k, v in stats.items()), severity="medium",
                    locator=f"maps:{gaia}", data=stats))
            cal = obj.get("calendar") or {}
            if cal.get("details") or cal.get("events"):
                res.findings.append(Finding(
                    self.name, "profile", "Public Google Calendar", evidence="calendar is publicly readable",
                    severity="medium", locator=f"calendar:{gaia}"))
            if obj.get("play_games"):
                res.findings.append(Finding(self.name, "profile", "Google Play Games profile",
                                            severity="low", locator=f"games:{gaia}"))
        return res


class Mosint(ToolPlugin):
    name, kinds, timeout, binary = "mosint", ("email",), 300, ("mosint", "~/go/bin/mosint")

    def produce(self, ctx, value, kind, tmp):
        out = tmp / "mosint.json"
        return expect_output("mosint", run([find_binary(*self.binary), value, "-s", "-o", str(out)], tmp, self.timeout), out)

    def parse(self, ctx, text, value, kind):
        d, res = json.loads(text), PluginResult()
        for b in (d.get("breachdirectory") or {}).get("result") or []:
            srcs = b.get("sources") or ["unknown"]
            for s in srcs if isinstance(srcs, list) else [srcs]:
                res.findings.append(Finding(self.name, "breach", f"{s} leak (BreachDirectory)",
                                            evidence="password hash/partial exposed" if b.get("has_password") else "",
                                            severity="high" if b.get("has_password") else "medium", locator=f"bd:{s}"))
        for b in d.get("haveibeenpwned") or []:
            name = b.get("Name") if isinstance(b, dict) else str(b)
            res.findings.append(Finding(self.name, "breach", f"{name} breach (HIBP via mosint)",
                                        severity="medium", locator=f"hibp:{name}"))
        ix = d.get("intelx") if isinstance(d.get("intelx"), dict) else {}
        for r in ix.get("records") or []:
            res.findings.append(Finding(self.name, "leak", f"IntelX: {r.get('name')}", severity="medium",
                                        locator=f"ix:{r.get('systemid')}"))
        for p in d.get("psbdmp") or []:
            pid = p.get("id") if isinstance(p, dict) else str(p)
            res.findings.append(Finding(self.name, "paste", f"Pastebin dump {pid}", url=f"https://pastebin.com/{pid}",
                                        severity="high", locator=f"psbdmp:{pid}"))
        for site in ("instagram", "spotify", "twitter"):
            if d.get(f"{site}_exists"):
                res.findings.append(account(self.name, site, f"https://{site}.com"))
        for url in d.get("google_search") or []:
            res.findings.append(Finding(self.name, "web_page", url, url=url, severity="medium", locator=url))
            res.candidates += candidates_in_text(url, ctx.keyword, "mosint:google")
        details = (d.get("emailrep") or {}).get("details") or {}
        if details.get("credentials_leaked") or details.get("data_breach"):
            res.findings.append(Finding(self.name, "breach", "EmailRep: credentials leaked / in data breach",
                                        evidence=f"first seen {details.get('first_seen') or '?'}", severity="medium",
                                        locator="emailrep"))
        for prof in details.get("profiles") or []:
            res.findings.append(account(self.name, prof, "", "listed by EmailRep"))
        return res


class SocialScan(ToolPlugin):
    name, kinds, timeout, binary = "socialscan", ("email", "username"), 300, ("socialscan",)

    def produce(self, ctx, value, kind, tmp):
        out = tmp / "socialscan.json"
        return expect_output("socialscan", run([find_binary("socialscan"), value, "--json", str(out)], tmp, self.timeout), out)

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        for rows in json.loads(text).values():
            for r in rows:
                res.checked += 1
                if r.get("success") != "True":
                    res.fail(str(r.get("message", "no answer")).split(" - ")[0][:60])
                    continue
                # values are stringified; "available: False" on a valid query = taken/registered
                if r.get("success") == "True" and r.get("valid") == "True" and r.get("available") == "False":
                    res.findings.append(account(self.name, r.get("platform", "?"), r.get("link", ""),
                                                f"{kind} is registered"))
        return res


class Sherlock(ToolPlugin):
    name, kinds, ext, timeout, binary = "sherlock", ("username",), "csv", 900, ("sherlock",)

    def produce(self, ctx, value, kind, tmp):
        run([find_binary("sherlock"), value, "--csv", "--folderoutput", str(tmp), "--print-found",
             "--no-color", "--timeout", "15"], tmp, self.timeout)
        files = list(tmp.rglob(f"{value}.csv"))
        return files[0] if files else None

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        for row in csv.DictReader(io.StringIO(text)):
            if row.get("exists") == "Claimed":
                res.findings.append(account(self.name, row["name"], row["url_user"]))
        return res


class Maigret(ToolPlugin):
    name, kinds, timeout, binary = "maigret", ("username",), 1200, ("maigret",)

    def produce(self, ctx, value, kind, tmp):
        run([find_binary("maigret"), value, "-J", "simple", "--folderoutput", str(tmp), "--no-color",
             "--no-progressbar", "--timeout", "20"], tmp, self.timeout)
        files = list(tmp.rglob(f"report_{value}_simple.json"))
        return files[0] if files else None

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        for site, info in json.loads(text).items():
            st = info.get("status") or {}
            res.checked += 1
            if st.get("status") != "Claimed":
                if st.get("status") not in ("Available", "Illegal"):
                    res.fail(f"maigret: {st.get('status') or 'unknown'}")
                continue
            ids = st.get("ids") or {}
            res.findings.append(account(self.name, site, st.get("url") or info.get("url_user", ""),
                                        ", ".join(f"{k}={v}" for k, v in list(ids.items())[:6]),
                                        {"ids": ids, "tags": st.get("tags")}))
            res.candidates += candidates_in_text(json.dumps(ids), ctx.keyword, f"maigret:{site}")
        return res


class Blackbird(ToolPlugin):
    name, kinds, timeout = "blackbird", ("username", "email"), 900
    binary = ("~/tools/blackbird/blackbird.py",)

    def produce(self, ctx, value, kind, tmp):
        script = Path(find_binary(*self.binary))
        home = script.parent
        py = home / ".venv/bin/python"
        started = time.time()
        flag = "-e" if kind == "email" else "-u"
        data = home / "data" / ("email-data.json" if kind == "email" else "wmn-data.json")
        update = [] if not data.exists() else ["--no-update"]       # first run: let blackbird fetch its site list
        proc = run([str(py), str(script), flag, value, "--json", *update], home, self.timeout)
        files = [p for p in (home / "results").rglob("*.json") if p.stat().st_mtime >= started]
        return expect_output("blackbird", proc, max(files, key=lambda p: p.stat().st_mtime) if files else None)

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        rows = json.loads(text)
        for r in rows if isinstance(rows, list) else rows.get("results", []):
            res.checked += 1
            if r.get("status") == "ERROR":
                res.fail("blackbird: site error")
            if r.get("status") == "FOUND":
                res.findings.append(account(self.name, r.get("name", "?"), r.get("url", ""),
                                            r.get("category", ""), {"metadata": r.get("metadata")}))
                res.candidates += candidates_in_text(json.dumps(r.get("metadata") or ""), ctx.keyword,
                                                     f"blackbird:{r.get('name')}")
        return res


SPIDERFOOT_TYPES = {
    "Account on External Site": "account", "Hacked Email Address": "breach",
    "Hacked Account on External Site": "breach", "Leak Site URL": "paste", "Leak Site Content": "paste",
    "Email Address - Generic": None, "Similar Account on External Site": None,
}


class SpiderFoot(ToolPlugin):
    name, kinds, timeout, binary = "spiderfoot", ("email", "username"), 3600, ("spiderfoot",)

    def produce(self, ctx, value, kind, tmp):
        target = value if kind == "email" else f'"{value}"'   # quoted target = username in SpiderFoot
        p = run([find_binary("spiderfoot"), "-s", target, "-u", "passive", "-o", "json", "-q",
                 "-max-threads", "10"], tmp, self.timeout)
        out = tmp / "spiderfoot.json"
        if p.stdout.strip():
            out.write_text(p.stdout)
        return expect_output("spiderfoot", p, out if p.stdout.strip() else None)

    def parse(self, ctx, text, value, kind):
        res = PluginResult()
        text = text.strip()
        if not text.startswith("["):
            text = f"[{text}]"
        for ev in json.loads(text):
            data = str(ev.get("data", ""))
            cat = SPIDERFOOT_TYPES.get(ev.get("type", ""))
            res.candidates += candidates_in_text(data, ctx.keyword, f"spiderfoot:{ev.get('module')}")
            if not cat:
                continue
            first = data.splitlines()[0][:200] if data else ""
            res.findings.append(Finding(self.name, cat, f"{ev.get('type')}: {first}", evidence=f"module {ev.get('module')}",
                                        severity="high" if cat in ("breach", "paste") else "low",
                                        locator=f"{ev.get('type')}:{first}"))
        return res


TOOL_PLUGINS = [Holehe(), H8mail(), GHunt(), Mosint(), SocialScan(), Sherlock(), Maigret(), Blackbird(), SpiderFoot()]
