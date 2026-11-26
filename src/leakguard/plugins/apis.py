"""Plugins for HTTP APIs. All requests go through ctx.http, which enforces scope and rate limits."""

from __future__ import annotations

import hashlib
import time
from urllib.parse import quote, urlsplit

from ..models import Finding, Identity, PluginResult, candidates_in_text
from .base import Context, Plugin, SkipSource

PASTE_HOSTS = ("pastebin.com", "ghostbin", "paste.ee", "justpaste.it", "controlc.com", "rentry.co", "hastebin")


def _endpoint(ctx: Context, name: str) -> str:
    url = ctx.settings.endpoints.get(name)
    if not url:
        raise SkipSource(f"no endpoint '{name}' in profile {ctx.settings.profile}")
    return url


class HIBP(Plugin):
    name, kinds, needs = "hibp", ("email",), ("HIBP_API_KEY",)

    def run(self, ctx, ident):
        base = _endpoint(ctx, "hibp")
        res = PluginResult()
        with ctx.http.client(self.name, {"hibp-api-key": ctx.settings.key("HIBP_API_KEY")}) as c:
            r = c.get(f"{base}/breachedaccount/{quote(ident.value)}", params={"truncateResponse": "false"})
            if r.status_code not in (200, 404):
                r.raise_for_status()
            for b in r.json() if r.status_code == 200 else []:
                classes = b.get("DataClasses", [])
                res.findings.append(Finding(
                    self.name, "breach", f"{b.get('Title', b['Name'])} breach ({b.get('BreachDate', '?')})",
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{b['Name']}",
                    evidence="exposed: " + ", ".join(classes),
                    severity="high" if "Passwords" in classes else "medium",
                    locator=b["Name"], data={"domain": b.get("Domain"), "data_classes": classes,
                                             "verified": b.get("IsVerified")}))
            r = c.get(f"{base}/pasteaccount/{quote(ident.value)}")
            if r.status_code not in (200, 404):
                r.raise_for_status()
            for p in r.json() if r.status_code == 200 else []:
                url = f"https://pastebin.com/{p['Id']}" if p.get("Source") == "Pastebin" else ""
                res.findings.append(Finding(
                    self.name, "paste", f"Paste on {p.get('Source')}: {p.get('Title') or p['Id']}", url=url,
                    evidence=f"{p.get('EmailCount', '?')} emails in paste, {p.get('Date') or 'date unknown'}",
                    severity="high", locator=f"{p.get('Source')}:{p['Id']}", data=p))
        return res


class IntelX(Plugin):
    name, kinds, needs = "intelx", ("email", "username", "keyword"), ("INTELX_API_KEY",)

    def run(self, ctx, ident):
        base = _endpoint(ctx, "intelx")
        res = PluginResult()
        with ctx.http.client(self.name, {"x-key": ctx.settings.key("INTELX_API_KEY")}) as c:
            r = c.post(f"{base}/intelligent/search",
                       json={"term": ident.value, "maxresults": 50, "media": 0, "sort": 2, "terminate": []})
            r.raise_for_status()
            sid = r.json()["id"]
            records = []
            for _ in range(8):
                r = c.get(f"{base}/intelligent/search/result", params={"id": sid, "limit": 50})
                r.raise_for_status()
                body = r.json()
                records += body.get("records") or []
                if body.get("status") in (1, 2):      # 1 = done, 2 = id not found
                    break
                if body.get("status") == 3:           # no results yet, keep polling
                    time.sleep(0 if ctx.settings.is_lab else 2)
            c.get(f"{base}/intelligent/search/terminate", params={"id": sid})
        for rec in records:
            name = rec.get("name") or rec.get("systemid")
            res.findings.append(Finding(
                self.name, "leak", f"IntelX: {name}", url=f"https://intelx.io/?did={rec.get('systemid')}",
                evidence=f"bucket {rec.get('bucket')}, date {rec.get('date')}", severity="medium",
                locator=rec.get("systemid", name), data={k: rec.get(k) for k in ("bucket", "date", "media", "added")}))
            res.candidates += candidates_in_text(str(name), ctx.keyword, f"intelx:{rec.get('systemid')}")
        return res


class GoogleSearch(Plugin):
    """Google Programmable Search. 100 free queries/day, so queries are few and exact."""
    name, kinds, needs = "pse", ("email", "username", "keyword"), ("GOOGLE_PSE_API_KEY", "GOOGLE_PSE_CX")

    def queries(self, ident: Identity) -> list[str]:
        if ident.kind == "keyword":
            return [f'"{ident.value}"', f'"{ident.value}" site:pastebin.com OR site:github.com OR site:reddit.com']
        return [f'"{ident.value}"']

    def run(self, ctx, ident):
        base = _endpoint(ctx, "pse")
        res = PluginResult()
        pages = 3 if ident.kind == "keyword" else 1
        seen: set[str] = set()
        with ctx.http.client(self.name) as c:
            for q in self.queries(ident):
                for page in range(pages):
                    r = c.get(base, params={"key": ctx.settings.key("GOOGLE_PSE_API_KEY"),
                                            "cx": ctx.settings.key("GOOGLE_PSE_CX"),
                                            "q": q, "num": 10, "start": 1 + page * 10})
                    r.raise_for_status()
                    items = r.json().get("items") or []
                    for it in items:
                        link, text = it.get("link", ""), f"{it.get('title', '')} {it.get('snippet', '')}"
                        if link in seen:
                            continue
                        seen.add(link)
                        host = urlsplit(link).hostname or ""
                        is_paste = any(h in host for h in PASTE_HOSTS)
                        res.findings.append(Finding(
                            self.name, "paste" if is_paste else "web_page", it.get("title") or link, url=link,
                            evidence=it.get("snippet", "")[:300], severity="high" if is_paste else "medium",
                            locator=link, data={"query": q, "host": host}))
                        res.candidates += candidates_in_text(f"{text} {link}", ctx.keyword, f"pse:{link}")
                    if len(items) < 10:
                        break
        return res


class LeakCheck(Plugin):
    name, kinds = "leakcheck", ("email", "username")

    def run(self, ctx, ident):
        base = _endpoint(ctx, "leakcheck")
        res = PluginResult()
        with ctx.http.client(self.name) as c:
            r = c.get(base, params={"check": ident.value})
            r.raise_for_status()
            body = r.json()
        if not body.get("success") or not body.get("found"):
            return res
        fields = body.get("fields") or []
        for src in body.get("sources") or []:
            res.findings.append(Finding(
                self.name, "breach", f"{src.get('name')} leak ({src.get('date') or 'date unknown'})",
                evidence="fields: " + ", ".join(fields), severity="high" if "password" in fields else "medium",
                locator=src.get("name", ""), data=src))
        return res


class Psbdmp(Plugin):
    name, kinds = "psbdmp", ("email", "keyword")

    def run(self, ctx, ident):
        base = _endpoint(ctx, "psbdmp")
        res = PluginResult()
        with ctx.http.client(self.name) as c:
            r = c.get(f"{base}/search/{quote(ident.value)}")
            if r.status_code == 404:
                return res
            r.raise_for_status()
            rows = r.json()
        for p in rows if isinstance(rows, list) else rows.get("data", []):
            text = p.get("text", "")
            res.findings.append(Finding(
                self.name, "paste", f"Pastebin dump {p['id']}", url=f"https://pastebin.com/{p['id']}",
                evidence=text[:200], severity="high", locator=p["id"],
                data={"time": p.get("time"), "length": p.get("length"), "tags": p.get("tags")}))
            res.candidates += candidates_in_text(text, ctx.keyword, f"psbdmp:{p['id']}")
        return res


class Gravatar(Plugin):
    name, kinds = "gravatar", ("email",)

    def run(self, ctx, ident):
        base = _endpoint(ctx, "gravatar")
        h = hashlib.sha256(ident.value.strip().lower().encode()).hexdigest()
        res = PluginResult()
        with ctx.http.client(self.name) as c:
            r = c.get(f"{base}/profiles/{h}")
        if r.status_code == 404:
            return res
        r.raise_for_status()
        p = r.json()
        shown = {k: p[k] for k in ("display_name", "location", "description", "job_title", "company") if p.get(k)}
        res.findings.append(Finding(
            self.name, "profile", f"Gravatar profile: {p.get('display_name') or h[:12]}",
            url=p.get("profile_url", f"https://gravatar.com/{h}"),
            evidence=", ".join(f"{k}={v}" for k, v in shown.items()) or "public avatar",
            severity="low", locator=h, data=shown))
        for acc in p.get("verified_accounts") or []:
            res.candidates += candidates_in_text(str(acc.get("url", "")), ctx.keyword, "gravatar")
        return res


class PGP(Plugin):
    name, kinds = "pgp", ("email",)

    def run(self, ctx, ident):
        res = PluginResult()
        with ctx.http.client(self.name) as c:
            r = c.get(f"{_endpoint(ctx, 'openpgp')}/by-email/{quote(ident.value)}")
            if r.status_code == 200:
                res.findings.append(Finding(
                    self.name, "keyserver", "PGP key on keys.openpgp.org",
                    url=f"https://keys.openpgp.org/search?q={quote(ident.value)}",
                    evidence="verified key published with this address", severity="low", locator="keys.openpgp.org"))
            r = c.get(_endpoint(ctx, "ubuntu_keyserver"),
                      params={"op": "index", "options": "mr", "search": ident.value})
            if r.status_code == 200 and "pub:" in r.text:
                uids = [ln.split(":")[1] for ln in r.text.splitlines() if ln.startswith("uid:")]
                res.findings.append(Finding(
                    self.name, "keyserver", "PGP key on keyserver.ubuntu.com",
                    url=f"https://keyserver.ubuntu.com/pks/lookup?search={quote(ident.value)}&op=index",
                    evidence="uids: " + "; ".join(uids)[:300], severity="low", locator="keyserver.ubuntu.com",
                    data={"uids": uids}))
        return res


class GitHub(Plugin):
    name, kinds = "github", ("email", "username", "keyword")

    def run(self, ctx, ident):
        base = _endpoint(ctx, "github")
        headers = {"Accept": "application/vnd.github+json"}
        if tok := ctx.settings.key("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {tok}"
        res = PluginResult()
        with ctx.http.client(self.name, headers) as c:
            if ident.kind == "email":
                r = c.get(f"{base}/search/commits", params={"q": f"author-email:{ident.value}", "per_page": 100})
                r.raise_for_status()
                repos: dict[str, list] = {}
                for it in r.json().get("items", []):
                    repos.setdefault(it["repository"]["full_name"], []).append(it)
                for repo, commits in repos.items():
                    res.findings.append(Finding(
                        self.name, "code", f"{len(commits)} commit(s) in {repo} show this email",
                        url=commits[0].get("html_url", f"https://github.com/{repo}"),
                        evidence="; ".join(c_["commit"]["message"].splitlines()[0][:60] for c_ in commits[:3]),
                        severity="medium", locator=repo,
                        data={"repo": repo, "commits": [c_.get("sha") for c_ in commits]}))
                if tok:
                    r = c.get(f"{base}/search/code", params={"q": f'"{ident.value}"', "per_page": 50})
                    if r.status_code == 200:
                        for it in r.json().get("items", []):
                            res.findings.append(Finding(
                                self.name, "code", f"Email in {it['repository']['full_name']}/{it['path']}",
                                url=it.get("html_url", ""), severity="medium", locator=it.get("html_url", it["path"])))
            else:
                r = c.get(f"{base}/search/users", params={"q": f"{ident.value} in:login", "per_page": 50})
                r.raise_for_status()
                for u in r.json().get("items", []):
                    login = u["login"]
                    if ctx.keyword in login.lower():
                        res.findings.append(Finding(
                            self.name, "account", f"GitHub user {login}", url=u.get("html_url", ""),
                            severity="low", locator=login))
                        res.candidates += candidates_in_text(login, ctx.keyword, f"github:{login}")
        return res


class Brokers(Plugin):
    """Search each data broker listed in the profile for the identity."""
    name, kinds = "brokers", ("email", "username", "keyword")

    def run(self, ctx, ident):
        res = PluginResult()
        if not ctx.settings.brokers:
            raise SkipSource("no brokers configured for this profile")
        with ctx.http.client(self.name) as c:
            for b in ctx.settings.brokers:
                url = b["search_url"].format(q=quote(ident.value))
                r = c.get(url)
                if r.status_code == 200 and ident.value.lower() in r.text.lower():
                    res.findings.append(Finding(
                        self.name, "broker", f"Listed on {b['name']}", url=url,
                        evidence=f"search page for '{ident.value}' shows a matching record",
                        severity="high", locator=b["id"], data={"broker": b["id"]}))
                    res.candidates += candidates_in_text(r.text, ctx.keyword, f"broker:{b['id']}")
        return res


API_PLUGINS = [HIBP(), IntelX(), GoogleSearch(), LeakCheck(), Psbdmp(), Gravatar(), PGP(), GitHub(), Brokers()]
