"""Fill an opt-out form with Playwright. Always screenshots the filled form; clicks submit only with confirm.
Every request the page makes is checked: lab = lab scope only; internet = the form's own host(s)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..config import Settings
from ..paths import DATA
from ..scope import ScopeError, ScopeGuard

SHOTS = DATA / "screenshots"
CHROMIUM = "/usr/bin/chromium"


@dataclass
class FormResult:
    filled: Path
    submitted: bool = False
    after: Path | None = None
    success: bool | None = None
    blocked: list[str] | None = None


def _allowed(settings: Settings, guard: ScopeGuard, form_url: str):
    hosts = {urlsplit(form_url).hostname or ""} | set(settings.removal.get("allowed_form_hosts", []))

    def ok(url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme in ("data", "blob", "about"):
            return True
        if settings.is_lab:
            try:
                guard.check_url(url, "brokers")
                return True
            except ScopeError:
                return False
        h = (parts.hostname or "").lower()
        return any(h == x or h.endswith("." + x) for x in hosts)
    return ok


def fill(settings: Settings, guard: ScopeGuard, action_id: int, url: str, form: dict, values: dict,
         confirm: bool) -> FormResult:
    from playwright.sync_api import sync_playwright

    SHOTS.mkdir(parents=True, exist_ok=True)
    SHOTS.chmod(0o700)
    ok, blocked = _allowed(settings, guard, url), []

    def route(r):
        if ok(r.request.url):
            r.continue_()
        else:
            blocked.append(r.request.url)
            r.abort()

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM if os.path.exists(CHROMIUM) else None, headless=True)
        page = browser.new_page()
        page.route("**/*", route)
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        for selector, template in form.get("fields", {}).items():
            page.fill(selector, template.format(**values))
        res = FormResult(filled=SHOTS / f"action-{action_id}-filled.png", blocked=blocked)
        page.screenshot(path=str(res.filled), full_page=True)
        if confirm:
            page.click(form["submit"])
            page.wait_for_load_state("domcontentloaded", timeout=30000)
            res.submitted = True
            res.after = SHOTS / f"action-{action_id}-after.png"
            page.screenshot(path=str(res.after), full_page=True)
            if form.get("success_text"):
                res.success = form["success_text"].lower() in page.content().lower()
        browser.close()
    for f in (res.filled, res.after):
        if f and f.exists():
            f.chmod(0o600)
    return res
