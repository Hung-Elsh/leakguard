"""Plain words for everything the desktop app shows.

The core keeps its precise terms (candidate, finding, disposition, partial, scope_blocked...) and logs errors in
full. This module turns them into short sentences a non-technical person understands. The full detail stays
available behind a "Details" fold-out. tests/test_wording.py checks that every internal value has a text here and
that none of them uses technical jargon.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

# ---- what was found ------------------------------------------------------------------------------
SEVERITY = {"high": "Serious", "medium": "Medium", "low": "Minor", "info": "Just a mention"}
SEVERITY_HELP = {
    "high": "A password, or your address on a public page, may be out there.",
    "medium": "Your address is in a leak, but we don't know what else was in it.",
    "low": "An account or a page in your name. Worth tidying up.",
    "info": "Something similar to your name. Probably nothing to do.",
}
CATEGORY = {
    "breach": "Data breach", "leak": "Leaked file", "paste": "Public text post", "account": "Account",
    "profile": "Public profile", "web_page": "Web page", "broker": "People-search site", "code": "Public code",
    "keyserver": "Public key directory",
}

# ---- your answers --------------------------------------------------------------------------------
VERDICT_BUTTON = {"open": "Remove it", "protect": "It's mine: keep & secure", "accepted": "Ignore",
                  "false_positive": "Not me"}
VERDICT_DONE = {
    "open": "We'll work on removing it.",
    "protect": "Added to your security checklist.",
    "accepted": "Okay, we'll leave it as it is.",
    "false_positive": "Got it, that's not you.",
}
IDENTITY_STATUS = {"candidate": "Is this you?", "claimed": "Yours", "rejected": "Not yours"}
IDENTITY_DONE = {"claimed": "Added. We'll check {value} too.", "rejected": "Okay, we'll ignore {value}."}
IDENTITY_KIND = {"email": "Email address", "username": "Username", "keyword": "Your keyword"}

# ---- checks --------------------------------------------------------------------------------------
CHECK_KIND = {"quick": "Quick check", "full": "Full check", "mail": "Check my mail"}
CHECK_KIND_HELP = {
    "quick": "The fast sources only. A few minutes.",
    "full": "Every source, including the slow account searches. Can take half an hour.",
    "mail": "Looks through your inbox for unwanted mail. Nothing is moved until you say so.",
}
RUN_STATUS = {"ok": "Done", "partial": "Partly done", "skipped": "Not used", "error": "Didn't work",
              "scope_blocked": "Blocked for your safety"}
SOURCE = {
    "hibp": "known data breaches", "intelx": "archives of leaked files", "pse": "web search",
    "brave": "web search", "leakcheck": "leaked password lists", "psbdmp": "public text posts",
    "gravatar": "profile pictures", "pgp": "public key directories", "github": "public code",
    "brokers": "people-search sites", "holehe": "sites where your email has an account",
    "h8mail": "leaked password lists", "ghunt": "your public Google profile", "mosint": "email lookups",
    "socialscan": "account sign-up checks", "sherlock": "usernames across many sites",
    "maigret": "usernames across many sites", "blackbird": "accounts across many sites",
    "spiderfoot": "leak search engines",
}

# ---- clean-up ------------------------------------------------------------------------------------
ACTION_KIND = {
    "account_delete": "Delete your account on {target}",
    "data_erasure": "Ask {target} to erase your data",
    "leak_removal": "Ask {target} to remove leaked files with your address",
    "paste_report": "Ask {target} to take down a post with your data",
    "broker_optout": "Remove yourself from {target}",
    "protect_checklist": "Secure the accounts you keep",
    "rotate_password": "Change passwords that leaked",
    "hibp_optout": "Hide your address from public breach searches",
    "manual": "{target}",
}
ACTION_STATE = {"planned": "To do", "drafted": "Ready to send", "requested": "Waiting for the site",
                "acknowledged": "The site replied", "removed": "Removed, we're double-checking",
                "verified": "Confirmed gone", "done": "Done", "skipped": "Skipped"}
METHOD_BUTTON = {"email": "Review & send", "form": "Review & submit", "manual": "Open the page",
                 "checklist": "Show the steps"}
SEND_CONFIRM = "Send this email from {sender} to {to}?"
SUBMIT_CONFIRM = "Submit this form to {target} with {sender}?"

# ---- problems: one sentence each, by kind; the logged detail stays behind "Details" -------------
PROBLEM = {
    "off": "Turned off.",
    "needs_key": "Needs a free key. You can add it under Settings, Search services.",
    "not_installed": "This extra check isn't installed. You can add it under Settings, Extra checks.",
    "offline": "Couldn't reach the service. Check your internet connection.",
    "slow": "The service took too long to answer. We'll try again next time.",
    "busy": "The service is busy right now. We'll try again next time.",
    "refused": "The service didn't accept your key. Check it under Settings, Search services.",
    "their_side": "The service had a problem on its side. We'll try again next time.",
    "some_sites": "Some sites didn't answer. We'll try them again next time, and nothing counts as removed "
                  "because of it.",
    "blocked": "Blocked: LeakGuard only contacts services it is allowed to.",
    "sign_in": "The sign-in for this check has expired. Sign in again under Settings, Extra checks.",
    "other": "Something went wrong with this check. The details are saved.",
}


def problem_kind(status: str, error: str = "", error_type: str = "", http_status: int | None = None) -> str:
    """Classify a logged source run into one PROBLEM key ('' when the run went fine)."""
    e = (error or "").lower()
    if status == "ok":
        return ""
    if status == "partial":
        return "some_sites"
    if status == "scope_blocked":
        return "blocked"
    if status == "skipped" or error_type == "SkipSource":
        return "needs_key" if "missing key" in e else "off"
    if "not installed" in e:
        return "not_installed"
    if "cookie" in e or "login" in e or "authenticate" in e:
        return "sign_in"
    if http_status == 429 or "429" in e or "rate limit" in e or "too many" in e:
        return "busy"
    if http_status in (401, 403) or re.search(r"\b40[13]\b", e):
        return "refused"
    if (http_status or 0) >= 500:
        return "their_side"
    if "timed out" in e or "timeout" in e:
        return "slow"
    if "connect" in e or "name or service" in e or "no address" in e or "network" in e:
        return "offline"
    return "other"


def problem(status: str, error: str = "", error_type: str = "", http_status: int | None = None) -> str:
    kind = problem_kind(status, error, error_type, http_status)
    return PROBLEM[kind] if kind else ""


# ---- one sentence per finding ----------------------------------------------------------------------
def _site(f) -> str:
    data = {}
    try:
        data = json.loads(f["data"] or "{}") if not isinstance(f["data"], dict) else f["data"]
    except (ValueError, TypeError):
        pass
    site = data.get("site") or data.get("name") or data.get("breach") or data.get("broker") or ""
    if not site and f["url"]:
        site = (urlsplit(f["url"]).hostname or "").removeprefix("www.")
    return str(site)


def finding_sentence(f) -> str:
    """'Your email is in the Adobe data breach.' Works on a store row or a dict with the same keys."""
    who, site, cat = f["identity"], _site(f), f["category"]
    title = re.sub(r"^[A-Za-z]+:\s*", "", f["title"] or "")          # "IntelX: file.txt" -> "file.txt"
    return {
        "breach": f"{who} was in the {site or title} data breach.",
        "leak": f"{who} appears in a leaked file ({title}).",
        "paste": f"{who} was posted on a public text site{f' ({site})' if site else ''}.",
        "account": f"An account on {site or title} uses {who}.",
        "profile": f"Your public {site or 'profile'} page shows {who}.",
        "web_page": f"A web page{f' on {site}' if site else ''} mentions {who}.",
        "broker": f"The people-search site {site or title} lists {who}.",
        "code": f"Public code on {site or 'GitHub'} contains {who}.",
        "keyserver": f"A public key directory lists {who}.",
    }.get(cat, f"{who}: {title}")


def action_title(a) -> str:
    return ACTION_KIND.get(a["kind"], "{target}").format(target=a["target"] or "the site")
