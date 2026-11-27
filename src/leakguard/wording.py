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


# ---- the desktop app's screens -------------------------------------------------------------------
NAV = {"overview": "Overview", "todo": "To do", "found": "Found", "cleanup": "Clean-up", "mail": "Mail",
       "reports": "Reports"}
SOON = "This part of the app arrives in the next update. Everything it will show is already being recorded."

ABOUT_YOU = {
    "title": "About you",
    "intro": "Tell LeakGuard what to look for. This is the only setup you need: everything else is optional "
             "and can be added later.",
    "keyword": "Your keyword",
    "keyword_help": "A word only you use, like a nickname you made up. We search for it to find your old "
                    "addresses and accounts.",
    "emails": "Your email addresses",
    "emails_help": "One per line. The first one is your main address.",
    "usernames": "Usernames (optional)",
    "usernames_help": "Names you use on websites and games, one per line.",
    "name": "Your name (optional)",
    "name_help": "Used to sign the removal requests we write for you.",
    "privacy": "Saved only on this computer. To look you up, each check service receives just the address "
               "or name it checks.",
    "save_first": "Save && start first check",
    "save": "Save",
    "bad_keyword": "Your keyword needs 4 to 64 letters or numbers (you can also use . _ and -).",
    "no_email": "Add at least one email address.",
    "bad_email": "This doesn't look like an email address: {value}",
    "bad_username": "This doesn't look like a username: {value} (letters, numbers, . _ and - only)",
}

CHECK = {
    "start": "Start check",
    "stop": "Stop",
    "stopping": "Stopping after the checks already running...",
    "target_all": "Everything of mine",
    "step_keyword": "Step 1 of 2: searching for your keyword",
    "step_identities": "Step 2 of 2: checking your addresses and usernames",
    "single": "Checking {value}",
    "progress": "{done} of {total} done, now: {source}",
    "finishing": "Finishing up: re-checking the removals that are due...",
    "nothing_new": "Check finished. Nothing new.",
    "new": "Check finished. {count} new {things} found.",
    "serious": "{count} of them {look} serious. Have a look in To do.",
    "candidates": "{count} new {addresses} might be yours. Have a look in To do.",
    "problems": "{count} {services} didn't work this time. We'll try again next time.",
    "gone": "{count} {things} no longer found. Good news.",
    "stopped": "Check stopped. Everything that finished is saved.",
    "failed": "The check couldn't run. The details are saved.",
    "running": "A check is already running.",
    "first_hint": "For the most complete results, run a Full check when you have half an hour.",
}

OVERVIEW = {
    "cleaned": "{gone} of {total} cleaned up",
    "cleaned_none": "Nothing found yet",
    "needs_you": "{count} {things} need you",
    "needs_you_none": "Nothing needs you right now.",
    "waiting": "Waiting on {count} {sites}. Next follow-up {date}.",
    "waiting_none": "Not waiting on any site.",
    "card_needs": "Needs you",
    "card_waiting": "Waiting for sites",
    "card_open": "Still open",
    "card_mail": "Mail blocked this week",
    "open_line": "{high} serious, {medium} medium, {low} minor",
    "mail_none": "Mail isn't connected yet.",
    "details": "See details",
    "trend": "Over time",
    "trend_open": "Still open",
    "trend_gone": "Gone",
    "trend_wait": "The chart appears after your second check.",
    "recent": "Recent changes",
    "recent_none": "Nothing yet. Start a check to begin.",
    "never": "No check yet",
    "last_check": "Last check: {when}",
}
EVENT = {"found": "Found: {text}", "requested": "Request sent: {text}", "acknowledged": "The site replied: {text}",
         "removed": "Removed: {text}", "verified": "Confirmed gone: {text}", "done": "Done: {text}"}
PRACTICE = "Practice mode: made-up data, nothing leaves this computer."


def plural(n: int, one: str, many: str | None = None) -> str:
    return one if n == 1 else (many or one + "s")


def ago(ts: str | None, now=None) -> str:
    """'just now', '5 minutes ago', '2 hours ago', 'yesterday', '3 days ago', or a date."""
    from datetime import datetime, timezone
    if not ts:
        return ""
    t = datetime.fromisoformat(ts)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    secs = ((now or datetime.now(timezone.utc)) - t).total_seconds()
    if secs < 90:
        return "just now"
    if secs < 3600:
        m = int(secs // 60)
        return f"{m} {plural(m, 'minute')} ago"
    if secs < 86400:
        h = int(secs // 3600)
        return f"{h} {plural(h, 'hour')} ago"
    if secs < 172800:
        return "yesterday"
    if secs < 7 * 86400:
        return f"{int(secs // 86400)} days ago"
    return day(ts)


def day(ts: str | None) -> str:
    """'3 Dec' (and the year when it isn't this year)."""
    from datetime import datetime, timezone
    if not ts:
        return ""
    t = datetime.fromisoformat(ts)
    this_year = datetime.now(timezone.utc).year
    return f"{t.day} {t.strftime('%b')}" + ("" if t.year == this_year else f" {t.year}")
