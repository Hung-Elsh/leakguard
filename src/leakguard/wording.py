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
    "page": "Get the page on {target} taken down",
    "keyserver": "Take your entry off the public key directory {target}",
    "profile": "Hide your public {target} profile",
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
SOURCE_SITE = {"ghunt": "Google", "gravatar": "Gravatar", "github": "GitHub"}   # profile / code finds
NAMED_BY_SITE = ("account", "breach", "profile")                                   # the removal planner names these


def _field(f, key: str):
    try:
        return f[key]
    except (KeyError, IndexError):
        return None


def _data(f) -> dict:
    raw = _field(f, "data")
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


def _row(f) -> dict:
    """The fields the removal planner reads, from a store row or a plain dict."""
    data = _field(f, "data")
    return {k: _field(f, k) or "" for k in ("category", "source", "title", "url", "evidence")} | {
        "data": data if isinstance(data, str) else json.dumps(data or {})}


def site_of(f) -> str:
    """The site a finding is about, as the removal planner sees it ('spotify.com' and 'Spotify' are one site;
    a breach is named after the breached site, not the service that reported it). '' when unknown."""
    from .removal.planner import _site_of
    cat = _field(f, "category")
    if cat in NAMED_BY_SITE:
        name, domain = _site_of(_row(f))
        name = name or domain
        if cat == "profile":
            name = SOURCE_SITE.get(_field(f, "source") or "", name)
        return name[:1].upper() + name[1:] if name and name == name.lower() else name
    site = _data(f).get("site") or _data(f).get("broker") or ""
    if not site and cat == "code":
        site = SOURCE_SITE.get(_field(f, "source") or "", "")
    if not site and _field(f, "url"):
        site = (urlsplit(f["url"]).hostname or "").removeprefix("www.")
    return str(site)


def join_names(names: list[str]) -> str:
    """'a', 'a and b', 'a, b and c'."""
    names = list(dict.fromkeys(names))
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def finding_sentence(f, who: str | None = None, many: bool = False) -> str:
    """'zorblat11@... was in the LabShop data breach.' Works on a store row or a dict with the same keys.
    `who` replaces the identity (e.g. 'zorblat11 and zorblat_x' for a group; then many=True)."""
    who, site, cat = who or f["identity"], site_of(f), f["category"]
    was, appears = ("were", "appear") if many else ("was", "appears")
    title = re.sub(r"^[A-Za-z]+:\s*", "", f["title"] or "")          # "IntelX: file.txt" -> "file.txt"
    return {
        "breach": f"{who} {was} in the {site} data breach." if site else f"{who} {was} in a data breach.",
        "leak": f"{who} {appears} in a leaked file ({title}).",
        "paste": f"{who} {was} posted on a public text site{f' ({site})' if site else ''}.",
        "account": f"An account on {site or title} uses {who}.",
        "profile": f"Your public {site or 'profile'} page shows {who}.",
        "web_page": f"A web page{f' on {site}' if site else ''} mentions {who}.",
        "broker": f"The people-search site {site or title} lists {who}.",
        "code": f"Public code on {site or 'GitHub'} contains {who}.",
        "keyserver": f"A public key directory lists {who}.",
    }.get(cat, f"{who}: {title}")


def group_sentence(category: str, rows: list) -> str:
    """One sentence for a To do question that groups several finds."""
    names = list(dict.fromkeys(r["identity"] for r in rows))
    who, many = join_names(names), len(names) > 1
    files = {r["url"] or r["title"] for r in rows}
    if category == "leak" and len(files) > 1:
        return f"{who} {'appear' if many else 'appears'} in {len(files)} leaked files."
    return finding_sentence(rows[0], who, many)


def action_title(a) -> str:
    key, title = _field(a, "key") or "", _field(a, "title") or ""
    kind = ("page" if key.startswith("page:") else "keyserver" if key.startswith("keyserver:")
            else "profile" if title.startswith("Remove or hide the public") else a["kind"])
    return ACTION_KIND.get(kind, "{target}").format(target=a["target"] or "the site")


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


# ---- To do -------------------------------------------------------------------------------------------
TODO = {
    "empty": "All done. Nothing needs you right now.",
    "who_title": "Is this you?",
    "who_help": "A check found these. Only what you say is yours gets checked and cleaned up.",
    "yes": "Yes, it's me", "no": "No", "yes_all": "Yes to all", "no_all": "No to all",
    "add_mine": "Add another one of yours", "add_placeholder": "an email address or username", "add": "Add",
    "what_title": "What should we do?",
    "what_help": "New things a check found. Pick what should happen; you can change it later under Found.",
    "remove_all": "Remove all {count}",
    "show_more": "Show {count} more",
    "turn_title": "Your turn",
    "turn_help": "Things only you can do, or that need your OK before anything is sent.",
    "waiting_title": "Waiting for sites",
    "waiting_help": "Requests that are out. We check again on the date shown.",
    "replied": "They replied", "check_now": "Check now", "its_done": "It's done",
    "done": "Done", "cant": "Can't do it", "steps": "How", "undo": "Undo",
    "answered": "{answer} ({count} {things}).",
    "decided_yes": "Added {who}. We'll check {them} from now on.",
    "decided_no": "Okay, we'll ignore {who}.",
    "marked_done": "Marked as done: {target}.",
    "skipped": "Skipped: {target}.",
    "replied_done": "Noted: {target} replied.",
    "checking": "Checking {target}...",
    "gone": "Confirmed gone: {target}.",
    "still_there": "Still there: {target}. We'll check again around {date}.",
    "check_owner": "This one is confirmed by you, not by a check: press Done when it's done.",
    "check_nothing": "There's nothing to look up for this one: press Done when it's done.",
    "next_check": "Next check {date}",
    "found_by": "Seen in {how}",
    "made_from_keyword": "Made from your keyword",
    "made_from_address": "The name part of {address}",
    "added_by_you": "Added by you",
    "put_back": "Put back",
    "put_back_done": "Put back: {target}.",
    "history": "History",
}

ACTION_HELP = {
    "email": "We wrote the request for you. Review it, then send it from your address.",
    "form": "We fill in the site's form for you. You see it before anything is submitted.",
    "manual": "This one is done on the site itself. Open the page, follow the steps, then press Done.",
    "checklist": "A short checklist for the accounts you keep.",
}

SEND = {
    "title": "Review and send",
    "from": "From", "to": "To", "subject": "Subject",
    "send": "Send", "not_now": "Not now",
    "need_contact": "We don't have a checked address for this site yet. Find its privacy email address or "
                    "contact page on the site, enter it here, then press Save.",
    "contact_placeholder": "privacy@example.com or example.com/privacy",
    "save_contact": "Save",
    "page_only": "This site takes requests on a web page, not by email. Copy the text below, open the page, "
                 "and put it into the form there. Press Done in To do when you have sent it.",
    "copy": "Copy the text", "open_page": "Open the page", "copied": "Copied.",
    "sending": "Sending...",
    "sent": "Sent to {to}. We'll check again around {date}.",
    "failed": "It couldn't be sent. Nothing was sent. The details are saved.",
}

FORM = {
    "title": "Review and submit",
    "filling": "Filling in the form on {target}... This takes a few seconds.",
    "filled": "We filled in the form below. Nothing has been submitted yet.",
    "submit": "Submit", "not_now": "Not now",
    "submitting": "Submitting...",
    "submitted": "Submitted. We'll check again around {date}.",
    "no_success": "Submitted, but the site didn't show a clear confirmation. We'll check again around {date}.",
    "failed": "The form couldn't be filled in. Nothing was submitted. The details are saved.",
}

STEPS = {"title": "How to do it", "close": "Close", "done": "I've done it"}

# ---- Found and Clean-up ------------------------------------------------------------------------------
FOUND = {
    "intro": "Everything the checks found. Double-click a row to see it and change your answer.",
    "search": "Search...",
    "show_open": "Still there", "show_all": "Everything", "show_gone": "Gone",
    "col_seriousness": "Seriousness", "col_what": "What", "col_where": "Where", "col_first": "First seen",
    "col_status": "Now", "col_answer": "Your answer",
    "status_there": "Still there", "status_gone": "Gone",
    "answer_none": "Not answered",
    "open_link": "Open the page",
    "change": "Change your answer:",
    "sources": "Found by",
    "empty": "Nothing here yet. Start a check to begin.",
}
VERDICT_LABEL = {"open": "Remove", "protect": "Keep & secure", "accepted": "Ignore", "false_positive": "Not me"}

CLEANUP = {
    "intro": "Every clean-up step, from what needs you to what's confirmed gone.",
    "your_turn": "Your turn", "waiting": "Waiting for sites", "finished": "Done and confirmed",
    "skipped": "Skipped",
    "add_title": "Add a site we missed",
    "add_help": "An account you know about that no check found. We'll look up how to delete it.",
    "add_site": "Site name (e.g. Zing ID)", "add_who": "Your email or username on it",
    "add_page": "Its delete page or privacy email (optional)",
    "add": "Add",
    "added": "Added {target} to your clean-up.",
    "empty": "Nothing to clean up yet.",
    "history": "History",
}


def origin_text(origin: str) -> str:
    """Where a proposed identity came from, in plain words."""
    origin = origin or ""
    head, _, rest = origin.partition(":")
    if head == "derived":
        rest = rest.strip()
        if rest == "keyword":
            return TODO["made_from_keyword"]
        if rest.startswith("local part of "):
            return TODO["made_from_address"].format(address=rest.removeprefix("local part of "))
        return TODO["made_from_keyword"]
    if head.startswith("owner"):
        return TODO["added_by_you"]
    return TODO["found_by"].format(how=SOURCE.get(head, "web search"))


def check_result(text: str, target: str, date: str) -> str:
    """tracker.check's answer, in plain words."""
    if text.startswith("verified") or "are gone" in text:
        return TODO["gone"].format(target=target)
    if "confirmed by you" in text:
        return TODO["check_owner"]
    if text.startswith("no linked"):
        return TODO["check_nothing"]
    return TODO["still_there"].format(target=target, date=date or "soon")
