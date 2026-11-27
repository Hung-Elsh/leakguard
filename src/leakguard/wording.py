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
NAV = {"overview": "Overview", "todo": "To do", "found": "Found items", "cleanup": "Clean-up", "mail": "Mail",
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
    "save_first": "Save & start first check",
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
    "check_now": "Check now", "check_full": "Full check", "checking": "Checking...",
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
    "show_open": "Still there", "show_all": "All", "show_gone": "Gone", "search_go": "Search",
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


# ---- Mail ----------------------------------------------------------------------------------------------
MAIL = {
    "intro": "LeakGuard looks through your inbox for spam, scams and newsletters you never signed up for, and "
             "moves them out of the way. Nothing is deleted.",
    "connected_app_password": "Connected: {address} ({provider}, with an app password).",
    "connected_google": "Connected: {address} (with your own Google project).",
    "connected_practice": "Practice mailbox: {address}.",
    "not_connected": "Your mail isn't connected yet.",
    "check": "Check my mail", "change": "Change", "disconnect": "Disconnect",
    "disconnected": "Mail disconnected. Its password was removed from this computer.",
    "checking": "Looking through your inbox...",
    "summary": "We looked at {total} messages.",
    "nothing": "Nothing to move: your inbox looks clean.",
    "keep_rest": "{count} stay in your inbox.",
    "move": "Move {count} messages",
    "move_confirm": "Move {count} messages?\n\n{breakdown}\n\nNothing is deleted: you can move them back any time.",
    "moving": "Moving...",
    "moved": "Moved {count} messages.",
    "col_from": "From", "col_subject": "Subject", "col_action": "What we'd do", "col_why": "Why",
    "connect_title": "Connect your mail",
    "connect_intro": "LeakGuard uses an app password: a separate password just for LeakGuard, which you can "
                     "remove at any time. Your normal password is never used or stored.",
    "email": "Your email address", "password": "App password", "test_save": "Test & save",
    "testing": "Checking that it works...",
    "saved": "Connected. Your app password is kept in {where}.",
    "detected": "Mail service: {name}",
    "unknown_provider": "We don't know this mail service yet. Enter its servers under Other mail service.",
    "unsupported": "Outlook, Hotmail and Live no longer allow app passwords, so LeakGuard can't connect to "
                   "them yet.",
    "other": "Other mail service (advanced)",
    "incoming": "Incoming server", "outgoing": "Outgoing server", "port": "Port", "security": "Security",
    "google": "Use my own Google project (advanced)",
    "google_help": "If you made your own Google Cloud project for Gmail, choose its client file. A browser "
                   "opens to sign in with Google on the next mail check.",
    "google_pick": "Choose the client file...",
    "google_saved": "Saved. Press Check my mail to sign in with Google.",
    "open_page": "Open the page",
    "failed": "The mail check couldn't run. The details are saved.",
}
MAIL_STEPS = {
    "gmail": "1. Turn on 2-Step Verification in your Google Account (under Security).\n"
             "2. Open the app passwords page, type LeakGuard as the name, and press Create.\n"
             "3. Copy the 16-letter password and put it below.",
    "yahoo": "1. Open Account Security in your Yahoo account.\n"
             "2. Choose Generate app password, type LeakGuard, and press Generate.\n"
             "3. Copy the password and put it below.",
    "icloud": "1. Sign in to your Apple Account and open Sign-In and Security.\n"
              "2. Choose App-Specific Passwords and add one called LeakGuard.\n"
              "3. Copy the password and put it below.",
    "other": "Ask your mail service for an app password (or use your normal password if it has none), and "
             "enter its incoming and outgoing servers below.",
}
MAIL_PROBLEM = {
    "refused": "The address or app password wasn't accepted. Check both and try again.",
    "offline": "Couldn't reach the mail service. Check your internet connection and the server names.",
    "blocked": "LeakGuard isn't allowed to contact that server.",
    "other": "Something went wrong. The details are saved.",
}
MAIL_ACTION = {"spam": "To Junk", "trash": "To Trash", "label": "Put aside to review", "keep": "Stays"}
MAIL_WOULD = {
    "spam": "{count} look like spam or scams (to Junk)",
    "trash": "{count} are from senders you blocked (to Trash)",
    "label": "{count} are newsletters that started after your address leaked (put aside to review)",
}
MAIL_RULE = {
    "owner-blocklist": "From a sender you blocked",
    "sextortion": "A blackmail threat",
    "phishing-brand-spoof": "Pretends to be a well-known company",
    "phishing-reply-to": "Replies would go to a different, unknown address",
    "auth-fail": "The sender couldn't be confirmed as real",
    "scam-subject": "A typical scam subject",
    "scam-body": "Typical scam wording",
    "storage-scam": "A fake \"your storage is full\" warning",
    "random-domain": "Sent from a random-looking address",
    "bulk-bcc": "Sent to many people at once, hidden",
    "list-after-leak": "A newsletter that started after your address leaked",
    "allowlist": "From someone you allowed",
    "": "Looks normal",
}


# ---- Settings: search services and extra checks -------------------------------------------------------
SETTINGS = {"title": "Settings", "services": "Search services", "tools": "Extra checks", "about_you": "About you...",
            "close": "Close", "better": "Make checks better",
            "better_keys": "{count} search {services}", "better_tools": "{count} extra {checks}",
            "better_line": "{what} can still be added: open the Settings menu at the top to set them up.",
            "and": "and",
            "better_button": "Set up"}
KEYS = {
    "intro": "Each one lets LeakGuard look in more places. All of them are optional.",
    "key": "Key", "test_save": "Test & save", "test": "Test", "remove": "Remove", "open_page": "Get a key",
    "connected": "Connected", "not_connected": "Not connected",
    "from_outside": "Set outside the app (in a settings file); it can't be changed here.",
    "testing": "Checking the key...",
    "saved": "Works. The key is kept in {where}.",
    "works": "Works.",
    "removed": "Removed {name}.",
    "practice": "Practice mode uses made-up keys; you can test them, but not change them.",
}
KEY_PROBLEM = {
    "refused": "The service didn't accept this key. Check that you copied all of it.",
    "offline": "Couldn't reach the service. Check your internet connection.",
    "busy": "The service is busy right now. Try again in a minute.",
    "blocked": "LeakGuard isn't allowed to contact this service.",
    "other": "Something went wrong. The details are saved.",
}
KEY_INFO = {
    "HIBP_API_KEY": {"name": "Have I Been Pwned", "cost": "Paid (a small monthly subscription)",
                     "adds": "The most complete list of data breaches your addresses were in.",
                     "steps": "1. Open the page and choose a subscription.\n2. Copy the key it shows.\n"
                              "3. Put it below.",
                     "page": "https://haveibeenpwned.com/API/Key"},
    "INTELX_API_KEY": {"name": "Intelligence X", "cost": "Free account",
                       "adds": "Searches archives of leaked files for your addresses.",
                       "steps": "1. Open the page and create a free account.\n2. Copy the key shown under "
                                "your account's developer settings.\n3. Put it below.",
                       "page": "https://intelx.io/account?tab=developer"},
    "BRAVE_API_KEY": {"name": "Brave Search", "cost": "Free plan",
                      "adds": "Searches the web for pages that mention your keyword, addresses and usernames.",
                      "steps": "1. Open the page and sign up for the free plan.\n2. Create a key and copy it.\n"
                               "3. Put it below.",
                      "page": "https://api-dashboard.search.brave.com/app/keys"},
    "GITHUB_TOKEN": {"name": "GitHub", "cost": "Free",
                     "adds": "Faster, deeper searches of public code. Works without it, just slower.",
                     "steps": "1. Open the page and sign in to GitHub.\n2. Press Generate (no extra permissions "
                              "are needed) and copy what it shows.\n3. Put it below.",
                     "page": "https://github.com/settings/personal-access-tokens/new"},
}
TOOLS = {
    "intro": "Extra tools that look in more places. They run on this computer.",
    "installed": "Installed", "missing": "Not installed",
    "install": "Install", "copy": "Copy the command", "copied": "Copied.",
    "installing": "Installing {name}... This can take a few minutes.",
    "installed_ok": "{name} is installed.",
    "install_failed": "{name} couldn't be installed. The details are saved.",
    "need_pipx": "One-click installs need a helper called pipx. Run this once in a terminal (it asks for your "
                 "password), then press Install again:",
    "by_hand": "This one is installed with a command in a terminal (it asks for your password):",
    "practice": "Practice mode uses recorded results instead of these tools.",
}
TOOL_INFO = {
    "holehe": "Finds sites where an account was made with your email.",
    "h8mail": "Looks your email up in leaked password lists.",
    "ghunt": "Shows what your Google account reveals publicly.",
    "mosint": "Several email lookups in one: leaks, linked sites, related addresses.",
    "socialscan": "Checks whether your email or usernames are taken on big platforms.",
    "sherlock": "Finds your usernames on hundreds of sites.",
    "maigret": "Finds your usernames on thousands of sites, with what each profile shows.",
    "blackbird": "Finds accounts for your usernames and email across many sites.",
    "spiderfoot": "A large search tool that checks leak search engines for your email.",
    "chromium": "A browser LeakGuard uses, hidden, to fill in opt-out forms for you.",
}
GHUNT = {
    "title": "Sign in for the Google check",
    "intro": "The Google check looks at what your Google account shows to anyone. It needs to be signed in "
             "with a Google account: use a spare one, not your main account.",
    "steps": "1. Open the page and add the GHunt Companion extension to Firefox or Chrome.\n"
             "2. In that browser, sign in to Google with your spare account.\n"
             "3. Open the extension, copy the code it shows, and put it below.",
    "page": "https://github.com/mxrch/ghunt_companion",
    "open_page": "Open the page", "code": "Code from the extension", "sign_in": "Sign in",
    "signing_in": "Signing in...", "ok": "Signed in as {who}.",
    "failed": "The sign-in didn't work. Copy a fresh code from the extension and try again.",
    "signed_in": "Signed in", "not_signed_in": "Not signed in", "button": "Sign in...",
}


# ---- Reports -------------------------------------------------------------------------------------------
REPORTS = {
    "intro": "A closer look at what was found, what was done, and how the checks are working.",
    "tab_found": "Summary", "tab_cleanup": "Clean-up", "tab_mail": "Mail", "tab_health": "Check health",
    "tab_trend": "Over time", "tab_final": "Final report",
    "found_help": "Everything still counted. Gone means a check no longer sees it.",
    "by_kind": "By kind", "by_seriousness": "By seriousness", "by_status": "Still there or gone",
    "still_there": "Still there", "slice": "{name}: {count}",
    "gone": "Gone", "answers": "Your answers: {text}.", "unanswered": "{count} not answered yet (see To do).",
    "cleanup_help": "Every step taken, newest first.",
    "cleanup_counts": "{out} waiting for sites · {gone} confirmed gone · {done} done by you · {skipped} skipped",
    "col_when": "When", "col_step": "Step", "col_what": "What happened", "col_note": "Note",
    "mail_help": "Messages moved out of your inbox each week, and why.",
    "mail_none": "No messages moved yet. Check your mail on the Mail page.",
    "col_reason": "Reason", "col_count": "Messages", "week_of": "Week of",
    "health_help": "How each search service did the last time it ran. Double-click one for the full details.",
    "health_none": "No checks have run yet.",
    "col_service": "Service", "col_last": "Last run", "col_result": "Result", "col_happened": "What happened",
    "health_detail": "Details for {service}",
    "col_for": "For", "col_detail": "Logged details",
    "trend_help": "How many exposures were still open, and how many are gone, after each check.",
    "trend_serious": "Serious, still open",
    "final_help": "A summary you can keep, or share with someone helping you.",
    "share": "Hide my names and addresses (for sharing)",
    "save": "Save as...",
    "saved": "Saved to {path}.",
    "refused": "The shareable copy wasn't saved: some of your details were still in it. The details are saved.",
}
AUTO = {
    "tab": "Automatic checks",
    "switch": "Check for me every week",
    "help": "Every Monday morning LeakGuard runs a full check by itself, even when the app is closed, and tells "
            "you if something new turns up. It runs while you are logged in to this computer.",
    "on": "On. Next check {date}.",
    "on_soon": "On.",
    "off": "Off. You can still check whenever you like.",
    "failed": "That didn't work. The details are saved.",
    "practice": "Not available in practice mode.",
}
NOTIFY = {
    "open": "Open LeakGuard", "quick": "Start a quick check", "quit": "Quit",
    "check_done": "Check finished",
    "serious": "Something serious was found",
    "removed": "Removal confirmed",
}


# ---- Your own tools (Settings > Extra checks; docs/ADD_A_TOOL.md) ---------------------------------------
# For people who already run command-line tools, so it names JSON and patterns (exempt from the jargon test).
CUSTOM = {
    "section": "Your own tools",
    "section_help": "Tools you added yourself. Each one runs in your checks while it's switched on.",
    "none": "None yet. You can add any tool that prints its results. See the guide: docs/ADD_A_TOOL.md.",
    "add": "Add a tool...", "edit": "Change...", "remove": "Remove", "on": "Switched on",
    "removed": "Removed {name}.", "saved": "Saved {name}. It runs in your next check.",
    "practice_example": "Practice example: runs only in practice mode, on recorded output.",
    "title": "Add a tool",
    "intro": "Describe the tool once: what it checks, the command, and how it prints results. Test it on your "
             "email, then save. It runs with the same safety rules as the built-in tools.",
    "name": "Name", "about": "What it finds (one sentence)",
    "checks": "What it checks", "check_email": "Email addresses", "check_username": "Usernames",
    "command": "Command",
    "command_help": "Exactly what you would type in a terminal. Write {value} where the email address or "
                    "username goes. It runs directly, not through a shell.",
    "format": "How it prints results",
    "format_json": "One JSON document", "format_jsonl": "One JSON result per line", "format_lines": "Lines of text",
    "items": "The list of results is at (optional)",
    "items_help": "Where the results are inside the JSON, e.g. results or data.accounts. Empty: the whole output.",
    "match": "Only results where (optional)", "equals": "equals",
    "pattern": "Pattern",
    "pattern_help": "A regular expression with named parts, e.g.  \\[\\+\\] (?P<site>\\S+): (?P<url>\\S+)",
    "result_title": "Title", "result_link": "Link (optional)", "result_site": "Site (optional)",
    "fields_help": "Use {name} for a part of each result, e.g.  Account on {site}  and  {url}.",
    "kind": "Kind of find", "seriousness": "Seriousness",
    "test": "Test on my email", "testing": "Running it on {value}...",
    "test_found": "Found {count} with {value}:", "test_nothing": "It ran, and found nothing for {value}.",
    "test_failed": "It didn't run. The details are saved.",
    "test_practice": "Practice mode doesn't run tools. This shows what the recorded example output gives.",
    "save": "Save", "cancel": "Cancel",
    "not_installed": "{program} isn't on this computer. Install it first, or give its full path.",
    "bad_id": "The name needs at least two letters or numbers.",
    "taken": "{name} is already a built-in check. Pick another name.",
    "no_name": "Give the tool a name.",
    "no_checks": "Tick what it checks: email addresses, usernames, or both.",
    "no_command": "Enter the command.",
    "no_value": "Write {value} in the command where the email address or username goes.",
    "bad_program": "Give the program's name, or its full path starting with / or ~.",
    "no_format": "Choose how it prints results.",
    "pattern_names": "The pattern needs named parts, like (?P<site>...).",
    "bad_pattern": "The pattern isn't a valid regular expression.",
    "no_title": "Enter a title for each result.",
    "no_category": "Choose the kind of find.",
    "no_severity": "Choose how serious a find is.",
    "bad_timeout": "The time limit must be between 10 seconds and an hour.",
}


# ---- menus and quick access --------------------------------------------------------------------------
MENU = {
    "file": "&File", "edit": "&Edit", "view": "&View", "settings": "&Settings", "addons": "&Add-ons",
    "help": "&Help",
    "quick": "Start a quick check", "full": "Start a full check", "mail": "Check my mail",
    "report": "Save the final report...", "quit": "Quit",
    "undo": "Undo", "find": "Find in found items",
    "command": "Show the command line (advanced)", "refresh": "Refresh",
    "about_you": "About you...", "services": "Search services...", "tools": "Extra checks...",
    "auto": "Automatic checks...", "mail_connection": "Mail connection...",
    "add_tool": "Add a tool...", "my_tools": "Your own tools...", "tool_guide": "How to add a tool",
    "manual": "User manual", "about": "About LeakGuard",
    "about_text": "LeakGuard {version}\n\nFinds, blocks and removes your own leaked personal data.\n"
                  "Everything stays on this computer.",
    "nothing_to_undo": "Nothing to undo.",
}
QUICK = {
    "button": "Quick actions", "title": "Quick actions", "target": "Check:",
    "quick": "Quick check", "full": "Full check", "mail": "Check my mail", "todo": "Open To do ({count})",
    "todo_none": "Open To do", "running": "A check is running: {text}", "stop": "Stop the check",
    "close": "Close",
}
