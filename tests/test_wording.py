"""The app's words: every internal value has a plain text, and none of them uses technical jargon."""

import re

import pytest

from leakguard import wording
from leakguard.plugins import ALL_PLUGINS
from leakguard.store import ACTION_STATES, DISPOSITIONS

# words a regular user should never have to read (the full detail stays behind "Details")
JARGON = ["api", "http", "https", "oauth", "smtp", "imap", "token", "scope", "candidate", "finding", "findings",
          "disposition", "plugin", "json", "sqlite", "endpoint", "regex", "stdout", "stderr", "exception",
          "traceback", "timeout", "rate limit", "fixture", "osint", "cli", "paste", "partial", "dns", "url"]


def _texts():
    for name in dir(wording):
        value = getattr(wording, name)
        if name.isupper() and isinstance(value, dict):
            yield from ((f"{name}[{k}]", v) for k, v in value.items())
        elif name.isupper() and isinstance(value, str):
            yield name, value


@pytest.mark.parametrize("where,text", list(_texts()))
def test_no_jargon(where, text):
    words = re.sub(r"\{\w+\}", "", text).lower()
    hits = [j for j in JARGON if re.search(rf"\b{re.escape(j)}\b", words)]
    assert not hits, f"{where}: {hits} in {text!r}"


def test_every_internal_value_has_words():
    assert set(ACTION_STATES) <= set(wording.ACTION_STATE)
    assert set(DISPOSITIONS) <= set(wording.VERDICT_BUTTON) and set(DISPOSITIONS) <= set(wording.VERDICT_DONE)
    assert {p.name for p in ALL_PLUGINS} <= set(wording.SOURCE)
    assert {"ok", "partial", "skipped", "error", "scope_blocked"} <= set(wording.RUN_STATUS)
    assert {"account_delete", "broker_optout", "hibp_optout", "leak_removal", "manual", "paste_report",
            "protect_checklist", "rotate_password", "data_erasure"} <= set(wording.ACTION_KIND)
    assert {"info", "low", "medium", "high"} <= set(wording.SEVERITY)


@pytest.mark.parametrize("status,error,etype,http,kind", [
    ("ok", "", "", None, ""),
    ("partial", "5/6 checks got no answer: KeyError (2)", "", None, "some_sites"),
    ("skipped", "disabled in config/sources.json (allowed: false)", "SkipSource", None, "off"),
    ("skipped", "missing key(s): HIBP_API_KEY", "SkipSource", None, "needs_key"),
    ("error", "ConnectError: [Errno -5] No address associated with hostname", "ConnectError", None, "offline"),
    ("error", "HTTP 403: This project does not have the access", "HTTPStatusError", 403, "refused"),
    ("error", "HTTP 429: Too Many Requests", "HTTPStatusError", 429, "busy"),
    ("error", "HTTP 502: Bad gateway", "HTTPStatusError", 502, "their_side"),
    ("error", "maigret timed out after 900s", "ToolError", None, "slow"),
    ("error", "not installed: holehe (run `leakguard doctor`)", "ToolError", None, "not_installed"),
    ("scope_blocked", "host not allowed", "ScopeError", None, "blocked"),
    ("error", "KeyError: 'x'", "KeyError", None, "other"),
])
def test_problems_in_plain_words(status, error, etype, http, kind):
    assert wording.problem_kind(status, error, etype, http) == kind


def test_finding_sentence():
    row = {"identity": "zorblat11@seclab.test", "category": "leak", "title": "IntelX: combo.txt",
           "url": "https://intelx.io/?did=1", "data": "{}"}
    assert wording.finding_sentence(row) == "zorblat11@seclab.test appears in a leaked file (combo.txt)."
    acct = {"identity": "zorblat11", "category": "account", "title": "Account on Twitch", "url": "",
            "data": '{"site": "Twitch"}'}
    assert wording.finding_sentence(acct) == "An account on Twitch uses zorblat11."
