"""Removal workflow: grouping, verdicts, state machine, drafts (no secrets), browser scope."""

import pytest

from leakguard import config
from leakguard.models import Finding
from leakguard.removal import drafts
from leakguard.removal.browser import _allowed
from leakguard.removal.catalog import Catalog
from leakguard.removal.planner import build
from leakguard.scope import ScopeGuard
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def store(tmp_path):
    st = Store(tmp_path / "t.sqlite")
    st.seed("zorblat11@seclab.test", "email", "test")
    st.seed("zorblat11", "username", "test")
    return st


def _save(st, ident_value, source, findings):
    ident = next(i for i in st.identities("claimed") if i.value == ident_value)
    st.save_findings(st.start_scan("scan"), ident, source, findings)


def test_one_action_per_site_across_tools(lab, store):
    _save(store, "zorblat11@seclab.test", "holehe", [Finding("holehe", "account", "Account on spotify.com",
                                                             url="https://spotify.com", locator="spotify.com",
                                                             data={"site": "spotify.com"})])
    _save(store, "zorblat11@seclab.test", "socialscan", [Finding("socialscan", "account", "Account on Spotify",
                                                                 locator="spotify", data={"site": "Spotify"})])
    plans = {p.key: p for p in build(store, Catalog(lab))}
    assert "account:spotify" in plans and len(plans["account:spotify"].finding_ids) == 2
    assert plans["account:spotify"].contact == "privacy@spotify.seclab.test"


def test_verdicts_drive_the_plan(lab, store):
    fs = [Finding("sherlock", "account", "Account on Twitch", locator="twitch", data={"site": "Twitch"}),
          Finding("sherlock", "account", "Account on Houzz", locator="houzz", data={"site": "Houzz"}),
          Finding("intelx", "leak", "IntelX: game_forum.txt", severity="medium", locator="ix1"),
          Finding("brave", "web_page", "similar page", severity="info", locator="p1"),
          Finding("spiderfoot", "breach", "Hacked Email Address: x [cit0day.in]", severity="high", locator="c")]
    _save(store, "zorblat11", "mixed", fs)
    rows = {r["title"]: r["id"] for r in store.findings()}
    store.mark([rows["Account on Houzz"][:8]], "false_positive")
    store.mark([rows["IntelX: game_forum.txt"][:8]], "protect")
    keys = {p.key for p in build(store, Catalog(lab))}
    assert "account:twitch" in keys                      # open -> removal
    assert "account:houzz" not in keys                   # false positive -> nothing
    assert "protect" in keys                             # protect -> checklist ...
    assert "leakindex:intelx:zorblat11" in keys          # ... and a leaked copy of its data is still removed
    assert not any(k.startswith("page:") for k in keys)  # info-only search match -> nothing
    assert "rotate:compilations" in keys                 # credential compilation -> rotate passwords


def test_state_machine(store):
    aid, created = store.upsert_action({"key": "account:x", "kind": "account_delete", "method": "email",
                                        "finding_ids": ["f1"]})
    assert created
    with pytest.raises(ValueError):
        store.set_action_state(aid, "verified")          # planned -> verified is not allowed
    store.set_action_state(aid, "requested", "sent")
    aid2, created2 = store.upsert_action({"key": "account:x", "kind": "account_delete", "method": "email",
                                          "finding_ids": ["f2"]})
    a = store.action(aid)
    assert aid2 == aid and not created2 and a["state"] == "requested"   # re-plan never resets progress
    assert '"f1"' in a["finding_ids"] and '"f2"' in a["finding_ids"]


def test_draft_masks_secrets_and_dedupes(lab, store, monkeypatch, tmp_path):
    monkeypatch.setattr(drafts, "DRAFTS", tmp_path / "drafts")
    for ident in ("zorblat11@seclab.test", "zorblat11"):
        _save(store, ident, "psbdmp", [Finding("psbdmp", "paste", "dump zorblat11@seclab.test:hunter22",
                                               url="https://pastebin.com/abc", severity="high", locator="abc")])
    aid, _ = store.upsert_action({"key": "paste:pastebin", "kind": "paste_report", "method": "email",
                                  "contact": "abuse@paste.seclab.test", "contact_verified": True,
                                  "template": "paste_report", "target": "Pastebin",
                                  "finding_ids": [r["id"] for r in store.findings()]})
    msg, path = drafts.render(lab, store, aid)
    body = msg.get_content()
    assert "hunter22" not in body and body.count("https://pastebin.com/abc") == 1
    assert path.stat().st_mode & 0o777 == 0o600


def test_send_refuses_without_contact_but_draft_works(lab, store, monkeypatch, tmp_path):
    from leakguard.removal import tracker
    monkeypatch.setattr(drafts, "DRAFTS", tmp_path / "drafts")
    aid, _ = store.upsert_action({"key": "account:y", "kind": "account_delete", "method": "email",
                                  "template": "account_deletion", "target": "Y", "finding_ids": [],
                                  "identities": ["zorblat11"]})
    msg, _ = drafts.render(lab, store, aid)                 # draftable: text can go into a contact form
    assert not msg["To"]
    with pytest.raises(drafts.DraftError):
        tracker.send(lab, store, aid, confirm=True)         # unverified / no address: never sent


def test_browser_scope(lab):
    ok = _allowed(lab, ScopeGuard(lab), "http://127.0.0.1:5055/broker/optout")
    assert ok("http://127.0.0.1:5055/static/x.js")
    assert not ok("https://tracker.example.com/pixel")    # lab: anything outside the lab is aborted


def test_catalog_name_beats_software_domain_and_jdm_wins(lab, tmp_path):
    import dataclasses
    import json as _json
    jdm = tmp_path / "jdm.json"
    _json.dump([{"name": "Discourse", "url": "https://www.discourse.org/privacy", "difficulty": "easy",
                 "domains": ["discourse.org", "forums.envato.com"]},
                {"name": "Envato", "url": "https://help.market.envato.com/close", "difficulty": "hard",
                 "domains": ["envato.com"], "notes": "Use the contact form."},
                {"name": "Adobe", "url": "https://account.adobe.com/privacy/delete-account", "difficulty": "easy",
                 "domains": ["adobe.com"]}], jdm.open("w"))
    s = dataclasses.replace(lab, removal={"jdm": str(jdm)})
    cat = Catalog(s)
    assert cat.lookup("Envato Forum", "forums.envato.com").name == "Envato"        # not Discourse
    adobe = cat.lookup("Adobe")
    assert adobe.url.endswith("/delete-account")                                    # fresher JDM link wins
    assert "Cancel paid plans" in adobe.steps                                       # hand-written steps kept


def test_leak_index_never_uses_account_deletion(lab, store):
    _save(store, "zorblat11@seclab.test", "intelx", [Finding("intelx", "leak", "IntelX: combo.txt", severity="high",
                                                             locator="ix9")])
    p = {p.key: p for p in build(store, Catalog(lab))}["leakindex:intelx:zorblat11@seclab.test"]
    assert p.kind == "leak_removal" and p.contact == "removal@intelx.seclab.test"   # lab record-removal entry


def test_request_comes_from_the_address_it_is_about(lab, store, monkeypatch, tmp_path):
    """IntelX removed nothing for an address listed in a request sent from another address: one request per
    address, sent from it; a username-only or multi-address action falls back to the main address."""
    monkeypatch.setattr(drafts, "DRAFTS", tmp_path / "drafts")
    store.seed("zorblat.old@seclab.test", "email", "test")
    for ident, loc in (("zorblat11@seclab.test", "ix1"), ("zorblat.old@seclab.test", "ix2")):
        _save(store, ident, "intelx", [Finding("intelx", "leak", f"IntelX: {loc}.txt", severity="high", locator=loc)])
    keys = {p.key for p in build(store, Catalog(lab)) if p.kind == "leak_removal"}
    assert keys == {"leakindex:intelx:zorblat11@seclab.test", "leakindex:intelx:zorblat.old@seclab.test"}
    base = {"kind": "leak_removal", "method": "email", "contact": "removal@intelx.seclab.test",
            "contact_verified": True, "template": "leak_removal", "target": "Intelligence X", "finding_ids": []}
    old, _ = store.upsert_action(base | {"key": "a", "identities": ["zorblat.old@seclab.test"]})
    msg, _ = drafts.render(lab, store, old)
    assert msg["From"] == "zorblat.old@seclab.test" and "zorblat.old@seclab.test" in msg.get_content()
    both, _ = store.upsert_action(base | {"key": "b", "identities": ["zorblat11", "zorblat.old@seclab.test",
                                                                     "zorblat11@seclab.test"]})
    assert drafts.sender_address(lab, store.action(both)) == drafts.sender_address(lab)


def test_gmail_refuses_to_send_from_another_account(lab, monkeypatch):
    import dataclasses
    from email.message import EmailMessage
    from leakguard.mail import gmail_backend
    from leakguard.removal import sender

    class Fake:
        sent = []
        def __init__(self, *a): pass
        def send_as(self): return {"zorblat11@seclab.test"}
        def send(self, msg): Fake.sent.append(msg); return "id1"
    monkeypatch.setattr(gmail_backend, "GmailBackend", Fake)
    s = dataclasses.replace(lab, removal={"sender": "gmail"})
    msg = EmailMessage()
    msg["From"] = "zorblat.old@seclab.test"
    with pytest.raises(drafts.DraftError, match="must come from zorblat.old@seclab.test"):
        sender.send(s, ScopeGuard(s), msg)
    assert not Fake.sent


def test_owner_confirmed_actions_are_not_rechecked(lab, store):
    from leakguard.removal import tracker
    aid, _ = store.upsert_action({"key": "protect", "kind": "protect_checklist", "method": "checklist",
                                  "finding_ids": ["f1"]})
    store.set_action_state(aid, "done", "secured")
    assert "confirmed by you" in tracker.check(lab, store, aid)
    assert store.action(aid)["state"] == "done"
