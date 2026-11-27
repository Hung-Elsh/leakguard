"""The app's service layer: the To do queue, decisions, and stopping a check part way."""

import threading

import pytest

from leakguard import config, engine, service
from leakguard.models import Candidate, Finding
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def store(tmp_path):
    st = Store(tmp_path / "t.sqlite")
    st.seed("zorblat11@seclab.test", "email", "test")
    return st


def test_todo_queue_empties_as_the_owner_answers(lab, store):
    ident = store.identities("claimed")[0]
    store.save_findings(store.start_scan("scan"), ident, "intelx", [
        Finding("intelx", "leak", "IntelX: combo.txt", severity="high", locator="ix1"),
        Finding("brave", "web_page", "similar name", severity="info", locator="p1")])
    store.add_candidate(Candidate("zorblat.old@seclab.test", "email", "intelx:1"))
    t = service.todo(lab, store)
    assert [c.value for c in t.candidates] == ["zorblat.old@seclab.test"]
    assert [f["title"] for f in t.review] == ["IntelX: combo.txt"]         # info-only mentions are not asked
    assert any(a["kind"] == "leak_removal" for a in t.your_turn)

    service.decide_identities(lab, store, ["zorblat.old@seclab.test"], yours=False)
    service.set_verdict(store, [t.review[0]["id"]], "open")
    t = service.todo(lab, store)
    assert not t.candidates and not t.review


def test_claim_gate_still_holds_through_the_service(lab, store):
    store.add_candidate(Candidate("zorblat.old@seclab.test", "email", "intelx:1"))
    cand = store.identities("candidate")[0]
    with pytest.raises(engine.ClaimError):
        engine._execute(lab, store, "scan", [cand], None, 1)


def test_cancel_stops_a_check_part_way(lab, store):
    seen, stop = [], threading.Event()

    def progress(done, total, source, identity, status):
        seen.append((done, total))
        stop.set()                                   # the owner presses Cancel after the first result
    summary = engine.scan(lab, store, workers=1, progress=progress, cancel=stop)
    assert summary.cancelled
    assert seen and seen[-1][0] < seen[-1][1]        # not every run happened
    assert len(summary.runs) == len(seen)            # every finished run is still recorded


def test_recent_changes_keep_the_order_within_one_second(lab, store):
    aid, _ = store.upsert_action({"key": "broker:x", "kind": "broker_optout", "method": "form", "target": "X",
                                  "finding_ids": []})
    store.set_action_state(aid, "requested", "form submitted")
    store.set_action_state(aid, "verified", "gone after re-check")
    kinds = [k for _, k, _ in service.recent_changes(store)]
    assert kinds[:2] == ["verified", "requested"]


def _finds(store, ident_value, source, items):
    ident = next(i for i in store.identities("claimed") if i.value == ident_value)
    store.save_findings(store.start_scan("scan"), ident, source, items)


def test_review_groups_one_question_per_site_page_or_leak(lab, store):
    store.seed("zorblat_x", "username", "test")
    _finds(store, "zorblat11@seclab.test", "holehe", [Finding("holehe", "account", "Account on spotify.com",
                                                              locator="s1", data={"site": "spotify.com"})])
    _finds(store, "zorblat_x", "sherlock", [Finding("sherlock", "account", "Account on Spotify", locator="s2",
                                                    data={"site": "Spotify"})])
    _finds(store, "zorblat11@seclab.test", "intelx", [
        Finding("intelx", "leak", "IntelX: a.txt", url="https://intelx.io/?did=1", severity="high", locator="i1"),
        Finding("intelx", "leak", "IntelX: b.txt", url="https://intelx.io/?did=2", severity="medium", locator="i2")])
    groups = service.review_groups(service.todo(lab, store).review)
    assert len(groups) == 2
    leak = next(g for g in groups if g.category == "leak")
    acct = next(g for g in groups if g.category == "account")
    assert leak.severity == "high" and len(leak.rows) == 2
    assert acct.identities == ["zorblat11@seclab.test", "zorblat_x"]
    from leakguard import wording
    assert wording.group_sentence("leak", leak.rows) == "zorblat11@seclab.test appears in 2 leaked files."
    assert wording.group_sentence("account", acct.rows) == "An account on Spotify uses zorblat11@seclab.test and zorblat_x."


def test_answers_and_decisions_can_be_undone(lab, store):
    _finds(store, "zorblat11@seclab.test", "intelx", [Finding("intelx", "leak", "IntelX: a.txt", severity="high",
                                                              locator="i1")])
    fid = store.findings()[0]["id"]
    before = service.set_verdict(store, [fid], "false_positive")
    assert store.findings()[0]["disposition"] == "false_positive" and store.findings()[0]["reviewed"]
    service.undo_verdicts(store, before)
    assert store.findings()[0]["disposition"] == "open" and store.findings()[0]["reviewed"] is None
    store.add_candidate(Candidate("zorblat.old@seclab.test", "email", "intelx:1"))
    cand = store.identities("candidate")[0]
    service.decide_identities(lab, store, [str(cand.id)], yours=True)
    service.undo_identities(lab, store, [(cand.id, "candidate")])
    assert store.get_identity(cand.id).status == "candidate"


def test_progress_contact_and_added_sites(lab, store):
    aid, _ = store.upsert_action({"key": "account:y", "kind": "account_delete", "method": "email",
                                  "template": "account_deletion", "target": "Y", "finding_ids": ["f1"],
                                  "identities": ["zorblat11@seclab.test"]})
    service.set_contact(store, aid, "y.example/privacy")                  # a page, typed without https://
    a = store.action(aid)
    assert a["contact"] == "https://y.example/privacy" and a["method"] == "manual" and a["contact_verified"]
    service.set_contact(store, aid, "privacy@y.example")
    assert store.action(aid)["method"] == "email"
    a = service.record_progress(store, aid, "done")
    assert a["state"] == "done" and a["next_check"]                       # has findings: re-checked later
    a = service.record_progress(store, aid, "planned")                     # Undo
    assert a["state"] == "planned" and a["next_check"] is None
    new, created = service.add_site(lab, store, "Zing ID", "zorblat11@seclab.test", email="dpo@zing.example")
    assert created and store.action(new)["contact"] == "dpo@zing.example" and store.action(new)["method"] == "email"
