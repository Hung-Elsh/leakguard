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
