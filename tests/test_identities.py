"""claim / reject by ID or value; new values are added; the private identity file follows (internet only)."""

import pytest

from leakguard import config, engine, leaks
from leakguard.identities import decide
from leakguard.models import Candidate
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def store(tmp_path, lab):
    st = Store(tmp_path / "t.sqlite")
    engine.bootstrap(lab, st)
    st.add_candidate(Candidate("zorblat_x", "username", "test"))
    return st


def test_claim_by_exact_value_and_by_id(lab, store):
    d = decide(lab, store, "zorblat_x", "claimed")
    assert d.identity.status == "claimed" and not d.created
    cand = store.identities("candidate")
    assert cand == []                                                   # the only candidate was claimed
    d2 = decide(lab, store, str(d.identity.id), "rejected")
    assert d2.identity.status == "rejected"


def test_unknown_value_is_added(lab, store):
    d = decide(lab, store, "zorblat2024", "claimed")
    assert d.created and d.identity.kind == "username" and d.identity.status == "claimed"
    r = decide(lab, store, "someone.else@seclab.test", "rejected")
    assert r.created and r.identity.kind == "email" and r.identity.status == "rejected"
    assert decide(lab, store, "@ZORBLAT2024", "claimed").created is False   # case and leading @ are ignored


def test_bad_token(lab, store):
    with pytest.raises(config.ConfigError):
        decide(lab, store, "not a valid name!", "claimed")


@pytest.fixture
def internet(tmp_path, monkeypatch):
    path = tmp_path / "identities.yaml"
    monkeypatch.setattr(config, "USER_IDENTITY", path)
    monkeypatch.setattr(leaks, "USER_IDENTITY", path)
    config.write_identity({"keyword": "quillfox", "emails": ["quillfox9@example.org"], "usernames": []})
    return config.load("internet")


def test_internet_identity_file_follows_decisions(internet, tmp_path):
    st = Store(tmp_path / "i.sqlite")
    engine.bootstrap(internet, st)
    decide(internet, st, "qfox_old@example.org", "claimed")
    assert "qfox_old@example.org" in config.read_identity("internet")["emails"]
    decide(internet, st, "qfox_old@example.org", "rejected")
    assert "qfox_old@example.org" not in config.read_identity("internet")["emails"]
    with pytest.raises(config.ConfigError):
        decide(internet, st, "quillfox9@example.org", "rejected")       # never remove the only email
