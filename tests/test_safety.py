"""Tests for the safety-critical parts only: scope guard, claim gate, secret masking."""

import pytest

from leakguard import config, engine, leaks
from leakguard.models import Candidate, Identity, candidates_in_text, mask, scrub
from leakguard.scope import ScopeError, ScopeGuard
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def private_identity(tmp_path, monkeypatch):
    """A fictional owner identity in a temp dir; the real ~/.config file is never touched."""
    path = tmp_path / "identities.yaml"
    monkeypatch.setattr(config, "USER_IDENTITY", path)
    monkeypatch.setattr(leaks, "USER_IDENTITY", path)
    monkeypatch.setattr(leaks, "DATA", tmp_path)
    config.write_identity({"keyword": "quillfox", "emails": ["quillfox9@example.org"], "usernames": ["qfox_9"]})
    return path


@pytest.fixture
def internet(private_identity):
    return config.load("internet")


# ---- scope guard ------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://127.0.0.1:5055/x", "http://192.168.1.250:143/", "http://localhost/"])
def test_lab_allows_scope(lab, url):
    ScopeGuard(lab).check_url(url, "hibp")


@pytest.mark.parametrize("url", ["http://192.168.1.1/", "http://192.168.1.10/", "https://8.8.8.8/",
                                 "ftp://127.0.0.1/", "file:///etc/passwd"])
def test_lab_refuses_out_of_scope(lab, url):
    with pytest.raises(ScopeError):
        ScopeGuard(lab).check_url(url, "hibp")


def test_lab_never_runs_tools(lab):
    with pytest.raises(ScopeError):
        ScopeGuard(lab).check_tool("holehe")


def test_internet_allows_listed_host(internet):
    ScopeGuard(internet).check_url("https://haveibeenpwned.com/api/v3/breachedaccount/x", "hibp")


@pytest.mark.parametrize("url,source", [
    ("https://evil.example.com/", "hibp"),                     # host not listed for the source
    ("https://haveibeenpwned.com.evil.com/", "hibp"),          # suffix trick
    ("https://api.github.com/search/users", "hibp"),           # another source's host
    ("https://haveibeenpwned.com/", "unknown-source"),         # source not in catalogue
])
def test_internet_refuses(internet, url, source):
    with pytest.raises(ScopeError):
        ScopeGuard(internet).check_url(url, source)


def test_internet_refuses_disallowed_source(internet):
    internet.sources["hibp"]["allowed"] = False
    with pytest.raises(ScopeError):
        ScopeGuard(internet).check_url("https://haveibeenpwned.com/api/v3/x", "hibp")


# ---- claim gate ---------------------------------------------------------------
def test_candidates_are_not_scanned(lab, tmp_path):
    store = Store(tmp_path / "t.sqlite")
    engine.bootstrap(lab, store)
    store.add_candidate(Candidate("stranger@seclab.test", "email", "test"))
    claimed_values = {i.value for i in store.identities("claimed")}
    assert "stranger@seclab.test" not in claimed_values


def test_execute_refuses_unclaimed(lab, tmp_path):
    store = Store(tmp_path / "t.sqlite")
    with pytest.raises(engine.ClaimError):
        engine._execute(lab, store, "scan", [Identity(99, "x@seclab.test", "email", "candidate")], None, 1)


def test_candidate_never_overrides_decision(tmp_path):
    store = Store(tmp_path / "t.sqlite")
    store.add_candidate(Candidate("a@seclab.test", "email", "test"))
    ident = store.identities()[0]
    store.decide(ident.id, "rejected")
    assert store.add_candidate(Candidate("a@seclab.test", "email", "again")) is False
    assert store.get_identity(ident.id).status == "rejected"


def test_keyword_cannot_be_changed(lab, tmp_path):
    store = Store(tmp_path / "t.sqlite")
    kw = engine.bootstrap(lab, store)
    with pytest.raises(ValueError):
        store.decide(kw.id, "rejected")


# ---- masking / extraction ------------------------------------------------------
def test_mask():
    assert mask("hunter22") == "hu****22"
    assert "hunter22" not in scrub("zorblat11@seclab.test:hunter22 and password=hunter22")


def test_candidates_only_with_keyword():
    text = "contact zorblat.old@seclab.test or bob@seclab.test, profile /u/zorblat_x, site zorblat.seclab.test"
    vals = {c.value for c in candidates_in_text(text, "zorblat", "t")}
    assert vals == {"zorblat.old@seclab.test", "zorblat_x"}


# ---- private identity / leak check ---------------------------------------------------
def test_identity_file_is_private(private_identity):
    assert private_identity.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("bad", [{"keyword": "ab", "emails": ["a@b.co"]},
                                 {"keyword": "quillfox", "emails": []},
                                 {"keyword": "quillfox", "emails": ["not-an-email"]}])
def test_identity_validation(bad):
    with pytest.raises(config.ConfigError):
        config.validate_identity(bad)


def test_leak_terms_and_masked_output(private_identity):
    terms = leaks.private_terms()
    assert {"quillfox", "quillfox9@example.org", "qfox_9"} <= terms
    msg = leaks.describe(leaks.Hit("README.md", 3, "quillfox9@example.org"))
    assert "quillfox9@example.org" not in msg
