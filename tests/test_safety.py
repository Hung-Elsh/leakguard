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


# ---- mail hosts ---------------------------------------------------------------------
def test_lab_mail_host_must_be_in_scope(lab):
    ScopeGuard(lab).check_host("192.168.1.250", "mail")
    with pytest.raises(ScopeError):
        ScopeGuard(lab).check_host("imap.gmail.com", "mail")


def test_internet_mail_hosts(internet):
    ScopeGuard(internet).check_host("gmail.googleapis.com", "mail")
    with pytest.raises(ScopeError):
        ScopeGuard(internet).check_host("imap.evil.test", "mail")


# ---- secrets never reach output/storage ------------------------------------------------
def test_redact_url_params_and_known_values():
    from leakguard.models import redact
    msg = "403 for url 'https://x.test/v1?key=AIzaSECRETVALUE123&cx=abc&q=a' token=ghp_abcdef123 used SECRETVALUE2"
    out = redact(msg, ["SECRETVALUE2"])
    assert "AIzaSECRETVALUE123" not in out and "ghp_abcdef123" not in out and "SECRETVALUE2" not in out
    assert "cx=abc" in out          # non-secret parameters stay readable


def test_http_error_is_logged_in_full_but_without_key(lab):
    import httpx

    from leakguard.engine import _run_one
    from leakguard.models import PluginResult
    from leakguard.plugins import Context, Plugin
    from leakguard.net import Http

    class Failing(Plugin):
        name, kinds = "fake", ("email",)

        def run(self, ctx, ident):
            req = httpx.Request("GET", "https://api.test/v1?key=SUPERSECRET123&q=x")
            resp = httpx.Response(403, request=req, json={"error": {"message": "This project does not have the access"}})
            resp.raise_for_status()
            return PluginResult()

    guard = ScopeGuard(lab)
    out = _run_one(Context(lab, guard, Http(lab, guard)), Failing(), Identity(1, "a@seclab.test", "email", "claimed"),
                   ["SUPERSECRET123"])
    assert out.status == "error" and out.log["http_status"] == 403
    assert "does not have the access" in out.error and "does not have the access" in out.log["detail"]
    assert "SUPERSECRET123" not in out.log["url"] and "key=***" in out.log["url"]
    assert out.log["error_type"] == "HTTPStatusError" and out.log["duration_ms"] >= 0


# ---- match level: only the owner's email on a page is a real exposure ---------------------
def test_match_level(lab):
    from leakguard.net import Http
    from leakguard.plugins import Context
    guard = ScopeGuard(lab)
    ctx = Context(lab, guard, Http(lab, guard), {"zorblat11@seclab.test", "zorblat_x"})
    assert ctx.match_level("contact zorblat11@seclab.test") == "email"
    assert ctx.match_level("profile of zorblat_x on a forum") == "exact"
    assert ctx.match_level("the zorblat project") == "exact"          # the keyword itself as a word
    assert ctx.match_level("zorblatfan2000 posted") == "variant"
    assert ctx.match_level("blat zor sniper") == "none"


# ---- tool failures are never reported as "nothing found" -----------------------------------
def test_tool_failure_without_output_raises(tmp_path):
    import subprocess

    from leakguard.runner import ToolError, expect_output
    crashed = subprocess.CompletedProcess(["ghunt"], 1, stdout="[+] Authenticated !", stderr="Traceback\nNameError: name 'photos'")
    with pytest.raises(ToolError) as e:
        expect_output("ghunt", crashed, tmp_path / "missing.json")
    assert "NameError" in str(e.value) and "exit code 1" in e.value.detail
    clean = subprocess.CompletedProcess(["ghunt"], 0, stdout="not found", stderr="")
    assert expect_output("ghunt", clean, tmp_path / "missing.json") is None   # ran fine, nothing to report


def test_rate_limited_sites_count_as_failures(lab):
    from leakguard.net import Http
    from leakguard.plugins import BY_NAME, Context
    from leakguard.paths import ROOT
    guard = ScopeGuard(lab)
    ctx = Context(lab, guard, Http(lab, guard), set())
    text = (ROOT / "lab/fixtures/holehe/zorblat11@seclab.test.csv").read_text()
    r = BY_NAME["holehe"].parse(ctx, text, "zorblat11@seclab.test", "email")
    assert r.failures == {"rate limited": 1} and len(r.findings) == 3 and r.checked == 5


@pytest.mark.parametrize("name,fields,expected", [
    ("cit0day.in", (), "high"), ("Collection #1", (), "high"), ("gmail (2).rar/gmail.txt", (), "high"),
    ("combo_2023.txt", (), "high"), ("AndroidLista", ("username", "id", "first_name"), "medium"),
    ("LabShop", ("email", "password"), "high"), ("dragonnest.com", (), "medium"), ("hiGH !.txt", (), "medium"),
])
def test_breach_severity(name, fields, expected):
    from leakguard.models import breach_severity
    assert breach_severity(name, fields) == expected


# ---- finding lifecycle: new -> known -> gone; partial runs never mark gone; verdicts survive ----------
def test_finding_lifecycle(tmp_path):
    from leakguard.models import Finding
    store = Store(tmp_path / "t.sqlite")
    store.seed("a@seclab.test", "email", "test")
    ident = store.identities("claimed")[0]
    f1, f2 = Finding("src", "account", "Account on A", locator="a"), Finding("src", "account", "Account on B", locator="b")
    s1 = store.start_scan("scan")
    assert store.save_findings(s1, ident, "src", [f1, f2]) == (2, 0)
    rows = {r["title"]: r for r in store.findings()}
    assert rows["Account on A"]["status"] == "new" and rows["Account on A"]["disposition"] == "open"
    store.mark([rows["Account on B"]["id"][:8]], "false_positive", "control")
    s2 = store.start_scan("scan")
    assert store.save_findings(s2, ident, "src", [f1], mark_gone=False) == (0, 0)   # partial: B kept
    assert store.save_findings(s2, ident, "src", [f1]) == (0, 1)                    # complete: B gone
    rows = {r["title"]: r for r in store.findings()}
    assert rows["Account on A"]["status"] == "known"
    assert rows["Account on B"]["status"] == "gone" and rows["Account on B"]["disposition"] == "false_positive"


def test_protect_verdict(tmp_path):
    from leakguard.models import Finding
    store = Store(tmp_path / "t.sqlite")
    store.seed("a@seclab.test", "email", "test")
    ident = store.identities("claimed")[0]
    store.save_findings(store.start_scan("scan"), ident, "src", [Finding("src", "breach", "Game forum", locator="g")])
    fid = store.findings()[0]["id"]
    store.mark([fid[:8]], "protect", "main account")
    assert store.findings()[0]["disposition"] == "protect"
    with pytest.raises(ValueError):
        store.mark([fid[:8]], "delete-it")
