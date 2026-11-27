"""G3 connections: the owner's mail servers (and only those), sending from the connected address, key tests,
moving exactly the previewed mail, pinned one-click installs, and a GHunt sign-in that never shows the token."""

import dataclasses
import subprocess
from email.message import EmailMessage

import httpx
import pytest

from leakguard import config, keystore, service
from leakguard.mail import connection
from leakguard.removal import drafts, sender
from leakguard.scope import ScopeError, ScopeGuard
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def internet(lab):
    return dataclasses.replace(lab, profile="internet", keys={})


def _with_mail(settings, cfg):
    mail, removal = connection.profile_mail(cfg)
    return dataclasses.replace(settings, mail=mail, removal={**settings.removal, **removal})


def test_mail_connection_file_and_scope(internet, private_secrets):
    cfg = connection.app_password_config("Me@Gmail.com", *[connection.PROVIDERS["gmail"][k] for k in ("imap", "smtp")],
                                         provider="gmail")
    connection.save(cfg)
    assert connection.path().stat().st_mode & 0o777 == 0o600 and "password:" not in connection.path().read_text()
    prof = connection.apply_to_profile({"mail": {"backend": "gmail"}, "removal": {"catalog": "x"}})
    assert prof["mail"]["host"] == "imap.gmail.com" and prof["removal"]["sender"] == "smtp"
    assert prof["removal"]["catalog"] == "x"                               # the rest of the profile stays
    s = _with_mail(internet, cfg)
    guard = ScopeGuard(s)
    guard.check_host("smtp.gmail.com", "mail")                             # the owner's own servers: allowed
    with pytest.raises(ScopeError):
        guard.check_host("smtp.attacker.example", "mail")                  # anything else: refused
    assert connection.provider_for("x@icloud.com") == "icloud" and connection.unsupported("x@hotmail.com")


def test_smtp_refuses_another_sender(internet, monkeypatch):
    cfg = connection.app_password_config("me@gmail.com", ("imap.gmail.com", 993, "ssl"),
                                         ("smtp.gmail.com", 465, "ssl"), "gmail")
    s = _with_mail(internet, cfg)
    monkeypatch.setattr(sender, "smtp_connection", lambda *a, **k: pytest.fail("must not connect"))
    msg = EmailMessage()
    msg["From"] = "old.me@gmail.com"
    with pytest.raises(drafts.DraftError, match="must come from old.me@gmail.com"):
        sender.send(s, ScopeGuard(s), msg)


def test_mail_status(internet):
    assert not service.mail_status(internet).connected
    cfg = connection.app_password_config("me@gmail.com", ("imap.gmail.com", 993, "ssl"),
                                         ("smtp.gmail.com", 465, "ssl"), "gmail")
    connection.save(cfg)
    s = _with_mail(internet, cfg)
    assert service.mail_status(s).how == "app_password" and not service.mail_status(s).connected
    keystore.store().set(connection.SECRET, "abcd efgh")
    assert service.mail_status(s).connected and service.mail_status(s).provider == "Gmail"


@pytest.mark.parametrize("status,ok,problem", [(200, True, ""), (401, False, "refused"), (429, False, "busy"),
                                               (500, False, "other")])
def test_key_test_answers(lab, monkeypatch, status, ok, problem):
    from leakguard import net
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(status, text="no")
    real = net.Http.client
    monkeypatch.setattr(net.Http, "client", lambda self, source, headers=None, timeout=25: httpx.Client(
        headers=headers, transport=httpx.MockTransport(handler)) if real else None)
    r = service.test_key(lab, "HIBP_API_KEY", "  k-123456789  ")
    assert (r.ok, r.problem) == (ok, problem)
    assert seen["headers"]["hibp-api-key"] == "k-123456789"
    assert "k-123456789" not in r.detail                                    # the key never lands in details


def test_apply_moves_exactly_the_preview(lab, tmp_path, monkeypatch):
    from types import SimpleNamespace as NS
    from leakguard.mail import backend
    moved = {}

    class Fake:
        def apply(self, action, uids):
            moved[action] = list(uids)
            return len(uids)

        def close(self):
            pass
    monkeypatch.setattr(backend, "make_backend", lambda s, g: Fake())
    rows = [(NS(uid="1", message_id="a", from_addr="x@y", subject="s"), NS(action="spam", rule="scam-body")),
            (NS(uid="2", message_id="b", from_addr="x@y", subject="s"), NS(action="keep", rule="")),
            (NS(uid="3", message_id="c", from_addr="x@y", subject="s"), NS(action="trash", rule="owner-blocklist"))]
    store = Store(tmp_path / "t.sqlite")
    assert service.apply_mail(lab, store, rows) == {"spam": 1, "trash": 1}
    assert moved == {"spam": ["1"], "trash": ["3"]}                         # "keep" is never touched


def test_one_click_install_uses_the_pinned_version(monkeypatch):
    calls = []
    monkeypatch.setattr(service, "pipx_path", lambda: "/usr/bin/pipx")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "ok", ""))
    ok, out = service.install_tool("ghunt")
    assert ok and calls[0] == ["/usr/bin/pipx", "install", "--python", "3.12", "--fetch-missing-python", "ghunt==2.3.4"]
    assert calls[1][-1].endswith("patch_ghunt.py")                         # GHunt gets its crash fixes
    calls.clear()
    assert service.install_tool("spiderfoot") == (False, "no one-click install for this tool") and not calls


def test_ghunt_sign_in_never_shows_the_token(monkeypatch):
    out = ("[+] Got OAuth2 token => oauth2_4/SECRETSECRET\n[Connected account]\nName : Spare\n"
           "Email : spare@gmail.com\nGenerating cookies and osids...\n[+] Cookies and osids generated !\n")
    seen = {}

    def run(cmd, input, **k):
        seen["input"] = input
        return subprocess.CompletedProcess(cmd, 0, out, "")
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(service, "ghunt_signed_in", lambda: True)
    monkeypatch.setattr("leakguard.runner.find_binary", lambda *a: "/usr/bin/ghunt")
    ok, who, detail = service.ghunt_sign_in("eyJvYXV0aF90b2tlbiI6ICJ4In0=")
    assert ok and who == "spare@gmail.com"
    assert seen["input"] == "y\n2\neyJvYXV0aF90b2tlbiI6ICJ4In0=\n"          # existing session: replace it
    assert "SECRETSECRET" not in detail and "eyJvYXV0aF90b2tlbiI6" not in detail


def test_connect_mail_tests_before_saving(internet, tmp_path, monkeypatch):
    import imapclient
    from imapclient.exceptions import LoginError
    state = {"password": "right pass"}

    class FakeImap:
        def __init__(self, *a, **k): pass
        def login(self, user, password):
            if password != state["password"].replace(" ", ""):
                raise LoginError("bad credentials")
        def select_folder(self, *a, **k): pass
        def logout(self): pass

    class FakeSmtp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def login(self, user, password): pass
    monkeypatch.setattr(imapclient, "IMAPClient", FakeImap)
    monkeypatch.setattr(sender, "smtp_connection", lambda cfg, timeout=30: FakeSmtp())
    store = Store(tmp_path / "t.sqlite")
    gmail = connection.PROVIDERS["gmail"]
    bad = service.connect_mail(internet, store, "me@gmail.com", "wrong", gmail["imap"], gmail["smtp"], "gmail")
    assert not bad.ok and bad.problem == "refused" and not connection.load()        # nothing saved
    good = service.connect_mail(internet, store, "me@gmail.com", "right pass", gmail["imap"], gmail["smtp"], "gmail")
    assert good.ok and connection.load()["address"] == "me@gmail.com"
    assert keystore.store().get(connection.SECRET) == "rightpass"                    # app-password spaces removed
    assert store.connections()[connection.SECRET]["last_result"] == "ok"
    service.disconnect_mail(store)
    assert not connection.load() and not keystore.store().get(connection.SECRET)
