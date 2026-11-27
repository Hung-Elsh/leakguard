"""Secrets live in the keyring or a mode-600 file: never in the database, reports or logs."""

import dataclasses
import json

import pytest

from leakguard import config, keystore, report, service
from leakguard.store import Store

SECRET = "sk-test-0123456789abcdef"


@pytest.fixture
def lab():
    return config.load("lab")


def test_file_fallback_roundtrip(private_secrets):
    st = keystore.store()
    assert st.backend == "file"
    st.set("BRAVE_API_KEY", SECRET)
    assert private_secrets.stat().st_mode & 0o777 == 0o600
    keystore.reset()                                       # a fresh process reads it back
    assert keystore.store().get("BRAVE_API_KEY") == SECRET
    assert keystore.store().names() == ["BRAVE_API_KEY"]
    assert keystore.store().delete("BRAVE_API_KEY") and not keystore.store().get("BRAVE_API_KEY")


def test_multiline_secret_survives_the_file(private_secrets):
    token = json.dumps({"refresh_token": "1//refresh-abcdef", "client_id": "x"}, indent=1)
    keystore.store().set("GMAIL_TOKEN", token)
    keystore.reset()
    assert keystore.store().get("GMAIL_TOKEN") == token


def test_secret_never_reaches_the_database_or_reports(lab, tmp_path):
    db = tmp_path / "t.sqlite"
    store = Store(db)
    store.seed("zorblat11@seclab.test", "email", "test")
    where = service.set_key(store, "BRAVE_API_KEY", SECRET)
    assert where.endswith("secrets.env")
    assert "BRAVE_API_KEY" in store.connections()                  # only the fact that it exists
    store.db.execute("PRAGMA wal_checkpoint(FULL)")
    for f in tmp_path.glob("t.sqlite*"):
        assert SECRET.encode() not in f.read_bytes()
    rep = report.build(lab, store)
    assert SECRET not in json.dumps(rep, default=str) and SECRET not in report.to_markdown(rep)


def test_internet_reads_the_store_and_redacts_it(lab):
    internet = dataclasses.replace(lab, profile="internet", keys={})
    keystore.store().set("INTELX_API_KEY", SECRET)
    keystore.store().set("GMAIL_TOKEN", json.dumps({"refresh_token": "1//refresh-abcdef"}))
    assert internet.key("INTELX_API_KEY") == SECRET and internet.key_origin("INTELX_API_KEY") == "file"
    assert {SECRET, "1//refresh-abcdef"} <= set(internet.secret_values())


def test_lab_never_reads_the_owner_store(lab):
    keystore.store().set("HIBP_API_KEY", SECRET)
    assert lab.key("HIBP_API_KEY") != SECRET


def test_unknown_key_refused(lab, tmp_path):
    with pytest.raises(ValueError):
        service.set_key(Store(tmp_path / "t.sqlite"), "SOMETHING_ELSE", "x" * 10)
