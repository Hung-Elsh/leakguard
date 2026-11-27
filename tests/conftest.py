"""Shared test setup: no real secrets in tests. The project's .env is not loaded, every known key is cleared
from the environment, and secrets go to a temp file, never to the owner's keyring or ~/.config."""

import pytest

from leakguard import config, keystore, paths


@pytest.fixture(autouse=True)
def private_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "load_dotenv", lambda *a, **k: False)
    for name in (*keystore.KNOWN, "GOOGLE_PSE_CX", "GMAIL_CLIENT_SECRET_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LEAKGUARD_SECRETS", "file")
    monkeypatch.setattr(paths, "USER_CONFIG", tmp_path / "config")
    keystore.reset()
    yield tmp_path / "config" / "secrets.env"
    keystore.reset()
