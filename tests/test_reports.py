"""G4: check health (latest run, worst result, full detail), summaries, report export, the weekly switch."""

import subprocess
from pathlib import Path

import pytest

from leakguard import config, service
from leakguard.models import Finding
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def store(tmp_path):
    st = Store(tmp_path / "t.sqlite")
    st.seed("zorblat11@seclab.test", "email", "test")
    st.seed("zorblat_x", "username", "test")
    return st


def test_check_health_uses_the_latest_run_and_the_worst_result(store):
    a, b = store.identities("claimed")[-2:]
    old = store.start_scan("scan")
    store.record_run(old, "holehe", a, "error", error="ConnectError: boom")
    new = store.start_scan("scan")
    store.record_run(new, "holehe", a, "ok", 3)
    store.record_run(new, "holehe", b, "partial", 1, "87/118 checks got no answer: rate limited (87)",
                     http_status=429, detail="Too Many Requests")
    store.record_run(new, "hibp", a, "skipped", error="missing key(s): HIBP_API_KEY")
    health = {h.source: h for h in service.check_health(store)}
    assert health["holehe"].status == "partial" and len(health["holehe"].runs) == 2      # the old error is gone
    assert health["holehe"].worst["detail"] == "Too Many Requests"                       # full detail kept
    assert health["hibp"].status == "skipped"
    assert [h.source for h in service.check_health(store)][0] == "holehe"                # problems first


def test_summaries(store):
    ident = store.identities("claimed")[-2]
    store.save_findings(store.start_scan("scan"), ident, "intelx", [
        Finding("intelx", "leak", "IntelX: a.txt", severity="high", locator="i1"),
        Finding("brave", "web_page", "look-alike", severity="info", locator="w1")])
    s = service.found_summary(store)
    assert dict(s["by_kind"]) == {"leak": {"high": 1}} and s["unanswered"] == 1           # info not counted
    aid, _ = store.upsert_action({"key": "x", "kind": "leak_removal", "method": "email", "target": "X",
                                  "finding_ids": []})
    store.set_action_state(aid, "requested", "sent")
    assert [h["state"] for _, _, h in service.cleanup_timeline(store)] == ["requested"]  # "plan" left out
    store.log_mail("lab", [("m1", "a@b", "s", "scam-body", "spam")], applied=True)
    store.log_mail("lab", [("m2", "a@b", "s", "scam-body", "spam")], applied=False)     # a preview: not moved
    m = service.mail_summary(store)
    assert m["total"] == 1 and m["by_rule"]["scam-body"] == 1 and m["weeks"][-1][1] == 1


def test_save_report_private_file(lab, store, tmp_path, monkeypatch):
    from leakguard import report
    monkeypatch.setattr(report, "REPORTS", tmp_path / "reports")
    dest = service.save_report(lab, store, share=True, dest=tmp_path / "out.md")
    assert dest.stat().st_mode & 0o777 == 0o600 and "Cleanup report" in dest.read_text()
    assert "zorblat11@seclab.test" not in dest.read_text()                                # masked for sharing


def test_weekly_switch(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    def fake(*args, timeout=30):
        calls.append(args)
        out = {"is-enabled": "enabled\n", "show": "Mon 2026-11-30 09:13:01 CET\n"}.get(args[0], "")
        return subprocess.CompletedProcess(args, 0, out, "")
    monkeypatch.setattr(service, "_systemctl", fake)
    ok, _ = service.set_weekly("internet", True)
    units = tmp_path / ".config" / "systemd" / "user"
    assert ok and (units / "leakguard-monitor.timer").exists() and "monitor -p internet" in \
        (units / "leakguard-monitor.service").read_text()
    assert calls[:2] == [("daemon-reload",), ("enable", "--now", "leakguard-monitor.timer")]
    assert service.weekly_status() == (True, "2026-11-30")
    calls.clear()
    assert service.set_weekly("internet", False)[0] and calls == [("disable", "--now", "leakguard-monitor.timer")]
