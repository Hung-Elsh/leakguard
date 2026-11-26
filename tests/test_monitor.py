"""Monitor: diff, grouping, reopening removals that come back, scorecard, timer files."""

import json

import pytest

from leakguard import config, monitor
from leakguard.models import Finding
from leakguard.store import Store


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def store(tmp_path):
    st = Store(tmp_path / "t.sqlite")
    st.seed("zorblat11@seclab.test", "email", "t")
    st.seed("zorblat11", "username", "t")
    return st


def _save(st, value, source, findings, mark_gone=True):
    ident = next(i for i in st.identities("claimed") if i.value == value)
    st.save_findings(st.start_scan("scan"), ident, source, findings, mark_gone)


def test_grouped_new_counts_one_leak_once():
    res = monitor.MonitorResult(started="x")
    base = {"title": "dump", "url": "https://paste.example/1", "disposition": "open"}
    res.new = [{**base, "severity": "low", "source": "brave", "identity": "zorblat11"},
               {**base, "severity": "high", "source": "pse", "identity": "zorblat11@seclab.test"}]
    g = res.grouped_new()
    assert len(g) == 1 and g[0]["severity"] == "high" and g[0]["sources"] == {"brave", "pse"}
    assert len(res.alert_worthy("medium")) == 1 and res.alert_worthy("medium")[0]["identities"] == {"zorblat11", "zorblat11@seclab.test"}


def test_scorecard_and_snapshot(store):
    _save(store, "zorblat11", "sherlock", [Finding("sherlock", "account", "Account on A", locator="a"),
                                          Finding("sherlock", "account", "Account on B", locator="b")])
    _save(store, "zorblat11", "brave", [Finding("brave", "web_page", "look-alike", severity="info", locator="p")])
    _save(store, "zorblat11", "sherlock", [Finding("sherlock", "account", "Account on A", locator="a")])  # B gone
    sc = monitor.scorecard(store)
    assert sc["found"] == 2 and sc["open"] == 1 and sc["gone"] == 1 and sc["cleaned_pct"] == 50   # info not counted
    snap = monitor.snapshot(store)
    assert snap["open"] == 1 and snap["gone"] == 1


def test_reopen_when_removed_data_comes_back(lab, store, monkeypatch, tmp_path):
    f = Finding("brokers", "broker", "Listed on X", locator="x", severity="high")
    _save(store, "zorblat11@seclab.test", "brokers", [f])
    fid = store.findings()[0]["id"]
    aid, _ = store.upsert_action({"key": "broker:x", "kind": "broker_optout", "method": "form", "finding_ids": [fid]})
    store.set_action_state(aid, "requested")
    store.set_action_state(aid, "verified")
    # the next scan sees the record again (status stays known); nothing else runs in this test
    monkeypatch.setattr(monitor.engine, "expand", lambda *a, **k: monitor.engine.RunSummary(0))
    monkeypatch.setattr(monitor.engine, "scan", lambda *a, **k: monitor.engine.RunSummary(0))
    monkeypatch.setattr(monitor, "REPORTS", tmp_path / "reports")          # never the real data folder
    res = monitor.run(lab, store)
    assert store.action(aid)["state"] == "requested" and res.reopened
    assert "came back" in monitor.summary_line(res, "medium")


def test_schedule_files():
    files = monitor.schedule_files("internet", "weekly", "--quick")
    assert "OnCalendar=Mon *-*-* 09:00" in files["leakguard-monitor.timer"]
    assert "monitor -p internet --quick" in files["leakguard-monitor.service"]
    with pytest.raises(ValueError):
        monitor.schedule_files("internet", "hourly")


def test_breach_records_are_never_marked_gone(store):
    _save(store, "zorblat11@seclab.test", "spiderfoot",
          [Finding("spiderfoot", "breach", "Hacked Email Address: x [site.com]", locator="b", severity="medium"),
           Finding("spiderfoot", "account", "Account on External Site: X", locator="a")])
    _save(store, "zorblat11@seclab.test", "spiderfoot", [])          # a complete run that returned nothing
    st = {f["category"]: f["status"] for f in store.findings()}
    assert st["breach"] != "gone" and st["account"] == "gone"


def test_ghunt_not_found_is_not_an_error(lab, tmp_path, monkeypatch):
    import subprocess

    from leakguard.plugins import tools
    monkeypatch.setattr(tools, "find_binary", lambda *a: "ghunt")
    monkeypatch.setattr(tools, "run", lambda *a, **k: subprocess.CompletedProcess(
        ["ghunt"], 1, stdout="[+] Authenticated !\n[-] The target wasn't found.", stderr=""))
    assert tools.GHunt().produce(None, "nobody@example.org", "email", tmp_path) is None


def test_rerate_fixes_stale_search_ratings(lab, store):
    _save(store, "zorblat11", "brave", [Finding("brave", "web_page", "Snoiper tf2", url="https://r.example/x",
                                                severity="medium", locator="x")])
    assert monitor.rerate(lab, store) == 1
    assert store.findings()[0]["severity"] == "info"                 # no owned name or email on the page


def test_shared_final_report_masks_every_identity(lab, store):
    from leakguard import report
    _save(store, "zorblat11@seclab.test", "holehe", [Finding("holehe", "account", "Account on forum",
                                                             url="https://forum.example/u/zorblat11", locator="f")])
    store.upsert_action({"key": "account:forum", "kind": "account_delete", "method": "manual",
                         "target": "forum (zorblat11)", "finding_ids": [store.findings()[0]["id"]]})
    text = report.final_markdown(lab, store, share=True)
    assert "zorblat" not in text.lower() and "z*****t" in text
    assert report._mask_value("abcdefgh11@gmail.com") == "a********1@g***l.com"
