"""Desktop app smoke tests (offscreen): the window builds on practice data, bad setup input is never saved, and
check results are told in plain words. Skipped when PySide6 isn't installed."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from leakguard import config, service, wording                      # noqa: E402
from leakguard.gui import main_window                                # noqa: E402
from leakguard.gui.wizard import about_you                           # noqa: E402


@pytest.fixture
def temp_data(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA", tmp_path)                    # never the real ~/.local/share/leakguard


def test_setup_problems_in_plain_words():
    assert about_you.problems("zorblat", ["zorblat11@seclab.test"], ["zorblat_x"]) == []
    found = about_you.problems("ab", [], ["bad name!"])
    assert wording.ABOUT_YOU["bad_keyword"] in found and wording.ABOUT_YOU["no_email"] in found
    assert any("bad name!" in p for p in found)


def test_bad_setup_is_never_saved(qtbot, monkeypatch):
    saved = []
    monkeypatch.setattr(about_you.service, "identity_form",
                        lambda profile="internet": {"keyword": "", "emails": [], "usernames": [], "owner": {}})
    monkeypatch.setattr(about_you.service, "setup_identity", lambda *a, **k: saved.append(a))
    d = about_you.AboutYouDialog(first_run=True)
    qtbot.addWidget(d)
    d.keyword.setText("ab")
    d.emails.setPlainText("not-an-email")
    d._save()
    assert not saved and not d.error.isHidden()
    d.keyword.setText("zorblat")
    d.emails.setPlainText("zorblat11@seclab.test, zorblat.old@seclab.test")
    d._save()
    assert saved == [("zorblat", ["zorblat11@seclab.test", "zorblat.old@seclab.test"], [], "")]


def test_window_builds_on_practice_data(qtbot, temp_data):
    w = main_window.MainWindow("lab")
    qtbot.addWidget(w)
    assert w.windowTitle().endswith("(practice mode)")
    assert w.target.itemText(0) == wording.CHECK["target_all"]
    w.kind.setCurrentIndex(w.kind.findData("full"))
    assert w.command.text() == "leakguard monitor -p lab"            # the same check from the command line


def test_check_summary_words():
    res = service.CheckResult(new=2, serious=1, candidates=["x@seclab.test"], problems=["hibp / x: error: ..."])
    text = " ".join(main_window.check_summary(res))
    assert "2 new things found" in text and "1 of them looks serious" in text
    assert "1 new address or username might be yours" in text and "1 service didn't work" in text
    assert main_window.check_summary(service.CheckResult(cancelled=True)) == [wording.CHECK["stopped"]]
    assert main_window.check_summary(service.CheckResult()) == [wording.CHECK["nothing_new"]]


def _lab_window(qtbot):
    w = main_window.MainWindow("lab")
    qtbot.addWidget(w)
    return w


def test_todo_answer_and_undo(qtbot, temp_data):
    from leakguard.models import Candidate, Finding
    w = _lab_window(qtbot)
    st = w.store
    st.seed("zorblat11@seclab.test", "email", "test")
    ident = st.identities("claimed")[-1]
    st.save_findings(st.start_scan("scan"), ident, "intelx",
                     [Finding("intelx", "leak", "IntelX: a.txt", severity="high", locator="i1")])
    st.add_candidate(Candidate("zorblat-fanclub", "username", "pse:http://127.0.0.1:5055/x"))
    page = w.pages["todo"]
    page.refresh()
    t = service.todo(w.settings, st)
    assert t.count == 3                                   # 1 identity, 1 question, 1 clean-up step
    page._answer(service.review_groups(t.review), "open")
    assert not service.todo(w.settings, st).review
    w.toast._action()                                     # Undo
    assert service.todo(w.settings, st).review


def test_send_needs_a_checked_address(qtbot, temp_data):
    from PySide6.QtWidgets import QPushButton
    from leakguard.gui import actions
    w = _lab_window(qtbot)
    aid, _ = w.store.upsert_action({"key": "account:y", "kind": "account_delete", "method": "email",
                                    "template": "account_deletion", "target": "Y", "finding_ids": [],
                                    "identities": ["zorblat11@seclab.test"], "contact": "guess@y.example",
                                    "contact_verified": False})
    d = actions.SendDialog(w, aid)
    qtbot.addWidget(d)
    assert "Send" not in [b.text() for b in d.findChildren(QPushButton)]     # a guessed address: never sendable
    service.set_contact(w.store, aid, "privacy@y.example")
    d.build()
    assert "Send" in [b.text() for b in d.findChildren(QPushButton)]
    assert w.store.action(aid)["state"] == "drafted"                         # shown, not sent
