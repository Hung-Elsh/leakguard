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
