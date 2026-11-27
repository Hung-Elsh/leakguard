"""Your own tools (custom_tools.py + plugins/manifest.py): validation, the three output formats, one argument
per value (no shell), switched on/off, profile separation, and test-before-save."""

import dataclasses
import json

import pytest

from leakguard import config, custom_tools, engine, plugins, runner, service
from leakguard.plugins.manifest import ManifestTool, fill, keep, results
from leakguard.store import Store

ECHO = ("import json,sys; v=sys.argv[1]; print(json.dumps({'results': ["
        "{'site': 'Echo', 'url': 'https://echo.example/u/' + v, 'exists': True}, "
        "{'site': 'Gone', 'url': '', 'exists': False}]}))")


def echo_tool(**over) -> dict:
    m = {"id": "echo", "name": "Echo", "about": "test", "checks": ["email"],
         "command": ["python3", "-c", ECHO, "{value}"],
         "output": {"format": "json", "items": "results", "match": {"field": "exists", "equals": True},
                    "title": "Account on {site}", "url": "{url}", "site": "{site}"},
         "category": "account", "severity": "low", "timeout": 60, "enabled": True}
    m.update(over)
    return m


@pytest.fixture
def lab():
    return config.load("lab")


@pytest.fixture
def internet(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "DATA", tmp_path / "data")        # raw tool output stays in the temp dir
    yield dataclasses.replace(lab, profile="internet", keys={}, tools_mode="run", fixtures_dir=None)
    plugins.reload_custom()                                       # forget the test's tools


def test_plain_problems():
    taken = service.builtin_ids()
    assert custom_tools.problems(echo_tool(), taken) == []
    assert "Write {value}" in " ".join(custom_tools.problems(echo_tool(command=["x", "--json"]), taken))
    assert "already a built-in check" in " ".join(custom_tools.problems(echo_tool(id="holehe"), taken))
    lines = echo_tool(output={"format": "lines", "pattern": r"\S+", "title": "x"})
    assert "named parts" in " ".join(custom_tools.problems(lines, taken))
    assert custom_tools.slug("My Forum Tool!") == "my-forum-tool"


def test_three_output_formats():
    js = {"format": "json", "items": "data.hits", "match": {"field": "ok"}, "title": "{site} ({profile.name})"}
    text = json.dumps({"data": {"hits": [{"site": "A", "ok": 1, "profile": {"name": "Zor"}}, {"site": "B", "ok": 0}]}})
    kept = [i for i in results(js, text) if keep(js, i)]
    assert [fill(js["title"], i) for i in kept] == ["A (Zor)"]
    jl = {"format": "jsonl", "title": "{site}"}
    assert [i["site"] for i in results(jl, 'progress...\n{"site": "A"}\n{"site": "B"}\n')] == ["A", "B"]
    ln = {"format": "lines", "pattern": r"^\[\+\] (?P<site>\S+): (?P<url>\S+)", "title": "Account on {site}"}
    assert results(ln, "[*] checking\n[+] Forum: https://f.example/u\n") == [{"site": "Forum", "url": "https://f.example/u"}]


def test_value_is_one_argument_never_a_shell(monkeypatch):
    monkeypatch.setattr("leakguard.plugins.manifest.find_binary", lambda *a: "/usr/bin/tool")
    t = ManifestTool(echo_tool(command=["tool", "--email={value}", "{value}"]))
    assert t.command("a b;rm -rf ~") == ["/usr/bin/tool", "--email=a b;rm -rf ~", "a b;rm -rf ~"]


def test_runs_in_your_checks_only_while_switched_on(internet, tmp_path):
    service.save_tool(echo_tool())
    store = Store(tmp_path / "t.sqlite")                          # scan claims the profile's own address
    r = engine.scan(internet, store, ["echo"])
    assert r.runs == [("echo", "zorblat11@seclab.test", "ok, 1 finding(s)")]
    f = store.findings()[0]
    assert f["title"] == "Account on Echo" and f["url"] == "https://echo.example/u/zorblat11@seclab.test"
    service.switch_tool("echo", False)
    r = engine.scan(internet, store, ["echo"])
    assert "skipped" in r.runs[0][2] and "turned off" in r.runs[0][2]
    assert service.remove_tool("echo") and "echo" not in plugins.BY_NAME


def test_profiles_stay_separate(lab, internet):
    names = lambda s: {p.name for p in plugins.active(s)}
    assert "forumcheck" in names(lab) and "forumcheck" not in names(internet)    # the lab's example
    service.save_tool(echo_tool())
    assert "echo" in names(internet) and "echo" not in names(lab)                # your tool: real checks only


def test_try_before_saving(lab, internet):
    t = service.try_tool(internet, echo_tool(), "me@example.org")
    assert t.ok and t.found == ["Account on Echo"] and not custom_tools.load("user")   # nothing saved
    bad = service.try_tool(internet, echo_tool(command=["definitely-not-a-program-xyz", "{value}"]))
    assert bad.problem == "not_installed"
    example = custom_tools.load("lab")[0]
    assert service.try_tool(lab, example).found == ["Account on LabForum2", "Account on QuietBoard"]
