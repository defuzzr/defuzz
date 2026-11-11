"""The /scaffold/match route carries the whole project pick-list under `catalog`."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule
from tests.fake_kit_bridge import FakeKitBridge, load_list_fixture

_FIXTURE_KIT_IDS = [k["id"] for k in load_list_fixture()["kits"]]
_OLD_KEYS = {"matches", "closest", "handoff", "kits", "kit_catalog", "kits_notice", "preferred"}
_FAILED = {"entries": [], "suggested": [], "notice": "The project list could not be built."}


def _routes() -> Any:
    return load_submodule("dashboard.plugin_api")._load("dashboard.routes.workspace_routes")


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    _routes()._reset_kit_cache_for_tests()


def _client(monkeypatch: pytest.MonkeyPatch, bridge: FakeKitBridge) -> TestClient:
    bridge.install(monkeypatch, load_submodule("componentize_bridge"))
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    bridge.install(monkeypatch, routes.componentize_bridge)
    routes._reset_kit_cache_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app)


def _match(client: TestClient, body: dict) -> dict:
    resp = client.post("/scaffold/match", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _expected_entries(bridge: FakeKitBridge) -> list:
    routes = _routes()
    catalog_list = load_submodule("catalog_list")
    kits, _notice, _status = routes.matcher.parse_kit_list(bridge.kit_list())
    entries = catalog_list.build_catalog(routes.templates.load_templates(), kits)
    return catalog_list.to_json(entries)["entries"]


def _keys(catalog: dict) -> list:
    return [f"{e['kind']}:{e['id']}" for e in catalog["entries"]]


BODIES = [
    {},
    {"prompt": ""},
    {"prompt": "portfolio website"},
    {"prompt": "set up a video production project", "answers": {"building": "video"}},
    {"prompt": "what is the weather today?"},
]


@pytest.mark.parametrize("body", BODIES)
def test_catalog_is_the_whole_list_on_every_branch(monkeypatch: pytest.MonkeyPatch, body: dict) -> None:
    bridge = FakeKitBridge()
    data = _match(_client(monkeypatch, bridge), body)
    assert _OLD_KEYS <= set(data)
    cat = data["catalog"]
    assert set(cat) == {"entries", "suggested", "notice"}
    assert cat["entries"] == _expected_entries(bridge)
    keys = _keys(cat)
    assert len(keys) == len(set(keys)) == 7 + len(_FIXTURE_KIT_IDS)
    assert sum(k.startswith("template:") for k in keys) == 7
    assert sorted(k[4:] for k in keys if k.startswith("kit:")) == sorted(_FIXTURE_KIT_IDS)
    assert set(cat["suggested"]) <= set(keys)
    assert len(cat["suggested"]) <= 3
    assert cat["notice"] == ""
    json.dumps(data)


def test_non_project_branch_has_catalog_and_message(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _match(_client(monkeypatch, FakeKitBridge()), {"prompt": "what is the weather today?"})
    assert "message" in data
    assert data["catalog"]["suggested"] == []
    assert data["catalog"]["entries"]


def test_suggested_empty_for_empty_idea_and_set_for_portfolio(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, FakeKitBridge())
    assert _match(client, {"prompt": ""})["catalog"]["suggested"] == []
    assert _match(client, {})["catalog"]["suggested"] == []
    assert _match(client, {"prompt": "portfolio website"})["catalog"]["suggested"]


def test_kits_unavailable_lists_templates_with_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, FakeKitBridge(status="unavailable", notice="componentize CLI is unavailable."))
    for body in ({}, {"prompt": "what is the weather today?"}):
        data = _match(client, body)
        cat = data["catalog"]
        assert {e["kind"] for e in cat["entries"]} == {"template"}
        assert len(cat["entries"]) == 7
        assert cat["notice"] == NOTICE_MISSING


def test_list_failure_keeps_rest_of_response(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, FakeKitBridge())
    body = {"prompt": "portfolio website"}
    normal = _match(client, body)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("broken")

    monkeypatch.setattr(_routes().catalog_list, "build_catalog_counted", boom)
    for b in (body, {"prompt": "what is the weather today?"}):
        failed = _match(client, b)
        assert failed["catalog"] == _FAILED
    failed = _match(client, body)
    # Pre-existing keys are byte-identical whether or not the list was built.
    assert set(normal) - {"catalog"} == _OLD_KEYS
    assert {k: v for k, v in normal.items() if k != "catalog"} == {
        k: v for k, v in failed.items() if k != "catalog"
    }


@pytest.mark.parametrize(
    "extra",
    [{}, {"template_id": ""}, {"kit_id": "  "}, {"template_id": None, "kit_id": None},
     {"template_id": "python-golden", "kit_id": "video-production"}],
)
def test_propose_refuses_without_exactly_one_explicit_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extra: dict
) -> None:
    client = _client(monkeypatch, FakeKitBridge())
    dest = tmp_path / "projects"
    dest.mkdir()
    resp = client.post("/scaffold/propose", json={"name": "Demo", "dest_root": str(dest), **extra})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Specify exactly one of template_id or kit_id"
    assert list(dest.iterdir()) == []
    assert _routes()._PROPOSALS == {}


NOTICE_MISSING = "Kits need the defuzz-componentize plugin. Install it, then run `hermes defuzz kits`."
NOTICE_TIMEOUT = "The kit list did not answer in time. Try again, or run `hermes defuzz kits`."
NOTICE_ERROR = "Kits are unavailable right now. Run `hermes defuzz kits` for details."
NOTICE_SETTINGS = "Kits could not be listed: componentize settings are invalid. Run `hermes defuzz kits`."
_TIMED_OUT = "Project kits check timed out: componentize kit list timed out."


def _patch_list(monkeypatch: pytest.MonkeyPatch, fn: Any) -> None:
    monkeypatch.setattr(_routes().componentize_bridge, "kit_list", fn)


def _reply(status: str, notice: str) -> Any:
    calls: list = []

    def kit_list(*, timeout: Any = None) -> dict:
        calls.append(timeout)
        return {"status": status, "data": None, "notice": notice, "exit_code": None}

    kit_list.calls = calls  # type: ignore[attr-defined]
    return kit_list


def _assert_templates_only(cat: dict, notice: str) -> None:
    kinds = [e["kind"] for e in cat["entries"]]
    assert kinds.count("template") == 7
    assert "kit" not in kinds
    assert cat["notice"] == notice
    assert len(cat["notice"]) <= 100
    assert "\n" not in cat["notice"] and "/" not in cat["notice"].replace("`hermes defuzz kits`", "")


def test_hanging_kit_list_is_bounded_to_five_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, FakeKitBridge())
    seen: list = []

    def slow(*, timeout: Any = None) -> dict:
        seen.append(timeout)
        time.sleep(30 if timeout is None else min(30, timeout))
        return {"status": "error", "data": None, "notice": _TIMED_OUT, "exit_code": None}

    _patch_list(monkeypatch, slow)
    start = time.monotonic()
    data = _match(client, {})
    elapsed = time.monotonic() - start
    print(f"hanging lookup took {elapsed:.2f}s")
    assert seen == [5]
    assert elapsed < 7
    _assert_templates_only(data["catalog"], NOTICE_TIMEOUT)
    # Negative result is cached: a second call inside the TTL does not wait again.
    start = time.monotonic()
    again = _match(client, {"prompt": "portfolio website"})
    assert time.monotonic() - start < 1
    assert seen == [5]
    _assert_templates_only(again["catalog"], NOTICE_TIMEOUT)


FAILURES = [
    ("unavailable", "componentize CLI is unavailable", NOTICE_MISSING),
    ("error", _TIMED_OUT, NOTICE_TIMEOUT),
    ("error", "componentize kit list error (exit 2): boom: /tmp/x/no catalog", NOTICE_ERROR),
    ("error", "componentize kit list exited 1 without valid fail envelope.", NOTICE_ERROR),
    ("error", "componentize kit list returned invalid JSON.", NOTICE_ERROR),
    ("error", "componentize kit list returned wrong schema.", NOTICE_ERROR),
    ("error", "componentize kit list envelope validation failed.", NOTICE_ERROR),
    ("error", "componentize kit list envelope status mismatch on exit 0.", NOTICE_ERROR),
    ("error", "componentize kit list failed: output too large", NOTICE_ERROR),
    ("error", "componentize settings error: Expecting value: line 1 column 1 (char 0)", NOTICE_SETTINGS),
    ("error", "", NOTICE_ERROR),
]


@pytest.mark.parametrize(("status", "raw", "notice"), FAILURES)
def test_each_failure_lists_templates_with_short_notice(
    monkeypatch: pytest.MonkeyPatch, status: str, raw: str, notice: str
) -> None:
    client = _client(monkeypatch, FakeKitBridge())
    fake = _reply(status, raw)
    _patch_list(monkeypatch, fake)
    for body in ({}, {"prompt": "what is the weather today?"}):
        _assert_templates_only(_match(client, body)["catalog"], notice)
    assert fake.calls == [5]


def test_raising_kit_list_lists_templates_with_error_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, FakeKitBridge())

    def boom(*, timeout: Any = None) -> dict:
        raise ImportError("no plugin storage at /somewhere")

    _patch_list(monkeypatch, boom)
    _assert_templates_only(_match(client, {})["catalog"], NOTICE_ERROR)


def test_ok_path_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    cat = _match(_client(monkeypatch, FakeKitBridge()), {})["catalog"]
    assert len(cat["entries"]) == 21
    assert cat["notice"] == ""


def test_kit_details_route_keeps_default_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, FakeKitBridge())
    fake = _reply("unavailable", "componentize CLI is unavailable")
    _patch_list(monkeypatch, fake)
    assert client.get("/scaffold/kits/video-production").status_code == 503
    assert fake.calls == [None]

_SECRET = "ZZBADKITTEXT"


def _bad_kits(n: int) -> list:
    """Entries the bridge accepts but the parser skips (empty name / empty tag)."""
    out = []
    for i in range(n):
        if i % 2:
            out.append({"id": f"bad-{i}", "name": "", "summary": _SECRET, "tags": [], "version": 1})
        else:
            out.append({"id": f"bad-{i}", "name": _SECRET, "summary": _SECRET, "tags": [""], "version": 1})
    return out


_SKIP_LINES = {
    0: "",
    1: "1 kit was skipped because its description is not valid. Run `hermes defuzz kits`.",
    3: "3 kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`.",
}


@pytest.mark.parametrize("n", [0, 1, 3])
def test_catalog_notice_counts_skipped_kits(monkeypatch: pytest.MonkeyPatch, n: int) -> None:
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = list(bridge._list_data["kits"]) + _bad_kits(n)
    client = _client(monkeypatch, bridge)
    for body in ({}, {"prompt": "what is the weather today?"}, {"prompt": "portfolio website"}):
        data = _match(client, body)
        assert data["catalog"]["notice"] == _SKIP_LINES[n]
        assert _SECRET not in json.dumps(data)
        kit_ids = [e["id"] for e in data["catalog"]["entries"] if e["kind"] == "kit"]
        assert kit_ids == _FIXTURE_KIT_IDS or sorted(kit_ids) == sorted(_FIXTURE_KIT_IDS)


def test_catalog_all_kits_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = _bad_kits(3)
    data = _match(_client(monkeypatch, bridge), {})
    assert data["catalog"]["notice"] == _SKIP_LINES[3]
    assert {e["kind"] for e in data["catalog"]["entries"]} == {"template"}


def test_match_route_never_lists_unsafe_kit_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = ["--yes", "../../etc/passwd", "a b; rm -rf ~", "id\x1b[31mred", "id\u202ertl", "3"]
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = list(bridge._list_data["kits"]) + [
        {"id": i, "name": "Hostile", "summary": "s", "tags": ["x"], "version": 1} for i in bad]
    cat = _match(_client(monkeypatch, bridge), {"prompt": "set up a video production project"})["catalog"]
    ids = [e["id"] for e in cat["entries"]]
    assert not set(ids) & set(bad)
    assert sorted(i for i in ids if not i.endswith("-golden")) == sorted(_FIXTURE_KIT_IDS)
    assert all(e["flag"] in (f"--kit {e['id']}", f"--template {e['id']}") for e in cat["entries"])


def test_match_route_notice_counts_unsafe_kit_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = ["--yes", "../../etc/passwd", "a b; rm -rf ~", "id\x1b[31mred", "id\u202ertl", "3"]
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = list(bridge._list_data["kits"]) + [
        {"id": i, "name": "Hostile", "summary": "s", "tags": ["x"], "version": 1} for i in bad]
    client = _client(monkeypatch, bridge)
    for body in ({}, {"prompt": "what is the weather today?"}, {"prompt": "portfolio website"}):
        cat = _match(client, body)["catalog"]
        assert cat["notice"] == (
            f"{len(bad)} kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`.")
