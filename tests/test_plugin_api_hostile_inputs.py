"""Hostile request inputs to every Defuzz dashboard route: always a 4xx with one plain sentence, never a 500.

The route list is taken from ``plugin_api.router`` itself, so a route added later is
covered by the table-driven matrix without editing this file.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from tests.conftest import load_submodule

PREFIX = "/api/plugins/defuzz"


# ---------------------------------------------------------------------------
# fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def api() -> Any:
    return load_submodule("dashboard.plugin_api")


@pytest.fixture()
def client(api: Any, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Never run real lint, setup or audits from the hostile matrix.
    monkeypatch.setattr(api._load("linter"), "run_lint", lambda *a, **k: {"ok": True, "stub": True})
    monkeypatch.setattr(api._load("lint_setup"), "run_setup", lambda *a, **k: {"ok": False, "error": "stub"})
    audit_routes = api._load("dashboard.routes.audit_routes")
    monkeypatch.setattr(audit_routes, "execute_audit", lambda args, **k: {"status": "stub", "action": args.get("action")})
    monkeypatch.setattr(api._load("toolchk"), "probe", lambda *a, **k: ("20.11.0", "/usr/bin/node"))
    app = FastAPI()
    # Mount the way Hermes does (include_router with a prefix), so the guard must survive re-inclusion.
    app.include_router(api.router, prefix=PREFIX)
    return TestClient(app, raise_server_exceptions=False)


def _message(resp: Any) -> str:
    data = resp.json()
    assert isinstance(data, dict), resp.text
    msg = data.get("detail", data.get("error"))
    assert isinstance(msg, str), resp.text
    return msg


def _assert_plain_refusal(resp: Any, *, label: str = "") -> str:
    assert 400 <= resp.status_code < 500, f"{label}: {resp.status_code} {resp.text[:300]}"
    msg = _message(resp)
    assert msg.strip(), label
    assert "\n" not in msg, f"{label}: {msg!r}"
    assert "Traceback" not in msg and "Error:" not in msg[:40], f"{label}: {msg!r}"
    assert len(msg) <= 300, f"{label}: {len(msg)} chars"
    return msg


def _project(tmp_path: Path, name: str = "proj") -> Path:
    proj = tmp_path / "work" / name
    proj.mkdir(parents=True)
    (proj / "package.json").write_text('{"name": "hostile-proj"}\n', encoding="utf-8")
    return proj


def _seed(client: TestClient, proj: Path) -> None:
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True})
    assert resp.status_code == 200, resp.text
    assert (proj / "TOOLS.lock").is_file()


# ---------------------------------------------------------------------------
# defect 2: relative / ~ / empty / control-character project paths
# ---------------------------------------------------------------------------


PROJECT_ROUTES = (
    ("POST", "/lint", {}),
    ("POST", "/tools-lock/init", {"confirm": True}),
    ("POST", "/tools-lock/reason", {"tool": "node", "reason": "x"}),
    ("POST", "/tools-lock/accept", {"tool": "node", "reason": "x"}),
    ("POST", "/tools-lock/snooze", {"tool": "node", "days": 1}),
    ("POST", "/tools-lock/trust", {"confirm": True, "expected_hash": "0" * 64}),
    ("GET", "/tools-lock", None),
)


def _bad_project_values(proj: Path) -> list[tuple[str, Any]]:
    rel = str(Path("work") / proj.name)
    return [
        ("relative", rel),
        ("dot relative", "." + "/" + rel),
        ("empty", ""),
        ("blank", "   "),
        ("tilde", "~"),
        ("tilde path", "~" + "/" + rel),
        ("control", f"{proj}\x01"),
        ("escape", f"{proj}\x1b[31m"),
        ("newline", f"{proj}\nx"),
        ("nul", f"{proj}\x00x"),
        ("too long", "/" + "a" * 5000),
        ("int", 12345),
        ("list", [str(proj)]),
    ]


@pytest.mark.parametrize("method,route,extra", PROJECT_ROUTES, ids=[r for _m, r, _e in PROJECT_ROUTES])
def test_project_path_must_be_absolute_text(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                             method: str, route: str, extra: dict[str, Any] | None) -> None:
    proj = _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    for label, value in _bad_project_values(proj):
        if method == "GET":
            if not isinstance(value, str):
                continue
            resp = client.get(f"{PREFIX}{route}", params={"project": value})
        else:
            resp = client.post(f"{PREFIX}{route}", json={"project": value, **(extra or {})})
        msg = _assert_plain_refusal(resp, label=f"{route} {label}")
        assert resp.status_code == 400, f"{route} {label}: {resp.status_code} {msg}"
    # Nothing was written for any refused request, including the cwd-relative one.
    assert not (proj / "TOOLS.lock").exists()
    assert not (proj / ".adopt").exists()


def test_relative_project_message_names_the_problem(client: TestClient, tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    rel = str(Path("work") / proj.name)
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": rel, "confirm": True})
    assert resp.status_code == 400
    assert "full path" in _message(resp)
    resp = client.post(f"{PREFIX}/lint", json={"project": "~" + "/" + rel})
    assert resp.status_code == 400
    assert "~" in _message(resp)


def test_absolute_project_with_surrounding_spaces_still_works(client: TestClient, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": f"  {proj}  ", "confirm": True})
    assert resp.status_code == 200, resp.text
    assert (proj / "TOOLS.lock").is_file()


def test_other_path_taking_routes_refuse_relative_paths(client: TestClient, tmp_path: Path,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    rel = str(Path("work") / proj.name)
    cases = [
        ("GET", "/workspace/file", {"params": {"project": rel, "path": "package.json"}}),
        ("GET", "/componentize/status", {"params": {"project_root": rel}}),
        ("PUT", "/componentize/settings", {"json": {"cli_path_override": str(Path("bin") / "componentize")}}),
        ("POST", "/audit/start", {"json": {"root": rel}}),
        ("POST", "/audit/start", {"json": {"selected_projects": [rel]}}),
        ("POST", "/audit/start", {"json": {"selected_projects": ["~" + "/" + rel]}}),
        ("POST", "/scaffold/propose", {"json": {"template_id": "python-golden", "name": "demo", "dest_root": rel}}),
    ]
    for method, route, kwargs in cases:
        resp = client.request(method, f"{PREFIX}{route}", **kwargs)
        _assert_plain_refusal(resp, label=f"{method} {route} {kwargs}")
        assert resp.status_code == 400, f"{route}: {resp.status_code} {resp.text}"
    # The refused override must not have been saved.
    resp = client.get(f"{PREFIX}/componentize/settings")
    assert resp.json().get("cli_path_override") is None


# ---------------------------------------------------------------------------
# defect 3: free text written into TOOLS.lock is bounded by the lock's own size limit
# ---------------------------------------------------------------------------


def test_huge_reason_is_refused_and_lock_stays_readable(client: TestClient, api: Any, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    _seed(client, proj)
    before = (proj / "TOOLS.lock").read_bytes()
    limit = api.MAX_REASON_CHARS
    assert limit == api._load("toolchk").MAX_LOCK_BYTES // 256
    for route in ("/tools-lock/reason", "/tools-lock/accept"):
        for reason in ("r" * 1_000_000, "r" * (limit + 1)):
            resp = client.post(f"{PREFIX}{route}", json={"project": str(proj), "tool": "node", "reason": reason})
            msg = _assert_plain_refusal(resp, label=f"{route} {len(reason)}")
            assert resp.status_code == 400
            # 1 MB is stopped by the body cap; just over the reason limit by the reason rule.
            assert str(limit) in msg or "KiB" in msg
        assert (proj / "TOOLS.lock").read_bytes() == before
    resp = client.get(f"{PREFIX}/tools-lock", params={"project": str(proj)})
    assert resp.status_code == 200 and resp.json()["rows"], resp.text
    ok = client.post(f"{PREFIX}/tools-lock/reason", json={"project": str(proj), "tool": "node", "reason": "r" * limit})
    assert ok.status_code == 200, ok.text
    assert client.get(f"{PREFIX}/tools-lock", params={"project": str(proj)}).status_code == 200


def test_reason_with_control_characters_is_refused(client: TestClient, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    _seed(client, proj)
    before = (proj / "TOOLS.lock").read_bytes()
    for reason in ("a\x00b", "a\x1b[2Jb", "a\x7fb"):
        resp = client.post(f"{PREFIX}/tools-lock/reason", json={"project": str(proj), "tool": "node", "reason": reason})
        assert resp.status_code == 400, resp.text
        _assert_plain_refusal(resp)
    assert (proj / "TOOLS.lock").read_bytes() == before
    ok = client.post(f"{PREFIX}/tools-lock/reason", json={"project": str(proj), "tool": "node", "reason": "line one\n\tline two"})
    assert ok.status_code == 200, ok.text


def test_reason_that_would_overflow_a_nearly_full_lock_is_refused(client: TestClient, api: Any, tmp_path: Path) -> None:
    toolchk = api._load("toolchk")
    proj = _project(tmp_path)
    _seed(client, proj)
    loaded = toolchk.load_lock(proj / "TOOLS.lock")
    filler = "f" * api.MAX_REASON_CHARS
    i = 0
    while (proj / "TOOLS.lock").stat().st_size < toolchk.MAX_LOCK_BYTES - 1500:
        loaded["tools"][f"extra{i:04d}"] = {"version": "1.0.0", "chosen": "2026-11-06", "reason": filler,
                                           "probe": "command", "argv": ["true"], "source": "human"}
        toolchk.dump_lock(proj / "TOOLS.lock", loaded)
        i += 1
    before = (proj / "TOOLS.lock").read_bytes()
    assert len(before) <= toolchk.MAX_LOCK_BYTES
    resp = client.post(f"{PREFIX}/tools-lock/reason",
                       json={"project": str(proj), "tool": "node", "reason": "\u00e9" * api.MAX_REASON_CHARS})
    msg = _assert_plain_refusal(resp)
    assert resp.status_code == 400
    assert "TOOLS.lock" in msg
    assert (proj / "TOOLS.lock").read_bytes() == before
    assert client.get(f"{PREFIX}/tools-lock", params={"project": str(proj)}).status_code == 200


def test_init_event_is_bounded_text(client: TestClient, api: Any, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    for event in ("e" * (api.MAX_EVENT_CHARS + 1), "e" * 1_000_000, "a\x00b", 5, ["x"], {"a": 1}):
        resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True, "event": event})
        _assert_plain_refusal(resp, label=repr(event)[:40])
        assert resp.status_code == 400
    assert not (proj / "TOOLS.lock").exists()
    ok = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True, "event": "re-check"})
    assert ok.status_code == 200, ok.text


# ---------------------------------------------------------------------------
# defect 4: 500s from huge numbers and deep nesting
# ---------------------------------------------------------------------------


def test_snooze_days_range(client: TestClient, api: Any, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    _seed(client, proj)
    max_days = api._load("tool_seed").MAX_SNOOZE_DAYS
    for days in (10**30, 10**18, max_days + 1, -1, 1.5, "7", True, None, [1]):
        resp = client.post(f"{PREFIX}/tools-lock/snooze", json={"project": str(proj), "tool": "node", "days": days})
        _assert_plain_refusal(resp, label=repr(days)[:30])
        assert resp.status_code == 400
    raw = b'{"project": ' + json.dumps(str(proj)).encode() + b', "tool": "node", "days": 1' + b"0" * 5000 + b"}"
    resp = client.post(f"{PREFIX}/tools-lock/snooze", content=raw, headers={"content-type": "application/json"})
    _assert_plain_refusal(resp, label="5000-digit days")
    ok = client.post(f"{PREFIX}/tools-lock/snooze", json={"project": str(proj), "tool": "node", "days": max_days})
    assert ok.status_code == 200, ok.text


def test_ui_state_seq_range(client: TestClient) -> None:
    for seq in (10**40, 2**63, 2**53, 0, -1, "1", 1.5, True):
        resp = client.post(f"{PREFIX}/ui-state", json={"key": "workspace", "value": 1, "seq": seq})
        _assert_plain_refusal(resp, label=repr(seq)[:30])
        assert resp.status_code == 400
    ok = client.post(f"{PREFIX}/ui-state", json={"key": "workspace", "value": {"tab": "lint"}, "seq": 2**53 - 1})
    assert ok.status_code == 200 and ok.json()["seq"] == 2**53 - 1, ok.text


def test_ui_state_key_control_characters_refused(client: TestClient) -> None:
    resp = client.post(f"{PREFIX}/ui-state", json={"key": "a\x00\x1b", "value": 1, "seq": 9})
    assert resp.status_code == 400, resp.text
    _assert_plain_refusal(resp)


def _nested(depth: int) -> bytes:
    return b'{"a":' * depth + b"1" + b"}" * depth


def test_match_with_deeply_nested_answers_is_400(client: TestClient) -> None:
    for depth in (100, 5000, 100_000):
        raw = b'{"answers":' + _nested(depth) + b"}"
        resp = client.post(f"{PREFIX}/scaffold/match", content=raw, headers={"content-type": "application/json"})
        msg = _assert_plain_refusal(resp, label=f"depth {depth}")
        assert resp.status_code == 400
        assert "nested" in msg or "KiB" in msg


# ---------------------------------------------------------------------------
# defect 1b: prompt and body size for the idea parser routes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ["/scaffold/parse-idea", "/scaffold/match"])
def test_prompt_length_and_body_size_are_capped(client: TestClient, api: Any, route: str) -> None:
    limit = api.MAX_PROMPT_CHARS
    t0 = time.monotonic()
    resp = client.post(f"{PREFIX}{route}", json={"prompt": "python " * 300_000})
    assert time.monotonic() - t0 < 5
    msg = _assert_plain_refusal(resp, label="2MB prompt")
    assert resp.status_code == 400
    resp = client.post(f"{PREFIX}{route}", json={"prompt": "p" * (limit + 1)})
    msg = _assert_plain_refusal(resp, label="limit+1")
    assert resp.status_code == 400 and str(limit) in msg
    big_body = {"prompt": "a Python tool", "answers": {"x": "y" * (api.MAX_PROMPT_BODY_BYTES + 1)}}
    resp = client.post(f"{PREFIX}{route}", json=big_body)
    _assert_plain_refusal(resp, label="body over limit")
    assert resp.status_code == 400
    ok = client.post(f"{PREFIX}{route}", json={"prompt": ("a Python command-line tool " * 200)[:limit]})
    assert ok.status_code == 200, ok.text[:300]


def test_body_size_cap_counts_bytes_not_declared_length(client: TestClient, api: Any) -> None:
    payload = b'{"prompt": "' + b"p" * (api.MAX_PROMPT_BODY_BYTES * 2) + b'"}'

    def chunks():
        for i in range(0, len(payload), 4096):
            yield payload[i:i + 4096]

    resp = client.post(f"{PREFIX}/scaffold/parse-idea", content=chunks(), headers={"content-type": "application/json"})
    _assert_plain_refusal(resp, label="chunked")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# general rule: the hostile matrix against EVERY route on the router
# ---------------------------------------------------------------------------


def _routes(api: Any) -> list[tuple[str, APIRoute]]:
    out = []
    for route in api.router.routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods):
                out.append((method, route))
    return out


_PARAM_RE = re.compile(r"{([^}:]+)(:[^}]*)?}")


def _fill_path(path: str, value: str) -> str:
    return _PARAM_RE.sub(lambda _m: value, path)


_HUGE = 10**40
_WRONG_TYPES = {
    "project": 12345, "tool": ["x"], "reason": {"a": 1}, "days": "7", "seq": _HUGE, "key": 5, "value": float("nan"),
    "prompt": ["x"], "answers": [], "template_id": 7, "kit_id": 7, "name": {}, "dest_root": 5, "proposal_id": 1,
    "confirm": "yes", "expected_hash": 5, "mode": 5, "event": [1], "options": [], "variables": 5,
    "run_id": 5, "root": 5, "selected_projects": "x", "quick": "x", "full_home": "x", "sessions": "x",
    "max_entries": _HUGE, "as_of": _HUGE, "unused_threshold_days": _HUGE, "languages_chosen": "x",
    "enabled_on_adopt": "x", "run_survey_on_new": "x", "cli_path_override": 5, "remember_options": "x",
}


# Bodies no route may accept: broken syntax, bad encoding, non-finite or huge numbers,
# deep nesting, oversized. (A list, null or a string can be fine for a route that
# ignores its body, e.g. POST /setup/cancel.)
_MUST_REFUSE = {"malformed json", "not utf-8", "json number", "nan", "infinity", "huge float", "huge int",
                "deep 100k", "deep 5000 under answers", "deep 5000 under value", "deep array", "2MB body",
                "huge numbers"}


def _hostile_bodies() -> list[tuple[str, bytes]]:
    deep = _nested(100_000)
    return [
        ("malformed json", b'{"confirm": tru'),
        ("not utf-8", b'{"prompt": "\xff\xfe"}'),
        ("json list", b"[1, 2, 3]"),
        ("json null", b"null"),
        ("json string", b'"x"'),
        ("json number", b"1e400"),
        ("nan", b'{"days": NaN}'),
        ("infinity", b'{"seq": Infinity}'),
        ("huge float", b'{"days": 1e400}'),
        ("huge int", b'{"days": ' + b"9" * 5000 + b"}"),
        ("deep 100k", deep),
        ("deep 5000 under answers", b'{"answers":' + _nested(5000) + b"}"),
        ("deep 5000 under value", b'{"key":"workspace","seq":3,"value":' + _nested(5000) + b"}"),
        ("deep array", b"[" * 50_000 + b"]" * 50_000),
        ("2MB body", json.dumps({"prompt": "python " * 300_000}).encode()),
        ("wrong types", json.dumps({k: v for k, v in _WRONG_TYPES.items() if v == v}).encode()),
        ("huge numbers", json.dumps({k: _HUGE for k in _WRONG_TYPES}).encode()),
        ("control chars", json.dumps({k: "a\x00\x1b[2J\n" for k in _WRONG_TYPES}).encode()),
        ("long strings", json.dumps({k: "/" + "a" * 20_000 for k in ("project", "prompt", "reason", "key", "tool")}).encode()),
    ]


_HOSTILE_QUERY_VALUES = [
    ("nul", "a\x00b"),
    ("control", "\x01\x1b[31m"),
    ("huge", "/" + "a" * 20_000),
    ("relative", "a/b"),
    ("dotdot", "../../etc"),
]


def test_every_route_survives_the_hostile_matrix(client: TestClient, api: Any, tmp_path: Path,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    routes = _routes(api)
    paths = {r.path for _m, r in routes}
    # Sanity: the enumeration really sees all four route modules.
    for expected in ("/lint", "/tools-lock/snooze", "/scaffold/match", "/ui-state", "/audit/start",
                     "/componentize/settings"):
        assert expected in paths, sorted(paths)
    failures: list[str] = []

    def check(label: str, resp: Any) -> None:
        # 503 "componentize CLI is unavailable" is a real answer; 500 is a crash.
        if resp.status_code == 500 or "Traceback" in resp.text:
            failures.append(f"{label}: {resp.status_code} {resp.text[:200]}")
            return
        if resp.status_code >= 400:
            try:
                msg = _message(resp)
            except (AssertionError, ValueError):
                failures.append(f"{label}: {resp.status_code} not a plain message: {resp.text[:200]}")
                return
            if "\n" in msg or len(msg) > 300 or not msg.strip():
                failures.append(f"{label}: {resp.status_code} not one plain sentence: {msg[:200]!r}")

    for method, route in routes:
        url = PREFIX + _fill_path(route.path, "x")
        label = f"{method} {route.path}"
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            for blabel, raw in _hostile_bodies():
                resp = client.request(method, url, content=raw, headers={"content-type": "application/json"})
                check(f"{label} body {blabel}", resp)
                if resp.status_code < 400 and blabel in _MUST_REFUSE:
                    failures.append(f"{label} body {blabel}: accepted with {resp.status_code}")
            resp = client.request(method, url, content=b"x" * 64, headers={"content-type": "text/plain"})
            check(f"{label} text/plain", resp)
        query_names = [p.alias for p in route.dependant.query_params]
        for qlabel, qval in _HOSTILE_QUERY_VALUES:
            params = {name: qval for name in query_names} or {"junk": qval}
            resp = client.request(method, url, params=params)
            check(f"{label} query {qlabel}", resp)
        if route.dependant.path_params:
            for plabel, pval in (("huge", "a" * 6000), ("encoded dotdot", "..%2F..%2Fetc"), ("control", "%01%1b")):
                resp = client.request(method, PREFIX + _fill_path(route.path, pval))
                check(f"{label} path {plabel}", resp)
    assert not failures, "\n".join(failures)


def test_validation_errors_are_plain_sentences(client: TestClient) -> None:
    # Missing required query parameters used to answer 422 with a list of error objects.
    resp = client.get(f"{PREFIX}/workspace/file")
    msg = _assert_plain_refusal(resp)
    assert resp.status_code == 400
    assert "path" in msg or "project" in msg
    resp = client.get(f"{PREFIX}/audit/status")
    _assert_plain_refusal(resp)
    resp = client.post(f"{PREFIX}/setup", content=b'{"confirm": tru', headers={"content-type": "application/json"})
    _assert_plain_refusal(resp)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# parser limit (prompt_parse.MAX_PROMPT_CHARS / PromptTooLongError on the parser branch)
# ---------------------------------------------------------------------------


def test_prompt_cap_follows_the_parser_limit(api: Any) -> None:
    prompt_parse = api._load("prompt_parse")
    assert api.MAX_PROMPT_CHARS == getattr(prompt_parse, "MAX_PROMPT_CHARS", 2048)
    assert api.MAX_PROMPT_CHARS <= 2048


@pytest.mark.parametrize("route", ["/scaffold/parse-idea", "/scaffold/match"])
def test_parser_value_error_is_a_plain_400(client: TestClient, api: Any, monkeypatch: pytest.MonkeyPatch,
                                           route: str) -> None:
    routes = api._load("dashboard.routes.workspace_routes")

    class _TooLong(ValueError):
        pass

    def _raise(_prompt: str, *a: Any, **k: Any) -> Any:
        raise _TooLong("Prompt is too long: 9 characters (limit 8). Describe the project in a sentence.")

    monkeypatch.setattr(routes.prompt_parse, "parse_deterministic", _raise)
    resp = client.post(f"{PREFIX}{route}", json={"prompt": "a python tool"})
    msg = _assert_plain_refusal(resp, label=route)
    assert resp.status_code == 400
    assert msg.startswith("Prompt is too long")


@pytest.mark.parametrize("route", ["/scaffold/parse-idea", "/scaffold/match"])
def test_whitespace_prompt_is_capped_before_stripping(client: TestClient, api: Any,
                                                      monkeypatch: pytest.MonkeyPatch, route: str) -> None:
    matcher = api._load("dashboard.routes.workspace_routes").matcher
    called: list[int] = []
    real = matcher.match_kits
    monkeypatch.setattr(matcher, "match_kits", lambda infos, prompt, answers: called.append(len(prompt)) or real(infos, prompt, answers))
    for prompt in (" " * (api.MAX_PROMPT_CHARS + 1), "\n\t " * 3000):
        resp = client.post(f"{PREFIX}{route}", json={"prompt": prompt})
        msg = _assert_plain_refusal(resp, label=f"{route} whitespace {len(prompt)}")
        assert resp.status_code == 400
        assert str(api.MAX_PROMPT_CHARS) in msg or "KiB" in msg
    assert called == []
    ok = client.post(f"{PREFIX}{route}", json={"prompt": "a Python tool" + " " * (api.MAX_PROMPT_CHARS - 13)})
    assert ok.status_code == 200, ok.text[:200]
