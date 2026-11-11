"""Path-taking dashboard routes refuse '..' segments and never answer 500 for a write error."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule

PREFIX = "/api/plugins/defuzz"


@pytest.fixture()
def api() -> Any:
    return load_submodule("dashboard.plugin_api")


@pytest.fixture()
def client(api: Any, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(api._load("linter"), "run_lint", lambda *a, **k: {"ok": True, "stub": True})
    monkeypatch.setattr(api._load("lint_setup"), "run_setup", lambda *a, **k: {"ok": False, "error": "stub"})
    audit_routes = api._load("dashboard.routes.audit_routes")
    monkeypatch.setattr(audit_routes, "execute_audit", lambda args, **k: {"status": "stub"})
    monkeypatch.setattr(api._load("toolchk"), "probe", lambda *a, **k: ("20.11.0", "/usr/bin/node"))
    app = FastAPI()
    app.include_router(api.router, prefix=PREFIX)
    return TestClient(app, raise_server_exceptions=False)


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "work" / "proj"
    proj.mkdir(parents=True)
    (proj / "package.json").write_text('{"name": "boundary-proj"}\n', encoding="utf-8")
    return proj


def _plain(resp: Any, label: str) -> str:
    assert resp.status_code == 400, f"{label}: {resp.status_code} {resp.text[:300]}"
    msg = resp.json().get("detail", resp.json().get("error"))
    assert isinstance(msg, str) and msg.strip(), label
    assert "\n" not in msg and "Traceback" not in msg and len(msg) <= 300, f"{label}: {msg!r}"
    return msg


PROJECT_ROUTES = (
    ("POST", "/lint", {}),
    ("POST", "/tools-lock/init", {"confirm": True}),
    ("POST", "/tools-lock/reason", {"tool": "node", "reason": "x"}),
    ("POST", "/tools-lock/accept", {"tool": "node", "reason": "x"}),
    ("POST", "/tools-lock/snooze", {"tool": "node", "days": 1}),
    ("POST", "/tools-lock/trust", {"confirm": True, "expected_hash": "0" * 64}),
    ("GET", "/tools-lock", None),
)


def _dotdot_values(proj: Path) -> list[str]:
    return [
        "/tmp/../../etc",
        f"{proj}/../proj",
        f"{proj}/..",
        f"{proj.parent}/./../work/proj/",
    ]


@pytest.mark.parametrize("method,route,extra", PROJECT_ROUTES, ids=[r for _m, r, _e in PROJECT_ROUTES])
def test_project_routes_refuse_dotdot(client: TestClient, tmp_path: Path, method: str, route: str,
                                      extra: dict[str, Any] | None) -> None:
    proj = _project(tmp_path)
    for value in _dotdot_values(proj):
        if method == "GET":
            resp = client.get(f"{PREFIX}{route}", params={"project": value})
        else:
            resp = client.post(f"{PREFIX}{route}", json={"project": value, **(extra or {})})
        msg = _plain(resp, f"{route} {value}")
        assert ".." in msg, msg
        # The reply never names the folder the '..' would collapse to.
        assert "/etc" not in msg.replace("/tmp/../../etc", "")
        assert str(tmp_path / "work") + "'" not in msg and not msg.rstrip(".").endswith(str(tmp_path / "work"))
    assert not (proj / "TOOLS.lock").exists()
    assert not (proj.parent / "TOOLS.lock").exists()


def test_other_path_routes_refuse_dotdot(client: TestClient, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    bad = f"{proj}/../proj"
    cases = [
        ("GET", "/workspace/file", {"params": {"project": bad, "path": "package.json"}}),
        ("GET", "/componentize/status", {"params": {"project_root": bad}}),
        ("PUT", "/componentize/settings", {"json": {"cli_path_override": "/usr/../bin/componentize"}}),
        ("POST", "/audit/start", {"json": {"root": bad}}),
        ("POST", "/audit/start", {"json": {"selected_projects": [bad]}}),
    ]
    for method, route, kwargs in cases:
        resp = client.request(method, f"{PREFIX}{route}", **kwargs)
        assert ".." in _plain(resp, f"{method} {route}")
    resp = client.get(f"{PREFIX}/componentize/settings")
    assert resp.json().get("cli_path_override") is None


def test_dotdot_inside_a_name_is_still_accepted(client: TestClient, tmp_path: Path) -> None:
    proj = tmp_path / "work" / "a..b"
    proj.mkdir(parents=True)
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True})
    assert resp.status_code == 200, resp.text


def test_init_write_error_is_plain_400(client: TestClient, api: Any, tmp_path: Path,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    hidden_path = "/hidden/elsewhere/TOOLS.lock.tmp"

    def boom(*_a: Any, **_k: Any) -> Any:
        raise PermissionError(13, "Permission denied", hidden_path)

    monkeypatch.setattr(api._load("tool_seed"), "seed_lock", boom)
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True})
    msg = _plain(resp, "init write error")
    assert "hidden" not in msg and "Errno" not in msg


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anywhere")
def test_init_on_unwritable_folder_is_400(client: TestClient, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    proj.chmod(0o555)
    try:
        resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True})
        msg = _plain(resp, "unwritable")
        assert str(tmp_path / "work") not in msg.replace(str(proj), "")
    finally:
        proj.chmod(0o755)
    assert not (proj / "TOOLS.lock").exists()


def test_valid_init_unchanged(client: TestClient, tmp_path: Path) -> None:
    proj = _project(tmp_path)
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": str(proj), "confirm": True})
    assert resp.status_code == 200, resp.text
    assert (proj / "TOOLS.lock").is_file()


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root could write here")
def test_init_on_system_folder_is_400(client: TestClient) -> None:
    resp = client.post(f"{PREFIX}/tools-lock/init", json={"project": "/etc", "confirm": True})
    _plain(resp, "/etc")
