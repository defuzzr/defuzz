"""Every dashboard route that writes answers a failed write with one plain 4xx sentence.

A write can fail for ordinary reasons: a read-only folder, a full disk, a locked or
read-only state database. None of these may turn into a 500, a traceback, or a reply
that repeats the exception text or a path the caller did not send.

The second half covers project creation: a create that fails before anything is moved
into place can be retried; one that fails after the project folder exists is kept as
'partial' (the page then says to inspect the folder) and a retry is refused.
"""

from __future__ import annotations

import errno
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule
from tests.fake_kit_bridge import FakeKitBridge
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

SECRET = "/hidden/secret-place/state.db"

ERRORS: dict[str, Callable[[], BaseException]] = {
    "permission": lambda: PermissionError(errno.EACCES, "Permission denied", SECRET),
    "read-only": lambda: OSError(errno.EROFS, "Read-only file system", SECRET),
    "disk-full": lambda: OSError(errno.ENOSPC, "No space left on device", SECRET),
    "sqlite": lambda: sqlite3.OperationalError(f"attempt to write a readonly database {SECRET}"),
}

NOT_ROOT = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anywhere")


@pytest.fixture()
def api() -> Any:
    return load_submodule("dashboard.plugin_api")


@pytest.fixture()
def routes(api: Any) -> Any:
    mod = api._load("dashboard.routes.workspace_routes")
    with mod._LOCK:
        mod._PROPOSALS.clear()
    mod._reset_kit_cache_for_tests()
    mod.accept_jobs._reset_for_tests()
    yield mod
    with mod._LOCK:
        mod._PROPOSALS.clear()
    mod.accept_jobs._reset_for_tests()


@pytest.fixture()
def bridge(monkeypatch: pytest.MonkeyPatch, routes: Any) -> FakeKitBridge:
    fake = FakeKitBridge()
    fake.install(monkeypatch, load_submodule("componentize_bridge"))
    fake.install(monkeypatch, routes.componentize_bridge)
    routes._reset_kit_cache_for_tests()
    return fake


@pytest.fixture()
def client(api: Any, routes: Any, bridge: FakeKitBridge, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(api._load("toolchk"), "probe", lambda *a, **k: ("20.11.0", "/usr/bin/node"))
    fixtures = Path(__file__).resolve().parent / "fixtures" / "templates"
    orig = routes.templates.load_templates
    monkeypatch.setattr(routes.templates, "load_templates",
                        lambda root=None: orig(fixtures if root is None else root))
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app, raise_server_exceptions=False)


def _boom(exc: BaseException) -> Callable[..., Any]:
    def raiser(*_a: Any, **_k: Any) -> Any:
        raise exc
    return raiser


def _message(resp: Any) -> str:
    body = resp.json()
    msg = body.get("detail", body.get("error")) if isinstance(body, dict) else None
    if isinstance(msg, dict):
        msg = msg.get("error")
    assert isinstance(msg, str), resp.text
    return msg


def _plain(resp: Any, label: str, *, status: int = 400) -> str:
    assert resp.status_code == status, f"{label}: {resp.status_code} {resp.text[:300]}"
    msg = _message(resp)
    assert msg.strip(), label
    assert "\n" not in msg and "Traceback" not in msg and len(msg) <= 300, f"{label}: {msg!r}"
    assert ". " not in msg.rstrip("."), f"{label}: more than one sentence: {msg!r}"
    for leak in ("hidden", "secret", "Errno", "readonly database", "No space left", "Permission denied"):
        assert leak not in resp.text, f"{label}: reply leaks {leak!r}: {resp.text[:300]}"
    return msg


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "work" / "proj"
    proj.mkdir(parents=True)
    (proj / "package.json").write_text('{"name": "write-errors"}\n', encoding="utf-8")
    return proj


def _locked_project(client: TestClient, tmp_path: Path) -> Path:
    proj = _project(tmp_path)
    resp = client.post("/tools-lock/init", json={"project": str(proj), "confirm": True})
    assert resp.status_code == 200, resp.text
    return proj


def _first_tool(api: Any, proj: Path) -> str:
    return next(iter(api._load("toolchk").load_lock(proj / "TOOLS.lock")["tools"]))


# --- item 1: every writing route ------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(ERRORS))
def test_tools_lock_writes(kind: str, api: Any, client: TestClient, tmp_path: Path,
                           monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _locked_project(client, tmp_path)
    tool = _first_tool(api, proj)
    guard, seed = api._load("tool_guard"), api._load("tool_seed")
    before = (proj / "TOOLS.lock").read_bytes()
    monkeypatch.setattr(guard, "trust_lock", _boom(ERRORS[kind]()))
    monkeypatch.setattr(guard, "edit_lock", _boom(ERRORS[kind]()))
    monkeypatch.setattr(seed, "snooze", _boom(ERRORS[kind]()))
    monkeypatch.setattr(seed, "seed_lock", _boom(ERRORS[kind]()))
    cases = [
        ("/tools-lock/trust", {"confirm": True, "expected_hash": "0" * 64}),
        ("/tools-lock/accept", {"tool": tool, "reason": "pinned"}),
        ("/tools-lock/reason", {"tool": tool, "reason": "pinned"}),
        ("/tools-lock/snooze", {"tool": tool, "days": 3}),
        ("/tools-lock/init", {"confirm": True}),
    ]
    for route, extra in cases:
        _plain(client.post(route, json={"project": str(proj), **extra}), f"{route} {kind}")
    assert (proj / "TOOLS.lock").read_bytes() == before


@pytest.mark.parametrize("kind", sorted(ERRORS))
def test_lint_write_errors(kind: str, api: Any, client: TestClient, tmp_path: Path,
                           monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    monkeypatch.setattr(api._load("linter"), "run_lint", _boom(ERRORS[kind]()))
    _plain(client.post("/lint", json={"project": str(proj), "mode": "pre"}), f"lint {kind}")
    # The lint's own pre-check records its result under .adopt.
    proj = _locked_project(client, tmp_path / "locked")
    monkeypatch.setattr(api._load("toolchk"), "require", _boom(ERRORS[kind]()))
    _plain(client.post("/lint", json={"project": str(proj), "mode": "pre"}), f"lint require {kind}")


def test_lint_job_poll_reports_plain_sentence(api: Any, client: TestClient, tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    monkeypatch.setattr(api._load("linter"), "run_lint", _boom(ERRORS["disk-full"]()))
    with api._LINT_JOBS_LOCK:
        api._LINT_JOBS.clear()
    _plain(client.post("/lint", json={"project": str(proj), "mode": "pre"}), "lint")
    with api._LINT_JOBS_LOCK:
        (job_id,) = list(api._LINT_JOBS)
    poll = client.get(f"/lint/{job_id}")
    assert poll.status_code == 200 and poll.json()["state"] == "failed"
    assert "secret" not in poll.text and "Errno" not in poll.text


@pytest.mark.parametrize("kind", sorted(ERRORS))
def test_ui_state_save(kind: str, api: Any, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api._load("safe_state_store"), "_connect", _boom(ERRORS[kind]()))
    resp = client.post("/ui-state", json={"key": "settings", "value": {"a": 1}, "seq": 1})
    _plain(resp, f"ui-state {kind}")


@pytest.mark.parametrize("kind", sorted(ERRORS))
@pytest.mark.parametrize("route", ["/audit/start", "/audit/cancel", "/audit/resume"])
def test_audit_writes(kind: str, route: str, api: Any, client: TestClient,
                      monkeypatch: pytest.MonkeyPatch) -> None:
    audit_routes = api._load("dashboard.routes.audit_routes")
    monkeypatch.setattr(audit_routes, "execute_audit", _boom(ERRORS[kind]()))
    _plain(client.post(route, json={"run_id": "r1"}), f"{route} {kind}")


@pytest.mark.parametrize("kind", ["permission", "read-only", "disk-full"])
def test_componentize_settings_save(kind: str, api: Any, client: TestClient,
                                    monkeypatch: pytest.MonkeyPatch) -> None:
    settings = api._load("componentize_settings")
    monkeypatch.setattr(settings, "plugin_data_dir", lambda *_a, **_k: Path(SECRET).parent)
    monkeypatch.setattr(settings.tempfile, "NamedTemporaryFile", _boom(ERRORS[kind]()))
    _plain(client.put("/componentize/settings", json={}), f"componentize {kind}")


@pytest.mark.parametrize("kind", sorted(ERRORS))
def test_propose_write_errors(kind: str, routes: Any, client: TestClient, tmp_path: Path,
                              monkeypatch: pytest.MonkeyPatch) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setattr(routes.scaffolder, "propose", _boom(ERRORS[kind]()))
    monkeypatch.setattr(routes.kit_scaffold, "propose_kit", _boom(ERRORS[kind]()))
    resp = client.post("/scaffold/propose", json={
        "template_id": "fake-rust-game", "name": "Star Cruiser", "dest_root": str(projects),
        "answers": {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}})
    _plain(resp, f"propose template {kind}")
    resp = client.post("/scaffold/propose", json={
        "kit_id": "video-production", "name": "Night Shoot", "dest_root": str(projects),
        "answers": {"building": "video"}})
    _plain(resp, f"propose kit {kind}")
    assert routes._PROPOSALS == {}


def _propose_kit(client: TestClient, projects: Path, name: str = "Night Shoot") -> str:
    resp = client.post("/scaffold/propose", json={
        "kit_id": "video-production", "name": name, "answers": {"building": "video"},
        "dest_root": str(projects)})
    assert resp.status_code == 200, resp.text
    return resp.json()["proposal_id"]


def _propose_template(client: TestClient, projects: Path, name: str = "Star Cruiser") -> str:
    resp = client.post("/scaffold/propose", json={
        "template_id": "fake-rust-game", "name": name, "dest_root": str(projects),
        "answers": {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}})
    assert resp.status_code == 200, resp.text
    return resp.json()["proposal_id"]


@pytest.mark.parametrize("kind", sorted(ERRORS))
def test_accept_and_discard_write_errors(kind: str, routes: Any, client: TestClient, tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_kit(client, projects)
    tid = _propose_template(client, projects)
    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", _boom(ERRORS[kind]()))
    monkeypatch.setattr(routes.scaffolder, "accept", _boom(ERRORS[kind]()))
    monkeypatch.setattr(routes.kit_scaffold, "discard_kit", _boom(ERRORS[kind]()))
    for proposal_id in (pid, tid):
        resp = client.post("/scaffold/accept", json={"proposal_id": proposal_id, "confirm": True})
        _plain(resp, f"accept {kind}", status=409)
        assert resp.json()["detail"]["created_dirs"] == []
        assert routes._PROPOSALS[proposal_id]["state"] == "ready"
    _plain(client.post("/scaffold/discard", json={"proposal_id": pid}), f"discard {kind}", status=409)
    assert routes._PROPOSALS[pid]["state"] == "ready"


def test_state_folder_not_writable_is_plain(api: Any, routes: Any, client: TestClient, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    state_store = api._load("state_store")
    hidden = state_store.StateDirNotWritable(Path(SECRET).parent)

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise hidden

    proj = _locked_project(client, tmp_path)
    tool = _first_tool(api, proj)
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_kit(client, projects)
    monkeypatch.setattr(state_store, "state_db_path", refuse)
    for name in ("tool_guard", "tool_seed"):
        mod = api._load(name)
        if hasattr(mod, "state_db_path"):
            monkeypatch.setattr(mod, "state_db_path", refuse)
    _plain(client.post("/ui-state", json={"key": "k", "value": 1, "seq": 1}), "ui-state")
    _plain(client.post("/tools-lock/accept", json={"project": str(proj), "tool": tool, "reason": "r"}), "accept")
    _plain(client.post("/tools-lock/reason", json={"project": str(proj), "tool": tool, "reason": "r"}), "reason")
    _plain(client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}), "scaffold accept",
           status=409)
    assert routes._PROPOSALS[pid]["state"] == "ready"
    resp = client.post("/scaffold/propose", json={
        "template_id": "fake-rust-game", "name": "Other", "dest_root": str(projects),
        "answers": {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}})
    _plain(resp, "propose")


@NOT_ROOT
def test_reason_and_accept_on_read_only_project_are_plain(api: Any, client: TestClient, tmp_path: Path) -> None:
    proj = _locked_project(client, tmp_path)
    tool = _first_tool(api, proj)
    before = (proj / "TOOLS.lock").read_bytes()
    proj.chmod(0o555)
    try:
        for route in ("/tools-lock/reason", "/tools-lock/accept"):
            resp = client.post(route, json={"project": str(proj), "tool": tool, "reason": "kept"})
            assert resp.status_code == 400, resp.text
            msg = _message(resp)
            assert "Errno" not in msg and "\n" not in msg
            assert str(proj) + "/." not in msg  # no temporary file name
    finally:
        proj.chmod(0o755)
    assert (proj / "TOOLS.lock").read_bytes() == before


@NOT_ROOT
def test_ui_state_on_read_only_state_folder_is_plain(api: Any, client: TestClient, tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "ro-state"
    folder.mkdir()
    monkeypatch.setattr(api._load("state_store"), "state_db_path", lambda *_a, **_k: folder / "state.db")
    folder.chmod(0o555)
    try:
        resp = client.post("/ui-state", json={"key": "k", "value": 1, "seq": 1})
    finally:
        folder.chmod(0o755)
    assert resp.status_code == 400, resp.text
    assert str(folder) not in resp.text and "Errno" not in resp.text


def test_workspace_file_read_error_is_plain(api: Any, client: TestClient, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    proj = _project(tmp_path)
    db = api._load("audit.readonly_db")
    snap = SimpleNamespace(records=[{"canonical_path": str(proj.resolve())}], coverage="verified",
                           changed_during_read=False)
    monkeypatch.setattr(db, "read_profile_registrations_readonly", lambda *_a, **_k: snap)
    fp = api._load("audit.fingerprint")
    for kind in ("permission", "disk-full"):
        monkeypatch.setattr(fp, "safe_read_regular_file_plain", _boom(ERRORS[kind]()))
        _plain(client.get("/workspace/file", params={"project": str(proj), "path": "package.json"}), kind)
    monkeypatch.setattr(db, "read_profile_registrations_readonly", _boom(ERRORS["sqlite"]()))
    _plain(client.get("/workspace/file", params={"project": str(proj), "path": "package.json"}), "sqlite")


def test_success_replies_unchanged(api: Any, client: TestClient, tmp_path: Path) -> None:
    proj = _locked_project(client, tmp_path)
    tool = _first_tool(api, proj)
    resp = client.post("/tools-lock/reason", json={"project": str(proj), "tool": tool, "reason": "kept"})
    assert resp.status_code == 200 and resp.json()["tool"] == tool
    resp = client.post("/ui-state", json={"key": "k", "value": {"x": 1}, "seq": 1})
    assert resp.status_code == 200 and resp.json()["value"] == {"x": 1}


# --- item 2: a create that fails after the move is partial ------------------------------


RETRY_REFUSED = "Proposal is busy or requires inspection after partial creation"


def _accept(client: TestClient, pid: str) -> Any:
    return client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})


def _assert_partial(client: TestClient, routes: Any, pid: str, resp: Any, *, created: list[str]) -> None:
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["created_dirs"] == created, detail
    assert routes._PROPOSALS[pid]["state"] == "partial"
    # Accepting again answers the stored final answer (start-and-poll contract), never a
    # second attempt; a discard is refused as before.
    again = _accept(client, pid)
    assert again.status_code == 409 and again.json() == resp.json(), again.text
    again = client.post("/scaffold/discard", json={"proposal_id": pid})
    assert again.status_code == 409 and again.json() == {"detail": RETRY_REFUSED}, again.text
    # A partial proposal is kept for inspection: the expiry of abandoned proposals skips it.
    with routes._LOCK:
        routes._PROPOSALS[pid]["created"] = 0.0
        assert routes._take_expired_locked() == []
    assert routes._PROPOSALS[pid]["state"] == "partial"


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_template_failure_before_move_stays_ready_and_retry_works(
    routes: Any, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_template(client, projects)
    safety_err = routes.scaffolder.GitUnavailableError
    real_check = routes.scaffolder.ensure_git_available

    def no_git() -> None:
        raise safety_err("git is not installed")

    monkeypatch.setattr(routes.scaffolder, "ensure_git_available", no_git)
    resp = _accept(client, pid)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["created_dirs"] == []
    assert routes._PROPOSALS[pid]["state"] == "ready"
    assert not (projects / "star-cruiser").exists()
    monkeypatch.setattr(routes.scaffolder, "ensure_git_available", real_check)
    resp = _accept(client, pid)
    assert resp.status_code == 200, resp.text
    assert (projects / "star-cruiser" / ".git").is_dir()


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_template_failure_after_move_is_partial(
    routes: Any, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_template(client, projects)
    monkeypatch.setattr(routes.scaffolder, "record_project", _boom(sqlite3.OperationalError("database is locked")))
    resp = _accept(client, pid)
    dest = projects / "star-cruiser"
    assert dest.is_dir()
    assert f"The project folder {dest} was created and kept" in resp.json()["detail"]["error"]
    _assert_partial(client, routes, pid, resp, created=[str(dest)])


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_template_redirected_move_is_partial_and_names_where_it_went(
    routes: Any, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_template(client, projects)
    real_rename = os.rename
    moved_to = tmp_path / "moved-away"
    swapped = []

    def rename_then_swap(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
        out = real_rename(src, dst, *a, **k)
        if dst == "star-cruiser" and k.get("dst_dir_fd") is not None and not swapped:
            swapped.append(True)
            real_rename(projects, moved_to)  # the projects folder is swapped during the move
            projects.mkdir()
        return out

    monkeypatch.setattr(os, "rename", rename_then_swap)
    resp = _accept(client, pid)
    monkeypatch.setattr(os, "rename", real_rename)
    assert swapped and resp.status_code == 409, resp.text
    error = resp.json()["detail"]["error"]
    assert "changed while the project was being moved. Nothing was created." in error
    assert not (moved_to / "star-cruiser").exists() and not (projects / "star-cruiser").exists()
    assert resp.json()["detail"]["created_dirs"] == []


def test_kit_failure_before_move_stays_ready_and_retry_works(
    routes: Any, client: TestClient, bridge: FakeKitBridge, tmp_path: Path
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_kit(client, projects)
    dest = projects / "night-shoot"
    dest.mkdir()  # someone else made a folder with that name: nothing of ours was created
    resp = _accept(client, pid)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["error"].startswith("Destination already exists")
    assert resp.json()["detail"]["created_dirs"] == []
    assert routes._PROPOSALS[pid]["state"] == "ready"
    dest.rmdir()
    bridge.check_env_status = "fail"
    resp = _accept(client, pid)
    assert resp.status_code == 409 and resp.json()["detail"]["created_dirs"] == [], resp.text
    assert routes._PROPOSALS[pid]["state"] == "ready"
    bridge.check_env_status = "pass"
    resp = _accept(client, pid)
    assert resp.status_code == 200, resp.text
    assert (dest / ".git").is_dir()


def test_kit_failure_after_move_is_partial(
    routes: Any, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_kit(client, projects)
    monkeypatch.setattr(routes.kit_scaffold, "record_project", _boom(sqlite3.OperationalError("disk I/O error")))
    resp = _accept(client, pid)
    dest = projects / "night-shoot"
    assert dest.is_dir()
    _assert_partial(client, routes, pid, resp, created=[str(dest)])


def test_kit_write_error_after_move_is_partial_and_plain(
    routes: Any, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    pid = _propose_kit(client, projects)
    real = routes.kit_scaffold.accept_kit

    def accept_then_fail(proposal: Any, **kw: Any) -> Any:
        real(proposal, **kw)
        raise ERRORS["disk-full"]()

    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", accept_then_fail)
    resp = _accept(client, pid)
    _plain(resp, "accept after move", status=409)
    _assert_partial(client, routes, pid, resp, created=[str(projects / "night-shoot")])
