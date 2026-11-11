"""Kit accept must not follow a projects folder that was swapped or redirected after the preview.

Each case runs twice: with the default staging folder (held by a no-follow handle) and with an
explicit staging folder (moved by path).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, List

import pytest

from tests import ensure_test_package
from tests.conftest import load_submodule
from tests.fake_kit_bridge import FakeKitBridge

ensure_test_package()

from hermes_plugins.defuzz import kit_scaffold  # noqa: E402
from hermes_plugins.defuzz.kit_scaffold import accept_kit, propose_kit  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError  # noqa: E402

KIT_ID = "video-production"
ANSWERS = {"building": "video", "layout": "single", "languages": []}
MODES = ["handle", "path"]


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "p1", "name": name, "path": path})


def _snapshot(path: Path) -> List[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


def _visible(path: Path) -> List[str]:
    """Entries of a folder, leaving out the hidden staging folder the default mode keeps there."""
    return sorted(p.name for p in path.iterdir() if not p.name.startswith(".adopt-scaffold-"))


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp))
    return tmp_path


def _staged_now(proposal, projects: Path, moved: Path) -> Path:
    """The staged project, followed to where a renamed projects folder took it (default mode)."""
    staged = proposal.staged
    if projects in staged.parents:
        return moved / staged.relative_to(projects)
    return staged


def _propose(tmp_path: Path, mode: str, dest_root: Path, name: str = "Demo", bridge: Any = None):
    staging_parent = None if mode == "handle" else tmp_path / "stage"
    return propose_kit(
        KIT_ID,
        name,
        ANSWERS,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge or FakeKitBridge(),
    )


def _accept(tmp_path: Path, proposal, bridge: Any = None):
    return accept_kit(proposal, register=_register, db_path=tmp_path / "s.db", bridge=bridge or FakeKitBridge())


@pytest.mark.parametrize("mode", MODES)
def test_accept_refuses_projects_folder_swapped_for_link_after_propose(env: Path, mode: str) -> None:
    projects = env / "projects"
    projects.mkdir()
    outside = env / "outside"
    outside.mkdir()
    (outside / "sentinel.txt").write_text("keep", encoding="utf-8")
    proposal = _propose(env, mode, projects)

    moved = env / "projects-moved"
    projects.rename(moved)
    projects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)

    message = str(caught.value)
    assert "changed" in message
    assert "Traceback" not in message
    assert getattr(caught.value, "created_dirs", []) == []
    assert _snapshot(outside) == ["sentinel.txt"]
    assert (outside / "sentinel.txt").read_text(encoding="utf-8") == "keep"
    assert _visible(moved) == []
    assert _staged_now(proposal, projects, moved).is_dir(), "staging must be kept for discard"


@pytest.mark.parametrize("mode", MODES)
def test_accept_refuses_missing_projects_folder_created_as_link_after_propose(env: Path, mode: str) -> None:
    base = env / "base"
    base.mkdir()
    projects = base / "projects"  # does not exist yet; accept would create it
    outside = env / "outside"
    outside.mkdir()
    proposal = _propose(env, mode, projects)

    projects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)

    assert "changed after the preview" in str(caught.value)
    assert getattr(caught.value, "created_dirs", []) == []
    assert _snapshot(outside) == []
    assert proposal.staged.is_dir()


@pytest.mark.parametrize("mode", MODES)
def test_accept_refuses_projects_folder_replaced_by_other_folder(env: Path, mode: str) -> None:
    projects = env / "projects"
    projects.mkdir()
    proposal = _propose(env, mode, projects)

    projects.rename(env / "projects-old")
    projects.mkdir()

    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)

    assert "changed" in str(caught.value)
    assert list(projects.iterdir()) == []


@pytest.mark.parametrize("mode", MODES)
def test_accept_keeps_configured_symlinked_projects_folder(env: Path, mode: str) -> None:
    real = env / "real-projects"
    real.mkdir()
    link = env / "projects-link"
    link.symlink_to(real, target_is_directory=True)
    proposal = _propose(env, mode, link)

    result = _accept(env, proposal)

    assert result.repos[0]["path"] == str(link / "demo")
    assert (real / "demo" / "AGENTS.md").is_file()
    assert (real / "demo" / ".git").is_dir()
    assert link.is_symlink()
    assert _visible(real) == ["demo"]


@pytest.mark.parametrize("mode", MODES)
def test_accept_creates_missing_projects_folder(env: Path, mode: str) -> None:
    projects = env / "a" / "b" / "projects"
    proposal = _propose(env, mode, projects)

    result = _accept(env, proposal)

    assert result.repos[0]["path"] == str(projects / "demo")
    assert (projects / "demo" / ".git").is_dir()
    for folder in (env / "a", env / "a" / "b", projects):
        assert not os.path.islink(folder)


@pytest.mark.parametrize("mode", MODES)
def test_two_previews_share_a_projects_folder_created_by_the_first_accept(env: Path, mode: str) -> None:
    projects = env / "new-root"
    first = _propose(env, mode, projects, name="One")
    second = _propose(env, mode, projects, name="Two")

    _accept(env, first)
    _accept(env, second)

    assert _visible(projects) == ["one", "two"]


@pytest.mark.parametrize("mode", MODES)
def test_accept_refusal_does_not_remove_existing_user_folder(env: Path, mode: str) -> None:
    projects = env / "projects"
    projects.mkdir()
    proposal = _propose(env, mode, projects)
    mine = projects / "demo"
    mine.mkdir()
    (mine / "notes.txt").write_text("mine", encoding="utf-8")

    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)

    assert "already exists" in str(caught.value)
    assert getattr(caught.value, "created_dirs", []) == []
    assert (mine / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert _snapshot(mine) == ["notes.txt"]
    kit_scaffold.discard_kit(proposal)


# --- After the move: the caller can tell "partial" from "nothing created" ----------------------


@pytest.mark.parametrize("mode", MODES)
def test_failure_after_the_move_says_the_folder_is_kept_and_marks_it_created(
    env: Path, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = env / "projects"
    projects.mkdir()
    proposal = _propose(env, mode, projects)

    def _git_fails(*_a: Any, **_k: Any) -> Any:
        raise ScaffoldError(f"git init failed in {proposal.dest} (folder kept at {proposal.dest}): boom")

    monkeypatch.setattr(kit_scaffold, "_init_and_commit_dest_repo", _git_fails)
    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)

    assert caught.value.created_dirs == [proposal.dest]
    assert "folder kept at" in str(caught.value)
    assert (proposal.dest / "AGENTS.md").is_file()


@pytest.mark.parametrize("mode", MODES)
def test_interrupt_after_the_move_marks_the_project_created(
    env: Path, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = env / "projects"
    projects.mkdir()
    proposal = _propose(env, mode, projects)

    def _interrupted(*_a: Any, **_k: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(kit_scaffold, "_init_and_commit_dest_repo", _interrupted)
    with pytest.raises(KeyboardInterrupt) as caught:
        _accept(env, proposal)

    assert caught.value.created_dirs == [proposal.dest]
    assert proposal.dest.is_dir()


def test_redirect_during_the_move_that_cannot_be_undone_says_where_the_project_is(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = env / "projects"
    projects.mkdir()
    outside = env / "outside"
    outside.mkdir()
    proposal = _propose(env, "handle", projects)
    assert proposal.stage is not None
    moved = env / "projects-moved"
    real_rename = os.rename
    calls: List[Any] = []

    def _rename(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        if (src, dst) == ("demo", "demo") and not calls:
            calls.append((src, dst))
            real_rename(src, dst, *args, **kwargs)
            # Swap the projects folder right after the project landed in it.
            real_rename(projects, moved)
            os.symlink(outside, projects, target_is_directory=True)
            return
        if calls and (src, dst) == ("demo", "demo"):
            raise PermissionError(13, "Permission denied")  # moving it back fails
        real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(kit_scaffold.os, "rename", _rename)
    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)
    monkeypatch.setattr(kit_scaffold.os, "rename", real_rename)

    message = str(caught.value)
    landed = Path(os.path.realpath(moved)) / "demo"
    assert landed.is_dir()
    assert str(landed) in message
    assert "delete" in message
    assert caught.value.created_dirs == [landed]
    assert _snapshot(outside) == []


def test_redirect_during_the_move_that_is_undone_reports_nothing_created(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = env / "projects"
    projects.mkdir()
    outside = env / "outside"
    outside.mkdir()
    proposal = _propose(env, "handle", projects)
    moved = env / "projects-moved"
    real_rename = os.rename
    calls: List[Any] = []

    def _rename(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        real_rename(src, dst, *args, **kwargs)
        if (src, dst) == ("demo", "demo") and not calls:
            calls.append((src, dst))
            real_rename(projects, moved)
            os.symlink(outside, projects, target_is_directory=True)

    monkeypatch.setattr(kit_scaffold.os, "rename", _rename)
    with pytest.raises(ScaffoldError) as caught:
        _accept(env, proposal)
    monkeypatch.setattr(kit_scaffold.os, "rename", real_rename)

    assert getattr(caught.value, "created_dirs", []) == []
    assert "was not created" in str(caught.value)
    assert _visible(moved) == []
    assert _snapshot(outside) == []
    assert _staged_now(proposal, projects, moved).is_dir()


# --- The route keeps a partly created kit project for inspection -------------------------------


def _client(monkeypatch: pytest.MonkeyPatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    bridge = FakeKitBridge()
    bridge.install(monkeypatch, load_submodule("componentize_bridge"))
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    bridge.install(monkeypatch, routes.componentize_bridge)
    routes._reset_kit_cache_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app), routes


def test_route_marks_partial_after_the_move_and_ready_after_a_swap_refusal(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, routes = _client(monkeypatch)
    projects = env / "projects"
    projects.mkdir()
    body = {"kit_id": KIT_ID, "answers": {"building": "video"}, "dest_root": str(projects)}

    # A swap refusal: nothing created, the preview can still be discarded.
    swapped = client.post("/scaffold/propose", json={**body, "name": "Swap Shoot"})
    assert swapped.status_code == 200, swapped.text
    swap_id = swapped.json()["proposal_id"]
    outside = env / "outside"
    outside.mkdir()
    projects.rename(env / "projects-moved")
    projects.symlink_to(outside, target_is_directory=True)
    refused = client.post("/scaffold/accept", json={"proposal_id": swap_id, "confirm": True})
    assert refused.status_code == 409
    assert refused.json()["detail"]["created_dirs"] == []
    assert routes._PROPOSALS[swap_id]["state"] == "ready"
    assert _snapshot(outside) == []
    projects.unlink()
    (env / "projects-moved").rename(projects)

    # A failure after the move: the project exists, the row is kept for inspection.
    made = client.post("/scaffold/propose", json={**body, "name": "Night Shoot"})
    assert made.status_code == 200, made.text
    made_id = made.json()["proposal_id"]
    dest = projects / "night-shoot"

    def _git_fails(*_a: Any, **_k: Any) -> Any:
        raise ScaffoldError(f"git init failed in {dest} (folder kept at {dest}): boom")

    monkeypatch.setattr(routes.kit_scaffold, "_init_and_commit_dest_repo", _git_fails)
    failed = client.post("/scaffold/accept", json={"proposal_id": made_id, "confirm": True})
    assert failed.status_code == 409
    assert failed.json()["detail"]["created_dirs"] == [str(dest)]
    assert routes._PROPOSALS[made_id]["state"] == "partial"
    assert dest.is_dir()
    for row in list(routes._PROPOSALS.values()):
        proposal = row.get("proposal")
        if proposal is not None:
            shutil.rmtree(proposal.staging_dir, ignore_errors=True)
