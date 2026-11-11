"""The create route and the scaffolders agree on which project folders a failed create left.

The scaffolders put `created_dirs` on the error once a folder is in place; the route
observes the folders on disk itself. The two must name the same folders, each once, and
the proposal state must follow: 'ready' before the move, 'partial' after it.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.fake_kit_bridge import FakeKitBridge
from tests.test_route_write_errors import (  # noqa: F401  (fixtures)
    _accept,
    _boom,
    _propose_kit,
    _propose_template,
    api,
    bridge,
    client,
    routes,
)
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401


def _record_errors(monkeypatch: pytest.MonkeyPatch, module: Any, name: str) -> list[BaseException]:
    seen: list[BaseException] = []
    real = getattr(module, name)

    def wrapped(*a: Any, **k: Any) -> Any:
        try:
            return real(*a, **k)
        except BaseException as exc:
            seen.append(exc)
            raise

    monkeypatch.setattr(module, name, wrapped)
    return seen


@pytest.mark.parametrize("kind", ["template", "kit"])
@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.usefixtures("fake_rust_toolchain")
def test_route_and_scaffolder_name_the_same_folders(
    kind: str, when: str, routes: Any, client: Any, bridge: FakeKitBridge, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    if kind == "template":
        pid = _propose_template(client, projects)
        dest = projects / "star-cruiser"
        module, entry = routes.scaffolder, "accept"
        if when == "before":
            err = routes.scaffolder.GitUnavailableError

            def no_git() -> None:
                raise err("git is not installed")

            monkeypatch.setattr(routes.scaffolder, "ensure_git_available", no_git)
        else:
            monkeypatch.setattr(routes.scaffolder, "record_project", _boom(sqlite3.OperationalError("locked")))
    else:
        pid = _propose_kit(client, projects)
        dest = projects / "night-shoot"
        module, entry = routes.kit_scaffold, "accept_kit"
        if when == "before":
            bridge.check_env_status = "fail"
        else:
            monkeypatch.setattr(routes.kit_scaffold, "record_project", _boom(sqlite3.OperationalError("locked")))
    seen = _record_errors(monkeypatch, module, entry)

    resp = _accept(client, pid)

    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert len(seen) == 1
    from_error = [str(p) for p in (getattr(seen[0], "created_dirs", None) or [])]
    expected = [] if when == "before" else [str(dest)]
    assert detail["created_dirs"] == expected, detail
    assert from_error == expected, from_error
    assert len(set(detail["created_dirs"])) == len(detail["created_dirs"])
    # The message names the kept folder at most once, and only when it exists.
    assert detail["error"].count(str(dest)) == (0 if when == "before" else 1), detail["error"]
    assert "locked" not in detail["error"]  # the underlying error text is not shown
    assert dest.is_dir() is (when == "after")
    assert routes._PROPOSALS[pid]["state"] == ("ready" if when == "before" else "partial")


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_redirected_move_names_the_folder_to_check_on_both_sides(
    routes: Any, client: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The projects folder is swapped during the move: nobody knows the new path, so the
    error and created_dirs name the folder to check and never claim a path that is empty."""
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
    seen = _record_errors(monkeypatch, routes.scaffolder, "accept")
    resp = _accept(client, pid)
    monkeypatch.setattr(os, "rename", real_rename)
    assert swapped and resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    # The move is taken back out through the held folder handle: nothing was created.
    assert detail["created_dirs"] == [] and getattr(seen[0], "created_dirs", []) == []
    assert "changed while the project was being moved. Nothing was created." in detail["error"]
    assert not (projects / "star-cruiser").exists() and not (moved_to / "star-cruiser").exists()
    assert routes._PROPOSALS[pid]["state"] == "ready"
