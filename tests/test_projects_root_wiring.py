"""Project creation resolves its folder through workspace_root, never a hardcoded default."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import kit_scaffold, scaffolder, workspace_root
from hermes_plugins.defuzz.scaffolder import ScaffoldError  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "templates" / "fake-rust-game"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    hh = h / ".hermes"
    hh.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("HERMES_HOME", str(hh))
    monkeypatch.delenv("HERMES_PROJECTS_ROOT", raising=False)
    monkeypatch.setattr("sys.stdin", open(os.devnull))
    return h


def _snapshot(root: Path) -> set:
    return {p.relative_to(root) for p in root.rglob("*")}


def test_saved_setting_wins(home):
    chosen = home / "work"
    workspace_root.set_projects_root(str(chosen))
    assert scaffolder.projects_root() == chosen


def test_env_var_only(home, monkeypatch):
    chosen = home / "envroot"
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(chosen))
    assert scaffolder.projects_root() == chosen


def test_unset_raises_and_creates_nothing(home):
    before = _snapshot(home)
    with pytest.raises(ScaffoldError, match="No projects folder has been chosen yet"):
        scaffolder.projects_root()
    assert _snapshot(home) == before
    assert not (home / "Projects").exists()
    assert not (home / workspace_root.DEFAULT_FOLDER_NAME).exists()


def test_explicit_root_wins_over_unset(home, tmp_path):
    dest = tmp_path / "explicit"
    dest.mkdir()
    answers = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
    proposal = scaffolder.propose(
        load_template(FIXTURE), "My Game", answers,
        dest_root=dest, staging_parent=tmp_path / "staging",
    )
    assert str(dest) in repr(proposal)
    with pytest.raises(ScaffoldError):
        scaffolder.propose(load_template(FIXTURE), "My Game", answers,
                           staging_parent=tmp_path / "staging2")


def test_kit_path_uses_same_resolver(home, monkeypatch):
    assert kit_scaffold.projects_root is scaffolder.projects_root
    chosen = home / "shared"
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(chosen))
    assert kit_scaffold.projects_root() == scaffolder.projects_root() == chosen


def test_no_hardcoded_projects_default():
    src = Path(scaffolder.__file__).read_text()
    assert "~/Projects" not in src
