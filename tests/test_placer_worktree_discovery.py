"""Ancestor discovery treats .worktrees as an ordinary directory name."""
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.placer import find_adopted_root


@pytest.mark.parametrize("relative", [".worktrees/child", "project/.worktrees/child"])
@pytest.mark.parametrize("existing_directory", [False, True])
def test_discovers_adopted_ancestor_beneath_worktrees(tmp_path, relative, existing_directory):
    root = tmp_path / relative
    (root / ".adopt").mkdir(parents=True)
    (root / ".adopt/rules.json").write_text("{}")
    nested = root / "nested/deep"
    nested.mkdir(parents=True)
    target = nested if existing_directory else nested / "new.txt"
    assert find_adopted_root(target) == root


def test_discovers_adopted_ancestor_above_worktrees(tmp_path):
    (tmp_path / ".adopt").mkdir()
    (tmp_path / ".adopt/rules.json").write_text("{}")
    nested = tmp_path / ".worktrees/child/nested"
    nested.mkdir(parents=True)
    assert find_adopted_root(nested / "new.txt") == tmp_path


@pytest.mark.parametrize("protected", ["home", "active", "default"])
def test_discovery_keeps_protected_root_stops(tmp_path, monkeypatch, protected):
    home = tmp_path / "home"
    active = tmp_path / "active"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(active))
    root = {"home": home, "active": active, "default": home / ".hermes"}[protected]
    (root / ".adopt").mkdir(parents=True)
    (root / ".adopt/rules.json").write_text("{}")
    nested = root / ".worktrees/child"
    nested.mkdir(parents=True)
    assert find_adopted_root(nested / "new.txt") is None
