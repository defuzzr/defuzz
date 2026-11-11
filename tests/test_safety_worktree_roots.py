"""Worktree directory names do not override protected-root safety."""
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.safety import SafetyError, assert_safe_root, safe_write_text


def test_worktree_child_root_supports_safe_writes(tmp_path):
    root = tmp_path / ".worktrees" / "child" / "output"
    assert assert_safe_root(root) == root
    written = safe_write_text(root, "nested/probe.txt", "safe\n")
    assert written.read_text() == "safe\n"


@pytest.mark.parametrize("kind", ["filesystem", "home", "active", "default", "custom", "alias"])
def test_worktree_support_retains_protected_roots(tmp_path, monkeypatch, kind):
    home = tmp_path / "user"
    active = tmp_path / "active"
    custom = tmp_path / "protected"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(active))
    roots = {
        "filesystem": Path("/"),
        "home": home,
        "active": active / ".worktrees" / "child",
        "default": home / ".hermes" / ".worktrees" / "child",
        "custom": custom / ".worktrees" / "child",
    }
    if kind == "alias":
        active.mkdir()
        alias = tmp_path / ".worktrees" / "alias"
        alias.parent.mkdir()
        alias.symlink_to(active, target_is_directory=True)
        roots[kind] = alias / "child"
    with pytest.raises(SafetyError, match="filesystem or home root|inside live"):
        assert_safe_root(roots[kind], protected_roots=[custom])
