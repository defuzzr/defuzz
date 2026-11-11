"""safe_rename opens its folder once for both names and never replaces an existing name.

Every case runs under pytest's tmp_path.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import safety  # noqa: E402
from hermes_plugins.defuzz.safety import SafetyError  # noqa: E402


def _tree(root: Path) -> list:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.mark.parametrize("with_base", [False, True], ids=["no-base", "path-base"])
def test_swap_between_the_two_sides_is_refused(tmp_path, monkeypatch, with_base):
    parent = tmp_path / "work"
    root = parent / "root"
    (root / "a").mkdir(parents=True)
    (root / "a" / "f.txt").write_text("payload\n")
    (root / "b").mkdir()
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "root" / "b").mkdir(parents=True)
    held = tmp_path / "work.held"
    real_walk = safety._walk_dirs
    calls = []

    def walk_then_swap(*args, **kwargs):
        result = real_walk(*args, **kwargs)
        calls.append(args[1])
        if len(calls) == 1:  # after the source side, before the destination side
            os.rename(parent, held)
            parent.symlink_to(elsewhere, target_is_directory=True)
        return result

    monkeypatch.setattr(safety, "_walk_dirs", walk_then_swap)
    kwargs = {"base": parent} if with_base else {}
    with pytest.raises(SafetyError):
        safety.safe_rename(root, "a/f.txt", "b/f.txt", **kwargs)
    assert len(calls) == 1
    assert _tree(elsewhere) == ["root", "root/b"]
    assert (held / "root" / "a" / "f.txt").read_text() == "payload\n"
    assert not (held / "root" / "b" / "f.txt").exists()


@pytest.mark.parametrize("kind", ["file", "folder"])
def test_name_created_just_before_the_move_is_not_replaced(tmp_path, monkeypatch, kind):
    root = tmp_path / "root"
    root.mkdir()
    if kind == "file":
        (root / "src").write_text("moved\n")
    else:
        (root / "src").mkdir()
        (root / "src" / "inner").write_text("moved\n")
    real_stat = os.stat
    planted = []

    def stat_then_plant(path, *args, **kwargs):
        dir_fd = kwargs.get("dir_fd")
        if path == "dst" and dir_fd is not None and not planted:
            fd = os.open("dst", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=dir_fd)
            os.write(fd, b"someone else's bytes\n")
            os.close(fd)
            planted.append(True)
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_then_plant)
    with pytest.raises(SafetyError, match="existing name"):
        safety.safe_rename(root, "src", "dst")
    monkeypatch.undo()
    assert planted
    assert (root / "dst").read_text() == "someone else's bytes\n"
    assert (root / "src").exists()


@pytest.mark.parametrize("kind", ["file", "folder"])
def test_move_still_works_where_the_no_replace_move_is_unavailable(tmp_path, monkeypatch, kind):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    if kind == "file":
        (root / "src").write_text("moved\n")
    else:
        (root / "src").mkdir()
    monkeypatch.setattr(safety, "_rename_noreplace", lambda *a: False)
    assert safety.safe_rename(root, "src", "sub/dst") == root / "sub" / "dst"
    assert not os.path.lexists(root / "src")
    assert os.path.lexists(root / "sub" / "dst")


def test_ordinary_moves_keep_working(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "f.txt").write_text("x\n")
    (root / "d").mkdir()
    safety.safe_rename(root, "f.txt", "deep/er/f.txt")
    safety.safe_rename(root, "d", "deep/d")
    assert _tree(root) == ["deep", "deep/d", "deep/er", "deep/er/f.txt"]
    with pytest.raises(SafetyError, match="existing name"):
        safety.safe_rename(root, "deep/d", "deep/er")
