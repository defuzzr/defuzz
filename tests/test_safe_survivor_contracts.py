"""Contract tests that the copy refuses to follow a link, even to the same folder.

Three narrow cases, one per test: reopening a released copy level, opening a listed
source folder, and opening a protected root through a linked parent. Each passes only
because the code opens with no-follow and refuses the link; matching device and inode
is not enough when the name has become a link. All folders are under pytest's tmp_path
with a fake home.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import safety  # noqa: E402


@pytest.fixture(autouse=True)
def fake_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    return home


def test_reopened_copy_level_refuses_link_to_the_same_folder(tmp_path, monkeypatch):
    """A released destination level reopened by name must not follow a link to itself."""
    src = tmp_path / "src"
    (src / "a" / "b" / "c").mkdir(parents=True)
    (src / "a" / "z").mkdir()
    (src / "a" / "z" / "payload").write_text("payload", encoding="utf-8")
    dst = tmp_path / "dst"
    original = safety._reopen_level
    moved = []

    monkeypatch.setattr(safety, "_COPY_HELD_LEVELS", 1)

    def move_same_inode(stack, idx, *args):
        if not moved:
            assert stack[idx].parts == ("a",)
            (dst / "a").rename(dst / "saved-a")
            (dst / "a").symlink_to(dst / "saved-a", target_is_directory=True)
            moved.append(True)
        return original(stack, idx, *args)

    monkeypatch.setattr(safety, "_reopen_level", move_same_inode)
    with pytest.raises(safety.SafetyError, match="Folder changed while copying"):
        safety.copy_tree_nofollow(src, dst)
    assert moved
    assert not (dst / "saved-a" / "z").exists()


def test_listed_source_folder_refuses_link_to_the_same_folder(tmp_path, monkeypatch):
    """A source sub-folder that becomes a link to its own moved inode is refused."""
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "payload").write_text("payload", encoding="utf-8")
    dst = tmp_path / "dst"
    original = os.open
    src_id = (src.stat().st_dev, src.stat().st_ino)
    moved = []

    def swap_after_stat(name, flags, *args, **kwargs):
        fd = kwargs.get("dir_fd")
        if name == "sub" and fd is not None and not moved:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) == src_id:
                (src / "sub").rename(src / "saved-sub")
                (src / "sub").symlink_to(src / "saved-sub", target_is_directory=True)
                moved.append(True)
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_after_stat)
    with pytest.raises(safety.SafetyError, match="Source folder changed while copying"):
        safety.copy_tree_nofollow(src, dst)
    assert moved
    assert not (dst / "sub").exists()


def test_pinned_folder_refuses_protected_root_behind_a_link(tmp_path):
    """The constructor itself refuses a protected root reached through a linked parent."""
    protected = Path(os.environ["HERMES_HOME"])
    (protected / "chosen").mkdir()
    link = tmp_path / "parent-link"
    link.symlink_to(protected, target_is_directory=True)
    with pytest.raises(safety.SafetyError, match="inside live"):
        with safety.PinnedFolder(link / "chosen"):
            pass
