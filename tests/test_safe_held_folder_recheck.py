"""A folder opened earlier and kept open is checked again each time it is used.

The chosen path must still name the same folder (same device and inode), and that folder's
current real location must still be allowed (not inside the Hermes home). Otherwise the
write is refused. Every case runs under pytest's tmp_path with a fake home.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import applier, cli, output_file, safety  # noqa: E402
from hermes_plugins.defuzz.safety import PinnedFolder, SafetyError  # noqa: E402


def _files(root: Path) -> list:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.exists() else []


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    return home


def _move_into_hermes_home(home: Path, folder: Path) -> Path:
    moved = home / ".hermes" / "moved"
    os.rename(folder, moved)
    folder.mkdir()  # a fresh, empty folder now has the chosen name
    return moved


@pytest.mark.parametrize("caller", ["write", "mkdir"])
def test_held_folder_moved_into_hermes_home_is_refused(home, tmp_path, caller):
    chosen = tmp_path / "work" / "chosen"
    chosen.mkdir(parents=True)
    with PinnedFolder(chosen) as pin:
        moved = _move_into_hermes_home(home, chosen)
        with pytest.raises(SafetyError, match="moved after it was opened"):
            if caller == "write":
                safety.safe_write_text(chosen, "payload", "data\n", base=pin)
            else:
                safety.safe_mkdirs(chosen, "payload", base=pin)
    assert _files(moved) == []
    assert _files(chosen) == []


def test_held_output_folder_moved_into_hermes_home_is_refused(home, tmp_path):
    chosen = tmp_path / "work" / "chosen"
    chosen.mkdir(parents=True)
    with PinnedFolder(chosen, role="report") as pin:
        moved = _move_into_hermes_home(home, chosen)
        with pytest.raises(SafetyError, match="moved after it was opened"):
            output_file.write_output_text(chosen / "payload", "data\n", role="report", base=pin)
    assert _files(moved) == []
    assert _files(chosen) == []


def test_report_folder_moved_into_hermes_home_is_refused(home, tmp_path):
    reports = tmp_path / "work" / "reports"
    reports.mkdir(parents=True)
    with applier.ReportDestination(reports / "report.json") as dest:
        moved = _move_into_hermes_home(home, reports)
        with pytest.raises(SafetyError, match="moved after it was opened"):
            dest.write("{}\n")
    assert _files(moved) == []
    assert _files(reports) == []


def test_completion_marker_copy_moved_into_hermes_home_is_refused(home, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# source\n")
    parent = tmp_path / "work" / "proj"
    copy_root = parent / "adopted"
    copy_root.mkdir(parents=True)
    with pytest.raises(SafetyError, match="moved after it was opened"):
        with output_file.adopt_copy_guard(copy_root, src):
            moved = _move_into_hermes_home(home, parent)
    assert _files(moved) == ["adopted"]
    assert _files(parent) == []


def test_held_folder_whose_parent_is_swapped_for_a_link_is_refused(tmp_path):
    parent = tmp_path / "work"
    root = parent / "root"
    root.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "root").mkdir(parents=True)
    held = tmp_path / "work.held"
    with PinnedFolder(root) as pin:
        os.rename(parent, held)
        parent.symlink_to(elsewhere, target_is_directory=True)
        with pytest.raises(SafetyError, match="moved after it was opened"):
            safety.safe_write_text(root, "payload", "data\n", base=pin)
    assert _files(held / "root") == []
    assert _files(elsewhere) == ["root"]


def test_run_source_with_projects_folder_swapped_after_copy_fails_without_marker(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# source\n")
    (src / "main.py").write_text("print(1)\n")
    projects = home / "Projects"
    projects.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.copytree(src, outside / "copy")
    real_copy = cli.copy_tree_nofollow
    swapped = False

    def copy_then_swap(*args, **kwargs):
        nonlocal swapped
        result = real_copy(*args, **kwargs)
        if not swapped:
            swapped = True
            os.rename(projects, home / "Held")
            projects.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(cli, "copy_tree_nofollow", copy_then_swap)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = cli.main([
            "run", str(projects / "copy"), "--source", str(src),
            "--inventory", str(tmp_path / "inventory.json"), "--deterministic",
        ])
    assert swapped
    assert rc == 1, out.getvalue()
    assert "Traceback" not in out.getvalue()
    marker = Path(*output_file.ADOPT_COMPLETE_MARKER)
    assert not (home / "Held" / "copy" / marker).exists()
    assert not (outside / "copy" / marker).exists()
