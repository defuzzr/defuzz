"""One test per single weakened check in the safe-write helpers.

Each test fails when its check is removed or weakened, and passes on the real code. Where an
earlier, broader check would also refuse the same input, the test makes the input change in
between (a folder swapped, a name planted) so only the check under test can refuse it.
Every case runs under pytest's tmp_path.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import applier, output_file, safety  # noqa: E402
from hermes_plugins.defuzz.rules import build_deterministic_fallback_rules  # noqa: E402
from hermes_plugins.defuzz.safety import PinnedFolder, SafetyError  # noqa: E402
from hermes_plugins.defuzz.scanner import scan_folder  # noqa: E402

OTHER = b"someone else's file\n"


def _stat_with(st: os.stat_result, *, ino=None, dev=None) -> os.stat_result:
    values = list(st)
    if ino is not None:
        values[1] = ino
    if dev is not None:
        values[2] = dev
    return os.stat_result(values)


def _swap_for_link(folder: Path, target: Path) -> Path:
    held = folder.with_name(folder.name + ".held")
    os.rename(folder, held)
    folder.symlink_to(target, target_is_directory=True)
    return held


def _source(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# source\n")
    (src / "main.py").write_text("print(1)\n")
    return src


# ------------------------------------------------------------------ identity: device and inode


def test_pin_compares_device_even_when_the_inode_matches(tmp_path, monkeypatch):
    chosen, foreign = tmp_path / "chosen", tmp_path / "foreign"
    chosen.mkdir()
    foreign.mkdir()
    expected = chosen.stat()
    foreign_ino = foreign.stat().st_ino
    real_fstat = os.fstat

    def foreign_handle(path):
        return os.open(foreign, os.O_RDONLY | os.O_DIRECTORY)

    def same_inode_other_device(fd):
        st = real_fstat(fd)
        if st.st_ino == foreign_ino:
            return _stat_with(st, ino=expected.st_ino, dev=expected.st_dev + 1)
        return st

    monkeypatch.setattr(safety, "_open_resolved_dir", foreign_handle)
    monkeypatch.setattr(os, "fstat", same_inode_other_device)
    with pytest.raises(SafetyError, match="changed while it was opened"):
        PinnedFolder(chosen)


def _fail_after_swapping_the_name(monkeypatch, root: Path, name: str):
    """Make the next data write fail after another file has taken `name`."""
    real_write_all = safety._write_all

    def swap_then_fail(fd, data):
        other = root / ".other"
        other.write_bytes(OTHER)
        os.rename(other, root / name)
        monkeypatch.setattr(safety, "_write_all", real_write_all)
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(safety, "_write_all", swap_then_fail)


def test_cleanup_after_a_failed_write_keeps_a_file_that_is_not_ours(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _fail_after_swapping_the_name(monkeypatch, root, "out.txt")
    with pytest.raises(SafetyError, match="Could not write file"):
        safety.safe_write_text(root, "out.txt", "ours\n")
    assert (root / "out.txt").read_bytes() == OTHER


def test_cleanup_compares_device_even_when_the_inode_matches(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    _fail_after_swapping_the_name(monkeypatch, root, "out.txt")
    real_fstat, real_stat = os.fstat, os.stat
    ours = {}

    def remember(fd):
        st = real_fstat(fd)
        if stat.S_ISREG(st.st_mode):
            ours["st"] = st
        return st

    def same_inode_other_device(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        if path == "out.txt" and kwargs.get("dir_fd") is not None and "st" in ours:
            return _stat_with(st, ino=ours["st"].st_ino, dev=ours["st"].st_dev + 1)
        return st

    monkeypatch.setattr(os, "fstat", remember)
    monkeypatch.setattr(os, "stat", same_inode_other_device)
    with pytest.raises(SafetyError, match="Could not write file"):
        safety.safe_write_text(root, "out.txt", "ours\n")
    monkeypatch.undo()
    assert (root / "out.txt").read_bytes() == OTHER


def test_failed_new_file_write_leaves_no_partial_file(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()

    def half_then_fail(fd, data):
        os.write(fd, data[: len(data) // 2])
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(safety, "_write_all", half_then_fail)
    with pytest.raises(SafetyError, match="Could not write file"):
        safety.safe_write_text(root, "out.txt", "complete contents\n")
    assert os.listdir(root) == []


# ------------------------------------------------------------------ the Hermes home, checked late


@pytest.fixture
def hermes_alias(tmp_path, monkeypatch):
    """HERMES_HOME is a link that first names an unrelated folder; tests repoint it."""
    unrelated = tmp_path / "unrelated-settings"
    unrelated.mkdir()
    alias = tmp_path / "settings-link"
    alias.symlink_to(unrelated, target_is_directory=True)
    monkeypatch.setenv("HERMES_HOME", str(alias))

    def point_at(target: Path) -> None:
        alias.unlink()
        alias.symlink_to(target)

    return point_at


def test_report_name_that_becomes_the_hermes_home_is_refused(tmp_path, monkeypatch, hermes_alias):
    reports = tmp_path / "reports"
    reports.mkdir()
    report = reports / "report.json"
    real_pin = applier.PinnedFolder

    def repoint_then_pin(*args, **kwargs):
        hermes_alias(report)  # after the first check of the report path
        return real_pin(*args, **kwargs)

    monkeypatch.setattr(applier, "PinnedFolder", repoint_then_pin)
    with pytest.raises(SafetyError, match="inside live"):
        applier.ReportDestination(report)
    assert os.listdir(reports) == []


def test_root_below_base_that_becomes_the_hermes_home_is_refused(tmp_path, monkeypatch, hermes_alias):
    base = tmp_path / "base"
    root = base / "inner"
    root.mkdir(parents=True)
    real_require = safety._require_dir_fd
    done = []

    def repoint_then_continue(path):
        if not done:
            done.append(True)
            hermes_alias(root)  # after the start checks, before the folders are opened
        return real_require(path)

    monkeypatch.setattr(safety, "_require_dir_fd", repoint_then_continue)
    with pytest.raises(SafetyError, match="inside live"):
        safety.safe_write_text(root, "payload", "x\n", base=base)
    assert os.listdir(root) == []


# ------------------------------------------------------------------ overlap on the opened real folders


def test_copy_destination_whose_parent_turns_into_a_link_into_the_source_is_refused(tmp_path, monkeypatch):
    src = _source(tmp_path)
    (src / "inside").mkdir()
    parent = tmp_path / "out" / "p"
    parent.mkdir(parents=True)
    dst = parent / "copy"
    real_open_dest = safety._open_copy_destination

    def swap_then_open(*args, **kwargs):
        _swap_for_link(parent, src / "inside")  # after the start check of the roots
        return real_open_dest(*args, **kwargs)

    def no_copy(*args, **kwargs):  # a copy into its own source would never end
        raise AssertionError("the copy started inside the source")

    monkeypatch.setattr(safety, "_open_copy_destination", swap_then_open)
    monkeypatch.setattr(safety, "_copy_walk", no_copy)
    with pytest.raises(SafetyError, match="overlapping roots"):
        safety.copy_tree_nofollow(src, dst)
    assert not (src / "inside" / "copy" / "README.md").exists()


def test_report_folder_reached_into_the_source_is_refused_before_any_work(tmp_path):
    src = _source(tmp_path)
    (src / "reports" / "sub").mkdir(parents=True)
    copy = tmp_path / "copy"
    safety.copy_tree_nofollow(src, copy)
    inventory = scan_folder(copy, source_root=src)
    rules = build_deterministic_fallback_rules(inventory)
    link = tmp_path / "report-link"
    link.symlink_to(src / "reports", target_is_directory=True)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "sub").mkdir(parents=True)
    with applier.ReportDestination(link / "sub" / "report.json") as dest:
        link.unlink()
        link.symlink_to(elsewhere, target_is_directory=True)
        with pytest.raises(SafetyError, match="overlapping roots"):
            applier.apply_rules_to_copy(copy, inventory, rules, source_root=src, report_out_path=dest)
    assert not (copy / ".git").exists()
    assert not (copy / ".adopt").exists()
    assert os.listdir(src / "reports" / "sub") == []
    assert os.listdir(elsewhere / "sub") == []


# ------------------------------------------------------------------ the read-only walk (safe_rename's source side)


def test_rename_source_folder_swapped_for_a_link_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.txt").write_text("outside\n")
    (root / "a" / "f.txt").write_text("inside\n")
    real_below = safety._below_base
    done = []

    def swap_then_pin(*args, **kwargs):
        if not done:
            done.append(True)
            _swap_for_link(root / "a", outside)  # after the start checks of both names
        return real_below(*args, **kwargs)

    monkeypatch.setattr(safety, "_below_base", swap_then_pin)
    with pytest.raises(SafetyError, match="symlink"):
        safety.safe_rename(root, "a/f.txt", "g.txt")
    assert (outside / "f.txt").read_text() == "outside\n"
    assert not os.path.lexists(root / "g.txt")


def test_rename_in_a_missing_root_creates_nothing(tmp_path):
    root = tmp_path / "missing" / "root"
    with pytest.raises(SafetyError, match="does not exist"):
        safety.safe_rename(root, "a.txt", "b.txt")
    assert not (tmp_path / "missing").exists()


# ------------------------------------------------------------------ output files, the final name, copies, apply


def test_output_subfolder_swapped_for_a_link_after_the_check_is_refused(tmp_path, monkeypatch):
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_check = output_file.assert_output_path_safe

    def check_then_swap(*args, **kwargs):
        result = real_check(*args, **kwargs)
        _swap_for_link(out / "sub", outside)
        return result

    monkeypatch.setattr(output_file, "assert_output_path_safe", check_then_swap)
    with pytest.raises(SafetyError, match="link"):
        output_file.write_output_text(out / "sub" / "inventory.json", "{}\n", role="inventory_out")
    assert os.listdir(outside) == []


def test_overwrite_refuses_a_link_planted_at_the_name(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    (root / "name.txt").write_text("old\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n")
    real_walk = safety._walk_dirs

    def walk_then_plant(*args, **kwargs):
        result = real_walk(*args, **kwargs)
        (root / "name.txt").unlink()
        (root / "name.txt").symlink_to(outside)
        return result

    monkeypatch.setattr(safety, "_walk_dirs", walk_then_plant)
    with pytest.raises(SafetyError, match="symlink"):
        safety.safe_write_text(root, "name.txt", "new\n", overwrite=True)
    assert os.path.islink(root / "name.txt")
    assert outside.read_text() == "outside\n"


def test_copy_keeps_folder_modes(tmp_path):
    src = _source(tmp_path)
    (src / "private").mkdir()
    (src / "private" / "x.txt").write_text("x\n")
    os.chmod(src / "private", 0o750)
    dst = tmp_path / "copy"
    safety.copy_tree_nofollow(src, dst)
    assert stat.S_IMODE((dst / "private").stat().st_mode) == 0o750


def test_apply_fails_when_a_file_changes_before_it_is_confirmed(tmp_path, monkeypatch):
    src = _source(tmp_path)
    copy = tmp_path / "copy"
    safety.copy_tree_nofollow(src, copy)
    inventory = scan_folder(copy, source_root=src)
    rules = build_deterministic_fallback_rules(inventory)
    real_verify = applier._verify_post_apply_integrity

    def change_then_verify(*args, **kwargs):
        for path in copy.rglob("main.py"):
            path.write_text("print('changed')\n")
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(applier, "_verify_post_apply_integrity", change_then_verify)
    with pytest.raises(SafetyError, match="SHA-256 mismatch"):
        applier.apply_rules_to_copy(copy, inventory, rules, source_root=src)
