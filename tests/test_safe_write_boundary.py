"""Writes through safety.safe_write_bytes / safe_mkdirs / copy_tree_nofollow never leave their folder.

A link, a hard link, a FIFO or a folder swapped for a link between the check and the write
must not redirect, truncate or block the write. Everything runs in temporary folders.
"""

from __future__ import annotations

import errno
import os
import resource
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import safety  # noqa: E402
from hermes_plugins.defuzz.safety import (  # noqa: E402
    SafetyError,
    copy_tree_nofollow,
    safe_mkdirs,
    safe_write_bytes,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTSIDE_BYTES = b"precious outside data\n"


@pytest.fixture()
def case(tmp_path: Path):
    root = tmp_path / "proj"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_bytes(OUTSIDE_BYTES)
    return {"tmp": tmp_path, "root": root, "outside": outside, "victim": victim}


def _listing(folder: Path):
    return sorted(p.name for p in folder.iterdir())


def _no_temp_leftovers(folder: Path) -> None:
    names = [p.name for p in folder.rglob("*")]
    assert not [n for n in names if n.endswith(".tmp")], names


# ------------------------------------------------------------------ normal behaviour


def test_new_file_nested_and_mode(case):
    old = os.umask(0o022)
    try:
        out = safe_write_bytes(case["root"], "a/b/c.txt", b"hello", mode=0o600)
    finally:
        os.umask(old)
    assert out == case["root"] / "a" / "b" / "c.txt"
    assert out.read_bytes() == b"hello"
    assert stat.S_IMODE(os.lstat(out).st_mode) == 0o600
    _no_temp_leftovers(case["root"])


def test_overwrite_false_refuses_existing(case):
    target = case["root"] / "f.txt"
    target.write_bytes(b"old")
    with pytest.raises(SafetyError, match="Refusing to overwrite existing file"):
        safe_write_bytes(case["root"], "f.txt", b"new", overwrite=False)
    assert target.read_bytes() == b"old"


def test_overwrite_regular_keeps_mode(case):
    target = case["root"] / "sub" / "f.txt"
    target.parent.mkdir()
    target.write_bytes(b"old old old")
    os.chmod(target, 0o640)
    safe_write_bytes(case["root"], "sub/f.txt", b"new", overwrite=True)
    assert target.read_bytes() == b"new"
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o640
    assert stat.S_ISREG(os.lstat(target).st_mode)
    _no_temp_leftovers(case["root"])


def test_overwrite_creates_missing_file(case):
    safe_write_bytes(case["root"], ".adopt/rules.json", b"{}", overwrite=True)
    assert (case["root"] / ".adopt" / "rules.json").read_bytes() == b"{}"


def test_overwrite_folder_leaf_refused(case):
    (case["root"] / "d").mkdir()
    with pytest.raises(SafetyError):
        safe_write_bytes(case["root"], "d", b"x", overwrite=True)
    assert (case["root"] / "d").is_dir()


# ------------------------------------------------------------------ links


@pytest.mark.parametrize("overwrite", [False, True])
def test_leaf_symlink_refused(case, overwrite):
    (case["root"] / "AGENTS.md").symlink_to(case["victim"])
    with pytest.raises(SafetyError, match="symlink"):
        safe_write_bytes(case["root"], "AGENTS.md", b"pwned", overwrite=overwrite)
    assert case["victim"].read_bytes() == OUTSIDE_BYTES
    assert os.path.islink(case["root"] / "AGENTS.md")


@pytest.mark.parametrize("overwrite", [False, True])
def test_dangling_leaf_symlink_refused(case, overwrite):
    missing = case["outside"] / "made.txt"
    (case["root"] / "x.txt").symlink_to(missing)
    with pytest.raises(SafetyError, match="symlink"):
        safe_write_bytes(case["root"], "x.txt", b"pwned", overwrite=overwrite)
    assert not missing.exists()


def test_ancestor_symlink_inside_root_refused(case):
    (case["root"] / "sub").symlink_to(case["outside"], target_is_directory=True)
    with pytest.raises(SafetyError, match="symlink"):
        safe_write_bytes(case["root"], "sub/new.txt", b"pwned")
    with pytest.raises(SafetyError, match="symlink"):
        safe_mkdirs(case["root"], "sub/deeper")
    assert _listing(case["outside"]) == ["victim.txt"]


def test_root_created_through_ancestor_link_below_base_refused(case):
    # The chosen folder (base) is trusted; a link between it and the root is not.
    vdir = case["outside"] / "victim_dir"
    vdir.mkdir()
    (case["tmp"] / "via").symlink_to(vdir, target_is_directory=True)
    with pytest.raises(SafetyError, match="symlink"):
        safe_write_bytes(case["tmp"] / "via" / "newroot", "f.txt", b"pwned", base=case["tmp"])
    with pytest.raises(SafetyError, match="symlink"):
        safe_mkdirs(case["tmp"] / "via" / "newroot2", "a", base=case["tmp"])
    with safety.PinnedFolder(case["tmp"]) as pinned:
        with pytest.raises(SafetyError, match="symlink"):
            safe_write_bytes(case["tmp"] / "via" / "newroot3", "f.txt", b"pwned", base=pinned)
    assert _listing(vdir) == []


def test_root_outside_base_refused(case):
    with pytest.raises(SafetyError, match="outside the chosen folder"):
        safe_write_bytes(case["outside"] / "x", "f.txt", b"pwned", base=case["root"])
    assert _listing(case["outside"]) == ["victim.txt"]


def test_root_reached_through_the_chosen_link_works(case):
    # A link ABOVE the chosen root is the person's own (for example ~/Work -> /mnt/disk).
    disk = case["tmp"] / "disk"
    disk.mkdir()
    (case["tmp"] / "Work").symlink_to(disk, target_is_directory=True)
    safe_write_bytes(case["tmp"] / "Work" / "Projects" / "new", "a/b.txt", b"ok")
    assert (disk / "Projects" / "new" / "a" / "b.txt").read_bytes() == b"ok"
    assert safe_mkdirs(case["tmp"] / "Work" / "Projects" / "n2", "x") == case["tmp"] / "Work" / "Projects" / "n2" / "x"
    assert (disk / "Projects" / "n2" / "x").is_dir()


def test_root_that_is_a_link_refused(case):
    (case["tmp"] / "rootlink").symlink_to(case["outside"], target_is_directory=True)
    for call in (
        lambda: safe_write_bytes(case["tmp"] / "rootlink", "f.txt", b"pwned"),
        lambda: safe_mkdirs(case["tmp"] / "rootlink", "a"),
        lambda: safety.PinnedFolder(case["tmp"] / "rootlink"),
    ):
        with pytest.raises(SafetyError, match="symlink"):
            call()
    assert _listing(case["outside"]) == ["victim.txt"]


def test_symlinked_home_still_works(case, monkeypatch):
    real_home = case["tmp"] / "real_home"
    real_home.mkdir()
    home = case["tmp"] / "home_link"
    home.symlink_to(real_home, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    safe_write_bytes(home / "work" / "proj", "a/b.txt", b"ok")
    assert (real_home / "work" / "proj" / "a" / "b.txt").read_bytes() == b"ok"
    assert safe_mkdirs(home / "work" / "proj2", "x") == home / "work" / "proj2" / "x"
    assert (real_home / "work" / "proj2" / "x").is_dir()


# ------------------------------------------------------------------ hard links


def test_overwrite_hardlink_leaves_outside_inode_unchanged(case):
    ext = case["victim"]
    before = os.lstat(ext)
    os.link(ext, case["root"] / "place-log.json")
    safe_write_bytes(case["root"], "place-log.json", b"new log", overwrite=True)
    after = os.lstat(ext)
    assert ext.read_bytes() == OUTSIDE_BYTES
    assert (after.st_ino, after.st_size) == (before.st_ino, before.st_size)
    inside = os.lstat(case["root"] / "place-log.json")
    assert inside.st_ino != before.st_ino
    assert (case["root"] / "place-log.json").read_bytes() == b"new log"


# ------------------------------------------------------------------ FIFOs (bounded subprocess)

_FIFO_PROBE = r'''
import importlib.util, sys
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("defuzz_fifo", root + "/__init__.py",
                                              submodule_search_locations=[root])
module = importlib.util.module_from_spec(spec)
sys.modules["defuzz_fifo"] = module
spec.loader.exec_module(module)
import importlib
safety = importlib.import_module("defuzz_fifo.safety")
try:
    safety.safe_write_bytes(sys.argv[2], sys.argv[3], b"x", overwrite=sys.argv[4] == "1")
    print("WROTE")
except safety.SafetyError as exc:
    print("REFUSED " + str(exc))
'''


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("overwrite", ["0", "1"])
def test_fifo_leaf_never_blocks(case, overwrite):
    fifo = case["root"] / ".adopt" / "rules.json"
    fifo.parent.mkdir()
    os.mkfifo(fifo)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _FIFO_PROBE, str(REPO_ROOT), str(case["root"]), ".adopt/rules.json", overwrite],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL, cwd=str(case["tmp"]),
        )
    except subprocess.TimeoutExpired:
        # Unblock and reap the writer before failing.
        fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        os.close(fd)
        pytest.fail("safe_write_bytes blocked on a FIFO")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("REFUSED"), proc.stdout
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)


# ------------------------------------------------------------------ races


def test_race_parent_swapped_to_link_after_check(case, monkeypatch):
    # The folder is swapped for a link just before the file itself is opened, after every check.
    sub = case["root"] / "sub"
    sub.mkdir()
    real_open = os.open
    swapped = []

    def open_after_swap(path, flags, mode=0o777, *, dir_fd=None):
        if not swapped and os.path.basename(os.fspath(path)) not in ("proj", "sub"):
            swapped.append(path)
            os.rename(sub, case["root"] / "sub.moved")
            sub.symlink_to(case["outside"], target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", open_after_swap)
    try:
        safe_write_bytes(case["root"], "sub/victim.txt", b"pwned", overwrite=True)
    except SafetyError:
        pass
    monkeypatch.undo()
    assert swapped
    assert case["victim"].read_bytes() == OUTSIDE_BYTES
    assert _listing(case["outside"]) == ["victim.txt"]


def test_race_leaf_swapped_to_hardlink_after_check(case, monkeypatch):
    real_verify = safety.verify_nofollow_within_root

    def verify_then_link(root, rel_path):
        out = real_verify(root, rel_path)
        os.link(case["victim"], case["root"] / "AGENTS.md")
        return out

    monkeypatch.setattr(safety, "verify_nofollow_within_root", verify_then_link)
    safe_write_bytes(case["root"], "AGENTS.md", b"mine", overwrite=True)
    assert case["victim"].read_bytes() == OUTSIDE_BYTES
    assert (case["root"] / "AGENTS.md").read_bytes() == b"mine"


def test_race_leaf_swapped_to_link_after_check(case, monkeypatch):
    real_verify = safety.verify_nofollow_within_root

    def verify_then_link(root, rel_path):
        out = real_verify(root, rel_path)
        (case["root"] / "new.txt").symlink_to(case["victim"])
        return out

    monkeypatch.setattr(safety, "verify_nofollow_within_root", verify_then_link)
    with pytest.raises(SafetyError):
        safe_write_bytes(case["root"], "new.txt", b"pwned", overwrite=False)
    assert case["victim"].read_bytes() == OUTSIDE_BYTES


def test_overwrite_failure_cleans_temp_and_keeps_old(case, monkeypatch):
    target = case["root"] / "f.txt"
    target.write_bytes(b"old")

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(safety.os, "replace", boom)
    with pytest.raises(SafetyError, match="disk full"):
        safe_write_bytes(case["root"], "f.txt", b"new", overwrite=True)
    assert target.read_bytes() == b"old"
    assert _listing(case["root"]) == ["f.txt"]


# ------------------------------------------------------------------ copy_tree_nofollow


@pytest.fixture()
def src_tree(tmp_path: Path):
    src = tmp_path / "src"
    (src / "pkg" / "deep").mkdir(parents=True)
    (src / "README.md").write_bytes(b"# readme\n")
    (src / "pkg" / "main.py").write_bytes(b"print(1)\n")
    os.chmod(src / "pkg" / "main.py", 0o750)
    (src / "pkg" / "deep" / "x.txt").write_bytes(b"x\n")
    (src / "link").symlink_to("pkg/main.py")
    (src / "dangling").symlink_to("../nowhere")
    if hasattr(os, "mkfifo"):
        os.mkfifo(src / "pipe")
    os.utime(src / "README.md", ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
    return src


def test_copy_tree_normal(tmp_path, src_tree):
    dst = tmp_path / "copy"
    assert copy_tree_nofollow(src_tree, dst) == dst
    assert (dst / "README.md").read_bytes() == b"# readme\n"
    assert (dst / "pkg" / "deep" / "x.txt").read_bytes() == b"x\n"
    assert stat.S_IMODE(os.lstat(dst / "pkg" / "main.py").st_mode) == 0o750
    assert os.readlink(dst / "link") == "pkg/main.py"
    assert os.readlink(dst / "dangling") == "../nowhere"
    assert not os.path.lexists(dst / "pipe")
    assert os.lstat(dst / "README.md").st_mtime_ns == 1_000_000_000_000_000_000


def test_copy_tree_into_existing_empty_folder(tmp_path, src_tree):
    dst = tmp_path / "copy"
    dst.mkdir()
    copy_tree_nofollow(src_tree, dst)
    assert (dst / "pkg" / "main.py").is_file()


def test_copy_tree_refuses_nonempty_destination(tmp_path, src_tree):
    dst = tmp_path / "copy"
    dst.mkdir()
    (dst / "keep.txt").write_bytes(b"keep")
    with pytest.raises(SafetyError, match="non-empty"):
        copy_tree_nofollow(src_tree, dst)
    assert _listing(dst) == ["keep.txt"]


def test_copy_tree_destination_under_ancestor_link_below_base_refused(tmp_path, src_tree):
    outside = tmp_path / "outside"
    vdir = outside / "victim_dir"
    vdir.mkdir(parents=True)
    (vdir / "keep.txt").write_bytes(OUTSIDE_BYTES)
    (outside / "via").symlink_to(vdir, target_is_directory=True)
    with pytest.raises(SafetyError, match="symlink"):
        copy_tree_nofollow(src_tree, outside / "via" / "thecopy", base=outside)
    assert _listing(vdir) == ["keep.txt"]


def test_copy_tree_destination_through_the_chosen_link_works(tmp_path, src_tree):
    disk = tmp_path / "disk"
    disk.mkdir()
    (tmp_path / "Projects").symlink_to(disk, target_is_directory=True)
    dst = tmp_path / "Projects" / "group" / "thecopy"
    assert copy_tree_nofollow(src_tree, dst, base=dst) == dst
    assert (disk / "group" / "thecopy" / "pkg" / "deep" / "x.txt").read_bytes() == b"x\n"
    assert copy_tree_nofollow(src_tree, tmp_path / "Projects" / "c2") == tmp_path / "Projects" / "c2"
    assert (disk / "c2" / "README.md").is_file()


@pytest.mark.parametrize("preexisting", [False, True])
def test_copy_tree_folder_swapped_to_link_mid_copy(tmp_path, src_tree, monkeypatch, preexisting):
    outside = tmp_path / "outside"
    outside.mkdir()
    dst = tmp_path / "copy"
    if preexisting:
        dst.mkdir()
    real_mkdir = os.mkdir

    def mkdir_then_swap(path, mode=0o777, *, dir_fd=None):
        real_mkdir(path, mode, dir_fd=dir_fd)
        if os.path.basename(os.fspath(path)) != "pkg":
            return
        if dir_fd is None:
            os.rename(path, os.fspath(path) + ".moved")
            os.symlink(str(outside), path)
        else:
            os.rename(path, "pkg.moved", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.symlink(str(outside), path, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "mkdir", mkdir_then_swap)
    with pytest.raises(SafetyError):
        copy_tree_nofollow(src_tree, dst)
    monkeypatch.undo()
    assert _listing(outside) == []
    assert dst.is_dir()  # nothing is deleted on failure


# ------------------------------------------------------------------ pinned base: swaps before the open


def _swap_on_first_open(monkeypatch, action, nth_walk=1):
    """Run `action` once, right before the nth walk from "/" starts (after every path check)."""
    real_open = os.open
    done = []
    walks = []

    def hooked(path, flags, mode=0o777, *, dir_fd=None):
        if path == "/":
            walks.append(path)
        if not done and len(walks) == nth_walk:
            done.append(path)
            action()
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", hooked)
    return done


@pytest.fixture()
def swap_case(tmp_path: Path):
    parent = tmp_path / "parent"
    (parent / "root").mkdir(parents=True)
    other = tmp_path / "outside"
    (other / "root").mkdir(parents=True)
    return {"tmp": tmp_path, "parent": parent, "held": tmp_path / "held", "other": other}


def _no_victim_anywhere(c) -> None:
    for top in (c["tmp"],):
        assert not [p for p in top.rglob("victim")], list(top.rglob("victim"))


def test_existing_root_ancestor_swapped_for_link_refused(swap_case, monkeypatch):
    c = swap_case

    def swap():
        os.rename(c["parent"], c["held"])
        os.symlink(c["other"], c["parent"], target_is_directory=True)

    done = _swap_on_first_open(monkeypatch, swap)
    with pytest.raises(SafetyError):
        safe_write_bytes(c["parent"] / "root", "victim", b"injected", overwrite=True)
    monkeypatch.undo()
    assert done
    assert _listing(c["other"] / "root") == []
    _no_victim_anywhere(c)


def test_existing_root_ancestor_swapped_for_link_to_itself_refused(swap_case, monkeypatch):
    # Any link met while opening the resolved path was swapped in: refused even when it leads
    # back to the same folder.
    c = swap_case

    def swap():
        os.rename(c["parent"], c["held"])
        os.symlink(c["held"], c["parent"], target_is_directory=True)

    _swap_on_first_open(monkeypatch, swap)
    with pytest.raises(SafetyError, match="changed while it was opened"):
        safe_write_bytes(c["parent"] / "root", "victim", b"injected", overwrite=True)
    monkeypatch.undo()
    _no_victim_anywhere(c)


@pytest.mark.parametrize("helper", ["write", "mkdirs", "copy", "missing_root"])
def test_root_ancestor_swapped_for_another_real_folder_refused(swap_case, monkeypatch, src_tree, helper):
    c = swap_case
    (c["other"] / "root" / "keep").mkdir()

    def swap():
        os.rename(c["parent"], c["held"])
        os.rename(c["other"], c["parent"])

    root = c["parent"] / "root"
    calls = {
        "write": lambda: safe_write_bytes(root, "victim", b"injected"),
        "mkdirs": lambda: safe_mkdirs(root, "victim"),
        "copy": lambda: copy_tree_nofollow(src_tree, root / "victim"),
        "missing_root": lambda: safe_write_bytes(root / "victim", "f", b"injected"),
    }
    # the copy opens its source first, then the destination
    _swap_on_first_open(monkeypatch, swap, nth_walk=2 if helper == "copy" else 1)
    with pytest.raises(SafetyError, match="changed while it was opened"):
        calls[helper]()
    monkeypatch.undo()
    _no_victim_anywhere(c)
    assert _listing(c["parent"] / "root") == ["keep"]


# ------------------------------------------------------------------ copy: source swapped at the open


def _swap_before_source_open(monkeypatch, name, action):
    real_open = os.open
    done = []

    def hooked(path, flags, mode=0o777, *, dir_fd=None):
        if not done and path == name and dir_fd is not None and not flags & os.O_CREAT and not flags & os.O_DIRECTORY:
            done.append(path)
            action()
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", hooked)
    return done


def test_copy_source_file_replaced_by_other_file_refused(tmp_path, src_tree, monkeypatch):
    main = src_tree / "pkg" / "main.py"
    other = tmp_path / "other.py"
    other.write_bytes(b"SECRET other file\n")

    done = _swap_before_source_open(monkeypatch, "main.py", lambda: os.replace(other, main))
    with pytest.raises(SafetyError, match="Source file changed while copying"):
        copy_tree_nofollow(src_tree, tmp_path / "copy")
    monkeypatch.undo()
    assert done
    assert not (tmp_path / "copy" / "pkg" / "main.py").exists()


def test_copy_source_file_replaced_by_link_refused(tmp_path, src_tree, monkeypatch):
    main = src_tree / "pkg" / "main.py"

    def swap():
        os.rename(main, src_tree / "pkg" / "main.held")
        os.symlink("main.held", main)

    _swap_before_source_open(monkeypatch, "main.py", swap)
    with pytest.raises(SafetyError, match="Source file changed while copying"):
        copy_tree_nofollow(src_tree, tmp_path / "copy")
    monkeypatch.undo()
    assert not os.path.lexists(tmp_path / "copy" / "pkg" / "main.py")


_SOURCE_FIFO_PROBE = r'''
import importlib.util, importlib, os, sys
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("defuzz_fifo2", root + "/__init__.py",
                                              submodule_search_locations=[root])
module = importlib.util.module_from_spec(spec)
sys.modules["defuzz_fifo2"] = module
spec.loader.exec_module(module)
safety = importlib.import_module("defuzz_fifo2.safety")
src, dst = sys.argv[2], sys.argv[3]
real_open = os.open
def hooked(path, flags, mode=0o777, *, dir_fd=None):
    if path == "README.md" and dir_fd is not None and not flags & os.O_CREAT:
        os.unlink(os.path.join(src, "README.md"))
        os.mkfifo(os.path.join(src, "README.md"))
    return real_open(path, flags, mode, dir_fd=dir_fd)
safety.os.open = hooked
try:
    safety.copy_tree_nofollow(src, dst)
    print("COPIED")
except safety.SafetyError as exc:
    print("REFUSED " + str(exc))
'''


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_copy_source_file_replaced_by_fifo_never_blocks(tmp_path, src_tree):
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _SOURCE_FIFO_PROBE, str(REPO_ROOT), str(src_tree), str(tmp_path / "copy")],
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL, cwd=str(tmp_path),
        )
    except subprocess.TimeoutExpired:
        pytest.fail("copy_tree_nofollow blocked on a FIFO swapped in for a source file")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("REFUSED"), proc.stdout
    assert "changed while copying" in proc.stdout


def test_copy_unreadable_source_file_named_plainly(tmp_path, src_tree, monkeypatch):
    real_open = os.open

    def hooked(path, flags, mode=0o777, *, dir_fd=None):
        if path == "main.py" and dir_fd is not None and not flags & os.O_CREAT:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", hooked)
    with pytest.raises(SafetyError) as info:
        copy_tree_nofollow(src_tree, tmp_path / "copy")
    monkeypatch.undo()
    msg = str(info.value)
    assert msg == f"Could not read source file (Permission denied): {src_tree / 'pkg' / 'main.py'}"
    assert (tmp_path / "copy" / "README.md").is_file()  # earlier files are kept


def test_copy_source_folder_swapped_for_other_folder_refused(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / "a" / "b" / "c" / "x").mkdir(parents=True)
    (src / "a" / "b" / "c" / "y").mkdir()
    (src / "a" / "b" / "c" / "y" / "mine.txt").write_bytes(b"mine")
    other = tmp_path / "other"
    (other / "c" / "y").mkdir(parents=True)
    (other / "c" / "y" / "theirs.txt").write_bytes(b"theirs")
    monkeypatch.setattr(safety, "_COPY_HELD_LEVELS", 1)
    real_mkdir = os.mkdir

    def mkdir_then_swap(path, mode=0o777, *, dir_fd=None):
        real_mkdir(path, mode, dir_fd=dir_fd)
        if path == "x":  # while c's own handles are closed (beyond the held levels)
            os.rename(src / "a" / "b", tmp_path / "b.moved")
            os.rename(other, src / "a" / "b")

    monkeypatch.setattr(safety.os, "mkdir", mkdir_then_swap)
    with pytest.raises(SafetyError, match="Folder changed while copying"):
        copy_tree_nofollow(src, tmp_path / "copy")
    monkeypatch.undo()
    assert not list((tmp_path / "copy").rglob("theirs.txt"))


def test_copy_source_subfolder_swapped_at_open_refused(tmp_path, src_tree, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "not-in-source.txt").write_bytes(b"outside the source")
    real_open = os.open
    done = []

    def hooked(path, flags, mode=0o777, *, dir_fd=None):
        if path == "pkg" and dir_fd is not None and flags & os.O_DIRECTORY and not done:
            done.append(path)
            os.rename(src_tree / "pkg", tmp_path / "pkg.moved")
            os.rename(elsewhere, src_tree / "pkg")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", hooked)
    with pytest.raises(SafetyError, match="Source folder changed while copying"):
        copy_tree_nofollow(src_tree, tmp_path / "copy")
    monkeypatch.undo()
    assert done
    assert not list((tmp_path / "copy").rglob("not-in-source.txt"))


# ------------------------------------------------------------------ exclusive creates


@pytest.mark.parametrize("where", ["new_file", "overwrite_temp", "copy_file"])
def test_exclusive_create_never_writes_into_planted_hard_link(case, monkeypatch, src_tree, where):
    real_open = os.open
    victim = case["victim"]
    planted = []

    def hooked(path, flags, mode=0o777, *, dir_fd=None):
        name = os.fspath(path)
        wanted = {
            "new_file": name == "new.txt",
            "overwrite_temp": name.startswith(safety._WRITE_TEMP_PREFIX),
            "copy_file": name == "README.md",
        }[where]
        if wanted and flags & os.O_CREAT and dir_fd is not None and not planted:
            planted.append(name)
            os.link(victim, name, dst_dir_fd=dir_fd)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", hooked)
    try:
        if where == "new_file":
            safe_write_bytes(case["root"], "new.txt", b"pwned")
        elif where == "overwrite_temp":
            safe_write_bytes(case["root"], "f.txt", b"pwned", overwrite=True)
        else:
            copy_tree_nofollow(src_tree, case["tmp"] / "copy")
    except SafetyError:
        pass
    monkeypatch.undo()
    assert planted
    assert victim.read_bytes() == OUTSIDE_BYTES


# ------------------------------------------------------------------ descriptors


def _fd_count() -> int:
    for folder in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(folder):
            return len(os.listdir(folder))
    pytest.fail("cannot count open descriptors here")


def test_no_descriptor_leak_after_many_writes_and_a_failing_copy(case, src_tree, monkeypatch):
    before = _fd_count()
    for i in range(2000):
        safe_write_bytes(case["root"], f"d{i % 7}/f.txt", b"x" * (i % 13), overwrite=True)
    safe_mkdirs(case["root"], "m/n/o")
    with safety.PinnedFolder(case["tmp"] / "pinned-new") as pinned:
        os.close(pinned.open_dir())
    real_open = os.open

    def deny(path, flags, mode=0o777, *, dir_fd=None):
        if path == "x.txt" and dir_fd is not None and not flags & os.O_CREAT:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safety.os, "open", deny)
    with pytest.raises(SafetyError, match="Could not read source file"):
        copy_tree_nofollow(src_tree, case["tmp"] / "copy")
    monkeypatch.undo()
    with pytest.raises(SafetyError):
        safe_write_bytes(case["root"], "d0/f.txt", b"y")  # refused: exists
    assert _fd_count() == before


def _deep_chain(top: Path, depth: int, *, create: bool):
    """Open (or create) top/d/d/.../d by handles; paths this deep are too long for some calls."""
    fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY)
    for level in range(depth):
        if create:
            os.mkdir("d", dir_fd=fd)
            if level == depth // 2:
                os.mkdir("side", dir_fd=fd)
                sfd = os.open("side", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                with open(os.open("s.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=sfd), "wb") as fh:
                    fh.write(b"side")
                os.close(sfd)
        child = os.open("d", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = child
    return fd


def _read_at(fd: int, *names: str) -> bytes:
    opened = []
    try:
        for name in names[:-1]:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened.append(fd)
        with open(os.open(names[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd), "rb") as fh:
            return fh.read()
    finally:
        for item in opened:
            os.close(item)


@pytest.mark.parametrize("depth", [200, 1000])
def test_deep_copy_fits_a_small_descriptor_budget(tmp_path, monkeypatch, depth):
    # A sibling folder half-way down makes the walk come back up and reopen closed levels.
    src = tmp_path / "src"
    src.mkdir()
    leaf_fd = _deep_chain(src, depth, create=True)
    with open(os.open("leaf.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=leaf_fd), "wb") as fh:
        fh.write(b"deep")
    os.close(leaf_fd)
    real_open = os.open
    peak = [0]

    def counting(path, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        peak[0] = max(peak[0], fd)
        return fd

    monkeypatch.setattr(safety.os, "open", counting)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, hard), hard))
    try:
        before = _fd_count()
        copy_tree_nofollow(src, tmp_path / "copy")
        after = _fd_count()
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    monkeypatch.undo()
    deep = _deep_chain(tmp_path / "copy", depth, create=False)
    try:
        assert _read_at(deep, "leaf.txt") == b"deep"
    finally:
        os.close(deep)
    half = _deep_chain(tmp_path / "copy", depth // 2, create=False)
    try:
        assert _read_at(half, "side", "s.txt") == b"side"
    finally:
        os.close(half)
    assert after == before
    # the highest descriptor number used stays far below the budget, however deep the tree
    assert peak[0] < before + 2 * (safety._COPY_HELD_LEVELS + 8), (peak[0], before)
    print(f"depth={depth} descriptors before={before} highest used={peak[0]}")


# ------------------------------------------------------------------ platform check


def test_no_dir_fd_support_refuses_before_creating_anything(tmp_path, src_tree, monkeypatch):
    monkeypatch.setattr(safety, "_DIR_FD_SUPPORTED", False)
    for call in (
        lambda: safe_write_bytes(tmp_path / "w", "a/f.txt", b"x"),
        lambda: safe_mkdirs(tmp_path / "m", "a"),
        lambda: copy_tree_nofollow(src_tree, tmp_path / "c"),
        lambda: safety.PinnedFolder(tmp_path / "p"),
        lambda: safety.safe_rename(tmp_path, "src", "moved"),
    ):
        with pytest.raises(SafetyError, match="cannot write files without following links"):
            call()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["src"]


# ------------------------------------------------------------------ safe_rename


def test_safe_rename_moves_within_root_and_refuses_links(case):
    (case["root"] / "a").mkdir()
    (case["root"] / "a" / "f.txt").write_bytes(b"f")
    safety.safe_rename(case["root"], "a/f.txt", "_archive/a/f.txt")
    assert (case["root"] / "_archive" / "a" / "f.txt").read_bytes() == b"f"
    (case["root"] / "b").symlink_to(case["outside"], target_is_directory=True)
    (case["root"] / "g.txt").write_bytes(b"g")
    with pytest.raises(SafetyError, match="symlink"):
        safety.safe_rename(case["root"], "g.txt", "b/g.txt")
    with pytest.raises(SafetyError, match="symlink"):
        safety.safe_rename(case["root"], "b/victim.txt", "stolen.txt")
    (case["root"] / "h.txt").write_bytes(b"h")
    with pytest.raises(SafetyError, match="existing name"):
        safety.safe_rename(case["root"], "h.txt", "g.txt")
    assert (case["root"] / "g.txt").read_bytes() == b"g"
    assert _listing(case["outside"]) == ["victim.txt"]
