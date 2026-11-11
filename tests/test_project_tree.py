"""Read-only, bounded file-tree listing for explicitly opened projects.

The service is an audit surface, not a file browser for arbitrary folders: a folder
must be an active-profile registration, a safe root, and it is traversed with
descriptor-relative no-follow opens.  Nothing in this module reads file content.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from tests.conftest import load_submodule


def _register(folder: Path, name: str = "Registered") -> Path:
    store = load_submodule("state_store")
    store.record_project(
        folder,
        name,
        name.lower().replace(" ", "-"),
        "existing",
        {"building": "other", "layout": "single", "languages": []},
        None,
        db_path=store.state_db_path(),
    )
    return store.state_db_path()


def _snapshot(root: Path) -> dict[str, tuple]:
    """Every entry, its bytes and metadata; any read/write/touch is visible."""
    entries: dict[str, tuple] = {}
    for path in sorted([root, *root.rglob("*")]):
        st = os.lstat(path)
        relative = str(path.relative_to(root))
        if stat.S_ISREG(st.st_mode):
            entries[relative] = (
                "file", st.st_mode, st.st_size, st.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        elif stat.S_ISLNK(st.st_mode):
            entries[relative] = ("link", st.st_mode, os.readlink(path))
        else:
            entries[relative] = ("other", st.st_mode)
    return entries


def _write(root: Path, relative: str, data: str | bytes = "x") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


def test_registered_nonadopted_project_lists_real_files_without_mutation(tmp_path):
    tree = load_submodule("project_tree")
    root = tmp_path / "plain-project"
    root.mkdir()
    _write(root, "README.md", "# existing\n")
    _write(root, "src/main.py", "print('hello')\n")
    _write(root, "src/deep/util.ts", "export const x = 1;\n")
    _write(root, "assets/logo.bin", b"\x00\x01\x02")
    (root / "empty").mkdir()
    assert not (root / ".adopt").exists()

    db_path = _register(root)
    before_tree = _snapshot(root)
    before_db = db_path.read_bytes()

    result = tree.list_project_files(root)

    assert result == {
        "project": str(root.resolve()),
        "files": ["README.md", "assets/logo.bin", "src/deep/util.ts", "src/main.py"],
        "truncated": False,
        "coverage": "verified",
        "omitted": 0,
    }
    assert _snapshot(root) == before_tree
    assert db_path.read_bytes() == before_db


def test_symlinks_secret_paths_and_dependency_caches_are_omitted(tmp_path):
    tree = load_submodule("project_tree")
    root = tmp_path / "project-with-secrets"
    root.mkdir()
    _write(root, "visible.txt", "visible")
    _write(root, ".env", "TOKEN=do-not-leak")
    _write(root, "credentials.json", '{"token": "do-not-leak"}')
    _write(root, "secrets/token.txt", "do-not-leak")
    _write(root, ".git/config", "[core]")
    _write(root, "node_modules/pkg/index.js", "module.exports = 1;")
    _write(root, ".cache/blob.bin", b"cached")
    _write(root, "src/__pycache__/mod.pyc", b"bytecode")
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "secret.txt", "outside-secret")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "inside-link").symlink_to(root / "visible.txt")

    _register(root)
    before_outside = _snapshot(outside)

    result = tree.list_project_files(str(root))

    assert result["files"] == ["visible.txt"]
    assert result["truncated"] is False
    assert result["coverage"] == "verified"
    assert _snapshot(outside) == before_outside
    assert all("secret" not in name and "node_modules" not in name for name in result["files"])


def test_returned_and_scanned_bounds_are_visible(tmp_path):
    tree = load_submodule("project_tree")
    root = tmp_path / "many-files"
    root.mkdir()
    for index in range(5005):
        _write(root, f"f{index:05d}.txt")
    _register(root)

    result = tree.list_project_files(root)

    assert len(result["files"]) == tree.MAX_RETURNED
    assert result["files"] == sorted(result["files"])
    assert all((root / name).is_file() for name in result["files"])
    assert result["truncated"] is True
    assert result["omitted"] == 4000
    assert result["coverage"] == "verified"


def test_scandir_consumption_is_bounded_before_sorting(tmp_path, monkeypatch):
    tree = load_submodule("project_tree")
    root = tmp_path / "bounded-enumeration"
    root.mkdir()
    for index in range(20):
        _write(root, f"file-{index:02d}")
    _register(root)
    monkeypatch.setattr(tree, "MAX_SCANNED", 5)
    real_scandir = os.scandir
    consumed = []

    class CountingScan:
        def __init__(self, path):
            self.entries = real_scandir(path)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.entries.close()

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self.entries)
            consumed.append(entry.name)
            return entry

    monkeypatch.setattr(tree.os, "scandir", CountingScan)
    result = tree.list_project_files(root)
    assert len(consumed) <= 6  # budget plus one overflow sentinel
    assert len(result["files"]) == 5
    assert result["truncated"] is True
    assert result["coverage"] == "verified"


def test_non_utf8_names_are_omitted_with_partial_coverage(tmp_path):
    import json

    tree = load_submodule("project_tree")
    root = tmp_path / "non-utf8"
    root.mkdir()
    _write(root, "visible.txt")
    bad_directory = os.fsencode(root) + b"/bad-\xff"
    os.mkdir(bad_directory)
    with open(bad_directory + b"/hidden.txt", "wb") as handle:
        handle.write(b"x")
    with open(os.fsencode(root) + b"/bad-\xfe.txt", "wb") as handle:
        handle.write(b"x")
    _register(root)

    result = tree.list_project_files(root)

    assert result["files"] == ["visible.txt"]
    assert result["coverage"] == "could_not_verify"
    assert result["truncated"] is True
    json.dumps(result, ensure_ascii=False).encode("utf-8")


def test_root_swapped_after_validation_is_not_traversed(tmp_path, monkeypatch):
    from contextlib import contextmanager

    tree = load_submodule("project_tree")
    root = tmp_path / "swap-root"
    root.mkdir()
    _write(root, "original.txt")
    _register(root)
    real_open = tree._open_root_dir_fd

    @contextmanager
    def swapped_open(path):
        root.rename(tmp_path / "original-root")
        root.mkdir()
        _write(root, "replacement.txt")
        with real_open(path) as opened:
            yield opened

    monkeypatch.setattr(tree, "_open_root_dir_fd", swapped_open)
    result = tree.list_project_files(root)

    assert result["files"] == []
    assert result["coverage"] == "could_not_verify"
    assert result["truncated"] is True


def test_depth_bound_is_enforced_and_reported(tmp_path):
    tree = load_submodule("project_tree")
    root = tmp_path / "deep"
    root.mkdir()
    current = root
    for index in range(11):
        current = current / f"d{index}"
        current.mkdir()
    # 11 directories + a file = depth 12, inside the bound.
    _write(current, "at-depth-12.txt")
    # A directory at depth 12 would put its children at depth 13.
    deeper = current / "d11"
    deeper.mkdir()
    _write(deeper, "at-depth-13.txt")

    _register(root)
    result = tree.list_project_files(root)

    assert "d0/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/at-depth-12.txt" in result["files"]
    assert not any(name.endswith("at-depth-13.txt") for name in result["files"])
    assert result["truncated"] is True
    assert result["coverage"] == "verified"


def test_unregistered_and_active_profile_roots_are_denied(tmp_path):
    tree = load_submodule("project_tree")
    safety = load_submodule("safety")

    unregistered = tmp_path / "not-registered"
    unregistered.mkdir()
    _write(unregistered, "file.txt")
    with pytest.raises(safety.SafetyError, match="not registered"):
        tree.list_project_files(unregistered)

    inside_hermes = Path(os.environ["HERMES_HOME"]) / "inside-project"
    inside_hermes.mkdir(parents=True)
    _write(inside_hermes, "file.txt")
    _register(inside_hermes)
    with pytest.raises(safety.SafetyError):
        tree.list_project_files(inside_hermes)


def test_registry_must_be_verified_and_unchanged(tmp_path, monkeypatch):
    tree = load_submodule("project_tree")
    safety = load_submodule("safety")
    root = tmp_path / "registered"
    root.mkdir()
    _write(root, "file.txt")
    _register(root)

    readonly = load_submodule("audit.readonly_db")
    from hermes_constants import get_hermes_home

    snapshot = readonly.read_profile_registrations_readonly("active", get_hermes_home())
    assert snapshot.coverage == "verified"

    class Snapshot:
        def __init__(self, coverage, changed):
            self.coverage = coverage
            self.changed_during_read = changed
            self.records = snapshot.records

    for bad in (Snapshot("could_not_verify", False), Snapshot("verified", True)):
        monkeypatch.setattr(tree, "read_profile_registrations_readonly", lambda *a, _s=bad: _s)
        with pytest.raises(safety.SafetyError, match="could not be verified"):
            tree.list_project_files(root)


@pytest.mark.parametrize("maker", [
    lambda tmp: "relative/not-absolute",
    lambda tmp: "",
    lambda tmp: str(tmp / "missing-root"),
    lambda tmp: str(tmp / "not-a-directory"),
    lambda tmp: str(tmp / "nul\x00root"),
])
def test_malformed_roots_are_refused(tmp_path, maker):
    tree = load_submodule("project_tree")
    safety = load_submodule("safety")
    (tmp_path / "not-a-directory").write_text("plain file", encoding="utf-8")

    with pytest.raises(safety.SafetyError):
        tree.list_project_files(maker(tmp_path))


def test_symlink_root_is_refused_even_when_target_is_registered(tmp_path):
    tree = load_submodule("project_tree")
    safety = load_submodule("safety")
    root = tmp_path / "real-root"
    root.mkdir()
    _write(root, "file.txt")
    _register(root)
    alias = tmp_path / "alias-root"
    alias.symlink_to(root, target_is_directory=True)

    with pytest.raises(safety.SafetyError):
        tree.list_project_files(alias)


@pytest.mark.skipif(os.geteuid() == 0 if hasattr(os, "geteuid") else False,
                    reason="permission bits do not deny root")
def test_unreadable_subtree_is_not_a_silent_empty_success(tmp_path):
    tree = load_submodule("project_tree")
    root = tmp_path / "blocked"
    root.mkdir()
    _write(root, "visible.txt")
    blocked = root / "private"
    blocked.mkdir()
    _write(blocked, "hidden.txt")
    _register(root)

    os.chmod(blocked, 0o000)
    try:
        result = tree.list_project_files(root)
    finally:
        os.chmod(blocked, 0o700)

    assert result["coverage"] == "could_not_verify"
    assert result["truncated"] is True
    assert "visible.txt" in result["files"]
