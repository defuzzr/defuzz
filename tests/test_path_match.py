"""Unit tests for path_match.py."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_tools, path_match, tool_detect  # noqa: E402


@pytest.mark.parametrize(
    ("pattern", "rel_posix", "expected"),
    [
        ("Cargo.toml", "Cargo.toml", True),
        ("Cargo.toml", "sub/Cargo.toml", False),
        ("**/Cargo.toml", "Cargo.toml", True),
        ("**/Cargo.toml", "a/b/Cargo.toml", True),
        ("**/Cargo.toml", "a/b/Other.toml", False),
        ("**/*.py", "main.py", True),
        ("**/*.py", "pkg/sub/mod.py", True),
        ("**/*.py", "pkg/sub/mod.rs", False),
        ("**/foo/*.py", "foo/bar.py", True),
        ("**/foo/*.py", "a/b/foo/bar.py", True),
        ("**/foo/*.py", "a/b/bar/bar.py", False),
        (".github/workflows/*.yml", ".github/workflows/ci.yml", True),
        (".github/workflows/*.yml", "sub/.github/workflows/ci.yml", False),
        ("*.uproject", "Game.uproject", True),
        ("*.uproject", "nested/Game.uproject", False),
    ],
)
def test_glob_matches_path_table(pattern: str, rel_posix: str, expected: bool) -> None:
    assert path_match.glob_matches_path(pattern, rel_posix) is expected
    assert path_match._glob_matches_path(pattern, rel_posix) is expected
    assert lint_tools._glob_matches_path(pattern, rel_posix) is expected
    assert tool_detect._glob_matches_path(pattern, rel_posix) is expected


def test_scan_and_walk_project_files_skips_ignored_and_symlinks_and_bounds(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.rs").write_text("fn main() {}\n", encoding="utf-8")

    for ignored in (".git", "node_modules", "target", ".venv", "__pycache__", ".adopt", ".worktrees"):
        d = tmp_path / ignored
        d.mkdir()
        (d / "ignored.py").write_text("y = 2\n", encoding="utf-8")

    outside = tmp_path.parent / f"outside_{tmp_path.name}"
    outside.mkdir(exist_ok=True)
    try:
        (outside / "secret.py").write_text("z = 3\n", encoding="utf-8")
        os.symlink(str(outside), str(tmp_path / "sym_dir"))
        os.symlink(str(outside / "secret.py"), str(tmp_path / "sym_file.py"))

        res = path_match.scan(tmp_path)
        assert res == path_match.ScanResult(files=("a.py", "sub/b.rs"), truncated=False)
        assert path_match.walk_project_files(tmp_path) == ("a.py", "sub/b.rs")

        capped = path_match.scan(tmp_path, max_entries=1)
        assert capped == path_match.ScanResult(files=("a.py",), truncated=True)
        assert path_match.walk_project_files(tmp_path, max_entries=1) == ("a.py",)

        zero = path_match.scan(tmp_path, max_entries=0)
        assert zero == path_match.ScanResult(files=(), truncated=True)
        assert path_match.walk_project_files(tmp_path, max_entries=0) == ()

        missing = path_match.scan(tmp_path / "does_not_exist")
        assert missing == path_match.ScanResult(files=(), truncated=False)
    finally:
        if (outside / "secret.py").exists():
            (outside / "secret.py").unlink()
        if outside.exists():
            outside.rmdir()
