"""Path glob matching and bounded project directory walking helpers.

The walk skips IGNORED_DIRS by name. When the folder being walked is itself the top of a
Git repository, it also skips every untracked file and folder that the project's own
ignore rules exclude (build output, dependency folders), as listed by `git ls-files`.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

IGNORED_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "target", ".venv", "__pycache__", ".adopt",
    ".worktrees", ".import_linter_cache", ".rumdl_cache", ".pytest_cache",
    ".mypy_cache", ".ruff_cache",
    # Build output and check-runner caches written by template checks (dist/ from bundlers,
    # .xtask-cache/ from xtask runners); generated, git-ignored, never linted.
    "dist", ".xtask-cache",
})

MAX_DETECT_WALK_ENTRIES: int = 20000


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning project files up to max_entries visited filesystem entries."""

    files: Tuple[str, ...]
    truncated: bool


def glob_matches_path(pattern: str, rel_posix: str) -> bool:
    """Return True if a detect_glob pattern matches a relative posix file path."""
    if pattern.startswith("**/"):
        sub_pat = pattern[3:]
        if "/" not in sub_pat:
            return fnmatch.fnmatchcase(rel_posix.rsplit("/", 1)[-1], sub_pat)
        return fnmatch.fnmatchcase(rel_posix, sub_pat) or fnmatch.fnmatchcase(rel_posix, pattern)
    if "/" not in pattern and "/" in rel_posix:
        return False
    return fnmatch.fnmatchcase(rel_posix, pattern)


_glob_matches_path = glob_matches_path


def _git_ignored(base: Path) -> Tuple[frozenset[str], frozenset[str]]:
    """Untracked (folders, files) the project's own Git ignore rules exclude; empty if base is not a repository top."""
    empty: Tuple[frozenset[str], frozenset[str]] = (frozenset(), frozenset())
    if not os.path.lexists(base / ".git"):
        return empty
    try:
        from .safety import run_git_hardened

        proc = run_git_hardened(
            base,
            ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"],
            timeout=30,
        )
    except Exception:
        return empty
    if proc.returncode != 0:
        return empty
    dirs: set[str] = set()
    files: set[str] = set()
    for raw in (proc.stdout or b"").split(b"\0"):
        if not raw:
            continue
        text = os.fsdecode(raw)
        if text.endswith("/"):
            dirs.add(text.rstrip("/"))
        else:
            files.add(text)
    return frozenset(dirs), frozenset(files)


def scan(root: Path, max_entries: int = MAX_DETECT_WALK_ENTRIES) -> ScanResult:
    """Walk root deterministically skipping IGNORED_DIRS and Git-ignored paths, bounding visited dirs and files."""
    base = Path(root)
    if not base.exists() or not base.is_dir():
        return ScanResult(files=(), truncated=False)
    if max_entries <= 0:
        return ScanResult(files=(), truncated=True)
    ignored_dirs, ignored_files = _git_ignored(base)

    relpaths: List[str] = []
    visited = 0

    for dirpath, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        rel_dir = os.path.relpath(dirpath, base)
        rel_dir_posix = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        filtered_dirs = [
            d for d in sorted(dirnames)
            if d not in IGNORED_DIRS and not os.path.islink(os.path.join(dirpath, d))
            and (f"{rel_dir_posix}/{d}" if rel_dir_posix else d) not in ignored_dirs
        ]

        for fname in sorted(filenames):
            if os.path.islink(os.path.join(dirpath, fname)):
                continue
            if (f"{rel_dir_posix}/{fname}" if rel_dir_posix else fname) in ignored_files:
                continue
            if visited >= max_entries:
                dirnames[:] = []
                return ScanResult(files=tuple(relpaths), truncated=True)
            visited += 1
            relpaths.append(f"{rel_dir_posix}/{fname}" if rel_dir_posix else fname)

        kept_dirs: List[str] = []
        for d in filtered_dirs:
            if visited >= max_entries:
                dirnames[:] = []
                return ScanResult(files=tuple(relpaths), truncated=True)
            visited += 1
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

    return ScanResult(files=tuple(relpaths), truncated=False)


def walk_project_files(
    project_root: Path,
    max_entries: int = MAX_DETECT_WALK_ENTRIES,
) -> tuple[str, ...]:
    """Walk project_root deterministically skipping IGNORED_DIRS and symlinks, bounded by max_entries."""
    return scan(project_root, max_entries=max_entries).files


_walk_project_files = walk_project_files
