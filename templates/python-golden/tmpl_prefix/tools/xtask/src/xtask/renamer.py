"""Context-aware workspace prefix renamer supporting single-word round-trips."""

from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING, Literal

import xtask.workspace as ws_mod
from xtask.process import run_command
from xtask.workspace import PrefixForms, derive_forms

if TYPE_CHECKING:
    from pathlib import Path

_EXCLUDED_DIRS: set[str] = {
    ".git",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "build",
}


def replace_prefix_in_text(
    text: str,
    src: PrefixForms,
    dst: PrefixForms,
    *,
    bare_mode: Literal["kebab", "snake"],
) -> str:
    """Context-aware replacement of all four prefix forms in text.

    Rules applied in order:
    1. ``<kebab>-`` -> ``dst.kebab + "-"``
    2. ``<snake>_`` -> ``dst.snake + "_"``
    3. ``<SCREAMING>_`` -> ``dst.screaming + "_"``
    4. ``<Pascal>(?=[A-Z])`` -> ``dst.pascal``
    5. Distinct non-colliding forms (screaming, pascal, or multi-word kebab/snake)
    6. Bare occurrence when ``src.kebab == src.snake`` resolved via ``bare_mode``
    """
    if not text or src == dst:
        return text

    branches: list[str] = [
        f"(?P<kebab_sep>{re.escape(src.kebab)}-)",
        f"(?P<snake_sep>{re.escape(src.snake)}_)",
        f"(?P<scream_sep>{re.escape(src.screaming)}_)",
        f"(?P<pascal_sep>{re.escape(src.pascal)})(?=[A-Z])",
        f"(?P<scream_bare>\\b{re.escape(src.screaming)}\\b)",
        f"(?P<pascal_bare>\\b{re.escape(src.pascal)}\\b)",
    ]
    if src.kebab != src.snake:
        branches.append(f"(?P<kebab_exact>{re.escape(src.kebab)})")
        branches.append(f"(?P<snake_exact>{re.escape(src.snake)})")
    else:
        branches.append(
            f"(?<![A-Za-z0-9_-])(?P<bare>{re.escape(src.kebab)})(?![A-Za-z0-9_-])",
        )

    master_re = re.compile("|".join(branches))

    replacements = {
        "kebab_sep": f"{dst.kebab}-",
        "snake_sep": f"{dst.snake}_",
        "scream_sep": f"{dst.screaming}_",
        "pascal_sep": dst.pascal,
        "pascal_bare": dst.pascal,
        "scream_bare": dst.screaming,
        "kebab_exact": dst.kebab,
        "snake_exact": dst.snake,
    }

    def _sub(match: re.Match[str]) -> str:
        return replacements.get(
            match.lastgroup or "",
            dst.kebab if bare_mode == "kebab" else dst.snake,
        )

    return master_re.sub(_sub, text)


def _bare_mode_for_file(path: Path) -> Literal["kebab", "snake"] | None:
    """Return the bare-token resolution mode for a given file, or None if skipped."""
    name = path.name
    if name.endswith((".py", ".py.tmpl")):
        return "snake"
    if name.endswith((".toml", ".toml.tmpl", ".md", ".yml", ".yaml")) or name in (
        ".env.example",
        "uv.lock",
        "CODEOWNERS",
        ".gitignore",
        ".worktreeinclude",
    ):
        return "kebab"
    return None


def _iter_workspace_files(root: Path) -> list[Path]:
    """Collect all editable workspace files excluding build/cache directories."""
    collected: list[Path] = []

    def _walk(directory: Path) -> None:
        for entry in sorted(directory.iterdir()):
            if entry.name in _EXCLUDED_DIRS or entry.name.endswith(".egg-info"):
                continue
            if entry.is_dir():
                _walk(entry)
            elif entry.is_file():
                collected.append(entry)

    _walk(root)
    return collected


def _rename_directories(root: Path, src: PrefixForms, dst: PrefixForms) -> None:
    """Rename package directories (kebab) and src module directories (snake)."""
    packages_root = root / "packages"
    if not packages_root.is_dir():
        return

    for layer_dir in sorted(packages_root.iterdir()):
        if not layer_dir.is_dir():
            continue
        for pkg_dir in sorted(layer_dir.iterdir()):
            if not pkg_dir.is_dir():
                continue
            _rename_modules(pkg_dir, src, dst)

            new_pkg_name = replace_prefix_in_text(
                pkg_dir.name,
                src,
                dst,
                bare_mode="kebab",
            )
            if new_pkg_name != pkg_dir.name:
                pkg_dir.rename(layer_dir / new_pkg_name)


def _read_current_prefix(root: Path) -> str:
    """Read the current PREFIX constant from tools/xtask/src/xtask/workspace.py."""
    ws_file = root / "tools" / "xtask" / "src" / "xtask" / "workspace.py"
    content = ws_file.read_text(encoding="utf-8")
    match = re.search(r'^PREFIX:\s*str\s*=\s*"([^"]+)"', content, flags=re.MULTILINE)
    if match is None:
        return ws_mod.PREFIX
    return match.group(1)


def rename_workspace(root: Path, new_prefix: str) -> PrefixForms:
    """Rename all four prefix forms across files, directories, and lockfile."""
    dst = derive_forms(new_prefix)
    current_prefix = _read_current_prefix(root)
    src = derive_forms(current_prefix)

    if src != dst:
        for file_path in _iter_workspace_files(root):
            mode = _bare_mode_for_file(file_path)
            if mode is None:
                continue
            original = file_path.read_text(encoding="utf-8")
            updated = replace_prefix_in_text(original, src, dst, bare_mode=mode)
            if updated != original:
                file_path.write_text(updated, encoding="utf-8")

        _rename_directories(root, src, dst)

        # Clean stale egg-info directories under packages/ if any exist.
        for egg_info in (root / "packages").rglob("*.egg-info"):
            if egg_info.is_dir():
                shutil.rmtree(egg_info)

    ws_mod.PREFIX = dst.snake
    run_command(["uv", "sync"], cwd=root, check=True)
    return dst


def _rename_modules(pkg_dir: Path, src: PrefixForms, dst: PrefixForms) -> None:
    """Rename source modules within one package before renaming the package."""
    src_parent = pkg_dir / "src"
    if src_parent.is_dir():
        for mod_dir in sorted(src_parent.iterdir()):
            if mod_dir.is_dir():
                new_mod_name = replace_prefix_in_text(
                    mod_dir.name,
                    src,
                    dst,
                    bare_mode="snake",
                )
                if new_mod_name != mod_dir.name:
                    mod_dir.rename(src_parent / new_mod_name)
