"""Workspace discovery, prefix form derivation, and marker-anchored file edits."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

PREFIX: str = "tmpl_prefix"

LAYER_ORDER: Mapping[str, int] = {
    "foundation": 0,
    "domain": 1,
    "adapters": 2,
    "apps": 3,
}

SNAKE_PREFIX_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")


@dataclass(frozen=True, slots=True)
class PrefixForms:
    """Four canonical case forms derived from a snake_case workspace prefix."""

    kebab: str
    snake: str
    screaming: str
    pascal: str


@dataclass(frozen=True, slots=True)
class PackageInfo:
    """Parsed metadata for a single workspace package under packages/<layer>/."""

    layer: str
    layer_index: int
    dist_name: str
    mod_name: str
    path: Path
    dependencies: tuple[str, ...]
    optional_dependencies: tuple[str, ...]
    dependency_groups: tuple[str, ...]
    uv_sources: tuple[str, ...]


def derive_forms(snake_prefix: str) -> PrefixForms:
    """Derive kebab, snake, SCREAMING, and Pascal forms from a snake_case prefix."""
    if not SNAKE_PREFIX_RE.fullmatch(snake_prefix):
        msg = f"Invalid prefix '{snake_prefix}': must match [a-z][a-z0-9]*(_[a-z0-9]+)*"
        raise ValueError(msg)
    parts = snake_prefix.split("_")
    return PrefixForms(
        kebab="-".join(parts),
        snake=snake_prefix,
        screaming=snake_prefix.upper(),
        pascal="".join(part.capitalize() for part in parts),
    )


def find_workspace_root(start: Path | None = None) -> Path:
    """Locate the workspace root containing pyproject.toml with [tool.uv.workspace]."""
    current = (start if start is not None else Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file():
            data = load_toml(pyproject)
            tool = data.get("tool")
            if isinstance(tool, dict) and isinstance(tool.get("uv"), dict):
                uv_cfg = tool["uv"]
                if "workspace" in uv_cfg:
                    return candidate
    msg = f"Could not locate uv workspace root from '{current}'"
    raise RuntimeError(msg)


def load_toml(path: Path) -> dict[str, object]:
    """Parse a TOML file using standard-library tomllib."""
    with path.open("rb") as handle:
        return tomllib.load(handle)


def extract_requirement_name(spec: str) -> str:
    """Extract the normalized package name from a PEP 508 dependency specifier."""
    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    if match is None:
        return spec.strip().lower()
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def discover_packages(root: Path, prefix: str = PREFIX) -> list[PackageInfo]:
    """Discover all workspace packages under packages/<layer>/<pkg>."""
    forms = derive_forms(prefix)
    packages_dir = root / "packages"
    discovered: list[PackageInfo] = []
    if not packages_dir.is_dir():
        return discovered

    for layer_dir in sorted(packages_dir.iterdir()):
        if not layer_dir.is_dir() or layer_dir.name == "tests":
            continue
        layer_name = layer_dir.name
        layer_idx = LAYER_ORDER.get(layer_name, -1)
        for pkg_dir in sorted(layer_dir.iterdir()):
            pyproject_path = pkg_dir / "pyproject.toml"
            if not pkg_dir.is_dir() or not pyproject_path.is_file():
                continue
            data = load_toml(pyproject_path)
            project = data.get("project")
            dist_name = (
                str(project.get("name", pkg_dir.name))
                if isinstance(project, dict)
                else pkg_dir.name
            )
            mod_name = dist_name.replace("-", "_")

            deps, opt_deps, dep_groups, sources = _package_dependencies(data, project)

            _ = forms
            discovered.append(
                PackageInfo(
                    layer=layer_name,
                    layer_index=layer_idx,
                    dist_name=dist_name,
                    mod_name=mod_name,
                    path=pkg_dir,
                    dependencies=tuple(deps),
                    optional_dependencies=tuple(opt_deps),
                    dependency_groups=tuple(dep_groups),
                    uv_sources=tuple(sources),
                ),
            )
    return discovered


def insert_above_marker(text: str, marker: str, new_line: str) -> str:
    """Insert a line immediately above a marker comment, preserving indentation."""
    lines = text.splitlines(keepends=True)
    result: list[str] = []
    inserted = False
    for line in lines:
        stripped = line.strip()
        if stripped == marker:
            indent_len = len(line) - len(line.lstrip(" "))
            indent = " " * indent_len
            candidate = f"{indent}{new_line.strip()}\n"
            block_lines: list[str] = []
            for prev in reversed(result):
                prev_s = prev.strip()
                if not prev_s or prev_s.endswith("[") or prev_s.startswith("["):
                    break
                block_lines.append(prev)
            if candidate not in block_lines:
                result.append(candidate)
            inserted = True
        result.append(line)
    if not inserted:
        msg = f"Required marker '{marker}' not found"
        raise RuntimeError(msg)
    return "".join(result)


def sort_lines_above_marker(text: str, marker: str) -> str:
    """Insert or sort contiguous list items or imports immediately above a marker."""
    lines = text.splitlines(keepends=True)
    marker_idx = -1
    for idx, line in enumerate(lines):
        if line.strip() == marker:
            marker_idx = idx
            break
    if marker_idx == -1:
        msg = f"Required marker '{marker}' not found"
        raise RuntimeError(msg)

    start_idx = marker_idx
    while start_idx > 0:
        prev = lines[start_idx - 1].strip()
        if not prev or prev.endswith("[") or prev.startswith(("#", "[")):
            break
        start_idx -= 1

    block = lines[start_idx:marker_idx]
    sorted_block = sorted(set(block), key=lambda s: s.strip())
    return "".join(lines[:start_idx] + sorted_block + lines[marker_idx:])


def _package_dependencies(
    data: dict[str, object],
    project: object,
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Read dependency lists and workspace sources from one manifest."""
    deps: list[str] = []
    opt_deps: list[str] = []
    if isinstance(project, dict):
        raw_deps = project.get("dependencies", [])
        if isinstance(raw_deps, list):
            deps = [str(item) for item in raw_deps]
        raw_opt = project.get("optional-dependencies", {})
        if isinstance(raw_opt, dict):
            for group_items in raw_opt.values():
                if isinstance(group_items, list):
                    opt_deps.extend(str(item) for item in group_items)

    dep_groups: list[str] = []
    raw_groups = data.get("dependency-groups", {})
    if isinstance(raw_groups, dict):
        for group_items in raw_groups.values():
            if isinstance(group_items, list):
                dep_groups.extend(str(item) for item in group_items if isinstance(item, str))

    sources = _workspace_sources(data)
    return deps, opt_deps, dep_groups, sources


def _workspace_sources(data: dict[str, object]) -> list[str]:
    """Return manifest source names explicitly marked as workspace packages."""
    sources: list[str] = []
    tool_tbl = data.get("tool")
    if isinstance(tool_tbl, dict):
        uv_tbl = tool_tbl.get("uv")
        if isinstance(uv_tbl, dict):
            src_tbl = uv_tbl.get("sources")
            if isinstance(src_tbl, dict):
                for src_key, src_val in src_tbl.items():
                    if isinstance(src_val, dict) and src_val.get("workspace") is True:
                        sources.append(str(src_key))

    return sources
