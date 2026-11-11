"""Architectural boundary, manifest, catalogue, and AST source-import checker."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from xtask.process import run_command
from xtask.workspace import (
    LAYER_ORDER,
    PREFIX,
    PackageInfo,
    derive_forms,
    discover_packages,
    extract_requirement_name,
    load_toml,
)

if TYPE_CHECKING:
    from pathlib import Path

_DEV_IMPORT_ALIASES: dict[str, str] = {
    "import-linter": "importlinter",
    "pip-audit": "pip_audit",
    "pytest-asyncio": "pytest_asyncio",
}


def _load_catalogue(root_data: dict[str, object]) -> dict[str, str]:
    """Parse [tool.uv].constraint-dependencies into {normalized_name: exact_spec}."""
    catalogue: dict[str, str] = {}
    tool = root_data.get("tool")
    if not isinstance(tool, dict):
        return catalogue
    uv_tbl = tool.get("uv")
    if not isinstance(uv_tbl, dict):
        return catalogue
    constraints = uv_tbl.get("constraint-dependencies", [])
    if not isinstance(constraints, list):
        return catalogue
    for entry in constraints:
        if isinstance(entry, str):
            norm = extract_requirement_name(entry)
            catalogue[norm] = entry.strip()
    return catalogue


def _load_dev_modules(root_data: dict[str, object]) -> set[str]:
    """Return top-level module names corresponding to [dependency-groups].dev."""
    dev_modules: set[str] = set()
    groups = root_data.get("dependency-groups")
    if not isinstance(groups, dict):
        return dev_modules
    dev_list = groups.get("dev", [])
    if not isinstance(dev_list, list):
        return dev_modules
    for spec in dev_list:
        if isinstance(spec, str):
            dist = extract_requirement_name(spec)
            dev_modules.add(dist.replace("-", "_"))
            if dist in _DEV_IMPORT_ALIASES:
                dev_modules.add(_DEV_IMPORT_ALIASES[dist])
    return dev_modules


def _check_package_structure_and_root_config(
    root: Path,
    packages: list[PackageInfo],
    root_data: dict[str, object],
    prefix: str,
) -> list[str]:
    """Verify naming, src/ layout, py.typed, and root tool registrations."""
    errors: list[str] = []
    tool = root_data.get("tool")
    if not isinstance(tool, dict):
        tool = {}

    ruff_tbl = tool.get("ruff", {})
    lint_tbl = ruff_tbl.get("lint", {}) if isinstance(ruff_tbl, dict) else {}
    isort_tbl = lint_tbl.get("isort", {}) if isinstance(lint_tbl, dict) else {}
    known_first_party = set(
        isort_tbl.get("known-first-party", []) if isinstance(isort_tbl, dict) else [],
    )

    mypy_tbl = tool.get("mypy", {})
    mypy_paths = set(
        mypy_tbl.get("mypy_path", []) if isinstance(mypy_tbl, dict) else [],
    )

    il_tbl = tool.get("importlinter", {})
    root_packages = set(
        il_tbl.get("root_packages", []) if isinstance(il_tbl, dict) else [],
    )
    contracts = il_tbl.get("contracts", []) if isinstance(il_tbl, dict) else []
    layer_lines: list[str] = []
    if isinstance(contracts, list):
        for contract in contracts:
            if isinstance(contract, dict) and contract.get("type") == "layers":
                raw_layers = contract.get("layers", [])
                if isinstance(raw_layers, list):
                    layer_lines = [str(line) for line in raw_layers]

    for pkg in packages:
        errors.extend(
            _check_package_registration(
                root=root,
                pkg=pkg,
                prefix=prefix,
                known_first_party=known_first_party,
                mypy_paths=mypy_paths,
                root_packages=root_packages,
                layer_lines=layer_lines,
            )
        )
    return errors


def _check_package_registration(
    *,
    root: Path,
    pkg: PackageInfo,
    prefix: str,
    known_first_party: set[str],
    mypy_paths: set[str],
    root_packages: set[str],
    layer_lines: list[str],
) -> list[str]:
    """Verify one package layout and its registrations in root tooling."""
    errors: list[str] = []
    errors.extend(_check_package_names(pkg, prefix))

    src_mod_dir = pkg.path / "src" / pkg.mod_name
    errors.extend(
        f"{pkg.dist_name}: missing src/{pkg.mod_name}/{filename}"
        for filename in ("__init__.py", "py.typed")
        if not (src_mod_dir / filename).is_file()
    )

    if pkg.mod_name not in known_first_party:
        errors.append(
            f"{pkg.dist_name}: '{pkg.mod_name}' missing from "
            f"[tool.ruff.lint.isort].known-first-party",
        )
    rel_src = pkg.path.relative_to(root).as_posix() + "/src"
    if rel_src not in mypy_paths:
        errors.append(
            f"{pkg.dist_name}: '{rel_src}' missing from [tool.mypy].mypy_path",
        )
    if pkg.mod_name not in root_packages:
        errors.append(
            f"{pkg.dist_name}: '{pkg.mod_name}' missing from [tool.importlinter].root_packages",
        )

    matching_lines = [
        line
        for line in layer_lines
        if pkg.mod_name in [tok.strip() for tok in line.replace("|", ":").split(":")]
    ]
    if len(matching_lines) != 1:
        errors.append(
            f"{pkg.dist_name}: '{pkg.mod_name}' must appear in exactly 1 "
            f"import-linter layer line (found {len(matching_lines)})",
        )

    return errors


def _check_manifest_dependencies_and_catalogue(
    packages: list[PackageInfo],
    catalogue: dict[str, str],
) -> list[str]:
    """Verify manifest layer direction, acyclicity, workspace sources, and catalogue specs."""
    errors: list[str] = []
    by_dist: dict[str, PackageInfo] = {pkg.dist_name: pkg for pkg in packages}
    adj: dict[str, list[str]] = {pkg.dist_name: [] for pkg in packages}

    for pkg in packages:
        uv_source_set = set(pkg.uv_sources)

        for spec in (*pkg.dependencies, *pkg.optional_dependencies):
            dep_name = extract_requirement_name(spec)
            if dep_name in by_dist:
                target = by_dist[dep_name]
                adj[pkg.dist_name].append(target.dist_name)
                errors.extend(_check_internal_dependency(pkg, target, spec, uv_source_set))
            else:
                expected_spec = catalogue.get(dep_name)
                if expected_spec is None:
                    errors.append(
                        f"{pkg.dist_name}: third-party dependency '{spec}' is not in "
                        f"the approved workspace catalogue",
                    )
                elif spec.strip() != expected_spec:
                    errors.append(
                        f"{pkg.dist_name}: dependency spec '{spec}' does not match "
                        f"catalogue entry '{expected_spec}'",
                    )

        for group_spec in pkg.dependency_groups:
            dep_name = extract_requirement_name(group_spec)
            if dep_name in by_dist:
                adj[pkg.dist_name].append(by_dist[dep_name].dist_name)

    errors.extend(_detect_cycles(adj))
    return errors


def _detect_cycles(adj: dict[str, list[str]]) -> list[str]:
    """Detect cycles in the internal package dependency graph via DFS."""
    errors: list[str] = []
    state: dict[str, int] = dict.fromkeys(adj, 0)
    stack: list[str] = []

    def _dfs(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for neighbor in adj.get(node, []):
            if state.get(neighbor, 0) == 1:
                idx = stack.index(neighbor)
                cycle_path = " -> ".join([*stack[idx:], neighbor])
                errors.append(f"Dependency cycle detected: {cycle_path}")
            elif state.get(neighbor, 0) == 0:
                _dfs(neighbor)
        stack.pop()
        state[node] = 2

    for pkg_name in sorted(adj):
        if state[pkg_name] == 0:
            _dfs(pkg_name)
    return errors


def _scan_source_imports(
    root: Path,
    packages: list[PackageInfo],
    dev_modules: set[str],
    prefix: str,
) -> list[str]:
    """Scan every src/**/*.py via AST for undeclared, dev-only, or upward imports."""
    errors: list[str] = []
    forms = derive_forms(prefix)
    by_mod: dict[str, PackageInfo] = {pkg.mod_name: pkg for pkg in packages}

    for pkg in packages:
        src_root = pkg.path / "src" / pkg.mod_name
        if not src_root.is_dir():
            continue
        declared_internal_mods = {
            extract_requirement_name(spec).replace("-", "_")
            for spec in pkg.dependencies
            if extract_requirement_name(spec).startswith(f"{forms.kebab}-")
        }

        for py_file in sorted(src_root.rglob("*.py")):
            rel_file = py_file.relative_to(root).as_posix()
            rel_inside_pkg = py_file.relative_to(src_root)
            pkg_depth = len(rel_inside_pkg.parts)

            source_text = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=rel_file)

            errors.extend(
                _check_import_tree(
                    tree=tree,
                    pkg_depth=pkg_depth,
                    rel_file=rel_file,
                    pkg=pkg,
                    dev_modules=dev_modules,
                    prefix=prefix,
                    by_mod=by_mod,
                    declared_internal_mods=declared_internal_mods,
                )
            )

    return errors


def _check_uv_lock(root: Path) -> list[str]:
    """Run uv lock --check to verify uv.lock is synchronized with manifests."""
    proc = run_command(
        ["uv", "lock", "--check"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        return [f"uv.lock is out of date (uv lock --check failed): {detail}"]
    return []


def run_check(root: Path, prefix: str = PREFIX) -> list[str]:
    """Execute all architectural, manifest, AST import, and lockfile checks."""
    root_data = load_toml(root / "pyproject.toml")
    packages = discover_packages(root, prefix=prefix)
    catalogue = _load_catalogue(root_data)
    dev_modules = _load_dev_modules(root_data)

    errors: list[str] = []
    errors.extend(
        _check_package_structure_and_root_config(root, packages, root_data, prefix),
    )
    errors.extend(_check_manifest_dependencies_and_catalogue(packages, catalogue))
    errors.extend(_scan_source_imports(root, packages, dev_modules, prefix))
    errors.extend(_check_uv_lock(root))
    return errors


def format_graph(root: Path, prefix: str = PREFIX) -> str:
    """Format the workspace package dependency graph grouped by architectural layer."""
    packages = discover_packages(root, prefix=prefix)
    by_dist = {pkg.dist_name for pkg in packages}
    lines: list[str] = ["Workspace Dependency Graph:"]

    ordered_layers = sorted(LAYER_ORDER.items(), key=lambda item: item[1])
    for layer_name, layer_idx in ordered_layers:
        lines.append(f"\n  Layer {layer_idx} ({layer_name}):")
        layer_pkgs = [pkg for pkg in packages if pkg.layer == layer_name]
        for pkg in layer_pkgs:
            internal_deps = sorted(
                extract_requirement_name(spec)
                for spec in pkg.dependencies
                if extract_requirement_name(spec) in by_dist
            )
            deps_str = ", ".join(internal_deps) if internal_deps else "(none)"
            lines.append(f"    - {pkg.dist_name} ({pkg.mod_name}) -> {deps_str}")

    return "\n".join(lines) + "\n"


def _check_internal_dependency(
    pkg: PackageInfo,
    target: PackageInfo,
    spec: str,
    uv_source_set: set[str],
) -> list[str]:
    """Validate one declared internal dependency and its layer direction."""
    errors: list[str] = []
    if spec.strip() != target.dist_name:
        errors.append(
            f"{pkg.dist_name}: internal dependency '{spec}' must be bare name '{target.dist_name}'",
        )
    if target.dist_name not in uv_source_set:
        errors.append(
            f"{pkg.dist_name}: internal dependency '{target.dist_name}' missing "
            f"'{{ workspace = true }}' in [tool.uv.sources]",
        )
    if target.layer_index > pkg.layer_index:
        errors.append(
            f"{pkg.dist_name} ({pkg.layer}) cannot depend on higher layer "
            f"{target.dist_name} ({target.layer})",
        )
    elif pkg.layer == "apps" and target.layer == "apps":
        errors.append(
            f"{pkg.dist_name} (apps) cannot depend on sibling app {target.dist_name} (apps)",
        )
    return errors


def _check_import_tree(
    *,
    tree: ast.AST,
    pkg_depth: int,
    rel_file: str,
    pkg: PackageInfo,
    dev_modules: set[str],
    prefix: str,
    by_mod: dict[str, PackageInfo],
    declared_internal_mods: set[str],
) -> list[str]:
    """Check import nodes from one source file."""
    errors: list[str] = []
    for node in ast.walk(tree):
        imported_tops: list[str] = []
        if isinstance(node, ast.Import):
            imported_tops.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0 and node.level > pkg_depth:
                errors.append(
                    f"{rel_file}:{node.lineno} ({pkg.dist_name}): relative import "
                    f"escapes package root",
                )
                continue
            if node.level == 0 and node.module:
                imported_tops.append(node.module.split(".")[0])

        errors.extend(
            _check_imported_modules(
                imported_tops=imported_tops,
                node=node,
                rel_file=rel_file,
                pkg=pkg,
                dev_modules=dev_modules,
                prefix=prefix,
                by_mod=by_mod,
                declared_internal_mods=declared_internal_mods,
            )
        )

    return errors


def _check_imported_modules(
    *,
    imported_tops: list[str],
    node: ast.AST,
    rel_file: str,
    pkg: PackageInfo,
    dev_modules: set[str],
    prefix: str,
    by_mod: dict[str, PackageInfo],
    declared_internal_mods: set[str],
) -> list[str]:
    """Check source import declarations and architectural boundaries."""
    errors: list[str] = []
    forms = derive_forms(prefix)
    for top_mod in imported_tops:
        if top_mod == pkg.mod_name:
            continue
        if top_mod in dev_modules:
            errors.append(
                f"{rel_file}:{getattr(node, 'lineno', 1)} ({pkg.dist_name}): "
                f"production src/ cannot import dev-only package '{top_mod}'",
            )
            continue
        if top_mod.startswith(f"{forms.snake}_"):
            target_pkg = by_mod.get(top_mod)
            if target_pkg is None:
                errors.append(
                    f"{rel_file}:{getattr(node, 'lineno', 1)} ({pkg.dist_name}): "
                    f"imports unknown internal module '{top_mod}'",
                )
                continue
            if target_pkg.layer_index > pkg.layer_index:
                errors.append(
                    f"{rel_file}:{getattr(node, 'lineno', 1)} ({pkg.dist_name}): "
                    f"upward import of '{top_mod}' ({target_pkg.layer}) from {pkg.layer}",
                )
            elif pkg.layer == "apps" and target_pkg.layer == "apps":
                errors.append(
                    f"{rel_file}:{getattr(node, 'lineno', 1)} ({pkg.dist_name}): app "
                    f"cannot import sibling app '{top_mod}'",
                )
            if top_mod not in declared_internal_mods:
                errors.append(
                    f"{rel_file}:{getattr(node, 'lineno', 1)} ({pkg.dist_name}): "
                    f"imports '{top_mod}' without declaring '{target_pkg.dist_name}' "
                    f"in dependencies",
                )

    return errors


def _check_package_names(pkg: PackageInfo, prefix: str) -> list[str]:
    """Validate the directory, distribution, module and layer names."""
    errors: list[str] = []
    forms = derive_forms(prefix)
    if pkg.layer_index < 0:
        errors.append(f"{pkg.dist_name}: invalid layer directory '{pkg.layer}'")
    if pkg.path.name != pkg.dist_name:
        errors.append(
            f"{pkg.dist_name}: directory '{pkg.path.name}' != distribution '{pkg.dist_name}'",
        )
    if not pkg.dist_name.startswith(f"{forms.kebab}-"):
        errors.append(
            f"{pkg.dist_name}: distribution must start with '{forms.kebab}-'",
        )
    expected_mod = pkg.dist_name.replace("-", "_")
    if pkg.mod_name != expected_mod:
        errors.append(
            f"{pkg.dist_name}: module '{pkg.mod_name}' != '{expected_mod}'",
        )

    return errors
