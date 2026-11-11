"""Code generators for scaffolding new workspace packages and runtime components."""

from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING

from xtask.process import run_command
from xtask.workspace import (
    LAYER_ORDER,
    PREFIX,
    derive_forms,
    discover_packages,
    insert_above_marker,
    sort_lines_above_marker,
)

if TYPE_CHECKING:
    from pathlib import Path

_NAME_RE = re.compile(r"^[a-z][a-z0-9]*([_-][a-z0-9]+)*$")


def _normalize_tokens(raw_name: str) -> tuple[str, str, str]:
    """Return (kebab, snake, Pascal) forms for a package or component short name."""
    if not _NAME_RE.fullmatch(raw_name):
        msg = f"Invalid identifier '{raw_name}': expected lowercase alphanumeric words"
        raise ValueError(msg)
    parts = [part for part in re.split(r"[_-]+", raw_name) if part]
    kebab = "-".join(parts)
    snake = "_".join(parts)
    pascal = "".join(part.capitalize() for part in parts)
    return kebab, snake, pascal


def _update_importlinter_layer_line(
    pyproject_text: str,
    layer: str,
    mod_name: str,
) -> str:
    """Append mod_name to the corresponding # @xtask:layer-<layer> line."""
    marker = f"# @xtask:layer-{layer}"
    separator = " | " if layer == "apps" else " : "
    lines = pyproject_text.splitlines(keepends=True)
    updated: list[str] = []
    found = False

    for line in lines:
        if marker in line:
            found = True
            match = re.match(r'^(\s*)"([^"]*)"(,\s*#.*)$', line)
            if match is None:
                msg = f"Malformed layer line for marker '{marker}'"
                raise RuntimeError(msg)
            indent, existing_mods, suffix = match.groups()
            tokens = [
                tok.strip() for tok in existing_mods.replace("|", ":").split(":") if tok.strip()
            ]
            if mod_name not in tokens:
                new_mods = (
                    f"{existing_mods}{separator}{mod_name}" if existing_mods.strip() else mod_name
                )
                updated.append(f'{indent}"{new_mods}"{suffix}\n')
            else:
                updated.append(line)
        else:
            updated.append(line)

    if not found:
        msg = f"Layer marker '{marker}' not found in pyproject.toml"
        raise RuntimeError(msg)
    return "".join(updated)


def new_package(
    root: Path,
    layer: str,
    name: str,
    *,
    is_app: bool = False,
    description: str | None = None,
    prefix: str = PREFIX,
) -> Path:
    """Scaffold a new workspace package from templates/ and register it at root."""
    if layer not in LAYER_ORDER:
        valid = ", ".join(LAYER_ORDER)
        msg = f"Invalid layer '{layer}'. Expected one of: {valid}"
        raise ValueError(msg)

    forms = derive_forms(prefix)
    kebab_name, snake_name, _ = _normalize_tokens(name)
    dist_name = f"{forms.kebab}-{kebab_name}"
    mod_name = f"{forms.snake}_{snake_name}"
    pkg_dir = root / "packages" / layer / dist_name
    if pkg_dir.exists():
        msg = f"Package directory '{pkg_dir}' already exists"
        raise FileExistsError(msg)

    desc = description.strip() if description else f"{dist_name} {layer} package."
    use_app_template = is_app or layer == "apps"
    template_dir = root / "templates" / ("package-app" if use_app_template else "package-lib")

    def _render(raw: str) -> str:
        return (
            raw.replace("__PKG_DIST__", dist_name)
            .replace("__PKG_MOD__", mod_name)
            .replace("__PKG_DESC__", desc)
        )

    src_dir = pkg_dir / "src" / mod_name
    tests_dir = pkg_dir / "tests"
    src_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)

    (pkg_dir / "pyproject.toml").write_text(
        _render((template_dir / "pyproject.toml.tmpl").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (src_dir / "__init__.py").write_text(
        _render((template_dir / "src" / "__init__.py.tmpl").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (src_dir / "py.typed").write_text("", encoding="utf-8")

    if use_app_template and (template_dir / "src" / "main.py.tmpl").is_file():
        (src_dir / "main.py").write_text(
            _render((template_dir / "src" / "main.py.tmpl").read_text(encoding="utf-8")),
            encoding="utf-8",
        )

    (tests_dir / "test_smoke.py").write_text(
        _render(
            (template_dir / "tests" / "test_smoke.py.tmpl").read_text(encoding="utf-8"),
        ),
        encoding="utf-8",
    )

    root_pyproject = root / "pyproject.toml"
    text = root_pyproject.read_text(encoding="utf-8")
    rel_src = f"packages/{layer}/{dist_name}/src"
    text = insert_above_marker(text, "# @xtask:known-first-party", f'"{mod_name}",')
    text = insert_above_marker(text, "# @xtask:mypy-path", f'"{rel_src}",')
    text = insert_above_marker(text, "# @xtask:root-packages", f'"{mod_name}",')
    text = insert_above_marker(text, "# @xtask:forbidden-sources", f'"{mod_name}",')
    text = _update_importlinter_layer_line(text, layer, mod_name)
    root_pyproject.write_text(text, encoding="utf-8")

    run_command(["uv", "sync"], cwd=root, check=True)
    return pkg_dir


def _ensure_internal_dependency(pkg_pyproject: Path, dep_dist: str) -> None:
    """Ensure dep_dist is declared in dependencies and [tool.uv.sources]."""
    text = pkg_pyproject.read_text(encoding="utf-8")
    text = insert_above_marker(text, "# @xtask:dependencies", f'"{dep_dist}",')
    text = sort_lines_above_marker(text, "# @xtask:dependencies")
    text = insert_above_marker(
        text,
        "# @xtask:sources",
        f"{dep_dist} = {{ workspace = true }}",
    )
    text = sort_lines_above_marker(text, "# @xtask:sources")
    pkg_pyproject.write_text(text, encoding="utf-8")


def _isort_all_key(symbol: str) -> tuple[int, str]:
    """Return isort-compatible sort key for __all__ entries (RUF022)."""
    if symbol.isupper():
        return (0, symbol)
    if symbol[:1].isupper():
        return (1, symbol)
    return (2, symbol)


def _export_component_from_init(
    init_path: Path,
    pkg_mod: str,
    comp_mod: str,
    comp_class: str,
) -> None:
    """Export the generated component class from the package __init__.py."""
    text = init_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    doc_line = lines[0] if lines else f'"""Package {pkg_mod}."""'
    import_stmt = f"from {pkg_mod}.{comp_mod} import {comp_class}"

    existing_imports: list[str] = []
    existing_assigns: list[str] = []
    existing_all: set[str] = set()
    in_all = False

    for line in lines[1:]:
        stripped = line.strip()
        if not stripped or stripped == "from __future__ import annotations":
            continue
        if stripped.startswith("__all__"):
            in_all = True
            continue
        if in_all:
            if stripped == "]":
                in_all = False
            else:
                symbol = stripped.strip('", ')
                if symbol:
                    existing_all.add(symbol)
            continue
        if stripped.startswith(("from ", "import ")):
            existing_imports.append(stripped)
        else:
            existing_assigns.append(line)

    if import_stmt not in existing_imports:
        existing_imports.append(import_stmt)
    existing_imports.sort()

    existing_all.add(comp_class)
    sorted_all = sorted(existing_all, key=_isort_all_key)

    out_lines: list[str] = [
        doc_line,
        "",
        "from __future__ import annotations",
        "",
        *existing_imports,
    ]
    if existing_assigns:
        out_lines.append("")
        out_lines.extend(existing_assigns)
    out_lines.append("")
    out_lines.append("__all__ = [")
    out_lines.extend(f'    "{sym}",' for sym in sorted_all)
    out_lines.append("]")

    init_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def _insert_sorted_first_party_import(
    text: str,
    marker: str,
    import_line: str,
) -> str:
    """Insert a first-party import into the block above marker and sort it."""
    lines = text.splitlines(keepends=True)
    marker_idx = next(
        (idx for idx, line in enumerate(lines) if line.strip() == marker),
        -1,
    )
    if marker_idx == -1:
        msg = f"Required marker '{marker}' not found"
        raise RuntimeError(msg)

    end_idx = marker_idx
    while end_idx > 0 and not lines[end_idx - 1].strip():
        end_idx -= 1

    start_idx = end_idx
    while start_idx > 0 and lines[start_idx - 1].strip().startswith(("from ", "import ")):
        start_idx -= 1

    block = [line.strip() for line in lines[start_idx:end_idx] if line.strip()]
    if import_line not in block:
        block.append(import_line)
    block.sort()

    new_block = [f"{stmt}\n" for stmt in block]
    return "".join([*lines[:start_idx], *new_block, "\n", *lines[marker_idx:]])


def _wire_component_into_app(
    app_dir: Path,
    app_mod: str,
    pkg_dist: str,
    pkg_mod: str,
    comp_class: str,
) -> None:
    """Add dependency on pkg_dist and register comp_class() in app wiring.py."""
    _ensure_internal_dependency(app_dir / "pyproject.toml", pkg_dist)
    wiring_path = app_dir / "src" / app_mod / "wiring.py"
    text = wiring_path.read_text(encoding="utf-8")
    text = _insert_sorted_first_party_import(
        text,
        "# @xtask:component-imports",
        f"from {pkg_mod} import {comp_class}",
    )
    text = insert_above_marker(
        text,
        "# @xtask:register-components",
        f"registry.register({comp_class}())",
    )
    wiring_path.write_text(text, encoding="utf-8")


def new_component(
    root: Path,
    package: str,
    name: str,
    *,
    wire_app: str | None = None,
    prefix: str = PREFIX,
) -> Path:
    """Scaffold a Component implementation and unit test into an existing package."""
    forms = derive_forms(prefix)
    packages = discover_packages(root, prefix=prefix)
    target_dist = package if package.startswith(f"{forms.kebab}-") else f"{forms.kebab}-{package}"
    pkg_info = next((p for p in packages if p.dist_name == target_dist), None)
    if pkg_info is None:
        msg = f"Workspace package '{package}' not found"
        raise ValueError(msg)

    kebab_comp, snake_comp, pascal_comp = _normalize_tokens(name)
    comp_class = f"{pascal_comp}Component"
    prefixed_class = f"{forms.pascal}{comp_class}"

    comp_tmpl = (root / "templates" / "component.py.tmpl").read_text(encoding="utf-8")
    rendered_comp = (
        comp_tmpl.replace("__COMP_NAME__", kebab_comp)
        .replace("__COMP_MOD__", snake_comp)
        .replace("__COMP_CLASS__", comp_class)
    )
    comp_path = pkg_info.path / "src" / pkg_info.mod_name / f"{snake_comp}.py"
    comp_path.write_text(rendered_comp, encoding="utf-8")

    # Build test file with sorted first-party imports so ruff I001 is always satisfied.
    test_tmpl = (root / "templates" / "test_component.py.tmpl").read_text(
        encoding="utf-8",
    )
    rendered_test = (
        test_tmpl.replace("__PKG_MOD__", pkg_info.mod_name)
        .replace("__COMP_NAME__", kebab_comp)
        .replace("__COMP_MOD__", snake_comp)
        .replace("__COMP_CLASS__", comp_class)
    )
    pkg_import_lines = (
        f"from {pkg_info.mod_name} import {comp_class}\n"
        f"from {pkg_info.mod_name}.{snake_comp} import {prefixed_class}"
    )
    core_mod = f"{forms.snake}_core"
    core_import_stmt = f"from {core_mod} import Component, Context"
    tmpl_import_block = f"{pkg_import_lines}\n{core_import_stmt}"
    if pkg_info.mod_name < core_mod:
        replacement_block = f"{pkg_import_lines}\n{core_import_stmt}"
    else:
        replacement_block = f"{core_import_stmt}\n{pkg_import_lines}"
    rendered_test = rendered_test.replace(tmpl_import_block, replacement_block)

    test_path = pkg_info.path / "tests" / f"test_{snake_comp}.py"
    test_path.write_text(rendered_test, encoding="utf-8")

    core_dist = f"{forms.kebab}-core"
    if pkg_info.dist_name != core_dist:
        _ensure_internal_dependency(pkg_info.path / "pyproject.toml", core_dist)

    _export_component_from_init(
        pkg_info.path / "src" / pkg_info.mod_name / "__init__.py",
        pkg_info.mod_name,
        snake_comp,
        comp_class,
    )

    if wire_app is not None:
        app_dist = (
            wire_app if wire_app.startswith(f"{forms.kebab}-") else f"{forms.kebab}-{wire_app}"
        )
        app_info = next((p for p in packages if p.dist_name == app_dist), None)
        if app_info is None:
            msg = f"Target application package '{wire_app}' not found"
            raise ValueError(msg)
        _wire_component_into_app(
            app_info.path,
            app_info.mod_name,
            pkg_info.dist_name,
            pkg_info.mod_name,
            comp_class,
        )

    run_command(["uv", "sync"], cwd=root, check=True)
    return comp_path


def remove_package(
    root: Path,
    package: str,
    *,
    prefix: str = PREFIX,
) -> Path:
    """Remove a scaffolded package directory and restore tracked workspace manifests."""
    forms = derive_forms(prefix)
    packages = discover_packages(root, prefix=prefix)
    target_dist = package if package.startswith(f"{forms.kebab}-") else f"{forms.kebab}-{package}"
    pkg_info = next((p for p in packages if p.dist_name == target_dist), None)
    if pkg_info is None:
        msg = f"Workspace package '{package}' not found"
        raise ValueError(msg)

    shutil.rmtree(pkg_info.path)
    run_command(
        ["git", "checkout", "--", "pyproject.toml", "uv.lock", "packages"],
        cwd=root,
        check=True,
    )
    run_command(["uv", "sync"], cwd=root, check=True)
    return pkg_info.path
