"""Command-line entrypoint for workspace automation (uv run xtask ...)."""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import TYPE_CHECKING

from xtask.checker import format_graph, run_check
from xtask.ci import bump_python, run_ci
from xtask.componentize import run_componentize_gate
from xtask.generators import new_component, new_package, remove_package
from xtask.renamer import _read_current_prefix, rename_workspace
from xtask.workspace import LAYER_ORDER, find_workspace_root

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    """Build the xtask argument parser and subcommands."""
    parser = argparse.ArgumentParser(
        prog="xtask",
        description="Zero-dependency platform automation for the workspace.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "check",
        help="Enforce layer rules, catalogue specs, AST imports, and lockfile freshness.",
    )
    sub.add_parser(
        "graph",
        help="Print every workspace package by layer with its internal dependencies.",
    )

    ci_p = sub.add_parser(
        "ci",
        help="Run the full quality gate and wheel-install smoke test.",
    )
    ci_p.add_argument(
        "--offline",
        action="store_true",
        help="Skip online pip-audit vulnerability querying.",
    )

    new_pkg_p = sub.add_parser(
        "new-package",
        help="Scaffold a new workspace package into packages/<layer>/.",
    )
    new_pkg_p.add_argument(
        "layer",
        choices=list(LAYER_ORDER.keys()),
        help="Target architectural layer.",
    )
    new_pkg_p.add_argument(
        "name",
        help="Short package name without prefix (e.g. billing).",
    )
    new_pkg_p.add_argument(
        "--app",
        action="store_true",
        help="Scaffold using the deployable application template.",
    )
    new_pkg_p.add_argument(
        "--description",
        default=None,
        help="Package description string.",
    )

    new_comp_p = sub.add_parser(
        "new-component",
        help="Scaffold a runtime Component into an existing package.",
    )
    new_comp_p.add_argument(
        "package",
        help="Target package name (with or without the workspace prefix).",
    )
    new_comp_p.add_argument(
        "name",
        help="Component module/identifier name (e.g. invoice_sync).",
    )
    new_comp_p.add_argument(
        "--wire",
        default=None,
        help="Optional application package to register the component in.",
    )

    rename_p = sub.add_parser(
        "rename",
        help="Context-aware rename of the workspace prefix across all four forms.",
    )
    rename_p.add_argument(
        "new_prefix",
        help="New snake_case prefix (e.g. my_service or zenith).",
    )

    bump_p = sub.add_parser(
        "bump-python",
        help="Update the workspace Python version floor and verify with CI.",
    )
    bump_p.add_argument(
        "version",
        help="Target Python major.minor version (e.g. 3.13).",
    )

    rm_pkg_p = sub.add_parser(
        "remove-package",
        help="Remove a temporary workspace package and restore manifests.",
    )
    rm_pkg_p.add_argument(
        "package",
        help="Target package name (with or without the workspace prefix).",
    )

    gate = sub.add_parser(
        "componentize-gate", help="Audit Python component boundaries; never begin jobs."
    )
    gate.add_argument("paths", nargs="+", help="Component source paths.")
    return parser


def _dispatch(args: argparse.Namespace, ws_root: Path, current_prefix: str) -> int:
    """Dispatch parsed CLI arguments to the corresponding xtask handler."""
    if args.command == "componentize-gate":
        return run_componentize_gate(ws_root, args.paths)
    if args.command == "check":
        violations = run_check(ws_root, prefix=current_prefix)
        if violations:
            for item in violations:
                sys.stderr.write(f"ERROR: {item}\n")
            return 1
        sys.stdout.write(
            "xtask check: all architectural and manifest invariants passed.\n",
        )
        return 0

    if args.command == "graph":
        sys.stdout.write(format_graph(ws_root, prefix=current_prefix))
        return 0

    if args.command == "ci":
        return run_ci(ws_root, offline=bool(args.offline), prefix=current_prefix)

    return _dispatch_mutation(args, ws_root, current_prefix)


def _dispatch_mutation(args: argparse.Namespace, ws_root: Path, current_prefix: str) -> int:
    """Dispatch workspace mutations after read-only commands are handled."""
    if args.command == "new-package":
        created = new_package(
            ws_root,
            args.layer,
            args.name,
            is_app=bool(args.app),
            description=args.description,
            prefix=current_prefix,
        )
        sys.stdout.write(f"Scaffolded package at {created.relative_to(ws_root)}\n")
        return 0

    if args.command == "new-component":
        comp_file = new_component(
            ws_root,
            args.package,
            args.name,
            wire_app=args.wire,
            prefix=current_prefix,
        )
        sys.stdout.write(
            f"Scaffolded component at {comp_file.relative_to(ws_root)}\n",
        )
        return 0

    if args.command == "rename":
        forms = rename_workspace(ws_root, args.new_prefix)
        sys.stdout.write(
            f"Renamed workspace prefix to '{forms.snake}' ({forms.kebab} / "
            f"{forms.screaming} / {forms.pascal})\n",
        )
        return 0

    if args.command == "bump-python":
        return bump_python(ws_root, args.version)

    if args.command == "remove-package":
        removed = remove_package(ws_root, args.package, prefix=current_prefix)
        sys.stdout.write(f"Removed package at {removed.relative_to(ws_root)}\n")
        return 0

    return 1


def run(argv: Sequence[str] | None = None, *, root: Path | None = None) -> int:
    """Execute an xtask subcommand and return its exit status code."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else [])
    ws_root = root if root is not None else find_workspace_root()
    current_prefix = _read_current_prefix(ws_root)

    try:
        return _dispatch(args, ws_root, current_prefix)
    except (
        ValueError,
        FileExistsError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as exc:
        sys.stderr.write(f"xtask error: {exc}\n")
        return 1


def main() -> None:
    """Console script entrypoint for ``xtask``."""
    sys.exit(run(sys.argv[1:]))
