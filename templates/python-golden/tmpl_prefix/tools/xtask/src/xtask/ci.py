"""CI pipeline runner, wheel-install smoke test, and Python floor bumper."""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from xtask.checker import run_check
from xtask.process import run_command
from xtask.renamer import _read_current_prefix
from xtask.workspace import PREFIX, derive_forms

if TYPE_CHECKING:
    from collections.abc import Sequence

_PY_VER_RE = re.compile(r"^3\.\d+$")


def _run_step(label: str, cmd: Sequence[str], cwd: Path) -> bool:
    """Run a single CI step and write status output to stdout/stderr."""
    sys.stdout.write(f"==> [{label}] {' '.join(cmd)}\n")
    sys.stdout.flush()
    proc = run_command(cmd, cwd=cwd, check=False)
    return proc.returncode == 0


def _run_pip_audit(root: Path) -> bool:
    """Audit all locked third-party dependencies via pip-audit --strict."""
    sys.stdout.write("==> [pip-audit] uv run pip-audit --strict\n")
    sys.stdout.flush()
    export_proc = run_command(
        [
            "uv",
            "export",
            "--locked",
            "--no-emit-workspace",
            "--no-annotate",
            "--no-header",
        ],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if export_proc.returncode != 0:
        sys.stderr.write(export_proc.stderr or export_proc.stdout)
        return False

    cleaned_lines: list[str] = []
    for raw_line in export_proc.stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("--hash="):
            cleaned_lines.append(f"    {stripped}")
        else:
            has_cont = stripped.endswith("\\")
            pkg_spec = stripped.rstrip("\\").split(";")[0].strip()
            cleaned_lines.append(f"{pkg_spec} \\" if has_cont else pkg_spec)

    with tempfile.TemporaryDirectory(prefix="xtask-pip-audit-") as tmp_dir:
        req_file = Path(tmp_dir) / "requirements.txt"
        req_file.write_text("\n".join(cleaned_lines) + "\n", encoding="utf-8")
        audit_proc = run_command(
            [
                "uv",
                "run",
                "pip-audit",
                "--strict",
                "--require-hashes",
                "--disable-pip",
                "-r",
                str(req_file),
            ],
            cwd=root,
            check=False,
        )
        return audit_proc.returncode == 0


def _run_wheel_smoke(root: Path, kebab_prefix: str) -> bool:
    """Build all workspace wheels and verify offline installation in a fresh venv."""
    dist_dir = root / "dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)

    if not _run_step(
        "wheel-build",
        ["uv", "build", "--all-packages"],
        root,
    ):
        return False

    server_pkg = f"{kebab_prefix}-server"
    with tempfile.TemporaryDirectory(prefix="xtask-wheel-smoke-") as tmp_dir:
        venv_dir = Path(tmp_dir).resolve() / "venv"
        if not _run_step("wheel-venv", ["uv", "venv", str(venv_dir)], root):
            return False

        py_bin = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        srv_bin = venv_dir / (
            f"Scripts/{server_pkg}.exe" if sys.platform == "win32" else f"bin/{server_pkg}"
        )

        seed_cmd = [
            "uv",
            "pip",
            "install",
            "--python",
            str(py_bin),
            "fastapi>=0.115,<1",
            "pydantic>=2.10,<3",
            "pydantic-settings>=2.7,<3",
            "uvicorn>=0.34,<1",
        ]
        if not _run_step("wheel-seed-deps", seed_cmd, root):
            return False

        install_cmd = [
            "uv",
            "pip",
            "install",
            "--python",
            str(py_bin),
            "--no-index",
            "--find-links",
            str(dist_dir),
            server_pkg,
        ]
        if not _run_step("wheel-install", install_cmd, root):
            return False

        smoke_cmd = [str(srv_bin), "--check", "--http", "stdlib"]
        if not _run_step("wheel-check", smoke_cmd, root):
            return False
    return True


def run_ci(root: Path, *, offline: bool = False, prefix: str | None = None) -> int:
    """Run the full quality gate and wheel-install smoke pipeline."""
    active_prefix = prefix if prefix is not None else _read_current_prefix(root)
    forms = derive_forms(active_prefix)
    server_bin = f"{forms.kebab}-server"

    steps: list[tuple[str, list[str]]] = [
        ("sync", ["uv", "sync", "--locked"]),
        ("ruff-format", ["uv", "run", "ruff", "format", "--check", "."]),
        ("ruff-check", ["uv", "run", "ruff", "check", "."]),
        ("mypy", ["uv", "run", "mypy"]),
        ("import-linter", ["uv", "run", "lint-imports"]),
        ("pytest", ["uv", "run", "pytest"]),
        ("smoke-stdlib", ["uv", "run", server_bin, "--check", "--http", "stdlib"]),
        ("smoke-fastapi", ["uv", "run", server_bin, "--check", "--http", "fastapi"]),
    ]

    results: list[tuple[str, str]] = []
    for label, cmd in steps:
        ok = _run_step(label, cmd, root)
        results.append((label, "PASS" if ok else "FAIL"))
        if not ok:
            _print_summary(results)
            return 1

    if not offline:
        audit_ok = _run_pip_audit(root)
        results.append(("pip-audit", "PASS" if audit_ok else "FAIL"))
        if not audit_ok:
            _print_summary(results)
            return 1

    sys.stdout.write("==> [xtask-check] uv run xtask check\n")
    sys.stdout.flush()
    violations = run_check(root, prefix=active_prefix)
    if violations:
        for violation in violations:
            sys.stderr.write(f"ERROR: {violation}\n")
        results.append(("xtask-check", "FAIL"))
        _print_summary(results)
        return 1
    results.append(("xtask-check", "PASS"))

    wheel_ok = _run_wheel_smoke(root, forms.kebab)
    results.append(("wheel-smoke", "PASS" if wheel_ok else "FAIL"))
    _print_summary(results)
    return 0 if wheel_ok else 1


def _print_summary(results: Sequence[tuple[str, str]]) -> None:
    """Write a summary table of CI step outcomes to stdout."""
    sys.stdout.write("\nCI Summary:\n")
    sys.stdout.write("-" * 36 + "\n")
    for step_name, status in results:
        sys.stdout.write(f"  {step_name:<20} {status}\n")
    sys.stdout.write("-" * 36 + "\n")
    sys.stdout.flush()


def bump_python(root: Path, version: str) -> int:
    """Rewrite Python version floor across workspace manifests and verify via CI."""
    if not _PY_VER_RE.fullmatch(version):
        sys.stderr.write(
            f"Invalid Python version '{version}': must match 3.<minor> (e.g. 3.13)\n",
        )
        return 1

    find_proc = run_command(
        ["uv", "python", "find", version],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if find_proc.returncode != 0:
        sys.stderr.write(
            f"Python {version} is not installed. Install it with:\n  uv python install {version}\n",
        )
        return 1

    ruff_target = "py" + version.replace(".", "")
    targets: list[Path] = [
        root / "pyproject.toml",
        root / "tools" / "xtask" / "pyproject.toml",
        *sorted((root / "packages").rglob("pyproject.toml")),
        *sorted((root / "templates").rglob("*.toml.tmpl")),
    ]
    ci_workflow = root / ".github" / "workflows" / "ci.yml"
    if ci_workflow.is_file():
        targets.append(ci_workflow)

    snapshots: dict[Path, str] = {
        path: path.read_text(encoding="utf-8") for path in targets if path.is_file()
    }

    try:
        for path, original in snapshots.items():
            _rewrite_python_floor(path, original, version, ruff_target)

        ci_proc = run_command(
            ["uv", "run", "--python", version, "xtask", "ci"],
            cwd=root,
            check=False,
        )
        if ci_proc.returncode != 0:
            for path, original in snapshots.items():
                path.write_text(original, encoding="utf-8")
            return 1
    except Exception:
        for path, original in snapshots.items():
            path.write_text(original, encoding="utf-8")
        raise

    return 0


_ = PREFIX


def _rewrite_python_floor(path: Path, original: str, version: str, ruff_target: str) -> None:
    """Update Python constraints in one manifest or workflow."""
    updated = original
    if path.name.endswith((".toml", ".toml.tmpl")):
        updated = re.sub(
            r'requires-python\s*=\s*">=3\.\d+"',
            f'requires-python = ">={version}"',
            updated,
        )
        updated = re.sub(
            r'target-version\s*=\s*"py3\d+"',
            f'target-version = "{ruff_target}"',
            updated,
        )
        updated = re.sub(
            r'python_version\s*=\s*"3\.\d+"',
            f'python_version = "{version}"',
            updated,
        )
    elif path.name == "ci.yml":
        updated = re.sub(
            r'python-version:\s*\["3\.\d+",\s*"3\.x"\]',
            f'python-version: ["{version}", "3.x"]',
            updated,
        )
    if updated != original:
        path.write_text(updated, encoding="utf-8")
