"""Byte-compile every tracked plugin .py file with the runtime Python floor.

The registration gate defines the minimum Python. Code that compiles under
an interpreter newer than that floor can still fail on the floor. Two checks:

- an AST check that needs no other interpreter and always runs: every tracked
  .py file is parsed with ``ast.parse(..., feature_version=floor)`` by the running
  interpreter, which rejects grammar newer than the floor;
- a byte-compile with a real interpreter for the floor version, when one is on PATH.

Template trees whose generated project declares its own newer Python
(`requires-python = ">=3.N"` with N above the floor) are excluded; only those.

Skip: when no interpreter for the floor version is on PATH the byte-compile is
skipped with a clear reason, so it then runs only in CI (which installs 3.13).
This is the one acceptable skip in this file; the AST check never skips.
"""
from __future__ import annotations

import ast
import re
import shutil
import warnings
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _runtime_floor() -> tuple[int, int]:
    tree = ast.parse((REPO / "__init__.py").read_text(encoding="utf-8"))
    register = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "register")
    gates = [n for n in ast.walk(register) if isinstance(n, ast.Compare)
             and "sys.version_info" in ast.unparse(n.left)
             and len(n.ops) == 1 and isinstance(n.ops[0], ast.Lt)]
    assert len(gates) == 1, "register() must have one minimum-Python gate"
    floor = ast.literal_eval(gates[0].comparators[0])
    assert isinstance(floor, tuple) and len(floor) == 2
    assert all(isinstance(part, int) for part in floor)
    return floor


def _tracked_py_files() -> list[str]:
    if shutil.which("git") is None or not (REPO / ".git").exists():
        return sorted(str(p.relative_to(REPO)) for p in REPO.rglob("*.py")
                      if ".git" not in p.parts and ".worktrees" not in p.parts
                      and "__pycache__" not in p.parts)
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "--", "*.py"],
                         check=True, capture_output=True).stdout.decode()
    return sorted(f for f in out.split("\0") if f)


def _templates_declaring_newer(floor: tuple[int, int]) -> set[str]:
    """Template ids whose generated project declares a Python floor above ours."""
    newer: set[str] = set()
    tdir = REPO / "templates"
    if not tdir.is_dir():
        return newer
    pat = re.compile(r'requires-python\s*=\s*"\s*>=\s*(\d+)\.(\d+)')
    for tmpl in sorted(p for p in tdir.iterdir() if p.is_dir()):
        for f in tmpl.rglob("*"):
            if not f.is_file() or not (f.name.startswith("pyproject.toml") or f.name == "uv.lock"):
                continue
            for m in pat.finditer(f.read_text(encoding="utf-8", errors="replace")):
                if (int(m.group(1)), int(m.group(2))) > floor:
                    newer.add(tmpl.name)
    return newer


def test_runtime_floor_matches_ci():
    import yaml
    workflow = yaml.safe_load((REPO / ".github/workflows/ci.yml").read_text())
    versions = {str(version) for job in workflow["jobs"].values()
                for version in job.get("strategy", {}).get("matrix", {}).get("python", [])}
    assert ".".join(map(str, _runtime_floor())) in versions


def _files_for_floor(floor: tuple[int, int]) -> list[str]:
    excluded = _templates_declaring_newer(floor)
    return [f for f in _tracked_py_files()
            if not (f.startswith("templates/") and f.split("/")[1] in excluded)]


def test_tracked_python_parses_with_floor_grammar():
    floor = _runtime_floor()
    files = _files_for_floor(floor)
    assert len(files) > 50, f"too few tracked .py files found ({len(files)})"
    bad = []
    for rel in files:
        source = (REPO / rel).read_text(encoding="utf-8")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                ast.parse(source, filename=rel, feature_version=floor)
        except SyntaxError as exc:
            bad.append(f"{rel}:{exc.lineno}: {exc.msg}")
    assert not bad, (f"{len(bad)} file(s) use syntax newer than Python "
                     f"{floor[0]}.{floor[1]}:\n" + "\n".join(bad))


def test_tracked_python_compiles_on_runtime_floor(tmp_path):
    floor = _runtime_floor()
    exe_name = f"python{floor[0]}.{floor[1]}"
    exe = shutil.which(exe_name)
    if exe is None:
        pytest.skip(f"{exe_name} not installed; the byte-compile on the floor runs only in CI "
                    "(the AST check above still ran)")
    ver = subprocess.run([exe, "-c", "import sys; print(*sys.version_info[:2])"],
                         check=True, capture_output=True, text=True).stdout.split()
    assert tuple(map(int, ver)) == floor, f"{exe} reports {ver}, expected {floor}"

    files = _files_for_floor(floor)
    assert len(files) > 50, f"too few tracked .py files found ({len(files)})"

    copy = tmp_path / "src"
    for rel in files:
        dst = copy / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, dst)

    script = (
        "import sys, py_compile\n"
        "bad = []\n"
        "for f in sys.argv[1:]:\n"
        "    try:\n"
        "        py_compile.compile(f, cfile=f + 'c', doraise=True)\n"
        "    except py_compile.PyCompileError as e:\n"
        "        bad.append(f + ': ' + str(e.exc_value).splitlines()[0] if e.exc_value else f)\n"
        "print('\\n'.join(bad))\n"
    )
    proc = subprocess.run([exe, "-c", script, *files], cwd=copy,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    failures = [line for line in proc.stdout.splitlines() if line.strip()]
    assert not failures, (f"{len(failures)} file(s) do not compile on Python "
                          f"{floor[0]}.{floor[1]}:\n" + "\n".join(failures))
