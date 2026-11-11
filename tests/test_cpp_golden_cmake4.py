"""The C++ template's own check passes, with build output that lint accepts, on CMake 3 and CMake 4.

The cmake found on PATH is always tested. To also test other CMake versions, list their
`bin` folders in DEFUZZ_TEST_CMAKE_BIN_DIRS (separated like PATH).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

REPO_ROOT = Path(__file__).resolve().parent.parent
TMPL_REPO_DIR = REPO_ROOT / "templates" / "cpp-golden" / "tmpl_prefix"


def _cmake_bin_dirs() -> list[str]:
    found = shutil.which("cmake")
    dirs = [str(Path(found).parent)] if found else []
    for item in os.environ.get("DEFUZZ_TEST_CMAKE_BIN_DIRS", "").split(os.pathsep):
        if item and item not in dirs:
            dirs.append(item)
    return dirs


def _cmake_version(bin_dir: str) -> str:
    out = subprocess.run([str(Path(bin_dir) / "cmake"), "--version"], capture_output=True, text=True, check=True)
    match = re.search(r"cmake version (\d+\.\d+(?:\.\d+)?)", out.stdout)
    assert match, out.stdout
    return match.group(1)


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _tool_env(cmake_dir: str) -> dict[str, str]:
    env = dict(os.environ)
    fmt = shutil.which("clang-format")
    assert fmt, "clang-format not on PATH (install the Defuzz lint tools)"
    fmt_dir = str(Path(fmt).parent)
    assert not (Path(fmt_dir) / "cmake").exists(), "the lint tools folder must not hold a cmake"
    # The lint tools' clang-format first (a distribution one next to cmake is older), then cmake.
    rest = [p for p in env.get("PATH", "").split(os.pathsep) if p and p not in (cmake_dir, fmt_dir)]
    env["PATH"] = os.pathsep.join([fmt_dir, cmake_dir, *rest])
    return env


def test_cmake_floor_is_stated_once_and_cmake_4_accepts_the_range() -> None:
    text = (TMPL_REPO_DIR / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"cmake_minimum_required\(VERSION (\d+\.\d+)\.\.\.(\d+\.\d+)\)", text)
    assert match, "cmake_minimum_required must state a min...max range"
    low, high = match.group(1), match.group(2)
    # CMake 4 refuses a minimum below 3.5 and warns below 3.10.
    assert _version_tuple(low) >= (3, 10)
    assert _version_tuple(high) >= _version_tuple(low)
    lock = (TMPL_REPO_DIR / "TOOLS.lock").read_text(encoding="utf-8")
    section = lock.split("[cmake]", 1)[1].split("\n[", 1)[0]
    assert f'minimum = "{low}"' in section


@pytest.mark.parametrize("cmake_dir", _cmake_bin_dirs())
def test_own_check_passes_and_build_output_is_left_as_cmake_wrote_it(tmp_path: Path, cmake_dir: str) -> None:
    from hermes_plugins.defuzz.linter import run_lint

    version = _cmake_version(cmake_dir)
    lock = (TMPL_REPO_DIR / "TOOLS.lock").read_text(encoding="utf-8")
    floor_match = re.search(r'\[cmake\][^\[]*minimum = "([^"]+)"', lock)
    assert floor_match, "TOOLS.lock states no cmake minimum"
    floor = floor_match.group(1)
    assert _version_tuple(version) >= _version_tuple(floor)

    repo = tmp_path / "proj"
    shutil.copytree(TMPL_REPO_DIR, repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    env = _tool_env(cmake_dir)
    proc = subprocess.run(
        ["cmake", "-P", "cmake/xtask.cmake", "--", "ci"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=900,
    )
    detail = f"cmake {version}\n{proc.stdout}\n{proc.stderr}"
    assert proc.returncode == 0, detail
    assert "CMake Deprecation Warning" not in proc.stderr, detail
    assert "CMake Warning" not in proc.stderr, detail

    cc_json = repo / "build" / "compile_commands.json"
    raw = cc_json.read_text(encoding="utf-8")
    entries = json.loads(raw)
    assert entries and all("file" in entry for entry in entries)
    # The check does not rewrite CMake's file: no extra blank line, CMake's own layout.
    assert not raw.endswith("\n\n"), f"cmake {version}: {raw[-40:]!r}"
    assert "\n\t{" not in raw, f"cmake {version}: compile_commands.json was rewritten"

    report = run_lint(repo, env=env, db_path=tmp_path / "state.db")
    assert report["ok"] and report["status"] == "clean", (version, report)
