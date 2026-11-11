"""Tests for the version-floor half of tests/toolchain_needs.py."""

from __future__ import annotations

import contextlib
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from tests.toolchain_needs import (  # noqa: E402
    need_at_least,
    template_floors,
)


def _write_version_tool(directory: Path, name: str, output: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / name
    script.write_text(f"#!/bin/sh\necho '{output}'\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    return script


@contextlib.contextmanager
def _path_first(directory: Path) -> Iterator[Path]:
    """Put `directory` first on PATH without writing any stand-in over it."""
    old_path = os.environ.get("PATH")
    os.environ["PATH"] = f"{directory}{os.pathsep}{old_path}" if old_path else str(directory)
    try:
        yield directory
    finally:
        if old_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = old_path


def test_need_at_least_skips_when_tool_absent() -> None:
    assert shutil.which("definitely-missing-tool-xyz") is None
    with pytest.raises(pytest.skip.Exception, match=r"^definitely-missing-tool-xyz not installed$"):
        need_at_least("definitely-missing-tool-xyz", "1.0")


def test_need_at_least_skips_when_found_version_is_older(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _write_version_tool(bin_dir, "clang-format", "clang-format version 18.1.3")
    with _path_first(bin_dir):
        with pytest.raises(
            pytest.skip.Exception,
            match=r"^clang-format 18\.1\.3 is older than 23\.1$",
        ):
            need_at_least("clang-format", "23.1")


def test_need_at_least_runs_when_version_is_equal(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _write_version_tool(bin_dir, "floor-tool", "floor-tool 23.1.0")
    with _path_first(bin_dir):
        need_at_least("floor-tool", "23.1")


def test_need_at_least_runs_when_version_is_newer(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _write_version_tool(bin_dir, "floor-tool", "floor-tool 24.0.1")
    with _path_first(bin_dir):
        need_at_least("floor-tool", "23.1")


def test_need_at_least_compares_parts_numerically(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _write_version_tool(bin_dir, "floor-tool", "floor-tool 23.10")
    with _path_first(bin_dir):
        need_at_least("floor-tool", "23.9")
    _write_version_tool(bin_dir, "floor-tool", "floor-tool 23.9")
    with _path_first(bin_dir):
        with pytest.raises(
            pytest.skip.Exception, match=r"^floor-tool 23\.9 is older than 23\.10$"
        ):
            need_at_least("floor-tool", "23.10")


def test_need_at_least_runs_when_version_cannot_be_read(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    _write_version_tool(bin_dir, "quiet-tool", "no version here")
    with _path_first(bin_dir):
        need_at_least("quiet-tool", "23.1")


def test_template_floors_are_read_from_the_template_lock() -> None:
    floors = template_floors("cpp-golden")
    assert floors["clang-format"] == "23.1"
    assert floors["cmake"] == "3.20"
    assert template_floors("python-golden") == {}
