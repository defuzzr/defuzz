"""Regression tests for shell-free, resolved xtask command execution."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from xtask import process

if TYPE_CHECKING:
    from pathlib import Path


def test_command_execution_and_missing_executable(tmp_path: Path) -> None:
    """Run literal arguments and fail clearly when a command cannot be resolved."""
    result = process.run_command(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(not-a-shell)"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )
    assert result.stdout == "$(not-a-shell)\n"
    with pytest.raises(RuntimeError, match="Executable not found"):
        process.run_command(["xtask-nonexistent-executable"], cwd=tmp_path)
