"""Shell-free execution of workspace tool commands."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


def run_command(
    cmd: Sequence[str],
    *,
    cwd: Path,
    capture_output: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Resolve the executable and pass arguments literally, never through a shell."""
    executable = shutil.which(cmd[0])
    if executable is None:
        msg = f"Executable not found: {cmd[0]}"
        raise RuntimeError(msg)
    # Trusted developer tooling; resolved executable and argv, with no shell expansion.
    return subprocess.run(  # noqa: S603
        [str(Path(executable).absolute()), *cmd[1:]],
        cwd=cwd,
        capture_output=capture_output,
        text=True,
        check=check,
        shell=False,
    )
