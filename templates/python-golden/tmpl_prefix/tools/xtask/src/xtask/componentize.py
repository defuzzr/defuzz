"""Optional, read-only component architecture audit adapter."""

from __future__ import annotations

import sys
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


def run_componentize_gate(root: Path, paths: Sequence[str]) -> int:
    """Audit every supplied component without starting an extraction job."""
    try:
        architecture_gate = import_module("hermes_audit.architecture_gate")
    except ImportError:
        sys.stderr.write("componentize gate unavailable; optional check skipped.\n")
        return 0
    index = root / "COMPONENTS.md"
    index_text = index.read_text(encoding="utf-8") if index.exists() else ""
    failed = False
    for name in paths:
        path = root / name
        result = architecture_gate.audit_module(
            str(path),
            source=path.read_text(encoding="utf-8"),
            role="component",
            index_text=index_text,
        )
        sys.stdout.write(str(result) + "\n")
        failed = failed or not result["ok"]
    return int(failed)
