"""Component gate command contract."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from xtask.main import _build_parser, _dispatch

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_component_gate_parser() -> None:
    """Accept explicit source paths for the read-only gate."""
    args = _build_parser().parse_args(["componentize-gate", "sample.py"])
    assert args.paths == ["sample.py"]


def test_gate_unavailable_is_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Missing optional audit dependency is a visible, successful skip."""
    monkeypatch.setitem(sys.modules, "hermes_audit", None)
    args = _build_parser().parse_args(["componentize-gate", "sample.py"])
    assert _dispatch(args, tmp_path, "sample") == 0
    assert "unavailable" in capsys.readouterr().err
