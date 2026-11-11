"""Dedicated CLI output layer (the only module permitted to call print)."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


def emit_json(payload: Mapping[str, object]) -> None:
    """Print a dictionary as formatted JSON to standard output."""
    print(json.dumps(dict(payload), sort_keys=True))


def emit_line(text: str) -> None:
    """Print a single line of text to standard output."""
    print(text)


def emit_error(payload: Mapping[str, object]) -> None:
    """Print a structured error payload as JSON to standard error."""
    print(json.dumps(dict(payload), sort_keys=True), file=sys.stderr)
