"""HTTP server application composition root and entrypoint."""

from __future__ import annotations

from tmpl_prefix_server.main import main, run
from tmpl_prefix_server.wiring import (
    Application,
    build_application,
)

__all__ = [
    "Application",
    "build_application",
    "main",
    "run",
]
