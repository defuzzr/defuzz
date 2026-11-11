"""Structured JSON telemetry and logging built on stdlib logging."""

from __future__ import annotations

from tmpl_prefix_telemetry.logger import (
    JsonFormatter,
    StructuredLogger,
    init,
)

__all__ = [
    "JsonFormatter",
    "StructuredLogger",
    "init",
]
