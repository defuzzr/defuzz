"""Structured JSON logger implementing the core Logger protocol."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from tmpl_prefix_core import Logger

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import TextIO


DEFAULT_SERVICE_NAME = "tmpl-prefix-service"


class JsonFormatter(logging.Formatter):
    """Format stdlib LogRecords into single-line structured JSON objects."""

    def __init__(
        self,
        service_name: str = DEFAULT_SERVICE_NAME,
    ) -> None:
        """Initialize the JSON formatter with the owning service name."""
        super().__init__()
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Serialize the log record as a JSON string."""
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "service": getattr(record, "service_name", self._service_name),
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra_fields = getattr(record, "structured_fields", None)
        if isinstance(extra_fields, dict):
            for key, val in extra_fields.items():
                if key not in payload:
                    payload[key] = val
        return json.dumps(payload, default=str)


class StructuredLogger(Logger):
    """Core Logger protocol implementation backed by stdlib logging."""

    def __init__(
        self,
        raw_logger: logging.Logger,
        service_name: str,
        bound_fields: Mapping[str, object] | None = None,
    ) -> None:
        """Initialize a structured logger wrapper."""
        self._logger = raw_logger
        self._service_name = service_name
        self._bound: dict[str, object] = dict(bound_fields) if bound_fields else {}

    def _emit(self, level: int, message: str, fields: Mapping[str, object]) -> None:
        merged = {**self._bound, **fields}
        self._logger.log(
            level,
            message,
            extra={
                "service_name": self._service_name,
                "structured_fields": merged,
            },
        )

    def debug(self, message: str, **fields: object) -> None:
        """Emit a debug-level structured log entry."""
        self._emit(logging.DEBUG, message, fields)

    def info(self, message: str, **fields: object) -> None:
        """Emit an info-level structured log entry."""
        self._emit(logging.INFO, message, fields)

    def warning(self, message: str, **fields: object) -> None:
        """Emit a warning-level structured log entry."""
        self._emit(logging.WARNING, message, fields)

    def error(self, message: str, **fields: object) -> None:
        """Emit an error-level structured log entry."""
        self._emit(logging.ERROR, message, fields)

    def bind(self, **fields: object) -> StructuredLogger:
        """Return a child logger with merged bound context fields."""
        return StructuredLogger(
            self._logger,
            self._service_name,
            bound_fields={**self._bound, **fields},
        )


def init(
    level: str = "INFO",
    service_name: str = DEFAULT_SERVICE_NAME,
    stream: TextIO | None = None,
) -> StructuredLogger:
    """Configure and return a structured JSON logger.

    Args:
        level: Minimum log level name (e.g. ``"INFO"``, ``"DEBUG"``).
        service_name: Logical service name attached to every log record.
        stream: Optional output stream (defaults to ``sys.stderr``).

    Returns:
        Configured ``StructuredLogger`` instance.
    """
    target_stream = stream if stream is not None else sys.stderr
    logger_name = f"tmpl_prefix.{service_name}"
    raw_logger = logging.getLogger(logger_name)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    raw_logger.setLevel(numeric_level)
    raw_logger.propagate = False

    handler = logging.StreamHandler(target_stream)
    handler.setLevel(numeric_level)
    handler.setFormatter(JsonFormatter(service_name=service_name))
    raw_logger.handlers = [handler]

    return StructuredLogger(raw_logger, service_name=service_name)


TmplPrefixJsonFormatter = JsonFormatter
TmplPrefixLogger = StructuredLogger
