"""Unit tests for the workspace structured JSON logger."""

from __future__ import annotations

import io
import json

from tmpl_prefix_core import Logger
from tmpl_prefix_telemetry import init
from tmpl_prefix_telemetry.logger import (
    TmplPrefixLogger,
)


def test_structured_logger_emits_json_and_binds_child_fields() -> None:
    """Verify JSON formatting and bound context propagation across child loggers."""
    buf = io.StringIO()
    logger = init(
        level="DEBUG",
        service_name="tmpl-prefix-test",
        stream=buf,
    )
    assert isinstance(logger, Logger)
    assert isinstance(
        logger,
        TmplPrefixLogger,
    )

    child = logger.bind(request_id="req-123", component="accounts")
    child.info("account created", account_id="acc-1")
    child.debug("debug trace", step=2)

    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["level"] == "INFO"
    expected_service = "tmpl-prefix-test"
    assert first["service"] == expected_service
    assert first["message"] == "account created"
    assert first["request_id"] == "req-123"
    assert first["component"] == "accounts"
    assert first["account_id"] == "acc-1"
    assert "timestamp" in first

    second = json.loads(lines[1])
    assert second["level"] == "DEBUG"
    assert second["step"] == 2
    assert second["request_id"] == "req-123"
