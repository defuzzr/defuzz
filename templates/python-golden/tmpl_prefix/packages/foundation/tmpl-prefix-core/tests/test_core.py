"""Unit tests for the workspace error taxonomy and component registry."""

from __future__ import annotations

import asyncio

import pytest

from tmpl_prefix_core import (
    AppError,
    Component,
    Context,
    Health,
    Registry,
)
from tmpl_prefix_core.component import (
    TmplPrefixRegistry,
)
from tmpl_prefix_core.error import (
    TmplPrefixError,
)


class _RecordingLogger:
    """In-memory logger double for unit tests."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, str, dict[str, object]]] = []

    def debug(self, message: str, **fields: object) -> None:
        self.messages.append(("DEBUG", message, dict(fields)))

    def info(self, message: str, **fields: object) -> None:
        self.messages.append(("INFO", message, dict(fields)))

    def warning(self, message: str, **fields: object) -> None:
        self.messages.append(("WARNING", message, dict(fields)))

    def error(self, message: str, **fields: object) -> None:
        self.messages.append(("ERROR", message, dict(fields)))

    def bind(self, **fields: object) -> _RecordingLogger:
        _ = fields
        return self


class _FakeComponent:
    """Test component tracking start and stop ordering."""

    def __init__(
        self,
        name: str,
        events: list[str],
        *,
        fail_on_start: bool = False,
        cancel_on_start: bool = False,
        health_status: Health | None = None,
    ) -> None:
        self._name = name
        self._events = events
        self._fail_on_start = fail_on_start
        self._cancel_on_start = cancel_on_start
        self._health = health_status or Health(status="healthy")

    @property
    def name(self) -> str:
        return self._name

    async def start(self, ctx: Context) -> None:
        _ = ctx
        self._events.append(f"start:{self._name}")
        if self._cancel_on_start:
            raise asyncio.CancelledError
        if self._fail_on_start:
            raise AppError(kind="unavailable", message=f"{self._name} failed to start")

    async def stop(self) -> None:
        self._events.append(f"stop:{self._name}")

    async def health(self) -> Health:
        return self._health


def test_app_error_formatting_and_serialization() -> None:
    """Verify AppError string representation and JSON dictionary export."""
    root = ValueError("bad port")
    err = TmplPrefixError(
        kind="config",
        message="Invalid HTTP settings",
        cause=root,
        details={"field": "http.port"},
    )
    assert "config" in str(err)
    assert "bad port" in str(err)
    payload = err.to_dict()
    assert payload == {
        "kind": "config",
        "message": "Invalid HTTP settings",
        "details": {"field": "http.port"},
        "cause": "bad port",
    }


async def test_registry_starts_in_order_and_stops_in_reverse() -> None:
    """Verify components start in registration order and stop in reverse order."""
    events: list[str] = []
    registry = TmplPrefixRegistry()
    comp_a = _FakeComponent("alpha", events)
    comp_b = _FakeComponent("beta", events)
    comp_c = _FakeComponent("gamma", events)
    assert isinstance(comp_a, Component)

    registry.register(comp_a)
    registry.register(comp_b)
    registry.register(comp_c)

    ctx = Context(
        environment="test",
        service_name="tmpl-prefix-test",
        logger=_RecordingLogger(),
    )
    await registry.start(ctx)
    assert registry.is_serving() is True

    report = await registry.report()
    assert report["status"] == "healthy"
    assert report["serving"] is True

    await registry.stop()
    assert registry.is_serving() is False
    assert events == [
        "start:alpha",
        "start:beta",
        "start:gamma",
        "stop:gamma",
        "stop:beta",
        "stop:alpha",
    ]


async def test_registry_rolls_back_in_reverse_on_start_failure() -> None:
    """Verify already-started components stop in reverse order when start fails."""
    events: list[str] = []
    registry = Registry()
    registry.register(_FakeComponent("first", events))
    registry.register(_FakeComponent("second", events))
    registry.register(_FakeComponent("third", events, fail_on_start=True))
    registry.register(_FakeComponent("fourth", events))

    ctx = Context(
        environment="test",
        service_name="tmpl-prefix-test",
        logger=_RecordingLogger(),
    )
    with pytest.raises(AppError, match="third failed to start"):
        await registry.start(ctx)

    assert registry.is_serving() is False
    assert events == [
        "start:first",
        "start:second",
        "start:third",
        "stop:second",
        "stop:first",
    ]


async def test_registry_rolls_back_on_cancellation() -> None:
    """Verify cancellation during start still rolls back started components."""
    events: list[str] = []
    registry = Registry()
    registry.register(_FakeComponent("first", events))
    registry.register(_FakeComponent("second", events, cancel_on_start=True))

    ctx = Context(
        environment="test",
        service_name="tmpl-prefix-test",
        logger=_RecordingLogger(),
    )
    with pytest.raises(asyncio.CancelledError):
        await registry.start(ctx)

    assert registry.is_serving() is False
    assert events == [
        "start:first",
        "start:second",
        "stop:first",
    ]


def test_registry_rejects_duplicate_component_names() -> None:
    """Verify registering two components with the same name raises conflict AppError."""
    events: list[str] = []
    registry = Registry()
    registry.register(_FakeComponent("dup", events))
    with pytest.raises(AppError) as exc_info:
        registry.register(_FakeComponent("dup", events))
    assert exc_info.value.kind == "conflict"
