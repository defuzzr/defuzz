"""Runtime component protocol, execution context, and lifecycle registry."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from tmpl_prefix_core.error import AppError

HealthStatus = Literal["healthy", "degraded", "unhealthy"]


@dataclass(frozen=True, slots=True)
class Health:
    """Point-in-time health status reported by a runtime component."""

    status: HealthStatus
    reason: str | None = None


@runtime_checkable
class Logger(Protocol):
    """Structured logger protocol used across all layers."""

    def debug(self, message: str, **fields: object) -> None:
        """Emit a debug-level log entry."""
        ...

    def info(self, message: str, **fields: object) -> None:
        """Emit an info-level log entry."""
        ...

    def warning(self, message: str, **fields: object) -> None:
        """Emit a warning-level log entry."""
        ...

    def error(self, message: str, **fields: object) -> None:
        """Emit an error-level log entry."""
        ...

    def bind(self, **fields: object) -> Logger:
        """Return a child logger with additional bound context fields."""
        ...


@dataclass(frozen=True, slots=True)
class Context:
    """Immutable runtime context passed to components during startup."""

    environment: str
    service_name: str
    logger: Logger


@runtime_checkable
class Component(Protocol):
    """Lifecycle unit managed by the application registry."""

    @property
    def name(self) -> str:
        """Unique identifier for this component within a registry."""
        ...

    async def start(self, ctx: Context) -> None:
        """Start the component using the given runtime context."""
        ...

    async def stop(self) -> None:
        """Stop the component and release any held resources."""
        ...

    async def health(self) -> Health:
        """Inspect and return current component health."""
        ...


class Registry:
    """Ordered component lifecycle manager with reverse rollback on failure."""

    def __init__(self) -> None:
        """Initialize an empty component registry."""
        self._components: list[Component] = []
        self._by_name: dict[str, Component] = {}
        self._started: list[Component] = []
        self._running: bool = False
        self._last_unhealthy: bool = False

    @property
    def components(self) -> tuple[Component, ...]:
        """Return registered components in registration order."""
        return tuple(self._components)

    def register(self, component: Component) -> None:
        """Register a component with a unique name.

        Args:
            component: Component instance to manage.

        Raises:
            AppError: If a component with the same name is already registered.
        """
        if component.name in self._by_name:
            raise AppError(
                kind="conflict",
                message=f"Component '{component.name}' is already registered",
                details={"component": component.name},
            )
        self._components.append(component)
        self._by_name[component.name] = component

    async def start(self, ctx: Context) -> None:
        """Start all registered components in registration order.

        If any component raises an exception or is cancelled during startup,
        already-started components are stopped in reverse order before the
        original error is re-raised.

        Args:
            ctx: Runtime execution context.
        """
        started: list[Component] = []
        try:
            for comp in self._components:
                ctx.logger.info("starting component", component=comp.name)
                await comp.start(ctx)
                started.append(comp)
        except BaseException:
            await self._rollback(started, ctx)
            self._started = []
            self._running = False
            raise
        self._started = started
        self._running = True
        self._last_unhealthy = False

    async def _rollback(self, started: list[Component], ctx: Context) -> None:
        """Stop already-started components in reverse order during failed start."""
        for comp in reversed(started):
            err_msg: str | None = None
            try:
                ctx.logger.warning("rolling back component", component=comp.name)
                await asyncio.shield(comp.stop())
            except Exception as exc:  # noqa: BLE001
                err_msg = str(exc)
            if err_msg is not None:
                ctx.logger.error(
                    "component rollback failed",
                    component=comp.name,
                    error=err_msg,
                )

    async def stop(self) -> None:
        """Stop all started components in reverse registration order."""
        to_stop = list(reversed(self._started))
        self._started = []
        self._running = False
        first_error: Exception | None = None
        for comp in to_stop:
            try:
                await comp.stop()
            except Exception as exc:  # noqa: BLE001
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def is_serving(self) -> bool:
        """Return whether the registry is started and not known to be unhealthy."""
        return self._running and not self._last_unhealthy

    async def report(self) -> dict[str, object]:
        """Collect health statuses from all registered components."""
        if not self._running:
            self._last_unhealthy = True
            return {
                "status": "unhealthy",
                "serving": False,
                "components": {},
            }

        overall: HealthStatus = "healthy"
        details: dict[str, object] = {}
        for comp in self._components:
            comp_health = await comp.health()
            details[comp.name] = {
                "status": comp_health.status,
                "reason": comp_health.reason,
            }
            if comp_health.status == "unhealthy":
                overall = "unhealthy"
            elif comp_health.status == "degraded" and overall == "healthy":
                overall = "degraded"

        self._last_unhealthy = overall == "unhealthy"
        return {
            "status": overall,
            "serving": self.is_serving(),
            "components": details,
        }


TmplPrefixHealth = Health
TmplPrefixLogger = Logger
TmplPrefixContext = Context
TmplPrefixComponent = Component
TmplPrefixRegistry = Registry
