"""Foundation primitives, error taxonomy, component lifecycle, and HTTP seam."""

from __future__ import annotations

from tmpl_prefix_core.component import (
    Component,
    Context,
    Health,
    HealthStatus,
    Logger,
    Registry,
)
from tmpl_prefix_core.error import (
    AppError,
    ErrorKind,
)
from tmpl_prefix_core.http import (
    BoundAddress,
    HttpServer,
    Response,
    RouteHandler,
    Routes,
)

__all__ = [
    "AppError",
    "BoundAddress",
    "Component",
    "Context",
    "ErrorKind",
    "Health",
    "HealthStatus",
    "HttpServer",
    "Logger",
    "Registry",
    "Response",
    "RouteHandler",
    "Routes",
]
