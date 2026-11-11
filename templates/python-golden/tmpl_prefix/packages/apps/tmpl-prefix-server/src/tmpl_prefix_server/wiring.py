"""Composition root wiring settings, telemetry, domain services, and HTTP adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tmpl_prefix_accounts import (
    AccountsComponent,
    AccountService,
)
from tmpl_prefix_config import (
    HttpAdapter,
    Settings,
    load_settings,
)
from tmpl_prefix_core import (
    Context,
    HttpServer,
    Registry,
    Response,
    Routes,
)
from tmpl_prefix_http_fastapi import (
    FastApiHttpServer,
)
from tmpl_prefix_http_stdlib import (
    StdlibHttpServer,
)
from tmpl_prefix_storage_memory import (
    InMemoryAccountRepository,
)
from tmpl_prefix_telemetry import (
    init as init_logger,
)

# @xtask:component-imports

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class Application:
    """Wired server application bundle."""

    settings: Settings
    context: Context
    registry: Registry
    account_service: AccountService
    http_server: HttpServer


def _build_routes(registry: Registry) -> Routes:
    """Build standard health, liveness, and readiness routes backed by the registry."""

    async def _health() -> Response:
        report = await registry.report()
        status_code = 200 if registry.is_serving() else 503
        return status_code, report

    async def _live() -> Response:
        return 200, {"status": "alive"}

    async def _ready() -> Response:
        report = await registry.report()
        status_code = 200 if registry.is_serving() else 503
        return status_code, report

    return {
        "/health": _health,
        "/live": _live,
        "/ready": _ready,
    }


def _select_http_server(adapter: HttpAdapter, routes: Routes) -> HttpServer:
    """Instantiate the configured HTTP server adapter."""
    if adapter == "stdlib":
        return StdlibHttpServer(routes)
    return FastApiHttpServer(routes)


def build_application(
    *,
    env: Mapping[str, str] | None = None,
    http_adapter_override: HttpAdapter | None = None,
) -> Application:
    """Compose the full server application graph.

    Args:
        env: Optional explicit environment mapping for configuration loading.
        http_adapter_override: Optional CLI override for ``settings.http.adapter``.

    Returns:
        Wired ``Application`` instance ready to start.
    """
    settings = load_settings(env)
    if http_adapter_override is not None:
        settings = settings.model_copy(
            update={
                "http": settings.http.model_copy(
                    update={"adapter": http_adapter_override},
                ),
            },
        )

    logger = init_logger(
        level=settings.log.level,
        service_name=settings.service_name,
    )
    context = Context(
        environment=settings.environment,
        service_name=settings.service_name,
        logger=logger,
    )

    repo = InMemoryAccountRepository()
    account_service = AccountService(repo)

    registry = Registry()
    registry.register(AccountsComponent(account_service))
    # @xtask:register-components

    routes = _build_routes(registry)
    http_server = _select_http_server(settings.http.adapter, routes)

    return Application(
        settings=settings,
        context=context,
        registry=registry,
        account_service=account_service,
        http_server=http_server,
    )


TmplPrefixApplication = Application
