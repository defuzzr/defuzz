"""HTTP server port protocol and route type definitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

Response = tuple[int, Mapping[str, object]]
RouteHandler = Callable[[], Awaitable[Response]]
Routes = Mapping[str, RouteHandler]


@dataclass(frozen=True, slots=True)
class BoundAddress:
    """Resolved TCP host and port bound by an HTTP server."""

    host: str
    port: int


@runtime_checkable
class HttpServer(Protocol):
    """Port seam implemented by HTTP server adapters."""

    async def listen(self, host: str, port: int) -> BoundAddress:
        """Bind to the given address and begin serving HTTP requests."""
        ...

    async def close(self) -> None:
        """Stop serving requests and release the bound socket."""
        ...


TmplPrefixBoundAddress = BoundAddress
TmplPrefixHttpServer = HttpServer
