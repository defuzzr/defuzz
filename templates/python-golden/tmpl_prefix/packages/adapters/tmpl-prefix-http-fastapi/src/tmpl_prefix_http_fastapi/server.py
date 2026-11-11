"""FastAPI + Uvicorn implementation of the HttpServer port."""

from __future__ import annotations

import asyncio
import socket
from contextlib import suppress
from typing import TYPE_CHECKING

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from tmpl_prefix_core import (
    AppError,
    BoundAddress,
    HttpServer,
    RouteHandler,
    Routes,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


def _make_endpoint(
    handler: RouteHandler,
) -> Callable[[], Coroutine[object, object, JSONResponse]]:
    """Wrap a port RouteHandler into a FastAPI endpoint function."""

    async def _endpoint() -> JSONResponse:
        status_code, body = await handler()
        return JSONResponse(status_code=status_code, content=dict(body))

    return _endpoint


class _EmbeddedUvicornServer(uvicorn.Server):
    """Uvicorn Server subclass that leaves signal handling to the host process."""

    def install_signal_handlers(self) -> None:
        """Skip installing signal handlers when running embedded."""


class FastApiHttpServer(HttpServer):
    """In-process FastAPI and Uvicorn HTTP server adapter."""

    def __init__(self, routes: Routes) -> None:
        """Initialize the FastAPI server adapter with the given route table."""
        self._routes: dict[str, RouteHandler] = dict(routes)
        self._server: uvicorn.Server | None = None
        self._serve_task: asyncio.Task[None] | None = None
        self._socket: socket.socket | None = None

    async def listen(self, host: str, port: int) -> BoundAddress:
        """Bind a socket, start Uvicorn in-process, and return the bound address."""
        if self._serve_task is not None:
            raise AppError(
                kind="conflict",
                message="FastApiHttpServer is already listening",
            )

        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        for path, handler in self._routes.items():
            app.add_api_route(path, _make_endpoint(handler), methods=["GET"])

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(0.0)
        raw_addr = sock.getsockname()
        bound_host = str(raw_addr[0])
        bound_port = int(raw_addr[1])

        config = uvicorn.Config(
            app=app,
            host=bound_host,
            port=bound_port,
            lifespan="off",
            log_level="warning",
            access_log=False,
        )
        server = _EmbeddedUvicornServer(config)

        serve_task: asyncio.Task[None] = asyncio.create_task(
            server.serve(sockets=[sock]),
        )

        while not server.started:
            if serve_task.done():
                sock.close()
                exc = serve_task.exception()
                raise AppError(
                    kind="unavailable",
                    message="FastAPI server exited before startup completed",
                    cause=exc if isinstance(exc, Exception) else None,
                )
            await asyncio.sleep(0.005)

        self._socket = sock
        self._server = server
        self._serve_task = serve_task
        return BoundAddress(host=bound_host, port=bound_port)

    async def close(self) -> None:
        """Signal Uvicorn to exit, await task completion, and close the socket."""
        server = self._server
        serve_task = self._serve_task
        sock = self._socket
        self._server = None
        self._serve_task = None
        self._socket = None

        if server is not None:
            server.should_exit = True
        if serve_task is not None:
            with suppress(asyncio.CancelledError):
                await serve_task
        if sock is not None:
            with suppress(OSError):
                sock.close()


TmplPrefixFastApiHttpServer = (
    # Public prefixed alias for the stable implementation.
    FastApiHttpServer
)
