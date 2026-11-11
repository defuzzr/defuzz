"""Standard-library ThreadingHTTPServer implementation of the HttpServer port."""

from __future__ import annotations

import asyncio
import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from tmpl_prefix_core import (
    AppError,
    BoundAddress,
    HttpServer,
    Response,
    RouteHandler,
    Routes,
)

_HANDLER_TIMEOUT_SECONDS: float = 5.0


async def _invoke_route(handler: RouteHandler) -> Response:
    """Await a RouteHandler inside a concrete coroutine for run_coroutine_threadsafe."""
    return await handler()


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with immediate address reuse enabled."""

    allow_reuse_address = True
    daemon_threads = True


def _build_handler_class(
    routes: dict[str, RouteHandler],
    loop: asyncio.AbstractEventLoop,
) -> type[BaseHTTPRequestHandler]:
    """Create a request handler class bound to the route table and event loop."""

    class _RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed_path = urlsplit(self.path).path
            route_handler = routes.get(parsed_path)
            if route_handler is None:
                self._write_json(int(HTTPStatus.NOT_FOUND), {"detail": "Not Found"})
                return

            try:
                future = asyncio.run_coroutine_threadsafe(
                    _invoke_route(route_handler),
                    loop,
                )
                status_code, body = future.result(timeout=_HANDLER_TIMEOUT_SECONDS)
            except Exception as exc:  # noqa: BLE001
                self._write_json(
                    int(HTTPStatus.INTERNAL_SERVER_ERROR),
                    {"detail": str(exc)},
                )
                return

            self._write_json(status_code, dict(body))

        def _write_json(self, status_code: int, payload: dict[str, object]) -> None:
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Suppress default stderr access logging from BaseHTTPRequestHandler."""
            _ = (format, args)

    return _RequestHandler


class StdlibHttpServer(HttpServer):
    """Zero-dependency HTTP server running ThreadingHTTPServer on a background thread."""

    def __init__(self, routes: Routes) -> None:
        """Initialize the stdlib HTTP server adapter with the given route table."""
        self._routes: dict[str, RouteHandler] = dict(routes)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    async def listen(self, host: str, port: int) -> BoundAddress:
        """Bind ThreadingHTTPServer and serve requests on a background thread."""
        if self._httpd is not None:
            raise AppError(
                kind="conflict",
                message="StdlibHttpServer is already listening",
            )

        loop = asyncio.get_running_loop()
        handler_cls = _build_handler_class(self._routes, loop)
        httpd = _ReusableThreadingHTTPServer((host, port), handler_cls)
        raw_addr = httpd.server_address
        bound_host = str(raw_addr[0])
        bound_port = int(raw_addr[1])

        thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="tmpl-prefix-http-stdlib",
            daemon=True,
        )
        thread.start()

        self._httpd = httpd
        self._thread = thread
        return BoundAddress(host=bound_host, port=bound_port)

    async def close(self) -> None:
        """Stop the serve loop, close the listening socket, and join the thread."""
        httpd = self._httpd
        thread = self._thread
        self._httpd = None
        self._thread = None

        if httpd is not None:
            await asyncio.to_thread(httpd.shutdown)
            httpd.server_close()
        if thread is not None:
            await asyncio.to_thread(thread.join, _HANDLER_TIMEOUT_SECONDS)


TmplPrefixStdlibHttpServer = StdlibHttpServer
