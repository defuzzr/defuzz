"""CLI entrypoint and signal-managed run loop for the workspace."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from typing import TYPE_CHECKING, cast

from tmpl_prefix_core import AppError
from tmpl_prefix_server.wiring import (
    Application,
    build_application,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from tmpl_prefix_config import HttpAdapter


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for the server binary."""
    parser = argparse.ArgumentParser(
        prog="tmpl-prefix-server",
        description="Run the HTTP server or execute a lifecycle health check.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Start the component registry, emit the health report as JSON, stop, and exit.",
    )
    parser.add_argument(
        "--http",
        choices=["fastapi", "stdlib"],
        default=None,
        help="Override the HTTP server adapter (fastapi or stdlib).",
    )
    return parser


async def _run_check(app: Application) -> int:
    """Start registry, write JSON health report to stdout, stop, and return exit code."""
    await app.registry.start(app.context)
    try:
        report = await app.registry.report()
        serving = app.registry.is_serving()
    finally:
        await app.registry.stop()

    sys.stdout.write(json.dumps(report) + "\n")
    sys.stdout.flush()
    return 0 if serving else 1


def _install_signal_handlers(
    loop: asyncio.AbstractEventLoop,
    stop_event: asyncio.Event,
) -> None:
    """Register SIGINT and SIGTERM handlers on POSIX event loops.

    On Windows, ``loop.add_signal_handler`` raises ``NotImplementedError``; in
    that environment ``signal.signal`` is registered as a fallback so Ctrl+C
    still triggers graceful shutdown.
    """
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            signal.signal(sig, lambda _s, _f: loop.call_soon_threadsafe(stop_event.set))


async def _serve_until_stopped(
    app: Application,
    stop_event: asyncio.Event | None = None,
) -> int:
    """Start components and HTTP server, wait for shutdown signal, and stop cleanly."""
    shutdown_signal = stop_event if stop_event is not None else asyncio.Event()
    loop = asyncio.get_running_loop()
    if stop_event is None:
        _install_signal_handlers(loop, shutdown_signal)

    await app.registry.start(app.context)
    try:
        bound = await app.http_server.listen(
            app.settings.http.host,
            app.settings.http.port,
        )
        app.context.logger.info(
            "http server listening",
            host=bound.host,
            port=bound.port,
            adapter=app.settings.http.adapter,
        )
        try:
            await shutdown_signal.wait()
        finally:
            await app.http_server.close()
    finally:
        await app.registry.stop()
    return 0


async def run_async(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stop_event: asyncio.Event | None = None,
) -> int:
    """Execute the server command asynchronously and return an exit status code."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else [])
    adapter_override = cast("HttpAdapter", args.http) if isinstance(args.http, str) else None

    try:
        app = build_application(
            env=env,
            http_adapter_override=adapter_override,
        )
        if args.check:
            return await _run_check(app)
        return await _serve_until_stopped(app, stop_event=stop_event)
    except AppError as exc:
        sys.stderr.write(json.dumps(exc.to_dict()) + "\n")
        sys.stderr.flush()
        return 1


def run(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> int:
    """Synchronous wrapper around ``run_async`` returning an exit status code."""
    return asyncio.run(run_async(argv, env=env))


def main() -> None:
    """Process entrypoint invoked by the ``the workspace`` console script."""
    sys.exit(run(sys.argv[1:]))
