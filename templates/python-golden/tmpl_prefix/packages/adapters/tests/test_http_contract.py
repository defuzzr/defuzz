"""Shared contract tests parametrized across FastAPI and stdlib HTTP adapters."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest

from tmpl_prefix_http_fastapi import (
    FastApiHttpServer,
)
from tmpl_prefix_http_stdlib import (
    StdlibHttpServer,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tmpl_prefix_core import (
        HttpServer,
        Response,
        Routes,
    )

_REQUEST_TIMEOUT_SECONDS: float = 5.0


def _fetch_sync(url: str) -> tuple[int, dict[str, object]]:
    """Perform a blocking HTTP GET with a bounded 5 s timeout."""
    try:
        with urlopen(url, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
            parsed: dict[str, object] = json.loads(raw)
            return int(resp.status), parsed
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        parsed_err: dict[str, object] = json.loads(raw)
        return int(exc.code), parsed_err


async def _fetch(url: str) -> tuple[int, dict[str, object]]:
    """Run blocking urllib request on a worker thread so the event loop stays free."""
    return await asyncio.to_thread(_fetch_sync, url)


def _sample_routes() -> Routes:
    """Build deterministic routes returning 200 and 503 JSON payloads."""

    async def _health() -> Response:
        await asyncio.sleep(0)
        return 200, {"status": "healthy", "serving": True}

    async def _ready() -> Response:
        await asyncio.sleep(0)
        return 503, {"status": "unhealthy", "serving": False}

    return {
        "/health": _health,
        "/ready": _ready,
    }


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(FastApiHttpServer, id="fastapi"),
        pytest.param(StdlibHttpServer, id="stdlib"),
    ],
)
async def test_http_adapter_contract(factory: Callable[[Routes], HttpServer]) -> None:
    """Verify both adapters serve identical status/JSON and release their port on close."""
    server = factory(_sample_routes())
    bound = await server.listen("127.0.0.1", 0)
    assert bound.host == "127.0.0.1"
    assert bound.port > 0

    base_url = f"http://{bound.host}:{bound.port}"
    try:
        status_ok, body_ok = await _fetch(f"{base_url}/health")
        assert status_ok == 200
        assert body_ok == {"status": "healthy", "serving": True}

        status_unready, body_unready = await _fetch(f"{base_url}/ready")
        assert status_unready == 503
        assert body_unready == {"status": "unhealthy", "serving": False}

        status_missing, body_missing = await _fetch(f"{base_url}/missing")
        assert status_missing == 404
        assert body_missing == {"detail": "Not Found"}
    finally:
        await server.close()

    # Verify the port is no longer serving and can be rebound immediately.
    with pytest.raises(URLError):
        await _fetch(f"{base_url}/health")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((bound.host, bound.port))
