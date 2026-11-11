"""Unit and integration tests for the workspace."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from urllib.request import urlopen

import pytest

from tmpl_prefix_config import ENV_PREFIX
from tmpl_prefix_server import (
    build_application,
    run,
)
from tmpl_prefix_server.main import run_async
from tmpl_prefix_server.wiring import (
    TmplPrefixApplication,
)

if TYPE_CHECKING:
    from tmpl_prefix_config import HttpAdapter


@pytest.mark.parametrize("adapter", ["fastapi", "stdlib"])
def test_server_check_flag_succeeds_for_both_adapters(
    adapter: HttpAdapter,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --check starts the registry, outputs healthy JSON, and returns 0."""
    code = run(["--check", "--http", adapter], env={})
    assert code == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out.strip())
    assert report["status"] == "healthy"
    assert report["serving"] is True
    assert "accounts" in report["components"]


def test_build_application_honours_env_port_and_adapter() -> None:
    """Verify prefixed HTTP port and adapter settings wire into the application."""
    env = {
        f"{ENV_PREFIX}HTTP__PORT": "19090",
        f"{ENV_PREFIX}HTTP__ADAPTER": "stdlib",
    }
    app = build_application(env=env)
    assert isinstance(
        app,
        TmplPrefixApplication,
    )
    assert app.settings.http.port == 19090
    assert app.settings.http.adapter == "stdlib"


async def test_server_serves_health_live_and_ready_routes() -> None:
    """Verify live server responds to /health, /live, and /ready then stops cleanly."""
    app = build_application(
        env={f"{ENV_PREFIX}HTTP__PORT": "0", f"{ENV_PREFIX}HTTP__ADAPTER": "stdlib"},
    )
    await app.registry.start(app.context)
    try:
        bound = await app.http_server.listen("127.0.0.1", 0)
        try:
            for route in ("/health", "/live", "/ready"):
                url = f"http://{bound.host}:{bound.port}{route}"
                status, payload = await asyncio.to_thread(_get_json, url)
                assert status == 200
                assert isinstance(payload, dict)
        finally:
            await app.http_server.close()
    finally:
        await app.registry.stop()


async def test_run_async_stops_when_stop_event_is_set() -> None:
    """Verify _serve_until_stopped exits cleanly when stop_event triggers."""
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.call_later(0.05, stop_event.set)
    code = await run_async(
        ["--http", "stdlib"],
        env={f"{ENV_PREFIX}HTTP__PORT": "0"},
        stop_event=stop_event,
    )
    assert code == 0


def _get_json(url: str) -> tuple[int, dict[str, object]]:
    with urlopen(url, timeout=5.0) as resp:  # noqa: S310
        body: dict[str, object] = json.loads(resp.read().decode("utf-8"))
        return int(resp.status), body
