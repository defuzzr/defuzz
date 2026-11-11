# ADR 0002: Dual FastAPI and Standard-Library HTTP Adapter Pair

- **Status**: Accepted
- **Date**: 2026-11-06

## Context

Services in `tmpl-prefix`
need a production ASGI stack out of the box
while keeping the application composition root decoupled from any
specific web framework and providing a zero-dependency reference
adapter.

## Decision

1. Define a minimal `HttpServer` Protocol in
   `tmpl-prefix-core`
   (`listen(host, port) -> BoundAddress`, `close()`).
2. Ship two interchangeable adapters in `packages/adapters/`:
   - `tmpl-prefix-http-fastapi`
     (`FastApiHttpServer`): runs FastAPI +
     Uvicorn in-process (`lifespan="off"`), used by default
     (`TMPL_PREFIX_HTTP__ADAPTER=fastapi`).
   - `tmpl-prefix-http-stdlib`
     (`StdlibHttpServer`): runs
     `http.server.ThreadingHTTPServer` on a background thread and
     schedules async route coroutines onto the owning event loop via
     `asyncio.run_coroutine_threadsafe`.
3. Verify both adapters against a single parametrized contract test
   (`packages/adapters/tests/test_http_contract.py`) and smoke-test both
   in `uv run xtask ci`.

## Consequences

- **Positive**: Proves the port/adapter seam with two genuinely distinct
  runtimes; enables zero-dependency smoke testing and serves as the
  canonical playbook example for adding new adapters.
- **Negative / Trade-offs**: Both adapters must be maintained in
  lockstep with the `HttpServer` Protocol.
