# ADR 0002: Dual HTTP Adapter Pair (`http-hono` and `http-node`)

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

Services need a clean port seam for HTTP routing so business logic and
lifecycle management do not couple to a specific web framework, and
developers need a concrete reference example for adding and
contract-testing adapters.

## Decision

We define the `HttpServer` port in
`tmpl-prefix-core` and ship
two
interchangeable adapters in `packages/adapters/`:

- `tmpl-prefix-http-hono`
  (default): Built on `hono` and
  `@hono/node-server` from the workspace catalogue.
- `tmpl-prefix-http-node`:
  Built exclusively on Node's standard
  `node:http` module with zero external dependencies.

Both adapters are verified against a shared contract test
(`http-contract.test.ts`) and exercised in `pnpm xtask ci` via
`--check --http node` and `--check --http hono`. Selection at runtime is
controlled by
`TMPL_PREFIX_HTTP_ADAPTER`
(`"hono" | "node"`).

## Consequences

- **Positive:** Proves port/adapter substitutability on every CI run and
  provides a copy-pasteable pattern for database or queue adapters.
- **Negative / Trade-offs:** Changes to the `HttpServer` port interface
  must be implemented in both adapters.
