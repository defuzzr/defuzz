# ADR 0001: Four-Layer Native pnpm Workspace Architecture

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

Growing TypeScript codebases frequently suffer from circular
dependencies, leaked I/O primitives inside domain logic, and heavy
third-party monorepo orchestrators.

## Decision

We organize `tmpl-prefix`
as a single native `pnpm` workspace monorepo
divided into four strict layers under `packages/`:

1. `foundation` (Layer 0): Shared primitives
   (`tmpl-prefix-core`,
   `tmpl-prefix-config`,
   `tmpl-prefix-telemetry`).
2. `domain` (Layer 1): Pure business models, ports, and services
   (`tmpl-prefix-accounts`).
3. `adapters` (Layer 2): Concrete I/O implementations
   (`tmpl-prefix-storage-memory`,
   `tmpl-prefix-http-hono`,
   `tmpl-prefix-http-node`).
4. `apps` (Layer 3): Composition roots and deployable entry points
   (`tmpl-prefix-server`,
   `tmpl-prefix-cli`).

Layer rules, manifest declarations, `tsconfig.json` project references,
and source imports are enforced by `pnpm xtask check` using zero
third-party dependencies.

## Consequences

- **Positive:** Compile-time isolation via `tsc -b`, deterministic
  dependency graph, zero external orchestrator lock-in.
- **Negative / Trade-offs:** New internal dependencies must be added to
  both `package.json` (`"workspace:*"`) and `tsconfig.json`
  (`references`), automated via `pnpm xtask`.
