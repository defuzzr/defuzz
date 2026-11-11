# ADR 0001: Four-Layer `uv` Workspace Architecture

- **Status**: Accepted
- **Date**: 2026-11-06

## Context

Growing Python repositories frequently suffer from circular imports,
domain logic coupled to web frameworks or database drivers, and
inconsistent dependency bounds across packages.

## Decision

1. Organize all deployables and libraries into a single native `uv`
   workspace under four strict layers:
   - `foundation` (Layer 0):
     `tmpl-prefix-core`,
     `tmpl-prefix-config`,
     `tmpl-prefix-telemetry`
   - `domain` (Layer 1):
     `tmpl-prefix-accounts`
   - `adapters` (Layer 2):
     `tmpl-prefix-storage-memory`,
     `tmpl-prefix-http-fastapi`,
     `tmpl-prefix-http-stdlib`
   - `apps` (Layer 3):
     `tmpl-prefix-server`,
     `tmpl-prefix-cli`
2. Enforce the downward dependency rule
   (`foundation <= domain <= adapters <= apps`, acyclic same-layer
   dependencies, independent apps) using two independent tools:
   `uv run xtask check` (manifest + AST scanner + cycle detector) and
   `uv run lint-imports` (`import-linter`).
3. Pin approved third-party version ranges in root
   `[tool.uv].constraint-dependencies` and verify in `xtask check` that
   any package opting into a third-party dependency copies the exact
   catalogue range.

## Consequences

- **Positive**: Domain logic remains pure and testable without I/O;
  published wheel metadata carries explicit version bounds;
  architectural drift fails CI immediately.
- **Negative / Trade-offs**: Adding a new package requires registering
  it in root `pyproject.toml` (automated via
  `uv run xtask new-package`).
