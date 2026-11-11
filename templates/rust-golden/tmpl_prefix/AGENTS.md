# AGENTS.md

`tmpl-prefix` is a Rust
workspace template organized as a strict
four-layer architecture (`foundation`, `domain`, `adapters`, `apps`)
with an `xtask` automation runner. Each layer starts as a minimal shell
ready for project-specific code.

## Workspace Layout

| Directory | Crate | Role | Allowed Internal Dependencies |
| --- | --- | --- | --- |
| `foundation/` | `tmpl-prefix-foundation` | Shared primitives and workspace error types (`Error`, `Result`) | None |
| `domain/` | `tmpl-prefix-domain` | Pure business logic with no I/O | `foundation` |
| `adapters/` | `tmpl-prefix-adapters` | External boundaries and integration adapters | `foundation`, `domain` |
| `apps/cli/` | `tmpl-prefix-cli` | Composition root and binary entrypoint (`tmpl-prefix`) | `foundation`, `domain`, `adapters` |
| `xtask/` | `xtask` | Workspace automation (`ci`, `fmt`, `layers`, `bump-msrv`) | None (standalone tool) |

## Conventions & Constraints

- **Layer dependency rule**: Dependency direction is strictly
  `foundation < domain < adapters < apps`. Library crates may never
  depend on higher layers or `apps`. Enforced automatically by
  `cargo xtask layers`.
- **Standard-library only**: Library and application crates
  (`foundation`, `domain`, `adapters`, `apps/*`) must remain `std`-only
  unless explicitly approved; only `xtask` uses `toml` and `serde`.
- **No unsafe code**: `unsafe_code = "forbid"` is set at the workspace
  level.
- **Explicit configuration over process mutation**: Never mutate process
  environment at runtime or in tests; read configuration at the
  composition root (`apps/`) and pass typed values explicitly into lower
  layers.
- **Errors as types**: Define structured error enums in `foundation`
  implementing `std::error::Error` and `Display`. Avoid `.unwrap()` and
  `.expect()` in production code (allowed in `#[cfg(test)]` via
  `clippy.toml`).
- **Workspace-wide lints**: Every crate inherits
  `[lints] workspace = true`. Do not add local `#[allow(...)]`
  attributes without an inline comment explaining why the suppression is
  necessary.
- **Where new files go**: notes and diagrams (`.md`, `.rst`, `.adoc`,
  `.mmd`, `.puml`, `.drawio`) go in `docs/`. Root shell and PowerShell
  scripts (`.sh`, `.bash`, `.ps1`) move to `scripts/`. Rust sources and
  tests go in the `src/` or `tests/` folder of the one crate they belong
  to; a file written at the root is not moved for you.
- **Reusable workflows**: Keep multi-step operational procedures in
  dedicated skills rather than expanding this file.
- **Template placeholder**: The scaffolder renames
  `tmpl-prefix` across
  all case forms
  (`tmpl-prefix` /
  `tmpl_prefix` /
  `TMPL_PREFIX` /
  `TmplPrefix`).

## Build & Verification Commands

- `cargo build --workspace` — compile all workspace crates.
- `cargo test --workspace --locked` — run unit and documentation tests
  across all layers.
- `cargo xtask fmt` — format all workspace crates with `rustfmt`.
- `cargo xtask layers` — verify crate dependency directions against the
  layer hierarchy.
- `cargo xtask bump-msrv <ver>` — rewrite `rust-version` (`Cargo.toml`),
  `msrv` (`clippy.toml`), and the MSRV CI job
  (`.github/workflows/ci.yml`), then verify with
  `cargo +<ver> check --workspace --all-targets --locked` (rolling back
  all three files on failure; see `00-INDEX.md` §11).
- `cargo xtask ci` — run the full CI gate (`fmt --check`,
  `clippy -D warnings`, `test`, and `layers`).
