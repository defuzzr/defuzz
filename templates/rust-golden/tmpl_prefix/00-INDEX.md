# 00 — Index: How This Workspace Works

> Master reference for the
> `tmpl-prefix` layered
> Rust workspace
> (`foundation` -> `domain` -> `adapters` -> `apps/cli`) and
> `cargo xtask` automation.

## 1. Quick start

```sh
cargo xtask ci
cargo xtask layers
cargo xtask fmt
cargo run --bin tmpl-prefix
```

## 2. Folder map

```text
.
├── 00-INDEX.md                 ← master workspace guide
├── AGENTS.md                   ← concise agent conventions & commands
├── README.md                   ← quick start
├── Cargo.toml
    workspace root: members, dependencies, lints, MSRV (1.88)
├── Cargo.lock                  ← reproducible dependency lockfile
├── clippy.toml                 ← clippy thresholds & MSRV (1.88.0)
├── rustfmt.toml                ← edition & style_edition 2024
├── rust-toolchain.toml
    channel = "stable" (components: rustfmt, clippy)
├── .cargo/config.toml          ← cargo alias `xtask`
├── .github/workflows/ci.yml
    CI (`cargo xtask ci`) + MSRV (`cargo +1.88 check`)
├── foundation/
    Layer 0: shared primitives & error types (`tmpl-prefix-foundation`)
├── domain/
    Layer 1: pure business logic (`tmpl-prefix-domain`)
├── adapters/
    Layer 2: external I/O & integration boundaries
    (`tmpl-prefix-adapters`)
├── apps/cli/
    Layer 3: composition root & binary (`tmpl-prefix-cli`)
├── scripts/
    shell and PowerShell helper scripts (created on first use)
└── xtask/
    workspace automation (`ci`, `fmt`, `layers`, `bump-msrv`)
```

## 3. The four layers

| Layer | Path | Crate | Allowed internal dependencies |
| --- | --- | --- | --- |
| **foundation** | `foundation/` | `tmpl-prefix-foundation` | None |
| **domain** | `domain/` | `tmpl-prefix-domain` | `foundation` |
| **adapters** | `adapters/` | `tmpl-prefix-adapters` | `foundation`, `domain` |
| **apps** | `apps/cli/` | `tmpl-prefix-cli` | `foundation`, `domain`, `adapters` |

`cargo xtask layers` parses all workspace manifests and enforces
`foundation < domain < adapters < apps`.

## 4. Modules vs components

Each crate in `foundation/`, `domain/`, `adapters/`, and `apps/` is a
compile-time Cargo boundary inheriting `[lints] workspace = true`. Keep
domain crates `std`-only and free of I/O.

## 5. Anatomy of a domain module

Domain crates expose pure functions and types over
`tmpl_prefix_foundation::Error`
and
`tmpl_prefix_foundation::Result`
without depending on adapters
or environment variables.

## 6. Configuration

Read configuration and environment variables at the composition root
(`apps/`) and pass typed values explicitly into adapters and domain
functions. Never call `std::env::set_var` or `std::env::remove_var`.

## 7. Adding crates and dependencies

1. Add new crates under the appropriate layer directory (`foundation/`,
   `domain/`, `adapters/`, or `apps/*`) and list them in root
   `Cargo.toml` `[workspace].members`.
2. Inherit workspace metadata and lints (`[lints] workspace = true`).
3. Run `cargo xtask ci` to verify formatting, clippy lints, tests, and
   layer boundaries.

Notes and diagrams written at the root (`.md`, `.rst`, `.adoc`, `.mmd`,
`.puml`, `.drawio`) are moved to `docs/`. Root shell and PowerShell
scripts (`.sh`, `.bash`, `.ps1`) move to `scripts/`. New Rust sources,
tests and data written at the root stay where they are: each belongs to
one crate, so put them in that crate's `src/` or `tests/` yourself.

## 8. Quality gates and CI

`.github/workflows/ci.yml` runs two jobs on every push and pull request:

- **CI (`ci`)**: `cargo xtask ci` (`cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`, and `cargo xtask layers`) on
  `stable`.
- **MSRV (`msrv`)**:
  `cargo +1.88 check --workspace --all-targets --locked` using the
  pinned minimum supported Rust version.

## 9. The `xtask` tool

| Subcommand | Purpose |
| --- | --- |
| `cargo xtask ci` | Run `fmt --check`, `clippy -D warnings`, `test`, and `layers`. |
| `cargo xtask fmt` | Format all workspace crates via `cargo fmt --all`. |
| `cargo xtask layers` | Verify workspace dependency direction rules. |
| `cargo xtask bump-msrv <ver>` | Update MSRV across `Cargo.toml`, `clippy.toml`, and `.github/workflows/ci.yml` and verify with `cargo +<ver> check --workspace --all-targets --locked`. |

## 10. Governance

All crates forbid `unsafe_code` at the workspace level and warn on
`unwrap_used`, `expect_used`, `dbg_macro`, `todo`, `unimplemented`, and
`exit` (with `allow-unwrap-in-tests` and `allow-expect-in-tests` enabled
in `clippy.toml`).

## 11. Releases, versioning, and bumping MSRV

`rust-toolchain.toml` stays on `channel = "stable"` so contributors and
beginners never trigger a second toolchain download during normal
development, while the MSRV floor (`1.88`) is enforced in `Cargo.toml`,
`clippy.toml`, and CI.

To raise or change the minimum supported Rust version in one step, run:

```sh
cargo xtask bump-msrv <ver>
```

`cargo xtask bump-msrv <ver>` (for example, `cargo xtask bump-msrv 1.88`
or `cargo xtask bump-msrv 1.89.0`):

1. Validates `<ver>` against `\d+\.\d+(\.\d+)?`.
2. Rewrites `[workspace.package] rust-version = "<ver>"` in
   `Cargo.toml`, `msrv = "<major.minor.patch>"` in `clippy.toml`, and
   the `msrv` job (`dtolnay/rust-toolchain@<ver>` +
   `cargo +<ver> check --workspace --all-targets --locked`) in
   `.github/workflows/ci.yml`.
3. Invokes `rustup run <ver> cargo` /
   `cargo +<ver> check --workspace --all-targets --locked` directly
   (ignoring `$CARGO` so the active stable cargo wrapper cannot mask the
   target toolchain).
4. If toolchain `<ver>` is not installed, prints
   `rustup toolchain install <ver>`, rolls back `Cargo.toml`,
   `clippy.toml`, and `.github/workflows/ci.yml` to their exact prior
   contents, and exits non-zero. If the check fails for any reason, all
   three files are rolled back automatically.
