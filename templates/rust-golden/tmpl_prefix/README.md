# tmpl-prefix

Rust command-line project with separate code layers.

Tools: Rust, Cargo, rustfmt and Clippy.
Minimum versions are in `TOOLS.lock`.

Run all checks: `cargo xtask ci`

- Code: `foundation/`, `domain/`, `adapters/`, `apps/`.
- Tests: inline `#[cfg(test)]` modules beside the code.
- Scripts: `.sh`, `.bash` and `.ps1` go in `scripts/` (created as needed).

Template: MIT, Copyright (c) 2026 defuzzr. Choose your project's licence.
