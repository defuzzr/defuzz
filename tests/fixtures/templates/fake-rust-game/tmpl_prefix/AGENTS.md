# tmpl-prefix

## Purpose
Minimal Bevy game workspace (`tmpl_prefix`).

## Layout
- `src/` — game entry point
- `tmpl_prefix_core/` — core library crate
- `assets/` — binary game assets

## Conventions & constraints
- Keep core logic in `tmpl_prefix_core` independent of engine adapters.

## Build & test
```
cargo check
```
