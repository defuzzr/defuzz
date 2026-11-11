# Contributing to the workspace

Before opening a pull request, read [`00-INDEX.md`](./00-INDEX.md) for
the workspace architecture and playbooks.

## Architectural Rules

1. **Downward-only layer dependencies:**
   `foundation (0) <= domain (1) <= adapters (2) <= apps (3)`.
   Same-layer dependencies must be acyclic. Apps never depend on apps.
2. **Strict ESM & Erasable TypeScript:** Every package uses
   `"type": "module"`, `.js` relative import extensions,
   `--isolatedDeclarations`, and `--erasableSyntaxOnly` (no `any`, `!`,
   `enum`, `namespace`, or parameter properties).
3. **Typed Configuration:** Environment variables
   (`TMPL_PREFIX_*`) are
   parsed only in
   `tmpl-prefix-config`.
4. **Workspace Catalogue:** Third-party packages must be declared in
   root `pnpm-workspace.yaml` under `catalog:` and referenced with
   `"catalog:"`.

## Verification Gate

Every change must pass the full CI suite locally with zero warnings:

```bash
pnpm xtask ci
```
