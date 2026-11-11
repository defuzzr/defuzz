# AGENTS.md

`tmpl-prefix`
is a Go workspace template organized as a strict four-layer architecture
(`foundation`, `domain`, `adapters`, `apps`) with an `xtask` automation
runner. Each layer starts as a minimal package ready for project-specific
code.

## Workspace Layout

| Directory | Package | Role | Allowed Internal Dependencies |
| --- | --- | --- | --- |
| `foundation/` | `foundation` | Shared primitives and workspace error types | None |
| `domain/` | `domain` | Pure business logic with no external I/O | `foundation` |
| `adapters/` | `adapters` | External boundaries and integration adapters | `foundation`, `domain` |
| `apps/cli/` | `main` | Composition root and CLI entrypoint | `foundation`, `domain`, `adapters` |
| `xtask/` | `main` | Workspace automation (`ci`, `fmt`, `layers`) | None (standalone tool) |

## Conventions & Constraints

- **Layer dependency rule**: Dependency direction is strictly
  `foundation < domain < adapters < apps`. Lower layers may never import
  higher layers or `apps`. Enforced automatically by `go run ./xtask layers`.
- **Standard-library first**: Packages remain standard-library only unless
  explicitly approved in `template.yaml` and `go.mod`.
- **Explicit configuration**: Read environment variables at the composition
  root (`apps/`) and pass typed values explicitly into lower layers.
- **Errors as values**: Return structured errors from `foundation` rather
  than panicking in library or domain code.
- **Where new files go**: notes and diagrams (`.md`, `.rst`, `.adoc`,
  `.mmd`, `.puml`, `.drawio`) go in `docs/`. Root shell and PowerShell
  scripts (`.sh`, `.bash`, `.ps1`) move to `scripts/`. Put `*.go` and
  `*_test.go` files in the package folder they belong to; a root write
  is not moved for you.
- **Template placeholder**: The scaffolder renames the prefix across all
  four case forms:
  `tmpl-prefix`
  `tmpl_prefix`
  `TMPL_PREFIX`
  `TmplPrefix`

## Build & Verification Commands

- `go build ./...` — compile all workspace packages.
- `go test ./...` — run unit tests across all layers.
- `go run ./xtask fmt` — format all Go files with `gofmt`.
- `go run ./xtask layers` — verify package import directions against the
  layer hierarchy.
- `go run ./xtask ci` — run the full CI gate (`gofmt -e -l`, `go vet`,
  `golangci-lint`, `go build`, `go test`, and `layers`).
