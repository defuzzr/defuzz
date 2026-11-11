# 00 — Index: How This Workspace Works

> Master reference for the
> `tmpl-prefix`
> layered Go workspace (`foundation` -> `domain` -> `adapters` -> `apps/cli`)
> and `go run ./xtask` automation.

## 1. Quick start

```sh
go run ./xtask ci
go run ./xtask layers
go run ./xtask fmt
go run ./apps/cli
```

## 2. Folder map

```text
.
├── 00-INDEX.md                 ← master workspace guide
├── AGENTS.md                   ← concise agent conventions & commands
├── COMPONENTS.md               ← reusable component index
├── README.md                   ← quick start
├── TOOLS.lock                  ← pinned Go and golangci-lint versions
├── go.mod                      ← module definition and Go version
├── go.sum                      ← reproducible module checksum file
├── .golangci.yml               ← golangci-lint v2 configuration
├── .github/workflows/ci.yml    ← CI workflow (`go run ./xtask ci`)
├── docs/
│   └── component-boundaries.md ← boundary rules for reusable logic
├── foundation/                 ← Layer 0: shared primitives & error types
├── domain/                     ← Layer 1: pure business logic
├── adapters/                   ← Layer 2: external I/O & integration adapters
├── apps/cli/                   ← Layer 3: composition root & CLI binary
├── scripts/                    ← shell and PowerShell helper scripts
└── xtask/                      ← workspace automation (`ci`, `fmt`, `layers`)
```

## 3. Naming forms

The scaffolder substitutes all four canonical case forms of the workspace
prefix:

- Kebab:
  `tmpl-prefix`
- Snake:
  `tmpl_prefix`
- Screaming:
  `TMPL_PREFIX`
- Pascal:
  `TmplPrefix`

## 4. The four layers

| Layer | Path | Package | Allowed internal dependencies |
| --- | --- | --- | --- |
| **foundation** | `foundation/` | `foundation` | None |
| **domain** | `domain/` | `domain` | `foundation` |
| **adapters** | `adapters/` | `adapters` | `foundation`, `domain` |
| **apps** | `apps/cli/` | `main` | `foundation`, `domain`, `adapters` |

`go run ./xtask layers` parses all Go source files in the workspace and
enforces `foundation < domain < adapters < apps`.

## 5. Quality gates and CI

`go run ./xtask ci` runs:

1. `gofmt -e -l .` (format verification)
2. `go vet ./...` (compiler static checks)
3. `golangci-lint run ./...` (lint suite)
4. `go build ./...` (full workspace build)
5. `go test ./...` (unit and layer tests)
6. `xtask layers` (AST import boundary verification)
