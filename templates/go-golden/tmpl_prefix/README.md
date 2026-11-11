# tmpl-prefix

Go command-line project with separate code layers.

Tools: Go, gofmt and golangci-lint.
Minimum versions are in `TOOLS.lock`.

Run all checks: `go run ./xtask ci`

- Code: `foundation/`, `domain/`, `adapters/`, `apps/`.
- Tests: `*_test.go` beside the code.
- Scripts: `.sh`, `.bash` and `.ps1` go in `scripts/` (created as needed).

Template: MIT, Copyright (c) 2026 defuzzr. Choose your project's licence.
