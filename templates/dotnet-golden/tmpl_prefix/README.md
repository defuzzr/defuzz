# tmpl-prefix

C# command-line project with separate code layers.

Tools: .NET SDK (selected by `global.json`).
Minimum versions are in `TOOLS.lock`.

Run all checks: `dotnet run --project xtask -- ci`

- Code: `foundation/`, `domain/`, `adapters/`, `apps/`.
- Tests: self-tests in `apps/cli/Program.cs`.
- Scripts: `.sh`, `.bash` and `.ps1` go in `scripts/` (created as needed).

Template: MIT, Copyright (c) 2026 defuzzr. Choose your project's licence.
