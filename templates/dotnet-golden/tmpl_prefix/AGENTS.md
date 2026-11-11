# AGENTS.md

`tmpl-prefix` is a .NET
workspace template organized as a strict
four-layer architecture (`foundation`, `domain`, `adapters`, `apps`)
with an `xtask` automation runner. Each layer starts as a minimal shell
ready for project-specific code.

## Workspace Layout

| Directory     | Layer        | Role                                                             | Allowed Internal Dependencies      |
| ------------- | ------------ | ---------------------------------------------------------------- | ---------------------------------- |
| `foundation/` | `foundation` | Shared primitives and workspace exception (`WorkspaceException`) | None                               |
| `domain/`     | `domain`     | Pure business logic with no external I/O                         | `foundation`                       |
| `adapters/`   | `adapters`   | External boundaries and integration adapters                     | `foundation`, `domain`             |
| `apps/cli/`   | `apps`       | Composition root and CLI entrypoint                              | `foundation`, `domain`, `adapters` |
| `xtask/`      | `xtask`      | Workspace automation (`ci`, `fmt`, `layers`, `self-test`)        | None (standalone tool)             |

## Conventions & Constraints

- **Layer dependency rule**: Dependency direction is strictly
  `foundation < domain < adapters < apps`. Library projects may never
  depend on higher layers or `apps`. Enforced automatically by
  `dotnet run --project xtask -- layers`.
- **SDK-only dependencies**: All workspace projects (`foundation`,
  `domain`, `adapters`, `apps/*`, `xtask`) use only the .NET SDK base
  class library (`Microsoft.NET.Sdk`) and restore offline against
  committed `packages.lock.json` files (`NuGet.Config` clears external
  sources).
- **Strict analyzers and warnings as errors**: `Directory.Build.props`
  sets `Nullable=enable`, `AnalysisLevel=latest-recommended`,
  `EnforceCodeStyleInBuild=true`, and `TreatWarningsAsErrors=true`.
- **Centralized build outputs**: `UseArtifactsOutput=true` routes all
  intermediate (`obj`) and binary (`bin`) outputs under `target/`.
- **Explicit configuration over process mutation**: Read configuration
  at the composition root (`apps/`) and pass typed values explicitly
  into lower layers.
- **Toolchain prerequisites**: Requires a .NET SDK 10.0.100 or newer
  10.0 release on `PATH` (`global.json` sets `"version": "10.0.100"`
  with `rollForward: "latestFeature"`; `TOOLS.lock` records the same
  floor). Keep that roll-forward rule: pinning an exact SDK would reject
  the SDK that `setup-tools` installs. Running `hermes defuzz lint`
  additionally requires `csharpier` (`1.3.0`) on `PATH`, provisioned by
  Defuzz tool setup (`hermes defuzz setup-tools --yes`).
- **Where new files go**: notes, guides and diagram sources written at the
  root (`.md`, `.rst`, `.adoc`, `.mmd`, `.puml`, `.drawio`) move to
  `docs/`. Root shell and PowerShell scripts (`.sh`, `.bash`, `.ps1`) move
  to `scripts/`. C# sources, tests and images stay where you write them:
  put each one in the layer project that owns it.
- **Template placeholder**: The scaffolder renames
  `tmpl-prefix` across
  all case forms
  (`tmpl-prefix` /
  `tmpl_prefix` /
  `TMPL_PREFIX` /
  `TmplPrefix`).

## Build & Verification Commands

- `dotnet restore --locked-mode` — verify NuGet lockfiles offline.
- `dotnet build --no-restore -warnaserror` — compile all projects with
  analyzers and warnings as errors.
- `dotnet test --no-build` — run self-tests across workspace projects.
- `dotnet run --project xtask -- fmt` — format all workspace C# files
  with `dotnet format`.
- `dotnet run --project xtask -- layers` — verify project dependency
  directions against the layer hierarchy.
- `dotnet run --project xtask -- ci` — run the full CI gate
  (`restore --locked-mode`, `format --verify-no-changes`,
  `build -warnaserror`, `test`, and `layers`).
