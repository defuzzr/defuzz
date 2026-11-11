# 00 — Index: How This Workspace Works

> Master reference for the
> `tmpl-prefix` layered
> .NET C# workspace
> (`foundation` -> `domain` -> `adapters` -> `apps/cli`) and
> `xtask` automation.

## 1. Quick start

```sh
dotnet run --project xtask -- ci
dotnet run --project xtask -- layers
dotnet run --project xtask -- fmt
dotnet run --project apps/cli
```

## 2. Folder map

```text
.
├── 00-INDEX.md                 ← master workspace guide
├── AGENTS.md                   ← concise agent conventions & commands
├── COMPONENTS.md               ← reusable component index
├── README.md                   ← quick start
├── TOOLS.lock                  ← pinned .NET SDK toolchain lock
├── Directory.Build.props       ← shared SDK, analyzer & target/ settings
├── Directory.Build.targets     ← SDK-only VSTest runner target
├── NuGet.Config                ← offline-first cleared package sources
├── global.json                 ← .NET SDK floor 10.0.100, any newer 10.0
├── TmplPrefix.sln
    solution file: foundation, domain, adapters, apps/cli, xtask
├── .github/workflows/ci.yml    ← CI workflow (`dotnet run --project xtask -- ci`)
├── foundation/
    Layer 0: shared primitives (`TmplPrefix.Foundation`)
├── domain/
    Layer 1: pure business logic (`TmplPrefix.Domain`)
├── adapters/
    Layer 2: integration adapters (`TmplPrefix.Adapters`)
├── apps/cli/
    Layer 3: CLI composition root (`TmplPrefix.Cli`)
├── scripts/
    shell and PowerShell helper scripts (created on first use)
└── xtask/
    workspace automation (`ci`, `fmt`, `layers`, `self-test`)
```

## 3. The four layers

| Layer          | Path          | Suffix        | Allowed internal dependencies      |
| -------------- | ------------- | ------------- | ---------------------------------- |
| **foundation** | `foundation/` | `.Foundation` | None                               |
| **domain**     | `domain/`     | `.Domain`     | `foundation`                       |
| **adapters**   | `adapters/`   | `.Adapters`   | `foundation`, `domain`             |
| **apps**       | `apps/cli/`   | `.Cli`        | `foundation`, `domain`, `adapters` |

`dotnet run --project xtask -- layers` inspects all workspace `.csproj`
manifests and enforces `foundation < domain < adapters < apps`.

## 4. Modules vs components

Each `.csproj` in `foundation/`, `domain/`, `adapters/`, and `apps/` is
a compile-time assembly boundary inheriting `Directory.Build.props`.
Keep domain logic free of external I/O.

## 5. Anatomy of a domain module

Domain types expose pure functions over
`TmplPrefix.Foundation`
primitives without depending on adapters or environment variables.
Prefix constants in `Foundation`:

- Kebab slug:
  `tmpl-prefix`
- Snake prefix:
  `tmpl_prefix`
- Environment prefix:
  `TMPL_PREFIX`
- Pascal prefix:
  `TmplPrefix`

## 6. Configuration

Read configuration and environment variables at the composition root
(`apps/`) and pass typed values explicitly into adapters and domain
functions.

## 7. Adding projects and dependencies

1. Add new projects under the appropriate layer directory (`foundation/`,
   `domain/`, `adapters/`, or `apps/*`) and register them in the root
   solution file.
2. Keep `packages.lock.json` committed for deterministic offline
   restores.
3. Run `dotnet run --project xtask -- ci` to verify lockfiles,
   formatting, analyzer rules, tests, and layer boundaries.

## 8. The `xtask` tool

| Subcommand                                | Purpose                                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `dotnet run --project xtask -- ci`        | Run `restore --locked-mode`, `format --verify-no-changes`, `build -warnaserror`, `test`, and `layers`. |
| `dotnet run --project xtask -- fmt`       | Format all workspace C# files via `dotnet format --no-restore`.                                        |
| `dotnet run --project xtask -- layers`    | Verify workspace project dependency direction rules.                                                   |
| `dotnet run --project xtask -- self-test` | Run `xtask` layer-rule and CLI parser unit tests.                                                      |
