# AGENTS.md

`tmpl-prefix`
is a C++20 CMake and Ninja workspace template organized as a strict four-layer
architecture (`foundation`, `domain`, `adapters`, `apps`) with a
`cmake/xtask.cmake` automation runner.

## Workspace Layout

| Directory     | Layer        | Role                                       | Allowed Internal Dependencies      |
| ------------- | ------------ | ------------------------------------------ | ---------------------------------- |
| `foundation/` | `foundation` | Shared primitives and workspace errors     | None                               |
| `domain/`     | `domain`     | Pure business logic with no external I/O   | `foundation`                       |
| `adapters/`   | `adapters`   | External boundaries and storage adapters   | `foundation`, `domain`             |
| `apps/cli/`   | `apps`       | Composition root and CLI binary            | `foundation`, `domain`, `adapters` |
| `tests/`      | `tests`      | Workspace unit and CLI smoke test suite    | `foundation`, `domain`, `adapters` |
| `cmake/`      | `xtask`      | Workspace automation (`cmake/xtask.cmake`) | None                               |

## Conventions & Constraints

- **Layer dependency rule**: Dependency direction is strictly
  `foundation < domain < adapters < apps`. Lower layers may never link or
  include higher layers or `apps`. Enforced automatically by
  `cmake -P cmake/xtask.cmake -- layers`.
- **Standard-library only**: All targets use standard C++20 without third-party
  network dependencies.
- **Strict compiler & lint gates**: All targets build under `-Wall -Wextra
  -Wpedantic -Werror` and pass `clang-format --dry-run -Werror` and
  `clang-tidy` (`WarningsAsErrors: "*"`).
- **Where new files go**: notes and diagrams (`.md`, `.rst`, `.adoc`,
  `.mmd`, `.puml`, `.drawio`) go in `docs/`. Root shell and PowerShell
  scripts (`.sh`, `.bash`, `.ps1`) move to `scripts/`. Sources, headers
  and tests stay where you write them: put each one in the library or
  `tests/` folder that owns it, and add it to that `CMakeLists.txt`.
- **Template placeholder**: The scaffolder renames
  `tmpl-prefix`
  across all case forms:
  `tmpl-prefix` /
  `tmpl_prefix` /
  `TMPL_PREFIX` /
  `TmplPrefix`.

## Build & Verification Commands

- `cmake -P cmake/xtask.cmake -- ci` — run `fmt-check`, `layers`, CMake + Ninja
  build, `ctest`, and `clang-tidy`.
- `cmake -P cmake/xtask.cmake -- fmt` — format all C++ headers and sources with
  `clang-format`.
- `cmake -P cmake/xtask.cmake -- layers` — verify target and header dependency
  directions against the layer hierarchy.
- `cmake -P cmake/xtask.cmake -- test` — configure, build, and run `ctest`.
- `cmake -P cmake/xtask.cmake -- lint` — run `clang-tidy` against
  `build/compile_commands.json`.
