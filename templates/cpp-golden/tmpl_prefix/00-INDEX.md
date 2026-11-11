# 00 — Index: How This Workspace Works

> Master reference for the
> `tmpl-prefix`
> layered C++20 CMake and Ninja workspace
> (`foundation` -> `domain` -> `adapters` -> `apps/cli`) and
> `cmake/xtask.cmake` automation.

## 1. Quick start

```sh
cmake -P cmake/xtask.cmake -- ci
cmake -P cmake/xtask.cmake -- layers
cmake -P cmake/xtask.cmake -- fmt
./build/apps/cli/tmpl-prefix
```

## 2. Folder map

```text
.
├── 00-INDEX.md                 ← master workspace guide
├── AGENTS.md                   ← concise agent conventions & commands
├── README.md                   ← quick start
├── COMPONENTS.md               ← reusable component index
├── TOOLS.lock                  ← pinned system toolchain versions
├── CMakeLists.txt              ← root C++20 CMake build definition
├── .clang-format               ← LLVM-based C++20 formatting rules
├── .clang-tidy                 ← clang-tidy static analysis configuration
├── .editorconfig               ← editor formatting defaults
├── .github/workflows/ci.yml    ← GitHub Actions CI workflow
├── cmake/xtask.cmake           ← automation runner (ci, fmt, layers, lint, test)
├── foundation/                 ← Layer 0: shared primitives & error types
├── domain/                     ← Layer 1: pure business logic
├── adapters/                   ← Layer 2: integration adapters
├── apps/cli/                   ← Layer 3: composition root & CLI binary
├── scripts/                    ← shell and PowerShell helper scripts
└── tests/                      ← unit & CLI smoke tests
```

## 3. The four layers

| Layer          | Path          | Role                               | Allowed internal dependencies      |
| -------------- | ------------- | ---------------------------------- | ---------------------------------- |
| **foundation** | `foundation/` | Shared primitives and error types  | None                               |
| **domain**     | `domain/`     | Pure business logic                | `foundation`                       |
| **adapters**   | `adapters/`   | Integration and storage boundaries | `foundation`, `domain`             |
| **apps**       | `apps/cli/`   | Composition root and CLI binary    | `foundation`, `domain`, `adapters` |

`cmake -P cmake/xtask.cmake -- layers` inspects both `CMakeLists.txt` link
targets and C++ `#include` directives to enforce
`foundation < domain < adapters < apps`.

## 4. Naming & placeholder forms

The workspace binds all four canonical prefix forms:

- Kebab-case binary and slug:
  `tmpl-prefix`
- Snake_case CMake project prefix (C++ namespace uses `ws_` prefix):
  `tmpl_prefix`
- Screaming snake_case environment prefix:
  `TMPL_PREFIX`
- PascalCase metadata type:
  `TmplPrefix`

## 5. Quality gates and CI

`.github/workflows/ci.yml` and local acceptance run
`cmake -P cmake/xtask.cmake -- ci`, which executes:

1. `fmt-check`: `clang-format --dry-run -Werror` across all `.hpp` and `.cpp`
   files.
2. `layers`: static verification of target and `#include` layer boundaries.
3. `test`: `cmake -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`,
   `cmake --build build`, and `ctest --test-dir build --output-on-failure`.
4. `lint`: `clang-tidy -p build` across all translation units.
