# tmpl-prefix

C++ command-line project with separate code layers.

Tools: CMake/CTest, Ninja, Clang/clang++, clang-format and clang-tidy.
Minimum versions are in `TOOLS.lock`.

Run all checks: `cmake -P cmake/xtask.cmake -- ci`

- Code: `foundation/`, `domain/`, `adapters/`, `apps/`.
- Tests: `tests/`.
- Scripts: `.sh`, `.bash` and `.ps1` go in `scripts/` (created as needed).

Template: MIT, Copyright (c) 2026 defuzzr. Choose your project's licence.
