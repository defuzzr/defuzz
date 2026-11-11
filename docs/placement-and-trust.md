# Placement modes and project trust

Defuzz's `pre_tool_call` and `transform_tool_result` hooks redirect a new
`write_file` call only when the enclosing project has a valid
`.adopt/rules.json` whose SHA-256 digest matches the `rules_hash` recorded in
the active profile's `plugin-data/defuzz/state.db` (`projects` table). Editing `.adopt/rules.json`
outside Defuzz changes its hash and drops trust immediately.

## Trust modes (`declared_only` and `full`)

Each trusted project record in that `state.db` carries `trust_mode`
(`state_store.py`, `placer.py`):

- **`declared_only`**:
  - Redirects a new file **only** when an explicit rule in `.adopt/rules.json`
    (`placement_rules` entry without `"source": "fallback"`, such as
    `"source": "explicit"`) matches it and targets a folder explicitly declared
    in `declared_dirs`.
  - Honors optional `"root_only": true` on explicit `placement_rules`,
    restricting redirects to files written directly at the project root so
    files deliberately placed in subfolders are never pulled out of them.
  - Never uses fallback extension heuristics from
    `build_deterministic_fallback_rules`, and never routes unmatched files to
    `_inbox/`.
  - Never redirects protected root build, manifest, lockfile, config, dotfile,
    CI, governance, or manifest-declared entry files (`PROTECTED_ROOT_TABLE`
    and `is_protected_root_path` in `rules.py`), even if a broad explicit rule
    would otherwise match.
  - Never raises or blocks from the hook: any destination collision,
    `SafetyError`, or unexpected error leaves the `write_file` path unchanged
    ("do not redirect").
  - Every redirect appends a single-sentence plain notice in
    `transform_tool_result` (`defuzz_notice` and `placed_by_adopt.note`)
    stating where the file was written and why, escaped via `_display_path` and
    capped at 600 characters.
- **`full`**:
  - Preserves manual-trust placement behaviour: explicit and fallback
    `match_ext` rules route to their `dest_dir`, unmatched loose files route to
    `_inbox/`, destination collisions return `action: "block"`, and
    `placed_by_adopt` records the move.

## How projects receive trust

| Project origin | Auto-trusted at creation? | Mode |
| --- | --- | --- |
| Template scaffold (`scaffolder.accept`) | Yes, when destination `.adopt/rules.json` matches the scaffolder's `scaffold_rules_hash` | `declared_only` |
| Kit scaffold (`kit_scaffold.accept_kit`) | Unchanged (trusted at creation) | `full` |
| Adopted copy / existing folder | Manual (`hermes defuzz trust <folder>`) | `full` (or `declared_only` with `--declared-only` / `trust_project(..., declared_only=True)`) |

## Protected root table and project extensions

`PROTECTED_ROOT_TABLE` in `rules.py` defines the single data table of root
files and directories that `declared_only` mode never redirects:

- Governance and root docs (`AGENTS.md`, `CLAUDE.md`, `TOOLS.lock`,
  `THEMING.md`, `COMPONENTS.md`, `00-INDEX.md`, `README*`, `LICENSE*`,
  `LICENCE*`, `COPYING*`, `NOTICE*`, `CHANGELOG*`, `CHANGES*`,
  `CONTRIBUTING*`, `SECURITY*`, `CODE_OF_CONDUCT*`).
- Well-known root files (`WELLKNOWN_ROOT_FILES`, also kept in `full` mode and
  by adopt apply): agent instructions (`AGENTS`, `AGENT`, `CLAUDE`, `GEMINI`,
  `COPILOT`, `CONVENTIONS`, `WARP`, `QWEN`, `CRUSH`, `llms.txt`,
  `llms-full.txt`, `.cursorrules`, `.windsurfrules`), governance and community
  files (`DCO`, `ACKNOWLEDGMENTS`, `ACKNOWLEDGEMENTS`, `README`, `LICENSE`,
  `LICENCE`, `COPYING`, `NOTICE`, `AUTHORS`, `CONTRIBUTORS`, `MAINTAINERS`,
  `GOVERNANCE`, `SUPPORT`, `CODEOWNERS`, `CODE_OF_CONDUCT`, `SECURITY`,
  `CONTRIBUTING`, `PULL_REQUEST_TEMPLATE`, `ISSUE_TEMPLATE`, `THIRD_PARTY`,
  `THIRD_PARTY_NOTICES`, `THIRD_PARTY_LICENSES`, `THIRD-PARTY-NOTICES`,
  `THIRD-PARTY-LICENSES`, `PATENTS`, `TRADEMARK`, `TRADEMARKS`, `CITATION.cff`,
  `CITATION.bib`, `FUNDING.yml`, `COMPONENTS.md`, `00-INDEX.md`) and release
  notes (`CHANGELOG`, `CHANGES`, `HISTORY`, `NEWS`, `RELEASES`,
  `RELEASE_NOTES`, `RELEASE-NOTES`, `UPGRADING`, `MIGRATING`, `MIGRATION`).
  A stem is kept only in UPPERCASE, alone or with `.md`, `.txt`, `.rst`,
  `.markdown`, `.adoc` or `.org`: `SUPPORT.md` stays, while `support-matrix.md`
  and `SUPPORTED_VERSIONS.md` are ordinary notes. `ROADMAP` is not protected,
  since many projects keep it in `docs/`.
- Root dotfiles (`.*`, `.gitignore`, `.editorconfig`, `.env.example`,
  `.worktreeinclude`, `.npmrc`, `.nvmrc`, `.clang-format`, `.clang-tidy`,
  `.golangci.yml`) and CI/tooling directories (`.github`, `.gitlab`,
  `.circleci`, `.cargo`, `.devcontainer`, `ci`).
- Containers and build definitions (`Dockerfile*`, `Containerfile*`,
  `docker-compose*`, `compose*.yml`, `compose*.yaml`, `Makefile`,
  `CMakeLists.txt`, `CMakePresets.json`, `Justfile`, `Taskfile.yml`).
- Ecosystem manifests, lockfiles, and workspace configs across Python
  (`pyproject.toml`, `uv.lock`, `requirements*.txt`, `constraints*.txt`,
  `setup.py`, `setup.cfg`, `Pipfile*`, `poetry.lock`, `ruff.toml`),
  JavaScript/TypeScript (`package.json`, `pnpm-lock.yaml`,
  `pnpm-workspace.yaml`, `package-lock.json`, `yarn.lock`, `tsconfig*.json`,
  `biome.json`, `*.config.*`), Rust (`Cargo.toml`, `Cargo.lock`, `build.rs`,
  `rust-toolchain*`, `rustfmt.toml`, `clippy.toml`, `deny.toml`), Go (`go.mod`,
  `go.sum`, `go.work`, `go.work.sum`), .NET (`*.sln`, `*.slnx`, `*.csproj`,
  `*.props`, `*.targets`, `NuGet.Config`, `global.json`, `packages.lock.json`),
  and JVM/polyglot (`build.gradle*`, `settings.gradle*`, `pom.xml`, `Gemfile*`,
  `composer.*`, `mix.exs`, `pubspec.yaml`, `Package.swift`).
- Entry files named in a root manifest (`extract_manifest_entry_files`:
  `package.json` `main`/`module`/`bin`/`exports`, `pyproject.toml`
  `[project.scripts]`/`[project.gui-scripts]`/`[tool.poetry.scripts]` /
  `[tool.setuptools].py-modules`, `Cargo.toml`
  `package.build`/`lib.path`/`[[bin]].path`, `CMakeLists.txt`
  `add_executable`/`add_library`).

A project may extend this set in `.adopt/rules.json` via
`"protected_root_files": ["CustomRunner.py", "bench-*.txt"]`, and may narrow
explicit `placement_rules` with optional `"match_glob"` patterns and
`"root_only": true`.

Adding a rule for one extension (`add_placement_rule`, the `add_rule` action of the `defuzz_place` tool)
takes only that extension away from other rules: a rule that also names other
extensions keeps them, and a rule left with no extension is removed. Pattern
rules that need a file name pattern (`match_glob`), such as decision records,
stay first and keep winning for the files they name; the new rule is placed right
after the last of them.

## Bundled template layouts and shipped placement rules

Each bundled template ships declarative rules in `templates/<id>/rules.json`
(`"source": "explicit"`, `"root_only": true`), materialized into
`.adopt/rules.json` by `scaffolder._generate_scaffold_context` without
template-specific branches in code. The first matching rule wins.

- The six layered templates (`cpp-golden`, `dotnet-golden`, `go-golden`,
  `python-golden`, `rust-golden`, `ts-node-golden`) move loose root notes and
  diagram sources (`.md`, `.rst`, `.adoc`, `.mmd`, `.puml`, `.drawio`) to
  `docs/`, and shell and PowerShell scripts (`.sh`, `.bash`, `.ps1`) to
  `scripts/`. `python-golden` and `ts-node-golden`, the two that ship
  `docs/adr/`, first move decision records (`adr-*.md`, `ADR-*.md`, and numbered
  `0NNN-*.md` such as `0003-name.md`) to `docs/adr/`. Each declares `scripts/` in
  `declared_dirs`; none of them ships a `scripts/` folder.
- `web-golden` moves loose root `*.md` notes to `docs/` and loose root
  `*.test.ts` / `*.spec.ts` files to `tests/unit/`.

No other file type is moved by a shipped rule. Every template also lists its own
root configuration in `protected_root_files`; the six layered templates add
`AGENT.md`, `WARP.md`, `QWEN.md`, `CRUSH.md`, `DCO.md` and `ACKNOWLEDGMENTS.md`
there, which the shared well-known list above already keeps at the root.

### Real layout and test discovery per template

| Template | Source & workspace members | Tests & discovery | Docs | Automation / templates | Scripts / assets / benches / examples / fixtures | CI check command |
| --- | --- | --- | --- | --- | --- | --- |
| `cpp-golden` | 4 CMake targets (`foundation/`, `domain/`, `adapters/`, `apps/cli/`) with `include/` + `src/` | `tests/` (`tests/CMakeLists.txt` lists `workspace_test.cpp` explicitly; `ctest --test-dir build`) | `docs/` | `cmake/xtask.cmake` | `scripts/` declared for routed scripts (no folder shipped) | `cmake -P cmake/xtask.cmake -- ci` |
| `dotnet-golden` | 4 `.csproj` projects (`foundation/`, `domain/`, `adapters/`, `apps/cli/`) in `TmplPrefix.sln` | `xtask/Xtask.csproj` (`dotnet test` runs `xtask self-test`; no separate user test `.csproj`) | `docs/` | `xtask/` | `scripts/` declared for routed scripts (no folder shipped) | `dotnet run --project xtask -- ci` |
| `go-golden` | 4 layered Go package trees (`foundation/`, `domain/`, `adapters/`, `apps/cli/`) | Colocated `*_test.go` beside each package (`go test ./...`) | `docs/` | `xtask/` | `scripts/` declared for routed scripts (no folder shipped) | `go run ./xtask ci` |
| `python-golden` | Virtual `uv` workspace; 9 packages under `packages/{foundation,domain,adapters,apps}/*` | 9 `tests/` dirs: 7 in `packages/*/*/tests/`, plus `packages/adapters/tests/` and `tools/xtask/tests/` (`pytest` `testpaths = ["packages", "tools"]`); the 2 skeletons in `templates/package-app/tests/` and `templates/package-lib/tests/` are not collected | `docs/`, `docs/adr/` | `tools/xtask/`, `templates/`, `componentize/` | `scripts/` declared for routed scripts (no folder shipped) | `uv run xtask ci` |
| `rust-golden` | Virtual Cargo workspace (`Cargo.toml` has `[workspace]`, no `[package]`); 4 crates (`foundation/`, `domain/`, `adapters/`, `apps/cli/`) | Inline `#[cfg(test)]` modules and per-crate `tests/` (`cargo test --workspace --locked`) | `docs/` | `xtask/` | `scripts/` declared for routed scripts (no folder shipped) | `cargo xtask ci` (+ `cargo check --workspace --locked`) |
| `ts-node-golden` | `pnpm` workspace; 9 packages under `packages/{foundation,domain,adapters,apps}/*` | Colocated `packages/*/*/src/*.test.ts` compiled by `tsc -b` to `dist/*.test.js` (`node --test`) | `docs/`, `docs/adr/` | `tools/xtask/`, `templates/` | `scripts/` declared for routed scripts (no folder shipped) | `pnpm xtask ci` |
| `web-golden` | One Vite multi-page site: pages in `src/pages/` (the Vite root), partials and `site.ts` in `src/components/`, `src/styles/`, `src/assets/`, `src/lib/`; design tokens in `design/tokens/`; `public/` copied as-is | `tests/unit/**/*.test.ts` and `*.spec.ts` only (`test.include` in `vite.config.ts`; `vitest run`); optional browser tests `tests/e2e/*.e2e.ts` (`pnpm xtask e2e`, not in `ci`) | `docs/` | `tools/xtask/` (locked) | `scripts/check-contrast.ts`; `design/{sources,specs,exports}/` (Git LFS for sources and exports) | `pnpm xtask ci` (after `pnpm xtask prepare-scaffold`) |

### Shipped explicit rules and deliberately omitted candidates

| Template | Shipped root-only rules (`pattern -> dest_dir`, convention) | Deliberately omitted candidate rules and why |
| --- | --- | --- |
| `cpp-golden` | Notes and diagram sources -> `docs/`; `.sh`, `.bash`, `.ps1 -> scripts/`; `protected_root_files`: CTest/CPack config, `compile_commands.json`, vcpkg/conan files, `build`, `out` | `*_test.cpp -> tests/`: `tests/CMakeLists.txt` lists `workspace_test.cpp` explicitly (single `main()`) while `cmake/xtask.cmake` globs `tests/*.cpp` into `clang-tidy -p build`, so an unlisted `.cpp` is uncompiled by `ctest` and breaks `clang-tidy`. `.cpp`/`.hpp`/`.cmake`: split across 4 layer targets; root `CTestConfig.cmake`/`PreLoad.cmake` are root-scoped. Assets: no `assets/` folder, so no asset rule. |
| `dotnet-golden` | Notes and diagram sources -> `docs/`; `.sh`, `.bash`, `.ps1 -> scripts/`; `protected_root_files`: SDK pin, NuGet and MSBuild files, `*.sln`, `*.slnx`, `.config` | `*Tests.cs` / `.cs`: solution has 4 layered library/CLI `.csproj` projects plus locked standalone `xtask/Xtask.csproj` (no references to workspace libraries) and no user test `.csproj`; moving `.cs` files cannot pick a valid project. Assets: no `assets/` folder, so no asset rule. |
| `go-golden` | Notes and diagram sources -> `docs/`; `.sh`, `.bash`, `.ps1 -> scripts/`; `protected_root_files`: Go module and workspace files, golangci-lint config, Make and Task files | `*_test.go` / `.go`: in Go a directory is a package (`_test.go` must stay beside the package under test), and `xtask layers` rejects `.go` files at root or outside `foundation`, `domain`, `adapters`, `apps`, and `xtask`. Assets: no `assets/` folder, so no asset rule. |
| `python-golden` | `adr-*.md`, `ADR-*.md`, `0NNN-*.md -> docs/adr/` (decision records live in `docs/adr/`); other notes and diagram sources -> `docs/`; `.sh`, `.bash`, `.ps1 -> scripts/`; `protected_root_files`: `pyproject.toml`, `uv.lock`, `uv.toml`, `.python-version`, `conftest.py`, `py.typed` | `test_*.py` / `*_test.py`: `pyproject.toml` sets `testpaths = ["packages", "tools"]` across 9 test directories with no root `tests/` dir. `.py`: moving modules alters imports across 9 workspace packages. Assets: no `assets/` folder, so no asset rule. |
| `rust-golden` | Notes and diagram sources -> `docs/`; `.sh`, `.bash`, `.ps1 -> scripts/`; `protected_root_files`: Cargo, toolchain and Rust tool configs, `target` | `tests/*.rs`, `benches/*.rs`, `examples/*.rs`, `.rs`: root `Cargo.toml` is a virtual workspace manifest with no `[package]`, so Cargo ignores workspace-root `tests/`, `benches/`, and `examples/`; crate ownership across the 5 members is ambiguous. Assets: no `assets/` folder, so no asset rule. |
| `ts-node-golden` | `adr-*.md`, `ADR-*.md`, `0NNN-*.md -> docs/adr/` (decision records live in `docs/adr/`); other notes and diagram sources -> `docs/`; `.sh`, `.bash`, `.ps1 -> scripts/`; `protected_root_files`: `*.d.ts`, `*.d.mts`, `*.d.cts`, `*.test-d.ts`, `*.config.cts`, `vitest.*`, `tsconfig*.json`, `pnpm-*.yaml`, `pnpm-*.yml` | `*.test.ts` / `*.spec.ts`: tests are colocated inside the 9 workspace packages (`packages/*/*/src/*.test.ts`), compiled via `tsc -b` project references, and discovered from `packages/**/dist/**/*.test.js`. `.ts`: package-scoped imports enforced by `xtask check`. Assets: no `assets/` folder, so no asset rule. |
| `web-golden` | `*.md -> docs/` (loose Markdown notes; README, LICENSE, CHANGELOG and other governance files stay); `*.test.ts`, `*.spec.ts -> tests/unit/` (Vitest discovers only `tests/unit/`); `protected_root_files`: the root configs (`package.json`, `pnpm-lock.yaml`, `biome.json`, `tsconfig.json`, `vite.config.ts`, `playwright.config.ts`, `.nvmrc`, `.npmrc`, `.editorconfig`, `.gitattributes`, `.gitignore`) and the generated `.xtask-cache`, `dist`, `test-results`, `playwright-report`, `coverage` | `*.e2e.ts`: optional browser tests stay where written (`playwright.config.ts` `testMatch`). `.ts` / `.html` / `.css` / images: pages, partials, styles and assets are split across `src/` folders by role, so no single destination is right; `.xtask-cache/` and `dist/` are generated and never moved (both are also skipped by `defuzz lint`). |
