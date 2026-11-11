# Static code (`static_code`)

`audit/vendor/static_code.py` checks a registered project that was created from a bundled
template: its lockfile against the template's `approved_deps` list, its top-level imports
against the lockfile, and a few mechanical code patterns against the template's own baseline.
Entry point: `audit_static_code(provenance, *, project_id, template_id, prefix, approved_deps,
project_files, project_root, template_spec, template_files, template_root,
baseline_suppressions, registered, template_has_guardrails, max_nesting_depth, max_file_bytes,
max_entries) -> dict`. The audit surface (`audit_surface.py`) calls it once per selected
registered project, in the audit's time-bounded worker, with the project files and template
files it captured, the project's provenance and the template's `approved_deps`. It never runs
project code, a package manager or any other tool, and it reads no file itself when it is given
captured files. It has no section page in `docs/audit-sections/` and no wiring sheet; its
findings are listed by the summary as `Other check: static code`.

The module states one fixed limit in every result (`disclosure`): "This audit cannot tell
whether working code is correct."

## Scope

- Only a registered project whose template is one of the bundled templates (`cpp-golden`,
  `dotnet-golden`, `go-golden`, `python-golden`, `rust-golden`, `ts-node-golden`,
  `web-golden`, read from the template registry at run time) is checked. Any other project gets
  one `static_code.not_included` finding and coverage `not_included`, with reason
  `unregistered_repository` or `non_golden_template:<id>`.
- A template that declares an empty `approved_deps` is `not_included` with reason
  `template_guardrails_not_configured`.
- The template registry unreadable, or the template's manifest excluded or invalid, gives
  `static_code.approved_deps_unavailable` and coverage `could_not_verify`, with reason
  `templates_registry_unavailable`, `template_manifest_excluded_by_credential_policy` or
  `template_manifest_invalid:<detail>`.

Each template maps to one ecosystem and one lockfile:

| Ecosystem | Templates | Lockfile read | Imports scanned |
|---|---|---|---|
| `rust` | `rust-golden` | `Cargo.lock` (with `Cargo.toml`) | `.rs` `use` and `extern crate` roots |
| `ts-node` | `ts-node-golden`, `web-golden` | `pnpm-lock.yaml` (with `package.json`) | `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.mjs`, `.cjs` static and dynamic imports |
| `python` | `python-golden` | `uv.lock` (with `pyproject.toml`) | `.py` imports |
| `go` | `go-golden` | `go.sum` (with `go.mod`) | none |
| `cpp` | `cpp-golden` | `CMakeLists.txt` | none |
| `dotnet` | `dotnet-golden` | every `packages.lock.json` | none |

For `go`, `cpp` and `dotnet` only the lockfile is compared with `approved_deps`.

## Import mapping

Each import the scanner finds is put in one of four groups:

1. **Built-in or local**: language built-ins and standard library modules, and relative or
   project-local modules. Counted in `builtin_imports_count`; nothing is reported.
2. **Mapped**: an external package that has an entry in the lockfile. Counted in
   `mapped_imports_count`.
3. **Missing from the lockfile**: an external package with no lockfile entry gives
   `static_code.import_missing_from_lock` (`warning`).
4. **Unmappable**: an import whose package cannot be read from the text alone gives
   `static_code.unmappable_import` (`info`, coverage `could_not_verify`). Its `reason` is one of
   `dynamic_import`, `alias` (a path or package alias), `unparseable_use`,
   `conditional_or_dev_scope` (a development dependency, or an import the scanner placed in a
   conditional or development scope) or `workspace_crate` (a package of the project's own
   workspace, in any ecosystem).

For the `ts-node` ecosystem these rules also apply:

- `node:` modules and other Node built-ins, and relative specifiers, count as built-in or
  local wherever they appear, also inside a dynamic import and inside a block.
- A dynamic import (`import(...)` or `require(...)`) of one plain string literal is read by its
  specifier and mapped like a static import. A computed argument, or a literal that is a URL
  (any `scheme:` other than `node:`), stays `unmappable_import` with reason `dynamic_import`.
- In development-scope files (`*.test.ts`, `*.spec.ts` and their `.js` / `.mts` forms, any file
  under a `test/` or `tests/` folder, `<name>.config.<ext>` files, and files under a top-level
  `tools/` or `scripts/` folder) a package import, including a declared devDependency, goes
  through the lockfile mapping.
- A devDependency imported from production source stays `unmappable_import` with reason
  `conditional_or_dev_scope`.

For `python` and `rust` a development dependency stays `unmappable_import` wherever it is
imported. Workspace packages stay `unmappable_import` in every ecosystem.

Any unmappable import makes the result's coverage `could_not_verify`, because the module has no
word for "verified except for these imports". A freshly created project therefore reports
`could_not_verify`:

- `web-golden`: 4 unmappable imports, all `dynamic_import` (three URL literals and one computed
  value in its own unit tests); 19 imports are mapped; no other finding.
- `ts-node-golden`: 30 unmappable imports, all `workspace_crate` (its packages import each
  other); no other finding.

## Other checks

- **Lockfile against `approved_deps`**: every external lockfile package that is not in the
  template's `approved_deps` gives `static_code.unapproved_dependency` (`warning`). Python
  names are compared after normalising case and separators; other ecosystems compare exact
  names. Workspace packages are not external.
- **Lockfile missing or unreadable**: `static_code.lockfile_missing_or_invalid` (`info`,
  `could_not_verify`); imports are then not mapped.
- **`approved_deps` not given**: `static_code.approved_deps_unavailable` (`info`,
  `could_not_verify`).
- **Suppressions** (lint and type suppressions in code, not in comments or strings): more than
  the template's own count gives one `static_code.suppressions_above_baseline`
  (`review_suggested`).
- **Stubs** (`todo!`, `unimplemented!`, `NotImplementedError`, `throw new Error("not
  implemented")`, stub `pass` / `...` bodies): more than the template's own count gives a
  `static_code.stub_detected` (`review_suggested`) for each stub.
- **Heuristic review items** (`review_suggested`): `static_code.useless_try_catch` (an empty or
  pass-through exception handler), `static_code.excess_nesting` (control-flow nesting deeper
  than 6, `DEFAULT_MAX_NESTING_DEPTH`), `static_code.unreferenced_code` (a private helper that
  nothing else in the project names).
- **Files that cannot be read safely** (not a regular file, a symbolic link, unreadable, over
  10 MiB, `DEFAULT_MAX_FILE_BYTES`, or changed while read): `static_code.unverified_file`
  (`info`, `could_not_verify`).
- **Python syntax errors**: `static_code.syntax_error` (`info`, `could_not_verify`).

The audit surface reports `static_code.unverified` (`review_suggested`, `could_not_verify`)
instead of running the check when the project's template provenance is missing, unrecognised
or invalid, and when the check times out or stops in the audit worker (with the worker's fixed
sentence; see the time-budget paragraph in [audit-scope.md](audit-scope.md)).

## Result

`{ok, status, error, coverage, classification, findings, disclosure, rule_version, project_id,
template_id, ecosystem, summary}`. `coverage` is `verified`, `could_not_verify` (any finding
with that coverage makes the whole result `could_not_verify`) or `not_included`.
`classification` is the highest class among the findings. `summary` holds `included`, and for
an included project `lockfile`, `external_lock_package_count`,
`unapproved_lock_package_count`, `mapped_imports_count`, `builtin_imports_count`,
`missing_lock_imports_count`, `unmappable_imports_count`, `project_suppressions`,
`baseline_suppressions`, `suppression_delta` and `stubs_count`; for a project that is not
included, `reason`.

## Not measured

- Whether the code works, is safe, or matches what the template intended.
- Imports in Go, C++ and .NET sources.
- Which import a dynamic import of a computed value loads.
- Whether a workspace package or a development dependency imported from production source is
  locked.
