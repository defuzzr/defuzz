# Static code (`static_code`)

`audit/vendor/static_code.py` compares a registered project's dependencies, imports and code patterns with its bundled template.
`audit_surface.py` supplies captured project/template files; the check may read template metadata even with captured files.
It inspects source rather than executing the project. This audit cannot tell whether working code is correct.

## Scope

Template support comes from `resolve_runtime_golden_registry` in `audit/contract.py`.
Unregistered or unsupported projects receive `static_code.not_included`; empty template guardrails also mean `not_included`.
Unavailable or invalid template metadata produces `static_code.approved_deps_unavailable` with `could_not_verify` coverage.

| Ecosystem | Lockfile/input | Imports scanned |
|---|---|---|
| Rust | `Cargo.lock`, `Cargo.toml` | `.rs` use/extern crate roots |
| TypeScript/Node | `pnpm-lock.yaml`, `package.json` | JavaScript and TypeScript static/dynamic imports |
| Python | `uv.lock`, `pyproject.toml` | Python imports |
| Go | `go.sum`, `go.mod` | Dependency comparison only |
| C++ | `CMakeLists.txt` | Dependency comparison only |
| .NET | `packages.lock.json` | Dependency comparison only |

## Checks

- External lockfile packages outside the template's `approved_deps` produce `static_code.unapproved_dependency` (`warning`).
- Missing or unreadable lockfiles produce `static_code.lockfile_missing_or_invalid` (`info`, `could_not_verify`); import mapping is skipped.
- Built-in/local imports are counted. External imports missing from the lockfile produce `static_code.import_missing_from_lock` (`warning`).
- Imports that cannot be mapped produce `static_code.unmappable_import` (`info`, `could_not_verify`): `dynamic_import`, `alias`, `unparseable_use`, `conditional_or_dev_scope` or `workspace_crate`.
- Suppressions count lint and type directives outside string literals, including comment directives. Counts above the template baseline produce `static_code.suppressions_above_baseline` (`review_suggested`).
- Stubs above the template baseline produce `static_code.stub_detected`. Empty/pass-through handlers, excess nesting and unreferenced private helpers produce heuristic review findings.
- Python syntax errors produce `static_code.syntax_error`. Unsafe, unreadable, changed, oversized or credential-policy-excluded files produce `static_code.unverified_file`; both use `could_not_verify` coverage.

Bounds are `DEFAULT_MAX_NESTING_DEPTH`, `DEFAULT_MAX_FILE_BYTES` and `DEFAULT_MAX_DIR_ENTRIES` in `audit/vendor/static_code.py`.
Missing/invalid provenance or a worker timeout can instead produce `static_code.unverified`; see [audit-scope.md](audit-scope.md).

## Import limits

Node built-ins and relative imports count as local, including in dynamic imports.
A plain-string dynamic import maps like a static import; computed arguments and non-Node URLs remain unmappable.
TypeScript/Node development-scope imports are mapped against the lockfile; production imports of development dependencies remain unmappable.
Python/Rust development dependencies and workspace packages remain unmappable.
These limits can give a fresh bundled project `could_not_verify` coverage without a dependency warning.

## Result

Coverage is `verified`, `could_not_verify` or `not_included`; any unverified finding makes the included result unverified.
`classification` is the highest finding class. `summary` contains inclusion, dependency/import counts and baseline comparisons, or an exclusion reason.
The report groups these findings under `Other check: static code`. Static matches do not establish correctness, safety or runtime behavior.
