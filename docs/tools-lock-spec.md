# TOOLS.lock — file format and `toolchk` API (schema 1)

Normative for `defuzz`; implemented by `toolchk.py` and tested in `tests/test_toolchk.py` and `tests/test_toolchk_portable_pins.py`.
It descends from an earlier preflight script; no external checkout is required. TOML; parsed with stdlib `tomllib`; written by `toolchk.dump_lock` (own
serializer, deterministic key order, one blank line between tables, `#` comments preserved only in the header,
control characters `< 0x20` and `0x7f` escaped as `\uXXXX`; atomic temp file + `os.replace`; a new file gets mode `0644`,
an existing file keeps its nonzero mode except `0600`, which is normalized to `0644`). `TOOLS.lock` must be a regular UTF-8
file of at most 256 KB (`O_RDONLY | O_NOFOLLOW | O_NONBLOCK`); violations raise `PreflightError` code 4.

## Header table (optional; defaults shown)

```toml
[lock]
schema = 1
enforce = "warn"          # "warn" | "block" — what drift inside a declared `minimum` does at an explicit check (see Enforcement)
age_nudge_months = 12     # non-negative int; 0 disables; when age_months >= age_nudge_months > 0 appends " · chosen N months ago, re-decide?" to text
network = false           # boolean; this release has no network advisory, so true enables nothing
```

## Tool tables — one per tool, table name = tool name

Table name must match `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`.
Required: `version` (exact string the probe must report), `chosen` (ISO date `YYYY-MM-DD`), `reason` (non-empty), `probe`.
Optional: `minimum` (oldest compatible version, dotted digits such as `"3.20"`), `source` (`"auto" | "human" | "agent"`, default `"human"`), `advisory`, and the probe-specific keys below.
`load_lock` validates required keys and field shapes: an entry missing a required key, with an invalid `chosen` date,
unknown `probe` kind, or malformed probe-specific keys/types is a parse error (`PreflightError` code 4): a pin without a
reason is not a pin. The safety checks on `argv`, module and package names, file paths and regexes described below run
later, inside `probe`, and a violation there reports the tool as `probe-failed`.

| `probe` | keys | installed version comes from |
|---|---|---|
| `"command"` | `argv = ["tool", "--version"]`, optional `resolve = "hermes-tools"` | `argv[0]` must match `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` (no path separators) and equal the tool table name or an allowed alias (`rust`↔`rustc`, `python`↔`python3`, `node`↔`nodejs`, `ripgrep`↔`rg`, `go`↔`go`); `argv[1:]` must be a subset of `{"--version", "-V", "-v", "version", "-version", "--help"}`. `resolve="hermes-tools"` globs only the validated tool table name under `$HERMES_HOME/tools/<name>-*/<name>`; `PATH` lookup ignores relative entries and entries inside `project_root`. Runs with `stdin=DEVNULL`, `start_new_session=True`, minimal env `{PATH, HOME, LANG=C.UTF-8, LC_ALL=C}` plus `SYSTEMROOT` and `TMPDIR` when set, configurable `timeout` (default 20s), and stdout/stderr capped at 64 KB each, from a neutral working folder (the temporary folder, else `/`; never the project or a Hermes home), so project files such as `rust-toolchain.toml` cannot choose which toolchain answers. The version is the first token in stdout+stderr made of dotted numbers (`\d+(\.\d+)+`), with an optional pre-release or build tail: `-`, `+` or `.` followed by up to 31 letters, digits, `.`, `+` or `-` that start and end with a letter or digit (for example `1.2.3-rc.1`). |
| `"module"` | optional `module = "websockets"` (default: table name) | `module` must match `^[A-Za-z0-9_.-]+$`; resolved via `importlib.metadata.version(module)` without importing the module (`PackageNotFoundError` → `probe-failed`). |
| `"interpreter"` | — | `platform.python_version()` of the running interpreter |
| `"pm"` | optional `package = "<pm name>"` (default: table name) | `pm.installed_package(package).version` (Hermes-managed binaries, no subprocess); if `pm` is unimportable → `probe-failed` |
| `"file"` | `file = "<path relative to project root>"`, one of `key = "a.b.c"` (JSON/TOML dotted path) or `regex = "..."` (first group) | `file` must be relative, stay strictly inside `project_root` (outside any live Hermes home) with no symlinks (`O_NOFOLLOW`), pass `_refuse_secret_path` on both the given and resolved paths before opening (`secret_path_refused`), have a basename matching `ALLOWED_PROBE_FILES` (`package.json`, `pyproject.toml`, `Cargo.toml`, `rust-toolchain.toml`, `rust-toolchain`, `go.mod`, `global.json`, `.nvmrc`, `.node-version`, `.python-version`, `.tool-versions`, `houdini.version`, `VERSION`, `*.uproject`, `*.uplugin`; else `probe_file_not_allowed`), be a regular file (`stat.S_ISREG`), and not exceed 64 KiB (`MAX_FILE_PROBE_BYTES`, checked via `lstat` before `os.open(O_RDONLY\|O_NOFOLLOW\|O_NONBLOCK)` and via `fstat` after open; else `probe_file_too_large`). `regex` is capped at 128 chars, rejected on unsafe nested quantifiers/backreferences, and applied per line (lines truncated to 512 chars). Extracted version must match tightened `SAFE_VERSION_TOKEN_RE` (`^(?=.{1,32}$)(?=.{0,2}\d)(?!.*[^.]{20})v?[._-]?[0-9][0-9A-Za-z.+_-]*$`); invalid or unparseable values report only length and class (e.g. `invalid version token (40 chars, too_long)`), never echoing file content. |

`advisory` (optional, never blocks): `{ kind = "json", path = "~/.cua-driver/version_check.json", key = "latest_version" }` or
`{ kind = "pm" }` (Hermes's own locked version from `pm.Lockfile`) — both local. Advisory `json` paths use the
same `_refuse_secret_path` guard before open, no-follow regular-file `<= 64 KiB` read discipline, and no-echo version validation, and must be either an exact fixed file in `ALLOWED_ADVISORY_JSON_FILES` (`~/.cua-driver/version_check.json` — never a directory wildcard under a Hermes home) or a relative `.json` path strictly inside `project_root` (outside any live Hermes home; else `advisory_path_not_allowed`). Only these two local kinds are
supported. Any other kind is reported as an advisory error and never fetched: with `network = false` it is refused,
and with `network = true` it is reported as unsupported.

## Enforcement (`check`)

Each needed tool is classified in this order; versions compare numerically by dotted part (missing parts are 0):

1. not in the lock → `unlisted`, blocked;
2. probe fails → `probe-failed`; a tool not on `PATH` reports `<tool>: not found on PATH[, need >= <minimum>]. Install <tool>, or run `hermes defuzz setup-tools` to see what it can install.`;
3. installed below `minimum` → `drift` with `below_minimum: true` (table mark `TOO-OLD`), blocked under either `enforce`: `<tool>: found <installed>, need >= <minimum> (<where>). Upgrade <tool>, or run `hermes defuzz setup-tools` to see what it can install.`;
4. installed equals `version` → `ok`;
5. otherwise `drift`. With a `minimum` and `enforce = "warn"` it is a warning: listed in `warnings`, `ok` stays true, exit 0. With `enforce = "block"`, or for an entry without `minimum` (an exact pin: only that version is compatible), it is blocked.

These rules apply at every explicit boundary that calls `check`/`require` (scaffold preflight, lint, harness). The
plugin installs no editing-session probe: nothing checks tools automatically while files are edited.

## Template locks and seeding

A bundled template either ships a *floor lock* or no `TOOLS.lock`:

- `cpp-golden`, `dotnet-golden` and `go-golden` ship a floor lock: every entry has `source = "auto"`,
  `minimum` = the oldest version the template's build files need, and `version = minimum` as a placeholder.
- `ts-node-golden` and `web-golden` ship no lock. Both state node >= 24 in `.nvmrc` and `engines.node` and name
  pnpm 12.15.0 in `packageManager`. At creation the `.nvmrc` number becomes the `minimum` of the seeded `node`
  entry, and the installed node is asked with `node --version`.
- `python-golden` and `rust-golden` ship no lock and get no floor at creation. `python` is probed as the
  interpreter that runs Hermes (`probe = "interpreter"`), not the project's `requires-python`; `rust-golden`'s
  `rust-toolchain.toml` names the channel `stable`, which is not a version, so the seeded `rustc` entry has no
  `minimum` (a concrete channel such as `1.82.0` would set one; rustc is asked with `rustc --version`).

`hermes defuzz new` seeds the project's lock from the user's machine: every `auto` entry is re-probed and records
the installed version and today's `chosen`; an entry with `minimum` keeps its probe, `minimum` and `reason`.
Entries set by a human or agent are never re-probed. The template author's own versions are never written into a
user's lock. Creation then runs `require` on the seeded tools: a needed tool that is missing, cannot report its
version, or is older than its `minimum` stops creation with one plain line naming the tool, before the template's
check runs and before anything is moved, committed or registered. So the five templates with a floor (the three
floor locks and the two `.nvmrc` files) enforce it at creation, and `python-golden` and `rust-golden` do not.

## Report (`preflight.json`)

```json
{"ok": false, "at": "...", "lock": "/abs/TOOLS.lock", "enforce": "warn",
 "tools": {"cua-driver": {"status": "ok|drift|unlisted|probe-failed", "locked": "0.21.0", "installed": "0.21.0",
            "where": "/path", "chosen": "2026-11-06", "reason": "...", "source": "auto", "upstream_latest": "0.38.0",
            "age_months": 0, "error": "..."}},
 "blocked": ["<human line per drift/unlisted>"], "probe_failed": ["..."], "warnings": ["<drift within minimum under warn>"],
 "summary": "preflight ok|preflight ok with N warning(s): ...|preflight BLOCKED: ...",
 "text": "<aligned multi-line table with header for stderr>"}
```

When `load_lock` raises `PreflightError(4, report)`, `report` has the full key set above (`ok, at, lock, enforce, tools, blocked, probe_failed, warnings, summary, text`) with `blocked = [summary]`.

## `toolchk` Python API (module `toolchk.py` at plugin root; stdlib only; must NOT be imported from `audit/`)

```python
class PreflightError(RuntimeError): code: int; report: dict      # 2 drift/unlisted · 3 probe failed · 4 lock broken
load_lock(path) -> dict                      # {"lock": {...defaults filled...}, "tools": {name: entry}}
dump_lock(path, lock: dict) -> None          # inverse of load_lock; atomic write (tmp + chmod + os.replace; mode rule above)
probe(name, entry, project_root=None, timeout=20.0) -> (installed: str, where: str)
check(needs: list[str], lock: dict | None = None, project_root=None, timeout=20.0) -> report
version_below(installed: str, minimum: str) -> bool  # numeric dotted comparison used for `minimum`
record(report, directory) -> Path            # writes <directory>/preflight.json
require(needs, project_root=None, record_dir=None, lock=None, timeout=20.0) -> report   # prints text+summary to stderr; raises on not ok
main(argv) -> int                            # --need T... | --all ; --project DIR (default cwd) ; --record DIR (writes on 0/2/3/4)
```

`check` never raises for a tool problem; it classifies. Exit/raise codes: 0 ok, 2 when `blocked` is non-empty,
3 when only `probe_failed` is non-empty, 4 for a broken lock. Upstream-latest and age never affect `ok`.
