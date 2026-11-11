# TOOLS.lock — file format and toolchk API

`toolchk.py` reads UTF-8 TOML from a bounded regular file and writes it atomically.
Its serializer preserves leading comments and uses TOML short or Unicode escapes.

## Fields

Optional `[lock]` fields use defaults from `toolchk.DEFAULT_HEADER`:
| Field | Meaning |
| --- | --- |
| `schema` | Supported schema identifier, validated by `load_lock`. |
| `enforce` | `warn` or `block`; controls compatible version drift. |
| `age_nudge_months` | Non-negative age reminder threshold; zero disables it. |
| `network` | Boolean; enabling it does not add a network advisory provider. |

Each other table names a tool. Required fields are `version`, `chosen` (ISO date),
`reason` (non-empty) and `probe`. Optional `minimum` is a dotted numeric supported
floor. `source` is `auto`, `human` or `agent`, defaulting to `human`.
Tool names and field shapes are validated by `load_lock`.

| `probe` | Fields and result |
| --- | --- |
| `command` | Required `argv`; optional `resolve = "hermes-tools"`. Runs an allowed version/help command and extracts a version token. |
| `module` | Optional `module`, defaulting to the tool name; reads installed distribution metadata. |
| `interpreter` | Reports the Python interpreter running Defuzz. |
| `pm` | Optional `package`, defaulting to the tool name; reads Hermes package metadata. |
| `file` | Required project-relative `file` and exactly one of `key` or `regex`. A dotted key reads JSON/TOML; regex uses its first capture group or the whole match. |

Command probes use a filtered PATH, minimal environment and neutral working folder.
File probes enforce allowed filenames, bounded regular-file reads, path and secret
checks, and restricted regexes. See `toolchk.py` for the accepted names and limits.
Optional `advisory` supports local `kind = "json"` with `path` and `key`, or
`kind = "pm"`. Advisory results and age reminders do not affect acceptance.

## Enforcement

`check` classifies tools as `unlisted`, `probe-failed`, `ok` or `drift`.
Missing lock entries block. A version below `minimum` blocks in either mode.
Other drift warns only when a minimum exists and `enforce = "warn"`;
without a minimum, the entry is an exact pin. Probe failures fail preflight.

## Template locks and seeding

`tool_seed.py` probes detected automatic entries and existing automatic floor
entries, recording the installed version and selection date. It preserves a
floor's probe, minimum and reason, and keeps human/agent entries unchanged.
Undetected automatic entries without a floor are retained without re-probing.

Template floor locks and supported manifest pins supply creation-time minimums.
A needed tool below an enforced floor stops creation before publication; see
[scaffold acceptance](scaffold-ci.md). Template files hold the actual requirements.

## API and reports

`load_lock` and `dump_lock` read/write locks; `probe` reports an installed version;
`check` returns a report; `require` raises `PreflightError` on failed preflight.
`record` writes `preflight.json`. Reports include tool results, blocked entries,
probe failures, warnings and a summary. Exit/error codes are `0` for success,
`2` for blocked tools, `3` for probe failures alone, and `4` for a broken lock or
refused report write. Function signatures and CLI options live in `toolchk.py`.
