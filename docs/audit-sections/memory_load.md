# Memory load (`memory_load`)

An inventory of private memory. It never changes a memory file. **No memory text, words,
entry hashes, profile names, snapshot names, session IDs, paths, addresses or
hostnames leave this component.** File rows use numeric profile indexes and fixed
kind/scope labels. No model, runtime plugin, provider, runtime config loader or
network is called. The machine-readable wiring sheet for the report is
`audit/wiring/memory_load.json` (keys, vocabulary, rules, sentences, inputs).

## Wiring sheet

```python
audit_memory_load(
    *, profile_path, memory_char_limit=FROM_PROFILE, user_char_limit=FROM_PROFILE,
    memory_provider=FROM_PROFILE,
    prompt_injecting_plugins: list[str] | None = None,
    project_families: dict | None = None, home_os=FROM_PROFILE, clock=time.monotonic,
) -> dict
```

Return: the standard component envelope (`findings`, `status`, `coverage`, plus the
shared `ok`/`error`/`classification`) with two siblings: `memory_load` (the
section) and `run_metrics` = `{elapsed_ms}`. `run_metrics` is the only
run-dependent value and is kept OUT of the section, so the raw section does not
change between two runs on an unchanged home. Section keys:
`status`, `coverage`, `files`, `snapshots`, `duplicates`, `systems`, `pending`,
`limits`, `truncated_by`, `other_os_coverage`, `foreign_technology_coverage`,
`foreign_technology_reason`, `input_sources`, `char_limits`.

- `files`: main/profile rows (`memories/MEMORY.md`, `memories/USER.md`); `profile_index=0` is the supplied root. Nonzero
  indexes identify immediate `profiles/*` children without disclosing names.
  Row keys: `kind`, `scope`, `coverage`, `profile_index`, `bytes`, `characters`,
  `entries`, `char_limit`, `percent_of_limit`, `over_limit`, `duplicate_entries`,
  `dated_entries`, `other_os_entries`, `other_os_coverage`,
  `private_network_entries`, `other_machine_entries`, `standing_order_entries`,
  `unasked_write_entries`, `approval_entries`, `foreign_technology_entries`,
  `foreign_technology_coverage`. Unreadable or over-budget rows keep only `kind`,
  `scope`, `profile_index`, `bytes`, `coverage` and null `characters`/`entries`.
- `snapshots`: `count` (snapshot directories), `files` (rows as above, `scope`
  `snapshot`) and `by_kind` summaries per memory kind (root home only, so
  `profile_index` is always 0): `kind`, `profile_index`, `files`,
  `min_characters`, `max_characters`, `min_percent_of_limit`,
  `max_percent_of_limit`, `identical_extra_snapshots`, `growth_characters`,
  `chronology_coverage`, `entries_added`, `entries_removed` and `changes` (a list
  of `{entries_added, entries_removed}` per consecutive pair).
- `duplicates`: `within_file_extra_entries`, `across_file_entries`,
  `cross_file_share`, `near_duplicate_pairs`, `coverage`. Snapshot byte identity is
  separate.
- `systems`: `builtin_nonempty` (boolean/null), `external_configured`
  (boolean/null), `external_provider` (`byterover`, `retaindb`, `other` or null),
  `prompt_injecting_plugins` (count/null), lower-bound `active_mechanisms`,
  `coverage`, and metadata-only `stores` (`name`, `profile_index`, `files`, `bytes`,
  `overlap`, and for state directories `same_size_groups`, `same_size_extra_files`).
- `pending`: `count`, `stale_edits`, `approval_edits`, `operations`,
  `unverified_edits`, `coverage`. Multiple qualifying operations in one record
  count once for stale/approval metrics.
- `limits`: `max_file_bytes`, `max_files`, `max_tree_entries`, `max_depth`,
  `max_entries`, `max_seconds`, `max_total_bytes`, `max_shingles`, `files_read`,
  `bytes_read`, `tree_entries`, `cuts`.
- `input_sources`: for `memory_char_limit`, `user_char_limit`, `memory_provider`
  and `home_os`, where the value came from: `config`, `default`, `caller`, `host`
  or `could_not_verify`.
- `char_limits`: one object per file kind, `memory` (MEMORY.md) and `user`
  (USER.md), each with `shipped_char_limit` (the value Hermes ships with:
  2200 / 1375, `hermes_cli/config_defaults.py:1304-1305`), `configured_char_limit`
  (the limit this audit used; null when unknown), `limit_ratio_to_shipped`
  (configured / shipped, rounded to 2 decimals; null when unknown),
  `limit_source` (the same token as `input_sources`: `config`, `default`, `caller`
  or `could_not_verify`) and `chars_over_shipped_limit` (characters in the
  main-home file beyond the SHIPPED limit; 0 when under it or when the file is
  absent; null when the file could not be measured). A lowered limit is reported
  here (ratio below 1) and produces no finding.

Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound; symlinked folders are counted as links and not measured.

All section string values are closed vocabulary:
`completed`, `not_measured`, `verified`, `could_not_verify`, `memory`, `user`,
`main`, `profile`, `snapshot`, `could_not_compare`, `other`, `byterover`, `retaindb`,
`memory_store.db`, `memlock`, `memory-lock`, `memory_lock`, `config`, `default`,
`caller`, `host`, plus `truncated_by` (module constant `TRUNCATION_REASONS`):
`time_budget`, `tree_entries`, `depth`, `files`, `file_bytes`, `total_bytes`,
`entries`, `shingles`, `credential_path`, `symlink`, `special_file`, `unreadable`,
`encoding`, `pending_shape`, `snapshot_shape`; outside the scan cuts, `truncated_by` can
also hold `input_unknown` (a setting the check needs could not be read) and `missing`
(the profile folder was not found). `foreign_technology_reason` is null when that
sub-check ran, else `no_projects` or `input_unknown`.
The shared envelope additionally uses `info`, `review_suggested`, `pass`, `warn`;
nulls are JSON null, not strings. Rule IDs and fixed consequence sentences below
are the only other emitted strings.

### Inputs

Only `profile_path` is required. The module resolves the rest itself:

- `memory_char_limit` / `user_char_limit` (omitted): read from
  `<profile>/config.yaml` keys `memory.memory_char_limit` /
  `memory.user_char_limit`, with the same safe reader, duplicate-key-rejecting
  parser and managed-overlay rule as `write_settings`. No config file or no key
  means the shipped defaults `DEFAULT_MEMORY_LIMIT` (2200) and
  `DEFAULT_USER_LIMIT` (1375), source `default`. An unreadable config, duplicate
  keys, a `${...}` value, a non-positive or non-integer value (booleans are not
  integers here) or an active managed overlay is **unknown**: `char_limit`,
  `percent_of_limit` and `over_limit` are null, no `over_limit` finding is made,
  and coverage is `could_not_verify`.
- `memory_provider` (omitted): `memory.provider` from the same config; missing
  means no configured external provider. Core sentinel names are not external
  providers. Unknown external names emit only `other`.
- `home_os` (omitted): the host OS (`linux`, `macos`, `windows`), which is the OS
  of the live home the audit inspects.
- Explicit caller values win (source `caller`); an explicit `None` limit or OS is
  unknown, an explicit `None` provider means no external provider.
- `prompt_injecting_plugins` and `project_families` come from the caller (the
  module does not read plugin manifests or project trees). `project_families`
  maps known family labels to counts; its keys are the native-family set. `None`
  means no projects to compare with; only the foreign-technology sub-check is skipped. Plugins are deduplicated by supplied name, but
  names never emit. An omitted plugin list is unknown; an explicit empty list
  means none supplied.

The resolved limits and OS apply to every inventoried profile and historical
snapshot: this is not a reconstruction of historical configuration.

## Source-confirmed formats

Hermes source citations (no code from homes/backups is executed):

- `tools/memory_tool.py:38-40` resolves the profile's `memories/`;
  `tools/memory_tool_store.py:303` chooses `MEMORY.md` or `USER.md`.
  `hermes_cli/profiles.py:288-290,2392` locates named profiles under `profiles/`.
- `tools/memory_tool_store.py:26,683-703`: UTF-8 BOM-tolerant text, universal
  newlines, stripped nonempty entries split on the **full** `\n§\n` delimiter.
  Bare section signs do not split entries. Characters mean decoded characters,
  not bytes. Raw text length includes formatting/newlines; byte identity uses
  unmodified bytes. Raw character load may differ slightly from rendered usage
  because the renderer strips entries before rejoining them.
- `hermes_cli/config_defaults.py:1304-1305`, `tools/memory_tool_store.py:188`,
  `tools/memory_tool.py:56` and `agent/agent_init.py:1247-1248`: config keys
  `memory.memory_char_limit` (default 2200) and `memory.user_char_limit` (default
  1375). Homes often configure other limits, so an unreadable config never
  falls back to a guess.
- `tools/memory_tool_store.py:255` stores the load-time block, `:654-657` returns
  that frozen snapshot and `:674-680` renders title, usage header and joined
  entries; `agent/system_prompt.py:527-531` appends the enabled built-in blocks.
  An on-disk file is not proof of current wire content.
- `agent/memory_provider.py:42-49` defines core provider sentinels;
  `agent/agent_init.py:1254-1278` selects `memory.provider`.
  `plugins/memory/byterover/plugin.yaml:1` and
  `plugins/memory/retaindb/plugin.yaml:1` supply the known-provider allowlist.
- `agent/turn_context.py:849-862` runs `pre_llm_call` hooks; its docstring
  (`:853-854`) states that returned context goes into the **user message**, not a
  system-prompt block. Counting supplied injecting plugins does
  not prove every model request receives their context.
- `tools/write_approval.py:66-84`: `pending/memory/*.json` records wrap a `payload`.
  `tools/memory_tool.py:131-140,165-176` confirms target, action, old_text and batch
  operations; `:67-82` pins `matched_entry`. Targets are only `memory` and `user`,
  never a path taken from the record. Replacement/patch/removal touching approval
  wording is counted conservatively, even when the old text is already stale.

- `hermes_cli/backup.py:1114` names `memory_store.db` (holographic memory store);
  `hermes_cli/plugins_state.py:143` places plugin state under `plugin-data/<namespace>`.

### Conventions not defined by Hermes (`third_party_convention: true`)

These are NOT in the Hermes source (a grep of the source finds no
`memory-bg-review` and no layout for the plugin state directories below). When absent they are simply
not present: no finding, no coverage penalty.

- Snapshot folder, `third_party_convention: true`. Layout:
  `backups/memory-bg-review/<YYYYMMDD-HHMMSS>/<hex id>/MEMORY.md` and
  `USER.md`. Only the
  ROOT home's folder is read, and only that exact shape: stamp `[0-9]{8}-[0-9]{6}`,
  id `[0-9a-f]{4,64}`, basename exactly `MEMORY.md` or `USER.md`, regular file.
  Anything else inside it (other names, deeper levels, non-matching directory
  names, symlinks, directories named `MEMORY.md`) is not read and reports
  `snapshot_shape` (or `symlink` / `credential_path`). Fixed-width stamps make
  lexical order chronological; this does not prove creation time.
- State directories of a third-party memory plugin, `memlock`, `memory-lock`,
  `memory_lock` (module constant `STATE_DIR_NAMES`; at a profile
  root or under `plugin-data/`), `third_party_convention: true`: listed by name and
  `lstat` only; no file inside is opened. `memory_store.db` is `lstat`ed only and is
  never opened (no SQLite connection, so no DB wrapper is needed). Both report
  `overlap: could_not_compare`; nothing is inferred about their contents.

## Measurements and thresholds

- Over limit: strictly greater than the caller-supplied character limit; review
  suggested. Equality is not over limit; an unknown limit is never compared.
  Snapshot copies are compared with the same supplied limit.
- Mostly dated: strictly more than 50% of at least six entries contain ISO-style
  dates or English month/day/year forms. Info only. Dates are not proof of staleness.
- Other machine (left-over content, **info**; design decision: not a current fault):
  at least two entries **or** at least 25% of nonempty entries
  contain another OS-family absolute path or private-network identifier. The
  union avoids double counting. Family tests: `/Users/`, `/home/`, drive-letter
  backslash paths, compared with the supplied linux/macos/windows label. Network
  tests cover RFC1918, tailnet IPv4 and `.ts.net`/`.local` hostnames. OS unknown
  (`home_os=None`): `other_os_entries` and the union `other_machine_entries` are
  null, `other_os_coverage` is `could_not_verify`, and the finding is not raised;
  `private_network_entries` remains available. This is a literal-path heuristic;
  it misses other-machine text that has no such path or address.
- Entries phrased as always/never instructions (rule `standing_orders`): exact
  case-insensitive word/phrase list `always`, `never`, `must`, `unasked`,
  `without asking`, `every session`. Info unless an entry also contains a write
  verb, skills/memory/config and unasked/without asking wording, when review is
  suggested. This is a word match on the user's own notes; it does not judge who
  wrote an entry, negation or intent.
- Approval-related words: `approve`, `approval`, `permission`, `confirm`, whole words.
- Exact duplicates: whitespace collapsed and casefolded entries. Within-file
  count is copies beyond the first. Cross-file share counts every occurrence with
  an equal entry in another live file, including profile copies. Near duplicates
  exclude exact equals and require Jaccard overlap of **eight-word shingles >=60%**.
  No semantic fact extraction or conflict detection is attempted. Short repeated
  facts inside otherwise different entries may not qualify.
- Foreign technology: entry counts using imported
  `audit.session_contamination.technology_counts`, never copied regexes. A match
  outside supplied family keys is heuristic review evidence, not irrelevance.
- Multiple systems: at least two root mechanisms: nonempty built-in store, one
  configured external provider, plus supplied injecting plugins. Historical
  snapshots and other profiles do not imply simultaneous activation. Disk-only
  stores are not counted active. Configured is not runtime-verified activation.
- State sprawl: **more than 100** regular files in a known state directory. State counts/bytes and equal-size groups use
  metadata only; size equality is not content equality or a pin count.
- Pending stale: old_text absent from current target, including confirmed missing
  target files. Unreadable/truncated targets are unknown, not stale. The approval
  count (rule `pending_edit_changes_approval_entry`) counts pending records with a
  replace/remove/patch operation that replaces or removes an entry that contains
  approval-related words (in old_text, pinned matched_entry or the current matching
  entry). It is a count; it does not say that any rule or setting would change.
- Limit raised above shipped (rule `limit_raised_above_shipped`): a limit read
  FROM `config.yaml` (`limit_source` `config`) that is strictly greater than the
  shipped value for MEMORY.md or USER.md. Review suggested when a raised file's
  ratio is at least 2.0 (module constant `RAISED_REVIEW_RATIO`), info otherwise.
  An equal or lower limit, the shipped default, a caller-supplied limit or an
  unknown limit gives no finding. This is a measurement of the setting; it is
  reported alongside, and does not change, `over_limit` and the percentages.

Do not flag empty memories, a few ordinary entries below budget, or a single
memory mechanism. Missing/unreadable measurements produce informational coverage
findings, never a claim that the home is clean.

## Read policy and bounds

Memory content is read only from built-in memory files, the explicit snapshot
subtree's `MEMORY.md`/`USER.md` and pending-memory JSON: at most **200 files**, **512 KiB/file**, **16 MiB
aggregate**, all strict UTF-8 (binary/NUL rejected). Discovery stops at **10,000
entries**, **eight recursive levels**, and a cooperative injectable **five-second**
deadline. Near comparison examines at most **2,000 live entries** and **100,000
shingle positions**. No filesystem/network operation can be forcibly interrupted;
checks occur between bounded operations. Cap hits preserve available numbers and
mark incomplete coverage. Byte budgets include data consumed before a detected
file race. When a limit or the provider is omitted, the module also reads
`<profile>/config.yaml` (see Inputs and the config read below). No databases,
caches, temp files or sidecars are written. SQLite is never opened, so no DB
wrapper is needed.

Discovery is descriptor-relative, `lstat`/`follow_symlinks=False`; opening uses
`O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, checks regular-file identity before/after reads,
and refuses symlinked roots/parents/leaves. AppleDouble `._*` files are skipped.
Credential-looking paths use `audit.policy.credential_path` on the absolute path
plus conservative secret/token/credential/.env/.pem/.key name exclusions.

**Credential-policy exception (README disclosure sentence):** Defuzz reads one
otherwise-excluded backup location, the regular files
`backups/memory-bg-review/<timestamp>/<id>/MEMORY.md` and `USER.md` in the main
Hermes home, to count memory snapshots; nothing else under `backups/` is opened.

The exception is enforced twice: by the discovery predicate (`_blocked`) and inside
the private reader itself (`_read_private_file` refuses any path outside its
allowlist: `memories/{MEMORY,USER}.md`, `profiles/<p>/memories/{MEMORY,USER}.md`,
`[profiles/<p>/]pending/memory/*.json`, and the exact snapshot shape). Profile
`backups/` folders, `backups/config/`, deeper or differently named snapshot
paths, `..` components and credential names inside a snapshot directory remain
refused. Declared-credential and uncertain-root run state (`audit/policy.py:39-45`)
is still applied to the absolute snapshot path.

Private reader: memory, snapshot and pending-edit content uses a dedicated
reader, not the fingerprint/capture reader. The capture reader retains the bytes
it reads and computes a content digest. The dedicated reader keeps memory bytes
in this call only and computes no hash of them. Snapshot identity and entry churn
compare bytes and normalized text in memory.

Config read: omitted limits and the provider come from `config.yaml`, read with the
shared `safe_read_regular_file` reader (at most `MAX_CONFIG_BYTES`). For an
existing file this reader computes a SHA-256 of the bytes and turns it into a
keyed digest with the private audit key. If that key does not exist yet, it is
created: 32 random bytes in `audit.key` (mode 0600, with an `audit.key.lock`
file), next to the audit store, or `plugin-data/defuzz/audit.key` in the Hermes
home when no store is in scope. If the key cannot be read or created, the limits
are unknown. The digest is not part of this section.

The result is built with `make_finding` / `make_component_envelope` and serialized
by the normal evidence path. It contains only counts and the closed vocabulary
above (no entry text, words, hashes, hostnames, addresses, names or paths).

## Finding contract (exact sentences)

All IDs have prefix `memory_load.`; findings contain numerical evidence only.

| Suffix | Classification | Consequence |
| --- | --- | --- |
| `over_limit` | review_suggested | Memory files (live or snapshot copies) are longer, in characters, than the character limit used for this audit; this compares file length only and does not measure what is sent with a request. |
| `mostly_dated_entries` | info | Memory files were counted where more than half of at least six entries contain a calendar date; a date does not show that the entry is out of date. |
| `other_machine_entries` | info | Memory files were counted whose entries contain another operating system's home-path form or a private-network address; this is left over text from another machine, and the count does not show that it is used or wrong here. |
| `standing_orders` | info / review_suggested as above | Entries phrased as always/never instructions were counted by word match; the count does not show who wrote them, whether they are followed, or whether they are wrong. |
| `duplicate_entries` | info | Normalized entries or eight-word shingles were counted that repeat within or across live memory files; the count does not show that the repeated text means the same thing. |
| `foreign_technology_entries` | review_suggested | Entries were counted that name technology families absent from the supplied projects; the count does not show that those entries are irrelevant. |
| `memory_state_sprawl` | info | A memory state directory, found by name and counted by file metadata only, holds more than 100 files; the count does not show whether the files are used or repeat each other. |
| `stale_pending_edits` | info | Pending memory edits were counted whose old text is absent from the current target file; the count does not predict whether approving them would succeed. |
| `pending_edit_changes_approval_entry` | review_suggested | This counts pending memory edits where an edit replaces or removes an entry that contains approval-related words; it is a word count and does not show that any approval setting or instruction would change. |
| `limit_raised_above_shipped` | info / review_suggested (ratio >= 2.0) | The character limit for a memory file is set above the value Hermes ships with; text in these files is sent with every request, so a higher limit allows more text on every request. The setting was measured from config.yaml and does not show who changed it or why. |
| `multiple_memory_systems` | review_suggested | Two or more memory mechanisms are configured or present together; the audit counted them from config and files, and did not measure what each adds to a request or whether they repeat each other. |
| `could_not_verify` | info, could_not_verify coverage | Some memory measurements could not be verified; missing coverage is not a clean result. |

Every sentence is fixed (no interpolated numbers or names). Numbers are in the
finding's `evidence`: `count` for the counted rules, `mechanisms` and
`builtin_nonempty` for `multiple_memory_systems`, `cuts` for `could_not_verify`;
for `limit_raised_above_shipped`, per kind (`memory`, `user`):
`memory_shipped_char_limit`, `memory_configured_char_limit`,
`memory_limit_ratio_to_shipped`, `memory_characters`, `user_shipped_char_limit`,
`user_configured_char_limit`, `user_limit_ratio_to_shipped`, `user_characters`
(numbers only; a value that is unknown is left out).
