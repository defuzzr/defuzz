# Profile duplicates (`report.profile_duplicates`)

## What it measures

`audit.profile_duplicates.audit_profile_duplicates(profile_path)` measures duplicated content, cloned memory files, repeated regenerable caches, profile naming families, and unpopulated profile folders across `<hermes_home>/profiles/<name>/`. `profile_path` must be the Hermes HOME ROOT that contains `profiles/`; the module needs no other input and never opens `config.yaml`. When the audited profile is itself a named profile (its path is `<hermes_home>/profiles/<name>`), the caller passes the home root two levels up. If the given folder has no `profiles/` child but its parent folder is named `profiles`, the section reports `status` `not_measured` with `reason` `named_profile_given` instead of a silent 0 profiles.

Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound. Symlinks (to files or folders) are never followed and their targets are not measured; each one is recorded as a `symlink_refused` cut, so coverage becomes `could_not_verify`.

1. **Profile inventory**:
   - Count of non-hidden profile directories under `profiles/` (ignoring internal `.deleted` tombstones and `.staging-*` directories: `hermes_constants.py:318,345-408`, `hermes_cli/profiles_initialization.py:9-18`).
   - Per-profile regular file count and total byte size via `os.scandir` and `os.lstat` (entries are never followed through symlinks).
   - Empty profiles (`file_count == 0`), log-only profiles (every file is under `logs/` or ends with `.log`), and profiles with no `config.yaml` at the profile root. A profile whose walk was incomplete (unreadable directory, depth cap, time or entry cap) is never counted as empty, log-only or config-less.
   - Credential-classified folders inside a profile (`mcp-tokens/`, `vault/`, `pairing/`, `backups/`, `checkpoints/`, `platforms/` …, per `audit.policy`) are never walked; their number is reported as `skipped_credential_dirs` (not a coverage cut) and their bytes are not in `profiles_total_bytes`.
2. **Exact duplicates across profiles (and between a profile and the main home)**:
   - Groups non-credential regular files (`size > 0`) by `(size_bytes, sha256)`.
   - Only hashes files whose size appears in at least two profiles (or in a named profile and at the same relative path in `<hermes_home>`).
   - Files `>= 1 MiB` are hashed regardless of basename; smaller files (`< 1 MiB`) are hashed only when the basename is `SOUL.md`, `MEMORY.md`, `USER.md`, `AGENTS.md`, `SKILL.md`, `models_dev_cache.json`, or `*.db`. `config.yaml` (and `config.yaml.*`, `config.yml*`) is never hashed or opened, in profiles or the main home: it can hold API keys (`model.api_key`, `hermes_cli/config.py:766-781`), so it is treated like a credential file (size only).
   - Databases (`*.db`, e.g. `cron/executions.db`, `projects.db`) are hashed as raw bytes; SQLite is never used, no lock is taken, so a live database is neither blocked nor altered (a database written during the read just hashes differently).
   - Each `top_duplicate_groups` row: `location`, `file_kind`, `copies`, `profile_copies`, `distinct_profiles`, `in_main_home`, `size_bytes`, `wasted_bytes = (copies - 1) * size_bytes`, `executable_magic`, and `regenerable_cache` (every copy is a per-profile cache file, see 4). No file name is emitted. `location` is the absolute path of the existing first-level folder inside ONE member profile where the copies live: `<hermes_home>/profiles/<first member, sorted>/<first path component>` (never deeper), or the profile folder itself for a file directly in the profile root; members whose profile or first-level folder name fails the safe-name rule (see 6) are skipped, and `location` is `null` when no member qualifies. `file_kind` is one of `hub_index_cache`, `models_dev_cache`, `provider_models_cache` (cache files, see 4), `skill_md`, `identity_md` (`SOUL.md`, `MEMORY.md`, `USER.md`), `agents_md`, `database` (`*.db`), `executable_file` (executable magic bytes) or `large_file` (any other file of at least 1 MiB), taken from the first member.
   - Totals: `duplicate_group_count`, top 15 groups by wasted bytes, `skill_md_duplicate_groups`, `skill_md_duplicate_copies`, `total_wasted_bytes`, `wasted_bytes_including_main_home`, `cache_duplicate_wasted_bytes` (the part of `total_wasted_bytes` in `regenerable_cache` groups), `wasted_bytes_excluding_caches` (`total_wasted_bytes - cache_duplicate_wasted_bytes`), and `wasted_share_of_profiles`. The `identical_files` rule uses `wasted_bytes_excluding_caches`: cache copies are reported once, under `per_profile_caches`.
   - For credential-looking files (`.env`, `auth.json`, etc., per `audit.policy.credential_path`) and `config.yaml`, records only a size-only row in `credential_same_size_groups` when 2+ profiles have a file of the same class, placement and `st_size`: `file_kind` (`env_file`, `auth_json`, `config_yaml`, or `credential_other` for any other credential-classified file), `suffixed_copy` (a suffixed copy such as `.env.bak-1` or `config.yaml.bak-<date>`), `at_profile_root`, `profiles_count`, `size_bytes`, `hashed` (always `false`), `observation` (always `size_only_not_hashed`). These rows never carry a file name or a path. Hermes seeds the same placeholder `.env` into new profiles (`hermes_cli/profiles_initialization.py:39-43`), so same-size `.env` rows are expected and never a finding.
3. **Cloned identity and memory (`cloned_identity`)**:
   - Locates `SOUL.md` at profile root (`hermes_cli/profiles.py:43`) and `memories/MEMORY.md`, `memories/USER.md` (`hermes_cli/profiles.py:46`, `tools/memory_tool.py:38-40`). Root `MEMORY.md`/`USER.md` are used only when `memories/<file>` is absent; the source lists them only as export artifacts (`hermes_cli/profiles.py:264`), not as a place Hermes reads memory.
   - `by_kind` has the keys `SOUL.md`, `MEMORY.md`, `USER.md`, each with `profiles_with_file`, `identical_group_sizes`, `identical_profiles_count`, `median_shared_line_share`, `max_shared_line_share`.
   - The top-level numbers (`identical_profiles_count`, `median_shared_line_share`, `max_shared_line_share`, `profiles_above_50pct`) and the finding use `MEMORY.md` and `USER.md` only. `SOUL.md` is measured but excluded, because Hermes seeds the same default `SOUL.md` into every new profile (`hermes_cli/profiles_initialization.py:45-48`, `hermes_cli/default_soul.py:9`).
   - Near-clones: splits each file (up to 256 KiB each, at most 200 files) into lines/sentences, normalizes whitespace and case, hashes each line with SHA-256 in memory, and computes the share of lines in each file that also appear in `>= 50%` of the other profiles. Only counts and shares are emitted: no line text, no line hash, no file hash. `files` lists at most 150 rows (`path` = the profile folder, `file` = `SOUL.md` | `MEMORY.md` | `USER.md`, `line_count`, `shared_line_share`), only for profiles with a safe name; `files_count` gives the total of all rows.
4. **Per-profile regenerable caches (`per_profile_caches`)**:
   - Sums bytes across profiles for `skills/.hub/` (including `skills/.hub/index-cache/hermes-index.json`: `tools/skills_hub.py:61-67`, `tools/skills_hub_search.py:31-33`), `models_dev_cache.json` / `models_dev_cache.etag` (`agent/models_dev.py:241,245`), and `provider_models_cache*` (`hermes_cli/models.py:1857-1859`, `hermes_cli/models_cache_lock.py:21-24`). Keys: `total_bytes`, `hub_index_cache_bytes`, `hub_index_cache_profiles`, `models_dev_cache_bytes`, `models_dev_cache_profiles`, `provider_models_cache_bytes`, `provider_models_cache_profiles`, `profiles_with_caches`.
5. **Profile families (`profile_families`)**:
   - `family_count` and `families` (at most 50): each family is `kind` = `alphabetic_prefix` (shared alphabetic prefix of length `>= 2` with `>= 3` members) or `digit_series` (trailing digit series with `>= 3` distinct numbers), `member_count`, and `paths` (the member profile folders, at most 50). No prefix or label string is emitted. Computed from safe names only.
6. **Profiles in the output**: a profile is never named by a string; it is named by the absolute path of its existing folder `<hermes_home>/profiles/<name>`, and only if the name matches `[A-Za-z0-9._-]{1,64}`. Other profiles are counted (in `unsafe_profile_name_count` and every total) but never listed. Each `profiles` row: `path`, `file_count`, `size_bytes`, `empty`, `logs_only`, `has_config` (at most 50 rows, sorted). `empty_profiles`, `log_only_profiles` and `no_config_profiles` are each `{count, paths}`: `count` is the total, `paths` at most the first 50 profile folders (sorted).

## Output shape

- Returned dict (the wiring envelope): exactly `profile_duplicates` (the section), `findings`, `run_metrics` (`{"elapsed_ms": int}`), `status` (legacy `pass` | `fail`, ignored by `adapt_component_result`) and `coverage`. `run_metrics` is the only run-dependent value and must be stored outside the fingerprinted report: two runs on an unchanged home return the same raw section and findings.
- No tokenisable string: every string in the section and its findings is either a fixed vocabulary token or the absolute path of an existing folder. The report serializer keeps such a path only in a declared path field and only when it resolves to an existing item (stored as the resolved path); it turns any other free string into a per-run token. A token or path that overlaps a credential value read in the same run is sealed as a `credential_overlap` token, even when it equals an ordinary word. Section paths appear only under `path`, `paths` and `location`, and only at two depths: a profile folder, or a first-level folder inside a profile. All paths are built from the resolved `profile_path`. Findings name the measured folder by its absolute path (`<hermes_home>/profiles`, `<hermes_home>` when no profile was measured, or the named profile folder for `named_profile_given`) in `affected_identities` and `source_paths`; when the given path is missing or not a real folder both lists are empty. Raw measurements are the same for an unchanged home within budgets. The sealed output is unchanged only while every kept path still resolves and no value overlaps a credential value read in the same run; otherwise it holds tokens keyed per run, which differ between runs.
- Section keys (completed): `status`, `coverage`, `truncated_by`, `cut_reasons`, `profile_count`, `unsafe_profile_name_count`, `skipped_credential_dirs`, `profiles_total_bytes`, `profiles_total_files`, `profiles`, `empty_profiles`, `log_only_profiles`, `no_config_profiles` (each with `count`, `paths`), `duplicate_group_count`, `top_duplicate_groups`, `skill_md_duplicate_groups`, `skill_md_duplicate_copies`, `total_wasted_bytes`, `wasted_bytes_including_main_home`, `cache_duplicate_wasted_bytes`, `wasted_bytes_excluding_caches`, `wasted_share_of_profiles`, `credential_same_size_groups`, `cloned_identity`, `per_profile_caches`, `profile_families`, `limits`, `thresholds`. Not measured: `status`, `coverage`, `reason`, `truncated_by`, `cut_reasons`, `limits`.
- `limits`: `max_entries`, `max_bytes_hashed`, `max_files_hashed`, `max_seconds`, `max_depth`, `max_identity_file_bytes`, `max_identity_files`, `max_names_listed`, and the counters `entries_walked`, `files_hashed`, `bytes_hashed`, `identity_files_read`, `cuts`.
- `thresholds`: `min_profiles_for_findings`, `min_repeated_binary_bytes`, `min_repeated_binary_profiles`, `identical_files_wasted_bytes`, `cloned_identity_min_profiles`, `cloned_identity_shared_line_share`, `per_profile_cache_bytes`, `min_empty_or_log_only_profiles`, `min_family_prefix_len`, `min_family_members`.
- `status`: `completed` | `not_measured`. `coverage`: `verified` | `could_not_verify`. `reason` (not measured): `missing_profile_root`, `unreadable_profile_root`, `invalid_profile_root`, `named_profile_given`.
- `truncated_by` / `cut_reasons` values: `time_budget`, `entries_limit`, `files_hashed_limit`, `bytes_hashed_limit`, `depth_limit`, `identity_files_limit`, `identity_file_bytes_limit`, `symlink_refused`, `symlink_or_non_dir_profiles_root`, `credential_root_refused`, `unreadable_profiles_dir`, `unreadable_directory`, `non_directory_profile_entry`, `special_file_refused`, `non_regular_file`, `stat_error`, `read_error`, `inode_changed`, `invalid_encoding`, `unsafe_or_symlink_path`. A stop cap (`time_budget`, `entries_limit`, `files_hashed_limit`, `bytes_hashed_limit`) always wins `truncated_by` over an earlier exclusion; `cut_reasons` lists every reason seen. The `could_not_verify` finding uses `cut_or_exclusion` when no reason was named.
- Finding evidence (numbers only, plus `reason` / `truncated_by` labels): `repeated_binary`: `groups`, `copies`, `wasted_bytes`, `bytes_wasted`; `identical_files`: `duplicate_groups`, `wasted_bytes`, `bytes_wasted`, `wasted_bytes_excluding_caches`, `cache_duplicate_wasted_bytes`, `profiles_total_bytes`, `wasted_share`; `cloned_identity_files`: `affected_profiles`, `identical_profiles`, `profiles_above_50pct`, `median_shared_line_share`, `max_shared_line_share`; `per_profile_caches`: `total_bytes`, `hub_index_cache_bytes`, `models_dev_cache_bytes`, `provider_models_cache_bytes`, `profiles_with_caches`; `empty_profiles`: `empty_profiles`, `log_only_profiles`, `no_config_profiles`, `total_empty_or_log_only`; `could_not_verify`: `cuts`, `truncated_by`, `reason`.
- The full sealed vocabulary (including the section name `profile_duplicates`), key list and free-string list (kept absolute paths only) are in `audit/wiring/profile_duplicates.json` (tested against the code).

## Rules

Every consequence is one fixed sentence; the numbers are in the finding's evidence.

| Rule id | Classification | Consequence |
|---|---|---|
| `profile_duplicates.repeated_binary` | `review_suggested` | An executable file of at least 10 MiB is stored as byte-identical copies in at least three profiles; this measures duplicated disk bytes and does not show whether any profile runs it. |
| `profile_duplicates.identical_files` | `review_suggested` | Byte-identical non-credential files repeated across profiles take more than 100 MiB beyond one copy each, not counting regenerable caches; this measures redundant storage across profile directories and does not establish which profile copy is authoritative. |
| `profile_duplicates.cloned_identity_files` | `review_suggested` | Byte-identical MEMORY.md or USER.md files appear in at least three profiles, or more than half of the lines in the median memory file match other profiles; this measures matching content only and cannot tell which copy is the original or how the files came to match. |
| `profile_duplicates.per_profile_caches` | `info` | Regenerable hub and model catalog caches repeated across profile directories exceed 50 MiB; this measures disk space used by per-profile cache copies and does not show data corruption. |
| `profile_duplicates.empty_profiles` | `info` | At least five profile directories are completely empty or contain only log files; this counts folder contents and does not show whether a gateway still references them. |
| `profile_duplicates.could_not_verify` | `info` | Profile duplicate measurements hit a safety bound, symlink exclusion, or read error before all profile entries were verified; partial counts are retained and unverified regions are not claimed clean. |

## Thresholds

| Constant | Value | Purpose |
|---|---|---|
| `MIN_PROFILES_FOR_FINDINGS` | `3` | Do not flag homes with 0, 1, or 2 named profiles. |
| `MIN_REPEATED_BINARY_BYTES` | `10 MiB` (`10,485,760`) | Only executables of at least this size count as repeated binaries. |
| `MIN_REPEATED_BINARY_PROFILES` | `3` | Requires at least 3 profiles sharing the identical executable-magic binary. |
| `IDENTICAL_FILES_WASTED_BYTES_THRESHOLD` | `100 MiB` (`104,857,600`) | Compared with `wasted_bytes_excluding_caches`, so repeated hub caches alone do not trigger it. |
| `CLONED_IDENTITY_MIN_PROFILES` | `3` | Flags byte-identical `memories/MEMORY.md` or `memories/USER.md` in at least 3 profiles. |
| `CLONED_IDENTITY_SHARED_LINE_THRESHOLD` | `0.5` (`50%`) | Flags near-identical `MEMORY.md`/`USER.md` files when the median shared-line share exceeds 50%. |
| `PER_PROFILE_CACHE_BYTES_THRESHOLD` | `50 MiB` (`52,428,800`) | Repeated regenerable caches (such as `skills/.hub/` and `models_dev_cache.json`) across profiles above this total. |
| `MIN_EMPTY_OR_LOG_ONLY_PROFILES` | `5` | Flags at least 5 profile folders that are empty or hold only logs. |
| `MIN_FAMILY_PREFIX_LEN` / `MIN_FAMILY_MEMBERS` | `2` / `3` | Profile names sharing an alphabetic prefix of at least 2 letters, in groups of at least 3. |
| `MAX_ENTRIES` | `300,000` | Bounds total directory entries walked. |
| `MAX_BYTES_HASHED` | `2 GiB` (`2,147,483,648`) | Bounds total bytes hashed. |
| `MAX_FILES_HASHED` | `20,000` | Bounds total files opened and hashed. |
| `MAX_SECONDS` | `30.0` | Cooperative wall-clock budget via injectable `clock`, checked between directory entries, between files and between 1 MiB chunks of one file; a cut keeps every group already hashed. |
| `MAX_NAMES_LISTED` / `MAX_IDENTITY_ROWS_LISTED` | `50` / `150` | Output-size caps on path lists, profile rows, families and identity rows (not coverage cuts; totals are always given). |
| `MAX_IDENTITY_FILE_BYTES` / `MAX_IDENTITY_FILES` | `256 KiB` / `200` | Bounds per-file and total reads for near-clone line hashing. |

## What it cannot tell

- Which profile was the original source of a cloned `SOUL.md`, `MEMORY.md`, `USER.md`, `SKILL.md`, database, or binary, or whether edits were intended to propagate across clones.
- Whether two credential files (`.env`, `auth.json`) or `config.yaml` files with identical byte sizes have identical contents, because they are never opened or hashed.
- How profile copies came to match (`hermes profile create --clone` copies `config.yaml`, `.env`, `SOUL.md` and the memory files by design: `hermes_cli/profiles.py:43-46`).
- What is inside credential-classified folders: only their number (`skipped_credential_dirs`) is reported. If the `profiles/` folder itself is credential-classified, nothing is walked and `credential_root_refused` is reported.
- Unique disk usage: sizes are file sizes, so reflinked or deduplicated copies are still counted once per copy.
- Whether a repeated binary in `<profile>/bin/` is actively invoked at runtime by that profile.
- Whether an empty or log-only profile folder is still referenced by an external script or service unit.

## Do-not-flag list

- A Hermes home with 0, 1, or 2 named profiles (`profile_count < 3`).
- Profiles each having their own distinct `state.db`, `auth.json`, and `.env`.
- Identical empty (`0`-byte) files or small non-allowlisted files (`< 1 MiB`) such as `.lock` files, `.gitkeep`, or `.etag`.
- Identical bundled stock `SKILL.md` files across profiles when there are fewer than 3 profiles.
- Byte-identical `SOUL.md` files (Hermes seeds the same default into every profile); same-size placeholder `.env` files.
- Identical regenerable caches (hub index, model catalogs): reported as `info` under `per_profile_caches`, never as `identical_files` (tested with 4 profiles x 41 MB hub cache).
- A healthy home (3 profiles, default `SOUL.md`, own memories, bundled skills, own databases, logs) yields no finding above `info` (tested).

## Read policy

- **Stat'ed only (`os.scandir`, with entries inspected by `os.lstat` or `entry.stat(follow_symlinks=False)`)**:
  - All profile directories and entries under `<hermes_home>/profiles/<name>/` (up to `MAX_ENTRIES = 300,000` and `MAX_DEPTH = 64`).
  - Credential files (`.env*`, `auth.json`, etc.) matched by `audit.policy.credential_path`: only `st_size` and mode from `lstat` are observed; credential directories (`mcp-tokens/`, `vault/`, `pairing/`, etc.) are counted but not descended into.
  - Matching relative paths in `<hermes_home>` for files already seen in named profiles.
  - `config.yaml` (and suffixed copies) everywhere: size only.
- **Read / hashed in `1 MiB` chunks with `os.open(O_RDONLY | O_NOFOLLOW | O_NONBLOCK)`, trying `O_NOATIME` first**:
  - Non-credential regular files (`size > 0`) whose exact byte size appears in 2+ profiles (or in a profile and `<hermes_home>`) and that are either `>= 1 MiB` or named `SOUL.md`, `MEMORY.md`, `USER.md`, `AGENTS.md`, `SKILL.md`, `models_dev_cache.json`, or `*.db`, up to `20,000` files and `2 GiB` total.
  - Non-credential regular identity/memory files (`SOUL.md`, `memories/MEMORY.md`, `memories/USER.md`, or root `MEMORY.md`/`USER.md`) up to `256 KiB` each and `200` files total; only line-hash overlap ratios are retained, never file text.
  - `O_NOATIME` (Linux, files owned by the user running the audit) keeps access times unchanged; where it is unavailable (other systems, or files owned by someone else, where it is refused) the file is opened without it, so access times may change.
- **Never opened**:
  - Any path matching `audit.policy.credential_path` (`.env*`, `auth.json`, `*token*`, `*secret*`, `*credential*`, `*.pem`, `*.key`, `mcp-tokens/`, `pairing/`, `vault/`, etc.), and `config.yaml*` / `config.yml*`.
  - No database is ever opened through SQLite (`_open_user_db` exists for the house rule but is unused).
  - Symlinks, FIFOs, sockets, device nodes, or any path outside `profile_path`.
