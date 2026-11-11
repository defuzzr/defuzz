# Skill packs (`report.skill_packs`)

`audit/skill_packs.py` (`audit_skill_packs`) measures, from files only, the size of the skills index Hermes puts in every prompt, recorded per-skill usage, groups of skills that share an install signal, licence copies and large binary files inside skill folders, always-on skills, and the size of non-stock `SKILL.md` files. It reports measurements and their limits; it does not say why a home looks the way it does.

Entry point: `audit_skill_packs(profile_path, *, disabled_skills=None, auto_load_skills=None, external_dirs=None, now=None, clock=None, host_platform=None) -> dict`.

- `profile_path`: the profile directory. It is the only argument the report needs to pass.
- `disabled_skills`, `auto_load_skills`, `external_dirs`: `None` (default) means the module reads `skills.disabled`, `skills.auto_load` and `skills.external_dirs` from `<profile>/config.yaml` itself (bounded read, same rules as every other read; only those three keys are used and no config text is output). An explicit value, also `()`, overrides the config. An unparseable config, duplicate keys, a non-mapping `skills` block, a `${VAR}` reference or non-string list items are cuts (`could_not_verify`). `skills.platform_disabled` depends on the session platform and is not applied.
- `host_platform`: `None` means `sys.platform`. The audited home's own platform is not knowable from files, so the figure assumes the current platform; `index.platform_excluded_count` shows how many skills the platform and environment gates removed.
- `now` is accepted and ignored (all ages are relative to the usage file's own newest timestamp). `clock` is a test hook for the time budget.

Return value: `{"skill_packs": <section>, "findings": [...], "run_metrics": {"elapsed_ms", "time_budget_hit"}, "status", "coverage", "ok", "error", "classification"}` (the last three come from the shared `make_component_envelope`). `run_metrics` holds the only run-dependent figures and is kept out of the section, so two runs on an unchanged home give the same raw section and findings. The wiring sheet for the report is `audit/wiring/skill_packs.json`.

## What it measures and how

1. **Index cost (`index`)**
   - Scans `<profile>/skills` (`TIER_LOCAL = 1`) and in-profile `external_dirs` (`TIER_EXTERNAL = 3`), pruning `EXCLUDED_SKILL_DIRS` and, below a skill, `SKILL_SUPPORT_DIRS` (`agent/skill_utils.py:28-36,878-891`).
   - Parses frontmatter like Hermes: YAML mapping, or the key:value line fallback when YAML fails; an undecodable `SKILL.md` is listed with no description (`agent/skill_utils.py:71-91`, `agent/prompt_builder.py:1154-1165`).
   - Resolves names exactly like `resolve_skill_catalog` (aliases: declared name, folder name, relative path; lower tier wins; identical copies under one root resolve to the shallower; other same-tier collisions are listed by relative path or not at all, `agent/skill_utils.py:445-519`).
   - Hides what Hermes hides: `skills.disabled` matched by folder name, declared name or `load_name` (`hermes-agent` can never be disabled, `agent/skill_utils.py:278-293`, `agent/prompt_builder.py:1400-1433`); `platforms:` not matching `host_platform` (`agent/skill_utils.py:22,94-118`); and `environments:` whose tags are all detected environments (`kanban`, `docker`, `s6`; false in an ordinary desktop session, `agent/skill_utils.py:121-174`). These are `platform_excluded_count`.
   - Renders the block the way `_render_skills_index` does (category = `general` / folder name / path above the folder per `agent/prompt_builder.py:1137-1151`; one-skill categories as a top-level row, others under a `  <category>:` line; rows `- name: description`; description clipped to 60 characters at a word boundary, `agent/skill_utils.py:846-870`; fixed header and footer, `agent/prompt_builder.py:1295-1360`). `index_chars` is the length of that whole block; `estimated_tokens = index_chars // 4`; `name_chars` and `description_chars` are the row parts.
   - Checked against Hermes's own `build_skills_system_prompt` (Linux, tool list unknown, default variant) on copies of the upstream bundled tree and of all official skills: identical lengths.
   - **Upper bound.** `runtime_gated_count` counts listed skills whose visibility also depends on the session (`requires_apps`, unknown `environments`, `metadata.hermes` tool/toolset/session-platform conditions, `agent/skill_utils.py:177-206,728-743`). They are counted as listed, so `index_chars` is an upper bound whenever `runtime_gated_count > 0`; the `index_cost` sentence therefore says "about" and "upper bound".
   - `.skills_prompt_snapshot.json` (`agent/prompt_builder.py:1082-1135`): `version`, entry count, clipped `description_chars`, and `stale_count` for entries with no matching `SKILL.md` under `skills/` (by `rel` for v4+, inferred from `category`/`skill_name` for v3). Stale entries have no file on disk, so they are counted, never named. The snapshot is a cache Hermes rebuilds when its manifest no longer matches; its counts cover a different skill set from `index` (it includes disabled and removed skills).

2. **Usage (`usage`)** from `skills/.usage.json` (`tools/skill_usage.py:47-53,348-378`).
   - What counts as a use: `use_count` is incremented by `bump_use` when a skill is loaded through a successful `skill_view` (`tools/skills_tool.py:776-780`), a slash command or `--skills` preload (`agent/skill_commands.py:428-429`), or a cron job (`cron/scheduler_prompt.py:248`). Reading a `SKILL.md` with file tools is not a use. Usage recording arrived with the curator feature (`tools/skill_usage.py`, first commit 2026-04-26); a home older than that has no earlier history, and a record exists only once a skill was touched or seeded.
   - The recording window is the earliest and newest timestamp in the file (`created_at`, `first_seen_at`, `last_used_at`, `last_viewed_at`, `last_patched_at`), reported as `recording_since` / `recording_until`, integers `YYYYMM` (for example `202605`).
   - A skill with zero uses is counted in `zero_use_count` only when the file observed it: it has its own record with a timestamp, or its `SKILL.md` modification time lies inside the window. A skill changed before the first record or after the newest record is `zero_use_unverifiable_count`, never "never used".
   - Missing file: `coverage: could_not_verify`, `reason: usage_file_missing`. Unparseable or wrong types: `usage_file_malformed`. No timestamps at all: `usage_file_no_timestamps`. A cut while reading: `truncated`.
   - `days_since_last_use` buckets (`never`, `lt_30_days`, `days_30_to_90`, `gt_90_days`, `unverifiable`) are measured from each skill's latest activity to the newest timestamp in the file, so the output does not depend on when the audit runs.
   - `top_used_counts`: up to 10 `{path, use_count}` from the usage file, highest first. `path` is the absolute folder of the skill with that name on disk, or `null` when no such skill exists (the name itself is never output).

3. **Bulk installs (`bulk_installs`)** across non-stock skills (not in `skills/.bundled_manifest`, `tools/skills_sync.py:38,113-130`), in priority order:
   1. `license_hash` (`weak_signal: false`): at least 20 folders with an identical LICENSE/NOTICE/COPYING SHA-256.
   2. `hub_lock_source` (`weak_signal: false`): at least 20 folders with one `source` in `skills/.hub/lock.json` (`tools/skills_hub.py:63,322-370`).
   3. `mtime_window_2m` (`weak_signal: true`): at least 20 remaining folders whose `SKILL.md` modification times fall within 120 seconds. Directory times are not used: archive extraction rewrites them.
   - Reports `group_count`, up to 10 `groups` (`signal`, `weak_signal`, `skills_count`, `used_skills_count`, `used_share`; the last two `null` without verified usage), `hub_lock_present`, `hub_lock_entries`, `hub_lock_missing_on_disk`.

4. **Dead weight (`dead_weight`)**: LICENSE/LICENCE/NOTICE/COPYING counts, identical copies, distinct texts and bytes; files over 1 MiB whose first 512 bytes are not UTF-8 text, by class (`non_text_over_1mb_by_type`, each `{count, bytes}`): `image`, `video`, `audio`, `archive`, `model_weights`, `executable_file`, `document`, `other`.

5. **Always-on (`always_on`)**: listed skills named in `skills.auto_load` (their body joins the stable prompt prefix every session, `agent/system_prompt.py:318-342,768`, `agent/skill_commands.py:1000-1028`) or whose frontmatter description contains `every session`, `always load`, `load first` or `before anything`. Counts plus `paths`: up to 10 absolute folders of the non-stock ones.

6. **Loaded sizes (`loaded_sizes`)**: `SKILL.md` character median, nearest-rank p90, max and `top_10_largest` (`{path, chars}`) across listed non-stock skills.

**Sizes and links.** Byte figures (`license_bytes`, `non_text_over_1mb_bytes`, `bytes` per class) are file sizes (`st_size`), not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound. Character figures are decoded `SKILL.md` lengths. Symlinks are never followed or measured: each skipped symlink (a linked skill folder, a linked file, a linked usage or snapshot file) is counted in `limits.symlinks_skipped` and is a cut, so the section becomes `could_not_verify`.

## Findings

| Rule id | Classification | Fires when | Evidence |
|---|---|---|---|
| `skill_packs.index_cost` | `review_suggested` | `index_chars > 17,000` or more than 150 listed skills | `skills`, `chars`, `estimated_tokens`, `runtime_gated_count`, `platform_excluded_count` |
| `skill_packs.never_used` | `review_suggested` | usage verified, at least 20 evaluated non-stock skills, at least 70% with zero recorded uses | `skills`, `zero_use_count`, `never_used_share`, `unverifiable_count` |
| `skill_packs.bulk_install` | `info`; `review_suggested` only for a `license_hash` / `hub_lock_source` group of at least 50 with verified usage under 10% | one per group (first 10 groups); an `mtime_window_2m` group is always `info` | `signal`, `weak_signal`, `skills`; `used_skills`, `used_share` only with verified usage |
| `skill_packs.stale_index_snapshot` | `info` | snapshot parsed and `stale_count > 0` | `snapshot_version`, `snapshot_skills`, `stale_entries` (a count) |
| `skill_packs.always_on_skills` | `review_suggested` | at least one non-stock always-on skill | `count`, `auto_loaded_count`, `description_cue_count` |
| `skill_packs.license_copies` | `info` | more than 50 licence files with fewer distinct texts than files | `count`, `distinct_texts`, `bytes` |
| `skill_packs.could_not_verify` | `info` | any cut, usage not verified, or snapshot unreadable | `cuts`, `reason`, `truncated_by` (only when set) |

Every consequence is one fixed sentence (`FINDING_CONSEQUENCES` in the module); numbers are only in the evidence. Finding identities and source paths are the fixed strings `skills`, `skills/.usage.json` and `.skills_prompt_snapshot.json`.

- `skill_packs.index_cost`: The rendered skills index is above 17,000 characters or 150 listed skills and is sent with every request before any skill is opened; the character count is about the real size and an upper bound when listed skills depend on tools, apps or environments, and it does not include any skill body.
- `skill_packs.never_used`: At least 70% of at least 20 non-stock skills with a usable observation window have zero recorded uses in skills/.usage.json; Hermes records a use only when a skill is loaded through skill_view, a slash command or a cron job, so this does not show reads by other means or use before recording began.
- `skill_packs.bulk_install`: At least 20 non-stock skill folders share one install signal (identical license text, the same hub-lock source, or SKILL.md times within 2 minutes, which is a weak signal); this counts folders and does not show how or why they were installed.
- `skill_packs.stale_index_snapshot`: The on-disk .skills_prompt_snapshot.json lists skill entries with no matching SKILL.md under skills/; Hermes rebuilds this cache when its manifest no longer matches, so this counts left-over cache entries and does not describe the current prompt.
- `skill_packs.always_on_skills`: One or more non-stock skills are listed in skills.auto_load or carry an every-session cue in their frontmatter description; auto-loaded skills add their body to every session, while a description cue is wording only and does not show that the skill is loaded.
- `skill_packs.license_copies`: More than 50 LICENSE, NOTICE or COPYING files inside skill folders share fewer distinct texts than files; this counts duplicated license files and does not show how the folders were installed.
- `skill_packs.could_not_verify`: Skill pack usage or directory coverage could not be completely verified; missing usage records or bounded traversal cuts are not evidence of clean state or zero usage.

## Thresholds

| Constant | Value | Note |
|---|---:|---|
| `INDEX_CHARS_THRESHOLD` | `17,000` | A stock install renders well below it. |
| `INDEX_SKILLS_THRESHOLD` | `150` | A stock install lists far fewer skills. |
| `NEVER_USED_MIN_SKILLS` / `NEVER_USED_SHARE_THRESHOLD` | `20` / `0.70` | Evaluated non-stock skills only, so stock skills and a handful of installs never trigger it. |
| `BULK_GROUP_MIN_SKILLS` | `20` | Minimum group size for every bulk-install signal. |
| `BULK_REVIEW_MIN_SKILLS` / `BULK_REVIEW_MAX_USED_SHARE` | `50` / `0.10` | Strong-signal groups only. |
| `MTIME_WINDOW_SECONDS` | `120` | Weak signal; informational only. |
| `LICENSE_COPIES_THRESHOLD` | `50` | Licence files above this count are reported. |
| `LARGE_PAYLOAD_BYTES` | `1,048,576` | Non-text files at least this large are counted by class. |

## What it cannot tell

- Session-dependent visibility: available tools/toolsets (`requires_*`, `fallback_for_*`), gateway session platform, registered apps (`requires_apps`), `platform_disabled`, `compact_categories`, the one-shot variant and the shorter header used when web tools are absent. Plugin-registered skills, trusted project skills (`TIER_PROJECT`) and `skills.create_dir` (`TIER_CREATE_DIR`) are not scanned. A `SKILL.md` placed directly in `skills/` is not counted.
- Hermes follows symlinked skill folders; this audit never does (see "Sizes and links").
- Whether a zero-use skill was used before the usage file existed, or read with file tools. `SKILL.md` modification times can be preserved by copies, so the observation window is an approximation.
- Why skills share an install signal. `SKILL.md` times within 2 minutes can come from a restore, checkout or copy.
- Out-of-profile `external_dirs`, and entries with `~`, `$` or `..`, are not traversed (`limits.external_dirs_skipped`, a cut).
- The audited home's platform: the index is rendered for `host_platform`.

## Do-not-flag list

- A plain stock install (upstream bundled tree, 39-58 listed, about 4-5K rendered characters): tested against a copy of the upstream tree; no finding above `info`.
- A handful of hub or local installs (under 20 non-stock skills).
- Disabled and platform/environment-hidden skills: not in `index_chars`.
- Stock skills with large support folders or large `.md` references.
- Stock skills in `skills.auto_load`: counted in `always_on.auto_loaded_count`, no finding.
- `SKILL.md`-time clusters alone: `info` at most.

## Output keys

`status` (`completed`, `not_measured`), `coverage` (`verified`, `could_not_verify`), `reason` (`null`, `missing`, `truncated`, `usage_file_missing`, `usage_file_malformed`, `usage_file_no_timestamps`, `unverified_inputs`), `truncated_by` (`null`, `time_budget`, `max_entries`, `max_depth`, `max_skills`, `max_files_per_skill`, `max_file_bytes`, `max_license_files`, `max_total_bytes`, `max_usage_rows`), `index` {`loadable_skills`, `discovered_skills`, `stock_skills`, `non_stock_skills`, `disabled_skills_count`, `shadowed_skills_count`, `platform_excluded_count`, `runtime_gated_count`, `index_chars`, `name_chars`, `description_chars`, `estimated_tokens`, `snapshot` {`present`, `coverage` (`not_applicable`, `verified`, `could_not_verify`), `version`, `skills_count`, `description_chars`, `stale_count`}}, `usage` {`present`, `coverage`, `reason`, `recording_since`, `recording_until`, `skills_evaluated`, `zero_use_count`, `never_used_share`, `zero_use_unverifiable_count`, `non_stock_skills_evaluated`, `non_stock_zero_use_count`, `non_stock_never_used_share`, `top_used_counts` [{`path`, `use_count`}], `days_since_last_use` {`never`, `gt_90_days`, `days_30_to_90`, `lt_30_days`, `unverifiable`}}, `bulk_installs` {`group_count`, `groups` [{`signal` (`license_hash`, `hub_lock_source`, `mtime_window_2m`), `weak_signal`, `skills_count`, `used_skills_count`, `used_share`}], `hub_lock_present`, `hub_lock_entries`, `hub_lock_missing_on_disk`}, `dead_weight` {`license_files_count`, `identical_license_copies`, `distinct_license_texts`, `license_bytes`, `non_text_over_1mb_count`, `non_text_over_1mb_bytes`, `non_text_over_1mb_by_type` {class: {`count`, `bytes`}}}, `always_on` {`count`, `auto_loaded_count`, `description_cue_count`, `non_stock_count`, `paths`}, `loaded_sizes` {`median_chars`, `p90_chars`, `max_chars`, `top_10_largest` [{`path`, `chars`}]}, `limits` {`max_entries`, `max_depth`, `max_skills`, `max_files_per_skill`, `max_file_bytes`, `max_license_file_bytes`, `max_license_files`, `max_total_bytes`, `max_usage_rows`, `max_seconds`, `entries_walked`, `files_hashed`, `bytes_read`, `symlinks_skipped`, `credentials_skipped`, `external_dirs_skipped`, `cuts`}, `thresholds` {`index_chars`, `index_skills`, `never_used_min_skills`, `never_used_share`, `bulk_group_min_skills`, `bulk_review_min_skills`, `bulk_review_max_used_share`, `mtime_window_seconds`, `license_copies`, `large_payload_bytes`, `description_clip_chars`}.

Every list holds at most 10 entries. The only strings that are not fixed labels are `path` / `paths`: absolute paths of existing skill folders inside the profile. The report serializer keeps them because they are declared path fields, and only when the path resolves (stored as the resolved path); a path or label that overlaps a credential value read in the same run is sealed as a `credential_overlap` token. Raw measurements are the same for an unchanged home within budgets. The sealed output is unchanged only while every kept path still resolves and no value overlaps a credential value read in the same run; otherwise it holds tokens keyed per run, which differ between runs. No skill name, description, hub source or identifier, licence text, config value or file content is output; names without a folder on disk are counted only.

## Read policy

- **Stat'ed** (`os.lstat`, and `os.scandir` with entries inspected by `entry.stat(follow_symlinks=False)`): the profile root, `skills/`, in-profile `external_dirs`, skill folders and files inside them, within `MAX_TREE_ENTRIES = 10,000`, `MAX_DEPTH = 16`, `MAX_SKILLS = 1,000`, `MAX_FILES_PER_SKILL = 256`.
- **Read** (bounded, regular, non-symlink, non-credential files only): `config.yaml` (only when a config-derived argument is `None`; only `skills.disabled`, `skills.auto_load`, `skills.external_dirs` are used), `skills/.bundled_manifest`, `skills/.hub/lock.json`, `skills/.usage.json`, `.skills_prompt_snapshot.json`, each `SKILL.md` (`MAX_FILE_BYTES = 1 MiB`); LICENSE/NOTICE/COPYING files (64 KiB each, at most 5,000) hashed in memory; the first 512 bytes of files over 1 MiB. Totals capped at `MAX_TOTAL_BYTES = 32 MiB` and `MAX_SECONDS = 10` (injectable clock).
- **Never opened**: anything matching `audit.policy.credential_path` (`.env*`, `auth.json`, `*token*`, `*secret*`, `*credential*`, keys, `mcp-tokens/`, `pairing/`, `vault/`, ...), symlinks and anything below a symlink, paths outside the profile, `memories/`, `sessions/`, databases, and support files other than licences and the 512-byte probes.
- Nothing is written, created or modified.
