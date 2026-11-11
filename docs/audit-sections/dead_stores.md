# Dead stores and regenerable caches (`report.dead_stores`)

## What it measures

`audit.dead_stores.audit_dead_stores` performs a single, bounded, non-symlink-following
`os.scandir` / `os.lstat` walk over a Hermes profile home and quantifies ten classes of
accumulated dead weight and regenerable cache material.

**Overlap with other sections.** The section carries `overlaps_other_sections: true`. Bytes
counted here (for example per-profile caches under `profiles/<name>/`, plugin trees, files
inside user work folders) are also counted by other audit sections. These totals must not be
added to other sections' totals; the `dead_stores.summary` consequence says the same.

1. **Exports and archives (`exports_and_archives`)**:
   - Count and bytes of `<home>/profile-exports/` created by `hermes profile export`
     (`hermes_cli/profiles.py:2022-2027,2050-2069,2158-2165`,
     `hermes_cli/subcommands/profile.py:119`).
   - Top-level or `backups/` archives (`*.tar.gz`, `*.tgz`, `*.tar.xz`, `*.zip`) larger
     than `LARGE_ARCHIVE_BYTES` (10 MiB; `hermes_cli/backup.py:60-145`).
   - Archive write bursts (`>= 3` archives written within a 60-second `mtime` window).

2. **Plugins on disk vs. enabled (`plugins`)**:
   - Parked or backup-suffixed plugin directories (`*.parked-*`, `*.parked`, `*.bak`,
     `*.bak-*`, `*.bak.*`, `*.old`, `*.old-*`, `*-backup*`, `*.backup*`, `.previous-*`)
     under `<home>/plugins/` and `<home>/desktop-plugins/` (`pm/publication.py:185`,
     `hermes_cli/desktop_plugin_halves.py:1-15`).
   - Disabled plugin directories still present under `<home>/plugins/` when not listed in
     `plugins.enabled` (or when overridden by `plugins.disabled`;
     `hermes_cli/plugins_discovery.py:112-132,269-334`, `pm/plugins_state.py:83-110`).
     For each disabled plugin on disk, its `plugin.yaml` / `plugin.yml` is read with a
     256 KiB cap to count declared hook names under `provides_hooks` / `hooks`
     (`hermes_cli/plugins_manifest.py:575-577`).
   - Non-bundled `plugins.enabled` entries (minus `plugins.disabled`, which wins) whose on-disk
     folder is missing (`no_folder`), empty (`empty_folder`), or missing a plugin manifest
     (`no_manifest`: no `plugin.yaml`, `plugin.yml`, `plugin.json`, or `dashboard/manifest.json`).
     `BUNDLED_PLUGIN_NAMES` is the exact set of directory keys and manifest names under the Hermes
     source `plugins/` tree (a test recomputes it from the source and asserts equality); bundled
     names are never missing.
   - An enabled name whose `plugins/<name>` (or `plugins/<category>/<name>`) entry is a SYMLINK is
     counted in `enabled_symlinked_count`, not followed, and never counted in `enabled_missing`.
   - An enabled name that left core for the plugin catalog (`LEFT_CORE_PLUGIN_NAMES`, from
     `hermes_cli/left_core_migration.py:454-520`, e.g. `langfuse`, formerly bundled
     `observability/langfuse`) with no folder is listed in `enabled_moved_out_of_core` (values come
     only from that fixed list), never in `enabled_missing`.
   - `dead_stores.enabled_plugin_missing` is `review_suggested`, not `warning`: pip entry-point
     plugins (`hermes_cli/plugins_discovery.py:72-95`) and project plugins
     (`hermes_cli/plugins_discovery.py:212-216`) have no folder in the home, so a file walk cannot
     be certain a plugin is unavailable.
   - Development and build residue inside plugin trees: `.git/`, `__pycache__/`, `tests/`,
     and `node_modules/`.

3. **Orphan plugin data (`orphan_plugin_data`)**:
   - Subdirectories `<home>/plugin-data/<name>` (`plugins/plugin_storage.py:1,27-33`) that
     match no installed plugin directory under `plugins/` or `desktop-plugins/`, no symlinked
     plugin folder, no name in `plugins.enabled`, and no active bundled plugin.

4. **Regenerable caches (`regenerable_caches`)**:
   - Skills Hub index cache at `skills/.hub/index-cache/` (and `profiles/*/skills/.hub/index-cache/`;
     `tools/skills_hub.py:61-67`, `tools/skills_hub_search.py:31-33`).
   - Model catalog caches: `models_dev_cache.json` and `models_dev_cache.etag`
     (`agent/models_dev.py:4,241-245`), `provider_models_cache.json` and
     `*_models_cache.json` (`hermes_cli/models.py:1772,1857-1859`).
   - Media, document, screenshot, and discovery caches: `image_cache/`, `cache/images/`,
     `audio_cache/`, `cache/audio/`, `document_cache/`, `cache/documents/`, `cache/`,
     `video_cache/`, `browser_screenshots/`, and `bootstrap-cache/`
     (`gateway/platforms/base.py:485,560-561,681-683,728-731,757`,
     `tools/credential_files.py:249-251`, `tools/image_source.py:189`,
     `tools/registry.py:183`).
   - Tool caches (`tools/*/cache/`) and download archives (`tools/*/dl/*.tar.xz`, `*.tar.gz`,
     `*.tgz`, `*.zip`). `<home>/tools` is the PM store root (`hermes_cli/home_data_layout.py:6`,
     `pm/paths.py:71`), but the `<name>/cache` and `<name>/dl` layout is not in the Hermes
     source, so these bytes are kept and labelled `tool_cache_label: "cache_in_work_folder"`.
   - Top-level bootstrap installer binaries (`hermes-setup*`;
     `apps/bootstrap-installer/src-tauri/src/paths.rs:110-116`,
     `apps/bootstrap-installer/src-tauri/src/bootstrap.rs:901`), verified by an 8-byte
     executable magic header check (ELF, Mach-O, or PE).

5. **Piles that only grow (`growing_piles`)**:
   - API error request dumps: `request_dump_*.json` directly in `sessions/` or
     `profiles/<name>/sessions/` only (`agent/agent_init.py:1102-1104`,
     `agent/agent_runtime_helpers.py:1553`); copies elsewhere are not counted.
   - Unrotated logs: `.log` files larger than 500 KiB in Hermes's own log locations only:
     `logs/**` of the home and of each `profiles/<name>/` (`hermes_logging.py:369,710`),
     `disk-cleanup/cleanup.log` (`plugins/disk-cleanup/disk_cleanup.py:27-29,59-66`),
     `skills/.hub/audit.log` (`tools/skills_hub.py:65`), and files under `plugins/`,
     `desktop-plugins/`, `plugin-data/`. Skipped and tallied in
     `rotation_managed_skipped_count`: `agent.log`, `errors.log`, `gateway.log`, `gui.log`
     (`hermes_logging.py:396-401`), `tool_calls.log` (`gateway/run_turn.py:70-71`), and
     `desktop.log` (`apps/desktop/electron/main.ts:1355,2037`, `log-rotation.ts:15-16,52`) directly
     in a `logs/` folder: Hermes rotates these, and below the size cap no `.1` exists yet. Also
     skipped: files with a `.1`, `.0` or `.1.gz` sibling. Append-only logs with no rotation in the
     source include `logs/mcp-stderr.log` (`tools/mcp_tool_config.py:39`) and `logs/update.log`
     (`hermes_cli/main_dashboard.py:546`). `.log` files over 500 KiB anywhere else (user work
     folders such as `plans/`, `tmp/`) are work output, not counted, and only tallied in
     `outside_hermes_log_locations_count` / `_bytes`.
   - `attachments/` and `composer-pastes/` file counts, byte totals, and oldest UTC
     `YYYY-MM` timestamp (`tui_gateway/prompt_attachments.py:110-124`,
     `apps/desktop/electron/composer-paste.ts:5,18-24`).
   - Backup-style files (`*.bak`, `*.bak-*`, `*.bak.*`, `*.pre-*`, `*.before`, `*.orig`,
     `*~`, `.env.*backup*`, and `backups/config/*` copies from
     `hermes_cli/config_backups.py:21-27,44-71`), including config-backup bursts and a
     separate count/size of credential-named backup files classified strictly by filename.
   - Empty profile directories under `profiles/` and deleted profile tombstones under
     `profiles/.deleted/` (`hermes_constants.py:318,327`, `hermes_cli/profiles.py:2320`).

6. **Stale locks (`stale_locks`)**:
   - Zero-byte `*.lock` files whose mtime is more than 24 hours before the NEWEST regular-file
     mtime in the home (`reference: "newest_mtime_in_home"`), so a backup is judged as of when it
     was taken and the result does not depend on the wall clock (`hermes_state_repair.py:181,210`,
     `hermes_state_dbfile.py:659`, `pm/publication.py:173`). The optional `now` parameter changes
     nothing in the section; it only feeds the envelope's top-level `run_metrics.stale_locks_vs_now_count`
     (zero-byte locks more than 24 hours older than `now`; `null` when `now` is not supplied), which
     is stored outside the fingerprinted report.

7. **Unreferenced skill clones (`unreferenced_skill_clones`)**:
   - Top-level `vendor-skills/` (and `vendor_skills/`, `external-skills/`,
     `third-party-skills/`) repositories not covered by `external_skill_dirs`
     (`agent/skill_utils.py:402-424`, `cli-config.yaml.example:1219`). These folder names are an
     naming convention, NOT in the Hermes source; when absent nothing is reported. Parked plugin
     folder names (`*.parked-*` etc.) are also a naming convention: the section carries
     `plugins.parked_name_label` and `growing_piles.backup_files.name_pattern_label` =
     `"name_pattern_not_in_hermes_source"` (also in the two findings' evidence), because only
     `.previous-<uuid>` plugin folders and `backups/config/` copies come from the Hermes source.

8. **Feature-off leftovers (`feature_off_assets`)**:
   - Sprite assets under `<home>/pets/` when `pet_enabled` (`display.pet.enabled`) is
     `False` (`hermes_cli/config_defaults.py:970-982`, `hermes_cli/pets.py:16-112`).

9. **Summary totals (`dead_weight_by_class`, `total_dead_weight_bytes`, `dead_weight_share_of_home`)**:
   - Deduplicated byte totals per dead-weight class and overall share of `total_home_bytes`.

## How it works and parameter contract

`audit_dead_stores(profile_path, *, enabled_plugins, disabled_plugins, external_skill_dirs,
pet_enabled, now=None, clock=time.monotonic, managed_dir=None)`. The caller passes only
`profile_path`; every configuration input left at its default is read by the module from
`<profile>/config.yaml` (1 MiB cap, descriptor-relative `O_NOFOLLOW`, never a credential file):

| Input | Config key | Missing file / missing key |
| --- | --- | --- |
| `enabled_plugins` | `plugins.enabled` | `[]` (omitted from Hermes defaults) |
| `disabled_plugins` | `plugins.disabled` | `[]` |
| `external_skill_dirs` | `skills.external_dirs` | `[]` (`hermes_cli/config_defaults.py`) |
| `pet_enabled` | `display.pet.enabled` | `False` (`hermes_cli/config_defaults.py`) |

An unreadable, oversized, unparsable or duplicate-key file adds `config_unreadable` and makes all
four unverified; an active managed scope (`write_settings._has_managed_overlay`) adds
`managed_config_overlay`; a value of the wrong type, or `${VAR}` in `skills.external_dirs`, makes its
check unverified. An explicit argument, including `None` ("not supplied"), wins over the file.
`now` feeds only `run_metrics`; `clock` drives the 20 s time budget.

The function returns exactly `{"dead_stores": <section>, "findings": [...], "run_metrics":
{"stale_locks_vs_now_count": int|null}, "status": "pass"|"fail", "coverage": ...}`.
`adapt_component_result` keeps `dead_stores` and `run_metrics` unchanged. Two runs on an unchanged home
with different `now` and `clock` values give the same raw section and findings (tested).
Raw measurements are the same for an unchanged home within budgets. The sealed
output is unchanged only while every kept path still resolves and no value
overlaps a credential value read in the same run; otherwise it holds tokens keyed
per run, which differ between runs.

When an input is unverified its sub-check reports `coverage: "could_not_verify"`, adds the check
name to `unverified_checks`, and `dead_stores.could_not_verify` is emitted. Unverified sub-checks
never emit false-positive findings and never claim clean coverage.

**Sizes and links.** Sizes are file sizes (`st_size`), not unique disk blocks; on filesystems with
shared blocks or hard links the totals are an upper bound. Symlinks (files and folders) are never
followed and never measured: they are counted in `limits.symlinks_skipped`, and an enabled plugin
whose folder is a symlink is counted in `plugins.enabled_symlinked_count`.

## Output reference (matches `audit/wiring/dead_stores.json`)

**Paths, not names.** The report serializer keeps a string only if it is a fixed vocabulary token,
or a path in a declared path field (such as `path`) that resolves to an existing item; it stores
the resolved path. A token or path that overlaps a credential value read in the same run is sealed
as a `credential_overlap` token, even when it equals an ordinary word. The section therefore emits names from disk only as
absolute paths built from the resolved home, at plugin-folder depth (`<profile>/plugins/<name>`,
`<profile>/plugins/<category>/<name>`, `<profile>/desktop-plugins/<name>`) or two components
(`<profile>/plugin-data/<name>`, `<profile>/vendor-skills/<repo>`), under `path` keys:
`plugins.parked_copies[].path`, `plugins.disabled_on_disk[].path`, `plugins.enabled_missing[].path`, `plugins.dev_residue.by_plugin[].path`, `orphan_plugin_data.orphans[].path`, `unreferenced_skill_clones.clones[].path`. A credential-named component gives `path: null`.
Names that exist only in configuration (plugins.enabled entries with no folder, symlinked plugin
folders, manifest names, hook names) are never emitted: only counts and the vocabulary reason
(`enabled_missing[].reason` with `path: null` for `no_folder`). Unrotated logs are reported as
`{log_location, in_named_profile, bytes}`; the oldest attachment / composer paste is
`oldest_year` / `oldest_month` integers (UTC).

Keys (section and finding evidence): `active_plugin_residue_bytes`, `age_threshold_seconds`, `attachments`, `audio_cache_bytes`, `backup_files`, `backup_pile_count`, `burst_count`, `burst_span_seconds`, `burst_window_seconds`, `by_plugin`, `bytes`, `clones`, `composer_pastes`, `config_backup_burst_count`, `config_backup_bytes`, `config_backup_count`, `count`, `coverage`, `cred_named_bytes`, `cred_named_count`, `cuts`, `dead_stores`, `dead_weight_by_class`, `dead_weight_share_of_home`, `deleted_profile_tombstones_count`, `dev_residue`, `disabled_bytes`, `disabled_count`, `disabled_hooks_declared`, `disabled_on_disk`, `disabled_plugin_bytes`, `document_cache_bytes`, `empty_folder_count`, `empty_profile_dirs_count`, `enabled_missing`, `enabled_missing_count`, `enabled_moved_out_of_core`, `enabled_moved_out_of_core_count`, `enabled_symlinked_count`, `entries_walked`, `exports_and_archives`, `feature_off_assets`, `file_count`, `files`, `git_bytes`, `growing_piles`, `hooks_declared`, `hub_index_cache_bytes`, `hub_index_cache_count`, `image_cache_bytes`, `in_named_profile`, `installer_binaries_bytes`, `installer_binaries_count`, `large_archive_bytes`, `large_archives_bytes`, `large_archives_count`, `limits`, `log_location`, `manifest_coverage`, `max_depth`, `max_entries`, `max_metadata_file_bytes`, `max_metadata_reads`, `max_seconds`, `metadata_bytes_read`, `metadata_reads`, `missing_count`, `models_dev_cache_bytes`, `moved_out_of_core_count`, `name_pattern_label`, `no_folder_count`, `no_manifest_count`, `node_modules_bytes`, `oldest_month`, `oldest_year`, `orphan_count`, `orphan_plugin_data`, `orphans`, `other_media_cache_bytes`, `outside_hermes_log_locations_bytes`, `outside_hermes_log_locations_count`, `overlaps_other_sections`, `parked_and_disabled_plugins`, `parked_bytes`, `parked_copies`, `parked_count`, `parked_name_label`, `path`, `pet_enabled`, `pets_bytes`, `pets_file_count`, `plugin_dev_residue`, `plugins`, `profile_exports_bytes`, `profile_exports_count`, `provider_models_cache_bytes`, `pycache_bytes`, `reason`, `reference`, `regenerable_caches`, `regenerable_caches_bytes`, `request_dumps`, `request_dumps_count`, `rotation_managed_skipped_count`, `source_dir`, `stale_lock_age_seconds`, `stale_locks`, `stale_locks_count`, `status`, `symlinked_count`, `symlinks_skipped`, `tests_bytes`, `threshold_bytes`, `threshold_count`, `thresholds`, `tool_cache_bytes`, `tool_cache_label`, `total_bytes`, `total_dead_weight_bytes`, `total_home_bytes`, `total_home_files`, `truncated_by`, `unreferenced_skill_clones`, `unrotated_log_bytes`, `unrotated_logs`, `unverified_checks`, `unverified_count`, `young_or_nonempty_ignored_count`.

Fixed string values: `.`, `agent-importers`, `backups`, `cache`, `cache_in_work_folder`, `camofox`, `completed`, `config_unreadable`, `could_not_verify`, `depth_budget`, `desktop-plugins`, `disk_cleanup_log`, `empty_folder`, `empty_home`, `enabled_plugins`, `entry_budget`, `external_skill_dirs`, `github-copilot`, `homeassistant`, `info`, `installer_magic_read`, `langfuse`, `locks`, `logs`, `logs_folder`, `managed_config_overlay`, `mcp-serve`, `metadata_byte_budget`, `metadata_read_budget`, `missing`, `name_pattern_not_in_hermes_source`, `newest_mtime_in_home`, `no_folder`, `no_manifest`, `not_directory`, `not_measured`, `observability/langfuse`, `pet_enabled`, `pets`, `plugin-data`, `plugin_folder`, `plugin_manifest`, `plugins`, `profile-exports`, `review_suggested`, `root_missing`, `root_not_directory`, `root_symlink`, `root_unreadable`, `sessions`, `singularity`, `skills_hub_audit_log`, `spotify`, `stale_locks`, `stat_error`, `surrogate_name`, `symlink_root`, `time_budget`, `unreadable`, `unreadable_subdir`, `vendor-skills`, `verified`, `walk_truncated`, `warn`.

- `status`: `completed`, `not_measured`; `reason`: `missing`, `unreadable`, `symlink_root`,
  `not_directory`, `empty_home` (or `null`).
- `truncated_by`: `time_budget`, `entry_budget`, `depth_budget`, `metadata_byte_budget`,
  `metadata_read_budget` (or `null`).
- `unverified_checks`: `enabled_plugins`, `external_skill_dirs`, `pet_enabled`, `config_unreadable`,
  `managed_config_overlay`, `root_missing`, `root_unreadable`, `root_symlink`, `root_not_directory`,
  `walk_truncated`, `unreadable_subdir`, `surrogate_name`, `stat_error`, `installer_magic_read`,
  `plugin_manifest`, `stale_locks`.
- `enabled_missing[].reason`: `no_folder`, `empty_folder`, `no_manifest`; `source_dir`: `plugins`,
  `desktop-plugins`; `manifest_coverage`: `verified`, `could_not_verify`.
- `growing_piles.unrotated_logs.files[].log_location`: `logs_folder`, `disk_cleanup_log`,
  `skills_hub_audit_log`, `plugin_folder`.
- Labels: `regenerable_caches.tool_cache_label` = `cache_in_work_folder`; `stale_locks.reference` =
  `newest_mtime_in_home`; `parked_name_label` / `name_pattern_label` = `name_pattern_not_in_hermes_source`.
- Finding `affected_identities` / `source_paths`: `.`, `profile-exports`, `plugins`, `plugin-data`,
  `cache`, `sessions`, `logs`, `backups`, `locks`, `vendor-skills`, `pets`.

## Thresholds

| Constant | Value | Purpose |
| --- | --- | --- |
| `PROFILE_EXPORTS_THRESHOLD_BYTES` | `50 MiB` (`52,428,800 B`) | Export tarballs kept in `profile-exports/` above this total are reported. |
| `LARGE_ARCHIVE_BYTES` | `10 MiB` (`10,485,760 B`) | Distinguishes full/profile archive dumps at top level or `backups/` from small config/skill files. |
| `EXPORT_BURST_COUNT` / `EXPORT_BURST_WINDOW_SECONDS` | `3` files within `60.0 s` | Several archives or config backups written within one minute look like one repeated action. |
| `DISABLED_PLUGIN_THRESHOLD_BYTES` | `5 MiB` (`5,242,880 B`) | Disabled plugin folders above this size are reported; smaller ones are ignored. |
| `REGENERABLE_CACHES_THRESHOLD_BYTES` | `20 MiB` (`20,971,520 B`) | Caches Hermes can rebuild are reported above this total. |
| `REQUEST_DUMPS_THRESHOLD_COUNT` | `> 10` files | A few request dumps are normal debugging output; more than ten are reported. |
| `UNROTATED_LOG_THRESHOLD_BYTES` | `500 KiB` (`512,000 B`) | Only logs in Hermes log locations without rotation count; work output and rotation-managed logs are excluded. |
| `BACKUP_PILE_THRESHOLD_COUNT` | `> 20` files | More than twenty backup-style files are reported. |
| `STALE_LOCK_AGE_SECONDS` / `STALE_LOCKS_THRESHOLD_COUNT` | `> 86,400 s` (24 h before the newest mtime in the home), `> 10` files | Age is measured against the newest mtime in the home, so the result does not depend on when the audit runs. |
| `MAX_ENTRIES` / `MAX_SECONDS` | `400,000` entries / `20.0 s` | Bound the walk; a cut marks the section `could_not_verify`. |
| `MAX_METADATA_FILE_BYTES` / `MAX_METADATA_READS` | `256 KiB` / `500` reads | Bounds disabled-plugin `plugin.yaml` reads and 8-byte installer magic checks. |

## What it cannot tell

- Static file and directory sizes do not prove whether a user or external script still
  relies on a profile export, backup file, disabled plugin, or `vendor-skills/` checkout.
- Counting declared hooks in a disabled plugin's `plugin.yaml` measures what the plugin
  would register if enabled, not active runtime hook execution.
- Observing a zero-byte `.lock` file older than 24 hours does not prove whether a process
  currently holds an OS-level `flock`/`fcntl` lock on that inode.
- Counting orphan directories under `plugin-data/` does not prove whether the user plans to
  reinstall the corresponding plugin and reuse its state.

## Do-not-flag list

- `cron/output/<job>/*.md`: Hermes prunes per-job run output to `_CRON_OUTPUT_DEFAULT_KEEP = 50`
  files on every `save_job_output` call (`cron/jobs.py:3318-3364`).
- Rotated log siblings (`*.log.1`, `*.log.2`, etc.) and active `*.log` files that have a
  `.1` / `.0` / `.1.gz` sibling in the same directory (`hermes_logging.py:387-401`).
- Zero-byte `.lock` files younger than 24 hours and non-empty `.lock` files (such as
  `uv.lock` or PID-bearing lockfiles).
- One `bin/` directory containing tool binaries.
- A single config backup copy (threshold requires `> 20` backup-style files).
- `models_dev_cache.json` alone under 20 MiB (never triggers `dead_stores.regenerable_caches`
  and never produces anything above `info`).
- Enabled plugin names that have no folder in `<home>/plugins/` because they are bundled in
  the Hermes source tree (`BUNDLED_PLUGIN_NAMES`, equal to the source `plugins/` keys and names),
  symlinked plugin folders (`enabled_symlinked_count`), and plugins that left core
  (`enabled_moved_out_of_core`).
- `.log` files in user work folders (`plans/`, `tmp/`, ...) and rotation-managed Hermes logs
  below their size cap.
- `request_dump_*.json` copies outside `sessions/` folders.
- `pets/` when `pet_enabled` is `True`, and `vendor-skills/<repo>` when covered by
  `external_skill_dirs`.

## Read policy

- **Stat'ed (`os.scandir` / `os.lstat` with `follow_symlinks=False`)**: directory entries
  and regular file metadata (`st_mode`, `st_size`, `st_mtime`, `st_dev`, `st_ino`) below
  `profile_path`. Symlinks are counted in `limits.symlinks_skipped` and never followed.
- **Read (bounded, descriptor-relative `O_NOFOLLOW`)**:
  - `<home>/plugins/<disabled>/plugin.yaml` (or `plugin.yml`): at most 256 KiB per file,
    at most 500 metadata reads total, parsed via `_parse_simple_yaml_mapping` to extract
    `name` and count `provides_hooks` / `hooks`. No raw strings from `plugin.yaml` are
    emitted into the report.
  - Top-level `<home>/hermes-setup*`: at most 8 header bytes read to verify ELF, Mach-O, or
    PE executable magic.
- **Never opened**: any path matching `audit.policy.credential_path` or credential filename
  patterns (`.env*`, `auth.json*`, `*token*`, `*secret*`, `*credential*`, `*password*`,
  `*passwd*`, `*api_key*`, `*private_key*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, or
  anything under `mcp-tokens/`, `pairing/`, `vault/`, `backups/`). Credential-looking
  backup files are counted strictly by filename (`lstat` only); a test wraps `builtins.open`,
  `io.open` and `os.open` and proves none is opened, and the output carries only their count and
  byte total, never a name.

## Rules and consequences

| Rule id | Classification | Fires when | Consequence (exact, fixed) |
| --- | --- | --- | --- |
| `dead_stores.profile_exports` | `review_suggested` | exports + large archives > 50 MiB | Profile export and backup archive files total more than 50 MiB; byte counts and write-time bursts measure archive files on disk and do not show whether another copy exists or whether the files are still needed. |
| `dead_stores.parked_or_disabled_plugins` | `review_suggested` | any parked copy, disabled bytes > 5 MiB, or disabled hooks > 0 | Plugin folders with parked-style names, or not enabled in plugins.enabled, are on disk; parked-style folder names other than .previous- are not defined by the Hermes source, and byte and declared-hook counts measure files and manifest entries and do not show whether these plugins were ever loaded. |
| `dead_stores.enabled_plugin_missing` | `review_suggested` | any `enabled_missing` entry | Names in plugins.enabled matched no bundled plugin and no plugin folder with a manifest in this home; this compares configuration with disk and does not prove the plugin is unavailable, because entry-point plugins and plugins outside the home are not visible to this check. |
| `dead_stores.orphan_plugin_data` | `info` | any orphan | Folders under plugin-data match no plugin folder, enabled name, or bundled plugin in this home; byte counts measure stored plugin state and do not show whether it will be used again. |
| `dead_stores.regenerable_caches` | `info` | cache total > 20 MiB | Index, model-catalog, media, tool and installer cache files total more than 20 MiB; sizes measure files on disk and do not show whether they will be needed again or what a rebuild would cost. |
| `dead_stores.request_dumps` | `review_suggested` | > 10 dumps in sessions folders | More than 10 request_dump files from failed API requests are in sessions folders; counts and sizes measure files on disk and do not show the cause of those failures or any current fault. |
| `dead_stores.unrotated_logs` | `info` | any unrotated log in a Hermes log location | Log files over 500 KiB in Hermes log locations, excluding logs Hermes rotates and files with a rotated sibling, were found; sizes measure those files on disk and do not show errors or a current fault. |
| `dead_stores.backup_file_pile` | `info` | > 20 backup-style files | More than 20 backup-style files were found across the home; backup-style name patterns outside backups/config are not defined by the Hermes source, counts and sizes come from file names and sizes only, credential-named files are counted and never opened, and this does not show whether any copy is still needed. |
| `dead_stores.stale_locks` | `info` | > 10 stale zero-byte locks | More than 10 zero-byte .lock files have a modification time over 24 hours before the newest file in the home; this measures file timestamps and does not show whether any process holds or waits on a lock. |
| `dead_stores.unreferenced_skill_clones` | `review_suggested` | `external_skill_dirs` known and an unreferenced clone exists | Folders under a top-level vendor-skills style directory are not listed in skills.external_dirs; byte counts measure files on disk and do not show whether anything outside Hermes uses them. |
| `dead_stores.feature_off_assets` | `info` | `pet_enabled` is `False` and `pets/` has bytes | Pet sprite files are on disk under pets while display.pet.enabled is false; byte counts measure those files and do not show a configuration error. |
| `dead_stores.summary` | `info` | total dead weight > 0 | Dead-store classes were measured across the home; class totals and home share are file sizes on disk that overlap bytes counted by other sections, must not be added to other sections' totals, and do not by themselves make any file safe to delete. |
| `dead_stores.could_not_verify` | `info` | any unverified check or cut (`coverage: could_not_verify`) | One or more dead-store sub-checks could not be verified because a configuration value was not supplied, the home could not be read, or a traversal budget was reached; unverified checks are not reported as clean. |

Finding evidence holds numbers and booleans only, plus `name_pattern_label` on
`parked_or_disabled_plugins` and `backup_file_pile`. Consequence sentences are fixed (no interpolated
values); the numbers are in the evidence. Single source: `FINDING_CONSEQUENCES` in
`audit/dead_stores.py`, mirrored in `audit/wiring/dead_stores.json` and this table (tests compare all three).
