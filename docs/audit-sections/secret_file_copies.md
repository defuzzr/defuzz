# Secret File Copies and Misplaced Secret-Named Files (`report.secret_file_copies`)

Matches secret-store names using directory listings and `lstat` metadata, rather than file contents.
A name match does not establish whether a file contains a live credential. Third-party stores written by plugins can be counted as misplaced files.
Name heuristics can miss plain-stem keys and flag non-secret reports. Permission findings depend on whether the home's mode bits are informative.
Thresholds and exclusions are defined in `audit/secret_file_copies.py`, including `CONFIG_BACKUP_REVIEW_THRESHOLD`.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/secret_file_copies.py`.

## Findings

- `secret_file_copies.backup_copies_of_secret_files`: `warning`.
  > Files named as copies of a Hermes secret store (such as .env.bak-*, auth.json.old, or a store's name inside a backups folder) were counted next to the live stores or in backup folders. The audit matched file names and lstat metadata only and did not open any file, so it cannot tell whether a copy holds a working secret, an expired one, or none.
- `secret_file_copies.config_backup_copies`: `info` / `review_suggested`.
  > Copies of config.yaml were counted at the home or profile root and in backup folders; a config.yaml can contain keys typed into it. The audit matched file names and lstat metadata only and did not open any file, so it cannot tell whether any copy holds a key.
- `secret_file_copies.could_not_verify`: `info`.
  > Part of the home could not be listed (a safety cap, an unreadable folder, an undecodable name, or a missing or invalid home path), so the counts are partial. The audit matched file names only and did not open any file; what was not listed is neither clean nor a problem.
- `secret_file_copies.plugin_holds_secret_file`: `review_suggested`.
  > A .env-style file was counted inside one or more plugin folders, outside the profile's secret stores. The audit matched file names only and did not open any file, so it cannot tell whether the file holds a real secret.
- `secret_file_copies.readable_by_others`: `warning`.
  > Secret-named files carry group or world permission bits (mode & 0o077) in a home whose file modes vary. The audit matched file names and lstat mode bits only and did not open any file, so it cannot tell whether a file holds a real secret or who else can log in to this machine.
- `secret_file_copies.secret_named_files_in_fixture_homes`: `review_suggested`.
  > Secret-named files were counted inside nested directories shaped like a Hermes home below the profile root. The audit matched file names only and did not open any file, so it cannot tell real secrets from test values.
- `secret_file_copies.secret_named_files_in_work_folders`: `warning`.
  > Files whose names match secret-store patterns were counted outside the places the Hermes source keeps secrets. The audit matched file names only and did not open any file, so it cannot tell whether any of them holds a real secret; a copy, sync or share of those folders includes them. Files that third-party plugins write are not known to the audit as expected stores and are counted here.

## Output reference

Keys and labels from `audit/wiring/secret_file_copies.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `api-key`, `auth-json`, `auth_json`, `backup_copies`, `backup_copies_warning`, `backups_config_dir_count`, `browser_and_home_stores`, `burst_count`, `by_kind`, `by_pattern_class`, `by_top_level_folder`, `checked_count`, `class`, `class_count`, `classes`, `config_backup_burst_min_files`, `config_backup_burst_window_seconds`, `config_backup_info`, `config_backup_review`, `config_backups`, `copies`, `count`, `coverage`, `credential`, `credentials_store`, `cuts`, `dotenv`, `entries_walked`, `example_locations`, `expected_secret_files`, `fixture_home_count`, `fixture_home_secret_files_review`, `fixture_homes`, `fixture_profile_dir_count`, `folder_count`, `key`, `keystore`, `limits`, `max_burst_files`, `max_depth`, `max_depth_reached`, `max_entries`, `max_seconds`, `mcp_tokens`, `mode_bits`, `mode_check`, `mode_check_reason`, `month`, `netrc`, `note`, `npmrc`, `oauth-json`, `oauth_stores`, `os_credential_dirs`, `pairing`, `path`, `pem`, `pkcs12`, `platform_token_stores`, `plugin_count`, `plugin_dotenv_count`, `plugin_folder_count`, `plugin_folders_with_dotenv`, `plugin_secret_file_review`, `profile_count`, `pypirc`, `readable_by_others_count`, `readable_by_others_warning`, `reason`, `review_threshold`, `root_count`, `same_size_as_live`, `same_size_as_live_count`, `scope`, `secret_file_copies`, `secret_kind`, `secret_named_file_count`, `secret_named_files`, `secret_named_symlinks`, `secret_word`, `service-account-json`, `shared_auth`, `ssh-key`, `status`, `symlinks`, `symlinks_skipped`, `thresholds`, `token-json`, `tokens`, `top_level_folder_count`, `total`, `truncated_by`, `vault`, `work_folder_secret_files_warning`, `year`.

**Run metrics:** `elapsed_seconds`.

**Labels:** `Counted apart from work folders because names alone cannot tell test values from real secrets; the audit opened no file.`, `all_files_permissive`, `backups`, `completed`, `configs_may_embed_keys_not_read`, `home`, `invalid_path`, `limit_exceeded`, `missing`, `no_group_or_other_bits_anywhere`, `not_directory`, `not_measured`, `profile`, `subpath_unreadable`, `symlink_root`, `time_budget`, `uniform_mode`, `unreadable`, `verified`, `warn`.

**Path fields:** `by_top_level_folder.path`, `example_locations.path`.
