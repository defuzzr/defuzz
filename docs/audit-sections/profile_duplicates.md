# Profile duplicates (`report.profile_duplicates`)

Measures repeated files, identity/memory similarity, caches and empty named-profile folders from the HOME ROOT.
Passing a named profile produces `named_profile_given`. Size findings require `MIN_PROFILES_FOR_FINDINGS` in `audit/profile_duplicates.py`; coverage findings still apply below it.
Eligible files are hashed through `open_checked` (read-only, no-follow). It tries `O_NOATIME`; access times may change on fallback.
Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound.
Symlinks (to files or folders) are never followed and their targets are not measured.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/profile_duplicates.py`.

## Findings

| Rule id | Classification | Consequence |
|---|---|---|
| `profile_duplicates.repeated_binary` | `review_suggested` | An executable file of at least 10 MiB is stored as byte-identical copies in at least three profiles; this measures duplicated disk bytes and does not show whether any profile runs it. |
| `profile_duplicates.identical_files` | `review_suggested` | Byte-identical non-credential files repeated across profiles take more than 100 MiB beyond one copy each, not counting regenerable caches; this measures redundant storage across profile directories and does not establish which profile copy is authoritative. |
| `profile_duplicates.cloned_identity_files` | `review_suggested` | Byte-identical MEMORY.md or USER.md files appear in at least three profiles, or more than half of the lines in the median memory file match other profiles; this measures matching content only and cannot tell which copy is the original or how the files came to match. |
| `profile_duplicates.per_profile_caches` | `info` | Regenerable hub and model catalog caches repeated across profile directories exceed 50 MiB; this measures disk space used by per-profile cache copies and does not show data corruption. |
| `profile_duplicates.empty_profiles` | `info` | At least five profile directories are completely empty or contain only log files; this counts folder contents and does not show whether a gateway still references them. |
| `profile_duplicates.could_not_verify` | `info` | Profile duplicate measurements hit a safety bound, symlink exclusion, or read error before all profile entries were verified; partial counts are retained and unverified regions are not claimed clean. |

## Output reference

Keys and labels from `audit/wiring/profile_duplicates.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `MEMORY.md`, `SOUL.md`, `USER.md`, `affected_profiles`, `at_profile_root`, `by_kind`, `bytes_hashed`, `bytes_wasted`, `cache_duplicate_wasted_bytes`, `cloned_identity`, `cloned_identity_min_profiles`, `cloned_identity_shared_line_share`, `copies`, `count`, `coverage`, `credential_same_size_groups`, `cut_reasons`, `cuts`, `distinct_profiles`, `duplicate_group_count`, `duplicate_groups`, `empty`, `empty_profiles`, `entries_walked`, `executable_magic`, `families`, `family_count`, `file`, `file_count`, `file_kind`, `files`, `files_count`, `files_hashed`, `groups`, `has_config`, `hashed`, `hub_index_cache_bytes`, `hub_index_cache_profiles`, `identical_files_wasted_bytes`, `identical_group_sizes`, `identical_profiles`, `identical_profiles_count`, `identity_files_read`, `in_main_home`, `kind`, `limits`, `line_count`, `location`, `log_only_profiles`, `logs_only`, `max_bytes_hashed`, `max_depth`, `max_entries`, `max_files_hashed`, `max_identity_file_bytes`, `max_identity_files`, `max_names_listed`, `max_seconds`, `max_shared_line_share`, `median_shared_line_share`, `member_count`, `min_empty_or_log_only_profiles`, `min_family_members`, `min_family_prefix_len`, `min_profiles_for_findings`, `min_repeated_binary_bytes`, `min_repeated_binary_profiles`, `models_dev_cache_bytes`, `models_dev_cache_profiles`, `no_config_profiles`, `observation`, `path`, `paths`, `per_profile_cache_bytes`, `per_profile_caches`, `profile_copies`, `profile_count`, `profile_duplicates`, `profile_families`, `profiles`, `profiles_above_50pct`, `profiles_count`, `profiles_total_bytes`, `profiles_total_files`, `profiles_with_caches`, `profiles_with_file`, `provider_models_cache_bytes`, `provider_models_cache_profiles`, `reason`, `regenerable_cache`, `shared_line_share`, `size_bytes`, `skill_md_duplicate_copies`, `skill_md_duplicate_groups`, `skipped_credential_dirs`, `status`, `suffixed_copy`, `thresholds`, `top_duplicate_groups`, `total_bytes`, `total_empty_or_log_only`, `total_wasted_bytes`, `truncated_by`, `unsafe_profile_name_count`, `wasted_bytes`, `wasted_bytes_excluding_caches`, `wasted_bytes_including_main_home`, `wasted_share`, `wasted_share_of_profiles`.

**Run metrics:** `elapsed_ms`.

**Labels:** `agents_md`, `alphabetic_prefix`, `auth_json`, `bytes_hashed_limit`, `completed`, `config_yaml`, `credential_other`, `credential_root_refused`, `cut_or_exclusion`, `database`, `depth_limit`, `digit_series`, `entries_limit`, `env_file`, `executable_file`, `files_hashed_limit`, `hub_index_cache`, `identity_file_bytes_limit`, `identity_files_limit`, `identity_md`, `inode_changed`, `invalid_encoding`, `invalid_profile_root`, `large_file`, `missing_profile_root`, `models_dev_cache`, `non_directory_profile_entry`, `non_regular_file`, `not_measured`, `provider_models_cache`, `read_error`, `size_only_not_hashed`, `skill_md`, `special_file_refused`, `stat_error`, `symlink_or_non_dir_profiles_root`, `symlink_refused`, `time_budget`, `unreadable_directory`, `unreadable_profile_root`, `unreadable_profiles_dir`, `unsafe_or_symlink_path`, `verified`.

**Path fields:** `affected_identities`, `source_paths.path`.
