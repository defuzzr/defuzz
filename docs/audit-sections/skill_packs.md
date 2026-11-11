# Skill packs (`report.skill_packs`)

Estimates skills-index cost and measures usage records, install signals, snapshots and payload files.
The index estimate is an upper bound for runtime-gated skills; missing usage is unknown, not zero use.
Install signals do not establish how folders arrived. Timestamp clusters are weak evidence.
Non-text files strictly over `LARGE_PAYLOAD_BYTES` in `audit/skill_packs.py` are counted by class; bounded header probes classify them.
Config supplies omitted skill lists. The scan assumes the host platform and limits external directories to the profile.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/skill_packs.py`.

## Findings

| Rule id | Classification | Fires when | Evidence |
|---|---|---|---|
| `skill_packs.index_cost` | `review_suggested` | index chars > `INDEX_CHARS_THRESHOLD` or listed skills > `INDEX_SKILLS_THRESHOLD` | `skills`, `chars`, `estimated_tokens`, `runtime_gated_count`, `platform_excluded_count` |
| `skill_packs.never_used` | `review_suggested` | verified usage meets `NEVER_USED_MIN_SKILLS` and `NEVER_USED_SHARE_THRESHOLD` | `skills`, `zero_use_count`, `never_used_share`, `unverifiable_count` |
| `skill_packs.bulk_install` | `info`; `review_suggested` for a `license_hash` / `hub_lock_source` group meeting `BULK_REVIEW_MIN_SKILLS` and verified usage below `BULK_REVIEW_MAX_USED_SHARE` | one per reported group; an `mtime_window_2m` group is `info` | `signal`, `weak_signal`, `skills`; `used_skills`, `used_share` only with verified usage |
| `skill_packs.stale_index_snapshot` | `info` | snapshot parsed and `stale_count > 0` | `snapshot_version`, `snapshot_skills`, `stale_entries` (a count) |
| `skill_packs.always_on_skills` | `review_suggested` | at least one non-stock always-on skill | `count`, `auto_loaded_count`, `description_cue_count` |
| `skill_packs.license_copies` | `info` | count > `LICENSE_COPIES_THRESHOLD`, with fewer distinct texts than files | `count`, `distinct_texts`, `bytes` |
| `skill_packs.could_not_verify` | `info` | any cut, usage not verified, or snapshot unreadable | `cuts`, `reason`, `truncated_by` (only when set) |

- `skill_packs.index_cost`: The rendered skills index is above 17,000 characters or 150 listed skills and is sent with every request before any skill is opened; the character count is about the real size and an upper bound when listed skills depend on tools, apps or environments, and it does not include any skill body.
- `skill_packs.never_used`: At least 70% of at least 20 non-stock skills with a usable observation window have zero recorded uses in skills/.usage.json; Hermes records a use only when a skill is loaded through skill_view, a slash command or a cron job, so this does not show reads by other means or use before recording began.
- `skill_packs.bulk_install`: At least 20 non-stock skill folders share one install signal (identical license text, the same hub-lock source, or SKILL.md times within 2 minutes, which is a weak signal); this counts folders and does not show how or why they were installed.
- `skill_packs.stale_index_snapshot`: The on-disk .skills_prompt_snapshot.json lists skill entries with no matching SKILL.md under skills/; Hermes rebuilds this cache when its manifest no longer matches, so this counts left-over cache entries and does not describe the current prompt.
- `skill_packs.always_on_skills`: One or more non-stock skills are listed in skills.auto_load or carry an every-session cue in their frontmatter description; auto-loaded skills add their body to every session, while a description cue is wording only and does not show that the skill is loaded.
- `skill_packs.license_copies`: More than 50 LICENSE, NOTICE or COPYING files inside skill folders share fewer distinct texts than files; this counts duplicated license files and does not show how the folders were installed.
- `skill_packs.could_not_verify`: Skill pack usage or directory coverage could not be completely verified; missing usage records or bounded traversal cuts are not evidence of clean state or zero usage.

## Output reference

Keys and labels from `audit/wiring/skill_packs.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `always_on`, `archive`, `audio`, `bulk_group_min_skills`, `bulk_installs`, `bulk_review_max_used_share`, `bulk_review_min_skills`, `bytes_read`, `coverage`, `credentials_skipped`, `days_30_to_90`, `days_since_last_use`, `dead_weight`, `description_chars`, `description_clip_chars`, `disabled_skills_count`, `discovered_skills`, `distinct_license_texts`, `document`, `entries_walked`, `executable_file`, `external_dirs_skipped`, `files_hashed`, `group_count`, `groups`, `gt_90_days`, `hub_lock_entries`, `hub_lock_missing_on_disk`, `hub_lock_present`, `identical_license_copies`, `image`, `index`, `index_chars`, `index_skills`, `large_payload_bytes`, `license_bytes`, `license_copies`, `license_files_count`, `limits`, `loadable_skills`, `loaded_sizes`, `lt_30_days`, `max_chars`, `max_depth`, `max_entries`, `max_file_bytes`, `max_files_per_skill`, `max_license_file_bytes`, `max_license_files`, `max_seconds`, `max_skills`, `max_total_bytes`, `max_usage_rows`, `median_chars`, `model_weights`, `mtime_window_seconds`, `name_chars`, `never`, `never_used_min_skills`, `non_stock_count`, `non_stock_never_used_share`, `non_stock_skills`, `non_stock_skills_evaluated`, `non_stock_zero_use_count`, `non_text_over_1mb_by_type`, `non_text_over_1mb_bytes`, `non_text_over_1mb_count`, `other`, `p90_chars`, `path`, `paths`, `present`, `recording_since`, `recording_until`, `shadowed_skills_count`, `skill_packs`, `skills_count`, `skills_evaluated`, `snapshot`, `stale_count`, `status`, `stock_skills`, `symlinks_skipped`, `thresholds`, `top_10_largest`, `top_used_counts`, `unverifiable`, `usage`, `use_count`, `used_skills_count`, `version`, `video`, `zero_use_unverifiable_count`.

**Run metrics:** `elapsed_ms`, `time_budget_hit`.

**Labels:** `.skills_prompt_snapshot.json`, `completed`, `missing`, `not_applicable`, `not_measured`, `skills/.usage.json`, `time_budget`, `truncated`, `unverified_inputs`, `usage_file_malformed`, `usage_file_missing`, `usage_file_no_timestamps`, `verified`.
