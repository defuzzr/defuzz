# Skill change ledger and backup store (`report.skill_ledger`)

Measures recorded skill changes, backup sizes and bookkeeping from the ledger and usage metadata.
Actor labels describe the recorded surface, not who requested or approved a change; edits outside Hermes may be absent.
Blob and snapshot sizes come from metadata. Equal sizes do not prove equal content.
Symlinks are refused (`symlink_refused`) and counted as a cut. An absent ledger is incomplete coverage, not evidence of no changes.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/skill_ledger.py`.

## Findings

| Rule ID | Class | Fires when | Note |
|---|---|---|---|
| `skill_ledger.changes_by_recorded_actor` | `info` | changes >= `ACTOR_SUMMARY_MIN_CHANGES` and actor share > `ACTOR_SUMMARY_SHARE_THRESHOLD` | `info` because `agent` includes edits a person asked for. |
| `skill_ledger.patch_storm` | `review_suggested` | changes >= `PATCH_STORM_THRESHOLD` within `PATCH_STORM_WINDOW_SECONDS` | Many recorded changes to one skill in one day. |
| `skill_ledger.skill_growth` | `review_suggested` | verified growth >= `SKILL_GROWTH_FACTOR` and latest size >= `SKILL_GROWTH_MIN_BYTES` | Only verified growth counts. |
| `skill_ledger.version_churn` | `info` | distinct versions >= `VERSION_CHURN_THRESHOLD` | Counts distinct recorded versions. |
| `skill_ledger.noop_changes` | `info` | `> 0` recorded no-ops | Only recorded no-ops count; a same-size change is not a no-op. |
| `skill_ledger.orphan_backups` | `review_suggested` | unreferenced bytes > `ORPHAN_BACKUP_BYTES_THRESHOLD`, with `references_complete` or no ledger | Applies with no ledger at all, or when every reference was read. |
| `skill_ledger.bookkeeping_orphans` | `info` | `>= 1` active usage record without a folder | A usage record whose skill folder no longer exists. |
| `skill_ledger.could_not_verify` | `info` | no ledger, any cut, or any cap | For example `ledger_absent`. |

- `skill_ledger.bookkeeping_orphans`: Skills are recorded as active in skills/.usage.json with no skill folder of that name on disk; usage records are keyed by frontmatter name, so a skill whose folder is named differently is also counted.
- `skill_ledger.changes_by_recorded_actor`: Recorded skill changes are counted by the actor label the ledger stores: curator (curator runs and background review forks), agent (tool calls in a conversation, which may include edits a person asked for or approved) and user (hermes curator archive, restore and purge commands); the ledger does not record who requested or reviewed a change, and edits made to skill files outside Hermes are not recorded at all.
- `skill_ledger.could_not_verify`: The skill change ledger or bookkeeping metadata is absent, unreadable, malformed, or truncated by collection bounds; an absent ledger is not evidence that no skill changes occurred.
- `skill_ledger.noop_changes`: The ledger contains change records whose recorded after-state is identical to the before-state (same file hashes, or no file recorded on either side); this shows the record, not why the change was made.
- `skill_ledger.orphan_backups`: More than 20 MiB of backup blobs under .curator_backups/blobs are not referenced by any entry in the skill change ledger, or cannot be matched because there is no ledger; this measures disk use, not whether the files are still wanted.
- `skill_ledger.patch_storm`: At least one skill has 10 or more ledger changes within a 24-hour window of ledger timestamps; the ledger records the changes, not why they were made or who asked for them.
- `skill_ledger.skill_growth`: One or more skills grew to at least twice their initial recorded size and at least 8,000 bytes; blob sizes measure growth on disk but do not distinguish distilled reference depth from incident accumulation.
- `skill_ledger.version_churn`: One or more skills accumulated at least 20 distinct SKILL.md content versions in the ledger; this counts recorded hashes, not the size or nature of each change.

## Output reference

Keys and labels from `audit/wiring/skill_ledger.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `actor_summary_min_changes`, `actor_summary_share`, `affected_skill_count`, `agent_changes`, `all_blobs_orphaned_no_ledger`, `backup_store`, `blob_bytes`, `blob_count`, `blob_entries_examined`, `bookkeeping_orphans`, `changes`, `changes_before_delete`, `changes_by_actor`, `changes_by_month`, `coverage`, `curator`, `curator_changes`, `curator_enabled`, `curator_enabled_source`, `curator_or_agent_changes`, `curator_or_agent_share`, `cuts`, `date_range`, `deleted`, `distinct_versions`, `earliest_epoch_s`, `first_size_bytes`, `growth_coverage`, `growth_factor_threshold`, `growth_ratio`, `latest_epoch_s`, `latest_size_bytes`, `ledger_bytes_read`, `ledger_lines_read`, `ledger_present`, `limits`, `manifest_entries_not_on_disk_count`, `max_blob_entries`, `max_changes_24h`, `max_distinct_versions`, `max_growth_ratio`, `max_latest_size_bytes`, `max_ledger_bytes`, `max_ledger_lines`, `max_seconds`, `min_latest_bytes_threshold`, `missing_blob_hashes`, `month`, `near_identical_size_pairs`, `near_identical_size_ratio`, `noop_changes`, `orphan_backup_bytes`, `orphan_blob_bytes`, `orphan_blob_count`, `orphan_count`, `other`, `other_changes`, `patch_storm_changes_24h`, `path`, `paths`, `peak_changes_24h`, `reason`, `reasons`, `skill_growth_factor`, `skill_growth_min_bytes`, `skill_ledger`, `skills`, `skills_deleted_count`, `skills_growth_could_not_verify`, `skills_in_ledger`, `skills_without_folder_count`, `span_days`, `status`, `tarball_bytes`, `tarball_count`, `threshold_bytes`, `threshold_changes_24h`, `thresholds`, `top_skills_by_changes`, `top_skills_by_growth`, `total`, `total_changes`, `truncated_by`, `unlocated_count`, `usage_orphan_count`, `user`, `user_changes`, `version_churn`, `version_churn_threshold`, `year`.

**Run metrics:** `elapsed_ms`.

**Labels:** `.`, `.curator_backups/blobs`, `blobs_unreadable`, `caller`, `completed`, `config`, `default`, `growth_blob_missing`, `ledger_unreadable`, `malformed_ledger_line`, `manifest_malformed`, `manifest_unreadable`, `not_applicable`, `not_measured`, `profile_missing`, `profile_unreadable`, `skills/.curator_ledger.jsonl`, `skills/.usage.json`, `skills_tree_unreadable`, `snapshots_unreadable`, `time_budget`, `usage_malformed`, `usage_unreadable`, `verified`, `warn`.

**Path fields:** `skills[].path`, `top_skills_by_changes.paths[]`, `top_skills_by_growth.paths[]`.
