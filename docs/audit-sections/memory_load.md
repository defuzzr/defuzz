# Memory load (`memory_load`)

Measures live memory, snapshots and pending edits as counts and fixed labels. Text comparisons are lexical, not semantic.
Omitted limits and provider settings come from `config.yaml`; unreadable or ambiguous settings yield unknown coverage.
Shipped limits are `DEFAULT_MEMORY_LIMIT` and `DEFAULT_USER_LIMIT` in `audit/memory_load.py`; raised-limit review uses `RAISED_REVIEW_RATIO`.
The current resolved limits apply to profiles and snapshots, not their historical configurations.
The snapshot convention is `third_party_convention: true`: only `backups/memory-bg-review/<timestamp>/<id>/MEMORY.md` and `USER.md` are read; nothing else under backups/ is opened.
Config reads use the shared fingerprint reader, which may create the audit key in plugin data; private memory comparisons use a separate reader.
Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound; symlinked folders are counted as links and not measured.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/memory_load.py`.

## Findings

| Suffix | Classification | Consequence |
| --- | --- | --- |
| `over_limit` | review_suggested | Memory files (live or snapshot copies) are longer, in characters, than the character limit used for this audit; this compares file length only and does not measure what is sent with a request. |
| `mostly_dated_entries` | info | Memory files were counted where more than half of at least six entries contain a calendar date; a date does not show that the entry is out of date. |
| `other_machine_entries` | info | Memory files were counted whose entries contain another operating system's home-path form or a private-network address; this is left over text from another machine, and the count does not show that it is used or wrong here. |
| `standing_orders` | info / review_suggested for unasked-write wording | Entries phrased as always/never instructions were counted by word match; the count does not show who wrote them, whether they are followed, or whether they are wrong. |
| `duplicate_entries` | info | Normalized entries or eight-word shingles were counted that repeat within or across live memory files; the count does not show that the repeated text means the same thing. |
| `foreign_technology_entries` | review_suggested | Entries were counted that name technology families absent from the supplied projects; the count does not show that those entries are irrelevant. |
| `memory_state_sprawl` | info | A memory state directory, found by name and counted by file metadata only, holds more than 100 files; the count does not show whether the files are used or repeat each other. |
| `stale_pending_edits` | info | Pending memory edits were counted whose old text is absent from the current target file; the count does not predict whether approving them would succeed. |
| `pending_edit_changes_approval_entry` | review_suggested | This counts pending memory edits where an edit replaces or removes an entry that contains approval-related words; it is a word count and does not show that any approval setting or instruction would change. |
| `limit_raised_above_shipped` | info / review_suggested (ratio >= `RAISED_REVIEW_RATIO`) | The character limit for a memory file is set above the value Hermes ships with; text in these files is sent with every request, so a higher limit allows more text on every request. The setting was measured from config.yaml and does not show who changed it or why. |
| `multiple_memory_systems` | review_suggested | Two or more memory mechanisms are configured or present together; the audit counted them from config and files, and did not measure what each adds to a request or whether they repeat each other. |
| `could_not_verify` | info, could_not_verify coverage | Some memory measurements could not be verified; missing coverage is not a clean result. |

Elapsed time is returned separately in `run_metrics.elapsed_ms`.

## Output reference

Keys and labels from `audit/wiring/memory_load.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `across_file_entries`, `active_mechanisms`, `approval_edits`, `approval_entries`, `builtin_nonempty`, `by_kind`, `bytes`, `bytes_read`, `changes`, `char_limit`, `char_limits`, `characters`, `chars_over_shipped_limit`, `chronology_coverage`, `configured_char_limit`, `count`, `coverage`, `cross_file_share`, `cuts`, `dated_entries`, `duplicates`, `entries`, `entries_added`, `entries_removed`, `external_configured`, `external_provider`, `files`, `files_read`, `foreign_technology_coverage`, `foreign_technology_reason`, `growth_characters`, `home_os`, `identical_extra_snapshots`, `input_sources`, `kind`, `limit_ratio_to_shipped`, `limit_source`, `limits`, `max_characters`, `max_depth`, `max_entries`, `max_file_bytes`, `max_files`, `max_percent_of_limit`, `max_seconds`, `max_shingles`, `max_total_bytes`, `max_tree_entries`, `mechanisms`, `memory`, `memory_char_limit`, `memory_characters`, `memory_configured_char_limit`, `memory_limit_ratio_to_shipped`, `memory_provider`, `memory_shipped_char_limit`, `min_characters`, `min_percent_of_limit`, `name`, `near_duplicate_pairs`, `operations`, `other_os_coverage`, `other_os_entries`, `overlap`, `pending`, `percent_of_limit`, `private_network_entries`, `profile_index`, `prompt_injecting_plugins`, `same_size_extra_files`, `same_size_groups`, `scope`, `shipped_char_limit`, `snapshots`, `stale_edits`, `standing_order_entries`, `status`, `stores`, `systems`, `tree_entries`, `truncated_by`, `unasked_write_entries`, `unverified_edits`, `user`, `user_char_limit`, `user_characters`, `user_configured_char_limit`, `user_limit_ratio_to_shipped`, `user_shipped_char_limit`, `within_file_extra_entries`.

**Run metrics:** `elapsed_ms`.

**Labels:** `byterover`, `caller`, `completed`, `config`, `could_not_compare`, `credential_path`, `default`, `depth`, `encoding`, `file_bytes`, `host`, `info`, `input_unknown`, `main`, `memlock`, `memory-lock`, `memory_lock`, `memory_store.db`, `missing`, `no_projects`, `not_measured`, `other`, `pass`, `pending_shape`, `profile`, `retaindb`, `review_suggested`, `shingles`, `snapshot`, `snapshot_shape`, `special_file`, `symlink`, `time_budget`, `total_bytes`, `unreadable`, `verified`, `warn`.
