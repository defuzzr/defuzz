# Kanban residue (`kanban_residue`)

Measures boards in the shared default home through read-only SQLite queries and log metadata.
Retry context is reconstructed from today's stored body, earlier comments and closed runs, not from recorded model requests.
The first-run estimate can include later body edits; it excludes parts of the full worker context.
Author markers identify writing surfaces, not people. Default-profile work counts as user-side even when an agent performed it.
Ages use the board's newest event unless a reference time is supplied. `gc_ever_run` remains `could_not_verify`.
Database reads follow [audit-scope.md](../audit-scope.md); an existing WAL shared-memory file may receive read marks.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/kanban_residue.py`.

## Findings

| Rule suffix | Classification | Trigger |
|---|---|---|
| retry_context_growth | review_suggested | latest reconstructed payload exceeds the size or growth threshold |
| blocked_loops | review_suggested | repeated runs without completion, or block recurrence limit reached |
| agent_authored_board | info | agent-side share and board size meet thresholds; authorship verified |
| archived_never_collected | review_suggested | archived share with old GC-eligible events, or archived-log bytes, exceeds thresholds |
| heartbeat_bloat | info | heartbeat share and event count exceed thresholds |
| never_run_backlog | info | old never-run tasks exceed the backlog share threshold |
| workspaces_inside_home | review_suggested | enough task workspace paths are inside the home but outside Hermes scratch roots |
| orphan_board_folders | info | any board.json folder without a database, excluding default metadata folder |
| machine_paths_in_tasks | info | body or comment path-marker share exceeds threshold |
| could_not_verify | info; coverage could_not_verify | unreadable/unsupported/unstable data, unknown authorship or budget cut |

| Rule | Classification | Evidence keys |
|---|---|---|
| agent_authored_board | info | tasks, agent_tasks, user_tasks, unclassified_tasks |
| archived_never_collected | review_suggested | archived_share, gc_eligible_events, archived_log_bytes |
| blocked_loops | review_suggested | four_runs_without_completion, repeated_block_threshold, repeated_block_nonzero, max_block_recurrences, repeated_block_limit |
| could_not_verify | info | cuts (coverage could_not_verify) |
| heartbeat_bloat | info | events, heartbeat_events, heartbeat_share |
| machine_paths_in_tasks | info | tasks, comments, bodies_with_home_paths, comments_with_home_paths |
| never_run_backlog | info | tasks, never_run, never_run_older_than_seven_days |
| orphan_board_folders | info | orphan_board_folders |
| retry_context_growth | review_suggested | runs, first_worker_chars, latest_worker_chars, first_run_body_edited_later, first_uncapped_chars, latest_uncapped_chars, current_uncapped_chars, growth_ratio (omitted when null), growth_tasks |
| workspaces_inside_home | review_suggested | workspaces_inside_home, workspaces_in_kanban_scratch_root, workspaces_outside_kanban_scratch_root |

- `agent_authored_board`: At least 80% of a board's tasks, on a board of 20 or more tasks, carry an agent-side author marker (worker, decomposer or a profile that ran tasks); the marker names the writing surface, not who asked for the work, and work done through the default chat profile counts as user-side.
- `archived_never_collected`: Archived tasks still keep their logs and all their rows: more than 1,000,000 bytes of archived-task logs, or a board at least 80% archived with events more than 30 days older than its newest event; the audit cannot tell whether clean-up was ever run.
- `blocked_loops`: At least one task has four or more runs with no completed run or reached Hermes's repeated-block limit of 2; these are stored records of past attempts, not a current fault, and do not show whether another attempt would succeed.
- `could_not_verify`: Some kanban measurements could not be verified within the supported schema and read budgets; missing coverage is not a clean result.
- `heartbeat_bloat`: More than half of a board's stored events, on a board of 500 or more events, are worker heartbeats; this counts retained rows, not whether the work made progress.
- `machine_paths_in_tasks`: More than half of a board's task bodies or of its comments contain a home-style absolute path marker; this counts text markers, not whether those paths exist on this machine.
- `never_run_backlog`: More than 10% of a board's tasks have no recorded run and were created more than seven days before the reference time; this counts stored rows, not why they never ran.
- `orphan_board_folders`: One or more board folders hold board metadata but no database; the audit does not tell how they came to be that way.
- `retry_context_growth`: Rebuilt from text stored today, a retried task would hand its latest worker more characters of its own body, comments and earlier attempts than at its first run, above the review limit of 20,000 characters or three times the first-run figure; Hermes caps each item but not the total. The first-run figure uses today's body and is an estimate when the body was edited after that run. This is a reconstruction from stored rows, not a recording of any prompt, and it describes left-over data, not a current fault.
- `workspaces_inside_home`: Five or more tasks store a workspace path inside the Hermes home but outside Hermes's own kanban workspaces folder; this counts stored paths, not files that are safe to delete.

## Output reference

Keys and labels from `audit/wiring/kanban_residue.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `active`, `agent`, `agent_tasks`, `archived`, `archived_board`, `archived_bytes`, `archived_count`, `archived_log_bytes`, `archived_share`, `authorship`, `blocked`, `board`, `boards`, `bodies`, `bodies_with_home_paths`, `body_home_path_share`, `bytes`, `comment_agent_share`, `comment_home_path_share`, `comment_unclassified_share`, `comment_user_share`, `comments`, `comments_with_home_paths`, `complete_prompt_measured`, `completed`, `count`, `coverage`, `crashed`, `current_uncapped_chars`, `cuts`, `cycles`, `databases_found`, `date_range`, `deepest_chain`, `default_profile_runs`, `done`, `events`, `events_older_than_gc_window`, `failed`, `first_run_body_edited_later`, `first_uncapped_chars`, `first_worker_chars`, `four_runs_without_completion`, `gave_up`, `gc_eligible_events`, `growth_example`, `growth_ratio`, `growth_tasks`, `heartbeat_events`, `heartbeat_share`, `historical_body_verified`, `largest_bytes`, `largest_tree`, `latest_uncapped_chars`, `latest_worker_chars`, `limits`, `links`, `logs`, `loops`, `machine_binding`, `max`, `max_block_recurrences`, `max_entries`, `max_graph_steps`, `max_json_nodes`, `max_links`, `max_metadata_chars`, `max_path_chars`, `max_rows_per_table`, `max_seconds`, `max_sql_steps`, `median`, `never_run`, `never_run_older_than_seven_days`, `older_than_gc_window`, `open_inactive_over_fourteen_days`, `p90`, `path`, `ready`, `reclaimed`, `reference_clock`, `released`, `repeated_block_limit`, `repeated_block_nonzero`, `repeated_block_threshold`, `retried_tasks`, `retry_context`, `review`, `roots`, `rotated_count`, `run_errors`, `run_metadata`, `run_summaries`, `running`, `runs`, `runs_by_outcome`, `scheduled`, `spawn_failed`, `status`, `symlinks_skipped`, `task_agent_share`, `task_unclassified_share`, `task_user_share`, `tasks`, `tasks_by_status`, `tasks_linked_to_project`, `text_volume`, `timed_out`, `todo`, `top_tasks`, `trees`, `triage`, `truncated_by`, `unclassified`, `unclassified_tasks`, `user`, `user_tasks`, `widest_fanout`, `workspace_folders_existing`, `workspaces_in_kanban_scratch_root`, `workspaces_outside_kanban_scratch_root`.

**Run metrics:** `elapsed_seconds`, `reference_time_override`.

**Labels:** `authorship_unclassified`, `credential_path`, `dangling_links`, `database_changed`, `database_in_use`, `database_unreadable`, `default`, `directory_entries`, `graph_cycle`, `graph_steps`, `hot_journal`, `info`, `injected`, `invalid_board_name`, `invalid_task_id`, `invalid_values`, `kanban`, `kanban.db`, `metadata_chars`, `metadata_invalid`, `metadata_nodes`, `metadata_normalization`, `named_board`, `newest_event`, `not_measured`, `not_present`, `outside_profile`, `path_chars`, `review_suggested`, `schema_unsupported`, `sql_steps`, `symlink`, `table_rows`, `time_budget`, `unreadable`, `verified`, `wal_needs_index`, `warn`.

**Path fields:** `source_paths`.
