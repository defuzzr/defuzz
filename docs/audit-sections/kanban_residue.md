# Kanban residue (`kanban_residue`)

Read-only, deterministic inventory and stored-text measurement. No cleanup action,
model call, network access, Hermes import, home-side file creation, or execution.
The public audit runner includes this section and passes the shared Hermes home
root. Its wiring sheet is `audit/wiring/kanban_residue.json` (keys, vocabulary,
rules, sentences, free strings).

## Source contract

References are to the audited Hermes source tree, not this plugin.

| Assumption | Verified source |
|---|---|
| Shared default home, not the active named profile | `hermes_cli/kanban_db.py:401-415` |
| Main `kanban.db`; named `kanban/boards/<slug>/kanban.db`; slug grammar | `kanban_db.py:372-386,485-498,540-566` |
| `board.json` identity marker; archive directories and metadata tombstones | `hermes_cli/kanban_db_boards.py:19-30,146-191` |
| Default `kanban/logs/`, named-board `logs/`, `<task-id>.log` | `kanban_db.py:586-589,4043-4046` |
| `tasks`: id, body, assignee, status, created_by, created_at, completed_at, workspace_path, project_id | `kanban_db.py:777-798` |
| Originating session_id; block_recurrences (not consecutive_failures) | `kanban_db.py:858-877` |
| `task_links(parent_id,child_id)`; no separate dependency table is required | `kanban_db.py:880-884` |
| `task_comments(id,task_id,author,body,created_at)` | `kanban_db.py:886-892` |
| `task_events(id,task_id,kind,payload,created_at)` | `kanban_db.py:894-901` |
| Body edits leave events: `edited` with `{"fields": [...]}`, `specified` with `{"changed_fields": [...]}`; no body history is stored | `kanban_db.py:3048-3084,3732-3781`; `hermes_cli/kanban_specify.py:222-229` |
| Hermes's own scratch workspace roots `<home>/kanban/workspaces/` and `kanban/boards/<slug>/workspaces/` | `kanban_db.py:569-572`; `hermes_cli/kanban_db_workspace.py:312-320,347-349` |
| Author/creator = current profile name: `default` for the default home, the profile directory name otherwise, `custom` elsewhere | `hermes_cli/profiles.py:1971-2006` |
| `task_runs(id,task_id,profile,status,outcome,summary,error,metadata,started_at,ended_at)` | `kanban_db.py:910-934` |
| Task statuses and archive status (not an archive boolean) | `hermes_cli/kanban_workflow.py:27-28,114-123` |
| Completed/blocked/crashed/etc. outcomes; scheduled outcome | `kanban_db.py:928-930,3889` |
| Task IDs: `t_` + eight hexadecimal digits | `kanban_db.py:988-991` |
| Worker context sections (header, attachments, prior attempts, parent results, assignee's other runs, comments), no total-length cap | `kanban_db.py:3896-3917` |
| 10 prior attempts, 30 comments, 8192 body chars, 2048 comment chars, 4096 chars per summary/error/metadata/result | `hermes_cli/kanban_db_context.py:23-27,50-57` |
| Prior attempts are closed runs (`ended_at` set) in `started_at, id` order; comments in `created_at` order; both keep the NEWEST items | `kanban_db_context.py:76-84,130-154,220-239`; ordering: `kanban_db.py:1700-1701,4109-4128` |
| Attachments are paths; completed-parent results; assignee's five other completed runs (200-char first-line summaries) | `kanban_db_context.py:112-127,157-216` |
| Prompt tells worker to call kanban_show first | `agent/prompt_builder.py:271-273` |
| kanban_show exposes full body/comments/runs, last 50 events, AND worker_context | `tools/kanban_tools.py:421-430,663-692` |
| Event name `heartbeat` | `hermes_cli/kanban_db_dispatch.py:636` |
| Repeated-block routing threshold = 2 | `kanban_db.py:113-115,871-877` |
| `hermes kanban gc`: default 30-day event/log retention, archived workspace cleanup | `hermes_cli/kanban_ops.py:305-352` |
| GC event sweep only targets done/archived tasks, excludes decomposed events; logs use mtime | `kanban_db.py:4013-4038` |
| Logs append on retry; rotation checked before opening | `kanban_db_dispatch.py:2703-2713` |
| Default rotation above 2 MiB, one backup, configurable | `hermes_cli/kanban_worker_log.py:9-29,36-62` |

No automatic call to the event/log GC was found in the production Python callers:
the calls are in `kanban_ops.py:349-350`. This is not evidence about a user's cron,
external shell automation, prior versions, or whether GC ever ran. Notification
subscription GC and completion-time workspace cleanup are different operations.
Consequently `gc_ever_run` is always `could_not_verify`. GC does **not** remove the
archived task's body, comments or run history. A sub-2-MiB log without rotations is
normal under the default rotation policy.

## Measurement semantics

### Authorship

`created_by` and comment `author` are profile/surface markers, not authenticated
human identities. CLI calls use current profile or `user`
(`hermes_cli/kanban.py:202-205`); tools use current profile or `worker`
(`tools/kanban_tools.py:139-150`); auto-decomposition uses `auto-decomposer`
(`gateway/kanban_watchers_dispatcher.py:291`).

Rule, in priority order: explicit `user`/`default` is user-side (even when the
task carries an originating chat session id); `worker`, `auto-decomposer`, or a
nonempty task session marker is agent-side; another author matching a
non-user/non-default profile in this board's runs is agent-side; otherwise
unclassified. No author or session identifiers are returned.

Limit, stated plainly: the marker names the profile that wrote the row, not a
person. A board the user drives through the default chat profile is counted as
user-directed, and the audit cannot tell a person typing from an agent acting for
them in that profile. The default profile can also run as a worker:
`authorship.default_profile_runs` counts such runs,
and comments it wrote are still counted user-side. Likewise a named profile used
interactively is counted agent-side. More than 20% unclassified in either
population makes authorship `could_not_verify` and suppresses the
agent-authored-board finding.

### Retry context

What the figure is: a **reconstruction from the text stored today**, not a
recording of any prompt. For every task with at least two runs it rebuilds the
task's OWN part of Hermes's worker context at the first and the latest run start:

- today's task body, stripped, capped at 8,192 characters (included only if
  non-blank);
- comments created strictly before the run start, the newest 30 (oldest dropped
  first), each stripped and capped at 2,048 characters; comments made after a run
  started are not counted for that run (they postdate the spawn-time build);
- closed runs (`ended_at` set) that ended strictly before the run start, the
  newest 10, each with summary, error and normalized metadata capped separately
  at 4,096 characters.

The caps are characters (Python slices) although the source constants are named
`BYTES`; the visible `… [truncated, N chars omitted]` suffix counts. Not counted:
the header/title lines, headings and labels, attachment lines, completed parents'
results, the assignee's last 5 completed runs on other tasks (first line, at most
200 characters each), and omitted-item notes. There is no cap on the total.
Separately, the worker prompt tells the worker to call `kanban_show` first, which
returns the uncapped body, every comment, every run, the last 50 events AND
another copy of the rendered worker context: the worker can therefore read more
than the reconstruction counts.

Body history: the schema keeps none. The first-run figure uses today's body. If a
body-edit event (`edited`/`specified` whose payload lists `"body"`, found with
`instr()` on that fixed marker) is dated at or after the first run start,
`first_run_body_edited_later` is true and the first-run figure is an estimate.

Metadata JSON stays in SQLite: a bounded JSON-tree aggregate counts the length of
sorted, Unicode-preserving Python JSON serialization, including punctuation and
spaces. Sorting keys changes order, not length. A numeric-only SQLite callback
matches Python float rendering; no prose enters that callback. Duplicate object
keys, oversized integers, malformed JSON and JSON-budget cuts mark uncertainty.
Falsy decoded metadata is omitted just as in the source renderer.

`first_uncapped_chars`, `latest_uncapped_chars` and `current_uncapped_chars` are
stored body/comment/summary/error/metadata character totals without item/count
caps. The last includes all currently saved runs and comments. These are **not**
the byte/character length of serialized kanban_show JSON: JSON escaping, task
result/other fields, event payloads, headings, attachment paths, parent results,
role history and kanban_show's additional worker_context copy are excluded.

The source has no historical body snapshots and permits edited notes/run metadata;
same-second ordering cannot prove before/after. Thus `historical_body_verified`
and `complete_prompt_measured` are false even when arithmetic coverage is verified.
This measures stored text available for replay, not a model request, model behavior,
tokens, cost, or causal contamination. The finding's “about” language refers to
this latest-start reconstruction, not an exact forecast of a future prompt.

Rank top ten by latest payload size; evaluate the growth threshold over **all**
retried tasks, including those outside that ten. `growth_example` (the finding's
subject) is the qualifying task with the most runs, then the largest latest
payload. Report first/latest size and growth
ratio distributions: median, nearest-rank p90 and max. A zero first payload has a
null ratio; positive growth from zero still triggers the relative comparison.

### Trees, inactivity, binding and storage

Links are directed parent-to-child. Roots include isolated tasks; deepest chain is
an **edge count** (seven edges means eight tasks). Largest tree means unique tasks
reachable from a root; DAGs may share children. Topological traversal detects
cycles; bounded reachability uses visited sets and a separate work budget.

Report all never-run tasks plus those older than seven days; only the older subset
triggers the backlog finding. Four or more runs without any completed outcome is
reported even if the task was later archived. Report positive repeated-block
counters, counters at least two, and their maximum separately. Open inactivity is
over fourteen days since latest creation/comment/run/event activity. Reference time
is the board's newest event, never wall clock, unless explicitly injected; an
injected value is echoed at `run_metrics.reference_time_override`. If a board has
no events, age-dependent metrics are unavailable (no stale finding).

SQL `instr` counts bodies/comments containing `/home/`, `/Users/`, or `C:\\`.
These are marker matches, not validated paths. Workspace association requires a
literal home-prefix boundary. `home_path` can map a historical backup home to the
supplied extracted root; only relative suffixes under that root are stat'ed. Paths
outside the root and symlinks never authorize traversal. Existing workspace samples
are not output: no workspace folder name leaves the module, only counts
(`workspaces_inside_home`, `workspaces_in_kanban_scratch_root`,
`workspace_folders_existing`). Counts include repeated task associations, not just
distinct directories. `workspaces_in_kanban_scratch_root` counts paths strictly
below Hermes's own scratch roots; those are where Hermes puts every scratch task,
so they do not count toward the finding. Project IDs are counted, never printed.

Text-volume totals are SQL `length` aggregates for bodies, comments, run summaries,
run errors and run metadata; malformed/non-text/NUL-containing data is unverified.
Log contents are never opened. Log count, bytes, largest file, rotated-file count,
mtime age and archived-task-associated bytes come from lstat only. Archive folders
without a DB may still hold logs; their task association is unknown. A metadata-only
folder is an informational observation, not proof of an orphan or corruption.

## Thresholds and exclusions

All thresholds are named module constants.

| Rule suffix | Classification | Trigger |
|---|---|---|
| retry_context_growth | review_suggested | any latest payload >20,000 chars **or** >3 times first |
| blocked_loops | review_suggested | any task with >=4 runs/no completion, or block_recurrences >=2 |
| agent_authored_board | info | >=20 tasks and >=80% agent-side, authorship verified |
| archived_never_collected | review_suggested | >=80% archived with GC-eligible events more than 30 days older than the newest event, **or** >1,000,000 bytes of archived-task logs |
| heartbeat_bloat | info | >=500 events and >50% heartbeat |
| never_run_backlog | info | >10% of tasks never ran and are older than 7 days |
| workspaces_inside_home | review_suggested | >=5 task workspace paths inside the home and outside Hermes's own scratch roots |
| orphan_board_folders | info | any board.json folder without a database, excluding default metadata folder |
| machine_paths_in_tasks | info | >50% of bodies **or** >50% of comments contain path markers |
| could_not_verify | info; coverage could_not_verify | unreadable/unsupported/unstable data, unknown authorship or budget cut |

Do not flag an absent kanban home, schema-only empty board, small mostly-user board,
workspace paths under Hermes's own `kanban/workspaces/` scratch root, credential-named
or lock files in a log folder (skipped by name, never stat'ed), archived status alone, normal decomposition links, active-task log size, old active
or decomposed events deliberately excluded by GC, zero-byte locks, or notification
subscription rows. Empty board databases return section `not_present` without
findings; their inventory remains visible. No finding recommends deletion.

## Read policy and limits

`_open_user_db(path)` is the only database opener and delegates to the shared
`audit.readonly_db.open_readonly_sqlite`, so kanban follows the audit-wide rule
(`docs/audit-scope.md`, user SQLite databases):

- no `-wal`, or an empty `-wal`: `mode=ro&immutable=1`, post-read identity check;
- `-wal` with frames and an existing `-shm` (a running Hermes holds the board
  open): `mode=ro` in place; only the existing `-shm` read marks may change;
- `-wal` with frames and no `-shm`: refused, `truncated_by: wal_needs_index`;
- a rollback `-journal`: refused, `truncated_by: hot_journal`;
- SQLite busy/locked while reading: `truncated_by: database_in_use`.

A refused board is `not_measured` with coverage `could_not_verify`. Nothing is
created beside a database. Credential paths and symlinked DB/ancestors/sidecars
are rejected first. Tested: a writer-held WAL board is read with the file listing
unchanged except `-shm` bytes; a closed WAL board is read immutable; `-wal`
without `-shm`, a hot journal, a 0-byte `-wal` and a rollback-mode board create
nothing. Query-only and trusted-schema-off precede schema inspection; DB/WAL
identity is compared after measurement (change detection, not an atomic snapshot).

Discovery only visits the fixed main DB, named boards, one `_archived` level and
their logs. No config, board.json, memory, attachment, workspace content, credential,
subscription payload, session database or log content is opened. Reuse
`audit.policy.credential_path`, including the caller's declaration scope.

Sizes and symlinks: log sizes are `lstat` file sizes, not unique disk blocks. A
symlink anywhere on a measured path (database, its folders or sidecars, a log
entry, a workspace path) is never followed or measured: it is counted in
`limits.symlinks_skipped` and makes coverage `could_not_verify` (`symlink`).

Limits: 200,000 unique rows per table per DB, 50,000 links, 50,000 directory entries
globally, 10,000,000 SQL VM steps globally, 1,000,000 graph visits globally,
4096 workspace-path characters, 1,048,576 metadata characters, 10,000 JSON nodes per
metadata value, and 15 cooperative seconds through an injectable clock. Table-count
lookahead examines at most one extra row; several projections revisit the bounded
prefix. A SQLite builtin/OS call cannot be preempted mid-call. These are logical
row/work limits, not a physical disk-I/O or SQLite-native-memory cap. Partial
inventory survives interruption. Every cut increments `limits.cuts`; all affected
coverage is `could_not_verify`, never silently clean. No caches or temp files.

## Wiring sheet

Entry point:

```python
audit_kanban_residue(*, profile_path, db_path=None, reference_time=None,
                     home_path=None, clock=None) -> dict
```

The runner passes only `profile_path`: the shared default Hermes home (kanban
lives there, not in a named profile). The module reads no `config.yaml` and no
credential file. `db_path` (a renamed DB inside the root), `home_path` (maps the
original home prefix of an extracted copy) and `clock` are measurement/test hooks.
Do not pass `reference_time` in the runner: ages are then relative to each board's
newest event, so the raw section does not depend on when the audit runs.

Return value: exactly `kanban_residue` (the section), `findings`, `run_metrics`,
`status` (legacy `pass`/`fail`, ignored by `adapt_component_result`) and
`coverage`. `run_metrics` (`elapsed_seconds`, `reference_time_override`) is NOT
part of the deterministic section; `adapt_component_result` passes it through and
the caller stores it outside the digested report. Raw measurements are the same
for an unchanged home within budgets. The sealed section is unchanged only while
every kept path still resolves and no value overlaps a credential value read in
the same run; otherwise it holds tokens keyed per run, which differ between runs.
A test covers two clean runs with clocks days apart and no `hmac` token.

Top-level section keys: `status`, `coverage`, `boards`, `databases_found`,
`orphan_board_folders`, `logs`, `gc_ever_run`, `reference_clock`, `limits`,
`truncated_by`. `logs`: `count`, `bytes`, `largest_bytes`, `archived_count`,
`archived_bytes`, `older_than_gc_window`, `rotated_count`. `limits`:
`max_rows_per_table`, `max_links`, `max_entries`, `max_seconds`, `max_sql_steps`,
`max_graph_steps`, `max_metadata_chars`, `max_json_nodes`, `max_path_chars`,
`cuts`, `symlinks_skipped`.

Per-board keys: `board`, `path`, `archived_board`, `status`, `coverage`, `tasks`,
`comments`, `events`, `runs`, `links`, `tasks_by_status`, `runs_by_outcome`,
`archived_share`, `date_range` (two integers `YYYYMM`, earliest and latest month),
`authorship` (`tasks`, `comments` each with `agent`/`user`/`unclassified`,
`task_agent_share`, `task_user_share`, `task_unclassified_share`,
`comment_agent_share`, `comment_user_share`, `comment_unclassified_share`, `default_profile_runs`, `coverage`), `trees` (`links`, `roots`,
`deepest_chain`, `largest_tree`, `widest_fanout`, `cycles`), `retry_context`
(`retried_tasks`, `top_tasks`, `growth_tasks`, `growth_example`,
`first_worker_chars`, `latest_worker_chars`, `growth_ratio` each as `median`/`p90`/`max`,
`historical_body_verified`, `complete_prompt_measured`; each task entry has `runs`,
`first_worker_chars`, `latest_worker_chars`, `first_run_body_edited_later`,
`first_uncapped_chars`, `latest_uncapped_chars`, `current_uncapped_chars`,
`growth_ratio`; no task ID), `loops` (`four_runs_without_completion`,
`repeated_block_threshold`, `repeated_block_nonzero`, `max_block_recurrences`,
`never_run`, `never_run_older_than_seven_days`, `open_inactive_over_fourteen_days`),
`events_older_than_gc_window`, `gc_eligible_events`, `heartbeat_events`,
`heartbeat_share`, `machine_binding` (`bodies_with_home_paths`,
`body_home_path_share`, `comments_with_home_paths`, `comment_home_path_share`,
`workspaces_inside_home`, `workspaces_in_kanban_scratch_root`,
`workspace_folders_existing`, `tasks_linked_to_project`), `text_volume` (`bodies`,
`comments`, `run_summaries`, `run_errors`, `run_metadata`), `logs`.

Closed string values:
- status: `completed`, `not_measured`, `not_present`.
- coverage / gc_ever_run: `verified`, `could_not_verify`.
- reference_clock: `injected`, `newest_event`.
- board: `default`, `named_board` (an archived board is `named_board` with
  `archived_board: true`).
- author classes (keys): `agent`, `user`, `unclassified`.
- task statuses (keys of `tasks_by_status`): `triage`, `todo`, `scheduled`, `ready`,
  `running`, `blocked`, `review`, `done`, `archived`, `unclassified`.
- run outcomes (keys of `runs_by_outcome`): `completed`, `blocked`, `crashed`,
  `timed_out`, `spawn_failed`, `gave_up`, `reclaimed`, `scheduled`, `released`,
  `failed`, `active`, `unclassified`.
- classification: `info`, `review_suggested`; finding identity `kanban`; finding
  source label `kanban.db` (only for `could_not_verify`).
- truncated_by: `authorship_unclassified`, `credential_path`, `dangling_links`, `database_changed`, `database_in_use`, `database_unreadable`, `directory_entries`, `graph_cycle`, `graph_steps`, `hot_journal`, `invalid_board_name`, `invalid_task_id`, `invalid_values`, `links`, `metadata_chars`, `metadata_invalid`, `metadata_nodes`, `metadata_normalization`, `outside_profile`, `path_chars`, `schema_unsupported`, `sql_steps`, `symlink`, `table_rows`, `time_budget`, `unreadable`, `wal_needs_index`.

The only other strings are kept absolute paths: `boards[].path` is the absolute
path of the board database that was opened (`<home>/kanban.db`,
`<home>/kanban/boards/<slug>/kanban.db` or
`<home>/kanban/boards/_archived/<slug>-<epoch>/kanban.db`), and board findings use
the same path in `source_paths`; `orphan_board_folders` uses `<home>/kanban/boards`.
The report serializer keeps these paths only because they are declared path
fields, and only when the path resolves and exists; it stores the resolved path.
A path or label that overlaps a credential value read in the same run is sealed
as a `credential_overlap` token, even when it equals an ordinary word. Any other
free string would become a per-run token, so board slugs, task IDs,
workspace folder names, titles, authors, sessions and source prose are never output.

### Rules, classifications and exact consequences

All IDs are prefixed `kanban_residue.`. Each consequence is one fixed sentence
(module constant `CONSEQUENCES`); the measured numbers are in the finding's flat
`evidence` (numbers and booleans only).

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

- **agent_authored_board**: “At least 80% of a board's tasks, on a board of 20 or more tasks, carry an agent-side author marker (worker, decomposer or a profile that ran tasks); the marker names the writing surface, not who asked for the work, and work done through the default chat profile counts as user-side.”
- **archived_never_collected**: “Archived tasks still keep their logs and all their rows: more than 1,000,000 bytes of archived-task logs, or a board at least 80% archived with events more than 30 days older than its newest event; the audit cannot tell whether clean-up was ever run.”
- **blocked_loops**: “At least one task has four or more runs with no completed run or reached Hermes's repeated-block limit of 2; these are stored records of past attempts, not a current fault, and do not show whether another attempt would succeed.”
- **could_not_verify**: “Some kanban measurements could not be verified within the supported schema and read budgets; missing coverage is not a clean result.”
- **heartbeat_bloat**: “More than half of a board's stored events, on a board of 500 or more events, are worker heartbeats; this counts retained rows, not whether the work made progress.”
- **machine_paths_in_tasks**: “More than half of a board's task bodies or of its comments contain a home-style absolute path marker; this counts text markers, not whether those paths exist on this machine.”
- **never_run_backlog**: “More than 10% of a board's tasks have no recorded run and were created more than seven days before the reference time; this counts stored rows, not why they never ran.”
- **orphan_board_folders**: “One or more board folders hold board metadata but no database; the audit does not tell how they came to be that way.”
- **retry_context_growth**: “Rebuilt from text stored today, a retried task would hand its latest worker more characters of its own body, comments and earlier attempts than at its first run, above the review limit of 20,000 characters or three times the first-run figure; Hermes caps each item but not the total. The first-run figure uses today's body and is an estimate when the body was edited after that run. This is a reconstruction from stored rows, not a recording of any prompt, and it describes left-over data, not a current fault.”
- **workspaces_inside_home**: “Five or more tasks store a workspace path inside the Hermes home but outside Hermes's own kanban workspaces folder; this counts stored paths, not files that are safe to delete.”
