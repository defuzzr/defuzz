# Home workdirs (`report.home_workdirs`)

`audit/home_workdirs.py` measures work output, copied trees, huge files and nested home copies stored inside the Hermes home (`~/.hermes` or a profile home). Everything inside the home is walked by backups, scans and sync unless excluded. Entry point: `audit_home_workdirs(profile_path, *, huge_file_threshold_bytes, work_folders_bytes_threshold, work_folders_share_threshold, hermes_folder_other_bytes_threshold, max_entries, max_depth, max_magic_reads, max_seconds, clock) -> dict`. The caller passes only `profile_path` (the profile directory); the module reads no `config.yaml` key and opens no credential file. The wiring sheet for the report is `audit/wiring/home_workdirs.json`.

Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound. Symlinks are never followed: each one counts in `symlinks_skipped`, a top-level symlink is listed with kind `symlink`, size 0 and its path withheld, and nothing behind a link is measured.

## Envelope

`audit_home_workdirs` returns exactly `home_workdirs` (the section below), `findings`, `status` (`pass`), `coverage` (`verified` or `could_not_verify`) and `run_metrics`. `run_metrics` holds `elapsed_ms` (from the injected clock), the only run-dependent value; it is stored outside the fingerprinted report. The section and findings hold no clock-derived value: two runs on an unchanged home give the same raw section and findings. The one exception is inherent to the time cap: when `max_seconds` stops the walk, the partial numbers depend on run speed, and the section then says `coverage: could_not_verify`, `truncated_by: max_seconds`.

## What it measures

1. **Not-Hermes top-level folders (`not_hermes_folders`)**: top-level entries whose names the Hermes source never creates. A name counts as Hermes-named when it is in `HERMES_OWNED_TOP_LEVEL` (cited file:line per group in the module), in `WELL_KNOWN_PLUGIN_RUNTIME_TOP_LEVEL` (which includes `KNOWN_THIRD_PARTY_PLUGIN_TOP_LEVEL`, state folders of community plugins from the upstream Hermes plugin catalog), or matches `_HERMES_OWNED_ROOT_PATTERNS` (root `.bak`/`.corrupt`/`.lock` and database sidecars). Each entry: `path` (absolute path of the entry under the resolved home, or `null`), `path_withheld` (`null`, or why the path is not shown: `undecodable_name`, `credential_named`, `long_name` for a name over 40 characters, `symlink`), `kind` (`directory`, `regular`, `symlink`, `special`), recursive `size_bytes`, `file_count`, `oldest_year_month`/`newest_year_month` (UTC year and month of the oldest and newest file time as the integer `YYYYMM`, for example `202608`, or `null`). Empty unknown directories are left out. Folders made by backup tools (for example `dbtmp/`) are reported like any other not-Hermes name.
2. **Hermes folders holding work output (`hermes_folders_holding_work_output`)**: `plans/`, `tools/` and `venvs/` are folders Hermes creates, so they are never called "not Hermes". For each, the module counts bytes of the kind Hermes puts there (`expected_kind_bytes`) and everything else (`other_kind_bytes`, `other_kind_files`), and lists the folder when `other_kind_bytes` exceeds the threshold. Fields: `name` (`plans`, `tools`, `venvs`), `expectation`, `layout_marker_present`, `size_bytes`, `file_count`, `expected_kind_bytes`, `other_kind_bytes`, `other_kind_files`, `oldest_year_month`, `newest_year_month`.
   - `plans/` (`markdown_plans_at_folder_root`): created at profile bootstrap (`hermes_cli/profiles.py:40`); the only Hermes writer found is `/plan`, which saves one `YYYY-MM-DD_HHMMSS-<slug>.md` (`agent/plan_prompt.py:21`, `hermes_cli/commands.py:166`). Expected kind: `*.md` directly in `plans/`. Marker: any expected-kind file. This expectation is stricter than the Hermes source strictly confirms: the source shows only that one writer, not that nothing else may write there.
   - `tools/` (`pm_tool_store_with_facts_json`): the pm store of downloaded tool generations (`hermes_cli/home_data_layout.py:5-6`, `pm/paths.py:71`) with `facts.json` at its root (`pm/paths.py:63`, `hermes_cli/gateway.py:3108`). With `tools/facts.json` every byte counts as expected kind (the check cannot tell pm generations from other content); without it nothing does. The branch with `facts.json` is tested on synthetic data.
   - `venvs/` (`virtualenvs_with_pyvenv_cfg`): installer venvs `$HERMES_HOME/venvs/<name>` (`hermes_constants.py:1373-1374`). Expected kind: files in `venvs/<name>/` holding `pyvenv.cfg`.
3. **Hermes databases (`hermes_databases`: `count`, `bytes`, `files`: a list of `path`, `path_withheld`, `size_bytes`, at most 50, largest first)**: Hermes's own SQLite stores and their `-wal`/`-shm`/`-journal` sidecars at the home root or `profiles/<name>/`: `state.db`, `hermes_state.db`, `projects.db`, `response_store.db`, `memory_store.db`, `verification_evidence.db`, `kanban.db`, `shared-state.db`, `runs_idempotency.db`, `cron/executions.db`, `cron/deliveries.db`, `cron/notepad.db`, `gateway/discord_message_recovery.db`, `kanban/boards/<slug>/kanban.db`, `kanban/boards/_archived/<slug>/kanban.db` (citations in the module). Size only; never opened; never in `huge_files`. A database-named file elsewhere (for example inside `plans/`) is an ordinary file.
4. **Huge files (`huge_files`)**: regular files other than Hermes databases with `size_bytes >= 50 MiB`; `path` (absolute path of the file, or of its second-level folder when it lies deeper: never more than two components below the home) with `path_withheld` as above (a component over 40 characters withholds the path rather than truncating it), `size_bytes`, `extension_class` (`text_like`, `archive`, `media`, `executable_file`, `database`, `other`), `hermes_named_top_level` (boolean).
5. **Working trees (`working_trees`)**: `virtualenv_count`/`virtualenv_bytes` (`pyvenv.cfg`), `source_tree_count`/`source_tree_bytes` (outermost `pyproject.toml`/`package.json` under a not-Hermes folder, `tmp/` or `plans/`), `node_modules_count`/`node_modules_bytes`, `git_dir_count`/`git_dir_bytes`, `archive_count`/`archive_bytes` (`.zip .tar .tar.gz .tgz .tar.xz .7z`), `archives_beside_extracted_count`/`archives_beside_extracted_bytes`, `executable_count`/`executable_bytes` (4-byte ELF / Mach-O / `MZ` magic). Markers are not counted inside Hermes's own dependency and checkout folders (`HERMES_DEPENDENCY_TOP_LEVEL`: `installs`, `cache`, `hermes-agent`, `.worktrees`, `bin`, `node_modules`, `.hermes-runtime`, `node`, `runtimes`, `plugins`, `skills`, `desktop-plugins`, `venvs`, and `tools` when it holds `facts.json`); archives and executables are still counted everywhere.
6. **Nested Hermes homes (`nested_hermes_homes`: `count`, `config_with_marker`, `config_only`)**: one definition: a directory below the root that holds a regular file `config.yaml`, excluding named profiles `profiles/<name>`, plugin packages (`plugins/...` with `plugin.yaml`), and Hermes's own copy folders (`state-snapshots`, `backups`, `checkpoints`, also under `profiles/<name>/`, and `profiles/.deleted`). It is `config_with_marker` when it also holds one of `skills`, `state.db`, `auth.json`, `.env`, `SOUL.md`, `profile.yaml`, `profiles` (Hermes's own markers, `hermes_constants.py:320,399`), else `config_only`. `count == config_with_marker`; only that raises the finding.
7. **Totals (`totals`)**: `total_home_bytes`, `hermes_named_bytes`, `not_hermes_bytes`, `hermes_folders_other_kind_bytes` (all three folders), `hermes_database_bytes`, `huge_files_bytes`, `hermes_named_share`, `not_hermes_share`, `huge_files_share`.

Other keys: `status` (`completed`, `not_measured`), `coverage` (`verified`, `could_not_verify`), `reason` (`null`, `missing_home`, `unreadable_home`, `invalid_home_root`), `truncated_by` (`null`, `max_entries`, `max_depth`, `max_magic_reads`, `max_seconds`, `scandir_error`, `lstat_error`), `symlinks_skipped`, `limits` (`max_entries`, `max_depth`, `max_magic_reads`, `max_seconds`, `entries_walked`, `magic_reads`, `cuts`), `thresholds` (`huge_file_bytes`, `work_folders_bytes`, `work_folders_share`, `hermes_folder_other_kind_bytes`).

## Findings

Rule ids are `home_workdirs.<rule>`. Each consequence is one fixed sentence; the numbers are in the finding's `evidence`. The legacy `severity` field is `warn` for `review_suggested` and `info` for `info`.

| Rule id | Class | Fires when | Consequence |
|---|---|---|---|
| `home_workdirs.work_folders_in_home` | `review_suggested` | `not_hermes_bytes` > 100 MiB or share > 20% | Top-level folders whose names the Hermes source never creates hold more than the size or share threshold of this home's bytes; this is a measurement of names, sizes and file counts and does not show who created them or whether they are still needed. |
| `home_workdirs.oversized_hermes_folders` | `review_suggested` | a Hermes folder's `other_kind_bytes` > 100 MiB | Folders that Hermes creates (plans, tools, venvs) hold more than the threshold in files that are not the kind Hermes writes there; this measures file names and sizes only and does not show who wrote them or whether they are still needed. |
| `home_workdirs.huge_files` | `review_suggested` | any huge file (Hermes databases excluded) | Files other than Hermes's own databases are at or above the single-file size threshold; this records size and file type only and does not show who wrote them or whether they are still needed. |
| `home_workdirs.working_trees_in_home` | `info` | any venv, source tree, node_modules, .git or archive beside an extracted copy | Virtual environments, copied source trees, dependency folders, repositories or archives beside an extracted copy were found by marker names outside Hermes's own dependency folders; this counts them and their bytes and does not show whether anything still uses them. |
| `home_workdirs.nested_hermes_homes` | `review_suggested` | `config_with_marker` > 0 | Directories below the home root, outside named profiles, hold config.yaml together with a Hermes home marker name; this counts them by file name only and does not show how they were made or whether Hermes uses them. |
| `home_workdirs.could_not_verify` | `info` | any cap hit or unreadable part | Home workdir inspection hit a safety cap or could not read part of the home; incomplete traversal is reported as could_not_verify rather than clean. |

Evidence per rule:

- `work_folders_in_home`: `not_hermes_count`, `not_hermes_bytes`, `total_home_bytes`, `not_hermes_share`, `threshold_bytes`, `threshold_share`.
- `oversized_hermes_folders`: `folder_count`, `other_kind_bytes`, `other_kind_files`, `threshold_bytes`.
- `huge_files`: `huge_file_count`, `huge_files_bytes`, `largest_file_bytes`, `threshold_bytes`.
- `working_trees_in_home`: the fourteen `working_trees` counts and byte totals.
- `nested_hermes_homes`: `nested_hermes_home_count`, `config_with_marker`, `config_only`.
- `could_not_verify`: `cuts` with `truncated_by` (a value above, or the fallback `io_error`, which the current code never reaches), or `reason` and `cuts` when the home was not measured.

Each finding's `affected_identities` is the absolute profile directory; `source_paths` is that directory, or `<profile>/<name>` for the first 10 not-Hermes folders and for the listed Hermes folders.

## Free strings and sealing

The report stores the section through the closed-vocabulary serializer. It keeps vocabulary labels, and paths in declared path fields that resolve to an existing item (stored as the resolved path); any other string becomes a token keyed per run. A label or path that overlaps a credential value read in the same run is sealed as a `credential_overlap` token, even when it equals an ordinary word. So the section and its findings carry no free name: numbers, booleans and the labels above, plus absolute paths under the resolved home (`path`, finding `source_paths` and `affected_identities`). Raw measurements are the same for an unchanged home within budgets. The sealed output is unchanged only while every kept path still resolves and no value overlaps a credential value read in the same run; otherwise it holds tokens keyed per run, which differ between runs. A name that is undecodable, credential-looking, longer than 40 characters, or a symlink is not shown: `path` is `null` and `path_withheld` says why. When the home was not measured, findings carry no identity or path.

## Thresholds

- `WORK_FOLDERS_BYTES_THRESHOLD` 100 MiB, `WORK_FOLDERS_SHARE_THRESHOLD` 0.20: content that is not Hermes's own kind (work output, project and notes folders, copied trees).
- `HERMES_FOLDER_OTHER_BYTES_THRESHOLD` 100 MiB: content of another kind inside a Hermes folder (for example `plans/` beyond its root `.md` plans, or `tools/` without `facts.json`).
- `HUGE_FILE_THRESHOLD_BYTES` 50 MiB: single large files; `state.db` and other Hermes databases are counted under `hermes_databases` instead.
- Caps `MAX_ENTRIES` 400,000, `MAX_DEPTH` 40, `MAX_SECONDS` 20 (injectable clock), `MAX_MAGIC_READS` 10,000: a cap stops the walk, keeps partial numbers, increments `limits.cuts`, sets `truncated_by` and `coverage: could_not_verify`.

## What it cannot tell

Who created a folder or file (agent, plugin or user), whether anything still uses it, or whether a `tools/` store with `facts.json` holds only pm content.

## Do-not-flag list

A fresh home; `cache/`; `bin/` with a few tool binaries; named profiles; rotated logs; empty unknown folders; large `state.db` and other Hermes databases; markdown plans in `plans/`; a pm store in `tools/` with `facts.json`; venvs in `venvs/<name>`; `installs/` environments; the `hermes-agent` checkout; Hermes snapshots and backups holding `config.yaml`.

## Read policy

- **Stat only** (`os.scandir`, with entries inspected by `os.lstat` or `entry.stat(follow_symlinks=False)`): traversal, sizes, months, all marker names. Symlinks are counted in `symlinks_skipped`, never followed.
- **4-byte magic read** (`os.open` with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, regular files of 4+ bytes whose name or mode suggests a binary), up to `MAX_MAGIC_READS`.
- **Never opened**: anything `audit.policy.credential_path` matches (`.env*`, `auth.json`, `*.pem`, `*.key`, `id_*`, `mcp-tokens/`, `pairing/`, `vault/`, ...), names containing `token`, `secret`, `credential`, `password` or `passwd`, every database, symlinks, FIFOs, sockets and devices.
- A `profile_path` that is not a path (None, a number, a NUL byte) gives `not_measured` / `invalid_home_root`. Undecodable bytes in names are shown as U+FFFD so the output is always valid UTF-8.
- Output paths: absolute, under the resolved home, at most two components below it (Hermes database paths are shown in full); finding `affected_identities`/`source_paths` hold the profile root and `root/<top-level name>`.
