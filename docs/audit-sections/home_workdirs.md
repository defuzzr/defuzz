# Home workdirs (`report.home_workdirs`)

Measures work folders, nested homes and large files inside the Hermes home from names and metadata.
Executable probes use `open_checked` (read-only, no-follow, nonblocking), bounded by `MAX_MAGIC_READS` in `audit/home_workdirs.py`.
Sizes are file sizes, not unique disk blocks. Symlinks are never followed.
Folder names and sizes do not establish ownership or whether files are still used.

Within budgets, unchanged inputs give unchanged raw measurements. Budget cuts retain partial results with `could_not_verify` coverage.
Read scope: [audit-scope.md](../audit-scope.md). Bounds are the `MAX_*` constants in `audit/home_workdirs.py`.

## Findings

| Rule id | Class | Fires when | Consequence |
|---|---|---|---|
| `home_workdirs.work_folders_in_home` | `review_suggested` | `not_hermes_bytes` > `WORK_FOLDERS_BYTES_THRESHOLD` or share > `WORK_FOLDERS_SHARE_THRESHOLD` | Top-level folders whose names the Hermes source never creates hold more than the size or share threshold of this home's bytes; this is a measurement of names, sizes and file counts and does not show who created them or whether they are still needed. |
| `home_workdirs.oversized_hermes_folders` | `review_suggested` | a Hermes folder’s `other_kind_bytes` > `HERMES_FOLDER_OTHER_BYTES_THRESHOLD` | Folders that Hermes creates (plans, tools, venvs) hold more than the threshold in files that are not the kind Hermes writes there; this measures file names and sizes only and does not show who wrote them or whether they are still needed. |
| `home_workdirs.huge_files` | `review_suggested` | any huge file (Hermes databases excluded) | Files other than Hermes's own databases are at or above the single-file size threshold; this records size and file type only and does not show who wrote them or whether they are still needed. |
| `home_workdirs.working_trees_in_home` | `info` | any venv, source tree, node_modules, .git or archive beside an extracted copy | Virtual environments, copied source trees, dependency folders, repositories or archives beside an extracted copy were found by marker names outside Hermes's own dependency folders; this counts them and their bytes and does not show whether anything still uses them. |
| `home_workdirs.nested_hermes_homes` | `review_suggested` | `config_with_marker` > 0 | Directories below the home root, outside named profiles, hold config.yaml together with a Hermes home marker name; this counts them by file name only and does not show how they were made or whether Hermes uses them. |
| `home_workdirs.could_not_verify` | `info` | any cap hit or unreadable part | Home workdir inspection hit a safety cap or could not read part of the home; incomplete traversal is reported as could_not_verify rather than clean. |

## Output reference

Keys and labels from `audit/wiring/home_workdirs.json`; classifications and consequence text are checked against the module by its tests.

**Keys:** `archive_bytes`, `archive_count`, `archives_beside_extracted_bytes`, `archives_beside_extracted_count`, `bytes`, `config_only`, `count`, `coverage`, `cuts`, `entries_walked`, `executable_bytes`, `executable_count`, `expectation`, `expected_kind_bytes`, `extension_class`, `file_count`, `files`, `folder_count`, `git_dir_bytes`, `git_dir_count`, `hermes_database_bytes`, `hermes_databases`, `hermes_folder_other_kind_bytes`, `hermes_folders_holding_work_output`, `hermes_folders_other_kind_bytes`, `hermes_named_bytes`, `hermes_named_share`, `hermes_named_top_level`, `home_workdirs`, `huge_file_bytes`, `huge_file_count`, `huge_files`, `huge_files_bytes`, `huge_files_share`, `kind`, `largest_file_bytes`, `layout_marker_present`, `limits`, `magic_reads`, `max_depth`, `max_entries`, `max_magic_reads`, `max_seconds`, `name`, `nested_hermes_home_count`, `nested_hermes_homes`, `newest_year_month`, `node_modules_bytes`, `node_modules_count`, `not_hermes_count`, `not_hermes_folders`, `not_hermes_share`, `oldest_year_month`, `other_kind_files`, `path`, `path_withheld`, `reason`, `size_bytes`, `source_tree_bytes`, `source_tree_count`, `status`, `symlinks_skipped`, `threshold_bytes`, `threshold_share`, `thresholds`, `total_home_bytes`, `totals`, `truncated_by`, `virtualenv_bytes`, `virtualenv_count`, `work_folders_bytes`, `work_folders_share`, `working_trees`.

**Run metrics:** `elapsed_ms`.

**Labels:** `archive`, `completed`, `credential_named`, `database`, `directory`, `executable_file`, `invalid_home_root`, `io_error`, `long_name`, `lstat_error`, `markdown_plans_at_folder_root`, `media`, `missing_home`, `not_measured`, `other`, `pass`, `plans`, `pm_tool_store_with_facts_json`, `regular`, `scandir_error`, `special`, `symlink`, `text_like`, `tools`, `undecodable_name`, `unreadable_home`, `venvs`, `verified`, `virtualenvs_with_pyvenv_cfg`, `warn`.

**Path fields:** `affected_identities`.
