# Optional componentize survey

After applying the copy layout, Defuzz tries `hermes componentize` (a successful
`--version` probe), then the `componentize` executable on PATH. It does not assume a
vendored executable or a developer's local toolkit checkout exists. If unavailable, it
prints a notice and adoption continues successfully.

A successful `survey <copy> --json` with a `componentize.survey/1` envelope is
saved as `.adopt/componentize-survey.json`. AGENTS.md records the proposed split
count and asks for review. Both are included in the adoption commit. Malformed,
failed or timed-out surveys and write failures print a notice and do not block adoption.
Survey stdout/stderr and stored survey reads are bounded to 1 MiB. Status uses
no-follow, nonblocking regular-file reads, rejects FIFOs and validates the survey
path against the project. Existing unsafe survey targets are refused. AGENTS.md
is written before publishing the survey, so its write failure cannot publish an
orphan survey. The optional line is skipped with a notice when it would exceed
`agents_md_max_lines`; generated AGENTS.md line endings are normalized to LF.

This is a Python inventory, not proof of purity or approval to extract. The
optional survey path never invokes `begin`, attest or finish. Creating a project
from a kit is separate: it explicitly calls the companion's `kit apply` and
`kit check` commands (see `componentize_bridge.kit_apply` and `kit_check`). When
the desktop app's Cancel stops a kit project before it is moved into place, the
running `kit check` is stopped too: with a cancel hook the companion runs in its
own process group, and the whole group is ended.

No vendored copy shipped: the checked-in `templates/` tree contains no componentize
entry point. The vendored fallback is therefore intentionally not implemented;
Defuzz never searches arbitrary project scripts or developer checkouts.

## UI contract

Import the plugin's pure-Python `componentize_settings` module:

- `load() -> dict`: active profile preferences; missing file returns defaults.
- `save(settings: dict) -> dict`: replace preferences, filling omitted keys with
  defaults (not a merge with the previous file). Validates before writing, uses a
  same-directory temporary file, fsync and atomic replace. Returns saved settings.
- `status(project_root: str | Path | None = None) -> dict`: probe CLI and optionally
  read the project's existing `.adopt/componentize-survey.json`; never runs survey.

Settings JSON (also the defaults):
```json
{"enabled_on_adopt": true, "run_survey_on_new": false, "cli_path_override": null}
```
Booleans must be actual JSON booleans. Override is null or a nonempty string with
no NUL; it is one absolute executable path, not a shell command or argument string.
At detection it must resolve to an executable regular file outside the project;
invalid overrides are rejected with a notice and no fallback. PATH discovery
excludes empty/current-directory entries and entries inside the project, and
resolves the selected executable to an absolute path before either invocation.
Unknown keys and invalid values raise `ValueError`. Corrupt stored settings also
raise `ValueError`; filesystem failures propagate as `OSError`. Adoption catches
these errors and skips the optional survey rather than ignoring user preferences.
Storage: `plugin_data_dir("defuzz") / "componentize-settings.json"` using the public
`plugins.plugin_storage` API, resolved on every call to follow profile switches.

Status JSON:
```json
{"detected": true, "version": "componentize 1.2", "source": "hermes", "last_survey": {"schema": "componentize.survey/1", "status": "ok", "path": "/project", "files": 4, "proposed_splits": 1, "findings": 0}}
```
`version` is trimmed CLI stdout or null, not a parsed semver. `source` is
`hermes|path|override|absent|timeout`; `timeout` means a `--version` probe exceeded its
deadline, so the CLI's presence is unknown (then `detected` is false).
Absent means `detected: false, version: null, source: "absent"`. `last_survey` is
null without a project or with a missing, unsafe, invalid or unreadable survey;
otherwise its three numeric fields are array counts, not the original arrays.
The summary can exist even when the CLI is absent. Status never modifies project
files. The `componentize.survey/1` envelope is an external bridge contract, not a
Defuzz-owned schema.

An override takes precedence and must pass `--version`; failure means absent,
not silent fallback. Otherwise probe `hermes componentize --version`; it counts only
if it prints one line `componentize <version>` (for example `componentize 0.2.0`),
anything else is treated like a failed probe. Then use
`componentize` on PATH (attempt `--version` for display; an older standalone CLI
without that flag remains detected with null version). Probes time out after 15s;
surveys after 60s. Commands use argv, never a shell. `enabled_on_adopt: false`
prevents even detection during adoption. `run_survey_on_new` runs the optional survey after successful acceptance,
independent of enabled_on_adopt (which still controls adoption only). The flag
defaults to false. `scaffolder.py:1707-1752` (called from `_accept_template` at line 2021) records successful survey outputs in a
separate commit (`survey_commit`); optional failures leave project creation successful.
See `tests/test_scaffolder.py:80-211` for the real bridge and commit contracts.

## Delivered dashboard routes

`dashboard/routes/componentize_routes.py:1-75` implements profile-scoped routes
under the Defuzz API prefix (full paths below). Host auth/origin guards apply;
synchronous handlers run blocking probes in the worker pool:

| Method | Path | Body/query | 200 response |
| --- | --- | --- | --- |
| GET | `/api/plugins/defuzz/componentize/settings` | none | `load()` settings object above |
| PUT | `/api/plugins/defuzz/componentize/settings` | settings JSON object above | `save(body)` settings object |
| GET | `/api/plugins/defuzz/componentize/status` | optional `project_root` query string | `status(project_root)` status object above |

Invalid input/settings return 400 `{"error":"message"}`. A PUT whose save fails
on a file or folder error (read-only folder, full disk) returns 400 with one plain
sentence asking to check folder permissions and free disk space, never the error
text or a path. Other storage failures return 500 with `componentize settings
unavailable` (or `componentize status unavailable` for status). A supplied project_root must match verified current-profile
registrations before it is read. PUT is executable-selection authorization and
retains the host's auth/origin protections. No route starts componentize jobs.

## Delivered Python template support

`templates/python-golden/tmpl_prefix` includes `componentize/spec.example.json`,
`COMPONENTS.md`, boundary documentation, and the optional Python
`xtask componentize-gate` command. Its implementation lives in
`tools/xtask/src/xtask/componentize.py`, wired by `tools/xtask/src/xtask/main.py`.
These are template helpers, not a vendored componentize executable; the external
survey bridge and explicit approval boundaries remain unchanged.
