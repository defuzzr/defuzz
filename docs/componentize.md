# Optional componentize survey

[defuzz-componentize](https://github.com/defuzzr/defuzz-componentize) is an optional companion plugin.
After adoption, Defuzz can run `survey <copy> --json` to inventory Python code for review.
A valid result is saved to `.adopt/componentize-survey.json`; `AGENTS.md` records proposed splits.
Both are included in the adoption commit. Survey failures print a notice and adoption continues.
The optional survey path never invokes `begin`, attest or finish.
Kit creation is separate: `kit_scaffold.py` calls `kit apply` and `kit check`.
Desktop cancellation before placement also stops the running kit check's process group.

## UI contract

### For plugin developers

`componentize_settings.py` provides `load()`, `save(settings)` and `status(project_root=None)`.
Preferences live in the active profile's plugin data, in `componentize-settings.json`.
`save()` validates and replaces preferences, filling omitted keys with defaults.
Defaults and validation rules live in `componentize_settings.py`.
`enabled_on_adopt` controls adoption surveys, including detection.
`run_survey_on_new` runs the optional survey after successful acceptance,
independent of enabled_on_adopt. `scaffolder.py` records it in `survey_commit`;
optional failures leave project creation successful.

`cli_path_override` selects an absolute executable file outside the project.
Its failed probe reports absent or timeout, without fallback.
Otherwise discovery probes `hermes componentize --version`, then `componentize` on PATH.
Hermes must return the companion's version format. A standalone CLI without version support
may remain detected with a null version if no probe timed out and the shared deadline permits it.
Discovery excludes relative PATH entries and executables inside the project.
Probe deadlines and output limits live in `componentize_bridge.py`; commands run as argument lists.

`status()` probes availability and reads an existing survey, rather than starting one.
It reports detection, version, source and a survey summary; unsafe or invalid surveys yield no summary.
The `componentize.survey/1` JSON response is an external bridge contract.

## Delivered dashboard routes

`dashboard/routes/componentize_routes.py` exposes these routes under `/api/plugins/defuzz/componentize`:
- GET and PUT `/settings` read and replace preferences.
- GET `/status` accepts an optional `project_root` for a registered project in the active profile.

Host authentication and origin checks apply. Invalid input or failed saves return errors.

## Delivered Python template support

`templates/python-golden/tmpl_prefix` includes `componentize/spec.example.json`,
`COMPONENTS.md` and `xtask componentize-gate`.
These are template helpers; the survey runs through the external companion.
