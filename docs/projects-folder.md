# Projects folder (`projects_root`)

## Choosing your projects folder

When a selected project needs a folder and none is configured, an interactive terminal asks you to choose one.
The prompt suggests `~/Tools`; you can enter another path.
The choice is saved when chosen, including during a preview, in the active Hermes profile's `config.yaml`
under `plugins.entries.defuzz.settings.projects_root`.
Saving stores a normalized full path; project creation creates the folder.
Non-interactive runs that need an unset folder return instructions instead of prompting.

## Viewing or changing the folder

```sh
hermes defuzz folder
hermes defuzz folder --json
hermes defuzz folder set ~/Tools
```

`folder set` requires an interactive terminal. Changes affect future projects; existing projects stay put.

## Resolution order

1. `--root <folder>` (or `--dest-root <folder>`) on `hermes defuzz new`, for that command only.
2. The saved `projects_root` setting.
3. `HERMES_PROJECTS_ROOT`.
4. An interactive choice, or an error with instructions.

## Validation rules

`workspace_root.py` checks paths and writability before use.
Relative paths are accepted from the terminal prompt or `--root`; saved and environment paths must be absolute after `~` expansion.
Home folders and their ancestors, Hermes data folders, protected system folders and temporary-folder roots are refused.
Symbolic-link roots, files, existing projects and folders inside projects are refused.
A parent holding separate projects is allowed.

## In the desktop app

The new-project dialog asks for an unset folder and lets you change a configured one.
It validates and saves through Hermes plugin settings. If saving is unavailable, use `hermes defuzz folder set` in a terminal.
