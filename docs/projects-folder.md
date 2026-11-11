# Projects folder (`projects_root`)

Defuzz never guesses a folder silently and never creates a projects folder when
the plugin is installed, imported, or registered. There is no fixed default such as
`~/Projects`: the folder comes from your first-run choice, a saved setting, an
environment variable, or `--root`.

## Choosing your projects folder

The first time `hermes defuzz new` creates a project in an interactive terminal (when
neither `plugins.entries.defuzz.settings.projects_root` nor
`HERMES_PROJECTS_ROOT` is set and `--root` is not passed), Defuzz asks once:

```text
Choose the folder where Defuzz creates new projects (only new projects go here; nothing else on your machine is touched, and the folder is created when you create your first project) [/home/user/Tools]:
```

- Press **Enter** to accept `/home/user/Tools`, or type another folder path
  (full path, `~/...`, or a relative path, which is resolved against your
  current directory and shown back before saving).
- Your choice is saved as a normalized full path in the active profile's
  `plugins.entries.defuzz.settings.projects_root` and is not asked again.
- Saving the setting does not create the folder on disk; the folder is created
  only when you actually create a project (`hermes defuzz new --template ID ... --yes`).

When no terminal is attached (an agent tool call, `/defuzz` slash command,
pipe, or CI job) and no folder has been chosen yet, Defuzz stops immediately
without guessing or blocking and prints the command to run in your own terminal.

## Viewing or changing the folder

```bash
hermes defuzz folder               # show current folder and where it comes from
hermes defuzz folder --json        # same information as JSON
hermes defuzz folder set ~/Tools   # save a new folder (interactive terminal only)
```

Changing `projects_root` never moves existing projects; they stay where they
are, and only future projects are created in the new folder.

## Resolution order

1. `--root <folder>` (or `--dest-root <folder>`) on `hermes defuzz new` —
   one-command override, never saved.
2. `plugins.entries.defuzz.settings.projects_root` in the active Hermes
   profile's `config.yaml`.
3. `HERMES_PROJECTS_ROOT` environment variable — kept as a script/CI override
   and for existing shell setups.
4. Not chosen yet — prompts once in an interactive terminal, or exits non-zero
   with instructions in non-interactive runs.

## Validation rules

Every candidate folder is checked without creating files or directories:

- Must be a full path after `~` expansion (relative paths are accepted only
  when typed interactively in the terminal or passed via `--root`; relative
  values in `config.yaml` or `HERMES_PROJECTS_ROOT` are refused).
- Cannot be `/`, your home folder itself, or a folder containing your home
  folder.
- Cannot be inside a Hermes home (active profile or default `~/.hermes`,
  following symlinks).
- Cannot be inside a system folder (`/bin`, `/boot`, `/dev`, `/etc`, `/lib`,
  `/lib32`, `/lib64`, `/libx32`, `/opt`, `/proc`, `/run`, `/sbin`, `/srv`,
  `/sys`, `/usr`), and cannot be exactly `/tmp` or `/var/tmp`.
- Cannot be a symbolic link root or an existing regular file.
- Cannot be an existing project or inside one (checked with `structure_check`'s
  project markers); a parent folder holding separate projects side by side is
  allowed.
- If `HOME` is empty or unset, Defuzz uses the account's home folder from the
  system user database; if that is also unavailable it stops with "Cannot find
  your home folder" instead of treating `/` as home.
- Its target directory (if already present) or nearest existing parent directory
  must be writable. Spaces and Unicode names are supported.

## In the desktop app

When you start a new project and no projects folder has been chosen yet, the
desktop app asks once, before anything is created:

```text
Where should your projects go?
```

The suggestion is the same default, a folder named `Tools` in your home folder
(`/home/user/Tools`). You can keep that suggestion or type another full path.
Defuzz checks the path and, if it is allowed, saves it through Hermes plugin
settings (`plugins.entries.defuzz.settings.projects_root`). Nothing else on
your machine is touched, and the folder is created only when you create your
first project.

If a folder is already saved, or `HERMES_PROJECTS_ROOT` is set, the new-project
dialog shows that folder and does not ask again. You can change it there.
Existing projects stay where they are; only new projects are created in the
new folder.

If the app cannot read the projects folder, it does not guess one and does not
create a project.
