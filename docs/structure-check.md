# Structure check: one project, or projects inside a project?

`hermes defuzz check [PATH]` checks for undeclared project roots inside a folder.
PATH defaults to the current folder. Add `--json` for the full result.
The implementation is `structure_check.py`.

## What it checks

The check lists directory entries and reads root workspace declarations.
Project markers include manifests and `.git`; some build files count only at PATH.
An `index.html` beside a recognized asset folder can also mark a project.
Names such as `public` exclude this HTML heuristic in nested folders, not at PATH.
Marker and exclusion definitions live in `structure_check.py`.

Workspace declarations identify members by matching project roots, not arbitrary
folders. Supported declarations include package workspaces, Cargo and uv members,
Go workspaces, Git submodules, and `.adopt/rules.json` `declared_dirs`.
Exclusion patterns apply. Wildcards stop at intervening project roots unless their
literal prefix explicitly reaches inside. Declared submodules are skipped.

Undeclared roots normally produce `nested_project`. Common embedded layouts can
instead produce informational `embedded_subproject` findings. Independent Git
roots, leftover-copy names, scratch locations and crowded layouts can override
that classification. An inner `.git` outside a declared submodule is reported
as `git_inside_git`, including in declared workspace members.

## A folder of separate projects

When PATH has no marker or member declaration but contains project roots, the
result is `not_a_project` with a `folder_of_projects` finding. Each discovered
project is checked with its own declarations, subject to the remaining budgets
and project cap. Results include PATH-relative findings and `top_level_projects`.

`no_project_marker` means the checked folder has no marker and was not classified
as a folder of separate projects; it does not rule out every inner project.

## Limits

The check opens declaration files read-only and limits their size.
It skips symbolic links, dependency/build folders and detected Hermes homes.
It refuses a home or Hermes-home root. The walk has depth, entry and time budgets;
these are defaults in the code, not a hard wall-clock deadline.

Depth truncation adds an informational finding. Unreadable declarations, exhausted
entry/time budgets and unchecked projects add `could_not_verify` findings.
A folder-of-projects or nesting status can take precedence over incomplete work,
so read the findings as well as `status`. Rerun inside a smaller folder if needed.

## Output

Text gives a verdict, findings and next steps. JSON includes roots, declarations,
findings, limits and skipped entries. Paths are relative to PATH; displayed control
characters are escaped. Completed walks of unchanged folders are repeatable.

Exit codes: `0` for one project; `2` for `not_a_project`; otherwise `1` for blocking
findings, or `2` when verification is incomplete. Informational findings alone do
not change the exit code.

Declare intentional members in the root workspace configuration. For separate
projects, copy them beside the outer project, verify the copies, then remove the
originals when you are ready.
