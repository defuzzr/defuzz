# Structure check: one project, or projects inside a project?

`hermes defuzz check [PATH]` looks at a folder (default: the current folder) and says, in plain
words, whether it is **one project** or whether other project roots are hidden inside it. It exists
for the "26 projects in one folder" problem: a site folder that slowly collected many separate
projects, some with their own `.git`, so that a clone of the outer project silently loses work.

The code is `structure_check.py`; the function is `check_structure(path)`.

## What it checks

1. **Project markers.** Two lists (`FILE_MARKERS` / `ROOT_ONLY_MARKERS` in the code):
   - **Strong markers** make the checked folder *or any folder below it* a project root:
     `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `pubspec.yaml`, `pom.xml`,
     `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`,
     `composer.json`, `Gemfile`, `mix.exs`, `deno.json`, `Package.swift`, any `*.sln`, any
     `*.csproj`, any `*.xcodeproj` folder, and a `.git` entry (folder or file).
   - **Root-only markers** make only the checked folder a project; the same file in a
     sub-folder never marks a nested project (these files are common in ordinary
     sub-folders): `go.work`, `setup.py`, `requirements.txt`, `Pipfile`, `setup.cfg`,
     `manage.py`, `Makefile`, `CMakeLists.txt`.
   - `index.html` counts only when no manifest is present, the same folder also has an
     `assets`, `css`, `js`, `src`, `img`, `images`, `static`, `styles` or `scripts` folder, and the
     folder itself is not named `public`, `static`, `assets`, `www`, `templates`, `client` or
     `docs` (those usually hold a project's own web files).
   - A checked folder whose only marker is `.git` is a project (it is one git repository); the
     info finding `git_only_root` says so.
2. **Declarations at the root only.** Inner projects that the root declares are *members*, not
   problems:
   - `package.json` `workspaces` (list form, or object form with `packages`; `!pattern` excludes),
   - `pnpm-workspace.yaml` top-level `packages:` (block list or one-line `[...]` list; `!` excludes),
   - `Cargo.toml` `[workspace]` `members` and `exclude`,
   - `pyproject.toml` `[tool.uv.workspace]` `members` and `exclude` (a uv workspace reports each
     folder its `members` patterns match, minus `exclude`, as a declared member),
   - `go.work` `use ./dir` lines and `use ( ... )` blocks (exact paths),
   - `.gitmodules` `path = ...` lines (a declared submodule is a member and is not looked inside),
   - a Defuzz project's `.adopt/rules.json` `declared_dirs` (each `dir` is one exact member path).
   Patterns are matched per path segment: `apps/*` matches `apps/web` but never
   `apps/web/rogue`; `packages/**` matches any depth, except that a wildcard never reaches
   inside another project root (so `packages/ui/rogue` is still reported). A pattern whose
   fixed leading part already names a place inside a member does reach it on purpose:
   `ui/packages/*` declares `ui/packages/ink` even though `ui` is itself a member.
3. **Findings**, each with a one-sentence explanation and a next step:
   - `nested_project`: an undeclared project root below the root that looks like independent
     work placed inside this project (path, depth, markers).
   - `embedded_subproject` (information only): an undeclared project root that matches a
     well-known, legitimate layout (table below). It does not change the status or exit code.
   - `git_inside_git`: a `.git` below the root that is not a declared submodule. It may mean
     work that cloning the outer repository does not reproduce; inspect tracking and submodule
     configuration before moving or deleting anything. Reported even inside a declared member.
   - `root_is_home_or_agent_home`: the folder is the filesystem root (`/`), the home folder, a folder containing the home
     folder, or a Hermes home (`HERMES_HOME`, and `~/.hermes`) or a folder inside one.
     Nothing inside it is listed or read.
   - `root_is_symlink`: the path given is a symbolic link; run the check on the real folder.
   - `no_project_marker`: no project file was found at the top of this folder (and no project
     was found below it). The advice is neutral: add the project's manifest at the top, or run
     the check inside the project folder.
   - `git_only_root` (information only): the folder has no manifest at the top but has `.git`,
     so it is checked as one project.
   - `many_embedded_subprojects` (information only): more than 12 roots were excused as
     templates or fixtures under one `templates`/`fixtures`/`tests`/`examples`-style folder
     (see below); `detail.count` gives the number.
   - `folder_of_projects` (information; status `not_a_project`): see "A folder of separate
     projects" below. `detail.projects` counts the top-level projects, `detail.with_git` how many
     of them have their own `.git`.
   - `duplicate_tree_names` (information only): folders such as `src/src`, `<name>/<name>`, or
     names ending `-v2`, `-final`, `-old`, `-copy`, ` copy`, `(1)`, up to 3 levels deep.
   - `depth_limit_reached` (information only): folders deeper than the depth limit were not
     entered; `detail.folders_not_entered` counts them.
   - `could_not_verify`: the entry or time limit was reached, a folder could not be listed, or a
     declaration file could not be read (then the projects it might declare are listed here,
     not as nested).

## Nested project or embedded sub-package?

Many healthy repositories hold small separate packages on purpose. An undeclared project root
becomes `embedded_subproject` when it matches one of these patterns (first match wins; the
`reason` token is in `detail.reason`; the table is `structure_check.py` constants):

| reason | matches |
|---|---|
| `template_or_fixture` | an **ancestor** folder (strictly above the root, below PATH) is `templates`, `template`, `fixtures`, `fixture`, `__fixtures__`, `testdata`, `test-data`, `test_data`, `examples`, `example`, `samples`, `sample`, `demos`, `demo`, `tests`, `test`, `__tests__`, `e2e`, `spec`, `benchmarks`, `bench`, `mocks`, `__mocks__`, `scaffolds`, `boilerplate`, `starters`, `starter-kits`, or ends `-fixture(s)`, `-template`, `-example`, `_fixture`, `_template`, `_example`, or starts `tmpl_` / `tmpl-`. The root's **own** name excuses it only when it sits inside a declared workspace member (a fixture of that member); so `shop-example/` or `templates/` holding a manifest directly below PATH is nested, while `templates/myapp` is excused because of its ancestor |
| `vendored_code` | a segment `third_party`, `third-party`, `external`, `extern`, `deps`, `submodules` (`vendor` is never entered at all) |
| `framework_layout` | `src-tauri` with Cargo.toml; `android`/`ios`/`macos`/`windows`/`linux` with a manifest, directly in a folder with package.json or pubspec.yaml; `functions` with package.json beside `firebase.json`; `native`/`sidecar`/`wasm`/`rust`/`core-rs` with Cargo.toml inside a JS or Python project; `sidecar` with any manifest (a helper process); `bindings`/`ffi`; `docs`/`website`/`docs-site` with package.json; `infra`/`terraform`/`deploy`/`cdk`; `xtask`; `tools/<name>` or `scripts/<name>` with a manifest; a Gradle/Maven, .NET or Mix root inside a build of the same kind (their member lists live in `settings.gradle`, `pom.xml`, a `.sln` or `mix.exs`, which are not read) |
| `different_ecosystem` | its manifest kinds (JS, Python, Rust, Go, Dart, JVM, PHP, Ruby, Elixir, Swift, C/C++, .NET) share nothing with the root's and every declared member's; it is at depth 2 or less; its folder holds fewer than 2,000 directory entries; its name is not project-like (ends `project`, starts `my`, contains `other`, `copy`, `backup` or `test2`, or starts/ends with `new`/`old` or has it as a separated word); and it is the only undeclared root of that kind at depth 3 or less (a second-language component, for example one Rust crate in a JS app, or a `frontend/package.json` in a Django project) |

"Manifest" means any marker other than `.git` and the `index.html` rule.

Strong nesting signals always win; such a root stays `nested_project`:

- it has its own `.git` (it also gets `git_inside_git`, unless `.gitmodules` declares it);
- three or more undeclared roots share one parent folder (this is the "26 projects in `globe/`"
  shape, in any language). Exceptions: roots below an ancestor at depth 1 or 2 named exactly
  `templates`, `template`, `fixtures`, `__fixtures__`, `testdata`, `tests`, `test`, `__tests__` or
  `examples`; roots below a vendored folder; and platform shells (`android`, `ios`, ...) and
  Gradle/Maven/.NET/Mix modules, which never count toward a crowd. Below such a template or test
  folder the excuse holds for any number of roots, but more than 12 under one such folder add
  one `many_embedded_subprojects` note (information only);
- its name looks like a leftover copy: ends `-v2` (any `-vN`), `-final`, `-old`, `-copy`, ` copy`,
  `(1)`, `-backup`, `-new`;
- it sits under an agent scratch area: `_ai_temp`, `.planning`, `scratch`, `tmp`, `temp`,
  `playground`, `sandbox`, `experiments`, `wip`.

To silence an `embedded_subproject` note, declare the folder (root workspace declaration or
`.adopt/rules.json` `declared_dirs`).

## A folder of separate projects

A folder such as `~/Projects`, or an umbrella folder holding several repositories side by side,
is not a project and nothing is nested in it. When PATH has **no project marker and no member
declaration** (no `workspaces`, `pnpm-workspace.yaml` packages, Cargo members, `go.work` `use`
lines or `.gitmodules` paths; a `go.work`-only root is still treated as one Go workspace), then:

- the status is `not_a_project` (exit code `2`, whatever is found inside), with one
  `folder_of_projects` finding instead of `no_project_marker`;
- the **top-level projects** (project roots with no other project root above them below PATH)
  are not reported as `nested_project` or `git_inside_git`, and the walk does not go into them;
- the ordinary check then runs **inside each** of the first 50 top-level projects (sorted by
  path), using that project's own declarations, embedded patterns and overrides, within the
  remaining entry/time budget and depth limit. What it finds (`nested_project`,
  `embedded_subproject`, `git_inside_git`, `could_not_verify`, `duplicate_tree_names`) is reported
  with paths relative to PATH (for example `client-a/stray`) and depth counted from PATH;
- projects beyond the first 50, or left when the budget ran out, are not looked inside; one
  `could_not_verify` finding at `.` gives the real reason in `detail.reason` (`entries` or
  `time` when the budget ran out, otherwise `project_cap`), with `detail.evaluated` and
  `detail.not_evaluated`.

The JSON gains `top_level_projects`: up to 50 entries `{path, markers, nested_count,
embedded_count}`, where `nested_count` is the number of distinct paths inside that project with a
`nested_project` or `git_inside_git` finding. Its `roots` entries have `kind` `separate_project`;
roots found inside them are added with their own kinds and PATH-relative paths. In every other
case `top_level_projects` is an empty list.

```text
Projects/notes.txt  Projects/blog/package.json  Projects/blog/stray/package.json
Projects/game/Cargo.toml  Projects/game/.git/
$ hermes defuzz check Projects
Not a project: Projects is not a project itself; it holds 2 separate projects, and each can be checked on its own.
Needs a look inside: blog (1)
What to do:
  1. Run the check inside one of these projects; each one is checked on its own. For example: hermes defuzz check Projects/blog
```

The text output lists at most 10 projects that need a look inside.

## What it never does

It does not write anything, run `git` or any other program, follow symbolic links (they are
counted), or open any file except the seven root declaration files listed above (for a folder of separate
projects: those files in each of the first 50 top-level projects, never in PATH's other folders). Secret-looking
files (`.env`, keys, credentials) are never opened. Declaration files must be regular files under
1 MiB. It never descends into: `node_modules`, `.git`, `.next`, `.open-next`, `.turbo`, `dist`,
`build`, `out`, `.venv`, `venv`, `target`, `vendor`, `__pycache__`, `.cache`, `coverage`,
`.worktrees`, `.svelte-kit`, `.nuxt`, `.output`, `.parcel-cache`, `.pytest_cache`, `.mypy_cache`,
`.ruff_cache`, or a Hermes home found below the folder.

## Limits

At most 8 folder levels below PATH, 50,000 directory entries and 5 seconds.

- **Depth alone:** folders below level 8 are not entered and an info `depth_limit_reached`
  finding counts them. The verdict stays what the rest of the walk showed (large ordinary
  repositories have deep source trees), and the exit code is unchanged by it. Project roots
  deeper than 8 levels are not seen; run the check on a sub-folder to look there.
- **Entries or time:** the answer is `could_not_verify` with the partial counts, never "clean".

## Output

Text by default, at most 20 lines: a one-line verdict ("One project: ... (N declared workspace
members; M embedded sub-packages noted)"), a "Needs a look:" group (`nested_project`,
`git_inside_git`, `could_not_verify` and root findings), a "Noted, usually fine:" group
(`embedded_subproject` counted per reason, `duplicate_tree_names`, `depth_limit_reached`),
"What to do" lines, and one closing line on how to declare a folder.
`--json` prints the full result:

```json
{
  "schema": "defuzz.structure-check/1",
  "path": "site",
  "status": "nested_projects_found",
  "roots": [{"path": "globe/solar", "depth": 2, "markers": [".git", "package.json"], "kind": "nested"}],
  "declared_members": 0,
  "declarations": {"package.json": "absent", "pnpm-workspace.yaml": "absent"},
  "findings": [{"id": "nested_project", "path": "globe/solar",
                "detail": {"depth": 2, "markers": [".git", "package.json"]},
                "sentence": "...", "next": "..."}],
  "top_level_projects": [],
  "limits": {"max_depth": 8, "max_entries": 50000, "max_seconds": 5.0,
             "hit": [], "entries_seen": 51, "dirs_scanned": 30, "folders_not_entered": 0},
  "skipped": {"ignored_dirs": 0, "symlinks": 0, "unreadable": 0, "agent_home": 0, "declared_submodules": 0}
}
```

`status` is one of `one_project`, `nested_projects_found`, `not_a_project`, `could_not_verify`.
`roots[].kind` is `root`, `declared_member`, `declared_submodule`, `embedded`, `nested`,
`unverified` or `separate_project`. An `embedded_subproject` finding's `detail` has `depth`, `markers`, `reason` and,
for `framework_layout`, a `rule` label such as `Tauri crate`.
Paths are relative to PATH (PATH itself is shown as given); control characters in names are
escaped (`\x1b`, `\n`). Two runs on an unchanged folder give identical output.

Exit codes: `0` one project; `2` whenever the status is `not_a_project`; otherwise `1` a `nested_project`, `git_inside_git` or
`root_is_home_or_agent_home` finding exists; `2` could not verify, or not a project.
`embedded_subproject`, `duplicate_tree_names` and `depth_limit_reached` never change the exit code.

## A declared workspace versus a nested project

A monorepo is one project with several parts, and its root says so. This is fine:

```text
mono/package.json            {"workspaces": ["apps/*", "packages/*"]}
mono/apps/web/package.json
mono/packages/ui/package.json
$ hermes defuzz check mono
One project: mono (2 declared workspace members).
```

Nobody declared these two inner projects, and one has its own `.git`:

```text
site/index.html  site/assets/  site/.git/
site/globe/solar/package.json  site/globe/solar/.git/
site/globe/rover/pyproject.toml
$ hermes defuzz check site
Not one project: site has 2 undeclared project roots and 1 inner .git folders inside it.
```

To fix a nest, copy each inner project out to its own folder beside the outer one, check that the
copy works, and only then remove the original; or declare it as a workspace member.

A JS app with a Tauri crate and one test fixture is still one project:

```text
app/package.json  app/src-tauri/Cargo.toml  app/e2e/login-fixture/package.json
$ hermes defuzz check app
One project: app (0 declared workspace members; 2 embedded sub-packages noted).
```
