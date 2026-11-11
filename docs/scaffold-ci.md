# Scaffold preparation and delivered-tree CI

A repository's `check` may declare an optional `prepare` argv alongside `cmd`
and `cwd`. It runs only during acceptance, after tool preflight and generation of
`TOOLS.lock`, `.adopt/rules.json`, and `AGENTS.md`, but before the check command.
Both commands share the acceptance deadline and contained working directory.
TOOLS.lock seed or preflight failure also fails closed before publication: no
move, commit, or registration occurs, and staging is kept
(`_seed_and_verify_tools` at `scaffolder.py:1416-1451`; `accept` at `scaffolder.py:1786-1819`, body in `_accept_template` at `scaffolder.py:1822-2022`).
A preparation failure retains staging and prevents checking, moving, committing,
and registration. Templates without `prepare` retain the usual single command.

Before anything runs, acceptance checks that Git is available, because Git is needed
after the project is moved into place; without it acceptance stops with a message
ending "Nothing was created."

The `prepare` and check commands run in their own process group, with no standard
input. A timeout, a cancel, or an interrupt (Ctrl-C in the terminal) stops the whole
group: SIGTERM, then SIGKILL after one second. A timeout keeps the output printed so
far; a cancel is reported as a cancelled check. Either way the staging folder is kept
and nothing is moved.

The staged project is then moved into the folder recorded when the preview was made.
Acceptance refuses when that folder was replaced or redirected in the meantime;
missing folders between it and the destination are created without following links.
The move uses Python's `shutil.move`: on the same filesystem it is a rename, and on
another filesystem it copies the staged tree to the destination and then deletes the
staged copy.

```yaml
check:
  prepare: ["pnpm", "xtask", "prepare-scaffold"]
  cmd: ["pnpm", "xtask", "ci"]
  cwd: "."
```

The TypeScript templates' explicit preparation (`ts-node-golden` and `web-golden`
declare the same `prepare` and `cmd`) installs their frozen dependencies
and uses the pinned Biome to normalize formatting and imports after substitution.
Lint fixes are disabled. Renaming can change both line wrapping and import order;
a single static template cannot be preformatted for every possible project name.
Generated metadata is included, not ignored or regenerated after validation.
Ordinary `pnpm xtask ci` remains a non-fixing check. When the project is created on a
drive other than the one that holds pnpm's store, pnpm creates its store as
`<mount>/.pnpm-store` at the root of the project's drive.

## Creating from the desktop app (start and poll)

The dashboard route `POST /scaffold/accept` starts the acceptance in a worker thread
and waits for it for up to 20 seconds. A finished acceptance answers at once; a
slower one answers `202` with `status: running`, the current step (preparing the
project, running its first check, moving it into place, registering it) and a `poll`
path, and the page polls `GET /scaffold/accept/{proposal_id}` until the job ends.
`POST /scaffold/cancel` stops a job that has not started moving the project into
place: it waits up to 15 seconds for the job to stop, and the running check (or a
kit's `kit check`, which then runs in its own process group too) is stopped. Once the
move has started it answers `cancel: too_late` and the job finishes. At most four
acceptances run at once in one dashboard process; a fifth is refused with `429`. A
finished job's answer is kept for 10 minutes (at most 64 answers). The same steps
apply to projects created from templates and from kits.

`tests/test_accepted_scaffold_ci.py` covers every template found under
`templates/*/template.yaml` (seven today) with each of the names `northstar`,
`acceptance-ts`, `my-app-2`, `c2-python-final`, `a`, and a 64-character `z` name.
It accepts each scaffold into pytest temporary storage and requires a successful
staging check. At the final destination it reruns the template's declared CI
commands (the check command plus any `extra_cmds`, such as `cargo check --workspace
--locked` for Rust), requires clean Git status, and then requires a clean manual
lint result.
Set `TMPDIR` to isolated scratch storage. These checks require the template
runtimes and network/cache access; `ADOPT_SKIP_SLOW=1` explicitly skips them.
An isolated HOME must still be paired with usable Rust toolchain executables
(or explicitly configured Rustup state); skipped preflight is not a passing test.
