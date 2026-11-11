# Scaffold preparation and delivered-tree CI

Acceptance checks Git availability, generates project metadata and seeds and checks
[TOOLS.lock](tools-lock-spec.md). A tool preflight failure keeps staging and stops
before preparation, publication, commit or registration.

A template's `check` can specify `prepare`, `cmd` and `cwd`.
Preparation runs before the check; both share the acceptance deadline and a
working directory inside staging. These commands execute project code on the host.
A failed preparation or check keeps staging. Timeout or cancellation stops the
command's process group. TypeScript preparation installs frozen dependencies and
normalizes formatting and imports before the non-fixing CI check.

Templates and kits publish through checked folder handles. The destination parent
is checked against the preview record, and existing destinations are refused.
On the same filesystem, publication renames staging into place. Across filesystems,
it copies through handles into a hidden `.adopt-move-*` folder, renames that folder
into place, then removes staging. See `scaffolder.py` and `safety.py`.

## Creating from the desktop app (start and poll)

`POST /scaffold/accept` starts acceptance. Longer jobs return `202` with a `poll`
path; the page polls `GET /scaffold/accept/{proposal_id}` for the result.
`POST /scaffold/cancel` cancels before publication starts; afterward it reports
`too_late`. Job limits and result retention are defined in
`dashboard/routes/accept_jobs.py`.

## Validation

`tests/test_accepted_scaffold_ci.py` accepts discovered templates under varied
project names, reruns their declared checks at the destination, and checks Git
cleanliness and manual lint. It needs the template toolchains and network/cache
access; `ADOPT_SKIP_SLOW=1` skips it. A skipped check is not a passing check.
Defuzz supports Linux. The Ubuntu-only CI jobs and Python matrix are defined in
`.github/workflows/ci.yml`.
