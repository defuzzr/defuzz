# Project-outward audit scope

`hermes defuzz audit` inspects local files for configuration, context, storage
and project-isolation problems. Findings suggest review, not safe deletion
or proof that code is safe.

## What the audit reads

The audit reads the active Hermes profile's configuration, memories, skills,
job and plugin declarations, and local state. It inventories sibling profiles
and project registrations without treating them all as selected content.

Use `--root /registered/project` to select a registered project. Selecting a
parent does not select registered descendants. Without a project selection,
the audit inspects the active profile. Selected projects add project files,
parent context and outgoing paths supported by declarations or references.

Full mode also discovers startup settings in the user home associated with
the audited profile: shell, Git, package-manager, Python, user-service and
desktop-startup configuration. Discovery lives in `audit/home_startup.py`;
credential handling still applies.

## Read-only inspection

The audit opens inspected files read-only. It runs none of the user's scripts
and makes no network requests. It parses execution declarations rather than
running hooks, plugins, project commands or startup files. It reports advice
rather than applying cleanup or changing inspected settings.

SQLite inspection uses read-only connections. An existing WAL index can have
its read marks changed; concurrent path changes remain a limitation.
Audit progress, results and keys are written to Defuzz's own storage.

## Full and quick modes

Full static inspection is the default. `--quick` selects an incomplete,
fixed-file inspection and skips the full outward trace. Uncollected regions
remain unknown, not clean. `--full-home` is a compatibility flag for full mode,
not a request to select other projects.

`--unbounded` removes outward traversal budgets, including ordinary folder
pruning. Component capture limits and database safeguards still apply.
The report records effective limits and incomplete coverage.

`--sessions` opts into bounded session-transcript metrics; transcript text is
not retained. Quick mode does not measure transcripts even with this flag.

## Credential stores

Recognized credential stores are checked for presence and file metadata,
not opened for content inspection. Classification and declaration sources
are defined in `audit/policy.py` and `audit/file_types.py`.
Fixed declaration-source paths remain readable; declaring such a source as a
credential does not exclude it by name.

This is a best-effort boundary, not an absolute never-open guarantee.
The shared reader checks the opened file's identity before reading and closes
recognized credential handles unread. A known limitation: an SQLite database
is reopened by path after that check, so a concurrent replacement can bypass
the checked handle. See `audit/readonly_db.py` and [limits](limits.md).

## Report storage

Reports live in the active Hermes home's `plugin-data/defuzz/state.db`.
The serializer seals source-derived strings and redacts credential overlaps;
approved existing paths can remain visible. Sealing is not encryption.

`audit_summary.py` renders the stored report; `--json` exposes its structured
fields. Rule identifiers and report vocabulary live in
`audit/evidence_constants.py` and `audit/evidence_vocabulary.py`.

## Skill hygiene reference

Skill hygiene is a count to review, not a verdict. Its oversized-body threshold
is 24000 characters. `audit/skill_hygiene.py` defines `dated_lesson_lines`,
`PLACEHOLDER_USERS` and `TICKET_PREFIX_DENYLIST`; it distinguishes `hub`
provenance from the skill-change ledger. An `external_dir` can be reported as
`external_skill_dir_not_scanned`; other outcomes include `not_applicable`
and `duplicate_config_key`.

## More detail

See [audit sections](audit-sections/) for individual checks and
[limits](limits.md) for limitations.
