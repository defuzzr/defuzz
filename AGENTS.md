# Defuzz

The strict credential policy (credential files are never opened) applies: audit credential stores with lstat only, without following symlinks; record kind (`credential_store`), path, size, mode and mtime, with coverage `credential_store_not_opened`. Never read, mmap, parse or fingerprint their contents, in full or quick audits.

Project Defuzz is a Hermes project scaffolder, organizer, and auditor (plugin id `defuzz`).
Run tests with `python -m pytest --confcutdir=tests --rootdir=tests tests -q` using a Python environment with Hermes core and pytest installed and a temporary `HERMES_HOME`; verify CLI changes via `python -m cli --help`.
State uses the public `plugins.plugin_storage.plugin_data_dir("defuzz")` API. Preserve checked automatic migration from the active profile: SQLite backup, private stability-checked WAL snapshot, legacy files untouched, existing destinations never overwritten or merged, and provenance recorded (`state_store.py:81-199,343-363`; `tests/test_state_migration.py`).

Constraint: generated AGENTS.md fits its line target automatically. Rule-derived overflow moves to `.adopt/AGENTS.details.md` (linked). Never drop rule-derived content, never fail or warn on its length, never ask the user. The optional componentize survey line is separate: it is skipped with a notice when it would exceed the line cap. Both files are generated from `.adopt/rules.json`: anything that changes the rules must call `write_agents_md` and `git add` both files.
