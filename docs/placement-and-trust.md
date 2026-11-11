# Placement modes and project trust

Defuzz redirects new `write_file` paths in trusted projects using `.adopt/rules.json`.
Trust requires a valid rules file whose hash matches the active profile's
`plugin-data/defuzz/state.db`. Editing the rules outside Defuzz invalidates that match.
Existing files are left at their requested paths.

## Trust modes (`declared_only` and `full`)

- `declared_only` uses matching non-fallback rules whose destinations appear in
  `declared_dirs`. Unmatched files stay where requested. Collisions and safety
  failures leave the write path unchanged.
- `full` also uses fallback extension rules and routes unmatched loose files to
  `_inbox/`. Destination collisions block the write.

Successful redirected writes receive a placement notice in the tool result.
The hooks and placement decisions are implemented in `placer.py`.

## How projects receive trust

Template scaffolds receive `declared_only` trust when their destination rules match
the generated hash. Kits and adopted copies receive `full` trust on registration.
For other folders, run `hermes defuzz trust <folder>` after reviewing the rules;
add `--declared-only` to select the narrower mode.

## Protected root table and project extensions

In `declared_only` mode, `rules.py` checks `PROTECTED_ROOT_TABLE`, project
`protected_root_files`, and supported manifest entry paths before redirecting.
The table defines the exact protected names and patterns.

Rules can restrict matches with `match_glob` and `root_only`. The first match wins.
`add_placement_rule` replaces an extension's routing while preserving sibling
extensions in existing rules. Pattern-specific rules stay ahead of the new rule.

## Bundled template layouts and shipped placement rules

Each template's `rules.json` supplies its root-only placement rules.
Layered templates route loose notes and diagrams to `docs/`, and `.sh`, `.bash`
and `.ps1` files to a declared `scripts/` destination, created when needed.
Python and TypeScript workspace templates route matching decision records to
`docs/adr/` first. The web template routes Markdown notes to `docs/` and matching
unit tests to `tests/unit/`.

Source and test ownership depends on each template's build configuration;
placement does not infer the correct package or build target from an extension.
See [scaffold acceptance](scaffold-ci.md) for creation and validation.
