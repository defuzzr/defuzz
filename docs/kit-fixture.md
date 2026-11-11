# Kit fixture

Routing tests do not call the companion plugin (`defuzz-componentize`) live.
They read a recorded copy of its kit commands in `tests/fixtures/kit_contract/`.
Production routing is different: unless kit data is passed in explicitly, it asks
the companion for its catalog through the bridge (`componentize_bridge.kit_list`,
which runs `kit list --json`).

The recorded files are:

- `list.json`: `kit list --json` (the fields the router reads: `id`, `name`,
  `summary`, `tags`, `version`).
- `shows/<id>.json`: `kit show <id> --json` for every kit. `tests/fake_kit_bridge.py`
  serves `list` and `show` from these files and synthesises `apply` by writing a kit tree,
  so no kit content is typed by hand in tests.
- `show.json`, `apply.json`, `check.json`: single-kit contract samples
  (`video-production`; the temporary target folder is recorded as `/ROOT`).

## Why

Routing depends on what each kit says it is for. A hand-kept copy drifts from the
real kits. The fixture is therefore generated, so kit summaries and tags cannot
drift, and a test fails when it is stale.

## Regenerate

```sh
python3 scripts/gen_kit_fixture.py --source <defuzz-componentize folder>
```

The folder can also come from `DEFUZZ_COMPONENTIZE_SOURCE`. The script loads the
companion's `kit_commands` module in a subprocess and runs `list`, `show` for every
kit, then `apply` and `check` for the contract kit. It uses a temporary HOME and
working folder, which are deleted afterwards. Output is written with sorted keys and
a trailing newline. `--check` does not modify the committed fixture; it still runs
the same commands, including `apply` into the temporary folder, and exits 1 with the
kit ids and field names that differ.

Run it whenever the companion's kits change (added, removed, renamed, new summary or
tags), then re-run the routing tests (`tests/test_routing_*.py`, `tests/test_kit_*.py`):
a changed summary or tag can change which kits a typed idea marks `(suggested)`.

## Guard

`tests/test_kit_fixture_sync.py` always checks that the fixture is internally
consistent. With `DEFUZZ_COMPONENTIZE_SOURCE` set it also runs the generator in
`--check` mode; without it, that part is skipped.
