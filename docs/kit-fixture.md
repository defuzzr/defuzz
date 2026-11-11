# Kit fixture

Routing tests use recordings in `tests/fixtures/kit_contract/`.
Production asks the optional `defuzz-componentize` companion for `kit list --json`.
`list.json` and `shows/<id>.json` record the kits the companion lists, including `availability` metadata.
`show.json`, `apply.json` and `check.json` hold the contract-kit samples.
`tests/fake_kit_bridge.py` serves recorded metadata and builds test kit trees.

## Why

Regeneration refreshes summaries and tags used for suggestions. Picker availability is separate;
see [routing](routing.md).

## Regenerate

```sh
python3 scripts/gen_kit_fixture.py --source <companion folder>
python3 scripts/gen_kit_fixture.py --source <companion folder> --check
```

The source can also come from `DEFUZZ_COMPONENTIZE_SOURCE`. Both commands run the companion's
list, show, apply and check operations in temporary folders; `--check` compares instead of saving recordings.

## Guard
`tests/test_kit_fixture_sync.py` checks internal consistency. Its live drift check runs only when `DEFUZZ_COMPONENTIZE_SOURCE` is set.
