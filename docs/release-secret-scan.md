# Release secret scan

`scripts/secret_scan.py` checks recognized secret patterns and secret-like filenames.
Rules live in the script; exceptions live in `scripts/secret_scan_allow.json`.
Output gives the rule, location and masked preview rather than the full value.

## Limits

- Unrecognized, encoded, split or encrypted secrets can escape detection.
- Personal data, private hostnames and internal URLs need manual review.
- Oversized text, binary files and symbolic links are skipped; read the skipped list.
- A clean result applies to scanned material, not skipped files.

## Before publishing

Use the test environment described in [plugin readiness](plugin-readiness.md).

```sh
python3 scripts/secret_scan.py .
python3 scripts/secret_scan.py --git .
python3 -m pytest tests/test_export_secret_scan.py
```

`--git` scans tracked files and reports stale allowlist entries; it requires a Git checkout.
`--json` produces machine-readable output. Export and second-opinion checks may skip
when their maintainer tooling is absent; a skip is not a pass.

## Hermes installation scan

Hermes uses a separate scanner. High findings can come from `sudo` in
`templates/cpp-golden/tmpl_prefix/.github/workflows/ci.yml` for generated-project CI;
`/proc` handle inspection in `audit/bounded_call.py`, `audit/fingerprint.py` and
`kit_scaffold.py`; and the deliberately unsafe link fixture in
`templates/web-golden/tmpl_prefix/tests/unit/dist-check.test.ts`.
Bundled templates and tests can also trigger file-count and bundle-size warnings.
Run the scan for current findings and numbers; inspect warnings before accepting them.

## Deliberate test canaries

Allow a specific finding with a reason, not a whole folder. Use an inline
`secret-scan: allow` marker or a path, rule and exact-line hash in the allowlist.
`python3 scripts/secret_scan.py <folder> --hashes` prints finding hashes.
Build synthetic test secrets from pieces rather than committing complete token-shaped literals.

Enable GitHub Secret scanning and Push protection when publishing there.
Run local checks before pushes to other remotes too.
