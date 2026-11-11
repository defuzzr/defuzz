# Real-tool lint tests

The matrix runs installed linters against clean and failing fixtures, checks
parsed findings, and checks that target source fixture text stays unchanged.
Cases live in `cases.py`; tool pins live in `setup_manifest.py`.

## Run

Use the repository test dependencies and an importable Hermes checkout. On Linux,
provide the installed toolchain root and run from the repository root:

```sh
PYTHONPATH=/path/to/hermes-agent LINT_MATRIX_TOOL_ROOT=/path/to/tool-root python -m pytest tests/lint_matrix -s
```

The tool root supplies `bin`, `opt/dotnet`, and
`home/.local/share/powershell/Modules`. Without `LINT_MATRIX_TOOL_ROOT`, detection
uses the environment's tool paths. Tests use installed tools rather than installing
them. Set `LINT_MATRIX_STRICT=1` to fail execution rows with missing executables;
otherwise those rows skip. Optional unimplemented rows skip in either mode.

## Evidence and limits

Execution and configuration tests print `LINT_MATRIX_RECEIPT` paths. Inventory
and argv-only checks do not. Receipt rows distinguish `pass`, `missing`, `fail`,
and optional `skip` outcomes; missing or skipped tools are not execution passes.
Preflight failures can stop a test before it writes a receipt.

Offline execution tests require `libseccomp.so.2` and verify network denial with
a connection canary. These test runtime behavior, not offline installation.
`test_offline_dependency.py` checks a cold-cache dependency failure.

`test_arm_receipt.py` checks ARM artifact configuration and known gaps without
running ARM binaries. `test_guard_journey.py` checks `doctor_report` and the lint
command handler across tool-lock drift and acceptance. `test_argv_regressions.py`
checks command construction.
