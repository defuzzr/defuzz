# Audit summary

`hermes defuzz audit --summary` renders the audit report as plain text.
JSON is the default, and `--json` takes precedence over `--summary`.
If a report is not ready, status output remains JSON.

## Reading the output

- The opening block groups findings by classification and highlights measured items.
- Section blocks show measurements, findings and reasons for incomplete coverage.
- Other checks follow the main sections when space allows.
- Long summaries shorten finding lists or omit later blocks; use `--json` for the full report.
- Missing or malformed sections are shown as not measured.
- Paths in highlighted items are relative to the audited home; recognized credential-shaped paths are withheld.
- Report text is escaped before terminal display.
- Suggested next steps favor inspection and backup before deletion.

Formatting limits, section order and reason labels live in `audit_summary.py`.
See [audit scope](audit-scope.md) for what each check reads and [limits](limits.md) for gaps.

## Desktop

`GET /audit/summary?run_id=<id>` returns the stored report’s text and summary.
A run without a report returns its status with null text and summary.
The desktop shows a summary after completion and offers a raw-report toggle.
If the summary request fails, it shows JSON instead.
