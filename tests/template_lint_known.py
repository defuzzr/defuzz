"""Defuzz lint findings a bundled template is known to ship with.

Each entry is (file, rule). They are fixed in the template's source repository and then
removed here; any other finding, and any finding in another template, still fails.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

# No bundled template has known findings at present. Add (file, rule) pairs here only
# while a fix is on its way in the template's source repository.
KNOWN_TEMPLATE_LINT_FINDINGS: dict[str, frozenset[tuple[str, str]]] = {}


def assert_lint_clean_or_known(template_id: str, report: Mapping[str, Any]) -> None:
    """The manual lint gate is clean, or reports only this template's known findings."""
    assert report["ok"], report
    known = KNOWN_TEMPLATE_LINT_FINDINGS.get(template_id, frozenset())
    found = {(f["file"], f["rule"]) for f in report.get("findings") or []}
    assert found <= known, f"New defuzz lint findings in {template_id}: {sorted(found - known)}"
    if not known:
        assert report["status"] == "clean", report


_RUMDL_ISSUE = re.compile(r"^(?P<file>[^:\s]+):\d+:\d+: \[(?P<rule>MD\d+)\]", re.MULTILINE)


def run_format_checks_allowing_known(spec: Any, root: Path) -> None:
    """templates.run_scaffold_format_checks, except that rumdl may report only known findings."""
    from hermes_plugins.defuzz.templates import format_check_commands

    known = KNOWN_TEMPLATE_LINT_FINDINGS.get(spec.id, frozenset())
    for command, require_empty_stdout in format_check_commands(spec, root):
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
        detail = f"{command}\n{result.stdout}\n{result.stderr}"
        if result.returncode != 0 and known and Path(command[0]).name == "rumdl":
            found = {(m["file"], m["rule"]) for m in _RUMDL_ISSUE.finditer(result.stdout)}
            assert found and found <= known, detail
            continue
        assert result.returncode == 0, detail
        if require_empty_stdout:
            assert result.stdout.strip() == "", detail
