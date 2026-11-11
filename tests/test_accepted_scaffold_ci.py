"""Slow end-to-end checks of the delivered tree, not just the staging copy."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.scaffolder import accept, propose
from hermes_plugins.defuzz.templates import load_template, load_templates, templates_root
from tests.template_lint_known import assert_lint_clean_or_known
from tests.toolchain_needs import check_tools, need, need_lint_tools


def discover_template_ids(root: Path | None = None) -> list[str]:
    """Discover all template IDs under templates/*/template.yaml."""
    specs = load_templates(root)
    assert specs, f"No templates discovered under {root or templates_root()}"
    return [spec.id for spec in specs]


@pytest.mark.skipif(os.environ.get("ADOPT_SKIP_SLOW") == "1", reason="ADOPT_SKIP_SLOW=1")
@pytest.mark.parametrize("name", ["northstar", "acceptance-ts", "my-app-2", "c2-python-final", "a", "z" * 64])
@pytest.mark.parametrize("template", discover_template_ids())
def test_accepted_scaffold_passes_own_ci(tmp_path, monkeypatch, template, name, templates_dir=None):
    """Acceptance must deliver a clean, committed tree that passes unchanged CI."""
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)
    base_dir = Path(templates_dir) if templates_dir is not None else templates_root()
    spec = load_template(base_dir / template)
    need(*check_tools(spec))
    proposal = propose(
        spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
    )
    result = accept(
        proposal, register=lambda *_: json.dumps({"success": True, "id": "test-project"}),
        db_path=tmp_path / "state.db", timeout_s=900,
    )
    assert result.repos[0]["check"] == "ok", result.repos[0]
    repo = Path(result.repos[0]["path"])
    assert (repo / ".adopt/rules.json").is_file()
    assert (repo / "AGENTS.md").is_file()
    assert (repo / "TOOLS.lock").is_file()
    check_spec = spec.repos[0].check
    assert check_spec is not None
    commands = [list(cmd) for cmd in check_spec.ci_commands()]
    check_cwd = repo if check_spec.cwd == "." else (repo / check_spec.cwd)
    for command in commands:
        proc = subprocess.run(command, cwd=check_cwd, capture_output=True, text=True, timeout=900)
        assert proc.returncode == 0, f"{command}\n{proc.stdout}\n{proc.stderr}"
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True,
    )
    assert status.stdout == "", status.stdout

    # The manual gate must remain clean after CI has populated caches/build output.
    from hermes_plugins.defuzz.linter import run_lint
    report = run_lint(repo, env=dict(os.environ), db_path=tmp_path / "state.db")
    (tmp_path / "manual-lint.json").write_text(json.dumps(report, indent=2))
    need_lint_tools(report)
    assert_lint_clean_or_known(spec.id, report)
    expected_lockfiles = list(spec.generated_lockfiles(repo))
    assert report["skipped_generated"] == expected_lockfiles, report
