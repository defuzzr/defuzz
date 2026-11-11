"""Opt-in compatibility probe against an externally supplied Componentize CLI."""
import json
import os
from pathlib import Path
import sys

import pytest

from .conftest import load_submodule


def test_componentize_release_b_real_cli(monkeypatch):
    cli = os.environ.get("RELB_COMPONENTIZE_CLI")
    scratch = os.environ.get("RELB_COMPAT_ROOT")
    if not cli or not scratch:
        pytest.skip("set RELB_COMPONENTIZE_CLI and RELB_COMPAT_ROOT for the external compatibility check")
    root = Path(scratch)
    root.mkdir(parents=True, exist_ok=True)
    scaffolder = load_submodule("scaffolder")
    templates = load_submodule("templates")
    bridge = load_submodule("componentize_bridge")
    settings = load_submodule("componentize_settings")
    spec = templates.load_template(Path(__file__).resolve().parents[1] / "templates/python-golden")
    proposal = scaffolder.propose(
        spec, "Release B Compat", {}, dest_root=root / "projects",
        staging_parent=root / "staging", db_path=root / "state.db",
    )
    project = proposal.repos[0].staged
    # Leave the proposed scaffold intact as inspectable evidence; no acceptance
    # or project registration is required for this read-only survey contract.
    example = json.loads((project / "componentize/spec.example.json").read_text())
    assert example["schema_version"] == 2
    command = [sys.executable, cli, "--tools-root", str(root / "tools"),
               "--state-root", str(root / "componentize-state")]
    monkeypatch.setattr(settings, "load", lambda: dict(settings.DEFAULTS))
    monkeypatch.setattr(bridge, "detect_command", lambda *a, **kw: (command, "override", None))
    # conftest suppresses optional external discovery by default: restore the
    # real adoption entry point through the explicitly authorized survey API.
    result = bridge.survey_project(project)
    assert result == {"status": "ok", "exit": 0}
    survey = bridge.read_survey(project)
    assert survey["schema"] == "componentize.survey/1"
    assert survey["files"]
    assert "Never begin automatically" in (project / "AGENTS.md").read_text()
    assert not (root / "componentize-state").exists()
    assert not (root / "tools/.componentize").exists()
    evidence = {"project": str(project), "command": command,
                "files": len(survey["files"]),
                "proposed_splits": len(survey["proposed_splits"]),
                "result": result}
    (root / "compat-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
