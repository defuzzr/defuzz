"""Hermes PM's Python environment must not leak into project-owned CI."""
import json
import os
import sys
from pathlib import Path

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.scaffolder import accept, propose
from hermes_plugins.defuzz.templates import CheckSpec, load_template


@pytest.mark.parametrize("phase", ["prepare", "check"])
def test_project_check_drops_parent_python_environment(tmp_path, monkeypatch, phase):
    spec = load_template(Path(__file__).parent / "fixtures/templates/fake-py-service")
    proposal = propose(
        spec, "env-proof", {},
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
    )
    blocked = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")
    # A real child process asserts the boundary, including its prepare phase.
    code = (
        f"import os; assert not set({blocked!r}) & os.environ.keys(); "
        f"assert os.environ['UV_CACHE_DIR'] == {str(tmp_path / 'cache')!r}"
    )
    command = [sys.executable, "-c", code]
    noop = [sys.executable, "-c", "pass"]
    proposal.repos[0].check = CheckSpec(
        cmd=command if phase == "check" else noop,
        cwd=".",
        prepare=command if phase == "prepare" else None,
    )
    for key in blocked:
        monkeypatch.setenv(key, str(tmp_path / "parent-python"))
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "cache"))
    # Seed probes must also succeed despite the deliberately poisoned parent env.
    # Tool version policy is covered separately; exercise the real subprocess boundary.
    monkeypatch.setattr(
        sys.modules[accept.__module__].toolchk, "probe",
        lambda *a, **k: ("1.0.0", "fixture-tool"),
    )
    monkeypatch.setattr(sys.modules[accept.__module__].toolchk, "require", lambda *a, **k: None)
    result = accept(
        proposal,
        register=lambda *_: json.dumps({"success": True, "id": "env-proof"}),
        db_path=tmp_path / "state.db",
        timeout_s=30,
    )
    assert result.repos[0]["check"] == "ok"
    assert all(os.environ[key] == str(tmp_path / "parent-python") for key in blocked)
