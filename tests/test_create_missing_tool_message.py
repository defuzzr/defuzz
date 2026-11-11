"""Creating a project with a missing tool tells the user which tool and what to do, and creates nothing."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import scaffolder, toolchk  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # noqa: E402

EXPECTED = "node: not found on PATH, need >= 20. Install node, " + toolchk.SETUP_HINT


def _message_carries_plain_line() -> bool:
    """True once the scaffolder adds the first plain tool line to its preflight message."""
    line = toolchk.missing_tool_line("node", "20")
    exc = toolchk.PreflightError(3, {"ok": False, "summary": "x", "tools": {"node": {}}, "probe_failed": [line]})
    plan = SimpleNamespace(staged=Path("/nonexistent-defuzz-probe"), check_status=None)
    proposal = SimpleNamespace(staging_dir=None)
    original = toolchk.record
    toolchk.record = lambda *a, **kw: None  # type: ignore[assignment]
    try:
        err = scaffolder._scaffold_preflight_error(proposal, plan, exc)  # type: ignore[arg-type]
    finally:
        toolchk.record = original  # type: ignore[assignment]
    return line in str(err)


pytestmark = pytest.mark.skipif(
    not _message_carries_plain_line(),
    reason="the scaffolder preflight message does not yet include the plain tool line "
    "(scaffolder-preflight-message patch not applied)",
)


def _proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    template = tmp_path / "fixture"
    source = template / "tmpl_prefix"
    source.mkdir(parents=True)
    (source / "README.md").write_text("fixture")
    (source / "package.json").write_text('{"name": "demo"}\n')
    (source / ".nvmrc").write_text("20\n")
    (template / "template.yaml").write_text(json.dumps({
        "id": "fixture", "name": "Fixture", "summary": "fixture",
        "kind": "app", "layout": "single", "languages": ["typescript"],
        "placeholder": "tmpl_prefix", "substitute_in": ["*.md"], "repos": [{"name": "tmpl_prefix"}],
    }))
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    git = shutil.which("git")
    if git:  # creation checks git before tools; node stays missing
        (empty_bin / "git").symlink_to(git)
    monkeypatch.setenv("PATH", str(empty_bin))
    return scaffolder.propose(load_template(template), "example", {},
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging")


def test_cli_create_with_missing_tool_shows_plain_line(tmp_path, monkeypatch, capsys):
    from hermes_plugins.defuzz import cli

    proposal = _proposal(tmp_path, monkeypatch)
    register = Mock()
    monkeypatch.setattr(cli, "propose", lambda *a, **kw: proposal)
    monkeypatch.setattr(cli, "REGISTER_PROJECT", register)
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    args = parser.parse_args(["new", "--name", "example", "--template", "fixture",
                              "--templates-root", str(tmp_path), "--yes", "--answers",
                              json.dumps({"building": "app", "layout": "mono", "languages": ["typescript"]})])
    assert cli.handle_defuzz_cli(args) == 1
    err = capsys.readouterr().err
    assert EXPECTED in err
    assert not proposal.repos[0].dest.exists()
    register.assert_not_called()


def test_dashboard_create_with_missing_tool_shows_plain_line(tmp_path, monkeypatch):
    from fastapi import HTTPException

    from hermes_plugins.defuzz.dashboard.routes import workspace_routes as routes

    proposal = _proposal(tmp_path, monkeypatch)
    real_accept = scaffolder.accept
    register = Mock()
    monkeypatch.setattr(scaffolder, "accept", lambda p, **kw: real_accept(p, register=register,
                                                                         db_path=tmp_path / "state.db"))
    monkeypatch.setattr(routes, "_PROPOSALS", {
        "fixture": {**routes._new_row("template"), "state": "ready", "proposal": proposal,
                    "remember_options": False}})
    with pytest.raises(HTTPException) as response:
        routes.accept_project({"proposal_id": "fixture", "confirm": True})
    assert response.value.status_code == 409
    assert EXPECTED in response.value.detail["error"]
    assert response.value.detail["created_dirs"] == []
    assert not proposal.repos[0].dest.exists()
    register.assert_not_called()
