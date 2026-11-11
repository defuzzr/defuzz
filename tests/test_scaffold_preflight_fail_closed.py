"""Required tool preflight is a publication barrier, including no-check repos."""
import json
import sys
from unittest.mock import Mock
from pathlib import Path
from argparse import Namespace

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import scaffolder, toolchk
from hermes_plugins.defuzz.templates import load_template


def test_cli_template_yes_preserves_failed_preflight(tmp_path, monkeypatch, capsys):
    from hermes_plugins.defuzz import cli

    fixtures = Path(__file__).parent / "fixtures/templates"
    proposal = scaffolder.propose(load_template(fixtures / "fake-rust-game"),
        "example", {}, dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging")
    monkeypatch.setattr(cli, "propose", lambda *a, **kw: proposal)
    monkeypatch.setattr(scaffolder.tool_seed, "seed_lock", Mock(side_effect=OSError("seed failure")))
    register = Mock()
    monkeypatch.setattr(cli, "REGISTER_PROJECT", register)
    rc = cli._handle_new_subcommand(Namespace(
        answers=json.dumps({"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}),
        name="example", template_id="fake-rust-game", yes=True,
        templates_root=fixtures, dest_root=tmp_path / "projects"))
    assert rc == 1
    assert proposal.staging_dir.is_dir()
    report = json.loads((proposal.repos[0].staged / ".adopt/preflight.json").read_text())
    assert report["reason"] == "seed-failed"
    assert not proposal.repos[0].dest.exists()
    register.assert_not_called()
    stderr = capsys.readouterr().err
    assert "seed-failed" in stderr
    assert str(proposal.staging_dir) in stderr


@pytest.mark.parametrize("seeding", [False, True])
def test_scaffold_report_write_failure_preserves_flow(tmp_path, monkeypatch, seeding):
    from hermes_plugins.defuzz import new_project

    def seed(root, **kwargs):
        (root / ".adopt").write_text("obstruct report directory")
        if seeding:
            raise OSError("seed failure")
        return {"added": ["fixture"], "probe_failed": {"fixture": "probe failed"}}

    monkeypatch.setattr(scaffolder.tool_seed, "seed_lock", seed)
    errors = []
    real_accept = scaffolder.accept

    def accept(*args, **kwargs):
        try:
            return real_accept(*args, **kwargs)
        except Exception as exc:
            errors.append(exc)
            raise

    monkeypatch.setattr(new_project, "accept", accept)
    register = Mock()
    answers = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
    result = new_project.run_new_project_flow(
        ask=lambda q, _: answers.get(q.id), template_id="fake-rust-game",
        name_provider=lambda: "example", confirm=lambda _: True,
        templates_root=Path(__file__).parent / "fixtures/templates",
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
        db_path=tmp_path / "state.db", register=register)
    assert result.status == "error"
    assert result.proposal.staging_dir.is_dir()
    error, = errors
    assert isinstance(error, scaffolder.ScaffoldError)
    assert error.reason == ("seed-failed" if seeding else "preflight-failed")
    assert error.report_error == "report-write-failed"
    assert error.keep_staging and error.staging_dir == result.proposal.staging_dir
    assert "report-write-failed" in result.message
    assert not result.proposal.repos[0].dest.exists()
    assert (result.proposal.repos[0].staged / ".adopt").is_file()
    register.assert_not_called()


@pytest.mark.parametrize("seeding", [False, True])
def test_scaffold_preflight_error_excludes_command_output(tmp_path, monkeypatch, seeding):
    canary = "INERT_OUTPUT_CANARY\n\x1b[31m" + "x" * 10000
    fixtures = Path(__file__).parent / "fixtures/templates"
    proposal = scaffolder.propose(load_template(fixtures / "fake-rust-game"),
        "example", {}, dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging")

    def seed(root, **kwargs):
        if seeding:
            raise OSError(canary)
        toolchk.dump_lock(root / "TOOLS.lock", {"lock": toolchk.DEFAULT_HEADER,
            "tools": {"fixture": {"version": "1.0", "chosen": "2026-01-01",
                "reason": "test pin", "probe": "command", "argv": [sys.executable, "--version"]}}})
        return {"added": ["fixture"]}

    monkeypatch.setattr(scaffolder.tool_seed, "seed_lock", seed)
    monkeypatch.setattr(toolchk, "_resolve_command", lambda *a, **kw: [sys.executable, "--version"])
    monkeypatch.setattr(toolchk, "_run_bounded_command", lambda *a, **kw: (canary, ""))
    with pytest.raises(scaffolder.ScaffoldError) as caught:
        scaffolder.accept(proposal, register=Mock())
    message = str(caught.value)
    assert "INERT_OUTPUT_CANARY" not in message
    assert "\x1b" not in message
    assert len(message) < 512
    assert caught.value.reason in message
    if not seeding:
        assert "fixture" in message
        assert "exit code 3" in message
    report = json.loads((proposal.repos[0].staged / ".adopt/preflight.json").read_text())
    assert "INERT_OUTPUT_CANARY" in json.dumps(report)


@pytest.mark.parametrize("with_check", [False, True])
@pytest.mark.parametrize("failure,entry", [
    (failure, entry)
    for failure in ["seed", "seed-probe", "missing", "probe", "drift", "broken", "exception"]
    for entry in ["accept", "cli", "dashboard", "flow"]
] + [(None, "accept")])
def test_scaffold_preflight_fail_closed(tmp_path, monkeypatch, with_check, failure, entry):
    template = tmp_path / "fixture"
    source = template / "tmpl_prefix"
    source.mkdir(parents=True)
    (source / "README.md").write_text("fixture")
    repo = {"name": "tmpl_prefix"}
    if with_check:
        repo["check"] = {"cmd": [sys.executable, "-c",
            "from pathlib import Path; Path('checked').touch()"], "cwd": "."}
    (template / "template.yaml").write_text(json.dumps({
        "id": "fixture", "name": "Fixture", "summary": "fixture",
        "kind": "app", "layout": "single", "languages": ["python"],
        "placeholder": "tmpl_prefix", "substitute_in": ["*.md"], "repos": [repo],
    }))
    proposal = scaffolder.propose(load_template(template), "example", {},
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging")
    plan = proposal.repos[0]

    def seed(root, **kwargs):
        if failure == "seed":
            raise OSError("seed write failed")
        if failure != "missing":
            toolchk.dump_lock(root / "TOOLS.lock", {"lock": toolchk.DEFAULT_HEADER,
                "tools": {"fixture": {"version": "1.0", "chosen": "2026-01-01",
                    "reason": "test pin", "probe": "command", "argv": ["fixture", "--version"]}}})
        if failure == "broken":
            (root / "TOOLS.lock").write_text("[broken")
        return {"added": ["fixture"], "probe_failed": (
            {"fixture": "probe failed during seed"} if failure == "seed-probe" else {}
        )}

    monkeypatch.setattr(scaffolder.tool_seed, "seed_lock", seed)
    def probe(*args, **kwargs):
        if failure == "probe":
            raise FileNotFoundError("fixture missing")
        return ("2.0" if failure == "drift" else "1.0", "/fixture")
    monkeypatch.setattr(toolchk, "probe", probe)
    if failure == "exception":
        monkeypatch.setattr(toolchk, "require", Mock(side_effect=RuntimeError("unexpected")))
    register = Mock(return_value=json.dumps({"success": True, "id": "fixture"}))
    git = Mock(side_effect=AssertionError("must not initialize or commit"))
    db = tmp_path / "state.db"
    if failure is None:
        result = scaffolder.accept(proposal, register=register, db_path=db)
        assert result.repos[0]["path"] == str(plan.dest)
        assert (plan.dest / ".git").is_dir()
        assert (plan.dest / "checked").exists() == with_check
        register.assert_called_once()
        return
    errors = []
    real_accept = scaffolder.accept

    def guarded_accept(candidate, **kwargs):
        assert candidate is proposal
        try:
            return real_accept(candidate, register=register, git=git, db_path=db)
        except scaffolder.ScaffoldError as exc:
            errors.append(exc)
            raise

    if entry == "accept":
        with pytest.raises(scaffolder.ScaffoldError):
            guarded_accept(proposal)
    elif entry == "cli":
        import argparse
        from hermes_plugins.defuzz import cli
        monkeypatch.setattr(cli, "propose", lambda *a, **kw: proposal)
        monkeypatch.setattr(cli, "accept", guarded_accept)
        parser = argparse.ArgumentParser()
        cli.setup_defuzz_cli(parser)
        args = parser.parse_args(["new", "--name", "example", "--template", "fixture",
                                  "--templates-root", str(tmp_path), "--yes", "--answers",
                                  json.dumps({"building": "app", "layout": "mono",
                                              "languages": ["python"]})])
        assert cli.handle_defuzz_cli(args) == 1
    elif entry == "dashboard":
        from hermes_plugins.defuzz.dashboard.routes import workspace_routes as routes
        from fastapi import HTTPException
        monkeypatch.setattr(scaffolder, "accept", guarded_accept)
        routes.accept_jobs._reset_for_tests()  # each case plants the same proposal id
        # Build the row the way the propose route does, so it carries the Hermes home it belongs to.
        monkeypatch.setattr(routes, "_PROPOSALS", {
            "fixture": {**routes._new_row("template"),
                        "state": "ready", "proposal": proposal, "remember_options": False}})
        with pytest.raises(HTTPException) as response:
            routes.accept_project({"proposal_id": "fixture", "confirm": True})
        assert response.value.status_code == 409
        assert response.value.detail["keep_staging"] is True
        assert response.value.detail["created_dirs"] == []
        assert routes._PROPOSALS["fixture"]["state"] == "ready"
    else:
        from hermes_plugins.defuzz import new_project
        proposed = []

        def flow_propose(chosen, *args, **kwargs):
            proposed.append(chosen.id)
            return proposal

        monkeypatch.setattr(new_project, "propose", flow_propose)
        monkeypatch.setattr(new_project, "accept", guarded_accept)
        answers = {"building": "app", "layout": "mono", "languages": ["python"]}
        result = new_project.run_new_project_flow(
            ask=lambda q, _: answers.get(q.id), template_id="fixture",
            name_provider=lambda: "example", confirm=lambda _: True,
            templates_root=tmp_path,
            dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
            db_path=db, register=register)
        assert result.status == "error"
        assert result.proposal is proposal
        assert proposed == ["fixture"]
    error, = errors
    reason = "seed-failed" if failure == "seed" else "preflight-failed"
    assert error.reason == reason
    assert error.keep_staging and error.staging_dir == proposal.staging_dir
    assert error.completed == []
    assert plan.check_status != "skipped"
    assert plan.staged.is_dir() and not plan.dest.exists()
    assert not (plan.staged / ".git").exists()
    assert not (plan.staged / "checked").exists()
    assert not db.exists()
    register.assert_not_called()
    git.assert_not_called()
    report = json.loads((plan.staged / ".adopt/preflight.json").read_text())
    assert report["ok"] is False
    assert report["reason"] == reason
    assert report["summary"]
    if failure in {"probe", "drift"}:
        assert report["tools"]["fixture"]["status"] == (
            "probe-failed" if failure == "probe" else "drift"
        )
