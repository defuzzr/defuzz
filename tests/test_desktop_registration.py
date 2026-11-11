"""Desktop registration must work before chat/model tool initialization."""
import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests import load_submodule
from tests.toolchain_needs import fake_toolchain

# The fake-rust-game fixture declares cargo; creating it probes cargo and rustc and runs
# `cargo check`. These tests are about registration, so stand-ins answer for both.
FAKE_RUST = ("cargo", "rustc")


@pytest.fixture
def fake_rust(tmp_path):
    with fake_toolchain(tmp_path / "fake-bin", FAKE_RUST) as bin_dir:
        yield bin_dir


@pytest.mark.parametrize("discovery_error", [None, RuntimeError("discovery blocked")])
def test_unavailable_cli_scaffolds_with_notice(tmp_path, monkeypatch, capsys, discovery_error, fake_rust):
    from argparse import Namespace
    import tools.registry as tools_registry
    cli = load_submodule("cli")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setattr(tools_registry.registry, "get_entry", lambda _: None)

    def discover():
        if discovery_error:
            raise discovery_error
        return []

    monkeypatch.setattr(tools_registry, "discover_builtin_tools", discover)
    status = cli._handle_new_subcommand(Namespace(
        answers='{"building":"service","layout":"mono","languages":["rust"]}',
        name="Unavailable", yes=True, template_id="fake-rust-game",
        templates_root=Path(__file__).parent / "fixtures/templates",
        dest_root=tmp_path / "projects",
    ))
    assert status == 0
    assert (tmp_path / "projects/unavailable/.git").is_dir()
    output = capsys.readouterr()
    assert "Registration skipped" in output.err
    assert "unavailable" in output.err
    assert not (tmp_path / "hh/projects.db").exists()


@pytest.mark.parametrize("response", [
    RuntimeError("dispatch raised"),
    '{"success": false, "error": "permission denied"}',
    "not json", [], None, {},
])
def test_dispatch_failure_cli_exits_zero(tmp_path, monkeypatch, capsys, response, fake_rust):
    from argparse import Namespace
    import tools.registry as tools_registry
    cli = load_submodule("cli")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setattr(tools_registry.registry, "get_entry", lambda _: object())

    def dispatch(*args, **kwargs):
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(tools_registry.registry, "dispatch", dispatch)
    status = cli._handle_new_subcommand(Namespace(
        answers='{"building":"service","layout":"mono","languages":["rust"]}',
        name="Dispatch Failure", yes=True, template_id="fake-rust-game",
        templates_root=Path(__file__).parent / "fixtures/templates",
        dest_root=tmp_path / "projects",
    ))
    assert status == 0
    project = tmp_path / "projects/dispatch-failure"
    assert subprocess.run(["git", "rev-parse", "HEAD"], cwd=project,
                          capture_output=True).returncode == 0
    output = capsys.readouterr()
    notices = [line for line in output.err.splitlines() if "Desktop registration failed:" in line]
    assert len(notices) == 1
    assert "Register manually with desktop_project" in notices[0]
    assert str(project) in notices[0]
    assert "Registration skipped" not in output.err


@pytest.mark.parametrize("template_id", ["fake-py-service", None])
def test_all_poly_registrations_fail_once_per_repo(tmp_path, monkeypatch, capsys, template_id):
    import json
    from argparse import Namespace
    cli = load_submodule("cli")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    calls = []
    reason = 'denied "access"\nretry'

    def register(name, path):
        calls.append((name, path))
        return json.dumps({"error": reason})

    monkeypatch.setattr(cli, "REGISTER_PROJECT", register)
    # Scaffold preflight fails closed; give this registration test a passing tool probe.
    monkeypatch.setattr(load_submodule("scaffolder").toolchk, "probe",
                        lambda *a, **k: ("1.0.0", "fixture-tool"))
    status = cli._handle_new_subcommand(Namespace(
        answers='{"building":"service","layout":"poly","languages":["python","typescript"]}',
        name="Poly Failure", yes=True, template_id=template_id,
        templates_root=Path(__file__).parent / "fixtures/templates",
        dest_root=tmp_path / 'projects "quoted"',
    ))
    output = capsys.readouterr()
    if template_id is None:
        # List-first: without --template/--kit nothing is chosen, created or registered.
        assert status == 2
        assert calls == []
        assert not (tmp_path / 'projects "quoted"').exists()
        assert "Desktop registration failed:" not in output.out + output.err
        return
    assert status == 0
    assert len(calls) == 2
    notices = [line for line in output.err.splitlines() if "Desktop registration failed:" in line]
    assert len(notices) == 2
    for (name, path), notice in zip(calls, notices):
        assert json.dumps(reason) in notice
        args = notice.split("Register manually with desktop_project ", 1)[1].removesuffix(".")
        assert json.loads(args) == {"action": "create", "name": name, "path": path}
    assert "Desktop registration failed:" not in output.out


def test_workspace_response_contains_registration_result(tmp_path, monkeypatch, fake_rust):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    routes = load_submodule("dashboard.routes.workspace_routes")
    scaffolder = load_submodule("scaffolder")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    proposal = scaffolder.propose(
        load_submodule("templates").load_template(Path(__file__).parent / "fixtures/templates/fake-rust-game"),
        "Dashboard Failure", {"building": "game", "layout": "mono", "languages": ["rust"]},
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
    )
    monkeypatch.setattr(load_submodule("desktop_registration"), "create_project", lambda *a: '{"error":"denied"}')
    routes.accept_jobs._reset_for_tests()  # other tests plant the same proposal id
    # Build the row the way the propose route does, so it carries the Hermes home it belongs to.
    monkeypatch.setattr(routes, "_PROPOSALS", {"test": {
        **routes._new_row("template"),
        "state": "ready", "proposal": proposal, "remember_options": False,
    }})
    app = FastAPI()
    app.include_router(routes.router)
    response = TestClient(app).post("/scaffold/accept", json={"proposal_id": "test", "confirm": True})
    assert response.status_code == 200, response.text
    assert response.json()["repos"][0]["registration_result"] == {"registered": False, "reason": "denied"}


def test_discovery_exception_is_logged(monkeypatch, caplog):
    import logging
    import tools.registry as tools_registry
    registration = load_submodule("desktop_registration")
    monkeypatch.setattr(tools_registry.registry, "get_entry", lambda _: None)

    def discover():
        raise RuntimeError("discovery blocked")

    monkeypatch.setattr(tools_registry, "discover_builtin_tools", discover)
    with caplog.at_level(logging.DEBUG, logger=registration.__name__):
        with pytest.raises(registration.RegistrationUnavailable):
            registration.create_project("Example", "/unused")
    assert "discovery blocked" in caplog.text


def test_cold_scaffold_is_in_desktop_project_store(tmp_path, fake_rust):
    # A subprocess is essential: other tests may already have discovered tools.
    script = '''
import json
from pathlib import Path
from tests import ensure_test_package
ensure_test_package()
from hermes_plugins.defuzz.scaffolder import propose, accept
from hermes_plugins.defuzz.templates import load_template
from tools.registry import registry
assert registry.get_entry("desktop_project") is None
root = Path(__import__("os").environ["HERMES_HOME"])
proposal = propose(load_template(Path("tests/fixtures/templates/fake-rust-game")),
    "Cold Desktop", {"building": "game", "layout": "mono", "languages": ["rust"]},
    dest_root=root.parent / "projects", staging_parent=root.parent / "staging")
result = accept(proposal, db_path=root / "defuzz.db")
assert result.repos[0]["registration"] == "registered", result.repos
# This is the exact store API used by Desktop's projects.list RPC.
from hermes_cli import projects_db as pdb
with pdb.connect_closing() as conn:
    projects = pdb.list_projects(conn, include_archived=True)
assert len(projects) == 1
assert projects[0].id == result.repos[0]["hermes_project_id"]
assert projects[0].primary_path == result.repos[0]["path"]
assert pdb.projects_db_path() == root / "projects.db"
print(json.dumps(projects[0].to_dict()))
'''
    env = dict(os.environ)
    for key in ("HOME", "HERMES_HOME", "HERMES_REAL_HOME"):
        env[key] = str(tmp_path / key)
        Path(env[key]).mkdir()
    result = subprocess.run([sys.executable, "-c", script], env=env,
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
