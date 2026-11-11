"""A template accept that fails after the project folder is in place must say that folder exists.

Callers read `created_dirs` on the error: the dashboard keeps such a proposal as 'partial'
(look first) instead of 'ready' (retry is safe), and the command line tells the user.
"""

from __future__ import annotations

import json
import shutil
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package, load_submodule
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError, accept, propose  # noqa: E402
from hermes_plugins.defuzz.templates import RepoSpec, TemplateSpec  # noqa: E402

SECRET_TEXT = "internal-detail-xyz"


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "p1"})


def _template(tmp_path: Path, repos: tuple[str, ...] = ("tmpl_prefix",)) -> TemplateSpec:
    root = tmp_path / "tpl"
    for name in repos:
        repo = root / name
        repo.mkdir(parents=True)
        (repo / "README.md").write_text("tmpl_prefix\n", encoding="utf-8")
    return TemplateSpec(
        id="mini",
        name="Mini",
        summary="Minimal template.",
        kind="lib",
        layout="mono" if len(repos) == 1 else "poly",
        languages=("python",),
        engine=None,
        tags=(),
        needs=(),
        placeholder="tmpl_prefix",
        substitute_in=("**/*.md",),
        repos=tuple(RepoSpec(name=n, check=None) for n in repos),
        root=root,
    )


def _propose(tmp_path: Path, **kw: Any):
    projects = tmp_path / "projects"
    projects.mkdir(exist_ok=True)
    return propose(
        _template(tmp_path, **kw), "Demo", {}, dest_root=projects,
        staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db",
    )


def _raise(exc: BaseException):
    def _fail(*_a: Any, **_k: Any) -> Any:
        raise exc
    return _fail


def _assert_plain_partial(message: str, dest: Path) -> None:
    assert str(dest) in message
    assert "delete" in message
    assert SECRET_TEXT not in message
    assert "Traceback" not in message
    assert "\n" not in message


# --- Direct accept --------------------------------------------------------------------------


def test_failure_before_the_move_marks_nothing_created(tmp_path, monkeypatch):
    proposal = _propose(tmp_path)
    dest = proposal.repos[0].dest
    monkeypatch.setattr(scaffolder, "_publish_staged_repo", _raise(scaffolder._changed_parent_error(dest)))
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert getattr(caught.value, "created_dirs", []) == []
    assert "Nothing was created" in str(caught.value)
    assert not dest.exists()


@pytest.mark.parametrize("step", ["registration", "record", "save_answers"])
def test_failure_after_the_move_marks_the_folder_created(tmp_path, monkeypatch, step):
    proposal = _propose(tmp_path)
    dest = proposal.repos[0].dest
    boom = RuntimeError(SECRET_TEXT)
    target = {"registration": "_attempt_project_registration", "record": "record_project",
              "save_answers": "save_answers"}[step]
    monkeypatch.setattr(scaffolder, target, _raise(boom))
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert caught.value.created_dirs == [dest]
    _assert_plain_partial(str(caught.value), dest)
    assert (dest / "README.md").is_file()


def test_interrupt_after_the_move_marks_the_folder_created(tmp_path):
    proposal = _propose(tmp_path)
    dest = proposal.repos[0].dest
    with pytest.raises(KeyboardInterrupt) as caught:
        accept(proposal, register=_raise(KeyboardInterrupt()), db_path=tmp_path / "s.db")
    assert caught.value.created_dirs == [dest]
    assert dest.is_dir()


def test_second_repo_refused_after_first_moved_marks_the_first_created(tmp_path, monkeypatch):
    proposal = _propose(tmp_path, repos=("tmpl_prefix_api", "tmpl_prefix_web"))
    first, second = (plan.dest for plan in proposal.repos)
    real = scaffolder._publish_staged_repo

    def _publish(plan):
        if plan.dest == second:
            raise scaffolder._changed_parent_error(second)
        return real(plan)

    monkeypatch.setattr(scaffolder, "_publish_staged_repo", _publish)
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert caught.value.created_dirs == [first]
    assert str(first) in str(caught.value)
    assert first.is_dir() and not second.exists()


def test_move_that_landed_but_was_not_confirmed_says_where_it_is(tmp_path, monkeypatch):
    proposal = _propose(tmp_path)
    dest = proposal.repos[0].dest

    def _publish(plan):
        shutil.move(str(plan.staged), str(plan.dest))
        raise ScaffoldError(f"The projects folder for {plan.dest} changed while the project was being moved. "
                            f"Nothing was deleted. Check {plan.dest.parent} and remove anything you do not want.")

    monkeypatch.setattr(scaffolder, "_publish_staged_repo", _publish)
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert caught.value.created_dirs == [dest]
    assert str(dest) in str(caught.value)


# --- Through the dashboard route ------------------------------------------------------------


def _route_accept(tmp_path, monkeypatch, proposal):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    routes = load_submodule("dashboard.routes.workspace_routes")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    rows = {"test": {"state": "ready", "proposal": proposal, "remember_options": False,
                     "kind": "template", "home": routes._active_home(), "created": 0.0}}
    routes.accept_jobs._reset_for_tests()  # other tests plant the same proposal id
    monkeypatch.setattr(routes, "_PROPOSALS", rows)
    monkeypatch.setattr(routes, "_take_expired_locked", lambda: [])
    app = FastAPI()
    app.include_router(routes.router)
    response = TestClient(app).post("/scaffold/accept", json={"proposal_id": "test", "confirm": True})
    return response, rows["test"]["state"]


def test_route_ready_when_failure_is_before_the_move(tmp_path, monkeypatch):
    proposal = _propose(tmp_path)
    dest = proposal.repos[0].dest
    sc = load_submodule("scaffolder")
    monkeypatch.setattr(sc, "_publish_staged_repo", _raise(sc._changed_parent_error(dest)))
    response, state = _route_accept(tmp_path, monkeypatch, proposal)
    assert response.status_code == 409
    assert response.json()["detail"]["created_dirs"] == []
    assert state == "ready"
    assert not dest.exists()


@pytest.mark.parametrize("target", ["_attempt_project_registration", "record_project"])
def test_route_partial_when_failure_is_after_the_move(tmp_path, monkeypatch, target):
    proposal = _propose(tmp_path)
    dest = proposal.repos[0].dest
    monkeypatch.setattr(load_submodule("scaffolder"), target, _raise(RuntimeError(SECRET_TEXT)))
    response, state = _route_accept(tmp_path, monkeypatch, proposal)
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["created_dirs"] == [str(dest)]
    _assert_plain_partial(detail["error"], dest)
    assert state == "partial"
    assert dest.is_dir()


# --- Command line ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_cli_prints_one_plain_line_saying_the_folder_exists(tmp_path, monkeypatch, capsys):
    import tools.registry as tools_registry

    cli = load_submodule("cli")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setattr(tools_registry.registry, "get_entry", lambda _: None)
    monkeypatch.setattr(tools_registry, "discover_builtin_tools", lambda: [])
    monkeypatch.setattr(load_submodule("scaffolder"), "record_project", _raise(RuntimeError(SECRET_TEXT)))
    status = cli._handle_new_subcommand(Namespace(
        answers='{"building":"service","layout":"mono","languages":["rust"]}',
        name="Half Made", yes=True, template_id="fake-rust-game",
        templates_root=Path(__file__).parent / "fixtures/templates",
        dest_root=tmp_path / "projects",
    ))
    dest = tmp_path / "projects" / "half-made"
    out = capsys.readouterr()
    assert status != 0
    assert dest.is_dir()
    lines = [line for line in (out.out + out.err).splitlines() if str(dest) in line]
    assert len(lines) == 1, out
    _assert_plain_partial(lines[0].split(": ", 1)[-1], dest)
    assert SECRET_TEXT not in out.out + out.err
