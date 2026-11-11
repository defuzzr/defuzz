"""Wiring of Unicode project folders into project creation.

The folder of a new project keeps the typed non-ASCII name for the proven templates; every
identifier written into files, the database slug and rules.json stay ASCII. The protection
against a projects folder swapped after the preview, and the report of a create that stops
after the move, must work the same with such a folder.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package, load_submodule

ensure_test_package()

from hermes_plugins.defuzz import cli, scaffolder  # noqa: E402
from hermes_plugins.defuzz.naming import folder_name, slugify  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError, accept, propose  # noqa: E402
from hermes_plugins.defuzz.state_store import get_project  # noqa: E402
from hermes_plugins.defuzz.templates import RepoSpec, TemplateSpec  # noqa: E402

from tests.test_route_write_errors import api, bridge, client, routes  # noqa: E402,F401  (fixtures)

NAME = "Café Ünïcode"  # its folder name differs from what was typed, so a note is shown


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "p1"})


def _template(tmp_path: Path, template_id: str = "rust-golden") -> TemplateSpec:
    root = tmp_path / "tpl"
    repo = root / "tmpl_prefix"
    repo.mkdir(parents=True)
    (repo / "README.md").write_text("tmpl_prefix\n", encoding="utf-8")
    return TemplateSpec(
        id=template_id, name="Mini", summary="Minimal template.", kind="lib", layout="mono",
        languages=("python",), engine=None, tags=(), needs=(), placeholder="tmpl_prefix",
        substitute_in=("**/*.md",), repos=(RepoSpec(name="tmpl_prefix", check=None),), root=root,
    )


def _propose(tmp_path: Path, name: str = NAME, template_id: str = "rust-golden"):
    projects = tmp_path / "projects"
    projects.mkdir(parents=True, exist_ok=True)
    return projects, propose(
        _template(tmp_path, template_id), name, {}, dest_root=projects,
        staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db",
    )


def test_proven_template_gets_unicode_folder_and_ascii_contents(tmp_path):
    projects, proposal = _propose(tmp_path)
    folder = folder_name(NAME)
    assert not folder.isascii()
    assert proposal.folder == folder and proposal.repos[0].dest == projects / folder
    assert proposal.slug == slugify(NAME) and proposal.slug.isascii()
    assert folder in proposal.folder_note and NAME in proposal.folder_note
    result = accept(proposal, register=_register, db_path=tmp_path / "s.db")
    repo = Path(result.repos[0]["path"])
    assert repo == projects / folder and repo.is_dir()
    assert (repo / "README.md").read_text(encoding="utf-8") == f"{proposal.forms.snake}\n"
    assert proposal.forms.snake.isascii()
    assert get_project(repo, db_path=tmp_path / "s.db")["slug"] == proposal.slug
    rules = json.loads((repo / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    assert rules["project_slug"] == proposal.slug


def test_ascii_name_and_unproven_template_keep_ascii_folder(tmp_path):
    projects, proposal = _propose(tmp_path, "Plain Name")
    assert proposal.repos[0].dest == projects / "plain-name" and proposal.folder_note == ""
    _, other = _propose(tmp_path / "b", NAME, template_id="mini")
    assert other.repos[0].dest.name == slugify(NAME)
    assert "not yet tested" in other.folder_note
    # A pure Unicode name that is already a valid folder name gets the same folder and no note.
    _, same = _propose(tmp_path / "c", "日本語サイト")
    assert same.repos[0].dest.name == "日本語サイト" and same.folder_note == ""


def test_swapped_projects_folder_is_refused_with_unicode_folder(tmp_path):
    projects, proposal = _propose(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    projects.rename(tmp_path / "projects-moved")
    projects.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert "changed" in str(caught.value)
    assert getattr(caught.value, "created_dirs", []) == []
    assert list(outside.iterdir()) == []
    assert list((tmp_path / "projects-moved").iterdir()) == []
    assert proposal.repos[0].staged.is_dir()


def _boom(*_a: Any, **_k: Any) -> Any:
    raise sqlite3.OperationalError("database is locked")


def test_failure_after_move_reports_unicode_folder(tmp_path, monkeypatch):
    projects, proposal = _propose(tmp_path)
    dest = projects / folder_name(NAME)
    monkeypatch.setattr(scaffolder, "record_project", _boom)
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert caught.value.created_dirs == [dest]
    assert str(dest) in str(caught.value) and dest.is_dir()


def test_route_reports_partial_with_unicode_folder(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    projects, proposal = _propose(tmp_path)
    dest = projects / folder_name(NAME)
    routes = load_submodule("dashboard.routes.workspace_routes")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    row = routes._new_row("template")
    row.update(state="ready", proposal=proposal, remember_options=False)
    monkeypatch.setattr(routes, "_PROPOSALS", {"u": row})
    monkeypatch.setattr(routes.scaffolder, "record_project", _boom)
    app = FastAPI()
    app.include_router(routes.router)
    resp = TestClient(app).post("/scaffold/accept", json={"proposal_id": "u", "confirm": True})
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["created_dirs"] == [str(dest)]
    assert detail["error"].count(str(dest)) == 1
    assert row["state"] == "partial" and dest.is_dir()


def test_route_propose_passes_folder_note(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    routes = load_submodule("dashboard.routes.workspace_routes")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setattr(routes, "_PROPOSALS", {})
    spec = _template(tmp_path)
    monkeypatch.setattr(routes.templates, "load_templates", lambda root=None: [spec])
    app = FastAPI()
    app.include_router(routes.router)
    projects = tmp_path / "projects"
    projects.mkdir()
    resp = TestClient(app).post("/scaffold/propose", json={
        "template_id": "rust-golden", "name": NAME, "dest_root": str(projects), "answers": {}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["folder"] == folder_name(NAME)
    assert body["folder_note"] and folder_name(NAME) in body["folder_note"]
    assert body["tree"][0]["dest"] == str(projects / folder_name(NAME))
    for row in routes._PROPOSALS.values():
        scaffolder.discard(row["proposal"])


def test_dry_run_prints_the_folder_note(tmp_path, capsys):
    _, proposal = _propose(tmp_path)
    cli._print_proposal_dry_run(proposal)
    out = capsys.readouterr().out
    assert proposal.folder_note in out.splitlines()
    scaffolder.discard(proposal)


def test_kit_propose_answer_carries_folder_note_and_ascii_folder(client, tmp_path):
    projects = tmp_path / "projects"
    projects.mkdir()
    resp = client.post("/scaffold/propose", json={
        "kit_id": "video-production", "name": NAME, "answers": {"building": "video"},
        "dest_root": str(projects)})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tree"][0]["dest"] == str(projects / slugify(NAME))  # kits keep ASCII folders
    assert "not yet tested" in body["folder_note"]
