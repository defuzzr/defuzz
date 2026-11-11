"""Routes for explicit existing-project discovery, opening, and read-only tree listing.

The route tests use the real sibling services when they are present, so the API shape and
the service contract are exercised together. A tree request is refused unless the folder
is a verified registration in the active profile; no arbitrary folder can be browsed.
"""
from __future__ import annotations

import hashlib
import os
import stat
from contextlib import closing
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule


def _client() -> TestClient:
    routes = load_submodule("dashboard.routes.existing_project_routes")
    app = FastAPI()
    app.include_router(routes.router)
    return TestClient(app)


def _core():
    from hermes_cli import projects_db

    return projects_db


def _core_db_path() -> Path:
    return Path(os.environ["HERMES_HOME"]) / "projects.db"


def _create_core_project(name: str, folders: list[Path], *, primary_path: Path | None = None) -> str:
    pdb = _core()
    with closing(pdb.connect()) as conn:
        return pdb.create_project(
            conn,
            name=name,
            folders=[str(folder) for folder in folders],
            primary_path=None if primary_path is None else str(primary_path),
        )


def _register(folder: Path, name: str = "Registered") -> Path:
    store = load_submodule("state_store")
    store.record_project(
        folder,
        name,
        name.lower().replace(" ", "-"),
        "existing",
        {"building": "other", "layout": "single", "languages": []},
        None,
        db_path=store.state_db_path(),
    )
    return store.state_db_path()


def _snapshot(root: Path) -> dict[str, tuple]:
    """Bytes and metadata for every entry, so any read/write/touch is visible."""
    entries: dict[str, tuple] = {}
    for path in sorted([root, *root.rglob("*")]):
        st = os.lstat(path)
        relative = str(path.relative_to(root))
        if stat.S_ISREG(st.st_mode):
            entries[relative] = (
                "file",
                st.st_mode,
                st.st_size,
                st.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        elif stat.S_ISLNK(st.st_mode):
            entries[relative] = ("link", st.st_mode, os.readlink(path))
        else:
            entries[relative] = ("other", st.st_mode)
    return entries


def _write(root: Path, relative: str, data: str | bytes = "x") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# GET /workspace/available-projects
# ---------------------------------------------------------------------------


def test_available_projects_route_reports_missing_registry_as_verified_empty(isolated_home):
    db_path = _core_db_path()
    assert not db_path.exists()

    response = _client().get("/workspace/available-projects")

    assert response.status_code == 200, response.text
    assert response.json() == {"projects": [], "coverage": "verified"}
    assert not db_path.exists()


def test_available_projects_route_lists_core_projects_without_writing(isolated_home, tmp_path):
    folder = tmp_path / "existing-project"
    folder.mkdir()
    project_id = _create_core_project("Existing", [folder], primary_path=folder)
    db_before = _core_db_path().read_bytes()
    folder_before = _snapshot(folder)

    response = _client().get("/workspace/available-projects")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["coverage"] == "verified"
    assert "error" not in body
    assert [(p["id"], p["name"], p["path"], p["primary_path"]) for p in body["projects"]] == [
        (project_id, "Existing", str(folder.resolve()), str(folder.resolve()))
    ]
    assert _core_db_path().read_bytes() == db_before
    assert _snapshot(folder) == folder_before


def test_available_projects_route_keeps_unverified_coverage_explicit(isolated_home):
    db_path = _core_db_path()
    db_path.write_bytes(b"not a sqlite database")
    before = db_path.read_bytes()

    response = _client().get("/workspace/available-projects")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["projects"] == []
    assert body["coverage"] == "could_not_verify"
    assert body["error"]
    assert db_path.read_bytes() == before


# ---------------------------------------------------------------------------
# POST /workspace/projects/open
# ---------------------------------------------------------------------------


def test_open_route_registers_a_pointer_without_touching_the_source(tmp_path):
    folder = tmp_path / "My Project"
    folder.mkdir()
    _write(folder, "README.md", "# existing\n")
    before = _snapshot(folder)
    store = load_submodule("state_store")

    response = _client().post("/workspace/projects/open", json={"path": str(folder)})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "opened"
    project = body["project"]
    assert project["path"] == str(folder.resolve())
    assert project["name"] == "My Project"
    assert project["template_id"] == "existing"
    assert project["hermes_project_id"] is None
    assert _snapshot(folder) == before
    assert not (folder / ".adopt").exists()
    record = store.get_project(folder)
    assert record is not None and record["path"] == str(folder.resolve())


def test_open_route_validates_the_body_before_registering(tmp_path):
    folder = tmp_path / "valid"
    folder.mkdir()
    missing = tmp_path / "missing"
    regular = tmp_path / "regular"
    regular.write_text("not a folder", encoding="utf-8")
    inside_hermes = Path(os.environ["HERMES_HOME"]) / "inside-project"
    inside_hermes.mkdir(parents=True)
    store = load_submodule("state_store")
    client = _client()

    cases = [
        (["not", "an", "object"], 400),
        ({}, 400),
        ({"path": 42}, 400),
        ({"path": ""}, 400),
        ({"path": "relative/path"}, 400),
        ({"path": str(missing)}, 400),
        ({"path": str(regular)}, 400),
        ({"path": str(folder) + "\x00"}, 400),
        ({"path": str(folder), "extra": True}, 400),
        ({"path": str(folder), "hermes_project_id": 7}, 400),
        ({"path": str(folder), "hermes_project_id": ""}, 400),
        ({"path": str(inside_hermes)}, 400),
    ]
    for payload, expected in cases:
        response = client.post("/workspace/projects/open", json=payload)
        assert response.status_code == expected, (payload, response.text)

    # Refused requests created no registration and no source metadata.
    assert store.list_projects(store.state_db_path()) == []
    assert list(inside_hermes.iterdir()) == []
    assert not (folder / ".adopt").exists()


def test_open_route_passes_a_matching_core_project_id(tmp_path):
    folder = tmp_path / "core-folder"
    folder.mkdir()
    project_id = _create_core_project("Core Project", [folder], primary_path=folder)

    response = _client().post(
        "/workspace/projects/open",
        json={"path": str(folder), "hermes_project_id": project_id},
    )

    assert response.status_code == 200, response.text
    assert response.json()["project"]["hermes_project_id"] == project_id


def test_open_route_refuses_a_mismatched_core_project_id(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    project_id = _create_core_project("First", [first], primary_path=first)
    store = load_submodule("state_store")

    response = _client().post(
        "/workspace/projects/open",
        json={"path": str(second), "hermes_project_id": project_id},
    )

    assert response.status_code == 400, response.text
    assert "does not match" in response.text
    assert store.list_projects(store.state_db_path()) == []


def test_open_route_duplicate_import_preserves_metadata(tmp_path):
    folder = tmp_path / "custom"
    folder.mkdir()
    store = load_submodule("state_store")
    store.record_project(
        folder,
        "Custom Name",
        "custom-slug",
        "template-x",
        {"building": "web", "layout": "poly", "languages": ["python"]},
        "hp_existing",
        trust_mode="full",
        rules_hash="abc123",
        db_path=store.state_db_path(),
    )

    response = _client().post("/workspace/projects/open", json={"path": str(folder)})

    assert response.status_code == 200, response.text
    project = response.json()["project"]
    assert project["name"] == "Custom Name"
    assert project["template_id"] == "template-x"
    assert project["hermes_project_id"] == "hp_existing"
    assert project["trust_mode"] == "full"


# ---------------------------------------------------------------------------
# GET /workspace/tree
# ---------------------------------------------------------------------------


def test_tree_route_lists_a_registered_project_without_writing(tmp_path):
    root = tmp_path / "registered-project"
    root.mkdir()
    _write(root, "README.md", "# existing\n")
    _write(root, "src/main.py", "print('hello')\n")
    _write(root, ".env", "TOKEN=do-not-leak")
    _write(root, ".git/config", "[core]")
    _write(root, "node_modules/pkg/index.js", "module.exports = 1;")
    _write(root, "src/__pycache__/mod.pyc", b"bytecode")
    (root / "empty").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "secret.txt", "outside-secret")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    db_path = _register(root)
    before_tree = _snapshot(root)
    before_db = db_path.read_bytes()
    before_outside = _snapshot(outside)

    response = _client().get("/workspace/tree", params={"project": str(root)})

    assert response.status_code == 200, response.text
    assert response.json() == {
        "project": str(root.resolve()),
        "files": ["README.md", "src/main.py"],
        "truncated": False,
        "coverage": "verified",
        "omitted": 0,
    }
    assert _snapshot(root) == before_tree
    assert db_path.read_bytes() == before_db
    assert _snapshot(outside) == before_outside


def test_tree_route_refuses_an_unregistered_folder_before_listing(tmp_path, monkeypatch):
    root = tmp_path / "not-registered"
    root.mkdir()
    _write(root, "file.txt")
    tree = load_submodule("project_tree")

    def must_not_run(*args, **kwargs):
        raise AssertionError("tree service ran for an unregistered folder")

    monkeypatch.setattr(tree, "list_project_files", must_not_run)

    response = _client().get("/workspace/tree", params={"project": str(root)})

    assert response.status_code == 400, response.text
    assert "not registered" in response.text.lower()


def test_tree_route_requires_verified_and_unchanged_registrations(tmp_path, monkeypatch):
    root = tmp_path / "registered"
    root.mkdir()
    _write(root, "file.txt")
    _register(root)
    readonly = load_submodule("audit.readonly_db")

    class Snapshot:
        def __init__(self, coverage: str, changed: bool):
            self.coverage = coverage
            self.changed_during_read = changed
            self.records = []

    for snapshot in (Snapshot("could_not_verify", False), Snapshot("verified", True)):
        monkeypatch.setattr(
            readonly,
            "read_profile_registrations_readonly",
            lambda *args, _snapshot=snapshot, **kwargs: _snapshot,
        )
        response = _client().get("/workspace/tree", params={"project": str(root)})
        assert response.status_code == 400, response.text
        assert "could not be verified" in response.text.lower()


@pytest.mark.parametrize(
    "maker",
    [
        lambda tmp: {"project": "relative/path"},
        lambda tmp: {"project": ""},
        lambda tmp: {"project": str(tmp) + "\x00"},
        lambda tmp: {"project": str(tmp / "missing-root")},
    ],
)
def test_tree_route_refuses_malformed_or_missing_roots(tmp_path, maker):
    response = _client().get("/workspace/tree", params=maker(tmp_path))

    assert response.status_code == 400, response.text


def test_tree_route_rejects_missing_query_with_a_4xx(tmp_path):
    response = _client().get("/workspace/tree")

    assert response.status_code == 422, response.text


def test_tree_route_refuses_a_symlink_root_even_when_its_target_is_registered(tmp_path):
    root = tmp_path / "registered"
    root.mkdir()
    _write(root, "file.txt")
    _register(root)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)

    response = _client().get("/workspace/tree", params={"project": str(alias)})

    assert response.status_code == 400, response.text
    assert "symlink" in response.text.lower()


def test_tree_route_refuses_a_registered_regular_file(tmp_path):
    path = tmp_path / "registered-file"
    path.write_text("not a directory", encoding="utf-8")
    _register(path)

    response = _client().get("/workspace/tree", params={"project": str(path)})

    assert response.status_code == 400, response.text
    assert "not a directory" in response.text.lower()
