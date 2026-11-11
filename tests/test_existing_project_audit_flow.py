"""End-to-end existing-project journey: discover, open, then audit only the selected folder.

This is the cross-layer regression the product promises: a project that already lives in
Hermes's core ``projects.db`` can be listed, opened as a reference (never copied or
written), and then audited through the real mounted routes. The audit must use the
selected canonical folder, must not widen to its parent or an unselected registered
sibling, and an ``existing`` project has no template provenance, so the template checks
must stay explicitly unverified rather than passing on an invented baseline.

The public report seals paths, so the source identity is asserted where it is durable:
``AuditStore.get_run(...)['units']`` (``unit_id``/``manifest.root_path``).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import closing
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule

POLL_TIMEOUT_S = 120.0
SIBLING_CANARY = "UNSELECTED_SIBLING_CANARY_7C1E"


def _client() -> TestClient:
    api = load_submodule("dashboard.plugin_api")
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app)


def _create_core_project(name: str, folder: Path) -> str:
    from hermes_cli import projects_db

    with closing(projects_db.connect()) as conn:
        return projects_db.create_project(
            conn,
            name=name,
            slug=name.lower().replace(" ", "-"),
            folders=[str(folder)],
            primary_path=str(folder),
        )


def _write_project(root: Path, marker: str) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "README.md").write_text(f"# {marker}\n", encoding="utf-8")
    (root / ".env").write_text("TOKEN=not-for-evidence\n", encoding="utf-8")


def _snapshot(root: Path) -> dict[str, tuple]:
    """Every entry's type, mode, size, mtime, inode and content (links: target)."""
    manifest: dict[str, tuple] = {}
    for base, dirs, files in os.walk(root):
        for name in sorted([*dirs, *files]):
            path = Path(base) / name
            info = os.lstat(path)
            relative = str(path.relative_to(root))
            if path.is_symlink():
                payload = os.readlink(path)
            elif path.is_file():
                payload = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                payload = None
            manifest[relative] = (
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
                info.st_ino,
                payload,
            )
    return manifest


def _wait_for_completion(client: TestClient, run_id: str) -> dict:
    deadline = time.monotonic() + POLL_TIMEOUT_S
    body: dict = {}
    while time.monotonic() < deadline:
        response = client.get("/audit/status", params={"run_id": run_id})
        assert response.status_code == 200, response.text
        body = response.json()
        if body["status"] != "running":
            return body
        time.sleep(0.05)
    raise AssertionError(f"audit did not finish within {POLL_TIMEOUT_S}s: {body}")


@pytest.fixture()
def journey(tmp_path: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch):
    """A parent folder with a selected project (alias-linked) and an unselected sibling."""
    # Run the journey from a neutral directory: a real user's cwd is not inside the
    # Hermes source tree, and worker pipes must be judged against that cwd.
    monkeypatch.chdir(tmp_path)
    parent = tmp_path / "workspace"
    parent.mkdir()
    selected = parent / "selected-app"
    sibling = parent / "sibling-app"
    _write_project(selected, "selected")
    _write_project(sibling, SIBLING_CANARY)
    alias = tmp_path / "links" / "selected-alias"
    alias.parent.mkdir()
    alias.symlink_to(selected, target_is_directory=True)
    return {
        "home": isolated_home,
        "parent": parent,
        "selected": selected,
        "sibling": sibling,
        "alias": alias,
        "canonical": str(selected.resolve()),
    }


def test_existing_project_discovery_open_and_selected_quick_audit(journey):
    parent, selected, sibling = journey["parent"], journey["selected"], journey["sibling"]
    alias, canonical, home = journey["alias"], journey["canonical"], journey["home"]

    core_id = _create_core_project("Existing Core Project", alias)
    sibling_id = _create_core_project("Sibling Project", sibling)
    selected_before = _snapshot(selected)
    sibling_before = _snapshot(sibling)
    parent_entries_before = sorted(p.name for p in parent.iterdir())

    client = _client()

    # Discovery reads the real core registry read-only and canonicalises the alias.
    available = client.get("/workspace/available-projects")
    assert available.status_code == 200, available.text
    body = available.json()
    assert body["coverage"] == "verified"
    assert "error" not in body
    assert (core_id, canonical) in [(p["id"], p["path"]) for p in body["projects"]]

    # Open registers a reference only; the source folder is untouched.
    opened = client.post(
        "/workspace/projects/open", json={"path": str(alias), "hermes_project_id": core_id}
    )
    assert opened.status_code == 200, opened.text
    project = opened.json()["project"]
    assert opened.json()["status"] == "opened"
    assert project["path"] == canonical
    assert project["name"] == "Existing Core Project"
    assert project["hermes_project_id"] == core_id
    assert project["template_id"] == "existing"
    assert _snapshot(selected) == selected_before
    assert not (selected / ".adopt").exists()

    # A registered sibling exists but is deliberately not selected for the audit.
    sibling_open = client.post(
        "/workspace/projects/open", json={"path": str(sibling), "hermes_project_id": sibling_id}
    )
    assert sibling_open.status_code == 200, sibling_open.text

    # Selected quick audit through the real route: start, then poll real status.
    started = client.post(
        "/audit/start", json={"selected_projects": [str(alias)], "quick": True}
    )
    assert started.status_code == 200, started.text
    start_body = started.json()
    run_id = start_body["run_id"]
    assert isinstance(run_id, str) and run_id
    assert start_body["status"] == "running"

    final = _wait_for_completion(client, run_id)

    assert final["status"] == "completed"
    report_response = client.get("/audit/report", params={"run_id": run_id})
    assert report_response.status_code == 200, report_response.text
    report = report_response.json()["report"]
    assert isinstance(report, dict)
    assert report["headline"]["can_claim_clean"] is False

    # Durable identity: the run contains exactly the selected canonical project, once.
    store = load_submodule("audit.store").AuditStore()
    assert str(store.db_path).startswith(str(home)), "audit state escaped the isolated profile"
    run = store.get_run(run_id)
    assert run is not None
    project_units = [u for u in run["units"] if u["unit_kind"] == "project"]
    assert [u["unit_id"] for u in project_units] == [canonical]
    assert project_units[0]["manifest"]["root_path"] == canonical
    assert str(parent) not in {u["unit_id"] for u in run["units"]}

    # No fake template pass: an "existing" project has no template baseline.
    assert project_units[0]["coverage"] == "could_not_verify"
    assert project_units[0]["status"] == "incomplete"
    project_findings = [f for r in run["unit_results"]
                        if r["unit_kind"] == "project" and r["unit_id"] == canonical
                        for f in r["findings"]]
    template_findings = [f for f in project_findings
                         if f["id"].startswith(("template_drift.", "static_code."))]
    assert {f["id"] for f in template_findings} >= {
        "template_drift.unverified", "static_code.unverified"}
    assert all(f["coverage"] == "could_not_verify" for f in template_findings)
    assert not any(f["coverage"] == "verified" for f in template_findings)

    # The report names the same selected project and nothing outside it, while the
    # unselected sibling's content never becomes evidence.
    report_project_units = [u for u in report["units"] if u["unit_kind"] == "project"]
    assert [u["unit_id"] for u in report_project_units] == [canonical]
    assert report["mode"] == "bounded"
    report_json = json.dumps(report, default=str)
    assert str(sibling.resolve()) not in report_json
    assert SIBLING_CANARY not in report_json

    # Immutability: neither the selected project nor the unselected sibling changed.
    assert _snapshot(selected) == selected_before
    assert _snapshot(sibling) == sibling_before
    assert sorted(p.name for p in parent.iterdir()) == parent_entries_before
    assert not (selected / ".adopt").exists()
    assert not (sibling / ".adopt").exists()
    assert not (parent / ".adopt").exists()
