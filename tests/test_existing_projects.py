"""Safe discovery and explicit registration of already-existing project folders.

Discovery opens the active profile's core projects DB read-only and never migrates it.
Registration records a reference in the Defuzz state DB only; the source folder is never
written, copied, installed, or trusted implicitly.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

import pytest

from tests.conftest import load_submodule


def _core():
    from hermes_cli import projects_db

    return projects_db


def _create_core_project(name, folders, *, primary_path=None, slug=None):
    pdb = _core()
    with closing(pdb.connect()) as conn:
        return pdb.create_project(
            conn, name=name, slug=slug, folders=[str(p) for p in folders],
            primary_path=None if primary_path is None else str(primary_path),
        )


def _archive_core_project(project_id):
    pdb = _core()
    with closing(pdb.connect()) as conn:
        assert pdb.archive_project(conn, project_id) is True


def _core_ids():
    pdb = _core()
    with closing(pdb.connect()) as conn:
        return {p.id: {"name": p.name, "folders": [f.path for f in p.folders]} for p in pdb.list_projects(conn)}


def _snapshot(root: Path):
    """Bytes, mode and mtime for every entry, so any write/touch is visible."""
    entries = {}
    for path in sorted([root, *root.rglob("*")]):
        st = os.lstat(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(st.st_mode) else None
        entries[str(path.relative_to(root))] = (
            stat.S_IFMT(st.st_mode), st.st_mode, st.st_mtime_ns, st.st_size, digest,
        )
    return entries


def _store():
    return load_submodule("state_store")


def test_wal_without_index_is_unverifiable_without_creating_sidecars(tmp_path, monkeypatch):
    ep = load_submodule("existing_projects")
    source = tmp_path / "source.db"
    copied = tmp_path / "copied"
    copied.mkdir()
    target = copied / "projects.db"
    with closing(sqlite3.connect(source)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE evidence (value TEXT)")
        conn.execute("INSERT INTO evidence VALUES ('committed')")
        conn.commit()
        target.write_bytes(source.read_bytes())
        Path(str(target) + "-wal").write_bytes(Path(str(source) + "-wal").read_bytes())
    monkeypatch.setattr(ep, "_core_db_path", lambda: target)
    before = _snapshot(copied)

    result = ep.list_available_projects()

    assert _snapshot(copied) == before
    assert result["coverage"] == "could_not_verify"
    assert result["projects"] == []
    assert "wal_needs_index" in result["error"]
    assert "corrupt" not in result["error"].lower()


@pytest.mark.parametrize("candidate", ["/", "home", "hermes", "relative"])
def test_discovery_filters_folders_that_open_would_refuse(tmp_path, monkeypatch, candidate):
    ep = load_submodule("existing_projects")
    raw = {"/": "/", "home": str(Path.home()), "hermes": os.environ["HERMES_HOME"],
           "relative": "."}[candidate]
    monkeypatch.setattr(ep, "_read_core_projects", lambda: (
        [{"id": "unsafe", "folders": [{"path": raw}]}], "verified", None))
    assert ep.list_available_projects() == {"projects": [], "coverage": "verified"}


def test_discovery_reports_folder_resolution_failure(tmp_path, monkeypatch):
    ep = load_submodule("existing_projects")
    folder = _existing_folder(tmp_path)
    monkeypatch.setattr(ep, "_read_core_projects", lambda: (
        [{"id": "unreadable", "folders": [{"path": str(folder)}]}], "verified", None))
    def denied(path):
        raise OSError("resolution denied")
    monkeypatch.setattr(ep, "_canonical", denied)
    result = ep.list_available_projects()
    assert result["coverage"] == "could_not_verify"
    assert result["projects"] == []
    assert "resolution denied" in result["error"]


@pytest.mark.parametrize("changed", ["main", "wal", "shm"])
def test_registry_mutation_during_sdk_read_is_not_verified(tmp_path, monkeypatch, changed):
    ep = load_submodule("existing_projects")
    folder = _existing_folder(tmp_path)
    _create_core_project("Stable before read", [folder])
    target = Path(os.environ["HERMES_HOME"]) / "projects.db"
    original = _core().list_projects

    def changing_reader(conn):
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        rows = original(conn)
        path = target if changed == "main" else Path(str(target) + "-" + changed)
        if changed == "main":
            st = path.stat()
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
        else:
            path.write_bytes(b"concurrent companion")
        return rows

    monkeypatch.setattr(_core(), "list_projects", changing_reader)
    result = ep.list_available_projects()
    assert result["coverage"] == "could_not_verify"
    assert result["projects"] == []
    assert "race_detected" in result["error"]


def test_missing_core_db_is_verified_empty_and_is_not_created(isolated_home):
    ep = load_submodule("existing_projects")
    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    assert not db_path.exists()

    assert ep.list_available_projects() == {"projects": [], "coverage": "verified"}
    assert not db_path.exists()
    assert not list(db_path.parent.glob("projects.db*"))


def test_corrupt_core_db_is_unavailable_not_invented_empty(isolated_home):
    ep = load_submodule("existing_projects")
    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"this is not sqlite")
    before = db_path.read_bytes()

    result = ep.list_available_projects()

    assert result["projects"] == []
    assert result["coverage"] == "could_not_verify"
    assert result["error"]
    assert db_path.read_bytes() == before


def test_unreadable_or_symlinked_registry_is_not_trusted(tmp_path):
    ep = load_submodule("existing_projects")
    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    real = tmp_path / "elsewhere.db"
    real.write_bytes(b"placeholder")
    db_path.symlink_to(real)

    result = ep.list_available_projects()

    assert result["projects"] == []
    assert result["coverage"] == "could_not_verify"
    assert result["error"]
    assert real.read_bytes() == b"placeholder"

    db_path.unlink()
    db_path.write_bytes(b"unreadable")
    os.chmod(db_path, 0o000)
    try:
        result = ep.list_available_projects()
    finally:
        os.chmod(db_path, 0o600)
    assert result["coverage"] == "could_not_verify"
    assert result["projects"] == []


def test_unsupported_sdk_reader_is_reported_not_invented(monkeypatch):
    ep = load_submodule("existing_projects")
    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("CREATE TABLE sdk_probe (value TEXT)")

    def unsupported(conn, **kwargs):
        raise TypeError("unexpected SDK signature")

    monkeypatch.setattr(_core(), "list_projects", unsupported)
    result = ep.list_available_projects()

    assert result["projects"] == []
    assert result["coverage"] == "could_not_verify"
    assert "unsupported" in result["error"].lower()


def test_lists_nonarchived_projects_dedupes_canonical_folders_and_reads_only(tmp_path):
    ep = load_submodule("existing_projects")
    one = tmp_path / "one"
    two = tmp_path / "two"
    missing = tmp_path / "missing"
    one.mkdir()
    two.mkdir()
    (one / "keep.txt").write_text("keep", encoding="utf-8")
    first_snapshot = _snapshot(one)

    live_id = _create_core_project("Live", [one, two], primary_path=one)
    # Same folder reached through an alias path must collapse to one canonical entry.
    pdb = _core()
    with closing(pdb.connect()) as conn:
        pdb.add_folder(conn, live_id, str(one / ".." / "one"))
    archived_id = _create_core_project("Archived", [missing])
    _archive_core_project(archived_id)

    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    db_before = db_path.read_bytes()
    result = ep.list_available_projects()

    assert result["coverage"] == "verified"
    assert "error" not in result
    projects = result["projects"]
    assert [p["id"] for p in projects] == [live_id]
    listed = projects[0]
    assert listed["id"] == live_id
    assert listed["name"] == "Live"
    assert listed["path"] == str(one.resolve())
    assert listed["primary_path"] == str(one.resolve())
    assert [f["path"] for f in listed["folders"]] == [str(one.resolve()), str(two.resolve())]
    assert all(f["exists"] is True for f in listed["folders"])
    # Missing folders are not advertised as available projects, and archived ones are absent.
    assert all(p["id"] != archived_id for p in projects)
    assert db_path.read_bytes() == db_before
    assert _snapshot(one) == first_snapshot


def test_discovery_uses_only_the_active_profile(tmp_path, monkeypatch):
    ep = load_submodule("existing_projects")
    current = Path(os.environ["HERMES_HOME"])
    other = tmp_path / "other-profile"
    other.mkdir()
    current_src = tmp_path / "current-src"
    other_src = tmp_path / "other-src"
    current_src.mkdir()
    other_src.mkdir()

    monkeypatch.setenv("HERMES_HOME", str(current))
    current_id = _create_core_project("Current", [current_src])

    monkeypatch.setenv("HERMES_HOME", str(other))
    _create_core_project("Other", [other_src])
    other_db = other / "projects.db"
    other_before = other_db.read_bytes()

    monkeypatch.setenv("HERMES_HOME", str(current))
    result = ep.list_available_projects()

    assert result["coverage"] == "verified"
    assert [(p["id"], p["name"]) for p in result["projects"]] == [(current_id, "Current")]
    assert other_db.read_bytes() == other_before


def _existing_folder(tmp_path, name="My Project"):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "README.md").write_text("existing\n", encoding="utf-8")
    return folder


def test_open_registers_reference_without_touching_source(tmp_path):
    ep = load_submodule("existing_projects")
    store = _store()
    folder = _existing_folder(tmp_path)
    before = _snapshot(folder)

    result = ep.open_existing_project(str(folder))

    assert result["status"] == "opened"
    project = result["project"]
    assert project["path"] == str(folder.resolve())
    assert project["name"] == "My Project"
    assert project["slug"] == "my-project"
    assert project["template_id"] == "existing"
    assert project["hermes_project_id"] is None
    assert "languages" not in project or project["languages"] == []
    assert not (folder / ".adopt").exists()
    assert _snapshot(folder) == before

    record = store.get_project(folder)
    assert record is not None
    assert record["template_id"] == "existing"
    assert record["kind"] == "other"
    assert record["layout"] == "single"
    assert record["languages"] == []
    assert record["hermes_project_id"] is None
    assert record["path"] == str(folder.resolve())


def test_duplicate_import_preserves_existing_metadata_and_trust(tmp_path):
    ep = load_submodule("existing_projects")
    store = _store()
    folder = _existing_folder(tmp_path)
    store.record_project(
        folder, "Custom Name", "custom-slug", "template-x",
        {"building": "web", "layout": "poly", "languages": ["python"]},
        "hp_existing", trust_mode="full", rules_hash="abc123", prefix="pref",
        locked_hashes={"a": "b"},
    )
    before = store.get_project(folder)
    source_before = _snapshot(folder)

    result = ep.open_existing_project(str(folder))

    assert result["status"] == "opened"
    assert result["project"]["name"] == "Custom Name"
    assert result["project"]["template_id"] == "template-x"
    after = store.get_project(folder)
    for key in ("name", "slug", "template_id", "kind", "layout", "languages",
                "hermes_project_id", "trust_mode", "rules_hash", "prefix",
                "locked_hashes", "created_at"):
        assert after[key] == before[key]
    assert _snapshot(folder) == source_before


def test_hermes_project_id_only_accepted_when_it_matches_core_folder(tmp_path):
    ep = load_submodule("existing_projects")
    store = _store()
    folder = _existing_folder(tmp_path, "Matching")
    other = _existing_folder(tmp_path, "Other")
    core_id = _create_core_project("Core Display", [folder], primary_path=folder)
    other_id = _create_core_project("Other Display", [other], primary_path=other)

    # Supplied id names a different project -> refuse before registering anything.
    with pytest.raises(load_submodule("safety").SafetyError):
        ep.open_existing_project(str(folder), hermes_project_id=other_id)
    assert store.get_project(folder) is None

    # Unknown id -> refuse as well.
    with pytest.raises(load_submodule("safety").SafetyError):
        ep.open_existing_project(str(folder), hermes_project_id="p_does-not-exist")
    assert store.get_project(folder) is None

    result = ep.open_existing_project(str(folder), hermes_project_id=core_id)
    assert result["project"]["hermes_project_id"] == core_id
    assert result["project"]["name"] == "Core Display"
    assert store.get_project(folder)["hermes_project_id"] == core_id


def test_unmatched_core_record_is_detected_without_an_explicit_id(tmp_path):
    ep = load_submodule("existing_projects")
    folder = _existing_folder(tmp_path, "Core Named")
    core_id = _create_core_project("Display Name", [folder], primary_path=folder)

    result = ep.open_existing_project(folder)

    assert result["project"]["hermes_project_id"] == core_id
    assert result["project"]["name"] == "Display Name"


def test_open_leaves_the_core_registry_unchanged(tmp_path):
    ep = load_submodule("existing_projects")
    folder = _existing_folder(tmp_path, "Core Stable")
    _create_core_project("Stable", [folder], primary_path=folder)
    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    before_db = db_path.read_bytes()
    before_ids = _core_ids()

    ep.open_existing_project(str(folder))

    assert db_path.read_bytes() == before_db
    assert _core_ids() == before_ids


def test_unverifiable_core_db_rejects_supplied_id_and_does_not_register(tmp_path):
    ep = load_submodule("existing_projects")
    store = _store()
    folder = _existing_folder(tmp_path, "Corrupt Core")
    db_path = Path(os.environ["HERMES_HOME"]) / "projects.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"broken")

    with pytest.raises(load_submodule("safety").SafetyError):
        ep.open_existing_project(str(folder), hermes_project_id="p_anything")
    assert store.get_project(folder) is None


@pytest.mark.parametrize("maker", [
    lambda tmp: "",
    lambda tmp: "   ",
    lambda tmp: "relative/path",
    lambda tmp: "./also-relative",
    lambda tmp: str(tmp / "nul\x00path"),
    lambda tmp: str(tmp / "missing"),
    lambda tmp: str(tmp / "not-a-dir"),
])
def test_invalid_paths_are_refused(tmp_path, maker):
    ep = load_submodule("existing_projects")
    safety = load_submodule("safety")
    (tmp_path / "not-a-dir").write_text("file", encoding="utf-8")
    value = maker(tmp_path)

    with pytest.raises(safety.SafetyError):
        ep.open_existing_project(value)


def test_root_home_and_hermes_home_are_refused(tmp_path):
    ep = load_submodule("existing_projects")
    safety = load_submodule("safety")
    hermes_home = Path(os.environ["HERMES_HOME"])
    inside_hermes = hermes_home / "some-project"
    inside_hermes.mkdir(parents=True, exist_ok=True)

    for candidate in ("/", str(Path.home()), str(inside_hermes), "~"):
        with pytest.raises(safety.SafetyError):
            ep.open_existing_project(candidate)


def test_secret_named_files_are_neither_read_nor_changed(tmp_path):
    ep = load_submodule("existing_projects")
    folder = _existing_folder(tmp_path, "Has Secrets")
    (folder / ".env").write_text("TOKEN=super-secret\n", encoding="utf-8")
    (folder / "credentials.json").write_text('{"token": "secret"}\n', encoding="utf-8")
    before = _snapshot(folder)

    result = ep.open_existing_project(str(folder))

    assert result["status"] == "opened"
    assert _snapshot(folder) == before


def test_listing_does_not_use_sdk_connect_or_mutators(monkeypatch):
    ep = load_submodule("existing_projects")
    pdb = _core()
    calls = []
    monkeypatch.setattr(pdb, "connect", lambda *a, **k: calls.append(("connect", a, k)))
    monkeypatch.setattr(pdb, "create_project", lambda *a, **k: calls.append(("create", a, k)))
    monkeypatch.setattr(pdb, "add_folder", lambda *a, **k: calls.append(("add", a, k)))
    monkeypatch.setattr(pdb, "update_project", lambda *a, **k: calls.append(("update", a, k)))

    assert ep.list_available_projects() == {"projects": [], "coverage": "verified"}
    assert calls == []
