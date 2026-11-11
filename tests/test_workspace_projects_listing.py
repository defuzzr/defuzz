"""Workspace project listing and explicit registration forget API.

The workspace page lists only registrations whose folder still is a directory; the
remaining registrations are reported separately and never removed automatically.
"""
from __future__ import annotations

import os
import sqlite3

from tests.conftest import load_submodule


def _client():
    api = load_submodule('dashboard.plugin_api')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app)


def _register(store, path, name):
    store.record_project(path, name, name.lower(), None, {}, None,
                         db_path=store.state_db_path())


def _insert_registration(store, stored_path, name):
    """Store an exact legacy/alias registration identifier without normalisation."""
    db = store.state_db_path()
    store.list_projects(db)  # initialize the schema before the exact raw insert
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO projects (path, name, slug, languages, created_at) VALUES (?, ?, ?, ?, ?)",
            (stored_path, name, name.lower(), '[]', 0),
        )


def _make_projects(tmp_path):
    """An existing folder, a missing path, a regular file and an unreadable parent."""
    store = load_submodule('state_store')
    base = tmp_path / 'space'
    base.mkdir()
    existing = base / 'exists'
    existing.mkdir()
    (existing / 'keep.txt').write_text('keep me', encoding='utf-8')
    missing = base / 'missing'
    regular = base / 'regular'
    regular.write_text('not a folder', encoding='utf-8')
    blocked_parent = base / 'blocked'
    blocked_parent.mkdir()
    blocked = blocked_parent / 'project'
    blocked.mkdir()
    for path, name in ((existing, 'Exists'), (missing, 'Missing'),
                       (regular, 'Regular'), (blocked, 'Blocked')):
        _register(store, path, name)
    return store, base, existing, missing, regular, blocked_parent, blocked


def test_workspace_projects_lists_only_existing_directories(tmp_path):
    store, base, existing, missing, regular, blocked_parent, blocked = _make_projects(tmp_path)
    os.chmod(blocked_parent, 0o000)
    try:
        response = _client().get('/workspace/projects')
    finally:
        os.chmod(blocked_parent, 0o700)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body['coverage'] == 'verified'
    assert {p['canonical_path'] for p in body['projects']} == {str(existing)}
    assert 'folder_status' not in body['projects'][0]
    by_path = {p['canonical_path']: p['folder_status'] for p in body['unavailable_projects']}
    assert by_path == {
        str(missing): 'missing',
        str(regular): 'not_directory',
        str(blocked): 'unavailable',
    }
    # Classification is read-only: the registered folders are all still there.
    assert (existing / 'keep.txt').read_text(encoding='utf-8') == 'keep me'
    assert regular.read_text(encoding='utf-8') == 'not a folder'


def test_workspace_projects_keeps_stale_records_for_audit_reader(tmp_path):
    store, base, existing, missing, regular, blocked_parent, blocked = _make_projects(tmp_path)
    from hermes_constants import get_hermes_home
    readonly_db = load_submodule('audit.readonly_db')

    snapshot = readonly_db.read_profile_registrations_readonly('active', get_hermes_home())
    assert {r['canonical_path'] for r in snapshot.records} == {
        str(existing), str(missing), str(regular), str(blocked)}
    # The route lists all records too: unavailable ones are separated, never dropped silently.
    body = _client().get('/workspace/projects').json()
    assert len(body['projects']) + len(body['unavailable_projects']) == 4


def test_forget_removes_only_the_matching_registration_and_no_files(tmp_path):
    store = load_submodule('state_store')
    first = tmp_path / 'first'
    second = tmp_path / 'second'
    for folder, name in ((first, 'First'), (second, 'Second')):
        folder.mkdir()
        (folder / 'file.txt').write_text(name, encoding='utf-8')
        _register(store, folder, name)

    client = _client()
    response = client.post('/workspace/projects/forget', json={'path': str(first)})
    assert response.status_code == 200, response.text
    assert response.json() == {'status': 'forgotten', 'removed': True}
    remaining = {p['path'] for p in store.list_projects(store.state_db_path())}
    assert remaining == {str(second)}
    # No filesystem effect, including on the forgotten project's own folder.
    assert (first / 'file.txt').read_text(encoding='utf-8') == 'First'
    assert (second / 'file.txt').read_text(encoding='utf-8') == 'Second'

    # Idempotent: forgetting again still reports forgotten and changes nothing.
    again = client.post('/workspace/projects/forget', json={'path': str(first)})
    assert again.status_code == 200
    assert again.json() == {'status': 'forgotten', 'removed': False}
    assert {p['path'] for p in store.list_projects(store.state_db_path())} == {str(second)}


def test_forget_uses_the_exact_raw_path_the_listing_reports(tmp_path):
    store = load_submodule('state_store')
    folder = tmp_path / 'listed'
    folder.mkdir()
    _register(store, folder, 'Listed')

    client = _client()
    projects = client.get('/workspace/projects').json()['projects']
    assert len(projects) == 1
    response = client.post('/workspace/projects/forget', json={'path': projects[0]['raw_path']})
    assert response.status_code == 200
    assert response.json() == {'status': 'forgotten', 'removed': True}
    assert store.list_projects(store.state_db_path()) == []


def test_forget_removes_exactly_one_identical_canonical_peer(tmp_path):
    store = load_submodule('state_store')
    folder = tmp_path / 'real-project'
    folder.mkdir()
    _register(store, folder, 'Real')
    alias = tmp_path / 'alias-project'
    alias.symlink_to(folder, target_is_directory=True)
    _insert_registration(store, str(alias), 'Alias')

    client = _client()
    listing = client.get('/workspace/projects').json()
    # Both rows name the same canonical folder; the listing must not dedupe registrations.
    assert {p['raw_path'] for p in listing['projects']} == {str(folder), str(alias)}
    assert len(listing['projects']) == 2

    response = client.post('/workspace/projects/forget', json={'path': str(alias)})
    assert response.status_code == 200
    assert response.json() == {'status': 'forgotten', 'removed': True}
    # Only the explicit alias row was removed; its canonical peer is untouched.
    assert [p['path'] for p in store.list_projects(store.state_db_path())] == [str(folder)]
    assert folder.is_dir() and alias.is_symlink()

    response = client.post('/workspace/projects/forget', json={'path': str(folder)})
    assert response.json() == {'status': 'forgotten', 'removed': True}
    assert store.list_projects(store.state_db_path()) == []


def test_forget_treats_an_alias_as_an_unmatched_identifier(tmp_path):
    store = load_submodule('state_store')
    folder = tmp_path / 'real-project'
    folder.mkdir()
    _register(store, folder, 'Real')
    alias = tmp_path / 'alias-project'
    alias.symlink_to(folder, target_is_directory=True)

    client = _client()
    response = client.post('/workspace/projects/forget', json={'path': str(alias)})
    assert response.status_code == 200
    assert response.json() == {'status': 'forgotten', 'removed': False}
    assert [p['path'] for p in store.list_projects(store.state_db_path())] == [str(folder)]
    assert folder.is_dir() and alias.is_symlink()


def test_forget_preserves_trailing_space_in_the_identifier(tmp_path):
    store = load_submodule('state_store')
    folder = tmp_path / 'spaced-project '
    folder.mkdir()
    _register(store, folder, 'Spaced')
    stored = [p['path'] for p in store.list_projects(store.state_db_path())]
    assert stored == [str(folder)]

    client = _client()
    response = client.post('/workspace/projects/forget', json={'path': str(folder)})
    assert response.json() == {'status': 'forgotten', 'removed': True}
    assert store.list_projects(store.state_db_path()) == []


def test_forget_never_touches_another_profile_state_db(tmp_path):
    store = load_submodule('state_store')
    active = tmp_path / 'active-project'
    sibling = tmp_path / 'sibling-project'
    for folder, name in ((active, 'Active'), (sibling, 'Sibling')):
        folder.mkdir()
    _register(store, active, 'Active')
    sibling_db = tmp_path / 'sibling-profile' / 'plugin-data' / 'defuzz' / 'state.db'
    store.record_project(sibling, 'Sibling', 'sibling', None, {}, None, db_path=sibling_db)

    response = _client().post('/workspace/projects/forget', json={'path': str(sibling)})
    assert response.status_code == 200
    assert response.json() == {'status': 'forgotten', 'removed': False}
    # The sibling profile registration survives; only the active profile DB was in scope.
    assert [p['path'] for p in store.list_projects(sibling_db)] == [str(sibling)]
    assert [p['path'] for p in store.list_projects(store.state_db_path())] == [str(active)]


def test_listing_preserves_a_whitespace_ending_raw_path_for_exact_forget(tmp_path):
    store = load_submodule('state_store')
    folder = tmp_path / 'spaced-project '
    folder.mkdir()
    (folder / 'keep.txt').write_text('keep', encoding='utf-8')
    _register(store, folder, 'Spaced')

    client = _client()
    listing = client.get('/workspace/projects').json()
    assert len(listing['projects']) == 1
    listed = listing['projects'][0]
    # The exact stored identifier must survive the read-only listing unchanged, so a
    # client can hand the same string back to forget.
    assert listed['raw_path'] == str(folder)
    assert listed['canonical_path'] == str(folder)

    response = client.post('/workspace/projects/forget', json={'path': listed['raw_path']})
    assert response.status_code == 200, response.text
    assert response.json() == {'status': 'forgotten', 'removed': True}
    assert store.list_projects(store.state_db_path()) == []
    # Only the registration row changed; the project folder and its file survive.
    assert (folder / 'keep.txt').read_text(encoding='utf-8') == 'keep'


def test_forget_deletes_legacy_relative_and_tilde_identifiers_verbatim(tmp_path):
    store = load_submodule('state_store')
    db = store.state_db_path()
    _insert_registration(store, 'relative/folder', 'Relative')
    _insert_registration(store, '~/project', 'Tilde')
    _insert_registration(store, str(tmp_path / 'keep'), 'Keep')

    # These legacy spellings are stored identifiers, never filesystem paths. Any
    # nonempty NUL-free string is an exact SQL delete key; no absolute check applies.
    assert store.forget_project('relative/folder', db_path=db) is True
    assert store.forget_project('~/project', db_path=db) is True
    assert [p['path'] for p in store.list_projects(db)] == [str(tmp_path / 'keep')]
    # The legacy spellings were never used as paths, so nothing on disk was touched.
    assert not (tmp_path / 'relative').exists()
    assert not (tmp_path / 'project').exists()


def test_forget_missing_state_db_creates_nothing(tmp_path):
    store = load_submodule('state_store')
    missing = tmp_path / 'absent-profile' / 'plugin-data' / 'defuzz' / 'state.db'

    assert store.forget_project('/any/identifier', db_path=missing) is False
    # No profile directory, database, journal, WAL or lock may be created.
    assert not (tmp_path / 'absent-profile').exists()


def test_forget_default_missing_state_db_creates_nothing(tmp_path, monkeypatch):
    store = load_submodule('state_store')
    home = tmp_path / 'fresh-home'
    monkeypatch.setenv('HERMES_HOME', str(home))

    assert store.forget_project('/any/identifier') is False
    # The default resolution must not run state_db_path(), which creates and migrates.
    assert not home.exists()


def test_forget_leaves_a_minimal_old_schema_unchanged(tmp_path):
    store = load_submodule('state_store')
    db = tmp_path / 'old-profile' / 'plugin-data' / 'defuzz' / 'state.db'
    db.parent.mkdir(parents=True)
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT)')
        conn.execute("INSERT INTO projects VALUES ('legacy/relative', 'Legacy')")
    with sqlite3.connect(db) as conn:
        before = [row[1] for row in conn.execute('PRAGMA table_info(projects)')]
    assert before == ['path', 'name']

    assert store.forget_project('legacy/relative', db_path=db) is True
    with sqlite3.connect(db) as conn:
        after = [row[1] for row in conn.execute('PRAGMA table_info(projects)')]
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        remaining = conn.execute('SELECT count(*) FROM projects').fetchone()[0]
    # The delete connection neither initialises tables nor migrates old columns.
    assert after == before
    assert tables == {'projects'}
    assert remaining == 0
    assert set(os.listdir(db.parent)) == {'state.db'}


def test_forget_route_rejects_invalid_request_shapes(tmp_path):
    store = load_submodule('state_store')
    folder = tmp_path / 'keep'
    folder.mkdir()
    _register(store, folder, 'Keep')
    client = _client()
    # Shape validation remains: only a nonempty, NUL-free string can be an identifier.
    for body in ({'path': ''}, {'path': 5}, {'path': None}, {},
                 [], ['path'], {'path': '/tmp/with\x00nul'}):
        response = client.post('/workspace/projects/forget', json=body)
        assert response.status_code == 400, (body, response.text)
    assert [p['path'] for p in store.list_projects(store.state_db_path())] == [str(folder)]
