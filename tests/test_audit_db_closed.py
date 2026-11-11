"""Synthetic database association disclosure; never opens a user's stores."""
import hashlib
import json
import sqlite3

from tests.conftest import load_submodule

inspect_database = load_submodule('audit.outward_db').inspect_database


def token(value):
    return hashlib.sha256(value.encode()).hexdigest()


def test_selected_secondary_folder_returns_all_registered_folders(tmp_path):
    db = tmp_path / 'projects.db'
    with sqlite3.connect(db) as conn:
        conn.executescript('''
            CREATE TABLE projects(id TEXT, slug TEXT, primary_path TEXT, name TEXT);
            CREATE TABLE project_folders(project_id TEXT, path TEXT, label TEXT);
            INSERT INTO projects VALUES ('private-id', 'private-slug', '/selected', 'SECRET');
            INSERT INTO projects VALUES ('other', 'other', '/unrelated', 'SECRET');
            INSERT INTO project_folders VALUES ('private-id', '/secondary', 'SECRET');
            INSERT INTO project_folders VALUES ('private-id', '/third', 'SECRET');
        ''')
    result = inspect_database(db, selected_projects=['/secondary/subdir'], scratch_dir=tmp_path)
    assert {r['path'] for r in result['folder_references']} == {'/selected', '/secondary', '/third'}
    assert {r['project_id_sha256'] for r in result['folder_references']} == {token('private-id')}
    assert len(result['associations']) == 4
    assert 'SECRET' not in json.dumps(result)
    assert 'private-id' not in json.dumps(result)


def test_shared_kanban_wal_discloses_cross_profile_links_not_contents(tmp_path):
    db = tmp_path / 'kanban.db'
    conn = sqlite3.connect(db)
    try:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript('''
            CREATE TABLE tasks(id TEXT, title TEXT, body TEXT, status TEXT,
                workspace_path TEXT, project_id TEXT, tenant TEXT, assignee TEXT);
            INSERT INTO tasks VALUES ('task-secret', 'TITLE SECRET', 'BODY SECRET',
                'todo', '/work', 'private-project', 'profile-a', 'profile-b');
            INSERT INTO tasks VALUES ('task-2', 'TITLE SECRET', 'BODY SECRET',
                'todo', NULL, 'other-project', 'profile-c', NULL);
        ''')
        before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if not p.name.endswith('-shm')}
        before_names = {p.name for p in tmp_path.iterdir()}
        result = inspect_database(db, selected_projects=['/work'], scratch_dir=tmp_path)
        assert len(result['associations']) == 2
        task = result['associations'][0]
        assert task['id_sha256'] == token('task-secret')
        assert task['project_id_sha256'] == token('private-project')
        assert task['tenant_sha256'] == token('profile-a')
        assert task['assignee_sha256'] == token('profile-b')
        assert task['title_sha256'] == token('TITLE SECRET')
        assert all(s not in json.dumps(result) for s in ('SECRET', 'task-secret', 'private-project', 'profile-a', 'profile-b'))
        assert {p.name for p in tmp_path.iterdir()} == before_names
        assert {p.name: p.read_bytes() for p in tmp_path.iterdir() if not p.name.endswith('-shm')} == before
        limited = inspect_database(db, row_limit=1, scratch_dir=tmp_path)
        assert limited['limits']['truncated']
        assert len(limited['associations']) == 1
        assert limited['associations'][0] == task
    finally:
        conn.close()
