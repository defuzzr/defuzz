"""End-to-end project-outward scope and persistence contract."""
import json
import sys
import os
import sqlite3
from pathlib import Path
from tests.conftest import load_submodule


def test_default_selected_project_outward_scope(tmp_path, monkeypatch):
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *args, **kwargs:
                        discover(*args, **kwargs, system_config=tmp_path / 'absent-gitconfig'))
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home'
    home.mkdir()
    home = home / '.hermes'
    home.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    sibling = home / 'profiles' / 'blended'
    sibling.mkdir(parents=True)
    (sibling / 'config.yaml').write_text('{}')
    (sibling / 'skills' / 'shared').mkdir(parents=True)
    (sibling / 'skills' / 'shared' / 'SKILL.md').write_text('Shared skill')
    (sibling / 'plugins').mkdir()
    (sibling / 'plugins' / 'plugin.yaml').write_text('name: synthetic')
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    (unrelated / 'private').write_text('DO NOT READ')
    (project / 'shared').symlink_to(sibling, target_is_directory=True)
    (home / 'config.yaml').write_text('{}')
    for name in ('skills', 'plugins', 'sessions', 'memories'):
        (home / name).mkdir()
        (home / name / 'sample.txt').write_text('Synthetic sample')
    (home / 'SOUL.md').write_text('Synthetic identity')
    with sqlite3.connect(home / 'state.db') as conn:
        conn.execute('CREATE TABLE sessions (cwd TEXT, git_repo_root TEXT, started_at INTEGER)')
        conn.execute('INSERT INTO sessions VALUES (?, ?, ?)', (str(project / 'src'), str(project), 123))
    secret = 'FAKE-CREDENTIAL-MUST-NEVER-PERSIST-81288'
    (home / 'auth.json').write_text(json.dumps({'token': secret}))
    monkeypatch.setenv('HERMES_HOME', str(home))
    original_inventory = surface._active_inventory
    def inventory(*args):
        value = original_inventory(*args)
        value['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
        return value
    monkeypatch.setattr(surface, '_active_inventory', inventory)
    enabled = [True]
    def guard(event, args):
        if enabled[0] and event == 'open' and isinstance(args[0], (str, bytes)):
            assert not str(args[0]).startswith(str(unrelated))
    sys.addaudithook(guard)
    real_open = os.open
    reads = []
    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / path if dir_fd is not None else Path(path)
        assert not full.is_relative_to(unrelated)
        if not flags & os.O_DIRECTORY:
            reads.append(str(full))
        return real_open(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(os, 'open', guarded_open)
    db = home / 'plugin-data' / 'defuzz' / 'audit.db'
    try:
        result = surface.execute_audit({'action': 'run', 'root': str(project)}, db_path=db, wait=True)
    finally:
        enabled[0] = False
    assert result['status'] == 'completed'
    assert str(sibling / 'skills' / 'shared' / 'SKILL.md') in reads
    assert str(sibling / 'plugins' / 'plugin.yaml') in reads
    assert result['report']['session_history']['selected_project_records'] == 1
    scope = result['report']['scope']
    assert scope['description'] == 'Project-outward full static audit'
    assert scope['coverage'] == 'could_not_verify', scope
    assert scope['regions']['credentials']['coverage'] == 'could_not_verify', scope
    assert 'credential_store_not_opened' in json.dumps(scope)
    assert any(b['target'] == str(sibling) and b['relationship'] == 'symlink' for b in result['report']['blending'])
    assert any(f['id'] == 'audit.blending' for f in result['report']['findings'])
    assert scope['max_file_bytes'] > 0
    assert result['report']['credentials'][0]['kind'] == 'credential_store'
    assert 'fingerprint' not in result['report']['credentials'][0]
    assert surface.execute_audit({'action': 'report', 'run_id': result['run_id']}, db_path=db)['report'] == result['report']
    for file in db.parent.rglob('*'):
        if file.is_file():
            assert secret.encode() not in file.read_bytes()


def test_quick_is_explicit_and_default_does_not_select_unrelated_projects(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    store = surface.AuditStore(tmp_path / 'output' / 'audit.db')
    prepared = surface._prepare(store, {})
    assert prepared[-1] is True
    assert prepared[3] == []
    quick = surface._prepare(store, {'quick': True})
    assert quick[-1] is False
