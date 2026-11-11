"""Real capture with locked hashes, behaviour when the audit key is unavailable, and where a store keeps its key."""
import os
import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('changed', [False, True])
def test_audit_real_capture_locked_hash_compatibility(tmp_path, monkeypatch, changed):
    surface = load_submodule('audit_surface')
    capture = load_submodule('audit.capture')
    key = load_submodule('audit.key')
    templates = load_submodule('templates')
    home, project, template = (tmp_path / n for n in ('home', 'project', 'template'))
    for path in (home, project, template / 'repo'):
        path.mkdir(parents=True)
    monkeypatch.setenv('HERMES_HOME', str(home))
    original = b'# INERT_LOCKED_CONTENT_ORIGINAL\n'
    content = b'# INERT_LOCKED_CONTENT_CHANGED\n' if changed else original
    (project / 'guard.md').write_bytes(content)
    (template / 'repo' / 'guard.md').write_bytes(original)
    provenance = {'template_id': 'python-golden', 'plugin_commit': 'inert-commit',
                  'prefix': 'demo', 'locked_hashes': {'guard.md': hashlib.sha256(original).hexdigest()}}
    db = tmp_path / 'store' / 'audit.db'
    with key.key_scope(db):
        manifest, files = capture.capture_project_files(project)
        tm, tf = capture.capture_project_files(template / 'repo')
        direct = surface.template_drift.audit_template_drift(
            provenance=provenance, project_id=str(project), project_files=files,
            template_files=tf, template_spec={'id': 'python-golden', 'placeholder': 'tmpl_prefix', 'locked': ['guard.md']})
    assert ('template.locked_hash_drift' in [f['id'] for f in direct['findings']]) == changed
    original_inventory = surface._active_inventory
    def inventory(*args):
        result = original_inventory(*args)
        result['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified', 'registrations': [provenance]}]
        return result
    monkeypatch.setattr(surface, '_active_inventory', inventory)
    monkeypatch.setattr(templates, 'load_templates', lambda **kwargs: [SimpleNamespace(
        id='python-golden', placeholder='tmpl_prefix', locked=['guard.md'], approved_deps={},
        repos=[SimpleNamespace(name='repo')], root=template)])
    result = surface.execute_audit({'quick': True, 'as_of': 1800000000,
                                   'selected_projects': [str(project)]}, db_path=db, wait=True)
    assert result['status'] == 'completed'
    assert ('template.locked_hash_drift' in [f['id'] for f in result['report']['findings']]) == changed
    with sqlite3.connect(db) as conn:
        dump = '\n'.join(conn.iterdump()).encode()
    surfaces = [json.dumps(result).encode(), json.dumps(manifest).encode(), dump, db.read_bytes()]
    for raw in (content, original):
        for output in surfaces:
            assert raw.strip() not in output
            assert hashlib.sha256(raw).hexdigest().encode() not in output


@pytest.mark.parametrize('damage', ['directory', 'fifo', 'symlink', 'permission', 'lock_directory'])
def test_audit_unavailable_key_closed_and_reports_readable(tmp_path, monkeypatch, damage):
    surface = load_submodule('audit_surface')
    key = load_submodule('audit.key')
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    db = tmp_path / 'store' / 'audit.db'
    result = surface.execute_audit({'quick': True, 'as_of': 1800000000}, db_path=db, wait=True)
    path = key.key_path(db)
    target = db.parent / 'target'
    target.write_bytes(b'INERT_UNTOUCHED_TARGET')
    if damage in ('directory', 'fifo', 'symlink'):
        path.unlink()
        if damage == 'directory':
            path.mkdir()
            (path / 'keep').write_bytes(b'INERT_KEEP_DIRECTORY_CONTENT')
        elif damage == 'fifo':
            os.mkfifo(path)
        else:
            path.symlink_to(target)
    elif damage == 'lock_directory':
        lock = path.with_name('audit.key.lock')
        lock.unlink()
        lock.mkdir()
    else:
        original_open = key.os.open
        def denied(name, *args, **kwargs):
            if os.fspath(name) == str(path):
                raise PermissionError('INERT_PRIVATE_ERROR')
            return original_open(name, *args, **kwargs)
        monkeypatch.setattr(key.os, 'open', denied)
    for action in ('status', 'report'):
        saved = surface.execute_audit({'action': action, 'run_id': result['run_id']}, db_path=db)
        # run_metrics are returned by the run itself only and are never stored.
        assert saved == {k: v for k, v in result.items() if k != 'run_metrics'}
    resumed = surface.execute_audit({'action': 'resume', 'run_id': result['run_id']}, db_path=db, wait=True)
    assert resumed['resume_reason'] == 'audit_key_unavailable'
    assert resumed['status'] == 'completed'
    fresh = surface.execute_audit({'quick': True}, db_path=db, wait=True)
    assert fresh['reason'] == 'audit_key_unavailable'
    assert fresh['status'] == 'failed'
    assert target.read_bytes() == b'INERT_UNTOUCHED_TARGET'
    if damage == 'directory':
        assert (path / 'keep').read_bytes() == b'INERT_KEEP_DIRECTORY_CONTENT'
    if damage == 'fifo':
        import stat
        assert stat.S_ISFIFO(path.lstat().st_mode)
    if damage == 'symlink':
        assert path.is_symlink()



def test_store_migration_digests_use_the_key_beside_the_store(tmp_path, monkeypatch):
    """A store kept outside the Hermes home never creates its key inside the Hermes home."""
    store = load_submodule('audit.store')
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    db = tmp_path / 'elsewhere' / 'audit.db'
    original = store._migrate_audit_schema

    def migrate_and_digest(conn):
        original(conn)
        store.control_digest('unit-under-migration')
    monkeypatch.setattr(store, '_migrate_audit_schema', migrate_and_digest)
    store.ensure_audit_tables(db)
    assert (db.parent / 'audit.key').is_file()
    assert not (home / 'plugin-data' / 'defuzz' / 'audit.key').exists()
