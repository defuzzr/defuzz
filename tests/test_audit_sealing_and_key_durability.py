"""Sealed-string forgery, rule ids, restart resume and audit key durability regressions; inert fixtures only."""
import json
import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('typename', ['GeneratedDigest', 'ControlIdentity', 'PersistedJSON', 'SealedKey'])
def test_audit_privileged_string_forgery(typename):
    e = load_submodule('audit.evidence')
    store = load_submodule('audit.store')
    value = str.__new__(getattr(e, typename), 'INERT_FORGED_LEAF_CANARY')
    assert 'INERT_FORGED_LEAF_CANARY' not in json.dumps(e.EvidenceSerializer().serialize(value))
    assert 'INERT_FORGED_LEAF_CANARY' not in store._dto_json({'evidence': value})
    assert 'INERT_FORGED_LEAF_CANARY' not in store._source_text(value)


@pytest.mark.parametrize('mode', ['quick', 'full', 'error'])
def test_audit_all_emitted_rule_ids(mode, tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    e = load_submodule('audit.evidence')
    home = tmp_path / 'home'
    home.mkdir()
    (home / 'config.yaml').write_text('{}')
    monkeypatch.setenv('HERMES_HOME', str(home))
    if mode == 'error':
        def broken(**kwargs):
            raise ValueError('INERT_COLLECTOR_FAILURE')
        monkeypatch.setattr(surface.memory, 'audit_profile_memory', broken)
    result = surface.execute_audit({'quick': mode != 'full', 'as_of': 1800000000},
                                   db_path=tmp_path / 'audit.db', wait=True)
    ids = [f['id'] for f in result['report']['findings']]
    assert ids
    assert all(type(rule) is str and rule in e.RULE_IDS for rule in ids), ids
    for component in ('audit_scope', 'profile_context', 'memory', 'executable_inventory', 'template_drift', 'static_code'):
        raw = surface._component(component, 'system', lambda: (_ for _ in ()).throw(ValueError()))
        assert all(f['id'] in e.RULE_IDS for f in raw['findings'])


def test_audit_natural_content_hash_not_persisted(tmp_path, monkeypatch):
    import hashlib
    import sqlite3
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home'
    home.mkdir()
    content = b'api_key: INERT_LOW_ENTROPY_ALPHA\n'
    (home / 'config.yaml').write_bytes(content)
    monkeypatch.setenv('HERMES_HOME', str(home))
    db = tmp_path / 'store' / 'audit.db'
    surface.execute_audit({'quick': True, 'as_of': 1800000000}, db_path=db, wait=True)
    with sqlite3.connect(db) as conn:
        dump = '\n'.join(conn.iterdump()).encode()
    for candidate in (content, b'api_key: INERT_LOW_ENTROPY_BETA\n'):
        plain = hashlib.sha256(candidate).hexdigest().encode()
        assert plain not in dump
        assert plain not in db.read_bytes()


import subprocess
import sys

_RESUME_SCRIPT = r'''
import json, sys, threading
from pathlib import Path
from tests.conftest import load_submodule
surface = load_submodule('audit_surface')
db, home, phase, kind = sys.argv[1:]
db, home = Path(db), Path(home)
project = home / ('missing' if kind == 'missing' else 'project')
if kind != 'missing':
    project.mkdir(exist_ok=True)
original_inventory = surface._active_inventory
def inventory(*args):
    value = original_inventory(*args)
    value['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
    return value
surface._active_inventory = inventory
if phase == 'seed':
    entered, release = threading.Event(), threading.Event()
    original_sweep = surface._sweep
    def paused(*args):
        entered.set()
        assert release.wait(20)
        return original_sweep(*args)
    surface._sweep = paused
    initial = surface.execute_audit({'quick': True, 'as_of': 1800000000,
        'selected_projects': [str(project)]}, db_path=db)
    assert entered.wait(20)
    rid = initial['run_id']
    assert surface.execute_audit({'action': 'cancel', 'run_id': rid}, db_path=db)['status'] == 'cancelled'
    release.set()
    assert surface._RUN_LOCK.acquire(timeout=20)
    surface._RUN_LOCK.release()
    (home / 'run_id').write_text(rid)
else:
    rid = (home / 'run_id').read_text()
    result = surface.execute_audit({'action': 'resume', 'run_id': rid}, db_path=db, wait=True)
    assert result['status'] == 'completed', result
    assert result['as_of'] == 1800000000
print('ok')
'''


@pytest.mark.parametrize('kind', ['existing', 'missing'])
def test_audit_public_restart_resume(kind, tmp_path, monkeypatch):
    import os
    home = tmp_path / 'home'
    home.mkdir()
    (home / 'config.yaml').write_text('{}')
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setenv('HOME', str(home))
    for phase in ('seed', 'resume'):
        result = subprocess.run([sys.executable, '-c', _RESUME_SCRIPT,
            str(tmp_path / 'store' / 'audit.db'), str(home), phase, kind],
            env=os.environ.copy(), capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('damage', ['missing', 'corrupt'])
def test_audit_key_rotation_fails_resume_closed(damage, tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    key = load_submodule('audit.key')
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    db = tmp_path / 'store' / 'audit.db'
    store = surface.AuditStore(db)
    run = store.create_run(as_of=1800000000)
    store.cancel_run(run['run_id'])
    path = key.key_path(db)
    assert len(path.read_bytes()) == 32
    assert path.stat().st_mode & 0o777 == 0o600
    if damage == 'missing':
        path.unlink()
    else:
        path.write_bytes(b'INERT_CORRUPT_KEY')
    result = surface.execute_audit({'action': 'resume', 'run_id': run['run_id']}, db_path=db, wait=True)
    assert result['resume_reason'] == 'audit_key_unavailable'
    assert result['status'] == 'cancelled'
    assert len(path.read_bytes()) == 32


@pytest.mark.parametrize('typename,value', [('GeneratedDigest', 'a' * 64), ('ControlIdentity', 'component_' + 'a' * 64)])
def test_audit_privileged_digest_constructors_private(typename, value):
    e = load_submodule('audit.evidence')
    with pytest.raises(TypeError):
        getattr(e, typename)(value)


def test_audit_private_key_excluded_from_capture(tmp_path):
    key = load_submodule('audit.key')
    capture = load_submodule('audit.capture')
    db = tmp_path / 'audit.db'
    with key.key_scope(db):
        key.content_digest('a' * 64)
        manifest, files = capture.capture_project_files(tmp_path)
    assert 'audit.key' not in manifest['files']
    assert 'audit.key.lock' not in manifest['files']
    assert 'audit.key' not in files


def test_audit_durable_content_handles_restart(tmp_path):
    import hashlib
    import hmac
    project = tmp_path / 'project'
    project.mkdir()
    content = b'INERT_LOW_ENTROPY_CONTENT'
    (project / 'README.md').write_bytes(content)
    db = tmp_path / 'store' / 'audit.db'
    script = '''
import json, sys
from tests.conftest import load_submodule
key = load_submodule('audit.key')
capture = load_submodule('audit.capture')
with key.key_scope(sys.argv[1]):
    manifest, _ = capture.capture_project_files(sys.argv[2])
print(json.dumps([manifest['unit_digest'], manifest['files']['README.md']['sha256']]))
'''
    def run():
        result = subprocess.run([sys.executable, '-c', script, str(db), str(project)],
                                capture_output=True, text=True, timeout=60, check=True)
        return json.loads(result.stdout)
    first = run()
    assert run() == first
    key = (db.parent / 'audit.key').read_bytes()
    expected = hmac.new(key, b'content\0' + hashlib.sha256(content).hexdigest().encode(), hashlib.sha256).hexdigest()
    assert first[1] == expected
    (project / 'README.md').write_bytes(b'INERT_CHANGED_CONTENT')
    assert all(a != b for a, b in zip(first, run()))


def test_audit_schema_provenance():
    e = load_submodule('audit.evidence')
    for key in ('b', 'n', 't', 'pathlib', 'dataclasses', '_mid_read_hook'):
        assert key not in e.SCHEMA_KEYS
    for key in ('value', 'location', 'hmac', 'argument_count', 'arguments', 'executable', 'hosts'):
        assert isinstance(e.EvidenceSerializer().serialize(key), e.SealedEvidence), key
