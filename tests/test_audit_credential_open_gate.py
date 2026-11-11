"""Public credential boundary regressions: credential files are never opened; observe real descriptor opens."""
import json
import os
import sys
from pathlib import Path

import pytest
from tests.conftest import load_submodule


@pytest.fixture
def gate(tmp_path, monkeypatch):
    # Import before wrapping open so platform support detection stays truthful.
    surface = load_submodule('audit_surface')
    identity = load_submodule('audit.identity')
    load_submodule('audit.fingerprint')
    templates = load_submodule('templates')
    home = tmp_path / 'home'
    profile = home / '.hermes'
    project = home / 'project'
    installed = tmp_path / 'installed'
    for p in (profile, project, installed / 'audit/vendor'):
        p.mkdir(parents=True)
    (installed / 'audit/vendor/provenance.json').write_text('{}')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    monkeypatch.setattr(identity, '__file__', str(installed / 'audit/identity.py'))
    monkeypatch.setattr(templates, 'templates_root', lambda: installed / 'templates')
    original_inventory = surface._active_inventory
    def inventory(*args):
        result = original_inventory(*args)
        result['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified', 'template_id': 'demo'}]
        return result
    monkeypatch.setattr(surface, '_active_inventory', inventory)
    protected = set()
    def put(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path
    def secret(path):
        protected.add(str(path))
        return put(path, 'PROBE_CREDENTIAL_GATE_CANARY')
    def run(quick):
        attempts = []
        enabled = [True]
        def observe(path):
            if enabled[0] and isinstance(path, (str, bytes, os.PathLike)):
                path = os.path.abspath(os.fsdecode(path))
                if path in protected:
                    attempts.append(path)
        def hook(event, args):
            if event in ('open', 'os.scandir'):
                observe(args[0])
        sys.addaudithook(hook)
        original = os.open
        def wrapped(path, flags, mode=0o777, *, dir_fd=None):
            full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / os.fsdecode(path) if dir_fd is not None else path
            observe(full)
            return original(path, flags, mode, dir_fd=dir_fd)
        db = profile / 'plugin-data/defuzz/audit.db'
        os.supports_dir_fd.add(wrapped)
        monkeypatch.setattr(os, 'open', wrapped)
        try:
            response = surface.execute_audit({'root': str(project), 'quick': quick}, db_path=db, wait=True)
        finally:
            enabled[0] = False
            monkeypatch.setattr(os, 'open', original)
            os.supports_dir_fd.discard(wrapped)
        assert not attempts, attempts
        assert response['status'] == 'completed'
        assert 'PROBE_CREDENTIAL_GATE_CANARY' not in json.dumps(response)
        for path in db.parent.rglob('*'):
            if path.is_file() and str(path) not in protected:
                assert b'PROBE_CREDENTIAL_GATE_CANARY' not in path.read_bytes()
        return response
    return home, profile, project, installed, protected, put, secret, run


@pytest.mark.parametrize('quick', [False, True])
@pytest.mark.parametrize('source', ['config.yaml', 'profiles/sib/config.yaml', '.git/config',
    'settings.json', 'settings.toml', 'package.json', 'pyproject.toml', 'Cargo.toml', 'pnpm-workspace.yaml'])
def test_audit_gate_regressions_template_source(gate, quick, source):
    home, profile, project, installed, protected, put, secret, run = gate
    template = installed / 'templates/demo'
    target = secret(template / 'aaa-payload.txt')
    declaration = ('[include]\npath = ' + json.dumps(str(target)) if source == '.git/config'
        else 'credential_file = ' + json.dumps(str(target)) if source.endswith('.toml')
        else json.dumps({'credential_file': str(target)}))
    put(template / source, declaration)
    run(quick)


@pytest.mark.parametrize('quick', [False, True])
@pytest.mark.parametrize('valid', [False, True])
def test_audit_gate_regressions_template_manifest(gate, quick, valid):
    home, profile, project, installed, protected, put, secret, run = gate
    template = installed / 'templates/demo'
    manifest = secret(template / 'template.yaml')
    if valid:
        put(manifest, json.dumps({'id': 'demo', 'name': 'Demo', 'summary': 'PROBE_CREDENTIAL_GATE_CANARY',
            'kind': 'tool', 'layout': 'single', 'languages': ['python'], 'placeholder': 'demo',
            'substitute_in': ['README.md'], 'repos': [{'name': 'tmpl'}]}))
        (template / 'tmpl').mkdir()
    put(template / 'settings.json', json.dumps({'credential_file': str(manifest)}))
    response = run(quick)
    assert 'could_not_verify' in json.dumps(response)


@pytest.mark.parametrize('quick', [False, True])
def test_audit_gate_regressions_registry(gate, quick):
    home, profile, project, installed, protected, put, secret, run = gate
    target = secret(profile / 'plugin-data/defuzz/state.db')
    put(profile / 'config.yaml', json.dumps({'credential_file': str(target)}))
    response = run(quick)
    assert 'could_not_verify' in json.dumps(response)
    assert 'credential_store_not_opened' in json.dumps(response)


@pytest.mark.parametrize('quick', [False, True])
@pytest.mark.parametrize('location', ['project', 'template', 'referenced-child'])
def test_audit_gate_regressions_directory_exact(gate, quick, location):
    home, profile, project, installed, protected, put, secret, run = gate
    root = installed / 'templates/demo' if location == 'template' else project
    target = root / 'opaque-dir'
    secret(target / 'payload.txt')
    protected.add(str(target))
    put(root / 'config.yaml', json.dumps({'credential_file': str(target)}))
    if location == 'referenced-child':
        put(project / 'aaa-launch.sh', 'cat ' + str(target / 'payload.txt'))
    run(quick)


def test_audit_gate_regressions_quick_metadata(gate):
    home, profile, project, installed, protected, put, secret, run = gate
    in_scope = secret(project / '.netrc')
    memory = secret(profile / 'memories/MEMORY.md')
    outside = secret(home / '.pgpass')
    put(profile / 'config.yaml', json.dumps({'credential_file': str(memory)}))
    response = run(True)
    records = response['report']['credentials']
    assert {r['path'] for r in records} >= {str(in_scope), str(memory)}
    assert str(outside) not in {r['path'] for r in records}
    for record in records:
        assert set(record) == {'kind', 'path', 'size', 'mode', 'mtime'}
    assert 'credential_store_not_opened' in json.dumps(response)
