"""A05: public audit must not open credential stores, even transiently."""
import json
import os
import sys
from pathlib import Path

import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('quick', [False, True])
@pytest.mark.parametrize('scenario', ['base', 'git-late', 'sibling-config', 'templates', 'toml', 'cross-later', 'cross-earlier', 'self-source'])
def test_audit_credential_store_public_tripwire(tmp_path, monkeypatch, quick, scenario):
    home = tmp_path / 'home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    project = home / 'project'
    project.mkdir()
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    names = ['.netrc', '.pgpass', '.git-credentials', '.docker/config.json',
             '.npmrc', '.config/pip/pip.conf', '.pip/pip.conf']
    names += ['project/' + name for name in ['auth.json', 'credentials.json',
              'secrets.json', '.env', '.pypirc', 'id_rsa', 'private.pem', 'private.key', 'pip.conf', '.envrc', '.env.local',
              'credentials-extra', 'id_ed25519', 'token', 'tokens.json', 'npmrc']]
    names += ['.hermes/.env', '.hermes/profiles/sibling/.env', 'project/opaque.dat']
    (profile / 'config.yaml').write_text('credential_file: ' + str(project / 'opaque.dat') + '\n')
    (project / '.git').mkdir()
    (project / '.git/config').write_text('[include]\n    path = ../pip.conf\n')
    protected = set()
    for name in names:
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('A05_INERT_CREDENTIAL_CANARY_' + name)
        protected.add(str(path))
    link = project / '.netrc'
    target = home / 'never-follow.txt'
    target.write_text('A05_SYMLINK_CANARY')
    link.symlink_to(target)
    protected.update([str(link), str(target)])
    late = project / 'aaa-payload.txt'
    late.write_text('A05_INERT_CREDENTIAL_CANARY_LATE')
    protected.add(str(late))
    (project / 'settings.json').write_text(json.dumps({'credential_file': str(late)}))
    if scenario == 'toml':
        (project / 'settings.json').unlink()
        (project / 'settings.toml').write_text('credential_file = ' + json.dumps(str(late)))
    sibling = profile / 'profiles/sibling/config.yaml'
    sibling_target = project / 'sibling-payload.dat'
    sibling_target.write_text('A05_INERT_CREDENTIAL_CANARY_SIBLING')
    protected.add(str(sibling_target))
    sibling.write_text('credential_file: ' + str(sibling_target))
    if scenario == 'git-late':
        (project / 'settings.json').unlink()
        (project / '.git/config').write_text('[include]\n    path = ../aaa-payload.txt\n')
    if scenario in {'sibling-config', 'self-source'}:
        # Fixed declaration sources remain readable even when declared credentials.
        (profile / 'config.yaml').write_text('credential_file: [' + str(project / 'opaque.dat') + ', ' + str(sibling) + ', ' + str(profile / 'config.yaml') + ']')
    if scenario in {'cross-later', 'cross-earlier'}:
        cross_target = project / ('zzz.json' if scenario == 'cross-later' else '000.json')
        cross_target.write_text('A05_INERT_CREDENTIAL_CANARY_CROSS')
        protected.add(str(cross_target))
        (project / 'settings.json').write_text(json.dumps({'credential_file': [str(late), str(cross_target)]}))
    if scenario == 'templates':
        identity = load_submodule('audit.identity')
        installed = tmp_path / 'installed'
        (installed / 'audit/vendor').mkdir(parents=True)
        (installed / 'audit/vendor/provenance.json').write_text('{}')
        template = installed / 'templates/python/tmpl/.netrc'
        template.parent.mkdir(parents=True)
        template.write_text('A05_INERT_CREDENTIAL_CANARY_TEMPLATE')
        protected.add(str(template))
        opaque_template = template.parent / 'opaque.txt'
        opaque_template.write_text('A05_INERT_CREDENTIAL_CANARY_TEMPLATE_OPAQUE')
        engine_target = installed / 'audit/vendor/provenance.json'
        engine_target.write_text('A05_INERT_CREDENTIAL_CANARY_ENGINE')
        (template.parent / 'settings.json').write_text(json.dumps({'credential_file': [str(opaque_template), str(engine_target)]}))
        protected.update([str(opaque_template), str(engine_target)])
        monkeypatch.setattr(identity, '__file__', str(installed / 'audit/identity.py'))
    attempts = []
    sources_opened = set()
    enabled = [True]
    def check(path):
        if enabled[0] and isinstance(path, (str, bytes, os.PathLike)):
            if os.fsdecode(path) in {str(profile / 'config.yaml'), str(sibling)}:
                sources_opened.add(os.fsdecode(path))
            if os.fsdecode(path) in protected:
                attempts.append(os.fsdecode(path))
                raise AssertionError('credential store opened')
    def hook(event, args):
        if event == 'open':
            check(args[0])
    sys.addaudithook(hook)
    # Import the audit modules BEFORE wrapping os.open: audit/fingerprint.py records
    # `os.open in os.supports_dir_fd` at import time, and a wrapper would make it False.
    surface = load_submodule('audit_surface')
    original = os.open
    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / path if dir_fd is not None else path
        check(full)
        return original(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(os, 'open', guarded_open)
    db = profile / 'plugin-data/defuzz/audit.db'
    try:
        original_inventory = surface._active_inventory
        def inventory(*args):
            result = original_inventory(*args)
            result['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
            return result
        monkeypatch.setattr(surface, '_active_inventory', inventory)
        options = {'root': str(project)}
        if quick:
            options['quick'] = True
        response = surface.execute_audit(options, db_path=db, wait=True)
    finally:
        enabled[0] = False
    assert not attempts
    assert sources_opened == {str(profile / 'config.yaml'), str(sibling)}
    assert response['status'] == 'completed'
    assert 'A05_INERT_CREDENTIAL_CANARY' not in json.dumps(response)
    assert 'A05_SYMLINK_CANARY' not in json.dumps(response)
    for file in db.parent.rglob('*'):
        if file.is_file():
            assert b'A05_INERT_CREDENTIAL_CANARY' not in file.read_bytes()
            assert b'A05_SYMLINK_CANARY' not in file.read_bytes()
    if not quick:
        records = response['report']['credentials']
        for name in names:
            record = next(item for item in records if item['path'] == str(home / name))
            assert set(record) == {'kind', 'path', 'size', 'mode', 'mtime'}
            assert record['kind'] == 'credential_store'
        symlink_record = next(item for item in records if item['path'] == str(target))
        assert symlink_record['size'] == link.lstat().st_size
        assert symlink_record['mtime'] == link.lstat().st_mtime
        assert 'credential_store_not_opened' in json.dumps(response)
