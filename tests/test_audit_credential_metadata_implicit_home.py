"""Implicit credentials use the audited HOME and lstat only."""
import json

import pytest

from tests.conftest import load_submodule


@pytest.mark.parametrize(('name', 'data', 'expected'), [
    ('.netrc', 'machine example.org login USER password PRIVATE_VALUE', {'host': 'example.org'}),
    ('.pgpass', 'example.org:5432:db:USER:PRIVATE_VALUE', {'host': 'example.org', 'port': 5432}),
    ('.git-credentials', 'https://USER:PRIVATE_VALUE@example.org:8443/private', {'scheme': 'https', 'host': 'example.org', 'port': 8443}),
    ('.docker/config.json', '{"auths":{"example.org":{"auth":"PRIVATE_VALUE"}}}', {'host': 'example.org'}),
    ('.config/pip/pip.conf', '[global]\nindex-url=https://USER:PRIVATE_VALUE@example.org/private', {'scheme': 'https', 'host': 'example.org'}),
    ('.pip/pip.conf', '[global]\nindex-url=https://USER:PRIVATE_VALUE@example.org/private', {'scheme': 'https', 'host': 'example.org'}),
])
@pytest.mark.parametrize('unbounded', [False, True])
def test_audit_credential_metadata_implicit_home(tmp_path, monkeypatch, name, data, expected, unbounded):
    home = tmp_path / 'audited-home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    process_home = tmp_path / 'process-home'
    process_home.mkdir()
    monkeypatch.setenv('HOME', str(process_home))
    monkeypatch.setenv('HERMES_HOME', str(process_home / '.hermes'))
    source = home / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(data)
    source.chmod(0o600)
    report = load_submodule('audit.outward').collect_outward(profile, [], unbounded=unbounded)
    matches = [item for item in report['credentials'] if item['path'] == str(source)]
    assert len(matches) == 1
    assert matches[0] == {'kind': 'credential_store', 'path': str(source),
                          'mode': 0o600, 'size': source.lstat().st_size,
                          'mtime': source.lstat().st_mtime}
    assert 'credential_store_not_opened' in json.dumps(report)
    assert 'PRIVATE_VALUE' not in json.dumps(report)
    assert source.read_text() == data
    assert list(process_home.iterdir()) == []
