"""Unavailable YAML must fail closed through the persisted public audit."""
import json
import sqlite3
import sys

import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('parser_state', ['missing', 'wrong_version'])
def test_audit_yaml_public_unavailable(tmp_path, monkeypatch, parser_state):
    home = tmp_path / 'home'
    profile = home / '.hermes'
    plugin = profile / 'plugins' / 'demo'
    plugin.mkdir(parents=True)
    secret = 'UNPARSED-YAML-SECRET-CANARY'
    (profile / 'config.yaml').write_text('api_key: >-\n  ' + secret + '\nhooks: {}\n')
    (plugin / 'plugin.yaml').write_text('name: demo\nversion: "1"\n')
    for key, value in {'HOME': home, 'HERMES_HOME': profile,
                       'XDG_CONFIG_HOME': home / '.config'}.items():
        monkeypatch.setenv(key, str(value))
    surface = load_submodule('audit_surface')
    if parser_state == 'missing':
        monkeypatch.setitem(sys.modules, 'yaml', None)
    else:
        import yaml
        monkeypatch.setattr(yaml, '__version__', '6.0.2')
    redaction = load_submodule('audit.redaction')
    # No literal extractor may consume unparsed YAML, including folded secrets.
    assert redaction.extraction(path=profile / 'config.yaml',
                                data=(profile / 'config.yaml').read_bytes()) == b''
    db = tmp_path / 'audit.db'
    result = surface.execute_audit({'action': 'run', 'as_of': 1800000000},
                                   db_path=db, wait=True)
    assert result['status'] == 'completed'
    saved = surface.execute_audit({'action': 'report', 'run_id': result['run_id']}, db_path=db)
    assert saved['report'] == result['report']
    units = saved['report']['units']
    assert units and all(unit['coverage'] == 'could_not_verify' for unit in units)
    findings = saved['report']['findings']
    affected = [f for f in findings if f['id'] in
                {'audit.scope.active_profile', 'audit.scope.plugins'}]
    assert len(affected) == 2
    assert all(f['coverage'] == 'could_not_verify' for f in affected)
    unknown = [f for f in findings if f['id'] == 'executable_inventory.plugin_manifest_unverified']
    assert unknown and all(f['coverage'] == 'could_not_verify' for f in unknown)
    assert not any(f['id'] == 'executable_inventory.plugin_manifest' and
                   f['coverage'] == 'verified' for f in findings)
    with sqlite3.connect(db) as conn:
        dump = '\n'.join(conn.iterdump())
    assert secret not in json.dumps(saved)
    assert secret not in dump
    assert secret.encode() not in db.read_bytes()
