"""Extraction and sink invariants independently of scanner-specific filtering."""
import json
from pathlib import Path
import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('name,text', [
    ('x.py', 'API_KEY = "/never/CANARY"'),
    ('x.py', 'config = {"private_key": "/never/CANARY"}'),
    ('x.py', 'API_KEY: str = "/never/CANARY"'),
    ('.pythonrc', 'API_KEY = "/never/CANARY"'),
    ('x.json', '{"api_key": "/never/CA\\u004eARY"}'),
    ('x.yaml', 'api_key: |\n  /never/CANARY\n'),
    ('x.toml', 'api_key = "/never/CANARY"'),
    ('x.ini', '[demo]\napi_key = /never/CANARY'),
    ('x.sh', 'export API_KEY="/never/CANARY"'),
    ('x.sh', 'echo --api-key /never/CANARY'),
    ('x.sh', 'echo --credential=/never/CANARY'),
    ('x.json', '{"args": ["--token", "/never/CANARY"]}'),
])
def test_audit_shared_extractor_withholds_sensitive_literals(name, text):
    paths = load_submodule('audit.literal_paths')
    result = paths.path_references(Path(name), text.encode())
    assert 'CANARY' not in json.dumps(result)


def test_audit_taint_scope_sink_and_reset(tmp_path):
    redaction = load_submodule('audit.redaction')
    secret = '/never/CANARY'
    @redaction.redaction_scope
    def collect():
        # A value can be emitted BEFORE another input identifies it as secret.
        evidence = {'path': secret, 'nested': ['error: ' + secret], secret: secret}
        redaction.observe(Path('example.py'), f'API_KEY = {secret!r}'.encode())
        with redaction.GuardedConnection(str(tmp_path / 'audit.db')) as conn:
            conn.execute('CREATE TABLE evidence(value TEXT)')
            conn.execute('INSERT INTO evidence VALUES (?)', (json.dumps(evidence),))
            assert 'CANARY' not in '\n'.join(conn.iterdump())
        return load_submodule('audit.evidence').serialize_evidence(evidence)
    result = collect()
    assert 'CANARY' not in json.dumps(result)
    assert result['path']['kind'] == 'unresolved_reference'
    assert len(result['path']['hmac']) == 64
    assert any(key.startswith('hmac:') for key in result)
    assert redaction.scrub(secret) == secret
    assert b'CANARY' not in (tmp_path / 'audit.db').read_bytes()


def test_audit_redaction_short_values_idempotent():
    state = load_submodule('audit.redaction').Taint()
    state.add('a')
    clean = state.scrub({'path': '/a', 'coverage': 'could_not_verify'})
    assert clean['path'] == '/a'
    assert state.scrub('a') == '[redacted]'
    assert clean['coverage'] == 'could_not_verify'
    assert state.scrub(clean) == clean
