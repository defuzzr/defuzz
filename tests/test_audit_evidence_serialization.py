from tests.conftest import load_submodule


def test_audit_evidence_allowlist(tmp_path):
    api = load_submodule('audit.evidence')
    source = tmp_path / 'source.py'
    source.write_text('ordinary = "unobserved-private-value"\n')
    existing = tmp_path / 'real'
    existing.touch()
    serializer = api.EvidenceSerializer()
    result = serializer.serialize({'path': str(source), 'line': 1,
                                   'target': str(tmp_path / 'missing-private'),
                                   'value': 'unobserved-private-value',
                                   'sample_paths': [str(existing)]})
    assert result['path'] == str(source)
    assert result['sample_paths'] == [str(existing)]
    assert result['target']['kind'] == 'unresolved_reference'
    assert result['value']['kind'] == 'text'
    assert result['value']['location'] == {'path': str(source), 'line': 1}
    assert result['value']['hmac'] != 'unobserved-private-value'
    assert serializer.serialize({'value': 'unobserved-private-value'})['value']['hmac'] == result['value']['hmac']
    assert api.EvidenceSerializer().serialize({'value': 'unobserved-private-value'})['value']['hmac'] != result['value']['hmac']


def test_audit_evidence_typed_leaf_cannot_bypass(tmp_path):
    api = load_submodule('audit.evidence')
    serializer = api.EvidenceSerializer()
    token = serializer.serialize({'value': 'original'})['value']
    token['location']['path'] = 'nested-private-leak'
    dict.update(token, extra='base-dict-private-leak')
    cleaned = serializer.serialize(token)
    assert 'private-leak' not in str(cleaned)
    endpoint = api.EvidenceEndpoint(host='raw secret / query?', scheme='raw scheme')
    assert 'raw secret' not in str(serializer.serialize(endpoint))


def test_audit_evidence_path_taint_guard(tmp_path):
    api = load_submodule('audit.evidence')
    redaction = load_submodule('audit.redaction')
    path = tmp_path / 'existing-sensitive'
    path.touch()
    state = redaction.Taint()
    state.add(str(path))
    token = redaction._CURRENT.set(state)
    try:
        out = api.serialize_evidence({'path': str(path)})
        assert out['path']['kind'] == 'credential_overlap'
        assert str(path) not in str(out['path'])
    finally:
        redaction._CURRENT.reset(token)


def test_audit_evidence_command_arguments(tmp_path, monkeypatch):
    api = load_submodule('audit.evidence')
    outward = load_submodule('audit.outward')
    home = tmp_path / 'home'
    profile = home / '.hermes'
    project = home / 'project'
    profile.mkdir(parents=True)
    project.mkdir()
    (project / '.git').mkdir()
    exe = project / 'run-tool'
    exe.write_text('#!/bin/sh\nexit 0\n')
    exe.chmod(0o700)
    source = project / 'package.json'
    import json
    source.write_text(json.dumps({'scripts': {'start': f'{exe} private-argument --flag'}}))
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    report = outward.collect_outward(profile, [str(project)])
    commands = [c for item in report['dynamic_invocations'] for c in item.get('commands', [])]
    assert commands
    command = commands[0]
    assert command['executable'] == str(exe)
    assert command['argument_count'] == 2
    assert len(command['arguments']) == 2
    assert all(arg['kind'] == 'argument' for arg in command['arguments'])
    assert command['location'] == {'path': str(source), 'line': 1}
    assert 'private-argument' not in json.dumps(report)
