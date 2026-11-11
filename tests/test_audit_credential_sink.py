"""Canonical credential sink regressions."""
import json
import sqlite3
from urllib.parse import quote
import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('secret,candidate', [
    ('/a/./CANARY_VALUE', '/a/CANARY_VALUE'),
    ('/a//CANARY_VALUE/', '/a/CANARY_VALUE'),
    ('/a/x/../CANARY_VALUE', '/a/CANARY_VALUE'),
    ('%252Fa%252FCANARY_VALUE', '/a/CANARY_VALUE'),
    (' " /a/CANARY_VALUE " ', '/A/canary_value'),
])
def test_audit_canonical_taint_sink(secret, candidate):
    state = load_submodule('audit.redaction').Taint()
    state.add(secret)
    assert state.scrub('evidence: ' + candidate) == '[redacted]'
    assert state.scrub(candidate) == '[redacted]'


@pytest.mark.parametrize('prefix', ['endpoint=', 'DATABASE_URL=', 'index-url=', 'registry=', 'url = '])
def test_audit_url_userinfo(prefix):
    state = load_submodule('audit.redaction').Taint()
    url = 'https://user:PRIVATE_CANARY@example.invalid/path'
    state.observe_text(prefix + url)
    assert state.scrub('/evidence/PRIVATE_CANARY') == '[redacted]'
    assert state.scrub(url) == 'https://[redacted]@example.invalid/path'


@pytest.mark.parametrize('secret', ['a', 'abcde', 'DISTINCT_LONG_SECRET'])
def test_audit_short_precision_and_disclosure(tmp_path, monkeypatch, secret):
    outward = load_submodule('audit.outward')
    home = tmp_path / 'home'
    profile = home / '.hermes'
    project = home / 'project'
    other = home / 'ordinary'
    for directory in (profile, project / '.git', other):
        directory.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    paths = [other / f'path{i}.py' for i in range(20)]
    for path in paths:
        path.write_text('pass\n')
    (project / 'main.py').write_text(f'API_KEY = {secret!r}\n' + '\n'.join(f'p{i} = {str(path)!r}' for i, path in enumerate(paths)))
    report = outward.collect_outward(profile, [str(project)])
    targets = {edge['target'] for edge in report['blending']}
    assert all(str(path) in targets for path in paths)
    # Rejected credential extraction never became allowed outgoing evidence.
    # It must not downgrade otherwise complete traversal coverage.
    region = report['regions']['project_tree']
    assert region['coverage'] == 'verified'
    assert not region['reasons']
    if len(secret) >= 6:
        assert secret not in json.dumps(report)

@pytest.mark.parametrize('exists', [False, True])
def test_audit_sink_disclosure_is_local_counted_and_idempotent(tmp_path, exists):
    redaction = load_submodule('audit.redaction')
    state = redaction.Taint()
    source = tmp_path / 'project' / 'main.py'
    source.parent.mkdir()
    source.write_text('pass\n')
    target = tmp_path / 'PRIVATE_CANARY'
    if exists:
        target.touch()
    state.add(str(target))
    state.owner = lambda path: 'project_tree' if str(path) == str(source) else 'shared_infrastructure'
    report = {
        'regions': {name: {'coverage': 'verified', 'reasons': []} for name in ('project_tree', 'shared_infrastructure')},
        'blending': [{'source': str(source), 'target': str(target)}],
    }
    token = redaction._CURRENT.set(state)
    try:
        cleaned = state.disclose(state.serializer.serialize(report))
    finally:
        redaction._CURRENT.reset(token)
    assert cleaned['blending'][0]['source'] == str(source)
    evidence = cleaned['blending'][0]['target']
    assert evidence['kind'] == ('credential_overlap' if exists else 'unresolved_reference')
    assert len(evidence['hmac']) == 64
    assert 'PRIVATE_CANARY' not in json.dumps(cleaned)
    assert cleaned['regions']['project_tree'] == {
        'coverage': 'could_not_verify' if exists else 'verified',
        'reasons': ['evidence_redacted_due_to_credential_overlap: 1 items'] if exists else [],
    }
    assert cleaned['regions']['shared_infrastructure']['coverage'] == 'verified'
    assert state.scrub(cleaned) == cleaned


@pytest.mark.parametrize('secret', ['a', 'abcde', '"a"', '%61', '%61%62%63', '%2561%2562%2563'])
def test_audit_short_canonical_values_match_only_whole_field(secret):
    state = load_submodule('audit.redaction').Taint()
    state.add(secret)
    assert state.scrub('/ordinary/abcde/path') == '/ordinary/abcde/path'
    embedded = '/ordinary/' + secret + '/path'
    assert state.scrub(embedded) == ('[redacted]' if len(secret) >= 6 else embedded)
    assert state.scrub(secret) == '[redacted]'


# All 25 credential sink cases, each exercised in bounded and unbounded mode.
def _assignment(secret):
    return f'API_KEY = {secret!r}\n'


def _url(secret):
    return 'https://user:' + secret.rsplit('/', 1)[-1] + '@example.invalid'


_CASES = [
    ('pythonrc', 'HOME/.pythonrc', _assignment, False, None),
    ('sitecustomize', 'HOME/.local/lib/python3.14/site-packages/sitecustomize.py', _assignment, False, None),
    ('shellrc', 'HOME/.bashrc', lambda s: f'export API_KEY="{s}"\n', False, None),
    ('nested_json', 'novel.json', lambda s: json.dumps({'outer': [{'api_key': s}]}), True, None),
    ('toml', 'novel.toml', lambda s: f'[outer]\napi_key = "{s}"\n', True, None),
    ('ini', 'novel.ini', lambda s: f'[outer]\nApi_Key = "{s}"\n', True, None),
    ('export', 'novel.sh', lambda s: f'export API_KEY="{s}"\n', True, None),
    ('yaml_anchor', 'novel.yaml', lambda s: f'api_key: &val "{s}"\nother: *val\n', True, None),
    ('cli_equals', 'novel.sh', lambda s: f'echo --token={s}\n', True, None),
    ('mixed_key_case', 'novel.py', lambda s: f'aPi_KeY = "{s}"\n', True, None),
    ('url_userinfo', 'novel.json', lambda s: json.dumps({'endpoint': _url(s)}), True, _url),
    ('quoted', 'novel.py', _assignment, True, lambda s: '"' + s + '"'),
    ('trailing_slash', 'novel.py', lambda s: _assignment(s + '/'), True, None),
    ('normalize_dot', 'novel.py', lambda s: _assignment(s.replace('/missing/', '/missing/./')), True, None),
    ('urlencode', 'novel.py', lambda s: _assignment(quote(s, safe='')), True, None),
    ('value_case', 'novel.py', _assignment, True, str.lower),
    ('natural_trailing', 'novel.py', lambda s: _assignment(s + '/') + f'ordinary = "{s}"\n', False, None),
    ('natural_normalize', 'novel.py', lambda s: _assignment(s.replace('/missing/', '/missing/./')) + f'ordinary = "{s}"\n', False, None),
    ('natural_yaml_block', 'novel.yaml', lambda s: f'api_key: |\n  {s}\nordinary: "{s}"\n', False, None),
    ('natural_url', 'novel.py', lambda s: f'endpoint = "{_url(s)}"\nordinary = "{s}"\n', False, None),
    ('home_trailing', 'HOME/.pythonrc', lambda s: _assignment(s + '/') + f'ordinary = "{s}"\n', False, None),
    ('home_normalize', 'HOME/.pythonrc', lambda s: _assignment(s.replace('/missing/', '/missing/./')) + f'ordinary = "{s}"\n', False, None),
    ('home_yaml_block', 'HOME/.config/systemd/user/example.service', lambda s: f'[Service]\nAPI_KEY="{s}/"\nWorkingDirectory={s}\n', False, None),
    ('home_url', 'HOME/.pythonrc', lambda s: f'endpoint = "{_url(s)}"\nordinary = "{s}"\n', False, None),
    ('home_urlencoded', 'HOME/.pythonrc', lambda s: _assignment(quote(s, safe='')) + f'ordinary = "{s}"\n', False, None),
]


@pytest.mark.parametrize('unbounded', [False, True])
@pytest.mark.parametrize('name,relative,content,bypass,variant', _CASES, ids=[c[0] for c in _CASES])
def test_audit_credential_sink_public_api(tmp_path, monkeypatch, unbounded, name, relative, content, bypass, variant):
    surface = load_submodule('audit_surface')
    outward = load_submodule('audit.outward')
    git = load_submodule('audit.outward_git')
    home = tmp_path / 'home'
    profile = home / '.hermes'
    project = home / 'project'
    profile.mkdir(parents=True)
    (project / '.git').mkdir(parents=True)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / '.config'))
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **k: discover(*a, **{**k, 'system_config': tmp_path / 'absent-gitconfig'}))
    canary = 'PROBE_' + name.upper() + '_CANARY'
    secret = str(tmp_path / 'missing' / canary)
    source = (home if relative.startswith('HOME/') else project) / relative.removeprefix('HOME/')
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content(secret))
    before = source.read_bytes()
    inventory = surface._active_inventory
    def active(*args):
        result = inventory(*args)
        result['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
        return result
    monkeypatch.setattr(surface, '_active_inventory', active)
    collect = outward.collect_outward
    emitted = variant(secret) if variant else secret
    def inject(*args, **kwargs):
        result = collect(*args, **kwargs)
        if bypass:
            result['database_records'] = [{'path': emitted, 'reason': 'probe: ' + emitted, emitted: emitted}]
        return result
    monkeypatch.setattr(outward, 'collect_outward', inject)
    db = tmp_path / 'store' / 'audit.db'
    response = surface.execute_audit({'action': 'run', 'root': str(project), 'unbounded': unbounded}, db_path=db, wait=True)
    assert response['status'] == 'completed'
    assert canary.lower() not in json.dumps(response).lower()
    with sqlite3.connect(db) as connection:
        assert canary.lower() not in '\n'.join(connection.iterdump()).lower()
    assert canary.lower().encode() not in db.read_bytes().lower()
    assert source.read_bytes() == before
