"""Public persistence regressions: inert synthetic inputs, synthetic HOME only.

The allowlist contract is stronger than observed-secret matching: arbitrary
adapter evidence must not be persisted verbatim, even when encoded or unknown.
No fixture source is executed. Random cases need no optional property library.
"""
import base64
import json
from pathlib import Path
import random
import re
import sqlite3
import subprocess
import unicodedata
from urllib.parse import quote

import pytest
from tests.conftest import load_submodule
from tests.test_audit_credential_sink import _CASES as SINK_CASES


@pytest.fixture
def audit_probe(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    outward = load_submodule('audit.outward')
    git = load_submodule('audit.outward_git')
    home = tmp_path / 'home'
    profile = home / '.hermes'
    project = home / 'project'
    profile.mkdir(parents=True)
    (project / '.git').mkdir(parents=True)
    for key, value in {'HOME': home, 'HERMES_HOME': profile,
                       'XDG_CONFIG_HOME': home / '.config'}.items():
        monkeypatch.setenv(key, str(value))
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **k: discover(
        *a, **{**k, 'system_config': tmp_path / 'absent-gitconfig'}))
    inventory = surface._active_inventory
    def active(*args):
        result = inventory(*args)
        result['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
        return result
    monkeypatch.setattr(surface, '_active_inventory', active)
    collect = outward.collect_outward
    records = []
    def inject(*args, **kwargs):
        result = collect(*args, **kwargs)
        if records:
            result['database_records'] = records
        return result
    monkeypatch.setattr(outward, 'collect_outward', inject)

    def run(files, evidence=None, unbounded=False):
        originals = {}
        for relative, text in files.items():
            source = (home if relative.startswith('HOME/') else project) / relative.removeprefix('HOME/')
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(text)
            originals[source] = source.read_bytes()
        if evidence is not None:
            records.extend(evidence)
        db = tmp_path / 'store' / 'audit.db'
        response = surface.execute_audit(
            {'action': 'run', 'root': str(project), 'unbounded': unbounded},
            db_path=db, wait=True)
        assert response['status'] == 'completed'
        assert all(p.read_bytes() == data for p, data in originals.items())
        with sqlite3.connect(db) as connection:
            dump = '\n'.join(connection.iterdump()).encode()
        return response, {'report': json.dumps(response, ensure_ascii=False).encode(),
                          'db': db.read_bytes(), 'sql_dump': dump}
    run.home, run.project = home, project
    return run


def assert_absent(sinks, *needles):
    leaks = []
    for name, data in sinks.items():
        for needle in needles:
            if not needle:
                continue
            # SQLite JSON and public JSON may escape non-ASCII/multiline values.
            variants = {needle.encode(), json.dumps(needle)[1:-1].encode(),
                        json.dumps(needle, ensure_ascii=False)[1:-1].encode()}
            if any(value in data for value in variants):
                leaks.append((name, needle))
    assert not leaks, f'raw evidence leaked: {leaks}'


def objects(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from objects(item)
    elif isinstance(value, list):
        for item in value:
            yield from objects(item)


def disclosures(report):
    result = []
    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and value.startswith('evidence_redacted_due_to_credential_overlap: '):
            result.append(value)
    walk(report)
    return result


@pytest.mark.parametrize('case', SINK_CASES, ids=[case[0] for case in SINK_CASES])
def test_audit_allowlist_credential_sink_cases(audit_probe, tmp_path, case):
    name, relative, content, bypass, variant = case
    secret = str(tmp_path / 'missing' / ('PROBE_' + name.upper() + '_CANARY'))
    emitted = variant(secret) if variant else secret
    evidence = [{'path': emitted, 'reason': 'probe: ' + emitted, emitted: emitted}] if bypass else None
    _, sinks = audit_probe({relative: content(secret)}, evidence)
    assert_absent(sinks, secret.rsplit('/', 1)[-1], emitted if bypass else '')


def fresh_case(kind, secret, home):
    encoded = base64.b64encode(secret.encode()).decode()
    ordinary = json.dumps({'api_key': secret})
    if kind in ('base64', 'hex'):
        return 'novel.json', ordinary, encoded if kind == 'base64' else secret.encode().hex()
    if kind in ('NFC', 'NFKC'):
        value = ('A\u030a' if kind == 'NFC' else '\uff30\uff32\uff2f\uff22\uff25') + secret
        return 'novel.json', json.dumps({'api_key': value}), unicodedata.normalize(kind, value)
    if kind == 'windows_slashes':
        return 'novel.json', json.dumps({'api_key': 'C:\\private\\' + secret}), 'C:/private/' + secret
    if kind == 'tilde':
        return 'novel.json', json.dumps({'api_key': '~/private/' + secret}), str(home / 'private' / secret)
    if kind.startswith('split'):
        parts = {'first': secret[:12], 'second': secret[12:]}
        return 'novel.json', json.dumps({'api_key': parts} if kind == 'split_sensitive' else parts), secret
    if kind.startswith('yaml'):
        a, b = secret[:12], secret[12:]
        literal = kind == 'yaml_literal'
        return 'novel.yaml', f'api_key: {"|" if literal else ">-"}\n  {a}\n  {b}\n', a + ('\n' if literal else ' ') + b + ('\n' if literal else '')
    if kind in ('netrc', 'netrc_text'):
        return ('.netrc' if kind == 'netrc' else 'novel.txt'), f'machine example.invalid login demo password {secret}\n', secret
    if kind in ('pgpass', 'pgpass_text'):
        return ('.pgpass' if kind == 'pgpass' else 'novel.txt'), f'example.invalid:5432:demo:demo:{secret}\n', secret
    if kind in ('git_credentials', 'empty_user', 'url_retention'):
        user = '' if kind == 'empty_user' else 'demo'
        url = f'https://{user}:{secret}@example.invalid/path'
        return '.git-credentials', url + '\n', url
    if kind.startswith('docker'):
        auth = base64.b64encode(('demo:' + secret).encode()).decode()
        return 'docker.json', json.dumps({'auths': {'example.invalid': {'auth': auth}}}), auth if kind == 'docker_encoded' else secret
    if kind == 'double_slash':
        return 'novel.py', f'API_KEY = "//private/{secret}"\n', '/private/' + secret
    if kind == 'short':
        # Not hex: the store holds random hex digests, and a hex-shaped needle matches one by chance.
        return 'novel.json', json.dumps({'api_key': 'qzxwv'}), 'qzxwv'
    raise AssertionError(kind)


FRESH = ['base64', 'hex', 'NFC', 'NFKC', 'windows_slashes', 'tilde',
         'split_sensitive', 'split_ordinary', 'yaml_literal', 'yaml_folded',
         'netrc', 'netrc_text', 'pgpass', 'pgpass_text', 'git_credentials',
         'empty_user', 'url_retention', 'docker_encoded', 'docker_decoded',
         'double_slash', 'short']


@pytest.mark.parametrize('kind', FRESH)
@pytest.mark.parametrize('unbounded', [False, True])
def test_audit_allowlist_fresh_encodings(audit_probe, kind, unbounded):
    secret = 'PROBE_' + kind.upper() + '_SYNTHETIC_CANARY'
    relative, text, emitted = fresh_case(kind, secret, audit_probe.home)
    _, sinks = audit_probe({relative: text}, [
        {'path': emitted, 'reason': 'probe: ' + emitted, emitted: emitted}], unbounded)
    assert_absent(sinks, secret, emitted)


@pytest.mark.parametrize('kind', ['double_slash', 'empty_user', 'tilde', 'netrc', 'pgpass'])
def test_audit_allowlist_natural_values(audit_probe, tmp_path, kind):
    secret = 'NATURAL_' + kind.upper() + '_PRIVATE_CANARY'
    missing = str(tmp_path / 'missing' / secret)  # outside HOME: actually outward
    text = f'ordinary = {missing!r}\n'
    files = {}
    if kind == 'double_slash':
        text += f'API_KEY = {("/" + missing)!r}\n'
    elif kind == 'tilde':
        text += f'API_KEY = {("~/../missing/" + secret)!r}\n'
    elif kind == 'empty_user':
        text += f'endpoint = "https://:{secret}@example.invalid/path"\n'
    else:
        relative, content, _ = fresh_case(kind, secret, audit_probe.home)
        files[relative] = content
    files['HOME/.pythonrc'] = text
    _, sinks = audit_probe(files)
    assert_absent(sinks, secret)


@pytest.mark.parametrize('seed', range(4))
@pytest.mark.parametrize('extension', ['json', 'yaml', 'toml', 'ini', 'py', 'sh', 'txt'])
def test_audit_allowlist_random_cross_supported_types(audit_probe, seed, extension):
    rng = random.Random(seed)
    secrets = [''.join(rng.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=32)) for _ in range(3)]
    secret = secrets[0]
    content = {
        'json': json.dumps({'api_key': secret}), 'yaml': f'api_key: "{secret}"\n',
        'toml': f'api_key = "{secret}"\n', 'ini': f'[auth]\napi_key = {secret}\n',
        'py': f'API_KEY = {secret!r}\n', 'sh': f'export API_KEY="{secret}"\n',
        'txt': f'machine example.invalid login demo password {secret}\n',
    }[extension]
    # Include unobserved random evidence, arbitrary keys and nested lists: an
    # allowlist must protect these without guessing every credential spelling.
    candidates = secrets + [base64.b64encode(secret.encode()).decode(), secret.encode().hex(), quote('/private/' + secret, safe='')]
    response, sinks = audit_probe({'novel.' + extension: content}, [
        {'path': value, 'reason': 'probe: ' + value, value: [value, {'value': value}]}
        for value in candidates])
    assert_absent(sinks, *candidates)
    tokens = [obj for obj in objects(response) if 'kind' in obj and 'location' in obj
              and any('hmac' in str(key).lower() or 'token' in str(key).lower() for key in obj)]
    assert tokens, 'arbitrary evidence must become HMAC token objects with kind and location'


def test_audit_allowlist_ordinary_node_python_no_over_redaction(audit_probe):
    other = audit_probe.home / 'ordinary.py'
    other.write_text('pass\n')
    response, sinks = audit_probe({
        'package.json': json.dumps({'name': 'ordinary-app', 'version': '1.0.0', 'scripts': {'start': 'node index.js'}, 'type': 'module'}),
        'index.js': 'export function greet(name) { return `Hello ${name}`; }\n',
        'pyproject.toml': '[project]\nname = "ordinary-app"\nversion = "1.0.0"\n',
        'main.py': 'def names(data):\n    keys = ["description", "version", "dependencies"]\n    return [data.get(key) for key in keys]\n' + f'ordinary = {str(other)!r}\n',
    })
    assert disclosures(response) == []
    for key in ('contract_version', 'rule_versions', 'template_versions'):
        assert any(key in obj for obj in objects(response)), f'lost fixed schema key: {key}'
    assert str(other).encode() in sinks['report'], 'existing resolved ordinary paths remain raw'


def test_audit_allowlist_self_repo_copy_disclosure_count(audit_probe, record_property):
    # Copy only tracked regular files from THIS checkout; never scan live HOME.
    root = Path(__file__).resolve().parents[1]
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    copied = 0
    for name in names:
        source = root / name
        if not name or source.is_symlink() or not source.is_file():
            continue
        target = audit_probe.project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        copied += 1
    assert copied > 100
    response, _ = audit_probe({})
    reasons = disclosures(response)
    counts = [int(re.search(r': (\d+) items', reason).group(1)) for reason in reasons]
    record_property('copied_files', copied)
    record_property('credential_overlap_disclosures', len(reasons))
    record_property('credential_overlap_items', sum(counts))
    assert reasons == [], f'false-positive credential overlap disclosures: {reasons}'
    assert sum(counts) == 0
    assert any('contract_version' in obj for obj in objects(response))
