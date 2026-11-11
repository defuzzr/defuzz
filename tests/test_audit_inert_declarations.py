"""Inert declaration regressions: synthetic HOME, no execution."""
import json
import sqlite3
import pytest
from tests.conftest import load_submodule
from tests.test_audit_outward_inventory_contracts import base, run, _no_host_system_gitconfig


@pytest.mark.parametrize('variant', ['workspace', 'args', 'assignment', 'command'])
def test_audit_credentials_never_persist(tmp_path, monkeypatch, variant):
    home, profile, project, other = base(tmp_path, git=True)
    canary = 'PROBE_DECLARATION_SECRET_CANARY'
    secret = str(other / canary)
    if variant == 'workspace':
        (project / 'demo.code-workspace').write_text('// jsonc\n' + json.dumps({'settings': {'demo.apiKey': secret}}))
    else:
        args = ['--api-key', secret, '--token', secret, '--password', secret, '--secret', secret, '--auth', secret, '-p', secret]
        if variant == 'assignment':
            args = ['API_KEY=' + secret, '--token=' + secret]
        command = 'echo' if variant != 'command' else 'echo --api-key ' + secret
        (profile / 'config.yaml').write_text(json.dumps({'mcp_servers': {'demo': {'command': command, 'args': args}}}))
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    report = run(profile, project, other)
    assert canary not in json.dumps(report)
    db = tmp_path / 'store' / 'audit.db'
    surface = load_submodule('audit_surface')
    original = surface._active_inventory
    def inventory(*args):
        value = original(*args)
        value['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
        return value
    monkeypatch.setattr(surface, '_active_inventory', inventory)
    result = surface.execute_audit({'action': 'run', 'root': str(project)}, db_path=db, wait=True)
    assert result['status'] == 'completed'
    assert canary not in json.dumps(result)
    assert canary.encode() not in db.read_bytes()
    with sqlite3.connect(db) as conn:
        assert canary not in '\n'.join(conn.iterdump())


@pytest.mark.parametrize('name,line', [('.envrc', 'source {target}'), ('.envrc', 'source_env {target}'), ('.envrc', 'dotenv {target}'), *[('.npmrc', key + '={target}') for key in ('pnpmfile', 'globalconfig', 'userconfig', 'init-module')]])
def test_audit_credential_execution_refs(tmp_path, name, line):
    home, profile, project, other = base(tmp_path, git=True)
    target = other / 'hook.sh'
    target.write_text('# inert\n')
    source = project / name
    source.write_text(line.format(target=target) + '\nAPI_KEY=/never/SECRET_CANARY\n')
    r = run(profile, project, other)
    assert 'SECRET_CANARY' not in json.dumps(r)
    assert not any(e['source'] == str(source) for e in r['blending'])
    assert any(c.get('kind') == 'credential_store' and c['path'] == str(source) for c in r['credentials'])
    assert 'credential_store_not_opened' in json.dumps(r)


@pytest.mark.parametrize('raw', ['**/tests/*', '*/src', '${root}/dist', '{{root}}/tests', '<rootDir>/dist/**/*.test.js'])
def test_audit_no_fabricated_glob_paths(tmp_path, raw):
    home, profile, project, other = base(tmp_path, git=True)
    (project / 'pyproject.toml').write_text('[tool.coverage.run]\nomit = ' + json.dumps([raw]))
    r = run(profile, project, other)
    assert not [e for e in r['blending'] if e['relationship'] == 'execution_path'], r['blending']


@pytest.mark.parametrize('relative,content', [
    ('.config/systemd/user/demo.service', '[Service]\nExecStart={target}'),
    ('.config/autostart/demo.desktop', '[Desktop Entry]\nExec={target}'),
    *[(n, 'source {target}') for n in ('.bashrc', '.profile', '.zshrc', '.bash_profile')],
    ('.npmrc', 'pnpmfile={target}'), ('.cargo/config.toml', '[target.demo]\nrunner="{target}"'),
    ('.local/lib/python3.14/site-packages/sitecustomize.py', 'PATH = "{target}"'),
    ('.local/lib/python3.14/site-packages/usercustomize.py', 'PATH = "{target}"'),
    ('.local/lib/python3.14/site-packages/demo.pth', '{target}'),
    ('.pythonrc', 'PATH = "{target}"'),
])
def test_audit_home_startup(tmp_path, relative, content):
    home, profile, project, other = base(tmp_path, git=True)
    target = project / 'tool.py'
    target.write_text('pass\n')
    source = home / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content.format(target=target))
    r = run(profile, project, other)
    if relative.startswith('.config/') or relative == '.npmrc':
        assert any(c.get('kind') == 'credential_store' and c['path'] == str(source) for c in r['credentials'])
        assert not any(e['source'] == str(source) for e in r['blending'])
        return
    assert any(d['path'] == str(source) for d in r['dynamic_invocations'])
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in r['blending'])


def test_audit_ci_template_role(tmp_path):
    home, profile, project, other = base(tmp_path, git=True)
    (project / 'azure-pipelines.yml').write_text('steps:\n  - template: template.yaml\n')
    source = project / 'template.yaml'
    source.write_text('steps:\n  - script: echo inert\n    workingDirectory: ' + str(other))
    r = run(profile, project, other)
    assert any(d['path'] == str(source) for d in r['dynamic_invocations'])
    assert any(e['source'] == str(source) and e['target'] == str(other) for e in r['blending'])


def test_audit_unreferenced_template_not_inert(tmp_path):
    home, profile, project, other = base(tmp_path, git=True)
    (project / 'template.yaml').write_text('steps: []')
    assert run(profile, project, other)['regions']['project_tree']['coverage'] == 'could_not_verify'


@pytest.mark.parametrize('name,key', [('biome.json', 'extends'), ('.eslintrc.json', 'extends'), ('ruff.toml', 'extend'), ('.prettierrc.json', 'extend'), ('babel.config.json', 'extends')])
def test_audit_config_inheritance(tmp_path, name, key):
    home, profile, project, other = base(tmp_path, git=True)
    target = other / 'settings.json'
    target.write_text('{}')
    source = project / name
    source.write_text(key + ' = "../other/settings.json"' if name.endswith('.toml') else json.dumps({key: '../other/settings.json'}))
    r = run(profile, project, other)
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in r['blending'])
    assert r['limits']['bytes_read'] >= source.stat().st_size + target.stat().st_size


@pytest.mark.parametrize('relative', ['config.yaml', 'mcp.json', 'cron/jobs.json'])
def test_audit_malformed_sibling(tmp_path, relative):
    home, profile, project, other = base(tmp_path, git=True)
    source = profile / 'profiles/other' / relative
    source.parent.mkdir(parents=True)
    source.write_text('{"mcp_servers": [')
    r = run(profile, project, other)
    region = r['regions']['sibling_profiles']
    assert region['coverage'] == 'could_not_verify'
    assert any('parse' in item['code'] for item in region['reason_details'])


@pytest.mark.parametrize('section', ['mcp_servers', 'hooks', 'plugins'])
def test_audit_sibling_commands(tmp_path, section):
    home, profile, project, other = base(tmp_path, git=True)
    target = project / 'tool.py'
    target.write_text('pass')
    source = profile / 'profiles/other/config.yaml'
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps({section: {'demo': {'command': str(target), 'args': ['--api-key', '/SECRET_CANARY']}}}))
    r = run(profile, project, other)
    assert 'SECRET_CANARY' not in json.dumps(r)
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in r['blending'])


def test_audit_code_inventory_aggregates(tmp_path):
    home, profile, project, other = base(tmp_path, git=True)
    root = profile / 'plugins/demo'
    root.mkdir(parents=True)
    for i in range(300):
        (root / f'mod{i}.py').write_text('pass\n')
    r = run(profile, project, other)
    assert r['regions']['dynamic_execution']['coverage'] == 'verified'
    entries = [d for d in r['dynamic_invocations'] if d.get('load_root') == str(root)]
    assert len(entries) == 1
    assert entries[0]['file_count'] == 300
    assert len(entries[0]['samples']) <= 5


@pytest.mark.parametrize('relative,key', [('.envrc', 'source'), ('.envrc', 'source_env'), ('.envrc', 'dotenv'), ('.npmrc', 'pnpmfile')])
def test_audit_bare_execution_reference(tmp_path, relative, key):
    home, profile, project, other = base(tmp_path, git=True)
    target = project / 'local.sh'
    target.write_text('# inert')
    source = project / relative
    source.write_text(key + ('=' if relative == '.npmrc' else ' ') + 'local.sh')
    r = run(profile, project, other)
    assert not any(e['source'] == str(source) for e in r['blending'])
    assert any(c.get('kind') == 'credential_store' and c['path'] == str(source) for c in r['credentials'])


@pytest.mark.parametrize('kind', ['skill', 'package'])
def test_audit_inventory_load_roots(tmp_path, kind):
    home, profile, project, other = base(tmp_path, git=True)
    root = profile / 'skills/demo' if kind == 'skill' else project
    root.mkdir(parents=True, exist_ok=True)
    if kind == 'package':
        (root / 'pyproject.toml').write_text('[project]\nname="demo"')
    for i in range(270):
        (root / f'mod{i}.py').write_text('pass')
    r = run(profile, project, other)
    entries = [d for d in r['dynamic_invocations'] if d.get('load_root') == str(root)]
    assert len(entries) == 1 and entries[0]['file_count'] == 270
    assert r['regions']['dynamic_execution']['coverage'] == 'verified'


def test_audit_cap_scoped_to_surface(tmp_path, monkeypatch):
    home, profile, project, other = base(tmp_path, git=True)
    for i in range(3):
        root = profile / 'plugins' / str(i)
        root.mkdir(parents=True)
        (root / 'mod.py').write_text('pass')
    monkeypatch.setattr(load_submodule('audit.outward'), 'MAX_INVOCATIONS', 1)
    r = run(profile, project, other)
    assert r['regions']['plugins']['coverage'] == 'could_not_verify'
    assert r['regions']['project_tree']['coverage'] == 'verified'
    assert r['regions']['dynamic_execution']['coverage'] == 'verified'
    assert r['regions']['cross_project_isolation']['coverage'] == 'verified'
