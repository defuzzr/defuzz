"""Global credential, desktop working directory and invocation budget regressions; synthetic fixtures, no source payload is executed."""
import json
import sqlite3
import pytest
from tests.conftest import load_submodule
from tests.test_audit_outward_inventory_contracts import base, run, _no_host_system_gitconfig


@pytest.mark.parametrize('unbounded', [False, True])
def test_audit_global_credential_canary(tmp_path, monkeypatch, unbounded):
    home, profile, project, other = base(tmp_path, git=True)
    canary = 'PROBE_GLOBAL_CREDENTIAL_CANARY'
    secret = str(other / canary)
    sources = {
        home / '.pythonrc': f'API_KEY = "{secret}"',
        home / '.local/lib/python3.14/site-packages/sitecustomize.py': f'API_KEY = "{secret}"',
        home / '.local/lib/python3.14/site-packages/usercustomize.py': f'credentials = {{"auth": "{secret}"}}',
        home / '.bashrc': f'export API_KEY="{secret}"',
        home / '.profile': f'API_KEY="{secret}"',
        home / '.zshrc': f'API_KEY="{secret}"',
        home / '.bash_profile': f'API_KEY="{secret}"',
        home / '.npmrc': f'_authToken={secret}',
        home / '.local/lib/python3.14/site-packages/demo.pth': f'import os; API_KEY="{secret}"',
        project / 'package.json': json.dumps({'name': 'example', 'config': {'apiKey': secret}}),
        project / 'pyproject.toml': f'[tool.example]\napi_key="{secret}"',
        profile / 'mcp.json': json.dumps({'mcpServers': {'demo': {'command': 'echo', 'args': ['--auth', secret]}}}),
        profile / 'profiles/sibling/config.yaml': json.dumps({'apiKey': secret}),
        home / '.config/systemd/user/a.service': f'[Service]\nEnvironment=API_KEY={secret}',
        home / '.config/autostart/a.desktop': f'[Desktop Entry]\nExec=echo --api-key {secret}',
        home / '.cargo/config.toml': f'[env]\nAPI_KEY="{secret}"',
        project / 'a.py': f'private_key = "{secret}"',
        project / 'a.sh': f'API_KEY = "{secret}"',
        project / '.env': f'API_KEY={secret}',
        project / '.envrc': f'API_KEY={secret}',
        project / '.npmrc': f'_authToken={secret}',
        project / 'a.ini': f'[auth]\nAPI_KEY={secret}',
        project / 'a.toml': f'API_KEY="{secret}"',
        project / 'a.yaml': f'API_KEY: "{secret}"',
        project / 'a.json': json.dumps({'API_KEY': secret}),
        project / 'a.code-workspace': json.dumps({'settings': {'apiKey': secret}}),
        profile / 'config.yaml': json.dumps({'mcp_servers': {'demo': {'command': 'echo', 'args': ['--api-key', secret]}}}),
        profile / 'cron/jobs.json': json.dumps({'jobs': [{'command': 'echo --token ' + secret}]}),
        profile / 'sessions/demo.jsonl': json.dumps({'API_KEY': secret, 'cwd': secret}),
    }
    secrets = []
    for index, (path, content) in enumerate(sources.items()):
        unique = secret + '_' + str(index) + '_END'
        secrets.append(unique)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.replace(secret, unique))
    secret += '_KANBAN_END'
    secrets.append(secret)
    with sqlite3.connect(profile / 'kanban.db') as conn:
        conn.execute('CREATE TABLE tasks(id TEXT, title TEXT, status TEXT, workspace_path TEXT)')
        conn.execute('INSERT INTO tasks VALUES (?, ?, ?, ?)', ('1', 'API_KEY=' + secret, 'todo', secret))
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    surface = load_submodule('audit_surface')
    original = surface._active_inventory
    def inventory(*args):
        value = original(*args)
        value['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
        return value
    monkeypatch.setattr(surface, '_active_inventory', inventory)
    # Simulate a future scanner bypassing every extraction filter. Every
    # captured format must taint its unique value before this sink is reached.
    outward = load_submodule('audit.outward')
    collect = outward.collect_outward
    def bypass(*args, **kwargs):
        report = collect(*args, **kwargs)
        report['database_records'] = [{'path': value, 'reason': 'failed: ' + value, value: value}
                                    for value in secrets]
        return report
    monkeypatch.setattr(outward, 'collect_outward', bypass)
    db = tmp_path / 'store/audit.db'
    result = surface.execute_audit({'action': 'run', 'root': str(project), 'unbounded': unbounded}, db_path=db, wait=True)
    assert result['status'] == 'completed'
    assert canary not in json.dumps(result)
    records = result['report']['database_records']
    assert len(records) == len(secrets)
    assert all(r['path']['kind'] == 'unresolved_reference' and len(r['path']['hmac']) == 64 for r in records)
    assert all(any(key.startswith('hmac:') for key in r) for r in records)
    assert load_submodule('audit.contract').canonical_report_digest(result['report']) == result['canonical_digest']
    assert canary.encode() not in db.read_bytes()
    with sqlite3.connect(db) as conn:
        assert canary not in '\n'.join(conn.iterdump())


def test_audit_desktop_working_directory(tmp_path):
    home, profile, project, other = base(tmp_path, git=True)
    source = home / '.config/autostart/demo.desktop'
    source.parent.mkdir(parents=True)
    source.write_text(f'[Desktop Entry]\nType=Application\nExec=true\nPath={project}\n')
    report = run(profile, project, other)
    assert not any(e['source'] == str(source) for e in report['blending'])
    assert any(c.get('kind') == 'credential_store' and c['path'] == str(source) for c in report['credentials'])


@pytest.mark.parametrize('unbounded', [False, True])
def test_audit_invocation_budget_independent_roots(tmp_path, monkeypatch, unbounded):
    home, profile, project, other = base(tmp_path, git=True)
    for i in range(4):
        (project / f'mod{i}.py').write_text('pass\n')
    plugin = profile / 'plugins/demo/main.py'
    plugin.parent.mkdir(parents=True)
    plugin.write_text('pass\n')
    outward = load_submodule('audit.outward')
    monkeypatch.setattr(outward, 'MAX_INVOCATIONS', 2)
    report = run(profile, project, other, unbounded=unbounded)
    assert any(d['path'] == str(plugin) for d in report['dynamic_invocations'])
    assert report['regions']['plugins']['coverage'] == 'verified'
    counts = report['limits']['invocation_roots']
    assert counts[str(project.resolve())]['admitted'] == (4 if unbounded else 2)
    assert counts['plugins']['admitted'] == 1
    assert counts[str(project.resolve())]['cuts'] == (0 if unbounded else 2)
