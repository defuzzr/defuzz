"""Public product contracts, isolated from live Hermes state."""
import argparse
from tests.conftest import load_submodule


def test_new_accepts_prompt_and_repeated_options():
    cli = load_submodule('cli')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    ns = parser.parse_args(['new', '--prompt', 'Python API named Ledger', '--option', 'http_adapter=stdlib_http'])
    assert ns.prompt == 'Python API named Ledger'
    assert ns.option == ['http_adapter=stdlib_http']


def test_cli_prompt_options_reach_existing_flow(monkeypatch, capsys):
    import io, sys
    cli = load_submodule('cli')
    from types import SimpleNamespace
    calls = []
    def flow(**kwargs):
        calls.append(('flow', kwargs))
        return SimpleNamespace(status='no_match', message='No match')
    def propose(spec, name, answers, **kwargs):
        calls.append(('propose', {'template_id': spec.id, 'name': name, 'answers': answers, **kwargs}))
        raise cli.ScaffoldError('stop after propose')
    kit = SimpleNamespace(id='video-production', name='Video production', summary='Video project.')
    monkeypatch.setattr(cli, '_load_kits', lambda: ([kit], 'ok', ''))
    monkeypatch.setattr(cli, 'run_new_project_flow', flow)
    monkeypatch.setattr(cli, 'propose', propose)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(''))
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    base = ['new', '--prompt', 'Python API named Ledger', '--option', 'http_adapter=stdlib_http']
    # Without an explicit id nothing is chosen: neither creation path is reached.
    ns = parser.parse_args(base)
    assert cli.handle_defuzz_cli(ns) == 2
    assert calls == []
    assert 'Nothing was created. Run again with --template ID or --kit ID.' in capsys.readouterr().out
    # An explicit kit reaches the existing flow with the prompt answers and options.
    ns = parser.parse_args(base + ['--kit', 'video-production'])
    assert cli.handle_defuzz_cli(ns) == 2
    (kind, captured), = calls
    assert kind == 'flow' and captured['kit_id'] == 'video-production'
    assert captured['options'] == {'http_adapter': 'stdlib_http'}
    assert captured['initial_answers']['languages'] == ['python']
    # An explicit template reaches propose with the same prompt answers and options.
    calls.clear()
    ns = parser.parse_args(base + ['--template', 'python-golden'])
    assert cli.handle_defuzz_cli(ns) == 1
    (kind, captured), = calls
    assert kind == 'propose' and captured['template_id'] == 'python-golden'
    assert captured['name'] == 'Ledger'
    assert captured['options'] == {'http_adapter': 'stdlib_http'}
    assert captured['answers']['languages'] == ['python']
    calls.clear()
    for extra in ([], ['--kit', 'video-production'], ['--template', 'python-golden']):
        ns = parser.parse_args(base + extra)
        ns.option = ['broken']
        assert cli.handle_defuzz_cli(ns) == 1
    assert calls == []


def test_scaffold_routes_use_real_parser_and_server_proposals(tmp_path):
    api = load_submodule('dashboard.plugin_api')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI(); app.include_router(api.router)
    client = TestClient(app)
    response = client.post('/scaffold/parse-idea', json={'prompt': 'Python API named Ledger'})
    assert response.status_code == 200
    parsed = response.json()
    assert parsed['source'] == 'deterministic'
    assert parsed['answers']['languages'] == ['python']
    answers = {'kind': 'service', 'layout': 'single', 'languages': ['python']}
    match = client.post('/scaffold/match', json={'answers': answers})
    assert match.status_code == 200
    response = client.post('/scaffold/propose', json={'template_id': 'python-golden', 'name': 'Ledger', 'answers': answers, 'dest_root': str(tmp_path/'projects')})
    assert response.status_code == 200, response.text
    proposal = response.json()
    assert proposal['tree']
    assert not (tmp_path/'projects'/'ledger').exists()
    assert client.post('/scaffold/accept', json={'proposal_id': proposal['proposal_id']}).status_code == 400
    assert client.post('/scaffold/discard', json={'proposal_id': proposal['proposal_id']}).status_code == 200
    assert client.post('/scaffold/accept', json={'proposal_id': proposal['proposal_id'], 'confirm': True}).status_code == 404


def test_lock_trust_reads_do_not_trust_and_edits_invalidate(tmp_path):
    guard = load_submodule('tool_guard')
    project = tmp_path/'repo'; project.mkdir()
    db = tmp_path/'plugin'/'state.db'
    (project/'TOOLS.lock').write_text('[lock]\nschema=1\n')
    first = guard.inspect_lock_trust(project, db_path=db)
    assert first['status'] == 'unknown'
    assert not db.exists()
    trusted = guard.trust_lock(project, expected_hash=first['tools_lock_hash'], db_path=db)
    assert trusted['trusted']
    (project/'TOOLS.lock').write_text('[lock]\nschema=1\n# changed\n')
    assert guard.inspect_lock_trust(project, db_path=db)['status'] == 'untrusted'
    import pytest
    with pytest.raises(ValueError):
        guard.trust_lock(project, expected_hash=first['tools_lock_hash'], db_path=db)
    with pytest.raises(ValueError):
        guard.trust_lock(project, expected_hash='x', db_path=project/'state.db')


def test_workspace_and_ui_state_are_bounded(tmp_path, monkeypatch):
    api = load_submodule('dashboard.plugin_api')
    routes = api._load('dashboard.routes.workspace_routes')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI(); app.include_router(api.router); client = TestClient(app)
    assert client.get('/workspace/projects').status_code == 200
    root = tmp_path/'repo'; root.mkdir()
    (root/'README.md').write_text('hello')
    (root/'.env').write_text('SECRET=no')
    (root/'link').symlink_to(root/'README.md')
    from types import SimpleNamespace
    registrations = api._load('audit.readonly_db')
    assert client.get('/workspace/file', params={'project':str(root),'path':'README.md'}).status_code == 400
    monkeypatch.setattr(registrations, 'read_profile_registrations_readonly', lambda *a: SimpleNamespace(
        coverage='verified', changed_during_read=False, records=[{'canonical_path': str(root)}]))
    assert client.get('/workspace/file', params={'project':str(root),'path':'README.md'}).json()['content'] == 'hello'
    for path in ['../outside','.env','link']:
        assert client.get('/workspace/file', params={'project':str(root),'path':path}).status_code == 400
    assert client.post('/ui-state', json={'key':'split','value':70,'seq':2}).status_code == 200
    client.post('/ui-state', json={'key':'split','value':10,'seq':1})
    assert client.get('/ui-state', params={'key':'split'}).json()['value'] == 70


def test_audit_surface_runs_persists_and_never_executes(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    facts = load_submodule('audit.facts')
    home = tmp_path/'profile'; home.mkdir()
    (home/'config.yaml').write_text('model: test\n')
    original = facts.collect_system_inventory_facts
    monkeypatch.setattr(surface, '_active_inventory', lambda as_of, threshold: original(as_of=as_of, unused_threshold_days=threshold, list_profile_names_fn=lambda:['default'], get_profile_dir_fn=lambda n:home, active_profile='default'))
    from tests.test_audit_tripwires import sweep_forbidden_call_tripwires
    db = tmp_path/'output'/'state.db'
    db.parent.mkdir()
    with sweep_forbidden_call_tripwires(allowed_write_root=db.parent):
        result = surface.execute_audit({'action':'run','as_of':1234567890}, db_path=db, wait=True)
    assert result['run_id']
    assert result['report']['scope']['description'] == 'Project-outward full static audit'
    assert all(region['coverage'] == 'verified' for region in result['report']['scope']['regions'].values())
    # Static scope completion does not override unverifiable vendor evidence.
    assert result['report']['headline']['can_claim_clean'] is False
    stored = surface.execute_audit({'action':'report','run_id':result['run_id']}, db_path=db)
    assert stored['report'] == result['report']
    import pytest
    with pytest.raises(ValueError):
        surface.execute_audit({'action':'cleanup','run_id':result['run_id']}, db_path=db)


def test_audit_registration_cli_and_routes_match_manifest(tmp_path, monkeypatch):
    import json
    from tests.conftest import ensure_test_package, REPO_ROOT
    pkg = ensure_test_package()
    tools = []
    class Context:
        def get_config(self, key, default): return default
        def register_tool(self, **kwargs): tools.append(kwargs['name'])
        def register_hook(self, *args, **kwargs): pass
        def register_cli_command(self, **kwargs): pass
        def register_command(self, **kwargs): pass
    pkg.register(Context())
    assert 'defuzz_audit' in tools
    assert '  - defuzz_audit' in (REPO_ROOT/'plugin.yaml').read_text()
    assert 'PyYAML>=6.0.3,<7' in (REPO_ROOT/'plugin.yaml').read_text()
    cli = load_submodule('cli'); parser = argparse.ArgumentParser(); cli.setup_defuzz_cli(parser)
    ns = parser.parse_args(['audit', 'report', '--run-id', 'missing'])
    assert cli.handle_defuzz_cli(ns) == 1
    result = pkg._handle_slash_command(Context(), 'audit report --run-id missing')
    assert 'Unknown audit' in result
    api = load_submodule('dashboard.plugin_api')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI(); app.include_router(api.router); client = TestClient(app)
    assert client.get('/audit/report', params={'run_id':'missing'}).status_code == 404
    assert client.post('/audit/cleanup', json={}).status_code == 404


def test_lock_trust_rest_requires_exact_reviewed_hash(tmp_path):
    api = load_submodule('dashboard.plugin_api')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI(); app.include_router(api.router); client = TestClient(app)
    root = tmp_path/'repo'; root.mkdir(); (root/'TOOLS.lock').write_text('[lock]\nschema=1\n')
    data = client.get('/tools-lock', params={'project':str(root)}).json()
    assert data['trust']['status'] == 'unknown'
    body = {'project':str(root),'confirm':True,'expected_hash':data['trust']['tools_lock_hash']}
    assert client.post('/tools-lock/trust', json=body).json()['trusted'] is True
    (root/'TOOLS.lock').write_text('[lock]\nschema=1\n# changed\n')
    assert client.post('/tools-lock/trust', json=body).status_code == 409


def test_audit_worker_failure_is_persisted_and_resumable(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    db = tmp_path/'state.db'
    original = surface._sweep
    def fail(*args):
        raise RuntimeError('source secret must not be returned')
    monkeypatch.setattr(surface, '_sweep', fail)
    started = surface.execute_audit({'selected_projects':[], 'as_of':1234567890}, db_path=db)
    assert surface._RUN_LOCK.acquire(timeout=10)
    surface._RUN_LOCK.release()
    failed = surface.execute_audit({'action':'status', 'run_id':started['run_id']}, db_path=db)
    assert failed['status'] == 'failed'
    assert 'secret' not in repr(failed)
    monkeypatch.setattr(surface, '_sweep', original)
    resumed = surface.execute_audit({'action':'resume', 'run_id':started['run_id']}, db_path=db, wait=True)
    assert resumed['status'] == 'completed'
    assert resumed['as_of'] == 1234567890
    assert resumed['report']['headline']['can_claim_clean'] is False


def test_workspace_registration_is_active_profile_only(tmp_path, monkeypatch):
    import sqlite3
    import hermes_constants
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    api = load_submodule('dashboard.plugin_api')
    app = FastAPI(); app.include_router(api.router); client = TestClient(app)
    root = tmp_path/'registered'; root.mkdir(); (root/'README.md').write_text('visible')
    active, sibling = tmp_path/'active', tmp_path/'sibling'
    for home, paths in [(active, []), (sibling, [str(root)])]:
        db = home/'plugin-data'/'defuzz'/'state.db'; db.parent.mkdir(parents=True)
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY)')
            conn.executemany('INSERT INTO projects VALUES (?)', [(p,) for p in paths])
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: active)
    params = {'project':str(root),'path':'README.md'}
    assert client.get('/workspace/file', params=params).status_code == 400
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: sibling)
    assert client.get('/workspace/file', params=params).json()['content'] == 'visible'
    (sibling/'plugin-data'/'defuzz'/'state.db').write_bytes(b'unreadable sqlite')
    assert client.get('/workspace/file', params=params).status_code == 400


def test_audit_start_returns_before_profile_capture(tmp_path, monkeypatch):
    import threading
    surface = load_submodule('audit_surface')
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()
    original = surface.facts.collect_profile_unit_facts
    def blocked(**kwargs):
        entered.set()
        assert release.wait(10)
        return original(**kwargs)
    monkeypatch.setattr(surface.facts, 'collect_profile_unit_facts', blocked)
    result = []
    def start():
        result.append(surface.execute_audit({'selected_projects':[], 'full_home': True}, db_path=tmp_path/'state.db'))
        returned.set()
    thread = threading.Thread(target=start); thread.start()
    try:
        assert entered.wait(5)
        assert returned.wait(1), 'profile capture must run after start returns an ID'
        surface.execute_audit({'action':'cancel', 'run_id':result[0]['run_id']}, db_path=tmp_path/'state.db')
    finally:
        release.set(); thread.join(10)
        assert surface._RUN_LOCK.acquire(timeout=10)
        surface._RUN_LOCK.release()


def test_lock_edit_does_not_bless_or_overwrite_concurrent_bytes(tmp_path, monkeypatch):
    import pytest
    guard = load_submodule('tool_guard'); toolchk = load_submodule('toolchk')
    root = tmp_path/'repo'; root.mkdir(); db = tmp_path/'state.db'
    toolchk.dump_lock(root/'TOOLS.lock', {'tools':{'python':{
        'version':'3.14.9', 'chosen':'2026-01-01', 'reason':'reviewed',
        'source':'human', 'probe':'command', 'argv':['python','--version']}}})
    original = (root/'TOOLS.lock').read_bytes()
    monkeypatch.setattr(toolchk, 'probe', lambda *a: ('3.14.9', '/trusted/python'))
    state = guard.inspect_lock_trust(root, db_path=db)
    guard.trust_lock(root, expected_hash=state['tools_lock_hash'], db_path=db)
    check = toolchk.check
    external = original + b'\n# concurrent edit\n'
    def mutate_before_publication(*a, **k):
        (root/'TOOLS.lock').write_bytes(external)
        return check(*a, **k)
    with monkeypatch.context() as scoped:
        scoped.setattr(toolchk, 'check', mutate_before_publication)
        with pytest.raises(ValueError, match='changed during edit'):
            guard.edit_lock(root, 'python', 'new reason', action='reason', db_path=db)
    assert (root/'TOOLS.lock').read_bytes() == external
    assert guard.inspect_lock_trust(root, db_path=db)['status'] == 'untrusted'
    (root/'TOOLS.lock').write_bytes(original)
    def mutate_during_publication(*a):
        (root/'TOOLS.lock').write_bytes(external)
        raise OSError('publication failed')
    monkeypatch.setattr(guard, '_publish_digest', mutate_during_publication)
    with pytest.raises(OSError):
        guard.edit_lock(root, 'python', 'new reason', action='reason', db_path=db)
    assert (root/'TOOLS.lock').read_bytes() == external
    assert guard.inspect_lock_trust(root, db_path=db)['status'] == 'untrusted'


def test_plugin_reason_edit_preserves_trust_and_rolls_back(tmp_path, monkeypatch):
    api = load_submodule('dashboard.plugin_api')
    guard = api._load('tool_guard'); toolchk = api._load('toolchk')
    def no_audit_key():
        raise AssertionError('Lock publication must not access the audit key')
    monkeypatch.setattr(api._load('audit.key'), '_load_key', no_audit_key)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    root = tmp_path/'repo'; root.mkdir()
    toolchk.dump_lock(root/'TOOLS.lock', {'tools':{'python':{
        'version':'3.14.9', 'chosen':'2026-01-01', 'reason':'reviewed',
        'source':'human', 'probe':'command', 'argv':['python','--version']}}})
    monkeypatch.setattr(toolchk, 'probe', lambda *a: ('3.14.9', '/trusted/python'))
    state = guard.inspect_lock_trust(root)
    guard.trust_lock(root, expected_hash=state['tools_lock_hash'])
    app = FastAPI(); app.include_router(api.router); client = TestClient(app)
    body = {'project':str(root), 'tool':'python', 'reason':'explicit reason'}
    response = client.post('/tools-lock/reason', json=body)
    assert response.status_code == 200, response.text
    after = guard.inspect_lock_trust(root)
    assert after['trusted']
    assert after['tools_lock_hash'] != state['tools_lock_hash']
    before = (root/'TOOLS.lock').read_bytes()
    publish = guard._publish_digest
    def fail(*a, **k):
        publish(*a, **k)
        raise OSError('publication failed')
    monkeypatch.setattr(guard, '_publish_digest', fail)
    response = client.post('/tools-lock/reason', json={**body, 'reason':'must roll back'})
    assert response.status_code == 400
    assert (root/'TOOLS.lock').read_bytes() == before
    assert guard.inspect_lock_trust(root) == after
    monkeypatch.setattr(guard, '_publish_digest', publish)
    import sqlite3
    connect = sqlite3.connect
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError('commit failed')
    with monkeypatch.context() as scoped:
        scoped.setattr(guard.sqlite3, 'connect', lambda *a, **k: connect(*a, **{**k, 'factory':CommitFailure}))
        response = client.post('/tools-lock/reason', json={**body, 'reason':'commit rollback'})
        assert response.status_code == 400
    assert (root/'TOOLS.lock').read_bytes() == before
    assert guard.inspect_lock_trust(root) == after
    monkeypatch.setattr(toolchk, 'probe', lambda *a: ('3.14.10', '/trusted/python'))
    response = client.post('/tools-lock/accept', json={**body, 'reason':'accept tested runtime'})
    assert response.status_code == 200, response.text
    assert guard.inspect_lock_trust(root)['trusted']
    assert toolchk.load_lock(root/'TOOLS.lock')['tools']['python']['version'] == '3.14.10'
    with (root/'TOOLS.lock').open('a') as stream:
        stream.write('\n# external modification\n')
    assert guard.inspect_lock_trust(root)['status'] == 'untrusted'
    assert client.post('/tools-lock/reason', json=body).status_code == 200
    assert guard.inspect_lock_trust(root)['status'] == 'untrusted'


def test_audit_root_selects_one_registered_project_not_parent(tmp_path, monkeypatch):
    import pytest
    surface = load_submodule('audit_surface')
    child = tmp_path/'parent'/'repo'; child.mkdir(parents=True)
    monkeypatch.setattr(surface, '_active_inventory', lambda a, t: {
        'active_profile':'default', 'profile_units':[], 'coverage':'verified',
        'project_units':[{'canonical_path':str(child)}]})
    with pytest.raises(ValueError, match='not registered'):
        surface.execute_audit({'root':str(child.parent)}, db_path=tmp_path/'state.db')
    prepared = surface._prepare(surface.AuditStore(tmp_path/'state.db'), {'root':str(child)})
    assert [p['canonical_path'] for p in prepared[3]] == [str(child)]
    cli = load_submodule('cli'); parser = argparse.ArgumentParser(); cli.setup_defuzz_cli(parser)
    audit = parser._subparsers._group_actions[0].choices['audit']
    assert 'registered project' in audit.format_help()
    assert 'discovery' not in audit.format_help()


def test_audit_start_can_cancel_blocked_final_collector(tmp_path, monkeypatch):
    import threading
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    api = load_submodule('dashboard.plugin_api')
    surface = api._load('audit_surface')
    facts = api._load('audit.facts')
    home = tmp_path/'profile'; home.mkdir()
    original = facts.collect_system_inventory_facts
    monkeypatch.setattr(surface, '_active_inventory', lambda a, t: original(
        as_of=a, unused_threshold_days=t, list_profile_names_fn=lambda:['default'],
        get_profile_dir_fn=lambda n:home, active_profile='default'))
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()
    collector = surface.executable_inventory.audit_executable_inventory
    def blocked(**kwargs):
        entered.set()
        assert release.wait(10)
        return collector(**kwargs)
    monkeypatch.setattr(surface.executable_inventory, 'audit_executable_inventory', blocked)
    app = FastAPI(); app.include_router(api.router); client = TestClient(app)
    response = []
    def start():
        response.append(client.post('/audit/start', json={'selected_projects':[], 'full_home': True}))
        returned.set()
    thread = threading.Thread(target=start); thread.start()
    try:
        # The final collector runs after the whole full-home sweep (outward walk, identity
        # reads, every other component): several seconds on a small machine. This bound
        # only catches a hang, so it matches the component budget, not a speed target.
        assert entered.wait(60)
        assert returned.wait(1), 'start must return before the blocked collector finishes'
        run_id = response[0].json()['run_id']
        assert client.get('/audit/status', params={'run_id':run_id}).json()['status'] == 'running'
        assert client.post('/audit/cancel', json={'run_id':run_id}).json()['status'] == 'cancelled'
    finally:
        release.set(); thread.join(10)
        # Wait for the bounded worker to leave its final safe boundary.
        assert surface._RUN_LOCK.acquire(timeout=10)
        surface._RUN_LOCK.release()
    assert client.get('/audit/status', params={'run_id':run_id}).json()['status'] == 'cancelled'
