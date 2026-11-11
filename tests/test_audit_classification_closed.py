import pytest
from tests.conftest import load_submodule

@pytest.mark.parametrize('name,data', [
 ('unknown.xyz', b'executor=opaque'), ('opaque.dat', b'\x7fELF\x00payload'),
 ('config.yaml', b'terminal:\n  custom_runner: malicious\n'),
 ('tsconfig.json', b'{"compilerOptions":{"customRunner":"opaque"}}'),
 ('biome.json', b'{"unrecognizedExecutor":"opaque"}'),
])
@load_submodule('audit.redaction').redaction_scope
def test_unknown_executable_semantics_never_verified(tmp_path, name, data):
    profile = tmp_path / '.hermes'; profile.mkdir()
    project = tmp_path / 'project'; project.mkdir()
    (project / name).write_bytes(data)
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    # Known code/config is inventoried, not behavior-analyzed. Unknown types
    # still fail closed, and path-bearing declarations retain their edges.
    if name in {'unknown.xyz', 'arbitrary'}:
        assert result['regions']['project_tree']['coverage'] == 'could_not_verify'
    elif name in {'tsconfig.json', 'biome.json'}:
        assert result['regions']['project_tree']['coverage'] == 'verified'
    else:
        assert any(d['path'] == str(project / name) for d in result['dynamic_invocations'])
    if name == 'pnpm-workspace.yaml':
        expected = load_submodule('audit.redaction')._CURRENT.get().serializer._hmac(str(tmp_path / 'outside'))
        assert any(isinstance(b['target'], dict) and b['target']['kind'] == 'unresolved_reference'
                   and b['target']['hmac'] == expected for b in result['blending'])


@pytest.mark.parametrize('name,data', [
 ('arbitrary', b'[CORE]\nfsmonitor=opaque\n'),
 ('arbitrary', b'[sequence]\neditor=opaque\n'),
 ('pnpm-workspace.yaml', b'packages: ["../outside"]\n'),
 ('run.py', b'import pickle\npickle.loads(data)\n'),
 ('run.py', b'import os\n@os.system\ndef f(): pass\n'),
])
def test_review_false_verification(tmp_path, name, data):
    test_unknown_executable_semantics_never_verified(tmp_path, name, data)


def test_sibling_exclusion_precedes_metadata_reads(tmp_path, monkeypatch):
    import os
    profile = tmp_path / '.hermes'; profile.mkdir()
    sibling = profile / 'profiles' / 'excluded'; sibling.mkdir(parents=True)
    (sibling / 'config.yaml').write_text('{}')
    original = os.open
    def guarded(path, flags, *args, **kwargs):
        parent = kwargs.get('dir_fd')
        resolved = __import__('pathlib').Path(os.readlink(f'/proc/self/fd/{parent}')) / path if parent is not None else __import__('pathlib').Path(path)
        assert resolved != sibling and not resolved.is_relative_to(sibling)
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', guarded)
    result = load_submodule('audit.outward').collect_outward(profile, [], excluded_paths=[sibling])
    assert result['regions']['sibling_profiles']['coverage'] == 'could_not_verify'


def test_database_budget_and_report_disclosure(tmp_path, monkeypatch):
    import sqlite3
    profile = tmp_path / 'home' / '.hermes'; profile.mkdir(parents=True)
    project = tmp_path / 'project'; project.mkdir()
    db = profile / 'kanban.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE tasks(id TEXT, title TEXT, status TEXT, workspace_path TEXT)')
        conn.execute('INSERT INTO tasks VALUES (?,?,?,?)', ('CANARY-ID', 'CANARY-TITLE', 'running', str(project)))
    outward = load_submodule('audit.outward')
    limited = outward.collect_outward(profile, [str(project)], max_bytes=64)
    assert limited['regions']['active_profile']['coverage'] == 'could_not_verify'
    monkeypatch.setenv('HERMES_HOME', str(profile))
    monkeypatch.setenv('HOME', str(profile.parent))
    from hermes_cli import projects_db
    conn = projects_db.connect(db_path=profile / 'projects.db')
    projects_db.create_project(conn, name='selected', primary_path=str(project))
    conn.close()
    surface = load_submodule('audit_surface')
    report = surface.execute_audit({'action': 'run'}, db_path=tmp_path / 'output.db', wait=True)['report']
    assert report['database_records']
    assert 'CANARY-' not in __import__('json').dumps(report)
