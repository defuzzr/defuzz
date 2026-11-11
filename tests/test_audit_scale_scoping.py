import sqlite3
from pathlib import Path


def test_open_wal_is_inspected_without_profile_writes(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    project.mkdir()
    with sqlite3.connect(profile / 'state.db') as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('CREATE TABLE sessions (cwd TEXT, started_at REAL)')
        writer.execute('INSERT INTO sessions VALUES (?, ?)', (str(project), 123))
        writer.commit()
        before = {p.name: (p.stat().st_mtime_ns, p.stat().st_size) for p in profile.iterdir() if not p.name.endswith('-shm')}
        before_names = {p.name for p in profile.iterdir()}
        result = outward.collect_outward(profile, [str(project)])
        assert result['session_history']['selected_project_records'] == 1
        assert result['regions']['session_history']['coverage'] == 'verified'
        assert before_names == {p.name for p in profile.iterdir()}
        assert before == {p.name: (p.stat().st_mtime_ns, p.stat().st_size) for p in profile.iterdir() if not p.name.endswith('-shm')}


def test_worktree_external_hook_is_dynamic(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    project.mkdir()
    gitdir = tmp_path / 'gitdir'
    gitdir.mkdir()
    (project / '.git').write_text('gitdir: ' + str(gitdir))
    (gitdir / 'config').write_text('[core]\n hooksPath = ' + str(tmp_path / 'hooks'))
    hooks = tmp_path / 'hooks'
    hooks.mkdir()
    (hooks / 'pre-commit').write_text('echo hello')
    result = outward.collect_outward(profile, [str(project)])
    assert any(d['path'] == str(hooks / 'pre-commit') for d in result['dynamic_invocations'])


def test_benign_structured_and_glob(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    project.mkdir()
    (project / 'tsconfig.json').write_text('{"include": ["src/**/*.ts"]}')
    (project / 'config.json').write_text('{"paths": ["*.txt"]}')
    (project / 'a.txt').write_text('plain')
    result = outward.collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'verified'
    assert any(e['target'] == str(project / 'a.txt') for e in result['blending'])

from .conftest import load_submodule


import pytest


@pytest.mark.parametrize('ddl,schema', [
    ('CREATE TABLE tasks(id TEXT, title TEXT, status TEXT, workspace_path TEXT)', 'hermes_kanban'),
    ('CREATE TABLE projects(id TEXT, slug TEXT, primary_path TEXT); CREATE TABLE project_folders(project_id TEXT, path TEXT)', 'hermes_projects'),
    ('CREATE TABLE responses(response_id TEXT, data TEXT, accessed_at REAL); CREATE TABLE conversations(name TEXT, response_id TEXT)', 'hermes_response_store'),
])
def test_known_hermes_database_schemas(tmp_path, ddl, schema):
    db = tmp_path / 'any-name.db'
    with sqlite3.connect(db) as conn:
        conn.executescript(ddl)
    result = load_submodule('audit.outward_db').inspect_database(db)
    assert result['schema'] == schema
    assert not result['uncertainties']


def test_unbounded_lifts_edge_invocation_and_row_caps(tmp_path, monkeypatch):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    (project / '.git').mkdir()
    for i in range(3):
        surface = project / 'hooks' / f'run{i}.sh'
        surface.parent.mkdir(exist_ok=True)
        surface.write_text('echo hi')
        (project / f'{i}.egg-link').write_text(str(surface))
    monkeypatch.setattr(outward, 'MAX_EDGES', 1)
    monkeypatch.setattr(outward, 'MAX_INVOCATIONS', 1)
    result = outward.collect_outward(profile, [str(project)], unbounded=True)
    assert len(result['blending']) > 1
    assert len(result['dynamic_invocations']) > 1
    assert result['limits']['max_edges'] is None
    db = profile / 'state.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE sessions(cwd TEXT)')
        conn.executemany('INSERT INTO sessions VALUES (?)', [(str(project),)] * 10001)
    report = load_submodule('audit.outward_db').inspect_database(db, unbounded=True)
    assert report['limits']['rows_inspected'] == 10001
    assert not report['limits']['truncated']


def test_lane_sessiondb_open_wal(tmp_path):
    from hermes_state import SessionDB
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    store = SessionDB(db_path=profile / 'state.db')
    try:
        result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
        assert result['regions']['session_history']['coverage'] == 'verified'
    finally:
        store.close()


def test_unknown_db_is_owned_by_containing_region(tmp_path):
    profile = tmp_path / '.hermes'
    (profile / 'plugins').mkdir(parents=True)
    with sqlite3.connect(profile / 'plugins' / 'unknown.db') as conn:
        conn.execute('CREATE TABLE t(x)')
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert result['regions']['plugins']['coverage'] == 'could_not_verify'
    assert result['regions']['session_history']['coverage'] == 'verified'
    assert result['regions']['active_profile']['coverage'] == 'verified'


def test_audited_home_xdg_git_include(tmp_path, monkeypatch):
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    project = tmp_path / 'project'
    project.mkdir()
    (project / '.git').mkdir()
    xdg = tmp_path / 'home' / 'custom-config'
    (xdg / 'git').mkdir(parents=True)
    hooks = tmp_path / 'hooks'
    hooks.mkdir()
    (hooks / 'pre-commit').write_text('echo hi')
    (xdg / 'git' / 'config').write_text('[include]\n path = extra\n')
    (xdg / 'git' / 'extra').write_text('[core]\n hooksPath = ' + str(hooks))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(xdg))
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert not any(d['path'] == str(hooks / 'pre-commit') for d in result['dynamic_invocations'])
    assert any(c['path'] == str(xdg / 'git' / 'extra') and c['kind'] == 'credential_store'
               for c in result['credentials'])


def test_fixture_location_does_not_hide_live_config(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'project'
    fixture = project / 'tests' / 'fixtures'
    fixture.mkdir(parents=True)
    target = tmp_path / 'shared'
    target.mkdir()
    (fixture / 'config.json').write_text('{"path": ' + repr(str(target)).replace("'", '"') + '}')
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert any(e['target'] == str(target) for e in result['blending'])


def test_python_dynamic_aliases_are_ordinary_code(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'dynamic.py').write_text('from subprocess import run as invoke\ninvoke(command)\n')
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert any(d['kind'] == 'program_code' and d['path'] == str(project / 'dynamic.py') for d in result['dynamic_invocations'])
    assert result['regions']['project_tree']['coverage'] == 'verified'


def test_jsonc_and_multidocument_lockfiles(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    project.mkdir()
    (project / 'tsconfig.json').write_text('{"files": [], // a comment\n "references": [],}')
    (project / 'pnpm-lock.yaml').write_text('---\nlockfileVersion: 9\n---\npackages: {}\n')
    result = outward.collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'verified'


def test_profile_unknown_does_not_poison_project(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    (profile / 'skills').mkdir(parents=True)
    project.mkdir()
    (profile / 'skills' / 'unknown.jsonl').write_text('{}\n')
    result = outward.collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'verified'
    assert result['regions']['skills']['coverage'] == 'could_not_verify'
    assert result['regions']['plugins']['coverage'] == 'verified'


def test_many_links_aggregate_without_losing_inspection(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    links = project / 'tools' / 'bin'
    links.mkdir(parents=True)
    target = tmp_path / 'target'
    target.write_text('ordinary data')
    for i in range(300):
        (links / str(i)).symlink_to(target)
    result = outward.collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'verified'
    edges = [e for e in result['blending'] if e['relationship'] == 'symlink']
    assert len(edges) == 1
    assert edges[0]['count'] == 300


def test_links_in_skipped_dependency_folder_are_not_walked(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    links = project / 'node_modules' / '.bin'
    links.mkdir(parents=True)
    target = tmp_path / 'target'
    target.write_text('ordinary data')
    for i in range(300):
        (links / str(i)).symlink_to(target)
    result = outward.collect_outward(profile, [str(project)])
    region = result['regions']['project_tree']
    assert region['coverage'] == 'could_not_verify'
    assert 'skipped_folders' in [d['code'] for d in region['reason_details']]
    skipped = str(project / 'node_modules')
    assert not [e for e in result['blending'] if e['relationship'] == 'symlink' and skipped in str(e)]


def test_local_python_call_needs_no_behavior_allowlist(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    project = tmp_path / 'project'
    profile.mkdir()
    project.mkdir()
    (project / 'plain.py').write_text('import json\ndef f(x):\n return str(x)\nf(1)\n')
    result = outward.collect_outward(profile, [str(project)])
    findings = [d for d in result['dynamic_invocations'] if d['path'] == str(project / 'plain.py')]
    assert len(findings) == 1 and findings[0]['kind'] == 'program_code'
    assert result['regions']['project_tree']['coverage'] == 'verified'


def test_incoming_active_skill_declaration(tmp_path):
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    (profile / 'skills').mkdir(parents=True)
    sibling = profile / 'profiles' / 'other'
    sibling.mkdir(parents=True)
    (sibling / 'config.yaml').write_text('skills:\n  external_dirs:\n    - ' + str(profile / 'skills'))
    result = outward.collect_outward(profile, [])
    assert any(e['relationship'] == 'incoming_sibling_reference' for e in result['blending'])
