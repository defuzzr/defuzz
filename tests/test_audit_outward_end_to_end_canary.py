"""Outward audit end to end: persisted secret canary and a snapshot of this repository."""
import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

from tests.conftest import load_submodule

WT = Path(__file__).resolve().parents[1]


def log(name, **kw):
    if name == 'g1_separate_gitdir_fsmonitor': assert kw['dyn']
    elif name.startswith(('g2_', 'g3')): assert kw['dyn'] and kw['blending']
    elif name == 'd1_wal_open':
        assert kw['unchanged'] and kw['session']['selected_project_records'] == 1
    elif name == 'd2_core_dbs': assert kw['unchanged'] and kw['dbs']
    elif name == 'd3_unknown_db_project': assert kw['coverage']['project_tree'] == 'could_not_verify'
    elif name == 'd4_sqlite_nosuffix': assert kw['bad'] or kw.get('dbs')
    elif name == 'c1_caps':
        assert kw['edges'][1] > kw['edges'][0]
        assert all(v is None for v in kw['lim'].values())
    elif name in {'s1_code_workspace','s2_package_file_dep','s4_mcp_args','i1_sibling_symlink','i2_default_incoming','i3_sibling_config','r3_ancestor_symlink'}:
        assert kw['blending']
    elif name == 's3_python':
        assert all(v[0] == 'could_not_verify' and v[1] for k,v in kw['results'].items() if k != 'open_other')
    elif name == 's5_other_region': assert kw['coverage']['other_projects'] == 'could_not_verify'
    elif name == 'r1_parent_session': assert kw['session']['selected_project_records'] == 1 and kw['blending']
    elif name == 'r2_canary': assert not kw['leaked'] and kw['creds']
    elif name == 'e2e_canary': assert kw['err'] is None and not kw['leaked']
    elif name == 'repo_self': assert kw['entries'] > 100 and kw['project_tree'] == 'could_not_verify'
    elif name == 'k1_named_kanban': assert kw['mentions_kanban'] and kw['blending']
    elif name == 'p1_projects_folders': assert kw['err'] is None and kw['dyn'] and kw['blending']
    else: raise AssertionError(name)



def test_e2e_canary_persisted(tmp_path, monkeypatch):
    canary = 'CANARYE2E-55aa77'
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    (profile / '.env').write_text('OPENAI_API_KEY=' + canary + '\n')
    (profile / 'config.yaml').write_text('providers:\n  x:\n    api_key: ' + canary + '1\nmcp_servers:\n  y:\n    env:\n      T: ' + canary + '2\n'
                                         '    headers:\n      Authorization: Bearer ' + canary + '3\n')
    c = sqlite3.connect(profile / 'state.db')
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('CREATE TABLE sessions (id TEXT, title TEXT, cwd TEXT, started_at REAL)')
    c.execute('INSERT INTO sessions VALUES (?,?,?,?)', ('s', canary + '4', '/x', 1.0))
    c.commit()
    monkeypatch.setenv('HERMES_HOME', str(profile))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    surface = load_submodule('audit_surface')
    db = tmp_path / 'store' / 'audit.db'
    db.parent.mkdir()
    err = None
    try:
        res = surface.execute_audit({'action': 'run'}, db_path=db, wait=True)
    except Exception as exc:
        err = repr(exc)[:300]
        res = None
    c.close()
    blobs = b''.join(p.read_bytes() for p in db.parent.iterdir() if p.is_file())
    log('e2e_canary', err=err, status=(res or {}).get('status'), leaked=canary.encode() in blobs,
        store_files=sorted(p.name for p in db.parent.iterdir()),
        profile_files=sorted(p.name for p in profile.iterdir()),
        scope_cov=((res or {}).get('report') or {}).get('scope', {}).get('coverage'))


def test_repo_self_snapshot(tmp_path):
    repo = tmp_path / 'repo'
    if repo.exists():
        shutil.rmtree(repo)
    files = []
    for dirpath, dirnames, filenames in os.walk(WT):
        dirnames[:] = [d for d in dirnames if d not in ('.git', '.worktrees', '__pycache__', '.pytest_cache')]
        for name in filenames:
            if name == '.git' or name.startswith('test_zz_'):
                continue
            files.append(os.path.relpath(os.path.join(dirpath, name), WT).encode())
    for f in files:
        if not f:
            continue
        src = WT / f.decode()
        if src.is_symlink() or not src.is_file():
            continue
        dst = repo / f.decode()
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    subprocess.run(['git', 'init', '-q'], cwd=repo, check=True,
                   env={**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'})
    for s in (repo / '.git' / 'hooks').glob('*'):
        s.unlink()
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    r = load_submodule('audit.outward').collect_outward(profile, [str(repo)])
    pt = r['regions']['project_tree']
    log('repo_self', entries=r['limits']['entries_inspected'], project_tree=pt['coverage'],
        details=[(d['code'], d['count'], d['samples'][:2]) for d in pt.get('reason_details', [])],
        other={k: [(d['code'], d['count']) for d in v.get('reason_details', [])] for k, v in r['regions'].items() if k != 'project_tree' and v['coverage'] != 'verified'})
