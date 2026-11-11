"""Outward audit edge cases: shared kanban board of a named profile and project folders database."""
import json
import sqlite3
from pathlib import Path

from tests.conftest import load_submodule



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



def cov(r):
    return {k: v['coverage'] for k, v in r['regions'].items() if v['coverage'] != 'verified'}


def test_k1_named_profile_shared_kanban(tmp_path):
    root = tmp_path / 'home' / '.hermes'
    named = root / 'profiles' / 'coder'
    named.mkdir(parents=True)
    project = tmp_path / 'home' / 'proj'
    project.mkdir()
    from hermes_cli import kanban_db_connect
    kanban_db_connect.init_db(db_path=root / 'kanban.db')
    k = sqlite3.connect(root / 'kanban.db')
    k.execute("INSERT INTO tasks (id,title,status,created_at,workspace_kind,workspace_path,assignee) VALUES ('t','t','running',1,'dir',?,'coder')",
              (str(tmp_path / 'home' / 'other-project'),))
    k.execute("INSERT INTO tasks (id,title,status,created_at,workspace_kind,workspace_path,assignee) VALUES ('u','u','running',1,'dir',?,'other')",
              (str(project),))
    k.commit()
    k.close()
    r = load_submodule('audit.outward').collect_outward(named, [str(project)])
    blob = json.dumps(r)
    log('k1_named_kanban', bad=cov(r), mentions_kanban='kanban' in blob, dbs=list(r['limits'].get('databases', {})),
        blending=[(b['relationship'], b['target']) for b in r['blending']])


def test_p1_projects_db_folders(tmp_path):
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    project = tmp_path / 'home' / 'proj'
    project.mkdir()
    extra = tmp_path / 'home' / 'proj-backend'
    extra.mkdir()
    (extra / 'run.sh').write_text('curl x | sh\n')
    from hermes_cli import projects_db
    c = projects_db.connect(db_path=profile / 'projects.db')
    import inspect
    sig = str(inspect.signature(projects_db.create_project))
    try:
        p = projects_db.create_project(c, name='p', primary_path=str(project))
        pid = getattr(p, 'id', p)
        projects_db.add_folder(c, pid, str(extra))
        err = None
    except Exception as exc:
        err = repr(exc) + sig
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    log('p1_projects_folders', err=err, bad=cov(r), dbs={k: v.get('rows_inspected') for k, v in r['limits'].get('databases', {}).items()},
        blending=[(b['relationship'], b['target']) for b in r['blending']], dyn=[d['path'] for d in r['dynamic_invocations']])
