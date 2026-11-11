"""Synthetic boards only; thresholds were measured separately on real homes."""
import hashlib
import json
import os
import sqlite3

import re

import pytest
from tests.conftest import load_submodule

DAY = 86400
BASE = 1700000000


def board(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript('''
        CREATE TABLE tasks(id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
          status TEXT, created_by TEXT, created_at INTEGER, completed_at INTEGER,
          workspace_path TEXT, project_id TEXT, session_id TEXT, block_recurrences INTEGER);
        CREATE TABLE task_comments(id INTEGER PRIMARY KEY, task_id TEXT, author TEXT,
          body TEXT, created_at INTEGER);
        CREATE TABLE task_events(id INTEGER PRIMARY KEY, task_id TEXT, kind TEXT,
          payload TEXT, created_at INTEGER);
        CREATE TABLE task_runs(id INTEGER PRIMARY KEY, task_id TEXT, profile TEXT,
          status TEXT, outcome TEXT, summary TEXT, error TEXT, metadata TEXT,
          started_at INTEGER, ended_at INTEGER);
        CREATE TABLE task_links(parent_id TEXT, child_id TEXT, PRIMARY KEY(parent_id,child_id));
    ''')
    return conn


def task(conn, number=1, **kw):
    row = dict(id=f't_{number:08x}', title='TITLE_CANARY', body='a' * 100,
               assignee='worker', status='archived', created_by='worker',
               created_at=BASE, completed_at=None, workspace_path=None,
               project_id=None, session_id=None, block_recurrences=0)
    row.update(kw)
    conn.execute('INSERT INTO tasks (' + ','.join(row) + ') VALUES (' +
                 ','.join('?' for _ in row) + ')', tuple(row.values()))
    return row['id']


def run(conn, tid, number, start, **kw):
    row = dict(id=number, task_id=tid, profile='worker', status='blocked',
               outcome='blocked', summary='b' * 100, error=None, metadata=None,
               started_at=start, ended_at=start + 10)
    row.update(kw)
    conn.execute('INSERT INTO task_runs (' + ','.join(row) + ') VALUES (' +
                 ','.join('?' for _ in row) + ')', tuple(row.values()))


def audit(root, **kw):
    return load_submodule('audit.kanban_residue').audit_kanban_residue(profile_path=root, **kw)


def test_inventory_retry_and_residue_end_to_end(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    for n in range(1, 21):
        task(conn, n, body='/home/user/' + 'a' * 989, block_recurrences=2 if n == 1 else 0,
             workspace_path=str(tmp_path / 'plans' / 'work' / 'DEEP_CANARY') if n <= 5 else None)
    tid = 't_00000001'
    for n in range(1, 5):
        run(conn, tid, n, BASE + n * DAY, summary='b' * 5000, error='c' * 6000)
    for n in range(1, 36):
        conn.execute('INSERT INTO task_comments VALUES(?,?,?,?,?)',
                     (n, tid, 'worker', '/home/user/' + 'd' * 2989, BASE + DAY + n))
    for n in range(1, 601):
        conn.execute('INSERT INTO task_events VALUES(?,?,?,?,?)',
                     (n, tid, 'heartbeat' if n <= 400 else 'commented', 'EVENT_CANARY',
                      BASE if n < 600 else BASE + 40 * DAY))
    conn.executemany('INSERT INTO task_links VALUES(?,?)',
                     [('t_00000001', 't_00000002'), ('t_00000002', 't_00000003'),
                      ('t_00000001', 't_00000004')])
    conn.commit(); conn.close()
    logs = tmp_path / 'kanban/logs'
    logs.mkdir(parents=True)
    (logs / (tid + '.log')).write_bytes(b'x' * 1100000)
    tomb = tmp_path / 'kanban/boards/retired'
    tomb.mkdir(parents=True)
    (tomb / 'board.json').write_text('{broken JSON CANARY}')
    result = audit(tmp_path)
    sec = result['kanban_residue']
    b = sec['boards'][0]
    assert b['tasks'] == 20 and b['comments'] == 35 and b['events'] == 600
    assert b['tasks_by_status'] == {'archived': 20}
    assert b['runs_by_outcome'] == {'blocked': 4}
    assert b['archived_share'] == 1
    assert b['authorship']['tasks'] == {'agent': 20, 'user': 0, 'unclassified': 0}
    assert b['authorship']['task_agent_share'] == 1
    assert b['authorship']['comment_agent_share'] == 1
    assert b['machine_binding']['body_home_path_share'] == 1
    assert b['machine_binding']['comment_home_path_share'] == 1
    assert b['trees'] == {'links': 3, 'roots': 17, 'deepest_chain': 2,
                          'largest_tree': 4, 'widest_fanout': 2, 'cycles': 0}
    top = b['retry_context']['top_tasks'][0]
    assert top['first_worker_chars'] == 1000
    # Includes source renderer's visible per-field truncation suffix.
    cap = lambda n, c: c + len(f'… [truncated, {n-c} chars omitted]')
    expected = 1000 + 30 * cap(3000, 2048) + 3 * (cap(5000, 4096) + cap(6000, 4096))
    assert top['latest_worker_chars'] == expected
    assert top['latest_uncapped_chars'] == 1000 + 35 * 3000 + 3 * 11000
    assert b['loops']['four_runs_without_completion'] == 1
    assert b['loops']['repeated_block_threshold'] == 1
    assert b['loops']['never_run_older_than_seven_days'] == 19
    assert b['events_older_than_gc_window'] == 599
    assert b['gc_eligible_events'] == 599
    assert b['machine_binding']['workspaces_inside_home'] == 5
    assert sec['logs']['archived_bytes'] == 1100000
    assert sec['orphan_board_folders'] == 1
    assert b['text_volume']['bodies'] == 20000
    ids = {f['id'] for f in result['findings']}
    assert ids == {'kanban_residue.' + name for name in (
        'retry_context_growth', 'blocked_loops', 'agent_authored_board',
        'archived_never_collected', 'heartbeat_bloat', 'never_run_backlog',
        'workspaces_inside_home', 'orphan_board_folders', 'machine_paths_in_tasks')}
    assert 'CANARY' not in json.dumps(result)


def test_empty_board_and_small_user_board_are_normal(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    conn.commit(); conn.close()
    result = audit(tmp_path)
    assert result['findings'] == []
    assert result['kanban_residue']['status'] == 'not_present'
    conn = sqlite3.connect(tmp_path / 'kanban.db')
    tid = task(conn, created_by='default', status='done')
    run(conn, tid, 1, BASE + DAY, outcome='completed', status='done')
    conn.commit(); conn.close()
    assert audit(tmp_path)['findings'] == []


def test_archived_board_folders_and_extra_database(tmp_path):
    archived = tmp_path / 'kanban/boards/_archived'
    for name in ('old-1700000000', 'retired-1700000001'):
        folder = archived / name
        folder.mkdir(parents=True)
        (folder / 'board.json').write_bytes(b'\xffnot-json')
    conn = board(archived / 'kept-1700000002/kanban.db')
    task(conn, created_by='default', session_id='SESSION_CANARY')
    conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    assert sec['coverage'] == 'verified'
    assert sec['databases_found'] == 1
    assert sec['orphan_board_folders'] == 2
    assert sec['boards'][0]['authorship']['tasks']['user'] == 1


@pytest.mark.parametrize('metadata', [
    {'z': ['😀', True, None, {'newline': 'a\nb'}], 'a': {'x': 1}},
    {'float': 1.234e-40, 'whole_float': 1.0, 'large': 1e100},
    {}, [], None, False, 0, '', 'a', {'a': 'x' * 5000},
])
def test_metadata_renderer_length_without_fetching_prose(tmp_path, metadata):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, body=' \t😀' * 3000 + ' \n')
    raw = json.dumps(metadata, ensure_ascii=True, separators=(',', ':'))
    run(conn, tid, 1, BASE + 1, metadata=raw, summary=' \tx\n ', error='')
    run(conn, tid, 2, BASE + 20, summary='')
    conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    top = sec['boards'][0]['retry_context']['top_tasks'][0]
    cap = lambda n, c: n if n <= c else c + len(f'… [truncated, {n-c} chars omitted]')
    body = len((' \t😀' * 3000 + ' \n').strip())
    normalized = len(json.dumps(metadata, ensure_ascii=False, sort_keys=True)) if metadata else 0
    assert top['first_worker_chars'] == cap(body, 8192)
    assert top['latest_worker_chars'] == cap(body, 8192) + 1 + cap(normalized, 4096)
    assert sec['coverage'] == 'verified'


def test_unknown_authors_and_malformed_metadata_are_explicit(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, created_by='AUTHOR_CANARY')
    run(conn, tid, 1, BASE + 1, metadata='{BROKEN_CANARY')
    run(conn, tid, 2, BASE + 20)
    conn.commit(); conn.close()
    result = audit(tmp_path)
    assert result['kanban_residue']['boards'][0]['authorship']['coverage'] == 'could_not_verify'
    assert 'metadata_invalid' in result['kanban_residue']['truncated_by']
    assert 'CANARY' not in json.dumps(result)


@pytest.mark.parametrize('constant,value,reason', [
    ('MAX_ROWS', 1, 'table_rows'), ('MAX_LINKS', 1, 'links'),
    ('MAX_ENTRIES', 1, 'directory_entries'), ('MAX_SQL_STEPS', 0, 'sql_steps'),
    ('MAX_GRAPH_STEPS', 0, 'graph_steps'), ('MAX_SECONDS', 0, 'time_budget'),
    ('MAX_METADATA_CHARS', 1, 'metadata_chars'), ('MAX_JSON_NODES', 1, 'metadata_nodes'),
    ('MAX_PATH_CHARS', 1, 'path_chars'),
])
def test_every_budget_is_explicit_and_preserves_partial_counts(tmp_path, monkeypatch, constant, value, reason):
    conn = board(tmp_path / 'kanban.db')
    for n in range(1, 4):
        tid = task(conn, n, workspace_path=str(tmp_path / 'work'))
        run(conn, tid, n, BASE + n, metadata='{"x":[1,2]}')
    conn.executemany('INSERT INTO task_links VALUES(?,?)',
                     [('t_00000001','t_00000002'), ('t_00000002','t_00000003')])
    conn.executemany('INSERT INTO task_events VALUES(?,?,?,?,?)',
                     [(i, 't_00000001', 'heartbeat', None, BASE) for i in range(1, 1001)])
    conn.commit(); conn.close()
    for name in ('one', 'two', 'three'):
        folder = tmp_path / 'kanban/boards' / name
        folder.mkdir(parents=True)
        (folder / 'board.json').touch()
    mod = load_submodule('audit.kanban_residue')
    monkeypatch.setattr(mod, constant, value)
    sec = audit(tmp_path)['kanban_residue']
    assert sec['coverage'] == 'could_not_verify'
    assert reason in sec['truncated_by']
    assert sec['limits']['cuts'] >= 1
    if constant == 'MAX_GRAPH_STEPS':
        assert sec['boards'][0]['tasks'] == 3
    if constant == 'MAX_ROWS':
        assert sec['boards'][0]['tasks'] == 1


def test_retry_limits_completion_and_gc_exemptions(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, status='running', created_by='default', body='x')
    for n in range(1, 13):
        run(conn, tid, n, BASE + n * DAY, summary='s' * 10,
            outcome='completed' if n == 1 else 'blocked')
    conn.execute('INSERT INTO task_events VALUES(1,?,?,?,?)', (tid, 'heartbeat', None, BASE))
    conn.execute('INSERT INTO task_events VALUES(2,?,?,?,?)', (tid, 'heartbeat', None, BASE + 40 * DAY))
    conn.commit(); conn.close()
    logs = tmp_path / 'kanban/logs'; logs.mkdir(parents=True)
    (logs / (tid + '.log')).write_bytes(b'x' * 1100000)
    (logs / '.lock').touch()
    result = audit(tmp_path)
    sec = result['kanban_residue']; b = sec['boards'][0]
    assert b['retry_context']['top_tasks'][0]['latest_worker_chars'] == 101
    assert b['loops']['four_runs_without_completion'] == 0
    assert b['gc_eligible_events'] == 0  # GC excludes active tasks, even old events.
    assert sec['logs']['archived_bytes'] == 0
    assert 'kanban_residue.archived_never_collected' not in {f['id'] for f in result['findings']}
    assert b['loops']['open_inactive_over_fourteen_days'] == 0  # newest event is activity
    conn = sqlite3.connect(tmp_path / 'kanban.db')
    conn.execute("UPDATE tasks SET status='archived'")
    conn.execute("UPDATE task_events SET kind='decomposed'")
    conn.commit(); conn.close()
    assert audit(tmp_path)['kanban_residue']['boards'][0]['gc_eligible_events'] == 0


def test_small_growth_task_outside_top_ten_still_flags(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    for n in range(1, 12):
        tid = task(conn, n, body='x' * (1000 if n <= 10 else 1))
        run(conn, tid, n * 2, BASE, summary='s' * (1 if n <= 10 else 10))
        run(conn, tid, n * 2 + 1, BASE + 20)
    conn.commit(); conn.close()
    result = audit(tmp_path)
    assert 'kanban_residue.retry_context_growth' in {f['id'] for f in result['findings']}


def test_graph_cycle_is_guarded(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    a = task(conn, 1); b = task(conn, 2)
    conn.executemany('INSERT INTO task_links VALUES(?,?)', [(a,b),(b,a)])
    conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    assert 'graph_cycle' in sec['truncated_by']
    assert sec['boards'][0]['trees']['cycles'] == 1


@pytest.mark.parametrize('kind', ['binary', 'wrong_schema', 'view', 'wrong_type', 'nul_text'])
def test_malformed_inputs_are_unknown_not_clean(tmp_path, kind):
    path = tmp_path / 'kanban.db'
    if kind == 'binary':
        path.write_bytes(b'NOT_SQLITE_CANARY')
    else:
        conn = board(path)
        if kind == 'wrong_schema':
            conn.execute('DROP TABLE task_runs')
        elif kind == 'view':
            conn.execute('ALTER TABLE tasks RENAME TO source_tasks')
            conn.execute('CREATE VIEW tasks AS SELECT * FROM source_tasks')
        else:
            task(conn, body=b'BLOB_CANARY' if kind == 'wrong_type' else 'abc\x00CANARY')
        conn.commit(); conn.close()
    result = audit(tmp_path)
    assert result['kanban_residue']['coverage'] == 'could_not_verify'
    assert 'CANARY' not in json.dumps(result)


def listing(root):
    return sorted((str(p.relative_to(root)), p.lstat().st_mode, p.lstat().st_size,
                   hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else '')
                  for p in root.rglob('*'))


def test_private_readonly_home_and_credential_files_never_opened(tmp_path, monkeypatch):
    import builtins
    import io
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, body='BODY_CANARY', session_id='SESSION_CANARY', created_by='AUTHOR_CANARY')
    run(conn, tid, 1, BASE + 1, summary='RUN_CANARY', metadata='{"key":"META_CANARY"}')
    run(conn, tid, 2, BASE + 20)
    conn.execute('INSERT INTO task_comments VALUES(1,?,?,?,?)', (tid,'worker','COMMENT_CANARY',BASE))
    conn.commit(); conn.close()
    for name in ('.env', 'auth.json', 'secret.key', 'token.pem'):
        (tmp_path / name).write_text('CREDENTIAL_CANARY')
    (tmp_path / 'memory').mkdir()
    (tmp_path / 'memory/MEMORY.md').write_text('MEMORY_CANARY')
    before = listing(tmp_path)
    opened = []
    for module, name in ((builtins, 'open'), (io, 'open'), (os, 'open')):
        original = getattr(module, name)
        def observe(path, *args, _original=original, **kwargs):
            opened.append(str(path))
            return _original(path, *args, **kwargs)
        monkeypatch.setattr(module, name, observe)
    result = audit(tmp_path)
    assert 'CANARY' not in json.dumps(result)
    assert not any(name in p for p in opened for name in ('.env','auth.json','secret.key','token.pem','MEMORY.md'))
    monkeypatch.undo()
    assert listing(tmp_path) == before


@pytest.mark.parametrize('place', ['database', 'parent', 'workspace', 'sidecar', 'root'])
def test_symlinks_never_followed(tmp_path, place):
    safe = tmp_path / 'home'; safe.mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    conn = board(outside / 'kanban.db'); task(conn); conn.commit(); conn.close()
    if place == 'database':
        (safe / 'kanban.db').symlink_to(outside / 'kanban.db')
    elif place == 'parent':
        (safe / 'kanban').symlink_to(outside, target_is_directory=True)
    elif place == 'root':
        alias = tmp_path / 'alias'; alias.symlink_to(outside, target_is_directory=True)
        safe = alias
    else:
        conn = board(safe / 'kanban.db')
        task(conn, workspace_path=str(safe / 'work' / 'CANARY'))
        conn.commit(); conn.close()
        if place == 'workspace':
            (safe / 'work').symlink_to(outside, target_is_directory=True)
        else:
            (safe / 'kanban.db-wal').symlink_to(outside / 'kanban.db')
    result = audit(safe)
    assert result['kanban_residue']['coverage'] == 'could_not_verify'
    assert 'CANARY' not in json.dumps(result)


def test_database_path_cannot_expand_scope(tmp_path):
    root = tmp_path / 'home'; root.mkdir()
    conn = board(tmp_path / 'external.db'); conn.commit(); conn.close()
    result = audit(root, db_path=tmp_path / 'external.db')
    assert 'outside_profile' in result['kanban_residue']['truncated_by']


def test_numeric_types_dates_and_schema_keys_are_validated(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    task(conn, created_at='TIME_CANARY')
    conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    assert sec['coverage'] == 'could_not_verify'
    assert sec['boards'][0]['tasks'] == 1
    assert 'CANARY' not in json.dumps(sec)


def test_metadata_unusual_numbers_and_duplicate_keys_are_unknown(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn)
    run(conn, tid, 1, BASE, metadata='{"n":1.2,"n":2.3}')
    run(conn, tid, 2, BASE + 20)
    conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    assert 'metadata_normalization' in sec['truncated_by']


def test_reference_override_and_nonzero_block_history(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    a = task(conn, status='ready', block_recurrences=1)
    task(conn, 2, block_recurrences=4)
    conn.execute('INSERT INTO task_events VALUES(1,?,?,?,?)', (a, 'commented', None, BASE))
    conn.commit(); conn.close()
    result = audit(tmp_path, reference_time=BASE + 40 * DAY)
    b = result['kanban_residue']['boards'][0]
    assert b['loops']['open_inactive_over_fourteen_days'] == 1
    assert b['loops']['repeated_block_nonzero'] == 2
    assert b['loops']['max_block_recurrences'] == 4
    assert b['loops']['repeated_block_threshold'] == 1
    assert b['events_older_than_gc_window'] == 1


def test_clock_is_injectable_and_orphan_logs_are_inventoried(tmp_path):
    logs = tmp_path / 'kanban/logs'; logs.mkdir(parents=True)
    (logs / 't_00000001.log').write_bytes(b'LOG_CANARY')
    result = audit(tmp_path, clock=lambda: 0)
    sec = result['kanban_residue']
    assert sec['logs']['count'] == 1 and sec['logs']['bytes'] == 10
    assert result['findings'] == []
    assert sec['status'] == 'completed'


def test_all_sql_result_cells_exclude_source_prose(tmp_path, monkeypatch):
    from contextlib import contextmanager
    mod = load_submodule('audit.kanban_residue')
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, body='BODY_CANARY')
    run(conn, tid, 1, BASE, summary='SUMMARY_CANARY', metadata='{"x":"META_CANARY"}')
    run(conn, tid, 2, BASE + 20)
    conn.execute('INSERT INTO task_comments VALUES(1,?,?,?,?)', (tid,'worker','COMMENT_CANARY',BASE))
    conn.commit(); conn.close()
    original = mod._open_user_db
    @contextmanager
    def checked(path):
        with original(path) as (db, identity):
            def factory(cursor, row):
                assert all('CANARY' not in str(v) for v in row)
                return row
            db.row_factory = factory
            yield db, identity
    monkeypatch.setattr(mod, '_open_user_db', checked)
    assert audit(tmp_path)['kanban_residue']['boards'][0]['tasks'] == 1


def test_credential_database_is_never_opened(tmp_path, monkeypatch):
    import builtins
    import io
    path = tmp_path / 'secret.key'
    path.write_bytes(b'SECRET_CANARY')
    opened = []
    for module, name in ((builtins, 'open'), (io, 'open'), (os, 'open')):
        original = getattr(module, name)
        def observe(file, *args, _original=original, **kwargs):
            opened.append(str(file))
            return _original(file, *args, **kwargs)
        monkeypatch.setattr(module, name, observe)
    result = audit(tmp_path, db_path=path)
    assert str(path) not in opened
    assert 'credential_path' in result['kanban_residue']['truncated_by']


def test_archived_long_slugs_and_notification_rows_are_normal(tmp_path):
    archive_name = 'a' * 64 + '-1700000000-1'
    conn = board(tmp_path / 'kanban/boards/_archived' / archive_name / 'kanban.db')
    conn.execute('CREATE TABLE kanban_notify_subs(task_id TEXT, platform TEXT)')
    conn.execute('INSERT INTO kanban_notify_subs VALUES(?,?)', ('SESSION_CANARY','PLATFORM_CANARY'))
    conn.commit(); conn.close()
    result = audit(tmp_path)
    assert result['kanban_residue']['databases_found'] == 1
    assert result['kanban_residue']['coverage'] == 'verified'
    assert result['findings'] == []
    assert 'CANARY' not in json.dumps(result)


def test_missing_home(tmp_path):
    mod = load_submodule('audit.kanban_residue')
    result = mod.audit_kanban_residue(profile_path=tmp_path / 'missing')
    assert result['kanban_residue']['status'] == 'not_present'
    assert result['findings'] == []


# --- x9 review: corrections and adversarial checks -------------------------

def _events(conn, rows):
    conn.executemany('INSERT INTO task_events(task_id, kind, payload, created_at) VALUES(?,?,?,?)', rows)


def test_one_bad_board_does_not_stop_the_other_boards(tmp_path):
    conn = board(tmp_path / 'kanban.db'); task(conn, created_at=None); conn.commit(); conn.close()
    conn = board(tmp_path / 'kanban/boards/good/kanban.db'); task(conn); conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    status = [(b['board'], b['status']) for b in sec['boards']]
    assert status == [('default', 'not_measured'), ('named_board', 'completed')]
    assert sec['coverage'] == 'could_not_verify' and 'invalid_values' in sec['truncated_by']


def tree_listing(root):
    out = []
    for folder, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(folder, name)
            st = os.lstat(path)
            digest = ''
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, 'rb') as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
            out.append((os.path.relpath(path, root), st.st_mode, st.st_size, digest))
    return sorted(out)


def _without_shm_bytes(listing_rows):
    # Only the existing -shm index's read marks may change (audit-wide rule).
    return [row if row[0] != 'kanban.db-shm' else row[:2] for row in listing_rows]


def _record_uris(monkeypatch):
    uris = []
    original = sqlite3.connect
    def connect(database, *args, **kwargs):
        uris.append(str(database))
        return original(database, *args, **kwargs)
    monkeypatch.setattr(sqlite3, 'connect', connect)
    return uris


def test_database_held_open_by_writer_is_read_in_place(tmp_path, monkeypatch):
    """Audit-wide rule (shared opener): -wal with frames and an existing -shm is
    read mode=ro in place; nothing is created; only -shm read marks may change."""
    conn = board(tmp_path / 'kanban.db')
    conn.execute('PRAGMA journal_mode=WAL'); task(conn); conn.commit()
    before = tree_listing(tmp_path)
    assert {'kanban.db-wal', 'kanban.db-shm'} <= {row[0] for row in before}
    assert os.path.getsize(tmp_path / 'kanban.db-wal') > 0
    uris = _record_uris(monkeypatch)
    sec = audit(tmp_path)['kanban_residue']
    monkeypatch.undo()
    after = tree_listing(tmp_path)
    assert [row[0] for row in after] == [row[0] for row in before]  # no file created
    assert _without_shm_bytes(after) == _without_shm_bytes(before)
    assert sec['coverage'] == 'verified' and sec['boards'][0]['tasks'] == 1
    assert 'database_in_use' not in sec['truncated_by']
    assert any(u.endswith('?mode=ro') for u in uris) and not any('immutable' in u for u in uris)
    conn.close()
    assert not os.path.exists(tmp_path / 'kanban.db-wal')  # closed WAL is checkpointed away
    before = tree_listing(tmp_path)
    uris = _record_uris(monkeypatch)
    sec = audit(tmp_path)['kanban_residue']
    monkeypatch.undo()
    assert tree_listing(tmp_path) == before
    assert sec['coverage'] == 'verified' and sec['boards'][0]['tasks'] == 1
    assert uris and all(u.endswith('&immutable=1') for u in uris)


def test_wal_with_frames_but_no_index_is_refused_and_creates_nothing(tmp_path):
    import shutil
    live = tmp_path / 'live'; home = tmp_path / 'home'
    conn = board(live / 'kanban.db')
    conn.execute('PRAGMA journal_mode=WAL'); task(conn); conn.commit()
    home.mkdir()
    for name in ('kanban.db', 'kanban.db-wal'):
        shutil.copyfile(live / name, home / name)
    conn.close()
    assert os.path.getsize(home / 'kanban.db-wal') > 0
    before = tree_listing(home)
    sec = audit(home)['kanban_residue']
    assert tree_listing(home) == before
    assert sec['coverage'] == 'could_not_verify' and 'wal_needs_index' in sec['truncated_by']
    assert sec['boards'][0]['status'] == 'not_measured'


def test_hot_rollback_journal_is_refused(tmp_path):
    conn = board(tmp_path / 'kanban.db'); task(conn); conn.commit(); conn.close()
    (tmp_path / 'kanban.db-journal').write_bytes(b'JOURNAL')
    before = tree_listing(tmp_path)
    sec = audit(tmp_path)['kanban_residue']
    assert tree_listing(tmp_path) == before
    assert sec['coverage'] == 'could_not_verify' and 'hot_journal' in sec['truncated_by']


def test_locked_database_is_reported_in_use(tmp_path, monkeypatch):
    mod = load_submodule('audit.kanban_residue')
    conn = board(tmp_path / 'kanban.db'); task(conn); conn.commit(); conn.close()
    def busy(*args, **kwargs):
        raise sqlite3.OperationalError('database is locked')
    monkeypatch.setattr(mod, '_schema', busy)
    sec = audit(tmp_path)['kanban_residue']
    assert sec['coverage'] == 'could_not_verify' and sec['truncated_by'] == ['database_in_use']


def test_wal_with_empty_log_and_rollback_mode_create_nothing(tmp_path):
    conn = board(tmp_path / 'kanban.db'); task(conn); conn.commit(); conn.close()
    (tmp_path / 'kanban.db-wal').write_bytes(b'')
    before = tree_listing(tmp_path)
    assert audit(tmp_path)['kanban_residue']['boards'][0]['tasks'] == 1
    assert tree_listing(tmp_path) == before


def test_credential_names_in_log_folder_are_skipped_not_cut(tmp_path):
    conn = board(tmp_path / 'kanban.db'); task(conn); conn.commit(); conn.close()
    logs = tmp_path / 'kanban/logs'; logs.mkdir(parents=True)
    for name in ('.env', '.env.bak-1', 'auth.json', 'id_ed25519', 'secrets.yaml'):
        (logs / name).write_text('CREDENTIAL_CANARY')
    (logs / 't_00000001.log').write_bytes(b'x' * 7)
    sec = audit(tmp_path)['kanban_residue']
    assert sec['coverage'] == 'verified' and sec['logs']['count'] == 1


def test_read_only_directories(tmp_path):
    conn = board(tmp_path / 'kanban.db'); task(conn); conn.commit(); conn.close()
    (tmp_path / 'kanban/logs').mkdir(parents=True)
    (tmp_path / 'kanban/logs/t_00000001.log').write_bytes(b'x')
    before = tree_listing(tmp_path)
    folders = [tmp_path / 'kanban/logs', tmp_path / 'kanban', tmp_path]
    for folder in folders:
        folder.chmod(0o555)
    try:
        sec = audit(tmp_path)['kanban_residue']
    finally:
        for folder in reversed(folders):
            folder.chmod(0o755)
    assert sec['coverage'] == 'verified' and sec['logs']['count'] == 1
    assert tree_listing(tmp_path) == before


def test_retry_reconstruction_matches_hermes_rules_and_marks_body_edits(tmp_path):
    """Hermes kanban_db_context.py: newest 10 closed runs, newest 30 comments,
    per-item caps; this reconstruction only counts comments older than the run."""
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, 1, body='  ' + 'b' * 9000 + '\n')
    for n in range(1, 13):
        run(conn, tid, n, BASE + n * DAY, summary='s' * 10, error=None)
    for n in range(1, 41):  # 40 comments before the last run, 5 after it
        conn.execute('INSERT INTO task_comments VALUES(?,?,?,?,?)', (n, tid, 'worker', 'c' * 3000, BASE + DAY + n))
    for n in range(41, 46):
        conn.execute('INSERT INTO task_comments VALUES(?,?,?,?,?)', (n, tid, 'worker', 'c' * 3000, BASE + 13 * DAY))
    other = task(conn, 2, body='x' * 50)
    for n in range(100, 113):  # 13 runs but no stored run text: it does not qualify
        run(conn, other, n, BASE + (n - 100) * 10, summary=None)
    _events(conn, [(tid, 'specified', '{"changed_fields": ["title", "body"]}', BASE + 3 * DAY),
                   (other, 'edited', '{"fields": ["title"]}', BASE + 20)])
    conn.commit(); conn.close()
    result = audit(tmp_path)
    rc = result['kanban_residue']['boards'][0]['retry_context']
    by_runs = {t['runs']: t for t in rc['top_tasks']}  # task IDs are not output
    top = by_runs[12]
    cap = lambda n, c: c + len(f'… [truncated, {n-c} chars omitted]')
    assert top['first_worker_chars'] == cap(9000, 8192)
    assert top['latest_worker_chars'] == cap(9000, 8192) + 30 * cap(3000, 2048) + 10 * 10
    assert top['first_run_body_edited_later'] is True
    assert by_runs[13]['first_run_body_edited_later'] is False
    # Example = the qualifying task with the most runs; other has 13 runs but does not qualify.
    assert rc['growth_example'] == top
    finding = [f for f in result['findings'] if f['id'].endswith('retry_context_growth')][0]
    assert 'estimate' in finding['consequence'] and 'not a recording' in finding['consequence']
    # Fixed sentence; the numbers travel in the evidence.
    assert finding['consequence'] == load_submodule('audit.kanban_residue').CONSEQUENCES['retry_context_growth']
    assert finding['evidence']['latest_worker_chars'] == top['latest_worker_chars']
    assert finding['evidence']['first_run_body_edited_later'] is True and finding['evidence']['runs'] == 12


def test_growth_example_prefers_most_runs_among_qualifying(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    big = task(conn, 1, body='x' * 100)
    run(conn, big, 1, BASE, summary='s' * 4000); run(conn, big, 2, BASE + 20)  # 2 runs, 100 -> 4100
    many = task(conn, 2, body='x' * 100)
    for n in range(10, 15):
        run(conn, many, n, BASE + n * 20, summary='s' * 100)  # 5 runs, 100 -> 500
    conn.commit(); conn.close()
    rc = audit(tmp_path)['kanban_residue']['boards'][0]['retry_context']
    assert rc['growth_example']['runs'] == 5 and rc['growth_tasks'] == 2  # the 'many' task
    assert rc['top_tasks'][0]['runs'] == 2  # 'big': ranking by size is unchanged


def test_authorship_default_profile_is_user_side_even_with_session(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    task(conn, 1, created_by='default', session_id='SESSION_CANARY')
    task(conn, 2, created_by='user')
    task(conn, 3, created_by='builder', session_id='SESSION_CANARY')
    task(conn, 4, created_by='auto-decomposer')
    task(conn, 5, created_by='worker')
    t6 = task(conn, 6, created_by='stranger')
    run(conn, t6, 1, BASE, profile='builder')
    run(conn, t6, 2, BASE + 20, profile='default')
    conn.execute('INSERT INTO task_comments VALUES(1,?,?,?,?)', (t6, 'default', 'x', BASE))
    conn.execute('INSERT INTO task_comments VALUES(2,?,?,?,?)', (t6, 'builder', 'x', BASE))
    conn.commit(); conn.close()
    auth = audit(tmp_path)['kanban_residue']['boards'][0]['authorship']
    assert auth['tasks'] == {'agent': 3, 'user': 2, 'unclassified': 1}
    assert auth['comments'] == {'agent': 1, 'user': 1, 'unclassified': 0}
    assert auth['default_profile_runs'] == 1
    assert auth['coverage'] == 'verified'  # 1/6 unclassified is under 20%


def test_archived_residue_fires_on_logs_not_on_age_and_says_so(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, 1)
    _events(conn, [(tid, 'created', None, BASE), (tid, 'archived', None, BASE + 20 * DAY)])
    conn.commit(); conn.close()
    logs = tmp_path / 'kanban/logs'; logs.mkdir(parents=True)
    (logs / (tid + '.log')).write_bytes(b'x' * 1500000)
    result = audit(tmp_path)
    b = result['kanban_residue']['boards'][0]
    assert b['events_older_than_gc_window'] == 0 and b['gc_eligible_events'] == 0
    finding = [f for f in result['findings'] if f['id'].endswith('archived_never_collected')][0]
    assert finding['consequence'] == load_submodule('audit.kanban_residue').CONSEQUENCES['archived_never_collected']
    assert finding['evidence']['archived_log_bytes'] == 1500000 and finding['evidence']['gc_eligible_events'] == 0
    (logs / (tid + '.log')).write_bytes(b'x' * 10)
    assert not any(f['id'].endswith('archived_never_collected') for f in audit(tmp_path)['findings'])


def test_board_names_and_workspace_folder_names_are_not_output(tmp_path):
    conn = board(tmp_path / 'kanban/boards/_archived/old-1700000000/kanban.db'); task(conn); conn.commit(); conn.close()
    conn = board(tmp_path / 'kanban.db')
    for n, rel in enumerate(('plans/ok-name.v2/deeper/DEEP_CANARY', 'we ird$/x', 'kanban/workspaces/t_00000003',
                             'kanban/boards/proj/workspaces/t_00000004', 'kanban/workspaces'), 1):
        (tmp_path / rel).mkdir(parents=True, exist_ok=True)
        task(conn, n, workspace_path=str(tmp_path / rel))
    conn.commit(); conn.close()
    sec = audit(tmp_path)['kanban_residue']
    # Workspace folder names never leave the module; a board folder name appears
    # only inside that board's kept absolute database path.
    assert [(b['board'], b['archived_board']) for b in sec['boards']] == [('default', False), ('named_board', True)]
    mb = sec['boards'][0]['machine_binding']
    assert 'workspace_samples' not in mb
    assert mb['workspace_folders_existing'] == 5
    assert mb['workspaces_inside_home'] == 5 and mb['workspaces_in_kanban_scratch_root'] == 2
    assert [b['path'] for b in sec['boards']] == [str(tmp_path / 'kanban.db'),
                                                   str(tmp_path / 'kanban/boards/_archived/old-1700000000/kanban.db')]
    dumped = json.dumps({k: v for k, v in sec.items() if k != 'boards'}) + json.dumps(
        [{k: v for k, v in b.items() if k != 'path'} for b in sec['boards']])
    assert not any(name in dumped for name in ('plans', 'ok-name', 'we ird', 'boards/proj', 'old-1700000000'))
    assert 'CANARY' not in json.dumps(sec)


def test_determinism_across_clocks_and_reference_echo(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn); run(conn, tid, 1, BASE); run(conn, tid, 2, BASE + 9)
    _events(conn, [(tid, 'heartbeat', None, BASE)])
    conn.commit(); conn.close()
    ticks = iter(range(0, 10**9, 3))
    first = audit(tmp_path, clock=lambda: 0.0)
    second = audit(tmp_path, clock=lambda: float(next(ticks)) / 1e6 + 9 * DAY)
    assert set(first) == set(second) and 'run_metrics' in first
    first.pop('run_metrics'); second.pop('run_metrics')
    assert first == second
    echoed = audit(tmp_path, reference_time=BASE + 40 * DAY)
    assert echoed['run_metrics']['reference_time_override'] == BASE + 40 * DAY
    assert audit(tmp_path)['run_metrics']['reference_time_override'] is None


@pytest.mark.parametrize('kind', ['nulls', 'view', 'trigger_name', 'extra_columns'])
def test_hostile_schemas(tmp_path, kind):
    conn = board(tmp_path / 'kanban.db')
    if kind == 'nulls':
        for table in ('tasks', 'task_comments', 'task_runs', 'task_events'):
            conn.execute(f'INSERT INTO {table}(id) VALUES (1)')
        conn.execute('INSERT INTO task_links VALUES(NULL, NULL)')
    elif kind == 'view':
        conn.execute('ALTER TABLE task_runs RENAME TO real_runs')
        conn.execute('CREATE VIEW task_runs AS SELECT * FROM real_runs')
    elif kind == 'trigger_name':
        conn.execute('CREATE TRIGGER task_events AFTER INSERT ON tasks BEGIN SELECT 1; END')
        task(conn)
    else:
        conn.execute('ALTER TABLE tasks ADD COLUMN extra BLOB'); task(conn, extra=b'\x00EXTRA_CANARY')
    conn.commit(); conn.close()
    result = audit(tmp_path)
    sec = result['kanban_residue']
    if kind in ('trigger_name', 'extra_columns'):
        assert sec['coverage'] == 'verified' and sec['boards'][0]['tasks'] == 1
    else:
        assert sec['coverage'] == 'could_not_verify'
    assert 'CANARY' not in json.dumps(result)


def test_hundred_megabyte_body_is_bounded(tmp_path):
    import time as _time
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, body='y' * (100 * 1024 * 1024))
    run(conn, tid, 1, BASE); run(conn, tid, 2, BASE + 20)
    conn.commit(); conn.close()
    start = _time.perf_counter()
    sec = audit(tmp_path)['kanban_residue']
    assert _time.perf_counter() - start < 15
    top = sec['boards'][0]['retry_context']['top_tasks'][0]
    assert top['first_worker_chars'] == 8192 + len(f'… [truncated, {100*1024*1024-8192} chars omitted]')
    assert sec['boards'][0]['text_volume']['bodies'] == 100 * 1024 * 1024


def test_consequences_measure_and_do_not_infer(tmp_path):
    mod = load_submodule('audit.kanban_residue')
    banned = ('suggest', 'indicat', 'often means', 'uncurated', 'scratchpad', 'intentional', 'abandon',
              'bloat', 'machine binding', 'now hands')
    for text in mod.CONSEQUENCES.values():
        assert not any(word in text.lower() for word in banned), text
    # Dynamic consequence sentences too: run the full positive board.
    conn = board(tmp_path / 'kanban.db')
    for n in range(1, 21):
        task(conn, n, body='/home/user/x', block_recurrences=2 if n == 1 else 0,
             workspace_path=str(tmp_path / 'plans' / 'w') if n <= 5 else None)
    for n in range(1, 5):
        run(conn, 't_00000001', n, BASE + n * DAY, summary='b' * 9000)
    _events(conn, [('t_00000001', 'heartbeat', None, BASE + i) for i in range(600)])
    conn.commit(); conn.close()
    (tmp_path / 'kanban/logs').mkdir(parents=True)
    (tmp_path / 'kanban/logs/t_00000001.log').write_bytes(b'x' * 1100000)
    findings = audit(tmp_path)['findings']
    assert len(findings) >= 6
    for finding in findings:
        text = finding['consequence'].lower()
        assert not any(word in text for word in banned), text
        assert finding['classification'] in ('info', 'review_suggested')


def test_healthy_board_with_default_scratch_workspaces_has_no_findings(tmp_path):
    """Hermes stores every scratch task's path under <home>/kanban/workspaces
    (kanban_db.py:569-572): that alone is normal, not residue."""
    conn = board(tmp_path / 'kanban.db')
    for n in range(1, 26):
        tid = task(conn, n, created_by='default', status='done', body='short brief',
                   workspace_path=str(tmp_path / 'kanban/workspaces' / f't_{n:08x}'))
        run(conn, tid, n, BASE + n * 60, outcome='completed', status='done', summary='done')
        conn.execute('INSERT INTO task_comments(task_id, author, body, created_at) VALUES(?,?,?,?)',
                     (tid, 'default', 'thanks', BASE + n * 60 + 30))
        _events(conn, [(tid, 'created', None, BASE + n * 60), (tid, 'completed', None, BASE + n * 60 + 20)])
    conn.commit(); conn.close()
    (tmp_path / 'kanban/logs').mkdir(parents=True)
    (tmp_path / 'kanban/logs/t_00000001.log').write_bytes(b'x' * 5000)
    result = audit(tmp_path)
    assert result['kanban_residue']['coverage'] == 'verified'
    assert result['findings'] == []
    mb = result['kanban_residue']['boards'][0]['machine_binding']
    assert mb['workspaces_inside_home'] == 25 and mb['workspaces_in_kanban_scratch_root'] == 25
    # The only home path in the output is the board database itself.
    dumped = json.dumps(result).replace(json.dumps(str(tmp_path / 'kanban.db')), '')
    assert str(tmp_path) not in dumped


def test_event_payload_never_crosses_sqlite(tmp_path, monkeypatch):
    from contextlib import contextmanager
    mod = load_submodule('audit.kanban_residue')
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn); run(conn, tid, 1, BASE); run(conn, tid, 2, BASE + 20)
    _events(conn, [(tid, 'edited', '{"fields": ["body"], "host": "PAYLOAD_CANARY 203.0.113.7"}', BASE + 1)])
    conn.commit(); conn.close()
    original = mod._open_user_db
    @contextmanager
    def checked(path):
        with original(path) as (db, identity):
            def factory(cursor, row):
                assert all('CANARY' not in str(v) and '203.0.113' not in str(v) for v in row)
                return row
            db.row_factory = factory
            yield db, identity
    monkeypatch.setattr(mod, '_open_user_db', checked)
    result = audit(tmp_path)
    assert result['kanban_residue']['boards'][0]['retry_context']['top_tasks'][0]['first_run_body_edited_later']
    assert 'CANARY' not in json.dumps(result) and '203.0.113' not in json.dumps(result)


def _positive_home(root):
    """One board that fires every board-level rule plus an orphan folder."""
    conn = board(root / 'kanban.db')
    for n in range(1, 21):
        task(conn, n, body='/home/user/' + 'a' * 989, block_recurrences=2 if n == 1 else 0,
             workspace_path=str(root / 'plans' / 'work' / 'DEEP_CANARY') if n <= 5 else None)
    tid = 't_00000001'
    for n in range(1, 5):
        run(conn, tid, n, BASE + n * DAY, summary='b' * 5000, error='c' * 6000)
    for n in range(1, 36):
        conn.execute('INSERT INTO task_comments VALUES(?,?,?,?,?)',
                     (n, tid, 'worker', '/home/user/' + 'd' * 2989, BASE + DAY + n))
    for n in range(1, 601):
        conn.execute('INSERT INTO task_events VALUES(?,?,?,?,?)',
                     (n, tid, 'heartbeat' if n <= 400 else 'commented', 'EVENT_CANARY',
                      BASE if n < 600 else BASE + 40 * DAY))
    conn.commit(); conn.close()
    logs = root / 'kanban/logs'; logs.mkdir(parents=True)
    (logs / (tid + '.log')).write_bytes(b'x' * 1100000)
    (root / 'kanban/boards/retired').mkdir(parents=True)
    (root / 'kanban/boards/retired/board.json').write_text('{}')


def test_every_consequence_is_one_fixed_sentence_and_numbers_are_evidence(tmp_path):
    mod = load_submodule('audit.kanban_residue')
    _positive_home(tmp_path)
    findings = audit(tmp_path, reference_time=BASE + 60 * DAY)['findings']
    assert {f['id'] for f in findings} == {'kanban_residue.' + r for r in mod.CONSEQUENCES if r != 'could_not_verify'}
    for f in findings:
        rule = f['id'].removeprefix('kanban_residue.')
        assert f['consequence'] == mod.CONSEQUENCES[rule]
        assert f['evidence'] and all(type(v) in (int, float, bool) for v in f['evidence'].values()), f
    by = {f['id'].removeprefix('kanban_residue.'): f['evidence'] for f in findings}
    assert by['blocked_loops']['repeated_block_limit'] == mod.BLOCK_THRESHOLD
    assert by['agent_authored_board'] == {'tasks': 20, 'agent_tasks': 20, 'user_tasks': 0, 'unclassified_tasks': 0}
    assert by['heartbeat_bloat']['heartbeat_events'] == 400 and by['heartbeat_bloat']['events'] == 600
    assert by['workspaces_inside_home']['workspaces_outside_kanban_scratch_root'] == 5
    assert by['orphan_board_folders'] == {'orphan_board_folders': 1}
    # No digits other than the fixed limits named by the constants.
    numbers = {re.sub(r'[,%]', '', n) for t in mod.CONSEQUENCES.values() for n in re.findall(r'[0-9][0-9,]*%?', t)}
    assert numbers <= {'20000', '2', '80', '20', '1000000', '30', '500', '10'}
    assert (mod.CONTEXT_CHARS, mod.BLOCK_THRESHOLD, mod.AGENT_SHARE, mod.AGENT_MIN_TASKS, mod.ARCHIVED_LOG_BYTES,
            mod.ARCHIVED_SHARE, mod.GC_DAYS, mod.HEARTBEAT_MIN_EVENTS, mod.HEARTBEAT_SHARE, mod.NEVER_RUN_SHARE,
            mod.WORKSPACE_MIN, mod.MACHINE_SHARE, mod.CONTEXT_RATIO, mod.NEVER_RUN_DAYS) == (
            20000, 2, .8, 20, 1000000, .8, 30, 500, .5, .1, 5, .5, 3, 7)
    for text in mod.CONSEQUENCES.values():
        assert not re.search(r'\byou\b|indicat|suggest|unpruned|abandon', text, re.I), text


def test_months_are_integers_and_envelope_has_exactly_the_contract_keys(tmp_path):
    conn = board(tmp_path / 'kanban.db')
    tid = task(conn, created_at=1700000000)  # 2023-11
    _events(conn, [(tid, 'commented', None, 1706745600)])  # 2024-02
    conn.commit(); conn.close()
    result = audit(tmp_path)
    assert set(result) == {'kanban_residue', 'findings', 'run_metrics', 'status', 'coverage'}
    assert result['kanban_residue']['boards'][0]['date_range'] == [202311, 202402]
    assert result['status'] == 'pass' and result['coverage'] == 'verified'
    assert set(result['run_metrics']) == {'elapsed_seconds', 'reference_time_override'}


# --- wiring: closed-vocabulary sealing (audit/wiring/kanban_residue.json) ---

from pathlib import Path as _Path

WIRING = json.loads((_Path(__file__).resolve().parents[1] / 'audit/wiring/kanban_residue.json').read_text())
_FINDING_FIELDS = ('id', 'classification', 'coverage', 'affected_identities', 'source_paths', 'evidence',
                   'consequence', 'limitations', 'proposed_cleanup_id', 'severity', 'detail', 'fix')


def _scenario_positive(root, mp):
    _positive_home(root)
    return {}


def _scenario_archived(root, mp):
    for name in ('old-1700000000', 'retired-1700000001'):
        (root / 'kanban/boards/_archived' / name).mkdir(parents=True)
        (root / 'kanban/boards/_archived' / name / 'board.json').write_text('{}')
    conn = board(root / 'kanban/boards/_archived/kept-1700000002/kanban.db')
    task(conn, created_by='default'); conn.commit(); conn.close()
    conn = board(root / 'kanban/boards/named/kanban.db')
    tid = task(conn, status='running', created_by='builder')
    run(conn, tid, 1, BASE, profile='builder', outcome=None)
    run(conn, tid, 2, BASE + 9, outcome='OUTCOME_CANARY')
    conn.execute("INSERT INTO tasks(id, status, created_at, block_recurrences) VALUES('t_0000000a','STATUS_CANARY',?,0)", (BASE,))
    conn.commit(); conn.close()
    (root / 'kanban/boards/Bad Name').mkdir(parents=True)
    return {'reference_time': BASE + 90 * DAY}


def _scenario_cuts(root, mp):
    mod = load_submodule('audit.kanban_residue')
    conn = board(root / 'kanban.db')
    for n in range(1, 4):
        tid = task(conn, n, workspace_path=str(root / 'work'))
        run(conn, tid, n, BASE + n, metadata='{"x":[1,2]}')
    conn.executemany('INSERT INTO task_links VALUES(?,?)', [('t_00000001', 't_00000002'), ('t_00000002', 't_00000099')])
    conn.commit(); conn.close()
    for name, value in (('MAX_JSON_NODES', 1), ('MAX_PATH_CHARS', 1), ('MAX_LINKS', 1)):
        mp.setattr(mod, name, value)
    return {}


def _scenario_bad_values(root, mp):
    conn = board(root / 'kanban.db')
    a = task(conn, 1, created_by='AUTHOR_CANARY'); b = task(conn, 2, created_by='AUTHOR_CANARY')
    run(conn, a, 1, BASE, metadata='{BROKEN'); run(conn, a, 2, BASE + 9, metadata='{"n":1.5,"n":2}')
    conn.executemany('INSERT INTO task_links VALUES(?,?)', [(a, b), (b, a), (a, 't_000000ff')])
    conn.execute("INSERT INTO tasks(id, created_at, block_recurrences) VALUES('ID_CANARY', ?, 0)", (BASE,))
    conn.commit(); conn.close()
    conn = board(root / 'kanban/boards/second/kanban.db'); task(conn, created_at='TIME_CANARY'); conn.commit(); conn.close()
    (root / 'kanban/boards/third').mkdir(parents=True); (root / 'kanban/boards/third/kanban.db').write_bytes(b'NOT_SQLITE')
    conn = board(root / 'kanban/boards/fourth/kanban.db'); conn.execute('DROP TABLE task_runs'); conn.commit(); conn.close()
    return {}


def _scenario_wal_journal(root, mp):
    import shutil
    live = root.parent / (root.name + '-live')
    conn = board(live / 'kanban.db'); conn.execute('PRAGMA journal_mode=WAL'); task(conn); conn.commit()
    (root / 'kanban/boards/wal').mkdir(parents=True)
    for name in ('kanban.db', 'kanban.db-wal'):
        shutil.copyfile(live / name, root / 'kanban/boards/wal' / name)
    conn.close()
    conn = board(root / 'kanban/boards/journal/kanban.db'); task(conn); conn.commit(); conn.close()
    (root / 'kanban/boards/journal/kanban.db-journal').write_bytes(b'J')
    conn = board(root / 'kanban.db'); task(conn); conn.commit(); conn.close()
    outside = root.parent / (root.name + '-outside'); outside.mkdir()
    (root / 'kanban/boards/linked').mkdir(parents=True)
    (root / 'kanban/boards/linked/kanban.db').symlink_to(live / 'kanban.db')
    return {}


def _scenario_locked(root, mp):
    mod = load_submodule('audit.kanban_residue')
    conn = board(root / 'kanban.db'); task(conn); conn.commit(); conn.close()
    def busy(*args, **kwargs):
        raise sqlite3.OperationalError('database is locked')
    mp.setattr(mod, '_schema', busy)
    return {}


def _scenario_outside_and_credential(root, mp):
    (root / 'secret.key').write_text('CREDENTIAL_CANARY')
    return {'db_path': root / 'secret.key'}


def _scenario_outside(root, mp):
    conn = board(root.parent / 'external.db'); task(conn); conn.commit(); conn.close()
    return {'db_path': root.parent / 'external.db'}


def _scenario_missing(root, mp):
    return {'profile_path': root / 'missing'}


def _scenario_empty(root, mp):
    conn = board(root / 'kanban.db'); conn.commit(); conn.close()
    return {}


def _scenario_time_budget(root, mp):
    mod = load_submodule('audit.kanban_residue')
    _positive_home(root)
    mp.setattr(mod, 'MAX_SECONDS', 0)
    return {}


def _budget_scenario(constant, value):
    def build(root, mp):
        conn = board(root / 'kanban.db')
        for n in range(1, 4):
            tid = task(conn, n)
            run(conn, tid, n, BASE + n, metadata='{"x":[1,2]}')
        conn.executemany('INSERT INTO task_links VALUES(?,?)', [('t_00000001', 't_00000002')])
        conn.commit(); conn.close()
        for name in ('one', 'two'):
            (root / 'kanban/boards' / name).mkdir(parents=True)
            (root / 'kanban/boards' / name / 'board.json').touch()
        mp.setattr(load_submodule('audit.kanban_residue'), constant, value)
        return {}
    return build


for _c, _v in (('MAX_ROWS', 1), ('MAX_SQL_STEPS', 0), ('MAX_GRAPH_STEPS', 0), ('MAX_ENTRIES', 1),
               ('MAX_METADATA_CHARS', 1)):
    globals()['_scenario_budget_' + _c.lower()] = _budget_scenario(_c, _v)


SCENARIOS = {name.removeprefix('_scenario_'): fn for name, fn in globals().items() if name.startswith('_scenario_')}


def _walk(value, keys, strings, path=()):
    if isinstance(value, dict):
        for k, v in value.items():
            keys.add((k, path))
            _walk(v, keys, strings, (*path, k))
    elif isinstance(value, list):
        for v in value:
            _walk(v, keys, strings, path)
    elif isinstance(value, str):
        strings.add((value, path))
    else:
        assert value is None or type(value) in (int, float, bool), (path, value)


def _strict_check(result):
    """Every key is a schema key; every string is vocabulary (no free strings)."""
    free = {f['key'] for f in WIRING['free_strings']}
    keys, strings = set(), set()
    _walk(result['kanban_residue'], keys, strings)
    for f in result['findings']:
        assert set(f) <= set(_FINDING_FIELDS)
        assert f['id'] in WIRING['rule_ids']
        assert f['classification'] in WIRING['classifications'][f['id']]
        assert f['consequence'] == f['detail'] == WIRING['consequences'][f['id']]
        assert f['limitations'] == '' and f['proposed_cleanup_id'] is None and f['fix'] is None
        for text in (f['classification'], f['coverage'], f['severity'], *f['affected_identities']):
            strings.add((text, ('finding',)))
        for p in f['source_paths']:
            strings.add((p['path'], ('finding', 'source_paths')))
        ev_keys, ev_strings = set(), set()
        _walk(f['evidence'], ev_keys, ev_strings)
        assert all(not p for _, p in ev_keys), 'finding evidence must be flat'
        assert {k for k, _ in ev_keys} <= set(WIRING['numeric_evidence_keys']) | set(WIRING['vocab_evidence_keys'])
        assert all(type(f['evidence'][k]) in (int, float, bool) for k in f['evidence'] if k in WIRING['numeric_evidence_keys'])
        keys |= ev_keys; strings |= ev_strings
    bad_keys = {k for k, _ in keys} - set(WIRING['schema_keys'])
    bad_strings = {(s, p) for s, p in strings if s not in WIRING['vocabulary'] and not (p and p[-1] in free)}
    assert not bad_keys and not bad_strings, (bad_keys, bad_strings)
    return {k for k, _ in keys}, {s for s, _ in strings}


_REACHED = {'keys': set(), 'strings': set()}


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_wiring_json_is_complete_for_every_reachable_branch(tmp_path, monkeypatch, name):
    root = tmp_path / 'home'; root.mkdir()
    kwargs = SCENARIOS[name](root, monkeypatch)
    result = load_submodule('audit.kanban_residue').audit_kanban_residue(**{'profile_path': root, **kwargs})
    assert set(result) == {'kanban_residue', 'findings', 'run_metrics', 'status', 'coverage'}
    assert set(result['run_metrics']) == set(WIRING['run_metrics_keys'])
    keys, strings = _strict_check(result)
    _REACHED['keys'] |= keys; _REACHED['strings'] |= strings
    assert 'CANARY' not in json.dumps(result)


def test_wiring_scenarios_reach_the_documented_vocabulary(tmp_path):
    # Self-contained: runs every scenario itself, so it holds in any shard or order.
    reached = {'keys': set(), 'strings': set()}
    for name in sorted(SCENARIOS):
        root = tmp_path / name / 'home'; root.mkdir(parents=True)
        with pytest.MonkeyPatch.context() as patch:
            kwargs = SCENARIOS[name](root, patch)
            result = load_submodule('audit.kanban_residue').audit_kanban_residue(**{'profile_path': root, **kwargs})
        keys, strings = _strict_check(result)
        reached['keys'] |= keys; reached['strings'] |= strings
    _REACHED['keys'] |= reached['keys']; _REACHED['strings'] |= reached['strings']
    unreached = set(WIRING['vocabulary']) - _REACHED['strings']
    # Only a mid-read writer race and an OS permission error are not reached here.
    assert unreached <= {'database_changed', 'unreadable'}, unreached
    assert set(WIRING['schema_keys']) - _REACHED['keys'] <= {'kanban_residue', *load_submodule('audit.kanban_residue').STATUSES,
        *load_submodule('audit.kanban_residue').OUTCOMES, 'active'}


def _sealing_sets(monkeypatch):
    """Union of the current sealing sets and the wiring JSON, patched where USED."""
    ev = load_submodule('audit.evidence')
    per = load_submodule('audit.persistence')
    const = load_submodule('audit.evidence_constants')
    consequences = set(WIRING['consequences'].values())
    vocab = ev.VOCABULARY | set(WIRING['vocabulary']) | set(WIRING['rule_ids']) | consequences
    monkeypatch.setattr(ev, 'SCHEMA_KEYS', ev.SCHEMA_KEYS | set(WIRING['schema_keys']))
    monkeypatch.setattr(ev, 'VOCABULARY', vocab)
    monkeypatch.setattr(per, 'VOCABULARY', vocab)
    monkeypatch.setattr(const, 'RULE_IDS', const.RULE_IDS | set(WIRING['rule_ids']))
    table = {**const.FINDING_CONSEQUENCES, **WIRING['consequences']}
    monkeypatch.setattr(const, 'FINDING_CONSEQUENCES', table)
    monkeypatch.setattr(per, 'FINDING_CONSEQUENCES', table)
    allowed = const.ALLOWED_FINDING_CONSEQUENCES | consequences
    monkeypatch.setattr(const, 'ALLOWED_FINDING_CONSEQUENCES', allowed)
    monkeypatch.setattr(per, 'ALLOWED_FINDING_CONSEQUENCES', allowed)
    monkeypatch.setattr(per, '_EVIDENCE_NUMERIC_KEYS', per._EVIDENCE_NUMERIC_KEYS | set(WIRING['numeric_evidence_keys']))
    monkeypatch.setattr(per, '_EVIDENCE_VOCAB_KEYS', per._EVIDENCE_VOCAB_KEYS | set(WIRING['vocab_evidence_keys']))
    return ev, per


def _seal(result, ev, per):
    contract = load_submodule('audit.contract')
    adapted = contract.adapt_component_result(result, component_id='kanban_residue', affected_identities=['identity'])
    section = adapted['kanban_residue']
    sealed_section = ev.serialize_evidence({'kanban_residue': section})['kanban_residue']
    dtos = [per.finding_dto(f) for f in adapted['findings']]
    # The report stores persisted finding DTOs (store -> finding_dto), then seals them.
    sealed_findings = ev.serialize_evidence({'findings': dtos})['findings']
    return adapted, sealed_section, sealed_findings, dtos


@pytest.mark.parametrize('name', ['positive', 'archived', 'bad_values', 'wal_journal'])
def test_sealing_keeps_every_key_value_and_sentence(tmp_path, monkeypatch, name):
    root = tmp_path / 'home'; root.mkdir()
    kwargs = SCENARIOS[name](root, monkeypatch)
    result = load_submodule('audit.kanban_residue').audit_kanban_residue(profile_path=root, **kwargs)
    ev, per = _sealing_sets(monkeypatch)
    adapted, sealed_section, sealed_findings, dtos = _seal(result, ev, per)
    assert adapted['run_metrics'] == result['run_metrics']  # passed through, outside the section
    assert adapted['coverage'] == result['coverage']
    assert sealed_section == result['kanban_residue']  # nothing dropped, hashed or replaced
    assert sealed_findings == dtos
    for finding, dto in zip(adapted['findings'], dtos):
        assert dto['id'] == finding['id'] and dto['classification'] == finding['classification']
        assert dto['coverage'] == finding['coverage']
        assert dto['consequence'] == dto['detail'] == finding['consequence'] == WIRING['consequences'][finding['id']]
        assert dto['affected_identities'] == ['kanban'] and dto['source_paths'] == finding['source_paths']
        evidence = dict(dto['evidence']); evidence.pop('source_digest')
        assert evidence == finding['evidence']
        assert dto['limitations'] == 'Source-derived text withheld by persistence policy.' and dto['fix'] is None


def test_live_sealing_sets_keep_the_section_and_findings(tmp_path):
    """The live (unpatched) sets now include the sheet: section, rule ids and sentences survive."""
    root = tmp_path / 'home'; root.mkdir()
    _scenario_archived(root, None)
    result = load_submodule('audit.kanban_residue').audit_kanban_residue(profile_path=root, reference_time=BASE + 90 * DAY)
    ev, per = load_submodule('audit.evidence'), load_submodule('audit.persistence')
    sealed = ev.serialize_evidence({'kanban_residue': result['kanban_residue']})
    assert json.dumps(sealed, sort_keys=True) == json.dumps({'kanban_residue': result['kanban_residue']}, sort_keys=True)
    dtos = [per.finding_dto(f) for f in result['findings']]
    assert dtos and all(dto['id'] == f['id'] for f, dto in zip(result['findings'], dtos))
    assert all(dto['consequence'] == f['consequence'] == WIRING['consequences'][f['id']]
               for f, dto in zip(result['findings'], dtos))


def test_section_and_sealed_report_are_digest_stable_across_clocks_and_run_keys(tmp_path, monkeypatch):
    import time as _time
    _positive_home(tmp_path)
    mod = load_submodule('audit.kanban_residue')
    first = mod.audit_kanban_residue(profile_path=tmp_path, clock=lambda: 0.0)
    real = _time.time
    monkeypatch.setattr(_time, 'time', lambda: real() + 5 * DAY)
    ticks = iter(range(10**9))
    second = mod.audit_kanban_residue(profile_path=tmp_path, clock=lambda: 9 * DAY + next(ticks) / 1e6)
    monkeypatch.setattr(_time, 'time', real)
    dump = lambda v: json.dumps(v, sort_keys=True)
    assert dump(first['kanban_residue']) == dump(second['kanban_residue'])
    assert dump(first['findings']) == dump(second['findings'])
    ev, per = _sealing_sets(monkeypatch)
    def sealed(result):
        # Separate serializers = separate per-run HMAC keys: no token may appear.
        dtos = [per.finding_dto(f) for f in result['findings']]
        for dto in dtos:
            dto['evidence'].pop('source_digest')  # keyed handle added by persistence, not section data
        return ev.EvidenceSerializer().serialize({'kanban_residue': result['kanban_residue'], 'findings': dtos})
    assert dump(sealed(first)) == dump(sealed(second))


def test_canaries_in_every_user_controlled_input_never_reach_sealed_output(tmp_path, monkeypatch):
    root = tmp_path / 'home'; root.mkdir()
    c = 'CANARYX'
    for folder in ('kanban.db', f'kanban/boards/{c.lower()}/kanban.db', f'kanban/boards/_archived/{c.lower()}-1700000000/kanban.db'):
        conn = board(root / folder)
        for n in range(1, 4):
            tid = task(conn, n, title=c, body=f'{c} /home/user/{c}', assignee=c, created_by=c if n == 1 else 'worker',
                       status=c if n == 2 else 'archived', workspace_path=str(root / c / c), project_id=c, session_id=c)
            run(conn, tid, n * 10, BASE, profile=c, status=c, outcome=c if n == 3 else 'blocked', summary=c, error=c,
                metadata=json.dumps({c: c, 'n': [1, c]}))
            run(conn, tid, n * 10 + 1, BASE + 9, summary=c)
            conn.execute('INSERT INTO task_comments(task_id, author, body, created_at) VALUES(?,?,?,?)', (tid, c, c, BASE))
            _events(conn, [(tid, c, json.dumps({'fields': ['body'], c: c}), BASE), (tid, 'heartbeat', c, BASE + 1)])
        conn.execute('INSERT INTO task_links VALUES(?,?)', ('t_00000001', c))
        conn.commit(); conn.close()
    (root / c / c).mkdir(parents=True)
    (root / f'kanban/boards/{c.lower()}-orphan').mkdir(parents=True)
    (root / f'kanban/boards/{c.lower()}-orphan/board.json').write_text(json.dumps({c: c}))
    logs = root / 'kanban/logs'; logs.mkdir(parents=True)
    (logs / 't_00000001.log').write_text(c * 100)
    (logs / f'{c}.log').write_text(c)
    result = load_submodule('audit.kanban_residue').audit_kanban_residue(profile_path=root)
    ev, per = _sealing_sets(monkeypatch)
    adapted, sealed_section, sealed_findings, dtos = _seal(result, ev, per)
    _strict_check(result)
    # Board folder names are user-chosen: they may appear ONLY inside the kept
    # absolute database paths (free_strings 'path' / 'source_paths'), nowhere else.
    kept = {b['path'] for b in sealed_section['boards']} | {p['path'] for d in dtos for p in d['source_paths']}
    assert all(p.startswith(str(root.resolve()) + '/') and os.path.lexists(p) for p in kept if p != 'kanban.db')
    blob = json.dumps([result, adapted, sealed_section, sealed_findings, dtos], default=str)
    for p in sorted(kept, key=len, reverse=True):
        blob = blob.replace(json.dumps(p)[1:-1], '')
    assert c not in blob and c.lower() not in blob and str(root) not in blob
    assert 'hmac' not in json.dumps([sealed_section, sealed_findings])


def _hmac_dicts(value, found):
    if isinstance(value, dict):
        if 'hmac' in value or any(str(k).startswith('hmac:') for k in value):
            found.append(value)
        for v in value.values():
            _hmac_dicts(v, found)
    elif isinstance(value, list):
        for v in value:
            _hmac_dicts(v, found)
    return found


@pytest.mark.parametrize('name', sorted(SCENARIOS))
def test_sealed_output_contains_no_hmac_token_and_is_identical_across_two_runs(tmp_path, monkeypatch, name):
    """Two runs on the same home, each through
    adapt_component_result + serialize_evidence (own per-run key), are identical."""
    root = tmp_path / 'home'; root.mkdir()
    kwargs = SCENARIOS[name](root, monkeypatch)
    kwargs = {'profile_path': root, **kwargs}
    mod = load_submodule('audit.kanban_residue')
    ev, per = _sealing_sets(monkeypatch)
    outputs = []
    for _ in range(2):
        adapted, sealed_section, sealed_findings, dtos = _seal(mod.audit_kanban_residue(**kwargs), ev, per)
        for d in sealed_findings:
            d['evidence'].pop('source_digest')  # keyed handle added by persistence for every section
        outputs.append(json.dumps({'section': sealed_section, 'findings': sealed_findings}, sort_keys=True))
        assert _hmac_dicts(sealed_section, []) == [] and _hmac_dicts(sealed_findings, []) == []
    assert outputs[0] == outputs[1]


def test_board_database_paths_are_kept_unchanged_by_the_serializer(tmp_path, monkeypatch):
    root = tmp_path / 'home'; root.mkdir()
    _scenario_archived(root, monkeypatch)
    result = audit(root, reference_time=BASE + 90 * DAY)
    ev, per = _sealing_sets(monkeypatch)
    _, sealed_section, sealed_findings, dtos = _seal(result, ev, per)
    paths = [b['path'] for b in sealed_section['boards']]
    assert paths == [b['path'] for b in result['kanban_residue']['boards']]
    assert paths == [str(root / 'kanban/boards/named/kanban.db'), str(root / 'kanban/boards/_archived/kept-1700000002/kanban.db')]
    assert [p['path'] for d in dtos for p in d['source_paths']] == [p['path'] for f in result['findings'] for p in f['source_paths']]
    # A path that no longer exists at sealing time is NOT kept: it becomes a token.
    gone = ev.serialize_evidence({'path': str(root / 'kanban/boards/absent/kanban.db')})['path']
    assert isinstance(gone, dict) and 'hmac' in gone


def test_doc_page_matches_code_and_wiring_json():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words
    mod = load_submodule('audit.kanban_residue')
    doc = (_Path(__file__).resolve().parents[1] / 'docs/audit-sections/kanban_residue.md').read_text()
    assert WIRING['consequences'] == {'kanban_residue.' + r: s for r, s in mod.CONSEQUENCES.items()}
    rows = _doc_rule_rows(doc, {r.split('.', 1)[1] for r in WIRING['rule_ids']}, required_column='trigger')
    for rid, sentence in WIRING['consequences'].items():
        _doc_contains(doc, sentence)
        row = rows[rid.split('.', 1)[1]]
        assert _doc_words(row['classification']).split()[0] == WIRING['classifications'][rid][0], rid
    for key in WIRING['schema_keys'] + WIRING['numeric_evidence_keys'] + WIRING['run_metrics_keys']:
        _doc_contains(doc, key)
    # The complete source vocabulary covers truncation reasons without maintaining
    # a second, handwritten subtraction list or a one-line truncated_by bullet.
    for word in WIRING['vocabulary']:
        if word != 'warn':
            _doc_contains(doc, word)
