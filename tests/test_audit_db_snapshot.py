from .conftest import load_submodule
import sqlite3


def test_open_wal_writer_inspected_without_touching_originals(tmp_path):
    path = tmp_path / 'state.db'
    writer = sqlite3.connect(path)
    try:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('CREATE TABLE sessions (id TEXT, cwd TEXT, started_at INTEGER)')
        writer.execute("INSERT INTO sessions VALUES ('s', '/selected/sub', 123)")
        writer.commit()
        before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if not p.name.endswith('-shm')}
        before_names = {p.name for p in tmp_path.iterdir()}
        module = load_submodule('audit.outward_db')
        result = module.inspect_database(path)
        assert result['schema'] == 'hermes_sessions'
        assert result['records'] == [{'table': 'sessions', 'cwd': '/selected/sub', 'started_at': 123}]
        assert result['uncertainties'] == []
        assert result['changed_during_read'] is False
        assert before_names == {p.name for p in tmp_path.iterdir()}
        assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir() if not p.name.endswith('-shm')}
    finally:
        writer.close()


def test_schema_associations_and_disclosed_pagination(tmp_path):
    module = load_submodule('audit.outward_db')
    path = tmp_path / 'state.db'
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE projects(path TEXT, hermes_project_id TEXT); CREATE TABLE answers(project_path TEXT, answers_json TEXT);")
        db.executemany('INSERT INTO projects VALUES (?, ?)', [('/p/' + str(i), 'id') for i in range(5)])
        db.execute("INSERT INTO answers VALUES ('/p/answer', 'SECRET')")
    result = module.inspect_database(path, row_limit=2)
    assert result['schema'] == 'defuzz_state'
    assert result['limits'] == {'row_limit': 2, 'rows_inspected': 2, 'truncated': True,
                                'page_size': 1000, 'pages_inspected': 1}
    assert len(result['records']) == 2
    assert result['uncertainties'][0]['reason'] == 'database_row_limit_exceeded'
    full = module.inspect_database(path, row_limit=2, unbounded=True)
    assert len(full['records']) == 6
    assert full['limits']['row_limit'] is None
    assert full['limits']['truncated'] is False
    assert 'SECRET' not in str(full)


def test_unknown_schema_scoped_uncertainty(tmp_path):
    module = load_submodule('audit.outward_db')
    path = tmp_path / 'unknown.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE arbitrary(secret TEXT)')
    result = module.inspect_database(path)
    assert result['schema'] == 'unknown'
    assert result['uncertainties'] == [{'reason': 'unsupported_database_schema', 'regions': ['session_history', 'cross_project_isolation']}]
    assert result['limits']['row_limit'] == 10000


def test_sparse_900mb_database_read_in_place_without_copy_or_byte_limit_blowup(tmp_path, monkeypatch):
    module = load_submodule('audit.outward_db')
    outward = load_submodule('audit.outward')
    readonly = load_submodule('audit.readonly_db')
    assert not hasattr(module, 'private_snapshot')
    profile = tmp_path / '.hermes'
    profile.mkdir()
    path = profile / 'state.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE sessions(cwd TEXT, started_at INTEGER)')
        db.execute("INSERT INTO sessions VALUES ('/selected', 123)")
    with path.open('r+b') as stream:
        stream.truncate(900 * 1024 * 1024)
    connect = readonly.sqlite3.connect
    opened = []
    def checked_connect(target, **kwargs):
        assert path.as_uri() in str(target)
        opened.append(target)
        return connect(target, **kwargs)
    monkeypatch.setattr(readonly.sqlite3, 'connect', checked_connect)
    accounted = []
    result = module.inspect_database(path, scratch_dir=tmp_path, account=accounted.append)
    assert result['records'] == [{'table': 'sessions', 'cwd': '/selected', 'started_at': 123}]
    assert result['changed_during_read'] is False
    assert opened
    assert 0 < sum(accounted) < 4096
    assert sorted(p.name for p in profile.iterdir()) == ['state.db']
    out = outward.collect_outward(profile, ['/selected'], max_bytes=65536)
    assert out['regions']['session_history']['coverage'] == 'verified'
    assert out['session_history']['selected_project_records'] == 1


def test_mid_read_change_keeps_records_and_discloses_changed_during_read(tmp_path, monkeypatch):
    module = load_submodule('audit.outward_db')
    redaction = load_submodule('audit.redaction')
    path = tmp_path / 'state.db'
    writer = sqlite3.connect(path)
    try:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('CREATE TABLE sessions(cwd TEXT)')
        writer.execute("INSERT INTO sessions VALUES ('/initial')")
        writer.commit()
        original = redaction.observe_value
        changed = False
        def mutate(val):
            nonlocal changed
            if not changed and isinstance(val, dict) and val.get('cwd') == '/initial':
                writer.execute("INSERT INTO sessions VALUES ('/late')")
                writer.commit()
                changed = True
            return original(val)
        monkeypatch.setattr(redaction, 'observe_value', mutate)
        result = module.inspect_database(path, scratch_dir=tmp_path)
        assert result['changed_during_read'] is True
        assert result['records'] == [{'table': 'sessions', 'cwd': '/initial'}]
        assert result['limits']['rows_inspected'] == 1
        assert result['uncertainties'][0]['reason'] == 'database_snapshot_or_read_failed'
    finally:
        writer.close()


def test_sql_step_budget_and_busy_timeout_prevent_stall(tmp_path, monkeypatch):
    module = load_submodule('audit.outward_db')
    path = tmp_path / 'state.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE sessions(cwd TEXT)')
        db.executemany('INSERT INTO sessions VALUES (?)', [(f'/p/{i}',) for i in range(1000)])
    monkeypatch.setattr(module, 'MAX_SQL_STEPS', 1)
    stepped = module.inspect_database(path)
    assert stepped['records'] == []
    assert stepped['uncertainties'][0]['reason'] == 'database_snapshot_or_read_failed'


def test_source_links_and_hot_journal_rejected(tmp_path):
    module = load_submodule('audit.outward_db')
    path = tmp_path / 'state.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE sessions(cwd TEXT)')
    link = tmp_path / 'linked.db'
    link.symlink_to(path)
    assert module.inspect_database(link)['uncertainties']
    (tmp_path / 'state.db-journal').write_bytes(b'hot')
    assert module.inspect_database(path)['uncertainties']


def test_unknown_sessions_view_is_not_executed(tmp_path):
    module = load_submodule('audit.outward_db')
    path = tmp_path / 'view.db'
    with sqlite3.connect(path) as db:
        db.execute("CREATE VIEW sessions AS SELECT '/secret' AS cwd")
    result = module.inspect_database(path)
    assert result['schema'] == 'unknown'
    assert result['records'] == []
