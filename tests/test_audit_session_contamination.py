"""Synthetic SQLite only; assert no source bodies/IDs persist."""
import json
import sqlite3
import pytest
from datetime import datetime, timezone
from tests.conftest import load_submodule


def database(home, project, *, dedup=False):
    home.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(home / 'state.db')
    conn.executescript('''
        CREATE TABLE sessions(id TEXT PRIMARY KEY, cwd TEXT, git_repo_root TEXT,
          system_prompt TEXT, started_at REAL, message_count INTEGER, source TEXT,
          parent_session_id TEXT, system_prompt_hash TEXT);
        CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT,
          content TEXT, timestamp REAL, api_content TEXT);
        CREATE TABLE system_prompts(hash TEXT PRIMARY KEY, prompt TEXT);
        CREATE INDEX idx_sessions_started ON sessions(started_at DESC);
        CREATE INDEX idx_messages_session ON messages(session_id, timestamp);
    ''')
    render = load_submodule('audit.vendor.profile_context')._render_memory_prompt_block
    block = render({'enabled': True, 'entries': ['Python pip CANARY_MEMORY'], 'char_limit': 2200}, 'memory')['rendered_block']
    for i in range(6):
        prompt = 'Java outside memory must not count.\n' + block + '\n\n' + ('z' * (6000 if i >= 3 else 100))
        sid = 'PRIVATE_SESSION_' + str(i)
        stamp = datetime(2025, 2 if i >= 3 else 1, 1, tzinfo=timezone.utc).timestamp()
        conn.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)',
                     (sid, str(project), str(project), None if dedup else prompt, stamp, 1, 'cli', None, sid if dedup else None))
        if dedup:
            conn.execute('INSERT INTO system_prompts VALUES(?,?)', (sid, prompt))
        conn.execute('INSERT INTO messages VALUES(?,?,?,?,?,?)',
                     (i, sid, 'user', 'Java C++ unrelated user request CANARY_USER', stamp,
                      'Java user text\n<memory-context>Python Django CANARY_RECALL</memory-context>'))
    conn.commit()
    conn.close()
    return block


def test_opt_in_legacy_and_dedup_contamination(tmp_path):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}')
    for dedup in (False, True):
        home = tmp_path / str(dedup)
        block = database(home, project, dedup=dedup)
        before = (home / 'state.db').read_bytes()
        result = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])
        section = result['session_contamination']
        assert section['overall']['sessions_examined'] == 6
        assert section['overall']['sessions_with_foreign_memory'] == 6
        assert section['overall']['foreign_families'] == {'python': 24}
        assert section['overall']['median_memory_block_chars'] == len(block)
        assert section['overall']['memory_context_chars'] == 6 * len('<memory-context>Python Django CANARY_RECALL</memory-context>')
        assert section['overall']['contamination_rate'] == 1
        assert len(section['system_prompt_by_month']) == 2
        ids = {f['id'] for f in result['findings']}
        assert {'session_contamination.foreign_memory_in_project', 'session_contamination.system_prompt_growth',
                'session_contamination.external_memory_injection_observed'} <= ids
        assert (home / 'state.db').read_bytes() == before
        assert sorted(p.name for p in home.iterdir()) == ['state.db']
        assert 'CANARY' not in json.dumps(result)
        assert 'PRIVATE_SESSION' not in json.dumps(result)
        assert result == mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])


@pytest.mark.parametrize('readonly', [False, True])
def test_closed_wal_creates_nothing(tmp_path, readonly):
    import os
    import hashlib
    if readonly and os.geteuid() == 0:
        pytest.skip('root bypasses directory permissions')
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    home = tmp_path / 'home'
    database(home, project)
    conn = sqlite3.connect(home / 'state.db')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.close()
    before = sorted(p.name for p in home.iterdir())
    digest = hashlib.sha256((home / 'state.db').read_bytes()).hexdigest()
    if readonly:
        home.chmod(0o555)
    try:
        section = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
        after = sorted(p.name for p in home.iterdir())
        after_digest = hashlib.sha256((home / 'state.db').read_bytes()).hexdigest()
        print('CLOSED_WAL', before, after, digest, after_digest)
        assert after == before == ['state.db']
        assert digest == after_digest
        assert section['overall']['sessions_examined'] == 6
        assert section['changed_during_read'] is False
        assert section['read_mode'] == 'immutable'
    finally:
        home.chmod(0o755)


def test_stale_empty_wal_creates_nothing(tmp_path):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    database(tmp_path / 'home', project)
    conn = sqlite3.connect(tmp_path / 'home/state.db')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.close()
    wal = tmp_path / 'home/state.db-wal'
    wal.touch()
    listing = sorted(p.name for p in (tmp_path / 'home').iterdir())
    before = (tmp_path / 'home/state.db').read_bytes()
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['read_mode'] == 'immutable'
    assert section['overall']['sessions_examined'] == 6
    assert section['changed_during_read'] is False
    assert wal.stat().st_size == 0
    assert (tmp_path / 'home/state.db').read_bytes() == before
    assert sorted(p.name for p in (tmp_path / 'home').iterdir()) == listing


def test_wal_with_frames_but_no_index_is_not_opened(tmp_path):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    database(tmp_path / 'src', project)
    writer = sqlite3.connect(tmp_path / 'src/state.db')
    writer.execute('PRAGMA journal_mode=WAL')
    writer.execute("INSERT INTO messages(session_id, role, content, timestamp) VALUES('PRIVATE_SESSION_0','user','x',1.0)")
    writer.commit()
    home = tmp_path / 'home'
    home.mkdir()
    for name in ('state.db', 'state.db-wal'):
        (home / name).write_bytes((tmp_path / 'src' / name).read_bytes())
    writer.close()
    assert (home / 'state.db-wal').stat().st_size > 0
    listing = sorted(p.name for p in home.iterdir())
    hashes = {p.name: p.read_bytes() for p in home.iterdir()}
    section = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert section['status'] == 'not_measured'
    assert section['reason'] == 'wal_needs_index'
    assert sorted(p.name for p in home.iterdir()) == listing
    assert {p.name: p.read_bytes() for p in home.iterdir()} == hashes


def test_writer_starts_after_immutable_open(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    database(tmp_path / 'home', project)
    writer = sqlite3.connect(tmp_path / 'home/state.db')
    writer.execute('PRAGMA journal_mode=WAL')
    writer.close()
    original = mod._project
    writers = []
    def start(root):
        conn = sqlite3.connect(tmp_path / 'home/state.db')
        writers.append(conn)
        conn.execute("UPDATE sessions SET source='new'")
        conn.commit()
        return original(root)
    monkeypatch.setattr(mod, '_project', start)
    try:
        section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
        assert section['changed_during_read'] is True
        assert section['read_mode'] == 'immutable'
    finally:
        for conn in writers:
            conn.close()


def test_unregistered_session_directory_never_touched(tmp_path, monkeypatch):
    import os
    import builtins
    mod = load_submodule('audit.session_contamination')
    canary = tmp_path / 'PRIVATE_UNREGISTERED_CANARY'
    canary.mkdir()
    (canary / 'main.py').touch()
    home = tmp_path / 'home'
    database(home, canary)
    touched = []
    for owner, name in ((os, 'scandir'), (os, 'walk'), (builtins, 'open')):
        original = getattr(owner, name)
        def track(path, *args, _original=original, **kwargs):
            touched.append(str(path))
            return _original(path, *args, **kwargs)
        monkeypatch.setattr(owner, name, track)
    result = mod.audit_session_contamination(profile_path=home, sessions=True)
    assert not any(str(canary) in p for p in touched)
    assert str(canary) not in json.dumps(result)
    assert result['session_contamination']['sessions_outside_registered_projects'] == 6
    surface = load_submodule('audit_surface')
    monkeypatch.setenv('HERMES_HOME', str(home))
    (home / 'config.yaml').write_text('{}')
    db = tmp_path / 'reports/audit.db'
    report = surface.execute_audit({'action': 'run'}, db_path=db, wait=True, sessions=True)
    assert str(canary) not in json.dumps(report['report']['session_contamination'])
    with sqlite3.connect(db) as conn:
        assert 'PRIVATE_UNREGISTERED_CANARY' not in '\n'.join(conn.iterdump())


@pytest.mark.parametrize('cap', [10000, 1])
def test_ordinary_project_skips_keep_classification(tmp_path, monkeypatch, cap):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'a.js').touch()
    (project / 'z.js').touch()
    (project / '.env').write_text('SECRET')
    (project / '.venv').symlink_to(tmp_path / 'absent', target_is_directory=True)
    (project / 'node_modules').mkdir()
    (project / 'node_modules/foreign.py').touch()
    database(tmp_path / 'home', project)
    monkeypatch.setattr(mod, 'MAX_PROJECT_ENTRIES', cap)
    result = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])
    section = result['session_contamination']
    assert section['overall']['sessions_classified'] == 6
    assert section['projects'][0]['project_families'] == ['javascript']
    assert section['projects'][0]['project_coverage'] == ('partial' if cap == 1 else 'verified')
    assert section['limits']['cuts'] == (1 if cap == 1 else 0)
    assert any(f['id'] == 'session_contamination.foreign_memory_in_project' for f in result['findings'])


@pytest.mark.parametrize('stamp', [None, 'not-a-time'])
def test_malformed_message_timestamp_is_a_row_cut(tmp_path, stamp):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').touch()
    database(tmp_path / 'home', project)
    with sqlite3.connect(tmp_path / 'home/state.db') as conn:
        conn.execute('UPDATE messages SET timestamp=? WHERE id=0', (stamp,))
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['status'] == 'completed'
    assert section['limits']['messages_examined'] == 6
    assert section['limits']['cuts'] == 1
    assert section['overall']['memory_context_blocks'] == 6


def test_raw_bracket_turn_and_unicode_recall_offsets():
    mod = load_submodule('audit.session_contamination')
    raw = '[OUT-OF-BAND USER MESSAGE] İ <MeMoRy-CoNtExT>Python</mEmOrY-CoNtExT>'
    assert mod._text_parts(raw) == raw
    assert mod.recalled_blocks(raw) == ['Python']
    assert mod.recalled_blocks('İ<memory-context>a</memory-context>İ<memory-context>b</memory-context>') == ['a', 'b']
    assert mod._text_parts('[{"type":"text","text":"hello"}]') == 'hello'


TECH_CASES = [
    ('node.js nodejs javascript typescript jsx tsx', {'javascript': 6}),
    ('C++17 C++20 C#12 main.cpp util.c header.hpp', {'cpp': 5, 'csharp': 1}),
    ('java code ruby package unity SDK rust crate go project swift lang',
     {'java': 1, 'ruby': 1, 'unity': 1, 'rust': 1, 'go': 1, 'swift': 1}),
    ('java 21 ruby 3.3 unity 6 rust 1.80 go 1.23 swift 6',
     {'java': 1, 'ruby': 1, 'unity': 1, 'rust': 1, 'go': 1, 'swift': 1}),
    ('go to the store', {}), ('rust on the bike', {}), ('a java coffee', {}),
    ('tree node', {}), ('react to this', {}), ('Washington D.C.', {}),
    ('swift reply', {}), ('ruby ring', {}), ('unity of purpose', {}),
    ('blueprint blueprints .c .h x.c x.h React', {}),
]


@pytest.mark.parametrize('text,expected', TECH_CASES)
def test_technology_table(text, expected):
    assert load_submodule('audit.session_contamination').technology_counts(text) == expected


def test_overfull_memory_percentage_is_parsed():
    mod = load_submodule('audit.session_contamination')
    render = load_submodule('audit.vendor.profile_context')._render_memory_prompt_block
    block = render({'enabled': True, 'entries': ['Python'], 'char_limit': 1}, 'memory')['rendered_block']
    import re
    block = re.sub(r'\[\d+%', '[12345%', block)
    assert len(mod.memory_blocks(block)[0]) == 1


@pytest.mark.parametrize('stamp', [None, 'odd', 0, -1])
def test_null_prompt_and_bad_session_time_keep_messages(tmp_path, stamp):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').touch()
    database(tmp_path / 'home', project)
    with sqlite3.connect(tmp_path / 'home/state.db') as conn:
        conn.execute('UPDATE sessions SET system_prompt=NULL, started_at=?', (stamp,))
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['overall']['sessions_without_prompt'] == 6
    assert section['overall']['sessions_classified'] == 6
    assert section['overall']['memory_context_blocks'] == 6
    assert section['overall']['foreign_families'] == {'python': 12}
    assert section['limits']['cuts'] == 6
    assert section['system_prompt_by_month'] == []


@pytest.mark.parametrize('cwd', [None, 'relative'])
def test_null_or_relative_cwd_is_outside(tmp_path, cwd):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    database(tmp_path / 'home', project)
    with sqlite3.connect(tmp_path / 'home/state.db') as conn:
        conn.execute('UPDATE sessions SET cwd=?', (cwd,))
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['sessions_outside_registered_projects'] == 6
    assert section['projects'] == []


@pytest.mark.parametrize('variant', ['without_rowid', 'generated', 'view', 'virtual'])
def test_unsupported_session_table_variants(tmp_path, variant):
    mod = load_submodule('audit.session_contamination')
    database(tmp_path, tmp_path / 'project')
    with sqlite3.connect(tmp_path / 'state.db') as conn:
        if variant == 'without_rowid':
            sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='sessions'").fetchone()[0]
            conn.execute('DROP TABLE sessions')
            conn.execute(sql + ' WITHOUT ROWID')
        elif variant == 'generated':
            conn.execute('ALTER TABLE messages ADD COLUMN computed TEXT GENERATED ALWAYS AS (content)')
        elif variant == 'view':
            conn.execute('ALTER TABLE messages RENAME TO actual_messages')
            conn.execute('CREATE VIEW messages AS SELECT * FROM actual_messages')
        else:
            conn.execute('DROP TABLE messages')
            conn.execute('CREATE VIRTUAL TABLE messages USING fts5(session_id,role,content,timestamp)')
    section = mod.audit_session_contamination(profile_path=tmp_path, sessions=True)['session_contamination']
    assert section['reason'] == 'schema_unsupported'


def test_sql_interrupt_preserves_partial_metrics(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    database(tmp_path / 'home', project)
    with sqlite3.connect(tmp_path / 'home/state.db') as conn:
        conn.executemany('INSERT INTO messages(id,session_id,content) VALUES(?,?,?)',
                         ((i, 'PRIVATE_SESSION_0', 'ok') for i in range(10, 210)))
    original = mod.memory_blocks
    calls = []
    def exhaust(prompt):
        calls.append(1)
        if len(calls) == 2:
            monkeypatch.setattr(mod, 'MAX_SQL_STEPS', 0)
        return original(prompt)
    monkeypatch.setattr(mod, 'memory_blocks', exhaust)
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['status'] == 'completed'
    assert section['truncated_by'] == 'sql_steps'
    assert section['overall']['sessions_examined'] >= 1
    assert section['coverage'] == 'could_not_verify'


@pytest.mark.parametrize('live', [False, True])
def test_sqlite_hardened_before_schema_read(tmp_path, monkeypatch, live):
    mod = load_submodule('audit.session_contamination')
    database(tmp_path, tmp_path / 'project')
    writer = sqlite3.connect(tmp_path / 'state.db')
    if live:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("UPDATE sessions SET source='wal'")
        writer.commit()
    original = sqlite3.connect
    statements = []
    def tracked(*args, **kwargs):
        conn = original(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn
    monkeypatch.setattr(sqlite3, 'connect', tracked)
    try:
        mod.audit_session_contamination(profile_path=tmp_path, sessions=True)
        normalized = [s.replace(' ', '').lower() for s in statements]
        first_schema = next(i for i, s in enumerate(normalized) if 'sqlite_master' in s)
        assert normalized.index('pragmatrusted_schema=off') < first_schema
        assert normalized.index('pragmaquery_only=on') < first_schema
    finally:
        writer.close()


def test_large_text_prefix_stays_bounded_in_python(tmp_path, monkeypatch):
    import tracemalloc
    import gc
    from contextlib import contextmanager
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    database(tmp_path / 'home', project)
    conn = sqlite3.connect(tmp_path / 'home/state.db')
    conn.execute("UPDATE sessions SET system_prompt=? WHERE id='PRIVATE_SESSION_0'", ('é' * (25 * 1024 * 1024),))
    conn.execute('UPDATE messages SET content=?,api_content=NULL WHERE id=0', ('é' * (25 * 1024 * 1024),))
    conn.commit()
    conn.close()
    gc.collect()
    original = mod.open_readonly_sqlite
    statements = []
    @contextmanager
    def traced(*args, **kwargs):
        with original(*args, **kwargs) as pair:
            pair[0].set_trace_callback(statements.append)
            yield pair
    monkeypatch.setattr(mod, 'open_readonly_sqlite', traced)
    monkeypatch.setattr(mod, 'MAX_TEXT_BYTES', 4096)
    tracemalloc.start()
    try:
        section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    print('LARGE_TEXT_PYTHON_PEAK', peak)
    assert section['overall']['max_system_prompt_chars'] == 25 * 1024 * 1024
    assert peak < 2 * 1024 * 1024
    assert section['limits']['bytes_read'] < 100000
    text_queries = [s for s in statements if s.startswith('SELECT') and ('system_prompt' in s or 'content' in s)]
    assert text_queries
    assert all('CAST(s.system_prompt AS BLOB)' not in s and 'CAST(COALESCE(' not in s for s in text_queries)
    assert any('substr(CAST(substr(' in s for s in text_queries)


def test_session_finding_numeric_summary_and_unverified_consequence(tmp_path):
    mod = load_submodule('audit.session_contamination')
    persistence = load_submodule('audit.persistence')
    constants = load_submodule('audit.evidence_constants')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').touch()
    database(tmp_path / 'home', project)
    result = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])
    finding = next(f for f in result['findings'] if f['id'] == 'session_contamination.foreign_memory_in_project')
    saved = persistence.finding_dto(finding)
    numbers = {k: v for k, v in finding['evidence'].items() if type(v) in (int, float)}
    assert {k: saved['evidence'].get(k) for k in numbers} == numbers
    assert 'session_contamination.unverified' in constants.FINDING_CONSEQUENCES
    consequence = constants.FINDING_CONSEQUENCES['session_contamination.unverified']
    assert consequence != constants.DEFAULT_FINDING_CONSEQUENCE
    assert consequence in constants.ALLOWED_FINDING_CONSEQUENCES


def test_off_never_opens_database(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    def forbidden(*args, **kwargs):
        raise AssertionError('database opened without opt in')
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    assert mod.audit_session_contamination(profile_path=tmp_path)['session_contamination']['status'] == 'not_run'


def test_vocab_and_unavailable_inputs(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    assert not mod.technology_counts('go c rust rusty cargoes javascriptish Docker Kubernetes')
    assert mod.technology_counts('go build golang c++ cpp dotnet cargo Rust language') == {
        'go': 2, 'cpp': 2, 'csharp': 1, 'rust': 2}
    missing = mod.audit_session_contamination(profile_path=tmp_path, sessions=True)
    assert missing['findings'][0]['id'] == 'session_contamination.database_unreadable'
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('# native Python')
    home = tmp_path / 'home'
    database(home, project)
    native = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert native['overall']['sessions_with_foreign_memory'] == 0
    assert native['overall']['native_term_occurrences'] == 24
    filtered = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[tmp_path / 'other'])
    assert filtered['session_contamination']['overall']['sessions_examined'] == 0
    (project / 'main.py').unlink()
    project.rmdir()
    missing = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert missing['projects'][0]['coverage'] == 'project_missing'
    assert missing['overall']['contamination_rate'] is None
    monkeypatch.setattr(mod, 'MAX_SESSIONS', 2)
    cut = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert cut['limits']['cuts'] > 0 and cut['overall']['sessions_examined'] == 2
    with sqlite3.connect(home / 'state.db') as conn:
        conn.execute('DROP TABLE messages')
    bad = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])
    assert bad['findings'][0]['id'] == 'session_contamination.schema_unsupported'


def test_live_wal_measured_without_database_or_wal_mutation(tmp_path):
    import hashlib
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}')
    home = tmp_path / 'home'
    database(home, project)
    writer = sqlite3.connect(home / 'state.db')
    try:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("UPDATE sessions SET source='test'")
        writer.commit()
        writer.execute("INSERT INTO sessions(id, cwd) VALUES('UNCOMMITTED', ?)", (str(project),))
        assert (home / 'state.db-wal').exists() and (home / 'state.db-shm').exists()
        paths = [home / name for name in ('state.db', 'state.db-wal')]
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
        result = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])
        section = result['session_contamination']
        assert section['status'] == 'completed'
        assert section['overall']['sessions_examined'] == 6
        assert section['overall']['foreign_families'] == {'python': 24}
        assert section['limits']['messages_examined'] == 6
        assert section['wal_mode'] is True
        assert section['read_mode'] == 'mode=ro'
        assert section['changed_during_read'] is False
        assert section['immutable'] is False and section['database_copied'] is False
        assert [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths] == before
    finally:
        writer.close()


@pytest.mark.parametrize('freeze_identity', [False, True])
def test_concurrent_wal_commit_discloses_counts(tmp_path, monkeypatch, freeze_identity):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}')
    home = tmp_path / 'home'
    database(home, project)
    writer = sqlite3.connect(home / 'state.db')
    try:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("UPDATE sessions SET source='committed'")
        writer.commit()
        if freeze_identity:
            readonly = load_submodule('audit.readonly_db')
            identity = readonly.stat_db_identity(home / 'state.db')
            monkeypatch.setattr(readonly, 'stat_db_identity', lambda _: identity)
            monkeypatch.setattr(mod, 'stat_db_identity', lambda _: identity)
        original = mod._project
        def commit_during_read(root):
            writer.execute("INSERT INTO sessions SELECT 'NEW_COMMITTED', cwd, git_repo_root, system_prompt, started_at, message_count, source, parent_session_id, system_prompt_hash FROM sessions LIMIT 1")
            writer.commit()
            return original(root)
        monkeypatch.setattr(mod, '_project', commit_during_read)
        result = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])
        section = result['session_contamination']
        assert section['status'] == 'completed'
        assert section['overall']['sessions_examined'] == 6
        assert section['changed_during_read'] is True
        finding = next(f for f in result['findings'] if f['id'] == 'session_contamination.database_changed_during_read')
        assert finding['classification'] == 'info'
        assert 'counts may be off' in finding['consequence'].lower()
    finally:
        writer.close()


def test_shm_bookkeeping_is_not_a_database_change(tmp_path, monkeypatch):
    import os
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('')
    database(tmp_path / 'home', project)
    writer = sqlite3.connect(tmp_path / 'home/state.db')
    try:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("UPDATE sessions SET source='wal'")
        writer.commit()
        original = mod._project
        def touch_shm(root):
            shm = tmp_path / 'home/state.db-shm'
            info = shm.stat()
            os.utime(shm, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
            return original(root)
        monkeypatch.setattr(mod, '_project', touch_shm)
        section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
        assert section['changed_during_read'] is False
        assert section['coverage'] == 'verified'
        assert section['overall']['sessions_examined'] == 6
    finally:
        writer.close()


@pytest.mark.parametrize('change', [
    'DROP TABLE system_prompts; CREATE TABLE system_prompts(hash TEXT, prompt TEXT)',
    'ALTER TABLE sessions ADD COLUMN rowid TEXT',
])
def test_lookalike_unindexed_schemas_are_not_scanned(tmp_path, change):
    mod = load_submodule('audit.session_contamination')
    database(tmp_path, tmp_path / 'missing')
    with sqlite3.connect(tmp_path / 'state.db') as conn:
        conn.executescript(change)
    section = mod.audit_session_contamination(profile_path=tmp_path, sessions=True)['session_contamination']
    assert section['status'] == 'not_measured'
    assert section['reason'] == 'schema_unsupported'


def test_read_errors_have_fixed_reason_without_exception_text(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    database(tmp_path, tmp_path / 'missing')
    def fail(*args):
        raise sqlite3.OperationalError('CANARY_PRIVATE_SQL_ERROR')
    monkeypatch.setattr(mod, '_columns', fail)
    result = mod.audit_session_contamination(profile_path=tmp_path, sessions=True)
    assert result['session_contamination']['reason'] == 'read_error'
    assert 'CANARY' not in json.dumps(result)


def test_time_budget_keeps_partial_results(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('')
    database(tmp_path / 'home', project)
    import time
    clock = [0.0]
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    original = mod.memory_blocks
    def exhaust_after_prompt(text):
        result = original(text)
        clock[0] = 21.0
        return result
    monkeypatch.setattr(mod, 'memory_blocks', exhaust_after_prompt)
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['status'] == 'completed'
    assert section['truncated_by'] == 'time_budget'
    assert section['overall']['sessions_examined'] == 1
    assert section['limits']['max_seconds'] == 20
    assert section['coverage'] == 'could_not_verify'


def test_large_store_indexed_queries_and_filtered_prompt_reads(tmp_path, monkeypatch):
    from contextlib import contextmanager
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('')
    home = tmp_path / 'home'
    database(home, project, dedup=True)
    # Synthetic sparse >1 GiB store; no real session DB is opened or copied.
    with (home / 'state.db').open('r+b') as stream:
        stream.truncate(1024 * 1024 * 1024 + 4096)
    original = mod.open_readonly_sqlite
    statements, plans = [], []
    @contextmanager
    def tracked(path, **kwargs):
        assert 0 < kwargs['timeout'] <= 0.1
        with original(path, **kwargs) as (conn, identity):
            assert conn.execute('PRAGMA query_only').fetchone()[0] == 1
            conn.set_trace_callback(statements.append)
            yield conn, identity
            conn.set_trace_callback(None)
            for sql in set(statements):
                if sql.startswith('SELECT'):
                    plans.extend(row[3] for row in conn.execute('EXPLAIN QUERY PLAN ' + sql))
    monkeypatch.setattr(mod, 'open_readonly_sqlite', tracked)
    section = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert section['overall']['sessions_examined'] == 6
    assert not any('TEMP B-TREE' in plan or 'AUTOMATIC' in plan for plan in plans)
    assert not any('SCAN messages' in plan for plan in plans)
    statements.clear()
    mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[tmp_path / 'other'])
    assert not any('substr(CAST(' in sql for sql in statements)
    statements.clear()
    monkeypatch.setattr(mod, 'MAX_TOTAL_TEXT_BYTES', 4096)
    section = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert section['limits']['cuts'] > 0
    assert section['limits']['bytes_read'] <= 4096


def test_message_keyset_is_linear_for_equal_timestamps(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('')
    database(tmp_path / 'home', project)
    with sqlite3.connect(tmp_path / 'home/state.db') as conn:
        conn.execute('DELETE FROM messages')
        conn.executemany('INSERT INTO messages(id,session_id,role,content,timestamp) VALUES(?,?,?,?,?)',
                         ((i, 'PRIVATE_SESSION_0', 'user', 'ok', 1.0) for i in range(2000)))
    monkeypatch.setattr(mod, 'MAX_SQL_STEPS', 2000000)
    section = mod.audit_session_contamination(profile_path=tmp_path / 'home', sessions=True, selected_projects=[project])['session_contamination']
    assert section['status'] == 'completed'
    assert section['limits']['messages_examined'] == 2000


def test_fixed_database_failure_reasons_and_hot_journal(tmp_path):
    import hashlib
    mod = load_submodule('audit.session_contamination')
    def reason():
        section = mod.audit_session_contamination(profile_path=tmp_path, sessions=True)['session_contamination']
        assert section['status'] == 'not_measured'
        assert section['coverage'] == 'could_not_verify'
        return section['reason']
    assert reason() == 'missing'
    (tmp_path / 'state.db').write_bytes(b'')
    assert reason() == 'not_sqlite'
    (tmp_path / 'state.db').write_bytes(b'not sqlite')
    assert reason() == 'not_sqlite'
    (tmp_path / 'state.db').unlink()
    database(tmp_path, tmp_path / 'missing')
    journal = tmp_path / 'state.db-journal'
    journal.write_bytes(bytes.fromhex('d9d505f920a163d7') + b'\0' * 1016)
    before = hashlib.sha256((tmp_path / 'state.db').read_bytes()).hexdigest()
    assert reason() == 'hot_journal'
    assert hashlib.sha256((tmp_path / 'state.db').read_bytes()).hexdigest() == before
    journal.unlink()
    with sqlite3.connect(tmp_path / 'state.db') as writer:
        writer.execute('BEGIN EXCLUSIVE')
        # Immutable ignores locks; the writer is detected on post-read identity.
        assert mod.audit_session_contamination(profile_path=tmp_path, sessions=True)['session_contamination']['status'] == 'completed'
        writer.rollback()
        writer.execute('DROP TABLE messages')
    assert reason() == 'schema_unsupported'


def test_precise_memory_boundaries_extensions_and_caps(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    assert mod.technology_counts('main.cpp util.c lib.rs') == {'cpp': 2, 'rust': 1}
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}')
    home = tmp_path / 'home'
    database(home, project)
    monkeypatch.setattr(mod, 'MAX_MESSAGES', 1)
    section = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert section['limits']['messages_examined'] == 1
    assert section['limits']['cuts'] > 0
    assert section['coverage'] == 'could_not_verify'
    monkeypatch.setattr(mod, 'MAX_TEXT_BYTES', 8)
    section = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert section['overall']['median_memory_block_chars'] is None
    assert section['overall']['sessions_classified'] == 0


def test_metadata_and_text_read_bounds(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}')
    home = tmp_path / 'home'
    database(home, project)
    with sqlite3.connect(home / 'state.db') as conn:
        conn.execute("UPDATE sessions SET id=? WHERE id='PRIVATE_SESSION_0'", ('x' * 5000,))
    result = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])['session_contamination']
    assert result['limits']['cuts'] > 0
    assert result['overall']['sessions_examined'] == 5
    assert result['coverage'] == 'could_not_verify'


def test_surface_sessions_flag_persistence_and_cli(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home/.hermes'
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}')
    database(home, project, dedup=True)
    (home / 'config.yaml').write_text('{}')
    registry = home / 'plugin-data/defuzz/state.db'
    registry.parent.mkdir(parents=True)
    with sqlite3.connect(registry) as conn:
        conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY)')
        conn.execute('INSERT INTO projects VALUES(?)', (str(project),))
    monkeypatch.setenv('HERMES_HOME', str(home))
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: discover(*a, **kw, system_config=tmp_path / 'absent'))
    db = tmp_path / 'report/audit.db'
    result = surface.execute_audit({'action': 'run'}, db_path=db, wait=True, sessions=True)
    section = result['report']['session_contamination']
    assert section['read_mode'] == 'immutable'
    assert section['wal_mode'] is False
    assert section['changed_during_read'] is False
    assert section['limits']['max_seconds'] == 20
    saved_run = surface.AuditStore(db).get_run(result['run_id'])
    assert saved_run['inventory']['sessions'] is True
    assert section['overall']['sessions_examined'] == 6
    assert section['overall']['foreign_families'] == {'python': 24}
    finding = next(f for f in result['report']['findings'] if f['id'] == 'session_contamination.foreign_memory_in_project')
    assert finding['evidence']['foreign_families'] == {'python': 24}
    assert 'CANARY' not in json.dumps(result) and 'PRIVATE_SESSION' not in json.dumps(result)
    reread = surface.execute_audit({'action': 'report', 'run_id': result['run_id']}, db_path=db)
    assert reread['report']['session_contamination'] == section
    resumed = surface.execute_audit({'action': 'resume', 'run_id': result['run_id']}, db_path=db, wait=True)
    assert resumed['report']['session_contamination'] == section
    with sqlite3.connect(db) as conn:
        dump = '\n'.join(conn.iterdump())
    assert 'CANARY' not in dump and 'PRIVATE_SESSION' not in dump
    off = surface.execute_audit({'action': 'run'}, db_path=db, wait=True)
    assert off['report']['session_contamination']['status'] == 'not_run'
    quick = surface.execute_audit({'action': 'run', 'quick': True, 'sessions': True}, db_path=db, wait=True)
    assert quick['report']['session_contamination']['reason'] == 'bounded_quick_audit_not_collected'
    import argparse
    parser = argparse.ArgumentParser()
    load_submodule('cli').setup_defuzz_cli(parser)
    assert parser.parse_args(['audit', '--sessions']).sessions is True
    assert surface.SCHEMA['parameters']['properties']['sessions']['type'] == 'boolean'
