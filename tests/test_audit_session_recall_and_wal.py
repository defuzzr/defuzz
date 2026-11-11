"""Session reader regressions (recall scan, pagination, coverage cuts, WAL header), using synthetic stores only."""
import signal
import time

import pytest

from tests.conftest import load_submodule


def test_unterminated_recall_scan_is_linear():
    mod = load_submodule('audit.session_contamination')
    text = (mod.OPEN_FENCE * (1024 * 1024 // len(mod.OPEN_FENCE) + 1))[:1024 * 1024]
    def too_slow(*_):
        pytest.fail('unterminated recall scan exceeded 3 seconds')
    old = signal.signal(signal.SIGALRM, too_slow)
    start = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, 3)
    try:
        assert mod.recalled_blocks(text) == []
        assert time.monotonic() - start < 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


@pytest.mark.parametrize(('text', 'expected'), [
    ('İ<MeMoRy-CoNtExT>hello</MEMORY-context>', ['hello']),
    ('<memory-context>a<memory-context>b</memory-context>c</memory-context>', ['a<memory-context>b']),
    ('</memory-context>before<memory-context>yes</memory-context>', ['yes']),
    ('<memory-context>a</memory-context><memory-context>b</memory-context>', ['a', 'b']),
])
def test_recall_linear_scan_preserves_tag_semantics(text, expected):
    assert load_submodule('audit.session_contamination').recalled_blocks(text) == expected


def test_recall_scan_caps_bytes_and_blocks(monkeypatch):
    mod = load_submodule('audit.session_contamination')
    monkeypatch.setattr(mod, 'MAX_TEXT_BYTES', 40)
    assert mod.recalled_blocks('é' * 5 + '<memory-context>x</memory-context>') == []
    monkeypatch.setattr(mod, 'MAX_TEXT_BYTES', 1024)
    monkeypatch.setattr(mod, 'MAX_MESSAGES', 1)
    assert mod.recalled_blocks('<memory-context>x</memory-context>' * 2) == ['x']


@pytest.mark.parametrize('declaration', ['id INTEGER PRIMARY KEY DESC', 'id INTEGER, PRIMARY KEY(id DESC)'])
def test_message_pagination_requires_true_rowid_alias(tmp_path, declaration):
    import sqlite3
    from tests.test_audit_session_contamination import database
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    home = tmp_path / 'home'
    database(home, project)
    conn = sqlite3.connect(home / 'state.db')
    try:
        conn.execute('DROP TABLE messages')
        # Table-level DESC *is* a rowid alias; column-level DESC is not.
        conn.execute('CREATE TABLE messages(session_id TEXT, role TEXT, content TEXT, timestamp REAL, ' + declaration + ')')
        conn.execute("INSERT INTO messages(session_id, role, content, timestamp) VALUES ('PRIVATE_SESSION_0','user','<memory-context>Python</memory-context>',1738368000)")
        conn.commit()
        alias = conn.execute('SELECT id IS NOT NULL AND id=rowid FROM messages').fetchone()[0]
    finally:
        conn.close()
    result = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])
    if alias:
        assert result['session_contamination']['overall']['memory_context_blocks'] == 1
    else:
        assert result['coverage'] == 'could_not_verify'
        assert any(f['id'] == 'session_contamination.schema_unsupported' for f in result['findings'])


@pytest.mark.parametrize('stamp', ['invalid', -1, 1e100])
def test_outside_session_invalid_time_does_not_cut_selected_coverage(tmp_path, stamp):
    import sqlite3
    from tests.test_audit_session_contamination import database
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    home = tmp_path / 'home'
    database(home, project)
    conn = sqlite3.connect(home / 'state.db')
    try:
        conn.execute('INSERT INTO sessions(id,cwd,started_at) VALUES (?,?,?)',
                     ('outside', '/home/user/unregistered', stamp))
        conn.commit()
    finally:
        conn.close()
    result = mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])
    section = result['session_contamination']
    assert section['sessions_outside_registered_projects'] == 1
    assert section['limits']['cuts'] == 0
    assert result['coverage'] == 'verified'


@pytest.mark.parametrize('state', ['rollback', 'closed_wal', 'empty_wal', 'live_writer'])
def test_wal_mode_reports_file_header_even_when_immutable(tmp_path, state):
    from tests.test_audit_user_db_readonly import prepare
    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    path, writer = prepare(tmp_path, state, project)
    try:
        section = mod.audit_session_contamination(profile_path=path.parent, sessions=True,
                                                  selected_projects=[project])['session_contamination']
        assert section['wal_mode'] is (state != 'rollback')
        assert section['read_mode'] == ('mode=ro' if state == 'live_writer' else 'immutable')
    finally:
        if writer:
            writer.close()
