"""All audit-reachable user DB readers; synthetic stores only."""
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from tests.conftest import load_submodule
from tests.test_audit_session_contamination import database

READERS = ('session_evidence', 'registrations', 'contamination', 'outward', 'lock_trust')
STATES = ('rollback', 'closed_wal', 'empty_wal', 'empty_wal_stale_shm',
          'frames_shm', 'frames_no_shm', 'live_writer', 'empty', 'truncated', 'hot_journal')


def snapshot(root, *, exclude=None):
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in root.rglob('*') if exclude is None or not p.is_relative_to(exclude)}


def invoke(reader, path, project):
    ro = load_submodule('audit.readonly_db')
    if reader == 'session_evidence':
        return ro.read_profile_session_evidence(path)
    if reader == 'registrations':
        return ro.read_profile_registrations_readonly('default', path.parent, db_path=path)
    if reader == 'contamination':
        return load_submodule('audit.session_contamination').audit_session_contamination(
            profile_path=path.parent, sessions=True, selected_projects=[project])
    if reader == 'outward':
        return load_submodule('audit.outward_db').inspect_database(path)
    return load_submodule('tool_guard').inspect_lock_trust(project, db_path=path)


def prepare(tmp_path, state, project):
    home = tmp_path / 'home'
    database(home, project)
    path = home / 'state.db'
    writer = sqlite3.connect(path)
    writer.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
    writer.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synthetic'))
    writer.commit()
    writer.close()
    live = None
    if state in {'closed_wal', 'empty_wal', 'empty_wal_stale_shm', 'frames_shm', 'frames_no_shm', 'live_writer'}:
        writer = sqlite3.connect(path)
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("UPDATE sessions SET message_count=2")
        writer.commit()
        if state.startswith('frames'):
            copied = tmp_path / 'copied'
            copied.mkdir()
            for suffix in ('', '-wal', '-shm'):
                shutil.copyfile(str(path) + suffix, copied / ('state.db' + suffix))
            writer.close()
            path = copied / 'state.db'
            if state == 'frames_no_shm':
                Path(str(path) + '-shm').unlink()
        elif state == 'live_writer':
            live = writer
        else:
            writer.close()
            if state.startswith('empty_wal'):
                Path(str(path) + '-wal').touch()
            if state == 'empty_wal_stale_shm':
                Path(str(path) + '-shm').write_bytes(b'stale' * 6554)
    elif state == 'empty':
        path.write_bytes(b'')
    elif state == 'truncated':
        path.write_bytes(path.read_bytes()[:100])
    elif state == 'hot_journal':
        # Nonzero rollback-journal header; never recover or ignore this evidence.
        Path(str(path) + '-journal').write_bytes(bytes.fromhex('d9d505f920a163d7') + bytes(1016))
    return path, live


@pytest.mark.parametrize('reader', READERS)
@pytest.mark.parametrize('state', STATES)
@pytest.mark.parametrize('readonly', [False, True], ids=['writable', '0555'])
def test_every_reader_creates_no_user_sidecars(tmp_path, reader, state, readonly):
    if readonly and os.geteuid() == 0:
        pytest.skip('root bypasses chmod 0555 directory permissions')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    path, writer = prepare(tmp_path, state, project)
    before = snapshot(path.parent)
    if readonly:
        path.parent.chmod(0o555)
    try:
        assert invoke(reader, path, project) is not None
        after = snapshot(path.parent)
        assert after.keys() == before.keys()
        assert {k: v for k, v in after.items() if not k.endswith('-shm')} == {
            k: v for k, v in before.items() if not k.endswith('-shm')}
    finally:
        path.parent.chmod(0o755)
        if writer:
            writer.close()


@pytest.mark.parametrize('sessions', [False, True])
def test_full_audit_preserves_synthetic_home(tmp_path, monkeypatch, sessions):
    import tempfile
    import time
    surface = load_submodule('audit_surface')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').touch()
    home = tmp_path / 'home'
    database(home, project)
    (home / 'config.yaml').write_text('{}')
    # Explicit audit DB isolated from the inspected registration store.
    allowed = home / 'plugin-data' / 'defuzz' / 'audit-output'
    allowed.mkdir(parents=True)
    registry = home / 'plugin-data' / 'defuzz' / 'state.db'
    stores = [home / 'state.db', registry, home / 'projects.db', home / 'kanban.db', home / 'cron.db']
    for path in stores:
        conn = sqlite3.connect(path)
        if path != home / 'state.db':
            conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
            conn.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synthetic'))
            conn.commit()
        conn.execute('PRAGMA journal_mode=WAL')
        conn.close()
    rollback_db = home / 'rollback.db'
    conn = sqlite3.connect(rollback_db)
    conn.execute('PRAGMA journal_mode=DELETE')
    conn.execute('CREATE TABLE tasks(id TEXT, title TEXT, status TEXT, workspace_path TEXT)')
    conn.execute('INSERT INTO tasks VALUES (?, ?, ?, ?)', ('t1', 'title', 'todo', str(project)))
    conn.commit()
    conn.close()
    large_db = home / 'large64m.db'
    conn = sqlite3.connect(large_db)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE sessions(cwd TEXT, started_at INTEGER)')
    conn.execute('INSERT INTO sessions VALUES (?, ?)', (str(project), 456))
    conn.commit()
    conn.close()

    watched_tmp = tmp_path / 'watched-tmpdir'
    watched_tmp.mkdir()
    for var in ('TMPDIR', 'TMP', 'TEMP'):
        monkeypatch.setenv(var, str(watched_tmp))
    monkeypatch.setattr(tempfile, 'tempdir', str(watched_tmp))

    tmpdir_creates = []
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    orig_os_open = os.open
    orig_mkdir = os.mkdir

    def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
        resolved = (
            Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / path
            if dir_fd is not None and not Path(path).is_absolute()
            else Path(path)
        )
        if resolved == watched_tmp or resolved.is_relative_to(watched_tmp):
            tmpdir_creates.append(str(resolved))
        if flags & write_flags:
            abs_p = resolved.absolute()
            if not (abs_p == allowed or abs_p.is_relative_to(allowed)):
                pytest.fail(f'write os.open outside plugin audit store: {abs_p}')
        return orig_os_open(path, flags, mode, dir_fd=dir_fd)

    def guarded_mkdir(path, mode=0o777, *, dir_fd=None):
        resolved = Path(path)
        if resolved == watched_tmp or resolved.is_relative_to(watched_tmp):
            tmpdir_creates.append(str(resolved))
        return orig_mkdir(path, mode, dir_fd=dir_fd)

    def forbidden_temp(*args, **kwargs):
        tmpdir_creates.append(f'tempfile:{args}:{kwargs}')
        pytest.fail('audit must not create temporary files or directories')

    def forbidden_copy(*args, **kwargs):
        pytest.fail('audit must not copy files with shutil.copy*')

    monkeypatch.setattr(os, 'open', guarded_os_open)
    monkeypatch.setattr(os, 'mkdir', guarded_mkdir)
    monkeypatch.setattr(tempfile, 'TemporaryDirectory', forbidden_temp)
    monkeypatch.setattr(tempfile, 'mkdtemp', forbidden_temp)
    monkeypatch.setattr(tempfile, 'mkstemp', forbidden_temp)
    for fn_name in ('copy', 'copy2', 'copyfile', 'copytree'):
        monkeypatch.setattr(shutil, fn_name, forbidden_copy)

    monkeypatch.setenv('HERMES_HOME', str(home))
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw:
                        discover(*a, **kw, system_config=tmp_path / 'absent-gitconfig'))
    # This guards against size-dependent DB work, not a universal full-audit
    # latency promise (docs/audit-scope.md allows full profiles to take minutes).
    # Calibrate the same audit before padding the DB, with all no-write/no-copy
    # guards active. Allow 2x that work plus scheduling headroom, but keep a
    # finite 30-second ceiling so a slow calibration cannot hide a regression.
    before_small = snapshot(home, exclude=allowed)
    t_small0 = time.monotonic()
    small = surface.execute_audit({'action': 'run', 'root': str(project)},
                                 db_path=allowed / 'audit.db', wait=True, sessions=sessions)
    t_small = time.monotonic() - t_small0
    assert small['status'] == 'completed'
    assert snapshot(home, exclude=allowed) == before_small
    assert tmpdir_creates == []
    assert list(watched_tmp.iterdir()) == []
    if sessions:
        assert small['report']['session_contamination']['database_copied'] is False
    # Fixture setup, outside both audit timings. Only unused DB space changes.
    with large_db.open('r+b') as stream:
        stream.truncate(64 * 1024 * 1024)
    budget = min(30.0, 2.0 * t_small + 1.0)
    assert t_small < 30.0, f'calibration audit took {t_small:.3f}s'
    before = snapshot(home, exclude=allowed)
    t_db0 = time.monotonic()
    db_report = load_submodule('audit.outward_db').inspect_database(large_db)
    t_db = time.monotonic() - t_db0
    assert db_report['schema'] == 'hermes_sessions'
    assert t_db < 1.0
    t0 = time.monotonic()
    result = surface.execute_audit({'action': 'run', 'root': str(project)},
                                   db_path=allowed / 'audit.db', wait=True, sessions=sessions)
    elapsed = time.monotonic() - t0
    print(f'LARGE64M_TIMING sessions={sessions} inspect_database_s={t_db:.6f} '
          f'calibration_s={t_small:.6f} execute_audit_s={elapsed:.6f} budget_s={budget:.6f}')
    assert result['status'] == 'completed'
    assert elapsed < budget, f'64 MiB audit took {elapsed:.3f}s; calibrated budget {budget:.3f}s'
    assert tmpdir_creates == []
    assert list(watched_tmp.iterdir()) == []
    assert snapshot(home, exclude=allowed) == before
    if sessions:
        assert result['report']['session_contamination']['database_copied'] is False
