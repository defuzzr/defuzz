"""Non-audit consumers must not acquire audit keys or keyed digests."""
import hashlib
from types import SimpleNamespace

import pytest
from tests import load_submodule


@pytest.mark.parametrize('consumer', ['guard', 'workspace'])
def test_non_audit_reads_do_not_touch_audit_key(tmp_path, monkeypatch, consumer):
    key = load_submodule('audit.key')
    key_paths = key.private_paths()
    def forbidden():
        pytest.fail('non-audit read attempted audit key access')
    monkeypatch.setattr(key, '_load_key', forbidden)
    root = tmp_path / 'repo'
    root.mkdir()
    content = b'[lock]\n'
    (root / 'TOOLS.lock').write_bytes(content)
    if consumer == 'guard':
        guard = load_submodule('tool_guard')
        state = guard.inspect_lock_trust(root)
        assert state['tools_lock_hash'] == hashlib.sha256(content).hexdigest()
        assert guard.trust_lock(root, expected_hash=state['tools_lock_hash'])['trusted']
        assert guard.static_lock_summary(root)['coverage'] == 'verified'
    else:
        registrations = load_submodule('audit.readonly_db')
        monkeypatch.setattr(registrations, 'read_profile_registrations_readonly', lambda *a: SimpleNamespace(
            coverage='verified', changed_during_read=False, records=[{'canonical_path': str(root)}]))
        routes = load_submodule('dashboard.routes.workspace_routes')
        assert routes.workspace_file(str(root), 'TOOLS.lock')['content'] == content.decode()
    assert not any(path.exists() for path in key_paths)


def test_plain_reader_keeps_audit_capture_keyed(tmp_path):
    fp = load_submodule('audit.fingerprint')
    capture_mod = load_submodule('audit.capture')
    capture = capture_mod.Capture()
    data = b'reviewed content'
    (tmp_path / 'README.md').write_bytes(data)
    token = capture_mod.CURRENT_CAPTURE.set(capture)
    try:
        plain = fp.safe_read_regular_file_plain(tmp_path, 'README.md', retain_bytes=False)
        assert plain.sha256 == hashlib.sha256(data).hexdigest()
        assert plain.content is None
        assert capture.reads == {}
        audit = fp.safe_read_regular_file(tmp_path, 'README.md')
        assert audit.sha256 != plain.sha256
        assert list(capture.reads.values()) == [audit]
        assert fp.safe_read_regular_file_plain(tmp_path, 'README.md').sha256 == plain.sha256
        assert list(capture.reads.values()) == [audit]
    finally:
        capture_mod.CURRENT_CAPTURE.reset(token)


def test_plain_reader_preserves_safe_read_guards(tmp_path):
    fp = load_submodule('audit.fingerprint')
    path = tmp_path / 'README.md'
    path.write_bytes(b'content')
    (tmp_path / 'link').symlink_to(path)
    assert fp.safe_read_regular_file_plain(tmp_path, 'link').kind == 'symlink'
    bounded = fp.safe_read_regular_file_plain(tmp_path, 'README.md', max_bytes=2)
    assert bounded.bounded_exceeded and bounded.sha256 is None
    raced = fp.safe_read_regular_file_plain(tmp_path, 'README.md',
        _mid_read_hook=lambda: path.write_bytes(b'changed content'))
    assert not raced.stable and raced.sha256 is None and raced.content is None


def test_lock_trust_race_on_exit_and_open_failures_never_trust(tmp_path, monkeypatch):
    import sqlite3
    import shutil
    from pathlib import Path

    guard = load_submodule('tool_guard')
    ro = load_submodule('audit.readonly_db')
    root = tmp_path / 'repo'
    root.mkdir()
    content = b'[lock]\nschema = 1\n[python]\nversion = "3.12.0"\nsource = "human"\n'
    (root / 'TOOLS.lock').write_bytes(content)
    db = tmp_path / 'store' / 'state.db'

    initial = guard.inspect_lock_trust(root, db_path=db)
    trusted = guard.trust_lock(root, expected_hash=initial['tools_lock_hash'], db_path=db)
    assert trusted['trusted'] is True
    assert trusted['status'] == 'trusted'
    assert trusted['coverage'] == 'verified'
    assert guard.static_lock_summary(root, db_path=db)['coverage'] == 'verified'
    before_files = sorted(p.name for p in db.parent.iterdir())
    assert guard.inspect_lock_trust(root, db_path=db)['trusted'] is True
    assert sorted(p.name for p in db.parent.iterdir()) == before_files

    # 1. Race on context exit AFTER stored = row[0] was assigned
    orig_stat = ro.stat_db_identity
    calls = 0

    def stat_race_on_post(target):
        nonlocal calls
        calls += 1
        ident = orig_stat(target)
        if calls >= 2:
            return ro.replace(ident, size=ident.size + 4096)
        return ident

    with monkeypatch.context() as mp:
        mp.setattr(ro, 'stat_db_identity', stat_race_on_post)
        raced_state = guard.inspect_lock_trust(root, db_path=db)
        assert raced_state['trusted'] is False
        assert raced_state['status'] == 'unknown'
        assert raced_state['trusted_hash'] is None
        assert raced_state['coverage'] == 'could_not_verify'
        assert raced_state['reason'] == 'ReadOnlyDbError'
        calls = 0
        raced_summary = guard.static_lock_summary(root, db_path=db)
        assert raced_summary['coverage'] == 'could_not_verify'
        assert raced_summary['trust']['trusted'] is False

    # 2. wal_needs_index (WAL with frames, no -shm)
    wal_dir = tmp_path / 'wal_no_shm'
    wal_dir.mkdir()
    wal_db = wal_dir / 'state.db'
    shutil.copyfile(db, wal_db)
    writer = sqlite3.connect(wal_db)
    writer.execute('PRAGMA journal_mode=WAL')
    writer.execute("UPDATE tools_lock_trust SET source='plugin'")
    writer.commit()
    copied_dir = tmp_path / 'copied_wal'
    copied_dir.mkdir()
    for suffix in ('', '-wal'):
        shutil.copyfile(str(wal_db) + suffix, copied_dir / ('state.db' + suffix))
    writer.close()
    no_shm_db = copied_dir / 'state.db'

    wal_state = guard.inspect_lock_trust(root, db_path=no_shm_db)
    assert wal_state['trusted'] is False
    assert wal_state['status'] == 'unknown'
    assert wal_state['trusted_hash'] is None
    assert wal_state['coverage'] == 'could_not_verify'
    wal_summary = guard.static_lock_summary(root, db_path=no_shm_db)
    assert wal_summary['coverage'] == 'could_not_verify'
    assert not Path(str(no_shm_db) + '-shm').exists()

    # 3. hot_journal
    Path(str(db) + '-journal').write_bytes(b'hot-journal')
    try:
        hj_state = guard.inspect_lock_trust(root, db_path=db)
        assert hj_state['trusted'] is False
        assert hj_state['status'] == 'unknown'
        assert hj_state['trusted_hash'] is None
        assert hj_state['coverage'] == 'could_not_verify'
        assert guard.static_lock_summary(root, db_path=db)['coverage'] == 'could_not_verify'
    finally:
        Path(str(db) + '-journal').unlink()
