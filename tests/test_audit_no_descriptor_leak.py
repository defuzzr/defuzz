"""Full in-process audits must not retain handles on the inspected home."""
from contextlib import closing
import gc
import os
from pathlib import Path
import sqlite3

import pytest

from tests.conftest import load_submodule

from tests.test_audit_reasons_present import _sweep_home
from tests.test_audit_wired_sections import _audit

pytestmark = pytest.mark.skipif(not Path('/proc/self/fd').is_dir(), reason='requires Linux procfs')


def _descriptors():
    gc.collect()
    targets = {}
    for name in os.listdir('/proc/self/fd'):
        try:
            targets[name] = os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:
            pass  # listdir's own directory handle has already closed
    return targets


def _assert_no_home_handles(targets, home):
    root = str(home)
    assert not {fd: target for fd, target in targets.items()
                if target == root or target.startswith(root + os.sep)}


def test_full_audit_releases_descriptors(tmp_path, monkeypatch):
    home, _, _ = _sweep_home(tmp_path, 'typical')
    before = _descriptors()
    _audit(tmp_path, monkeypatch, home)
    first = _descriptors()
    _audit(tmp_path, monkeypatch, home)
    second = _descriptors()
    print(f'FDCOUNTS complete: {len(before)} -> {len(first)} -> {len(second)}')
    assert len(second) == len(first) == len(before)
    _assert_no_home_handles(first, home)
    _assert_no_home_handles(second, home)


def test_cancelled_audit_releases_descriptors(tmp_path, monkeypatch):
    home, _, _ = _sweep_home(tmp_path, 'typical')
    # Request cancellation at 80/2000 opens so the next real cancellation
    # poll stops the first sweep at about 5%. The product polls every 100
    # checks, while the directory iterator is still open.
    files = home / 'notes'
    files.mkdir()
    for index in range(2000):
        (files / f'{index:04d}.txt').write_text('synthetic note\n', encoding='utf-8')
    surface = load_submodule('audit_surface')
    outward = load_submodule('audit.outward')
    original = outward.open_checked
    inspected = 0
    cancellations = []
    db = tmp_path / 'audit-store' / 'audit.db'

    def progress(*args, **kwargs):
        nonlocal inspected
        inspected += 1
        if inspected == 80:
            with closing(sqlite3.connect(db)) as conn:
                run_id = conn.execute("SELECT run_id FROM audit_runs WHERE status='running'").fetchone()[0]
            # Both the CLI and dashboard call this product cancellation action.
            cancellations.append(surface.execute_audit({'action': 'cancel', 'run_id': run_id}, db_path=db))
        return original(*args, **kwargs)

    monkeypatch.setattr(outward, 'open_checked', progress)
    before = _descriptors()
    result = _audit(tmp_path, monkeypatch, home)
    after = _descriptors()
    print(f'FDCOUNTS cancelled: {len(before)} -> {len(after)}; entries={inspected}/2000')
    assert len(cancellations) == 1
    assert cancellations[0]['status'] == result['status'] == 'cancelled'
    assert 80 <= inspected <= 110  # cancellation must actually stop this directory walk
    assert len(after) == len(before)
    _assert_no_home_handles(after, home)


def test_exception_mid_walk_releases_descriptors(tmp_path, monkeypatch):
    home, _, _ = _sweep_home(tmp_path, 'typical')
    fingerprint = load_submodule('audit.fingerprint')
    original = fingerprint._record_regular_file_in_manifest
    read = fingerprint.safe_read_regular_file
    files_read = 0
    raised = []

    def interrupt():
        raised.append(True)
        raise RuntimeError('synthetic mid-walk failure')

    def record(*args, **kwargs):
        nonlocal files_read
        files_read += 1
        if files_read != 3:
            return original(*args, **kwargs)

        def interrupted_read(*a, **kw):
            return read(*a, **{**kw, '_mid_read_hook': interrupt})

        with monkeypatch.context() as patch:
            patch.setattr(fingerprint, 'safe_read_regular_file', interrupted_read)
            return original(*args, **kwargs)

    monkeypatch.setattr(fingerprint, '_record_regular_file_in_manifest', record)
    before = _descriptors()
    with pytest.raises(RuntimeError, match='synthetic mid-walk failure'):
        _audit(tmp_path, monkeypatch, home)
    after = _descriptors()
    print(f'FDCOUNTS exception: {len(before)} -> {len(after)}; files={files_read}')
    assert files_read == 3 and raised == [True]
    assert len(after) == len(before)
    _assert_no_home_handles(after, home)
    with closing(sqlite3.connect(tmp_path / 'audit-store' / 'audit.db')) as conn:
        assert conn.execute('SELECT status FROM audit_runs').fetchall() == [('failed',)]


@pytest.mark.parametrize('failure', ['open', 'iterate'])
def test_directory_recheck_closes_duplicate_on_exception(tmp_path, monkeypatch, failure):
    fingerprint = load_submodule('audit.fingerprint')
    home = tmp_path / 'home'
    home.mkdir()
    original = os.scandir
    duplicates = []
    duplicate = os.dup

    def tracked_dup(fd):
        result = duplicate(fd)
        duplicates.append(result)
        return result

    class InterruptedScan:
        def __init__(self, fd):
            self.iterator = original(fd)

        def __enter__(self):
            self.iterator.__enter__()
            return self

        def __exit__(self, *args):
            return self.iterator.__exit__(*args)

        def __iter__(self):
            raise RuntimeError('synthetic recheck failure')

    def interrupted_scan(fd):
        if failure == 'open':
            raise RuntimeError('synthetic recheck failure')
        return InterruptedScan(fd)

    before = _descriptors()
    with fingerprint._open_root_dir_fd(home) as (fd, _, _):
        manifest = fingerprint.TreeFingerprintManifest(unit_kind='profile', unit_id='default', root_path=str(home))
        with monkeypatch.context() as patch:
            patch.setattr(os, 'dup', tracked_dup)
            patch.setattr(os, 'scandir', interrupted_scan)
            with pytest.raises(RuntimeError, match='synthetic recheck failure'):
                fingerprint._verify_dir_entries_unchanged(manifest, fd, '', [])
        assert len(duplicates) == 1
        with pytest.raises(OSError):
            os.fstat(duplicates[0])
        os.fstat(fd)  # the borrowed parent handle still belongs to its caller
    after = _descriptors()
    assert len(after) == len(before)
    _assert_no_home_handles(after, home)
