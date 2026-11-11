"""Legacy state is copied only within the active profile."""
import errno
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests import load_submodule


def _legacy(store, name='defuzz'):
    path = Path(os.environ['HERMES_HOME']) / f'plugins/{name}/state.db'
    store.record_template_option('template', 'option', name, db_path=path)
    return path


@pytest.mark.parametrize('missing', ['fcntl', 'flags', 'dir_fd', 'fd', 'follow_symlinks'])
def test_portable_migration_without_sweep(missing):
    child = subprocess.run([sys.executable, '-c', """
import importlib, os, sys
from pathlib import Path
from tests import load_submodule
if sys.argv[1] == 'fcntl':
    sys.modules['fcntl'] = None
elif sys.argv[1] == 'flags':
    del os.O_NOFOLLOW
else:
    setattr(os, 'supports_' + sys.argv[1], set())
store = load_submodule('state_store')
store = importlib.reload(store)
legacy = Path(os.environ['HERMES_HOME']) / 'plugins/defuzz/state.db'
store.record_template_option('template', 'option', 'legacy', db_path=legacy)
target = store.plugin_data_dir('defuzz') / 'state.db'
artifact = store._create_artifact(target.parent, 'source')
manifest = artifact / store._ARTIFACT_MANIFEST
import json
metadata = json.loads(manifest.read_text())
metadata['created_at'] = 1
manifest.write_text(json.dumps(metadata))
os.utime(artifact, (1, 1))
before = manifest.read_bytes()
assert store.state_db_path() == target
assert store.get_template_option('template', 'option')['choice'] == 'legacy'
assert manifest.read_bytes() == before
store.record_template_option('template', 'option', 'current')
assert store.get_template_option('template', 'option')['choice'] == 'current'
assert store.get_template_option('template', 'option', db_path=legacy)['choice'] == 'legacy'
assert not (target.parent / '.state-migration.lock').exists()
""", missing], capture_output=True, text=True)
    assert child.returncode == 0, child.stdout + child.stderr


def test_hot_journal_is_skipped(caplog):
    store = load_submodule('state_store')
    legacy = _legacy(store)
    child = subprocess.Popen([sys.executable, '-c', """
import sqlite3, sys, time
conn = sqlite3.connect(sys.argv[1])
conn.execute('PRAGMA cache_size=1')
conn.execute('BEGIN EXCLUSIVE')
conn.execute("UPDATE template_options SET choice='uncommitted'")
conn.execute('CREATE TABLE spill (data BLOB)')
for _ in range(100):
    conn.execute('INSERT INTO spill VALUES (zeroblob(4096))')
print('ready', flush=True)
time.sleep(60)
""", str(legacy)], stdout=subprocess.PIPE, text=True)
    assert child.stdout is not None
    try:
        assert child.stdout.readline().strip() == 'ready'
    finally:
        child.kill()
        child.wait()
        child.stdout.close()
    journal = Path(str(legacy) + '-journal')
    assert journal.stat().st_size > 0
    before = {p.name: p.read_bytes() for p in legacy.parent.iterdir()}
    assert not store.state_db_path().exists()
    assert 'journal' in caplog.text
    assert {p.name: p.read_bytes() for p in legacy.parent.iterdir()} == before


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'replaced'])
def test_unsafe_wal_is_rejected(tmp_path, monkeypatch, caplog, kind):
    store = load_submodule('state_store')
    legacy = _legacy(store)
    conn = sqlite3.connect(legacy)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute("UPDATE template_options SET choice='wal'")
    conn.commit()
    wal = Path(str(legacy) + '-wal')
    try:
        if kind == 'hardlink':
            os.link(wal, tmp_path / 'other-wal')
        elif kind == 'symlink':
            other = tmp_path / 'other-wal'
            other.write_bytes(wal.read_bytes())
            wal.unlink()
            wal.symlink_to(other)
        else:
            backup = store._backup_legacy
            def replace(*args):
                backup(*args)
                other = wal.with_suffix('.replacement')
                other.write_bytes(wal.read_bytes())
                other.replace(wal)
            monkeypatch.setattr(store, '_backup_legacy', replace)
        assert not store.state_db_path().exists()
        assert 'Skipping legacy state' in caplog.text
    finally:
        conn.close()


def test_prefix_named_user_directory_is_preserved(tmp_path):
    store = load_submodule('state_store')
    artifact = tmp_path / '.state-source-user'
    artifact.mkdir()
    personal = artifact / 'personal-data'
    personal.write_text('irreplaceable')
    old = time.time() - 7200
    os.utime(artifact, (old, old))
    store._sweep_migration_leftovers(tmp_path)
    assert personal.read_text() == 'irreplaceable'


def _owned_artifact(directory, kind='source'):
    nonce = 'a' * 32
    path = directory / f'.state-{kind}-{nonce}'
    path.mkdir()
    old = time.time() - 7200
    (path / '.defuzz-artifact.json').write_text(json.dumps({
        'kind': kind, 'nonce': nonce, 'created_by': 'defuzz-state-migration',
        'pid': os.getpid(), 'created_at': old,
    }))
    (path / 'state.db').write_bytes(b'old')
    os.utime(path, (old, old))
    return path


def test_active_artifact_not_swept_with_other_process_lock(tmp_path):
    import subprocess
    import sys
    store = load_submodule('state_store')
    artifact = _owned_artifact(tmp_path)
    code = "import fcntl,sys; f=open(sys.argv[1], 'a'); fcntl.flock(f, fcntl.LOCK_EX); print('ready', flush=True); sys.stdin.read()"
    with subprocess.Popen([sys.executable, '-c', code, str(tmp_path / '.state-migration.lock')],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
        try:
            assert process.stdout is not None
            assert process.stdout.readline().strip() == 'ready'
            store._sweep_migration_leftovers(tmp_path)
            assert artifact.exists()
        finally:
            process.communicate(timeout=10)
    store._sweep_migration_leftovers(tmp_path)
    assert not artifact.exists()


def test_migration_owns_artifacts_and_holds_lock(monkeypatch):
    import fcntl
    store = load_submodule('state_store')
    _legacy(store)
    backup = store._backup_legacy
    def inspect(source, query, temporary, legacy):
        directory = temporary.parent.parent
        with (directory / '.state-migration.lock').open('a') as lock:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for kind in ('source', 'migration'):
            artifacts = list(directory.glob(f'.state-{kind}-*'))
            assert len(artifacts) == 1
            manifest = json.loads((artifacts[0] / '.defuzz-artifact.json').read_text())
            assert manifest['kind'] == kind
            assert artifacts[0].name == f".state-{kind}-{manifest['nonce']}"
        backup(source, query, temporary, legacy)
    monkeypatch.setattr(store, '_backup_legacy', inspect)
    assert store.get_template_options('template') == {'option': 'defuzz'}
    assert {p.name for p in store.state_db_path().parent.glob('.state-*')} == {'.state-migration.lock'}


@pytest.mark.parametrize('entry', ['state.db', '.defuzz-artifact.json'])
def test_artifact_symlink_is_not_followed(tmp_path, entry):
    store = load_submodule('state_store')
    artifact = _owned_artifact(tmp_path)
    outside = tmp_path / 'personal-data'
    outside.write_text('untouched')
    (artifact / entry).unlink()
    (artifact / entry).symlink_to(outside)
    old = time.time() - 7200
    os.utime(artifact, (old, old))
    store._sweep_migration_leftovers(tmp_path)
    assert outside.read_text() == 'untouched'
    assert (artifact / entry).is_symlink()
    assert artifact.exists()


@pytest.mark.parametrize('change', ['nonce', 'extra-key', 'pid', 'kind', 'extra-file', 'nan', 'huge-time'])
def test_unverified_manifest_is_preserved(tmp_path, change, caplog):
    store = load_submodule('state_store')
    artifact = _owned_artifact(tmp_path)
    path = artifact / '.defuzz-artifact.json'
    manifest = json.loads(path.read_text())
    if change == 'extra-file':
        (artifact / 'personal-data').write_text('untouched')
    elif change == 'extra-key':
        manifest['extra'] = True
    elif change == 'huge-time':
        manifest['created_at'] = 10 ** 1000
    elif change == 'nan':
        manifest['created_at'] = float('nan')
    else:
        manifest[change] = 'invalid'
    path.write_text(json.dumps(manifest))
    old = time.time() - 7200
    os.utime(artifact, (old, old))
    with caplog.at_level('DEBUG'):
        store._sweep_migration_leftovers(tmp_path)
    assert (artifact / 'state.db').read_bytes() == b'old'
    assert 'unverified migration artifact' in caplog.text


def test_stale_migration_files_are_swept():
    store = load_submodule('state_store')
    target = store.plugin_data_dir('defuzz') / 'state.db'
    old_file = target.parent / '.state-migration-old'
    old_dir = _owned_artifact(target.parent)
    old_file.write_bytes(b'old')
    fresh = target.parent / '.state-migration-fresh'
    fresh.touch()
    unrelated = target.parent / '.state-other-old'
    unrelated.touch()
    legacy = _legacy(store)
    legacy_leftover = legacy.parent / '.state-migration-old'
    legacy_leftover.touch()
    for item in (old_file, old_dir, unrelated, legacy_leftover):
        old = time.time() - 7200
        os.utime(item, (old, old))
    store.state_db_path()
    assert old_file.exists()  # Prefix-only artifacts from older versions are unverified.
    assert not old_dir.exists()
    assert fresh.exists() and unrelated.exists() and legacy_leftover.exists()


def test_wal_snapshot_does_not_read_whole_files(monkeypatch):
    store = load_submodule('state_store')
    legacy = _legacy(store)
    conn = sqlite3.connect(legacy)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute("UPDATE template_options SET choice='streamed'")
    conn.commit()
    def forbid(*args):
        raise AssertionError('whole-file read')
    monkeypatch.setattr(Path, 'read_bytes', forbid)
    try:
        assert store.get_template_options('template') == {'option': 'streamed'}
    finally:
        conn.close()


def test_hardlinked_legacy_is_rejected(tmp_path, caplog):
    store = load_submodule('state_store')
    legacy = _legacy(store)
    os.link(legacy, tmp_path / 'other-profile.db')
    assert store.get_template_options('template') == {}
    assert 'hardlink' in caplog.text


def test_replaced_source_is_rejected(monkeypatch, caplog):
    store = load_submodule('state_store')
    legacy = _legacy(store)
    backup = store._backup_legacy
    def replace(*args):
        backup(*args)
        other = legacy.with_suffix('.new')
        other.write_bytes(legacy.read_bytes())
        other.replace(legacy)
    monkeypatch.setattr(store, '_backup_legacy', replace)
    assert store.get_template_options('template') == {}
    assert 'changed' in caplog.text


def test_unsupported_publication_warns_explicitly(monkeypatch, caplog):
    store = load_submodule('state_store')
    _legacy(store)
    def unsupported(*args):
        raise OSError(errno.EOPNOTSUPP, 'no hardlinks')
    monkeypatch.setattr(store.os, 'link', unsupported)
    assert store.get_template_options('template') == {}
    assert 'Cannot publish legacy state atomically' in caplog.text


def test_marker_failure_does_not_report_migration_skipped(monkeypatch, caplog):
    store = load_submodule('state_store')
    _legacy(store)
    def fail(*args):
        raise OSError('marker failure')
    monkeypatch.setattr(store.os, 'replace', fail)
    assert store.get_template_options('template') == {'option': 'defuzz'}
    assert 'marker' in caplog.text
    assert 'Skipping legacy state' not in caplog.text
    assert {p.name for p in store.state_db_path().parent.glob('.state-*')} == {'.state-migration.lock'}


def test_precedence_and_migration_records():
    store = load_submodule('state_store')
    _legacy(store, 'adopt-place')
    legacy = _legacy(store)
    assert store.get_template_options('template') == {'option': 'defuzz'}
    target = store.state_db_path()
    # The record names the resolved source (the home may sit behind a link).
    assert json.loads(target.with_suffix('.migration.json').read_text()) == {
        'source': os.path.realpath(legacy), 'method': 'sqlite3.backup'}
    conn = sqlite3.connect(target)
    try:
        assert conn.execute('SELECT source FROM defuzz_migrations').fetchall() == [(os.path.realpath(legacy),)]
    finally:
        conn.close()


def test_concurrent_publication_keeps_winner(monkeypatch):
    store = load_submodule('state_store')
    _legacy(store)
    def winner(source, target):
        store.record_template_option('template', 'option', 'winner', db_path=target)
        raise FileExistsError(target)
    monkeypatch.setattr(store.os, 'link', winner)
    assert store.get_template_options('template') == {'option': 'winner'}
    assert not store.state_db_path().with_suffix('.migration.json').exists()


@pytest.mark.parametrize('journal,live', [('DELETE', False), ('WAL', False), ('WAL', True)])
def test_legacy_directory_is_byte_identical(journal, live):
    store = load_submodule('state_store')
    legacy = Path(os.environ['HERMES_HOME']) / 'plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'legacy', db_path=legacy)
    conn = sqlite3.connect(legacy)
    conn.execute(f'PRAGMA journal_mode={journal}')
    conn.execute("UPDATE template_options SET choice='latest'")
    conn.commit()
    if not live:
        conn.close()
    before = {p.name: p.read_bytes() for p in legacy.parent.iterdir()}
    try:
        assert store.get_template_options('template') == {'option': 'latest'}
        assert {p.name: p.read_bytes() for p in legacy.parent.iterdir()} == before
    finally:
        conn.close()


def test_wal_without_shm_preserves_directory(tmp_path):
    store = load_submodule('state_store')
    source = tmp_path / 'source.db'
    store.record_template_option('template', 'option', 'old', db_path=source)
    conn = sqlite3.connect(source)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute("UPDATE template_options SET choice='wal-only'")
    conn.commit()
    legacy = Path(os.environ['HERMES_HOME']) / 'plugins/defuzz/state.db'
    legacy.parent.mkdir(parents=True)
    try:
        legacy.write_bytes(source.read_bytes())
        Path(str(legacy) + '-wal').write_bytes(Path(str(source) + '-wal').read_bytes())
    finally:
        conn.close()
    before = {p.name: p.read_bytes() for p in legacy.parent.iterdir()}
    assert store.get_template_options('template') == {'option': 'wal-only'}
    assert {p.name: p.read_bytes() for p in legacy.parent.iterdir()} == before


def test_legacy_is_backed_up_on_first_read():
    store = load_submodule('state_store')
    legacy = Path(os.environ['HERMES_HOME']) / 'plugins/adopt-place/state.db'
    store.record_template_option('template', 'option', 'legacy', db_path=legacy)
    before = legacy.read_bytes()
    assert store.get_template_options('template') == {'option': 'legacy'}
    assert legacy.read_bytes() == before
    assert store.state_db_path().with_suffix('.migration.json').is_file()


def test_no_legacy_initializes_empty_state():
    assert load_submodule('state_store').list_projects() == []


def test_existing_destination_is_not_overwritten():
    store = load_submodule('state_store')
    store.record_template_option('template', 'option', 'current')
    legacy = Path(os.environ['HERMES_HOME']) / 'plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'legacy', db_path=legacy)
    assert store.get_template_options('template') == {'option': 'current'}


def test_corrupt_legacy_is_skipped_with_warning(caplog):
    store = load_submodule('state_store')
    legacy = Path(os.environ['HERMES_HOME']) / 'plugins/defuzz/state.db'
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b'not sqlite')
    assert store.list_projects() == []
    assert 'Skipping legacy state' in caplog.text
    assert legacy.read_bytes() == b'not sqlite'


def test_defuzz_migration_is_idempotent():
    store = load_submodule('state_store')
    legacy = Path(os.environ['HERMES_HOME']) / 'plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'original', db_path=legacy)
    assert store.get_template_options('template') == {'option': 'original'}
    store.record_template_option('template', 'option', 'changed', db_path=legacy)
    assert store.get_template_options('template') == {'option': 'original'}


def test_nested_named_profile_symlink_is_rejected(caplog):
    store = load_submodule('state_store')
    home = Path(os.environ['HERMES_HOME'])
    legacy = home / 'profiles/other/plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'other', db_path=legacy)
    before = legacy.read_bytes()
    (home / 'plugins').mkdir()
    (home / 'plugins/defuzz').symlink_to(legacy.parent, target_is_directory=True)

    target = store.state_db_path()

    assert not target.exists()
    assert not target.with_suffix('.migration.json').exists()
    assert legacy.read_bytes() == before
    assert 'Skipping legacy state' in caplog.text


@pytest.mark.parametrize('name', ['defuzz', 'adopt-place'])
def test_active_named_profile_migrates_own_legacy(name, monkeypatch):
    store = load_submodule('state_store')
    default_home = Path(os.environ['HERMES_HOME'])
    home = default_home / 'profiles/active'
    legacy = home / 'plugins' / name / 'state.db'
    store.record_template_option('template', 'option', 'own', db_path=legacy)
    other = default_home / 'profiles/other/plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'other', db_path=other)
    before = legacy.read_bytes()
    monkeypatch.setenv('HERMES_HOME', str(home))

    assert store.get_template_options('template') == {'option': 'own'}
    assert store.state_db_path() == home / 'plugin-data/defuzz/state.db'
    assert legacy.read_bytes() == before


@pytest.mark.parametrize('component', ['plugins', 'state.db'])
def test_symlinked_legacy_component_is_rejected(component, caplog):
    store = load_submodule('state_store')
    home = Path(os.environ['HERMES_HOME'])
    source = home / 'old-plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'linked', db_path=source)
    before = source.read_bytes()
    if component == 'plugins':
        (home / 'plugins').symlink_to(source.parent.parent, target_is_directory=True)
    else:
        legacy = home / 'plugins/defuzz/state.db'
        legacy.parent.mkdir(parents=True)
        legacy.symlink_to(source)

    target = store.state_db_path()

    assert not target.exists()
    assert not target.with_suffix('.migration.json').exists()
    assert source.read_bytes() == before
    assert 'Skipping legacy state' in caplog.text


def test_other_profile_is_not_imported(tmp_path, monkeypatch):
    store = load_submodule('state_store')
    legacy = tmp_path / 'other/plugins/defuzz/state.db'
    store.record_template_option('template', 'option', 'other', db_path=legacy)
    home = Path(os.environ['HERMES_HOME'])
    (home / 'plugins').mkdir()
    (home / 'plugins/defuzz').symlink_to(legacy.parent, target_is_directory=True)
    assert store.get_template_options('template') == {}

