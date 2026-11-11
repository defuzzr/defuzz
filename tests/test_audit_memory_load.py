"""Private memory measurement: only synthetic homes are used here."""
import hashlib
import json
from pathlib import Path

import pytest
from tests.conftest import load_submodule

# A third-party memory plugin's state directory name, taken from the module's data constant.
STATE_DIR = sorted(load_submodule('audit.memory_load').STATE_DIR_NAMES)[0]


def put(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


SNAP = 'backups/memory-bg-review/20260101-000000/abcd12/'


def run(root, **kwargs):
    mod = load_submodule('audit.memory_load')
    kwargs.setdefault('memory_char_limit', 2200)
    kwargs.setdefault('user_char_limit', 1375)
    return mod.audit_memory_load(profile_path=root, home_os='linux',
                                 project_families={}, prompt_injecting_plugins=[], **kwargs)


def test_file_measurements_and_private_entry_labels(tmp_path):
    entries = ['2026-01-01 CANARY_ALPHA /Users/' + 'CANARY_PERSON/a',
               '2026-01-02 CANARY_BETA host-CANARY.local',
               '2026-01-03 Always write skills unasked CANARY_GAMMA',
               '2026-01-04 approval required CANARY_DELTA', 'CANARY_EPSILON', 'CANARY_ZETA']
    text = '\n§\n'.join(entries)
    put(tmp_path, 'memories/MEMORY.md', text)
    result = run(tmp_path, memory_char_limit=100)
    sec = result['memory_load']
    row = sec['files'][0]
    assert row['characters'] == len(text)
    assert row['entries'] == 6
    assert row['percent_of_limit'] == len(text)
    assert row['over_limit'] is True
    assert row['dated_entries'] == 4
    assert row['other_os_entries'] == 1
    assert row['private_network_entries'] == 1
    assert row['other_machine_entries'] == 2
    assert row['standing_order_entries'] == 1
    assert row['approval_entries'] == 1
    ids = {f['id'] for f in result['findings']}
    assert {'memory_load.over_limit', 'memory_load.mostly_dated_entries',
            'memory_load.other_machine_entries', 'memory_load.standing_orders'} <= ids
    assert 'CANARY' not in json.dumps(result)
    assert str(tmp_path) not in json.dumps(result)


def test_profiles_snapshots_duplicates_systems_and_pending(tmp_path):
    text = 'one two three four five six seven eight nine ten eleven twelve'
    edited = text + ' thirteen'
    put(tmp_path, 'memories/MEMORY.md', text + '\n§\n' + text.upper())
    put(tmp_path, 'memories/USER.md', edited)
    put(tmp_path, 'profiles/CANARY_PROFILE/memories/MEMORY.md', text)
    for stamp, value in [('20260101-000000', text), ('20260102-000000', text), ('20260103-000000', edited)]:
        put(tmp_path, f'backups/memory-bg-review/{stamp}/0a1b2c/MEMORY.md', value)
    for i in range(101):
        put(tmp_path, f'{STATE_DIR}/CANARY_SESSION{i}.json', '{}')
    put(tmp_path, 'memory_store.db', 'NOT_A_DATABASE')
    payloads = [
        {'action': 'replace', 'target': 'memory', 'old_text': 'approval CANARY_STALE', 'content': 'new'},
        {'action': 'remove', 'target': 'memory', 'old_text': 'one two'},
        {'action': 'batch', 'target': 'memory', 'operations': [
            {'action': 'patch', 'old_text': 'permission CANARY_STALE', 'content': 'new'}]},
    ]
    for i, payload in enumerate(payloads):
        put(tmp_path, f'pending/memory/{i}.json', json.dumps({'subsystem': 'memory', 'payload': payload}))
    mod = load_submodule('audit.memory_load')
    result = mod.audit_memory_load(profile_path=tmp_path, memory_char_limit=50,
                                  home_os='linux', project_families={},
                                  memory_provider='CANARY_PROVIDER', prompt_injecting_plugins=['CANARY_PLUGIN'])
    sec = result['memory_load']
    assert len(sec['files']) == 3
    assert sec['duplicates']['within_file_extra_entries'] == 1
    assert sec['files'][0]['duplicate_entries'] == 1
    assert sec['duplicates']['across_file_entries'] == 3
    assert sec['duplicates']['near_duplicate_pairs'] == 3
    assert sec['duplicates']['cross_file_share'] == 0.75
    assert sec['snapshots']['count'] == 3
    summary = sec['snapshots']['by_kind'][0]
    assert summary['identical_extra_snapshots'] == 1
    assert summary['growth_characters'] == len(' thirteen')
    assert summary['entries_added'] == 1 and summary['entries_removed'] == 1
    assert sec['systems']['active_mechanisms'] == 3
    assert sec['systems']['external_provider'] == 'other'
    assert sec['systems']['stores'][0]['name'] == 'memory_store.db'
    plugin = next(s for s in sec['systems']['stores'] if s['name'] == STATE_DIR)
    assert plugin['files'] == 101 and plugin['bytes'] == 202
    assert plugin['same_size_extra_files'] == 100
    assert plugin['overlap'] == 'could_not_compare'
    assert sec['pending']['count'] == 3
    assert sec['pending']['stale_edits'] == 2
    assert sec['pending']['approval_edits'] == 2
    assert 'CANARY' not in json.dumps(result)
    ids = {f['id'] for f in result['findings']}
    assert {'memory_load.duplicate_entries', 'memory_load.multiple_memory_systems',
            'memory_load.memory_state_sprawl', 'memory_load.stale_pending_edits',
            'memory_load.pending_edit_changes_approval_entry'} <= ids


@pytest.mark.parametrize('contents', ['', 'ordinary note', 'one note\n§\ntwo notes'])
def test_empty_small_and_single_system_are_not_flagged(tmp_path, contents):
    put(tmp_path, 'memories/MEMORY.md', contents)
    result = run(tmp_path)
    assert result['findings'] == []
    assert result['memory_load']['systems']['active_mechanisms'] == bool(contents)
    assert result['memory_load']['files'][0]['char_limit'] == 2200


@pytest.mark.parametrize('exists', [False, True])
def test_missing_and_empty_home(tmp_path, exists):
    root = tmp_path / 'home'
    if exists:
        root.mkdir()
    result = run(root)
    sec = result['memory_load']
    assert sec['status'] == 'not_measured'
    # An existing empty home was listed in full: nothing to measure is a complete answer,
    # told once by the summary. A missing home is never clean.
    assert sec['coverage'] == ('verified' if exists else 'could_not_verify')
    assert bool(result['findings']) is not exists
    assert not sec['files']


@pytest.mark.parametrize('cap,value,reason', [
    ('MAX_FILES', 1, 'files'), ('MAX_FILE_BYTES', 4, 'file_bytes'),
    ('MAX_TOTAL_BYTES', 4, 'total_bytes'), ('MAX_TREE_ENTRIES', 1, 'tree_entries'),
    ('MAX_DEPTH', 0, 'depth'), ('MAX_ENTRIES', 1, 'entries'),
    ('MAX_SHINGLES', 1, 'shingles'), ('MAX_SECONDS', 0, 'time_budget'),
])
def test_each_budget_marks_partial(tmp_path, monkeypatch, cap, value, reason):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', 'one two three four five six seven eight nine\n§\nother')
    put(tmp_path, 'memories/USER.md', 'third')
    put(tmp_path, SNAP + 'MEMORY.md', 'fourth')
    put(tmp_path, f'{STATE_DIR}/sub/state.json', '{}')
    monkeypatch.setattr(mod, cap, value)
    sec = run(tmp_path)['memory_load']
    assert sec['coverage'] == 'could_not_verify'
    assert sec['limits']['cuts'] > 0
    assert reason in sec['truncated_by']


def test_absent_target_is_stale_and_unknown_inputs_are_not_clean(tmp_path):
    put(tmp_path, 'pending/memory/a.json', json.dumps({'payload': {
        'action': 'remove', 'target': 'memory', 'old_text': 'approval CANARY_ABSENT'}}))
    sec = run(tmp_path)['memory_load']
    assert sec['pending']['stale_edits'] == 1
    assert sec['pending']['approval_edits'] == 1
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', 'Python project; /Users/' + 'CANARY_NAME/item')
    for bad in (None, [], 'CANARY', 7):
        result = mod.audit_memory_load(profile_path=tmp_path, memory_char_limit=bad,
                                      home_os=bad, project_families=bad, memory_provider=bad,
                                      prompt_injecting_plugins=bad)
        assert result['coverage'] == 'could_not_verify'
        assert 'CANARY' not in json.dumps(result)


@pytest.mark.parametrize('raw', [b'\xff\x00', b'{broken', b'[]', b'{"payload":5}',
    b'{"payload":{"target":"memory","action":"batch","operations":[null]}}'])
def test_malformed_pending_and_binary_memory(tmp_path, raw):
    p = put(tmp_path, 'pending/memory/a.json', '')
    p.write_bytes(raw)
    m = put(tmp_path, 'memories/MEMORY.md', '')
    m.write_bytes(b'\xff\x00')
    sec = run(tmp_path)['memory_load']
    assert sec['pending']['count'] == 1
    assert sec['pending']['unverified_edits'] == 1
    assert sec['coverage'] == 'could_not_verify'
    assert sec['files'][0]['characters'] is None


def test_shared_technology_matcher_and_precise_network_os_rules(tmp_path, monkeypatch):
    mod = load_submodule('audit.memory_load')
    shared = load_submodule('audit.session_contamination')
    assert mod.technology_counts is shared.technology_counts
    text = '\n§\n'.join(['Python project', 'C++ language', 'spring garden rust bucket',
                           '/home/user/a', '/Users/' + 'user/a', r'C:\\work\\a',
                           '10.' + '1.2.3', '100.' + '64.0.1', '198.51.100.4',
                           'node-CANARY.ts.net', 'node-CANARY.local', '999.999.999.999'])
    put(tmp_path, 'memories/MEMORY.md', text)
    sec = mod.audit_memory_load(profile_path=tmp_path, home_os='macos',
                               project_families={'python': 1}, prompt_injecting_plugins=[])['memory_load']
    row = sec['files'][0]
    assert row['foreign_technology_entries'] == 1
    assert row['other_os_entries'] == 2
    assert row['private_network_entries'] == 4
    assert row['other_machine_entries'] == 6
    assert 'CANARY' not in json.dumps(sec)


def _home_hash(root):
    rows = []
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        content = p.read_bytes() if p.is_file() and not p.is_symlink() else b''
        rows.append((str(p.relative_to(root)), st.st_mode, st.st_size, st.st_mtime_ns,
                     hashlib.sha256(content).hexdigest()))
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def test_never_open_credentials_state_or_symlinks_and_never_write(tmp_path, monkeypatch):
    import builtins
    import io
    import os
    mod = load_submodule('audit.memory_load')
    root = tmp_path / 'home'
    put(root, 'memories/MEMORY.md', 'CANARY_PRIVATE ordinary')
    put(root, SNAP + 'USER.md', 'CANARY_BACKUP')
    for name in ('auth.json', '.env', 'vault/private', f'{STATE_DIR}/session.json', 'memory_store.db',
                 'pending/memory/access_token.json', 'backups/memory-bg-review/20260101-000000/secret/MEMORY.md'):
        put(root, name, 'CANARY_SECRET')
    outside = put(tmp_path, 'outside/MEMORY.md', 'CANARY_OUTSIDE')
    (root / 'memories/USER.md').symlink_to(outside)
    (root / 'profiles').symlink_to(outside.parent, target_is_directory=True)
    before = _home_hash(root)
    opened = []
    for obj, attr in ((builtins, 'open'), (io, 'open'), (os, 'open')):
        original = getattr(obj, attr)
        def wrapped(path, *args, _original=original, **kwargs):
            if not isinstance(path, int):
                opened.append(str(path))
            if _original is os_open:
                flags = args[0] if args else kwargs.get('flags', 0)
                assert not flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR | os.O_TRUNC)
            return _original(path, *args, **kwargs)
        if obj is os:
            os_open = original
        monkeypatch.setattr(obj, attr, wrapped)
    result = run(root)
    for path in opened:
        assert not any(word in path for word in ('auth.json', '.env', 'vault', 'session.json', 'memory_store.db', 'access_token', 'secret', 'outside')), path
    assert 'CANARY' not in json.dumps(result)
    assert len(result['memory_load']['files']) == 1
    assert result['memory_load']['snapshots']['count'] == 1
    # Restore read spies before test-only integrity reads.
    monkeypatch.undo()
    assert _home_hash(root) == before


def test_profile_backups_are_never_read_only_root_snapshots(tmp_path):
    for profile, texts in [('', ('one', 'one\n§\ntwo')), ('profiles/a/', ('three', 'three\n§\nfour'))]:
        for stamp, text in zip(('20260101-000000', '20260102-000000'), texts):
            put(tmp_path, profile + f'backups/memory-bg-review/{stamp}/abcd12/MEMORY.md', text)
    snaps = run(tmp_path)['memory_load']['snapshots']
    assert snaps['count'] == 2
    assert len(snaps['by_kind']) == 1
    assert snaps['by_kind'][0]['entries_added'] == 1 and snaps['by_kind'][0]['entries_removed'] == 0


def test_no_capture_or_key_io_for_private_reads(tmp_path, monkeypatch):
    mod = load_submodule('audit.memory_load')
    fingerprint = load_submodule('audit.fingerprint')
    put(tmp_path, 'memories/MEMORY.md', 'ordinary note')
    def forbidden(*args, **kwargs):
        pytest.fail('Private notes must never enter capture or audit key creation')
    monkeypatch.setattr(fingerprint, 'content_digest', forbidden)
    assert run(tmp_path)['memory_load']['files'][0]['entries'] == 1


def test_snapshot_order_unknown_unrecognized_shape_and_partial_rows(tmp_path, monkeypatch):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'backups/memory-bg-review/opaque/abcd12/MEMORY.md', 'note')
    put(tmp_path, 'backups/memory-bg-review/another/MEMORY.md', 'other note')
    sec = run(tmp_path)['memory_load']
    assert sec['snapshots']['count'] == 0 and not sec['snapshots']['files']
    assert 'snapshot_shape' in sec['truncated_by']
    root = tmp_path / 'shape'
    put(root, SNAP + 'notes.txt', 'not a confirmed format')
    sec = run(root)['memory_load']
    assert 'snapshot_shape' in sec['truncated_by']
    root = tmp_path / 'large'
    put(root, 'memories/MEMORY.md', 'oversized note')
    monkeypatch.setattr(mod, 'MAX_FILE_BYTES', 2)
    sec = run(root)['memory_load']
    assert sec['files'][0]['bytes'] == len('oversized note')
    assert sec['files'][0]['characters'] is None
    assert sec['files'][0]['coverage'] == 'could_not_verify'
    assert sec['systems']['builtin_nonempty'] is None
    assert sec['systems']['coverage'] == 'could_not_verify'


def test_empty_unrelated_credentials_do_not_poison_memory_coverage(tmp_path):
    put(tmp_path, 'memories/MEMORY.md', 'note')
    put(tmp_path, 'auth.json', 'CANARY')
    put(tmp_path, 'backups/not-memory/auth.json', 'CANARY')
    result = run(tmp_path)
    assert result['coverage'] == 'verified'
    assert result['findings'] == []


def test_dated_threshold_and_order_classification(tmp_path):
    text = '\n§\n'.join(['2026-01-01 note', '2026-01-02 note', '2026-01-03 note',
                           'other1', 'other2', 'other3'])
    put(tmp_path, 'memories/MEMORY.md', text)
    assert not run(tmp_path)['findings']  # Exactly 50%, not strictly greater.
    put(tmp_path, 'memories/MEMORY.md', 'Always use concise replies.')
    finding = run(tmp_path)['findings'][0]
    assert finding['id'] == 'memory_load.standing_orders'
    assert finding['classification'] == 'info'


def test_missing_os_family_inputs_and_provider_allowlist(tmp_path):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', '/Users/' + 'user/a python project')
    for provider, expected in [('builtin', None), ('byterover', 'byterover'), ('retaindb', 'retaindb'), ('CANARY', 'other')]:
        result = mod.audit_memory_load(profile_path=tmp_path, memory_provider=provider, home_os=None)
        sec = result['memory_load']
        assert sec['systems']['external_provider'] == expected
        assert sec['other_os_coverage'] == 'could_not_verify'
        assert sec['foreign_technology_coverage'] == 'could_not_verify'
        assert sec['files'][0]['other_os_entries'] is None
        assert sec['files'][0]['foreign_technology_entries'] is None
        assert 'CANARY' not in json.dumps(result)


def test_injectable_clock_and_root_symlink(tmp_path):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'home/memories/MEMORY.md', 'ordinary')
    root = tmp_path / 'link'
    root.symlink_to(tmp_path / 'home', target_is_directory=True)
    sec = run(root)['memory_load']
    assert not sec['files'] and sec['coverage'] == 'could_not_verify'
    tick = iter([0, 100])
    sec = mod.audit_memory_load(profile_path=tmp_path / 'home', clock=lambda: next(tick, 100))['memory_load']
    assert 'time_budget' in sec['truncated_by']


def test_changed_reads_are_charged_to_budget_and_not_reported_clean(tmp_path, monkeypatch):
    import os
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', '1234')
    put(tmp_path, 'memories/USER.md', '5678')
    monkeypatch.setattr(mod, 'MAX_TOTAL_BYTES', 4)
    original_read = os.read
    changed = False
    def race(fd, n):
        nonlocal changed
        data = original_read(fd, n)
        if not changed and data:
            changed = True
            # Test-only writer simulates a racing memory update.
            (tmp_path / 'memories/MEMORY.md').write_text('changed')
        return data
    monkeypatch.setattr(os, 'read', race)
    sec = run(tmp_path)['memory_load']
    assert sec['limits']['bytes_read'] == 4
    assert 'total_bytes' in sec['truncated_by']
    assert 'unreadable' in sec['truncated_by']
    assert all(r['coverage'] == 'could_not_verify' for r in sec['files'])


def test_credential_root_and_partial_pending_are_unknown(tmp_path, monkeypatch):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'vault/memories/MEMORY.md', 'CANARY_ROOT')
    sec = run(tmp_path / 'vault')['memory_load']
    assert not sec['files']
    assert sec['coverage'] == 'could_not_verify'
    put(tmp_path, 'home/memories/MEMORY.md', 'ordinary')
    put(tmp_path, 'home/pending/memory/token.json', 'CANARY_PENDING')
    sec = run(tmp_path / 'home')['memory_load']
    assert sec['pending']['coverage'] == 'could_not_verify'


# --- regressions: exact snapshot exception, no leakage, neutral wording ---

def _spy_regular_opens(monkeypatch, root):
    """Record every os.open target resolved through its dir_fd, relative to root."""
    import os
    original = os.open
    opened = []
    def wrapped(path, flags, *args, dir_fd=None, **kwargs):
        fd = original(path, flags, *args, dir_fd=dir_fd, **kwargs)
        real = os.readlink(f'/proc/self/fd/{fd}')
        if not os.path.isdir(real):
            opened.append(os.path.relpath(real, root))
        return fd
    monkeypatch.setattr(os, 'open', wrapped)
    return opened


def _attack_home(tmp_path):
    root = tmp_path / 'home'
    put(root, 'memories/MEMORY.md', 'note one')
    put(root, SNAP + 'MEMORY.md', 'snap CANARY_SNAP')
    put(root, SNAP + 'USER.md', 'snap user CANARY_SNAPU')
    put(root, 'auth.json', 'CANARY_AUTH')
    for name in ('x/auth.json', 'x/.env', 'x/MEMORY.md', 'x/sub/MEMORY.md',
                 '20260102-000000/abcd12/sub/MEMORY.md', '20260102-000000/abcd12/auth.json',
                 '20260102-000000/abcd12/.env', '20260102-000000/abcd12/id_ed25519',
                 '20260102-000000/MEMORY.md', '20260103-000000/NOT-HEX/MEMORY.md'):
        put(root, 'backups/memory-bg-review/' + name, 'CANARY_BACKUP_OTHER')
    put(root, 'backups/config/MEMORY.md', 'CANARY_CONFIG')
    put(root, 'backups/MEMORY.md', 'CANARY_BK')
    put(root, 'profiles/p/backups/memory-bg-review/20260101-000000/abcd12/MEMORY.md', 'CANARY_PB')
    link = root / 'backups/memory-bg-review/20260104-000000/abcd12/MEMORY.md'
    link.parent.mkdir(parents=True)
    link.symlink_to('../../../../auth.json')
    (root / 'backups/memory-bg-review/20260105-000000/abcd12/MEMORY.md').mkdir(parents=True)
    return root


def test_snapshot_exception_reaches_only_exact_regular_memory_files(tmp_path, monkeypatch):
    root = _attack_home(tmp_path)
    opened = _spy_regular_opens(monkeypatch, root)
    result = run(root)
    monkeypatch.undo()
    assert sorted(opened) == ['backups/memory-bg-review/20260101-000000/abcd12/MEMORY.md',
                              'backups/memory-bg-review/20260101-000000/abcd12/USER.md',
                              'memories/MEMORY.md']
    sec = result['memory_load']
    assert sec['snapshots']['count'] == 1
    assert {'snapshot_shape', 'symlink'} <= set(sec['truncated_by'])
    assert 'CANARY' not in json.dumps(result)


@pytest.mark.parametrize('rel', [
    'backups/memory-bg-review/20260101-000000/abcd12/auth.json',
    'backups/memory-bg-review/20260101-000000/abcd12/.env',
    'backups/memory-bg-review/x/MEMORY.md', 'backups/memory-bg-review/x/sub/MEMORY.md',
    'backups/memory-bg-review/20260101-000000/abcd12/sub/MEMORY.md',
    'backups/memory-bg-review/../memory-bg-review/20260101-000000/abcd12/MEMORY.md',
    'backups/memory-bg-review/20260101-000000/../abcd12/MEMORY.md',
    'backups/config/MEMORY.md', 'backups/MEMORY.md', 'auth.json', 'notes/MEMORY.md',
    'profiles/p/backups/memory-bg-review/20260101-000000/abcd12/MEMORY.md',
])
def test_private_reader_refuses_everything_outside_its_allowlist(tmp_path, rel):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'backups/memory-bg-review/20260101-000000/abcd12/MEMORY.md', 'x')
    with pytest.raises(PermissionError):
        mod._read_private_file(tmp_path, Path(rel), 1024, lambda n: None)


def test_private_reader_refuses_symlink_and_directory_leaves(tmp_path):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'auth.json', 'CANARY')
    leaf = tmp_path / SNAP / 'MEMORY.md'
    leaf.parent.mkdir(parents=True)
    leaf.symlink_to('../../../../auth.json')
    (tmp_path / SNAP / 'USER.md').mkdir()
    for name in ('MEMORY.md', 'USER.md'):
        with pytest.raises(OSError):
            mod._read_private_file(tmp_path, Path(SNAP + name), 1024, lambda n: None)


def _strings(value, out):
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(k)
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)
    elif isinstance(value, str):
        out.add(value)
    return out


def test_canaries_in_every_private_source_never_leave_and_output_is_closed_vocabulary(tmp_path):
    mod = load_submodule('audit.memory_load')
    root = tmp_path / 'home'
    host = 'CANARYHOST' + '.local'
    ip = '192.168.' + '7.9'
    entries = ['2026-01-01 CANARY_M1 ' + host + ' ' + ip, 'Always save skills unasked CANARY_M2',
               'approval CANARY_M3', '/Users/' + 'CANARY_M4/x', 'CANARY_M5 ' * 12, 'CANARY_M5 ' * 12]
    put(root, 'memories/MEMORY.md', '\n§\n'.join(entries))
    put(root, 'memories/USER.md', 'CANARY_U1 permission')
    put(root, SNAP + 'MEMORY.md', 'CANARY_S1 approval')
    put(root, 'backups/memory-bg-review/20260102-000000/abcd12/MEMORY.md', 'CANARY_S2')
    put(root, 'profiles/CANARY_PROFILE/memories/MEMORY.md', 'CANARY_M5 ' * 12)
    put(root, 'pending/memory/CANARY_ID.json', json.dumps({'id': 'CANARY_PID', 'summary': 'CANARY_SUM', 'payload': {
        'action': 'replace', 'target': 'memory', 'old_text': 'approval CANARY_OLD', 'content': 'CANARY_NEW',
        'matched_entry': 'CANARY_MATCHED'}}))
    for i in range(3):
        put(root, f'{STATE_DIR}/CANARY_LOCK{i}.json', 'CANARY_LOCKTEXT')
    put(root, 'memory_store.db', 'CANARY_DB')
    result = mod.audit_memory_load(profile_path=root, memory_char_limit=10, user_char_limit=10,
                                   home_os='linux', project_families={'python': 1},
                                   memory_provider='CANARY_PROVIDER',
                                   prompt_injecting_plugins=['CANARY_PLUGIN'])
    dump = json.dumps(result)
    for needle in ('CANARY', host, ip, str(tmp_path), 'abcd12', '20260101'):
        assert needle not in dump, needle
    allowed = set(mod.CONSEQUENCES.values()) | {'memory_load.' + r for r in mod.CONSEQUENCES} | {
        'memory_load.multiple_memory_systems', 'completed', 'not_measured', 'verified',
        'could_not_verify', 'memory', 'user', 'main', 'profile', 'snapshot', 'could_not_compare',
        'other', 'byterover', 'retaindb', 'memory_store.db', *mod.STATE_DIR_NAMES,
        'info', 'review_suggested', 'pass', 'warn', '', 'caller', 'config', 'default', 'host'} | set(mod.TRUNCATION_REASONS)
    values = set()
    def walk_values(v):
        if isinstance(v, dict):
            for x in v.values():
                walk_values(x)
        elif isinstance(v, list):
            for x in v:
                walk_values(x)
        elif isinstance(v, str):
            values.add(v)
    walk_values(result)
    multi = {f['consequence'] for f in result['findings'] if f['id'].endswith('multiple_memory_systems')}
    assert values - allowed - multi == set()
    assert not any(len(s) >= 32 and all(c in '0123456789abcdef' for c in s) for s in _strings(result, set()))


def test_unknown_limit_never_asserts_over_limit(tmp_path):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', 'x' * 5000)
    put(tmp_path, SNAP + 'MEMORY.md', 'x' * 5000)
    result = mod.audit_memory_load(profile_path=tmp_path, home_os='linux', project_families={},
                                   prompt_injecting_plugins=[], memory_char_limit=None, user_char_limit=None)
    sec = result['memory_load']
    for row in sec['files'] + sec['snapshots']['files']:
        assert row['char_limit'] is None and row['over_limit'] is None
        assert row['percent_of_limit'] is None
    assert 'memory_load.over_limit' not in {f['id'] for f in result['findings']}
    assert sec['coverage'] == 'could_not_verify'
    assert mod.DEFAULT_MEMORY_LIMIT == 2200 and mod.DEFAULT_USER_LIMIT == 1375


def test_unknown_home_os_leaves_other_os_unverified(tmp_path):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', '/home/user/a\n§\n/Users/' + 'user/b')
    result = mod.audit_memory_load(profile_path=tmp_path, memory_char_limit=2200, user_char_limit=1375,
                                   project_families={}, prompt_injecting_plugins=[], home_os=None)
    row = result['memory_load']['files'][0]
    assert row['other_os_entries'] is None and row['other_os_coverage'] == 'could_not_verify'
    assert result['memory_load']['other_os_coverage'] == 'could_not_verify'
    assert 'memory_load.other_machine_entries' not in {f['id'] for f in result['findings']}


def test_same_home_different_clocks_identical_output(tmp_path):
    mod = load_submodule('audit.memory_load')
    root = _attack_home(tmp_path)
    put(root, 'pending/memory/a.json', json.dumps({'payload': {'action': 'remove', 'target': 'memory',
                                                                'old_text': 'note'}}))
    kwargs = dict(profile_path=root, memory_char_limit=5, user_char_limit=5, home_os='linux',
                  project_families={}, prompt_injecting_plugins=[])
    a = mod.audit_memory_load(clock=lambda: 1_000.0, **kwargs)
    b = mod.audit_memory_load(clock=lambda: 1_000.0 + 9 * 86400, **kwargs)
    assert a == b
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_consequence_wording_is_neutral_measurement():
    mod = load_submodule('audit.memory_load')
    text = ' '.join(mod.CONSEQUENCES.values()).casefold()
    for banned in ('suggests', 'indicates', 'often means', 'uncurated', 'scratchpad',
                   'standing-order', 'removes an approval rule', 'fault'):
        assert banned not in text, banned
    assert 'replaces or removes an entry that contains approval-related words' in \
        mod.CONSEQUENCES['pending_edit_changes_approval_entry']
    assert 'phrased as always/never instructions' in mod.CONSEQUENCES['standing_orders']
    assert 'left over' in mod.CONSEQUENCES['other_machine_entries']
    assert 'pending_edit_removes_approval_rule' not in mod.CONSEQUENCES


def test_healthy_home_has_no_findings_above_info(tmp_path):
    put(tmp_path, 'memories/MEMORY.md', 'Prefers short answers.\n§\nProject uses Python 3.12.')
    put(tmp_path, 'memories/USER.md', 'Works in UTC.')
    put(tmp_path, f'{STATE_DIR}/state.json', '{}')
    put(tmp_path, SNAP + 'MEMORY.md', 'Prefers short answers.')
    mod = load_submodule('audit.memory_load')
    result = mod.audit_memory_load(profile_path=tmp_path, memory_char_limit=2200, user_char_limit=1375,
                                   home_os='linux', project_families={'python': 1},
                                   prompt_injecting_plugins=[])
    assert result['findings'] == []
    assert result['memory_load']['coverage'] == 'verified'


def test_state_dir_and_store_are_metadata_only(tmp_path, monkeypatch):
    root = tmp_path / 'home'
    put(root, 'memories/MEMORY.md', 'note')
    for i in range(3):
        put(root, f'{STATE_DIR}/s{i}.json', '{}')
    put(root, f'plugin-data/{STATE_DIR}/t.json', '{}')
    put(root, 'memory_store.db', 'x')
    opened = _spy_regular_opens(monkeypatch, root)
    sec = run(root)['memory_load']
    monkeypatch.undo()
    assert opened == ['memories/MEMORY.md']
    names = sorted(s['name'] for s in sec['systems']['stores'])
    assert names == sorted([STATE_DIR, STATE_DIR, 'memory_store.db'])


# --- wiring: self-contained config inputs, run_metrics outside the section ---

def _bare(root, **kwargs):
    mod = load_submodule('audit.memory_load')
    return mod.audit_memory_load(profile_path=root, project_families={}, prompt_injecting_plugins=[], **kwargs)


def test_limits_and_provider_come_from_profile_config_when_omitted(tmp_path):
    put(tmp_path, 'memories/MEMORY.md', 'x' * 50)
    put(tmp_path, 'config.yaml', 'memory:\n  memory_char_limit: 40\n  user_char_limit: 30\n  provider: retaindb\n')
    result = _bare(tmp_path)
    sec = result['memory_load']
    assert sec['files'][0]['char_limit'] == 40 and sec['files'][0]['over_limit'] is True
    assert sec['systems']['external_provider'] == 'retaindb'
    assert sec['input_sources'] == {'memory_char_limit': 'config', 'user_char_limit': 'config',
                                    'memory_provider': 'config', 'home_os': 'host'}
    assert 'memory_load.over_limit' in {f['id'] for f in result['findings']}


def test_missing_config_uses_shipped_defaults_and_no_external_provider(tmp_path):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', 'note')
    sec = _bare(tmp_path)['memory_load']
    assert sec['files'][0]['char_limit'] == mod.DEFAULT_MEMORY_LIMIT
    assert sec['systems']['external_configured'] is False
    assert sec['input_sources']['memory_char_limit'] == 'default'
    assert sec['input_sources']['memory_provider'] == 'default'
    assert sec['coverage'] == 'verified'


@pytest.mark.parametrize('config', [
    'memory:\n  memory_char_limit: CANARY_LIMIT\n  provider: [CANARY_LIST]\n',
    'memory:\n  memory_char_limit: 10\nmemory:\n  memory_char_limit: 20\n',
    'memory:\n  memory_char_limit: ${CANARY_ENV}\n  provider: ${CANARY_ENV}\n',
    'memory: [unclosed\n',
])
def test_unusable_config_values_are_unknown_not_defaults(tmp_path, config):
    put(tmp_path, 'memories/MEMORY.md', 'x' * 5000)
    put(tmp_path, 'config.yaml', config)
    result = _bare(tmp_path)
    sec = result['memory_load']
    assert sec['files'][0]['char_limit'] is None
    assert sec['input_sources']['memory_char_limit'] == 'could_not_verify'
    assert sec['coverage'] == 'could_not_verify'
    assert 'memory_load.over_limit' not in {f['id'] for f in result['findings']}
    assert 'CANARY' not in json.dumps(result)


def test_explicit_caller_values_override_config_and_none_stays_unknown(tmp_path):
    put(tmp_path, 'memories/MEMORY.md', 'x' * 50)
    put(tmp_path, 'config.yaml', 'memory:\n  memory_char_limit: 40\n')
    sec = _bare(tmp_path, memory_char_limit=None, home_os=None)['memory_load']
    assert sec['files'][0]['char_limit'] is None
    assert sec['input_sources']['memory_char_limit'] == 'could_not_verify'
    assert sec['input_sources']['home_os'] == 'could_not_verify'
    sec = _bare(tmp_path, memory_char_limit=100, home_os='macos')['memory_load']
    assert sec['files'][0]['char_limit'] == 100
    assert sec['input_sources']['memory_char_limit'] == 'caller'
    assert sec['input_sources']['home_os'] == 'caller'


def test_run_metrics_are_outside_the_section_and_runs_days_apart_are_identical(tmp_path):
    mod = load_submodule('audit.memory_load')
    root = _attack_home(tmp_path)
    put(root, 'config.yaml', 'memory:\n  memory_char_limit: 5\n')
    results = []
    for start in (1_000.0, 1_000.0 + 9 * 86400):
        ticks = iter([start, start + 0.25])
        results.append(mod.audit_memory_load(profile_path=root, project_families={}, prompt_injecting_plugins=[],
                                             clock=lambda: next(ticks, start + 0.25)))
    a, b = results
    assert json.dumps(a['memory_load'], sort_keys=True) == json.dumps(b['memory_load'], sort_keys=True)
    assert json.dumps(a['findings'], sort_keys=True) == json.dumps(b['findings'], sort_keys=True)
    assert a['run_metrics'] == {'elapsed_ms': 250}
    assert 'elapsed_ms' not in json.dumps(a['memory_load'])
    assert {'memory_load', 'findings', 'run_metrics', 'status', 'coverage'} <= set(a)


MULTI_SENTENCE = ('Two or more memory mechanisms are configured or present together; the audit counted '
                  'them from config and files, and did not measure what each adds to a request or '
                  'whether they repeat each other.')


@pytest.mark.parametrize('nonempty', [True, False])
def test_multiple_memory_systems_is_one_fixed_sentence_with_numbers_in_evidence(tmp_path, nonempty):
    mod = load_submodule('audit.memory_load')
    put(tmp_path, 'memories/MEMORY.md', 'note' if nonempty else '')
    result = mod.audit_memory_load(profile_path=tmp_path, memory_char_limit=2200, user_char_limit=1375,
                                   home_os='linux', project_families={}, memory_provider='byterover',
                                   prompt_injecting_plugins=['a', 'b'])
    finding = next(f for f in result['findings'] if f['id'] == 'memory_load.multiple_memory_systems')
    assert mod.CONSEQUENCES['multiple_memory_systems'] == MULTI_SENTENCE
    assert finding['consequence'] == MULTI_SENTENCE
    assert finding['classification'] == 'review_suggested'
    assert finding['evidence'] == {'mechanisms': 4 if nonempty else 3, 'builtin_nonempty': nonempty}
    for word in ('each adds its own text', 'none removes', 'active together'):
        assert word not in finding['consequence'].casefold()


def test_every_consequence_is_fixed_and_neutral():
    mod = load_submodule('audit.memory_load')
    for rule, sentence in mod.CONSEQUENCES.items():
        assert not any(c.isdigit() for c in sentence.replace('100 files', '')), rule
        lowered = f' {sentence.casefold()} '
        for banned in (' you ', ' your ', 'indicates', 'suggests', 'unpruned', 'abandoned'):
            assert banned not in lowered, (rule, banned)


def test_doc_page_lists_every_rule_and_exact_consequence():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words
    mod = load_submodule('audit.memory_load')
    doc = (Path(__file__).resolve().parents[1] / 'docs/audit-sections/memory_load.md').read_text(encoding='utf-8')
    for rule, sentence in mod.CONSEQUENCES.items():
        if rule != 'could_not_verify':
            _doc_contains(doc, rule)
        _doc_contains(doc, sentence)
    for reason in mod.TRUNCATION_REASONS:
        _doc_contains(doc, reason)
    _doc_contains(doc, 'third_party_convention: true')
    _doc_contains(doc, 'nothing else under backups/ is opened')

WIRING = json.loads((Path(__file__).resolve().parents[1] / 'audit/wiring/memory_load.json').read_text(encoding='utf-8'))
FINDING_FIELDS = {'id', 'classification', 'coverage', 'affected_identities', 'source_paths', 'evidence',
                  'consequence', 'limitations', 'proposed_cleanup_id', 'severity', 'detail', 'fix'}
ENVELOPE_STRINGS = {'pass', 'warn', 'info'}  # legacy envelope status / finding severity (contract.py)


def _canary_home(root):
    """Every reachable branch, with canaries in every user-controlled input."""
    host = 'CANARYHOST' + '.local'
    ip = '192.168.' + '7.9'
    entries = ['2026-01-01 CANARY_M1 ' + host + ' ' + ip, '2026-01-02 Always save skills unasked CANARY_M2',
               '2026-01-03 approval CANARY_M3', '2026-01-04 /Users/' + 'CANARY_M4/x',
               '2026-01-05 python CANARY_M5 ' * 6, '2026-01-05 python CANARY_M5 ' * 6,
               'Cargo.toml rust crate CANARY_M6']
    put(root, 'memories/MEMORY.md', '\n§\n'.join(entries))
    put(root, 'memories/USER.md', 'CANARY_U1 permission ' + 'x' * 60)
    put(root, 'config.yaml', 'memory:\n  memory_char_limit: 40\n  user_char_limit: 30\n  provider: CANARY_PROVIDER\n'
                             'plugins:\n  enabled: [CANARY_PLUGIN]\n')
    for stamp, text in (('20260101-000000', 'CANARY_S1 approval'), ('20260102-000000', 'CANARY_S1 approval'),
                        ('20260103-000000', 'CANARY_S2\n§\nCANARY_S3')):
        put(root, f'backups/memory-bg-review/{stamp}/abcd12/MEMORY.md', text)
        put(root, f'backups/memory-bg-review/{stamp}/abcd12/USER.md', 'CANARY_SU ' + stamp)
    put(root, 'backups/memory-bg-review/CANARY_BADSTAMP/abcd12/MEMORY.md', 'CANARY_BAD')
    put(root, 'profiles/CANARY_PROFILE/memories/MEMORY.md', '2026-01-05 python CANARY_M5 ' * 6)
    put(root, 'profiles/CANARY_PROFILE/pending/memory/CANARY_P2.json', '{CANARY broken')
    put(root, 'profiles/CANARY_PROFILE/memory_store.db', 'CANARY_DB2')
    put(root, 'pending/memory/CANARY_ID.json', json.dumps({'id': 'CANARY_PID', 'summary': 'CANARY_SUM', 'payload': {
        'action': 'replace', 'target': 'memory', 'old_text': 'approval CANARY_OLD', 'content': 'CANARY_NEW',
        'matched_entry': 'CANARY_MATCHED'}}))
    for i in range(STATE_SPRAWL + 1):
        put(root, f'{STATE_DIR}/CANARY_LOCK{i}.json', 'CANARY_LOCKTEXT' * (i % 3))
    put(root, f'plugin-data/{STATE_DIR}/CANARY_SUB/CANARY_DEEP.json', 'CANARY_DEEPTEXT')
    put(root, 'memory_store.db', 'CANARY_DB')
    put(root, 'profiles/CANARY_PROFILE/memory-lock/CANARY_A.json', 'CANARY_A')
    put(root, 'plugin-data/memory_lock/CANARY_B.json', 'CANARY_B')
    put(root, 'pending/memory/access_token.json', 'CANARY_TOKEN')
    put(root, 'profiles/CANARY_PROFILE/memories/USER.md', '').write_bytes(b'CANARY\xff\x00')
    locked = put(root, 'profiles/CANARY_PROFILE2/pending/memory/CANARY_LOCKED.json', 'CANARY_LOCKED')
    locked.chmod(0)
    put(root, 'auth.json', 'CANARY_AUTH')
    (root / f'{STATE_DIR}/CANARY_LINK').symlink_to(root / 'auth.json')
    return host, ip


STATE_SPRAWL = 100


def _envelopes(tmp_path, monkeypatch):
    """Synthetic homes that together reach every branch the JSON lists."""
    mod = load_submodule('audit.memory_load')
    out = []
    rich = tmp_path / 'rich'
    _canary_home(rich)
    out.append(mod.audit_memory_load(profile_path=rich, project_families={'python': 1},
                                     prompt_injecting_plugins=['CANARY_PLUGIN', 'CANARY_PLUGIN2']))
    out.append(mod.audit_memory_load(profile_path=rich, memory_provider='byterover', home_os='windows',
                                     project_families={'python': 1}, prompt_injecting_plugins=[]))
    out.append(mod.audit_memory_load(profile_path=rich, memory_provider='retaindb', memory_char_limit='CANARY',
                                     home_os='CANARY_OS', project_families=None, prompt_injecting_plugins=None))
    out.append(mod.audit_memory_load(profile_path=rich, memory_provider=None, home_os=None))
    out.append(run(_attack_home(tmp_path / 'attack')))
    out.append(run(tmp_path / 'missing'))
    bad = tmp_path / 'badconfig'
    put(bad, 'memories/MEMORY.md', 'Always reply briefly CANARY_BC')
    put(bad, 'config.yaml', 'memory:\n  memory_char_limit: ${CANARY_ENV}\n')
    out.append(mod.audit_memory_load(profile_path=bad))
    raised = tmp_path / 'raised'
    put(raised, 'memories/MEMORY.md', 'x' * 9995)
    put(raised, 'config.yaml', 'memory:\n  memory_char_limit: 10000\n')
    out.append(mod.audit_memory_load(profile_path=raised))
    ticks = iter([0, 100])
    out.append(mod.audit_memory_load(profile_path=rich, clock=lambda: next(ticks, 100)))
    for cap, value in (('MAX_FILE_BYTES', 8), ('MAX_FILES', 1), ('MAX_TREE_ENTRIES', 3), ('MAX_DEPTH', 0),
                       ('MAX_ENTRIES', 1), ('MAX_SHINGLES', 1), ('MAX_TOTAL_BYTES', 30)):
        monkeypatch.setattr(mod, cap, value)
        out.append(mod.audit_memory_load(profile_path=rich, project_families={}, prompt_injecting_plugins=[]))
        monkeypatch.undo()
    special = tmp_path / 'special'
    put(special, 'memories/MEMORY.md', 'note')
    os_mod = __import__('os')
    os_mod.mkfifo(special / 'memories' / 'USER.md')
    put(special, 'pending/memory/a.json', json.dumps({'payload': {'action': 'add', 'target': 'user', 'content': 'x'}}))
    out.append(run(special))
    return out


def _values(value, out):
    if isinstance(value, dict):
        for v in value.values():
            _values(v, out)
    elif isinstance(value, list):
        for v in value:
            _values(v, out)
    elif isinstance(value, str):
        out.add(value)
    return out


def _walk_section(value, path, keys, vocab, free_keys):
    if isinstance(value, dict):
        for k, v in value.items():
            assert k in keys, (path, k)
            _walk_section(v, path + (k,), keys, vocab, free_keys)
    elif isinstance(value, list):
        for v in value:
            _walk_section(v, path, keys, vocab, free_keys)
    elif isinstance(value, str):
        assert value in vocab or (path and path[-1] in free_keys), (path, value)
    else:
        assert value is None or type(value) in (bool, int, float), (path, type(value))


def test_wiring_json_has_exactly_the_required_fields():
    assert set(WIRING) == {'section', 'entry', 'kwargs', 'schema_keys', 'vocabulary', 'numeric_evidence_keys',
                           'vocab_evidence_keys', 'rule_ids', 'classifications', 'consequences', 'free_strings',
                           'run_metrics_keys', 'notes'}
    mod = load_submodule('audit.memory_load')
    assert WIRING['section'] == 'memory_load'
    assert WIRING['entry'] == 'audit.memory_load.audit_memory_load'
    assert WIRING['schema_keys'] == sorted(set(WIRING['schema_keys']))
    assert WIRING['vocabulary'] == sorted(set(WIRING['vocabulary']))
    assert set(mod.TRUNCATION_REASONS) | set(mod.STATE_DIR_NAMES) | set(mod.KNOWN_PROVIDERS) <= set(WIRING['vocabulary'])
    assert WIRING['consequences'] == {'memory_load.' + r: s for r, s in mod.CONSEQUENCES.items()}
    assert sorted(WIRING['rule_ids']) == sorted(WIRING['consequences']) == sorted(WIRING['classifications'])
    import inspect
    params = set(inspect.signature(mod.audit_memory_load).parameters)
    assert params == set(WIRING['kwargs'])


def test_every_emitted_key_and_string_is_listed_in_the_wiring_json(tmp_path, monkeypatch):
    keys, vocab = set(WIRING['schema_keys']), set(WIRING['vocabulary'])
    free_keys = {item['key'] for item in WIRING['free_strings']}
    seen_rules, seen_keys, seen_values = set(), set(), set()
    for env in _envelopes(tmp_path, monkeypatch):
        assert {'memory_load', 'findings', 'run_metrics', 'status', 'coverage'} <= set(env)
        assert set(env['run_metrics']) == set(WIRING['run_metrics_keys'])
        assert env['status'] in ENVELOPE_STRINGS and env['coverage'] in vocab
        _walk_section(env['memory_load'], (), keys, vocab, free_keys)
        _values(env['memory_load'], seen_values)
        seen_values.update({env['status'], env['coverage']})
        for finding in env['findings']:
            seen_values.update({finding['classification'], finding['coverage'], finding['severity']})
        for finding in env['findings']:
            assert set(finding) == FINDING_FIELDS
            rid = finding['id']
            seen_rules.add(rid)
            assert rid in WIRING['rule_ids']
            assert finding['classification'] in WIRING['classifications'][rid]
            assert finding['consequence'] == finding['detail'] == WIRING['consequences'][rid]
            assert finding['coverage'] in vocab and finding['severity'] in ENVELOPE_STRINGS | vocab
            assert finding['limitations'] == '' and finding['fix'] is None and finding['proposed_cleanup_id'] is None
            assert finding['affected_identities'] == [] and finding['source_paths'] == []
            for k, v in finding['evidence'].items():
                assert k in keys and k in WIRING['numeric_evidence_keys'], k
                assert type(v) in (int, float, bool), (k, v)
        def collect(v):
            if isinstance(v, dict):
                for k, x in v.items():
                    seen_keys.add(k)
                    collect(x)
            elif isinstance(v, list):
                for x in v:
                    collect(x)
        collect(env['memory_load'])
        for finding in env['findings']:
            seen_keys.update(finding['evidence'])
    # Strict in both directions: nothing listed that no home reaches.
    assert seen_rules == set(WIRING['rule_ids']), set(WIRING['rule_ids']) - seen_rules
    assert seen_keys | {'memory_load'} == keys, keys - seen_keys
    assert seen_values == vocab, (vocab - seen_values, seen_values - vocab)


def _sealing_sets(monkeypatch):
    evidence = load_submodule('audit.evidence')
    persistence = load_submodule('audit.persistence')
    constants = load_submodule('audit.evidence_constants')
    rules = frozenset(WIRING['rule_ids'])
    sentences = frozenset(WIRING['consequences'].values())
    vocabulary = evidence.VOCABULARY | frozenset(WIRING['vocabulary']) | rules | sentences
    monkeypatch.setattr(evidence, 'SCHEMA_KEYS', evidence.SCHEMA_KEYS | frozenset(WIRING['schema_keys']) | {'memory_load', 'run_metrics'})
    monkeypatch.setattr(evidence, 'VOCABULARY', vocabulary)
    monkeypatch.setattr(persistence, 'VOCABULARY', vocabulary)
    monkeypatch.setattr(constants, 'RULE_IDS', constants.RULE_IDS | rules)
    allowed = persistence.ALLOWED_FINDING_CONSEQUENCES | sentences
    monkeypatch.setattr(persistence, 'ALLOWED_FINDING_CONSEQUENCES', allowed)
    monkeypatch.setattr(constants, 'ALLOWED_FINDING_CONSEQUENCES', allowed)
    monkeypatch.setattr(persistence, 'FINDING_CONSEQUENCES', {**persistence.FINDING_CONSEQUENCES, **WIRING['consequences']})
    monkeypatch.setattr(persistence, '_EVIDENCE_NUMERIC_KEYS', persistence._EVIDENCE_NUMERIC_KEYS | frozenset(WIRING['numeric_evidence_keys']))
    monkeypatch.setattr(persistence, '_EVIDENCE_VOCAB_KEYS', persistence._EVIDENCE_VOCAB_KEYS | frozenset(WIRING['vocab_evidence_keys']))
    return evidence, persistence


def _sealed_envelopes(tmp_path, monkeypatch):
    envelopes = _envelopes(tmp_path, monkeypatch)
    evidence, persistence = _sealing_sets(monkeypatch)
    contract = load_submodule('audit.contract')
    sealed = []
    for env in envelopes:
        adapted = contract.adapt_component_result(env, component_id='memory_load', affected_identities=['default'])
        section = evidence.serialize_evidence({'memory_load': adapted['memory_load']})
        dto = evidence.serialize_evidence(persistence.component_dto(adapted))
        sealed.append((env, adapted, section, dto))
    return sealed


def test_sealed_output_keeps_every_key_number_label_and_sentence(tmp_path, monkeypatch):
    for env, adapted, section, dto in _sealed_envelopes(tmp_path, monkeypatch):
        # adapt_component_result keeps the section and run_metrics as top-level siblings.
        assert adapted['memory_load'] is env['memory_load']
        assert adapted['run_metrics'] == env['run_metrics']
        assert adapted['coverage'] == env['coverage']
        assert json.dumps(section, sort_keys=True) == json.dumps({'memory_load': env['memory_load']}, sort_keys=True)
        assert len(dto['findings']) == len(env['findings'])
        raw = {f['id']: f for f in env['findings']}
        for stored in dto['findings']:
            original = raw[stored['id']]
            for key in ('classification', 'coverage', 'severity', 'affected_identities', 'source_paths',
                        'proposed_cleanup_id'):
                assert stored[key] == original[key], key
            assert stored['consequence'] == stored['detail'] == original['consequence']
            evidence = dict(stored['evidence'])
            assert len(evidence.pop('source_digest')) == 64
            assert evidence == original['evidence']


def test_live_sealing_sets_keep_memory_load_output(tmp_path, monkeypatch):
    """The live (unpatched) sets now include the sheet: section, rule ids and sentences survive."""
    evidence = load_submodule('audit.evidence')
    persistence = load_submodule('audit.persistence')
    contract = load_submodule('audit.contract')
    env = _envelopes(tmp_path, monkeypatch)[0]
    adapted = contract.adapt_component_result(env, component_id='memory_load')
    section = evidence.serialize_evidence({'memory_load': adapted['memory_load']})
    dto = persistence.component_dto(adapted)
    assert json.dumps(section, sort_keys=True) == json.dumps({'memory_load': env['memory_load']}, sort_keys=True)
    assert dto['findings']
    for f in dto['findings']:
        assert isinstance(f['id'], str) and f['id'] in WIRING['rule_ids']
        assert f['consequence'] == WIRING['consequences'][f['id']]


def test_canaries_never_reach_sealed_output(tmp_path, monkeypatch):
    sealed = _sealed_envelopes(tmp_path, monkeypatch)
    needles = ('CANARY', 'CANARYHOST', '192.168.', str(tmp_path), 'abcd12', '20260101', '20260103', STATE_DIR + '/')
    for env, adapted, section, dto in sealed:
        for blob in (json.dumps(env), json.dumps(section), json.dumps(dto)):
            for needle in needles:
                assert needle not in blob, needle
        # No content hashes either: the only 64-hex strings are persistence's own source_digest.
        hexes = [s for s in _strings(section, set()) if len(s) >= 32 and all(c in '0123456789abcdef' for c in s)]
        assert hexes == []


def test_doc_page_matches_wiring_json():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words
    doc = (Path(__file__).resolve().parents[1] / 'docs/audit-sections/memory_load.md').read_text(encoding='utf-8')
    for key in WIRING['schema_keys'] + WIRING['vocabulary']:
        _doc_contains(doc, key)
    rows = _doc_rule_rows(doc, {rid.removeprefix('memory_load.') for rid in WIRING['consequences']})
    for rid, sentence in WIRING['consequences'].items():
        row = rows[rid.removeprefix('memory_load.')]
        assert _doc_words(sentence) == _doc_words(row['consequence']), rid
        for classification in WIRING['classifications'][rid]:
            _doc_contains(row['classification'], classification)
    _doc_contains(doc, 'Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound; symlinked folders are counted as links and not measured')
    for key in ('run_metrics', 'elapsed_ms'):
        _doc_contains(doc, key)

RAISED_SENTENCE = ('The character limit for a memory file is set above the value Hermes ships with; text in '
                   'these files is sent with every request, so a higher limit allows more text on every '
                   'request. The setting was measured from config.yaml and does not show who changed it or why.')


def _limit_home(root, config, memory_chars=9995, user_chars=100):
    put(root, 'memories/MEMORY.md', 'x' * memory_chars)
    put(root, 'memories/USER.md', 'y' * user_chars)
    if config is not None:
        put(root, 'config.yaml', config)
    return _bare(root)


def _raised(result):
    return [f for f in result['findings'] if f['id'] == 'memory_load.limit_raised_above_shipped']


def test_raised_memory_limit_is_reported_and_percentage_is_unchanged(tmp_path):
    result = _limit_home(tmp_path, 'memory:\n  memory_char_limit: 10000\n')
    sec = result['memory_load']
    row = next(r for r in sec['files'] if r['kind'] == 'memory')
    assert row['char_limit'] == 10000 and row['percent_of_limit'] == 99.95 and row['over_limit'] is False
    assert 'memory_load.over_limit' not in {f['id'] for f in result['findings']}
    assert sec['char_limits'] == {
        'memory': {'shipped_char_limit': 2200, 'configured_char_limit': 10000, 'limit_ratio_to_shipped': 4.55,
                   'limit_source': 'config', 'chars_over_shipped_limit': 7795},
        'user': {'shipped_char_limit': 1375, 'configured_char_limit': 1375, 'limit_ratio_to_shipped': 1.0,
                 'limit_source': 'default', 'chars_over_shipped_limit': 0}}
    [finding] = _raised(result)
    assert finding['classification'] == 'review_suggested'
    assert finding['consequence'] == RAISED_SENTENCE
    assert finding['evidence'] == {
        'memory_shipped_char_limit': 2200, 'memory_configured_char_limit': 10000,
        'memory_limit_ratio_to_shipped': 4.55, 'memory_characters': 9995,
        'user_shipped_char_limit': 1375, 'user_configured_char_limit': 1375,
        'user_limit_ratio_to_shipped': 1.0, 'user_characters': 100}


def test_raised_limit_below_double_is_info(tmp_path):
    result = _limit_home(tmp_path, 'memory:\n  memory_char_limit: 3000\n', memory_chars=10)
    [finding] = _raised(result)
    assert finding['classification'] == 'info'
    assert finding['evidence']['memory_limit_ratio_to_shipped'] == 1.36
    assert result['memory_load']['char_limits']['memory']['chars_over_shipped_limit'] == 0


@pytest.mark.parametrize('config,ratio', [
    ('memory:\n  memory_char_limit: 2200\n', 1.0),
    (None, 1.0),
    ('memory:\n  user_char_limit: 1375\n', 1.0),
    ('memory:\n  memory_char_limit: 1000\n', 0.45),
])
def test_equal_default_or_lowered_limit_has_no_finding_but_ratio(tmp_path, config, ratio):
    result = _limit_home(tmp_path, config, memory_chars=10)
    assert _raised(result) == []
    assert result['memory_load']['char_limits']['memory']['limit_ratio_to_shipped'] == ratio


@pytest.mark.parametrize('config', ['memory:\n  memory_char_limit: ${HOME_LIMIT}\n', 'memory: [unclosed\n'])
def test_unknown_limit_has_no_finding_and_null_ratio(tmp_path, config):
    result = _limit_home(tmp_path, config)
    limits = result['memory_load']['char_limits']['memory']
    assert _raised(result) == []
    assert limits['configured_char_limit'] is None and limits['limit_ratio_to_shipped'] is None
    assert limits['limit_source'] == 'could_not_verify' and limits['shipped_char_limit'] == 2200
    assert limits['chars_over_shipped_limit'] == 7795


def test_caller_limit_above_shipped_is_not_a_config_finding(tmp_path):
    put(tmp_path, 'memories/MEMORY.md', 'x' * 10)
    result = _bare(tmp_path, memory_char_limit=10000)
    assert _raised(result) == []
    assert result['memory_load']['char_limits']['memory']['limit_source'] == 'caller'
    assert result['memory_load']['char_limits']['memory']['limit_ratio_to_shipped'] == 4.55


def test_only_user_limit_raised_fires(tmp_path):
    result = _limit_home(tmp_path, 'memory:\n  user_char_limit: 2750\n', memory_chars=10)
    [finding] = _raised(result)
    assert finding['classification'] == 'review_suggested'
    assert finding['evidence']['memory_limit_ratio_to_shipped'] == 1.0
    assert finding['evidence']['user_limit_ratio_to_shipped'] == 2.0


def test_raised_limit_is_deterministic(tmp_path):
    a = _limit_home(tmp_path, 'memory:\n  memory_char_limit: 10000\n')
    b = _bare(tmp_path)
    assert json.dumps(a['memory_load'], sort_keys=True) == json.dumps(b['memory_load'], sort_keys=True)
    assert json.dumps(a['findings'], sort_keys=True) == json.dumps(b['findings'], sort_keys=True)


def test_raised_limit_survives_live_sealing(tmp_path):
    """LIVE sets, no monkeypatch: section, evidence and the sentence survive unchanged."""
    evidence = load_submodule('audit.evidence')
    persistence = load_submodule('audit.persistence')
    contract = load_submodule('audit.contract')
    env = _limit_home(tmp_path, 'memory:\n  memory_char_limit: 10000\n  user_char_limit: 2000\n')
    adapted = contract.adapt_component_result(env, component_id='memory_load', affected_identities=['default'])
    section = evidence.serialize_evidence({'memory_load': adapted['memory_load']})
    assert json.dumps(section, sort_keys=True) == json.dumps({'memory_load': env['memory_load']}, sort_keys=True)
    [raw] = _raised(env)
    [stored] = [persistence.finding_dto(f) for f in adapted['findings']
                if f['id'] == 'memory_load.limit_raised_above_shipped']
    assert stored['id'] == raw['id'] and stored['classification'] == 'review_suggested'
    assert stored['consequence'] == RAISED_SENTENCE
    kept = dict(stored['evidence'])
    kept.pop('source_digest', None)
    assert kept == raw['evidence'] and len(kept) == 8
