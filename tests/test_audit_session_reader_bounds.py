"""Bounds, linear scan, differential corpus, and sidecar-free proofs for session audit."""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest  # type: ignore[import-not-found]

from tests.conftest import load_submodule


def _make_session_db(
    home: Path,
    project: Path,
    *,
    sessions_count: int = 1,
    messages_per_session: int = 1,
    message_text: str = '<memory-context>Python pip CANARY_MSG_BODY</memory-context>',
    prompt_text: str = 'System prompt CANARY_PROMPT',
) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    db_path = home / 'state.db'
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE sessions(
            id TEXT PRIMARY KEY, cwd TEXT, git_repo_root TEXT,
            system_prompt TEXT, started_at REAL, message_count INTEGER,
            source TEXT, parent_session_id TEXT, system_prompt_hash TEXT
        );
        CREATE TABLE messages(
            id INTEGER PRIMARY KEY, session_id TEXT, role TEXT,
            content TEXT, timestamp REAL, api_content TEXT
        );
        CREATE TABLE system_prompts(hash TEXT PRIMARY KEY, prompt TEXT);
        CREATE INDEX idx_sessions_started ON sessions(started_at DESC);
        CREATE INDEX idx_messages_session ON messages(session_id, timestamp);
        """
    )
    stamp = datetime(2025, 3, 1, tzinfo=timezone.utc).timestamp()
    conn.executemany(
        'INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)',
        (
            (
                f'SYNTH_SESSION_{s}',
                str(project),
                str(project),
                prompt_text,
                stamp,
                messages_per_session,
                'cli',
                None,
                None,
            )
            for s in range(sessions_count)
        ),
    )
    mid = 0
    rows = []
    for s in range(sessions_count):
        sid = f'SYNTH_SESSION_{s}'
        for _ in range(messages_per_session):
            rows.append((mid, sid, 'user', 'user turn CANARY_RAW_TURN', stamp, message_text))
            mid += 1
    conn.executemany('INSERT INTO messages VALUES(?,?,?,?,?,?)', rows)
    conn.commit()
    conn.close()
    return db_path


def test_explicit_session_cap_constants_exist():
    mod = load_submodule('audit.session_contamination')
    assert mod.MAX_TEXT_BYTES == 1024 * 1024
    assert mod.MAX_BLOCKS_PER_MESSAGE == 1024
    assert mod.MAX_MESSAGES_PER_SESSION == 5000
    assert mod.MAX_MESSAGES == 50000
    assert mod.MAX_SESSIONS == 10000
    assert mod.MAX_SECONDS == 20


def test_cap_hits_emit_allowlisted_reason_tokens_and_unverified_coverage(tmp_path, monkeypatch):
    mod = load_submodule('audit.session_contamination')
    ev = load_submodule('audit.evidence')
    surface = load_submodule('audit_surface')

    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}', encoding='utf-8')

    # 1. Per-message byte cap on a single 20 MiB message (with leading block + canary)
    home_20m = tmp_path / 'home_20m'
    twenty_mib = (
        '<memory-context>Python CANARY_TWENTY_MIB</memory-context>'
        + ('x' * (20 * 1024 * 1024))
    )
    _make_session_db(home_20m, project, message_text=twenty_mib)
    t0 = time.monotonic()
    res_20m = mod.audit_session_contamination(
        profile_path=home_20m, sessions=True, selected_projects=[project]
    )
    dt_20m = time.monotonic() - t0
    sec_20m = res_20m['session_contamination']
    assert dt_20m < 3.0
    assert sec_20m['coverage'] == 'could_not_verify'
    assert sec_20m['truncated_by'] == 'file_byte_limit_exceeded'
    assert sec_20m['reason'] == 'file_byte_limit_exceeded'
    assert 'file_byte_limit_exceeded' in sec_20m['cut_reasons']
    assert sec_20m['truncated_by'] in ev.VOCABULARY
    assert sec_20m['overall']['memory_context_blocks'] == 1
    assert 'CANARY' not in json.dumps(res_20m)
    assert 'SYNTH_SESSION' not in json.dumps(res_20m)

    # 2. Per-message block cap (MAX_BLOCKS_PER_MESSAGE)
    home_blocks = tmp_path / 'home_blocks'
    many_blocks = '<memory-context>Python CANARY_BLK</memory-context>' * 5
    _make_session_db(home_blocks, project, message_text=many_blocks)
    with monkeypatch.context() as mp:
        mp.setattr(mod, 'MAX_BLOCKS_PER_MESSAGE', 2)
        assert len(mod.recalled_blocks(many_blocks)) == 2
        res_blk = mod.audit_session_contamination(
            profile_path=home_blocks, sessions=True, selected_projects=[project]
        )
    sec_blk = res_blk['session_contamination']
    assert sec_blk['coverage'] == 'could_not_verify'
    assert sec_blk['truncated_by'] == 'limit_exceeded'
    assert sec_blk['reason'] == 'limit_exceeded'
    assert 'limit_exceeded' in sec_blk['cut_reasons']
    assert sec_blk['truncated_by'] in ev.VOCABULARY
    assert sec_blk['overall']['memory_context_blocks'] == 2
    assert 'CANARY' not in json.dumps(res_blk)

    # 3. Per-session message cap (MAX_MESSAGES_PER_SESSION) does not starve later sessions
    home_sess_cap = tmp_path / 'home_sess_cap'
    _make_session_db(home_sess_cap, project, sessions_count=2, messages_per_session=4)
    with monkeypatch.context() as mp:
        mp.setattr(mod, 'MAX_MESSAGES_PER_SESSION', 2)
        res_sc = mod.audit_session_contamination(
            profile_path=home_sess_cap, sessions=True, selected_projects=[project]
        )
    sec_sc = res_sc['session_contamination']
    assert sec_sc['coverage'] == 'could_not_verify'
    assert sec_sc['truncated_by'] == 'row_cap'
    assert sec_sc['reason'] == 'row_cap'
    assert 'row_cap' in sec_sc['cut_reasons']
    assert sec_sc['truncated_by'] in ev.VOCABULARY
    # Both sessions got up to 2 blocks counted (4 total), neither starved the other
    assert sec_sc['overall']['memory_context_blocks'] == 4
    assert sec_sc['overall']['sessions_classified'] == 0

    # 4. Per-run message cap (MAX_MESSAGES) through full execute_audit serialization
    home_run_cap = tmp_path / 'home_run_cap'
    _make_session_db(home_run_cap, project, sessions_count=3, messages_per_session=3)
    (home_run_cap / 'config.yaml').write_text('{}\n', encoding='utf-8')
    reg = home_run_cap / 'plugin-data' / 'defuzz' / 'state.db'
    reg.parent.mkdir(parents=True)
    with sqlite3.connect(reg) as conn:
        conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
        conn.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synth'))
    git = load_submodule('audit.outward_git')
    orig_discover = git.discover_git_context
    with monkeypatch.context() as mp:
        mp.setenv('HERMES_HOME', str(home_run_cap))
        mp.setattr(
            git,
            'discover_git_context',
            lambda *a, **kw: orig_discover(*a, **kw, system_config=tmp_path / 'no-gitconfig'),
        )
        mp.setattr(mod, 'MAX_MESSAGES', 4)
        store_db = tmp_path / 'audit-out' / 'audit.db'
        store_db.parent.mkdir(parents=True)
        full_res = surface.execute_audit(
            {'action': 'run', 'root': str(project)},
            db_path=store_db,
            wait=True,
            sessions=True,
        )
    sealed_sec = full_res['report']['session_contamination']
    assert sealed_sec['coverage'] == 'could_not_verify'
    assert sealed_sec['truncated_by'] == 'database_row_limit_exceeded'
    assert sealed_sec['reason'] == 'database_row_limit_exceeded'
    assert 'database_row_limit_exceeded' in sealed_sec['cut_reasons']
    assert 'hmac' not in json.dumps(sealed_sec)
    assert 'CANARY' not in json.dumps(full_res)
    assert 'SYNTH_SESSION' not in json.dumps(full_res)
    with sqlite3.connect(store_db) as conn:
        dump = '\n'.join(conn.iterdump())
    assert 'CANARY' not in dump
    assert 'SYNTH_SESSION' not in dump


def _old_regex_recalled_blocks(text: str, open_fence: str, close_fence: str) -> list[str]:
    import re

    pattern = re.compile(re.escape(open_fence) + r'(.*?)' + re.escape(close_fence), re.I | re.S)
    return [m[1] for m in pattern.finditer(text)]


def test_differential_well_formed_and_edge_corpora_match_reference_regex():
    import random

    mod = load_submodule('audit.session_contamination')
    handcrafted = [
        '',
        'plain text without any tags',
        '<memory-context>Python fastapi</memory-context>',
        'before <MEMORY-CONTEXT>first\nline</MEMORY-CONTEXT> mid <MeMoRy-CoNtExT>second</mEmOrY-CoNtExT> after',
        '<memory-context>outer <memory-context>inner</memory-context> trailing</memory-context>',
        '</memory-context>orphan closer<memory-context>kept</memory-context></memory-context>',
        'İ<memory-context>unicode İ inside</memory-context>İ<MEMORY-CONTEXT>two</memory-context><memory-context>unclosed',
        '</memory-context><memory-context>a</memory-context></memory-context><memory-context>b<memory-context>c</memory-context><memory-context>tail',
        '<memory-context></memory-context><memory-context>nonempty</memory-context>',
    ]
    rng = random.Random(20261110)
    open_variants = ['<memory-context>', '<MEMORY-CONTEXT>', '<MeMoRy-CoNtExT>']
    close_variants = ['</memory-context>', '</MEMORY-CONTEXT>', '</mEmOrY-cOnTeXt>']
    atoms = [
        'Python ', 'rust crate ', 'java 21 ', 'İ', 'é', '中', '\n', 'plain prose ',
        *open_variants, *close_variants,
    ]
    generated = [
        ''.join(rng.choice(atoms) for _ in range(rng.randint(0, 24)))
        for _ in range(250)
    ]
    for sample in handcrafted + generated:
        expected = _old_regex_recalled_blocks(sample, mod.OPEN_FENCE, mod.CLOSE_FENCE)
        assert mod.recalled_blocks(sample) == expected


def test_adversarial_recall_and_store_inputs_stay_linear(tmp_path):
    import signal

    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}', encoding='utf-8')

    def _with_alarm(seconds: int, label: str, fn):
        def _timeout(*_):
            pytest.fail(f'{label} exceeded {seconds}s alarm')

        old = signal.signal(signal.SIGALRM, _timeout)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        t0 = time.monotonic()
        try:
            out = fn()
            return out, time.monotonic() - t0
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)

    # 1 MiB and 8 MiB of repeated unclosed openers
    for mib in (1, 8):
        nbytes = mib * 1024 * 1024
        unclosed = (mod.OPEN_FENCE * (nbytes // len(mod.OPEN_FENCE) + 1))[:nbytes]
        blocks, elapsed = _with_alarm(2, f'{mib}MiB unclosed', lambda s=unclosed: mod.recalled_blocks(s))
        print(f'ADVERSARIAL_{mib}MIB_UNCLOSED_S={elapsed:.6f}')
        assert blocks == []
        assert elapsed < 1.0

    # Adversarial technology_counts patterns inside recalled blocks ('1.' * 100k and '-a' * 524k)
    dotted_version_bomb = '<memory-context>' + ('1.' * 100_000) + ' Python</memory-context>'
    counts, dt_dots = _with_alarm(
        2,
        'dotted-version ReDoS check',
        lambda: mod.technology_counts(mod.recalled_blocks(dotted_version_bomb)[0]),
    )
    print(f'ADVERSARIAL_DOTTED_200KB_S={dt_dots:.6f}')
    assert counts == {'python': 1}
    assert dt_dots < 0.5

    hyphen_stem_bomb = '-a' * 524_288
    counts_h, dt_hyph = _with_alarm(
        2,
        'hyphen-stem 1MiB check',
        lambda: mod.technology_counts(hyphen_stem_bomb),
    )
    print(f'ADVERSARIAL_HYPHEN_1MIB_S={dt_hyph:.6f}')
    assert counts_h == {}
    assert dt_hyph < 1.5

    # Single 20 MiB message of repeated unclosed openers in SQLite
    home_20m = tmp_path / 'home_20m_unclosed'
    twenty_mib_unclosed = (mod.OPEN_FENCE * ((20 * 1024 * 1024) // len(mod.OPEN_FENCE) + 1))[: 20 * 1024 * 1024]
    _make_session_db(home_20m, project, message_text=twenty_mib_unclosed)
    res_20m, dt_20m = _with_alarm(
        5,
        '20MiB unclosed SQLite message',
        lambda: mod.audit_session_contamination(
            profile_path=home_20m, sessions=True, selected_projects=[project]
        ),
    )
    print(f'ADVERSARIAL_20MIB_MESSAGE_S={dt_20m:.6f}')
    assert res_20m['session_contamination']['coverage'] == 'could_not_verify'
    assert res_20m['session_contamination']['truncated_by'] == 'file_byte_limit_exceeded'
    assert res_20m['session_contamination']['overall']['memory_context_blocks'] == 0
    assert dt_20m < 3.0

    # 200,000 small messages in one session (hits MAX_MESSAGES_PER_SESSION = 5000)
    home_200k_one = tmp_path / 'home_200k_one'
    _make_session_db(
        home_200k_one,
        project,
        sessions_count=1,
        messages_per_session=200_000,
        message_text='turn <memory-context>Python</memory-context>',
    )
    res_200k_one, dt_200k_one = _with_alarm(
        5,
        '200k messages single session',
        lambda: mod.audit_session_contamination(
            profile_path=home_200k_one, sessions=True, selected_projects=[project]
        ),
    )
    sec_one = res_200k_one['session_contamination']
    print(f'ADVERSARIAL_200K_SINGLE_SESSION_S={dt_200k_one:.6f}')
    assert sec_one['coverage'] == 'could_not_verify'
    assert sec_one['truncated_by'] == 'row_cap'
    assert sec_one['overall']['memory_context_blocks'] == mod.MAX_MESSAGES_PER_SESSION
    assert dt_200k_one < 3.0

    # 200,000 small messages across 40 sessions (hits MAX_MESSAGES = 50,000 per run)
    home_200k_many = tmp_path / 'home_200k_many'
    _make_session_db(
        home_200k_many,
        project,
        sessions_count=40,
        messages_per_session=5_000,
        message_text='turn <memory-context>Python</memory-context>',
    )
    res_200k_many, dt_200k_many = _with_alarm(
        10,
        '200k messages across 40 sessions',
        lambda: mod.audit_session_contamination(
            profile_path=home_200k_many, sessions=True, selected_projects=[project]
        ),
    )
    sec_many = res_200k_many['session_contamination']
    print(f'ADVERSARIAL_200K_MULTI_SESSION_S={dt_200k_many:.6f}')
    assert sec_many['coverage'] == 'could_not_verify'
    assert sec_many['truncated_by'] == 'database_row_limit_exceeded'
    assert 'database_row_limit_exceeded' in sec_many['cut_reasons']
    assert sec_many['limits']['messages_examined'] == mod.MAX_MESSAGES
    assert dt_200k_many < 6.0


def test_hostile_empty_directory_tree_and_sql_bounds(tmp_path, monkeypatch):
    from contextlib import contextmanager

    mod = load_submodule('audit.session_contamination')
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('x = 1\n', encoding='utf-8')
    for idx in range(20):
        (project / f'empty_dir_{idx}').mkdir()

    home = tmp_path / 'home'
    _make_session_db(home, project)

    # Empty directories must also count toward MAX_PROJECT_ENTRIES so directory bombs cannot walk unboundedly
    with monkeypatch.context() as mp:
        mp.setattr(mod, 'MAX_PROJECT_ENTRIES', 5)
        res = mod.audit_session_contamination(
            profile_path=home, sessions=True, selected_projects=[project]
        )
    sec = res['session_contamination']
    assert sec['coverage'] == 'could_not_verify'
    assert sec['truncated_by'] == 'entry_limit_exceeded'
    assert 'entry_limit_exceeded' in sec['cut_reasons']

    # Verify SQL statements never cast unsliced text columns to BLOB and sqlite_master DDL is length-bounded
    statements = []
    orig_open = mod.open_readonly_sqlite

    @contextmanager
    def traced_open(*args, **kwargs):
        with orig_open(*args, **kwargs) as (conn, pre_id):
            conn.set_trace_callback(statements.append)
            yield conn, pre_id

    with monkeypatch.context() as mp:
        mp.setattr(mod, 'open_readonly_sqlite', traced_open)
        mod.audit_session_contamination(profile_path=home, sessions=True, selected_projects=[project])

    for sql in statements:
        for col in ('id', 'cwd', 'git_repo_root', 'session_id', 'content', 'api_content', 'system_prompt'):
            assert f'CAST({col} AS BLOB)' not in sql
    master_queries = [s for s in statements if 'sqlite_master' in s and 'SELECT type' in s]
    assert master_queries and all('substr(sql' in s for s in master_queries)


SESSION_DB_CASES = (
    'no_wal_rollback',
    'no_wal_closed_wal',
    'empty_wal',
    'empty_wal_stale_shm',
    'wal_frames_copied_shm',
    'wal_frames_live_writer',
    'wal_frames_no_shm',
    'rollback_journal_empty',
    'rollback_journal_hot',
)


def _snapshot_dir_entries(root: Path) -> dict[str, tuple[int, int, int]]:
    import os

    entries: dict[str, tuple[int, int, int]] = {}
    root_st = os.lstat(root)
    entries['.'] = (int(root_st.st_size), int(root_st.st_mtime_ns), int(root_st.st_ino))
    for path in sorted(root.rglob('*')):
        st = os.lstat(path)
        rel = str(path.relative_to(root))
        entries[rel] = (int(st.st_size), int(st.st_mtime_ns), int(st.st_ino))
    return entries


def _prepare_session_case_home(tmp_path: Path, case: str, project: Path):
    import shutil

    src_home = tmp_path / 'src_home'
    _make_session_db(src_home, project, sessions_count=4, messages_per_session=2)
    src_db = src_home / 'state.db'

    home = tmp_path / 'home'
    home.mkdir()
    (home / 'config.yaml').write_text('{}\n', encoding='utf-8')
    reg = home / 'plugin-data' / 'defuzz' / 'state.db'
    reg.parent.mkdir(parents=True)
    rconn = sqlite3.connect(reg)
    rconn.execute('PRAGMA journal_mode=WAL')
    rconn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
    rconn.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synth'))
    rconn.commit()
    rconn.close()

    live_writer = None
    target_db = home / 'state.db'

    if case == 'no_wal_rollback':
        shutil.copyfile(src_db, target_db)
    elif case in {'no_wal_closed_wal', 'empty_wal', 'empty_wal_stale_shm'}:
        shutil.copyfile(src_db, target_db)
        w = sqlite3.connect(target_db)
        w.execute('PRAGMA journal_mode=WAL')
        w.execute("UPDATE sessions SET source='wal'")
        w.commit()
        w.close()
        if case in {'empty_wal', 'empty_wal_stale_shm'}:
            Path(f'{target_db}-wal').touch()
        if case == 'empty_wal_stale_shm':
            Path(f'{target_db}-shm').write_bytes(b'\x00' * 32768)
    elif case in {'wal_frames_copied_shm', 'wal_frames_no_shm'}:
        w = sqlite3.connect(src_db)
        w.execute('PRAGMA journal_mode=WAL')
        w.execute("UPDATE sessions SET source='wal_frames'")
        w.commit()
        for suffix in ('', '-wal', '-shm'):
            if case == 'wal_frames_no_shm' and suffix == '-shm':
                continue
            shutil.copyfile(f'{src_db}{suffix}', f'{target_db}{suffix}')
        w.close()
    elif case == 'wal_frames_live_writer':
        shutil.copyfile(src_db, target_db)
        live_writer = sqlite3.connect(target_db)
        live_writer.execute('PRAGMA journal_mode=WAL')
        live_writer.execute("UPDATE sessions SET source='wal_live'")
        live_writer.commit()
    elif case == 'rollback_journal_empty':
        shutil.copyfile(src_db, target_db)
        Path(f'{target_db}-journal').write_bytes(b'')
    elif case == 'rollback_journal_hot':
        shutil.copyfile(src_db, target_db)
        Path(f'{target_db}-journal').write_bytes(bytes.fromhex('d9d505f920a163d7') + bytes(1016))
    else:
        raise AssertionError(f'unknown case {case}')

    return home, live_writer


@pytest.mark.parametrize('case', SESSION_DB_CASES)
@pytest.mark.parametrize('readonly', [False, True], ids=['writable', '0555'])
def test_full_sessions_audit_creates_or_modifies_no_sidecars(tmp_path, monkeypatch, case, readonly):
    import hashlib
    import os

    if readonly and os.geteuid() == 0:
        pytest.skip('root bypasses chmod 0555 directory permissions')

    # Preload audit_surface before any directory permissions are tightened.
    surface = load_submodule('audit_surface')
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(
        git,
        'discover_git_context',
        lambda *a, **kw: discover(*a, **kw, system_config=tmp_path / 'absent-gitconfig'),
    )

    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}\n', encoding='utf-8')

    home, live_writer = _prepare_session_case_home(tmp_path, case, project)
    monkeypatch.setenv('HERMES_HOME', str(home))

    # Backdate mtimes by 10s so any write or transient sidecar create/unlink advances mtime_ns.
    past_ns = time.time_ns() - 10_000_000_000
    all_paths = sorted(home.rglob('*'), key=lambda p: len(p.parts), reverse=True) + [home]
    for p in all_paths:
        os.utime(p, ns=(past_ns, past_ns), follow_symlinks=False)

    dirs_to_chmod = [p for p in [home, *home.rglob('*')] if p.is_dir()]
    if readonly:
        for d in sorted(dirs_to_chmod, key=lambda p: len(p.parts), reverse=True):
            d.chmod(0o555)

    before = _snapshot_dir_entries(home)
    before_bytes = {
        str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in home.rglob('*')
        if p.is_file() and not p.name.endswith('-shm')
    }
    store_dir = tmp_path / 'audit-store'
    store_dir.mkdir()

    try:
        result = surface.execute_audit(
            {'action': 'run', 'root': str(project), 'sessions': True},
            db_path=store_dir / 'audit.db',
            wait=True,
        )
        after = _snapshot_dir_entries(home)
        after_bytes = {
            str(p.relative_to(home)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in home.rglob('*')
            if p.is_file() and not p.name.endswith('-shm')
        }

        assert result['status'] == 'completed'
        section = result['report']['session_contamination']

        # Directory names and inodes/sizes never change in any case; non-SHM mtimes & bytes never change.
        assert list(after.keys()) == list(before.keys())
        assert after_bytes == before_bytes
        if case in {'wal_frames_copied_shm', 'wal_frames_live_writer'}:
            # Live/uncheckpointed WAL with existing -shm: only reader marks in existing -shm may update mtime.
            assert {k: (v[0], v[2]) for k, v in after.items()} == {k: (v[0], v[2]) for k, v in before.items()}
            assert {k: v for k, v in after.items() if not k.endswith('-shm')} == {
                k: v for k, v in before.items() if not k.endswith('-shm')
            }
            assert section['status'] == 'completed'
            assert section['read_mode'] == 'mode=ro'
            assert section['coverage'] == 'verified'
            assert section['overall']['sessions_examined'] == 4
        elif case in {'wal_frames_no_shm', 'rollback_journal_empty', 'rollback_journal_hot'}:
            # Refused without reading or creating/modifying any file.
            assert after == before
            assert section['status'] == 'not_measured'
            assert section['coverage'] == 'could_not_verify'
            expected_reason = 'wal_needs_index' if case == 'wal_frames_no_shm' else 'hot_journal'
            assert section['reason'] == expected_reason
        else:
            # No WAL or empty WAL (with or without stale -shm): immutable=1 touches zero bytes and zero mtimes.
            assert after == before
            assert section['status'] == 'completed'
            assert section['read_mode'] == 'immutable'
            assert section['coverage'] == 'verified'
            assert section['overall']['sessions_examined'] == 4
    finally:
        for d in dirs_to_chmod:
            d.chmod(0o755)
        if live_writer is not None:
            live_writer.close()


