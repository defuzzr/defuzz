"""Synthetic WAL registration reads must distinguish data from reader bookkeeping."""
import os
import sqlite3
from pathlib import Path

import pytest

from hermes_plugins.defuzz.audit import readonly_db


@pytest.fixture
def wal_db(tmp_path):
    path = tmp_path / "state.db"
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT)")
    writer.commit()
    writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    writer.execute("INSERT INTO projects VALUES (?, ?)", (str(tmp_path / "project"), "wal-only"))
    writer.commit()
    try:
        yield path, writer
    finally:
        writer.close()


def test_shm_bookkeeping_does_not_invalidate_wal_registrations(wal_db, monkeypatch):
    path, _ = wal_db
    before = {p: p.read_bytes() for p in (path, Path(f"{path}-wal"))}
    original = readonly_db._table_columns

    def reader_bookkeeping(conn, table):
        columns = original(conn, table)
        # WAL readers may update shared-memory read marks, including its mtime.
        shm = Path(f"{path}-shm")
        st = shm.stat()
        os.utime(shm, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        return columns

    monkeypatch.setattr(readonly_db, "_table_columns", reader_bookkeeping)
    result = readonly_db.read_profile_registrations_readonly("synthetic", path.parent, db_path=path)
    assert result.coverage == "verified"
    assert not result.changed_during_read
    assert result.error is None
    assert [r["name"] for r in result.records] == ["wal-only"]
    assert result.row_digest
    assert {p: p.read_bytes() for p in before} == before


def test_concurrent_wal_commit_is_unstable(wal_db, monkeypatch):
    path, writer = wal_db
    original = readonly_db._table_columns

    def concurrent_commit(conn, table):
        columns = original(conn, table)
        writer.execute("UPDATE projects SET name = 'changed'")
        writer.commit()
        return columns

    monkeypatch.setattr(readonly_db, "_table_columns", concurrent_commit)
    result = readonly_db.read_profile_registrations_readonly("synthetic", path.parent, db_path=path)
    assert result.coverage == "could_not_verify"
    assert result.changed_during_read


def test_row_change_detected_even_when_stat_identity_is_unchanged(wal_db, monkeypatch):
    path, writer = wal_db
    identity = readonly_db.stat_db_identity(path)
    monkeypatch.setattr(readonly_db, "stat_db_identity", lambda _: identity)
    original = readonly_db._parse_json_list

    writer.execute("ALTER TABLE projects ADD COLUMN languages TEXT")
    writer.commit()

    def concurrent_commit(raw):
        writer.execute("UPDATE projects SET name = 'changed'")
        writer.commit()
        return original(raw)

    monkeypatch.setattr(readonly_db, "_parse_json_list", concurrent_commit)
    result = readonly_db.read_profile_registrations_readonly("synthetic", path.parent, db_path=path)
    assert result.coverage == "could_not_verify"
    assert result.changed_during_read


def test_unsupported_schema_shm_change_is_not_a_data_change(wal_db, monkeypatch):
    path, writer = wal_db
    writer.execute("DROP TABLE projects")
    writer.commit()
    original = readonly_db._table_columns

    def reader_bookkeeping(conn, table):
        columns = original(conn, table)
        shm = Path(f"{path}-shm")
        st = shm.stat()
        os.utime(shm, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        return columns

    monkeypatch.setattr(readonly_db, "_table_columns", reader_bookkeeping)
    result = readonly_db.read_profile_registrations_readonly("synthetic", path.parent, db_path=path)
    assert result.coverage == "could_not_verify"
    assert result.error == "Unsupported projects schema"
    assert not result.changed_during_read


def test_session_evidence_live_wal_no_commit_not_changed_and_commit_changed(wal_db, monkeypatch):
    path, writer = wal_db
    writer.execute(
        "CREATE TABLE sessions (id TEXT PRIMARY KEY, started_at REAL, source TEXT, title TEXT, last_activity_at REAL, message_count INTEGER)"
    )
    writer.execute(
        "INSERT INTO sessions VALUES ('s1', 1700000000.0, 'cli', 'hello', 1700000010.0, 2)"
    )
    writer.commit()

    # Live WAL read with no commit in between (even when SHM read marks / mtime update)
    original_cols = readonly_db._table_columns

    def touch_shm(conn, table):
        cols = original_cols(conn, table)
        shm = Path(f"{path}-shm")
        st = shm.stat()
        os.utime(shm, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        return cols

    monkeypatch.setattr(readonly_db, "_table_columns", touch_shm)
    ev = readonly_db.read_profile_session_evidence(path)
    assert not ev.changed_during_read
    assert ev.coverage == "verified"
    assert ev.error is None
    assert ev.session_count == 1

    # Unsupported schema branch with SHM read-mark update also reports not changed
    writer.execute("DROP TABLE sessions")
    writer.commit()
    ev_missing = readonly_db.read_profile_session_evidence(path)
    assert not ev_missing.changed_during_read
    assert ev_missing.coverage == "could_not_verify"

    # Re-create sessions and commit in between pre_id and post_id -> reports changed
    writer.execute(
        "CREATE TABLE sessions (id TEXT PRIMARY KEY, started_at REAL, source TEXT, title TEXT, last_activity_at REAL, message_count INTEGER)"
    )
    writer.execute(
        "INSERT INTO sessions VALUES ('s1', 1700000000.0, 'cli', 'hello', 1700000010.0, 2)"
    )
    writer.commit()

    def commit_between(conn, table):
        cols = original_cols(conn, table)
        writer.execute(
            "INSERT INTO sessions VALUES ('s2', 1700000020.0, 'cli', 'world', 1700000030.0, 1)"
        )
        writer.commit()
        return cols

    monkeypatch.setattr(readonly_db, "_table_columns", commit_between)
    ev_changed = readonly_db.read_profile_session_evidence(path)
    assert ev_changed.changed_during_read
    assert ev_changed.coverage == "could_not_verify"
