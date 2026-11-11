"""In-place read-only SQLite metadata inspection through open_readonly_sqlite.

Integration: inspect_database(path, parent_fd=anchored_directory_fd,
expected_stat=info, unbounded=unbounded). Feed sessions records to session_record;
other records are historical path associations, never active blending. Propagate
uncertainties only to their listed regions. No message bodies are selected.
"""
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from .outward_git import _identity
from .readonly_db import ReadOnlyDbError, open_readonly_sqlite

MAX_SQL_STEPS = 10_000_000
BUSY_TIMEOUT_S = 0.1
_KNOWN_TABLES = (
    'sessions', 'projects', 'project_folders', 'discovered_repos',
    'tasks', 'task_attachments', 'responses', 'conversations', 'answers',
)
_PATH_COLUMNS = ('cwd', 'git_repo_root', 'project_path', 'working_directory', 'workspace_path', 'primary_path', 'stored_path', 'root')
_TIMESTAMP_COLUMNS = ('started_at', 'timestamp', 'created_at', 'updated_at')
_IDENTIFIER_COLUMNS = {
    'projects': ('id', 'slug', 'board_slug'),
    'project_folders': ('project_id',),
    'tasks': ('id', 'title', 'project_id', 'tenant', 'assignee', 'session_id'),
    'task_attachments': ('id', 'task_id'),
}
_ASSOCIATION_TABLES = frozenset({'projects', 'project_folders', 'tasks', 'task_attachments'})


class SnapshotError(OSError):
    """A database read or budget check failed."""


def _row_bytes(row) -> int:
    return sum(
        len(v) if isinstance(v, (bytes, bytearray, memoryview)) else len(str(v).encode('utf-8', errors='surrogatepass'))
        for v in row if v is not None
    )


def _digest(value):
    return None if value is None else hashlib.sha256(
        value if isinstance(value, bytes) else str(value).encode('utf-8')).hexdigest()


def _associations(result, selected_projects):
    """Project ownership is lexical, never filesystem resolution or activation."""
    rows = [r for r in result['records'] if r['table'] in _ASSOCIATION_TABLES]
    result['associations'] = [dict(r) for r in rows]
    folders = [
        {'path': value, 'project_id_sha256': pid, 'table': row['table'], 'field': field}
        for row in rows if row['table'] in {'projects', 'project_folders'}
        and (pid := row.get('project_id_sha256', row.get('id_sha256')))
        for field in ('primary_path', 'path')
        if isinstance(value := row.get(field), str) and os.path.isabs(value)
    ]
    selected = {
        folder['project_id_sha256'] for folder in folders
        if selected_projects is None or any(
            os.path.abspath(p) == (stem := os.path.normpath(folder['path']))
            or os.path.abspath(p).startswith(stem.rstrip('/') + '/')
            for p in selected_projects
        )
    }
    result['folder_references'] = [f for f in folders if f['project_id_sha256'] in selected]


def _classify_db_schema(known: dict[str, set[str]]) -> tuple[str | None, str | None]:
    if set(_PATH_COLUMNS) & known.get('sessions', set()):
        return 'hermes_sessions', None
    projects = known.get('projects', set())
    if {'path', 'hermes_project_id'} <= projects:
        return 'defuzz_state', None
    if {'path', 'id'} <= projects or {'id', 'slug', 'primary_path'} <= projects:
        return 'hermes_projects', None
    if {'id', 'title', 'status', 'workspace_path'} <= known.get('tasks', set()):
        return 'hermes_kanban', None
    if ({'response_id', 'data', 'accessed_at'} <= known.get('responses', set())
            and {'name', 'response_id'} <= known.get('conversations', set())):
        return 'hermes_response_store', 'schema inspected; response bodies not read; no path association columns'
    return None, None


def _build_table_query(table: str, fields: list[str], selected_projects) -> tuple[str, list]:
    query = 'SELECT ' + ','.join(fields) + ' FROM ' + table
    parameters = []
    if selected_projects is not None and table == 'sessions':
        clauses = []
        for project in selected_projects:
            root = os.path.abspath(project)
            prefix = root.rstrip('/') + '/'
            for field in fields:
                if field in _PATH_COLUMNS:
                    clauses.append(f'({field} = ? OR substr({field},1,?) = ?)')
                    parameters.extend((root, len(prefix), prefix))
        query += ' WHERE ' + (' OR '.join(clauses) or '0')
    return query, parameters


def inspect_database(path, *, parent_fd=None, expected_stat=None, scratch_dir=None,
                     row_limit=10000, unbounded=False, selected_projects=None, account=None, cancelled=None):
    """Return path/timestamp metadata, classification and scoped uncertainty."""
    if type(unbounded) is not bool or type(row_limit) is not int or row_limit <= 0:
        raise ValueError('invalid database inspection budget')
    limit = None if unbounded else row_limit
    result: dict[str, Any] = {
        'schema': 'unknown', 'records': [], 'associations': [],
        'folder_references': [], 'uncertainties': [],
        'changed_during_read': False,
        'limits': {'row_limit': limit, 'rows_inspected': 0, 'truncated': False, 'page_size': 1000, 'pages_inspected': 0},
    }

    def uncertain(reason):
        result['uncertainties'].append({'reason': reason, 'regions': ['session_history', 'cross_project_isolation']})

    from .redaction import observe_value
    target = Path(os.path.abspath(path))
    measured = False
    changed = False
    try:
        if any(p.is_symlink() for p in target.parents):
            raise ReadOnlyDbError('Refusing symlink ancestor for database file', reason='symlink')
        if parent_fd is not None:
            dir_info = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(dir_info.st_mode):
                raise ReadOnlyDbError('Not a regular file', reason='special_file')
            if expected_stat is not None and _identity(dir_info) != _identity(expected_stat):
                if (dir_info.st_dev, dir_info.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
                    raise ReadOnlyDbError('Database replaced before open', reason='race_detected')
                changed = True
        with open_readonly_sqlite(target, timeout=BUSY_TIMEOUT_S) as (conn, pre_id):
            if pre_id.size == 0:
                raise ReadOnlyDbError('Empty database file', reason='corrupt_header')
            if expected_stat is not None:
                if (pre_id.dev, pre_id.ino) != (expected_stat.st_dev, expected_stat.st_ino):
                    raise ReadOnlyDbError('Database replaced before open', reason='race_detected')
                if (pre_id.size, pre_id.mtime_ns) != (expected_stat.st_size, expected_stat.st_mtime_ns):
                    changed = True
            if parent_fd is not None:
                dir_after = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                if (dir_after.st_dev, dir_after.st_ino) != (pre_id.dev, pre_id.ino):
                    raise ReadOnlyDbError('Database replaced during open', reason='race_detected')
            if account:
                account(min(pre_id.size, 20))
            steps = 0

            def progress():
                nonlocal steps
                steps += 1000
                if (cancelled and cancelled()) or steps > MAX_SQL_STEPS:
                    return 1
                return 0

            conn.set_progress_handler(progress, 1000)
            master_rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if account:
                for r in master_rows:
                    account(_row_bytes(r))
            tables = {r[0] for r in master_rows}
            known: dict[str, set[str]] = {}
            for t in _KNOWN_TABLES:
                if t in tables:
                    info_rows = conn.execute(f'PRAGMA table_info({t})').fetchall()
                    if account:
                        for r in info_rows:
                            account(_row_bytes(r))
                    known[t] = {r[1] for r in info_rows}
            schema, scope_note = _classify_db_schema(known)
            if schema is None:
                uncertain('unsupported_database_schema')
                measured = True
            else:
                result['schema'] = schema
                if scope_note:
                    result['limits']['scope'] = scope_note
                truncated = False
                for table, columns in known.items():
                    if truncated:
                        break
                    candidates = _PATH_COLUMNS + (('path',) if table in {'projects', 'project_folders'} else ())
                    if not set(candidates) & columns:
                        continue
                    identifiers = _IDENTIFIER_COLUMNS.get(table, ())
                    fields = [f for f in candidates + _TIMESTAMP_COLUMNS + identifiers if f in columns]
                    query, parameters = _build_table_query(table, fields, selected_projects)
                    cursor = conn.execute(query, parameters)
                    while page := cursor.fetchmany(1000):
                        result['limits']['pages_inspected'] += 1
                        for row in page:
                            if limit is not None and len(result['records']) >= limit:
                                result['limits']['truncated'] = True
                                uncertain('database_row_limit_exceeded')
                                truncated = True
                                break
                            if account:
                                account(_row_bytes(row))
                            record = dict(table=table, **dict(zip(fields, row)))
                            observe_value(record)
                            for field in identifiers:
                                if field in record:
                                    record[field + '_sha256'] = _digest(record.pop(field))
                            result['records'].append(record)
                            result['limits']['rows_inspected'] += 1
                        if truncated:
                            break
                measured = True
    except (OSError, sqlite3.Error) as exc:
        if measured and isinstance(exc, ReadOnlyDbError) and exc.reason == 'race_detected':
            changed = True
        else:
            result['records'].clear()
            result['limits']['rows_inspected'] = 0
            uncertain('database_snapshot_or_read_failed')
    if changed:
        result['changed_during_read'] = True
        if not any(u['reason'] == 'database_snapshot_or_read_failed' for u in result['uncertainties']):
            uncertain('database_snapshot_or_read_failed')
    _associations(result, selected_projects)
    return result
