"""Bounded, read-only kanban measurements. Prose stays inside SQLite.

Source references refer to the audited Hermes source, not this plugin. Retry
context is RECONSTRUCTED from the text stored today (today's body, comments
older than the run, closed runs that ended before it); it is not a recording of
any prompt nor the complete kanban_show JSON response. The schema keeps no body
history, so a first-run figure is an estimate when a body-edit event exists.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
import math
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from statistics import median
import time

from .contract import make_component_envelope, make_finding
from .policy import credential_path
from .readonly_db import (ReadOnlyDbError, _db_or_wal_changed,
                          open_readonly_sqlite, stat_db_identity)

MAX_ROWS = 200000
MAX_LINKS = 50000
MAX_ENTRIES = 50000
MAX_SQL_STEPS = 10000000
MAX_GRAPH_STEPS = 1000000
MAX_SECONDS = 15
MAX_PATH_CHARS = 4096
MAX_METADATA_CHARS = 1048576
MAX_JSON_NODES = 10000
DAY = 86400
# Hermes kanban_db_context.py:23-27,50-57: misleading BYTES names actually
# slice characters, strip whitespace and APPEND a visible truncation suffix.
BODY_CAP, COMMENT_CAP, FIELD_CAP = 8192, 2048, 4096
COMMENT_LIMIT, ATTEMPT_LIMIT = 30, 10
# Hermes kanban_db.py:115,871-877; NOT consecutive_failures or max_retries.
BLOCK_THRESHOLD = 2
# Hermes kanban_ops.py:308-309; gc_events in kanban_db.py:4013-4024.
GC_DAYS = 30
# Review thresholds: a busy board is mostly agent tasks, mostly archived and heavy in
# heartbeat events; retried tasks can rebuild several times their first context and
# archived logs grow to megabytes. The values separate that residue from a fresh board.
# Not safety limits.
CONTEXT_CHARS, CONTEXT_RATIO = 20000, 3
AGENT_SHARE, AGENT_MIN_TASKS, UNKNOWN_SHARE = .8, 20, .2
ARCHIVED_SHARE, ARCHIVED_LOG_BYTES = .8, 1000000
HEARTBEAT_SHARE, HEARTBEAT_MIN_EVENTS = .5, 500
NEVER_RUN_SHARE, WORKSPACE_MIN, MACHINE_SHARE = .1, 5, .5
RETRY_LOOP_RUNS, NEVER_RUN_DAYS, INACTIVE_DAYS = 4, 7, 14
# Hermes kanban_workflow.py:27-28,114-123 and kanban_db.py:928-930,3889.
STATUSES = ('triage', 'todo', 'scheduled', 'ready', 'running', 'blocked', 'review', 'done', 'archived')
OUTCOMES = ('completed', 'blocked', 'crashed', 'timed_out', 'spawn_failed',
            'gave_up', 'reclaimed', 'scheduled', 'released', 'failed')
# Hermes kanban_db.py:777-798,858-900,910-934. No separate archived flag.
COLUMNS = {
    'tasks': {'id', 'body', 'status', 'created_by', 'created_at', 'completed_at',
              'workspace_path', 'project_id', 'session_id', 'block_recurrences', 'assignee'},
    'task_comments': {'id', 'task_id', 'author', 'body', 'created_at'},
    'task_events': {'id', 'task_id', 'kind', 'payload', 'created_at'},
    'task_runs': {'id', 'task_id', 'profile', 'status', 'outcome', 'summary',
                  'error', 'metadata', 'started_at', 'ended_at'},
    'task_links': {'parent_id', 'child_id'},
}
# Python str.strip whitespace; SQL trim keeps all source prose inside SQLite.
WHITESPACE = ''.join(chr(c) for c in (*range(9, 14), *range(28, 33), 133, 160,
                                     5760, *range(8192, 8203), 8232, 8233, 8239, 8287, 12288))
# Body edits are recorded as events whose JSON payload lists the field names:
# kanban_db.py:3084 ('edited', {"fields": [...]}) and kanban_db.py:3778-3781
# ('specified', {"changed_fields": [...]}). Only the fixed marker '"body"' is
# searched with instr(); no payload text leaves SQLite.
BODY_EDIT_KINDS = ('edited', 'specified')
# The report boundary keeps a string only if it is closed vocabulary or the
# absolute path of an item that exists; any other string becomes a per-run HMAC
# token that hides it and changes the stored report on every run. So a board is
# identified by the absolute path of its database file (found by lstat, inside
# the home, never a symlink), plus a kind label; task IDs and workspace folder
# names never leave this module (counts only); months are integers.
# Fixed consequence sentences: persistence keeps a consequence only when it is
# exactly one of the sealed sentences, so no measured number is interpolated.
# The numbers travel in each finding's evidence under numeric keys; the limits
# named here are the module constants below (checked by a test).
CONSEQUENCES = {
    'retry_context_growth': ('Rebuilt from text stored today, a retried task would hand its latest worker more '
                             'characters of its own body, comments and earlier attempts than at its first run, above '
                             'the review limit of 20,000 characters or three times the first-run figure; Hermes caps '
                             'each item but not the total. The first-run figure uses today\'s body and is an estimate '
                             'when the body was edited after that run. This is a reconstruction from stored rows, not a '
                             'recording of any prompt, and it describes left-over data, not a current fault.'),
    'blocked_loops': ('At least one task has four or more runs with no completed run or reached Hermes\'s '
                      'repeated-block limit of 2; these are stored records of past attempts, not a current fault, '
                      'and do not show whether another attempt would succeed.'),
    'agent_authored_board': ('At least 80% of a board\'s tasks, on a board of 20 or more tasks, carry an agent-side '
                             'author marker (worker, decomposer or a profile that ran tasks); the marker names the '
                             'writing surface, not who asked for the work, and work done through the default chat '
                             'profile counts as user-side.'),
    'archived_never_collected': ('Archived tasks still keep their logs and all their rows: more than 1,000,000 bytes '
                                 'of archived-task logs, or a board at least 80% archived with events more than 30 '
                                 'days older than its newest event; the audit cannot tell whether clean-up was ever run.'),
    'heartbeat_bloat': ('More than half of a board\'s stored events, on a board of 500 or more events, are worker '
                        'heartbeats; this counts retained rows, not whether the work made progress.'),
    'never_run_backlog': ('More than 10% of a board\'s tasks have no recorded run and were created more than seven '
                          'days before the reference time; this counts stored rows, not why they never ran.'),
    'workspaces_inside_home': ('Five or more tasks store a workspace path inside the Hermes home but outside '
                               'Hermes\'s own kanban workspaces folder; this counts stored paths, not files that are '
                               'safe to delete.'),
    'orphan_board_folders': ('One or more board folders hold board metadata but no database; the audit does not '
                             'tell how they came to be that way.'),
    'machine_paths_in_tasks': ('More than half of a board\'s task bodies or of its comments contain a home-style '
                               'absolute path marker; this counts text markers, not whether those paths exist on '
                               'this machine.'),
    'could_not_verify': 'Some kanban measurements could not be verified within the supported schema and read budgets; missing coverage is not a clean result.',
}


class _Stop(Exception):
    """Global budget exhausted: stop every board."""


class _BoardStop(Exception):
    """This board's data is unusable: stop this board only."""


class _Budget:
    def __init__(self, clock):
        self.clock = clock
        self.deadline = clock() + MAX_SECONDS
        self.reasons = set()
        self.steps = self.entries = self.graph_steps = self.cuts = 0
        self.symlinks = 0

    def cut(self, reason):
        self.reasons.add(reason)
        self.cuts += 1

    def check(self):
        if self.clock() >= self.deadline:
            self.cut('time_budget')
            raise _Stop

    def progress(self):
        self.steps += 1000
        try:
            self.check()
        except _Stop:
            return 1
        if self.steps > MAX_SQL_STEPS:
            self.cut('sql_steps')
            return 1
        return 0


def _safe_stat(path, root, budget):
    """lstat every component under the authorized root; never resolve links."""
    if not path.is_relative_to(root) or '..' in path.parts:
        budget.cut('outside_profile')
        return None
    current = root
    st = None
    for part in ('', *path.relative_to(root).parts):
        if part:
            current = current / part
        if credential_path(current):
            budget.cut('credential_path')
            return None
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return None
        except OSError:
            budget.cut('unreadable')
            return None
        if stat.S_ISLNK(st.st_mode):
            budget.symlinks += 1
            budget.cut('symlink')
            return None
    return st


@contextmanager
def _open_user_db(path):
    """The sole user-database opener; no migrations, copies or sidecar creation.

    Follows the audit-wide rule of the shared opener (docs/audit-scope.md):
    no -wal or an empty -wal -> mode=ro&immutable=1 with a post-read identity
    check; -wal with frames and an existing -shm (a running Hermes holds the
    board open) -> mode=ro, where only the existing -shm read marks may change;
    -wal with frames but no -shm -> refused (wal_needs_index); a rollback
    journal -> refused (hot_journal). Nothing is ever created beside the DB.
    """
    path = Path(path)
    if credential_path(path) or any(p.is_symlink() for p in (path, *path.parents)):
        raise ReadOnlyDbError('unsafe path', reason='unreadable')
    for suffix in ('-wal', '-shm', '-journal'):
        if Path(str(path) + suffix).is_symlink():
            raise ReadOnlyDbError('unsafe sidecar', reason='unreadable')
    with open_readonly_sqlite(path, timeout=.1) as opened:
        yield opened


# Shared-opener refusal reasons that are reported under their own name; every
# other opener failure is database_unreadable. Busy/locked is database_in_use.
OPENER_REASONS = ('wal_needs_index', 'hot_journal')


def _busy(exc):
    """True for SQLite busy/locked errors (the text is tested, never output)."""
    for err in (exc, getattr(exc, '__cause__', None)):
        if isinstance(err, sqlite3.OperationalError) and re.search(r'\b(locked|busy)\b', str(err), re.I):
            return True
    return False


# Numeric keys copied from the growth example into the finding evidence.
RETRY_EVIDENCE_KEYS = ('runs', 'first_worker_chars', 'latest_worker_chars', 'first_run_body_edited_later',
                       'first_uncapped_chars', 'latest_uncapped_chars', 'current_uncapped_chars', 'growth_ratio')


def _finding(rule, evidence, classification='review_suggested', coverage='verified', source='kanban.db'):
    return make_finding(rule_id='kanban_residue.' + rule, classification=classification,
                        coverage=coverage, affected_identities=['kanban'], source_paths=[source],
                        evidence=evidence, consequence=CONSEQUENCES[rule])


def _entries(path, root, budget):
    st = _safe_stat(path, root, budget)
    if st is None:
        return []
    if not stat.S_ISDIR(st.st_mode):
        budget.cut('unreadable')
        return []
    found = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                budget.check()
                budget.entries += 1
                if budget.entries > MAX_ENTRIES:
                    budget.cut('directory_entries')
                    break
                found.append(Path(entry.path))
    except OSError:
        budget.cut('unreadable')
    return sorted(found)


def _schema(conn):
    for table, expected in COLUMNS.items():
        # Triggers/indexes may share a name with a table; only tables pass.
        row = conn.execute("SELECT type, sql FROM sqlite_master WHERE name=? AND type IN ('table','view') "
                           "ORDER BY type LIMIT 1", (table,)).fetchone()
        if not row or row[0] != 'table' or re.search(r'\b(VIRTUAL|WITHOUT\s+ROWID)\b', row[1] or '', re.I):
            return False
        columns = conn.execute('SELECT name, hidden FROM pragma_table_xinfo(?) LIMIT 256', (table,)).fetchall()
        if len(columns) == 256 or any(r[1] for r in columns) or not expected <= {r[0] for r in columns}:
            return False
    return True


def _label(field, labels, otherwise='unclassified'):
    values = ','.join("'" + s + "'" for s in labels)
    return f"CASE WHEN {field} IN ({values}) THEN {field} ELSE '{otherwise}' END"


def _length(field, strip=False):
    value = f'trim({field}, :ws)' if strip else field
    return f"CASE WHEN typeof({field})='text' THEN length({value}) ELSE 0 END"


def _markers(field):
    return f"CASE WHEN typeof({field})='text' AND (instr({field},'/home/')>0 OR instr({field},'/Users/')>0 OR instr({field},'C:\\')>0) THEN 1 ELSE 0 END"


def _author(field, marker='0'):
    # tools/kanban_tools.py:139-150: tool author = current profile or worker;
    # kanban.py:202-205: CLI = current profile or user; gateway/
    # kanban_watchers_dispatcher.py:291: auto-decomposer. Default is an
    # interactive-side heuristic only: default chat can itself invoke tools.
    # Explicit user/default labels win over an originating chat session marker.
    return (f"CASE WHEN {field} IN ('user','default') THEN 'user' "
            f"WHEN {marker} OR {field} IN ('worker','auto-decomposer') THEN 'agent' "
            f"WHEN {field} IN (SELECT profile FROM (SELECT profile FROM task_runs LIMIT {MAX_ROWS}) "
            "WHERE profile NOT IN ('default','user') AND profile IS NOT NULL) THEN 'agent' "
            "ELSE 'unclassified' END")


def _cap(n, cap):
    return n if n <= cap else cap + len(f'… [truncated, {n-cap} chars omitted]')


def _distribution(values):
    values = sorted(values)
    return {'median': median(values) if values else None,
            'p90': values[max(0, math.ceil(len(values) * .9) - 1)] if values else None,
            'max': values[-1] if values else None}


def _trees(tasks, edges, budget):
    children = defaultdict(set)
    indegrees = dict.fromkeys(tasks, 0)
    for parent, child in edges:
        if parent not in tasks or child not in tasks:
            budget.cut('dangling_links')
            continue
        if child not in children[parent]:
            indegrees[child] += 1
            children[parent].add(child)
    roots = [key for key, degree in indegrees.items() if degree == 0]
    queue, depth, order = deque(roots), dict.fromkeys(tasks, 0), []
    while queue:
        budget.check()
        node = queue.popleft()
        order.append(node)
        for child in children[node]:
            depth[child] = max(depth[child], depth[node] + 1)
            indegrees[child] -= 1
            if not indegrees[child]:
                queue.append(child)
    cycles = int(len(order) != len(tasks))
    if cycles:
        budget.cut('graph_cycle')
    largest = 0
    for root in roots:
        seen, pending = set(), [root]
        while pending:
            budget.check()
            budget.graph_steps += 1
            if budget.graph_steps > MAX_GRAPH_STEPS:
                budget.cut('graph_steps')
                raise _Stop
            node = pending.pop()
            if node not in seen:
                seen.add(node)
                pending.extend(children[node] - seen)
        largest = max(largest, len(seen))
    return {'links': len(edges), 'roots': len(roots), 'deepest_chain': max(depth.values(), default=0),
            'largest_tree': largest, 'widest_fanout': max(map(len, children.values()), default=0), 'cycles': cycles}


def _metadata_length(conn, run_id, raw_length, budget):
    """Count json.dumps(..., ensure_ascii=False, sort_keys=True) characters
    without returning any JSON text: kanban_db_context.py:67-73 and
    kanban_db.py:703-714. Key ordering does not change serialized length.
    Duplicate keys and integers outside SQLite's exact range are unverified.
    """
    budget.check()
    if raw_length > MAX_METADATA_CHARS:
        budget.cut('metadata_chars')
        return 0
    valid = conn.execute("SELECT json_valid(metadata) FROM task_runs WHERE id=? LIMIT 1", (run_id,)).fetchone()[0]
    if not valid:
        budget.cut('metadata_invalid')
        return 0  # Hermes _json_or returns None for malformed input.
    values = conn.execute('''
        WITH nodes AS MATERIALIZED (
          SELECT j.id, j.parent, j.key, j.type, j.atom FROM task_runs r,
            json_tree(r.metadata) j WHERE r.id=? LIMIT ?
        ), children AS (
          SELECT parent, count(*) n, count(DISTINCT key) d FROM nodes
            WHERE parent IS NOT NULL GROUP BY parent
        )
        SELECT count(*),
          coalesce(sum(CASE WHEN type IN ('array','object') THEN 2
            WHEN type IN ('true','null') THEN 4 WHEN type='false' THEN 5
            WHEN type='real' THEN audit_number_chars(atom)
            ELSE length(json_quote(atom)) END
            + CASE WHEN typeof(key)='text' THEN length(json_quote(key))+2 ELSE 0 END),0)
            + coalesce((SELECT sum(2*(n-1)) FROM children),0),
          coalesce(sum(type='integer' AND typeof(atom)='real'),0),
          coalesce((SELECT sum(n!=d) FROM children),0),
          (SELECT CASE WHEN type IN ('null','false') OR
              (type IN ('integer','real') AND atom=0) OR (type='text' AND atom='') OR
              (type IN ('array','object') AND (SELECT count(*) FROM nodes)=1)
            THEN 1 ELSE 0 END FROM nodes WHERE parent IS NULL LIMIT 1)
        FROM nodes
    ''', (run_id, MAX_JSON_NODES + 1)).fetchone()
    count, size, real, duplicate, falsey = values
    if count > MAX_JSON_NODES:
        budget.cut('metadata_nodes')
        return 0
    if real or duplicate:
        budget.cut('metadata_normalization')
    return 0 if falsey else size


def _measure(conn, root, home, budget, reference_time, partial):
    # The UDF receives ONLY numeric atoms, never JSON/string source content.
    conn.create_function('audit_number_chars', 1, lambda value: len(json.dumps(value)), deterministic=True)
    params = {'ws': WHITESPACE, 'home': home.rstrip('/') + '/', 'plen': len(home.rstrip('/')) + 1}
    def rows(table, projection):
        budget.check()
        return conn.execute(f'SELECT {projection} FROM (SELECT * FROM {table} LIMIT {MAX_ROWS})', params).fetchall()

    counts = {}
    for table in COLUMNS:
        cap = min(MAX_ROWS, MAX_LINKS) if table == 'task_links' else MAX_ROWS
        count = conn.execute(f'SELECT count(*) FROM (SELECT 1 FROM {table} LIMIT ?)', (cap + 1,)).fetchone()[0]
        if count > cap:
            budget.cut('links' if table == 'task_links' else 'table_rows')
        counts[table] = min(count, cap)
        partial[{'task_comments': 'comments', 'task_events': 'events', 'task_runs': 'runs', 'task_links': 'links'}.get(table, table)] = min(count, cap)
    for table, fields in (('tasks', ('body',)), ('task_comments', ('body',)),
                          ('task_runs', ('summary', 'error', 'metadata'))):
        invalid = ' OR '.join(f"(typeof({f}) NOT IN ('null','text') OR instr({f},char(0))>0)" for f in fields)
        if conn.execute(f'SELECT count(*) FROM (SELECT * FROM {table} LIMIT {MAX_ROWS}) WHERE ' + invalid).fetchone()[0]:
            budget.cut('invalid_values')
    if conn.execute(f'SELECT count(*) FROM (SELECT workspace_path FROM tasks LIMIT {MAX_ROWS}) WHERE length(workspace_path)>?', (MAX_PATH_CHARS,)).fetchone()[0]:
        budget.cut('path_chars')
    body_raw, body_trim = _length('body'), _length('body', True)
    task_rows = rows('tasks',
        'substr(id,1,64), ' + _label('status', STATUSES) + ', ' + _author('created_by', "session_id IS NOT NULL AND session_id!=''") +
        f', created_at, completed_at, block_recurrences, {body_raw}, {body_trim}, {_markers("body")}, '
        "CASE WHEN project_id IS NOT NULL AND project_id!='' THEN 1 ELSE 0 END, "
        "CASE WHEN typeof(workspace_path)='text' AND substr(workspace_path,1,:plen)=:home "
        f"AND length(workspace_path)<= {MAX_PATH_CHARS} THEN substr(workspace_path,:plen+1) END")
    tasks = {r[0]: r for r in task_rows}
    if any(not isinstance(k, str) or not re.fullmatch(r't_[0-9a-f]{8}', k) for k in tasks):
        budget.cut('invalid_task_id')
    comments = rows('task_comments', 'id, substr(task_id,1,64), ' + _author('author') +
                    f', created_at, {body_raw}, {body_trim}, {_markers("body")}')
    runs = rows('task_runs', 'id, substr(task_id,1,64), started_at, ended_at, ' +
                "CASE WHEN outcome IS NULL THEN 'active' ELSE " + _label('outcome', OUTCOMES) + ' END, ' +
                ', '.join(_length(f) for f in ('summary', 'error', 'metadata')) + ', ' +
                ', '.join(_length(f, True) for f in ('summary', 'error')) + ', ' +
                "CASE WHEN metadata IS NULL OR metadata='' THEN 0 ELSE 1 END")
    runs = [(*r[:10], _metadata_length(conn, r[0], r[7], budget) if r[10] else 0) for r in runs]
    events = rows('task_events', "substr(task_id,1,64), created_at, kind='heartbeat', kind='decomposed'")
    kinds = ','.join("'" + k + "'" for k in BODY_EDIT_KINDS)
    body_edits = defaultdict(list)
    budget.check()
    for tid_, stamp in conn.execute(f"SELECT substr(task_id,1,64), created_at FROM (SELECT * FROM task_events LIMIT {MAX_ROWS}) "
                                    f"WHERE kind IN ({kinds}) AND typeof(payload)='text' AND instr(payload,'\"body\"')>0").fetchall():
        if isinstance(stamp, (int, float)):
            body_edits[tid_].append(stamp)
    default_runs = conn.execute(f"SELECT count(*) FROM (SELECT profile FROM task_runs LIMIT {MAX_ROWS}) "
                                "WHERE profile='default'").fetchone()[0]
    edges = conn.execute('SELECT substr(parent_id,1,64), substr(child_id,1,64) FROM task_links LIMIT ?',
                         (min(MAX_ROWS, MAX_LINKS),)).fetchall()
    # Aggregates (not source prose) cross the SQLite boundary. Each table's
    # unique-row prefix is bounded even when several projections inspect it.
    volumes = {}
    for name, table, fields in (('bodies', 'tasks', ('body',)), ('comments', 'task_comments', ('body',)),
                                 ('run_summaries', 'task_runs', ('summary',)), ('run_errors', 'task_runs', ('error',)),
                                 ('run_metadata', 'task_runs', ('metadata',))):
        volumes[name] = conn.execute('SELECT coalesce(sum(' + '+'.join(_length(f) for f in fields) +
                                    f'),0) FROM (SELECT * FROM {table} LIMIT {MAX_ROWS})').fetchone()[0]
    for row in task_rows:
        if not isinstance(row[3], (int, float)) or not isinstance(row[5], int):
            budget.cut('invalid_values')
            raise _BoardStop
    for row in (*comments, *runs):
        stamp = row[3] if len(row) == 7 else row[2]
        if not isinstance(stamp, (int, float)):
            budget.cut('invalid_values')
            raise _BoardStop
    if any(not isinstance(e[1], (int, float)) for e in events):
        budget.cut('invalid_values')
        raise _BoardStop
    newest = max((e[1] for e in events), default=None)
    reference = reference_time if reference_time is not None else newest
    dates = [t[3] for t in task_rows] + [e[1] for e in events] + [r[2] for r in runs]
    def month(value):
        try:
            stamp = datetime.fromtimestamp(value, timezone.utc)
            return stamp.year * 100 + stamp.month  # YYYYMM as an integer
        except (ValueError, OverflowError, OSError):
            budget.cut('invalid_values')
            return None
    by_comment, by_run, activity = defaultdict(list), defaultdict(list), {}
    for c in comments:
        by_comment[c[1]].append(c)
        activity[c[1]] = max(activity.get(c[1], 0), c[3])
    for r in runs:
        if r[3] is not None and not isinstance(r[3], (int, float)):
            budget.cut('invalid_values')
            raise _BoardStop
        by_run[r[1]].append(r)
        activity[r[1]] = max(activity.get(r[1], 0), r[3] or r[2])
    for e in events:
        activity[e[0]] = max(activity.get(e[0], 0), e[1])
    retry = []
    loops = Counter(four_runs_without_completion=0, repeated_block_threshold=0,
                    repeated_block_nonzero=0, max_block_recurrences=0,
                    never_run=0, never_run_older_than_seven_days=0, open_inactive_over_fourteen_days=0)
    workspaces = []
    for tid, t in tasks.items():
        budget.check()
        rs = sorted(by_run[tid], key=lambda r: (r[2], r[0]))
        cs = sorted(by_comment[tid], key=lambda c: (c[3], c[0]))
        loops['four_runs_without_completion'] += len(rs) >= RETRY_LOOP_RUNS and not any(r[4] == 'completed' for r in rs)
        loops['repeated_block_threshold'] += t[5] >= BLOCK_THRESHOLD
        loops['repeated_block_nonzero'] += t[5] > 0
        loops['max_block_recurrences'] = max(loops['max_block_recurrences'], t[5])
        loops['never_run'] += not rs
        if reference is not None:
            loops['never_run_older_than_seven_days'] += not rs and reference - t[3] > NEVER_RUN_DAYS * DAY
            loops['open_inactive_over_fourteen_days'] += (t[1] not in ('done', 'archived') and
                reference - max(t[3], activity.get(tid, 0)) > INACTIVE_DAYS * DAY)
        if t[10] is not None:
            path = root / t[10]
            st = _safe_stat(path, root, budget)
            parts = Path(t[10]).parts
            # Hermes's own scratch roots, strictly below them: kanban_db.py:569-572,
            # kanban_db_workspace.py:312-320,347-349.
            managed = ((parts[:2] == ('kanban', 'workspaces') and len(parts) > 2) or
                       (parts[:2] == ('kanban', 'boards') and len(parts) > 4 and parts[3] == 'workspaces'))
            # Counted only: no folder name leaves the module.
            workspaces.append({'exists': bool(st and stat.S_ISDIR(st.st_mode)), 'managed': managed})
        if len(rs) < 2:
            continue
        def payload(at):
            prior = [r for r in rs if r[0] != at[0] and r[3] is not None and r[3] < at[2] and (r[2], r[0]) < (at[2], at[0])]
            notes = [c for c in cs if c[3] < at[2]]
            worker = _cap(t[7], BODY_CAP) + sum(_cap(c[5], COMMENT_CAP) for c in notes[-COMMENT_LIMIT:])
            worker += sum(_cap(r[8], FIELD_CAP) + _cap(r[9], FIELD_CAP) + _cap(r[10], FIELD_CAP) for r in prior[-ATTEMPT_LIMIT:])
            raw = t[6] + sum(c[4] for c in notes) + sum(sum(r[5:8]) for r in prior)
            return worker, raw
        first, first_raw = payload(rs[0])
        latest, latest_raw = payload(rs[-1])
        # The schema keeps no body history: today's body stands in for the
        # first run's. An edit event at/after the first start makes it an estimate.
        edited_later = any(stamp >= rs[0][2] for stamp in body_edits.get(tid, ()))
        retry.append({'_order': str(tid),
                      'runs': len(rs), 'first_worker_chars': first, 'latest_worker_chars': latest,
                      'first_run_body_edited_later': edited_later,
                      'first_uncapped_chars': first_raw, 'latest_uncapped_chars': latest_raw,
                      'current_uncapped_chars': t[6] + sum(c[4] for c in cs) + sum(sum(r[5:8]) for r in rs),
                      'growth_ratio': latest / first if first else None})
    authorship = {}
    for name, data, index in (('tasks', task_rows, 2), ('comments', comments, 2)):
        authorship[name] = {key: sum(row[index] == key for row in data) for key in ('agent', 'user', 'unclassified')}
    for prefix, name, count in (('task', 'tasks', len(task_rows)), ('comment', 'comments', len(comments))):
        for kind in ('agent', 'user', 'unclassified'):
            authorship[prefix + '_' + kind + '_share'] = authorship[name][kind] / count if count else None
    authorship['default_profile_runs'] = default_runs
    authorship['coverage'] = 'could_not_verify' if any(authorship[n]['unclassified'] > counts[t] * UNKNOWN_SHARE
        for n, t in (('tasks', 'tasks'), ('comments', 'task_comments'))) else 'verified'
    if authorship['coverage'] != 'verified':
        budget.cut('authorship_unclassified')
    retry.sort(key=lambda r: (-r['latest_worker_chars'], r['_order']))
    growth = [r for r in retry if r['latest_worker_chars'] > CONTEXT_CHARS or r['latest_worker_chars'] > CONTEXT_RATIO * r['first_worker_chars']]
    # The example is the qualifying task retried most often (then largest).
    growth.sort(key=lambda r: (-r['runs'], -r['latest_worker_chars'], r['_order']))
    for r in retry:
        del r['_order']  # internal tie-break only; task IDs are not output
    archived = sum(t[1] == 'archived' for t in task_rows)
    old = [e for e in events if reference is not None and reference - e[1] > GC_DAYS * DAY]
    result = {'tasks': counts['tasks'], 'comments': counts['task_comments'], 'events': counts['task_events'],
              'runs': counts['task_runs'], 'tasks_by_status': dict(sorted(Counter(t[1] for t in task_rows).items())),
              'runs_by_outcome': dict(sorted(Counter(r[4] for r in runs).items())),
              'archived_share': archived / len(task_rows) if task_rows else 0,
              'date_range': [month(min(dates)), month(max(dates))] if dates else [],
              'authorship': authorship, 'trees': _trees(tasks, edges, budget),
              'retry_context': {'retried_tasks': len(retry), 'top_tasks': retry[:10],
                  'growth_tasks': len(growth), 'growth_example': growth[0] if growth else None,
                  'first_worker_chars': _distribution([r['first_worker_chars'] for r in retry]),
                  'latest_worker_chars': _distribution([r['latest_worker_chars'] for r in retry]),
                  'growth_ratio': _distribution([r['growth_ratio'] for r in retry if r['growth_ratio'] is not None]),
                  'historical_body_verified': False, 'complete_prompt_measured': False},
              'loops': dict(loops), 'events_older_than_gc_window': len(old),
              'gc_eligible_events': sum(e[0] in tasks and tasks[e[0]][1] in ('done', 'archived') and not e[3] for e in old),
              'heartbeat_events': sum(e[2] for e in events),
              'heartbeat_share': sum(e[2] for e in events) / len(events) if events else 0,
              'machine_binding': {'bodies_with_home_paths': sum(t[8] for t in task_rows),
                  'body_home_path_share': sum(t[8] for t in task_rows) / len(task_rows) if task_rows else None,
                  'comment_home_path_share': sum(c[6] for c in comments) / len(comments) if comments else None,
                  'comments_with_home_paths': sum(c[6] for c in comments), 'workspaces_inside_home': len(workspaces),
                  'workspaces_in_kanban_scratch_root': sum(w['managed'] for w in workspaces),
                  'workspace_folders_existing': sum(w['exists'] for w in workspaces),
                  'tasks_linked_to_project': sum(t[9] for t in task_rows)},
              'text_volume': volumes}
    return result, {tid for tid, t in tasks.items() if t[1] == 'archived'}, reference


def _log_stats(directory, root, archived, reference, budget):
    result = dict(count=0, bytes=0, largest_bytes=0, archived_count=0, archived_bytes=0,
                  older_than_gc_window=0, rotated_count=0)
    # kanban_db.py:586-589,4043-4046; kanban_worker_log.py:9-10,32-33.
    for path in _entries(directory, root, budget):
        budget.check()
        # Name first: lock files, credential-named and other entries are not
        # logs and are skipped without even an lstat (no cut: nothing missed).
        match = re.fullmatch(r'(t_[0-9a-f]{8})\.log(\.\d+)?', path.name)
        if not match:
            continue
        st = _safe_stat(path, root, budget)
        if st is None or not stat.S_ISREG(st.st_mode):
            continue
        result['count'] += 1
        result['bytes'] += st.st_size
        result['largest_bytes'] = max(result['largest_bytes'], st.st_size)
        result['rotated_count'] += bool(match[2])
        result['older_than_gc_window'] += reference is not None and reference - st.st_mtime > GC_DAYS * DAY
        if match[1] in archived:
            result['archived_count'] += 1
            result['archived_bytes'] += st.st_size
    return result


def audit_kanban_residue(*, profile_path, db_path=None, reference_time=None, home_path=None, clock=None):
    """Audit only the supplied home. home_path maps historical backup paths;
    db_path replaces the main DB (e.g. a renamed backup), never expands scope.
    No environment lookup, implicit sibling-profile traversal or file writes.
    """
    root = Path(os.path.abspath(profile_path))
    home = str(home_path) if home_path is not None else str(root)
    clock = clock or time.monotonic
    started = clock()
    budget = _Budget(clock)
    boards, findings, candidates, orphan, sources = [], [], [], 0, {}
    extra_log_dirs = []
    logs = dict(count=0, bytes=0, largest_bytes=0, archived_count=0, archived_bytes=0,
                older_than_gc_window=0, rotated_count=0)
    # kanban_db.py:401-415,485-498,563-589: default DB at home root;
    # named boards have kanban.db, board.json and logs in their directory.
    main = Path(db_path) if db_path is not None else root / 'kanban.db'
    if not main.is_absolute():
        main = root / main
    try:
        st = _safe_stat(main, root, budget)
        if st is not None:
            candidates.append(('default', False, main, root / 'kanban/logs'))
        else:
            extra_log_dirs.append(root / 'kanban/logs')
        folders = _entries(root / 'kanban/boards', root, budget)
        # kanban_db_boards.py:146-175: one extra archive level, never a
        # recursive home walk. Archive directory names include an epoch suffix.
        folders += _entries(root / 'kanban/boards/_archived', root, budget)
        for folder in folders:
            if folder.name == '_archived' or folder.name.startswith('._'):
                continue
            st = _safe_stat(folder, root, budget)
            if st is None or not stat.S_ISDIR(st.st_mode):
                continue
            archived_folder = folder.parent.name == '_archived'
            pattern = r'[a-z0-9][a-z0-9_-]{0,63}-[0-9]{1,20}(?:-[0-9]{1,20})?' if archived_folder else r'[a-z0-9][a-z0-9_-]{0,63}'
            if not re.fullmatch(pattern, folder.name):
                budget.cut('invalid_board_name')
                continue
            database = folder / 'kanban.db'
            db_st = _safe_stat(database, root, budget)
            metadata = _safe_stat(folder / 'board.json', root, budget)
            if folder.name == 'default':
                continue  # default metadata directory does not hold its own DB
            if db_st is not None:
                candidates.append((folder.name, archived_folder, database, folder / 'logs'))
            elif metadata is not None and stat.S_ISREG(metadata.st_mode):
                orphan += 1
                extra_log_dirs.append(folder / 'logs')
        for directory in extra_log_dirs:
            measured = _log_stats(directory, root, set(), reference_time, budget)
            for key, value in measured.items():
                logs[key] = max(logs[key], value) if key == 'largest_bytes' else logs[key] + value
        for name, archived_board, path, log_dir in candidates:
            budget.check()
            before_cuts = budget.cuts
            partial = {'board': 'default' if name == 'default' else 'named_board', 'path': str(path),
                       'archived_board': archived_board, 'coverage': 'could_not_verify', 'status': 'not_measured'}
            sources[id(partial)] = str(path)
            boards.append(partial)
            try:
                with _open_user_db(path) as (conn, identity):
                    conn.set_progress_handler(budget.progress, 1000)
                    conn.execute('PRAGMA trusted_schema=OFF')
                    if not _schema(conn):
                        budget.cut('schema_unsupported')
                        continue
                    result, archived, reference = _measure(conn, root, home, budget, reference_time, partial)
                    after = stat_db_identity(path)
                    if (_db_or_wal_changed(identity, after) or
                            os.path.lexists(str(path) + '-journal')):
                        budget.cut('database_changed')
                partial.update(result, status='completed')
                measured_logs = _log_stats(log_dir, root, archived, reference, budget)
                for key, value in measured_logs.items():
                    logs[key] = max(logs[key], value) if key == 'largest_bytes' else logs[key] + value
                partial['logs'] = measured_logs
                partial['coverage'] = 'could_not_verify' if budget.cuts > before_cuts else 'verified'
            except _BoardStop:
                pass  # cut already recorded; the remaining boards are still measured
            except ReadOnlyDbError as exc:
                if budget.cuts == before_cuts:
                    reason = getattr(exc, 'reason', None)
                    budget.cut(reason if reason in OPENER_REASONS else
                               'database_in_use' if _busy(exc) else 'database_unreadable')
            except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
                if budget.cuts == before_cuts:
                    budget.cut('database_in_use' if _busy(exc) else 'database_unreadable')
    except _Stop:
        pass
    for b in boards:
        if 'retry_context' not in b or not b.get('tasks'):
            continue
        source, cov = sources.get(id(b), 'kanban.db'), b['coverage']
        top = b['retry_context']['growth_example']
        if top:
            # Flat numeric evidence only; a null ratio (zero first figure) is omitted.
            evidence = {k: top[k] for k in RETRY_EVIDENCE_KEYS if top.get(k) is not None}
            evidence['growth_tasks'] = b['retry_context']['growth_tasks']
            findings.append(_finding('retry_context_growth', evidence, 'review_suggested', cov, source))
        loops, auth, mb, logs_b = b['loops'], b['authorship'], b['machine_binding'], b.get('logs', {})
        if loops['four_runs_without_completion'] or loops['repeated_block_threshold']:
            findings.append(_finding('blocked_loops', {
                'four_runs_without_completion': loops['four_runs_without_completion'],
                'repeated_block_threshold': loops['repeated_block_threshold'],
                'repeated_block_nonzero': loops['repeated_block_nonzero'],
                'max_block_recurrences': loops['max_block_recurrences'],
                'repeated_block_limit': BLOCK_THRESHOLD}, 'review_suggested', cov, source))
        if (b['tasks'] >= AGENT_MIN_TASKS and auth['coverage'] == 'verified' and
                auth['tasks']['agent'] / b['tasks'] >= AGENT_SHARE):
            findings.append(_finding('agent_authored_board', {
                'tasks': b['tasks'], 'agent_tasks': auth['tasks']['agent'], 'user_tasks': auth['tasks']['user'],
                'unclassified_tasks': auth['tasks']['unclassified']}, 'info', cov, source))
        aged = b['archived_share'] >= ARCHIVED_SHARE and b['gc_eligible_events'] > 0
        archived_logs = logs_b.get('archived_bytes', 0)
        if aged or archived_logs > ARCHIVED_LOG_BYTES:
            findings.append(_finding('archived_never_collected', {
                'archived_share': b['archived_share'], 'gc_eligible_events': b['gc_eligible_events'],
                'archived_log_bytes': archived_logs}, 'review_suggested', cov, source))
        if b['events'] >= HEARTBEAT_MIN_EVENTS and b['heartbeat_share'] > HEARTBEAT_SHARE:
            findings.append(_finding('heartbeat_bloat', {
                'events': b['events'], 'heartbeat_events': b['heartbeat_events'],
                'heartbeat_share': b['heartbeat_share']}, 'info', cov, source))
        if loops['never_run_older_than_seven_days'] / b['tasks'] > NEVER_RUN_SHARE:
            findings.append(_finding('never_run_backlog', {
                'tasks': b['tasks'], 'never_run': loops['never_run'],
                'never_run_older_than_seven_days': loops['never_run_older_than_seven_days']}, 'info', cov, source))
        # Hermes's own scratch root holds every scratch task's path by design,
        # so only paths elsewhere inside the home count toward the trigger.
        other_ws = mb['workspaces_inside_home'] - mb['workspaces_in_kanban_scratch_root']
        if other_ws >= WORKSPACE_MIN:
            findings.append(_finding('workspaces_inside_home', {
                'workspaces_inside_home': mb['workspaces_inside_home'],
                'workspaces_in_kanban_scratch_root': mb['workspaces_in_kanban_scratch_root'],
                'workspaces_outside_kanban_scratch_root': other_ws}, 'review_suggested', cov, source))
        if (mb['bodies_with_home_paths'] / b['tasks'] > MACHINE_SHARE or
                mb['comments_with_home_paths'] / max(1, b['comments']) > MACHINE_SHARE):
            findings.append(_finding('machine_paths_in_tasks', {
                'tasks': b['tasks'], 'comments': b['comments'],
                'bodies_with_home_paths': mb['bodies_with_home_paths'],
                'comments_with_home_paths': mb['comments_with_home_paths']}, 'info', cov, source))
    if orphan:
        findings.append(_finding('orphan_board_folders', {'orphan_board_folders': orphan}, 'info',
                                 source=str(root / 'kanban/boards')))
    if budget.reasons:
        findings.append(_finding('could_not_verify', {'cuts': budget.cuts}, 'info', 'could_not_verify'))
    coverage = 'could_not_verify' if budget.reasons else 'verified'
    present = any(b.get('tasks', 0) or b.get('events', 0) or b.get('comments', 0) or b.get('runs', 0) for b in boards) or orphan or logs['count']
    section = {'status': 'completed' if present else ('not_measured' if budget.reasons else 'not_present'),
               'coverage': coverage, 'boards': boards, 'databases_found': len(candidates),
               'orphan_board_folders': orphan, 'logs': logs, 'gc_ever_run': 'could_not_verify',
               'reference_clock': 'injected' if reference_time is not None else 'newest_event',
               'limits': {'max_rows_per_table': MAX_ROWS, 'max_links': MAX_LINKS, 'max_entries': MAX_ENTRIES,
                          'max_seconds': MAX_SECONDS, 'max_sql_steps': MAX_SQL_STEPS,
                          'max_graph_steps': MAX_GRAPH_STEPS, 'max_metadata_chars': MAX_METADATA_CHARS,
                          'max_json_nodes': MAX_JSON_NODES, 'max_path_chars': MAX_PATH_CHARS, 'cuts': budget.cuts,
                          'symlinks_skipped': budget.symlinks}, 'truncated_by': sorted(budget.reasons)}
    # Everything that depends on the caller's clock or an override lives here,
    # outside the deterministic section (the section's ages are relative to
    # each board's newest event unless reference_time is given and echoed).
    run_metrics = {'elapsed_seconds': round(max(0.0, clock() - started), 3),
                   'reference_time_override': reference_time}
    envelope = make_component_envelope(findings=findings, coverage=coverage,
                                       extra={'kanban_residue': section, 'run_metrics': run_metrics})
    # Exactly the keys adapt_component_result reads (status is the legacy
    # pass/fail it records as legacy_status_ignored; run_metrics passes through).
    return {k: envelope[k] for k in ('kanban_residue', 'findings', 'run_metrics', 'status', 'coverage')}
