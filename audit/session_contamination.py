"""Bounded private metrics. Immutable only without WAL at open, with post-read
identity checks: mode=ro alone creates sidecars beside cleanly closed WAL stores.
No transcript text or session IDs escape.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from statistics import median

from .contract import make_component_envelope, make_finding
from .policy import credential_path
from .readonly_db import ReadOnlyDbError, _db_or_wal_changed, open_readonly_sqlite, stat_db_identity, session_wal_has_frames
from .skill_hygiene import _finding
from .vendor.profile_context import MEMORY_BLOCK_HEADERS

MAX_SESSIONS = 10000  # Primary-key order gives reproducible bounded samples.
MAX_MESSAGES = 50000  # Global per-run message row budget.
MAX_MESSAGES_PER_SESSION = 5000  # Per-session message row budget; prevents one session starving the run.
MAX_METADATA_BYTES = 4096  # Bound IDs/paths before SQLite returns them to Python.
MAX_TEXT_BYTES = 1024 * 1024  # SQL slices bytes before crossing the Python boundary (per prompt/message).
MAX_BLOCKS_PER_MESSAGE = 1024  # Maximum recalled memory-context blocks counted per message.
MAX_TOTAL_TEXT_BYTES = 32 * 1024 * 1024  # Aggregate transcript parse budget.
MESSAGE_PAGE_SIZE = 256  # Keyset pagination batch size for message headers.
# No database-size refusal: real stores exceed 1 GiB. Default first-pass logical
# row results: 10,001 session keys + 10,000 metadata + 10,000 prompts + <=196
# global message-key pages (50,001 rows including lookahead) + 50,000 message bodies.
# One bounded recheck doubles this, excluding bounded schema metadata (DDL <=64 KiB).
# Python receives <=32 MiB text/metadata initially; rereads stop at the first
# difference, so <=65 MiB total (32 + 32 + at most one 1 MiB changed result).
# Numeric result fields, SQLite caches/index pages, and length()/bounded-prefix CAST internal
# reads are not included in that byte cap: this is NOT a physical disk-I/O cap.
# All data scans are indexed, SQL work has a VM cap, and time is cooperative.
MAX_SECONDS = 20  # Wall-clock budget, checked between bounded reads/batches.
MAX_SQL_STEPS = 10000000  # Progress-handler VM budget prevents unindexed quadratic scans.
MAX_PROJECT_ENTRIES = 10000  # Static names only; no project source is read.
MIN_PROJECT_SESSIONS = 3  # Avoid a warning based on a single exploratory conversation.
FOREIGN_RATE_THRESHOLD = 0.25  # A quarter of classifiable sessions prompts review.
GROWTH_FACTOR = 2.0  # Require relative AND absolute growth, avoiding small baselines.
GROWTH_CHARS = 4000
# Hermes hermes_state.py:181,204: per-profile canonical store.
DATABASE_NAME = 'state.db'
# Hermes hermes_state_common.py:461-492,531-540; dedup schema :456-459,478.
SESSION_COLUMNS = frozenset({'id', 'cwd', 'git_repo_root', 'system_prompt', 'started_at',
                             'message_count', 'source', 'parent_session_id'})
MESSAGE_COLUMNS = frozenset({'session_id', 'role', 'content', 'timestamp'})
# Hermes agent/memory_context.py:169-185. Parse tags with a single forward scan.
OPEN_FENCE, CLOSE_FENCE = '<memory-context>', '</memory-context>'
# Hermes tools/memory_tool_store.py:320-322,674-680; reuse vendor titles, use usage
# character count to end each block (there is NO closing fence). Never count later prompt prose.
SEP = '═' * 46
MEMORY_HEADER = re.compile(re.escape(SEP) + r'\n(?:' + '|'.join(re.escape(v) for v in MEMORY_BLOCK_HEADERS.values())
                           + r') \[\d+% — ([\d,]{1,20})/[\d,]{1,20} chars\]\n' + re.escape(SEP) + r'\n')
# Whole-word, case-insensitive signatures; English-word families java/ruby/unity/
# rust/go/swift require an adjacent code cue (below), never capitalization alone.
# No bare node/react/blueprint or .c/.h; C filenames need >=2 stem characters.
# Version digits after C++/C# are accepted. Docker/Kubernetes are neutral.
TECH_PATTERNS = {
    'python': r'python|pip|django|fastapi',
    'javascript': r'javascript|typescript|node\.js|nodejs|npm|jsx|tsx',
    'java': r'maven|gradle|spring boot',
    'cpp': r'c\+\+\d*|cpp|cmake|clang|(?<![a-z0-9_-])[a-z0-9_][a-z0-9_-]{1,127}+\.[ch](?:pp)?|\.[ch]pp',
    'csharp': r'c#\d*|\.net|dotnet|nuget',
    'rust': r'rustlang|rustc|cargo|(?<![a-z0-9_-])[a-z0-9_][a-z0-9_-]{0,127}+\.rs|\.rs',
    'go': r'golang|go\.mod|go build',
    'php': r'php|composer|laravel',
    'ruby': r'ruby on rails',
    'swift': r'xcode|swiftlang',
    'kotlin': r'kotlin|android',
    'unreal': r'unreal',
    'unity': r'(?!)', 'godot': r'godot|gdscript',
    'blender': r'blender', 'houdini': r'houdini',
}
# Require whitespace adjacency to a technical noun or numeric version. Existing
# explicit signatures (go build, rustc, ruby on rails, etc.) remain independent.
CODE_CUE = r'(?:language|lang|code|project|crate|package|sdk|v?\d++(?:\.\d++)*)'
CODE_CUE_BEFORE = r'(?:language|lang|code|project|crate|package|sdk|(?<!\d\.)v?\d++(?:\.\d++)*+)'
for _family in ('java', 'ruby', 'unity', 'rust', 'go', 'swift'):
    TECH_PATTERNS[_family] += (r'|' + _family + r'\s+' + CODE_CUE +
                              r'|' + CODE_CUE_BEFORE + r'\s+' + _family)
TECH_RE = {family: re.compile(r'(?<![\w])(?:' + pattern + r')(?![\w])', re.I)
           for family, pattern in TECH_PATTERNS.items()}
EXTENSIONS = {'.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
              '.java': 'java', '.c': 'cpp', '.cpp': 'cpp', '.h': 'cpp', '.hpp': 'cpp', '.cs': 'csharp',
              '.rs': 'rust', '.go': 'go', '.php': 'php', '.rb': 'ruby', '.swift': 'swift', '.kt': 'kotlin',
              '.uproject': 'unreal', '.unity': 'unity', '.gd': 'godot', '.blend': 'blender', '.hip': 'houdini'}
MARKERS = {'pyproject.toml': 'python', 'requirements.txt': 'python', 'package.json': 'javascript',
           'pom.xml': 'java', 'build.gradle': 'java', 'CMakeLists.txt': 'cpp', 'Cargo.toml': 'rust',
           'go.mod': 'go', 'composer.json': 'php', 'Gemfile': 'ruby', 'Package.swift': 'swift', 'project.godot': 'godot'}


def technology_counts(text):
    counts = Counter()
    for family, pattern in TECH_RE.items():
        n = sum(1 for _ in pattern.finditer(text))
        if n:
            counts[family] = n
    return counts


def memory_blocks(prompt):
    blocks, malformed = [], 0
    end = 0
    for match in MEMORY_HEADER.finditer(prompt):
        if match.start() < end:
            continue
        length = int(match[1].replace(',', ''))
        end = match.end() + length
        if end > len(prompt):
            malformed += 1
        else:
            blocks.append((prompt[match.start():end], prompt[match.end():end]))
    return blocks, malformed


_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def _scan_recalled_blocks(text):
    # ASCII-only case folding preserves offsets even with U+0130 before a tag.
    byte_cap = MAX_TEXT_BYTES
    block_cap = min(MAX_BLOCKS_PER_MESSAGE, MAX_MESSAGES)
    if len(text) <= byte_cap and text.isascii():
        byte_truncated = False
    else:
        raw = text[:byte_cap].encode('utf-8', errors='surrogatepass')
        byte_truncated = len(text) > byte_cap or len(raw) > byte_cap
        if byte_truncated:
            text = raw[:byte_cap].decode('utf-8', errors='ignore')
    folded = text.translate(_ASCII_LOWER)
    blocks, cursor, block_truncated = [], 0, False
    while True:
        start = folded.find(OPEN_FENCE, cursor)
        if start < 0:
            break
        start += len(OPEN_FENCE)
        end = folded.find(CLOSE_FENCE, start)
        if end < 0:
            break  # Never retry later openers against the same unterminated suffix.
        if len(blocks) >= block_cap:
            block_truncated = True
            break
        blocks.append(text[start:end])
        cursor = end + len(CLOSE_FENCE)
    return blocks, byte_truncated, block_truncated


def recalled_blocks(text):
    return _scan_recalled_blocks(text)[0]


def _text_parts(value):
    # Hermes agent/turn_context.py:113-144: api_content holds string injections;
    # multimodal list turns carry durable text parts. Don't count both sidecar and content.
    if value.lstrip().startswith('['):
        try:
            parts = json.loads(value)
            if isinstance(parts, list):
                return '\n'.join(p['text'] for p in parts if isinstance(p, dict)
                                 and p.get('type') == 'text' and isinstance(p.get('text'), str))
        except (ValueError, RecursionError):
            return value
    return value


def _project(root):
    path = Path(root)
    if (not path.is_absolute() or credential_path(path) or
            any(p.is_symlink() for p in (path, *path.parents)) or not path.is_dir()):
        return set(), 'project_missing', 0
    ignored = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'target', 'dist', 'build'}
    families, pending, count, dirs_seen = set(), [path], 0, 0
    try:
        while pending:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    p = Path(entry.path)
                    if entry.is_symlink() or credential_path(p):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in ignored:
                            if dirs_seen >= MAX_PROJECT_ENTRIES:
                                return families, ('partial' if families else 'could_not_verify'), 1
                            dirs_seen += 1
                            pending.append(p)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if count >= MAX_PROJECT_ENTRIES:
                        return families, 'partial', 1
                    count += 1
                    family = EXTENSIONS.get(p.suffix.lower()) or MARKERS.get(p.name)
                    if family:
                        families.add(family)
    except OSError:
        return families, 'could_not_verify', 0
    return families, ('verified' if families else 'could_not_verify'), 0


def _same_project(candidate, project, spellings):
    """True when `candidate` is `project` or inside it by resolved path or folder identity."""
    from .facts import _is_registered_folder, _registered_folder_keys
    if project not in spellings:
        real_paths, identities, _ = _registered_folder_keys([str(project)])
        spellings[project] = (real_paths, identities, tuple(Path(p) for p in real_paths))
    real_paths, identities, roots = spellings[project]
    try:
        real = Path(os.path.realpath(candidate))
    except (OSError, ValueError):
        return False
    if any(real.is_relative_to(root) for root in roots):
        return True
    return _is_registered_folder(str(candidate), real_paths, identities)


@contextmanager
def _open_database(path, state):
    # Same live-WAL contract as registration reads: DB/WAL never written;
    # SQLite's reader-owned SHM read marks are not evidence of a writer.
    if credential_path(path) or any(p.is_symlink() for p in (path, *path.parents)):
        raise ReadOnlyDbError('unsafe database path', reason='unreadable')
    if os.path.lexists(str(path) + '-journal'):
        raise ReadOnlyDbError('rollback journal present', reason='hot_journal')
    measured = False
    try:
        with open_readonly_sqlite(path, timeout=0.1) as (conn, before):
            if before.size == 0:
                raise ReadOnlyDbError('empty database', reason='corrupt_header')
            conn.execute('PRAGMA trusted_schema=OFF')
            state['read_mode'] = 'mode=ro' if session_wal_has_frames(before) else 'immutable'
            state['wal_mode'] = before.wal_mode
            try:
                yield conn
                measured = True
            finally:
                after = stat_db_identity(path)
                state['changed_during_read'] |= _db_or_wal_changed(before, after)
                if state['read_mode'] == 'immutable':
                    state['changed_during_read'] |= before.shm_identity != after.shm_identity
                state['changed_during_read'] |= os.path.lexists(str(path) + '-journal')
    except ReadOnlyDbError as exc:
        if exc.reason != 'race_detected' or not measured:
            raise
        # Keep measured counts but explicitly invalidate their coverage.
        state['changed_during_read'] = True


def _failure_reason(exc):
    # Never persist SQLite messages (they may include source values/SQL).
    cause = exc.__cause__ if isinstance(exc, ReadOnlyDbError) and exc.__cause__ else exc
    code = getattr(cause, 'sqlite_errorcode', 0) & 255
    if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        return 'busy_or_locked'
    if code in (sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_CORRUPT):
        return 'not_sqlite'
    if isinstance(exc, ReadOnlyDbError):
        if exc.reason in {'missing', 'hot_journal', 'wal_needs_index'}:
            return exc.reason
        if exc.reason in {'corrupt_header', 'corrupt_db'}:
            return 'not_sqlite'
        return 'unreadable' if exc.reason != 'sqlite_error' else 'read_error'
    return 'unreadable' if isinstance(exc, OSError) else 'read_error'


def _text_projection(expression):
    # SQLite must still read the value to compute character length (and may load
    # its overflow pages internally). Python receives at most cap UTF-8 bytes:
    # slice TEXT first, then cast only that bounded prefix, then enforce byte cap.
    return ('length(' + expression + '), substr(CAST(substr(' + expression +
            ',1,?) AS BLOB),1,?)')


def _decode_bounded_text(raw, characters, byte_cap):
    data = raw or b''
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        if byte_cap > 0 and len(data) == byte_cap and exc.start >= len(data) - 3:
            cut_kind = 'file_byte_limit_exceeded' if byte_cap >= MAX_TEXT_BYTES else 'total_byte_limit_exceeded'
            return data[:exc.start].decode('utf-8', errors='ignore'), False, cut_kind
        return data.decode('utf-8', errors='replace'), False, 'invalid_values'
    if characters is None or len(text) == characters:
        return text, True, None
    cut_kind = 'file_byte_limit_exceeded' if byte_cap >= MAX_TEXT_BYTES else 'total_byte_limit_exceeded'
    return text, False, cut_kind


def _decode_prefix(raw, characters):
    text, complete, _ = _decode_bounded_text(raw, characters, MAX_TEXT_BYTES)
    return text, complete


def _rows_digest(rows):
    # Ephemeral comparison only; neither row bodies nor digests leave this reader.
    return hashlib.sha256(repr(tuple(tuple(r) for r in rows)).encode('utf-8')).digest()


MAX_SCHEMA_SQL_CHARS = 65536


def _columns(conn, table):
    row = conn.execute(
        'SELECT type, substr(sql,1,?), length(sql) FROM sqlite_master WHERE name=?',
        (MAX_SCHEMA_SQL_CHARS, table),
    ).fetchone()
    if (row is None or row[0] != 'table' or (row[2] is not None and row[2] > MAX_SCHEMA_SQL_CHARS) or
            re.search(r'\b(?:VIRTUAL|WITHOUT\s+ROWID)\b', row[1] or '', re.I)):
        return set()
    info = list(conn.execute('PRAGMA table_xinfo("' + table + '")'))
    if len(info) > 256 or any(r[6] for r in info):  # Hidden and generated columns are not Hermes schema.
        return set()
    key = 'hash' if table == 'system_prompts' else 'id'
    if [r[1] for r in info if r[5]] != [key]:
        return set()
    if table == 'messages':
        if not any(r[1] == 'id' and r[2].upper() == 'INTEGER' for r in info):
            return set()
        # A true rowid alias has no separate primary-key index. In particular,
        # column-level INTEGER PRIMARY KEY DESC does, and permits NULL IDs.
        # Use SQLite's parsed schema rather than regex-parsing SQL declarations.
        if any(r[3] == 'pk' for r in conn.execute('PRAGMA index_list("messages")')):
            return set()
    return {r[1] for r in info}


def _summary(rows):
    result = {'sessions_examined': len(rows), 'sessions_classified': sum(r['classified'] for r in rows),
              'sessions_with_foreign_memory': sum(bool(r['foreign']) for r in rows),
              'memory_context_blocks': sum(r['recall_count'] for r in rows),
              'memory_context_chars': sum(r['recall_chars'] for r in rows),
              'native_term_occurrences': sum(r['native'] for r in rows)}
    foreign = Counter()
    for row in rows:
        foreign.update(row['foreign'])
    result['foreign_families'] = dict(sorted(foreign.items()))
    result['contamination_rate'] = (result['sessions_with_foreign_memory'] / result['sessions_classified']
                                    if result['sessions_classified'] else None)
    for metric, key in (('system_prompt', 'prompt_chars'), ('memory_block', 'memory_chars')):
        sizes = [r[key] for r in rows if r[key] is not None]
        result['median_' + metric + '_chars'] = median(sizes) if sizes else None
        result['max_' + metric + '_chars'] = max(sizes) if sizes else None
    result['sessions_without_prompt'] = sum(r['prompt_chars'] is None for r in rows)
    return result


def _contamination_report(rows, projects, findings, path, outside, limits, cut_reasons, state):
    grouped, months = defaultdict(list), defaultdict(list)
    for row in rows:
        grouped[row['project_root']].append(row)
        if row['month'] and row['prompt_chars'] is not None:
            months[row['month']].append(row['prompt_chars'])
    project_rows = []
    for root, prows in sorted(grouped.items()):
        summary = _summary(prows)
        project_rows.append({'project_root': root, 'coverage': projects[root][1], 'project_coverage': projects[root][1],
                             'project_families': sorted(projects[root][0]), **summary})
        if summary['sessions_classified'] >= MIN_PROJECT_SESSIONS and summary['contamination_rate'] >= FOREIGN_RATE_THRESHOLD:
            evidence = {**summary, 'project_root': root}
            findings.append(_finding('session_contamination.foreign_memory_in_project', root, evidence, classification='warning'))
    overall = _summary(rows)
    monthly = [{'year': y, 'month': m, 'sessions_examined': len(values), 'median_system_prompt_chars': median(values)}
               for (y, m), values in sorted(months.items())]
    if len(monthly) >= 2:
        first, last = monthly[0]['median_system_prompt_chars'], monthly[-1]['median_system_prompt_chars']
        if last >= first * GROWTH_FACTOR and last - first >= GROWTH_CHARS:
            findings.append(_finding('session_contamination.system_prompt_growth', path,
                                      {'earliest_chars': first, 'latest_chars': last, 'growth_chars': last - first}))
    if overall['memory_context_blocks']:
        findings.append(_finding('session_contamination.external_memory_injection_observed', path,
                                  {'memory_context_blocks': overall['memory_context_blocks'],
                                   'memory_context_chars': overall['memory_context_chars']}))
    coverage = 'could_not_verify' if (state['changed_during_read'] or limits['cuts'] or
                                      any(not r['classified'] for r in rows)) else 'verified'
    if state.get('truncated_by'):
        state['reason'] = state['truncated_by']
    section = {'sessions_outside_registered_projects': outside, 'coverage': coverage, 'status': 'completed', 'overall': overall, 'projects': project_rows,
               'top_projects': sorted(project_rows, key=lambda r: (-(r['contamination_rate'] or 0), r['project_root']))[:10],
               'system_prompt_by_month': monthly, 'limits': limits, 'cut_reasons': sorted(cut_reasons), **state,
               'immutable': state['read_mode'] == 'immutable', 'database_copied': False,
               'thresholds': {'min_project_sessions': MIN_PROJECT_SESSIONS, 'foreign_rate': FOREIGN_RATE_THRESHOLD,
                              'growth_factor': GROWTH_FACTOR, 'growth_chars': GROWTH_CHARS}}
    return make_component_envelope(findings=findings, coverage=coverage, extra={'session_contamination': section})


def audit_session_contamination(*, profile_path, sessions: bool = False, selected_projects=()):
    if type(sessions) is not bool:
        raise ValueError('sessions must be a boolean')
    if not sessions:
        return make_component_envelope(coverage='not_included', extra={
            'session_contamination': {'status': 'not_run', 'coverage': 'not_included'}})
    path = Path(profile_path) / DATABASE_NAME
    limits = {'max_sessions': MAX_SESSIONS, 'max_messages': MAX_MESSAGES, 'max_metadata_bytes': MAX_METADATA_BYTES,
              'max_file_bytes': MAX_TEXT_BYTES,
              'max_bytes': MAX_TOTAL_TEXT_BYTES, 'max_database_bytes': None,
              'max_project_entries': MAX_PROJECT_ENTRIES, 'max_sql_steps': MAX_SQL_STEPS, 'cuts': 0,
              'bytes_read': 0, 'messages_examined': 0}
    state = {'read_mode': 'mode=ro', 'wal_mode': False, 'changed_during_read': False}
    deadline = time.monotonic() + MAX_SECONDS
    limits['max_seconds'] = MAX_SECONDS
    cut_reasons = set()
    interrupted_by = None

    def record_cut(reason, *, cap_hit=False):
        limits['cuts'] += 1
        cut_reasons.add(reason)
        if cap_hit:
            state.setdefault('truncated_by', reason)

    def expired():
        if time.monotonic() < deadline:
            return False
        if 'time_budget' not in cut_reasons:
            limits['cuts'] += 1
            cut_reasons.add('time_budget')
        state.setdefault('truncated_by', 'time_budget')
        return True

    findings, rows, projects, by_session = [], [], {}, {}
    selected = sorted({Path(os.path.abspath(p)) for p in selected_projects},
                      key=lambda p: (-len(p.parts), str(p)))
    outside = 0
    spellings = {}
    error_rule = 'session_contamination.database_unreadable'
    try:
        with _open_database(path, state) as conn:
            steps = 0
            def progress():
                nonlocal steps, interrupted_by
                steps += 1000
                if expired():
                    interrupted_by = 'time_budget'
                    return 1
                if steps > MAX_SQL_STEPS:
                    if 'sql_steps' not in cut_reasons:
                        limits['cuts'] += 1
                        cut_reasons.add('sql_steps')
                    state.setdefault('truncated_by', 'sql_steps')
                    interrupted_by = 'sql_steps'
                    return 1
                return 0
            conn.set_progress_handler(progress, 1000)
            sc, mc = _columns(conn, 'sessions'), _columns(conn, 'messages')
            if not SESSION_COLUMNS <= sc or not MESSAGE_COLUMNS <= mc or 'rowid' in sc:
                error_rule = 'session_contamination.schema_unsupported'
                raise ValueError('unsupported schema')
            join = ''
            prompt = 's.system_prompt'
            if 'system_prompt_hash' in sc:
                if not {'hash', 'prompt'} <= _columns(conn, 'system_prompts'):
                    error_rule = 'session_contamination.schema_unsupported'
                    raise ValueError('unsupported prompt schema')
                # Hermes hermes_state.py:516-524; schema migration clears inline text
                # (hermes_state_schema.py:189-202). Count deduplicated stored prompts too.
                join = ' LEFT JOIN system_prompts p ON p.hash=s.system_prompt_hash'
                prompt = 'COALESCE(s.system_prompt,p.prompt)'
            # Hermes schema: sessions.id and system_prompts.hash are primary keys;
            # messages.id is INTEGER PRIMARY KEY. Never sort the entire store
            # by started_at or timestamp; timestamps do not define pagination.
            rechecks = []
            def read(query, parameters=()):
                batch = conn.execute(query, parameters).fetchall()
                rechecks.append((query, parameters, _rows_digest(batch)))
                return batch

            session_keys = 'SELECT rowid FROM sessions ORDER BY id LIMIT ?'
            message_keys = 'SELECT id FROM messages WHERE id>? ORDER BY id LIMIT ?'
            # Reject lookalike schemas that would turn bounded queries into full
            # sorts/scans. EXPLAIN does not execute the queries or read transcript data.
            for sql, parameters in ((session_keys, (MAX_SESSIONS + 1,)), (message_keys, (-9223372036854775808, 1))):
                plan = [r[3] for r in conn.execute('EXPLAIN QUERY PLAN ' + sql, parameters)]
                if any('TEMP B-TREE' in p or 'AUTOMATIC' in p or 'SCAN messages' in p for p in plan):
                    error_rule = 'session_contamination.schema_unsupported'
                    raise ValueError('unindexed schema')
            keys = read(session_keys, (MAX_SESSIONS + 1,))
            if len(keys) > MAX_SESSIONS:
                record_cut('table_rows', cap_hit=True)
            for (rowid,) in keys[:MAX_SESSIONS]:
                if expired():
                    break
                if limits['bytes_read'] >= MAX_TOTAL_TEXT_BYTES:
                    record_cut('total_byte_limit_exceeded', cap_hit=True)
                    break
                # Three independent fields, each <=4 KiB; don't overshoot the
                # aggregate byte cap even when the next metadata row is malicious.
                cap = min(MAX_METADATA_BYTES, (MAX_TOTAL_TEXT_BYTES - limits['bytes_read']) // 3)
                metadata = ', '.join(
                    f"CASE WHEN typeof({field})='text' AND length(CAST(substr({field},1,?) AS BLOB)) <= ? THEN {field} END"
                    for field in ('id', 'cwd', 'git_repo_root'))
                metadata_cut_sql = ' OR '.join(
                    f'length(CAST(substr({field},1,?) AS BLOB)) > ?' for field in ('id', 'cwd', 'git_repo_root'))
                meta_params = (cap + 1, cap) * 6 + (rowid,)
                records = read('SELECT ' + metadata + ", CASE WHEN typeof(started_at) IN ('integer','real') THEN started_at END, "
                               'CASE WHEN ' + metadata_cut_sql + ' THEN 1 ELSE 0 END FROM sessions WHERE rowid=?', meta_params)
                if not records:
                    state['changed_during_read'] = True
                    continue
                sid, cwd, gitroot, stamp, metadata_cut = records[0]
                limits['bytes_read'] += sum(len(v.encode('utf-8')) for v in (sid, cwd, gitroot) if isinstance(v, str))
                if metadata_cut:
                    cut_reason = 'metadata_byte_budget' if cap >= MAX_METADATA_BYTES else 'total_byte_limit_exceeded'
                    record_cut(cut_reason, cap_hit=True)
                    continue
                if not isinstance(sid, str):
                    record_cut('invalid_values')
                    continue
                # Session paths are association evidence, never permission to walk.
                # Use only an authorized root, not a historical nested directory.
                candidate = cwd if isinstance(cwd, str) else None
                matched = None
                if candidate and Path(candidate).is_absolute():
                    lexical = Path(os.path.normpath(candidate))
                    matched = next((p for p in selected if lexical.is_relative_to(p)), None)
                    if matched is None:
                        # Started through another spelling of a selected project (a linked
                        # projects folder): compare resolved paths, then folder identity.
                        # Metadata only: the session folder is never opened or walked.
                        matched = next((p for p in selected if _same_project(lexical, p, spellings)), None)
                if matched is None:
                    outside += 1
                    continue
                try:
                    if not isinstance(stamp, (int, float)) or stamp <= 0:
                        raise ValueError('invalid session time')
                    date = datetime.fromtimestamp(stamp, timezone.utc)
                    month = (date.year, date.month)
                except (ValueError, TypeError, OverflowError, OSError):
                    month = None
                    record_cut('invalid_values')
                root = str(matched)
                if root not in projects:
                    projects[root] = _project(root)
                    if projects[root][2]:
                        record_cut('entry_limit_exceeded', cap_hit=True)
                families, project_coverage, _ = projects[root]
                cap = min(MAX_TEXT_BYTES, MAX_TOTAL_TEXT_BYTES - limits['bytes_read'])
                # Fetch text only for the bounded, selected sessions analysed below;
                # SQL computes snapshot lengths, including deduplicated prompts.
                prompt_query = ('SELECT ' + _text_projection(prompt) +
                                ' FROM sessions s' + join + ' WHERE s.rowid=?')
                records = read(prompt_query, (cap, cap, rowid))
                if not records:
                    state['changed_during_read'] = True
                    continue
                prompt_chars, raw = records[0]
                limits['bytes_read'] += len(raw or b'')
                text, complete, prompt_cut = _decode_bounded_text(raw, prompt_chars, cap)
                if not complete:
                    record_cut(prompt_cut, cap_hit=prompt_cut != 'invalid_values')
                    blocks, malformed = [], 0
                else:
                    blocks, malformed = memory_blocks(text)
                    if malformed:
                        record_cut('invalid_values')
                memory_chars = sum(len(b[0]) for b in blocks) if complete and not malformed else None
                terms = technology_counts('\n'.join(b[1] for b in blocks))
                classified = bool(families) and project_coverage in {'verified', 'partial'} and complete and not malformed
                row = {'project_root': root, 'prompt_chars': prompt_chars, 'memory_chars': memory_chars,
                       'classified': classified, 'foreign': {}, 'native': 0,
                       'terms': terms, 'families': families,
                       'recall_count': 0, 'recall_chars': 0, 'month': month,
                       'messages_seen': 0, 'session_cap_cut': False}
                rows.append(row)
                by_session[sid] = row
            # One global INTEGER PRIMARY KEY seek in bounded pages, never per-session timestamp sorts.
            # Include the minimum signed rowid, then use strict id keyset paging.
            last = -9223372036854775808
            first = True
            messages_complete = True
            expr = 'COALESCE(api_content,content)' if 'api_content' in mc else 'content'
            while by_session:
                if expired():
                    messages_complete = False
                    break
                if limits['bytes_read'] >= MAX_TOTAL_TEXT_BYTES:
                    record_cut('total_byte_limit_exceeded', cap_hit=True)
                    messages_complete = False
                    break
                page_limit = min(MESSAGE_PAGE_SIZE, max(1, MAX_MESSAGES - limits['messages_examined'] + 1))
                key_query = (
                    "SELECT id, "
                    "CASE WHEN typeof(session_id)='text' AND length(CAST(substr(session_id,1,?) AS BLOB)) <= ? THEN session_id END, "
                    "CASE WHEN typeof(session_id)='text' AND length(CAST(substr(session_id,1,?) AS BLOB)) > ? THEN 1 ELSE 0 END, "
                    "CASE WHEN typeof(timestamp) IN ('integer','real') THEN timestamp END "
                    "FROM messages WHERE id" + ('>=?' if first else '>?') + ' ORDER BY id LIMIT ?'
                )
                page = read(key_query, (MAX_METADATA_BYTES + 1, MAX_METADATA_BYTES,
                                        MAX_METADATA_BYTES + 1, MAX_METADATA_BYTES,
                                        last, page_limit))
                first = False
                if not page:
                    break
                stop_messages = False
                for mid, sid, sid_cut, mstamp in page:
                    if expired():
                        messages_complete = False
                        stop_messages = True
                        break
                    if limits['bytes_read'] >= MAX_TOTAL_TEXT_BYTES:
                        record_cut('total_byte_limit_exceeded', cap_hit=True)
                        messages_complete = False
                        stop_messages = True
                        break
                    if limits['messages_examined'] >= MAX_MESSAGES:
                        record_cut('database_row_limit_exceeded', cap_hit=True)
                        messages_complete = False
                        stop_messages = True
                        break
                    sid_bytes = len((sid or '').encode('utf-8'))
                    if sid_bytes > MAX_TOTAL_TEXT_BYTES - limits['bytes_read']:
                        record_cut('total_byte_limit_exceeded', cap_hit=True)
                        messages_complete = False
                        stop_messages = True
                        break
                    last = mid
                    limits['messages_examined'] += 1
                    limits['bytes_read'] += sid_bytes
                    if sid_cut:
                        record_cut('metadata_byte_budget', cap_hit=True)
                        continue
                    if sid is None or not isinstance(mstamp, (int, float)):
                        record_cut('invalid_values')
                    row = by_session.get(sid)
                    if row is None:
                        continue
                    if row['messages_seen'] >= MAX_MESSAGES_PER_SESSION:
                        if not row['session_cap_cut']:
                            row['session_cap_cut'] = True
                            row['classified'] = False
                            record_cut('row_cap', cap_hit=True)
                        if all(r['session_cap_cut'] for r in by_session.values()):
                            messages_complete = False
                            stop_messages = True
                            break
                        continue
                    row['messages_seen'] += 1
                    if limits['bytes_read'] >= MAX_TOTAL_TEXT_BYTES:
                        record_cut('total_byte_limit_exceeded', cap_hit=True)
                        row['classified'] = False
                        messages_complete = False
                        stop_messages = True
                        break
                    cap = min(MAX_TEXT_BYTES, MAX_TOTAL_TEXT_BYTES - limits['bytes_read'])
                    message_query = 'SELECT ' + _text_projection(expr) + ' FROM messages WHERE id=?'
                    found = read(message_query, (cap, cap, mid))
                    if not found:
                        state['changed_during_read'] = True
                        row['classified'] = False
                        continue
                    size, mraw = found[0]
                    limits['bytes_read'] += len(mraw or b'')
                    message_text, message_complete, msg_cut = _decode_bounded_text(mraw, size, cap)
                    if not message_complete:
                        record_cut(msg_cut, cap_hit=msg_cut != 'invalid_values')
                        row['classified'] = False
                        if msg_cut == 'invalid_values':
                            continue
                    recalled, byte_cut, block_cut = _scan_recalled_blocks(_text_parts(message_text))
                    if byte_cut and message_complete:
                        record_cut('file_byte_limit_exceeded', cap_hit=True)
                        row['classified'] = False
                    if block_cut:
                        record_cut('limit_exceeded', cap_hit=True)
                        row['classified'] = False
                    row['recall_count'] += len(recalled)
                    row['recall_chars'] += sum(map(len, recalled)) + len(recalled) * (len(OPEN_FENCE) + len(CLOSE_FENCE))
                    for block in recalled:
                        row['terms'].update(technology_counts(block))
                if stop_messages or len(page) < page_limit:
                    break
            for row in rows:
                row['classified'] &= messages_complete
                if row['classified']:
                    row['foreign'] = {f: n for f, n in row['terms'].items() if f not in row['families']}
                    row['native'] = sum(n for f, n in row['terms'].items() if f in row['families'])
            # All cursors are exhausted: autocommit rereads now see later commits,
            # unlike rereading inside one pinned transaction. Same bounded SQL and
            # parameters; compare only ephemeral digests, as registration reads do.
            for query, parameters, digest in rechecks:
                if expired():
                    break
                if _rows_digest(conn.execute(query, parameters).fetchall()) != digest:
                    state['changed_during_read'] = True
                    break
    except (OSError, sqlite3.Error, ValueError) as exc:
        if (getattr(exc, 'sqlite_errorcode', 0) & 255) == sqlite3.SQLITE_INTERRUPT and (interrupted_by or state.get('truncated_by')):
            # A progress-handler cut is not an unreadable database. Retain measured
            # prompt/recall counts; unfinished message coverage cannot classify.
            for row in rows:
                row['classified'] = False
                row['foreign'], row['native'] = {}, 0
        else:
            reason = 'schema_unsupported' if error_rule.endswith('schema_unsupported') else _failure_reason(exc)
            findings.append(_finding(error_rule, path, {'cuts': limits['cuts'], 'reason': reason}, 'could_not_verify'))
            return make_component_envelope(findings=findings, coverage='could_not_verify', extra={
                'session_contamination': {'coverage': 'could_not_verify', 'status': 'not_measured', 'reason': reason,
                                          'limits': limits, **state, 'immutable': state['read_mode'] == 'immutable', 'database_copied': False}})
    if state['changed_during_read']:
        findings.append(make_finding(
            rule_id='session_contamination.database_changed_during_read', classification='info',
            coverage='could_not_verify', affected_identities=[str(path)], source_paths=[str(path)],
            evidence={'changed_during_read': True},
            consequence='Counts may be off by the sessions written during the read.'))
    return _contamination_report(rows, projects, findings, path, outside, limits, cut_reasons, state)
