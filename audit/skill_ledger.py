"""Bounded, read-only skill change ledger, backup store, and bookkeeping audit.

Measures which ledger actor label each recorded skill change carries (curator, agent, user,
other), how often skills changed, how much SKILL.md grew across recorded blobs, version churn,
recorded no-op changes, backup blobs no ledger entry references, snapshot tarball weight, and
active usage records without a skill folder.
Blob contents and snapshot tarballs are never read or extracted; only lstat metadata is used.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Sequence

from .contract import make_component_envelope, make_finding
from .facts import DuplicateConfigKeyError, _parse_simple_yaml_mapping
from .fingerprint import safe_read_regular_file, safe_read_regular_file_plain
from .policy import credential_path
from .write_settings import MAX_CONFIG_BYTES, _has_managed_overlay

# Caps (explicit module constants per the audit hygiene rules)
MAX_LEDGER_BYTES = 64 * 1024 * 1024  # 64 MiB ledger read bound
MAX_LEDGER_LINES = 500_000  # 500,000 ledger lines bound
MAX_BLOB_ENTRIES = 100_000  # 100,000 directory entries bound for blobs/snapshots/skills
MAX_BOOKKEEPING_BYTES = 4 * 1024 * 1024  # 4 MiB bound for .usage.json / .bundled_manifest
MAX_SECONDS = 20.0  # 20 s cooperative wall-clock budget

# Thresholds separate occasional skill edits from automated churn: busy ledgers hold hundreds or
# thousands of changes, almost all from the curator or agent, with skills rewritten many times and
# growing several-fold.
# Actor-summary trigger (info only): > 80% of >= 20 changes labelled curator or agent; it is an
# informational summary because 'agent' includes user-requested edits.
ACTOR_SUMMARY_SHARE_THRESHOLD = 0.80
ACTOR_SUMMARY_MIN_CHANGES = 20
PATCH_STORM_THRESHOLD = 10  # >= 10 changes within any 24h window
PATCH_STORM_WINDOW_SECONDS = 86_400
SKILL_GROWTH_FACTOR = 2.0  # latest/first size >= 2.0x
SKILL_GROWTH_MIN_BYTES = 8_000  # latest size >= 8,000 bytes (small skills doubling is not a concern)
VERSION_CHURN_THRESHOLD = 20  # >= 20 distinct versions
# > 20 MiB of blobs no readable ledger entry references (a few unreferenced blobs are normal;
# thousands left after a ledger is lost are not). Snapshot tarballs are retained
# rollback points (agent/curator_backup.py:30,118-120,200-211: newest `curator.backup.keep`, default 2),
# never "orphans": their weight is reported in backup_store only.
ORPHAN_BACKUP_BYTES_THRESHOLD = 20 * 1024 * 1024
NEAR_IDENTICAL_SIZE_RATIO = 0.02  # < 2% blob size difference heuristic between consecutive versions

# Hermes tools/skill_ledger.py:84-90: ledger lives at skills/.curator_ledger.jsonl;
# content-addressed sha256 blobs live at .curator_backups/blobs/<sha256>.
LEDGER_REL_PATH = 'skills/.curator_ledger.jsonl'
BLOBS_REL_DIR = '.curator_backups/blobs'
# Hermes agent/curator_backup.py:55-68: snapshots live at skills/.curator_backups/<utc-id>/skills.tar.gz.
SNAPSHOTS_REL_DIR = 'skills/.curator_backups'
SNAPSHOT_ARCHIVE_NAME = 'skills.tar.gz'
SNAPSHOT_ID_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z(-\d{2})?$')
# Hermes tools/skill_usage.py:51-52: usage telemetry sidecar at skills/.usage.json; states are
# active/stale/archived (line 35). Records are keyed by the skill's frontmatter name (hermes_cli/curator.py:479-481).
USAGE_REL_PATH = 'skills/.' + 'usage.json'
# Hermes tools/skills_sync.py:38,113-128: bundled manifest at skills/.bundled_manifest ("name:hash").
# An entry without a folder on disk is how sync remembers a user-deleted bundled skill so it is not
# re-added (tools/skills_sync.py:6,431-433): listed for information, never an orphan.
MANIFEST_REL_PATH = 'skills/.bundled_' + 'manifest'
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
MD5_RE = re.compile(r'^[0-9a-f]{32}$')

# Actor labels, from the only writer (tools/skill_ledger.py:298-311 append_entry): the value is the
# explicit `actor` argument if it is in _VALID_ACTORS = {'curator', 'agent', 'user'} (line 38), else
# derive_actor() (lines 68-78): a context override, else 'curator' for a background-review fork, else
# 'agent'. Every caller and the label it writes:
#   curator: agent/curator.py:195-206 (curator archive transitions, set_ledger_actor('curator'));
#            any skill_manage call inside a background review fork, including the curator's LLM pass
#            (agent/curator.py:1129) and the self-improvement review (agent/background_review.py:981-1001),
#            also when a person asked for it with /refine (tools/skill_provenance.py:29-44).
#   agent:   every other skill_manage call (tools/skill_manager_tool.py:750-760, 812-833): foreground
#            chat turns including edits a person asked for, cron and subagent runs; approved staged
#            writes replayed by /skills approve or the TUI review (tools/skill_manager_tool.py:717-723,
#            hermes_cli/write_approval_commands.py:141-142, tools/skills_review.py:225) carry no
#            override; and `hermes curator rollback <entry>` (hermes_cli/curator.py:542 ->
#            tools/skill_ledger.py:602,627, no override).
#   user:    only `hermes curator archive|restore` (hermes_cli/curator.py:330-355, set_ledger_actor('user'))
#            and `hermes curator purge` (hermes_cli/curator.py:508-509).
# NOT recorded at all: edits to skill files outside Hermes (by hand or by other tools), hub
# install/update and bundled-skill sync (no ledger call in tools/skills_hub*.py or tools/skills_sync.py:396-457),
# anything while `skills.ledger` is false (tools/skill_ledger.py:113-115), and rows dropped by the size
# trim (tools/skill_ledger.py:343-415). A label outside the three is not written by Hermes: 'other'.
ACTOR_CLASSES = ('curator', 'agent', 'user', 'other')
HERMES_ACTOR_LABELS = frozenset({'curator', 'agent', 'user'})
# tools/skill_ledger.py:306-308: 'pre-rollback' deliberately records before == after (not a no-op).
PRE_ROLLBACK_ACTION = 'pre-rollback'
# Hermes tools/skill_ledger.py:37,298-314 & tools/skill_manager_tool.py:738-744:
# destructive/archival actions that remove the skill from the active tree.
DELETE_ACTIONS = frozenset({'delete', 'archive', 'purge'})

# Hermes agent/skill_utils.py:26-56: excluded directories and support subdirectories under skills/.
EXCLUDED_SKILL_DIRS = frozenset({
    '.git', '.github', '.hub', '.archive', '.curator_backups', '.locks', '.hermes-dist',
    '.venv', 'venv', 'node_modules', 'site-packages', '__pycache__',
    '.tox', '.nox', '.pytest_cache', '.mypy_cache', '.ruff_cache',
})
SKILL_SUPPORT_DIRS = frozenset({'references', 'templates', 'assets', 'scripts'})
# Skill folders are reported as absolute paths at most `skills/<category>/<name>` deep; anything
# deeper, ambiguous, refused (symlink, credential-named) or absent is only counted, never named.
MAX_REPORTED_SKILL_DEPTH = 2

# One fixed sentence per rule (the report keeps a consequence only if it is exactly one of these);
# every number lives in the finding's evidence. Measurements and their limits, never a cause.
CONSEQUENCES = {
    'skill_ledger.changes_by_recorded_actor': (
        'Recorded skill changes are counted by the actor label the ledger stores: curator (curator runs '
        'and background review forks), agent (tool calls in a conversation, which may include edits a '
        'person asked for or approved) and user (hermes curator archive, restore and purge commands); '
        'the ledger does not record who requested or reviewed a change, and edits made to skill files '
        'outside Hermes are not recorded at all.'
    ),
    'skill_ledger.patch_storm': (
        'At least one skill has 10 or more ledger changes within a 24-hour window of ledger timestamps; '
        'the ledger records the changes, not why they were made or who asked for them.'
    ),
    'skill_ledger.skill_growth': (
        'One or more skills grew to at least twice their initial recorded size and at least 8,000 bytes; '
        'blob sizes measure growth on disk but do not distinguish distilled reference depth from incident accumulation.'
    ),
    'skill_ledger.version_churn': (
        'One or more skills accumulated at least 20 distinct SKILL.md content versions in the ledger; '
        'this counts recorded hashes, not the size or nature of each change.'
    ),
    'skill_ledger.noop_changes': (
        'The ledger contains change records whose recorded after-state is identical to the before-state '
        '(same file hashes, or no file recorded on either side); this shows the record, not why the change was made.'
    ),
    'skill_ledger.orphan_backups': (
        'More than 20 MiB of backup blobs under .curator_backups/blobs are not referenced by any entry in '
        'the skill change ledger, or cannot be matched because there is no ledger; this measures disk use, '
        'not whether the files are still wanted.'
    ),
    'skill_ledger.bookkeeping_orphans': (
        'Skills are recorded as active in skills/.usage.json with no skill folder of that name on disk; '
        'usage records are keyed by frontmatter name, so a skill whose folder is named differently is also counted.'
    ),
    'skill_ledger.could_not_verify': (
        'The skill change ledger or bookkeeping metadata is absent, unreadable, malformed, or truncated by collection bounds; '
        'an absent ledger is not evidence that no skill changes occurred.'
    ),
}
RULE_CLASSIFICATIONS = {
    'skill_ledger.changes_by_recorded_actor': 'info',
    'skill_ledger.patch_storm': 'review_suggested',
    'skill_ledger.skill_growth': 'review_suggested',
    'skill_ledger.version_churn': 'info',
    'skill_ledger.noop_changes': 'info',
    'skill_ledger.orphan_backups': 'review_suggested',
    'skill_ledger.bookkeeping_orphans': 'info',
    'skill_ledger.could_not_verify': 'info',
}


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _has_symlink_below(path: Path, anchor: Path) -> bool:
    cur = path
    while True:
        if cur.is_symlink():
            return True
        if cur == anchor or cur.parent == cur:
            return False
        cur = cur.parent


def _parse_iso_utc(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        dt = datetime.fromisoformat(raw.strip())
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_skill_md_path(path_str: str) -> bool:
    norm = path_str.replace('\\', '/')
    return norm == 'SKILL.md' or norm.endswith('/SKILL.md')


def _extract_file_items(items: Any) -> tuple[list[tuple[str, str]], bool]:
    """Validate and extract (path, sha256) pairs from a ledger before/after list."""
    if not isinstance(items, list):
        return [], False
    out: list[tuple[str, str]] = []
    ok = True
    for item in items:
        if not isinstance(item, dict):
            ok = False
            continue
        p = item.get('path')
        h = item.get('sha256')
        if not isinstance(p, str) or not p.strip() or not isinstance(h, str) or not SHA256_RE.match(h):
            ok = False
            continue
        out.append((p, h))
    return out, ok


def _plain_skill_name(name: str) -> bool:
    """A ledger skill name usable for a folder-name search: one plain path component."""
    return (
        bool(name)
        and name not in {'.', '..'}
        and not name.startswith(('.', '~'))
        and '/' not in name
        and '\\' not in name
        and '\x00' not in name
        and not os.path.isabs(name)
        and not _has_surrogate(name)
    )


def _recorded_skill_dirs(entries: Sequence[tuple[Any, dict[str, Any], list[tuple[str, str]], list[tuple[str, str]]]]) -> list[str]:
    """Candidate `skills/`-relative folders from the latest recorded SKILL.md path, if any.

    Hermes records absolute file paths at write time (tools/skill_ledger.py:172); the part after
    a `/skills/` segment is the recorded relative location. Every split point is a candidate.
    """
    for _dt, _row, before_items, after_items in reversed(entries):
        md_paths = [p for p, _ in after_items + before_items if _is_skill_md_path(p)]
        if not md_paths:
            continue
        norm = md_paths[0].replace('\\', '/')
        parent = norm.rsplit('/', 1)[0] if '/' in norm else ''
        out: list[str] = []
        marker = '/skills/'
        start = parent.find(marker)
        while start >= 0:
            rel = parent[start + len(marker):].strip('/')
            if rel:
                out.append(rel)
            start = parent.find(marker, start + 1)
        if parent.startswith('skills/'):
            out.append(parent[len('skills/'):].strip('/'))
        return out
    return []


def _curator_enabled_from_config(root: Path) -> tuple[bool | None, str]:
    """Hermes agent/curator.py is_enabled(): bool(config `curator.enabled`), default True.

    Only `<profile>/config.yaml` is read (the same bounded reader write_settings uses); no
    credential file is opened. Values whose meaning differs between YAML loaders, env
    interpolation, a managed overlay, or an unreadable config give (None, 'could_not_verify').
    """
    if _has_managed_overlay():
        return None, 'could_not_verify'
    read = safe_read_regular_file(root, 'config.yaml', max_bytes=MAX_CONFIG_BYTES)
    if read.kind == 'missing':
        return True, 'default'
    if read.coverage != 'verified' or not read.stable or read.content is None:
        return None, 'could_not_verify'
    try:
        config = _parse_simple_yaml_mapping(read.content.decode('utf-8'), reject_duplicate_keys=True)
    except (DuplicateConfigKeyError, ValueError, UnicodeError, RecursionError):
        return None, 'could_not_verify'
    curator = config.get('curator') if isinstance(config, dict) else None
    if curator is None:
        return True, 'default'
    if not isinstance(curator, dict):
        return None, 'could_not_verify'
    if 'enabled' not in curator:
        return True, 'default'
    value = curator['enabled']
    if type(value) is bool:
        return value, 'config'
    if value is None:
        return False, 'config'
    return None, 'could_not_verify'


def audit_skill_ledger(
    profile_path: str | Path,
    *,
    curator_enabled: bool | None = None,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Audit Hermes skill-change ledger, content-addressed blob backups, snapshots, and bookkeeping."""
    now_fn = clock if clock is not None else time.monotonic
    started = now_fn()
    deadline = started + MAX_SECONDS
    root = Path(os.path.abspath(os.path.expanduser(os.fspath(profile_path))))

    # Run-dependent numbers go to the envelope's `run_metrics`, never into the digested section.
    def _run_metrics() -> dict[str, Any]:
        return {'elapsed_ms': max(0, int(round((now_fn() - started) * 1000)))}

    curator_enabled_source = 'caller' if curator_enabled is not None else 'could_not_verify'

    limits: dict[str, Any] = {
        'max_ledger_bytes': MAX_LEDGER_BYTES,
        'max_ledger_lines': MAX_LEDGER_LINES,
        'max_blob_entries': MAX_BLOB_ENTRIES,
        'max_seconds': MAX_SECONDS,
        'ledger_bytes_read': 0,
        'ledger_lines_read': 0,
        'blob_entries_examined': 0,
        'cuts': 0,
    }
    truncated_by: str | None = None
    reasons: list[str] = []

    def _note_reason(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    def _cut(trunc: str | None = None, reason: str | None = None) -> None:
        nonlocal truncated_by
        limits['cuts'] += 1
        if trunc and truncated_by is None:
            truncated_by = trunc
        if reason:
            _note_reason(reason)

    def _expired() -> bool:
        if now_fn() < deadline:
            return False
        _cut('time_budget', 'time_budget')
        return True

    def _unmeasured_profile(reason: str) -> dict[str, Any]:
        finding = make_finding(
            rule_id='skill_ledger.could_not_verify',
            classification='info',
            coverage='could_not_verify',
            affected_identities=['.'],
            source_paths=['.'],
            evidence={'cuts': limits['cuts'], 'reason': reason},
            consequence=CONSEQUENCES['skill_ledger.could_not_verify'],
        )
        section = {
            'status': 'not_measured',
            'coverage': 'could_not_verify',
            'reason': reason,
            'reasons': reasons,
            'truncated_by': None,
            'ledger_present': False,
            'curator_enabled': curator_enabled,
            'curator_enabled_source': curator_enabled_source,
            'limits': limits,
        }
        return make_component_envelope(
            findings=[finding],
            coverage='could_not_verify',
            extra={'skill_ledger': section, 'run_metrics': _run_metrics()},
        )

    # Verify profile root exists and is a non-symlink directory
    try:
        st_root = os.lstat(root)
    except OSError:
        _note_reason('profile_missing')
        return _unmeasured_profile('profile_missing')

    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        _cut(reason='profile_unreadable')
        return _unmeasured_profile('profile_unreadable')

    if curator_enabled is None:
        curator_enabled, curator_enabled_source = _curator_enabled_from_config(root)

    # 1. Enumerate .curator_backups/blobs via os.scandir + entry.stat(follow_symlinks=False) ONLY.
    # Never open or read blob contents. Ignore macOS AppleDouble `._*` stub files.
    blobs_dir = root / BLOBS_REL_DIR
    blob_sizes: dict[str, int] = {}
    if not _expired() and os.path.lexists(blobs_dir):
        if credential_path(blobs_dir) or _has_symlink_below(blobs_dir, root):
            _cut(reason='blobs_unreadable')
        else:
            try:
                with os.scandir(blobs_dir) as it:
                    batch = []
                    for entry in it:
                        if _expired():
                            batch = None
                            break
                        if entry.name.startswith('._'):
                            continue
                        limits['blob_entries_examined'] += 1
                        if limits['blob_entries_examined'] > MAX_BLOB_ENTRIES:
                            _cut('max_blob_entries', 'max_blob_entries')
                            batch = None
                            break
                        batch.append(entry)
                if batch is not None:
                    for entry in sorted(batch, key=lambda e: e.name):
                        if _expired():
                            break
                        if _has_surrogate(entry.name):
                            _cut(reason='blobs_unreadable')
                            continue
                        epath = Path(entry.path)
                        if credential_path(epath):
                            # Credential-looking file in blobs dir: skip without opening
                            continue
                        if entry.is_symlink():
                            _cut(reason='symlink_refused')
                            continue
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            _cut(reason='blobs_unreadable')
                            continue
                        if stat.S_ISREG(st.st_mode) and SHA256_RE.match(entry.name):
                            blob_sizes[entry.name] = int(st.st_size)
            except OSError:
                _cut(reason='blobs_unreadable')

    # 2. Enumerate skills/.curator_backups/<id>/skills.tar.gz via os.scandir + lstat ONLY.
    # Never open or extract tarballs.
    snapshots_dir = root / SNAPSHOTS_REL_DIR
    tarball_count = 0
    tarball_bytes = 0
    if not _expired() and os.path.lexists(snapshots_dir):
        if credential_path(snapshots_dir) or _has_symlink_below(snapshots_dir, root):
            _cut(reason='snapshots_unreadable')
        else:
            try:
                with os.scandir(snapshots_dir) as it:
                    snap_entries = []
                    for entry in it:
                        if _expired():
                            snap_entries = None
                            break
                        if entry.name.startswith('._'):
                            continue
                        limits['blob_entries_examined'] += 1
                        if limits['blob_entries_examined'] > MAX_BLOB_ENTRIES:
                            _cut('max_blob_entries', 'max_blob_entries')
                            snap_entries = None
                            break
                        snap_entries.append(entry)
                if snap_entries is not None:
                    for entry in sorted(snap_entries, key=lambda e: e.name):
                        if _expired():
                            break
                        if entry.is_symlink():
                            _cut(reason='symlink_refused')
                            continue
                        if not entry.is_dir(follow_symlinks=False) or not SNAPSHOT_ID_RE.match(entry.name):
                            continue
                        tgz_path = Path(entry.path) / SNAPSHOT_ARCHIVE_NAME
                        if credential_path(tgz_path):
                            continue
                        try:
                            st_tgz = os.lstat(tgz_path)
                        except FileNotFoundError:
                            continue
                        except OSError:
                            _cut(reason='snapshots_unreadable')
                            continue
                        if stat.S_ISLNK(st_tgz.st_mode):
                            _cut(reason='symlink_refused')
                            continue
                        if stat.S_ISREG(st_tgz.st_mode):
                            tarball_count += 1
                            tarball_bytes += int(st_tgz.st_size)
            except OSError:
                _cut(reason='snapshots_unreadable')

    # 3. Read and parse skills/.curator_ledger.jsonl bounded
    ledger_path = root / LEDGER_REL_PATH
    ledger_present = False
    ledger_read = None
    if not _expired():
        if credential_path(ledger_path):
            _cut(reason='ledger_unreadable')
        elif not os.path.lexists(ledger_path):
            _note_reason('ledger_absent')
        elif _has_symlink_below(ledger_path, root):
            _cut(reason='symlink_refused')
        else:
            ledger_read = safe_read_regular_file_plain(root, LEDGER_REL_PATH, max_bytes=MAX_LEDGER_BYTES)
            if ledger_read.kind == 'missing':
                _note_reason('ledger_absent')
            elif ledger_read.bounded_exceeded:
                ledger_present = True
                _cut('max_ledger_bytes', 'max_ledger_bytes')
                # Even if bounded_exceeded, read up to MAX_LEDGER_BYTES prefix if needed,
                # or safe_read_regular_file_plain returns content=None when bounded_exceeded.
            elif ledger_read.coverage != 'verified' or not ledger_read.stable or ledger_read.content is None:
                _cut(reason='ledger_unreadable')
            else:
                ledger_present = True

    raw_lines: list[bytes] = []
    if ledger_read is not None and ledger_read.content is not None:
        raw_bytes = ledger_read.content
        limits['ledger_bytes_read'] = len(raw_bytes)
        if raw_bytes.startswith(b'\xef\xbb\xbf'):
            raw_bytes = raw_bytes[3:]
        raw_lines = raw_bytes.split(b'\n')
        if raw_lines and raw_lines[-1] == b'':
            raw_lines.pop()

    actor_counts: Counter[str] = Counter({k: 0 for k in ACTOR_CLASSES})
    monthly_counts: dict[tuple[int, int], Counter[str]] = defaultdict(lambda: Counter({k: 0 for k in ACTOR_CLASSES}))
    all_timestamps: list[datetime] = []
    referenced_blobs: set[str] = set()
    by_skill_entries: dict[str, list[tuple[datetime | None, dict[str, Any], list[tuple[str, str]], list[tuple[str, str]]]]] = defaultdict(list)

    # Every line must be read and parsed before a blob can be called unreferenced (Hermes itself
    # skips blob GC on any malformed line: tools/skill_ledger.py:470-481).
    references_complete = ledger_present and ledger_read is not None and ledger_read.content is not None
    for line_bytes in raw_lines:
        if _expired():
            references_complete = False
            break
        if not line_bytes.strip():
            continue
        if limits['ledger_lines_read'] >= MAX_LEDGER_LINES:
            _cut('max_ledger_lines', 'max_ledger_lines')
            references_complete = False
            break
        limits['ledger_lines_read'] += 1
        try:
            line_str = line_bytes.decode('utf-8')
            row = json.loads(line_str)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _cut(reason='malformed_ledger_line')
            references_complete = False
            continue
        if not isinstance(row, dict):
            _cut(reason='malformed_ledger_line')
            references_complete = False
            continue

        skill_name = row.get('skill')
        action = row.get('action')
        actor_raw = row.get('actor')
        if (
            not isinstance(skill_name, str)
            or not skill_name.strip()
            or _has_surrogate(skill_name)
            or not isinstance(action, str)
            or not action.strip()
            or not isinstance(actor_raw, str)
            or not actor_raw.strip()
        ):
            _cut(reason='malformed_ledger_line')
            references_complete = False
            continue

        before_items, b_ok = _extract_file_items(row.get('before', []))
        after_items, a_ok = _extract_file_items(row.get('after', []))
        if not b_ok or not a_ok:
            _cut(reason='malformed_ledger_line')
            references_complete = False
            continue

        dt = _parse_iso_utc(row.get('ts'))
        if dt is None:
            _cut(reason='malformed_ledger_line')
        else:
            all_timestamps.append(dt)

        # Exact match: Hermes writes only these three lowercase labels (tools/skill_ledger.py:38,311).
        actor_cls = actor_raw if actor_raw in HERMES_ACTOR_LABELS else 'other'
        actor_counts[actor_cls] += 1
        if dt is not None:
            monthly_counts[(dt.year, dt.month)][actor_cls] += 1

        for _, h in before_items:
            referenced_blobs.add(h)
        for _, h in after_items:
            referenced_blobs.add(h)

        by_skill_entries[skill_name.strip()].append((dt, row, before_items, after_items))

    # 4. Compute per-skill metrics
    skill_rows: list[dict[str, Any]] = []
    total_noop_changes = 0
    skills_growth_unverified = 0
    for skill_name in sorted(by_skill_entries):
        if _expired():
            break
        entries = by_skill_entries[skill_name]
        n_changes = len(entries)
        skill_md_hashes: set[str] = set()
        all_skill_hashes: set[str] = set()
        # SKILL.md hashes in LEDGER (file/append) order: the initial before-state, then each after-state.
        md_hash_seq: list[str] = []
        noop_count = 0
        deleted_flag = False
        changes_before_delete = 0

        # Peak changes in any 24h window (ledger timestamps only; rows without a timestamp are skipped)
        dts = sorted(dt for dt, _, _, _ in entries if dt is not None)
        peak_24h = 0
        right = 0
        for left in range(len(dts)):
            while right < len(dts) and (dts[right] - dts[left]).total_seconds() <= PATCH_STORM_WINDOW_SECONDS:
                right += 1
            peak_24h = max(peak_24h, right - left)

        for idx, (_dt, row, before_items, after_items) in enumerate(entries):
            action = str(row.get('action', '')).strip()
            b_map = dict(before_items)
            a_map = dict(after_items)

            for h in b_map.values():
                all_skill_hashes.add(h)
            for h in a_map.values():
                all_skill_hashes.add(h)

            # Recorded no-op: identical recorded state. Hermes drops unchanged paths from both sides
            # (tools/skill_ledger.py:285-296,306-308), so a successful write that changed nothing is
            # recorded with both sides empty; 'pre-rollback' records before == after by design.
            # A same-size SKILL.md with a different hash is a real content change, never a no-op.
            is_noop = False
            if action != PRE_ROLLBACK_ACTION and b_map and b_map == a_map:
                is_noop = True
            elif not b_map and not a_map and action in {'patch', 'edit', 'write_file', 'remove_file'}:
                is_noop = True
            if is_noop:
                noop_count += 1

            if not md_hash_seq:
                for p, h in before_items:
                    if _is_skill_md_path(p):
                        md_hash_seq.append(h)
            for p, h in before_items:
                if _is_skill_md_path(p):
                    skill_md_hashes.add(h)

            if action in DELETE_ACTIONS:
                deleted_flag = True
                changes_before_delete = idx + 1
            else:
                deleted_flag = False
                for p, h in after_items:
                    if _is_skill_md_path(p):
                        skill_md_hashes.add(h)
                        md_hash_seq.append(h)

        distinct_versions = len(skill_md_hashes) if skill_md_hashes else len(all_skill_hashes)
        # Growth: first and latest SKILL.md by ledger order; both blobs must exist (sizes come from lstat,
        # the ledger stores no sizes: tools/skill_ledger.py:158-173). A missing blob is could_not_verify.
        first_size = blob_sizes.get(md_hash_seq[0]) if md_hash_seq else None
        latest_size = blob_sizes.get(md_hash_seq[-1]) if md_hash_seq else None
        if not md_hash_seq:
            growth_coverage = 'not_applicable'
        elif first_size is None or latest_size is None or first_size <= 0:
            growth_coverage = 'could_not_verify'
            skills_growth_unverified += 1
        else:
            growth_coverage = 'verified'
        growth_ratio = round(latest_size / first_size, 2) if growth_coverage == 'verified' else None
        size_seq = [blob_sizes[h] for h in md_hash_seq if h in blob_sizes]

        # Near-identical consecutive versions by blob size (< 2% difference)
        near_identical_pairs = 0
        for s1, s2 in zip(size_seq, size_seq[1:]):
            denom = max(s1, s2)
            if denom > 0 and abs(s2 - s1) / denom < NEAR_IDENTICAL_SIZE_RATIO:
                near_identical_pairs += 1

        total_noop_changes += noop_count
        skill_rows.append({
            '_name': skill_name,
            'changes': n_changes,
            'distinct_versions': distinct_versions,
            'first_size_bytes': first_size,
            'latest_size_bytes': latest_size,
            'growth_ratio': growth_ratio,
            'growth_coverage': growth_coverage,
            'peak_changes_24h': peak_24h,
            'noop_changes': noop_count,
            'deleted': deleted_flag,
            'changes_before_delete': changes_before_delete,
            'near_identical_size_pairs': near_identical_pairs,
        })

    if skills_growth_unverified:
        _note_reason('growth_blob_missing')

    # Discover active skill directories on disk under skills/ and shared/skills/
    # shared/skills/ is a local convention seen in some homes, NOT a Hermes location: when absent it
    # contributes nothing (it can only remove usage orphans, never add a finding).
    on_disk_skill_keys: set[str] = set()
    # Primary skills tree only: skills/-relative folder -> absolute folder (None = refused entry).
    skill_dirs_by_rel: dict[str, str | None] = {}
    skill_rels_by_name: dict[str, list[str]] = defaultdict(list)
    skills_walk_complete = True
    skills_real_root = os.path.realpath(root / 'skills')
    for skills_rel in ('skills', 'shared/skills'):
        skills_root = root / skills_rel
        is_primary_skills = skills_rel == 'skills'
        if _expired() or not os.path.lexists(skills_root):
            continue
        if credential_path(skills_root) or _has_symlink_below(skills_root, root):
            if is_primary_skills:
                skills_walk_complete = False
                _cut(reason='skills_tree_unreadable')
            continue
        pending = [skills_root]
        while pending:
            if _expired():
                if is_primary_skills:
                    skills_walk_complete = False
                break
            cur_dir = pending.pop()
            if credential_path(cur_dir) or _has_symlink_below(cur_dir, root):
                if is_primary_skills:
                    _cut(reason='symlink_refused')
                continue
            try:
                with os.scandir(cur_dir) as it:
                    dir_entries = []
                    has_skill_md = False
                    for entry in it:
                        if _expired():
                            dir_entries = None
                            break
                        if entry.name.startswith('._'):
                            continue
                        limits['blob_entries_examined'] += 1
                        if limits['blob_entries_examined'] > MAX_BLOB_ENTRIES:
                            _cut('max_blob_entries', 'max_blob_entries')
                            dir_entries = None
                            break
                        if entry.name == 'SKILL.md' and not entry.is_symlink() and entry.is_file(follow_symlinks=False):
                            has_skill_md = True
                        dir_entries.append(entry)
                if dir_entries is None:
                    if is_primary_skills:
                        skills_walk_complete = False
                    break
                if has_skill_md and cur_dir != skills_root:
                    rel_posix = cur_dir.relative_to(skills_root).as_posix()
                    on_disk_skill_keys.add(cur_dir.name)
                    on_disk_skill_keys.add(rel_posix)
                    on_disk_skill_keys.add(rel_posix.replace('/', ':'))
                    if is_primary_skills:
                        skill_dirs_by_rel[rel_posix] = os.path.realpath(cur_dir)
                        skill_rels_by_name[cur_dir.name].append(rel_posix)
                for entry in sorted(dir_entries, key=lambda e: e.name):
                    if _has_surrogate(entry.name):
                        if is_primary_skills:
                            _cut(reason='skills_tree_unreadable')
                        continue
                    epath = Path(entry.path)
                    if credential_path(epath) or entry.is_symlink():
                        if is_primary_skills:
                            # A refused entry can never be reported, and a skill of that name
                            # or location is then not located unambiguously.
                            refused_rel = epath.relative_to(skills_root).as_posix()
                            skill_dirs_by_rel[refused_rel] = None
                            skill_rels_by_name[entry.name].append(refused_rel)
                            if entry.is_symlink():
                                _cut(reason='symlink_refused')
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in EXCLUDED_SKILL_DIRS:
                            continue
                        if has_skill_md and cur_dir != skills_root and entry.name in SKILL_SUPPORT_DIRS:
                            continue
                        pending.append(epath)
            except OSError:
                if is_primary_skills:
                    skills_walk_complete = False
                    _cut(reason='skills_tree_unreadable')

    def _locate_skill_dir(name: str) -> str | None:
        """Absolute existing skill folder for a ledger skill, or None when not located unambiguously."""
        if not skills_walk_complete or not _plain_skill_name(name):
            return None
        recorded = _recorded_skill_dirs(by_skill_entries.get(name, []))
        if recorded:
            rels = {r for r in recorded if r in skill_dirs_by_rel}
        else:
            rels = set(skill_rels_by_name.get(name, ()))
        if len(rels) != 1:
            return None
        rel = next(iter(rels))
        found = skill_dirs_by_rel.get(rel)
        if found is None or rel.count('/') >= MAX_REPORTED_SKILL_DEPTH:
            return None
        if not found.startswith(skills_real_root + os.sep) or not os.path.isdir(found) or os.path.islink(found):
            return None
        return found

    for row in skill_rows:
        row['path'] = _locate_skill_dir(row.pop('_name'))

    # 6. Check .usage.json and .bundled_manifest for bookkeeping orphans
    usage_orphans: list[str] = []
    usage_path = root / USAGE_REL_PATH
    if not _expired() and os.path.lexists(usage_path):
        if credential_path(usage_path) or _has_symlink_below(usage_path, root):
            _cut(reason='usage_unreadable')
        else:
            u_read = safe_read_regular_file_plain(root, USAGE_REL_PATH, max_bytes=MAX_BOOKKEEPING_BYTES)
            if u_read.coverage != 'verified' or not u_read.stable or u_read.content is None:
                _cut(reason='usage_unreadable')
            else:
                try:
                    u_data = json.loads(u_read.content.decode('utf-8-sig'))
                    if not isinstance(u_data, dict):
                        _cut(reason='usage_malformed')
                    else:
                        for k, rec in sorted(u_data.items()):
                            if not isinstance(k, str) or k.startswith('._') or _has_surrogate(k):
                                continue
                            if not isinstance(rec, dict):
                                _cut(reason='usage_malformed')
                                continue
                            if rec.get('state', 'active') == 'active' and k not in on_disk_skill_keys:
                                usage_orphans.append(k)
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                    _cut(reason='usage_malformed')

    manifest_orphans: list[str] = []
    manifest_path = root / MANIFEST_REL_PATH
    if not _expired() and os.path.lexists(manifest_path):
        if credential_path(manifest_path) or _has_symlink_below(manifest_path, root):
            _cut(reason='manifest_unreadable')
        else:
            m_read = safe_read_regular_file_plain(root, MANIFEST_REL_PATH, max_bytes=MAX_BOOKKEEPING_BYTES)
            if m_read.coverage != 'verified' or not m_read.stable or m_read.content is None:
                _cut(reason='manifest_unreadable')
            else:
                try:
                    for line in m_read.content.decode('utf-8-sig').splitlines():
                        sline = line.strip()
                        if not sline or sline.startswith('._'):
                            continue
                        m_name, sep, m_hash = sline.partition(':')
                        m_name = m_name.strip()
                        m_hash = m_hash.strip()
                        if not m_name or _has_surrogate(m_name) or (sep and not MD5_RE.match(m_hash)):
                            _cut(reason='manifest_malformed')
                            continue
                        if m_name not in on_disk_skill_keys:
                            manifest_orphans.append(m_name)
                except UnicodeDecodeError:
                    _cut(reason='manifest_malformed')

    all_bookkeeping_orphans = sorted(set(usage_orphans))
    manifest_not_on_disk = sorted(set(manifest_orphans))

    # 7. Backup store summary
    total_blob_count = len(blob_sizes)
    total_blob_bytes = sum(blob_sizes.values())
    if ledger_present:
        # Partial when references_complete is False: then no orphan_backups finding is raised.
        orphan_hashes = set(blob_sizes.keys()) - referenced_blobs
        missing_hashes = referenced_blobs - set(blob_sizes.keys())
        all_blobs_orphaned_no_ledger = False
    else:
        orphan_hashes = set(blob_sizes.keys())
        missing_hashes = set()
        all_blobs_orphaned_no_ledger = total_blob_count > 0

    orphan_blob_count = len(orphan_hashes)
    orphan_blob_bytes = sum(blob_sizes[h] for h in orphan_hashes)
    missing_blob_hashes = len(missing_hashes)

    # 8. Aggregate actor & date metrics
    total_changes = sum(actor_counts.values())
    curator_or_agent_changes = actor_counts['curator'] + actor_counts['agent']
    curator_or_agent_share = (
        round(curator_or_agent_changes / total_changes, 4) if total_changes > 0 else None
    )

    if all_timestamps:
        earliest_dt = min(all_timestamps)
        latest_dt = max(all_timestamps)
        # Numbers, not ISO strings: they pass the closed-vocabulary report serializer unchanged.
        date_range = {
            'earliest_epoch_s': int(earliest_dt.timestamp()),
            'latest_epoch_s': int(latest_dt.timestamp()),
            'span_days': (latest_dt - earliest_dt).days,
        }
    else:
        date_range = {
            'earliest_epoch_s': None,
            'latest_epoch_s': None,
            'span_days': None,
        }

    changes_by_month = [
        {
            'year': year,
            'month': month,
            'total': sum(counts.values()),
            'curator': counts['curator'],
            'agent': counts['agent'],
            'user': counts['user'],
            'other': counts['other'],
        }
        for (year, month), counts in sorted(monthly_counts.items())
    ]

    # skill_rows are sorted by ledger name; the stable sort keeps that order for ties, so the
    # ranking is deterministic although names are never reported.
    def _top(rows: list[dict[str, Any]]) -> dict[str, Any]:
        top = rows[:10]
        return {
            'paths': [r['path'] for r in top if r['path'] is not None],
            'unlocated_count': sum(1 for r in top if r['path'] is None),
        }

    top_skills_by_changes = _top(sorted(skill_rows, key=lambda r: -r['changes']))
    top_skills_by_growth = _top(sorted(
        (r for r in skill_rows if r['growth_ratio'] is not None),
        key=lambda r: (-r['growth_ratio'], -(r['latest_size_bytes'] or 0)),
    ))

    # 9. Emit Findings
    # Finding evidence carries numbers, booleans and vocabulary labels only: persistence keeps
    # nothing else, so skill names live in the section (see audit/wiring/skill_ledger.json).
    findings: list[dict[str, Any]] = []
    # Paths in findings are relative to the profile root (report path policy).
    ledger_source = LEDGER_REL_PATH if ledger_present else 'skills'

    # Finding 1: skill_ledger.changes_by_recorded_actor (info: 'agent' includes user-requested edits)
    if (
        total_changes >= ACTOR_SUMMARY_MIN_CHANGES
        and curator_or_agent_share is not None
        and curator_or_agent_share > ACTOR_SUMMARY_SHARE_THRESHOLD
    ):
        findings.append(make_finding(
            rule_id='skill_ledger.changes_by_recorded_actor',
            classification='info',
            coverage='verified',
            affected_identities=[ledger_source],
            source_paths=[ledger_source],
            evidence={
                'total_changes': total_changes,
                'curator_or_agent_changes': curator_or_agent_changes,
                'curator_or_agent_share': curator_or_agent_share,
                'curator_changes': actor_counts['curator'],
                'agent_changes': actor_counts['agent'],
                'user_changes': actor_counts['user'],
                'other_changes': actor_counts['other'],
            },
            consequence=CONSEQUENCES['skill_ledger.changes_by_recorded_actor'],
        ))

    # Finding 2: skill_ledger.patch_storm (review_suggested)
    storm_skills = [r for r in skill_rows if r['peak_changes_24h'] >= PATCH_STORM_THRESHOLD]
    if storm_skills:
        max_storm = max(r['peak_changes_24h'] for r in storm_skills)
        findings.append(make_finding(
            rule_id='skill_ledger.patch_storm',
            classification='review_suggested',
            coverage='verified',
            affected_identities=[ledger_source],
            source_paths=[ledger_source],
            evidence={
                'affected_skill_count': len(storm_skills),
                'max_changes_24h': max_storm,
                'threshold_changes_24h': PATCH_STORM_THRESHOLD,
            },
            consequence=CONSEQUENCES['skill_ledger.patch_storm'],
        ))

    # Finding 3: skill_ledger.skill_growth (review_suggested)
    grown_skills = [
        r for r in skill_rows
        if r['growth_ratio'] is not None
        and r['growth_ratio'] >= SKILL_GROWTH_FACTOR
        and (r['latest_size_bytes'] or 0) >= SKILL_GROWTH_MIN_BYTES
    ]
    if grown_skills:
        max_growth = max(r['growth_ratio'] for r in grown_skills)
        max_latest_bytes = max(r['latest_size_bytes'] or 0 for r in grown_skills)
        findings.append(make_finding(
            rule_id='skill_ledger.skill_growth',
            classification='review_suggested',
            coverage='verified',
            affected_identities=[ledger_source],
            source_paths=[ledger_source],
            evidence={
                'affected_skill_count': len(grown_skills),
                'max_growth_ratio': max_growth,
                'max_latest_size_bytes': max_latest_bytes,
                'growth_factor_threshold': SKILL_GROWTH_FACTOR,
                'min_latest_bytes_threshold': SKILL_GROWTH_MIN_BYTES,
            },
            consequence=CONSEQUENCES['skill_ledger.skill_growth'],
        ))

    # Finding 4: skill_ledger.version_churn (info)
    churn_skills = [r for r in skill_rows if r['distinct_versions'] >= VERSION_CHURN_THRESHOLD]
    if churn_skills:
        max_versions = max(r['distinct_versions'] for r in churn_skills)
        findings.append(make_finding(
            rule_id='skill_ledger.version_churn',
            classification='info',
            coverage='verified',
            affected_identities=[ledger_source],
            source_paths=[ledger_source],
            evidence={
                'affected_skill_count': len(churn_skills),
                'max_distinct_versions': max_versions,
                'version_churn_threshold': VERSION_CHURN_THRESHOLD,
            },
            consequence=CONSEQUENCES['skill_ledger.version_churn'],
        ))

    # Finding 5: skill_ledger.noop_changes (info)
    if total_noop_changes > 0:
        noop_skills = [r for r in skill_rows if r['noop_changes'] > 0]
        findings.append(make_finding(
            rule_id='skill_ledger.noop_changes',
            classification='info',
            coverage='verified',
            affected_identities=[ledger_source],
            source_paths=[ledger_source],
            evidence={
                'noop_changes': total_noop_changes,
                'affected_skill_count': len(noop_skills),
            },
            consequence=CONSEQUENCES['skill_ledger.noop_changes'],
        ))

    # Finding 6: skill_ledger.orphan_backups (review_suggested)
    # Only blobs no readable ledger entry references, and only when every ledger line was read
    # (or there is no ledger at all, in which case nothing can be matched).
    orphan_judgeable = references_complete or (not ledger_present and 'ledger_absent' in reasons)
    if orphan_judgeable and orphan_blob_bytes > ORPHAN_BACKUP_BYTES_THRESHOLD:
        findings.append(make_finding(
            rule_id='skill_ledger.orphan_backups',
            classification='review_suggested',
            coverage='verified',
            affected_identities=[BLOBS_REL_DIR],
            source_paths=[BLOBS_REL_DIR],
            evidence={
                'orphan_blob_count': orphan_blob_count,
                'orphan_blob_bytes': orphan_blob_bytes,
                'tarball_count': tarball_count,
                'tarball_bytes': tarball_bytes,
                'all_blobs_orphaned_no_ledger': all_blobs_orphaned_no_ledger,
                'threshold_bytes': ORPHAN_BACKUP_BYTES_THRESHOLD,
            },
            consequence=CONSEQUENCES['skill_ledger.orphan_backups'],
        ))

    # Finding 7: skill_ledger.bookkeeping_orphans (info)
    if all_bookkeeping_orphans:
        findings.append(make_finding(
            rule_id='skill_ledger.bookkeeping_orphans',
            classification='info',
            coverage='verified',
            affected_identities=[USAGE_REL_PATH],
            source_paths=[USAGE_REL_PATH],
            evidence={
                'orphan_count': len(all_bookkeeping_orphans),
                'usage_orphan_count': len(all_bookkeeping_orphans),
                'manifest_entries_not_on_disk_count': len(manifest_not_on_disk),
            },
            consequence=CONSEQUENCES['skill_ledger.bookkeeping_orphans'],
        ))

    # Finding 8: skill_ledger.could_not_verify
    unverified = (not ledger_present) or (limits['cuts'] > 0) or (truncated_by is not None)
    if unverified:
        primary_reason = truncated_by or (reasons[0] if reasons else 'could_not_verify')
        findings.append(make_finding(
            rule_id='skill_ledger.could_not_verify',
            classification='info',
            coverage='could_not_verify',
            affected_identities=['skills'],
            source_paths=['skills'],
            evidence={
                'cuts': limits['cuts'],
                'ledger_present': ledger_present,
                'reason': primary_reason,
                **({'truncated_by': truncated_by} if truncated_by is not None else {}),
            },
            consequence=CONSEQUENCES['skill_ledger.could_not_verify'],
        ))

    coverage = 'could_not_verify' if unverified else 'verified'
    section: dict[str, Any] = {
        'status': 'completed',
        'coverage': coverage,
        'reason': reasons[0] if reasons else None,
        'reasons': reasons,
        'truncated_by': truncated_by,
        'ledger_present': ledger_present,
        'curator_enabled': curator_enabled,
        'curator_enabled_source': curator_enabled_source,
        'total_changes': total_changes,
        'changes_by_actor': {k: actor_counts[k] for k in ACTOR_CLASSES},
        'curator_or_agent_changes': curator_or_agent_changes,
        'curator_or_agent_share': curator_or_agent_share,
        'date_range': date_range,
        'changes_by_month': changes_by_month,
        'skills_in_ledger': len(skill_rows),
        'noop_changes': total_noop_changes,
        'skills_deleted_count': sum(1 for r in skill_rows if r['deleted']),
        'skills_growth_could_not_verify': skills_growth_unverified,
        'skills_without_folder_count': sum(1 for r in skill_rows if r['path'] is None),
        'skills': skill_rows,
        'top_skills_by_changes': top_skills_by_changes,
        'top_skills_by_growth': top_skills_by_growth,
        'backup_store': {
            'blob_count': total_blob_count,
            'blob_bytes': total_blob_bytes,
            'orphan_blob_count': orphan_blob_count,
            'orphan_blob_bytes': orphan_blob_bytes,
            'all_blobs_orphaned_no_ledger': all_blobs_orphaned_no_ledger,
            'missing_blob_hashes': missing_blob_hashes,
            'references_complete': bool(references_complete),
            'tarball_count': tarball_count,
            'tarball_bytes': tarball_bytes,
        },
        'bookkeeping_orphans': {
            # Names only exist here as usage keys / manifest names with no folder: counts only.
            'orphan_count': len(all_bookkeeping_orphans),
            'usage_orphan_count': len(all_bookkeeping_orphans),
            'manifest_entries_not_on_disk_count': len(manifest_not_on_disk),
        },
        'limits': limits,
        'thresholds': {
            'actor_summary_share': ACTOR_SUMMARY_SHARE_THRESHOLD,
            'actor_summary_min_changes': ACTOR_SUMMARY_MIN_CHANGES,
            'patch_storm_changes_24h': PATCH_STORM_THRESHOLD,
            'skill_growth_factor': SKILL_GROWTH_FACTOR,
            'skill_growth_min_bytes': SKILL_GROWTH_MIN_BYTES,
            'version_churn': VERSION_CHURN_THRESHOLD,
            'orphan_backup_bytes': ORPHAN_BACKUP_BYTES_THRESHOLD,
            'near_identical_size_ratio': NEAR_IDENTICAL_SIZE_RATIO,
        },
    }
    return make_component_envelope(
        findings=findings,
        coverage=coverage,
        extra={'skill_ledger': section, 'run_metrics': _run_metrics()},
    )
