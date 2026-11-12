"""Read-only memory measurements; private text and content hashes never escape."""
from __future__ import annotations

import bisect
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path, PurePath
import re
import stat
import sys
import time

from .contract import make_component_envelope, make_finding
from .fingerprint import CredentialStoreNotOpened, _open_root_dir_fd, _walk_parent_dir_fds, open_checked
from .policy import credential_path
from .session_contamination import technology_counts

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 200
MAX_TREE_ENTRIES = 10000
MAX_DEPTH = 8
MAX_ENTRIES = 2000
MAX_SECONDS = 5
# Long-lived homes collect dozens of dated entries, exceed configured budgets several times over and
# keep thousands of plugin state files; the bounds below leave room for that.
MIN_DATED_ENTRIES = 6
DATED_SHARE = 0.5
OTHER_MACHINE_COUNT = 2
OTHER_MACHINE_SHARE = 0.25
STATE_SPRAWL_FILES = 100
NEAR_DUPLICATE_SHARE = 0.6
SHINGLE_WORDS = 8
STANDING_ORDER_WORDS = ('always', 'never', 'must', 'unasked', 'without asking', 'every session')
APPROVAL_WORDS = ('approve', 'approval', 'permission', 'confirm')
# Hermes tools/memory_tool.py:38-40; memory_tool_store.py:26,188,303,701-703.
# Config keys: memory.memory_char_limit / memory.user_char_limit,
# hermes_cli/config_defaults.py:1304-1305 (also tools/memory_tool.py:56,
# agent/agent_init.py:1247-1248). Never import the runtime/config loader.
# These defaults are EXPORTED for the caller: a caller that parsed config.yaml and
# found no override passes them explicitly. A limit of None means unknown, so no
# over-limit claim is made (homes commonly configure values between 2200 and 8000).
DEFAULT_MEMORY_LIMIT = 2200
DEFAULT_USER_LIMIT = 1375
DELIMITER = '\n§\n'
# Default for keyword inputs the module resolves itself (config.yaml / host OS).
# An explicit None from a caller still means unknown.
FROM_PROFILE = object()
MAX_CONFIG_BYTES = 1024 * 1024
HOST_OS = {'linux': 'linux', 'darwin': 'macos', 'win32': 'windows'}
# Bundled plugins/memory/{byterover,retaindb}/plugin.yaml:1; provider selection:
# agent/memory_provider.py:42-49; agent/agent_init.py:1254-1278.
# Prompt (re-checked against the Hermes source): tools/memory_tool_store.py:255
# stores the load-time block, :654-657 returns that frozen snapshot and :674-680
# renders header + usage + entries joined by the delimiter; agent/system_prompt.py:
# 527-531 appends the built-in memory/user blocks that are enabled. Plugin context:
# agent/turn_context.py:849-862 runs pre_llm_call hooks; its docstring (:853-854)
# states the returned context goes into the USER message, not the system prompt.
# Profile roots: hermes_cli/profiles.py:288-290,2392.
KNOWN_PROVIDERS = frozenset({'byterover', 'retaindb'})
CORE_PROVIDERS = frozenset({'', 'default', 'builtin', 'built-in', 'none'})
DATE_RE = re.compile(r'\b(?:\d{4}-\d{2}-\d{2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})\b', re.I)
ORDER_RE = re.compile(r'\b(?:' + '|'.join(STANDING_ORDER_WORDS) + r')\b', re.I)
APPROVAL_RE = re.compile(r'\b(?:' + '|'.join(APPROVAL_WORDS) + r')\b', re.I)
WRITE_RE = re.compile(r'\b(?:write|writing|save|saving|capture|create|update|edit|record)\b', re.I)
ARTIFACT_RE = re.compile(r'\b(?:skills?|memory|config)\b', re.I)
UNASKED_RE = re.compile(r'\b(?:unasked|without asking)\b', re.I)
# Private host names. The rule is the base pattern \b(?:[a-z0-9-]+\.)+(?:ts\.net|local)\b
# (re.I), which was quadratic on long dotted runs ('a.' or '1.' repeated): every word
# boundary started a new attempt that walked the whole run. _network_name answers the
# same question with linear regex passes and binary search; see that function.
_NET_TERMINATOR_RE = re.compile(r'\.(?=(?:ts\.net|local)\b)', re.I)
_NET_LABEL_START_RE = re.compile(r'\b(?=[a-z0-9-])', re.I)
_NET_RUN_RE = re.compile(r'[a-z0-9.-]+', re.I)
_NET_EMPTY_LABEL_RE = re.compile(r'\.(?=\.)')
IP_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))
CONSEQUENCES = {
    'over_limit': 'Memory files (live or snapshot copies) are longer, in characters, than the character limit used for this audit; this compares file length only and does not measure what is sent with a request.',
    'mostly_dated_entries': 'Memory files were counted where more than half of at least six entries contain a calendar date; a date does not show that the entry is out of date.',
    'other_machine_entries': 'Memory files were counted whose entries contain another operating system\'s home-path form or a private-network address; this is left over text from another machine, and the count does not show that it is used or wrong here.',
    'standing_orders': 'Entries phrased as always/never instructions were counted by word match; the count does not show who wrote them, whether they are followed, or whether they are wrong.',
    'duplicate_entries': 'Normalized entries or eight-word shingles were counted that repeat within or across live memory files; the count does not show that the repeated text means the same thing.',
    'foreign_technology_entries': 'Entries were counted that name technology families absent from the supplied projects; the count does not show that those entries are irrelevant.',
    'memory_state_sprawl': 'A memory state directory, found by name and counted by file metadata only, holds more than 100 files; the count does not show whether the files are used or repeat each other.',
    'stale_pending_edits': 'Pending memory edits were counted whose old text is absent from the current target file; the count does not predict whether approving them would succeed.',
    'pending_edit_changes_approval_entry': 'This counts pending memory edits where an edit replaces or removes an entry that contains approval-related words; it is a word count and does not show that any approval setting or instruction would change.',
    'could_not_verify': 'Some memory measurements could not be verified; missing coverage is not a clean result.',
    # Fixed sentence: the mechanism count is evidence.mechanisms, never interpolated.
    'multiple_memory_systems': 'Two or more memory mechanisms are configured or present together; the audit counted them from config and files, and did not measure what each adds to a request or whether they repeat each other.',
    # Fixed sentence: limits and ratios are evidence numbers, never interpolated.
    'limit_raised_above_shipped': 'The character limit for a memory file is set above the value Hermes ships with; text in these files is sent with every request, so a higher limit allows more text on every request. The setting was measured from config.yaml and does not show who changed it or why.',
}
# A configured limit at least this many times the shipped default => review_suggested.
RAISED_REVIEW_RATIO = 2.0


def _finding(rule, evidence, classification='info', coverage='verified'):
    # Every consequence is a fixed sentence (persistence keeps only exact sentences).
    return make_finding(rule_id='memory_load.' + rule, classification=classification,
                        coverage=coverage, evidence=evidence, consequence=CONSEQUENCES[rule])


def _entries(text):
    # Match universal-newline text reads, UTF-8 BOM handling and exact delimiter
    # in tools/memory_tool_store.py:683-703; bare § is not a separator.
    return [s.strip() for s in text.split(DELIMITER) if s.strip()]


def _normal(entry):
    return ' '.join(entry.casefold().split())


def _network_name(entry):
    r"""Same answer as bool(re.search(r'\b(?:[a-z0-9-]+\.)+(?:ts\.net|local)\b', entry, re.I)).

    That pattern matches iff some dot at q-1 is followed by ts.net/local and a word
    boundary, and some position p <= q-2 has a word boundary, a label character
    ([a-z0-9-] under re.I) at p, and s[p:q] made only of label characters and single
    dots. Each condition is one linear pass with the same character classes and \b
    semantics; each candidate dot then costs two binary searches, so the work is
    O(n log n) with no backtracking, whatever the input.
    """
    dots = [m.start() for m in _NET_TERMINATOR_RE.finditer(entry)]
    if not dots:
        return False
    starts = [m.start() for m in _NET_LABEL_START_RE.finditer(entry)]
    runs = [m.start() for m in _NET_RUN_RE.finditer(entry)]
    empty = [m.start() for m in _NET_EMPTY_LABEL_RE.finditer(entry)]
    for dot in dots:
        # Earliest admissible start: the start of the run holding this dot, and past
        # the last '..' before it (an empty label ends every chain).
        low = runs[bisect.bisect_right(runs, dot) - 1]
        k = bisect.bisect_right(empty, dot - 1) - 1
        if k >= 0:
            low = max(low, empty[k] + 1)
        i = bisect.bisect_left(starts, low)
        if i < len(starts) and starts[i] < dot:
            return True
    return False


def _private_network(entry):
    if _network_name(entry):
        return True
    for match in IP_RE.finditer(entry):
        try:
            ip = ipaddress.ip_address(match[0])
            if any(ip in network for network in PRIVATE_NETS):
                return True
        except ValueError:
            pass
    return False


def _other_os(entry, home_os):
    return bool((home_os != 'windows' and re.search(r'\b[A-Za-z]:\\', entry)) or
                (home_os != 'macos' and '/Users/' in entry) or
                (home_os != 'linux' and '/home/' in entry))


def _metrics(text, kind, scope, limit, home_os):
    entries = _entries(text)
    network = [_private_network(e) for e in entries]
    foreign_os = [_other_os(e, home_os) for e in entries] if home_os else None
    row = {'kind': kind, 'scope': scope, 'coverage': 'verified',
           'characters': len(text), 'entries': len(entries), 'char_limit': limit,
           'duplicate_entries': len(entries) - len({_normal(e) for e in entries}),
           'percent_of_limit': 100 * len(text) / limit if limit else None,
           'over_limit': len(text) > limit if limit else None,
           'dated_entries': sum(bool(DATE_RE.search(e)) for e in entries),
           'other_os_entries': sum(foreign_os) if foreign_os is not None else None,
           'other_os_coverage': 'verified' if home_os else 'could_not_verify',
           'private_network_entries': sum(network),
           # Union of OS-path and private-network entries; unknown when the OS is unknown.
           'other_machine_entries': sum(a or b for a, b in zip(foreign_os, network)) if foreign_os is not None else None,
           'standing_order_entries': sum(bool(ORDER_RE.search(e)) for e in entries),
           'unasked_write_entries': sum(bool(ORDER_RE.search(e) and WRITE_RE.search(e) and ARTIFACT_RE.search(e) and UNASKED_RE.search(e)) for e in entries),
           'approval_entries': sum(bool(APPROVAL_RE.search(e)) for e in entries)}
    return row, entries


MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_SHINGLES = 100000
# CONVENTION NOT IN THE HERMES SOURCE (third_party_convention; a grep of the Hermes source
# finds no 'memory-bg-review'): some homes hold
#   <home>/backups/memory-bg-review/<YYYYMMDD-HHMMSS>/<hex id>/{MEMORY.md,USER.md}
# (typically a handful of snapshot directories, one hex id directory each).
# Only that exact shape at the ROOT home is admitted; absent folder => not present.
SNAPSHOT_PARTS = ('backups', 'memory-bg-review')
SNAPSHOT_STAMP_RE = re.compile(r'[0-9]{8}-[0-9]{6}')
SNAPSHOT_ID_RE = re.compile(r'[0-9a-f]{4,64}')
MEMORY_NAMES = ('MEMORY.md', 'USER.md')
# memory_store.db: hermes_cli/backup.py:1114; plugin-data/<namespace>:
# hermes_cli/plugins_state.py:143. STATE_DIR_NAMES are the state directory
# names of a third-party memory plugin, NOT defined by Hermes; kept here as data and
# emitted only as these fixed labels. All of these are listed/lstat'ed, never opened.
STATE_DIR_NAMES = frozenset({'memlock', 'memory-lock', 'memory_lock'})
TRUNCATION_REASONS = ('time_budget', 'tree_entries', 'depth', 'files', 'file_bytes',
                      'total_bytes', 'entries', 'shingles', 'credential_path', 'symlink',
                      'special_file', 'unreadable', 'encoding', 'pending_shape', 'snapshot_shape')


def _snapshot_shape(parts):
    """True for the snapshot root itself or an exact prefix of the admitted shape."""
    parts = tuple(parts)
    if parts[:2] != SNAPSHOT_PARTS or not 2 <= len(parts) <= 5:
        return False
    checks = (SNAPSHOT_STAMP_RE.fullmatch, SNAPSHOT_ID_RE.fullmatch, MEMORY_NAMES.__contains__)
    return all(check(part) for check, part in zip(checks, parts[2:]))


def _declared_credential(full):
    # The shared declared-credential test (declared paths by spelling and by file
    # identity, and uncertain roots), applied to the absolute snapshot path.
    from .policy import declared_credential
    return declared_credential(os.path.abspath(full))


def _credential_name(parts):
    # Conservative name-only exclusions on top of the shared predicate.
    return any(any(w in p.casefold() for w in ('token', 'secret', 'credential')) or
               p.casefold().startswith('.env') or p.casefold().endswith(('.pem', '.key')) or
               credential_path(PurePath(p)) for p in parts if p not in SNAPSHOT_PARTS)


def _blocked(root, rel):
    """Shared credential predicate on the ABSOLUTE path, plus one narrow exception.

    audit.policy.credential_path refuses everything under 'backups/'. The only
    exception: the root home's backups/memory-bg-review/<stamp>/<hex id>/ chain and
    its exact MEMORY.md / USER.md basenames. Every other backups/ path, including
    any other name inside a snapshot directory, stays refused.
    """
    parts = tuple(rel.parts)
    if any(p in ('', '.', '..') for p in parts) or _credential_name(parts):
        return True
    if parts[:2] == SNAPSHOT_PARTS:
        return not _snapshot_shape(parts) or credential_path(root) or _declared_credential(root / rel)
    return credential_path(root / rel)


def _read_allowed(rel):
    parts = tuple(rel.parts)
    if parts[:1] == ('profiles',) and len(parts) > 2:
        parts = parts[2:]
    if len(parts) == 2 and parts[0] == 'memories' and parts[1] in MEMORY_NAMES:
        return True
    if len(parts) == 3 and parts[:2] == ('pending', 'memory') and parts[2].endswith('.json'):
        return True
    return len(rel.parts) == 5 and _snapshot_shape(rel.parts)


def _read_private_file(root, rel, cap, on_read):
    # Not the fingerprint/capture reader on purpose: capture.read retains bytes for
    # the shared capture and content_digest may create the audit key; neither may
    # hold private memory text. Output privacy is unaffected: this module emits only
    # counts and closed labels, and its result still goes through make_finding /
    # make_component_envelope like every module. The allowlist and credential checks
    # are enforced HERE as well, so no caller can widen what this reader opens.
    if not _read_allowed(rel) or _blocked(root, rel):
        raise PermissionError('not an admitted memory file')
    with _open_root_dir_fd(root) as (root_fd, _, _):
        with _walk_parent_dir_fds(root_fd, rel.parts[:-1]) as parent_fd:
            before = os.stat(rel.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise OSError('nonregular')
            if before.st_size > cap:
                return None
            try:
                fd = open_checked(rel.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0),
                                  dir_fd=parent_fd, full_path=os.path.abspath(root / rel))
            except CredentialStoreNotOpened:
                raise PermissionError('not an admitted memory file') from None
            try:
                identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                if not stat.S_ISREG(os.fstat(fd).st_mode) or identity(before) != identity(os.fstat(fd)):
                    raise OSError('changed')
                data = bytearray()
                while len(data) < before.st_size:
                    chunk = os.read(fd, min(65536, before.st_size - len(data)))
                    on_read(len(chunk))
                    if not chunk:
                        break
                    data.extend(chunk)
                after = os.stat(rel.name, dir_fd=parent_fd, follow_symlinks=False)
                if len(data) != before.st_size or identity(before) != identity(os.fstat(fd)) or identity(before) != identity(after):
                    raise OSError('changed')
                return bytes(data)
            finally:
                os.close(fd)


class _Scan:
    def __init__(self, root, clock):
        self.root, self.clock = root, clock
        self.start = clock()
        self.deadline = self.start + MAX_SECONDS
        self.reasons = set()
        self.limits = dict(max_file_bytes=MAX_FILE_BYTES, max_files=MAX_FILES,
                           max_tree_entries=MAX_TREE_ENTRIES, max_depth=MAX_DEPTH,
                           max_entries=MAX_ENTRIES, max_seconds=MAX_SECONDS,
                           max_total_bytes=MAX_TOTAL_BYTES, max_shingles=MAX_SHINGLES,
                           files_read=0, bytes_read=0, tree_entries=0, cuts=0)

    def cut(self, reason):
        self.reasons.add(reason)
        self.limits['cuts'] += 1

    def expired(self):
        if 'time_budget' in self.reasons:
            return True
        if self.clock() >= self.deadline:
            self.cut('time_budget')
            return True
        return False

    def children(self, rel, *, names=None):
        if self.expired():
            return []
        if _blocked(self.root, rel):
            self.cut('credential_path')
            return []
        batch = []
        try:
            # Descriptor-relative discovery refuses even swapped symlink parents.
            with _open_root_dir_fd(self.root) as (root_fd, _, _):
                with _walk_parent_dir_fds(root_fd, rel.parts) as fd:
                    with os.scandir(fd) as it:
                        for entry in it:
                            if self.expired():
                                break
                            if self.limits['tree_entries'] >= MAX_TREE_ENTRIES:
                                self.cut('tree_entries')
                                break
                            self.limits['tree_entries'] += 1
                            if names is not None and entry.name not in names:
                                continue
                            p = rel / entry.name
                            if entry.name.startswith('._'):
                                continue  # macOS AppleDouble sidecars, not memories.
                            if _blocked(self.root, p):
                                # Outside the admitted snapshot shape => shape, not secret.
                                off_shape = (p.parts[:2] == SNAPSHOT_PARTS and not _snapshot_shape(p.parts)
                                             and not _credential_name(p.parts))
                                self.cut('snapshot_shape' if off_shape else 'credential_path')
                                continue
                            st = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(st.st_mode):
                                self.cut('symlink')
                            elif stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode):
                                batch.append((p, st))
                            else:
                                self.cut('special_file')
        except FileNotFoundError:
            pass
        except (OSError, ValueError, RuntimeError):
            self.cut('unreadable')
        return sorted(batch, key=lambda pair: str(pair[0]))

    def walk(self, rel, depth=0):
        for p, st in self.children(rel):
            if stat.S_ISDIR(st.st_mode):
                if depth >= MAX_DEPTH:
                    self.cut('depth')
                else:
                    yield from self.walk(p, depth + 1)
            else:
                yield p, st

    def absent(self, rel):
        if self.expired() or _blocked(self.root, rel):
            return False
        try:
            with _open_root_dir_fd(self.root) as (root_fd, _, _):
                with _walk_parent_dir_fds(root_fd, rel.parts[:-1]) as fd:
                    os.stat(rel.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except (OSError, ValueError, RuntimeError):
            pass
        return False

    def read(self, rel):
        if self.expired():
            return None
        if self.limits['files_read'] >= MAX_FILES:
            self.cut('files')
            return None
        if _blocked(self.root, rel):
            self.cut('credential_path')
            return None
        remaining = MAX_TOTAL_BYTES - self.limits['bytes_read']
        if remaining <= 0:
            self.cut('total_bytes')
            return None
        cap = min(MAX_FILE_BYTES, remaining)
        self.limits['files_read'] += 1
        try:
            def charge(size):
                self.limits['bytes_read'] += size
            raw = _read_private_file(self.root, rel, cap, charge)
            if raw is None:
                self.cut('file_bytes' if MAX_FILE_BYTES <= remaining else 'total_bytes')
                return None
            text = raw.decode('utf-8-sig').replace('\r\n', '\n').replace('\r', '\n')
            if '\x00' in text:
                raise ValueError('binary')
            return text, raw
        except (OSError, RuntimeError):
            self.cut('unreadable')
            return None
        except (ValueError, UnicodeError):
            self.cut('encoding')
            return None


def _duplicates(records, scan):
    owners, occurrence = {}, Counter()
    within, total = 0, 0
    near_entries = []
    for index, (_, entries) in enumerate(records):
        counts = Counter(_normal(e) for e in entries)
        within += sum(n - 1 for n in counts.values())
        total += sum(counts.values())
        occurrence.update(counts)
        for entry in counts:
            owners.setdefault(entry, set()).add(index)
        near_entries.extend(_normal(e) for e in entries)
    across = sum(occurrence[e] for e, files in owners.items() if len(files) > 1)
    if len(near_entries) > MAX_ENTRIES:
        scan.cut('entries')
    shingles, used = [], 0
    for entry in near_entries[:MAX_ENTRIES]:
        if scan.expired():
            break
        words = entry.split()
        count = max(0, len(words) - SHINGLE_WORDS + 1)
        if used + count > MAX_SHINGLES:
            scan.cut('shingles')
            break
        used += count
        shingles.append((entry, {tuple(words[i:i + SHINGLE_WORDS]) for i in range(count)}))
    pairs = 0
    for i, (entry, a) in enumerate(shingles):
        if scan.expired():
            break
        for other, b in shingles[:i]:
            if a and b and entry != other:
                # Jaccard overlap, NOT containment of a short generic sentence.
                intersection = len(a & b)
                pairs += intersection / (len(a) + len(b) - intersection) >= NEAR_DUPLICATE_SHARE
    return {'within_file_extra_entries': within, 'across_file_entries': across,
            'cross_file_share': across / total if total else 0,
            'near_duplicate_pairs': pairs,
            'coverage': 'could_not_verify' if scan.reasons else 'verified'}


def _snapshot_summary(records):
    summaries = []
    groups = sorted({(r[0]['profile_index'], r[0]['kind']) for r in records})
    for profile_index, kind in groups:
        rows = [r for r in records if r[0]['kind'] == kind and r[0]['profile_index'] == profile_index]
        if not rows:
            continue
        # Rows arrive sorted by <stamp>/<id> path; stamps are fixed-width digits, so
        # lexical order is chronological. No identifiers, texts or hashes escape.
        sizes = [r[0]['characters'] for r in rows]
        percents = [r[0]['percent_of_limit'] for r in rows if r[0]['percent_of_limit'] is not None]
        order_known = all(r[3] for r in rows)
        added = removed = 0
        changes = []
        for previous, current in zip(rows, rows[1:]) if order_known else ():
            old = Counter(_normal(e) for e in previous[1])
            new = Counter(_normal(e) for e in current[1])
            a, d = sum((new - old).values()), sum((old - new).values())
            added += a
            removed += d
            changes.append({'entries_added': a, 'entries_removed': d})
        summaries.append({'kind': kind, 'profile_index': profile_index, 'files': len(rows), 'min_characters': min(sizes),
                          'max_characters': max(sizes), 'min_percent_of_limit': min(percents) if percents else None,
                          'max_percent_of_limit': max(percents) if percents else None,
                          'identical_extra_snapshots': len(rows) - len({r[2] for r in rows}),
                          'growth_characters': sizes[-1] - sizes[0] if order_known else None,
                          'chronology_coverage': 'verified' if order_known else 'could_not_verify',
                          'entries_added': added if order_known else None,
                          'entries_removed': removed if order_known else None, 'changes': changes})
    return summaries


def _pending(paths, texts, scan):
    result: dict = {'count': len(paths), 'stale_edits': 0, 'approval_edits': 0, 'operations': 0,
              'unverified_edits': 0}
    # Entries holding an approval word, split and regex-scanned ONCE per target text
    # (not once per operation): "some entry containing old matches APPROVAL_RE" is
    # the same as "old is in some approval entry".
    approval_entries: dict = {}
    for rel, profile in paths:
        # Deadline per file and per operation (_expired): a file cut short is unverified for time_budget.
        read = None if (cut := _expired(scan)) else scan.read(rel)
        stale = approval = invalid = False
        try:
            record = json.loads(read[0]) if read else None
            payload = record.get('payload') if isinstance(record, dict) else None
            if not isinstance(payload, dict) or payload.get('target') not in ('memory', 'user'):
                raise ValueError('shape')
            # tools/write_approval.py:66-84; tools/memory_tool.py:131-140,165-176.
            target = texts.get((profile, payload['target']))
            target_rel = rel.parent.parent.parent / 'memories' / (payload['target'].upper() + '.md')
            if target is None and scan.absent(target_rel):
                target = ''
            ops = payload.get('operations') if payload.get('action') == 'batch' else [payload]
            if not isinstance(ops, list) or not ops:
                raise ValueError('shape')
            for op in ops:
                if (cut := _expired(scan)):
                    break
                if not isinstance(op, dict) or op.get('action') not in ('add', 'remove', 'replace', 'patch'):
                    raise ValueError('shape')
                result['operations'] += 1
                if op['action'] == 'add':
                    continue
                old = op.get('old_text')
                if not isinstance(old, str) or not old:
                    raise ValueError('shape')
                if target is None:
                    invalid = True
                elif not stale:
                    stale = old not in target
                # Matched entry is pinned by tools/memory_tool.py:67-82.
                pinned = op.get('matched_entry', '')
                if not isinstance(pinned, str):
                    raise ValueError('shape')
                if approval:
                    continue  # already counted for this file; the checks below cannot raise
                text = target or ''
                if text not in approval_entries:
                    approval_entries[text] = [e for e in _entries(text) if APPROVAL_RE.search(e)]
                approval = bool(APPROVAL_RE.search(old) or APPROVAL_RE.search(pinned) or
                                any(old in e for e in approval_entries[text]))
        except (ValueError, TypeError, RecursionError):
            invalid = True
        result['stale_edits'] += stale
        result['approval_edits'] += approval
        result['unverified_edits'] += invalid or cut
        if invalid and not cut:
            scan.cut('pending_shape')
    result['coverage'] = 'could_not_verify' if result['unverified_edits'] or scan.reasons else 'verified'
    return result


def _profile_config(root):
    """memory.* values from <profile>/config.yaml: (values, readable).

    Same reader, parser and managed-overlay rule as audit.write_settings; config.yaml
    is not a credential file and no other file is opened here. Missing file =>
    shipped defaults; unreadable, duplicate keys or a managed overlay => unknown.
    """
    from .facts import DuplicateConfigKeyError, _parse_simple_yaml_mapping
    from .fingerprint import safe_read_regular_file
    from .write_settings import _has_managed_overlay
    if _has_managed_overlay():
        return {}, False
    try:
        read = safe_read_regular_file(root, 'config.yaml', max_bytes=MAX_CONFIG_BYTES)
    except (OSError, ValueError, RuntimeError):
        return {}, False
    if read.kind == 'missing':
        return {}, True
    if read.coverage != 'verified' or not read.stable or read.content is None:
        return {}, False
    try:
        config = _parse_simple_yaml_mapping(read.content.decode('utf-8'), reject_duplicate_keys=True)
    except (DuplicateConfigKeyError, ValueError, UnicodeError, RecursionError):
        return {}, False
    memory = config.get('memory') if isinstance(config, dict) else None
    return (memory if isinstance(memory, dict) else {}), True


def _resolve_inputs(root, memory_char_limit, user_char_limit, memory_provider, home_os):
    """Caller values win; FROM_PROFILE reads config.yaml (limits, provider) or the host OS."""
    sources, values = {}, {}
    config = None
    for name, value, field, default in (
            ('memory_char_limit', memory_char_limit, 'memory_char_limit', DEFAULT_MEMORY_LIMIT),
            ('user_char_limit', user_char_limit, 'user_char_limit', DEFAULT_USER_LIMIT),
            ('memory_provider', memory_provider, 'provider', None)):
        if value is not FROM_PROFILE:
            values[name], sources[name] = value, 'caller'
            continue
        if config is None:
            config = _profile_config(root)
        memory, readable = config
        raw = memory.get(field, default)
        if not readable or (isinstance(raw, str) and '${' in raw):
            values[name], sources[name] = (FROM_PROFILE, 'could_not_verify')
        elif default is None:
            ok = raw is None or isinstance(raw, str)
            values[name] = raw if ok else FROM_PROFILE
            sources[name] = ('config' if field in memory else 'default') if ok else 'could_not_verify'
        elif type(raw) is int and raw > 0:
            values[name], sources[name] = raw, 'config' if field in memory else 'default'
        else:
            values[name], sources[name] = None, 'could_not_verify'
    if home_os is FROM_PROFILE:
        values['home_os'] = HOST_OS.get(sys.platform)
        sources['home_os'] = 'host' if values['home_os'] else 'could_not_verify'
    else:
        values['home_os'], sources['home_os'] = home_os, 'caller'
    for name in ('memory_char_limit', 'user_char_limit'):
        if values[name] is FROM_PROFILE:
            values[name] = None
    # A caller value the module cannot use is reported as unknown, not as 'caller'.
    usable = {'memory_char_limit': lambda v: type(v) is int and v > 0,
              'user_char_limit': lambda v: type(v) is int and v > 0,
              'memory_provider': lambda v: v is None or isinstance(v, str),
              'home_os': lambda v: v in HOST_OS.values()}
    for name, check in usable.items():
        if sources[name] == 'caller' and not check(values[name]):
            sources[name] = 'could_not_verify'
    return values, sources


def _char_limits(limits, input_sources, rows, scan):
    """Configured limits against the shipped defaults (main-home files only)."""
    out = {}
    for kind, shipped in (('memory', DEFAULT_MEMORY_LIMIT), ('user', DEFAULT_USER_LIMIT)):
        configured = limits[kind]
        row = next((r for r in rows if r['kind'] == kind and r['profile_index'] == 0), None)
        if row is not None and row['coverage'] == 'verified':
            characters = row['characters']
        elif row is None and scan.absent(Path('memories') / (kind.upper() + '.md')):
            characters = 0
        else:
            characters = None
        out[kind] = {'shipped_char_limit': shipped, 'configured_char_limit': configured,
                     'limit_ratio_to_shipped': round(configured / shipped, 2) if configured else None,
                     'limit_source': input_sources[kind + '_char_limit'],
                     'chars_over_shipped_limit': max(0, characters - shipped) if characters is not None else None,
                     '_characters': characters}
    return out


def _limit_raised_finding(char_limits):
    raised = [v for v in char_limits.values() if v['limit_source'] == 'config'
              and v['configured_char_limit'] is not None and v['configured_char_limit'] > v['shipped_char_limit']]
    if not raised:
        return None
    evidence = {}
    for kind, v in char_limits.items():
        for key, value in (('shipped_char_limit', v['shipped_char_limit']),
                           ('configured_char_limit', v['configured_char_limit']),
                           ('limit_ratio_to_shipped', v['limit_ratio_to_shipped']),
                           ('characters', v['_characters'])):
            if value is not None:  # numeric only; unknown values are left out, never guessed
                evidence[f'{kind}_{key}'] = value
    review = any(v['configured_char_limit'] / v['shipped_char_limit'] >= RAISED_REVIEW_RATIO for v in raised)
    return _finding('limit_raised_above_shipped', evidence, 'review_suggested' if review else 'info')


def _expired(scan):
    """scan.expired() for _pending. One in-cap pending file can hold thousands of operations,
    each a substring search of the target text, so the deadline is checked per operation.
    A stand-in scan object without a deadline never expires."""
    expired = getattr(scan, 'expired', None)
    return bool(expired()) if expired is not None else False


def _unmeasured_row(kind, scope, profile_index, size):
    return {'kind': kind, 'scope': scope, 'profile_index': profile_index, 'bytes': size,
            'characters': None, 'entries': None, 'coverage': 'could_not_verify'}


def _measured_row(text, kind, scope, profile_index, size, limit, home_os, native, families_known):
    row, entries = _metrics(text, kind, scope, limit, home_os)
    row.update(profile_index=profile_index, bytes=size)
    row['foreign_technology_entries'] = sum(bool(set(technology_counts(e)) - native) for e in entries) if families_known else None
    row['foreign_technology_coverage'] = 'verified' if families_known else 'could_not_verify'
    return row, entries


def _scan_snapshots(scan, limits, home_os, native, families_known):
    """Root home only; exact convention shape (see SNAPSHOT_* above): (rows, records, groups)."""
    snapshots, records, groups = [], [], set()
    for stamp_rel, st in scan.children(Path(*SNAPSHOT_PARTS)):
        if not stat.S_ISDIR(st.st_mode) or not SNAPSHOT_STAMP_RE.fullmatch(stamp_rel.name):
            scan.cut('snapshot_shape')
            continue
        ids = scan.children(stamp_rel)
        if not ids:
            scan.cut('snapshot_shape')
        for id_rel, id_st in ids:
            if not stat.S_ISDIR(id_st.st_mode) or not SNAPSHOT_ID_RE.fullmatch(id_rel.name):
                scan.cut('snapshot_shape')
                continue
            found = False
            for rel, file_st in scan.children(id_rel, names=MEMORY_NAMES):
                if not stat.S_ISREG(file_st.st_mode):
                    scan.cut('snapshot_shape')
                    continue
                found = True
                groups.add(rel.parent)
                kind = 'memory' if rel.name == 'MEMORY.md' else 'user'
                read = scan.read(rel)
                if read is None:
                    snapshots.append(_unmeasured_row(kind, 'snapshot', 0, file_st.st_size))
                    continue
                row, entries = _measured_row(read[0], kind, 'snapshot', 0, file_st.st_size, limits[kind], home_os, native, families_known)
                snapshots.append(row)
                records.append((row, entries, read[1], True))
            if not found:
                scan.cut('snapshot_shape')
    return snapshots, records, groups


def _profile_stores(scan, profile, profile_index, children):
    """memory_store.db and state-directory inventory for one profile (metadata only)."""
    stores = []
    for rel, st in children:
        if rel.name == 'memory_store.db' and stat.S_ISREG(st.st_mode):
            stores.append({'name': 'memory_store.db', 'profile_index': profile_index,
                           'files': 1, 'bytes': st.st_size, 'overlap': 'could_not_compare'})
    state_dirs = [(p, st) for p, st in children if p.name in STATE_DIR_NAMES]
    state_dirs.extend((p, st) for p, st in scan.children(profile / 'plugin-data', names=STATE_DIR_NAMES))
    for rel, st in state_dirs:
        if not stat.S_ISDIR(st.st_mode):
            continue
        sizes = Counter(s.st_size for _, s in scan.walk(rel))
        stores.append({'name': rel.name, 'profile_index': profile_index,
                       'files': sum(sizes.values()), 'bytes': sum(s * n for s, n in sizes.items()),
                       'same_size_groups': sum(n > 1 for n in sizes.values()),
                       'same_size_extra_files': sum(n - 1 for n in sizes.values()),
                       'overlap': 'could_not_compare'})
    return stores


def _count_findings(all_rows, duplicates, stores, pending):
    findings = []
    for rule, count, classification in (
        ('over_limit', sum(bool(r['over_limit']) for r in all_rows), 'review_suggested'),
        ('mostly_dated_entries', sum(r['entries'] >= MIN_DATED_ENTRIES and r['dated_entries'] > r['entries'] * DATED_SHARE for r in all_rows), 'info'),
        # Design decision: other-machine text is left over, not a current fault => info.
        ('other_machine_entries', sum(r['other_machine_entries'] >= OTHER_MACHINE_COUNT or r['other_machine_entries'] > 0 and r['other_machine_entries'] >= r['entries'] * OTHER_MACHINE_SHARE for r in all_rows if r['other_machine_entries'] is not None), 'info'),
        ('standing_orders', sum(r['standing_order_entries'] for r in all_rows), 'review_suggested' if any(r['unasked_write_entries'] for r in all_rows) else 'info'),
        ('duplicate_entries', duplicates['within_file_extra_entries'] + duplicates['across_file_entries'] + duplicates['near_duplicate_pairs'], 'info'),
        ('foreign_technology_entries', sum(r['foreign_technology_entries'] or 0 for r in all_rows), 'review_suggested'),
        ('memory_state_sprawl', sum(s['files'] > STATE_SPRAWL_FILES for s in stores if s['name'] != 'memory_store.db'), 'info'),
        ('stale_pending_edits', pending['stale_edits'], 'info'),
        ('pending_edit_changes_approval_entry', pending['approval_edits'], 'review_suggested')):
        if count:
            findings.append(_finding(rule, {'count': count}, classification))
    return findings


def audit_memory_load(*, profile_path, memory_char_limit=FROM_PROFILE, user_char_limit=FROM_PROFILE,
                      memory_provider=FROM_PROFILE,
                      prompt_injecting_plugins: list[str] | None = None,
                      project_families: dict | None = None, home_os=FROM_PROFILE, clock=time.monotonic):
    """Measure memory load for one Hermes home; only profile_path is required.

    Omitted limits and provider are read from <profile>/config.yaml (memory.*), an
    omitted home_os is the host OS. An explicit None means unknown. The resolved
    limits apply to all inventoried profiles/snapshots; historical per-profile
    configurations, runtime enablement and actual injections are unknown.
    project_families maps family labels to counts; prompt_injecting_plugins lists
    enabled plugin names that declare prompt-injecting hooks (both from the caller).
    """
    root = Path(profile_path)
    scan = _Scan(root, clock)
    resolved, input_sources = _resolve_inputs(root, memory_char_limit, user_char_limit, memory_provider, home_os)
    memory_char_limit, user_char_limit = resolved['memory_char_limit'], resolved['user_char_limit']
    memory_provider, home_os = resolved['memory_provider'], resolved['home_os']
    limits = {}
    for kind, value in (('memory', memory_char_limit), ('user', user_char_limit)):
        # None = not supplied = unknown: never compare against a guessed default.
        limits[kind] = value if type(value) is int and value > 0 else None
    os_known = isinstance(home_os, str) and home_os in ('linux', 'macos', 'windows')
    home_os = home_os if os_known else None
    families_known = isinstance(project_families, dict) and all(isinstance(k, str) for k in project_families)
    native = set(project_families or {}) if families_known else set()
    plugin_known = isinstance(prompt_injecting_plugins, list) and all(isinstance(p, str) for p in prompt_injecting_plugins)
    plugin_count = len(set(prompt_injecting_plugins or [])) if plugin_known else None
    provider_known = memory_provider is not FROM_PROFILE and (memory_provider is None or isinstance(memory_provider, str))
    provider = memory_provider.strip().lower() if isinstance(memory_provider, str) else ''
    external = provider not in CORE_PROVIDERS if provider_known else None
    # No project families supplied (a home with no registered projects): only the
    # foreign-technology sub-check is skipped, and foreign_technology_coverage says so.
    # It does not make the whole section unverified.
    families_ok = families_known or project_families is None
    input_unknown = not all((os_known, families_ok, plugin_known, provider_known, all(limits.values())))
    rows, records, stores, pending_paths = [], [], [], []
    texts = {}
    root_names = STATE_DIR_NAMES | {'profiles', 'memory_store.db'}
    root_children = scan.children(Path(), names=root_names)
    profiles = [(Path(), 0)]
    if any(p.name == 'profiles' and stat.S_ISDIR(st.st_mode) for p, st in root_children):
        profiles.extend((p, i + 1) for i, (p, st) in enumerate(scan.children(Path('profiles')))
                        if stat.S_ISDIR(st.st_mode))
    for profile, profile_index in profiles:
        if scan.expired():
            break
        # Read ONLY the two builtin filenames, never arbitrary Markdown neighbors.
        for rel, st in scan.children(profile / 'memories'):
            if rel.name not in ('MEMORY.md', 'USER.md') or not stat.S_ISREG(st.st_mode):
                continue
            kind = 'memory' if rel.name == 'MEMORY.md' else 'user'
            scope = 'main' if profile_index == 0 else 'profile'
            read = scan.read(rel)
            if read is None:
                # Preserve lstat-only evidence even when content cannot be measured.
                rows.append(_unmeasured_row(kind, scope, profile_index, st.st_size))
                continue
            text, _ = read
            row, entries = _measured_row(text, kind, scope, profile_index, st.st_size, limits[kind], home_os, native, families_known)
            rows.append(row)
            records.append((row, entries))
            texts[(profile_index, kind)] = text
        for rel, st in scan.children(profile / 'pending' / 'memory'):
            if rel.suffix == '.json' and stat.S_ISREG(st.st_mode):
                pending_paths.append((rel, profile_index))
        children = root_children if profile_index == 0 else scan.children(profile, names=root_names)
        stores.extend(_profile_stores(scan, profile, profile_index, children))
    # Root home only; exact convention shape (see SNAPSHOT_* above).
    snapshots, snapshot_records, snapshot_groups = _scan_snapshots(scan, limits, home_os, native, families_known)
    pending = _pending(pending_paths, texts, scan)
    duplicates = _duplicates(records, scan)
    builtin = any(r['profile_index'] == 0 and r['entries'] for r in rows)
    if not builtin and any((0, kind) not in texts and not scan.absent(Path('memories') / (kind.upper() + '.md'))
                           for kind in ('memory', 'user')):
        builtin = None
    active = int(bool(builtin)) + int(bool(external)) + (plugin_count or 0)
    systems = {'builtin_nonempty': builtin, 'external_configured': external,
               'external_provider': provider if external and provider in KNOWN_PROVIDERS else 'other' if external else None,
               'prompt_injecting_plugins': plugin_count, 'active_mechanisms': active,
               'coverage': 'verified' if plugin_known and provider_known and builtin is not None else 'could_not_verify', 'stores': stores}
    all_rows = [r for r in rows + snapshots if r['coverage'] == 'verified']
    findings = _count_findings(all_rows, duplicates, stores, pending)
    char_limits = _char_limits(limits, input_sources, rows, scan)
    if (raised := _limit_raised_finding(char_limits)) is not None:
        findings.append(raised)
    char_limits = {k: {f: x for f, x in v.items() if f != '_characters'} for k, v in char_limits.items()}
    if active >= 2:
        findings.append(_finding('multiple_memory_systems', {'mechanisms': active, 'builtin_nonempty': bool(builtin)},
                                 'review_suggested'))
    measured = bool(rows or snapshots or stores or pending_paths)
    # An existing home that was listed in full and holds nothing to measure is a complete
    # answer ('not_measured' = nothing found); the summary says so in one line, so no
    # second 'could not be verified' note is added. A missing home is never clean.
    nothing_to_measure = not measured and not scan.reasons and os.path.lexists(root)
    coverage = ('could_not_verify' if scan.reasons or input_unknown or not (measured or nothing_to_measure)
                else 'verified')
    # Reason codes for an unverified result that no scan cut explains (not counted as cuts):
    # the home folder was not found (its settings then cannot be read either); a setting
    # the check needs could not be read.
    reasons = set(scan.reasons)
    if not os.path.lexists(root):
        reasons.add('missing')
    elif input_unknown:
        reasons.add('input_unknown')
    if coverage == 'could_not_verify' and not nothing_to_measure:
        findings.append(_finding('could_not_verify', {'cuts': scan.limits['cuts']}, coverage='could_not_verify'))
    section = {'status': 'completed' if measured else 'not_measured', 'coverage': coverage,
               'files': rows, 'snapshots': {'count': len(snapshot_groups), 'files': snapshots,
                                          'by_kind': _snapshot_summary(snapshot_records)},
               'duplicates': duplicates, 'systems': systems, 'pending': pending,
               'limits': scan.limits, 'truncated_by': sorted(reasons),
               'other_os_coverage': 'verified' if os_known else 'could_not_verify',
               'foreign_technology_coverage': 'verified' if families_known else 'could_not_verify',
               # Why the foreign-technology sub-check was skipped: no registered projects to
               # compare with, or project families the check could not read.
               'foreign_technology_reason': (None if families_known else 'no_projects'
                                             if project_families is None else 'input_unknown'),
               'input_sources': input_sources, 'char_limits': char_limits}
    # Run-dependent values stay OUTSIDE the section so the report digest is stable.
    elapsed = scan.clock() - scan.start
    run_metrics = {'elapsed_ms': max(0, round(elapsed * 1000)) if isinstance(elapsed, (int, float)) else None}
    return make_component_envelope(findings=findings, coverage=coverage,
                                   extra={'memory_load': section, 'run_metrics': run_metrics})
