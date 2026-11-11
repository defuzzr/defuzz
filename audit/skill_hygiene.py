"""Bounded, read-only skill package hygiene; source text never leaves this module.

Residue score = sum(4 + min(2, count - 1) for each nonempty evidence class).
Seven classes; review at >=13. Class diversity dominates repetition (one class
caps at 6). Headings and bullet counts are descriptive only, never evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .contract import make_component_envelope, make_finding
from .evidence_constants import FINDING_CONSEQUENCES
from .facts import _parse_simple_yaml_mapping, parse_frontmatter_stdlib
from .fingerprint import safe_read_regular_file
from .policy import credential_path

MAX_FILE_BYTES = 1024 * 1024  # Bound each text/binary read and regex input.
MAX_FILES_PER_SKILL = 256  # Large generated packages are unknown, not clean.
MAX_TREE_ENTRIES = 10000  # Bound discovery as well as content processing.
MAX_TOTAL_BYTES = 32 * 1024 * 1024  # Bound the entire component's retained reads.
RESIDUE_THRESHOLD = 13  # Three classes plus a repeat, or four distinct classes.
DATED_LESSON_LINES = 3  # Second residue trigger: >=3 date-leading lines outside frontmatter/changelog/tables.
OVERSIZED_BODY_CHARS = 24000  # Upstream 186 bodies: nearest-rank p95=23549; see audit-scope.md.
# Hermes tools/skills_sync.py:36-38,113-128: UTF-8 BOM-tolerant name:MD5 lines; v1 has no hash.
MANIFEST = 'skills/.bundled_manifest'
# Hermes tools/skills_sync_optional.py:41-58: ignore these dirs and bytecode alongside .py only.
CACHE_DIRS = frozenset({'__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'})
# Hermes agent/skill_utils.py:26-36,38-56: excluded VCS/dependency/cache/archive/hub dirs and
# progressive-disclosure support dirs inside a skill package (never scanned as standalone skills).
EXCLUDED_SKILL_DIRS = frozenset({
    '.git', '.github', '.hub', '.archive', '.curator_backups', '.locks', '.hermes-dist',
    '.venv', 'venv', 'node_modules', 'site-packages', '__pycache__',
    '.tox', '.nox', '.pytest_cache', '.mypy_cache', '.ruff_cache',
})
SKILL_SUPPORT_DIRS = frozenset({'references', 'templates', 'assets', 'scripts'})
PLACEHOLDER_USERS = frozenset({
    'user', 'x', 'you', 'me', 'username', 'name', 'USER', 'Shared', 'Public',
    'ubuntu', 'runner', 'root', 'alice', 'bob', 'admin', 'example',
    'yourname', 'your-username', 'myuser', '...',
})
_PLACEHOLDER_USERS_LOWER = frozenset(u.casefold() for u in PLACEHOLDER_USERS)
TICKET_PREFIX_DENYLIST = frozenset({
    'utf', 'sha', 'iso', 'rfc', 'md', 'cve', 'cwe', 'http', 'https', 'tls', 'ssl',
    'aes', 'rsa', 'dsa', 'ecdsa', 'base', 'top', 'gpt', 'glm', 'llm', 'agi',
    'erc', 'eip', 'bip', 'hip', 'pep', 'pico', 'agpl', 'gpl', 'lgpl', 'mit', 'bsd',
    'cifar', 'mnist', 'icml', 'ijcai', 'neurips', 'iclr', 'ieee', 'ansi', 'nist', 'fips',
    'pid', 'tts', 'stt', 'cpu', 'gpu', 'tpu', 'npu', 'usb', 'pci', 'arm', 'avx', 'sse',
    'xss', 'csrf', 'ssrf', 'sqli', 'rce', 'xxe', 'intellect', 'pkcs', 'cox',
    'ecma', 'psr', 'kb', 'jep', 'jsr', 'bcp', 'std', 'owasp', 'wcag', 'posix',
    'itu', 'mil', 'din', 'en', 'bs', 'as',
})
_DATE_LINE_EXEMPT_RE = re.compile(
    r'(?<![\d.])v?\d+\.\d+(?:\.\d+)?(?![\d.])|\b(?:released?|versions?|changelog|updated|last[ \t]+(?:verified|updated))\b',
    re.I,
)
_DATED_LESSON_PREFIX_RE = re.compile(r'^\s*(?:(?:[-*+]|\d+[.)])\s+)?[*_`\[\(]*\s*')
# Fixed patterns, no nested/unbounded backtracking quantifiers; each pass is linear in input.
# The ticket path form `seg(/seg)+[#!]digits` is NOT in this table: as a regex the engine
# retried it at every word boundary of a long `a/a/a/...` run and rescanned the run each
# time (quadratic). `_ticket_ref_spans` matches it with one scan per path run instead.
PATTERNS = {
    'dates': re.compile(
        r'(?<!["\'/\w])(?:\d{4}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])'
        r'|(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/\d{4}'
        r'|(?:0?[1-9]|[12]\d|3[01])[ \t]{1,3}(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?),?[ \t]{1,3}\d{4}'
        r'|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)[ \t]{1,3}(?:0?[1-9]|[12]\d|3[01])(?:,?[ \t]{1,3}\d{4})?)(?!["\'/\w]|\.\d)',
        re.I,
    ),
    'ticket_refs': re.compile(
        r'(?i:\bgithub\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull)/\d+\b)'
        r'|(?i:\b(?:PR|issue|ticket)[ \t]{1,3}#?\d+\b)'
        r'|(?i:\b(?:pull|fixes|closes|see)[ \t]{1,3}#\d+\b)'
        r'|(?<![:\\@\w.-])[A-Za-z][A-Za-z0-9_.-]{1,63}#\d{2,}\b'
        # (the path form `seg(/seg)+[#!]\d+\b` ranks here; see _ticket_ref_spans)
        r'|(?<![A-Za-z0-9_.-])(?P<prefix>[A-Z]{2,10})-(?P<num>[1-9]\d{1,6})(?![A-Za-z0-9_.-])'
    ),
    'commit_refs': re.compile(
        r'\b(?:commit|sha|revision|cherry-pick)[:\s]{1,4}[0-9a-f]{7,40}\b'
        r'|(?<![#\w])[0-9a-f]{7,40}\.\.[0-9a-f]{7,40}(?!\w)'
        r'|(?<!["\'/#\w])[0-9a-f]{40}(?![\w"\'])', re.I),
    'machine_paths': re.compile(
        r'/(?P<unix>home|Users)/(?P<user>[^/\s"\'`(),;]{1,128})(?=/|\s|["\'`(),;.]|$)'
        r'|(?i:\b[A-Z]:\\Users\\)(?P<win>[^\\\s"\'`(),;]{1,128})(?=\\|\s|["\'`(),;.]|$)'
    ),
    'network_identities': re.compile(
        r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)'
        r'|(?<![\w.-])[a-z0-9](?:[a-z0-9.-]{0,250}[a-z0-9])?\.(?:ts\.net|local|lan)(?![\w-]|\.[\w-])', re.I),
    'session_refs': re.compile(
        r'\b\d{8}_\d{6}_[0-9a-f]{6,16}\b'
        r'|\b(?:session|delegation|subagent)(?:[ _-]?id)?(?:[ \t]{1,3}|[:=][ \t]{0,3})(?:\d{8}_\d{6}_[0-9a-f]{6,16}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{8,64})\b',
        re.I,
    ),
    'narration': re.compile(
        r'\b(?:this session|this time|earlier we|previously we|we found|I tried|turned out|yesterday|earlier today|workaround for now)\b'
        r'|\blast time\b[^.!?\n]{0,120}\b(?:we|I|our|this session)\b'
        r'|\b(?:we|I|our|this session)\b[^.!?\n]{0,120}\blast time\b',
        re.I,
    ),
}
WEIGHTS = {key: 4 for key in PATTERNS}
# Path ticket form, base regex `\b[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64})+[#!]\d+\b`.
# A match's path part lies inside one maximal run of [A-Za-z0-9_./-] and ends where that run
# ends (`#`/`!` is outside the class), so a run not followed by the tail never matches, and in
# a run that is, the `/`-separated pieces decide every start at once.
_TICKET_PATH_RUN_RE = re.compile(r'[A-Za-z0-9_./-]+')
_TICKET_PATH_TAIL_RE = re.compile(r'[#!]\d+\b')
_WORD_BOUNDARY_RE = re.compile(r'\b')
_TICKET_SEGMENT_MAX = 64
_NETWORK_EXAMPLE_RE = re.compile(
    r'\be\.g\.(?!\w)|\bfor example\b|\bexample:|\b(?:RFC[ -]?1918|private (?:range|address space))\b', re.I)
_EXAMPLE_WORD_RE = re.compile(r'\bexample\b', re.I)


def _ticket_path_starts(text):
    """Yield (start, end) for every position where the base path regex matches, in order.

    One pass per run: piece bounds, then the pieces that may hold a start (every later piece
    is 1..64 chars) and only the last 64 chars of the starting piece. Linear in len(text).
    """
    for run in _TICKET_PATH_RUN_RE.finditer(text):
        run_start, run_end = run.span()
        tail = _TICKET_PATH_TAIL_RE.match(text, run_end)
        if tail is None:
            continue
        pieces, cursor = [], run_start
        while True:
            slash = text.find('/', cursor, run_end)
            if slash < 0:
                pieces.append((cursor, run_end))
                break
            pieces.append((cursor, slash))
            cursor = slash + 1
        last = len(pieces) - 1
        first = 0
        for index in range(last, 0, -1):
            piece_start, piece_end = pieces[index]
            if not 1 <= piece_end - piece_start <= _TICKET_SEGMENT_MAX:
                first = index
                break
        for piece_start, piece_end in pieces[first:last]:
            for start in range(max(piece_start, piece_end - _TICKET_SEGMENT_MAX), piece_end):
                if _WORD_BOUNDARY_RE.match(text, start):
                    yield start, tail.end()


def _ticket_ref_spans(text):
    """Yield (start, end, prefix) exactly as finditer of the base ticket_refs regex would.

    The base alternation put the path form fifth: at one start it loses to the first four
    forms and beats the uppercase `KEY-123` form (the only one with a `prefix` group).
    """
    pattern = PATTERNS['ticket_refs']
    paths = _ticket_path_starts(text)
    pos, regex_match, path_match = 0, False, False  # False = not fetched yet, None = exhausted
    while True:
        if regex_match is False or (regex_match is not None and regex_match.start() < pos):
            regex_match = pattern.search(text, pos)
        while path_match is False or (path_match is not None and path_match[0] < pos):
            path_match = next(paths, None)
        if path_match is not None and (
            regex_match is None or path_match[0] < regex_match.start()
            or (path_match[0] == regex_match.start() and regex_match.group('prefix') is not None)
        ):
            yield path_match[0], path_match[1], None
            pos = path_match[1]
        elif regex_match is not None:
            yield regex_match.start(), regex_match.end(), regex_match.group('prefix')
            pos = regex_match.end()
        else:
            return


def _strip_html_comments(text):
    """Same result as re.sub(r'<!--.*?-->', '', text, flags=re.S), in one pass.

    The regex retried at every unclosed `<!--` and scanned to the end each time; once no
    `-->` follows an opener, no later opener can close either.
    """
    out, pos = [], 0
    while True:
        opener = text.find('<!--', pos)
        if opener < 0:
            break
        closer = text.find('-->', opener + 4)
        if closer < 0:
            break
        out.append(text[pos:opener])
        pos = closer + 3
    out.append(text[pos:])
    return ''.join(out)


def residue_score(metrics):
    return sum(WEIGHTS[key] + min(2, metrics[key] - 1) for key in PATTERNS if metrics[key])


def _machine_specific(match):
    raw = (match.group('user') or match.group('win')).strip('"\'`(),;')
    if raw != '...':
        raw = raw.rstrip('.')
    if not raw or raw[0] in '{<:$%':
        return False
    return raw.strip('<>{}').casefold() not in _PLACEHOLDER_USERS_LOWER


def _line_flags(line):
    """(table row, example phrase, word `example`): everything _network_specific reads from a line."""
    return (line.lstrip().startswith('|') or line.count('|') >= 2,
            _NETWORK_EXAMPLE_RE.search(line) is not None,
            _EXAMPLE_WORD_RE.search(line) is not None)


def _line_start(text, match):
    return text.rfind('\n', 0, match.start()) + 1


def _line_of(text, match, line_start):
    line_end = text.find('\n', match.end())
    return text[line_start:line_end if line_end >= 0 else len(text)]


def _network_specific(match, text, line_flags=None):
    """`line_flags(match)` may supply cached _line_flags; without it the line is cut here."""
    value = match.group()
    if not value[0].isdigit() or not re.fullmatch(r'[0-9.]+', value):
        return True
    octets = [int(v) for v in value.split('.')]
    if any(v > 255 for v in octets):
        return False
    a, b, _, _ = octets
    private = a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127)
    if not private:
        return False
    suffix = text[match.end():match.end() + 4]
    if line_flags is None:
        table, example_phrase, example_word = _line_flags(_line_of(text, match, _line_start(text, match)))
    else:
        table, example_phrase, example_word = line_flags(match)
    if table or example_phrase:
        return False
    generic_cidr = re.match(r'/([0-9]{1,2})(?![0-9])', suffix)
    if generic_cidr:
        prefix_len = int(generic_cidr[1])
        if prefix_len in {8, 12, 16, 24} or (prefix_len <= 32 and example_word):
            return False
    return True


def _network_count(text):
    """Sum of _network_specific over all matches; line flags computed once per line.

    The base cut and searched the whole line again for every match: quadratic for many private
    addresses on one long line. Matches arrive in order, so the line start advances by a
    bounded rfind and each line's flags are kept until a match lands on a later line.
    """
    scanned, line_start, cached = 0, 0, None

    def flags(match):
        nonlocal cached
        if cached is None or cached[0] != line_start:
            cached = (line_start, _line_flags(_line_of(text, match, line_start)))
        return cached[1]

    total = 0
    for match in PATTERNS['network_identities'].finditer(text):
        newline = text.rfind('\n', scanned, match.start())
        if newline >= 0:
            line_start = newline + 1
        scanned = match.start()
        total += _network_specific(match, text, flags)
    return total


def _date_text(text):
    # Frontmatter is metadata, not an appended incident. Changelog sections end
    # only at a heading of equal/higher level; nested release headings stay exempt.
    text = re.sub(r'\A\ufeff?---[^\n]*\n.*?\n---[^\n]*(?:\n|$)', '', text, count=1, flags=re.S)
    lines, history_level = [], None
    for line in text.splitlines():
        heading = re.match(r'^\s{0,3}(#{1,6})\s+(.+)', line)
        if heading:
            level = len(heading[1])
            if history_level is not None and level <= history_level:
                history_level = None
            if re.search(r'\b(?:changelog|release|history|versions)\b', heading[2], re.I):
                history_level = level if history_level is None else min(history_level, level)
        if history_level is None and not _DATE_LINE_EXEMPT_RE.search(line):
            lines.append(line)
    return '\n'.join(lines)


def dated_lesson_lines(text):
    text = _strip_html_comments(text)
    count = 0
    for line in _date_text(text).splitlines():
        if line.lstrip().startswith('|') or line.count('|') >= 2:
            continue
        m = _DATED_LESSON_PREFIX_RE.match(line)
        if m and PATTERNS['dates'].match(line[m.end():]):
            count += 1
    return count


def counts(text):
    # Template comments are instructions for filling an example, not incident evidence.
    text = _strip_html_comments(text)
    result = {}
    for key, pattern in PATTERNS.items():
        if key == 'ticket_refs':
            result[key] = sum(
                1 for _, _, prefix in _ticket_ref_spans(text)
                if not (prefix and prefix.lower() in TICKET_PREFIX_DENYLIST)
            )
        elif key == 'machine_paths':
            result[key] = sum(_machine_specific(m) for m in pattern.finditer(text))
        elif key == 'network_identities':
            result[key] = _network_count(text)
        else:
            result[key] = sum(1 for _ in pattern.finditer(_date_text(text) if key == 'dates' else text))
    run = longest = 0
    lines = text.splitlines()
    for line in lines:
        run = run + 1 if re.match(r'^\s*[-*+]\s', line) else 0
        longest = max(longest, run)
    result.update(
        lesson_headings=dated_lesson_lines(text),
        total_lines=len(lines),
        characters=len(text),
        longest_bullet_run=longest,
    )
    return result


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _has_symlink_below(path: Path, anchor: Path) -> bool:
    """True only when `path` or an ancestor strictly above `anchor` (down to `anchor`) is a symlink.
    Symlinked ancestors above the profile root are normal user environment and not refused."""
    cur = path
    while True:
        if cur.is_symlink():
            return True
        if cur == anchor or cur.parent == cur:
            return False
        cur = cur.parent


def bounded_files(root, limit=MAX_TREE_ENTRIES, *, anchor=None, per_skill=False):
    """No links/credentials traversed below anchor; return paths and number of unknown/cut regions."""
    root = Path(root)
    anchor = Path(anchor) if anchor is not None else root
    pending, files, entries, cuts = [root], [], 0, 0
    cut_dirs = set()
    while pending:
        directory = pending.pop()
        try:
            if credential_path(directory) or _has_symlink_below(directory, anchor):
                cuts += 1
                cut_dirs.add(directory)
                continue
            with os.scandir(directory) as iterator:
                batch = []
                for entry in iterator:
                    entries += 1
                    if entries > limit:
                        if per_skill:
                            cuts += 1
                            cut_dirs.add(directory)
                            batch = None
                            break
                        return [], cuts + 1  # Never rank an arbitrary scandir prefix.
                    batch.append(entry)
            if batch is None:
                continue
            for entry in sorted(batch, key=lambda e: e.name):
                if _has_surrogate(entry.name):
                    cuts += 1
                    cut_dirs.add(directory)
                    continue
                path = Path(entry.path)
                if credential_path(path) or entry.is_symlink():
                    cuts += 1
                    cut_dirs.add(directory)
                elif entry.is_dir(follow_symlinks=False):
                    # skills_sync.py:195-198 hashes ALL package files, including VCS
                    # and dependencies. Safety refusals above make provenance unknown.
                    if per_skill or entry.name not in EXCLUDED_SKILL_DIRS - CACHE_DIRS:
                        pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files.append(path)
                else:
                    cuts += 1
                    cut_dirs.add(directory)
        except FileNotFoundError:
            if directory != root:
                cuts += 1
                cut_dirs.add(directory)
        except OSError:
            cuts += 1
            cut_dirs.add(directory)
    if per_skill:
        return sorted(files), cuts, cut_dirs
    return sorted(files), cuts


def _finding(rule, path, evidence, coverage='verified', classification='review_suggested'):
    return make_finding(rule_id=rule, classification=classification, coverage=coverage,
                        affected_identities=[str(path)], source_paths=[str(path)],
                        evidence=evidence, consequence=FINDING_CONSEQUENCES[rule])


def audit_skill_hygiene(*, profile_path):
    root = Path(profile_path).absolute()
    skills_root = root / 'skills'
    cuts = 0
    remaining = MAX_TOTAL_BYTES

    def read(path):
        nonlocal cuts, remaining
        limit = min(MAX_FILE_BYTES, remaining)
        if limit <= 0:
            cuts += 1
            return None
        result = safe_read_regular_file(root, str(path.relative_to(root)), max_bytes=limit)
        if result.coverage != 'verified' or not result.stable or result.content is None:
            cuts += 1
            return None
        remaining -= len(result.content)
        return result.content

    # agent/skill_utils.py:331-362: scalar/list, relative to HERMES_HOME.
    # No ambient expansion or project traversal: this component receives no selected-root
    # allowlist. In-home roots are within its read boundary; all others are disclosed only.
    discovery_roots, external_skipped = [skills_root], 0
    config_read = safe_read_regular_file(root, 'config.yaml', max_bytes=min(MAX_FILE_BYTES, remaining))
    if config_read.coverage == 'verified' and config_read.stable and config_read.content is not None:
        remaining -= len(config_read.content)
        try:
            config = _parse_simple_yaml_mapping(config_read.content.decode('utf-8'), reject_duplicate_keys=True)
            section = config.get('skills', {})
            external = section.get('external_dirs', []) if isinstance(section, dict) else []
            external = [external] if isinstance(external, str) else external
            if not isinstance(external, list):
                raise ValueError('invalid external dirs')
            seen = set()
            for entry in external:
                if not isinstance(entry, str):
                    external_skipped += 1
                    continue
                entry = entry.strip()
                if not entry or entry in seen:
                    continue
                seen.add(entry)
                path = Path(entry)
                path = path if path.is_absolute() else root / path
                if (not path.is_relative_to(root) or '..' in path.parts or '~' in entry or '$' in entry
                        or credential_path(path) or _has_symlink_below(path, root)):
                    external_skipped += 1
                    continue
                if path not in discovery_roots:
                    discovery_roots.append(path)
        except (ValueError, UnicodeError, RecursionError):
            cuts += 1
    elif config_read.kind != 'missing':
        cuts += 1

    # Discover skill packages without letting one huge skill or non-skill folder empty the whole section.
    skill_packages, visited_dirs = [], set()
    entry_budgets = {}
    discovery_roots_set = set(discovery_roots)
    pending_dirs = [(path, path) for path in discovery_roots]
    while pending_dirs:
        directory, owner = pending_dirs.pop()
        if directory in visited_dirs:
            continue
        visited_dirs.add(directory)
        try:
            if credential_path(directory) or _has_symlink_below(directory, root):
                cuts += 1
                continue
            md = directory / 'SKILL.md'
            has_skill_md = directory not in discovery_roots_set and not md.is_symlink() and md.is_file()
            if has_skill_md:
                if len(skill_packages) >= MAX_TREE_ENTRIES:
                    cuts += 1
                    continue
                skill_packages.append(directory)
                owner = directory
            with os.scandir(directory) as iterator:
                batch = []
                for entry in iterator:
                    entry_budgets[owner] = entry_budgets.get(owner, 0) + 1
                    if entry_budgets[owner] > MAX_TREE_ENTRIES:
                        cuts += 1
                        batch = None
                        break
                    if entry.name == 'SKILL.md' and not entry.is_symlink() and entry.is_file(follow_symlinks=False):
                        has_skill_md = True
                    batch.append(entry)
            if batch is None:
                continue
            for entry in sorted(batch, key=lambda e: e.name):
                if _has_surrogate(entry.name):
                    cuts += 1
                    continue
                path = Path(entry.path)
                if credential_path(path) or entry.is_symlink():
                    cuts += 1
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name in EXCLUDED_SKILL_DIRS - CACHE_DIRS:
                        continue
                    if has_skill_md and directory not in discovery_roots_set and entry.name in SKILL_SUPPORT_DIRS:
                        continue
                    pending_dirs.append((path, path if directory in discovery_roots_set else owner))
                elif not entry.is_file(follow_symlinks=False):
                    cuts += 1
        except FileNotFoundError:
            if directory != skills_root:
                cuts += 1
        except OSError:
            cuts += 1

    manifest_raw = read(root / MANIFEST)
    manifest = {}
    manifest_ok = manifest_raw is not None
    if manifest_ok:
        try:
            for line in manifest_raw.decode('utf-8-sig').splitlines():
                if not line.strip():
                    continue
                name, _, origin = line.strip().partition(':')
                if name in manifest or not re.fullmatch(r'[0-9a-f]{32}', origin.strip()):
                    manifest_ok = False
                manifest[name.strip()] = origin.strip()
        except UnicodeError:
            manifest_ok = False
    # tools/skills_sync_optional.py:73-88,222-227; skills_hub.py:323-365.
    # Only official sources gain exemption; lock paths never authorize new reads.
    hub_lock = skills_root / '.hub/lock.json'
    try:
        if not _has_symlink_below(hub_lock, root):
            hub_lock.lstat()
        hub_missing = False
    except FileNotFoundError:
        hub_missing = True
    except OSError:
        hub_missing = False
    hub_read = safe_read_regular_file(root, 'skills/.hub/lock.json', max_bytes=min(MAX_FILE_BYTES, remaining))
    hub_missing = hub_missing or hub_read.kind == 'missing'
    hub, hub_ok = {}, False
    if hub_read.coverage == 'verified' and hub_read.stable and hub_read.content is not None:
        remaining -= len(hub_read.content)
        try:
            lock = json.loads(hub_read.content.decode('utf-8-sig'))
            installed = lock['installed']
            if not isinstance(installed, dict):
                raise ValueError('invalid lock')
            hub_ok = True
            for entry in installed.values():
                if not isinstance(entry, dict):
                    raise ValueError('invalid entry')
                if entry.get('source') != 'official':
                    continue
                rel, digest = entry.get('install_path'), entry.get('content_hash')
                if (not isinstance(rel, str) or not rel or Path(rel).is_absolute()
                        or '..' in Path(rel).parts or '\\' in rel
                        or not isinstance(digest, str)
                        or not re.fullmatch(r'(?:sha256:[0-9a-f]{16}|[0-9a-f]{32})', digest)
                        or rel in hub):
                    raise ValueError('invalid entry')
                hub[rel] = digest
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            hub, hub_ok = {}, False
    rows, candidate_rows, findings, normalized, names = [], [], [], {}, {}
    matched_names = set()
    origins = []
    skill_packages.sort()
    pkg_set = set(skill_packages)
    for package in skill_packages:
        md = package / 'SKILL.md'
        # Bound entries PER SKILL (min of MAX_FILES_PER_SKILL * 4 and MAX_TREE_ENTRIES)
        pkg_files, pkg_cuts, _ = bounded_files(
            package, limit=min(MAX_TREE_ENTRIES, max(MAX_FILES_PER_SKILL * 2, 16)), anchor=root, per_skill=True
        )
        # Exclude any nested independent skill packages under this package
        nested_pkgs = {other for other in pkg_set if other != package and other.is_relative_to(package)}
        paths = pkg_files
        before = cuts
        cuts += pkg_cuts
        if len(paths) > MAX_FILES_PER_SKILL:
            cuts += 1
            paths = [md, *[p for p in paths if p != md][:MAX_FILES_PER_SKILL - 1]] if md in paths else paths[:MAX_FILES_PER_SKILL]
        elif pkg_cuts > 0 and md not in paths and md.is_file() and not md.is_symlink():
            paths = [md, *paths[:MAX_FILES_PER_SKILL - 1]]
        raw_files = {}
        metrics = []
        for path in paths:
            if _has_surrogate(str(path)):
                cuts += 1
                continue
            data = read(path)
            if data is None:
                continue
            relative = path.relative_to(package)
            rel_str = str(relative)
            raw_files[rel_str] = data
            try:
                text = data.decode('utf-8')
                if '\x00' not in text and not any(path.is_relative_to(np) for np in nested_pkgs):
                    metrics.append({'path': relative.as_posix(), **counts(text)})
            except UnicodeError:
                pass
        md_data = raw_files.get('SKILL.md')
        if md_data is None:
            continue
        try:
            fm, body = parse_frontmatter_stdlib(md_data.decode('utf-8'))
        except (UnicodeError, ValueError, RecursionError):
            cuts += 1
            continue
        name = str(fm.get('name') or package.name).strip()
        total = {k: sum(m[k] for m in metrics) for k in (*PATTERNS, 'lesson_headings', 'total_lines', 'characters')}
        total['longest_bullet_run'] = max((m['longest_bullet_run'] for m in metrics), default=0)
        score = residue_score(total)
        # Hermes tools/skills_sync.py:187-212: sorted relative OS paths followed by raw bytes,
        # MD5, compare BOTH cache-filtered and exact legacy hashes. Never persist either hash.
        current, legacy = hashlib.md5(), hashlib.md5()
        for relative, data in sorted(raw_files.items(), key=lambda kv: Path(kv[0]).parts):
            path = Path(relative)
            cached = any(p in CACHE_DIRS for p in path.parts[:-1]) or (
                path.suffix in {'.pyc', '.pyo'} and str(path.with_suffix('.py')) in raw_files)
            legacy.update(relative.encode('utf-8', errors='surrogateescape')); legacy.update(data)
            if not cached:
                current.update(relative.encode('utf-8', errors='surrogateescape')); current.update(data)
        is_local = package.is_relative_to(skills_root)
        rel_pkg = package.relative_to(skills_root).as_posix() if is_local else None
        manifest_key = (
            rel_pkg if rel_pkg in manifest else (
                package.name if package.name in manifest and name == package.name else None
            )
        )
        tracked = is_local and manifest_key is not None
        if tracked:
            matched_names.add(manifest_key)
        complete = before == cuts and not _has_symlink_below(package, root)
        valid_origin = tracked and re.fullmatch(r'[0-9a-f]{32}', manifest[manifest_key]) is not None
        verified_unmodified = bool(valid_origin and complete and manifest[manifest_key] in (current.hexdigest(), legacy.hexdigest()))
        provenance = 'external_dir' if not is_local else ('stock' if tracked else 'user_authored')
        hub_tracked = rel_pkg in hub
        if hub_tracked:
            provenance = 'hub'
            # tools/skills_guard.py:767-788: POSIX STRING order, path + NUL,
            # bytes; SHA256 truncated to 16 hex. Optional backfill can fall back to MD5.
            hub_digest = hashlib.sha256()
            for relative, data in sorted(raw_files.items()):
                hub_digest.update(Path(relative).as_posix().encode('utf-8') + b'\0')
                hub_digest.update(data)
            valid_origin = True
            verified_unmodified = complete and hub[rel_pkg] in (
                'sha256:' + hub_digest.hexdigest()[:16], current.hexdigest())
        modified = bool(valid_origin and complete and not verified_unmodified)
        row = {'path': str(package), 'skill_md_path': str(md), **total, 'file_count': len(raw_files),
               'body_char_count': len(body), 'residue_score': score, 'bundled': tracked and not hub_tracked,
               'provenance': provenance, 'verified_unmodified': verified_unmodified,
               'modified': modified, 'coverage': 'verified' if complete else 'could_not_verify', 'files': metrics}
        rows.append(row)
        origins.append((row, rel_pkg, name, (current.hexdigest(), legacy.hexdigest())))
        if complete:
            digest = hashlib.sha256(' '.join(body.split()).encode()).digest()
            normalized.setdefault(digest, []).append(str(md))
            names.setdefault(re.sub('[-_]', '', name.casefold()), []).append(str(md))

    # The v2 manifest usually contains names, not category paths (tools/skills_sync.py:113-128,170-185,325).
    # Resolve all claimants together: exact hash wins; without a hash match, a single claimant is
    # that stock skill, while multiple claimants require an exact recorded install path.
    matched_names.clear()
    for row in rows:
        if row['provenance'] not in {'hub', 'external_dir'}:
            row.update(bundled=False, provenance='user_authored', modified=False, verified_unmodified=False)
    for key, origin in manifest.items():
        candidates = [(r, rel, hashes) for r, rel, name, hashes in origins
                      if r['provenance'] not in {'hub', 'external_dir'} and (rel == key or Path(rel).name == key or name == key)]
        verified = [(r, rel, hashes) for r, rel, hashes in candidates
                    if r['coverage'] == 'verified' and origin in hashes]
        exact = [(r, rel, hashes) for r, rel, hashes in candidates if rel == key]
        chosen = (next((c for c in verified if c[1] == key), verified[0]) if verified
                  else candidates[0] if len(candidates) == 1 else exact[0] if len(exact) == 1 else None)
        if chosen is not None:
            row = chosen[0]
            valid = bool(re.fullmatch(r'[0-9a-f]{32}', origin)) and row['coverage'] == 'verified'
            row.update(bundled=True, provenance='stock', verified_unmodified=bool(verified),
                       modified=valid and not verified)
            matched_names.add(key)
    for row in rows:
        md = Path(row['skill_md_path'])
        verified_unmodified, modified = row['verified_unmodified'], row['modified']
        total = {k: row[k] for k in (*PATTERNS, 'lesson_headings', 'total_lines', 'characters', 'longest_bullet_run')}
        score, provenance = row['residue_score'], row['provenance']
        if not verified_unmodified:
            candidate_rows.append(row)
        if modified:
            findings.append(_finding('skill_hygiene.stock_skill_modified', md, {**total, 'provenance': provenance}))
        if not verified_unmodified:
            if score >= RESIDUE_THRESHOLD or total['lesson_headings'] >= DATED_LESSON_LINES:
                findings.append(_finding('skill_hygiene.scratchpad_residue', md, {**total, 'residue_score': score}))
            if total['machine_paths']:
                findings.append(_finding('skill_hygiene.machine_paths_in_skill', md, {'machine_paths': total['machine_paths']}))
            if total['network_identities']:
                findings.append(_finding('skill_hygiene.network_identity_in_skill', md, {'network_identities': total['network_identities']}))
            if row['body_char_count'] >= OVERSIZED_BODY_CHARS:
                findings.append(_finding('skill_hygiene.oversized_skill_body', md, {'characters': row['body_char_count'], 'char_limit': OVERSIZED_BODY_CHARS}))
    duplicate_groups = sorted({tuple(sorted(group)) for group in [*normalized.values(), *names.values()] if len(group) > 1})
    for paths in duplicate_groups:
        finding = _finding('skill_hygiene.duplicate_skill', paths[0], {'duplicate_count': len(paths)})
        finding['source_paths'] = list(paths)
        findings.append(finding)
    if external_skipped:
        findings.append(_finding('skill_hygiene.external_skill_dir_not_scanned', root / 'config.yaml',
                                 {'count': external_skipped}, 'could_not_verify'))
    unverified = (
        not manifest_ok
        or (not hub_missing and not hub_ok)
        or cuts > 0
        or external_skipped > 0
        or len(matched_names) != len(manifest)
    )
    if unverified:
        findings.append(_finding('skill_hygiene.could_not_verify', root / 'skills', {'cuts': cuts}, 'could_not_verify'))
    # One reviewed word for the first thing that kept the section from being verified.
    reason = (None if not unverified
              else 'missing' if manifest_raw is None and not os.path.lexists(root / MANIFEST)
              else 'unreadable' if not manifest_ok or (not hub_missing and not hub_ok)
              else 'external_skill_dirs' if external_skipped
              else 'truncated' if cuts
              else 'missing')  # a skill the install manifest lists was not found
    section = {'coverage': 'could_not_verify' if unverified else 'verified', 'reason': reason, 'profile_path': str(root),
               'bundled_tracked': len(manifest), 'bundled_modified': sum(r['modified'] and r['bundled'] for r in rows),
               'hub_coverage': 'verified' if hub_ok else ('not_applicable' if hub_missing else 'could_not_verify'),
               'hub_verified': sum(r['provenance'] == 'hub' and r['verified_unmodified'] for r in rows),
               'hub_modified': sum(r['provenance'] == 'hub' and r['modified'] for r in rows),
               'bundled_unlocated': len(manifest.keys() - matched_names), 'growth_measurable': False,
               'residue_skills': sum(
                   r['residue_score'] >= RESIDUE_THRESHOLD or r['lesson_headings'] >= DATED_LESSON_LINES
                   for r in candidate_rows
               ),
               'skills_examined': len(rows), 'skills': rows, 'modified_skills': [r for r in rows if r['modified']],
               'top_skills': sorted(candidate_rows, key=lambda r: (-r['residue_score'], -r['lesson_headings'], r['path']))[:10],
               'duplicate_groups': [list(g) for g in duplicate_groups],
               'limits': {'max_file_bytes': MAX_FILE_BYTES, 'max_files_per_skill': MAX_FILES_PER_SKILL,
                          'max_entries': MAX_TREE_ENTRIES, 'max_bytes': MAX_TOTAL_BYTES, 'cuts': cuts},
               'thresholds': {'residue_score': RESIDUE_THRESHOLD, 'lesson_headings': DATED_LESSON_LINES,
                              'body_char_count': OVERSIZED_BODY_CHARS}}
    return make_component_envelope(findings=findings, coverage=section['coverage'], extra={'skill_hygiene': section})
