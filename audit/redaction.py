"""Run-local credential taint: observe at capture, gate references, scrub sinks.

The set is ephemeral and is never serialized. Context-local ownership prevents
concurrent audits or nested collectors from sharing credential material.
"""
import ast
from collections import OrderedDict
from contextvars import ContextVar
from functools import wraps
import json
import posixpath
import re
import shlex
import sqlite3
from urllib.parse import unquote

_CURRENT = ContextVar('audit_redaction', default=None)
_URL_USERINFO = re.compile(r"(?<![a-zA-Z0-9+.-])([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@\"'<>]*:[^/\s@\"'<>]*)@")
_SENSITIVE = re.compile(
    r'(?:^|[_.\-/])(?:api[_-]?key|access[_-]key|secret|password|passwd|token|private[_-]key|'
    r'client[_-]secret|auth[_-]?token|credential|credentials|auth|authorization|bearer|cookie|'
    r'session[_-]secret)(?:$|[_.\-/])', re.I,
)
_ASSIGN = re.compile(r'''(?<![\w.\-/])["']?([\w.\-/]+)["']?\s*(?:=|:)\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;\]}]+)''')
_TEXT_HINT_RE = re.compile(r'(?i:key|token|secret|passw|credential|auth)|(?<!\w)-[pu]\b')
_REDACTED_OVERLAP_PREFIX = 'evidence_redacted_due_to_credential_overlap: '
_PATH_BEARER_KEYS = ('path', 'source', 'target', 'load_root', 'sample_paths')


def sensitive(key):
    # Explicit file declarations retain metadata-only credential classification.
    return isinstance(key, str) and key not in {'credential_file', 'credentials_file'} and bool(_SENSITIVE.search(key))


# shlex builds a quoted token one character at a time, so one unclosed quote in a
# large text costs quadratic time (about 12 s for 1 MB, minutes for a few MB). Texts
# up to this size are split whole, exactly as before; larger texts are split per
# logical line (backslash-continued lines joined), and only lines that can hold a flag.
_FLAG_SPLIT_WHOLE_MAX = 64 * 1024
_FLAG_LINE_MAX = 16 * 1024
_FLAG_JOIN_LINES = 40
_FLAG_JOIN_ATTEMPTS = 2000  # per text: keeps the multi-line join linear overall


def _plain_words(line):
    return [word.strip('"\'') for word in line.split()]


def _flag_word_groups(text):
    """Word lists to scan for sensitive command-line flags, in linear time.

    Large texts yield ONE flat word list so that a flag at the end of a line still
    takes its value from the next line, as a whole-text split would.
    """
    if len(text) <= _FLAG_SPLIT_WHOLE_MAX:
        try:
            return [shlex.split(text)]
        except ValueError:
            return [[]]
    lines = text.splitlines()
    words, index, total = [], 0, len(lines)
    join_budget = _FLAG_JOIN_ATTEMPTS
    while index < total:
        line = lines[index]
        index += 1
        # Join backslash-continued lines (bounded; a longer run is split as plain words).
        while line.endswith('\\') and index < total and len(line) < _FLAG_LINE_MAX:
            line = line[:-1] + ' ' + lines[index]
            index += 1
        awaiting_value = bool(words) and _is_sensitive_flag(words[-1]) and '=' not in words[-1]
        hinted = '-' in line and _TEXT_HINT_RE.search(line) is not None
        if not hinted:
            if awaiting_value:
                first = _plain_words(line)[:1]
                words.extend(first)
            continue
        if len(line) > _FLAG_LINE_MAX:
            words.extend(_plain_words(line))
            continue
        try:
            words.extend(shlex.split(line))
            continue
        except ValueError:
            pass
        # An unclosed quote: the value may span lines. Try a bounded join before giving up.
        joined, look = line, index
        while (join_budget > 0 and look < total and look - index < _FLAG_JOIN_LINES
               and len(joined) < _FLAG_LINE_MAX):
            join_budget -= 1
            joined += '\n' + lines[look]
            look += 1
            try:
                words.extend(shlex.split(joined))
                index = look
                break
            except ValueError:
                continue
        else:
            words.extend(_plain_words(line))
    return [words]


def _is_sensitive_flag(item):
    return isinstance(item, str) and item.startswith('-') and (sensitive(item.partition('=')[0]) or item in {'-p', '-u'})


def canonical_forms(value):
    """Retain both spelling and decoded/normalized aliases, never resolve paths."""
    forms = set()
    while True:
        value = value.strip(" \t\r\n\"'")
        if value:
            forms.update((value, value.casefold()))
            normalized = posixpath.normpath(value).rstrip('/') or '/'
            collapsed = normalized.lstrip('/') if not normalized.startswith('/') else '/' + normalized.lstrip('/')
            forms.update((normalized, normalized.casefold(), collapsed))
        decoded = unquote(value)
        if decoded == value:
            return forms
        value = decoded


class _LiteralMatcher:
    """Incremental literal trie, with a six-character hash-table prefilter.

    Every substring-capable form has at least six characters. A candidate start
    therefore costs one dictionary lookup, not one attempt per secret. On a
    prefix hit, follow just the matching trie edges (never scan sibling values).
    Search work is O(n * min(n, longest_form)), independent of the number of
    tainted values; typical misses take O(n). Insert/remove cost O(form length),
    and trie storage is O(total retained form length). No index rebuilds.

    Byte extraction seals the union of overlapping literal matches. Skipping
    starts inside a match could expose a later match's tail when another taint
    is added. Adjacent, non-overlapping matches keep separate replacements.
    """

    def __init__(self):
        self.roots = {}
        self.size = 0

    def __bool__(self):
        return bool(self.size)

    def add(self, value):
        prefix = value[:6]
        node = self.roots.get(prefix)
        if node is None:
            # Radix node: [edge label, terminal flag, outgoing edges]. Compress
            # single-child paths so even a huge literal needs no per-char dicts.
            self.roots[prefix] = [value[6:], True, {}]
            self.size += 1
            return
        offset = 6
        while True:
            label = node[0]
            common = 0
            while common < len(label) and offset + common < len(value) and label[common] == value[offset + common]:
                common += 1
            offset += common
            if common < len(label):
                rest = label[common:]
                old = [rest, node[1], node[2]]
                node[:] = [label[:common], offset == len(value), {rest[0]: old}]
                if offset < len(value):
                    node[2][value[offset]] = [value[offset:], True, {}]
                self.size += 1
                return
            if offset == len(value):
                if not node[1]:
                    node[1] = True
                    self.size += 1
                return
            child = node[2].get(value[offset])
            if child is None:
                node[2][value[offset]] = [value[offset:], True, {}]
                self.size += 1
                return
            node = child

    def discard(self, value):
        prefix = value[:6]
        node = self.roots.get(prefix)
        parents = [(self.roots, prefix)]
        offset = 6
        while node is not None:
            if not value.startswith(node[0], offset):
                return
            offset += len(node[0])
            if offset == len(value):
                break
            parents.append((node[2], value[offset]))
            node = node[2].get(value[offset])
        if node is None or not node[1]:
            return
        node[1] = False
        self.size -= 1
        for parent, key in reversed(parents):
            node = parent[key]
            if node[1]:
                break
            if not node[2]:
                del parent[key]
            elif len(node[2]) == 1:
                child = next(iter(node[2].values()))
                node[:] = [node[0] + child[0], child[1], child[2]]
            else:
                break

    def _end(self, text, start, *, longest=False):
        node = self.roots.get(text[start:start + 6])
        end = start + 6
        found = start
        while node is not None and text.startswith(node[0], end):
            end += len(node[0])
            if node[1]:
                found = end
                if not longest:
                    break
            if end == len(text):
                break
            node = node[2].get(text[end])
        return found

    def _possible(self, text):
        # C-speed prefix checks avoid a Python walk on large, clean texts with
        # few roots. This can only reject misses: every match has one of these
        # prefixes. Hits still use the same trie and overlap selection below.
        return bool(self.roots) and (len(text) < 128 or len(self.roots) > 64 or
                                     text[:6] in self.roots or
                                     any(prefix in text for prefix in self.roots))

    def search(self, text):
        return self._possible(text) and any(
            self._end(text, start) != start for start in range(len(text) - 5))

    def sub(self, replace, text):
        if not self._possible(text):
            return text
        # The sole caller uses match[0]; a one-item tuple retains that interface.
        parts = []
        start = copied = 0
        while start <= len(text) - 6:
            end = self._end(text, start, longest=True)
            if end == start:
                start += 1
                continue
            # Extend through every overlapping match, including chains. A
            # longest match at the first start need not cover later tails.
            scan = start + 1
            while scan < end and scan <= len(text) - 6 and end < len(text):
                end = max(end, self._end(text, scan, longest=True))
                scan += 1
            parts.append(text[copied:start])
            parts.append(replace((text[start:end],)))
            start = copied = end
        parts.append(text[copied:])
        return ''.join(parts)


class Taint:
    def __init__(self):
        from .evidence import EvidenceSerializer
        self.serializer = EvidenceSerializer()
        self.values = set()
        self.withheld_sources = set()
        self.credential_paths = set()
        self.credential_metadata = {}
        self.declaration_sources = set()
        self.declaration_anchors = {}
        self.exact_values = set()
        self.source = None
        self.owner = None
        self.redactions = {}
        self._matcher = _LiteralMatcher()
        self._short = self.exact_values
        self._forms = OrderedDict()
        self._forms_weight = 0

    def note(self, value, *, persisted=False):
        if persisted:
            region = self.owner(self.source) if self.owner and self.source else 'shared_infrastructure'
            self.redactions.setdefault(region, set()).add((str(self.source), value))

    def disclose(self, result):
        if isinstance(result, dict) and isinstance(result.get('regions'), dict):
            for name, items in self.redactions.items():
                region = result['regions'].get(name)
                if not isinstance(region, dict) or 'coverage' not in region:
                    continue
                region['reasons'] = [r for r in region.get('reasons', [])
                                     if not isinstance(r, str) or not r.startswith(_REDACTED_OVERLAP_PREFIX)]
                region['reasons'].append(f'{_REDACTED_OVERLAP_PREFIX}{len(items)} items')
                region['coverage'] = 'could_not_verify'
        return result

    @staticmethod
    def _form_weight(value, forms):
        # Include a per-string charge so tiny aliases cannot bypass the budget.
        return len(value) + sum(map(len, forms)) + 64 * (1 + len(forms))

    def _canonical_forms(self, value):
        forms = self._forms.get(value)
        if forms is not None:
            self._forms.move_to_end(value)
            return forms
        forms = canonical_forms(value)
        weight = self._form_weight(value, forms)
        # At most 4096 entries and 1 Mi codepoints/overhead units. A large input
        # is still canonicalized exactly, but is not retained in this cache.
        if weight <= 1024 * 1024:
            while self._forms and (len(self._forms) >= 4096 or
                                   self._forms_weight + weight > 1024 * 1024):
                old, aliases = self._forms.popitem(last=False)
                self._forms_weight -= self._form_weight(old, aliases)
            self._forms[value] = forms
            self._forms_weight += weight
        return forms

    def add(self, value):
        if isinstance(value, str) and value:
            forms = self._canonical_forms(value)
            # Classify each alias separately: a short spelling must never
            # demote a longer alias that already seals substrings.
            for form in forms - self.values:
                if len(form) < 6:
                    self.exact_values.add(form)
                else:
                    self._matcher.add(form)
            self.values.update(forms)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self.add(item)
        elif isinstance(value, dict):
            for item in value.values():
                self.add(item)

    def _observe_flag_sequence(self, items, on_other=None):
        skip = False
        for item in items:
            if skip:
                self.add(item)
                skip = False
            elif _is_sensitive_flag(item):
                _, sep, val = item.partition('=')
                if sep:
                    self.add(val)
                else:
                    skip = True
            elif on_other is not None:
                on_other(item)

    def observe_value(self, value, seen=None):
        seen = set() if seen is None else seen
        if isinstance(value, (dict, list, tuple)):
            if id(value) in seen:
                return
            seen.add(id(value))
        if isinstance(value, dict):
            for key, item in value.items():
                if sensitive(key):
                    self.add(item)
                else:
                    self.observe_value(item, seen)
        elif isinstance(value, (list, tuple)):
            self._observe_flag_sequence(value, on_other=lambda item: self.observe_value(item, seen))
        elif isinstance(value, str):
            self.observe_text(value)

    def observe_text(self, text):
        if "://" in text and "@" in text:
            for match in _URL_USERINFO.finditer(text):
                self.add(match[2])
                self.add(match[2].split(':', 1)[1])
        if not _TEXT_HINT_RE.search(text):
            return
        for match in _ASSIGN.finditer(text):
            if sensitive(match[1]):
                raw = match[2]
                try:
                    raw = ast.literal_eval(raw)
                except (SyntaxError, ValueError):
                    raw = raw.strip('"\'')
                self.add(raw)
            elif '=' in match[2]:
                self.observe_text(match[2].strip('"\''))
        for words in _flag_word_groups(text):
            self._observe_flag_sequence(words)

    def _observe_structured(self, path, raw_bytes):
        from .outward_structured import parse_data
        for document in parse_data(path, raw_bytes):
            self.observe_value(document)

    def observe(self, path, data):
        self.source = path
        try:
            text = data.decode('utf-8') if isinstance(data, bytes) else data
        except UnicodeError:
            return
        suffix, name = getattr(path, 'suffix', ''), getattr(path, 'name', '')
        if suffix in {'.yaml', '.yml'}:
            try:
                self._observe_structured(path, text.encode())
            except (ValueError, UnicodeError, RecursionError):
                self.withheld_sources.add(str(path))
                self.add(text)
                return
        if not any(marker in text for marker in ('=', ':', '--', '-p', '-u')):
            return
        if suffix == '.py' or name == '.pythonrc':
            self.observe_python(text)
            return
        self.observe_text(text)
        try:
            self.observe_value(json.loads(text))
        except (ValueError, RecursionError):
            pass
        if suffix == '.toml':
            import tomllib
            try:
                self.observe_value(tomllib.loads(text))
            except (ValueError, RecursionError):
                pass
        elif suffix in {'.jsonc', '.code-workspace'}:
            try:
                self._observe_structured(path, data if isinstance(data, bytes) else data.encode())
            except (ValueError, UnicodeError, RecursionError):
                pass

    def observe_python(self, text):
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                targets = (node.targets if isinstance(node, ast.Assign)
                           else [node.target] if isinstance(node, ast.AnnAssign) else [])
                if targets and getattr(node, 'value', None) is not None and any(sensitive(ast.unparse(t)) for t in targets):
                    try:
                        self.add(ast.literal_eval(node.value))  # type: ignore[arg-type]
                    except (ValueError, TypeError):
                        pass
                if isinstance(node, ast.Dict):
                    for key, val in zip(node.keys, node.values):
                        if isinstance(key, ast.Constant) and sensitive(key.value) and val is not None:
                            try:
                                self.add(ast.literal_eval(val))
                            except (ValueError, TypeError):
                                pass
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.observe_text(node.value)
        except (SyntaxError, ValueError, RecursionError):
            pass

    def _ensure_pattern(self):
        # Kept as the shared matching entry point for byte extraction and scrub.
        return self._matcher if self._matcher else None

    def _scrub_field(self, key, value):
        from . import evidence as _ev
        is_structural = _ev._is_structural_scalar  # type: ignore[attr-defined]
        if is_structural(key, value):
            return value
        if isinstance(value, (list, tuple)):
            return [item if is_structural(key, item) else self.scrub(item) for item in value]
        return self.scrub(value)

    def scrub(self, value):
        from .evidence import SealedEvidence
        if isinstance(value, SealedEvidence) or not self.values:
            return value
        if isinstance(value, str):
            if value == '[redacted]':
                return value
            clean_url = (_URL_USERINFO.sub(lambda m: m[1] + '[redacted]@', value)
                         if '://' in value and '@' in value else value)
            if clean_url != value:
                self.note(value)
                return self.scrub(clean_url)
            pattern = self._ensure_pattern()
            candidates = self._canonical_forms(value)
            if self._short.intersection(candidates) or (pattern and any(pattern.search(c) for c in candidates)):
                self.note(value)
                return '[redacted]'
            return value
        if isinstance(value, dict):
            previous_source = self.source
            source = value.get('source', value.get('path'))
            if isinstance(source, str) and source != '[redacted]':
                self.source = source
            result = {k: self._scrub_field(k, v) for k, v in value.items()}
            if result != value and any(k in value for k in _PATH_BEARER_KEYS):
                result['redacted'] = True
            self.source = previous_source
            return self.disclose(result)
        if isinstance(value, (list, tuple)):
            return [self.scrub(v) for v in value]
        return value


def observe(path, data):
    state = _CURRENT.get()
    if state is not None:
        state.observe(path, data)


def observe_value(value):
    state = _CURRENT.get()
    if state is not None:
        state.observe_value(value)


def scrub(value):
    state = _CURRENT.get()
    return state.scrub(value) if state is not None else value


def extraction(value=None, *, path=None, data=None):
    """Shared entry point for literal, argument and reference extraction.

    File input is observed before sanitizing; scalar input is rejected rather
    than turning a credential into an apparently real '[redacted]' path.
    """
    state = _CURRENT.get() or Taint()
    if data is not None:
        state.observe(path, data)
        if str(path) in state.withheld_sources:
            return b''
        text = data.decode('utf-8', errors='replace')
        pattern = state._ensure_pattern()
        def replace(match):
            state.note(match[0])
            return '[redacted]'
        return (pattern.sub(replace, text) if pattern else text).encode('utf-8')
    if isinstance(value, str):
        state.observe_text(value)
        if state.scrub(value) != value or '[redacted]' in value:
            state.note(value)
            return None
    return value


def redaction_scope(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if _CURRENT.get() is not None:
            return fn(*args, **kwargs)
        token = _CURRENT.set(Taint())
        try:
            return fn(*args, **kwargs)
        finally:
            _CURRENT.reset(token)
    return wrapped


class GuardedConnection(sqlite3.Connection):
    """Last gate before SQL binding, including callers bypassing DTO filters."""
    def execute(self, sql, parameters=()):
        def clean(value):
            from .evidence import PersistedJSON, serialize_evidence
            if isinstance(value, PersistedJSON):
                return str(value)
            if isinstance(value, str):
                try:
                    decoded = json.loads(value)
                except ValueError:
                    return scrub(value)
                return json.dumps(serialize_evidence(decoded), sort_keys=True)
            return value
        params = ({k: clean(v) for k, v in parameters.items()} if isinstance(parameters, dict)
                  else tuple(clean(v) for v in parameters))
        return super().execute(sql, params)
