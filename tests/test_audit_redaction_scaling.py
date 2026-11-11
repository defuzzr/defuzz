"""Differential and scaling checks using generated, synthetic credential values."""
import random
import re
import string
import time
from pathlib import Path

from tests.conftest import load_submodule


redaction = load_submodule('audit.redaction')


class OverlapRegex:
    """Independent regex oracle for the union of every literal occurrence."""

    def __init__(self, alternatives):
        self.pattern = re.compile('(?=(' + alternatives + '))')

    def search(self, text):
        return self.pattern.search(text)

    def sub(self, replace, text):
        parts, copied, start, end = [], 0, None, 0
        for match in self.pattern.finditer(text):
            left, right = match.span(1)
            if start is None:
                start, end = left, right
            elif left < end:
                end = max(end, right)
            else:
                parts.extend((text[copied:start], replace((text[start:end],))))
                copied, start, end = end, left, right
        if start is not None:
            parts.extend((text[copied:start], replace((text[start:end],))))
            copied = end
        return ''.join(parts) + text[copied:]


class LegacyTaint(redaction.Taint):
    """Regex reference with monotonic alias and overlap policy; observers shared."""

    def __init__(self):
        super().__init__()
        self._pattern_size = -1
        self._pattern = None
        self._short = set()
        self._forms = {}

    def add(self, value):
        if isinstance(value, str) and value:
            forms = redaction.canonical_forms(value)
            self.exact_values.update(form for form in forms if len(form) < 6)
            self.values.update(forms)
            self._pattern_size = -1
        elif isinstance(value, (list, tuple)):
            for item in value:
                self.add(item)
        elif isinstance(value, dict):
            for item in value.values():
                self.add(item)

    def _ensure_pattern(self):
        if self._pattern_size != len(self.values):
            long = sorted((s for s in self.values if s not in self.exact_values), key=len, reverse=True)
            self._pattern = OverlapRegex('|'.join(re.escape(s) for s in long)) if long else None
            self._short = self.exact_values.copy()
            self._pattern_size = len(self.values)
        return self._pattern

    def scrub(self, value):
        evidence = load_submodule('audit.evidence')
        if isinstance(value, evidence.SealedEvidence) or not self.values:
            return value
        if isinstance(value, str):
            if value == '[redacted]':
                return value
            clean_url = (redaction._URL_USERINFO.sub(lambda m: m[1] + '[redacted]@', value)
                         if '://' in value and '@' in value else value)
            if clean_url != value:
                self.note(value)
                return self.scrub(clean_url)
            pattern = self._ensure_pattern()
            candidates = self._forms.get(value)
            if candidates is None:
                candidates = redaction.canonical_forms(value)
                if len(self._forms) >= 4096:
                    self._forms.clear()
                self._forms[value] = candidates
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
            if result != value and any(k in value for k in redaction._PATH_BEARER_KEYS):
                result['redacted'] = True
            self.source = previous_source
            return self.disclose(result)
        if isinstance(value, (list, tuple)):
            return [self.scrub(v) for v in value]
        return value


def _pair():
    states = redaction.Taint(), LegacyTaint()
    logs = [], []
    for state, log in zip(states, logs):
        def note(value, *, persisted=False, state=state, log=log):
            log.append((value, persisted, state.source))
        state.note = note
    return states, logs


def _extract(state, **kwargs):
    token = redaction._CURRENT.set(state)
    try:
        return redaction.extraction(**kwargs)
    finally:
        redaction._CURRENT.reset(token)


def _values(count, seed=818):
    rng = random.Random(seed)
    return [''.join(rng.choices(string.ascii_letters, k=24)) for _ in range(count)]


def test_randomized_legacy_outputs_and_note_order():
    rng = random.Random(39171)
    alphabet = string.ascii_letters + string.digits + 'éßλ中.*+?[]()|\\'
    interesting = ['a', 'ab', 'abcde', 'abcdef', 'abcdefghi', 'defghi',
                   'Straße', 'STRASSE', 'a.*[b]', 'λ中éßab', '%2561bcdef',
                   'branch/../tiny', '[redacted]', '%61', 'complete']
    checked = 0
    for count in (0, 1, 5, 100, 1000, 5000):
        states, logs = _pair()
        seeds = interesting[:min(count, len(interesting))]
        seeds += [''.join(rng.choices(alphabet, k=rng.randrange(6, 32)))
                  for _ in range(count - len(seeds))]
        for state in states:
            state.add(seeds)
        for index in range(850):
            if index and index % 31 == 0:
                fresh = ''.join(rng.choices(alphabet, k=rng.randrange(1, 24)))
                seeds.append(fresh)
                for state in states:
                    state.add(fresh)
            selected = rng.choice(seeds) if seeds else 'readable'
            raw = rng.choice([selected, 'before ' + selected + ' after',
                              selected.upper(), 'readable-' + str(index),
                              '%25' + selected, '[redacted]', '\"' + selected + '\"'])
            kind = index % 10
            if kind == 0:
                value = {'source': 'sample/input', 'coverage': 'complete',
                         'nested': [raw, {'token': selected, 'reason': raw}],
                         'count': 3, 'sample_paths': [raw]}
                outputs = [state.scrub(value) for state in states]
            elif kind == 1:
                url = 'https' + '://' + 'reader:' + selected.replace('@', '') + '@' + 'example' + '.' + 'invalid' + '/item'
                outputs = [_extract(state, value=url) for state in states]
            elif kind == 2:
                data = ('prefix ' + raw + ' suffix ' + selected).encode()
                outputs = [_extract(state, path=Path('sample.txt'), data=data) for state in states]
            elif kind == 3:
                value = {'api_key': selected, 'nested': ['--token', raw]}
                for state in states:
                    state.observe_value(value)
                outputs = [state.scrub(value) for state in states]
            elif kind == 4:
                outputs = [_extract(state, value=raw) for state in states]
            elif kind == 5:
                outputs = [state.scrub([raw, (selected, None, 17, False)]) for state in states]
            else:
                outputs = [state.scrub(raw) for state in states]
            assert outputs[0] == outputs[1], (count, index, raw)
            assert logs[0] == logs[1], (count, index)
            assert states[0].values == states[1].values
            assert states[0].exact_values == states[1].exact_values
            logs[0].clear()
            logs[1].clear()
            checked += 1
    assert checked == 5100


def test_exact_promotion_overlaps_and_withheld_bytes():
    states, logs = _pair()
    # A shorter spelling must not demote long aliases or reveal overlapping tails.
    for value in ('branch/../tiny', 'tiny', 'abcdef', 'abcdefghi', 'defghi',
                  'ssssss', 'ssssss-tail', 'ssssss-tall', 'ßßß',
                  'i\u0307i\u0307i\u0307', 'İİİ',
                  '%2561', '%61', 'a', 'Straße', '[redacted]'):
        for state in states:
            state.add(value)
        for text in ('x branch/../tiny y', 'abcdefghi abcdef defghi',
                     'prefix ssssss suffix', 'ssssss-tail ssssss-tall',
                     'i\u0307i\u0307i\u0307', 'STRASSE', 'x%2561y', 'prefix [redacted] suffix'):
            assert states[0].scrub(text) == states[1].scrub(text)
            assert _extract(states[0], path=Path('plain.txt'), data=text.encode()) == _extract(
                states[1], path=Path('plain.txt'), data=text.encode())
            assert logs[0] == logs[1]
    for state in states:
        state.withheld_sources.add('withheld.txt')
    assert _extract(states[0], path=Path('withheld.txt'), data=b'ignored') == b''
    assert _extract(states[1], path=Path('withheld.txt'), data=b'ignored') == b''
    assert logs[0] == logs[1]


def _scrub_timing(factory, count, repeats=300):
    state = factory()
    state.add(_values(count))
    text = 'readable evidence ' * 12
    state.scrub(text)
    start = time.perf_counter()
    for _ in range(repeats):
        assert state.scrub(text) == text
    return time.perf_counter() - start


def test_scrub_cost_does_not_scale_with_taint_count():
    times = [_scrub_timing(redaction.Taint, count) for count in (100, 1000, 5000)]
    print('scrub seconds for 300 calls at 100/1000/5000:', times)
    # Fifty times as many secrets must not cause fifty times as much matching.
    # Additive slack and an eightfold ratio tolerate loaded/shared CI machines.
    assert times[-1] < times[0] * 8 + 0.03


def test_sweep_with_incremental_observation():
    state = redaction.Taint()
    values = _values(2500)
    state.add(values[:2000])
    started = time.perf_counter()
    for index in range(50000):
        if index % 100 == 0:
            state.observe_text('token=' + values[2000 + index // 100])
        text = 'readable evidence ' + str(index)
        assert _extract(state, value=text) == text
        if index % 1000 == 0:
            assert time.perf_counter() - started < 12
    print('sweep seconds:', time.perf_counter() - started)


def _deep_size(value):
    """Account for retained containers/strings, without process-wide profiling."""
    import sys
    seen, pending, size = set(), [value], 0
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        size += sys.getsizeof(item)
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            pending.extend(item)
    return size


def test_matcher_storage_does_not_allocate_a_container_per_character():
    state = redaction.Taint()
    # A whole observed value can be large; do not amplify it into a dict per char.
    value = 'z' * 20000 + 'end'
    state.add(value)
    retained = _deep_size(vars(state._matcher))
    assert retained < len(value) * 8 + 4096
    assert state.scrub(value) == '[redacted]'
    assert state.scrub(value[:-1]) == value[:-1]


def test_form_cache_is_lru_and_bounded_even_for_large_inputs():
    state = redaction.Taint()
    state.add('sensitive-value')
    hot = 'hot readable value'
    for index in range(6000):
        state.scrub('readable ' + str(index))
        state.scrub(hot)
    assert hot in state._forms
    assert 'readable 0' not in state._forms
    assert len(state._forms) <= 4096
    assert state._forms_weight <= 1024 * 1024
    huge = 'q' * (1024 * 1024)
    assert state._canonical_forms(huge) == redaction.canonical_forms(huge)
    assert huge not in state._forms
    assert hot in state._forms


def test_common_prefix_matching_work_is_independent_of_branch_count():
    class CountedText(str):
        operations = 0

        def __getitem__(self, key):
            self.operations += 1
            return super().__getitem__(key)

        def startswith(self, *args):
            self.operations += 1
            return super().startswith(*args)

    work = []
    for count in (100, 1000, 5000):
        state = redaction.Taint()
        state.add(['common-prefix-' + chr(0x1000 + index) + '-suffix' for index in range(count)])
        text = CountedText('common-prefix-' + chr(0x4000) + '-readable')
        assert not state._ensure_pattern().search(text)
        work.append(text.operations)
    assert max(work) <= min(work) * 2


def test_radix_branching_and_removal_against_literal_regex():
    rng = random.Random(1771)
    matcher = redaction._LiteralMatcher()
    values = set()
    for _ in range(1500):
        value = 'common' + ''.join(rng.choices('abc.*λ', k=rng.randrange(0, 20)))
        matcher.add(value)
        values.add(value)
        if rng.randrange(3) == 0:
            old = rng.choice(sorted(values))
            matcher.discard(old)
            values.remove(old)
        # Remove absent and already removed values as well.
        matcher.discard('absent-value')
        regex = OverlapRegex('|'.join(re.escape(v) for v in sorted(values, key=len, reverse=True))) if values else None
        texts = [value, 'prefix ' + value + ' suffix',
                 'common' + ''.join(rng.choices('abc.*λ', k=30)),
                 'readable', 'commoncommonabc']
        for text in texts:
            assert matcher.search(text) == bool(regex and regex.search(text))
            actual, expected = [], []
            def replacement(log):
                def replace(match):
                    log.append(match[0])
                    return '[redacted]'
                return replace
            assert matcher.sub(replacement(actual), text) == (
                regex.sub(replacement(expected), text) if regex else text)
            assert actual == expected
        assert matcher.size == len(values)


def test_report_synthetic_retained_memory():
    for count in (100, 1000, 5000):
        state = redaction.Taint()
        state.add(_values(count))
        print('retained matching bytes', count, _deep_size(
            [state.values, state.exact_values, vars(state._matcher), state._forms]))
