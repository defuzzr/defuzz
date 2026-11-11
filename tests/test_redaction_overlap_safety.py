"""Adding synthetic taints must never reveal a previously sealed field or span."""
from itertools import permutations
from pathlib import Path
import random

import pytest

from tests.conftest import load_submodule


redaction = load_submodule('audit.redaction')


def _extract(state, text):
    token = redaction._CURRENT.set(state)
    try:
        return redaction.extraction(path=Path('sample.txt'), data=text.encode()).decode()
    finally:
        redaction._CURRENT.reset(token)


@pytest.mark.parametrize('unit,short_unit', [('ss', 'ß'), ('i\u0307', 'İ'), ('fi', 'ﬁ')])
@pytest.mark.parametrize('before,after', [('', ''), ('', ' end'), ('start ', ''), ('start ', ' end')])
def test_short_alias_cannot_disable_long_substring_sealing(unit, short_unit, before, after):
    long = unit * 3
    short = short_unit * 3
    text = before + long + after
    state = redaction.Taint()
    state.add(long)
    assert state.scrub(text) == '[redacted]'
    assert _extract(state, text) == before + '[redacted]' + after
    state.add(short)
    assert state.scrub(text) == '[redacted]'
    assert _extract(state, text) == before + '[redacted]' + after
    assert state.scrub(text.upper()) == '[redacted]'


@pytest.mark.parametrize('reverse', [False, True])
def test_long_aliases_are_substring_taints_regardless_of_add_order(reverse):
    long, short = 'ss' * 3, 'ß' * 3
    state = redaction.Taint()
    state.add([short, long] if reverse else [long, short])
    assert state.scrub('start ' + long + ' end') == '[redacted]'
    assert state.scrub(short) == '[redacted]'
    assert _extract(state, 'start ' + long + ' end') == 'start [redacted] end'


def test_only_short_forms_remain_whole_field_only():
    state = redaction.Taint()
    short = 'a' + 'b'
    long = 'branch' + '/../' + short
    state.add(long)
    assert state.scrub(short) == '[redacted]'
    assert state.scrub('start ' + short + ' end') != '[redacted]'
    assert _extract(state, 'start ' + short + ' end') == 'start ' + short + ' end'
    assert _extract(state, 'start ' + long + ' end') == 'start [redacted] end'


def _mask(matcher, text):
    opened, closed = '\ue000', '\ue001'
    marked = matcher.sub(lambda match: opened + match[0] + closed, text)
    result, inside, restored = [], False, []
    for char in marked:
        if char == opened:
            assert not inside
            inside = True
        elif char == closed:
            assert inside
            inside = False
        else:
            result.append(inside)
            restored.append(char)
    assert not inside
    assert ''.join(restored) == text
    return result


def _literal_mask(values, text):
    expected = [False] * len(text)
    for value in values:
        for start in range(len(text) - len(value) + 1):
            if text.startswith(value, start):
                expected[start:start + len(value)] = [True] * len(value)
    return expected


@pytest.mark.parametrize('alphabet', ['abcdefghijk', 'AbCdEfGhIjK', 'αβγδεζηθικλ'])
@pytest.mark.parametrize('before,after', [('', ''), ('', ' end'), ('start ', ''), ('start ', ' end'),
                                         ('x' * 128 + ' ', ' ' + 'y' * 128)])
def test_earlier_overlap_cannot_reveal_a_sealed_tail(alphabet, before, after):
    long, short = alphabet[3:], alphabet[:6]
    text = before + alphabet + after
    state = redaction.Taint()
    state.add(long)
    prior = _mask(state._matcher, text)
    assert _extract(state, text) == before + alphabet[:3] + '[redacted]' + after
    state.add(short)
    current = _mask(state._matcher, text)
    assert all(not old or new for old, new in zip(prior, current))
    assert _extract(state, text) == before + '[redacted]' + after


@pytest.mark.parametrize('text,values', [
    ('a' * 19, ['a' * 6, 'a' * 7, 'a' * 11]),
    (''.join('abcdefghijklmnop'), ['abcdef', 'efghijk', 'jklmnop']),
    ('abcdef' + 'ghijkl', ['abcdef', 'ghijkl', 'cdefgh']),
    ('abc' * 5, ['abc' * 2, 'bcabca', 'cabcab']),
])
def test_overlap_union_is_monotonic_for_every_add_order(text, values):
    for order in permutations(values):
        matcher = redaction._LiteralMatcher()
        seen, previous = set(), [False] * len(text)
        for value in order:
            seen.add(value)
            matcher.add(value)
            current = _mask(matcher, text)
            assert all(not old or new for old, new in zip(previous, current))
            assert current == _literal_mask(seen, text)
            previous = current


def test_randomized_overlap_union_matches_all_literal_occurrences():
    rng = random.Random(431902)
    alphabet = 'abABßﬁi\u0307λ中.*[]'
    for _ in range(120):
        text = ''.join(rng.choices(alphabet, k=48))
        matcher = redaction._LiteralMatcher()
        previous, values = [False] * len(text), set()
        for _ in range(12):
            start = rng.randrange(len(text) - 6)
            value = text[start:start + rng.randrange(6, 18)]
            values.add(value)
            matcher.add(value)
            current = _mask(matcher, text)
            assert current == _literal_mask(values, text)
            assert all(not old or new for old, new in zip(previous, current))
            previous = current
        for value in sorted(values):
            matcher.discard(value)
            values.remove(value)
            assert _mask(matcher, text) == _literal_mask(values, text)
            assert matcher.search(text) == any(_literal_mask(values, text))


def test_nonoverlapping_replacements_keep_separate_notes():
    matcher = redaction._LiteralMatcher()
    left, right = 'abc' * 2, 'xyz' * 2
    matcher.add(left)
    matcher.add(right)
    notes = []
    def replace(match):
        notes.append(match[0])
        return '[redacted]'
    assert matcher.sub(replace, left + right + ' gap ' + left) == '[redacted][redacted] gap [redacted]'
    assert notes == [left, right, left]


@pytest.mark.parametrize('count', [1, 10, 30, 64])
def test_small_root_set_miss_needs_no_per_position_trie_walk(count):
    class CountedMatcher(redaction._LiteralMatcher):
        walks = 0

        def _end(self, *args, **kwargs):
            self.walks += 1
            return super()._end(*args, **kwargs)

    matcher = CountedMatcher()
    for index in range(count):
        matcher.add(f'{index:06d}' + 'suffix')
    text = 'readable prose ' * 1000
    assert not matcher.search(text)
    assert matcher.sub(lambda match: '[redacted]', text) == text
    assert matcher.walks == 0


@pytest.mark.parametrize('count', [1, 63, 64, 65, 100])
def test_prefilter_threshold_and_updates_preserve_every_literal_match(count):
    matcher = redaction._LiteralMatcher()
    values = {f'{index:06d}' + 'λsuffix' for index in range(count)}
    for value in sorted(values):
        matcher.add(value)
    target = f'{count - 1:06d}' + 'λsuffix'
    for text in [target, 'x' * 200 + target, target + 'x' * 200,
                 'x' * 200 + target[:-1] + ' gap ' + target + ' end',
                 'x' * 200 + target[:-1]]:
        assert matcher.search(text) == any(_literal_mask(values, text))
        assert _mask(matcher, text) == _literal_mask(values, text)
    matcher.discard(target)
    values.remove(target)
    assert not matcher.search('x' * 200 + target)
    matcher.add(target)
    assert matcher.search('x' * 200 + target)


def test_early_root_hit_does_not_prescan_large_text_for_other_roots():
    class CountedText(str):
        contains_calls = 0

        def __contains__(self, value):
            self.contains_calls += 1
            return super().__contains__(value)

    matcher = redaction._LiteralMatcher()
    for index in range(64):
        matcher.add(f'{index:06d}' + 'suffix')
    text = CountedText('000063suffix' + 'x' * 1000)
    assert matcher.search(text)
    assert text.contains_calls == 0
