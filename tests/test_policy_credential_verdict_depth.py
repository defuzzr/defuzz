"""credential_verdict stays linear in path depth, with unchanged (or stricter) verdicts.

The declared-credential and uncertain-root checks used to build and stringify a Path
for every ancestor of the checked path on every call: quadratic per call, cubic over
a deep walk. They now compare one absolute string against the (few) declared entries.
"""
import os
import pathlib
import random
from pathlib import Path, PurePath

import pytest

from tests.conftest import load_submodule

policy = load_submodule('audit.policy')
redaction = load_submodule('audit.redaction')


@pytest.fixture
def state():
    taint = redaction.Taint()
    token = redaction._CURRENT.set(taint)
    try:
        yield taint
    finally:
        redaction._CURRENT.reset(token)


def _deep(top, depth):
    return top + '/x' * depth


def _count_ancestor_paths(monkeypatch):
    """Count Path objects derived from another (each ancestor in .parents is one)."""
    calls = [0]
    original = PurePath.with_segments

    def counting(self, *segments):
        calls[0] += 1
        return original(self, *segments)

    monkeypatch.setattr(pathlib.PurePath, 'with_segments', counting)
    return calls


@pytest.mark.parametrize('case', ['declared', 'uncertain', 'relative-unmatched'])
def test_per_call_path_objects_do_not_grow_with_depth(state, monkeypatch, case):
    def make(depth):
        if case == 'relative-unmatched':
            return 'x/' * depth + 'plain.txt'
        return _deep('/b5cv_' + case, depth)

    if case == 'declared':
        state.credential_paths.add('/b5cv_declared')
    elif case == 'uncertain':
        state.credential_uncertain_roots = {Path('/b5cv_uncertain')}
    else:
        state.credential_paths.add('/b5cv_elsewhere')
    shallow_path, deep_path = make(3), make(3000)
    calls = _count_ancestor_paths(monkeypatch)
    shallow_verdict = policy.credential_verdict(shallow_path)
    shallow = calls[0]
    calls[0] = 0
    deep_verdict = policy.credential_verdict(deep_path)
    assert deep_verdict == shallow_verdict == (None if case == 'relative-unmatched' else 'credential')
    assert calls[0] <= shallow + 2, (shallow, calls[0])


def _count_normpath(monkeypatch):
    """Count os.path.normpath calls (os.path.abspath normalises through it too)."""
    calls = [0]
    original = os.path.normpath

    def counting(path):
        calls[0] += 1
        return original(path)

    monkeypatch.setattr(os.path, 'normpath', counting)
    return calls


@pytest.mark.parametrize('case', ['miss', 'declared', 'uncertain'])
def test_per_call_normalisation_does_not_grow_with_entries(state, monkeypatch, case):
    depth = 5
    path = '/b5cv_n' + '/d' * (depth - 1) + '/file.txt'
    others = {f'/b5cv_elsewhere/e{i}/.cfg/f{i}.txt' for i in range(5000)}
    state.credential_paths.update(others)
    state.credential_uncertain_roots = set(others)
    if case == 'declared':
        state.credential_paths.add('/b5cv_n/d')
    elif case == 'uncertain':
        state.credential_uncertain_roots.add('/b5cv_n/d')
    expected = None if case == 'miss' else 'credential'
    assert policy.credential_verdict(path) == expected  # Warm: the declared view is built once.
    calls = _count_normpath(monkeypatch)
    assert policy.credential_verdict(path) == expected
    # Per-entry normalisation made this ~10000; it must not depend on the entry count.
    assert calls[0] <= depth + 5, calls[0]


def test_helper_normalises_only_prefix_entries(monkeypatch):
    absolute = '/b5cv_n/d/d/d/d/file.txt'
    entries = {f'/b5cv_elsewhere/e{i}/f{i}' for i in range(5000)} | {'/b5cv_n/d', '/b5cv_n/d/d/d/d/fi'}
    calls = _count_normpath(monkeypatch)
    assert policy._self_or_inside(absolute, entries)
    assert calls[0] <= 3, calls[0]  # The joined text once, then only entries that prefix the path.
    calls[0] = 0
    assert not policy._self_or_inside(absolute, entries - {'/b5cv_n/d'})
    assert calls[0] <= 3, calls[0]


def test_root_as_declared_credential_covers_everything(state, tmp_path, monkeypatch):
    state.credential_paths.add('/')
    monkeypatch.chdir(tmp_path)
    for path in ('/', '/b5cv/a', _deep('/b5cv', 500), 'relative/file.txt', Path('/b5cv/p')):
        assert policy.credential_verdict(path) == 'credential', path


@pytest.mark.parametrize('root', [Path('/'), '/'])
def test_root_as_uncertain_root_covers_everything(state, root):
    state.credential_uncertain_roots = {root}
    for path in ('/', '/b5cv/a', _deep('/b5cv', 500)):
        assert policy.credential_verdict(path) == 'credential', path


@pytest.mark.parametrize('entry', ['/b5cv/tree/', Path('/b5cv/tree'), '/b5cv//tree', '/b5cv/./tree',
                                   '/b5cv/other/../tree'])
def test_unnormalized_and_path_entries_match_fail_closed(state, entry):
    state.credential_paths.add(entry)
    assert policy.credential_verdict('/b5cv/tree') == 'credential'
    assert policy.credential_verdict('/b5cv/tree/deep/file.txt') == 'credential'
    assert policy.credential_verdict('/b5cv/treehouse/file.txt') is None


@pytest.mark.parametrize('root', ['/b5cv/tree/', Path('/b5cv/tree'), '/b5cv/tree', Path('/b5cv/x/../tree')])
def test_uncertain_root_entries_match_fail_closed(state, root):
    state.credential_uncertain_roots = {root}
    assert policy.credential_verdict('/b5cv/tree') == 'credential'
    assert policy.credential_verdict('/b5cv/tree/deep/file.txt') == 'credential'
    assert policy.credential_verdict('/b5cv/treehouse/file.txt') is None


def test_sibling_prefix_is_not_inside(state):
    state.credential_paths.add('/b5cv/a/b')
    state.credential_uncertain_roots = {Path('/b5cv/u/b')}
    for path in ('/b5cv/a/bc', '/b5cv/a/bc/file.txt', '/b5cv/a/b.txt', '/b5cv/a',
                 '/b5cv/u/bc', '/b5cv/u/bc/file.txt', '/b5cv/u'):
        assert policy.credential_verdict(path) is None, path


def test_exact_and_deep_ancestor_matches(state):
    state.credential_paths.add('/b5cv/a/b')
    assert policy.credential_verdict('/b5cv/a/b') == 'credential'
    assert policy.credential_verdict(_deep('/b5cv/a/b', 2000)) == 'credential'
    assert policy.credential_verdict(Path(_deep('/b5cv/a/b', 7))) == 'credential'


def test_relative_paths_resolve_against_cwd(state, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state.credential_paths.add(str(tmp_path / 'keys'))
    assert policy.credential_verdict('keys') == 'credential'
    assert policy.credential_verdict('keys/inner/x.txt') == 'credential'
    assert policy.credential_verdict('./sub/../keys/inner') == 'credential'
    assert policy.credential_verdict('keysafe/x.txt') is None


def test_non_text_uncertain_roots_are_ignored(state):
    state.credential_uncertain_roots = {b'/b5cv/bytes', 3, None}
    assert policy.credential_verdict('/b5cv/bytes/file.txt') is None


def test_bytes_input_still_raises_type_error(state):
    state.credential_paths.add('/b5cv/a')
    with pytest.raises(TypeError):
        policy.credential_verdict(b'/b5cv/a/x')


def _reference(absolute, entries):
    """Base semantics of the two checks, on normalised entries (Path ancestors)."""
    path = Path(absolute)
    chain = (path, *path.parents)
    strings = {str(p) for p in chain}
    for entry in entries:
        try:
            text = os.fspath(entry)
        except TypeError:
            continue
        if isinstance(text, str) and str(Path(os.path.normpath(text))) in strings:
            return True
    return False


def test_helper_matches_path_ancestor_reference():
    rng = random.Random(5)
    names = ['a', 'b', 'ab', 'a.b', 'é', '中', 'x y', '..a', '.', '..']
    spellings = []
    for _ in range(400):
        parts = [rng.choice(names) for _ in range(rng.randint(0, 6))]
        lead = rng.choice(['/', '/', '//', '///', ''])
        tail = rng.choice(['', '', '/'])
        spellings.append(lead + '/'.join(parts) + tail)
    for _ in range(4000):
        absolute = os.path.abspath(rng.choice(spellings) or '/')
        absolute = str(Path(absolute))
        entries = rng.sample(spellings, rng.randint(1, 4))
        entries = [Path(e) if e and rng.random() < 0.3 else e for e in entries]
        assert policy._self_or_inside(absolute, entries) == _reference(absolute, entries), (absolute, entries)


@pytest.mark.parametrize('spelling', ['/b5cv/tree/', '/b5cv/tree/.', '/b5cv/tree/x/..', '/b5cv/tree/x/../',
                                      '/b5cv//tree', '/b5cv/./tree', '///b5cv/tree', '/b5cv/q/../tree'])
@pytest.mark.parametrize('position', [0, 1, 50])
def test_unnormalised_entry_counts_in_any_position_among_many(spelling, position):
    others = [f'/b5cv_o/e{i}/f' for i in range(50)]
    for container in (list, tuple):
        entries = container(others[:position] + [spelling] + others[position:])
        assert policy._self_or_inside('/b5cv/tree/deep', entries), (spelling, position)
        assert policy._self_or_inside('/b5cv/tree', entries), (spelling, position)
        assert not policy._self_or_inside('/b5cv/treehouse', entries), (spelling, position)


def _per_entry(absolute, entries):
    """The ca66465 per-entry check, kept verbatim as the reference for the fast path."""
    for entry in entries:
        try:
            entry = os.fspath(entry)
        except TypeError:
            continue
        if not isinstance(entry, str):
            continue
        entry = os.path.normpath(entry)
        if absolute == entry:
            return True
        prefix = entry if entry.endswith('/') else entry + '/'
        if absolute.startswith(prefix) and policy._anchor(absolute) == policy._anchor(entry):
            return True
    return False


class _Liar(str):
    """A str whose hash and equality disagree with its text: only its text may count."""

    def __hash__(self):
        return 7

    def __eq__(self, other):
        return False


def test_helper_matches_per_entry_reference_on_large_mixed_sets():
    rng = random.Random(55)
    names = ['a', 'b', 'ab', '.a', 'a.', 'é', 'x\0y', '.', '..', '']
    spellings = []
    for _ in range(600):
        parts = [rng.choice(names) for _ in range(rng.randint(0, 6))]
        lead = rng.choice(['/', '/', '/', '//', '///', ''])
        tail = rng.choice(['', '', '', '/', '/.', '/..'])
        spellings.append(lead + '/'.join(parts) + tail)
    normal = [str(Path(os.path.abspath(s or '/'))) for s in spellings]
    pool = spellings + normal + normal
    for _ in range(3000):
        absolute = rng.choice(normal)
        entries = rng.sample(pool, rng.randint(1, 60))
        roll = rng.random()
        if roll < 0.15:
            entries.append(Path(rng.choice(pool) or '/'))
        elif roll < 0.25:
            entries.append(_Liar(rng.choice(pool)))
        elif roll < 0.3:
            entries.append(rng.choice([b'/a', None, 3]))
        for container in (set, frozenset, list, tuple):
            try:
                built = container(entries)
            except TypeError:
                continue
            assert policy._self_or_inside(absolute, built) == _per_entry(absolute, built), (absolute, built)
