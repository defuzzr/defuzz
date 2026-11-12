"""Malformed deferred region references fail closed in the parent (B4).

The child reports regions it could not own as ``_DEFERRED + str(index)`` plus a
``deferred`` list of sources; the parent re-homes them. Anything that is not a
list/tuple of sources, or a reference that is not a non-negative ASCII decimal
index (leading zeros allowed) within range and within int()'s digit limit, must
raise ``BudgetExceeded('stopped')`` before any of the parent's taint data is
assigned.
"""
import pytest

from tests.conftest import load_submodule


@pytest.fixture
def bounded():
    return load_submodule('audit.bounded_call')


class _NoOwner:
    owner = None


class _Owner:
    def __init__(self):
        self.seen = []

    def owner(self, source):
        self.seen.append(source)
        return f'region:{source}'


MALFORMED_CONTAINERS = [
    pytest.param({0: 'src'}, id='int-keyed-mapping'),
    pytest.param({'0': 'src'}, id='str-keyed-mapping'),
    pytest.param({1: 'src'}, id='mapping-missing-key'),
    pytest.param({}, id='empty-mapping'),
    pytest.param('ab', id='str'),
    pytest.param(b'ab', id='bytes'),
    pytest.param(bytearray(b'ab'), id='bytearray'),
    pytest.param({'src'}, id='set'),
    pytest.param(range(3), id='range'),
    pytest.param(None, id='none'),
    pytest.param(5, id='int'),
]

MALFORMED_REFERENCES = ['-1', '+0', ' 0', '0 ', '\u0660', '\uff10', '0_0', '', 'x']


def _assert_unchained(exc):
    # Fail closed with no visible chained exception (the 'from None' contract).
    assert exc.__cause__ is None
    assert exc.__context__ is None or exc.__suppress_context__


def _ref(bounded, suffix):
    return bounded._DEFERRED + suffix


@pytest.mark.parametrize('deferred', MALFORMED_CONTAINERS)
def test_malformed_deferred_container_fails_closed(bounded, deferred):
    redactions = {_ref(bounded, '0'): ['v']}
    with pytest.raises(bounded.BudgetExceeded) as info:
        bounded._rehome_redactions(redactions, deferred, _NoOwner())
    assert info.value.kind == 'stopped'
    _assert_unchained(info.value)


@pytest.mark.parametrize('suffix', MALFORMED_REFERENCES)
def test_malformed_deferred_reference_fails_closed(bounded, suffix):
    redactions = {_ref(bounded, suffix): ['v']}
    with pytest.raises(bounded.BudgetExceeded) as info:
        bounded._rehome_redactions(redactions, ['a', 'b'], _NoOwner())
    assert info.value.kind == 'stopped'
    _assert_unchained(info.value)


def test_out_of_range_reference_still_fails_closed(bounded):
    with pytest.raises(bounded.BudgetExceeded):
        bounded._rehome_redactions({_ref(bounded, '2'): ['v']}, ['a', 'b'], _NoOwner())


def test_malformed_container_ignored_without_deferred_regions(bounded):
    # No deferred reference to resolve: plain regions pass through unchanged.
    out = bounded._rehome_redactions({'r': ['v']}, {'0': 'x'}, _NoOwner())
    assert out == {'r': {'v'}}


@pytest.mark.parametrize('container', [list, tuple])
def test_valid_deferred_rehomes(bounded, container):
    redactions = {_ref(bounded, '1'): [('p', 'v1')], _ref(bounded, '0'): {('q', 'v0')},
                  'plain': (('r', 'v2'),)}
    owner = _Owner()
    out = bounded._rehome_redactions(redactions, container(['a', 'b']), owner)
    assert out == {'region:b': {('p', 'v1')}, 'region:a': {('q', 'v0')},
                   'plain': {('r', 'v2')}}
    assert owner.seen == ['b', 'a']
    out = bounded._rehome_redactions(redactions, container(['a', 'b']), _NoOwner())
    assert out == {'shared_infrastructure': {('p', 'v1'), ('q', 'v0')},
                   'plain': {('r', 'v2')}}


@pytest.mark.parametrize('deferred', [
    pytest.param({0: 'src'}, id='int-keyed-mapping'),
    pytest.param('ab', id='str'),
    pytest.param(b'ab', id='bytes'),
])
def test_merge_taint_leaves_parent_unassigned(bounded, deferred):
    redaction = load_submodule('audit.redaction')
    state = redaction.Taint()
    state.values.add('parent-value')
    state.redactions['parent-region'] = {('src', 'parent-value')}
    state._pattern_size = 7
    token = redaction._CURRENT.set(state)
    try:
        final = {'fields': {'values': {'child-value'},
                            'redactions': {_ref(bounded, '0'): [('s', 'child-value')]}},
                 'project_roots': set(), 'deferred': deferred}
        with pytest.raises(bounded.BudgetExceeded) as info:
            bounded._merge_taint(final)
        assert info.value.kind == 'stopped'
    finally:
        redaction._CURRENT.reset(token)
    assert state.values == {'parent-value'}
    assert state.redactions == {'parent-region': {('src', 'parent-value')}}
    assert state._pattern_size == 7


# Longer than sys.get_int_max_str_digits() (4300 by default): passes the ASCII
# digit check but int() raises ValueError, which must still fail closed.
OVERSIZE_REFERENCES = [
    pytest.param('0' * 5000, id='zeros-5000'),
    pytest.param('1' * 5000, id='ones-5000'),
    pytest.param('9' * 4301, id='nines-4301'),
]


@pytest.mark.parametrize('owner_cls', [_Owner, _NoOwner], ids=['owner', 'no-owner'])
@pytest.mark.parametrize('container', [list, tuple])
@pytest.mark.parametrize('suffix', OVERSIZE_REFERENCES)
def test_oversize_reference_fails_closed(bounded, suffix, container, owner_cls):
    owner = owner_cls()
    redactions = {'plain': ['p'], _ref(bounded, suffix): ['v']}
    with pytest.raises(bounded.BudgetExceeded) as info:
        bounded._rehome_redactions(redactions, container(['a', 'b']), owner)
    assert info.value.kind == 'stopped'
    _assert_unchained(info.value)
    assert getattr(owner, 'seen', []) == []


@pytest.mark.parametrize('owner', [lambda src: f'region:{src}', None], ids=['owner', 'no-owner'])
@pytest.mark.parametrize('container', [list, tuple])
@pytest.mark.parametrize('suffix', OVERSIZE_REFERENCES)
def test_oversize_reference_leaves_parent_unassigned(bounded, suffix, container, owner):
    redaction = load_submodule('audit.redaction')
    state = redaction.Taint()
    state.owner = owner
    state.values.add('parent-value')
    state.redactions['parent-region'] = {('src', 'parent-value')}
    state._pattern_size = 7
    values, regions = state.values, state.redactions
    token = redaction._CURRENT.set(state)
    try:
        final = {'fields': {'values': {'child-value'},
                            'redactions': {_ref(bounded, suffix): [('s', 'child-value')]}},
                 'project_roots': set(), 'deferred': container(['a', 'b'])}
        with pytest.raises(bounded.BudgetExceeded) as info:
            bounded._merge_taint(final)
        assert info.value.kind == 'stopped'
        _assert_unchained(info.value)
    finally:
        redaction._CURRENT.reset(token)
    assert state.values is values and state.values == {'parent-value'}
    assert state.redactions is regions
    assert state.redactions == {'parent-region': {('src', 'parent-value')}}
    assert state._pattern_size == 7


@pytest.mark.parametrize('suffix', ['00', '01'])
def test_leading_zero_reference_accepted(bounded, suffix):
    out = bounded._rehome_redactions({_ref(bounded, suffix): ['v']}, ['a', 'b'], _Owner())
    assert out == {f'region:{"ab"[int(suffix)]}': {'v'}}


# Each region's items must be a set, frozenset, list or tuple; anything else
# (str would otherwise be split into characters) fails closed, for plain and
# deferred regions alike.
MALFORMED_ITEMS = [
    pytest.param('ab', id='str'),
    pytest.param(b'ab', id='bytes'),
    pytest.param({'v': 1}, id='mapping'),
    pytest.param(5, id='int'),
    pytest.param(None, id='none'),
]


@pytest.mark.parametrize('deferred_region', [False, True], ids=['plain', 'deferred'])
@pytest.mark.parametrize('items', MALFORMED_ITEMS)
def test_malformed_items_container_fails_closed(bounded, items, deferred_region):
    region = _ref(bounded, '0') if deferred_region else 'plain'
    redactions = {'ok': ['p'], region: items}
    with pytest.raises(bounded.BudgetExceeded) as info:
        bounded._rehome_redactions(redactions, ['a'], _NoOwner())
    assert info.value.kind == 'stopped'
    _assert_unchained(info.value)


@pytest.mark.parametrize('items', MALFORMED_ITEMS)
def test_malformed_items_leaves_parent_unassigned(bounded, items):
    redaction = load_submodule('audit.redaction')
    state = redaction.Taint()
    state.values.add('parent-value')
    state.redactions['parent-region'] = {('src', 'parent-value')}
    state._pattern_size = 7
    values, regions = state.values, state.redactions
    token = redaction._CURRENT.set(state)
    try:
        final = {'fields': {'values': {'child-value'}, 'redactions': {'plain': items}},
                 'project_roots': set(), 'deferred': []}
        with pytest.raises(bounded.BudgetExceeded) as info:
            bounded._merge_taint(final)
        assert info.value.kind == 'stopped'
    finally:
        redaction._CURRENT.reset(token)
    assert state.values is values and state.values == {'parent-value'}
    assert state.redactions is regions
    assert state.redactions == {'parent-region': {('src', 'parent-value')}}
    assert state._pattern_size == 7
