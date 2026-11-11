"""Pending-edit scan in audit/memory_load.py: linear work, identical output.

``_pending`` used to re-split the target memory file (and regex-scan every entry
holding the old text) once per pending operation, so a pending batch of N
operations against a file of M entries cost O(N * M). The scaling test counts
entry visits through the module's own ``_entries`` and ``APPROVAL_RE`` hooks
(no wall clock). The differential test keeps the pre-fix body below as a
reference and requires identical results, scan cuts and ``absent`` calls over a
few hundred generated cases.
"""

from __future__ import annotations

import json
import random
from pathlib import PurePosixPath

import pytest

from tests.conftest import load_submodule

mod = load_submodule('audit.memory_load')


def _reference_pending(paths, texts, scan):
    """Verbatim body of _pending before the linear rewrite (module helpers looked up live)."""
    result: dict = {'count': len(paths), 'stale_edits': 0, 'approval_edits': 0, 'operations': 0,
              'unverified_edits': 0}
    for rel, profile in paths:
        read = scan.read(rel)
        stale = approval = invalid = False
        try:
            record = json.loads(read[0]) if read else None
            payload = record.get('payload') if isinstance(record, dict) else None
            if not isinstance(payload, dict) or payload.get('target') not in ('memory', 'user'):
                raise ValueError('shape')
            target = texts.get((profile, payload['target']))
            target_rel = rel.parent.parent.parent / 'memories' / (payload['target'].upper() + '.md')
            if target is None and scan.absent(target_rel):
                target = ''
            ops = payload.get('operations') if payload.get('action') == 'batch' else [payload]
            if not isinstance(ops, list) or not ops:
                raise ValueError('shape')
            for op in ops:
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
                else:
                    stale |= old not in target
                pinned = op.get('matched_entry', '')
                if not isinstance(pinned, str):
                    raise ValueError('shape')
                matching = [e for e in mod._entries(target or '') if old in e]
                approval |= bool(mod.APPROVAL_RE.search(old) or mod.APPROVAL_RE.search(pinned) or
                                 any(mod.APPROVAL_RE.search(e) for e in matching))
        except (ValueError, TypeError, RecursionError):
            invalid = True
        result['stale_edits'] += stale
        result['approval_edits'] += approval
        if invalid:
            result['unverified_edits'] += 1
            scan.cut('pending_shape')
    result['coverage'] = 'could_not_verify' if result['unverified_edits'] or scan.reasons else 'verified'
    return result


class FakeScan:
    """Stands in for _Scan: canned reads/absence, records every call."""

    def __init__(self, reads, absent, reasons=()):
        self.reads, self.absent_paths = reads, absent
        self.reasons = set(reasons)
        self.log = []

    def read(self, rel):
        self.log.append(('read', str(rel)))
        return self.reads.get(str(rel))

    def absent(self, rel):
        self.log.append(('absent', str(rel)))
        return str(rel) in self.absent_paths

    def cut(self, reason):
        self.log.append(('cut', reason))
        self.reasons.add(reason)


WORDS = ('alpha', 'beta', 'approve', 'Approval', 'permission', 'CONFIRM', 'confirmed', 'gamma',
         'x', 'é', '§', 'path', 'approvals', 'do', 'not')


def _entry(rng):
    return ' '.join(rng.choice(WORDS) for _ in range(rng.randint(0, 6)))


def _target(rng):
    kind = rng.random()
    if kind < 0.1:
        return ''
    sep = rng.choice(['\n§\n', '\n§\n', '\r\n§\r\n', '§', '\n§\n\n§\n'])
    text = sep.join(_entry(rng) for _ in range(rng.randint(1, 8)))
    if rng.random() < 0.5:
        text += '\n'  # final newline (else none)
    if rng.random() < 0.2:
        text = text.replace('\n', '\r\n')
    return text


def _old(rng, target):
    choice = rng.random()
    if target and choice < 0.5:
        i = rng.randrange(len(target))
        return target[i:i + rng.randint(1, 30)]  # overlapping slices, may span delimiters
    if choice < 0.6:
        return ''
    if choice < 0.65:
        return rng.choice([None, 7, ['x']])
    if choice < 0.7:
        return '\n§\n'
    return _entry(rng) or 'zz'


def _op(rng, target, olds):
    r = rng.random()
    if r < 0.03:
        return rng.choice(['add', None, 3])
    action = rng.choice(['add', 'remove', 'replace', 'patch', 'patch', 'remove', 'bogus'])
    op = {'action': action}
    if action != 'add' or rng.random() < 0.3:
        if olds and rng.random() < 0.3:
            op['old_text'] = rng.choice(olds)  # duplicate old text
        else:
            op['old_text'] = _old(rng, target)
            if isinstance(op['old_text'], str):
                olds.append(op['old_text'])
    m = rng.random()
    if m < 0.2:
        op['matched_entry'] = _entry(rng)
    elif m < 0.25:
        op['matched_entry'] = rng.choice([None, 1])
    elif m < 0.3 and target:
        op['matched_entry'] = target
    return op


def _payload(rng, target_name, target):
    olds = []
    if rng.random() < 0.6:
        n = rng.choice([0, 1, 2, 3, 5, 12, 40])
        payload = {'action': 'batch', 'target': target_name,
                   'operations': [_op(rng, target, olds) for _ in range(n)]}
        if rng.random() < 0.03:
            payload['operations'] = rng.choice([None, {}, 'x'])
        return payload
    op = _op(rng, target, olds)
    if not isinstance(op, dict):
        return op
    op['target'] = target_name
    return op


def _case(rng):
    texts, reads, absent, paths = {}, {}, set(), []
    for profile in range(rng.randint(1, 3)):
        prefix = PurePosixPath() if profile == 0 else PurePosixPath('profiles', f'p{profile}')
        for kind in ('memory', 'user'):
            state = rng.random()
            if state < 0.6:
                texts[(profile, kind)] = _target(rng)
            elif state < 0.8:
                absent.add(str(prefix / 'memories' / (kind.upper() + '.md')))
            # else: present but unreadable => target None
        for i in range(rng.randint(0, 4)):
            rel = prefix / 'pending' / 'memory' / f'{i}.json'
            paths.append((rel, profile))
            kind = rng.choice(['memory', 'user', 'user', 'memory', 'other', None])
            shape = rng.random()
            if shape < 0.05:
                continue  # unreadable pending file
            if shape < 0.08:
                reads[str(rel)] = ('{broken', b'')
                continue
            if shape < 0.1:
                reads[str(rel)] = (json.dumps(rng.choice([[], 3, 'x', {'payload': []}])), b'')
                continue
            payload = _payload(rng, kind, texts.get((profile, kind)) or '')
            reads[str(rel)] = (json.dumps({'subsystem': 'memory', 'payload': payload}), b'')
    reasons = {'files'} if rng.random() < 0.1 else set()
    return paths, texts, reads, absent, reasons


def _both(paths, texts, reads, absent, reasons):
    old_scan, new_scan = FakeScan(reads, absent, reasons), FakeScan(reads, absent, reasons)
    old = _reference_pending(paths, texts, old_scan)
    new = mod._pending(paths, texts, new_scan)
    return (old, old_scan.log, old_scan.reasons), (new, new_scan.log, new_scan.reasons)


@pytest.mark.parametrize('seed', range(400))
def test_matches_reference_on_generated_cases(seed):
    old, new = _both(*_case(random.Random(seed)))
    assert new == old


def test_generated_cases_cover_every_counter():
    totals = dict.fromkeys(('stale_edits', 'approval_edits', 'unverified_edits', 'operations'), 0)
    for seed in range(400):
        (result, _, _), _ = _both(*_case(random.Random(seed)))
        for key in totals:
            totals[key] += result[key]
    assert all(totals.values()), totals


def test_hand_written_edge_cases():
    entries = ['keep approval rule', 'plain', 'confirm later', 'plain']
    target = '\n§\n'.join(entries)
    ops = [{'action': 'remove', 'old_text': 'plain'},          # duplicate old text, two entries
           {'action': 'remove', 'old_text': 'plain'},
           {'action': 'replace', 'old_text': 'rule\n§\npla'},  # spans a delimiter: in text, no entry
           {'action': 'patch', 'old_text': 'missing'},         # stale
           {'action': 'add', 'content': 'x'},
           {'action': 'remove', 'old_text': 'approval r'},     # overlaps an approval entry
           {'action': 'remove', 'old_text': ''}]               # empty old text => shape
    paths = [(PurePosixPath('pending/memory/a.json'), 0), (PurePosixPath('pending/memory/b.json'), 0),
             (PurePosixPath('pending/memory/c.json'), 0), (PurePosixPath('pending/memory/d.json'), 0)]
    reads = {'pending/memory/a.json': (json.dumps({'payload': {'action': 'batch', 'target': 'memory',
                                                               'operations': ops}}), b''),
             'pending/memory/b.json': (json.dumps({'payload': {'action': 'remove', 'target': 'user',
                                                               'old_text': 'confirm'}}), b''),
             'pending/memory/c.json': (json.dumps({'payload': {'action': 'batch', 'target': 'memory',
                                                               'operations': ops[:6]}}), b''),
             'pending/memory/d.json': (json.dumps({'payload': {'action': 'remove', 'target': 'memory',
                                                               'old_text': 'confirm', 'matched_entry': 3}}), b'')}
    for texts, absent in (({(0, 'memory'): target}, set()),            # user target unreadable
                          ({(0, 'memory'): target}, {'memories/USER.md'}),
                          ({(0, 'memory'): target.replace('\n', '\r\n') + '\r\n'}, set()),
                          ({(0, 'memory'): target + '\n', (0, 'user'): 'confirm me'}, set()),
                          ({}, {'memories/MEMORY.md', 'memories/USER.md'})):
        old, new = _both(paths, texts, reads, absent, set())
        assert new == old
    (result, _, _), _ = _both(paths[2:3], {(0, 'memory'): target}, reads, set(), set())
    assert result['stale_edits'] == 1 and result['approval_edits'] == 1 and result['operations'] == 6


def test_real_scan_crlf_and_non_utf8(tmp_path):
    """Through the real _Scan: CRLF/BOM targets and undecodable pending files."""
    (tmp_path / 'memories').mkdir()
    (tmp_path / 'pending' / 'memory').mkdir(parents=True)
    (tmp_path / 'memories' / 'MEMORY.md').write_bytes(b'\xef\xbb\xbfneeds approval\r\n\xc2\xa7\r\nplain\r\n')
    batch = {'payload': {'action': 'batch', 'target': 'memory', 'operations': [
        {'action': 'remove', 'old_text': 'plain'}, {'action': 'remove', 'old_text': 'needs'},
        {'action': 'remove', 'old_text': 'gone'}]}}
    (tmp_path / 'pending' / 'memory' / 'a.json').write_text(json.dumps(batch), encoding='utf-8')
    (tmp_path / 'pending' / 'memory' / 'b.json').write_bytes(b'{"payload": \xff\xfe}')
    (tmp_path / 'pending' / 'memory' / 'c.json').write_bytes(json.dumps(batch, indent=1).encode().replace(b'\n', b'\r\n'))
    results = []
    for fn in (_reference_pending, mod._pending):
        scan = mod._Scan(tmp_path, lambda: 0.0)
        read = scan.read(PurePosixPath('memories/MEMORY.md'))
        texts = {(0, 'memory'): read[0]}
        paths = [(PurePosixPath('pending/memory', n), 0) for n in ('a.json', 'b.json', 'c.json')]
        results.append((fn(paths, texts, scan), sorted(scan.reasons), dict(scan.limits)))
    assert results[0] == results[1]
    assert results[1][0]['stale_edits'] == 2 and results[1][0]['approval_edits'] == 2
    assert results[1][0]['unverified_edits'] == 1 and 'encoding' in results[1][1]


def _work(monkeypatch, operations, entries=200, fn=None):
    counter = {'entries_visited': 0}
    real_entries = mod._entries

    def counting_entries(text):
        out = real_entries(text)
        counter['entries_visited'] += len(out)
        return out

    target = '\n§\n'.join(f'shared approval note {i}' for i in range(entries))
    ops = [{'action': 'remove', 'old_text': 'shared', 'matched_entry': ''} for _ in range(operations)]
    rel = PurePosixPath('pending/memory/a.json')
    scan = FakeScan({str(rel): (json.dumps({'payload': {'action': 'batch', 'target': 'memory',
                                                        'operations': ops}}), b'')}, set())
    # Scoped context: undoing it must not undo the autouse isolated_home patches.
    with monkeypatch.context() as mp:
        mp.setattr(mod, '_entries', counting_entries)
        result = (fn or mod._pending)([(rel, 0)], {(0, 'memory'): target}, scan)
    assert result['operations'] == operations and result['approval_edits'] == 1
    return counter


def test_work_is_linear_in_operations(monkeypatch):
    import os
    env_before = {k: os.environ.get(k) for k in ('HOME', 'HERMES_HOME')}
    entries = 200
    for operations in (100, 200, 400, 800):
        work = _work(monkeypatch, operations, entries)
        # Splitting/scanning the target happens once, not once per operation.
        assert work['entries_visited'] <= 2 * entries, (operations, work)
        assert {k: os.environ.get(k) for k in env_before} == env_before
