"""A cut is decided by the fixed reason code, never by words that happen to be in a path.

Synthetic homes under tmp_path only.
"""
from pathlib import Path

import pytest

from tests.conftest import load_submodule

REAL_LIMITS = ('entry_limit_exceeded', 'total_byte_limit_exceeded', 'time_budget', 'file_byte_limit_exceeded')


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _home(tmp_path):
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    return load_submodule('audit.outward'), profile


def _cut_codes(result):
    # Cut evidence is sealed; its count per budget is what the stored report shows.
    return {name: len(budget['cuts']) for name, budget in result['limits']['regions'].items()}


def _skipped_codes(result):
    return {region: sorted(d['code'] for d in record.get('reason_details', []))
            for region, record in result['regions'].items()}


def _run_with_skipped_folder(tmp_path, parent, skipped):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / parent
    _write(tree / 'notes.md', 'plain text\n')
    _write(tree / skipped / 'index.js', 'x\n')
    if skipped == '.venv':
        _write(tree / skipped / 'pyvenv.cfg', 'home = /usr/bin\n')
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    return mod.collect_outward(profile, [])


@pytest.mark.parametrize('trigger, neutral, skipped', [
    ('rate-limit-notes', 'plain-notes', 'node_modules'),
    ('docs/excluded-ideas', 'docs/plain-ideas', '__pycache__'),
    ('time_budget-report', 'plain-report', '.venv'),
    ('limit-truncated-excluded-time_budget-entry_limit_exceeded', 'plain', 'node_modules'),
])
def test_trigger_words_in_a_path_do_not_make_a_cut(tmp_path, trigger, neutral, skipped):
    loaded = _run_with_skipped_folder(tmp_path / 'a', trigger, skipped)
    plain = _run_with_skipped_folder(tmp_path / 'b', neutral, skipped)
    assert _cut_codes(loaded) == _cut_codes(plain)
    assert not any(_cut_codes(loaded).values())
    # A skipped folder stays declared: counted, and its region could not be verified.
    assert loaded['limits']['regions']['active_profile']['pruned_roots']['count'] == 1
    assert 'skipped_folders' in _skipped_codes(loaded)['shared_infrastructure']
    assert loaded['regions']['shared_infrastructure']['coverage'] == 'could_not_verify'
    assert _skipped_codes(loaded) == _skipped_codes(plain)


def test_every_real_limit_still_records_a_cut(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'plain'
    for i in range(30):
        _write(tree / f'f{i}.md', 'x' * 1000)
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')

    def cuts(patch=None, **kwargs):
        with monkeypatch.context() as m:
            for name, value in (patch or {}).items():
                m.setattr(mod, name, value)
            result = mod.collect_outward(profile, [], **kwargs)
            codes = {c for region in _skipped_codes(result).values() for c in region}
            return sum(_cut_codes(result).values()), codes

    assert cuts() == (0, set())
    for code, patch, kwargs in (('entry_limit_exceeded', {'MAX_TREE_ENTRIES': 10}, {}),
                                ('total_byte_limit_exceeded', {'MAX_TREE_BYTES': 2500}, {}),
                                ('time_budget', {'MAX_TREE_SECONDS': 0}, {}),
                                ('file_byte_limit_exceeded', {}, {'max_file_bytes': 10})):
        count, codes = cuts(patch, **kwargs)
        assert code in codes and count >= 1, code
