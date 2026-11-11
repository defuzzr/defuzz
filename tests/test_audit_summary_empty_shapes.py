"""Legitimate empty, absent and could-not-verify section shapes in the plain summary.

Every section dict here comes from the real section modules run on small synthetic homes
(pytest tmp folders), so the shapes are the ones the producers really emit. None of them may
fall into the generic "unexpected shape" sentence; that sentence is only for malformed input.
"""
from __future__ import annotations

import pytest

from tests.conftest import load_submodule
from tests.test_audit_summary import _flat, _w, collect, make_report

SNAPSHOT_DIR = ('backups', 'memory-bg-review', '20261101-010101', 'abcd')


def _mod():
    return load_submodule('audit_summary')


def _snapshot_home(home, raised=True):
    _w(home.joinpath(*SNAPSHOT_DIR, 'MEMORY.md'), 'first note\n\u00a7\nsecond note')
    if raised:
        _w(home / 'config.yaml', 'memory:\n  memory_char_limit: 9000\n')
    return home


def _homes(base):
    empty = base / 'empty'
    empty.mkdir()
    emptymem = base / 'emptymem'
    (emptymem / 'memories').mkdir(parents=True)
    _w(emptymem / 'config.yaml', 'x: 1\n')
    fileroot = base / 'fileroot'
    fileroot.write_text('x')
    return {'empty': empty, 'snaps': _snapshot_home(base / 'snaps'), 'emptymem': emptymem,
            'missing': base / 'nope', 'fileroot': fileroot}


def _memory(home):
    mem = load_submodule('audit.memory_load')
    return mem.audit_memory_load(profile_path=home, home_os='linux', project_families={},
                                 prompt_injecting_plugins=[])


def _section(summary, name):
    return next(s for s in summary['sections'] if s['section'] == name)


def test_snapshot_only_home_says_no_live_memory_files_and_steps_apply(tmp_path):
    mod = _mod()
    res = _memory(_snapshot_home(tmp_path / 'home'))
    sec = res['memory_load']
    assert sec['files'] == [] and sec['snapshots']['count'] == 1  # the real producer's shape
    summary = mod.summarize(make_report({'memory_load': sec}, res['findings']))
    text = _flat(mod.render_text(summary))
    row = _section(summary, 'memory_load')
    assert row['measured'] is True and row['reason'] != mod.UNEXPECTED_SHAPE
    assert 'unexpected shape' not in text
    assert row['headline'].startswith('No memory files (MEMORY.md, USER.md) were found')
    assert row['numbers']['snapshots'] == 1  # snapshot count is kept for --json
    assert 'shipped value of 2,200' in row['headline']
    # No MEMORY.md: no step may tell the reader to copy it; the limit step still applies.
    assert not any('Copy MEMORY.md' in s for s in summary['next_steps'])
    assert mod.STEP_MEMORY_LIMIT_ONLY in summary['next_steps']
    assert all(len(line) <= mod.LINE_WIDTH for line in mod.render_text(summary).splitlines())


def test_home_without_any_memory_files_says_so(tmp_path):
    mod = _mod()
    home = tmp_path / 'home'
    home.mkdir()
    res = _memory(home)
    assert res['memory_load']['status'] == 'not_measured' and res['memory_load']['files'] == []
    summary = mod.summarize(make_report({'memory_load': res['memory_load']}, res['findings']))
    row = _section(summary, 'memory_load')
    assert row['measured'] is True
    assert row['headline'].startswith('No memory files (MEMORY.md, USER.md) were found')
    text = _flat(mod.render_text(summary))
    assert 'Not measured (not measured)' not in text and 'unexpected shape' not in text
    assert not any('Copy MEMORY.md' in s for s in summary['next_steps'])


def test_live_memory_files_keep_the_old_headline(tmp_path):
    mod = _mod()
    home = tmp_path / 'home'
    _w(home / 'memories/MEMORY.md', 'x' * 3000)
    res = _memory(home)
    summary = mod.summarize(make_report({'memory_load': res['memory_load']}, res['findings']))
    assert _section(summary, 'memory_load')['headline'].startswith('MEMORY.md: 3,000 of 2,200')
    assert mod.STEP_MEMORY in summary['next_steps']


@pytest.mark.parametrize('which', ['empty', 'snaps', 'emptymem', 'missing', 'fileroot'])
def test_no_real_shape_falls_into_unexpected_shape(tmp_path, which):
    mod = _mod()
    home = _homes(tmp_path)[which]
    sections, raw = collect(home)
    summary = mod.summarize(make_report(sections, raw))
    text = mod.render_text(summary)
    flat = _flat(text)
    for sec in summary['sections']:
        assert sec['reason'] != mod.UNEXPECTED_SHAPE, (which, sec['section'])
    assert 'unexpected shape' not in flat
    assert 'Not measured (not measured)' not in flat
    assert '[cuts 0' not in flat and ', cuts 0' not in flat
    assert not any(line.strip().endswith('()') for line in text.splitlines())
    assert all(len(line) <= mod.LINE_WIDTH for line in text.splitlines())
    if not (home / 'memories' / 'MEMORY.md').exists():
        assert not any('Copy MEMORY.md' in s for s in summary['next_steps'])


def test_section_reasons_are_plain_words(tmp_path):
    mod = _mod()
    sections, raw = collect(_homes(tmp_path)['empty'])
    text = _flat(mod.render_text(mod.summarize(make_report(sections, raw))))
    # skill_ledger reports ledger_absent, skill_packs reports missing, dead_stores empty_home.
    assert 'ledger absent' not in text and 'ledger_absent' not in text
    assert mod.reason_phrase('ledger_absent') in text
    assert mod.reason_phrase('empty_home') in text
    assert mod.reason_phrase('usage_file_missing') != 'usage file missing'


def test_partial_skill_hygiene_names_its_reason(tmp_path):
    """The skill check stores why it could not be verified (no install manifest in an empty home)."""
    mod = _mod()
    sections, raw = collect(_homes(tmp_path)['empty'])
    hygiene = sections['skill_hygiene']
    assert hygiene['coverage'] == 'could_not_verify' and hygiene['reason'] == 'missing'
    summary = mod.summarize(make_report(sections, raw))
    text = _flat(mod.render_text(summary))
    block = text.split(mod.SECTION_TITLES['skill_hygiene'], 1)[1]
    assert block.split('.', 2)[1].strip().startswith(
        f'Some parts could not be checked ({mod.reason_phrase("missing")})')


def test_partial_section_without_reason_says_the_audit_did_not_say_why():
    mod = _mod()
    summary = mod.summarize({'skill_hygiene': {'coverage': 'could_not_verify', 'skills_examined': 0,
                                               'skills': [], 'duplicate_groups': []}})
    row = next(s for s in summary['sections'] if s['section'] == 'skill_hygiene')
    assert row['partial'] is True and row['reason'] == mod.NO_REASON
    assert 'Some parts could not be checked (the audit did not say why)' in _flat(mod.render_text(summary))


def test_not_measured_without_reason_says_the_audit_did_not_say_why():
    mod = _mod()
    summary = mod.summarize({'kanban_residue': {'status': 'not_measured',
                                                'coverage': 'could_not_verify'}})
    assert 'Not measured (the audit did not say why).' in _flat(mod.render_text(summary))


def test_usage_file_missing_is_plain(tmp_path):
    mod = _mod()
    home = tmp_path / 'home'
    _w(home / 'skills/c/s/SKILL.md', '---\nname: s\ndescription: "Use when x."\n---\nb\n')
    packs = load_submodule('audit.skill_packs').audit_skill_packs(profile_path=home)
    assert packs['skill_packs']['reason'] == 'usage_file_missing'
    text = _flat(mod.render_text(mod.summarize(make_report({'skill_packs': packs['skill_packs']},
                                                           packs['findings']))))
    assert mod.reason_phrase('usage_file_missing') in text and 'usage file missing' not in text


def test_write_settings_unreadable_config_is_described(tmp_path):
    mod = _mod()
    sections, raw = collect(_homes(tmp_path)['missing'])
    summary = mod.summarize(make_report(sections, raw))
    row = _section(summary, 'write_settings')
    assert row['measured'] is True
    assert 'could not be read' in row['headline']


def test_could_not_verify_tags_say_what_was_cut():
    mod = _mod()
    rows = [{'sentence': 'S.', 'count': 1, 'evidence': [['cuts', 0]],
             'rule_id': 'memory_load.could_not_verify'},
            {'sentence': 'S.', 'count': 1, 'evidence': [['cuts', 3]],
             'rule_id': 'memory_load.could_not_verify'},
            {'sentence': 'S.', 'count': 1, 'evidence': [['hook_plugin_index', 1]],
             'rule_id': 'unattended_exposure.hook_plugin'}]
    assert mod._finding_line(rows[0]) == 'S.'
    assert mod._finding_line(rows[1]) == 'S. [3 parts skipped to stay within the audit limits]'
    assert mod._finding_line(rows[2]) == 'S.'


def test_sizes_use_decimal_units_labelled_mb():
    mod = _mod()
    assert mod.human_bytes(416_004_893) == '416.0 MB'
    assert mod.human_bytes(1500) == '1.5 KB'


def _memory_homes(base):
    nofiles = base / 'nofiles'
    nofiles.mkdir()
    emptydir = base / 'emptydir'
    (emptydir / 'memories').mkdir(parents=True)
    disabled = base / 'disabled'
    _w(disabled / 'config.yaml', 'memory:\n  memory_enabled: false\n  user_profile_enabled: false\n')
    return {'nofiles': nofiles, 'emptydir': emptydir, 'disabled': disabled,
            'archived': _snapshot_home(base / 'archived', raised=False)}


@pytest.mark.parametrize('which', ['nofiles', 'emptydir', 'disabled', 'archived'])
def test_no_live_memory_prints_one_nothing_to_measure_line(tmp_path, which):
    mod = _mod()
    sections, raw = collect(_memory_homes(tmp_path)[which])
    text = mod.render_text(mod.summarize(make_report(sections, raw)))
    lines = text.splitlines()
    i = lines.index(mod.SECTION_TITLES['memory_load'])
    assert lines[i + 1] == '  ' + mod.MEMORY_NONE_LINE  # one plain line, no wrap
    assert lines[i + 2].strip() in ('', 'For information:')
    assert 'unexpected shape' not in _flat(text)


@pytest.mark.parametrize('bad', ['garbage', {'status': 'completed'},
                                 {'status': 'completed', 'files': 'x'}])
def test_malformed_memory_section_still_says_unexpected_shape(bad):
    mod = _mod()
    summary = mod.summarize({'memory_load': bad, 'findings': []})
    assert _section(summary, 'memory_load')['reason'] == mod.UNEXPECTED_SHAPE
    assert 'unexpected shape' in _flat(mod.render_text(summary))
