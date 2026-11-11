"""Every reason that reaches the plain summary and the desktop page has a reviewed plain phrase.

The real audit runs over small synthetic homes (pytest tmp folders, the same homes as the
full-audit reason sweep) and over a home with lowered limits. Every section the audit stored
is in the summary, every section that could not be fully checked names a reason, and every
reason code the summary can show has a phrase in audit_summary._REASON_PHRASES and the same
phrase in the desktop page's table (desktop/plugin.js AUDIT_REASON_PHRASES).
"""
from __future__ import annotations

import os
import re

import pytest

from tests.conftest import REPO_ROOT, load_submodule
from tests.test_audit_reasons_present import _SMALL_LIMITS, _register, _sweep_home, _typical, _w

HOMES = ['empty', 'missing', 'typical', 'dependency', 'unreadable', 'many_files', 'small_reads']

# Byte, depth and time limits lowered for the 'small_reads' home.
_SMALL_READS = (
    ('audit.memory_load', 'MAX_FILE_BYTES', 4), ('audit.skill_hygiene', 'MAX_FILE_BYTES', 4),
    ('audit.skill_packs', 'MAX_FILE_BYTES', 4), ('audit.home_workdirs', 'MAX_DEPTH', 1),
    ('audit.secret_file_copies', 'MAX_DEPTH', 1), ('audit.dead_stores', 'MAX_DEPTH', 1),
    ('audit.profile_duplicates', 'MAX_DEPTH', 1), ('audit.unattended_exposure', 'MAX_TOTAL_BYTES', 4),
    ('audit.skill_ledger', 'MAX_BOOKKEEPING_BYTES', 4),
)


def _full_audit(tmp_path, monkeypatch, which):
    from tests.test_audit_wired_sections import _audit
    if which == 'unreadable' and os.geteuid() == 0:
        pytest.skip('root reads any file')
    limits = {'many_files': _SMALL_LIMITS, 'small_reads': _SMALL_READS}.get(which, ())
    for module, name, value in limits:
        monkeypatch.setattr(load_submodule(module), name, value)
    home, project, restore = _sweep_home(tmp_path, 'typical' if which == 'small_reads' else which)
    try:
        args = {'root': str(project)} if project else {}
        return _audit(tmp_path, monkeypatch, home, **args)
    finally:
        for path in restore:
            path.chmod(0o700)


def page_phrases():
    """The desktop page's reason table, read from desktop/plugin.js."""
    source = (REPO_ROOT / 'desktop' / 'plugin.js').read_text(encoding='utf-8')
    block = re.search(r'const AUDIT_REASON_PHRASES = \{\n(.*?)\n\}\n', source, re.S)
    assert block, 'AUDIT_REASON_PHRASES table not found in desktop/plugin.js'
    table = {}
    for line in block.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith('//'):
            continue
        match = re.fullmatch(r"([a-z][a-z0-9_]*): '([^'\\]*)',?", line)
        assert match, f'unexpected line in the page table: {line!r}'
        assert match.group(1) not in table, match.group(1)
        table[match.group(1)] = match.group(2)
    return table


@pytest.mark.parametrize('which', HOMES)
def test_every_reason_reaching_the_summary_has_a_reviewed_phrase(tmp_path, monkeypatch, which):
    mod = load_submodule('audit_summary')
    report = _full_audit(tmp_path, monkeypatch, which)['report']
    summary = mod.summarize(report)
    rows = {s['section']: s for s in summary['sections']}
    # A stored section is never silently absent from the summary.
    stored = {k for k, v in report.items() if isinstance(v, dict) and 'coverage' in v and k != 'headline'}
    assert stored <= set(rows), sorted(stored - set(rows))
    codes = set()
    for name, row in rows.items():
        sec = report.get(name)
        if row['partial'] or not row['measured']:
            assert row['reason'] and row['reason'] != mod.NO_REASON, (name, sec if isinstance(sec, dict) else None)
            codes.add(row['reason'])
        # Every code the reader could pick for this section, not only the first one.
        codes.update(mod.reason_candidates(name, sec, report.get('findings')))
    codes.update(m['reason'] for m in summary['not_measured'])
    table, page = mod._REASON_PHRASES, page_phrases()
    missing = sorted(c for c in codes if c not in table)
    assert not missing, f'reason codes without a reviewed phrase: {missing}'
    assert not sorted(c for c in codes if c not in page), 'the page table lacks a phrase'
    text = mod.render_text(summary)
    assert mod.reason_phrase(mod.NO_REASON) not in text, text


def test_page_and_summary_phrase_tables_match():
    mod = load_submodule('audit_summary')
    assert page_phrases() == mod._REASON_PHRASES


def test_phrases_are_plain_and_never_raw_codes():
    mod = load_submodule('audit_summary')
    for code, phrase in mod._REASON_PHRASES.items():
        assert phrase and phrase == phrase.strip() and '_' not in phrase, code
        assert not phrase.endswith('.'), code
        assert mod.reason_phrase(code) == phrase


# --- the reader accepts both declared reason shapes ---

@pytest.mark.parametrize('name,sec,expected', [
    ('dead_stores', {'status': 'completed', 'coverage': 'could_not_verify', 'reason': None,
                     'truncated_by': 'entry_budget', 'total_home_bytes': 1}, 'entry_budget'),
    ('home_workdirs', {'status': 'completed', 'coverage': 'could_not_verify', 'reason': None,
                       'truncated_by': 'scandir_error'}, 'scandir_error'),
    ('memory_load', {'status': 'completed', 'coverage': 'could_not_verify',
                     'truncated_by': ['file_bytes', 'files']}, 'file_bytes'),
    ('dead_stores', {'status': 'completed', 'coverage': 'could_not_verify', 'truncated_by': None,
                     'unverified_checks': ['config_unreadable', 'enabled_plugins']}, 'config_unreadable'),
])
def test_string_and_list_reasons_are_both_read(name, sec, expected):
    mod = load_submodule('audit_summary')
    assert mod.reason_candidates(name, sec, [])[0] == expected
    assert mod._measured_state(sec, name, []) == (True, True, expected)


def test_a_reason_stored_only_in_the_sections_own_finding_is_shown():
    mod = load_submodule('audit_summary')
    report = {'unattended_exposure': {'status': 'completed', 'reason': None, 'coverage': 'could_not_verify',
                                      'truncated_by': None, 'settings': {}},
              'findings': [{'id': 'unattended_exposure.could_not_verify', 'classification': 'info',
                            'coverage': 'could_not_verify', 'consequence': 'x',
                            'evidence': {'cuts': 1, 'reason': 'config_unreadable'}}]}
    row = next(s for s in mod.summarize(report)['sections'] if s['section'] == 'unattended_exposure')
    assert row['partial'] is True and row['reason'] == 'config_unreadable'


def test_context_load_names_the_part_that_could_not_be_measured():
    mod = load_submodule('audit_summary')
    sec = {'coverage': 'could_not_verify',
           'profile': {'coverage': 'could_not_verify', 'sources': [
               {'source': 'identity_soul', 'coverage': 'verified'},
               {'source': 'enabled_memory_files', 'coverage': 'could_not_verify'}]}}
    assert mod.reason_candidates('context_load', sec, [])[0] == 'enabled_memory_files'


# --- stored sections outside the fixed order are shown, not dropped ---

def test_sections_outside_the_fixed_order_are_shown_with_status_and_reason():
    mod = load_submodule('audit_summary')
    report = {'scope': {'coverage': 'could_not_verify', 'description': 'd',
                        'regions': {'project_tree': {'coverage': 'could_not_verify',
                                                     'reason_details': [{'code': 'skipped_folders'}]}}},
              'future_check': {'status': 'not_measured', 'coverage': 'could_not_verify', 'reason': 'missing'},
              'headline': {'coverage': 'could_not_verify'},
              'findings': [{'id': 'static_code.unmappable_import', 'classification': 'info',
                            'coverage': 'could_not_verify', 'consequence': 'An import was not mapped.'},
                           {'id': 'template_drift.changed', 'classification': 'review_suggested',
                            'coverage': 'verified', 'consequence': 'A template file changed.'}]}
    summary = mod.summarize(report)
    rows = {s['section']: s for s in summary['sections']}
    names = [s['section'] for s in summary['sections']]
    assert names[:len(mod.SECTION_ORDER)] == list(mod.SECTION_ORDER)
    assert {'scope', 'future_check', 'static_code', 'template_drift'} <= set(rows)
    assert 'headline' not in rows
    assert rows['scope']['partial'] is True and rows['scope']['reason'] == 'skipped_folders'
    assert rows['future_check']['measured'] is False and rows['future_check']['reason'] == 'missing'
    assert rows['static_code']['partial'] is True and rows['static_code']['coverage'] == 'could_not_verify'
    assert rows['template_drift']['partial'] is False
    text = mod.render_text(summary)
    for title in (rows[n]['title'] for n in ('scope', 'future_check', 'static_code', 'template_drift')):
        assert title in text
    assert 'An import was not mapped.' in text and 'A template file changed.' in text
    assert mod.reason_phrase('missing') in text


def test_rows_without_a_coverage_word_are_not_presented_as_verified():
    mod = load_submodule('audit_summary')
    summary = mod.summarize({'skill_hygiene': {'skills_examined': 1, 'skills': []},
                             'findings': [{'id': 'other_check.thing', 'classification': 'info',
                                           'consequence': 'A thing.'}]})
    rows = {s['section']: s for s in summary['sections']}
    assert rows['skill_hygiene']['coverage'] is None and rows['skill_hygiene']['partial'] is True
    assert rows['other_check']['coverage'] is None and rows['other_check']['partial'] is True


# --- an unreadable project list is not "no projects" ---

def _memory_section(tmp_path, monkeypatch, home):
    from tests.test_audit_wired_sections import _audit
    return _audit(tmp_path, monkeypatch, home)['report']['memory_load']


def test_no_registered_projects_is_no_projects(tmp_path, monkeypatch):
    home = _typical(tmp_path / 'home')
    sec = _memory_section(tmp_path, monkeypatch, home)
    assert sec['foreign_technology_reason'] == 'no_projects'
    assert sec['coverage'] == 'verified'


def test_a_project_that_could_not_be_read_is_not_no_projects(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip('root reads any folder')
    home = _typical(tmp_path / 'home')
    project = tmp_path / 'project'
    _w(project / 'app.py', 'print(1)\n')
    _register(home, project)
    project.chmod(0)
    try:
        sec = _memory_section(tmp_path, monkeypatch, home)
    finally:
        project.chmod(0o700)
    assert sec['foreign_technology_reason'] == 'input_unknown'
    assert sec['foreign_technology_coverage'] == 'could_not_verify'
    assert 'input_unknown' in sec['truncated_by']


def test_project_families_tells_unread_from_none():
    surface = load_submodule('audit_surface')
    assert surface._project_families([]) is None
    assert surface._project_families(['relative/path']) is False


def test_a_readable_project_without_known_technology_is_no_projects(tmp_path):
    """Read in full but nothing to compare with: still no_projects, never input_unknown."""
    surface = load_submodule('audit_surface')
    project = tmp_path / 'notes'
    _w(project / 'README.txt', 'notes\n')
    assert surface._project_families([str(project)]) is None
    _w(tmp_path / 'app' / 'app.py', 'print(1)\n')
    assert surface._project_families([str(project), str(tmp_path / 'app')]) == {'python': 1}
