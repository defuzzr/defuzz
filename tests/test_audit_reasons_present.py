"""Every memory check that could not be verified says why, in a reviewed reason code.

The memory component runs here on small synthetic homes (pytest tmp folders), with the
arguments the full audit passes (audit_surface._wired_kwargs). Whenever the section, the
envelope or a finding is not verified, the section must name at least one reason code that
is in the reviewed vocabulary, and the plain summary must show a reason instead of "the
audit did not say why". A home with nothing to measure is told so once.
"""
from __future__ import annotations

import json

import pytest

from tests.conftest import REPO_ROOT, load_submodule

AS_OF = 1794268800


def _w(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def _project(base):
    root = base / 'projects' / 'app'
    _w(root / 'pyproject.toml', '[project]\nname = "app"\n')
    _w(root / 'app.py', 'print(1)\n')
    return str(root)


def _homes(base):
    """name -> (home, project roots)."""
    no_projects = base / 'no_projects'
    _w(no_projects / 'memories' / 'MEMORY.md', 'Uses Python for scripts.\n\u00a7\nKeep replies short.')
    no_files = base / 'no_files'
    no_files.mkdir()
    disabled = base / 'disabled'
    _w(disabled / 'config.yaml', 'memory:\n  memory_enabled: false\n  user_profile_enabled: false\n')
    normal = base / 'normal'
    _w(normal / 'memories' / 'MEMORY.md', 'Uses Python for scripts.\n\u00a7\nKeep replies short.')
    _w(normal / 'memories' / 'USER.md', 'Prefers plain words.')
    missing = base / 'missing'
    bad_config = base / 'bad_config'
    _w(bad_config / 'config.yaml', 'memory:\n  memory_char_limit: 100\nmemory:\n  memory_char_limit: 200\n')
    _w(bad_config / 'memories' / 'MEMORY.md', 'Keep replies short.')
    return {'no_projects': (no_projects, []), 'no_files': (no_files, []),
            'disabled': (disabled, []), 'normal': (normal, [_project(base)]),
            'missing': (missing, []), 'bad_config': (bad_config, [_project(base)])}


def _run(home, roots):
    """The memory component with the arguments the full audit passes it."""
    surface = load_submodule('audit_surface')
    memory = load_submodule('audit.memory_load')
    exposure = load_submodule('audit.unattended_exposure').audit_unattended_exposure(profile_path=str(home))
    sections = {'unattended_exposure': exposure['unattended_exposure']}
    kwargs = surface._wired_kwargs('memory_load', str(home), as_of=AS_OF, sections=sections,
                                   project_roots=roots)
    return memory.audit_memory_load(**kwargs)


def _summary_row(result):
    from tests.test_audit_summary import make_report
    mod = load_submodule('audit_summary')
    summary = mod.summarize(make_report({'memory_load': result['memory_load']}, result['findings']))
    row = next(s for s in summary['sections'] if s['section'] == 'memory_load')
    return mod, summary, row


def _assert_sub_check_reasons(result):
    """The foreign-technology sub-check, when skipped, names its reason with a plain phrase."""
    vocabulary = load_submodule('audit.evidence').VOCABULARY
    phrases = load_submodule('audit_summary')._REASON_PHRASES
    sec = result['memory_load']
    skipped = sec['foreign_technology_coverage'] != 'verified' or any(
        r.get('foreign_technology_coverage', 'verified') != 'verified'
        for r in sec['files'] + sec['snapshots']['files'])
    reason = sec['foreign_technology_reason']
    if not skipped:
        assert reason is None, reason
        return False
    assert reason in vocabulary and reason in phrases, reason
    return True


def _assert_reasons(result):
    vocabulary = load_submodule('audit.evidence').VOCABULARY
    sec = result['memory_load']
    _assert_sub_check_reasons(result)
    unverified = (sec['coverage'] != 'verified' or result['coverage'] != 'verified'
                  or any(f['coverage'] != 'verified' for f in result['findings']))
    if not unverified:
        return False
    reasons = sec['truncated_by']
    assert reasons, 'could_not_verify without any reason code'
    assert all(isinstance(r, str) and r in vocabulary for r in reasons), reasons
    mod, summary, row = _summary_row(result)
    assert row['reason'] in vocabulary and row['reason'] != mod.NO_REASON, row
    assert mod.reason_phrase(row['reason']), row
    text = ' '.join(mod.render_text(summary).split())
    assert mod.reason_phrase(row['reason']) in text, (row['reason'], text)
    return True


@pytest.mark.parametrize('which', ['no_projects', 'no_files', 'disabled', 'normal', 'missing', 'bad_config'])
def test_every_unverified_memory_result_names_a_reviewed_reason(tmp_path, which):
    home, roots = _homes(tmp_path)[which]
    _assert_reasons(_run(home, roots))


@pytest.mark.parametrize('cap,value,reason', [('MAX_FILE_BYTES', 4, 'file_bytes'),
                                              ('MAX_FILES', 1, 'files'),
                                              ('MAX_SECONDS', 0, 'time_budget')])
def test_cut_short_scans_name_the_cut(tmp_path, monkeypatch, cap, value, reason):
    home, roots = _homes(tmp_path)['normal']
    monkeypatch.setattr(load_submodule('audit.memory_load'), cap, value)
    result = _run(home, roots)
    assert _assert_reasons(result) is True
    assert reason in result['memory_load']['truncated_by']


def test_no_registered_projects_skips_only_the_foreign_technology_check(tmp_path):
    home, roots = _homes(tmp_path)['no_projects']
    result = _run(home, roots)
    sec = result['memory_load']
    assert sec['status'] == 'completed'
    assert sec['foreign_technology_coverage'] == 'could_not_verify'
    assert sec['files'][0]['foreign_technology_entries'] is None
    assert sec['files'][0]['foreign_technology_coverage'] == 'could_not_verify'
    assert sec['coverage'] == 'verified' and result['coverage'] == 'verified'
    assert 'memory_load.could_not_verify' not in {f['id'] for f in result['findings']}


@pytest.mark.parametrize('which', ['no_files', 'disabled'])
def test_home_with_nothing_to_measure_is_told_once(tmp_path, which):
    home, roots = _homes(tmp_path)[which]
    result = _run(home, roots)
    assert result['memory_load']['status'] == 'not_measured'
    assert result['findings'] == []
    mod, summary, row = _summary_row(result)
    assert row['measured'] is True and row['partial'] is False
    text = ' '.join(mod.render_text(summary).split())
    assert text.count(mod.MEMORY_NONE_LINE) == 1
    assert 'could not be verified' not in text and 'could not be checked' not in text


def test_missing_home_is_still_not_clean(tmp_path):
    memory = load_submodule('audit.memory_load')
    result = memory.audit_memory_load(profile_path=tmp_path / 'absent', home_os='linux',
                                      project_families={}, prompt_injecting_plugins=[])
    assert result['memory_load']['coverage'] == 'could_not_verify'
    assert result['coverage'] == 'could_not_verify'
    # The existing word for a file or folder that was not found, with its plain phrase.
    assert result['memory_load']['truncated_by'] == ['missing']
    assert _assert_reasons(result) is True


def test_pending_edits_check_the_deadline_inside_one_file(tmp_path):
    """A single in-cap pending file with many operations stops at the scan deadline."""
    memory = load_submodule('audit.memory_load')
    home = tmp_path / 'home'
    _w(home / 'memories' / 'MEMORY.md', 'note one\n\u00a7\nnote two')
    ops = [{'action': 'remove', 'old_text': 'note one'} for _ in range(10000)]
    _w(home / 'pending' / 'memory' / 'a.json',
       json.dumps({'payload': {'action': 'batch', 'target': 'memory', 'operations': ops}}))
    calls = []

    def clock():
        # Each call moves time by one millisecond: the five-second budget is 5,000 calls.
        calls.append(None)
        return len(calls) / 1000

    result = memory.audit_memory_load(profile_path=home, home_os='linux', project_families={},
                                      prompt_injecting_plugins=[], memory_char_limit=2200,
                                      user_char_limit=1375, memory_provider=None, clock=clock)
    sec = result['memory_load']
    assert sec['pending']['operations'] < len(ops)
    assert sec['pending']['unverified_edits'] == 1
    assert sec['pending']['coverage'] == 'could_not_verify'
    assert 'time_budget' in sec['truncated_by'] and 'pending_shape' not in sec['truncated_by']
    assert _assert_reasons(result) is True


# Each reason word, the place it is stored and its plain phrase (the desktop page needs the same pairs).
NEW_REASONS = {
    'input_unknown': 'a setting the check needs could not be read',
    'missing': 'the file or folder it reads was not found',
    'no_projects': 'there are no projects to compare with',
}


def test_new_reason_words_are_reviewed_and_have_plain_phrases():
    vocabulary = load_submodule('audit.evidence').VOCABULARY
    summary = load_submodule('audit_summary')
    sheet = json.loads((REPO_ROOT / 'audit' / 'wiring' / 'memory_load.json').read_text(encoding='utf-8'))
    for word, phrase in NEW_REASONS.items():
        assert word in vocabulary and word in sheet['vocabulary'], word
        assert summary._REASON_PHRASES[word] == phrase, word


@pytest.mark.parametrize('kwargs', [{'home_os': None}, {'prompt_injecting_plugins': None},
                                    {'memory_provider': 42}, {'memory_char_limit': None},
                                    {'project_families': ['python']}])
def test_a_setting_that_could_not_be_read_is_named(tmp_path, kwargs):
    """Every input the check needs and could not read gives input_unknown, never a bare could_not_verify."""
    memory = load_submodule('audit.memory_load')
    home = _homes(tmp_path)['normal'][0]
    args = {'home_os': 'linux', 'project_families': {'python': 1}, 'prompt_injecting_plugins': [],
            'memory_char_limit': 2200, 'user_char_limit': 1375, 'memory_provider': None, **kwargs}
    result = memory.audit_memory_load(profile_path=home, **args)
    assert result['memory_load']['coverage'] == 'could_not_verify'
    assert 'input_unknown' in result['memory_load']['truncated_by']
    assert result['memory_load']['limits']['cuts'] == 0  # nothing was skipped for a limit
    assert _assert_reasons(result) is True


def test_unreadable_config_is_named(tmp_path):
    """config.yaml that cannot be read (chmod 000): the limits and provider are unknown."""
    import os
    if os.geteuid() == 0:
        pytest.skip('root reads any file')
    home, roots = _homes(tmp_path)['normal']
    config = _w(home / 'config.yaml', 'memory:\n  memory_char_limit: 100\n')
    config.chmod(0)
    try:
        result = _run(home, roots)
    finally:
        config.chmod(0o600)
    assert 'input_unknown' in result['memory_load']['truncated_by']
    assert _assert_reasons(result) is True


def test_no_projects_names_the_skipped_sub_check(tmp_path):
    home, roots = _homes(tmp_path)['no_projects']
    result = _run(home, roots)
    assert result['memory_load']['foreign_technology_reason'] == 'no_projects'
    assert _assert_sub_check_reasons(result) is True
    home, roots = _homes(tmp_path / 'b')['normal']
    assert _run(home, roots)['memory_load']['foreign_technology_reason'] is None


# --- every audit component: stored reason codes are reviewed words, never sealed tokens ---

# Limits lowered for the "many small files" home: entry and file counts per component.
_SMALL_LIMITS = (
    ('audit.home_workdirs', 'MAX_ENTRIES', 40), ('audit.secret_file_copies', 'MAX_ENTRIES', 40),
    ('audit.dead_stores', 'MAX_ENTRIES', 40), ('audit.profile_duplicates', 'MAX_ENTRIES', 40),
    ('audit.memory_load', 'MAX_TREE_ENTRIES', 40), ('audit.memory_load', 'MAX_FILES', 3),
    ('audit.skill_packs', 'MAX_TREE_ENTRIES', 40), ('audit.skill_hygiene', 'MAX_TREE_ENTRIES', 40),
    ('audit.skill_ledger', 'MAX_BLOB_ENTRIES', 40), ('audit.kanban_residue', 'MAX_ENTRIES', 40),
    ('audit.outward', 'MAX_TREE_ENTRIES', 40),
)


def _typical(home):
    _w(home / 'config.yaml', 'model: test\nmemory:\n  memory_char_limit: 2200\n')
    _w(home / 'memories' / 'MEMORY.md', 'Uses Python for scripts.\n\u00a7\nKeep replies short.')
    _w(home / 'memories' / 'USER.md', 'Prefers plain words.')
    _w(home / 'skills' / 'notes' / 'SKILL.md', '---\nname: notes\ndescription: Take notes.\n---\nWrite notes.\n')
    return home


def _register(home, project):
    """The plugin's project registry, as the full audit reads it."""
    import sqlite3
    registry = home / 'plugin-data' / 'defuzz' / 'state.db'
    registry.parent.mkdir(parents=True)
    conn = sqlite3.connect(registry)
    conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
    conn.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synthetic'))
    conn.commit()
    conn.close()


def _sweep_home(base, which):
    """name -> (home, project root or None, cleanup)."""
    home = base / 'home'
    project = None
    restore = []
    if which == 'empty':
        home.mkdir()
    elif which == 'typical':
        _typical(home)
    elif which == 'dependency':
        _typical(home)
        project = base / 'project'
        _w(project / 'package.json', '{"name": "app"}')
        _w(project / 'index.js', 'console.log(1)\n')
        _w(project / 'node_modules' / 'left-pad' / 'package.json', '{"name": "left-pad"}')
        _w(home / 'node_modules' / 'left-pad' / 'index.js', 'module.exports = 1\n')
        _register(home, project)
    elif which == 'unreadable':
        _typical(home)
        for rel in ('memories/MEMORY.md', 'skills/notes', 'config.yaml'):
            (home / rel).chmod(0)
            restore.append(home / rel)
    elif which == 'many_files':
        _typical(home)
        for i in range(120):
            _w(home / 'skills' / f's{i:03d}' / 'SKILL.md', f'---\nname: s{i:03d}\ndescription: d.\n---\nx\n')
            _w(home / 'cache' / f'c{i:03d}.txt', 'x')
    # 'missing': the home folder is never created.
    return home, project, restore


def _reason_key(key):
    return key in ('reason', 'reasons', 'truncated_by', 'cut_reasons', 'reason_details', 'path_withheld') \
        or key.endswith('_reason') or key.endswith('_reasons')


def _reason_problems(node, path, vocabulary, problems, codes):
    """Every value under a reason key: a reviewed word (or a {code: word} detail), never sealed."""
    if isinstance(node, dict):
        for key, item in node.items():
            here = f'{path}.{key}'
            if isinstance(key, str) and key.startswith('hmac:'):
                problems.append(f'{here}: sealed key')
            if key == 'reasons' and 'reason_details' in node and isinstance(item, list):
                # Outward-sweep region messages hold a path, so they stay sealed by design;
                # their reason codes are stored readable in reason_details[].code.
                if item and not node['reason_details']:
                    problems.append(f'{here}: sealed messages without readable reason codes')
                continue
            if isinstance(key, str) and _reason_key(key):
                for value in (item if isinstance(item, list) else [item]):
                    if isinstance(value, dict) and 'code' in value and 'hmac' not in value:
                        value = value['code']
                    if value is None:
                        continue
                    if isinstance(value, dict) and 'hmac' in value:
                        problems.append(f'{here}: sealed token')
                    elif not isinstance(value, str) or value not in vocabulary:
                        problems.append(f'{here}: {str(value)[:80]!r} is not a reviewed word')
                    else:
                        codes.add(value)
            _reason_problems(item, here, vocabulary, problems, codes)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _reason_problems(item, f'{path}[{index}]', vocabulary, problems, codes)


@pytest.mark.parametrize('which', ['empty', 'missing', 'typical', 'dependency', 'unreadable', 'many_files'])
def test_full_audit_stores_only_reviewed_reason_codes(tmp_path, monkeypatch, which):
    """The real audit entry over small synthetic homes: no stored reason code is sealed or unreviewed."""
    import os
    from tests.test_audit_wired_sections import _audit
    if which == 'unreadable' and os.geteuid() == 0:
        pytest.skip('root reads any file')
    if which == 'many_files':
        for module, name, value in _SMALL_LIMITS:
            monkeypatch.setattr(load_submodule(module), name, value)
    home, project, restore = _sweep_home(tmp_path, which)
    vocabulary = load_submodule('audit.evidence').VOCABULARY
    try:
        args = {'root': str(project)} if project else {}
        result = _audit(tmp_path, monkeypatch, home, **args)
    finally:
        for path in restore:
            path.chmod(0o700)
    problems, codes = [], set()
    _reason_problems(result, 'result', vocabulary, problems, codes)
    assert not problems, '\n'.join(problems)
    # Each home reaches the codes it was built for, stored as readable words.
    expected = {'empty': {'empty_home'}, 'missing': {'missing', 'missing_home'},
                'typical': {'default_profile_never_archived'}, 'dependency': {'skipped_folders'},
                'unreadable': {'unreadable', 'inspection_failed'},
                'many_files': {'entry_budget', 'max_blob_entries'}}[which]
    assert expected <= codes, (expected - codes, sorted(codes))
