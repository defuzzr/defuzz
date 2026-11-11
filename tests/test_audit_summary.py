"""Tests for audit_summary: the plain-language summary of a sealed audit report.

Section dicts and findings come from the real section modules run on synthetic homes; findings
pass through persistence.finding_dto so they have the stored report shape.
"""
from __future__ import annotations

import argparse
import json
import os
import re

import pytest

from tests.conftest import load_submodule
from tests.test_audit_context_load import _make_base_fixture
from tests.test_audit_kanban_residue import BASE, DAY, board, run as kanban_run, task

FORBIDDEN = ('you', 'your', 'misconfigured', 'wrong', 'bad', 'bloat', 'mess', 'should have',
             'failed to')
FORBIDDEN_RE = re.compile(r'\b(' + '|'.join(re.escape(w) for w in FORBIDDEN) + r')\b', re.IGNORECASE)
MIB = 1024 * 1024
NEW_SECTIONS = ('home_workdirs', 'secret_file_copies', 'dead_stores', 'profile_duplicates',
                'skill_ledger', 'skill_packs', 'unattended_exposure', 'memory_load', 'kanban_residue')


def _mod():
    return load_submodule('audit_summary')


def _w(path, data='x'):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding='utf-8')
    else:
        path.write_bytes(data)
    return path


def _sparse(path, size, head=b''):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as fh:
        fh.write(head)
        fh.truncate(size)


def build_home(home):
    """A synthetic home that triggers findings in most sections."""
    _w(home / 'config.yaml', "approvals:\n  mode: 'off'\nterminal:\n  backend: local\n")
    _w(home / 'SOUL.md', 'You are Hermes.\n')
    entries = ['2026-01-0%d entry number %d about things' % (i, i) for i in range(1, 9)] * 12
    _w(home / 'memories/MEMORY.md', '\n§\n'.join(entries))
    _w(home / 'memories/USER.md', 'Likes tea.')
    for i in range(3):
        _w(home / 'skills' / f'cat/s{i}' / 'SKILL.md',
           f'---\nname: s{i}\ndescription: "Use when testing {i}."\n---\nbody\n')
    _sparse(home / 'side-project/data.bin', 120 * MIB)
    _w(home / 'side-project/.env', b'secret')
    _sparse(home / 'profile-exports/p-20261001.tar.gz', 60 * MIB)
    for name in ('qa1', 'qa2', 'qa3'):
        profile = home / 'profiles' / name
        _w(profile / 'config.yaml', f'profile: {name}\n')
        _sparse(profile / 'bin/tool', 11 * MIB, head=b'\x7fELF')
    conn = board(home / 'kanban.db')
    for n in range(1, 6):
        task(conn, n)
    for n in range(1, 5):
        kanban_run(conn, 't_00000001', n, BASE + n * DAY, summary='b' * 5000, error='c' * 6000)
    conn.commit()
    conn.close()
    return home


def collect(home):
    """Run the real section modules on `home`; return ({section: dict}, raw findings)."""
    m = lambda name: load_submodule('audit.' + name)  # noqa: E731
    results = {
        'home_workdirs': m('home_workdirs').audit_home_workdirs(profile_path=home),
        'secret_file_copies': m('secret_file_copies').audit_secret_file_copies(profile_path=home),
        'dead_stores': m('dead_stores').audit_dead_stores(home),
        'profile_duplicates': m('profile_duplicates').audit_profile_duplicates(home),
        'skill_ledger': m('skill_ledger').audit_skill_ledger(profile_path=home),
        'skill_packs': m('skill_packs').audit_skill_packs(profile_path=home),
        'unattended_exposure': m('unattended_exposure').audit_unattended_exposure(profile_path=home),
        'memory_load': m('memory_load').audit_memory_load(
            profile_path=home, home_os='linux', project_families={}, prompt_injecting_plugins=[]),
        'kanban_residue': m('kanban_residue').audit_kanban_residue(profile_path=home),
        'skill_hygiene': m('skill_hygiene').audit_skill_hygiene(profile_path=home),
        'session_contamination': m('session_contamination').audit_session_contamination(
            profile_path=home, sessions=False),
    }
    results['write_settings'] = m('write_settings').audit_write_settings(
        profile_path=home, hygiene=results['skill_hygiene']['skill_hygiene'])
    ctx_section, ctx_findings = m('context_load').evaluate_context_load(
        _make_base_fixture(persona_tokens=2500, persona_injected_chars=10000))
    results['context_load'] = {'context_load': ctx_section, 'findings': ctx_findings}
    sections = {name: res[name] for name, res in results.items()}
    findings = [f for res in results.values() for f in res.get('findings', [])]
    return sections, findings


def _wired_consequences():
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'audit', 'wiring')
    out = {}
    for name in NEW_SECTIONS:
        with open(os.path.join(root, name + '.json'), encoding='utf-8') as fh:
            out.update(json.load(fh)['consequences'])
    return out


def make_report(sections, raw_findings, extra_findings=()):
    """Report-like dict: sections at the top level, findings in the stored finding_dto shape.

    Until the nine new sections are wired into persistence, finding_dto seals their rule ids
    and stores the default sentence. Here the id, the fixed wiring sentence and the numeric
    evidence are put back, which is the stored shape once wiring lands.
    """
    persistence = load_submodule('audit.persistence')
    contract = load_submodule('audit.contract')
    wired = _wired_consequences()
    findings = []
    for raw in raw_findings:
        dto = persistence.finding_dto(raw)
        rule_id = raw.get('id')
        if rule_id in wired:
            assert raw['consequence'] == wired[rule_id]
            dto['id'] = rule_id
            dto['consequence'] = dto['detail'] = wired[rule_id]
            for key, value in (raw.get('evidence') or {}).items():
                if type(value) in (int, float):
                    dto['evidence'][key] = value
        findings.append(dto)
    report = {'contract_version': 'test', 'as_of': 1794268800, 'mode': 'live',
              'findings': contract.sort_findings(findings) + list(extra_findings)}
    report.update(sections)
    return report


@pytest.fixture
def full(tmp_path):
    home = build_home(tmp_path / 'home')
    sections, raw = collect(home)
    report = make_report(sections, raw)
    mod = _mod()
    summary = mod.summarize(report, home=str(home))
    return {'home': home, 'sections': sections, 'report': report, 'summary': summary,
            'text': mod.render_text(summary)}


def _flat(text):
    return ' '.join(text.split())


def _blocks(text):
    """Section title -> that section's block text (flattened)."""
    mod = _mod()
    out, current = {}, None
    titles = set(mod.SECTION_TITLES.values())
    for line in text.splitlines():
        if line in titles:
            current = line
            out[current] = ''
        elif current is not None:
            out[current] += ' ' + line.strip()
    return out


def test_small_report_shows_every_sentence_verbatim(tmp_path):
    mod = _mod()
    home = build_home(tmp_path / 'home')
    sections, raw = collect(home)
    keep = ('unattended_exposure', 'secret_file_copies', 'memory_load', 'kanban_residue', 'dead_stores',
            'profile_duplicates')
    report = make_report({k: sections[k] for k in keep},
                         [f for f in raw if f['id'].split('.')[0] in keep])
    text = mod.render_text(mod.summarize(report, home=str(home)))
    assert len(text.splitlines()) <= mod.MAX_LINES and 'full text in --json).' not in text
    assert len(report['findings']) >= 6
    for f in report['findings']:
        assert _flat(f['consequence']) in _flat(text), f['id']
    blocks = _blocks(text)
    for f in report['findings']:  # each sentence sits in its own section block, under its label
        block = blocks[mod.SECTION_TITLES[f['id'].split('.')[0]]]
        assert mod.CLASS_LABELS[f['classification']] + ':' in block
        assert _flat(f['consequence']) in _flat(block)


def _sentences(report):
    return sorted({f['consequence'] for f in report['findings']}, key=len, reverse=True)


def test_every_title_and_one_block_per_section(full):
    mod = _mod()
    assert len(mod.SECTION_ORDER) == 13 and set(mod.SECTION_ORDER) == set(mod.SECTION_TITLES)
    lines = full['text'].splitlines()
    for name in mod.SECTION_ORDER:
        assert lines.count(mod.SECTION_TITLES[name]) == 1
    order = [lines.index(mod.SECTION_TITLES[n]) for n in mod.SECTION_ORDER]
    assert order == sorted(order)
    assert full['text'].startswith(mod.HEADER_TITLE + '\n')


def test_headline_numbers_equal_section_numbers(full):
    mod = _mod()
    s, text, by = full['sections'], _flat(full['text']), {x['section']: x for x in full['summary']['sections']}
    mem = next(r for r in s['memory_load']['files'] if r['kind'] == 'memory')
    assert by['memory_load']['numbers']['memory'] == {'characters': mem['characters'],
                                                       'char_limit': mem['char_limit']}
    assert f'MEMORY.md: {mem["characters"]:,} of {mem["char_limit"]:,} characters' in text
    assert by['dead_stores']['numbers']['total_dead_weight_bytes'] == s['dead_stores']['total_dead_weight_bytes']
    assert mod.human_bytes(s['dead_stores']['total_dead_weight_bytes']) in by['dead_stores']['headline']
    assert by['profile_duplicates']['numbers']['profile_count'] == s['profile_duplicates']['profile_count'] == 3
    assert by['profile_duplicates']['numbers']['total_wasted_bytes'] == s['profile_duplicates']['total_wasted_bytes']
    assert '3 profiles; ' + mod.human_bytes(s['profile_duplicates']['total_wasted_bytes']) in text
    count = s['secret_file_copies']['secret_named_files']['count']
    assert by['secret_file_copies']['numbers']['secret_named_files'] == count
    assert f'{count} secret-named file' in text
    idx = s['skill_packs']['index']
    assert f'{idx["loadable_skills"]} skills listed; the skill list adds {idx["index_chars"]:,} characters' in text
    assert by['unattended_exposure']['numbers']['approval_settings_without_prompt'] == ['approvals.mode']
    assert 'without a prompt: 1 of 4 (approvals.mode)' in text
    b = s['kanban_residue']['boards'][0]
    assert by['kanban_residue']['numbers']['tasks'] == b['tasks'] == 5
    assert f'{b["retry_context"]["latest_worker_chars"]["max"]:,} characters' in text
    t = s['home_workdirs']['totals']
    assert by['home_workdirs']['numbers']['not_hermes_bytes'] == t['not_hermes_bytes']
    assert mod.human_bytes(t['not_hermes_bytes']) + ' of ' + mod.human_bytes(t['total_home_bytes']) in text
    assert f'about {s["context_load"]["per_turn_total"]["estimated_tokens"]:,} tokens' in text
    # Session history was not opted in: reported as not measured with the section's own token.
    assert by['session_contamination']['measured'] is False
    assert by['session_contamination']['reason'] == 'not_run'


def test_each_finding_sentence_verbatim_and_grouped(full):
    mod = _mod()
    text = _flat(full['text'])
    shown = {(r['rule_id'], r['sentence']) for sec in full['summary']['sections']
             for rows in sec['findings'].values() for r in rows}
    blocks = _blocks(full['text'])
    for f in full['report']['findings']:
        assert (f['id'], f['consequence']) in shown
        block = blocks[mod.SECTION_TITLES[f['id'].split('.')[0]]]
        if _flat(f['consequence']) not in text:  # shortened to a count to fit the line budget
            assert f['classification'] != 'warning'
            assert re.search(mod.CLASS_LABELS[f['classification']] + r': \d+ notes? \(full text in --json\)\.',
                             block), f['id']
    # Warnings and the first sections' sentences are always shown in full.
    for f in full['report']['findings']:
        if f['classification'] == 'warning' or f['id'].split('.')[0] in mod.SECTION_ORDER[:2]:
            assert _flat(f['consequence']) in text
    sec_line = full['text'].splitlines()
    assert '  Warning:' in sec_line and '  Review suggested:' in sec_line
    for rows in (r for s in full['summary']['sections'] for r in s['findings'].values()):
        for row in rows:
            assert len(row['evidence']) <= 3
    assert any(r['rule_id'].startswith(n) for n in NEW_SECTIONS
               for s in full['summary']['sections'] for rows in s['findings'].values() for r in rows)
    counts = full['summary']['counts']
    for cls in mod.CLASS_ORDER:
        assert counts[cls] == sum(1 for f in full['report']['findings'] if f['classification'] == cls)


def test_forbidden_words_never_in_own_text(full):
    mod = _mod()
    rest = _flat(full['text'])
    for sentence in _sentences(full['report']):  # the report's fixed sentences are never reworded
        rest = rest.replace(_flat(sentence), ' ')
    assert not FORBIDDEN_RE.search(rest), FORBIDDEN_RE.search(rest)
    own = [v for k, v in vars(mod).items() if k.isupper() and isinstance(v, str)]
    own += list(mod.SECTION_TITLES.values()) + list(mod.CLASS_LABELS.values())
    for value in own:
        assert not FORBIDDEN_RE.search(value), value


def test_no_home_path_no_tokens_width_length_and_determinism(full):
    mod = _mod()
    text = full['text']
    assert str(full['home']) not in text and str(full['home'].parent) not in text
    assert 'hmac' not in text.lower() and not re.search(r'[0-9a-f]{32,}', text)
    assert all(len(line) <= mod.LINE_WIDTH for line in text.splitlines())
    assert len(text.splitlines()) <= mod.MAX_LINES
    again = mod.summarize(json.loads(json.dumps(full['report'], default=str)), home=str(full['home']))
    assert again == full['summary']
    assert mod.render_text(again) == text
    json.dumps(full['summary'])  # JSON-safe, exact numbers kept
    assert '\x1b[' not in text


def test_top_block_and_footer(full):
    mod = _mod()
    text, summary = full['text'], full['summary']
    assert 'Findings: ' in text and 'Biggest items:' in text
    biggest = summary['biggest_items']
    assert 1 <= len(biggest) <= 3
    assert [b['value'] for b in biggest] == sorted((b['value'] for b in biggest), reverse=True)
    assert biggest[0]['value'] >= 120 * MIB  # the 120 MiB work folder
    assert any(b['path'] == 'side-project' for b in biggest)
    assert ('Not measured this time: ' + mod.SECTION_TITLES['session_contamination']
            + ' (not run this time)') in _flat(text)
    assert '(not_run)' not in text
    assert mod.FOOTER_INTRO in _flat(text) and text.rstrip().endswith(mod.FOOTER_CLOSE)
    steps = summary['next_steps']
    assert len(steps) == 3 and steps[0] == mod.STEP_APPROVAL
    assert mod.STEP_NOTHING not in steps
    assert sum(1 for line in text.splitlines() if 'reasonable on the day' in line) == 1


def test_memory_step_and_nothing_today_rules(tmp_path):
    mod = _mod()
    mem = load_submodule('audit.memory_load')
    home = tmp_path / 'home'
    _w(home / 'memories/MEMORY.md', 'x' * 3000)
    res = mem.audit_memory_load(profile_path=home, home_os='linux', project_families={},
                                prompt_injecting_plugins=[])
    report = make_report({'memory_load': res['memory_load']}, res['findings'])
    assert mod.STEP_MEMORY in mod.summarize(report)['next_steps']
    # Zero findings: the footer says nothing needs action today.
    empty = mod.render_text(mod.summarize({'memory_load': res['memory_load'], 'findings': []}))
    assert mod.STEP_NOTHING in empty and '1. ' + mod.STEP_NOTHING in empty
    assert 'Findings: 0 warnings, 0 review suggested, 0 for information.' in empty


@pytest.mark.parametrize('report', [
    None, 'garbage', 42, [], {}, {'findings': 'nope'},
    {'findings': [None, 1, {'id': 5}, {'id': 'memory_load.x', 'classification': 'warning',
                                       'consequence': None, 'evidence': 'bad-shape'}]},
    {name: 'garbage' for name in ('memory_load', 'dead_stores', 'skill_packs')},
    {name: {'status': 'completed', 'files': 'x', 'index': [], 'boards': {}, 'settings': 3,
            'totals': None, 'overall': 'x', 'per_turn_total': 1}
     for name in ('memory_load', 'skill_packs', 'kanban_residue', 'unattended_exposure',
                  'home_workdirs', 'session_contamination', 'context_load')},
])
def test_garbage_never_raises_and_says_not_measured(report):
    mod = _mod()
    summary = mod.summarize(report, home='/home/user/.hermes')
    text = mod.render_text(summary)
    assert 'Not measured (' in text
    for name in mod.SECTION_ORDER:
        assert mod.SECTION_TITLES[name] in text
    assert all(len(line) <= mod.LINE_WIDTH for line in text.splitlines())
    assert mod.render_text(None) == mod.render_text(mod.summarize({}))


def test_reason_tokens_for_not_collected_sections():
    mod = _mod()
    ctx = load_submodule('audit.context_load')
    report = {
        'context_load': ctx.unverified_context_load('bounded_quick_audit_not_collected'),
        'dead_stores': {'status': 'not_measured', 'coverage': 'could_not_verify',
                        'reason': 'profile_missing'},
        'skill_packs': {'status': 'not_measured', 'reason': 'Not A Token /home/user/x'},
        'session_contamination': {'coverage': 'not_included', 'status': 'not_run'},
        'findings': [],
    }
    by = {s['section']: s for s in mod.summarize(report)['sections']}
    assert by['context_load']['reason'] == 'bounded_quick_audit_not_collected'
    assert by['dead_stores']['reason'] == 'profile_missing'
    # Non-token reason text is never echoed; a bare 'not_measured' status gives no reason.
    assert by['skill_packs']['reason'] == mod.NO_REASON
    assert by['home_workdirs']['reason'] == mod.NOT_IN_REPORT
    text = mod.render_text(mod.summarize(report))
    assert 'Not measured (the profile folder was not found).' in text and '/home/user' not in text
    assert 'Not measured (not included in a quick audit).' in text
    assert 'bounded_quick_audit_not_collected' not in text and '(not_in_report)' not in text
    assert mod.STEP_SESSIONS in mod.summarize(report)['next_steps']


def test_paths_relative_and_credential_or_sealed_paths_withheld():
    mod = _mod()
    home = '/home/user/.hermes'
    assert mod.relative_path('/home/user/.hermes/plans/a', home) == 'plans/a'
    assert mod.relative_path('/home/user/.hermes', home) == '.'
    assert mod.relative_path('/home/user/.hermes-other/x', home) is None
    assert mod.relative_path('/home/x/elsewhere', home) is None
    assert mod.relative_path('/home/user/.hermes/work/auth.json', home) is None
    assert mod.relative_path('/home/user/.hermes/a/../b', home) is None
    assert mod.relative_path({'kind': 'path', 'hmac': 'a' * 64}, home) is None
    assert mod.relative_path('/home/user/.hermes/x', None) is None
    sealed = {'kind': 'path', 'hmac': 'f' * 64, 'location': 'hmac:' + 'e' * 64}
    report = {'home_workdirs': {
        'status': 'completed', 'coverage': 'verified',
        'totals': {'not_hermes_bytes': 5 * MIB, 'total_home_bytes': 10 * MIB, 'not_hermes_share': 0.5},
        'huge_files': [{'path': sealed, 'size_bytes': 4 * MIB},
                       {'path': '/home/user/.hermes/plans/secret-token.json', 'size_bytes': 3 * MIB}],
        'not_hermes_folders': [{'path': '/home/user/.hermes/plans', 'size_bytes': 5 * MIB}],
        'thresholds': {'huge_file_bytes': 50 * MIB}}, 'findings': []}
    text = mod.render_text(mod.summarize(report, home=home))
    assert '(plans)' in text and 'secret-token' not in text
    assert 'hmac' not in text and '/home/user' not in text and 'f' * 32 not in text


def test_human_bytes():
    mod = _mod()
    assert mod.human_bytes(0) == '0 bytes'
    assert mod.human_bytes(1) == '1 byte'
    assert mod.human_bytes(1536) == '1.5 KB'
    assert mod.human_bytes(3 * MIB) == '3.1 MB'  # decimal units: 3,145,728 bytes
    assert mod.human_bytes(3_000_000) == '3.0 MB'
    assert mod.human_bytes(5 * 10**9) == '5.0 GB'
    assert mod.human_bytes(None) == 'not known' and mod.human_bytes(True) == 'not known'


def test_long_reports_collapse_info_before_review_and_keep_warnings():
    mod = _mod()
    long = 'Measured sentence number {} ' + 'with many plain words ' * 20
    findings = [{'id': f'dead_stores.rule_{i:02d}', 'classification': 'info', 'coverage': 'verified',
                 'consequence': long.format(i), 'evidence': {'count': i}} for i in range(40)]
    findings.append({'id': 'unattended_exposure.command_approval_off', 'classification': 'warning',
                     'coverage': 'verified', 'consequence': 'Fixed warning sentence.', 'evidence': {}})
    text = mod.render_text(mod.summarize({'findings': findings}))
    assert len(text.splitlines()) <= mod.MAX_LINES
    assert 'For information: 40 notes (full text in --json).' in text
    assert 'Fixed warning sentence.' in text


def _cli(monkeypatch, result):
    cli = load_submodule('cli')
    surface = load_submodule('audit_surface')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    monkeypatch.setattr(surface, 'execute_audit', lambda args, **kw: result)
    return cli, parser


def test_cli_summary_flag_prints_summary_and_default_stays_json(full, monkeypatch, capsys):
    mod = _mod()
    result = {'run_id': 'r1', 'status': 'completed', 'report': full['report']}
    cli, parser = _cli(monkeypatch, result)
    monkeypatch.setattr(cli, '_audit_home', lambda: str(full['home']))
    assert cli.handle_defuzz_cli(parser.parse_args(['audit', '--summary'])) == 0
    out = capsys.readouterr().out
    assert out == mod.render_text(mod.summarize(full['report'], home=str(full['home'])))
    assert str(full['home']) not in out
    assert cli.handle_defuzz_cli(parser.parse_args(['audit'])) == 0
    assert json.loads(capsys.readouterr().out)['run_id'] == 'r1'
    assert cli.handle_defuzz_cli(parser.parse_args(['audit', '--json'])) == 0
    assert json.loads(capsys.readouterr().out)['run_id'] == 'r1'
    assert parser.parse_args(['audit', 'report', '--run-id', 'r1', '--summary']).summary is True


def test_cli_summary_without_report_falls_back_to_json(monkeypatch, capsys):
    cli, parser = _cli(monkeypatch, {'run_id': 'r2', 'status': 'running'})
    assert cli.handle_defuzz_cli(parser.parse_args(['audit', 'status', '--summary'])) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'running'


def test_pure_module_has_no_io_imports():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'audit_summary.py')
    with open(path, encoding='utf-8') as fh:
        source = fh.read()
    for banned in ('import os', 'import time', 'open(', 'subprocess', 'pathlib', 'datetime.now',
                   'time.time', 'print('):
        assert banned not in source, banned


def test_stored_findings_keep_rule_ids_and_sit_under_their_sections(tmp_path):
    """The stored finding shape (finding_dto) keeps wired rule ids; the summary places them."""
    mod = _mod()
    persistence = load_submodule('audit.persistence')
    home = build_home(tmp_path / 'home')
    sections, raw = collect(home)
    report = dict(sections, findings=[persistence.finding_dto(f) for f in raw])
    report = json.loads(json.dumps(report, default=lambda o: dict(o) if hasattr(o, 'keys') else str(o)))
    summary = mod.summarize(report, home=str(home))
    text = mod.render_text(summary)
    assert sum(summary['counts'].values()) == len(raw)
    assert summary['other_findings'] == 0
    assert 'hmac' not in text.lower() and not re.search(r'[0-9a-f]{32,}', text)
    assert str(home) not in text


@pytest.mark.parametrize('raised', [True, False])
def test_memory_limit_raised_sentence_and_step(tmp_path, raised):
    mod = _mod()
    mem = load_submodule('audit.memory_load')
    home = tmp_path / 'home'
    _w(home / 'memories/MEMORY.md', 'x' * 9995)
    _w(home / 'config.yaml', 'memory:\n  memory_char_limit: %d\n' % (10000 if raised else 2200))
    res = mem.audit_memory_load(profile_path=home, home_os='linux', project_families={},
                                prompt_injecting_plugins=[])
    summary = mod.summarize(make_report({'memory_load': res['memory_load']}, res['findings']))
    sec = next(s for s in summary['sections'] if s['section'] == 'memory_load')
    text = _flat(mod.render_text(summary))
    extra = ' The limit is 4.5 times the shipped value of 2,200.'
    if raised:
        assert sec['headline'].startswith('MEMORY.md: 9,995 of 10,000 characters (100%).' + extra)
        assert mod.STEP_MEMORY_LIMIT in summary['next_steps']
        assert mod.STEP_MEMORY_LIMIT in text and extra.strip() in text
        assert sec['numbers']['shipped_char_limits'] == {'memory': 2200, 'user': 1375}
    else:
        assert 'shipped value' not in sec['headline'] and 'shipped value' not in text
        assert mod.STEP_MEMORY_LIMIT not in summary['next_steps']
        assert mod.STEP_MEMORY in summary['next_steps']
    assert not FORBIDDEN_RE.search(mod.STEP_MEMORY_LIMIT)
    assert all(len(line) <= mod.LINE_WIDTH for line in mod.render_text(summary).splitlines())


def test_write_settings_headline_when_tool_selection_is_unknown():
    """Real homes often give unattended_* = null; the headline then shows the settings read."""
    mod = _mod()
    report = {'write_settings': {
        'coverage': 'could_not_verify', 'unattended_skill_writes': None, 'unattended_memory_writes': None,
        'settings': {'memory.write_approval': {'value': False, 'source': 'default'},
                     'skills.write_approval': {'value': True, 'source': 'config'}}},
        'kanban_residue': {'status': 'not_present', 'coverage': 'verified'}, 'findings': []}
    summary = mod.summarize(report)
    text = mod.render_text(summary)
    by = {s['section']: s for s in summary['sections']}
    assert by['write_settings']['measured'] is True
    assert by['write_settings']['numbers']['memory_write_approval'] is False
    assert 'Approval before memory edits is on: no. Approval before skill edits is on: yes.' in ' '.join(text.split())
    assert 'unexpected_shape' not in text
    assert 'Not present in this home: Leftover task board data.' in ' '.join(text.split())
    assert 'Nothing of this kind was found in this home.' in text


# ---------------------------------------------------------------- final-review findings

def _step_constants(mod):
    return {k: v for k, v in vars(mod).items() if k.startswith(('STEP_', 'FOOTER_'))
            and isinstance(v, str)}


def test_next_steps_never_say_delete_first_and_never_address_the_reader():
    mod = _mod()
    steps = _step_constants(mod)
    assert len([k for k in steps if k.startswith('STEP_')]) >= 15
    for name, text in steps.items():
        assert not re.search(r'\b(you|your)\b', text, re.IGNORECASE), name
        if re.search(r'\bremove\b', text, re.IGNORECASE):  # removing entries: back up first
            assert 'backup folder' in text.split('remove')[0], name
        for sentence in re.split(r'(?<=[.!?])\s+', text):
            if re.search(r'\bdelet', sentence, re.IGNORECASE):
                # Deleting is never the first action: it comes after a safe step, and later.
                assert re.search(r'\blater\b', sentence, re.IGNORECASE), (name, sentence)
                assert not re.match(r'\W*(delete|or delete)', sentence, re.IGNORECASE), (name, sentence)
                assert not re.search(r'\bor delete\b', text, re.IGNORECASE), name
        assert len(re.findall(r'[.!?](\s|$)', text)) <= 2, name
    assert 'outside the Hermes home' in mod.STEP_SECRETS and 'change any key' in mod.STEP_SECRETS
    for name in ('STEP_DEAD', 'STEP_PROFILES'):
        assert 'backup folder outside the Hermes home' in steps[name], name


_HOSTILE = ('A\x1b[31mred\x1b[0m\x07bell \x1b]8;;http://evil.example/\x07link\x1b]8;;\x07 '
            'two\nlines \u202egnp.exe\x00nul\x9bc1 \u2028ls\u2066iso\u2069')
_FORBIDDEN_CP = re.compile('[\x00-\x09\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u2028\u2029]')


def test_safe_text_escapes_controls_and_keeps_visible_text():
    mod = _mod()
    out = mod.safe_text(_HOSTILE)
    assert not _FORBIDDEN_CP.search(out) and '\n' not in out
    for visible in ('red', 'bell', 'link', 'two', 'lines', 'gnp.exe', 'nul', 'iso'):
        assert visible in out
    assert '\\x1b' in out and '\\x07' in out and '\\x00' in out and '\\u202e' in out
    assert mod.safe_text(out) == out  # idempotent
    assert mod.safe_text(None) == '' and mod.safe_text(5) == '5'


def test_report_control_characters_never_reach_the_terminal():
    mod = _mod()
    home = '/home/user/.hermes'
    bad_path = home + '/work\x1b[31m\x07\u202edir\nx\x00'
    report = {
        'home_workdirs': {
            'status': 'completed', 'coverage': 'partial', 'reason': 'odd',
            'totals': {'not_hermes_bytes': 5 * MIB, 'total_home_bytes': 10 * MIB},
            'huge_files': [], 'not_hermes_folders': [{'path': bad_path, 'size_bytes': 5 * MIB}],
            'thresholds': {'huge_file_bytes': 50 * MIB}},
        'findings': [{'id': 'dead_stores.hostile', 'classification': 'warning',
                      'consequence': _HOSTILE, 'evidence': {'odd\x1b[2Jkey_count': 3}}],
    }
    summary = mod.summarize(report, home=home)
    text = mod.render_text(summary)
    body = text[:-1]  # the one trailing newline after the last line
    assert not _FORBIDDEN_CP.search(body.replace('\n', '')), _FORBIDDEN_CP.search(body.replace('\n', ''))
    for visible in ('red', 'bell', 'link', 'gnp.exe', 'nul', 'iso', 'work'):
        assert visible in text, visible
    # A hostile summary dict (not from summarize) is escaped too.
    forged = dict(summary)
    forged['sections'] = [dict(s, title='T\x1b]0;x\x07', headline='H\x1b[1m', reason='r\x1b',
                               measured=True, partial=True) for s in summary['sections']]
    forged['not_measured'] = [{'section': 's', 'title': 'N\x1b[5m', 'reason': 'q\x1b'}]
    forged['next_steps'] = ['S\x1b[31m\u202e']
    forged['biggest_items'] = [{'label': 'L\x1b', 'value': 1, 'unit': 'bytes', 'path': 'p\x1b\x07'}]
    out = mod.render_text(forged)
    assert not _FORBIDDEN_CP.search(out.replace('\n', ''))
    assert all(len(line) <= mod.LINE_WIDTH for line in out.splitlines())


def test_many_distinct_warnings_are_capped():
    mod = _mod()
    names = mod.SECTION_ORDER
    findings = [{'id': f'{names[i % len(names)]}.rule_{i:05d}', 'classification': 'warning',
                 'consequence': f'Distinct warning number {i} with a few plain words.',
                 'evidence': {'count': i}} for i in range(5000)]
    findings += [{'id': f'dead_stores.info_{i}', 'classification': 'info',
                  'consequence': f'Info {i}.', 'evidence': {}} for i in range(50)]
    text = mod.render_text(mod.summarize({'findings': findings}))
    lines = text.splitlines()
    assert len(lines) <= 200 == mod.MAX_LINES_HARD
    assert re.search(r'\d[\d,]* more warnings \(full list in --json\)\.', text)
    assert 'Distinct warning number 0 ' in text
    assert text.rstrip().endswith(mod.FOOTER_CLOSE)
    assert all(len(line) <= mod.LINE_WIDTH for line in lines)
    # One section alone with many long warnings is capped too.
    long = [{'id': f'dead_stores.r{i}', 'classification': 'warning',
             'consequence': f'Warning {i} ' + 'word ' * 300, 'evidence': {}} for i in range(400)]
    out = mod.render_text(mod.summarize({'findings': long}))
    assert len(out.splitlines()) <= mod.MAX_LINES_HARD and 'more warnings (full list in --json).' in out


@pytest.mark.parametrize('summary', [
    None, {}, {'sections': 'x'}, {'sections': [1, None, 'x', {'title': 5, 'measured': True}]},
    {'sections': [{'section': 'dead_stores', 'title': 'T', 'measured': True, 'headline': 7,
                   'findings': {'warning': [{'sentence': None, 'count': 'x', 'evidence': [[1]]}]}}],
     'counts': 'x', 'biggest_items': [{'value': 'x'}], 'not_measured': [None, {'reason': 3}],
     'next_steps': 'abc', 'other_findings': 'many', 'measured_on': 5},
    {'sections': [{'findings': 'x'}], 'counts': {'warning': 'two'}},
])
def test_render_text_never_raises_on_malformed_summary(summary):
    mod = _mod()
    text = mod.render_text(summary)
    assert isinstance(text, str) and text.strip()
    assert not _FORBIDDEN_CP.search(text.replace('\n', ''))
    if text.strip() == mod.RENDER_FAILED:
        return
    assert text.startswith(mod.HEADER_TITLE)


def test_render_failed_message_is_fixed():
    mod = _mod()
    assert mod.RENDER_FAILED == 'The summary could not be built from this report; see --json.'

    class Boom(dict):
        def get(self, *a, **k):
            raise RuntimeError('boom')
    assert mod.render_text(Boom(sections=[])) == mod.RENDER_FAILED + '\n'


def test_reason_tokens_become_plain_phrases():
    mod = _mod()
    assert mod.reason_phrase('not_in_report') == 'not part of this report'
    assert mod.reason_phrase('not_run') == 'not run this time'
    assert mod.reason_phrase('unexpected_shape') == 'the report section had an unexpected shape'
    assert mod.reason_phrase('bounded_quick_audit_not_collected') == 'not included in a quick audit'
    assert mod.reason_phrase('could_not_verify') == 'could not be verified'
    assert mod.reason_phrase('profile_missing') == 'the profile folder was not found'
    assert mod.reason_phrase('sibling_gone') == 'sibling gone'
    assert mod.reason_phrase('no_reason') == 'the audit did not say why'
    assert mod.reason_phrase(None) == 'unknown'
    report = {'memory_load': 'garbage', 'findings': []}
    text = mod.render_text(mod.summarize(report))
    assert 'the report section had an unexpected shape' in text and 'not part of this report' in text
    for token in ('(not_in_report)', '(not_run)', '(unexpected_shape)', 'unexpected_shape'):
        assert token not in text


def test_credential_part_pattern_unchanged_by_tuple_construction():
    audit_summary = load_submodule("audit_summary")
    old = (r'(secret|token|auth|cred|passw|\.env|env$|key|\.pem|\.p12|\.pfx|id_rsa|id_ed25519|id_ecdsa|'
           r'netrc|npmrc|pypirc|oauth|vault|keystore)')
    assert audit_summary._CREDENTIAL_PART_RE.pattern == old
    assert audit_summary._CREDENTIAL_PART_RE.flags & __import__('re').IGNORECASE


_FINDING_FIELDS = ('classification', 'id', 'rule_id', 'coverage', 'consequence', 'detail',
                   'evidence', 'affected_identities', 'source_paths', 'severity')
_WRONG_VALUES = {
    'list': ['warning'], 'nested_list': [['warning', {'a': [1]}]], 'dict': {'warning': 1},
    'nested_dict': {'evidence': {'bytes': {'x': [1]}}}, 'none': None, 'int': 7, 'bool': True,
    'float_nan': float('nan'), 'long_str': 'w' * 20000, 'set': {'warning'},
    'tuple': ('warning',), 'bytes': b'warning', 'evidence_bad_keys': {1: 2, None: 'x', 'n_bytes': [1]},
}


@pytest.mark.parametrize('kind', sorted(_WRONG_VALUES))
@pytest.mark.parametrize('field', _FINDING_FIELDS)
def test_every_finding_field_tolerates_every_wrong_type(field, kind):
    mod = _mod()
    good = {'id': 'memory_load.over_limit', 'classification': 'warning',
            'consequence': 'Memory is over its limit.', 'evidence': {'bytes': 10}}
    finding = dict(good, **{field: _WRONG_VALUES[kind]})
    summary = mod.summarize({'findings': [finding, good]}, home='/home/user/.hermes')
    text = mod.render_text(summary)
    assert text != mod.RENDER_FAILED + '\n'
    assert summary['counts']['warning'] >= 1
    assert len(text.splitlines()) <= mod.MAX_LINES_HARD
    assert all(len(line) <= mod.LINE_WIDTH for line in text.splitlines())


def test_random_mutations_of_a_real_report_never_raise(full):
    import copy
    import random
    mod = _mod()
    rng = random.Random(20261110)
    base = json.loads(json.dumps(full['report'], default=str))
    junk = list(_WRONG_VALUES.values()) + ['', 'x', -1, 0, 10 ** 30, [{}], {'': None}]

    def slots(obj, out, parent=None, key=None):
        if parent is not None:
            out.append((parent, key))
        if isinstance(obj, dict):
            for k in list(obj):
                slots(obj[k], out, obj, k)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                slots(obj[i], out, obj, i)
        return out

    for _ in range(500):
        report = copy.deepcopy(base)
        for parent, key in rng.sample(spots := slots(report, []), min(3, len(spots))):
            parent[key] = copy.deepcopy(rng.choice(junk))
        summary = mod.summarize(report, home=str(full['home']))
        text = mod.render_text(summary)
        assert len(text.splitlines()) <= mod.MAX_LINES_HARD
