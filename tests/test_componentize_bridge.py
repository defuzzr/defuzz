"""Release B survey integration contract."""
import json
from types import SimpleNamespace
from .conftest import load_submodule
import pytest

pytestmark = pytest.mark.usefixtures('componentize_live')


@pytest.fixture
def componentize_live():
    pass


def test_adopt_settings_failure_is_optional(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    settings = load_submodule('componentize_settings')
    def broken():
        raise ValueError('corrupt settings')
    monkeypatch.setattr(settings, 'load', broken)
    assert bridge.survey_after_apply(tmp_path) == {'status': 'skipped', 'exit': 0}


def test_survey_persists_review_only_candidates(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    payload = dict(schema='componentize.survey/1', ok=True, status='pass', error=None,
                   findings=[], path=str(tmp_path), exit=0, files=[], proposed_splits=[])
    calls = []
    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: '/usr/bin/true')
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[-1] == '--version':
            return SimpleNamespace(returncode=0, stdout='componentize 0.2.0\n', stderr='')
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr='')
    monkeypatch.setattr(bridge.subprocess, 'run', run)
    monkeypatch.setattr(bridge, '_run_survey', lambda command, root: run([*command, 'survey', str(root), '--json']))
    result = bridge.survey_after_apply(tmp_path)
    assert result['status'] == 'ok'
    assert json.loads((tmp_path / '.adopt/componentize-survey.json').read_text()) == payload
    assert 'Componentize candidates: 0' in (tmp_path / 'AGENTS.md').read_text()
    assert calls[0] == ['/usr/bin/true', 'componentize', '--version']
    assert calls[1] == ['/usr/bin/true', 'componentize', 'survey', str(tmp_path), '--json']
    assert not (tmp_path / '.componentize').exists()


def test_apply_invokes_survey(tmp_path, monkeypatch):
    applier = load_submodule('applier')
    bridge = load_submodule('componentize_bridge')
    copy = tmp_path / 'copy'
    copy.mkdir()
    (copy / 'hello.py').write_text('print(1)\n')
    inv = load_submodule('scanner').scan_folder(copy)
    rules = load_submodule('rules').build_deterministic_fallback_rules(inv)
    seen = []
    monkeypatch.setattr(bridge, 'survey_after_apply', lambda root, **kw: seen.append(root) or {'status': 'skipped', 'exit': 0})
    applier.apply_rules_to_copy(copy, inv, rules, db_path=tmp_path / 'state.db')
    assert seen == [copy]


@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('cap', [6, 7, 8, 9, 10, 11, 40])
def test_large_apply_reserves_pointer_line(tmp_path, monkeypatch, enabled, cap):
    applier = load_submodule('applier')
    bridge = load_submodule('componentize_bridge')
    copy = tmp_path / 'copy'
    copy.mkdir()
    (copy / 'hello.py').write_text('print(1)\n')
    inv = load_submodule('scanner').scan_folder(copy)
    rules = load_submodule('rules').build_deterministic_fallback_rules(inv)
    original_writer = applier.write_agents_md
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'load', lambda: {
        'enabled_on_adopt': enabled, 'cli_path_override': None})
    reservations = []
    def large_writer(root, payload, *, reserve_lines=0):
        reservations.append(reserve_lines)
        assert payload['agents_md_max_lines'] == cap
        payload = {**payload, 'declared_dirs': [
            {'dir': f'dir{i}', 'summary': 'summary', 'why': 'reason'} for i in range(60)]}
        return original_writer(root, payload, reserve_lines=reserve_lines)
    monkeypatch.setattr(applier, 'write_agents_md', large_writer)
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: (['/bin/true'], 'path', None))
    payload = dict(schema='componentize.survey/1', ok=True, status='pass', error=None,
                   findings=[], path=str(copy), exit=0, files=[], proposed_splits=[])
    monkeypatch.setattr(bridge, '_run_survey', lambda *a: SimpleNamespace(
        returncode=0, stdout=json.dumps(payload), stderr=''))
    applier.apply_rules_to_copy(copy, inv, rules, db_path=tmp_path / 'state.db',
                                agents_md_max_lines=cap)
    assert reservations == [int(enabled)]
    text = (copy / 'AGENTS.md').read_text()
    assert ('Componentize candidates:' in text) == enabled
    assert len(text.splitlines()) <= load_submodule('agents_md').clamp_max_lines(cap)


@pytest.mark.parametrize('cap', [6, 7, 8, 9, 10, 11, 40])
def test_generated_guide_reserves_bridge_pointer(tmp_path, monkeypatch, cap):
    agents = load_submodule('agents_md')
    bridge = load_submodule('componentize_bridge')
    rules = {'project_slug': 'budget', 'agents_md_max_lines': cap,
             'declared_dirs': [{'dir': f'dir{i}', 'summary': 'summary', 'why': 'reason'}
                               for i in range(60)]}
    agents.write_agents_md(tmp_path, rules, reserve_lines=1)
    generated = (tmp_path / 'AGENTS.md').read_text()
    agents.validate_agents_md(generated)
    assert len(generated.splitlines()) <= agents.clamp_max_lines(cap) - 1
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: (['/bin/true'], 'path', None))
    payload = dict(schema='componentize.survey/1', ok=True, status='pass', error=None,
                   findings=[], path=str(tmp_path), exit=0, files=[], proposed_splits=[])
    monkeypatch.setattr(bridge, '_run_survey', lambda *a: SimpleNamespace(
        returncode=0, stdout=json.dumps(payload), stderr=''))
    assert bridge.survey_after_apply(tmp_path, agents_md_max_lines=cap)['status'] == 'ok'
    text = (tmp_path / 'AGENTS.md').read_text()
    assert 'Componentize candidates:' in text
    assert len(text.splitlines()) <= agents.clamp_max_lines(cap)
    agents.validate_agents_md(text)


def test_missing_command_notice(tmp_path, monkeypatch, capsys):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: None)
    assert bridge.survey_after_apply(tmp_path) == {'status': 'skipped', 'exit': 0}
    assert 'unavailable' in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_plain_fallback_and_invalid_schema(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    calls = []
    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: '/usr/bin/true')
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=2 if '--version' in argv else 0,
                               stdout='{"schema":"wrong"}', stderr='')
    monkeypatch.setattr(bridge.subprocess, 'run', run)
    monkeypatch.setattr(bridge, '_run_survey', lambda command, root: run([*command, 'survey', str(root), '--json']))
    assert bridge.survey_after_apply(tmp_path)['exit'] == 0
    assert calls[-1][0] == '/usr/bin/true'
    assert not (tmp_path / '.adopt/componentize-survey.json').exists()


def test_agents_failure_does_not_publish_survey(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: (['/bin/true'], 'path', None))
    payload = dict(schema='componentize.survey/1', ok=True, status='pass', error=None,
                   findings=[], path=str(tmp_path), exit=0, files=[], proposed_splits=[])
    monkeypatch.setattr(bridge, '_run_survey', lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout=json.dumps(payload), stderr=''))
    real_write = bridge.safe_write_text
    def fail_agents(root, path, text, **kwargs):
        if path == 'AGENTS.md':
            raise load_submodule('safety').SafetyError('write failed')
        return real_write(root, path, text, **kwargs)
    monkeypatch.setattr(bridge, 'safe_write_text', fail_agents)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    assert not (tmp_path / '.adopt/componentize-survey.json').exists()


def test_survey_project_bounds_detect_command_total_probe_time_to_15s(tmp_path, monkeypatch):
    from pathlib import Path
    import subprocess
    bridge = load_submodule('componentize_bridge')
    settings = load_submodule('componentize_settings')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name in ('hermes', 'componentize'):
        exe = bin_dir / name
        exe.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        exe.chmod(0o755)
    monkeypatch.setenv('PATH', str(bin_dir))
    monkeypatch.setattr(settings, 'load', lambda: {**settings.DEFAULTS, 'cli_path_override': None})

    now = [100.0]
    monkeypatch.setattr(bridge.time, 'monotonic', lambda: now[0])
    handed_timeouts: list[float] = []

    def fake_probe_run(cmd, **kwargs):
        t = float(kwargs['timeout'])
        handed_timeouts.append(t)
        if Path(cmd[0]).name == 'hermes':
            now[0] += 9.0
            return SimpleNamespace(returncode=1, stdout='', stderr='')
        now[0] += t
        raise subprocess.TimeoutExpired(cmd, t)

    monkeypatch.setattr(bridge.subprocess, 'run', fake_probe_run)
    proj = tmp_path / 'proj'
    proj.mkdir()
    res = bridge.survey_project(proj)
    assert res == {'status': 'skipped', 'exit': 0}
    assert handed_timeouts == [15.0, 6.0]
    assert (now[0] - 100.0) <= 15.0

    # And when the first probe hangs for its full 15s budget, the second candidate is not spawned at all
    now[0] = 200.0
    handed_timeouts.clear()

    def hanging_probe_run(cmd, **kwargs):
        t = float(kwargs['timeout'])
        handed_timeouts.append(t)
        now[0] += t
        raise subprocess.TimeoutExpired(cmd, t)

    monkeypatch.setattr(bridge.subprocess, 'run', hanging_probe_run)
    assert bridge.survey_project(proj) == {'status': 'skipped', 'exit': 0}
    assert handed_timeouts == [15.0]
    assert sum(handed_timeouts) <= 15.0
