"""Pure-Python settings and desktop status contract."""
import json
import pytest
from .conftest import load_submodule

pytestmark = pytest.mark.usefixtures('componentize_live')


@pytest.fixture
def componentize_live():
    pass


def test_settings_round_trip(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path if name == 'defuzz' else None)
    assert settings.load() == dict(enabled_on_adopt=True, run_survey_on_new=False, cli_path_override=None)
    value = dict(enabled_on_adopt=False, run_survey_on_new=True, cli_path_override='/opt/my cli')
    assert settings.save(value) == value
    assert settings.load() == value
    assert json.loads((tmp_path / 'componentize-settings.json').read_text()) == value


@pytest.mark.parametrize('bad', [[], {'extra': True}, {'enabled_on_adopt': 1},
    {'run_survey_on_new': 'false'}, {'cli_path_override': ''}, {'cli_path_override': 3},
    {'cli_path_override': 'bad\x00path'}])
def test_invalid_settings_rejected(tmp_path, monkeypatch, bad):
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path)
    with pytest.raises(ValueError):
        settings.save(bad)
    assert not (tmp_path / 'componentize-settings.json').exists()


def test_corrupt_settings_rejected(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path)
    (tmp_path / 'componentize-settings.json').write_text('{"enabled_on_adopt": 1}')
    with pytest.raises(ValueError):
        settings.load()


def test_atomic_failure_preserves_previous(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path)
    original = settings.save({})
    def fail(*args):
        raise OSError('replace failed')
    monkeypatch.setattr(settings.os, 'replace', fail)
    with pytest.raises(OSError):
        settings.save({'enabled_on_adopt': False})
    assert settings.load() == original
    assert [p.name for p in tmp_path.iterdir()] == ['componentize-settings.json']


def test_override_status_and_disabled_adoption(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path)
    executable = tmp_path / 'my cli'
    executable.write_text('#!/bin/sh\nprintf "componentize 1.2\\n"\n')
    executable.chmod(0o755)
    settings.save({'cli_path_override': str(executable), 'enabled_on_adopt': False})
    assert settings.status(None) == dict(detected=True, version='componentize 1.2', source='override', last_survey=None)
    monkeypatch.setattr(bridge.subprocess, 'run', lambda *a, **kw: pytest.fail('disabled adoption ran a command'))
    assert bridge.survey_after_apply(tmp_path) == {'status': 'skipped', 'exit': 0}


def test_absent_status(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path)
    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: None)
    assert settings.status(tmp_path) == dict(detected=False, version=None, source='absent', last_survey=None)
    (tmp_path / '.adopt').mkdir()
    survey = tmp_path / '.adopt/componentize-survey.json'
    payload = dict(schema='componentize.survey/1', ok=True, status='ok', error=None,
                   findings=[], path=str(tmp_path), exit=0, files=['a.py'], proposed_splits=[{}])
    survey.write_text(json.dumps(payload))
    before = survey.read_bytes()
    assert settings.status(tmp_path)['last_survey'] == dict(schema='componentize.survey/1', status='ok',
        path=str(tmp_path), files=1, proposed_splits=1, findings=0)
    assert survey.read_bytes() == before
    survey.write_text('{"schema":"wrong"}')
    assert settings.status(tmp_path)['last_survey'] is None
    survey.unlink()
    survey.symlink_to(tmp_path / 'componentize-settings.json')
    assert settings.status(tmp_path)['last_survey'] is None


def test_status_bounds_detect_command_total_probe_time_to_15s(tmp_path, monkeypatch):
    import subprocess
    settings = load_submodule('componentize_settings')
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(settings, 'plugin_data_dir', lambda name, **kw: tmp_path)
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name in ('hermes', 'componentize'):
        exe = bin_dir / name
        exe.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        exe.chmod(0o755)
    monkeypatch.setenv('PATH', str(bin_dir))

    now = [200.0]
    monkeypatch.setattr(bridge.time, 'monotonic', lambda: now[0])
    handed_timeouts: list[float] = []

    def fake_probe_run(cmd, **kwargs):
        from pathlib import Path
        from types import SimpleNamespace
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
    st = settings.status(proj)
    assert st['detected'] is False
    assert st['source'] == 'timeout'
    assert handed_timeouts == [15.0, 6.0]
    assert (now[0] - 200.0) <= 15.0

    # And when the first probe hangs for its full 15s budget, the second candidate is not spawned at all
    now[0] = 300.0
    handed_timeouts.clear()

    def hanging_probe_run(cmd, **kwargs):
        t = float(kwargs['timeout'])
        handed_timeouts.append(t)
        now[0] += t
        raise subprocess.TimeoutExpired(cmd, t)

    monkeypatch.setattr(bridge.subprocess, 'run', hanging_probe_run)
    st_hang = settings.status(proj)
    assert st_hang['detected'] is False
    assert st_hang['source'] == 'timeout'
    assert handed_timeouts == [15.0]
    assert sum(handed_timeouts) <= 15.0
