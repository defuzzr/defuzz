"""Negative-path contracts for the optional bridge."""
import json
import os
import subprocess
from types import SimpleNamespace

import pytest
from .conftest import load_submodule

pytestmark = pytest.mark.usefixtures('componentize_live')


@pytest.fixture
def componentize_live():
    """Opt into the bridge without the suite's hermetic guard."""


@pytest.fixture
def survey(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'load', lambda: settings.DEFAULTS.copy())
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: (['/bin/true'], 'path', None))
    payload = dict(schema='componentize.survey/1', ok=True, status='ok', error=None,
                   findings=[], path=str(tmp_path), exit=0, files=[], proposed_splits=[])
    result = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr='')
    monkeypatch.setattr(bridge, '_run_survey', lambda *a, **kw: result)
    return bridge, payload, result


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'directory'])
def test_unsafe_existing_survey(tmp_path, survey, kind, capsys):
    bridge, _, _ = survey
    target = tmp_path / '.adopt/componentize-survey.json'
    target.parent.mkdir()
    if kind == 'symlink':
        target.symlink_to(tmp_path / 'elsewhere')
    elif kind == 'fifo':
        os.mkfifo(target)
    else:
        target.mkdir()
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    assert capsys.readouterr().err
    assert not (tmp_path / 'AGENTS.md').exists()


@pytest.mark.parametrize('cap', [1, None, '40', False])
def test_effective_line_budget(tmp_path, survey, cap):
    bridge, _, _ = survey
    agents = tmp_path / 'AGENTS.md'
    agents.write_text('line\n' * 10)
    assert bridge.survey_after_apply(tmp_path, agents_md_max_lines=cap)['status'] == 'ok'
    assert 'Componentize candidates:' in agents.read_text()


def test_optional_type_error_is_notice(tmp_path, survey, monkeypatch, capsys):
    bridge, _, _ = survey
    def fail(*args):
        raise TypeError('bad Python value')
    monkeypatch.setattr(bridge, '_run_survey', fail)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    assert 'bad Python value' in capsys.readouterr().err


def test_line_budget(tmp_path, survey, capsys):
    bridge, _, _ = survey
    agents = tmp_path / 'AGENTS.md'
    original = 'line\n' * 11
    agents.write_text(original)
    assert bridge.survey_after_apply(tmp_path, agents_md_max_lines=11)['status'] == 'ok'
    assert agents.read_text() == original
    assert 'line' in capsys.readouterr().err


@pytest.mark.parametrize('field,value', [('exit', False), ('exit', 0.0), ('path', '/elsewhere')])
def test_strict_envelope(tmp_path, survey, field, value):
    bridge, payload, result = survey
    payload[field] = value
    result.stdout = json.dumps(payload)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'


@pytest.mark.parametrize('kind', ['nonzero', 'malformed', 'oversized', 'timeout'])
def test_survey_failure(tmp_path, survey, kind, monkeypatch, capsys):
    bridge, _, result = survey
    if kind == 'nonzero':
        result.returncode, result.stdout, result.stderr = 7, 'not json', 'survey failed\nmore'
    elif kind == 'malformed':
        result.stdout = '{'
    elif kind == 'oversized':
        result.stdout = ' ' * (1024 * 1024 + 1)
    else:
        def timeout(*a, **kw):
            raise subprocess.TimeoutExpired('survey', 60)
        monkeypatch.setattr(bridge, '_run_survey', timeout)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    notice = capsys.readouterr().err
    if kind == 'nonzero':
        assert '7' in notice and 'survey failed' in notice
    if kind == 'oversized':
        assert 'size' in notice


@pytest.mark.parametrize('kind', ['relative', 'inside', 'nonexec', 'directory'])
def test_reject_unsafe_override(tmp_path, monkeypatch, kind, capsys):
    bridge = load_submodule('componentize_bridge')
    root = tmp_path / 'root'
    root.mkdir()
    executable = (root if kind == 'inside' else tmp_path) / 'cli'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o644 if kind == 'nonexec' else 0o755)
    override = 'cli' if kind == 'relative' else str(tmp_path if kind == 'directory' else executable)
    monkeypatch.setattr(bridge.subprocess, 'run', lambda *a, **kw: pytest.fail('unsafe probe'))
    assert bridge.detect_command(override, root=root)[0] is None
    assert capsys.readouterr().err


@pytest.mark.parametrize('override', [True, False])
def test_preserves_symlink_argv0(tmp_path, monkeypatch, override):
    bridge = load_submodule('componentize_bridge')
    executable = tmp_path / 'multicall'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    link = tmp_path / 'hermes'
    link.symlink_to(executable)
    monkeypatch.setenv('PATH', str(tmp_path))
    calls = []
    monkeypatch.setattr(bridge.subprocess, 'run', lambda argv, **kw:
                        calls.append(argv) or SimpleNamespace(returncode=0, stdout='componentize 1'))
    command = bridge.detect_command(str(link) if override else None)[0]
    assert command[0] == str(link)
    assert calls[0][0] == str(link)


@pytest.mark.parametrize('entry', ['bin', './bin', '../bin'])
def test_skips_all_relative_path_entries(tmp_path, monkeypatch, entry):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PATH', os.pathsep.join([entry, '/usr/bin']))
    seen = []
    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: seen.append(kw['path']))
    assert bridge.detect_command()[0] is None
    assert seen == ['/usr/bin', '/usr/bin']


def test_safe_path_resolution(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    root = tmp_path / 'root'
    root.mkdir()
    safe = tmp_path / 'safe'
    safe.mkdir()
    executable = safe / 'hermes'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', os.pathsep.join(['', '.', str(root), str(safe)]))
    calls = []
    monkeypatch.setattr(bridge.subprocess, 'run', lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0, stdout='componentize 1'))
    assert bridge.detect_command(root=root)[0] == [str(executable), 'componentize']
    assert calls == [[str(executable), 'componentize', '--version']]


@pytest.mark.parametrize('kind', ['nonzero', 'timeout', 'missing'])
def test_override_probe_failure(tmp_path, monkeypatch, kind):
    bridge = load_submodule('componentize_bridge')
    executable = tmp_path / 'cli'
    executable.write_text('#!/bin/sh\nexit 1\n')
    executable.chmod(0o755)
    def run(*a, **kw):
        if kind == 'timeout':
            raise subprocess.TimeoutExpired('cli', 15)
        if kind == 'missing':
            raise FileNotFoundError('gone')
        return SimpleNamespace(returncode=1, stdout='')
    monkeypatch.setattr(bridge.subprocess, 'run', run)
    monkeypatch.setattr(bridge.shutil, 'which', lambda *a, **kw: pytest.fail('fallback'))
    # A probe that times out is reported as a timeout, not as a missing plugin.
    expected = 'timeout' if kind == 'timeout' else 'absent'
    assert bridge.detect_command(str(executable)) == (None, expected, None)


@pytest.mark.parametrize('kind', ['fifo', 'oversized', 'wrong_path', 'bool_exit'])
def test_status_rejects_unsafe_survey(tmp_path, monkeypatch, kind):
    settings = load_submodule('componentize_settings')
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(settings, 'load', lambda: settings.DEFAULTS.copy())
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: (None, 'absent', None))
    target = tmp_path / '.adopt/componentize-survey.json'
    target.parent.mkdir()
    if kind == 'fifo':
        os.mkfifo(target)
    else:
        payload = dict(schema='componentize.survey/1', ok=True, status='ok', error=None,
                       findings=[], path=str(tmp_path), exit=0, files=[], proposed_splits=[])
        if kind == 'wrong_path':
            payload['path'] = '/elsewhere'
        if kind == 'bool_exit':
            payload['exit'] = False
        target.write_text(' ' * (1024 * 1024 + 1) if kind == 'oversized' else json.dumps(payload))
    assert settings.status(tmp_path)['last_survey'] is None


def test_enabled_override_runs_real_survey(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    bridge = load_submodule('componentize_bridge')
    root = tmp_path / 'project'
    root.mkdir()
    executable = tmp_path / 'cli'
    payload = dict(schema='componentize.survey/1', ok=True, status='ok', error=None,
                   findings=[], path=str(root), exit=0, files=[], proposed_splits=[])
    import shlex
    executable.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then printf v1; else printf "%s" '
                          + shlex.quote(json.dumps(payload)) + '; fi\n')
    executable.chmod(0o755)
    monkeypatch.setattr(settings, 'load', lambda: {**settings.DEFAULTS, 'cli_path_override': str(executable)})
    assert bridge.survey_after_apply(root)['status'] == 'ok'
    assert settings.status(root)['last_survey']['path'] == str(root)


def test_replaces_existing_marker(tmp_path, survey):
    bridge, _, _ = survey
    agents = tmp_path / 'AGENTS.md'
    agents.write_text('hello\nComponentize candidates: old\n')
    assert bridge.survey_after_apply(tmp_path)['status'] == 'ok'
    assert agents.read_text().count('Componentize candidates:') == 1
    assert 'old' not in agents.read_text()


def test_corrupt_settings_skips(tmp_path, monkeypatch, capsys):
    bridge = load_submodule('componentize_bridge')
    settings = load_submodule('componentize_settings')
    def corrupt():
        raise ValueError('corrupt settings')
    monkeypatch.setattr(settings, 'load', corrupt)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    assert 'corrupt settings' in capsys.readouterr().err


@pytest.mark.parametrize('error', [OSError, RuntimeError])
@pytest.mark.parametrize('original', [None, b'original\r\nbytes\r\n'])
def test_survey_write_failure(tmp_path, survey, monkeypatch, error, original):
    bridge, _, _ = survey
    error = load_submodule('safety').SafetyError if error is RuntimeError else error
    real_write = bridge.safe_write_text
    def fail(root, path, text, **kwargs):
        if path == bridge.SURVEY_PATH:
            raise error('disk full')
        return real_write(root, path, text, **kwargs)
    monkeypatch.setattr(bridge, 'safe_write_text', fail)
    agents = tmp_path / 'AGENTS.md'
    if original is not None:
        agents.write_bytes(original)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    assert not (tmp_path / bridge.SURVEY_PATH).exists()
    assert (agents.read_bytes() if agents.exists() else None) == original


def test_real_output_is_bounded(tmp_path):
    bridge = load_submodule('componentize_bridge')
    import sys
    with pytest.raises(ValueError, match='size'):
        bridge._run_survey([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 2000000)'], tmp_path)


def test_nonzero_even_with_valid_envelope(tmp_path, survey, capsys):
    bridge, _, result = survey
    result.returncode = 3
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
    assert 'exited 3' in capsys.readouterr().err
    assert not (tmp_path / bridge.SURVEY_PATH).exists()


def test_hermes_success_does_not_lookup_standalone(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    executable = tmp_path / 'hermes'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    def which(name, **kwargs):
        assert name == 'hermes'
        return str(executable)
    monkeypatch.setattr(bridge.shutil, 'which', which)
    monkeypatch.setattr(bridge.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout='componentize 1'))
    assert bridge.detect_command()[1] == 'hermes'


def test_override_symlink_into_project_rejected(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    root = tmp_path / 'project'
    root.mkdir()
    executable = root / 'cli'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    link = tmp_path / 'cli'
    link.symlink_to(executable)
    monkeypatch.setattr(bridge.subprocess, 'run', lambda *a, **kw: pytest.fail('unsafe probe'))
    assert bridge.detect_command(str(link), root=root)[0] is None
