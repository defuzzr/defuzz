"""Resilience of the componentize bridge: bad list entries, deep JSON, version shape,
and the project folder the companion reports back after it ran."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from .conftest import load_submodule

pytestmark = pytest.mark.usefixtures('componentize_live')

FIXTURES_DIR = Path(__file__).resolve().parent / 'fixtures' / 'kit_contract'
NESTED = '[' * 200_000 + ']' * 200_000


@pytest.fixture
def componentize_live():
    """Opt into real CLI detection and fake CLI subprocesses."""


def _fixture(name):
    return json.loads((FIXTURES_DIR / name).read_text(encoding='utf-8'))


_FAKE = r'''
import json
import os
import sys
from pathlib import Path

FIXTURES = Path(__FIXTURES__)
LOG = Path(__LOG__)
CFG = Path(__CFG__)

argv = sys.argv[1:]
if argv == ['--version']:
    print('componentize 0.2.0')
    sys.exit(0)
with LOG.open('a', encoding='utf-8') as fh:
    fh.write(json.dumps({'argv': argv, 'cwd': os.getcwd()}) + '\n')
cfg = json.loads(CFG.read_text(encoding='utf-8'))
mode = cfg['mode']
if mode == 'raw':
    sys.stdout.write(cfg['stdout'])
    sys.exit(0)
if argv[:2] == ['kit', 'list']:
    data = json.loads((FIXTURES / 'list.json').read_text(encoding='utf-8'))
    if mode == 'list_extra':
        data['kits'] = data['kits'] + cfg['extra']
    elif mode == 'list_only':
        data['kits'] = cfg['extra']
    print(json.dumps(data))
    sys.exit(0)
call, kit_id, dest = argv[1], argv[2], argv[3]
data = json.loads((FIXTURES / (call + '.json')).read_text(encoding='utf-8'))
data['kit'] = kit_id
if mode == 'swap':
    link = cfg['link']
    os.unlink(link)
    os.symlink(cfg['new_target'], link)
# Like the real companion: decide on realpath(dest) and report that folder.
operate = os.path.realpath(os.path.normpath(dest))
if mode == 'root':
    operate = cfg['root']
if call == 'apply' and mode != 'root':
    os.makedirs(operate, exist_ok=True)
    with open(os.path.join(operate, 'AGENTS.md'), 'a', encoding='utf-8') as fh:
        fh.write('x\n')
data['root'] = operate
print(json.dumps(data))
sys.exit(0)
'''


@pytest.fixture
def companion(tmp_path, monkeypatch):
    settings = load_submodule('componentize_settings')
    bindir = tmp_path / 'cli_bin'
    bindir.mkdir()
    log, cfg = bindir / 'log.jsonl', bindir / 'cfg.json'
    cfg.write_text(json.dumps({'mode': 'normal'}), encoding='utf-8')
    script = bindir / 'fake-componentize'
    body = (_FAKE.replace('__FIXTURES__', repr(str(FIXTURES_DIR)))
            .replace('__LOG__', repr(str(log))).replace('__CFG__', repr(str(cfg))))
    script.write_text(f'#!{sys.executable}\n{body}', encoding='utf-8')
    script.chmod(0o755)
    monkeypatch.setattr(settings, 'load', lambda: {**settings.DEFAULTS, 'cli_path_override': str(script)})

    def calls():
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines() if line]

    def mode(name, **extra):
        cfg.write_text(json.dumps({'mode': name, **extra}), encoding='utf-8')

    return SimpleNamespace(calls=calls, mode=mode)


# --- kit list: one bad entry must not hide the good ones -------------------------------

def test_genuine_kits_pass_unchanged(companion):
    bridge = load_submodule('componentize_bridge')
    res = bridge.kit_list()
    assert res['status'] == 'ok'
    assert res['data'] == _fixture('list.json')
    assert len(res['data']['kits']) == len(_fixture('list.json')['kits'])
    assert 'left out' not in res['notice']


def test_malformed_entries_are_dropped_one_by_one(companion):
    bridge = load_submodule('componentize_bridge')
    matcher = load_submodule('matcher')
    deep = {'id': 'deep'}
    for _ in range(50):
        deep = {'nested': deep}
    bad = [
        {'id': 'bool-version', 'name': 'x', 'summary': 'x', 'tags': [], 'version': True},
        'not-a-dict',
        None,
        {'id': 'tag-not-text', 'name': 'x', 'summary': 'x', 'tags': [1], 'version': 1},
        deep,
    ]
    companion.mode('list_extra', extra=bad)
    res = bridge.kit_list()
    assert res['status'] == 'ok'
    kits = res['data']['kits']
    assert [k['id'] for k in kits] == [k['id'] for k in _fixture('list.json')['kits']]
    assert res['data']['skipped_kits'] == 5
    assert '5 malformed kit entries were left out' in res['notice']
    assert '\n' not in res['notice']
    parsed = matcher.parse_kit_list_detailed(res)
    assert len(parsed.infos) == len(_fixture('list.json')['kits']) and parsed.status == 'ok'


def test_one_malformed_entry_notice_is_singular(companion):
    bridge = load_submodule('componentize_bridge')
    companion.mode('list_extra', extra=[42])
    res = bridge.kit_list()
    assert res['status'] == 'ok' and len(res['data']['kits']) == len(_fixture('list.json')['kits'])
    assert res['data']['skipped_kits'] == 1
    assert '1 malformed kit entry was left out' in res['notice']


def test_all_entries_malformed_is_ok_and_empty(companion):
    bridge = load_submodule('componentize_bridge')
    companion.mode('list_only', extra=[1, 'two'])
    res = bridge.kit_list()
    assert res['status'] == 'ok'
    assert res['data']['kits'] == [] and res['data']['skipped_kits'] == 2


def test_kits_not_a_list_still_fails_whole_reply(companion):
    bridge = load_submodule('componentize_bridge')
    payload = _fixture('list.json')
    payload['kits'] = {'a': 1}
    companion.mode('raw', stdout=json.dumps(payload))
    res = bridge.kit_list()
    assert res['status'] == 'error' and res['data'] is None


# --- deeply nested JSON -----------------------------------------------------------------

@pytest.mark.parametrize('call', ['list', 'show'])
def test_deeply_nested_reply_is_a_plain_error(companion, call):
    bridge = load_submodule('componentize_bridge')
    companion.mode('raw', stdout=NESTED)
    res = bridge.kit_list() if call == 'list' else bridge.kit_show('video-production')
    assert res == {'status': 'error', 'data': None,
                   'notice': f'componentize kit {call} returned invalid JSON.', 'exit': 0}


def test_deeply_nested_survey_is_skipped_not_raised(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'load', lambda: {**settings.DEFAULTS, 'enabled_on_adopt': True})
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: (['/bin/true'], 'path', None))
    monkeypatch.setattr(bridge, '_run_survey', lambda command, root: SimpleNamespace(
        returncode=0, stdout=NESTED, stderr=''))
    assert bridge.survey_project(tmp_path) == {'status': 'skipped', 'exit': 0}
    assert not (tmp_path / 'AGENTS.md').exists()


def test_deeply_nested_saved_survey_raises_value_error(tmp_path):
    bridge = load_submodule('componentize_bridge')
    (tmp_path / '.adopt').mkdir()
    (tmp_path / '.adopt/componentize-survey.json').write_text(NESTED[:400_000], encoding='utf-8')
    with pytest.raises(ValueError):
        bridge.read_survey(tmp_path)


# --- `hermes componentize --version` must look like the companion's reply ----------------

def _bin(tmp_path, monkeypatch, hermes_out, *, standalone=False):
    bindir = tmp_path / 'pathbin'
    bindir.mkdir()
    hermes = bindir / 'hermes'
    hermes.write_text('#!/bin/sh\nprintf %s ' + _sh_quote(hermes_out) + '\n', encoding='utf-8')
    hermes.chmod(0o755)
    if standalone:
        comp = bindir / 'componentize'
        comp.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        comp.chmod(0o755)
    monkeypatch.setenv('PATH', str(bindir))
    return bindir


def _sh_quote(text):
    return "'" + text.replace("'", "'\\''") + "'"


def test_version_from_companion_is_accepted(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    bindir = _bin(tmp_path, monkeypatch, 'componentize 0.2.0\n')
    assert bridge.detect_command() == ([str(bindir / 'hermes'), 'componentize'], 'hermes', 'componentize 0.2.0')


_BAD_VERSION_OUTPUTS = [
    'Hermes Agent v0.23.0 (2026.11.1)\nProject: /x\nPython: 3.11\n',
    'v1',
    'garbage!!',
    '{"schema": "componentize.kit/1"}',
    'componentize 0.2.0\nsecond line\n',
    'componentize ' + '9' * 500,
    'componentize ' + '9' * (1024 * 1024),
    'componentize \x1b[31m0.2\n',
    'componentize 0.2\x07',
    'componentize 0.2 beta 3',
    '',
]


@pytest.mark.parametrize('out', _BAD_VERSION_OUTPUTS, ids=range(len(_BAD_VERSION_OUTPUTS)))
def test_version_with_wrong_shape_is_not_the_companion(tmp_path, monkeypatch, out):
    bridge = load_submodule('componentize_bridge')
    _bin(tmp_path, monkeypatch, out)
    assert bridge.detect_command() == (None, 'absent', None)


@pytest.mark.parametrize('out', _BAD_VERSION_OUTPUTS, ids=range(len(_BAD_VERSION_OUTPUTS)))
def test_wrong_version_shape_falls_back_to_standalone(tmp_path, monkeypatch, out):
    bridge = load_submodule('componentize_bridge')
    bindir = _bin(tmp_path, monkeypatch, out, standalone=True)
    command, source, version = bridge.detect_command()
    assert (command, source) == ([str(bindir / 'componentize')], 'path')
    # The standalone stub prints nothing, so the rejected text is never shown.
    assert version is None


# --- project folder identity under a symlinked parent or home ----------------------------

def _alias(tmp_path, name='alias-parent'):
    real = tmp_path / ('real-' + name)
    real.mkdir()
    alias = tmp_path / name
    alias.symlink_to(real, target_is_directory=True)
    return real, alias


def test_apply_and_check_under_symlinked_parent_succeed(tmp_path, companion):
    bridge = load_submodule('componentize_bridge')
    real, alias = _alias(tmp_path)
    dest = str(alias / 'sample')
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'ok', res['notice']
    assert res['data']['root'] == str(real / 'sample')
    assert (real / 'sample' / 'AGENTS.md').read_text() == 'x\n'
    res_check = bridge.kit_check('video-production', dest)
    assert res_check['status'] == 'ok', res_check['notice']
    calls = companion.calls()
    # The companion gets the path as written, once per call (no retry).
    assert [c['argv'][:4] for c in calls] == [
        ['kit', 'apply', 'video-production', dest],
        ['kit', 'check', 'video-production', dest],
    ]


def test_symlinked_home_passes_path_as_written(tmp_path, companion, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    real_home, home_link = _alias(tmp_path, 'home-link')
    monkeypatch.setenv('HOME', str(home_link))
    (real_home / 'Projects').mkdir()
    dest = os.path.join(str(home_link), 'Projects', 'demo')
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'ok', res['notice']
    assert companion.calls()[0]['argv'][3] == dest
    assert res['data']['root'] == str(real_home / 'Projects' / 'demo')


def test_plain_destination_still_matches(tmp_path, companion):
    bridge = load_submodule('componentize_bridge')
    parent = tmp_path / 'plain'
    parent.mkdir()
    res = bridge.kit_apply('video-production', str(parent / 'p'))
    assert res['status'] == 'ok'


@pytest.mark.parametrize('which', ['elsewhere', 'other-link-to-same-folder'])
def test_unexpected_reply_root_is_rejected(tmp_path, companion, which):
    bridge = load_submodule('componentize_bridge')
    real, alias = _alias(tmp_path)
    if which == 'elsewhere':
        other = tmp_path / 'elsewhere'
        other.mkdir()
        reported = str(other / 'sample')
    else:
        # Another link that happens to point at the same folder is not blessed.
        link2 = tmp_path / 'second-link'
        link2.symlink_to(real, target_is_directory=True)
        reported = str(link2 / 'sample')
    companion.mode('root', root=reported)
    for call in (bridge.kit_apply, bridge.kit_check):
        res = call('video-production', str(alias / 'sample'))
        assert res['status'] == 'error' and res['data'] is None
        assert 'did not match' in res['notice']
    assert len(companion.calls()) == 2


def test_parent_link_swapped_during_apply_is_rejected_without_retry(tmp_path, companion):
    bridge = load_submodule('componentize_bridge')
    real, alias = _alias(tmp_path)
    moved = tmp_path / 'moved'
    moved.mkdir()
    companion.mode('swap', link=str(alias), new_target=str(moved))
    res = bridge.kit_apply('video-production', str(alias / 'sample'))
    assert res['status'] == 'error' and 'did not match' in res['notice']
    assert len(companion.calls()) == 1


def test_apply_timeout_is_reported_once(tmp_path, companion, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    _real, alias = _alias(tmp_path)
    seen = []

    def slow(command, args, **kw):
        seen.append(args)
        raise subprocess.TimeoutExpired(args, kw.get('timeout'))

    monkeypatch.setattr(bridge, '_run_cli', slow)
    res = bridge.kit_apply('video-production', str(alias / 'sample'))
    assert res['status'] == 'error' and 'timed out' in res['notice']
    assert len(seen) == 1
