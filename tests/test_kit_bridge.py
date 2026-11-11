"""Contract and negative-path tests for componentize kit bridge calls."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

from .conftest import load_submodule

pytestmark = pytest.mark.usefixtures('componentize_live')

FIXTURES_DIR = Path(__file__).resolve().parent / 'fixtures' / 'kit_contract'


@pytest.fixture
def componentize_live():
    """Opt into real CLI detection / fake CLI subprocesses."""


@pytest.fixture
def fake_cli(tmp_path, monkeypatch):
    """Write an executable fake componentize CLI into tmp_path and configure settings override."""
    settings = load_submodule('componentize_settings')
    cli_dir = tmp_path / 'cli_bin'
    cli_dir.mkdir()
    log_path = cli_dir / 'invocations.jsonl'
    mode_path = cli_dir / 'mode.json'
    mode_path.write_text(json.dumps({'mode': 'golden'}), encoding='utf-8')

    script = cli_dir / 'fake-componentize'
    script.write_text(
        f"""#!{sys.executable}
import json
import os
import sys
from pathlib import Path

FIXTURES = Path({str(FIXTURES_DIR)!r})
LOG_PATH = Path({str(log_path)!r})
MODE_PATH = Path({str(mode_path)!r})

argv = sys.argv[1:]
if argv == ['--version']:
    print('componentize 2.0.0')
    sys.exit(0)

with LOG_PATH.open('a', encoding='utf-8') as fh:
    fh.write(json.dumps({{'argv': argv, 'cwd': os.getcwd()}}) + '\\n')

cfg = json.loads(MODE_PATH.read_text(encoding='utf-8'))
mode = cfg.get('mode', 'golden')

if mode == 'exit2':
    err_env = {{
        'schema': 'componentize.kit/1',
        'ok': False,
        'status': 'error',
        'error': 'unknown kit id',
        'findings': [],
    }}
    print(json.dumps(err_env))
    sys.stderr.write('usage error: unknown kit\\n')
    sys.exit(2)

if mode == 'bad_json':
    sys.stdout.write('{{not valid json\\n')
    sys.exit(0)

if mode == 'wrong_schema':
    data = json.loads((FIXTURES / 'list.json').read_text(encoding='utf-8'))
    data['schema'] = 'componentize.kit/999'
    print(json.dumps(data))
    sys.exit(0)

if mode == 'unsafe_dir':
    data = json.loads((FIXTURES / 'show.json').read_text(encoding='utf-8'))
    data['declared_dirs'][0]['dir'] = cfg.get('unsafe_dir_value', '../escape')
    print(json.dumps(data))
    sys.exit(0)

if mode == 'unsafe_dest_dir':
    data = json.loads((FIXTURES / 'show.json').read_text(encoding='utf-8'))
    data['placement_rules'][0]['dest_dir'] = cfg.get('unsafe_dir_value', '/abs/escape')
    print(json.dumps(data))
    sys.exit(0)

if mode == 'oversized':
    sys.stdout.write('x' * (1024 * 1024 + 64))
    sys.exit(0)

if mode == 'check_fail':
    data = json.loads((FIXTURES / 'check.json').read_text(encoding='utf-8'))
    data['ok'] = False
    data['status'] = 'fail'
    data['root'] = data['root'].replace('/ROOT', argv[3])
    data['findings'] = [{{
        'id': 'missing-dir',
        'severity': 'error',
        'detail': 'assets/generated is missing',
        'fix': 'run componentize kit apply',
    }}]
    print(json.dumps(data))
    sys.exit(1)

if mode == 'custom_payload':
    print(json.dumps(cfg['payload']))
    sys.exit(cfg.get('exit_code', 0))

if mode == 'read_stdin':
    stdin_data = sys.stdin.read()
    data = json.loads((FIXTURES / 'list.json').read_text(encoding='utf-8'))
    data['stdin_len'] = len(stdin_data)
    print(json.dumps(data))
    sys.exit(0)

if mode == 'apply_fail':
    data = json.loads((FIXTURES / 'apply.json').read_text(encoding='utf-8'))
    data['ok'] = False
    data['status'] = 'fail'
    data['kit'] = argv[2]
    data['root'] = data['root'].replace('/ROOT', argv[3])
    data['findings'] = [{{
        'id': 'conflict-file',
        'severity': 'error',
        'detail': 'assets/generated exists as a file where a folder is expected',
        'fix': 'remove or rename the conflicting file',
    }}]
    print(json.dumps(data))
    sys.exit(1)

if mode == 'exit2_long_error':
    err_env = {{
        'schema': 'componentize.kit/1',
        'ok': False,
        'status': 'error',
        'error': ('long error line 1\\n' + 'E' * 5000),
        'findings': [],
    }}
    print(json.dumps(err_env))
    sys.exit(2)

# Default: golden fixtures
sub = argv[1] if len(argv) > 1 and argv[0] == 'kit' else ''
if sub == 'list':
    data = json.loads((FIXTURES / 'list.json').read_text(encoding='utf-8'))
elif sub == 'show':
    data = json.loads((FIXTURES / 'show.json').read_text(encoding='utf-8'))
    data['kit']['id'] = argv[2]
elif sub == 'apply':
    data = json.loads((FIXTURES / 'apply.json').read_text(encoding='utf-8'))
    data['kit'] = argv[2]
    data['root'] = data['root'].replace('/ROOT', argv[3])
elif sub == 'check':
    data = json.loads((FIXTURES / 'check.json').read_text(encoding='utf-8'))
    data['kit'] = argv[2]
    data['root'] = data['root'].replace('/ROOT', argv[3])
else:
    sys.stderr.write(f'unexpected args: {{argv!r}}\\n')
    sys.exit(2)

print(json.dumps(data))
sys.exit(0)
""",
        encoding='utf-8',
    )
    script.chmod(0o755)
    monkeypatch.setattr(
        settings,
        'load',
        lambda: {**settings.DEFAULTS, 'cli_path_override': str(script)},
    )

    def read_invocations():
        if not log_path.exists():
            return []
        return [
            json.loads(line)
            for line in log_path.read_text(encoding='utf-8').splitlines()
            if line.strip()
        ]

    def set_mode(mode: str, **extra):
        mode_path.write_text(json.dumps({'mode': mode, **extra}), encoding='utf-8')

    return SimpleNamespace(
        script=script,
        log_path=log_path,
        read_invocations=read_invocations,
        set_mode=set_mode,
    )


from types import SimpleNamespace


def test_kit_list_happy_path(fake_cli):
    bridge = load_submodule('componentize_bridge')
    res = bridge.kit_list()
    assert res['status'] == 'ok'
    assert res['exit'] == 0
    assert isinstance(res['notice'], str) and '\n' not in res['notice']
    expected = json.loads((FIXTURES_DIR / 'list.json').read_text(encoding='utf-8'))
    assert res['data'] == expected
    ids = [k['id'] for k in expected['kits']]
    assert ids == sorted(ids) and {'component-library', 'game-assets', 'video-production'} <= set(ids)
    assert [k['id'] for k in res['data']['kits']] == [k['id'] for k in expected['kits']]

    invocations = fake_cli.read_invocations()
    assert len(invocations) == 1
    assert invocations[0]['argv'] == ['kit', 'list', '--json']
    assert os.path.realpath(invocations[0]['cwd']) == os.path.realpath(tempfile.gettempdir())


def test_kit_show_happy_path(fake_cli):
    bridge = load_submodule('componentize_bridge')
    res = bridge.kit_show('video-production')
    assert res['status'] == 'ok'
    assert res['exit'] == 0
    assert isinstance(res['notice'], str) and '\n' not in res['notice']
    expected = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    assert res['data'] == expected

    invocations = fake_cli.read_invocations()
    assert len(invocations) == 1
    assert invocations[0]['argv'] == ['kit', 'show', 'video-production', '--json']
    assert os.path.realpath(invocations[0]['cwd']) == os.path.realpath(tempfile.gettempdir())


def test_kit_apply_happy_path_and_set_forwarding(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'workspace' / 'new-video-proj'
    dest.parent.mkdir(parents=True)
    res = bridge.kit_apply(
        'video-production',
        dest,
        variables={'fps': '24', 'aspect': '16:9'},
    )
    assert res['status'] == 'ok'
    assert res['exit'] == 0
    expected = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    expected['root'] = expected['root'].replace('/ROOT', str(dest))
    assert res['data'] == expected
    assert res['data']['ok'] is True
    assert res['data']['status'] == 'pass'
    assert res['data']['kit'] == 'video-production'
    assert res['data']['root'] == str(dest)

    invocations = fake_cli.read_invocations()
    assert len(invocations) == 1
    argv = invocations[0]['argv']
    assert argv[:4] == ['kit', 'apply', 'video-production', str(dest)]
    assert argv[-1] == '--json'
    middle = argv[4:-1]
    assert middle == ['--set', 'fps=24', '--set', 'aspect=16:9'] or middle == [
        '--set', 'aspect=16:9', '--set', 'fps=24'
    ]
    assert os.path.realpath(invocations[0]['cwd']) == os.path.realpath(dest.parent)


def test_kit_check_happy_path(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'existing-proj'
    dest.mkdir()
    res = bridge.kit_check('video-production', dest)
    assert res['status'] == 'ok'
    assert res['exit'] == 0
    expected = json.loads((FIXTURES_DIR / 'check.json').read_text(encoding='utf-8'))
    expected['root'] = expected['root'].replace('/ROOT', str(dest))
    assert res['data'] == expected
    assert res['data']['status'] == 'pass'
    assert res['data']['root'] == str(dest)

    invocations = fake_cli.read_invocations()
    assert len(invocations) == 1
    assert invocations[0]['argv'] == ['kit', 'check', 'video-production', str(dest), '--json']
    assert os.path.realpath(invocations[0]['cwd']) == os.path.realpath(dest.parent)


def test_kit_check_exit_1_with_valid_fail_envelope_is_ok(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('check_fail')
    dest = tmp_path / 'incomplete-proj'
    dest.mkdir()
    res = bridge.kit_check('video-production', dest)
    assert res['status'] == 'ok'
    assert res['exit'] == 1
    assert res['data'] is not None
    assert res['data']['ok'] is False
    assert res['data']['status'] == 'fail'
    assert len(res['data']['findings']) == 1


def test_absent_cli_returns_unavailable(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    settings = load_submodule('componentize_settings')
    monkeypatch.setattr(settings, 'load', lambda: settings.DEFAULTS.copy())
    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: None)

    dest = tmp_path / 'proj'
    for call in (
        lambda: bridge.kit_list(),
        lambda: bridge.kit_show('video-production'),
        lambda: bridge.kit_apply('video-production', dest),
        lambda: bridge.kit_check('video-production', dest),
    ):
        res = call()
        assert res['status'] == 'unavailable'
        assert res['data'] is None
        assert res['exit'] is None
        assert isinstance(res['notice'], str) and res['notice']


def test_exit_2_returns_error(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('exit2')
    res = bridge.kit_show('video-production')
    assert res['status'] == 'error'
    assert res['exit'] == 2
    assert res['data'] is None
    assert 'unknown kit' in res['notice'] or 'exit' in res['notice'].lower()


def test_invalid_json_returns_error(fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('bad_json')
    res = bridge.kit_list()
    assert res['status'] == 'error'
    assert res['data'] is None
    assert res['exit'] == 0
    assert 'json' in res['notice'].lower()


def test_wrong_schema_returns_error(fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('wrong_schema')
    res = bridge.kit_list()
    assert res['status'] == 'error'
    assert res['data'] is None
    assert 'schema' in res['notice'].lower() or 'envelope' in res['notice'].lower()


@pytest.mark.parametrize(
    'bad_dir',
    ['../escape', '/abs/path', 'a/../b', 'a\\b', '.', ''],
)
def test_unsafe_dir_in_declared_dirs_returns_error(fake_cli, bad_dir):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('unsafe_dir', unsafe_dir_value=bad_dir)
    res = bridge.kit_show('video-production')
    assert res['status'] == 'error'
    assert res['data'] is None
    assert 'envelope' in res['notice'].lower() or 'declared_dirs' in res['notice'].lower() or 'dir' in res['notice'].lower()


@pytest.mark.parametrize(
    'bad_dir',
    ['../escape', '/abs/path', 'a\\b', '.', ''],
)
def test_unsafe_dest_dir_in_placement_rules_returns_error(fake_cli, bad_dir):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('unsafe_dest_dir', unsafe_dir_value=bad_dir)
    res = bridge.kit_show('video-production')
    assert res['status'] == 'error'
    assert res['data'] is None


@pytest.mark.parametrize(
    'bad_id',
    ['', 'Video', 'video_prod', '-video', 'video-', 'video--prod', '../etc', 'a/b', 'a b', 'abc\n', 123],
)
def test_bad_kit_id_rejected_without_spawning(tmp_path, fake_cli, monkeypatch, bad_id):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: pytest.fail('should not probe CLI on bad kit_id'))
    for fn in (
        lambda: bridge.kit_show(bad_id),
        lambda: bridge.kit_apply(bad_id, tmp_path / 'dest'),
        lambda: bridge.kit_check(bad_id, tmp_path / 'dest'),
    ):
        res = fn()
        assert res == {
            'status': 'error',
            'data': None,
            'notice': res['notice'],
            'exit': None,
        }
        assert 'kit_id' in res['notice'] or 'kit id' in res['notice'].lower()
    assert fake_cli.read_invocations() == []


@pytest.mark.parametrize(
    'bad_dest',
    ['relative/path', './relative', '../up', '/abs/with/../dotdot', ''],
)
def test_bad_dest_rejected_without_spawning(fake_cli, monkeypatch, bad_dest):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: pytest.fail('should not probe CLI on bad dest'))
    for fn in (
        lambda: bridge.kit_apply('video-production', bad_dest),
        lambda: bridge.kit_check('video-production', bad_dest),
    ):
        res = fn()
        assert res['status'] == 'error'
        assert res['data'] is None
        assert res['exit'] is None
        assert 'dest' in res['notice'].lower() or 'path' in res['notice'].lower()
    assert fake_cli.read_invocations() == []


def test_missing_dest_parent_rejected_without_spawning(tmp_path, fake_cli, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: pytest.fail('should not probe CLI when parent missing'))
    dest = tmp_path / 'nonexistent_parent' / 'child'
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'error'
    assert res['data'] is None
    assert res['exit'] is None
    assert fake_cli.read_invocations() == []


@pytest.mark.parametrize(
    'bad_vars',
    [
        ['not-a-dict'],
        {'': 'val'},
        {'bad=key': 'val'},
        {'key\nnewline': 'val'},
        {'abc\n': 'val'},
        {'key': 'line1\nline2'},
        {'key': 'line1\rline2'},
        {'key': 123},
        {123: 'val'},
    ],
)
def test_bad_variables_rejected_without_spawning(tmp_path, fake_cli, monkeypatch, bad_vars):
    bridge = load_submodule('componentize_bridge')
    monkeypatch.setattr(bridge, 'detect_command', lambda *a, **kw: pytest.fail('should not probe CLI on bad variables'))
    res = bridge.kit_apply('video-production', tmp_path / 'dest', variables=bad_vars)
    assert res['status'] == 'error'
    assert res['data'] is None
    assert res['exit'] is None
    assert fake_cli.read_invocations() == []


def test_output_over_byte_cap_returns_error(fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('oversized')
    res = bridge.kit_list()
    assert res['status'] == 'error'
    assert res['data'] is None
    assert res['exit'] is None
    assert 'size' in res['notice'].lower() or 'limit' in res['notice'].lower()


def test_valid_kit_envelope_rejects_shape_violations(fake_cli):
    bridge = load_submodule('componentize_bridge')
    # Extra keys are tolerated
    list_ok = json.loads((FIXTURES_DIR / 'list.json').read_text(encoding='utf-8'))
    list_ok['extra_field'] = 123
    list_ok['kits'][0]['extra_kit_field'] = 'allowed'
    assert bridge._valid_kit_envelope(list_ok, 'list') is True

    # Bool version is rejected (type(version) is int)
    bad_ver = json.loads((FIXTURES_DIR / 'list.json').read_text(encoding='utf-8'))
    bad_ver['kits'][0]['version'] = True
    assert bridge._valid_kit_envelope(bad_ver, 'list') is False

    # Non-bool ok is rejected
    bad_ok = json.loads((FIXTURES_DIR / 'list.json').read_text(encoding='utf-8'))
    bad_ok['ok'] = 1
    assert bridge._valid_kit_envelope(bad_ok, 'list') is False

    # Placement rule with empty match_ext or ext without leading dot is rejected
    bad_pr = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    bad_pr['placement_rules'][0]['match_ext'] = ['png']
    assert bridge._valid_kit_envelope(bad_pr, 'show') is False

    bad_pr2 = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    bad_pr2['placement_rules'][0]['match_ext'] = []
    assert bridge._valid_kit_envelope(bad_pr2, 'show') is False

    # Non-bool lfs in placement_rules is rejected
    bad_lfs = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    bad_lfs['placement_rules'][0]['lfs'] = 1
    assert bridge._valid_kit_envelope(bad_lfs, 'show') is False

    # Missing agents_block in show is rejected
    bad_show = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    del bad_show['agents_block']
    assert bridge._valid_kit_envelope(bad_show, 'show') is False

    # Missing items in apply/check is rejected
    bad_apply = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    del bad_apply['items']
    assert bridge._valid_kit_envelope(bad_apply, 'apply') is False


def test_run_cli_timeout_returns_error(fake_cli, monkeypatch):
    import subprocess
    bridge = load_submodule('componentize_bridge')
    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(['kit'], 60)
    monkeypatch.setattr(bridge, '_run_cli', boom)
    res = bridge.kit_list()
    assert res == {
        'status': 'error',
        'data': None,
        'notice': res['notice'],
        'exit': None,
    }
    assert 'timed out' in res['notice'].lower()
    assert 'survey' not in res['notice'].lower()


def test_kit_apply_exit_1_with_valid_fail_envelope_is_ok(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('apply_fail')
    dest = tmp_path / 'conflict-proj'
    dest.parent.mkdir(parents=True, exist_ok=True)
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'ok'
    assert res['exit'] == 1
    assert res['data'] is not None
    assert res['data']['ok'] is False
    assert res['data']['status'] == 'fail'
    assert len(res['data']['findings']) == 1
    assert res['data']['findings'][0]['id'] == 'conflict-file'


def test_exit_0_with_fail_envelope_returns_error(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'proj'
    payload = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    payload['ok'] = False
    payload['status'] = 'fail'
    payload['kit'] = 'video-production'
    payload['root'] = str(dest)
    fake_cli.set_mode('custom_payload', payload=payload, exit_code=0)
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'error'
    assert res['data'] is None
    assert res['exit'] == 0


def test_exit_1_with_pass_envelope_returns_error(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'proj'
    payload = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    payload['ok'] = True
    payload['status'] = 'pass'
    payload['kit'] = 'video-production'
    payload['root'] = str(dest)
    fake_cli.set_mode('custom_payload', payload=payload, exit_code=1)
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'error'
    assert res['data'] is None
    assert res['exit'] == 1


def test_exit_1_for_list_and_show_returns_error(fake_cli):
    bridge = load_submodule('componentize_bridge')
    list_payload = json.loads((FIXTURES_DIR / 'list.json').read_text(encoding='utf-8'))
    list_payload['ok'] = False
    list_payload['status'] = 'fail'
    fake_cli.set_mode('custom_payload', payload=list_payload, exit_code=1)
    res_list = bridge.kit_list()
    assert res_list['status'] == 'error'
    assert res_list['data'] is None
    assert res_list['exit'] == 1

    show_payload = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    show_payload['ok'] = False
    show_payload['status'] = 'fail'
    fake_cli.set_mode('custom_payload', payload=show_payload, exit_code=1)
    res_show = bridge.kit_show('video-production')
    assert res_show['status'] == 'error'
    assert res_show['data'] is None
    assert res_show['exit'] == 1


def test_kit_id_mismatch_in_apply_and_check_reply_returns_error(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'proj'
    payload = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    payload['kit'] = 'wrong-kit'
    payload['root'] = str(dest)
    fake_cli.set_mode('custom_payload', payload=payload, exit_code=0)

    res_apply = bridge.kit_apply('video-production', dest)
    assert res_apply['status'] == 'error'
    assert res_apply['data'] is None
    assert 'did not match' in res_apply['notice'].lower()

    res_check = bridge.kit_check('video-production', dest)
    assert res_check['status'] == 'error'
    assert res_check['data'] is None
    assert 'did not match' in res_check['notice'].lower()


def test_root_mismatch_in_apply_and_check_reply_returns_error(tmp_path, fake_cli):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'proj'
    payload = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    payload['kit'] = 'video-production'
    payload['root'] = str(tmp_path / 'other-proj')
    fake_cli.set_mode('custom_payload', payload=payload, exit_code=0)

    res_apply = bridge.kit_apply('video-production', dest)
    assert res_apply['status'] == 'error'
    assert res_apply['data'] is None
    assert 'did not match' in res_apply['notice'].lower()

    res_check = bridge.kit_check('video-production', dest)
    assert res_check['status'] == 'error'
    assert res_check['data'] is None
    assert 'did not match' in res_check['notice'].lower()


def test_show_kit_id_mismatch_returns_error(fake_cli):
    bridge = load_submodule('componentize_bridge')
    payload = json.loads((FIXTURES_DIR / 'show.json').read_text(encoding='utf-8'))
    payload['kit']['id'] = 'different-kit'
    fake_cli.set_mode('custom_payload', payload=payload, exit_code=0)
    res = bridge.kit_show('video-production')
    assert res['status'] == 'error'
    assert res['data'] is None
    assert 'did not match' in res['notice'].lower()


@pytest.mark.parametrize(
    'bad_item',
    [
        {'path': '../escape', 'state': 'created'},
        {'path': '/abs/path', 'state': 'created'},
        {'path': 'a/../b', 'state': 'created'},
        {'path': 'a\\b', 'state': 'created'},
        {'path': '.', 'state': 'created'},
        {'path': '', 'state': 'created'},
        {'path': 123, 'state': 'created'},
        {'path': 'assets/generated', 'state': ''},
        {'path': 'assets/generated', 'state': 123},
        {'path': 'assets/generated'},
    ],
)
def test_unsafe_or_invalid_items_path_in_apply_returns_error(tmp_path, fake_cli, bad_item):
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'proj'
    payload = json.loads((FIXTURES_DIR / 'apply.json').read_text(encoding='utf-8'))
    payload['kit'] = 'video-production'
    payload['root'] = str(dest)
    payload['items'] = [bad_item]
    fake_cli.set_mode('custom_payload', payload=payload, exit_code=0)
    res = bridge.kit_apply('video-production', dest)
    assert res['status'] == 'error'
    assert res['data'] is None


def test_stdin_closed_gets_eof_immediately(fake_cli, monkeypatch):
    import subprocess
    import time
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('read_stdin')
    # Replace fd 0 temporarily with an open pipe so that without stdin=DEVNULL,
    # a child inheriting fd 0 and calling sys.stdin.read() would block forever.
    r_fd, w_fd = os.pipe()
    saved_stdin = os.dup(0)
    try:
        os.dup2(r_fd, 0)
        t0 = time.monotonic()
        # Use a short timeout in _run_cli so that if stdin is NOT closed, it times out quickly
        orig_run_cli = bridge._run_cli
        monkeypatch.setattr(
            bridge,
            '_run_cli',
            lambda command, args, *, cwd, timeout=60: orig_run_cli(command, args, cwd=cwd, timeout=2),
        )
        res = bridge.kit_list()
        elapsed = time.monotonic() - t0
        assert res['status'] == 'ok'
        assert elapsed < 1.5
        assert res['data']['stdin_len'] == 0
    finally:
        os.dup2(saved_stdin, 0)
        os.close(saved_stdin)
        os.close(r_fd)
        os.close(w_fd)


def test_probe_passes_stdin_devnull(monkeypatch):
    import subprocess
    bridge = load_submodule('componentize_bridge')
    assert not hasattr(bridge, '_ORIG_PROBE')
    seen_kwargs = {}

    def fake_run(cmd, **kwargs):
        seen_kwargs.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout='componentize 2.0.0\n', stderr='')

    monkeypatch.setattr(bridge.subprocess, 'run', fake_run)
    ok, ver = bridge._probe(['/usr/bin/componentize'])
    assert ok is True
    assert ver == 'componentize 2.0.0'
    assert seen_kwargs.get('stdin') == subprocess.DEVNULL


def test_oversized_kit_output_notice_does_not_contain_survey(fake_cli):
    bridge = load_submodule('componentize_bridge')
    assert bridge.MAX_CLI_OUTPUT_BYTES == bridge.MAX_SURVEY_BYTES
    assert bridge.UNAVAILABLE_NOTICE == 'componentize CLI is unavailable'
    assert 'resolve once' not in (bridge.detect_command.__doc__ or '').lower()
    fake_cli.set_mode('oversized')
    res = bridge.kit_list()
    assert res['status'] == 'error'
    assert 'size' in res['notice'].lower() or 'limit' in res['notice'].lower()
    assert 'survey' not in res['notice'].lower()


def test_long_error_on_exit_2_yields_bounded_single_line_notice(fake_cli):
    bridge = load_submodule('componentize_bridge')
    fake_cli.set_mode('exit2_long_error')
    res = bridge.kit_show('video-production')
    assert res['status'] == 'error'
    assert res['exit'] == 2
    assert isinstance(res['notice'], str)
    assert '\n' not in res['notice']
    assert '\r' not in res['notice']
    assert len(res['notice']) <= 240
    assert res['notice'].endswith('...') or res['notice'].endswith('…')


def test_bridge_kit_calls_and_probe_respect_and_cap_timeout_and_fail_before_spawning(
    tmp_path, fake_cli, monkeypatch
):
    import subprocess
    bridge = load_submodule('componentize_bridge')
    dest = tmp_path / 'proj'
    dest.parent.mkdir(parents=True, exist_ok=True)

    probe_timeouts = []
    orig_subproc_run = bridge.subprocess.run

    def recording_probe_run(cmd, **kwargs):
        probe_timeouts.append(kwargs.get('timeout'))
        return orig_subproc_run(cmd, **kwargs)

    monkeypatch.setattr(bridge.subprocess, 'run', recording_probe_run)

    cli_timeouts = []
    orig_run_cli = bridge._run_cli

    def recording_run_cli(command, args, *, cwd, timeout=60):
        cli_timeouts.append(timeout)
        return orig_run_cli(command, args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(bridge, '_run_cli', recording_run_cli)

    # 1. Default (None) uses existing caps: 15s for probe, <=60s remaining for CLI
    assert bridge.kit_list()['status'] == 'ok'
    assert probe_timeouts[-1] == 15.0
    assert 0 < cli_timeouts[-1] <= 60.0

    # 2. Short timeout (e.g. 4.5s) shares one deadline across probe and CLI
    assert bridge.kit_show('video-production', timeout=4.5)['status'] == 'ok'
    assert 0 < probe_timeouts[-1] <= 4.5
    assert 0 < cli_timeouts[-1] <= probe_timeouts[-1]

    # 3. Large timeout (e.g. 120s) is capped at 15s for probe and 60s for CLI
    assert bridge.kit_apply('video-production', dest, timeout=120.0)['status'] == 'ok'
    assert probe_timeouts[-1] == 15.0
    assert cli_timeouts[-1] == 60.0

    assert bridge.kit_check('video-production', dest, timeout=8.25)['status'] == 'ok'
    assert 0 < probe_timeouts[-1] <= 8.25
    assert 0 < cli_timeouts[-1] <= probe_timeouts[-1]

    # 4. Non-positive timeout fails with timed out notice BEFORE spawning probe or CLI
    probe_count_before = len(probe_timeouts)
    cli_count_before = len(cli_timeouts)
    for call_fn in (
        lambda: bridge.kit_list(timeout=0),
        lambda: bridge.kit_show('video-production', timeout=-1.0),
        lambda: bridge.kit_apply('video-production', dest, timeout=0.0),
        lambda: bridge.kit_check('video-production', dest, timeout=-0.5),
    ):
        res = call_fn()
        assert res['status'] == 'error'
        assert 'timed out' in res['notice'].lower()
    assert len(probe_timeouts) == probe_count_before
    assert len(cli_timeouts) == cli_count_before
    assert bridge._probe(['/usr/bin/componentize'], timeout=0) == (False, None)
    assert len(probe_timeouts) == probe_count_before


def test_one_deadline_per_kit_call_and_probe_timeout_notice(tmp_path, monkeypatch):
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
    monkeypatch.setattr(
        settings,
        'load',
        lambda: {**settings.DEFAULTS, 'cli_path_override': None},
    )

    now = [100.0]
    monkeypatch.setattr(bridge.time, 'monotonic', lambda: now[0])

    # Scenario 1: Hanging runner where each spawned step uses its full handed timeout
    # and raises TimeoutExpired. With timeout=5.0, total handed timeouts must sum to <= 5.0
    # (never [5, 5, 5]), and the result must report a timeout rather than 'unavailable'.
    handed_timeouts: list[float] = []

    def hanging_probe_run(cmd, **kwargs):
        t = float(kwargs['timeout'])
        handed_timeouts.append(t)
        now[0] += t
        raise subprocess.TimeoutExpired(cmd, t)

    def hanging_run_cli(command, args, *, cwd, timeout=60.0):
        t = float(timeout)
        handed_timeouts.append(t)
        now[0] += t
        raise subprocess.TimeoutExpired([*command, *args], t)

    monkeypatch.setattr(bridge.subprocess, 'run', hanging_probe_run)
    monkeypatch.setattr(bridge, '_run_cli', hanging_run_cli)

    res_hang = bridge.kit_list(timeout=5.0)
    assert handed_timeouts == [5.0]
    assert sum(handed_timeouts) <= 5.0
    assert res_hang['status'] != 'unavailable'
    assert res_hang['status'] == 'error'
    assert 'Project kits check timed out' in res_hang['notice']

    # Scenario 2: Two probes + CLI run under one 5.0s deadline:
    # probe 1 ('hermes componentize --version') takes 2.0s and exits 1;
    # probe 2 ('componentize --version') gets remaining 3.0s, takes 1.5s and exits 0;
    # _run_cli gets remaining 1.5s (not 5.0s).
    now[0] = 200.0
    step_timeouts: list[float] = []
    list_payload = (FIXTURES_DIR / 'list.json').read_text(encoding='utf-8')

    def stepped_probe_run(cmd, **kwargs):
        t = float(kwargs['timeout'])
        step_timeouts.append(t)
        if Path(cmd[0]).name == 'hermes':
            now[0] += 2.0
            return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='no subcommand')
        now[0] += 1.5
        return subprocess.CompletedProcess(cmd, 0, stdout='componentize 2.0.0\n', stderr='')

    def stepped_run_cli(command, args, *, cwd, timeout=60.0):
        t = float(timeout)
        step_timeouts.append(t)
        now[0] += 1.0
        return subprocess.CompletedProcess([*command, *args], 0, stdout=list_payload, stderr='')

    monkeypatch.setattr(bridge.subprocess, 'run', stepped_probe_run)
    monkeypatch.setattr(bridge, '_run_cli', stepped_run_cli)

    res_ok = bridge.kit_list(timeout=5.0)
    assert res_ok['status'] == 'ok'
    assert step_timeouts == [5.0, 3.0, 1.5]

    # Scenario 3: Probes exhaust the 5.0s budget before _run_cli -> _run_cli is never spawned
    now[0] = 300.0
    exhausted_timeouts: list[float] = []
    cli_called = []

    def exhausting_probe_run(cmd, **kwargs):
        t = float(kwargs['timeout'])
        exhausted_timeouts.append(t)
        if Path(cmd[0]).name == 'hermes':
            now[0] += 2.0
            return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='')
        now[0] += 3.0
        return subprocess.CompletedProcess(cmd, 0, stdout='componentize 2.0.0\n', stderr='')

    def forbidden_run_cli(command, args, *, cwd, timeout=60.0):
        cli_called.append(timeout)
        raise AssertionError('_run_cli must not be spawned when deadline is exhausted')

    monkeypatch.setattr(bridge.subprocess, 'run', exhausting_probe_run)
    monkeypatch.setattr(bridge, '_run_cli', forbidden_run_cli)

    res_exhausted = bridge.kit_list(timeout=5.0)
    assert cli_called == []
    assert exhausted_timeouts == [5.0, 3.0]
    assert res_exhausted['status'] == 'error'
    assert 'Project kits check timed out' in res_exhausted['notice']

    # Scenario 4: Override probe timing out reports timeout ('error'), never 'unavailable'
    now[0] = 400.0
    monkeypatch.setattr(
        settings,
        'load',
        lambda: {**settings.DEFAULTS, 'cli_path_override': str(bin_dir / 'componentize')},
    )
    monkeypatch.setattr(bridge.subprocess, 'run', hanging_probe_run)
    handed_timeouts.clear()
    res_override_timeout = bridge.kit_show('video-production', timeout=4.0)
    assert handed_timeouts == [4.0]
    assert sum(handed_timeouts) <= 4.0
    assert res_override_timeout['status'] == 'error'
    assert 'Project kits check timed out' in res_override_timeout['notice']
    assert 'unavailable' not in res_override_timeout['notice'].lower()

    # Scenario 5: First candidate probe times out while time remains, second candidate succeeds -> second is used
    now[0] = 500.0
    monkeypatch.setattr(
        settings,
        'load',
        lambda: {**settings.DEFAULTS, 'cli_path_override': None},
    )
    probe_seq: list[tuple[str, float]] = []

    def first_timeout_second_ok_probe(cmd, **kwargs):
        t = float(kwargs['timeout'])
        probe_seq.append((Path(cmd[0]).name, t))
        if Path(cmd[0]).name == 'hermes':
            now[0] += 2.0
            raise subprocess.TimeoutExpired(cmd, 2.0)
        now[0] += 1.0
        return subprocess.CompletedProcess(cmd, 0, stdout='componentize 2.0.0\n', stderr='')

    monkeypatch.setattr(bridge.subprocess, 'run', first_timeout_second_ok_probe)
    monkeypatch.setattr(bridge, '_run_cli', stepped_run_cli)
    step_timeouts.clear()

    det_res = bridge.detect_command(timeout=5.0)
    assert det_res == ([str(bin_dir / 'componentize')], 'path', 'componentize 2.0.0')
    assert probe_seq == [('hermes', 5.0), ('componentize', 3.0)]

    now[0] = 600.0
    probe_seq.clear()
    step_timeouts.clear()
    res_fallback = bridge.kit_list(timeout=5.0)
    assert res_fallback['status'] == 'ok'
    assert probe_seq == [('hermes', 5.0), ('componentize', 3.0)]
    assert step_timeouts == [2.0]

    # Scenario 6: First candidate times out with time remaining, second candidate fails non-zero (absent) -> 'timeout'
    now[0] = 700.0
    probe_seq.clear()

    def first_timeout_second_nonzero_probe(cmd, **kwargs):
        t = float(kwargs['timeout'])
        probe_seq.append((Path(cmd[0]).name, t))
        if Path(cmd[0]).name == 'hermes':
            now[0] += 2.0
            raise subprocess.TimeoutExpired(cmd, 2.0)
        now[0] += 1.0
        raise FileNotFoundError('gone')

    monkeypatch.setattr(bridge.subprocess, 'run', first_timeout_second_nonzero_probe)
    assert bridge.detect_command(timeout=5.0) == (None, 'timeout', None)
    assert probe_seq == [('hermes', 5.0), ('componentize', 3.0)]

    # Scenario 7: All candidates time out -> 'timeout'; none exist -> 'absent'
    now[0] = 800.0
    probe_seq.clear()

    def both_timeout_probe(cmd, **kwargs):
        t = float(kwargs['timeout'])
        probe_seq.append((Path(cmd[0]).name, t))
        now[0] += 2.0
        raise subprocess.TimeoutExpired(cmd, 2.0)

    monkeypatch.setattr(bridge.subprocess, 'run', both_timeout_probe)
    assert bridge.detect_command(timeout=5.0) == (None, 'timeout', None)
    assert probe_seq == [('hermes', 5.0), ('componentize', 3.0)]

    monkeypatch.setattr(bridge.shutil, 'which', lambda name, **kw: None)
    assert bridge.detect_command(timeout=5.0) == (None, 'absent', None)


def test_child_env_strips_approval_and_session_vars_while_preserving_runtime_vars(
    fake_cli, monkeypatch
):
    import subprocess
    bridge = load_submodule('componentize_bridge')

    stripped_vars = {
        'HERMES_YOLO_MODE': '1',
        'HERMES_EXEC_ASK': '1',
        'HERMES_INTERACTIVE': '1',
        'HERMES_NONINTERACTIVE': '1',
        'HERMES_QUIET': '1',
        'HERMES_SPINNER_PAUSE': '1',
        'HERMES_SINGLE_QUERY_SESSION': '1',
        'HERMES_CRON_SESSION': '1',
        'HERMES_GATEWAY_SESSION': '1',
        '_HERMES_GATEWAY': '1',
        'HERMES_ACP_AUTO_APPROVE': '1',
        'HERMES_DELEGATED_CHILD_CONTEXT': '1',
        'HERMES_UI_SESSION_ID': 'ui-123',
        'HERMES_SESSION_KEY': 'sess-key',
        'HERMES_SESSION_ID': 'sess-id',
        'HERMES_SESSION_PLATFORM': 'webhook',
        'HERMES_SESSION_SOURCE': 'cli',
        'HERMES_SESSION_SOURCE_EXPLICIT': '1',
        'HERMES_SESSION_CHAT_ID': 'chat-1',
        'HERMES_CRON_AUTO_DELIVER_PLATFORM': 'telegram',
        'HERMES_KANBAN_TASK': 'task-1',
        'HERMES_KANBAN_RUN_ID': '1',
        'HERMES_KANBAN_CLAIM_LOCK': 'lock-1',
        'HERMES_KANBAN_GOAL_MODE': '1',
        'HERMES_KANBAN_GOAL_MAX_TURNS': '5',
        'HERMES_ACCEPT_HOOKS': '1',
        'HERMES_DASHBOARD_SESSION_TOKEN': 'tok-123',
        'HERMES_PLATFORM': 'webhook',
        '_HERMES_CRON_EXTERNAL_WORKER': 'exec-1',
        'HERMES_KANBAN_BOARD': 'board-1',
        'HERMES_KANBAN_DB': '/home/user/kanban.db',
        'HERMES_KANBAN_HOME': '/home/user/kanban',
        'SUDO_PASSWORD': 'secret',
        'HERMES_ALLOW_PRIVATE_URLS': 'true',
    }
    for k, v in stripped_vars.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv('HERMES_PROFILE', 'work')
    monkeypatch.setenv('HERMES_DESKTOP', '1')
    monkeypatch.setenv('LANG', 'C.UTF-8')
    monkeypatch.setenv('VIRTUAL_ENV', '/home/user/.venv')

    child_env = bridge._child_env()
    for k in stripped_vars:
        assert k not in child_env, f'{k} must be stripped from _child_env()'
    for keep_key in ('PATH', 'HOME', 'HERMES_HOME', 'HERMES_PROFILE', 'HERMES_DESKTOP', 'LANG', 'VIRTUAL_ENV'):
        assert child_env.get(keep_key) == os.environ.get(keep_key)

    # Probe and _run_cli pass the stripped env to subprocess.run / subprocess.Popen
    seen_envs: list[dict[str, str]] = []
    orig_run = bridge.subprocess.run

    def recording_run(cmd, **kwargs):
        assert kwargs.get('stdin') == subprocess.DEVNULL
        assert kwargs.get('shell') in (None, False)
        seen_envs.append(dict(kwargs['env']))
        return orig_run(cmd, **kwargs)

    orig_run_cli = bridge._run_cli
    orig_popen = bridge.subprocess.Popen

    def recording_popen(argv, **kwargs):
        assert kwargs.get('stdin') == subprocess.DEVNULL
        assert kwargs.get('shell') in (None, False)
        seen_envs.append(dict(kwargs['env']))
        return orig_popen(argv, **kwargs)

    monkeypatch.setattr(bridge.subprocess, 'run', recording_run)
    monkeypatch.setattr(bridge.subprocess, 'Popen', recording_popen)

    res = bridge.kit_list()
    assert res['status'] == 'ok'
    assert len(seen_envs) >= 2
    for env_dict in seen_envs:
        for k in stripped_vars:
            assert k not in env_dict
        for keep_key in ('PATH', 'HOME', 'HERMES_HOME', 'HERMES_PROFILE', 'HERMES_DESKTOP', 'LANG', 'VIRTUAL_ENV'):
            assert env_dict.get(keep_key) == os.environ.get(keep_key)



