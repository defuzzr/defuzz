"""Shell startup files zsh and bash read (the macOS default shell is zsh), and the
macOS homes of classes the audit already covers on Linux. Synthetic HOME only."""
import json
from itertools import islice
from pathlib import Path

import pytest

from tests.conftest import load_submodule
from tests.test_audit_outward_inventory_contracts import base, run, _no_host_system_gitconfig  # noqa: F401

ORIGINAL = ('.bashrc', '.profile', '.zshrc', '.bash_profile')
ADDED = ('.zshenv', '.zprofile', '.zlogin', '.zlogout', '.bash_login', '.bash_logout')


def _startup_home(tmp_path, relative, content):
    home, profile, project, other = base(tmp_path, git=True)
    target = project / 'tool.py'
    target.write_text('pass\n')
    source = home / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content.format(target=target))
    return source, target, run(profile, project, other)


@pytest.mark.parametrize('name', ADDED)
def test_added_shell_file_gives_the_same_finding_as_zshrc(tmp_path, name):
    source, target, r = _startup_home(tmp_path, name, 'source {target}')
    rows = [d for d in r['dynamic_invocations'] if d['path'] == str(source)]
    assert rows and rows[0]['trigger'] == 'user interpreter startup', r['dynamic_invocations']
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in r['blending'])


def test_zshrc_reference_finding_matches_added_name(tmp_path):
    """The added names reuse the .zshrc finding word for word."""
    first, _, a = _startup_home(tmp_path / 'a', '.zshrc', 'source {target}')
    second, _, b = _startup_home(tmp_path / 'b', '.zshenv', 'source {target}')
    old = [{k: v for k, v in d.items() if k != 'path'} for d in a['dynamic_invocations'] if d['path'] == str(first)]
    new = [{k: v for k, v in d.items() if k != 'path'} for d in b['dynamic_invocations'] if d['path'] == str(second)]
    assert old and old == new


def test_absent_added_files_give_nothing(tmp_path):
    home, profile, project, other = base(tmp_path, git=True)
    text = json.dumps(run(profile, project, other))
    for name in ADDED:
        assert str(home / name) not in text


def test_shell_names_come_from_one_list():
    file_types = load_submodule('audit.file_types')
    home_startup = load_submodule('audit.home_startup')
    names = file_types.SHELL_STARTUP_FILES
    assert names[:4] == ORIGINAL and set(names[4:]) == set(ADDED) and len(names) == 10
    found = [p.name for p in islice(home_startup.discover(Path('/h'), None, lambda r: None), len(names))]
    assert found == list(names)
    for name in (*names, '.pythonrc'):
        assert file_types.execution_trigger(Path('/h') / name) == 'user interpreter startup'


def test_macos_user_site_pth_is_found_like_linux(tmp_path):
    relative = 'Library/Python/3.12/lib/python/site-packages/demo.pth'
    source, target, r = _startup_home(tmp_path, relative, '{target}')
    assert any(d['path'] == str(source) for d in r['dynamic_invocations'])
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in r['blending'])


@pytest.mark.parametrize('name', ['sitecustomize.py', 'usercustomize.py'])
def test_macos_user_site_customize_is_found_like_linux(tmp_path, name):
    relative = 'Library/Python/3.12/lib/python/site-packages/' + name
    source, target, r = _startup_home(tmp_path, relative, 'PATH = "{target}"')
    assert any(d['path'] == str(source) for d in r['dynamic_invocations'])
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in r['blending'])


def test_macos_user_site_other_files_and_folders_are_not_read(tmp_path):
    relative = 'Library/Python/notaversion/lib/python/site-packages/demo.pth'
    source, _, r = _startup_home(tmp_path, relative, '{target}')
    assert str(source) not in json.dumps(r)
    source, _, r = _startup_home(tmp_path / 'b', 'Library/Python/3.12/lib/python/site-packages/plain.py', '{target}')
    assert str(source) not in json.dumps(r)


def test_macos_pip_conf_is_metadata_only_like_linux(tmp_path):
    relative = 'Library/Application Support/pip/pip.conf'
    source, _, r = _startup_home(tmp_path, relative, '[global]\nindex-url = {target}\n')
    assert any(c.get('kind') == 'credential_store' and c['path'] == str(source) for c in r['credentials'])
    assert not any(e['source'] == str(source) for e in r['blending'])
