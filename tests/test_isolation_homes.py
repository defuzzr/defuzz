"""Exercise isolation using synthetic roots; never access protected homes."""
import os
import subprocess
from pathlib import Path

import pytest

from tests import conftest


def _hook(tmp_path, **overrides):
    return conftest._build_home_tripwire(
        tmp_path, protected=overrides.get('_PROTECTED', (str(tmp_path / 'protected'),)),
        git_roots=overrides.get('_GIT_READ_ROOTS', (str(tmp_path / 'protected/git'),)),
        violations=[],
    )


@pytest.mark.parametrize('iteration', range(2))
def test_home_is_fresh(iteration):
    sentinel = Path(os.environ['HOME']) / 'isolation-sentinel'
    assert not sentinel.exists()
    sentinel.touch()


@pytest.mark.parametrize('event', [
    'open', 'os.listdir', 'os.scandir', 'sqlite3.connect', 'os.remove',
    'os.rename', 'os.mkdir', 'os.rmdir', 'shutil.rmtree', 'os.chdir',
    'os.link', 'os.symlink', 'os.truncate', 'os.chmod', 'os.chown', 'os.utime',
])
@pytest.mark.parametrize('which', ['protected/file', 'protected/git/HEAD'])
def test_audit_blocks_access(tmp_path, event, which):
    path = str(tmp_path / which)
    args = (path, 'w', os.O_WRONLY) if event == 'open' else (path,)
    with pytest.raises(AssertionError, match='REAL-HOME TRIPWIRE'):
        _hook(tmp_path)(event, args)


@pytest.mark.parametrize('event', ['os.rename', 'os.link', 'os.symlink'])
def test_destination_is_checked(tmp_path, event):
    with pytest.raises(AssertionError, match='REAL-HOME TRIPWIRE'):
        _hook(tmp_path)(event, (str(tmp_path / 'safe'), str(tmp_path / 'protected/dst')))


@pytest.mark.parametrize('mode,flags', [('w', 0), ('a', 0), ('x', 0), ('r+', 0),
    (None, os.O_WRONLY), (None, os.O_RDWR), (None, os.O_CREAT),
    (None, os.O_TRUNC), (None, os.O_APPEND)])
def test_git_writes_are_blocked(tmp_path, mode, flags):
    with pytest.raises(AssertionError):
        _hook(tmp_path)('open', (str(tmp_path / 'protected/git/HEAD'), mode, flags))


def test_git_symlink_cannot_escape_allowance(tmp_path):
    git = tmp_path / 'protected/git'
    git.mkdir(parents=True)
    (git / 'HEAD').symlink_to(tmp_path / 'protected/secret')
    with pytest.raises(AssertionError):
        _hook(tmp_path)('open', (str(git / 'HEAD'), 'r', 0))


def test_nonprotected_workdir_is_allowed(tmp_path):
    _hook(tmp_path)('open', (str(tmp_path / 'work/source.py'), 'w', os.O_WRONLY))


@pytest.mark.parametrize('operation', ['cwd', 'dir_fd'])
def test_hook_survives_unresolvable_paths(tmp_path, monkeypatch, operation):
    hook = _hook(tmp_path)
    def fail(*args):
        raise OSError('gone')
    if operation == 'cwd':
        with monkeypatch.context() as scoped:
            scoped.setattr(os, 'getcwd', fail)
            hook('os.listdir', (None,))
    else:
        with monkeypatch.context() as scoped:
            scoped.setattr(os, 'readlink', fail)
            hook('os.remove', ('relative', 12345))


def test_git_read_and_boundaries(tmp_path):
    hook = _hook(tmp_path)
    hook('open', (str(tmp_path / 'protected/git/HEAD'), 'r', os.O_RDONLY))
    with pytest.raises(AssertionError):
        hook('open', (str(tmp_path / 'protected/git-other/HEAD'), 'r', os.O_RDONLY))


@pytest.mark.parametrize('form', ['alias', 'real'])
def test_symlinked_protected_roots(tmp_path, form):
    real = tmp_path / 'real'
    real.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    hook = _hook(tmp_path, _PROTECTED=(str(alias),))
    with pytest.raises(AssertionError):
        hook('open', (str((alias if form == 'alias' else real) / 'file'), 'r', 0))


def test_symlinked_git_roots_are_read_only(tmp_path):
    real = tmp_path / 'protected/git'
    real.mkdir(parents=True)
    alias = tmp_path / 'git-alias'
    alias.symlink_to(real, target_is_directory=True)
    hook = _hook(tmp_path, _GIT_READ_ROOTS=(str(alias),))
    hook('open', (str(real / 'HEAD'), 'r', 0))
    with pytest.raises(AssertionError):
        hook('os.remove', (str(alias / 'HEAD'),))


def test_sqlite_uri_and_memory(tmp_path):
    hook = _hook(tmp_path)
    hook('sqlite3.connect', (':memory:',))
    hook('sqlite3.connect', ('file::memory:?cache=shared',))
    with pytest.raises(AssertionError):
        hook('sqlite3.connect', ((tmp_path / 'protected/a b.db').as_uri() + '?mode=ro',))


def test_listdir_none_checks_cwd(tmp_path, monkeypatch):
    root = tmp_path / 'protected'
    root.mkdir()
    monkeypatch.chdir(root)
    with pytest.raises(AssertionError):
        _hook(tmp_path)('os.listdir', (None,))


@pytest.mark.parametrize('failure', ['mismatch', 'non-git', 'missing'])
def test_git_discovery_fails_closed(tmp_path, monkeypatch, failure):
    def output(*args, **kwargs):
        if failure == 'non-git':
            raise subprocess.CalledProcessError(128, 'git')
        if failure == 'missing':
            raise FileNotFoundError('git')
        return str(tmp_path.parent)
    monkeypatch.setattr(conftest.subprocess, 'check_output', output)
    assert conftest._discover_git_read_roots(tmp_path) == ()


def test_own_git_metadata_is_readable():
    assert conftest._GIT_READ_ROOTS
    assert (Path(conftest._GIT_READ_ROOTS[0]) / 'HEAD').read_text().strip()


@pytest.mark.parametrize('failure', ['mismatch', 'non-git', 'missing'])
def test_collection_initialization_survives_git_failure(tmp_path, monkeypatch, failure):
    def output(*args, **kwargs):
        if failure == 'missing':
            raise FileNotFoundError('git')
        if failure == 'non-git':
            raise subprocess.CalledProcessError(128, 'git')
        return str(tmp_path.parent)
    monkeypatch.setattr(subprocess, 'check_output', output)
    hook = conftest._build_home_tripwire(tmp_path, protected=(str(tmp_path),), violations=[])
    assert hook.__globals__['_GIT_READ_ROOTS'] == ()
    with pytest.raises(AssertionError):
        hook('open', (str(tmp_path / 'git/HEAD'), 'r', 0))


def test_tmpdir_under_protected_root_fails(tmp_path):
    with pytest.raises(RuntimeError, match='TMPDIR.*protected'):
        conftest._check_tmpdir(str(tmp_path / 'protected/tmp'), (str(tmp_path / 'protected'),))
