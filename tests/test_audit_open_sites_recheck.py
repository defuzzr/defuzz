"""Every audit open site re-checks the OPENED file against the declared credentials.

The path check runs first; between it and the open, the file it allowed can be
replaced. Each case below wraps the site's own path check so that, right after it
answers 'allowed' for the file the site is about to read, the file is replaced:

- by a hard link to a declared credential (same inode: only a check of the open
  descriptor can tell),
- by a symbolic link to it (refused by the no-follow open),
- or its folder is replaced by a link to the folder holding a declared file of the
  same name (refused by the folder walk, or caught on the open descriptor).

The swap is deterministic: a dry run counts the site's path checks of that file,
the real run swaps right after the last one. A spy counts every byte read from the
declared file by (device, inode), never by path spelling.
"""
from __future__ import annotations

import ast
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path, PurePosixPath

import pytest
from tests.conftest import REPO_ROOT, load_submodule

SECRET = b'OPEN_SITE_CANARY_DO_NOT_READ\n' * 4
SWAPS = ('hardlink', 'leaf-symlink', 'parent-symlink')


class Spy:
    """Record opens of, and bytes read from, protected files by identity."""

    def __init__(self, monkeypatch, protected):
        load_submodule('audit_surface')  # dir_fd support is recorded at import time
        self.ids = {self._identity(os.stat(p)) for p in protected}
        self.stream_opens = []
        self.bytes_read = 0
        self.enabled = True
        self._live = set()
        spy = self

        def hook(event, args):
            if not spy.enabled or event != 'open' or not args:
                return
            target, mode = args[0], args[1] if len(args) > 1 else None
            if mode is None:
                return  # os.open: accounted for by the descriptor wrapper below
            try:
                if isinstance(target, int):
                    info = os.fstat(target)
                elif isinstance(target, (str, bytes, os.PathLike)) and os.path.isabs(os.fsdecode(target)):
                    info = os.stat(target)
                else:
                    return
            except OSError:
                return
            if spy._identity(info) in spy.ids:
                spy.stream_opens.append(target)

        sys.addaudithook(hook)
        original_open, original_read, original_close = os.open, os.read, os.close

        def spy_open(path, flags, mode=0o777, *, dir_fd=None):
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if spy.enabled:
                try:
                    if spy._identity(os.fstat(fd)) in spy.ids:
                        spy._live.add(fd)
                except OSError:
                    pass
            return fd

        def spy_read(fd, n):
            data = original_read(fd, n)
            if fd in spy._live:
                spy.bytes_read += len(data)
            return data

        def spy_close(fd):
            spy._live.discard(fd)
            return original_close(fd)

        monkeypatch.setattr(os, 'open', spy_open)
        monkeypatch.setattr(os, 'read', spy_read)
        monkeypatch.setattr(os, 'close', spy_close)

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino)

    def assert_never_read(self):
        assert self.stream_opens == []
        assert self.bytes_read == 0


def _swap(target: Path, secret: Path, kind: str):
    if kind == 'hardlink':
        target.unlink()
        os.link(secret, target)
    elif kind == 'leaf-symlink':
        target.unlink()
        target.symlink_to(secret)
    else:
        assert secret.name == target.name
        folder = target.parent
        folder.rename(folder.with_name(folder.name + '.moved'))
        folder.symlink_to(secret.parent, target_is_directory=True)


def _restore(target: Path, benign: bytes, kind: str):
    if kind == 'parent-symlink':
        folder = target.parent
        if folder.is_symlink():
            folder.unlink()
            folder.with_name(folder.name + '.moved').rename(folder)
    else:
        if target.is_symlink() or target.exists():
            target.unlink()
        target.write_bytes(benign)


def _caller_name():
    return sys._getframe(2).f_code.co_name


def run_with_swap(monkeypatch, module, name, matches, run, *, target, secret, benign, kind, caller=None):
    """Dry run counting the site's checks of `target`; real run swaps after the last one."""
    original = getattr(module, name)
    counted = []

    def counting(*args, **kwargs):
        verdict = original(*args, **kwargs)
        if matches(*args) and (caller is None or _caller_name() == caller):
            counted.append(verdict)
        return verdict

    monkeypatch.setattr(module, name, counting)
    dry = run()
    monkeypatch.setattr(module, name, original)
    assert counted, f'{name} never checked {target}'
    assert not any(counted), f'{name} refused {target} in the dry run: the swap would not be tested'
    last = len(counted)
    calls = []

    def swapping(*args, **kwargs):
        verdict = original(*args, **kwargs)
        if matches(*args) and (caller is None or _caller_name() == caller):
            calls.append(verdict)
            if len(calls) == last:
                _swap(target, secret, kind)
        return verdict

    monkeypatch.setattr(module, name, swapping)
    try:
        result = run()
    finally:
        monkeypatch.setattr(module, name, original)
        _restore(target, benign, kind)
    assert len(calls) >= last, 'the swap did not happen'
    return dry, result


def _vault(tmp_path, name):
    vault = tmp_path / 'vault'
    vault.mkdir(exist_ok=True)
    secret = vault / name
    secret.write_bytes(SECRET)
    return secret


def _scoped(fn, *declared):
    redaction = load_submodule('audit.redaction')
    policy = load_submodule('audit.policy')

    @redaction.redaction_scope
    def run():
        for path in declared:
            policy.declare_credential(path)
        return fn()

    return run


def _same(path):
    resolved = os.path.realpath(path)
    return lambda arg, *rest: os.path.realpath(os.fspath(arg)) == resolved


# --- one test per site ------------------------------------------------------------


@pytest.mark.parametrize('kind', SWAPS)
def test_dead_stores_bounded_reader(tmp_path, monkeypatch, kind):
    ds = load_submodule('audit.dead_stores')
    root = tmp_path / 'home'
    (root / 'sub').mkdir(parents=True)
    benign = b'plain: value\n'
    target = root / 'sub' / 'data.txt'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'data.txt')
    spy = Spy(monkeypatch, [secret])
    run = _scoped(lambda: ds._read_bounded_regular_bytes(root, ('sub', 'data.txt'), 4096), secret)
    dry, result = run_with_swap(monkeypatch, ds, 'credential_path', _same(target), run,
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry == (benign, None)
    assert result[0] is None
    if kind == 'hardlink':
        assert result == (None, 'credential_excluded')


@pytest.mark.parametrize('kind', SWAPS)
def test_home_workdirs_magic_probe(tmp_path, monkeypatch, kind):
    hw = load_submodule('audit.home_workdirs')
    root = tmp_path / 'home'
    (root / 'tools').mkdir(parents=True)
    benign = b'\x7fELF' + b'\0' * 60
    target = root / 'tools' / 'runner'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'runner')
    spy = Spy(monkeypatch, [secret])

    def site():  # the walker's own order: path check, then the probe
        is_cred = hw._credential_like(str(target), target.name)
        return hw._is_magic_executable(str(target), len(benign), is_credential=is_cred)

    dry, result = run_with_swap(monkeypatch, hw, 'credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry == (True, True)
    assert result[0] is False
    if kind != 'leaf-symlink':
        # Same answer as for a declared file: not probed, so not counted as a read.
        assert result == (False, False)


@pytest.mark.parametrize('kind', SWAPS)
def test_memory_load_private_reader(tmp_path, monkeypatch, kind):
    ml = load_submodule('audit.memory_load')
    root = tmp_path / 'home' / '.hermes'
    (root / 'memories').mkdir(parents=True)
    benign = b'remember the milk\n'
    target = root / 'memories' / 'MEMORY.md'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'MEMORY.md')
    spy = Spy(monkeypatch, [secret])
    rel = PurePosixPath('memories/MEMORY.md')

    def site():
        try:
            return ('data', ml._read_private_file(root, rel, 1 << 20, lambda n: None))
        except OSError as exc:
            return ('error', type(exc).__name__, str(exc))

    dry, result = run_with_swap(monkeypatch, ml, '_blocked', lambda r, rl: rl == rel, _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry == ('data', benign)
    assert result[0] == 'error'
    if kind == 'hardlink':
        assert result == ('error', 'PermissionError', 'not an admitted memory file')


def _outward_home(tmp_path):
    home = tmp_path / 'home'
    default = home / '.hermes'
    profile = default / 'profiles' / 'work'
    profile.mkdir(parents=True)
    (default / 'config.yaml').write_text('model: local\n')
    return home, default, profile


def _credential_paths(result):
    return {c['path'] for c in result['credentials']}


@pytest.mark.parametrize('kind', SWAPS)
def test_outward_walk_reader(tmp_path, monkeypatch, kind):
    outward = load_submodule('audit.outward')
    _home, _default, profile = _outward_home(tmp_path)
    (profile / 'notes').mkdir()
    benign = b'ordinary notes\n'
    target = profile / 'notes' / 'todo.txt'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'todo.txt')
    spy = Spy(monkeypatch, [secret])
    run = _scoped(lambda: outward.collect_outward(profile, []), secret)
    dry, result = run_with_swap(monkeypatch, outward, '_credential', _same(target), run,
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert str(target) not in _credential_paths(dry)
    reasons = json.dumps(result['regions'])
    if kind == 'hardlink':
        # Either refusal is a could-not-verify with an existing reason, never a read.
        assert (str(target) in _credential_paths(result)
                or 'file_changed_during_inspection' in reasons)
    assert SECRET.decode().strip() not in json.dumps(result, default=str)


@pytest.mark.parametrize('kind', SWAPS)
def test_outward_sibling_config_reader(tmp_path, monkeypatch, kind):
    outward = load_submodule('audit.outward')
    _home, default, profile = _outward_home(tmp_path)
    target = default / 'config.yaml'
    benign = target.read_bytes()
    secret = _vault(tmp_path, 'config.yaml')
    spy = Spy(monkeypatch, [secret])
    run = _scoped(lambda: outward.collect_outward(profile, []), secret)
    dry, result = run_with_swap(monkeypatch, outward, '_credential', _same(target), run,
                                target=target, secret=secret, benign=benign, kind=kind,
                                caller='inspect_sibling')
    spy.assert_never_read()
    assert str(target) not in _credential_paths(dry)
    reasons = json.dumps(result['regions'])
    assert 'sibling_config_parse_or_read_failed' in reasons or str(target) in _credential_paths(result)
    if kind == 'hardlink':
        assert str(target) in _credential_paths(result)
        assert 'credential_store_not_opened' in reasons


def _profiles_home(tmp_path):
    root = tmp_path / 'home' / '.hermes'
    benign = b'You are a careful helper.\n'
    for name in ('alpha', 'beta'):
        (root / 'profiles' / name).mkdir(parents=True)
        (root / 'profiles' / name / 'SOUL.md').write_bytes(benign)
    return root, root / 'profiles' / 'alpha' / 'SOUL.md', benign


@pytest.mark.parametrize('caller,cut', [('stream_hash_file', 'unsafe_or_symlink_path'),
                                        ('audit_profile_duplicates', 'symlink_refused')])
@pytest.mark.parametrize('kind', SWAPS)
def test_profile_duplicates_readers(tmp_path, monkeypatch, kind, caller, cut):
    pd = load_submodule('audit.profile_duplicates')
    root, target, benign = _profiles_home(tmp_path)
    secret = _vault(tmp_path, 'SOUL.md')
    spy = Spy(monkeypatch, [secret])
    run = _scoped(lambda: pd.audit_profile_duplicates(root), secret)
    _dry, result = run_with_swap(monkeypatch, pd, 'credential_path', _same(target), run,
                                 target=target, secret=secret, benign=benign, kind=kind, caller=caller)
    spy.assert_never_read()
    if kind == 'hardlink':
        assert cut in json.dumps(result)


@pytest.mark.parametrize('kind', SWAPS)
def test_skill_packs_prefix_reader(tmp_path, monkeypatch, kind):
    sp = load_submodule('audit.skill_packs')
    root = tmp_path / 'home' / '.hermes'
    (root / 'skills' / 'pack' / 'assets').mkdir(parents=True)
    benign = b'GGUF' + b'\0' * 60
    target = root / 'skills' / 'pack' / 'assets' / 'model.bin'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'model.bin')
    spy = Spy(monkeypatch, [secret])
    rel = target.relative_to(root).as_posix()

    def site():  # the walker's own order: path check, then the prefix read
        if sp.credential_path(target):
            return 'refused_by_path'
        return sp._read_prefix_bytes(root, rel, 64)

    dry, result = run_with_swap(monkeypatch, sp, 'credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry == benign
    assert result is None


@pytest.mark.parametrize('kind', SWAPS)
def test_unattended_exposure_prefix_reader(tmp_path, monkeypatch, kind):
    ue = load_submodule('audit.unattended_exposure')
    root = tmp_path / 'home' / '.hermes'
    (root / 'hooks').mkdir(parents=True)
    benign = b'#!/bin/sh\necho hi\n'
    target = root / 'hooks' / 'on-start.sh'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'on-start.sh')
    spy = Spy(monkeypatch, [secret])
    run = _scoped(lambda: ue.audit_unattended_exposure(root), secret)
    dry, result = run_with_swap(monkeypatch, ue, '_is_credential_file', _same(target), run,
                                target=target, secret=secret, benign=benign, kind=kind, caller='read_prefix')
    spy.assert_never_read()
    assert '"interpreter": "sh"' in json.dumps(dry) or 'on-start.sh' in json.dumps(dry)
    assert 'on-start.sh' not in json.dumps(result)


@pytest.mark.parametrize('kind', SWAPS)
def test_outward_git_reader(tmp_path, monkeypatch, kind):
    git = load_submodule('audit.outward_git')
    policy = load_submodule('audit.policy')
    repo = tmp_path / 'repo' / '.git'
    repo.mkdir(parents=True)
    benign = b'[core]\n\tbare = false\n'
    target = repo / 'config'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'config')
    spy = Spy(monkeypatch, [secret])

    def site():
        try:
            return ('data', git._read(target, 4096))
        except ValueError as exc:
            return ('refused', type(exc).__name__)
        except OSError as exc:
            return ('error', type(exc).__name__)

    dry, result = run_with_swap(monkeypatch, policy, 'credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry == ('data', benign)
    # The folder is walked by descriptor before the check: after a folder swap the reader
    # still reads the checked file through the descriptor it already holds.
    assert result[0] != 'data' or (kind == 'parent-symlink' and result == dry)
    if kind == 'hardlink':
        assert result == ('refused', 'CredentialStoreNotOpened')


def _sqlite_file(path):
    connection = sqlite3.connect(path)
    connection.execute('CREATE TABLE t (x)')
    connection.commit()
    connection.close()
    return path.read_bytes()


@pytest.mark.parametrize('kind', SWAPS)
def test_readonly_db_identity_reader(tmp_path, monkeypatch, kind):
    rdb = load_submodule('audit.readonly_db')
    policy = load_submodule('audit.policy')
    (tmp_path / 'home' / 'data').mkdir(parents=True)
    target = tmp_path / 'home' / 'data' / 'state.db'
    benign = _sqlite_file(target)
    secret = _vault(tmp_path, 'state.db')
    spy = Spy(monkeypatch, [secret])

    def site():
        try:
            return ('ok', rdb.stat_db_identity(target).ino)
        except rdb.ReadOnlyDbError as exc:
            return ('refused', exc.reason)

    dry, result = run_with_swap(monkeypatch, policy, 'credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry[0] == 'ok'
    assert result[0] == 'refused'
    if kind != 'leaf-symlink':
        assert result == ('refused', 'excluded')  # the reason a declared database gets


@pytest.mark.parametrize('kind', SWAPS)
def test_template_manifest_reader(tmp_path, monkeypatch, kind):
    contract = load_submodule('audit.contract')
    templates = load_submodule('templates')
    base = tmp_path / 'templates'
    base.mkdir()
    import shutil
    shutil.copytree(REPO_ROOT / 'templates' / 'python-golden', base / 'python-golden', symlinks=True)
    target = base / 'python-golden' / 'template.yaml'
    benign = target.read_bytes()
    secret = _vault(tmp_path, 'template.yaml')
    spy = Spy(monkeypatch, [secret])
    monkeypatch.setattr(templates, 'templates_root', lambda: base)

    def site():
        info = contract.resolve_runtime_golden_registry()
        return (sorted(info['specs']), sorted(info['excluded_ids']), dict(info['invalid_ids']))

    dry, result = run_with_swap(monkeypatch, contract, '_credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind)
    spy.assert_never_read()
    assert dry == (['python-golden'], [], {})
    assert result[0] == []
    if kind == 'hardlink':
        # The same answer as for a declared template.yaml: excluded, not invalid.
        assert result == ([], ['python-golden'], {})


class _SweepStop(Exception):
    pass


@pytest.mark.parametrize('kind', SWAPS)
def test_surface_fallback_template_reader(tmp_path, monkeypatch, kind):
    # The report loads a template manifest itself when the shared registry did not.
    surface = load_submodule('audit_surface')
    contract = load_submodule('audit.contract')
    policy = load_submodule('audit.policy')
    templates = load_submodule('templates')
    base = tmp_path / 'templates'
    base.mkdir()
    import shutil
    shutil.copytree(REPO_ROOT / 'templates' / 'python-golden', base / 'python-golden', symlinks=True)
    target = base / 'python-golden' / 'template.yaml'
    benign = target.read_bytes()
    secret = _vault(tmp_path, 'template.yaml')
    project = tmp_path / 'project'
    project.mkdir()
    spy = Spy(monkeypatch, [secret])
    monkeypatch.setattr(templates, 'templates_root', lambda: base)
    monkeypatch.setattr(contract, 'resolve_runtime_golden_registry',
                        lambda: {'available': True, 'reason': None, 'specs': {}, 'invalid_ids': {}})

    class Store:
        db_path = tmp_path / 'store' / 'audit.db'

        # The sweep's first run-status check after the template loads ends it.
        def get_run(self, run_id):
            seen = sys._getframe(1).f_locals
            if 'invalid_templates' in seen:
                raise _SweepStop(sorted(seen['specs']), dict(seen['invalid_templates']))
            return {'status': 'running'}

    prepared = ('run', {}, [], [{'canonical_path': str(project), 'template_id': 'python-golden'}],
                None, None, False)

    def site():
        with pytest.raises(_SweepStop) as stop:
            surface._sweep(Store(), prepared)
        return stop.value.args

    dry, result = run_with_swap(monkeypatch, policy, 'credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind, caller='_sweep')
    spy.assert_never_read()
    assert dry == (['python-golden'], {})
    assert result[0] == []
    if kind == 'hardlink':
        # The same answer as for a declared template.yaml: left out, not invalid.
        assert result == ([], {})


@pytest.mark.parametrize('component', ('static_code', 'template_drift'))
@pytest.mark.parametrize('kind', SWAPS)
def test_vendored_walk_reader(tmp_path, monkeypatch, kind, component):
    module = load_submodule(f'audit.vendor.{component}')
    policy = load_submodule('audit.policy')
    root = tmp_path / 'project'
    (root / 'src').mkdir(parents=True)
    benign = b'print("hi")\n'
    target = root / 'src' / 'main.py'
    target.write_bytes(benign)
    secret = _vault(tmp_path, 'main.py')
    spy = Spy(monkeypatch, [secret])

    def site():
        files, _coverage, issues = module._safe_walk_directory(root)
        return ((files.get('src/main.py') or {}).get('content'),
                [i['reason'] for i in issues if i['path'] == 'src/main.py'])

    dry, result = run_with_swap(monkeypatch, policy, 'credential_path', _same(target), _scoped(site, secret),
                                target=target, secret=secret, benign=benign, kind=kind, caller='_walk')
    spy.assert_never_read()
    assert dry == (benign, [])
    # The folder is walked by descriptor before the check: after a folder swap the walker
    # still reads the checked file through the descriptor it already holds.
    assert result[0] is None or (kind == 'parent-symlink' and result == dry)
    if kind == 'hardlink':
        assert result == (None, ['credential_policy_exclusion'])


# --- the shared checked opener ------------------------------------------------------


def test_checked_opener_refuses_hard_link_and_linked_folder(tmp_path, monkeypatch):
    fp = load_submodule('audit.fingerprint')
    vault = tmp_path / 'vault'
    vault.mkdir()
    secret = vault / 'token.dat'
    secret.write_bytes(SECRET)
    inside = vault / 'other.dat'
    inside.write_bytes(SECRET)
    (tmp_path / 'work').mkdir()
    hard = tmp_path / 'work' / 'copy.dat'
    os.link(secret, hard)
    alias = tmp_path / 'alias'
    alias.symlink_to(vault, target_is_directory=True)
    plain = tmp_path / 'work' / 'plain.txt'
    plain.write_bytes(b'ordinary')
    spy = Spy(monkeypatch, [secret, inside])
    seen = {}

    def site():
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        for name, path in (('hard', hard), ('linked-folder', alias / 'other.dat')):
            try:
                fd = fp.open_checked(str(path), flags)
                os.close(fd)
                seen[name] = 'opened'
            except fp.CredentialStoreNotOpened:
                seen[name] = 'refused'
        fd = fp.open_checked(str(plain), flags)
        try:
            seen['plain'] = os.read(fd, 100)
        finally:
            os.close(fd)

    _scoped(site, secret, vault)()
    spy.assert_never_read()
    assert seen == {'hard': 'refused', 'linked-folder': 'refused', 'plain': b'ordinary'}


def test_checked_opener_under_a_racing_link(tmp_path, monkeypatch):
    fp = load_submodule('audit.fingerprint')
    a, b = tmp_path / 'a', tmp_path / 'b'
    (a / 'sub').mkdir(parents=True)
    (b / 'sub').mkdir(parents=True)
    secret = a / 'sub' / 'payload.dat'
    secret.write_bytes(SECRET)
    (b / 'sub' / 'payload.dat').write_bytes(b'benign')
    link = tmp_path / 'link'
    link.symlink_to(b, target_is_directory=True)
    spy = Spy(monkeypatch, [secret])
    stop = threading.Event()
    outcomes = {}

    def swapper():
        flip = False
        nxt = tmp_path / 'link.next'
        while not stop.is_set():
            flip = not flip
            try:
                os.unlink(nxt)
            except FileNotFoundError:
                pass
            os.symlink(a if flip else b, nxt, target_is_directory=True)
            os.replace(nxt, link)

    def site():
        thread = threading.Thread(target=swapper, daemon=True)
        thread.start()
        try:
            for _ in range(2000):
                try:
                    fd = fp.open_checked(str(link / 'sub' / 'payload.dat'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                except fp.CredentialStoreNotOpened:
                    outcomes['refused'] = outcomes.get('refused', 0) + 1
                    continue
                except OSError:
                    outcomes['error'] = outcomes.get('error', 0) + 1
                    continue
                try:
                    data = os.read(fd, 100)
                finally:
                    os.close(fd)
                assert data == b'benign'
                outcomes['benign'] = outcomes.get('benign', 0) + 1
        finally:
            stop.set()
            thread.join()

    _scoped(site, secret)()
    spy.assert_never_read()
    assert sum(outcomes.values()) == 2000


def test_no_declarations_means_no_handle_work(tmp_path, monkeypatch):
    """Without declarations the opener adds no system calls beyond the open itself."""
    fp = load_submodule('audit.fingerprint')
    plain = tmp_path / 'plain.txt'
    plain.write_bytes(b'ordinary')
    calls = []
    original_readlink, original_fstat = os.readlink, os.fstat

    def site():
        monkeypatch.setattr(os, 'readlink', lambda *a, **k: calls.append(a) or original_readlink(*a, **k))
        monkeypatch.setattr(os, 'fstat', lambda *a, **k: calls.append(a) or original_fstat(*a, **k))
        try:
            fd = fp.open_checked(str(plain), os.O_RDONLY | os.O_NOFOLLOW)
        finally:
            monkeypatch.setattr(os, 'readlink', original_readlink)
            monkeypatch.setattr(os, 'fstat', original_fstat)
        os.close(fd)

    _scoped(site)()
    assert calls == []


# --- no new unchecked open ----------------------------------------------------------

# (file, enclosing function) -> why this raw open may stay. Keep this list short.
ALLOWED_RAW_OPENS = {
    # The shared reader itself: the descriptor goes straight to _stream_regular_fd,
    # which re-checks it before the first byte is read.
    ('audit/fingerprint.py', '_safe_read_regular_file'): 1,
    # The checked opener (one call with dir_fd, one without).
    ('audit/fingerprint.py', 'open_checked'): 2,
    # The audit's own key file under the plugin's data folder, never home content.
    ('audit/key.py', '_read_existing_key'): 1,
    # Process status files under /proc for the time-bounded child runner.
    ('audit/bounded_call.py', '_ppid_map'): 1,
    ('audit/bounded_call.py', '_children'): 1,
    ('audit/bounded_call.py', '_gone'): 1,
}

_WRITE_FLAGS = ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_APPEND', 'O_TRUNC')
_DIRECTORY_FLAGS = ('O_DIRECTORY', 'o_directory')
_READ_METHODS = {'read_text', 'read_bytes'}


def _raw_reading_opens(path: Path):
    source = path.read_text(encoding='utf-8')
    tree = ast.parse(source)
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
        return '<module>'

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        text = ast.get_source_segment(source, node) or ''
        if isinstance(func, ast.Attribute) and func.attr == 'open' and isinstance(func.value, ast.Name) and func.value.id == 'os':
            flags = (ast.get_source_segment(source, node.args[1]) if len(node.args) > 1 else '') or ''
            if any(f in flags for f in _WRITE_FLAGS + _DIRECTORY_FLAGS):
                continue
        elif isinstance(func, ast.Name) and func.id == 'open' or (
                isinstance(func, ast.Attribute) and func.attr == 'open' and not (
                    isinstance(func.value, ast.Name) and func.value.id in {'os', 'sqlite3', 'contextlib', 'webbrowser'})):
            mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == 'mode'), None)
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in 'wax+'):
                continue
        elif isinstance(func, ast.Attribute) and func.attr in _READ_METHODS:
            pass
        else:
            continue
        found.append((enclosing(node), node.lineno, text.splitlines()[0]))
    return found


def test_no_raw_reading_open_outside_the_checked_opener():
    counts, unexpected = {}, []
    for path in sorted((REPO_ROOT / 'audit').rglob('*.py')):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for function, line, text in _raw_reading_opens(path):
            key = (rel, function)
            counts[key] = counts.get(key, 0) + 1
            if key not in ALLOWED_RAW_OPENS:
                unexpected.append(f'{rel}:{line} in {function}: {text}')
    assert unexpected == [], (
        'A new raw open for reading in the audit: use fingerprint.open_checked (it re-checks the '
        'opened file against the declared credentials) or justify it in ALLOWED_RAW_OPENS.\n'
        + '\n'.join(unexpected))
    over = {k: (counts.get(k, 0), n) for k, n in ALLOWED_RAW_OPENS.items() if counts.get(k, 0) != n}
    assert over == {}, f'allow-list out of date (found, allowed): {over}'
