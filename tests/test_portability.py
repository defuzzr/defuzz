"""Payload portability gate: installed copies and source checkouts alike."""
from pathlib import Path
import os
import re
import subprocess
import sys
from contextlib import contextmanager

import pytest


@contextmanager
def confined_io(root, read_roots):
    """CPython filesystem tripwire (not an OS sandbox for subprocesses)."""
    active = [True]
    violations = []
    root = root.resolve()
    read_roots = tuple(p.resolve() for p in read_roots)

    ancestors = {p for base in (root, *read_roots) for p in base.parents}
    # CPython's open audit event omits dir_fd. Supply its resolved path from
    # a test-only wrapper, without changing the actual descriptor-relative open.
    from threading import local
    opening = local()
    directories = {}
    original_open = os.open

    def confined_open(path, flags, mode=0o777, *, dir_fd=None):
        raw = os.fsdecode(path)
        if dir_fd is not None and not os.path.isabs(raw):
            identity = os.fstat(dir_fd)
            key = (identity.st_dev, identity.st_ino)
            directory = directories.get(key)
            if directory is None:
                violations.append(f'open: unknown directory descriptor {dir_fd}')
                raise AssertionError(violations[-1])
            raw = os.path.join(directory, raw)
        previous = getattr(opening, 'path', None)
        opening.path = Path(raw).resolve()
        try:
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if flags & getattr(os, 'O_DIRECTORY', 0):
                identity = os.fstat(fd)
                directories[(identity.st_dev, identity.st_ino)] = opening.path
            return fd
        finally:
            opening.path = previous

    def hook(event, args):
        if not active[0] or not args:
            return
        if event not in {'open', 'os.listdir', 'os.scandir', 'sqlite3.connect',
                         'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename',
                         'os.chmod', 'os.utime', 'os.link', 'os.symlink'}:
            return
        indexes = (0, 1) if event in {'os.rename', 'os.link', 'os.symlink'} else (0,)
        for index in indexes:
            raw = args[index]
            if isinstance(raw, int) or raw is None or raw == ':memory:':
                continue
            raw = os.fsdecode(raw)
            if event == 'sqlite3.connect' and raw.startswith('file:'):
                from urllib.parse import unquote, urlsplit
                from urllib.request import url2pathname
                raw = url2pathname(unquote(urlsplit(raw).path))
            if raw == os.devnull:
                continue  # Portable subprocess null device, not persistent state.
            fd_slot = ({'os.remove': 1, 'os.rmdir': 1, 'os.mkdir': 2,
                        'os.chmod': 2, 'os.utime': 3}.get(event))
            if event in {'os.rename', 'os.link'}:
                fd_slot = index + 2
            if fd_slot is not None and len(args) > fd_slot:
                fd = args[fd_slot]
                if isinstance(fd, int) and fd >= 0 and not os.path.isabs(raw):
                    identity = os.fstat(fd)
                    candidates = [root, *(p for p in root.rglob('*') if p.is_dir())]
                    directory = next(p for p in candidates
                                     if (p.stat().st_dev, p.stat().st_ino)
                                     == (identity.st_dev, identity.st_ino))
                    raw = os.path.join(directory, raw)
            path = Path(raw).resolve()
            writing = event not in {'open', 'os.listdir', 'os.scandir'}
            directory_read = event in {'os.listdir', 'os.scandir'}
            if event == 'open':
                path = getattr(opening, 'path', None) or path
                writing = bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT
                                          | os.O_TRUNC | os.O_APPEND))
                directory_read = bool(args[2] & getattr(os, 'O_DIRECTORY', 0))
            # Stat is not audited by CPython; listing and explicit read-only
            # directory opens may inspect ancestors, never their other contents.
            if not writing and directory_read and path in ancestors:
                continue
            if path.is_relative_to(root):
                continue
            if not writing and any(path.is_relative_to(p) for p in read_roots):
                continue
            # The audit worker finds its own descendants in the process table;
            # that is process metadata, not a user file (see _process_table_read).
            if not writing and _process_table_read(event, path):
                continue
            violations.append(f'{event}: {path}')
            raise AssertionError(violations[-1])

    sys.addaudithook(hook)
    try:
        with pytest.MonkeyPatch.context() as patcher:
            patcher.setattr(os, 'open', confined_open)
            yield
    finally:
        active[0] = False
        assert not violations, '\n'.join(violations)

from tests import REPO_ROOT, load_submodule
from tests.toolchain_needs import need


# Generic machine-path sentinels; workspace-specific names live in a separate private guard.
_MACHINE = re.compile(
    r"/home/(?!user\b|x\b)[a-z][\w.-]*"
    + r"|/Users/[A-Za-z][\w.-]*|C:\\Users\\[A-Za-z][\w.-]*"
)
# Only user and x are neutral synthetic home names; no file-wide exclusions.
# Temporary fixture paths are not machine identities and remain permitted.


def payload_files(root):
    try:
        top = subprocess.check_output(
            ['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
            stderr=subprocess.DEVNULL, text=True).strip()
        if Path(top).resolve() != root.resolve():
            raise OSError('installed payload is not the repository root')
        names = subprocess.check_output(
            ['git', '-C', str(root), 'ls-files', '-z'], stderr=subprocess.DEVNULL
        ).decode().split('\0')
        return [root / name for name in names if name and (root / name).is_file()]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in root.rglob('*') if p.is_file()
                and not {'.git', '__pycache__', '.pytest_cache'} & set(p.relative_to(root).parts)]


def test_standalone_toolchk_profile_resolution(tmp_path):
    import platform
    lock = tmp_path / 'TOOLS.lock'
    lock.write_text(
        '[lock]\nschema = 1\n[python]\n'
        f'version = "{platform.python_version()}"\n'
        'chosen = "2026-01-01"\nreason = "portability fixture"\n'
        'probe = "command"\nargv = ["python", "--version"]\n'
        'resolve = "hermes-tools"\n', encoding='utf-8')
    env = dict(os.environ)
    env['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env.get('PATH', '')
    result = subprocess.run([sys.executable, str(REPO_ROOT / 'toolchk.py'),
                             '--all', '--project', str(tmp_path)],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_replace_lock_without_fchmod(tmp_path, monkeypatch):
    target = tmp_path / 'TOOLS.lock'
    target.write_bytes(b'old')
    monkeypatch.delattr(os, 'fchmod', raising=False)
    load_submodule('tool_guard')._replace_lock(tmp_path, b'new')
    assert target.read_bytes() == b'new'


def test_collection_without_posix_account_api():
    script = """
import os
from pathlib import Path
import runpy
import sys
expected = Path.home()
sys.modules['pwd'] = None
if hasattr(os, 'getuid'):
    del os.getuid
namespace = runpy.run_path(sys.argv[1])
assert namespace['_REAL_HOME'] == expected
"""
    result = subprocess.run([sys.executable, '-c', script, str(REPO_ROOT / 'tests/conftest.py')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_payload_inside_enclosing_repository(tmp_path, monkeypatch):
    package = tmp_path / 'installed'
    package.mkdir()
    marker = package / 'plugin.yaml'
    marker.write_text('name: fixture')
    monkeypatch.setattr(subprocess, 'check_output', lambda *a, **k: str(tmp_path))
    assert payload_files(package) == [marker]


def test_payload_walk_fallback(tmp_path, monkeypatch):
    (tmp_path / 'visible.txt').write_text('fixture')
    (tmp_path / '__pycache__').mkdir()
    (tmp_path / '__pycache__' / 'ignored.pyc').write_bytes(b'cache')
    monkeypatch.setattr(subprocess, 'check_output', lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert payload_files(tmp_path) == [tmp_path / 'visible.txt']


def test_confinement_detects_swallowed_outside_write(tmp_path):
    inside = tmp_path / 'inside'
    inside.mkdir()
    with pytest.raises(AssertionError, match='outside'):
        with confined_io(inside, []):
            try:
                (tmp_path / 'outside').write_text('must not be written')
            except AssertionError:
                pass
    assert not (tmp_path / 'outside').exists()


@pytest.mark.skipif(not hasattr(os, 'O_DIRECTORY'), reason='directory descriptors required')
def test_confinement_allows_ancestor_directory_walk(tmp_path):
    inside = tmp_path / 'inside'
    inside.mkdir()
    with confined_io(inside, []):
        fd = os.open(inside.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in inside.parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = child
            assert os.fstat(fd).st_ino == inside.stat().st_ino
            assert 'inside' in os.listdir(tmp_path)
            with os.scandir(tmp_path) as entries:
                assert 'inside' in {entry.name for entry in entries}
        finally:
            os.close(fd)


@pytest.mark.skipif(not hasattr(os, 'O_DIRECTORY'), reason='directory descriptors required')
@pytest.mark.parametrize('operation', ['write', 'read', 'directory', 'plain_directory',
                                        'directory_write', 'listdir'])
@pytest.mark.parametrize('relative', [False, True])
def test_confinement_ancestor_exception_still_blocks_outside(tmp_path, operation, relative):
    inside = tmp_path / 'inside'
    inside.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    data = tmp_path / 'outside.txt'
    data.write_text('unchanged')
    flags = {
        'write': os.O_WRONLY | os.O_TRUNC,
        'read': os.O_RDONLY,
        'directory': os.O_RDONLY | os.O_DIRECTORY,
        'plain_directory': os.O_RDONLY,
        'directory_write': os.O_RDWR | os.O_DIRECTORY,
    }
    target = (outside if operation in {'directory', 'listdir'} else
              tmp_path if operation in {'plain_directory', 'directory_write'} else data)
    with pytest.raises(AssertionError, match='open:|os.listdir:'):
        with confined_io(inside, []):
            parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                if operation == 'listdir':
                    os.listdir(target)
                else:
                    path = os.path.relpath(target, tmp_path) if relative else target
                    fd = os.open(path, flags[operation], dir_fd=parent if relative else None)
                    os.close(fd)
            finally:
                os.close(parent)
    assert data.read_text() == 'unchanged'


def _process_table_read(event, path):
    """The audit worker's tree walk: its own task children, or the /proc listing and stat."""
    if path == Path('/proc') or re.fullmatch(r'/proc/[0-9]+/task', str(path)):
        return event in {'os.listdir', 'os.scandir'}
    return event == 'open' and re.fullmatch(r'/proc/[0-9]+/(stat|task/[0-9]+/children)', str(path)) is not None


@pytest.mark.skipif(not os.path.isdir('/proc/self'), reason='/proc required')
def test_confinement_allows_only_the_process_table(tmp_path):
    inside = tmp_path / 'inside'
    inside.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    with confined_io(inside, []):
        assert str(os.getpid()) in os.listdir('/proc')
        with open('/proc/self/stat', 'rb') as handle:
            assert handle.read(64)
    for probe in (lambda: open('/proc/self/environ', 'rb').close(),
                  lambda: os.listdir('/proc/self/fd'),
                  lambda: os.listdir(outside)):
        with pytest.raises(AssertionError, match='open:|os.listdir:'):
            with confined_io(inside, []):
                probe()


@pytest.mark.parametrize('fd_dirs', [('/proc-absent/self/fd', '/dev/fd'), ('/proc-absent', '/dev-absent')])
def test_worker_closes_inherited_handles_without_proc(monkeypatch, fd_dirs):
    """macOS has no /proc: the worker still closes every handle except the kept ones."""
    bounded = load_submodule('audit.bounded_call')
    if fd_dirs[1] == '/dev/fd' and not os.path.isdir('/dev/fd'):
        pytest.skip('/dev/fd required')
    read_fd, write_fd = os.pipe()
    closed, ranges = [], []
    monkeypatch.setattr(bounded, '_FD_DIRS', fd_dirs)
    monkeypatch.setattr(bounded.os, 'close', closed.append)
    monkeypatch.setattr(bounded.os, 'closerange', lambda lo, hi: ranges.append((lo, hi)))
    try:
        keep = {0, 1, 2, write_fd}
        bounded._close_inherited(keep)
    finally:
        monkeypatch.undo()
        os.close(read_fd)
        os.close(write_fd)
    if fd_dirs[1] == '/dev/fd':
        assert read_fd in closed and ranges == []
    else:
        assert closed == []
        covered = {fd for lo, hi in ranges for fd in range(lo, hi)}
        assert set(range(3, max(read_fd, write_fd) + 1)) - keep <= covered
    assert not keep & set(closed)
    assert not any(lo <= fd < hi for lo, hi in ranges for fd in keep)


def test_payload_has_no_machine_paths():
    violations = []
    files = payload_files(REPO_ROOT)
    assert len(files) >= 100, "Incomplete or empty plugin payload enumeration"
    for path in files:
        for number, line in enumerate(path.read_bytes().decode('utf-8', errors='replace').splitlines(), 1):
            if _MACHINE.search(line):
                violations.append(f'{path.relative_to(REPO_ROOT)}:{number}: {line}')
    assert not violations, '\n'.join(violations)


def test_real_golden_stage_lint_and_desktop_registration(tmp_path):
    """Real shipped staging, Ruff execution and cold Desktop tool discovery.

    Does not accept/build the golden workspace: its uv CI has separate tests.
    """
    need('ruff')
    home = tmp_path / 'workflow é space'
    profile = home / '.hermes' / 'profiles' / 'tester'
    profile.mkdir(parents=True)
    env = dict(os.environ)
    for key, value in {'HOME': home, 'USERPROFILE': home, 'HERMES_REAL_HOME': home,
                       'HERMES_HOME': profile, 'HERMES_PROJECTS_ROOT': home / 'projects',
                       'XDG_CACHE_HOME': home / 'cache', 'XDG_CONFIG_HOME': home / 'config',
                       'XDG_DATA_HOME': home / 'data'}.items():
        env[key] = str(value)
    script = r'''
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
home = Path(os.environ['HOME'])
profile = Path(os.environ['HERMES_HOME'])
spec = importlib.util.spec_from_file_location('portable_plugin', root / '__init__.py',
                                             submodule_search_locations=[str(root)])
package = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = package
spec.loader.exec_module(package)
from portable_plugin import scaffolder, templates, linter, desktop_registration, state_store
proposal = scaffolder.propose(templates.load_template(root / 'templates/python-golden'),
    'Portable Golden', {'building': 'service', 'layout': 'mono', 'languages': ['python']},
    staging_parent=home / 'staging')
staged = proposal.repos[0].staged
assert (staged / 'pyproject.toml').exists()
assert (staged / 'packages').is_dir()
assert 'tmpl_prefix' not in (staged / 'pyproject.toml').read_text()
lint_root = home / 'lint project'
lint_root.mkdir()
(lint_root / 'example.py').write_text('print(undefined_portability_name)\n', encoding='utf-8')
report = linter.run_lint(lint_root, mode='pre')
assert report['ok'], report
assert any(f['rule'] == 'F821' for f in report['findings']), report
from tools.registry import registry
assert registry.get_entry('desktop_project') is None
registration = json.loads(desktop_registration.create_project('Portable Golden', str(staged)))
assert registration.get('success'), registration
from hermes_cli import projects_db
with projects_db.connect_closing() as conn:
    projects = projects_db.list_projects(conn, include_archived=True)
assert any(p.primary_path == str(staged) for p in projects), projects
assert projects_db.projects_db_path() == profile / 'projects.db'
assert state_store.state_db_path().is_relative_to(profile)
assert (profile / 'cache' / 'tool_discovery_cache.json').exists()
print(json.dumps({'golden_staged': True, 'ruff_F821': True, 'desktop_registered': True}))
'''
    result = subprocess.run([sys.executable, '-c', script, str(REPO_ROOT)],
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"desktop_registered": true' in result.stdout


def test_odd_home_profile_path_resolution(tmp_path, monkeypatch):
    import json
    import hermes_constants
    from plugins.plugin_storage import plugin_data_dir
    from tests import ensure_test_package

    home = tmp_path / 'user é space'
    profile = home / '.hermes' / 'profiles' / 'tester'
    profile.mkdir(parents=True)
    (profile / 'config.yaml').write_text('{}', encoding='utf-8')
    projects = home / 'projects'
    projects.mkdir()
    scratch = home / 'scratch'
    scratch.mkdir()
    for key, value in {'HOME': home, 'USERPROFILE': home, 'HERMES_REAL_HOME': home,
                       'HERMES_HOME': profile, 'HERMES_PROJECTS_ROOT': projects,
                       'TMPDIR': scratch, 'TMP': scratch, 'TEMP': scratch}.items():
        monkeypatch.setenv(key, str(value))
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)
    read_roots = [REPO_ROOT, Path(sys.base_prefix), Path(sys.prefix),
                  Path(hermes_constants.__file__).parent]
    # Git metadata is read-only provenance, including linked worktree metadata.
    from tests.conftest import _GIT_READ_ROOTS
    read_roots.extend(Path(p) for p in _GIT_READ_ROOTS)
    # Import the modules that decide a platform capability at import (for
    # example audit/fingerprint.py: `os.open in os.supports_dir_fd`) now, with
    # the real os.open. Imported first under confined_io's os.open wrapper, the
    # flag would be False: the audit below would refuse to read, and every later
    # test in this process would fail with "os.open does not support dir_fd".
    for name in ('audit', 'audit.vendor.static_code', 'audit.vendor.template_drift',
                 'output_file', 'kit_scaffold', 'toolchk', 'state_store'):
        load_submodule(name)
    with confined_io(tmp_path, read_roots):
        assert ensure_test_package('portability_probe.defuzz').__file__
        scaffold = load_submodule('scaffolder')
        templates = load_submodule('templates')
        state = load_submodule('state_store')
        template_root = home / 'portable-template'
        source = template_root / 'tmpl_prefix'
        source.mkdir(parents=True)
        (source / 'sample.unknown').write_text('tmpl_prefix', encoding='utf-8')
        (template_root / 'template.yaml').write_text(
            'id: portable-template\nname: Portable\nsummary: Tiny fixture\n'
            'kind: service\nlayout: mono\nlanguages: [python]\n'
            'placeholder: tmpl_prefix\nsubstitute_in: ["**/*"]\n'
            'repos:\n  - name: tmpl_prefix\n', encoding='utf-8')
        template = templates.load_template(template_root)
        proposal = scaffold.propose(template, 'Portable Game', {'languages': ['rust']},
                                    staging_parent=scratch)
        result = scaffold.accept(proposal, register=lambda n, p: json.dumps({'success': True, 'id': n}))
        assert result.answers_id > 0
        assert proposal.repos[0].dest.is_relative_to(projects)
        assert (proposal.repos[0].dest / 'sample.unknown').exists()
        # Explicit manual lint with no supported files needs no installed linters.
        lint_root = projects / 'manual lint é'
        lint_root.mkdir()
        (lint_root / 'sample.unknown').write_text('synthetic', encoding='utf-8')
        lint = load_submodule('linter').run_lint(lint_root)
        assert lint['ok'], lint
        assert state.state_db_path().is_relative_to(profile)
        assert state.state_db_path().exists()
        surface = load_submodule('audit_surface')
        # Full outward capture is the default; `quick` selects bounded.
        for quick in (True, False):
            audit = surface.execute_audit({'action': 'run', 'quick': quick,
                                           'as_of': 1800000000}, wait=True)
            assert audit['status'] == 'completed', audit
            run = surface.AuditStore().get_run(audit['run_id'])
            # Allowlist persistence: the profile name is content-derived, so the
            # saved run carries a sealed token, never the plaintext name.
            assert isinstance(run['active_profile'], dict), run['active_profile']
            assert set(run['active_profile']) >= {'hmac', 'kind'}
            assert 'tester' not in repr(run['active_profile'])
            assert run['mode'] == ('bounded' if quick else 'full_home')
        assert plugin_data_dir('defuzz').is_relative_to(profile)


def test_advisory_roots_include_public_profile(tmp_path, monkeypatch):
    import hermes_constants
    fake_home = tmp_path / 'home é space'
    profile = fake_home / '.hermes-custom'
    cua_check = fake_home / '.cua-driver' / 'version_check.json'
    cua_check.parent.mkdir(parents=True)
    cua_check.write_text('{"latest_version": "0.38.0"}', encoding='utf-8')
    profile.mkdir(parents=True)
    (profile / 'vc.json').write_text('{"latest_version": "9.9.9"}', encoding='utf-8')
    proj = tmp_path / 'proj'
    proj.mkdir()
    monkeypatch.setenv('HOME', str(fake_home))
    monkeypatch.setenv('USERPROFILE', str(fake_home))
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: profile)
    chk = load_submodule('toolchk')
    assert chk._resolve_advisory_json_path('~/.cua-driver/version_check.json', proj) == cua_check
    with pytest.raises(ValueError, match='advisory_path_not_allowed'):
        chk._resolve_advisory_json_path(str(profile / 'vc.json'), proj)


def test_unresolvable_home_fails_without_posix_temp_assumption(monkeypatch):
    env = load_submodule('lint_env')
    monkeypatch.setattr(env, '_hermes_get_real_home', None)
    monkeypatch.setattr(env.os.path, 'expanduser', lambda _: '~')
    monkeypatch.setattr(env.tempfile, 'gettempdir', lambda: (_ for _ in ()).throw(OSError('no temp')))
    monkeypatch.setattr(env.os, 'getuid', lambda: -1, raising=False)
    for key in ('HOME', 'USERPROFILE', 'HERMES_REAL_HOME'):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(RuntimeError, match='home'):
        env.real_home({})


def test_hermes_tool_resolution_uses_public_profile(tmp_path, monkeypatch):
    toolchk = load_submodule('toolchk')
    active = tmp_path / 'profile é space'
    executable = active / 'tools' / 'node-22' / 'node'
    executable.parent.mkdir(parents=True)
    executable.write_text('synthetic executable', encoding='utf-8')
    executable.chmod(0o755)
    import hermes_constants
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: active)
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'stale-profile'))
    assert toolchk._resolve_command('node', ['node', '--version'], 'hermes-tools')[0] == str(executable)
