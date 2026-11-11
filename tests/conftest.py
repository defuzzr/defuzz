"""Pytest configuration and package-loader helper for defuzz tests."""

from __future__ import annotations

import importlib
import importlib.util
import os
try:
    import pwd
except ImportError:  # Windows has no POSIX account database.
    pwd = None
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest


def _path_forms(path):
    lexical = os.path.abspath(os.fsdecode(path))
    return (lexical, os.path.realpath(lexical))


def _under(paths, roots):
    return any(path == root or path.startswith(root + os.sep)
               for path in paths for prefix in roots for root in _path_forms(prefix))


def _check_tmpdir(directory, protected):
    if _under(_path_forms(directory), protected):
        raise RuntimeError(f"TMPDIR is under a protected real-home prefix: {directory}")


# Must run before creating temp files or changing HOME, not merely before fixtures.
_REAL_HOME = (Path(pwd.getpwuid(os.getuid()).pw_dir)
              if pwd is not None and hasattr(os, "getuid") else Path.home())
_PROTECTED = tuple(str(_REAL_HOME / name) for name in (".hermes", ".hermes-qol", "Projects"))
_check_tmpdir(os.environ.get('TMPDIR') or tempfile.gettempdir(), _PROTECTED)
_TEST_HOME = tempfile.TemporaryDirectory(prefix="defuzz-tests-")
_HOME_ENV = {
    "HOME": "user", "USERPROFILE": "user", "HERMES_REAL_HOME": "user",
    "HERMES_HOME": "hermes", "HERMES_PROJECTS_ROOT": "projects",
    "XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache", "XDG_DATA_HOME": "data",
}
for _key, _relative in _HOME_ENV.items():
    _path = Path(_TEST_HOME.name) / _relative
    _path.mkdir(exist_ok=True)
    os.environ[_key] = str(_path)

_TRIPWIRE_VIOLATIONS = []


# Linked worktrees keep HEAD and shared refs outside the checkout itself.
REPO_ROOT = Path(__file__).resolve().parent.parent


def _discover_git_read_roots(repo_root):
    def git(option):
        return subprocess.check_output(
            ['git', '-C', str(repo_root), 'rev-parse', option],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    try:
        if os.path.realpath(git('--show-toplevel')) != os.path.realpath(repo_root):
            return ()
        return tuple(str(repo_root / git(option))
                     for option in ('--absolute-git-dir', '--git-common-dir'))
    except (OSError, subprocess.CalledProcessError):
        return ()


_GIT_READ_ROOTS = _discover_git_read_roots(REPO_ROOT)
# Read-only opens of the checkout itself are allowed even under a protected
# prefix (a clone in ~/Projects/defuzz, an install in ~/.hermes/plugins/defuzz).
_READ_ROOTS = ()
_GIT_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _home_tripwire(event, args):
    watched = {'open', 'os.listdir', 'os.scandir', 'sqlite3.connect', 'os.remove',
               'os.rename', 'os.mkdir', 'os.rmdir', 'shutil.rmtree', 'os.chdir',
               'os.link', 'os.symlink', 'os.truncate', 'os.chmod', 'os.chown', 'os.utime'}
    if event not in watched or not args:
        return
    # Audit argument positions follow CPython's audit-events table. Resolve
    # dir_fd-relative paths too; otherwise removal via an open directory escapes.
    # CPython's open audit event omits dir_fd: dir_fd-relative os.open is outside
    # this regression tripwire's scope (this is not a security sandbox).
    slots = [(0, None)]
    if event in {'os.rename', 'os.link'}:
        slots = [(0, 2), (1, 3)]
    elif event == 'os.symlink':
        slots = [(0, None), (1, 2)]
    elif event in {'os.remove', 'os.rmdir', 'shutil.rmtree'}:
        slots = [(0, 1)]
    elif event in {'os.mkdir', 'os.chmod'}:
        slots = [(0, 2)]
    elif event in {'os.chown', 'os.utime'}:
        slots = [(0, 3)]
    for index, fd_index in slots:
        if index >= len(args):
            continue
        path = args[index]
        if path is None:
            try:
                path = os.getcwd()
            except OSError:
                continue
        if isinstance(path, int):
            try:
                path = os.readlink(f'/proc/self/fd/{path}')
            except OSError:
                continue
        path = os.fsdecode(path)
        if event == 'sqlite3.connect':
            if path == ':memory:':
                continue
            if path.startswith('file:'):
                uri = urlsplit(path)
                path = unquote(uri.path)
                if path == ':memory:' or 'mode=memory' in uri.query.split('&'):
                    continue
        if fd_index is not None and len(args) > fd_index:
            fd = args[fd_index]
            if isinstance(fd, int) and fd >= 0 and not os.path.isabs(path):
                try:
                    path = os.path.join(os.readlink(f'/proc/self/fd/{fd}'), path)
                except OSError:
                    continue
        try:
            forms = _path_forms(path)
        except OSError:
            continue
        if not _under(forms, _PROTECTED):
            continue
        if (event in {'os.listdir', 'os.scandir', 'os.chdir'}
                and any(forms[1] == root or forms[1].startswith(root + os.sep)
                        for root in map(os.path.realpath, _READ_ROOTS))):
            continue
        if event == 'open' and len(args) >= 3:
            mode, flags = args[1:3]
            if ((mode is None or (isinstance(mode, str) and not any(c in mode for c in 'wax+')))
                    and isinstance(flags, int) and not flags & _GIT_WRITE_FLAGS
                    and any(forms[1] == root or forms[1].startswith(root + os.sep)
                            for root in map(os.path.realpath, (*_GIT_READ_ROOTS, *_READ_ROOTS)))):
                continue
        message = f'REAL-HOME TRIPWIRE: {event} forbidden path {path}'
        _TRIPWIRE_VIOLATIONS.append(message)
        raise AssertionError(message)


def _build_home_tripwire(repo_root, *, protected=None, violations=None, git_roots=None, read_roots=()):
    """Build an uninstalled hook so collection setup can be tested directly."""
    namespace = dict(_home_tripwire.__globals__)
    namespace.update(
        _PROTECTED=_PROTECTED if protected is None else protected,
        _TRIPWIRE_VIOLATIONS=_TRIPWIRE_VIOLATIONS if violations is None else violations,
        _GIT_READ_ROOTS=_discover_git_read_roots(repo_root) if git_roots is None else git_roots,
        _READ_ROOTS=tuple(read_roots),
    )
    return types.FunctionType(_home_tripwire.__code__, namespace)


sys.addaudithook(_build_home_tripwire(REPO_ROOT, git_roots=_GIT_READ_ROOTS, read_roots=(str(REPO_ROOT),)))


def pytest_sessionfinish(session, exitstatus):
    # Fail even when production code or a test swallowed the audit exception.
    if _TRIPWIRE_VIOLATIONS:
        session.exitstatus = 1
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter:
            reporter.write_sep("!", "\n".join(_TRIPWIRE_VIOLATIONS))


def _leaked_module_state() -> set[str]:
    """Capability flags that lost their true value, and os functions still replaced."""
    from tests.test_zz_no_module_state_leak import _OS_FUNCS, poisoned_flags
    import posix

    wrapped = {f"os.{n} is wrapped" for n in _OS_FUNCS if getattr(os, n, None) is not getattr(posix, n, None)}
    return wrapped | {f"{flag} is False" for flag in poisoned_flags()}


@pytest.fixture(autouse=True)
def _no_leaked_module_state(request, monkeypatch):
    """Fail the test that LEAVES a capability flag False or an os function wrapped (not every later one)."""
    before = _leaked_module_state()
    yield
    # monkeypatch is torn down after this fixture; undo now (it is idempotent) so its patches do not count.
    monkeypatch.undo()
    new = _leaked_module_state() - before
    if new:
        pytest.fail(f"{request.node.nodeid} left module state behind: {', '.join(sorted(new))}", pytrace=False)


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch):
    """Public test fixture: fresh profile and user roots for every test."""
    with tempfile.TemporaryDirectory(prefix="case-", dir=_TEST_HOME.name) as directory:
        for key, relative in _HOME_ENV.items():
            path = Path(directory) / relative
            path.mkdir(exist_ok=True)
            monkeypatch.setenv(key, str(path))
        yield Path(directory)


TEST_NS_NAME = "hermes_plugins"
TEST_PACKAGE_NAME = f"{TEST_NS_NAME}.defuzz"


def ensure_test_package(package_name: str = TEST_PACKAGE_NAME) -> types.ModuleType:
    """Load the defuzz plugin package from REPO_ROOT under package_name without touching sys.path."""
    existing = sys.modules.get(package_name)
    init_file = REPO_ROOT / "__init__.py"
    if existing is not None and hasattr(existing, "__path__"):
        existing_file = getattr(existing, "__file__", None)
        if existing_file is not None and Path(existing_file).resolve() == init_file.resolve():
            return existing

    parent_name, _, _ = package_name.rpartition(".")
    if parent_name and parent_name not in sys.modules:
        ns_pkg = types.ModuleType(parent_name)
        ns_pkg.__path__ = []  # type: ignore[attr-defined]
        ns_pkg.__package__ = parent_name
        sys.modules[parent_name] = ns_pkg

    spec = importlib.util.spec_from_file_location(
        package_name,
        init_file,
        submodule_search_locations=[str(REPO_ROOT)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create package spec for {init_file}")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package_name
    module.__path__ = [str(REPO_ROOT)]  # type: ignore[attr-defined]
    sys.modules[package_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        prefix = f"{package_name}."
        for k in list(sys.modules):
            if k == package_name or k.startswith(prefix):
                sys.modules.pop(k, None)
        raise
    return module


def load_submodule(name: str, package_name: str = TEST_PACKAGE_NAME) -> Any:
    """Import a submodule of the defuzz plugin package."""
    ensure_test_package(package_name)
    return importlib.import_module(f"{package_name}.{name}")


def _require_hermes_sdk() -> None:
    """Stop the run with one line when the Hermes SDK the plugin imports is missing.

    pytest wraps exceptions raised while importing a conftest (pytest.exit included)
    in a traceback report; SystemExit is not wrapped, so the line below is all it prints.
    """
    try:
        importlib.import_module("plugins.plugin_storage")
    except ImportError as exc:
        sys.stderr.write(
            "Defuzz tests need a Hermes Agent source checkout on the import path "
            f"({exc}); run from the plugin folder as "
            "`PYTHONPATH=/path/to/hermes-agent python -m pytest tests/...`.\n"
        )
        raise SystemExit(int(pytest.ExitCode.USAGE_ERROR)) from None


_require_hermes_sdk()
ensure_test_package()

# --- componentize hermetic guard (D1fix) ---
import pytest


@pytest.fixture(autouse=True)
def _componentize_hermetic_guard(request, monkeypatch):
    if 'componentize_live' in request.fixturenames:
        return
    absent = lambda *args, **kwargs: (None, 'absent', None)
    load_submodule('componentize_bridge')
    load_submodule('dashboard.plugin_api')._load('componentize_bridge')
    for name, mod in list(sys.modules.items()):
        if name.endswith('.componentize_bridge') and hasattr(mod, 'detect_command'):
            monkeypatch.setattr(mod, 'detect_command', absent)
        if name.endswith('.workspace_routes') and hasattr(mod, '_reset_kit_cache_for_tests'):
            mod._reset_kit_cache_for_tests()
