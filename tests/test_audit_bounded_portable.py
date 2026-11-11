"""The component worker's kill path on Linux and on a platform without /proc.

Real worker processes. "No /proc" is simulated the way the descriptor-closing
fallback test does it: the module's view of the file system is narrowed (its
``os`` and ``open`` names), so every /proc path is missing for the parent's
kill path while the real Linux kernel runs the processes. "No waitid" also
hides ``os.waitid`` (macOS before Python 3.13). Nothing here runs on a Mac.
"""
from __future__ import annotations

import os
import re
import secrets
import signal
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import load_submodule
from tests.test_audit_component_time_budget import _descendants, _named, _open_fds

_TESTS = str(Path(__file__).resolve().parent)
if _TESTS not in sys.path:
    sys.path.append(_TESTS)
import test_audit_component_time_budget_stubs as stubs  # noqa: E402

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux') or not os.path.isdir('/proc/self'),
                                reason='real processes are observed through Linux /proc')

MODES = ('linux', 'no_proc', 'no_proc_no_waitid')
_REAL_OPEN = open


def _bounded():
    return load_submodule('audit.bounded_call')


def _is_proc(path) -> bool:
    text = os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else ''
    return text == '/proc' or text.startswith('/proc/')


class _Path:
    """os.path as seen without /proc (and, optionally, without children files)."""

    def __init__(self, missing):
        self._missing = missing

    def __getattr__(self, name):
        real = getattr(os.path, name)
        if name in {'exists', 'isdir', 'isfile', 'lexists'}:
            return lambda path: False if self._missing(path) else real(path)
        return real


class _OS:
    """The module's os: /proc paths missing, chosen names hidden."""

    def __init__(self, missing, hide=()):
        self._missing = missing
        self._hide = frozenset(hide)
        self.path = _Path(missing)

    def __getattr__(self, name):
        if name in self._hide:
            raise AttributeError(name)
        real = getattr(os, name)
        if name in {'listdir', 'scandir', 'stat', 'lstat'}:
            def gated(path='.', *args, **kwargs):
                if self._missing(path):
                    raise FileNotFoundError(2, 'No such file or directory', os.fsdecode(path))
                return real(path, *args, **kwargs)
            return gated
        return real


def _simulate(monkeypatch, bounded, missing, hide=()):
    def gated_open(path, *args, **kwargs):
        if missing(path):
            raise FileNotFoundError(2, 'No such file or directory', os.fsdecode(path))
        return _REAL_OPEN(path, *args, **kwargs)
    monkeypatch.setattr(bounded, 'os', _OS(missing, hide))
    monkeypatch.setattr(bounded, 'open', gated_open, raising=False)


def _platform(monkeypatch, bounded, mode):
    if mode == 'no_proc':
        _simulate(monkeypatch, bounded, _is_proc)
    elif mode == 'no_proc_no_waitid':
        _simulate(monkeypatch, bounded, _is_proc, hide=('waitid', 'P_PID', 'WNOWAIT'))


def _spy_workers(monkeypatch, bounded):
    workers = []
    original = bounded._spawn_worker

    def spawn(limit):
        worker = original(limit)
        workers.append(worker)
        return worker
    monkeypatch.setattr(bounded, '_spawn_worker', spawn)
    return workers


def _run(monkeypatch, mode, fn, component_s, cancel_after=None, **kwargs):
    """Warm a worker, run fn under component_s; (result, elapsed, worker)."""
    surface = load_submodule('audit_surface')
    bounded = _bounded()
    _platform(monkeypatch, bounded, mode)
    workers = _spy_workers(monkeypatch, bounded)
    before = set(_descendants(os.getpid()))
    fds = _open_fds()
    cancel_at = [None]

    def cancelled():
        return cancel_at[0] is not None and time.monotonic() >= cancel_at[0]
    with bounded.budgets(20.0, 60.0), bounded.audit_call_scope(cancelled=cancelled) as session:
        warm = surface._component('memory', 'default', stubs.echo)
        assert warm['coverage'] == 'verified', bounded.LAST_CAUSE
        with bounded.budgets(component_s, 60.0):
            start = time.monotonic()
            if cancel_after is not None:
                cancel_at[0] = start + cancel_after
            result = surface._component('memory', 'default', fn, **kwargs)
            elapsed = time.monotonic() - start
        assert session.starts == 1
    assert set(_descendants(os.getpid())) - before == set()
    assert _open_fds() == fds
    assert len(workers) == 1
    worker = workers[0]
    # The wait status was collected: no zombie is left behind.
    assert worker.proc.returncode is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(worker.pid, os.WNOHANG)
    return result, elapsed, worker


def _bound(budget):
    return budget + _bounded()._GRACE_S + 1.0


def _wait_gone(token, seconds=2.0):
    deadline = time.monotonic() + seconds
    while _named(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    return _named(token)


def test_worker_is_its_own_session_and_process_group():
    bounded = _bounded()
    worker = bounded._start_worker(30.0)
    try:
        assert os.getpgid(worker.pid) == worker.pid
        assert os.getsid(worker.pid) == worker.pid
    finally:
        worker.close()
    assert worker.proc.returncode is not None


@pytest.mark.parametrize('mode', MODES)
def test_sleep_past_budget_is_killed_within_budget_grace_and_one_second(monkeypatch, mode):
    result, elapsed, worker = _run(monkeypatch, mode, stubs.sleep, 0.5)
    assert result['coverage'] == 'could_not_verify'
    assert _bounded().LAST_CAUSE[0] == 'timeout'
    assert elapsed < _bound(0.5), elapsed


@pytest.mark.parametrize('mode', MODES)
def test_grace_period_is_real(monkeypatch, mode):
    """SIGTERM first, then a real wait: the worker exits by itself inside the grace."""
    result, elapsed, worker = _run(monkeypatch, mode, stubs.exit_late_on_term, 0.5)
    assert result['coverage'] == 'could_not_verify'
    assert worker.proc.returncode == 7, worker.proc.returncode
    assert elapsed < _bound(0.5), elapsed


@pytest.mark.parametrize('mode', MODES)
def test_child_in_the_process_group_is_killed(monkeypatch, mode):
    token = 'tbpg' + secrets.token_hex(4)
    result, elapsed, _worker = _run(monkeypatch, mode, stubs.group_child, 1.0, token=token)
    assert result['coverage'] == 'could_not_verify'
    assert elapsed < _bound(1.0), elapsed
    assert _wait_gone(token) == []


def test_setsid_child_is_killed_on_linux(monkeypatch):
    token = 'tbps' + secrets.token_hex(4)
    result, elapsed, _worker = _run(monkeypatch, 'linux', stubs.setsid_child, 1.0, token=token)
    assert result['coverage'] == 'could_not_verify'
    assert elapsed < _bound(1.0), elapsed
    assert _wait_gone(token) == []


@pytest.mark.parametrize('mode', ('no_proc', 'no_proc_no_waitid'))
def test_setsid_child_survives_without_proc_as_documented(monkeypatch, mode):
    bounded = _bounded()
    doc = ' '.join(bounded.__doc__.split())
    assert 'Without /proc (macOS)' in doc
    assert 'a descendant that left the process group' in doc
    assert 'is not signalled and keeps running until it exits by itself' in doc
    token = 'tbpx' + secrets.token_hex(4)
    try:
        result, elapsed, _worker = _run(monkeypatch, mode, stubs.setsid_child, 1.0, token=token)
        assert result['coverage'] == 'could_not_verify'
        assert elapsed < _bound(1.0), elapsed
        time.sleep(0.3)
        survivors = _named(token)
        assert len(survivors) == 1, survivors
        # It is no longer below this process: nothing here can reap it.
        assert survivors[0] not in _descendants(os.getpid())
    finally:
        for pid in _named(token):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    assert _wait_gone(token) == []


@pytest.mark.parametrize('mode', MODES)
def test_cancel_during_a_running_component_kills_within_the_bound(monkeypatch, mode):
    result, elapsed, _worker = _run(monkeypatch, mode, stubs.sleep, 60.0, cancel_after=0.5)
    assert result['coverage'] == 'could_not_verify'
    assert _bounded().LAST_CAUSE[0] == 'cancelled'
    # Same bound as the end-to-end cancel test: not the 60 s component budget.
    assert elapsed - 0.5 < 3.0, elapsed


def _has_children_files():
    return os.path.exists(f'/proc/{os.getpid()}/task/{os.getpid()}/children')


def _ppid(pid):
    try:
        with _REAL_OPEN(f'/proc/{pid}/stat', 'rb') as handle:
            return int(handle.read().rsplit(b')', 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


@pytest.mark.skipif(not _has_children_files(), reason='kernel without /proc/<pid>/task/<tid>/children')
def test_narrow_walk_reads_only_the_worker_tree(monkeypatch):
    bounded = _bounded()
    workers = _spy_workers(monkeypatch, bounded)
    reads, outside, busy = [], [], [False]
    pattern = re.compile(r'/proc/([0-9]+)(?:/|$)')

    def in_tree(pid):
        roots = {worker.pid for worker in workers}
        for _ in range(64):
            if pid in roots:
                return True
            if pid is None or pid <= 1:
                return False
            pid = _ppid(pid)
        return False

    def hook(event, args):
        if busy[0] or event not in {'open', 'os.listdir', 'os.scandir'} or not args:
            return
        raw = args[0]
        if not isinstance(raw, (str, bytes)) or not _is_proc(raw):
            return
        busy[0] = True
        try:
            path = os.fsdecode(raw)
            reads.append((event, path))
            match = pattern.match(path)
            if match is None or not in_tree(int(match.group(1))):
                outside.append((event, path))
        finally:
            busy[0] = False
    active = [True]
    sys.addaudithook(lambda event, args: hook(event, args) if active[0] else None)
    token = 'tbpn' + secrets.token_hex(4)
    try:
        surface = load_submodule('audit_surface')
        with bounded.budgets(20.0, 60.0), bounded.audit_call_scope():
            assert surface._component('memory', 'default', stubs.echo)['coverage'] == 'verified'
            with bounded.budgets(1.0, 60.0):
                result = surface._component('memory', 'default', stubs.stubborn_tree, token=token)
    finally:
        active[0] = False
    assert result['coverage'] == 'could_not_verify'
    assert _wait_gone(token) == []
    assert ('os.listdir', '/proc') not in reads
    assert any(path.endswith('/children') for _event, path in reads), reads
    assert outside == [], outside


def test_narrow_walk_and_full_walk_find_the_same_tree(monkeypatch):
    bounded = _bounded()
    token = 'tbpf' + secrets.token_hex(4)
    worker = bounded._start_worker(30.0)
    try:
        # Hand the worker one request by hand and leave it running: the tree it
        # builds stays in place while both walks look at it.
        import pickle
        frame = pickle.dumps({
            'module': stubs.__name__, 'qualname': 'stubborn_tree',
            'kwargs': pickle.dumps({'token': token}), 'taint': pickle.dumps(bounded._taint_seed()),
            'key': bounded._key_seed(), 'environ': dict(os.environ), 'cwd': os.getcwd(), 'state': None,
        })
        bounded._write_frame(worker.write_fd, frame, time.monotonic() + 5)
        deadline = time.monotonic() + 10
        while len(_named(token)) < 3 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(_named(token)) == 3
        narrow = sorted(bounded._descendants(worker.pid))
        with monkeypatch.context() as patch:
            _simulate(patch, bounded, lambda path: os.fsdecode(path).endswith('/children'))
            full = sorted(bounded._descendants(worker.pid))
        assert narrow == full == sorted(_descendants(worker.pid))
        assert set(_named(token)) <= set(narrow)
    finally:
        worker.close()
    assert _wait_gone(token) == []


def test_prctl_is_only_called_on_linux(monkeypatch):
    bounded = _bounded()
    import ctypes
    calls = []
    monkeypatch.setattr(ctypes, 'CDLL', lambda *a, **k: calls.append(a) or pytest.fail('CDLL loaded'))
    monkeypatch.setattr(bounded.sys, 'platform', 'darwin')
    bounded._arm_death_signal()
    assert calls == []
