"""Hard wall-clock budget for one audit component, in a killable child.

Linux is the supported system. A component stuck in a
CPU-bound loop or a regular-expression match cannot be interrupted from a
thread, so the call runs in a child process that the parent can kill.

Mechanism
- Start method is spawn: a fresh interpreter (``sys.executable -c <fixed boot
  code>``), never fork. The parent can hold SQLite connections (the audit
  store, or a caller's live writer); a forked child inherits SQLite's
  in-memory lock bookkeeping for those files and later reads fail. A spawned
  child inherits no descriptors besides its three pipes.
- One worker per audit (``audit_call_scope``), replaced only after a kill. A
  call outside an audit scope gets its own worker. An audit sweep spawns its
  worker on entry, so the interpreter start overlaps the parent's own work.
- Data path is pipes only. argv holds the fixed boot code; the repository
  path, package name, ``sys.path``, every request and every reply travel on
  stdin/stdout as length-prefixed frames. No argument is placed in argv, the
  environment or a file. The child's stderr is a pipe whose read end the
  parent closed at once: nothing the child prints is kept.
- The child is a new session (own process group) and, on Linux, a child
  subreaper. On timeout, cancel, crash or refused reply the parent sends
  SIGTERM to the group and every descendant it can find, waits up to _GRACE_S
  for the worker to exit (its wait status, read without reaping it), freezes
  what is left with SIGSTOP, SIGKILLs it and reaps the worker. Grandchildren
  that outlive a normal call are killed when the worker is closed.

What is killed where
- Linux: the worker, its process group, and every descendant, including one
  that called setsid or double-forked: the worker is a child subreaper
  (PR_SET_CHILD_SUBREAPER), so orphans stay below it, and the parent walks
  only the worker's own tree through /proc/<pid>/task/<tid>/children. A
  kernel without that file (no CONFIG_PROC_CHILDREN) falls back to reading
  the parent pid of every process in /proc. The worker also dies with the
  parent (PR_SET_PDEATHSIG).
- Without /proc (macOS): the worker and every process still in its process
  group get SIGTERM, a real grace (the worker's wait status; other pids are
  probed with signal 0), then SIGKILL. There is no subreaper, no death signal
  and no way to list descendants, so a descendant that left the process group
  (setsid, setpgid, a double-fork daemon) is not signalled and keeps running
  until it exits by itself; nothing bounds how long. It is re-parented to
  launchd, so it leaves no zombie here. What it holds of the audit is small:
  the worker's boot code replaced its standard input with an empty pipe and
  pointed its output at a pipe nobody reads, and closed every inherited
  handle, and the parent closes its ends of the protocol pipes on kill, so
  the survivor reads end of file and fails any write; it cannot send anything
  back. No audit component starts a process today, so this is reachable only
  through a future component that starts a daemon.
- The reply is refused above RESULT_CAP_BYTES from its length prefix, before
  the body is read, and is unpickled with an allowlist of plain types.
- The child cannot do more than the parent: it never receives the audit
  store, and an audit hook in the child refuses every write-capable open,
  file-system mutation and non-read-only SQLite connection.

Determinism
The child runs the same function with the parent's audit state: the
redaction taint (all data fields, the evidence serializer key and project
roots), the audit key, and the parent's plain module-level values for the
plugin's modules (so configuration set at run time crosses). The taint the
child ends with replaces the parent's, so sealing sees exactly what an
in-process call would have produced. A call that needs live state which
cannot cross runs in-process: a function that cannot be named by module and
qualified name (a lambda or a local function), arguments that cannot be
pickled, or an active capture cache (audit.capture.CURRENT_CAPTURE).

Cancellation: a sweep that passes worker_scope(cancelled=...) is asked every
_CANCEL_POLL_MS while a check runs in the worker; a cancelled audit kills the
worker at once (BudgetExceeded('stopped', 'cancelled')) and starts no other.

Failures carry no child text: a timeout raises BudgetExceeded('timeout'); a
crash, a signal, a truncated, oversized or unreadable reply raises
BudgetExceeded('stopped'); a component exception raises RemoteFailure with the
exception type name only.
"""
from __future__ import annotations

import importlib
import io
import os
import pickle
import select
import signal
import subprocess
import sys
import time
import types
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import partial, wraps
from pathlib import Path, PurePath
from typing import Any, Iterator

# Chosen from fixture measurements (docs/audit-scope.md): every component on
# the existing fixtures finishes in well under one second. The per-component
# budget sits above the largest inner cooperative cap (profile_duplicates
# MAX_SECONDS = 30, session_contamination MAX_SECONDS = 20) so a graceful inner
# cut wins over a hard kill.
DEFAULT_COMPONENT_BUDGET_S = 60.0
DEFAULT_AUDIT_BUDGET_S = 900.0
RESULT_CAP_BYTES = 8 * 1024 * 1024
_GRACE_S = 0.1
_EXIT_S = 1.0
_START_S = 30.0
_LENGTH = 8

_ROOT_PACKAGE = __name__.rsplit('.', 2)[0]


def sentence(component: str, kind: str = 'timeout') -> str:
    """Fixed finding sentence. The name is a closed component id, never input."""
    from .evidence_constants import component_stopped_sentence, component_time_budget_sentence
    if kind == 'timeout':
        return component_time_budget_sentence(component)
    return component_stopped_sentence(component)


class BudgetExceeded(Exception):
    """Timeout ('timeout') or crash / refused reply ('stopped'). No child text.

    cause is a closed parent-side label (start, eof, refused, oversize, crash,
    unreadable, timeout, cancelled) for diagnostics; it never carries child
    output.
    """

    def __init__(self, kind: str = 'stopped', cause: str = '') -> None:
        self.kind = 'timeout' if kind == 'timeout' else 'stopped'
        self.cause = cause or self.kind
        super().__init__()


class RemoteFailure(Exception):
    """Component raised. type_name only; the message stayed in the child.

    Raised as a subclass named after the child's exception type, so the
    caller's existing ``type(exc).__name__`` no-echo sentence is unchanged.
    """

    def __init__(self, type_name: str) -> None:
        self.type_name = type_name
        super().__init__()


_REMOTE_TYPES: dict[str, type] = {}


def _remote_failure(type_name: str) -> RemoteFailure:
    cls = _REMOTE_TYPES.get(type_name)
    if cls is None:
        cls = _REMOTE_TYPES.setdefault(type_name, type(type_name, (RemoteFailure,), {}))
    return cls(type_name)


@dataclass(frozen=True)
class Budgets:
    component_s: float = DEFAULT_COMPONENT_BUDGET_S
    audit_s: float = DEFAULT_AUDIT_BUDGET_S


_BUDGETS_CV: ContextVar[Budgets] = ContextVar('defuzz_component_budgets', default=Budgets())
_IN_PROCESS: ContextVar[bool] = ContextVar('defuzz_component_in_process', default=False)
_SESSION: ContextVar[Any] = ContextVar('defuzz_component_session', default=None)
LAST_CAUSE = ['']  # diagnostics: closed label of the last budget failure


def _positive(args: dict, key: str, default: float) -> float:
    if key not in args or args[key] is None:
        return default
    value = args[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0 or value != value \
            or value == float('inf'):
        raise ValueError(f'{key} must be a positive number')
    return float(value)


@contextmanager
def bind_budgets(args: dict | None) -> Iterator[Budgets]:
    """Budgets from the audit arguments (component_budget_s, audit_budget_s)."""
    chosen = Budgets(
        _positive(args or {}, 'component_budget_s', DEFAULT_COMPONENT_BUDGET_S),
        _positive(args or {}, 'audit_budget_s', DEFAULT_AUDIT_BUDGET_S),
    )
    token = _BUDGETS_CV.set(chosen)
    try:
        yield chosen
    finally:
        _BUDGETS_CV.reset(token)


def budget_arguments(fn):
    """Decorator: budgets from the audit arguments (first positional argument)."""
    @wraps(fn)
    def wrapped(args, *rest, **kwargs):
        with bind_budgets(args if isinstance(args, dict) else None):
            return fn(args, *rest, **kwargs)
    return wrapped


def worker_scope(fn=None, *, cancelled=None):
    """Decorator: one bounded worker for the whole call (one audit sweep).

    The worker is spawned on entry, so its interpreter start overlaps the
    sweep's own in-process work. cancelled(*args, **kwargs) -> bool, when
    given, is asked while a check is running in the worker; a cancelled audit
    kills the worker at once instead of waiting for the check or its budget.
    """
    def decorate(inner):
        @wraps(inner)
        def wrapped(*args, **kwargs):
            probe = None if cancelled is None else partial(cancelled, *args, **kwargs)
            with audit_call_scope(cancelled=probe, prestart=True):
                return inner(*args, **kwargs)
        return wrapped
    return decorate if fn is None else decorate(fn)


@contextmanager
def budgets(component_s: float, audit_s: float) -> Iterator[None]:
    """Caller and test override. Not an environment variable."""
    with bind_budgets({'component_budget_s': component_s, 'audit_budget_s': audit_s}):
        yield


@contextmanager
def in_process() -> Iterator[None]:
    """Test-only switch: run components in this process. Results must match."""
    token = _IN_PROCESS.set(True)
    try:
        yield
    finally:
        _IN_PROCESS.reset(token)


def _ref(fn: Any) -> tuple[str, str] | None:
    """(module, qualname) when that name resolves back to fn, else None."""
    module = getattr(fn, '__module__', None)
    qualname = getattr(fn, '__qualname__', None)
    if not isinstance(module, str) or not isinstance(qualname, str) or not module or not qualname:
        return None
    if module in {'__main__', 'builtins'} or '<' in qualname:
        return None
    target = sys.modules.get(module)
    if target is None:
        return None
    try:
        for part in qualname.split('.'):
            target = getattr(target, part)
    except AttributeError:
        return None
    return (module, qualname) if target is fn else None


def _capture_active() -> bool:
    capture = sys.modules.get(_ROOT_PACKAGE + '.audit.capture')
    current = getattr(capture, 'CURRENT_CAPTURE', None)
    return current is not None and current.get() is not None


class _Session:
    def __init__(self, cancelled: Any = None) -> None:
        self.spent = 0.0
        self.worker: _Worker | None = None
        self.starts = 0
        self.cancelled = cancelled
        self.halted = False  # cancelled: no further worker is started
        self.pending: _Worker | None = None  # spawned ahead, not yet ready

    def prestart(self) -> None:
        """Spawn the worker now so its interpreter start overlaps the parent's own work."""
        if self.worker is None and self.pending is None:
            try:
                self.pending = _spawn_worker(_START_S)
            except Exception:  # the first call starts it, and reports, as without a prestart
                self.pending = None

    def call(self, request: dict, component_s: float, audit_left: float) -> Any:
        begin = time.monotonic()
        if self.halted:
            raise BudgetExceeded('stopped', 'cancelled')
        if self.worker is None or not self.worker.alive():
            if self.worker is not None:
                self.worker.close()
            # Interpreter start is the bound's own cost, not the component's:
            # it has its own allowance inside the total audit budget.
            pending, self.pending = self.pending, None
            try:
                if pending is not None:
                    self.worker = pending
                    _await_ready(pending, min(_START_S, audit_left))
                else:
                    self.worker = _start_worker(min(_START_S, audit_left))
            except TimeoutError:
                self.worker = None
                raise BudgetExceeded('timeout', 'start') from None
            except OSError:
                self.worker = None
                raise BudgetExceeded('stopped', 'start') from None
            self.starts += 1
        try:
            fingerprint = _module_fingerprint()
            state = None
            if fingerprint != self.worker.state_fingerprint:
                state = _module_state()
            frame = pickle.dumps({**request, 'state': state}, protocol=pickle.HIGHEST_PROTOCOL)
            limit = min(component_s, audit_left - (time.monotonic() - begin))
            if limit <= 0:
                raise BudgetExceeded('timeout')
            reply = self.worker.request(frame, time.monotonic() + limit, self.cancelled)
            self.worker.state_fingerprint = fingerprint
            return reply
        except BudgetExceeded as exc:
            self.halted = exc.cause == 'cancelled'
            self.worker.close()
            self.worker = None
            raise

    def close(self) -> None:
        if self.pending is not None:
            self.pending.close()  # never used: nothing to finish gracefully
            self.pending = None
        if self.worker is not None:
            self.worker.close(graceful=True)
            self.worker = None


@contextmanager
def audit_call_scope(cancelled: Any = None, prestart: bool = False) -> Iterator[_Session]:
    """One worker for the audit, replaced only after a kill; closed at the end.

    prestart spawns the worker at once (an audit sweep is about to need it);
    nothing is spawned when calls run in-process.
    """
    session = _Session(cancelled)
    if prestart and not _IN_PROCESS.get() and not _capture_active():
        session.prestart()
    token = _SESSION.set(session)
    try:
        yield session
    finally:
        _SESSION.reset(token)
        session.close()


def invoke(fn: Any, kwargs: dict) -> Any:
    """Run fn(**kwargs) under the current budget, or in-process when it cannot move."""
    ref = None if _IN_PROCESS.get() or _capture_active() else _ref(fn)
    if ref is None:
        return fn(**kwargs)
    try:
        arguments = pickle.dumps(kwargs, protocol=pickle.HIGHEST_PROTOCOL)
        request = {
            'module': ref[0], 'qualname': ref[1], 'kwargs': arguments,
            'taint': pickle.dumps(_taint_seed(), protocol=pickle.HIGHEST_PROTOCOL),
            'key': _key_seed(), 'environ': dict(os.environ), 'cwd': os.getcwd(),
        }
    except (TypeError, AttributeError, ValueError, RecursionError, OSError, pickle.PicklingError):
        return fn(**kwargs)
    chosen = _BUDGETS_CV.get()
    session = _SESSION.get()
    owns = session is None
    if owns:
        session = _Session()
    start = time.monotonic()
    try:
        audit_left = chosen.audit_s - session.spent
        if audit_left <= 0:
            raise BudgetExceeded('timeout')
        reply = session.call(request, chosen.component_s, audit_left)
        return _accept(reply)
    except BudgetExceeded as exc:
        LAST_CAUSE[0] = exc.cause
        raise
    finally:
        session.spent += time.monotonic() - start
        if owns:
            session.close()


def _accept(msg: Any) -> Any:
    if not isinstance(msg, dict):
        raise BudgetExceeded('stopped')
    kind = msg.get('kind')
    if kind not in {'ok', 'exception'}:
        stage = msg.get('stage') if msg.get('stage') in {'state', 'resolve', 'environ', 'key', 'taint', 'exit'} else ''
        cause = f'{kind}:{stage}' if kind == 'crash' and stage else kind
        raise BudgetExceeded('stopped', cause if kind in {'oversize', 'crash'} else 'unreadable')
    _merge_taint(msg.get('taint'))
    if kind == 'ok':
        return msg.get('result')
    type_name = msg.get('type')
    if not isinstance(type_name, str) or not type_name.isidentifier() or len(type_name) > 80:
        raise BudgetExceeded('stopped')
    raise _remote_failure(type_name)


# ---------------------------------------------------------------- parent side

class _Worker:
    def __init__(self, proc: subprocess.Popen) -> None:
        self.proc = proc
        self.pid = proc.pid
        self.write_fd = proc.stdin.fileno()  # type: ignore[union-attr]
        self.read_fd = proc.stdout.fileno()  # type: ignore[union-attr]
        self.state_fingerprint: Any = None
        self._closed = False

    def alive(self) -> bool:
        # WNOWAIT: look without reaping, so the pid (and its group id) cannot be
        # recycled before close() has signalled the group.
        if self._closed:
            return False
        return not _exited(self.pid, self.proc)

    def request(self, request: bytes, deadline: float, cancelled: Any = None) -> Any:
        try:
            _write_frame(self.write_fd, request, deadline)
            reply = _read_frame(self.read_fd, deadline, RESULT_CAP_BYTES, cancelled)
        except _Cancelled:
            raise BudgetExceeded('stopped', 'cancelled') from None
        except TimeoutError:
            raise BudgetExceeded('timeout') from None
        except ValueError:
            raise BudgetExceeded('stopped', 'refused') from None
        except (EOFError, OSError):
            raise BudgetExceeded('stopped', 'eof') from None
        try:
            return _loads_safe(reply)
        except Exception:
            raise BudgetExceeded('stopped', 'unreadable') from None

    def close(self, graceful: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        if graceful:
            # Descendants first, while the worker (their subreaper) still
            # holds them; then end of input: the idle worker runs its exit
            # handlers (cleanup of what its imports created) and exits.
            _kill_descendants(self.pid)
            try:
                self.proc.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass
            deadline = time.monotonic() + _EXIT_S
            # Wait without reaping: the zombie keeps the pid (and group id)
            # ours until the group has been signalled below.
            while time.monotonic() < deadline and not _exited(self.pid, self.proc):
                time.sleep(0.005)
        try:
            _shutdown_tree(self.pid, self.proc)
        finally:
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _signal(self.pid, signal.SIGKILL)
                self.proc.wait()


_BOOT = r'''
import importlib.util, os, sys, types

def _line():
    buf = bytearray()
    while True:
        chunk = os.read(0, 1)
        if not chunk or chunk == b"\n":
            return bytes(buf).decode("utf-8", "surrogateescape")
        buf += chunk

sys.dont_write_bytecode = True
repo, package, parent_pid = _line(), _line(), int(_line())
count = int(_line())
paths = [_line() for _ in range(count)]
sys.path[:] = [entry for entry in paths if entry]
# Every missing ancestor: the package may sit several levels deep (the
# dashboard loads its private copy as <dashboard module>__pkg).
parts = package.split(".")
for depth in range(1, len(parts)):
    parent = ".".join(parts[:depth])
    if parent not in sys.modules:
        ns = types.ModuleType(parent)
        ns.__path__ = []
        ns.__package__ = parent
        sys.modules[parent] = ns
spec = importlib.util.spec_from_file_location(
    package, os.path.join(repo, "__init__.py"), submodule_search_locations=[repo])
module = importlib.util.module_from_spec(spec)
module.__package__ = package
module.__path__ = [repo]
sys.modules[package] = module
spec.loader.exec_module(module)
importlib.import_module(package + ".audit.bounded_call").worker_main(parent_pid)
'''


def _start_worker(limit: float) -> _Worker:
    worker = _spawn_worker(limit)
    _await_ready(worker, limit)
    return worker


def _spawn_worker(limit: float) -> _Worker:
    """Start the interpreter and send its boot lines; do not wait for it."""
    repo = str(Path(__file__).resolve().parents[1])
    proc = subprocess.Popen(
        [sys.executable, '-c', _BOOT],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, close_fds=True,
    )
    # Nothing the child writes to stderr is read or kept (it could hold secrets).
    proc.stderr.close()  # type: ignore[union-attr]
    worker = _Worker(proc)
    deadline = time.monotonic() + limit
    try:
        lines = [repo, _ROOT_PACKAGE, str(os.getpid()), str(len(sys.path)), *map(str, sys.path)]
        _write_all(worker.write_fd, b''.join(
            line.encode('utf-8', 'surrogateescape') + b'\n' for line in lines), deadline)
    except TimeoutError:
        worker.close()
        raise
    except OSError:
        worker.close()
        raise OSError('component worker did not start') from None
    return worker


def _await_ready(worker: _Worker, limit: float) -> None:
    """Wait for the worker's ready byte; close it on any failure."""
    try:
        ready = _read_exact(worker.read_fd, 1, time.monotonic() + limit)
    except TimeoutError:
        worker.close()
        raise
    except (EOFError, OSError):
        worker.close()
        raise OSError('component worker did not start') from None
    if ready != b'R':
        worker.close()
        raise OSError('component worker did not start')


def _ppid_map() -> dict[int, int]:
    """Parent pid of every process: the fallback walk, used only without children files."""
    out: dict[int, int] = {}
    try:
        names = os.listdir('/proc')
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(f'/proc/{name}/stat', 'rb') as handle:
                stat = handle.read(4096)
            out[int(name)] = int(stat.rsplit(b')', 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
    return out


def _children_files() -> bool:
    """True where the kernel lists each thread's children (CONFIG_PROC_CHILDREN)."""
    me = os.getpid()
    return os.path.exists(f'/proc/{me}/task/{me}/children')


def _children(pid: int) -> list[int]:
    """Direct children of pid, from its threads' children files only."""
    try:
        tids = os.listdir(f'/proc/{pid}/task')
    except OSError:
        return []
    out: list[int] = []
    for tid in tids:
        if not tid.isdigit():
            continue
        try:
            with open(f'/proc/{pid}/task/{tid}/children', 'rb') as handle:
                out.extend(int(child) for child in handle.read().split())
        except (OSError, ValueError):
            continue
    return out


def _descendants(pid: int) -> list[int]:
    """Everything below pid. Empty where there is no /proc (descendants unknown)."""
    if _children_files():
        direct = _children
    else:
        children: dict[int, list[int]] = {}
        for child, parent in _ppid_map().items():
            children.setdefault(parent, []).append(child)
        direct = lambda current: children.get(current, ())  # noqa: E731
    found, stack = [], [pid]
    while stack:
        for child in direct(stack.pop()):
            if child not in found and child != pid:
                found.append(child)
                stack.append(child)
    return found


def _signal(pid: int, sig: int) -> None:
    try:
        os.kill(pid, sig)
    except OSError:
        return


def _signal_tree(pid: int, sig: int, extras: list[int]) -> None:
    try:
        os.killpg(pid, sig)
    except OSError:
        pass
    for child in extras:
        _signal(child, sig)
    _signal(pid, sig)


def _exited(pid: int, proc: subprocess.Popen | None = None) -> bool:
    """True once the direct child pid has exited.

    Looks without reaping where os.waitid exists (Linux; macOS from Python
    3.13), so the pid, and the group id, stay ours until the group has been
    signalled. Elsewhere the Popen object reaps it; POSIX keeps a process
    group id from being reused while any member is alive, so signalling the
    group afterwards still reaches only what is left of it.
    """
    if hasattr(os, 'waitid'):
        try:
            return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        except ChildProcessError:
            return True
    if proc is not None:
        return proc.poll() is not None
    try:
        return os.waitpid(pid, os.WNOHANG)[0] != 0
    except ChildProcessError:
        return True


def _gone(pid: int) -> bool:
    """True when pid (not a direct child) has exited or is a zombie."""
    try:
        with open(f'/proc/{pid}/stat', 'rb') as handle:
            state = handle.read(4096).rsplit(b')', 1)[1].split()[0]
        return state in {b'Z', b'X'}
    except (OSError, IndexError):
        pass
    # No /proc: signal 0 only tells whether the pid exists. A zombie still
    # exists, so this errs on waiting (never past the grace). A pid that now
    # belongs to another user (EPERM) is no longer one of ours.
    try:
        os.kill(pid, 0)
    except OSError:  # ESRCH: gone; EPERM: the pid was reused by someone else
        return True
    return False


def _kill_descendants(pid: int) -> None:
    """Freeze and SIGKILL everything below pid (not pid itself)."""
    seen: list[int] = []
    for _ in range(20):
        current = _descendants(pid)
        for child in current:
            _signal(child, signal.SIGSTOP)
        if set(current) <= set(seen):
            break
        seen = list(dict.fromkeys([*seen, *current]))
    for child in seen:
        _signal(child, signal.SIGKILL)


def _shutdown_tree(pid: int, proc: subprocess.Popen | None = None) -> None:
    """SIGTERM the worker's group and descendants, short grace, then SIGKILL."""
    extras = _descendants(pid)
    _signal_tree(pid, signal.SIGTERM, extras)
    deadline = time.monotonic() + _GRACE_S
    while time.monotonic() < deadline:
        if _exited(pid, proc) and all(_gone(child) for child in extras):
            break
        time.sleep(0.005)
    # Freeze before the final walk so nothing forks or escapes between the
    # walk and the kill; the worker is a subreaper, so orphans stay below it.
    seen: list[int] = []
    for _ in range(20):
        current = _descendants(pid)
        _signal_tree(pid, signal.SIGSTOP, current)
        if set(current) <= set(seen):
            break
        seen = list(dict.fromkeys([*seen, *current]))
    seen = list(dict.fromkeys([*extras, *seen, *_descendants(pid)]))
    _signal_tree(pid, signal.SIGKILL, seen)


# ----------------------------------------------------------------- child side

def worker_main(parent_pid: int) -> None:
    """Entry used by the spawned interpreter. Never returns to a caller."""
    try:
        read_fd, write_fd = _become_worker(parent_pid)
        if _worker_loop(read_fd, write_fd):
            # Clean end of input only: run exit handlers (cleanup of what
            # imports created), never after a component asked to exit.
            _IMPORTING[0] = True
            import atexit
            atexit._run_exitfuncs()
    except BaseException:
        pass
    os._exit(0)


class _Sink(io.TextIOBase):
    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        return len(text)


def _become_worker(parent_pid: int) -> tuple[int, int]:
    if os.getpgrp() != os.getpid():
        os.setsid()
    _arm_death_signal()
    if os.getppid() != parent_pid:
        os._exit(0)
    # Move the protocol pipes off 0/1 so stray prints cannot corrupt a frame.
    read_fd, write_fd = os.dup(0), os.dup(1)
    empty_r, empty_w = os.pipe()
    os.close(empty_w)
    os.dup2(empty_r, 0)
    os.close(empty_r)
    os.dup2(2, 1)  # fd 2 is a pipe the parent never reads
    sys.stdin = io.StringIO('')
    sys.stdout = sys.stderr = _Sink()
    _close_inherited({0, 1, 2, read_fd, write_fd})
    sys.addaudithook(_read_only_hook)
    _write_all(write_fd, b'R', None)
    return read_fd, write_fd


_FD_DIRS = ('/proc/self/fd', '/dev/fd')  # Linux, then macOS (no /proc there)


def _close_inherited(keep: set[int]) -> None:
    """Close every descriptor not in keep: listed when possible, else by range."""
    for directory in _FD_DIRS:
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if name.isdigit() and int(name) not in keep:
                try:
                    os.close(int(name))
                except OSError:
                    pass
        return
    try:
        top = os.sysconf('SC_OPEN_MAX')
    except (AttributeError, ValueError, OSError):
        top = -1
    low = 0
    for fd in sorted(keep):
        os.closerange(low, fd)
        low = fd + 1
    os.closerange(low, max(top if top > 0 else 4096, low))


def _arm_death_signal() -> None:
    # prctl is Linux only. Elsewhere (macOS) there is no death signal and no
    # subreaper: see "What is killed where" in the module docstring.
    if not sys.platform.startswith('linux'):
        return
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG: die with the parent
        libc.prctl(36, 1)  # PR_SET_CHILD_SUBREAPER: orphans stay below the worker
    except (OSError, AttributeError):
        return


_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_MUTATING_EVENTS = frozenset({
    'os.remove', 'os.rename', 'os.mkdir', 'os.rmdir', 'shutil.rmtree', 'os.link',
    'os.symlink', 'os.truncate', 'os.chmod', 'os.chown', 'os.utime', 'os.chflags',
    'os.lchflags', 'os.mkfifo', 'os.mknod', 'os.setxattr', 'os.removexattr',
    'shutil.copyfile', 'shutil.copymode', 'shutil.copystat', 'shutil.copytree',
    'shutil.move', 'shutil.chown',
})


_IMPORTING = [False]


def _read_only_hook(event: str, args: tuple) -> None:
    """The child may read; it may not write anything. Raised as PermissionError."""
    if _IMPORTING[0]:
        return
    if event == 'open':
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else 0
        if (isinstance(mode, str) and any(c in mode for c in 'wax+')) or \
                (isinstance(flags, int) and flags & _WRITE_FLAGS):
            raise PermissionError('read-only audit worker')
    elif event in _MUTATING_EVENTS:
        raise PermissionError('read-only audit worker')
    elif event == 'sqlite3.connect':
        target = os.fsdecode(args[0]) if args and isinstance(args[0], (str, bytes, PurePath)) else ''
        query = target.partition('?')[2].split('&') if target.startswith('file:') else ()
        if target != ':memory:' and 'mode=ro' not in query and 'mode=memory' not in query:
            raise PermissionError('read-only audit worker')


def _worker_loop(read_fd: int, write_fd: int) -> bool:
    """Serve requests; True on a clean end of input."""
    while True:
        try:
            frame = _read_frame(read_fd, None, None)
        except EOFError:
            return True
        except (OSError, ValueError):
            return False
        try:
            req = pickle.loads(frame)  # written by the parent, on our own pipe
        except BaseException:
            return False
        reply = _run_request(req)
        try:
            payload = pickle.dumps(reply, protocol=pickle.HIGHEST_PROTOCOL)
        except BaseException:
            payload = pickle.dumps({'kind': 'crash'})
        if len(payload) > RESULT_CAP_BYTES:
            payload = pickle.dumps({'kind': 'oversize'})
        try:
            _write_frame(write_fd, payload, None)
        except OSError:
            return False
        if reply.get('kind') == 'crash':
            return False


def _run_request(req: Any) -> dict:
    if not isinstance(req, dict):
        return {'kind': 'crash'}
    stage = 'state'
    # Importing a module may write (bytecode caches, a test module's own
    # set-up): the same imports the parent already ran. The component itself
    # always runs under the read-only hook.
    _IMPORTING[0] = True
    try:
        _apply_module_state(req.get('state'))
        stage = 'resolve'
        fn: Any = importlib.import_module(req['module'])
        for part in req['qualname'].split('.'):
            fn = getattr(fn, part)
        kwargs = pickle.loads(req['kwargs'])
        stage = 'environ'
        # The parent's process state at the time of this call; imports above
        # may have changed ours.
        os.environ.clear()
        os.environ.update(req['environ'])
        os.chdir(req['cwd'])
        stage = 'key'
        _install_key(req.get('key'))
        stage = 'taint'
        owner = _install_taint(pickle.loads(req['taint']))
    except BaseException:
        return {'kind': 'crash', 'stage': stage}
    finally:
        _IMPORTING[0] = False
    try:
        result = fn(**kwargs)
    except (KeyboardInterrupt, SystemExit):
        return {'kind': 'crash', 'stage': 'exit'}
    except BaseException as exc:
        # The message may hold secrets: the type name only.
        name = type(exc).__name__
        return {'kind': 'exception', 'type': name if name.isidentifier() else 'Exception',
                'taint': _taint_final(owner)}
    return {'kind': 'ok', 'result': result, 'taint': _taint_final(owner)}


# ------------------------------------------------------- state that crosses

def _key_seed() -> dict:
    try:
        from .key import _CURRENT_KEY_BYTES, _CURRENT_KEY_PATH
    except Exception:
        return {}
    path = _CURRENT_KEY_PATH.get()
    return {'path': None if path is None else str(path), 'bytes': _CURRENT_KEY_BYTES.get()}


def _install_key(seed: Any) -> None:
    from .key import _CURRENT_KEY_BYTES, _CURRENT_KEY_PATH
    seed = seed if isinstance(seed, dict) else {}
    path = seed.get('path')
    _CURRENT_KEY_PATH.set(Path(path) if isinstance(path, str) else None)
    raw = seed.get('bytes')
    _CURRENT_KEY_BYTES.set(raw if isinstance(raw, bytes) else None)


# Taint attributes that are behaviour, not data: the serializer crosses as its
# key and project roots; owner is a parent closure (redactions it would have
# assigned are re-homed in the parent); underscore names are caches.
_TAINT_SKIP = frozenset({'serializer', 'owner'})
_DEFERRED = '\x00deferred-region\x00'


def _taint_state():
    redaction = sys.modules.get(_ROOT_PACKAGE + '.audit.redaction')
    current = getattr(redaction, '_CURRENT', None)
    return None if current is None else current.get()


def _taint_fields(state) -> dict:
    return {name: value for name, value in vars(state).items()
            if not name.startswith('_') and name not in _TAINT_SKIP}


def _taint_seed() -> dict | None:
    state = _taint_state()
    if state is None:
        return None
    serializer = state.serializer
    return {'fields': _taint_fields(state), 'owner': state.owner is not None,
            'serializer_key': serializer._key, 'project_roots': set(serializer._project_roots)}


class _DeferredOwner:
    """Child stand-in for the parent's region owner; the parent resolves it."""

    def __init__(self) -> None:
        self.sources: list = []

    def __call__(self, source) -> str:
        self.sources.append(source)
        return f'{_DEFERRED}{len(self.sources) - 1}'


def _install_taint(seed: Any) -> _DeferredOwner | None:
    from .redaction import Taint, _CURRENT
    if not isinstance(seed, dict):
        _CURRENT.set(None)
        return None
    state = Taint()
    for name, value in seed['fields'].items():
        setattr(state, name, value)
    state.serializer._key = seed['serializer_key']
    state.serializer._project_roots = seed['project_roots']
    owner = _DeferredOwner() if seed.get('owner') else None
    state.owner = owner
    _CURRENT.set(state)
    return owner


def _taint_final(owner: _DeferredOwner | None) -> dict | None:
    state = _taint_state()
    if state is None:
        return None
    return {'fields': _taint_fields(state), 'project_roots': set(state.serializer._project_roots),
            'deferred': list(owner.sources) if owner is not None else []}


def _rehome_redactions(redactions: dict, deferred: Any, state: Any) -> dict:
    rehomed: dict = {}
    for region, items in redactions.items():
        if isinstance(region, str) and region.startswith(_DEFERRED):
            try:
                source = deferred[int(region[len(_DEFERRED):])]
            except (IndexError, ValueError, TypeError):
                raise BudgetExceeded('stopped') from None
            # The region the parent's owner would have assigned in-process.
            region = state.owner(source) if state.owner else 'shared_infrastructure'
        if not isinstance(items, (set, frozenset, list, tuple)):
            raise BudgetExceeded('stopped')
        rehomed.setdefault(region, set()).update(items)
    return rehomed


def _merge_taint(final: Any) -> None:
    """Replace the parent's taint data with the child's final state, in place."""
    state = _taint_state()
    if state is None or not isinstance(final, dict) or not isinstance(final.get('fields'), dict):
        return
    fields = dict(final['fields'])
    redactions = fields.get('redactions')
    if isinstance(redactions, dict):
        deferred = final.get('deferred') or []
        fields['redactions'] = _rehome_redactions(redactions, deferred, state)
    for name, value in fields.items():
        if name.startswith('_') or name in _TAINT_SKIP:
            continue
        current = getattr(state, name, None)
        if isinstance(current, set) and isinstance(value, set):
            current.clear()
            current.update(value)
        elif isinstance(current, dict) and isinstance(value, dict):
            current.clear()
            current.update(value)
        else:
            setattr(state, name, value)
    roots = final.get('project_roots')
    if isinstance(roots, set):
        state.serializer._project_roots.clear()
        state.serializer._project_roots.update(roots)
    state._pattern_size = -1


_PLAIN_SCALARS = (type(None), bool, int, float, complex, str, bytes)
_PLAIN_LIMIT = 20000


def _plain(value: Any, budget: list[int]) -> bool:
    budget[0] -= 1
    if budget[0] < 0:
        return False
    kind = type(value)
    if kind in _PLAIN_SCALARS or isinstance(value, PurePath):
        return True
    if kind in (tuple, frozenset, list, set):
        return all(_plain(item, budget) for item in value)
    if kind is dict:
        return all(_plain(k, budget) and _plain(v, budget) for k, v in value.items())
    return False


def _mirrored(name: str) -> bool:
    """The plugin package, its top-level modules and the audit subtree."""
    if name == __name__:
        return False
    if name == _ROOT_PACKAGE:
        return True
    rest = name[len(_ROOT_PACKAGE) + 1:] if name.startswith(_ROOT_PACKAGE + '.') else ''
    return bool(rest) and ('.' not in rest or rest.startswith('audit.'))


def _mirrored_modules() -> list[tuple[str, dict]]:
    out = []
    for name, module in list(sys.modules.items()):
        if module is None or not _mirrored(name):
            continue
        try:
            out.append((name, vars(module)))
        except TypeError:
            continue
    out.sort(key=lambda item: item[0])
    return out


def _module_fingerprint() -> int:
    """Cheap change detector: rebinding (what monkeypatching does) changes ids."""
    parts = []
    for name, namespace in _mirrored_modules():
        for key, value in list(namespace.items()):
            if isinstance(value, types.ModuleType):
                continue
            size = len(value) if type(value) in (list, dict, set) else -1
            parts.append((name, key, id(value), size))
    return hash(tuple(parts))


def _module_state() -> bytes:
    """The parent's plain module values and named callables, for the child.

    Run-time configuration (and test monkeypatching) rebinds module globals;
    a fresh interpreter would otherwise see import-time values.
    """
    entries = []
    for name, namespace in _mirrored_modules():
        for key, value in list(namespace.items()):
            if key.startswith('__') and key.endswith('__') or isinstance(value, types.ModuleType):
                continue
            if _plain(value, [_PLAIN_LIMIT]):
                entries.append((name, key, 0, value))
            elif isinstance(value, (types.FunctionType, type)):
                ref = _ref(value)
                if ref is None or ref == (name, key) or ref[0].partition('.')[0] in sys.stdlib_module_names:
                    continue
                entries.append((name, key, 1, ref))
    return pickle.dumps(entries, protocol=pickle.HIGHEST_PROTOCOL)


_MISSING = object()
_PRISTINE: dict[tuple[str, str], Any] = {}


def _apply_module_state(state: Any) -> None:
    """Restore what earlier requests changed, then take the parent's values."""
    if not isinstance(state, bytes):
        return
    entries = pickle.loads(state)  # written by the parent, on our own pipe
    for (module_name, key), value in list(_PRISTINE.items()):
        module = sys.modules.get(module_name)
        if module is None:
            continue
        if value is _MISSING:
            module.__dict__.pop(key, None)
        else:
            setattr(module, key, value)
    _PRISTINE.clear()
    resolved = []
    for module_name, key, kind, value in entries:
        try:
            module = sys.modules.get(module_name)
            if module is None:
                if not module_name.startswith(_ROOT_PACKAGE + '.audit.'):
                    continue  # not loaded here; components import from the audit subtree
                module = importlib.import_module(module_name)
            if kind == 1:
                target: Any = importlib.import_module(value[0])
                for part in value[1].split('.'):
                    target = getattr(target, part)
                value = target
        except Exception:
            continue
        resolved.append((module, module_name, key, value))
    for module, module_name, key, value in resolved:
        current = module.__dict__.get(key, _MISSING)
        if current is value or (type(current) is type(value) and _same(current, value)):
            continue
        _PRISTINE.setdefault((module_name, key), current)
        setattr(module, key, value)


def _same(left: Any, right: Any) -> bool:
    try:
        return bool(left == right)
    except Exception:
        return False


# ------------------------------------------------------------ pipe frames

def _install_pipe_reducers() -> None:
    """Round-trip factory-only evidence strings across the pipe.

    pickle would call GeneratedDigest(value) and the class refuses that. The
    reducers call the same factories the parent used; they are registered on
    import in both processes.
    """
    import copyreg
    from . import evidence as ev

    copyreg.pickle(ev.GeneratedDigest, lambda value: (ev.generated_digest, (str(value),)))
    copyreg.pickle(ev.ControlIdentity, lambda value: (ev.control_identity, (str(value),)))
    copyreg.pickle(ev.SealedKey, lambda value: (_rebuild_sealed_key, (str(value),)))
    copyreg.pickle(ev.PersistedJSON, lambda value: (_rebuild_persisted, (str(value),)))
    copyreg.pickle(ev.SealedEvidence, lambda value: (_rebuild_sealed, (value._canonical,)))


def _rebuild_sealed_key(value: str):
    from .evidence import SealedKey, _FACTORY
    return SealedKey(value, _factory=_FACTORY)


def _rebuild_persisted(value: str):
    from .evidence import PersistedJSON
    return PersistedJSON(value)


def _rebuild_sealed(canonical: str):
    import json
    from .evidence import SealedEvidence, _FACTORY
    return SealedEvidence(_factory=_FACTORY, **json.loads(canonical))


_install_pipe_reducers()


class _Restricted(pickle.Unpickler):
    """Replies come from a process that read hostile input: plain types only."""

    _ALLOWED = {
        ('builtins', 'set'), ('builtins', 'frozenset'), ('builtins', 'bytearray'),
        ('builtins', 'complex'),
        ('pathlib', 'Path'), ('pathlib', 'PosixPath'), ('pathlib', 'PurePath'),
        ('pathlib', 'PurePosixPath'),
        ('pathlib._local', 'Path'), ('pathlib._local', 'PosixPath'),
        ('pathlib._local', 'PurePath'), ('pathlib._local', 'PurePosixPath'),
        (f'{_ROOT_PACKAGE}.audit.evidence', 'generated_digest'),
        (f'{_ROOT_PACKAGE}.audit.evidence', 'control_identity'),
        (__name__, '_rebuild_sealed_key'),
        (__name__, '_rebuild_persisted'),
        (__name__, '_rebuild_sealed'),
    }

    def find_class(self, module: str, name: str):  # noqa: ANN204
        if (module, name) not in self._ALLOWED:
            raise pickle.UnpicklingError('refused')
        return super().find_class(module, name)


def _loads_safe(blob: bytes) -> Any:
    return _Restricted(io.BytesIO(blob)).load()


class _Cancelled(Exception):
    """The audit was cancelled while a check was running in the worker."""


_CANCEL_POLL_MS = 200


def _wait(fd: int, event: int, deadline: float | None, cancelled: Any = None) -> None:
    poller = select.poll()
    poller.register(fd, event)
    while True:
        timeout_ms = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            timeout_ms = max(1, int(remaining * 1000))
        if cancelled is not None:
            # A quick reply never waits a full slice, so it never asks.
            timeout_ms = _CANCEL_POLL_MS if timeout_ms is None else min(timeout_ms, _CANCEL_POLL_MS)
        try:
            events = poller.poll(timeout_ms)
        except InterruptedError:
            continue
        if events:
            return
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError
        if cancelled is not None and _asked(cancelled):
            raise _Cancelled


def _asked(cancelled: Any) -> bool:
    try:
        return bool(cancelled())
    except Exception:
        return False


def _write_all(fd: int, data: bytes, deadline: float | None) -> None:
    view = memoryview(data)
    while view:
        _wait(fd, select.POLLOUT, deadline)
        try:
            written = os.write(fd, view[:1 << 20])
        except (InterruptedError, BlockingIOError):
            continue
        if written <= 0:
            raise OSError('short write')
        view = view[written:]


def _write_frame(fd: int, payload: bytes, deadline: float | None) -> None:
    _write_all(fd, len(payload).to_bytes(_LENGTH, 'big'), deadline)
    _write_all(fd, payload, deadline)


def _read_exact(fd: int, count: int, deadline: float | None, cancelled: Any = None) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        _wait(fd, select.POLLIN, deadline, cancelled)
        try:
            chunk = os.read(fd, min(count - len(buf), 1 << 20))
        except InterruptedError:
            continue
        if not chunk:
            raise EOFError
        buf += chunk
    return bytes(buf)


def _read_frame(fd: int, deadline: float | None, cap: int | None, cancelled: Any = None) -> bytes:
    length = int.from_bytes(_read_exact(fd, _LENGTH, deadline, cancelled), 'big')
    if length == 0 or (cap is not None and length > cap):
        raise ValueError('frame refused')
    return _read_exact(fd, length, deadline, cancelled)
