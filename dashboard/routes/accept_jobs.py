"""Start-and-poll jobs for creating a project from a staged proposal.

``POST /scaffold/accept`` starts the accept in a worker thread and waits for it for a
short while; a slow accept answers ``202`` and the page polls
``GET /scaffold/accept/{proposal_id}``. ``POST /scaffold/cancel`` stops a job that has
not yet moved the project into place. The route file owns the proposal table; this
module owns only the jobs, and talks to the route through the three callables the
route passes to :func:`accept_answer`.

Lock order: the route's proposal lock may be held while a function here takes
``_JOBS_LOCK`` (``protects`` is called from the proposal-expiry sweep). Nothing here
calls back into the route (``claim``, ``work``) while ``_JOBS_LOCK`` is held, so the
reverse order never happens.

Every text a person can see comes from the route's own answers or from the fixed
sentences below; exception text and paths never enter a job record.
"""
from __future__ import annotations

import contextvars
import inspect
import threading
import time
from typing import Any, Callable

from fastapi import HTTPException
from fastapi.responses import JSONResponse

ACCEPT_INLINE_WAIT_S = 20.0    # POST /scaffold/accept waits this long before answering 202
ACCEPT_RESULT_TTL_S = 600.0    # a finished job's answer is kept this long after it finished
ACCEPT_CANCEL_WAIT_S = 15.0    # POST /scaffold/cancel waits this long for the job to stop
MAX_RUNNING_JOBS = 4           # accepts running at once in this process
MAX_STORED_JOBS = 64           # finished answers kept at once (oldest dropped first)

UNKNOWN_DETAIL = 'Unknown or consumed proposal_id'
BUSY_DETAIL = 'Too many projects are being created at once. Wait for one to finish, then try again.'
CRASH_DETAIL = ('Project creation stopped because of an unexpected error. '
                'Check the project list before trying again.')

STEP_PREPARE = 'Preparing the project'
STEP_CHECK = "Running the project's first check"
STEP_MOVE = 'Moving the project into place'
STEP_REGISTER = 'Registering the project'
# Phase names an accept function may report through ``progress``; anything else is ignored.
PHASE_STEPS = {'prepare': STEP_PREPARE, 'check': STEP_CHECK,
               'move': STEP_MOVE, 'register': STEP_REGISTER}
_NO_RETURN_PHASES = frozenset({'move', 'register'})

_JOBS: dict[str, '_Job'] = {}
_JOBS_LOCK = threading.Lock()


class _Job:
    """One accept attempt for one proposal; fields are read and written under _JOBS_LOCK."""

    def __init__(self, proposal_id: str, home: str, previous: '_Job | None') -> None:
        self.proposal_id = proposal_id
        self.home = home
        self.previous = previous          # finished job this one replaces, until the claim succeeds
        self.state = 'starting'           # starting -> running -> done | failed | cancelled
        self.started_at = time.monotonic()
        self.finished_at: float | None = None
        self.step = STEP_PREPARE
        self.hooked = False               # the accept function reports its own phases
        self.no_return = False            # the project is being moved into place: too late to cancel
        self.cancel_requested = False
        self.cancel_fired = False         # the accept function saw the cancel and is stopping
        self.result: Any = None
        self.http_status: int | None = None
        self.detail: Any = None
        self.partial = False
        self.retryable = False            # the proposal is ready again: a new accept starts a new job
        self.claimed = threading.Event()  # set when the claim has succeeded or failed
        self.done = threading.Event()     # set when the job has finished (any outcome)

    @property
    def finished(self) -> bool:
        return self.state in ('done', 'failed', 'cancelled')


class CancelToken:
    """Passed to the accept function as ``cancel`` (and ``progress`` when it takes one).

    ``is_set()`` is what scaffolder/kit_scaffold already poll between steps. Once the
    project is being moved into place it always answers False."""

    def __init__(self, job: _Job) -> None:
        self._job = job

    def is_set(self) -> bool:
        with _JOBS_LOCK:
            job = self._job
            if not job.hooked and job.step == STEP_PREPARE:
                job.step = STEP_CHECK
            if job.cancel_requested and not job.no_return:
                job.cancel_fired = True
                return True
            return False

    def progress(self, phase: str) -> None:
        step = PHASE_STEPS.get(phase) if isinstance(phase, str) else None
        if step is None:
            return
        with _JOBS_LOCK:
            job = self._job
            job.hooked = True
            job.step = step
            if phase in _NO_RETURN_PHASES and not job.cancel_fired:
                job.no_return = True

    def kwargs_for(self, fn: Callable[..., Any]) -> dict[str, Any]:
        """Keyword arguments for an accept function: ``cancel`` and ``progress``, each only
        when the function takes it (scaffolder.accept and kit_scaffold.accept_kit take
        ``cancel`` today; ``progress`` is the optional phase hook)."""
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            return {}
        open_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        kwargs: dict[str, Any] = {}
        if open_kw or 'cancel' in params:
            kwargs['cancel'] = self
        if 'progress' in params:
            kwargs['progress'] = self.progress
        return kwargs


def _elapsed(job: _Job, now: float) -> float:
    return round(max(0.0, (job.finished_at or now) - job.started_at), 1)


def _prune_locked(now: float) -> None:
    """Drop finished jobs past their time limit, then the oldest finished ones over the cap."""
    for pid in [pid for pid, job in _JOBS.items()
                if job.finished and job.finished_at is not None
                and now - job.finished_at >= ACCEPT_RESULT_TTL_S]:
        del _JOBS[pid]
    finished = sorted((job.finished_at or 0.0, pid) for pid, job in _JOBS.items() if job.finished)
    while finished and len(finished) > MAX_STORED_JOBS:
        del _JOBS[finished.pop(0)[1]]


def _lookup_locked(proposal_id: str, home: str) -> _Job | None:
    _prune_locked(time.monotonic())
    job = _JOBS.get(proposal_id)
    return job if job is not None and job.home == home else None


def _running_count_locked() -> int:
    return sum(1 for job in _JOBS.values() if not job.finished)


def _is_partial(detail: Any) -> bool:
    return isinstance(detail, dict) and bool(detail.get('created_dirs'))


def _running_body(job: _Job, now: float) -> dict[str, Any]:
    return {'status': 'running', 'proposal_id': job.proposal_id, 'step': job.step,
            'elapsed_s': _elapsed(job, now)}


def _final_answer(job: _Job) -> Any:
    """What a finished POST answers: the stored body, or the stored error raised again."""
    if job.state == 'done':
        return job.result
    raise HTTPException(job.http_status or 500, job.detail)


def _run(job: _Job, token: CancelToken, claimed: Any, work: Callable[[Any, CancelToken], Any]) -> None:
    state, result, status, detail, partial, retryable = 'failed', None, 500, CRASH_DETAIL, False, False
    try:
        result = work(claimed, token)
        state = 'done'
    except HTTPException as exc:
        status, detail = exc.status_code, exc.detail
        partial = _is_partial(detail)
        with _JOBS_LOCK:
            fired = job.cancel_fired
        state = 'cancelled' if fired and not partial else 'failed'
        # The route puts a proposal back to 'ready' after a failure that moved nothing.
        retryable = state == 'cancelled' or (status == 409 and not partial)
    except BaseException as exc:  # noqa: BLE001 - recorded, never re-raised or printed
        # An unexpected error or an interrupt raised inside the worker. On an interrupt
        # (not an Exception) the route has put the proposal back to 'ready' (nothing in
        # place) or 'partial' (a folder exists); this job follows the same split, so a
        # ready proposal can be accepted again. Any other error escaped the route's own
        # handling: its answer is kept as it is.
        with _JOBS_LOCK:
            partial = job.no_return or bool(getattr(exc, 'created_dirs', None))
        retryable = not partial and not isinstance(exc, Exception)
    finally:
        with _JOBS_LOCK:
            job.state = state
            job.result = result if state == 'done' else None
            job.http_status = None if state == 'done' else status
            job.detail = None if state == 'done' else detail
            job.partial = partial
            job.retryable = retryable
            job.finished_at = time.monotonic()
            job.done.set()


def _start_thread(job: _Job, claimed: Any, work: Callable[[Any, CancelToken], Any]) -> None:
    token = CancelToken(job)
    context = contextvars.copy_context()  # keeps the request's Hermes home override
    thread = threading.Thread(target=context.run, args=(_run, job, token, claimed, work),
                              name=f'defuzz-scaffold-accept-{job.proposal_id[:8]}', daemon=True)
    with _JOBS_LOCK:
        job.state = 'running'
    try:
        thread.start()
    except BaseException:  # noqa: BLE001 - cannot start a thread: recorded as a failed job
        with _JOBS_LOCK:
            job.state, job.http_status, job.detail = 'failed', 500, CRASH_DETAIL
            job.finished_at = time.monotonic()
            job.done.set()


def _reserve(proposal_id: str, home: str) -> tuple[str, _Job]:
    """Decide what this POST does: ('wait', job), ('stored', job) or ('claim', new job)."""
    waited_for_cancel = False
    while True:
        unwinding = None
        with _JOBS_LOCK:
            _prune_locked(time.monotonic())
            job = _JOBS.get(proposal_id)
            if job is not None and job.home != home:
                raise HTTPException(404, UNKNOWN_DETAIL)
            if job is not None and job.state == 'starting':
                pending = job
            elif job is not None and not job.finished and job.cancel_fired and not waited_for_cancel:
                # Cancelled and still stopping (the cancel may already have answered
                # 'cancelled'): this POST is a new Create, so let that job end first.
                unwinding = job
            elif job is not None and not job.finished:
                return 'wait', job
            elif job is not None and not job.retryable:
                return 'stored', job
            else:
                if _running_count_locked() >= MAX_RUNNING_JOBS:
                    raise HTTPException(429, BUSY_DETAIL)
                new = _Job(proposal_id, home, job)
                _JOBS[proposal_id] = new
                return 'claim', new
        if unwinding is not None:
            unwinding.done.wait(ACCEPT_CANCEL_WAIT_S)
            waited_for_cancel = True
            continue
        # Another request is claiming this proposal right now: wait for its claim, then look again.
        pending.claimed.wait(ACCEPT_INLINE_WAIT_S)


def accept_answer(proposal_id: str, home: str, *, claim: Callable[[], Any],
                  work: Callable[[Any, CancelToken], Any],
                  inline_wait_s: float | None = None) -> Any:
    """The whole answer of ``POST /scaffold/accept``.

    ``claim()`` is the route's existing claim (moves a ready proposal to 'accepting' or
    raises its 404/409); it runs at most once per job. ``work(claimed, token)`` is the
    route's existing accept body: it returns the success body or raises the route's
    HTTPException, and passes ``token.kwargs_for(fn)`` to the accept function.
    Returns the success body, a 202 JSONResponse, or raises the final HTTPException."""
    action, job = _reserve(proposal_id, home)
    if action == 'stored':
        return _final_answer(job)
    if action == 'claim':
        try:
            claimed = claim()
        except BaseException:
            with _JOBS_LOCK:
                if _JOBS.get(proposal_id) is job:
                    if job.previous is not None:
                        _JOBS[proposal_id] = job.previous
                    else:
                        del _JOBS[proposal_id]
                job.state = 'failed'
                job.retryable = True  # nothing ran: a cancel waiting on it answers like "no job"
                job.finished_at = time.monotonic()
                job.claimed.set()
                job.done.set()
            raise
        with _JOBS_LOCK:
            job.previous = None
        _start_thread(job, claimed, work)
        job.claimed.set()
    wait_s = ACCEPT_INLINE_WAIT_S if inline_wait_s is None else inline_wait_s
    if job.done.wait(max(0.0, wait_s)):
        with _JOBS_LOCK:
            return _final_answer(job)
    with _JOBS_LOCK:
        if job.finished:
            return _final_answer(job)
        body = _running_body(job, time.monotonic())
    body['poll'] = f'/scaffold/accept/{proposal_id}'
    return JSONResponse(status_code=202, content=body)


def status(proposal_id: str, home: str) -> dict[str, Any] | None:
    """The body of ``GET /scaffold/accept/{proposal_id}``; None means the route's 404."""
    with _JOBS_LOCK:
        job = _lookup_locked(proposal_id, home)
        if job is None:
            return None
        if not job.finished:
            return _running_body(job, time.monotonic())
        if job.state == 'done':
            return {'status': 'done', 'proposal_id': proposal_id, 'result': job.result}
        if job.state == 'cancelled':
            return {'status': 'cancelled', 'proposal_id': proposal_id}
        return {'status': 'failed', 'proposal_id': proposal_id, 'http_status': job.http_status,
                'detail': job.detail, 'partial': job.partial}


def _cancel_body_locked(job: _Job) -> dict[str, Any] | None:
    if job.state == 'cancelled':
        return {'status': 'cancelled', 'proposal_id': job.proposal_id}
    if job.finished and job.retryable:
        return None  # the proposal is ready again: the route answers 'idle'
    return {'status': 'running', 'proposal_id': job.proposal_id, 'cancel': 'too_late'}


def cancel(proposal_id: str, home: str, *, wait_s: float | None = None) -> dict[str, Any] | None:
    """The body of ``POST /scaffold/cancel``; None means "no job": the route answers
    'idle' for a known proposal and its 404 otherwise.

    A cancel before the move is delivered through the token the accept function polls;
    this waits up to ``wait_s`` for the job to stop. If the accept function has not
    looked at the token by then, the request is withdrawn and the job finishes normally
    ('too_late'), so the answer is always true."""
    limit = ACCEPT_CANCEL_WAIT_S if wait_s is None else wait_s
    with _JOBS_LOCK:
        job = _lookup_locked(proposal_id, home)
        if job is None:
            return None
        if job.finished or job.no_return:
            return _cancel_body_locked(job)
        job.cancel_requested = True
    job.claimed.wait(max(0.0, limit))
    job.done.wait(max(0.0, limit))
    with _JOBS_LOCK:
        if job.finished:
            return _cancel_body_locked(job)
        if not job.cancel_fired:
            job.cancel_requested = False
            return {'status': 'running', 'proposal_id': proposal_id, 'cancel': 'too_late'}
    # The accept function saw the cancel and is unwinding; nothing will be moved now.
    job.done.wait(max(0.0, limit))
    with _JOBS_LOCK:
        if job.finished:
            return _cancel_body_locked(job)
    return {'status': 'cancelled', 'proposal_id': proposal_id}


def protects(proposal_id: str) -> bool:
    """True while a job runs or its answer is kept: the proposal must not expire.

    Called by the route's expiry sweep with the route's lock held (see lock order)."""
    with _JOBS_LOCK:
        now = time.monotonic()
        _prune_locked(now)
        job = _JOBS.get(proposal_id)
        if job is None:
            return False
        if job.state == 'starting':
            # Being claimed right now: only an earlier, still-kept answer protects it, so a
            # proposal past its time limit still expires when someone tries to accept it.
            prev = job.previous
            return (prev is not None and prev.finished_at is not None
                    and now - prev.finished_at < ACCEPT_RESULT_TTL_S)
        return True


def forget(proposal_id: str) -> None:
    """Drop a finished job's answer (after the proposal was discarded); a running job stays."""
    with _JOBS_LOCK:
        job = _JOBS.get(proposal_id)
        if job is not None and job.finished:
            del _JOBS[proposal_id]


def _reset_for_tests() -> None:
    with _JOBS_LOCK:
        _JOBS.clear()
