"""Start-and-poll jobs for project creation (dashboard/routes/accept_jobs.py).

The fake accept functions block on events, so no test depends on machine speed."""
from __future__ import annotations

import contextvars
import json
import threading

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from tests.conftest import load_submodule

jobs = load_submodule('dashboard.routes.accept_jobs')

HOME = '/homes/a'
WAIT = 5.0  # upper bound for event waits; every wait below ends as soon as its event is set


@pytest.fixture(autouse=True)
def _clean_jobs():
    jobs._reset_for_tests()
    yield
    jobs._reset_for_tests()


class FakeRoute:
    """The route's proposal table and claim rules, with a fake accept that blocks on events."""

    def __init__(self, behaviour='ok', hook=False):
        self.lock = threading.Lock()
        self.rows: dict[str, dict] = {}
        self.behaviour = behaviour
        self.hook = hook
        self.started = threading.Event()
        self.release = threading.Event()
        self.terminated = threading.Event()
        self.calls = 0
        self.claims = 0

    def add(self, pid, home=HOME):
        self.rows[pid] = {'state': 'ready', 'home': home}

    def claim(self, pid, home=HOME):
        def _claim():
            with self.lock:
                self.claims += 1
                row = self.rows.get(pid)
                if row is None or row['home'] != home:
                    raise HTTPException(404, 'Unknown or consumed proposal_id')
                if row['state'] != 'ready':
                    raise HTTPException(409, 'Proposal is busy or requires inspection after partial creation')
                row['state'] = 'accepting'
            return pid
        return _claim

    def accept_fn(self, *, cancel, progress=None):
        """Stands in for scaffolder.accept: polls the token while its 'check' runs."""
        self.calls += 1
        if progress is not None:
            progress('prepare')
            progress('check')
        self.started.set()
        while not self.release.wait(0.01):
            if cancel.is_set():
                self.terminated.set()
                raise RuntimeError('Scaffold accept cancelled during check app')
        if self.behaviour == 'crash':
            raise KeyError('/private/staging/secret-path')
        if self.behaviour == 'fail':
            raise RuntimeError('Check command failed with exit code 1 in app')
        if progress is not None:
            progress('move')
            progress('register')
        if self.behaviour == 'partial':
            err = RuntimeError('Failed to record project')
            err.created_dirs = ['/projects/app']
            raise err
        return {'repos': [{'path': '/projects/app'}], 'answers_id': 7}

    def accept_fn_no_poll(self, *, cancel):
        """An accept whose check never looks at the token (no cancel hook inside the check)."""
        self.calls += 1
        self.started.set()
        cancel.is_set()
        self.release.wait(WAIT)
        return {'repos': [], 'answers_id': 1}

    def work(self, fn=None):
        def _work(pid, token):
            target = fn or (self.accept_fn if self.hook else
                            (lambda *, cancel: self.accept_fn(cancel=cancel)))
            try:
                result = target(**token.kwargs_for(target))
            except Exception as exc:
                if isinstance(exc, KeyError):
                    raise  # an unexpected error outside the route's own handling
                with self.lock:
                    self.rows[pid]['state'] = 'partial' if getattr(exc, 'created_dirs', []) else 'ready'
                raise HTTPException(409, {'error': str(exc), 'output': '',
                                          'created_dirs': list(getattr(exc, 'created_dirs', []))}) from exc
            with self.lock:
                self.rows.pop(pid, None)
            return {'status': 'created', **result}
        return _work

    def post(self, pid, home=HOME, wait=0.05, fn=None):
        return jobs.accept_answer(pid, home, claim=self.claim(pid, home), work=self.work(fn), inline_wait_s=wait)


def _body(resp):
    assert isinstance(resp, JSONResponse)
    return resp.status_code, json.loads(resp.body)


def _post_error(route, pid, **kw):
    with pytest.raises(HTTPException) as info:
        route.post(pid, **kw)
    return info.value


def _wait_done(pid, home=HOME):
    with jobs._JOBS_LOCK:
        job = jobs._JOBS[pid]
    assert job.done.wait(WAIT)


def test_finished_within_the_wait_passes_the_final_answer_through_unchanged():
    route = FakeRoute()
    route.add('p1')
    route.release.set()
    assert route.post('p1', wait=WAIT) == {'status': 'created', 'repos': [{'path': '/projects/app'}], 'answers_id': 7}
    assert 'p1' not in route.rows
    err = FakeRoute(behaviour='fail')
    err.add('p2')
    err.release.set()
    exc = _post_error(err, 'p2', wait=WAIT)
    assert exc.status_code == 409 and exc.detail['error'].startswith('Check command failed')
    assert err.rows['p2']['state'] == 'ready'


def test_still_running_answers_202_and_a_second_start_joins_the_same_job():
    route = FakeRoute(hook=True)
    route.add('p1')
    code, body = _body(route.post('p1'))
    assert code == 202
    assert body['status'] == 'running' and body['proposal_id'] == 'p1'
    assert body['poll'] == '/scaffold/accept/p1'
    assert body['step'] in jobs.PHASE_STEPS.values()
    assert isinstance(body['elapsed_s'], float)
    code2, body2 = _body(route.post('p1'))
    assert code2 == 202 and body2['status'] == 'running'
    assert route.calls == 1 and route.claims == 1
    route.release.set()
    _wait_done('p1')
    # Called again after it finished: the stored final answer, the same as the first time.
    assert route.post('p1') == {'status': 'created', 'repos': [{'path': '/projects/app'}], 'answers_id': 7}
    assert route.calls == 1


def test_poll_running_done_failed_cancelled_and_unknown():
    assert jobs.status('nope', HOME) is None
    route = FakeRoute(hook=True)
    route.add('p1')
    route.post('p1')
    assert route.started.wait(WAIT)
    running = jobs.status('p1', HOME)
    assert running['status'] == 'running' and running['step'] == jobs.STEP_CHECK
    assert set(running) == {'status', 'proposal_id', 'step', 'elapsed_s'}
    route.release.set()
    _wait_done('p1')
    assert jobs.status('p1', HOME) == {'status': 'done', 'proposal_id': 'p1', 'result': {
        'status': 'created', 'repos': [{'path': '/projects/app'}], 'answers_id': 7}}
    assert jobs.status('p1', HOME) == jobs.status('p1', HOME)  # reading changes nothing

    failing = FakeRoute(behaviour='partial', hook=True)
    failing.add('p2')
    failing.post('p2')
    failing.release.set()
    _wait_done('p2')
    failed = jobs.status('p2', HOME)
    assert failed == {'status': 'failed', 'proposal_id': 'p2', 'http_status': 409, 'partial': True,
                      'detail': {'error': 'Failed to record project', 'output': '',
                                 'created_dirs': ['/projects/app']}}
    # A partial failure is final: posting again gives the stored answer, not a new job.
    exc = _post_error(failing, 'p2')
    assert exc.status_code == 409 and exc.detail['created_dirs'] == ['/projects/app']
    assert failing.calls == 1

    cancelling = FakeRoute()
    cancelling.add('p3')
    cancelling.post('p3')
    assert cancelling.started.wait(WAIT)
    assert jobs.cancel('p3', HOME, wait_s=WAIT) == {'status': 'cancelled', 'proposal_id': 'p3'}
    assert jobs.status('p3', HOME) == {'status': 'cancelled', 'proposal_id': 'p3'}


def test_stored_result_expires(monkeypatch):
    route = FakeRoute()
    route.add('p1')
    route.release.set()
    route.post('p1', wait=WAIT)
    assert jobs.status('p1', HOME)['status'] == 'done'
    assert jobs.protects('p1')
    monkeypatch.setattr(jobs, 'ACCEPT_RESULT_TTL_S', 0.0)
    assert jobs.status('p1', HOME) is None
    assert not jobs.protects('p1')
    # After expiry the route's own answer for a consumed proposal comes back.
    exc = _post_error(route, 'p1')
    assert exc.status_code == 404 and exc.detail == 'Unknown or consumed proposal_id'


def test_cancel_before_the_move_terminates_the_check_and_leaves_the_proposal_ready():
    route = FakeRoute(hook=True)
    route.add('p1')
    assert _body(route.post('p1'))[0] == 202
    assert route.started.wait(WAIT)
    assert jobs.cancel('p1', HOME, wait_s=WAIT) == {'status': 'cancelled', 'proposal_id': 'p1'}
    assert route.terminated.is_set()
    assert route.rows['p1']['state'] == 'ready'
    # The user may accept again: that starts a new job.
    route.started.clear()
    route.release.set()
    assert route.post('p1', wait=WAIT)['status'] == 'created'
    assert route.calls == 2


def test_cancel_after_the_move_is_too_late_and_the_job_finishes_normally():
    route = FakeRoute(hook=True)
    route.add('p1')
    moved = threading.Event()
    go_on = threading.Event()

    def accept_fn(*, cancel, progress):
        route.calls += 1
        progress('check')
        assert not cancel.is_set()
        progress('move')
        moved.set()
        go_on.wait(WAIT)
        assert not cancel.is_set()  # never answers True once the move started
        return {'repos': [], 'answers_id': 2}

    route.post('p1', fn=accept_fn)
    assert moved.wait(WAIT)
    assert jobs.status('p1', HOME)['step'] == jobs.STEP_MOVE
    assert jobs.cancel('p1', HOME, wait_s=WAIT) == {'status': 'running', 'proposal_id': 'p1', 'cancel': 'too_late'}
    go_on.set()
    _wait_done('p1')
    assert jobs.status('p1', HOME)['status'] == 'done'
    assert jobs.cancel('p1', HOME) == {'status': 'running', 'proposal_id': 'p1', 'cancel': 'too_late'}


def test_cancel_that_the_accept_never_sees_is_withdrawn_and_answers_too_late():
    route = FakeRoute()
    route.add('p1')
    route.post('p1', fn=route.accept_fn_no_poll)
    assert route.started.wait(WAIT)
    assert jobs.status('p1', HOME)['step'] == jobs.STEP_CHECK  # coarse phase without a progress hook
    assert jobs.cancel('p1', HOME, wait_s=0.05) == {'status': 'running', 'proposal_id': 'p1', 'cancel': 'too_late'}
    route.release.set()
    _wait_done('p1')
    assert jobs.status('p1', HOME)['status'] == 'done'


def test_cancel_with_no_job_and_for_a_ready_proposal_after_a_failure():
    assert jobs.cancel('none', HOME) is None
    route = FakeRoute(behaviour='fail')
    route.add('p1')
    route.release.set()
    with pytest.raises(HTTPException):
        route.post('p1', wait=WAIT)
    assert route.rows['p1']['state'] == 'ready'
    assert jobs.cancel('p1', HOME) is None  # the route answers 'idle'


def test_at_most_four_jobs_run_at_once():
    routes = []
    for i in range(jobs.MAX_RUNNING_JOBS):
        route = FakeRoute()
        route.add(f'p{i}')
        assert _body(route.post(f'p{i}'))[0] == 202
        routes.append(route)
    fifth = FakeRoute()
    fifth.add('p9')
    exc = _post_error(fifth, 'p9')
    assert exc.status_code == 429 and exc.detail == jobs.BUSY_DETAIL
    assert fifth.claims == 0 and fifth.rows['p9']['state'] == 'ready'
    assert jobs.status('p9', HOME) is None
    routes[0].release.set()
    _wait_done('p0')
    fifth.release.set()
    assert fifth.post('p9', wait=WAIT)['status'] == 'created'
    for route in routes:
        route.release.set()


def test_a_worker_exception_is_a_failed_job_with_a_plain_message():
    route = FakeRoute(behaviour='crash')
    route.add('p1')
    route.post('p1')
    route.release.set()
    _wait_done('p1')
    failed = jobs.status('p1', HOME)
    assert failed == {'status': 'failed', 'proposal_id': 'p1', 'http_status': 500,
                      'detail': jobs.CRASH_DETAIL, 'partial': False}
    assert 'secret-path' not in json.dumps(failed)
    exc = _post_error(route, 'p1')
    assert exc.status_code == 500 and exc.detail == jobs.CRASH_DETAIL
    assert route.calls == 1


def test_another_hermes_home_sees_nothing():
    route = FakeRoute()
    route.add('p1')
    route.post('p1')
    other = '/homes/b'
    assert jobs.status('p1', other) is None
    assert jobs.cancel('p1', other) is None
    exc = _post_error(route, 'p1', home=other)
    assert exc.status_code == 404 and exc.detail == 'Unknown or consumed proposal_id'
    assert jobs.status('p1', HOME)['status'] == 'running'
    route.release.set()
    _wait_done('p1')


def test_claim_errors_pass_through_and_leave_no_job():
    route = FakeRoute()
    exc = _post_error(route, 'missing')
    assert exc.status_code == 404
    assert jobs.status('missing', HOME) is None
    route.rows['busy'] = {'state': 'accepting', 'home': HOME}
    exc = _post_error(route, 'busy')
    assert exc.status_code == 409
    assert jobs.status('busy', HOME) is None and not jobs.protects('busy')


def test_many_concurrent_polls_and_starts_create_exactly_one_job():
    route = FakeRoute()
    route.add('p1')
    barrier = threading.Barrier(220)
    answers, errors = [], []

    def start():
        barrier.wait(WAIT)
        try:
            answers.append(route.post('p1', wait=0.05))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def poll():
        barrier.wait(WAIT)
        try:
            jobs.status('p1', HOME)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=start) for _ in range(20)]
    threads += [threading.Thread(target=poll) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(WAIT * 2)
    assert errors == []
    assert len(answers) == 20 and all(_body(a)[0] == 202 for a in answers)
    assert route.claims == 1
    route.release.set()
    _wait_done('p1')
    assert route.calls == 1


def test_running_jobs_and_unexpired_results_protect_their_proposals(monkeypatch):
    route = FakeRoute(behaviour='fail')
    route.add('p1')
    route.post('p1')
    assert jobs.protects('p1')  # running
    route.release.set()
    _wait_done('p1')
    assert route.rows['p1']['state'] == 'ready'
    assert jobs.protects('p1')  # failed, answer kept: the ready row must not expire yet
    monkeypatch.setattr(jobs, 'ACCEPT_RESULT_TTL_S', 0.0)
    assert not jobs.protects('p1')


def test_stored_answers_are_bounded(monkeypatch):
    monkeypatch.setattr(jobs, 'MAX_STORED_JOBS', 3)
    for i in range(5):
        route = FakeRoute()
        route.add(f'p{i}')
        route.release.set()
        route.post(f'p{i}', wait=WAIT)
    with jobs._JOBS_LOCK:
        jobs._prune_locked(jobs.time.monotonic())
        kept = sorted(jobs._JOBS)
    assert kept == ['p2', 'p3', 'p4']


def test_the_worker_runs_in_the_request_context():
    var = contextvars.ContextVar('home_override', default='process')
    seen = []
    route = FakeRoute()
    route.add('p1')

    def accept_fn(*, cancel):
        seen.append(var.get())
        return {'repos': []}

    var.set('request-home')
    route.post('p1', fn=accept_fn, wait=WAIT)
    assert seen == ['request-home']


def test_kwargs_for_offers_progress_only_to_functions_that_take_it():
    job = jobs._Job('p', HOME, None)
    token = jobs.CancelToken(job)
    assert set(token.kwargs_for(lambda *, cancel: None)) == {'cancel'}
    assert token.kwargs_for(lambda proposal, db_path=None: None) == {}
    assert set(token.kwargs_for(lambda proposal, **kw: None)) == {'cancel'}
    assert set(token.kwargs_for(lambda *, cancel, progress=None: None)) == {'cancel', 'progress'}
    token.progress('not-a-phase')
    assert job.step == jobs.STEP_PREPARE and not job.hooked
