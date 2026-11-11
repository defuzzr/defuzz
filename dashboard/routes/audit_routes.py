"""Read-only audit routes; cleanup execution is deliberately absent."""
from typing import Any
from fastapi import APIRouter, Body, HTTPException
from ...audit_surface import execute_audit

router = APIRouter()


def _call(action, body):
    if not isinstance(body, dict):
        raise HTTPException(400, 'Request body must be an object')
    try:
        return execute_audit({**body, 'action': action})
    except KeyError as exc:
        raise HTTPException(404, 'Unknown audit run_id') from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get('/audit/scope')
def scope():
    from ...audit_surface import audit_scope_payload
    return audit_scope_payload()


@router.post('/audit/start')
def start(body: Any = Body(default_factory=dict)):
    return _call('run', body)


@router.get('/audit/status')
def status(run_id: str):
    return _call('status', {'run_id': run_id})


@router.get('/audit/report')
def report(run_id: str):
    return _call('report', {'run_id': run_id})


@router.get('/audit/summary')
def summary(run_id: str):
    """Plain-language reading of the stored report (same text as `audit --summary`)."""
    run = _call('report', {'run_id': run_id})
    run = run if isinstance(run, dict) else {}
    report = run.get('report')
    if not isinstance(report, dict):
        # Not ready: same 200 + status as /audit/report, with nothing to read yet.
        return {'run_id': run.get('run_id'), 'status': run.get('status'), 'text': None, 'summary': None}
    from ...audit_summary import render_text, summarize
    from ...cli import _audit_home
    data = summarize(report, home=_audit_home())
    return {'run_id': run.get('run_id'), 'status': run.get('status'), 'text': render_text(data), 'summary': data}


@router.post('/audit/cancel')
def cancel(body: Any = Body(default_factory=dict)):
    return _call('cancel', body)


@router.post('/audit/resume')
def resume(body: Any = Body(default_factory=dict)):
    return _call('resume', body)
