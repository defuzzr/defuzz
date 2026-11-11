"""Profile-scoped componentize preferences; host auth/origin guards apply.

Synchronous handlers run filesystem operations and CLI probes in FastAPI's
worker pool. No endpoint runs a survey or starts a componentize job.
"""
import logging
from typing import Any

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from ... import componentize_settings


class _ComponentizeRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def handle(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(status_code=400, content={'error': 'Invalid componentize request'})
        return handle


router = APIRouter(route_class=_ComponentizeRoute)


def _call(function, *args, unavailable='componentize settings unavailable', passthrough=()):
    try:
        return function(*args)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={'error': str(exc)})
    except passthrough:
        raise  # the dashboard boundary answers a failed write with one plain 400 sentence
    except Exception:
        logging.getLogger(__name__).exception(unavailable)
        return JSONResponse(status_code=500, content={'error': unavailable})


@router.get('/componentize/settings')
def get_settings():
    return _call(componentize_settings.load)


@router.put('/componentize/settings')
def put_settings(body: Any = Body(default=None)):
    return _call(componentize_settings.save, body, passthrough=(OSError,))


def _status(project_root):
    root = None
    if project_root is not None:
        if not project_root.strip() or '\x00' in project_root:
            raise ValueError('project_root must be a non-empty path')
        from hermes_constants import get_hermes_home
        from ...audit.readonly_db import read_profile_registrations_readonly
        from ...safety import assert_safe_root, SafetyError
        try:
            root = assert_safe_root(project_root, role='componentize_root')
        except SafetyError as exc:
            raise ValueError(str(exc)) from exc
        snapshot = read_profile_registrations_readonly('active', get_hermes_home())
        if snapshot.coverage != 'verified' or snapshot.changed_during_read:
            raise ValueError('Active-profile registrations could not be verified')
        if str(root.resolve()) not in {row['canonical_path'] for row in snapshot.records}:
            raise ValueError('Project is not registered in the active profile')
    return componentize_settings.status(root)


@router.get('/componentize/status')
def get_status(project_root: str | None = None):
    return _call(_status, project_root, unavailable='componentize status unavailable')
