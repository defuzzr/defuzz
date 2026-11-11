"""Explicit discovery, registration, and read-only tree routes for existing projects.

Discovery lists core projects from the active profile. Opening a project records a
Defuzz state reference only; the source folder is never modified. The tree route
returns names from a folder that is *already* a verified active-profile registration,
so an arbitrary path can never be browsed through it.
"""
from __future__ import annotations

import os
import sqlite3
from typing import Any

from fastapi import APIRouter, Body, HTTPException

from ...safety import SafetyError
from ...state_store import StateDirNotWritable

router = APIRouter()

_OPEN_FIELDS = frozenset({"path", "hermes_project_id"})
_WRITE_FAILED = (
    "The change could not be saved because a file or the Defuzz state could not be "
    "read or written; check folder permissions and free disk space, then try again."
)
_REGISTRATIONS_UNVERIFIED = "Active-profile registrations could not be verified"


def _object(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise HTTPException(400, "Request body must be an object")
    return body


def _strict_object(body: Any, allowed: frozenset[str]) -> dict[str, Any]:
    body = _object(body)
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise HTTPException(400, f"Unknown field(s): {', '.join(unknown)}")
    return body


def _absolute_path_text(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(400, f"{key} must be a non-empty string")
    if "\x00" in value:
        raise HTTPException(400, f"{key} is invalid")
    if not os.path.isabs(value):
        raise HTTPException(400, f"{key} must be an absolute path")
    return value


def _optional_project_id(body: dict[str, Any]) -> str | None:
    if "hermes_project_id" not in body:
        return None
    value = body["hermes_project_id"]
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(400, "hermes_project_id must be a non-empty string when provided")
    return value


def _service():
    """Import the helper lazily so the router can be mounted before its sibling exists."""
    from ... import existing_projects

    return existing_projects


def _tree_service():
    from ... import project_tree

    return project_tree


def _canonical(project: str) -> str:
    try:
        return os.path.realpath(os.path.expanduser(project))
    except (OSError, RuntimeError) as exc:
        raise HTTPException(400, "project path is invalid") from exc


def _require_verified_active_registration(canonical: str) -> None:
    """Refuse a tree request unless the folder is a verified active-profile registration.

    The tree service enforces this too; doing it here means the route never reaches the
    listing code for an arbitrary unregistered root.
    """
    try:
        from hermes_constants import get_hermes_home
        from ...audit.readonly_db import read_profile_registrations_readonly

        snapshot = read_profile_registrations_readonly("active", get_hermes_home())
    except Exception as exc:
        raise HTTPException(400, _REGISTRATIONS_UNVERIFIED) from exc

    if getattr(snapshot, "coverage", None) != "verified" or getattr(
        snapshot, "changed_during_read", True
    ):
        raise HTTPException(400, _REGISTRATIONS_UNVERIFIED)
    records = getattr(snapshot, "records", None) or ()
    registered = {
        record.get("canonical_path")
        for record in records
        if isinstance(record, dict)
    }
    if canonical not in registered:
        raise HTTPException(400, "Project is not registered in the active profile")


@router.get("/workspace/available-projects")
def available_projects():
    """List non-archived core projects whose folders still exist; coverage is explicit."""
    return _service().list_available_projects()


@router.post("/workspace/projects/open")
def open_existing_project(body: Any = Body(default_factory=dict)):
    """Register a reference to an existing folder; no source file is written or copied."""
    body = _strict_object(body, _OPEN_FIELDS)
    path = _absolute_path_text(body, "path")
    hermes_project_id = _optional_project_id(body)
    try:
        return _service().open_existing_project(path, hermes_project_id=hermes_project_id)
    except SafetyError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (ValueError, OSError) as exc:
        # Validation is done by the helper with SafetyError; a plain ValueError/OSError
        # is still a caller-facing path problem, never a successful open.
        raise HTTPException(400, str(exc)) from exc
    except (sqlite3.Error, StateDirNotWritable) as exc:
        raise HTTPException(400, _WRITE_FAILED) from exc


@router.get("/workspace/tree")
def project_tree(project: str):
    """List file names under one verified active-profile project registration."""
    if not project or not project.strip():
        raise HTTPException(400, "project must be a non-empty string")
    if "\x00" in project:
        raise HTTPException(400, "project is invalid")
    if not os.path.isabs(project):
        raise HTTPException(400, "project must be an absolute path")

    canonical = _canonical(project)
    _require_verified_active_registration(canonical)
    try:
        return _tree_service().list_project_files(project)
    except SafetyError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc
