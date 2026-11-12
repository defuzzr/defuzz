"""Discover existing Hermes projects and register explicit references to them.

Discovery reads the active profile's core ``projects.db`` through a read-only SQLite URI and
the public ``hermes_cli.projects_db.list_projects`` reader. It never opens the SDK's
``connect`` (which creates or migrates the DB), never touches another profile, and never
inventories unrelated folders. Opening an existing project records a Defuzz state reference
only: the source folder is not written, copied, installed, or trusted implicitly.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from . import safety, state_store
from .audit.readonly_db import ReadOnlyDbError, open_readonly_sqlite, stat_db_identity

__all__ = ["list_available_projects", "open_existing_project"]

# A project adopted from an existing folder is not a template and has no questionnaire
# history; these fixed answers keep every downstream consumer (audit, placement) honest.
_EXISTING_TEMPLATE_ID = "existing"
_EXISTING_ANSWERS = {"building": "other", "layout": "single", "languages": []}
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_MAX_SLUG_LENGTH = 64


def _core_db_path() -> Path:
    """The active profile's core projects DB, without creating anything."""
    from hermes_cli.projects_db import projects_db_path

    return Path(projects_db_path())


def _read_core_projects() -> tuple[list[dict], str, str | None]:
    """Read non-archived core projects. Missing DB is verified-empty; faults are explicit."""
    try:
        db_path = _core_db_path()
    except Exception as exc:  # SDK missing or home unresolvable
        return [], "could_not_verify", f"core projects registry unavailable: {exc}"

    try:
        info = os.lstat(db_path)
    except FileNotFoundError:
        return [], "verified", None
    except OSError as exc:
        return [], "could_not_verify", f"core projects registry unreadable: {exc}"
    if not stat.S_ISREG(info.st_mode):
        return [], "could_not_verify", "core projects registry is not a regular file"

    try:
        with open_readonly_sqlite(db_path) as (conn, pre_id):
            from hermes_cli.projects_db import list_projects

            rows = [project.to_dict() for project in list_projects(conn)]
            if not all(isinstance(row, dict) for row in rows):
                raise TypeError("core project records are not mappings")
            if stat_db_identity(db_path) != pre_id:
                raise ReadOnlyDbError("registry changed during read", reason="race_detected")
        return rows, "verified", None
    except ReadOnlyDbError as exc:
        return [], "could_not_verify", f"core projects registry unavailable ({exc.reason}): {exc}"
    except Exception as exc:
        return [], "could_not_verify", f"core projects registry unsupported or unreadable: {exc}"


def _canonical(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def _available_folders(record: dict, claimed_paths: set[str]) -> tuple[list[dict], set[str], str | None]:
    """Validate and deduplicate a core project's folders, retaining the last I/O fault."""
    folders: list[dict] = []
    seen: set[str] = set()
    error = None
    for folder in record.get("folders") or ():
        if not isinstance(folder, dict):
            continue
        raw = folder.get("path")
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            continue
        try:
            canonical = _validated_existing_dir(raw)
        except safety.SafetyError:
            continue
        except OSError as exc:
            error = f"core project folder unavailable: {exc}"
            continue
        if canonical in seen or canonical in claimed_paths:
            continue
        seen.add(canonical)
        folders.append({
            "path": canonical,
            "label": folder.get("label"),
            "is_primary": bool(folder.get("is_primary")),
            "exists": True,
        })
    return folders, seen, error


def _available_projects() -> tuple[list[dict], str, str | None]:
    records, coverage, error = _read_core_projects()
    if coverage != "verified":
        return [], coverage, error

    projects: list[dict] = []
    claimed_paths: set[str] = set()
    for record in records:
        if record.get("archived"):
            continue
        folders, seen, folder_error = _available_folders(record, claimed_paths)
        if folder_error is not None:
            coverage = "could_not_verify"
            error = folder_error
        if not folders:
            continue

        primary = record.get("primary_path")
        primary_canonical = None
        if isinstance(primary, str) and primary:
            try:
                primary_canonical = _validated_existing_dir(primary)
            except safety.SafetyError:
                pass
            except OSError as exc:
                coverage = "could_not_verify"
                error = f"core project primary folder unavailable: {exc}"
        if primary_canonical not in seen:
            primary_canonical = next(
                (f["path"] for f in folders if f["is_primary"]), folders[0]["path"]
            )
        claimed_paths.update(seen)
        projects.append({
            "id": str(record.get("id") or ""),
            "name": str(record.get("name") or ""),
            "slug": record.get("slug"),
            "path": primary_canonical,
            "primary_path": primary_canonical,
            "folders": folders,
            "description": record.get("description"),
            "icon": record.get("icon"),
            "color": record.get("color"),
            "board_slug": record.get("board_slug"),
        })
    return projects, coverage, error


def list_available_projects() -> dict:
    """List non-archived core projects whose folders still exist, deduped by canonical path.

    ``coverage`` is ``verified`` only when the registry was actually read (or genuinely
    absent); a corrupt, unreadable, or unsupported registry is reported as
    ``could_not_verify`` with an error, never as an empty verified list.
    """
    projects, coverage, error = _available_projects()
    result: dict = {"projects": projects, "coverage": coverage}
    if error is not None:
        result["error"] = error
    return result


def _validated_existing_dir(path) -> str:
    """Validate a literal absolute folder path and return its canonical form."""
    if not isinstance(path, (str, os.PathLike)):
        raise safety.SafetyError("existing project path must be a string path")
    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise safety.SafetyError("existing project path must be a string path") from exc
    if not isinstance(raw, str) or not raw.strip():
        raise safety.SafetyError("existing project path must not be empty")
    if "\x00" in raw:
        raise safety.SafetyError("existing project path must not contain NUL")
    if not os.path.isabs(raw):
        raise safety.SafetyError(f"existing project path must be absolute: {raw!r}")

    safety.assert_safe_root(raw, role="existing project")
    canonical = _canonical(raw)
    if not os.path.isdir(canonical):
        raise safety.SafetyError(f"existing project is not an existing directory: {raw}")
    return canonical


def _display_name(value, fallback: str) -> str:
    """Use a core display name only when it is clean enough to store verbatim."""
    if isinstance(value, str):
        text = value.strip()
        if text and len(text) <= 200 and all(ch.isprintable() or ch == " " for ch in text):
            return text
    return fallback


def _safe_slug(folder_name: str) -> str:
    slug = _SLUG_RE.sub("-", folder_name.lower()).strip("-_")
    slug = slug[:_MAX_SLUG_LENGTH].strip("-_")
    if not slug or not slug[0].isalnum():
        return "project"
    return slug


def _matching_core_project(projects: list[dict], canonical: str, supplied_id) -> dict | None:
    """Return the core project whose folder is exactly ``canonical``, validating a supplied id."""
    if supplied_id is not None:
        if not isinstance(supplied_id, str) or not supplied_id.strip():
            raise safety.SafetyError("hermes_project_id must be a non-empty project id")
        requested = supplied_id.strip()
        for project in projects:
            if project["id"] != requested:
                continue
            if canonical in {folder["path"] for folder in project["folders"]}:
                return project
        raise safety.SafetyError(
            f"hermes_project_id {requested!r} does not match the core project for {canonical}"
        )

    matches = [p for p in projects if canonical in {f["path"] for f in p["folders"]}]
    unique_ids = {p["id"] for p in matches if p["id"]}
    return matches[0] if len(unique_ids) == 1 else None


def open_existing_project(path, hermes_project_id=None) -> dict:
    """Register a reference to an existing folder, without changing the folder itself.

    The path must be an absolute literal directory outside filesystem/home roots and the live
    Hermes home. If the project is already registered, its rules, trust mode, name, template,
    and other metadata are preserved untouched. A core ``hermes_project_id`` is recorded only
    when it names a freshly enumerated core project containing that exact canonical folder.
    """
    canonical = _validated_existing_dir(path)

    projects, coverage, error = _available_projects()
    if hermes_project_id is not None and coverage != "verified":
        raise safety.SafetyError(
            f"cannot verify hermes_project_id: core projects registry is unavailable ({error})"
        )
    match = _matching_core_project(projects, canonical, hermes_project_id)

    existing = state_store.get_project(canonical)
    if existing is not None:
        return {"status": "opened", "project": existing}

    fallback_name = Path(canonical).name or "project"
    name = _display_name(match["name"], fallback_name) if match else fallback_name
    state_store.record_project(
        canonical,
        name,
        _safe_slug(fallback_name),
        _EXISTING_TEMPLATE_ID,
        dict(_EXISTING_ANSWERS),
        match["id"] if match else None,
    )
    record = state_store.get_project(canonical)
    return {"status": "opened", "project": record}
