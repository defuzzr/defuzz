"""Dashboard REST API routes for defuzz whole-project lint and tool setup."""

from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import json
import logging
import math
import os
import sys
import sqlite3
import threading
import time
import types
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import JSONResponse

try:  # Real FastAPI; the unit tests also load this module with a stub `fastapi`.
    from fastapi.exceptions import RequestValidationError
    from fastapi.routing import APIRoute
    try:
        from fastapi.routing import request_response
    except ImportError:  # older FastAPI
        from starlette.routing import request_response
except ImportError:  # pragma: no cover - stub FastAPI
    APIRoute = None  # type: ignore[assignment,misc]

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE_NAME = f"{__name__.replace('-', '_')}__pkg"


def _ensure_plugin_package() -> types.ModuleType:
    """Return or load a private plugin package copy owned by this dashboard module, never touching hermes_plugins.* or sys.path."""
    init_file = _PLUGIN_ROOT / "__init__.py"
    existing = sys.modules.get(_PACKAGE_NAME)
    if existing is not None and hasattr(existing, "__path__"):
        existing_file = getattr(existing, "__file__", None)
        if existing_file is not None:
            try:
                if Path(existing_file).resolve() == init_file.resolve():
                    return existing
            except OSError:
                pass

    prefix = f"{_PACKAGE_NAME}."
    for k in list(sys.modules):
        if k == _PACKAGE_NAME or k.startswith(prefix):
            sys.modules.pop(k, None)

    spec = importlib.util.spec_from_file_location(
        _PACKAGE_NAME,
        init_file,
        submodule_search_locations=[str(_PLUGIN_ROOT)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {init_file}")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = _PACKAGE_NAME
    module.__path__ = [str(_PLUGIN_ROOT)]  # type: ignore[attr-defined]
    sys.modules[_PACKAGE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        for k in list(sys.modules):
            if k == _PACKAGE_NAME or k.startswith(prefix):
                sys.modules.pop(k, None)
        raise
    return module


def _load(name: str) -> Any:
    """Import a plugin submodule under the dashboard's private package namespace without mutating sys.path."""
    pkg = _ensure_plugin_package()
    pkg_name = pkg.__name__
    stem = name
    if stem.startswith(f"{pkg_name}."):
        stem = stem[len(pkg_name) + 1 :]
    elif stem.startswith("defuzz_place_"):
        stem = stem.removeprefix("defuzz_place_")
    full_name = f"{pkg_name}.{stem}"
    existing = sys.modules.get(full_name)
    if existing is not None:
        return existing
    return importlib.import_module(f".{stem}", pkg_name)


linter = _load("linter")
lint_setup = _load("lint_setup")
lint_tools = _load("lint_tools")
setup_manifest = _load("setup_manifest")

router = APIRouter()
_workspace_routes = _load("dashboard.routes.workspace_routes")
_audit_routes = _load("dashboard.routes.audit_routes")
_componentize_routes = _load("dashboard.routes.componentize_routes")
router.include_router(_workspace_routes.router)
router.include_router(_audit_routes.router)
router.include_router(_componentize_routes.router)
_existing_project_routes = _load("dashboard.routes.existing_project_routes")
router.include_router(_existing_project_routes.router)

# A write that fails (read-only folder, full disk, locked or read-only state database)
# is answered with one plain sentence; see _boundary_handler.
_WRITE_ERRORS = _workspace_routes.WRITE_ERRORS
_WRITE_FAILED = _workspace_routes.WRITE_FAILED
_LINT_WRITE_FAILED = (
    "The lint run stopped because a file could not be read or written; "
    "check the project folder's permissions and free disk space."
)

# ---------------------------------------------------------------------------
# Request-boundary limits. Every route on `router` (including the included
# workspace, audit and componentize routes) goes through `_BoundaryRoute`, so a
# malformed, oversized, wrongly typed or deeply nested request is refused with a
# 4xx and one plain sentence before any handler code runs.
# ---------------------------------------------------------------------------

# Default body cap: the largest legitimate body is a /ui-state save (its own
# check allows 64 KiB of JSON); twice that leaves room for whitespace.
MAX_BODY_BYTES = 128 * 1024
# The idea parser routes take a short prompt; same 16 KiB cap the componentize
# plugin's settings route uses.
MAX_PROMPT_BODY_BYTES = 16 * 1024
# A project idea is a sentence or a short paragraph. Follows the parser's own limit
# (prompt_parse.MAX_PROMPT_CHARS = 2048 on the parser branch) so both always agree.
MAX_PROMPT_CHARS = int(getattr(_load("prompt_parse"), "MAX_PROMPT_CHARS", 2048))
# No legitimate body is nested anywhere near this deep; FastAPI's encoder and the
# matcher recurse, so deep input must stop at the boundary.
MAX_JSON_DEPTH = 32
# Integers must fit SQLite's signed 64-bit INTEGER.
MAX_JSON_INT = 2**63 - 1
# Linux PATH_MAX.
MAX_PATH_CHARS = 4096
# Declared query parameters (paths, run ids, keys) never need more than this.
MAX_QUERY_VALUE_CHARS = 4096
# /ui-state seq comes from the page, a JavaScript number: keep it exactly representable.
MAX_UI_SEQ = 2**53 - 1
MAX_UI_KEY_CHARS = 128
# Free text written into TOOLS.lock. MAX_LOCK_BYTES // 256 keeps one reason (even
# at 6 bytes per escaped character) a small fraction of the whole lock.
MAX_REASON_CHARS = _load("toolchk").MAX_LOCK_BYTES // 256
# The init `event` is folded into every auto-detected tool's reason.
MAX_EVENT_CHARS = 64

_LINT_WAIT_TIMEOUT_S: float = 25.0
_LINT_JOB_TTL_S: float = 600.0
_MAX_LINT_JOBS: int = 20
_LINT_JOBS: dict[str, dict[str, Any]] = {}
_LINT_JOBS_LOCK = threading.Lock()

_SETUP_LOCK = threading.Lock()
_SETUP_CANCEL_EVENT: threading.Event | None = None
_SETUP_THREAD: threading.Thread | None = None
_SETUP_STATE: dict[str, Any] = {
    "state": "idle",
    "percent": 0.0,
    "item": None,
    "step": None,
    "message": "",
    "started_at": None,
    "finished_at": None,
    "result": None,
}


def _status_dict(st: Any) -> dict[str, Any]:
    """Convert a SetupStatus dataclass or mapping into a JSON-serializable dict."""
    raw: dict[str, Any] = dict(st) if isinstance(st, dict) else dataclasses.asdict(st)
    if "install_root" in raw and raw["install_root"] is not None:
        raw["install_root"] = str(raw["install_root"])
    if "platform" in raw and isinstance(raw["platform"], tuple):
        raw["platform"] = list(raw["platform"])
    return raw


def _prune_lint_jobs(now: float | None = None, *, max_jobs: int = _MAX_LINT_JOBS) -> None:
    """Remove expired finished lint jobs (older than 10 min) and evict oldest finished jobs down to max_jobs."""
    ts = time.time() if now is None else now
    expired = [
        jid
        for jid, job in _LINT_JOBS.items()
        if job.get("state") in ("done", "failed")
        and job.get("finished_at") is not None
        and (ts - float(job["finished_at"])) > _LINT_JOB_TTL_S
    ]
    for jid in expired:
        _LINT_JOBS.pop(jid, None)

    while len(_LINT_JOBS) > max_jobs:
        finished = [
            (float(j.get("finished_at") or j.get("started_at") or 0.0), jid)
            for jid, j in _LINT_JOBS.items()
            if j.get("state") in ("done", "failed")
        ]
        if not finished:
            break
        finished.sort(key=lambda item: item[0])
        _LINT_JOBS.pop(finished[0][1], None)


@router.post("/lint")
def post_lint(body: Any = Body(default_factory=dict)) -> Any:
    """Run whole-project lint on project root, returning 200 or 202 with a pollable job_id."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    project = body.get("project")
    mode = body.get("mode", "both")
    if mode is None:
        mode = "both"
    if not isinstance(mode, str) or mode not in ("pre", "post", "both"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode {mode!r}; expected 'pre', 'post', or 'both'",
        )

    proj_path = _validate_project_dir(project, require_safe_root=True, role="lint_root")
    project = str(proj_path)
    # Like the CLI, run available project tools and let run_lint report
    # project-specific tools_missing rather than gating on global setup.
    linter_mod = _load("linter")

    lock_file = proj_path / "TOOLS.lock"
    if not lock_file.is_symlink() and lock_file.is_file():
        toolchk_mod = _load("toolchk")
        try:
            loaded_lock = toolchk_mod.load_lock(lock_file)
            all_lock_tools = list(loaded_lock["tools"].keys())
            toolchk_mod.require(
                all_lock_tools,
                proj_path,
                record_dir=proj_path / ".adopt",
                lock=loaded_lock,
            )
        except toolchk_mod.PreflightError as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason": "tools_drift", "report": exc.report},
            ) from exc

    done_event = threading.Event()
    job_id = uuid.uuid4().hex[:12]
    started_at = time.time()

    with _LINT_JOBS_LOCK:
        _prune_lint_jobs(started_at, max_jobs=_MAX_LINT_JOBS - 1)
        if len(_LINT_JOBS) >= _MAX_LINT_JOBS:
            raise HTTPException(
                status_code=429,
                detail=f"Too many concurrent lint jobs ({_MAX_LINT_JOBS} running); wait for a running job to finish",
            )
        job_entry: dict[str, Any] = {
            "job_id": job_id,
            "state": "running",
            "project": project,
            "mode": mode,
            "started_at": started_at,
            "finished_at": None,
            "result": None,
            "error": None,
            "_event": done_event,
        }
        _LINT_JOBS[job_id] = job_entry

    def _worker() -> None:
        try:
            res = linter_mod.run_lint(project, mode)
            with _LINT_JOBS_LOCK:
                job_entry["result"] = res
                job_entry["state"] = "done"
                job_entry["finished_at"] = time.time()
        except _WRITE_ERRORS:
            logging.getLogger(__name__).warning("lint could not write", exc_info=True)
            with _LINT_JOBS_LOCK:
                job_entry["error"] = _LINT_WRITE_FAILED
                job_entry["write_failed"] = True
                job_entry["state"] = "failed"
                job_entry["finished_at"] = time.time()
        except Exception as exc:  # noqa: BLE001
            with _LINT_JOBS_LOCK:
                job_entry["error"] = str(exc)
                job_entry["state"] = "failed"
                job_entry["finished_at"] = time.time()
        finally:
            done_event.set()

    worker = threading.Thread(
        target=_worker,
        name=f"defuzz-lint-{job_id}",
        daemon=True,
    )
    worker.start()

    finished = done_event.wait(timeout=_LINT_WAIT_TIMEOUT_S)
    if not finished:
        return JSONResponse(
            status_code=202,
            content={"state": "running", "job_id": job_id},
        )

    with _LINT_JOBS_LOCK:
        state = job_entry["state"]
        result = job_entry["result"]
        err = job_entry["error"]
        write_failed = job_entry.get("write_failed", False)

    if state == "failed":
        raise HTTPException(status_code=400 if write_failed else 500, detail=err or "Lint execution failed")
    return result


@router.get("/lint/{job_id}")
def get_lint_job(job_id: str) -> dict[str, Any]:
    """Poll the status or result of a background lint job started by POST /lint."""
    with _LINT_JOBS_LOCK:
        _prune_lint_jobs()
        job = _LINT_JOBS.get(job_id)
        if job is None:
            shown = job_id if len(job_id) <= 64 else job_id[:64] + "..."
            raise HTTPException(status_code=404, detail=f"Unknown lint job: {shown}")
        state = job["state"]
        result = job["result"]
        err = job["error"]
        started_at = job["started_at"]
        finished_at = job["finished_at"]

    if state == "running":
        return {
            "state": "running",
            "job_id": job_id,
            "started_at": started_at,
        }
    if state == "failed":
        return {
            "state": "failed",
            "job_id": job_id,
            "ok": False,
            "error": err or "Lint execution failed",
            "started_at": started_at,
            "finished_at": finished_at,
            "result": None,
        }
    res_dict = dict(result) if isinstance(result, dict) else {}
    return {
        **res_dict,
        "state": "done",
        "job_id": job_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "result": result,
    }


@router.get("/tools/status")
def get_tools_status() -> dict[str, Any]:
    """Return current tool setup status, wheel packages, disclosure plan, and total MB."""
    setup_mod = _load("lint_setup")
    tools_mod = _load("lint_tools")
    manifest_mod = _load("setup_manifest")

    st = setup_mod.status()
    payload = _status_dict(st)
    plat_tuple = tuple(st.platform) if isinstance(st.platform, (list, tuple)) else manifest_mod.current_platform()
    wheel_pkgs = {
        pkg: (list(bins) if isinstance(bins, tuple) else bins)
        for pkg, bins in tools_mod.WHEEL_PACKAGES.items()
    }
    payload["wheel_packages"] = wheel_pkgs
    # This synchronous FastAPI route runs in the worker pool, not the event loop.
    versions = {row["name"]: row for row in setup_mod.installed_tool_versions()}
    for item in payload["items"]:
        item.update(versions.pop(item["name"], {}))
    payload["items"].extend(versions.values())
    payload["plan"] = setup_mod.describe_plan(platform=plat_tuple)
    payload["total_mb"] = manifest_mod.total_size_mb(plat_tuple)
    return payload


def _setup_progress(prog: Any) -> None:
    with _SETUP_LOCK:
        _SETUP_STATE.update(
            {
                "percent": float(getattr(prog, "percent", 0.0)),
                "item": getattr(prog, "item", None),
                "step": getattr(prog, "step", None),
                "message": getattr(prog, "message", ""),
            }
        )


def _run_setup(setup_mod: Any, cancel_event: threading.Event) -> None:
    try:
        res = setup_mod.run_setup(_setup_progress, cancel=cancel_event)
        res_dict: dict[str, Any] = (
            dict(res) if isinstance(res, dict) else dataclasses.asdict(res)
        )
        ok = bool(res_dict.get("ok"))
        with _SETUP_LOCK:
            _SETUP_STATE.update(
                {
                    "state": "done" if ok else "failed",
                    "percent": 100.0 if ok else _SETUP_STATE["percent"],
                    "step": "done" if ok else "failed",
                    "message": (
                        "Setup complete"
                        if ok
                        else (res_dict.get("error") or "Setup failed")
                    ),
                    "finished_at": time.time(),
                    "result": res_dict,
                }
            )
    except Exception as exc:  # noqa: BLE001
        with _SETUP_LOCK:
            _SETUP_STATE.update(
                {
                    "state": "failed",
                    "step": "failed",
                    "message": str(exc),
                    "finished_at": time.time(),
                    "result": {
                        "ok": False,
                        "installed": [],
                        "skipped": [],
                        "failed": {},
                        "error": str(exc),
                        "log": [str(exc)],
                    },
                }
            )


@router.post("/setup")
def post_setup(body: Any = Body(default_factory=dict)) -> dict[str, Any]:
    """Start the mandatory user-space tool setup in a background thread after user consent."""
    global _SETUP_CANCEL_EVENT, _SETUP_THREAD

    if not isinstance(body, dict) or body.get("confirm") is not True:
        raise HTTPException(
            status_code=400,
            detail="Explicit confirmation {'confirm': true} is required to start setup",
        )

    setup_mod = _load("lint_setup")
    st = setup_mod.status()
    if not st.lazy_installs_allowed:
        raise HTTPException(
            status_code=503,
            detail=st.blocked_reason or "Lazy tool installs are disabled in config.yaml",
        )

    with _SETUP_LOCK:
        if _SETUP_STATE["state"] == "running":
            raise HTTPException(status_code=409, detail="Setup is already running")

        cancel_event = threading.Event()
        _SETUP_CANCEL_EVENT = cancel_event
        _SETUP_STATE.update(
            {
                "state": "running",
                "percent": 0.0,
                "item": None,
                "step": "starting",
                "message": "Starting lint tool setup",
                "started_at": time.time(),
                "finished_at": None,
                "result": None,
            }
        )

        thread = threading.Thread(
            target=_run_setup,
            args=(setup_mod, cancel_event),
            name="defuzz-setup",
            daemon=True,
        )
        _SETUP_THREAD = thread
        thread.start()

    return {"state": "running"}


@router.get("/setup/status")
def get_setup_status() -> dict[str, Any]:
    """Return a snapshot of the current or most recent tool setup run."""
    with _SETUP_LOCK:
        return dict(_SETUP_STATE)


@router.post("/setup/cancel")
def post_setup_cancel() -> dict[str, Any]:
    """Signal the active background setup run to cancel."""
    with _SETUP_LOCK:
        if _SETUP_CANCEL_EVENT is not None:
            _SETUP_CANCEL_EVENT.set()
        return {"ok": True, "state": _SETUP_STATE["state"]}


def _validate_project_dir(project: Any, *, require_safe_root: bool = False, role: str = "tools_lock_root") -> Path:
    """Return the project folder for a request, refusing anything but an existing absolute folder."""
    try:
        cleaned = _abs_path_text(project, "project")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        proj_path = Path(cleaned)
        is_valid_dir = proj_path.exists() and proj_path.is_dir() and not proj_path.is_symlink()
    except (RuntimeError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid project path {cleaned!r}: {exc}",
        ) from exc
    if not is_valid_dir:
        raise HTTPException(
            status_code=400,
            detail=f"Project root does not exist or is not a directory: {cleaned}",
        )
    if require_safe_root:
        safety_mod = _load("safety")
        try:
            proj_path = safety_mod.assert_safe_root(proj_path, role=role)
        except safety_mod.SafetyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return proj_path


def _validate_reason(reason: Any, *, empty_detail: str) -> str:
    """Return the stripped reason, refusing empty, oversized or control-character text."""
    if not isinstance(reason, str) or not reason.strip():
        raise HTTPException(status_code=400, detail=empty_detail)
    clean = reason.strip()
    if len(clean) > MAX_REASON_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"The reason is longer than {MAX_REASON_CHARS} characters; shorten it.",
        )
    if _has_control_chars(clean, allow="\t\n\r"):
        raise HTTPException(
            status_code=400,
            detail="The reason must not contain control characters other than tabs and line breaks.",
        )
    return clean


def _check_lock_room(lock_file: Path, tool: str, reason: str) -> None:
    """Refuse an edit whose new reason would push TOOLS.lock past the size the plugin can read back."""
    toolchk_mod = _load("toolchk")
    try:
        loaded = toolchk_mod.load_lock(lock_file)
        size = lock_file.stat().st_size
    except toolchk_mod.PreflightError as exc:
        raise HTTPException(status_code=400, detail=exc.report.get("summary", str(exc))) from exc
    except OSError as exc:
        raise HTTPException(status_code=400, detail="TOOLS.lock cannot be read") from exc
    entry = loaded["tools"].get(tool)
    if not isinstance(entry, dict):
        return  # the edit itself answers 404 for an unknown tool
    old = entry.get("reason")
    old_len = len(toolchk_mod._format_toml_str(old).encode("utf-8")) if isinstance(old, str) else 0
    new_len = len(toolchk_mod._format_toml_str(reason).encode("utf-8"))
    # 256 bytes of slack covers the version/chosen/source fields an accept rewrites.
    if size - old_len + new_len + 256 > toolchk_mod.MAX_LOCK_BYTES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"This reason would make TOOLS.lock larger than its {toolchk_mod.MAX_LOCK_BYTES}-byte limit; "
                "shorten it."
            ),
        )


def _ensure_lock_file_exists(proj_path: Path) -> Path:
    lock_file = proj_path / "TOOLS.lock"
    if lock_file.is_symlink() or not lock_file.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"No TOOLS.lock found in {proj_path}",
        )
    return lock_file


@router.get("/tools-lock")
def get_tools_lock(project: str | None = None) -> dict[str, Any]:
    """Return project TOOLS.lock status, rows table, enforce setting, and summary."""
    # Read-only on purpose: showing a lock outside the safe roots writes nothing,
    # and every route that changes TOOLS.lock requires a safe root.
    proj_path = _validate_project_dir(project, require_safe_root=False)
    lock_file = proj_path / "TOOLS.lock"
    if lock_file.is_symlink() or not lock_file.is_file():
        return {
            "lock": None,
            "enforce": "warn",
            "rows": [],
            "summary": "No TOOLS.lock present",
        }

    tool_seed_mod = _load("tool_seed")
    toolchk_mod = _load("toolchk")
    try:
        rep = tool_seed_mod.status(proj_path)
        rows = tool_seed_mod.table(proj_path)
    except toolchk_mod.PreflightError as exc:
        raise HTTPException(
            status_code=400,
            detail=exc.report.get("summary", str(exc)),
        ) from exc

    return {
        "lock": rep.get("lock", str(lock_file.resolve())),
        "enforce": rep.get("enforce", "warn"),
        "rows": rows,
        "summary": rep.get("summary", ""),
        "trust": _load("tool_guard").inspect_lock_trust(proj_path),
    }


@router.post("/tools-lock/trust")
def post_tools_lock_trust(body: Any = Body(default_factory=dict)) -> dict[str, Any]:
    if not isinstance(body, dict) or body.get("confirm") is not True:
        raise HTTPException(400, "Explicit confirm:true and expected_hash are required")
    project = _validate_project_dir(body.get("project"), require_safe_root=True)
    _ensure_lock_file_exists(project)
    try:
        return _load("tool_guard").trust_lock(project, expected_hash=body.get("expected_hash"))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/tools-lock/accept")
def post_tools_lock_accept(body: Any = Body(default_factory=dict)) -> dict[str, Any]:
    """Accept the currently installed version of a tool as chosen in TOOLS.lock."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    proj_path = _validate_project_dir(
        body.get("project"),
        require_safe_root=True,
        role="tools_accept_root",
    )
    tool = body.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise HTTPException(status_code=400, detail="tool is required and must be a non-empty string")

    reason = _validate_reason(
        body.get("reason"),
        empty_detail="A non-empty reason is required to accept an installed version.",
    )

    lock_file = _ensure_lock_file_exists(proj_path)
    _check_lock_room(lock_file, tool.strip(), reason)
    toolchk_mod = _load("toolchk")
    try:
        return _load("tool_guard").edit_lock(proj_path, tool.strip(), reason, action="accept")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except toolchk_mod.PreflightError as exc:
        raise HTTPException(
            status_code=400,
            detail=exc.report.get("summary", str(exc)),
        ) from exc
    except _WRITE_ERRORS as exc:
        raise HTTPException(status_code=400, detail=_WRITE_FAILED) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"Failed to probe or accept installed version for {tool!r}: {exc}",
        ) from exc


@router.post("/tools-lock/reason")
def post_tools_lock_reason(body: Any = Body(default_factory=dict)) -> dict[str, Any]:
    """Update the reason for a locked tool in TOOLS.lock."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    proj_path = _validate_project_dir(
        body.get("project"),
        require_safe_root=True,
        role="tools_reason_root",
    )
    tool = body.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise HTTPException(status_code=400, detail="tool is required and must be a non-empty string")

    reason = _validate_reason(body.get("reason"), empty_detail="A non-empty reason is required.")

    lock_file = _ensure_lock_file_exists(proj_path)
    _check_lock_room(lock_file, tool.strip(), reason)
    toolchk_mod = _load("toolchk")
    try:
        return _load("tool_guard").edit_lock(proj_path, tool.strip(), reason, action="reason")
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(400, "Lock edit could not be published") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except toolchk_mod.PreflightError as exc:
        raise HTTPException(
            status_code=400,
            detail=exc.report.get("summary", str(exc)),
        ) from exc


@router.post("/tools-lock/snooze")
def post_tools_lock_snooze(body: Any = Body(default_factory=dict)) -> dict[str, Any]:
    """Snooze upstream advisory note for a locked tool in the plugin state DB."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    proj_path = _validate_project_dir(
        body.get("project"),
        require_safe_root=True,
        role="tools_snooze_root",
    )
    tool = body.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise HTTPException(status_code=400, detail="tool is required and must be a non-empty string")

    days = body.get("days", 30)
    tool_seed_mod = _load("tool_seed")
    max_days = tool_seed_mod.MAX_SNOOZE_DAYS
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= max_days:
        raise HTTPException(status_code=400, detail=f"days must be a whole number from 0 to {max_days}.")

    lock_file = _ensure_lock_file_exists(proj_path)
    toolchk_mod = _load("toolchk")
    try:
        loaded = toolchk_mod.load_lock(lock_file)
    except toolchk_mod.PreflightError as exc:
        raise HTTPException(
            status_code=400,
            detail=exc.report.get("summary", str(exc)),
        ) from exc

    tool_name = tool.strip()
    if tool_name not in loaded["tools"]:
        raise HTTPException(status_code=404, detail=f"Tool {tool_name!r} is not in {lock_file}")

    try:
        tool_seed_mod.snooze(proj_path, tool_name, days)
        rows = tool_seed_mod.table(proj_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    for r in rows:
        if r.get("tool") == tool_name:
            return r
    return {"tool": tool_name, "days": days, "snoozed_until": tool_seed_mod.snoozed(proj_path).get(tool_name)}


@router.post("/tools-lock/init")
def post_tools_lock_init(body: Any = Body(default_factory=dict)) -> dict[str, Any]:
    """Seed or refresh TOOLS.lock in a project root after explicit confirmation."""
    if not isinstance(body, dict) or body.get("confirm") is not True:
        raise HTTPException(
            status_code=400,
            detail="Explicit confirmation {'confirm': true} is required to seed TOOLS.lock",
        )

    proj_path = _validate_project_dir(
        body.get("project"),
        require_safe_root=True,
        role="tools_init_root",
    )
    event = body.get("event")
    if event is None or event == "":
        event = "adoption"
    if (
        not isinstance(event, str)
        or not event.strip()
        or len(event) > MAX_EVENT_CHARS
        or _has_control_chars(event)
    ):
        raise HTTPException(
            status_code=400,
            detail=f"event must be a short label of at most {MAX_EVENT_CHARS} characters without control characters.",
        )
    event = event.strip()
    tool_seed_mod = _load("tool_seed")
    toolchk_mod = _load("toolchk")
    try:
        return tool_seed_mod.seed_lock(proj_path, event=event)
    except toolchk_mod.PreflightError as exc:
        raise HTTPException(
            status_code=400,
            detail=exc.report.get("summary", str(exc)),
        ) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=400,
            detail="TOOLS.lock could not be written in that folder; check that you can write there.",
        ) from exc



# ---------------------------------------------------------------------------
# Request-boundary validation shared by every route
# ---------------------------------------------------------------------------


class _Refusal(Exception):
    """A request refused at the boundary: always a 400 with one plain sentence."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


_NESTED_MSG = f"The request body is nested too deeply (the limit is {MAX_JSON_DEPTH} levels)."
_BIG_NUMBER_MSG = "The request body contains a number that is too large."


def _has_control_chars(text: str, *, allow: str = "") -> bool:
    return any((ord(ch) < 32 or ord(ch) == 127) and ch not in allow for ch in text)


def _abs_path_text(value: Any, label: str = "project") -> str:
    """Return the stripped absolute path text, or raise ValueError with one plain sentence.

    Same normalisation as the projects-root rule (strip, refuse control
    characters), then a full path is required: relative paths would resolve
    against the backend's working folder and `~` is not expanded here.
    """
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a folder path given as text.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} is required and must be a path.")
    if len(cleaned) > MAX_PATH_CHARS:
        raise ValueError(f"{label} is longer than {MAX_PATH_CHARS} characters.")
    if _has_control_chars(cleaned):
        raise ValueError(f"{label} must not contain control characters such as newlines or NUL.")
    if cleaned.startswith("~"):
        raise ValueError(f"{label} must be a full path starting with /; a ~ path is not expanded here.")
    if not os.path.isabs(cleaned):
        raise ValueError(f"{label} must be a full path starting with /, not a relative path.")
    if ".." in cleaned.split("/"):
        raise ValueError(f"{label} must not contain .. folder steps; give the full path directly.")
    return cleaned


def _json_int(text: str) -> int:
    digits = text.lstrip("-")
    if len(digits) > 19:  # also avoids int()'s 4300-digit ValueError
        raise _Refusal(_BIG_NUMBER_MSG)
    value = int(text)
    if abs(value) > MAX_JSON_INT:
        raise _Refusal(_BIG_NUMBER_MSG)
    return value


def _json_float(text: str) -> float:
    if len(text) > 64:
        raise _Refusal(_BIG_NUMBER_MSG)
    value = float(text)
    if not math.isfinite(value):
        raise _Refusal(_BIG_NUMBER_MSG)
    return value


def _json_constant(_name: str) -> Any:
    raise _Refusal("The request body contains NaN or Infinity, which are not allowed.")


def _check_depth(obj: Any) -> None:
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise _Refusal(_NESTED_MSG)
        children = cur.values() if isinstance(cur, dict) else cur
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))


def _parse_json_body(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _Refusal("The request body is not valid UTF-8 text.") from None
    try:
        obj = json.loads(text, parse_int=_json_int, parse_float=_json_float, parse_constant=_json_constant)
    except RecursionError:
        raise _Refusal(_NESTED_MSG) from None
    except ValueError:
        raise _Refusal("The request body is not valid JSON.") from None
    if isinstance(obj, (dict, list)):
        _check_depth(obj)
    return obj


async def _read_body(request: Any, limit: int) -> bytes:
    too_large = f"The request body is larger than {limit // 1024} KiB."
    declared = request.headers.get("content-length", "")
    if declared and (len(declared) > 15 or not declared.isdigit() or int(declared) > limit):
        raise _Refusal(too_large)
    size = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise _Refusal(too_large)
        chunks.append(chunk)
    body = b"".join(chunks)
    request._body = body  # cached for FastAPI's own body parsing
    return body


def _validation_sentence(exc: Any) -> str:
    try:
        errors = exc.errors()
        first = errors[0] if errors else {}
        loc = [str(p) for p in first.get("loc", ()) if p not in ("body", "query", "path")]
        kind = str(first.get("type", ""))
    except Exception:  # noqa: BLE001
        loc, kind = [], ""
    name = ".".join(loc)[:64]
    if kind == "json_invalid" or (not name and kind.startswith("json")):
        return "The request body is not valid JSON."
    if kind == "missing" and name:
        return f"The request is missing the required field {name}."
    if name:
        return f"The request field {name} is not valid."
    return "The request is not valid."


# --- per-route rules (keyed by endpoint, which survives Hermes's include_router) ---


def _check_prompt_body(body: Any, _request: Any) -> None:
    if isinstance(body, dict):
        prompt = body.get("prompt")
        if isinstance(prompt, str) and len(prompt) > MAX_PROMPT_CHARS:
            # Measured before any stripping: an all-whitespace prompt skips the parser in
            # /scaffold/match and would otherwise reach the matcher uncapped.
            raise _Refusal(
                f"The prompt is too long: {len(prompt)} characters (limit {MAX_PROMPT_CHARS}). "
                "Describe the project in a sentence or a short paragraph."
            )


def _check_ui_key(key: Any) -> None:
    if isinstance(key, str):
        if len(key) > MAX_UI_KEY_CHARS:
            raise _Refusal(f"key must be at most {MAX_UI_KEY_CHARS} characters.")
        if _has_control_chars(key):
            raise _Refusal("key must not contain control characters.")


def _check_ui_state_body(body: Any, _request: Any) -> None:
    if not isinstance(body, dict):
        return
    _check_ui_key(body.get("key"))
    seq = body.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or not 1 <= seq <= MAX_UI_SEQ:
        raise _Refusal(f"seq must be a whole number from 1 to {MAX_UI_SEQ}.")


def _check_ui_state_query(request: Any) -> None:
    _check_ui_key(request.query_params.get("key"))


def _query_path(request: Any, name: str, *, required: bool) -> None:
    value = request.query_params.get(name)
    if value is None and not required:
        return
    if value is None:
        raise _Refusal(f"The request is missing the required field {name}.")
    try:
        _abs_path_text(value, name)
    except ValueError as exc:
        raise _Refusal(str(exc)) from None


def _check_workspace_file_query(request: Any) -> None:
    _query_path(request, "project", required=True)
    path = request.query_params.get("path")
    if path is None:
        raise _Refusal("The request is missing the required field path.")
    if _has_control_chars(path):
        raise _Refusal("path must not contain control characters.")


def _check_workspace_tree_query(request: Any) -> None:
    _query_path(request, "project", required=True)


def _check_existing_open_body(body: Any, _request: Any) -> None:
    if not isinstance(body, dict):
        return
    try:
        _abs_path_text(body.get("path"), "path")
    except ValueError as exc:
        raise _Refusal(str(exc)) from None


def _check_componentize_status_query(request: Any) -> None:
    _query_path(request, "project_root", required=False)


def _check_componentize_settings_body(body: Any, _request: Any) -> None:
    if isinstance(body, dict) and isinstance(body.get("cli_path_override"), str):
        try:
            _abs_path_text(body["cli_path_override"], "cli_path_override")
        except ValueError as exc:
            raise _Refusal(str(exc)) from None


def _check_audit_start_body(body: Any, _request: Any) -> None:
    if not isinstance(body, dict):
        return
    try:
        if body.get("root") is not None:
            _abs_path_text(body["root"], "root")
        selected = body.get("selected_projects")
        if isinstance(selected, list):
            for item in selected:
                _abs_path_text(item, "selected_projects entry")
    except ValueError as exc:
        raise _Refusal(str(exc)) from None


_ROUTE_RULES: dict[Any, dict[str, Any]] = {
    # value_error: the parser raises ValueError (PromptTooLongError) for prompts it refuses.
    _workspace_routes.parse_idea: {"body_limit": MAX_PROMPT_BODY_BYTES, "body": _check_prompt_body,
                                   "value_error": True},
    _workspace_routes.match_templates: {"body_limit": MAX_PROMPT_BODY_BYTES, "body": _check_prompt_body,
                                        "value_error": True},
    _workspace_routes.save_ui_state: {"body": _check_ui_state_body},
    _workspace_routes.get_ui_state: {"query": _check_ui_state_query},
    _workspace_routes.workspace_file: {"query": _check_workspace_file_query},
    _existing_project_routes.project_tree: {"query": _check_workspace_tree_query},
    _existing_project_routes.open_existing_project: {"body": _check_existing_open_body},
    _componentize_routes.get_status: {"query": _check_componentize_status_query},
    _componentize_routes.put_settings: {"body": _check_componentize_settings_body},
    _audit_routes.start: {"body": _check_audit_start_body},
}

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _boundary_handler(route: Any, handler: Any) -> Any:
    rules = _ROUTE_RULES.get(route.endpoint, {})
    body_limit = int(rules.get("body_limit", MAX_BODY_BYTES))
    body_rule = rules.get("body")
    query_rule = rules.get("query")
    map_value_error = bool(rules.get("value_error"))
    error_key = "error" if getattr(route.endpoint, "__module__", "").endswith("componentize_routes") else "detail"
    query_names = [p.alias for p in route.dependant.query_params]

    async def handle(request: Any) -> Any:
        try:
            for name in query_names:
                for value in request.query_params.getlist(name):
                    if len(value) > MAX_QUERY_VALUE_CHARS:
                        raise _Refusal(f"The {name} parameter is longer than {MAX_QUERY_VALUE_CHARS} characters.")
                    if "\x00" in value:
                        raise _Refusal(f"The {name} parameter must not contain NUL characters.")
            if query_rule is not None:
                query_rule(request)
            if request.method in _BODY_METHODS:
                raw = await _read_body(request, body_limit)
                if raw.strip():
                    parsed = _parse_json_body(raw)
                    if body_rule is not None:
                        body_rule(parsed, request)
            try:
                return await handler(request)
            except RequestValidationError as exc:
                raise _Refusal(_validation_sentence(exc)) from None
            except RecursionError:
                raise _Refusal(_NESTED_MSG) from None
            except ValueError as exc:
                if not map_value_error:
                    raise
                text = " ".join(str(exc).split())[:300] or "The prompt could not be read."
                raise _Refusal(text) from None
            except _WRITE_ERRORS:
                # A route that changes something hit a failed write: one plain sentence,
                # never the exception text or a path the caller did not send.
                if request.method not in _BODY_METHODS:
                    raise
                logging.getLogger(__name__).warning("%s %s could not write", request.method,
                                                    request.url.path, exc_info=True)
                raise _Refusal(_WRITE_FAILED) from None
        except _Refusal as exc:
            return JSONResponse(status_code=400, content={error_key: exc.message})

    return handle


if APIRoute is not None:

    class _BoundaryMixin:
        def get_route_handler(self) -> Any:
            return _boundary_handler(self, super().get_route_handler())  # type: ignore[misc]

    _BOUNDARY_CLASSES: dict[type, type] = {}

    def _boundary_class(cls: type) -> type:
        if issubclass(cls, _BoundaryMixin):
            return cls
        if cls not in _BOUNDARY_CLASSES:
            _BOUNDARY_CLASSES[cls] = type(f"_Boundary{cls.__name__}", (_BoundaryMixin, cls), {})
        return _BOUNDARY_CLASSES[cls]

    def _install_boundary(target: Any) -> None:
        """Give every APIRoute on `target` the boundary checks; include_router keeps the class."""
        for route in target.routes:
            if isinstance(route, APIRoute) and not isinstance(route, _BoundaryMixin):
                route.__class__ = _boundary_class(type(route))
                route.app = request_response(route.get_route_handler())

    _install_boundary(router)
