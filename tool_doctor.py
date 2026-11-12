"""Tool doctor: one-line lock health summary across registered projects."""

from __future__ import annotations

import inspect
import os
import sqlite3
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import state_store, toolchk
from .audit.readonly_db import open_readonly_sqlite


def _readonly_state_db_path() -> Path:
    """Resolve `<hermes_home>/plugin-data/defuzz/state.db` without mkdir, lock files, or migration."""
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()).expanduser() / "plugin-data" / "defuzz" / "state.db"


def _call_toolchk_check(
    needs: list[str],
    lock_data: dict[str, Any],
    project_root: Path,
) -> dict[str, Any]:
    """Call `toolchk.check`, passing `timeout=3.0` only when supported by its signature."""
    check_fn: Any = toolchk.check
    try:
        has_timeout = "timeout" in inspect.signature(check_fn).parameters
    except (ValueError, TypeError):
        has_timeout = False
    if has_timeout:
        return check_fn(needs, lock_data, project_root, timeout=3.0)
    return check_fn(needs, lock_data, project_root)


def registered_project_paths(db_path: Path | str | None = None) -> list[Path]:
    """Read registered project paths from state_store's `projects` table read-only.

    Never creates parent directories, never creates a missing DB file, and skips
    paths that no longer exist on disk.
    """
    target = Path(db_path).expanduser() if db_path is not None else _readonly_state_db_path()
    try:
        st = os.lstat(target)
    except OSError:
        return []
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size == 0:
        return []

    try:
        with open_readonly_sqlite(target, timeout=2.0) as (conn, _pre_id):
            has_projects = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='projects'"
            ).fetchone()
            if has_projects is None:
                return []
            rows = conn.execute(
                "SELECT path FROM projects ORDER BY created_at ASC, path ASC"
            ).fetchall()
    except (OSError, sqlite3.Error):
        return []

    paths: list[Path] = []
    seen: set[str] = set()
    for row in rows:
        raw = str(row["path"] or "").strip()
        if not raw:
            continue
        p = Path(raw).expanduser()
        try:
            if not p.is_dir():
                continue
            key = str(p.resolve())
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            paths.append(p)
    return paths


def _check_with_timeout(
    needs: list[str],
    lock_data: dict[str, Any],
    project_root: Path,
    timeout: float,
) -> dict[str, Any]:
    if timeout == 3.0:
        return _call_toolchk_check(needs, lock_data, project_root)
    try:
        return toolchk.check(needs, lock_data, project_root, timeout=timeout)
    except TypeError:
        return toolchk.check(needs, lock_data, project_root)


def _broken_project(proj_path: Path, proj_name: str, exc: BaseException) -> dict[str, Any]:
    raw = (exc.report.get("summary") or exc) if isinstance(exc, toolchk.PreflightError) else exc
    summary = " ".join(str(raw).splitlines()).strip()
    return {
        "project": str(proj_path),
        "name": proj_name,
        "status": "broken",
        "summary": summary,
        "line": f"  BROKEN {proj_name}  {summary}",
    }


def _drift_detail(tool_names: list[str], report_tools: dict[str, Any], fallback: Any) -> str:
    clauses: list[str] = []
    for tname in tool_names:
        row = report_tools.get(tname)
        if not isinstance(row, dict):
            continue
        st = row.get("status")
        locked = row.get("locked", "?")
        if st == "drift":
            clauses.append(f"{tname} {row.get('installed', '?')} != {locked}")
        elif st == "probe-failed":
            err = " ".join(str(row.get("error") or "probe failed").splitlines()).strip()
            clauses.append(f"{tname} probe failed ({err}) != {locked}")
        elif st == "unlisted":
            clauses.append(f"{tname} unlisted")
    return "; ".join(clauses) if clauses else str(fallback or "drift")


def _inspect_project(proj: Path, *, timeout: float = 3.0) -> dict[str, Any]:
    proj_path = Path(proj)
    proj_name = proj_path.name or str(proj_path)
    identity = {"project": str(proj_path), "name": proj_name}
    lock_file = proj_path / "TOOLS.lock"

    try:
        has_lock = not os.path.islink(lock_file) and lock_file.is_file()
    except OSError:
        has_lock = False

    if not has_lock:
        return {
            **identity,
            "status": "missing",
            "line": f"  --     {proj_name}  no TOOLS.lock",
        }

    try:
        loaded = toolchk.load_lock(lock_file)
        raw_tools = loaded.get("tools") if isinstance(loaded, dict) else {}
        if not isinstance(raw_tools, dict):
            raw_tools = {}
        tool_names = list(raw_tools.keys())
        report = _check_with_timeout(tool_names, loaded, proj_path, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return _broken_project(proj_path, proj_name, exc)

    report_tools = report.get("tools") or {}
    if report.get("ok"):
        chosen_dates = [
            str(entry.get("chosen")).strip()
            for entry in raw_tools.values()
            if isinstance(entry, dict) and str(entry.get("chosen") or "").strip()
        ]
        lock_date = max(chosen_dates) if chosen_dates else "-"
        return {
            **identity,
            "status": "ok",
            "tools": report_tools,
            "tools_count": len(tool_names),
            "lock_date": lock_date,
            "line": f"  ok     {proj_name}  ({len(tool_names)} tools, lock {lock_date})",
        }

    detail = _drift_detail(tool_names, report_tools, report.get("summary"))
    return {
        **identity,
        "status": "drift",
        "tools": report_tools,
        "detail": detail,
        "line": f"  DRIFT  {proj_name}  {detail}",
    }


def doctor_report(
    project_paths: Iterable[Path | str],
    *,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Return structured doctor report with `lines` and `projects` entries."""
    items = [_inspect_project(Path(p), timeout=timeout) for p in project_paths]
    return {
        "ok": all(item["status"] == "ok" for item in items),
        "lines": [item["line"] for item in items],
        "projects": items,
    }


def doctor_lines(
    project_paths: Iterable[Path | str],
    *,
    timeout: float = 3.0,
) -> list[str]:
    """Return one status line per project path for `hermes defuzz tools doctor`."""
    return doctor_report(project_paths, timeout=timeout)["lines"]
