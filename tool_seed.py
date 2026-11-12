"""Seed and inspect project TOOLS.lock files from static evidence and live probes."""

from __future__ import annotations

import datetime as dt
import json
import os
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import safe_state_store, state_store, toolchk
from .safety import SafetyError, safe_write_text, verify_nofollow_within_root
from .tool_detect import detect_tools

TOOLS_LOG_REL = ".adopt/tools-log.json"
SNOOZE_NAMESPACE = "tools-snooze"
# Ten years: longer than any advisory is worth hiding, and far below date overflow.
MAX_SNOOZE_DAYS = 3650


def lock_path(project_root: Path | str) -> Path:
    """Return the path to TOOLS.lock inside project_root."""
    return Path(project_root) / "TOOLS.lock"


def tools_log_path(project_root: Path | str) -> Path:
    """Return the path to .adopt/tools-log.json inside project_root."""
    return Path(project_root) / ".adopt" / "tools-log.json"


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _today_iso(today: str | dt.date | None = None) -> str:
    if today is None:
        return dt.date.today().isoformat()
    if isinstance(today, dt.date):
        return today.isoformat()
    return str(today)


def _today_date(today: str | dt.date | None = None) -> dt.date:
    if today is None:
        return dt.date.today()
    if isinstance(today, dt.date):
        return today
    return dt.date.fromisoformat(str(today).strip())


def load_tools_log(project_root: Path | str) -> list[dict[str, Any]]:
    """Read .adopt/tools-log.json without following symlinks; returns [] if absent or malformed."""
    root = Path(project_root)
    try:
        log_file = verify_nofollow_within_root(root, TOOLS_LOG_REL)
    except Exception:
        return []
    if not log_file.exists() or os.path.islink(log_file):
        return []
    try:
        data = json.loads(log_file.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _append_tools_log_entries(
    project_root: Path | str,
    new_entries: list[dict[str, Any]],
) -> None:
    """Append one or more entries to .adopt/tools-log.json atomically and without following symlinks."""
    if not new_entries:
        return
    root = Path(project_root)
    entries = load_tools_log(root)
    entries.extend(new_entries)
    payload = json.dumps(entries, indent=2, sort_keys=False) + "\n"
    try:
        safe_write_text(root, TOOLS_LOG_REL, payload, overwrite=True)
    except SafetyError:
        # Fallback for unit-test paths (e.g. inside a git worktree) where safe_mkdirs refuses .worktrees:
        # still verify no-follow within root and write via safe_state_store.atomic_write_json.
        target = verify_nofollow_within_root(root, TOOLS_LOG_REL)
        if os.path.islink(target.parent):
            raise
        target.parent.mkdir(parents=True, exist_ok=True)
        safe_state_store.atomic_write_json(target, entries, mode=0o644)


def _probe_seed_entry(
    name: str,
    entry: dict[str, Any],
    root: Path,
) -> tuple[str, str | None]:
    """Return the probed version and an optional sanitized failure message."""
    try:
        installed_ver, _where = toolchk.probe(name, entry, root)
    except FileNotFoundError:
        err_str = toolchk.missing_tool_line(name, entry.get("minimum"))
    except Exception:  # noqa: BLE001
        # Plain words only: the raw error can carry paths and command output the user never gave.
        err_str = f"{name}: found, but its version could not be read. Check that {name} runs, {toolchk.SETUP_HINT}"
    else:
        return installed_ver, None
    return "unknown", err_str


def seed_lock(
    project_root: Path | str,
    *,
    event: str,
    template_needs: Iterable[str] = (),
    today: str | dt.date | None = None,
) -> dict[str, Any]:
    """Detect project tools, probe versions, merge with existing TOOLS.lock, and write atomically."""
    root = Path(project_root)
    target = lock_path(root)
    chosen = _today_iso(today)

    detected = detect_tools(
        root,
        chosen=chosen,
        event=event,
        template_needs=template_needs,
    )

    existing_header: dict[str, Any] = dict(toolchk.DEFAULT_HEADER)
    existing_tools: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    if os.path.islink(target):
        notes.append("Refused to follow symlinked TOOLS.lock; treated as absent.")
    elif target.is_file():
        loaded = toolchk.load_lock(target)
        existing_header = dict(loaded["lock"])
        existing_tools = {k: dict(v) for k, v in loaded["tools"].items()}

    merged_tools: dict[str, dict[str, Any]] = {}
    added: list[str] = []
    refreshed: list[str] = []
    kept: list[str] = []
    probe_failed: dict[str, str] = {}
    log_entries: list[dict[str, Any]] = []
    at_ts = _iso_now()

    for name in sorted(set(existing_tools.keys()) | set(detected.keys())):
        prev = existing_tools.get(name)
        if prev is not None and prev.get("source", "human") in ("human", "agent"):
            merged_tools[name] = dict(prev)
            kept.append(name)
            continue

        # An auto entry that states a `minimum` is a template floor: keep its probe, floor and reason,
        # and record this machine's version (never the template author's).
        floor_entry = prev is not None and bool(prev.get("minimum"))
        if name not in detected and not floor_entry:
            # Never delete existing entries even if source == 'auto' and no longer detected.
            assert prev is not None
            merged_tools[name] = dict(prev)
            kept.append(name)
            continue

        if floor_entry:
            assert prev is not None
            entry = dict(prev)
            entry["chosen"] = chosen
            entry["source"] = "auto"
        else:
            entry = dict(detected[name])
        installed_ver, probe_error = _probe_seed_entry(name, entry, root)
        entry["version"] = installed_ver
        if probe_error is not None:
            entry["reason"] = f"{entry['reason']} Probe failed at seeding: {probe_error}"
            probe_failed[name] = probe_error

        merged_tools[name] = entry
        if prev is None:
            added.append(name)
        else:
            refreshed.append(name)

        log_entries.append(
            {
                "at": at_ts,
                "who": str(entry.get("source") or "auto"),
                "tool": name,
                "before": dict(prev) if prev is not None else None,
                "after": dict(entry),
                "reason": str(entry.get("reason") or ""),
            }
        )

    lock_payload = {
        "lock": existing_header,
        "tools": merged_tools,
    }
    if os.path.islink(target):
        target.unlink()
    toolchk.dump_lock(target, lock_payload)

    # Append provenance log only when .adopt/ already exists (e.g. adopted project or after first manual action)
    # so fresh template scaffolds don't gain an untracked .adopt/ directory before git commit.
    adopt_dir = root / ".adopt"
    if not os.path.islink(adopt_dir) and adopt_dir.is_dir() and log_entries:
        try:
            _append_tools_log_entries(root, log_entries)
        except Exception:  # noqa: BLE001
            pass

    res: dict[str, Any] = {
        "written": str(target),
        "added": added,
        "refreshed": refreshed,
        "kept": kept,
        "probe_failed": probe_failed,
    }
    if notes:
        res["notes"] = notes
    return res


def status(project_root: Path | str) -> dict[str, Any]:
    """Load TOOLS.lock and run toolchk.check across all locked tools without raising on tool issues."""
    root = Path(project_root)
    target = lock_path(root)
    loaded = toolchk.load_lock(target)
    all_tools = list(loaded["tools"].keys())
    return toolchk.check(all_tools, loaded, root)


def _resolve_snooze_db(db_path: Path | str | None = None) -> Path:
    if db_path is not None:
        return Path(db_path).expanduser()
    return state_store.state_db_path()


def _project_snooze_key(project_root: Path | str) -> str:
    return str(Path(project_root).expanduser().resolve())


def snoozed(
    project_root: Path | str,
    db_path: Path | str | None = None,
    *,
    today: str | dt.date | None = None,
) -> dict[str, str]:
    """Return active `{tool: until_iso}` snoozes for `project_root` from `safe_state_store` namespace 'tools-snooze'."""
    target_db = _resolve_snooze_db(db_path)
    proj_key = _project_snooze_key(project_root)
    raw = safe_state_store.get_state(target_db, SNOOZE_NAMESPACE, proj_key, default={})
    if not isinstance(raw, dict):
        return {}
    ref_date = _today_date(today)
    active: dict[str, str] = {}
    for tool_name, until_val in raw.items():
        if not isinstance(tool_name, str) or not isinstance(until_val, str):
            continue
        cleaned = until_val.strip()
        if not cleaned:
            continue
        try:
            until_date = dt.date.fromisoformat(cleaned[:10])
        except ValueError:
            continue
        if until_date >= ref_date:
            active[tool_name] = cleaned
    return active


def snooze(
    project_root: Path | str,
    tool: str,
    days: int,
    db_path: Path | str | None = None,
    *,
    today: str | dt.date | None = None,
) -> dict[str, Any]:
    """Snooze upstream advisory note for `tool` in `project_root` for `days` days inside state.db (never in TOOLS.lock)."""
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tool must be a non-empty string")
    tool_name = tool.strip()
    if isinstance(days, bool) or not isinstance(days, int):
        raise ValueError("days must be an integer")
    if days < 0:
        raise ValueError("days must be >= 0")
    if days > MAX_SNOOZE_DAYS:
        raise ValueError(f"days must be at most {MAX_SNOOZE_DAYS}")

    target_db = _resolve_snooze_db(db_path)
    proj_key = _project_snooze_key(project_root)
    store = safe_state_store.SafeStateStore(target_db, default_namespace=SNOOZE_NAMESPACE)
    current = store.get(proj_key, default={})
    updated: dict[str, str] = dict(current) if isinstance(current, dict) else {}

    ref_date = _today_date(today)
    if days == 0:
        updated.pop(tool_name, None)
        until_iso: str | None = None
    else:
        try:
            until_iso = (ref_date + dt.timedelta(days=days)).isoformat()
        except OverflowError as exc:
            raise ValueError("days reaches past the last supported date") from exc
        updated[tool_name] = until_iso

    # Prune expired entries while saving
    cleaned_map: dict[str, str] = {}
    for k, v in updated.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        try:
            if dt.date.fromisoformat(v[:10]) >= ref_date:
                cleaned_map[k] = v
        except ValueError:
            continue

    store.save(proj_key, cleaned_map)
    return {
        "tool": tool_name,
        "snoozed_until": until_iso,
        "days": days,
    }


def _row_from_check(
    tool_name: str,
    check_row: dict[str, Any],
    *,
    age_nudge_months: int,
    snoozed_map: dict[str, str],
) -> dict[str, Any]:
    age_months = int(check_row.get("age_months", 0) or 0)
    nudge = bool(age_nudge_months > 0 and age_months >= age_nudge_months)
    return {
        "tool": tool_name,
        "chosen": check_row.get("locked"),
        "installed": check_row.get("installed"),
        "upstream_latest": check_row.get("upstream_latest"),
        "chosen_on": check_row.get("chosen"),
        "age_months": age_months,
        "nudge": nudge,
        "by": check_row.get("source", "human"),
        "reason": check_row.get("reason", ""),
        "status": check_row.get("status", "unknown"),
        "snoozed_until": snoozed_map.get(tool_name),
    }


def _age_nudge_months(loaded: dict[str, Any]) -> int:
    header = loaded["lock"]
    raw_nudge = header.get("age_nudge_months", 12)
    return (
        int(raw_nudge)
        if isinstance(raw_nudge, int) and not isinstance(raw_nudge, bool)
        else 12
    )


def _checked_tool_row(
    root: Path,
    loaded: dict[str, Any],
    tool_name: str,
    db_path: Path | str | None,
) -> dict[str, Any]:
    age_nudge_months = _age_nudge_months(loaded)
    rep = toolchk.check([tool_name], loaded, root)
    c_row = rep.get("tools", {}).get(tool_name, {})
    snoozed_map = snoozed(root, db_path=db_path)
    return _row_from_check(
        tool_name,
        c_row,
        age_nudge_months=age_nudge_months,
        snoozed_map=snoozed_map,
    )


def table(
    project_root: Path | str,
    *,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Return human-surface rows for all tools in TOOLS.lock combined with snooze state."""
    root = Path(project_root)
    target = lock_path(root)
    loaded = toolchk.load_lock(target)
    age_nudge_months = _age_nudge_months(loaded)
    all_tools = list(loaded["tools"].keys())
    rep = toolchk.check(all_tools, loaded, root)
    snoozed_map = snoozed(root, db_path=db_path)

    rows: list[dict[str, Any]] = []
    rep_tools = rep.get("tools", {})
    for name in all_tools:
        c_row = rep_tools.get(name, {})
        rows.append(
            _row_from_check(
                name,
                c_row,
                age_nudge_months=age_nudge_months,
                snoozed_map=snoozed_map,
            )
        )
    return rows


def accept_installed(
    project_root: Path | str,
    tool: str,
    reason: str,
    *,
    today: str | dt.date | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Accept the currently installed version of `tool` as the chosen version in TOOLS.lock."""
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("A non-empty reason is required to accept an installed version.")
    clean_reason = reason.strip()

    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tool must be a non-empty string")
    tool_name = tool.strip()

    root = Path(project_root)
    target = lock_path(root)
    loaded = toolchk.load_lock(target)
    tools_map = loaded["tools"]
    if tool_name not in tools_map:
        raise KeyError(f"Tool {tool_name!r} is not in {target}")

    before_entry = dict(tools_map[tool_name])
    installed_ver, _where = toolchk.probe(tool_name, before_entry, root)
    chosen_str = _today_iso(today)

    after_entry = dict(before_entry)
    after_entry["version"] = installed_ver
    after_entry["chosen"] = chosen_str
    after_entry["reason"] = clean_reason
    after_entry["source"] = "human"

    tools_map[tool_name] = after_entry
    toolchk.dump_lock(target, loaded)

    _append_tools_log_entries(
        root,
        [
            {
                "at": _iso_now(),
                "who": "human",
                "tool": tool_name,
                "before": before_entry,
                "after": dict(after_entry),
                "reason": clean_reason,
            }
        ],
    )

    return _checked_tool_row(root, loaded, tool_name, db_path)


def set_reason(
    project_root: Path | str,
    tool: str,
    reason: str,
    *,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Update the reason for `tool` in TOOLS.lock (auto source becomes human; human/agent stays)."""
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("A non-empty reason is required.")
    clean_reason = reason.strip()

    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tool must be a non-empty string")
    tool_name = tool.strip()

    root = Path(project_root)
    target = lock_path(root)
    loaded = toolchk.load_lock(target)
    tools_map = loaded["tools"]
    if tool_name not in tools_map:
        raise KeyError(f"Tool {tool_name!r} is not in {target}")

    before_entry = dict(tools_map[tool_name])
    prev_source = str(before_entry.get("source") or "human")
    new_source = "human" if prev_source == "auto" else prev_source

    after_entry = dict(before_entry)
    after_entry["reason"] = clean_reason
    after_entry["source"] = new_source

    tools_map[tool_name] = after_entry
    toolchk.dump_lock(target, loaded)

    log_who = new_source if new_source in ("human", "auto", "agent") else "human"
    _append_tools_log_entries(
        root,
        [
            {
                "at": _iso_now(),
                "who": log_who,
                "tool": tool_name,
                "before": before_entry,
                "after": dict(after_entry),
                "reason": clean_reason,
            }
        ],
    )

    return _checked_tool_row(root, loaded, tool_name, db_path)
