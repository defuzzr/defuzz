"""Explicit TOOLS.lock provenance, not session hooks or an execution gate.

Reads never establish trust. Legacy projects without a recorded digest are unknown.
Only human trust or plugin-owned lock edits record an out-of-repository digest.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import time
import tomllib
from contextlib import closing
from pathlib import Path
from typing import Any

from . import safety, tool_seed, toolchk
from .audit.fingerprint import safe_read_regular_file_plain
from .audit.readonly_db import open_readonly_sqlite
from .state_store import state_db_path

_TRUST_TABLE_DDL = (
    "CREATE TABLE IF NOT EXISTS tools_lock_trust ("
    "path TEXT PRIMARY KEY, digest TEXT NOT NULL, source TEXT NOT NULL, trusted_at INTEGER NOT NULL)"
)


def _db(project: Path | str, db_path: Path | str | None = None) -> tuple[Path, Path]:
    root = Path(project).expanduser().resolve()
    db = (Path(db_path) if db_path is not None else state_db_path()).expanduser().resolve()
    if db == root or root in db.parents:
        raise ValueError("Lock trust must be stored outside the repository")
    return root, db


def _read_lock_sha(root: Path) -> tuple[str | None, str]:
    read = safe_read_regular_file_plain(root, "TOOLS.lock", retain_bytes=False)
    digest = read.sha256 if read.stable and read.coverage == "verified" and read.kind == "regular" else None
    return digest, read.coverage


def inspect_lock_trust(project: Path | str, *, db_path: Path | str | None = None) -> dict[str, Any]:
    root, db = _db(project, db_path)
    digest, coverage = _read_lock_sha(root)
    stored, error = None, None
    if os.path.lexists(db):
        try:
            with open_readonly_sqlite(db) as (conn, _identity):
                if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tools_lock_trust'").fetchone():
                    row = conn.execute("SELECT digest FROM tools_lock_trust WHERE path=?", (str(root),)).fetchone()
                    stored = row[0] if row else None
        except (OSError, sqlite3.Error) as exc:
            stored = None
            coverage = "could_not_verify"
            error = type(exc).__name__
    status = (
        "unknown"
        if error is not None or stored is None or digest is None
        else ("trusted" if stored == digest else "untrusted")
    )
    reason = error or (
        "Lock missing or unreadable" if digest is None
        else "No provenance recorded" if stored is None
        else "Hash matches" if stored == digest
        else "TOOLS.lock changed"
    )
    return {
        "trusted": error is None and status == "trusted", "status": status, "tools_lock_hash": digest,
        "trusted_hash": stored, "coverage": coverage, "reason": reason,
    }


def trust_lock(project: Path | str, *, expected_hash: str | None, db_path: Path | str | None = None, source: str = "human") -> dict[str, Any]:
    root, db = _db(project, db_path)
    state = inspect_lock_trust(root, db_path=db)
    if not expected_hash or state["tools_lock_hash"] != expected_hash:
        raise ValueError("TOOLS.lock changed or cannot be read; review its current hash before trusting")
    if source not in ("human", "plugin"):
        raise ValueError("Invalid provenance source")
    db.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute(_TRUST_TABLE_DDL)
        conn.execute(
            "INSERT INTO tools_lock_trust VALUES (?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET "
            "digest=excluded.digest,source=excluded.source,trusted_at=excluded.trusted_at",
            (str(root), expected_hash, source, int(time.time())),
        )
    return inspect_lock_trust(root, db_path=db)


def _publish_digest(conn: sqlite3.Connection, root: Path, digest: str) -> None:
    """Caller owns the transaction; never commit a digest before its bytes."""
    conn.execute("UPDATE tools_lock_trust SET digest=?, source=?, trusted_at=? WHERE path=?", (digest, "plugin", int(time.time()), str(root)))


def _replace_lock(root: Path, content: bytes) -> None:
    target = safety.verify_nofollow_within_root(root, "TOOLS.lock")
    mode = target.stat().st_mode & 0o777
    fd, name = tempfile.mkstemp(prefix=".TOOLS.lock.", dir=root)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode) if hasattr(os, "fchmod") else os.chmod(name, mode)
            os.fsync(stream.fileno())
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _stage_lock_edit(root: Path, db_parent: Path, before_bytes: bytes, tool: str, clean_reason: str, action: str):
    with tempfile.TemporaryDirectory(prefix="lock-edit-", dir=db_parent) as directory:
        staged = Path(directory) / "TOOLS.lock"
        staged.write_bytes(before_bytes)
        loaded = toolchk.load_lock(staged)
        if tool not in loaded["tools"]:
            raise KeyError(f"Unknown locked tool: {tool}")
        entry = dict(loaded["tools"][tool])
        updated = dict(entry, reason=clean_reason)
        if action == "accept":
            updated.update(version=toolchk.probe(tool, entry, root)[0], chosen=tool_seed._today_iso(None), source="human")
        elif entry.get("source") == "auto":
            updated["source"] = "human"
        loaded["tools"][tool] = updated
        toolchk.dump_lock(staged, loaded)
        return loaded, entry, updated, staged.read_bytes()


def _commit_lock_edit(root: Path, db: Path, before_sha256: str | None, before_bytes: bytes, content: bytes, digest: str) -> None:
    written = False
    with closing(sqlite3.connect(db)) as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(_TRUST_TABLE_DDL)
            baseline = conn.execute("SELECT digest FROM tools_lock_trust WHERE path=?", (str(root),)).fetchone()
            if _read_lock_sha(root)[0] != before_sha256:
                raise ValueError("TOOLS.lock changed during edit; review again")
            _replace_lock(root, content)
            written = True
            if baseline and baseline[0] == before_sha256:
                _publish_digest(conn, root, digest)
            if _read_lock_sha(root)[0] != digest:
                raise ValueError("TOOLS.lock changed during publication")
            conn.commit()
        except BaseException:
            conn.rollback()
            if written and _read_lock_sha(root)[0] == digest:
                _replace_lock(root, before_bytes)
            raise


def edit_lock(project: Path | str, tool: str, reason: str, *, action: str, db_path: Path | str | None = None) -> dict[str, Any]:
    """Stage an exact edit, then publish bytes and reviewed provenance together."""
    if action not in ("reason", "accept") or not isinstance(reason, str) or not reason.strip():
        raise ValueError("An explicit edit action and non-empty reason are required")
    clean_reason = reason.strip()
    root, db = _db(safety.assert_safe_root(project, role="tools_edit_root"), db_path)
    before = safe_read_regular_file_plain(root, "TOOLS.lock", retain_bytes=True)
    if before.content is None or not before.stable or before.coverage != "verified":
        raise ValueError("TOOLS.lock cannot be safely read")
    db.parent.mkdir(parents=True, exist_ok=True)
    loaded, entry, updated, content = _stage_lock_edit(root, db.parent, before.content, tool, clean_reason, action)
    digest = hashlib.sha256(content).hexdigest()
    report = toolchk.check([tool], loaded, root)
    row = tool_seed._row_from_check(
        tool, report.get("tools", {}).get(tool, {}),
        age_nudge_months=loaded["lock"].get("age_nudge_months", 12),
        snoozed_map=tool_seed.snoozed(root, db_path=db),
    )
    _commit_lock_edit(root, db, before.sha256, before.content, content, digest)
    try:
        tool_seed._append_tools_log_entries(root, [{
            "at": tool_seed._iso_now(), "who": updated.get("source", "human"),
            "tool": tool, "before": entry, "after": updated, "reason": clean_reason,
        }])
    except Exception:  # noqa: BLE001
        row["log_warning"] = "Lock saved; advisory log could not be written"
    return row


def static_lock_summary(project: Path | str, *, db_path: Path | str | None = None) -> dict[str, Any]:
    """Metadata only: never probe installed tools or run project commands."""
    state = inspect_lock_trust(project, db_path=db_path)
    read = safe_read_regular_file_plain(Path(project), "TOOLS.lock", retain_bytes=True)
    if read.content is None or read.coverage != "verified" or not read.stable:
        return {"trust": state, "coverage": "could_not_verify", "tools": [], "installed_versions": "not_included"}
    try:
        data = tomllib.loads(read.content.decode("utf-8"))
        tools = [
            {"name": name, "version": row.get("version"), "source": row.get("source", "unknown")}
            for name, row in sorted(data.items()) if name != "lock" and isinstance(row, dict)
        ]
    except (ValueError, UnicodeError):
        return {"trust": state, "coverage": "could_not_verify", "tools": [], "error": "Invalid TOOLS.lock", "installed_versions": "not_included"}
    summary_coverage = "verified" if state.get("coverage") == "verified" else "could_not_verify"
    return {"trust": state, "coverage": summary_coverage, "tools": tools, "installed_versions": "not_included"}
