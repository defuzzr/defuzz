"""Read-only SQLite opener and readers for inspected profile/plugin databases.

Settled invariants (§1, §2, §3, §10, §12):
- Never create, initialize, or migrate inspected profile `state.db` or per-profile
  `defuzz/state.db` files during a sweep.
- Verify the target path is an existing regular file (using descriptor-relative /
  O_NOFOLLOW + O_NONBLOCK validation where supported) before opening with SQLite
  `mode=ro`. Never open FIFOs, sockets, device nodes, or symlinks.
- Enforce `PRAGMA query_only = ON` on every read-only connection.
- Capture DB file + WAL/SHM sidecar stat identities before and after reading so
  mid-read mutations or replacements mark the snapshot unstable (`changed_during_read`).
  Registration reads exclude reader-owned SHM metadata from this comparison and
  additionally compare bounded row contents across two reads.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterator, Sequence

from .contract import (
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    make_finding,
)
from .fingerprint import CredentialStoreNotOpened, open_checked

_SQLITE_HEADER_MAGIC = b"SQLite format 3\x00"
_DENIED_SESSION_SOURCES: frozenset[str] = frozenset({"tool", "kanban", "subagent"})
MAX_REGISTRATION_ROWS = 10_000
_READ_ONLY_IOERR_RETRIES = 3
_READ_ONLY_IOERR_BACKOFF_S = 0.03
_ALLOWED_REGISTRATION_COLUMNS: frozenset[str] = frozenset({
    "path", "name", "slug", "template_id", "kind", "layout", "languages", "engine",
    "created_at", "hermes_project_id", "rules_hash", "plugin_commit", "prefix",
    "substituted_prefix", "locked_hashes", "locked_hashes_json",
})


class ReadOnlyDbError(OSError):
    """Raised when a database cannot be safely opened in read-only mode."""

    def __init__(self, message: str, *, reason: str = "unreadable") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class DbFileIdentity:
    """Stat identity of a SQLite database and its optional WAL/SHM sidecars."""

    path: str
    dev: int
    ino: int
    size: int
    mtime_ns: int
    ctime_ns: int
    wal_identity: tuple[int, int, int, int] | None = None
    shm_identity: tuple[int, int, int, int] | None = None
    wal_mode: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "dev": self.dev,
            "ino": self.ino,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "wal_identity": list(self.wal_identity) if self.wal_identity is not None else None,
            "shm_identity": list(self.shm_identity) if self.shm_identity is not None else None,
        }


def _json_sha256(payload: Any, *, sort_keys: bool = False) -> str:
    encoded = json.dumps(payload, sort_keys=sort_keys, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _db_or_wal_changed(pre_id: DbFileIdentity, post_id: DbFileIdentity) -> bool:
    """Compare DB + WAL identity while ignoring reader-owned SHM read-mark updates."""
    return replace(pre_id, shm_identity=None) != replace(post_id, shm_identity=None)


def _stat_sidecar(path: Path) -> tuple[int, int, int, int] | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReadOnlyDbError(f"Could not stat SQLite sidecar {path}: {exc}", reason="sidecar_unreadable") from exc
    if not stat.S_ISREG(st.st_mode):
        raise ReadOnlyDbError(f"SQLite sidecar {path} is not a regular file", reason="special_file")
    return (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_mtime_ns))


def stat_db_identity(db_path: Path | str) -> DbFileIdentity:
    """Validate and capture the pre/post-read stat identity of `db_path` without following a leaf symlink."""
    from .policy import credential_path

    target = Path(db_path)
    if credential_path(target.absolute()):
        raise ReadOnlyDbError("Credential database excluded by policy", reason="excluded")
    try:
        st = os.lstat(target)
    except FileNotFoundError as exc:
        raise ReadOnlyDbError(f"Database does not exist: {target}", reason="missing") from exc
    except OSError as exc:
        raise ReadOnlyDbError(f"Could not stat database {target}: {exc}", reason="unreadable") from exc

    if stat.S_ISLNK(st.st_mode):
        raise ReadOnlyDbError(f"Refusing symlink database file: {target}", reason="symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ReadOnlyDbError(f"Refusing non-regular database file: {target}", reason="special_file")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = open_checked(str(target), flags)
    except CredentialStoreNotOpened:
        # The opened file is a declared credential: closed unread, reported as a declared database is.
        raise ReadOnlyDbError("Credential database excluded by policy", reason="excluded") from None
    except OSError as exc:
        raise ReadOnlyDbError(f"Could not open database {target} safely: {exc}", reason="unreadable") from exc

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ReadOnlyDbError(f"Opened descriptor for {target} is not a regular file", reason="special_file")
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise ReadOnlyDbError(f"Database identity changed during open: {target}", reason="race_detected")
        header = os.read(fd, 20)
        if fst.st_size > 0:
            if len(header) < 16 or header[:16] != _SQLITE_HEADER_MAGIC:
                raise ReadOnlyDbError(f"Invalid SQLite header in {target}", reason="corrupt_header")
    finally:
        os.close(fd)

    return DbFileIdentity(
        path=str(target),
        dev=int(fst.st_dev),
        ino=int(fst.st_ino),
        size=int(fst.st_size),
        mtime_ns=int(fst.st_mtime_ns),
        ctime_ns=int(fst.st_ctime_ns),
        wal_identity=_stat_sidecar(Path(f"{target}-wal")),
        shm_identity=_stat_sidecar(Path(f"{target}-shm")),
        wal_mode=header[18:20] == b'\x02\x02',
    )


def read_only_sqlite_uri(db_path: Path | str) -> str:
    """Build a percent-encoded `file:...?mode=ro` URI for `db_path`."""
    abs_path = Path(os.path.abspath(os.fspath(db_path)))
    return abs_path.as_uri() + "?mode=ro"


@contextlib.contextmanager
def open_readonly_sqlite(
    db_path: Path | str,
    *,
    timeout: float = 2.0,
) -> Iterator[tuple[sqlite3.Connection, DbFileIdentity]]:
    """Open a user database without creating any file beside it.

    No WAL or an empty WAL uses mode=ro&immutable=1. Nonempty WAL requires
    an existing SHM index and uses mode=ro; only its read marks may change.
    Refuse rollback journals rather than recovering or ignoring them.
    The post-read identity check covers the TOCTOU window between capture and open.
    """
    pre_id = stat_db_identity(db_path)
    if os.path.lexists(str(db_path) + '-journal'):
        raise ReadOnlyDbError('rollback journal present', reason='hot_journal')
    has_frames = session_wal_has_frames(pre_id)
    if has_frames and pre_id.shm_identity is None:
        raise ReadOnlyDbError('write-ahead log without its index', reason='wal_needs_index')
    uri = read_only_sqlite_uri(db_path) + ('' if has_frames else '&immutable=1')
    conn: sqlite3.Connection | None = None
    last_err: Exception | None = None

    for attempt in range(_READ_ONLY_IOERR_RETRIES + 1):
        try:
            conn = sqlite3.connect(
                uri, uri=True, timeout=timeout, isolation_level=None, check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
            break
        except sqlite3.OperationalError as exc:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
                conn = None
            last_err = exc
            if "disk i/o error" in str(exc).lower() and attempt < _READ_ONLY_IOERR_RETRIES:
                time.sleep(_READ_ONLY_IOERR_BACKOFF_S)
                continue
            raise ReadOnlyDbError(f"SQLite read-only open failed for {db_path}: {exc}", reason="sqlite_error") from exc
        except sqlite3.DatabaseError as exc:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
                conn = None
            raise ReadOnlyDbError(f"SQLite database error for {db_path}: {exc}", reason="corrupt_db") from exc

    if conn is None:
        raise ReadOnlyDbError(f"Could not open {db_path}: {last_err}", reason="sqlite_error")

    try:
        yield conn, pre_id
        post_id = stat_db_identity(db_path)
        if (_db_or_wal_changed(pre_id, post_id)
                or (not has_frames and pre_id.shm_identity != post_id.shm_identity)
                or os.path.lexists(str(db_path) + '-journal')):
            raise ReadOnlyDbError('Database changed during read', reason='race_detected')
    finally:
        with contextlib.suppress(Exception):
            conn.close()


def session_wal_has_frames(identity) -> bool:
    """True when a write-ahead log exists and holds data (size is field 2 of the identity)."""
    return identity.wal_identity is not None and identity.wal_identity[2] > 0


@contextlib.contextmanager
def open_session_sqlite_without_sidecar_creation(db_path, *, timeout=0.1):
    """Compatibility alias; all user-database readers share the same opener."""
    with open_readonly_sqlite(db_path, timeout=timeout) as opened:
        yield opened


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    ).fetchall()
    if not rows:
        return set()
    escaped = '"' + table_name.replace('"', '""') + '"'
    return {str(r["name"]) for r in conn.execute(f"PRAGMA table_info({escaped})").fetchall()}


@dataclass(frozen=True)
class ProfileSessionEvidence:
    """Read-only session evidence extracted from a profile's `state.db` (§2, §8, §13.5)."""

    db_path: str
    exists: bool
    coverage: str
    newest_started_at: float | None = None
    newest_session_id: str | None = None
    newest_human_session: dict[str, Any] | None = None
    newest_worker_session: dict[str, Any] | None = None
    session_count: int | None = None
    changed_during_read: bool = False
    error: str | None = None
    row_digest: str | None = None
    db_identity: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_path": self.db_path,
            "exists": self.exists,
            "coverage": self.coverage,
            "newest_started_at": self.newest_started_at,
            "newest_session_id": self.newest_session_id,
            "newest_human_session": self.newest_human_session,
            "newest_worker_session": self.newest_worker_session,
            "session_count": self.session_count,
            "changed_during_read": self.changed_during_read,
            "error": self.error,
            "row_digest": self.row_digest,
            "db_identity": self.db_identity,
        }


def _query_recent_sessions(conn: sqlite3.Connection, cols: set[str]) -> tuple[list[sqlite3.Row], int]:
    select_cols = [
        "id",
        "started_at",
        "source" if "source" in cols else "'' AS source",
        "title" if "title" in cols else "'' AS title",
        "last_activity_at" if "last_activity_at" in cols else "NULL AS last_activity_at",
        "message_count" if "message_count" in cols else "0 AS message_count",
    ]
    query = (
        f"SELECT {', '.join(select_cols)} FROM sessions "
        "ORDER BY COALESCE(started_at, 0) DESC, id ASC LIMIT 50"
    )
    rows = conn.execute(query).fetchall()
    count_row = conn.execute("SELECT COUNT(*) AS cnt FROM sessions").fetchone()
    total_count = int(count_row["cnt"]) if count_row is not None else len(rows)
    return rows, total_count


def _summarize_session_rows(
    rows: Sequence[sqlite3.Row],
) -> tuple[float | None, str | None, dict[str, Any] | None, dict[str, Any] | None, list[tuple[Any, ...]]]:
    newest_started_at: float | None = None
    newest_session_id: str | None = None
    human: dict[str, Any] | None = None
    worker: dict[str, Any] | None = None
    digest_items: list[tuple[Any, ...]] = []

    for r in rows:
        sid = str(r["id"])
        raw_started = r["started_at"]
        started_val = float(raw_started) if isinstance(raw_started, (int, float)) and raw_started > 0 else None
        raw_active = r["last_activity_at"]
        active_val = (
            float(raw_active) if isinstance(raw_active, (int, float)) and raw_active > 0 else started_val
        )
        src = str(r["source"] or "").strip().lower()
        title = str(r["title"] or "")
        msg_count = int(r["message_count"] or 0)
        digest_items.append((sid, started_val, active_val, src, msg_count))

        if newest_started_at is None and started_val is not None:
            newest_started_at = started_val
            newest_session_id = sid

        if src in _DENIED_SESSION_SOURCES:
            if worker is None:
                worker = {"id": sid, "source": src, "title": title, "started_at": started_val, "last_active": active_val}
        elif human is None:
            human = {
                "id": sid, "source": src, "title": title, "started_at": started_val,
                "last_active": active_val, "message_count": msg_count,
            }
    return newest_started_at, newest_session_id, human, worker, digest_items


def read_profile_session_evidence(db_path: Path | str) -> ProfileSessionEvidence:
    """Read last-session evidence from `<profile_dir>/state.db` without writing or migrating."""
    target = Path(db_path)
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return ProfileSessionEvidence(db_path=str(target), exists=False, coverage=COVERAGE_COULD_NOT_VERIFY)
    except OSError as exc:
        return ProfileSessionEvidence(
            db_path=str(target), exists=True, coverage=COVERAGE_COULD_NOT_VERIFY, error=f"Could not stat {target}: {exc}"
        )

    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_size == 0:
        reason = "symlink" if stat.S_ISLNK(st.st_mode) else ("special_file" if not stat.S_ISREG(st.st_mode) else "empty_db")
        return ProfileSessionEvidence(
            db_path=str(target),
            exists=True,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            error=f"Database {target} is not a readable non-empty regular SQLite file ({reason})",
        )

    try:
        with open_readonly_sqlite(target) as (conn, pre_id):
            cols = _table_columns(conn, "sessions")
            if not cols or "id" not in cols or "started_at" not in cols:
                post_id = stat_db_identity(target)
                return ProfileSessionEvidence(
                    db_path=str(target),
                    exists=True,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    session_count=0,
                    changed_during_read=_db_or_wal_changed(pre_id, post_id),
                    error="sessions table or started_at column absent",
                    db_identity=post_id.to_dict(),
                )

            rows, total_count = _query_recent_sessions(conn, cols)
            newest_started_at, newest_session_id, human, worker, digest_items = _summarize_session_rows(rows)
            post_id = stat_db_identity(target)
            changed = _db_or_wal_changed(pre_id, post_id)
            cov = COVERAGE_COULD_NOT_VERIFY if (changed or newest_started_at is None) else COVERAGE_VERIFIED
            return ProfileSessionEvidence(
                db_path=str(target),
                exists=True,
                coverage=cov,
                newest_started_at=newest_started_at,
                newest_session_id=newest_session_id,
                newest_human_session=human,
                newest_worker_session=worker,
                session_count=total_count,
                changed_during_read=changed,
                error="Database changed during read" if changed else None,
                row_digest=_json_sha256({"total": total_count, "rows": digest_items}),
                db_identity=post_id.to_dict(),
            )
    except (ReadOnlyDbError, sqlite3.Error) as exc:
        return ProfileSessionEvidence(
            db_path=str(target), exists=True, coverage=COVERAGE_COULD_NOT_VERIFY,
            changed_during_read=getattr(exc, 'reason', None) == 'race_detected', error=str(exc)
        )


def _parse_json_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except (ValueError, TypeError):
            pass
        return [raw]
    return [str(raw)]


def _parse_json_dict(raw: Any) -> dict[str, Any] | None:
    if not raw:
        return None
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            return None
    return None


@dataclass(frozen=True)
class ProfileRegistrationsSnapshot:
    """Read-only snapshot of one profile's `plugin-data/defuzz/state.db` registrations."""

    profile_name: str
    db_path: str
    exists: bool
    coverage: str
    records: list[dict[str, Any]] = field(default_factory=list)
    changed_during_read: bool = False
    error: str | None = None
    row_digest: str | None = None
    db_identity: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "db_path": self.db_path,
            "exists": self.exists,
            "coverage": self.coverage,
            "records": list(self.records),
            "changed_during_read": self.changed_during_read,
            "error": self.error,
            "row_digest": self.row_digest,
            "db_identity": self.db_identity,
        }


def _normalize_registration_row(r: sqlite3.Row, profile_name: str, target: Path) -> dict[str, Any] | None:
    keys = set(r.keys())
    # Preserve the exact stored identifier: forgetting compares this string verbatim, so
    # stripping would make a whitespace-ending registration impossible to forget.
    raw_path = str(r["path"] or "")
    if not raw_path:
        return None
    # Canonicalise only a path that is already an absolute filesystem spelling. Legacy
    # relative and "~" registrations stay raw in both fields; they are identifiers, not
    # paths to expand. No strip happens before either use.
    canonical_path = raw_path
    if "\x00" not in raw_path and os.path.isabs(raw_path):
        try:
            canonical_path = str(Path(raw_path).resolve(strict=False))
        except (OSError, RuntimeError):  # RuntimeError: a link loop on Python 3.11 and 3.12
            canonical_path = raw_path

    def _col(name: str) -> Any:
        return r[name] if name in keys else None

    locked_raw = _col("locked_hashes") if "locked_hashes" in keys else _col("locked_hashes_json")
    prefix_val = _col("prefix") if "prefix" in keys else _col("substituted_prefix")
    return {
        "owning_profile": profile_name,
        "db_path": str(target),
        "raw_path": raw_path,
        "canonical_path": canonical_path,
        "name": _col("name"),
        "slug": _col("slug"),
        "template_id": _col("template_id"),
        "kind": _col("kind"),
        "layout": _col("layout"),
        "languages": _parse_json_list(r["languages"]) if "languages" in keys else [],
        "engine": _col("engine"),
        "created_at": _col("created_at"),
        "hermes_project_id": _col("hermes_project_id"),
        "rules_hash": _col("rules_hash"),
        "plugin_commit": _col("plugin_commit"),
        "prefix": prefix_val,
        "locked_hashes": _parse_json_dict(locked_raw),
    }


def read_profile_registrations_readonly(
    profile_name: str,
    profile_dir: Path | str,
    *,
    db_path: Path | str | None = None,
) -> ProfileRegistrationsSnapshot:
    """Read `projects` registrations from a profile's `plugin-data/defuzz/state.db` read-only."""
    target = Path(db_path) if db_path is not None else Path(profile_dir) / "plugin-data" / "defuzz" / "state.db"
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return ProfileRegistrationsSnapshot(
            profile_name=profile_name, db_path=str(target), exists=False, coverage=COVERAGE_VERIFIED, records=[]
        )
    except OSError as exc:
        return ProfileRegistrationsSnapshot(
            profile_name=profile_name,
            db_path=str(target),
            exists=True,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            error=f"Could not stat plugin DB {target}: {exc}",
        )

    from .policy import credential_path, note_credential_skip

    if credential_path(target):
        note_credential_skip(target)
        return ProfileRegistrationsSnapshot(
            profile_name=profile_name,
            db_path=str(target),
            exists=True,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            records=[],
            error="credential_store_not_opened",
        )
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return ProfileRegistrationsSnapshot(
            profile_name=profile_name,
            db_path=str(target),
            exists=True,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            error=f"Plugin DB {target} is not a regular file",
        )
    if st.st_size == 0:
        return ProfileRegistrationsSnapshot(
            profile_name=profile_name,
            db_path=str(target),
            exists=True,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            error=f"Plugin DB {target} is 0 bytes",
        )

    try:
        with open_readonly_sqlite(target) as (conn, pre_id):
            cols = _table_columns(conn, "projects")
            if not cols or "path" not in cols:
                post_id = stat_db_identity(target)
                return ProfileRegistrationsSnapshot(
                    profile_name=profile_name,
                    db_path=str(target),
                    exists=True,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    error="Unsupported projects schema",
                    records=[],
                    changed_during_read=_db_or_wal_changed(pre_id, post_id),
                    row_digest=hashlib.sha256(b"[]").hexdigest(),
                    db_identity=post_id.to_dict(),
                )

            selected = ", ".join('"' + name + '"' for name in sorted(cols & _ALLOWED_REGISTRATION_COLUMNS))
            query = f"SELECT {selected} FROM projects ORDER BY path ASC LIMIT ?"
            rows = conn.execute(query, (MAX_REGISTRATION_ROWS + 1,)).fetchall()
            first_rows = [tuple(row) for row in rows]
            truncated = len(rows) > MAX_REGISTRATION_ROWS

            records = [
                rec
                for r in rows[:MAX_REGISTRATION_ROWS]
                if (rec := _normalize_registration_row(r, profile_name, target)) is not None
            ]
            last_rows = [tuple(row) for row in conn.execute(query, (MAX_REGISTRATION_ROWS + 1,)).fetchall()]
            post_id = stat_db_identity(target)
            changed = _db_or_wal_changed(pre_id, post_id) or first_rows != last_rows
            err = (
                "Registration row budget exceeded"
                if truncated
                else ("Plugin DB changed during read" if changed else None)
            )
            return ProfileRegistrationsSnapshot(
                profile_name=profile_name,
                db_path=str(target),
                exists=True,
                coverage=COVERAGE_COULD_NOT_VERIFY if (changed or truncated) else COVERAGE_VERIFIED,
                records=records,
                changed_during_read=changed,
                error=err,
                row_digest=_json_sha256(records, sort_keys=True),
                db_identity=post_id.to_dict(),
            )
    except (ReadOnlyDbError, sqlite3.Error) as exc:
        return ProfileRegistrationsSnapshot(
            profile_name=profile_name, db_path=str(target), exists=True, coverage=COVERAGE_COULD_NOT_VERIFY,
            changed_during_read=getattr(exc, 'reason', None) == 'race_detected', error=str(exc)
        )


def _multi_profile_registration_finding(
    cpath: str,
    owners: list[str],
    recs: list[dict[str, Any]],
    *,
    has_conflict: bool,
) -> dict[str, Any]:
    if has_conflict:
        return make_finding(
            rule_id="inventory.conflicting_profile_registrations",
            classification=CLASSIFICATION_REVIEW,
            coverage=COVERAGE_VERIFIED,
            affected_identities=[cpath, *owners],
            source_paths=[r["db_path"] for r in recs],
            evidence={"canonical_path": cpath, "owning_profiles": owners, "records": recs},
            consequence=(
                f"Project {cpath} is registered by {len(recs)} profiles with differing "
                "template or prefix metadata."
            ),
            limitations="Audit cannot automatically choose which profile's template baseline is authoritative.",
        )
    return make_finding(
        rule_id="inventory.multi_profile_registration",
        classification=CLASSIFICATION_INFO,
        coverage=COVERAGE_VERIFIED,
        affected_identities=[cpath, *owners],
        source_paths=[r["db_path"] for r in recs],
        evidence={
            "canonical_path": cpath,
            "profile_count": len(recs),
            "owning_profiles": owners,
            "records": recs,
        },
        consequence=f"Info: registered by {len(recs)} profiles ({', '.join(owners)}).",
        limitations="",
    )


def _build_project_unit(
    cpath: str,
    raw_recs: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    recs = sorted(raw_recs, key=lambda r: (str(r["owning_profile"]), str(r.get("created_at") or 0)))
    owners = [str(r["owning_profile"]) for r in recs]
    signatures = {
        (r.get("template_id"), r.get("prefix") if r.get("prefix") is not None else r.get("slug"))
        for r in recs
    }
    has_conflict = len(signatures) > 1
    finding = (
        _multi_profile_registration_finding(cpath, owners, recs, has_conflict=has_conflict)
        if len(recs) > 1
        else None
    )
    primary = recs[0]
    created_candidates = [int(r["created_at"]) for r in recs if isinstance(r.get("created_at"), (int, float))]
    unit = {
        "canonical_path": cpath,
        "owning_profiles": owners,
        "registration_count": len(recs),
        "conflicting_registrations": has_conflict,
        "template_id": primary.get("template_id") if not has_conflict else None,
        "prefix": (primary.get("prefix") or primary.get("slug")) if not has_conflict else None,
        "name": primary.get("name"),
        "slug": primary.get("slug"),
        "kind": primary.get("kind"),
        "layout": primary.get("layout"),
        "languages": primary.get("languages") or [],
        "engine": primary.get("engine"),
        "created_at": max(created_candidates) if created_candidates else None,
        "records": recs,
    }
    return unit, finding


def union_profile_registrations(
    snapshots: list[ProfileRegistrationsSnapshot],
) -> dict[str, Any]:
    """Union project registrations across all profile snapshots (§3, §13.1)."""
    by_path: dict[str, list[dict[str, Any]]] = {}
    all_records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED

    for snap in sorted(snapshots, key=lambda s: s.profile_name):
        if snap.coverage == COVERAGE_COULD_NOT_VERIFY:
            coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                make_finding(
                    rule_id="inventory.registration_db_unreadable",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[snap.profile_name],
                    source_paths=[snap.db_path],
                    evidence={
                        "profile": snap.profile_name,
                        "db_path": snap.db_path,
                        "error": snap.error or "unreadable plugin state.db",
                    },
                    consequence=f"Could not read project registrations for profile {snap.profile_name!r}.",
                    limitations="Projects registered only in this profile could not be inventoried.",
                )
            )
        for rec in snap.records:
            all_records.append(rec)
            by_path.setdefault(str(rec["canonical_path"]), []).append(rec)

    units: list[dict[str, Any]] = []
    for cpath in sorted(by_path.keys()):
        unit, finding = _build_project_unit(cpath, by_path[cpath])
        if finding is not None:
            findings.append(finding)
        units.append(unit)

    return {
        "coverage": coverage,
        "all_records": all_records,
        "project_units": units,
        "findings": findings,
    }
