"""Safe auto-save SQLite state store with monotonic sequence guards.

Provides a standalone, dependency-free key-value state store backed by SQLite in
WAL mode (plus optional atomic JSON file snapshots). Each write carries a
monotonic sequence number (`seq`) per `(namespace, key)` and only updates the
stored record when `seq > old_seq`, preventing out-of-order or duplicate writes
from clobbering newer state during rapid UI interactions.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS safe_state (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    seq INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


class SafeStateError(RuntimeError):
    """Raised when a safe state store argument or operation is invalid."""


# SQLite INTEGER is a signed 64-bit value; larger seq values cannot be stored.
MAX_SEQ = 2**63 - 1


def _validate_token(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SafeStateError(f"{label} must be a non-empty string")
    return value.strip()


def _validate_seq(seq: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise SafeStateError(f"seq must be a positive integer (>= 1), got {_short_repr(seq)}")
    if seq > MAX_SEQ:
        raise SafeStateError(f"seq must be at most {MAX_SEQ}")
    return seq


def _short_repr(value: Any) -> str:
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001
        text = f"<{type(value).__name__}>"
    return text if len(text) <= 64 else text[:61] + "..."


def _encode_value(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True)
    except RecursionError as exc:
        raise SafeStateError("value is nested too deeply to store") from exc
    except (TypeError, ValueError) as exc:
        raise SafeStateError(f"value is not JSON-serializable: {exc}") from exc


def _decode_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return raw


def _ensure_parent_dirs(target: Path) -> Path:
    resolved = Path(os.path.expanduser(os.fspath(target)))
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _connect(db_path: os.PathLike | str) -> sqlite3.Connection:
    target = _ensure_parent_dirs(Path(db_path))
    conn = sqlite3.connect(str(target), timeout=30.0)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(_SCHEMA_SQL)
    except BaseException:
        conn.close()
        raise
    return conn


def _row_to_entry(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "namespace": str(row["namespace"]),
        "key": str(row["key"]),
        "value": _decode_value(str(row["value_json"])),
        "seq": int(row["seq"]),
        "updated_at": float(row["updated_at"]),
    }


def _upsert_entry(
    *,
    conn: sqlite3.Connection,
    ns: str,
    k: str,
    payload: str,
    s: int,
    ts: float,
) -> bool:
    """Return True only if the sequence guard allowed an insert or update."""
    cur = conn.execute(
        """
        INSERT INTO safe_state (namespace, key, value_json, seq, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(namespace, key) DO UPDATE SET
            value_json = excluded.value_json,
            seq = excluded.seq,
            updated_at = excluded.updated_at
        WHERE excluded.seq > safe_state.seq
        """,
        (ns, k, payload, s, ts),
    )
    return (cur.rowcount or 0) > 0


def _select_entry(conn: sqlite3.Connection, ns: str, k: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT namespace, key, value_json, seq, updated_at FROM safe_state WHERE namespace = ? AND key = ?",
        (ns, k),
    ).fetchone()


def save_state(
    db_path: os.PathLike | str,
    namespace: str,
    key: str,
    value: Any,
    seq: int,
    *,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Persist `(namespace, key, value, seq)` only if `seq > old_seq`.

    Returns a dict with:
    - `applied`: True if the row was inserted or updated, False if rejected as stale/duplicate.
    - `namespace`, `key`, `value`, `seq`, `updated_at`: current authoritative record in the DB.
    """
    ns = _validate_token(namespace, "namespace")
    k = _validate_token(key, "key")
    s = _validate_seq(seq)
    payload = _encode_value(value)
    ts = float(time.time() if now is None else now)

    with closing(_connect(db_path)) as conn:
        with conn:
            applied = _upsert_entry(conn=conn, ns=ns, k=k, payload=payload, s=s, ts=ts)
            row = _select_entry(conn, ns, k)

    if row is None:
        return {
            "applied": applied,
            "namespace": ns,
            "key": k,
            "value": _decode_value(payload),
            "seq": s,
            "updated_at": ts,
        }
    out = _row_to_entry(row)
    out["applied"] = applied
    return out


def save_batch(
    db_path: os.PathLike | str,
    items: Iterable[Mapping[str, Any] | Tuple[str, str, Any, int]],
    *,
    now: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Apply a batch of state updates in a single transaction, enforcing `seq > old_seq` per item."""
    prepared: List[Tuple[str, str, str, int, float]] = []
    default_ts = float(time.time() if now is None else now)
    for item in items:
        if isinstance(item, Mapping):
            ns = _validate_token(str(item.get("namespace", "")), "namespace")
            k = _validate_token(str(item.get("key", "")), "key")
            s = _validate_seq(item.get("seq"))  # type: ignore[arg-type]
            val = item.get("value")
            ts = float(item.get("updated_at", default_ts))
        elif isinstance(item, (tuple, list)) and len(item) == 4:
            ns = _validate_token(str(item[0]), "namespace")
            k = _validate_token(str(item[1]), "key")
            val = item[2]
            s = _validate_seq(item[3])
            ts = default_ts
        else:
            raise SafeStateError(f"Invalid batch item: {item!r}")
        prepared.append((ns, k, _encode_value(val), s, ts))

    results: List[Dict[str, Any]] = []
    with closing(_connect(db_path)) as conn:
        with conn:
            for ns, k, payload, s, ts in prepared:
                applied = _upsert_entry(conn=conn, ns=ns, k=k, payload=payload, s=s, ts=ts)
                row = _select_entry(conn, ns, k)
                assert row is not None
                entry = _row_to_entry(row)
                entry["applied"] = applied
                results.append(entry)
    return results


def get_entry(
    db_path: os.PathLike | str,
    namespace: str,
    key: str,
) -> Optional[Dict[str, Any]]:
    """Return the full `{namespace, key, value, seq, updated_at}` record, or None if absent."""
    ns = _validate_token(namespace, "namespace")
    k = _validate_token(key, "key")
    target = Path(os.path.expanduser(os.fspath(db_path)))
    if not target.exists():
        return None
    with closing(_connect(target)) as conn:
        row = _select_entry(conn, ns, k)
    if row is None:
        return None
    return _row_to_entry(row)


def get_state(
    db_path: os.PathLike | str,
    namespace: str,
    key: str,
    default: Any = None,
) -> Any:
    """Return the decoded value for `(namespace, key)`, or `default` if absent."""
    entry = get_entry(db_path, namespace, key)
    if entry is None:
        return default
    return entry["value"]


def list_namespace(
    db_path: os.PathLike | str,
    namespace: str,
) -> Dict[str, Dict[str, Any]]:
    """Return all entries in `namespace` keyed by `key`."""
    ns = _validate_token(namespace, "namespace")
    target = Path(os.path.expanduser(os.fspath(db_path)))
    if not target.exists():
        return {}
    with closing(_connect(target)) as conn:
        rows = conn.execute(
            "SELECT namespace, key, value_json, seq, updated_at FROM safe_state WHERE namespace = ? ORDER BY key ASC",
            (ns,),
        ).fetchall()
    return {str(r["key"]): _row_to_entry(r) for r in rows}


def delete_state(
    db_path: os.PathLike | str,
    namespace: str,
    key: str,
    *,
    min_seq: Optional[int] = None,
) -> bool:
    """Delete `(namespace, key)` if present (and if `min_seq` is given, only when `min_seq > seq`)."""
    ns = _validate_token(namespace, "namespace")
    k = _validate_token(key, "key")
    s = _validate_seq(min_seq) if min_seq is not None else None
    target = Path(os.path.expanduser(os.fspath(db_path)))
    if not target.exists():
        return False
    with closing(_connect(target)) as conn:
        with conn:
            if s is not None:
                cur = conn.execute(
                    "DELETE FROM safe_state WHERE namespace = ? AND key = ? AND seq < ?",
                    (ns, k, s),
                )
            else:
                cur = conn.execute(
                    "DELETE FROM safe_state WHERE namespace = ? AND key = ?",
                    (ns, k),
                )
            return (cur.rowcount or 0) > 0


def sync_wal(
    db_path: os.PathLike | str,
    mode: str = "PASSIVE",
) -> Tuple[int, int, int]:
    """Run `PRAGMA wal_checkpoint(<mode>)` on `db_path` and return `(busy, log, checkpointed)`."""
    allowed = {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}
    norm_mode = (mode or "PASSIVE").strip().upper()
    if norm_mode not in allowed:
        raise SafeStateError(f"Invalid WAL checkpoint mode {mode!r}; expected one of {sorted(allowed)}")
    with closing(_connect(db_path)) as conn:
        row = conn.execute(f"PRAGMA wal_checkpoint({norm_mode})").fetchone()
    if row is None:
        return (0, 0, 0)
    return (int(row[0]), int(row[1]), int(row[2]))


def atomic_write_json(
    target_path: os.PathLike | str,
    data: Any,
    *,
    mode: int = 0o600,
) -> Path:
    """Atomically write JSON `data` to `target_path` via a temp file + `fsync` + `os.replace`."""
    target = _ensure_parent_dirs(Path(target_path))
    if os.path.islink(target):
        raise SafeStateError(f"Refusing to overwrite symlink at {target}")
    encoded = (_encode_value(data) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, str(target))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


class SafeStateStore:
    """Object-oriented wrapper around a `safe_state` SQLite database with optional coalescing buffer."""

    def __init__(
        self,
        db_path: os.PathLike | str,
        *,
        default_namespace: str = "default",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db_path = Path(os.path.expanduser(os.fspath(db_path)))
        self.default_namespace = _validate_token(default_namespace, "default_namespace")
        self._clock = clock
        self._lock = threading.Lock()
        self._seq_counters: Dict[Tuple[str, str], int] = {}
        self._pending: Dict[Tuple[str, str], Tuple[Any, int, float]] = {}

    def next_seq(self, key: str, *, namespace: Optional[str] = None) -> int:
        """Return the next monotonic sequence number for `(namespace, key)`."""
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        k = _validate_token(key, "key")
        pair = (ns, k)
        with self._lock:
            current = self._seq_counters.get(pair)
            if current is None:
                existing = get_entry(self.db_path, ns, k)
                current = int(existing["seq"]) if existing is not None else 0
            nxt = current + 1
            if nxt > MAX_SEQ:
                raise SafeStateError(f"seq for {k!r} has reached its limit of {MAX_SEQ}")
            self._seq_counters[pair] = nxt
            return nxt

    def save(
        self,
        key: str,
        value: Any,
        *,
        seq: Optional[int] = None,
        namespace: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Immediately persist `(namespace, key, value, seq)` with sequence guard."""
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        k = _validate_token(key, "key")
        effective_seq = _validate_seq(seq) if seq is not None else self.next_seq(k, namespace=ns)
        with self._lock:
            prev = self._seq_counters.get((ns, k), 0)
            if effective_seq > prev:
                self._seq_counters[(ns, k)] = effective_seq
            pending = self._pending.get((ns, k))
            if pending is not None and pending[1] <= effective_seq:
                self._pending.pop((ns, k), None)
        return save_state(
            self.db_path,
            ns,
            k,
            value,
            effective_seq,
            now=self._clock() if now is None else now,
        )

    def stage(
        self,
        key: str,
        value: Any,
        *,
        seq: Optional[int] = None,
        namespace: Optional[str] = None,
        now: Optional[float] = None,
    ) -> int:
        """Coalesce an update in memory until `flush()` is called; returns the assigned `seq`."""
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        k = _validate_token(key, "key")
        _encode_value(value)  # validate JSON serializability up front
        effective_seq = _validate_seq(seq) if seq is not None else self.next_seq(k, namespace=ns)
        ts = float(self._clock() if now is None else now)
        pair = (ns, k)
        with self._lock:
            prev_counter = self._seq_counters.get(pair, 0)
            if effective_seq > prev_counter:
                self._seq_counters[pair] = effective_seq
            existing_pending = self._pending.get(pair)
            if existing_pending is None or effective_seq > existing_pending[1]:
                self._pending[pair] = (value, effective_seq, ts)
        return effective_seq

    def flush(self) -> List[Dict[str, Any]]:
        """Flush all staged updates to SQLite in a single transaction."""
        with self._lock:
            if not self._pending:
                return []
            items = [
                {
                    "namespace": ns,
                    "key": k,
                    "value": val,
                    "seq": seq,
                    "updated_at": ts,
                }
                for (ns, k), (val, seq, ts) in self._pending.items()
            ]
            self._pending.clear()
        return save_batch(self.db_path, items)

    def get(self, key: str, default: Any = None, *, namespace: Optional[str] = None) -> Any:
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        return get_state(self.db_path, ns, key, default=default)

    def get_entry(self, key: str, *, namespace: Optional[str] = None) -> Optional[Dict[str, Any]]:
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        return get_entry(self.db_path, ns, key)

    def list(self, *, namespace: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        return list_namespace(self.db_path, ns)

    def delete(
        self,
        key: str,
        *,
        namespace: Optional[str] = None,
        min_seq: Optional[int] = None,
    ) -> bool:
        ns = _validate_token(namespace or self.default_namespace, "namespace")
        k = _validate_token(key, "key")
        with self._lock:
            self._pending.pop((ns, k), None)
        return delete_state(self.db_path, ns, k, min_seq=min_seq)

    def sync_wal(self, mode: str = "PASSIVE") -> Tuple[int, int, int]:
        self.flush()
        return sync_wal(self.db_path, mode=mode)
