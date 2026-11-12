"""SQLite state store for defuzz projects, questionnaire answers, and template options."""

from __future__ import annotations

try:
    import fcntl
except ImportError:  # Windows and other platforms without POSIX flock.
    fcntl = None
import hashlib
import json
import logging
import math
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Mapping
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Optional

from plugins.plugin_storage import plugin_data_dir


_LOG = logging.getLogger(__name__)

# Destructive cleanup requires every primitive used by the pinned-FD verifier.
_SAFE_MIGRATION_CLEANUP = (
    fcntl is not None and hasattr(fcntl, 'flock')
    and all(hasattr(os, flag) for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'))
    and {os.open, os.stat, os.unlink, os.rmdir} <= getattr(os, 'supports_dir_fd', set())
    and os.listdir in getattr(os, 'supports_fd', set())
    and os.stat in getattr(os, 'supports_follow_symlinks', set())
)


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    path TEXT PRIMARY KEY,
    name TEXT,
    slug TEXT,
    template_id TEXT,
    kind TEXT,
    layout TEXT,
    languages TEXT,
    engine TEXT,
    created_at INTEGER,
    hermes_project_id TEXT,
    rules_hash TEXT,
    plugin_commit TEXT,
    prefix TEXT,
    locked_hashes TEXT, trust_mode TEXT
);

CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER,
    answers_json TEXT,
    project_path TEXT NULL
);

CREATE TABLE IF NOT EXISTS template_options (
    template_id TEXT NOT NULL,
    option_id TEXT NOT NULL,
    choice TEXT NOT NULL,
    chosen_at INTEGER NOT NULL,
    PRIMARY KEY (template_id, option_id)
);
"""


_PROVENANCE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("rules_hash", "TEXT"),
    ("plugin_commit", "TEXT"),
    ("prefix", "TEXT"),
    ("locked_hashes", "TEXT"), ("trust_mode", "TEXT"),
)


class StateDirNotWritable(RuntimeError):
    """Raised when the profile's defuzz data folder cannot be created or written."""

    def __init__(self, folder: Path | str) -> None:
        self.folder = str(folder)
        super().__init__(f"cannot save defuzz state: the folder {self.folder} is not writable")


def _state_dir_hint() -> str:
    try:
        from hermes_constants import get_hermes_home

        return str(Path(get_hermes_home()) / "plugin-data" / "defuzz")
    except Exception:  # noqa: BLE001 - only used to name the folder in a message
        return "<Hermes home>/plugin-data/defuzz"


def state_db_path(ctx: Any = None) -> Path:
    """Resolve profile-local state through Hermes's public persistent-storage API.

    ``ctx`` remains accepted for callers; profile routing belongs to Hermes.
    Legacy state is backed up once, without altering the install directory.
    Raises StateDirNotWritable (one plain reason) when the folder cannot be written.
    """
    try:
        state_dir = plugin_data_dir("defuzz")
    except OSError as exc:
        raise StateDirNotWritable(_state_dir_hint()) from exc
    if not os.access(state_dir, os.W_OK | os.X_OK):
        raise StateDirNotWritable(state_dir)
    target = state_dir / "state.db"
    _migrate_legacy_state(target)
    return target


def _migrate_legacy_state(target: Path) -> None:
    if not _SAFE_MIGRATION_CLEANUP:
        # No lock or destructive cleanup. The checked backup is still published
        # with atomic, no-clobber link(); unsupported filesystems fail closed.
        _migrate_legacy_state_locked(target)
        return
    # A sweep never waits for an active migration. Migration itself waits so
    # callers cannot initialize an empty target while a backup is in flight.
    _sweep_migration_leftovers(target.parent)
    with _migration_lock(target.parent, blocking=True):
        _migrate_legacy_state_locked(target)


def _migrate_legacy_state_locked(target: Path) -> None:
    """Publish a checked SQLite backup without ever replacing existing state.

    The storage API's resolved profile is the sole source of legacy scope.
    Defuzz takes precedence over adopt-place when both databases exist; they
    are never merged. A marker records the selected source inside the backup.
    """
    if target.exists():
        return
    # Core plugins/plugin_storage.py uses <profile>/plugin_data/<name>/.
    home = target.parent.parent.parent.resolve()
    for name in ("defuzz", "adopt-place"):
        legacy = home / "plugins" / name / "state.db"
        # Check every component before following links, not just containment in
        # home: a default home's profiles/ subtree belongs to other profiles.
        # A link-free path confined to this exact plugin directory cannot enter
        # that subtree (and still permits an active named profile's own plugin).
        try:
            component = home
            for part in legacy.relative_to(home).parts:
                component = component / part
                identity = component.lstat()
                if stat.S_ISLNK(identity.st_mode):
                    raise ValueError("symlink component")
            if identity.st_nlink > 1:
                raise ValueError("hardlinked legacy file")
            resolved = legacy.resolve(strict=True)
            if not resolved.is_relative_to(legacy.parent.resolve(strict=True)):
                raise ValueError("outside active profile's legacy plugin directory")
            if not resolved.is_relative_to(home / 'plugins' / name):
                raise ValueError("outside active profile's legacy plugin directory")
        except FileNotFoundError:
            continue
        except (OSError, ValueError, RuntimeError) as exc:
            _LOG.warning("Skipping legacy state %s: %s", legacy, exc)
            continue
        if not resolved.is_file():
            continue
        temporary = None
        try:
            journal = Path(str(legacy) + "-journal")
            if journal.exists() and journal.stat().st_size:
                raise OSError("non-empty rollback journal; recover legacy database before migration")
            temporary = _create_artifact(target.parent, 'migration') / 'state.db'
            # SQLite's read-only WAL readers can still update shared-memory
            # read marks. Use a private, stability-checked DB/WAL snapshot so
            # neither existing sidecar bytes nor the legacy listing can change.
            with _migration_artifact(target.parent, 'source') as staging:
                wal = Path(str(legacy) + "-wal")
                source_path = legacy
                query = "?mode=ro&immutable=1"
                wal_identity = None
                if wal.exists() or wal.is_symlink():
                    wal_identity = wal.lstat()
                    if (not stat.S_ISREG(wal_identity.st_mode) or wal_identity.st_nlink > 1):
                        raise OSError("unsafe symlink or hardlinked legacy WAL")
                    source_path = Path(staging) / legacy.name
                    captured = {}
                    for path in (legacy, wal):
                        digest = hashlib.sha256()
                        with path.open("rb") as source, (Path(staging) / path.name).open("wb") as dest:
                            while chunk := source.read(1024 * 1024):
                                digest.update(chunk)
                                dest.write(chunk)
                        captured[path] = digest.digest()
                    if any(_file_digest(path) != digest for path, digest in captured.items()):
                        raise OSError("legacy WAL changed during snapshot; retry migration later")
                    query = "?mode=ro"
                _backup_legacy(source_path, query, temporary, legacy)
            if wal_identity is not None:
                current_wal = wal.lstat()
                if (not stat.S_ISREG(current_wal.st_mode) or current_wal.st_nlink > 1
                        or (current_wal.st_dev, current_wal.st_ino) !=
                        (wal_identity.st_dev, wal_identity.st_ino)):
                    raise OSError("legacy WAL identity changed during backup")
            current = legacy.lstat()
            if ((current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
                    or current.st_nlink > 1):
                raise OSError("legacy identity changed during backup")
            try:
                # Atomic no-clobber publication, even with concurrent first opens.
                os.link(temporary, target)
            except FileExistsError:
                return
            except OSError as exc:
                _LOG.warning("Cannot publish legacy state atomically %s: %s; "
                             "legacy preserved; migrate manually on a hardlink-capable filesystem", legacy, exc)
                return
            _write_migration_marker(target, legacy)
            return
        except (sqlite3.Error, OSError) as exc:
            _LOG.warning("Skipping legacy state %s: %s", legacy, exc)
        finally:
            if temporary is not None:
                _remove_artifact(temporary.parent, cutoff=float('inf'))


def _file_digest(path: Path) -> bytes:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").digest()


_ARTIFACT_MANIFEST = '.defuzz-artifact.json'
_ARTIFACT_FILES = {
    'source': {'state.db', 'state.db-wal', 'state.db-shm'},
    'migration': {'state.db', 'state.db-journal', 'state.db-wal', 'state.db-shm'},
    'marker': {'marker.json'},
}


def _create_artifact(directory: Path, kind: str) -> Path:
    nonce = uuid.uuid4().hex
    path = directory / f'.state-{kind}-{nonce}'
    path.mkdir(mode=0o700)
    with (path / _ARTIFACT_MANIFEST).open('x', encoding='utf-8') as stream:
        json.dump({'kind': kind, 'created_by': 'defuzz-state-migration',
                   'nonce': nonce, 'pid': os.getpid(), 'created_at': time.time()}, stream)
    return path


@contextmanager
def _migration_artifact(directory: Path, kind: str):
    """The caller holds the migration lock through creation and cleanup."""
    path = _create_artifact(directory, kind)
    try:
        yield path
    finally:
        _remove_artifact(path, cutoff=float('inf'))


def _remove_artifact(path: Path, *, cutoff: float) -> None:
    """Fail closed; inspect relative to pinned directory FDs, never recurse."""
    if not _SAFE_MIGRATION_CLEANUP:
        return
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    artifact_fd = None
    try:
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('not an artifact directory')
        artifact_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        opened = os.fstat(artifact_fd)
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('artifact identity changed')
        names = set(os.listdir(artifact_fd))
        identities = {}
        for name in names:
            child = os.stat(name, dir_fd=artifact_fd, follow_symlinks=False)
            if not stat.S_ISREG(child.st_mode):
                raise ValueError('non-regular artifact entry')
            identities[name] = (child.st_dev, child.st_ino)
        fd = os.open(_ARTIFACT_MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=artifact_fd)
        with os.fdopen(fd, 'r') as stream:
            manifest_info = os.fstat(stream.fileno())
            if not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_size > 4096:
                raise ValueError('invalid manifest file')
            manifest = json.loads(stream.read(4097))
        if not isinstance(manifest, dict) or set(manifest) != {'kind', 'created_by', 'nonce', 'pid', 'created_at'}:
            raise ValueError('invalid manifest structure')
        kind = manifest['kind']
        nonce = manifest['nonce']
        if (not isinstance(kind, str) or kind not in _ARTIFACT_FILES
                or not isinstance(nonce, str) or len(nonce) != 32
                or any(c not in '0123456789abcdef' for c in nonce)
                or path.name != f'.state-{kind}-{nonce}'
                or manifest['created_by'] != 'defuzz-state-migration'
                or type(manifest['pid']) is not int or manifest['pid'] <= 0
                or type(manifest['created_at']) not in (int, float)
                or not math.isfinite(manifest['created_at']) or manifest['created_at'] <= 0
                or not names <= _ARTIFACT_FILES[kind] | {_ARTIFACT_MANIFEST}):
            raise ValueError('unverified ownership or contents')
        if manifest['created_at'] >= cutoff or info.st_mtime >= cutoff:
            return
        # Check every entry before deleting any. unlink cannot follow a link
        # substituted after this check, and rmdir cannot remove added contents.
        for name, identity in identities.items():
            child = os.stat(name, dir_fd=artifact_fd, follow_symlinks=False)
            if not stat.S_ISREG(child.st_mode) or (child.st_dev, child.st_ino) != identity:
                raise ValueError('artifact entry changed')
        for name in sorted(names - {_ARTIFACT_MANIFEST}):
            os.unlink(name, dir_fd=artifact_fd)
        os.unlink(_ARTIFACT_MANIFEST, dir_fd=artifact_fd)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('artifact directory replaced')
        os.rmdir(path.name, dir_fd=parent_fd)
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        _LOG.debug('Leaving unverified migration artifact %s: %s', path, exc)
    finally:
        if artifact_fd is not None:
            os.close(artifact_fd)
        os.close(parent_fd)


@contextmanager
def _migration_lock(directory: Path, *, blocking: bool):
    if not _SAFE_MIGRATION_CLEANUP or fcntl is None:
        yield False
        return
    # Never unlink the lock: waiters must continue to coordinate on one inode.
    fd = os.open(directory / '.state-migration.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError('unsafe migration lock file')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
        else:
            try:
                yield True
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _sweep_migration_leftovers(directory: Path) -> None:
    if not _SAFE_MIGRATION_CLEANUP:
        return
    try:
        with _migration_lock(directory, blocking=False) as acquired:
            if acquired:
                _sweep_migration_leftovers_locked(directory)
            else:
                _LOG.debug('Skipping migration sweep: migration lock busy')
    except OSError as exc:
        _LOG.debug('Skipping migration sweep: %s', exc)


def _sweep_migration_leftovers_locked(directory: Path) -> None:
    cutoff = time.time() - 3600
    for kind in _ARTIFACT_FILES:
        for path in directory.glob(f'.state-{kind}-*'):
            _remove_artifact(path, cutoff=cutoff)


def _write_migration_marker(target: Path, legacy: Path) -> None:
    try:
        with _migration_artifact(target.parent, 'marker') as artifact:
            temporary = artifact / 'marker.json'
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump({"source": str(legacy), "method": "sqlite3.backup"}, stream)
                stream.write("\n")
            os.replace(temporary, target.with_suffix(".migration.json"))
    except OSError as exc:
        _LOG.warning("Legacy state migrated but marker could not be written: %s", exc)


def _backup_legacy(source_path: Path, query: str, temporary: Path, legacy: Path) -> None:
    with closing(sqlite3.connect(source_path.as_uri() + query, uri=True)) as source:
        with closing(sqlite3.connect(temporary)) as backup:
            source.backup(backup)
            if backup.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise sqlite3.DatabaseError("integrity_check failed")
            backup.execute("CREATE TABLE IF NOT EXISTS defuzz_migrations (source TEXT PRIMARY KEY)")
            backup.execute("INSERT OR IGNORE INTO defuzz_migrations VALUES (?)", (str(legacy),))
            backup.commit()


def _resolve_db_path(db_path: Optional[Path | str] = None, *, ctx: Any = None) -> Path:
    """Resolve db_path (or default state_db_path) and ensure parent directories exist."""
    target = Path(db_path).expanduser() if db_path is not None else state_db_path(ctx=ctx)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _connect(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    """Open a SQLite connection and initialize the schema on first use."""
    target = _resolve_db_path(db_path)
    conn = sqlite3.connect(str(target))
    try:
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA_SQL)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(projects)").fetchall()}
        if cols:
            for col_name, col_type in _PROVENANCE_COLUMNS:
                if col_name not in cols:
                    conn.execute(f"ALTER TABLE projects ADD COLUMN {col_name} {col_type}")
    except BaseException:
        conn.close()
        raise
    return conn


def _existing_db_path(db_path: Optional[Path | str] = None) -> Path:
    """Resolve a state DB path without creating folders or migrating legacy state."""
    if db_path is not None:
        target = Path(db_path).expanduser()
    else:
        try:
            from hermes_constants import get_hermes_home

            target = Path(get_hermes_home()) / "plugin-data" / "defuzz" / "state.db"
        except Exception:  # noqa: BLE001 - fall back to the documented default folder
            target = Path(_state_dir_hint()) / "state.db"
    return Path(os.path.abspath(target))


def _connect_existing(db_path: Optional[Path | str] = None) -> Optional[sqlite3.Connection]:
    """Open only an already-existing state DB, read/write, with no schema work.

    ``mode=rw`` makes SQLite refuse to create the file, and nothing here runs the
    schema script or provenance migrations. Callers that only need to delete an
    exact row therefore cannot conjure a profile folder, database or lock, and cannot
    add columns to a legacy schema they are merely cleaning up.
    """
    target = _existing_db_path(db_path)
    if not target.is_file():
        return None
    try:
        conn = sqlite3.connect(target.as_uri() + "?mode=rw", uri=True)
    except sqlite3.OperationalError:
        if not target.exists():
            return None
        raise
    conn.row_factory = sqlite3.Row
    return conn


def _normalize_path_key(path: Path | str) -> str:
    """Convert a project path to a consistent resolved string key."""
    return str(Path(path).expanduser().resolve())


def _optional_column(row: sqlite3.Row, row_keys: set[str], name: str) -> Any:
    """Legacy schemas may predate the provenance columns."""
    return row[name] if name in row_keys else None


def _row_to_project_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a projects table row into a dictionary with parsed languages list."""
    row_keys = set(row.keys())
    raw_langs = row["languages"]
    try:
        parsed_langs = json.loads(raw_langs) if raw_langs else []
    except Exception:
        parsed_langs = []
    if not isinstance(parsed_langs, list):
        parsed_langs = [str(parsed_langs)]

    raw_locked = _optional_column(row, row_keys, "locked_hashes")
    parsed_locked: Optional[dict[str, str]] = None
    if raw_locked is not None:
        try:
            loaded = json.loads(raw_locked)
            if isinstance(loaded, dict):
                parsed_locked = {
                    str(k): str(v) for k, v in loaded.items() if isinstance(k, str) and isinstance(v, str)
                }
        except Exception:
            parsed_locked = None

    return {
        "path": row["path"],
        "name": row["name"],
        "slug": row["slug"],
        "template_id": row["template_id"],
        "kind": row["kind"],
        "layout": row["layout"],
        "languages": parsed_langs,
        "engine": row["engine"],
        "created_at": row["created_at"],
        "hermes_project_id": row["hermes_project_id"],
        "rules_hash": _optional_column(row, row_keys, "rules_hash"),
        "plugin_commit": _optional_column(row, row_keys, "plugin_commit"),
        "prefix": _optional_column(row, row_keys, "prefix"),
        "locked_hashes": parsed_locked,
        "trust_mode": _optional_column(row, row_keys, "trust_mode"),
    }


def save_answers(
    answers: dict[str, Any],
    project_path: Optional[Path | str] = None,
    db_path: Optional[Path | str] = None,
) -> int:
    """Persist questionnaire answers as JSON and return the inserted row id."""
    proj_str = _normalize_path_key(project_path) if project_path is not None else None
    payload = json.dumps(answers, sort_keys=True)
    now = int(time.time())
    with closing(_connect(db_path)) as conn:
        with conn:
            cur = conn.execute(
                "INSERT INTO answers (created_at, answers_json, project_path) VALUES (?, ?, ?)",
                (now, payload, proj_str),
            )
            return int(cur.lastrowid or 0)


_UPSERT_TEMPLATE_OPTION_SQL = """
INSERT INTO template_options (template_id, option_id, choice, chosen_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(template_id, option_id) DO UPDATE SET
    choice = excluded.choice,
    chosen_at = excluded.chosen_at
"""


def _require_nonempty(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


def _template_option_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "template_id": row["template_id"],
        "option_id": row["option_id"],
        "choice": row["choice"],
        "chosen_at": row["chosen_at"],
    }


def _state_db_missing(db_path: Path | str | None) -> bool:
    """Readers return empty results instead of creating a DB that does not exist yet."""
    target = Path(db_path).expanduser() if db_path is not None else state_db_path()
    return not target.is_file()


def record_template_option(
    template_id: str,
    option_id: str,
    choice: str,
    db_path: Optional[Path | str] = None,
    *,
    chosen_at: Optional[int] = None,
) -> None:
    """Record or update a chosen template option in the template_options table."""
    _require_nonempty(template_id, "template_id")
    _require_nonempty(option_id, "option_id")
    _require_nonempty(choice, "choice")
    ts = int(chosen_at) if chosen_at is not None else int(time.time())
    with closing(_connect(db_path)) as conn:
        with conn:
            conn.execute(
                _UPSERT_TEMPLATE_OPTION_SQL,
                (template_id.strip(), option_id.strip(), choice.strip(), ts),
            )


save_template_option = record_template_option
set_template_option = record_template_option


def record_template_options(
    template_id: str,
    options: Mapping[str, str],
    db_path: Optional[Path | str] = None,
    *,
    chosen_at: Optional[int] = None,
) -> None:
    """Record multiple option choices for a template in a single transaction."""
    if not options:
        return
    _require_nonempty(template_id, "template_id")
    ts = int(chosen_at) if chosen_at is not None else int(time.time())
    rows: list[tuple[str, str, str, int]] = []
    for opt_id, choice in options.items():
        _require_nonempty(opt_id, "option_id")
        _require_nonempty(choice, "choice")
        rows.append((template_id.strip(), opt_id.strip(), choice.strip(), ts))
    with closing(_connect(db_path)) as conn:
        with conn:
            conn.executemany(
                _UPSERT_TEMPLATE_OPTION_SQL,
                rows,
            )


save_template_options = record_template_options


def get_template_option(
    template_id: str,
    option_id: str,
    db_path: Optional[Path | str] = None,
) -> Optional[dict[str, Any]]:
    """Return the recorded template_options row dict for (template_id, option_id), or None."""
    if _state_db_missing(db_path):
        return None
    with closing(_connect(db_path)) as conn:
        row = conn.execute(
            """
            SELECT template_id, option_id, choice, chosen_at
            FROM template_options
            WHERE template_id = ? AND option_id = ?
            """,
            (template_id, option_id),
        ).fetchone()
    if row is None:
        return None
    return _template_option_dict(row)


def get_template_options(
    template_id: str,
    db_path: Optional[Path | str] = None,
) -> dict[str, str]:
    """Return all recorded {option_id: choice} picks for template_id."""
    if _state_db_missing(db_path):
        return {}
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT option_id, choice
            FROM template_options
            WHERE template_id = ?
            ORDER BY option_id ASC
            """,
            (template_id,),
        ).fetchall()
    return {str(r["option_id"]): str(r["choice"]) for r in rows}


def list_template_options(
    template_id: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> list[dict[str, Any]]:
    """Return recorded template_options rows ordered by template_id, option_id."""
    if _state_db_missing(db_path):
        return []
    with closing(_connect(db_path)) as conn:
        if template_id is not None:
            rows = conn.execute(
                """
                SELECT template_id, option_id, choice, chosen_at
                FROM template_options
                WHERE template_id = ?
                ORDER BY template_id ASC, option_id ASC
                """,
                (template_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT template_id, option_id, choice, chosen_at
                FROM template_options
                ORDER BY template_id ASC, option_id ASC
                """
            ).fetchall()
    return [_template_option_dict(r) for r in rows]


def _optional_str(value: Any) -> str | None:
    return str(value) if value is not None else None


def record_project(
    path: Path | str,
    name: str,
    slug: str,
    template_id: Optional[str],
    answers: dict[str, Any],
    hermes_project_id: Optional[str],
    db_path: Optional[Path | str] = None,
    rules_hash: Optional[str] = None,
    *,
    plugin_commit: Optional[str] = None,
    prefix: Optional[str] = None,
    locked_hashes: Optional[dict[str, str]] = None,
    trust_mode: Optional[str] = None,
) -> None:
    """Insert or replace a scaffolded or adopted project record in the state DB."""
    if trust_mode is not None and trust_mode not in ("full", "declared_only"):
        raise ValueError(f"Invalid trust_mode: {trust_mode!r}")
    proj_str = _normalize_path_key(path)
    kind = answers.get("building") or answers.get("kind")
    layout = answers.get("layout")
    raw_langs = answers.get("languages", [])
    if isinstance(raw_langs, (list, tuple)):
        langs_list = [str(x) for x in raw_langs]
    elif isinstance(raw_langs, str):
        langs_list = [raw_langs]
    else:
        langs_list = []
    engine = answers.get("engine")
    now = int(time.time())
    locked_hashes_json: Optional[str] = (
        json.dumps(
            {str(k): str(v) for k, v in sorted(locked_hashes.items())},
            sort_keys=True,
        )
        if locked_hashes is not None
        else None
    )

    with closing(_connect(db_path)) as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO projects (
                    path, name, slug, template_id, kind, layout,
                    languages, engine, created_at, hermes_project_id, rules_hash,
                    plugin_commit, prefix, locked_hashes, trust_mode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    name = excluded.name,
                    slug = excluded.slug,
                    template_id = excluded.template_id,
                    kind = excluded.kind,
                    layout = excluded.layout,
                    languages = excluded.languages,
                    engine = excluded.engine,
                    hermes_project_id = excluded.hermes_project_id,
                    rules_hash = COALESCE(excluded.rules_hash, projects.rules_hash),
                    plugin_commit = COALESCE(excluded.plugin_commit, projects.plugin_commit),
                    prefix = COALESCE(excluded.prefix, projects.prefix),
                    locked_hashes = COALESCE(excluded.locked_hashes, projects.locked_hashes),
                    trust_mode = COALESCE(excluded.trust_mode, projects.trust_mode)
                """,
                (
                    proj_str,
                    name,
                    slug,
                    template_id,
                    _optional_str(kind),
                    _optional_str(layout),
                    json.dumps(langs_list),
                    _optional_str(engine),
                    now,
                    hermes_project_id,
                    rules_hash,
                    _optional_str(plugin_commit),
                    _optional_str(prefix),
                    locked_hashes_json,
                    trust_mode,
                ),
            )


def update_rules_hash(
    path: Path | str,
    rules_hash: str,
    db_path: Optional[Path | str] = None,
) -> None:
    """Update the recorded .adopt/rules.json SHA-256 hash for a registered project."""
    proj_str = _normalize_path_key(path)
    with closing(_connect(db_path)) as conn:
        with conn:
            cur = conn.execute(
                "UPDATE projects SET rules_hash = ? WHERE path = ?",
                (rules_hash, proj_str),
            )
            if cur.rowcount == 0:
                raise KeyError(f"Project not registered in state DB: {proj_str}")


def get_project(
    path: Path | str,
    db_path: Optional[Path | str] = None,
) -> Optional[dict[str, Any]]:
    """Return the project dictionary for path, or None if not registered."""
    proj_str = _normalize_path_key(path)
    with closing(_connect(db_path)) as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE path = ?",
            (proj_str,),
        ).fetchone()
    if row is None:
        return None
    return _row_to_project_dict(row)


def list_projects(db_path: Optional[Path | str] = None) -> list[dict[str, Any]]:
    """Return all recorded projects ordered by created_at ascending, then path."""
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT * FROM projects ORDER BY created_at ASC, path ASC"
        ).fetchall()
    return [_row_to_project_dict(r) for r in rows]


def is_registered(
    path: Path | str,
    db_path: Optional[Path | str] = None,
) -> bool:
    """Return True if path exists in the projects table."""
    return get_project(path, db_path=db_path) is not None


# How a registered project folder looks right now. Only ``exists`` folders belong in the
# workspace listing; the other values are reported for records that are still registered.
PROJECT_FOLDER_EXISTS = "exists"
PROJECT_FOLDER_MISSING = "missing"
PROJECT_FOLDER_NOT_DIRECTORY = "not_directory"
PROJECT_FOLDER_UNAVAILABLE = "unavailable"
PROJECT_FOLDER_STATUSES: tuple[str, ...] = (
    PROJECT_FOLDER_MISSING,
    PROJECT_FOLDER_NOT_DIRECTORY,
    PROJECT_FOLDER_UNAVAILABLE,
)


def project_folder_status(path: Path | str | None) -> str:
    """Classify a registered project path with one read-only ``lstat``.

    No file is opened and this ``lstat`` does not follow a link. The caller normally
    supplies the registration's ``canonical_path`` (the resolved target), so a project
    folder reached through a symlink is intentionally classified as the existing
    canonical directory. A raw symlink string supplied instead of its canonical target is
    not itself a directory and classifies as ``not_directory``. A path that cannot be
    inspected (permissions, I/O error, relative or malformed record) is ``unavailable``,
    never ``missing``.
    """
    if not isinstance(path, (str, os.PathLike)):
        return PROJECT_FOLDER_UNAVAILABLE
    try:
        text = os.fspath(path)
    except TypeError:
        return PROJECT_FOLDER_UNAVAILABLE
    if not isinstance(text, str) or not text.strip() or "\x00" in text:
        return PROJECT_FOLDER_UNAVAILABLE
    expanded = os.path.expanduser(text)
    if not os.path.isabs(expanded):
        return PROJECT_FOLDER_UNAVAILABLE
    try:
        st = os.lstat(expanded)
    except FileNotFoundError:
        return PROJECT_FOLDER_MISSING
    except NotADirectoryError:
        return PROJECT_FOLDER_NOT_DIRECTORY
    except OSError:
        return PROJECT_FOLDER_UNAVAILABLE
    if stat.S_ISDIR(st.st_mode):
        return PROJECT_FOLDER_EXISTS
    # A raw symlink is not itself a project folder; callers pass canonical_path instead.
    return PROJECT_FOLDER_NOT_DIRECTORY


def split_registered_projects(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split registration records into existing folders and unavailable records.

    Classification prefers ``canonical_path`` (the intentionally resolved registration
    target), so an alias registration whose target is a real directory is listed as
    present while its distinct ``raw_path`` identity is preserved for exact deletion.
    The unavailable records are copies carrying ``folder_status``. Nothing is deleted:
    stale registrations stay in the DB (the audit reader still reports them) until an
    explicit forget request removes the registration.
    """
    present: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        candidate = record.get("canonical_path") or record.get("raw_path")
        status = project_folder_status(candidate)
        if status == PROJECT_FOLDER_EXISTS:
            present.append(dict(record))
        else:
            entry = dict(record)
            entry["folder_status"] = status
            unavailable.append(entry)
    return present, unavailable


def forget_project(
    path: str,
    db_path: Optional[Path | str] = None,
) -> bool:
    """Delete the registration whose stored ``path`` is exactly ``path``.

    The supplied string is the stored identifier, not a filesystem alias to resolve:
    it is compared verbatim (``DELETE ... WHERE path = ?``), so an alias, a canonical
    spelling, a trailing slash or a differently-normalised form selects a different row
    or no row at all. Any nonempty NUL-free string is accepted as a delete key, including
    legacy relative and ``~`` spellings; the string is never used as a filesystem path
    and no absolute-path check applies. Only the projects row is deleted. No file, folder
    or link is created, changed or removed. A missing state DB returns False without
    creating the profile folder, database, journal or lock, and an existing legacy schema
    is not initialized or migrated. Returns True when a row was deleted; repeating the
    call with the same string is a no-op returning False.
    """
    if not isinstance(path, str):
        raise ValueError("Project path must be a string")
    if not path:
        raise ValueError("Project path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("Project path is invalid")
    conn = _connect_existing(db_path)
    if conn is None:
        return False
    with closing(conn) as conn, conn:
        deleted = conn.execute("DELETE FROM projects WHERE path = ?", (path,)).rowcount
    return deleted > 0
