"""Versioned fingerprint manifest and safe descriptor-relative content reads (§4, §12).

Constraints enforced here:
- Safe content reads (§12 "Safe content reads and races"):
  - Content reads accept regular files only; symlinks are inventoried via `os.readlink`.
  - Never open FIFOs, sockets, devices, or other special files (`coverage="could_not_verify"`).
  - Root-anchored, descriptor-relative traversal (`dir_fd`, `O_NOFOLLOW`, `O_NONBLOCK`, `O_DIRECTORY`).
  - Pre/post-read stat identity comparison and explicit byte bounds (`DEFAULT_MAX_FILE_BYTES`).
- Versioned ownership manifest (§5, §12 "Profile ownership and totals"):
  - Distinguishes `config_match`, `profile_owned`, `shared_infrastructure`, and `unclassified`.
  - Prunes `profiles/` and descendant profile roots; tracks logical and deduplicated bytes.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from .contract import COVERAGE_COULD_NOT_VERIFY, COVERAGE_VERIFIED
from .key import content_digest
from .policy import credential_path, credential_verdict, has_declarations, note_credential_skip, opened_credential

FINGERPRINT_MANIFEST_VERSION = "2.0.0"
OWNERSHIP_MANIFEST_VERSION = "1.0.0"
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB explicit default bound
DEFAULT_MAX_DIR_ENTRIES = 20_000

# §5, §12: Profile ownership manifest categories at a profile root.
PROFILE_CONFIG_MATCH_ENTRIES: frozenset[str] = frozenset({
    "memories", "skills", "config.yaml", "SOUL.md",
})

PROFILE_OWNED_EXTRA_ENTRIES: frozenset[str] = frozenset({
    "MEMORY.md", "USER.md", "profile.yaml", "system_prompt.md", "AGENTS.md", "CLAUDE.md",
    ".cursorrules", "desktop.json", "todo.json", "sessions", "state.db", "state.db-wal",
    "state.db-shm", "cron", "plugins", "skins", "logs", "plans", "workspace", "home",
    "scripts", "knowledge", "preferences", "auth.json", ".env", ".op.env", "npmrc",
    ".anthropic_oauth.json", "google_token.json", "google_oauth_pending.json",
    "google_client_secret.json", "slack_tokens.json", "honcho.json", "mem0.json",
    "webhook_subscriptions.json", "teams_pipeline_store.json", "mcp-tokens", "vault",
    "pairing", "platforms", "whatsapp", "matrix", "weixin", "proxy",
})

PROFILE_OWNED_ROOT_ENTRIES: frozenset[str] = PROFILE_CONFIG_MATCH_ENTRIES | PROFILE_OWNED_EXTRA_ENTRIES

# Shared installation / runtime infrastructure at the default root (§12).
SHARED_INFRASTRUCTURE_ROOT_ENTRIES: frozenset[str] = frozenset({
    "hermes-agent", ".worktrees", "profiles", "bin", "node_modules", ".hermes-runtime",
    "node", "models", "runtimes", "installs", "tools", "cache", "backups",
    "state-snapshots", "checkpoints", "image_cache", "audio_cache", "document_cache",
    "browser_screenshots", "sandboxes", "venvs", "environments", "test-environment",
    "active_profile", ".update_check", ".managed", "gateway.pid", "gateway_state.json",
    "processes.json", "errors.log", ".hermes_history",
})

_PROFILE_EXCLUDED_DB_PATHS: frozenset[str] = frozenset({
    "plugin-data/defuzz/state.db",
    "plugin-data/defuzz/state.db-wal",
    "plugin-data/defuzz/state.db-shm",
    "plugin-data/defuzz/audit.db",
    "plugin-data/defuzz/audit.db-wal",
    "plugin-data/defuzz/audit.db-shm",
})


class ContainmentUnsupportedError(RuntimeError):
    """Raised when the platform/runtime lacks descriptor-relative `O_NOFOLLOW` containment."""


_SUPPORTS_OPEN_DIR_FD: bool = "open" in {fn.__name__ for fn in getattr(os, "supports_dir_fd", set())}  # wrap-proof


def _expand_abs_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _stat_identity_tuple(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _safe_read_result_with_stat(
    *,
    path: str,
    rel_path: str,
    kind: str,
    coverage: str,
    stable: bool,
    st: os.stat_result,
    size: int | None = None,
    content: bytes | None = None,
    sha256: str | None = None,
    symlink_target: str | None = None,
    bounded_exceeded: bool = False,
    error: str | None = None,
) -> SafeReadResult:
    return SafeReadResult(
        path=path,
        rel_path=rel_path,
        kind=kind,
        coverage=coverage,
        stable=stable,
        content=content,
        sha256=sha256,
        size=int(st.st_size) if size is None else size,
        symlink_target=symlink_target,
        dev=int(st.st_dev),
        ino=int(st.st_ino),
        nlink=int(st.st_nlink),
        mtime_ns=int(st.st_mtime_ns),
        ctime_ns=int(st.st_ctime_ns),
        bounded_exceeded=bounded_exceeded,
        error=error,
    )


def _json_content_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return content_digest(hashlib.sha256(encoded).hexdigest())


def _require_containment_support() -> tuple[int, int, int]:
    """Verify the OS supports descriptor-relative traversal (`dir_fd` + `O_NOFOLLOW`) (§12)."""
    if not _SUPPORTS_OPEN_DIR_FD:
        raise ContainmentUnsupportedError("os.open does not support dir_fd on this platform")
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not o_nofollow:
        raise ContainmentUnsupportedError("os.O_NOFOLLOW is not available on this platform")
    return o_nofollow, getattr(os, "O_NONBLOCK", 0), getattr(os, "O_DIRECTORY", 0)


def classify_mode(st_mode: int) -> str:
    """Return a stable string label for an inode mode."""
    if stat.S_ISREG(st_mode):
        return "regular"
    if stat.S_ISLNK(st_mode):
        return "symlink"
    if stat.S_ISDIR(st_mode):
        return "directory"
    if stat.S_ISFIFO(st_mode):
        return "fifo"
    if stat.S_ISSOCK(st_mode):
        return "socket"
    if stat.S_ISCHR(st_mode):
        return "char_device"
    if stat.S_ISBLK(st_mode):
        return "block_device"
    return "special"


@dataclass(frozen=True)
class SafeReadResult:
    """Result of a root-anchored, race-checked file or metadata read (§12)."""

    path: str
    rel_path: str
    kind: str
    coverage: str
    stable: bool
    content: bytes | None = None
    sha256: str | None = None
    size: int | None = None
    symlink_target: str | None = None
    dev: int | None = None
    ino: int | None = None
    nlink: int | None = None
    mtime_ns: int | None = None
    ctime_ns: int | None = None
    bounded_exceeded: bool = False
    error: str | None = None

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "path": self.path,
            "rel_path": self.rel_path,
            "kind": self.kind,
            "coverage": self.coverage,
            "stable": self.stable,
            "sha256": self.sha256,
            "size": self.size,
            "symlink_target": self.symlink_target,
            "dev": self.dev,
            "ino": self.ino,
            "nlink": self.nlink,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "bounded_exceeded": self.bounded_exceeded,
            "error": self.error,
        }
        if include_content and self.content is not None:
            out["content_utf8"] = self.content.decode("utf-8", errors="replace")
        return out


@contextlib.contextmanager
def _open_root_dir_fd(root: Path | str):
    """Open `root` as a verified non-symlink directory descriptor."""
    o_nofollow, o_nonblock, o_directory = _require_containment_support()
    root_path = _expand_abs_path(root)
    st_pre = os.lstat(root_path)
    if stat.S_ISLNK(st_pre.st_mode):
        raise OSError(f"Root directory is a symlink: {root_path}")
    if not stat.S_ISDIR(st_pre.st_mode):
        raise NotADirectoryError(f"Root path is not a directory: {root_path}")

    fd = os.open(str(root_path), os.O_RDONLY | o_nofollow | o_nonblock | o_directory)
    try:
        st_fd = os.fstat(fd)
        if not stat.S_ISDIR(st_fd.st_mode):
            raise NotADirectoryError(f"Opened root descriptor is not a directory: {root_path}")
        if (st_fd.st_dev, st_fd.st_ino) != (st_pre.st_dev, st_pre.st_ino):
            raise OSError(f"Root directory identity changed during open: {root_path}")
        yield fd, root_path, st_fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def _walk_parent_dir_fds(root_fd: int, parts: Sequence[str]):
    """Step through intermediate directory components relative to `root_fd` with `O_NOFOLLOW | O_DIRECTORY`."""
    o_nofollow, o_nonblock, o_directory = _require_containment_support()
    opened_fds: list[int] = []
    cur_fd = root_fd
    try:
        for part in parts:
            if part in ("", ".", "..") or "/" in part or "\\" in part:
                raise PermissionError(f"Invalid path component: {part!r}")
            st_comp = os.stat(part, dir_fd=cur_fd, follow_symlinks=False)
            if stat.S_ISLNK(st_comp.st_mode):
                raise PermissionError(f"Ancestor component is a symlink: {part!r}")
            if not stat.S_ISDIR(st_comp.st_mode):
                raise NotADirectoryError(f"Ancestor component is not a directory: {part!r}")
            next_fd = os.open(part, os.O_RDONLY | o_nofollow | o_nonblock | o_directory, dir_fd=cur_fd)
            opened_fds.append(next_fd)
            st_open = os.fstat(next_fd)
            if (st_open.st_dev, st_open.st_ino) != (st_comp.st_dev, st_comp.st_ino):
                raise OSError(f"Ancestor directory {part!r} swapped during traversal")
            cur_fd = next_fd
        yield cur_fd
    finally:
        for fd in reversed(opened_fds):
            with contextlib.suppress(OSError):
                os.close(fd)


def _normalize_rel_parts(rel_path: str | Path) -> tuple[str, tuple[str, ...]]:
    raw = str(rel_path).replace("\\", "/").strip()
    if raw in ("", "."):
        return ".", ()
    if raw.startswith("/"):
        raise ValueError(f"Relative path must not be absolute: {rel_path!r}")
    parts = tuple(p for p in raw.split("/") if p and p != ".")
    if any(p == ".." for p in parts):
        raise ValueError(f"Relative path escapes root via '..': {rel_path!r}")
    return "/".join(parts), parts


def safe_read_regular_file(
    root,
    rel_path,
    *,
    max_bytes=DEFAULT_MAX_FILE_BYTES,
    retain_bytes=True,
    _mid_read_hook=None,
):
    from .capture import CURRENT_CAPTURE

    capture = CURRENT_CAPTURE.get()
    args: dict[str, Any] = dict(max_bytes=max_bytes, retain_bytes=retain_bytes, _mid_read_hook=_mid_read_hook)
    if capture is not None:
        return capture.read(_safe_read_regular_file, root, rel_path, **args)
    return _safe_read_regular_file(root, rel_path, **args)


def safe_read_regular_file_plain(
    root,
    rel_path,
    *,
    max_bytes=DEFAULT_MAX_FILE_BYTES,
    retain_bytes=True,
    _mid_read_hook=None,
):
    """Read for non-audit consumers with a plain SHA-256, without audit key IO."""
    return _safe_read_regular_file(
        root,
        rel_path,
        max_bytes=max_bytes,
        retain_bytes=retain_bytes,
        _mid_read_hook=_mid_read_hook,
        _plain_digest=True,
    )


def _read_symlink_entry(
    full_path_str: str,
    norm_rel: str,
    leaf: str,
    parent_fd: int,
    st_pre: os.stat_result,
) -> SafeReadResult:
    raw_target = os.readlink(leaf, dir_fd=parent_fd)
    st_post_link = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    same_link = (
        stat.S_ISLNK(st_post_link.st_mode)
        and (st_post_link.st_dev, st_post_link.st_ino, st_post_link.st_mtime_ns)
        == (st_pre.st_dev, st_pre.st_ino, st_pre.st_mtime_ns)
    )
    return _safe_read_result_with_stat(
        path=full_path_str,
        rel_path=norm_rel,
        kind="symlink",
        coverage=COVERAGE_VERIFIED if same_link else COVERAGE_COULD_NOT_VERIFY,
        stable=same_link,
        st=st_pre,
        symlink_target=raw_target,
        error=None if same_link else "Symlink changed during read",
    )


def _stream_regular_fd(
    fd: int,
    full_path_str: str,
    norm_rel: str,
    leaf: str,
    parent_fd: int,
    st_pre: os.stat_result,
    *,
    max_bytes: int,
    retain_bytes: bool,
    _mid_read_hook: Callable[[], None] | None,
    _plain_digest: bool,
) -> SafeReadResult:
    try:
        st_open = os.fstat(fd)
        open_kind = classify_mode(st_open.st_mode)
        if open_kind != "regular":
            return SafeReadResult(
                path=full_path_str,
                rel_path=norm_rel,
                kind=open_kind,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                stable=False,
                error=f"Swapped to non-regular file ({open_kind}) on open",
            )
        if (st_open.st_dev, st_open.st_ino) != (st_pre.st_dev, st_pre.st_ino):
            return SafeReadResult(
                path=full_path_str,
                rel_path=norm_rel,
                kind="regular",
                coverage=COVERAGE_COULD_NOT_VERIFY,
                stable=False,
                error="File inode changed between lstat and open",
            )
        # Re-check the open descriptor itself before any byte is read: a link swapped
        # after the path check cannot turn this read into a read of a declared credential.
        try:
            check_open_handle(fd, full_path_str, info=st_open, parent_fd=parent_fd)
        except CredentialStoreNotOpened:
            return _credential_excluded(full_path_str, norm_rel)
        if max_bytes >= 0 and st_open.st_size > max_bytes:
            return _safe_read_result_with_stat(
                path=full_path_str,
                rel_path=norm_rel,
                kind="regular",
                coverage=COVERAGE_COULD_NOT_VERIFY,
                stable=True,
                st=st_open,
                bounded_exceeded=True,
                error=f"File size {st_open.st_size} exceeds limit {max_bytes} bytes",
            )

        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        total_read = 0
        hook_called = False

        while True:
            chunk = os.read(fd, 65536)
            if not hook_called and _mid_read_hook is not None:
                hook_called = True
                _mid_read_hook()
            if not chunk:
                break
            total_read += len(chunk)
            if max_bytes >= 0 and total_read > max_bytes:
                return _safe_read_result_with_stat(
                    path=full_path_str,
                    rel_path=norm_rel,
                    kind="regular",
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    stable=False,
                    st=st_open,
                    size=total_read,
                    bounded_exceeded=True,
                    error=f"Streamed read exceeded limit {max_bytes} bytes",
                )
            hasher.update(chunk)
            if retain_bytes:
                chunks.append(chunk)

        st_after_fd = os.fstat(fd)
    finally:
        os.close(fd)

    try:
        st_post_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        st_post_path = None

    stable = (
        st_post_path is not None
        and stat.S_ISREG(st_post_path.st_mode)
        and _stat_identity_tuple(st_pre) == _stat_identity_tuple(st_after_fd) == _stat_identity_tuple(st_post_path)
        and total_read == st_pre.st_size
    )
    if not stable:
        return _safe_read_result_with_stat(
            path=full_path_str,
            rel_path=norm_rel,
            kind="regular",
            coverage=COVERAGE_COULD_NOT_VERIFY,
            stable=False,
            st=st_open,
            size=total_read,
            error="File identity or metadata changed during read",
        )

    hex_digest = hasher.hexdigest()
    return _safe_read_result_with_stat(
        path=full_path_str,
        rel_path=norm_rel,
        kind="regular",
        coverage=COVERAGE_VERIFIED,
        stable=True,
        st=st_open,
        size=total_read,
        content=b"".join(chunks) if retain_bytes else None,
        sha256=hex_digest if _plain_digest else content_digest(hex_digest),
    )


def _credential_excluded(full_path_str: str, norm_rel: str) -> SafeReadResult:
    note_credential_skip(full_path_str)
    return SafeReadResult(
        path=full_path_str,
        rel_path=norm_rel,
        kind="excluded",
        coverage="not_included",
        stable=True,
        error="Credential content excluded by policy",
    )


class CredentialStoreNotOpened(ValueError):
    """The opened file is a declared credential: it was closed before any byte was read.

    `info` is the descriptor's fstat (metadata only), for callers that record a
    credential store's size, mode and time the way they do for a declared path.
    """

    def __init__(self, info: os.stat_result | None = None) -> None:
        super().__init__("credential_store_not_opened")
        self.info = info


_PROC_FD = "/proc/self/fd"


def _descriptor_location(fd: int) -> str | None:
    """Where the open descriptor really is (Linux /proc), or None where /proc is absent.

    Raises CredentialStoreNotOpened when /proc exists but the location cannot be read:
    a file that cannot be checked is never read.
    """
    try:
        return os.readlink(f"{_PROC_FD}/{fd}")
    except OSError:
        if os.path.isdir(_PROC_FD):
            raise CredentialStoreNotOpened() from None
        return None


def check_open_handle(fd: int, full_path: str, *, info: os.stat_result | None = None, parent_fd: int | None = None) -> None:
    """Re-check an OPEN descriptor against the declared credentials before any byte is read.

    The one handle check of the audit (the shared reader and `open_checked` both use it):
    the opened file's identity, its folder's identity and its real location must not be a
    declared credential, so a link or hard link swapped in after the path check is never
    read. Raises CredentialStoreNotOpened; the caller closes the descriptor.
    """
    if not has_declarations():
        return
    st = info if info is not None else os.fstat(fd)
    parent = os.fstat(parent_fd) if parent_fd is not None else None
    try:
        real = _descriptor_location(fd)
    except CredentialStoreNotOpened:
        raise CredentialStoreNotOpened(st) from None
    if opened_credential(st, full_path, real, parent):
        raise CredentialStoreNotOpened(st)


def open_checked(path: str, flags: int, *, dir_fd: int | None = None, full_path: str | None = None) -> int:
    """`os.open` for reading, returning the descriptor only after `check_open_handle`.

    `full_path` is the absolute path the caller checked (required with `dir_fd`). Flags,
    limits and error handling stay the caller's; on a declared credential the descriptor
    is closed unread and CredentialStoreNotOpened is raised.
    """
    if dir_fd is not None and full_path is None:
        raise ValueError("full_path is required with dir_fd")
    fd = os.open(path, flags, dir_fd=dir_fd) if dir_fd is not None else os.open(path, flags)
    try:
        check_open_handle(fd, full_path if full_path is not None else os.path.abspath(path), parent_fd=dir_fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _safe_read_regular_file(
    root: Path | str,
    rel_path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    retain_bytes: bool = True,
    _mid_read_hook: Callable[[], None] | None = None,
    _plain_digest: bool = False,
) -> SafeReadResult:
    """Safely read or hash a regular file inside `root` using descriptor-relative no-follow opens (§12)."""
    _require_containment_support()
    root_abs = _expand_abs_path(root)
    try:
        norm_rel, parts = _normalize_rel_parts(rel_path)
    except ValueError as exc:
        return SafeReadResult(
            path=str(root_abs / str(rel_path)),
            rel_path=str(rel_path),
            kind="escaped",
            coverage=COVERAGE_COULD_NOT_VERIFY,
            stable=False,
            error=str(exc),
        )

    full_path_str = str(root_abs if not parts else root_abs.joinpath(*parts))
    verdict = credential_verdict(full_path_str)
    if verdict == "unverified":
        # The path could not be checked against the declared credentials: never open it.
        return SafeReadResult(
            path=full_path_str,
            rel_path=norm_rel,
            kind="unreadable",
            coverage=COVERAGE_COULD_NOT_VERIFY,
            stable=False,
            error="Could not verify the path against declared credentials",
        )
    if verdict is not None:
        return _credential_excluded(full_path_str, norm_rel)
    if not parts:
        return SafeReadResult(
            path=full_path_str,
            rel_path=".",
            kind="directory",
            coverage=COVERAGE_COULD_NOT_VERIFY,
            stable=True,
            error="Target is root directory, not a regular file",
        )

    try:
        with _open_root_dir_fd(root_abs) as (root_fd, _, _):
            with _walk_parent_dir_fds(root_fd, parts[:-1]) as parent_fd:
                leaf = parts[-1]
                try:
                    st_pre = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return SafeReadResult(
                        path=full_path_str, rel_path=norm_rel, kind="missing", coverage=COVERAGE_VERIFIED, stable=True
                    )

                mode_kind = classify_mode(st_pre.st_mode)
                if mode_kind == "symlink":
                    return _read_symlink_entry(full_path_str, norm_rel, leaf, parent_fd, st_pre)
                if mode_kind != "regular":
                    return _safe_read_result_with_stat(
                        path=full_path_str,
                        rel_path=norm_rel,
                        kind=mode_kind,
                        coverage=COVERAGE_COULD_NOT_VERIFY,
                        stable=True,
                        st=st_pre,
                        error=f"Refusing to open non-regular file of type {mode_kind}",
                    )

                o_nofollow, o_nonblock, _ = _require_containment_support()
                fd = os.open(leaf, os.O_RDONLY | o_nofollow | o_nonblock, dir_fd=parent_fd)
                return _stream_regular_fd(
                    fd,
                    full_path_str,
                    norm_rel,
                    leaf,
                    parent_fd,
                    st_pre,
                    max_bytes=max_bytes,
                    retain_bytes=retain_bytes,
                    _mid_read_hook=_mid_read_hook,
                    _plain_digest=_plain_digest,
                )
    except PermissionError as exc:
        return SafeReadResult(
            path=full_path_str, rel_path=norm_rel, kind="escaped", coverage=COVERAGE_COULD_NOT_VERIFY, stable=False, error=str(exc)
        )
    except OSError as exc:
        return SafeReadResult(
            path=full_path_str, rel_path=norm_rel, kind="unreadable", coverage=COVERAGE_COULD_NOT_VERIFY, stable=False, error=str(exc)
        )


def resolve_permitted_symlink_target(
    *,
    link_root: Path | str,
    link_rel_path: str | Path,
    raw_target: str,
    allowed_roots: Sequence[Path | str],
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    retain_bytes: bool = True,
) -> SafeReadResult:
    """Resolve and read a symlink target ONLY if it resolves inside `allowed_roots` via protected traversal (§12)."""
    link_root_abs = _expand_abs_path(link_root)
    norm_rel, parts = _normalize_rel_parts(link_rel_path)
    parent_abs = link_root_abs.joinpath(*parts[:-1]) if len(parts) > 1 else link_root_abs

    candidate_abs = Path(
        os.path.normpath(raw_target if os.path.isabs(raw_target) else os.path.join(str(parent_abs), raw_target))
    )
    for allowed in allowed_roots:
        allowed_abs = _expand_abs_path(allowed)
        try:
            rel_to_allowed = candidate_abs.relative_to(allowed_abs).as_posix()
        except ValueError:
            continue
        return safe_read_regular_file(
            allowed_abs, rel_to_allowed, max_bytes=max_bytes, retain_bytes=retain_bytes
        )

    return SafeReadResult(
        path=str(candidate_abs),
        rel_path=norm_rel,
        kind="escaped",
        coverage=COVERAGE_COULD_NOT_VERIFY,
        stable=True,
        symlink_target=raw_target,
        error=f"Symlink target {raw_target!r} resolves outside permitted evidence roots",
    )


def classify_profile_root_entry(name: str, *, is_default_profile: bool = False) -> str:
    """Classify a top-level entry under a profile root according to the §12 ownership manifest."""
    if name in PROFILE_CONFIG_MATCH_ENTRIES:
        return "config_match"
    if name in PROFILE_OWNED_EXTRA_ENTRIES:
        return "profile_owned"
    if name in SHARED_INFRASTRUCTURE_ROOT_ENTRIES:
        return "shared_infrastructure"
    lower = name.casefold()
    if lower.startswith(("auth.json.", ".env.bak", "config.yaml.bak", "config.yaml.corrupt")):
        return "profile_owned"
    return "unclassified"


@dataclass
class TreeFingerprintManifest:
    """Versioned fingerprint manifest for a profile or project unit (§4, §5, §12)."""

    unit_kind: str
    unit_id: str
    root_path: str
    manifest_version: str = FINGERPRINT_MANIFEST_VERSION
    ownership_manifest_version: str = OWNERSHIP_MANIFEST_VERSION
    coverage: str = COVERAGE_VERIFIED
    stable: bool = True
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    directories: dict[str, list[str]] = field(default_factory=dict)
    symlinks: dict[str, dict[str, Any]] = field(default_factory=dict)
    special_files: dict[str, dict[str, Any]] = field(default_factory=dict)
    absent_expected_paths: list[str] = field(default_factory=list)
    pruned_roots: list[str] = field(default_factory=list)
    excluded_audit_paths: list[str] = field(default_factory=list)
    shared_infrastructure_entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    unclassified_entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    unreadable_paths: list[dict[str, str]] = field(default_factory=list)
    db_row_digests: dict[str, str | None] = field(default_factory=dict)
    config_digest: str | None = None
    template_baseline_version: str | None = None
    rule_versions: dict[str, str] = field(default_factory=dict)
    discovery_policy: dict[str, Any] = field(default_factory=dict)
    logical_bytes: int = 0
    deduplicated_bytes: int = 0
    memory_bytes: int = 0
    seen_inodes: dict[tuple[int, int], int] = field(default_factory=dict, repr=False)
    configuration_match_digest: str | None = None
    whole_profile_digest: str | None = None
    whole_profile_exact_eligible: bool = True
    unit_digest: str = ""

    def _compute_profile_digests(self) -> None:
        config_pairs: list[tuple[str, str]] = []
        for rel, meta in sorted(self.files.items()):
            if rel.split("/", 1)[0] in PROFILE_CONFIG_MATCH_ENTRIES and meta.get("sha256"):
                config_pairs.append((rel, f"file:{meta['sha256']}"))
        for rel, lmeta in sorted(self.symlinks.items()):
            if rel.split("/", 1)[0] in PROFILE_CONFIG_MATCH_ENTRIES:
                config_pairs.append((rel, f"symlink:{lmeta.get('target', '')}"))
        config_pairs.sort(key=lambda item: item[0])
        self.configuration_match_digest = _json_content_digest(config_pairs)

        eligible = (
            self.stable
            and self.coverage == COVERAGE_VERIFIED
            and not self.unreadable_paths
            and not self.special_files
            and not self.excluded_audit_paths
        )
        self.whole_profile_exact_eligible = eligible
        if not eligible:
            self.whole_profile_digest = None
            return

        whole_payload = {
            "ownership_manifest_version": self.ownership_manifest_version,
            "files": {rel: meta["sha256"] for rel, meta in sorted(self.files.items())},
            "directories": {rel: list(children) for rel, children in sorted(self.directories.items())},
            "symlinks": {rel: lmeta["target"] for rel, lmeta in sorted(self.symlinks.items())},
            "absent_expected_paths": sorted(self.absent_expected_paths),
            "db_row_digests": dict(sorted(self.db_row_digests.items())),
        }
        self.whole_profile_digest = _json_content_digest(whole_payload)

    def compute_digests(self) -> None:
        """Compute deterministic configuration-match, whole-profile, and unit digests (§4, §5, §12)."""
        self.deduplicated_bytes = sum(self.seen_inodes.values())
        if self.unit_kind == "profile":
            self._compute_profile_digests()

        unit_payload = {
            "root_path": self.root_path,
            "manifest_version": self.manifest_version,
            "ownership_manifest_version": self.ownership_manifest_version,
            "unit_kind": self.unit_kind,
            "unit_id": self.unit_id,
            "coverage": self.coverage,
            "stable": self.stable,
            "files": {
                rel: {"sha256": m.get("sha256"), "size": m.get("size")}
                for rel, m in sorted(self.files.items())
            },
            "directories": {rel: list(children) for rel, children in sorted(self.directories.items())},
            "symlinks": {rel: m.get("target") for rel, m in sorted(self.symlinks.items())},
            "special_files": {rel: m.get("kind") for rel, m in sorted(self.special_files.items())},
            "absent_expected_paths": sorted(self.absent_expected_paths),
            "unclassified_entries": sorted(self.unclassified_entries.keys()),
            "unreadable_paths": sorted((p.get("path", ""), p.get("error", "")) for p in self.unreadable_paths),
            "db_row_digests": dict(sorted(self.db_row_digests.items())),
            "config_digest": self.config_digest,
            "template_baseline_version": self.template_baseline_version,
            "rule_versions": dict(sorted(self.rule_versions.items())),
            "discovery_policy": self.discovery_policy,
        }
        self.unit_digest = _json_content_digest(unit_payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "ownership_manifest_version": self.ownership_manifest_version,
            "unit_kind": self.unit_kind,
            "unit_id": self.unit_id,
            "root_path": self.root_path,
            "coverage": self.coverage,
            "stable": self.stable,
            "files": self.files,
            "directories": self.directories,
            "symlinks": self.symlinks,
            "special_files": self.special_files,
            "absent_expected_paths": self.absent_expected_paths,
            "pruned_roots": self.pruned_roots,
            "excluded_audit_paths": self.excluded_audit_paths,
            "shared_infrastructure_entries": self.shared_infrastructure_entries,
            "unclassified_entries": self.unclassified_entries,
            "unreadable_paths": self.unreadable_paths,
            "db_row_digests": self.db_row_digests,
            "config_digest": self.config_digest,
            "template_baseline_version": self.template_baseline_version,
            "rule_versions": self.rule_versions,
            "discovery_policy": self.discovery_policy,
            "logical_bytes": self.logical_bytes,
            "deduplicated_bytes": self.deduplicated_bytes,
            "memory_bytes": self.memory_bytes,
            "configuration_match_digest": self.configuration_match_digest,
            "whole_profile_digest": self.whole_profile_digest,
            "whole_profile_exact_eligible": self.whole_profile_exact_eligible,
            "unit_digest": self.unit_digest,
        }


def _record_unreadable(
    manifest: TreeFingerprintManifest,
    path: str,
    error: str,
    *,
    unstable: bool = False,
) -> None:
    if unstable:
        manifest.stable = False
    manifest.coverage = COVERAGE_COULD_NOT_VERIFY
    manifest.unreadable_paths.append({"path": path, "error": error})


def _build_excluded_rel_set(
    root_abs: Path,
    unit_kind: str,
    excluded_rel_paths: Sequence[str],
) -> set[str]:
    from .key import private_paths

    excluded_rel_set = {p.strip("/") for p in excluded_rel_paths if p and p.strip("/")}
    for private in private_paths():
        if private.is_relative_to(root_abs):
            excluded_rel_set.add(private.relative_to(root_abs).as_posix())
    if unit_kind == "profile":
        excluded_rel_set.update(_PROFILE_EXCLUDED_DB_PATHS)
    return excluded_rel_set


def _record_absent_expected_paths(
    manifest: TreeFingerprintManifest,
    root_abs: Path,
    expected_rel_paths: Sequence[str],
) -> None:
    for exp in sorted({e.strip("/") for e in expected_rel_paths if e and e.strip("/")}):
        try:
            os.lstat(root_abs.joinpath(*exp.split("/")))
        except FileNotFoundError:
            manifest.absent_expected_paths.append(exp)
        except OSError as exc:
            _record_unreadable(manifest, exp, str(exc))


def _record_root_ownership_if_excluded(
    manifest: TreeFingerprintManifest,
    name: str,
    mode_kind: str,
    st: os.stat_result,
    *,
    is_default_profile: bool,
) -> bool:
    bucket = classify_profile_root_entry(name, is_default_profile=is_default_profile)
    if bucket not in ("shared_infrastructure", "unclassified"):
        return False
    entry = {
        "kind": mode_kind,
        "size": int(st.st_size) if mode_kind != "directory" else None,
        "mtime_ns": int(st.st_mtime_ns),
    }
    target_map = (
        manifest.shared_infrastructure_entries
        if bucket == "shared_infrastructure"
        else manifest.unclassified_entries
    )
    target_map[name] = entry
    return True


def _record_regular_file_in_manifest(
    manifest: TreeFingerprintManifest,
    root_abs: Path,
    rel: str,
    unit_kind: str,
    max_file_bytes: int,
) -> None:
    read_res = safe_read_regular_file(root_abs, rel, max_bytes=max_file_bytes, retain_bytes=False)
    if not read_res.stable:
        _record_unreadable(manifest, rel, read_res.error or "File changed during read", unstable=True)
        return
    if read_res.coverage != COVERAGE_VERIFIED or read_res.sha256 is None:
        _record_unreadable(manifest, rel, read_res.error or "File could not be verified")
        return

    fsize = int(read_res.size or 0)
    manifest.files[rel] = {
        "sha256": read_res.sha256,
        "size": fsize,
        "dev": read_res.dev,
        "ino": read_res.ino,
        "nlink": read_res.nlink,
        "mtime_ns": read_res.mtime_ns,
        "ctime_ns": read_res.ctime_ns,
    }
    manifest.logical_bytes += fsize
    if unit_kind == "profile" and (rel.startswith("memories/") or rel in ("MEMORY.md", "USER.md")):
        manifest.memory_bytes += fsize
    if read_res.dev is not None and read_res.ino is not None:
        manifest.seen_inodes.setdefault((read_res.dev, read_res.ino), fsize)


def _verify_dir_entries_unchanged(
    manifest: TreeFingerprintManifest,
    dir_fd: int,
    rel_prefix: str,
    names_before: list[str],
) -> None:
    try:
        post_fd = os.dup(dir_fd)
        try:
            with contextlib.suppress(OSError):
                os.lseek(post_fd, 0, os.SEEK_SET)
            with os.scandir(post_fd) as it_after:
                names_after = sorted(e.name for e in it_after)
            if names_after != names_before:
                _record_unreadable(manifest, rel_prefix or ".", "Directory entries changed during scan", unstable=True)
        finally:
            # scandir closes its own duplicate, not the descriptor passed to it.
            os.close(post_fd)
    except OSError:
        manifest.stable = False
        manifest.coverage = COVERAGE_COULD_NOT_VERIFY


def _record_symlink_in_manifest(
    manifest: TreeFingerprintManifest,
    dir_fd: int,
    *,
    name: str,
    rel: str,
    st: os.stat_result,
) -> None:
    try:
        target_str = os.readlink(name, dir_fd=dir_fd)
    except OSError as exc:
        _record_unreadable(manifest, rel, str(exc))
        return
    manifest.symlinks[rel] = {
        "target": target_str,
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
    }


def _record_special_file_in_manifest(
    manifest: TreeFingerprintManifest,
    rel: str,
    mode_kind: str,
    st: os.stat_result,
) -> None:
    manifest.special_files[rel] = {
        "kind": mode_kind,
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
    }
    _record_unreadable(manifest, rel, f"Special file ({mode_kind}) cannot be safely read")


def _walk_manifest_subdirectory(
    manifest: TreeFingerprintManifest,
    dir_fd: int,
    *,
    name: str,
    rel: str,
    st: os.stat_result,
    walk_dir: Callable[[int, str], None],
) -> None:
    """Recurse only after a no-follow open confirms the observed directory inode."""
    o_nofollow, o_nonblock, o_directory = _require_containment_support()
    try:
        sub_fd = os.open(
            name, os.O_RDONLY | o_nofollow | o_nonblock | o_directory, dir_fd=dir_fd
        )
    except OSError as exc:
        _record_unreadable(manifest, rel, str(exc))
        return
    try:
        st_sub = os.fstat(sub_fd)
        if (st_sub.st_dev, st_sub.st_ino) != (st.st_dev, st.st_ino):
            _record_unreadable(manifest, rel, "Directory inode changed during open", unstable=True)
            return
        walk_dir(sub_fd, rel)
    finally:
        os.close(sub_fd)


def build_tree_fingerprint_manifest(
    *,
    unit_kind: str,
    unit_id: str,
    root_path: Path | str,
    expected_rel_paths: Sequence[str] = (),
    descendant_profile_roots: Sequence[Path | str] = (),
    excluded_rel_paths: Sequence[str] = (),
    db_row_digests: Mapping[str, str | None] | None = None,
    config_digest: str | None = None,
    template_baseline_version: str | None = None,
    rule_versions: Mapping[str, str] | None = None,
    discovery_policy: Mapping[str, Any] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_entries: int = DEFAULT_MAX_DIR_ENTRIES,
    max_depth: int = 64,
    _mid_walk_hook: Callable[[str], None] | None = None,
) -> TreeFingerprintManifest:
    """Fingerprint a profile or project directory tree using descriptor-relative no-follow reads (§4, §12)."""
    _require_containment_support()
    root_abs = _expand_abs_path(root_path)
    manifest = TreeFingerprintManifest(
        unit_kind=unit_kind,
        unit_id=unit_id,
        root_path=str(root_abs),
        db_row_digests=dict(db_row_digests or {}),
        config_digest=config_digest,
        template_baseline_version=template_baseline_version,
        rule_versions=dict(rule_versions or {}),
        discovery_policy=dict(discovery_policy or {}),
    )

    if credential_path(root_abs):
        note_credential_skip(root_abs)
        manifest.coverage = "not_included"
        manifest.excluded_audit_paths.append(".")
        manifest.whole_profile_exact_eligible = False
        manifest.compute_digests()
        return manifest

    descendant_abs_set = {
        str(d_abs) for desc in descendant_profile_roots if (d_abs := _expand_abs_path(desc)) != root_abs
    }
    excluded_rel_set = _build_excluded_rel_set(root_abs, unit_kind, excluded_rel_paths)
    _record_absent_expected_paths(manifest, root_abs, expected_rel_paths)

    try:
        with _open_root_dir_fd(root_abs) as (root_fd, _, _):
            entries_seen = 0

            def _walk_dir(dir_fd: int, rel_prefix: str) -> None:
                nonlocal entries_seen
                if rel_prefix and len(PurePosixPath(rel_prefix).parts) > max_depth:
                    _record_unreadable(manifest, rel_prefix, "Directory depth budget exceeded")
                    return
                try:
                    with os.scandir(dir_fd) as it:
                        raw_entries = sorted(it, key=lambda e: e.name)
                except OSError as exc:
                    _record_unreadable(manifest, rel_prefix or ".", str(exc))
                    return

                names_before = [e.name for e in raw_entries]
                manifest.directories[rel_prefix or "."] = names_before

                for entry in raw_entries:
                    name = entry.name
                    rel = name if not rel_prefix else f"{rel_prefix}/{name}"
                    full_entry_abs = os.path.join(str(root_abs), *rel.split("/"))

                    if _mid_walk_hook is not None:
                        _mid_walk_hook(rel)

                    if credential_path(full_entry_abs):
                        note_credential_skip(full_entry_abs)
                        manifest.excluded_audit_paths.append(rel)
                        continue

                    if full_entry_abs in descendant_abs_set or (
                        unit_kind == "profile" and not rel_prefix and name == "profiles"
                    ):
                        manifest.pruned_roots.append(rel)
                        continue

                    if rel in excluded_rel_set:
                        manifest.excluded_audit_paths.append(rel)
                        continue

                    try:
                        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        _record_unreadable(manifest, rel, "Entry vanished during directory walk", unstable=True)
                        continue
                    except OSError as exc:
                        _record_unreadable(manifest, rel, str(exc))
                        continue

                    mode_kind = classify_mode(st.st_mode)
                    if unit_kind == "profile" and not rel_prefix:
                        if _record_root_ownership_if_excluded(
                            manifest, name, mode_kind, st, is_default_profile=(unit_id == "default")
                        ):
                            continue

                    entries_seen += 1
                    if max_entries > 0 and entries_seen > max_entries:
                        _record_unreadable(manifest, rel, f"Directory entry limit ({max_entries}) exceeded")
                        return

                    if mode_kind == "symlink":
                        _record_symlink_in_manifest(manifest, dir_fd, name=name, rel=rel, st=st)
                        continue

                    if mode_kind == "directory":
                        if unit_kind == "project" and name == ".git":
                            manifest.directories[rel] = ["<git_metadata>"]
                            continue
                        _walk_manifest_subdirectory(
                            manifest, dir_fd, name=name, rel=rel, st=st, walk_dir=_walk_dir
                        )
                        continue

                    if mode_kind != "regular":
                        _record_special_file_in_manifest(manifest, rel, mode_kind, st)
                        continue

                    _record_regular_file_in_manifest(manifest, root_abs, rel, unit_kind, max_file_bytes)

                _verify_dir_entries_unchanged(manifest, dir_fd, rel_prefix, names_before)

            _walk_dir(root_fd, "")
    except OSError as exc:
        _record_unreadable(manifest, ".", str(exc), unstable=True)

    manifest.compute_digests()
    return manifest


def compute_system_deduplicated_bytes(manifests: Iterable[TreeFingerprintManifest]) -> dict[str, int]:
    """Compute logical sum vs deduplicated `(st_dev, st_ino)` physical bytes across multiple units (§12)."""
    logical_total = 0
    global_inodes: dict[tuple[int, int], int] = {}
    for m in manifests:
        logical_total += m.logical_bytes
        for inode_key, size in m.seen_inodes.items():
            global_inodes.setdefault(inode_key, size)
    return {
        "logical_total_bytes": logical_total,
        "deduplicated_system_bytes": sum(global_inodes.values()),
    }
