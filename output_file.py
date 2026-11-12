"""No-follow writes for adopt output files (inventory.json, rules.json).

``write_output_text`` writes a whole file at a caller-chosen path without ever
following a symbolic link, so a link planted at the output path or in one of
its parent folders cannot redirect the write to another file.

Ancestor rule (the one place links ARE followed): the leading path components
that are the same as, or a parent of, the user's home folder or the temporary
folder (each taken both as written and with links resolved) are trusted and
opened normally. This keeps a home folder that is itself a link, ``/home`` on
systems where it is a link, and the macOS ``/var`` -> ``/private/var`` and
``/tmp`` -> ``/private/tmp`` links working. Every component below that trusted
prefix is checked without following links: an existing link, at any depth or
at the leaf, is refused; missing folders are created one at a time through a
folder handle opened with ``O_NOFOLLOW``. An output under some other top-level
link (for example ``/mnt`` when it is a link) is therefore refused.

Chosen folder: a caller that knows the folder the person chose (``run --source``
writes its completion marker below the copy folder) passes it as ``base``. That
folder may be reached through links the person made: it is pinned by identity
(``safety.PinnedFolder``) and every component below it is checked as above. The
trusted home/temporary prefix is likewise opened through its real path, one
folder at a time without following links, and checked by identity.

Separately, the output's real location (real path of its parent folder plus
the file name) must not be inside any of ``forbidden_roots`` (compared by real
path on both sides); this catches a link inside the trusted prefix.

Linux and macOS only: the write needs ``dir_fd`` support for ``os.open``,
``os.mkdir``, ``os.stat``, ``os.rename``/``os.replace`` and ``os.unlink`` and
refuses (never falls back to a by-path write) when it is missing.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional, Tuple

from .safety import PinnedFolder, SafetyError, _is_same_or_subpath, _lexical_abs, _open_resolved_dir, _same_file

_TEMP_PREFIX = ".defuzz-out-"
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _probe_dir_fd_support() -> bool:
    needed = (os.open, os.mkdir, os.stat, os.rename, os.unlink)
    return (
        bool(_O_NOFOLLOW and _O_DIRECTORY)
        and all(fn in os.supports_dir_fd for fn in needed)
        and os.stat in os.supports_follow_symlinks
    )


# Probed once at import: tests that wrap os.open to observe file access must not
# turn the platform check off.
_DIR_FD_SUPPORTED = _probe_dir_fd_support()


def _dir_fd_supported() -> bool:
    return _DIR_FD_SUPPORTED


def _trusted_anchors() -> List[str]:
    anchors: List[str] = []
    for raw in (os.path.expanduser("~"), tempfile.gettempdir()):
        if raw and os.path.isabs(raw):
            lex = os.path.abspath(raw)
            anchors.extend((lex, os.path.realpath(lex)))
    return anchors


def _is_anchor_prefix(prefix: str, anchors: Iterable[str]) -> bool:
    if prefix == os.sep:
        return True
    return any(a == prefix or a.startswith(prefix + os.sep) for a in anchors)


def _split_trusted(parent: Path) -> Tuple[str, List[str]]:
    """Split ``parent`` into (trusted prefix, components to walk without following links)."""
    parts = parent.parts  # parts[0] is the root
    anchors = _trusted_anchors()
    prefix = parts[0]
    idx = 1
    while idx < len(parts):
        candidate = os.path.join(prefix, parts[idx])
        if not _is_anchor_prefix(candidate, anchors):
            break
        prefix = candidate
        idx += 1
    return prefix, list(parts[idx:])


def _split_base(lex: Path, base: Any, role: str) -> Tuple[Path, List[str]]:
    """Split ``lex.parent`` into (chosen folder, components below it); refuse a path outside it."""
    base_lex = base.lex if isinstance(base, PinnedFolder) else _lexical_abs(base)
    try:
        rest = lex.parent.relative_to(base_lex).parts
    except ValueError:
        raise SafetyError(f"Refusing {role} path outside the chosen folder {base_lex}: {lex}") from None
    return base_lex, list(rest)


def _open_trusted_prefix(prefix: str, role: str) -> int:
    """Open the trusted prefix through its real path, no-follow, and check it is the folder resolved."""
    real = os.path.realpath(prefix)
    try:
        expected = os.stat(real)
        fd = _open_resolved_dir(real)
    except OSError as exc:
        raise SafetyError(f"Could not open folder for {role} path ({exc.strerror}): {prefix}") from exc
    if not _same_file(os.fstat(fd), expected):
        os.close(fd)
        raise SafetyError(f"Refusing {role} path: the folder changed while it was opened: {prefix}")
    return fd


def _forbidden_real_hit(lex: Path, forbidden_roots: Iterable[Optional[os.PathLike | str]]) -> Optional[Tuple[Path, Path]]:
    real = Path(os.path.realpath(lex.parent)) / lex.name
    for root in forbidden_roots:
        if root is None:
            continue
        real_root = Path(os.path.realpath(os.fspath(root)))
        if _is_same_or_subpath(real, real_root):
            return real, real_root
    return None


def _symlink_error(role: str, where: os.PathLike | str) -> SafetyError:
    return SafetyError(f"Refusing to traverse or overwrite symlink in {role} path: {where}")


def assert_output_path_safe(
    path: os.PathLike | str,
    *,
    role: str,
    forbidden_roots: Iterable[Optional[os.PathLike | str]] = (),
    base: Any = None,
) -> Path:
    """Refuse an output path that a link redirects or whose real location is forbidden; return it lexically.

    ``base`` (a path or a ``PinnedFolder``) is the folder the person chose; links above it are theirs.
    """
    lex = _lexical_abs(path)
    if lex.name in ("", ".", ".."):
        raise SafetyError(f"Refusing {role} path that does not name a file: {path}")
    hit = _forbidden_real_hit(lex, forbidden_roots)
    if hit is not None:
        raise SafetyError(f"Refusing {role} path whose real location {hit[0]} is inside {hit[1]}: {path}")
    if base is None:
        prefix, rest = _split_trusted(lex.parent)
    else:
        base_lex, rest = _split_base(lex, base, role)
        prefix = str(base_lex)
    cur = prefix
    for name in rest + [lex.name]:
        cur = os.path.join(cur, name)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return lex
        except OSError as exc:
            raise SafetyError(f"Refusing {role} path that cannot be checked ({exc.strerror}): {cur}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise _symlink_error(role, cur)
        if cur != str(lex) and not stat.S_ISDIR(st.st_mode):
            raise SafetyError(f"Refusing {role} path whose parent is not a folder: {cur}")
        if cur == str(lex) and not stat.S_ISREG(st.st_mode):
            raise SafetyError(f"Refusing to overwrite non-regular file at {role} path: {cur}")
    return lex


def _open_child_dir(parent_fd: int, name: str, role: str, shown: str) -> int:
    flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o777, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SafetyError(f"Could not create folder for {role} path ({exc.strerror}): {shown}") from exc
    except OSError:
        pass
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        try:
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            raise _symlink_error(role, shown) from exc
        raise SafetyError(f"Refusing {role} path whose parent is not a folder: {shown}") from exc


def _replace_output_file(fd: int, lex: Path, data: bytes, role: str) -> None:
    """Write a temporary sibling and replace the checked leaf through its parent handle.

    ``fd`` is borrowed; the caller retains responsibility for closing it. After
    the temporary file is opened, any BaseException triggers best-effort removal.
    """
    leaf = lex.name
    # The earlier path check can race: re-check the leaf through the pinned parent
    # handle so a swapped-in symlink or non-regular file is refused before writing.
    try:
        st: Optional[os.stat_result] = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        raise _symlink_error(role, lex)
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise SafetyError(f"Refusing to overwrite non-regular file at {role} path: {lex}")
    tmp_name = f"{_TEMP_PREFIX}{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
    try:
        tfd = os.open(tmp_name, flags, 0o666, dir_fd=fd)
    except OSError as exc:
        raise SafetyError(f"Could not write {role} file ({exc.strerror}): {lex}") from exc
    try:
        with os.fdopen(tfd, "wb") as fh:
            if st is not None:
                os.fchmod(fh.fileno(), stat.S_IMODE(st.st_mode))
            fh.write(data)
        os.replace(tmp_name, leaf, src_dir_fd=fd, dst_dir_fd=fd)
    except BaseException as exc:
        try:
            os.unlink(tmp_name, dir_fd=fd)
        except OSError:
            pass
        if isinstance(exc, OSError):
            reason = exc.strerror or str(exc)
            raise SafetyError(f"Could not write {role} file ({reason}): {lex}") from exc
        raise


def write_output_text(
    path: os.PathLike | str,
    text: str,
    *,
    role: str,
    forbidden_roots: Iterable[Optional[os.PathLike | str]] = (),
    base: Any = None,
) -> Path:
    """Write ``text`` (UTF-8) to ``path`` without following links; return the lexical path.

    ``base`` (a path, or a ``PinnedFolder`` opened earlier) is the folder the person chose:
    it is pinned by identity and the output must lie below it. Without it the trusted
    prefix is the home or temporary folder (see the module notes).

    An existing regular file is replaced atomically (its permission bits are
    kept); a new file gets mode 0o666 minus the umask, as ``Path.write_text``
    did. The data goes to a temporary sibling opened with
    ``O_CREAT|O_EXCL|O_NOFOLLOW`` and is renamed onto the final name through
    the parent folder handle, so a link planted at the last moment is replaced,
    never followed. The temporary file is removed on failure.
    """
    forbidden = list(forbidden_roots)
    if not _dir_fd_supported():
        raise SafetyError(f"Refusing {role} write: this platform cannot write files without following links: {path}")
    lex = assert_output_path_safe(path, role=role, forbidden_roots=forbidden, base=base)
    data = text.encode("utf-8")
    if base is None:
        prefix, rest = _split_trusted(lex.parent)
        fd = _open_trusted_prefix(prefix, role)
    else:
        base_lex, rest = _split_base(lex, base, role)
        prefix = str(base_lex)
        pin = base if isinstance(base, PinnedFolder) else PinnedFolder(base_lex, role=role)
        try:
            pin.recheck()
            hit = _forbidden_real_hit(pin.real.joinpath(*rest, lex.name), forbidden)
            if hit is not None:
                raise SafetyError(f"Refusing {role} path whose real location {hit[0]} is inside {hit[1]}: {path}")
            fd = pin.open_dir()
        finally:
            if pin is not base:
                pin.close()
    try:
        shown = prefix
        for name in rest:
            shown = os.path.join(shown, name)
            child = _open_child_dir(fd, name, role, shown)
            os.close(fd)
            fd = child
        _replace_output_file(fd, lex, data, role)
    finally:
        os.close(fd)
    return lex


# ``run --source`` writes this file last, after the copy is adopted. Without it an
# existing destination may be empty or half-copied, so it is never adopted again.
ADOPT_COMPLETE_MARKER = (".adopt", "adopt-complete.json")


class UnfinishedCopyError(SafetyError):
    """An existing ``run --source`` destination that no finished run left."""


def _marker_source(copy_root: Path) -> Optional[str]:
    """Source recorded by a finished run, or None (missing, a link, unreadable, malformed)."""
    cur = str(copy_root)
    for name in ADOPT_COMPLETE_MARKER:
        cur = os.path.join(cur, name)
        try:
            st = os.lstat(cur)
        except OSError:
            return None
        want = stat.S_ISREG if name == ADOPT_COMPLETE_MARKER[-1] else stat.S_ISDIR
        if stat.S_ISLNK(st.st_mode) or not want(st.st_mode):
            return None
    try:
        fd = os.open(cur, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        with os.fdopen(fd, "rb") as fh:
            data = json.loads(fh.read(65536).decode("utf-8"))
    except (OSError, ValueError):
        return None
    source = data.get("source_root") if isinstance(data, dict) else None
    return source if isinstance(source, str) else None


def reuse_finished_copy(copy_root: os.PathLike | str, source_root: os.PathLike | str) -> bool:
    """False when ``copy_root`` does not exist yet (copy it). True when an earlier finished run
    from this source left it: its marker is removed first, so an interrupted run leaves none.
    Anything else (empty, half-copied, another source) is refused and left as it is."""
    copy_lex = _lexical_abs(copy_root)
    if not os.path.lexists(copy_lex):
        return False
    recorded = _marker_source(copy_lex) if os.path.isdir(copy_lex) and not os.path.islink(copy_lex) else None
    if recorded is None or os.path.realpath(recorded) != os.path.realpath(os.fspath(source_root)):
        raise UnfinishedCopyError(
            f"The copy folder {copy_lex} already exists and no earlier run from this source finished it, "
            "so it may be incomplete: if Defuzz started it, delete it and run again, otherwise pick a new copy folder."
        )
    try:
        os.unlink(copy_lex.joinpath(*ADOPT_COMPLETE_MARKER))
    except OSError as exc:
        raise SafetyError(f"Could not reset the copy folder ({exc.strerror}): {copy_lex}") from exc
    return True


@contextlib.contextmanager
def adopt_copy_guard(copy_root: os.PathLike | str, source_root: Optional[os.PathLike | str]) -> Iterator[None]:
    """Around ``run``: with a source, write the completion marker after everything else succeeded.

    A refusal after the copy folder exists says the copy is incomplete. Without a
    source the folder is the user's own, so the message is left as it is.
    """
    # The copy folder the person chose is pinned now, so a parent swapped for a link
    # during the run cannot move the marker (the folder itself may not exist yet).
    pin = PinnedFolder(copy_root, role="copy marker") if source_root is not None else None
    try:
        try:
            yield
        except SafetyError as exc:
            if source_root is None or type(exc) is not SafetyError or not os.path.lexists(copy_root):
                raise
            raise SafetyError(
                f"{exc} The copy at {_lexical_abs(copy_root)} is incomplete: delete it and run again."
            ) from exc
        if pin is not None:
            copy_lex = _lexical_abs(copy_root)
            text = json.dumps({"schema": 1, "source_root": str(_lexical_abs(source_root))}, indent=2) + "\n"
            write_output_text(
                copy_lex.joinpath(*ADOPT_COMPLETE_MARKER), text, role="copy marker",
                forbidden_roots=(source_root,), base=pin,
            )
    finally:
        if pin is not None:
            pin.close()
