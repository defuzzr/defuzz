"""Scaffold a non-code project from a componentize kit: propose, accept, and discard."""

from __future__ import annotations

import errno
import inspect
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Set, Tuple

try:
    import pwd
except ImportError:  # pragma: no cover - Windows
    pwd = None  # type: ignore[assignment]

from . import componentize_bridge
from .agents_md import write_agents_md
from .naming import folder_name, is_ascii_folder, slugify
from .network_failure import NETWORK_REQUIRED_REASON, looks_like_network_failure, network_required_note
from .placer import compute_rules_hash
from .rules import (
    _SAFE_EXT_RE,
    _validate_extensions,
    _validate_safe_rel_prefix,
    validate_rules_spec,
)
from .safety import (
    SafetyError,
    _is_same_or_subpath,
    _lexical_abs,
    _protected_hermes_roots,
    _real_parent_bound,
    run_git_hardened,
    safe_mkdirs,
    safe_write_bytes,
    safe_write_text,
    verify_nofollow_within_root,
)
from .scaffolder import (
    _AFTER_MOVE_NOTE,
    AcceptResult,
    RepoPlan,
    ScaffoldError,
    ScaffoldTimeout,
    _attempt_project_registration,
    _build_proposed_tree,
    _changed_parent_error,
    _check_cancelled,
    _check_deadline,
    _check_not_live_hermes,
    _dest_anchor,
    _fsync_dir,
    _init_and_commit_dest_repo,
    _is_non_symlink_dir,
    _publish_staged_repo,
    _raise_scaffold_error,
    _validate_single_path_component,
    _writable_stage_parent,
    default_project_create,
    projects_root,
    resolve_plugin_commit,
)
from .state_store import record_project, save_answers

_FIXED_FALLBACK_DECLARED_DIRS: Tuple[Dict[str, str], ...] = (
    {
        "dir": "_inbox",
        "summary": "unclassified incoming files",
        "why": "catch unknown file kinds without prompting",
    },
)

_EMPTY_PROJECT_IGNORE_PATTERNS: Tuple[str, ...] = (
    ".hermes/scratch/",
    ".hermes/sessions/",
    ".adopt/place-log.json",
)


def _reject_if_abs_dir(raw: str, label: str, *, staging_dir: Optional[Path] = None) -> None:
    stripped = raw.strip()
    if stripped.startswith(("/", "\\")) or os.path.isabs(stripped):
        raise ScaffoldError(
            f"Invalid kit {label} ({raw!r}): absolute path is not allowed",
            staging_dir=staging_dir,
            keep_staging=True,
        )


def _sync_staged_gitignore(staged: Path, ignore_patterns: Sequence[str]) -> None:
    target = verify_nofollow_within_root(staged, ".gitignore")
    existing_lines: List[str] = []
    if os.path.lexists(target):
        st = os.lstat(target)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise SafetyError(f"Refusing non-regular .gitignore in {staged}: {target}")
        raw_text = target.read_bytes().decode("utf-8", errors="replace")
        existing_lines = [ln.rstrip("\r") for ln in raw_text.splitlines()]
    seen = set(existing_lines)
    out_lines = list(existing_lines)
    for pat in ignore_patterns:
        if pat and pat not in seen:
            out_lines.append(pat)
            seen.add(pat)
    new_text = ("\n".join(out_lines) + "\n") if out_lines else "\n"
    safe_write_text(staged, ".gitignore", new_text, overwrite=True)


def _system_stage_candidates() -> List[str]:
    """System temp folders tried after the projects folder and TMPDIR."""
    raw = [os.environ.get("TEMP"), os.environ.get("TMP")] if os.name == "nt" else ["/tmp", "/var/tmp", "/usr/tmp"]
    return [c for c in raw if c]


# --- The companion's target rule -------------------------------------------------------------
# `componentize kit apply/check` (defuzz-componentize `_kit_runtime.py`: resolve_home,
# _stable_hermes_home, _hermes_homes, _decide, verify_target) refuses a target folder when:
#   * the home folder cannot be determined: HOME if it is an absolute existing folder, else
#     the account home from the password database, else refuse everything;
#   * it is (lexically or resolved) inside <home>/.hermes or inside HERMES_HOME (after $VAR
#     expansion and ~ expansion against that home; a relative HERMES_HOME is ignored), each
#     compared both as written and resolved;
#   * it is inside a system folder, is a top-level folder or the filesystem root, is the home
#     folder or one of its ancestors, or only resolves into the home through a symlink;
#   * its last component is an existing symlink.
# Staging must never pick a folder the companion refuses, so Defuzz applies the same rule here
# and additionally refuses its own protected roots (`safety._protected_hermes_roots`).
_COMPANION_ENV_REF = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_COMPANION_SYSTEM_SUBTREES = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys")
_COMPANION_SYSTEM_EXACT = ("/var", "/opt")


def _same_or_inside(path: str, base: str) -> bool:
    if base == os.path.sep:
        return True
    return path == base or path.startswith(base + os.path.sep)


def _companion_home() -> Optional[str]:
    """The home folder the companion protects (its `resolve_home`), or None."""
    env_home = os.environ.get("HOME")
    if isinstance(env_home, str) and os.path.isabs(env_home) and os.path.isdir(env_home):
        return os.path.normpath(env_home)
    pw_dir: Optional[str] = None
    if pwd is not None and hasattr(os, "getuid"):
        try:
            pw_dir = pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OSError, AttributeError):
            pw_dir = None
    elif pwd is None:
        guess = os.path.expanduser("~")
        pw_dir = guess if os.path.isabs(guess) else None
    if isinstance(pw_dir, str) and os.path.isabs(pw_dir) and os.path.isdir(pw_dir):
        return os.path.normpath(pw_dir)
    return None


def _companion_hermes_homes(home: str) -> List[str]:
    """<home>/.hermes plus a stable HERMES_HOME (the companion's `_hermes_homes`)."""
    out = [os.path.normpath(os.path.join(home, ".hermes"))]
    raw = os.environ.get("HERMES_HOME", "").strip()
    if raw:

        def repl(match: "re.Match[str]") -> str:
            return os.environ[match.group(1) or match.group(2)]

        try:
            raw = _COMPANION_ENV_REF.sub(repl, raw)
        except KeyError:
            raw = ""
        path: Optional[str] = None
        if raw == "~":
            path = home
        elif raw.startswith("~/"):
            path = os.path.join(home, raw[2:])
        elif raw.startswith("~"):
            path = os.path.expanduser(raw)
        elif os.path.isabs(raw):
            path = raw
        if path and os.path.isabs(path):
            norm = os.path.normpath(path)
            if norm not in out:
                out.append(norm)
    return out


def _companion_refuses(path: os.PathLike[str] | str, home: str) -> bool:
    """True when the companion's `_decide` would refuse this folder."""
    lexical = os.path.normpath(os.path.abspath(os.fspath(path)))
    resolved = os.path.realpath(lexical)
    forms = (lexical, resolved)
    for norm_hh in _companion_hermes_homes(home):
        bases = (norm_hh, os.path.realpath(norm_hh))
        if any(_same_or_inside(f, b) for f in forms for b in bases):
            return True
    for sys_root in _COMPANION_SYSTEM_SUBTREES:
        real_sys = os.path.realpath(sys_root)
        bases = (sys_root,) + ((real_sys,) if real_sys != os.path.sep else ())
        if any(_same_or_inside(f, b) for f in forms for b in bases):
            return True
    for exact in _COMPANION_SYSTEM_EXACT:
        if exact in forms or os.path.realpath(exact) in forms:
            return True
    for f in forms:
        if f == os.path.sep or os.path.dirname(f) == os.path.sep:
            return True  # filesystem root, top-level folder (and /lib*)
    home_norm = os.path.normpath(home)
    home_real = os.path.realpath(home_norm)
    for f, h in ((lexical, home_norm), (resolved, home_real)):
        if f == h or h.startswith(f + os.path.sep):
            return True
    if _same_or_inside(resolved, home_real) and not _same_or_inside(lexical, home_norm):
        return True
    return os.path.islink(lexical)


def _inside_any_hermes_home(path: os.PathLike[str] | str) -> bool:
    """True when the companion would refuse `path`, or it is inside a Defuzz-protected Hermes home.

    Cache/scratch gets no exemption: the companion's `kit apply` refuses targets there too.
    When no home folder can be determined the companion refuses everything, so this does too.
    """
    home = _companion_home()
    if home is None or _companion_refuses(path, home):
        return True
    roots = _protected_hermes_roots()
    for candidate in (_lexical_abs(path), _real_parent_bound(path)):
        if any(_is_same_or_subpath(candidate, root) for root in roots):
            return True
    return False


# --- A staging folder pinned by directory handle ----------------------------------------------
# Same technique as `audit/outward_git._directory` (walk from "/" with O_NOFOLLOW) and the
# companion's `verify_target` (hold the checked directory open, compare device+inode).
_DIR_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_STAGE_CHANGED = (
    "Stopped: the staging folder {path} changed after it was checked; nothing this run did not "
    "create was deleted."
)
_MOVE_CHANGED = (
    "Stopped: the project folder {path} changed while it was being moved into place. The project "
    "was not created and nothing this run did not create was deleted; the staging folder {stage} was kept."
)
_MOVE_PARTIAL = (
    "Stopped: the projects folder for {path} changed while the project was being moved into place. "
    "The new project is at {landed}; delete that folder if you do not want it. Nothing else was deleted."
)
# Linux: open a name without following it and without read permission (owner-masking umask).
_PATH_OPEN_FLAGS = getattr(os, "O_PATH", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class _StageChanged(Exception):
    """The pinned staging parent or stage no longer matches what was created."""


class _SkipCandidate(Exception):
    """This staging parent turned out to be one the companion would refuse: try the next one."""


# Decided once at import (POSIX: always true) by name from os.supports_*: those sets hold the built-ins, so
# wrapping os functions before or after import cannot change it. If truly False (not Linux or macOS) the
# fallback is an unpinned tempfile.mkdtemp stage (see _make_kit_stage).
_HANDLES_SUPPORTED = (
    hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and {"open", "mkdir", "stat", "rmdir", "unlink", "chmod", "rename", "readlink", "symlink"}
    <= {fn.__name__ for fn in os.supports_dir_fd}
    and "scandir" in {fn.__name__ for fn in os.supports_fd}
    and hasattr(os, "fchmod")
)


def _identity(st: os.stat_result) -> Tuple[int, int]:
    return st.st_dev, st.st_ino


def _open_dir_nofollow(resolved: str) -> int:
    """Open an already-resolved absolute folder, refusing a symlink in any component."""
    fd = os.open(os.path.sep, _DIR_OPEN_FLAGS)
    try:
        for part in Path(resolved).parts[1:]:
            child = os.open(part, _DIR_OPEN_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _close_fd(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _chmod_dir_nofollow(dir_fd: int, name: str, ident: Tuple[int, int], mode: int) -> None:
    """chmod the folder `name` (of identity `ident`) without following a symlink swapped in.

    Linux: through an O_PATH handle (`/proc/self/fd`). Elsewhere: re-check the identity first
    (one call apart); the caller re-checks it again after opening.
    """
    if _PATH_OPEN_FLAGS & getattr(os, "O_PATH", 0) and os.path.isdir("/proc/self/fd"):
        pfd = os.open(name, _PATH_OPEN_FLAGS | getattr(os, "O_DIRECTORY", 0), dir_fd=dir_fd)
        try:
            if _identity(os.fstat(pfd)) != ident:
                raise _StageChanged
            os.chmod(f"/proc/self/fd/{pfd}", mode)
        finally:
            os.close(pfd)
        return
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or _identity(st) != ident:
        raise _StageChanged
    os.chmod(name, mode, dir_fd=dir_fd)


def _remove_contents(dir_fd: int) -> bool:
    """Delete everything inside an open folder without following symlinks. True when emptied."""
    ok = True
    with os.scandir(dir_fd) as entries:
        items = list(entries)
    for entry in items:
        try:
            st = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                try:
                    child = os.open(entry.name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
                except PermissionError:
                    # e.g. created under an owner-masking umask: make our own folder readable.
                    _chmod_dir_nofollow(dir_fd, entry.name, _identity(st), stat.S_IMODE(st.st_mode) | stat.S_IRWXU)
                    child = os.open(entry.name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
                try:
                    if _identity(os.fstat(child)) != _identity(st):
                        ok = False
                        continue
                    ok = _remove_contents(child) and ok
                finally:
                    os.close(child)
                os.rmdir(entry.name, dir_fd=dir_fd)
            else:
                os.unlink(entry.name, dir_fd=dir_fd)
        except (OSError, _StageChanged):
            ok = False
    return ok


class _KitStage:
    """A staging folder created inside a parent folder held open by a no-follow handle.

    `parent_path` is the parent as written (possibly through a symlinked HOME): that is the form
    handed to componentize, whose home rule compares it with HOME as written. `resolved_parent`
    is the folder the handle was opened on; every check ties the written form to it.
    """

    def __init__(
        self,
        parent_fd: int,
        parent_path: str,
        name: str,
        ident: Tuple[int, int],
        resolved_parent: Optional[str] = None,
    ) -> None:
        self.parent_fd: Optional[int] = parent_fd
        self.parent_path = parent_path
        self.resolved_parent = resolved_parent if resolved_parent is not None else parent_path
        self.name = name
        self.ident = ident
        self.path = Path(parent_path) / name
        self._finalizer = weakref.finalize(self, _close_fd, parent_fd)

    def close(self) -> None:
        self._finalizer()
        self.parent_fd = None

    def verify(self, *extra: os.PathLike[str] | str) -> None:
        """Raise _StageChanged unless the path still names exactly the folder this run created."""
        if self.parent_fd is None:
            raise _StageChanged
        try:
            pinned = os.fstat(self.parent_fd)
            on_path = os.stat(self.parent_path)
            by_handle = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            by_path = os.lstat(self.path)
        except OSError as exc:
            raise _StageChanged from exc
        if (
            _identity(pinned) != _identity(on_path)
            or not stat.S_ISDIR(by_handle.st_mode)
            or not stat.S_ISDIR(by_path.st_mode)
            or _identity(by_handle) != self.ident
            or _identity(by_path) != self.ident
            or os.path.realpath(self.path) != os.path.join(self.resolved_parent, self.name)
        ):
            raise _StageChanged
        for p in (self.path, *extra):
            if _inside_any_hermes_home(p):
                raise _StageChanged

    def remove(self) -> str:
        """Delete the stage through the pinned parent only.

        Returns "removed", "gone" (nothing there), "foreign" (that name is no longer the folder
        this run created: nothing deleted) or "incomplete" (ours, but not everything could go).
        """
        if self.parent_fd is None:
            return "gone"
        try:
            st = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "gone"
        except OSError:
            return "incomplete"
        if not stat.S_ISDIR(st.st_mode) or _identity(st) != self.ident:
            return "foreign"
        try:
            fd = os.open(self.name, _DIR_OPEN_FLAGS, dir_fd=self.parent_fd)
        except OSError:
            return "incomplete"
        try:
            if _identity(os.fstat(fd)) != self.ident:
                return "foreign"
            if not _remove_contents(fd):
                return "incomplete"
        finally:
            os.close(fd)
        try:
            st = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if _identity(st) != self.ident:
                return "foreign"
            os.rmdir(self.name, dir_fd=self.parent_fd)
        except OSError:
            return "incomplete"
        return "removed"


def _open_new_stage(parent_fd: int, name: str) -> int:
    """Open the just-created `name` without following it, making it usable (0700) by handle."""
    try:
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except PermissionError:
        pass  # created under an owner-masking umask (mode 0000): unlock it, then open
    st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode):
        raise _StageChanged
    _chmod_dir_nofollow(parent_fd, name, _identity(st), 0o700)
    fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    if _identity(os.fstat(fd)) != _identity(st):
        os.close(fd)
        raise _StageChanged
    return fd


def _create_pinned_stage(lexical: str, resolved: str, prefix: str) -> _KitStage:
    """Create a private stage relative to a no-follow handle on `resolved`, then re-verify it.

    The new folder is opened by handle right after mkdir and only adopted when it is an empty
    folder owned by this user on the parent's filesystem; its identity comes from that handle.
    """
    try:
        parent_fd = _open_dir_nofollow(resolved)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise _StageChanged from exc
        raise
    try:
        pinned = os.fstat(parent_fd)
        if _identity(pinned) != _identity(os.stat(resolved)) or _identity(pinned) != _identity(os.stat(lexical)):
            raise _StageChanged
        if _inside_any_hermes_home(os.path.join(lexical, prefix + "check")):
            raise _SkipCandidate
        for _ in range(100):
            name = prefix + secrets.token_hex(6)
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            break
        else:
            raise FileExistsError(errno.EEXIST, "no unused staging folder name", resolved)
        try:
            fd = _open_new_stage(parent_fd, name)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise _StageChanged from exc
            raise
        try:
            created = os.fstat(fd)
            with os.scandir(fd) as entries:
                empty = next(iter(entries), None) is None
            if (
                not stat.S_ISDIR(created.st_mode)
                or created.st_dev != pinned.st_dev
                or (hasattr(os, "geteuid") and created.st_uid != os.geteuid())
                or not empty
            ):
                raise _StageChanged  # not the folder this run just made: leave it alone
            # mkdir's mode is reduced by the umask; the stage must be usable and private (0700).
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
    except BaseException:
        os.close(parent_fd)
        raise
    stage = _KitStage(parent_fd, lexical, name, _identity(created), resolved_parent=resolved)
    try:
        stage.verify()
    except BaseException:
        stage.remove()
        stage.close()
        raise
    return stage


def _make_kit_stage(target_root: Path) -> Tuple[Path, Optional[_KitStage]]:
    """Create a private (0700) kit staging folder outside every Hermes home.

    Preferred: a hidden folder inside the projects folder, so the final move is a rename on the
    same filesystem. Then TMPDIR and the system temp folders, skipping any the companion would
    refuse (under Hermes, TMPDIR is the Hermes home's cache/scratch). The chosen parent is
    resolved once and pinned by a no-follow handle; the stage is created relative to it and
    re-verified, and is later only removed through that handle.
    """
    if _companion_home() is None:
        raise ScaffoldError(
            "Cannot determine your home folder, so the kit cannot be staged safely; set HOME to your home folder."
        )
    use_handles = _HANDLES_SUPPORTED
    tmpdir = os.environ.get("TMPDIR") or None
    candidates: List[Tuple[str, str]] = [(str(target_root), ".adopt-scaffold-")]
    if tmpdir:
        candidates.append((_writable_stage_parent(tmpdir) or tmpdir, "adopt-scaffold-"))
    candidates.extend((c, "adopt-scaffold-") for c in _system_stage_candidates())

    seen: Set[str] = set()
    skipped_home = False
    last_error: Optional[Tuple[str, OSError]] = None
    for parent, prefix in candidates:
        lexical = os.path.normpath(os.path.abspath(parent))
        if lexical in seen:
            continue
        seen.add(lexical)
        # Judge the folder the companion will actually be handed (a child of this parent).
        if _inside_any_hermes_home(os.path.join(lexical, prefix + "check")):
            skipped_home = True
            continue
        resolved = os.path.realpath(lexical)
        if not os.path.isdir(resolved) or not os.access(resolved, os.W_OK | os.X_OK):
            continue
        try:
            if use_handles:
                # Hand over the written form (the companion compares it with HOME as written);
                # pin, create and verify on the resolved side.
                stage = _create_pinned_stage(lexical, resolved, prefix)
                return stage.path, stage
            return Path(tempfile.mkdtemp(prefix=prefix, dir=lexical)), None
        except _SkipCandidate:
            skipped_home = True
            continue
        except _StageChanged:
            raise ScaffoldError(_STAGE_CHANGED.format(path=lexical)) from None
        except OSError as exc:
            last_error = (parent, exc)
    if last_error is not None:
        where, exc = last_error
        raise ScaffoldError(
            f"Cannot create a staging folder in {where} ({exc.strerror or exc}); set TMPDIR to a writable folder"
        )
    if skipped_home:
        raise ScaffoldError(
            f"Cannot create a staging folder outside the Hermes home: the projects folder {target_root} "
            "is missing or not writable and every temporary folder is inside the Hermes home, so create "
            "the projects folder or set TMPDIR to a writable folder outside the Hermes home."
        )
    raise ScaffoldError(
        f"Cannot create a staging folder in {tmpdir or target_root} (no writable folder); set TMPDIR to a writable folder"
    )


def _verify_kit_stage(
    stage: Optional[_KitStage], *extra: os.PathLike[str] | str, keep_staging: bool = False
) -> None:
    """Re-check a pinned stage right before componentize or the final move sees it."""
    if stage is None:
        return
    try:
        stage.verify(*extra)
    except _StageChanged:
        raise ScaffoldError(
            _STAGE_CHANGED.format(path=stage.path), staging_dir=stage.path, keep_staging=keep_staging
        ) from None


def _remove_kit_stage(stage: Optional[_KitStage], staging_dir: Path, *, report: bool = True) -> None:
    """Remove a stage: through its pinned handle when there is one, else by path (explicit parent).

    With `report`, a stage name that now holds something else raises one plain sentence.
    """
    if stage is None:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return
    try:
        outcome = stage.remove()
    finally:
        stage.close()
    if outcome == "foreign" and report:
        raise ScaffoldError(
                f"Did not delete the staging folder {stage.path}: it is no longer the folder this run created.",
                staging_dir=stage.path,
                keep_staging=True,
            )


# --- The final move, relative to the pinned folders ---------------------------------------------


class _SpecialFileError(OSError):
    """The staged project holds a socket, pipe or device file: it is not copied."""

    special_file = True


_COPY_CHUNK = 1 << 20


def _copy_tree_fd(src_fd: int, dst_fd: int) -> None:
    """Copy a folder's contents between two open folders without following any symlink.

    The one handle copy: kit creation and template publication (scaffolder._copy_staged_into)
    both use it. Every name is opened relative to its parent's handle at both ends; links are
    copied as links, files and folders keep their mode and times. Each folder is flushed to
    disk (names and links are durable once the caller's final rename is flushed); file contents
    are left to the system's normal write-back, because flushing every file made a real
    template's move take over 2 seconds on a busy disk. A socket, pipe or device raises
    _SpecialFileError; an entry replaced while it is copied raises _StageChanged.
    """
    _copy_tree_into(src_fd, dst_fd, "")


def _copy_fd_data(s_fd: int, d_fd: int) -> None:
    while True:
        chunk = os.read(s_fd, _COPY_CHUNK)
        if not chunk:
            return
        view = memoryview(chunk)
        while view:
            view = view[os.write(d_fd, view):]


def _copy_tree_into(src_fd: int, dst_fd: int, rel_dir: str) -> None:
    with os.scandir(src_fd) as entries:
        names = sorted(e.name for e in entries)
    for name in names:
        rel = f"{rel_dir}/{name}" if rel_dir else name
        st = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
        mode = stat.S_IMODE(st.st_mode)
        times = (st.st_atime_ns, st.st_mtime_ns)
        if stat.S_ISDIR(st.st_mode):
            os.mkdir(name, 0o700, dir_fd=dst_fd)
            s_fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=src_fd)
            try:
                if _identity(os.fstat(s_fd)) != _identity(st):
                    raise _StageChanged
                d_fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=dst_fd)
                try:
                    _copy_tree_into(s_fd, d_fd, rel)
                    os.fchmod(d_fd, mode)
                    os.utime(d_fd, ns=times)
                    _fsync_dir(d_fd)
                finally:
                    os.close(d_fd)
            finally:
                os.close(s_fd)
        elif stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(name, dir_fd=src_fd), name, dir_fd=dst_fd)
            if os.utime in os.supports_follow_symlinks and os.utime in os.supports_dir_fd:
                try:
                    os.utime(name, ns=times, dir_fd=dst_fd, follow_symlinks=False)
                except OSError:
                    pass
        elif stat.S_ISREG(st.st_mode):
            # O_NONBLOCK: a file swapped for a pipe after the check must not block the open.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
            s_fd = os.open(name, flags, dir_fd=src_fd)
            try:
                if _identity(os.fstat(s_fd)) != _identity(st):
                    raise _StageChanged
                out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                d_fd = os.open(name, out_flags, 0o600, dir_fd=dst_fd)
                try:
                    _copy_fd_data(s_fd, d_fd)
                    os.fchmod(d_fd, mode)
                    os.utime(d_fd, ns=times)
                finally:
                    os.close(d_fd)
            finally:
                os.close(s_fd)
        else:
            raise _SpecialFileError(errno.EINVAL, "special file in the staged project", rel)


def _rmdir_if_ours(dir_fd: int, name: str, ident: Tuple[int, int], *, contents: bool = False) -> None:
    """Remove `name` when it is still the folder of identity `ident`.

    Only when empty, unless `contents` (a folder only this run wrote into, e.g. its own copy).
    """
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode) or _identity(st) != ident:
            return
        if contents:
            fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
            try:
                if _identity(os.fstat(fd)) != ident or not _remove_contents(fd):
                    return
            finally:
                os.close(fd)
        os.rmdir(name, dir_fd=dir_fd)
    except OSError:
        pass


def _fd_path(fd: int, fallback: str) -> str:
    """Where an open folder is now (it may have been renamed); `fallback` when that cannot be told."""
    try:
        if os.path.isdir("/proc/self/fd"):
            return os.readlink(f"/proc/self/fd/{fd}")
        import fcntl

        if hasattr(fcntl, "F_GETPATH"):
            raw = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024))
            return os.fsdecode(raw.split(b"\0", 1)[0])
    except (OSError, ImportError, ValueError):
        pass
    return fallback


def _mark_created(exc: BaseException, path: Path) -> None:
    """Tell the caller a project folder exists on disk (callers read `created_dirs`)."""
    if not getattr(exc, "created_dirs", None):
        try:
            exc.created_dirs = [path]  # type: ignore[attr-defined]
        except AttributeError:
            pass


def _parent_changed(dest: Path, staging_dir: Path) -> ScaffoldError:
    return ScaffoldError(str(_changed_parent_error(dest)), staging_dir=staging_dir, keep_staging=True)


def _check_dest_anchor(proposal: "KitProposal") -> Tuple[str, str, int, int]:
    """Refuse when the folder pinned above the destination at preview time was replaced or redirected."""
    pin = proposal.dest_anchor
    if pin is None:  # a proposal made without a preview pin: pin it now
        try:
            pin = _dest_anchor(proposal.dest)
        except ScaffoldError as exc:
            raise ScaffoldError(str(exc), staging_dir=proposal.staging_dir, keep_staging=True) from None
        proposal.dest_anchor = pin
    anchor_lex, anchor_real, dev, ino = pin
    try:
        st = os.stat(anchor_lex)
    except OSError:
        raise _parent_changed(proposal.dest, proposal.staging_dir) from None
    if _identity(st) != (dev, ino) or os.path.realpath(anchor_lex) != anchor_real:
        raise _parent_changed(proposal.dest, proposal.staging_dir)
    return pin


def _dest_parent_parts(proposal: "KitProposal", anchor_lex: str) -> Tuple[str, ...]:
    try:
        return _lexical_abs(proposal.dest).parent.relative_to(anchor_lex).parts
    except ValueError:
        raise _parent_changed(proposal.dest, proposal.staging_dir) from None


def _make_pinned_dest_parent(proposal: "KitProposal") -> Tuple[str, Tuple[int, int]]:
    """Create the missing folders below the pinned folder by handle, never following a link.

    Returns the real path of the destination's parent and its identity.
    """
    anchor_lex, anchor_real, dev, ino = _check_dest_anchor(proposal)
    parts = _dest_parent_parts(proposal, anchor_lex)
    changed = _parent_changed(proposal.dest, proposal.staging_dir)
    try:
        fd = _open_dir_nofollow(anchor_real)
    except OSError:
        raise changed from None
    try:
        if _identity(os.fstat(fd)) != (dev, ino):
            raise changed
        for part in parts:
            try:
                os.mkdir(part, dir_fd=fd)
            except FileExistsError:
                pass
            except OSError:
                raise changed from None
            try:
                child = os.open(part, _DIR_OPEN_FLAGS, dir_fd=fd)
            except OSError:
                raise changed from None
            os.close(fd)
            fd = child
        ident = _identity(os.fstat(fd))
    finally:
        os.close(fd)
    return os.path.join(anchor_real, *parts), ident


def _move_pinned_into_place(
    stage: _KitStage,
    slug: str,
    dest: Path,
    pinned_parent: Optional[Tuple[str, Tuple[int, int]]] = None,
) -> None:
    """Move <stage>/<slug> to `dest` by rename relative to the pinned stage and destination folders.

    The destination name is reserved first with mkdir (an existing destination is refused, never
    replaced). After the rename the result is checked by handle and by path; when it is not the
    staged folder or the destination path no longer leads to it, it is moved back and the run stops.
    With `pinned_parent` (real path, identity), the destination's parent must still be that folder.
    """
    assert stage.parent_fd is not None
    changed = ScaffoldError(
        _MOVE_CHANGED.format(path=dest, stage=stage.path), staging_dir=stage.path, keep_staging=True
    )
    dest_parent = os.path.normpath(os.path.abspath(os.fspath(dest.parent)))
    resolved_parent = os.path.realpath(dest_parent)
    if pinned_parent is not None and resolved_parent != pinned_parent[0]:
        raise _parent_changed(dest, stage.path)
    _check_not_live_hermes(Path(resolved_parent) / dest.name, role="dest")
    try:
        dest_fd = _open_dir_nofollow(resolved_parent)
    except OSError:
        raise changed from None
    stage_fd: Optional[int] = None
    try:
        if pinned_parent is not None and _identity(os.fstat(dest_fd)) != pinned_parent[1]:
            raise _parent_changed(dest, stage.path)
        if _identity(os.fstat(dest_fd)) != _identity(os.stat(dest_parent)):
            raise changed
        stage_fd = os.open(stage.name, _DIR_OPEN_FLAGS, dir_fd=stage.parent_fd)
        if _identity(os.fstat(stage_fd)) != stage.ident:
            raise changed
        staged = os.stat(slug, dir_fd=stage_fd, follow_symlinks=False)
        if not stat.S_ISDIR(staged.st_mode):
            raise changed
        try:
            os.mkdir(dest.name, 0o700, dir_fd=dest_fd)
        except FileExistsError:
            raise ScaffoldError(
                f"Destination already exists: {dest}", staging_dir=stage.path, keep_staging=True
            ) from None
        placeholder = _identity(os.stat(dest.name, dir_fd=dest_fd, follow_symlinks=False))
        expected = _identity(staged)
        try:
            try:
                os.rename(slug, dest.name, src_dir_fd=stage_fd, dst_dir_fd=dest_fd)
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
                # Different filesystems: copy by handle into a fresh folder next to the
                # destination, then rename it into place (same filesystem).
                tmp_name = ".adopt-move-" + secrets.token_hex(6)
                os.mkdir(tmp_name, 0o700, dir_fd=dest_fd)
                tmp_ident = _identity(os.stat(tmp_name, dir_fd=dest_fd, follow_symlinks=False))
                try:
                    src_fd = os.open(slug, _DIR_OPEN_FLAGS, dir_fd=stage_fd)
                    try:
                        if _identity(os.fstat(src_fd)) != expected:
                            raise changed
                        tmp_fd = os.open(tmp_name, _DIR_OPEN_FLAGS, dir_fd=dest_fd)
                        try:
                            if _identity(os.fstat(tmp_fd)) != tmp_ident:
                                raise changed
                            _copy_tree_fd(src_fd, tmp_fd)
                            os.fchmod(tmp_fd, stat.S_IMODE(staged.st_mode))
                        finally:
                            os.close(tmp_fd)
                    finally:
                        os.close(src_fd)
                    os.rename(tmp_name, dest.name, src_dir_fd=dest_fd, dst_dir_fd=dest_fd)
                except BaseException:
                    _rmdir_if_ours(dest_fd, tmp_name, tmp_ident, contents=True)
                    raise
                expected = tmp_ident
        except _StageChanged:
            _rmdir_if_ours(dest_fd, dest.name, placeholder)
            raise changed from None
        except OSError as exc:
            _rmdir_if_ours(dest_fd, dest.name, placeholder)
            raise ScaffoldError(
                f"Cannot move the staged project into {dest} ({exc.strerror or exc}); nothing this run "
                "did not create was deleted.",
                staging_dir=stage.path,
                keep_staging=True,
            ) from exc
        except BaseException:
            _rmdir_if_ours(dest_fd, dest.name, placeholder)
            raise
        moved = os.stat(dest.name, dir_fd=dest_fd, follow_symlinks=False)
        try:
            on_path = os.lstat(dest)
        except OSError:
            on_path = None
        if (
            _identity(moved) == expected
            and on_path is not None
            and _identity(on_path) == expected
            and os.path.realpath(dest) == os.path.join(resolved_parent, dest.name)
        ):
            return
        # Not what was staged, or the destination path no longer leads to it: undo the move.
        if expected != _identity(staged):
            _rmdir_if_ours(dest_fd, dest.name, expected, contents=True)  # our copy; the stage keeps the original
        else:
            try:
                os.stat(slug, dir_fd=stage_fd, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    os.rename(dest.name, slug, src_dir_fd=dest_fd, dst_dir_fd=stage_fd)
                except OSError:
                    pass
        try:
            left = os.stat(dest.name, dir_fd=dest_fd, follow_symlinks=False)
        except OSError:
            left = None
        if left is not None and _identity(left) == expected:
            # It could not be taken back: say where it is.
            landed = Path(_fd_path(dest_fd, resolved_parent)) / dest.name
            partial = ScaffoldError(
                _MOVE_PARTIAL.format(path=dest, landed=landed), staging_dir=stage.path, keep_staging=True
            )
            _mark_created(partial, landed)
            raise partial
        raise changed
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(dest_fd)


class KitUnavailable(ScaffoldError):
    """Raised when the componentize CLI is unavailable during kit scaffolding."""


# Kits are third-party content with their own tools; their folders stay ASCII unless enabled.
UNICODE_FOLDER_KITS = False


def kit_folder_name(name: str, slug: str) -> str:
    """Folder name for a new kit project: Unicode only when enabled and not plain ASCII."""
    if not UNICODE_FOLDER_KITS:
        return slug
    try:
        folder = folder_name(name)
    except ValueError:
        return slug
    return slug if is_ascii_folder(folder) else folder


@dataclass
class KitProposal:
    """Staged componentize kit proposal holding tree, declared dirs, placement rules, and answers."""

    kit_id: str
    slug: str
    display_name: str
    dest: Path
    staging_dir: Path
    staged: Path
    tree: List[str]
    declared_dirs: List[Dict[str, Any]]
    placement_rules: List[Dict[str, Any]]
    answers: Dict[str, Any]
    plugin_commit: str = "unknown"
    stage: Optional[_KitStage] = field(default=None, repr=False, compare=False)
    # (nearest existing folder at or above dest.parent, its real path, st_dev, st_ino), pinned at preview
    dest_anchor: Optional[Tuple[str, str, int, int]] = None
    folder_note: str = ""


def _accepts_timeout(fn: Any) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        p.kind == inspect.Parameter.VAR_KEYWORD or p.name == "timeout"
        for p in params
    )


def _accepts_kw(fn: Any, name: str) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.kind == inspect.Parameter.VAR_KEYWORD or p.name == name for p in params)


def _format_bridge_error_message(call_name: str, kit_id: str, result: Mapping[str, Any]) -> str:
    notice = str(result.get("notice") or "").strip()
    data = result.get("data")
    finding_details: List[str] = []
    if isinstance(data, Mapping) and isinstance(data.get("findings"), list):
        for item in data["findings"][:5]:
            if isinstance(item, Mapping):
                detail = str(
                    item.get("detail") or item.get("message") or item.get("id") or ""
                ).strip()
                if detail:
                    finding_details.append(detail)
            elif isinstance(item, str) and item.strip():
                finding_details.append(item.strip())

    base = notice or f"componentize kit {call_name} failed for {kit_id!r}"
    if finding_details:
        joined = "; ".join(finding_details)
        return f"{base}: {joined}" if base else joined
    return base


def _verify_bridge_envelope(
    call_name: str,
    kit_id: str,
    result: Any,
    *,
    staging_dir: Optional[Path] = None,
    keep_staging: bool = False,
) -> Mapping[str, Any]:
    if not isinstance(result, Mapping):
        raise ScaffoldError(
            f"componentize kit {call_name} for {kit_id!r} returned an invalid response",
            staging_dir=staging_dir,
            keep_staging=keep_staging,
        )
    status = result.get("status")
    if status == "unavailable":
        notice = str(result.get("notice") or "").strip() or (
            f"{componentize_bridge.UNAVAILABLE_NOTICE} for kit {kit_id!r}"
        )
        raise KitUnavailable(notice, staging_dir=staging_dir, keep_staging=keep_staging)
    if status != "ok":
        msg = _format_bridge_error_message(call_name, kit_id, result)
        raise ScaffoldError(msg, staging_dir=staging_dir, keep_staging=keep_staging)

    data = result.get("data")
    if (
        not isinstance(data, Mapping)
        or data.get("ok") is not True
        or data.get("status") != "pass"
    ):
        msg = _format_bridge_error_message(call_name, kit_id, result)
        raise ScaffoldError(msg, staging_dir=staging_dir, keep_staging=keep_staging)
    return data


def _clean_declared_dir(
    idx: int,
    item: Any,
    fail: Callable[..., NoReturn],
    *,
    staging_dir: Optional[Path] = None,
) -> Dict[str, str]:
    if not isinstance(item, Mapping):
        fail(f"Invalid kit declared_dirs[{idx}]: must be an object")
    raw_dir = item.get("dir")
    raw_summary = item.get("summary")
    raw_why = item.get("why")
    if (
        not isinstance(raw_dir, str)
        or not raw_dir.strip()
        or not isinstance(raw_summary, str)
        or not isinstance(raw_why, str)
    ):
        fail(f"Invalid kit declared_dirs[{idx}]: dir, summary, and why must be strings")
    _reject_if_abs_dir(raw_dir, f"declared_dirs[{idx}]", staging_dir=staging_dir)
    try:
        clean_dir = _validate_safe_rel_prefix(
            raw_dir, f"declared_dirs[{idx}].dir", allow_dot=False
        )
    except SafetyError as exc:
        fail(f"Invalid kit declared_dirs[{idx}] ({raw_dir!r}): {exc}", exc)
    return {
        "dir": clean_dir,
        "summary": (raw_summary.strip() or "project directory")[:80],
        "why": (raw_why.strip() or "declared project folder")[:100],
    }


def _clean_placement_rule(
    idx: int,
    pr: Any,
    kit_dir_set: Set[str],
    fail: Callable[..., NoReturn],
    *,
    staging_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    raw_kind_val = pr.get("kind") if isinstance(pr, Mapping) else None
    rule_name = (
        raw_kind_val.strip()
        if isinstance(raw_kind_val, str) and raw_kind_val.strip()
        else f"placement_rules[{idx}]"
    )
    if not isinstance(pr, Mapping):
        fail(f"Invalid kit placement rule {rule_name!r}: must be an object")
    raw_kind = pr.get("kind")
    if not isinstance(raw_kind, str) or not raw_kind.strip():
        fail(f"Invalid kit placement rule {rule_name!r}: missing or non-string kind")
    clean_kind = re.sub(r"[^a-z0-9_-]", "", raw_kind.strip().lower())[:24]
    if not clean_kind:
        fail(f"Invalid kit placement rule {rule_name!r}: kind {raw_kind!r} has no valid characters")

    raw_exts = pr.get("match_ext")
    if (
        not isinstance(raw_exts, Sequence)
        or isinstance(raw_exts, (str, bytes))
        or not raw_exts
        or not all(
            isinstance(e, str) and _SAFE_EXT_RE.match(e.strip().lower())
            for e in raw_exts
        )
    ):
        fail(f"Invalid kit placement rule {rule_name!r}: match_ext must be a non-empty list of valid '.ext' strings")
    try:
        exts = _validate_extensions(raw_exts, f"placement_rules[{idx}].match_ext")
    except SafetyError as exc:
        fail(f"Invalid kit placement rule {rule_name!r}: {exc}", exc)

    raw_dest = pr.get("dest_dir")
    if not isinstance(raw_dest, str) or not raw_dest.strip():
        fail(f"Invalid kit placement rule {rule_name!r}: dest_dir must be a non-empty string")
    _reject_if_abs_dir(raw_dest, f"placement rule {rule_name!r} dest_dir", staging_dir=staging_dir)
    try:
        clean_dest = _validate_safe_rel_prefix(
            raw_dest, f"placement_rules[{idx}].dest_dir", allow_dot=False
        )
    except SafetyError as exc:
        fail(f"Invalid kit placement rule {rule_name!r}: {exc}", exc)

    if clean_dest not in kit_dir_set:
        fail(
            f"Kit placement rule {rule_name!r} targets undeclared dest_dir {clean_dest!r} "
            f"(not in kit declared_dirs)"
        )

    raw_lfs = pr.get("lfs")
    if type(raw_lfs) is not bool:
        fail(f"Invalid kit placement rule {rule_name!r}: lfs must be a boolean")

    raw_reason = pr.get("reason")
    if not isinstance(raw_reason, str):
        fail(f"Invalid kit placement rule {rule_name!r}: reason must be a string")
    clean_reason = " ".join(raw_reason.split())[:100] or f"route {clean_kind} files to {clean_dest}"

    return {
        "kind": clean_kind,
        "match_ext": exts,
        "dest_dir": clean_dest,
        "lfs": raw_lfs,
        "reason": clean_reason,
    }


def _build_kit_rules(
    slug: str,
    raw_declared_dirs: Sequence[Any],
    raw_placement_rules: Sequence[Any],
    *,
    staging_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    def fail(msg: str, cause: Optional[BaseException] = None) -> NoReturn:
        if cause is not None:
            raise ScaffoldError(msg, staging_dir=staging_dir, keep_staging=True) from cause
        raise ScaffoldError(msg, staging_dir=staging_dir, keep_staging=True)

    if not isinstance(raw_declared_dirs, Sequence) or isinstance(raw_declared_dirs, (str, bytes)):
        fail("Kit declared_dirs must be a list")
    if not isinstance(raw_placement_rules, Sequence) or isinstance(raw_placement_rules, (str, bytes)):
        fail("Kit placement_rules must be a list")

    declared_dirs: List[Dict[str, str]] = []
    kit_dir_set: Set[str] = set()
    seen_dirs: Set[str] = set()

    for idx, item in enumerate(raw_declared_dirs):
        entry = _clean_declared_dir(idx, item, fail, staging_dir=staging_dir)
        clean_dir = entry["dir"]
        kit_dir_set.add(clean_dir)
        if clean_dir not in seen_dirs:
            seen_dirs.add(clean_dir)
            declared_dirs.append(entry)

    for fixed in _FIXED_FALLBACK_DECLARED_DIRS:
        if fixed["dir"] not in seen_dirs:
            seen_dirs.add(fixed["dir"])
            declared_dirs.append(dict(fixed))

    placement_rules = [
        _clean_placement_rule(idx, pr, kit_dir_set, fail, staging_dir=staging_dir)
        for idx, pr in enumerate(raw_placement_rules)
    ]

    raw_spec: Dict[str, Any] = {
        "project_slug": slug,
        "declared_dirs": declared_dirs,
        "folder_rules": [],
        "placement_rules": placement_rules,
        "ignore_patterns": list(_EMPTY_PROJECT_IGNORE_PATTERNS),
        "lfs_patterns": [],
    }
    try:
        return validate_rules_spec(raw_spec)
    except SafetyError as exc:
        fail(f"Invalid kit rules specification: {exc}", exc)


def propose_kit(
    kit_id: str,
    name: str,
    answers: Mapping[str, Any],
    *,
    dest_root: Optional[os.PathLike[str] | str] = None,
    staging_parent: Optional[os.PathLike[str] | str] = None,
    variables: Optional[Dict[str, str]] = None,
    bridge: Optional[Any] = None,
    timeout_s: Optional[float] = None,
    clock: Optional[Callable[[], float]] = None,
) -> KitProposal:
    """Stage a componentize kit into a temporary staging directory and return a KitProposal."""
    from .catalog_list import coming_soon_message

    refusal = coming_soon_message("kit", kit_id)
    if refusal:
        raise ScaffoldError(refusal)
    eff_bridge = bridge if bridge is not None else componentize_bridge
    now_fn = clock if clock is not None else time.monotonic
    deadline: Optional[float] = None
    if timeout_s is not None:
        if timeout_s <= 0:
            raise ScaffoldTimeout("Scaffold propose timeout_s must be positive")
        deadline = now_fn() + float(timeout_s)

    try:
        slug = slugify(name)
    except ValueError as exc:
        raise ScaffoldError(str(exc)) from exc
    _validate_single_path_component(slug, "project slug")

    target_root = _lexical_abs(dest_root) if dest_root is not None else _lexical_abs(projects_root())
    _check_not_live_hermes(target_root, role="dest_root")
    folder = kit_folder_name(name, slug)
    _validate_single_path_component(folder, "project folder name")
    dest_path = target_root / folder
    _check_not_live_hermes(dest_path, role="dest")
    if os.path.lexists(dest_path):
        raise ScaffoldError(f"Destination already exists: {dest_path}")

    stage: Optional[_KitStage] = None
    if staging_parent is not None:
        stage_base = _lexical_abs(staging_parent)
        _check_not_live_hermes(stage_base, role="staging_parent")
        stage_base.mkdir(parents=True, exist_ok=True)
        try:
            staging_dir = Path(tempfile.mkdtemp(prefix="adopt-scaffold-", dir=str(stage_base)))
        except OSError as exc:
            raise ScaffoldError(
                f"Cannot create a staging folder in {stage_base} ({exc.strerror or exc}); set TMPDIR to a writable folder"
            ) from exc
    else:
        staging_dir, stage = _make_kit_stage(target_root)
    try:
        try:
            staged = verify_nofollow_within_root(staging_dir, slug)
        except SafetyError as exc:
            raise ScaffoldError(str(exc)) from exc
        _verify_kit_stage(stage, staged)

        if deadline is not None:
            rem_apply: Optional[float] = _check_deadline(now_fn, deadline, f"before apply {slug}")
            if _accepts_timeout(eff_bridge.kit_apply):
                apply_res = eff_bridge.kit_apply(kit_id, staged, variables, timeout=rem_apply)
            else:
                apply_res = eff_bridge.kit_apply(kit_id, staged, variables)
        else:
            apply_res = eff_bridge.kit_apply(kit_id, staged, variables)
        data = _verify_bridge_envelope("apply", kit_id, apply_res)
        if deadline is not None:
            _check_deadline(now_fn, deadline, f"after apply {slug}")

        try:
            verified_staged = verify_nofollow_within_root(staging_dir, slug)
        except SafetyError as exc:
            raise ScaffoldError(str(exc)) from exc
        if not _is_non_symlink_dir(verified_staged):
            raise ScaffoldError(
                f"Staged kit folder does not exist or is not a directory: {staged}"
            )
        _verify_kit_stage(stage, staged)

        tree = _build_proposed_tree(staged)
        declared_dirs = [
            dict(d) if isinstance(d, Mapping) else d
            for d in (data.get("declared_dirs") or [])
        ]
        placement_rules = [
            dict(r) if isinstance(r, Mapping) else r
            for r in (data.get("placement_rules") or [])
        ]
        dest_anchor = _dest_anchor(dest_path)
    except BaseException:
        _remove_kit_stage(stage, staging_dir, report=False)  # keep the original error
        raise

    return KitProposal(
        kit_id=kit_id,
        slug=slug,
        display_name=name.strip() or slug,
        dest=dest_path,
        staging_dir=staging_dir,
        staged=staged,
        tree=tree,
        declared_dirs=declared_dirs,
        placement_rules=placement_rules,
        answers=dict(answers),
        plugin_commit=resolve_plugin_commit(),
        stage=stage,
        folder_note=_kit_folder_note(name, folder),
        dest_anchor=dest_anchor,
    )


def _kit_folder_note(name: str, folder: str) -> str:
    from .scaffolder import folder_name_note

    return folder_name_note(name, folder, proven=UNICODE_FOLDER_KITS)


def discard_kit(proposal: KitProposal) -> None:
    """Remove the kit proposal's staging directory: only the exact folder propose created."""
    stage = getattr(proposal, "stage", None)
    if stage is not None:
        if stage.parent_fd is not None:
            _remove_kit_stage(stage, proposal.staging_dir)
        return
    if proposal.staging_dir and os.path.lexists(proposal.staging_dir):
        shutil.rmtree(proposal.staging_dir, ignore_errors=True)


def accept_kit(
    proposal: KitProposal,
    *,
    register: Callable[[str, str], str] = default_project_create,
    git: Callable[..., subprocess.CompletedProcess[bytes]] = run_git_hardened,
    db_path: Optional[Path | str] = None,
    timeout_s: float = 60.0,
    clock: Optional[Callable[[], float]] = None,
    cancel: Any = None,
    bridge: Optional[Any] = None,
) -> AcceptResult:
    """Verify staged kit, write rules and AGENTS.md preserving kit block, move to dest, git commit, and record trust."""
    eff_bridge = bridge if bridge is not None else componentize_bridge
    now_fn = clock if clock is not None else time.monotonic
    deadline = now_fn() + float(timeout_s)

    if timeout_s <= 0:
        raise ScaffoldTimeout(
            "Scaffold accept timeout_s must be positive",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        )

    _check_cancelled(cancel, proposal.staging_dir, step="start")
    _check_deadline(now_fn, deadline, "start", staging_dir=proposal.staging_dir, keep_staging=True)

    _check_not_live_hermes(proposal.dest, role="dest")
    _check_dest_anchor(proposal)
    if os.path.lexists(proposal.dest):
        raise ScaffoldError(
            f"Destination already exists: {proposal.dest}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        )
    if not _is_non_symlink_dir(proposal.staged):
        raise ScaffoldError(
            f"Staged directory missing for {proposal.slug}: {proposal.staged}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        )

    _check_staged_kit_for_accept(
        proposal, bridge=eff_bridge, cancel=cancel, now_fn=now_fn, deadline=deadline
    )
    _write_staged_kit_rules(proposal)

    # fail if destination now exists; move staged to destination
    _check_cancelled(cancel, proposal.staging_dir, step=f"before move {proposal.slug}")
    _check_deadline(
        now_fn,
        deadline,
        f"before move {proposal.slug}",
        staging_dir=proposal.staging_dir,
        keep_staging=True,
    )
    _check_not_live_hermes(proposal.dest, role="dest")
    if os.path.lexists(proposal.dest):
        raise ScaffoldError(
            f"Destination already exists: {proposal.dest}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        )

    _verify_kit_stage(getattr(proposal, "stage", None), proposal.staged, keep_staging=True)
    accepted_repos: List[Dict[str, Any]] = []
    created_dirs: List[Path] = []
    stage = getattr(proposal, "stage", None)
    if stage is not None and stage.parent_fd is not None:
        pinned_parent = _make_pinned_dest_parent(proposal)
        _move_pinned_into_place(stage, proposal.slug, proposal.dest, pinned_parent)
    else:
        anchor_lex, anchor_real, _dev, _ino = _check_dest_anchor(proposal)
        landed = Path(anchor_real).joinpath(*_dest_parent_parts(proposal, anchor_lex), proposal.dest.name)
        plan = RepoPlan(
            name=proposal.slug, dest=proposal.dest, staged=proposal.staged, tree=[], dest_anchor=proposal.dest_anchor
        )
        try:
            _publish_staged_repo(plan)
        except ScaffoldError as exc:
            if os.path.lexists(proposal.staged):  # not moved: nothing was created
                raise ScaffoldError(str(exc), staging_dir=proposal.staging_dir, keep_staging=True) from exc
            partial = ScaffoldError(
                _MOVE_PARTIAL.format(path=proposal.dest, landed=landed),
                staging_dir=proposal.staging_dir,
                keep_staging=True,
            )
            _mark_created(partial, landed)
            raise partial from exc
    created_dirs.append(proposal.dest)
    try:
        return _finish_kit_accept(
            proposal,
            register=register,
            git=git,
            db_path=db_path,
            now_fn=now_fn,
            deadline=deadline,
            created_dirs=created_dirs,
            accepted_repos=accepted_repos,
        )
    except BaseException as exc:
        _mark_created(exc, proposal.dest)  # the project folder exists: the caller must not report "nothing created"
        raise


def _check_staged_kit_for_accept(
    proposal: KitProposal,
    *,
    bridge: Any,
    cancel: Any,
    now_fn: Callable[[], float],
    deadline: float,
) -> None:
    """Check the staged kit with the companion, preserving cancellation and timeout checks."""
    _check_cancelled(cancel, proposal.staging_dir, step=f"check {proposal.slug}")
    _verify_kit_stage(getattr(proposal, "stage", None), proposal.staged, keep_staging=True)
    rem_check = _check_deadline(
        now_fn,
        deadline,
        f"before check {proposal.slug}",
        staging_dir=proposal.staging_dir,
        keep_staging=True,
    )
    # A cancel hook reaches the companion run only when kit_check takes one (it stops the run).
    check_kw: Dict[str, Any] = {"cancel": cancel} if cancel is not None and _accepts_kw(bridge.kit_check, "cancel") else {}
    if _accepts_timeout(bridge.kit_check):
        check_res = bridge.kit_check(proposal.kit_id, proposal.staged, timeout=rem_check, **check_kw)
    else:
        check_res = bridge.kit_check(proposal.kit_id, proposal.staged, **check_kw)
    _check_cancelled(cancel, proposal.staging_dir, step=f"check {proposal.slug}")
    try:
        _verify_bridge_envelope(
            "check",
            proposal.kit_id,
            check_res,
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        )
    except KitUnavailable:
        raise
    except ScaffoldError as exc:
        # The shown message is the only check text classified; the note adds constant words only.
        shown = str(exc)
        if not looks_like_network_failure(shown):
            raise
        untouched = not _same_or_inside(
            os.path.abspath(proposal.staging_dir), os.path.abspath(proposal.dest.parent)
        )
        raise ScaffoldError(
            f"{shown}\n{network_required_note(projects_untouched=untouched)}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
            reason=NETWORK_REQUIRED_REASON,
        ) from exc
    _check_cancelled(cancel, proposal.staging_dir, step=f"after check {proposal.slug}")
    _check_deadline(
        now_fn,
        deadline,
        f"after check {proposal.slug}",
        staging_dir=proposal.staging_dir,
        keep_staging=True,
    )



def _write_staged_kit_rules(proposal: KitProposal) -> None:
    """Write validated rules and preserve the kit's AGENTS.md block before publication."""
    rules = _build_kit_rules(
        proposal.slug,
        proposal.declared_dirs,
        proposal.placement_rules,
        staging_dir=proposal.staging_dir,
    )
    try:
        for folder in ("_inbox", ".adopt", *(d["dir"] for d in rules["declared_dirs"])):
            safe_mkdirs(proposal.staged, folder)
        if not os.path.lexists(proposal.staged / "_inbox" / ".gitkeep"):
            safe_write_text(proposal.staged, "_inbox/.gitkeep", "")
        safe_write_bytes(
            proposal.staged,
            ".adopt/rules.json",
            (json.dumps(rules, indent=2) + "\n").encode("utf-8"),
            overwrite=False,
        )
        _sync_staged_gitignore(proposal.staged, rules.get("ignore_patterns") or ())
    except (SafetyError, OSError) as exc:
        raise ScaffoldError(
            f"Failed to write rules in staged kit {proposal.staged}: {exc}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        ) from exc

    # write_agents_md preserving kit block
    try:
        agents_res = write_agents_md(proposal.staged, rules, preserve_kit_blocks=True)
    except (SafetyError, OSError, ValueError) as exc:
        raise ScaffoldError(
            f"Failed to write AGENTS.md in staged kit {proposal.staged}: {exc}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        ) from exc
    dropped_kits = list(agents_res.get("kit_blocks_dropped") or ())
    preserved_kits = list(agents_res.get("kit_blocks_preserved") or ())
    if dropped_kits or proposal.kit_id not in preserved_kits:
        raise ScaffoldError(
            f"Kit {proposal.kit_id!r} AGENTS.md section is missing or damaged "
            f"(preserved={preserved_kits}, dropped={dropped_kits})",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        )


def _finish_kit_accept(
    proposal: KitProposal,
    *,
    register: Callable[[str, str], str],
    git: Callable[..., subprocess.CompletedProcess[bytes]],
    db_path: Optional[Path | str],
    now_fn: Callable[[], float],
    deadline: float,
    created_dirs: List[Path],
    accepted_repos: List[Dict[str, Any]],
) -> AcceptResult:
    """Steps after the project is in place: git commit, registration, state records, staging cleanup."""

    template_id = f"kit:{proposal.kit_id}"
    effective_plugin_commit = (
        proposal.plugin_commit
        if proposal.plugin_commit and proposal.plugin_commit != "unknown"
        else resolve_plugin_commit()
    )

    # initialize git repository and create single initial commit
    commit_sha = _init_and_commit_dest_repo(
        git,
        proposal.dest,
        template_id,
        now_fn=now_fn,
        deadline=deadline,
        created_dirs=created_dirs,
        accepted_repos=accepted_repos,
    )

    # attempt project registration
    _check_deadline(now_fn, deadline, f"before register {proposal.slug}", created_dirs=created_dirs)
    reg_name = proposal.display_name or proposal.slug
    reg_status, registration_reason, hermes_project_id = _attempt_project_registration(
        register, reg_name, proposal.dest
    )
    _check_deadline(now_fn, deadline, f"after register {proposal.slug}", created_dirs=created_dirs)

    # record project in state_store with rules_hash so placement trusts it
    try:
        rules_hash = compute_rules_hash(proposal.dest)
        record_project(
            path=proposal.dest,
            name=reg_name,
            slug=proposal.slug,
            template_id=template_id,
            answers=proposal.answers,
            hermes_project_id=hermes_project_id,
            db_path=db_path,
            rules_hash=rules_hash,
            plugin_commit=effective_plugin_commit,
        )
    except Exception as exc:
        _raise_scaffold_error(
            "Could not save the new project in the project list. " + _AFTER_MOVE_NOTE.format(path=proposal.dest),
            accepted_repos,
            cause=exc,
        )
    _check_deadline(now_fn, deadline, f"after record_project {proposal.slug}", created_dirs=created_dirs)

    repo_entry: Dict[str, Any] = {
        "path": str(proposal.dest),
        "registration": reg_status,
        "registration_result": {"registered": registration_reason is None, "reason": registration_reason},
        "registration_name": reg_name,
        "hermes_project_id": hermes_project_id,
        "commit": commit_sha,
        "template_id": template_id,
        "kit_id": proposal.kit_id,
        "rules_hash": rules_hash,
        "plugin_commit": effective_plugin_commit,
    }
    if registration_reason is not None:
        repo_entry["registration_reason"] = registration_reason
    accepted_repos.append(repo_entry)

    # save answers
    try:
        answers_id = save_answers(proposal.answers, project_path=str(proposal.dest), db_path=db_path)
    except Exception as exc:
        _raise_scaffold_error(
            "Could not save the answers for the new project. " + _AFTER_MOVE_NOTE.format(path=proposal.dest),
            accepted_repos,
            cause=exc,
        )
    _check_deadline(now_fn, deadline, "after save_answers", created_dirs=created_dirs)

    # remove staging directory (the project exists now: a foreign stage name is left alone, not an error)
    stage = getattr(proposal, "stage", None)
    if stage is not None:
        if stage.parent_fd is not None:
            _remove_kit_stage(stage, proposal.staging_dir, report=False)
    else:
        discard_kit(proposal)
    return AcceptResult(repos=accepted_repos, answers_id=answers_id)
