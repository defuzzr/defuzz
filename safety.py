"""Hard safety invariants for Project Defuzz.

Rules enforced here:
- Work only on a copy. Source, staging and output roots must be disjoint; refuse if they overlap.
- Never write to, rename or delete anything in the source folder. Never delete anywhere.
- Do not follow symlinks out of the copy; create files no-follow.
- Refuse worktree gitfiles, submodules and git alternates (v1).
- Never print secrets.
- No writes to ~/.hermes.
- Hardened git invocations only (no hooks, no smudge/clean filters, no network, literal pathspecs).
"""

from __future__ import annotations

import errno
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class SafetyError(RuntimeError):
    """Raised when an operation violates a Project Defuzz safety invariant."""


class GitUnavailableError(SafetyError):
    """Raised when git is missing from PATH or older than MIN_GIT_VERSION."""


# `git restore --source=HEAD --worktree` (scaffolder) is the newest git feature used
# without a fallback (Git 2.23.0); `--no-optional-locks` needs 2.15 and `init -b` falls back.
MIN_GIT_VERSION: Tuple[int, int, int] = (2, 23, 0)
_MIN_GIT_TEXT = ".".join(str(part) for part in MIN_GIT_VERSION)
# Resolved git executable -> version already accepted (checked once per binary).
_GIT_CHECKED: Dict[str, Tuple[int, int, int]] = {}


def _lexical_abs(path: os.PathLike | str) -> Path:
    """Return lexical absolute path WITHOUT resolving a final symlink."""
    raw = os.path.abspath(os.path.expanduser(os.fspath(path)))
    return Path(raw)


def _real_parent_bound(path: os.PathLike | str) -> Path:
    """Resolve all aliases, including a symlink at the leaf."""
    return Path(os.path.realpath(os.path.expanduser(os.fspath(path))))


def _is_same_or_subpath(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def resolve_hermes_home(ctx: Any = None) -> Path:
    """Resolve the active Hermes home directory via hermes_constants.get_hermes_home(), $HERMES_HOME, or ~/.hermes."""
    _ = ctx
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        home = get_hermes_home()
        if home:
            return Path(home).expanduser()
    except Exception:
        pass
    raw = os.environ.get("HERMES_HOME", "").strip()
    if raw:
        return Path(os.path.expandvars(raw)).expanduser()
    return Path(os.path.expanduser("~/.hermes"))


def _hermes_live_root(ctx: Any = None) -> Path:
    return resolve_hermes_home(ctx=ctx)


def _hermes_scratch_root(live_root: Optional[Path] = None) -> Path:
    base = live_root if live_root is not None else _hermes_live_root()
    return base / "cache" / "scratch"


def _protected_hermes_roots(
    *,
    ctx: Any = None,
    protected_roots: Optional[Iterable[os.PathLike | str]] = None,
) -> List[Path]:
    roots: List[Path] = [resolve_hermes_home(ctx=ctx)]
    env_raw = os.environ.get("HERMES_HOME", "").strip()
    if env_raw:
        roots.append(Path(os.path.expandvars(env_raw)).expanduser())
    roots.append(Path(os.path.expanduser("~/.hermes")))
    if protected_roots is not None:
        for r in protected_roots:
            roots.append(Path(os.path.expandvars(os.path.expanduser(os.fspath(r)))))

    expanded: List[Path] = []
    seen: set[str] = set()
    for r in roots:
        for variant in (_lexical_abs(r), _real_parent_bound(r)):
            key = str(variant)
            if key not in seen:
                seen.add(key)
                expanded.append(variant)
    return expanded


def assert_not_live_hermes(
    path: os.PathLike | str,
    role: str = "target",
    *,
    ctx: Any = None,
    protected_roots: Optional[Iterable[os.PathLike | str]] = None,
) -> None:
    """Refuse any path inside active/custom/default Hermes home (except cache/scratch for temp tests)."""
    protected = _protected_hermes_roots(ctx=ctx, protected_roots=protected_roots)
    for candidate in (_lexical_abs(path), Path(os.path.realpath(os.path.expanduser(os.fspath(path))))):
        for live in protected:
            if _is_same_or_subpath(candidate, live):
                scratch = _hermes_scratch_root(live)
                if _is_same_or_subpath(candidate, scratch):
                    continue
                raise SafetyError(f"Refusing {role} path inside live ~/.hermes ({live}): {path}")


def assert_safe_root(
    path: os.PathLike | str,
    role: str = "root",
    *,
    ctx: Any = None,
    protected_roots: Optional[Iterable[os.PathLike | str]] = None,
) -> Path:
    """Verify that a root path is not '/', $HOME, or inside live ~/.hermes."""
    lex = _lexical_abs(path)
    real = _real_parent_bound(path)
    home_lex = _lexical_abs(os.path.expanduser("~"))
    home_real = Path(os.path.expanduser("~")).resolve()
    for p in (lex, real):
        if p == Path("/") or p == home_lex or p == home_real or p.parent == p:
            raise SafetyError(f"Refusing {role} at filesystem or home root: {path}")

    assert_not_live_hermes(path, role=role, ctx=ctx, protected_roots=protected_roots)
    return lex


def assert_disjoint_roots(
    *,
    source: Optional[os.PathLike | str] = None,
    staging: Optional[os.PathLike | str] = None,
    output: Optional[os.PathLike | str] = None,
) -> Dict[str, Path]:
    """Ensure source, staging, and output roots are pairwise disjoint (neither equal nor nested)."""
    present: List[Tuple[str, Path, Path]] = []
    out: Dict[str, Path] = {}
    for role, val in (("source", source), ("staging", staging), ("output", output)):
        if val is None:
            continue
        lex = assert_safe_root(val, role=role)
        real = _real_parent_bound(val)
        present.append((role, lex, real))
        out[role] = lex

    for i in range(len(present)):
        role_a, lex_a, real_a = present[i]
        for j in range(i + 1, len(present)):
            role_b, lex_b, real_b = present[j]
            for a in (lex_a, real_a):
                for b in (lex_b, real_b):
                    if _is_same_or_subpath(a, b) or _is_same_or_subpath(b, a):
                        raise SafetyError(
                            f"Refusing overlapping roots ({role_a}={lex_a} vs {role_b}={lex_b}): "
                            "source, staging, and output roots must be disjoint."
                        )
    return out


def verify_nofollow_within_root(root: os.PathLike | str, rel_path: str) -> Path:
    """Verify rel_path stays strictly inside root and traverses zero symlinks along existing components."""
    root_lex = _lexical_abs(root)
    if os.path.islink(root_lex):
        raise SafetyError(f"Root itself is a symlink: {root_lex}")

    if not rel_path or rel_path in (".", "/"):
        raise SafetyError(f"Invalid relative path: {rel_path!r}")
    norm = os.path.normpath(rel_path)
    if norm.startswith("..") or norm.startswith("/") or norm.startswith("\\") or ".." in Path(norm).parts:
        raise SafetyError(f"Path escapes root: {rel_path!r}")

    current = root_lex
    parts = Path(norm).parts
    for part in parts:
        if part in ("", ".", ".."):
            raise SafetyError(f"Invalid path segment {part!r} in {rel_path!r}")
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            raise SafetyError(f"Refusing to traverse or overwrite symlink inside copy: {current}")
    return root_lex / norm


# The descriptor-relative helpers used below (PinnedFolder, _walk_dirs, _write_leaf,
# _open_copy_destination, _copy_walk) are defined at the end of this module, together with the
# platform check they rely on.
def safe_mkdirs(root: os.PathLike | str, rel_dir: str = ".", *, base: Any = None) -> Path:
    """Create directories under root without following symlinks.

    Trust rule: `base` is the folder the person chose (default: root itself). It may be
    reached through links they made: it is opened once through its real path, one folder at a
    time without following links, and checked to be the same folder that was resolved. Any
    folder of `base` that is missing is created there. Everything below `base` (the folders up
    to root, then rel_dir) is opened or created relative to its parent's handle with
    O_NOFOLLOW, so a link there, or a folder swapped for a link after a check, is refused.
    A root that is itself a link is refused.
    """
    root_lex = assert_safe_root(root, role="output")
    if os.path.islink(root_lex):
        raise SafetyError(f"Refusing symlink root: {root_lex}")
    parts: Tuple[str, ...] = ()
    if rel_dir not in ("", "."):
        norm = os.path.normpath(rel_dir)
        if norm.startswith("..") or os.path.isabs(norm) or ".." in Path(norm).parts:
            raise SafetyError(f"Directory escapes root: {rel_dir!r}")
        parts = Path(norm).parts
    _require_dir_fd(root_lex)
    fd, cur = _walk_dirs(root_lex, parts, mode=0o755, base=base)
    os.close(fd)
    return cur


def safe_write_bytes(
    root: os.PathLike | str,
    rel_path: str,
    data: bytes,
    *,
    overwrite: bool = False,
    mode: int = 0o644,
    base: Any = None,
) -> Path:
    """Write bytes to root/rel_path through no-follow folder handles.

    overwrite=False creates the file exclusively (refused when anything exists there).
    overwrite=True replaces a regular file atomically through a temporary sibling and keeps
    its permission bits; a link, FIFO, device or folder at the name is refused. The
    existing name is never opened, so a FIFO cannot block the write and the other names
    of a hard-linked file keep their bytes. A temporary file is removed on failure.
    Folders, the root and `base` follow the safe_mkdirs rules.
    """
    assert_not_live_hermes(root, role="write_root")
    target = verify_nofollow_within_root(root, rel_path)
    parts = Path(os.path.normpath(rel_path)).parts
    root_lex = assert_safe_root(root, role="output")
    if os.path.islink(root_lex):
        raise SafetyError(f"Refusing symlink root: {root_lex}")
    _require_dir_fd(target)
    fd, _parent = _walk_dirs(root_lex, parts[:-1], mode=0o755, base=base)
    try:
        _write_leaf(fd, parts[-1], target, data, overwrite=overwrite, mode=mode)
    finally:
        os.close(fd)
    return target


def safe_write_text(
    root: os.PathLike | str,
    rel_path: str,
    text: str,
    *,
    overwrite: bool = False,
    mode: int = 0o644,
    base: Any = None,
) -> Path:
    """Write UTF-8 text to root/rel_path with no-follow semantics."""
    return safe_write_bytes(root, rel_path, text.encode("utf-8"), overwrite=overwrite, mode=mode, base=base)


def safe_rename(root: os.PathLike | str, src_rel: str, dst_rel: str, *, base: Any = None) -> Path:
    """Move root/src_rel to root/dst_rel through no-follow folder handles (both inside root).

    The parent folders are opened without following links (the destination's are created);
    the folder (or base) is opened once and used for both names. The name moved is never
    followed, and an existing destination name is refused, also one created at the last
    moment (Linux renameat2 RENAME_NOREPLACE; where the filesystem cannot do that, only the
    check just before the move applies).
    """
    root_lex = assert_safe_root(root, role="output")
    src_target = verify_nofollow_within_root(root_lex, src_rel)
    dst_target = verify_nofollow_within_root(root_lex, dst_rel)
    src_parts = Path(os.path.normpath(src_rel)).parts
    dst_parts = Path(os.path.normpath(dst_rel)).parts
    _require_dir_fd(root_lex)
    occupied = f"Refusing to move onto an existing name: {dst_target}"
    pin, owned, _between = _below_base(root_lex, base)
    try:
        sfd, _ = _walk_dirs(root_lex, src_parts[:-1], mode=0o755, base=pin, create=False)
        try:
            dfd, _ = _walk_dirs(root_lex, dst_parts[:-1], mode=0o755, base=pin)
            try:
                try:
                    os.stat(dst_parts[-1], dir_fd=dfd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise SafetyError(occupied)
                try:
                    if not _rename_noreplace(sfd, src_parts[-1], dfd, dst_parts[-1]):
                        os.rename(src_parts[-1], dst_parts[-1], src_dir_fd=sfd, dst_dir_fd=dfd)
                except FileExistsError as exc:
                    raise SafetyError(occupied) from exc
                except OSError as exc:
                    raise SafetyError(f"Could not move ({exc.strerror or exc}): {src_target}") from exc
            finally:
                os.close(dfd)
        finally:
            os.close(sfd)
    finally:
        if owned:
            pin.close()
    return dst_target


_RENAME_NOREPLACE = 1  # linux/fs.h
_RENAMEAT2: List[Any] = []


def _rename_noreplace(src_fd: int, src_name: str, dst_fd: int, dst_name: str) -> bool:
    """Move src_name to dst_name (both relative to folder handles) without replacing an existing name.

    Linux renameat2(RENAME_NOREPLACE): an existing destination raises FileExistsError.
    Returns False, having done nothing, when this system or filesystem cannot do it.
    """
    if not _RENAMEAT2:
        try:
            import ctypes

            fn = ctypes.CDLL(None, use_errno=True).renameat2
            fn.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            fn.restype = ctypes.c_int
            _RENAMEAT2.append((ctypes, fn))
        except (ImportError, OSError, AttributeError):
            _RENAMEAT2.append(None)
    if _RENAMEAT2[0] is None:
        return False
    ctypes, fn = _RENAMEAT2[0]
    sys.audit("os.rename", src_name, dst_name, src_fd, dst_fd)
    if fn(src_fd, os.fsencode(src_name), dst_fd, os.fsencode(dst_name), _RENAME_NOREPLACE) == 0:
        return True
    err = ctypes.get_errno()
    if err in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
        return False
    raise OSError(err, os.strerror(err), src_name)


def copy_tree_nofollow(
    source_root: os.PathLike | str,
    copy_root: os.PathLike | str,
    *,
    staging_root: Optional[os.PathLike | str] = None,
    include_secret_files: bool = False,
    left_behind: Optional[List[str]] = None,
    base: Any = None,
) -> Path:
    """Create a read-only-source, no-follow copy of source_root at copy_root.

    - Source, staging, and copy roots must be disjoint (also checked on the opened real folders).
    - Secret-named regular files and symlinks (scanner._is_secret_filename) are not
      copied unless include_secret_files=True; real directories are ordinary directories.
    - Symlinks are copied as symlinks (raw link target preserved, never followed).
    - Source folder is never modified.
    - Refuses if copy_root already exists and is non-empty, or is a link.
    - `base` (default: copy_root) is the folder the person chose; it follows the safe_mkdirs
      trust rule. The source root follows the same rule (it must exist and not be a link).
    - Both trees are walked through folder handles: a folder swapped for a link or another
      folder mid-copy stops the copy (SafetyError); nothing already copied is deleted. Only a
      bounded number of folder handles is held, however deep the tree.
    """
    roots = assert_disjoint_roots(source=source_root, staging=staging_root, output=copy_root)
    src = roots["source"]
    dst = roots["output"]

    if not src.exists() or os.path.islink(src) or not src.is_dir():
        raise SafetyError(f"Source root must be an existing non-symlink directory: {src}")
    _require_dir_fd(dst)

    skipped_secrets: List[str] = []
    with PinnedFolder(src, role="source", create=False) as src_pin:
        dst_fd, dst_real = _open_copy_destination(dst, base)
        try:
            assert_disjoint_roots(source=src_pin.real, staging=staging_root, output=dst_real)
            _copy_walk(src_pin, dst_fd, src, dst, include_secret_files, skipped_secrets)
        finally:
            _close_quietly(dst_fd)

    if left_behind is not None:
        left_behind.clear()
        left_behind.extend(sorted(skipped_secrets))

    return dst


_MAX_GIT_CONFIG_BYTES: int = 1024 * 1024

_FILTER_PROGRAM_KEYS: frozenset[str] = frozenset({"clean", "smudge", "process"})

# Repository-level command hooks that cannot be cleanly cleared via `git -c key=`:
# - `core.alternateRefsCommand=`: git attempts execvp("", ...) when alternates exist.
# - `core.gitProxy=`: multi-valued in git's connect.c; `-c core.gitProxy=` appends instead of clearing.
# - `uploadpack.packObjectsHook`: server-side pack hook, never needed in ordinary project repos.
_UNOVERRIDEABLE_SECTION_KEYS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("core", "alternaterefscommand"): ("a command hook", "core.alternateRefsCommand"),
    ("core", "gitproxy"): ("a command hook", "core.gitProxy"),
    ("uploadpack", "packobjectshook"): ("a command hook", "uploadpack.packObjectsHook"),
}

_FALSE_GIT_BOOL_VALUES: frozenset[str] = frozenset({"false", "no", "off", "0", ""})

_GIT_CONFIG_ESCAPES: Dict[str, str] = {"n": "\n", "t": "\t", "b": "\b", "\\": "\\", '"': '"'}


def format_unsafe_repo_git_settings_message(matches: Sequence[Tuple[str, str]]) -> str:
    """Format a plain-English refusal message naming the un-overrideable kind(s) and key(s) found."""
    kinds: List[str] = []
    keys: List[str] = []
    for kind_label, key_label in matches:
        if kind_label not in kinds:
            kinds.append(kind_label)
        if key_label not in keys:
            keys.append(key_label)
    if not kinds:
        kind_text = "an unsafe setting"
    elif len(kinds) == 1:
        kind_text = kinds[0]
    elif len(kinds) == 2:
        kind_text = f"{kinds[0]} and {kinds[1]}"
    else:
        kind_text = ", ".join(kinds[:-1]) + f", and {kinds[-1]}"
    keys_text = ", ".join(keys)
    return (
        f"This repository's own git settings include {kind_text} ({keys_text}), "
        "which can run programs and cannot be switched off from outside. "
        "Defuzz will not run git in it. "
        "Remove that setting in the copy, or adopt a copy without its .git folder."
    )


class _GitConfigParseError(ValueError):
    """Raised when a repository git config file is non-regular, unreadable, or malformed."""


def _read_git_file_nofollow(path: Path, max_bytes: int = _MAX_GIT_CONFIG_BYTES) -> Optional[bytes]:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _GitConfigParseError(f"cannot stat {path.name}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise _GitConfigParseError(f"{path.name} is not a regular file")

    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise _GitConfigParseError(f"cannot open {path.name}: {exc}") from exc

    try:
        with os.fdopen(fd, "rb") as fh:
            fst = os.fstat(fh.fileno())
            if not stat.S_ISREG(fst.st_mode):
                raise _GitConfigParseError(f"{path.name} changed to non-regular file")
            data = fh.read(max_bytes + 1)
    except _GitConfigParseError:
        raise
    except OSError as exc:
        raise _GitConfigParseError(f"cannot read {path.name}: {exc}") from exc

    if len(data) > max_bytes:
        raise _GitConfigParseError(f"{path.name} exceeds {max_bytes} bytes")
    return data


def _skip_line_continuation(text: str, idx: int, length: int) -> int:
    if idx < length and text[idx] == "\\":
        if idx + 1 < length and text[idx + 1] == "\n":
            return idx + 2
        if idx + 2 < length and text[idx + 1] == "\r" and text[idx + 2] == "\n":
            return idx + 3
    return idx


def _parse_git_config_bytes(
    raw: bytes,
) -> Tuple[List[Tuple[str, Optional[str]]], List[Tuple[str, Optional[str], str, Optional[str]]]]:
    if b"\x00" in raw:
        raise _GitConfigParseError("NUL byte in git config")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("latin-1")
    n = len(text)
    i = 0
    current_section: Optional[Tuple[str, Optional[str]]] = None
    sections: List[Tuple[str, Optional[str]]] = []
    entries: List[Tuple[str, Optional[str], str, Optional[str]]] = []

    while i < n:
        nxt = _skip_line_continuation(text, i, n)
        if nxt != i:
            i = nxt
            continue
        ch = text[i]
        if ch in " \t\r\n\v\f":
            i += 1
            continue
        if ch in "#;":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if ch == "[":
            i += 1
            sec_start = i
            while i < n and (text[i].isalnum() or text[i] in "-."):
                i += 1
            sec_raw = text[sec_start:i]
            if not sec_raw:
                raise _GitConfigParseError("empty section header")
            while i < n and text[i] in " \t":
                i += 1
            if i < n and text[i] == '"':
                if "." in sec_raw:
                    raise _GitConfigParseError("dot in quoted section header")
                i += 1
                sub_chars: List[str] = []
                while True:
                    if i >= n or text[i] in "\r\n":
                        raise _GitConfigParseError("unterminated subsection header")
                    if text[i] == "\\":
                        i += 1
                        if i >= n or text[i] in "\r\n":
                            raise _GitConfigParseError("invalid escape in subsection header")
                        sub_chars.append(text[i])
                        i += 1
                    elif text[i] == '"':
                        i += 1
                        break
                    else:
                        sub_chars.append(text[i])
                        i += 1
                while i < n and text[i] in " \t":
                    i += 1
                if i >= n or text[i] != "]":
                    raise _GitConfigParseError("missing closing bracket after subsection")
                i += 1
                current_section = (sec_raw.lower(), "".join(sub_chars))
            elif i < n and text[i] == "]":
                i += 1
                if "." in sec_raw:
                    head, sub = sec_raw.split(".", 1)
                    if not head or not sub:
                        raise _GitConfigParseError("invalid dot subsection header")
                    current_section = (head.lower(), sub)
                else:
                    current_section = (sec_raw.lower(), None)
            else:
                raise _GitConfigParseError("malformed section header")
            sections.append(current_section)
            continue

        if ch.isalpha():
            if current_section is None:
                raise _GitConfigParseError("config variable outside section")
            key_start = i
            while i < n and (text[i].isalnum() or text[i] == "-"):
                i += 1
            key = text[key_start:i].lower()
            while i < n:
                nxt = _skip_line_continuation(text, i, n)
                if nxt != i:
                    i = nxt
                    continue
                if text[i] in " \t":
                    i += 1
                    continue
                break

            if i >= n or text[i] in "\r\n#;":
                entries.append((current_section[0], current_section[1], key, None))
                continue
            if text[i] != "=":
                raise _GitConfigParseError(f"expected '=' after key {key!r}")
            i += 1

            val_chars: List[str] = []
            pending_ws: List[str] = []
            quoted = False
            while i < n:
                nxt = _skip_line_continuation(text, i, n)
                if nxt != i:
                    i = nxt
                    continue
                vc = text[i]
                if vc == "\\":
                    i += 1
                    if i >= n or text[i] not in _GIT_CONFIG_ESCAPES:
                        raise _GitConfigParseError("invalid escape in config value")
                    val_chars.extend(pending_ws)
                    pending_ws.clear()
                    val_chars.append(_GIT_CONFIG_ESCAPES[text[i]])
                    i += 1
                elif vc == '"':
                    val_chars.extend(pending_ws)
                    pending_ws.clear()
                    quoted = not quoted
                    i += 1
                elif not quoted and vc in "#;":
                    break
                elif vc in "\r\n":
                    if quoted:
                        raise _GitConfigParseError("unterminated quote in config value")
                    i += 1
                    break
                elif not quoted and vc in " \t":
                    if val_chars:
                        pending_ws.append(vc)
                    i += 1
                else:
                    val_chars.extend(pending_ws)
                    pending_ws.clear()
                    val_chars.append(vc)
                    i += 1
            if quoted:
                raise _GitConfigParseError("unterminated quote at end of config")
            entries.append((current_section[0], current_section[1], key, "".join(val_chars)))
            continue

        raise _GitConfigParseError(f"unexpected character {ch!r} in git config")

    return sections, entries


def _forbidden_matches_in_parsed_config(
    sections: Sequence[Tuple[str, Optional[str]]],
    entries: Sequence[Tuple[str, Optional[str], str, Optional[str]]],
) -> List[Tuple[str, str]]:
    """Return (kind_label, key_label) pairs for repo git settings that cannot be overridden externally."""
    found: List[Tuple[str, str]] = []
    seen_keys: set[str] = set()
    recorded_include_sections: set[Tuple[str, Optional[str]]] = set()

    def _record(kind_label: str, key_label: str) -> None:
        if key_label not in seen_keys:
            seen_keys.add(key_label)
            found.append((kind_label, key_label))

    for sec, sub, key, _val in entries:
        if sec == "filter":
            # Exact lowercase "lfs" is Git LFS and is neutralised via `-c filter.lfs.*=`.
            # Subsection names in git config are case-sensitive, so `[filter "LFS"]` or any
            # non-lfs filter name cannot be switched off by name and must be refused.
            if sub != "lfs" and key in _FILTER_PROGRAM_KEYS:
                _record("a custom filter", f"filter.{sub}.{key}" if sub is not None else f"filter.{key}")
            continue
        if sec == "include":
            recorded_include_sections.add((sec, sub))
            _record("a config include", f"include.{sub}.{key}" if sub is not None else f"include.{key}")
            continue
        if sec == "includeif":
            recorded_include_sections.add((sec, sub))
            _record("a config include", f"includeIf.{sub}.{key}" if sub is not None else f"includeIf.{key}")
            continue
        unoverrideable = _UNOVERRIDEABLE_SECTION_KEYS.get((sec, key))
        if unoverrideable is not None:
            kind_label, canonical_key = unoverrideable
            _record(kind_label, f"{sec}.{sub}.{key}" if sub is not None else canonical_key)

    for sec, sub in sections:
        if sec in ("include", "includeif") and (sec, sub) not in recorded_include_sections:
            prefix = "includeIf" if sec == "includeif" else "include"
            _record("a config include", f"{prefix}.{sub}" if sub is not None else prefix)

    return found


def _layout_hazards_in_parsed_config(
    git_dir_full: Path,
    rel_path: str,
    entries: Sequence[Tuple[str, Optional[str], str, Optional[str]]],
) -> List[Dict[str, str]]:
    """Check for layout hazards (`core.bare=true` and `core.worktree` outside the repository)."""
    hazards: List[Dict[str, str]] = []
    saw_bare = False
    saw_worktree = False
    repo_root = git_dir_full.parent
    repo_lex = _lexical_abs(repo_root)
    repo_real = _real_parent_bound(repo_root)
    git_lex = _lexical_abs(git_dir_full)

    for sec, sub, key, val in entries:
        if sec != "core" or sub is not None:
            continue
        if key == "bare" and not saw_bare:
            if val is None or val.strip().lower() not in _FALSE_GIT_BOOL_VALUES:
                saw_bare = True
                hazards.append({
                    "kind": "bare_repo",
                    "path": rel_path,
                    "detail": "core.bare is enabled; bare repositories have no working tree and are refused in v1",
                })
        elif key == "worktree" and not saw_worktree:
            if val is None or not val.strip() or val.startswith("~"):
                saw_worktree = True
                hazards.append({
                    "kind": "external_worktree",
                    "path": rel_path,
                    "detail": "core.worktree is invalid or outside the repository root, refused in v1",
                })
                continue
            candidate = Path(val) if os.path.isabs(val) else (git_dir_full / val)
            wt_lex = _lexical_abs(candidate)
            wt_real = _real_parent_bound(candidate)
            if (
                not _is_same_or_subpath(wt_lex, repo_lex)
                or not _is_same_or_subpath(wt_real, repo_real)
                or _is_same_or_subpath(wt_lex, git_lex)
            ):
                saw_worktree = True
                hazards.append({
                    "kind": "external_worktree",
                    "path": rel_path,
                    "detail": "core.worktree points outside the repository root, refused in v1",
                })
    return hazards


def inspect_git_config_dir_refusals(git_dir_full: Path, git_rel: str = ".git") -> List[Dict[str, str]]:
    """Inspect .git/config and .git/config.worktree without running git; return refusal dicts if unsafe."""
    refusals: List[Dict[str, str]] = []
    for cfg_name in ("config", "config.worktree"):
        cfg_path = git_dir_full / cfg_name
        rel_path = f"{git_rel}/{cfg_name}"
        try:
            raw = _read_git_file_nofollow(cfg_path)
            if raw is None:
                continue
            sections, entries = _parse_git_config_bytes(raw)
        except _GitConfigParseError as exc:
            refusals.append({
                "kind": "unsafe_git_config",
                "path": rel_path,
                "detail": (
                    f"This repository's own git config cannot be safely parsed ({exc}). "
                    "Defuzz will not run git in it. "
                    "Fix or remove that file in the copy, or adopt a copy without its .git folder."
                ),
            })
            continue
        matches = _forbidden_matches_in_parsed_config(sections, entries)
        if matches:
            refusals.append({
                "kind": "unsafe_git_config",
                "path": rel_path,
                "detail": format_unsafe_repo_git_settings_message(matches),
            })
        refusals.extend(_layout_hazards_in_parsed_config(git_dir_full, rel_path, entries))
    return refusals


def _assert_safe_single_repo_root(repo_lex: Path) -> None:
    if os.path.lexists(repo_lex / ".gitmodules"):
        raise SafetyError(
            "Unsupported Git layout (v1 refusal): submodule at .gitmodules: "
            ".gitmodules present; submodules are refused in v1"
        )

    dot_git = repo_lex / ".git"
    try:
        st = os.lstat(dot_git)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SafetyError(f"Cannot inspect {dot_git}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise SafetyError("Unsupported Git layout (v1 refusal): worktree_gitfile at .git: .git is a symlink, refused in v1")
    if not stat.S_ISDIR(st.st_mode):
        raise SafetyError(
            "Unsupported Git layout (v1 refusal): worktree_gitfile at .git: "
            ".git is a file (worktree gitfile or submodule gitdir pointer), refused in v1"
        )

    alt_file = dot_git / "objects" / "info" / "alternates"
    if os.path.lexists(alt_file):
        try:
            alt_raw = _read_git_file_nofollow(alt_file) or b""
        except _GitConfigParseError as exc:
            raise SafetyError(f"Unsupported Git layout (v1 refusal): git_alternates at .git/objects/info/alternates: {exc}") from exc
        alt_text = alt_raw.decode("utf-8", errors="replace")
        if any(ln.strip() and not ln.strip().startswith("#") for ln in alt_text.splitlines()):
            raise SafetyError(
                "Unsupported Git layout (v1 refusal): git_alternates at .git/objects/info/alternates: "
                "Git object alternates present; shared object stores are refused in v1"
            )

    worktrees_dir = dot_git / "worktrees"
    if os.path.lexists(worktrees_dir):
        if os.path.islink(worktrees_dir):
            raise SafetyError("Unsupported Git layout (v1 refusal): worktree_gitfile at .git/worktrees: symlink refused in v1")
        if worktrees_dir.is_dir():
            try:
                has_entries = any(True for _ in worktrees_dir.iterdir())
            except OSError:
                has_entries = True
            if has_entries:
                raise SafetyError(
                    "Unsupported Git layout (v1 refusal): worktree_gitfile at .git/worktrees: "
                    "Linked worktrees metadata present, refused in v1"
                )

    cfg_refusals = inspect_git_config_dir_refusals(dot_git, ".git")
    if cfg_refusals:
        summary = "; ".join(f"{r['path']}: {r['detail']}" for r in cfg_refusals)
        raise SafetyError(summary)


def assert_safe_repo_for_git(repo_dir: os.PathLike | str) -> None:
    """Fail closed before spawning git if repo_dir has unsafe layout or repo-supplied program settings."""
    repo_lex = _lexical_abs(repo_dir)
    _assert_safe_single_repo_root(repo_lex)
    repo_real = _real_parent_bound(repo_dir)
    if repo_real != repo_lex:
        _assert_safe_single_repo_root(repo_real)


HARDENED_GIT_CONFIG_ARGS: Tuple[str, ...] = (
    "--no-pager",
    "--no-optional-locks",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.useBuiltinFSMonitor=false",
    "-c", "core.pager=cat",
    "-c", "core.editor=false",
    "-c", "sequence.editor=false",
    "-c", "core.sshCommand=false",
    "-c", "core.askPass=/bin/false",
    "-c", "core.gitProxy=",
    "-c", "core.alternateRefsCommand=false",
    "-c", "core.attributesFile=/dev/null",
    "-c", "core.excludesFile=/dev/null",
    "-c", "credential.helper=",
    "-c", "protocol.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.http.allow=never",
    "-c", "protocol.https.allow=never",
    "-c", "protocol.ssh.allow=never",
    "-c", "protocol.git.allow=never",
    "-c", "commit.gpgSign=false",
    "-c", "commit.verbose=false",
    "-c", "commit.template=",
    "-c", "tag.gpgSign=false",
    "-c", "tag.forceSignAnnotated=false",
    "-c", "push.gpgSign=false",
    "-c", "log.showSignature=false",
    "-c", "gpg.program=/bin/false",
    "-c", "gpg.openpgp.program=/bin/false",
    "-c", "gpg.ssh.program=/bin/false",
    "-c", "gpg.ssh.defaultKeyCommand=",
    "-c", "gpg.x509.program=/bin/false",
    "-c", "diff.external=",
    "-c", "submodule.recurse=false",
    "-c", "status.submoduleSummary=false",
    "-c", "gc.auto=0",
    "-c", "maintenance.auto=false",
    "-c", "uploadpack.packObjectsHook=",
    "-c", "interactive.diffFilter=",
    "-c", "web.browser=false",
    "-c", "man.viewer=cat",
    "-c", "init.templateDir=",
    # Git LFS filter commands are cleared so git never invokes git-lfs or a repo-supplied
    # filter.lfs.* command. Consequence: LFS pointer files (and any files matching filter=lfs)
    # are treated as ordinary small files; Defuzz never downloads or rewrites LFS content.
    "-c", "filter.lfs.clean=",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false",
    "--literal-pathspecs",
)

# Defuzz only ever invokes local compiled-in git builtins. Git ignores any `[alias]` entry
# whose name matches a builtin, and this allowlist blocks non-builtin aliases as well as
# network, merge, interactive-tool, and submodule subcommands before spawning git.
_ALLOWED_GIT_SUBCOMMANDS: frozenset[str] = frozenset({
    "add",
    "branch",
    "clean",
    "commit",
    "config",
    "diff",
    "for-each-ref",
    "init",
    "log",
    "ls-files",
    "ls-tree",
    "mv",
    "remote",
    "reset",
    "restore",
    "rev-parse",
    "rm",
    "show",
    "status",
    "symbolic-ref",
})


def hardened_git_env(
    base_env: Optional[Dict[str, str]] = None,
    *,
    ceiling_dirs: Optional[Sequence[os.PathLike | str]] = None,
) -> Dict[str, str]:
    """Return minimal git environment with inherited GIT_* dropped, HOME=/nonexistent, and prompts/configs disabled."""
    src = base_env if base_env is not None else os.environ
    env: Dict[str, str] = {
        "PATH": src.get("PATH") or os.defpath,
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_SSH_COMMAND": "false",
        "GIT_PAGER": "cat",
        "GIT_EDITOR": "/bin/false",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }
    if os.name == "nt":
        for win_key in ("SYSTEMROOT", "WINDIR"):
            if src.get(win_key):
                env[win_key] = src[win_key]
    if ceiling_dirs:
        ceil_items: List[str] = []
        for item in ceiling_dirs:
            text_item = os.fspath(item)
            if text_item and text_item not in ceil_items:
                ceil_items.append(text_item)
        if ceil_items:
            env["GIT_CEILING_DIRECTORIES"] = os.pathsep.join(ceil_items)
    return env


def _hardened_subcommand_args(args: Sequence[str]) -> List[str]:
    """Validate allowed built-in subcommand and inject subcommand-level safety flags."""
    out = list(args)
    idx = 0
    while idx < len(out):
        tok = out[idx]
        if tok == "-c":
            if idx + 1 >= len(out):
                raise SafetyError("Incomplete -c option in run_git_hardened")
            cfg_kv = out[idx + 1]
            if not cfg_kv.lower().startswith("user."):
                raise SafetyError(f"Disallowed -c override in run_git_hardened: {cfg_kv!r}")
            idx += 2
            continue
        if tok.startswith("-"):
            raise SafetyError(f"Disallowed global git option in run_git_hardened: {tok!r}")
        if tok not in _ALLOWED_GIT_SUBCOMMANDS:
            raise SafetyError(f"Disallowed git subcommand in run_git_hardened: {tok!r}")
        if tok in ("diff", "show", "log"):
            inject: List[str] = []
            if "--no-ext-diff" not in out[idx + 1 :]:
                inject.append("--no-ext-diff")
            if "--no-textconv" not in out[idx + 1 :]:
                inject.append("--no-textconv")
            if inject:
                out[idx + 1 : idx + 1] = inject
        elif tok == "commit":
            commit_inject: List[str] = []
            if "--no-gpg-sign" not in out[idx + 1 :]:
                commit_inject.append("--no-gpg-sign")
            if "--no-verify" not in out[idx + 1 :]:
                commit_inject.append("--no-verify")
            if commit_inject:
                out[idx + 1 : idx + 1] = commit_inject
        elif tok == "remote":
            rest = [t for t in out[idx + 1 :] if not t.startswith("-")]
            if rest and rest[0] not in ("get-url",):
                raise SafetyError(f"Disallowed git remote subcommand in run_git_hardened: {rest[0]!r}")
        return out
    raise SafetyError("Missing git subcommand in run_git_hardened")


def _parse_git_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse `git version X.Y[.Z]...` output into a comparable tuple."""
    match = re.search(r"git version (\d+)\.(\d+)(?:\.(\d+))?", text or "")
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def ensure_git_available(env: Optional[Dict[str, str]] = None) -> Tuple[int, int, int]:
    """Check once per git binary that git is on PATH and new enough; raise GitUnavailableError if not."""
    git_env = env if env is not None else hardened_git_env()
    exe = shutil.which("git", path=git_env.get("PATH"))
    if exe is None:
        raise GitUnavailableError(
            f"git is required but was not found on PATH; install git {_MIN_GIT_TEXT} or newer and retry"
        )
    cached = _GIT_CHECKED.get(exe)
    if cached is not None:
        return cached
    try:
        proc = subprocess.run(
            [exe, "--version"],
            env=git_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=False,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitUnavailableError(f"git is required but {exe} could not be run ({exc.__class__.__name__})") from exc
    output = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    found = _parse_git_version(output)
    if found is None:
        raise GitUnavailableError(
            f"git is required but `{exe} --version` did not report a version; "
            f"install git {_MIN_GIT_TEXT} or newer and retry"
        )
    if found < MIN_GIT_VERSION:
        found_text = ".".join(str(part) for part in found)
        raise GitUnavailableError(
            f"git {_MIN_GIT_TEXT} or newer is required; found git {found_text} at {exe}"
        )
    _GIT_CHECKED[exe] = found
    return found


def run_git_hardened(
    repo_dir: os.PathLike | str,
    args: Sequence[str],
    *,
    timeout: int = 30,
    check: bool = False,
    allow_literal_pathspecs: bool = True,
) -> subprocess.CompletedProcess:
    """Execute a local git command with hooks, filters, and network disabled."""
    assert_safe_repo_for_git(repo_dir)
    repo_lex = _lexical_abs(repo_dir)
    repo_real = _real_parent_bound(repo_dir)
    cmd: List[str] = ["git", "-C", os.fspath(repo_dir)]
    for item in HARDENED_GIT_CONFIG_ARGS:
        if item == "--literal-pathspecs" and not allow_literal_pathspecs:
            continue
        cmd.append(item)
    cmd.extend(_hardened_subcommand_args(args))
    git_env = hardened_git_env(ceiling_dirs=(repo_lex.parent, repo_real.parent))
    ensure_git_available(git_env)
    try:
        return subprocess.run(
            cmd,
            env=git_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=check,
        )
    except FileNotFoundError as exc:
        raise GitUnavailableError(
            f"git is required but was not found on PATH; install git {_MIN_GIT_TEXT} or newer and retry"
        ) from exc


# --- Descriptor-relative writes ---------------------------------------------------------------
# Every write below a root goes through folder handles opened with O_NOFOLLOW, one component at
# a time, so a link (or a folder swapped for a link after a check) cannot redirect it.
# Trust rule: the folder the person chose (the `base`; by default the root a helper is given)
# may be reached through links they made. Its deepest existing folder is resolved once to its
# real path, which is then opened from "/" one folder at a time without following links (a real
# path has no links, so a link met there was swapped in: refused), and checked to be the same
# folder (device and inode) that was resolved. That handle is kept; the missing folders of the
# chosen path are created under it, and everything below it is opened strictly no-follow. The
# same opening is used whether the root exists or must be created.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_PATH = getattr(os, "O_PATH", 0)
_DIR_OPEN_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_WRITE_TEMP_PREFIX = ".defuzz-write-"
_COPY_CHUNK = 1024 * 1024
# Folder handles kept open per tree while copying, besides the two roots (deeper ones are
# reopened from the nearest kept folder and checked by identity when needed).
_COPY_HELD_LEVELS = 16

# Probed once at import, so tests that wrap os functions do not turn it off.
_DIR_FD_SUPPORTED = bool(_O_NOFOLLOW and _O_DIRECTORY) and all(
    fn in os.supports_dir_fd for fn in (os.open, os.mkdir, os.stat, os.rename, os.unlink, os.readlink, os.symlink)
) and hasattr(os, "fchmod") and os.listdir in os.supports_fd


def _require_dir_fd(what: object) -> None:
    if not _DIR_FD_SUPPORTED:
        raise SafetyError(f"Refusing to write: this platform cannot write files without following links: {what}")


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _open_resolved_dir(real: str) -> int:
    """Open the real (link-free) folder path `real` from "/" one folder at a time, never following a link."""
    fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    shown = os.sep
    try:
        names = Path(real).parts[1:]
        for idx, name in enumerate(names):
            shown = os.path.join(shown, name)
            last = idx == len(names) - 1
            try:
                child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=fd)
            except PermissionError as exc:
                # A folder on the way that may be entered but not listed (mode --x): Linux can
                # still hold it without reading it. The chosen folder itself must be readable.
                if last or not _O_PATH:
                    raise SafetyError(f"Could not open folder ({exc.strerror or exc}): {shown}") from exc
                try:
                    child = os.open(name, _O_PATH | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=fd)
                except OSError as exc2:
                    raise SafetyError(f"Could not open folder ({exc2.strerror or exc2}): {shown}") from exc2
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise SafetyError(f"Refusing folder that changed while it was opened (a link appeared): {shown}") from exc
                raise SafetyError(f"Could not open folder ({exc.strerror or exc}): {shown}") from exc
            os.close(fd)
            fd = child
    except BaseException:
        _close_quietly(fd)
        raise
    return fd


class PinnedFolder:
    """A folder the person chose, opened once through its real path and kept open.

    When the folder does not exist yet, its deepest existing parent is the one opened; the
    missing folders are created under that handle (no-follow) by open_dir(). The folder may
    not itself be a link.
    """

    def __init__(self, path: os.PathLike | str, *, role: str = "output", create: bool = True) -> None:
        _require_dir_fd(path)
        self.fd = -1
        self.role = role
        self.lex = _lexical_abs(path)
        anchor = self.lex
        missing: List[str] = []
        while not os.path.lexists(anchor) and anchor.parent != anchor:
            missing.insert(0, anchor.name)
            anchor = anchor.parent
        if not missing and os.path.islink(anchor):
            raise SafetyError(f"Refusing symlink root: {self.lex}")
        if missing and not create:
            raise SafetyError(f"Root folder does not exist: {self.lex}")
        real = os.path.realpath(anchor)
        try:
            expected = os.stat(real)
        except OSError as exc:
            raise SafetyError(f"Could not open folder ({exc.strerror or exc}): {anchor}") from exc
        if not stat.S_ISDIR(expected.st_mode):
            raise SafetyError(f"Path component is not a directory: {anchor}")
        fd = _open_resolved_dir(real)
        try:
            if not _same_file(os.fstat(fd), expected):
                raise SafetyError(f"Refusing folder that changed while it was opened: {anchor}")
            self.anchor = anchor
            self.missing: Tuple[str, ...] = tuple(missing)
            self.real = Path(real).joinpath(*missing)
            assert_safe_root(self.real, role=role)
        except BaseException:
            _close_quietly(fd)
            raise
        self.fd = fd

    def recheck(self) -> None:
        """Check, before each use, that the chosen path still names the held folder.

        The recorded path is resolved again; its folder must have the same device and inode
        as the open handle, and its current real location must pass the same root checks
        as when it was opened (not a protected Hermes home). Otherwise: refused.

        This is race-free against everyone except the folder's own owner: someone who
        cannot rename the held folder cannot change what the handle names. The owner (or
        whoever controls its parent) can still rename it between this check and the write
        that follows; no call can prevent that, so this narrows that case to a short window.
        """
        if self.fd < 0:
            raise SafetyError(f"Folder is no longer open: {self.lex}")
        moved = f"Refusing folder that moved after it was opened: {self.lex}"
        try:
            real = os.path.realpath(self.anchor)
            now = os.stat(real)
        except (OSError, ValueError) as exc:
            raise SafetyError(moved) from exc
        if not _same_file(now, os.fstat(self.fd)):
            raise SafetyError(moved)
        self.real = Path(real).joinpath(*self.missing)
        assert_safe_root(self.real, role=self.role)

    def open_dir(self) -> int:
        """Return a new handle to the chosen folder (the caller closes it), creating missing folders."""
        self.recheck()
        fd = os.dup(self.fd)
        shown = self.anchor
        try:
            for name in self.missing:
                shown = shown / name
                child = _open_child_dir(fd, name, shown, mode=0o777, link_msg="Refusing to traverse symlink in folder path")
                os.close(fd)
                fd = child
            if self.missing:
                pinned = os.dup(fd)
                os.close(self.fd)
                self.fd, self.missing, self.anchor = pinned, (), self.lex
        except BaseException:
            _close_quietly(fd)
            raise
        return fd

    def close(self) -> None:
        if self.fd >= 0:
            _close_quietly(self.fd)
            self.fd = -1

    def __enter__(self) -> "PinnedFolder":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _below_base(root_lex: Path, base: Any) -> Tuple["PinnedFolder", bool, Tuple[str, ...]]:
    """Return (pinned base, opened here?, folders from the base down to root)."""
    if base is None:
        return PinnedFolder(root_lex), True, ()
    pin, owned = (base, False) if isinstance(base, PinnedFolder) else (PinnedFolder(base), True)
    try:
        between = root_lex.relative_to(pin.lex).parts
    except ValueError:
        if owned:
            pin.close()
        raise SafetyError(f"Folder is outside the chosen folder {pin.lex}: {root_lex}") from None
    return pin, owned, between


def _open_child_dir(parent_fd: int, name: str, shown: os.PathLike | str, *, mode: int, link_msg: str) -> int:
    """Open folder `name` under parent_fd without following a link, creating it when missing."""
    try:
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass  # created meanwhile: reopen without following
        except OSError as exc:
            raise SafetyError(f"Could not create folder ({exc.strerror or exc}): {shown}") from exc
    except OSError:
        pass
    try:
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        try:
            st: Optional[os.stat_result] = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            raise SafetyError(f"{link_msg}: {shown}") from exc
        raise SafetyError(f"Path component is not a directory: {shown}") from exc


def _walk_dirs(
    root_lex: Path, parts: Sequence[str], *, mode: int, base: Any = None, create: bool = True
) -> Tuple[int, Path]:
    """Open the pinned base, then the folders down to root and each of parts no-follow.

    Returns the last folder handle and its lexical path. Folders are created when missing
    unless create=False (then only the base's own missing folders would be, and none are).
    """
    pin, owned, between = _below_base(root_lex, base)
    try:
        if not create and pin.missing:
            raise SafetyError(f"Root folder does not exist: {root_lex}")
        pin.recheck()
        assert_safe_root(pin.real.joinpath(*between), role="output")
        fd = pin.open_dir()
    finally:
        if owned:
            pin.close()
    cur = pin.lex
    try:
        for name in between:
            cur = cur / name
            child = _open_existing_or_new(fd, name, cur, 0o777, "Refusing to traverse symlink in folder path", create)
            os.close(fd)
            fd = child
        for part in parts:
            cur = cur / part
            child = _open_existing_or_new(fd, part, cur, mode, "Refusing symlink directory component", create)
            os.close(fd)
            fd = child
    except BaseException:
        _close_quietly(fd)
        raise
    return fd, cur


def _open_existing_or_new(fd: int, name: str, shown: Path, mode: int, link_msg: str, create: bool) -> int:
    if create:
        return _open_child_dir(fd, name, shown, mode=mode, link_msg=link_msg)
    try:
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP or os.path.islink(shown):
            raise SafetyError(f"{link_msg}: {shown}") from exc
        raise SafetyError(f"Folder does not exist or is not a directory: {shown}") from exc


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _unlink_if_ours(dir_fd: int, name: str, fd: int) -> None:
    """Remove `name` only while it is still the file open on fd (never a file swapped in)."""
    try:
        ours = os.fstat(fd)
        now = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if (ours.st_dev, ours.st_ino) == (now.st_dev, now.st_ino):
            os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def _write_error(target: Path, exc: BaseException) -> SafetyError:
    reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
    return SafetyError(f"Could not write file ({reason}): {target}")


def _write_leaf(dir_fd: int, leaf: str, target: Path, data: bytes, *, overwrite: bool, mode: int) -> None:
    try:
        st: Optional[os.stat_result] = os.stat(leaf, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        raise SafetyError(f"Refusing to traverse or overwrite symlink inside copy: {target}")
    if not overwrite:
        if st is not None:
            raise SafetyError(f"Refusing to overwrite existing file: {target}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
        try:
            fd = os.open(leaf, flags, mode, dir_fd=dir_fd)
        except FileExistsError as exc:
            raise SafetyError(f"Refusing to overwrite existing file: {target}") from exc
        except OSError as exc:
            raise SafetyError(f"No-follow write failed for {target}: {exc}") from exc
        try:
            _write_all(fd, data)
        except BaseException as exc:
            _unlink_if_ours(dir_fd, leaf, fd)
            if isinstance(exc, OSError):
                raise _write_error(target, exc) from exc
            raise
        finally:
            os.close(fd)
        return
    # Overwrite: never open the existing name. Write a fresh sibling and rename it over the name,
    # so a FIFO cannot block, a hard link's other names keep their bytes, and a link swapped in
    # at the last moment is replaced, not followed. The existing permission bits are kept.
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise SafetyError(f"Refusing to overwrite non-regular file: {target}")
    tmp = f"{_WRITE_TEMP_PREFIX}{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
    try:
        tfd = os.open(tmp, flags, mode, dir_fd=dir_fd)
    except OSError as exc:
        raise SafetyError(f"No-follow write failed for {target}: {exc}") from exc
    try:
        if st is not None:
            os.fchmod(tfd, stat.S_IMODE(st.st_mode))
        _write_all(tfd, data)
        os.replace(tmp, leaf, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException as exc:
        _unlink_if_ours(dir_fd, tmp, tfd)
        if isinstance(exc, OSError):
            raise _write_error(target, exc) from exc
        raise
    finally:
        os.close(tfd)


def _copy_file_nofollow(
    src_dir_fd: int, name: str, lst: os.stat_result, dst_dir_fd: int, shown: Path, src_shown: Path
) -> None:
    """Copy regular file `name` between two folder handles: no link followed, no FIFO opened blocking."""
    changed = f"Source file changed while copying: {src_shown}"
    try:
        sfd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=src_dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOENT, errno.ENXIO):
            raise SafetyError(changed) from exc
        raise SafetyError(f"Could not read source file ({exc.strerror or exc}): {src_shown}") from exc
    try:
        sst = os.fstat(sfd)
        if not stat.S_ISREG(sst.st_mode) or not _same_file(sst, lst):
            raise SafetyError(changed)
        os.set_blocking(sfd, True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
        try:
            dfd = os.open(name, flags, 0o600, dir_fd=dst_dir_fd)
        except OSError as exc:
            raise _write_error(shown, exc) from exc
        try:
            while True:
                try:
                    chunk = os.read(sfd, _COPY_CHUNK)
                except OSError as exc:
                    raise SafetyError(f"Could not read source file ({exc.strerror or exc}): {src_shown}") from exc
                if not chunk:
                    break
                _write_all(dfd, chunk)
            copy_xattr = getattr(shutil, "_copyxattr", None)
            if copy_xattr is not None:
                try:
                    copy_xattr(sfd, dfd)
                except OSError:
                    pass
            os.fchmod(dfd, stat.S_IMODE(sst.st_mode))
            os.utime(dfd, ns=(sst.st_atime_ns, sst.st_mtime_ns))
        finally:
            os.close(dfd)
    finally:
        os.close(sfd)


def _open_copy_destination(dst: Path, base: Any) -> Tuple[int, Path]:
    """Open (or create under the trust rule) an empty copy destination; refuse anything else."""
    non_empty = f"Copy destination already exists and is non-empty: {dst}"
    if os.path.lexists(dst) and (os.path.islink(dst) or not dst.is_dir()):
        raise SafetyError(non_empty)
    pin, owned, between = _below_base(dst, base)
    try:
        fd, _ = _walk_dirs(dst, (), mode=0o777, base=pin)
        real = pin.real.joinpath(*between)
    except SafetyError as exc:
        if os.path.islink(dst):
            raise SafetyError(non_empty) from exc
        raise
    finally:
        if owned:
            pin.close()
    try:
        entries = os.listdir(fd)
    except BaseException:
        _close_quietly(fd)
        raise
    if entries:
        _close_quietly(fd)
        raise SafetyError(non_empty)
    return fd, real


class _CopyLevel:
    __slots__ = ("parts", "src_id", "dst_id", "src_fd", "dst_fd", "pending")

    def __init__(self, parts: Tuple[str, ...], src_fd: int, dst_fd: int) -> None:
        self.parts = parts
        self.src_fd: Optional[int] = src_fd
        self.dst_fd: Optional[int] = dst_fd
        self.src_id = os.fstat(src_fd)
        self.dst_id = os.fstat(dst_fd)
        self.pending: List[str] = []

    def drop(self) -> None:
        for fd in (self.src_fd, self.dst_fd):
            if fd is not None:
                _close_quietly(fd)
        self.src_fd = self.dst_fd = None


def _reopen_level(stack: List[_CopyLevel], idx: int, src: Path, dst: Path) -> None:
    """Reopen both handles of stack[idx] from the nearest held level, checking every folder's identity."""
    j = idx - 1
    while stack[j].src_fd is None:
        j -= 1
    s_fd = os.dup(stack[j].src_fd)  # type: ignore[arg-type]
    d_fd = os.dup(stack[j].dst_fd)  # type: ignore[arg-type]
    try:
        for k in range(j + 1, idx + 1):
            lvl, name = stack[k], stack[k].parts[-1]
            for side, cur in (("src", s_fd), ("dst", d_fd)):
                try:
                    child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=cur)
                except OSError as exc:
                    child = -1
                    err: Optional[BaseException] = exc
                else:
                    err = None
                    if not _same_file(os.fstat(child), lvl.src_id if side == "src" else lvl.dst_id):
                        _close_quietly(child)
                        child = -1
                if child < 0:
                    where = (src if side == "src" else dst).joinpath(*lvl.parts)
                    raise SafetyError(f"Folder changed while copying: {where}") from err
                os.close(cur)
                if side == "src":
                    s_fd = child
                else:
                    d_fd = child
    except BaseException:
        _close_quietly(s_fd)
        _close_quietly(d_fd)
        raise
    stack[idx].src_fd, stack[idx].dst_fd = s_fd, d_fd


def _copy_entries(
    lvl: _CopyLevel, src: Path, dst: Path, include_secret_files: bool, skipped: List[str]
) -> None:
    """Copy the links and regular files of one folder; remember its sub-folders in lvl.pending."""
    from .scanner import _is_secret_filename

    rel_dir = "/".join(lvl.parts)
    in_git_dir = rel_dir == ".git" or rel_dir.startswith(".git/") or "/.git/" in f"/{rel_dir}/"
    s_fd, d_fd = lvl.src_fd, lvl.dst_fd
    assert s_fd is not None and d_fd is not None
    dirs: List[str] = []
    for name in sorted(os.listdir(s_fd)):
        rel = name if not rel_dir else f"{rel_dir}/{name}"
        st = os.stat(name, dir_fd=s_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            dirs.append(name)
        elif stat.S_ISLNK(st.st_mode):
            if not include_secret_files and not in_git_dir and _is_secret_filename(rel):
                skipped.append(rel)
                continue
            os.symlink(os.readlink(name, dir_fd=s_fd), name, dir_fd=d_fd)
        elif stat.S_ISREG(st.st_mode):
            if not include_secret_files and not in_git_dir and _is_secret_filename(rel):
                skipped.append(rel)
                continue
            _copy_file_nofollow(s_fd, name, st, d_fd, dst.joinpath(*lvl.parts, name), src.joinpath(*lvl.parts, name))
        # Ignore sockets/FIFOs/devices in copy
    lvl.pending = sorted(dirs, reverse=True)


def _copy_walk(
    src_pin: PinnedFolder, dst_fd: int, src: Path, dst: Path, include_secret_files: bool, skipped: List[str]
) -> None:
    """Walk the source by handles, depth first, holding at most _COPY_HELD_LEVELS levels open per tree."""
    root = _CopyLevel((), src_pin.open_dir(), os.dup(dst_fd))
    stack = [root]
    try:
        _copy_entries(root, src, dst, include_secret_files, skipped)
        while stack:
            top = stack[-1]
            if not top.pending:
                top.drop()
                stack.pop()
                continue
            name = top.pending.pop()
            if top.src_fd is None:
                _reopen_level(stack, len(stack) - 1, src, dst)
            assert top.src_fd is not None and top.dst_fd is not None
            src_shown = src.joinpath(*top.parts, name)
            try:
                listed = os.stat(name, dir_fd=top.src_fd, follow_symlinks=False)
                child_src = os.open(name, _DIR_OPEN_FLAGS, dir_fd=top.src_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise SafetyError(f"Source folder changed while copying: {src_shown}") from exc
                continue  # unreadable folder: skipped, as before
            try:
                if not stat.S_ISDIR(listed.st_mode) or not _same_file(os.fstat(child_src), listed):
                    raise SafetyError(f"Source folder changed while copying: {src_shown}")
                try:
                    os.listdir(child_src)
                except OSError:
                    _close_quietly(child_src)
                    continue  # unreadable folder: skipped, as before
                child_dst = _open_child_dir(
                    top.dst_fd, name, dst.joinpath(*top.parts, name), mode=0o777,
                    link_msg="Refusing symlink directory component in copy",
                )
            except BaseException:
                _close_quietly(child_src)
                raise
            try:
                try:
                    os.fchmod(child_dst, stat.S_IMODE(listed.st_mode))
                except OSError:
                    pass
                lvl = _CopyLevel(top.parts + (name,), child_src, child_dst)
            except BaseException:
                _close_quietly(child_src)
                _close_quietly(child_dst)
                raise
            stack.append(lvl)
            far = len(stack) - 1 - _COPY_HELD_LEVELS
            if far > 0:
                stack[far].drop()
            _copy_entries(lvl, src, dst, include_secret_files, skipped)
    finally:
        for lvl in stack:
            lvl.drop()
