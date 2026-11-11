"""Mechanical file placement engine and pre_tool_call / transform_tool_result hooks.

Rules:
- pre_tool_call intercepts 'write_file' only.
- Only NEW files outside declared project folders are candidates for placement.
- Never relocate edits to existing files, root AGENTS.md/README.md/dotfiles, or files in src/ or tests/.
- Matched extension rules route to their declared dest_dir; unmatched kinds route to '_inbox/'.
- Refuses symlink traversal and refuses overwriting an existing file at the destination.
- Records placements in '.adopt/place-log.json' and supports 'undo'.
- transform_tool_result appends a one-line 'placed_at' note when a write_file path was redirected.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shlex
import shutil
import stat
import threading
import time
import tomllib
from collections import OrderedDict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .agents_md import write_agents_md
from .catalog_list import escape_text
from .rules import (
    PROTECTED_ROOT_FILES,
    _validate_extensions,
    _validate_safe_rel_prefix,
    is_protected_root_path,
    validate_rules_spec,
)
from .safety import (
    PinnedFolder,
    SafetyError,
    _is_same_or_subpath,
    _lexical_abs,
    assert_not_live_hermes,
    assert_safe_root,
    run_git_hardened,
    safe_mkdirs,
    safe_write_bytes,
    safe_write_text,
    verify_nofollow_within_root,
)
from .state_store import get_project, is_registered, record_project, state_db_path, update_rules_hash

# Protected top-level directories whose files are never relocated by the hook
EXEMPT_TOP_DIRS: frozenset[str] = frozenset({
    "src", "tests", "test", ".git", ".adopt", "_archive", ".hermes", ".github",
})
TRUST_MODE_FULL = "full"
TRUST_MODE_DECLARED_ONLY = "declared_only"
VALID_TRUST_MODES: frozenset[str] = frozenset({TRUST_MODE_FULL, TRUST_MODE_DECLARED_ONLY})

_PENDING_NOTES_LOCK = threading.Lock()
_RULES_MUTATION_LOCK = threading.RLock()
_PENDING_NOTES: Dict[str, Dict[str, str]] = {}
_PENDING_SKIP_NOTICES: OrderedDict[str, str] = OrderedDict()
_MAX_PENDING_SKIP_NOTICES = 64
_NOTIFIED_TRUST_ROOTS: OrderedDict[str, None] = OrderedDict()
_NOTIFIED_ERROR_ROOTS: OrderedDict[str, None] = OrderedDict()
_MAX_NOTIFIED_ROOTS = 256
_LAST_HOOK_SKIP_REASON: Optional[str] = None


def _reset_notice_state_for_tests() -> None:
    """Reset module-level pending note/notice and throttle state (for unit tests)."""
    global _LAST_HOOK_SKIP_REASON
    with _PENDING_NOTES_LOCK:
        _PENDING_NOTES.clear()
        _PENDING_SKIP_NOTICES.clear()
        _NOTIFIED_TRUST_ROOTS.clear()
        _NOTIFIED_ERROR_ROOTS.clear()
        _LAST_HOOK_SKIP_REASON = None


def _record_notified_root(store: OrderedDict[str, None], root_key: str) -> bool:
    """Return True if root_key has not been notified yet and record it (bounded to 256 entries, oldest-first eviction)."""
    if root_key in store:
        return False
    while len(store) >= _MAX_NOTIFIED_ROOTS:
        store.popitem(last=False)
    store[root_key] = None
    return True


def _has_control_char(text: str) -> bool:
    return not text.isprintable()


def _classify_trust_skip_reason(reason_str: str) -> str:
    lower = reason_str.lower()
    if "hash mismatch" in lower:
        return "its rules file changed since it was trusted"
    if "invalid .adopt/rules.json" in lower or "malformed .adopt/rules.json" in lower:
        return "its rules file is invalid"
    return "project is not trusted yet"


def _format_trust_failure_notice(proj_root: Path, short_reason: str) -> str:
    root_str = str(proj_root)
    if _has_control_char(root_str):
        return (
            f"[defuzz: automatic file placement is OFF: {short_reason}. "
            f"Do not run the trust command yourself; tell the user they can turn it on with: hermes defuzz trust]"
        )
    quoted_root = shlex.quote(root_str)
    return (
        f"[defuzz: automatic file placement is OFF for {root_str}: {short_reason}. "
        f"Do not run the trust command yourself; tell the user they can turn it on with: hermes defuzz trust {quoted_root}]"
    )


def _format_unexpected_error_notice(exc: BaseException) -> str:
    return f"[defuzz: automatic file placement skipped for this write ({type(exc).__name__})]"


def _stash_pending_skip_notice(tool_call_id: str, target_lex: Path, notice: str) -> None:
    key = f"id:{tool_call_id}" if tool_call_id else f"path:{target_lex}"
    if key in _PENDING_SKIP_NOTICES:
        del _PENDING_SKIP_NOTICES[key]
    while len(_PENDING_SKIP_NOTICES) >= _MAX_PENDING_SKIP_NOTICES:
        _PENDING_SKIP_NOTICES.popitem(last=False)
    _PENDING_SKIP_NOTICES[key] = notice


def _record_unexpected_error_skip(
    exc: BaseException,
    root_key: str,
    tool_call_id: str,
    target_lex: Path,
) -> None:
    notice = _format_unexpected_error_notice(exc)
    with _PENDING_NOTES_LOCK:
        if _record_notified_root(_NOTIFIED_ERROR_ROOTS, root_key):
            _stash_pending_skip_notice(tool_call_id, target_lex, notice)


def _pop_pending_skip_notice(tool_call_id: str, args: Optional[Dict[str, Any]]) -> Optional[str]:
    with _PENDING_NOTES_LOCK:
        if tool_call_id:
            return _PENDING_SKIP_NOTICES.pop(f"id:{tool_call_id}", None)
        if isinstance(args, dict) and isinstance(args.get("path"), str):
            try:
                p_key = f"path:{_lexical_abs(args['path'])}"
            except Exception:
                return None
            return _PENDING_SKIP_NOTICES.pop(p_key, None)
    return None


def get_last_hook_skip_reason() -> Optional[str]:
    """Return the most recent reason why pre_tool_call skipped an untrusted or mismatched project."""
    with _PENDING_NOTES_LOCK:
        return _LAST_HOOK_SKIP_REASON


def find_adopted_root(file_path: os.PathLike | str) -> Optional[Path]:
    """Walk up from file_path to find an enclosing directory containing .adopt/rules.json."""
    try:
        lex = _lexical_abs(file_path)
    except Exception:
        return None
    home_lex = _lexical_abs(os.path.expanduser("~"))
    home = Path(os.path.expanduser("~")).resolve()
    cur = lex if lex.is_dir() else lex.parent
    for _ in range(32):
        if cur in (Path("/"), home_lex, home) or cur.parent == cur:
            break
        try:
            assert_safe_root(cur, role="adopted_root")
        except SafetyError:
            break
        adopt_dir = cur / ".adopt"
        rules_file = adopt_dir / "rules.json"
        try:
            if (
                not os.path.islink(adopt_dir)
                and adopt_dir.is_dir()
                and not os.path.islink(rules_file)
                and rules_file.is_file()
            ):
                return cur
        except OSError:
            pass
        cur = cur.parent
    return None


def _is_valid_adopted_rules(rules_data: Any) -> bool:
    """Return True when rules_data is a valid .adopt/rules.json payload written by apply."""
    if not isinstance(rules_data, dict):
        return False
    if rules_data.get("schema") != 1:
        return False
    if "schema_version" in rules_data and rules_data.get("schema_version") != 1:
        return False
    slug = rules_data.get("project_slug")
    if not isinstance(slug, str) or not slug.strip():
        return False
    if not isinstance(rules_data.get("declared_dirs"), list):
        return False
    if not isinstance(rules_data.get("placement_rules"), list):
        return False
    if "folder_rules" in rules_data and not isinstance(rules_data.get("folder_rules"), list):
        return False
    if "protected_root_files" in rules_data and not isinstance(rules_data.get("protected_root_files"), list):
        return False
    try:
        validate_rules_spec({
            "project_slug": slug,
            "declared_dirs": rules_data["declared_dirs"],
            "folder_rules": rules_data.get("folder_rules") or [],
            "placement_rules": rules_data["placement_rules"],
            "ignore_patterns": rules_data.get("ignore_patterns") or [],
            "lfs_patterns": rules_data.get("lfs_patterns") or [],
            "protected_root_files": rules_data.get("protected_root_files") or [],
        })
    except Exception:
        return False
    return True


def _read_rules_bytes_nofollow(proj_root: os.PathLike | str) -> bytes:
    """Read .adopt/rules.json bytes once using O_NOFOLLOW where available without following symlinks."""
    root = _lexical_abs(proj_root)
    rules_file = verify_nofollow_within_root(root, ".adopt/rules.json")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(rules_file), flags)
    except FileNotFoundError as exc:
        raise SafetyError(f"No .adopt/rules.json found in {root}") from exc
    except OSError as exc:
        raise SafetyError(f"Refusing or failed to open .adopt/rules.json in {root}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise SafetyError(f"No .adopt/rules.json found in {root}")
        with os.fdopen(fd, "rb") as fh:
            return fh.read()
    except SafetyError:
        raise
    except OSError as exc:
        raise SafetyError(f"Failed reading .adopt/rules.json in {root}: {exc}") from exc


def _parse_rules_bytes(raw_bytes: bytes, root: Path) -> Dict[str, Any]:
    """Parse a JSON object from raw .adopt/rules.json bytes."""
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise SafetyError(f"Malformed .adopt/rules.json in {root}: {exc}") from exc
    if not isinstance(data, dict):
        raise SafetyError(f"Malformed .adopt/rules.json in {root}")
    return data


def _read_and_validate_adopted_rules(root: Path) -> Tuple[Dict[str, Any], str, Path, str]:
    """Read, parse, and validate .adopt/rules.json once; return (rules_data, rules_hash, resolved_root, slug)."""
    raw_bytes = _read_rules_bytes_nofollow(root)
    rules_data = _parse_rules_bytes(raw_bytes, root)
    if not _is_valid_adopted_rules(rules_data):
        raise SafetyError(f"Refusing to trust invalid .adopt/rules.json in {root}")
    rules_hash = hashlib.sha256(raw_bytes).hexdigest()
    resolved_root = root.resolve()
    slug = str(rules_data.get("project_slug") or resolved_root.name).strip() or resolved_root.name
    return rules_data, rules_hash, resolved_root, slug


def compute_rules_hash(proj_root: os.PathLike | str) -> str:
    """Compute SHA-256 hex digest of .adopt/rules.json (without following symlinks)."""
    return hashlib.sha256(_read_rules_bytes_nofollow(proj_root)).hexdigest()


def _untrusted_result(
    resolved_root: Path,
    untrusted_hint: str,
    detail: str,
    *,
    rules_hash: Optional[str] = None,
    expected_rules_hash: Optional[str] = None,
) -> Tuple[Dict[str, Any], None]:
    return (
        {
            "trusted": False,
            "mode": None,
            "status": untrusted_hint,
            "reason": f"{untrusted_hint}: {detail}",
            "project_root": str(resolved_root),
            "rules_hash": rules_hash,
            "expected_rules_hash": expected_rules_hash,
        },
        None,
    )


def _inspect_and_load_project_trust(
    proj_root: os.PathLike | str,
    *,
    db_path: Optional[Path | str] = None,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Read .adopt/rules.json bytes once, hash, parse+validate, and verify against state.db."""
    root = _lexical_abs(proj_root)
    resolved_root = root.resolve()
    untrusted_hint = (
        f"not trusted: ask the user to run `hermes defuzz trust {resolved_root}` in their own terminal"
    )
    try:
        raw_bytes = _read_rules_bytes_nofollow(root)
        rules_data = _parse_rules_bytes(raw_bytes, root)
    except Exception as exc:
        return _untrusted_result(resolved_root, untrusted_hint, str(exc))

    if not _is_valid_adopted_rules(rules_data):
        return _untrusted_result(resolved_root, untrusted_hint, f"invalid .adopt/rules.json in {root}")

    actual_hash = hashlib.sha256(raw_bytes).hexdigest()
    target_db = Path(db_path).expanduser() if db_path is not None else state_db_path()
    if not target_db.exists():
        return _untrusted_result(
            resolved_root, untrusted_hint,
            f"state DB does not exist for {resolved_root}",
            rules_hash=actual_hash,
        )

    try:
        rec = get_project(resolved_root, db_path=target_db)
    except Exception as exc:
        return _untrusted_result(
            resolved_root, untrusted_hint,
            f"failed reading state DB ({exc})",
            rules_hash=actual_hash,
        )

    if rec is None:
        return _untrusted_result(
            resolved_root, untrusted_hint,
            f"unregistered project folder {resolved_root}",
            rules_hash=actual_hash,
        )

    expected_hash = rec.get("rules_hash")
    if not expected_hash:
        return _untrusted_result(
            resolved_root, untrusted_hint,
            f"missing provenance rules_hash for {resolved_root}",
            rules_hash=actual_hash,
        )

    if expected_hash != actual_hash:
        return _untrusted_result(
            resolved_root, untrusted_hint,
            f".adopt/rules.json hash mismatch in {resolved_root} (expected {expected_hash}, got {actual_hash})",
            rules_hash=actual_hash,
            expected_rules_hash=expected_hash,
        )

    raw_mode = rec.get("trust_mode")
    if raw_mode is None:
        effective_mode = TRUST_MODE_FULL
    elif raw_mode in VALID_TRUST_MODES:
        effective_mode = str(raw_mode)
    else:
        return _untrusted_result(
            resolved_root,
            untrusted_hint,
            f"invalid trust_mode {raw_mode!r} for {resolved_root}",
            rules_hash=actual_hash,
            expected_rules_hash=expected_hash,
        )

    return (
        {
            "trusted": True,
            "mode": effective_mode,
            "status": "trusted",
            "reason": "trusted",
            "project_root": str(resolved_root),
            "rules_hash": actual_hash,
            "expected_rules_hash": expected_hash,
        },
        rules_data,
    )


def inspect_project_trust(
    proj_root: os.PathLike | str,
    *,
    db_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    """Inspect whether proj_root is a trusted adopted project in state.db with matching rules_hash."""
    info, _ = _inspect_and_load_project_trust(proj_root, db_path=db_path)
    return info


def trust_project(
    proj_root: os.PathLike | str,
    *,
    mode: Optional[str] = None,
    declared_only: bool = False,
    db_path: Optional[Path | str] = None,
    protected_roots: Optional[Iterable[os.PathLike | str]] = None,
) -> Dict[str, Any]:
    """Explicitly trust an adopted project folder by recording its resolved path, current rules.json hash, and mode in state.db."""
    if mode is None:
        effective_mode = TRUST_MODE_DECLARED_ONLY if declared_only else TRUST_MODE_FULL
    else:
        if mode not in VALID_TRUST_MODES:
            raise SafetyError(
                f"Invalid trust mode {mode!r} (expected one of {sorted(VALID_TRUST_MODES)})"
            )
        if declared_only and mode != TRUST_MODE_DECLARED_ONLY:
            raise SafetyError(
                "Conflicting trust mode arguments: cannot combine declared_only=True with mode='full'"
            )
        effective_mode = mode

    root = assert_safe_root(proj_root, role="trust_root", protected_roots=protected_roots)
    _rules_data, rules_hash, resolved_root, slug = _read_and_validate_adopted_rules(root)
    target_db = Path(db_path).expanduser() if db_path is not None else state_db_path()
    record_project(
        path=resolved_root,
        name=slug,
        slug=slug,
        template_id="adopted",
        answers={"building": "other", "layout": "single", "languages": []},
        hermes_project_id=None,
        db_path=target_db,
        rules_hash=rules_hash,
        trust_mode=effective_mode,
    )
    return {
        "ok": True,
        "action": "trust",
        "project_root": str(resolved_root),
        "project_slug": slug,
        "rules_hash": rules_hash,
        "mode": effective_mode,
        "trusted": True,
        "status": "trusted",
    }


def _require_registered_project(
    proj_root: Path,
    *,
    db_path: Optional[Path | str] = None,
    require_registered: Optional[bool] = None,
) -> Dict[str, Any]:
    """Verify proj_root has a state.db provenance record whose resolved path and rules_hash match current .adopt/rules.json, returning validated rules."""
    info, rules_data = _inspect_and_load_project_trust(proj_root, db_path=db_path)
    if not info["trusted"] or rules_data is None:
        raise SafetyError(info["reason"])
    return rules_data


def load_project_rules(proj_root: Path) -> Dict[str, Any]:
    root = _lexical_abs(proj_root)
    return _parse_rules_bytes(_read_rules_bytes_nofollow(root), root)


def _load_place_log(proj_root: Path) -> List[Dict[str, Any]]:
    log_path = verify_nofollow_within_root(proj_root, ".adopt/place-log.json")
    if not log_path.exists():
        return []
    try:
        data = json.loads(log_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _append_place_log(proj_root: Path, entry: Dict[str, Any]) -> None:
    entries = _load_place_log(proj_root)
    entries.append(entry)
    safe_write_text(
        proj_root,
        ".adopt/place-log.json",
        json.dumps(entries, indent=2, sort_keys=False) + "\n",
        overwrite=True,
    )


def _declared_dir_prefixes(rules_data: Dict[str, Any]) -> Set[str]:
    prefixes: Set[str] = set()
    for list_key, field in (("declared_dirs", "dir"), ("placement_rules", "dest_dir")):
        for item in rules_data.get(list_key) or []:
            if isinstance(item, dict) and item.get(field):
                dp = str(item[field]).strip("/")
                if dp and dp != "_inbox":
                    prefixes.add(dp)
    return prefixes


# Protected root files that mark a project root. Below the root they mean a second project
# is being put inside this one, so they are reported instead of silently left alone.
NESTED_PROJECT_MANIFESTS: frozenset[str] = frozenset(
    name for name in ("package.json", "pyproject.toml", "Cargo.toml", "go.mod", "CMakeLists.txt")
    if name in PROTECTED_ROOT_FILES
)
NESTED_PROJECT_MANIFEST_CODE = "nested_project_manifest"
# Dependency and build output folders: manifests inside them are never reported.
_DEPENDENCY_BUILD_DIRS: frozenset[str] = frozenset({
    "node_modules", ".next", "dist", "build", ".venv", "venv", "target", "vendor", "__pycache__",
})
_MAX_WORKSPACE_DECL_BYTES = 1024 * 1024


class _UnreadableDeclaration(Exception):
    pass


def _read_root_text(proj_root: Path, name: str) -> Optional[str]:
    """Read a small regular file at the project root without following symlinks; None if absent."""
    path = Path(proj_root) / name
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _UnreadableDeclaration(name) from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_WORKSPACE_DECL_BYTES:
        raise _UnreadableDeclaration(name)
    try:
        with open(path, "rb") as fh:
            return fh.read(_MAX_WORKSPACE_DECL_BYTES + 1).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _UnreadableDeclaration(name) from exc


def _yaml_strip_comment(line: str) -> str:
    """Drop a YAML '#' comment (at line start or after whitespace, outside quotes)."""
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


def _yaml_scalar(text: str, decl: str, flow: bool) -> str:
    """Parse one plain or quoted YAML scalar list item; anything unusual is _UnreadableDeclaration."""
    text = text.strip()
    if not text:
        raise _UnreadableDeclaration(decl)
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise _UnreadableDeclaration(decl)
        inner = text[1:-1]
        if inner.replace("''", "").find("'") >= 0:
            raise _UnreadableDeclaration(decl)
        return inner.replace("''", "'")
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise _UnreadableDeclaration(decl)
        inner = text[1:-1]
        if "\\" in inner or '"' in inner:
            raise _UnreadableDeclaration(decl)
        return inner
    # Plain scalar: reject indicators that would make it a tag, alias, anchor, nested
    # collection, mapping or block scalar instead of a simple string.
    if text[0] in "!&*[]{}|>%@`,-?:" and not (text[0] == "-" and len(text) > 1 and text[1] not in " \t"):
        raise _UnreadableDeclaration(decl)
    if ": " in text or text.endswith(":") or " #" in text or "\t" in text:
        raise _UnreadableDeclaration(decl)
    if flow and any(c in text for c in "[]{},"):
        raise _UnreadableDeclaration(decl)
    return text


def _split_flow_items(body: str, decl: str) -> List[str]:
    """Split the inside of a YAML flow sequence on top-level commas (quote-aware)."""
    items: List[str] = []
    cur: List[str] = []
    quote = ""
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch == ",":
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if quote:
        raise _UnreadableDeclaration(decl)
    tail = "".join(cur)
    if tail.strip():
        items.append(tail)
    elif not items and not tail.strip():
        return []
    if any(not it.strip() for it in items):
        raise _UnreadableDeclaration(decl)  # empty item such as '[a,,b]'
    return [_yaml_scalar(it, decl, flow=True) for it in items]


def _flow_close_index(text: str) -> int:
    """Index of the first ']' outside quotes, or -1."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "]":
            return i
    return -1


def _pnpm_packages(raw: str) -> List[str]:
    """Parse `packages` from pnpm-workspace.yaml: block or flow (single/multi-line) lists of
    plain or quoted strings. Anything else raises _UnreadableDeclaration (membership unknown)."""
    decl = "pnpm-workspace.yaml"
    lines = [_yaml_strip_comment(l).rstrip() for l in raw.replace("\r\n", "\n").split("\n")]
    found: Optional[List[str]] = None
    current: Optional[str] = None
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        if line.lstrip() != line:
            if "\t" in line[: len(line) - len(line.lstrip())] or current is None:
                raise _UnreadableDeclaration(decl)
            continue  # nested content of the current top-level key (packages is handled below)
        if line in ("---", "..."):
            continue
        if line.startswith("-"):
            if current is None or current == "packages":
                raise _UnreadableDeclaration(decl)
            continue
        key, sep, rest = line.partition(":")
        key = key.strip()
        if not sep or not key or (rest and rest[0] not in " \t"):
            raise _UnreadableDeclaration(decl)
        if key[:1] in "'\"" and len(key) >= 2 and key[-1] == key[0]:
            key = key[1:-1]
        current = key
        if key != "packages":
            continue
        if found is not None:
            raise _UnreadableDeclaration(decl)
        rest = rest.strip()
        if not rest:
            # Value starts on following lines: a block list ('- item') or a flow list.
            items: List[str] = []
            item_indent: Optional[int] = None
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    i += 1
                    continue
                indent = len(nxt) - len(nxt.lstrip())
                stripped = nxt.strip()
                if indent == 0 and not stripped.startswith("-"):
                    break
                if "\t" in nxt[:indent]:
                    raise _UnreadableDeclaration(decl)
                if stripped.startswith("[") and not items and item_indent is None:
                    rest = stripped
                    i += 1
                    break
                if not (stripped == "-" or stripped.startswith("- ")):
                    raise _UnreadableDeclaration(decl)
                if item_indent is None:
                    item_indent = indent
                elif indent != item_indent:
                    raise _UnreadableDeclaration(decl)
                items.append(_yaml_scalar(stripped[1:], decl, flow=False))
                i += 1
            if not rest:
                found = items
                current = None if not items else "packages"
                continue
        if not rest.startswith("["):
            raise _UnreadableDeclaration(decl)
        buf = rest[1:]
        close = _flow_close_index(buf)
        while close < 0:
            if i >= len(lines):
                raise _UnreadableDeclaration(decl)
            buf += "\n" + lines[i]
            i += 1
            close = _flow_close_index(buf)
        if buf[close + 1:].strip():
            raise _UnreadableDeclaration(decl)
        found = _split_flow_items(buf[:close].replace("\n", " "), decl)
        current = "packages"
    return found or []


def _string_list(value: Any, decl: str) -> List[str]:
    """A declared list of member strings; absent -> []; any other type -> _UnreadableDeclaration."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _UnreadableDeclaration(decl)
    return list(value)


def _go_token(text: str, decl: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"`":
        inner = text[1:-1]
        if not inner or any(c in inner for c in "\"`\\"):
            raise _UnreadableDeclaration(decl)
        return inner
    if not text or any(c in text for c in " \t\"`'(){}"):
        raise _UnreadableDeclaration(decl)
    return text


def _go_work_uses(raw: str) -> List[str]:
    """Parse `use` directives from go.work; unknown directives or broken blocks -> unreadable."""
    decl = "go.work"
    uses: List[str] = []
    block: Optional[str] = None
    for line in raw.replace("\r\n", "\n").split("\n"):
        text = line.split("//", 1)[0].strip()
        if not text:
            continue
        if block is not None:
            if text == ")":
                block = None
            elif block == "use":
                uses.append(_go_token(text, decl))
            continue
        word, _, rest = text.partition(" ")
        if text.endswith("(") and text[:-1].strip() in ("use", "replace", "godebug"):
            block = text[:-1].strip()
            continue
        if word in ("go", "toolchain", "replace", "godebug") and rest.strip():
            continue
        if word == "use" and rest.strip():
            uses.append(_go_token(rest, decl))
            continue
        raise _UnreadableDeclaration(decl)
    if block is not None:
        raise _UnreadableDeclaration(decl)
    for u in uses:
        if u.startswith("/") or (len(u) > 1 and u[1] == ":"):
            raise _UnreadableDeclaration(decl)  # absolute paths: cannot verify safely
    return uses


def _workspace_patterns(proj_root: Path) -> List[str]:
    """Collect workspace member globs declared at the project root ('!' = excluded).

    Raises _UnreadableDeclaration when any declaration is present but cannot be parsed
    confidently, so membership is reported as unknown rather than as 'not a member'.
    """
    patterns: List[str] = []

    raw = _read_root_text(proj_root, "package.json")
    if raw is not None:
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise _UnreadableDeclaration("package.json") from exc
        ws = data.get("workspaces") if isinstance(data, dict) else None
        if isinstance(ws, dict):
            ws = ws.get("packages")  # 'nohoist' and other keys are ignored
        patterns.extend(_string_list(ws, "package.json"))

    raw = _read_root_text(proj_root, "pnpm-workspace.yaml")
    if raw is not None:
        patterns.extend(_pnpm_packages(raw))

    for toml_name, keys in (("Cargo.toml", ("workspace",)), ("pyproject.toml", ("tool", "uv", "workspace"))):
        raw = _read_root_text(proj_root, toml_name)
        if raw is None:
            continue
        try:
            node: Any = tomllib.loads(raw)
        except tomllib.TOMLDecodeError as exc:
            raise _UnreadableDeclaration(toml_name) from exc
        for key in keys:
            if not isinstance(node, dict):
                raise _UnreadableDeclaration(toml_name)
            node = node.get(key)
            if node is None:
                break
        if node is None:
            continue
        if not isinstance(node, dict):
            raise _UnreadableDeclaration(toml_name)
        patterns.extend(_string_list(node.get("members"), toml_name))
        patterns.extend("!" + e for e in _string_list(node.get("exclude"), toml_name))

    raw = _read_root_text(proj_root, "go.work")
    if raw is not None:
        patterns.extend(_go_work_uses(raw))
    return patterns


_GLOB_MATCH_MAX_STEPS = 100_000


class _GlobTooComplex(SafetyError):
    """A folder pattern needs more matching work than the fixed limit allows."""


def _glob_parts_match(pat: Sequence[str], path: Sequence[str]) -> bool:
    """Match pattern parts against path parts ('**' spans any number of parts).

    The set of path positions reachable after each pattern part is kept, so the work
    is at most len(pat) * (len(path) + 1) steps; past _GLOB_MATCH_MAX_STEPS the match
    is refused.
    """
    n_path = len(path)
    reach: List[int] = [0]
    steps = 0
    for part in pat:
        steps += len(reach)
        if steps > _GLOB_MATCH_MAX_STEPS:
            raise _GlobTooComplex(
                "A folder pattern in .adopt/rules.json is too complex to check, so it was not used."
            )
        if part == "**":
            reach = list(range(reach[0], n_path + 1))
        else:
            reach = [j + 1 for j in reach if j < n_path and fnmatch.fnmatchcase(path[j], part)]
        if not reach:
            return False
    return n_path in reach


def _workspace_glob_matches(pattern: str, folder: str) -> bool:
    pat = pattern.strip().replace("\\", "/")
    while pat.startswith("./"):
        pat = pat[2:]
    pat = pat.strip("/")
    if not pat:
        return False
    parts: List[str] = []
    for part in PurePosixPath(pat).parts:
        if not (part == "**" and parts and parts[-1] == "**"):
            parts.append(part)  # collapse '**/**' so matching stays polynomial
    return _glob_parts_match(parts, PurePosixPath(folder).parts)


# Control characters (C0, DEL, C1) and bidi/invisible formatting marks are escaped
# before a path is shown to the agent.
_UNSAFE_DISPLAY_CHARS = frozenset(
    [chr(c) for c in range(0x20)] + [chr(c) for c in range(0x7F, 0xA0)]
    + ["\u061c", "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2028", "\u2029", "\ufeff"]
    + [chr(c) for c in range(0x202A, 0x202F)] + [chr(c) for c in range(0x2066, 0x206A)]
)
_NOTICE_PATH_MAX = 200
_NOTICE_MAX = 600
_NOTICE_PREFIX = f"[defuzz: {NESTED_PROJECT_MANIFEST_CODE}: "
_NOTICE_FALLBACK = (
    f"[defuzz: {NESTED_PROJECT_MANIFEST_CODE}: A project manifest was written below the project root. "
    "The file was written where you asked; nothing was moved.]"
)


def _display_path(text: str, limit: int = _NOTICE_PATH_MAX) -> str:
    """Escape unsafe characters and middle-elide to at most `limit` characters."""
    out = "".join(
        (f"\\x{ord(c):02x}" if ord(c) < 0x100 else f"\\u{ord(c):04x}") if c in _UNSAFE_DISPLAY_CHARS else c
        for c in escape_text(text)
    )
    limit = max(limit, 5)
    if len(out) > limit:
        keep = limit - 3
        out = out[: (keep + 1) // 2] + "..." + out[len(out) - keep // 2:]
    return out


def _nested_manifest_message(name: str, folder: str, verified: bool) -> str:
    if verified:
        status = "That folder is not declared as a workspace member, so it is a second project root inside this project."
    else:
        status = ("Workspace membership could not be verified because a workspace declaration at the project "
                  "root could not be read; it may be a second project root inside this project.")
    tail = (f" {status} The file was written where you asked; nothing was moved. If this folder is meant to be "
            "part of this project, declare it in the root workspace settings. If it is a separate project, ask "
            "the user where it should live before writing more files there.")
    head = f"A project manifest ({name}) was written below the project root, in "
    budget = _NOTICE_MAX - len(_NOTICE_PREFIX) - len(head) - len("/.") - len(tail) - len("]")
    return f"{head}{_display_path(folder, min(_NOTICE_PATH_MAX, budget))}/.{tail}"


def check_nested_project_manifest(
    proj_root: Path,
    rel_path: str,
    rules_data: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Report a project manifest below the project root that is not a declared workspace member.

    Returns None when rel_path is not such a manifest (or is declared); otherwise a dict with
    code, rel, folder, verified and a plain message. When a workspace declaration cannot be
    parsed confidently, membership is unknown and the manifest is reported with verified=False.
    Never raises: any unexpected error returns None (no notice).
    """
    try:
        norm = os.path.normpath(rel_path).replace("\\", "/").lstrip("/")
        if not norm or norm == "." or norm.startswith("..") or ".." in PurePosixPath(norm).parts:
            return None
        parts = PurePosixPath(norm).parts
        if len(parts) < 2 or parts[-1] not in NESTED_PROJECT_MANIFESTS:
            return None
        dir_parts = parts[:-1]
        if any(p in _DEPENDENCY_BUILD_DIRS or p.startswith(".") for p in dir_parts):
            return None
        folder = "/".join(dir_parts)
        if any(folder == pref or folder.startswith(pref + "/") for pref in _declared_dir_prefixes(rules_data)):
            return None

        verified = True
        try:
            patterns = _workspace_patterns(Path(proj_root))
        except _UnreadableDeclaration:
            verified = False
            patterns = []
        if verified:
            included = any(_workspace_glob_matches(p, folder) for p in patterns if not p.startswith("!"))
            excluded = any(_workspace_glob_matches(p[1:], folder) for p in patterns if p.startswith("!"))
            if included and not excluded:
                return None

        return {
            "code": NESTED_PROJECT_MANIFEST_CODE,
            "rel": norm,
            "folder": folder,
            "verified": verified,
            "message": _nested_manifest_message(parts[-1], folder, verified),
        }
    except Exception:
        return None


def _format_nested_manifest_notice(found: Dict[str, Any]) -> str:
    try:
        notice = f"{_NOTICE_PREFIX}{found['message']}]"
    except Exception:
        return _NOTICE_FALLBACK
    if len(notice) > _NOTICE_MAX:
        notice = notice[: _NOTICE_MAX - 4] + "...]"
    return notice


_REDIRECT_NOTICE_PREFIX = "[defuzz: "
_REDIRECT_NOTICE_FALLBACK = (
    "[defuzz: Wrote the new file into a declared project folder per .adopt/rules.json.]"
)


def _format_redirect_notice(original_rel: str, placed_rel: str, reason: str) -> str:
    """Format a single-sentence plain redirect notice reusing _display_path escaping and _NOTICE_MAX cap."""
    try:
        clean_reason = " ".join(str(reason or "declared folder rule").split()).rstrip(".")
        safe_reason = _display_path(clean_reason or "declared folder rule", 140).rstrip(".")
        mid1 = "Wrote "
        mid2 = " instead of "
        mid3 = f" because .adopt/rules.json declares: {safe_reason}.]"
        overhead = len(_REDIRECT_NOTICE_PREFIX) + len(mid1) + len(mid2) + len(mid3)
        avail = max(20, _NOTICE_MAX - overhead)
        p_budget = min(_NOTICE_PATH_MAX, max(10, avail // 2))
        o_budget = min(_NOTICE_PATH_MAX, max(10, avail - p_budget))
        safe_placed = _display_path(str(placed_rel), p_budget)
        safe_orig = _display_path(str(original_rel), o_budget)
        notice = f"{_REDIRECT_NOTICE_PREFIX}{mid1}{safe_placed}{mid2}{safe_orig}{mid3}"
        if len(notice) > _NOTICE_MAX:
            notice = notice[: _NOTICE_MAX - 4] + "...]"
        return notice
    except Exception:
        return _REDIRECT_NOTICE_FALLBACK


def _explicit_declared_dir_prefixes(rules_data: Dict[str, Any]) -> Set[str]:
    """Return non-fallback declared directory prefixes from rules_data['declared_dirs']."""
    prefixes: Set[str] = set()
    for item in rules_data.get("declared_dirs") or []:
        if not isinstance(item, dict) or item.get("source") == "fallback":
            continue
        dp = str(item.get("dir") or "").strip("/")
        if dp and dp not in {"_inbox", "_archive"} and not dp.startswith(("_inbox/", "_archive/")):
            prefixes.add(dp)
    return prefixes


def _rule_glob_matches_path(pattern: str, norm: str, filename: str) -> bool:
    clean = pattern.strip().replace("\\", "/")
    while clean.startswith("./"):
        clean = clean[2:]
    clean = clean.lstrip("/")
    if not clean:
        return False
    if "/" in clean:
        return _workspace_glob_matches(clean, norm) or fnmatch.fnmatchcase(norm, clean)
    return fnmatch.fnmatchcase(filename, clean)


def _checked_rule_dest(rule: Dict[str, Any]) -> Optional[str]:
    """The rule's dest_dir as validate_rules_spec accepts it (whitespace and './' removed), or None."""
    try:
        return _validate_safe_rel_prefix(rule.get("dest_dir") or "", "placement_rules.dest_dir", allow_dot=False)
    except SafetyError:
        return None


def _checked_rule_reason(rule: Dict[str, Any], default: str) -> str:
    """The rule's reason as validate_rules_spec keeps it: one line, at most 100 characters."""
    return " ".join(str(rule.get("reason") or default).split())[:100] or default


def _match_explicit_declared_rule(
    rules_data: Dict[str, Any],
    norm: str,
    filename: str,
    ext: str,
    explicit_dirs: Set[str],
) -> Optional[Dict[str, Any]]:
    for pr in rules_data.get("placement_rules") or []:
        if not isinstance(pr, dict) or pr.get("source") == "fallback":
            continue
        if pr.get("root_only") is True and "/" in norm:
            continue
        dest_dir = _checked_rule_dest(pr)
        if (
            not dest_dir
            or dest_dir in {"_inbox", "_archive"}
            or dest_dir.startswith(("_inbox/", "_archive/"))
            or not any(dest_dir == d or dest_dir.startswith(d + "/") for d in explicit_dirs)
        ):
            continue
        raw_exts = [str(e).lower() for e in (pr.get("match_ext") or []) if e]
        raw_globs = [str(g).strip() for g in (pr.get("match_glob") or []) if str(g).strip()]
        if not raw_exts and not raw_globs:
            continue
        if raw_exts and (not ext or ext not in raw_exts):
            continue
        if raw_globs and not any(_rule_glob_matches_path(g, norm, filename) for g in raw_globs):
            continue
        return pr
    return None


def resolve_placement_for_new_path(
    proj_root: Path,
    rel_path: str,
    rules_data: Dict[str, Any],
    *,
    mode: str = TRUST_MODE_FULL,
) -> Optional[Dict[str, str]]:
    """Determine if rel_path should be redirected by placement rules.

    Returns None if rel_path is exempt or already in a declared folder.
    Otherwise returns {"original_rel": ..., "placed_rel": ..., "kind": ..., "dest_dir": ..., "reason": ...}.
    """
    norm = os.path.normpath(rel_path).replace("\\", "/").lstrip("/")
    if not norm or norm == "." or norm.startswith("..") or ("/" in norm and ".." in PurePosixPath(norm).parts):
        return None

    parts = PurePosixPath(norm).parts
    top, filename = parts[0], parts[-1]
    if top in EXEMPT_TOP_DIRS or top.startswith(".") or filename.startswith(".") or filename in PROTECTED_ROOT_FILES:
        return None

    if mode == TRUST_MODE_DECLARED_ONLY:
        if filename in NESTED_PROJECT_MANIFESTS:
            return None
        if is_protected_root_path(norm, proj_root=proj_root, rules_data=rules_data):
            return None
        explicit_dirs = _explicit_declared_dir_prefixes(rules_data)
        if any(norm == pref or norm.startswith(pref + "/") for pref in explicit_dirs):
            return None
        _, ext = os.path.splitext(filename.lower())
        matched_explicit = _match_explicit_declared_rule(rules_data, norm, filename, ext, explicit_dirs)
        if matched_explicit is None:
            return None
        dest_dir = _checked_rule_dest(matched_explicit)
        if dest_dir is None:
            return None
        kind = str(matched_explicit.get("kind") or "matched")
        reason = _checked_rule_reason(matched_explicit, f"matched {ext or filename} -> {dest_dir}/")
        sub_parts = [p for p in parts[:-1] if p != "_inbox"]
        placed_parent = "/".join([dest_dir, *sub_parts])
        placed_rel = f"{placed_parent}/{filename}"
        if placed_rel == norm:
            return None
        return {
            "original_rel": norm,
            "placed_rel": placed_rel,
            "kind": kind,
            "dest_dir": dest_dir,
            "placed_parent": placed_parent,
            "reason": reason,
        }

    if mode != TRUST_MODE_FULL:
        return None

    if any(norm == pref or norm.startswith(pref + "/") for pref in _declared_dir_prefixes(rules_data)):
        return None

    _, ext = os.path.splitext(filename.lower())
    matched_rule = next(
        (
            pr for pr in (rules_data.get("placement_rules") or [])
            if ext and ext in [str(e).lower() for e in (pr.get("match_ext") or [])]
        ),
        None,
    )
    if matched_rule is not None:
        checked_dest = _checked_rule_dest(matched_rule)
        if checked_dest is None:
            raise SafetyError("A placement rule in .adopt/rules.json names an unsafe folder.")
        dest_dir = checked_dest
        kind = str(matched_rule.get("kind") or "matched")
        reason = _checked_rule_reason(matched_rule, f"matched {ext} -> {dest_dir}/")
    else:
        dest_dir = "_inbox"
        kind = "unknown"
        reason = "unmatched file kind routed to _inbox/"

    sub_parts = list(parts[:-1])
    if sub_parts and sub_parts[0] == "_inbox":
        sub_parts = sub_parts[1:]
    placed_parent = "/".join([dest_dir, *sub_parts])
    placed_rel = f"{placed_parent}/{filename}"
    if placed_rel == norm:
        return None

    return {
        "original_rel": norm,
        "placed_rel": placed_rel,
        "kind": kind,
        "dest_dir": dest_dir,
        "placed_parent": placed_parent,
        "reason": reason,
    }


def _write_succeeded(result: str, placed_path: str) -> bool:
    """True when the write_file result reports no error and the placed file exists."""
    try:
        parsed = json.loads(result)
    except Exception:
        parsed = None
    if isinstance(parsed, dict) and (parsed.get("error") or parsed.get("success") is False):
        return False
    return os.path.isfile(placed_path) and not os.path.islink(placed_path)


def on_pre_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    tool_call_id: str = "",
    auto_place_enabled: bool = True,
    db_path: Optional[Path | str] = None,
    require_registered: Optional[bool] = None,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """Hook callback for pre_tool_call. Redirects new write_file paths outside declared folders."""
    try:
        if not auto_place_enabled or tool_name != "write_file" or not isinstance(args, dict):
            return None

        raw_path = args.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None

        target_lex = _lexical_abs(raw_path)
        if os.path.lexists(target_lex):
            return None

        proj_root = find_adopted_root(target_lex)
        if proj_root is None:
            return None
    except Exception:
        return None

    global _LAST_HOOK_SKIP_REASON
    root_key = str(proj_root)
    try:
        trust_info, loaded_rules = _inspect_and_load_project_trust(proj_root, db_path=db_path)
        if not trust_info["trusted"] or loaded_rules is None:
            raise SafetyError(trust_info["reason"])
        rules_data = loaded_rules
        trust_mode = str(trust_info.get("mode") or TRUST_MODE_FULL)
    except SafetyError as exc:
        reason_str = str(exc)
        short_reason = _classify_trust_skip_reason(reason_str)
        notice = _format_trust_failure_notice(proj_root, short_reason)
        with _PENDING_NOTES_LOCK:
            _LAST_HOOK_SKIP_REASON = reason_str
            if _record_notified_root(_NOTIFIED_TRUST_ROOTS, root_key):
                _stash_pending_skip_notice(tool_call_id, target_lex, notice)
        return None
    except Exception as exc:
        _record_unexpected_error_skip(exc, root_key, tool_call_id, target_lex)
        return None
    with _PENDING_NOTES_LOCK:
        _LAST_HOOK_SKIP_REASON = None

    try:
        rel_path = os.path.relpath(str(target_lex), str(proj_root)).replace("\\", "/")
    except ValueError:
        return None
    except Exception as exc:
        if trust_mode != TRUST_MODE_DECLARED_ONLY:
            _record_unexpected_error_skip(exc, root_key, tool_call_id, target_lex)
        return None
    if rel_path.startswith(".."):
        return None

    try:
        decision = resolve_placement_for_new_path(proj_root, rel_path, rules_data, mode=trust_mode)
        if decision is None:
            nested_rules = (
                {
                    **rules_data,
                    "declared_dirs": [
                        d for d in (rules_data.get("declared_dirs") or [])
                        if isinstance(d, dict) and d.get("source") != "fallback"
                    ],
                    "placement_rules": [
                        r for r in (rules_data.get("placement_rules") or [])
                        if isinstance(r, dict) and r.get("source") != "fallback"
                    ],
                }
                if trust_mode == TRUST_MODE_DECLARED_ONLY
                else rules_data
            )
            nested = check_nested_project_manifest(proj_root, rel_path, nested_rules)
            if nested is not None:
                with _PENDING_NOTES_LOCK:
                    _stash_pending_skip_notice(tool_call_id, target_lex, _format_nested_manifest_notice(nested))
            return None

        placed_rel = decision["placed_rel"]
        placed_full = verify_nofollow_within_root(proj_root, placed_rel)
        if os.path.lexists(placed_full):
            if trust_mode == TRUST_MODE_DECLARED_ONLY:
                return None
            return {
                "action": "block",
                "message": (
                    f"defuzz refused write_file collision: placement target "
                    f"'{_display_path(placed_rel)}' already exists in {_display_path(str(proj_root))}."
                ),
            }

        # Create the folder below the root the registry checked (its real path), opened
        # without following links: a parent swapped for a link after the check is refused.
        real_root = Path(trust_info["project_root"])
        with PinnedFolder(real_root, role="place_root", create=False) as pin:
            if pin.real != real_root:
                raise SafetyError(f"Refusing to place: the project folder moved after it was checked: {proj_root}")
            safe_mkdirs(real_root, decision["placed_parent"], base=pin)
        note_info = {
            "proj_root": str(proj_root),
            "original_path": str(target_lex),
            "placed_path": str(placed_full),
            "original_rel": decision["original_rel"],
            "placed_rel": placed_rel,
            "kind": decision["kind"],
            "reason": decision["reason"],
            "trust_mode": trust_mode,
        }
        with _PENDING_NOTES_LOCK:
            if tool_call_id:
                _PENDING_NOTES[f"id:{tool_call_id}"] = note_info
            _PENDING_NOTES[f"path:{placed_full}"] = note_info

        return {"action": "modify", "args": {"path": str(placed_full)}}
    except SafetyError as exc:
        if trust_mode == TRUST_MODE_DECLARED_ONLY:
            return None
        return {"action": "block", "message": f"defuzz safety refusal: {exc}"}
    except Exception as exc:
        if trust_mode != TRUST_MODE_DECLARED_ONLY:
            _record_unexpected_error_skip(exc, root_key, tool_call_id, target_lex)
        return None


def _pop_pending_note(tool_call_id: str, args: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    note_info: Optional[Dict[str, str]] = None
    with _PENDING_NOTES_LOCK:
        if tool_call_id and f"id:{tool_call_id}" in _PENDING_NOTES:
            note_info = _PENDING_NOTES.pop(f"id:{tool_call_id}", None)
        if isinstance(args, dict) and isinstance(args.get("path"), str):
            p_key = f"path:{_lexical_abs(args['path'])}"
            popped = _PENDING_NOTES.pop(p_key, None)
            if note_info is None:
                note_info = popped
    return note_info


def on_transform_tool_result(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    result: Any = None,
    tool_call_id: str = "",
    **kwargs: Any,
) -> Optional[str]:
    """Hook callback for transform_tool_result. Adds placed_at note when write_file was redirected."""
    try:
        if tool_name != "write_file" or not isinstance(result, str):
            return None

        note_info = _pop_pending_note(tool_call_id, args)
        skip_notice = _pop_pending_skip_notice(tool_call_id, args)
        if note_info is None:
            if skip_notice is None:
                return None
            try:
                parsed_skip = json.loads(result)
                if isinstance(parsed_skip, dict):
                    parsed_skip["defuzz_notice"] = skip_notice
                    return json.dumps(parsed_skip)
            except Exception:
                pass
            return f"{result}\n{skip_notice}"

        if not _write_succeeded(result, note_info["placed_path"]):
            return None

        try:
            _append_place_log(
                Path(note_info["proj_root"]),
                {
                    "timestamp": int(time.time()),
                    "mode": "pre_tool_call",
                    "original_rel": note_info["original_rel"],
                    "placed_rel": note_info["placed_rel"],
                    "kind": note_info["kind"],
                    "reason": note_info["reason"],
                },
            )
        except (SafetyError, OSError):
            pass

        if note_info.get("trust_mode") == TRUST_MODE_DECLARED_ONLY:
            redirect_notice = _format_redirect_notice(
                note_info["original_rel"],
                note_info["placed_rel"],
                note_info["reason"],
            )
            try:
                parsed_decl = json.loads(result)
                if isinstance(parsed_decl, dict):
                    parsed_decl["placed_by_adopt"] = {
                        "from": note_info["original_rel"],
                        "to": note_info["placed_rel"],
                        "kind": note_info["kind"],
                        "note": redirect_notice,
                    }
                    parsed_decl["defuzz_notice"] = redirect_notice
                    return json.dumps(parsed_decl)
            except Exception:
                pass
            return f"{result}\n{redirect_notice}"

        note_text = _format_redirect_notice(
            note_info["original_rel"],
            note_info["placed_rel"],
            note_info["reason"],
        )
        try:
            parsed = json.loads(result)
            if isinstance(parsed, dict):
                parsed["placed_by_adopt"] = {
                    "from": note_info["original_rel"],
                    "to": note_info["placed_rel"],
                    "kind": note_info["kind"],
                    "note": note_text,
                }
                return json.dumps(parsed)
        except Exception:
            pass
        return f"{result}\n{note_text}"
    except Exception:
        return None


def place_existing_files(
    proj_root: os.PathLike | str,
    rel_paths: Sequence[str],
    *,
    db_path: Optional[Path | str] = None,
    require_registered: Optional[bool] = None,
    _validated_rules: Optional[Dict[str, Any]] = None,
    _trust_mode: Optional[str] = None,
) -> List[Dict[str, str]]:
    """Place one or more existing loose files inside proj_root according to .adopt/rules.json."""
    root = assert_safe_root(proj_root, role="place_root")
    if _validated_rules is not None:
        rules_data = _validated_rules
        effective_mode = _trust_mode or TRUST_MODE_FULL
    else:
        info, loaded = _inspect_and_load_project_trust(root, db_path=db_path)
        if not info["trusted"] or loaded is None:
            raise SafetyError(info["reason"])
        rules_data = loaded
        effective_mode = str(info.get("mode") or TRUST_MODE_FULL)
    moved: List[Dict[str, str]] = []

    for rp in rel_paths:
        src_full = verify_nofollow_within_root(root, rp)
        if not src_full.is_file():
            raise SafetyError(f"Cannot place non-existent or non-regular file: {rp}")
        norm_rel = os.path.relpath(str(src_full), str(root)).replace("\\", "/")
        decision = resolve_placement_for_new_path(root, norm_rel, rules_data, mode=effective_mode)
        if decision is None:
            continue
        placed_rel = decision["placed_rel"]
        dst_full = verify_nofollow_within_root(root, placed_rel)
        if os.path.lexists(dst_full):
            raise SafetyError(f"Refusing placement collision: {placed_rel} already exists")
        safe_mkdirs(root, decision["placed_parent"])
        shutil.move(str(src_full), str(dst_full))
        entry = {
            "timestamp": int(time.time()),
            "mode": "cli_place",
            "original_rel": norm_rel,
            "placed_rel": placed_rel,
            "kind": decision["kind"],
            "reason": decision["reason"],
        }
        _append_place_log(root, entry)
        moved.append(entry)
    return moved


def sweep_inbox(
    proj_root: os.PathLike | str,
    *,
    db_path: Optional[Path | str] = None,
    require_registered: Optional[bool] = None,
) -> List[Dict[str, str]]:
    """Sweep files in _inbox/ (recursively, without following symlinks) that now match an extension rule."""
    root = assert_safe_root(proj_root, role="sweep_root")
    info, loaded = _inspect_and_load_project_trust(root, db_path=db_path)
    if not info["trusted"] or loaded is None:
        raise SafetyError(info["reason"])
    rules_data = loaded
    effective_mode = str(info.get("mode") or TRUST_MODE_FULL)
    inbox_dir = root / "_inbox"
    if not inbox_dir.is_dir() or os.path.islink(inbox_dir):
        return []
    candidates: List[str] = []
    for dirpath, dirnames, filenames in os.walk(str(inbox_dir), topdown=True, followlinks=False):
        keep_dirs: List[str] = []
        for dname in sorted(dirnames):
            if dname.startswith("."):
                continue
            try:
                st = os.lstat(os.path.join(dirpath, dname))
            except OSError:
                continue
            if not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode):
                keep_dirs.append(dname)
        dirnames[:] = keep_dirs

        for fname in sorted(filenames):
            if fname.startswith("."):
                continue
            f_full = os.path.join(dirpath, fname)
            try:
                st = os.lstat(f_full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            rel = os.path.relpath(f_full, str(root)).replace("\\", "/")
            decision = resolve_placement_for_new_path(root, rel, rules_data, mode=effective_mode)
            if decision is not None and decision["dest_dir"] != "_inbox":
                candidates.append(rel)
    return place_existing_files(
        root,
        candidates,
        db_path=db_path,
        require_registered=require_registered,
        _validated_rules=rules_data,
        _trust_mode=effective_mode,
    )


def _rules_for_agents_guide(rules_data: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of rules_data whose free text (rule reasons, folder summaries and whys) has
    control, bidi and format characters escaped, for rendering into AGENTS.md only."""
    def _escaped(item: Any, keys: Tuple[str, ...]) -> Any:
        if not isinstance(item, dict):
            return item
        return {**item, **{k: _display_path(str(item[k]), 400) for k in keys if isinstance(item.get(k), str)}}

    return {
        **rules_data,
        "declared_dirs": [_escaped(d, ("summary", "why")) for d in (rules_data.get("declared_dirs") or [])],
        "placement_rules": [_escaped(r, ("reason",)) for r in (rules_data.get("placement_rules") or [])],
    }


def add_placement_rule(
    proj_root: os.PathLike | str,
    ext: str,
    dest_dir: str,
    *,
    kind: Optional[str] = None,
    lfs: bool = False,
    reason: Optional[str] = None,
    db_path: Optional[Path | str] = None,
    require_registered: Optional[bool] = None,
    registry: Optional[Any] = None,
) -> Dict[str, Any]:
    """Add or update an extension placement rule in .adopt/rules.json."""
    root = assert_safe_root(proj_root, role="rule_root")
    ext_val = _validate_extensions([ext], "add_placement_rule.ext")[0]
    clean_dest = _validate_safe_rel_prefix(dest_dir, "add_placement_rule.dest_dir", allow_dot=False)
    new_rule = {
        "kind": kind or f"custom_{ext_val.lstrip('.')}",
        "match_ext": [ext_val],
        "dest_dir": clean_dest,
        "lfs": bool(lfs),
        "reason": reason or f"route {ext_val} files to {clean_dest}/",
    }
    target_db = Path(db_path).expanduser() if db_path is not None else state_db_path()
    with _RULES_MUTATION_LOCK:
        trust_info, loaded_rules = _inspect_and_load_project_trust(root, db_path=db_path)
        if not trust_info["trusted"] or loaded_rules is None:
            raise SafetyError(trust_info["reason"])
        rules_data = loaded_rules
        if trust_info.get("mode") == TRUST_MODE_DECLARED_ONLY:
            explicit_dirs = _explicit_declared_dir_prefixes(rules_data)
            if not any(clean_dest == d or clean_dest.startswith(d + "/") for d in explicit_dirs):
                declared_list = list(rules_data.get("declared_dirs") or [])
                declared_list.append({
                    "dir": clean_dest,
                    "summary": f"{new_rule['kind']} files",
                    "why": new_rule["reason"],
                })
                rules_data["declared_dirs"] = declared_list
        # Take only this extension away from other rules. A rule that also needs a name
        # pattern (match_glob) is narrower than a plain extension rule, so it is kept and
        # the new rule goes right after the last such rule: first match wins, so it keeps
        # winning for the files it names. Rule order is otherwise unchanged.
        placement_rules: List[Dict[str, Any]] = []
        insert_at = 0
        narrowed: List[str] = []
        removed: List[Dict[str, Any]] = []
        kept_patterns: List[str] = []
        for r in rules_data.get("placement_rules") or []:
            exts = list(r.get("match_ext") or []) if isinstance(r, dict) else []
            if ext_val not in exts:
                placement_rules.append(r)
                continue
            if r.get("match_glob"):
                placement_rules.append(r)
                insert_at = len(placement_rules)
                kept_patterns.append(f"{r.get('dest_dir')}/")
                continue
            rest = [e for e in exts if e != ext_val]
            if rest:
                placement_rules.append({**r, "match_ext": rest})
                narrowed.append(f"{r.get('dest_dir')}/")
            else:
                removed.append(r)
        placement_rules.insert(insert_at, new_rule)
        rules_data["placement_rules"] = placement_rules
        # A folder this function declared only for a rule it has now removed is dropped,
        # so no declared folder is left without a reason.
        still_used = {str(r.get("dest_dir")) for r in placement_rules if isinstance(r, dict)}
        orphaned = {
            (str(r.get("dest_dir")), f"{r.get('kind')} files", r.get("reason"))
            for r in removed
            if str(r.get("dest_dir")) not in still_used
        }
        if orphaned and rules_data.get("declared_dirs"):
            rules_data["declared_dirs"] = [
                d for d in rules_data["declared_dirs"]
                if not (isinstance(d, dict) and (d.get("dir"), d.get("summary"), d.get("why")) in orphaned)
            ]
        rules_bytes = (json.dumps(rules_data, indent=2, sort_keys=False) + "\n").encode("utf-8")
        new_hash = hashlib.sha256(rules_bytes).hexdigest()
        safe_write_bytes(root, ".adopt/rules.json", rules_bytes, overwrite=True)
        update_rules_hash(root.resolve(), new_hash, db_path=target_db)

    lookup = (
        registry.get_project
        if registry is not None and hasattr(registry, "get_project")
        else (registry if callable(registry) else get_project)
    )
    try:
        rec = lookup(root.resolve(), db_path=target_db)
    except Exception:
        rec = None

    guide_rules = _rules_for_agents_guide(rules_data)
    if not isinstance(rec, dict):
        agents_md_result = write_agents_md(root, guide_rules, preserve_kit_blocks=True)
    else:
        template_id = str(rec.get("template_id") or "")
        kit_id_to_preserve = (
            template_id[len("kit:") :]
            if template_id.startswith("kit:") and template_id[len("kit:") :]
            else None
        )
        if kit_id_to_preserve is not None:
            agents_md_result = write_agents_md(
                root,
                guide_rules,
                preserve_kit_blocks=True,
                kit_ids=(kit_id_to_preserve,),
            )
        else:
            agents_md_result = write_agents_md(root, guide_rules, preserve_kit_blocks=False)
    safe_mkdirs(root, clean_dest)
    git_dir = root / ".git"
    if git_dir.is_dir() and not os.path.islink(git_dir):
        # Deliberately pass -f so generated .adopt/rules.json and AGENTS files are tracked even if ignored.
        git_add = run_git_hardened(root, ["add", "-f", "--", ".adopt/rules.json", *agents_md_result["paths"]])
        if git_add.returncode != 0:
            raise SafetyError(f"Failed to stage updated rules and AGENTS guide in {root}")
    message = f"New {ext_val} files now go to {clean_dest}/."
    if narrowed:
        message += f" The rule for {', '.join(narrowed)} keeps its other file types but no longer takes {ext_val}."
    if kept_patterns:
        message += (
            f" Named {ext_val} files still go to {', '.join(kept_patterns)} because that rule comes first;"
            " to move them too, remove it from .adopt/rules.json and trust the project again."
        )
    return {**new_rule, "message": _display_path(message, 600)}


def undo_placements(
    proj_root: os.PathLike | str,
    count: int = 1,
    *,
    db_path: Optional[Path | str] = None,
    require_registered: Optional[bool] = None,
) -> List[Dict[str, str]]:
    """Undo the last `count` file placements recorded in .adopt/place-log.json."""
    root = assert_safe_root(proj_root, role="undo_root")
    _require_registered_project(root, db_path=db_path, require_registered=require_registered)
    entries = _load_place_log(root)
    if not entries or count <= 0:
        return []
    undone: List[Dict[str, str]] = []
    for _ in range(min(count, len(entries))):
        last = entries.pop()
        placed_rel, orig_rel = last["placed_rel"], last["original_rel"]
        placed_full = verify_nofollow_within_root(root, placed_rel)
        orig_full = verify_nofollow_within_root(root, orig_rel)
        if placed_full.exists() and not os.path.lexists(orig_full):
            safe_mkdirs(root, os.path.dirname(orig_rel) or ".")
            shutil.move(str(placed_full), str(orig_full))
            undone.append({"restored": orig_rel, "from": placed_rel})
    safe_write_text(
        root,
        ".adopt/place-log.json",
        json.dumps(entries, indent=2, sort_keys=False) + "\n",
        overwrite=True,
    )
    return undone
