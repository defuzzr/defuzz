#!/usr/bin/env python3
"""toolchk: refuse a bench/debug/lint run on a tool whose version nobody chose.

Reads ``TOOLS.lock`` (TOML, schema 1), probes every needed tool, and blocks when a needed tool is not in the lock
or its installed version differs from the locked one in either direction. Upstream "latest" and age are only ever
reported as advisory information.

Exit codes:
    0  ok
    2  blocked (drift or unlisted)
    3  probe failed (tool missing or version unreadable)
    4  lock file broken
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import glob
import importlib.metadata
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from pathlib import Path, PurePath
from typing import Any, NoReturn

try:
    from .safety import SafetyError as _SafetyError
    from .safety import resolve_hermes_home
    from .safety import verify_nofollow_within_root as _safety_verify_nofollow
    from .scanner import _is_secret_filename as _scanner_is_secret_filename
except ImportError:  # pragma: no cover - standalone script execution
    _SafetyError = RuntimeError  # type: ignore[misc,assignment]
    _safety_verify_nofollow = None

    # Mirrors scanner._is_secret_filename (scanner.py:59-102) when run standalone.
    _FALLBACK_SECRET_EXACT = frozenset({
        ".env", ".netrc", ".pgpass", ".npmrc", ".pypirc", "credentials",
        "credentials.json", "client_secret.json", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    })
    _FALLBACK_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".schema")
    _FALLBACK_SECRET_EXTS = frozenset({".pem", ".key", ".p12", ".pfx", ".keystore"})

    def _scanner_is_secret_filename(rel_path: str) -> bool:
        lower = os.path.basename(rel_path).lower()
        if lower.endswith(_FALLBACK_SAFE_SUFFIXES):
            return False
        _, ext = os.path.splitext(lower)
        return lower in _FALLBACK_SECRET_EXACT or lower.startswith(".env.") or ext in _FALLBACK_SECRET_EXTS

    def resolve_hermes_home() -> Path:
        try:
            from hermes_constants import get_hermes_home

            home = get_hermes_home()
            if home:
                return Path(home).expanduser()
        except Exception:
            pass
        raw = os.environ.get("HERMES_HOME", "").strip()
        return Path(os.path.expandvars(raw)).expanduser() if raw else Path.home() / ".hermes"

# A version and an optional pre-release/build tail (hyphens allowed inside), never ending in "." or "-".
# The look-behind keeps the search linear on long digit runs.
VERSION_RE = re.compile(r"(?<!\d)\d+(?:\.\d+)+(?:[-+.][0-9A-Za-z](?:[0-9A-Za-z.+-]{0,29}[0-9A-Za-z])?)?")
SAFE_VERSION_TOKEN_RE = re.compile(
    r"^(?=.{1,32}$)(?=.{0,2}\d)(?!.*[^.]{20})v?[._-]?[0-9][0-9A-Za-z.+_-]*$"
)
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")

REQUIRED_KEYS = ("version", "chosen", "reason", "probe")
VALID_PROBES = ("command", "module", "interpreter", "pm", "file")
VALID_SOURCES = ("auto", "human", "agent")
VALID_ENFORCE = ("warn", "block")
SETUP_HINT = "or run `hermes defuzz setup-tools` to see what it can install."
_VERSION_PART_RE = re.compile(r"^(\d+)")
ALLOWED_COMMAND_ARGS: frozenset[str] = frozenset(
    {"--version", "-V", "-v", "version", "-version", "--help"}
)
COMMAND_ALIASES: dict[str, frozenset[str]] = {
    "rust": frozenset({"rustc"}),
    "rustc": frozenset({"rust"}),
    "python": frozenset({"python3"}),
    "python3": frozenset({"python"}),
    "node": frozenset({"nodejs"}),
    "nodejs": frozenset({"node"}),
    "ripgrep": frozenset({"rg"}),
    "rg": frozenset({"ripgrep"}),
    "go": frozenset({"go"}),
}

MAX_LOCK_BYTES = 256 * 1024
MAX_FILE_PROBE_BYTES = 64 * 1024
MAX_PROBE_OUTPUT_BYTES = 64 * 1024
MAX_FILE_REGEX_CHARS = 128
MAX_FILE_LINE_CHARS = 512
DEFAULT_PROBE_TIMEOUT = 20.0

ALLOWED_PROBE_FILES: tuple[str, ...] = (
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "rust-toolchain.toml",
    "rust-toolchain",
    "go.mod",
    "global.json",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".tool-versions",
    "houdini.version",
    "VERSION",
    "*.uproject",
    "*.uplugin",
)

ALLOWED_ADVISORY_JSON_FILES: tuple[str, ...] = (
    "~/.cua-driver/version_check.json",
)

DEFAULT_HEADER: dict[str, Any] = {
    "schema": 1,
    "enforce": "warn",
    "age_nudge_months": 12,
    "network": False,
}

HEADER_KEY_ORDER = ("schema", "enforce", "age_nudge_months", "network")
TOOL_KEY_ORDER = (
    "version", "minimum", "chosen", "reason", "probe", "argv", "resolve", "module",
    "package", "file", "key", "regex", "source", "advisory",
)
ADVISORY_KEY_ORDER = ("kind", "path", "json", "key")

_TOML_SHORT_ESCAPES: dict[int, str] = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f",
    0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\",
}


class PreflightError(RuntimeError):
    """Raised when a lock is broken (4), a probe fails (3), or a tool is drifted/unlisted (2)."""

    def __init__(self, code: int, report: dict[str, Any]) -> None:
        super().__init__(report.get("summary", f"preflight error (code {code})"))
        self.code = code
        self.report = report


def _is_same_or_subpath(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_non_empty_str(val: Any) -> bool:
    return isinstance(val, str) and bool(val.strip())


def _ordered_keys(mapping: dict[str, Any], preferred: tuple[str, ...]) -> list[str]:
    return [k for k in preferred if k in mapping] + sorted(k for k in mapping if k not in preferred)


def _broken_lock_report(lock_path: Path, message: str, enforce: str = "warn") -> dict[str, Any]:
    summary = f"{lock_path}: {message}"
    eff_enforce = enforce if enforce in VALID_ENFORCE else "warn"
    return {
        "ok": False,
        "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "lock": str(Path(os.path.abspath(os.path.expanduser(str(lock_path))))),
        "enforce": eff_enforce,
        "tools": {},
        "blocked": [summary],
        "probe_failed": [],
        "warnings": [],
        "summary": summary,
        "text": "",
    }


def _raise_broken_lock(lock_path: Path, message: str, enforce: str = "warn") -> NoReturn:
    raise PreflightError(4, _broken_lock_report(lock_path, message, enforce=enforce))


def _validate_iso_date(val: Any) -> bool:
    if not isinstance(val, str) or not ISO_DATE_RE.match(val):
        return False
    try:
        dt.date.fromisoformat(val)
        return True
    except ValueError:
        return False


def _extract_leading_comments(text: str) -> list[str]:
    comments: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if comments:
                comments.append("")
            continue
        if stripped.startswith("#"):
            comments.append(line.rstrip())
        else:
            break
    while comments and comments[-1] == "":
        comments.pop()
    return comments


def _read_regular_file_bytes(
    target: Path,
    max_bytes: int,
    *,
    strict_max: bool,
    expected_stat: os.stat_result | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(target), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            if strict_max and expected_stat is None:
                raise OSError("refusing non-regular lock file")
            raise ValueError("non_regular_file_refused")
        if expected_stat is not None and (st.st_dev, st.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
            raise ValueError("file_changed_during_open")
        if strict_max and st.st_size > max_bytes:
            if expected_stat is not None:
                raise ValueError("probe_file_too_large")
            raise ValueError(f"lock file size {st.st_size} exceeds {max_bytes} bytes")
        limit = max_bytes + 1 if strict_max else max_bytes
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if strict_max and total > max_bytes:
            if expected_stat is not None:
                raise ValueError("probe_file_too_large")
            raise ValueError(f"lock file exceeds {max_bytes} bytes")
        return b"".join(chunks)[:max_bytes]
    finally:
        os.close(fd)


def _read_lock_text(lock_path: Path) -> str:
    return _read_regular_file_bytes(lock_path, MAX_LOCK_BYTES, strict_max=True).decode("utf-8")


def _validate_entry_probe_fields(
    lock_path: Path,
    name: str,
    entry: dict[str, Any],
    enforce: str,
) -> None:
    kind = entry.get("probe")
    if kind not in VALID_PROBES:
        _raise_broken_lock(
            lock_path,
            f"[{name}] invalid probe kind {kind!r} (expected one of {', '.join(VALID_PROBES)})",
            enforce,
        )

    if kind == "command":
        argv = entry.get("argv")
        if not isinstance(argv, list) or not argv or not all(_is_non_empty_str(x) for x in argv):
            _raise_broken_lock(lock_path, f"[{name}] command probe requires non-empty string list 'argv'", enforce)
        if entry.get("resolve") is not None and entry["resolve"] != "hermes-tools":
            _raise_broken_lock(lock_path, f"[{name}] invalid resolve {entry['resolve']!r} (expected 'hermes-tools')", enforce)
    elif kind == "module":
        if entry.get("module") is not None and not _is_non_empty_str(entry["module"]):
            _raise_broken_lock(lock_path, f"[{name}] module probe 'module' must be a non-empty string", enforce)
    elif kind == "pm":
        if entry.get("package") is not None and not _is_non_empty_str(entry["package"]):
            _raise_broken_lock(lock_path, f"[{name}] pm probe 'package' must be a non-empty string", enforce)
    elif kind == "file":
        if not _is_non_empty_str(entry.get("file")):
            _raise_broken_lock(lock_path, f"[{name}] file probe requires non-empty string 'file'", enforce)
        has_key = entry.get("key") is not None
        has_regex = entry.get("regex") is not None
        if has_key == has_regex:
            _raise_broken_lock(lock_path, f"[{name}] file probe requires exactly one of 'key' or 'regex'", enforce)
        if has_key and not _is_non_empty_str(entry["key"]):
            _raise_broken_lock(lock_path, f"[{name}] file probe 'key' must be a non-empty string", enforce)
        if has_regex and not _is_non_empty_str(entry["regex"]):
            _raise_broken_lock(lock_path, f"[{name}] file probe 'regex' must be a non-empty string", enforce)

    if entry.get("advisory") is not None and not isinstance(entry["advisory"], dict):
        _raise_broken_lock(lock_path, f"[{name}] 'advisory' must be a table", enforce)


def _validate_lock_header(lock_path: Path, raw_header: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(raw_header, dict):
        _raise_broken_lock(lock_path, "[lock] must be a table")
    header = {**DEFAULT_HEADER, **raw_header}
    if header.get("schema") != 1:
        _raise_broken_lock(lock_path, f"unsupported [lock].schema {header.get('schema')!r} (expected 1)")
    if header.get("enforce") not in VALID_ENFORCE:
        _raise_broken_lock(lock_path, f"invalid [lock].enforce {header.get('enforce')!r}")
    enforce = str(header["enforce"])
    age_nudge = header.get("age_nudge_months")
    if not isinstance(age_nudge, int) or isinstance(age_nudge, bool) or age_nudge < 0:
        _raise_broken_lock(lock_path, "[lock].age_nudge_months must be a non-negative integer", enforce)
    if not isinstance(header.get("network"), bool):
        _raise_broken_lock(lock_path, "[lock].network must be a boolean", enforce)
    return header, enforce


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric key of a dotted version: leading digits of each part, stopping at the first non-numeric part."""
    text = str(version).strip()
    text = text[1:] if text[:1] in ("v", "V") else text
    parts: list[int] = []
    for raw in re.split(r"[.]", text):
        m = _VERSION_PART_RE.match(raw)
        if not m:
            break
        parts.append(int(m.group(1)))
        if m.group(1) != raw:
            break
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _is_valid_minimum(val: Any) -> bool:
    return isinstance(val, str) and bool(re.fullmatch(r"\d+(?:\.\d+){0,3}", val.strip()))


def version_below(installed: str, minimum: str) -> bool:
    """True when `installed` is numerically older than `minimum` (missing parts count as 0)."""
    return _version_key(installed) < _version_key(minimum)


def _validate_lock_tool_entry(
    lock_path: Path,
    name: Any,
    entry: Any,
    enforce: str,
) -> dict[str, Any]:
    if not TOOL_NAME_RE.match(str(name)):
        _raise_broken_lock(lock_path, f"invalid tool table name {name!r}", enforce)
    if not isinstance(entry, dict):
        _raise_broken_lock(lock_path, f"[{name}] must be a table", enforce)
    missing = [k for k in REQUIRED_KEYS if not _is_non_empty_str(entry.get(k))]
    if missing:
        _raise_broken_lock(
            lock_path,
            f"[{name}] missing {', '.join(missing)}; a pin without a reason is not a pin",
            enforce,
        )
    if not _validate_iso_date(entry.get("chosen")):
        _raise_broken_lock(
            lock_path,
            f"[{name}] invalid chosen date {entry.get('chosen')!r} (expected YYYY-MM-DD)",
            enforce,
        )
    tool_entry = dict(entry)
    if not tool_entry.get("source"):
        tool_entry["source"] = "human"
    elif not isinstance(tool_entry["source"], str) or tool_entry["source"] not in VALID_SOURCES:
        _raise_broken_lock(lock_path, f"[{name}] invalid source {tool_entry['source']!r}", enforce)
    if "minimum" in tool_entry and not _is_valid_minimum(tool_entry["minimum"]):
        _raise_broken_lock(
            lock_path,
            f"[{name}] invalid minimum {tool_entry['minimum']!r} (expected a dotted number such as \"3.20\")",
            enforce,
        )
    _validate_entry_probe_fields(lock_path, str(name), tool_entry, enforce)
    return tool_entry


def load_lock(path: Path | str) -> dict[str, Any]:
    """Load and validate a TOOLS.lock file, returning {'lock': {...}, 'tools': {...}}."""
    lock_path = Path(path)
    try:
        data = tomllib.loads(_read_lock_text(lock_path))
    except (OSError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PreflightError(4, _broken_lock_report(lock_path, str(exc))) from exc

    if not isinstance(data, dict):
        _raise_broken_lock(lock_path, "top-level must be a TOML table")

    header, enforce = _validate_lock_header(lock_path, data.get("lock", {}))
    tools = {
        name: _validate_lock_tool_entry(lock_path, name, entry, enforce)
        for name, entry in data.items()
        if name != "lock"
    }
    return {"lock": header, "tools": tools}


def _format_toml_key(key: str) -> str:
    return key if BARE_KEY_RE.match(key) else _format_toml_str(key)


def _format_toml_str(val: str) -> str:
    out: list[str] = ['"']
    for ch in val:
        code = ord(ch)
        if code in _TOML_SHORT_ESCAPES:
            out.append(_TOML_SHORT_ESCAPES[code])
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _format_toml_value(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        return _format_toml_str(val)
    if isinstance(val, (list, tuple)):
        return "[" + ", ".join(_format_toml_str(str(x)) for x in val) + "]"
    if isinstance(val, dict):
        pairs = [
            f"{_format_toml_key(str(k))} = {_format_toml_value(val[k])}"
            for k in _ordered_keys(val, ADVISORY_KEY_ORDER)
        ]
        return "{ " + ", ".join(pairs) + " }" if pairs else "{}"
    raise TypeError(f"Unsupported TOML value type: {type(val).__name__}")


def _serialize_lock_toml(lock: dict[str, Any], leading_comments: list[str]) -> str:
    if "lock" in lock or "tools" in lock:
        raw_header = lock.get("lock") or {}
        raw_tools = lock.get("tools") or {}
    else:
        raw_header = {}
        raw_tools = {k: v for k, v in lock.items() if k != "lock" and isinstance(v, dict)}

    header = {**DEFAULT_HEADER, **raw_header}
    header_lines = ["[lock]"] + [
        f"{_format_toml_key(k)} = {_format_toml_value(header[k])}"
        for k in _ordered_keys(header, HEADER_KEY_ORDER)
    ]
    blocks = ["\n".join(header_lines)]

    for name in sorted(raw_tools.keys()):
        entry = dict(raw_tools[name])
        if not entry.get("source"):
            entry["source"] = "human"
        table_lines = [f"[{_format_toml_key(name)}]"] + [
            f"{_format_toml_key(k)} = {_format_toml_value(entry[k])}"
            for k in _ordered_keys(entry, TOOL_KEY_ORDER)
            if entry[k] is not None
        ]
        blocks.append("\n".join(table_lines))

    body = "\n\n".join(blocks) + "\n"
    return ("\n".join(leading_comments) + "\n\n" + body) if leading_comments else body


def dump_lock(path: Path | str, lock: dict[str, Any]) -> None:
    """Deterministically serialize lock to TOML and write atomically via temp file + os.replace."""
    lock_path = Path(path)
    leading_comments: list[str] = []
    target_mode = 0o644
    if not os.path.islink(lock_path) and lock_path.is_file():
        try:
            existing_mode = stat.S_IMODE(lock_path.stat().st_mode)
            if existing_mode and existing_mode != 0o600:
                target_mode = existing_mode
        except OSError:
            target_mode = 0o644
        try:
            leading_comments = _extract_leading_comments(lock_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            leading_comments = []

    content = _serialize_lock_toml(lock, leading_comments)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{lock_path.name}.", suffix=".tmp", dir=str(lock_path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            try:
                os.fchmod(f.fileno(), target_mode)
            except (AttributeError, OSError):
                os.chmod(tmp_name, target_mode)
            os.fsync(f.fileno())
        os.replace(tmp_name, lock_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _safe_search_path(project_root: Path, raw_path: str | None = None) -> str:
    path_val = os.environ.get("PATH", "") if raw_path is None else raw_path
    if not path_val:
        return ""
    proj_lex = Path(os.path.abspath(os.path.expanduser(str(project_root))))
    proj_real = Path(os.path.realpath(proj_lex))
    kept: list[str] = []
    for entry in path_val.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        entry_lex = Path(os.path.abspath(entry))
        entry_real = Path(os.path.realpath(entry))
        if any(
            _is_same_or_subpath(child, parent)
            for child in (entry_lex, entry_real)
            for parent in (proj_lex, proj_real)
        ):
            continue
        kept.append(entry)
    return os.pathsep.join(kept)


def _minimal_probe_env(safe_path: str) -> dict[str, str]:
    env: dict[str, str] = {"PATH": safe_path, "LANG": "C.UTF-8", "LC_ALL": "C"}
    home_val = os.environ.get("HOME") or str(Path.home())
    if home_val:
        env["HOME"] = home_val
    for key in ("SYSTEMROOT", "TMPDIR"):
        val = os.environ.get(key)
        if val:
            env[key] = val
    return env


def _validate_command_argv(name: str, argv: list[str]) -> str:
    if not isinstance(name, str) or not TOOL_NAME_RE.match(name):
        raise ValueError(f"invalid tool name {name!r} for command probe")
    if not argv:
        raise ValueError(f"empty argv for command probe {name!r}")
    exe = argv[0]
    if not isinstance(exe, str) or not TOOL_NAME_RE.match(exe):
        raise ValueError(f"invalid command executable {exe!r} for {name!r}")
    allowed_exes = {name, *COMMAND_ALIASES.get(name, frozenset())}
    if exe not in allowed_exes:
        raise ValueError(
            f"command argv[0] {exe!r} does not match tool {name!r} (allowed: {sorted(allowed_exes)})"
        )
    if len(argv) - 1 > len(ALLOWED_COMMAND_ARGS):
        raise ValueError(f"too many arguments in command probe for {name!r}")
    for arg in argv[1:]:
        if not isinstance(arg, str) or arg not in ALLOWED_COMMAND_ARGS:
            raise ValueError(
                f"disallowed command argument {arg!r} for {name!r}; "
                f"allowed flags: {sorted(ALLOWED_COMMAND_ARGS)}"
            )
    return exe


def _resolve_command(
    name: str,
    argv: list[str],
    resolve: str | None,
    project_root: Path | None = None,
) -> list[str]:
    exe = _validate_command_argv(name, argv)
    if resolve is not None and resolve != "hermes-tools":
        raise ValueError(f"unsupported resolve mode {resolve!r}")

    if resolve == "hermes-tools":
        home = resolve_hermes_home()
        hits = sorted(
            h
            for h in glob.glob(os.path.join(home, "tools", f"{name}-*", name))
            if os.path.isfile(h) and os.access(h, os.X_OK)
        )
        if hits:
            return [hits[-1], *argv[1:]]

    root = project_root if project_root is not None else Path.cwd()
    safe_path = _safe_search_path(root)
    if not safe_path:
        raise FileNotFoundError(exe)
    found = shutil.which(exe, path=safe_path)
    if not found or _is_same_or_subpath(Path(os.path.realpath(found)), Path(os.path.realpath(root))):
        raise FileNotFoundError(exe)
    return [found, *argv[1:]]


def _neutral_probe_cwd(project_root: Path | None = None) -> str:
    """A folder to run version commands in: never the project, never under a Hermes home.

    Project files such as rust-toolchain.toml must not steer which toolchain answers.
    """
    avoid: list[Path] = list(_hermes_home_paths())
    if project_root is not None:
        avoid.extend({Path(os.path.abspath(project_root)), Path(os.path.realpath(project_root))})
    candidates: list[str] = []
    try:
        candidates.append(tempfile.gettempdir())
    except Exception:
        pass
    candidates.append(os.path.abspath(os.sep))
    for cand in candidates:
        try:
            real = Path(os.path.realpath(cand))
        except OSError:
            continue
        if not real.is_dir():
            continue
        if any(_is_same_or_subpath(real, bad) or _is_same_or_subpath(Path(os.path.abspath(cand)), bad) for bad in avoid):
            continue
        return str(real)
    return os.path.abspath(os.sep)


def _run_bounded_command(
    argv: list[str],
    *,
    env: dict[str, str],
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    cwd: str | None = None,
) -> tuple[str, str]:
    proc = subprocess.Popen(
        argv,
        cwd=cwd if cwd is not None else _neutral_probe_cwd(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )

    def _read_bounded(stream: Any, sink: bytearray) -> None:
        try:
            while len(sink) < MAX_PROBE_OUTPUT_BYTES:
                chunk = stream.read(min(8192, MAX_PROBE_OUTPUT_BYTES - len(sink)))
                if not chunk:
                    break
                sink.extend(chunk)
        except OSError:
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    out_buf, err_buf = bytearray(), bytearray()
    t_out = threading.Thread(target=_read_bounded, args=(proc.stdout, out_buf), daemon=True)
    t_err = threading.Thread(target=_read_bounded, args=(proc.stderr, err_buf), daemon=True)
    t_out.start()
    t_err.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL) if hasattr(os, "killpg") else proc.kill()
        except OSError:
            proc.kill()
        proc.wait()
        raise
    finally:
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

    return (
        bytes(out_buf[:MAX_PROBE_OUTPUT_BYTES]).decode("utf-8", errors="replace"),
        bytes(err_buf[:MAX_PROBE_OUTPUT_BYTES]).decode("utf-8", errors="replace"),
    )


def _dotted_lookup(data: Any, dotted_key: str) -> Any:
    cur = data
    for part in dotted_key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(dotted_key)
    return cur


_SECRET_DIR_NAMES: frozenset[str] = frozenset({
    "mcp-tokens", "pairing", "vault", "platforms", ".ssh", ".aws", ".gnupg",
})
_SECRET_EXACT_NAMES: frozenset[str] = frozenset({
    ".env", "auth.json", ".netrc", ".pgpass", ".npmrc", ".pypirc",
    ".git-credentials", "audit.key", "audit.key.lock",
})
_SECRET_SUFFIXES: tuple[str, ...] = (".pem", ".key", ".p12", ".pfx", ".keystore")
_PYTEST_TEMP_PARENT_RE = re.compile(r"^pytest-\d+$")


def _hermes_home_paths() -> set[Path]:
    candidates: list[Path] = [resolve_hermes_home()]
    try:
        home = Path.home()
        candidates.extend((home / ".hermes", home / ".hermes-dev"))
    except Exception:
        pass
    raw_env = os.environ.get("HERMES_HOME", "").strip()
    if raw_env:
        candidates.append(Path(os.path.expandvars(raw_env)).expanduser())
    out: set[Path] = set()
    for cand in candidates:
        try:
            lex = Path(os.path.abspath(os.path.expanduser(os.fspath(cand))))
            out.add(lex)
            out.add(Path(os.path.realpath(lex)))
        except OSError:
            continue
    return out


def _is_secret_dir_parts(parts: tuple[str, ...]) -> bool:
    lows = tuple(p.lower() for p in parts)
    if any(p in _SECRET_DIR_NAMES for p in lows):
        return True
    return any((lows[i], lows[i + 1]) == (".config", "gh") for i in range(len(lows) - 1))


def _is_secret_component(comp: str) -> bool:
    if comp in ("", ".", "..", "/", "\\"):
        return False
    if _scanner_is_secret_filename(comp):
        return True
    low = comp.lower()
    if low in _SECRET_EXACT_NAMES or low in _SECRET_DIR_NAMES:
        return True
    if low.startswith((".env.", "credentials", "id_")):
        return True
    if low.endswith(_SECRET_SUFFIXES):
        return True
    if fnmatch.fnmatchcase(low, "*-auth.json") or fnmatch.fnmatchcase(low, "*auth*.json"):
        return True
    return any(tok in low for tok in ("token", "secret", "password"))


def _is_hermes_home_config(cand: Path, hermes_homes: set[Path]) -> bool:
    if cand.name.lower() not in ("config.yaml", "config.yml"):
        return False
    parent = cand.parent
    if parent in hermes_homes or parent.name.lower() in (".hermes", ".hermes-dev"):
        return True
    return parent.parent.name.lower() == "profiles" and parent.parent.parent in hermes_homes


def _check_single_secret_candidate(
    cand: Path,
    *,
    anchor: Path | None,
    hermes_homes: set[Path],
) -> None:
    if _is_secret_dir_parts(cand.parts):
        raise ValueError("secret_path_refused")
    if _is_hermes_home_config(cand, hermes_homes):
        raise ValueError("secret_path_refused")
    if _is_secret_component(cand.name):
        raise ValueError("secret_path_refused")
    if anchor is not None and _is_same_or_subpath(cand, anchor):
        rel_parts = cand.relative_to(anchor).parts
    else:
        rel_parts = tuple(
            part
            for idx, part in enumerate(cand.parts)
            if not (idx > 0 and _PYTEST_TEMP_PARENT_RE.fullmatch(cand.parts[idx - 1]))
        )
    if _is_secret_dir_parts(rel_parts) or any(_is_secret_component(p) for p in rel_parts):
        raise ValueError("secret_path_refused")


def _refuse_secret_path(path: Path | str, *, root: Path | None = None) -> None:
    """Refuse secret-like file or directory components on both the given and resolved paths."""
    raw_str = os.fspath(path)
    if not isinstance(raw_str, str) or not raw_str or "\x00" in raw_str:
        raise ValueError("secret_path_refused")

    raw_pure = PurePath(raw_str)
    if _is_secret_dir_parts(raw_pure.parts) or _is_secret_component(raw_pure.name):
        raise ValueError("secret_path_refused")
    if not os.path.isabs(raw_str) and not raw_str.startswith("~"):
        if any(_is_secret_component(p) for p in raw_pure.parts):
            raise ValueError("secret_path_refused")

    hermes_homes = _hermes_home_paths()
    anchor_lex: Path | None = None
    anchor_real: Path | None = None
    if root is not None:
        anchor_lex = Path(os.path.abspath(os.path.expanduser(os.fspath(root))))
        try:
            anchor_real = Path(os.path.realpath(anchor_lex))
        except OSError as exc:
            raise ValueError("secret_path_refused") from exc

    variants = {os.path.expanduser(raw_str), os.path.expanduser(os.path.expandvars(raw_str))}
    for exp_str in variants:
        if anchor_lex is not None and not os.path.isabs(exp_str):
            cand_lex = Path(os.path.abspath(os.path.join(str(anchor_lex), exp_str)))
        else:
            cand_lex = Path(os.path.abspath(exp_str))
        _check_single_secret_candidate(cand_lex, anchor=anchor_lex, hermes_homes=hermes_homes)
        try:
            cand_real = Path(os.path.realpath(cand_lex))
        except OSError as exc:
            raise ValueError("secret_path_refused") from exc
        _check_single_secret_candidate(cand_real, anchor=anchor_real, hermes_homes=hermes_homes)


def _is_inside_live_hermes_home(path: Path) -> bool:
    hermes_homes = _hermes_home_paths()
    try:
        lex = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
        real = Path(os.path.realpath(lex))
    except OSError:
        return True
    for cand in (lex, real):
        for live in hermes_homes:
            if _is_same_or_subpath(cand, live):
                if _is_same_or_subpath(cand, live / "cache" / "scratch"):
                    continue
                return True
    return False


def _verify_safe_relpath_within_root(root: Path, rel_path: str) -> Path:
    if not _is_non_empty_str(rel_path):
        raise ValueError("path must be a non-empty relative path")
    if os.path.isabs(rel_path) or rel_path.startswith(("~", "/", "\\")):
        raise ValueError(f"path must be relative, got {rel_path!r}")
    if _safety_verify_nofollow is not None:
        try:
            target = _safety_verify_nofollow(root, rel_path)
        except _SafetyError as exc:
            raise ValueError(str(exc)) from exc
    else:
        root_lex = Path(os.path.abspath(os.path.expanduser(str(root))))
        if os.path.islink(root_lex):
            raise ValueError(f"root itself is a symlink: {root_lex}")
        norm = os.path.normpath(rel_path)
        if norm in ("", ".", "/") or norm.startswith(("..", "/", "\\")) or ".." in Path(norm).parts:
            raise ValueError(f"path escapes root: {rel_path!r}")
        cur = root_lex
        for part in Path(norm).parts:
            if part in ("", ".", ".."):
                raise ValueError(f"invalid path segment {part!r} in {rel_path!r}")
            cur = cur / part
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise ValueError(f"refusing symlink component: {cur}")
        target = root_lex / norm

    root_real = Path(os.path.realpath(root))
    target_real = Path(os.path.realpath(target))
    if target_real == root_real or not _is_same_or_subpath(target_real, root_real):
        raise ValueError(f"path {rel_path!r} resolves outside root {root}")
    return target


def _is_allowed_probe_filename(filename: str) -> bool:
    if not filename or filename in (".", ".."):
        return False
    for pat in ALLOWED_PROBE_FILES:
        if "*" in pat:
            if len(filename) > len(pat) - 1 and fnmatch.fnmatchcase(filename, pat):
                return True
        elif filename == pat:
            return True
    return False


def _read_bounded_regular_file(target: Path, max_bytes: int = MAX_FILE_PROBE_BYTES) -> str:
    _refuse_secret_path(target)
    st_pre = os.lstat(target)
    if stat.S_ISLNK(st_pre.st_mode):
        raise ValueError("symlink_refused")
    if not stat.S_ISREG(st_pre.st_mode):
        raise ValueError("non_regular_file_refused")
    if st_pre.st_size > max_bytes:
        raise ValueError("probe_file_too_large")
    raw_bytes = _read_regular_file_bytes(
        target,
        max_bytes,
        strict_max=True,
        expected_stat=st_pre,
    )
    try:
        return raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError(f"invalid utf-8 ({len(raw_bytes)} bytes)") from None


def _compile_safe_file_regex(pattern: str) -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("file probe regex must be a non-empty string")
    if len(pattern) > MAX_FILE_REGEX_CHARS:
        raise ValueError(f"file probe regex exceeds {MAX_FILE_REGEX_CHARS} characters ({len(pattern)})")

    parsed = re._parser.parse(pattern)  # type: ignore[attr-defined]
    repeat_ops = (
        re._parser.MAX_REPEAT,  # type: ignore[attr-defined]
        re._parser.MIN_REPEAT,  # type: ignore[attr-defined]
        getattr(re._parser, "POSSESSIVE_REPEAT", None),  # type: ignore[attr-defined]
    )
    groupref_ops = (
        re._parser.GROUPREF,  # type: ignore[attr-defined]
        re._parser.GROUPREF_EXISTS,  # type: ignore[attr-defined]
    )

    def _unwrap(items: Any) -> list[tuple[Any, Any]]:
        res: list[tuple[Any, Any]] = []
        for op, av in items:
            if op == re._parser.SUBPATTERN:  # type: ignore[attr-defined]
                res.extend(_unwrap(av[3]))
            else:
                res.append((op, av))
        return res

    def _has_repeat_or_branch(items: Any) -> bool:
        for op, av in _unwrap(items):
            if op in repeat_ops and (av[1] > 1 or _has_repeat_or_branch(av[2])):
                return True
            if op == re._parser.BRANCH or op in groupref_ops:  # type: ignore[attr-defined]
                return True
        return False

    def _is_safe_delimited_repeat(items: Any) -> bool:
        flat = _unwrap(items)
        if len(flat) != 2:
            return False
        (op0, av0), (op1, av1) = flat
        if op0 != re._parser.LITERAL or op1 not in repeat_ops or _has_repeat_or_branch(av1[2]):  # type: ignore[attr-defined]
            return False
        inner_sub = re._parser.SubPattern(parsed.state, list(av1[2]))  # type: ignore[attr-defined]
        return re._compiler.compile(inner_sub).match(chr(av0)) is None  # type: ignore[attr-defined]

    total_multi_repeats = 0

    def _walk(items: Any) -> None:
        nonlocal total_multi_repeats
        for op, av in items:
            if op in groupref_ops:
                raise ValueError(f"backreferences are not allowed in file probe regex: {pattern!r}")
            if op == re._parser.SUBPATTERN:  # type: ignore[attr-defined]
                _walk(av[3])
            elif op == re._parser.BRANCH:  # type: ignore[attr-defined]
                for br in av[1]:
                    _walk(br)
            elif op in repeat_ops:
                _min_r, max_r, body = av
                if max_r > 1:
                    total_multi_repeats += 1
                    if total_multi_repeats > 6:
                        raise ValueError(f"too many quantified groups in file probe regex: {pattern!r}")
                    if _has_repeat_or_branch(body) and not _is_safe_delimited_repeat(body):
                        raise ValueError(f"unsafe nested quantifier in file probe regex: {pattern!r}")
                _walk(body)

    _walk(parsed)
    return re.compile(pattern)


def _classify_invalid_version(cleaned: str) -> str:
    if len(cleaned) > 32:
        return "too_long"
    if any(ch.isspace() for ch in cleaned):
        return "whitespace"
    if not re.fullmatch(r"[0-9A-Za-z.+_-]+", cleaned):
        return "invalid_chars"
    if re.search(r"[^.]{20}", cleaned):
        return "dotless_run"
    return "malformed"


def _validate_extracted_version(version: str, source_desc: str) -> str:
    del source_desc
    cleaned = version.strip()
    if not cleaned:
        raise ValueError(f"empty version token ({len(version)} chars)")
    if SAFE_VERSION_TOKEN_RE.fullmatch(cleaned):
        return cleaned
    kind = _classify_invalid_version(cleaned)
    raise ValueError(f"invalid version token ({len(cleaned)} chars, {kind})")


def _parse_structured_manifest(text: str, suffix: str) -> Any:
    try:
        if suffix == ".toml":
            return tomllib.loads(text)
        if suffix in (".json", ".uproject", ".uplugin"):
            return json.loads(text)
        try:
            return json.loads(text)
        except ValueError:
            return tomllib.loads(text)
    except (ValueError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"manifest parse error ({type(exc).__name__}, {len(text)} chars)") from None


def _resolve_probe_file_path(rel_file: str, project_root: Path) -> Path:
    """Resolve an allowed, non-secret relative probe path outside live Hermes home."""
    if os.path.isabs(rel_file) or rel_file.startswith(("~", "/", "\\")):
        raise ValueError("probe_file_not_relative")
    _refuse_secret_path(rel_file, root=project_root)
    if not _is_allowed_probe_filename(PurePath(rel_file).name):
        raise ValueError("probe_file_not_allowed")
    if _is_inside_live_hermes_home(project_root):
        raise ValueError("probe_file_not_allowed")
    target = _verify_safe_relpath_within_root(project_root, rel_file)
    if _is_inside_live_hermes_home(target):
        raise ValueError("probe_file_not_allowed")
    _refuse_secret_path(target, root=project_root)
    if not _is_allowed_probe_filename(target.name):
        raise ValueError("probe_file_not_allowed")
    return target


def _probe_file(entry: dict[str, Any], project_root: Path) -> tuple[str, str]:
    rel_file = entry.get("file")
    if not rel_file or not isinstance(rel_file, str):
        raise ValueError("file probe requires 'file' path")

    has_key = entry.get("key") is not None
    has_regex = entry.get("regex") is not None
    if has_key == has_regex:
        raise ValueError("file probe requires exactly one of 'key' or 'regex'")

    compiled_re = _compile_safe_file_regex(str(entry["regex"])) if has_regex else None
    target = _resolve_probe_file_path(rel_file, project_root)
    text = _read_bounded_regular_file(target, max_bytes=MAX_FILE_PROBE_BYTES)
    resolved_str = str(target.resolve())

    if has_key:
        dotted = str(entry["key"])
        parsed = _parse_structured_manifest(text, target.suffix.lower())
        val = _dotted_lookup(parsed, dotted)
        if val is None:
            raise ValueError("empty version token (0 chars)")
        if isinstance(val, bool) or not isinstance(val, str):
            raise ValueError(f"non-string version value ({type(val).__name__})")
        if not val.strip():
            raise ValueError(f"empty version token ({len(val)} chars, whitespace)")
        return _validate_extracted_version(val, str(target)), resolved_str

    assert compiled_re is not None
    pattern = str(entry["regex"])
    for raw_line in text.splitlines():
        m = compiled_re.search(raw_line[:MAX_FILE_LINE_CHARS])
        if m:
            raw_ver = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            return _validate_extracted_version(raw_ver, str(target)), resolved_str
    raise ValueError(f"regex {pattern!r} did not match in {target}")


def probe(
    name: str,
    entry: dict[str, Any],
    project_root: Path | str | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> tuple[str, str]:
    """Return (installed_version, where) for the given tool entry."""
    root = Path(project_root) if project_root is not None else Path.cwd()
    kind = entry.get("probe")
    if kind == "interpreter":
        return platform.python_version(), sys.executable
    if kind == "module":
        mod_name = str(entry.get("module") or name)
        if not MODULE_NAME_RE.match(mod_name) or len(mod_name) > 128:
            raise ValueError(f"invalid module name {mod_name!r}")
        ver = importlib.metadata.version(mod_name)
        if not ver or not str(ver).strip():
            raise ValueError(f"module {mod_name!r} has no version")
        return str(ver).strip(), mod_name
    if kind == "command":
        raw_argv = entry.get("argv")
        if not isinstance(raw_argv, (list, tuple)) or not raw_argv:
            raise ValueError(f"command probe for {name!r} requires non-empty argv")
        argv = _resolve_command(name, [str(x) for x in raw_argv], entry.get("resolve"), project_root=root)
        env = _minimal_probe_env(_safe_search_path(root))
        stdout_text, stderr_text = _run_bounded_command(
            argv, env=env, timeout=timeout, cwd=_neutral_probe_cwd(root)
        )
        combined = stdout_text + "\n" + stderr_text
        m = VERSION_RE.search(combined)
        if not m:
            raise ValueError(f"no version in output of {' '.join(argv)!r}: {combined.strip()[:200]!r}")
        return m.group(0), argv[0]
    if kind == "pm":
        pkg_name = str(entry.get("package") or name)
        if not TOOL_NAME_RE.match(pkg_name):
            raise ValueError(f"invalid pm package name {pkg_name!r}")
        import pm  # type: ignore[import-not-found]

        inst = pm.installed_package(pkg_name)
        if inst is None:
            raise LookupError(f"pm package {pkg_name!r} is not installed")
        ver = getattr(inst, "version", None)
        if not ver:
            raise ValueError(f"pm package {pkg_name!r} has no version")
        where = getattr(inst, "binary", None) or getattr(inst, "path", None) or pkg_name
        return str(ver), str(where)
    if kind == "file":
        return _probe_file(entry, root)
    raise ValueError(f"unknown probe kind {kind!r}")


_DEFAULT_PROBE = probe


def _compute_age_months(chosen_str: str, today: dt.date | None = None) -> int:
    cleaned = chosen_str.strip()
    if not _validate_iso_date(cleaned):
        return 0
    chosen_date = dt.date.fromisoformat(cleaned)
    ref = today or dt.date.today()
    months = (ref.year - chosen_date.year) * 12 + (ref.month - chosen_date.month)
    if ref.day < chosen_date.day:
        months -= 1
    return max(0, months)


def _allowed_advisory_json_paths() -> list[tuple[Path, str]]:
    home_lex = Path(os.path.abspath(os.path.expanduser("~")))
    allowed: list[tuple[Path, str]] = []
    for spec in ALLOWED_ADVISORY_JSON_FILES:
        if spec.startswith("~/"):
            allowed.append((home_lex, spec[2:]))
        else:
            cand = Path(os.path.abspath(os.path.expanduser(spec)))
            allowed.append((cand.parent, cand.name))
    return allowed


def _resolve_advisory_json_path(raw_path: str, project_root: Path) -> Path:
    if not _is_non_empty_str(raw_path):
        raise ValueError("advisory json path must be a non-empty string")
    if ".." in Path(raw_path).parts:
        raise ValueError("advisory json path cannot traverse '..'")

    is_ext = raw_path.startswith("~") or os.path.isabs(raw_path)
    _refuse_secret_path(raw_path, root=None if is_ext else project_root)

    if is_ext:
        expanded = os.path.expanduser(raw_path)
        if not os.path.isabs(expanded) or ".." in Path(expanded).parts:
            raise ValueError("invalid advisory json path")
        cand_lex = Path(os.path.abspath(expanded))
        for anchor_lex, rel_spec in _allowed_advisory_json_paths():
            if cand_lex == anchor_lex / rel_spec:
                target = _verify_safe_relpath_within_root(anchor_lex, rel_spec)
                _refuse_secret_path(target)
                return target
        raise ValueError("advisory_path_not_allowed")

    if PurePath(raw_path).suffix.lower() != ".json" or _is_inside_live_hermes_home(project_root):
        raise ValueError("advisory_path_not_allowed")
    target = _verify_safe_relpath_within_root(project_root, raw_path)
    if _is_inside_live_hermes_home(target):
        raise ValueError("advisory_path_not_allowed")
    _refuse_secret_path(target, root=project_root)
    return target


def _evaluate_advisory(
    name: str,
    entry: dict[str, Any],
    network_allowed: bool,
    project_root: Path | None = None,
) -> tuple[str | None, str | None]:
    """Return (upstream_latest, advisory_error). Never raises."""
    adv = entry.get("advisory")
    if not adv:
        return None, None
    if not isinstance(adv, dict):
        return None, "invalid advisory specification"

    kind = adv.get("kind")
    if kind is None and "json" in adv:
        kind = "json"
    if kind == "json":
        raw_path = adv.get("path") or adv.get("json")
        key = adv.get("key")
        if not isinstance(raw_path, str) or not raw_path or not isinstance(key, str) or not key:
            return None, "advisory json requires path and key"
        try:
            root = project_root if project_root is not None else Path.cwd()
            target = _resolve_advisory_json_path(raw_path, root)
            raw_text = _read_bounded_regular_file(target, max_bytes=MAX_FILE_PROBE_BYTES)
            try:
                data = json.loads(raw_text)
            except ValueError as exc:
                raise ValueError(f"advisory parse error ({type(exc).__name__}, {len(raw_text)} chars)") from None
            if not isinstance(data, dict):
                raise ValueError(f"advisory json root must be object ({type(data).__name__})")
            val = _dotted_lookup(data, key) if "." in key else data.get(key)
            if val is None or val == "":
                return None, None
            if isinstance(val, bool) or not isinstance(val, str):
                raise ValueError(f"non-string version value ({type(val).__name__})")
            return _validate_extracted_version(val, str(target)), None
        except Exception as exc:  # noqa: BLE001
            return None, f"{type(exc).__name__}: {exc}"

    if kind == "pm":
        pkg_name = str(adv.get("package") or entry.get("package") or name)
        try:
            import pm  # type: ignore[import-not-found]
            from pm import paths as pm_paths  # type: ignore[import-not-found]

            ver = pm.Lockfile(pm_paths.lockfile_path()).version(pkg_name)
            return (str(ver) if ver else None), None
        except Exception as exc:  # noqa: BLE001
            return None, f"{type(exc).__name__}: {exc}"

    if not network_allowed:
        return None, f"advisory kind {kind!r} refused: [lock].network is false"
    return None, f"advisory kind {kind!r} is not supported in phase 1"


def _normalize_lock_arg(
    lock: dict[str, Any] | None,
    project_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], Path]:
    lock_file = project_root / "TOOLS.lock"
    if lock is None:
        loaded = load_lock(lock_file)
        return loaded["lock"], loaded["tools"], lock_file.resolve()

    if "lock" in lock or "tools" in lock:
        raw_header = lock.get("lock")
        header = {**DEFAULT_HEADER, **(raw_header if isinstance(raw_header, dict) else {})}
        raw_tools = lock.get("tools")
        tools = (
            {k: dict(v) for k, v in raw_tools.items() if isinstance(v, dict)}
            if isinstance(raw_tools, dict)
            else {}
        )
        return header, tools, lock_file.resolve()

    return dict(DEFAULT_HEADER), {k: dict(v) for k, v in lock.items() if isinstance(v, dict)}, lock_file.resolve()


def _invoke_probe(
    name: str,
    entry: dict[str, Any],
    root: Path,
    timeout: float,
) -> tuple[str, str]:
    probe_fn = probe
    if probe_fn is _DEFAULT_PROBE:
        return probe_fn(name, entry, root, timeout=timeout)
    if timeout == DEFAULT_PROBE_TIMEOUT:
        return probe_fn(name, entry, root)  # type: ignore[call-arg]
    try:
        return probe_fn(name, entry, root, timeout=timeout)
    except TypeError:
        return probe_fn(name, entry, root)  # type: ignore[call-arg]


def missing_tool_line(name: str, minimum: Any = None) -> str:
    """One plain line for a tool that is not on PATH."""
    need = f", need >= {minimum}" if minimum else ""
    return f"{name}: not found on PATH{need}. Install {name}, {SETUP_HINT}"


def too_old_line(name: str, installed: str, minimum: str, where: str) -> str:
    """One plain line for a tool older than the lock's `minimum`."""
    return f"{name}: found {installed}, need >= {minimum} ({where}). Upgrade {name}, {SETUP_HINT}"


def _check_single_tool(
    name: str,
    entry: dict[str, Any] | None,
    root: Path,
    timeout: float,
    network_allowed: bool,
    enforce: str = "block",
) -> tuple[dict[str, Any], str | None, str | None, str | None]:
    """Classify one tool: (row, blocked line, probe-failed line, warning line).

    Order: missing -> probe-failed; below `minimum` -> blocked under any `enforce`; equal to `version` -> ok;
    otherwise drift, which is a warning only when the entry states a `minimum` and `enforce` is "warn".
    """
    if entry is None:
        return {"status": "unlisted"}, f"{name}: not in TOOLS.lock (no chosen version)", None, None

    row: dict[str, Any] = {
        "locked": entry["version"],
        "chosen": entry["chosen"],
        "reason": entry["reason"],
        "source": str(entry.get("source") or "human"),
        "age_months": _compute_age_months(str(entry["chosen"])),
    }
    minimum = entry.get("minimum")
    if minimum:
        row["minimum"] = minimum
    try:
        installed, where = _invoke_probe(name, entry, root, timeout)
    except FileNotFoundError as exc:
        row.update(status="probe-failed", error=f"{type(exc).__name__}: {exc}")
        return row, None, missing_tool_line(name, minimum), None
    except Exception as exc:  # noqa: BLE001
        row.update(status="probe-failed", error=f"{type(exc).__name__}: {exc}")
        return row, None, f"{name}: {row['error']}", None

    row.update(installed=installed, where=where)
    latest, adv_err = _evaluate_advisory(name, entry, network_allowed, project_root=root)
    if latest:
        row["upstream_latest"] = latest
    if adv_err:
        row["advisory_error"] = adv_err
        row.setdefault("error", adv_err)

    if minimum and version_below(installed, str(minimum)):
        row.update(status="drift", below_minimum=True)
        return row, too_old_line(name, installed, str(minimum), where), None, None

    if installed == entry["version"]:
        row["status"] = "ok"
        return row, None, None, None

    row["status"] = "drift"
    drift = f"{name}: installed {installed} != locked {entry['version']} ({where})"
    if minimum and enforce == "warn":
        return row, None, None, f'{drift}; meets minimum {minimum}, warning only (enforce = "warn")'
    return row, drift, None, None


def _format_check_table(tools: dict[str, dict[str, Any]], age_nudge_months: int) -> str:
    name_width = max([len("TOOL"), 12, *(len(n) for n in tools)])
    lines: list[str] = [f"  {'STATUS':8} {'TOOL':{name_width}} DETAIL"]
    marks = {"ok": "ok  ", "drift": "DRIFT", "unlisted": "UNLISTED", "probe-failed": "FAIL"}
    for name, row in tools.items():
        mark = "TOO-OLD" if row.get("below_minimum") else marks[row["status"]]
        if row["status"] == "probe-failed":
            detail = row["error"]
        else:
            detail = f"{row.get('installed', '?')} (locked {row.get('locked', '-')})"
            if row.get("minimum"):
                detail = f"{row.get('installed', '?')} (locked {row.get('locked', '-')}, minimum {row['minimum']})"
            if row.get("upstream_latest") and row["upstream_latest"] != row.get("installed"):
                detail += f" · upstream reports {row['upstream_latest']}, advisory only"
        if isinstance(row.get("age_months"), int) and age_nudge_months > 0 and row["age_months"] >= age_nudge_months:
            detail += f" · chosen {row['age_months']} months ago, re-decide?"
        lines.append(f"  {mark:8} {name:{name_width}} {detail}")
    return "\n".join(lines)


def check(
    needs: list[str],
    lock: dict[str, Any] | None = None,
    project_root: Path | str | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> dict[str, Any]:
    """Check needed tools against lock. Never raises for a tool problem; classifies into ok/drift/unlisted/probe-failed.

    `[lock].enforce` decides only drift inside an entry's declared `minimum`: "warn" lists it in `warnings`
    and keeps `ok`; "block" blocks it. Missing tools, tools below `minimum`, unlisted tools, and any mismatch
    against an entry without `minimum` (an exact pin) block under either setting.
    """
    root = Path(project_root) if project_root is not None else Path.cwd()
    header, lock_tools, lock_path = _normalize_lock_arg(lock, root)
    enforce = str(header.get("enforce", "warn"))
    if enforce not in VALID_ENFORCE:
        enforce = "block"
    network_allowed = bool(header.get("network", False))
    raw_nudge = header.get("age_nudge_months", 12)
    age_nudge_months = int(raw_nudge) if isinstance(raw_nudge, int) and not isinstance(raw_nudge, bool) else 12

    tools: dict[str, dict[str, Any]] = {}
    blocked: list[str] = []
    failed: list[str] = []
    warnings: list[str] = []

    for name in needs:
        row, block_msg, fail_msg, warn_msg = _check_single_tool(
            name, lock_tools.get(name), root, timeout, network_allowed, enforce
        )
        tools[name] = row
        if block_msg:
            blocked.append(block_msg)
        if fail_msg:
            failed.append(fail_msg)
        if warn_msg:
            warnings.append(warn_msg)

    ok = not blocked and not failed
    if not ok:
        summary = "preflight BLOCKED: " + "; ".join(blocked + failed)
    elif warnings:
        noun = "warning" if len(warnings) == 1 else "warnings"
        summary = f"preflight ok with {len(warnings)} {noun}: " + "; ".join(warnings)
    else:
        summary = "preflight ok"
    return {
        "ok": ok,
        "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "lock": str(lock_path),
        "enforce": enforce,
        "tools": tools,
        "blocked": blocked,
        "probe_failed": failed,
        "warnings": warnings,
        "summary": summary,
        "text": _format_check_table(tools, age_nudge_months),
    }


class RecordRefused(PreflightError):
    """Raised (code 4) when the record folder or file inside the project is a link or not a plain folder/file."""

    def __init__(self, line: str, report: dict[str, Any] | None = None) -> None:
        body = dict(report or {})
        body.update(ok=False, summary=line, record_refused=True)
        super().__init__(4, body)


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIR_FD_OK = _O_NOFOLLOW != 0 and _O_DIRECTORY != 0 and {"open", "mkdir", "rename", "unlink"} <= {
    fn.__name__ for fn in getattr(os, "supports_dir_fd", set())  # the set holds built-ins: a wrapped os.open can't hide them
}


def _refusal(path: Path, why: str) -> str:
    return f"preflight record refused: {path} {why}; nothing was written"


def _open_inner_dir_nofollow(parent_fd: int, name: str, shown: Path) -> int:
    """Open (creating if missing) the folder ``name`` relative to ``parent_fd`` without following a link."""
    flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
    for _attempt in range(2):
        try:
            return os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(name, 0o777, dir_fd=parent_fd)
            except FileExistsError:
                pass  # raced with another creator: reopen without following
            except OSError as exc:
                raise RecordRefused(_refusal(shown, f"could not be created ({exc.strerror or exc})")) from exc
        except OSError as exc:  # ELOOP (a link, dangling or not), ENOTDIR (a file), anything else
            raise RecordRefused(_refusal(shown, "is a link or not a real folder")) from exc
    raise RecordRefused(_refusal(shown, "is a link or not a real folder"))


def write_inside_nofollow(directory: Path | str, name: str, data: bytes) -> Path:
    """Write ``data`` to ``<directory>/<name>`` without following any link inside the project.

    Rule: ``directory.parent`` (the project folder) is the caller's choice and may be reached through links;
    ``directory``'s last component (for example ``.adopt``) and ``name`` are inside the project and are never
    followed. The project folder is opened once; the inner folder is opened relative to that handle with
    ``O_DIRECTORY | O_NOFOLLOW`` (created with mkdir relative to the handle when missing); the bytes go to a fresh
    temporary name created with ``O_CREAT | O_EXCL | O_NOFOLLOW`` and are renamed over ``name`` relative to the same
    handle, so a link, FIFO or device at the leaf is replaced, never written through. Refusals raise RecordRefused
    with one plain line.
    """
    shown = Path(directory)
    lexical = Path(os.path.abspath(shown))  # lexical only: nothing is resolved
    inner = lexical.name
    if inner in ("", ".", "..") or os.sep in name or name in ("", ".", ".."):
        raise RecordRefused(_refusal(shown / name, "is not a plain folder/file name"))
    parent = lexical.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)  # caller-chosen location outside the project's inner names
    out = shown / name
    if not _DIR_FD_OK:  # pragma: no cover - platforms without dir_fd/O_NOFOLLOW: best-effort lstat checks
        for p, want_dir in ((shown, True), (out, False)):
            try:
                st = os.lstat(p)
            except FileNotFoundError:
                if want_dir:
                    os.mkdir(p)
                continue
            if stat.S_ISLNK(st.st_mode) or (want_dir and not stat.S_ISDIR(st.st_mode)):
                raise RecordRefused(_refusal(p, "is a link or not a real folder"))
        tmp = shown / f".{name}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | getattr(os, "O_BINARY", 0), 0o666)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, out)
        return out
    try:
        pfd = os.open(parent, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except OSError as exc:
        raise RecordRefused(_refusal(parent, f"could not be opened ({exc.strerror or exc})")) from exc
    try:
        dfd = _open_inner_dir_nofollow(pfd, inner, shown)
    finally:
        os.close(pfd)
    try:
        tmp = f".{name}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o666, dir_fd=dfd)
        except OSError as exc:
            raise RecordRefused(_refusal(shown, f"is not writable ({exc.strerror or exc})")) from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except OSError as exc:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise RecordRefused(_refusal(out, f"could not be replaced ({exc.strerror or exc})")) from exc
    finally:
        os.close(dfd)
    return out


def record(report: dict[str, Any], directory: Path | str) -> Path:
    """Write report to <directory>/preflight.json and return its Path.

    ``directory`` is normally ``<project>/.adopt``. The project folder may be reached through links the user chose;
    ``.adopt`` and ``preflight.json`` are inside the project and are never followed (see write_inside_nofollow):
    a linked or non-folder ``.adopt`` raises RecordRefused (code 4, one plain line); a link at the leaf is replaced
    by a regular file and its target is left untouched.
    """
    return write_inside_nofollow(directory, "preflight.json", (json.dumps(report, indent=2) + "\n").encode("utf-8"))


def require(
    needs: list[str],
    project_root: Path | str | None = None,
    record_dir: Path | str | None = None,
    lock: dict[str, Any] | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> dict[str, Any]:
    """Harness entry point: prints text+summary to stderr; returns report or raises PreflightError (code 2 or 3)."""
    root = Path(project_root) if project_root is not None else Path.cwd()
    report = check(needs, lock, root, timeout=timeout)
    if record_dir is not None:
        try:
            report["recorded"] = str(record(report, record_dir))
        except RecordRefused as exc:
            raise RecordRefused(exc.report["summary"], report) from None
    print(report["text"], file=sys.stderr)
    print(report["summary"], file=sys.stderr)
    if not report["ok"]:
        raise PreflightError(3 if report["probe_failed"] and not report["blocked"] else 2, report)
    return report


def main(argv: list[str] | None = None) -> int:
    """CLI entry point supporting --need/--all, --project, and --record."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--need", nargs="+", metavar="TOOL", help="tools this run depends on")
    g.add_argument("--all", action="store_true", help="check every tool in TOOLS.lock")
    p.add_argument("--project", type=Path, default=None, metavar="DIR", help="project root containing TOOLS.lock (default: cwd)")
    p.add_argument("--record", type=Path, default=None, metavar="DIR", help="write preflight.json into DIR")
    a = p.parse_args(argv)

    project_root = (a.project if a.project is not None else Path.cwd()).resolve()
    lock_path = project_root / "TOOLS.lock"
    try:
        loaded = load_lock(lock_path)
        needs = list(loaded["tools"].keys()) if a.all else list(a.need)
        require(needs, project_root, record_dir=a.record, lock=loaded)
    except PreflightError as exc:
        if exc.code == 4:
            print(exc.report["summary"], file=sys.stderr)
        if a.record and "recorded" not in exc.report and not isinstance(exc, RecordRefused):
            try:
                exc.report["recorded"] = str(record(exc.report, a.record))
            except RecordRefused as refused:
                print(refused.report["summary"], file=sys.stderr)
        return exc.code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
