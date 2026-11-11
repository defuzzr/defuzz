# vendored module (origin: hermes_audit/static_code.py, from the author's audit toolkit; not published separately). Do not edit: change the origin and re-vendor.
"""Static code, lockfile catalogue, lexical import, suppression, and stub audit component (100% Python stdlib).

Implements the static code and dependency checks from `hermes-adopt-audit-redesign.md` (§5, §6, §11, §12, §13.3):
- Scope (§13.3): all registered golden templates from `templates.py` (`rust-golden`, `ts-node-golden`,
  `python-golden`, `go-golden`, `cpp-golden`, `dotnet-golden`, `web-golden`).
  Projects outside the golden template registry or unregistered repositories return `coverage="not_included"`.
- Lockfile vs `approved_deps` catalogue (`template.yaml`):
  - Rust: `Cargo.toml` + `Cargo.lock`
  - TS-Node: `package.json` + `pnpm-lock.yaml`
  - Python: `pyproject.toml` + `uv.lock`
  - Go: `go.mod` + `go.sum`
  - C++: `CMakeLists.txt`
  - .NET / C#: `packages.lock.json`
  External lockfile entries outside `approved_deps` emit `static_code.unapproved_dependency` (`classification="warning"`).
- Lexical top-level import scan mapped to lock entries:
  - Ignores commented imports and string literals.
  - Recognizes language built-ins / stdlib and relative local imports as `verified`.
  - Top-level external import with no lockfile entry -> `static_code.import_missing_from_lock` (`classification="warning"`).
  - Unmappable forms (dynamic imports, path/package aliases, workspace crates/packages, conditional/dev scopes)
    -> `static_code.unmappable_import` (`coverage="could_not_verify"`, `classification="info"`), never a silent
    pass and never an invented-dependency warning.
  - LOCAL PATCH dev-scope-import-mapping-v1 (TS/JS only): `node:` and other built-in modules and relative
    specifiers count as local wherever they appear; a dynamic import of one plain string literal is mapped by
    its specifier; in development-scope files (tests, `<name>.config.<ext>`, top-level `tools/` and `scripts/`)
    a package import, including a declared devDependency, goes through the lockfile mapping. Computed or URL
    dynamic imports stay `unmappable_import`, and a devDependency imported from production source stays
    `unmappable_import` (`conditional_or_dev_scope`).
- Counts lint/type suppressions above the substituted template baseline, excluding comments and string literals
  -> `static_code.suppressions_above_baseline` (`classification="review_suggested"`).
- Mechanically identifies stubs (`todo!`, `unimplemented!`, `NotImplementedError`, `throw new Error("not implemented")`,
  stub `pass`/`...` bodies) and heuristic review items (useless try/catch, excess nesting, unreferenced private helpers)
  above baseline -> `classification="review_suggested"`. Never executes code.
"""

from __future__ import annotations

import ast
import bisect
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tomllib
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "CLASSIFICATION_INFO",
    "CLASSIFICATION_REVIEW",
    "CLASSIFICATION_WARNING",
    "COVERAGE_COULD_NOT_VERIFY",
    "COVERAGE_NOT_INCLUDED",
    "COVERAGE_VERIFIED",
    "FIXED_AUDIT_DISCLOSURE",
    "GOLDEN_TEMPLATE_IDS",
    "RULE_VERSION",
    "audit_static_code",
    "count_source_suppressions",
    "parse_cargo_lock",
    "parse_pnpm_lock",
    "parse_uv_lock",
]

RULE_VERSION = "1.0.0"
FIXED_AUDIT_DISCLOSURE = "This audit cannot tell whether working code is correct."

CLASSIFICATION_WARNING = "warning"
CLASSIFICATION_REVIEW = "review_suggested"
CLASSIFICATION_INFO = "info"

COVERAGE_VERIFIED = "verified"
COVERAGE_COULD_NOT_VERIFY = "could_not_verify"
COVERAGE_NOT_INCLUDED = "not_included"

# LOCAL PATCH golden-template-registry-v1: derive GOLDEN_TEMPLATE_IDS and TEMPLATE_TO_ECOSYSTEM from templates.py.
_ECOSYSTEM_ALIASES: dict[str, str] = {
    "rust": "rust",
    "typescript": "ts-node",
    "ts-node": "ts-node",
    "ts_node": "ts-node",
    "python": "python",
    "go": "go",
    "cpp": "cpp",
    "csharp": "csharp",
    "dotnet": "csharp",
}

_FALLBACK_TEMPLATE_TO_ECOSYSTEM: dict[str, str] = {
    "rust-golden": "rust",
    "ts-node-golden": "ts-node",
    "python-golden": "python",
    "go-golden": "go",
    "cpp-golden": "cpp",
    "dotnet-golden": "csharp",
    # LOCAL PATCH web-golden-registry-v1: the web-golden template (TypeScript, pnpm, Vite) is the ts-node ecosystem.
    "web-golden": "ts-node",
}


def _infer_template_ecosystem(spec_or_meta: Any, template_id: str | None = None) -> str | None:
    approved = (
        spec_or_meta.get("approved_deps")
        if isinstance(spec_or_meta, Mapping)
        else getattr(spec_or_meta, "approved_deps", None)
    )
    if isinstance(approved, Mapping):
        for eco_key in approved:
            k_norm = str(eco_key).strip().lower()
            if k_norm and k_norm != "default":
                return _ECOSYSTEM_ALIASES.get(k_norm, k_norm)
    languages = (
        spec_or_meta.get("languages")
        if isinstance(spec_or_meta, Mapping)
        else getattr(spec_or_meta, "languages", None)
    )
    if isinstance(languages, (list, tuple)) and languages:
        lang_norm = str(languages[0]).strip().lower()
        if lang_norm:
            return _ECOSYSTEM_ALIASES.get(lang_norm, lang_norm)
    tid = template_id or (
        str(spec_or_meta.get("id") or "")
        if isinstance(spec_or_meta, Mapping)
        else str(getattr(spec_or_meta, "id", "") or "")
    )
    if tid in _FALLBACK_TEMPLATE_TO_ECOSYSTEM:
        return _FALLBACK_TEMPLATE_TO_ECOSYSTEM[tid]
    if tid.endswith("-golden"):
        stem = tid[: -len("-golden")]
        return _ECOSYSTEM_ALIASES.get(stem, stem)
    return None


def _load_golden_template_registry() -> tuple[frozenset[str], dict[str, str]]:
    from ..contract import discover_golden_template_ids

    ids = discover_golden_template_ids()
    eco_map: dict[str, str] = dict(_FALLBACK_TEMPLATE_TO_ECOSYSTEM)
    for tid in ids:
        if tid not in eco_map:
            inferred = _infer_template_ecosystem(None, tid)
            if inferred:
                eco_map[tid] = inferred
    return ids, eco_map


GOLDEN_TEMPLATE_IDS, TEMPLATE_TO_ECOSYSTEM = _load_golden_template_registry()

ECOSYSTEM_LOCKFILE: dict[str, str] = {
    "rust": "Cargo.lock",
    "ts-node": "pnpm-lock.yaml",
    "python": "uv.lock",
    "go": "go.sum",
    "cpp": "CMakeLists.txt",
    "csharp": "packages.lock.json",
    "dotnet": "packages.lock.json",
}

DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_DIR_ENTRIES = 20_000
DEFAULT_MAX_NESTING_DEPTH = 6
_BINARY_SNIFF_BYTES = 8192

_CLASSIFICATION_RANK: dict[str, int] = {
    CLASSIFICATION_WARNING: 3,
    CLASSIFICATION_REVIEW: 2,
    CLASSIFICATION_INFO: 1,
}

_CLASSIFICATION_TO_LEGACY_SEVERITY: dict[str, str] = {
    CLASSIFICATION_WARNING: "warn",
    CLASSIFICATION_REVIEW: "warn",
    CLASSIFICATION_INFO: "info",
}

_FORBIDDEN_EVIDENCE_KEYS: frozenset[str] = frozenset({
    "cmd",
    "command",
    "commands",
    "script",
    "shell_cmd",
    "executable_fix",
    "fix_cmd",
    "fix_command",
    "fix_script",
    "argv",
})

_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret|auth[_-]?token|credential)s?(?:$|_)"
)

_SUPPORTS_OPEN_DIR_FD: bool = os.open in getattr(os, "supports_dir_fd", set())

_RUST_BUILTIN_ROOTS: frozenset[str] = frozenset({
    "std",
    "core",
    "alloc",
    "proc_macro",
    "test",
    "crate",
    "self",
    "super",
})

_NODE_BUILTIN_MODULES: frozenset[str] = frozenset({
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "test",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
})

_PYTHON_STDLIB_MODULES: frozenset[str] = frozenset(
    set(getattr(sys, "stdlib_module_names", ()))
    | {"__future__", "builtins", "typing", "tomllib", "dataclasses", "pathlib", "asyncio"}
)


def _norm_py_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name.strip().lower())


def _norm_rust_crate(name: str) -> str:
    return name.strip().replace("-", "_")


def _sanitize_evidence(value: Any, *, _key_hint: str = "") -> Any:
    if callable(value):
        raise ValueError("Callable objects are forbidden in audit finding evidence")
    if _key_hint and _key_hint.lower() in _FORBIDDEN_EVIDENCE_KEYS:
        raise ValueError(f"Executable fix field {_key_hint!r} is forbidden inside finding evidence")
    if _key_hint and _SECRET_KEY_RE.search(_key_hint):
        return "<redacted>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in sorted(value.items(), key=lambda item: str(item[0])):
            k_str = str(k)
            if k_str.lower() in _FORBIDDEN_EVIDENCE_KEYS:
                raise ValueError(f"Executable fix field {k_str!r} is forbidden inside finding evidence")
            out[k_str] = _sanitize_evidence(v, _key_hint=k_str)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [_sanitize_evidence(item) for item in seq]
    return str(value)


def _normalize_source_paths(source_paths: Sequence[Mapping[str, Any] | str] | None) -> list[dict[str, Any]]:
    if not source_paths:
        return []
    normalized: list[dict[str, Any]] = []
    for entry in source_paths:
        if isinstance(entry, str):
            normalized.append({"path": entry, "start_line": None, "end_line": None})
        elif isinstance(entry, Mapping):
            path_str = str(entry.get("path") or "").strip()
            start_line = entry.get("start_line", entry.get("line"))
            end_line = entry.get("end_line", start_line)
            normalized.append({
                "path": path_str,
                "start_line": int(start_line) if isinstance(start_line, int) and start_line > 0 else None,
                "end_line": int(end_line) if isinstance(end_line, int) and end_line > 0 else None,
            })
        else:
            normalized.append({"path": str(entry), "start_line": None, "end_line": None})
    normalized.sort(
        key=lambda item: (
            item["path"],
            item["start_line"] if item["start_line"] is not None else -1,
            item["end_line"] if item["end_line"] is not None else -1,
        )
    )
    return normalized


def _make_finding(
    *,
    rule_id: str,
    classification: str,
    coverage: str = COVERAGE_VERIFIED,
    affected_identities: Sequence[str] = (),
    source_paths: Sequence[Mapping[str, Any] | str] = (),
    evidence: Mapping[str, Any] | None = None,
    consequence: str,
    limitations: str = "",
    proposed_cleanup_id: str | None = None,
    detail: str | None = None,
    fix: str | None = None,
) -> dict[str, Any]:
    rid = str(rule_id or "").strip()
    if not rid:
        raise ValueError("Finding rule_id must be non-empty")
    if classification not in _CLASSIFICATION_RANK:
        raise ValueError(f"Invalid classification: {classification!r}")
    if coverage not in (COVERAGE_VERIFIED, COVERAGE_COULD_NOT_VERIFY, COVERAGE_NOT_INCLUDED):
        raise ValueError(f"Invalid coverage: {coverage!r}")
    consequence_str = str(consequence or "").strip()
    if not consequence_str:
        raise ValueError(f"Finding {rid!r} must include a plain-language consequence")
    limitations_str = str(limitations or "").strip()
    detail_str = str(detail).strip() if detail is not None and str(detail).strip() else consequence_str
    identities = sorted({str(x).strip() for x in affected_identities if str(x).strip()})
    paths = _normalize_source_paths(source_paths)
    clean_ev = _sanitize_evidence(dict(evidence) if evidence is not None else {})
    sev = _CLASSIFICATION_TO_LEGACY_SEVERITY[classification]
    return {
        "id": rid,
        "classification": classification,
        "coverage": coverage,
        "affected_identities": identities,
        "source_paths": paths,
        "evidence": clean_ev,
        "consequence": consequence_str,
        "limitations": limitations_str,
        "proposed_cleanup_id": proposed_cleanup_id,
        "severity": sev,
        "detail": detail_str,
        "fix": str(fix) if fix is not None else None,
    }


def _finding_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    cls_name = str(finding.get("classification") or CLASSIFICATION_INFO)
    rank = _CLASSIFICATION_RANK.get(cls_name, 0)
    identities = tuple(finding.get("affected_identities") or ())
    paths = tuple(
        (
            str(p.get("path") or ""),
            int(p["start_line"]) if isinstance(p.get("start_line"), int) else -1,
        )
        for p in (finding.get("source_paths") or ())
        if isinstance(p, Mapping)
    )
    return (
        -rank,
        str(finding.get("id") or ""),
        identities,
        paths,
        str(finding.get("consequence") or ""),
        str(finding.get("proposed_cleanup_id") or ""),
    )


def _compute_classification_headline(findings: Sequence[Mapping[str, Any]]) -> str:
    best = CLASSIFICATION_INFO
    best_rank = _CLASSIFICATION_RANK[best]
    for f in findings:
        cls_val = str(f.get("classification") or CLASSIFICATION_INFO)
        rank = _CLASSIFICATION_RANK.get(cls_val, 1)
        if rank > best_rank:
            best = cls_val
            best_rank = rank
    return best


def _make_envelope(
    *,
    findings: Iterable[Mapping[str, Any]] = (),
    coverage: str = COVERAGE_VERIFIED,
    error: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    sorted_findings = [dict(f) for f in findings]
    sorted_findings.sort(key=_finding_sort_key)
    if error is not None:
        err_str = str(error).strip() or "Component execution failed"
        out: dict[str, Any] = {
            "ok": False,
            "status": "error",
            "error": err_str,
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "classification": _compute_classification_headline(sorted_findings),
            "findings": sorted_findings,
            "disclosure": FIXED_AUDIT_DISCLOSURE,
        }
    else:
        norm_cov = coverage
        if any(f.get("coverage") == COVERAGE_COULD_NOT_VERIFY for f in sorted_findings):
            norm_cov = COVERAGE_COULD_NOT_VERIFY
        has_legacy_error = any(f.get("severity") == "error" for f in sorted_findings)
        legacy_status = "fail" if has_legacy_error else "pass"
        out = {
            "ok": legacy_status == "pass",
            "status": legacy_status,
            "error": None,
            "coverage": norm_cov,
            "classification": _compute_classification_headline(sorted_findings),
            "findings": sorted_findings,
            "disclosure": FIXED_AUDIT_DISCLOSURE,
        }
    if extra:
        for k, v in extra.items():
            if k not in out:
                out[str(k)] = v
    return out


def _classify_mode(st_mode: int) -> str:
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


def _require_containment_flags() -> tuple[int, int, int]:
    if not _SUPPORTS_OPEN_DIR_FD:
        raise RuntimeError("os.open does not support dir_fd on this platform")
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not o_nofollow:
        raise RuntimeError("os.O_NOFOLLOW is not available on this platform")
    o_nonblock = getattr(os, "O_NONBLOCK", 0)
    o_directory = getattr(os, "O_DIRECTORY", 0)
    return o_nofollow, o_nonblock, o_directory


def _safe_walk_directory(
    root_path: Path | str,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_entries: int = DEFAULT_MAX_DIR_ENTRIES,
) -> tuple[dict[str, dict[str, Any]], str, list[dict[str, str]]]:
    """Descriptor-relative, race-checked directory walk returning regular files and unverified entries (§12)."""
    o_nofollow, o_nonblock, o_directory = _require_containment_flags()
    from ..policy import credential_path  # Explicit defuzz local security patch.
    from ..fingerprint import CredentialStoreNotOpened, open_checked  # LOCAL PATCH open-handle-credential-check-v1.
    root_abs = Path(os.path.abspath(os.fspath(root_path)))
    if credential_path(root_abs):
        return {}, COVERAGE_COULD_NOT_VERIFY, [{"path": str(root_abs), "reason": "credential_policy_exclusion"}]
    files: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    coverage = COVERAGE_VERIFIED
    entries_seen = 0

    try:
        st_root = os.lstat(root_abs)
        if stat.S_ISLNK(st_root.st_mode):
            return {}, COVERAGE_COULD_NOT_VERIFY, [{"path": str(root_abs), "reason": "symlink_root"}]
        if not stat.S_ISDIR(st_root.st_mode):
            return {}, COVERAGE_COULD_NOT_VERIFY, [{"path": str(root_abs), "reason": "not_a_directory"}]
        root_fd = os.open(str(root_abs), os.O_RDONLY | o_nofollow | o_nonblock | o_directory)
    except OSError as exc:
        return {}, COVERAGE_COULD_NOT_VERIFY, [{"path": str(root_abs), "reason": str(exc)}]

    try:
        st_fd = os.fstat(root_fd)
        if (st_fd.st_dev, st_fd.st_ino) != (st_root.st_dev, st_root.st_ino):
            return {}, COVERAGE_COULD_NOT_VERIFY, [{"path": str(root_abs), "reason": "root_swapped_on_open"}]

        def _walk(dir_fd: int, rel_prefix: str) -> None:
            nonlocal coverage, entries_seen
            try:
                with os.scandir(dir_fd) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as exc:
                coverage = COVERAGE_COULD_NOT_VERIFY
                issues.append({"path": rel_prefix or ".", "reason": str(exc)})
                return

            names_before = [e.name for e in entries]
            for entry in entries:
                name = entry.name
                if name in (".git", "node_modules", "target", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"):
                    continue
                rel = name if not rel_prefix else f"{rel_prefix}/{name}"
                if credential_path(root_abs / rel):
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    issues.append({"path": rel, "reason": "credential_policy_exclusion"})
                    continue
                entries_seen += 1
                if max_entries > 0 and entries_seen > max_entries:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    issues.append({"path": rel, "reason": f"max_entries ({max_entries}) exceeded"})
                    return

                try:
                    st_pre = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError as exc:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    issues.append({"path": rel, "reason": f"stat_failed: {exc}"})
                    continue

                kind = _classify_mode(st_pre.st_mode)
                if kind == "directory":
                    try:
                        sub_fd = os.open(
                            name,
                            os.O_RDONLY | o_nofollow | o_nonblock | o_directory,
                            dir_fd=dir_fd,
                        )
                    except OSError as exc:
                        coverage = COVERAGE_COULD_NOT_VERIFY
                        issues.append({"path": rel, "reason": f"open_dir_failed: {exc}"})
                        continue
                    try:
                        st_sub = os.fstat(sub_fd)
                        if (st_sub.st_dev, st_sub.st_ino) != (st_pre.st_dev, st_pre.st_ino):
                            coverage = COVERAGE_COULD_NOT_VERIFY
                            issues.append({"path": rel, "reason": "dir_inode_changed_during_open"})
                            continue
                        _walk(sub_fd, rel)
                    finally:
                        os.close(sub_fd)
                    continue

                if kind == "symlink":
                    try:
                        target = os.readlink(name, dir_fd=dir_fd)
                    except OSError as exc:
                        target = ""
                        issues.append({"path": rel, "reason": f"readlink_failed: {exc}"})
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    files[rel] = {
                        "rel_path": rel,
                        "kind": "symlink",
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "stable": True,
                        "content": None,
                        "sha256": None,
                        "symlink_target": target,
                        "error": f"Symlink ({target!r}) is not a regular file",
                    }
                    issues.append({"path": rel, "reason": f"symlink:{target}"})
                    continue

                if kind != "regular":
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    files[rel] = {
                        "rel_path": rel,
                        "kind": kind,
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "stable": True,
                        "content": None,
                        "sha256": None,
                        "error": f"Refusing non-regular file ({kind})",
                    }
                    issues.append({"path": rel, "reason": f"special_file:{kind}"})
                    continue

                try:
                    # LOCAL PATCH open-handle-credential-check-v1: the opened file is checked
                    # against the declared credentials before any byte is read.
                    fd = open_checked(name, os.O_RDONLY | o_nofollow | o_nonblock, dir_fd=dir_fd,
                                      full_path=str(root_abs / rel))
                except CredentialStoreNotOpened:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    issues.append({"path": rel, "reason": "credential_policy_exclusion"})
                    continue
                except OSError as exc:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    files[rel] = {
                        "rel_path": rel,
                        "kind": "unreadable",
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "stable": False,
                        "content": None,
                        "sha256": None,
                        "error": str(exc),
                    }
                    issues.append({"path": rel, "reason": f"open_failed: {exc}"})
                    continue

                try:
                    st_open = os.fstat(fd)
                    if not stat.S_ISREG(st_open.st_mode) or (st_open.st_dev, st_open.st_ino) != (
                        st_pre.st_dev,
                        st_pre.st_ino,
                    ):
                        coverage = COVERAGE_COULD_NOT_VERIFY
                        files[rel] = {
                            "rel_path": rel,
                            "kind": "regular",
                            "coverage": COVERAGE_COULD_NOT_VERIFY,
                            "stable": False,
                            "content": None,
                            "sha256": None,
                            "error": "File identity changed during open",
                        }
                        issues.append({"path": rel, "reason": "inode_changed_during_open"})
                        continue

                    if max_file_bytes >= 0 and st_open.st_size > max_file_bytes:
                        coverage = COVERAGE_COULD_NOT_VERIFY
                        files[rel] = {
                            "rel_path": rel,
                            "kind": "regular",
                            "coverage": COVERAGE_COULD_NOT_VERIFY,
                            "stable": True,
                            "content": None,
                            "sha256": None,
                            "bounded_exceeded": True,
                            "error": f"File size {st_open.st_size} exceeds limit {max_file_bytes}",
                        }
                        issues.append({"path": rel, "reason": "bounded_exceeded"})
                        continue

                    chunks: list[bytes] = []
                    total = 0
                    hasher = hashlib.sha256()
                    exceeded = False
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if max_file_bytes >= 0 and total > max_file_bytes:
                            exceeded = True
                            break
                        hasher.update(chunk)
                        chunks.append(chunk)
                    st_after = os.fstat(fd)
                finally:
                    os.close(fd)

                if exceeded:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    files[rel] = {
                        "rel_path": rel,
                        "kind": "regular",
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "stable": False,
                        "content": None,
                        "sha256": None,
                        "bounded_exceeded": True,
                        "error": f"Streamed read exceeded limit {max_file_bytes}",
                    }
                    issues.append({"path": rel, "reason": "bounded_exceeded"})
                    continue

                try:
                    st_post = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    st_post = None

                stable = (
                    st_post is not None
                    and stat.S_ISREG(st_post.st_mode)
                    and (
                        st_pre.st_dev,
                        st_pre.st_ino,
                        st_pre.st_size,
                        st_pre.st_mtime_ns,
                        st_pre.st_ctime_ns,
                    )
                    == (
                        st_after.st_dev,
                        st_after.st_ino,
                        st_after.st_size,
                        st_after.st_mtime_ns,
                        st_after.st_ctime_ns,
                    )
                    == (
                        st_post.st_dev,
                        st_post.st_ino,
                        st_post.st_size,
                        st_post.st_mtime_ns,
                        st_post.st_ctime_ns,
                    )
                    and total == st_pre.st_size
                )
                if not stable:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    files[rel] = {
                        "rel_path": rel,
                        "kind": "regular",
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "stable": False,
                        "content": None,
                        "sha256": None,
                        "error": "File mutated during read",
                    }
                    issues.append({"path": rel, "reason": "mutated_during_read"})
                    continue

                raw_bytes = b"".join(chunks)
                files[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_VERIFIED,
                    "stable": True,
                    "content": raw_bytes,
                    "sha256": hasher.hexdigest(),
                    "size": total,
                    "error": None,
                }

            try:
                dup_fd = os.dup(dir_fd)
                try:
                    with contextlib.suppress(OSError):
                        os.lseek(dup_fd, 0, os.SEEK_SET)
                    with os.scandir(dup_fd) as it_after:
                        names_after = sorted(e.name for e in it_after)
                    if names_after != names_before:
                        coverage = COVERAGE_COULD_NOT_VERIFY
                        issues.append({"path": rel_prefix or ".", "reason": "dir_membership_changed_during_scan"})
                finally:
                    with contextlib.suppress(OSError):
                        os.close(dup_fd)
            except OSError:
                pass

        _walk(root_fd, "")
    finally:
        with contextlib.suppress(OSError):
            os.close(root_fd)

    return files, coverage, issues


def _normalize_file_map(
    raw_files: Mapping[str, Any] | None,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> tuple[dict[str, dict[str, Any]], str, list[dict[str, str]]]:
    """Normalize plain-data file mappings (bytes, str, or SafeReadResult dicts) into a canonical dict."""
    if not raw_files:
        return {}, COVERAGE_VERIFIED, []
    out: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    coverage = COVERAGE_VERIFIED

    for raw_rel, val in sorted(raw_files.items(), key=lambda item: str(item[0])):
        rel = str(raw_rel).replace("\\", "/").strip("/")
        if not rel or rel == "." or rel.startswith(".git/") or rel == ".git":
            continue
        parts = PurePosixPath(rel).parts
        if any(p in ("", ".", "..") for p in parts):
            coverage = COVERAGE_COULD_NOT_VERIFY
            issues.append({"path": str(raw_rel), "reason": "invalid_relative_path"})
            continue

        if isinstance(val, bytes):
            if max_file_bytes >= 0 and len(val) > max_file_bytes:
                coverage = COVERAGE_COULD_NOT_VERIFY
                out[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_COULD_NOT_VERIFY,
                    "stable": True,
                    "content": None,
                    "sha256": None,
                    "bounded_exceeded": True,
                    "error": f"File size {len(val)} exceeds limit {max_file_bytes}",
                }
                issues.append({"path": rel, "reason": "bounded_exceeded"})
            else:
                out[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_VERIFIED,
                    "stable": True,
                    "content": val,
                    "sha256": hashlib.sha256(val).hexdigest(),
                    "size": len(val),
                    "error": None,
                }
        elif isinstance(val, str):
            raw_b = val.encode("utf-8")
            if max_file_bytes >= 0 and len(raw_b) > max_file_bytes:
                coverage = COVERAGE_COULD_NOT_VERIFY
                out[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_COULD_NOT_VERIFY,
                    "stable": True,
                    "content": None,
                    "sha256": None,
                    "bounded_exceeded": True,
                    "error": f"File size {len(raw_b)} exceeds limit {max_file_bytes}",
                }
                issues.append({"path": rel, "reason": "bounded_exceeded"})
            else:
                out[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_VERIFIED,
                    "stable": True,
                    "content": raw_b,
                    "sha256": hashlib.sha256(raw_b).hexdigest(),
                    "size": len(raw_b),
                    "error": None,
                }
        elif isinstance(val, Mapping):
            kind = str(val.get("kind") or "regular")
            cov = str(val.get("coverage") or COVERAGE_VERIFIED)
            stable = bool(val.get("stable", True))
            bounded = bool(val.get("bounded_exceeded", False))
            err = val.get("error")
            raw_content = val.get("content")
            if raw_content is None and isinstance(val.get("content_utf8"), str):
                raw_content = val["content_utf8"].encode("utf-8")
            elif isinstance(raw_content, str):
                raw_content = raw_content.encode("utf-8")

            sha = val.get("sha256")
            if sha is None and isinstance(raw_content, bytes):
                sha = hashlib.sha256(raw_content).hexdigest()

            if (
                kind != "regular"
                or cov != COVERAGE_VERIFIED
                or not stable
                or bounded
                or raw_content is None
            ):
                coverage = COVERAGE_COULD_NOT_VERIFY
                out[rel] = {
                    "rel_path": rel,
                    "kind": kind,
                    "coverage": COVERAGE_COULD_NOT_VERIFY,
                    "stable": stable,
                    "content": None,
                    "sha256": None,
                    "bounded_exceeded": bounded,
                    "symlink_target": val.get("symlink_target"),
                    "error": str(err or f"Unverified file ({kind})"),
                }
                issues.append({"path": rel, "reason": str(err or kind)})
            else:
                out[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_VERIFIED,
                    "stable": True,
                    "content": raw_content,
                    "sha256": str(sha).lower() if sha else None,
                    "size": len(raw_content),
                    "error": None,
                }
        else:
            coverage = COVERAGE_COULD_NOT_VERIFY
            issues.append({"path": rel, "reason": f"unsupported_entry_type:{type(val).__name__}"})

    return out, coverage, issues


# LOCAL PATCH golden-template-registry-v1: decode UTF-8 with BOM tolerance (utf-8-sig).
def _decode_utf8(meta: Mapping[str, Any]) -> str | None:
    raw = meta.get("content")
    if not isinstance(raw, bytes) or b"\x00" in raw[:_BINARY_SNIFF_BYTES]:
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _resolve_approved_deps_for_ecosystem(
    ecosystem: str,
    approved_deps: Mapping[str, Sequence[str]] | Sequence[str] | None,
    template_spec: Mapping[str, Any] | None = None,
) -> list[str] | None:
    raw = approved_deps
    if raw is None and isinstance(template_spec, Mapping):
        raw = template_spec.get("approved_deps")
    if raw is None:
        return None
    if isinstance(raw, (list, tuple, set, frozenset)):
        return sorted({str(x).strip() for x in raw if str(x).strip()})
    if isinstance(raw, Mapping):
        if not raw:
            return None
        # LOCAL PATCH golden-template-registry-v1: support go, cpp, and csharp/dotnet approved_deps keys.
        candidate_keys = {
            "rust": ("rust", "cargo", "crates", "default"),
            "ts-node": ("ts-node", "ts_node", "typescript", "node", "pnpm", "npm", "js", "ts", "default"),
            "python": ("python", "py", "uv", "pypi", "default"),
            "go": ("go", "golang", "default"),
            "cpp": ("cpp", "c++", "cxx", "cmake", "default"),
            "csharp": ("csharp", "dotnet", "cs", "nuget", "default"),
            "dotnet": ("dotnet", "csharp", "cs", "nuget", "default"),
        }.get(ecosystem, (ecosystem, "default"))
        for key in candidate_keys:
            if key in raw and isinstance(raw[key], (list, tuple, set, frozenset)):
                return sorted({str(x).strip() for x in raw[key] if str(x).strip()})
        # Fallback if there is exactly 1 ecosystem key in approved_deps
        if len(raw) == 1:
            only_val = next(iter(raw.values()))
            if isinstance(only_val, (list, tuple, set, frozenset)):
                return sorted({str(x).strip() for x in only_val if str(x).strip()})
    return None


def parse_cargo_lock(text: str) -> dict[str, Any]:
    """Parse `Cargo.lock` into external packages (with `source`) and workspace packages (without `source`)."""
    data = tomllib.loads(text)
    packages = data.get("package", [])
    if not isinstance(packages, list):
        raise ValueError("Cargo.lock 'package' field must be a list")

    external: dict[str, list[str]] = {}
    workspace: set[str] = set()
    for pkg in packages:
        if not isinstance(pkg, Mapping):
            continue
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        version = str(pkg.get("version") or "").strip()
        if "source" in pkg and pkg.get("source"):
            external.setdefault(name, []).append(version)
        else:
            workspace.add(name)

    return {
        "external_packages": {k: sorted(v) for k, v in sorted(external.items())},
        "workspace_packages": sorted(workspace),
    }


def _split_pnpm_pkg_key(raw_key: str) -> tuple[str, str] | None:
    """Parse a pnpm package key like `'@hono/node-server@2.1.5(hono@4.13.10)'` or `/zod/3.25.76` into `(name, version)`."""
    cleaned = raw_key.strip()
    if (cleaned.startswith("'") and cleaned.endswith("'")) or (
        cleaned.startswith('"') and cleaned.endswith('"')
    ):
        cleaned = cleaned[1:-1].strip()
    if not cleaned:
        return None
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    # Strip peer suffix `(...)`
    paren_idx = cleaned.find("(")
    if paren_idx != -1:
        cleaned = cleaned[:paren_idx]
    if not cleaned:
        return None

    if cleaned.startswith("@"):
        slash_idx = cleaned.find("/")
        if slash_idx == -1:
            return None
        rest = cleaned[slash_idx + 1 :]
        if "@" in rest:
            pkg_sub, _, ver = rest.partition("@")
            return f"{cleaned[:slash_idx]}/{pkg_sub}", ver
        if "/" in rest:
            pkg_sub, _, ver = rest.partition("/")
            return f"{cleaned[:slash_idx]}/{pkg_sub}", ver
        return f"{cleaned[:slash_idx]}/{rest}", ""

    if "@" in cleaned:
        name, _, ver = cleaned.partition("@")
        return (name, ver) if name else None
    if "/" in cleaned:
        name, _, ver = cleaned.partition("/")
        return (name, ver) if name else None
    return cleaned, ""


def _unquote_yaml_scalar(val: str) -> str:
    s = val.strip()
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        return s[1:-1]
    return s


# LOCAL PATCH pnpm-config-document-v1: linear helpers for trailing comments and
# one-line flow maps (`configDependencies: {}` / `{a: 1.0.0+sha512-...}`).
def _strip_yaml_comment(line: str) -> str:
    """Drop a ` #` trailing comment outside quotes (single left-to-right pass)."""
    quote = ""
    prev = " "
    for idx, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"') and prev in (" ", ":", "{", ",", "["):
            quote = ch
        elif ch == "#" and prev in (" ", "\t"):
            return line[:idx].rstrip()
        prev = ch
    return line


_PNPM_TOOL_DEP_SECTIONS = ("configDependencies", "packageManagerDependencies")


def _parse_pnpm_flow_map(section: str, value: str) -> dict[str, str]:
    """Parse a one-line `{k: v, ...}` map without nesting; anything else is malformed."""
    if not (value.startswith("{") and value.endswith("}")):
        raise ValueError(f"pnpm-lock.yaml {section} is not a mapping")
    body = value[1:-1]
    if "{" in body or "}" in body or "[" in body or "]" in body:
        raise ValueError(f"pnpm-lock.yaml {section} has a nested or unterminated mapping")
    out: dict[str, str] = {}
    for item in body.split(","):
        if not item.strip():
            continue
        k_raw, sep, v_raw = item.partition(":")
        name = _unquote_yaml_scalar(k_raw)
        if not sep or not name:
            raise ValueError(f"pnpm-lock.yaml {section} has an entry without a package name")
        out[name] = _unquote_yaml_scalar(v_raw)
    return out


def _pnpm_plain_version(raw: str) -> str:
    """`1.2.3+sha512-...(peer@1)` -> `1.2.3`."""
    return raw.split("(")[0].split("+")[0].strip()


def parse_pnpm_lock(text: str) -> dict[str, Any]:
    """Stdlib parser for `pnpm-lock.yaml` (supports pnpm v6/v8/v9/v12 single and multi-document lockfiles)."""
    if not text or not text.strip():
        raise ValueError("pnpm-lock.yaml is empty")
    if "lockfileVersion" not in text:
        raise ValueError("pnpm-lock.yaml is missing lockfileVersion")

    raw_docs = re.split(r"(?m)^---\s*$", text)
    docs = [d for d in raw_docs if d.strip()]
    if not docs:
        raise ValueError("pnpm-lock.yaml contains no YAML documents")

    # LOCAL PATCH pnpm-config-document-v1: every YAML document is read, including the
    # first (environment) document of pnpm v11+ lockfiles. Its importers name
    # configDependencies (installed and executed by pnpm before any other install) and
    # packageManagerDependencies (the pnpm binary itself), and its packages/snapshots
    # sections list what those resolve to, so each can introduce code.

    external: dict[str, set[str]] = {}
    workspace: set[str] = set()
    dev_packages: set[str] = set()
    runtime_packages: set[str] = set()
    catalog_packages: set[str] = set()
    tool_packages: set[str] = set()

    def _add_tool_flow_map(section: str, value: str) -> None:
        for name, ver in _parse_pnpm_flow_map(section, value).items():
            if ver.startswith(("link:", "file:", "workspace:")):
                workspace.add(name)
            else:
                external.setdefault(name, set()).add(_pnpm_plain_version(ver))
                dev_packages.add(name)

    for doc in docs:
        top_section: str | None = None
        importer_dep_section: str | None = None
        current_importer_pkg: str | None = None
        current_importer_spec: str | None = None
        current_importer_ver: str | None = None

        def _flush_importer_pkg() -> None:
            nonlocal current_importer_pkg, current_importer_spec, current_importer_ver
            if not current_importer_pkg or not importer_dep_section:
                current_importer_pkg = None
                current_importer_spec = None
                current_importer_ver = None
                return
            spec_s = (current_importer_spec or "").strip()
            ver_s = (current_importer_ver or "").strip()
            is_ws = (
                spec_s.startswith(("workspace:", "link:", "file:"))
                or ver_s.startswith(("link:", "file:", "workspace:"))
            )
            if is_ws:
                workspace.add(current_importer_pkg)
            else:
                clean_ver = _pnpm_plain_version(ver_s)
                external.setdefault(current_importer_pkg, set()).add(clean_ver)
                if importer_dep_section in _PNPM_TOOL_DEP_SECTIONS:
                    tool_packages.add(current_importer_pkg)
                elif importer_dep_section == "devDependencies":
                    dev_packages.add(current_importer_pkg)
                else:
                    runtime_packages.add(current_importer_pkg)
            current_importer_pkg = None
            current_importer_spec = None
            current_importer_ver = None

        for raw_line in doc.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            stripped = _strip_yaml_comment(raw_line).strip()
            if not stripped:
                continue

            if indent == 0 and stripped.endswith(":"):
                _flush_importer_pkg()
                top_section = stripped[:-1].strip()
                importer_dep_section = None
                continue
            if indent == 0:
                _flush_importer_pkg()
                top_section = None
                importer_dep_section = None
                key_part, _, top_val = stripped.partition(":")
                if key_part.strip() in _PNPM_TOOL_DEP_SECTIONS:
                    _add_tool_flow_map(key_part.strip(), top_val.strip())
                continue

            if top_section == "catalogs":
                if indent == 4 and ":" in stripped:
                    key_part = _unquote_yaml_scalar(stripped.partition(":")[0])
                    if key_part:
                        catalog_packages.add(key_part)
            elif top_section == "importers":
                if indent == 2:
                    _flush_importer_pkg()
                    importer_dep_section = None
                elif indent == 4 and stripped.endswith(":"):
                    _flush_importer_pkg()
                    sec_name = stripped[:-1].strip()
                    if sec_name in ("dependencies", "devDependencies", "optionalDependencies", *_PNPM_TOOL_DEP_SECTIONS):
                        importer_dep_section = sec_name
                    else:
                        importer_dep_section = None
                elif indent == 4 and ":" in stripped:
                    _flush_importer_pkg()
                    importer_dep_section = None
                    sec_name, _, sec_val = stripped.partition(":")
                    if sec_name.strip() in _PNPM_TOOL_DEP_SECTIONS:
                        _add_tool_flow_map(sec_name.strip(), sec_val.strip())
                elif indent == 6 and importer_dep_section is not None and ":" in stripped:
                    _flush_importer_pkg()
                    k_raw, _, v_raw = stripped.partition(":")
                    pkg_name = _unquote_yaml_scalar(k_raw)
                    v_clean = _unquote_yaml_scalar(v_raw)
                    current_importer_pkg = pkg_name
                    if v_clean and not v_clean.startswith("{"):
                        current_importer_ver = v_clean
                elif indent == 8 and current_importer_pkg is not None and ":" in stripped:
                    k_raw, _, v_raw = stripped.partition(":")
                    k_clean = k_raw.strip()
                    v_clean = _unquote_yaml_scalar(v_raw)
                    if k_clean == "specifier":
                        current_importer_spec = v_clean
                    elif k_clean == "version":
                        current_importer_ver = v_clean
            elif top_section in _PNPM_TOOL_DEP_SECTIONS:
                if indent == 2 and ":" in stripped:
                    k_raw, _, v_raw = stripped.partition(":")
                    name = _unquote_yaml_scalar(k_raw)
                    if name:
                        external.setdefault(name, set()).add(_pnpm_plain_version(_unquote_yaml_scalar(v_raw)))
                        dev_packages.add(name)
            elif top_section in ("packages", "snapshots"):
                if indent == 2 and ":" in stripped:
                    key_raw = stripped.partition(":")[0].strip()
                    parsed_key = _split_pnpm_pkg_key(key_raw)
                    if parsed_key is not None:
                        p_name, p_ver = parsed_key
                        if p_name and p_name not in workspace:
                            external.setdefault(p_name, set()).add(p_ver)

        _flush_importer_pkg()

    for ws_pkg in workspace:
        external.pop(ws_pkg, None)

    return {
        "external_packages": {k: sorted(v for v in vers if v) for k, vers in sorted(external.items())},
        "workspace_packages": sorted(workspace),
        "dev_packages": sorted((dev_packages | tool_packages) - runtime_packages),
        "runtime_packages": sorted(runtime_packages),
        "catalog_packages": sorted(catalog_packages),
    }


def parse_uv_lock(text: str) -> dict[str, Any]:
    """Parse `uv.lock` into external packages, workspace members, and dev-group packages."""
    data = tomllib.loads(text)
    raw_manifest = data.get("manifest")
    manifest: Mapping[str, Any] = raw_manifest if isinstance(raw_manifest, Mapping) else {}
    raw_members_val = manifest.get("members")
    raw_members: list[Any] = raw_members_val if isinstance(raw_members_val, list) else []
    workspace: set[str] = {str(m).strip() for m in raw_members if str(m).strip()}

    dev_packages: set[str] = set()
    dep_groups = manifest.get("dependency-groups")
    if isinstance(dep_groups, Mapping):
        for group_items in dep_groups.values():
            if isinstance(group_items, list):
                for item in group_items:
                    if isinstance(item, Mapping) and item.get("name"):
                        dev_packages.add(str(item["name"]).strip())
                    elif isinstance(item, str):
                        dev_packages.add(re.split(r"[<>=!~;\s\[]", item, maxsplit=1)[0].strip())

    packages = data.get("package", [])
    if not isinstance(packages, list):
        raise ValueError("uv.lock 'package' field must be a list")

    external: dict[str, list[str]] = {}
    for pkg in packages:
        if not isinstance(pkg, Mapping):
            continue
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        version = str(pkg.get("version") or "").strip()
        source = pkg.get("source")
        is_local = name in workspace
        if isinstance(source, Mapping):
            if any(k in source for k in ("editable", "virtual", "directory")):
                is_local = True
        elif source is None:
            is_local = True

        if is_local:
            workspace.add(name)
        else:
            external.setdefault(name, []).append(version)

    return {
        "external_packages": {k: sorted(v) for k, v in sorted(external.items())},
        "workspace_packages": sorted(workspace),
        "dev_packages": sorted(dev_packages),
    }


# LOCAL PATCH golden-template-registry-v1: lockfile parsers for go, cpp, and csharp/dotnet templates.
_GO_SUM_MOD_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?)+(?:/[A-Za-z0-9_.~+-]+)*$"
)
_GO_SUM_VER_RE = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_GO_SUM_H1_RE = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")


def parse_go_sum(text: str) -> dict[str, Any]:
    """Parse `go.sum` into external module versions with strict module/semver/h1 validation."""
    text = text.removeprefix("\ufeff")
    external: dict[str, set[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError(f"Malformed go.sum line: {raw_line!r}")
        mod_name, raw_ver, digest = parts
        ver = raw_ver[: -len("/go.mod")] if raw_ver.endswith("/go.mod") else raw_ver
        if (
            not _GO_SUM_MOD_RE.fullmatch(mod_name)
            or any(seg in (".", "..") for seg in mod_name.split("/"))
            or not _GO_SUM_VER_RE.fullmatch(ver)
            or not _GO_SUM_H1_RE.fullmatch(digest)
        ):
            raise ValueError(f"Invalid go.sum entry: {raw_line!r}")
        external.setdefault(mod_name, set()).add(ver)
    return {
        "external_packages": {k: sorted(v) for k, v in sorted(external.items())},
        "workspace_packages": [],
        "dev_packages": [],
    }


_CMAKE_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_CMAKE_CMD_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _strip_cmake_comments(text: str) -> str:
    """Strip CMake `#` line comments and `#[[ ... ]]` / `#[=[ ... ]=]` bracket comments outside quoted strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_quote = False
    while i < n:
        ch = text[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            if ch == '"':
                in_quote = False
            out.append(ch)
            i += 1
            continue

        if ch == '"':
            in_quote = True
            out.append(ch)
            i += 1
            continue

        # Bracket argument [[ ... ]] or [=[ ... ]=] (not a comment when not preceded by #)
        if ch == "[" and i + 1 < n and text[i + 1] in ("[", "="):
            j = i + 1
            while j < n and text[j] == "=":
                j += 1
            if j < n and text[j] == "[":
                eq_len = j - (i + 1)
                close_delim = "]" + ("=" * eq_len) + "]"
                close_idx = text.find(close_delim, j + 1)
                if close_idx == -1:
                    raise ValueError("Unclosed CMake bracket argument")
                end_pos = close_idx + len(close_delim)
                out.append(text[i:end_pos])
                i = end_pos
                continue

        if ch == "#":
            # Check for CMake bracket comment: #[[ ... ]] or #[=[ ... ]=]
            if i + 1 < n and text[i + 1] == "[":
                j = i + 2
                while j < n and text[j] == "=":
                    j += 1
                if j < n and text[j] == "[":
                    eq_len = j - (i + 2)
                    close_delim = "]" + ("=" * eq_len) + "]"
                    close_idx = text.find(close_delim, j + 1)
                    if close_idx == -1:
                        raise ValueError("Unclosed CMake bracket comment")
                    end_pos = close_idx + len(close_delim)
                    for c in text[i:end_pos]:
                        out.append("\n" if c == "\n" else " ")
                    i = end_pos
                    continue
            # Regular line comment to end of line
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue

        out.append(ch)
        i += 1

    if in_quote:
        raise ValueError("Unclosed quoted string in CMakeLists.txt")
    return "".join(out)


def parse_cmake_lock(text: str) -> dict[str, Any]:
    """Parse `CMakeLists.txt` / `*.cmake` for declared external `FetchContent_Declare` / `find_package` dependencies."""
    text = text.removeprefix("\ufeff")
    if not text or not text.strip():
        raise ValueError("CMakeLists.txt is empty")
    stripped = _strip_cmake_comments(text)
    external: dict[str, list[str]] = {}
    n = len(stripped)
    pos = 0
    at_cmd_start = True

    def _scan_balanced_parens(start_idx: int, cmd_label: str) -> int:
        idx = start_idx + 1
        depth = 1
        in_str = False
        while idx < n and depth > 0:
            c = stripped[idx]
            if in_str:
                if c == "\\" and idx + 1 < n:
                    idx += 2
                    continue
                if c == '"':
                    in_str = False
                idx += 1
                continue

            if c == '"':
                in_str = True
                idx += 1
                continue

            if c == "[" and idx + 1 < n and stripped[idx + 1] in ("[", "="):
                j = idx + 1
                while j < n and stripped[j] == "=":
                    j += 1
                if j < n and stripped[j] == "[":
                    eq_len = j - (idx + 1)
                    close_delim = "]" + ("=" * eq_len) + "]"
                    close_idx = stripped.find(close_delim, j + 1)
                    if close_idx == -1:
                        raise ValueError("Unclosed CMake bracket argument")
                    idx = close_idx + len(close_delim)
                    continue

            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            idx += 1

        if depth != 0:
            raise ValueError(f"Unclosed {cmd_label}(...) invocation in CMakeLists.txt")
        return idx

    while pos < n:
        ch = stripped[pos]
        if ch.isspace() or ch == ";":
            if ch in ("\n", "\r", ";"):
                at_cmd_start = True
            pos += 1
            continue

        if ch == '"':
            pos += 1
            while pos < n:
                if stripped[pos] == "\\" and pos + 1 < n:
                    pos += 2
                    continue
                if stripped[pos] == '"':
                    pos += 1
                    break
                pos += 1
            at_cmd_start = False
            continue

        if ch == "[" and pos + 1 < n and stripped[pos + 1] in ("[", "="):
            j = pos + 1
            while j < n and stripped[j] == "=":
                j += 1
            if j < n and stripped[j] == "[":
                eq_len = j - (pos + 1)
                close_delim = "]" + ("=" * eq_len) + "]"
                close_idx = stripped.find(close_delim, j + 1)
                if close_idx == -1:
                    raise ValueError("Unclosed CMake bracket argument")
                pos = close_idx + len(close_delim)
                at_cmd_start = False
                continue

        if ch == "(":
            pos = _scan_balanced_parens(pos, "command")
            at_cmd_start = True
            continue

        if ch == ")":
            raise ValueError("Unmatched ')' in CMakeLists.txt")

        ident_match = _CMAKE_CMD_IDENT_RE.match(stripped, pos)
        if not ident_match:
            at_cmd_start = False
            pos += 1
            continue

        cmd_name = ident_match.group(0)
        was_cmd_start = at_cmd_start
        pos = ident_match.end()
        at_cmd_start = False

        if not was_cmd_start or cmd_name.lower() not in ("fetchcontent_declare", "find_package"):
            continue

        while pos < n and stripped[pos].isspace():
            pos += 1
        if pos >= n or stripped[pos] != "(":
            raise ValueError(f"Malformed {cmd_name} invocation in CMakeLists.txt")

        paren_start = pos
        pos = _scan_balanced_parens(paren_start, cmd_name)
        at_cmd_start = True

        args_body = stripped[paren_start + 1 : pos - 1].strip()
        if not args_body:
            raise ValueError(f"Empty {cmd_name}() invocation in CMakeLists.txt")

        if args_body.startswith('"'):
            end_q = 1
            arg_chars: list[str] = []
            closed_q = False
            while end_q < len(args_body):
                ch = args_body[end_q]
                if ch == "\\" and end_q + 1 < len(args_body):
                    arg_chars.append(args_body[end_q + 1])
                    end_q += 2
                    continue
                if ch == '"':
                    closed_q = True
                    end_q += 1
                    break
                arg_chars.append(ch)
                end_q += 1
            if not closed_q:
                raise ValueError(f"Unclosed quoted package argument in {cmd_name}")
            if end_q < len(args_body) and not args_body[end_q].isspace() and args_body[end_q] != ";":
                raise ValueError(f"Malformed quoted first argument in {cmd_name}")
            pkg = "".join(arg_chars).strip()
        else:
            token_match = re.match(r"^([^\s;()\"#]+)", args_body)
            if not token_match:
                raise ValueError(f"Cannot parse first argument in {cmd_name}")
            pkg = token_match.group(1).strip()

        if not pkg or "$" in pkg or not _CMAKE_PKG_NAME_RE.fullmatch(pkg):
            raise ValueError(f"Unparseable package identifier {pkg!r} in {cmd_name}")
        external.setdefault(pkg, []).append("declared")

    return {
        "external_packages": {k: sorted(set(v)) for k, v in sorted(external.items())},
        "workspace_packages": [],
        "dev_packages": [],
    }


def parse_nuget_lock(text: str) -> dict[str, Any]:
    """Parse NuGet `packages.lock.json` into external packages and solution project references with strict shape validation."""
    text = text.removeprefix("\ufeff")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"Invalid packages.lock.json: {exc}") from exc
    if not isinstance(data, Mapping) or "dependencies" not in data:
        raise ValueError("packages.lock.json must be a JSON object with 'dependencies'")
    version = data.get("version")
    if version is not None and (isinstance(version, bool) or not isinstance(version, int) or version < 1):
        raise ValueError("packages.lock.json 'version' must be a positive integer")
    deps_root = data.get("dependencies")
    if not isinstance(deps_root, Mapping):
        raise ValueError("packages.lock.json 'dependencies' field must be an object")
    external: dict[str, set[str]] = {}
    workspace: set[str] = set()
    for tfm_key, tfm_deps in deps_root.items():
        if not isinstance(tfm_key, str) or not tfm_key.strip() or not isinstance(tfm_deps, Mapping):
            raise ValueError(f"packages.lock.json target framework entry {tfm_key!r} must map to an object")
        for pkg_name, pkg_info in tfm_deps.items():
            if not isinstance(pkg_name, str) or not pkg_name.strip() or not isinstance(pkg_info, Mapping):
                raise ValueError(f"packages.lock.json dependency {pkg_name!r} must map to an object")
            name = pkg_name.strip()
            raw_type = pkg_info.get("type")
            if raw_type is not None and not isinstance(raw_type, str):
                raise ValueError(f"packages.lock.json dependency {name!r} has non-string 'type'")
            dep_type = (raw_type or "").strip().lower()
            if dep_type == "project":
                workspace.add(name)
            else:
                raw_resolved = pkg_info.get("resolved")
                raw_requested = pkg_info.get("requested")
                if raw_resolved is not None and not isinstance(raw_resolved, str):
                    raise ValueError(f"packages.lock.json dependency {name!r} has non-string 'resolved'")
                if raw_requested is not None and not isinstance(raw_requested, str):
                    raise ValueError(f"packages.lock.json dependency {name!r} has non-string 'requested'")
                ver = (raw_resolved or raw_requested or "").strip()
                if not ver:
                    raise ValueError(f"packages.lock.json dependency {name!r} is missing 'resolved'/'requested' version")
                external.setdefault(name, set()).add(ver)
    return {
        "external_packages": {k: sorted(v) for k, v in sorted(external.items())},
        "workspace_packages": sorted(workspace),
        "dev_packages": [],
    }


def _strip_rust_comments_and_strings(text: str) -> str:
    """Replace Rust comments and string literals with spaces while preserving line breaks."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # Line comment
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # Block comment (supports nested /* ... */ in Rust)
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            continue
        # Raw string literal r#"..."# or br#"..."#
        if ch in ("r", "b") and i + 1 < n:
            start = i
            if ch == "b" and text[i + 1] == "r":
                j = i + 2
            elif ch == "r":
                j = i + 1
            else:
                j = -1
            if j != -1:
                hashes = 0
                while j < n and text[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and text[j] == '"':
                    closing = '"' + ("#" * hashes)
                    j += 1
                    end_idx = text.find(closing, j)
                    if end_idx == -1:
                        end_idx = n
                    else:
                        end_idx += len(closing)
                    for k in range(start, end_idx):
                        out.append("\n" if text[k] == "\n" else " ")
                    i = end_idx
                    continue
        # Normal string literal
        if ch == '"':
            out.append(" ")
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                if text[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_rust_use_roots(clause: str) -> list[tuple[str, str | None]]:
    """Extract `(root_ident, alias_ident)` pairs from a Rust `use` tree expression."""
    cleaned = clause.strip()
    if cleaned.startswith("::"):
        cleaned = cleaned[2:].strip()
    if not cleaned:
        return []
    if cleaned.startswith("{") and cleaned.endswith("}"):
        inner = cleaned[1:-1]
        parts: list[str] = []
        depth = 0
        cur: list[str] = []
        for ch in inner:
            if ch == "{":
                depth += 1
                cur.append(ch)
            elif ch == "}":
                depth = max(0, depth - 1)
                cur.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        if cur:
            parts.append("".join(cur))
        results: list[tuple[str, str | None]] = []
        for p in parts:
            results.extend(_extract_rust_use_roots(p))
        return results

    m_root = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", cleaned)
    if not m_root:
        return []
    root_ident = m_root.group(1)
    # Check if top-level crate itself is aliased: `use foo as bar` (no `::` before `as`)
    m_alias = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$", cleaned)
    if m_alias:
        return [(m_alias.group(1), m_alias.group(2))]
    return [(root_ident, None)]


# LOCAL PATCH linear-source-scan-v1: the import, suppression and line-count
# scans below replace patterns whose cost grew with the square (or worse) of
# hostile input: `[^)]*?` / `[\s\S]*?` before a required literal retried from
# every start, adjacent `\s*` runs split the same whitespace, and line numbers
# counted from offset 0 for every match. Each helper reproduces the original
# match spans and groups exactly (pinned by a differential test against the
# base revision); none truncates input.
_WS_RUN_RE = re.compile(r"\s*")
_QUOTE_RE = re.compile(r"['\"]")
_TS_DYNAMIC_HEAD_RE = re.compile(r"(?<![A-Za-z0-9_$.])(?:import|require)\s*\(")
_TS_FROM_SITE_RE = re.compile(r"(?<=\s)from")
_RUST_SUPPRESSION_HEAD_RE = re.compile(r"#\s*(?:!\s*)?\[\s*(allow|expect)\s*\(")
_RUST_SUPPRESSION_TAIL_RE = re.compile(r"\s*\]")
_RUST_USE_PREFIX_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?use\s+")
_RUST_USE_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?use\s+(.(?:[^;\n]*[^\s;])?)\s*;")


class _RunningCount:
    """Count of ``ch`` in ``text[:pos]`` for non-decreasing ``pos``, in linear total time."""

    def __init__(self, text: str, ch: str) -> None:
        self._text = text
        self._ch = ch
        self._pos = 0
        self._count = 0

    def upto(self, pos: int) -> int:
        if pos < self._pos:
            self._pos = 0
            self._count = 0
        self._count += self._text.count(self._ch, self._pos, pos)
        self._pos = pos
        return self._count


def _iter_ts_dynamic_imports(code: str) -> Iterable[tuple[int, int, str]]:
    r"""Yield (start, end, inner) for `import(` / `require(` calls closed by the next `)`.

    Same spans as finditer over
    ``(?<![A-Za-z0-9_$.])(?:import|require)\s*\(\s*([^)]*?)\s*\)``; ``inner`` is
    the text between the parentheses (callers strip it, as group 1 was).
    """
    pos = 0
    while True:
        head = _TS_DYNAMIC_HEAD_RE.search(code, pos)
        if head is None:
            return
        close = code.find(")", head.end())
        if close < 0:
            return
        yield head.start(), close + 1, code[head.end():close]
        pos = close + 1


def _ts_from_sites(code: str) -> tuple[list[int], dict[int, tuple[int, int]]]:
    r"""Positions r where ``\s+from\s+['"][^'"]+['"]`` can match with `from` at r."""
    quotes = [m.start() for m in _QUOTE_RE.finditer(code)]
    sites: list[int] = []
    spans: dict[int, tuple[int, int]] = {}
    for m_from in _TS_FROM_SITE_RE.finditer(code):
        r = m_from.start()
        t = _WS_RUN_RE.match(code, r + 4).end()
        if t == r + 4 or t >= len(code) or code[t] not in "'\"":
            continue
        k = bisect.bisect_right(quotes, t)
        if k == len(quotes) or quotes[k] == t + 1:
            continue
        sites.append(r)
        spans[r] = (t, quotes[k])
    return sites, spans


def _iter_ts_static_imports(code: str) -> Iterable[tuple[int, int, str]]:
    r"""Yield (start, end, spec) exactly as finditer over the upstream pattern
    ``(?m)^(\s*)(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]\s*;?``.

    The lazy ``[\s\S]*?\s+from\s+`` branch reaches the first `from` site after
    the keyword anywhere later in the text (also on a later line); that site is
    looked up in a precomputed sorted list instead of rescanned per start.
    """
    n = len(code)
    sites, spans = _ts_from_sites(code)
    quotes = [m.start() for m in _QUOTE_RE.finditer(code)]

    def tail_end(z: int) -> int:
        e = _WS_RUN_RE.match(code, z + 1).end()
        return e + 1 if e < n and code[e] == ";" else e

    def via_site(r: int) -> tuple[int, str]:
        t, z = spans[r]
        return tail_end(z), code[t + 1:z]

    def next_site_after(p: int) -> int | None:
        k = bisect.bisect_right(sites, p)
        return sites[k] if k < len(sites) else None

    def quoted_at(p: int) -> tuple[int, str] | None:
        if p >= n or code[p] not in "'\"":
            return None
        k = bisect.bisect_right(quotes, p)
        if k == len(quotes) or quotes[k] == p + 1:
            return None
        z = quotes[k]
        return tail_end(z), code[p + 1:z]

    def match_at(a: int) -> tuple[int, str] | None:
        if not code.startswith(("import", "export"), a):
            return None
        w_end = _WS_RUN_RE.match(code, a + 6).end()
        if w_end == a + 6:
            return None
        p = w_end
        type_ws = _WS_RUN_RE.match(code, p + 4).end() if code.startswith("type", p) else p + 4
        if code.startswith("type", p) and type_ws > p + 4:
            p1 = type_ws
            r = next_site_after(p1)
            if r is not None:
                return via_site(r)
            quoted = quoted_at(p1)
            if quoted is not None:
                return quoted
            return via_site(p1) if p1 in spans else None
        r = next_site_after(p)
        if r is not None:
            return via_site(r)
        quoted = quoted_at(p)
        if quoted is not None:
            return quoted
        if w_end - (a + 6) >= 2 and p in spans:
            return via_site(p)
        return None

    pos = 0
    while pos <= n:
        st = pos if pos == 0 or code[pos - 1] == "\n" else code.find("\n", pos) + 1
        if st == 0 and pos != 0:
            return
        a = _WS_RUN_RE.match(code, st).end()
        found = match_at(a)
        if found is not None:
            end, spec = found
            yield st, end, spec
            pos = end
            continue
        # Every later line start inside this whitespace run reaches the same
        # keyword and fails the same way.
        nxt = code.find("\n", a)
        if nxt < 0:
            return
        pos = nxt + 1


def _iter_rust_suppressions(line: str) -> Iterable[tuple[str, str]]:
    r"""Yield (kind, inner) as finditer over ``#\s*!?\s*\[\s*(allow|expect)\s*\(([^)]*)\)\s*\]``."""
    pos = 0
    while True:
        head = _RUST_SUPPRESSION_HEAD_RE.search(line, pos)
        if head is None:
            return
        close = line.find(")", head.end())
        if close < 0:
            return
        tail = _RUST_SUPPRESSION_TAIL_RE.match(line, close + 1)
        if tail is not None:
            yield head.group(1), line[head.end():close]
            pos = tail.end()
        else:
            # Every head that starts before `close` ends before it (a head holds
            # no `)`), reaches the same `)` and fails the same tail.
            pos = close + 1


def _match_rust_use(s: str) -> re.Match[str] | None:
    r"""Same result as matching ``^(?:pub(?:\([^)]*\))?\s+)?use\s+(.+?)\s*;`` on one line.

    The body starts with any one character, then reaches back to the last
    non-blank before the first `;`; without a `;` after the keyword no match is
    possible, so the regex is not tried.
    """
    prefix = _RUST_USE_PREFIX_RE.match(s)
    if prefix is None or ";" not in s[prefix.end():]:
        return None
    return _RUST_USE_RE.match(s)


def _scan_rust_imports_and_constructs(
    rel_path: str,
    text: str,
    *,
    local_mods: set[str],
    cargo_renamed_deps: set[str],
    max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH,
) -> dict[str, Any]:
    """Scan a Rust source file for imports, suppressions, stubs, and nesting depth."""
    stripped = _strip_rust_comments_and_strings(text)
    lines = stripped.splitlines()

    is_test_file = (
        rel_path.startswith(("tests/", "benches/", "examples/"))
        or "/tests/" in rel_path
        or "/benches/" in rel_path
    )

    imports: list[dict[str, Any]] = []
    declared_mods: set[str] = set(local_mods)
    local_crate_aliases: dict[str, str] = {}

    # Pre-scan `mod <ident>;` declarations in this file
    for line in lines:
        m_mod = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
        if m_mod:
            declared_mods.add(m_mod.group(1))

    brace_depth = 0
    pending_cfg = False
    cfg_block_depths: list[int] = []
    max_observed_nesting = 0
    max_nesting_line = 1

    for line_no, line in enumerate(lines, start=1):
        s = line.strip()
        if not s:
            continue

        # Detect `#[cfg(...)]` or `#[test]` attributes
        if re.search(r"#\s*\[\s*(?:cfg|test)\b", s):
            pending_cfg = True

        # Detect dynamic include! macro
        if re.search(r"\binclude!\s*\(", s):
            imports.append({
                "line": line_no,
                "raw": s,
                "target": "include!",
                "kind": "dynamic_import",
            })

        in_conditional_scope = is_test_file or pending_cfg or bool(cfg_block_depths) or (brace_depth > 0)

        # Detect `extern crate foo;` or `extern crate foo as bar;`
        m_ext = re.match(
            r"^(?:pub(?:\([^)]*\))?\s+)?extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;",
            s,
        )
        if m_ext:
            crate_ident = m_ext.group(1)
            alias_ident = m_ext.group(2)
            if alias_ident and alias_ident != "_":
                local_crate_aliases[alias_ident] = crate_ident
            imports.append({
                "line": line_no,
                "raw": s,
                "target": crate_ident,
                "alias": alias_ident,
                "kind": "conditional_or_dev_scope" if in_conditional_scope else "extern_crate",
            })

        # Detect `use ...;`
        m_use = _match_rust_use(s)
        if m_use:
            clause = m_use.group(1)
            roots = _extract_rust_use_roots(clause)
            if not roots:
                imports.append({
                    "line": line_no,
                    "raw": s,
                    "target": clause,
                    "kind": "unparseable_use",
                })
            for root_ident, alias_ident in roots:
                if alias_ident and alias_ident != "_":
                    local_crate_aliases[alias_ident] = root_ident
                if root_ident in local_crate_aliases or root_ident in cargo_renamed_deps:
                    imp_kind = "alias"
                elif in_conditional_scope:
                    imp_kind = "conditional_or_dev_scope"
                elif root_ident in _RUST_BUILTIN_ROOTS or root_ident in declared_mods:
                    imp_kind = "builtin_or_local"
                else:
                    imp_kind = "external"
                imports.append({
                    "line": line_no,
                    "raw": s,
                    "target": root_ident,
                    "alias": alias_ident,
                    "kind": imp_kind,
                })

        # Track brace depth and cfg block depth
        open_braces = line.count("{")
        close_braces = line.count("}")
        if open_braces > 0 and (pending_cfg or re.search(r"\bmod\s+tests\b", s)):
            cfg_block_depths.append(brace_depth + 1)
            pending_cfg = False
        elif not s.startswith("#[") and open_braces == 0 and ";" in s:
            pending_cfg = False

        brace_depth = max(0, brace_depth + open_braces - close_braces)
        while cfg_block_depths and brace_depth < cfg_block_depths[-1]:
            cfg_block_depths.pop()

        # Nesting inside functions (brace_depth - 1 for fn body)
        inner_nesting = max(0, brace_depth - 1)
        if inner_nesting > max_observed_nesting:
            max_observed_nesting = inner_nesting
            max_nesting_line = line_no

    # Suppressions in Rust (outside comments and strings): `#[allow(...)]`, `#![allow(...)]`, `#[expect(...)]`, `#![expect(...)]`
    suppressions: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        for sup_kind, sup_rule in _iter_rust_suppressions(line):
            suppressions.append({
                "path": rel_path,
                "line": line_no,
                "kind": sup_kind,
                "rule": sup_rule.strip(),
            })

    # Stubs in Rust (outside comments and strings): `todo!(...)`, `unimplemented!(...)`
    stubs: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        for m_stub in re.finditer(r"\b(todo|unimplemented)!\s*\(", line):
            stubs.append({
                "path": rel_path,
                "line": line_no,
                "kind": f"{m_stub.group(1)}!",
            })

    # Private helper functions for unreferenced check: `fn _foo(`
    private_defs: list[tuple[str, int]] = []
    for line_no, line in enumerate(lines, start=1):
        m_fn = re.search(r"(?<!pub\s)\bfn\s+(_[a-z0-9_]+)\s*\(", line)
        if m_fn:
            private_defs.append((m_fn.group(1), line_no))

    excess_nesting = (
        {"path": rel_path, "line": max_nesting_line, "depth": max_observed_nesting}
        if max_observed_nesting > max_nesting_depth
        else None
    )

    return {
        "imports": imports,
        "suppressions": suppressions,
        "stubs": stubs,
        "useless_try_catch": [],
        "excess_nesting": excess_nesting,
        "private_defs": private_defs,
        "stripped_code": stripped,
    }


def _tokenize_ts_source(text: str) -> tuple[str, list[tuple[int, str]]]:
    """Strip comments and string literals from TS/JS source while recording directive comments with 1-indexed lines."""
    code_no_comments_or_strings: list[str] = []
    directive_comments: list[tuple[int, str]] = []
    i = 0
    n = len(text)
    line_no = 1

    while i < n:
        ch = text[i]
        if ch == "\n":
            code_no_comments_or_strings.append("\n")
            line_no += 1
            i += 1
            continue
        # Line comment //
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            start_line = line_no
            j = i + 2
            while j < n and text[j] != "\n":
                j += 1
            comment_body = text[i + 2 : j].strip()
            directive_comments.append((start_line, comment_body))
            code_no_comments_or_strings.append(" " * (j - i))
            i = j
            continue
        # Block comment /* ... */
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            start_line = line_no
            j = i + 2
            body_chars: list[str] = []
            while j < n and not (text[j] == "*" and j + 1 < n and text[j + 1] == "/"):
                if text[j] == "\n":
                    line_no += 1
                    code_no_comments_or_strings.append("\n")
                else:
                    code_no_comments_or_strings.append(" ")
                body_chars.append(text[j])
                j += 1
            if j < n:
                j += 2
                code_no_comments_or_strings.append("  ")
            comment_body = "".join(body_chars).strip()
            directive_comments.append((start_line, comment_body))
            i = j
            continue
        # String literal ('...', "...", `...`)
        if ch in ("'", '"', "`"):
            quote = ch
            code_no_comments_or_strings.append(" ")
            i += 1
            while i < n:
                c = text[i]
                if c == "\\":
                    code_no_comments_or_strings.append("  ")
                    if i + 1 < n and text[i + 1] == "\n":
                        line_no += 1
                    i += 2
                    continue
                if c == "\n":
                    line_no += 1
                    code_no_comments_or_strings.append("\n")
                    i += 1
                    if quote != "`":
                        break
                    continue
                if c == quote:
                    code_no_comments_or_strings.append(" ")
                    i += 1
                    break
                code_no_comments_or_strings.append(" ")
                i += 1
            continue

        code_no_comments_or_strings.append(ch)
        i += 1

    return "".join(code_no_comments_or_strings), directive_comments


def _strip_ts_comments_keep_strings(text: str) -> str:
    """Strip `//` and `/* ... */` comments from TS/JS while keeping string literals intact for import specifier extraction."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = text[i]
                if c == "\\":
                    out.append(text[i : i + 2])
                    i += 2
                    continue
                out.append(c)
                i += 1
                if c == quote:
                    break
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _classify_ts_specifier(
    spec: str,
    *,
    tsconfig_path_prefixes: Sequence[str],
) -> tuple[str, str]:
    """Return `(category, normalized_pkg_or_spec)` for a TS/JS module specifier."""
    s = spec.strip()
    if not s:
        return ("alias", s)
    if s.startswith("node:"):
        return ("builtin", s)
    first_seg = s.split("/")[0]
    if first_seg in _NODE_BUILTIN_MODULES:
        return ("builtin", first_seg)
    for pat in tsconfig_path_prefixes:
        if s == pat or s.startswith(pat):
            return ("alias", s)
    if s.startswith(("@/", "~/", "#", "$", "workspace:", "link:", "file:", "npm:", "jsr:", "http:", "https:")):
        return ("alias", s)
    if s.startswith(("./", "../")) or s in (".", ".."):
        return ("relative", s)
    if s.startswith("@"):
        parts = s.split("/")
        if len(parts) < 2 or not parts[0][1:] or not parts[1]:
            return ("alias", s)
        return ("package", f"{parts[0]}/{parts[1]}")
    return ("package", first_seg)


# LOCAL PATCH dev-scope-import-mapping-v1: development-scope files are the scanner's own
# test classification plus `<name>.config.<ext>` files and anything under a top-level
# `tools/` or `scripts/` folder. A dynamic import argument is a specifier only when it is
# one plain string literal; a URL-like literal (`scheme:`) is never a package.
_TS_DEV_CONFIG_RE = re.compile(r"\.config\.(?:ts|tsx|mts|cts|js|mjs|cjs)$")
_TS_LITERAL_ARG_RE = re.compile(r"""^(?:"([^"\\\n]*)"|'([^'\\\n]*)'|`([^`\\$\n]*)`)$""")
_TS_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _ts_dev_scope_file(rel_path: str) -> bool:
    return (
        rel_path.endswith((".test.ts", ".spec.ts", ".test.js", ".spec.js", ".test.mts", ".spec.mts"))
        or rel_path.startswith(("test/", "tests/", "tools/", "scripts/"))
        or "/test/" in rel_path
        or "/tests/" in rel_path
        or bool(_TS_DEV_CONFIG_RE.search(rel_path.rsplit("/", 1)[-1]))
    )


def _ts_literal_dynamic_specifier(arg: str) -> str | None:
    m = _TS_LITERAL_ARG_RE.match(arg)
    if m is None:
        return None
    spec = next(g for g in m.groups() if g is not None).strip()
    if not spec or (_TS_URL_SCHEME_RE.match(spec) and not spec.startswith("node:")):
        return None
    return spec


def _scan_ts_imports_and_constructs(
    rel_path: str,
    text: str,
    *,
    tsconfig_path_prefixes: Sequence[str] = (),
    max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH,
) -> dict[str, Any]:
    """Scan a TypeScript/JavaScript source file for imports, suppressions, stubs, useless catch, and nesting."""
    stripped_all, directive_comments = _tokenize_ts_source(text)
    code_with_strings = _strip_ts_comments_keep_strings(text)

    is_test_file = (
        rel_path.endswith((".test.ts", ".spec.ts", ".test.js", ".spec.js", ".test.mts", ".spec.mts"))
        or rel_path.startswith(("test/", "tests/"))
        or "/test/" in rel_path
        or "/tests/" in rel_path
    )

    imports: list[dict[str, Any]] = []
    # LOCAL PATCH linear-source-scan-v1: running line and brace counts, not a
    # count from offset 0 for every match.
    code_lines = _RunningCount(code_with_strings, "\n")
    open_before = _RunningCount(stripped_all, "{")
    close_before = _RunningCount(stripped_all, "}")

    # 1. Dynamic `import(...)` and `require(...)` calls (on comment-stripped code)
    for dyn_start, dyn_end, arg_raw in _iter_ts_dynamic_imports(code_with_strings):
        line_no = code_lines.upto(dyn_start) + 1
        arg_txt = arg_raw.strip()
        imports.append({
            "line": line_no,
            "raw": code_with_strings[dyn_start:dyn_end].strip(),
            "target": arg_txt,
            "kind": "dynamic_import",
        })

    # 2. Static `import ... from "spec"`, `export ... from "spec"`, `import "spec"`
    code_lines = _RunningCount(code_with_strings, "\n")
    for imp_start, imp_end, spec_raw in _iter_ts_static_imports(code_with_strings):
        line_no = code_lines.upto(imp_start) + 1
        spec = spec_raw.strip()
        net_braces = open_before.upto(imp_start) - close_before.upto(imp_start)
        cat, resolved_target = _classify_ts_specifier(spec, tsconfig_path_prefixes=tsconfig_path_prefixes)

        if net_braces > 0:
            kind = "conditional_or_dev_scope"
        elif cat == "alias":
            kind = "alias"
        elif cat in ("builtin", "relative"):
            kind = "builtin_or_local"
        elif is_test_file:
            kind = "conditional_or_dev_scope"
        else:
            kind = "external"

        imports.append({
            "line": line_no,
            "raw": code_with_strings[imp_start:imp_end].strip(),
            "specifier": spec,
            "target": resolved_target,
            "kind": kind,
        })

    # 3. Suppressions in TS/JS: directive comments starting with `@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `biome-ignore`, `eslint-disable`
    suppressions: list[dict[str, Any]] = []
    directive_re = re.compile(
        r"^(?:@ts-ignore|@ts-expect-error|@ts-nocheck|biome-ignore|eslint-disable(?:-next-line|-line)?)\b(.*)$"
    )
    for line_no, comment_body in directive_comments:
        m_dir = directive_re.match(comment_body)
        if m_dir:
            suppressions.append({
                "path": rel_path,
                "line": line_no,
                "kind": comment_body.split()[0],
                "rule": m_dir.group(1).strip(),
            })

    # 4. Stubs in TS/JS: `throw new Error("not implemented" | "todo")` (in comment-stripped code)
    stubs: list[dict[str, Any]] = []
    code_lines = _RunningCount(code_with_strings, "\n")
    for m_stub in re.finditer(
        r"\bthrow\s+new\s+[A-Za-z0-9_]*Error\s*\(\s*['\"`](?:not\s+implemented|todo|unimplemented)[^'\"`]*['\"`]\s*\)",
        code_with_strings,
        flags=re.IGNORECASE,
    ):
        line_no = code_lines.upto(m_stub.start()) + 1
        stubs.append({
            "path": rel_path,
            "line": line_no,
            "kind": "throw_not_implemented",
        })

    # 5. Useless try/catch in TS/JS: empty `catch (...) {}` or `catch (e) { throw e; }`
    useless_try_catch: list[dict[str, Any]] = []
    # LOCAL PATCH linear-source-scan-v1: the optional groups own their trailing
    # whitespace, so adjacent `\s*` runs cannot split the same blanks.
    stripped_lines = _RunningCount(stripped_all, "\n")
    for m_catch in re.finditer(
        r"\bcatch\s*(?:\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*)?\{\s*(?:throw\s+\1\s*(?:;\s*)?)?\}",
        stripped_all,
    ):
        line_no = stripped_lines.upto(m_catch.start()) + 1
        useless_try_catch.append({
            "path": rel_path,
            "line": line_no,
            "kind": "empty_or_rethrow_catch",
        })

    # 6. Excess nesting in TS/JS
    brace_depth = 0
    max_observed_nesting = 0
    max_nesting_line = 1
    for line_no, line in enumerate(stripped_all.splitlines(), start=1):
        brace_depth = max(0, brace_depth + line.count("{") - line.count("}"))
        inner = max(0, brace_depth - 1)
        if inner > max_observed_nesting:
            max_observed_nesting = inner
            max_nesting_line = line_no

    excess_nesting = (
        {"path": rel_path, "line": max_nesting_line, "depth": max_observed_nesting}
        if max_observed_nesting > max_nesting_depth
        else None
    )

    # 7. Private helper functions `function _foo(`
    private_defs: list[tuple[str, int]] = []
    for line_no, line in enumerate(stripped_all.splitlines(), start=1):
        m_fn = re.search(r"(?<!export\s)\bfunction\s+(_[A-Za-z0-9_]+)\s*\(", line)
        if m_fn:
            private_defs.append((m_fn.group(1), line_no))

    return {
        "imports": imports,
        "suppressions": suppressions,
        "stubs": stubs,
        "useless_try_catch": useless_try_catch,
        "excess_nesting": excess_nesting,
        "private_defs": private_defs,
        "stripped_code": stripped_all,
    }


def _scan_python_suppressions(rel_path: str, text: str) -> list[dict[str, Any]]:
    """Scan Python source for `# noqa`, `# type: ignore`, `# pyright: ignore`, `# ruff: noqa`, `# mypy: ignore-errors` outside string literals."""
    import io
    import tokenize

    suppressions: list[dict[str, Any]] = []
    code_lines: set[int] = set()
    comment_tokens: list[tuple[int, str]] = []

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return suppressions

    for tok in tokens:
        tok_type = tok.type
        start_line = tok.start[0]
        if tok_type == tokenize.COMMENT:
            comment_tokens.append((start_line, tok.string))
        elif tok_type not in (
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.ENCODING,
            tokenize.ENDMARKER,
            tokenize.STRING,
        ):
            code_lines.add(start_line)

    # LOCAL PATCH linear-source-scan-v1: the rule list class already holds
    # whitespace, so a separate leading `\s*` only split the same blanks.
    inline_re = re.compile(
        r"^#\s*(noqa(?::[A-Za-z0-9_,\s-]+)?|type:\s*ignore(?:\[[^\]]*\])?|pyright:\s*ignore(?:\[[^\]]*\])?|ruff:\s*noqa(?::[A-Za-z0-9_,\s-]+)?|flake8:\s*noqa|mypy:\s*ignore-errors)\b",
        flags=re.IGNORECASE,
    )
    file_level_re = re.compile(
        r"^#\s*(ruff:\s*noqa(?::[A-Za-z0-9_,\s-]+)?|flake8:\s*noqa|mypy:\s*ignore-errors|pyright:\s*ignore|type:\s*ignore)\b",
        flags=re.IGNORECASE,
    )

    for line_no, raw_comment in comment_tokens:
        c_str = raw_comment.strip()
        if line_no in code_lines:
            m = inline_re.match(c_str)
            if m:
                suppressions.append({
                    "path": rel_path,
                    "line": line_no,
                    "kind": m.group(1).split(":")[0].strip().lower(),
                    "rule": m.group(1).strip(),
                })
        else:
            m_file = file_level_re.match(c_str)
            if m_file:
                suppressions.append({
                    "path": rel_path,
                    "line": line_no,
                    "kind": m_file.group(1).split(":")[0].strip().lower(),
                    "rule": m_file.group(1).strip(),
                })

    return suppressions


def _is_stub_body_py(body: list[ast.stmt]) -> bool:
    """Return True if a Python function body (after optional docstring) is solely `pass`, `...`, or `raise NotImplementedError`."""
    stmts = list(body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if len(stmts) != 1:
        return False
    only = stmts[0]
    if isinstance(only, ast.Pass):
        return True
    if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) and only.value.value is Ellipsis:
        return True
    return False


def _scan_python_imports_and_constructs(
    rel_path: str,
    text: str,
    *,
    local_py_modules: set[str],
    max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH,
) -> dict[str, Any]:
    """Scan a Python source file via `ast` and `tokenize` for imports, suppressions, stubs, useless try/except, and nesting."""
    suppressions = _scan_python_suppressions(rel_path, text)
    is_test_file = (
        rel_path.startswith(("tests/", "test/"))
        or "/tests/" in rel_path
        or Path(rel_path).name.startswith("test_")
        or Path(rel_path).name.endswith("_test.py")
    )

    try:
        tree = ast.parse(text, filename=rel_path)
    except SyntaxError as exc:
        return {
            "syntax_error": f"{exc.msg} (line {exc.lineno})",
            "imports": [],
            "suppressions": suppressions,
            "stubs": [],
            "useless_try_catch": [],
            "excess_nesting": None,
            "private_defs": [],
            "referenced_names": set(),
        }

    imports: list[dict[str, Any]] = []
    stubs: list[dict[str, Any]] = []
    useless_try_catch: list[dict[str, Any]] = []
    private_defs: list[tuple[str, int]] = []
    referenced_names: set[str] = set()

    top_level_nodes = set(tree.body)

    # Walk AST for imports, stubs, useless try/except, nesting, and name references
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            referenced_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced_names.add(node.attr)

        # Dynamic import calls: `__import__(...)` or `importlib.import_module(...)`
        if isinstance(node, ast.Call):
            func = node.func
            is_dyn = (
                (isinstance(func, ast.Name) and func.id in ("__import__", "import_module"))
                or (isinstance(func, ast.Attribute) and func.attr == "import_module")
            )
            if is_dyn:
                imports.append({
                    "line": getattr(node, "lineno", 1),
                    "raw": ast.unparse(node) if hasattr(ast, "unparse") else "dynamic_import",
                    "target": "__import__",
                    "kind": "dynamic_import",
                })

        # `raise NotImplementedError`
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc_node = node.exc
            exc_name = ""
            if isinstance(exc_node, ast.Name):
                exc_name = exc_node.id
            elif isinstance(exc_node, ast.Call) and isinstance(exc_node.func, ast.Name):
                exc_name = exc_node.func.id
            if exc_name == "NotImplementedError":
                stubs.append({
                    "path": rel_path,
                    "line": getattr(node, "lineno", 1),
                    "kind": "NotImplementedError",
                })

        # Useless try/except (`except ...: pass` or bare `except ...: raise`)
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if len(handler.body) == 1:
                    stmt = handler.body[0]
                    if isinstance(stmt, ast.Pass) or (
                        isinstance(stmt, ast.Raise) and stmt.exc is None and stmt.cause is None
                    ):
                        useless_try_catch.append({
                            "path": rel_path,
                            "line": getattr(handler, "lineno", getattr(node, "lineno", 1)),
                            "kind": "pass_or_bare_rethrow_except",
                        })

        if isinstance(node, ast.Import):
            is_top = node in top_level_nodes
            for alias in node.names:
                top_mod = (alias.name or "").split(".")[0]
                if not top_mod:
                    continue
                if top_mod in _PYTHON_STDLIB_MODULES or top_mod in local_py_modules:
                    kind = "builtin_or_local"
                elif not is_top or is_test_file:
                    kind = "conditional_or_dev_scope"
                else:
                    kind = "external"
                imports.append({
                    "line": getattr(node, "lineno", 1),
                    "raw": f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
                    "target": top_mod,
                    "alias": alias.asname,
                    "kind": kind,
                })

        elif isinstance(node, ast.ImportFrom):
            is_top = node in top_level_nodes
            level = int(node.level or 0)
            if level > 0:
                imports.append({
                    "line": getattr(node, "lineno", 1),
                    "raw": f"from {'.' * level}{node.module or ''} import ...",
                    "target": f"{'.' * level}{node.module or ''}",
                    "kind": "builtin_or_local",
                })
            else:
                top_mod = (node.module or "").split(".")[0]
                if not top_mod:
                    continue
                if top_mod in _PYTHON_STDLIB_MODULES or top_mod in local_py_modules:
                    kind = "builtin_or_local"
                elif not is_top or is_test_file:
                    kind = "conditional_or_dev_scope"
                else:
                    kind = "external"
                imports.append({
                    "line": getattr(node, "lineno", 1),
                    "raw": f"from {node.module} import ...",
                    "target": top_mod,
                    "kind": kind,
                })

    # Inspect classes and functions for stub bodies, private defs, and control-flow nesting depth
    protocol_or_abc_classes: set[ast.ClassDef] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                b_name = base.id if isinstance(base, ast.Name) else (base.attr if isinstance(base, ast.Attribute) else "")
                if b_name in ("Protocol", "ABC"):
                    protocol_or_abc_classes.add(node)

    methods_in_protocols: set[ast.AST] = set()
    for cls_node in protocol_or_abc_classes:
        for item in cls_node.body:
            methods_in_protocols.add(item)

    max_observed_nesting = 0
    max_nesting_line = 1

    def _measure_nesting(stmts: list[ast.stmt], depth: int) -> None:
        nonlocal max_observed_nesting, max_nesting_line
        for st in stmts:
            if isinstance(st, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Match)):
                new_d = depth + 1
                if new_d > max_observed_nesting:
                    max_observed_nesting = new_d
                    max_nesting_line = getattr(st, "lineno", 1)
                for child_field in ("body", "orelse", "finalbody"):
                    child_stmts = getattr(st, child_field, None)
                    if isinstance(child_stmts, list):
                        _measure_nesting(child_stmts, new_d)
                if isinstance(st, ast.Try):
                    for h in st.handlers:
                        _measure_nesting(h.body, new_d)
                elif isinstance(st, ast.Match):
                    for c in st.cases:
                        _measure_nesting(c.body, new_d)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_") and not node.name.startswith("__"):
                private_defs.append((node.name, getattr(node, "lineno", 1)))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _measure_nesting(node.body, 0)
            if node in methods_in_protocols:
                continue
            has_abstract_dec = any(
                (isinstance(d, ast.Name) and "abstract" in d.id)
                or (isinstance(d, ast.Attribute) and "abstract" in d.attr)
                for d in node.decorator_list
            )
            if not has_abstract_dec and _is_stub_body_py(node.body):
                stubs.append({
                    "path": rel_path,
                    "line": getattr(node, "lineno", 1),
                    "kind": f"stub_function:{node.name}",
                })

    excess_nesting = (
        {"path": rel_path, "line": max_nesting_line, "depth": max_observed_nesting}
        if max_observed_nesting > max_nesting_depth
        else None
    )

    return {
        "syntax_error": None,
        "imports": imports,
        "suppressions": suppressions,
        "stubs": stubs,
        "useless_try_catch": useless_try_catch,
        "excess_nesting": excess_nesting,
        "private_defs": private_defs,
        "referenced_names": referenced_names,
    }


def count_source_suppressions(
    files: Mapping[str, Any],
    *,
    ecosystem: str,
) -> dict[str, Any]:
    """Count lint/type suppressions across source files for `ecosystem`, excluding comments and strings (§5, §11)."""
    norm_files, cov, _ = _normalize_file_map(files)
    occurrences: list[dict[str, Any]] = []

    for rel_path, meta in sorted(norm_files.items()):
        text = _decode_utf8(meta)
        if text is None:
            continue
        if ecosystem == "rust" and rel_path.endswith(".rs"):
            res = _scan_rust_imports_and_constructs(
                rel_path, text, local_mods=set(), cargo_renamed_deps=set()
            )
            occurrences.extend(res["suppressions"])
        elif ecosystem == "ts-node" and rel_path.endswith((".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs")):
            res = _scan_ts_imports_and_constructs(rel_path, text)
            occurrences.extend(res["suppressions"])
        elif ecosystem == "python" and rel_path.endswith(".py"):
            occurrences.extend(_scan_python_suppressions(rel_path, text))

    return {
        "coverage": cov,
        "count": len(occurrences),
        "occurrences": occurrences,
    }


def _collect_manifest_context(
    norm_project: Mapping[str, Mapping[str, Any]],
    *,
    ecosystem: str,
    prefix: str | None,
) -> dict[str, Any]:
    """Extract workspace packages, dev dependencies, path aliases, and local module names from project manifests."""
    workspace_packages: set[str] = set()
    dev_packages: set[str] = set()
    cargo_renamed_deps: set[str] = set()
    tsconfig_path_prefixes: list[str] = []
    local_rust_mods: set[str] = set()
    local_py_modules: set[str] = set()

    prefix_kebab = prefix.replace("_", "-") if prefix else None
    prefix_snake = prefix.replace("-", "_") if prefix else None

    for rel_path, meta in sorted(norm_project.items()):
        name = PurePosixPath(rel_path).name
        if ecosystem == "rust":
            if rel_path.endswith(".rs") and name not in ("lib.rs", "main.rs", "mod.rs"):
                local_rust_mods.add(name[:-3])
            elif name == "mod.rs":
                parts = PurePosixPath(rel_path).parts
                if len(parts) >= 2:
                    local_rust_mods.add(parts[-2])
            elif name == "Cargo.toml":
                txt = _decode_utf8(meta)
                if txt:
                    try:
                        cdata = tomllib.loads(txt)
                    except ValueError:
                        cdata = {}
                    pkg_sec = cdata.get("package")
                    if isinstance(pkg_sec, Mapping) and pkg_sec.get("name"):
                        workspace_packages.add(str(pkg_sec["name"]).strip())
                    ws_sec = cdata.get("workspace")
                    if isinstance(ws_sec, Mapping):
                        ws_deps = ws_sec.get("dependencies")
                        if isinstance(ws_deps, Mapping):
                            for dep_k, dep_v in ws_deps.items():
                                if isinstance(dep_v, Mapping):
                                    if "path" in dep_v:
                                        workspace_packages.add(str(dep_k).strip())
                                    if "package" in dep_v:
                                        cargo_renamed_deps.add(_norm_rust_crate(str(dep_k)))
                    for dep_sec_name in ("dependencies", "dev-dependencies", "build-dependencies"):
                        dep_sec = cdata.get(dep_sec_name)
                        if isinstance(dep_sec, Mapping):
                            for dep_k, dep_v in dep_sec.items():
                                if dep_sec_name == "dev-dependencies":
                                    dev_packages.add(str(dep_k).strip())
                                if isinstance(dep_v, Mapping):
                                    if "path" in dep_v:
                                        workspace_packages.add(str(dep_k).strip())
                                    if "package" in dep_v:
                                        cargo_renamed_deps.add(_norm_rust_crate(str(dep_k)))

        elif ecosystem == "ts-node":
            if name == "package.json":
                txt = _decode_utf8(meta)
                if txt:
                    try:
                        pdata = json.loads(txt)
                    except ValueError:
                        pdata = {}
                    if isinstance(pdata, Mapping):
                        pkg_name = str(pdata.get("name") or "").strip()
                        if pkg_name and rel_path != "package.json":
                            workspace_packages.add(pkg_name)
                        for dep_field in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
                            dmap = pdata.get(dep_field)
                            if isinstance(dmap, Mapping):
                                for dk, dv in dmap.items():
                                    dk_s = str(dk).strip()
                                    dv_s = str(dv or "").strip()
                                    if dv_s.startswith(("workspace:", "link:", "file:")):
                                        workspace_packages.add(dk_s)
                                    elif dep_field == "devDependencies":
                                        dev_packages.add(dk_s)
            elif name in ("tsconfig.json", "tsconfig.base.json"):
                txt = _decode_utf8(meta)
                if txt:
                    try:
                        # Strip // and /* */ comments for JSONC tolerance
                        clean_json = _strip_ts_comments_keep_strings(txt)
                        tdata = json.loads(clean_json)
                    except ValueError:
                        tdata = {}
                    if isinstance(tdata, Mapping):
                        co = tdata.get("compilerOptions")
                        if isinstance(co, Mapping) and isinstance(co.get("paths"), Mapping):
                            for alias_pat in co["paths"]:
                                pfx = str(alias_pat).rstrip("*")
                                if pfx:
                                    tsconfig_path_prefixes.append(pfx)

        elif ecosystem == "python":
            if rel_path.endswith(".py"):
                parts = PurePosixPath(rel_path).parts
                if name == "__init__.py" and len(parts) >= 2:
                    pkg_dir = parts[-2]
                    # If top-level package under `src/<pkg>/__init__.py`, treat `<pkg>` as workspace package if matching prefix
                    if len(parts) >= 3 and parts[-3] == "src":
                        if (prefix_snake and pkg_dir.startswith(f"{prefix_snake}_")) or pkg_dir.startswith("tmpl_prefix_"):
                            workspace_packages.add(pkg_dir)
                        else:
                            local_py_modules.add(pkg_dir)
                elif name != "__init__.py":
                    # Only sibling modules that aren't workspace package roots
                    local_py_modules.add(name[:-3])
            elif name == "pyproject.toml":
                txt = _decode_utf8(meta)
                if txt:
                    try:
                        pydata = tomllib.loads(txt)
                    except ValueError:
                        pydata = {}
                    proj_sec = pydata.get("project")
                    if isinstance(proj_sec, Mapping) and proj_sec.get("name"):
                        workspace_packages.add(str(proj_sec["name"]).strip())
                    dep_groups = pydata.get("dependency-groups")
                    if isinstance(dep_groups, Mapping):
                        for grp_list in dep_groups.values():
                            if isinstance(grp_list, list):
                                for item in grp_list:
                                    if isinstance(item, str):
                                        dname = re.split(r"[<>=!~;\s\[]", item, maxsplit=1)[0].strip()
                                        if dname:
                                            dev_packages.add(dname)
                    tool_sec = pydata.get("tool")
                    if isinstance(tool_sec, Mapping) and isinstance(tool_sec.get("uv"), Mapping):
                        uv_sources = tool_sec["uv"].get("sources")
                        if isinstance(uv_sources, Mapping):
                            for sk, sv in uv_sources.items():
                                if isinstance(sv, Mapping) and sv.get("workspace") is True:
                                    workspace_packages.add(str(sk).strip())

    return {
        "workspace_packages": workspace_packages,
        "dev_packages": dev_packages,
        "cargo_renamed_deps": cargo_renamed_deps,
        "tsconfig_path_prefixes": tsconfig_path_prefixes,
        "local_rust_mods": local_rust_mods,
        "local_py_modules": local_py_modules,
        "prefix_kebab": prefix_kebab,
        "prefix_snake": prefix_snake,
    }


def audit_static_code(
    provenance: Mapping[str, Any] | Path | str | None = None,
    *,
    project_id: str | None = None,
    template_id: str | None = None,
    prefix: str | None = None,
    approved_deps: Mapping[str, Sequence[str]] | Sequence[str] | None = None,
    project_files: Mapping[str, Any] | None = None,
    project_root: Path | str | None = None,
    template_spec: Mapping[str, Any] | None = None,
    template_files: Mapping[str, Any] | None = None,
    template_root: Path | str | None = None,
    baseline_suppressions: int | None = None,
    registered: bool = True,
    template_has_guardrails: bool = True,
    max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_entries: int = DEFAULT_MAX_DIR_ENTRIES,
) -> dict[str, Any]:
    """Audit a project for lockfile catalogue compliance, top-level import mapping, suppressions, and stubs (§5, §11, §12, §13.3).

    Never executes project code, package managers, or external tools.
    """
    if isinstance(provenance, (Path, str)):
        if project_root is None:
            project_root = provenance
        prov_map: Mapping[str, Any] = {}
    elif isinstance(provenance, Mapping):
        prov_map = provenance
    else:
        prov_map = {}

    if "provenance" in prov_map and isinstance(prov_map.get("provenance"), Mapping):
        outer = prov_map
        prov_map = outer["provenance"]
        if project_id is None and outer.get("project_id") is not None:
            project_id = str(outer["project_id"])
        if template_id is None and outer.get("template_id") is not None:
            template_id = str(outer["template_id"])
        if prefix is None and outer.get("prefix") is not None:
            prefix = str(outer["prefix"])
        if approved_deps is None and outer.get("approved_deps") is not None:
            approved_deps = outer["approved_deps"]
        if project_files is None and isinstance(outer.get("project_files"), Mapping):
            project_files = outer["project_files"]
        if project_root is None and outer.get("project_root") is not None:
            project_root = outer["project_root"]
        if template_spec is None and isinstance(outer.get("template_spec"), Mapping):
            template_spec = outer["template_spec"]
        if template_files is None and isinstance(outer.get("template_files"), Mapping):
            template_files = outer["template_files"]
        if template_root is None and outer.get("template_root") is not None:
            template_root = outer["template_root"]
        if baseline_suppressions is None and outer.get("baseline_suppressions") is not None:
            baseline_suppressions = int(outer["baseline_suppressions"])
        if "registered" in outer:
            registered = bool(outer["registered"])
        if "template_has_guardrails" in outer:
            template_has_guardrails = bool(outer["template_has_guardrails"])

    if "registered" in prov_map and registered is True:
        registered = bool(prov_map["registered"])
    if prov_map.get("not_set_up_by_plugin") is True:
        registered = False

    resolved_project_id = str(
        project_id
        or prov_map.get("canonical_path")
        or prov_map.get("path")
        or (str(project_root) if project_root is not None else "")
        or "unknown-project"
    ).strip()

    raw_tmpl_id = (
        template_id
        or prov_map.get("template_id")
        or (template_spec.get("id") if isinstance(template_spec, Mapping) else None)
    )
    resolved_template_id = str(raw_tmpl_id).strip() if raw_tmpl_id else None

    resolved_prefix = str(
        prefix
        or prov_map.get("prefix")
        or prov_map.get("slug")
        or ""
    ).strip() or None

    findings: list[dict[str, Any]] = []

    # LOCAL PATCH golden-template-registry-v1: load golden template registry and ecosystem map at run time after preflight.
    from ..contract import resolve_runtime_golden_registry

    registry = resolve_runtime_golden_registry()
    runtime_specs: Mapping[str, Any] = registry["specs"]
    discovered_ids: frozenset[str] = registry["discovered_ids"]
    supported_ids: frozenset[str] = discovered_ids or GOLDEN_TEMPLATE_IDS
    runtime_eco_map: dict[str, str] = dict(TEMPLATE_TO_ECOSYSTEM)
    for sid, spec_obj in runtime_specs.items():
        inferred_eco = _infer_template_ecosystem(spec_obj, sid)
        if inferred_eco:
            runtime_eco_map[sid] = inferred_eco

    if registered and resolved_template_id:
        unverified_reason: str | None = None
        if not registry["available"]:
            unverified_reason = str(registry.get("reason") or "templates_registry_unavailable")
        elif resolved_template_id in registry["excluded_ids"]:
            unverified_reason = "template_manifest_excluded_by_credential_policy"
        elif resolved_template_id in registry["invalid_ids"]:
            unverified_reason = f"template_manifest_invalid:{registry['invalid_ids'][resolved_template_id]}"
        if unverified_reason is not None:
            fallback_eco = (
                runtime_eco_map.get(resolved_template_id)
                or _infer_template_ecosystem(template_spec, resolved_template_id)
                or resolved_template_id.removesuffix("-golden")
            )
            findings.append(
                _make_finding(
                    rule_id="static_code.approved_deps_unavailable",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[resolved_project_id],
                    source_paths=[resolved_project_id],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": resolved_template_id,
                        "ecosystem": fallback_eco,
                        "reason": unverified_reason,
                    },
                    consequence=(
                        f"Golden template registry metadata for {resolved_template_id!r} could not be verified ({unverified_reason})."
                    ),
                    limitations="Unavailable or invalid template registry metadata is never treated as unsupported scope.",
                )
            )
            return _make_envelope(
                findings=findings,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                extra={
                    "rule_version": RULE_VERSION,
                    "project_id": resolved_project_id,
                    "template_id": resolved_template_id,
                    "ecosystem": fallback_eco,
                    "summary": {
                        "included": True,
                        "reason": unverified_reason,
                    },
                },
            )

    if template_spec is None and resolved_template_id and resolved_template_id in runtime_specs:
        loaded_spec = runtime_specs[resolved_template_id]
        template_spec = {
            "id": loaded_spec.id,
            "placeholder": loaded_spec.placeholder,
            "substitute_in": list(loaded_spec.substitute_in),
            "locked": list(loaded_spec.locked),
            "approved_deps": {k: list(v) for k, v in loaded_spec.approved_deps.items()},
            "languages": list(loaded_spec.languages),
        }
        if template_files is None and template_root is None and len(loaded_spec.repos) == 1:
            template_root = loaded_spec.root / loaded_spec.repos[0].name

    # §5, §13.3: Projects outside the golden template registry or unregistered repos -> not_included
    if not registered or not resolved_template_id or resolved_template_id not in supported_ids:
        reason = (
            "unregistered_repository"
            if not registered
            else f"non_golden_template:{resolved_template_id or 'none'}"
        )
        findings.append(
            _make_finding(
                rule_id="static_code.not_included",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_NOT_INCLUDED,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "registered": registered,
                    "template_id": resolved_template_id,
                    "reason": reason,
                    "supported_templates": sorted(supported_ids),
                },
                # LOCAL PATCH golden-template-registry-v1: reflect full golden template registry in diagnostics.
                consequence=(
                    "Not set up by the plugin; static code and dependency checks are not included."
                    if not registered
                    else f"Template {resolved_template_id or 'none'!r} is outside the golden template registry; static code checks are not included."
                ),
                limitations=f"Only registered golden templates ({', '.join(sorted(supported_ids))}) participate in template/static-code checks.",
            )
        )
        return _make_envelope(
            findings=findings,
            coverage=COVERAGE_NOT_INCLUDED,
            extra={
                "rule_version": RULE_VERSION,
                "project_id": resolved_project_id,
                "template_id": resolved_template_id,
                "ecosystem": None,
                "summary": {
                    "included": False,
                    "reason": reason,
                },
            },
        )

    # LOCAL PATCH golden-template-registry-v1: derive ecosystem from run-time registry metadata.
    ecosystem = (
        _infer_template_ecosystem(runtime_specs.get(resolved_template_id), resolved_template_id)
        or _infer_template_ecosystem(template_spec, resolved_template_id)
        or runtime_eco_map.get(resolved_template_id)
        or resolved_template_id.removesuffix("-golden")
    )

    if not template_has_guardrails or (
        isinstance(template_spec, Mapping)
        and "approved_deps" in template_spec
        and not template_spec.get("approved_deps")
    ):
        findings.append(
            _make_finding(
                rule_id="static_code.not_included",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_NOT_INCLUDED,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": resolved_template_id,
                    "reason": "template_guardrails_not_configured",
                },
                consequence=f"Template {resolved_template_id!r} does not configure approved_deps yet; static dependency checks are not included.",
                limitations="Static dependency checks require approved_deps in template.yaml.",
            )
        )
        return _make_envelope(
            findings=findings,
            coverage=COVERAGE_NOT_INCLUDED,
            extra={
                "rule_version": RULE_VERSION,
                "project_id": resolved_project_id,
                "template_id": resolved_template_id,
                "ecosystem": ecosystem,
                "summary": {
                    "included": False,
                    "reason": "template_guardrails_not_configured",
                },
            },
        )

    lockfile_name = ECOSYSTEM_LOCKFILE.get(ecosystem, "Cargo.lock")

    # Normalize or read project_files
    if project_files is not None:
        norm_project, proj_cov, proj_issues = _normalize_file_map(
            project_files, max_file_bytes=max_file_bytes
        )
    elif project_root is not None:
        norm_project, proj_cov, proj_issues = _safe_walk_directory(
            project_root, max_file_bytes=max_file_bytes, max_entries=max_entries
        )
    else:
        norm_project, proj_cov, proj_issues = {}, COVERAGE_COULD_NOT_VERIFY, [
            {"path": resolved_project_id, "reason": "project_files_not_provided"}
        ]

    overall_coverage = proj_cov
    for issue in proj_issues:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="static_code.unverified_file",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[issue["path"]],
                evidence={
                    "project_id": resolved_project_id,
                    "path": issue["path"],
                    "reason": issue["reason"],
                },
                consequence=f"File {issue['path']!r} could not be safely read as a stable regular file.",
                limitations="Non-regular files, symlinks, unreadable paths, size-bound overflows, and mid-read changes are never treated as verified.",
            )
        )

    # Resolve approved_deps allowlist
    approved_list = _resolve_approved_deps_for_ecosystem(
        ecosystem, approved_deps, template_spec
    )
    if approved_list is None:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="static_code.approved_deps_unavailable",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": resolved_template_id,
                    "ecosystem": ecosystem,
                },
                consequence=f"Approved dependency catalogue (approved_deps) for {resolved_template_id!r} was not provided.",
                limitations="Cannot verify whether lockfile packages belong to the template's approved catalogue.",
            )
        )

    # LOCAL PATCH golden-template-registry-v1: parse ecosystem lockfile(s) across all seven golden templates.
    lock_meta = norm_project.get(lockfile_name)
    lock_text = _decode_utf8(lock_meta) if lock_meta is not None else None
    lock_parsed: dict[str, Any] | None = None

    if ecosystem in ("csharp", "dotnet"):
        sub_lock_paths = sorted(
            rel for rel in norm_project if rel == "packages.lock.json" or rel.endswith("/packages.lock.json")
        )
        if sub_lock_paths:
            merged_ext: dict[str, set[str]] = {}
            merged_ws: set[str] = set()
            parse_failed = False
            for sub_rel in sub_lock_paths:
                sub_meta = norm_project[sub_rel]
                sub_txt = _decode_utf8(sub_meta)
                if sub_txt is None:
                    overall_coverage = COVERAGE_COULD_NOT_VERIFY
                    findings.append(
                        _make_finding(
                            rule_id="static_code.lockfile_missing_or_invalid",
                            classification=CLASSIFICATION_INFO,
                            coverage=COVERAGE_COULD_NOT_VERIFY,
                            affected_identities=[resolved_project_id],
                            source_paths=[sub_rel],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": resolved_template_id,
                                "lockfile": sub_rel,
                                "reason": "unreadable",
                            },
                            consequence=f"Expected lockfile {sub_rel!r} is missing or unreadable; dependencies could not be verified.",
                            limitations="Top-level imports cannot be mapped to locked versions without a readable lockfile.",
                        )
                    )
                    parse_failed = True
                    continue
                try:
                    sub_parsed = parse_nuget_lock(sub_txt)
                    for k, vers in sub_parsed["external_packages"].items():
                        merged_ext.setdefault(k, set()).update(vers)
                    merged_ws.update(sub_parsed.get("workspace_packages") or ())
                except ValueError as exc:
                    overall_coverage = COVERAGE_COULD_NOT_VERIFY
                    findings.append(
                        _make_finding(
                            rule_id="static_code.lockfile_missing_or_invalid",
                            classification=CLASSIFICATION_INFO,
                            coverage=COVERAGE_COULD_NOT_VERIFY,
                            affected_identities=[resolved_project_id],
                            source_paths=[sub_rel],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": resolved_template_id,
                                "lockfile": sub_rel,
                                "reason": f"parse_error:{exc}",
                            },
                            consequence=f"Lockfile {sub_rel!r} could not be parsed: {exc}",
                            limitations="Malformed lockfiles cannot verify dependency locking.",
                        )
                    )
                    parse_failed = True
            if not parse_failed:
                lock_parsed = {
                    "external_packages": {k: sorted(v) for k, v in sorted(merged_ext.items())},
                    "workspace_packages": sorted(merged_ws),
                    "dev_packages": [],
                }
        else:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="static_code.lockfile_missing_or_invalid",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[resolved_project_id],
                    source_paths=[lockfile_name],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": resolved_template_id,
                        "lockfile": lockfile_name,
                        "reason": "missing",
                    },
                    consequence=f"Expected lockfile {lockfile_name!r} is missing or unreadable; dependencies could not be verified.",
                    limitations="Top-level imports cannot be mapped to locked versions without a readable lockfile.",
                )
            )
    elif ecosystem == "cpp":
        # LOCAL PATCH golden-template-registry-v1: aggregate all root and nested CMakeLists.txt and *.cmake files.
        sub_cmake_paths = sorted(
            rel
            for rel in norm_project
            if rel == "CMakeLists.txt" or rel.endswith("/CMakeLists.txt") or rel.endswith(".cmake")
        )
        parse_failed = False
        if "CMakeLists.txt" not in norm_project:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="static_code.lockfile_missing_or_invalid",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[resolved_project_id],
                    source_paths=[lockfile_name],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": resolved_template_id,
                        "lockfile": lockfile_name,
                        "reason": "missing",
                    },
                    consequence=f"Expected lockfile {lockfile_name!r} is missing or unreadable; dependencies could not be verified.",
                    limitations="Top-level imports cannot be mapped to locked versions without a readable lockfile.",
                )
            )
            parse_failed = True
        if sub_cmake_paths:
            merged_ext: dict[str, set[str]] = {}
            merged_ws: set[str] = set()
            for sub_rel in sub_cmake_paths:
                sub_meta = norm_project[sub_rel]
                sub_txt = _decode_utf8(sub_meta)
                if sub_txt is None:
                    overall_coverage = COVERAGE_COULD_NOT_VERIFY
                    findings.append(
                        _make_finding(
                            rule_id="static_code.lockfile_missing_or_invalid",
                            classification=CLASSIFICATION_INFO,
                            coverage=COVERAGE_COULD_NOT_VERIFY,
                            affected_identities=[resolved_project_id],
                            source_paths=[sub_rel],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": resolved_template_id,
                                "lockfile": sub_rel,
                                "reason": "unreadable",
                            },
                            consequence=f"Expected lockfile {sub_rel!r} is missing or unreadable; dependencies could not be verified.",
                            limitations="Top-level imports cannot be mapped to locked versions without a readable lockfile.",
                        )
                    )
                    parse_failed = True
                    continue
                try:
                    sub_parsed = parse_cmake_lock(sub_txt)
                    for k, vers in sub_parsed["external_packages"].items():
                        merged_ext.setdefault(k, set()).update(vers)
                    merged_ws.update(sub_parsed.get("workspace_packages") or ())
                except ValueError as exc:
                    overall_coverage = COVERAGE_COULD_NOT_VERIFY
                    findings.append(
                        _make_finding(
                            rule_id="static_code.lockfile_missing_or_invalid",
                            classification=CLASSIFICATION_INFO,
                            coverage=COVERAGE_COULD_NOT_VERIFY,
                            affected_identities=[resolved_project_id],
                            source_paths=[sub_rel],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": resolved_template_id,
                                "lockfile": sub_rel,
                                "reason": f"parse_error:{exc}",
                            },
                            consequence=f"Lockfile {sub_rel!r} could not be parsed: {exc}",
                            limitations="Malformed lockfiles cannot verify dependency locking.",
                        )
                    )
                    parse_failed = True
            if not parse_failed:
                lock_parsed = {
                    "external_packages": {k: sorted(v) for k, v in sorted(merged_ext.items())},
                    "workspace_packages": sorted(merged_ws),
                    "dev_packages": [],
                }
    elif lock_meta is None or lock_text is None:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="static_code.lockfile_missing_or_invalid",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[lockfile_name],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": resolved_template_id,
                    "lockfile": lockfile_name,
                    "reason": "missing" if lock_meta is None else "unreadable",
                },
                consequence=f"Expected lockfile {lockfile_name!r} is missing or unreadable; dependencies could not be verified.",
                limitations="Top-level imports cannot be mapped to locked versions without a readable lockfile.",
            )
        )
    else:
        try:
            if ecosystem == "rust":
                lock_parsed = parse_cargo_lock(lock_text)
            elif ecosystem == "ts-node":
                lock_parsed = parse_pnpm_lock(lock_text)
            elif ecosystem == "python":
                lock_parsed = parse_uv_lock(lock_text)
            elif ecosystem == "go":
                lock_parsed = parse_go_sum(lock_text)
            elif ecosystem == "cpp":
                lock_parsed = parse_cmake_lock(lock_text)
            elif ecosystem in ("csharp", "dotnet"):
                lock_parsed = parse_nuget_lock(lock_text)
            else:
                lock_parsed = {"external_packages": {}, "workspace_packages": [], "dev_packages": []}
        except ValueError as exc:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="static_code.lockfile_missing_or_invalid",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[resolved_project_id],
                    source_paths=[lockfile_name],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": resolved_template_id,
                        "lockfile": lockfile_name,
                        "reason": f"parse_error:{exc}",
                    },
                    consequence=f"Lockfile {lockfile_name!r} could not be parsed: {exc}",
                    limitations="Malformed lockfiles cannot verify dependency locking.",
                )
            )

    manifest_ctx = _collect_manifest_context(
        norm_project, ecosystem=ecosystem, prefix=resolved_prefix
    )

    external_lock_pkgs: dict[str, list[str]] = (
        dict(lock_parsed["external_packages"]) if lock_parsed is not None else {}
    )
    workspace_pkgs: set[str] = set(manifest_ctx["workspace_packages"])
    dev_pkgs: set[str] = set(manifest_ctx["dev_packages"])
    if lock_parsed is not None:
        workspace_pkgs.update(lock_parsed.get("workspace_packages") or ())
        dev_pkgs.update(lock_parsed.get("dev_packages") or ())

    # Remove any workspace package detected via manifests from external_lock_pkgs
    for ws_p in list(workspace_pkgs):
        external_lock_pkgs.pop(ws_p, None)

    # Check lock entries against `approved_deps` catalogue (§5, §13.3: Lock entry outside the catalogue -> Warning)
    unapproved_lock_entries: list[str] = []
    if lock_parsed is not None and approved_list is not None:
        if ecosystem == "python":
            approved_norm = {_norm_py_pkg(x) for x in approved_list}
            for pkg_name, versions in sorted(external_lock_pkgs.items()):
                if _norm_py_pkg(pkg_name) not in approved_norm:
                    unapproved_lock_entries.append(pkg_name)
                    findings.append(
                        _make_finding(
                            rule_id="static_code.unapproved_dependency",
                            classification=CLASSIFICATION_WARNING,
                            coverage=COVERAGE_VERIFIED,
                            affected_identities=[resolved_project_id],
                            source_paths=[lockfile_name],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": resolved_template_id,
                                "ecosystem": ecosystem,
                                "lockfile": lockfile_name,
                                "package": pkg_name,
                                "versions": versions,
                            },
                            consequence=(
                                f"Lockfile {lockfile_name!r} contains package {pkg_name!r} "
                                f"outside {resolved_template_id!r}'s approved_deps catalogue."
                            ),
                            limitations="Compared against the versioned approved_deps list in template.yaml.",
                        )
                    )
        else:
            approved_exact = set(approved_list)
            for pkg_name, versions in sorted(external_lock_pkgs.items()):
                if pkg_name not in approved_exact:
                    unapproved_lock_entries.append(pkg_name)
                    findings.append(
                        _make_finding(
                            rule_id="static_code.unapproved_dependency",
                            classification=CLASSIFICATION_WARNING,
                            coverage=COVERAGE_VERIFIED,
                            affected_identities=[resolved_project_id],
                            source_paths=[lockfile_name],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": resolved_template_id,
                                "ecosystem": ecosystem,
                                "lockfile": lockfile_name,
                                "package": pkg_name,
                                "versions": versions,
                            },
                            consequence=(
                                f"Lockfile {lockfile_name!r} contains package {pkg_name!r} "
                                f"outside {resolved_template_id!r}'s approved_deps catalogue."
                            ),
                            limitations="Compared against the versioned approved_deps list in template.yaml.",
                        )
                    )

    # Build lookup sets for import -> lock mapping
    if ecosystem == "rust":
        lock_lookup = {_norm_rust_crate(k): k for k in external_lock_pkgs}
        ws_lookup = {_norm_rust_crate(k) for k in workspace_pkgs} | {"xtask"}
        dev_lookup = {_norm_rust_crate(k) for k in dev_pkgs}
    elif ecosystem == "ts-node":
        lock_lookup = {k: k for k in external_lock_pkgs}
        ws_lookup = set(workspace_pkgs)
        dev_lookup = set(dev_pkgs)
    else:
        lock_lookup = {_norm_py_pkg(k): k for k in external_lock_pkgs}
        ws_lookup = {_norm_py_pkg(k) for k in workspace_pkgs} | {"xtask"}
        dev_lookup = {_norm_py_pkg(k) for k in dev_pkgs}

    # Scan source files for imports, suppressions, stubs, useless try/catch, excess nesting, and unreferenced helpers
    all_suppressions: list[dict[str, Any]] = []
    all_stubs: list[dict[str, Any]] = []
    all_useless_try: list[dict[str, Any]] = []
    all_excess_nesting: list[dict[str, Any]] = []
    all_private_defs: list[tuple[str, str, int]] = []
    all_stripped_blobs: list[tuple[str, str]] = []
    all_py_referenced_names: set[str] = set()

    mapped_imports_count = 0
    builtin_imports_count = 0
    missing_lock_imports: list[dict[str, Any]] = []
    unmappable_imports: list[dict[str, Any]] = []

    pfx_snake = manifest_ctx["prefix_snake"]
    pfx_kebab = manifest_ctx["prefix_kebab"]

    for rel_path, meta in sorted(norm_project.items()):
        text = _decode_utf8(meta)
        if text is None:
            continue

        scan_res: dict[str, Any] | None = None
        if ecosystem == "rust" and rel_path.endswith(".rs"):
            scan_res = _scan_rust_imports_and_constructs(
                rel_path,
                text,
                local_mods=manifest_ctx["local_rust_mods"],
                cargo_renamed_deps=manifest_ctx["cargo_renamed_deps"],
                max_nesting_depth=max_nesting_depth,
            )
        elif ecosystem == "ts-node" and rel_path.endswith((".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs")):
            scan_res = _scan_ts_imports_and_constructs(
                rel_path,
                text,
                tsconfig_path_prefixes=manifest_ctx["tsconfig_path_prefixes"],
                max_nesting_depth=max_nesting_depth,
            )
        elif ecosystem == "python" and rel_path.endswith(".py"):
            scan_res = _scan_python_imports_and_constructs(
                rel_path,
                text,
                local_py_modules=manifest_ctx["local_py_modules"],
                max_nesting_depth=max_nesting_depth,
            )
            if scan_res.get("syntax_error"):
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                findings.append(
                    _make_finding(
                        rule_id="static_code.syntax_error",
                        classification=CLASSIFICATION_INFO,
                        coverage=COVERAGE_COULD_NOT_VERIFY,
                        affected_identities=[resolved_project_id],
                        source_paths=[rel_path],
                        evidence={
                            "project_id": resolved_project_id,
                            "path": rel_path,
                            "error": scan_res["syntax_error"],
                        },
                        consequence=f"Source file {rel_path!r} could not be parsed due to a syntax error.",
                        limitations=str(scan_res["syntax_error"]),
                    )
                )
            all_py_referenced_names.update(scan_res.get("referenced_names") or set())

        if scan_res is None:
            continue

        all_suppressions.extend(scan_res["suppressions"])
        all_stubs.extend(scan_res["stubs"])
        all_useless_try.extend(scan_res["useless_try_catch"])
        if scan_res["excess_nesting"] is not None:
            all_excess_nesting.append(scan_res["excess_nesting"])
        for fn_name, fn_line in scan_res.get("private_defs") or ():
            all_private_defs.append((rel_path, fn_name, fn_line))
        if isinstance(scan_res.get("stripped_code"), str):
            all_stripped_blobs.append((rel_path, scan_res["stripped_code"]))

        for imp in scan_res["imports"]:
            imp_kind = imp["kind"]
            target = str(imp["target"])
            line_no = int(imp["line"])

            if imp_kind == "builtin_or_local":
                builtin_imports_count += 1
                continue

            # LOCAL PATCH dev-scope-import-mapping-v1 (ts-node only): a dynamic import of one
            # string literal, and a static import the scanner put in conditional/dev scope, are
            # re-read by their specifier. Built-in and relative modules count as local anywhere;
            # a package goes through the lockfile mapping below when the import is a literal
            # dynamic import or sits in a development-scope file. Computed and URL dynamic
            # imports, aliases, and packages in a block of production source stay unmappable.
            ts_dev_scope = ecosystem == "ts-node" and _ts_dev_scope_file(rel_path)
            if ecosystem == "ts-node" and imp_kind in ("dynamic_import", "conditional_or_dev_scope"):
                if imp_kind == "dynamic_import":
                    ts_spec = _ts_literal_dynamic_specifier(target)
                else:
                    ts_spec = str(imp.get("specifier") or "")
                if ts_spec:
                    ts_cat, ts_norm = _classify_ts_specifier(
                        ts_spec, tsconfig_path_prefixes=manifest_ctx["tsconfig_path_prefixes"]
                    )
                    if ts_cat in ("builtin", "relative"):
                        builtin_imports_count += 1
                        continue
                    if ts_cat == "package" and (imp_kind == "dynamic_import" or ts_dev_scope):
                        imp_kind = "external"
                        target = ts_norm

            if imp_kind in ("dynamic_import", "alias", "unparseable_use", "conditional_or_dev_scope"):
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                unmappable_imports.append({
                    "path": rel_path,
                    "line": line_no,
                    "target": target,
                    "reason": imp_kind,
                    "raw": imp.get("raw", ""),
                })
                continue

            # `imp_kind` is `"external"` or `"extern_crate"` -> check workspace / dev / lockfile mapping
            if ecosystem == "rust":
                norm_t = _norm_rust_crate(target)
                is_ws = (
                    norm_t in ws_lookup
                    or (pfx_snake is not None and norm_t.startswith(f"{pfx_snake}_"))
                    or norm_t.startswith("tmpl_prefix_")
                )
                is_dev = norm_t in dev_lookup
            elif ecosystem == "ts-node":
                norm_t = target
                is_ws = (
                    norm_t in ws_lookup
                    or (pfx_kebab is not None and norm_t.startswith(f"{pfx_kebab}-"))
                    or norm_t.startswith("tmpl-prefix-")
                )
                is_dev = norm_t in dev_lookup
            else:
                norm_t = _norm_py_pkg(target)
                is_ws = (
                    norm_t in ws_lookup
                    or (pfx_snake is not None and norm_t.startswith(f"{pfx_snake}_"))
                    or norm_t.startswith("tmpl_prefix_")
                )
                is_dev = norm_t in dev_lookup

            if is_ws:
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                unmappable_imports.append({
                    "path": rel_path,
                    "line": line_no,
                    "target": target,
                    "reason": "workspace_crate",
                    "raw": imp.get("raw", ""),
                })
                continue

            if is_dev and not ts_dev_scope:
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                unmappable_imports.append({
                    "path": rel_path,
                    "line": line_no,
                    "target": target,
                    "reason": "conditional_or_dev_scope",
                    "raw": imp.get("raw", ""),
                })
                continue

            if lock_parsed is None:
                # Lockfile was missing/invalid; already marked could_not_verify
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                continue

            if norm_t in lock_lookup:
                mapped_imports_count += 1
            else:
                missing_lock_imports.append({
                    "path": rel_path,
                    "line": line_no,
                    "target": target,
                    "raw": imp.get("raw", ""),
                })
                findings.append(
                    _make_finding(
                        rule_id="static_code.import_missing_from_lock",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[resolved_project_id],
                        source_paths=[{"path": rel_path, "start_line": line_no, "end_line": line_no}],
                        evidence={
                            "project_id": resolved_project_id,
                            "template_id": resolved_template_id,
                            "ecosystem": ecosystem,
                            "lockfile": lockfile_name,
                            "path": rel_path,
                            "line": line_no,
                            "imported_target": target,
                            "statement": imp.get("raw", ""),
                        },
                        consequence=(
                            f"Top-level import {target!r} in {rel_path}:{line_no} has no matching entry in {lockfile_name!r}."
                        ),
                        limitations="Lexical top-level import scan compared against lockfile package entries.",
                    )
                )

    for unm in unmappable_imports:
        findings.append(
            _make_finding(
                rule_id="static_code.unmappable_import",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[{"path": unm["path"], "start_line": unm["line"], "end_line": unm["line"]}],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": resolved_template_id,
                    "ecosystem": ecosystem,
                    "path": unm["path"],
                    "line": unm["line"],
                    "target": unm["target"],
                    "reason": unm["reason"],
                    "statement": unm["raw"],
                },
                consequence=(
                    f"Import {unm['target']!r} in {unm['path']}:{unm['line']} uses {unm['reason']} "
                    f"and could not be verified by lexical lockfile mapping."
                ),
                limitations="Dynamic imports, path/package aliases, workspace crates, and conditional/dev scopes cannot be statically mapped to external lock entries.",
            )
        )

    # Compute template baseline suppressions / stubs if template_files or template_root provided
    resolved_baseline_suppressions = baseline_suppressions
    baseline_stub_count = 0
    raw_tmpl_files: Mapping[str, Any] | None = template_files
    if raw_tmpl_files is None and template_root is not None:
        walked_t, _, _ = _safe_walk_directory(
            template_root, max_file_bytes=max_file_bytes, max_entries=max_entries
        )
        raw_tmpl_files = walked_t

    if raw_tmpl_files is not None:
        norm_tmpl, _, _ = _normalize_file_map(raw_tmpl_files, max_file_bytes=max_file_bytes)
        tmpl_sup_count = 0
        for t_rel, t_meta in sorted(norm_tmpl.items()):
            t_txt = _decode_utf8(t_meta)
            if t_txt is None:
                continue
            if ecosystem == "rust" and t_rel.endswith(".rs"):
                t_scan = _scan_rust_imports_and_constructs(
                    t_rel, t_txt, local_mods=set(), cargo_renamed_deps=set()
                )
                tmpl_sup_count += len(t_scan["suppressions"])
                baseline_stub_count += len(t_scan["stubs"])
            elif ecosystem == "ts-node" and t_rel.endswith((".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs")):
                t_scan = _scan_ts_imports_and_constructs(t_rel, t_txt)
                tmpl_sup_count += len(t_scan["suppressions"])
                baseline_stub_count += len(t_scan["stubs"])
            elif ecosystem == "python" and t_rel.endswith(".py"):
                t_scan = _scan_python_imports_and_constructs(t_rel, t_txt, local_py_modules=set())
                tmpl_sup_count += len(t_scan["suppressions"])
                baseline_stub_count += len(t_scan["stubs"])
        if resolved_baseline_suppressions is None:
            resolved_baseline_suppressions = tmpl_sup_count

    if resolved_baseline_suppressions is None:
        resolved_baseline_suppressions = 0

    # Suppressions above substituted template baseline (§5, §11)
    suppression_delta = len(all_suppressions) - resolved_baseline_suppressions
    if suppression_delta > 0:
        findings.append(
            _make_finding(
                rule_id="static_code.suppressions_above_baseline",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_VERIFIED,
                affected_identities=[resolved_project_id],
                source_paths=[
                    {"path": s["path"], "start_line": s["line"], "end_line": s["line"]}
                    for s in all_suppressions
                ],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": resolved_template_id,
                    "ecosystem": ecosystem,
                    "project_suppressions": len(all_suppressions),
                    "baseline_suppressions": resolved_baseline_suppressions,
                    "delta": suppression_delta,
                    "occurrences": all_suppressions[:50],
                },
                consequence=(
                    f"Project contains {len(all_suppressions)} lint/type suppression(s) "
                    f"({suppression_delta} above the template baseline of {resolved_baseline_suppressions})."
                ),
                limitations="Counts code-level suppressions excluding prose comments and string literals.",
            )
        )

    # Stubs above baseline (§5)
    if len(all_stubs) > baseline_stub_count:
        for st_item in all_stubs:
            findings.append(
                _make_finding(
                    rule_id="static_code.stub_detected",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[resolved_project_id],
                    source_paths=[
                        {"path": st_item["path"], "start_line": st_item["line"], "end_line": st_item["line"]}
                    ],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": resolved_template_id,
                        "ecosystem": ecosystem,
                        "path": st_item["path"],
                        "line": st_item["line"],
                        "stub_kind": st_item["kind"],
                    },
                    consequence=(
                        f"Mechanical stub marker ({st_item['kind']}) detected at {st_item['path']}:{st_item['line']}; "
                        "review suggested to confirm whether implementation is incomplete."
                    ),
                    limitations="Static pattern check; cannot determine runtime reachability or developer intent.",
                )
            )

    # Heuristic review items: useless try/catch, excess nesting, unreferenced private helpers (§5)
    for ut in all_useless_try:
        findings.append(
            _make_finding(
                rule_id="static_code.useless_try_catch",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_VERIFIED,
                affected_identities=[resolved_project_id],
                source_paths=[{"path": ut["path"], "start_line": ut["line"], "end_line": ut["line"]}],
                evidence={
                    "project_id": resolved_project_id,
                    "path": ut["path"],
                    "line": ut["line"],
                    "kind": ut["kind"],
                },
                consequence=f"Heuristic review item: empty or pass-through exception handler at {ut['path']}:{ut['line']}.",
                limitations="Heuristic static syntax check.",
            )
        )

    for en in all_excess_nesting:
        findings.append(
            _make_finding(
                rule_id="static_code.excess_nesting",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_VERIFIED,
                affected_identities=[resolved_project_id],
                source_paths=[{"path": en["path"], "start_line": en["line"], "end_line": en["line"]}],
                evidence={
                    "project_id": resolved_project_id,
                    "path": en["path"],
                    "line": en["line"],
                    "depth": en["depth"],
                    "threshold": max_nesting_depth,
                },
                consequence=(
                    f"Heuristic review item: control-flow nesting depth {en['depth']} exceeds threshold "
                    f"{max_nesting_depth} at {en['path']}:{en['line']}."
                ),
                limitations="Heuristic nesting depth count.",
            )
        )

    for def_path, def_name, def_line in all_private_defs:
        if ecosystem == "python":
            is_ref = def_name in all_py_referenced_names
        else:
            pat = re.compile(rf"\b{re.escape(def_name)}\b")
            total_mentions = sum(len(pat.findall(blob)) for _, blob in all_stripped_blobs)
            is_ref = total_mentions > 1
        if not is_ref:
            findings.append(
                _make_finding(
                    rule_id="static_code.unreferenced_code",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[resolved_project_id],
                    source_paths=[{"path": def_path, "start_line": def_line, "end_line": def_line}],
                    evidence={
                        "project_id": resolved_project_id,
                        "path": def_path,
                        "line": def_line,
                        "symbol": def_name,
                    },
                    consequence=f"Heuristic review item: private helper {def_name!r} in {def_path}:{def_line} appears unreferenced.",
                    limitations="Lexical/AST reference check within project source files.",
                )
            )

    return _make_envelope(
        findings=findings,
        coverage=overall_coverage,
        extra={
            "rule_version": RULE_VERSION,
            "project_id": resolved_project_id,
            "template_id": resolved_template_id,
            "ecosystem": ecosystem,
            "summary": {
                "included": True,
                "lockfile": lockfile_name,
                "external_lock_package_count": len(external_lock_pkgs),
                "unapproved_lock_package_count": len(unapproved_lock_entries),
                "mapped_imports_count": mapped_imports_count,
                "builtin_imports_count": builtin_imports_count,
                "missing_lock_imports_count": len(missing_lock_imports),
                "unmappable_imports_count": len(unmappable_imports),
                "project_suppressions": len(all_suppressions),
                "baseline_suppressions": resolved_baseline_suppressions,
                "suppression_delta": max(0, suppression_delta),
                "stubs_count": len(all_stubs),
            },
        },
    )


check_static_code = audit_static_code
