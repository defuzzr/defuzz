# vendored module (origin: hermes_audit/template_drift.py, from the author's audit toolkit; not published separately). Do not edit: change the origin and re-vendor.
"""Template drift and scaffold provenance audit component (100% Python stdlib).

Implements the template drift checks from `hermes-adopt-audit-redesign.md` (§5, §6, §11, §12, §13.3):
- Compares a registered project against its step-2 scaffold provenance (`template_id`,
  `plugin_commit`, `prefix`, `locked_hashes`) and the substituted vendored template.
- Separates creation baseline (`provenance.locked_hashes` at `plugin_commit`) from the current
  shipped template (`current_plugin_commit`); an unreconstructable old baseline reports
  `coverage="could_not_verify"` and is never retroactively blessed.
- Validates:
  1. Scope: all registered golden templates from `templates.py` (`rust-golden`, `ts-node-golden`,
     `python-golden`, `go-golden`, `cpp-golden`, `dotnet-golden`, `web-golden`) are included; other templates
     and unregistered repos return `coverage="not_included"`.
  2. Provenance completeness: missing/unknown `plugin_commit`, `prefix`, or `locked_hashes`
     produces `coverage="could_not_verify"`.
  3. Locked-file hash drift (`template.locked_hash_drift`) and missing locked files
     (`template.locked_file_missing`) -> `classification="warning"`.
  4. Missing substituted template files (`template.missing_file`) -> `classification="warning"`.
  5. Leftover placeholder forms (`snake`, `kebab`, `screaming`, `pascal`) in paths or text
     contents (`template.leftover_placeholder`) -> `classification="warning"`.
  6. Safe content reads (§12): regular files only; symlinks, FIFOs, sockets, devices, unreadable
     files, size-bound violations, or mid-read races report `coverage="could_not_verify"`.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Callable, Iterable, Mapping, Sequence

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
    "PrefixForms",
    "audit_template_drift",
    "compute_substituted_template_baseline",
    "forms_from_placeholder",
    "forms_from_prefix",
    "rename_path_parts",
    "rename_text",
]

RULE_VERSION = "1.0.0"
FIXED_AUDIT_DISCLOSURE = "This audit cannot tell whether working code is correct."

CLASSIFICATION_WARNING = "warning"
CLASSIFICATION_REVIEW = "review_suggested"
CLASSIFICATION_INFO = "info"

COVERAGE_VERIFIED = "verified"
COVERAGE_COULD_NOT_VERIFY = "could_not_verify"
COVERAGE_NOT_INCLUDED = "not_included"


# LOCAL PATCH golden-template-registry-v1: derive GOLDEN_TEMPLATE_IDS without reading file contents at import; load registry at run time.
def _load_golden_template_ids() -> frozenset[str]:
    from ..contract import discover_golden_template_ids

    return discover_golden_template_ids()


GOLDEN_TEMPLATE_IDS: frozenset[str] = _load_golden_template_ids()

DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_DIR_ENTRIES = 20_000
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

_PLACEHOLDER_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_PREFIX_TOKEN_RE = re.compile(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$")
_SUPPORTS_OPEN_DIR_FD: bool = os.open in getattr(os, "supports_dir_fd", set())


@dataclass(frozen=True)
class PrefixForms:
    """Four canonical case forms derived from a template placeholder or project prefix."""

    kebab: str
    snake: str
    screaming: str
    pascal: str

    def as_dict(self) -> dict[str, str]:
        return {
            "kebab": self.kebab,
            "snake": self.snake,
            "screaming": self.screaming,
            "pascal": self.pascal,
        }


def forms_from_placeholder(placeholder_snake: str) -> PrefixForms:
    """Derive all four prefix forms from a snake_case placeholder."""
    if not isinstance(placeholder_snake, str) or not _PLACEHOLDER_RE.fullmatch(placeholder_snake):
        raise ValueError(f"Invalid snake_case placeholder: {placeholder_snake!r}")
    parts = [p for p in placeholder_snake.split("_") if p]
    kebab = "-".join(parts)
    snake = "_".join(parts)
    screaming = snake.upper()
    pascal = "".join(p.capitalize() for p in parts)
    return PrefixForms(kebab=kebab, snake=snake, screaming=screaming, pascal=pascal)


def forms_from_prefix(prefix: str) -> PrefixForms:
    """Derive all four prefix forms from a snake_case or kebab-case project prefix."""
    if not isinstance(prefix, str):
        raise ValueError("Prefix must be a string")
    cleaned = prefix.strip()
    if not _PREFIX_TOKEN_RE.fullmatch(cleaned):
        raise ValueError(f"Invalid project prefix: {prefix!r}")
    parts = [p for p in re.split(r"[-_]+", cleaned) if p]
    if not parts:
        raise ValueError(f"Empty project prefix: {prefix!r}")
    kebab = "-".join(parts)
    snake = "_".join(parts)
    screaming = snake.upper()
    pascal = "".join(p.capitalize() for p in parts)
    return PrefixForms(kebab=kebab, snake=snake, screaming=screaming, pascal=pascal)


def rename_text(text: str, src: PrefixForms, dst: PrefixForms) -> str:
    """Replace all four prefix forms in `text` in a single longest-first regex pass."""
    if not text:
        return text
    pairs = [
        (src.snake, dst.snake),
        (src.kebab, dst.kebab),
        (src.screaming, dst.screaming),
        (src.pascal, dst.pascal),
    ]
    mapping: dict[str, str] = {}
    for s_val, d_val in pairs:
        if s_val and s_val not in mapping:
            mapping[s_val] = d_val
    if not mapping:
        return text
    ordered_keys = sorted(mapping.keys(), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(k) for k in ordered_keys))
    return pattern.sub(lambda m: mapping[m.group(0)], text)


def rename_path_parts(rel_path: str, src: PrefixForms, dst: PrefixForms) -> str:
    """Rename each path component of `rel_path` using `rename_text`."""
    norm = rel_path.replace("\\", "/").strip("/")
    if not norm or norm == ".":
        return ""
    parts = [
        rename_text(part, src, dst)
        for part in PurePosixPath(norm).parts
        if part not in ("", ".")
    ]
    return "/".join(parts)


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]


def _matches_glob(rel_posix: str, patterns: Sequence[str], *, root_anchored: bool = False) -> bool:
    """Match a relative POSIX path against template glob patterns."""
    rel = rel_posix.replace("\\", "/").strip("/")
    if not rel:
        return False
    p = PurePosixPath(rel)
    full_match = getattr(p, "full_match", None)
    for pat in patterns:
        norm_pat = str(pat).replace("\\", "/").strip("/")
        if not norm_pat:
            continue
        if root_anchored:
            if callable(full_match):
                if full_match(norm_pat):
                    return True
                if norm_pat.startswith("**/") and norm_pat[3:] and full_match(norm_pat[3:]):
                    return True
                continue
            if "**" not in norm_pat:
                parts = p.parts
                pat_parts = PurePosixPath(norm_pat).parts
                if len(parts) == len(pat_parts) and all(
                    fnmatch.fnmatchcase(seg, pseg) for seg, pseg in zip(parts, pat_parts)
                ):
                    return True
            else:
                if fnmatch.fnmatchcase(rel, norm_pat):
                    return True
                if norm_pat.startswith("**/") and norm_pat[3:] and fnmatch.fnmatchcase(rel, norm_pat[3:]):
                    return True
        else:
            if p.match(norm_pat) or fnmatch.fnmatchcase(rel, norm_pat):
                return True
            if norm_pat.startswith("**/"):
                tail = norm_pat[3:]
                if tail and (p.match(tail) or fnmatch.fnmatchcase(rel, tail)):
                    return True
    return False


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
                if name == ".git":
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
                or (sha is None and raw_content is None)
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
                raw_size = val.get("size")
                file_size = (
                    int(raw_size)
                    if isinstance(raw_size, (int, float))
                    else (len(raw_content) if isinstance(raw_content, bytes) else 0)
                )
                out[rel] = {
                    "rel_path": rel,
                    "kind": "regular",
                    "coverage": COVERAGE_VERIFIED,
                    "stable": True,
                    "content": raw_content,
                    "sha256": str(sha).lower() if sha else None,
                    "size": file_size,
                    "error": None,
                }
        else:
            coverage = COVERAGE_COULD_NOT_VERIFY
            issues.append({"path": rel, "reason": f"unsupported_entry_type:{type(val).__name__}"})

    return out, coverage, issues


def compute_substituted_template_baseline(
    *,
    template_files: Mapping[str, Any],
    placeholder: str,
    prefix: str,
    substitute_in: Sequence[str],
    locked_globs: Sequence[str] = (),
    repo_subpath: str | None = None,
) -> dict[str, Any]:
    """Apply prefix substitution to `template_files` and compute expected paths, contents, and locked hashes."""
    src_forms = forms_from_placeholder(placeholder)
    dst_forms = forms_from_prefix(prefix)

    norm_template, t_cov, t_issues = _normalize_file_map(template_files)
    repo_prefix = (repo_subpath or "").replace("\\", "/").strip("/")

    substituted_files: dict[str, dict[str, Any]] = {}
    locked_hashes: dict[str, str] = {}

    for raw_rel, meta in sorted(norm_template.items()):
        rel = raw_rel
        if repo_prefix and rel.startswith(f"{repo_prefix}/"):
            rel = rel[len(repo_prefix) + 1 :]
        elif not repo_prefix and rel == "template.yaml":
            continue

        if meta["coverage"] != COVERAGE_VERIFIED:
            t_cov = COVERAGE_COULD_NOT_VERIFY
            continue

        renamed_rel = rename_path_parts(rel, src_forms, dst_forms)
        if not renamed_rel:
            continue

        raw_bytes: bytes | None = meta.get("content")
        out_bytes = raw_bytes
        if raw_bytes is not None and (
            _matches_glob(rel, substitute_in) or _matches_glob(renamed_rel, substitute_in)
        ):
            if not _is_binary(raw_bytes):
                try:
                    text = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    text = None
                if text is not None:
                    new_text = rename_text(text, src_forms, dst_forms)
                    if new_text != text:
                        out_bytes = new_text.encode("utf-8")

        sha = (
            hashlib.sha256(out_bytes).hexdigest()
            if out_bytes is not None
            else meta.get("sha256")
        )
        substituted_files[renamed_rel] = {
            "rel_path": renamed_rel,
            "template_rel_path": rel,
            "content": out_bytes,
            "sha256": sha,
        }
        if locked_globs and sha and _matches_glob(renamed_rel, locked_globs, root_anchored=True):
            locked_hashes[renamed_rel] = sha

    return {
        "coverage": t_cov,
        "issues": t_issues,
        "src_forms": src_forms.as_dict(),
        "dst_forms": dst_forms.as_dict(),
        "files": substituted_files,
        "locked_hashes": dict(sorted(locked_hashes.items())),
    }


def _parse_locked_hashes_field(raw: Any) -> dict[str, str] | None:
    if raw is None:
        return None
    data = raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            data = json.loads(stripped)
        except ValueError:
            return None
    if not isinstance(data, Mapping) or not data:
        return None
    parsed: dict[str, str] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return None
        k_norm = k.replace("\\", "/").strip("/")
        v_norm = v.strip().lower()
        if not k_norm or not v_norm:
            return None
        parsed[k_norm] = v_norm
    return parsed if parsed else None


def _scan_leftover_placeholders(
    *,
    project_files: Mapping[str, Mapping[str, Any]],
    src_forms: PrefixForms,
    dst_forms: PrefixForms,
) -> list[dict[str, Any]]:
    """Find any remaining occurrences of the template placeholder forms in paths or UTF-8 contents."""
    # Only scan forms that differ between placeholder and target prefix
    active_forms: list[tuple[str, str]] = []
    for label, s_val, d_val in (
        ("snake", src_forms.snake, dst_forms.snake),
        ("kebab", src_forms.kebab, dst_forms.kebab),
        ("screaming", src_forms.screaming, dst_forms.screaming),
        ("pascal", src_forms.pascal, dst_forms.pascal),
    ):
        if s_val and s_val != d_val:
            active_forms.append((label, s_val))

    if not active_forms:
        return []

    hits: list[dict[str, Any]] = []
    for rel_path, meta in sorted(project_files.items()):
        path_forms = [label for label, token in active_forms if token in rel_path]
        content_lines: list[int] = []
        content_forms: set[str] = set()

        raw_bytes = meta.get("content")
        if isinstance(raw_bytes, bytes) and not _is_binary(raw_bytes):
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None:
                for line_no, line in enumerate(text.splitlines(), start=1):
                    matched_here = False
                    for label, token in active_forms:
                        if token in line:
                            content_forms.add(label)
                            matched_here = True
                    if matched_here:
                        content_lines.append(line_no)

        if path_forms or content_lines:
            hits.append({
                "rel_path": rel_path,
                "path_forms": sorted(set(path_forms)),
                "content_forms": sorted(content_forms),
                "line_numbers": content_lines[:50],
                "occurrence_count": len(content_lines) + (1 if path_forms else 0),
            })

    return hits


def audit_template_drift(
    provenance: Mapping[str, Any] | Path | str | None = None,
    *,
    project_id: str | None = None,
    project_files: Mapping[str, Any] | None = None,
    project_root: Path | str | None = None,
    template_spec: Mapping[str, Any] | None = None,
    template_files: Mapping[str, Any] | None = None,
    template_root: Path | str | None = None,
    current_plugin_commit: str | None = None,
    registered: bool = True,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_entries: int = DEFAULT_MAX_DIR_ENTRIES,
) -> dict[str, Any]:
    """Audit a project for template locked-file drift, missing template files, and leftover placeholders (§5, §11, §12, §13.3).

    Accepts plain-data inputs (`provenance`, `project_files`, `template_spec`, `template_files`)
    or optional directory roots (`project_root`, `template_root`) read safely via descriptor-relative
    `O_NOFOLLOW | O_NONBLOCK` traversal. Never opens any state database.
    """
    if isinstance(provenance, (Path, str)):
        if project_root is None:
            project_root = provenance
        prov_map: Mapping[str, Any] = {}
    elif isinstance(provenance, Mapping):
        prov_map = provenance
    else:
        prov_map = {}

    # Allow composite single-dict invocation: `audit_template_drift({"provenance": ..., "project_files": ...})`
    if "provenance" in prov_map and isinstance(prov_map.get("provenance"), Mapping):
        outer = prov_map
        prov_map = outer["provenance"]
        if project_id is None and outer.get("project_id") is not None:
            project_id = str(outer["project_id"])
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
        if current_plugin_commit is None and outer.get("current_plugin_commit") is not None:
            current_plugin_commit = str(outer["current_plugin_commit"])
        if "registered" in outer:
            registered = bool(outer["registered"])

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

    raw_template_id = prov_map.get("template_id")
    if raw_template_id is None and isinstance(template_spec, Mapping):
        raw_template_id = template_spec.get("id")
    template_id = str(raw_template_id).strip() if raw_template_id else None

    findings: list[dict[str, Any]] = []

    # LOCAL PATCH golden-template-registry-v1: load golden template registry at run time after preflight.
    from ..contract import resolve_runtime_golden_registry

    registry = resolve_runtime_golden_registry()
    runtime_specs: Mapping[str, Any] = registry["specs"]
    discovered_ids: frozenset[str] = registry["discovered_ids"]
    supported_ids: frozenset[str] = discovered_ids or GOLDEN_TEMPLATE_IDS

    if registered and template_id:
        unverified_reason: str | None = None
        if not registry["available"]:
            unverified_reason = str(registry.get("reason") or "templates_registry_unavailable")
        elif template_id in registry["excluded_ids"]:
            unverified_reason = "template_manifest_excluded_by_credential_policy"
        elif template_id in registry["invalid_ids"]:
            unverified_reason = f"template_manifest_invalid:{registry['invalid_ids'][template_id]}"
        if unverified_reason is not None:
            findings.append(
                _make_finding(
                    rule_id="template.unreconstructable_baseline",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[resolved_project_id],
                    source_paths=[resolved_project_id],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": template_id,
                        "reason": unverified_reason,
                    },
                    consequence=(
                        f"Golden template registry metadata for {template_id!r} could not be verified ({unverified_reason})."
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
                    "template_id": template_id,
                    "summary": {
                        "included": True,
                        "reason": unverified_reason,
                        "locked_drifted_count": 0,
                        "missing_files_count": 0,
                        "leftover_placeholder_count": 0,
                    },
                },
            )

    if template_spec is None and template_id and template_id in runtime_specs:
        loaded_spec = runtime_specs[template_id]
        template_spec = {
            "id": loaded_spec.id,
            "placeholder": loaded_spec.placeholder,
            "substitute_in": list(loaded_spec.substitute_in),
            "locked": list(loaded_spec.locked),
            "approved_deps": {k: list(v) for k, v in loaded_spec.approved_deps.items()},
            "repos": [{"name": r.name} for r in loaded_spec.repos],
        }
        if template_files is None and template_root is None and len(loaded_spec.repos) == 1:
            template_root = loaded_spec.root / loaded_spec.repos[0].name

    # §3, §5, §13.3: Unregistered repos or non-golden templates -> not_included
    if not registered or not template_id or template_id not in supported_ids:
        reason = (
            "unregistered_repository"
            if not registered
            else f"non_golden_template:{template_id or 'none'}"
        )
        findings.append(
            _make_finding(
                rule_id="template.not_included",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_NOT_INCLUDED,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "registered": registered,
                    "template_id": template_id,
                    "reason": reason,
                    "supported_templates": sorted(supported_ids),
                },
                # LOCAL PATCH golden-template-registry-v1: reflect full golden template registry in diagnostics.
                consequence=(
                    "Not set up by the plugin; template drift checks are not included."
                    if not registered
                    else f"Template {template_id or 'none'!r} is outside the golden template registry; template drift checks are not included."
                ),
                limitations=f"Only registered golden templates ({', '.join(sorted(supported_ids))}) participate in template drift checks.",
            )
        )
        return _make_envelope(
            findings=findings,
            coverage=COVERAGE_NOT_INCLUDED,
            extra={
                "rule_version": RULE_VERSION,
                "project_id": resolved_project_id,
                "template_id": template_id,
                "summary": {
                    "included": False,
                    "reason": reason,
                    "locked_drifted_count": 0,
                    "missing_files_count": 0,
                    "leftover_placeholder_count": 0,
                },
            },
        )

    # §10.2: If a golden template spec explicitly has no `locked:` / `approved_deps:` yet -> not_included
    if isinstance(template_spec, Mapping):
        spec_locked = template_spec.get("locked")
        spec_approved = template_spec.get("approved_deps")
        if (
            "locked" in template_spec
            and not spec_locked
            and not spec_approved
        ):
            findings.append(
                _make_finding(
                    rule_id="template.not_included",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_NOT_INCLUDED,
                    affected_identities=[resolved_project_id],
                    source_paths=[resolved_project_id],
                    evidence={
                        "project_id": resolved_project_id,
                        "template_id": template_id,
                        "reason": "template_guardrails_not_configured",
                    },
                    consequence=f"Template {template_id!r} does not define locked/approved_deps guardrails yet; template checks are not included.",
                    limitations="Template checks activate once locked and approved_deps are populated in template.yaml.",
                )
            )
            return _make_envelope(
                findings=findings,
                coverage=COVERAGE_NOT_INCLUDED,
                extra={
                    "rule_version": RULE_VERSION,
                    "project_id": resolved_project_id,
                    "template_id": template_id,
                    "summary": {
                        "included": False,
                        "reason": "template_guardrails_not_configured",
                        "locked_drifted_count": 0,
                        "missing_files_count": 0,
                        "leftover_placeholder_count": 0,
                    },
                },
            )

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
                rule_id="template.unverified_file",
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

    # Check provenance fields (§5, §10.2, §11)
    plugin_commit_raw = prov_map.get("plugin_commit")
    plugin_commit = str(plugin_commit_raw).strip() if plugin_commit_raw else None
    prefix_raw = prov_map.get("prefix")
    prefix_str = str(prefix_raw).strip() if prefix_raw else None
    locked_hashes = _parse_locked_hashes_field(
        prov_map.get("locked_hashes")
        if "locked_hashes" in prov_map
        else prov_map.get("locked_hashes_json")
    )

    missing_prov_fields: list[str] = []
    if not plugin_commit or plugin_commit.lower() == "unknown":
        missing_prov_fields.append("plugin_commit")
    if not prefix_str:
        missing_prov_fields.append("prefix")
    if not locked_hashes:
        missing_prov_fields.append("locked_hashes")

    prefix_forms: PrefixForms | None = None
    if prefix_str:
        try:
            prefix_forms = forms_from_prefix(prefix_str)
        except ValueError:
            missing_prov_fields.append("prefix_invalid")

    if missing_prov_fields:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="template.provenance_missing",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": template_id,
                    "missing_fields": sorted(set(missing_prov_fields)),
                    "plugin_commit": plugin_commit,
                    "prefix": prefix_str,
                },
                consequence=(
                    f"Scaffold provenance for {resolved_project_id} is incomplete "
                    f"(missing: {', '.join(sorted(set(missing_prov_fields)))}); creation baseline could not be verified."
                ),
                limitations="Missing scaffold provenance is never retroactively backfilled or blessed.",
            )
        )

    # Check creation plugin_commit vs current_plugin_commit (§5: separate creation baseline from current shipped template)
    baseline_commit_mismatch = (
        bool(plugin_commit)
        and plugin_commit.lower() != "unknown"
        and bool(current_plugin_commit)
        and str(current_plugin_commit).strip().lower() not in ("", "unknown", plugin_commit.lower())
    )
    if baseline_commit_mismatch:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="template.unreconstructable_baseline",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": template_id,
                    "creation_plugin_commit": plugin_commit,
                    "current_plugin_commit": str(current_plugin_commit).strip(),
                },
                consequence=(
                    f"Project was scaffolded at plugin commit {plugin_commit!r}, which differs from "
                    f"the current shipped template commit {str(current_plugin_commit).strip()!r}."
                ),
                limitations="Locked hashes from creation provenance are still checked, but full creation template tree differences outside locked_hashes cannot be reconstructed from the current shipped template.",
            )
        )

    # 1. Verify locked-file hashes against step-2 provenance record (`locked_hashes`)
    locked_drifted: list[dict[str, Any]] = []
    locked_missing: list[str] = []
    if locked_hashes:
        for rel_locked, expected_sha in sorted(locked_hashes.items()):
            fmeta = norm_project.get(rel_locked)
            if fmeta is None:
                locked_missing.append(rel_locked)
                findings.append(
                    _make_finding(
                        rule_id="template.locked_file_missing",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[resolved_project_id],
                        source_paths=[rel_locked],
                        evidence={
                            "project_id": resolved_project_id,
                            "template_id": template_id,
                            "rel_path": rel_locked,
                            "expected_sha256": expected_sha,
                        },
                        consequence=f"Locked guardrail file {rel_locked!r} recorded at project creation is missing.",
                        limitations="Compared against scaffold-time provenance locked_hashes.",
                    )
                )
                continue

            if fmeta.get("coverage") != COVERAGE_VERIFIED or not fmeta.get("sha256"):
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                continue

            actual_sha = str(fmeta["sha256"]).lower()
            if actual_sha != expected_sha.lower():
                locked_drifted.append({
                    "rel_path": rel_locked,
                    "expected_sha256": expected_sha.lower(),
                    "actual_sha256": actual_sha,
                })
                findings.append(
                    _make_finding(
                        rule_id="template.locked_hash_drift",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[resolved_project_id],
                        source_paths=[rel_locked],
                        evidence={
                            "project_id": resolved_project_id,
                            "template_id": template_id,
                            "rel_path": rel_locked,
                            "expected_sha256": expected_sha.lower(),
                            "actual_sha256": actual_sha,
                            "baseline_source": "provenance_locked_hashes",
                            "plugin_commit": plugin_commit,
                        },
                        consequence=f"Locked guardrail file {rel_locked!r} has drifted from its scaffold-time SHA-256 baseline.",
                        limitations="Hash comparison detects any byte modification to locked template guardrail files.",
                    )
                )

    # 2. Substitute template baseline (if template_files/template_root provided) and check missing files + template locked baseline
    placeholder_str = (
        str(template_spec.get("placeholder") or "tmpl_prefix").strip()
        if isinstance(template_spec, Mapping)
        else "tmpl_prefix"
    )
    substitute_in: Sequence[str] = (
        tuple(str(x) for x in (template_spec.get("substitute_in") or ()))
        if isinstance(template_spec, Mapping)
        else ("**/*.rs", "**/*.toml", "**/*.md", "**/*.yml", "**/*.yaml", "**/*.ts", "**/*.json", "**/*.py", "**/Cargo.lock", "**/pnpm-lock.yaml", "**/uv.lock", ".env.example", "**/*.tmpl")
    )
    locked_globs: Sequence[str] = (
        tuple(str(x) for x in (template_spec.get("locked") or ()))
        if isinstance(template_spec, Mapping)
        else ()
    )
    repo_subpath: str | None = None
    if isinstance(template_spec, Mapping):
        repos_raw = template_spec.get("repos")
        if isinstance(repos_raw, Sequence) and len(repos_raw) == 1 and isinstance(repos_raw[0], Mapping):
            repo_subpath = str(repos_raw[0].get("name") or "").strip() or None

    raw_tmpl_files: Mapping[str, Any] | None = template_files
    if raw_tmpl_files is None and template_root is not None:
        walked_tmpl, tmpl_walk_cov, tmpl_walk_issues = _safe_walk_directory(
            template_root, max_file_bytes=max_file_bytes, max_entries=max_entries
        )
        raw_tmpl_files = walked_tmpl
        if tmpl_walk_cov != COVERAGE_VERIFIED or tmpl_walk_issues:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY

    missing_template_files: list[str] = []
    substituted_baseline: dict[str, Any] | None = None

    if raw_tmpl_files is not None and prefix_forms is not None:
        try:
            substituted_baseline = compute_substituted_template_baseline(
                template_files=raw_tmpl_files,
                placeholder=placeholder_str,
                prefix=prefix_forms.snake,
                substitute_in=substitute_in,
                locked_globs=locked_globs,
                repo_subpath=repo_subpath,
            )
        except ValueError as exc:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="template.unreconstructable_baseline",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[resolved_project_id],
                    source_paths=[resolved_project_id],
                    evidence={"error": str(exc), "template_id": template_id},
                    consequence=f"Could not reconstruct substituted template baseline: {exc}",
                    limitations="Template substitution requires valid placeholder and prefix forms.",
                )
            )

    if substituted_baseline is not None:
        if substituted_baseline["coverage"] != COVERAGE_VERIFIED:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
        expected_files = substituted_baseline["files"]
        already_missing_locked = set(locked_missing)

        for exp_rel in sorted(expected_files.keys()):
            if exp_rel not in norm_project:
                missing_template_files.append(exp_rel)
                if exp_rel in already_missing_locked:
                    continue
                # If creation commit differs from current shipped template commit and file wasn't in locked_hashes,
                # report as could_not_verify rather than assuming it existed at creation time (§5).
                if baseline_commit_mismatch:
                    findings.append(
                        _make_finding(
                            rule_id="template.missing_file",
                            classification=CLASSIFICATION_REVIEW,
                            coverage=COVERAGE_COULD_NOT_VERIFY,
                            affected_identities=[resolved_project_id],
                            source_paths=[exp_rel],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": template_id,
                                "rel_path": exp_rel,
                                "creation_plugin_commit": plugin_commit,
                                "current_plugin_commit": current_plugin_commit,
                            },
                            consequence=f"File {exp_rel!r} from the current shipped template is absent in the project.",
                            limitations="Creation commit differs from current shipped template; cannot verify without historical template tree.",
                        )
                    )
                else:
                    findings.append(
                        _make_finding(
                            rule_id="template.missing_file",
                            classification=CLASSIFICATION_WARNING,
                            coverage=COVERAGE_VERIFIED,
                            affected_identities=[resolved_project_id],
                            source_paths=[exp_rel],
                            evidence={
                                "project_id": resolved_project_id,
                                "template_id": template_id,
                                "rel_path": exp_rel,
                                "template_rel_path": expected_files[exp_rel]["template_rel_path"],
                            },
                            consequence=f"Expected template file {exp_rel!r} is missing from the project.",
                            limitations="Compared against the substituted golden template file manifest.",
                        )
                    )
    elif raw_tmpl_files is None:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="template.unreconstructable_baseline",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[resolved_project_id],
                source_paths=[resolved_project_id],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": template_id,
                    "reason": "template_files_not_provided",
                },
                consequence=f"Vendored template files for {template_id!r} were not provided; full file-set baseline could not be verified.",
                limitations="Without template files, only provenance locked_hashes and placeholder checks could run.",
            )
        )

    # 3. Leftover placeholder forms (§5)
    leftover_hits: list[dict[str, Any]] = []
    try:
        src_placeholder_forms = forms_from_placeholder(placeholder_str)
        effective_dst_forms = prefix_forms or PrefixForms(
            kebab="", snake="", screaming="", pascal=""
        )
        leftover_hits = _scan_leftover_placeholders(
            project_files=norm_project,
            src_forms=src_placeholder_forms,
            dst_forms=effective_dst_forms,
        )
    except ValueError:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    for hit in leftover_hits:
        line_nums = hit["line_numbers"]
        first_line = line_nums[0] if line_nums else None
        last_line = line_nums[-1] if line_nums else None
        findings.append(
            _make_finding(
                rule_id="template.leftover_placeholder",
                classification=CLASSIFICATION_WARNING,
                coverage=COVERAGE_VERIFIED,
                affected_identities=[resolved_project_id],
                source_paths=[
                    {
                        "path": hit["rel_path"],
                        "start_line": first_line,
                        "end_line": last_line,
                    }
                ],
                evidence={
                    "project_id": resolved_project_id,
                    "template_id": template_id,
                    "placeholder": placeholder_str,
                    "rel_path": hit["rel_path"],
                    "path_forms": hit["path_forms"],
                    "content_forms": hit["content_forms"],
                    "line_numbers": line_nums,
                    "occurrence_count": hit["occurrence_count"],
                },
                consequence=(
                    f"Unsubstituted template placeholder form ({placeholder_str!r}) remains in {hit['rel_path']!r}."
                ),
                limitations="Lexical scan for the template placeholder's four case forms (snake, kebab, SCREAMING, Pascal).",
            )
        )

    return _make_envelope(
        findings=findings,
        coverage=overall_coverage,
        extra={
            "rule_version": RULE_VERSION,
            "project_id": resolved_project_id,
            "template_id": template_id,
            "summary": {
                "included": True,
                "plugin_commit": plugin_commit,
                "current_plugin_commit": current_plugin_commit,
                "prefix": prefix_str,
                "locked_checked_count": len(locked_hashes) if locked_hashes else 0,
                "locked_drifted_count": len(locked_drifted),
                "locked_missing_count": len(locked_missing),
                "missing_files_count": len(missing_template_files),
                "leftover_placeholder_count": len(leftover_hits),
                "unverified_files_count": len(proj_issues),
            },
        },
    )


check_template_drift = audit_template_drift
