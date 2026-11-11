# vendored module (origin: hermes_audit/memory.py, from the author's audit toolkit; not published separately). Do not edit: change the origin and re-vendor.
"""Read-only Profile Memory audit component (100% Python stdlib).

Implements the 'memory' checks of the 'Profile context and memory' component group
from `hermes-adopt-audit-redesign.md` (§1, §2, §4, §5, §6, §8, §11, §12, §13.5).

Settled invariants enforced here:
- 100% Python stdlib; imports nothing from sibling modules or Hermes runtime packages.
- Never reads `~`, `Path.home()`, `Path.cwd()`, or `os.environ`.
- Never executes subprocesses, network calls, or external providers.
- Memory checks (§5, §8, §12, §13.5):
  1. Exact vs whitespace-normalized entry duplicates:
     - Byte-identical entry text (`sha256_exact`) -> `warning` with declarative
       `proposed_cleanup_id` (cleanup-eligible, unticked by default per §8/§13.5).
     - Whitespace-normalized match (`sha256_normalized_ws` equal, `sha256_exact` different)
       -> `review_suggested` and NEVER cleanup-eligible (`proposed_cleanup_id=None`).
  2. Authoritative entry age vs file mtime (§5, §12):
     - Evaluates entry age ONLY when authoritative entry creation metadata (`authoritative_created_at`)
       exists against the run's captured `as_of` timestamp.
     - File `mtime` is recorded as file metadata ONLY and is NEVER used as an entry birth date;
       entries without `authoritative_created_at` report age `coverage="could_not_verify"`.
  3. Resolvable path/project references & missing-path staleness (§5):
     - Missing paths are flagged stale (`warning`) ONLY when local identity (`path_on_local_machine=True`)
       and an accessible namespace (`accessible_namespace_roots`) establish absence (`exists=False`).
     - Foreign-host paths or paths under inaccessible/unverified roots report `coverage="could_not_verify"`,
       never a false stale-path warning.
  4. Deterministic registered-project mapping (§5):
     - Every entry receives a deterministic mapping or an explicit classification:
       `mapped` | `ambiguous` | `unmatched` | `general`.
     - Exact canonical/raw paths and `hermes_project_id` match first (`mapped`).
     - Unique project `name`/`slug` token matches map deterministically (`mapped`).
     - Shared/colliding project `name`/`slug` across multiple registered projects is classified
       `ambiguous` (`review_suggested`) and NEVER silently chooses a project.
     - Entries referencing paths that belong to a project outside the profile's own registrations
       (cross-project exposure) emit a `warning` with the named consequence.
  5. Operational directives vs declarative facts (§5):
     - Proven cross-project operational directives carry `warning`.
     - Heuristic imperative/directive phrasing (`ALWAYS ...`, `NEVER ...`, `MUST ...`) is
       `review_suggested`.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "COMPONENT_VERSION",
    "audit_profile_memory",
]

COMPONENT_VERSION = "1.0.0"

CLASSIFICATION_WARNING = "warning"
CLASSIFICATION_REVIEW = "review_suggested"
CLASSIFICATION_INFO = "info"
VALID_CLASSIFICATIONS = frozenset({
    CLASSIFICATION_WARNING,
    CLASSIFICATION_REVIEW,
    CLASSIFICATION_INFO,
})

COVERAGE_VERIFIED = "verified"
COVERAGE_COULD_NOT_VERIFY = "could_not_verify"
COVERAGE_NOT_INCLUDED = "not_included"
VALID_COVERAGES = frozenset({
    COVERAGE_VERIFIED,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_NOT_INCLUDED,
})

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

_FORBIDDEN_EVIDENCE_KEYS = frozenset({
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

# Filesystem path extraction regex: matches `~/...` or absolute POSIX paths `/home/...`, `/Users/...`, `/opt/...`, `/srv/...`, `/var/...`, `/tmp/...`, `/etc/...`, `/mnt/...`, `/workspace/...`
_PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>~/[A-Za-z0-9_./-]+|/(?:home|Users|root|opt|srv|var|tmp|etc|mnt|workspace|Projects|projects|work|repos|code)/[A-Za-z0-9_./-]+)"
)

# Heuristic operational directive patterns (§5: heuristic interpretation is review_suggested; proven cross-project operational directive is warning)
_HEURISTIC_DIRECTIVE_RE = re.compile(
    r"(?im)(?:^|[.;:!]\s+)(?:always|never|must\s+always|must\s+not|do\s+not\s+ever|under\s+no\s+circumstances|from\s+now\s+on\s+always|ignore\s+all\s+previous|override\s+default)\b"
)


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
    cls_norm = str(classification).strip().lower()
    if cls_norm not in VALID_CLASSIFICATIONS:
        raise ValueError(f"Invalid classification: {classification!r}")
    cov_norm = str(coverage).strip().lower()
    if cov_norm not in VALID_COVERAGES:
        raise ValueError(f"Invalid coverage: {coverage!r}")

    clean_evidence = _sanitize_evidence(dict(evidence) if evidence is not None else {})
    identities = sorted({str(x).strip() for x in affected_identities if str(x).strip()})
    paths = _normalize_source_paths(source_paths)
    consequence_str = str(consequence or "").strip()
    if not consequence_str:
        raise ValueError(f"Finding {rid!r} must include a plain-language consequence")
    limitations_str = str(limitations or "").strip()
    detail_str = str(detail).strip() if detail is not None and str(detail).strip() else consequence_str

    if proposed_cleanup_id is not None:
        cleanup_id = str(proposed_cleanup_id).strip() or None
        if cleanup_id and any(ch in cleanup_id for ch in ("\n", "\r", ";", "|", "&", "`", "$(")):
            raise ValueError(f"Invalid proposed_cleanup_id: {proposed_cleanup_id!r}")
    else:
        cleanup_id = None

    return {
        "id": rid,
        "classification": cls_norm,
        "coverage": cov_norm,
        "affected_identities": identities,
        "source_paths": paths,
        "evidence": clean_evidence,
        "consequence": consequence_str,
        "limitations": limitations_str,
        "proposed_cleanup_id": cleanup_id,
        "severity": _CLASSIFICATION_TO_LEGACY_SEVERITY[cls_norm],
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
    findings: Sequence[Mapping[str, Any]],
    coverage: str,
    error: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    sorted_findings = sorted((dict(f) for f in findings), key=_finding_sort_key)
    if error is not None:
        err_str = str(error).strip() or "Component operational error"
        out: dict[str, Any] = {
            "ok": False,
            "status": "error",
            "error": err_str,
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "classification": _compute_classification_headline(sorted_findings),
            "findings": sorted_findings,
        }
    else:
        cov_norm = coverage if coverage in VALID_COVERAGES else COVERAGE_COULD_NOT_VERIFY
        if any(f.get("coverage") == COVERAGE_COULD_NOT_VERIFY for f in sorted_findings):
            cov_norm = COVERAGE_COULD_NOT_VERIFY
        has_legacy_error = any(f.get("severity") == "error" for f in sorted_findings)
        status = "fail" if has_legacy_error else "pass"
        out = {
            "ok": status == "pass",
            "status": status,
            "error": None,
            "coverage": cov_norm,
            "classification": _compute_classification_headline(sorted_findings),
            "findings": sorted_findings,
        }
    if extra:
        for k, v in extra.items():
            if k not in out:
                out[str(k)] = v
    return out


def _norm_posix(path_str: str, *, home_dir: str | None = None) -> str:
    s = str(path_str or "").strip().rstrip(".,;:!?)']\"")
    if not s:
        return ""
    if s.startswith("~/") and home_dir:
        s = home_dir.rstrip("/") + "/" + s[2:]
    elif s == "~" and home_dir:
        s = home_dir.rstrip("/")
    if s.startswith("/"):
        return posixpath.normpath(s)
    return s


def _is_under_root(candidate_path: str, root_path: str) -> bool:
    if not candidate_path.startswith("/") or not root_path.startswith("/"):
        return False
    c_norm = posixpath.normpath(candidate_path)
    r_norm = posixpath.normpath(root_path)
    if r_norm == "/":
        return True
    return c_norm == r_norm or c_norm.startswith(r_norm + "/")


def _extract_paths_from_text(text: str, *, home_dir: str | None = None) -> list[dict[str, str]]:
    """Extract filesystem path references from an entry's text."""
    seen: set[str] = set()
    extracted: list[dict[str, str]] = []
    for match in _PATH_TOKEN_RE.finditer(text or ""):
        raw = match.group("path").rstrip(".,;:!?)']\"")
        if not raw or raw in seen:
            continue
        seen.add(raw)
        resolved = _norm_posix(raw, home_dir=home_dir)
        extracted.append({
            "raw_path": raw,
            "resolved_path": resolved,
        })
    return extracted


def _index_registered_projects(
    registered_projects: Sequence[Mapping[str, Any]],
    *,
    home_dir: str | None = None,
) -> dict[str, Any]:
    """Build deterministic lookup tables for registered projects (§5).

    Supports both `project_units` from `union_profile_registrations` and raw registration records.
    """
    by_canonical_path: dict[str, dict[str, Any]] = {}
    by_raw_path: dict[str, str] = {}
    by_project_id: dict[str, list[str]] = {}
    by_name_lower: dict[str, list[str]] = {}
    by_slug_lower: dict[str, list[str]] = {}

    for proj in registered_projects:
        if not isinstance(proj, Mapping):
            continue
        cpath_raw = str(proj.get("canonical_path") or proj.get("path") or "").strip()
        if not cpath_raw:
            continue
        cpath = _norm_posix(cpath_raw, home_dir=home_dir)
        if not cpath:
            continue

        owners_raw = proj.get("owning_profiles")
        if isinstance(owners_raw, Sequence) and not isinstance(owners_raw, (str, bytes)):
            owners = sorted({str(x).strip() for x in owners_raw if str(x).strip()})
        elif proj.get("owning_profile"):
            owners = [str(proj["owning_profile"]).strip()]
        else:
            owners = []

        existing = by_canonical_path.get(cpath)
        if existing is None:
            unit_info: dict[str, Any] = {
                "canonical_path": cpath,
                "name": str(proj.get("name") or "").strip() or None,
                "slug": str(proj.get("slug") or "").strip() or None,
                "hermes_project_id": str(proj.get("hermes_project_id") or "").strip() or None,
                "owning_profiles": owners,
                "raw_paths": {cpath},
            }
            by_canonical_path[cpath] = unit_info
        else:
            unit_info = existing
            unit_info["owning_profiles"] = sorted(set(unit_info["owning_profiles"]) | set(owners))
            if not unit_info["name"] and proj.get("name"):
                unit_info["name"] = str(proj["name"]).strip()
            if not unit_info["slug"] and proj.get("slug"):
                unit_info["slug"] = str(proj["slug"]).strip()
            if not unit_info["hermes_project_id"] and proj.get("hermes_project_id"):
                unit_info["hermes_project_id"] = str(proj["hermes_project_id"]).strip()

        raw_p = str(proj.get("raw_path") or "").strip()
        if raw_p:
            norm_raw = _norm_posix(raw_p, home_dir=home_dir)
            unit_info["raw_paths"].add(norm_raw)
            by_raw_path[norm_raw] = cpath
        by_raw_path[cpath] = cpath

        for sub_rec in (proj.get("records") or ()):
            if isinstance(sub_rec, Mapping):
                sr_raw = str(sub_rec.get("raw_path") or "").strip()
                if sr_raw:
                    norm_sr = _norm_posix(sr_raw, home_dir=home_dir)
                    unit_info["raw_paths"].add(norm_sr)
                    by_raw_path[norm_sr] = cpath
                sr_pid = str(sub_rec.get("hermes_project_id") or "").strip()
                if sr_pid:
                    by_project_id.setdefault(sr_pid, []).append(cpath)
                sr_name = str(sub_rec.get("name") or "").strip().lower()
                if sr_name:
                    by_name_lower.setdefault(sr_name, []).append(cpath)
                sr_slug = str(sub_rec.get("slug") or "").strip().lower()
                if sr_slug:
                    by_slug_lower.setdefault(sr_slug, []).append(cpath)

        pid = unit_info.get("hermes_project_id")
        if pid:
            by_project_id.setdefault(str(pid), []).append(cpath)
        nm = unit_info.get("name")
        if nm:
            by_name_lower.setdefault(str(nm).lower(), []).append(cpath)
        sl = unit_info.get("slug")
        if sl:
            by_slug_lower.setdefault(str(sl).lower(), []).append(cpath)

    # Deduplicate and sort target lists
    for d in (by_project_id, by_name_lower, by_slug_lower):
        for k in list(d.keys()):
            d[k] = sorted(set(d[k]))

    return {
        "by_canonical_path": by_canonical_path,
        "by_raw_path": by_raw_path,
        "by_project_id": by_project_id,
        "by_name_lower": by_name_lower,
        "by_slug_lower": by_slug_lower,
    }


def _map_entry_to_projects(
    *,
    entry_text: str,
    extracted_paths: Sequence[Mapping[str, str]],
    project_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Deterministically map a memory entry to registered projects (§5).

    Precedence rules (§5):
    1. Exact canonical/raw path containment or exact `hermes_project_id` match first.
       - If all matched paths/IDs resolve to a single project -> `classification="mapped"`.
       - If an entry explicitly references multiple distinct projects by exact path/ID -> `classification="mapped"`
         with `multi_project_reference=True` and all matched canonical paths.
    2. If no exact path/ID matched, check registered project `slug` and `name` tokens (word-bounded,
       case-insensitive, minimum length 3):
       - If a matched name/slug belongs to >1 registered project -> `classification="ambiguous"`
         (never silently chooses a project!).
       - If multiple distinct project names/slugs are matched without exact paths -> `classification="ambiguous"`
         unless each matched token is unambiguous.Wait: if an entry mentions an ambiguous name shared by 2 projects,
         it MUST be `ambiguous`.
    3. If the entry contains filesystem paths (or project-like repo references) that do not match any
       registered project -> `classification="unmatched"`.
    4. Otherwise (no project paths, IDs, or names/slugs referenced) -> `classification="general"`.
    """
    by_cpath: Mapping[str, Mapping[str, Any]] = project_index["by_canonical_path"]
    by_raw: Mapping[str, str] = project_index["by_raw_path"]
    by_pid: Mapping[str, list[str]] = project_index["by_project_id"]
    by_name: Mapping[str, list[str]] = project_index["by_name_lower"]
    by_slug: Mapping[str, list[str]] = project_index["by_slug_lower"]

    exact_matches: set[str] = set()
    matched_via: list[str] = []

    # 1a. Check extracted paths against registered canonical/raw project paths
    for p_item in extracted_paths:
        res_p = str(p_item.get("resolved_path") or "")
        if not res_p:
            continue
        for raw_proj_path, target_cpath in sorted(by_raw.items(), key=lambda x: (-len(x[0]), x[0])):
            if _is_under_root(res_p, raw_proj_path):
                exact_matches.add(target_cpath)
                matched_via.append(f"path:{p_item.get('raw_path')}")
                break

    # 1b. Check exact hermes_project_id tokens in text
    for pid, cpaths in sorted(by_pid.items()):
        if len(pid) >= 4 and re.search(rf"(?<![A-Za-z0-9_-]){re.escape(pid)}(?![A-Za-z0-9_-])", entry_text):
            if len(cpaths) == 1:
                exact_matches.add(cpaths[0])
                matched_via.append(f"project_id:{pid}")
            else:
                return {
                    "mapping_status": "ambiguous",
                    "matched_projects": [],
                    "candidate_projects": list(cpaths),
                    "matched_via": [f"ambiguous_project_id:{pid}"],
                }

    if exact_matches:
        sorted_exact = sorted(exact_matches)
        return {
            "mapping_status": "mapped",
            "matched_projects": sorted_exact,
            "candidate_projects": sorted_exact,
            "matched_via": sorted(set(matched_via)),
        }

    # 2. Check project names / slugs in text (never silently choosing when ambiguous)
    ambiguous_candidates: set[str] = set()
    ambiguous_tokens: list[str] = []
    unique_name_matches: set[str] = set()
    unique_tokens: list[str] = []

    combined_tokens: dict[str, list[str]] = {}
    for token_str, cpaths in by_slug.items():
        if len(token_str) >= 3:
            combined_tokens.setdefault(token_str, []).extend(cpaths)
    for token_str, cpaths in by_name.items():
        if len(token_str) >= 3:
            combined_tokens.setdefault(token_str, []).extend(cpaths)

    for token_str, raw_cpaths in sorted(combined_tokens.items()):
        cpaths = sorted(set(raw_cpaths))
        pattern = rf"(?<![A-Za-z0-9_/-]){re.escape(token_str)}(?![A-Za-z0-9_/-])"
        if re.search(pattern, entry_text, flags=re.IGNORECASE):
            if len(cpaths) > 1:
                ambiguous_candidates.update(cpaths)
                ambiguous_tokens.append(token_str)
            else:
                unique_name_matches.add(cpaths[0])
                unique_tokens.append(token_str)

    if ambiguous_candidates:
        return {
            "mapping_status": "ambiguous",
            "matched_projects": [],
            "candidate_projects": sorted(ambiguous_candidates | unique_name_matches),
            "matched_via": [f"ambiguous_name:{t}" for t in sorted(set(ambiguous_tokens))],
        }

    if len(unique_name_matches) > 1:
        # Entry mentions multiple different project names without an exact path/ID to disambiguate
        return {
            "mapping_status": "ambiguous",
            "matched_projects": [],
            "candidate_projects": sorted(unique_name_matches),
            "matched_via": [f"multiple_names:{t}" for t in sorted(set(unique_tokens))],
        }

    if len(unique_name_matches) == 1:
        only_proj = next(iter(unique_name_matches))
        return {
            "mapping_status": "mapped",
            "matched_projects": [only_proj],
            "candidate_projects": [only_proj],
            "matched_via": [f"name_or_slug:{t}" for t in sorted(set(unique_tokens))],
        }

    # 3. If the entry had filesystem paths that didn't match any registered project -> unmatched
    if extracted_paths:
        return {
            "mapping_status": "unmatched",
            "matched_projects": [],
            "candidate_projects": [],
            "matched_via": [f"unmatched_path:{p['raw_path']}" for p in extracted_paths],
        }

    # 4. General preference / environment note
    return {
        "mapping_status": "general",
        "matched_projects": [],
        "candidate_projects": [],
        "matched_via": [],
    }


def _evaluate_path_reference(
    *,
    raw_path: str,
    resolved_path: str,
    path_observations: Mapping[str, Mapping[str, Any]],
    accessible_namespace_roots: Sequence[str],
    local_identity_verified: bool,
) -> dict[str, Any]:
    """Evaluate a path reference in a memory entry per §5:
    - Missing paths are stale ONLY when local identity and accessible namespace establish absence.
    - If local identity is unverified, or path is outside accessible_namespace_roots, or observation
      is missing/unreadable -> `status="could_not_verify"`, `coverage="could_not_verify"`.
    """
    obs = path_observations.get(resolved_path) or path_observations.get(raw_path)
    if not local_identity_verified:
        return {
            "raw_path": raw_path,
            "resolved_path": resolved_path,
            "status": "could_not_verify",
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "reason": "local_identity_unverified",
        }

    if isinstance(obs, Mapping):
        if obs.get("on_local_machine") is False:
            return {
                "raw_path": raw_path,
                "resolved_path": resolved_path,
                "status": "could_not_verify",
                "coverage": COVERAGE_COULD_NOT_VERIFY,
                "reason": "foreign_host_path",
            }
        ns_accessible = bool(obs.get("namespace_accessible", True))
        obs_cov = str(obs.get("coverage") or COVERAGE_VERIFIED)
        exists_val = obs.get("exists")
        if not ns_accessible or obs_cov != COVERAGE_VERIFIED or not isinstance(exists_val, bool):
            return {
                "raw_path": raw_path,
                "resolved_path": resolved_path,
                "status": "could_not_verify",
                "coverage": COVERAGE_COULD_NOT_VERIFY,
                "reason": str(obs.get("reason") or "namespace_inaccessible_or_unverified"),
            }
        return {
            "raw_path": raw_path,
            "resolved_path": resolved_path,
            "status": "exists" if exists_val else "missing_stale",
            "coverage": COVERAGE_VERIFIED,
            "reason": "verified_present" if exists_val else "verified_absent_in_accessible_namespace",
        }

    # Check if resolved_path falls under an explicitly accessible namespace root
    in_accessible_ns = any(
        _is_under_root(resolved_path, _norm_posix(ns_root))
        for ns_root in accessible_namespace_roots
        if str(ns_root).strip()
    )
    return {
        "raw_path": raw_path,
        "resolved_path": resolved_path,
        "status": "could_not_verify",
        "coverage": COVERAGE_COULD_NOT_VERIFY,
        "reason": "no_path_observation" if in_accessible_ns else "outside_accessible_namespace",
    }


def audit_profile_memory(
    *,
    profile_name: str,
    memory_facts: Mapping[str, Any],
    registered_projects: Sequence[Mapping[str, Any]] = (),
    as_of: int | float | None = None,
    stale_age_days: int = 90,
    home_dir: str | None = None,
    local_identity_verified: bool = True,
    accessible_namespace_roots: Sequence[str] = (),
    path_observations: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Audit a profile's built-in memory entries (`MEMORY.md` and `USER.md`) per §5, §6, §8, §11, §12, §13.5.

    Parameters:
    - `profile_name`: Official profile identity (`"default"`, `"coder"`, etc.).
    - `memory_facts`: Plain-data dict from `audit/facts.py:resolve_profile_memory_facts`
      (or `profile_unit_facts["memory"]`).
    - `registered_projects`: Unioned project units or registration records from `readonly_db.py`.
    - `as_of`: Captured reference unix timestamp for deterministic entry-age evaluation (§4, §12).
    - `stale_age_days`: Age threshold in days for authoritative entry timestamps (default 90).
    - `home_dir`: Explicit home path string for expanding `~/...` references inside memory text
      (never calls `os.path.expanduser` or `Path.home()`).
    - `local_identity_verified`: Whether the paths in memory belong to the inspected local machine.
    - `accessible_namespace_roots`: Explicitly verified readable root directories on the local host.
    - `path_observations`: Mapping of `path -> {"exists": bool, "namespace_accessible": bool, "on_local_machine": bool, "coverage": str}`
      produced by the step-1 fact adapter.
    """
    pname = str(profile_name or "").strip()
    if not pname:
        return _make_envelope(
            findings=[],
            coverage=COVERAGE_COULD_NOT_VERIFY,
            error="profile_name must be non-empty",
        )
    if not isinstance(memory_facts, Mapping):
        return _make_envelope(
            findings=[],
            coverage=COVERAGE_COULD_NOT_VERIFY,
            error="memory_facts must be a mapping",
        )

    findings: list[dict[str, Any]] = []
    overall_coverage = str(memory_facts.get("coverage") or COVERAGE_VERIFIED)
    if overall_coverage not in VALID_COVERAGES:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    obs_map: Mapping[str, Mapping[str, Any]] = path_observations if isinstance(path_observations, Mapping) else {}
    proj_index = _index_registered_projects(registered_projects, home_dir=home_dir)
    by_cpath = proj_index["by_canonical_path"]

    raw_files = memory_facts.get("files")
    files_map: Mapping[str, Any] = raw_files if isinstance(raw_files, Mapping) else {}
    all_entry_records: list[dict[str, Any]] = []

    for store_key in ("memory", "user"):
        f_info = files_map.get(store_key)
        if not isinstance(f_info, Mapping):
            continue
        f_path = str(f_info.get("path") or f"memories/{'USER.md' if store_key == 'user' else 'MEMORY.md'}")
        f_cov = str(f_info.get("coverage") or COVERAGE_VERIFIED)
        f_symlink = bool(f_info.get("is_symlink", False))
        f_mtime_ns = f_info.get("file_mtime_ns")

        if f_symlink:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="memory.symlink_store",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[pname],
                    source_paths=[f_path],
                    evidence={
                        "profile": pname,
                        "store": store_key,
                        "path": f_path,
                        "symlink_target": f_info.get("symlink_target"),
                    },
                    consequence=(
                        f"Profile {pname!r} {store_key} store ({f_path}) is a symlink "
                        f"to {f_info.get('symlink_target')!r}; entries could not be verified as profile-isolated."
                    ),
                    limitations="Symlinked memory files are recorded as link metadata without following outside allowed roots.",
                )
            )
            continue

        if f_cov != COVERAGE_VERIFIED:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="memory.store_unreadable",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[pname],
                    source_paths=[f_path],
                    evidence={
                        "profile": pname,
                        "store": store_key,
                        "path": f_path,
                        "error": f_info.get("error") or "unreadable memory file",
                    },
                    consequence=f"Profile {pname!r} {store_key} store ({f_path}) could not be safely read.",
                    limitations="Unreadable or mid-read mutated memory files cannot be inspected.",
                )
            )
            continue

        raw_entries_seq = f_info.get("entries")
        entries_seq: Sequence[Any] = raw_entries_seq if isinstance(raw_entries_seq, Sequence) else ()
        for idx, raw_entry in enumerate(entries_seq):
            if isinstance(raw_entry, Mapping):
                text = str(raw_entry.get("text") or "").strip()
                entry_idx = int(raw_entry.get("index", idx))
                sha_exact = str(
                    raw_entry.get("sha256_exact")
                    or hashlib.sha256(text.encode("utf-8")).hexdigest()
                )
                norm_ws = " ".join(text.split())
                sha_ws = str(
                    raw_entry.get("sha256_normalized_ws")
                    or hashlib.sha256(norm_ws.encode("utf-8")).hexdigest()
                )
                auth_created_at = raw_entry.get("authoritative_created_at")
            elif isinstance(raw_entry, str):
                text = raw_entry.strip()
                entry_idx = idx
                sha_exact = hashlib.sha256(text.encode("utf-8")).hexdigest()
                norm_ws = " ".join(text.split())
                sha_ws = hashlib.sha256(norm_ws.encode("utf-8")).hexdigest()
                auth_created_at = None
            else:
                continue

            if not text:
                continue

            entry_id = f"{pname}:{store_key}:{entry_idx}"
            extracted_paths = _extract_paths_from_text(text, home_dir=home_dir)
            mapping_res = _map_entry_to_projects(
                entry_text=text,
                extracted_paths=extracted_paths,
                project_index=proj_index,
            )

            # Evaluate path references (§5)
            path_evals: list[dict[str, Any]] = []
            for p_ref in extracted_paths:
                pe = _evaluate_path_reference(
                    raw_path=p_ref["raw_path"],
                    resolved_path=p_ref["resolved_path"],
                    path_observations=obs_map,
                    accessible_namespace_roots=accessible_namespace_roots,
                    local_identity_verified=local_identity_verified,
                )
                path_evals.append(pe)
                if pe["coverage"] == COVERAGE_COULD_NOT_VERIFY:
                    overall_coverage = COVERAGE_COULD_NOT_VERIFY

            # Evaluate authoritative entry age vs file mtime (§5, §12: file mtime is NEVER an entry birth date)
            age_days: float | None = None
            age_coverage = COVERAGE_COULD_NOT_VERIFY
            is_stale_by_age: bool | None = None
            if isinstance(auth_created_at, (int, float)) and auth_created_at > 0 and isinstance(as_of, (int, float)):
                age_sec = max(0.0, float(as_of) - float(auth_created_at))
                age_days = round(age_sec / 86400.0, 4)
                age_coverage = COVERAGE_VERIFIED
                is_stale_by_age = age_days > float(stale_age_days)
            else:
                # Without authoritative per-entry metadata, entry age is unknown (`could_not_verify`), never derived from file_mtime_ns
                overall_coverage = COVERAGE_COULD_NOT_VERIFY

            has_directive_phrasing = bool(_HEURISTIC_DIRECTIVE_RE.search(text))

            rec = {
                "entry_id": entry_id,
                "profile_name": pname,
                "store": store_key,
                "path": f_path,
                "index": entry_idx,
                "text": text,
                "char_count": len(text),
                "sha256_exact": sha_exact,
                "sha256_normalized_ws": sha_ws,
                "authoritative_created_at": float(auth_created_at) if isinstance(auth_created_at, (int, float)) else None,
                "file_mtime_ns_metadata_only": int(f_mtime_ns) if isinstance(f_mtime_ns, int) else None,
                "age_days": age_days,
                "age_coverage": age_coverage,
                "is_stale_by_age": is_stale_by_age,
                "paths": path_evals,
                "project_mapping": mapping_res,
                "has_directive_phrasing": has_directive_phrasing,
            }
            all_entry_records.append(rec)

    # 1. Duplicate checks within the profile (across MEMORY.md and USER.md) (§5, §8, §13.5)
    by_exact: dict[str, list[dict[str, Any]]] = {}
    by_ws: dict[str, list[dict[str, Any]]] = {}
    for rec in all_entry_records:
        by_exact.setdefault(rec["sha256_exact"], []).append(rec)
        by_ws.setdefault(rec["sha256_normalized_ws"], []).append(rec)

    for exact_sha, group in sorted(by_exact.items()):
        if len(group) > 1:
            cleanup_id = f"cleanup.memory.exact_duplicate.{pname}.{exact_sha[:12]}"
            findings.append(
                _make_finding(
                    rule_id="memory.duplicate_entry_exact",
                    classification=CLASSIFICATION_WARNING,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[pname],
                    source_paths=[g["path"] for g in group],
                    evidence={
                        "profile": pname,
                        "sha256_exact": exact_sha,
                        "duplicate_count": len(group),
                        "entries": [
                            {
                                "entry_id": g["entry_id"],
                                "store": g["store"],
                                "index": g["index"],
                                "path": g["path"],
                            }
                            for g in group
                        ],
                        "selected_by_default": False,
                    },
                    consequence=(
                        f"Profile {pname!r} contains {len(group)} byte-identical memory entries, "
                        "wasting prompt budget on every session."
                    ),
                    limitations="Exact byte-for-byte duplicate match.",
                    proposed_cleanup_id=cleanup_id,
                )
            )

    for ws_sha, group in sorted(by_ws.items()):
        if len(group) > 1:
            distinct_exact = {g["sha256_exact"] for g in group}
            if len(distinct_exact) > 1:
                # Whitespace-normalized match that is NOT byte-identical -> review_suggested and NEVER cleanup-eligible (§5, §13.5)
                findings.append(
                    _make_finding(
                        rule_id="memory.duplicate_entry_similar_whitespace",
                        classification=CLASSIFICATION_REVIEW,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[pname],
                        source_paths=[g["path"] for g in group],
                        evidence={
                            "profile": pname,
                            "sha256_normalized_ws": ws_sha,
                            "distinct_exact_hashes": sorted(distinct_exact),
                            "entries": [
                                {
                                    "entry_id": g["entry_id"],
                                    "store": g["store"],
                                    "index": g["index"],
                                    "path": g["path"],
                                }
                                for g in group
                            ],
                            "cleanup_eligible": False,
                        },
                        consequence=(
                            f"Profile {pname!r} has {len(group)} memory entries that match after whitespace "
                            "normalization but differ in exact bytes."
                        ),
                        limitations="Whitespace-normalized matches require human review and are never eligible for automated duplicate removal.",
                        proposed_cleanup_id=None,
                    )
                )

    # 2. Per-entry checks: missing paths, ambiguous project names, cross-project exposure, authoritative age, operational directives
    for rec in all_entry_records:
        eid = rec["entry_id"]
        f_path = rec["path"]
        mapping = rec["project_mapping"]
        map_status = mapping["mapping_status"]

        # 2a. Missing path staleness vs unverified paths (§5)
        for pe in rec["paths"]:
            if pe["status"] == "missing_stale":
                findings.append(
                    _make_finding(
                        rule_id="memory.stale_missing_path",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[pname],
                        source_paths=[f_path],
                        evidence={
                            "profile": pname,
                            "entry_id": eid,
                            "raw_path": pe["raw_path"],
                            "resolved_path": pe["resolved_path"],
                            "reason": pe["reason"],
                        },
                        consequence=(
                            f"Memory entry {eid} references local path {pe['raw_path']!r} which no longer exists "
                            "in the accessible filesystem namespace, steering the agent toward a dead path."
                        ),
                        limitations="Verified against local identity and accessible namespace roots.",
                    )
                )
            elif pe["status"] == "could_not_verify":
                findings.append(
                    _make_finding(
                        rule_id="memory.path_reference_unverified",
                        classification=CLASSIFICATION_INFO,
                        coverage=COVERAGE_COULD_NOT_VERIFY,
                        affected_identities=[pname],
                        source_paths=[f_path],
                        evidence={
                            "profile": pname,
                            "entry_id": eid,
                            "raw_path": pe["raw_path"],
                            "resolved_path": pe["resolved_path"],
                            "reason": pe["reason"],
                        },
                        consequence=(
                            f"Memory entry {eid} references path {pe['raw_path']!r} whose existence could not "
                            f"be verified ({pe['reason']})."
                        ),
                        limitations="Missing paths are flagged stale only when local identity and accessible namespace establish absence.",
                    )
                )

        # 2b. Ambiguous project mapping (§5)
        if map_status == "ambiguous":
            findings.append(
                _make_finding(
                    rule_id="memory.ambiguous_project_mapping",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[pname, *mapping["candidate_projects"]],
                    source_paths=[f_path],
                    evidence={
                        "profile": pname,
                        "entry_id": eid,
                        "candidate_projects": mapping["candidate_projects"],
                        "matched_via": mapping["matched_via"],
                    },
                    consequence=(
                        f"Memory entry {eid} in profile {pname!r} matches multiple registered projects "
                        f"({', '.join(mapping['candidate_projects'])}); audit refuses to guess which project owns it."
                    ),
                    limitations="Ambiguous project names/slugs require explicit path or project ID disambiguation.",
                )
            )

        # 2c. Proven cross-project exposure (§5: entry mapped to a project registered ONLY in other profiles,
        # or profile has multiple registered projects and global memory injects project-specific facts/directives into all of them)
        matched_projs = mapping["matched_projects"]
        foreign_owned_projs: list[str] = []
        profile_owned_projs = [
            cp for cp, pmeta in by_cpath.items() if pname in (pmeta.get("owning_profiles") or ())
        ]
        for mp in matched_projs:
            pmeta = by_cpath.get(mp)
            owners = pmeta.get("owning_profiles") if isinstance(pmeta, Mapping) else ()
            if owners and pname not in owners:
                foreign_owned_projs.append(mp)

        is_cross_project_exposed = bool(foreign_owned_projs) or (
            bool(matched_projs) and len(profile_owned_projs) > 1
        )
        if is_cross_project_exposed:
            findings.append(
                _make_finding(
                    rule_id="memory.cross_project_exposure",
                    classification=CLASSIFICATION_WARNING,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[pname, *matched_projs],
                    source_paths=[f_path],
                    evidence={
                        "profile": pname,
                        "entry_id": eid,
                        "matched_projects": matched_projs,
                        "foreign_owned_projects": foreign_owned_projs,
                        "profile_registered_project_count": len(profile_owned_projs),
                        "has_directive_phrasing": rec["has_directive_phrasing"],
                    },
                    consequence=(
                        f"Memory entry {eid} in profile {pname!r} is scoped to project {', '.join(matched_projs)} "
                        "but built-in profile memory is injected into every project session run under this profile."
                    ),
                    limitations="Built-in MEMORY.md and USER.md are profile-wide, not per-project.",
                )
            )

        # 2d. Operational directives (§5: unrelated operational directives / proven cross-project carry warning;
        # heuristic interpretation is review_suggested)
        if rec["has_directive_phrasing"]:
            if is_cross_project_exposed or map_status == "unmatched":
                findings.append(
                    _make_finding(
                        rule_id="memory.unrelated_operational_directive",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[pname, *matched_projs],
                        source_paths=[f_path],
                        evidence={
                            "profile": pname,
                            "entry_id": eid,
                            "mapping_status": map_status,
                            "matched_projects": matched_projs,
                        },
                        consequence=(
                            f"Memory entry {eid} in profile {pname!r} contains an operational directive tied to "
                            "another/unmatched project context that overrides behavior across unrelated sessions."
                        ),
                        limitations="",
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        rule_id="memory.heuristic_operational_directive",
                        classification=CLASSIFICATION_REVIEW,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[pname],
                        source_paths=[f_path],
                        evidence={
                            "profile": pname,
                            "entry_id": eid,
                            "mapping_status": map_status,
                        },
                        consequence=(
                            f"Memory entry {eid} in profile {pname!r} uses imperative directive phrasing "
                            "which may act as a standing instruction rather than a declarative fact."
                        ),
                        limitations="Heuristic keyword detection; human review suggested to confirm intent.",
                    )
                )

        # 2e. Authoritative entry age (§5, §12)
        if rec["age_coverage"] == COVERAGE_VERIFIED and rec["is_stale_by_age"]:
            findings.append(
                _make_finding(
                    rule_id="memory.authoritative_entry_stale",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[pname],
                    source_paths=[f_path],
                    evidence={
                        "profile": pname,
                        "entry_id": eid,
                        "authoritative_created_at": rec["authoritative_created_at"],
                        "as_of": as_of,
                        "age_days": rec["age_days"],
                        "stale_age_days": stale_age_days,
                    },
                    consequence=(
                        f"Memory entry {eid} in profile {pname!r} has an authoritative age of "
                        f"{rec['age_days']:.1f} days (older than {stale_age_days} days)."
                    ),
                    limitations="",
                )
            )

    if any(r["age_coverage"] == COVERAGE_COULD_NOT_VERIFY for r in all_entry_records):
        findings.append(
            _make_finding(
                rule_id="memory.entry_age_unverified",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[pname],
                source_paths=sorted({r["path"] for r in all_entry_records}),
                evidence={
                    "profile": pname,
                    "unverified_entry_count": sum(
                        1 for r in all_entry_records if r["age_coverage"] == COVERAGE_COULD_NOT_VERIFY
                    ),
                },
                consequence=(
                    f"Built-in memory entries in profile {pname!r} do not carry per-entry creation timestamps; "
                    "entry age could not be verified."
                ),
                limitations="File mtime is never used as an entry birth date (§5, §12).",
            )
        )

    mapping_counts = {
        "mapped": sum(1 for r in all_entry_records if r["project_mapping"]["mapping_status"] == "mapped"),
        "ambiguous": sum(1 for r in all_entry_records if r["project_mapping"]["mapping_status"] == "ambiguous"),
        "unmatched": sum(1 for r in all_entry_records if r["project_mapping"]["mapping_status"] == "unmatched"),
        "general": sum(1 for r in all_entry_records if r["project_mapping"]["mapping_status"] == "general"),
    }

    return _make_envelope(
        findings=findings,
        coverage=overall_coverage,
        extra={
            "component_version": COMPONENT_VERSION,
            "profile_name": pname,
            "entry_count": len(all_entry_records),
            "mapping_counts": mapping_counts,
            "entries": all_entry_records,
        },
    )
