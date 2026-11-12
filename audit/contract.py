"""Coverage, classification, finding, and headline contract for the Defuzz audit.

Layered on top of the legacy component envelope of the vendored audit components (§6, §13.2):
- Components keep emitting {ok, status, error, findings} plus coverage + classification.
- The plugin adapter computes the headline strictly from (classification, coverage)
  and ignores legacy `status` / `ok`.
- Operational component errors (`status == "error"`) map to coverage="could_not_verify",
  never product severity.
- Unknown or incomplete evidence never becomes a clean/passed verdict.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from . import evidence as _evidence
from . import evidence_constants as _evidence_constants
from . import persistence as _persistence
from .policy import (
    DECLARATION_SOURCE_FILES as _DECLARATION_SOURCE_FILES,
    credential_declarations as _credential_declarations,
    credential_path as _credential_path,
)
from .redaction import _CURRENT as _REDACTION_CURRENT
from .. import templates as _templates

CONTRACT_VERSION = "2.0.0"
FIXED_AUDIT_DISCLOSURE = "This audit cannot tell whether working code is correct."

CLASSIFICATION_WARNING = "warning"
CLASSIFICATION_REVIEW = "review_suggested"
CLASSIFICATION_INFO = "info"
VALID_CLASSIFICATIONS: frozenset[str] = frozenset({
    CLASSIFICATION_WARNING, CLASSIFICATION_REVIEW, CLASSIFICATION_INFO,
})

COVERAGE_VERIFIED = "verified"
COVERAGE_COULD_NOT_VERIFY = "could_not_verify"
COVERAGE_NOT_INCLUDED = "not_included"
VALID_COVERAGES: frozenset[str] = frozenset({
    COVERAGE_VERIFIED, COVERAGE_COULD_NOT_VERIFY, COVERAGE_NOT_INCLUDED,
})


# LOCAL PATCH golden-template-registry-v1: list template directory names without reading file contents at import.
def discover_golden_template_ids() -> frozenset[str]:
    """Return golden template directory names under templates_root() using os.scandir only (zero file reads)."""
    try:
        base = Path(_templates.templates_root())
        if not base.exists() or base.is_symlink() or not base.is_dir():
            return frozenset()
        ids: set[str] = set()
        with os.scandir(base) as it:
            for entry in it:
                try:
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                    if os.path.lexists(os.path.join(entry.path, "template.yaml")):
                        ids.add(entry.name)
                except OSError:
                    continue
        return frozenset(ids)
    except OSError:
        return frozenset()


def _preflight_template_dir_declarations(entry_path: Path, repo_root: Path, state: Any) -> None:
    """Run declaration preflight on a non-excluded template directory, checking directory and source exclusions first."""
    if state is None or _credential_path(entry_path):
        return
    done_dirs = getattr(state, "_golden_preflight_dirs", None)
    if done_dirs is None:
        done_dirs = set()
        state._golden_preflight_dirs = done_dirs
    entry_abs = os.path.abspath(entry_path)
    if entry_abs in done_dirs:
        return
    try:
        st = entry_path.lstat()
    except OSError:
        return
    if os.path.islink(entry_path) or not os.path.isdir(entry_path):
        return
    del st
    candidates: list[Path] = []
    for name in _DECLARATION_SOURCE_FILES:
        if "*" in name:
            candidates.extend(entry_path.glob(name))
        else:
            candidates.append(entry_path / name)
    allowed_candidates: list[Path] = []
    for cand in candidates:
        if _credential_path(entry_path) or _credential_path(cand):
            continue
        allowed_candidates.append(cand)
    if not allowed_candidates:
        done_dirs.add(entry_abs)
        return
    sources = getattr(state, "declaration_sources", set())
    sources.update(os.path.abspath(p) for p in allowed_candidates)
    state.declaration_sources = sources
    for cand in allowed_candidates:
        state.declaration_anchors[os.path.abspath(cand)] = Path(entry_abs)
    state.credential_paths.difference_update(sources)
    for cand in allowed_candidates:
        if _credential_path(entry_path):
            break
        _credential_declarations(cand, repo_root, excluded_paths=state.credential_paths)
    done_dirs.add(entry_abs)


def _load_golden_manifests(
    eligible_entries: list[tuple[str, Path, Path]],
    specs: dict[str, Any],
    excluded: set[str],
    invalid: dict[str, str],
) -> None:
    # Imported here: fingerprint imports this module at its top.
    from .fingerprint import CredentialStoreNotOpened, open_checked

    for entry_name, entry_path, yaml_path in eligible_entries:
        if _credential_path(entry_path) or _credential_path(yaml_path):
            excluded.add(entry_name)
            continue
        try:
            # The opened template.yaml is checked again before a byte is read.
            spec = _templates.load_template(entry_path, opener=open_checked)
            specs[spec.id] = spec
        except CredentialStoreNotOpened:
            excluded.add(entry_name)
        except (_templates.TemplateError, OSError, ValueError) as exc:
            invalid[entry_name] = type(exc).__name__


def resolve_runtime_golden_registry() -> dict[str, Any]:
    """Load and validate the golden template registry at run time after declaration preflight (cached per audit run)."""
    state = _REDACTION_CURRENT.get()
    base = Path(_templates.templates_root())
    load_fn = getattr(_templates, "load_templates", None)

    discovered: set[str] = set()
    invalid: dict[str, str] = {}
    excluded: set[str] = set()
    specs: dict[str, Any] = {}
    registry_available = True
    registry_reason: str | None = None
    eligible_entries: list[tuple[str, Path, Path]] = []

    try:
        if not base.exists() or base.is_symlink() or not base.is_dir():
            registry_available = False
            registry_reason = "templates_root_missing_or_invalid"
        else:
            repo_root = base.parent
            if _credential_path(base):
                registry_available = False
                registry_reason = "templates_root_excluded_by_credential_policy"
            else:
                with os.scandir(base) as it:
                    entries = sorted(it, key=lambda e: e.name)
                # Phase A: enumerate eligible template directories and run declaration preflight
                # over non-excluded directories before checking/loading any template.yaml.
                for entry in entries:
                    try:
                        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        registry_available = False
                        invalid[entry.name] = "template_dir_unreadable"
                        continue
                    entry_path = Path(entry.path)
                    yaml_path = entry_path / "template.yaml"
                    if not os.path.lexists(yaml_path):
                        continue
                    discovered.add(entry.name)
                    eligible_entries.append((entry.name, entry_path, yaml_path))
                    if state is not None and not _credential_path(entry_path):
                        _preflight_template_dir_declarations(entry_path, repo_root, state)
    except OSError as exc:
        registry_available = False
        registry_reason = type(exc).__name__

    # Check cache after Phase A finalized credential declarations so repeated calls
    # within the same redaction_scope reuse the loaded manifests instead of re-reading them.
    cache_key = (
        str(base),
        id(load_fn),
        frozenset(getattr(state, "credential_paths", ())) if state is not None else frozenset(),
        frozenset(getattr(state, "credential_uncertain_roots", ())) if state is not None else frozenset(),
    )
    if state is not None:
        cached = getattr(state, "_golden_registry_cache", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
            return cached[1]

    # Phase B: load template manifests using the finalized credential exclusion set.
    if registry_available:
        _load_golden_manifests(eligible_entries, specs, excluded, invalid)

    # Support test overrides of templates.load_templates when custom specs are injected.
    if callable(load_fn) and getattr(load_fn, "__name__", "") != "load_templates":
        try:
            custom_specs = load_fn(excluded=_credential_path)
            if isinstance(custom_specs, Iterable):
                for extra_spec in custom_specs:
                    sid = getattr(extra_spec, "id", None)
                    if isinstance(sid, str) and sid:
                        discovered.add(sid)
                        specs[sid] = extra_spec
        except Exception as exc:
            registry_available = False
            registry_reason = type(exc).__name__

    info: dict[str, Any] = {
        "available": registry_available,
        "reason": registry_reason,
        "discovered_ids": frozenset(discovered),
        "specs": specs,
        "excluded_ids": frozenset(excluded),
        "invalid_ids": invalid,
    }
    if state is not None:
        state._golden_registry_cache = (cache_key, info)
    return info


GOLDEN_TEMPLATE_IDS: frozenset[str] = discover_golden_template_ids()

_CLASSIFICATION_RANK: dict[str, int] = {
    CLASSIFICATION_WARNING: 3,
    CLASSIFICATION_REVIEW: 2,
    CLASSIFICATION_INFO: 1,
}

_LEGACY_SEVERITY_TO_CLASSIFICATION: dict[str, str] = {
    "error": CLASSIFICATION_WARNING,
    "warning": CLASSIFICATION_WARNING,
    "warn": CLASSIFICATION_WARNING,
    "review_suggested": CLASSIFICATION_REVIEW,
    "review": CLASSIFICATION_REVIEW,
    "info": CLASSIFICATION_INFO,
}

_CLASSIFICATION_TO_LEGACY_SEVERITY: dict[str, str] = {
    CLASSIFICATION_WARNING: "warn",
    CLASSIFICATION_REVIEW: "warn",
    CLASSIFICATION_INFO: "info",
}

# Executable fix keys prohibited inside finding["evidence"] (§5: no executable fixes embedded in evidence).
_FORBIDDEN_EVIDENCE_KEYS: frozenset[str] = frozenset({
    "cmd", "command", "commands", "script", "shell_cmd",
    "executable_fix", "fix_cmd", "fix_command", "fix_script", "argv",
})

# Secret-like key patterns redacted if ever passed into evidence dicts (§3: never load .env/auth secret values).
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret|auth[_-]?token|credential)s?(?:$|_)"
)
_TOKEN_COUNT_EVIDENCE_KEYS: frozenset[str] = frozenset({
    "auto_loaded_skill_tokens", "estimated_tokens", "exact_tokens",
    "fixed_prompt_estimated_tokens", "fixed_prompt_tokens", "injected_tokens",
    "largest_auto_loaded_estimated_tokens", "largest_project_estimated_tokens",
    "memory_tokens", "persona_injected_tokens",
    "project_context_additions_estimated_tokens", "project_context_tokens",
    "review_suggested_tokens", "review_window_tokens",
    "skills_index_tokens", "static_base_estimated_tokens", "threshold_tokens",
    "token_threshold", "tokens",
    "total_static_base_estimated_tokens", "warning_tokens", "warning_window_tokens",
})

_CLEANUP_ID_FORBIDDEN_CHARS = ("\n", "\r", ";", "|", "&", "`", "$(")
_STRUCTURED_CONTENT_FIELDS = (
    "id", "rule_id", "consequence", "detail", "limitations",
    "fix", "proposed_cleanup_id", "affected_identities", "source_paths",
)
_PLAIN_TEXT_FINDING_FIELDS = (
    "id", "rule_id", "classification", "coverage", "severity",
    "detail", "consequence", "limitations", "proposed_cleanup_id", "fix",
)
_ENVELOPE_METADATA_KEYS = frozenset({
    "run_id", "started_at", "finished_at", "execution_timestamp", "elapsed_ms",
})


def normalize_classification(
    classification: str | None = None, *, legacy_severity: str | None = None
) -> str:
    """Resolve a finding classification from explicit `classification` or legacy `severity`."""
    if classification is not None:
        norm = str(classification).strip().lower()
        if norm in VALID_CLASSIFICATIONS:
            return norm
        if norm in _LEGACY_SEVERITY_TO_CLASSIFICATION:
            return _LEGACY_SEVERITY_TO_CLASSIFICATION[norm]
        raise ValueError(f"Invalid audit classification: {classification!r}")
    if legacy_severity is not None:
        norm_sev = str(legacy_severity).strip().lower()
        if norm_sev in _LEGACY_SEVERITY_TO_CLASSIFICATION:
            return _LEGACY_SEVERITY_TO_CLASSIFICATION[norm_sev]
        raise ValueError(f"Invalid legacy finding severity: {legacy_severity!r}")
    return CLASSIFICATION_INFO


def normalize_coverage(coverage: str | None = None) -> str:
    """Validate and normalize a coverage token."""
    if coverage is None:
        return COVERAGE_VERIFIED
    norm = str(coverage).strip().lower().replace(" ", "_").replace("-", "_")
    if norm in VALID_COVERAGES:
        return norm
    raise ValueError(f"Invalid audit coverage: {coverage!r}")


def sanitize_evidence(value: Any, *, _key_hint: str = "") -> Any:
    """Ensure evidence is plain JSON-ready data with no callables, no executable fix fields, and redacted secrets."""
    if callable(value):
        raise ValueError("Callable objects are forbidden in audit finding evidence")
    if _key_hint and _key_hint.lower() in _FORBIDDEN_EVIDENCE_KEYS:
        raise ValueError(f"Executable fix field {_key_hint!r} is forbidden inside finding evidence")
    is_numeric_token_metric = (
        _key_hint in _TOKEN_COUNT_EVIDENCE_KEYS
        and type(value) in (int, float)
    )
    if _key_hint and not is_numeric_token_metric and _SECRET_KEY_RE.search(_key_hint):
        return "<redacted>"
    if isinstance(value, (_evidence.SealedEvidence, _evidence.GeneratedDigest)):
        return _evidence.serialize_evidence(value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite audit number")
    if value is None or type(value) in (bool, int, float, str):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(k, str) for k in value):
            raise ValueError("Audit JSON keys must be strings")
        out: dict[str, Any] = {}
        for k, v in sorted(value.items(), key=lambda item: str(item[0])):
            k_str = k if isinstance(k, _evidence.SealedKey) else str(k)
            if k_str.lower() in _FORBIDDEN_EVIDENCE_KEYS:
                raise ValueError(f"Executable fix field {k_str!r} is forbidden inside finding evidence")
            out[k_str] = sanitize_evidence(v, _key_hint=k_str)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize_evidence(item) for item in value]
    raise ValueError("Audit data must contain only typed JSON values")


def normalize_source_paths(source_paths: Sequence[Mapping[str, Any] | str] | None) -> list[dict[str, Any]]:
    """Normalize source path/range descriptors into sorted canonical dicts."""
    if not source_paths:
        return []
    if not isinstance(source_paths, (list, tuple)):
        raise ValueError("Source paths must be a sequence")
    normalized: list[dict[str, Any]] = []
    for entry in source_paths:
        if isinstance(entry, str):
            normalized.append({"path": entry, "start_line": None, "end_line": None})
        elif isinstance(entry, Mapping):
            path_value = entry.get("path")
            reason = entry.get("path_withheld")
            for field in ("start_line", "end_line", "line"):
                if entry.get(field) is not None and type(entry[field]) is not int:
                    raise ValueError("Source line must be an integer")
            start_line = entry.get("start_line", entry.get("line"))
            end_line = entry.get("end_line", start_line)
            start = int(start_line) if isinstance(start_line, int) and start_line > 0 else None
            end = int(end_line) if isinstance(end_line, int) and end_line > 0 else None
            # A path the evidence gate already withheld must stay withheld. Rebuilding
            # it as "" drops the reason and seals an empty string instead.
            if path_value is None and isinstance(reason, str) and reason:
                normalized.append({
                    "path": None,
                    "path_withheld": reason,
                    "start_line": start,
                    "end_line": end,
                })
                continue
            if path_value is not None and type(path_value) is not str:
                raise ValueError("Source path must be a string")
            normalized.append({
                "path": str(path_value or "").strip(),
                "start_line": start,
                "end_line": end,
            })
        else:
            raise ValueError("Source path must be a string or range mapping")
    normalized.sort(key=lambda item: (
        item["path"] or "",
        item["start_line"] if item["start_line"] is not None else -1,
        item["end_line"] if item["end_line"] is not None else -1,
    ))
    return normalized


def _validate_cleanup_id(proposed_cleanup_id: str | None) -> str | None:
    if proposed_cleanup_id is None:
        return None
    cleanup_id = str(proposed_cleanup_id).strip()
    if not cleanup_id:
        return None
    if any(ch in cleanup_id for ch in _CLEANUP_ID_FORBIDDEN_CHARS):
        raise ValueError(
            f"proposed_cleanup_id must be a declarative identifier, not an executable command: {proposed_cleanup_id!r}"
        )
    return cleanup_id


def make_finding(
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
    legacy_severity: str | None = None,
) -> dict[str, Any]:
    """Construct a validated, JSON-serializable finding conforming to both §5/§6 and the legacy envelope."""
    _persistence.strict_json(dict(
        rule_id=rule_id, classification=classification, coverage=coverage,
        affected_identities=affected_identities, source_paths=source_paths,
        evidence=evidence, consequence=consequence, limitations=limitations,
        proposed_cleanup_id=proposed_cleanup_id, detail=detail, fix=fix,
    ))
    if type(rule_id) is not str or type(consequence) is not str:
        raise ValueError("Finding rule and consequence must be strings")
    for text in (classification, coverage, limitations, proposed_cleanup_id, detail, fix, legacy_severity):
        if text is not None and type(text) is not str:
            raise ValueError("Finding text fields must be strings")
    if not isinstance(affected_identities, (list, tuple)) or any(type(i) is not str for i in affected_identities):
        raise ValueError("Finding identities must be a string sequence")
    if evidence is not None and not isinstance(evidence, Mapping):
        raise ValueError("Finding evidence must be a mapping")
    rid = str(rule_id or "").strip()
    if not rid:
        raise ValueError("Finding rule_id must be non-empty")

    norm_class = normalize_classification(classification, legacy_severity=legacy_severity)
    norm_cov = normalize_coverage(coverage)
    clean_evidence = sanitize_evidence(dict(evidence) if evidence is not None else {})
    identities = sorted({str(x).strip() for x in affected_identities if str(x).strip()})
    paths = normalize_source_paths(source_paths)

    consequence_str = str(consequence or "").strip()
    if not consequence_str:
        raise ValueError(f"Finding {rid!r} must include a plain-language consequence")
    limitations_str = str(limitations or "").strip()
    detail_str = str(detail).strip() if detail is not None and str(detail).strip() else consequence_str
    cleanup_id = _validate_cleanup_id(proposed_cleanup_id)
    sev = (str(legacy_severity).strip().lower()
           if legacy_severity in ("error", "warn", "info") else _CLASSIFICATION_TO_LEGACY_SEVERITY[norm_class])

    return {
        "id": rid, "classification": norm_class, "coverage": norm_cov,
        "affected_identities": identities, "source_paths": paths, "evidence": clean_evidence,
        "consequence": consequence_str, "limitations": limitations_str,
        "proposed_cleanup_id": cleanup_id, "severity": sev, "detail": detail_str,
        "fix": str(fix) if fix is not None else None,
    }


def _normalize_structured_finding(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    structured = {
        k: raw[k] for k in _STRUCTURED_CONTENT_FIELDS
        if k in raw and (isinstance(raw[k], Mapping) or (
            k in ("affected_identities", "source_paths") and isinstance(raw[k], (list, tuple))
            and any(isinstance(v, Mapping) and (k == "affected_identities" or isinstance(v.get("path"), Mapping))
                    for v in raw[k])
        ))
    }
    if not structured:
        return None
    for k, v in structured.items():
        if k in ("affected_identities", "source_paths") and not isinstance(v, (list, tuple)):
            raise ValueError("Finding identities and paths must be sequences")
        candidates = (v if k == "affected_identities"
                      else [p.get("path") if isinstance(p, Mapping) else p for p in v] if k == "source_paths"
                      else [v])
        for item in candidates:
            if isinstance(item, Mapping) and not {"kind", "hmac", "location"} <= item.keys():
                raise ValueError("Invalid structured finding content")
    plain = dict(raw)
    for k in structured:
        plain[k] = ([] if k in ("affected_identities", "source_paths")
                    else "audit.finding" if k in ("id", "rule_id")
                    else "Source-derived text withheld by persistence policy.")
    normalized = normalize_finding(plain)
    for k, v in structured.items():
        normalized["id" if k == "rule_id" else k] = _evidence.serialize_evidence(v)
    return normalized


def normalize_finding(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a raw or legacy component finding into the full §6 finding shape."""
    if not isinstance(raw, Mapping):
        raise ValueError(f"Finding must be a mapping, got {type(raw).__name__}")
    _persistence.strict_json(raw)
    structured = _normalize_structured_finding(raw)
    if structured is not None:
        return structured
    for field in _PLAIN_TEXT_FINDING_FIELDS:
        if raw.get(field) is not None and type(raw[field]) is not str:
            raise ValueError("Finding text fields must be strings")
    identities = raw.get("affected_identities")
    if identities is not None and (not isinstance(identities, (list, tuple)) or any(type(i) is not str for i in identities)):
        raise ValueError("Finding identities must be a string sequence")
    if raw.get("evidence") is not None and not isinstance(raw["evidence"], Mapping):
        raise ValueError("Finding evidence must be a mapping")
    rid = str(raw.get("id") or raw.get("rule_id") or "audit.finding").strip()
    raw_class, raw_sev = raw.get("classification"), raw.get("severity")
    classification = normalize_classification(
        str(raw_class) if raw_class is not None else None,
        legacy_severity=str(raw_sev) if raw_sev is not None else None,
    )
    coverage = normalize_coverage(str(raw["coverage"]) if raw.get("coverage") is not None else COVERAGE_VERIFIED)
    detail = str(raw.get("detail") or raw.get("consequence") or rid).strip()
    consequence = str(raw.get("consequence") or detail or rid).strip()
    limitations = str(raw.get("limitations") or "").strip()

    return make_finding(
        rule_id=rid, classification=classification, coverage=coverage,
        affected_identities=raw.get("affected_identities") or (),
        source_paths=raw.get("source_paths") or (),
        evidence=raw.get("evidence") if isinstance(raw.get("evidence"), Mapping) else {},
        consequence=consequence, limitations=limitations,
        proposed_cleanup_id=raw.get("proposed_cleanup_id"), detail=detail, fix=raw.get("fix"),
        legacy_severity=str(raw_sev) if raw_sev in ("error", "warn", "info") else None,
    )


def finding_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """Deterministic ordering key for findings (§1, §4)."""
    cls_name = str(finding.get("classification") or CLASSIFICATION_INFO)
    rank = _CLASSIFICATION_RANK.get(cls_name, 0)
    identities = json.dumps(_persistence.strict_json(finding.get("affected_identities") or ()), sort_keys=True)
    paths = tuple(
        (str(p.get("path") or ""), int(p["start_line"]) if isinstance(p.get("start_line"), int) else -1)
        for p in (finding.get("source_paths") or ()) if isinstance(p, Mapping)
    )
    return (
        -rank, str(finding.get("id") or ""), identities, paths,
        str(finding.get("consequence") or ""), str(finding.get("proposed_cleanup_id") or ""),
        json.dumps(_persistence.strict_json(finding), sort_keys=True, separators=(",", ":"), allow_nan=False),
    )


def sort_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalize and deterministically sort a collection of findings."""
    normalized = [normalize_finding(f) for f in findings]
    normalized.sort(key=finding_sort_key)
    return normalized


def make_component_envelope(
    *,
    findings: Sequence[Mapping[str, Any]] = (),
    coverage: str = COVERAGE_VERIFIED,
    error: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a shared component result envelope compatible with the component result contract (§6)."""
    sorted_findings = sort_findings(findings)
    headline_cls = compute_classification_headline(sorted_findings)
    if error is not None:
        out: dict[str, Any] = {
            "ok": False, "status": "error",
            "error": str(error).strip() or "Component execution failed",
            "coverage": COVERAGE_COULD_NOT_VERIFY, "classification": headline_cls,
            "findings": sorted_findings,
        }
    else:
        norm_cov = normalize_coverage(coverage)
        if any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in sorted_findings):
            norm_cov = COVERAGE_COULD_NOT_VERIFY
        legacy_status = "fail" if any(f.get("severity") == "error" for f in sorted_findings) else "pass"
        out = {
            "ok": legacy_status == "pass", "status": legacy_status, "error": None,
            "coverage": norm_cov, "classification": headline_cls, "findings": sorted_findings,
        }
    if extra:
        for k, v in extra.items():
            if k not in out:
                out[str(k)] = v
    return out


def adapt_component_result(
    raw_envelope: Mapping[str, Any],
    *,
    component_id: str = "component",
    affected_identities: Sequence[str] = (),
) -> dict[str, Any]:
    """Adapt a raw vendored audit component envelope into the plugin's §6 contract."""
    if not isinstance(raw_envelope, Mapping):
        raise ValueError(f"Component result must be a mapping, got {type(raw_envelope).__name__}")

    raw_findings = raw_envelope.get("findings")
    findings_list = [normalize_finding(f) for f in raw_findings] if isinstance(raw_findings, Sequence) else []
    op_error = raw_envelope.get("error") or raw_envelope.get("operational_error")
    legacy_status = str(raw_envelope.get("status") or "pass").strip().lower()
    explicit_cov = raw_envelope.get("coverage")

    if op_error or legacy_status == "error":
        err_msg = str(op_error or f"{component_id} operational error").strip()
        cov = COVERAGE_COULD_NOT_VERIFY
        if not any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in findings_list):
            findings_list.append(make_finding(
                rule_id=f"{component_id}.operational_error",
                classification=CLASSIFICATION_INFO, coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=affected_identities,
                consequence=f"Check {component_id!r} could not complete verification.",
                limitations=err_msg, evidence={"operational_error": err_msg},
            ))
    elif explicit_cov is not None:
        cov = normalize_coverage(str(explicit_cov))
    else:
        cov = COVERAGE_VERIFIED

    if any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in findings_list):
        cov = COVERAGE_COULD_NOT_VERIFY
    elif cov == COVERAGE_VERIFIED and findings_list and all(f["coverage"] == COVERAGE_NOT_INCLUDED for f in findings_list):
        cov = COVERAGE_NOT_INCLUDED

    sorted_findings = sort_findings(findings_list)
    adapted: dict[str, Any] = {
        "component_id": component_id, "coverage": cov,
        "classification": compute_classification_headline(sorted_findings),
        "findings": sorted_findings,
        "operational_error": str(op_error) if op_error else None,
        "legacy_status_ignored": legacy_status,
    }
    for k, v in raw_envelope.items():
        if k not in ("ok", "status", "error", "findings", "coverage", "classification"):
            adapted[str(k)] = v
    return adapted


def compute_classification_headline(findings: Sequence[Mapping[str, Any]]) -> str:
    """Compute highest product severity from findings (`warning` > `review_suggested` > `info`)."""
    best = CLASSIFICATION_INFO
    best_rank = _CLASSIFICATION_RANK[best]
    for f in findings:
        cls_val = normalize_classification(
            str(f.get("classification")) if f.get("classification") is not None else None,
            legacy_severity=str(f.get("severity")) if f.get("severity") is not None else None,
        )
        rank = _CLASSIFICATION_RANK[cls_val]
        if rank > best_rank:
            best, best_rank = cls_val, rank
    return best


def _collect_scope_coverages(
    unit_coverages: Sequence[str], component_results: Sequence[Mapping[str, Any]]
) -> list[str]:
    scope_coverages: list[str] = [normalize_coverage(c) for c in unit_coverages]
    for comp in component_results:
        if isinstance(comp, Mapping):
            if comp.get("error") or comp.get("operational_error") or comp.get("status") == "error":
                scope_coverages.append(COVERAGE_COULD_NOT_VERIFY)
            elif comp.get("coverage") is not None:
                scope_coverages.append(normalize_coverage(str(comp["coverage"])))
    return scope_coverages


def _resolve_headline_coverage(
    total_could_not_verify: int, total_not_included: int, total_verified: int
) -> str:
    if total_could_not_verify > 0:
        return COVERAGE_COULD_NOT_VERIFY
    if total_not_included > 0:
        return COVERAGE_NOT_INCLUDED
    return COVERAGE_COULD_NOT_VERIFY if total_verified == 0 else COVERAGE_VERIFIED


def compute_headline(
    *,
    findings: Sequence[Mapping[str, Any]] = (),
    unit_coverages: Sequence[str] = (),
    component_results: Sequence[Mapping[str, Any]] = (),
    incomplete_units: int = 0,
) -> dict[str, Any]:
    """Compute the §6 audit headline from findings, unit coverages, and component results."""
    all_raw_findings: list[Mapping[str, Any]] = list(findings)
    for comp in component_results:
        if isinstance(comp, Mapping) and isinstance(comp.get("findings"), Sequence):
            all_raw_findings.extend(comp["findings"])
    normalized_findings = sort_findings(all_raw_findings)

    classification_counts = {
        CLASSIFICATION_WARNING: 0, CLASSIFICATION_REVIEW: 0, CLASSIFICATION_INFO: 0,
    }
    finding_coverage_counts = {
        COVERAGE_VERIFIED: 0, COVERAGE_COULD_NOT_VERIFY: 0, COVERAGE_NOT_INCLUDED: 0,
    }
    for f in normalized_findings:
        classification_counts[f["classification"]] += 1
        finding_coverage_counts[f["coverage"]] += 1

    scope_coverages = _collect_scope_coverages(unit_coverages, component_results)
    clamped_incomplete = max(0, int(incomplete_units))
    unit_coverage_counts = {
        COVERAGE_VERIFIED: sum(1 for c in scope_coverages if c == COVERAGE_VERIFIED),
        COVERAGE_COULD_NOT_VERIFY: sum(1 for c in scope_coverages if c == COVERAGE_COULD_NOT_VERIFY) + clamped_incomplete,
        COVERAGE_NOT_INCLUDED: sum(1 for c in scope_coverages if c == COVERAGE_NOT_INCLUDED),
    }

    total_could_not_verify = (
        finding_coverage_counts[COVERAGE_COULD_NOT_VERIFY] + unit_coverage_counts[COVERAGE_COULD_NOT_VERIFY]
    )
    total_not_included = (
        finding_coverage_counts[COVERAGE_NOT_INCLUDED] + unit_coverage_counts[COVERAGE_NOT_INCLUDED]
    )
    total_verified = finding_coverage_counts[COVERAGE_VERIFIED] + unit_coverage_counts[COVERAGE_VERIFIED]

    headline_cov = _resolve_headline_coverage(total_could_not_verify, total_not_included, total_verified)
    headline_cls = compute_classification_headline(normalized_findings)
    can_claim_clean = (
        headline_cls == CLASSIFICATION_INFO and headline_cov == COVERAGE_VERIFIED and total_could_not_verify == 0
    )

    return {
        "contract_version": CONTRACT_VERSION, "classification": headline_cls, "coverage": headline_cov,
        "can_claim_clean": can_claim_clean, "classification_counts": classification_counts,
        "finding_coverage_counts": finding_coverage_counts, "scope_coverage_counts": unit_coverage_counts,
        "incomplete_units": clamped_incomplete, "disclosure": FIXED_AUDIT_DISCLOSURE,
    }


# Recommendations are advisory policy reviews, never cleanup authorization.
_POLICY_KINDS = {
    'memory.cross_project_exposure': 'review_memory_scope',
    'static_code.unapproved_dependency': 'review_dependency_policy',
    'template.locked_hash_drift': 'review_template_policy',
    'executable_inventory.mcp_unsafe_declaration': 'review_execution_policy',
    'executable_inventory.hook_unsafe_path_or_command': 'review_execution_policy',
}


def _finding_unit_verified(finding, units, findings):
    identities = finding.get('affected_identities', [])
    if finding.get('coverage') != COVERAGE_VERIFIED or not identities:
        return False
    for identity in identities:
        matches = [u for u in units if u.get('unit_id') == identity]
        if not matches or any(
            u.get('coverage') != COVERAGE_VERIFIED or u.get('status') != 'completed' or u.get('stable') is False
            for u in matches
        ):
            return False
        if any(f.get('coverage') != COVERAGE_VERIFIED and identity in f.get('affected_identities', []) for f in findings):
            return False
    return True


def policy_recommendations(findings, units):
    result = []
    for finding in findings:
        rule = finding.get('id')
        kind = _POLICY_KINDS.get(rule) if isinstance(rule, str) else None
        if kind and _finding_unit_verified(finding, units, findings):
            result.append({
                'finding_ids': [rule], 'affected_identities': finding['affected_identities'],
                'kind': kind, 'execution_available': False,
            })
    return result


def _preservation_category(finding, units, findings) -> str:
    rule = finding.get('id')
    if not (isinstance(rule, str) and rule in _evidence_constants.RULE_IDS and _finding_unit_verified(finding, units, findings)):
        return 'unknown'
    if rule.startswith(('memory.', 'cross_checks.memory_')):
        return 'user_data'
    if rule.startswith(('template.', 'executable_inventory.')):
        return 'config'
    if rule == 'audit.scope.credentials':
        return 'credentials_metadata_only'
    return 'unknown'


def preservation_assessments(findings, units):
    """Conservative preservation requirements, not permission to remove anything."""
    result = []
    for finding in findings:
        category = _preservation_category(finding, units, findings)
        known = category != 'unknown'
        result.append({
            'finding_ids': [finding.get('id')],
            'affected_identities': finding.get('affected_identities', []),
            'proposed_cleanup_id': finding.get('proposed_cleanup_id'),
            'must_preserve': [category],
            'confidence': 'verified' if known else 'unknown',
            'reason': 'static_evidence_only' if known else 'insufficient_evidence',
            'execution_available': False,
        })
    return result


def canonical_report_payload(
    *,
    as_of: int | float,
    mode: str = "live",
    optional_root: str | None = None,
    active_profile: str = "default",
    unused_threshold_days: int = 90,
    rule_versions: Mapping[str, str] | None = None,
    template_versions: Mapping[str, str] | None = None,
    units: Sequence[Mapping[str, Any]] = (),
    findings: Sequence[Mapping[str, Any]] = (),
    headline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the deterministic canonical report dictionary (§4: excludes run_id and execution timestamps)."""
    sorted_findings = sort_findings(findings)
    sorted_units = sorted(
        (dict(u) for u in units),
        key=lambda u: (str(u.get("unit_kind") or ""), str(u.get("unit_id") or "")),
    )
    identities = [
        (u.get("unit_kind"),
         json.dumps(_persistence.strict_json(u.get("unit_id")), sort_keys=True)
         if isinstance(u.get("unit_id"), _evidence.SealedEvidence) else u.get("unit_id"))
        for u in sorted_units
    ]
    if any(type(k) is not str or not k or type(i) is not str or not i for k, i in identities):
        raise ValueError("Unit identities must be nonempty strings")
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate audit unit identity")
    unit_covs = [str(u.get("coverage") or COVERAGE_COULD_NOT_VERIFY) for u in sorted_units]
    incomplete = sum(1 for u in sorted_units if u.get("status") != "completed")
    baseline = compute_headline(findings=sorted_findings, unit_coverages=unit_covs, incomplete_units=incomplete)
    resolved_headline = dict(headline) if headline is not None else baseline
    if not baseline["can_claim_clean"]:
        resolved_headline["can_claim_clean"] = False
        if baseline["coverage"] != COVERAGE_VERIFIED:
            resolved_headline["coverage"] = baseline["coverage"]
    payload = _evidence.serialize_evidence({
        "contract_version": CONTRACT_VERSION, "disclosure": FIXED_AUDIT_DISCLOSURE,
        "as_of": int(as_of), "mode": mode, "optional_root": optional_root,
        "active_profile": active_profile, "unused_threshold_days": int(unused_threshold_days),
        "rule_versions": dict(sorted((rule_versions or {}).items())),
        "template_versions": dict(sorted((template_versions or {}).items())),
        "headline": resolved_headline, "units": sorted_units, "findings": sorted_findings,
        "policy_recommendations": policy_recommendations(sorted_findings, sorted_units),
        "preservation_assessments": preservation_assessments(sorted_findings, sorted_units),
    })
    assert isinstance(payload, dict)
    return payload


def canonical_report_bytes(report_payload: Mapping[str, Any]) -> bytes:
    """Serialize a canonical report payload to deterministic UTF-8 JSON bytes (excluding envelope metadata)."""
    filtered = {k: v for k, v in report_payload.items() if k not in _ENVELOPE_METADATA_KEYS}
    cleaned = _persistence.strict_json(_evidence.serialize_evidence(filtered))
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_report_digest(report_payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 hex digest of the canonical report."""
    return hashlib.sha256(canonical_report_bytes(report_payload)).hexdigest()
