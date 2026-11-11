"""Read-only, pure-stdlib profile and project context load analysis.

Computes the `context_load` report section and `context_load.*` bloat/leakage
findings over the adapted `profile_context` result, profile config, and project
context-chain facts without any I/O, network calls, subprocesses, or tokenizers.
"""
from __future__ import annotations

import math
import posixpath
from typing import Any, Mapping, Sequence

from .contract import (
    CLASSIFICATION_REVIEW,
    CLASSIFICATION_WARNING,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    make_component_envelope,
    make_finding,
    sort_findings,
)
from .evidence_constants import (
    FINDING_CONSEQUENCES,
    PROJECT_CONTEXT_TRUNCATED_ASSUMED_CONSEQUENCE,
)
from .vendor.profile_context import (
    CHARS_PER_TOKEN,
    DEFAULT_CONTEXT_FILE_MAX_CHARS,
    TOKEN_ESTIMATOR_VERSION,
    _estimate_tokens,
    _render_auto_loaded_skill_block,
)

__all__ = [
    "AUTO_SKILL_REVIEW_TOKENS",
    "AUTO_SKILL_WARNING_TOKENS",
    "FIXED_PROMPT_REVIEW_TOKENS",
    "FIXED_PROMPT_WARNING_TOKENS",
    "KNOWN_EXTERNAL_MEMORY_PROVIDERS",
    "MEMORY_REVIEW_TOKENS",
    "MEMORY_WARNING_TOKENS",
    "PERSONA_REVIEW_TOKENS",
    "PERSONA_WARNING_TOKENS",
    "PROJECT_CONTEXT_REVIEW_TOKENS",
    "PROJECT_CONTEXT_WARNING_TOKENS",
    "REFERENCE_WINDOWS",
    "RESEND_COST_NOTE",
    "RESEND_TURNS",
    "SKILLS_INDEX_REVIEW_COUNT",
    "SKILLS_INDEX_REVIEW_TOKENS",
    "SKILLS_INDEX_WARNING_COUNT",
    "SKILLS_INDEX_WARNING_TOKENS",
    "SOURCE_ORDER",
    "UNMEASURED_DYNAMIC_SOURCES",
    "WINDOW_SHARE_REVIEW_TOKENS",
    "WINDOW_SHARE_REVIEW_WINDOW",
    "WINDOW_SHARE_THRESHOLD",
    "WINDOW_SHARE_WARNING_TOKENS",
    "WINDOW_SHARE_WARNING_WINDOW",
    "audit_context_load",
    "evaluate_context_load",
    "resolve_context_file_max_chars",
    "sanitize_profile_facts_for_context",
    "unverified_context_load",
]

PERSONA_REVIEW_TOKENS = 2000
PERSONA_WARNING_TOKENS = 4000

AUTO_SKILL_REVIEW_TOKENS = 2000
AUTO_SKILL_WARNING_TOKENS = 5000

SKILLS_INDEX_REVIEW_TOKENS = 1500
SKILLS_INDEX_WARNING_TOKENS = 4000
SKILLS_INDEX_REVIEW_COUNT = 60
SKILLS_INDEX_WARNING_COUNT = 150

MEMORY_REVIEW_TOKENS = 1500
MEMORY_WARNING_TOKENS = 3000

FIXED_PROMPT_REVIEW_TOKENS = 10000
FIXED_PROMPT_WARNING_TOKENS = 32000

PROJECT_CONTEXT_REVIEW_TOKENS = 2500
PROJECT_CONTEXT_WARNING_TOKENS = 5000

WINDOW_SHARE_REVIEW_WINDOW = 32000
WINDOW_SHARE_WARNING_WINDOW = 128000
WINDOW_SHARE_THRESHOLD = 0.25
WINDOW_SHARE_REVIEW_TOKENS = int(WINDOW_SHARE_REVIEW_WINDOW * WINDOW_SHARE_THRESHOLD)
WINDOW_SHARE_WARNING_TOKENS = int(WINDOW_SHARE_WARNING_WINDOW * WINDOW_SHARE_THRESHOLD)

REFERENCE_WINDOWS: tuple[int, ...] = (32000, 128000, 200000)
RESEND_TURNS: tuple[int, ...] = (10, 50, 100)

SOURCE_ORDER: tuple[str, ...] = (
    "identity_soul",
    "core_guidance",
    "enabled_memory_files",
    "auto_loaded_skill_bodies",
    "skills_index_text",
)

KNOWN_EXTERNAL_MEMORY_PROVIDERS: frozenset[str] = frozenset({
    "byterover",
    "retaindb",
})

UNMEASURED_DYNAMIC_SOURCES: tuple[str, ...] = (
    "dynamic_plugin_prompt_sections",
    "plugin_registered_skills",
    "builtin_tool_schemas",
    "mcp_tool_schemas",
    "external_memory_provider_prefetch_and_blocks",
    "caller_ephemeral_system_message",
    "workspace_git_status_snapshot",
    "runtime_environment_metadata",
)

RESEND_COST_NOTE = (
    "Estimated cumulative prompt tokens re-sent across turns, ignoring provider prompt caching."
)


def _est_tokens(chars: int, explicit_tokens: Any = None) -> int:
    if isinstance(explicit_tokens, int) and not isinstance(explicit_tokens, bool):
        return max(0, explicit_tokens)
    c = max(0, int(chars or 0))
    return (c + 3) // CHARS_PER_TOKEN if c > 0 else 0


def _build_skills_lookup(skills_facts: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if not isinstance(skills_facts, Mapping):
        return {}
    raw_list = skills_facts.get("skills")
    if not isinstance(raw_list, Sequence):
        return {}
    lookup: dict[str, Mapping[str, Any]] = {}
    for item in raw_list:
        if not isinstance(item, Mapping):
            continue
        if item.get("disabled") or item.get("status") == "shadowed":
            continue
        for key_field in ("skill_md_path", "load_name", "name"):
            val = str(item.get(key_field) or "").strip()
            if val and val not in lookup:
                lookup[val] = item
    return lookup


def _estimate_skill_tokens(
    sk: Mapping[str, Any],
    skills_lookup: Mapping[str, Mapping[str, Any]],
    profile_path: str | None = None,
) -> tuple[int, str]:
    explicit = sk.get("estimated_tokens")
    if isinstance(explicit, int) and not isinstance(explicit, bool):
        return max(0, explicit), str(sk.get("estimator_version") or TOKEN_ESTIMATOR_VERSION)
    tm = sk.get("token_metrics")
    if isinstance(tm, Mapping) and isinstance(tm.get("estimated_tokens"), int) and not isinstance(tm.get("estimated_tokens"), bool):
        return max(0, int(tm["estimated_tokens"])), str(tm.get("estimator_version") or TOKEN_ESTIMATOR_VERSION)
    if isinstance(sk.get("rendered_text"), str) and sk["rendered_text"]:
        return int(_estimate_tokens(sk["rendered_text"])["estimated_tokens"]), TOKEN_ESTIMATOR_VERSION
    if isinstance(sk.get("body_text"), str):
        rendered = _render_auto_loaded_skill_block(sk, profile_root=profile_path or "")["rendered_text"]
        return int(_estimate_tokens(rendered)["estimated_tokens"]), TOKEN_ESTIMATOR_VERSION

    for key_field in ("skill_md_path", "load_name", "name"):
        val = str(sk.get(key_field) or "").strip()
        if val and val in skills_lookup:
            matched = skills_lookup[val]
            if isinstance(matched.get("body_text"), str) or isinstance(matched.get("rendered_auto_load_block"), str):
                rendered = _render_auto_loaded_skill_block(matched, profile_root=profile_path or "")["rendered_text"]
                return int(_estimate_tokens(rendered)["estimated_tokens"]), TOKEN_ESTIMATOR_VERSION
            m_tm = matched.get("token_metrics")
            if isinstance(m_tm, Mapping) and isinstance(m_tm.get("estimated_tokens"), int) and not isinstance(m_tm.get("estimated_tokens"), bool):
                return max(0, int(m_tm["estimated_tokens"])), TOKEN_ESTIMATOR_VERSION

    sk_chars = max(0, int(sk.get("injected_chars") or 0))
    return ((sk_chars + 3) // CHARS_PER_TOKEN if sk_chars > 0 else 0), "chars_div_4_fallback"


def _is_from_parent(file_path: str, project_root: str) -> bool:
    fp = posixpath.normpath(str(file_path or "").strip())
    pr = posixpath.normpath(str(project_root or "").strip())
    if not fp or not pr or not fp.startswith("/") or not pr.startswith("/"):
        return False
    if pr == "/":
        return False
    return not (fp == pr or fp.startswith(pr + "/"))


def resolve_context_file_max_chars(
    config: Mapping[str, Any] | None,
    default_max_chars: int = DEFAULT_CONTEXT_FILE_MAX_CHARS,
) -> dict[str, Any]:
    """Resolve effective `context_file_max_chars` and its source ('config' | 'assumed_default')."""
    if isinstance(config, Mapping):
        raw = config.get("context_file_max_chars")
        if (
            isinstance(raw, (int, float))
            and not isinstance(raw, bool)
            and math.isfinite(raw)
            and int(raw) > 0
        ):
            return {"value": int(raw), "source": "config"}
    fallback = (
        int(default_max_chars)
        if isinstance(default_max_chars, (int, float))
        and not isinstance(default_max_chars, bool)
        and math.isfinite(default_max_chars)
        and int(default_max_chars) > 0
        else DEFAULT_CONTEXT_FILE_MAX_CHARS
    )
    return {"value": fallback, "source": "assumed_default"}


def sanitize_profile_facts_for_context(
    profile_facts: Mapping[str, Any],
    default_max_chars: int = DEFAULT_CONTEXT_FILE_MAX_CHARS,
) -> dict[str, Any]:
    """Return a shallow-copied `profile_facts` whose `config.context_file_max_chars` rejects booleans/invalid values."""
    if not isinstance(profile_facts, Mapping):
        return {}
    out = dict(profile_facts)
    raw_cfg = out.get("config")
    if isinstance(raw_cfg, Mapping):
        limit_info = resolve_context_file_max_chars(raw_cfg, default_max_chars)
        cfg_copy = dict(raw_cfg)
        if limit_info["source"] == "config":
            cfg_copy["context_file_max_chars"] = limit_info["value"]
        else:
            cfg_copy.pop("context_file_max_chars", None)
        out["config"] = cfg_copy
    return out


def _resolve_effective_max_chars(
    config: Mapping[str, Any] | None,
    default_max_chars: int = DEFAULT_CONTEXT_FILE_MAX_CHARS,
) -> int:
    return int(resolve_context_file_max_chars(config, default_max_chars)["value"])


def _extract_external_memory_provider(config: Mapping[str, Any] | None) -> tuple[bool, str | None]:
    if not isinstance(config, Mapping):
        return False, None
    raw_mem = config.get("memory")
    raw_prov = raw_mem.get("provider") if isinstance(raw_mem, Mapping) else config.get("memory.provider")
    if isinstance(raw_prov, str):
        cleaned = raw_prov.strip()
        if cleaned and cleaned.lower() not in ("none", "null", "false"):
            return True, cleaned
    return False, None


def _thresholds_dict(effective_max_chars: int) -> dict[str, Any]:
    return {
        "persona_injected_tokens": {
            "review_suggested": PERSONA_REVIEW_TOKENS,
            "warning": PERSONA_WARNING_TOKENS,
        },
        "auto_loaded_skill_tokens": {
            "review_suggested": AUTO_SKILL_REVIEW_TOKENS,
            "warning": AUTO_SKILL_WARNING_TOKENS,
        },
        "skills_index_tokens": {
            "review_suggested": SKILLS_INDEX_REVIEW_TOKENS,
            "warning": SKILLS_INDEX_WARNING_TOKENS,
        },
        "skills_index_listed_count": {
            "review_suggested": SKILLS_INDEX_REVIEW_COUNT,
            "warning": SKILLS_INDEX_WARNING_COUNT,
        },
        "memory_tokens": {
            "review_suggested": MEMORY_REVIEW_TOKENS,
            "warning": MEMORY_WARNING_TOKENS,
        },
        "fixed_prompt_tokens": {
            "review_suggested": FIXED_PROMPT_REVIEW_TOKENS,
            "warning": FIXED_PROMPT_WARNING_TOKENS,
        },
        "project_context_tokens": {
            "review_suggested": PROJECT_CONTEXT_REVIEW_TOKENS,
            "warning": PROJECT_CONTEXT_WARNING_TOKENS,
        },
        "per_turn_window_share": {
            "review_window_tokens": WINDOW_SHARE_REVIEW_WINDOW,
            "warning_window_tokens": WINDOW_SHARE_WARNING_WINDOW,
            "share_threshold": WINDOW_SHARE_THRESHOLD,
            "review_suggested_tokens": WINDOW_SHARE_REVIEW_TOKENS,
            "warning_tokens": WINDOW_SHARE_WARNING_TOKENS,
        },
        "context_file_max_chars": int(effective_max_chars),
    }


def unverified_context_load(reason: str = "bounded_quick_audit_not_collected") -> dict[str, Any]:
    """Build a non-zeroed `could_not_verify` context_load section for quick mode or collector errors."""
    return {
        "coverage": COVERAGE_COULD_NOT_VERIFY,
        "reason": str(reason or "bounded_quick_audit_not_collected"),
    }


def _normalize_project_entries(
    raw_projects: Sequence[Mapping[str, Any]],
    effective_max_chars: int,
) -> list[dict[str, Any]]:
    projects_out: list[dict[str, Any]] = []
    for raw_p in raw_projects:
        if not isinstance(raw_p, Mapping):
            continue
        proj_root = str(raw_p.get("project_root") or "").strip()
        winning_kind = raw_p.get("winning_kind")
        if winning_kind is not None:
            winning_kind = str(winning_kind)
        p_cov = str(raw_p.get("coverage") or COVERAGE_VERIFIED)
        if p_cov != COVERAGE_VERIFIED:
            p_cov = COVERAGE_COULD_NOT_VERIFY

        injected_files: list[dict[str, Any]] = []
        shadowed_files: list[dict[str, Any]] = []

        if isinstance(raw_p.get("injected_files"), Sequence):
            for f in raw_p["injected_files"]:
                if not isinstance(f, Mapping):
                    continue
                fpath = str(f.get("path") or "")
                fkind = str(f.get("kind") or "")
                raw_c_val = f.get("raw_chars") if f.get("raw_chars") is not None else f.get("char_count")
                raw_c = int(raw_c_val or 0)
                inj_c = int(f.get("injected_chars") or 0)
                est_t = _est_tokens(inj_c, f.get("estimated_tokens"))
                trunc = bool(f.get("truncated", raw_c > effective_max_chars))
                from_parent = bool(f["from_parent"]) if "from_parent" in f else _is_from_parent(fpath, proj_root)
                injected_files.append({
                    "path": fpath,
                    "kind": fkind,
                    "raw_chars": raw_c,
                    "injected_chars": inj_c,
                    "estimated_tokens": est_t,
                    "truncated": trunc,
                    "from_parent": from_parent,
                })
            for sf in (raw_p.get("shadowed_files") or ()):
                if not isinstance(sf, Mapping):
                    continue
                sf_raw = sf.get("raw_chars") if sf.get("raw_chars") is not None else sf.get("char_count")
                shadowed_files.append({
                    "path": str(sf.get("path") or ""),
                    "kind": str(sf.get("kind") or ""),
                    "raw_chars": int(sf_raw or 0),
                })
        elif isinstance(raw_p.get("files"), Sequence):
            for f in raw_p["files"]:
                if not isinstance(f, Mapping):
                    continue
                fpath = str(f.get("path") or "")
                fkind = str(f.get("kind") or "")
                if f.get("coverage") and str(f.get("coverage")) != COVERAGE_VERIFIED:
                    p_cov = COVERAGE_COULD_NOT_VERIFY
                f_raw = f.get("char_count") if f.get("char_count") is not None else f.get("raw_chars")
                raw_c = int(f_raw or 0)
                if bool(f.get("injected")):
                    inj_c = int(f.get("injected_chars") or min(raw_c, effective_max_chars))
                    est_t = _est_tokens(inj_c, f.get("estimated_tokens"))
                    trunc = bool(f.get("truncated", raw_c > effective_max_chars))
                    from_parent = bool(f["from_parent"]) if "from_parent" in f else _is_from_parent(fpath, proj_root)
                    injected_files.append({
                        "path": fpath,
                        "kind": fkind,
                        "raw_chars": raw_c,
                        "injected_chars": inj_c,
                        "estimated_tokens": est_t,
                        "truncated": trunc,
                        "from_parent": from_parent,
                    })
                else:
                    shadowed_files.append({
                        "path": fpath,
                        "kind": fkind,
                        "raw_chars": raw_c,
                    })

        proj_inj_chars = int(
            raw_p["injected_chars"]
            if "injected_chars" in raw_p and raw_p.get("injected_chars") is not None
            else (
                raw_p["total_injected_chars"]
                if "total_injected_chars" in raw_p and raw_p.get("total_injected_chars") is not None
                else sum(item["injected_chars"] for item in injected_files)
            )
        )
        proj_est_tokens = int(
            raw_p["estimated_tokens"]
            if "estimated_tokens" in raw_p and raw_p.get("estimated_tokens") is not None
            else sum(item["estimated_tokens"] for item in injected_files)
        )

        projects_out.append({
            "project_root": proj_root,
            "winning_kind": winning_kind,
            "injected_chars": proj_inj_chars,
            "estimated_tokens": proj_est_tokens,
            "injected_files": injected_files,
            "shadowed_files": shadowed_files,
            "shadowed_file_count": len(shadowed_files),
            "coverage": p_cov,
        })

    projects_out.sort(key=lambda item: item["project_root"])
    return projects_out


def evaluate_context_load(
    profile_context_result: Mapping[str, Any],
    *,
    config: Mapping[str, Any] | None = None,
    project_contexts: Sequence[Mapping[str, Any]] = (),
    profile_path: str | None = None,
    context_file_max_chars: int = DEFAULT_CONTEXT_FILE_MAX_CHARS,
    skills_facts: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compute the `context_load` report section and `context_load.*` findings."""
    if not isinstance(profile_context_result, Mapping):
        raise ValueError("profile_context_result must be a mapping")

    raw_base = profile_context_result.get("static_profile_base")
    base: Mapping[str, Any] = raw_base if isinstance(raw_base, Mapping) else profile_context_result
    raw_comps = base.get("components")
    if not isinstance(raw_comps, Mapping):
        raise ValueError("profile_context_result is missing static_profile_base.components")

    max_chars_info = resolve_context_file_max_chars(config, context_file_max_chars)
    effective_max_chars = int(max_chars_info["value"])
    max_chars_source = str(max_chars_info["source"])
    skills_lookup = _build_skills_lookup(skills_facts)
    profile_name = str(
        profile_context_result.get("profile_name")
        or base.get("profile_name")
        or "default"
    ).strip() or "default"

    raw_totals = base.get("totals")
    totals: Mapping[str, Any] = raw_totals if isinstance(raw_totals, Mapping) else {}
    estimator_version = str(
        totals.get("estimator_version")
        or base.get("estimator_version")
        or TOKEN_ESTIMATOR_VERSION
    )
    is_exact = bool(totals.get("is_exact", False))

    source_rows: list[dict[str, Any]] = []
    for src_name in SOURCE_ORDER:
        raw_src = raw_comps.get(src_name)
        src_map: Mapping[str, Any] = raw_src if isinstance(raw_src, Mapping) else {}
        chars = max(0, int(src_map.get("characters") or 0))
        src_bytes = src_map.get("utf8_bytes")
        utf8_bytes = max(0, int(src_bytes) if src_bytes is not None else chars)
        est_tokens = _est_tokens(chars, src_map.get("estimated_tokens"))
        cov = str(src_map.get("coverage") or COVERAGE_VERIFIED)
        if cov != COVERAGE_VERIFIED:
            cov = COVERAGE_COULD_NOT_VERIFY
        source_rows.append({
            "source": src_name,
            "characters": chars,
            "utf8_bytes": utf8_bytes,
            "estimated_tokens": est_tokens,
            "coverage": cov,
            "share_of_fixed": 0.0,
        })

    fixed_chars = int(
        totals["characters"]
        if "characters" in totals and totals.get("characters") is not None
        else sum(r["characters"] for r in source_rows)
    )
    fixed_bytes = int(
        totals["utf8_bytes"]
        if "utf8_bytes" in totals and totals.get("utf8_bytes") is not None
        else sum(r["utf8_bytes"] for r in source_rows)
    )
    fixed_tokens = int(
        totals["estimated_tokens"]
        if "estimated_tokens" in totals and totals.get("estimated_tokens") is not None
        else sum(r["estimated_tokens"] for r in source_rows)
    )

    for row in source_rows:
        row["share_of_fixed"] = round(row["estimated_tokens"] / fixed_tokens, 4) if fixed_tokens > 0 else 0.0

    rows_by_source = {r["source"]: r for r in source_rows}
    profile_sources_verified = all(r["coverage"] == COVERAGE_VERIFIED for r in source_rows)
    profile_cov = COVERAGE_VERIFIED if profile_sources_verified else COVERAGE_COULD_NOT_VERIFY

    # Persona details
    raw_soul = raw_comps.get("identity_soul")
    soul_map: Mapping[str, Any] = raw_soul if isinstance(raw_soul, Mapping) else {}
    persona_injected_chars = rows_by_source["identity_soul"]["characters"]
    persona_raw_chars = int(
        soul_map["raw_chars"]
        if "raw_chars" in soul_map and soul_map.get("raw_chars") is not None
        else persona_injected_chars
    )
    persona_tokens = rows_by_source["identity_soul"]["estimated_tokens"]
    persona_truncated = bool(soul_map.get("truncated", False))
    persona_source = str(soul_map.get("source") or "SOUL.md")
    persona_path = str(soul_map["path"]) if soul_map.get("path") else None
    persona_cov = rows_by_source["identity_soul"]["coverage"]

    # Skills details
    raw_auto = raw_comps.get("auto_loaded_skill_bodies")
    auto_map: Mapping[str, Any] = raw_auto if isinstance(raw_auto, Mapping) else {}
    raw_loaded_skills = auto_map.get("loaded_skills")
    loaded_skills: Sequence[Mapping[str, Any]] = (
        [s for s in raw_loaded_skills if isinstance(s, Mapping)]
        if isinstance(raw_loaded_skills, Sequence)
        else ()
    )
    auto_loaded_count = len(loaded_skills)
    largest_auto_chars = max((int(s.get("injected_chars") or 0) for s in loaded_skills), default=0)
    per_skill_estimates = [
        _estimate_skill_tokens(s, skills_lookup, profile_path)
        for s in loaded_skills
    ]
    largest_auto_tokens = max((tok for tok, _ in per_skill_estimates), default=0)

    raw_index = raw_comps.get("skills_index_text")
    index_map: Mapping[str, Any] = raw_index if isinstance(raw_index, Mapping) else {}
    listed_in_index = int(
        index_map["listed_skill_count"]
        if "listed_skill_count" in index_map and index_map.get("listed_skill_count") is not None
        else len(index_map.get("listed_skills") or ())
    )
    zero_counted_skill_count = int(
        index_map["zero_counted_skill_count"]
        if "zero_counted_skill_count" in index_map and index_map.get("zero_counted_skill_count") is not None
        else len(index_map.get("zero_counted_skills") or ())
    )

    # Memory details
    raw_mem = raw_comps.get("enabled_memory_files")
    mem_map: Mapping[str, Any] = raw_mem if isinstance(raw_mem, Mapping) else {}
    raw_mem_blk = mem_map.get("memory")
    mem_blk: Mapping[str, Any] = raw_mem_blk if isinstance(raw_mem_blk, Mapping) else {}
    raw_user_blk = mem_map.get("user")
    user_blk: Mapping[str, Any] = raw_user_blk if isinstance(raw_user_blk, Mapping) else {}
    mem_entry_count = int(
        mem_map["entry_count"]
        if "entry_count" in mem_map and mem_map.get("entry_count") is not None
        else (
            int(mem_blk.get("unique_entry_count_injected") or 0)
            + int(user_blk.get("unique_entry_count_injected") or 0)
        )
    )
    mem_entry_count_on_disk = int(mem_blk.get("entry_count_on_disk") or 0) + int(
        user_blk.get("entry_count_on_disk") or 0
    )
    mem_chars = rows_by_source["enabled_memory_files"]["characters"]
    mem_tokens = rows_by_source["enabled_memory_files"]["estimated_tokens"]
    mem_cov = rows_by_source["enabled_memory_files"]["coverage"]

    # Projects
    raw_proj_additions = profile_context_result.get("project_context_additions")
    proj_source: Sequence[Mapping[str, Any]] = (
        [p for p in raw_proj_additions if isinstance(p, Mapping)]
        if isinstance(raw_proj_additions, Sequence) and raw_proj_additions
        else [p for p in project_contexts if isinstance(p, Mapping)]
    )
    projects = _normalize_project_entries(proj_source, effective_max_chars)
    projects_verified = all(p["coverage"] == COVERAGE_VERIFIED for p in projects)

    if projects:
        largest_proj = max(
            projects,
            key=lambda p: (p["estimated_tokens"], p["injected_chars"], p["project_root"]),
        )
        largest_proj_chars = largest_proj["injected_chars"]
        largest_proj_tokens = largest_proj["estimated_tokens"]
        largest_proj_root: str | None = largest_proj["project_root"] or None
    else:
        largest_proj_chars = 0
        largest_proj_tokens = 0
        largest_proj_root = None

    per_turn_chars = fixed_chars + largest_proj_chars
    per_turn_tokens = fixed_tokens + largest_proj_tokens
    measured_inputs_cov = (
        COVERAGE_VERIFIED
        if (profile_sources_verified and projects_verified)
        else COVERAGE_COULD_NOT_VERIFY
    )

    window_share = {
        str(win): round(per_turn_tokens / win, 4)
        for win in REFERENCE_WINDOWS
    }
    resend_cost = {
        "turns_10": per_turn_tokens * 10,
        "turns_50": per_turn_tokens * 50,
        "turns_100": per_turn_tokens * 100,
        "is_estimate": True,
        "ignores_prompt_caching": True,
        "note": RESEND_COST_NOTE,
    }

    ext_configured, ext_provider_name = _extract_external_memory_provider(config)
    external_memory_provider: dict[str, Any] = {
        "configured": ext_configured,
        "provider": ext_provider_name if ext_configured else None,
        "coverage": COVERAGE_COULD_NOT_VERIFY if ext_configured else COVERAGE_VERIFIED,
        "measured": False,
    }

    overall_cov = (
        COVERAGE_COULD_NOT_VERIFY
        if (measured_inputs_cov != COVERAGE_VERIFIED or ext_configured)
        else COVERAGE_VERIFIED
    )

    section: dict[str, Any] = {
        "coverage": overall_cov,
        "estimator_version": estimator_version,
        "is_exact": is_exact,
        "is_lower_bound": True,
        "context_file_max_chars": {
            "value": effective_max_chars,
            "source": max_chars_source,
        },
        "profile": {
            "name": profile_name,
            "coverage": profile_cov,
            "sources": source_rows,
            "fixed_prompt": {
                "characters": fixed_chars,
                "utf8_bytes": fixed_bytes,
                "estimated_tokens": fixed_tokens,
            },
            "skill_counts": {
                "listed_skill_count": listed_in_index,
                "auto_loaded_count": auto_loaded_count,
                "largest_auto_loaded_injected_chars": largest_auto_chars,
                "largest_auto_loaded_estimated_tokens": largest_auto_tokens,
                "zero_counted_skill_count": zero_counted_skill_count,
            },
            "persona": {
                "source": persona_source,
                "path": persona_path,
                "raw_chars": persona_raw_chars,
                "injected_chars": persona_injected_chars,
                "estimated_tokens": persona_tokens,
                "truncated": persona_truncated,
                "coverage": persona_cov,
            },
            "memory": {
                "characters": mem_chars,
                "estimated_tokens": mem_tokens,
                "entry_count": mem_entry_count,
                "entry_count_on_disk": mem_entry_count_on_disk,
                "coverage": mem_cov,
            },
        },
        "projects": projects,
        "per_turn_total": {
            "characters": per_turn_chars,
            "estimated_tokens": per_turn_tokens,
            "fixed_prompt_characters": fixed_chars,
            "fixed_prompt_estimated_tokens": fixed_tokens,
            "largest_project_characters": largest_proj_chars,
            "largest_project_estimated_tokens": largest_proj_tokens,
            "largest_project_root": largest_proj_root,
            "is_lower_bound": True,
        },
        "window_share": window_share,
        "resend_cost": resend_cost,
        "external_memory_provider": external_memory_provider,
        "unmeasured": list(UNMEASURED_DYNAMIC_SOURCES),
        "thresholds": _thresholds_dict(effective_max_chars),
    }

    findings: list[dict[str, Any]] = []

    # 1. context_load.persona_oversized
    if persona_tokens >= PERSONA_REVIEW_TOKENS:
        cls = CLASSIFICATION_WARNING if persona_tokens >= PERSONA_WARNING_TOKENS else CLASSIFICATION_REVIEW
        findings.append(
            make_finding(
                rule_id="context_load.persona_oversized",
                classification=cls,
                coverage=persona_cov,
                affected_identities=[profile_name],
                source_paths=[persona_path] if persona_path else [],
                evidence={
                    "raw_chars": persona_raw_chars,
                    "injected_chars": persona_injected_chars,
                    "estimated_tokens": persona_tokens,
                    "truncated": persona_truncated,
                    "threshold_tokens": PERSONA_WARNING_TOKENS if cls == CLASSIFICATION_WARNING else PERSONA_REVIEW_TOKENS,
                },
                consequence=FINDING_CONSEQUENCES["context_load.persona_oversized"],
            )
        )

    # 2. context_load.auto_loaded_skill_oversized
    for sk, (sk_tokens, sk_estimator) in zip(loaded_skills, per_skill_estimates):
        sk_chars = max(0, int(sk.get("injected_chars") or 0))
        if sk_tokens >= AUTO_SKILL_REVIEW_TOKENS:
            cls = CLASSIFICATION_WARNING if sk_tokens >= AUTO_SKILL_WARNING_TOKENS else CLASSIFICATION_REVIEW
            sk_path = str(sk.get("skill_md_path") or "").strip()
            sk_cov = str(sk.get("coverage") or rows_by_source["auto_loaded_skill_bodies"]["coverage"])
            if sk_cov != COVERAGE_VERIFIED:
                sk_cov = COVERAGE_COULD_NOT_VERIFY
            ev_sk: dict[str, Any] = {
                "injected_chars": sk_chars,
                "estimated_tokens": sk_tokens,
                "estimator_version": sk_estimator,
                "supporting_listing_chars": int(sk.get("supporting_listing_chars") or 0),
                "threshold_tokens": AUTO_SKILL_WARNING_TOKENS if cls == CLASSIFICATION_WARNING else AUTO_SKILL_REVIEW_TOKENS,
            }
            if sk_path:
                ev_sk["skill_md_path"] = sk_path
                ev_sk["path"] = sk_path
            findings.append(
                make_finding(
                    rule_id="context_load.auto_loaded_skill_oversized",
                    classification=cls,
                    coverage=sk_cov,
                    affected_identities=[profile_name],
                    source_paths=[sk_path] if sk_path else [],
                    evidence=ev_sk,
                    consequence=FINDING_CONSEQUENCES["context_load.auto_loaded_skill_oversized"],
                )
            )

    # 3. context_load.skills_index_oversized
    index_chars = rows_by_source["skills_index_text"]["characters"]
    index_tokens = rows_by_source["skills_index_text"]["estimated_tokens"]
    index_cov = rows_by_source["skills_index_text"]["coverage"]
    if (
        index_tokens >= SKILLS_INDEX_REVIEW_TOKENS
        or listed_in_index >= SKILLS_INDEX_REVIEW_COUNT
    ):
        is_warn = (
            index_tokens >= SKILLS_INDEX_WARNING_TOKENS
            or listed_in_index >= SKILLS_INDEX_WARNING_COUNT
        )
        cls = CLASSIFICATION_WARNING if is_warn else CLASSIFICATION_REVIEW
        findings.append(
            make_finding(
                rule_id="context_load.skills_index_oversized",
                classification=cls,
                coverage=index_cov,
                affected_identities=[profile_name],
                source_paths=[],
                evidence={
                    "characters": index_chars,
                    "estimated_tokens": index_tokens,
                    "listed_skill_count": listed_in_index,
                    "zero_counted_skill_count": zero_counted_skill_count,
                    "token_threshold": SKILLS_INDEX_WARNING_TOKENS if is_warn else SKILLS_INDEX_REVIEW_TOKENS,
                    "count_threshold": SKILLS_INDEX_WARNING_COUNT if is_warn else SKILLS_INDEX_REVIEW_COUNT,
                },
                consequence=FINDING_CONSEQUENCES["context_load.skills_index_oversized"],
            )
        )

    # 4. context_load.memory_oversized
    if mem_tokens >= MEMORY_REVIEW_TOKENS:
        cls = CLASSIFICATION_WARNING if mem_tokens >= MEMORY_WARNING_TOKENS else CLASSIFICATION_REVIEW
        mem_paths = [
            str(b["path"])
            for b in (mem_blk, user_blk)
            if isinstance(b, Mapping) and b.get("enabled") and b.get("exists") and b.get("path")
        ]
        findings.append(
            make_finding(
                rule_id="context_load.memory_oversized",
                classification=cls,
                coverage=mem_cov,
                affected_identities=[profile_name],
                source_paths=mem_paths,
                evidence={
                    "characters": mem_chars,
                    "estimated_tokens": mem_tokens,
                    "entry_count": mem_entry_count,
                    "threshold_tokens": MEMORY_WARNING_TOKENS if cls == CLASSIFICATION_WARNING else MEMORY_REVIEW_TOKENS,
                },
                consequence=FINDING_CONSEQUENCES["context_load.memory_oversized"],
            )
        )

    # 5. context_load.fixed_prompt_oversized
    if fixed_tokens >= FIXED_PROMPT_REVIEW_TOKENS:
        cls = CLASSIFICATION_WARNING if fixed_tokens >= FIXED_PROMPT_WARNING_TOKENS else CLASSIFICATION_REVIEW
        findings.append(
            make_finding(
                rule_id="context_load.fixed_prompt_oversized",
                classification=cls,
                coverage=profile_cov,
                affected_identities=[profile_name],
                source_paths=[],
                evidence={
                    "characters": fixed_chars,
                    "estimated_tokens": fixed_tokens,
                    "threshold_tokens": FIXED_PROMPT_WARNING_TOKENS if cls == CLASSIFICATION_WARNING else FIXED_PROMPT_REVIEW_TOKENS,
                },
                consequence=FINDING_CONSEQUENCES["context_load.fixed_prompt_oversized"],
            )
        )

    # 6, 7, 8. Per-project findings
    for proj in projects:
        p_root = proj["project_root"]
        p_cov = proj["coverage"]
        p_tokens = proj["estimated_tokens"]
        p_chars = proj["injected_chars"]
        p_identities = [p_root] if p_root else [profile_name]

        if p_cov != COVERAGE_VERIFIED:
            ev_unv: dict[str, Any] = {
                "coverage": COVERAGE_COULD_NOT_VERIFY,
            }
            if p_root:
                ev_unv["project_root"] = p_root
            findings.append(
                make_finding(
                    rule_id="context_load.project_context_unverified",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=p_identities,
                    source_paths=[p_root] if p_root else [],
                    evidence=ev_unv,
                    consequence=FINDING_CONSEQUENCES["context_load.project_context_unverified"],
                )
            )

        if p_tokens >= PROJECT_CONTEXT_REVIEW_TOKENS:
            cls = CLASSIFICATION_WARNING if p_tokens >= PROJECT_CONTEXT_WARNING_TOKENS else CLASSIFICATION_REVIEW
            ev_proj: dict[str, Any] = {
                "injected_chars": p_chars,
                "estimated_tokens": p_tokens,
                "threshold_tokens": PROJECT_CONTEXT_WARNING_TOKENS if cls == CLASSIFICATION_WARNING else PROJECT_CONTEXT_REVIEW_TOKENS,
            }
            if p_root:
                ev_proj["project_root"] = p_root
            if proj["winning_kind"]:
                ev_proj["winning_kind"] = proj["winning_kind"]
            findings.append(
                make_finding(
                    rule_id="context_load.project_context_oversized",
                    classification=cls,
                    coverage=p_cov,
                    affected_identities=p_identities,
                    source_paths=[f["path"] for f in proj["injected_files"] if f.get("path")],
                    evidence=ev_proj,
                    consequence=FINDING_CONSEQUENCES["context_load.project_context_oversized"],
                )
            )

        for f in proj["injected_files"]:
            fpath = f["path"]
            if f["truncated"]:
                trunc_is_assumed = max_chars_source == "assumed_default"
                trunc_cov = COVERAGE_COULD_NOT_VERIFY if trunc_is_assumed else p_cov
                trunc_consequence = (
                    PROJECT_CONTEXT_TRUNCATED_ASSUMED_CONSEQUENCE
                    if trunc_is_assumed
                    else FINDING_CONSEQUENCES["context_load.project_context_truncated"]
                )
                ev_trunc: dict[str, Any] = {
                    "kind": f["kind"],
                    "raw_chars": f["raw_chars"],
                    "injected_chars": f["injected_chars"],
                    "estimated_tokens": f["estimated_tokens"],
                    "context_file_max_chars": effective_max_chars,
                    "source": max_chars_source,
                }
                if p_root:
                    ev_trunc["project_root"] = p_root
                if fpath:
                    ev_trunc["path"] = fpath
                findings.append(
                    make_finding(
                        rule_id="context_load.project_context_truncated",
                        classification=CLASSIFICATION_REVIEW,
                        coverage=trunc_cov,
                        affected_identities=p_identities,
                        source_paths=[fpath] if fpath else [],
                        evidence=ev_trunc,
                        consequence=trunc_consequence,
                    )
                )

            if f["from_parent"]:
                ev_parent: dict[str, Any] = {
                    "kind": f["kind"],
                    "raw_chars": f["raw_chars"],
                    "injected_chars": f["injected_chars"],
                    "estimated_tokens": f["estimated_tokens"],
                    "from_parent": True,
                }
                if p_root:
                    ev_parent["project_root"] = p_root
                if fpath:
                    ev_parent["path"] = fpath
                findings.append(
                    make_finding(
                        rule_id="context_load.parent_context_injected",
                        classification=CLASSIFICATION_REVIEW,
                        coverage=p_cov,
                        affected_identities=p_identities,
                        source_paths=[fpath] if fpath else [],
                        evidence=ev_parent,
                        consequence=FINDING_CONSEQUENCES["context_load.parent_context_injected"],
                    )
                )

    # 9. context_load.external_memory_provider_unmeasured
    if ext_configured:
        cfg_paths = [f"{profile_path.rstrip('/')}/config.yaml"] if profile_path else []
        ev_ext: dict[str, Any] = {
            "configured": True,
            "measured": False,
        }
        if ext_provider_name in KNOWN_EXTERNAL_MEMORY_PROVIDERS:
            ev_ext["provider"] = ext_provider_name
        findings.append(
            make_finding(
                rule_id="context_load.external_memory_provider_unmeasured",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[profile_name],
                source_paths=cfg_paths,
                evidence=ev_ext,
                consequence=FINDING_CONSEQUENCES["context_load.external_memory_provider_unmeasured"],
            )
        )

    # 10. context_load.per_turn_window_share
    if per_turn_tokens >= WINDOW_SHARE_REVIEW_TOKENS:
        cls = CLASSIFICATION_WARNING if per_turn_tokens >= WINDOW_SHARE_WARNING_TOKENS else CLASSIFICATION_REVIEW
        findings.append(
            make_finding(
                rule_id="context_load.per_turn_window_share",
                classification=cls,
                coverage=measured_inputs_cov,
                affected_identities=[profile_name],
                source_paths=[],
                evidence={
                    "characters": per_turn_chars,
                    "estimated_tokens": per_turn_tokens,
                    "share_32k": window_share["32000"],
                    "share_128k": window_share["128000"],
                    "share_200k": window_share["200000"],
                    "threshold_tokens": WINDOW_SHARE_WARNING_TOKENS if cls == CLASSIFICATION_WARNING else WINDOW_SHARE_REVIEW_TOKENS,
                    "threshold_share": WINDOW_SHARE_THRESHOLD,
                },
                consequence=FINDING_CONSEQUENCES["context_load.per_turn_window_share"],
            )
        )

    if any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in findings):
        section["coverage"] = COVERAGE_COULD_NOT_VERIFY

    return section, sort_findings(findings)


def audit_context_load(
    *,
    profile_facts: Mapping[str, Any],
    profile_context_result: Mapping[str, Any],
    project_contexts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Component entrypoint wrapping `evaluate_context_load` in a §6 component envelope."""
    profile_name = str(
        (profile_facts.get("name") if isinstance(profile_facts, Mapping) else None)
        or (profile_context_result.get("profile_name") if isinstance(profile_context_result, Mapping) else None)
        or "default"
    ).strip() or "default"
    profile_path = (
        str(profile_facts.get("path") or "").strip() or None
        if isinstance(profile_facts, Mapping)
        else None
    )
    config = (
        profile_facts.get("config")
        if isinstance(profile_facts, Mapping) and isinstance(profile_facts.get("config"), Mapping)
        else None
    )
    skills_facts = (
        profile_facts.get("skills")
        if isinstance(profile_facts, Mapping) and isinstance(profile_facts.get("skills"), Mapping)
        else None
    )

    if not isinstance(profile_context_result, Mapping) or "static_profile_base" not in profile_context_result:
        finding = make_finding(
            rule_id="context_load.unverified",
            classification=CLASSIFICATION_REVIEW,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            affected_identities=[profile_name],
            consequence=FINDING_CONSEQUENCES["context_load.unverified"],
        )
        return make_component_envelope(
            findings=[finding],
            coverage=COVERAGE_COULD_NOT_VERIFY,
            extra={"context_load": unverified_context_load("profile_context_unverified")},
        )

    section, findings = evaluate_context_load(
        profile_context_result,
        config=config,
        project_contexts=project_contexts,
        profile_path=profile_path,
        skills_facts=skills_facts,
    )
    return make_component_envelope(
        findings=findings,
        coverage=section["coverage"],
        extra={"context_load": section},
    )
