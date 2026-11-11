"""Lossy, allowlisted persistence DTOs. Raw fact packs remain memory-only.

Text is deliberately withheld rather than trusting key-name secret heuristics.
Hashes are evidence handles, not replayable source content. Re-analysis that needs
source text must recapture it; persisted summaries only support age evaluation.
"""
from collections.abc import Mapping
import hashlib
import json
import math

from . import evidence as _evidence
from .evidence import (
    VOCABULARY,
    EvidenceSerializer,
    generated_digest,
    serialize_evidence,
)
from .evidence_constants import (
    ALLOWED_FINDING_CONSEQUENCES,
    DEFAULT_FINDING_CONSEQUENCE,
    FINDING_CONSEQUENCES,
)
from . import key as _key
from .evidence_wiring import WIRED_NUMERIC_EVIDENCE_KEYS, WIRED_VOCAB_EVIDENCE_KEYS
from .redaction import _CURRENT

PERSISTENCE_VERSION = '2.0.0'
_UNSCOPED = EvidenceSerializer()

_BOOL_FIELDS = frozenset(('is_default', 'is_active', 'stable', 'whole_profile_exact_eligible'))
_INT_FIELDS = frozenset(('logical_bytes', 'deduplicated_bytes', 'memory_bytes',
                         'size', 'dev', 'ino', 'nlink', 'mtime_ns', 'ctime_ns'))
_NULLABLE_STRING_FIELDS = frozenset((
    'proposed_cleanup_id', 'config_digest', 'configuration_match_digest', 'whole_profile_digest',
))
_FACTS_KEYS = ('unit_kind', 'unit_id', 'name', 'path', 'is_default', 'is_active',
               'coverage', 'stable', 'logical_bytes', 'deduplicated_bytes', 'memory_bytes')
_MANIFEST_KEYS = ('unit_kind', 'unit_id', 'root_path', 'manifest_version', 'ownership_manifest_version',
                  'coverage', 'stable', 'unit_digest', 'config_digest', 'configuration_match_digest',
                  'whole_profile_digest', 'whole_profile_exact_eligible', 'logical_bytes',
                  'deduplicated_bytes', 'memory_bytes')
_FILE_META_KEYS = ('sha256', 'size', 'dev', 'ino', 'nlink', 'mtime_ns', 'ctime_ns')
_FINDING_KEYS = ('id', 'classification', 'coverage', 'affected_identities',
                 'source_paths', 'severity', 'proposed_cleanup_id')
_EVIDENCE_NUMERIC_KEYS = frozenset((
    'sessions_examined', 'sessions_classified', 'sessions_with_foreign_memory', 'memory_context_blocks',
    'native_term_occurrences', 'median_system_prompt_chars', 'max_system_prompt_chars',
    'median_memory_block_chars', 'max_memory_block_chars', 'sessions_without_prompt',
    'memory_context_chars', 'contamination_rate', 'earliest_chars', 'latest_chars', 'growth_chars',
    'enabled', 'approval_enabled', 'unattended_skill_writes', 'bundled_modified', 'residue_skills',
    'residue_score', 'machine_paths', 'dates', 'ticket_refs', 'commit_refs', 'session_refs',
    'narration', 'lesson_headings', 'longest_bullet_run', 'total_lines', 'cuts',
    'age_days', 'as_of', 'authoritative_created_at', 'auto_loaded_count',
    'char_limit', 'characters', 'cleanup_eligible', 'configured',
    'context_file_max_chars', 'count', 'count_threshold', 'duplicate_count',
    'end_line', 'entry_count', 'entry_count_on_disk', 'estimated_tokens',
    'exact_tokens', 'from_parent', 'has_directive_phrasing', 'injected_chars',
    'is_exact', 'line', 'listed_skill_count', 'measured', 'over_char_limit',
    'profile_registered_project_count', 'raw_chars', 'raw_content_chars',
    'selected_by_default', 'shadowed_count', 'share_128k', 'share_200k',
    'share_32k', 'share_of_fixed', 'share_threshold', 'size', 'size_bytes',
    'snapshot_differs_from_disk', 'stale_age_days', 'start_line',
    'supporting_bodies_injected_chars', 'supporting_listing_chars',
    'threshold_share', 'threshold_tokens', 'token_threshold', 'tokens',
    'truncated', 'unique_entry_count_injected', 'unverified_entry_count',
    'utf8_bytes', 'zero_counted_skill_count',
)) | WIRED_NUMERIC_EVIDENCE_KEYS  # wired sections: generated from audit/wiring/*.json
_EVIDENCE_VOCAB_KEYS = frozenset((
    'classification', 'coverage', 'estimator_version', 'inspection', 'kind',
    'mapping_status', 'provider', 'reason', 'relationship', 'source',
    'status', 'store', 'target_store', 'winning_kind',
)) | WIRED_VOCAB_EVIDENCE_KEYS  # wired sections: generated from audit/wiring/*.json
_EVIDENCE_PATH_KEYS = frozenset((
    'path', 'project_root', 'skill_md_path',
))


def strict_json(value, ancestors=()):
    if isinstance(value, _evidence.SealedEvidence):
        safe = serialize_evidence(value)
        value = safe.canonical() if isinstance(safe, _evidence.SealedEvidence) else safe
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError('Non-finite audit number')
    if value is None or isinstance(value, str) or type(value) in (int, float, bool):
        return value
    if id(value) in ancestors:
        raise ValueError('Cyclic audit data')
    parents = (*ancestors, id(value))
    if isinstance(value, Mapping) and all(isinstance(k, str) for k in value):
        return {k: strict_json(v, parents) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [strict_json(v, parents) for v in value]
    raise ValueError('Audit data must be typed JSON with string keys')


def _canonical_json(value) -> str:
    return json.dumps(strict_json(value), sort_keys=True, separators=(',', ':'), allow_nan=False)


def control_digest(value):
    """Durable private control index, separate from run-local display tokens."""
    return _key.keyed_digest(_canonical_json(value), domain='control')


def stable_content_digest(value):
    """Persisted cross-run comparison handle, not a per-run display token."""
    return _key.content_digest(hashlib.sha256(_canonical_json(value).encode()).hexdigest())


def digest(value):
    state = _CURRENT.get()
    serializer = state.serializer if state is not None else _UNSCOPED
    return generated_digest(serializer._hmac(_canonical_json(value)))


def _is_valid_dto_field(key: str, item) -> bool:
    if key in _BOOL_FIELDS:
        return type(item) is bool
    if key in _INT_FIELDS:
        return type(item) is int and item >= 0
    if key == 'last_use_timestamp':
        return item is None or type(item) in (int, float)
    if key == 'affected_identities':
        return type(item) is list and all(isinstance(i, (str, Mapping)) for i in item)
    if key in ('id', 'proposed_cleanup_id') and isinstance(item, Mapping):
        return True
    if key == 'source_paths':
        return type(item) is list
    return type(item) is str or isinstance(item, _evidence.GeneratedDigest) or (item is None and key in _NULLABLE_STRING_FIELDS)


def pick(value, keys):
    if not isinstance(value, Mapping):
        raise ValueError('Audit DTO must be a mapping')
    out = {}
    for key in keys:
        if key not in value:
            continue
        if not _is_valid_dto_field(key, strict_json(value[key])):
            raise ValueError('Invalid audit DTO field type: ' + key)
        safe = serialize_evidence({key: value[key]})
        assert isinstance(safe, dict)
        out[key] = next(iter(safe.values()))
    return out


def facts_dto(value):
    out = pick(value, _FACTS_KEYS)
    out['persistence_version'] = PERSISTENCE_VERSION
    out['raw_evidence_digest'] = digest(value)
    out['last_use_evidence'] = pick(value.get('last_use_evidence', {}), ('last_use_timestamp', 'coverage'))
    out['last_use_evidence']['last_use_source'] = 'captured_evidence'
    return out


def manifest_dto(value):
    out = pick(value, _MANIFEST_KEYS)
    out['capture_digest'] = digest(value)
    files = {path: pick(meta, _FILE_META_KEYS) for path, meta in value.get('files', {}).items()}
    out['files'] = serialize_evidence({'root_path': value.get('root_path'), 'files': files})['files']
    return out


def finding_dto(raw):
    from .contract import normalize_finding
    f = normalize_finding(raw)
    out = pick(f, _FINDING_KEYS)
    rule_id = f.get('id')
    is_context_load_rule = isinstance(rule_id, str) and rule_id.startswith('context_load.')
    raw_consequence = f.get('consequence')
    if isinstance(raw_consequence, str) and raw_consequence in ALLOWED_FINDING_CONSEQUENCES:
        consequence = raw_consequence
    elif isinstance(rule_id, str):
        consequence = FINDING_CONSEQUENCES.get(rule_id, DEFAULT_FINDING_CONSEQUENCE)
    else:
        consequence = DEFAULT_FINDING_CONSEQUENCE
    ev_out: dict[str, object] = {'source_digest': digest(f)}
    raw_ev = f.get('evidence')
    if isinstance(raw_ev, Mapping):
        for k, v in raw_ev.items():
            if k == 'source_digest':
                continue
            if k in _EVIDENCE_NUMERIC_KEYS and type(v) in (int, float, bool):
                if type(v) is float and not math.isfinite(v):
                    continue
                ev_out[k] = v
            elif (isinstance(rule_id, str) and rule_id.startswith('session_contamination.')
                  and k == 'foreign_families' and isinstance(v, Mapping)):
                families = {'python', 'javascript', 'java', 'cpp', 'csharp', 'rust', 'go', 'php',
                            'ruby', 'swift', 'kotlin', 'unreal', 'unity', 'godot', 'blender', 'houdini'}
                ev_out[k] = {family: count for family, count in v.items()
                             if family in families and type(count) is int and count >= 0}
            elif k in _EVIDENCE_VOCAB_KEYS and type(v) is str and v in VOCABULARY:
                ev_out[k] = v
            elif (
                is_context_load_rule
                and k in _EVIDENCE_PATH_KEYS
                and (type(v) is str and v or isinstance(v, _evidence.SealedEvidence))
            ):
                safe = serialize_evidence({k: v})
                if isinstance(safe, dict) and k in safe:
                    ev_out[k] = safe[k]
    out.update(consequence=consequence,
               detail=consequence,
               limitations='Source-derived text withheld by persistence policy.',
               fix=None, evidence=ev_out)
    return out


def component_dto(value):
    return {**pick(value, ('component_id', 'coverage', 'classification')),
            'findings': [finding_dto(f) for f in value.get('findings', ())],
            'operational_error': 'Component verification failed' if value.get('operational_error') else None}
