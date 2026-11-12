"""The evidence serialization boundary: unknown strings are never persisted raw.

The run key is ephemeral. A sealed value can be serialized again without losing
its evidence identity; ordinary dictionaries cannot claim to be sealed values.
"""
from dataclasses import dataclass
import hashlib
import hmac
import importlib.metadata
import json
import math
from pathlib import Path
import re
import secrets
import shlex
import shutil
from urllib.parse import urlsplit

from .evidence_constants import ALLOWED_FINDING_CONSEQUENCES, FINDING_CONSEQUENCES, RULE_IDS, SCOPE_LABELS
from .evidence_vocabulary import CREDENTIAL_KEY_LABELS, SCHEMA_KEYS, VOCABULARY as _VOCABULARY
from .evidence_wiring import WIRED_FIXED_SENTENCES, WIRED_SECTIONS
from .secret_paths import CREDENTIAL_IN_NAME, credential_tokens

try:
    _PARSER_LABEL = 'PyYAML:' + importlib.metadata.version('PyYAML')
except importlib.metadata.PackageNotFoundError:
    _PARSER_LABEL = 'PyYAML:missing'

CODE_LABELS = frozenset((
    'Bounded audit: static context load and project context chains were not collected.',
    'CI workflow', 'Cargo aliases and toolchain configuration',
    'Estimated cumulative prompt tokens re-sent across turns, ignoring provider prompt caching.',
    'Explicit quick bounded audit',
    'Full static audit (outward evidence unavailable)', 'Project-outward full static audit',
    'Program behavior cannot be verified: code correctness and safety are outside static inventory.',
    'Pure file-type gate. Classification is not execution or safety approval.',
    'Python interpreter startup', 'Source-derived text withheld by persistence policy.',
    'Static audit finding; review the referenced source.',
    'This audit cannot tell whether working code is correct.',
    'active profile, selected projects, evidenced outgoing paths',
    'application configuration load', 'build, install, or task runner',
    'code or declaration in this file; behavior not evaluated', 'configured or implicit execution',
    'dependency installation', 'desktop autostart', 'editor task or debugger launch',
    'editor workspace tasks or debugger launch', 'environment or package-manager startup',
    'hook handler load', 'lstat metadata only; credential stores never opened',
    'notebook kernel execution', 'plugin import',
    'program-code inventory for load root; behavior not evaluated', 'raw credential values',
    'registered hook', 'runtime execution', 'scheduled job',
    'selected roots and evidenced blending only', 'service manager activation',
    'static inspection only; not runtime safety', 'top-level metadata and config declarations only',
    'unrelated projects/profiles', 'user interpreter startup', 'version-control hook',
    'whole active profile and evidenced outgoing paths',
    *ALLOWED_FINDING_CONSEQUENCES,
))

VOCABULARY = _VOCABULARY | RULE_IDS | SCOPE_LABELS | CODE_LABELS | frozenset({
    'credential_store', 'credential_store_not_opened',
    'memories/MEMORY.md', 'memories/USER.md', 'config.yaml', 'SOUL.md',
    'credential_in_name',
    'skipped_folders',  # outward sweep: dependency, cache and Git object folders not walked
    'default_profile_never_archived', 'active_profile_never_archived', 'within_active_threshold',  # facts.evaluate_profile_age_and_unused
})

_FACTORY = object()
_HEX64_RE = re.compile(r'[0-9a-f]{64}')
_CONTROL_ID_RE = re.compile(r'(?:cross_|component_)[0-9a-f]{64}')
_SEALED_KEY_RE = re.compile(r'hmac:[0-9a-f]{64}')
_HOST_RE = re.compile(r'[A-Za-z0-9_.:\-]+')
_REDACTED_OVERLAP_RE = re.compile(r'evidence_redacted_due_to_credential_overlap: [0-9]+ items')
_URL_SCHEMES = frozenset({'http', 'https', 'ssh', 'ftp', 'ftps'})
_ENDPOINT_SCHEMES = frozenset({None, *_URL_SCHEMES})
_LEAF_KINDS = frozenset({'text', 'unresolved_reference', 'argument', 'credential_overlap', 'url', 'command', 'endpoint'})
_PATH_FIELDS = frozenset({
    'path', 'source', 'target', 'target_root', 'load_root', 'sample_paths',
    'canonical_path', 'root_path', 'source_paths', 'skill_md_path',
    'project_root', 'largest_project_root',
    'paths', 'location', 'plugin_folders_with_dotenv', 'affected_identities',
    'profile_path', 'duplicate_groups', 'optional_root',
    'unselected_project_roots', 'report_store_exclusions',
    'parent_context_boundary', 'parent_context_boundaries',
    'samples', 'database',
    'cwd', 'git_repo_root', 'project_path', 'working_directory',
    'workspace_path', 'primary_path', 'stored_path',
})
_PATH_KEY_MAPS = frozenset({
    'files', 'regions', 'invocation_roots', 'parent_context_boundaries', 'databases',
})


class _PathWithheld:
    """A resolved path that must not be printed. Not a sealed value and not a path."""
    __slots__ = ('reason',)

    def __init__(self, reason):
        self.reason = reason


def _withheld_marker(reason):
    return {'path': None, 'path_withheld': reason}


def _marker_reason(item):
    """The withhold reason when ``item`` is exactly the marker dict, else None."""
    if (isinstance(item, dict) and item.get('path') is None
            and item.get('path_withheld') == CREDENTIAL_IN_NAME
            and set(item) == {'path', 'path_withheld'}):
        return CREDENTIAL_IN_NAME
    return None
_FIXED_SENTENCES = CODE_LABELS | SCOPE_LABELS | WIRED_FIXED_SENTENCES
_COVERAGE_TOKENS = frozenset({
    'verified', 'could_not_verify', 'not_included', 'not_applicable',
    'partial', 'could_not_compare', 'credential_store_not_opened',
})
_STATUS_TOKENS = frozenset({
    'completed', 'running', 'cancelled', 'failed', 'pending', 'incomplete',
    'invalidated', 'not_run', 'not_measured', 'not_present', 'ok', 'pass', 'fail', 'error',
    'proposed', 'empty_dir', 'missing_manifest', 'portable_manifest_not_read',
    'symlink_skipped', 'kind_not_verified',
})
_CLASSIFICATION_TOKENS = frozenset({'info', 'review_suggested', 'warning'})
_SEVERITY_TOKENS = frozenset({'info', 'warn', 'error'})
_COMPONENT_TOKENS = frozenset({
    'profile_context', 'context_load', 'memory', 'executable_inventory',
    'skill_hygiene', 'write_settings', 'session_contamination',
    'template_drift', 'static_code', 'tools_lock', 'audit_scope',
    'profile_capture', 'registrations', 'project_capture', 'template_capture',
    *WIRED_SECTIONS,
})
_STRUCTURAL_REASON_TOKENS = VOCABULARY - frozenset({
    'local', 'default', 'main', 'approve', 'flash', 'yes', 'no',
    'byterover', 'retaindb', 'smart', 'manual', 'deny', 'approval_off', 'backup_off',
    'mini', 'nano', 'haiku', 'lite', 'small',
})
_STRUCTURAL_FIELD_TOKENS = {
    **{k: _COVERAGE_TOKENS for k in (
        'coverage', 'hub_coverage', 'project_coverage', 'growth_coverage', 'age_coverage',
        'chronology_coverage', 'foreign_technology_coverage', 'other_os_coverage',
        'manifest_coverage', 'dynamic_contributions_coverage', 'dynamic_plugins_coverage',
        'security_check_coverage',
    )},
    **{k: _STATUS_TOKENS for k in ('status', 'outcome_status', 'mapping_status', 'legacy_status_ignored')},
    'classification': _CLASSIFICATION_TOKENS,
    'severity': _SEVERITY_TOKENS,
    **{k: RULE_IDS for k in ('id', 'rule_id', 'finding_id', 'finding_ids')},
    **{k: _COMPONENT_TOKENS for k in ('component_id', 'required_components', 'required_collectors')},
    'unit_kind': frozenset({'profile', 'project'}),
    'mode': frozenset({'full_home', 'bounded', 'live'}),
    'read_mode': frozenset({'mode=ro', 'immutable'}),
    'must_preserve': frozenset({'user_data', 'config', 'credentials_metadata_only', 'unknown'}),
    'confidence': frozenset({'verified', 'unknown'}),
    'execution': frozenset({'never'}),
    **{k: _STRUCTURAL_REASON_TOKENS for k in (
        'reason', 'reasons', 'code', 'truncated_by', 'cut_reasons', 'path_withheld',
        'mode_check', 'mode_check_reason', 'relationship', 'inspection', 'resolution',
    )},
    # Unique leaf names: the value is chosen by audit code, never read from the home.
    # limit_source: chosen in memory_load._resolve_inputs, copied by memory_load._char_limits.
    'limit_source': frozenset({'config', 'default', 'could_not_verify', 'caller', 'host'}),
    # curator_enabled_source: set by skill_ledger.audit_skill_ledger.
    'curator_enabled_source': frozenset({'caller', 'config', 'default', 'could_not_verify'}),
    'last_use_source': frozenset({'captured_evidence'}),  # persistence.facts_dto
    'project_families': frozenset({  # session_contamination._project; _contamination_report emits them
        'python', 'javascript', 'java', 'cpp', 'csharp', 'rust', 'go', 'php', 'ruby',
        'swift', 'kotlin', 'unreal', 'unity', 'godot', 'blender', 'houdini',
    }),
    # file_kind: profile_duplicates._file_kind, plus the size-only classes from
    # profile_duplicates._size_only_class (_SIZE_ONLY_CLASSES / SIZE_ONLY_OTHER_CLASS).
    'file_kind': frozenset({
        'hub_index_cache', 'models_dev_cache', 'provider_models_cache', 'skill_md',
        'identity_md', 'agents_md', 'database', 'executable_file', 'large_file',
        'env_file', 'auth_json', 'config_yaml', 'credential_other',
    }),
    # provenance: set by skill_hygiene.audit_skill_hygiene and
    # skill_hygiene._resolve_manifest_origins.
    'provenance': frozenset({'external_dir', 'stock', 'user_authored', 'hub'}),
    'name_pattern_label': frozenset({'name_pattern_not_in_hermes_source'}),  # dead_stores.NAME_PATTERN_LABEL
    'parked_name_label': frozenset({'name_pattern_not_in_hermes_source'}),
    'tool_cache_label': frozenset({'cache_in_work_folder'}),
    # secret_kind: secret_file_copies.EXPECTED_SECRET_KINDS, emitted by
    # secret_file_copies._match_backup_of_expected_secret.
    'secret_kind': frozenset({
        'dotenv', 'auth_json', 'shared_auth', 'credentials_store', 'mcp_tokens', 'pairing',
        'vault', 'platform_token_stores', 'oauth_stores', 'browser_and_home_stores',
        'os_credential_dirs',
    }),
    'target_store': frozenset({'memory', 'user'}),  # vendor.profile_context.audit_profile_context
    'approvals_mode': frozenset({'approval_off', 'manual', 'smart', 'other'}),  # unattended_exposure.audit_unattended_exposure
    'cli_powerful_tools': frozenset({  # unattended_exposure.POWERFUL_TOOLS; emitted by
        # unattended_exposure._evaluate_platform_toolsets.
        'terminal', 'code_execution', 'cronjob', 'delegation', 'memory', 'skill_manage',
        'computer_use', 'browser',
    }),
    'unmeasured': frozenset({  # context_load.UNMEASURED_DYNAMIC_SOURCES
        'dynamic_plugin_prompt_sections', 'plugin_registered_skills', 'builtin_tool_schemas',
        'mcp_tool_schemas', 'external_memory_provider_prefetch_and_blocks',
        'caller_ephemeral_system_message', 'workspace_git_status_snapshot',
        'runtime_environment_metadata',
    }),
    'estimator_version': frozenset({'hermes-rough-bytes4-cjk1-v1'}),  # vendor.profile_context.TOKEN_ESTIMATOR_VERSION
    'contract_version': frozenset({'2.0.0'}),
    'observation': frozenset({'size_only_not_hashed'}),
    'reference': frozenset({'newest_mtime_in_home'}),
    'reference_clock': frozenset({'newest_event'}),
    'gc_ever_run': frozenset({'could_not_verify', 'verified', 'not_measured'}),
    'schema': frozenset({'unknown'}),  # outward_db.inspect_database; classified names are not vocabulary words
    'contract': frozenset({'2.0.0'}),
    'parser_policy': frozenset({'safe-load-json-v2'}),
    'persistence_policy': frozenset({'allowlist-v2'}),
    'ineligible_reason': frozenset({'last_use_could_not_verify', 'default_profile_never_archived',  # facts.evaluate_profile_age_and_unused
                                    'active_profile_never_archived', 'within_active_threshold'}),
}

# Same leaf name, two jobs. A rule matches the end of the key path ('*' is one key,
# including a dotted settings key such as 'approvals.mode'). The longest match wins.
# A value outside that rule's set stays taint-first. Ambiguous leaves are not in
# _STRUCTURAL_FIELD_TOKENS, so a bare use still seals.
# String values set_row emits. unattended_exposure._evaluate_settings_and_sanity.set_row.
# Bools and counts are not strings. Unknown input becomes 'other' or is omitted.
_SETTING_VALUES = frozenset({
    'approval_off', 'approve', 'deny', 'manual', 'smart', 'other',
    'local', 'docker', 'modal', 'daytona', 'vercel_sandbox', 'ssh', 'managed_modal',
    'project', 'strict', 'unlimited',
    'quick', 'full', 'backup_off',
    'stash', 'discard', 'switch', 'update_in_place',
    'unset', 'unclassified', 'flash', 'mini', 'nano', 'haiku', 'lite', 'small',
})
_STRUCTURAL_PATH_RULES = (
    # Settings provenance. write_settings._resolve_settings;
    # unattended_exposure._evaluate_settings_and_sanity.set_row.
    (('settings', '*', 'source'), frozenset({'config', 'default', 'could_not_verify'})),
    (('tool_selection', 'source'), frozenset({'config', 'default', 'could_not_verify'})),
    (('flush_interval', 'source'), frozenset({'not_found'})),
    # Finding evidence copies that token. Sealed as a bare list
    # (store._store_component_results) and under findings[]
    # (contract.canonical_report_payload). write_settings.audit_write_settings;
    # unattended_exposure.audit_unattended_exposure.
    (('evidence', 'source'), frozenset({'config', 'default', 'could_not_verify', 'not_found'})),
    # vendor.memory.audit_profile_memory. Built-in store label, not a user name.
    # Bare `store` stays user data.
    (('evidence', 'store'), frozenset({'memory', 'user'})),
    # context_load.resolve_context_file_max_chars; vendor.profile_context.audit_profile_context.
    (('context_file_max_chars', 'source'), frozenset({'config', 'assumed_default'})),
    (('persona', 'source'), frozenset({'SOUL.md', 'DEFAULT_AGENT_IDENTITY'})),
    # context_load.SOURCE_ORDER; emitted as row['source'] by context_load._build_source_rows.
    (('sources', 'source'), frozenset({
        'identity_soul', 'core_guidance', 'enabled_memory_files',
        'auto_loaded_skill_bodies', 'skills_index_text',
    })),
    # memory_load.audit_memory_load chooses these labels, never a value from the home.
    (('memory_load', 'foreign_technology_reason'), frozenset({'no_projects', 'input_unknown'})),
    # memory_load._resolve_inputs. The leaf name is the input, the value is the provenance token.
    (('input_sources', '*'), frozenset({'config', 'default', 'could_not_verify', 'caller', 'host'})),
    # Coerced setting labels, not the raw config string. unattended_exposure.py set_row values.
    (('settings', '*', 'value'), _SETTING_VALUES),
    # kanban_residue.audit_kanban_residue maps the slug to a label; the slug itself is not emitted.
    (('boards', 'board'), frozenset({'default', 'named_board'})),
    # memory_load._scan_snapshots. 'files' is also the snapshot file list.
    (('files', 'kind'), frozenset({'memory', 'user'})),
    # memory_load._scan_snapshots ('snapshot') and memory_load.audit_memory_load
    # ('main'/'profile').
    (('files', 'scope'), frozenset({'main', 'profile', 'snapshot'})),
    # secret_file_copies._match_backup_of_expected_secret. Region .scope sentences are
    # fixed sentences, not this set.
    (('copies', 'scope'), frozenset({'home', 'profile', 'backups'})),
    (('tool_selection', 'surface'), frozenset({'cli'})),  # write_settings.audit_write_settings
    # Finding evidence copies of closed labels. Top-level terminal_backend/size_class stay user data.
    (('evidence', 'terminal_backend'), frozenset({
        'local', 'docker', 'modal', 'daytona', 'vercel_sandbox', 'ssh', 'managed_modal', 'other',
    })),
    (('smart_approval', 'size_class'), frozenset({
        'unset', 'unclassified', 'flash', 'mini', 'nano', 'haiku', 'lite', 'small', 'other',
    })),
    # home_workdirs._directory_entry_records. Other kind leaves (credentials,
    # invocations) have their own sets.
    (('not_hermes_folders', 'kind'), frozenset({'symlink', 'directory', 'regular', 'special'})),
    (('credentials', 'kind'), frozenset({'credential_store', 'credential_store_not_opened'})),
    (('dynamic_invocations', 'kind'), frozenset({'execution_surface', 'program_code'})),
    (('dynamic_invocations', 'kinds'), frozenset({'execution_surface', 'program_code'})),
    (('evidence', 'kind'), frozenset({'kanban_task_workspace', 'symlink'})),  # outward.collect_outward
    (('families', 'kind'), frozenset({'alphabetic_prefix', 'digit_series'})),  # profile_duplicates
    # profile_duplicates._summarize_identity_files. The leaf is the identity-file label,
    # not a user filename.
    (('files', 'file'), frozenset({'SOUL.md', 'MEMORY.md', 'USER.md'})),
    # Only names in unattended_exposure.VALID_HOOKS are emitted
    # (unattended_exposure.audit_unattended_exposure).
    (('hook_plugins', 'hooks'), frozenset({
        'pre_tool_call', 'post_tool_call', 'transform_terminal_output', 'transform_tool_result',
        'transform_llm_output', 'pre_llm_call', 'post_llm_call',
        'on_stream_start', 'on_stream_delta', 'on_stream_end', 'on_interim_message',
        'pre_verify', 'pre_api_request', 'post_api_request', 'api_request_error',
        'pre_auxiliary_call', 'post_auxiliary_call', 'transform_api_error_classification',
        'on_session_start', 'on_session_end', 'on_session_finalize', 'on_session_reset',
        'on_session_delete', 'on_skill_lifecycle', 'subagent_start', 'subagent_stop',
        'pre_gateway_dispatch', 'post_gateway_admission', 'agent_loop_stopped',
        'pre_approval_request', 'post_approval_response',
        'on_human_input_request', 'on_human_input_resolved',
        'on_room_member_activity', 'pre_transcription',
        'kanban_task_claimed', 'kanban_task_completed', 'kanban_task_blocked',
        'on_kanban_worker_spawned', 'on_kanban_worker_exited', 'on_kanban_worker_stale_claim',
        'on_kanban_task_updated', 'on_kanban_dispatch_tick',
        'gateway_platform_event', 'pre_command', 'post_compaction',
    })),
    (('hook_plugins', 'prompt_or_approval_hooks'), frozenset({
        'pre_llm_call', 'pre_gateway_dispatch', 'pre_tool_call', 'transform_tool_result',
        'transform_terminal_output', 'transform_llm_output', 'pre_approval_request',
        'post_approval_response', 'on_human_input_request', 'on_human_input_resolved',
    })),
    # unattended_exposure.audit_unattended_exposure.pinned_state. A bare `pinned` stays
    # user data (sealing tests).
    (('hook_plugins', 'pinned'), frozenset({'yes', 'no', 'unknown'})),
    # scope.limits.regions.<name>.name is the region id, not a profile name.
    (('regions', '*', 'name'), frozenset({
        'active_profile', 'home_startup', 'sibling_declarations', 'credentials',
        'cross_project_isolation', 'dynamic_execution', 'identity', 'other_projects',
        'plugins', 'project_tree', 'session_history', 'shared_infrastructure',
        'sibling_profiles', 'skills',
    })),
)


def _structural_path_allowed(path):
    """Longest end-anchored path rule whose value set applies, or None."""
    keys = tuple(path or ())
    best, best_len = None, -1
    for suffix, allowed in _STRUCTURAL_PATH_RULES:
        n = len(suffix)
        if n <= len(keys) and n > best_len and all(
            pat == '*' or pat == key for pat, key in zip(suffix, keys[-n:])
        ):
            best, best_len = allowed, n
    return best


def structural_tokens():
    """Every token the structural table may keep. Tests use this as taint noise."""
    tokens = set()
    for allowed in _STRUCTURAL_FIELD_TOKENS.values():
        tokens.update(allowed)
    for _suffix, allowed in _STRUCTURAL_PATH_RULES:
        tokens.update(allowed)
    return frozenset(tokens)


def _is_structural_scalar(field, value, path=()):
    if not isinstance(value, str):
        return False
    if value == _PARSER_LABEL or value in _FIXED_SENTENCES or _REDACTED_OVERLAP_RE.fullmatch(value):
        return True
    keys = tuple(path) if path else ((field,) if isinstance(field, str) else ())
    allowed = _structural_path_allowed(keys)
    if allowed is not None:
        return value in allowed
    allowed = _STRUCTURAL_FIELD_TOKENS.get(field)
    return allowed is not None and value in allowed


def _validated_str(cls, value, _factory, pattern, factory_error, value_error):
    if _factory is not _FACTORY:
        raise TypeError(factory_error)
    if not pattern.fullmatch(value):
        raise ValueError(value_error)
    return str.__new__(cls, value)


def _valid_endpoint_fields(scheme, host, port):
    return (scheme in (None, *_URL_SCHEMES)
            and (host is None or (isinstance(host, str) and bool(_HOST_RE.fullmatch(host))))
            and (port is None or (type(port) is int and 0 < port < 65536)))


class SealedEvidence(dict):
    """Immutable leaf, produced only here, never by file/config parsers."""
    def __init__(self, *, _factory=None, **values):
        if _factory is not _FACTORY:
            raise TypeError("Use the evidence serializer factory")
        self._canonical = json.dumps(values, sort_keys=True, allow_nan=False)
        super().__init__(json.loads(self._canonical))

    def canonical(self):
        return json.loads(self._canonical)

    def _immutable(self, *args, **kwargs):
        raise TypeError('Sealed evidence cannot be mutated')
    __setitem__ = __delitem__ = clear = pop = popitem = _immutable  # type: ignore[assignment]
    setdefault = update = __ior__ = _immutable  # type: ignore[assignment]


class GeneratedDigest(str):
    """Digest computed by audit code, not a string parsed from inspected data."""
    def __new__(cls, value, *, _factory=None):
        return _validated_str(cls, value, _factory, _HEX64_RE, 'Use the generated digest factory', 'Invalid generated digest')


class ControlIdentity(str):
    """Code-computed, keyed SQL collector index, never arbitrary source text."""
    def __new__(cls, value, *, _factory=None):
        return _validated_str(cls, value, _factory, _CONTROL_ID_RE, 'Use the control identity factory', 'Invalid control identity')


def generated_digest(value):
    return GeneratedDigest(value, _factory=_FACTORY)


def control_identity(value):
    return ControlIdentity(value, _factory=_FACTORY)


class PersistedJSON(str):
    """JSON emitted by the evidence/control DTO boundary, not captured text."""


class SealedKey(str):
    """An HMAC-generated mapping key, not an untrusted source key."""
    def __new__(cls, value, *, _factory=None):
        return _validated_str(cls, value, _factory, _SEALED_KEY_RE, "Use the evidence serializer factory", "Invalid sealed key")


@dataclass(frozen=True)
class Evidence:
    value: str
    kind: str = 'text'
    path: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class EvidenceEndpoint:
    host: str | None = None
    scheme: str | None = None
    port: int | None = None


class EvidenceSerializer:
    def __init__(self):
        self._key = secrets.token_bytes(32)
        self._project_roots = set()

    @staticmethod
    def _seal(**value):
        return SealedEvidence(_factory=_FACTORY, **value)

    @staticmethod
    def _seal_key(value):
        return SealedKey(value, _factory=_FACTORY)

    def _valid_leaf(self, value):
        if not isinstance(value, dict):
            return False
        endpoint = set(value) == {'scheme', 'host', 'port'}
        kind = value.get('kind')
        token = {'kind', 'hmac', 'location'}
        fields = token
        if kind == 'url':
            fields = token | ({'scheme', 'host', 'port'} if 'port' in value else {'scheme', 'host'})
        elif kind == 'command' and 'arguments' in value:
            fields = token | {'executable', 'argument_count', 'arguments'}
            args, exe = value['arguments'], value.get('executable')
            if (not isinstance(args, list) or type(value.get('argument_count')) is not int
                    or value['argument_count'] != len(args)
                    or not all(self._valid_leaf(a) and a.get('kind') == 'argument' for a in args)
                    or (exe is not None and not isinstance(exe, str))):
                return False
        if not endpoint:
            hmac_val, loc = value.get('hmac'), value.get('location')
            if (not isinstance(kind, str) or kind not in _LEAF_KINDS or set(value) != fields
                    or not isinstance(hmac_val, str) or not _HEX64_RE.fullmatch(hmac_val)
                    or not isinstance(loc, dict) or set(loc) != {'path', 'line'}
                    or (loc['path'] is not None and not isinstance(loc['path'], str))
                    or (loc['line'] is not None and (type(loc['line']) is not int or loc['line'] <= 0))):
                return False
        return not (endpoint or kind == 'url') or _valid_endpoint_fields(
            value.get('scheme'), value.get('host'), value.get('port')
        )

    def _hmac(self, value):
        return hmac.new(self._key, value.encode('utf-8', errors='surrogatepass'), hashlib.sha256).hexdigest()

    @staticmethod
    def _path(value, base=None):
        if not isinstance(value, str) or not value or '\x00' in value:
            return None
        try:
            p = Path(value)
            if not p.is_absolute():
                if base is None:
                    return None
                p = Path(base).parent / p
            resolved = p.resolve()
            resolved.lstat()
            return str(resolved)
        except (OSError, ValueError, RuntimeError):
            return None

    @staticmethod
    def _tainted(value):
        if not isinstance(value, str):
            return False
        from .redaction import _CURRENT, canonical_forms
        state = _CURRENT.get()
        return bool(state is not None and state.values.intersection(canonical_forms(value)))

    def _credential_path(self, value):
        """Register credential tokens found in ``value`` and report whether any matched.

        The matched spelling is added to the run taint so the same string elsewhere
        is sealed. The path itself is not rewritten.
        """
        if not isinstance(value, str) or not value:
            return False
        tokens = credential_tokens(value)
        if not tokens:
            return False
        from .redaction import _CURRENT
        state = _CURRENT.get()
        if state is not None:
            for token in tokens:
                state.add(token)
            state.add(value)
        return True

    def _location(self, location):
        raw = location.get('path')
        path = self._path(raw)
        credential = self._credential_path(path)
        credential = self._credential_path(raw) or credential
        if credential or self._tainted(path):
            path = None
        line = location.get('line')
        return {'path': path, 'line': line if type(line) is int and line > 0 else None}

    def token(self, value, kind, location):
        return self._seal(kind=kind, hmac=self._hmac(value), location=self._location(location))

    def scalar(self, value, field, location, path=()):
        if _is_structural_scalar(field, value, path):
            return value
        if ((field in {'config_keys', 'key_path'} and value in CREDENTIAL_KEY_LABELS)
                or value in VOCABULARY):
            return self.token(value, 'credential_overlap', location) if self._tainted(value) else value
        if field == 'provider':
            return self.token(value, 'text', location)
        if field in _PATH_FIELDS or (field is None and value in self._project_roots):
            resolved = self._path(value, location.get('path'))
            credential = self._credential_path(value)
            credential = self._credential_path(resolved) or credential
            if credential:
                return _PathWithheld(CREDENTIAL_IN_NAME)
            if resolved is not None:
                if self._tainted(resolved) or self._tainted(value):
                    from .redaction import _CURRENT
                    state = _CURRENT.get()
                    clean_location = dict(location)
                    if clean_location.get('path') == resolved:
                        clean_location['path'] = None
                    if state is not None:
                        previous_source = state.source
                        state.source = location.get('path')
                        state.note(resolved, persisted=True)
                        state.source = previous_source
                    return self.token(value, 'credential_overlap', clean_location)
                return resolved
        if '://' in value:
            try:
                url = urlsplit(value)
                if url.scheme in _URL_SCHEMES and url.hostname:
                    if self._tainted(url.hostname):
                        return self.token(value, 'credential_overlap', location)
                    return self._seal(kind='url', scheme=url.scheme, host=url.hostname,
                                      port=url.port, hmac=self._hmac(value), location=self._location(location))
            except ValueError:
                pass
        kind = ('unresolved_reference'
                if field in _PATH_FIELDS or value.startswith(('/', './', '../', '~/')) else 'text')
        return self.token(value, kind, location)

    def _revalidate_sealed(self, item: dict) -> dict:
        cleaned = {
            k: ([self._revalidate_sealed(v) if isinstance(v, dict) else v for v in val]
                if isinstance(val, list) else self._revalidate_sealed(val) if isinstance(val, dict) else val)
            for k, val in item.items()
        }
        if isinstance(cleaned.get('location'), dict):
            cleaned['location'] = self._location(cleaned['location'])
        if 'executable' in cleaned:
            raw_exe = cleaned.get('executable')
            executable = self._path(raw_exe)
            cleaned['executable'] = None if (
                self._credential_path(executable) or self._credential_path(raw_exe) or self._tainted(executable)
            ) else executable
        if self._tainted(cleaned.get('host')):
            cleaned['host'] = None
        return cleaned

    def _serialize_command(self, text, location):
        try:
            words = shlex.split(text)
        except ValueError:
            return self.token(text, 'command', location)
        executable = None
        if words:
            raw_exe = words[0]
            executable = self._path(raw_exe, location['path'])
            if executable is None and '/' not in raw_exe:
                executable = self._path(shutil.which(raw_exe))
        if self._credential_path(executable) or self._credential_path(words[0] if words else None) or self._tainted(executable):
            executable = None
        return self._seal(
            kind='command', executable=executable, argument_count=max(0, len(words) - 1),
            arguments=[self.token(arg, 'argument', location) for arg in words[1:]],
            hmac=self._hmac(text), location=self._location(location),
        )

    def _serialize_dict_key(self, key, field, root_path):
        if not isinstance(key, str):
            raise ValueError('Audit evidence requires string keys')
        key_path = self._path(key.removeprefix('project:')) if field in _PATH_KEY_MAPS else None
        relative_file = (self._path(key, str(Path(root_path) / '_manifest'))
                         if field == 'files' and isinstance(root_path, str) else None)
        if relative_file is not None and (Path(key).is_absolute()
                or any(part in {'', '.', '..'} for part in key.split('/'))):
            key_path, relative_file = relative_file, None
        if (self._credential_path(key) or self._credential_path(key_path)
                or self._credential_path(relative_file)):
            return self._seal_key('hmac:' + self._hmac(key))
        if ((relative_file is not None and not self._tainted(relative_file))
                or (isinstance(key, SealedKey) and _SEALED_KEY_RE.fullmatch(key))
                or key in SCHEMA_KEYS
                or (key in VOCABULARY and not self._tainted(key))):
            return key
        return key_path if key_path is not None and not self._tainted(key_path) else self._seal_key('hmac:' + self._hmac(key))

    def _update_dict_location(self, value, location):
        for key in ('path', 'source', 'database', 'root_path'):
            resolved = self._path(value.get(key))
            if not resolved:
                continue
            location['path'] = None if self._credential_path(resolved) else resolved
            break
        if value.get('unit_kind') == 'project':
            proj_root = self._path(value.get('root_path'))
            if proj_root and not self._tainted(proj_root) and not self._credential_path(proj_root):
                self._project_roots.add(proj_root)
        if type(value.get('line')) is int:
            location['line'] = value['line']
        elif isinstance(value.get('evidence'), dict) and type(value['evidence'].get('line')) is int:
            location['line'] = value['evidence']['line']

    def _serialize_dict(self, value, location, field, ancestors, path):
        self._update_dict_location(value, location)
        root = location.get('path')
        is_project_unit = value.get('unit_kind') == 'project'
        out = {}
        withheld = None
        for k, v in value.items():
            item = self.serialize(
                v,
                location=location,
                field=('parent_context_boundaries' if field == 'parent_context_boundaries'
                       else 'project_root' if (is_project_unit and k == 'unit_id')
                       else k),
                _ancestors=ancestors,
                _path=path + (k,),
            )
            key = self._serialize_dict_key(k, field, root)
            reason = _marker_reason(item)
            if reason is not None:
                out[key] = None
                withheld = reason
            else:
                out[key] = item
        if withheld is not None:
            out['path_withheld'] = withheld
        return out

    def serialize(self, value, *, location=None, field=None, _ancestors=(), _path=()):
        if isinstance(value, GeneratedDigest) and _HEX64_RE.fullmatch(value):
            return value
        if isinstance(value, ControlIdentity) and _CONTROL_ID_RE.fullmatch(value):
            return value
        if isinstance(value, SealedEvidence):
            canonical = value.canonical()
            if not self._valid_leaf(canonical):
                return self.serialize(canonical, location=location, field=field, _ancestors=_ancestors, _path=_path)
            return self._seal(**self._revalidate_sealed(canonical))
        if isinstance(value, EvidenceEndpoint):
            host_ok = value.host is None or (isinstance(value.host, str) and bool(_HOST_RE.fullmatch(value.host)))
            if (host_ok and not self._tainted(value.host) and value.scheme in _ENDPOINT_SCHEMES
                    and (value.port is None or (type(value.port) is int and 0 < value.port < 65536))):
                return self._seal(scheme=value.scheme, host=value.host, port=value.port)
            return self.token(repr(value), 'endpoint', {'path': None, 'line': None})
        location = dict(location or {'path': None, 'line': None})
        if isinstance(value, Evidence):
            resolved = self._path(value.path)
            if self._credential_path(resolved) or self._credential_path(value.path):
                resolved = None
            location = {'path': resolved, 'line': value.line}
            result = (self._serialize_command(value.value, location)
                      if value.kind == 'command' else self.scalar(value.value, value.kind, location, _path))
            return _withheld_marker(result.reason) if isinstance(result, _PathWithheld) else result
        if value is None or type(value) in (bool, int):
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError('Non-finite audit evidence')
            return value
        if isinstance(value, str):
            result = self.scalar(value, field, location, _path)
            return _withheld_marker(result.reason) if isinstance(result, _PathWithheld) else result
        if id(value) in _ancestors:
            raise ValueError('Cyclic audit evidence')
        ancestors = (*_ancestors, id(value))
        if isinstance(value, dict):
            return self._serialize_dict(value, location, field, ancestors, _path)
        if isinstance(value, (list, tuple)):
            return [self.serialize(item, location=location, field=field, _ancestors=ancestors, _path=_path)
                    for item in value]
        raise ValueError('Unsupported audit evidence')


def serialize_evidence(value):
    from .redaction import _CURRENT
    state = _CURRENT.get()
    serializer = state.serializer if state is not None else EvidenceSerializer()
    result = serializer.serialize(value)
    return state.disclose(result) if state is not None else result


# importlib.reload re-runs this file in the same namespace. Modules that
# imported these names earlier (outward, contract, ...) keep the first
# objects, and the serializer's isinstance and factory checks must keep
# recognising what they build, so a reload restores the first identities.
# Nothing is accepted that was not accepted before.
_FIRST_IDENTITIES = globals().get('_FIRST_IDENTITIES') or {
    name: globals()[name] for name in ('_FACTORY', '_PathWithheld', 'SealedEvidence', 'GeneratedDigest',
                                       'ControlIdentity', 'PersistedJSON', 'SealedKey', 'Evidence', 'EvidenceEndpoint')}
globals().update(_FIRST_IDENTITIES)
