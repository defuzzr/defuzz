"""Static audit of unattended agent exposure across config, plugins, hooks, and cron.

Deterministic, read-only, stdlib-only check (no model calls, no network, no subprocesses).
Reuses config loading and provenance rules from ``audit.write_settings`` without duplicating
skill/memory write-approval findings.

Every setting below cites the Hermes source line that ships its default and the reader that
interprets it (paths relative to the hermes-agent source tree). Value coercion mirrors the
reader; where the reader would interpret a value the audit cannot resolve (``${...}`` env
templates, unknown enum strings, strings fed to ``bool()``) the row is ``could_not_verify``.
"""
from __future__ import annotations

from contextlib import contextmanager
import fnmatch
import json
import os
from pathlib import Path, PurePath
import re
import sqlite3
import stat
import time
from typing import Any, Callable

import yaml

from .contract import make_component_envelope, make_finding
from .facts import _parse_simple_yaml_mapping
from .fingerprint import CredentialStoreNotOpened, _open_root_dir_fd, _walk_parent_dir_fds, open_checked, safe_read_regular_file_plain
from .policy import credential_path
from .readonly_db import ReadOnlyDbError, open_session_sqlite_without_sidecar_creation
from .write_settings import (
    MAX_CONFIG_BYTES,
    _has_managed_overlay,
    _names,
    _section,
)

# Explicit resource bounds (audit hygiene rule 5).
# Plugin manifests and install metadata sidecars: task bound 256 KiB.
MAX_PLUGIN_MANIFEST_BYTES = 256 * 1024
# Cron jobs.json and usage_audit.jsonl: 256 KiB bound (normal files are a few KiB to tens of KiB).
MAX_CRON_BYTES = 256 * 1024
# Hook files in hooks/: only the first line, at most 256 bytes, to classify the #! interpreter.
MAX_HOOK_HEADER_BYTES = 256
# Plugin __init__.py prefix Hermes itself scans for kind markers when plugin.yaml has no ``kind``
# (hermes_cli/plugins_manifest.py:539-541 reads [:8192]); read only for warning candidates.
MAX_PLUGIN_INIT_BYTES = 8192
# Directory walk and depth bounds across profile_path, plugins/, hooks/, cron/.
MAX_ENTRIES = 2000
MAX_DEPTH = 4
# Aggregate byte budget across all files read in this component.
MAX_TOTAL_BYTES = 8 * 1024 * 1024
# SQLite VM step and row bounds for optional cron/executions.db inspection.
MAX_SQL_STEPS = 1_000_000
MAX_DB_ROWS = 2000
# Cooperative wall-clock budget (seconds).
MAX_SECONDS = 5.0

# Healthy cron jobs have a failure streak of 0; a job left broken keeps failing on every run, so a
# streak of 5 separates a transient error from a job nobody is looking at.
CRON_FAILURE_STREAK_THRESHOLD = 5
# Hermes hermes_cli/config_defaults.py:1346,1359,1366; tools/delegate_tool_config.py:19,23,104-119,204-216;
# tools/delegate_tool.py:597-598.
DELEGATION_CONCURRENT_DEFAULT = 10
DELEGATION_SPAWN_DEPTH_DEFAULT = 1
DELEGATION_MAX_ITERATIONS_DEFAULT = 250

# Hermes tools/approval_context.py:263 (_VALID_MODES); default 'smart' at hermes_cli/config_defaults.py:1661.
VALID_APPROVAL_MODES = frozenset({'manual', 'smart', 'off'})
# Hermes tools/approval_context.py:347-353: str(value).lower().strip() in this set -> 'approve', else 'deny'.
BINARY_APPROVAL_APPROVE = frozenset({'approve', 'off', 'allow', 'yes'})

# Hermes tools/terminal_tool_config.py:154-155 (_CONTAINER_BACKENDS | local, ssh, managed_modal).
KNOWN_TERMINAL_BACKENDS = frozenset({
    'local', 'docker', 'modal', 'daytona', 'vercel_sandbox', 'ssh', 'managed_modal',
})

# Hermes tools/code_execution_tool.py:843-844; hermes_cli/config_defaults.py:1952-1957.
VALID_CODE_EXECUTION_MODES = frozenset({'project', 'strict'})

# Hermes hermes_cli/config_defaults.py:2338-2367; hermes_cli/update_cmd_maint.py:639-648.
VALID_PRE_UPDATE_BACKUP = frozenset({'quick', 'full', 'off'})

# Emitted labels for the config value 'off' (input parsing still compares the plain word). The
# plain word is a sealed value in the report (tests/test_audit_gate_regressions.py), so the section
# emits these unambiguous tokens instead.
APPROVAL_OFF = 'approval_off'   # approvals.mode
BACKUP_OFF = 'backup_off'       # updates.pre_update_backup
VALID_NON_INTERACTIVE_LOCAL_CHANGES = frozenset({'stash', 'discard'})
VALID_PARKED_BRANCH_STRATEGIES = frozenset({'switch', 'update_in_place'})

# Hermes hermes_cli/config.py:1716-1718 (_UNLIMITED_SPELLINGS).
UNLIMITED_TURN_SPELLINGS = frozenset({
    'none', 'null', 'unlimited', 'infinite', 'infinity', 'inf', '∞', '-1', '0',
})

# Hermes utils.py:25 (TRUTHY_STRINGS, used by is_truthy_value for security.allow_private_urls).
HERMES_TRUTHY_STRINGS = frozenset({'1', 'true', 'yes', 'on'})
# Hermes agent/tool_guardrails.py:641 (_BOOL_WORDS used by tool_loop_guardrails flags).
GUARDRAIL_BOOL_WORDS = {
    **{w: True for w in ('1', 'true', 'yes', 'on', 'enabled')},
    **{w: False for w in ('0', 'false', 'no', 'off', 'disabled')},
}
# Hermes tools/mcp_tool_common.py:124-144: absent/null/unparseable = on; these words are off.
MCP_FALSE_WORDS = frozenset({'0', 'false', 'no', 'off', 'disabled'})

# Provider-name substrings treated as a local proxy for auxiliary.approval.provider. 'cliproxy' is a
# third-party local proxy product name, kept as data because users enter it as a provider name.
LOCAL_PROXY_PROVIDER_TOKENS = ('cliproxy', 'proxy', 'local')

# Name-based tier labels for auxiliary.approval.model. NOT a Hermes concept: vendor naming
# convention only; matched as whole tokens so e.g. 'gemini' does not match 'mini'.
SMALL_MODEL_CLASSES = ('flash', 'mini', 'nano', 'haiku', 'lite', 'small')

# Toolset keys whose tools let a session run code or schedule work (hermes_cli/tools_config.py:67-94
# CONFIGURABLE_TOOLSETS; toolsets.py:96-146).
HIGH_RISK_TOOLSETS = frozenset({'terminal', 'code_execution', 'cronjob', 'computer_use'})
# Broader capability labels reported for information (``skills`` toolset -> 'skill_manage').
POWERFUL_TOOLS = frozenset({
    'terminal', 'code_execution', 'cronjob', 'delegation',
    'memory', 'skill_manage', 'computer_use', 'browser',
})
# Configurable toolset key -> label (hermes_cli/tools_config.py:67-94).
TOOLSET_KEY_TO_POWERFUL: dict[str, frozenset[str]] = {
    'terminal': frozenset({'terminal'}),
    'code_execution': frozenset({'code_execution'}),
    'cronjob': frozenset({'cronjob'}),
    'computer_use': frozenset({'computer_use'}),
    'delegation': frozenset({'delegation'}),
    'memory': frozenset({'memory'}),
    'skills': frozenset({'skill_manage'}),
    'browser': frozenset({'browser'}),
}
CONFIGURABLE_TOOLSET_KEYS = frozenset({
    'web', 'browser', 'terminal', 'file', 'code_execution', 'vision', 'video', 'image_gen',
    'video_gen', 'x_search', 'tts', 'stt', 'skills', 'todo', 'kanban', 'memory', 'context_engine',
    'session_search', 'connections', 'clarify', 'delegation', 'cronjob', 'discord', 'discord_admin',
    'yuanbao', 'computer_use',
})
# Static composites (toolsets.py:11-36,166-241): which labels their configurable subset contains.
_CORE_LABELS = POWERFUL_TOOLS  # _HERMES_CORE_TOOLS covers all eight (toolsets.py:11-36).
_CORE_BUNDLES = frozenset({
    'hermes-cli', 'hermes-cron', 'hermes-telegram', 'hermes-discord', 'hermes-whatsapp',
    'hermes-slack', 'hermes-signal', 'hermes-bluebubbles', 'hermes-email', 'hermes-mattermost',
    'hermes-matrix', 'hermes-dingtalk', 'hermes-feishu', 'hermes-weixin', 'hermes-qqbot',
    'hermes-wecom', 'hermes-wecom-callback', 'hermes-yuanbao', 'hermes-sms', 'hermes-gateway',
})
_CODING_LABELS = frozenset({'terminal', 'code_execution', 'delegation', 'memory', 'skill_manage', 'browser'})
STATIC_COMPOSITE_LABELS: dict[str, frozenset[str]] = {
    **{name: _CORE_LABELS for name in _CORE_BUNDLES},
    # toolsets.py:193-197: core without text_to_speech, clarify, computer_use.
    'hermes-api-server': _CORE_LABELS - {'computer_use'},
    # toolsets.py:62,178-191: coding posture drops cronjob_manage and computer_use.
    'coding': _CODING_LABELS,
    'hermes-acp': _CODING_LABELS,
    # toolsets.py:171-172.
    'debugging': frozenset({'terminal'}),
    'safe': frozenset(),
    'hermes-webhook': frozenset(),
}
# Built-in platforms and their default composite (hermes_cli/platforms.py:15-35). Plugin
# platforms default to 'hermes-<name>' (hermes_cli/platforms.py:65), which has no static
# TOOLSETS entry, so their shipped default resolves to no high-risk toolset.
BUILTIN_PLATFORM_DEFAULTS = {
    'cli': 'hermes-cli', 'telegram': 'hermes-telegram', 'discord': 'hermes-discord',
    'slack': 'hermes-slack', 'whatsapp': 'hermes-whatsapp', 'whatsapp_cloud': 'hermes-whatsapp',
    'signal': 'hermes-signal', 'bluebubbles': 'hermes-bluebubbles', 'email': 'hermes-email',
    'mattermost': 'hermes-mattermost', 'matrix': 'hermes-matrix', 'dingtalk': 'hermes-dingtalk',
    'feishu': 'hermes-feishu', 'wecom': 'hermes-wecom', 'wecom_callback': 'hermes-wecom-callback',
    'weixin': 'hermes-weixin', 'qqbot': 'hermes-qqbot', 'yuanbao': 'hermes-yuanbao',
    'webhook': 'hermes-webhook', 'api_server': 'hermes-api-server', 'cron': 'hermes-cron',
}
# Bundled platform plugins (Hermes plugins/platforms/*) plus homeassistant (a platform key Hermes
# itself names, e.g. hermes_cli/toolset_validation.py; emitted by name only, never flagged on its own).
KNOWN_PLATFORM_NAMES = frozenset(BUILTIN_PLATFORM_DEFAULTS) | frozenset({
    'a2a', 'buzz', 'google_chat', 'irc', 'line', 'ntfy', 'photon', 'raft', 'simplex', 'sms',
    'teams', 'homeassistant',
})
# Local surfaces: agent/tool_guardrails.py:86 lists cli/tui/desktop/acp/subagent as attended (with
# api_server, whose HTTP clients are remote senders and so stay remote here); cron is unattended
# but local, not a remote sender.
LOCAL_SURFACES = frozenset({'cli', 'tui', 'desktop', 'acp', 'subagent', 'cron'})

# Hermes hermes_cli/plugins.py:109-204: real hook names from VALID_HOOKS.
VALID_HOOKS = frozenset({
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
})
# Hooks whose return value changes what the model is sent: pre_llm_call context is appended to the
# user message (agent/turn_context.py:853-857); pre_gateway_dispatch {"action": "rewrite"} replaces
# the inbound message text (hermes_cli/plugins.py:137-139).
PROMPT_INJECTING_HOOKS = frozenset({'pre_llm_call', 'pre_gateway_dispatch'})
# Hooks that can veto/escalate a tool call or replace tool/model output
# (hermes_cli/plugins.py:110-112; tools/approval.py:1222-1229).
TOOL_OR_OUTPUT_HOOKS = frozenset({
    'pre_tool_call', 'transform_tool_result', 'transform_terminal_output', 'transform_llm_output',
})
# Approval/human-input observers: return values ignored (hermes_cli/plugins.py:144-147).
APPROVAL_OBSERVER_HOOKS = frozenset({
    'pre_approval_request', 'post_approval_response',
    'on_human_input_request', 'on_human_input_resolved',
})
REPORTED_PLUGIN_HOOKS = PROMPT_INJECTING_HOOKS | TOOL_OR_OUTPUT_HOOKS | APPROVAL_OBSERVER_HOOKS
# Hermes hermes_cli/plugins.py:208 (shell hooks refuse these events).
SHELL_UNSUPPORTED_HOOKS = frozenset({'transform_api_error_classification'})

# Hermes hermes_cli/plugins_manifest.py:27,527-547,287-298.
VALID_PLUGIN_KINDS = frozenset({'standalone', 'backend', 'exclusive', 'platform', 'model-provider'})
_EXCLUSIVE_MARKERS = (
    'register_memory_provider', 'MemoryProvider', 'register_cron_scheduler', 'CronScheduler',
    'register_computer_use_provider', 'ComputerUseProvider',
)

# Approval-related setting keys compared across config.yaml.bak* copies.
APPROVAL_DRIFT_KEYS = frozenset({
    'approvals.mode',
    'approvals.cron_mode',
    'approvals.unattended_mode',
    'approvals.single_query_mode',
    'command_allowlist',
    'auxiliary.approval.model',
})

FINDING_CONSEQUENCES: dict[str, str] = {
    'unattended_exposure.command_approval_off': (
        'config.yaml sets approvals.mode to off and terminal.backend to local, so Hermes runs shell '
        'commands that match its dangerous-command patterns on this machine without asking a person '
        '(hardline blocks and approvals.deny rules still apply); this audit read config settings and '
        'does not show what commands any agent ran.'
    ),
    'unattended_exposure.unattended_auto_approve': (
        'config.yaml sets approvals.cron_mode, approvals.unattended_mode or approvals.single_query_mode '
        'to approve, so in cron jobs, on unattended platforms (webhook, msgraph_webhook, api_server) or '
        'in single-query runs Hermes runs commands and code that match its dangerous-command checks '
        'without asking a person (hardline blocks, the runtime self-delete and sudo stdin guards, and '
        'approvals.deny rules still apply); this audit read config settings and does not show what '
        'commands any agent ran.'
    ),
    'unattended_exposure.remote_platform_has_powerful_tools': (
        'Config lists, for one or more non-CLI platforms, toolsets that resolve to terminal, '
        'code_execution, cronjob or computer_use beyond that platform\'s shipped default, so sessions '
        'arriving on that platform can call those tools while it is connected; this audit read '
        'platform_toolsets and did not check whether the platform is connected or whether any '
        'remote session called the tools.'
    ),
    'unattended_exposure.unpinned_prompt_injector': (
        'An enabled user plugin declares pre_llm_call or pre_gateway_dispatch in its manifest and '
        'plugins/.install-metadata.json records it as installed without a pinned commit, so a plugin '
        'update can change the code that adds context to or rewrites user messages; this audit read '
        'the manifest and install metadata, did not load the plugin, and does not show what it added.'
    ),
    'unattended_exposure.small_model_decides_approvals': (
        'Config keeps approvals.mode at smart and names an auxiliary.approval.model whose name carries '
        'a smaller-tier label; in smart mode that model answers APPROVE, DENY or ESCALATE for flagged '
        'commands and an APPROVE runs the command without asking a person; this audit read the model '
        'name only and did not measure the model\'s decisions.'
    ),
    'unattended_exposure.guardrail_disabled': (
        'Config turns off a Hermes safety check that is on by default (protected instruction files, '
        'the unattended tool-loop hard stop) or turns on private-network URLs, so that check no '
        'longer stops the matching action; this audit read config settings and does not show that '
        'such an action happened.'
    ),
    'unattended_exposure.real_browser_profile': (
        'Config sets browser.use_real_profile to true, so local browser sessions run on a copy of the '
        'user\'s default Chromium-family browser profile, including its cookies and logins, whenever '
        'that profile can be copied; this audit read config settings and does not show which sites any '
        'browser session opened.'
    ),
    'unattended_exposure.cron_failing_jobs': (
        'One or more cron jobs in cron/jobs.json have a failure_streak of at least 5, the counter '
        'Hermes raises after each consecutive failed run and resets on success; this audit read job '
        'metadata and did not read job output.'
    ),
    'unattended_exposure.cron_runs_scripts': (
        'One or more cron jobs in cron/jobs.json name a script or monitor_script, which the scheduler '
        'runs when the job fires; this audit read job definitions and does not show when the scripts '
        'ran or what they did.'
    ),
    'unattended_exposure.ghost_cron_job': (
        'Cron usage, output or execution records, or another job\'s context_from, name job IDs that '
        'cron/jobs.json does not contain; this audit read cron metadata and does not show what those '
        'jobs did or why they are absent.'
    ),
    'unattended_exposure.approval_setting_changed_in_backups': (
        'Approval-related settings in config.yaml differ from at least one config.yaml.bak copy in the '
        'profile folder; the copies hold earlier saved values, not when each value was active, and '
        'this audit did not check what ran under them.'
    ),
    'unattended_exposure.config_value_malformed': (
        'One or more enumerated config keys hold a URL in a provider-name field or have leading or '
        'trailing whitespace; this audit read config syntax only and did not check how Hermes '
        'resolves these values, some of which its readers strip.'
    ),
    'unattended_exposure.could_not_verify': (
        'One or more unattended exposure settings, plugin manifests, hook entries, or cron records '
        'could not be verified from bounded static files; unverified items are not treated as '
        'clean or as enabled exposure.'
    ),
}

# Fixed limitations text for every finding (an existing sealed code label).
FINDING_LIMITATIONS = 'static inspection only; not runtime safety'

_CREDENTIAL_DIRS = frozenset({
    'mcp-tokens', 'pairing', 'vault', 'credentials', 'credential',
    'secrets', '.ssh', '.aws', '.gnupg', '.kube', '.docker',
})
_CREDENTIAL_GLOBS = (
    '.env*', 'auth.json*', '*token*', '*secret*', '*credential*',
    '*.pem', '*.key', 'id_*', '.npmrc', 'npmrc', '.netrc', '.pgpass', '.pypirc', 'pip.conf',
)
_SAFE_IDENT_RE = re.compile(r'^[a-z0-9][a-z0-9_.+-]{0,63}$')
_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_URL_RE = re.compile(r'^(?:https?|wss?)://', re.I)
# Hook FILE names are user-chosen: emitted only when they match this, else HOOK_NAME_PLACEHOLDER.
_HOOK_FILE_NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
HOOK_NAME_PLACEHOLDER = 'other'
# Public version part only (PEP 440 local labels after '+' are dropped).
_PUBLIC_VERSION_RE = re.compile(r'^\d{1,6}(?:\.\d{1,6}){0,3}(?:(?:a|b|rc)\d{1,4})?(?:\.post\d{1,4})?(?:\.dev\d{1,4})?')
# Platform key under platform_toolsets / platforms: emitted only when known.
_PLATFORM_KEY_RE = re.compile(r'^[a-z][a-z0-9_]{0,31}$')


def _is_credential_file(path: Path | str) -> bool:
    """Strict path-only credential predicate (never opens files)."""
    if credential_path(path):
        return True
    p = PurePath(str(path))
    for part in p.parts:
        if part.casefold() in _CREDENTIAL_DIRS:
            return True
    low = p.name.casefold()
    if low.startswith('._'):
        low = low[2:]
    return any(fnmatch.fnmatchcase(low, pat) for pat in _CREDENTIAL_GLOBS)


def _has_symlink_below(path: Path, anchor: Path) -> bool:
    cur = path
    while True:
        try:
            if cur.is_symlink():
                return True
        except OSError:
            return True
        if cur == anchor or cur.parent == cur:
            return False
        cur = cur.parent


def _safe_identifier(raw: Any, fallback: str = 'other') -> str:
    if not isinstance(raw, str):
        return fallback
    text = raw.strip()
    if not text or _IPV4_RE.match(text):
        return fallback
    if _SAFE_IDENT_RE.fullmatch(text):
        return text
    return fallback


def _safe_version(raw: Any) -> str:
    if not isinstance(raw, (str, int, float)) or isinstance(raw, bool):
        return 'unknown'
    match = _PUBLIC_VERSION_RE.match(str(raw).strip())
    return match.group(0) if match else 'unknown'


def _safe_hook_file_name(name: str) -> str:
    return name if _HOOK_FILE_NAME_RE.fullmatch(name) else HOOK_NAME_PLACEHOLDER


def _finding(
    rule_id: str,
    rel_path: str,
    evidence: dict[str, Any],
    *,
    coverage: str = 'verified',
    classification: str = 'review_suggested',
) -> dict[str, Any]:
    # Paths are relative to the profile root (report policy); never absolute.
    return make_finding(
        rule_id=rule_id,
        classification=classification,
        coverage=coverage,
        affected_identities=[rel_path],
        source_paths=[rel_path],
        evidence=evidence,
        consequence=FINDING_CONSEQUENCES[rule_id],
        limitations=FINDING_LIMITATIONS,
    )


def _envelope(
    findings: list[dict[str, Any]],
    coverage: str,
    section: dict[str, Any],
    run_metrics: dict[str, Any],
) -> dict[str, Any]:
    """Exactly the keys the report wiring reads; ``run_metrics`` stays outside the digested section."""
    env = make_component_envelope(findings=findings, coverage=coverage)
    return {
        'unattended_exposure': section,
        'findings': env['findings'],
        'run_metrics': run_metrics,
        'status': env['status'],
        'coverage': env['coverage'],
    }


@contextmanager
def _open_user_db(path: Path, anchor: Path):
    """Single read-only SQLite wrapper delegating to audit.readonly_db (house rule 6)."""
    if _is_credential_file(path) or _has_symlink_below(path, anchor):
        raise ReadOnlyDbError('unsafe database path', reason='unreadable')
    if os.path.lexists(str(path) + '-journal'):
        raise ReadOnlyDbError('rollback journal present', reason='hot_journal')
    with open_session_sqlite_without_sidecar_creation(path, timeout=0.1) as (conn, identity):
        if identity.size == 0:
            raise ReadOnlyDbError('empty database', reason='corrupt_header')
        conn.execute('PRAGMA trusted_schema=OFF')
        yield conn, identity


def _has_duplicate_yaml_keys(text: str) -> bool:
    """Detect duplicate mapping keys before PyYAML safe_load overwrites them."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise ValueError('Invalid YAML') from exc
    if root is None:
        return False
    stack = [root]
    visited: set[int] = set()
    nodes_left = 10000
    while stack:
        nodes_left -= 1
        if nodes_left < 0:
            raise ValueError('YAML node budget exceeded')
        node = stack.pop()
        nid = id(node)
        if nid in visited:
            continue
        visited.add(nid)
        if isinstance(node, yaml.MappingNode):
            seen: set[tuple[str, str]] = set()
            for k_node, v_node in node.value:
                if isinstance(k_node, yaml.ScalarNode):
                    key = (str(k_node.tag), str(k_node.value))
                    if key in seen:
                        return True
                    seen.add(key)
                stack.append(k_node)
                stack.append(v_node)
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return False


def _parse_yaml_strict(text: str) -> dict[str, Any]:
    if '\x00' in text or _has_duplicate_yaml_keys(text):
        raise ValueError('Invalid or duplicate-key YAML')
    return _parse_simple_yaml_mapping(text)


def _is_template(raw: Any) -> bool:
    # Hermes expands ${VAR} after loading (hermes_cli/config.py:1469-1476); the audit cannot.
    return isinstance(raw, str) and '${' in raw


def _coerce(raw: Any, rule: str) -> tuple[Any, bool]:
    """Coerce a present config value the way the named Hermes reader does.

    Returns ``(value, verified)``. ``verified`` False means the audit cannot resolve what the
    reader would do (template, or a string handed to ``bool()``).
    """
    if _is_template(raw):
        return None, False
    if rule == 'py_bool':
        # bool(value): bool/None/numbers resolve; any non-empty string is truthy to bool(),
        # which the audit does not guess at.
        if raw is None or isinstance(raw, (bool, int, float)):
            return bool(raw), True
        return None, False
    if rule == 'strict_false':
        # Only a real False turns the check off; anything else keeps the default True.
        return (raw is not False), True
    if rule == 'truthy_value':
        if raw is None:
            return False, True
        if isinstance(raw, str):
            return raw.strip().lower() in HERMES_TRUTHY_STRINGS, True
        if isinstance(raw, (bool, int, float)):
            return bool(raw), True
        return None, False
    if rule == 'guardrail_bool':
        if isinstance(raw, (bool, int, float)):
            return bool(raw), True
        if isinstance(raw, str) and raw.strip().lower() in GUARDRAIL_BOOL_WORDS:
            return GUARDRAIL_BOOL_WORDS[raw.strip().lower()], True
        return None, False
    raise ValueError(rule)


def _int_value(raw: Any) -> int | None:
    if isinstance(raw, bool) or _is_template(raw):
        return None
    if type(raw) is int:
        return raw
    if isinstance(raw, float) and raw == raw and abs(raw) < 1e12:
        return int(raw)
    if isinstance(raw, str) and re.fullmatch(r'\s*-?\d{1,12}\s*', raw):
        return int(raw)
    return None


def _classify_nonneg_int(raw: Any, *, min_value: int = 0) -> tuple[int | None, bool]:
    val = _int_value(raw)
    if val is None or val < min_value:
        return None, False
    return val, True


def _classify_model_size(raw: Any) -> tuple[str | None, bool, bool]:
    """Classify auxiliary.approval.model into an enumerated size class without echoing the name."""
    if raw is None:
        return 'unset', False, True
    if not isinstance(raw, str) or _is_template(raw):
        return None, False, False
    cleaned = raw.strip().lower()
    if not cleaned:
        return 'unset', False, True
    tokens = [t for t in re.split(r'[^a-z0-9.]+', cleaned) if t]
    for cls_name in SMALL_MODEL_CLASSES:
        if cls_name in tokens:
            return cls_name, True, True
    if any(re.fullmatch(r'(?:[1-8]|[0-7]\.\d+)b', tok) for tok in tokens):
        return 'small', True, True
    return 'unclassified', True, True


def _uses_local_proxy(aux_approval: dict[str, Any]) -> bool:
    provider = str(aux_approval.get('provider') or '').strip().lower()
    base_url = str(aux_approval.get('base_url') or '').strip().lower()
    if any(tok in provider for tok in LOCAL_PROXY_PROVIDER_TOKENS):
        return True
    if any(host in base_url for host in ('127.0.0.1', 'localhost', '[::1]')):
        return True
    return False


def _toolset_labels(names: list[str], *, explicit_path: bool) -> set[str]:
    """Labels a saved platform list resolves to, statically (hermes_cli/tools_config.py:571-646).

    Configurable keys count directly; static composites contribute their configurable subset in
    both resolver branches (``_explicit_toolsets`` / ``_composite_toolsets``, tools_config.py:488-517).
    ``all``/``*`` are not TOOLSETS keys, so only the composite branch expands them. Plugin toolsets,
    MCP server names and plugin platform bundles carry no static tools and add no label.
    """
    labels: set[str] = set()
    for raw in names:
        name = raw.strip()
        if name == 'hermes':  # tools_config.py:590-602 legacy alias -> hermes-cli + hermes-api-server
            labels |= _CORE_LABELS
        elif name in TOOLSET_KEY_TO_POWERFUL:
            labels |= TOOLSET_KEY_TO_POWERFUL[name]
        elif name in STATIC_COMPOSITE_LABELS:
            labels |= STATIC_COMPOSITE_LABELS[name]
        elif name in ('all', '*'):
            if explicit_path:
                continue  # not a TOOLSETS key; _explicit_toolsets ignores it
            labels |= _CORE_LABELS
    return labels


def _evaluate_settings_and_sanity(
    config: dict[str, Any],
    *,
    readable: bool,
    managed_active: bool,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Evaluate enumerated settings, smart approval, platform toolsets, A2A/MCP counts, and sanity."""
    unverified_all = not readable or managed_active
    settings: dict[str, dict[str, Any]] = {}
    provider_url_keys: set[str] = set()
    whitespace_keys: set[str] = set()

    def check_raw_string_sanity(key_path: str, raw_val: Any, *, is_provider: bool = False) -> None:
        if unverified_all or not isinstance(raw_val, str):
            return
        if raw_val != raw_val.strip():
            whitespace_keys.add(key_path)
        if is_provider and (_URL_RE.match(raw_val.strip()) or '://' in raw_val.strip()):
            provider_url_keys.add(key_path)

    def set_row(key: str, value: Any, source: str, widens: bool | None) -> None:
        if unverified_all or source == 'could_not_verify':
            settings[key] = {'value': value, 'source': 'could_not_verify', 'widens_unattended_action': None}
        else:
            settings[key] = {'value': value, 'source': source, 'widens_unattended_action': bool(widens)}

    def bool_row(key: str, sec: dict[str, Any], subkey: str, default: bool, rule: str,
                 widens_when: bool | None) -> None:
        """``widens_when``: the value that widens unattended action (None: never)."""
        if unverified_all:
            set_row(key, None, 'could_not_verify', None)
            return
        if subkey not in sec:
            set_row(key, default, 'default', widens_when is not None and default is widens_when)
            return
        val, ok = _coerce(sec.get(subkey), rule)
        if not ok:
            set_row(key, None, 'could_not_verify', None)
        else:
            set_row(key, val, 'config', widens_when is not None and val is widens_when)

    # approvals.mode: default 'smart' (hermes_cli/config_defaults.py:1661); reader
    # tools/approval_context.py:266-302 (bool False -> off, bool True -> manual, unknown -> manual
    # with a warning, which the audit reports as 'other'/could_not_verify).
    approvals_sec = _section(config, 'approvals')
    if unverified_all:
        set_row('approvals.mode', None, 'could_not_verify', None)
    elif 'mode' not in approvals_sec:
        set_row('approvals.mode', 'smart', 'default', False)
    else:
        raw_mode = approvals_sec.get('mode')
        check_raw_string_sanity('approvals.mode', raw_mode)
        if raw_mode is False:
            set_row('approvals.mode', APPROVAL_OFF, 'config', True)
        elif raw_mode is True:
            set_row('approvals.mode', 'manual', 'config', False)
        elif isinstance(raw_mode, str) and not _is_template(raw_mode):
            norm = raw_mode.strip().lower()
            if norm in VALID_APPROVAL_MODES:
                set_row('approvals.mode', APPROVAL_OFF if norm == 'off' else norm, 'config', norm == 'off')
            else:
                set_row('approvals.mode', 'other', 'could_not_verify', None)
        else:
            set_row('approvals.mode', None, 'could_not_verify', None)

    # approvals.cron_mode / unattended_mode / single_query_mode: default 'deny'
    # (hermes_cli/config_defaults.py:1664-1666); reader tools/approval_context.py:347-371 turns
    # str(value).lower().strip() in {approve, off, allow, yes} into 'approve', everything else
    # (including YAML booleans, which stringify to 'true'/'false') into 'deny'.
    for subkey in ('cron_mode', 'unattended_mode', 'single_query_mode'):
        full_key = f'approvals.{subkey}'
        if unverified_all:
            set_row(full_key, None, 'could_not_verify', None)
        elif subkey not in approvals_sec:
            set_row(full_key, 'deny', 'default', False)
        else:
            raw_b = approvals_sec.get(subkey)
            check_raw_string_sanity(full_key, raw_b)
            if _is_template(raw_b) or isinstance(raw_b, (dict, list)):
                set_row(full_key, None, 'could_not_verify', None)
            else:
                norm_b = str(raw_b).lower().strip()
                approve = norm_b in BINARY_APPROVAL_APPROVE
                set_row(full_key, 'approve' if approve else 'deny', 'config', approve)

    # command_allowlist: default [] (hermes_cli/config_defaults.py:1686); count only, entries never emitted.
    if unverified_all:
        set_row('command_allowlist', None, 'could_not_verify', None)
    elif 'command_allowlist' not in config:
        set_row('command_allowlist', 0, 'default', False)
    else:
        raw_al = config.get('command_allowlist')
        if raw_al is None:
            set_row('command_allowlist', 0, 'config', False)
        elif isinstance(raw_al, list) and all(isinstance(x, str) for x in raw_al):
            cnt = sum(1 for x in raw_al if x.strip())
            set_row('command_allowlist', cnt, 'config', cnt > 0)
        else:
            set_row('command_allowlist', None, 'could_not_verify', None)

    # auxiliary.approval.model: no shipped default (absent from DEFAULT_CONFIG); read through
    # agent/auxiliary_task_config.py:45-56 for task 'approval' by tools/approval_smart.py:88-127.
    aux_sec = _section(config, 'auxiliary')
    aux_app = _section(aux_sec, 'approval')
    check_raw_string_sanity('auxiliary.approval.provider', aux_app.get('provider'), is_provider=True)
    check_raw_string_sanity('auxiliary.approval.model', aux_app.get('model'))
    if unverified_all:
        set_row('auxiliary.approval.model', None, 'could_not_verify', None)
        smart_info = {'model_set': None, 'size_class': None, 'is_small': None, 'uses_local_proxy': None}
    else:
        present_model = 'model' in aux_app and bool(str(aux_app.get('model') or '').strip())
        cls_label, is_set, ok_model = _classify_model_size(aux_app.get('model'))
        if not ok_model:
            set_row('auxiliary.approval.model', None, 'could_not_verify', None)
            smart_info = {'model_set': None, 'size_class': None, 'is_small': None, 'uses_local_proxy': None}
        else:
            is_small = cls_label in SMALL_MODEL_CLASSES
            set_row('auxiliary.approval.model', cls_label, 'config' if present_model else 'default', is_small)
            smart_info = {
                'model_set': is_set,
                'size_class': cls_label,
                'is_small': is_small,
                'uses_local_proxy': _uses_local_proxy(aux_app),
            }

    # terminal.backend: default 'local' (hermes_cli/config_defaults.py:286). When the key is absent
    # the TERMINAL_ENV environment value wins (hermes_cli/config.py:2083-2086), which the audit
    # cannot read, so a default 'local' is never used for a finding.
    term_sec = _section(config, 'terminal')
    if unverified_all:
        set_row('terminal.backend', None, 'could_not_verify', None)
    elif 'backend' not in term_sec:
        set_row('terminal.backend', 'local', 'default', True)
    else:
        raw_tb = term_sec.get('backend')
        check_raw_string_sanity('terminal.backend', raw_tb)
        if isinstance(raw_tb, str) and not _is_template(raw_tb) and raw_tb.strip():
            norm_tb = raw_tb.strip().lower()
            if norm_tb in KNOWN_TERMINAL_BACKENDS:
                set_row('terminal.backend', norm_tb, 'config', norm_tb == 'local')
            else:
                set_row('terminal.backend', 'other', 'could_not_verify', None)
        else:
            set_row('terminal.backend', None, 'could_not_verify', None)

    # browser.use_real_profile: default False (hermes_cli/config_defaults.py:446); reader
    # tools/browser_session_cloud.py:43-51,150-153 applies bool().
    browser_sec = _section(config, 'browser')
    bool_row('browser.use_real_profile', browser_sec, 'use_real_profile', False, 'py_bool', True)

    # code_execution.mode: default 'project' (hermes_cli/config_defaults.py:1952-1957). Neither mode
    # changes command approval (env scrubbing and the tool whitelist apply in both), so it never widens.
    ce_sec = _section(config, 'code_execution')
    if unverified_all:
        set_row('code_execution.mode', None, 'could_not_verify', None)
    elif 'mode' not in ce_sec:
        set_row('code_execution.mode', 'project', 'default', False)
    else:
        raw_ce = ce_sec.get('mode')
        check_raw_string_sanity('code_execution.mode', raw_ce)
        if isinstance(raw_ce, str) and not _is_template(raw_ce):
            norm_ce = raw_ce.strip().lower()
            if norm_ce in VALID_CODE_EXECUTION_MODES:
                set_row('code_execution.mode', norm_ce, 'config', False)
            else:
                set_row('code_execution.mode', 'other', 'could_not_verify', None)
        else:
            set_row('code_execution.mode', None, 'could_not_verify', None)

    # security.protected_instruction_files: default True (hermes_cli/config_defaults.py:1770);
    # reader tools/file_tools_write_guards.py:198-215 keeps the gate on for any non-bool value.
    sec_block = _section(config, 'security')
    bool_row('security.protected_instruction_files', sec_block, 'protected_instruction_files', True,
             'strict_false', False)

    # security.allow_private_urls: default False (hermes_cli/config_defaults.py:1753); reader
    # tools/url_safety.py:157-173 is_truthy_value on security.* then legacy browser.* (config_defaults.py:423).
    # HERMES_ALLOW_PRIVATE_URLS in the environment can override; the audit cannot read it.
    if unverified_all:
        set_row('security.allow_private_urls', None, 'could_not_verify', None)
    else:
        present = [s for s in (sec_block, browser_sec) if 'allow_private_urls' in s]
        if not present:
            set_row('security.allow_private_urls', False, 'default', False)
        else:
            vals = [_coerce(s.get('allow_private_urls'), 'truthy_value') for s in present]
            if any(not ok for _, ok in vals):
                set_row('security.allow_private_urls', None, 'could_not_verify', None)
            else:
                on = any(v for v, _ in vals)
                set_row('security.allow_private_urls', on, 'config', on)

    # tool_loop_guardrails.hard_stop_enabled: default False, opt-in for attended sessions;
    # non_interactive_hard_stop_enabled: default True, forces hard stops on gateway/cron platforms
    # (hermes_cli/config_defaults.py:544-550; agent/tool_guardrails.py:123-145,644-649).
    tlg_sec = _section(config, 'tool_loop_guardrails')
    bool_row('tool_loop_guardrails.hard_stop_enabled', tlg_sec, 'hard_stop_enabled', False,
             'guardrail_bool', None)
    bool_row('tool_loop_guardrails.non_interactive_hard_stop_enabled', tlg_sec,
             'non_interactive_hard_stop_enabled', True, 'guardrail_bool', False)

    # agent.max_turns: default None = unlimited (hermes_cli/config_defaults.py:64-66); legacy root
    # max_turns moves under agent when agent.max_turns is unset (hermes_cli/config.py:2255-2260);
    # reader hermes_cli/config.py:1721-1746 (resolve_turn_limit).
    agent_sec = _section(config, 'agent')
    if unverified_all:
        set_row('agent.max_turns', None, 'could_not_verify', None)
    else:
        present_mt = 'max_turns' in agent_sec and agent_sec.get('max_turns') is not None
        raw_mt = agent_sec.get('max_turns') if present_mt else config.get('max_turns')
        from_config = present_mt or 'max_turns' in config or 'max_turns' in agent_sec
        if raw_mt is None:
            set_row('agent.max_turns', 'unlimited', 'config' if from_config else 'default', True)
        else:
            check_raw_string_sanity('agent.max_turns', raw_mt)
            if isinstance(raw_mt, bool) or _is_template(raw_mt):
                set_row('agent.max_turns', None, 'could_not_verify', None)
            elif isinstance(raw_mt, str) and raw_mt.strip().lower() in UNLIMITED_TURN_SPELLINGS:
                set_row('agent.max_turns', 'unlimited', 'config', True)
            else:
                ival = _int_value(raw_mt)
                if ival is None:
                    set_row('agent.max_turns', 'other', 'could_not_verify', None)
                elif ival <= 0:
                    set_row('agent.max_turns', 'unlimited', 'config', True)
                else:
                    set_row('agent.max_turns', ival, 'config', False)

    # delegation.*: defaults hermes_cli/config_defaults.py:1346,1359,1366; readers floor
    # max_concurrent_children and max_spawn_depth at 1 (tools/delegate_tool_config.py:104-119,204-216).
    del_sec = _section(config, 'delegation')
    check_raw_string_sanity('delegation.provider', del_sec.get('provider'), is_provider=True)
    check_raw_string_sanity('delegation.model', del_sec.get('model'))
    for dkey, ddef, floor in (
        ('max_concurrent_children', DELEGATION_CONCURRENT_DEFAULT, 1),
        ('max_spawn_depth', DELEGATION_SPAWN_DEPTH_DEFAULT, 1),
        ('max_iterations', DELEGATION_MAX_ITERATIONS_DEFAULT, 1),
    ):
        full_dk = f'delegation.{dkey}'
        if unverified_all:
            set_row(full_dk, None, 'could_not_verify', None)
        elif dkey not in del_sec or del_sec.get(dkey) is None:
            set_row(full_dk, ddef, 'default', False)
        else:
            ival = _int_value(del_sec.get(dkey))
            if ival is None:
                set_row(full_dk, None, 'could_not_verify', None)
            else:
                ival = max(floor, ival)
                set_row(full_dk, ival, 'config', ival > ddef)

    # cron.allow_agent_scheduling: default False (hermes_cli/config_defaults.py:1789); reader
    # cron/scheduler.py:424 uses truthiness. cron.catch_up_missed: default True (config_defaults.py:1784);
    # reader cron/missed_runs.py:41 treats only False as off.
    cron_sec = _section(config, 'cron')
    check_raw_string_sanity('cron.provider', cron_sec.get('provider'), is_provider=True)
    check_raw_string_sanity('cron.model', cron_sec.get('model'))
    bool_row('cron.allow_agent_scheduling', cron_sec, 'allow_agent_scheduling', False, 'py_bool', True)
    bool_row('cron.catch_up_missed', cron_sec, 'catch_up_missed', True, 'strict_false', True)

    # gateway.trust_recent_files: default True (hermes_cli/config_defaults.py:2220); reader
    # gateway/media_policy.py:60 bool(); only consulted when media delivery strict mode is on.
    gw_sec = _section(config, 'gateway')
    bool_row('gateway.trust_recent_files', gw_sec, 'trust_recent_files', True, 'py_bool', True)

    # curator.enabled: default True (hermes_cli/config_defaults.py:1484); reader agent/curator.py:106-107 bool().
    cur_sec = _section(config, 'curator')
    bool_row('curator.enabled', cur_sec, 'enabled', True, 'py_bool', True)

    # plugins.auto_apply: default False (hermes_cli/config_defaults.py:1713); reader
    # hermes_cli/plugins_cadence.py:117-121 bool().
    plug_sec = _section(config, 'plugins')
    bool_row('plugins.auto_apply', plug_sec, 'auto_apply', False, 'py_bool', True)

    # updates.check / auto_switch_parked_branch: defaults True (hermes_cli/config_defaults.py:2339,2362);
    # auto_switch reader hermes_cli/update_cmd_git.py:192 bool().
    upd_sec = _section(config, 'updates')
    bool_row('updates.check', upd_sec, 'check', True, 'py_bool', None)
    bool_row('updates.auto_switch_parked_branch', upd_sec, 'auto_switch_parked_branch', True, 'py_bool', True)

    # updates.pre_update_backup: default 'quick'; reader hermes_cli/update_cmd_maint.py:639-650
    # (True -> full, False -> off, aliases, unknown -> quick with a warning).
    if unverified_all:
        set_row('updates.pre_update_backup', None, 'could_not_verify', None)
    elif 'pre_update_backup' not in upd_sec:
        set_row('updates.pre_update_backup', 'quick', 'default', False)
    else:
        raw_pub = upd_sec.get('pre_update_backup')
        check_raw_string_sanity('updates.pre_update_backup', raw_pub)
        if raw_pub is True:
            set_row('updates.pre_update_backup', 'full', 'config', False)
        elif raw_pub is False:
            set_row('updates.pre_update_backup', BACKUP_OFF, 'config', True)
        elif isinstance(raw_pub, str) and not _is_template(raw_pub):
            norm_pub = raw_pub.strip().lower()
            if norm_pub in ('true', 'yes', 'on', '1'):
                norm_pub = 'full'
            elif norm_pub in ('false', 'no', '0', 'none', 'disabled'):
                norm_pub = 'off'
            if norm_pub in VALID_PRE_UPDATE_BACKUP:
                set_row('updates.pre_update_backup', BACKUP_OFF if norm_pub == 'off' else norm_pub, 'config',
                        norm_pub == 'off')
            else:
                set_row('updates.pre_update_backup', 'other', 'could_not_verify', None)
        else:
            set_row('updates.pre_update_backup', None, 'could_not_verify', None)

    # updates.non_interactive_local_changes / parked_branch_strategy: defaults 'stash' / 'switch'
    # (hermes_cli/config_defaults.py:2357,2367; readers hermes_cli/update_cmd.py:1373,1552).
    for ukey, udef, allowed_set, widens_val in (
        ('non_interactive_local_changes', 'stash', VALID_NON_INTERACTIVE_LOCAL_CHANGES, 'discard'),
        ('parked_branch_strategy', 'switch', VALID_PARKED_BRANCH_STRATEGIES, 'update_in_place'),
    ):
        full_uk = f'updates.{ukey}'
        if unverified_all:
            set_row(full_uk, None, 'could_not_verify', None)
        elif ukey not in upd_sec:
            set_row(full_uk, udef, 'default', False)
        else:
            raw_u = upd_sec.get(ukey)
            check_raw_string_sanity(full_uk, raw_u)
            if isinstance(raw_u, str) and not _is_template(raw_u):
                norm_u = raw_u.strip().lower()
                if norm_u in allowed_set:
                    set_row(full_uk, norm_u, 'config', norm_u == widens_val)
                else:
                    set_row(full_uk, 'other', 'could_not_verify', None)
            else:
                set_row(full_uk, None, 'could_not_verify', None)

    # skills.auto_load: default [] (hermes_cli/config_defaults.py:1448); count only.
    skills_sec = _section(config, 'skills')
    if unverified_all:
        set_row('skills.auto_load', None, 'could_not_verify', None)
    elif 'auto_load' not in skills_sec:
        set_row('skills.auto_load', 0, 'default', False)
    else:
        al_names = _names(skills_sec.get('auto_load'))
        if al_names is not None:
            cnt = sum(1 for s in al_names if s.strip())
            set_row('skills.auto_load', cnt, 'config', cnt > 0)
        else:
            set_row('skills.auto_load', None, 'could_not_verify', None)

    # plugins.enabled: opt-in allow-list, no shipped default (hermes_cli/config_defaults.py:1694-1696);
    # reader hermes_cli/plugins_discovery.py:121-130 accepts a YAML list only.
    if unverified_all:
        set_row('plugins.enabled', None, 'could_not_verify', None)
    elif 'enabled' not in plug_sec:
        set_row('plugins.enabled', 0, 'default', False)
    else:
        en_raw = plug_sec.get('enabled')
        if isinstance(en_raw, list):
            cnt = len({str(s).strip() for s in en_raw if str(s).strip()})
            set_row('plugins.enabled', cnt, 'config', cnt > 0)
        else:
            set_row('plugins.enabled', None, 'could_not_verify', None)

    # mcp_servers: count of dict entries enabled per tools/mcp_tool_common.py:124-144 (absent/null/
    # unparseable = on) as used by hermes_cli/tools_config.py:402-412. Server NAMES are never emitted.
    mcp_servers_raw = config.get('mcp_servers')
    configured_cnt = len(mcp_servers_raw) if isinstance(mcp_servers_raw, dict) else 0
    enabled_cnt = 0
    disabled_cnt = 0
    if isinstance(mcp_servers_raw, dict):
        for scfg in mcp_servers_raw.values():
            if not isinstance(scfg, dict):
                continue
            en = scfg.get('enabled', True)
            off = (
                (isinstance(en, (bool, int, float)) and not bool(en))
                or (isinstance(en, str) and en.strip().lower() in MCP_FALSE_WORDS)
            )
            if off:
                disabled_cnt += 1
            else:
                enabled_cnt += 1
    if unverified_all:
        set_row('mcp_servers', None, 'could_not_verify', None)
    elif 'mcp_servers' not in config or mcp_servers_raw is None:
        set_row('mcp_servers', 0, 'default', False)
    elif isinstance(mcp_servers_raw, dict):
        set_row('mcp_servers', enabled_cnt, 'config', enabled_cnt > 0)
    else:
        set_row('mcp_servers', None, 'could_not_verify', None)
    mcp_info = {
        'configured_count': 0 if unverified_all else configured_cnt,
        'enabled_count': 0 if unverified_all else enabled_cnt,
        'disabled_count': 0 if unverified_all else disabled_cnt,
    }

    # a2a: outbound peers from a2a_agents (plugins/platforms/a2a/tools.py:31-32); served agents from
    # platforms.a2a.extra.agents|served_agents, else top-level a2a_served_agents / a2a.served_agents
    # (plugins/platforms/a2a/adapter.py:390-400; gateway/config_loader.py:150-170 merges
    # gateway.platforms). Names and URLs are never emitted.
    outbound_peers = _section(config, 'a2a_agents')
    plat_top = _section(config, 'platforms')
    gw_plat = _section(gw_sec, 'platforms')
    served: dict[str, Any] = {}
    for p_source in (gw_plat, plat_top):
        ext_b = _section(_section(p_source, 'a2a'), 'extra')
        ag_b = ext_b.get('agents') or ext_b.get('served_agents')
        if isinstance(ag_b, dict):
            served.update(ag_b)
        elif isinstance(ag_b, list):
            served.update({str(i): v for i, v in enumerate(ag_b)})
    if not served:
        fb = config.get('a2a_served_agents') or _section(config, 'a2a').get('served_agents')
        if isinstance(fb, dict):
            served.update(fb)
        elif isinstance(fb, list):
            served.update({str(i): v for i, v in enumerate(fb)})
    served = {k: v for k, v in served.items() if isinstance(v, dict)}
    timeouts: set[int] = set()
    for p_dict in (outbound_peers, served):
        for p_entry in p_dict.values():
            if isinstance(p_entry, dict) and 'timeout' in p_entry:
                tval, tok = _classify_nonneg_int(p_entry.get('timeout'), min_value=1)
                if tok and tval is not None:
                    timeouts.add(tval)
    total_peers = len(outbound_peers) + len(served)
    if unverified_all:
        set_row('a2a_agents', None, 'could_not_verify', None)
    else:
        has_a2a_cfg = 'a2a_agents' in config or bool(served)
        set_row('a2a_agents', total_peers, 'config' if has_a2a_cfg else 'default', total_peers > 0)
    a2a_info = {
        'peer_count': 0 if unverified_all else total_peers,
        'outbound_peer_count': 0 if unverified_all else len(outbound_peers),
        'inbound_agent_count': 0 if unverified_all else len(served),
        'served_profile_count': 0 if unverified_all else ((1 + len(served)) if served else 0),
        'peer_timeouts': [] if unverified_all else sorted(timeouts),
    }

    # platform_toolsets.<platform> (hermes_cli/tools_config.py:571-646), minus agent.disabled_toolsets.
    pt_sec = _section(config, 'platform_toolsets')
    disabled_names = _names(agent_sec.get('disabled_toolsets', [])) or []
    # model_tools.py:300-328: a disabled hermes-* bundle or posture removes only its non-core tools,
    # so only direct toolset keys and non-bundle composites (debugging) subtract labels here.
    disabled_labels: set[str] = set()
    for dname in disabled_names:
        dkey = dname.strip()
        if dkey in TOOLSET_KEY_TO_POWERFUL:
            disabled_labels |= TOOLSET_KEY_TO_POWERFUL[dkey]
        elif dkey == 'debugging':
            disabled_labels |= STATIC_COMPOSITE_LABELS['debugging']

    cli_list = _names(pt_sec.get('cli')) if 'cli' in pt_sec else ['hermes-cli']
    cli_powerful: set[str] = set()
    if cli_list is not None:
        cli_explicit = any(n.strip() in CONFIGURABLE_TOOLSET_KEYS for n in cli_list)
        cli_powerful = _toolset_labels(cli_list, explicit_path=cli_explicit)
    cli_powerful -= disabled_labels

    def count_platform_peers_or_users(plat_name: str) -> int:
        if plat_name == 'a2a':
            return total_peers
        p_cfg = _section(plat_top, plat_name)
        allow_from = p_cfg.get('allow_from')
        cnt = len(allow_from) if isinstance(allow_from, list) else 0
        top_p = _section(config, plat_name)
        for k_allow in ('allowed_channels', 'allowed_chats', 'allowed_rooms'):
            raw_c = top_p.get(k_allow)
            if isinstance(raw_c, str) and raw_c.strip():
                cnt += len([x for x in raw_c.split(',') if x.strip()])
            elif isinstance(raw_c, list):
                cnt += len(raw_c)
        return cnt

    non_cli_platforms: dict[str, dict[str, Any]] = {}
    # Platforms that are not known Hermes platform names: rows without their (user-chosen) name.
    other_platforms: list[dict[str, Any]] = []
    if not unverified_all and isinstance(pt_sec, dict):
        for plat_key, raw_ts_list in sorted(pt_sec.items(), key=lambda kv: str(kv[0])):
            plat_str = str(plat_key)
            if plat_str == 'cli':
                continue
            ts_list = _names(raw_ts_list)
            if ts_list is None:
                continue
            explicit_path = any(n.strip() in CONFIGURABLE_TOOLSET_KEYS for n in ts_list)
            p_tools = _toolset_labels(ts_list, explicit_path=explicit_path)
            p_tools -= disabled_labels
            default_bundle = BUILTIN_PLATFORM_DEFAULTS.get(plat_str)
            default_tools = set(STATIC_COMPOSITE_LABELS.get(default_bundle or '', frozenset()))
            high_risk = p_tools & HIGH_RISK_TOOLSETS
            beyond = sorted(high_risk - default_tools)
            if plat_str in KNOWN_PLATFORM_NAMES and _PLATFORM_KEY_RE.fullmatch(plat_str):
                target = non_cli_platforms.setdefault(plat_str, {})
            else:
                target = {}
                other_platforms.append(target)
            target.update({
                'powerful_tools': sorted(p_tools),
                'high_risk_tools': sorted(high_risk),
                'beyond_default_high_risk_tools': beyond,
                'remote': plat_str not in LOCAL_SURFACES,
                'toolset_count': len(ts_list),
                'peer_or_user_count': count_platform_peers_or_users(plat_str),
            })

    platform_info = {
        'cli_toolset_count': len(cli_list) if (cli_list is not None and 'cli' in pt_sec and not unverified_all) else 0,
        'cli_powerful_tools': [] if unverified_all else sorted(cli_powerful),
        'non_cli_platforms': non_cli_platforms,
        'other_platforms': other_platforms,
    }

    mem_sec = _section(config, 'memory')
    check_raw_string_sanity('memory.provider', mem_sec.get('provider'), is_provider=True)

    sanity_info = {
        'provider_url_count': len(provider_url_keys),
        'provider_url_keys': sorted(provider_url_keys),
        'whitespace_value_count': len(whitespace_keys),
        'whitespace_value_keys': sorted(whitespace_keys),
        'total_malformed': len(provider_url_keys) + len(whitespace_keys),
    }

    return settings, smart_info, platform_info, {'a2a': a2a_info, 'mcp_servers': mcp_info}, sanity_info


def _classify_shebang(first_line: bytes) -> str:
    if not first_line.startswith(b'#!'):
        return 'none'
    line = first_line.decode('utf-8', errors='replace').lower()
    for interp in ('python', 'bash', 'zsh', 'sh', 'node', 'ruby', 'perl'):
        if re.search(r'\b' + interp + r'(?:\d+(?:\.\d+)*)?\b', line):
            return interp
    return 'other'


_CRON_FIELD_RANGES = ((0, 59), (0, 23))


def _cron_field_count(field: str, lo: int, hi: int) -> int | None:
    """Number of values a simple cron field matches (``*``, ``*/n``, ``a``, ``a-b``, ``a-b/n``, lists)."""
    total: set[int] = set()
    for part in field.split(','):
        m = re.fullmatch(r'(\*|\d{1,2}(?:-\d{1,2})?)(?:/(\d{1,2}))?', part)
        if not m:
            return None
        base, step_s = m.group(1), m.group(2)
        step = int(step_s) if step_s else 1
        if step < 1:
            return None
        if base == '*':
            start, end = lo, hi
        elif '-' in base:
            start, end = (int(x) for x in base.split('-'))
        else:
            start = int(base)
            end = hi if step_s else start
        if start < lo or end > hi or start > end:
            return None
        total.update(range(start, end + 1, step))
    return len(total)


def _classify_cron_schedule(schedule: Any) -> str:
    """Schedule class from cron/jobs.py:780-849 shapes (kind cron|interval|once)."""
    if not isinstance(schedule, dict):
        return 'unclassified'
    kind = str(schedule.get('kind') or '').strip().lower()
    if kind == 'once':
        return 'less_often'
    if kind == 'interval':
        minutes, ok = _classify_nonneg_int(schedule.get('minutes'), min_value=1)
        if not ok or minutes is None:
            return 'unclassified'
        if minutes < 60:
            return 'more_often_than_hourly'
        if minutes <= 1440:
            return 'hourly_to_daily'
        return 'less_often'
    if kind == 'cron':
        parts = str(schedule.get('expr') or '').split()
        if len(parts) != 5:
            return 'unclassified'
        n_min = _cron_field_count(parts[0], *_CRON_FIELD_RANGES[0])
        n_hour = _cron_field_count(parts[1], *_CRON_FIELD_RANGES[1])
        if n_min is None or n_hour is None:
            return 'unclassified'
        fires_per_active_day = n_min * n_hour
        if fires_per_active_day > 24:
            return 'more_often_than_hourly'
        if parts[2] == '*' and parts[3] == '*' and parts[4] == '*':
            return 'hourly_to_daily'
        return 'less_often'
    return 'unclassified'


def _empty_section(reason: str, limits: dict[str, Any], thresholds: dict[str, Any]) -> dict[str, Any]:
    empty_settings, empty_smart, empty_plat, empty_a2a_mcp, empty_sanity = _evaluate_settings_and_sanity(
        {}, readable=False, managed_active=False,
    )
    return {
        'status': 'not_measured',
        'reason': reason,
        'coverage': 'could_not_verify',
        'truncated_by': None,
        'settings': empty_settings,
        'smart_approval': empty_smart,
        'platform_toolsets': empty_plat,
        **empty_a2a_mcp,
        'plugins': {
            'enabled_count': 0, 'disabled_count': 0, 'installed_count': 0,
            'hook_plugins': [], 'memory_provider_count': 0, 'missing_or_empty_enabled': [],
        },
        'hooks': {'total_scripts': 0, 'scripts_by_event': {}, 'files': []},
        'cron': {
            'total': 0, 'enabled': 0, 'paused': 0, 'script_jobs': 0, 'prompt_jobs': 0,
            'schedule_classes': {'more_often_than_hourly': 0, 'hourly_to_daily': 0, 'less_often': 0,
                                 'unclassified': 0},
            'failing_jobs_count': 0, 'max_failure_streak': 0, 'failing_streaks': [],
            'ghost_jobs_count': 0,
            'allow_agent_scheduling': None, 'catch_up_missed': None,
        },
        'config_backup_drift': {
            'copies_compared': 0, 'backup_count': 0, 'changed_keys': [],
            'approval_changed_keys': [], 'changes': {},
        },
        'config_sanity': empty_sanity,
        'limits': limits,
        'thresholds': thresholds,
    }


def audit_unattended_exposure(
    profile_path: Path | str | None = None,
    *,
    managed_dir: Path | str | None = None,
    now_fn: Callable[[], float] = time.monotonic,
    max_entries: int | None = None,
    max_file_bytes: int | None = None,
    max_total_bytes: int | None = None,
    max_seconds: float | None = None,
) -> dict[str, Any]:
    """Audit what a Hermes agent can run or change without a person approving it."""
    if profile_path is None:
        raise ValueError('profile_path is required')
    root = Path(profile_path)
    # Base for emitted absolute paths: resolved, so the serializer's resolve() returns them unchanged.
    try:
        root_abs = root.resolve()
    except (OSError, RuntimeError):
        root_abs = root.absolute()
    eff_max_entries = MAX_ENTRIES if max_entries is None else int(max_entries)
    eff_max_file_bytes = MAX_CONFIG_BYTES if max_file_bytes is None else int(max_file_bytes)
    eff_max_total_bytes = MAX_TOTAL_BYTES if max_total_bytes is None else int(max_total_bytes)
    eff_max_seconds = MAX_SECONDS if max_seconds is None else float(max_seconds)

    start_time = now_fn()
    deadline = start_time + eff_max_seconds
    limits: dict[str, Any] = {
        'max_config_bytes': min(MAX_CONFIG_BYTES, eff_max_file_bytes),
        'max_plugin_manifest_bytes': min(MAX_PLUGIN_MANIFEST_BYTES, eff_max_file_bytes),
        'max_cron_bytes': min(MAX_CRON_BYTES, eff_max_file_bytes),
        'max_hook_header_bytes': min(MAX_HOOK_HEADER_BYTES, eff_max_file_bytes),
        'max_entries': eff_max_entries,
        'max_depth': MAX_DEPTH,
        'max_total_bytes': eff_max_total_bytes,
        'max_sql_steps': MAX_SQL_STEPS,
        'max_db_rows': MAX_DB_ROWS,
        'max_seconds': eff_max_seconds,
        'entries_walked': 0,
        'bytes_read': 0,
        'cuts': 0,
    }
    thresholds = {
        'cron_failure_streak': CRON_FAILURE_STREAK_THRESHOLD,
        'delegation_max_concurrent_children': DELEGATION_CONCURRENT_DEFAULT,
        'delegation_max_spawn_depth': DELEGATION_SPAWN_DEPTH_DEFAULT,
        'delegation_max_iterations': DELEGATION_MAX_ITERATIONS_DEFAULT,
    }
    truncated_by: str | None = None

    def run_metrics() -> dict[str, Any]:
        # Wall-clock dependent: returned beside the section, never inside it (digest safety).
        return {'elapsed_ms': max(0, int(round((now_fn() - start_time) * 1000)))}

    def note_cut(reason_code: str | None = None) -> None:
        nonlocal truncated_by
        limits['cuts'] += 1
        if reason_code and truncated_by is None:
            truncated_by = reason_code

    def check_time() -> bool:
        if now_fn() >= deadline:
            note_cut('time_budget')
            return True
        return False

    def step_entry() -> bool:
        if check_time():
            return False
        limits['entries_walked'] += 1
        if limits['entries_walked'] > eff_max_entries:
            note_cut('entry_cap')
            return False
        return True

    def read_bounded_file(rel_path: str, cap: int) -> tuple[bytes | None, str]:
        """Read a regular file inside root with strict credential, symlink, and byte caps."""
        if check_time():
            return None, 'time_budget'
        full = root / rel_path
        if _is_credential_file(full) or _has_symlink_below(full, root):
            note_cut()
            return None, 'excluded_or_symlink'
        rem = eff_max_total_bytes - limits['bytes_read']
        if rem <= 0:
            note_cut('total_bytes_cap')
            return None, 'total_bytes_cap'
        file_cap = min(cap, eff_max_file_bytes, rem)
        res = safe_read_regular_file_plain(root, rel_path, max_bytes=file_cap)
        if res.kind == 'missing':
            return None, 'missing'
        if res.bounded_exceeded:
            if res.size is not None and res.size > min(cap, eff_max_file_bytes):
                note_cut('file_size_cap')
                return None, 'file_size_cap'
            note_cut('total_bytes_cap')
            return None, 'total_bytes_cap'
        if res.coverage != 'verified' or not res.stable or res.content is None:
            note_cut()
            return None, 'unreadable'
        limits['bytes_read'] += len(res.content)
        return res.content, 'ok'

    def read_prefix(rel_path: str, cap_bytes: int) -> tuple[bytes | None, int | None]:
        """Read at most ``cap_bytes`` from a regular file (O_NOFOLLOW, dir-fd walk)."""
        if check_time():
            return None, None
        full = root / rel_path
        if _is_credential_file(full) or _has_symlink_below(full, root):
            note_cut()
            return None, None
        rem = eff_max_total_bytes - limits['bytes_read']
        if rem <= 0:
            note_cut('total_bytes_cap')
            return None, None
        cap = min(cap_bytes, eff_max_file_bytes, rem)
        parts = tuple(p for p in rel_path.split('/') if p and p != '.')
        try:
            with _open_root_dir_fd(root) as (root_fd, _, _):
                with _walk_parent_dir_fds(root_fd, parts[:-1]) as parent_fd:
                    leaf = parts[-1]
                    st_pre = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISREG(st_pre.st_mode):
                        note_cut()
                        return None, None
                    o_nofollow = getattr(os, 'O_NOFOLLOW', 0)
                    o_nonblock = getattr(os, 'O_NONBLOCK', 0)
                    try:
                        fd = open_checked(leaf, os.O_RDONLY | o_nofollow | o_nonblock, dir_fd=parent_fd,
                                          full_path=os.path.abspath(full))
                    except CredentialStoreNotOpened:
                        note_cut()  # same as a declared path: skipped, never read
                        return None, None
                    try:
                        st_open = os.fstat(fd)
                        if not stat.S_ISREG(st_open.st_mode) or (st_open.st_dev, st_open.st_ino) != (st_pre.st_dev, st_pre.st_ino):
                            note_cut()
                            return None, None
                        data = os.read(fd, cap)
                    finally:
                        os.close(fd)
                    limits['bytes_read'] += len(data)
                    return data, int(st_pre.st_size)
        except OSError:
            note_cut()
            return None, None

    # Preflight profile_path existence and non-emptiness (house rule 10).
    try:
        st_root = os.lstat(root)
    except FileNotFoundError:
        finding = _finding('unattended_exposure.could_not_verify', '.', {'reason': 'missing'},
                           coverage='could_not_verify', classification='info')
        return _envelope([finding], 'could_not_verify', _empty_section('missing', limits, thresholds),
                         run_metrics())
    except OSError:
        st_root = None

    if st_root is None or stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        finding = _finding('unattended_exposure.could_not_verify', '.', {'reason': 'unreadable'},
                           coverage='could_not_verify', classification='info')
        return _envelope([finding], 'could_not_verify', _empty_section('unreadable', limits, thresholds),
                         run_metrics())

    top_entries = []
    try:
        with os.scandir(root) as it:
            for entry in it:
                if not step_entry():
                    break
                top_entries.append(entry)
    except OSError:
        note_cut()

    if not top_entries and limits['cuts'] == 0:
        finding = _finding('unattended_exposure.could_not_verify', '.', {'reason': 'empty'},
                           coverage='could_not_verify', classification='info')
        return _envelope([finding], 'could_not_verify', _empty_section('empty', limits, thresholds),
                         run_metrics())

    managed_active = _has_managed_overlay(managed_dir)

    # Read config.yaml (same approach as audit.write_settings, plus duplicate-key check).
    cfg_bytes, cfg_status = read_bounded_file('config.yaml', MAX_CONFIG_BYTES)
    cfg_missing = cfg_status == 'missing'
    cfg_readable = cfg_missing or (cfg_status == 'ok' and cfg_bytes is not None)
    config: dict[str, Any] = {}
    if cfg_readable and not cfg_missing and cfg_bytes is not None:
        try:
            config = _parse_yaml_strict(cfg_bytes.decode('utf-8'))
        except (ValueError, UnicodeError, RecursionError):
            cfg_readable = False

    settings, smart_info, platform_info, a2a_mcp_info, sanity_info = _evaluate_settings_and_sanity(
        config, readable=cfg_readable, managed_active=managed_active,
    )
    config_trusted = cfg_readable and not managed_active

    # Compare enumerated settings across config.yaml.bak / config.yaml.bak-* / config.yaml.bak.* copies
    # in the profile root. Backups are ordered by (mtime_ns, name); the current config.yaml is
    # always the last element, so the sequence is stable for an unchanged home.
    backup_candidates: list[tuple[int, str]] = []
    for entry in sorted(top_entries, key=lambda e: e.name):
        name = entry.name
        if name.startswith('._'):
            continue
        if name == 'config.yaml.bak' or name.startswith(('config.yaml.bak-', 'config.yaml.bak.')):
            if _is_credential_file(Path(entry.path)):
                continue
            if entry.is_symlink():
                note_cut()
                continue
            try:
                st_b = entry.stat(follow_symlinks=False)
            except OSError:
                note_cut()
                continue
            if stat.S_ISREG(st_b.st_mode):
                backup_candidates.append((int(st_b.st_mtime_ns), name))

    snapshots: list[dict[str, dict[str, Any]]] = []
    if config_trusted and not cfg_missing:
        for _mtime_ns, bname in sorted(backup_candidates):
            if check_time():
                break
            b_bytes, b_status = read_bounded_file(bname, MAX_CONFIG_BYTES)
            if b_status != 'ok' or b_bytes is None:
                continue
            try:
                b_cfg = _parse_yaml_strict(b_bytes.decode('utf-8'))
            except (ValueError, UnicodeError, RecursionError):
                note_cut()
                continue
            b_settings, _, _, _, _ = _evaluate_settings_and_sanity(b_cfg, readable=True, managed_active=False)
            snapshots.append(b_settings)
        snapshots.append(settings)

    changed_keys: list[str] = []
    approval_changed_keys: list[str] = []
    drift_changes: dict[str, dict[str, Any]] = {}
    if len(snapshots) >= 2:
        for skey in sorted(settings.keys()):
            seq: list[Any] = []
            for snap in snapshots:
                val = snap[skey]['value']
                if not seq or seq[-1] != val:
                    seq.append(val)
            if len(seq) > 1:
                changed_keys.append(skey)
                drift_changes[skey] = {'values': seq, 'current': settings[skey]['value']}
                if skey in APPROVAL_DRIFT_KEYS:
                    approval_changed_keys.append(skey)

    backup_drift_info = {
        'copies_compared': len(snapshots),
        'backup_count': max(0, len(snapshots) - 1),
        'changed_keys': changed_keys,
        'approval_changed_keys': approval_changed_keys,
        'changes': drift_changes,
    }

    # Plugins: plugins.enabled is an opt-in allow-list and plugins.disabled wins
    # (hermes_cli/plugins_discovery.py:111-130,269-345). Lists only.
    plug_sec = _section(config, 'plugins') if config_trusted else {}
    raw_enabled = plug_sec.get('enabled')
    raw_disabled = plug_sec.get('disabled')
    enabled_is_list = isinstance(raw_enabled, list)
    enabled_set = {str(s).strip() for s in raw_enabled if str(s).strip()} if enabled_is_list else set()
    disabled_set = (
        {str(s).strip() for s in raw_disabled if str(s).strip()} if isinstance(raw_disabled, list) else set()
    )

    install_meta: dict[str, Any] = {}
    meta_readable = False
    plugins_dir = root / 'plugins'
    if os.path.lexists(plugins_dir):
        if _has_symlink_below(plugins_dir, root):
            note_cut()
        elif plugins_dir.is_dir():
            meta_bytes, meta_status = read_bounded_file('plugins/.install-metadata.json', MAX_PLUGIN_MANIFEST_BYTES)
            if meta_status == 'missing':
                meta_readable = True
            elif meta_status == 'ok' and meta_bytes is not None:
                try:
                    parsed_meta = json.loads(meta_bytes.decode('utf-8-sig'))
                    if isinstance(parsed_meta, dict):
                        install_meta = parsed_meta
                        meta_readable = True
                    else:
                        note_cut()
                except (ValueError, UnicodeError):
                    note_cut()

    def pinned_state(*names: str) -> str:
        """hermes_cli/plugins_cmd_git.py:90-94: pinned iff the record has pinned True and a str revision."""
        if not meta_readable:
            return 'unknown'
        for nm in names:
            rec = install_meta.get(nm)
            if isinstance(rec, dict):
                return 'yes' if (rec.get('pinned') is True and isinstance(rec.get('revision'), str)) else 'no'
        return 'unknown'

    hook_plugins: list[dict[str, Any]] = []
    memory_provider_count = 0
    missing_or_empty_enabled: list[dict[str, Any]] = []
    installed_plugin_count = 0

    def report_missing(gate_names: set[str], rel_dir: str | None, status_label: str) -> None:
        # Absolute path of the existing directory (the report serializer keeps existing absolute
        # paths); None for a symlink, whose resolved target lies outside the audited home.
        if gate_names & enabled_set and not gate_names & disabled_set:
            missing_or_empty_enabled.append({
                'path': str(root_abs / rel_dir) if rel_dir is not None else None,
                'status': status_label,
            })

    def scan_plugin_dir(rel_dir: str, depth: int, prefix: str) -> None:
        nonlocal installed_plugin_count, memory_provider_count
        if check_time():
            return
        if depth > MAX_DEPTH:
            note_cut('depth_cap')
            return
        dir_path = root / rel_dir
        if _is_credential_file(dir_path) or _has_symlink_below(dir_path, root):
            note_cut()
            return
        try:
            with os.scandir(dir_path) as it:
                entries = []
                for e in it:
                    if not step_entry():
                        return
                    entries.append(e)
        except OSError:
            note_cut()
            return

        for entry in sorted(entries, key=lambda e: e.name):
            if check_time():
                return
            ename = entry.name
            # hermes_cli/plugins_discovery.py:133-138 skips dunder dirs; dot entries are sidecars.
            if ename.startswith('.') or (ename.startswith('__') and ename.endswith('__')):
                continue
            child_rel = f'{rel_dir}/{ename}'
            child_key = f'{prefix}/{ename}' if prefix else ename
            if _is_credential_file(Path(entry.path)):
                note_cut()
                continue
            if entry.is_symlink():
                # Hermes follows directory symlinks (Path.is_dir); the audit never does.
                note_cut()
                report_missing({child_key}, None, 'symlink_skipped')
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                note_cut()
                continue
            if not is_dir:
                continue
            if depth + 1 > MAX_DEPTH:
                note_cut('depth_cap')
                continue
            try:
                with os.scandir(entry.path) as sub_it:
                    sub_entries = []
                    for se in sub_it:
                        if not step_entry():
                            return
                        sub_entries.append(se)
            except OSError:
                note_cut()
                continue

            visible = {se.name: se for se in sub_entries if not se.name.startswith('._')}
            manifest_name = next((n for n in ('plugin.yaml', 'plugin.yml') if n in visible), None)
            if manifest_name is None:
                if 'plugin.json' in visible:
                    report_missing({child_key}, child_rel, 'portable_manifest_not_read')
                elif not visible:
                    report_missing({child_key}, child_rel, 'empty_dir')
                elif not prefix:
                    # Category dir (plugins_discovery.py:184-186): one level of recursion.
                    report_missing({child_key}, child_rel, 'missing_manifest')
                    scan_plugin_dir(child_rel, depth + 1, child_key)
                else:
                    report_missing({child_key}, child_rel, 'missing_manifest')
                continue

            installed_plugin_count += 1
            m_bytes, m_status = read_bounded_file(f'{child_rel}/{manifest_name}', MAX_PLUGIN_MANIFEST_BYTES)
            if m_status != 'ok' or m_bytes is None:
                continue
            try:
                m_data = _parse_yaml_strict(m_bytes.decode('utf-8-sig'))
            except (ValueError, UnicodeError, RecursionError):
                note_cut()
                continue
            if not isinstance(m_data, dict):
                note_cut()
                continue

            # hermes_cli/plugins_manifest.py:564-565: name defaults to the dir name; the key is
            # '<category>/<dir>' inside a category, else the manifest name. Gate names: key + name.
            raw_pname = m_data.get('name', ename)
            pname = str(raw_pname).strip() if isinstance(raw_pname, (str, int, float)) else ename
            plugin_key = child_key if prefix else pname
            gate_names = {plugin_key, pname}
            safe_ver = _safe_version(m_data.get('version'))

            raw_kind = m_data.get('kind', 'standalone')
            kind = raw_kind.strip().lower() if isinstance(raw_kind, str) else 'standalone'
            if kind not in VALID_PLUGIN_KINDS:
                kind = 'standalone'
            kind_declared = 'kind' in m_data
            if kind == 'exclusive':
                memory_provider_count += 1

            listed = enabled_is_list and bool(gate_names & enabled_set) and not (gate_names & disabled_set)
            # Exclusive and model-provider kinds never load through plugins.enabled
            # (plugins_discovery.py:301-311).
            is_enabled = listed and kind not in ('exclusive', 'model-provider')

            # hermes_cli/plugins_manifest.py:575-577: provides_hooks, else legacy hooks.
            raw_hooks = m_data.get('provides_hooks', m_data.get('hooks', []))
            hook_list = sorted({h.strip() for h in raw_hooks if isinstance(h, str) and h.strip() in VALID_HOOKS}) \
                if isinstance(raw_hooks, list) else []
            relevant_hooks = sorted(set(hook_list) & REPORTED_PLUGIN_HOOKS)
            pinned_str = pinned_state(ename, plugin_key, pname)
            has_prompt_hook = bool(set(hook_list) & PROMPT_INJECTING_HOOKS)

            kind_verified = True
            if is_enabled and has_prompt_hook and pinned_str == 'no' and not kind_declared \
                    and '__init__.py' in visible:
                # Hermes auto-detects exclusive / model-provider kinds from the first 8192 chars of
                # __init__.py when plugin.yaml has no kind (plugins_manifest.py:539-546,287-298).
                init_bytes, _ = read_prefix(f'{child_rel}/__init__.py', MAX_PLUGIN_INIT_BYTES)
                if init_bytes is None:
                    kind_verified = False
                else:
                    text = init_bytes.decode('utf-8', errors='replace')
                    if any(mk in text for mk in _EXCLUSIVE_MARKERS) or (
                        'register_provider' in text and 'ProviderProfile' in text
                    ):
                        is_enabled = False

            if hook_list:
                hook_plugins.append({
                    # Absolute path of the plugin directory: names and versions are user text the
                    # report serializer would replace with a run-local hash.
                    'path': str(root_abs / child_rel),
                    'version_declared': safe_ver != 'unknown',
                    'enabled': is_enabled if kind_verified else None,
                    'pinned': pinned_str,
                    'hooks': hook_list,
                    'prompt_or_approval_hooks': relevant_hooks,
                    'hook_count': len(hook_list),
                    'provides_memory_provider': kind == 'exclusive',
                    'status': 'ok' if kind_verified else 'kind_not_verified',
                    '_has_prompt_hook': has_prompt_hook,
                })

    if os.path.lexists(plugins_dir) and not _has_symlink_below(plugins_dir, root) and plugins_dir.is_dir():
        scan_plugin_dir('plugins', 1, '')

    # Shell hooks: config.yaml hooks: block (agent/shell_hooks.py:368-447). Counts per event only;
    # command strings are never emitted.
    scripts_by_event: dict[str, int] = {}
    hooks_cfg = config.get('hooks') if config_trusted else None
    if isinstance(hooks_cfg, dict):
        for ev_name, ev_entries in sorted(hooks_cfg.items(), key=lambda kv: str(kv[0])):
            if ev_name in ('output_spill', 'outbound') or ev_name in SHELL_UNSUPPORTED_HOOKS:
                continue
            if ev_name not in VALID_HOOKS:
                note_cut()
                continue
            if ev_entries is None:
                continue
            if not isinstance(ev_entries, list):
                note_cut()
                continue
            valid_cnt = sum(
                1 for item in ev_entries
                if isinstance(item, dict) and isinstance(item.get('command'), str) and item['command'].strip()
            )
            if valid_cnt != len(ev_entries):
                note_cut()
            if valid_cnt > 0:
                scripts_by_event[ev_name] = valid_cnt
    elif hooks_cfg is not None:
        note_cut()

    # Regular files directly in hooks/: NOT a Hermes registration format (Hermes gateway hooks are
    # hooks/<name>/HOOK.yaml + handler.py, gateway/hooks.py:1-4,41-45). Listed by name, size and
    # first-line interpreter class only; never mapped to events.
    hook_files: list[dict[str, Any]] = []
    hooks_dir = root / 'hooks'
    if os.path.lexists(hooks_dir):
        if _has_symlink_below(hooks_dir, root) or _is_credential_file(hooks_dir):
            note_cut()
        elif hooks_dir.is_dir():
            try:
                with os.scandir(hooks_dir) as it:
                    h_entries = []
                    for e in it:
                        if not step_entry():
                            break
                        h_entries.append(e)
                for entry in sorted(h_entries, key=lambda e: e.name):
                    if check_time():
                        break
                    if entry.name.startswith('.'):
                        continue
                    if _is_credential_file(Path(entry.path)):
                        continue
                    if entry.is_symlink():
                        note_cut()
                        continue
                    if entry.is_file(follow_symlinks=False):
                        hdr, fsize = read_prefix(f'hooks/{entry.name}', MAX_HOOK_HEADER_BYTES)
                        if hdr is not None and fsize is not None:
                            first_line = hdr.split(b'\n', 1)[0]
                            hook_files.append({
                                'path': (str(root_abs / 'hooks' / entry.name)
                                         if _safe_hook_file_name(entry.name) != HOOK_NAME_PLACEHOLDER
                                         else None),
                                'size_bytes': fsize,
                                'interpreter': _classify_shebang(first_line),
                            })
            except OSError:
                note_cut()

    hooks_info = {
        'total_scripts': sum(scripts_by_event.values()),
        'scripts_by_event': dict(sorted(scripts_by_event.items())),
        'files': hook_files,
    }

    # Cron: cron/jobs.json {"jobs": [...]} (cron/jobs.py:1-3,95), cron/usage_audit.jsonl job_id
    # (cron/scheduler.py:1244-1264,2526-2530), cron/output/<job_id>/ (cron/jobs.py:1-3),
    # cron/executions.db executions/cron_incidents.job_id (cron/executions.py:65-71; cron/incidents.py:79-81).
    cron_total = 0
    cron_enabled = 0
    cron_paused = 0
    cron_script_jobs = 0
    cron_prompt_jobs = 0
    schedule_classes = {'more_often_than_hourly': 0, 'hourly_to_daily': 0, 'less_often': 0, 'unclassified': 0}
    failing_streaks: list[int] = []
    known_job_ids: set[str] = set()
    referenced_job_ids: set[str] = set()

    cron_dir = root / 'cron'
    if os.path.lexists(cron_dir):
        if _has_symlink_below(cron_dir, root) or _is_credential_file(cron_dir):
            note_cut()
        elif cron_dir.is_dir():
            j_bytes, j_status = read_bounded_file('cron/jobs.json', MAX_CRON_BYTES)
            if j_status == 'ok' and j_bytes is not None:
                try:
                    j_data = json.loads(j_bytes.decode('utf-8-sig'))
                    raw_jobs: Any
                    if isinstance(j_data, dict):
                        raw_jobs = j_data.get('jobs', [])
                        if isinstance(raw_jobs, dict):
                            raw_jobs = [
                                {**v, 'id': v.get('id') or k}
                                for k, v in raw_jobs.items() if isinstance(v, dict)
                            ]
                    elif isinstance(j_data, list):
                        raw_jobs = j_data
                    else:
                        raw_jobs = None
                    if not isinstance(raw_jobs, list):
                        note_cut()
                        raw_jobs = []
                    for job in raw_jobs:
                        if not isinstance(job, dict):
                            note_cut()
                            continue
                        cron_total += 1
                        jid = str(job.get('id') or '').strip()
                        if jid:
                            known_job_ids.add(jid)
                        c_from = job.get('context_from')
                        if isinstance(c_from, str) and c_from.strip():
                            referenced_job_ids.add(c_from.strip())
                        elif isinstance(c_from, list):
                            for cf in c_from:
                                if isinstance(cf, str) and cf.strip():
                                    referenced_job_ids.add(cf.strip())
                        # cron/jobs.py:531-539 is_job_runnable / _has_pause_marker.
                        paused_marker = (
                            str(job.get('state') or '').strip() == 'paused'
                            or bool(job.get('paused_at'))
                        )
                        if bool(job.get('enabled', True)) and not paused_marker:
                            cron_enabled += 1
                        else:
                            cron_paused += 1

                        # A script runs when 'script' (cron/scheduler.py:1516,2272-2279) or
                        # 'monitor_script' (cron/monitor.py:107-114) is a non-empty string.
                        has_script = False
                        for s_key in ('script', 'monitor_script'):
                            s_val = job.get(s_key)
                            if isinstance(s_val, str) and s_val.strip():
                                has_script = True
                        if has_script:
                            cron_script_jobs += 1
                        else:
                            cron_prompt_jobs += 1

                        schedule_classes[_classify_cron_schedule(job.get('schedule'))] += 1

                        # cron/jobs.py:2413-2417: consecutive failed runs; reset on success.
                        streak, s_ok = _classify_nonneg_int(job.get('failure_streak') or 0, min_value=0)
                        if s_ok and streak is not None and streak >= CRON_FAILURE_STREAK_THRESHOLD:
                            failing_streaks.append(streak)
                except (ValueError, UnicodeError):
                    note_cut()

            u_bytes, u_status = read_bounded_file('cron/usage_audit.jsonl', MAX_CRON_BYTES)
            if u_status == 'ok' and u_bytes is not None:
                try:
                    lines = u_bytes.decode('utf-8-sig').splitlines()
                except UnicodeError:
                    note_cut()
                    lines = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        note_cut()
                        continue
                    if not isinstance(row, dict):
                        note_cut()
                        continue
                    ujid = row.get('job_id')
                    if isinstance(ujid, str) and ujid.strip():
                        referenced_job_ids.add(ujid.strip())
                    elif ujid is not None:
                        note_cut()

            out_dir = cron_dir / 'output'
            if os.path.lexists(out_dir):
                if _has_symlink_below(out_dir, root) or _is_credential_file(out_dir):
                    note_cut()
                elif out_dir.is_dir():
                    try:
                        with os.scandir(out_dir) as it:
                            for e in it:
                                if not step_entry():
                                    break
                                if e.name.startswith('.'):
                                    continue
                                if e.is_symlink():
                                    note_cut()
                                    continue
                                if e.is_dir(follow_symlinks=False):
                                    referenced_job_ids.add(e.name)
                    except OSError:
                        note_cut()

            exec_db = cron_dir / 'executions.db'
            if os.path.lexists(exec_db):
                if _has_symlink_below(exec_db, root) or _is_credential_file(exec_db):
                    note_cut()
                else:
                    sql_steps = 0
                    step_quantum = min(1000, max(1, MAX_SQL_STEPS))

                    def progress_handler() -> int:
                        nonlocal sql_steps
                        sql_steps += step_quantum
                        if check_time():
                            return 1
                        if sql_steps > MAX_SQL_STEPS:
                            note_cut('sql_steps')
                            return 1
                        return 0

                    try:
                        with _open_user_db(exec_db, root) as (conn, _):
                            conn.set_progress_handler(progress_handler, step_quantum)
                            tables = {
                                r[0] for r in conn.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table' LIMIT 20"
                                ).fetchall()
                            }
                            for tbl in ('executions', 'cron_incidents'):
                                if tbl not in tables:
                                    continue
                                cols = {r[1] for r in conn.execute(f'PRAGMA table_info("{tbl}")').fetchall()}
                                if 'job_id' not in cols:
                                    continue
                                rows = conn.execute(
                                    f'SELECT DISTINCT substr(CAST(job_id AS TEXT), 1, 64) FROM "{tbl}" '
                                    f'WHERE typeof(job_id)=\'text\' LIMIT ?',
                                    (MAX_DB_ROWS + 1,),
                                ).fetchall()
                                if len(rows) > MAX_DB_ROWS:
                                    note_cut('row_cap')
                                for (db_jid,) in rows[:MAX_DB_ROWS]:
                                    if isinstance(db_jid, str) and db_jid.strip():
                                        referenced_job_ids.add(db_jid.strip())
                    except (ReadOnlyDbError, sqlite3.Error, OSError):
                        note_cut()

    ghost_all = sorted(referenced_job_ids - known_job_ids)

    cron_info = {
        'total': cron_total,
        'enabled': cron_enabled,
        'paused': cron_paused,
        'script_jobs': cron_script_jobs,
        'prompt_jobs': cron_prompt_jobs,
        'schedule_classes': schedule_classes,
        'failing_jobs_count': len(failing_streaks),
        'max_failure_streak': max(failing_streaks, default=0),
        'failing_streaks': sorted(failing_streaks),
        'ghost_jobs_count': len(ghost_all),
        'allow_agent_scheduling': settings['cron.allow_agent_scheduling']['value'],
        'catch_up_missed': settings['cron.catch_up_missed']['value'],
    }

    findings: list[dict[str, Any]] = []

    # 1. command_approval_off (warning): approvals.mode is off (APPROVAL_OFF) FROM CONFIG and terminal.backend
    # is 'local' FROM CONFIG (a default backend can be replaced by TERMINAL_ENV, unreadable here).
    # tools/approval.py:1123-1137 skips prompts for container backends anyway; ssh runs elsewhere.
    mode_row = settings['approvals.mode']
    backend_row = settings['terminal.backend']
    if (
        mode_row['value'] == APPROVAL_OFF and mode_row['source'] == 'config'
        and backend_row['value'] == 'local' and backend_row['source'] == 'config'
    ):
        findings.append(_finding(
            'unattended_exposure.command_approval_off',
            'config.yaml',
            {
                'approvals_mode': APPROVAL_OFF,
                'terminal_backend': 'local',
                'command_allowlist_count': settings['command_allowlist']['value'] or 0,
            },
            classification='warning',
        ))

    # 1b. unattended_auto_approve: approvals.cron_mode / unattended_mode / single_query_mode resolve to
    # 'approve' from config (tools/approval_context.py:347-371). In those contexts a flagged command or
    # execute_code script runs without a prompt (tools/approval.py:674-693,737-754,1086-1101,1278-1284,
    # 1350-1358); the floors (hardline, runtime self-delete, sudo stdin, approvals.deny) run first
    # (tools/approval.py:1151-1172,1259-1261). Warning only when terminal.backend is local FROM CONFIG.
    approve_modes = {
        sub: settings[f'approvals.{sub}']['value'] == 'approve'
        and settings[f'approvals.{sub}']['source'] == 'config'
        for sub in ('cron_mode', 'unattended_mode', 'single_query_mode')
    }
    if any(approve_modes.values()):
        local_from_config = backend_row['value'] == 'local' and backend_row['source'] == 'config'
        findings.append(_finding(
            'unattended_exposure.unattended_auto_approve',
            'config.yaml',
            {
                'cron_mode_approve': approve_modes['cron_mode'],
                'unattended_mode_approve': approve_modes['unattended_mode'],
                'single_query_mode_approve': approve_modes['single_query_mode'],
                'approve_mode_count': sum(approve_modes.values()),
                'terminal_backend': backend_row['value'] if isinstance(backend_row['value'], str)
                else 'could_not_verify',
                'terminal_backend_source': backend_row['source'],
            },
            classification='warning' if local_from_config else 'review_suggested',
        ))

    # 2. remote_platform_has_powerful_tools (warning): a remote platform's explicit list grants a
    # high-risk toolset its shipped default does not.
    flagged_platforms = {
        p: info for p, info in [*platform_info['non_cli_platforms'].items(),
                                *((f'other_{i}', row) for i, row in enumerate(platform_info['other_platforms']))]
        if info['remote'] and info['beyond_default_high_risk_tools']
    }
    if flagged_platforms:
        findings.append(_finding(
            'unattended_exposure.remote_platform_has_powerful_tools',
            'config.yaml',
            {
                # Scalars only (persistence keeps numbers, booleans and vocabulary strings); the
                # platform names and per-platform lists are in platform_toolsets.non_cli_platforms.
                'platform_count': len(flagged_platforms),
                **{
                    f'beyond_default_{tool}': any(
                        tool in info['beyond_default_high_risk_tools'] for info in flagged_platforms.values()
                    )
                    for tool in sorted(HIGH_RISK_TOOLSETS)
                },
                'max_peer_or_user_count': max(
                    (info['peer_or_user_count'] for info in flagged_platforms.values()), default=0,
                ),
            },
            classification='warning',
        ))

    # 3. unpinned_prompt_injector (warning): enabled (allow-listed, loadable kind), declares a
    # prompt-altering hook, and has an install record that is not pinned.
    for hp_index, hp in enumerate(hook_plugins):
        if hp['enabled'] is True and hp['_has_prompt_hook'] and hp['pinned'] == 'no':
            findings.append(_finding(
                'unattended_exposure.unpinned_prompt_injector',
                'plugins',
                {
                    # Index into plugins.hook_plugins (name and version live there, not here).
                    'hook_plugin_index': hp_index,
                    'pinned': hp['pinned'],
                    'declares_pre_llm_call': 'pre_llm_call' in hp['hooks'],
                    'declares_pre_gateway_dispatch': 'pre_gateway_dispatch' in hp['hooks'],
                },
                classification='warning',
            ))

    # 4. small_model_decides_approvals (review_suggested)
    if settings['approvals.mode']['value'] == 'smart' and smart_info.get('is_small') is True:
        findings.append(_finding(
            'unattended_exposure.small_model_decides_approvals',
            'config.yaml',
            {
                'approvals_mode': 'smart',
                'size_class': smart_info['size_class'],
                'uses_local_proxy': bool(smart_info['uses_local_proxy']),
            },
            classification='review_suggested',
        ))

    # 5. guardrail_disabled (review_suggested): only checks that are ON by default and turned off in
    # config (or the private-URL guard opened). hard_stop_enabled is off by default, never flagged.
    disabled_guards: list[tuple[str, Any]] = []
    if settings['security.protected_instruction_files']['value'] is False:
        disabled_guards.append(('security.protected_instruction_files', False))
    if settings['security.allow_private_urls']['value'] is True:
        disabled_guards.append(('security.allow_private_urls', True))
    if settings['tool_loop_guardrails.non_interactive_hard_stop_enabled']['value'] is False:
        disabled_guards.append(('tool_loop_guardrails.non_interactive_hard_stop_enabled', False))
    for guard_key, guard_val in disabled_guards:
        findings.append(_finding(
            'unattended_exposure.guardrail_disabled',
            'config.yaml',
            {'guard': guard_key, 'value': guard_val, 'source': settings[guard_key]['source']},
            classification='review_suggested',
        ))

    # 6. real_browser_profile (review_suggested)
    if settings['browser.use_real_profile']['value'] is True:
        findings.append(_finding(
            'unattended_exposure.real_browser_profile',
            'config.yaml',
            {'use_real_profile': True, 'source': settings['browser.use_real_profile']['source']},
            classification='review_suggested',
        ))

    # 7. cron_failing_jobs (review_suggested when any job is runnable; info when all paused)
    if cron_info['failing_jobs_count'] > 0:
        findings.append(_finding(
            'unattended_exposure.cron_failing_jobs',
            'cron/jobs.json',
            {
                'failing_jobs_count': cron_info['failing_jobs_count'],
                'max_failure_streak': cron_info['max_failure_streak'],
                'enabled_jobs_count': cron_info['enabled'],
                'paused_jobs_count': cron_info['paused'],
            },
            classification='review_suggested' if cron_info['enabled'] > 0 else 'info',
        ))

    # 8. cron_runs_scripts (info)
    if cron_info['script_jobs'] > 0:
        findings.append(_finding(
            'unattended_exposure.cron_runs_scripts',
            'cron/jobs.json',
            {
                'script_jobs': cron_info['script_jobs'],
                'total_jobs': cron_info['total'],
                'enabled_jobs': cron_info['enabled'],
            },
            classification='info',
        ))

    # 9. ghost_cron_job (info)
    if cron_info['ghost_jobs_count'] > 0:
        findings.append(_finding(
            'unattended_exposure.ghost_cron_job',
            'cron',
            {'ghost_jobs_count': cron_info['ghost_jobs_count']},
            classification='info',
        ))

    # 10. approval_setting_changed_in_backups (info)
    if backup_drift_info['approval_changed_keys']:
        findings.append(_finding(
            'unattended_exposure.approval_setting_changed_in_backups',
            'config.yaml',
            {
                'copies_compared': backup_drift_info['copies_compared'],
                'approval_changed_key_count': len(backup_drift_info['approval_changed_keys']),
            },
            classification='info',
        ))

    # 11. config_value_malformed (info)
    if sanity_info['total_malformed'] > 0:
        findings.append(_finding(
            'unattended_exposure.config_value_malformed',
            'config.yaml',
            {
                'provider_url_count': sanity_info['provider_url_count'],
                'whitespace_value_count': sanity_info['whitespace_value_count'],
                'total_malformed': sanity_info['total_malformed'],
            },
            classification='info',
        ))

    clean_hook_plugins = [{k: v for k, v in hp.items() if not k.startswith('_')} for hp in hook_plugins]
    plugins_info = {
        'enabled_count': len(enabled_set),
        'disabled_count': len(disabled_set),
        'installed_count': installed_plugin_count,
        'hook_plugins': clean_hook_plugins,
        'memory_provider_count': memory_provider_count,
        'missing_or_empty_enabled': missing_or_empty_enabled,
    }

    unverified = (
        not cfg_readable
        or managed_active
        or limits['cuts'] > 0
        or any(s['source'] == 'could_not_verify' for s in settings.values())
        or any(hp['enabled'] is None for hp in hook_plugins)
    )
    if unverified:
        reason_str = (
            'managed_overlay' if managed_active
            else (truncated_by or ('config_unreadable' if not cfg_readable else 'could_not_verify'))
        )
        findings.append(_finding(
            'unattended_exposure.could_not_verify',
            'config.yaml',
            {'reason': reason_str, 'cuts': limits['cuts']},
            coverage='could_not_verify',
            classification='info',
        ))

    coverage = 'could_not_verify' if unverified else 'verified'
    section = {
        'status': 'completed',
        'reason': 'managed_overlay' if managed_active else None,
        'coverage': coverage,
        'truncated_by': truncated_by,
        'settings': settings,
        'smart_approval': smart_info,
        'platform_toolsets': platform_info,
        **a2a_mcp_info,
        'plugins': plugins_info,
        'hooks': hooks_info,
        'cron': cron_info,
        'config_backup_drift': backup_drift_info,
        'config_sanity': sanity_info,
        'limits': limits,
        'thresholds': thresholds,
    }
    return _envelope(findings, coverage, section, run_metrics())
