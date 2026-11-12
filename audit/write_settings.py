"""Static write policy; no runtime config loader, plugin import, or provider calls."""
import os
from pathlib import Path

from .contract import make_component_envelope, make_finding
from .context_load import KNOWN_EXTERNAL_MEMORY_PROVIDERS
from .evidence import serialize_evidence
from .facts import DuplicateConfigKeyError, _parse_simple_yaml_mapping
from .fingerprint import safe_read_regular_file
from .skill_hygiene import RESIDUE_THRESHOLD, _finding

MAX_CONFIG_BYTES = 1024 * 1024  # Bound YAML parse independently of outward budgets.
# Hermes hermes_cli/config_defaults.py:1296-1310,1464-1467; tools/memory_tool.py:292-309.
# Explicit approval exists and defaults OFF, not "no approval implementation".
DEFAULTS = {
    'memory.memory_enabled': True, 'memory.user_profile_enabled': True,
    'memory.write_approval': False, 'skills.write_approval': False,
    'memory.nudge_interval': 10,
    # Hermes agent/agent_init.py:1284-1288; zero disables reminders, not skill_manage.
    'skills.creation_nudge_interval': 10,
    # Hermes hermes_cli/config_defaults.py:1455-1458: security scanner, NOT human approval.
    'skills.guard_agent_created': False,
}
# Hermes hermes_yaml.py:1-39 (ruamel YAML 1.1 safe loader) + tools/write_approval.py:40,45-61
# vs utils.py:25-34 (memory and guard flags). PyYAML 6.x (YAML 1.1 sans bare y/n) parses
# bare y/Y/n/N identically to quoted "y"/"n", whereas ruamel parses bare y/n as bool and
# quoted "y"/"n" as str (which _normalize_enabled / is_truthy_value treat as False). Anything
# outside the unambiguous known-true / known-false sets is reported as could_not_verify.
APPROVAL_TRUTHY = frozenset({'on', 'true', 'yes', '1', 'approve', 'enabled'})
APPROVAL_FALSY = frozenset({'off', 'false', 'no', '0', 'disabled', 'deny', 'none', ''})
MEMORY_TRUTHY = frozenset({'on', 'true', 'yes', '1'})
MEMORY_FALSY = frozenset({'off', 'false', 'no', '0', 'disabled', 'none', ''})
# Hermes agent/memory_provider.py:42-49: these mean no external provider.
CORE_PROVIDERS = frozenset({'', 'default', 'builtin', 'built-in', 'none'})
# Hermes toolsets.py:11-21,52-64,100-103,126,198; config_defaults.py:30.
WRITE_TOOLSETS = {'skills': {'skill_manage'}, 'memory': {'memory'},
                 'hermes-cli': {'skill_manage', 'memory'}, 'coding': {'skill_manage', 'memory'}}
INERT_TOOLSETS = frozenset({'file', 'terminal', 'web', 'search', 'browser', 'vision', 'image', 'todo', 'session_search'})
# Hermes tools/write_approval.py added 2026-06-09 (commit 96af61b6ef9); project started 2025-07-22.
APPROVAL_PRIOR_DRIFT_RULE = 'skill_hygiene.approval_enabled_with_prior_drift'
APPROVAL_PRIOR_DRIFT_CONSEQUENCE = (
    'Approval is on now, which stops new unattended writes, but it does not clean what was written '
    'before it was enabled; config cannot tell when approval was enabled, and existing skills still '
    'carry earlier changes or residue and need a manual look.'
)


_DEFAULT_MANAGED_DIR = Path('/etc/hermes')


def _has_managed_overlay(managed_dir=None) -> bool:
    """Hermes hermes_cli/config.py:2170-2185 & hermes_cli/managed_scope.py:31-60:
    an existing managed scope directory overrides user config at the leaf."""
    if managed_dir is not None:
        candidate = Path(managed_dir)
    else:
        override = os.environ.get('HERMES_MANAGED_DIR', '').strip()
        if override:
            candidate = Path(override)
        elif 'PYTEST_CURRENT_TEST' in os.environ:
            return False
        else:
            candidate = _DEFAULT_MANAGED_DIR
    try:
        return candidate.is_dir()
    except OSError:
        return True


def _section(config, key):
    value = config.get(key)
    return value if isinstance(value, dict) else {}


def _names(value):
    if isinstance(value, str):
        # Hermes tools_config.py:638-642 permits JSON-array strings through parse_config_string_list.
        import json
        try:
            value = json.loads(value)
        except ValueError:
            value = [value]
    return value if isinstance(value, list) and all(isinstance(v, str) for v in value) else None


def _read_settings_config(root, managed_active):
    read = safe_read_regular_file(root, 'config.yaml', max_bytes=MAX_CONFIG_BYTES)
    # Missing config means defaults; other read failures never mean defaults verified.
    missing = read.kind == 'missing'
    readable = missing or (read.coverage == 'verified' and read.stable and read.content is not None)
    config = {}
    # The reviewed word the could_not_verify finding stores for why settings are unknown.
    config_reason = 'input_unknown' if readable else ('unreadable' if root.is_dir() else 'missing')
    if readable and not missing:
        try:
            config = _parse_simple_yaml_mapping(read.content.decode('utf-8'), reject_duplicate_keys=True)
        except DuplicateConfigKeyError:
            readable = False
            config_reason = 'duplicate_config_key'
        except (ValueError, UnicodeError, RecursionError):
            readable = False
    if managed_active and readable:
        config_reason = 'managed_overlay'
    return config, readable, config_reason


def _resolve_settings(config, readable, managed_active):
    settings = {}
    for key, default in DEFAULTS.items():
        subsystem, field = key.split('.')
        section = _section(config, subsystem)
        present = field in section
        value = section.get(field, default)
        source = 'config' if present else 'default'
        if not readable or managed_active or (isinstance(value, str) and '${' in value):
            value, source = None, 'could_not_verify'
        elif isinstance(default, bool):
            if field == 'write_approval':
                # Hermes hermes_cli/config_migrations.py:397-416: legacy write_mode migrates to
                # write_approval on next start; do not report as unattended while unmigrated.
                if 'write_mode' in section and not present:
                    value, source = None, 'could_not_verify'
                elif isinstance(value, bool):
                    pass
                elif type(value) is int and value == 0:
                    value = False
                elif isinstance(value, str) and value.strip().lower() in APPROVAL_TRUTHY:
                    value = True
                elif isinstance(value, str) and value.strip().lower() in APPROVAL_FALSY:
                    value = False
                else:
                    value, source = None, 'could_not_verify'
            else:
                if isinstance(value, bool):
                    pass
                elif type(value) is int and value in (0, 1):
                    value = bool(value)
                elif isinstance(value, str) and value.strip().lower() in MEMORY_TRUTHY:
                    value = True
                elif isinstance(value, str) and value.strip().lower() in MEMORY_FALSY:
                    value = False
                else:
                    value, source = None, 'could_not_verify'
        else:
            try:
                value = int(value)
            except (TypeError, ValueError, OverflowError):
                value, source = None, 'could_not_verify'
        settings[key] = {'value': value, 'source': source}
    return settings


def _resolve_tool_selection(config, readable, managed_active):
    # Hermes hermes_cli/tools_config.py:580-616,631-642: CLI platform selection and global
    # denylist; runtime/plugin expansions deliberately unknown. Other surfaces may differ.
    platforms = _section(config, 'platform_toolsets')
    enabled = _names(platforms.get('cli', ['hermes-cli']))
    disabled = _names(_section(config, 'agent').get('disabled_toolsets', []))
    tool_source = 'could_not_verify' if managed_active else ('config' if 'cli' in platforms else 'default')
    tool_unknown = not readable or managed_active or enabled is None or disabled is None
    tools, deny = set(), set()
    for names, target in ((enabled or [], tools), (disabled or [], deny)):
        for name in names:
            if name in WRITE_TOOLSETS:
                target.update(WRITE_TOOLSETS[name])
            elif name not in INERT_TOOLSETS:
                tool_unknown = True
    tools -= deny
    availability = {name: (None if tool_unknown else name in tools) for name in ('skill_manage', 'memory')}
    return enabled, disabled, tool_source, tool_unknown, availability


def audit_write_settings(*, profile_path, hygiene=None, managed_dir=None):
    root = Path(profile_path)
    managed_active = _has_managed_overlay(managed_dir)
    config, readable, config_reason = _read_settings_config(root, managed_active)
    settings = _resolve_settings(config, readable, managed_active)
    enabled, disabled, tool_source, tool_unknown, availability = _resolve_tool_selection(
        config, readable, managed_active)
    flags = [settings[k]['value'] for k in ('memory.memory_enabled', 'memory.user_profile_enabled')]
    memory_on = True if True in flags else (None if None in flags else False)

    def unattended(available, on, gate):
        if available is False or on is False or gate is True:
            return False
        if None in (available, on, gate):
            return None
        return True

    skill_on = unattended(availability['skill_manage'], True, settings['skills.write_approval']['value'])
    memory_write = unattended(availability['memory'], memory_on, settings['memory.write_approval']['value'])
    # Hermes agent/agent_init.py:1254-1278; plugins/memory/__init__.py:1-7:
    # one external provider is configured by name, not proof it is installed or active.
    provider = _section(config, 'memory').get('provider', '')
    configured = isinstance(provider, str) and provider.strip().lower() not in CORE_PROVIDERS
    provider_unknown = not readable or managed_active or not isinstance(provider, (str, type(None))) or (isinstance(provider, str) and '${' in provider)
    external = {'configured': None if provider_unknown else configured,
                'provider': serialize_evidence(provider.strip()) if configured and not provider_unknown else None,
                'measured': False, 'coverage': 'could_not_verify' if configured or provider_unknown else 'verified'}
    findings = []
    for rule, active, gate_key in (('write_settings.unattended_skill_writes', skill_on, 'skills.write_approval'),
                                   ('write_settings.unattended_memory_writes', memory_write, 'memory.write_approval')):
        if active:
            findings.append(_finding(rule, root / 'config.yaml', {'enabled': True,
                'source': settings[gate_key]['source'], 'approval_enabled': False}))
    if configured and not provider_unknown:
        evidence = {'configured': True, 'measured': False}
        if provider.strip() in KNOWN_EXTERNAL_MEMORY_PROVIDERS:
            evidence['provider'] = provider.strip()
        findings.append(_finding('write_settings.external_memory_provider', root / 'config.yaml', evidence, 'could_not_verify'))
    drift = hygiene or {}
    candidates = [r for r in drift.get('skills', [])
                  if isinstance(r, dict) and not r.get('verified_unmodified', False)]
    prior_reasons = {
        'bundled_modified': drift.get('bundled_modified', 0),
        'hub_modified': drift.get('hub_modified', 0),
        'residue_skills': drift.get('residue_skills', 0),
        'machine_path_skills': sum(bool(r.get('machine_paths')) for r in candidates),
        'network_identity_skills': sum(bool(r.get('network_identities')) for r in candidates),
    }
    mod_skills = drift.get('modified_skills')
    if isinstance(mod_skills, list):
        correlated_residue = sum(1 for r in mod_skills if isinstance(r, dict) and r.get('residue_score', 0) >= RESIDUE_THRESHOLD)
    else:
        correlated_residue = drift.get('residue_skills', 0)
    if skill_on and drift.get('bundled_modified', 0) > 0 and correlated_residue > 0:
        findings.append(_finding('skill_hygiene.unattended_writes_with_drift', root / 'skills',
            {'unattended_skill_writes': 1, 'bundled_modified': drift['bundled_modified'],
             'residue_skills': drift.get('residue_skills', correlated_residue)}, classification='warning'))
    elif settings['skills.write_approval']['value'] is True and any(prior_reasons.values()):
        findings.append(make_finding(
            rule_id=APPROVAL_PRIOR_DRIFT_RULE,
            classification='review_suggested',
            coverage='verified',
            affected_identities=[str(root / 'skills')],
            source_paths=[str(root / 'skills')],
            evidence={
                'approval_enabled': True,
                **prior_reasons,
            },
            consequence=APPROVAL_PRIOR_DRIFT_CONSEQUENCE,
        ))
    unknown = not readable or managed_active or tool_unknown or provider_unknown or any(s['source'] == 'could_not_verify' for s in settings.values())
    if unknown:
        findings.append(_finding('write_settings.could_not_verify', root / 'config.yaml', {'reason': config_reason}, 'could_not_verify'))
    section = {'profile_path': str(root), 'settings': settings,
               'coverage': 'could_not_verify' if unknown or configured else 'verified',
               'unattended_skill_writes': skill_on, 'unattended_memory_writes': memory_write,
               'external_memory_provider': external,
               'tool_selection': {'source': tool_source, 'surface': 'cli', 'availability': availability,
                                  'enabled_toolsets': serialize_evidence(enabled), 'disabled_toolsets': serialize_evidence(disabled)},
               # Hermes tools/memory_tool.py:185-219: background patch/remove staged even with gate off.
               'background_memory_destructive_writes_gated': True,
               # No periodic flush setting found in agent_init.py, config_defaults.py, memory_tool*.py.
               # Provider pre-compression hooks exist: agent/conversation_compression.py:2885-2918.
               'flush_interval': {'value': None, 'source': 'not_found'},
               'limits': {'max_file_bytes': MAX_CONFIG_BYTES, 'cuts': int(not readable)}}
    return make_component_envelope(findings=findings, coverage=section['coverage'], extra={'write_settings': section})
