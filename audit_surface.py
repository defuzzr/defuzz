"""Manual, read-only audit product adapter over the existing audit engine.

Only the plugin database is written. No cleanup executor is exposed. Incomplete
collectors remain explicitly unknown, never represented as clean empty results.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .audit import context_load, facts, skill_hygiene, write_settings, session_contamination, bounded_call
from .audit import (home_workdirs, secret_file_copies, dead_stores, profile_duplicates, skill_ledger,
                    skill_packs, unattended_exposure, memory_load, kanban_residue)
from .audit.evidence_wiring import WIRED_SECTIONS
from .audit.contract import adapt_component_result, make_component_envelope, make_finding
from .audit.capture import capture_project_files
from .audit.store import AuditStore
from .audit.vendor import profile_context, memory, executable_inventory, template_drift, static_code

from .audit.evidence_constants import AUDIT_SCOPE_DISCLOSURE


def audit_scope_payload():
    from .audit.evidence import serialize_evidence
    return serialize_evidence({'scope_disclosure': AUDIT_SCOPE_DISCLOSURE})


SCHEMA = {
    'name': 'defuzz_audit',
    'description': AUDIT_SCOPE_DISCLOSURE,
    'parameters': {'type': 'object', 'properties': {
        'action': {'type': 'string', 'enum': ['run', 'status', 'report', 'cancel', 'resume']},
        'run_id': {'type': 'string'}, 'root': {'type': 'string', 'description': 'Select one project as the root of a full outward static trace.'},
        'selected_projects': {'type': 'array', 'items': {'type': 'string'}},
        'full_home': {'type': 'boolean', 'description': 'Compatibility flag; full outward capture is already the default.'},
        'sessions': {'type': 'boolean', 'default': False, 'description': 'Opt in to bounded private session transcript metrics; no source text is retained.'},
        'quick': {'type': 'boolean', 'description': 'Explicit opt-in to incomplete bounded capture.'},
        'max_entries': {'type': 'integer', 'minimum': 1},
        'max_bytes': {'type': 'integer', 'minimum': 1},
        'max_file_bytes': {'type': 'integer', 'minimum': 1}, 'component_budget_s': {'type': 'number', 'exclusiveMinimum': 0}, 'audit_budget_s': {'type': 'number', 'exclusiveMinimum': 0},
        'unbounded': {'type': 'boolean', 'description': 'Explicitly disable outward resource budgets; component capture limits still apply.'},
        'as_of': {'type': 'integer'}, 'unused_threshold_days': {'type': 'integer', 'minimum': 1}},
        'required': ['action'], 'additionalProperties': False},
}
_RUN_LOCK = threading.Lock()
_STATE_LOCK = threading.Lock()


def _unknown(component, identity, reason):
    finding = make_finding(rule_id=f'{component}.unverified', classification='review_suggested',
                           coverage='could_not_verify', affected_identities=[identity],
                           consequence=reason, limitations='Read-only static coverage; no execution or network.')
    return adapt_component_result(make_component_envelope(coverage='could_not_verify', findings=[finding]), component_id=component)


def _component(component, identity, fn, **kwargs):
    try:  # bounded_call.invoke: a killable child under the hard time budget (audit/bounded_call.py)
        return adapt_component_result(bounded_call.invoke(fn, kwargs), component_id=component, affected_identities=[identity])
    except Exception as exc:  # Never echo exception values (secrets); a child timeout/crash gets a fixed sentence.
        return _unknown(component, identity, bounded_call.sentence(component, exc.kind) if isinstance(exc, bounded_call.BudgetExceeded)
                        else f'Collector failed ({type(exc).__name__}); this check could not be verified.')


def _wired_component(component, identity, fn, **kwargs):
    """Like _component, but a raising collector reports <component>.operational_error.

    The exception type is named in the in-memory envelope only; persistence stores the
    rule's fixed sentence and drops the message, so exception values never reach the report.
    """
    try:
        result = adapt_component_result(bounded_call.invoke(fn, kwargs), component_id=component, affected_identities=[identity])
        # A section that is not plain finite JSON (NaN, a cycle, an object) must not abort the run later.
        json.dumps(result, allow_nan=False)
        return result
    except Exception as exc:
        if isinstance(exc, bounded_call.BudgetExceeded):  # child timeout/crash: the fixed sentence, no child text
            return _unknown(component, identity, bounded_call.sentence(component, exc.kind))
        return adapt_component_result(make_component_envelope(error=f'Collector failed ({type(exc).__name__})'),
                                      component_id=component, affected_identities=[identity])


def _hermes_home_root(profile_path):
    """The Hermes home that contains profiles/: two levels up for a named profile."""
    path = Path(profile_path)
    return path.parent.parent if path.parent.name == 'profiles' else path


def _prompt_injecting_plugins(section):
    """Enabled plugins declaring a prompt-injecting hook, from the unattended_exposure section.

    Plugin directory paths stand in for names: memory_load only counts them. Returns None
    (unknown) unless the section was fully verified and every such plugin's state is known; an empty home has none.
    """
    if not isinstance(section, dict) or section.get('status') != 'completed' or section.get('coverage') != 'verified':
        return [] if isinstance(section, dict) and (section.get('status'), section.get('reason')) == ('not_measured', 'empty') else None
    plugins = section.get('plugins')
    hook_plugins = plugins.get('hook_plugins') if isinstance(plugins, dict) else None
    if not isinstance(hook_plugins, list):
        return None
    found = []
    for index, plugin in enumerate(hook_plugins):
        if not isinstance(plugin, dict):
            return None
        if not set(plugin.get('hooks') or ()) & unattended_exposure.PROMPT_INJECTING_HOOKS:
            continue
        if plugin.get('enabled') is None:
            return None
        if plugin.get('enabled') is True:
            found.append(str(plugin.get('path') or f'hook_plugin_{index}'))
    return found


def _project_families(roots):
    """family -> number of projects using it.

    None when there are no projects to compare with; False (the memory check reads it as
    input_unknown) when the project list or a project folder could not be fully read.
    """
    if roots is None:
        return False
    if not roots:
        return None
    counts = {}
    for root in roots:
        families, status, cut = session_contamination._project(root)
        if status != 'verified':
            if status != 'could_not_verify' or families or cut or not _listable(root):
                return False
            continue  # read in full, no known technology: nothing to compare with
        for family in families:
            counts[family] = counts.get(family, 0) + 1
    return counts or None


def _listable(root):
    try:
        with os.scandir(root):
            return True
    except (OSError, TypeError, ValueError):
        return False


# Wired sections, in call order (WIRED_SECTIONS): entry point and the plain description
# used when a bounded audit does not collect the section.
_WIRED = {
    'home_workdirs': (home_workdirs.audit_home_workdirs, 'work folders and large files in the home'),
    'secret_file_copies': (secret_file_copies.audit_secret_file_copies, 'copies of secret-named files'),
    'dead_stores': (dead_stores.audit_dead_stores, 'unused plugin data, caches, backups and logs'),
    'profile_duplicates': (profile_duplicates.audit_profile_duplicates, 'duplicated files across profiles'),
    'skill_ledger': (skill_ledger.audit_skill_ledger, 'the skill change ledger'),
    'skill_packs': (skill_packs.audit_skill_packs, 'installed skill packs and skill use'),
    'unattended_exposure': (unattended_exposure.audit_unattended_exposure, 'unattended approval and scheduling settings'),
    'memory_load': (memory_load.audit_memory_load, 'memory file load'),
    'kanban_residue': (kanban_residue.audit_kanban_residue, 'kanban board residue'),
}
assert tuple(_WIRED) == WIRED_SECTIONS


def _wired_kwargs(name, profile_path, *, as_of, sections, project_roots):
    """Arguments per audit/wiring/<name>.json `kwargs`."""
    if name in ('profile_duplicates', 'kanban_residue'):
        # Both measure the shared Hermes home (profiles/ and kanban live there).
        return {'profile_path': str(_hermes_home_root(profile_path))}
    if name == 'dead_stores':
        return {'profile_path': profile_path, 'now': as_of}  # `now` feeds run_metrics only
    if name == 'skill_packs':
        return {'profile_path': profile_path, 'host_platform': None}
    if name == 'memory_load':
        return {'profile_path': profile_path,
                'prompt_injecting_plugins': _prompt_injecting_plugins(sections.get('unattended_exposure')),
                'project_families': _project_families(project_roots)}
    return {'profile_path': profile_path}


def _run_metrics(result):
    metrics = result.get('run_metrics')
    if not isinstance(metrics, dict):
        return None
    return {str(k): v for k, v in metrics.items() if v is None or type(v) in (int, float, bool)}


def _public_run(run):
    # Internal fingerprints and raw captured evidence are not a response surface.
    return {**{k: run.get(k) for k in ('run_id', 'status', 'as_of', 'canonical_digest', 'report')},
            **audit_scope_payload()}


def _persist_proposals(store, run_id, identity, digest, results):
    for result in results:
        for finding in result.get('findings', []):
            proposed = finding.get('proposed_cleanup_id')
            if not proposed:
                continue
            cleanup_id = hashlib.sha256(f'{run_id}\0{identity}\0{proposed}'.encode()).hexdigest()
            store.record_cleanup_proposal(cleanup_id=cleanup_id, run_id=run_id,
                fix_type=str(proposed), target_identity=identity, fingerprint_digest=digest,
                plan={'finding_id': finding['id'], 'consequence': finding['consequence'],
                      'execution_available': False}, selected=False)


def _active_inventory(as_of, threshold):
    """Capture only the active profile and its registrations, never sibling profiles."""
    from hermes_constants import get_hermes_home
    from .audit.readonly_db import read_profile_registrations_readonly
    home = Path(get_hermes_home()).absolute()
    active = facts.resolve_active_profile_name()
    # Planning reads only bounded registration metadata. Content capture and all
    # vendor collectors run after the persisted ID is returned to the client.
    snapshot = read_profile_registrations_readonly(active, home)
    profile = {'name': active, 'path': str(home), 'is_default': active == 'default',
               'is_active': True, 'coverage': snapshot.coverage}
    registrations = facts.union_profile_registrations([snapshot])
    if snapshot.error == 'credential_store_not_opened':
        registrations['findings'].append(make_finding(
            rule_id='inventory.registration_db_unreadable', classification='review_suggested',
            coverage='could_not_verify', affected_identities=[active],
            consequence='Registration inventory excluded by credential policy.',
            evidence={'reason': 'credential_store_not_opened'}))
    return {'active_profile': active, 'profile_units': [profile],
            'project_units': registrations['project_units'],
            'all_registration_records': registrations['all_records'],
            'coverage': profile['coverage'], 'findings': registrations['findings']}


from .audit import key as _audit_key
from .audit.key import using_store_key, private_paths, AuditKeyUnavailable


@using_store_key
def _prepare(store, args, previous=None):
    for key in ('max_entries', 'max_bytes', 'max_file_bytes'):
        if key in args and (type(args[key]) is not int or args[key] < 1):
            raise ValueError(f'{key} must be a positive integer')
    if 'unbounded' in args and type(args['unbounded']) is not bool:
        raise ValueError('unbounded must be a boolean')
    if any(not isinstance(args[key], bool) for key in ('quick', 'full_home') if key in args):
        raise ValueError('quick and full_home must be booleans')
    if 'sessions' in args and type(args['sessions']) is not bool:
        raise ValueError('sessions must be a boolean')
    if args.get('quick') and args.get('full_home'):
        raise ValueError('Use quick or full_home, not both')
    full_home = previous['mode'] != 'bounded' if previous else not args.get('quick', False)
    as_of = previous['as_of'] if previous else args.get('as_of', int(time.time()))
    threshold = previous['unused_threshold_days'] if previous else args.get('unused_threshold_days', 90)
    if isinstance(as_of, bool) or not isinstance(as_of, int) or isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError('as_of must be an integer and unused_threshold_days a positive integer')
    root = previous['optional_root'] if previous else args.get('root')
    # Declarations must precede even registration planning and active pointers.
    from hermes_constants import get_hermes_home
    from .audit.policy import credential_declarations
    profile_root = Path(get_hermes_home()).absolute()
    audited_home = profile_root.parent.parent.parent if profile_root.parent.name == 'profiles' else profile_root.parent
    credential_declarations(profile_root, audited_home)
    candidates = [root] if root is not None else args.get('selected_projects', [])
    if isinstance(candidates, list):
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                credential_declarations(Path(candidate).expanduser(), audited_home)
    inventory = _active_inventory(as_of, threshold)
    profiles, projects = inventory['profile_units'], inventory['project_units']
    if previous:
        from .audit.persistence import control_digest as digest
        if previous['inventory'].get('active_profile_control') != digest(inventory['active_profile']):
            raise ValueError('Resume requires the original active profile')
        saved = {u['unit_control_id'] for u in previous['units'] if u['unit_kind'] == 'project'}
        candidates = {digest(p['canonical_path']): p['canonical_path'] for p in projects}
        if saved - candidates.keys():
            raise ValueError('resume_project_not_registered')
        # Display IDs may be sealed unresolved paths; only the current registry
        # can supply source paths. Never interpret serialized evidence as input.
        selected = [candidates[identity] for identity in saved]
    else:
        selected = args.get('selected_projects', [])
        if selected is None:
            selected = []
        if root is not None:
            if args.get('selected_projects') is not None:
                raise ValueError('Use root or selected_projects, not both')
            selected = [root]
    if selected is not None:
        if not isinstance(selected, list) or any(not isinstance(p, str) or not p.strip() for p in selected):
            raise ValueError('selected_projects must be an array of non-empty paths')
        selected = {str(Path(p).expanduser().resolve()) for p in selected}
        registered = {p['canonical_path'] for p in projects}
        if selected - registered:
            raise ValueError('Selected project is not registered in the active profile')
        projects = [p for p in projects if p['canonical_path'] in selected]
    units = [{'unit_kind': 'profile', 'unit_id': p['name'],
              'required_components': ['profile_context', 'context_load', 'memory', 'executable_inventory',
                                      'skill_hygiene', 'write_settings', 'session_contamination',
                                      *WIRED_SECTIONS],
              'required_collectors': ['profile_capture', 'registrations']} for p in profiles]
    units += [{'unit_kind': 'project', 'unit_id': p['canonical_path'],
               'required_components': ['template_drift', 'static_code', 'tools_lock'],
               'required_collectors': ['project_capture', 'template_capture']} for p in projects]
    # Persist only identities/coverage, never raw config or memory bodies.
    inventory['outward_options'] = (previous['inventory'].get('outward_options', {}) if previous else
        {key: args[key] for key in ('max_entries', 'max_bytes', 'max_file_bytes', 'unbounded') if key in args})
    inventory['sessions'] = previous['inventory'].get('sessions', False) if previous else args.get('sessions', False)
    safe_inventory = {'coverage': inventory['coverage'], 'units': units,
                      'sessions': inventory['sessions'],
                      'outward_options': inventory['outward_options']}
    # Complete the shared declaration pass before run identity, Git discovery,
    # or any ordinary content capture (including quick mode).
    from .audit.policy import credential_declarations
    for profile in profiles:
        profile_root = Path(profile['path'])
        audited_home = profile_root.parent.parent.parent if profile_root.parent.name == 'profiles' else profile_root.parent
        for declaration_root in [profile_root, *[Path(p['canonical_path']) for p in projects]]:
            credential_declarations(declaration_root, audited_home)
    if previous:
        run_id = previous['run_id']
        # Conservative resume: recapture every unit; no stale cross-unit epoch reuse.
        store.resume_run(run_id, current_unit_digests={(u['unit_kind'], u['unit_id']): None for u in units})
    else:
        run = store.create_run(as_of=as_of, active_profile=inventory['active_profile'],
                               mode='full_home' if full_home else 'bounded',
                               unused_threshold_days=threshold, optional_root=root,
                               inventory=safe_inventory, planned_units=units)
        run_id = run['run_id']
    return run_id, inventory, profiles, projects, as_of, threshold, full_home


from .audit.redaction import redaction_scope


def _tools_lock_result(identity, summary):
    """Wrap the static TOOLS.lock summary as the ``tools_lock`` component result.

    ``summary`` is the dict returned by ``tool_guard.static_lock_summary``: its
    ``coverage`` key becomes both the finding and component coverage, and the whole
    summary becomes the finding evidence (validation walks every key). Returns a
    §6-adapted component result carrying one ``tools_lock.static`` info finding. Performs
    no file I/O: the plain data ``static_lock_summary`` returns is validated as plain data.
    """
    lock_finding = make_finding(rule_id='tools_lock.static', classification='info', coverage=summary['coverage'],
        affected_identities=[identity], consequence='Static TOOLS.lock provenance; installed versions were not probed.', evidence=summary)
    return adapt_component_result(make_component_envelope(findings=[lock_finding], coverage=summary['coverage']), component_id='tools_lock')


def _scope_findings(inventory, outward):
    """Collect the audit-scope findings added on top of the per-unit results.

    Starts from ``inventory.get('findings', [])``. When ``outward`` is not None, adds one
    ``audit.scope.<region>`` finding per region (``info`` when coverage is
    ``verified``, else ``review_suggested``) and one ``audit.blending`` finding per
    evidenced relationship; otherwise adds one ``audit_scope.unverified``
    ``review_suggested`` finding with ``could_not_verify`` coverage (via ``_unknown``),
    because a quick audit leaves those regions uncollected.

    Returns a new list; ``inventory['findings']`` is not mutated. Does no reads or writes
    of its own, but validating sealed evidence can resolve/lstat the evidence paths and
    update the run's redaction taint.
    """
    extra = list(inventory.get('findings', []))
    if outward is not None:
        for name, region in outward['regions'].items():
            extra.append(make_finding(rule_id='audit.scope.' + name,
                classification='info' if region['coverage'] == 'verified' else 'review_suggested',
                coverage=region['coverage'], affected_identities=['system'],
                consequence='Static outward inspection: ' + name,
                evidence=region))
        for relationship in outward['blending']:
            extra.append(make_finding(rule_id='audit.blending', classification='review_suggested',
                coverage='verified', affected_identities=[value for value in
                    (relationship['source'], relationship['target']) if isinstance(value, str)],
                consequence='BLENDING: an evidenced reference; evidence.inspection distinguishes inspected targets from metadata-only declarations.',
                evidence=relationship))
    else:
        extra.extend(_unknown('audit_scope', 'system', 'Explicit quick audit: uncollected regions remain unknown.')['findings'])
    return extra


@redaction_scope
@using_store_key
@bounded_call.worker_scope(cancelled=lambda store, prepared: store.get_run(prepared[0])['status'] == 'cancelled')
def _sweep(store, prepared):
    run_id, inventory, profiles, projects, as_of, threshold, full_home = prepared
    from .audit.bounded import collect_profile
    registrations = inventory.get('all_registration_records', [])
    outward = None
    from .audit.policy import credential_declarations
    profile_root = Path(profiles[0]['path']) if profiles else None
    audited_home = (Path.home() if profile_root is None else
                    profile_root.parent.parent.parent if profile_root.parent.name == 'profiles' else profile_root.parent)
    for root in ([profile_root] if profile_root is not None else []) + [Path(p['canonical_path']) for p in projects]:
        credential_declarations(root, audited_home,
            excluded_paths=inventory.get('outward_options', {}).get('excluded_paths', ()))
    if full_home:
        from .audit.outward import collect_outward
        cancel_checks = 0
        cancellation_seen = False
        def cancelled():
            nonlocal cancel_checks, cancellation_seen
            cancel_checks += 1
            if cancel_checks % 100 == 1:
                cancellation_seen = cancellation_seen or store.get_run(run_id)['status'] == 'cancelled'
            return cancellation_seen
        outward = collect_outward(Path(profiles[0]['path']),
            [p['canonical_path'] for p in projects],
            report_store_paths=(store.db_path, str(store.db_path) + '-wal', str(store.db_path) + '-shm', *private_paths()),
            cancelled=cancelled, **inventory.get('outward_options', {}),
            unselected_project_roots=[p['canonical_path'] for p in inventory['project_units']
                if p['canonical_path'] not in {selected['canonical_path'] for selected in projects}])
    context_load_section = (
        context_load.unverified_context_load('profile_context_unverified')
        if full_home
        else context_load.unverified_context_load('bounded_quick_audit_not_collected')
    )
    skill_hygiene_section = dict(context_load_section)
    write_settings_section = dict(context_load_section)
    session_section = (dict(context_load_section) if not full_home else
                       {'status': 'not_run', 'coverage': 'not_included'})
    wired_sections = {name: {**context_load_section, 'status': 'not_measured'} for name in WIRED_SECTIONS}
    run_metrics = {}
    for index, profile in enumerate(profiles):
        if store.get_run(run_id)['status'] == 'cancelled':
            return _public_run(store.get_run(run_id))
        identity = profile['name']
        profile = (facts.collect_profile_unit_facts if full_home else collect_profile)(
            profile_name=identity, profile_dir=Path(profile['path']),
            is_default=profile['is_default'], is_active=True,
            descendant_profile_roots=[Path(profile['path']) / 'profiles',
                *[Path(p['canonical_path']) for p in inventory['project_units']
                  if p['canonical_path'] not in {selected['canonical_path'] for selected in projects}]],
            as_of=as_of, unused_threshold_days=threshold)
        if store.get_run(run_id)['status'] == 'cancelled':
            return _public_run(store.get_run(run_id))
        if full_home:
            limit_info = context_load.resolve_context_file_max_chars(profile.get('config'))
            max_chars = limit_info['value']
            sanitized_profile = context_load.sanitize_profile_facts_for_context(profile, max_chars)
            project_contexts = []
            for p in projects:
                p_root = p['canonical_path']
                try:
                    project_contexts.append(
                        facts.resolve_project_context_chain_facts(p_root, context_max_chars=max_chars)
                    )
                except Exception:
                    project_contexts.append({
                        'project_root': p_root,
                        'cwd': p_root,
                        'coverage': 'could_not_verify',
                        'winning_kind': None,
                        'total_injected_chars': 0,
                        'estimated_tokens': 0,
                        'files': [],
                    })
            profile_ctx_res = _component(
                'profile_context', identity, profile_context.audit_profile_context,
                profile_facts=sanitized_profile, project_contexts=project_contexts,
                context_file_max_chars=max_chars,
            )
            ctx_load_res = _component(
                'context_load', identity, context_load.audit_context_load,
                profile_facts=sanitized_profile, profile_context_result=profile_ctx_res,
                project_contexts=project_contexts,
            )
            if isinstance(ctx_load_res.get('context_load'), dict):
                context_load_section = ctx_load_res['context_load']
            else:
                context_load_section = context_load.unverified_context_load('collector_failed')
        else:
            profile_ctx_res = _unknown(
                'profile_context', identity,
                'Bounded audit: skills, plugins, session history and whole-profile identity were not collected.',
            )
            ctx_load_res = _unknown(
                'context_load', identity,
                'Bounded audit: static context load and project context chains were not collected.',
            )
            context_load_section = context_load.unverified_context_load('bounded_quick_audit_not_collected')
        hygiene_res = (_component('skill_hygiene', identity, skill_hygiene.audit_skill_hygiene,
                                  profile_path=profile['path']) if full_home else
                       _unknown('skill_hygiene', identity, 'Bounded audit: skill hygiene was not collected.'))
        skill_hygiene_section = hygiene_res.get('skill_hygiene', skill_hygiene_section)
        settings_res = (_component('write_settings', identity, write_settings.audit_write_settings,
                                   profile_path=profile['path'], hygiene=skill_hygiene_section) if full_home else
                        _unknown('write_settings', identity, 'Bounded audit: write settings were not collected.'))
        write_settings_section = settings_res.get('write_settings', write_settings_section)
        if full_home:
            session_res = _component('session_contamination', identity,
                                     session_contamination.audit_session_contamination,
                                     profile_path=profile['path'], sessions=inventory['sessions'],
                                     selected_projects=[p['canonical_path'] for p in (projects or inventory['project_units'])])
            session_section = session_res.get('session_contamination',
                                             context_load.unverified_context_load('collector_failed'))
        else:
            session_res = _unknown('session_contamination', identity, 'Bounded audit: session transcripts were not collected.')
        wired_results = []
        for name, (entry, description) in _WIRED.items():
            if store.get_run(run_id)['status'] == 'cancelled':
                return _public_run(store.get_run(run_id))
            if full_home:
                res = _wired_component(name, identity, entry, **_wired_kwargs(
                    name, profile['path'], as_of=as_of, sections=wired_sections,
                    project_roots=[p['canonical_path'] for p in (projects or inventory['project_units'])]
                    or (None if inventory['coverage'] != 'verified' else [])))
                section = res.get(name)
                wired_sections[name] = (section if isinstance(section, dict) else
                                        {**context_load.unverified_context_load('collector_failed'),
                                         'status': 'not_measured'})
                metrics = _run_metrics(res)
                if metrics is not None:
                    run_metrics[name] = metrics
            else:
                res = _unknown(name, identity, f'Bounded audit: {description} was not collected.')
            wired_results.append(res)
        results = [
            *wired_results,
            session_res,
            settings_res,
            hygiene_res,
            profile_ctx_res,
            ctx_load_res,
            _component('memory', identity, memory.audit_profile_memory, profile_name=identity,
                       memory_facts=profile['memory'], registered_projects=registrations, as_of=as_of),
            (_component('executable_inventory', identity, executable_inventory.audit_executable_inventory,
                       inputs={'profiles': [{'profile': identity, 'profile_dir': profile['path'],
                                'config_data': profile['config'], 'plugin_manifests': profile['plugins'],
                                'coverage': profile['coverage']}]}, entry_security_check=facts.resolve_mcp_entry_security_check())
             if full_home else _unknown('executable_inventory', identity, 'Bounded audit: recursive executable/plugin inventory was not collected.')),
        ]
        manifest = profile['fingerprint_manifest']
        evidence = {k: profile[k] for k in ('unit_kind', 'name', 'is_default', 'is_active', 'coverage', 'last_use_evidence')}
        evidence['collectors'] = {'profile_capture': {'coverage': profile['coverage']},
                                  'registrations': {'coverage': profile['registrations_snapshot']['coverage']}}
        store.commit_unit_result(run_id=run_id, unit_kind='profile', unit_id=identity,
                                 manifest=manifest, evidence=evidence, component_results=results, sort_order=index)
        _persist_proposals(store, run_id, identity, manifest.get('unit_digest', ''), results)
    import os
    from . import templates
    from .audit.contract import resolve_runtime_golden_registry
    from .tool_guard import static_lock_summary
    # Two constraints from tests/test_audit_open_sites_recheck.py keep this code in _sweep:
    # (1) credential_path must be called directly from _sweep: the test's _caller_name() pins
    #     sys._getframe(2).f_code.co_name == '_sweep' on the wrapped call, so a helper caller
    #     would hide the site. (2) `specs` and `invalid_templates` must stay _sweep locals bound
    #     before the first project-loop store.get_run: the test's stub get_run reads
    #     sys._getframe(1).f_locals (the frame calling store.get_run) to stop the sweep once
    #     templates are loaded.
    from .audit.policy import credential_path
    from .audit.fingerprint import CredentialStoreNotOpened, open_checked
    specs, invalid_templates = {}, {}
    if projects:
        registry = resolve_runtime_golden_registry()
        if not registry['available'] and registry.get('reason') and registry['reason'] != 'templates_root_excluded_by_credential_policy':
            invalid_templates['*'] = str(registry['reason'])
        try:
            base = Path(templates.templates_root())
            entries = sorted(base.iterdir(), key=lambda p: p.name) if base.exists() and not base.is_symlink() and base.is_dir() else ()
        except OSError as exc:
            entries, invalid_templates['*'] = (), type(exc).__name__
        cached_specs = registry['specs']
        cached_invalid = registry['invalid_ids']
        for entry in entries:
            if credential_path(entry) or credential_path(entry / 'template.yaml'):
                continue
            try:
                if entry.is_symlink() or not entry.is_dir() or not os.path.lexists(entry / 'template.yaml'):
                    continue
                if entry.name in cached_specs:
                    spec = cached_specs[entry.name]
                elif entry.name in cached_invalid:
                    invalid_templates[entry.name] = cached_invalid[entry.name]
                    continue
                else:
                    # The opened template.yaml is checked again before a byte is read.
                    spec = templates.load_template(entry, opener=open_checked)
                specs[spec.id] = spec
            except CredentialStoreNotOpened:
                continue  # left out, like a declared template.yaml
            except (templates.TemplateError, OSError, ValueError) as exc:
                invalid_templates[entry.name] = type(exc).__name__
        for sid, extra_spec in cached_specs.items():
            specs.setdefault(sid, extra_spec)
    for index, project in enumerate(projects, len(profiles)):
        if store.get_run(run_id)['status'] == 'cancelled':
            return _public_run(store.get_run(run_id))
        identity = project['canonical_path']
        records = project.get('registrations') or project.get('records') or []
        provenance = records[0] if records else project
        template_id = provenance.get('template_id')
        spec = specs.get(template_id)
        if spec is not None and (credential_path(spec.root) or credential_path(spec.root / 'template.yaml')):
            spec = None
        template_error = invalid_templates.get(template_id) or invalid_templates.get('*')
        manifest, project_files = capture_project_files(identity)
        template_manifest = {'coverage': 'could_not_verify'}
        results = []
        if spec is None:
            reason = (f'Template manifest invalid ({template_error}); this check could not be verified.'
                      if template_error else 'Template provenance is missing or unrecognized.')
            results.extend([_unknown(c, identity, reason) for c in ('template_drift', 'static_code')])
        else:
            spec_data = {'id': spec.id, 'placeholder': spec.placeholder,
                         'locked': list(spec.locked), 'approved_deps': dict(spec.approved_deps)}
            # Resolve multi-repository provenance without guessing.
            repo_name = provenance.get('template_repo') or provenance.get('repo_name')
            repo = next((repo for repo in spec.repos if repo.name == repo_name), None)
            if repo is None and len(spec.repos) == 1:
                repo = spec.repos[0]
            template_root = spec.root / repo.name if repo else spec.root / '__unknown_repository__'
            if credential_path(template_root) or credential_path(template_root / 'template.yaml'):
                results.extend([_unknown(c, identity, 'Template provenance is missing or unrecognized.') for c in ('template_drift', 'static_code')])
            else:
                template_manifest, template_files = capture_project_files(template_root)
                captured = dict(provenance=provenance, project_id=identity, project_files=project_files,
                                template_spec=spec_data, template_files=template_files)
                results.append(_component('template_drift', identity, template_drift.audit_template_drift, **captured))
                results.append(_component('static_code', identity, static_code.audit_static_code, **captured))
        summary = static_lock_summary(identity, db_path=store.db_path)
        results.append(_tools_lock_result(identity, summary))
        template_collector = {'coverage': template_manifest['coverage']}
        if spec is None and template_error:
            template_collector['reason'] = 'structured_data_parse_failed'
        store.commit_unit_result(run_id=run_id, unit_kind='project', unit_id=identity, manifest=manifest,
                                 evidence={'coverage': project.get('coverage', 'could_not_verify'),
                                           'collectors': {'project_capture': {'coverage': manifest['coverage']},
                                                          'template_capture': template_collector}},
                                 component_results=results, sort_order=index)
        _persist_proposals(store, run_id, identity, manifest.get('unit_digest', ''), results)
    extra = _scope_findings(inventory, outward)
    with _STATE_LOCK:
        if store.get_run(run_id)['status'] == 'cancelled':
            return _public_run(store.get_run(run_id))
        # run_metrics (timings, budget hits) differ per run: returned to this caller only,
        # never part of the sealed report or any finding.
        return {**store.finalize_run(run_id, extra_findings=extra, outward=outward, context_load=context_load_section,
                                     measurements={'skill_hygiene': skill_hygiene_section,
                                                   'write_settings': write_settings_section,
                                                   'session_contamination': session_section,
                                                   **wired_sections}),
                'run_metrics': run_metrics,
                **audit_scope_payload()}


@redaction_scope
@bounded_call.budget_arguments
def execute_audit(args: dict[str, Any], *, db_path=None, wait=False, sessions: bool = False):
    if type(sessions) is not bool:
        raise ValueError('sessions must be a boolean')
    args = {**args, 'sessions': args.get('sessions', sessions)}
    action = args.get('action', 'run')
    if action not in ('run', 'status', 'report', 'cancel', 'resume'):
        raise ValueError('Unsupported audit action; cleanup execution is not available')
    store = AuditStore(db_path)
    previous = None
    if action != 'run':
        run_id = args.get('run_id')
        if not isinstance(run_id, str) or not run_id:
            raise ValueError('run_id is required')
        previous = store.get_run(run_id)
        if previous is None:
            raise KeyError('Unknown audit run_id')
        if action == 'resume' and not store.resume_key_available(previous['inventory']):
            return {**_public_run(previous), 'resume_reason': 'audit_key_unavailable'}
        if action in ('status', 'report'):
            return _public_run(previous)
        if action == 'cancel':
            with _STATE_LOCK:
                if store.get_run(run_id)['status'] == 'running':
                    store.cancel_run(run_id)
                return _public_run(store.get_run(run_id))
    if not _RUN_LOCK.acquire(blocking=False):
        raise ValueError('An audit is already running')
    try:
        prepared = _prepare(store, args, previous)
        initial = _public_run(store.get_run(prepared[0]))
    except (AuditKeyUnavailable, _audit_key.AuditKeyUnavailable):
        _RUN_LOCK.release()
        if previous:
            return {**_public_run(previous), 'resume_reason': 'audit_key_unavailable'}
        return {'status': 'failed', 'reason': 'audit_key_unavailable', **audit_scope_payload()}
    except BaseException:
        _RUN_LOCK.release()
        raise

    def work():
        try:
            return _sweep(store, prepared)
        except Exception:
            # Persist failure, not exception text that could contain captured secrets.
            from contextlib import closing
            with _STATE_LOCK, closing(store._connect()) as conn, conn:
                conn.execute("UPDATE audit_runs SET status='failed', updated_at=? WHERE run_id=? AND status='running'",
                             (int(time.time()), prepared[0]))
            if wait:
                raise
        finally:
            _RUN_LOCK.release()

    if wait:
        return work()
    try:
        # At most one worker; no unbounded executor queue. Host shutdown interrupts
        # it safely; an explicit resume recaptures under the original as_of.
        # The durable profile audit key must still match the saved control IDs.
        from contextvars import copy_context
        context = copy_context()
        threading.Thread(target=lambda: context.run(work), name='defuzz-audit', daemon=True).start()
    except BaseException:
        store.cancel_run(prepared[0])
        _RUN_LOCK.release()
        raise
    return initial
