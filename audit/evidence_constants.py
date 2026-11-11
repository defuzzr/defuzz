"""Explicit report rule identifiers and scope labels (not source text)."""
from .evidence_wiring import WIRED_FINDING_CONSEQUENCES, WIRED_RULE_IDS

RULE_IDS = frozenset("""
session_contamination.foreign_memory_in_project session_contamination.system_prompt_growth
session_contamination.external_memory_injection_observed session_contamination.database_unreadable
session_contamination.schema_unsupported session_contamination.unverified
session_contamination.database_changed_during_read
write_settings.unattended_skill_writes write_settings.unattended_memory_writes
write_settings.external_memory_provider write_settings.could_not_verify write_settings.unverified
skill_hygiene.unattended_writes_with_drift skill_hygiene.approval_enabled_with_prior_drift
skill_hygiene.stock_skill_modified skill_hygiene.scratchpad_residue
skill_hygiene.machine_paths_in_skill skill_hygiene.oversized_skill_body skill_hygiene.network_identity_in_skill
skill_hygiene.duplicate_skill skill_hygiene.could_not_verify skill_hygiene.unverified
skill_hygiene.external_skill_dir_not_scanned
audit.blending audit.scope.active_profile audit.scope.credentials
audit.scope.cross_project_isolation audit.scope.dynamic_execution audit.scope.identity
audit.scope.other_projects audit.scope.plugins audit.scope.project_tree
audit.scope.session_history audit.scope.shared_infrastructure audit.scope.sibling_profiles
audit.scope.skills audit_scope.unverified
context_load.auto_loaded_skill_oversized context_load.external_memory_provider_unmeasured
context_load.fixed_prompt_oversized context_load.memory_oversized
context_load.operational_error context_load.parent_context_injected
context_load.per_turn_window_share context_load.persona_oversized
context_load.project_context_oversized context_load.project_context_truncated
context_load.project_context_unverified context_load.skills_index_oversized context_load.unverified
cross_checks.cross_project_editable_install
cross_checks.cross_project_symlink cross_checks.editable_install_unparseable
cross_checks.editable_install_unreadable cross_checks.editable_pth_dynamic_hook
cross_checks.incomplete_unit_manifest cross_checks.memory_duplicate_exact_across_profiles
cross_checks.memory_duplicate_whitespace_across_profiles
cross_checks.memory_entry_multi_project_overlap cross_checks.memory_project_multiple_entries
cross_checks.memory_project_overlap_across_profiles cross_checks.memory_symlink_shared
cross_checks.nested_repo cross_checks.nested_worktree
cross_checks.parent_context_blocked_by_git_boundary cross_checks.parent_context_injected
cross_checks.parent_context_shadowed cross_checks.profile_configuration_match
cross_checks.profile_regions_unverified cross_checks.skill_duplicate_Near_or_metadata_diff
cross_checks.skill_duplicate_exact cross_checks.symlink_git_entry
cross_checks.whole_profile_exact_duplicate cross_checks.worktree_pointer_broken
cross_checks.worktree_pointer_invalid executable_inventory.config_unverified
executable_inventory.hook_declaration_unverified
executable_inventory.hook_unsafe_path_or_command executable_inventory.mcp_declaration_unverified
executable_inventory.mcp_server_declaration executable_inventory.mcp_unsafe_declaration
executable_inventory.operational_error executable_inventory.outbound_webhook_declaration
executable_inventory.plugin_dynamic_registrations_unverified
executable_inventory.plugin_manifest executable_inventory.plugin_manifest_unverified
executable_inventory.plugin_world_writable executable_inventory.shell_hook_declaration
executable_inventory.unverified inventory.conflicting_profile_registrations
inventory.multi_profile_registration inventory.profile_enumeration_incomplete
inventory.registration_db_unreadable memory.ambiguous_project_mapping
memory.authoritative_entry_stale memory.cross_project_exposure memory.duplicate_entry_exact
memory.duplicate_entry_similar_whitespace memory.entry_age_unverified
memory.heuristic_operational_directive memory.operational_error memory.path_reference_unverified
memory.stale_missing_path memory.store_unreadable memory.symlink_store
memory.unrelated_operational_directive memory.unverified profile_context.auto_load_skill_skipped
profile_context.auto_load_skill_unverified profile_context.dynamic_contributions_unverified
profile_context.memory_exceeds_char_limit profile_context.memory_snapshot_drift
profile_context.memory_symlink_shared profile_context.memory_unreadable
profile_context.operational_error profile_context.shadowed_skills
profile_context.skills_inventory_incomplete profile_context.soul_truncated
profile_context.soul_unreadable profile_context.unverified static_code.approved_deps_unavailable
static_code.excess_nesting static_code.import_missing_from_lock
static_code.lockfile_missing_or_invalid static_code.not_included static_code.operational_error
static_code.stub_detected static_code.suppressions_above_baseline static_code.syntax_error
static_code.unapproved_dependency static_code.unmappable_import static_code.unreferenced_code
static_code.unverified static_code.unverified_file static_code.useless_try_catch
template.leftover_placeholder template.locked_file_missing template.locked_hash_drift
template.missing_file template.not_included template.provenance_missing
template.unreconstructable_baseline template.unverified_file template_drift.operational_error
template_drift.unverified tools_lock.operational_error tools_lock.static tools_lock.unverified
""".split()) | WIRED_RULE_IDS  # wired sections: generated from audit/wiring/*.json

AUDIT_SCOPE_DISCLOSURE = (
    "Default full audit traces outward references from selected/registered projects and the active profile; "
    "implicit HOME startup metadata and inputs are inspected, including credential-file metadata "
    "(.netrc, .pgpass, .git-credentials, Docker config, .npmrc and pip.conf). A05 is decided strict: "
    "credential files are never opened; only lstat kind, path, size, mode and mtime are recorded "
    "without following symlinks, with credential_store_not_opened coverage. "
    "Sibling profile declarations are considered, not a full sibling audit. "
    "Fixed declaration sources are read first: config.yaml, profiles/*/config.yaml, .git/config, "
    "settings.json, settings.toml, package.json, pyproject.toml, Cargo.toml, pnpm-workspace.yaml "
    "relative to audited profile/project roots and installed template directories. "
    "Declaring a declaration source as a credential has no effect; it remains readable as a source. "
    "Arbitrary files do not supply credential declarations. All other declared paths and Git include "
    "targets are metadata-only and never opened. "
    "Profile and selected-project declarations run before registration inventory; a declared registry DB "
    "is skipped with could_not_verify and credential_store_not_opened. A declared template.yaml "
    "is skipped by template loading with could_not_verify; declared directories are never traversed. "
    "Quick mode records encountered skipped-credential lstat metadata without expanding quick scope. "
    "No execution or cleanup; writes only to plugin data. Explicit quick mode is bounded and incomplete."
)

SCOPE_LABELS = frozenset({
    AUDIT_SCOPE_DISCLOSURE,
    'Git pointers/config/includes/hooks; object stores not traversed by Git-context edges',
    'active-profile owned regions',
    'bounded shell, Python, npm, Cargo, user-systemd and desktop-autostart inputs in audited HOME',
    'complete cross-project isolation',
    'dynamic execution',
    'explicit selections only',
    'path metadata only; historical association does not authorize traversal',
    'registered projects (or explicit selection)',
    'session history',
    'shared infrastructure',
    'sibling profiles',
    'top-level lstat and config.yaml declarations (including default); unrelated content not inspected',
    'top-level symlink metadata, sibling config declarations and evidenced blending regions only',
    'whole-profile identity',
})

DEFAULT_FINDING_CONSEQUENCE = "Static audit finding; review the referenced source."

FINDING_CONSEQUENCES: dict[str, str] = {
    'session_contamination.unverified': 'Session transcript metrics were not collected or could not be verified. Missing measurements do not establish an absence of cross-project memory.',
    'session_contamination.foreign_memory_in_project': 'Injected memory contains technology families absent from the current project inventory; occurrence counts are heuristic, not proof of incorrect advice.',
    'session_contamination.system_prompt_growth': 'The latest stored monthly system-prompt median exceeds both the relative and absolute growth thresholds.',
    'session_contamination.external_memory_injection_observed': 'Stored memory-context fences were observed; block counts and characters measure saved recall, not live provider state or proven origin.',
    'session_contamination.database_unreadable': 'Session metrics could not be verified without copying or writing the database; an unsafe path, a hot rollback journal, a busy or locked store, or a read error prevented inspection.',
    'session_contamination.database_changed_during_read': 'Counts may be off by the sessions written during the read.',
    'session_contamination.schema_unsupported': 'Session tables do not expose the supported static schema; no transcript metrics are claimed.',
    'write_settings.unattended_skill_writes': 'CLI skill writes are enabled with the approval gate off; source=default explicitly identifies reliance on the shipped default.',
    'write_settings.unattended_memory_writes': 'Memory writes made during a conversation (additions, edits and removals) apply without approval because the gate is off; source=default identifies the shipped default. Only destructive edits from background review are staged separately.',
    'write_settings.unverified': 'Write settings were not collected or could not be verified. Missing measurements do not establish that writes need approval.',
    'skill_hygiene.unverified': 'Skill measurements were not collected or could not be verified. Missing measurements do not establish that skills are unmodified.',
    'skill_hygiene.approval_enabled_with_prior_drift': 'Approval is on now, which stops new unattended writes, but it does not clean what was written before it was enabled; config cannot tell when approval was enabled, and existing skills still carry earlier changes or residue and need a manual look.',
    'write_settings.external_memory_provider': 'An external memory provider is configured; injected content cannot be measured statically. Opt in to session_contamination to measure stored injection blocks.',
    'write_settings.could_not_verify': 'Write settings or runtime tool selection cannot be resolved from bounded static config.',
    'skill_hygiene.unattended_writes_with_drift': 'Unattended skill writes, modified bundled skills and elevated residue coexist; their counts warrant review but do not establish causation.',
    'skill_hygiene.stock_skill_modified': 'Bundled skill differs from its recorded shipped hash; original size is unavailable, so growth cannot be measured.',
    'skill_hygiene.scratchpad_residue': 'Counted incident-log signals exceed the residue threshold; review reusable rules separately from historical context.',
    'skill_hygiene.network_identity_in_skill': 'Private network identities can carry machine-specific assumptions into later work.',
    'skill_hygiene.machine_paths_in_skill': 'Machine-specific path occurrences can carry unrelated workspace assumptions into later work.',
    'skill_hygiene.oversized_skill_body': 'Skill body characters exceed the static size review threshold.',
    'skill_hygiene.external_skill_dir_not_scanned': 'Configured external skill directories outside the authorized profile read boundary were not scanned; their contents remain unknown.',
    'skill_hygiene.duplicate_skill': 'Multiple skills have identical normalized bodies or case/hyphen/underscore-equivalent names.',
    'skill_hygiene.could_not_verify': 'Skill provenance or bounded package coverage could not be verified; missing evidence is not a clean result.',
    "context_load.persona_oversized": (
        "Profile persona (SOUL.md) injects a large static prompt block on every turn."
    ),
    "context_load.auto_loaded_skill_oversized": (
        "An auto-loaded skill injects a large full body into every session prompt."
    ),
    "context_load.skills_index_oversized": (
        "The skills index is large and consumes significant prompt budget before any skill is loaded."
    ),
    "context_load.memory_oversized": (
        "Enabled built-in memory blocks consume a large fixed prompt budget on every turn."
    ),
    "context_load.fixed_prompt_oversized": (
        "The profile fixed prompt base is oversized and re-sent on every model call."
    ),
    "context_load.project_context_oversized": (
        "Project context files inject a large instruction block into every session in this project."
    ),
    "context_load.project_context_truncated": (
        "A project context file exceeds the character limit and is head/tail truncated in the prompt."
    ),
    "context_load.project_context_unverified": (
        "Project context chain could not be safely read or verified."
    ),
    "context_load.parent_context_injected": (
        "A context file from a parent directory above the project root is injected into this project."
    ),
    "context_load.external_memory_provider_unmeasured": (
        "An external memory provider is configured and injects unmeasured content into every turn."
    ),
    "context_load.per_turn_window_share": (
        "Fixed profile and project context consumes at least 25% of the reference context window before the user types anything."
    ),
    "context_load.unverified": (
        "Static context load could not be verified for this run."
    ),
    "context_load.operational_error": (
        "Context load check could not complete verification."
    ),
    "profile_context.soul_unreadable": (
        "Profile SOUL.md could not be safely read; identity prompt contribution is unknown."
    ),
    "profile_context.soul_truncated": (
        "Profile SOUL.md exceeds the character limit and is head/tail truncated in the prompt."
    ),
    "profile_context.skills_inventory_incomplete": (
        "One or more skill directories for this profile could not be completely read."
    ),
    "profile_context.shadowed_skills": (
        "One or more skills are shadowed by higher-precedence skill roots and contribute zero prompt characters."
    ),
    "profile_context.auto_load_skill_unverified": (
        "An auto-loaded skill body could not be safely read or verified."
    ),
    "profile_context.auto_load_skill_skipped": (
        "A configured skills.auto_load entry is missing, disabled, or shadowed and contributes zero characters."
    ),
    "profile_context.memory_symlink_shared": (
        "A built-in profile memory file is a symlink and cannot be verified as profile-isolated."
    ),
    "profile_context.memory_unreadable": (
        "A built-in profile memory file could not be safely read."
    ),
    "profile_context.memory_snapshot_drift": (
        "A built-in memory file on disk differs from the frozen session-start prompt snapshot."
    ),
    "profile_context.memory_exceeds_char_limit": (
        "A built-in memory file exceeds its configured character limit while still being injected in full."
    ),
    "profile_context.dynamic_contributions_unverified": (
        "Dynamic plugin sections, MCP tool schemas, external provider context, and runtime metadata cannot be measured statically."
    ),
    "profile_context.operational_error": (
        "Profile context check could not complete verification."
    ),
    "profile_context.unverified": (
        "Profile context was not collected or could not be verified."
    ),
    "memory.symlink_store": (
        "A built-in profile memory store is a symlink; entries could not be verified as profile-isolated."
    ),
    "memory.store_unreadable": (
        "A built-in profile memory store could not be safely read."
    ),
    "memory.duplicate_entry_exact": (
        "Profile memory contains byte-identical duplicate entries that waste prompt budget on every session."
    ),
    "memory.duplicate_entry_similar_whitespace": (
        "Profile memory contains entries that match after whitespace normalization and require human review."
    ),
    "memory.stale_missing_path": (
        "A memory entry references a local filesystem path that no longer exists."
    ),
    "memory.path_reference_unverified": (
        "A memory entry references a filesystem path whose existence could not be verified."
    ),
    "memory.ambiguous_project_mapping": (
        "A memory entry matches multiple registered projects without an explicit path or project ID to disambiguate."
    ),
    "memory.cross_project_exposure": (
        "A project-scoped memory entry is stored in profile-wide memory and injected into every project session."
    ),
    "memory.unrelated_operational_directive": (
        "A memory entry contains an operational directive tied to another project context that applies across unrelated sessions."
    ),
    "memory.heuristic_operational_directive": (
        "A memory entry uses imperative directive phrasing that may act as a standing instruction."
    ),
    "memory.authoritative_entry_stale": (
        "A memory entry has an authoritative creation timestamp older than the configured staleness threshold."
    ),
    "memory.entry_age_unverified": (
        "Built-in memory entries do not carry per-entry creation timestamps, so entry age could not be verified."
    ),
    "memory.operational_error": (
        "Profile memory check could not complete verification."
    ),
    "memory.unverified": (
        "Profile memory check could not be verified."
    ),
    # Wired sections: fixed sentences generated from audit/wiring/*.json.
    **WIRED_FINDING_CONSEQUENCES,
}

PROJECT_CONTEXT_TRUNCATED_ASSUMED_CONSEQUENCE = (
    "A project context file exceeds 20,000 characters; the truncation point depends on "
    "the active model's context window and 20,000 chars is an assumed conservative value."
)

# Closed component ids. The sentence is allowlisted so persistence keeps it verbatim.
TIME_BUDGET_COMPONENTS = (
    'profile_context', 'context_load', 'skill_hygiene', 'write_settings',
    'session_contamination', 'memory', 'executable_inventory', 'template_drift',
    'static_code', 'home_workdirs', 'secret_file_copies', 'dead_stores',
    'profile_duplicates', 'skill_ledger', 'skill_packs', 'unattended_exposure',
    'memory_load', 'kanban_residue',
)


def component_time_budget_sentence(component: str) -> str:
    name = component if component in TIME_BUDGET_COMPONENTS else 'component'
    return f'The {name} check exceeded its time budget and could not be verified.'


def component_stopped_sentence(component: str) -> str:
    """Crash, signal, oversized or unreadable reply from the bounded child."""
    name = component if component in TIME_BUDGET_COMPONENTS else 'component'
    return f'The {name} check stopped without a usable result and could not be verified.'


TIME_BUDGET_CONSEQUENCES = frozenset(
    sentence(name)
    for sentence in (component_time_budget_sentence, component_stopped_sentence)
    for name in (*TIME_BUDGET_COMPONENTS, 'component')
)

ALLOWED_FINDING_CONSEQUENCES: frozenset[str] = frozenset({
    *FINDING_CONSEQUENCES.values(),
    PROJECT_CONTEXT_TRUNCATED_ASSUMED_CONSEQUENCE,
    *TIME_BUDGET_CONSEQUENCES,
})
