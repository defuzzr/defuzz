"""Plain-language summary of a sealed Defuzz audit report.

`summarize(report, home=None)` turns the stored report dict into a small, JSON-safe summary;
`render_text(summary)` turns that summary into short lines for the terminal. Both are pure:
no file, network or clock access, and they never raise on a missing, partial or oddly shaped
report. Finding sentences are copied from the report unchanged (only control characters are
made visible, see `safe_text`); every other word printed here comes from the fixed text in this
module. The rendered text is capped at `MAX_LINES_HARD` lines.
"""
from __future__ import annotations

import json
import math
import re
import textwrap
from datetime import datetime, timezone
from typing import Any, Mapping

SUMMARY_VERSION = 1
LINE_WIDTH = 100
MAX_LINES = 120          # soft budget: over it, note lists are shortened to a count
MAX_LINES_HARD = 200     # hard cap: over it, warning lists are shortened too
WARNINGS_PER_SECTION = 15

# Fixed order: settings that act without a prompt first, then text sent with each request,
# then skills, then disk use.
SECTION_ORDER = (
    'unattended_exposure',
    'secret_file_copies',
    'write_settings',
    'memory_load',
    'context_load',
    'skill_packs',
    'skill_hygiene',
    'skill_ledger',
    'session_contamination',
    'home_workdirs',
    'dead_stores',
    'profile_duplicates',
    'kanban_residue',
)

SECTION_TITLES = {
    'unattended_exposure': 'Commands that can run without a prompt',
    'secret_file_copies': 'Secret-named files outside their usual places',
    'write_settings': 'Memory and skill edit settings',
    'memory_load': 'Memory files and their limits',
    'context_load': 'Text sent with every request',
    'skill_packs': 'Installed skills and the skill list',
    'skill_hygiene': 'What is inside skill files',
    'skill_ledger': 'Skill change history',
    'session_contamination': 'Memory from other projects in past sessions',
    'home_workdirs': 'Work files inside the Hermes home',
    'dead_stores': 'Stored files nothing uses',
    'profile_duplicates': 'Copies shared across profiles',
    'kanban_residue': 'Leftover task board data',
}

CLASS_ORDER = ('warning', 'review_suggested', 'info')
CLASS_LABELS = {
    'warning': 'Warning',
    'review_suggested': 'Review suggested',
    'info': 'For information',
}

HEADER_TITLE = 'Defuzz audit summary'
FOOTER_INTRO = (
    'Each setting and file counted here was reasonable on the day it was added. '
    'This report adds them up to show the running total.'
)
FOOTER_STEPS_TITLE = 'Small next steps:'
FOOTER_CLOSE = 'It is fine to stop here and come back to this later.'
FOOTER_JSON_HINT = 'Exact numbers for every line: hermes defuzz audit --json'
MISSING_SENTENCE = 'No fixed sentence was stored for this item.'
UNEXPECTED_SHAPE = 'unexpected_shape'
NOT_IN_REPORT = 'not_in_report'
NO_REASON = 'no_reason'
FINDINGS_UNVERIFIED = 'findings_unverified'
MEMORY_NONE_LINE = 'No memory files (MEMORY.md, USER.md) were found, so there is no memory to measure.'
# Statuses that say only that a section was not measured, not why.
_BARE_STATUSES = ('not_measured', 'could_not_verify', 'unknown')
RENDER_FAILED = 'The summary could not be built from this report; see --json.'
MORE_LINES = 'More lines are in --json.'

STEP_NOTHING = 'Nothing here needs action today.'
STEP_APPROVAL = 'Turn command approval back on, then re-run the audit.'
# No step tells the reader to delete anything as the first action: things are moved to a
# backup folder first, and deleting comes later, once nothing misses them.
STEP_SECRETS = ('Check whether each secret-named copy is still needed; move the ones that are not '
                'to a safe place outside the Hermes home, and change any key that was shared or exposed.')
STEP_MEMORY = ('Copy MEMORY.md to a backup folder outside the Hermes home, then remove entries '
               'that are no longer true.')
STEP_MEMORY_LIMIT = ('Copy MEMORY.md to a backup folder outside the Hermes home, then remove entries '
                     'that are no longer true. Then set the memory limit back to the shipped value.')
# Used when config.yaml raises the memory limit but no MEMORY.md exists: there is nothing to copy.
STEP_MEMORY_LIMIT_ONLY = ('Set the memory limit in config.yaml back to the shipped value. No MEMORY.md '
                          'exists yet, so nothing else needs to change.')
STEP_DEAD = ('Move old exports and unused plugin folders to a backup folder outside the Hermes home; '
             'delete them later once nothing misses them.')
STEP_PROFILES = ('Move profiles that are no longer used to a backup folder outside the Hermes home; '
                 'delete them later once nothing misses them.')
STEP_KANBAN = 'Archive finished tasks on the task board; delete them later once nothing misses them.'
STEP_SKILLS = 'Turn off skills that are rarely used, so less text goes with every request.'
STEP_WRITES = 'Turn on approval for memory and skill edits to see each change before it is saved.'
STEP_HOME = 'Move project folders that live inside the Hermes home to a normal projects folder.'
STEP_REVIEW = 'Read the items marked "Review suggested", one section at a time.'
STEP_SESSIONS = 'Re-run with --sessions to include past sessions.'
STEP_RERUN = 'Re-run the audit after big changes to compare the totals.'
STEP_KEEP = 'Save the --json output to compare with next time.'

# Plain labels for numbers that appear as "biggest items".
_DEAD_CLASS_LABELS = {
    'backup_files': 'Backup files',
    'exports_and_archives': 'Old exports and archives',
    'feature_off_assets': 'Files for features that are off',
    'orphan_plugin_data': 'Data for plugins that are gone',
    'parked_and_disabled_plugins': 'Parked or turned-off plugins',
    'plugin_dev_residue': 'Developer files inside plugins',
    'regenerable_caches': 'Caches that can be rebuilt',
    'request_dumps': 'Saved request dumps',
    'unreferenced_skill_clones': 'Skill copies nothing lists',
    'unrotated_logs': 'Logs that keep growing',
}
_CONTEXT_SOURCE_LABELS = {
    'identity_soul': 'SOUL.md persona',
    'core_guidance': 'built-in guidance',
    'enabled_memory_files': 'memory files',
    'auto_loaded_skill_bodies': 'auto-loaded skills',
    'skills_index_text': 'skill list',
}
_APPROVAL_KEYS = (
    ('approvals.mode', 'approval_off'),
    ('approvals.cron_mode', 'approve'),
    ('approvals.unattended_mode', 'approve'),
    ('approvals.single_query_mode', 'approve'),
)
_TOKEN_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')
# Built from a tuple so no source line reads like a shell `env |` pipe (same compiled pattern).
_CREDENTIAL_PARTS = (
    'secret', 'token', 'auth', 'cred', 'passw', r'\.env', 'env$', 'key', r'\.pem', r'\.p12',
    r'\.pfx', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'netrc', 'npmrc', 'pypirc', 'oauth', 'vault',
    'keystore',
)
_CREDENTIAL_PART_RE = re.compile('(' + '|'.join(_CREDENTIAL_PARTS) + ')', re.IGNORECASE)
_SKIP_EVIDENCE = ('threshold', 'limit', 'digest')
_INDEX_KEY_RE = re.compile(r'(^|_)index$')
# Plain phrases for reason tokens (the desktop page keeps the same table: desktop/plugin.js
# AUDIT_REASON_PHRASES); any other token is shown with underscores as spaces.
_REASON_PHRASES = {
    'not_in_report': 'not part of this report',
    'not_run': 'not run this time',
    'unexpected_shape': 'the report section had an unexpected shape',
    'bounded_quick_audit_not_collected': 'not included in a quick audit',
    'not_included': 'not included this time',
    'could_not_verify': 'could not be verified',
    'no_reason': 'the audit did not say why',
    'ledger_absent': 'no skill change history file exists yet',
    'usage_file_missing': 'no record of skill use exists yet, so use counts are not known',
    'missing': 'the file or folder it reads was not found',
    'empty': 'the file it reads is empty',
    'empty_home': 'the Hermes home is empty',
    'missing_home': 'the Hermes home folder was not found',
    'missing_profile_root': 'the profile folder was not found',
    'profile_missing': 'the profile folder was not found',
    'profile_unreadable': 'the profile folder could not be read',
    'unreadable': 'the file it reads could not be read',
    'not_directory': 'the Hermes home is not a folder',
    'invalid_home_root': 'the Hermes home is not a folder',
    'invalid_profile_root': 'the profile folder is not a folder',
    'managed_overlay': 'some settings are managed outside this home',
    'time_budget': 'the audit time limit was reached',
    'snapshot_shape': 'some memory backup folders had an unusual layout',
    'input_unknown': 'a setting the check needs could not be read',
    'no_projects': 'there are no projects to compare with',
    'default_profile_never_archived': 'the default profile is never offered for archiving',
    'active_profile_never_archived': 'the active profile is never offered for archiving',
    'within_active_threshold': 'the profile was used recently',
    'not_present': 'nothing of this kind is in this home',
    'findings_unverified': 'some of its results could not be verified',
    'unverified': 'the check was not run or did not finish',
    # Outward-sweep codes (scope.regions.*.reason_details).
    'skipped_folders': 'dependency, cache and Git object folders were skipped and not checked',
    'entry_limit_exceeded': 'some folders were not fully checked because the entry limit was reached',
    'total_byte_limit_exceeded': 'some folders were not fully checked because the size limit was reached',
    # Limits and read problems named by the sections.
    'truncated': 'some files or folders were skipped and not checked',
    'entry_budget': 'a folder had more entries than the audit limit',
    'max_entries': 'a folder had more entries than the audit limit',
    'max_blob_entries': 'a folder had more entries than the audit limit',
    'depth_budget': 'folders nested deeper than the audit limit were not checked',
    'walk_truncated': 'the walk through the home stopped at an audit limit',
    'file_bytes': 'a file was larger than the size limit',
    'max_file_bytes': 'a file was larger than the size limit',
    'total_bytes_cap': 'the total amount the check may read was reached',
    'scandir_error': 'a folder could not be listed',
    'subpath_unreadable': 'part of the home could not be listed',
    'unreadable_subdir': 'a folder could not be read',
    'config_unreadable': 'config.yaml could not be read',
    'duplicate_config_key': 'config.yaml sets the same setting twice',
    'skills_tree_unreadable': 'the skills folder could not be read',
    'external_skill_dirs': 'the skill folders named in config.yaml could not all be checked',
    'enabled_plugins': 'the list of turned-on plugins could not be read',
    'pet_enabled': 'the pet setting could not be read',
    'root_missing': 'the Hermes home folder was not found',
    # Parts of the text sent with every request (context_load) that could not be measured.
    'identity_soul': 'the SOUL.md persona could not be measured',
    'core_guidance': 'the built-in guidance could not be measured',
    'enabled_memory_files': 'the memory files could not be measured',
    'auto_loaded_skill_bodies': 'the auto-loaded skills could not be measured',
    'skills_index_text': 'the skill list could not be measured',
    'external_memory_provider': 'an external memory provider is set up and was not measured',
    'project_context': 'the context files of a project could not be fully read',
    # Checks known from their findings.
    'dynamic_contributions_unverified': 'plugin text, tool lists and other runtime parts cannot be measured from files',
    'memory_unreadable': 'a memory file could not be read',
    'soul_unreadable': 'the SOUL.md file could not be read',
    'store_unreadable': 'a memory store could not be read',
    'entry_age_unverified': 'memory entries carry no dates, so their age is not known',
    'inspection_failed': 'a file or folder could not be inspected',
}
# Fixed sentences for outward-sweep reason codes (report scope.regions.*.reason_details):
# one line each in the text summary when any region carries the code.
_SCOPE_SENTENCES = (
    ('skipped_folders', 'Dependency, cache and Git object folders were skipped and not checked.'),
    ('entry_limit_exceeded', 'Some folders were not fully checked because the entry limit was reached.'),
    ('total_byte_limit_exceeded', 'Some folders were not fully checked because the size limit was reached.'),
    ('time_budget', 'Some folders were not fully checked because the time limit was reached.'),
)
# C0 controls (newline/CR/tab handled separately), DEL, C1, bidi embeddings/overrides/isolates,
# and the Unicode line/paragraph separators.
_UNSAFE_RE = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069'
                        '\u2028\u2029]')
_BREAK_RE = re.compile('[\n\r\t]')


# ---------------------------------------------------------------- small pure helpers

def _num(value: Any) -> int | float | None:
    if type(value) is bool or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, Mapping):
            return None
        obj = obj.get(key)
    return obj


def _int_text(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f'{value:,.2f}'
    return f'{int(value):,}'


def human_bytes(value: Any) -> str:
    """Readable size in decimal units (1 MB = 1,000,000 bytes), e.g. 1,536 -> '1.5 KB'.

    One unit system everywhere in the summary, labelled as it is computed. Exact numbers stay
    in the JSON summary.
    """
    n = _num(value)
    if n is None:
        return 'not known'
    n = int(n)
    if abs(n) < 1000:
        return f'{n:,} bytes' if n != 1 else '1 byte'
    size = float(n)
    for unit in ('KB', 'MB', 'GB', 'TB'):
        size /= 1000.0
        if abs(size) < 999.95 or unit == 'TB':
            return f'{size:,.1f} {unit}'
    return f'{n:,} bytes'  # pragma: no cover


def _percent(share: Any) -> str | None:
    n = _num(share)
    if n is None:
        return None
    return f'{round(n * 100):d}%'


def _token(value: Any, default: str = 'unknown') -> str:
    return value if isinstance(value, str) and _TOKEN_RE.match(value) else default


def _plural(n: int | float, word: str, plural: str | None = None) -> str:
    return f'{_int_text(n)} {word if n == 1 else (plural or word + "s")}'


def _escape(ch: str) -> str:
    code = ord(ch)
    return f'\\x{code:02x}' if code <= 0xff else f'\\u{code:04x}'


def safe_text(value: Any, path: bool = False) -> str:
    """Text safe for a terminal and a <pre> block: control characters become visible escapes.

    C0 controls, DEL, C1 controls, bidi overrides/isolates and U+2028/U+2029 become `\\x1b` or
    `\\u202e`. Newline, carriage return and tab become a space in sentences and an escape in
    paths. Idempotent; non-strings become their str() (None becomes '').
    """
    if value is None:
        return ''
    text = value if isinstance(value, str) else str(value)
    text = _UNSAFE_RE.sub(lambda m: _escape(m.group()), text)
    return _BREAK_RE.sub((lambda m: _escape(m.group())) if path else (lambda m: ' '), text)


def reason_phrase(reason: Any) -> str:
    """Plain phrase for a reason token ('not_run' -> 'not run this time')."""
    if not isinstance(reason, str) or not reason:
        return 'unknown'
    return _REASON_PHRASES.get(reason) or safe_text(reason).replace('_', ' ')


def relative_path(path: Any, home: str | None) -> str | None:
    """Path relative to the audited home (terminal-safe), or None when it is not safely under it."""
    if not isinstance(path, str) or not isinstance(home, str) or not home.startswith('/'):
        return None
    root = home.rstrip('/') or '/'
    if 'hmac' in path.lower():
        return None
    if path == root:
        return '.'
    if not path.startswith(root + '/'):
        return None
    rel = path[len(root) + 1:]
    parts = rel.split('/')
    if not rel or any(p in ('', '.', '..') for p in parts):
        return None
    if any(_CREDENTIAL_PART_RE.search(p) for p in parts):
        return None
    return safe_text(rel, path=True)


# ---------------------------------------------------------------- per-section headlines
# Each returns (headline text, exact numbers) or raises; summarize() catches everything.

def _h_unattended(sec: Mapping, home: str | None):
    settings = sec.get('settings') if isinstance(sec.get('settings'), Mapping) else {}
    no_prompt, unread = [], 0
    for key, open_value in _APPROVAL_KEYS:
        row = settings.get(key)
        value = row.get('value') if isinstance(row, Mapping) else None
        if not isinstance(value, str):
            unread += 1
        elif value == open_value:
            no_prompt.append(key)
    text = (f'Approval settings that let commands run without a prompt: '
            f'{len(no_prompt)} of {len(_APPROVAL_KEYS)}')
    if no_prompt:
        text += ' (' + ', '.join(no_prompt) + ')'
    if unread:
        text += f'; {unread} could not be read'
    return text + '.', {'approval_settings_without_prompt': no_prompt,
                        'approval_settings_checked': len(_APPROVAL_KEYS),
                        'approval_settings_unread': unread}


def _h_secrets(sec: Mapping, home: str | None):
    count = _num(_get(sec, 'secret_named_files', 'count'))
    folders = _num(_get(sec, 'secret_named_files', 'top_level_folder_count'))
    backups = _num(_get(sec, 'backup_copies', 'count'))
    if count is None:
        raise ValueError('no count')
    text = f'{_plural(count, "secret-named file")} outside the expected places'
    if folders is not None:
        text += f', in {_plural(folders, "top-level folder")}'
    if backups is not None:
        text += f'; {_plural(backups, "backup copy", "backup copies")} of secret files'
    return text + '.', {'secret_named_files': count, 'top_level_folders': folders,
                        'backup_copies': backups}


def _yes_no(value: Any) -> str:
    return 'yes' if value is True else 'no' if value is False else 'not known'


def _h_write(sec: Mapping, home: str | None):
    skill, memory = sec.get('unattended_skill_writes'), sec.get('unattended_memory_writes')
    if not isinstance(skill, bool) and not isinstance(memory, bool):
        # The report could not work out which tools a session has; show the settings it did read.
        mem_ok = _get(sec, 'settings', 'memory.write_approval', 'value')
        skill_ok = _get(sec, 'settings', 'skills.write_approval', 'value')
        if not isinstance(mem_ok, bool) and not isinstance(skill_ok, bool):
            if not isinstance(sec.get('settings'), Mapping):
                raise ValueError('no settings')
            # Real shape when config.yaml is missing or unreadable: every value is null.
            return ('The memory and skill edit settings could not be read, so whether edits are '
                    'saved without a prompt is not known.'), {
                        'memory_write_approval': None, 'skills_write_approval': None,
                        'unattended_skill_writes': None, 'unattended_memory_writes': None}
        text = (f'Approval before memory edits is on: {_yes_no(mem_ok)}. '
                f'Approval before skill edits is on: {_yes_no(skill_ok)}. '
                'Which tools a session has could not be read from config, so whether edits are '
                'saved without a prompt is not known.')
        return text, {'memory_write_approval': mem_ok if isinstance(mem_ok, bool) else None,
                      'skills_write_approval': skill_ok if isinstance(skill_ok, bool) else None,
                      'unattended_skill_writes': None, 'unattended_memory_writes': None}
    text = (f'Skill edits saved without a prompt: {_yes_no(skill)}. '
            f'Memory edits saved without a prompt: {_yes_no(memory)}.')
    return text, {'unattended_skill_writes': skill if isinstance(skill, bool) else None,
                  'unattended_memory_writes': memory if isinstance(memory, bool) else None}


def _pick_memory_row(rows: list, kind: str):
    matches = [r for r in rows if isinstance(r, Mapping) and r.get('kind') == kind]
    main = [r for r in matches if r.get('scope') == 'main']
    return (main or matches or [None])[0]


def _raised_limit(sec: Mapping, kind: str):
    """(configured, shipped) when config.yaml sets this file's limit above the shipped value."""
    lim = _get(sec, 'char_limits', kind)
    if not isinstance(lim, Mapping) or lim.get('limit_source') != 'config':
        return None
    configured, shipped = _num(lim.get('configured_char_limit')), _num(lim.get('shipped_char_limit'))
    if not configured or not shipped or configured <= shipped:
        return None
    return configured, shipped


def _snapshot_count(sec: Mapping) -> int:
    n = _num(_get(sec, 'snapshots', 'count'))
    return int(n) if n is not None and n > 0 else 0


def _memory_nothing_found(sec: Any) -> bool:
    """memory_load's own 'nothing to measure' shape: no live file, snapshot, store or pending
    edit, and the scan was not cut short (audit/memory_load.py sets status 'not_measured')."""
    return (isinstance(sec, Mapping) and sec.get('status') == 'not_measured'
            and not _token(sec.get('reason'), '')
            and sec.get('files') == [] and _snapshot_count(sec) == 0
            and sec.get('truncated_by') == [])


def _h_memory_none(sec: Mapping, rows: list):
    # One plain line, like other 'nothing here' sections; saved snapshots stay in --json.
    snaps = _snapshot_count(sec)
    text = MEMORY_NONE_LINE
    if (raised := _raised_limit(sec, 'memory')) is not None:
        text += (f' The memory limit is set to {raised[0] / raised[1]:.1f} times the shipped '
                 f'value of {_int_text(raised[1])}.')
    numbers = {'memory': {'characters': None, 'char_limit': None},
               'user': {'characters': None, 'char_limit': None},
               'live_memory_files': 0, 'snapshots': snaps, 'files_over_limit': 0}
    return text, numbers


def _h_memory(sec: Mapping, home: str | None):
    rows = sec.get('files') if isinstance(sec.get('files'), list) else None
    if rows is None:
        raise ValueError('no files list')
    rows = [r for r in rows if isinstance(r, Mapping)]
    if not any(r.get('kind') in ('memory', 'user') for r in rows):
        return _h_memory_none(sec, rows)
    parts, numbers = [], {}
    shipped_limits = {}
    for kind, name in (('memory', 'MEMORY.md'), ('user', 'USER.md')):
        row = _pick_memory_row(rows, kind)
        chars = _num(row.get('characters')) if row else None
        limit = _num(row.get('char_limit')) if row else None
        numbers[kind] = {'characters': chars, 'char_limit': limit}
        shipped = _num(_get(sec, 'char_limits', kind, 'shipped_char_limit'))
        if shipped is not None:
            shipped_limits[kind] = shipped
        if row is None:
            parts.append(f'{name}: not found')
        elif chars is None:
            parts.append(f'{name}: found, but its size could not be read')
        elif limit:
            parts.append(f'{name}: {_int_text(chars)} of {_int_text(limit)} characters '
                         f'({round(chars * 100 / limit):d}%)')
        else:
            parts.append(f'{name}: {_int_text(chars)} characters (limit not known)')
        if (raised := _raised_limit(sec, kind)) is not None:
            parts[-1] += (f'. The limit is {raised[0] / raised[1]:.1f} times the shipped value of '
                          f'{_int_text(raised[1])}')
    if shipped_limits:
        numbers['shipped_char_limits'] = shipped_limits
    numbers['live_memory_files'] = sum(1 for r in rows if r.get('kind') in ('memory', 'user'))
    over = sum(1 for r in rows if isinstance(r, Mapping) and r.get('over_limit') is True)
    numbers['files_over_limit'] = over
    return '. '.join(parts) + '.', numbers


def _h_context(sec: Mapping, home: str | None):
    total = sec.get('per_turn_total') if isinstance(sec.get('per_turn_total'), Mapping) else {}
    tokens, chars = _num(total.get('estimated_tokens')), _num(total.get('characters'))
    if tokens is None and chars is None:
        raise ValueError('no totals')
    text = 'Sent with every request: '
    text += f'about {_int_text(tokens)} tokens' if tokens is not None else 'tokens not known'
    if chars is not None:
        text += f' ({_int_text(chars)} characters)'
    sources = _get(sec, 'profile', 'sources')
    largest = None
    if isinstance(sources, list):
        rows = [s for s in sources if isinstance(s, Mapping) and _num(s.get('characters'))]
        rows.sort(key=lambda s: (-s['characters'], str(s.get('source'))))
        if rows and rows[0].get('source') in _CONTEXT_SOURCE_LABELS:
            largest = rows[0]
    if largest is not None:
        text += (f'; largest part: {_CONTEXT_SOURCE_LABELS[largest["source"]]}, '
                 f'{_int_text(largest["characters"])} characters')
    return text + '.', {'estimated_tokens': tokens, 'characters': chars,
                        'largest_part': largest.get('source') if largest else None,
                        'largest_part_characters': largest.get('characters') if largest else None}


def _h_packs(sec: Mapping, home: str | None):
    index = sec.get('index') if isinstance(sec.get('index'), Mapping) else {}
    listed, chars = _num(index.get('loadable_skills')), _num(index.get('index_chars'))
    tokens = _num(index.get('estimated_tokens'))
    if listed is None and chars is None:
        raise ValueError('no index')
    text = f'{_plural(listed, "skill")} listed' if listed is not None else 'Skill count not known'
    if chars is not None:
        text += f'; the skill list adds {_int_text(chars)} characters'
        if tokens is not None:
            text += f' (about {_int_text(tokens)} tokens)'
        text += ' to every request'
    never = _num(_get(sec, 'usage', 'zero_use_count'))
    if never is not None:
        text += f'; {_int_text(never)} never used'
    return text + '.', {'listed_skills': listed, 'index_chars': chars,
                        'estimated_tokens': tokens, 'never_used': never}


def _h_hygiene(sec: Mapping, home: str | None):
    examined = _num(sec.get('skills_examined'))
    if examined is None and isinstance(sec.get('skills'), list):
        examined = len(sec['skills'])
    modified, residue = _num(sec.get('bundled_modified')), _num(sec.get('residue_skills'))
    groups = len(sec['duplicate_groups']) if isinstance(sec.get('duplicate_groups'), list) else None
    if examined is None:
        raise ValueError('no count')
    text = f'{_plural(examined, "skill")} checked'
    if modified is not None:
        text += f'; {_plural(modified, "stock skill")} changed since install'
    if residue is not None:
        text += f'; {_int_text(residue)} with leftover session notes'
    if groups:
        text += f'; {_plural(groups, "group")} of skills with the same content'
    return text + '.', {'skills_examined': examined, 'bundled_modified': modified,
                        'residue_skills': residue, 'duplicate_groups': groups}


def _h_ledger(sec: Mapping, home: str | None):
    orphan_bytes = _num(_get(sec, 'backup_store', 'orphan_blob_bytes'))
    if sec.get('ledger_present') is False:
        text = 'No skill change history file was found'
        if orphan_bytes:
            text += f'; {human_bytes(orphan_bytes)} of skill backups nothing refers to'
        return text + '.', {'ledger_present': False, 'orphan_blob_bytes': orphan_bytes}
    changes, skills = _num(sec.get('total_changes')), _num(sec.get('skills_in_ledger'))
    if changes is None:
        raise ValueError('no changes')
    text = f'{_plural(changes, "recorded change")}'
    if skills is not None:
        text += f' to {_plural(skills, "skill")}'
    if orphan_bytes is not None:
        text += f'; {human_bytes(orphan_bytes)} of skill backups nothing refers to'
    return text + '.', {'total_changes': changes, 'skills_in_ledger': skills,
                        'orphan_blob_bytes': orphan_bytes}


def _h_sessions(sec: Mapping, home: str | None):
    overall = sec.get('overall') if isinstance(sec.get('overall'), Mapping) else {}
    examined = _num(overall.get('sessions_examined'))
    foreign = _num(overall.get('sessions_with_foreign_memory'))
    rate = _percent(overall.get('contamination_rate'))
    if examined is None:
        raise ValueError('no sessions')
    text = f'{_plural(examined, "past session")} checked'
    if foreign is not None:
        text += f'; {_int_text(foreign)} carried memory from another project'
        if rate is not None:
            text += f' ({rate})'
    return text + '.', {'sessions_examined': examined, 'sessions_with_foreign_memory': foreign,
                        'contamination_rate': _num(overall.get('contamination_rate'))}


def _h_workdirs(sec: Mapping, home: str | None):
    totals = sec.get('totals') if isinstance(sec.get('totals'), Mapping) else {}
    other, total = _num(totals.get('not_hermes_bytes')), _num(totals.get('total_home_bytes'))
    if other is None or total is None:
        raise ValueError('no totals')
    huge = sec.get('huge_files') if isinstance(sec.get('huge_files'), list) else []
    limit = _num(_get(sec, 'thresholds', 'huge_file_bytes'))
    share = _percent(totals.get('not_hermes_share'))
    text = f'{human_bytes(other)} of {human_bytes(total)} in the home'
    if share is not None:
        text += f' ({share})'
    text += ' is in folders Hermes does not create'
    text += f'; {_plural(len(huge), "file")} over {human_bytes(limit) if limit else "the size limit"}'
    return text + '.', {'not_hermes_bytes': other, 'total_home_bytes': total,
                        'not_hermes_share': _num(totals.get('not_hermes_share')),
                        'huge_files': len(huge), 'huge_files_bytes': _num(totals.get('huge_files_bytes'))}


def _h_dead(sec: Mapping, home: str | None):
    dead, total = _num(sec.get('total_dead_weight_bytes')), _num(sec.get('total_home_bytes'))
    if dead is None:
        raise ValueError('no total')
    share = _percent(sec.get('dead_weight_share_of_home'))
    text = f'{human_bytes(dead)}'
    if total is not None:
        text += f' of {human_bytes(total)} in the home'
    if share is not None:
        text += f' ({share})'
    text += ' is in files nothing refers to, such as old exports, caches and backups'
    return text + '.', {'total_dead_weight_bytes': dead, 'total_home_bytes': total,
                        'dead_weight_share_of_home': _num(sec.get('dead_weight_share_of_home'))}


def _h_profiles(sec: Mapping, home: str | None):
    count, wasted = _num(sec.get('profile_count')), _num(sec.get('total_wasted_bytes'))
    groups = _num(sec.get('duplicate_group_count'))
    if count is None:
        raise ValueError('no profiles')
    text = f'{_plural(count, "profile")}'
    if wasted is not None:
        text += f'; {human_bytes(wasted)} stored more than once'
        if groups is not None:
            text += f', in {_plural(groups, "group")} of identical files'
    return text + '.', {'profile_count': count, 'total_wasted_bytes': wasted,
                        'duplicate_group_count': groups}


def _largest_retry(boards: list) -> int | float | None:
    best = None
    for b in boards:
        n = _num(_get(b, 'retry_context', 'latest_worker_chars', 'max'))
        if n is not None and (best is None or n > best):
            best = n
    return best


def _h_kanban(sec: Mapping, home: str | None):
    boards = [b for b in sec.get('boards', []) if isinstance(b, Mapping)] \
        if isinstance(sec.get('boards'), list) else []
    tasks = sum(_num(b.get('tasks')) or 0 for b in boards)
    comments = sum(_num(b.get('comments')) or 0 for b in boards)
    retry = _largest_retry(boards)
    if not boards:
        found = _num(sec.get('databases_found'))
        return f'{_plural(found or 0, "task board")} found.', {'boards': 0, 'tasks': 0,
                                                               'comments': 0, 'largest_retry_chars': None}
    text = (f'{_plural(tasks, "task")} and {_plural(comments, "comment")} on '
            f'{_plural(len(boards), "board")}')
    if retry is not None:
        text += f'; largest retry context: {_int_text(retry)} characters'
    return text + '.', {'boards': len(boards), 'tasks': tasks, 'comments': comments,
                        'largest_retry_chars': retry}


_HEADLINES = {
    'unattended_exposure': _h_unattended,
    'secret_file_copies': _h_secrets,
    'write_settings': _h_write,
    'memory_load': _h_memory,
    'context_load': _h_context,
    'skill_packs': _h_packs,
    'skill_hygiene': _h_hygiene,
    'skill_ledger': _h_ledger,
    'session_contamination': _h_sessions,
    'home_workdirs': _h_workdirs,
    'dead_stores': _h_dead,
    'profile_duplicates': _h_profiles,
    'kanban_residue': _h_kanban,
}


# ---------------------------------------------------------------- biggest items

def _biggest_items(report: Mapping, measured: set, home: str | None) -> list[dict]:
    items: list[dict] = []

    def add(label, value, unit, path=None):
        n = _num(value)
        if n is not None and n > 0:
            items.append({'label': label, 'value': n, 'unit': unit,
                          'path': relative_path(path, home)})

    def section(name):
        sec = report.get(name)
        return sec if name in measured and isinstance(sec, Mapping) else None

    if (s := section('home_workdirs')) is not None:
        for row in s.get('huge_files') or []:
            if isinstance(row, Mapping):
                add('Large file', row.get('size_bytes'), 'bytes', row.get('path'))
        for row in s.get('not_hermes_folders') or []:
            if isinstance(row, Mapping):
                add('Folder Hermes does not create', row.get('size_bytes'), 'bytes', row.get('path'))
    if (s := section('dead_stores')) is not None and isinstance(s.get('dead_weight_by_class'), Mapping):
        for cls, value in s['dead_weight_by_class'].items():
            if cls in _DEAD_CLASS_LABELS:
                add(_DEAD_CLASS_LABELS[cls], value, 'bytes')
    if (s := section('profile_duplicates')) is not None:
        for row in s.get('top_duplicate_groups') or []:
            if isinstance(row, Mapping):
                add('Identical copies across profiles', row.get('wasted_bytes'), 'bytes',
                    row.get('location'))
    if (s := section('skill_ledger')) is not None:
        add('Skill backups nothing refers to', _get(s, 'backup_store', 'orphan_blob_bytes'), 'bytes')
    if (s := section('memory_load')) is not None:
        rows = s.get('files') if isinstance(s.get('files'), list) else []
        for kind, name in (('memory', 'MEMORY.md'), ('user', 'USER.md')):
            row = _pick_memory_row(rows, kind)
            if row:
                add(name, row.get('characters'), 'characters')
    if (s := section('context_load')) is not None:
        add('Text sent with every request', _get(s, 'per_turn_total', 'characters'), 'characters')
    if (s := section('skill_packs')) is not None:
        add('Skill list sent with every request', _get(s, 'index', 'index_chars'), 'characters')
    if (s := section('kanban_residue')) is not None:
        boards = [b for b in s.get('boards') or [] if isinstance(b, Mapping)] \
            if isinstance(s.get('boards'), list) else []
        add('Largest task retry context', _largest_retry(boards), 'characters')
        add('Task board logs', _get(s, 'logs', 'bytes'), 'bytes')
    items.sort(key=lambda i: (-i['value'], i['label'], i['path'] or ''))
    kept: list[dict] = []
    # Sections overlap: a file inside a listed folder, or the same bytes counted by two
    # sections, is one item, listed once.
    for item in items:
        if any(k['unit'] == item['unit'] and (
                k['value'] == item['value']
                or (k['path'] and item['path'] and (k['path'].startswith(item['path'] + '/')
                                                    or item['path'].startswith(k['path'] + '/'))))
               for k in kept):
            continue
        kept.append(item)
    return kept[:3]


# ---------------------------------------------------------------- findings

def _evidence_numbers(evidence: Any) -> list[list]:
    if not isinstance(evidence, Mapping):
        return []
    rows = []
    for key in sorted(k for k in evidence if isinstance(k, str)):
        n = _num(evidence[key])
        if n is not None and not any(s in key for s in _SKIP_EVIDENCE):
            rows.append([key, n])
    rows.sort(key=lambda r: r[1] == 0)  # stable: non-zero numbers first, then by name
    return rows[:3]


def _evidence_text(key: str, value: int | float) -> str:
    label = key.replace('_', ' ')
    if 'bytes' in key:
        return f'{label} {human_bytes(value)}'
    if ('share' in key or 'rate' in key) and isinstance(value, float) and 0 <= value <= 1:
        return f'{label} {_percent(value)}'
    return f'{label} {_int_text(value)}'


def _classification(value: Any) -> str | None:
    """The finding's class when it is one of CLASS_ORDER; None for any other value or type."""
    return value if isinstance(value, str) and value in CLASS_ORDER else None


def _section_of(rule_id: Any) -> str | None:
    if not isinstance(rule_id, str) or '.' not in rule_id:
        return None
    return rule_id.split('.', 1)[0]


def _check_of(rule_id: Any) -> str | None:
    """The check a rule id belongs to; outward-sweep ids (audit.scope.x, audit.blending) by their second part."""
    name = _section_of(rule_id)
    if name == 'audit' and rule_id.count('.') >= 1:
        return rule_id.split('.')[1]
    return name


def _group_findings(findings: list, names=SECTION_TITLES) -> dict[str, dict[str, list[dict]]]:
    """section -> classification -> [{rule_id, sentence, count, evidence}] (one row per rule)."""
    grouped: dict[str, dict[str, dict[tuple, dict]]] = {}
    rows = []
    for f in findings:
        if not isinstance(f, Mapping):
            continue
        cls = _classification(f.get('classification'))
        name = _check_of(f.get('id'))
        if cls not in CLASS_ORDER or name not in names:
            continue
        sentence = f.get('consequence')
        if not isinstance(sentence, str) or not sentence.strip():
            sentence = f.get('detail') if isinstance(f.get('detail'), str) and f['detail'].strip() \
                else MISSING_SENTENCE
        evidence = _evidence_numbers(f.get('evidence'))
        rows.append((name, cls, f['id'], sentence, evidence))
    rows.sort(key=lambda r: (r[0], CLASS_ORDER.index(r[1]), r[2], r[3], json.dumps(r[4])))
    for name, cls, rule_id, sentence, evidence in rows:
        bucket = grouped.setdefault(name, {}).setdefault(cls, {})
        key = (rule_id, sentence)
        if key in bucket:
            bucket[key]['count'] += 1
        else:
            bucket[key] = {'rule_id': rule_id, 'sentence': sentence, 'count': 1, 'evidence': evidence}
    return {name: {cls: list(rows.values()) for cls, rows in by_cls.items()}
            for name, by_cls in grouped.items()}


# ---------------------------------------------------------------- next steps

def _next_steps(counts: Mapping, rule_ids: set, classes_by_section: Mapping,
                not_measured: list, live_memory: bool = True) -> list[str]:
    def has(section, *classes):
        return any(c in classes_by_section.get(section, ()) for c in classes)

    acting = counts.get('warning', 0) + counts.get('review_suggested', 0)
    steps: list[str] = []
    if not acting:
        steps.append(STEP_NOTHING)
    rules = [
        (bool(rule_ids & {'unattended_exposure.command_approval_off',
                          'unattended_exposure.unattended_auto_approve'}), STEP_APPROVAL),
        (has('secret_file_copies', 'warning'), STEP_SECRETS),
        # Steps that copy MEMORY.md apply only when a live MEMORY.md was measured.
        ('memory_load.limit_raised_above_shipped' in rule_ids,
         STEP_MEMORY_LIMIT if live_memory else STEP_MEMORY_LIMIT_ONLY),
        ('memory_load.over_limit' in rule_ids and live_memory
         and 'memory_load.limit_raised_above_shipped' not in rule_ids, STEP_MEMORY),
        (has('dead_stores', 'warning', 'review_suggested'), STEP_DEAD),
        (has('profile_duplicates', 'warning', 'review_suggested'), STEP_PROFILES),
        (has('home_workdirs', 'warning', 'review_suggested'), STEP_HOME),
        (has('kanban_residue', 'warning', 'review_suggested'), STEP_KANBAN),
        (has('skill_packs', 'warning', 'review_suggested')
         or has('context_load', 'warning', 'review_suggested'), STEP_SKILLS),
        (has('write_settings', 'warning', 'review_suggested'), STEP_WRITES),
        (acting > 0, STEP_REVIEW),
        (any(n['section'] == 'session_contamination' and n['reason'] == 'not_run'
             for n in not_measured), STEP_SESSIONS),
        (True, STEP_RERUN),
        (True, STEP_KEEP),
    ]
    for applies, step in rules:
        if applies and step not in steps:
            steps.append(step)
        if len(steps) == 3:
            break
    return steps


# ---------------------------------------------------------------- public API

def _measured_state(sec: Any, name: str = '', findings: Any = ()) -> tuple[bool, bool, str | None]:
    """(measured, partial, reason)."""
    if sec is None:
        return False, False, NOT_IN_REPORT
    if not isinstance(sec, Mapping):
        return False, False, UNEXPECTED_SHAPE
    status, coverage = sec.get('status'), sec.get('coverage')
    reason = next(iter(reason_candidates(name, sec, findings)), None)
    if status is not None and status != 'completed':
        return False, False, reason or _bare(_token(status))
    if coverage == 'not_included':
        return False, False, reason or 'not_included'
    if status is None and not set(sec) - {'coverage', 'reason', 'status'}:
        return False, False, reason or _bare(_token(coverage))
    partial = coverage != 'verified'
    return True, partial, reason or (NO_REASON if partial else None)


def _bare(token: str) -> str:
    """A status that only repeats 'not measured' gives no reason: say so plainly."""
    return NO_REASON if token in _BARE_STATUSES else token


# Section keys that hold reason codes, as a word or a list of words (both shapes are declared
# by the section pages), in the order the summary prefers them.
_REASON_KEYS = ('reason', 'truncated_by', 'cut_reasons', 'reasons', 'unverified_checks')


def _unverified(coverage: Any) -> bool:
    return coverage not in ('verified', 'not_applicable')


def reason_candidates(name: str, sec: Any, findings: Any = ()) -> list[str]:
    """Every reason code stored for a section, most specific first; never a bare status word.

    The section's own reason keys come first; then the parts a section records per row
    (context_load sources, outward-sweep regions); then the reason in the evidence of the
    section's own unverified findings; last, the check that could not be verified.
    """
    out: list[str] = []

    def add(value: Any) -> None:
        for item in (value if isinstance(value, list) else [value]):
            if isinstance(item, Mapping):
                item = item.get('code')
            token = _token(item, '')
            if token and token not in _BARE_STATUSES and token not in out:
                out.append(token)

    sec = sec if isinstance(sec, Mapping) else {}
    for key in _REASON_KEYS:
        add(sec.get(key))
    if name == 'scope':
        for region in _map(sec.get('regions')).values():
            add(_list(_map(region).get('reason_details')))
    if name == 'context_load':
        for row in _list(_map(sec.get('profile')).get('sources')):
            if isinstance(row, Mapping) and _unverified(row.get('coverage')):
                add(row.get('source'))
        if 'coverage' in _map(sec.get('external_memory_provider')) \
                and _unverified(sec['external_memory_provider']['coverage']):
            add('external_memory_provider')
        if any(isinstance(p, Mapping) and _unverified(p.get('coverage')) for p in _list(sec.get('projects'))):
            add('project_context')
    own = [f for f in _list(findings) if isinstance(f, Mapping) and _check_of(f.get('id')) == name
           and _unverified(f.get('coverage'))]
    own.sort(key=lambda f: (not f['id'].endswith('.could_not_verify'), f['id']))
    for f in own:
        evidence = _map(f.get('evidence'))
        add(evidence.get('reason'))
        add(evidence.get('truncated_by'))
    if not out:
        # Last: the unverified check itself, when its name has a reviewed phrase.
        for f in own:
            rest = f['id'].rsplit('.', 1)[1]
            if rest in _REASON_PHRASES:
                add(rest)
        if own and not out and name not in SECTION_TITLES:
            add(FINDINGS_UNVERIFIED)
    return out


def _coverage_word(sec: Any) -> str | None:
    """The stored coverage word of a section, or None when it has none."""
    value = sec.get('coverage') if isinstance(sec, Mapping) else None
    return value if isinstance(value, str) and _TOKEN_RE.match(value) else None


def _findings_coverage(rows: list) -> str | None:
    """The weakest coverage of a check known only from its findings; None when any has no word."""
    words = [_token(f.get('coverage'), '') or None for f in rows]
    if 'could_not_verify' in words:
        return 'could_not_verify'
    if None in words:
        return None
    return next((w for w in words if _unverified(w)), 'verified')


# Stored report entries that are not checks.
_NOT_SECTIONS = frozenset({'headline'})
_OTHER_TITLES = {'scope': 'Where the audit looked'}
OTHER_HEADLINE = 'The details of this check are in --json.'


def _other_title(name: str) -> str:
    return _OTHER_TITLES.get(name) or f'Other check: {name.replace("_", " ")}'


def _scope_notes(report: Mapping) -> list[str]:
    """The fixed sentences for cut or skipped parts of the outward sweep, in fixed order."""
    codes = set()
    for region in _map(_map(report.get('scope')).get('regions')).values():
        for detail in _list(_map(region).get('reason_details')):
            if isinstance(detail, Mapping) and isinstance(detail.get('code'), str):
                codes.add(detail['code'])
    return [sentence for code, sentence in _SCOPE_SENTENCES if code in codes]


def summarize(report: Any, home: str | None = None) -> dict:
    """Build the plain summary of a sealed audit report. Never raises."""
    rep = report if isinstance(report, Mapping) else {}
    raw_findings = rep.get('findings') if isinstance(rep.get('findings'), list) else []
    counts = {c: 0 for c in CLASS_ORDER}
    other = 0
    rule_ids: set = set()
    for f in raw_findings:
        cls = _classification(f.get('classification')) if isinstance(f, Mapping) else None
        if cls is not None:
            counts[cls] += 1
            if isinstance(f.get('id'), str):
                rule_ids.add(f['id'])
            if _section_of(f.get('id')) not in SECTION_TITLES:
                other += 1
    try:
        grouped = _group_findings(raw_findings)
    except Exception:  # noqa: BLE001 - a summary must never fail
        grouped = {}

    sections, not_measured, measured_names = [], [], set()
    for name in SECTION_ORDER:
        sec = rep.get(name)
        measured, partial, reason = _measured_state(sec, name, raw_findings)
        if name == 'memory_load' and _memory_nothing_found(sec):
            measured, partial, reason = True, False, None
        headline, numbers = None, {}
        if measured:
            try:
                headline, numbers = _HEADLINES[name](sec, home)
            except Exception:  # noqa: BLE001
                measured, partial, reason = False, False, UNEXPECTED_SHAPE
        if measured:
            measured_names.add(name)
        else:
            not_measured.append({'section': name, 'title': SECTION_TITLES[name], 'reason': reason})
        sections.append({
            'section': name, 'title': SECTION_TITLES[name], 'measured': measured,
            'partial': partial, 'reason': reason, 'coverage': _coverage_word(sec), 'headline': headline,
            'numbers': numbers, 'findings': {c: grouped.get(name, {}).get(c, []) for c in CLASS_ORDER},
        })
    # Checks outside the fixed order are never dropped: stored sections first, then checks
    # known only from their findings, each with its status and reason.
    stored = sorted(k for k, v in rep.items() if isinstance(k, str) and _TOKEN_RE.match(k)
                    and k not in SECTION_TITLES and k not in _NOT_SECTIONS
                    and isinstance(v, Mapping) and ('coverage' in v or 'status' in v))
    by_check: dict[str, list] = {}
    for f in raw_findings:
        prefix = _check_of(f.get('id')) if isinstance(f, Mapping) else None
        if prefix and _TOKEN_RE.match(prefix) and prefix not in SECTION_TITLES and prefix not in stored:
            by_check.setdefault(prefix, []).append(f)
    others = stored + sorted(by_check)
    try:
        grouped_other = _group_findings(raw_findings, frozenset(others))
    except Exception:  # noqa: BLE001 - a summary must never fail
        grouped_other = {}
    for name in others:
        if name in by_check:
            coverage = _findings_coverage(by_check[name])
            partial = coverage != 'verified'
            measured, reason = True, (next(iter(reason_candidates(name, {}, raw_findings)), NO_REASON)
                                      if partial else None)
        else:
            coverage = _coverage_word(rep[name])
            measured, partial, reason = _measured_state(rep[name], name, raw_findings)
        if not measured:
            not_measured.append({'section': name, 'title': _other_title(name), 'reason': reason})
        sections.append({
            'section': name, 'title': _other_title(name), 'measured': measured, 'partial': partial,
            'reason': reason, 'coverage': coverage, 'headline': OTHER_HEADLINE if measured else None,
            'numbers': {}, 'findings': {c: grouped_other.get(name, {}).get(c, []) for c in CLASS_ORDER},
        })
    try:
        biggest = _biggest_items(rep, measured_names, home)
    except Exception:  # noqa: BLE001
        biggest = []
    classes_by_section = {n: {c for c, rows in by.items() if rows} for n, by in grouped.items()}
    as_of = _num(rep.get('as_of'))
    measured_on = None
    if as_of is not None:
        try:
            measured_on = datetime.fromtimestamp(int(as_of), tz=timezone.utc).strftime('%Y-%m-%d')
        except (OverflowError, OSError, ValueError):
            measured_on = None
    return {
        'summary_version': SUMMARY_VERSION,
        'measured_on': measured_on,
        'counts': counts,
        'other_findings': other,
        'biggest_items': biggest,
        'not_measured': not_measured,
        'scope_notes': _scope_notes(rep),
        'sections': sections,
        'next_steps': _next_steps(counts, rule_ids, classes_by_section, not_measured,
                                  _live_memory(sections)),
    }


def _live_memory(sections: list) -> bool:
    """False only when the memory section was measured and found no live memory file."""
    row = next((s for s in sections if s['section'] == 'memory_load'), None)
    if not row or not row['measured']:
        return True
    return _num(row['numbers'].get('live_memory_files')) != 0


def _wrap(text: Any, indent: str, hang: str) -> list[str]:
    return textwrap.wrap(safe_text(text), width=LINE_WIDTH, initial_indent=indent,
                         subsequent_indent=hang, break_on_hyphens=False,
                         break_long_words=True) or [indent.rstrip()]


def _count(value: Any) -> int | float:
    n = _num(value)
    return n if n is not None else 0


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _map(value: Any) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _finding_line(row: Mapping) -> str:
    text = safe_text(row.get('sentence')) or MISSING_SENTENCE
    count = _count(row.get('count', 1))
    if count > 1:
        text += f' ({_int_text(count)} times)'
    ev = []
    unverified = isinstance(row.get('rule_id'), str) and row['rule_id'].endswith('.could_not_verify')
    for pair in _list(row.get('evidence')):
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and _num(pair[1]) is not None:
            key = safe_text(pair[0])
            if _INDEX_KEY_RE.search(key) or (unverified and pair[1] == 0):
                continue  # a position in a list, or a zero count, tells a reader nothing
            if key == 'cuts':
                ev.append(f'{_plural(pair[1], "part")} skipped to stay within the audit limits')
                continue
            ev.append(_evidence_text(key, pair[1]))
    if ev:
        text += ' [' + ', '.join(ev) + ']'
    return text


def _render(summary: Mapping, collapse: frozenset, warn_cap: int | None) -> tuple[list, list]:
    """(body lines, footer lines). Every string from the summary goes through safe_text."""
    counts = _map(summary.get('counts'))
    lines = [HEADER_TITLE]
    if summary.get('measured_on'):
        lines += _wrap(f'Measured on {safe_text(summary["measured_on"])} (UTC).', '', '  ')
    lines.append(f'Findings: {_plural(_count(counts.get("warning")), "warning")}, '
                 f'{_int_text(_count(counts.get("review_suggested")))} review suggested, '
                 f'{_int_text(_count(counts.get("info")))} for information.')
    if _count(summary.get('other_findings')):
        lines += _wrap(f'{_int_text(_count(summary["other_findings"]))} of these come from other '
                       'audit checks; they are listed in --json.', '', '  ')
    biggest = [b for b in _list(summary.get('biggest_items')) if isinstance(b, Mapping)]
    if biggest:
        lines.append('Biggest items:')
        for i, item in enumerate(biggest[:3], 1):
            value = human_bytes(item.get('value')) if item.get('unit') == 'bytes' \
                else f'{_int_text(_count(item.get("value")))} characters'
            text = f'{i}. {safe_text(item.get("label"))}: {value}'
            if item.get('path'):
                text += f' ({safe_text(item["path"], path=True)})'
            lines += _wrap(text, '  ', '     ')
    missing = [m for m in _list(summary.get('not_measured')) if isinstance(m, Mapping)]
    if missing:
        absent = [m for m in missing if m.get('reason') == 'not_present']
        missing = [m for m in missing if m.get('reason') != 'not_present']
        if missing:
            names = ', '.join(f'{safe_text(m.get("title"))} ({reason_phrase(m.get("reason"))})'
                              for m in missing)
            lines += _wrap(f'Not measured this time: {names}.', '', '  ')
        if absent:
            lines += _wrap('Not present in this home: '
                           + ', '.join(safe_text(m.get('title')) for m in absent) + '.', '', '  ')
    else:
        lines.append('Every section was measured.')
    for note in _list(summary.get('scope_notes')):
        lines += _wrap(note, '', '  ')
    for sec in _list(summary.get('sections')):
        if not isinstance(sec, Mapping):
            continue
        lines.append('')
        lines += _wrap(sec.get('title'), '', '  ')
        if sec.get('measured'):
            headline = safe_text(sec.get('headline'))
            if sec.get('partial'):
                headline += (' Some parts could not be checked '
                             f'({reason_phrase(sec.get("reason") or NO_REASON)}).')
            lines += _wrap(headline, '  ', '  ')
        elif sec.get('reason') == 'not_present':
            lines.append('  Nothing of this kind was found in this home.')
        else:
            lines += _wrap(f'Not measured ({reason_phrase(sec.get("reason") or NO_REASON)}).',
                           '  ', '  ')
        findings = _map(sec.get('findings'))
        for cls in CLASS_ORDER:
            rows = [r for r in _list(findings.get(cls)) if isinstance(r, Mapping)]
            if not rows:
                continue
            if (sec.get('section'), cls) in collapse:
                total = sum(_count(r.get('count', 1)) for r in rows)
                lines.append(f'  {CLASS_LABELS[cls]}: {_plural(total, "note")} (full text in --json).')
                continue
            lines.append(f'  {CLASS_LABELS[cls]}:')
            shown = rows if cls != 'warning' or warn_cap is None else rows[:warn_cap]
            for row in shown:
                lines += _wrap(_finding_line(row), '    - ', '      ')
            hidden = sum(_count(r.get('count', 1)) for r in rows[len(shown):])
            if hidden:
                lines.append(f'    {_plural(hidden, "more warning")} (full list in --json).')
    footer = ['']
    footer += _wrap(FOOTER_INTRO, '', '')
    footer.append(FOOTER_STEPS_TITLE)
    steps = [st for st in _list(summary.get('next_steps')) if isinstance(st, str)][:3]
    for i, step in enumerate(steps or [STEP_NOTHING], 1):
        footer += _wrap(f'{i}. {step}', '  ', '     ')
    footer.append(FOOTER_JSON_HINT)
    footer.append(FOOTER_CLOSE)
    return lines, footer


def _render_bounded(summary: Mapping) -> list[str]:
    # Over the soft budget, shorten note lists to a count: information notes first, then
    # "review suggested", starting from the last section. Over the hard cap, warning lists are
    # shortened too (first WARNINGS_PER_SECTION per section, then fewer), and as a last resort
    # the body is cut so the footer always fits.
    collapse: set = set()
    body, footer = _render(summary, frozenset(), None)
    names = [sec.get('section') for sec in _list(summary.get('sections')) if isinstance(sec, Mapping)]
    for step in [(n, c) for c in ('info', 'review_suggested') for n in reversed(names)]:
        if len(body) + len(footer) <= MAX_LINES:
            break
        collapse.add(step)
        body, footer = _render(summary, frozenset(collapse), None)
    for cap in (WARNINGS_PER_SECTION, 5, 1, 0):
        if len(body) + len(footer) <= MAX_LINES_HARD:
            break
        body, footer = _render(summary, frozenset(collapse), cap)
    if len(body) + len(footer) > MAX_LINES_HARD:
        footer = footer[-(MAX_LINES_HARD // 2):]
        body = body[:MAX_LINES_HARD - len(footer) - 1] + [MORE_LINES]
    # Backstop: nothing unsafe survives, whatever path a string took.
    return [safe_text(line) for line in body + footer]


def render_text(summary: Any) -> str:
    """Render a summary from `summarize()` as plain text (no colour). Never raises."""
    try:
        if not isinstance(summary, Mapping) or not isinstance(summary.get('sections'), list):
            summary = summarize({})
        return '\n'.join(_render_bounded(summary)) + '\n'
    except Exception:  # noqa: BLE001 - a summary must never fail
        return RENDER_FAILED + '\n'
