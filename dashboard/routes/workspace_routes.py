"""Plugin-local workspace routes; staged objects never come from the client."""
from __future__ import annotations

import dataclasses
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, HTTPException

from ... import (
    catalog_list,
    componentize_bridge,
    kit_scaffold,
    matcher,
    prompt_parse,
    questionnaire,
    scaffolder,
    templates,
    workspace_root,
)
from ...state_store import StateDirNotWritable
from . import accept_jobs

router = APIRouter()

# A failed write (read-only folder, full disk, locked or read-only state database) is
# answered with this one sentence: never the exception text or a path the caller did not send.
WRITE_ERRORS = (OSError, sqlite3.Error, StateDirNotWritable)
WRITE_FAILED = ('The change could not be saved because a file or the Defuzz state could not be '
                'read or written; check folder permissions and free disk space, then try again.')


def _error_text(exc: BaseException) -> str:
    return WRITE_FAILED if isinstance(exc, WRITE_ERRORS) else str(exc)
_PROPOSALS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()
_MAX_PROPOSALS = 32
_PROPOSAL_TTL_S = 30 * 60.0  # a ready proposal nobody accepts or discards is dropped after this
_KIT_CACHE_TTL_S = 30.0
_KIT_NEGATIVE_CACHE_TTL_S = 5.0
_KIT_CACHE: tuple[float, tuple[list[matcher.KitInfo], str, str]] | None = None
_KIT_SKIPPED: list[int] = []  # malformed entries in the cached kit list ([] = none)


def _reset_kit_cache_for_tests() -> None:
    global _KIT_CACHE
    with _LOCK:
        _KIT_CACHE = None
        _KIT_SKIPPED.clear()


def _active_home() -> str:
    """The Hermes home this request runs under; a proposal is only usable from the same one."""
    from hermes_constants import get_hermes_home
    try:
        return str(get_hermes_home().resolve())
    except (OSError, RuntimeError):
        return str(get_hermes_home())


def _new_row(kind: str) -> dict[str, Any]:
    return {'state': 'staging', 'kind': kind, 'proposal': None,
            'created': time.monotonic(), 'home': _active_home()}


def _take_expired_locked() -> list[dict[str, Any]]:
    """Remove ready proposals older than the time limit; call with _LOCK held.

    Only 'ready' rows expire: one being accepted, discarded or staged, or one kept
    for inspection after a partial creation, is never removed here, nor one whose
    accept job still runs or whose answer is still kept (lock order: _LOCK, then the jobs lock)."""
    now = time.monotonic()
    expired = [pid for pid, row in _PROPOSALS.items()
               if row.get('state') == 'ready' and now - row.get('created', now) >= _PROPOSAL_TTL_S
               and not accept_jobs.protects(pid)]
    return [_PROPOSALS.pop(pid) for pid in expired]


def _discard_expired(rows: list[dict[str, Any]]) -> None:
    """Remove the staging folders of expired proposals; a failure leaves the folder behind."""
    for row in rows:
        proposal = row.get('proposal')
        if proposal is None:
            continue
        try:
            if row.get('kind') == 'kit':
                kit_scaffold.discard_kit(proposal)
            else:
                scaffolder.discard(proposal)
        except Exception:
            pass


def _reserve(kind: str) -> str:
    proposal_id = uuid.uuid4().hex
    row = _new_row(kind)
    with _LOCK:
        expired = _take_expired_locked()
        full = len(_PROPOSALS) >= _MAX_PROPOSALS
        if not full:
            _PROPOSALS[proposal_id] = row
    _discard_expired(expired)
    if full:
        raise HTTPException(429, 'Discard an existing proposal before staging another')
    return proposal_id


def _object(body):
    if not isinstance(body, dict):
        raise HTTPException(400, 'Request body must be an object')
    return body


def _text(body, key):
    val = body.get(key)
    if not isinstance(val, str) or not val.strip():
        raise HTTPException(400, f'{key} must be a non-empty string')
    return val


def _json(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _json(dataclasses.asdict(value))
    if isinstance(value, Path):
        return str(value)
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {k: _json(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json(v) for v in value]
    return value


@router.post('/scaffold/parse-idea')
def parse_idea(body: Any = Body(default_factory=dict)):
    return prompt_parse.parse_deterministic(_text(_object(body), 'prompt')).as_json()


def _answers(body):
    answers = body.get('answers', {})
    if not isinstance(answers, dict):
        raise HTTPException(400, 'answers must be an object')
    return answers


def _match_json(match):
    spec = match.template
    from ...state_store import state_db_path
    picks = scaffolder._resolve_template_options(spec.options, None, template_id=spec.id, db_path=state_db_path())
    option_cards = _json(spec.options)
    for key, value in picks.items():
        option_cards[key]['default'] = value
    return {'template_id': spec.id, 'name': spec.name, 'summary': spec.summary,
            'score': match.score, 'reasons': match.reasons, 'needs': match.needs,
            'options': option_cards}


def _kit_catalog_json(kit_info: matcher.KitInfo) -> dict[str, Any]:
    return {
        'kit_id': kit_info.id,
        'name': kit_info.name,
        'summary': kit_info.summary,
        'tags': list(kit_info.tags),
    }


def _kit_match_json(kit_match: matcher.KitMatch) -> dict[str, Any]:
    return {
        **_kit_catalog_json(kit_match.kit),
        'score': kit_match.score,
        'reasons': list(kit_match.reasons),
    }


def _notice(res: Any, fallback: str) -> str:
    raw = res.get('notice') if isinstance(res, dict) else None
    text = str(raw).strip() if isinstance(raw, str) else ''
    return text or fallback


_MATCH_KIT_TIMEOUT_S = 5
def _load_kit_catalog(timeout: float | None = None) -> tuple[list[matcher.KitInfo], str, str]:
    global _KIT_CACHE
    now = time.monotonic()
    with _LOCK:
        if _KIT_CACHE is not None:
            cached_at, (cached_infos, cached_notice, cached_status) = _KIT_CACHE
            ttl = _KIT_CACHE_TTL_S if cached_status == 'ok' else _KIT_NEGATIVE_CACHE_TTL_S
            if (now - cached_at) < ttl:
                return list(cached_infos), cached_notice, cached_status
    try:
        reply = componentize_bridge.kit_list(timeout=timeout)
    except Exception:
        reply = {'status': 'error', 'data': None, 'notice': 'componentize kit list failed.'}
    parsed = matcher.parse_kit_list_detailed(reply)
    infos, notice, status = parsed.infos, parsed.notice, parsed.status
    with _LOCK:
        _KIT_CACHE = (time.monotonic(), (infos, notice, status))
        _KIT_SKIPPED[:] = [parsed.skipped]
    return list(infos), notice, status


def _catalog_kits_notice(status: str, notice: str, dropped: Any = None) -> str:
    """The pick-list's kit notice line, counting malformed entries in the cached list
    and the entries the pick-list builder left out (``dropped``)."""
    with _LOCK:
        skipped = _KIT_SKIPPED[0] if _KIT_SKIPPED else 0
    dropped = dropped or {}
    return catalog_list.kits_notice_line(
        status, notice, skipped + dropped.get('kit', 0), templates_skipped=dropped.get('template', 0))


_CATALOG_FAILED_NOTICE = 'The project list could not be built.'


def _catalog_json(specs: Any, kit_infos: Any, matches: Any, kit_matches: Any, preferred: Any,
                  kit_status: str, kits_notice: str) -> dict[str, Any]:
    """The whole pick-list for the desktop page; never raises."""
    try:
        if specs is None:
            specs = templates.load_templates()
        entries, dropped = catalog_list.build_catalog_counted(specs, kit_infos)
        suggested = catalog_list.suggested_ids(entries, matches, kit_matches, preferred)
        notice = _catalog_kits_notice(kit_status, kits_notice, dropped)
        return catalog_list.to_json(entries, suggested=suggested, notice=notice)
    except Exception:
        return {'entries': [], 'suggested': [], 'notice': _CATALOG_FAILED_NOTICE}


@router.post('/scaffold/match')
def match_templates(body: Any = Body(default_factory=dict)):
    body = _object(body)
    answers = _answers(body)
    raw_prompt = body.get('prompt', '')
    if raw_prompt is None:
        raw_prompt = ''
    if not isinstance(raw_prompt, str):
        raise HTTPException(400, 'prompt must be a string')
    languages_chosen = body.get('languages_chosen') is True

    parsed = prompt_parse.parse_deterministic(raw_prompt) if raw_prompt.strip() else None
    if parsed is not None and parsed.not_a_project_request:
        kit_infos, kits_notice, kit_status = _load_kit_catalog(_MATCH_KIT_TIMEOUT_S)
        catalog = _catalog_json(None, kit_infos, (), (), 'none', kit_status, kits_notice)
        return {
            'matches': [],
            'closest': [],
            'handoff': None,
            'kits': [],
            'kit_catalog': [_kit_catalog_json(ki) for ki in kit_infos],
            'kits_notice': kits_notice,
            'preferred': 'none',
            'message': 'This does not look like a request to set up a new project.',
            'catalog': catalog,
        }

    # languages_chosen means the user edited the Tech-stack menu, so these
    # answers are explicit choices, not automatic defaults. When it is not true,
    # values parsed from the prompt win over caller-supplied building, layout,
    # languages, and engine (caller values only fill what the prompt did not determine).
    eff_answers = prompt_parse.merge_parsed_answers(
        parsed, answers, caller_wins=bool(languages_chosen is True)
    )

    explicit_code = prompt_parse.explicit_code_from(
        parsed, answers if languages_chosen else None
    )

    specs = templates.load_templates()
    selectable_specs = [s for s in specs if not catalog_list.coming_soon_message("template", s.id)]
    matches = matcher.best_matches(selectable_specs, eff_answers, prompt=raw_prompt, explicit_code=explicit_code)
    kit_infos, kits_notice, kit_status = _load_kit_catalog(_MATCH_KIT_TIMEOUT_S)
    kit_catalog_unavailable = kit_status != 'ok'
    kit_matches = matcher.match_kits([k for k in kit_infos if not catalog_list.coming_soon_message("kit", k.id)], raw_prompt, eff_answers)
    preferred, _best = matcher.choose_catalog_entry(
        matches, kit_matches, eff_answers, explicit_code=explicit_code
    )

    suppress_code_fallback = preferred == 'kit' or (
        questionnaire.is_kit_kind(eff_answers) and not kit_catalog_unavailable
    )
    near = None if (matches or suppress_code_fallback) else matcher.closest(selectable_specs, eff_answers)
    from ...handoff import build_handoff
    return {
        'matches': [_match_json(m) for m in matches],
        'closest': [_match_json(near)] if near else [],
        'handoff': (
            build_handoff(eff_answers, near, templates_root=templates.templates_root())
            if not matches and not suppress_code_fallback
            else None
        ),
        'kits': [_kit_match_json(km) for km in kit_matches],
        'kit_catalog': [_kit_catalog_json(ki) for ki in kit_infos],
        'kits_notice': kits_notice,
        'preferred': preferred,
        'catalog': _catalog_json(
            specs, kit_infos, matches, kit_matches, preferred, kit_status, kits_notice,
        ),
    }


@router.get('/scaffold/kits/{kit_id}')
def get_kit_details(kit_id: str):
    refusal = catalog_list.coming_soon_message("kit", kit_id)
    if refusal:
        raise HTTPException(409, refusal)
    if componentize_bridge._validate_kit_id(kit_id) is not None:
        raise HTTPException(404, 'Unknown kit_id')
    kit_infos, list_notice, list_status = _load_kit_catalog()
    if list_status == 'unavailable':
        raise HTTPException(503, list_notice or componentize_bridge.UNAVAILABLE_NOTICE)
    if list_status != 'ok':
        raise HTTPException(502, list_notice or 'componentize kit list failed.')
    if not any(k.id == kit_id for k in kit_infos):
        raise HTTPException(404, 'Unknown kit_id')
    res = componentize_bridge.kit_show(kit_id)
    status = res.get('status') if isinstance(res, dict) else 'error'
    if status == 'unavailable':
        raise HTTPException(503, _notice(res, componentize_bridge.UNAVAILABLE_NOTICE))
    if status != 'ok' or not isinstance(res.get('data'), dict):
        raise HTTPException(502, _notice(res, 'componentize kit show failed.'))
    data = res['data']
    return {
        'kit': data['kit'],
        'tree': data['tree'],
        'declared_dirs': data['declared_dirs'],
        'placement_rules': data['placement_rules'],
    }


@router.get('/scaffold/projects-root')
def get_projects_root(candidate: str | None = None):
    res = workspace_root.resolve_projects_root()
    default_dir = workspace_root.default_projects_root()
    payload: dict[str, Any] = {
        'path': str(res.path) if res.path is not None else None,
        'source': res.source,
        'valid': res.path is not None or res.source == 'unset',
        'default_path': str(default_dir),
        'message': res.message,
    }
    if candidate is not None:
        try:
            validated = workspace_root.validate_projects_root(
                candidate,
                allow_relative=False,
                source_label='projects folder',
            )
            payload['candidate'] = {
                'valid': True,
                'path': str(validated),
                'message': '',
            }
        except workspace_root.WorkspaceRootError as exc:
            payload['candidate'] = {
                'valid': False,
                'path': None,
                'message': str(exc),
            }
    return payload


@router.post('/scaffold/propose')
def propose_project(body: Any = Body(default_factory=dict)):
    body = _object(body)
    raw_template_id = body.get('template_id')
    raw_kit_id = body.get('kit_id')
    has_template = raw_template_id is not None and (not isinstance(raw_template_id, str) or bool(raw_template_id.strip()))
    has_kit = raw_kit_id is not None and (not isinstance(raw_kit_id, str) or bool(raw_kit_id.strip()))
    if has_template == has_kit:
        raise HTTPException(400, 'Specify exactly one of template_id or kit_id')

    for kind in ('kit', 'template'):
        refusal = catalog_list.coming_soon_message(kind, body.get(f'{kind}_id'))
        if refusal:
            raise HTTPException(409, refusal)
    name = _text(body, 'name')
    answers = _answers(body)
    raw_dest_root = body.get('dest_root')
    if raw_dest_root is not None and not isinstance(raw_dest_root, str):
        raise HTTPException(400, 'dest_root must be a path string')
    try:
        resolved_dest = workspace_root.ensure_projects_root(
            cli_root=raw_dest_root,
            allow_cli_relative=False,
            interactive=False,
        )
    except workspace_root.WorkspaceRootError as exc:
        raise HTTPException(400, str(exc)) from exc

    if has_kit:
        kit_id = _text(body, 'kit_id')
        variables = body.get('variables')
        proposal_id = _reserve('kit')
        try:
            proposal = kit_scaffold.propose_kit(
                kit_id,
                name,
                answers,
                dest_root=str(resolved_dest),
                variables=variables,
                bridge=componentize_bridge,
            )
        except kit_scaffold.KitUnavailable as exc:
            with _LOCK:
                _PROPOSALS.pop(proposal_id, None)
            raise HTTPException(503, str(exc)) from exc
        except Exception as exc:
            with _LOCK:
                _PROPOSALS.pop(proposal_id, None)
            raise HTTPException(400, _error_text(exc)) from exc
        with _LOCK:
            _PROPOSALS[proposal_id].update(state='ready', kind='kit', proposal=proposal, created=time.monotonic())
        return {
            'proposal_id': proposal_id,
            'kind': 'kit',
            'kit_id': proposal.kit_id,
            'slug': proposal.slug,
            'tree': [{'name': proposal.slug, 'dest': str(proposal.dest), 'files': list(proposal.tree)}],
            'declared_dirs': _json(proposal.declared_dirs),
            'placement_rules': _json(proposal.placement_rules),
            'folder_note': getattr(proposal, 'folder_note', ''),
        }

    template_id = _text(body, 'template_id')
    options = body.get('options', {})
    remember = body.get('remember_options', True)
    if not isinstance(remember, bool):
        raise HTTPException(400, 'remember_options must be a boolean')
    if not isinstance(options, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in options.items()):
        raise HTTPException(400, 'options must map keys to choices')
    spec = next((s for s in templates.load_templates() if s.id == template_id), None)
    if spec is None:
        raise HTTPException(404, 'Unknown template_id')
    # Reserve a slot before staging, bounding abandoned proposals without deleting
    # user-inspectable failed checks automatically.
    proposal_id = _reserve('template')
    try:
        from ...state_store import state_db_path
        proposal = scaffolder.propose(spec, name, answers, options=options,
                                      db_path=state_db_path(), dest_root=str(resolved_dest))
    except Exception as exc:
        with _LOCK:
            _PROPOSALS.pop(proposal_id, None)
        raise HTTPException(400, _error_text(exc)) from exc
    with _LOCK:
        _PROPOSALS[proposal_id].update(state='ready', kind='template', proposal=proposal, remember_options=remember,
                                       created=time.monotonic())
    payload = _json(proposal)
    payload.update(proposal_id=proposal_id, tree=[{'name': r.name, 'dest': str(r.dest), 'files': r.tree} for r in proposal.repos])
    return payload


def _claim(body, state) -> tuple[str, Any]:
    proposal_id = _text(_object(body), 'proposal_id')
    home = _active_home()
    with _LOCK:
        expired = _take_expired_locked()
        row = _PROPOSALS.get(proposal_id)
        # A proposal made under another Hermes home is treated as unknown here.
        if row is None or row.get('home') != home:
            row = None
        claimed = row is not None and row['state'] == 'ready'
        if claimed:
            row['state'] = state
    _discard_expired(expired)
    if row is None:
        raise HTTPException(404, 'Unknown or consumed proposal_id')
    if not claimed:
        raise HTTPException(409, 'Proposal is busy or requires inspection after partial creation')
    return proposal_id, row['proposal']


def _accept_targets(proposal: Any, is_kit: bool) -> list[tuple[Path, Path]]:
    """(destination, staged folder) for each project folder an accept moves into place."""
    if is_kit:
        return [(Path(proposal.dest), Path(proposal.staged))]
    return [(Path(r.dest), Path(r.staged)) for r in proposal.repos]


def _missing_parents(proposal: Any, is_kit: bool) -> list[Path]:
    """Folders between the folder recorded at preview time and each destination that do not
    exist yet: an accept creates them before the move."""
    plans = [proposal] if is_kit else list(proposal.repos)
    missing: list[Path] = []
    for plan in plans:
        pin = getattr(plan, 'dest_anchor', None)
        if not pin:
            continue
        anchor = Path(pin[0])
        parent = Path(os.path.abspath(os.fspath(plan.dest))).parent
        while parent != anchor and anchor in parent.parents:
            if not os.path.lexists(parent) and parent not in missing:
                missing.append(parent)
            parent = parent.parent
    return missing


def _on_disk(targets: list[tuple[Path, Path]]) -> list[tuple[bool, bool]]:
    return [(os.path.lexists(dest), os.path.lexists(staged)) for dest, staged in targets]


# The scaffolder's message when the projects folder changed during the move names the
# folder to check; that is where the project ended up.
_MOVED_ELSEWHERE = re.compile(r'Check (.+?) and remove anything you do not want')


def _left_on_disk(targets: list[tuple[Path, Path]], before: list[tuple[bool, bool]],
                  exc: BaseException, missing: list[Path] | None = None) -> list[str]:
    """Folders a failed accept left behind: a destination that now exists, a staged folder
    that was moved away (reported where the scaffolder says it went), and a folder above a
    destination that the accept created and that is still there (seen on disk, or named by
    the error's own `created_dirs`)."""
    left: list[str] = []
    for (dest, staged), (had_dest, had_staged), (has_dest, has_staged) in zip(targets, before, _on_disk(targets)):
        if has_dest and not had_dest:
            left.append(str(dest))
        elif had_staged and not has_staged:
            moved = _MOVED_ELSEWHERE.search(str(exc))
            left.append(moved.group(1) if moved else str(dest))
    named = [Path(p) for p in (getattr(exc, 'created_dirs', None) or [])]
    for folder in sorted({*(missing or []), *named}, key=lambda p: len(p.parts)):
        covered = any(Path(p) == folder or folder in Path(p).parents or Path(p) in folder.parents for p in left)
        if not covered and os.path.lexists(folder):
            left.append(str(folder))
    return left


@router.post('/scaffold/accept')
def accept_project(body: Any = Body(default_factory=dict)):
    if _object(body).get('confirm') is not True:
        raise HTTPException(400, 'Explicit confirm:true is required')
    # Starts the accept in a worker thread, waits up to accept_jobs.ACCEPT_INLINE_WAIT_S,
    # then answers as before or 202 {"status": "running", ...}.
    return accept_jobs.accept_answer(_text(body, 'proposal_id'), _active_home(),
                                     claim=lambda: _claim(body, 'accepting'), work=_accept_claimed)


def _accept_claimed(claimed: tuple[str, Any], token: accept_jobs.CancelToken):
    proposal_id, proposal = claimed
    is_kit = _PROPOSALS[proposal_id].get('kind') == 'kit'
    targets = _accept_targets(proposal, is_kit)
    before = _on_disk(targets)
    missing = _missing_parents(proposal, is_kit)
    try:
        from ...state_store import state_db_path
        if is_kit:
            result = kit_scaffold.accept_kit(
                proposal,
                db_path=state_db_path(),
                bridge=componentize_bridge,
                **token.kwargs_for(kit_scaffold.accept_kit),
            )
        else:
            result = scaffolder.accept(
                proposal,
                db_path=state_db_path(),
                remember_options=_PROPOSALS[proposal_id]['remember_options'],
                **token.kwargs_for(scaffolder.accept),
            )
    except BaseException as exc:
        # Preserve staged-check failure evidence. Once a project folder was moved into
        # place the proposal is kept for inspection: a retry would only find it there.
        # An interrupt (KeyboardInterrupt, SystemExit) is recorded the same way, so the
        # proposal is never left 'accepting', and then goes on unchanged.
        created = _left_on_disk(targets, before, exc, missing)
        with _LOCK:
            _PROPOSALS[proposal_id]['state'] = 'partial' if created else 'ready'
        if not isinstance(exc, Exception):
            raise
        raise HTTPException(409, {'error': _error_text(exc), 'output': getattr(exc, 'output', ''),
                                 'keep_staging': getattr(exc, 'keep_staging', False),
                                 'created_dirs': created,
                                 'accepted_repos': _json(getattr(exc, 'accepted_repos', []))}) from exc
    with _LOCK:
        _PROPOSALS.pop(proposal_id, None)
    res_json: dict[str, Any] = _json(result)
    if is_kit:
        return {
            'status': 'created',
            'kind': 'kit',
            'kit_id': proposal.kit_id,
            'dest': str(proposal.dest),
            'path': str(proposal.dest),
            'placement': 'on',
            **res_json,
        }
    return {'status': 'created', **res_json}


@router.get('/scaffold/accept/{proposal_id}')
def accept_status(proposal_id: str):
    answer = accept_jobs.status(proposal_id, _active_home())
    if answer is None:
        raise HTTPException(404, 'Unknown or consumed proposal_id')
    return answer


@router.post('/scaffold/cancel')
def cancel_accept(body: Any = Body(default_factory=dict)):
    proposal_id = _text(_object(body), 'proposal_id')
    home = _active_home()
    answer = accept_jobs.cancel(proposal_id, home)
    if answer is None:
        with _LOCK:
            row = _PROPOSALS.get(proposal_id)
            known = row is not None and row.get('home') == home
        if not known:
            raise HTTPException(404, 'Unknown or consumed proposal_id')
        answer = {'status': 'idle', 'proposal_id': proposal_id}
    return answer


@router.post('/scaffold/discard')
def discard_project(body: Any = Body(default_factory=dict)):
    proposal_id, proposal = _claim(body, 'discarding')
    is_kit = _PROPOSALS[proposal_id].get('kind') == 'kit'
    try:
        if is_kit:
            kit_scaffold.discard_kit(proposal)
        else:
            scaffolder.discard(proposal)
    except Exception as exc:
        with _LOCK:
            _PROPOSALS[proposal_id]['state'] = 'ready'
        raise HTTPException(409, _error_text(exc)) from exc
    with _LOCK:
        _PROPOSALS.pop(proposal_id, None)
    accept_jobs.forget(proposal_id)
    return {'status': 'discarded'}


@router.get('/workspace/projects')
def workspace_projects():
    from hermes_constants import get_hermes_home
    from ...audit.readonly_db import read_profile_registrations_readonly
    from ...state_store import split_registered_projects
    snapshot = read_profile_registrations_readonly('active', get_hermes_home())
    projects, unavailable = split_registered_projects(snapshot.records)
    return {'projects': projects, 'unavailable_projects': unavailable,
            'coverage': snapshot.coverage}


@router.post('/workspace/projects/forget')
def forget_workspace_project(body: Any = Body(default_factory=dict)):
    """Forget one registration in the active profile; the project folder itself is never touched."""
    from ...state_store import forget_project, state_db_path
    body = _object(body)
    raw_path = body.get('path')
    if not isinstance(raw_path, str) or not raw_path or '\x00' in raw_path:
        raise HTTPException(400, 'path must be a non-empty NUL-free string')
    # An exact SQL registration identifier, not a filesystem path: legacy relative,
    # tilde and whitespace spellings must be passed through without normalisation.
    try:
        removed = forget_project(raw_path, db_path=state_db_path())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except WRITE_ERRORS as exc:
        raise HTTPException(400, _error_text(exc)) from exc
    return {'status': 'forgotten', 'removed': removed}


@router.get('/workspace/file')
def workspace_file(project: str, path: str):
    from ...audit.fingerprint import safe_read_regular_file_plain
    from ...audit.policy import credential_path
    from ...safety import assert_safe_root, SafetyError
    parts = Path(path).parts
    if not parts or Path(path).is_absolute() or '..' in parts or any(p.lower().startswith('.env') or p.lower() in ('auth.json', 'credentials.json', '.git') for p in parts):
        raise HTTPException(400, 'Unsafe or secret-bearing file path')
    try:
        root = assert_safe_root(project, role='workspace_root')
        from hermes_constants import get_hermes_home
        from ...audit.readonly_db import read_profile_registrations_readonly
        snapshot = read_profile_registrations_readonly('active', get_hermes_home())
        if snapshot.coverage != 'verified' or snapshot.changed_during_read:
            raise ValueError('Active-profile registrations could not be verified')
        registered = {r['canonical_path'] for r in snapshot.records}
        if str(root.resolve()) not in registered:
            raise ValueError('Project is not registered in the active profile')
        # Match the tree's conservative credential boundary, including the root's
        # own components. Registration is not permission to preview secret stores.
        if credential_path(root) or credential_path(root / path):
            raise ValueError('Unsafe or secret-bearing file path')
        read = safe_read_regular_file_plain(root, path, max_bytes=256 * 1024)
        if read.kind != 'regular' or read.coverage != 'verified' or not read.stable or read.content is None:
            raise ValueError('File cannot be safely read within the limit')
        content = read.content.decode('utf-8')
        if '\x00' in content:
            raise ValueError('Binary files are not supported')
    except WRITE_ERRORS as exc:
        raise HTTPException(400, 'The file could not be read.') from exc
    except (ValueError, SafetyError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {'project': str(root), 'path': path, 'content': content}


@router.get('/ui-state')
def get_ui_state(key: str = 'workspace'):
    from ...safe_state_store import get_entry
    from ...state_store import state_db_path
    return get_entry(state_db_path(), 'workspace-ui', key) or {'key': key, 'value': None, 'seq': 0}


@router.post('/ui-state')
def save_ui_state(body: Any = Body(default_factory=dict)):
    from ...safe_state_store import save_state, SafeStateError
    from ...state_store import state_db_path
    import json
    body = _object(body)
    key = _text(body, 'key')
    if len(key) > 128 or len(json.dumps(body)) > 65536:
        raise HTTPException(400, 'UI state exceeds size limit')
    try:
        save_state(state_db_path(), 'workspace-ui', key, body.get('value'), body.get('seq'))
    except SafeStateError as exc:
        raise HTTPException(400, str(exc)) from exc
    return get_ui_state(key)
