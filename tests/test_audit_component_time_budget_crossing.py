"""State that must cross the component time-budget boundary exactly as in-process.

The bounded child is a fresh interpreter. These tests pin that the redaction
taint, the evidence serializer key, the audit key and run-time module values
reach the child, and that what the child adds or removes reaches the parent's
sealing the same way as an in-process call. Synthetic values only.
"""
from __future__ import annotations

import json
import os
import sys
import sqlite3
from pathlib import Path

from tests.conftest import load_submodule
from tests.test_audit_component_time_budget import _both, _no_system_gitconfig, _strip
from tests.test_audit_wired_sections import _home

# The bounded child imports stubs by module name. Import them as a top-level
# module so the child does not run the tests package (and its conftest set-up).
_TESTS = str(Path(__file__).resolve().parent)
if _TESTS not in sys.path:
    sys.path.append(_TESTS)
import test_audit_component_time_budget_stubs as stubs  # noqa: E402


def _bounded():
    return load_submodule('audit.bounded_call')


def _secret(tag='TAINT'):
    return stubs.secret(tag + '-7f3a9c')


def _both_modes(fn, **kwargs):
    """fn(**kwargs) bounded and in-process, each in its own fresh redaction scope."""
    redaction = load_submodule('audit.redaction')
    bounded = _bounded()
    out = []
    for local in (False, True):
        @redaction.redaction_scope
        def run():
            state = redaction._CURRENT.get()
            if callable(_SETUP[0]):
                _SETUP[0](state)
            if local:
                with bounded.in_process():
                    result = bounded.invoke(fn, dict(kwargs))
            else:
                with bounded.budgets(20.0, 60.0):
                    result = bounded.invoke(fn, dict(kwargs))
            return result, _snapshot(state)
        out.append(run())
    return out


_SETUP = [None]


def _snapshot(state):
    return {
        'values': sorted(state.values), 'exact': sorted(state.exact_values),
        'withheld': sorted(state.withheld_sources), 'credential_paths': sorted(state.credential_paths),
        'credential_metadata': json.dumps(state.credential_metadata, sort_keys=True, default=str),
        'declaration_sources': sorted(getattr(state, 'declaration_sources', ())),
        'project_roots': sorted(state.serializer._project_roots),
        'redactions': sorted((str(k), sorted(map(str, v))) for k, v in state.redactions.items()),
    }


def test_parent_declared_credential_path_is_seen_by_the_child(tmp_path):
    target = tmp_path / 'notes' / 'plain.txt'
    _SETUP[0] = lambda state: state.credential_paths.add(os.path.abspath(target))
    try:
        (bounded_result, bounded_state), (local_result, local_state) = _both_modes(stubs.is_credential, path=str(target))
    finally:
        _SETUP[0] = None
    assert local_result == {'credential': True}
    assert bounded_result == local_result
    assert bounded_state == local_state


def test_child_declarations_metadata_and_taint_reach_the_parent(tmp_path):
    declared = tmp_path / 'found-store'
    skipped = tmp_path / 'skipped.json'
    skipped.write_text('{}')
    (bounded_result, bounded_state), (local_result, local_state) = _both_modes(
        stubs.declare, path=str(declared), skipped=str(skipped))
    assert bounded_result == local_result == {'ok': True}
    assert os.path.abspath(declared) in local_state['credential_paths']
    assert str(skipped) in local_state['credential_metadata']
    assert any(_secret('CHILD') in value for value in local_state['values'])
    assert bounded_state == local_state


def test_child_removal_from_taint_reaches_the_parent(tmp_path):
    target = tmp_path / 'was-credential'
    _SETUP[0] = lambda state: state.credential_paths.add(os.path.abspath(target))
    try:
        (_, bounded_state), (_, local_state) = _both_modes(stubs.forget, path=str(target))
    finally:
        _SETUP[0] = None
    assert os.path.abspath(target) not in local_state['credential_paths']
    assert bounded_state == local_state


def test_child_seals_with_the_parent_serializer_key():
    redaction = load_submodule('audit.redaction')
    bounded = _bounded()

    @redaction.redaction_scope
    def run():
        with bounded.budgets(20.0, 60.0):
            child = bounded.invoke(stubs.seal, {'value': 'synthetic-provider'})
        with bounded.in_process():
            local = bounded.invoke(stubs.seal, {'value': 'synthetic-provider'})
        return child, local
    child, local = run()
    assert child == local
    assert type(child['provider']) is type(local['provider'])  # still factory-sealed evidence
    assert child['provider']['kind'] == 'text' and len(child['provider']['hmac']) == 64


def test_child_taint_does_not_leak_between_calls_of_one_worker():
    redaction = load_submodule('audit.redaction')
    bounded = _bounded()
    with bounded.budgets(20.0, 60.0), bounded.audit_call_scope() as session:
        @redaction.redaction_scope
        def first():
            redaction._CURRENT.get().add(_secret('FIRST'))
            return bounded.invoke(stubs.taint_values, {})

        @redaction.redaction_scope
        def second():
            return bounded.invoke(stubs.taint_values, {})
        one = first()
        two = second()
        no_scope = bounded.invoke(stubs.taint_values, {})
        assert session.starts == 1
    assert any(_secret('FIRST') in value for value in one)
    assert not any(_secret('FIRST') in value for value in two)
    assert no_scope is None


def test_audit_key_crosses_and_is_cleared():
    key = load_submodule('audit.key')
    bounded = _bounded()
    raw = bytes(range(32))
    with bounded.budgets(20.0, 60.0), bounded.audit_call_scope():
        token = key._CURRENT_KEY_BYTES.set(raw)
        path_token = key._CURRENT_KEY_PATH.set(None)
        try:
            inside = bounded.invoke(stubs.key_bytes, {})
        finally:
            key._CURRENT_KEY_BYTES.reset(token)
            key._CURRENT_KEY_PATH.reset(path_token)
        after = bounded.invoke(stubs.key_bytes, {})
    assert inside == raw
    assert after is None


def test_run_time_module_values_cross_and_are_restored(monkeypatch):
    module = load_submodule('audit.session_contamination')
    bounded = _bounded()
    original = module.MAX_MESSAGES
    context_load = load_submodule('audit.context_load')
    with bounded.budgets(20.0, 60.0), bounded.audit_call_scope() as session:
        monkeypatch.setattr(module, 'MAX_MESSAGES', 4)
        monkeypatch.setattr(context_load, 'unverified_context_load', stubs.echo)
        patched = (bounded.invoke(stubs.session_limit, {}), bounded.invoke(stubs.bound_name, {}))
        monkeypatch.undo()
        restored = (bounded.invoke(stubs.session_limit, {}), bounded.invoke(stubs.bound_name, {}))
        assert session.starts == 1
    assert patched == (4, 'echo')
    assert restored == (original, 'unverified_context_load')


def _store_dump(path):
    with sqlite3.connect(path) as conn:
        dumped = '\n'.join(conn.iterdump())
    conn.close()
    return dumped


def test_taint_observed_in_the_child_seals_the_report_like_in_process(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home, project = _home(tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(monkeypatch, tmp_path)
    args = {'action': 'run', 'root': str(project), 'as_of': 1800000000}
    secret = _secret('SEAL')

    monkeypatch.setattr(surface.memory, 'audit_profile_memory', stubs.memory_not_observing)
    (tmp_path / 'control').mkdir()
    control = surface.execute_audit(args, db_path=tmp_path / 'control' / 'audit.db', wait=True)

    monkeypatch.setattr(surface.memory, 'audit_profile_memory', stubs.memory_observing)
    for sub in ('sealed/plain', 'sealed/bounded'):
        (tmp_path / sub).mkdir(parents=True)
    plain, bounded_run = _both(tmp_path / 'sealed', args)
    for run, db in ((plain, 'sealed/plain'), (bounded_run, 'sealed/bounded')):
        assert secret not in json.dumps(run)
        assert secret not in _store_dump(tmp_path / db / 'audit.db')
    # The observation is what sealed it: without it the report differs.
    memory_findings = lambda report: [f for f in report['findings'] if f.get('id') == 'memory.unverified']  # noqa: E731
    assert _strip(memory_findings(control['report'])) != _strip(memory_findings(bounded_run['report']))
