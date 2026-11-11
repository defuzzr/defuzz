import json
import sqlite3
import pytest
from tests import ensure_test_package
ensure_test_package()
from hermes_plugins.defuzz.audit.persistence import facts_dto, manifest_dto, finding_dto
from hermes_plugins.defuzz.audit.store import AuditStore
from hermes_plugins.defuzz.audit.contract import canonical_report_payload, canonical_report_bytes

SECRET = 'violet-marmalade-unknown-source-7391'

@pytest.mark.parametrize('field', ['name', 'unit_id', 'path'])
def test_audit_persistence_facts_content(field):
    assert SECRET not in json.dumps(facts_dto({field: SECRET}))

@pytest.mark.parametrize('field', ['unit_id', 'root_path', 'unit_digest'])
def test_audit_persistence_manifest_content(field):
    assert SECRET not in json.dumps(manifest_dto({field: SECRET}))

@pytest.mark.parametrize('field', ['affected_identities', 'source_paths'])
def test_audit_persistence_finding_content(field):
    raw = {'id': 'audit.finding', 'consequence': 'review', field: [SECRET]}
    assert SECRET not in json.dumps(finding_dto(raw))

def test_audit_store_all_sinks(tmp_path):
    db = tmp_path / 'audit.db'
    store = AuditStore(db)
    run = store.create_run(as_of=1, active_profile=SECRET, optional_root=SECRET)
    store.commit_unit_result(run_id=run['run_id'], unit_kind='profile', unit_id='default',
        manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'control-digest', 'root_path': SECRET},
        evidence={'coverage': 'verified', 'name': SECRET, 'unit_id': SECRET, 'path': SECRET})
    result = store.finalize_run(run['run_id'], extra_findings=[{'id': 'audit.finding', 'consequence': SECRET,
        'affected_identities': [SECRET], 'source_paths': [SECRET]}])
    with sqlite3.connect(db) as conn:
        dump = '\n'.join(conn.iterdump())
    for sink in (json.dumps(result), dump, db.read_bytes().decode('latin1')):
        assert SECRET not in sink


@pytest.mark.parametrize('field', ['unit_digest', 'manifest_version'])
def test_audit_store_manifest_sql_columns(tmp_path, field):
    db = tmp_path / 'audit.db'
    store = AuditStore(db)
    run = store.create_run(as_of=1)
    manifest = {'stable': True, 'coverage': 'verified', 'unit_digest': 'control-digest', field: SECRET}
    store.commit_unit_result(run_id=run['run_id'], unit_kind='profile', unit_id='default',
        manifest=manifest, evidence={'coverage': 'verified'})
    with sqlite3.connect(db) as conn:
        assert SECRET not in '\n'.join(conn.iterdump())
    assert SECRET.encode() not in db.read_bytes()


def test_audit_store_cleanup_content(tmp_path):
    db = tmp_path / 'audit.db'
    store = AuditStore(db)
    run = store.create_run(as_of=1)
    proposal = store.record_cleanup_proposal(cleanup_id='control-id', run_id=run['run_id'],
        fix_type=SECRET, target_identity=SECRET, fingerprint_digest=SECRET, plan={'source': SECRET})
    assert SECRET not in json.dumps(proposal)
    with sqlite3.connect(db) as conn:
        assert SECRET not in '\n'.join(conn.iterdump())
    assert SECRET.encode() not in db.read_bytes()


def test_audit_store_component_source_identity(tmp_path):
    db = tmp_path / 'audit.db'
    store = AuditStore(db)
    run = store.create_run(as_of=1)
    store.commit_unit_result(run_id=run['run_id'], unit_kind='profile', unit_id='default',
        manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'control'},
        evidence={'coverage': 'verified'}, component_results=[{'component_id': SECRET}])
    with sqlite3.connect(db) as conn:
        assert SECRET not in '\n'.join(conn.iterdump())
    assert SECRET.encode() not in db.read_bytes()


@pytest.mark.parametrize('content', ['a' * 64, 'kzix', 'alpha beta arbitrary'])
def test_audit_persistence_unknown_content_has_no_shape_exemption(content):
    dto = facts_dto({'name': content, 'unit_id': content, 'path': content})
    for field in ('name', 'unit_id', 'path'):
        assert isinstance(dto[field], dict)
        assert 'hmac' in dto[field] and 'location' in dto[field]
        assert content not in json.dumps(dto[field])


def test_audit_contract_determinism_is_scoped_to_one_run():
    from hermes_plugins.defuzz.audit.redaction import Taint, _CURRENT
    state = Taint()
    token = _CURRENT.set(state)
    try:
        first = canonical_report_payload(as_of=1, active_profile=SECRET)
        second = canonical_report_payload(as_of=1, active_profile=SECRET)
        assert canonical_report_bytes(first) == canonical_report_bytes(second)
    finally:
        _CURRENT.reset(token)
    other = canonical_report_payload(as_of=1, active_profile=SECRET)
    assert canonical_report_bytes(first) != canonical_report_bytes(other)


def test_audit_store_cached_content_and_requirement_controls(tmp_path):
    store = AuditStore(tmp_path / 'audit.db')
    run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'profile', 'unit_id': 'control',
        'required_components': [SECRET]}])
    store.commit_unit_result(run_id=run['run_id'], unit_kind='profile', unit_id='control',
        manifest={'stable': True, 'coverage': 'verified', 'unit_digest': SECRET},
        evidence={'coverage': 'verified', 'name': SECRET},
        component_results=[{'component_id': SECRET}])
    cached = store.get_cached_evidence(unit_kind='profile', unit_id='control', fingerprint_digest=SECRET)
    assert cached is not None
    assert SECRET not in json.dumps(cached)
    store.cancel_run(run['run_id'])
    resumed = store.resume_run(run['run_id'], current_unit_digests={('profile', 'control'): SECRET})
    assert resumed['reused_units'] == [{'unit_kind': 'profile', 'unit_id': 'control'}]
    report = store.finalize_run(run['run_id'])
    assert report['report']['headline']['can_claim_clean'] is True
    assert SECRET not in json.dumps(report)


def test_audit_store_last_gate_dto_and_report_injections(tmp_path, monkeypatch):
    from hermes_plugins.defuzz.audit import store as module
    db = tmp_path / 'audit.db'
    store = AuditStore(db)
    run = store.create_run(as_of=1)
    monkeypatch.setattr(module, 'facts_dto', lambda value: {'coverage': 'verified', 'injected': SECRET})
    monkeypatch.setattr(module, 'manifest_dto', lambda value: {'injected': SECRET})
    store.commit_unit_result(run_id=run['run_id'], unit_kind='profile', unit_id='default',
        manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'control'},
        evidence={'coverage': 'verified'})
    monkeypatch.setattr(module, 'canonical_report_payload', lambda **kwargs: {'injected': SECRET,
        'units': [{'unit_id': SECRET}], 'findings': [{'source_paths': [SECRET]}]})
    result = store.finalize_run(run['run_id'])
    assert SECRET not in json.dumps(result)
    assert SECRET not in json.dumps(store.get_run(run['run_id'])['report'])
    with sqlite3.connect(db) as conn:
        assert SECRET not in '\n'.join(conn.iterdump())
    assert SECRET.encode() not in db.read_bytes()


def test_audit_contract_direct_report_injection():
    report = canonical_report_payload(as_of=1, active_profile=SECRET,
        units=[{'unit_kind': 'profile', 'unit_id': SECRET, 'payload': SECRET}])
    assert SECRET not in json.dumps(report)
    assert SECRET.encode() not in canonical_report_bytes({'payload': SECRET})
