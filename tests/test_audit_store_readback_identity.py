"""Regression tests for plugin-owned evidence readback and SQL identities."""
import json
import sqlite3

from tests import ensure_test_package
ensure_test_package()
from hermes_plugins.defuzz.audit.store import AuditStore
from hermes_plugins.defuzz.audit.contract import make_finding


def populate(tmp_path, unit_id=None):
    unit_id = unit_id or str(tmp_path)
    store = AuditStore(tmp_path / 'audit.db')
    run = store.create_run(as_of=1800000000, active_profile='PROBE_STORE_PROFILE_CANARY',
        planned_units=[{'unit_kind': 'project', 'unit_id': unit_id}])
    store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id=unit_id,
        manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'a' * 64},
        evidence={'coverage': 'verified'}, component_results=[{
            'component_id': 'test', 'coverage': 'verified', 'classification': 'info',
            'findings': [make_finding(rule_id='PROBE_STORE_FINDING_CANARY', classification='info',
                coverage='verified', evidence={'value': 'PROBE_STORE_EVIDENCE_CANARY'},
                consequence='test', limitations='test')]}])
    return store, run['run_id']


def test_store_readback_preserves_stored_sealed_form(tmp_path):
    store, rid = populate(tmp_path)
    with sqlite3.connect(store.db_path) as conn:
        stored = json.loads(conn.execute('SELECT findings_json FROM audit_unit_results').fetchone()[0])[0]
        profile = json.loads(conn.execute('SELECT active_profile FROM audit_runs').fetchone()[0])
    report = store.finalize_run(rid)['report']
    assert report['active_profile'] == profile
    assert report['findings'][0] == stored
    assert store.get_run(rid)['report'] == report
    def no_nested_tokens(value):
        if isinstance(value, dict):
            if 'hmac' in value:
                assert isinstance(value['hmac'], str)
            for item in value.values():
                no_nested_tokens(item)
        elif isinstance(value, list):
            for item in value:
                no_nested_tokens(item)
    no_nested_tokens(report)


def test_store_stale_unit_identity_all_sql_sinks_and_resume(tmp_path):
    stale = str(tmp_path / 'MISSING_PROBE_STORE_UNIT_CANARY')
    store, rid = populate(tmp_path, stale)
    with sqlite3.connect(store.db_path) as conn:
        dump = '\n'.join(conn.iterdump())
        for table in ('audit_units', 'audit_unit_results', 'audit_evidence_cache'):
            identities = conn.execute(f'SELECT unit_id FROM {table}').fetchall()
            assert identities and all(stale not in value for (value,) in identities)
    assert 'MISSING_PROBE_STORE_UNIT_CANARY' not in dump
    store.cancel_run(rid)
    resumed = store.resume_run(rid, current_unit_digests={('project', stale): 'a' * 64})
    assert resumed['reused_units'] == [{'unit_kind': 'project', 'unit_id': stale}]
    report = store.finalize_run(rid)['report']
    assert report['units'][0]['unit_id']['kind'] == 'unresolved_reference'
    assert 'MISSING_PROBE_STORE_UNIT_CANARY' not in json.dumps(report)


def test_store_generated_digests_survive_readback(tmp_path):
    from hermes_plugins.defuzz.audit.persistence import digest
    from hermes_plugins.defuzz.audit.evidence import GeneratedDigest
    assert isinstance(digest({'coverage': 'verified'}), GeneratedDigest)
    store, rid = populate(tmp_path)
    saved = store.get_run(rid)
    assert isinstance(saved['units'][0]['evidence']['raw_evidence_digest'], GeneratedDigest)
    assert isinstance(saved['units'][0]['manifest']['capture_digest'], GeneratedDigest)
    report = store.finalize_run(rid)['report']
    assert isinstance(report['findings'][0]['evidence']['source_digest'], str)
    assert isinstance(report['rule_versions']['engine_digest'], str)
    assert isinstance(report['rule_versions']['caller_rules_digest'], str)


def test_store_store_has_one_connection_path(tmp_path):
    from hermes_plugins.defuzz.audit import store as module
    assert not hasattr(module, '_connect_plugin_db')
    store = AuditStore(tmp_path / 'audit.db')
    with store._connect() as conn:
        assert type(conn) is sqlite3.Connection
        assert conn.execute('PRAGMA foreign_keys').fetchone()[0] == 1
