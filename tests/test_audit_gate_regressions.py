"""Gate regressions: synthetic evidence only."""
import re
from tests.conftest import load_submodule


def test_audit_code_values_survive_boundary(tmp_path):
    e = load_submodule('audit.evidence')
    p = load_submodule('audit.persistence')
    s = e.EvidenceSerializer()
    for value in ('audit.scope.project_tree', 'static_code.unverified',
                  'profile_context.memory_unreadable', 'session history',
                  'whole-profile identity'):
        assert s.serialize(value) == value
    (tmp_path / 'sessions').mkdir()
    (tmp_path / 'sessions' / 'one').write_text('synthetic')
    dto = p.manifest_dto({'root_path': str(tmp_path), 'files': {'sessions/one': {'size': 9}}})
    assert 'sessions/one' in dto['files']
    assert s.serialize(dto)['files'] == dto['files']


def test_audit_sealed_constructors_are_private():
    import pytest
    e = load_submodule('audit.evidence')
    with pytest.raises(TypeError):
        e.SealedEvidence(value='PROBE_GATE_FORGED_PLACEHOLDER')
    with pytest.raises(TypeError):
        e.SealedKey('PROBE_GATE_FORGED_KEY_PLACEHOLDER')


def test_audit_sealed_forgery_revalidated():
    import json
    e = load_submodule('audit.evidence')
    forged = dict.__new__(e.SealedEvidence)
    forged._canonical = json.dumps({'kind': 'text', 'hmac': 'f' * 64,
        'location': {'path': None, 'line': None}, 'value': 'PROBE_GATE_FORGED_PLACEHOLDER'})
    key = str.__new__(e.SealedKey, 'PROBE_GATE_FORGED_KEY_PLACEHOLDER')
    output = json.dumps(e.EvidenceSerializer().serialize({key: forged}))
    assert 'PROBE_GATE_FORGED_PLACEHOLDER' not in output
    assert 'PROBE_GATE_FORGED_KEY_PLACEHOLDER' not in output


def test_audit_vocabulary_is_schema_not_identifier_scrape():
    e = load_submodule('audit.evidence')
    s = e.EvidenceSerializer()
    for value in ('root', 'password', 'secret', 'repr', 'object_hook', 'compute_headline', 'on', 'off'):
        assert isinstance(s.serialize(value), e.SealedEvidence), value
    for value in ('verified', 'could_not_verify', 'review_suggested', 'completed'):
        assert s.serialize(value) == value


def test_audit_content_digest_is_keyed_per_run():
    import hashlib
    import json
    p = load_submodule('audit.persistence')
    r = load_submodule('audit.redaction')
    value = {'value': 'PROBE_GATE_DIGEST_PLACEHOLDER'}
    plain = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    @r.redaction_scope
    def run():
        first = p.digest(value)
        assert first == p.digest(value)
        assert first != plain
        return first
    assert run() != run()


def test_audit_sensitive_whole_segments():
    r = load_submodule('audit.redaction')
    for key in ('authorization', 'bearer', 'cookie', 'session_secret', 'headers.authorization'):
        assert r.sensitive(key), key
    for key in ('tokens', 'keys', 'tokenizer', 'cookies'):
        assert not r.sensitive(key), key


def test_audit_resume_control_survives_distinct_run_scopes(tmp_path):
    r = load_submodule('audit.redaction')
    store_mod = load_submodule('audit.store')
    f = load_submodule('audit.facts')
    profile = tmp_path / 'profile'
    profile.mkdir()
    (profile / 'config.yaml').write_text('{}')
    (profile / 'memories').mkdir()
    (profile / 'memories' / 'MEMORY.md').write_text('Synthetic memory')
    (profile / 'skills').mkdir()
    import sqlite3
    with sqlite3.connect(profile / 'state.db') as db:
        db.execute('CREATE TABLE sessions (id TEXT PRIMARY KEY, started_at REAL, source TEXT, title TEXT)')
        db.execute("INSERT INTO sessions VALUES ('s1', 1700000000, 'cli', 'Synthetic')")
    store = store_mod.AuditStore(tmp_path / 'audit.db')
    identity = 'PROBE_GATE_RESUME_ID_PLACEHOLDER'
    facts = f.collect_profile_unit_facts(profile_name=identity, profile_dir=profile,
        is_default=False, is_active=False, as_of=1700100000)
    @r.redaction_scope
    def prepare():
        return store.create_run(as_of=1700100000,
            planned_units=[{'unit_kind': 'profile', 'unit_id': identity}])['run_id']
    rid = prepare()
    @r.redaction_scope
    def capture():
        store.commit_unit_result(run_id=rid, unit_kind='profile', unit_id=identity,
            manifest=facts['fingerprint_manifest'], evidence=facts)
        store.cancel_run(rid)
    capture()
    @r.redaction_scope
    def resume():
        return store.resume_run(rid, current_unit_digests={
            ('profile', identity): facts['fingerprint_manifest']['unit_digest']})
    assert resume()['reused_units'] == [{'unit_kind': 'profile', 'unit_id': identity}]
    assert identity not in str(store.get_run(rid))
    import sqlite3
    with sqlite3.connect(tmp_path / 'audit.db') as db:
        assert identity not in '\n'.join(db.iterdump())


def test_audit_dto_json_revalidates_raw_bindings():
    import json
    store = load_submodule('audit.store')
    e = load_submodule('audit.evidence')
    forged = dict.__new__(e.SealedEvidence)
    forged._canonical = json.dumps({'value': 'PROBE_GATE_DTO_PLACEHOLDER'})
    dict.__setitem__(forged, 'value', 'PROBE_GATE_DTO_PLACEHOLDER')
    assert 'PROBE_GATE_DTO_PLACEHOLDER' not in store._dto_json({'evidence': forged})


def test_audit_manifest_alias_key_cannot_smuggle_text(tmp_path):
    import json
    e = load_submodule('audit.evidence')
    (tmp_path / 'existing').write_text('synthetic')
    raw = {'root_path': str(tmp_path), 'files': {
        'PROBE_GATE_MISSING_ALIAS/../existing': {'size': 9}}}
    result = e.EvidenceSerializer().serialize(raw)
    assert 'PROBE_GATE_MISSING_ALIAS' not in json.dumps(result)


def test_audit_credential_labels_are_field_scoped():
    e = load_submodule('audit.evidence')
    s = e.EvidenceSerializer()
    assert s.serialize({'config_keys': ['password']}) == {'config_keys': ['password']}
    assert isinstance(s.serialize('password'), e.SealedEvidence)
    for value in ('hardlink_target_unknown', 'external_skill_root', 'execution_path'):
        assert s.serialize(value) == value


def test_audit_reopening_store_does_not_rewrite_control_inventory(tmp_path):
    m = load_submodule('audit.store')
    first = m.AuditStore(tmp_path / 'audit.db')
    rid = first.create_run(as_of=1, active_profile='PROBE_GATE_PROFILE_PLACEHOLDER')['run_id']
    inventory = first.get_run(rid)['inventory']
    second = m.AuditStore(tmp_path / 'audit.db')
    assert second.get_run(rid)['inventory'] == inventory


def test_audit_sealed_invalid_field_types_fail_closed():
    import json
    e = load_submodule('audit.evidence')
    for raw in ({'kind': ['PROBE_GATE_BAD_KIND'], 'hmac': 'f'*64, 'location': {'path': None, 'line': None}},
                {'scheme': ['PROBE_GATE_BAD_SCHEME'], 'host': None, 'port': None}):
        forged = dict.__new__(e.SealedEvidence)
        forged._canonical = json.dumps(raw)
        assert 'PROBE_GATE_BAD_' not in json.dumps(e.EvidenceSerializer().serialize(forged))


def test_audit_public_inventory_digest_uses_run_key(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home'
    home.mkdir()
    (home / 'config.yaml').write_text('{}')
    monkeypatch.setenv('HERMES_HOME', str(home))
    store = surface.AuditStore(tmp_path / 'audit.db')
    digests = []
    for _ in range(2):
        result = surface.execute_audit({'quick': True, 'as_of': 1800000000},
            db_path=tmp_path / 'audit.db', wait=True)
        digests.append(store.get_run(result['run_id'])['inventory']['source_digest'])
    assert digests[0] != digests[1]


def test_audit_async_worker_inherits_run_serializer(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    r = load_submodule('audit.redaction')
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    states = []
    prepare = surface._prepare
    def capture_prepare(*args):
        states.append(r._CURRENT.get())
        return prepare(*args)
    def capture_sweep(*args):
        states.append(r._CURRENT.get())
    monkeypatch.setattr(surface, '_prepare', capture_prepare)
    monkeypatch.setattr(surface, '_sweep', capture_sweep)
    surface.execute_audit({'quick': True}, db_path=tmp_path / 'audit.db')
    assert surface._RUN_LOCK.acquire(timeout=10)
    surface._RUN_LOCK.release()
    assert len(states) == 2 and states[0] is not None and states[0] is states[1]
