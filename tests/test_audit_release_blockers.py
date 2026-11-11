"""Synthetic release-blocker regressions; never inspect the host profile."""
import unittest
import tempfile
from pathlib import Path
from tests import ensure_test_package
ensure_test_package()
from hermes_plugins.defuzz.audit import contract
from hermes_plugins.defuzz.audit.store import AuditStore
from hermes_plugins.defuzz.audit.redaction import redaction_scope


class CanonicalBoundaryTests(unittest.TestCase):
    def test_tied_findings_have_total_order(self):
        a = contract.make_finding(rule_id='rule', classification='info', consequence='same', evidence={'count': 1})
        b = dict(a, evidence={'count': 2}, limitations='different')
        self.assertEqual(contract.sort_findings([a, b]), contract.sort_findings([b, a]))

    @redaction_scope
    def test_finalize_order_is_independent_of_arrival(self):
        # Freeze the run key too; independent run keys intentionally differ.
        findings = [contract.make_finding(rule_id='same', classification='info', consequence='same', evidence={'count': n}, limitations=str(n)) for n in (1, 2)]
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            outputs = []
            for seq in (findings, list(reversed(findings))):
                run = store.create_run(as_of=123, planned_units=[{'unit_kind': 'project', 'unit_id': 'p'}])
                store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                    manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'p'}, evidence={'coverage': 'verified'},
                    component_results=[{'component_id': 'check', 'coverage': 'verified', 'findings': seq}])
                outputs.append(store.finalize_run(run['run_id'])['canonical_digest'])
            self.assertEqual(*outputs)

    def test_engine_bytes_invalidate_cache_key(self):
        from unittest.mock import patch
        from hermes_plugins.defuzz.audit import store
        args = dict(unit_kind='project', unit_id='p', fingerprint_digest='d')
        before = store.compute_evidence_cache_key(**args)
        with patch('hermes_plugins.defuzz.audit.identity.engine_identity', return_value={'engine': 'changed'}):
            self.assertNotEqual(before, store.compute_evidence_cache_key(**args))

    def test_resume_invalidates_actual_engine_change_without_hint(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'project', 'unit_id': 'p'}])
            store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'p'}, evidence={'coverage': 'verified'})
            with patch('hermes_plugins.defuzz.audit.identity.engine_identity', return_value={'engine_digest': 'changed'}):
                resumed = store.resume_run(run['run_id'], current_unit_digests={('project', 'p'): 'p'})
            self.assertEqual(resumed['reused_units'], [])

    def test_non_json_and_nonfinite_rejected(self):
        for value in (object(), float('nan'), float('inf'), {1: 'x'}, {'x': {1, 2}}):
            with self.subTest(value=type(value).__name__), self.assertRaises((TypeError, ValueError)):
                contract.sanitize_evidence(value)

    def test_wrong_field_types_and_optimistic_headline_rejected(self):
        for field, value in [('id', 3), ('consequence', ['text']), ('affected_identities', 'not-a-list'), ('source_paths', [42])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.normalize_finding({'id': 'x', 'consequence': 'text', field: value})
        report = contract.canonical_report_payload(as_of=1, units=[{'unit_kind': 'project', 'unit_id': 'p', 'status': 'completed', 'coverage': 'could_not_verify'}], headline={'coverage': 'verified', 'classification': 'info', 'can_claim_clean': True})
        self.assertFalse(report['headline']['can_claim_clean'])

    def test_arbitrary_finding_field_and_nonstring_key_rejected(self):
        with self.assertRaises(ValueError):
            contract.normalize_finding({'id': object(), 'detail': 'x'})
        with self.assertRaises(ValueError):
            contract.canonical_report_bytes({1: 'x'})
        with self.assertRaises(ValueError):
            contract.make_finding(rule_id=object(), classification='info', consequence='x')

    def test_duplicate_units_rejected(self):
        unit = {'unit_kind': 'profile', 'unit_id': 'a', 'status': 'completed'}
        with self.assertRaises(ValueError):
            contract.canonical_report_payload(as_of=1, units=[unit, unit])


class ReadPolicyTests(unittest.TestCase):
    def test_credential_paths_never_open(self):
        from unittest.mock import patch
        from hermes_plugins.defuzz.audit.fingerprint import safe_read_regular_file, build_tree_fingerprint_manifest
        names = ['auth.json', 'auth.json.bak', '.env', '.env.backup', '.op.env', 'vault/key',
                 'mcp-tokens/server.json', '.aws/credentials', '.config/gcloud/token.json', 'google_token.json']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in names:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('SYNTHETIC-DO-NOT-OPEN')
            import os
            original = os.open
            def tripwire(path, *args, **kwargs):
                if str(path) in [Path(n).name for n in names]:
                    raise AssertionError('credential opened')
                return original(path, *args, **kwargs)
            with patch('os.open', side_effect=tripwire):
                for name in names:
                    result = safe_read_regular_file(root, name)
                    self.assertIsNone(result.content)
                manifest = build_tree_fingerprint_manifest(unit_kind='profile', unit_id='p', root_path=root)
                self.assertFalse(manifest.whole_profile_exact_eligible)

    def test_credential_root_is_not_opened(self):
        from unittest.mock import patch
        from hermes_plugins.defuzz.audit.fingerprint import build_tree_fingerprint_manifest
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'vault'
            root.mkdir()
            from hermes_plugins.defuzz.audit.key import key_scope
            with key_scope(Path(tmp) / 'store' / 'audit.db'), patch('os.open', side_effect=AssertionError('credential root opened')):
                manifest = build_tree_fingerprint_manifest(unit_kind='project', unit_id='p', root_path=root)
                self.assertNotEqual(manifest.coverage, 'verified')

    def test_registration_row_budget_marks_unknown(self):
        import sqlite3
        from contextlib import closing
        from unittest.mock import patch
        from hermes_plugins.defuzz.audit import readonly_db
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / 'plugin-data' / 'defuzz' / 'state.db'
            db.parent.mkdir(parents=True)
            with closing(sqlite3.connect(db)) as conn:
                conn.execute('CREATE TABLE projects (path TEXT)')
                conn.executemany('INSERT INTO projects VALUES (?)', [('/a',), ('/b',)])
                conn.commit()
            with patch.object(readonly_db, 'MAX_REGISTRATION_ROWS', 1, create=True):
                result = readonly_db.read_profile_registrations_readonly('p', root)
            self.assertEqual(result.coverage, 'could_not_verify')
            self.assertLessEqual(len(result.records), 1)

    def test_missing_registration_schema_is_unknown(self):
        import sqlite3
        from contextlib import closing
        from hermes_plugins.defuzz.audit.readonly_db import read_profile_registrations_readonly
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / 'plugin-data' / 'defuzz' / 'state.db'
            db.parent.mkdir(parents=True)
            with closing(sqlite3.connect(db)) as conn:
                conn.execute('CREATE TABLE unrelated (id INTEGER)')
                conn.commit()
            self.assertEqual(read_profile_registrations_readonly('p', root).coverage, 'could_not_verify')

    def test_yaml_dates_normalized_and_malformed_rejected(self):
        from hermes_plugins.defuzz.audit.facts import _parse_simple_yaml_mapping
        self.assertEqual(_parse_simple_yaml_mapping('date: 2026-01-02\nitems:\n  - nested: [a, b]\n')['date'], '2026-01-02')
        for text in ('a: [', 'value: .nan', '!!python/object:bad {}', '1: value'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                _parse_simple_yaml_mapping(text)


class CaptureTests(unittest.TestCase):
    def test_directory_depth_budget_marks_unknown(self):
        from hermes_plugins.defuzz.audit.fingerprint import build_tree_fingerprint_manifest
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a' / 'b').mkdir(parents=True)
            (root / 'a' / 'b' / 'x').write_text('data')
            manifest = build_tree_fingerprint_manifest(unit_kind='project', unit_id='p', root_path=root, max_depth=1)
            self.assertEqual(manifest.coverage, 'could_not_verify')
            self.assertNotIn('a/b/x', manifest.files)

    def test_same_name_different_roots_have_distinct_identity(self):
        from hermes_plugins.defuzz.audit.fingerprint import build_tree_fingerprint_manifest
        with tempfile.TemporaryDirectory() as tmp:
            digests = []
            for name in ('one', 'two'):
                root = Path(tmp) / name
                root.mkdir()
                (root / 'config.yaml').write_text('model: same\n')
                digests.append(build_tree_fingerprint_manifest(unit_kind='profile', unit_id='default', root_path=root).unit_digest)
            self.assertNotEqual(*digests)

    def test_project_capture_byte_map_and_manifest_agree(self):
        import hashlib
        from hermes_plugins.defuzz.audit import capture
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'main.py').write_text('print(1)\n')
            (root / '.env').write_text('CANARY')
            manifest, files = capture.capture_project_files(root)
            self.assertNotIn('.env', files)
            from hermes_plugins.defuzz.audit.key import content_digest
            plain = hashlib.sha256(files['main.py']['content']).hexdigest()
            self.assertNotEqual(manifest['files']['main.py']['sha256'], plain)
            self.assertEqual(manifest['files']['main.py']['sha256'], content_digest(plain))

    def test_interleaved_config_change_is_unknown_same_bytes(self):
        from unittest.mock import patch
        from hermes_plugins.defuzz.audit import facts
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'config.yaml').write_text('model: before\n')
            original = facts.resolve_profile_memory_facts
            def mutate(*args, **kwargs):
                (root / 'config.yaml').write_text('model: after\n')
                return original(*args, **kwargs)
            with patch.object(facts, 'resolve_profile_memory_facts', side_effect=mutate):
                result = facts.collect_profile_unit_facts(profile_name='p', profile_dir=root, is_active=True, is_default=False)
            self.assertFalse(result['stable'])
            self.assertEqual(result['coverage'], 'could_not_verify')
            manifest = result['fingerprint_manifest']
            self.assertEqual(manifest['config_digest'], manifest['files']['config.yaml']['sha256'])

    def test_external_skill_changes_unit_digest(self):
        from hermes_plugins.defuzz.audit.facts import collect_profile_unit_facts
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'profile'
            ext = Path(tmp) / 'external'
            root.mkdir()
            (ext / 'demo').mkdir(parents=True)
            (root / 'config.yaml').write_text('skills:\n  external_dirs:\n    - ' + str(ext) + '\n')
            skill = ext / 'demo' / 'SKILL.md'
            skill.write_text('---\nname: demo\ndescription: example\n---\nfirst')
            args = dict(profile_name='p', profile_dir=root, is_active=True, is_default=False)
            a = collect_profile_unit_facts(**args)
            skill.write_text('---\nname: demo\ndescription: example\n---\nsecond')
            b = collect_profile_unit_facts(**args)
            self.assertNotEqual(a['fingerprint_manifest']['unit_digest'], b['fingerprint_manifest']['unit_digest'])


class PersistenceTests(unittest.TestCase):
    def test_persistence_dto_rejects_structures_in_scalar_fields(self):
        from hermes_plugins.defuzz.audit.persistence import facts_dto, manifest_dto
        for fn, data in [(facts_dto, {'name': {'raw': 'CANARY'}}), (facts_dto, {'memory_bytes': 'CANARY'}),
                         (manifest_dto, {'stable': 'yes'}), (facts_dto, {'last_use_evidence': {'last_use_timestamp': 'CANARY'}})]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                fn(data)

    def test_nested_scalar_descriptors_and_direct_findings_rejected(self):
        from hermes_plugins.defuzz.audit.persistence import component_dto, manifest_dto
        for fn, data in [
            (component_dto, {'component_id': {'raw': 'CANARY'}}),
            (manifest_dto, {'files': {'x': {'size': True}}}),
            (manifest_dto, {'files': {1: {'size': 1}}}),
            (contract.normalize_finding, {'source_paths': [{'path': {'raw': 'CANARY'}}]}),
            (contract.normalize_finding, {'source_paths': [{'path': 'x', 'start_line': True}]}),
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                fn(data)
        for kwargs in ({'limitations': {'raw': 'CANARY'}}, {'affected_identities': [42]},
                       {'fix': ['CANARY']}, {'proposed_cleanup_id': {'raw': 'CANARY'}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                contract.make_finding(rule_id='check', classification='info', consequence='test', **kwargs)

    def test_canary_absent_from_database_caches_and_export(self):
        import sqlite3
        canary = 'SYNTHETIC_PRIVATE_CANARY_73'
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            run = store.create_run(as_of=1, inventory={'raw': canary}, planned_units=[{'unit_kind': 'project', 'unit_id': 'p'}])
            finding = contract.make_finding(rule_id='check', classification='info', consequence=canary, evidence={'ordinary': canary})
            store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'd', 'raw': canary},
                evidence={'coverage': 'verified', 'config': {'ordinary': canary}, 'soul': {'raw_text': canary}, 'memory': {'raw_text': canary}},
                component_results=[{'component_id': 'check', 'coverage': 'verified', 'findings': [finding], 'extra': canary}])
            result = store.finalize_run(run['run_id'], extra_findings=[finding])
            store.record_cleanup_proposal(cleanup_id='proposal', run_id=run['run_id'], fix_type='review', target_identity='p', fingerprint_digest='d', plan={'raw': canary})
            self.assertNotIn(canary, contract.canonical_report_bytes(result['report']).decode())
            from contextlib import closing
            with closing(sqlite3.connect(store.db_path)) as conn:
                self.assertNotIn(canary, '\n'.join(conn.iterdump()))
            self.assertNotIn(canary.encode(), store.db_path.read_bytes())


class CoverageTests(unittest.TestCase):
    def test_full_scope_report_discloses_real_byte_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            run = store.create_run(as_of=1, mode='full_home')
            result = store.finalize_run(run['run_id'])
            self.assertEqual(result['report']['scope']['max_file_bytes'], 10 * 1024 * 1024)
            self.assertEqual(result['report']['scope']['coverage'], 'could_not_verify')

    def test_unknown_recapture_revokes_previously_verified_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            for cov in ('verified', 'could_not_verify'):
                run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'project', 'unit_id': 'p'}])
                store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                    manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'p'}, evidence={'coverage': cov})
            self.assertIsNone(store.get_cached_evidence(unit_kind='project', unit_id='p', fingerprint_digest='p'))

    def test_cancelled_and_removed_required_units_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'project', 'unit_id': 'p'}, {'unit_kind': 'project', 'unit_id': 'q'}])
            for uid in ('p', 'q'):
                store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id=uid,
                    manifest={'stable': True, 'coverage': 'verified', 'unit_digest': uid}, evidence={'coverage': 'verified'})
            store.cancel_run(run['run_id'])
            self.assertFalse(store.finalize_run(run['run_id'])['report']['headline']['can_claim_clean'])
            store.resume_run(run['run_id'], current_unit_digests={('project', 'p'): 'p'})
            self.assertFalse(store.finalize_run(run['run_id'])['report']['headline']['can_claim_clean'])

    def test_required_collector_error_cannot_be_overridden(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'project', 'unit_id': 'p', 'required_collectors': ['config']}])
            store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'p'},
                evidence={'coverage': 'verified', 'collectors': {'config': {'coverage': 'verified', 'status': 'error'}}})
            self.assertFalse(store.finalize_run(run['run_id'])['report']['headline']['can_claim_clean'])

    def test_unknown_and_errors_never_clean_or_cached(self):
        for comp, evidence in [
            ({'component_id': 'check', 'coverage': 'could_not_verify'}, {'coverage': 'verified'}),
            ({'component_id': 'check', 'status': 'error'}, {'coverage': 'verified'}),
            ({'component_id': 'check', 'coverage': 'verified'}, {'coverage': 'could_not_verify'}),
        ]:
            with self.subTest(comp=comp, evidence=evidence), tempfile.TemporaryDirectory() as tmp:
                store = AuditStore(Path(tmp) / 'audit.db')
                run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'project', 'unit_id': 'p'}])
                store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                    manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'd'},
                    evidence=evidence, component_results=[comp])
                result = store.finalize_run(run['run_id'])
                self.assertFalse(result['report']['headline']['can_claim_clean'])
                self.assertIsNone(store.get_cached_evidence(unit_kind='project', unit_id='p', fingerprint_digest='d'))

    def test_required_missing_component_and_empty_scope_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AuditStore(Path(tmp) / 'audit.db')
            run = store.create_run(as_of=1, planned_units=[{'unit_kind': 'project', 'unit_id': 'p', 'required_components': ['check']}])
            store.commit_unit_result(run_id=run['run_id'], unit_kind='project', unit_id='p',
                manifest={'stable': True, 'coverage': 'verified', 'unit_digest': 'd'}, evidence={'coverage': 'verified'})
            self.assertFalse(store.finalize_run(run['run_id'])['report']['headline']['can_claim_clean'])
            empty = store.create_run(as_of=1)
            self.assertFalse(store.finalize_run(empty['run_id'])['report']['headline']['can_claim_clean'])
