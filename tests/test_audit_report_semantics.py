"""Public disclosure and conservative, typed report semantics."""
import argparse
from tests.conftest import load_submodule


def test_audit_scope_disclosure(capsys, monkeypatch):
    surface = load_submodule('audit_surface')
    disclosure = getattr(surface, 'AUDIT_SCOPE_DISCLOSURE', '')
    assert disclosure, 'one code-defined pre-run scope disclosure is required'
    for phrase in ('outward references', 'HOME', 'credential', 'sibling', 'No execution', 'plugin data', 'quick'):
        assert phrase in disclosure
    assert disclosure in surface.SCHEMA['description']
    routes = load_submodule('dashboard.routes.audit_routes')
    assert routes.scope() == {'scope_disclosure': disclosure}
    cli = load_submodule('cli')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    try:
        parser.parse_args(['audit', '--help'])
    except SystemExit:
        pass
    assert disclosure in ' '.join(capsys.readouterr().out.split())
    def run(*args, **kwargs):
        assert disclosure in capsys.readouterr().err
        return {}
    monkeypatch.setattr(surface, 'execute_audit', run)
    assert cli.handle_defuzz_cli(parser.parse_args(['audit'])) == 0


def report_fixture(coverage='verified', status='completed', extra=()):
    contract = load_submodule('audit.contract')
    finding = contract.make_finding(rule_id='memory.cross_project_exposure',
        classification='review_suggested', affected_identities=['default'],
        consequence='review', evidence={'coverage': 'verified'})
    return contract.canonical_report_payload(as_of=1,
        units=[{'unit_kind': 'profile', 'unit_id': 'default', 'coverage': coverage, 'status': status}],
        findings=[finding, *extra])


def test_audit_policy_recommendations():
    report = report_fixture()
    assert report.get('policy_recommendations') == [{
        'finding_ids': ['memory.cross_project_exposure'],
        'affected_identities': ['default'],
        'kind': 'review_memory_scope', 'execution_available': False}]
    for coverage in ('could_not_verify', 'not_included'):
        assert report_fixture(coverage)['policy_recommendations'] == []
    assert report_fixture(status='running')['policy_recommendations'] == []
    contract = load_submodule('audit.contract')
    unknown = contract.make_finding(rule_id='memory.unverified', classification='review_suggested',
        coverage='could_not_verify', affected_identities=['default'], consequence='unknown')
    report = report_fixture(extra=[unknown])
    assert report['policy_recommendations'] == []
    assert report['headline']['coverage'] == 'could_not_verify'
    # No inference from unrecognized rule IDs, free text, or absent unit evidence.
    unknown['id'] = 'PRIVATE_POLICY_CANARY'
    unknown['coverage'] = 'verified'
    result = contract.canonical_report_payload(as_of=1, findings=[unknown])
    assert result['policy_recommendations'] == []
    import json
    assert 'PRIVATE_POLICY_CANARY' not in json.dumps(result)
    # Unknown evidence in a different unit must not erase a supported review.
    unknown['id'] = 'memory.unverified'
    unknown['coverage'] = 'could_not_verify'
    unknown['affected_identities'] = ['other_projects']
    assert report_fixture(extra=[unknown])['policy_recommendations']
    for rule, kind in [
            ('static_code.unapproved_dependency', 'review_dependency_policy'),
            ('template.locked_hash_drift', 'review_template_policy'),
            ('executable_inventory.mcp_unsafe_declaration', 'review_execution_policy'),
            ('executable_inventory.hook_unsafe_path_or_command', 'review_execution_policy')]:
        finding = contract.make_finding(rule_id=rule, classification='warning',
            affected_identities=['default'], consequence='review')
        report = contract.canonical_report_payload(as_of=1, findings=[finding], units=[{
            'unit_kind': 'profile', 'unit_id': 'default', 'status': 'completed', 'coverage': 'verified'}])
        assert report['policy_recommendations'][0]['kind'] == kind
        assert report['policy_recommendations'][0]['finding_ids'] == [report['findings'][0]['id']]
        assert not report['policy_recommendations'][0]['execution_available']

def test_audit_preservation_assessment():
    report = report_fixture()
    assessment = report.get('preservation_assessments')
    assert assessment == [{
        'finding_ids': ['memory.cross_project_exposure'], 'affected_identities': ['default'],
        'proposed_cleanup_id': None, 'must_preserve': ['user_data'],
        'confidence': 'verified', 'reason': 'static_evidence_only', 'execution_available': False}]
    unknown = report_fixture('could_not_verify')['preservation_assessments'][0]
    assert unknown['must_preserve'] == ['unknown']
    assert unknown['confidence'] == 'unknown'
    assert unknown['reason'] == 'insufficient_evidence'
    contract = load_submodule('audit.contract')
    for rule, expected in [('template.locked_hash_drift', ['config']),
                           ('audit.scope.credentials', ['credentials_metadata_only'])]:
        finding = contract.make_finding(rule_id=rule, classification='review_suggested',
            affected_identities=['default'], consequence='review', proposed_cleanup_id='review')
        report = contract.canonical_report_payload(as_of=1, findings=[finding], units=[{
            'unit_kind': 'profile', 'unit_id': 'default', 'status': 'completed', 'coverage': 'verified'}])
        assessment = report['preservation_assessments'][0]
        assert assessment['must_preserve'] == expected
        assert assessment['proposed_cleanup_id'] == report['findings'][0]['proposed_cleanup_id']
        assert assessment['execution_available'] is False
    # Unmapped rules do not manufacture a preservation guarantee.
    finding['id'] = 'tools_lock.static'
    report = contract.canonical_report_payload(as_of=1, findings=[finding])
    assert report['preservation_assessments'][0]['reason'] == 'insufficient_evidence'

def test_full_audit_performance_contract(tmp_path, monkeypatch, record_property):
    """Complete public runner, default full mode; no collector or clock mocks."""
    import shutil
    import sqlite3
    import time
    from pathlib import Path
    from contextlib import closing

    surface = load_submodule('audit_surface')
    home = tmp_path / 'home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    (profile / 'config.yaml').write_text('{}')
    (profile / 'memories').mkdir()
    (profile / 'memories/MEMORY.md').write_text('Synthetic memory.')
    (profile / 'memories/USER.md').write_text('Synthetic user.')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    monkeypatch.setenv('HERMES_PROFILE', 'default')
    db = profile / 'plugin-data/defuzz/state.db'
    db.parent.mkdir(parents=True)
    fixtures = Path(__file__).parent / 'fixtures/audit_template'
    projects = []
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute('CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT)')
        for i, (language, template) in enumerate([
                ('python', 'python-golden'), ('ts_node', 'ts-node-golden'), ('rust', 'rust-golden')] * 3):
            project = home / 'projects' / f'project-{i}'
            shutil.copytree(fixtures / language, project)
            (project / '.git').mkdir()
            (project / '.git/config').write_text('[core]\n bare = false\n')
            projects.append(str(project))
            conn.execute('INSERT INTO projects VALUES (?, ?, ?, ?)',
                         (str(project), f'project-{i}', f'project-{i}', template))
    start = time.monotonic()
    result = surface.execute_audit({'action': 'run', 'selected_projects': projects}, db_path=db, wait=True)
    seconds = time.monotonic() - start
    record_property('full_audit_seconds', seconds)
    print(f'full default audit: {seconds:.3f} seconds (1 profile, 9 projects)')
    assert seconds < 120, f'full audit exceeded 120s: {seconds:.3f}s'
    assert result['status'] == 'completed'
    run = surface.AuditStore(db).get_run(result['run_id'])
    assert run['mode'] == 'full_home'
    assert len(run['units']) == 10
    assert sum(u['unit_kind'] == 'project' for u in run['units']) == 9
    # Unknown static coverage is legitimate; no unit may remain queued/running.
    assert all(u['status'] in ('completed', 'incomplete') for u in run['units'])
    # 7 profile components + 9 wired sections + 3 components for each of the 9 projects.
    assert len(run['unit_results']) == 43
    wired = load_submodule('audit.evidence_wiring').WIRED_SECTIONS
    assert {'skill_hygiene', 'write_settings', 'session_contamination', *wired} <= run['report'].keys()
    assert result['report']['scope']['description'] == 'Project-outward full static audit'
    assert 'policy_recommendations' in run['report']
    assert len(run['report']['preservation_assessments']) == len(run['report']['findings'])
