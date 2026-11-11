"""Public audit adapters must retain the shared disclosure on every run result."""
import argparse
import json

from tests.conftest import ensure_test_package, load_submodule


def test_run_results_keep_scope_disclosure(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    monkeypatch.setattr(surface, '_active_inventory', lambda *args: {
        'active_profile': 'default', 'profile_units': [], 'project_units': [],
        'all_registration_records': [], 'coverage': 'verified', 'findings': []})
    db = tmp_path / 'state.db'
    completed = surface.execute_audit({'quick': True}, db_path=db, wait=True)
    expected = surface.audit_scope_payload()
    assert completed.get('scope_disclosure') == expected['scope_disclosure']
    for action in ('status', 'report', 'cancel'):
        result = surface.execute_audit({'action': action, 'run_id': completed['run_id']}, db_path=db)
        assert result.get('scope_disclosure') == expected['scope_disclosure']
    routes = load_submodule('dashboard.routes.audit_routes')
    execute = surface.execute_audit
    monkeypatch.setattr(routes, 'execute_audit', lambda args: execute(args, db_path=db, wait=True))
    assert routes.start({'quick': True})['scope_disclosure'] == expected['scope_disclosure']
    assert routes.status(completed['run_id'])['scope_disclosure'] == expected['scope_disclosure']
    monkeypatch.setattr(surface, 'execute_audit', lambda args, **kw: execute(args, db_path=db, wait=True))
    pkg = ensure_test_package()
    assert json.loads(pkg._handle_defuzz_audit_tool({'action': 'status', 'run_id': completed['run_id']}))['scope_disclosure'] == expected['scope_disclosure']
    assert expected['scope_disclosure'] in pkg._handle_slash_command(None, 'audit --help')


def test_cli_help_uses_surface_disclosure(monkeypatch, capsys):
    surface = load_submodule('audit_surface')
    constants = load_submodule('audit.evidence_constants')
    cli = load_submodule('cli')
    # One shared text: the surface re-exports it; the CLI reads it from the
    # constants module so its parser builds without PyYAML.
    assert surface.AUDIT_SCOPE_DISCLOSURE == constants.AUDIT_SCOPE_DISCLOSURE
    monkeypatch.setattr(constants, 'AUDIT_SCOPE_DISCLOSURE', 'surface disclosure sentinel')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    import pytest
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(['audit', '--help'])
    assert exc.value.code == 0
    assert constants.AUDIT_SCOPE_DISCLOSURE in capsys.readouterr().out
