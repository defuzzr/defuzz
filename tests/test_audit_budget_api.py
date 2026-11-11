"""Budget plumbing contracts; collector implementation is tested separately."""
import argparse
import json

import pytest

from tests.conftest import load_submodule


def test_outward_options_reach_collector(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    outward = load_submodule('audit.outward')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    options = dict(max_entries=13, max_bytes=1234, max_file_bytes=123, unbounded=True)
    seen = {}

    def collector(*args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError('stop after observing collector arguments')

    monkeypatch.setattr(outward, 'collect_outward', collector)
    with pytest.raises(RuntimeError, match='stop after observing'):
        surface.execute_audit({'action': 'run', **options}, db_path=tmp_path / 'audit.db', wait=True)
    assert {key: seen.get(key) for key in options} == options


def test_cli_budget_flags_forwarded(monkeypatch, capsys):
    cli = load_submodule('cli')
    surface = load_submodule('audit_surface')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    ns = parser.parse_args(['audit', '--max-entries', '17', '--max-bytes', '999',
                            '--max-file-bytes', '99', '--unbounded'])
    monkeypatch.setattr(surface, 'execute_audit', lambda args, **kw: args)
    assert cli.handle_defuzz_cli(ns) == 0
    args = json.loads(capsys.readouterr().out)
    assert {key: args[key] for key in ('max_entries', 'max_bytes', 'max_file_bytes', 'unbounded')} == {
        'max_entries': 17, 'max_bytes': 999, 'max_file_bytes': 99, 'unbounded': True}


def test_capture_limits_use_fingerprint_constants(tmp_path, monkeypatch):
    store_module = load_submodule('audit.store')
    fingerprint = load_submodule('audit.fingerprint')
    monkeypatch.setattr(fingerprint, 'DEFAULT_MAX_FILE_BYTES', 321)
    monkeypatch.setattr(fingerprint, 'DEFAULT_MAX_DIR_ENTRIES', 123)
    store = store_module.AuditStore(tmp_path / 'audit.db')
    run = store.create_run(as_of=1, mode='full_home')
    limits = {'max_file_bytes': None, 'max_entries': None, 'max_total_bytes': None}
    outward = {'regions': {'test': {'coverage': 'could_not_verify'}}, 'limits': limits,
               'blending': [], 'credentials': [], 'dynamic_invocations': [], 'session_history': {}}
    report = store.finalize_run(run['run_id'], outward=outward)['report']
    scope = report['scope']
    assert scope['coverage'] == 'could_not_verify'
    assert scope['limits'] == limits
    assert scope['max_file_bytes'] is None
    assert scope['component_capture_limits']['max_file_bytes'] == 321
    assert scope['component_capture_limits']['max_entries'] == 123
    fallback = store.create_run(as_of=1, mode='full_home')
    assert store.finalize_run(fallback['run_id'])['report']['scope']['max_file_bytes'] == 321


def test_resume_preserves_outward_options(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    store = surface.AuditStore(tmp_path / 'audit.db')
    options = {'max_entries': 19, 'max_bytes': 1200, 'max_file_bytes': 100, 'unbounded': False}
    prepared = surface._prepare(store, options)
    previous = store.get_run(prepared[0])
    store.cancel_run(previous['run_id'])
    resumed = surface._prepare(store, {}, previous)
    assert resumed[1]['outward_options'] == options


@pytest.mark.parametrize('body', [{'max_entries': True}, {'max_bytes': 0},
                                  {'max_file_bytes': '9'}, {'unbounded': 'false'}])
def test_routes_reject_invalid_budgets(tmp_path, monkeypatch, body):
    surface = load_submodule('audit_surface')
    routes = load_submodule('dashboard.routes.audit_routes')
    monkeypatch.setattr(routes, 'execute_audit', lambda args: surface.execute_audit(
        args, db_path=tmp_path / 'audit.db', wait=True))
    with pytest.raises(routes.HTTPException) as error:
        routes.start(body)
    assert error.value.status_code == 400


def test_routes_report_effective_collector_limits(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    routes = load_submodule('dashboard.routes.audit_routes')
    outward = load_submodule('audit.outward')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    requested = {'max_entries': 7, 'max_bytes': 17, 'max_file_bytes': 3, 'unbounded': True}
    effective = {'max_entries': None, 'max_total_bytes': None, 'max_file_bytes': None}

    def collector(*args, **kwargs):
        assert {key: kwargs[key] for key in requested} == requested
        return {'regions': {'test': {'coverage': 'could_not_verify'}}, 'limits': effective,
                'blending': [], 'credentials': [], 'dynamic_invocations': [], 'session_history': {}}

    monkeypatch.setattr(outward, 'collect_outward', collector)
    monkeypatch.setattr(routes, 'execute_audit', lambda args: surface.execute_audit(
        args, db_path=tmp_path / 'audit.db', wait=True))
    result = routes.start(requested)
    assert result['report']['scope']['limits'] == effective
    assert result['report']['scope']['coverage'] == 'could_not_verify'
    assert routes.report(result['run_id'])['report'] == result['report']


def test_cli_defaults_leave_collector_defaults_untouched(monkeypatch, capsys):
    cli = load_submodule('cli')
    surface = load_submodule('audit_surface')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    monkeypatch.setattr(surface, 'execute_audit', lambda args, **kw: args)
    assert cli.handle_defuzz_cli(parser.parse_args(['audit'])) == 0
    args = json.loads(capsys.readouterr().out)
    assert not {'max_entries', 'max_bytes', 'max_file_bytes', 'unbounded'} & args.keys()


def test_budget_schema():
    properties = load_submodule('audit_surface').SCHEMA['parameters']['properties']
    for key in ('max_entries', 'max_bytes', 'max_file_bytes'):
        assert properties[key]['type'] == 'integer'
        assert properties[key]['minimum'] == 1
    assert properties['unbounded']['type'] == 'boolean'


@pytest.mark.parametrize('key', ['max_entries', 'max_bytes', 'max_file_bytes'])
@pytest.mark.parametrize('value', [0, -1, True, False, 1.5, '10', None, [], {}])
def test_invalid_budgets_rejected(tmp_path, monkeypatch, key, value):
    surface = load_submodule('audit_surface')
    monkeypatch.setattr(surface, '_active_inventory', lambda *a: pytest.fail('validation must precede capture'))
    with pytest.raises(ValueError, match=key):
        surface.execute_audit({'action': 'run', key: value}, db_path=tmp_path / 'audit.db', wait=True)


@pytest.mark.parametrize('value', [0, 1, 'true', None, [], {}])
def test_unbounded_requires_boolean(tmp_path, monkeypatch, value):
    surface = load_submodule('audit_surface')
    monkeypatch.setattr(surface, '_active_inventory', lambda *a: pytest.fail('validation must precede capture'))
    with pytest.raises(ValueError, match='unbounded'):
        surface.execute_audit({'action': 'run', 'unbounded': value}, db_path=tmp_path / 'audit.db', wait=True)

