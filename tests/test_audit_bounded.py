"""End-to-end bounded profile audit regressions (synthetic homes only)."""
import cProfile
import os
from pathlib import Path
import time

from tests.conftest import load_submodule


def test_default_audit_bounds_large_home(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home'
    home.mkdir()
    (home / 'config.yaml').write_text('{}')
    (home / 'memories').mkdir()
    (home / 'memories' / 'MEMORY.md').write_text('A synthetic memory.')
    (home / 'memories' / 'USER.md').write_text('A synthetic user.')
    # Large owned tree: no default discovery or hashing should enter it.
    sessions = home / 'sessions'
    sessions.mkdir()
    blob = sessions / '00000'
    blob.write_bytes(b'x' * 65536)
    for i in range(1, 20000):
        os.link(blob, sessions / f'{i:05d}')
    monkeypatch.setenv('HERMES_HOME', str(home))
    profiler = cProfile.Profile()
    start = time.monotonic()
    result = profiler.runcall(surface.execute_audit,
        {'action': 'run', 'quick': True, 'as_of': 1800000000}, db_path=tmp_path / 'audit.db', wait=True)
    elapsed = time.monotonic() - start
    evidence = os.environ.get('AUDIT_PROFILE_OUTPUT')
    if evidence:
        profiler.dump_stats(evidence)
    print(f'large-home elapsed={elapsed:.3f}s status={result["status"]}')
    assert elapsed < 30
    store = surface.AuditStore(tmp_path / 'audit.db')
    run = store.get_run(result['run_id'])
    assert run['mode'] == 'bounded'
    assert run['report']['scope']['coverage'] == 'could_not_verify'
    assert 'session history' in run['report']['scope']['not_included']
    assert run['units'][0]['manifest']['whole_profile_digest'] is None
    assert result['status'] == 'completed'
    assert 'bounded' in str(result['report']).lower()
    # Per-run HMAC evidence is deliberately unlinkable even with fixed as_of.
    again = surface.execute_audit({'action': 'run', 'quick': True, 'as_of': 1800000000},
                                 db_path=tmp_path / 'audit.db', wait=True)
    assert again['canonical_digest'] != result['canonical_digest']
    assert again['report']['scope'] == result['report']['scope']


def test_selected_full_audit_large_home(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home'
    sessions = home / 'sessions'
    sessions.mkdir(parents=True)
    (home / 'config.yaml').write_text('{}')
    blob = sessions / '00000'
    blob.write_bytes(b'x' * 65536)
    for i in range(1, 20000):
        os.link(blob, sessions / f'{i:05d}')
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    original = surface._active_inventory
    def inventory(*args):
        value = original(*args)
        value['project_units'] = [{'canonical_path': str(project), 'coverage': 'verified'}]
        return value
    monkeypatch.setattr(surface, '_active_inventory', inventory)
    start = time.monotonic()
    result = surface.execute_audit({'root': str(project), 'max_entries': 10000}, db_path=tmp_path / 'audit.db', wait=True)
    elapsed = time.monotonic() - start
    print(f'selected-project full large-profile elapsed={elapsed:.3f}s status={result["status"]}')
    assert result['status'] == 'completed'
    assert result['report']['scope']['description'] == 'Project-outward full static audit'
    assert result['report']['scope']['coverage'] == 'could_not_verify'
    assert 'entry_limit_exceeded' in result['report']['scope']['regions']['active_profile']['reasons']


def test_full_home_cli_opt_in():
    import argparse
    cli = load_submodule('cli')
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    assert parser.parse_args(['audit', '--full-home']).full_home is True
    assert parser.parse_args(['audit']).full_home is False
    assert parser.parse_args(['audit', '--quick']).quick is True
    assert parser.parse_args(['audit']).quick is False


def test_bounded_never_discovers_trees(tmp_path, monkeypatch):
    bounded = load_submodule('audit.bounded')
    (tmp_path / 'config.yaml').write_text('{}')
    (tmp_path / 'sessions').mkdir()
    (tmp_path / 'sessions' / 'private').write_text('not captured')
    def forbidden(*args, **kwargs):
        raise AssertionError('bounded capture must not recursively discover')
    monkeypatch.setattr(os, 'walk', forbidden)
    scandir = os.scandir
    def guarded(path):
        if str(path).startswith(str(tmp_path)):
            forbidden()
        return scandir(path)
    monkeypatch.setattr(os, 'scandir', guarded)
    result = bounded.collect_profile(profile_name='default', profile_dir=tmp_path, is_default=True)
    manifest = result['fingerprint_manifest']
    assert manifest['whole_profile_digest'] is None
    assert not manifest['whole_profile_exact_eligible']
    assert manifest['coverage'] == 'could_not_verify'
    assert not any(p.startswith('sessions') for p in manifest['files'])


def test_full_home_captures_sessions(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    (tmp_path / 'config.yaml').write_text('{}')
    (tmp_path / 'sessions').mkdir()
    (tmp_path / 'sessions' / 'one').write_text('synthetic')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    result = surface.execute_audit({'action': 'run', 'full_home': True, 'as_of': 1800000000},
                                   db_path=tmp_path / 'plugin-data' / 'defuzz' / 'state.db', wait=True)
    store = surface.AuditStore(tmp_path / 'plugin-data' / 'defuzz' / 'state.db')
    run = store.get_run(result['run_id'])
    assert run['mode'] == 'full_home'
    assert result['status'] == 'completed'
    assert 'Project-outward full static audit' in str(result['report'])
    assert 'sessions/one' in run['units'][0]['manifest']['files']


def test_invalid_config_does_not_claim_memory_settings_verified(tmp_path):
    bounded = load_submodule('audit.bounded')
    (tmp_path / 'config.yaml').write_text('[not a mapping]')
    (tmp_path / 'memories').mkdir()
    result = bounded.collect_profile(profile_name='default', profile_dir=tmp_path, is_default=True)
    assert result['memory']['coverage'] == 'could_not_verify'


def test_bounded_excludes_registered_projects_by_default(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'profile'
    home.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.setattr(surface, '_active_inventory', lambda *a: {
        'active_profile': 'default', 'coverage': 'verified', 'findings': [],
        'profile_units': [{'name': 'default', 'path': str(home), 'is_default': True}],
        'project_units': [{'canonical_path': str(project)}]})
    store = surface.AuditStore(tmp_path / 'audit.db')
    for args in ({}, {'selected_projects': None}):
        prepared = surface._prepare(store, args)
        assert prepared[3] == []
    assert surface._prepare(store, {'root': str(project)})[3]
    assert surface._prepare(store, {'full_home': True})[3] == []


def test_bounded_unsafe_and_oversized_files_stay_unknown(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'profile'
    home.mkdir()
    outside = tmp_path / 'secret'
    outside.write_text('SYNTHETIC-DO-NOT-CAPTURE')
    (home / 'config.yaml').symlink_to(outside)
    (home / 'memories').mkdir()
    with (home / 'memories' / 'MEMORY.md').open('wb') as stream:
        stream.truncate(1024 * 1024 + 1)
    monkeypatch.setenv('HERMES_HOME', str(home))
    result = surface.execute_audit({'action': 'run', 'quick': True}, db_path=tmp_path / 'audit.db', wait=True)
    assert result['status'] == 'completed'
    assert result['report']['scope']['coverage'] == 'could_not_verify'
    run = surface.AuditStore(tmp_path / 'audit.db').get_run(result['run_id'])
    assert 'sha256' not in run['units'][0]['manifest']['files']['config.yaml']
    assert 'SYNTHETIC-DO-NOT-CAPTURE' not in str(run)


def test_resume_preserves_bounded_scope(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    store = surface.AuditStore(tmp_path / 'audit.db')
    prepared = surface._prepare(store, {'quick': True, 'as_of': 1800000000})
    store.cancel_run(prepared[0])
    previous = store.get_run(prepared[0])
    resumed = surface._prepare(store, {'full_home': True}, previous)
    assert resumed[-1] is False
    assert resumed[4] == 1800000000
    assert store.get_run(prepared[0])['mode'] == 'bounded'

