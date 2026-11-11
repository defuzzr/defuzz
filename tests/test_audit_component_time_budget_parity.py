"""Guards for the component time budget: worker and in-process audits agree.

- The stored report of a full wired audit is the same whether the checks ran
  in the bounded worker or in-process, under both package names the plugin is
  loaded as (the Hermes plugin package and the dashboard's private copy, whose
  name is several levels deep). The worker must really have run the checks:
  one start per audit and no time-budget sentence in the report.
- The worker boots under a nested package name, and a small call costs
  milliseconds, not an interpreter start.
- Reloading the evidence module keeps the types other modules already
  imported, so the serializer still recognises what they build.
Synthetic homes only.
"""
from __future__ import annotations

import importlib
import os
import statistics
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import load_submodule
from tests.test_audit_component_time_budget import _descendants, _diff, _strip
from tests.test_audit_wired_sections import _home

_TESTS = str(Path(__file__).resolve().parent)
if _TESTS not in sys.path:
    sys.path.append(_TESTS)
import test_audit_component_time_budget_stubs as stubs  # noqa: E402


def _dashboard(name):
    return load_submodule('dashboard.plugin_api')._load(name)


LOADERS = {'plugin': load_submodule, 'dashboard': _dashboard}


def _no_system_gitconfig(load, monkeypatch, tmp_path):
    git = load('audit.outward_git')
    discover = getattr(git.discover_git_context, 'unpatched', git.discover_git_context)

    def no_system_gitconfig(*args, **kwargs):
        return discover(*args, **kwargs, system_config=tmp_path / 'absent-gitconfig')
    no_system_gitconfig.unpatched = discover
    monkeypatch.setattr(git, 'discover_git_context', no_system_gitconfig)


def _budget_sentences(bounded, report):
    hits = []
    for finding in report['findings']:
        ident = finding.get('id')
        if isinstance(ident, str) and ident.endswith('.unverified'):
            component = ident[:-len('.unverified')]
            if finding.get('consequence') in (bounded.sentence(component, 'timeout'),
                                              bounded.sentence(component, 'stopped')):
                hits.append(ident)
    return hits


@pytest.mark.parametrize('loader', sorted(LOADERS))
def test_stored_report_is_the_same_in_the_worker_and_in_process(tmp_path, monkeypatch, loader):
    load = LOADERS[loader]
    surface = load('audit_surface')
    bounded = load('audit.bounded_call')
    home, project = _home(tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(load, monkeypatch, tmp_path)
    starts = []
    real_spawn = bounded._spawn_worker

    def counted_spawn(limit):
        starts.append(limit)
        return real_spawn(limit)
    monkeypatch.setattr(bounded, '_spawn_worker', counted_spawn)
    args = {'action': 'run', 'root': str(project), 'as_of': 1800000000}
    stored = {}
    before = set(_descendants(os.getpid()))
    for mode in ('in_process', 'worker'):
        db = tmp_path / mode / 'audit.db'
        db.parent.mkdir()
        if mode == 'in_process':
            with bounded.in_process():
                run = surface.execute_audit(args, db_path=db, wait=True)
            assert starts == []
        else:
            run = surface.execute_audit(args, db_path=db, wait=True)
        assert run['status'] == 'completed', mode
        report = surface.execute_audit({'action': 'report', 'run_id': run['run_id']}, db_path=db)['report']
        assert 'run_metrics' not in report
        stored[mode] = report
    assert len(starts) == 1, 'one worker for the whole audit'
    assert set(_descendants(os.getpid())) - before == set()
    assert _budget_sentences(bounded, stored['worker']) == []
    left, right = _strip(stored['in_process']), _strip(stored['worker'])
    assert left == right, _diff(left, right)


def test_worker_boots_under_a_nested_package_name_and_calls_are_cheap():
    bounded = _dashboard('audit.bounded_call')
    assert bounded._ROOT_PACKAGE.count('.') >= 2, bounded._ROOT_PACKAGE
    with bounded.in_process():
        local = bounded.invoke(stubs.echo, {'marker': 'm'})
    durations = []
    with bounded.budgets(15.0, 60.0), bounded.audit_call_scope() as session:
        assert bounded.invoke(stubs.echo, {'marker': 'm'}) == local
        for _ in range(10):
            begin = time.monotonic()
            assert bounded.invoke(stubs.echo, {'marker': 'm'}) == local
            durations.append(time.monotonic() - begin)
        assert session.starts == 1
    # An interpreter start costs hundreds of milliseconds; a call on the
    # running worker costs a few. The bound leaves room for a loaded machine.
    assert statistics.median(durations) < 0.1, durations


def test_reloading_the_evidence_module_keeps_the_types_other_modules_imported():
    ev = load_submodule('audit.evidence')
    outward = load_submodule('audit.outward')
    contract = load_submodule('audit.contract')
    first = {name: getattr(ev, name) for name in (
        'Evidence', 'EvidenceEndpoint', 'SealedEvidence', 'GeneratedDigest', 'ControlIdentity',
        'PersistedJSON', 'SealedKey', '_FACTORY', '_PathWithheld')}
    importlib.reload(ev)
    for name, value in first.items():
        assert getattr(ev, name) is value, name
    assert outward.Evidence is ev.Evidence
    built = outward.Evidence('unknown_file_type: synthetic', path=None)
    serializer = ev.EvidenceSerializer()
    assert serializer.serialize({'reasons': [built]}) == serializer.serialize(
        {'reasons': [ev.Evidence('unknown_file_type: synthetic', path=None)]})
    digest = ev.generated_digest('d' * 64)
    assert isinstance(digest, first['GeneratedDigest'])
    assert contract.sanitize_evidence({'source_digest': digest}) == {'source_digest': 'd' * 64}
    # Unsupported values are still refused: nothing new is accepted.
    with pytest.raises(ValueError, match='Unsupported audit evidence'):
        ev.serialize_evidence({'reasons': [object()]})


def test_cancel_kills_a_check_running_in_the_worker_promptly(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    bounded = load_submodule('audit.bounded_call')
    home, project = _home(tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(load_submodule, monkeypatch, tmp_path)
    monkeypatch.setattr(surface.skill_hygiene, 'audit_skill_hygiene', stubs.spin)
    db = tmp_path / 'store' / 'audit.db'
    db.parent.mkdir()
    before = set(_descendants(os.getpid()))
    args = {'action': 'run', 'root': str(project), 'as_of': 1800000000,
            'component_budget_s': 60.0, 'audit_budget_s': 120.0}
    started = surface.execute_audit(args, db_path=db, wait=False)
    run_id = started['run_id']
    deadline = time.monotonic() + 20
    spinning = False
    while time.monotonic() < deadline and not spinning:
        time.sleep(0.2)
        # The spin stub is the only check that keeps the worker busy for seconds.
        spinning = any(_busy(pid) for pid in set(_descendants(os.getpid())) - before)
    assert spinning, 'the spinning check never reached the worker'
    cancelled_at = time.monotonic()
    assert surface.execute_audit({'action': 'cancel', 'run_id': run_id}, db_path=db)['status'] == 'cancelled'
    assert surface._RUN_LOCK.acquire(timeout=10)
    surface._RUN_LOCK.release()
    stopped_after = time.monotonic() - cancelled_at
    assert stopped_after < 3.0, stopped_after  # not the 60 s component budget
    assert set(_descendants(os.getpid())) - before == set()
    status = surface.execute_audit({'action': 'status', 'run_id': run_id}, db_path=db)['status']
    assert status == 'cancelled'
    assert bounded.LAST_CAUSE[0] == 'cancelled'


def _busy(pid, window=0.3):
    def ticks():
        try:
            with open(f'/proc/{pid}/stat', 'rb') as handle:
                fields = handle.read().rsplit(b')', 1)[1].split()
            return int(fields[11]) + int(fields[12])
        except (OSError, IndexError, ValueError):
            return 0
    first = ticks()
    time.sleep(window)
    return ticks() - first >= int(window * os.sysconf('SC_CLK_TCK') * 0.8)
