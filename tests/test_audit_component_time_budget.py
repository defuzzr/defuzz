"""Hard wall-clock budget around each audit component call. Synthetic homes only."""
from __future__ import annotations

import json
import os
import sys
import secrets
import sqlite3
import time
from pathlib import Path

from tests.conftest import load_submodule
from tests.test_audit_user_db_readonly import snapshot
from tests.test_audit_wired_sections import _home

# The bounded child imports stubs by module name. Import them as a top-level
# module so the child does not run the tests package (and its conftest set-up).
_TESTS = str(Path(__file__).resolve().parent)
if _TESTS not in sys.path:
    sys.path.append(_TESTS)
import test_audit_component_time_budget_stubs as stubs  # noqa: E402

BUDGET = 0.25
# The worker is warm when the budget starts: the margin covers the kill/reap grace.
MARGIN = 0.75


def _bounded():
    return load_submodule('audit.bounded_call')


def _secret():
    return stubs.secret()


def _descendants(pid):
    """Live or zombie processes whose parent chain includes pid."""
    parents = {}
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            stat = Path(f'/proc/{entry}/stat').read_text()
            parents[int(entry)] = int(stat.rsplit(')', 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
    found, stack = [], [pid]
    while stack:
        current = stack.pop()
        for child, parent in parents.items():
            if parent == current and child not in found:
                found.append(child)
                stack.append(child)
    return found


def _named(token):
    """Every process on the host whose comm carries token (orphans included)."""
    found = []
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            if token in Path(f'/proc/{entry}/comm').read_text():
                found.append(int(entry))
        except OSError:
            continue
    return found


def _open_fds():
    return sorted(int(name) for name in os.listdir('/proc/self/fd'))


def _call(component, fn, component_s=BUDGET, **kwargs):
    surface = load_submodule('audit_surface')
    bounded = _bounded()
    before = set(_descendants(os.getpid()))
    fds = _open_fds()
    with bounded.budgets(10.0, 60.0), bounded.audit_call_scope() as session:
        # Warm the worker (interpreter start, stub import) so the budget below
        # is spent inside the component itself.
        warm = surface._component(component, 'default', stubs.echo)
        assert warm['coverage'] == 'verified', bounded.LAST_CAUSE
        with bounded.budgets(component_s, 60.0):
            start = time.monotonic()
            result = surface._component(component, 'default', fn, **kwargs)
            elapsed = time.monotonic() - start
        assert session.starts == 1
    assert set(_descendants(os.getpid())) - before == set()
    assert _open_fds() == fds
    return result, elapsed


def _assert_unverified(result, component, kind):
    assert result['coverage'] == 'could_not_verify'
    finding = result['findings'][0]
    assert finding['id'] == f'{component}.unverified'
    assert finding['coverage'] == 'could_not_verify'
    assert finding['consequence'] == _bounded().sentence(component, kind), _bounded().LAST_CAUSE


def test_spin_loop_is_killed_within_budget():
    result, elapsed = _call('skill_hygiene', stubs.spin)
    assert elapsed < BUDGET + MARGIN, elapsed
    _assert_unverified(result, 'skill_hygiene', 'timeout')


def test_pathological_regex_is_killed_within_budget():
    result, elapsed = _call('context_load', stubs.regex)
    assert elapsed < BUDGET + MARGIN, elapsed
    _assert_unverified(result, 'context_load', 'timeout')


def test_sleep_is_killed_within_budget():
    result, elapsed = _call('write_settings', stubs.sleep)
    assert elapsed < BUDGET + MARGIN, elapsed
    _assert_unverified(result, 'write_settings', 'timeout')


def test_forked_grandchildren_are_killed_even_after_setsid():
    token = 'tbgc' + secrets.token_hex(4)
    result, elapsed = _call('memory', stubs.grandchildren, component_s=1.0, token=token)
    assert elapsed < 1.0 + MARGIN, elapsed
    _assert_unverified(result, 'memory', 'timeout')
    deadline = time.monotonic() + 2
    while _named(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _named(token) == []


def test_grandchild_left_by_a_finished_call_is_killed_with_the_worker():
    token = 'tbgd' + secrets.token_hex(4)
    result, _elapsed = _call('memory', stubs.daemon_then_return, component_s=5.0, token=token)
    assert result['coverage'] == 'verified'
    deadline = time.monotonic() + 2
    while _named(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _named(token) == []


def test_oversized_result_is_refused():
    result, elapsed = _call('executable_inventory', stubs.huge, component_s=20.0)
    assert elapsed < 20.0, elapsed
    _assert_unverified(result, 'executable_inventory', 'stopped')
    assert 'xxxxxxxx' not in json.dumps(result)


def test_signal_exit_is_could_not_verify():
    result, elapsed = _call('static_code', stubs.signalled, component_s=5.0)
    assert elapsed < 5.0, elapsed
    _assert_unverified(result, 'static_code', 'stopped')


def test_nonzero_exit_is_could_not_verify():
    result, _elapsed = _call('static_code', stubs.exit_nonzero, component_s=5.0)
    _assert_unverified(result, 'static_code', 'stopped')


def test_system_exit_with_secret_is_not_echoed(capsys):
    result, _elapsed = _call('template_drift', stubs.system_exit_secret, component_s=5.0)
    _assert_unverified(result, 'template_drift', 'stopped')
    captured = capsys.readouterr()
    assert _secret() not in json.dumps(result) + captured.out + captured.err


def test_unreadable_reply_is_could_not_verify():
    result, _elapsed = _call('template_drift', stubs.unreadable, component_s=5.0)
    _assert_unverified(result, 'template_drift', 'stopped')


def test_forged_reply_length_is_refused_before_reading():
    result, elapsed = _call('static_code', stubs.forged_length, component_s=10.0)
    assert elapsed < 2.0, elapsed  # refused on the length prefix, not after a timeout
    assert _bounded().LAST_CAUSE == ['refused']
    _assert_unverified(result, 'static_code', 'stopped')


def test_fixed_sentences_verbatim():
    bounded = _bounded()
    assert bounded.sentence('memory', 'timeout') == (
        'The memory check exceeded its time budget and could not be verified.')
    assert bounded.sentence('memory', 'stopped') == (
        'The memory check stopped without a usable result and could not be verified.')
    assert bounded.sentence('not-a-component', 'timeout') == (
        'The component check exceeded its time budget and could not be verified.')


def test_environment_and_cwd_follow_the_parent_per_call(tmp_path, monkeypatch):
    bounded = _bounded()
    name = 'DEFUZZ_TB_PROBE'
    with bounded.budgets(10.0, 60.0), bounded.audit_call_scope() as session:
        monkeypatch.delenv(name, raising=False)
        first = bounded.invoke(stubs.environment, {'name': name})
        monkeypatch.setenv(name, 'second')
        monkeypatch.chdir(tmp_path)
        second = bounded.invoke(stubs.environment, {'name': name})
        assert session.starts == 1
    assert first['value'] is None
    assert second == {'value': 'second', 'cwd': str(tmp_path)}


def test_raised_secret_is_not_echoed(capsys):
    result, elapsed = _call('template_drift', stubs.raise_secret)
    captured = capsys.readouterr()
    blob = json.dumps(result) + captured.out + captured.err
    assert _secret() not in blob
    assert elapsed < BUDGET + MARGIN
    assert result['coverage'] == 'could_not_verify'
    finding = result['findings'][0]
    assert finding['id'] == 'template_drift.unverified'
    assert finding['consequence'] == 'Collector failed (RuntimeError); this check could not be verified.'


def test_child_cannot_write(tmp_path):
    target = tmp_path / 'written-by-child'
    result, _elapsed = _call('memory', stubs.write_file, component_s=5.0, target=str(target))
    assert not target.exists()
    assert result['findings'][0]['consequence'] == (
        'Collector failed (PermissionError); this check could not be verified.')


def test_total_audit_budget_stops_later_components():
    surface = load_submodule('audit_surface')
    bounded = _bounded()
    with bounded.budgets(5.0, 100.0), bounded.audit_call_scope() as session:
        assert surface._component('memory', 'default', stubs.echo)['coverage'] == 'verified'
        spent = session.spent
        with bounded.budgets(5.0, spent + 0.4):
            start = time.monotonic()
            first = surface._component('memory', 'default', stubs.spin)
            first_s = time.monotonic() - start
            second = surface._component('skill_hygiene', 'default', stubs.echo)
            second_s = time.monotonic() - start - first_s
    assert first_s < 0.4 + MARGIN, first_s
    assert second_s < 0.1, second_s
    _assert_unverified(first, 'memory', 'timeout')
    _assert_unverified(second, 'skill_hygiene', 'timeout')


def test_one_worker_per_audit_replaced_only_after_a_kill():
    surface = load_submodule('audit_surface')
    bounded = _bounded()
    with bounded.budgets(5.0, 30.0), bounded.audit_call_scope() as session:
        surface._component('memory', 'default', stubs.echo)
        first = session.worker.pid
        surface._component('memory', 'default', stubs.echo)
        assert session.worker.pid == first and session.starts == 1
        with bounded.budgets(0.3, 30.0):
            surface._component('memory', 'default', stubs.spin)
        assert session.worker is None
        surface._component('memory', 'default', stubs.echo)
        assert session.starts == 2


def test_budgets_come_from_the_audit_arguments():
    bounded = _bounded()
    with bounded.bind_budgets({'component_budget_s': 2, 'audit_budget_s': 3.5}) as chosen:
        assert (chosen.component_s, chosen.audit_s) == (2.0, 3.5)
    with bounded.bind_budgets({}) as chosen:
        assert (chosen.component_s, chosen.audit_s) == (60.0, 900.0)
    for bad in (0, -1, True, 'x', float('nan'), float('inf')):
        try:
            with bounded.bind_budgets({'component_budget_s': bad}):
                pass
        except ValueError:
            continue
        raise AssertionError(bad)
    surface = load_submodule('audit_surface')
    props = surface.SCHEMA['parameters']['properties'] if 'parameters' in surface.SCHEMA else surface.SCHEMA['properties']
    assert {'component_budget_s', 'audit_budget_s'} <= set(props)


def test_default_budget_exceeds_inner_cooperative_caps():
    bounded = _bounded()
    assert bounded.DEFAULT_COMPONENT_BUDGET_S > load_submodule('audit.session_contamination').MAX_SECONDS
    assert bounded.DEFAULT_COMPONENT_BUDGET_S > load_submodule('audit.profile_duplicates').MAX_SECONDS
    assert bounded.DEFAULT_AUDIT_BUDGET_S > bounded.DEFAULT_COMPONENT_BUDGET_S


def test_every_called_component_has_a_fixed_sentence():
    import re
    surface = load_submodule('audit_surface')
    constants = load_submodule('audit.evidence_constants')
    evidence = load_submodule('audit.evidence')
    source = Path(surface.__file__).read_text()
    called = set(re.findall(r"_component\(\s*'([a-z_]+)'", source)) | set(surface._WIRED)
    assert called <= set(constants.TIME_BUDGET_COMPONENTS)
    for name in called:
        for kind in ('timeout', 'stopped'):
            assert _bounded().sentence(name, kind) in evidence.VOCABULARY
        assert f'{name}.unverified' in evidence.RULE_IDS


def _strip(value):
    if isinstance(value, dict):
        if 'hmac' in value and 'kind' in value:
            return {key: ('HMAC' if key == 'hmac' else _strip(item)) for key, item in value.items()}
        out = {
            key: _strip(item) for key, item in value.items()
            if not str(key).startswith('hmac:')
            and not str(key).endswith('_digest')
            and key != 'report_store_exclusions'
        }
        if isinstance(out.get('findings'), list):
            # Report order sorts on sealed (per-run keyed) paths: a per-run field.
            out['findings'] = sorted(out['findings'], key=lambda item: json.dumps(item, sort_keys=True))
        return out
    if isinstance(value, list):
        return [_strip(item) for item in value]
    if isinstance(value, str) and value.startswith('hmac:'):
        return 'hmac:'
    return value


def _diff(left, right):
    problems = []

    def walk(x, y, path):
        if type(x) is not type(y):
            problems.append(f'TYPE {path} {type(x).__name__} {type(y).__name__}')
        elif isinstance(x, dict):
            for key in sorted(set(x) | set(y), key=str):
                if key not in x or key not in y:
                    problems.append(f'KEY {path}.{key}')
                elif x[key] != y[key]:
                    walk(x[key], y[key], f'{path}.{key}')
        elif isinstance(x, list):
            if len(x) != len(y):
                problems.append(f'LEN {path} {len(x)} {len(y)}')
            for index, (item, other) in enumerate(zip(x, y)):
                if item != other:
                    walk(item, other, f'{path}[{index}]')
        elif x != y:
            problems.append(f'VAL {path} {x!r:.160} != {y!r:.160}')
    walk(left, right, 'report')
    import re
    for index in sorted({int(m) for m in re.findall(r'report\.findings\[(\d+)\]', '\n'.join(problems))})[:6]:
        problems.append(f'FINDING {index}: {json.dumps(left["findings"][index])[:600]}')
        problems.append(f'      vs {index}: {json.dumps(right["findings"][index])[:600]}')
    return '\n'.join(problems[:60])


def _no_system_gitconfig(monkeypatch, tmp_path):
    git = load_submodule('audit.outward_git')
    discover = getattr(git.discover_git_context, 'unpatched', git.discover_git_context)

    def no_system_gitconfig(*args, **kwargs):
        return discover(*args, **kwargs, system_config=tmp_path / 'absent-gitconfig')
    no_system_gitconfig.unpatched = discover
    monkeypatch.setattr(git, 'discover_git_context', no_system_gitconfig)


def _both(tmp_path, args, *, sessions=False):
    surface = load_submodule('audit_surface')
    bounded = _bounded()
    with bounded.in_process():
        plain = surface.execute_audit(args, db_path=tmp_path / 'plain' / 'audit.db', wait=True, sessions=sessions)
    before = set(_descendants(os.getpid()))
    bounded_run = surface.execute_audit(args, db_path=tmp_path / 'bounded' / 'audit.db', wait=True, sessions=sessions)
    assert set(_descendants(os.getpid())) - before == set()
    assert plain['status'] == bounded_run['status'] == 'completed'
    left, right = _strip(plain['report']), _strip(bounded_run['report'])
    assert left == right, _diff(left, right)
    assert 'run_metrics' not in plain['report'] and 'run_metrics' not in bounded_run['report']
    assert set(plain.get('run_metrics', {})) == set(bounded_run.get('run_metrics', {}))
    return plain, bounded_run


def test_bounded_report_matches_in_process_on_wired_fixture(tmp_path, monkeypatch):
    home, project = _home(tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(monkeypatch, tmp_path)
    for sub in ('plain', 'bounded'):
        (tmp_path / sub).mkdir()
    before = snapshot(home)
    _both(tmp_path, {'action': 'run', 'root': str(project), 'as_of': 1800000000})
    assert snapshot(home) == before


def test_bounded_report_matches_in_process_with_sessions_and_quick(tmp_path, monkeypatch):
    from tests.test_audit_session_reader_bounds import _make_session_db
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{}', encoding='utf-8')
    home = tmp_path / 'home'
    _make_session_db(home, project, sessions_count=2, messages_per_session=3)
    (home / 'config.yaml').write_text('{}\n', encoding='utf-8')
    reg = home / 'plugin-data' / 'defuzz' / 'state.db'
    reg.parent.mkdir(parents=True)
    with sqlite3.connect(reg) as conn:
        conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
        conn.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synth'))
    conn.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(monkeypatch, tmp_path)
    for run in ('full', 'quick'):
        for sub in ('plain', 'bounded'):
            (tmp_path / run / sub).mkdir(parents=True)
    _both(tmp_path / 'full', {'action': 'run', 'root': str(project), 'as_of': 1800000000}, sessions=True)
    _both(tmp_path / 'quick', {'action': 'run', 'root': str(project), 'as_of': 1800000000, 'quick': True})


def test_hung_component_leaves_the_rest_of_the_audit(tmp_path, monkeypatch, capsys):
    surface = load_submodule('audit_surface')
    home, project = _home(tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(monkeypatch, tmp_path)
    args = {'action': 'run', 'root': str(project), 'as_of': 1800000000}
    (tmp_path / 'baseline').mkdir()
    with _bounded().in_process():
        baseline = surface.execute_audit(args, db_path=tmp_path / 'baseline' / 'audit.db', wait=True)
    before = snapshot(home)
    monkeypatch.setattr(surface.skill_hygiene, 'audit_skill_hygiene', stubs.spin)
    entry, description = surface._WIRED['kanban_residue']
    monkeypatch.setitem(surface._WIRED, 'kanban_residue', (stubs.sleep, description))
    descendants = set(_descendants(os.getpid()))
    db = tmp_path / 'hung' / 'audit.db'
    db.parent.mkdir()
    start = time.monotonic()
    result = surface.execute_audit({**args, 'component_budget_s': 0.5, 'audit_budget_s': 60}, db_path=db, wait=True)
    elapsed = time.monotonic() - start
    captured = capsys.readouterr()
    assert elapsed < 30, elapsed
    assert result['status'] == 'completed'
    assert snapshot(home) == before
    assert set(_descendants(os.getpid())) - descendants == set()
    report = result['report']
    for component in ('skill_hygiene', 'kanban_residue'):
        hits = [f for f in report['findings'] if f.get('id') == f'{component}.unverified']
        assert len(hits) == 1, component
        assert hits[0]['coverage'] == 'could_not_verify'
        assert hits[0]['consequence'] == _bounded().sentence(component, 'timeout')
    hung = {'skill_hygiene', 'kanban_residue', 'write_settings'}  # write_settings reads skill_hygiene
    left, right = _strip(baseline['report']), _strip(report)
    for section in ('memory_load', 'home_workdirs', 'dead_stores', 'skill_ledger', 'unattended_exposure',
                    'secret_file_copies', 'profile_duplicates', 'skill_packs', 'context_load'):
        assert left.get(section) == right.get(section), section
    unaffected = lambda findings: sorted(  # noqa: E731
        json.dumps(f, sort_keys=True) for f in findings
        if not any(str(f.get('id', '')).startswith(name) for name in hung))
    assert unaffected(left['findings']) == unaffected(right['findings'])
    with sqlite3.connect(db) as conn:
        dumped = '\n'.join(conn.iterdump())
    conn.close()
    assert _secret() not in json.dumps(result) + captured.out + captured.err + dumped


def test_worker_start_does_not_depend_on_other_threads():
    import threading
    surface = load_submodule('audit_surface')
    bounded = _bounded()
    hold = threading.Event()
    thread = threading.Thread(target=hold.wait, name='tb-budget-hold')
    thread.start()
    try:
        with bounded.budgets(15.0, 30.0):
            spawned = surface._component('memory', 'default', stubs.echo, marker='m')
    finally:
        hold.set()
        thread.join(timeout=2)
    with bounded.in_process(), bounded.budgets(15.0, 30.0):
        local = surface._component('memory', 'default', stubs.echo, marker='m')
    assert spawned == local
    assert spawned['coverage'] == 'verified'

