"""Overhead of the component time budget on the wired-sections fixture.

Prints the measured seconds (run with -s to see them). The assertion is a
loose ceiling so a loaded machine does not flake; the numbers are the record.
"""
from __future__ import annotations

import time

from tests.conftest import load_submodule
from tests.test_audit_component_time_budget import _no_system_gitconfig
from tests.test_audit_wired_sections import _home


def test_overhead_on_wired_fixture(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    bounded = load_submodule('audit.bounded_call')
    home, project = _home(tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    _no_system_gitconfig(monkeypatch, tmp_path)
    args = {'action': 'run', 'root': str(project), 'as_of': 1800000000}
    per_component: dict[str, float] = {}
    original = bounded.invoke

    def timed(fn, kwargs):
        start = time.monotonic()
        try:
            return original(fn, kwargs)
        finally:
            name = getattr(fn, '__name__', '?')
            per_component[name] = max(per_component.get(name, 0.0), time.monotonic() - start)

    timings = {'in_process': [], 'bounded': []}
    for round_index in range(3):
        for mode in ('in_process', 'bounded'):
            db = tmp_path / f'{mode}-{round_index}' / 'audit.db'
            db.parent.mkdir()
            start = time.monotonic()
            if mode == 'in_process':
                with bounded.in_process():
                    monkeypatch.setattr(bounded, 'invoke', timed)
                    result = surface.execute_audit(args, db_path=db, wait=True)
                    monkeypatch.setattr(bounded, 'invoke', original)
            else:
                result = surface.execute_audit(args, db_path=db, wait=True)
            timings[mode].append(time.monotonic() - start)
            assert result['status'] == 'completed'
    plain, bound = min(timings['in_process']), min(timings['bounded'])
    slowest = max(per_component.items(), key=lambda item: item[1])
    print(f'\nOVERHEAD in_process={timings["in_process"]} bounded={timings["bounded"]} '
          f'best_in_process={plain:.2f}s best_bounded={bound:.2f}s overhead={bound - plain:.2f}s '
          f'ratio={bound / plain:.2f} slowest_component={slowest[0]}:{slowest[1]:.2f}s '
          f'components={len(per_component)}')
    assert bound - plain < max(3.0, plain), (timings, per_component)
