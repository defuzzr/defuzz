"""GET /audit/summary: the plain-language text of a stored run, read-only."""
import json

import pytest

from tests.conftest import load_submodule


def _completed_run(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    routes = load_submodule('dashboard.routes.audit_routes')
    outward = load_submodule('audit.outward')
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    (tmp_path / 'scratch-work').mkdir()
    (tmp_path / 'scratch-work' / 'big.bin').write_bytes(b'x' * 4096)

    def collector(*args, **kwargs):
        return {'regions': {'test': {'coverage': 'could_not_verify'}}, 'limits': {'max_entries': None, 'max_total_bytes': None, 'max_file_bytes': None},
                'blending': [], 'credentials': [], 'dynamic_invocations': [], 'session_history': {}}

    monkeypatch.setattr(outward, 'collect_outward', collector)
    monkeypatch.setattr(routes, 'execute_audit', lambda args: surface.execute_audit(
        args, db_path=tmp_path / 'audit.db', wait=True))
    started = routes.start({})
    assert started['status'] == 'completed'
    return routes, started


def test_summary_returns_rendered_text_for_completed_run(tmp_path, monkeypatch):
    routes, started = _completed_run(tmp_path, monkeypatch)
    summary_mod = load_submodule('audit_summary')
    result = routes.summary(started['run_id'])
    assert set(result) == {'run_id', 'status', 'text', 'summary'}
    assert result['run_id'] == started['run_id'] and result['status'] == 'completed'
    first_line = result['text'].splitlines()[0]
    assert first_line == summary_mod.HEADER_TITLE
    assert summary_mod.FOOTER_CLOSE in result['text']
    stored = routes.report(started['run_id'])['report']
    assert result['text'] == summary_mod.render_text(summary_mod.summarize(stored, home=str(tmp_path)))
    assert isinstance(result['summary'], dict)


def test_summary_never_contains_absolute_home(tmp_path, monkeypatch):
    routes, started = _completed_run(tmp_path, monkeypatch)
    result = routes.summary(started['run_id'])
    assert str(tmp_path) not in result['text']
    assert str(tmp_path) not in json.dumps(result, default=str)


def test_unknown_run_id_matches_report_route(tmp_path, monkeypatch):
    routes, _ = _completed_run(tmp_path, monkeypatch)
    errors = []
    for fn in (routes.report, routes.summary):
        with pytest.raises(routes.HTTPException) as error:
            fn('no-such-run')
        errors.append((error.value.status_code, error.value.detail))
    assert errors[0] == errors[1] == (404, 'Unknown audit run_id')


def test_not_ready_run_mirrors_report_route(tmp_path, monkeypatch):
    routes = load_submodule('dashboard.routes.audit_routes')
    pending = {'run_id': 'r1', 'status': 'running', 'as_of': 1, 'canonical_digest': None, 'report': None}
    monkeypatch.setattr(routes, 'execute_audit', lambda args: dict(pending))
    assert routes.report('r1')['status'] == 'running'
    assert routes.summary('r1') == {'run_id': 'r1', 'status': 'running', 'text': None, 'summary': None}


def test_summary_is_read_only(tmp_path, monkeypatch):
    routes, started = _completed_run(tmp_path, monkeypatch)
    db = tmp_path / 'audit.db'
    before = db.read_bytes()
    routes.summary(started['run_id'])
    routes.summary(started['run_id'])
    assert db.read_bytes() == before
