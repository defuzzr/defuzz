"""Componentize API contract, through the host-mounted plugin router."""
import asyncio
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.test_plugin_api import _load_plugin_api

PREFIX = '/api/plugins/defuzz/componentize'


@pytest.mark.parametrize('body', [None, [], {'unknown': True}, {'run_survey_on_new': 1}])
def test_settings_invalid_body_returns_error(body, tmp_path):
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'plugin_data_dir', return_value=tmp_path):
        response = client.put(PREFIX + '/settings', json=body)
    assert response.status_code == 400
    assert set(response.json()) == {'error'}


@pytest.mark.parametrize('method', ['get', 'put'])
@pytest.mark.parametrize('error,code,message', [(ValueError('bad settings'), 400, 'bad settings'),
    (OSError('private filesystem detail'), 500, 'componentize settings unavailable')])
def test_settings_errors(method, error, code, message):
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'load' if method == 'get' else 'save', side_effect=error):
        response = getattr(client, method)(PREFIX + '/settings', **({'json': {}} if method == 'put' else {}))
    if method == 'put' and isinstance(error, OSError):
        # A failed save is a failed write: one plain 400 sentence, not a server error.
        assert response.status_code == 400
        assert set(response.json()) == {'error'}
        assert response.json()['error'].startswith('The change could not be saved')
        assert 'private' not in response.text
        return
    assert response.status_code == code
    assert response.json() == {'error': message}


def test_status_no_project_runs_off_event_loop():
    client, settings, _ = client_and_settings()
    expected = dict(detected=False, version=None, source='absent', last_survey=None)
    def probe(root):
        assert root is None
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()
        return expected
    with mock.patch.object(settings, 'status', side_effect=probe) as status:
        response = client.get(PREFIX + '/status')
    assert response.status_code == 200
    assert response.json() == expected
    status.assert_called_once_with(None)


@pytest.mark.parametrize('registered,coverage,changed,code', [
    (True, 'verified', False, 200), (False, 'verified', False, 400),
    (True, 'partial', False, 400), (True, 'verified', True, 400)])
def test_status_authorizes_before_probe(tmp_path, registered, coverage, changed, code):
    client, settings, api = client_and_settings()
    db = api._load('audit.readonly_db')
    snapshot = SimpleNamespace(records=[{'canonical_path': str(tmp_path)}] if registered else [],
                               coverage=coverage, changed_during_read=changed)
    with mock.patch.object(db, 'read_profile_registrations_readonly', return_value=snapshot), \
         mock.patch.object(settings, 'status', return_value={'last_survey': None}) as status:
        response = client.get(PREFIX + '/status', params={'project_root': str(tmp_path)})
    assert response.status_code == code
    if code == 200:
        status.assert_called_once_with(tmp_path)
    else:
        assert set(response.json()) == {'error'}
        status.assert_not_called()


def test_settings_malformed_json_is_400():
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'save') as save:
        response = client.put(PREFIX + '/settings', content='{', headers={'Content-Type': 'application/json'})
    assert response.status_code == 400
    assert set(response.json()) == {'error'}
    save.assert_not_called()


@pytest.mark.parametrize('project', ['', ' ', '\x00', '/'])
def test_status_invalid_root_never_probes(project):
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'status') as status:
        response = client.get(PREFIX + '/status', params={'project_root': project})
    assert response.status_code == 400
    assert set(response.json()) == {'error'}
    status.assert_not_called()


def test_settings_follow_profile_storage_changes(tmp_path):
    client, settings, _ = client_and_settings()
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    with mock.patch.object(settings, 'plugin_data_dir', return_value=first) as storage:
        assert client.put(PREFIX + '/settings', json={'run_survey_on_new': True}).status_code == 200
        storage.return_value = second
        assert client.get(PREFIX + '/settings').json() == settings.DEFAULTS
        storage.return_value = first
        assert client.get(PREFIX + '/settings').json()['run_survey_on_new'] is True


@pytest.mark.parametrize('error,code', [(ValueError('corrupt'), 400), (OSError('private'), 500)])
def test_status_errors(error, code):
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'status', side_effect=error):
        response = client.get(PREFIX + '/status')
    assert response.status_code == code
    assert set(response.json()) == {'error'}
    assert 'private' not in response.text


@pytest.mark.parametrize('error', [RuntimeError('private'), KeyError('private'), OSError('private')])
def test_status_unexpected_errors_have_stable_shape(error, caplog):
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'status', side_effect=error):
        response = client.get(PREFIX + '/status')
    assert response.status_code == 500
    assert response.json() == {'error': 'componentize status unavailable'}
    assert caplog.records


def test_componentize_mount_preserves_host_dependencies():
    from fastapi import Depends, HTTPException
    api = _load_plugin_api()
    settings = api._load('componentize_settings')
    app = FastAPI()
    def reject():
        raise HTTPException(401, 'Unauthorized')
    app.include_router(api.router, prefix='/api/plugins/defuzz', dependencies=[Depends(reject)])
    with mock.patch.object(settings, 'save') as save:
        response = TestClient(app).put(PREFIX + '/settings', json={'cli_path_override': '/untrusted'})
    assert response.status_code == 401
    save.assert_not_called()


def client_and_settings():
    api = _load_plugin_api()
    app = FastAPI()
    app.include_router(api.router, prefix='/api/plugins/defuzz')
    return TestClient(app), api._load('componentize_settings'), api


def test_settings_roundtrip_and_replace(tmp_path):
    client, settings, _ = client_and_settings()
    with mock.patch.object(settings, 'plugin_data_dir', return_value=tmp_path):
        assert client.get(PREFIX + '/settings').json() == settings.DEFAULTS
        response = client.put(PREFIX + '/settings', json={'run_survey_on_new': True})
        assert response.status_code == 200
        assert response.json()['run_survey_on_new'] is True
        assert client.get(PREFIX + '/settings').json() == response.json()
        assert client.put(PREFIX + '/settings', json={}).json() == settings.DEFAULTS
