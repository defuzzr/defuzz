"""Existing-folder registration must not grant credential content previews."""

import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule


def _client():
    app = FastAPI()
    app.include_router(load_submodule('dashboard.plugin_api').router)
    return TestClient(app)


def _snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_mode, p.stat().st_size,
            p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
            for p in root.rglob('*')}


@pytest.mark.parametrize('relative', [
    '.ssh/id_rsa', '.SsH/notes.txt', 'nested/ID_RSA', 'nested/id_ed25519',
    '.env', 'nested/.ENV.production', 'nested/CREDENTIALS.JSON',
    '.AWS/config', 'secrets/notes.txt', 'nested/.npmrc',
])
def test_opened_project_refuses_credential_preview_before_content_read(tmp_path, monkeypatch, relative):
    root = tmp_path / 'ordinary-project'
    target = root / relative
    target.parent.mkdir(parents=True)
    target.write_text('PRIVATE_PREVIEW_CANARY', encoding='utf-8')
    (root / 'README.md').write_text('# ordinary source\n', encoding='utf-8')
    before = _snapshot(root)
    client = _client()
    opened = client.post('/workspace/projects/open', json={'path': str(root)})
    assert opened.status_code == 200, opened.text

    fingerprint = load_submodule('dashboard.plugin_api')._load('audit.fingerprint')
    reads = []
    original = fingerprint.safe_read_regular_file_plain

    def observe(*args, **kwargs):
        reads.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(fingerprint, 'safe_read_regular_file_plain', observe)
    response = client.get('/workspace/file', params={'project': str(root), 'path': relative})
    assert response.status_code == 400, response.text
    assert response.json() == {'detail': 'Unsafe or secret-bearing file path'}
    assert reads == []
    assert 'PRIVATE_PREVIEW_CANARY' not in response.text
    assert str(root) not in response.text
    assert _snapshot(root) == before


def test_opened_project_allows_normal_readme_preview(tmp_path):
    root = tmp_path / 'ordinary-project'
    root.mkdir()
    (root / 'README.md').write_text('# ordinary source\n', encoding='utf-8')
    before = _snapshot(root)
    client = _client()
    assert client.post('/workspace/projects/open', json={'path': str(root)}).status_code == 200
    response = client.get('/workspace/file', params={'project': str(root), 'path': 'README.md'})
    assert response.status_code == 200, response.text
    assert response.json()['content'] == '# ordinary source\n'
    assert _snapshot(root) == before


@pytest.mark.parametrize('component', ['.ssh', '.SsH', 'credentials'])
def test_registered_credential_root_refuses_normal_filename(tmp_path, monkeypatch, component):
    root = tmp_path / component
    root.mkdir()
    (root / 'notes.txt').write_text('PRIVATE_ROOT_CANARY', encoding='utf-8')
    client = _client()
    assert client.post('/workspace/projects/open', json={'path': str(root)}).status_code == 200

    def forbidden(*args, **kwargs):
        pytest.fail('credential-root preview attempted a content read')

    monkeypatch.setattr(load_submodule('dashboard.plugin_api')._load('audit.fingerprint'), 'safe_read_regular_file_plain', forbidden)
    response = client.get('/workspace/file', params={'project': str(root), 'path': 'notes.txt'})
    assert response.status_code == 400, response.text
    assert response.json() == {'detail': 'Unsafe or secret-bearing file path'}


@pytest.mark.parametrize('identifier', ['legacy/relative', '~/legacy-project', '   '])
def test_forget_route_removes_exact_legacy_identifier_without_touching_source(tmp_path, identifier):
    store = load_submodule('state_store')
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'README.md').write_text('keep source', encoding='utf-8')
    before = _snapshot(source)
    db = store.state_db_path()
    store.list_projects(db)
    with sqlite3.connect(db) as conn:
        conn.execute('INSERT INTO projects (path, name, slug, languages, created_at) '
                     'VALUES (?, ?, ?, ?, ?)', (identifier, 'Legacy', 'legacy', '[]', 0))
    response = _client().post('/workspace/projects/forget', json={'path': identifier})
    assert response.status_code == 200, response.text
    assert response.json() == {'status': 'forgotten', 'removed': True}
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT path FROM projects WHERE path = ?', (identifier,)).fetchall() == []
    assert _snapshot(source) == before
