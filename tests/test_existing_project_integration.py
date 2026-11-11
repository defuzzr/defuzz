"""Public mounted API opens existing folders without scaffolding them."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.conftest import load_submodule


def client():
    app = FastAPI()
    app.include_router(load_submodule('dashboard.plugin_api').router)
    return TestClient(app)


def test_mounted_open_tree_preview_and_forget(isolated_home, tmp_path):
    root = tmp_path / 'existing'
    root.mkdir()
    source = root / 'README.md'
    source.write_text('# Existing project\n')
    before = (source.read_bytes(), source.stat().st_mtime_ns, root.stat().st_mtime_ns)
    api = client()
    discovery = api.get('/workspace/available-projects')
    assert discovery.status_code == 200, discovery.text
    opened = api.post('/workspace/projects/open', json={'path': str(root)})
    assert opened.status_code == 200, opened.text
    listed = api.get('/workspace/projects').json()
    assert listed['coverage'] == 'verified'
    assert str(root) in [r['canonical_path'] for r in listed['projects']]
    tree = api.get('/workspace/tree', params={'project': str(root)})
    assert tree.status_code == 200, tree.text
    assert tree.json()['files'] == ['README.md']
    preview = api.get('/workspace/file', params={'project': str(root), 'path': 'README.md'})
    assert preview.status_code == 200, preview.text
    assert preview.json()['content'] == '# Existing project\n'
    raw_path = next(r['raw_path'] for r in listed['projects'] if r['canonical_path'] == str(root))
    forgotten = api.post('/workspace/projects/forget', json={'path': raw_path})
    assert forgotten.status_code == 200, forgotten.text
    assert forgotten.json()['removed'] is True
    assert not api.get('/workspace/projects').json()['projects']
    assert api.get('/workspace/tree', params={'project': str(root)}).status_code == 400
    assert (source.read_bytes(), source.stat().st_mtime_ns, root.stat().st_mtime_ns) == before
    assert not (root / '.adopt').exists()


def test_mounted_existing_boundaries(isolated_home):
    api = client()
    for path in ['relative', '/safe/../other', '/bad\npath', '/' + 'a' * 4097]:
        result = api.post('/workspace/projects/open', json={'path': path})
        assert 400 <= result.status_code < 500, result.text
    assert api.get('/workspace/tree', params={'project': '/bad\npath'}).status_code == 400
