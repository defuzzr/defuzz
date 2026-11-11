"""Unavailable picker entries stay visible but cannot start any work."""
import json
from unittest.mock import Mock

import pytest
from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import FakeKitBridge, load_list_fixture
from tests.test_kit_routes import _build_client

ensure_test_package()
from hermes_plugins.defuzz import catalog_list, cli, componentize_bridge, new_project, kit_scaffold

REFUSAL = "future-render is coming soon and cannot be created yet."


@pytest.fixture(autouse=True)
def synthetic_future_kit(monkeypatch, tmp_path):
    """Exercise the real picker loader without publishing an unavailable kit."""
    picker = catalog_list.load_picker_text()
    picker['entries']['kit:future-render'] = {
        'title': 'Future renderer', 'line': 'Coming soon. A synthetic renderer.',
        'group': 'workspace', 'order': 999, 'coming_soon': True,
    }
    path = tmp_path / 'picker.json'
    path.write_text(json.dumps(picker), encoding='utf-8')
    monkeypatch.setattr(catalog_list, 'PICKER_TEXT_PATH', path)
    from tests.conftest import load_submodule
    routes = load_submodule('dashboard.plugin_api')._load('dashboard.routes.workspace_routes')
    monkeypatch.setattr(routes.catalog_list, 'PICKER_TEXT_PATH', path)
    original_init = FakeKitBridge.__init__

    def init_with_future(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._list_data['kits'].append({
            'id': 'future-render', 'name': 'Future renderer',
            'summary': 'Future render GPU scenes.',
            'tags': ['future', 'render', 'gpu'], 'version': 1,
        })

    monkeypatch.setattr(FakeKitBridge, '__init__', init_with_future)


def test_cli_lists_coming_soon(monkeypatch, capsys):
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    assert cli.main(['list']) == 0
    text = capsys.readouterr().out
    assert '  [coming soon]' in text
    assert '[--kit future-render]' not in text
    assert 'Coming soon.' in text
    assert cli.main(['list', '--json']) == 0
    data = json.loads(capsys.readouterr().out)
    row = next(e for e in data['entries'] if e['id'] == 'future-render')
    assert row['coming_soon'] is True
    assert row['selectable'] is False
    kits = [e for e in data['entries'] if e['kind'] == 'kit']
    assert len(kits) == len(load_list_fixture()["kits"]) + 1
    assert len([e for e in kits if e.get('selectable', True)]) == len(load_list_fixture()["kits"])


def test_explicit_cli_refuses_before_bridge_or_writes(monkeypatch, tmp_path, capsys):
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    root = tmp_path / 'projects'
    assert cli.main(['new', '--kit', 'future-render', '--name', 'render', '--dest-root', str(root), '--yes']) != 0
    captured = capsys.readouterr()
    assert (captured.out + captured.err).strip() == REFUSAL
    assert not root.exists()
    assert not bridge.list_calls + bridge.show_calls + bridge.apply_calls + bridge.check_calls


def test_flow_and_proposal_refuse_before_bridge_or_writes(tmp_path):
    bridge = Mock()
    root = tmp_path / 'projects'
    res = new_project.run_new_project_flow(kit_id='future-render', kit_bridge=bridge, dest_root=root)
    assert res.status == 'error'
    assert res.message == REFUSAL
    with pytest.raises(kit_scaffold.ScaffoldError, match=REFUSAL):
        kit_scaffold.propose_kit('future-render', 'render', {}, dest_root=root, bridge=bridge)
    assert not bridge.mock_calls
    assert not root.exists()


def test_route_refuses_before_bridge_or_writes(monkeypatch, tmp_path):
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)
    root = tmp_path / 'projects'
    response = client.post('/scaffold/propose', json={'kit_id': 'future-render', 'name': 'render', 'dest_root': str(root)})
    assert response.status_code == 409
    assert response.json()['detail'] == REFUSAL
    assert not root.exists()
    assert not bridge.list_calls + bridge.show_calls + bridge.apply_calls + bridge.check_calls


def test_router_never_suggests_coming_soon(monkeypatch):
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)
    response = client.post('/scaffold/match', json={'prompt': 'Future render GPU scenes'})
    assert response.status_code == 200
    data = response.json()
    assert 'kit:future-render' not in data['catalog']['suggested']
    assert all(k['kit_id'] != 'future-render' for k in data['kits'])


def test_router_excludes_a_flagged_template(monkeypatch):
    from tests.conftest import load_submodule
    client = _build_client(monkeypatch, FakeKitBridge())
    routes = load_submodule('dashboard.plugin_api')._load('dashboard.routes.workspace_routes')
    picker = routes.catalog_list.load_picker_text()
    picker['entries']['template:python-golden']['coming_soon'] = True
    monkeypatch.setattr(routes.catalog_list, 'load_picker_text', lambda: picker)
    response = client.post('/scaffold/match', json={'answers': {'building': 'service', 'layout': 'single', 'languages': ['python']}})
    assert response.status_code == 200
    data = response.json()
    assert all(m['template_id'] != 'python-golden' for m in data['matches'] + data['closest'])
    assert 'template:python-golden' not in data['catalog']['suggested']
    row = next(e for e in data['catalog']['entries'] if e['id'] == 'python-golden')
    assert row['selectable'] is False


def test_generic_flag_preserves_normal_choices():
    entries = catalog_list.build_catalog(
        [{'id': 'normal-template'}, {'id': 'future-template'}],
        [{'id': 'normal-kit'}, {'id': 'future-kit'}],
        picker={'entries': {f'{kind}:future-{kind}': {'coming_soon': True} for kind in ('kit', 'template')}},
    )
    for number, entry in enumerate(entries, 1):
        expected = None if entry['id'].startswith('future-') else entry
        assert catalog_list.find_entry(entries, str(number)) == expected
        assert catalog_list.find_entry(entries, entry['id']) == expected


@pytest.mark.parametrize(('kind', 'ident'), [('kit', 'video-production'), ('template', 'fake-rust-game')])
def test_normal_kit_and_template_still_work(monkeypatch, tmp_path, capsys, kind, ident):
    from tests.test_cli_list_first import TEMPLATES_FIXTURES
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    root = tmp_path / 'projects'
    rc = cli.main(['new', f'--{kind}', ident, '--name', 'normal', '--dest-root', str(root), '--templates-root', str(TEMPLATES_FIXTURES)])
    out = capsys.readouterr()
    assert rc == 0, out.out + out.err
    assert 'coming soon' not in out.out + out.err
    if kind == 'kit':
        assert bridge.apply_calls
    else:
        assert 'Cargo.toml' in out.out


def test_agent_dispatch_refuses_coming_soon():
    import hermes_plugins.defuzz as plugin
    args = {'action': 'new', 'kit_id': 'future-render'}
    assert cli.execute_defuzz_project(args) == {'ok': False, 'error': REFUSAL}
    assert json.loads(plugin._handle_defuzz_project_tool(args)) == {'ok': False, 'error': REFUSAL}


def test_preview_refuses_before_companion(monkeypatch):
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)
    response = client.get('/scaffold/kits/future-render')
    assert response.status_code == 409
    assert response.json()['detail'] == REFUSAL
    assert not bridge.list_calls + bridge.show_calls


def test_legacy_kits_list_marks_coming_soon(monkeypatch, capsys):
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    assert cli.main(['kits']) == 0
    assert 'Coming soon' in capsys.readouterr().out
    assert cli.main(['kits', '--json']) == 0
    kits = json.loads(capsys.readouterr().out)['kits']
    row = next(k for k in kits if k['id'] == 'future-render')
    assert row['coming_soon'] is True
    assert row['selectable'] is False
