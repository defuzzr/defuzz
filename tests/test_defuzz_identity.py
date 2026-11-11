"""Public Project Defuzz identity contracts."""
from pathlib import Path
from .conftest import ensure_test_package

ROOT = Path(__file__).resolve().parents[1]


def test_public_identity_registration():
    plugin = ensure_test_package()
    class Context:
        def __init__(self):
            self.tools = []
            self.cli = []
            self.commands = []
        def get_config(self, key, default):
            return default
        def register_tool(self, **kw):
            self.tools.append(kw)
        def register_hook(self, *args, **kw):
            pass
        def register_cli_command(self, **kw):
            self.cli.append(kw)
        def register_command(self, **kw):
            self.commands.append(kw)
    ctx = Context()
    plugin.register(ctx)
    assert {t['name'] for t in ctx.tools} == {'defuzz_project', 'defuzz_place', 'defuzz_audit'}
    assert all(t['toolset'] == 'defuzz' and t['schema']['name'] == t['name'] for t in ctx.tools)
    assert [c['name'] for c in ctx.cli] == ['defuzz']
    assert [c['name'] for c in ctx.commands] == ['defuzz']
    assert '/defuzz' in ctx.commands[0]['handler']('')
    assert 'name: defuzz\n' in (ROOT / 'plugin.yaml').read_text()
    desktop = (ROOT / 'desktop/plugin.js').read_text()
    assert "const ROUTE_PATH = '/defuzz'" in desktop
    assert "id: 'defuzz'" in desktop  # ctx.rest derives its namespace from this ID.
    assert "name: 'Project Defuzz'" in desktop


def test_state_uses_public_storage_and_tracks_profile_without_migration(tmp_path, monkeypatch):
    from .conftest import load_submodule
    store = load_submodule('state_store')
    for profile in ('first', 'second'):
        home = tmp_path / profile
        legacy = home / 'plugins' / 'adopt-place' / 'state.db'
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(b'legacy database must remain untouched')
        monkeypatch.setenv('HERMES_HOME', str(home))
        target = store.state_db_path()
        assert target == home / 'plugin-data' / 'defuzz' / 'state.db'
        assert target.parent.is_dir()
        assert not target.exists()
        store.save_answers({'profile': profile})
        assert target.is_file()
        assert legacy.read_bytes() == b'legacy database must remain untouched'


def test_auditor_shares_public_state_path(tmp_path, monkeypatch):
    from .conftest import load_submodule
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    audit = load_submodule('audit.store')
    assert audit.audit_db_path() == tmp_path / 'plugin-data' / 'defuzz' / 'state.db'
    assert audit.ensure_audit_tables() == audit.audit_db_path()
