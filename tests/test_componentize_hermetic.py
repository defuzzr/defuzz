"""Default apply/CLI tests must never discover a host componentize executable."""
from .conftest import load_submodule


def test_componentize_probe_is_disabled_by_default(tmp_path, monkeypatch):
    bridge = load_submodule('componentize_bridge')
    def forbidden(*args, **kwargs):
        raise AssertionError('host executable discovery must be disabled')
    monkeypatch.setattr(bridge.shutil, 'which', forbidden)
    assert bridge.survey_after_apply(tmp_path)['status'] == 'skipped'
