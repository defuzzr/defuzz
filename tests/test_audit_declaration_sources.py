"""Fixed declaration discovery: no speculative structured-file reads."""
import json
import os
import sys
from pathlib import Path

from tests.conftest import load_submodule


def test_audit_declaration_discovery_does_not_open_arbitrary_candidates(tmp_path, monkeypatch):
    policy = load_submodule('audit.policy')
    load_submodule('audit.fingerprint')  # Establish dir_fd support before wrapping os.open.
    redaction = load_submodule('audit.redaction')
    root = tmp_path / 'project'
    root.mkdir()
    for name in ('000.json', 'zz-settings.json', 'extra.yaml', 'extra.toml'):
        (root / name).write_text(json.dumps({'credential_file': '000.json'}))
    (root / 'config.yaml').write_text('credential_file: [config.yaml, settings.json]\n')
    (root / 'settings.json').write_text(json.dumps({'credential_file': 'payload.dat'}))
    (root / 'payload.dat').write_text('A05C_INERT_CANARY')
    opened = []
    enabled = [True]
    def observe(path):
        if enabled[0] and isinstance(path, (str, bytes, os.PathLike)):
            path = Path(os.path.abspath(os.fsdecode(path)))
            if path.parent == root:
                opened.append(path.name)
    def hook(event, args):
        if event == 'open':
            observe(args[0])
    sys.addaudithook(hook)
    original = os.open
    def wrapped(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / path if dir_fd is not None else path
        observe(full)
        return original(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(os, 'open', wrapped)
    @redaction.redaction_scope
    def run():
        policy.credential_declarations(root, tmp_path)
        assert not policy.credential_path(root / 'config.yaml')
        assert not policy.credential_path(root / 'settings.json')
        assert policy.credential_path(root / 'payload.dat')
        assert not policy.credential_path(root / '000.json')  # no arbitrary declaration authority
    try:
        run()
    finally:
        enabled[0] = False
    assert set(opened) == {'config.yaml', 'settings.json'}
