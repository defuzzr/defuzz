"""Credential classification is path-only; contents are never parsed."""
from pathlib import Path
import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('name', ['.netrc', '.pgpass', '.git-credentials',
    '.docker/config.json', '.npmrc', 'pip.conf'])
def test_audit_credential_metadata_classification(name):
    assert load_submodule('audit.file_types').credential_file_kind(Path(name))
    assert load_submodule('audit.policy').credential_path(Path(name))


def test_audit_credential_metadata_not_generic_config():
    assert load_submodule('audit.file_types').credential_file_kind(Path('config.json')) is None


def test_audit_credential_content_parser_retired():
    assert not (Path(__file__).resolve().parents[1] / 'audit/credential_metadata.py').exists()

