"""Metadata-only outward analyzers; fixtures never execute inspected inputs."""
from .conftest import load_submodule


def test_dynamic_surfaces_are_unresolved_metadata():
    a = load_submodule('audit.outward_analyzers')
    surfaces = {
        'Makefile': 'build_recipe_unresolved', 'justfile': 'build_recipe_unresolved',
        'Dockerfile': 'container_build_unresolved', 'Containerfile': 'container_build_unresolved',
        '.envrc': 'environment_script_unresolved', 'build.rs': 'rust_build_unresolved',
        'Cargo.toml': 'rust_build_unresolved', 'main.go': 'source_execution_unresolved',
        'nb.ipynb': 'notebook_execution_unresolved', 'setup.cfg': 'entry_points_unresolved',
        'tox.ini': 'test_runner_unresolved', 'noxfile.py': 'test_runner_unresolved',
        '.git/config': 'git_config_unresolved', '.git/hooks/pre-commit': 'git_hook_unresolved',
        '.pre-commit-config.yaml': 'precommit_unresolved',
        '.github/workflows/build.yml': 'ci_execution_unresolved',
        '.gitlab-ci.yml': 'ci_execution_unresolved', 'package.json': 'package_scripts_unresolved',
        'unknown.sh': 'script_execution_unresolved', 'unknown': 'script_execution_unresolved',
    }
    for path, kind in surfaces.items():
        findings = a.analyze_dynamic(path, b'#!CANARY_COMMAND\n')
        assert findings == [{'path': path, 'kind': kind, 'resolution': 'unresolved'}]
        assert 'CANARY' not in str(findings)
    assert a.analyze_dynamic('README.txt', b'plain prose') == []
    assert a.analyze_dynamic('executable', b'opaque', mode=0o755)[0]['resolution'] == 'unresolved'


def test_credential_candidates_and_keys_never_return_values():
    a = load_submodule('audit.outward_analyzers')
    for name in ('.env', '.envrc', '.envprod', '.npmrc', '.pypirc', '.netrc',
                 'auth.json', 'credentials', 'credentials.backup', 'cert.pem',
                 'private.key', 'id_ed25519', 'id_custom'):
        assert a.credential_candidate('/project/' + name)
    assert not a.credential_candidate('/project/README.md')
    for key in ('OPENAI_API_KEY', 'GITHUB_PERSONAL_ACCESS_TOKEN', 'apiKey',
                'client_secret', 'PASSWORD', 'passwd', 'credentials', '_authToken'):
        assert a.credential_key_kind(key) == 'credential_value'
    assert a.credential_key_kind('command') is None
    assert a.credential_key_kind(None) is None
    assert a.credential_key_kind('CANARY_secret_CANARY') == 'credential_value'


def test_toolchains_use_only_explicit_home_and_inventory(tmp_path, monkeypatch):
    a = load_submodule('audit.outward_analyzers')
    home = tmp_path / 'work-home'
    monkeypatch.setenv('HOME', '/DO_NOT_USE')
    cases = [
        ('.python-version', b'3.12.8', home / '.pyenv/versions/3.12.8'),
        ('.node-version', b'22.4.0', home / '.nvm/versions/node/v22.4.0'),
        ('.nvmrc', b'v22.4.0', home / '.nvm/versions/node/v22.4.0'),
        ('.tool-versions', b'python 3.12.8 # comment', home / '.asdf/installs/python/3.12.8'),
        ('rust-toolchain.toml', b'[toolchain]\nchannel="stable"', home / '.rustup/toolchains/stable-x86_64-unknown-linux-gnu'),
        ('rust-toolchain', b'1.80.0', home / '.rustup/toolchains/1.80.0-x86_64-unknown-linux-gnu'),
        ('pyvenv.cfg', ('home = ' + str(home / '.pyenv/versions/3.12.8/bin')).encode(), home / '.pyenv/versions/3.12.8/bin'),
    ]
    for path, data, installed in cases:
        records = a.resolve_toolchain(path, data, home=home, available_paths=[installed])
        assert records == [{'path': path, 'kind': 'toolchain_reference',
                            'resolution': 'resolved', 'target': str(installed)}]
        assert a.resolve_toolchain(path, data, home=home)[0]['resolution'] == 'unresolved'
    assert a.resolve_toolchain('README.md', b'anything', home=home) == []


def test_conflicting_singleton_toolchain_declarations_are_unresolved(tmp_path):
    a = load_submodule('audit.outward_analyzers')
    target = tmp_path / '.pyenv/versions/3.12.8/bin'
    data = f'home = {target}\nhome = {target}'.encode()
    assert a.resolve_toolchain('pyvenv.cfg', data, home=tmp_path,
                               available_paths=[target]) == [
        {'path': 'pyvenv.cfg', 'kind': 'toolchain_reference', 'resolution': 'unresolved', 'target': None}]
    installed = tmp_path / '.rustup/toolchains/stable-x86_64-unknown-linux-gnu'
    result = a.resolve_toolchain('rust-toolchain.toml',
        b'[toolchain]\nchannel="stable"\npath="/CANARY"', home=tmp_path,
        available_paths=[installed])
    assert result[0]['resolution'] == 'unresolved'
    assert 'CANARY' not in str(result)


def test_toolchain_invalid_and_ambiguous_references_are_explicit(tmp_path):
    a = load_submodule('audit.outward_analyzers')
    for name, data in [('.python-version', b'../../CANARY'), ('.nvmrc', b'$(CANARY)'),
                       ('.tool-versions', b'CANARY system'), ('pyvenv.cfg', b'home=/outside/CANARY'),
                       ('rust-toolchain.toml', b'[broken CANARY'), ('.python-version', b'\xff'),
                       ('.node-version', b''), ('pyvenv.cfg', b'home=~/CANARY')]:
        assert a.resolve_toolchain(name, data, home=tmp_path) == [
            {'path': name, 'kind': 'toolchain_reference', 'resolution': 'unresolved', 'target': None}]
    paths = [tmp_path / '.pyenv/versions/3.12.8', tmp_path / '.asdf/installs/python/3.12.8']
    assert a.resolve_toolchain('.python-version', b'3.12.8', home=tmp_path,
                               available_paths=paths)[0]['resolution'] == 'unresolved'
