"""ARM scope is configuration resolution only. Never execute an ARM binary here."""
import json
import re

from packaging.markers import default_environment
from packaging.requirements import Requirement
import yaml

from ..conftest import REPO_ROOT, load_submodule
from .cases import CASES, OPTIONAL
from .test_matrix import FIXTURES, write_receipt


WHEELS = {
    'ruff': 'ruff', 'ruff-format': 'ruff', 'yamllint': 'yamllint',
    'rumdl': 'rumdl', 'shfmt': 'shfmt-py', 'hadolint': 'hadolint-py',
    'clang-format': 'clang-format', 'clang-tidy': 'clang-tidy',
    'gdformat': 'gdtoolkit', 'gdlint': 'gdtoolkit',
}
TIERS = {
    'rustfmt': 'rust', 'clippy': 'rust', 'gofmt': 'go', 'go-vet': 'go',
    'dotnet-format': 'dotnet', 'csharpier': 'dotnet',
    'pwsh-parse': 'pwsh', 'psscriptanalyzer': 'pwsh',
    'glslangValidator': 'glslang', 'biome-json': 'biome',
}


def test_arm_matrix_configuration_receipt(tmp_path):
    setup = load_submodule('lint_setup')
    plan = {row['name']: row for row in setup.describe_plan(
        platform=('linux', 'aarch64'), env={}, real_home=tmp_path / 'home',
        install_root=tmp_path / 'opt', bin_dir=tmp_path / 'bin')}
    dependencies = {r.name: r for r in map(Requirement,
        yaml.safe_load((REPO_ROOT / 'plugin.yaml').read_text())['python_dependencies'])}
    artifacts = json.loads((FIXTURES / 'arm-wheel-artifacts.json').read_text())
    rows = []
    for tool in [*CASES, *OPTIONAL]:
        row = dict(tool=tool, version=None, status='fail', execution='DEFERRED', evidence=[])
        rows.append(row)
        try:
            if tool in OPTIONAL:
                row.update(status='missing', evidence=['Optional research tool has no configured install tier'])
                continue
            if tool in WHEELS:
                package = WHEELS[tool]
                req = dependencies[package]
                for machine in ('aarch64', 'ARM64'):
                    env = dict(default_environment(), platform_machine=machine, sys_platform='linux', platform_system='Linux')
                    assert req.marker is None or req.marker.evaluate(env), str(req)
                catalog = artifacts[package]
                assert catalog['version'] in req.specifier
                assert catalog['artifacts'], f'No aarch64/universal wheel for {req}'
                for artifact in catalog['artifacts']:
                    assert ('aarch64' in artifact['filename'] or artifact['filename'].endswith('none-any.whl'))
                    assert re.fullmatch('[0-9a-f]{64}', artifact['sha256'])
                row.update(status='pass', version=catalog['version'], evidence=catalog)
                continue
            tier = TIERS.get(tool, tool)
            if tier not in plan:
                row.update(status='missing', evidence=[f'No linux/aarch64 artifact in lint_setup for {tier}'])
                continue
            artifact = plan[tier]
            assert 'aarch64' in artifact['url'] or 'arm64' in artifact['url'], artifact
            assert re.fullmatch('[0-9a-f]{64}|[0-9a-f]{128}', artifact['hash'])
            if tool in ('taplo', 'shellcheck'):
                req = dependencies['taplo' if tool == 'taplo' else 'shellcheck-py']
                assert req.marker is not None
                for machine in ('aarch64', 'ARM64'):
                    assert not req.marker.evaluate(dict(default_environment(), platform_machine=machine))
            row.update(status='pass', version=artifact['version'], evidence=artifact)
        except Exception as exc:
            row['evidence'] = [f'{type(exc).__name__}: {exc}']
    path = write_receipt(tmp_path, 'arm-config', rows, architecture='aarch64',
                         real_execution='DEFERRED: x86_64 host, no emulator installed',
                         wheel_evidence='Pinned PyPI JSON metadata snapshot; no ARM wheel execution')
    assert {r['tool'] for r in rows} == set(CASES) | set(OPTIONAL)
    assert not [r for r in rows if r['status'] == 'fail'], str(path)
    # Missing artifacts are explicit non-passes. This catches new silent omissions
    # while recording known upstream binary-tier gaps without pretending to run ARM.
    assert {r['tool'] for r in rows if r['status'] == 'missing'} == {
        'selene', 'glslangValidator', 'dxc', *OPTIONAL}, str(path)
