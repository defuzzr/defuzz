"""Real executables online and offline: real detection/argv/parsers, fail-closed receipts."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

from ..conftest import load_submodule
from .cases import CASES, LANGUAGE_ROWS, OPTIONAL

FIXTURES = Path(__file__).parents[1] / 'fixtures' / 'lint_matrix'


def write_receipt(tmp_path, name, rows, **metadata):
    path = tmp_path / (name + '.json')
    path.write_text(json.dumps(dict(rows=rows, **metadata), indent=2, default=str))
    print(f'\nLINT_MATRIX_RECEIPT={path}', flush=True)
    return path


def deny_network():
    """Kernel-enforced denial inherited by every tool child, including static Go/Rust."""
    lib = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    class Comparison(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                    ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                         ctypes.c_uint, ctypes.POINTER(Comparison)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not ctx:
        raise RuntimeError('seccomp_init failed')
    try:
        for syscall in (b'socket', b'io_uring_setup'):
            nr = lib.seccomp_syscall_resolve_name(syscall)
            comparison = Comparison(0, 1, 1, 0)  # SCMP_CMP_NE: domain != AF_UNIX
            count = 1 if syscall == b'socket' else 0
            if nr >= 0 and lib.seccomp_rule_add_array(ctx, 0x50000 | errno.EPERM, nr, count, ctypes.byref(comparison)) != 0:
                raise RuntimeError('seccomp_rule_add failed')
        if lib.seccomp_load(ctx) != 0:
            raise RuntimeError('seccomp_load failed')
    finally:
        lib.seccomp_release(ctx)


def executor(offline, evidence):
    def run(cmd, *, cwd, env, timeout_s):
        result = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True,
                                timeout=timeout_s, preexec_fn=deny_network if offline else None)
        evidence.append(dict(argv=list(map(str, cmd)), returncode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        return result
    return run


def fixture(root, tool, text):
    root.mkdir(parents=True)
    filename = CASES[tool][1]
    target = root / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    if tool == 'clippy':
        (root / 'Cargo.toml').write_text('[package]\nname = "matrix"\nversion = "0.1.0"\nedition = "2021"\n')
    if tool in ('go-vet', 'golangci-lint'):
        (root / 'go.mod').write_text('module example.com/matrix\n\ngo 1.20\n')
    if tool == 'clang-tidy':
        (root / '.clang-tidy').write_text("Checks: 'clang-analyzer-*'\nInheritParentConfig: false\n")
        (root / 'compile_commands.json').write_text(json.dumps([
            dict(directory=str(root), file=filename, arguments=['clang++', '-c', filename])]))
    if tool == 'dotnet-format':
        (root / 'Matrix.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    return target


def version_command(tool, binary):
    return {'clippy': [binary, 'clippy', '--version'],
            'gofmt': ['go', 'version', binary], 'go-vet': [binary, 'version'],
            'psscriptanalyzer': [binary, '-NoProfile', '-NonInteractive', '-Command',
                '(Get-Module -ListAvailable PSScriptAnalyzer).Version.ToString()'],
            }.get(tool, [binary, '--version'])


def test_frozen_matrix_inventory():
    source = (FIXTURES / 'tool-matrix.md').read_bytes()
    assert hashlib.sha256(source).hexdigest().startswith('33e34bc7ffea8db1')
    rows = [line.split('|')[1].strip() for line in source.decode().splitlines()
            if line.startswith('| ') and '`' in line and not line.startswith('| **')]
    assert set(rows) == set(LANGUAGE_ROWS)
    assert {t for names in LANGUAGE_ROWS.values() for t in names} == set(CASES) | set(OPTIONAL)
    specs = load_submodule('lint_tools').TOOLS
    assert {s.name for s in specs} == set(CASES) - {'biome-json'}


@pytest.mark.parametrize('offline', [False, True], ids=['L06-online', 'L07-offline'])
@pytest.mark.parametrize('tool', [*CASES, *OPTIONAL])
def test_real_lint_matrix(tmp_path, offline, tool, capsys):
    if sys.platform != 'linux':
        pytest.skip('Linux execution matrix')
    if tool in OPTIONAL:
        with capsys.disabled():
            write_receipt(tmp_path, 'offline' if offline else 'online',
                          [dict(tool=tool, version=None, status='skip',
                                reason='not_implemented', optional=True, evidence=[])],
                          real_execution=False)
        pytest.skip(f'optional/unimplemented: {tool}')
    evidence = []
    run = executor(offline, evidence)
    env = dict(os.environ, CARGO_NET_OFFLINE='true', GOTOOLCHAIN='local',
               DOTNET_CLI_TELEMETRY_OPTOUT='1')
    tool_root = os.environ.get('LINT_MATRIX_TOOL_ROOT')
    if tool_root:
        tools = Path(tool_root)
        env['PATH'] = str(tools / 'bin') + os.pathsep + env['PATH']
        env['DOTNET_ROOT'] = str(tools / 'opt' / 'dotnet')
        env['PSModulePath'] = str(tools / 'home/.local/share/powershell/Modules')
    mechanism = 'none'
    if offline:
        mechanism = 'libseccomp: EPERM socket(domain != AF_UNIX), io_uring_setup; inherited by descendants; close_fds'
        # A real blocked connection proves enforcement, not just proxy variables.
        probe = run([sys.executable, '-c',
            'import socket,errno; '
            '\ntry: socket.socket()'
            '\nexcept OSError as e: assert e.errno == errno.EPERM'
            '\nelse: raise AssertionError("network denial bypassed")'],
            cwd=tmp_path, env=env, timeout_s=10)
        assert probe.returncode == 0, probe.stderr
    specs = {s.name: s for s in load_submodule('lint_tools').TOOLS}
    mode, filename, bad, clean, diagnostic = CASES[tool]
    name = 'biome' if tool == 'biome-json' else tool
    spec = specs[name]
    row = dict(tool=tool, version=None, status='fail', evidence=[])
    start = len(evidence)
    try:
        binary = shutil.which(spec.binaries[0], path=env['PATH'])
        if binary:
            cp = run(version_command(name, binary), cwd=tmp_path, env=env, timeout_s=20)
            row['version'] = (cp.stdout + cp.stderr).strip()
            assert cp.returncode == 0 and re.search(r'\d+\.\d+', row['version']), 'version readback failed'
        outcomes = {}
        for label, text in [('bad', bad), ('clean', clean)]:
            root = tmp_path / tool / label
            target = fixture(root, tool, text)
            result = load_submodule('linter').run_lint(root, mode, env=env, runner=run,
                                                     db_path=tmp_path / 'state.sqlite')
            assert target.read_text() == text, 'lint modified the fixture'
            statuses = [s for s in result['tool_statuses'] if s['tool'] == name]
            findings = [f for f in result['findings'] if f['tool'] == name]
            outcomes[label] = dict(statuses=statuses, findings=findings)
            assert len(statuses) == 1, f'row silently absent: {outcomes[label]}'
            if not binary:
                assert statuses[0]['status'] == 'not_installed', outcomes[label]
                continue
            assert statuses[0]['status'] == ('findings' if label == 'bad' else 'clean'), outcomes[label]
            if label == 'bad':
                assert any(diagnostic.lower() in (f['rule'] + ' ' + f['message']).lower()
                           and Path(f['file']).name == Path(filename).name for f in findings), outcomes[label]
            else:
                assert not findings, outcomes[label]
        row['outcomes'] = outcomes
        row['status'] = 'pass' if binary else 'missing'
        if not binary:
            row['reason'] = 'Executable absent from supplied toolchain PATH; not an execution pass; installation not attempted by tests'
    except Exception as exc:
        row['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        row['evidence'] = evidence[start:]
    with capsys.disabled():
        path = write_receipt(tmp_path, 'offline' if offline else 'online', [row],
                             network_denial=mechanism, denial_canary=evidence[:1] if offline else [],
                             real_execution=True)
    assert row['status'] != 'fail', f"Failed row: {tool}: {row.get('error')}; {path}"
    if row['status'] == 'missing':
        reason = f'not installed: {tool}'
        if os.environ.get('LINT_MATRIX_STRICT') == '1':
            pytest.fail(f'{reason}; LINT_MATRIX_STRICT=1; {path}')
        pytest.skip(reason)
