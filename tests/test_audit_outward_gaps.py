"""Regressions promoted from review probes p1-p8."""
import json
import os
import sqlite3
from pathlib import Path
from tests.conftest import load_submodule
from tests.test_audit_outward import capture_reason_text


def fixture(tmp_path):
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    project = tmp_path / 'srv' / 'mono' / 'pkg'
    project.mkdir(parents=True)
    (project.parent / '.git').mkdir()
    return load_submodule('audit.outward'), profile, project


def test_p2_parent_context_outside_home_and_variants(tmp_path):
    mod, profile, project = fixture(tmp_path)
    names = ('AGENTS.md', 'agents.md', 'AGENTS.override.md', 'HERMES.md', '.hermes.md', 'CLAUDE.md', 'claude.md', '.cursorrules')
    for name in names:
        (project.parent / name).write_text('instructions')
    r = mod.collect_outward(profile, [str(project)])
    targets = {b['target'] for b in r['blending'] if b['relationship'] == 'parent_context'}
    assert {str(project.parent / n) for n in names} <= targets
    assert r['limits']['parent_context_boundary'] == str(project.parent)


def test_p3_dynamic_fallthrough(tmp_path):
    mod, profile, project = fixture(tmp_path)
    files = {'Makefile': 'all:\n\techo x', 'justfile': 'default:\n  echo x',
             'Dockerfile': 'RUN echo x', '.envrc': 'eval x', 'build.rs': 'fn main(){}',
             'main.go': '//go:generate sh x', 'nb.ipynb': '{"cells": []}',
             'setup.cfg': '[options.entry_points]', 'tox.ini': '[testenv]',
             'Cargo.toml': '[package]\nbuild="build.rs"', 'unknown.weird': '#!strange'}
    for name, body in files.items():
        (project / name).write_text(body)
    result = mod.collect_outward(profile, [str(project)])
    flagged = {Path(p).name for d in result['dynamic_invocations'] for p in d.get('samples', [d['path']])}
    assert set(files) - {'.envrc'} <= flagged
    assert any(c.get('kind') == 'credential_store' and c['path'].endswith('/.envrc') for c in result['credentials'])


def test_p5_credential_patterns_and_failed_parse(tmp_path):
    mod, profile, project = fixture(tmp_path)
    secret = 'CANARY-SECRET-12345'
    (profile / 'config.yaml').write_text('OPENAI_API_KEY: '+secret+'\nmcp_servers:\n  gh:\n    env:\n      CUSTOM_VALUE: '+secret+'\nproviders:\n  a:\n    apiKey: '+secret+'\n    client_secret: '+secret+'\n')
    (project / '.npmrc').write_text('_authToken='+secret)
    (project / '.env.broken').write_bytes(b'\xff')
    result = mod.collect_outward(profile, [str(project)])
    assert len(result['credentials']) == 6
    assert secret not in json.dumps(result)
    assert result['regions']['credentials']['coverage'] == 'could_not_verify'
    assert all('key_path' in c or c.get('kind') == 'credential_store' for c in result['credentials'])
    assert 'credential_store_not_opened' in json.dumps(result)


def test_p1_project_budget_independent_and_streamed(tmp_path, monkeypatch):
    reason_text = capture_reason_text(monkeypatch)
    mod, profile, project = fixture(tmp_path)
    for i in range(40):
        (profile / str(i)).write_text('x')
    (project / 'hook.sh').write_text('echo x')
    (project / 'large.bin').write_bytes(b'x' * 10000)
    result = mod.collect_outward(profile, [str(project)], max_entries=10, max_file_bytes=16)
    assert any(d['path'] == str(project / 'hook.sh') for d in result['dynamic_invocations'])
    assert result['regions']['project_tree']['coverage'] == 'could_not_verify'
    assert not any('entry_limit' in reason_text(r) for r in result['regions']['project_tree']['reasons'])
    assert result['regions']['active_profile']['coverage'] == 'could_not_verify'
    assert result['limits']['max_entries'] == 10
    assert result['limits']['regions'][str(project.resolve())]['bytes_read'] >= 10000


def test_p8_sqlite_large_readonly_subdir_and_repo_association(tmp_path):
    mod, profile, project = fixture(tmp_path)
    db = profile / 'state.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE sessions (cwd TEXT, git_repo_root TEXT, started_at INTEGER)')
        conn.executemany('INSERT INTO sessions VALUES (?,?,?)', [
            (str(project / 'src'), None, 1), ('elsewhere', str(project), 2),
            (str(project)+'-other', None, 3)])
    with db.open('r+b') as f:
        f.truncate(500 * 1024 * 1024)
    before = db.stat().st_mtime_ns
    result = mod.collect_outward(profile, [str(project)], max_file_bytes=16)
    assert result['session_history']['selected_project_records'] == 2
    assert result['session_history']['records_inspected'] == 2
    assert result['regions']['session_history']['coverage'] == 'verified'
    assert db.stat().st_mtime_ns == before
    assert not Path(str(db)+'-wal').exists()


def test_p4_incoming_sibling_and_p7_dirfd_read_guard(tmp_path, monkeypatch):
    mod, profile, project = fixture(tmp_path)
    sibling = profile / 'profiles' / 'blend'
    (sibling / 'skills' / 'x').mkdir(parents=True)
    (sibling / 'skills' / 'x' / 'SKILL.md').write_text('skill')
    (sibling / 'config.yaml').write_text('skills:\n  external_dirs: ['+str(project)+']\n')
    other = profile / 'profiles' / 'other'
    (other / 'skills').mkdir(parents=True)
    (other / 'config.yaml').write_text('{}')
    (other / 'skills' / 'private').write_text('never read')
    external = tmp_path / 'referenced'
    external.mkdir()
    (external / 'entry.sh').write_text('echo x')
    untouched = tmp_path / 'unreferenced'
    untouched.mkdir()
    (untouched / 'private').write_text('never read')
    (profile / 'config.yaml').write_text('plugins:\n  path: '+str(external)+'\n')
    reads = []
    original = os.open
    def guard(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(os.readlink('/proc/self/fd/'+str(dir_fd))) / path if dir_fd is not None else Path(path)
        if not flags & os.O_DIRECTORY:
            reads.append(str(full))
        return original(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(os, 'open', guard)
    result = mod.collect_outward(profile, [str(project)])
    assert str(other / 'config.yaml') in reads
    assert str(sibling / 'skills' / 'x' / 'SKILL.md') in reads
    assert not any(Path(p).is_relative_to(other / 'skills') or Path(p).is_relative_to(untouched) for p in reads)
    assert str(external / 'entry.sh') in reads
    assert any(b['relationship'] == 'incoming_sibling_reference' and b['source'] == str(sibling / 'config.yaml') for b in result['blending'])
    assert any(b['target'] == str(external) for b in result['blending'])


def test_toolchain_concrete_metadata_and_unresolved(tmp_path, monkeypatch):
    reason_text = capture_reason_text(monkeypatch)
    mod, profile, project = fixture(tmp_path)
    python = profile.parent / '.pyenv' / 'versions' / '3.12.8'
    (python / 'bin').mkdir(parents=True)
    node = profile.parent / '.nvm' / 'versions' / 'node' / 'v22.1.0'
    node.mkdir(parents=True)
    (project / '.python-version').write_text('3.12.8')
    (project / '.nvmrc').write_text('v22.1.0')
    (project / 'pyvenv.cfg').write_text('home = '+str(python / 'bin'))
    (project / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="missing"')
    result = mod.collect_outward(profile, [str(project)])
    targets = {b['target'] for b in result['blending'] if b['relationship'] == 'toolchain_metadata'}
    assert {str(python), str(python / 'bin'), str(node)} <= targets
    assert any('toolchain_unresolved' in reason_text(reason) for reason in result['regions']['shared_infrastructure']['reasons'])


def test_credential_mapping_keys_and_late_symlink_are_redacted(tmp_path, monkeypatch):
    from contextlib import contextmanager
    mod, profile, project = fixture(tmp_path)
    canary = 'SECRET-CANARY-IN-KEY'
    (profile / 'config.yaml').write_text(json.dumps({'providers': {canary: {'api_key': 'value'}, 'test': {canary + '_token': 'value'}}}))
    result = mod.collect_outward(profile, [str(project)])
    assert canary not in json.dumps(result)
    (project / 'plain.json').write_text(json.dumps({'path': canary}))
    (project / '.env.alias').symlink_to('plain.json')
    original = os.scandir
    @contextmanager
    def alias_last(fd):
        with original(fd) as entries:
            yield iter(sorted(entries, key=lambda e: e.name == '.env.alias'))
    monkeypatch.setattr(os, 'scandir', alias_last)
    result = mod.collect_outward(profile, [str(project)])
    assert canary not in json.dumps(result)
    assert result['regions']['credentials']['coverage'] == 'could_not_verify'


def test_session_wal_never_creates_sidecars(tmp_path):
    mod, profile, project = fixture(tmp_path)
    db = profile / 'state.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE sessions(cwd TEXT)')
    Path(str(db)+'-wal').write_bytes(b'unsupported live journal')
    before = {f.name: f.read_bytes() for f in profile.iterdir()}
    result = mod.collect_outward(profile, [str(project)])
    after = {f.name: f.read_bytes() for f in profile.iterdir()}
    assert before == after
    assert result['regions']['session_history']['coverage'] == 'could_not_verify'


def test_malformed_credential_candidate_is_unknown(tmp_path):
    mod, profile, project = fixture(tmp_path)
    (project / '.env.bad').write_text('not an assignment')
    result = mod.collect_outward(profile, [str(project)])
    assert result['regions']['credentials']['coverage'] == 'could_not_verify'
    assert 'not an assignment' not in json.dumps(result)


def test_tool_versions_and_uv_resolution(tmp_path):
    mod, profile, project = fixture(tmp_path)
    uv = profile.parent / '.local/share/uv/python/cpython-3.13.2-linux-x86_64-gnu'
    uv.mkdir(parents=True)
    node = profile.parent / '.nvm/versions/node/v22.1.0'
    node.mkdir(parents=True)
    (project / '.tool-versions').write_text('python 3.13.2\nnodejs 22.1.0')
    result = mod.collect_outward(profile, [str(project)])
    targets = {b['target'] for b in result['blending'] if b['relationship'] == 'toolchain_metadata'}
    assert {str(uv), str(node)} <= targets


def test_real_size_profile_benchmark(tmp_path):
    import time
    import resource
    mod, profile, project = fixture(tmp_path)
    for directory in range(100):
        folder = profile / 'cache' / str(directory)
        folder.mkdir(parents=True)
        for index in range(2000):
            (folder / f'{index}.txt').write_bytes(b'x')
    db = profile / 'state.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE sessions (cwd TEXT, git_repo_root TEXT, started_at INTEGER)')
        conn.execute('INSERT INTO sessions VALUES (?, ?, ?)', (str(project / 'src'), str(project), 123))
    with db.open('r+b') as stream:
        stream.truncate(500 * 1024 * 1024)
    (project / 'README.md').write_text('plain project')
    started = time.monotonic()
    result = mod.collect_outward(profile, [str(project)])
    measurement = {'wall_seconds': time.monotonic() - started,
                   'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                   'entries_inspected': result['limits']['entries_inspected'],
                   'sqlite_bytes': db.stat().st_size,
                   'project_coverage': result['regions']['project_tree']['coverage']}
    print('OUTWARD_BENCHMARK=' + json.dumps(measurement, sort_keys=True))
    assert measurement['entries_inspected'] >= 200000
    assert measurement['project_coverage'] == 'verified'
    assert result['regions']['active_profile']['coverage'] == 'verified'
    assert result['session_history']['selected_project_records'] == 1


def test_hookspath_and_arbitrary_structured_credentials(tmp_path):
    mod, profile, project = fixture(tmp_path)
    hooks = tmp_path / 'hooks'
    hooks.mkdir()
    (hooks / 'pre-commit').write_text('#!sh\necho x')
    (project / '.git').mkdir()
    (project / '.git' / 'config').write_text('[core]\n hooksPath = '+str(hooks))
    (project / 'settings.local.json').write_text(json.dumps({'Password': 'SECRET-CANARY'}))
    result = mod.collect_outward(profile, [str(project)])
    assert any(b['target'] == str(hooks) for b in result['blending'])
    assert any(c['path'] == str(project / 'settings.local.json') for c in result['credentials'])
    assert 'SECRET-CANARY' not in json.dumps(result)






