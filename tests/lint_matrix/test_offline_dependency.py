"""An uncached dependency must remain unknown/incomplete, not clean offline."""
import os
import shutil

import pytest

from ..conftest import load_submodule
from .test_matrix import executor, write_receipt


def test_offline_uncached_clippy_is_closed(tmp_path):
    if not shutil.which('cargo'):
        write_receipt(tmp_path, 'offline-cold-cache', [dict(tool='clippy', version=None,
            status='missing', evidence=['cargo absent'])], network_denial='not executed')
        pytest.skip('cargo absent; explicit missing receipt emitted')
    root = tmp_path / 'project'
    (root / 'src').mkdir(parents=True)
    (root / 'src/main.rs').write_text('fn main() {}\n')
    (root / 'Cargo.toml').write_text(
        '[package]\nname = "matrix_cold"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\nserde = "=1.0.228"\n')
    env = dict(os.environ, CARGO_HOME=str(tmp_path / 'empty-cargo'), CARGO_NET_OFFLINE='true')
    evidence = []
    run = executor(True, evidence)
    version = run(['cargo', 'clippy', '--version'], cwd=root, env=env, timeout_s=20)
    result = load_submodule('linter').run_lint(root, 'post', env=env, runner=run,
                                             db_path=tmp_path / 'state.sqlite')
    row = next(s for s in result['tool_statuses'] if s['tool'] == 'clippy')
    assert row['status'] not in ('clean', 'findings'), result
    assert result['status'] == 'incomplete' and not result['ok'], result
    assert not [f for f in result['findings'] if f['tool'] == 'clippy']
    assert any('offline' in e['stderr'] and 'serde' in e['stderr'] for e in evidence), evidence
    write_receipt(tmp_path, 'offline-cold-cache', [dict(tool='clippy',
        version=version.stdout.strip(), status='missing', reason='uncached dependency; closed unknown',
        evidence=dict(commands=evidence, result=result))],
        network_denial='libseccomp socket(domain != AF_UNIX) + cargo --offline',
        interpretation='Expected non-pass; no fabricated finding or clean verdict')
