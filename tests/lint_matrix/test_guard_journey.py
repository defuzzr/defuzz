"""Guard journey through the public CLI/API; no fake tools, probes, doctor or lint runner."""
import json
from ..conftest import load_submodule
from .test_matrix import write_receipt


def test_tools_lock_guard_journey(tmp_path, capsys):
    cli = load_submodule('cli')
    seed = load_submodule('tool_seed')
    chk = load_submodule('toolchk')
    guard = load_submodule('tool_guard')
    doctor = load_submodule('tool_doctor')
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'sample.py').write_text('answer = 42\n')
    (root / 'pyproject.toml').write_text('[project]\nname = "matrix"\nversion = "0.1.0"\n')
    seeded = seed.seed_lock(root, event='manual', template_needs=['python'])
    lock = chk.load_lock(root / 'TOOLS.lock')
    assert 'python' in lock['tools'], seeded
    original = lock['tools']['python']['version']
    assert original != 'unknown'
    lock['tools']['python']['version'] = '0.0.0'
    chk.dump_lock(root / 'TOOLS.lock', lock)
    state = guard.inspect_lock_trust(root)
    guard.trust_lock(root, expected_hash=state['tools_lock_hash'])
    before = doctor.doctor_report([root])
    assert before['projects'][0]['status'] == 'drift', before
    blocked = cli.main(['lint', str(root), '--mode', 'pre', '--json'])
    blocked_output = capsys.readouterr()
    assert blocked == 2, blocked_output
    assert 'drift' in blocked_output.out.lower()
    assert 'tools_run' not in json.loads(blocked_output.out), 'preflight failed to block lint'
    reviewed = guard.edit_lock(root, 'python', 'Reviewed actual interpreter for matrix fixture', action='accept')
    readback = chk.load_lock(root / 'TOOLS.lock')
    assert readback['tools']['python']['version'] == original
    assert readback['tools']['python']['source'] == 'human'
    assert guard.inspect_lock_trust(root)['trusted']
    after = doctor.doctor_report([root])
    assert after['ok'], after
    passed = cli.main(['lint', str(root), '--mode', 'pre', '--json'])
    output = capsys.readouterr()
    assert passed == 0, output
    result = json.loads(output.out)
    assert not result['findings'] and result['tools_run']
    write_receipt(tmp_path, 'guard-journey', [dict(tool='python', version=original,
        status='pass', evidence=dict(seed=seeded, doctor_drift=before, blocked_exit=blocked,
        blocked_output=blocked_output.out, review=reviewed, lock_readback=readback,
        doctor_after=after, relint=result))])
