"""The outward sweep is bounded on big referenced trees and says so when a bound is hit."""
import json
import os
from pathlib import Path

from tests.conftest import load_submodule


def _home(tmp_path):
    profile = tmp_path / 'home' / '.hermes'
    profile.mkdir(parents=True)
    return load_submodule('audit.outward'), profile


def _reads(monkeypatch):
    reads = []
    original = os.open

    def guard(path, flags, mode=0o777, *, dir_fd=None):
        full = Path(os.readlink('/proc/self/fd/' + str(dir_fd))) / path if dir_fd is not None else Path(path)
        if not flags & os.O_DIRECTORY:
            reads.append(str(full))
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, 'open', guard)
    return reads


def _codes(result, region):
    return {d['code']: d['count'] for d in result['regions'][region].get('reason_details', [])}


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _source_tree(root, outside):
    """A referenced checkout with dependency, cache and object folders."""
    _write(root / 'package.json', '{"name": "web"}\n')
    _write(root / 'src' / 'main.py', 'import os\n')
    for folder in ('node_modules/pkg', 'web/node_modules/@scope/dep', '__pycache__', '.pytest_cache',
                   '.git/objects/ab', '.git/lfs/objects', 'target/debug', '.venv/lib/python3.12/site-packages/dep'):
        _write(root / folder / 'index.js', "require('" + str(outside) + "');\n")
    _write(root / 'target' / 'CACHEDIR.TAG', 'Signature: 8a477f597d28d172789f06886806bc55\n')
    _write(root / '.venv' / 'pyvenv.cfg', 'home = /usr/bin\n')
    _write(root / '.git' / 'HEAD', 'ref: refs/heads/main\n')
    (root / '.git' / 'refs').mkdir()


def test_dependency_cache_and_object_folders_are_skipped_and_counted(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'agent'
    outside = tmp_path / 'home' / 'linked-only-from-dependencies'
    outside.mkdir(parents=True)
    _source_tree(tree, outside)
    editable = tmp_path / 'home' / 'editable-source'
    editable.mkdir()
    _write(tree / '.venv' / 'lib' / 'python3.12' / 'site-packages' / 'dep-1.0.dist-info' / 'direct_url.json',
           json.dumps({'url': editable.as_uri(), 'dir_info': {'editable': True}}))
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    reads = _reads(monkeypatch)
    result = mod.collect_outward(profile, [])
    skipped = [tree / p for p in ('node_modules', 'web/node_modules', '__pycache__', '.pytest_cache',
                                  '.git/objects', '.git/lfs', 'target')]
    assert not [p for p in reads if any(Path(p).is_relative_to(s) for s in skipped)]
    assert not [p for p in reads if Path(p).is_relative_to(tree / '.venv') and not p.endswith(('pyvenv.cfg', 'direct_url.json'))]
    assert str(tree / 'src' / 'main.py') in reads
    assert not any(b['target'] == str(outside) for b in result['blending'])
    # Editable-install metadata inside a virtual environment is still read.
    assert any(b['target'] == str(editable) and b['relationship'] == 'editable_install' for b in result['blending'])
    pruned = result['limits']['regions']['active_profile']['pruned_roots']
    assert pruned['count'] == 8
    assert len(pruned['samples']) == 3 and all(s.startswith(str(tree)) for s in pruned['samples'])
    assert result['limits']['trees']['max_tree_entries'] == mod.MAX_TREE_ENTRIES
    # Skipping is a declared scope rule, not a cut: no limit reason, but the region says what was skipped.
    assert not any(code in _codes(result, 'shared_infrastructure') for code in
                   ('entry_limit_exceeded', 'time_budget', 'total_byte_limit_exceeded'))
    assert _codes(result, 'shared_infrastructure')['skipped_folders'] == 8
    assert result['regions']['shared_infrastructure']['coverage'] == 'could_not_verify'


def test_unbounded_still_walks_dependency_folders(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'agent'
    _source_tree(tree, tmp_path)
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    reads = _reads(monkeypatch)
    result = mod.collect_outward(profile, [], unbounded=True)
    assert str(tree / 'node_modules' / 'pkg' / 'index.js') in reads
    assert result['limits']['regions']['active_profile']['pruned_roots']['count'] == 0


def test_tree_entry_limit_is_reported_with_what_was_covered(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'agent'
    for i in range(30):
        _write(tree / f'f{i}.md', 'text\n')
    (profile / 'skills').mkdir()
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    monkeypatch.setattr(mod, 'MAX_TREE_ENTRIES', 10)
    result = mod.collect_outward(profile, [])
    assert result['regions']['shared_infrastructure']['coverage'] == 'could_not_verify'
    assert 'entry_limit_exceeded' in _codes(result, 'shared_infrastructure')
    cut = [t for t in result['limits']['regions']['active_profile']['trees'] if t['path'] == str(tree)]
    assert len(cut) == 1
    assert cut[0]['truncated_by'] == 'entry_limit_exceeded'
    assert cut[0]['entries_walked'] == 10 and cut[0]['max_tree_entries'] == 10
    # The profile's own tree is a separate tree and is not cut by the referenced one.
    assert result['regions']['skills']['coverage'] == 'verified'


def test_tree_byte_and_time_limits_are_reported(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'agent'
    for i in range(5):
        _write(tree / f'f{i}.md', 'x' * 1000)
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    monkeypatch.setattr(mod, 'MAX_TREE_BYTES', 2500)
    result = mod.collect_outward(profile, [])
    cut = [t for t in result['limits']['regions']['active_profile']['trees'] if t['path'] == str(tree)]
    assert cut[0]['truncated_by'] == 'total_byte_limit_exceeded' and cut[0]['bytes_read'] <= 2500
    assert 'total_byte_limit_exceeded' in _codes(result, 'shared_infrastructure')

    monkeypatch.setattr(mod, 'MAX_TREE_BYTES', 10 ** 9)
    monkeypatch.setattr(mod, 'MAX_TREE_SECONDS', 0)
    result = mod.collect_outward(profile, [])
    cut = [t for t in result['limits']['regions']['active_profile']['trees'] if t['path'] == str(tree)]
    assert cut[0]['truncated_by'] == 'time_budget' and cut[0]['max_seconds'] == 0
    assert 'time_budget' in _codes(result, 'shared_infrastructure')
    assert result['limits']['trees']['max_seconds'] == 0
    # The shared wall time of all referenced trees is a second, separate bound.
    monkeypatch.setattr(mod, 'MAX_TREE_SECONDS', 10 ** 6)
    monkeypatch.setattr(mod, 'MAX_REFERENCED_SECONDS', 0)
    result = mod.collect_outward(profile, [])
    cut = [t for t in result['limits']['regions']['active_profile']['trees'] if t['path'] == str(tree)]
    assert cut[0]['truncated_by'] == 'time_budget' and result['limits']['max_seconds'] == 0


def test_selected_projects_and_profile_are_not_cut_by_tree_limits(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    project = (tmp_path / 'project').resolve()
    for i in range(20):
        _write(project / f'f{i}.md', 'text\n')
        _write(profile / 'skills' / f's{i}' / 'SKILL.md', 'skill\n')
    monkeypatch.setattr(mod, 'MAX_TREE_ENTRIES', 3)
    monkeypatch.setattr(mod, 'MAX_TREE_SECONDS', 0)
    result = mod.collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'verified'
    assert result['regions']['skills']['coverage'] == 'verified'
    assert all(not b['trees'] for b in result['limits']['regions'].values())


def test_referenced_tree_reads_large_files_only_up_to_the_file_cap(tmp_path):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'agent'
    _write(tree / 'bundle.js', 'x' * (5 * 1024 * 1024))
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    result = mod.collect_outward(profile, [], max_file_bytes=1000)
    assert 'file_byte_limit_exceeded' in _codes(result, 'shared_infrastructure')
    assert result['limits']['regions']['active_profile']['bytes_read'] <= 2 * 1024 * 1024


def test_nested_checkout_inside_profile_has_its_own_tree(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    agent = profile / 'hermes-agent'
    (agent / '.git').mkdir(parents=True)
    for i in range(30):
        _write(agent / f'f{i}.md', 'text\n')
    _write(profile / 'skills' / 'demo' / 'SKILL.md', 'skill\n')
    monkeypatch.setattr(mod, 'MAX_TREE_ENTRIES', 12)
    result = mod.collect_outward(profile, [])
    trees = {t['path']: t for t in result['limits']['regions']['active_profile']['trees']}
    assert trees[str(agent)]['truncated_by'] == 'entry_limit_exceeded'
    assert str(profile) not in trees
    assert result['regions']['skills']['coverage'] == 'verified'
    assert 'entry_limit_exceeded' in _codes(result, 'active_profile')


def test_outside_subject_large_and_binary_targets_are_not_matched(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    outside = tmp_path / 'elsewhere'
    linked = tmp_path / 'home' / 'linked'
    linked.mkdir(parents=True)
    _write(outside / 'big.md', 'see ' + str(linked) + '\n' + 'x' * 5000)
    (outside / 'blob.md').write_bytes(b'\x00\x01 see ' + str(linked).encode() + b'\n')
    _write(outside / 'small.md', 'see ' + str(linked) + '\n')
    _write(outside / 'repo.git' / 'HEAD', 'ref: refs/heads/main\n')
    (outside / 'repo.git' / 'refs').mkdir()
    _write(outside / 'repo.git' / 'objects' / 'pack' / 'pack-1.pack', 'PACK')
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(outside) + '\n')
    monkeypatch.setattr(mod, 'MAX_OUTSIDE_FILE_BYTES', 1024)
    reads = _reads(monkeypatch)
    observed = []
    redaction = load_submodule('audit.redaction')
    original = redaction.Taint.observe

    def observe(self, path, data):
        observed.append(str(path))
        return original(self, path, data)

    monkeypatch.setattr(redaction.Taint, 'observe', observe)
    result = mod.collect_outward(profile, [])
    assert str(outside / 'big.md') not in reads
    assert not any(p.startswith(str(outside / 'repo.git' / 'objects')) for p in reads)
    assert str(outside / 'blob.md') not in observed and str(outside / 'big.md') not in observed
    sources = {b['source'] for b in result['blending'] if b['target'] == str(linked)}
    assert sources == {str(outside / 'small.md')}
    codes = _codes(result, 'shared_infrastructure')
    assert 'file_byte_limit_exceeded' in codes and 'unknown_file_type' in codes
    assert result['limits']['trees']['max_file_bytes'] == 1024


def test_system_directories_outside_subject_are_not_walked(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    system = tmp_path / 'sysroot'
    _write(system / 'share' / 'doc.md', 'text\n')
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(system / 'share') + '\n')
    monkeypatch.setattr(mod, 'SYSTEM_ROOTS', (str(system),), raising=False)
    reads = _reads(monkeypatch)
    result = mod.collect_outward(profile, [])
    assert not any(p.startswith(str(system)) for p in reads)
    assert any(b['target'] == str(system / 'share') for b in result['blending'])
    assert 'excluded' in _codes(result, 'shared_infrastructure')
    assert result['regions']['shared_infrastructure']['coverage'] == 'could_not_verify'


def test_many_dependency_files_do_not_cost_per_file_work(tmp_path, monkeypatch):
    mod, profile = _home(tmp_path)
    tree = tmp_path / 'home' / 'src' / 'agent'
    for i in range(400):
        _write(tree / 'node_modules' / f'p{i}' / 'index.js', "require('/usr/lib/x');\n")
    _write(tree / 'main.py', 'x = 1\n')
    (profile / 'config.yaml').write_text('terminal:\n  cwd: ' + str(tree) + '\n')
    result = mod.collect_outward(profile, [])
    assert result['limits']['regions']['active_profile']['entries_inspected'] < 20
