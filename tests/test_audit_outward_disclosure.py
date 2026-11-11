"""The stored report never says more than was checked: skipped folders and cut trees are readable.

Synthetic homes under tmp_path only. Each home goes through the real full audit
(`execute_audit`), so the assertions read the stored, sealed report and its text summary.
"""
from pathlib import Path

from tests.conftest import load_submodule

# Import before any test patches os: fingerprint caches os.supports_dir_fd at import.
load_submodule('audit_surface')

SKIP = 'skipped_folders'
SKIP_SENTENCE = 'Dependency, cache and Git object folders were skipped and not checked.'
CAP_CODES = ('entry_limit_exceeded', 'total_byte_limit_exceeded', 'time_budget')
CAP_SENTENCES = {
    'entry_limit_exceeded': 'Some folders were not fully checked because the entry limit was reached.',
    'total_byte_limit_exceeded': 'Some folders were not fully checked because the size limit was reached.',
    'time_budget': 'Some folders were not fully checked because the time limit was reached.',
}


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def _home(tmp_path):
    home = tmp_path / 'home'
    profile = home / '.hermes'
    _write(profile / 'config.yaml', '{}\n')
    _write(profile / 'skills' / 'demo' / 'SKILL.md', '# Demo\n\nA plain skill.\n')
    return home, profile


def _audit(tmp_path, monkeypatch, profile):
    git = load_submodule('audit.outward_git')
    discover = getattr(git.discover_git_context, 'unpatched', git.discover_git_context)

    def no_system_gitconfig(*a, **kw):
        return discover(*a, **kw, system_config=tmp_path / 'absent-gitconfig')
    no_system_gitconfig.unpatched = discover
    monkeypatch.setattr(git, 'discover_git_context', no_system_gitconfig)
    monkeypatch.setenv('HERMES_HOME', str(profile))
    store = tmp_path / 'audit-store'
    store.mkdir(exist_ok=True)
    result = load_submodule('audit_surface').execute_audit({'action': 'run'}, db_path=store / 'audit.db', wait=True)
    assert result['status'] == 'completed'
    return result['report']


def _details(report, region):
    return {d['code']: d for d in report['scope']['regions'][region].get('reason_details', [])}


def _summary_text(report):
    summary = load_submodule('audit_summary')
    return ' '.join(summary.render_text(summary.summarize(report)).split())


def _stored_codes(report):
    """Every reason code the stored report carries: reason_details codes and tree cut words."""
    codes = []

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'reason_details' and isinstance(item, list):
                    codes.extend(d.get('code') if isinstance(d, dict) else d for d in item)
                elif key == 'truncated_by':
                    codes.append(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(report['scope'])
    walk([f.get('evidence') for f in report['findings'] if str(f.get('id', '')).startswith('audit.scope.')])
    return [c for c in codes if c is not None]


def _assert_codes_readable(report):
    vocabulary = load_submodule('audit.evidence').VOCABULARY
    codes = _stored_codes(report)
    assert all(isinstance(c, str) and c in vocabulary for c in codes), codes


def test_skipped_dependency_folder_is_disclosed_for_its_region(tmp_path, monkeypatch):
    home, profile = _home(tmp_path)
    outside = home / 'only-named-inside-dependencies'
    outside.mkdir()
    folder = profile / 'skills' / 'demo' / 'node_modules'
    _write(folder / 'pkg' / 'index.js', "require('" + str(outside) + "');\n")
    report = _audit(tmp_path, monkeypatch, profile)
    scope = report['scope']
    # docs/audit-scope.md: "Explicit exclusions and inaccessible paths remain `could_not_verify`."
    assert scope['regions']['skills']['coverage'] == 'could_not_verify'
    detail = _details(report, 'skills')[SKIP]
    assert detail['count'] == 1
    assert [s['location']['path'] for s in detail['samples']] == [str(folder)]
    pruned = scope['limits']['regions']['active_profile']['pruned_roots']
    assert pruned == {'count': 1, 'samples': [str(folder)]}
    assert not any(b['target'] == str(outside) for b in report['blending'])
    assert SKIP_SENTENCE in _summary_text(report)
    _assert_codes_readable(report)


def test_skipped_git_objects_in_a_referenced_tree_are_disclosed(tmp_path, monkeypatch):
    home, profile = _home(tmp_path)
    tree = home / 'src' / 'agent'
    _write(tree / 'README.md', 'Synthetic checkout.\n')
    _write(tree / '.git' / 'HEAD', 'ref: refs/heads/main\n')
    (tree / '.git' / 'refs').mkdir()
    for i in range(20):
        _write(tree / '.git' / 'objects' / f'{i:02x}' / ('0' * 38), 'blob\n')
    _write(profile / 'config.yaml', 'terminal:\n  cwd: ' + str(tree) + '\n')
    report = _audit(tmp_path, monkeypatch, profile)
    region = report['scope']['regions']['shared_infrastructure']
    assert region['coverage'] == 'could_not_verify'
    detail = _details(report, 'shared_infrastructure')[SKIP]
    assert [s['location']['path'] for s in detail['samples']] == [str(tree / '.git' / 'objects')]
    pruned = report['scope']['limits']['regions']['active_profile']['pruned_roots']
    assert str(tree / '.git' / 'objects') in pruned['samples']
    assert SKIP_SENTENCE in _summary_text(report)
    _assert_codes_readable(report)


def test_small_home_without_skipped_folders_stays_verified(tmp_path, monkeypatch):
    _home_root, profile = _home(tmp_path)
    report = _audit(tmp_path, monkeypatch, profile)
    assert report['scope']['regions']['skills']['coverage'] == 'verified'
    for name, region in report['scope']['regions'].items():
        codes = {d['code'] for d in region.get('reason_details', [])}
        assert not codes & {SKIP, 'excluded', *CAP_CODES}, (name, codes)
    assert all(b['pruned_roots'] == {'count': 0, 'samples': []}
               for b in report['scope']['limits']['regions'].values())
    text = _summary_text(report)
    assert SKIP_SENTENCE not in text
    assert not any(sentence in text for sentence in CAP_SENTENCES.values())
    _assert_codes_readable(report)


def test_capped_referenced_tree_prints_its_plain_sentence(tmp_path, monkeypatch):
    home, profile = _home(tmp_path)
    tree = home / 'src' / 'notes'
    for i in range(30):
        _write(tree / f'n{i}.md', 'note\n')
    _write(profile / 'config.yaml', 'terminal:\n  cwd: ' + str(tree) + '\n')
    monkeypatch.setattr(load_submodule('audit.outward'), 'MAX_TREE_ENTRIES', 10)
    report = _audit(tmp_path, monkeypatch, profile)
    assert 'entry_limit_exceeded' in _details(report, 'shared_infrastructure')
    text = _summary_text(report)
    assert CAP_SENTENCES['entry_limit_exceeded'] in text
    assert SKIP_SENTENCE not in text
    _assert_codes_readable(report)


def test_summary_has_one_fixed_sentence_per_cap_and_skip_code():
    summary = load_submodule('audit_summary')
    for code, sentence in {**CAP_SENTENCES, SKIP: SKIP_SENTENCE}.items():
        regions = {'skills': {'coverage': 'could_not_verify', 'reason_details': [{'code': code, 'count': 2}]},
                   'plugins': {'coverage': 'could_not_verify', 'reason_details': [{'code': code, 'count': 1}]}}
        text = summary.render_text(summary.summarize({'scope': {'regions': regions}}))
        assert ' '.join(text.split()).count(sentence) == 1, code


def test_many_startup_inputs_keep_every_reason_code_readable(tmp_path, monkeypatch):
    home, profile = _home(tmp_path)
    for name in ('.bashrc', '.profile', '.zshrc', '.bash_profile', '.pythonrc'):
        _write(home / name, 'export SYNTHETIC=1\n')
    lib = home / '.local' / 'lib'
    lib.mkdir(parents=True)
    for i in range(10001):  # home_startup discovery reads at most 10,000 directory entries
        (lib / f'e{i}').touch()
    monkeypatch.setattr(load_submodule('audit.outward'), 'MAX_INVOCATIONS', 2)
    report = _audit(tmp_path, monkeypatch, profile)
    region = report['scope']['regions']['shared_infrastructure']
    assert region['coverage'] == 'could_not_verify'
    details = _details(report, 'shared_infrastructure')
    assert 'invocation_limit_exceeded' in details
    assert 'entry_limit_exceeded' in details
    _assert_codes_readable(report)
    assert 'hmac' not in str([d['code'] for d in region['reason_details']])
