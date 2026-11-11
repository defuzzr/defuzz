"""End to end: the nine wired audit sections reach the sealed report intact (synthetic homes only)."""
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, load_submodule
from tests.test_audit_session_contamination import database
from tests.test_audit_user_db_readonly import snapshot
from tests import test_audit_home_workdirs as t_home_workdirs
from tests import test_audit_kanban_residue as t_kanban
from tests import test_audit_profile_duplicates as t_profile_duplicates
from tests import test_audit_skill_ledger as t_skill_ledger
from tests import test_audit_skill_packs as t_skill_packs

# Import before any test patches os.open: fingerprint caches os.supports_dir_fd at import.
load_submodule('audit_surface')

SHEETS = {p.stem: json.loads(p.read_text(encoding='utf-8'))
          for p in sorted((REPO_ROOT / 'audit' / 'wiring').glob('*.json'))}


def _wiring():
    return load_submodule('audit.evidence_wiring')


def _put(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def _home(tmp_path):
    """One synthetic Hermes home that gives each wired module something to measure."""
    home = tmp_path / 'home'
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'main.py').write_text('print(1)\n', encoding='utf-8')
    # home_workdirs: work folders, archives, executables, nested homes, Hermes folders.
    t_home_workdirs._rich_home(home)
    (home / 'pipe').unlink()                      # no FIFO in a home the whole audit walks
    (home / 'state.db').unlink()                  # replaced by a real session/registration store
    shutil.rmtree(home / 'kanban' / 'boards' / 'b1')
    database(home, project)
    registry = home / 'plugin-data' / 'defuzz' / 'state.db'   # the plugin's project registry
    registry.parent.mkdir(parents=True)
    conn = sqlite3.connect(registry)
    conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
    conn.execute('INSERT INTO projects VALUES (?, ?)', (str(project), 'synthetic'))
    conn.commit()
    conn.close()
    t_kanban._positive_home(home)                     # kanban_residue: one board firing board rules
    t_skill_ledger._build_rich_home(home)             # skill_ledger: ledger, blobs, snapshots
    t_skill_packs.build_render_fixture(home)          # skill_packs: an index of skills
    t_profile_duplicates._rich_home(home, symlink=False)  # profile_duplicates: cloned profiles
    # unattended_exposure + memory_load: config, an enabled prompt-injecting plugin, memory files.
    _put(home, 'config.yaml',
         'model: test\napprovals:\n  mode: \'off\'\nterminal:\n  backend: local\n'
         'updates:\n  pre_update_backup: \'off\'\n'
         'plugins:\n  enabled:\n    - hookplug\n'
         'memory:\n  memory_char_limit: 60\n  user_char_limit: 40\n')
    _put(home, 'plugins/hookplug/plugin.yaml', 'name: hookplug\nversion: 1.0.0\nprovides_hooks:\n  - pre_llm_call\n')
    _put(home, 'plugins/hookplug/__init__.py', 'def register(ctx):\n    pass\n')
    _put(home, 'memories/MEMORY.md', '\n§\n'.join([
        '2026-01-01 Always run the python tests first.', '2026-01-02 Never push on a Friday.',
        '2026-01-03 Rust crates live in a workspace.', '2026-01-04 Always run the python tests first.']))
    _put(home, 'memories/USER.md', 'The user builds tools and prefers short answers.')
    # secret_file_copies + dead_stores: a backup copy of a secret store, dumps, piles, locks.
    _put(home, '.env.bak-20260101', 'K=placeholder\n')
    for i in range(11):
        _put(home, f'sessions/request_dump_{i}_20261001.json', '{}')
    for i in range(18):
        _put(home, f'n{i}.md.bak', 'n')
    for i in range(11):
        lock = _put(home, f'locks/l{i}.lock', '')
        os.utime(lock, (1780000000.0, 1780000000.0))
    return home, project


@pytest.fixture
def watched_tmpdir(tmp_path, monkeypatch):
    """TMPDIR points at an empty folder; any file or folder created in it, or any tempfile use, fails."""
    watched = tmp_path / 'watched-tmpdir'
    watched.mkdir()
    for var in ('TMPDIR', 'TMP', 'TEMP'):
        monkeypatch.setenv(var, str(watched))
    monkeypatch.setattr(tempfile, 'tempdir', str(watched))
    creates = []
    orig_open, orig_mkdir = os.open, os.mkdir

    def inside(path, dir_fd=None):
        p = (Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / path
             if dir_fd is not None and not Path(path).is_absolute() else Path(path))
        return p == watched or p.is_relative_to(watched)

    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
        if inside(path, dir_fd):
            creates.append(str(path))
        return orig_open(path, flags, mode, dir_fd=dir_fd)

    def guarded_mkdir(path, mode=0o777, *, dir_fd=None):
        if inside(path, dir_fd):
            creates.append(str(path))
        return orig_mkdir(path, mode, dir_fd=dir_fd)

    def forbidden(*args, **kwargs):
        creates.append('tempfile')
        raise AssertionError('audit must not create temporary files or directories')

    monkeypatch.setattr(os, 'open', guarded_open)
    monkeypatch.setattr(os, 'mkdir', guarded_mkdir)
    for name in ('TemporaryDirectory', 'mkdtemp', 'mkstemp', 'NamedTemporaryFile'):
        monkeypatch.setattr(tempfile, name, forbidden)
    yield watched, creates


def _audit(tmp_path, monkeypatch, hermes_home, **args):
    surface = load_submodule('audit_surface')
    monkeypatch.setenv('HERMES_HOME', str(hermes_home))
    git = load_submodule('audit.outward_git')
    discover = getattr(git.discover_git_context, 'unpatched', git.discover_git_context)

    def no_system_gitconfig(*a, **kw):
        return discover(*a, **kw, system_config=tmp_path / 'absent-gitconfig')
    no_system_gitconfig.unpatched = discover
    monkeypatch.setattr(git, 'discover_git_context', no_system_gitconfig)
    store = tmp_path / 'audit-store'
    store.mkdir(exist_ok=True)
    return surface.execute_audit({'action': 'run', **args}, db_path=store / 'audit.db', wait=True)


def _record(monkeypatch, names):
    """Wrap wired entries to record their kwargs and raw envelopes."""
    surface = load_submodule('audit_surface')
    calls = {}
    for name in names:
        entry, description = surface._WIRED[name]

        def wrapper(*, _entry=entry, _name=name, **kwargs):
            out = _entry(**kwargs)
            calls.setdefault(_name, []).append((kwargs, out))
            return out
        monkeypatch.setitem(surface._WIRED, name, (wrapper, description))
    return calls


def _consequence(rule):
    return _wiring().WIRED_FINDING_CONSEQUENCES[rule]


def _walk(sealed, raw, path, tmp_root, vocabulary, problems):
    """Compare a sealed section with the raw section it came from."""
    if isinstance(sealed, dict) and 'hmac' in sealed:
        problems.append(f'{path}: sealed token for {raw!r}'[:160])
    elif isinstance(sealed, dict):
        for key, item in sealed.items():
            if key.startswith('hmac:'):
                problems.append(f'{path}: sealed key')
            _walk(item, raw.get(key) if isinstance(raw, dict) else None, f'{path}.{key}',
                  tmp_root, vocabulary, problems)
    elif isinstance(sealed, list):
        for index, item in enumerate(sealed):
            _walk(item, raw[index] if isinstance(raw, list) and index < len(raw) else None,
                  f'{path}[{index}]', tmp_root, vocabulary, problems)
    elif isinstance(sealed, str):
        if sealed not in vocabulary and not (Path(sealed).is_absolute() and Path(sealed).is_relative_to(tmp_root)):
            problems.append(f'{path}: {sealed[:80]!r}')


def _section_findings(report, section):
    return [f for f in report['findings'] if isinstance(f.get('id'), str) and f['id'].startswith(section + '.')]


def test_full_audit_stores_all_nine_sections_unsealed_and_unchanged(tmp_path, monkeypatch, watched_tmpdir):
    watched, creates = watched_tmpdir
    home, project = _home(tmp_path)
    w = _wiring()
    ev = load_submodule('audit.evidence')
    calls = _record(monkeypatch, w.WIRED_SECTIONS)
    before = snapshot(home)
    first = _audit(tmp_path, monkeypatch, home, root=str(project))
    second = _audit(tmp_path, monkeypatch, home, root=str(project))
    assert first['status'] == second['status'] == 'completed'
    report = first['report']

    problems = []
    for name in w.WIRED_SECTIONS:
        section = report[name]
        assert section['status'] == 'completed', (name, section.get('status'), section.get('reason'))
        _walk(section, json.loads(json.dumps(calls[name][0][1][name])), name, tmp_path.resolve(),
              ev.VOCABULARY, problems)
        for finding in _section_findings(report, name):
            _walk({k: v for k, v in finding.items() if k != 'evidence'}, None, finding['id'], tmp_path.resolve(),
                  ev.VOCABULARY, problems)
            _walk({k: v for k, v in finding['evidence'].items() if k != 'source_digest'}, None,
                  finding['id'] + '.evidence', tmp_path.resolve(), ev.VOCABULARY, problems)
        assert 'hmac' not in json.dumps([section, _section_findings(report, name)]), name
    assert problems == []

    for name in w.WIRED_SECTIONS:
        sheet = SHEETS[name]
        kwargs, raw = calls[name][0]
        stored = _section_findings(report, name)
        # Every raw finding is stored with its exact sheet sentence and all its evidence (no key dropped).
        expected = sorted((f['id'], json.dumps(f.get('evidence') or {}, sort_keys=True)) for f in raw['findings'])
        got = []
        for finding in stored:
            assert finding['consequence'] == finding['detail'] == sheet['consequences'][finding['id']], finding['id']
            evidence = dict(finding['evidence'])
            assert len(evidence.pop('source_digest')) == 64
            assert set(evidence) <= set(sheet['numeric_evidence_keys']) | set(sheet['vocab_evidence_keys'])
            got.append((finding['id'], json.dumps(evidence, sort_keys=True)))
        assert sorted(got) == expected, name

    # Each section is identical between two audits of the unchanged home (the digest differs by design).
    for name in w.WIRED_SECTIONS:
        sections = [json.dumps(run['report'][name], sort_keys=True) for run in (first, second)]
        assert sections[0] == sections[1], name
    def stable_findings(run):
        out = []
        for name in w.WIRED_SECTIONS:
            for finding in _section_findings(run['report'], name):
                evidence = {k: v for k, v in finding['evidence'].items() if k != 'source_digest'}
                out.append(json.dumps({**finding, 'evidence': evidence}, sort_keys=True))
        return sorted(out)
    assert stable_findings(first) == stable_findings(second) != []

    assert snapshot(home) == before
    assert creates == [] and list(watched.iterdir()) == []

    # Default profile active: both shared-home modules receive the home root.
    assert calls['profile_duplicates'][0][0]['profile_path'] == str(home)
    assert calls['kanban_residue'][0][0]['profile_path'] == str(home)
    # memory_load gets both caller inputs (the enabled pre_llm_call plugin; the project's families).
    memory_kwargs = calls['memory_load'][0][0]
    assert memory_kwargs['prompt_injecting_plugins'] == [str(home / 'plugins' / 'hookplug')]
    assert memory_kwargs['project_families'] == {'python': 1}


def test_approvals_off_survives_sealing_in_the_stored_report(tmp_path, monkeypatch):
    """The config word 'off' is emitted as approval_off / backup_off and kept verbatim, never as a token."""
    home, _project = _home(tmp_path)
    result = _audit(tmp_path, monkeypatch, home)
    assert result['status'] == 'completed'
    stored = load_submodule('audit_surface').execute_audit(
        {'action': 'report', 'run_id': result['run_id']}, db_path=tmp_path / 'audit-store' / 'audit.db')
    for report in (result['report'], stored['report']):
        settings = report['unattended_exposure']['settings']
        assert settings['approvals.mode'] == {'value': 'approval_off', 'source': 'config',
                                              'widens_unattended_action': True}
        assert settings['updates.pre_update_backup'] == {'value': 'backup_off', 'source': 'config',
                                                         'widens_unattended_action': True}
        [finding] = [f for f in report['findings'] if f.get('id') == 'unattended_exposure.command_approval_off']
        assert finding['evidence']['approvals_mode'] == 'approval_off'
        assert finding['evidence']['terminal_backend'] == 'local'
        assert 'hmac' not in json.dumps(finding)
    # The plain words stay sealed (tests/test_audit_gate_regressions.py, tests/test_audit_sealing_and_key_durability.py).
    ev = load_submodule('audit.evidence')
    for word in ('off', 'executable', 'secret'):
        assert isinstance(ev.EvidenceSerializer().serialize(word), ev.SealedEvidence), word


def test_run_metrics_are_returned_but_never_stored(tmp_path, monkeypatch):
    home, _project = _home(tmp_path)
    w = _wiring()
    result = _audit(tmp_path, monkeypatch, home)
    metrics = result['run_metrics']
    assert set(metrics) == set(w.WIRED_SECTIONS)
    for name, values in metrics.items():
        assert set(values) <= set(SHEETS[name]['run_metrics_keys']), name
        assert all(v is None or type(v) in (int, float, bool) for v in values.values())
    metric_keys = {key for name in w.WIRED_SECTIONS for key in SHEETS[name]['run_metrics_keys']}
    assert not metric_keys & w.WIRED_SCHEMA_KEYS  # a metric can never be a sealed report key

    def keys(value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from keys(item)
    stored = load_submodule('audit_surface').execute_audit(
        {'action': 'report', 'run_id': result['run_id']}, db_path=tmp_path / 'audit-store' / 'audit.db')
    for report in (result['report'], stored['report']):
        found = set(keys(report))
        assert 'run_metrics' not in found and not found & metric_keys
    assert 'run_metrics' not in stored
    assert json.dumps(stored['report'], sort_keys=True) == json.dumps(result['report'], sort_keys=True)


def test_quick_audit_reports_the_nine_sections_as_not_collected(tmp_path, monkeypatch):
    home, _project = _home(tmp_path)
    w = _wiring()
    called = _record(monkeypatch, w.WIRED_SECTIONS)
    result = _audit(tmp_path, monkeypatch, home, quick=True)
    assert result['status'] == 'completed'
    assert called == {}
    assert result['run_metrics'] == {}
    for name in w.WIRED_SECTIONS:
        assert result['report'][name] == {'coverage': 'could_not_verify', 'status': 'not_measured',
                                          'reason': 'bounded_quick_audit_not_collected'}
        findings = _section_findings(result['report'], name)
        assert [f['id'] for f in findings] == [name + '.unverified']
        assert findings[0]['consequence'] == _consequence(name + '.unverified')
        assert findings[0]['coverage'] == 'could_not_verify'


def test_a_raising_collector_yields_operational_error_and_the_audit_completes(tmp_path, monkeypatch):
    home, _project = _home(tmp_path)
    surface = load_submodule('audit_surface')
    _entry, description = surface._WIRED['skill_packs']

    def explode(**kwargs):
        raise RuntimeError('canary-secret')
    monkeypatch.setitem(surface._WIRED, 'skill_packs', (explode, description))
    result = _audit(tmp_path, monkeypatch, home)
    assert result['status'] == 'completed'
    assert 'canary-secret' not in json.dumps(result)
    assert result['report']['skill_packs'] == {'coverage': 'could_not_verify', 'status': 'not_measured',
                                               'reason': 'collector_failed'}
    findings = _section_findings(result['report'], 'skill_packs')
    assert [f['id'] for f in findings] == ['skill_packs.operational_error']
    assert findings[0]['consequence'] == _consequence('skill_packs.operational_error')
    assert 'skill_packs' not in result['run_metrics']
    # The other sections still ran.
    assert result['report']['memory_load']['status'] == 'completed'
    assert result['report']['kanban_residue']['status'] == 'completed'


def test_named_active_profile_passes_the_home_root_to_shared_home_modules(tmp_path, monkeypatch):
    home, _project = _home(tmp_path)
    named = home / 'profiles' / 'qa-alpha'
    calls = _record(monkeypatch, ('profile_duplicates', 'kanban_residue', 'home_workdirs'))
    result = _audit(tmp_path, monkeypatch, named)
    assert result['status'] == 'completed'
    assert calls['profile_duplicates'][0][0]['profile_path'] == str(home)
    assert calls['kanban_residue'][0][0]['profile_path'] == str(home)
    assert calls['home_workdirs'][0][0]['profile_path'] == str(named)
    assert result['report']['profile_duplicates']['status'] == 'completed'
    assert result['report']['kanban_residue']['status'] == 'completed'


def test_cancellation_is_checked_between_wired_modules(tmp_path, monkeypatch):
    home, _project = _home(tmp_path)
    surface = load_submodule('audit_surface')
    entry, description = surface._WIRED['dead_stores']
    seen = []

    def cancel_then_measure(**kwargs):
        db = tmp_path / 'audit-store' / 'audit.db'
        with sqlite3.connect(db) as conn:
            run_id = conn.execute("SELECT run_id FROM audit_runs WHERE status='running'").fetchone()[0]
        surface.execute_audit({'action': 'cancel', 'run_id': run_id}, db_path=db)
        return entry(**kwargs)
    monkeypatch.setitem(surface._WIRED, 'dead_stores', (cancel_then_measure, description))
    later = _record(monkeypatch, ('profile_duplicates',))
    result = _audit(tmp_path, monkeypatch, home)
    assert result['status'] == 'cancelled'
    assert later == {}


@pytest.mark.parametrize('garbage', ['nan', 'cycle', 'object'])
def test_a_collector_returning_non_json_garbage_does_not_abort_the_audit(tmp_path, monkeypatch, garbage):
    home, _project = _home(tmp_path)
    surface = load_submodule('audit_surface')
    _entry, description = surface._WIRED['skill_packs']

    def junk(**kwargs):
        if garbage == 'nan':
            section = {'bad': float('nan')}
        elif garbage == 'cycle':
            section = {}
            section['self'] = section
        else:
            section = {'bad': object()}
        return {'skill_packs': section, 'findings': [], 'status': 'completed', 'coverage': 'verified'}
    monkeypatch.setitem(surface._WIRED, 'skill_packs', (junk, description))
    result = _audit(tmp_path, monkeypatch, home)
    assert result['status'] == 'completed'
    assert result['report']['skill_packs']['status'] == 'not_measured'
    assert [f['id'] for f in _section_findings(result['report'], 'skill_packs')] == ['skill_packs.operational_error']
