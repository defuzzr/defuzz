"""Write setting tests never consult a real Hermes home."""
import json
from tests.conftest import load_submodule


def test_defaults_gates_and_combined_finding(tmp_path):
    mod = load_submodule('audit.write_settings')
    (tmp_path / 'config.yaml').write_text('{}\n')
    drift = {'bundled_modified': 2, 'residue_skills': 3}
    result = mod.audit_write_settings(profile_path=tmp_path, hygiene=drift)
    settings = result['write_settings']['settings']
    assert settings['memory.memory_enabled'] == {'value': True, 'source': 'default'}
    assert settings['skills.write_approval'] == {'value': False, 'source': 'default'}
    assert settings['skills.creation_nudge_interval']['value'] == 10
    assert result['write_settings']['unattended_skill_writes'] is True
    ids = {f['id'] for f in result['findings']}
    assert {'write_settings.unattended_skill_writes', 'write_settings.unattended_memory_writes', 'skill_hygiene.unattended_writes_with_drift'} <= ids
    (tmp_path / 'config.yaml').write_text('skills:\n  write_approval: true\nmemory:\n  write_approval: true\n  provider: byterover\n')
    gated = mod.audit_write_settings(profile_path=tmp_path, hygiene=drift)
    assert gated['write_settings']['unattended_skill_writes'] is False
    assert gated['write_settings']['unattended_memory_writes'] is False
    assert gated['write_settings']['external_memory_provider']['provider'] == 'byterover'
    assert {f['id'] for f in gated['findings']} == {
        'write_settings.external_memory_provider',
        'skill_hygiene.approval_enabled_with_prior_drift',
    }
    clean_gated = mod.audit_write_settings(profile_path=tmp_path, hygiene={'bundled_modified': 0, 'residue_skills': 0})
    assert {f['id'] for f in clean_gated['findings']} == {'write_settings.external_memory_provider'}


def test_disabled_unknown_and_provider_sentinels(tmp_path):
    mod = load_submodule('audit.write_settings')
    cfg = tmp_path / 'config.yaml'
    cfg.write_text('agent:\n  disabled_toolsets: [skills, memory]\nmemory:\n  provider: builtin\n')
    row = mod.audit_write_settings(profile_path=tmp_path)['write_settings']
    assert row['unattended_skill_writes'] is False
    assert row['unattended_memory_writes'] is False
    assert row['external_memory_provider']['configured'] is False
    cfg.write_text('skills:\n  write_approval: "${env:CANARY_ENV}"\nmemory:\n  provider: CANARY_PROVIDER\n')
    result = mod.audit_write_settings(profile_path=tmp_path)
    assert result['write_settings']['unattended_skill_writes'] is None
    assert result['coverage'] == 'could_not_verify'
    assert 'CANARY' not in json.dumps(result)
    cfg.write_text('platform_toolsets:\n  cli: []\n')
    assert mod.audit_write_settings(profile_path=tmp_path)['write_settings']['unattended_skill_writes'] is False


def test_yaml_truthiness_classification_and_unknown_scalars(tmp_path):
    mod = load_submodule('audit.write_settings')
    cfg = tmp_path / 'config.yaml'
    # Bare y/Y and n/N differ between PyYAML and ruamel if quoted vs bare, so they are could_not_verify
    for raw in ('y', 'Y', '"y"', 'n', 'N', '"n"', 'maybe', '2', '1', 'null'):
        cfg.write_text(f'skills:\n  write_approval: {raw}\nmemory:\n  write_approval: {raw}\n')
        res = mod.audit_write_settings(profile_path=tmp_path)
        sec = res['write_settings']
        assert sec['settings']['skills.write_approval'] == {'value': None, 'source': 'could_not_verify'}, raw
        assert sec['settings']['memory.write_approval'] == {'value': None, 'source': 'could_not_verify'}, raw
        assert sec['unattended_skill_writes'] is None, raw
        assert sec['unattended_memory_writes'] is None, raw
        assert res['coverage'] == 'could_not_verify', raw
        ids = {f['id'] for f in res['findings']}
        assert 'write_settings.unattended_skill_writes' not in ids, raw
        assert 'write_settings.unattended_memory_writes' not in ids, raw
        assert 'write_settings.could_not_verify' in ids, raw

    # Known-true and known-false sets for write_approval
    for raw in ('true', 'True', 'yes', 'on', '"1"', 'approve', 'enabled'):
        cfg.write_text(f'skills:\n  write_approval: {raw}\n')
        sec = mod.audit_write_settings(profile_path=tmp_path)['write_settings']
        assert sec['settings']['skills.write_approval'] == {'value': True, 'source': 'config'}, raw
        assert sec['unattended_skill_writes'] is False, raw

    for raw in ('false', 'False', 'no', 'off', '0', '"0"', 'disabled', 'deny'):
        cfg.write_text(f'skills:\n  write_approval: {raw}\n')
        sec = mod.audit_write_settings(profile_path=tmp_path)['write_settings']
        assert sec['settings']['skills.write_approval'] == {'value': False, 'source': 'config'}, raw
        assert sec['unattended_skill_writes'] is True, raw

    # Known-true, known-false, and unknown for memory enable flags
    cfg.write_text('memory:\n  memory_enabled: maybe\n  user_profile_enabled: false\n')
    res = mod.audit_write_settings(profile_path=tmp_path)
    assert res['write_settings']['settings']['memory.memory_enabled'] == {'value': None, 'source': 'could_not_verify'}
    assert res['write_settings']['unattended_memory_writes'] is None
    assert 'write_settings.unattended_memory_writes' not in {f['id'] for f in res['findings']}


def test_administrator_managed_overlay_marks_could_not_verify(tmp_path, monkeypatch):
    mod = load_submodule('audit.write_settings')
    profile = tmp_path / 'profile'
    profile.mkdir()
    (profile / 'config.yaml').write_text('{}\n')
    managed = tmp_path / 'managed_etc'
    managed.mkdir()
    # Injected via parameter
    res = mod.audit_write_settings(profile_path=profile, managed_dir=managed)
    sec = res['write_settings']
    assert res['coverage'] == 'could_not_verify'
    assert sec['coverage'] == 'could_not_verify'
    assert sec['unattended_skill_writes'] is None
    assert sec['unattended_memory_writes'] is None
    for s in sec['settings'].values():
        assert s == {'value': None, 'source': 'could_not_verify'}
    assert sec['tool_selection']['source'] == 'could_not_verify'
    assert sec['tool_selection']['availability'] == {'skill_manage': None, 'memory': None}
    assert sec['external_memory_provider']['configured'] is None
    ids = {f['id'] for f in res['findings']}
    assert ids == {'write_settings.could_not_verify'}
    f_unv = res['findings'][0]
    assert f_unv['evidence'].get('reason') == 'managed_overlay'

    # Injected via HERMES_MANAGED_DIR environment variable
    monkeypatch.setenv('HERMES_MANAGED_DIR', str(managed))
    res_env = mod.audit_write_settings(profile_path=profile)
    assert res_env['coverage'] == 'could_not_verify'
    assert res_env['write_settings']['unattended_skill_writes'] is None


def test_legacy_write_mode_and_modified_stock_residue_correlation(tmp_path):
    mod = load_submodule('audit.write_settings')
    cfg = tmp_path / 'config.yaml'
    # Legacy write_mode present -> could_not_verify, never unattended
    cfg.write_text('skills:\n  write_mode: approve\nmemory:\n  write_mode: approve\n')
    res = mod.audit_write_settings(profile_path=tmp_path)
    sec = res['write_settings']
    assert sec['settings']['skills.write_approval'] == {'value': None, 'source': 'could_not_verify'}
    assert sec['settings']['memory.write_approval'] == {'value': None, 'source': 'could_not_verify'}
    assert sec['unattended_skill_writes'] is None
    assert sec['unattended_memory_writes'] is None
    assert res['coverage'] == 'could_not_verify'
    ids = {f['id'] for f in res['findings']}
    assert 'write_settings.unattended_skill_writes' not in ids
    assert 'write_settings.unattended_memory_writes' not in ids
    assert 'write_settings.could_not_verify' in ids

    # Combined finding requires residue ON a modified stock skill, not an unrelated skill
    cfg.write_text('{}\n')
    unrelated_drift = {
        'bundled_modified': 1,
        'residue_skills': 1,
        'modified_skills': [{'path': 'skills/mod-clean', 'modified': True, 'residue_score': 2}],
        'skills': [
            {'path': 'skills/mod-clean', 'bundled': True, 'modified': True, 'residue_score': 2},
            {'path': 'skills/other-noisy', 'bundled': False, 'modified': False, 'residue_score': 20},
        ],
    }
    res_unrelated = mod.audit_write_settings(profile_path=tmp_path, hygiene=unrelated_drift)
    assert 'skill_hygiene.unattended_writes_with_drift' not in {f['id'] for f in res_unrelated['findings']}

    correlated_drift = {
        'bundled_modified': 1,
        'residue_skills': 1,
        'modified_skills': [{'path': 'skills/mod-dirty', 'modified': True, 'residue_score': 15}],
        'skills': [{'path': 'skills/mod-dirty', 'bundled': True, 'modified': True, 'residue_score': 15}],
    }
    res_corr = mod.audit_write_settings(profile_path=tmp_path, hygiene=correlated_drift)
    assert 'skill_hygiene.unattended_writes_with_drift' in {f['id'] for f in res_corr['findings']}


def test_approval_enabled_with_prior_drift_and_residue(tmp_path):
    from tests.test_audit_skill_hygiene import shipped_hash, skill
    sh_mod = load_submodule('audit.skill_hygiene')
    ws_mod = load_submodule('audit.write_settings')
    md = skill(tmp_path, 'stock-one', '---\nname: stock-one\n---\nClean stock rule.\n')
    origin = shipped_hash(md.parent)
    (tmp_path / 'skills/.bundled_manifest').write_text(f'stock-one:{origin}\n')
    cfg = tmp_path / 'config.yaml'
    cfg.write_text('skills:\n  write_approval: true\nmemory:\n  write_approval: true\n')

    # Approval on + everything verified clean -> no finding
    clean_hyg = sh_mod.audit_skill_hygiene(profile_path=tmp_path)
    clean_ws = ws_mod.audit_write_settings(profile_path=tmp_path, hygiene=clean_hyg['skill_hygiene'])
    assert clean_hyg['findings'] == []
    assert clean_ws['findings'] == []

    # Approval on + modified stock skill with residue -> drift/residue findings AND approval_enabled_with_prior_drift
    md.write_text(
        md.read_text()
        + '\n## Lessons\n'
        + '- Last time 2025-01-02 PR 45 commit abcdef1\n'
        + '- This session we found /home/user/private/\n'
        + '- I tried JIRA-12 and it turned out wrong\n'
        + '- see session 20260101_000000_abcdef\n'
    )
    dirty_hyg = sh_mod.audit_skill_hygiene(profile_path=tmp_path)
    hyg_ids = {f['id'] for f in dirty_hyg['findings']}
    assert {'skill_hygiene.stock_skill_modified', 'skill_hygiene.scratchpad_residue'} <= hyg_ids

    dirty_ws_on = ws_mod.audit_write_settings(profile_path=tmp_path, hygiene=dirty_hyg['skill_hygiene'])
    ws_on_ids = {f['id'] for f in dirty_ws_on['findings']}
    assert ws_on_ids == {'skill_hygiene.approval_enabled_with_prior_drift'}
    f_prior = dirty_ws_on['findings'][0]
    assert 'cannot tell when' in f_prior['consequence']
    assert 'stops new unattended writes' in f_prior['consequence']
    assert f_prior['evidence']['approval_enabled'] is True
    assert f_prior['evidence']['bundled_modified'] == 1
    assert f_prior['evidence']['residue_skills'] == 1

    # Approval off + same dirt -> combined unattended_writes_with_drift finding as before
    cfg.write_text('skills:\n  write_approval: false\nmemory:\n  write_approval: true\n')
    dirty_ws_off = ws_mod.audit_write_settings(profile_path=tmp_path, hygiene=dirty_hyg['skill_hygiene'])
    ws_off_ids = {f['id'] for f in dirty_ws_off['findings']}
    assert 'skill_hygiene.unattended_writes_with_drift' in ws_off_ids
    assert 'skill_hygiene.approval_enabled_with_prior_drift' not in ws_off_ids


def test_locked_but_not_cleaned_reason_counts(tmp_path):
    from tests.test_audit_skill_hygiene import skill, hub_hash
    sh = load_submodule('audit.skill_hygiene')
    ws = load_submodule('audit.write_settings')
    cases = [
        ('path-only', 'Use ' + '/Users/' + 'jdoe/work/', 'machine_path_skills', 1),
        ('network-only', 'Use 10.42.1.7', 'network_identity_skills', 1),
        ('size-only', 'x' * sh.OVERSIZED_BODY_CHARS, None, 0),
        ('residue', 'Yesterday PR 42 commit abcdef1\nChecked 11/10/2026', 'residue_skills', 1),
        ('clean', 'Use portable rules.', None, 0),
    ]
    for name, body, reason, expected in cases:
        home = tmp_path / name
        skill(home, name, body)
        (home / 'config.yaml').write_text('skills: {write_approval: true}\nmemory: {write_approval: true}')
        hygiene = sh.audit_skill_hygiene(profile_path=home)['skill_hygiene']
        findings = ws.audit_write_settings(profile_path=home, hygiene=hygiene)['findings']
        prior = [f for f in findings if f['id'] == ws.APPROVAL_PRIOR_DRIFT_RULE]
        assert len(prior) == expected, name
        if reason:
            assert prior[0]['evidence'][reason] == 1
    home = tmp_path / 'hub'
    md = skill(home, 'hub', 'Yesterday PR 42 commit abcdef1\nUse 10.42.1.7')
    (home / 'config.yaml').write_text('skills: {write_approval: true}\nmemory: {write_approval: true}')
    lock = home / 'skills/.hub/lock.json'
    lock.parent.mkdir()
    lock.write_text(json.dumps({'installed': {'hub': {'source': 'official', 'install_path': 'hub', 'content_hash': hub_hash(md.parent)}}}))
    def findings():
        return ws.audit_write_settings(profile_path=home, hygiene=sh.audit_skill_hygiene(profile_path=home)['skill_hygiene'])['findings']
    assert not findings()
    md.write_text('Edited official, without residue.')
    assert findings()[0]['evidence']['hub_modified'] == 1
    (home / 'config.yaml').write_text('skills: {write_approval: maybe}')
    assert not any(f['id'] == ws.APPROVAL_PRIOR_DRIFT_RULE for f in findings())


def test_duplicate_config_keys_are_unknown_at_every_depth(tmp_path):
    mod = load_submodule('audit.write_settings')
    facts = load_submodule('audit.facts')
    samples = [
        'skills: {write_approval: false}\nskills: {write_approval: true}\n',
        'skills: {write_approval: false, write_approval: true}\n',
        'skills: {write_approval: true}\nother: {nested: {a: 1, a: 2}}\n',
        'skills: {write_approval: true}\nother: [{a: 1, a: 2}]\n',
        'base: &base {a: 1, a: 2}\nskills: {<<: *base, write_approval: true}\n',
    ]
    for text in samples:
        (tmp_path / 'config.yaml').write_text(text)
        result = mod.audit_write_settings(profile_path=tmp_path)
        sec = result['write_settings']
        assert all(s == {'value': None, 'source': 'could_not_verify'} for s in sec['settings'].values())
        assert sec['unattended_skill_writes'] is None and sec['unattended_memory_writes'] is None
        assert [f['evidence']['reason'] for f in result['findings']] == ['duplicate_config_key']
    # Other facts callers keep their existing last-key-wins behaviour.
    assert facts._parse_simple_yaml_mapping(samples[0])['skills']['write_approval'] is True
    # A normal explicit override of a merged mapping is not a duplicate key.
    (tmp_path / 'config.yaml').write_text('base: &base {write_approval: false}\nskills: {<<: *base, write_approval: true}\n')
    assert mod.audit_write_settings(profile_path=tmp_path)['write_settings']['settings']['skills.write_approval']['value'] is True


def test_settings_surface_persistence(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home/.hermes'
    home.mkdir(parents=True)
    (home / 'config.yaml').write_text('skills:\n  write_approval: false\n')
    monkeypatch.setenv('HERMES_HOME', str(home))
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: discover(*a, **kw, system_config=tmp_path / 'absent'))
    db = tmp_path / 'report/audit.db'
    result = surface.execute_audit({'action': 'run'}, db_path=db, wait=True)
    section = result['report']['write_settings']
    assert section['settings']['skills.write_approval'] == {'value': False, 'source': 'config'}
    finding = next(f for f in result['report']['findings'] if f['id'] == 'write_settings.unattended_skill_writes')
    assert finding['evidence']['source'] == 'config'
    assert 'CLI skill writes' in finding['consequence']
    saved = surface.execute_audit({'action': 'report', 'run_id': result['run_id']}, db_path=db)
    assert saved['report']['write_settings'] == section
    quick = surface.execute_audit({'action': 'run', 'quick': True}, db_path=db, wait=True)
    assert quick['report']['write_settings']['reason'] == 'bounded_quick_audit_not_collected'
