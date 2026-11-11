import json
from pathlib import Path

from tests.conftest import load_submodule


def capture_reason_text(monkeypatch):
    """Verify reason semantics without requiring raw free-text persistence.

    Keep the serializer unchanged; record the preimage only in test memory so
    a token must correspond to the expected reason, not merely any HMAC.
    """
    serializer = load_submodule('audit.evidence').EvidenceSerializer
    original = serializer.token
    preimages = {}

    def token(self, value, kind, location):
        result = original(self, value, kind, location)
        preimages[result['hmac']] = value
        return result

    monkeypatch.setattr(serializer, 'token', token)

    def text(reason):
        if isinstance(reason, str):
            return reason
        assert set(reason) == {'kind', 'hmac', 'location'}
        assert reason['kind'] == 'text'
        assert len(reason['hmac']) == 64
        return preimages[reason['hmac']]

    return text


def test_source_paths_preserve_resolved_paths_and_tokenize_missing(tmp_path):
    serializer = load_submodule('audit.evidence').EvidenceSerializer()
    existing = tmp_path / 'source.py'
    existing.write_text('pass\n')
    missing = tmp_path / 'UNRESOLVED-PATH-CANARY'
    result = serializer.serialize({'source_paths': [str(existing), str(missing)]})
    assert result['source_paths'][0] == str(existing)
    token = result['source_paths'][1]
    assert set(token) == {'kind', 'hmac', 'location'}
    assert token['kind'] == 'unresolved_reference'
    assert len(token['hmac']) == 64
    assert token['location'] == {'path': None, 'line': None}
    assert 'UNRESOLVED-PATH-CANARY' not in json.dumps(result)
    assert serializer.serialize(result) == result


def test_simple_home_static_regions(tmp_path, monkeypatch):
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *args, **kwargs:
                        discover(*args, **kwargs, system_config=tmp_path / 'absent-gitconfig'))
    profile = tmp_path / '.hermes'
    project = tmp_path / 'Projects' / 'chosen'
    profile.mkdir()
    project.mkdir(parents=True)
    (project / 'README.md').write_text('plain project')
    outward = load_submodule('audit.outward')
    result = outward.collect_outward(profile, [str(project)])
    assert set(result['regions']) == {
        'project_tree', 'active_profile', 'skills', 'plugins', 'session_history',
        'identity', 'credentials', 'shared_infrastructure', 'sibling_profiles',
        'other_projects', 'dynamic_execution', 'cross_project_isolation',
    }
    assert all(r['coverage'] == 'verified' for r in result['regions'].values())
    assert result['limits']['execution'] == 'never'
    json.dumps(result)


def test_trace_symlink_credentials_without_sibling_reads(tmp_path, monkeypatch):
    import builtins
    import os
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'chosen'
    project.mkdir()
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    (unrelated / 'private.txt').write_text('never inspect')
    siblings = profile / 'profiles'
    siblings.mkdir()
    (siblings / 'private.txt').write_text('never inspect')
    external = tmp_path / 'shared'
    external.mkdir()
    secret = external / '.env'
    secret.write_text('API_KEY=canary-secret-never-return')
    (project / 'shared').symlink_to(external, target_is_directory=True)
    original_open, original_scan = builtins.open, os.scandir

    def guard_open(file, *args, **kwargs):
        if isinstance(file, (str, Path)):
            assert not Path(file).is_relative_to(unrelated)
            assert not Path(file).is_relative_to(siblings)
        return original_open(file, *args, **kwargs)

    def guard_scan(file):
        if isinstance(file, int):
            file = os.readlink(f'/proc/self/fd/{file}')
        assert not Path(file).is_relative_to(unrelated)
        assert Path(file) == siblings or not Path(file).is_relative_to(siblings)
        return original_scan(file)

    monkeypatch.setattr(builtins, 'open', guard_open)
    monkeypatch.setattr(os, 'scandir', guard_scan)
    outward = load_submodule('audit.outward')
    result = outward.collect_outward(profile, [str(project)])
    assert any(b['source'] == str((project / 'shared').resolve()) and b['target'] == str(external)
               and b['relationship'] == 'symlink' for b in result['blending'])
    metadata = next(c for c in result['credentials'] if c['path'] == str(secret))
    assert metadata['kind'] == 'credential_store'
    assert metadata['mode']
    assert set(metadata) == {'kind', 'path', 'size', 'mode', 'mtime'}
    assert 'canary-secret' not in json.dumps(result)
    again = outward.collect_outward(profile, [str(project)])
    assert metadata in again['credentials']


def test_external_config_roots_and_redacted_dynamic(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    external = tmp_path / 'external-skills'
    external.mkdir()
    (external / 'SKILL.md').write_text('plain skill')
    (profile / 'config.yaml').write_text(
        f'skills:\n  external_dirs:\n    - {external}\n'
        'mcp_servers:\n  example:\n    command: "sh -c secret-command-value"\n'
        '    api_key: supersecret-config-value\n')
    outward = load_submodule('audit.outward')
    result = outward.collect_outward(profile, [])
    assert any(b['target'] == str(external) and b['source'] == str(profile / 'config.yaml')
               and b['relationship'] == 'external_skill_root' for b in result['blending'])
    dynamic = result['regions']['dynamic_execution']
    assert dynamic['coverage'] == 'verified'
    assert not dynamic['reasons']
    assert any(d['kind'] == 'configured_command_unresolved'
               and d['resolution'] == 'enumerated' for d in result['dynamic_invocations'])
    assert result['dynamic_invocations'][0]['path'] == str(profile / 'config.yaml')
    assert any(c.get('config_keys') == ['api_key'] for c in result['credentials'])
    serialized = json.dumps(result)
    assert 'secret-command-value' not in serialized
    assert 'supersecret-config-value' not in serialized


def test_recursive_references_parent_context_and_code_are_static(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'projects' / 'chosen'
    project.mkdir(parents=True)
    parent_context = project.parent / 'AGENTS.md'
    parent_context.write_text('private-parent-context-do-not-persist')
    external = tmp_path / 'external'
    external.mkdir()
    linked = tmp_path / 'editable'
    linked.mkdir()
    (linked / 'run.py').write_text('import subprocess\nsubprocess.run(get_command())\n')
    (external / 'package.egg-link').write_text(str(linked) + '\n.')
    (profile / 'config.yaml').write_text(f'plugins:\n  path: {external}\n')
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    relations = {(b['target'], b['relationship']) for b in result['blending']}
    assert (str(external), 'configured_path') in relations
    assert (str(linked), 'editable_install') in relations
    assert (str(parent_context), 'parent_context') in relations
    assert any(d['kind'] == 'program_code' and d['path'] == str(linked / 'run.py')
                   for d in result['dynamic_invocations'])
    assert 'private-parent-context' not in json.dumps(result)
    assert 'get_command' not in json.dumps(result)


def test_shell_pth_and_modern_editable_are_not_executed(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    external = tmp_path / 'installed-source'
    external.mkdir()
    (profile / 'direct_url.json').write_text(json.dumps({
        'url': external.as_uri(), 'dir_info': {'editable': True}}))
    (profile / 'hook.sh').write_text('echo NEVER-PERSIST-THIS-COMMAND\n')
    (profile / 'startup.pth').write_text('import very_secret_module\n')
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert any(b['target'] == str(external) and b['relationship'] == 'editable_install'
               for b in result['blending'])
    kinds = {d['kind'] for d in result['dynamic_invocations']}
    assert any(d['kind'] == 'program_code' and d['path'] == str(profile / 'hook.sh')
                   for d in result['dynamic_invocations'])
    assert any('execution_surface' in d.get('kinds', [d['kind']]) for d in result['dynamic_invocations'])
    assert all(d['resolution'] == 'enumerated' for d in result['dynamic_invocations'])
    assert 'pth_execution_unresolved' in kinds
    assert 'NEVER-PERSIST' not in json.dumps(result)
    assert 'very_secret_module' not in json.dumps(result)


def test_limits_exclusions_and_read_errors_are_unknown(tmp_path, monkeypatch):
    reason_text = capture_reason_text(monkeypatch)
    import os
    outward = load_submodule('audit.outward')
    profile = tmp_path / '.hermes'
    profile.mkdir()
    oversized = profile / 'large.txt'
    oversized.write_bytes(b'x' * 32)
    monkeypatch.setattr(outward, 'MAX_FILE_BYTES', 16)
    result = outward.collect_outward(profile, [])
    assert any('file_byte_limit_exceeded' in reason_text(r) for r in result['regions']['active_profile']['reasons'])
    result = outward.collect_outward(profile, [], excluded_paths=[oversized])
    assert any('excluded_path' in reason_text(r) for r in result['regions']['active_profile']['reasons'])
    original = os.scandir
    def denied(path):
        if isinstance(path, int):
            path = os.readlink(f'/proc/self/fd/{path}')
        if Path(path) == profile:
            raise PermissionError('SECRET-ERROR-TEXT')
        return original(path)
    monkeypatch.setattr(os, 'scandir', denied)
    result = outward.collect_outward(profile, [])
    assert result['regions']['active_profile']['coverage'] == 'could_not_verify'
    assert 'SECRET-ERROR-TEXT' not in json.dumps(result)


def test_intermediate_symlink_is_disclosed(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'skills').mkdir()
    link = tmp_path / 'alias'
    link.symlink_to(target, target_is_directory=True)
    (profile / 'config.yaml').write_text(f'skills:\n  external_dirs: [{link / "skills"}]\n')
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert any(b['source'] == str(link.resolve()) and b['target'] == str(target)
               and b['relationship'] == 'symlink' for b in result['blending'])


def test_command_bearing_documents_and_invocation_limit(tmp_path, monkeypatch):
    reason_text = capture_reason_text(monkeypatch)
    profile = tmp_path / '.hermes'
    profile.mkdir()
    (profile / 'SKILL.md').write_text('Run `python secret_script.py --token SECRET-DOC-TOKEN`.\n')
    (profile / 'hooks.json').write_text(json.dumps({'command': 'SECRET-HOOK-COMMAND'}))
    outward = load_submodule('audit.outward')
    result = outward.collect_outward(profile, [])
    assert result['regions']['dynamic_execution']['coverage'] == 'verified'
    assert all(d['resolution'] == 'enumerated' for d in result['dynamic_invocations'])
    # Prose command mentions are not registered execution surfaces.
    assert not any(d['path'] == str(profile / 'SKILL.md')
                   for d in result['dynamic_invocations'])
    assert any(d['kind'] == 'configured_command_unresolved' for d in result['dynamic_invocations'])
    assert 'SECRET-' not in json.dumps(result)
    (profile / 'package.json').write_text('{}')
    monkeypatch.setattr(outward, 'MAX_INVOCATIONS', 1)
    result = outward.collect_outward(profile, [])
    assert len(result['dynamic_invocations']) <= 1
    assert any('invocation_limit_exceeded' in reason_text(r) for r in result['regions']['active_profile']['reasons'])


def test_explicit_reference_can_enter_previously_pruned_profiles(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    siblings = profile / 'profiles'
    siblings.mkdir()
    (siblings / '.env').write_text('TOKEN=do-not-return')
    # Selecting the container explicitly after default-profile traversal must
    # not confuse a pruned path with a completed inspection.
    result = load_submodule('audit.outward').collect_outward(profile, [str(siblings)])
    assert any(c['path'] == str(siblings / '.env') for c in result['credentials'])


def test_credential_references_and_unsupported_data_are_explicit(tmp_path):
    profile = tmp_path / 'home'
    profile.mkdir()
    (profile / 'config.yaml').write_text('env_file: .env\n')
    (profile / '.env').write_text('KEY=NEVER-RETURN-TEST')
    (profile / 'state.db').write_bytes(b'not a supported database')
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert any(c.get('kind') == 'credential_store' for c in result['credentials'])
    assert result['regions']['session_history']['coverage'] == 'could_not_verify'


def test_session_history_does_not_blend_unrelated_project(tmp_path, monkeypatch):
    import os
    profile = tmp_path / 'home'
    (profile / 'sessions').mkdir(parents=True)
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    (profile / 'sessions' / 'one.jsonl').write_text(json.dumps({'cwd': str(unrelated), 'started_at': 10}) + '\n')
    original = os.scandir
    def guarded(fd):
        path = os.readlink(f'/proc/self/fd/{fd}') if isinstance(fd, int) else str(fd)
        assert path != str(unrelated)
        return original(fd)
    monkeypatch.setattr(os, 'scandir', guarded)
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert not result['blending']
    assert result['session_history']['records_inspected'] == 1


def test_cancelled_outward_trace_is_not_verified(tmp_path):
    profile = tmp_path / 'home'
    profile.mkdir()
    result = load_submodule('audit.outward').collect_outward(profile, [], cancelled=lambda: True)
    assert result['regions']['active_profile']['coverage'] == 'could_not_verify'
    assert result['limits']['entries_inspected'] == 0


def test_captured_session_database_and_toml_dependencies(tmp_path):
    import sqlite3
    profile = tmp_path / 'home'
    profile.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    shared = tmp_path / 'shared'
    shared.mkdir()
    (project / 'pyproject.toml').write_text(f'[tool.dependencies.shared]\npath = "{shared}"\n')
    with sqlite3.connect(profile / 'state.db') as conn:
        conn.execute('CREATE TABLE sessions (id TEXT, started_at INTEGER, cwd TEXT)')
        conn.execute('INSERT INTO sessions VALUES (?, ?, ?)', ('one', 123, str(project)))
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert result['regions']['session_history']['coverage'] == 'verified'
    assert result['session_history']['newest_selected_timestamp'] == 123
    assert any(b['target'] == str(shared) for b in result['blending'])


def test_external_root_capture_carries_blending_provenance(tmp_path):
    facts = load_submodule('audit.facts')
    profile = tmp_path / 'home'
    profile.mkdir()
    shared = profile / 'profiles' / 'sibling' / 'skills'
    shared.mkdir(parents=True)
    (profile / 'config.yaml').write_text(f'skills:\n  external_dirs: [{shared}]\n')
    roots = facts.resolve_profile_skill_roots(profile, config={'skills': {'external_dirs': [str(shared)]}})
    external = next(r for r in roots if r['path'] == str(shared))
    assert external['blending']['relationship'] == 'external_skill_root'
    assert external['blending']['source'] == str(profile / 'config.yaml')
    captured = facts.collect_profile_unit_facts(profile_name='default', profile_dir=profile,
        is_default=True, is_active=True, as_of=100, unused_threshold_days=90)
    assert any(b['target'] == str(shared) for b in captured['fingerprint_manifest']['blending'])


def test_unselected_registered_project_inside_profile_is_not_read(tmp_path):
    profile = tmp_path / 'home'
    project = profile / 'projects' / 'unrelated'
    project.mkdir(parents=True)
    (project / 'hook.sh').write_text('do not inspect')
    result = load_submodule('audit.outward').collect_outward(profile, [],
        unselected_project_roots=[project])
    assert not result['dynamic_invocations']
    assert str(project) in result['limits']['unselected_project_roots']


import pytest


@pytest.mark.parametrize('filename', ['private.json', 'plugin.json'])
def test_late_credential_reference_cannot_persist_secret(tmp_path, filename, monkeypatch):
    profile = tmp_path / 'home'
    profile.mkdir()
    secret = 'LATE-CREDENTIAL-CANARY-923811'
    (profile / filename).write_text(json.dumps({'path': secret}))
    (profile / 'config.yaml').write_text(f'credential_file: {filename}\n')
    import os
    from contextlib import contextmanager
    original = os.scandir
    @contextmanager
    def config_last(fd):
        with original(fd) as entries:
            yield iter(sorted(entries, key=lambda entry: entry.name == 'config.yaml'))
    monkeypatch.setattr(os, 'scandir', config_last)
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert secret not in json.dumps(result)
    assert any(c['path'] == str(profile / filename) for c in result['credentials'])
    assert not any(b['source'] == str(profile / filename) for b in result['blending'])


def test_yaml_alias_work_budget(tmp_path):
    import pytest
    facts = load_submodule('audit.facts')
    text = 'a0: &a0 [1, 2]\n' + ''.join(
        f'a{i}: &a{i} [*a{i-1}, *a{i-1}]\n' for i in range(1, 15))
    with pytest.raises(ValueError, match='budget'):
        facts._parse_simple_yaml_mapping(text)


def test_directory_race_never_opens_unrelated_target(tmp_path, monkeypatch):
    import os
    outward = load_submodule('audit.outward')
    profile = tmp_path / 'home'
    profile.mkdir()
    target = tmp_path / 'unrelated'
    target.mkdir()
    (target / 'secret.txt').write_text('not for inspection')
    original = os.scandir
    def raced(path):
        if path == profile:
            profile.rename(tmp_path / 'moved')
            profile.symlink_to(target, target_is_directory=True)
        return original(path)
    monkeypatch.setattr(os, 'scandir', raced)
    result = outward.collect_outward(profile, [])
    # Descriptor traversal never triggers this pathname substitution.
    assert result['limits']['bytes_read'] == 0


def test_environment_paths_never_expand_credentials(tmp_path, monkeypatch):
    profile = tmp_path / 'profile'
    profile.mkdir()
    monkeypatch.setenv('AUDIT_CANARY_TOKEN', 'NEVER-PERSIST-ENV-128212')
    (profile / 'config.yaml').write_text('skills:\n  external_dirs: ["$AUDIT_CANARY_TOKEN"]\n')
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert 'NEVER-PERSIST-ENV' not in json.dumps(result)
    assert result['regions']['skills']['coverage'] == 'could_not_verify'


def test_project_profiles_directory_is_not_silently_pruned(tmp_path):
    profile = tmp_path / 'home'
    profile.mkdir()
    project = tmp_path / 'project'
    (project / 'profiles').mkdir(parents=True)
    # A registered hook surface, rather than an ordinary shell source file.
    (project / 'profiles' / 'hooks.json').write_text('{"command": "echo not-executed"}')
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert result['regions']['dynamic_execution']['coverage'] == 'verified'
    assert result['regions']['project_tree']['coverage'] == 'verified'
    assert any(d['path'] == str(project / 'profiles' / 'hooks.json')
               and d['resolution'] == 'enumerated' for d in result['dynamic_invocations'])


def test_credential_symlink_keeps_metadata_classification(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    secret = tmp_path / 'opaque.dat'
    secret.write_text('DO-NOT-RETURN-OPAQUE-SECRET')
    (profile / '.env').symlink_to(secret)
    result = load_submodule('audit.outward').collect_outward(profile, [])
    assert any(c['path'] == str(secret) for c in result['credentials'])
    assert 'DO-NOT-RETURN' not in json.dumps(result)
