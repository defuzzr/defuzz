"""Execution inventory is not a proof of program behavior."""
from tests.conftest import load_submodule
import pytest


@pytest.mark.parametrize('name,body', [
    ('app.py', 'p = "{target}"'),
    ('AGENTS.md', 'Edit `{target}` before starting.'),
    ('CMakeLists.txt', 'include("{target}")'),
    ('requirements.txt', '-e {target}'),
    ('Gemfile', 'gem "x", path: "{target}"'),
    ('BUILD', 'genrule(cmd="cat {target}")'),
    ('.npmrc', 'script-shell={target}'),
    ('.env', 'TERMINAL_CWD={target}'),
])
def test_explicit_outward_references(tmp_path, monkeypatch, name, body):
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile, project, other = (tmp_path / n for n in ('profile', 'project', 'other'))
    for p in (profile, project, other):
        p.mkdir()
    (project / '.git').mkdir()
    target = other / 'README.md'
    target.write_text('data')
    source = project / name
    source.write_text(body.format(target=target))
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    if name in {'.npmrc', '.env'}:
        assert any(c.get('kind') == 'credential_store' and c['path'] == str(source) for c in result['credentials'])
        assert not any(e['source'] == str(source) for e in result['blending'])
        return
    assert any(e['source'] == str(source) and e['target'] == str(target) for e in result['blending'])
    if name not in {'app.py', 'AGENTS.md'}:
        assert any(d['path'] == str(source) for d in result['dynamic_invocations'])



@pytest.mark.parametrize('name,body', [
    ('module.py', '# coding: utf-7\nx=1'),
    ('mystery', 'unknown extensionless DSL'),
])
def test_unknown_file_type_fails_closed(tmp_path, monkeypatch, name, body):
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile, project = tmp_path / 'profile', tmp_path / 'project'
    profile.mkdir(); project.mkdir(); (project / '.git').mkdir()
    (project / name).write_text(body)
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'could_not_verify'
    assert any(item['code'] == 'unknown_file_type' for item in result['regions']['project_tree']['reason_details'])


def test_hardlink_disclosure(tmp_path, monkeypatch):
    import os
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile, project = tmp_path / 'profile', tmp_path / 'project'
    profile.mkdir(); project.mkdir(); (project / '.git').mkdir()
    (project / 'a.md').write_text('hello')
    os.link(project / 'a.md', tmp_path / 'other.md')
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert result['regions']['cross_project_isolation']['disclosures'][0]['kind'] == 'hardlink_target_unknown'
    assert result['regions']['cross_project_isolation']['coverage'] == 'verified'


def test_parent_and_incoming_execution_declarations(tmp_path, monkeypatch):
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile, project = tmp_path / 'profile', tmp_path / 'workspace' / 'project'
    profile.mkdir(); project.mkdir(parents=True); (project.parent / '.git').mkdir()
    (project.parent / '.envrc').write_text('source_up')
    sibling = profile / 'profiles' / 'other'
    (sibling / 'cron').mkdir(parents=True)
    (sibling / '.env').write_text('TERMINAL_CWD=' + str(project))
    import json
    (sibling / 'cron' / 'jobs.json').write_text(json.dumps({'jobs': [{'workdir': str(project)}]}))
    for extra in ('plugins/a/plugin.yaml', 'hooks/a/HOOK.yaml'):
        path = sibling / extra
        path.parent.mkdir(parents=True)
        path.write_text('path: ' + str(project))
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert any(e['target'] == str(project.parent / '.envrc') for e in result['blending'])
    assert any(c.get('kind') == 'credential_store' and c['path'] == str(sibling / '.env') for c in result['credentials'])
    assert not any(e['source'] == str(sibling / '.env') for e in result['blending'])
    for source in (sibling / 'cron' / 'jobs.json', sibling / 'plugins/a/plugin.yaml', sibling / 'hooks/a/HOOK.yaml'):
        assert any(e['source'] == str(source) and e['target'] == str(project) for e in result['blending'])


@pytest.mark.parametrize('name,body', [
    ('pyproject.toml', '[project]\nname="example"\nversion="1"'),
    ('entry_points.txt', '[console_scripts]\nhello = app:main'),
    ('setup.cfg', '[options.entry_points]\nconsole_scripts = hello = app:main'),
    ('.justfile', 'task:\n  echo hi'),
    ('Containerfile', 'FROM scratch'),
    ('config.yaml', 'model: sample'),
])
def test_known_surface_inventory(tmp_path, monkeypatch, name, body):
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile, project = tmp_path / 'profile', tmp_path / 'project'
    profile.mkdir(); project.mkdir(); (project / '.git').mkdir()
    (project / name).write_text(body)
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert any(d['path'] == str(project / name) for d in result['dynamic_invocations'])
    assert not any(item['code'] in {'git_config_unclassified', 'unknown_file_type'} for item in result['regions']['project_tree'].get('reason_details', []))


def test_structured_secret_path_never_emitted(tmp_path, monkeypatch):
    import json
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile, project = tmp_path / 'profile', tmp_path / 'project'
    profile.mkdir(); project.mkdir(); (project / '.git').mkdir()
    secret = '/PRIVATE_TOKEN_secret_canary'
    (project / 'package.json').write_text(json.dumps({'token': secret, secret: 'x', 'env': {'X': secret}}))
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert secret not in json.dumps(result)


def test_program_code_is_not_call_analyzed(tmp_path, monkeypatch):
    git = load_submodule('audit.outward_git')
    original = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: original(*a, **kw, system_config=tmp_path / 'absent'))
    profile = tmp_path / 'profile'
    project = tmp_path / 'project'
    profile.mkdir()
    project.mkdir()
    (project / '.git').mkdir()
    (project / '.git' / 'config').write_text('[core]\n\tbare = false\n')
    (project / 'app.py').write_text('import anything\nx = anything.run()\n')
    result = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert result['regions']['project_tree']['coverage'] == 'verified'
    assert [d['kind'] for d in result['dynamic_invocations']] == ['program_code']
    assert 'behavior' in result['regions']['project_tree']['limitations'][0]
