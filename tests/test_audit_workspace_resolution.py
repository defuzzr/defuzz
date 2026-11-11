import json

from tests.conftest import load_submodule


def test_workspace_aliases_resolve_only_declared_unique_members(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'pnpm-workspace.yaml').write_text('packages: ["packages/*"]\n')
    for folder, name, deps in [('app', 'app', {'core': 'workspace:*', 'alias': 'workspace:core@^', 'missing': 'workspace:*'}),
                               ('core', 'core', {})]:
        p = project / 'packages' / folder
        p.mkdir(parents=True)
        (p / 'package.json').write_text(json.dumps({'name': name, 'dependencies': deps}))
    # Same name outside the declared workspace is not a candidate.
    other = project / 'unrelated'
    other.mkdir()
    (other / 'package.json').write_text('{"name":"core"}')
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    edges = [b for b in r['blending'] if b['relationship'] == 'workspace_dependency']
    assert len(edges) == 1 and edges[0]['count'] == 2
    assert edges[0]['target'] == str(project / 'packages' / 'core')
    reason = next(d for d in r['regions']['project_tree']['reason_details'] if d['code'] == 'workspace_dependency_unresolved')
    assert reason['count'] == 1

    # A nested empty declaration is a boundary, not permission to borrow an
    # outer workspace's similarly named package.
    (project / 'packages' / 'app' / 'pnpm-workspace.yaml').write_text('packages: []\n')
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert not any(b['relationship'] == 'workspace_dependency' for b in r['blending'])
    reason = next(d for d in r['regions']['project_tree']['reason_details'] if d['code'] == 'workspace_dependency_unresolved')
    assert reason['count'] == 3


def test_ambiguous_workspace_names_fail_closed(tmp_path):
    profile = tmp_path / '.hermes'
    profile.mkdir()
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text('{"workspaces":["packages/*"],"dependencies":{"core":"workspace:*"}}')
    for folder in ('a', 'b'):
        p = project / 'packages' / folder
        p.mkdir(parents=True)
        (p / 'package.json').write_text('{"name":"core"}')
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert not any(b['relationship'] == 'workspace_dependency' for b in r['blending'])
    assert any(d['code'] == 'workspace_dependency_unresolved' for d in r['regions']['project_tree']['reason_details'])
