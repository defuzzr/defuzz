import json
import pytest
from tests.conftest import load_submodule

@pytest.mark.parametrize('name,content', [
    ('package.json', '{"dependencies":{"x":"link:../other"}}'),
    ('package.json', '{"dependencies":{"x":"workspace:../other"}}'),
    ('pyproject.toml', '[tool.uv.sources]\nx = {path="../other"}\n'),
    ('Cargo.toml', '[dependencies]\nx = {path="../other"}\n'),
    ('project.code-workspace', '{"folders":[{"path":"../other"}]}'),
    ('go.mod', 'module demo\nreplace example.org/foo => ../other\n'),
    ('tsconfig.json', '{"references":[{"path":"../other"}]}'),
    ('tsconfig.json', '{"compilerOptions":{"baseUrl":".","paths":{"x":["../other"]}}}'),
    ('config.yaml', 'mcp_servers:\n  demo:\n    command: ../other/run.sh\n    args: [../other]\n'),
])
def test_outward_reference_inspected(tmp_path, name, content):
    profile = tmp_path / '.hermes'; profile.mkdir()
    project = tmp_path / 'project'; project.mkdir()
    other = tmp_path / 'other'; other.mkdir()
    (other / 'run.sh').write_text('echo untrusted\n')
    (project / name).write_text(content)
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)], unselected_project_roots=[str(other)])
    assert any(b['target'].startswith(str(other)) for b in r['blending'])
    assert any(d['path'] == str(other / 'run.sh') for d in r['dynamic_invocations'])


def test_unknown_config_like_file_fails_closed(tmp_path):
    profile = tmp_path / '.hermes'; profile.mkdir()
    project = tmp_path / 'project'; project.mkdir()
    (project / 'custom.conf').write_text('unknown-executor = external\n')
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert r['regions']['project_tree']['coverage'] == 'could_not_verify'
    assert 'custom.conf' in json.dumps(r['regions']['project_tree'])


def test_python_not_call_analyzed_but_paths_are_individual(tmp_path, monkeypatch):
    profile = tmp_path / '.hermes'; profile.mkdir()
    project = tmp_path / 'project'; project.mkdir()
    for i in range(10):
        (project / f'{i}.py').write_text('import os\nos.system("untrusted")\n')
    classifier = load_submodule('audit.outward_python')
    original = classifier.analyze_python
    calls = []
    def counted(data):
        calls.append(1)
        return original(data)
    monkeypatch.setattr(classifier, 'analyze_python', counted)
    r = load_submodule('audit.outward').collect_outward(profile, [str(project)])
    assert len(calls) == 0
    assert len({d['path'] for d in r['dynamic_invocations'] if d['path'].startswith(str(project))}) == 10
