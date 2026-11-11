"""Characterization tests for audit/outward*.py."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from tests.conftest import load_submodule


def test_public_and_facade_exports_exist():
    outward = load_submodule('audit.outward')
    analyzers = load_submodule('audit.outward_analyzers')
    db = load_submodule('audit.outward_db')
    git = load_submodule('audit.outward_git')
    git_cfg = load_submodule('audit.outward_git_config')
    py_mod = load_submodule('audit.outward_python')
    structured = load_submodule('audit.outward_structured')

    # outward.py constants and functions
    for name in (
        'REGIONS', 'MAX_ENTRIES', 'MAX_DEPTH', 'MAX_FILE_BYTES', 'MAX_TOTAL_BYTES',
        'MAX_EDGES', 'MAX_INVOCATIONS', '_absolute', '_directory_fd', '_identity',
        '_credential', 'collect_outward',
    ):
        assert hasattr(outward, name), f'audit.outward missing {name}'

    # outward_analyzers.py
    for name in ('credential_candidate', 'credential_key_kind', 'analyze_dynamic', 'resolve_toolchain'):
        assert hasattr(analyzers, name), f'audit.outward_analyzers missing {name}'

    # outward_db.py
    for name in (
        'SnapshotError', 'MAX_SQL_STEPS', 'BUSY_TIMEOUT_S',
        '_identity', '_digest', '_associations', 'inspect_database',
    ):
        assert hasattr(db, name), f'audit.outward_db missing {name}'
    assert not hasattr(db, 'private_snapshot')

    # outward_git.py
    for name in (
        'CredentialStoreNotOpened', 'GitEdge', 'GitContext', 'discover_git_context',
        '_absolute', '_directory', '_identity', '_stat', '_read', '_value',
    ):
        assert hasattr(git, name), f'audit.outward_git missing {name}'

    # outward_git_config.py
    for name in ('GitConfigClassification', '_INERT', '_EXECUTING', 'classify_git_config'):
        assert hasattr(git_cfg, name), f'audit.outward_git_config missing {name}'

    # outward_python.py
    for name in (
        'analyze_python', '_CAPABLE', '_DYNAMIC', '_PREFILTER',
        '_SAFE_MEMBERS', '_SAFE', '_PATH_CONSTRUCTORS', '_PATH_CHAIN',
    ):
        assert hasattr(py_mod, name), f'audit.outward_python missing {name}'

    # outward_structured.py
    for name in ('classification', 'parse_data'):
        assert hasattr(structured, name), f'audit.outward_structured missing {name}'


def test_structured_jsonc_and_yaml_limits(tmp_path):
    structured = load_submodule('audit.outward_structured')
    tsconfig = tmp_path / 'tsconfig.json'
    assert structured.classification(tsconfig) == 'jsonc_config'
    docs = structured.parse_data(tsconfig, b'{\n  // comment\n  "url": "https://a//b",\n  "list": [1, 2,],\n}')
    assert docs == [{'url': 'https://a//b', 'list': [1, 2]}]

    deep = b'[' * 66 + b']' * 66
    with pytest.raises(ValueError, match='budget exceeded'):
        structured.parse_data(tmp_path / 'a.json', deep, unbounded=False)
    assert structured.parse_data(tmp_path / 'a.json', deep, unbounded=True)


def test_git_value_and_config_classification():
    git = load_submodule('audit.outward_git')
    git_cfg = load_submodule('audit.outward_git_config')

    assert git._value(' "a\\nb\\tc\\"\\\\" # comment') == 'a\nb\tc"\\'
    with pytest.raises(ValueError, match='git_config_escape'):
        git._value('\\x')
    with pytest.raises(ValueError, match='git_config_quote'):
        git._value('"unclosed')

    inert = git_cfg.classify_git_config('[core]\n\tbare = false\n\tfilemode = true\n[user]\n\tname = test\n')
    assert inert.status == 'inert'
    assert inert.reasons == ()

    dyn = git_cfg.classify_git_config('[alias]\n\trun = !sh -c echo\n[include]\n\tpath = extra\n')
    assert dyn.status == 'dynamic'
    assert set(dyn.reasons) == {
        'git_config_execution_unresolved', 'git_include_unresolved', 'git_config_unknown_key'
    }


def test_python_analyzer_bindings_and_callbacks():
    py_mod = load_submodule('audit.outward_python')
    assert py_mod.analyze_python('x = 42\nprint(x)\n') == []
    assert py_mod.analyze_python('x = "str"\n') == [('python_syntax_unclassified', 1)]
    assert py_mod.analyze_python('from pathlib import Path\np = Path("a")\nq = p\nq.read_text()\n') == []
    assert py_mod.analyze_python('import os\n@os.system\ndef f():\n    pass\n') == [
        ('python_implicit_execution_unresolved', 3)
    ]


def test_analyzers_toolchain_and_dynamic(tmp_path):
    analyzers = load_submodule('audit.outward_analyzers')
    home = tmp_path / 'home'
    uv_py = home / '.local/share/uv/python/cpython-3.12.8-linux-x86_64-gnu'
    uv_py.mkdir(parents=True)
    res = analyzers.resolve_toolchain(
        tmp_path / '.python-version',
        b'3.12.8\n',
        home=home,
        available_paths=[uv_py],
    )
    assert res == [{
        'path': str(tmp_path / '.python-version'),
        'kind': 'toolchain_reference',
        'resolution': 'resolved',
        'target': str(uv_py),
    }]
    assert analyzers.analyze_dynamic('Dockerfile.prod', b'FROM scratch') == [{
        'path': 'Dockerfile.prod',
        'kind': 'container_build_unresolved',
        'resolution': 'unresolved',
    }]


def test_db_snapshot_and_associations_characterization(tmp_path):
    db_mod = load_submodule('audit.outward_db')
    db_path = tmp_path / 'projects.db'
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            'CREATE TABLE projects(id TEXT, slug TEXT, primary_path TEXT);\n'
            'CREATE TABLE project_folders(project_id TEXT, path TEXT);\n'
            "INSERT INTO projects VALUES ('p1', 'slug1', '/proj/main');\n"
            "INSERT INTO project_folders VALUES ('p1', '/proj/extra');\n"
        )
    report = db_mod.inspect_database(db_path, selected_projects=['/proj/main/sub'], scratch_dir=tmp_path)
    assert report['schema'] == 'hermes_projects'
    assert {f['path'] for f in report['folder_references']} == {'/proj/main', '/proj/extra'}


def test_collect_outward_end_to_end_characterization(tmp_path, monkeypatch):
    outward = load_submodule('audit.outward')
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(
        git,
        'discover_git_context',
        lambda *a, **kw: discover(*a, **{**kw, 'system_config': tmp_path / 'no-sys-gitconfig'}),
    )
    home = tmp_path / 'home'
    profile = home / '.hermes'
    project = home / 'project'
    other = home / 'other'
    for d in (profile, project / '.git', other):
        d.mkdir(parents=True, exist_ok=True)

    (project / 'package.json').write_text(json.dumps({
        'name': 'root-pkg',
        'workspaces': ['packages/*'],
        'dependencies': {'sub-pkg': 'workspace:*', 'ext-pkg': f'file:{other}'},
        'scripts': {'build': 'echo ok'},
    }))
    sub = project / 'packages' / 'sub'
    sub.mkdir(parents=True)
    (sub / 'package.json').write_text(json.dumps({'name': 'sub-pkg'}))
    (other / 'mod.py').write_text('x = 1\n')
    (profile / 'config.yaml').write_text('model: default\n')

    report = outward.collect_outward(profile, [str(project)], unselected_project_roots=[str(other)])
    assert report['regions']['project_tree']['coverage'] == 'verified'
    assert report['regions']['active_profile']['coverage'] == 'verified'
    rels = {(b['relationship'], b['target']) for b in report['blending']}
    assert ('workspace_dependency', str(sub)) in rels
    assert ('local_dependency', str(other)) in rels
    assert any(d['path'] == str(project / 'package.json') for d in report['dynamic_invocations'])
