"""Public-boundary readiness regressions."""
import os
from pathlib import Path
from tests import load_submodule


def _private_imports(source):
    import ast
    banned = {'hermes_cli.profiles', 'hermes_cli.mcp_security',
              'tools.environments.local', 'tools.project_tools'}
    violations = []
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names = [node.module or ''] + [f'{node.module}.{alias.name}' for alias in node.names]
        elif isinstance(node, ast.Call):
            function = node.func
            if ((isinstance(function, ast.Name) and function.id in {'__import__', 'import_module'})
                    or (isinstance(function, ast.Attribute) and function.attr in {'import_module', '__import__'})):
                argument = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg == 'name'), None)
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    names = [argument.value]
        for name in names:
            if any(name == b or name.startswith(b + '.') for b in banned):
                violations.append((node.lineno, name))
    return violations


def test_import_lock_detects_dynamic_literals():
    for expression in ("importlib.import_module('hermes_cli.profiles')",
                       "__import__('tools.project_tools')",
                       "importlib.__import__('hermes_cli.profiles')" ):
        assert _private_imports(expression)


def test_production_has_no_private_core_imports():
    from tests import REPO_ROOT
    violations = []
    for directory, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in {'tests', '.git', '.worktrees', '.venv', 'node_modules'}]
        for filename in files:
            if not filename.endswith('.py'):
                continue
            path = Path(directory) / filename
            for line, name in _private_imports(path.read_text()):
                violations.append(f'{path.relative_to(REPO_ROOT)}:{line}: {name}')
    assert not violations, '\n'.join(violations)


def test_lint_environment_is_allowlisted(tmp_path):
    lint = load_submodule('lint_env')
    base = {'HOME': str(tmp_path), 'HERMES_REAL_HOME': str(tmp_path), 'PATH': '/usr/bin',
            'OPENAI_API_KEY': 'secret', 'UNCLASSIFIED_CREDENTIAL': 'secret',
            'PYTHONPATH': '/injected', 'LD_PRELOAD': '/injected', 'NODE_OPTIONS': '--require evil',
            'RUFF_CACHE_DIR': str(tmp_path / 'cache')}
    env = lint.build_env(base)
    for key in ('OPENAI_API_KEY', 'UNCLASSIFIED_CREDENTIAL', 'PYTHONPATH', 'LD_PRELOAD', 'NODE_OPTIONS'):
        assert key not in env
    assert env['RUFF_CACHE_DIR'] == base['RUFF_CACHE_DIR']
    assert base['OPENAI_API_KEY'] == 'secret'


def test_project_registration_uses_public_dispatch(monkeypatch):
    from tools.registry import registry
    import sys
    import types
    monkeypatch.setitem(sys.modules, 'tools.project_tools', types.SimpleNamespace(project_create=lambda **kw: '{}'))
    calls = []
    monkeypatch.setattr(registry, 'get_entry', lambda name: object())
    monkeypatch.setattr(registry, 'dispatch', lambda name, args: calls.append((name, args)) or {'success': True})
    result = load_submodule('scaffolder').default_project_create('Example', '/example')
    assert calls == [('desktop_project', {'action': 'create', 'name': 'Example', 'path': '/example'})]
    assert result == '{"success": true}'


def test_cli_reports_registration_skip_in_both_creation_routes(monkeypatch, capsys):
    from types import SimpleNamespace
    cli = load_submodule('cli')
    result = SimpleNamespace(repos=[{
        'path': '/example', 'registration': 'skipped',
        'registration_reason': 'desktop_project unavailable', 'hermes_project_id': '',
    }])
    monkeypatch.setattr(cli, 'run_new_project_flow', lambda **kw: SimpleNamespace(status='created', accept=result))
    monkeypatch.setattr(cli, 'load_templates', lambda root: [SimpleNamespace(id='example')])
    monkeypatch.setattr(cli, 'load_templates_lenient', lambda root: ([SimpleNamespace(id='example')], []))
    monkeypatch.setattr(cli, 'run_questionnaire', lambda *args, **kw: {})
    monkeypatch.setattr(cli, 'propose', lambda *args, **kw: object())
    monkeypatch.setattr(cli, 'accept', lambda *args, **kw: result)
    # Without a chosen template or kit nothing is created (exit 2, no registration).
    assert cli._handle_new_subcommand(SimpleNamespace(answers='{}', name='Example', yes=True)) == 2
    assert 'Registration skipped' not in capsys.readouterr().err
    for template, kit in (('example', None), (None, 'example-kit')):
        assert cli._handle_new_subcommand(SimpleNamespace(
            answers='{}', name='Example', yes=True, template_id=template, kit_id=kit,
        )) == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == '/example'
        assert 'Registration skipped' in captured.err
        assert 'desktop_project unavailable' in captured.err


def test_security_semantics_are_unknown_without_injection():
    assert load_submodule('audit.facts').resolve_mcp_entry_security_check() is None


def test_profiles_use_explicit_public_scope(tmp_path, monkeypatch):
    facts = load_submodule('audit.facts')
    import hermes_constants
    (tmp_path / 'profiles' / 'coder').mkdir(parents=True)
    (tmp_path / 'profiles' / 'coder' / 'config.yaml').touch()
    calls = []
    monkeypatch.setattr(hermes_constants, 'get_default_hermes_root', lambda *, home: calls.append(home) or tmp_path)
    result = facts.enumerate_profiles()
    assert calls
    assert calls[0] == hermes_constants.get_hermes_home()
    assert {p['name'] for p in result.profiles} == {'default', 'coder'}


def test_collection_home_is_owned_and_temporary(request):
    # Use the conftest instance pytest actually loaded. `from tests import conftest`
    # can import a second copy (rootdir=tests + pythonpath=..) with its own temp dir.
    loaded = [p for p in request.config.pluginmanager.get_plugins()
              if getattr(p, '__file__', '').endswith(os.path.join('tests', 'conftest.py'))
              and hasattr(p, '_TEST_HOME')]
    assert loaded
    owned = loaded[0]._TEST_HOME.name
    assert Path(os.environ['HERMES_HOME']).is_relative_to(owned)
    assert Path(os.environ['HOME']).is_relative_to(owned)


def test_worktrees_are_excluded_from_scaffold(tmp_path):
    scaffolder = load_submodule('scaffolder')
    src = tmp_path / 'source'
    staged = tmp_path / 'staged'
    (src / '.worktrees' / 'child').mkdir(parents=True)
    (src / '.worktrees' / 'child' / 'private.txt').write_text('must not copy')
    (src / 'keep.txt').write_text('keep')
    forms = load_submodule('naming').forms_from_placeholder('tmpl_prefix')
    skipped = []
    scaffolder._stage_and_rename_repo(src, staged, forms, forms, [], skipped)
    assert not (staged / '.worktrees').exists()
    assert (staged / 'keep.txt').read_text() == 'keep'
    assert '.worktrees' in skipped


def test_manifest_declares_exact_registered_hooks():
    import yaml
    from tests.test_cli_and_plugin import _MockPluginContext
    from tests import ensure_test_package, REPO_ROOT
    ctx = _MockPluginContext()
    ensure_test_package().register(ctx)
    manifest = yaml.safe_load((REPO_ROOT / 'plugin.yaml').read_text())
    assert manifest['requires_hermes'] == '>=0.23.0'
    assert set(manifest['provides_hooks']) == set(ctx.hooks)
