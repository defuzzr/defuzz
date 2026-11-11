"""Manual lint must not be reachable through lifecycle hooks."""
from pathlib import Path
from unittest import mock

from tests import ensure_test_package
from tests.test_cli_and_plugin import _MockPluginContext

plugin = ensure_test_package()


def test_automatic_guard_code_is_removed():
    assert plugin.__file__ is not None
    root = Path(plugin.__file__).parent
    # Explicit lock provenance is not an automatic execution/lint guard.
    guard = (root / "tool_guard.py").read_text()
    assert "register_hook" not in guard
    assert "on_pre_tool_call" not in guard
    assert "on_transform_tool_result" not in guard


def test_registered_hooks_do_not_lint_or_probe_on_edits(tmp_path):
    from hermes_plugins.defuzz import linter, toolchk, placer

    ctx = _MockPluginContext()
    plugin.register(ctx)
    with (
        mock.patch.object(linter, "run_lint", side_effect=AssertionError("automatic lint")) as lint,
        mock.patch.object(toolchk, "check", side_effect=AssertionError("automatic probe")) as probe,
    ):
        for name in ("write_file", "patch", "terminal"):
            args = {"path": str(tmp_path / "new.py"), "content": "x = 1", "command": "python new.py"}
            for hook in ctx.hooks["pre_tool_call"]:
                assert hook(tool_name=name, args=args, session_id="manual-only") is None
            for hook in ctx.hooks["transform_tool_result"]:
                assert hook(tool_name=name, args=args, result='{"ok": true}', session_id="manual-only") is None
    lint.assert_not_called()
    probe.assert_not_called()
    assert ctx.hooks["transform_tool_result"] == [placer.on_transform_tool_result]


def test_slash_lint_dispatches_manual_cli_with_quoted_path():
    ctx = _MockPluginContext()
    plugin.register(ctx)
    from hermes_plugins.defuzz import cli

    with mock.patch.object(cli, "_handle_lint_subcommand", return_value=0) as run:
        response = ctx.slash_commands["defuzz"]["handler"]('lint "/project with spaces" --mode pre --json')
    run.assert_called_once()
    ns = run.call_args.args[0]
    assert ns.project == "/project with spaces"
    assert ns.mode == "pre"
    assert ns.as_json is True
    assert "exit code: 0" in response


def test_slash_lint_invalid_arguments_return_usage():
    response = plugin._handle_slash_command(_MockPluginContext(), "lint")
    assert "usage:" in response
    assert "exit code: 2" in response


def test_manifest_hooks_match_placement_registration():
    import yaml

    ctx = _MockPluginContext()
    plugin.register(ctx)
    manifest = yaml.safe_load(Path(plugin.__file__).with_name("plugin.yaml").read_text())
    assert set(manifest["provides_hooks"]) == set(ctx.hooks)
    assert "pre_llm_call" not in ctx.hooks
    with mock.patch.object(plugin, "on_pre_tool_call", return_value=None) as place:
        ctx.hooks["pre_tool_call"][0](tool_name="write_file", args={})
    place.assert_called_once_with(auto_place_enabled=True, tool_name="write_file", args={})
