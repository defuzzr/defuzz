"""Generated dependency locks are visible exclusions, not style inputs."""
import argparse
import json
from unittest import mock

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import cli, linter, lint_tools

LOCKS = (
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Cargo.lock", "uv.lock",
    "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum",
)


def test_generated_locks_are_reported_and_not_style_inputs(tmp_path):
    paths = sorted([*LOCKS, *(f"nested/{name}" for name in LOCKS)])
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("machine generated\n")
    for spec in lint_tools.TOOLS:
        assert linter._matching_files_for_spec(spec, paths) == []
    assert lint_tools.detect(tmp_path) == []
    result = linter.run_lint(tmp_path, env={}, db_path=tmp_path / "state.sqlite")
    assert result["skipped_generated"] == paths
    assert result["ok"] is True
    assert result["tools_run"] == []


def test_cli_prints_generated_skips_even_for_incomplete_runs(tmp_path, capsys):
    for ok in (True, False):
        result = {"ok": ok, "status": "clean" if ok else "incomplete",
                  "findings": [], "skipped_generated": ["nested/pnpm-lock.yaml"]}
        with mock.patch.object(cli, "run_lint", return_value=result):
            cli._handle_lint_subcommand(argparse.Namespace(project=str(tmp_path), mode="both", as_json=False))
        output = capsys.readouterr()
        assert "Skipped generated: nested/pnpm-lock.yaml" in output.out


def test_cli_json_preserves_generated_skips(tmp_path, capsys):
    result = {"ok": True, "status": "clean", "findings": [], "skipped_generated": ["uv.lock"]}
    with mock.patch.object(cli, "run_lint", return_value=result):
        assert cli._handle_lint_subcommand(argparse.Namespace(project=str(tmp_path), mode="both", as_json=True)) == 0
    assert json.loads(capsys.readouterr().out) == result


def test_ordinary_files_remain_style_inputs():
    spec = next(spec for spec in lint_tools.TOOLS if spec.tool == "yamllint")
    assert linter._matching_files_for_spec(spec, ["pnpm-lock.yaml", "config.yaml", "nested/config.yaml"]) == ["config.yaml", "nested/config.yaml"]
