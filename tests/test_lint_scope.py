"""File-oriented tools must honor the shared scan, including in POST mode."""
import os
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import lint_env, lint_tools
from hermes_plugins.defuzz.linter import _matching_files_for_spec


@pytest.mark.parametrize("extension", ["css", "scss", "html", "vue", "svelte", "astro", "graphql", "gql", "md", "markdown", "yaml", "yml", "mjs", "cjs", "mts", "cts"])
def test_biome_keeps_supported_source_types(extension):
    path = f"src/example.{extension}"
    assert _matching_files_for_spec(lint_tools.by_name("biome"), [path]) == [path]


@pytest.mark.parametrize("tool,mode", [("biome", "post"), ("oxlint", "post"), ("rumdl", "pre")])
def test_file_tools_do_not_rewalk_excluded_directories(tool, mode, tmp_path):
    selected = ["src/example.ts", "README.md"]
    command = lint_tools.argv(lint_tools.by_name(tool), mode, tmp_path, selected)
    assert lint_tools.by_name(tool).input_globs
    assert "." not in command
    assert command[-2:] == selected


def test_scan_excludes_tool_caches_but_keeps_source(tmp_path):
    caches = [".import_linter_cache", ".rumdl_cache", ".pytest_cache", ".mypy_cache", ".ruff_cache"]
    for directory in caches + ["src", "dist", "build"]:
        path = tmp_path / directory / "example.json"
        path.parent.mkdir()
        path.write_text("{}")
    # dist/ is generated build output (a bundler's or packager's), not project source.
    assert set(lint_tools.scan(tmp_path).files) == {
        "src/example.json", "build/example.json"
    }


@pytest.mark.skipif(lint_env.which("biome", lint_env.build_env(os.environ)) is None, reason="biome not installed")
def test_real_biome_ignores_caches_but_reports_bad_source(tmp_path):
    from hermes_plugins.defuzz.linter import run_lint

    (tmp_path / "data.json").write_text("{}\n")
    for directory in lint_tools.IGNORED_DIRS - {".git", ".worktrees"}:
        cache = tmp_path / directory
        cache.mkdir()
        (cache / "invalid.json").write_text("{broken")
    env = dict(os.environ)
    clean = run_lint(tmp_path, env=env, db_path=tmp_path / "state.db")
    assert clean["ok"] and clean["status"] == "clean", clean
    (tmp_path / "source.css").write_text("a { color: ; invalid")
    dirty = run_lint(tmp_path, env=env, db_path=tmp_path / "state.db")
    assert dirty["ok"] and dirty["status"] == "findings", dirty
    assert any(f["file"] == "source.css" for f in dirty["findings"])
    assert all(f["file"] != "invalid.json" for f in dirty["findings"])

