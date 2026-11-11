"""Lint never checks what the project's own Git ignore rules exclude (build output, dependencies)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_tools, path_match, tool_detect  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = REPO_ROOT / "templates"

# Output folders each bundled template's check or tools write, all git-ignored by the
# template's own .gitignore. Nested entries mirror where the tools really put them.
TEMPLATE_OUTPUT_DIRS = {
    "cpp-golden": ("build", "build/CMakeFiles", "out"),
    "dotnet-golden": ("target", "bin", "obj", "src/App/bin/Debug", "src/App/obj"),
    "go-golden": ("bin", "dist"),
    "python-golden": (
        ".venv/lib", "src/pkg/__pycache__", "build/lib", "dist", "wheels",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".import_linter_cache",
    ),
    "rust-golden": ("target/debug",),
    "ts-node-golden": ("node_modules/pkg", "dist", "coverage/lcov-report"),
    "web-golden": (
        "node_modules/pkg", "dist", "coverage", "test-results", "playwright-report",
        ".xtask-cache/tmp",
    ),
}
# Files that every lint tool would report: broken JSON, CSS, Markdown, YAML, C++, Python.
BAD_FILES = {
    "bad.json": "{broken",
    "bad.css": "a { color: ; invalid",
    "bad.md": "#bad heading\n\n\n\ntrailing   \n",
    "bad.yml": "a: [unclosed\n",
    "bad.cpp": "int  main( ){return 0;}",
    "bad.py": "import os,sys\nx=1\n",
}


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def _project_with_outputs(root: Path, template_id: str) -> None:
    """A Git project with the template's .gitignore and its output folders full of bad files."""
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    shutil.copyfile(TEMPLATES / template_id / "tmpl_prefix" / ".gitignore", root / ".gitignore")
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "data.json").write_text("{}\n", encoding="utf-8")
    for rel in TEMPLATE_OUTPUT_DIRS[template_id]:
        folder = root / rel
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in BAD_FILES.items():
            (folder / name).write_text(text, encoding="utf-8")


def test_every_template_is_covered() -> None:
    shipped = {p.parent.name for p in TEMPLATES.glob("*/template.yaml")}
    assert shipped == set(TEMPLATE_OUTPUT_DIRS)


@pytest.mark.parametrize("template_id", sorted(TEMPLATE_OUTPUT_DIRS))
def test_scan_skips_template_output_that_git_ignores(tmp_path: Path, template_id: str) -> None:
    root = tmp_path / "proj"
    _project_with_outputs(root, template_id)
    files = set(path_match.scan(root).files)
    assert files == {".gitignore", "src/data.json"}, sorted(files)
    assert set(tool_detect.walk_project_files(root)) == files
    assert set(lint_tools.scan(root).files) == files


def test_tracked_file_inside_ignored_folder_is_still_linted(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    _project_with_outputs(root, "cpp-golden")
    (root / "build" / "keep.json").write_text("{}\n", encoding="utf-8")
    _git(root, "add", "-f", "build/keep.json")
    (root / "notes.log").write_text("x\n", encoding="utf-8")
    (root / "new").mkdir()
    (root / "new" / "draft.json").write_text("{}\n", encoding="utf-8")
    files = set(path_match.scan(root).files)
    assert files == {".gitignore", "src/data.json", "build/keep.json", "new/draft.json", "notes.log"}


def test_folder_without_its_own_git_keeps_the_name_list(tmp_path: Path) -> None:
    # Not a Git project: only the fixed folder names are skipped, so a build/ folder of
    # real sources (for example packaging scripts) is still linted.
    root = tmp_path / "plain"
    (root / "build").mkdir(parents=True)
    (root / "build" / "ci.json").write_text("{}\n", encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "x.json").write_text("{}\n", encoding="utf-8")
    assert set(path_match.scan(root).files) == {"build/ci.json"}


def test_outer_repository_ignore_rules_do_not_hide_a_nested_plain_folder(tmp_path: Path) -> None:
    # A home folder kept in Git often ignores everything ("*"). A project inside it that is
    # not its own Git repository must still be linted in full.
    outer = tmp_path / "home"
    outer.mkdir()
    _git(outer, "init", "-q")
    (outer / ".gitignore").write_text("*\n", encoding="utf-8")
    proj = outer / "proj"
    (proj / "build").mkdir(parents=True)
    (proj / "build" / "ci.json").write_text("{}\n", encoding="utf-8")
    (proj / "main.json").write_text("{}\n", encoding="utf-8")
    assert set(path_match.scan(proj).files) == {"build/ci.json", "main.json"}


def test_scan_without_git_on_path_falls_back_to_the_name_list(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "proj"
    _project_with_outputs(root, "cpp-golden")
    monkeypatch.setenv("PATH", str(tmp_path / "no-tools"))
    files = set(path_match.scan(root).files)
    assert "src/data.json" in files and "build/bad.json" in files


def test_real_lint_is_clean_with_cmake_build_output(tmp_path: Path) -> None:
    from hermes_plugins.defuzz.linter import run_lint

    root = tmp_path / "proj"
    _project_with_outputs(root, "cpp-golden")
    # CMake 4 output exactly as it failed Biome's format check.
    (root / "build" / "compile_commands.json").write_text('[\n{\n  "file": "a.cpp"\n}\n]\n\n', encoding="utf-8")
    (root / "build" / "CMakeFiles" / "InstallScripts.json").write_text(
        '{\n  "InstallScripts" : [ "x" ]\n}\n', encoding="utf-8"
    )
    report = run_lint(root, env=dict(os.environ), db_path=tmp_path / "state.db")
    assert report["ok"] and report["status"] == "clean", report
    assert not any(f["file"].startswith("build/") for f in report.get("findings") or [])
