"""Scaffold context is generated from rules and committed."""
import json
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import scaffolder
from hermes_plugins.defuzz.agents_md import render_from_rules
from hermes_plugins.defuzz.templates import load_template, load_templates, templates_root
from tests.toolchain_needs import check_tools, fake_toolchain


def discover_template_ids(root: Path | None = None) -> list[str]:
    """Discover all template IDs under templates/*/template.yaml."""
    specs = load_templates(root)
    assert specs, f"No templates discovered under {root or templates_root()}"
    return [spec.id for spec in specs]


def test_scaffold_generates_rules_and_context_before_commit(tmp_path):
    spec = load_template(Path(__file__).parent / "fixtures/templates/fake-rust-game")
    proposal = scaffolder.propose(spec, "Rules Smoke", {}, dest_root=tmp_path / "projects")
    try:
        plan = proposal.repos[0]
        plan.check = None
        # Creation probes cargo and rustc versions; this test is about rules, so stand-ins answer.
        with fake_toolchain(tmp_path / "fake-bin", ("cargo", "rustc")):
            result = scaffolder.accept(
                proposal, db_path=tmp_path / "state.db",
                register=lambda name, path: json.dumps({"success": True, "id": "test-project"}),
            )
        root = Path(result.repos[0]["path"])
        rules = json.loads((root / ".adopt/rules.json").read_text())
        assert rules["project_slug"] == root.name
        for name, content in render_from_rules(rules).items():
            assert (root / name).read_text() == content
        tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
        assert "AGENTS.md" in tracked
        assert ".adopt/rules.json" in tracked
        assert all(name in tracked for name in render_from_rules(rules))
    finally:
        scaffolder.discard(proposal)


@pytest.mark.parametrize("template_id", discover_template_ids())
def test_golden_scaffold_rules_are_committed_and_reproducible(tmp_path, template_id, templates_dir=None):
    """Exercise real template trees; dependency installation/CI is separate."""
    base_dir = Path(templates_dir) if templates_dir is not None else templates_root()
    spec = load_template(base_dir / template_id)
    proposal = scaffolder.propose(
        spec, "Rules Golden", {}, dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging", db_path=tmp_path / "state.db",
    )
    try:
        # This test verifies rules generation, not external template CI. Creation still
        # probes the template's tool versions, so stand-ins answer for them.
        proposal.repos[0].check = None
        with fake_toolchain(tmp_path / "fake-bin", check_tools(spec)):
            result = scaffolder.accept(
                proposal, db_path=tmp_path / "state.db", remember_options=False,
                register=lambda name, path: json.dumps({"success": True, "id": "rules-test"}),
            )
        root = Path(result.repos[0]["path"])
        rules = json.loads((root / ".adopt/rules.json").read_text())
        assert rules["project_slug"] == root.name
        rendered = render_from_rules(rules)
        assert rendered
        for name, expected in rendered.items():
            assert (root / name).read_text() == expected
            committed = subprocess.check_output(
                ["git", "show", f"HEAD:{name}"], cwd=root, text=True,
            )
            assert committed == expected
        assert subprocess.check_output(
            ["git", "show", "HEAD:.adopt/rules.json"], cwd=root, text=True,
        ) == (root / ".adopt/rules.json").read_text()
    finally:
        scaffolder.discard(proposal)


def test_context_preserves_template_instructions_and_is_retry_safe(tmp_path):
    original = "# Template instructions\nKeep these project-specific instructions.\n"
    (tmp_path / "AGENTS.md").write_text(original)
    scaffolder._generate_scaffold_context(tmp_path, "preserve-me")
    assert (tmp_path / "docs/AGENTS.template.md").read_text() == original
    assert "docs/AGENTS.template.md" in (tmp_path / "AGENTS.md").read_text()
    first = (tmp_path / "AGENTS.md").read_bytes()
    scaffolder._generate_scaffold_context(tmp_path, "preserve-me")
    assert (tmp_path / "AGENTS.md").read_bytes() == first
    assert (tmp_path / "docs/AGENTS.template.md").read_text() == original
