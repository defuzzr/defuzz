"""Real formatter and Markdown/YAML lint coverage across scaffold name lengths.

Set ADOPT_ALL_NAME_LENGTHS=1 for every length; boundaries and the reported
regression always run. A test whose template's tools are not installed skips with
"<tool> not installed"; with them installed it runs unchanged.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.naming import MAX_NAME_LENGTH, slugify
from hermes_plugins.defuzz.scaffolder import discard, propose
from hermes_plugins.defuzz.templates import (
    load_template,
    load_templates,
    templates_root,
)
from tests.template_lint_known import run_format_checks_allowing_known
from tests.toolchain_needs import format_tools, need

LENGTHS = (
    range(1, MAX_NAME_LENGTH + 1)
    if os.environ.get("ADOPT_ALL_NAME_LENGTHS") == "1"
    else (1, 2, 59, 60, 61, MAX_NAME_LENGTH - 1, MAX_NAME_LENGTH)
)
NAMES = ["a" * length for length in LENGTHS] + ["c2-python-final", "z" * MAX_NAME_LENGTH, "a-" * 31 + "ab"]


def discover_template_ids(root: Path | None = None) -> list[str]:
    """Discover all template IDs under templates/*/template.yaml."""
    specs = load_templates(root)
    assert specs, f"No templates discovered under {root or templates_root()}"
    return [spec.id for spec in specs]


@pytest.mark.parametrize("template", discover_template_ids())
@pytest.mark.parametrize("name", NAMES, ids=lambda name: f"length-{len(name)}-{name[:15]}")
def test_scaffold_name_passes_format_and_check(tmp_path, template, name, templates_dir=None):
    base_dir = Path(templates_dir) if templates_dir is not None else templates_root()
    spec = load_template(base_dir / template)
    need(*format_tools(spec))
    proposal = propose(
        spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
    )
    try:
        root = proposal.repos[0].staged
        # Acceptance generates this linked guide; stage the real renderer's output
        # so Markdown link checking also runs before the slower acceptance matrix.
        from hermes_plugins.defuzz.agents_md import render_agents_md_files
        for relative, content in render_agents_md_files(
            project_slug=name, declared_dirs={}, placement_rules=[],
        ).items():
            target = root / relative
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
        run_format_checks_allowing_known(spec, root)
    finally:
        discard(proposal)


def test_slug_length_limit():
    assert slugify("a" * MAX_NAME_LENGTH) == "a" * MAX_NAME_LENGTH
    with pytest.raises(ValueError, match="64"):
        slugify("a" * (MAX_NAME_LENGTH + 1))
