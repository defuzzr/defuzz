"""Release B component contracts are delivered in generated workspaces."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.naming import forms_from_placeholder
from hermes_plugins.defuzz.scaffolder import discard, propose
from hermes_plugins.defuzz.templates import load_template, load_templates, templates_root
from tests.toolchain_needs import need

OPTIONAL_COMPONENTIZE_FILES = (
    "docs/component-boundaries.md",
    "componentize/spec.example.json",
    "tools/xtask/src/xtask/componentize.py",
    "tools/xtask/tests/test_componentize_gate.py",
)

# Templates that ship no component contract (web-golden: a static website synced from its
# own source). Every other template must deliver COMPONENTS.md; a new template without it
# fails until it is named here.
TEMPLATES_WITHOUT_COMPONENTS = frozenset({"web-golden"})


def discover_template_ids(root: Path | None = None) -> list[str]:
    """Discover all template IDs under templates/*/template.yaml."""
    specs = load_templates(root)
    assert specs, f"No templates discovered under {root or templates_root()}"
    return [spec.id for spec in specs]


def test_templates_without_components_are_real_templates():
    assert TEMPLATES_WITHOUT_COMPONENTS <= set(discover_template_ids())


@pytest.mark.parametrize("template", discover_template_ids())
def test_componentize_scaffold_contract(tmp_path, template, templates_dir=None):
    base_dir = Path(templates_dir) if templates_dir is not None else templates_root()
    spec = load_template(base_dir / template)
    proposal = propose(
        spec,
        "Boundary Probe",
        {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging",
    )
    try:
        root = proposal.repos[0].staged
        src_repo = spec.root / spec.repos[0].name
        if template in TEMPLATES_WITHOUT_COMPONENTS:
            assert not (src_repo / "COMPONENTS.md").is_file(), f"{template} now ships COMPONENTS.md; drop it from TEMPLATES_WITHOUT_COMPONENTS"
            for name in ("COMPONENTS.md", *OPTIONAL_COMPONENTIZE_FILES):
                assert not (root / name).exists(), name
            for path in sorted(root.rglob("*")):
                if path.is_file() and "node_modules" not in path.parts:
                    assert b"COMPONENTS.md" not in path.read_bytes(), path.relative_to(root).as_posix()
            return
        paths = ["COMPONENTS.md"] + [
            rel for rel in OPTIONAL_COMPONENTIZE_FILES if (src_repo / rel).is_file()
        ]
        forms = forms_from_placeholder(spec.placeholder)
        tokens = (forms.snake, forms.kebab, forms.screaming, forms.pascal)
        for name in paths:
            assert (root / name).is_file(), name
            text = (root / name).read_text()
            for token in tokens:
                assert token not in text
        if (root / "docs/component-boundaries.md").is_file():
            boundaries_text = " ".join((root / "docs/component-boundaries.md").read_text().split())
            assert "COMPONENTS.md" in boundaries_text
        if (root / "tools/xtask/src/xtask/componentize.py").is_file():
            main = (root / "tools/xtask/src/xtask/main.py").read_text()
            assert "Target package name (with or without the workspace prefix)." in main
            env = dict(os.environ)
            for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
                env.pop(key, None)
            check_spec = spec.repos[0].check
            assert check_spec is not None and len(check_spec.cmd) >= 2
            gate_cmd = [*check_spec.cmd[:-1], "componentize-gate", "example/component.py"]
            need(gate_cmd[0])
            proc = subprocess.run(
                gate_cmd,
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
            )
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "componentize gate unavailable; optional check skipped." in proc.stderr
    finally:
        discard(proposal)
