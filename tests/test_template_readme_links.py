"""Every relative Markdown link in a generated project's README and docs must resolve."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # type: ignore[import-not-found]  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
TEMPLATES = {
    "python-golden": "python",
    "rust-golden": "rust",
    "go-golden": "go",
    "cpp-golden": "cpp",
    "dotnet-golden": "csharp",
    "ts-node-golden": "typescript",
}


def _relative_links(text: str) -> list[str]:
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    out = []
    for target in LINK.findall(text):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            continue
        out.append(target.split("#", 1)[0])
    return [t for t in out if t]


@pytest.mark.parametrize("template_id", sorted(TEMPLATES))
def test_generated_readme_and_docs_links_resolve(template_id: str, tmp_path: Path) -> None:
    spec = load_template(REPO_ROOT / "templates" / template_id)
    proposal = scaffolder.propose(
        spec,
        "Probe Svc",
        {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=tmp_path / "dest",
        staging_parent=tmp_path / "staging",
    )
    try:
        staged = proposal.repos[0].staged
        rules = scaffolder._resolve_template_rules_for_proposal(proposal)
        # Same step accept() runs: keeps the template AGENTS.md as docs/AGENTS.template.md
        # and writes the project's own AGENTS.md.
        scaffolder._generate_scaffold_context(staged, proposal.slug, template_rules=rules)
        files = [staged / "README.md", *sorted((staged / "docs").rglob("*.md"))]
        assert (staged / "README.md").is_file()
        broken = []
        for md in files:
            for target in _relative_links(md.read_text(encoding="utf-8")):
                if not (md.parent / target).exists():
                    broken.append(f"{md.relative_to(staged)} -> {target}")
        assert broken == [], broken
    finally:
        scaffolder.discard(proposal)
