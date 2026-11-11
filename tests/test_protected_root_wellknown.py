"""Well-known root files (agent instructions, governance, release notes) stay at the root.

Runs a table of root names through both placement modes and through adopt apply's plan
(expand_rules), with a project whose rules send loose root Markdown and text to docs/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.placer import (  # noqa: E402
    TRUST_MODE_DECLARED_ONLY,
    TRUST_MODE_FULL,
    resolve_placement_for_new_path,
)
from hermes_plugins.defuzz.rules import (  # noqa: E402
    PROTECTED_ROOT_FILES,
    PROTECTED_ROOT_TABLE,
    expand_rules,
    is_protected_root_path,
)
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402

_EXTS = [".md", ".txt", ".rst", ".cff", ".yml", ".markdown", ".adoc"]

RULES = {
    "project_slug": "demo",
    "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs", "source": "explicit"}],
    "folder_rules": [],
    "placement_rules": [
        {
            "kind": "docs",
            "match_ext": _EXTS,
            "root_only": True,
            "dest_dir": "docs",
            "lfs": False,
            "reason": "notes live in docs/",
            "source": "explicit",
        }
    ],
    "ignore_patterns": [],
    "lfs_patterns": [],
}

PROTECTED = (
    # agent-instruction files
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "COPILOT.md", "CONVENTIONS.md", "llms.txt",
    "llms-full.txt",
    # governance and community
    "AUTHORS", "AUTHORS.md", "AUTHORS.txt", "CONTRIBUTORS.md", "CONTRIBUTORS.txt",
    "MAINTAINERS.md", "MAINTAINERS", "GOVERNANCE.md", "SUPPORT.md", "CODEOWNERS",
    "CODE_OF_CONDUCT.md", "SECURITY.md", "CONTRIBUTING.md", "CONTRIBUTING.rst",
    "CITATION.cff", "FUNDING.yml", "PULL_REQUEST_TEMPLATE.md", "ISSUE_TEMPLATE.md",
    "THIRD_PARTY_NOTICES.txt", "THIRD_PARTY_LICENSES.md", "THIRD-PARTY-NOTICES.txt",
    "PATENTS", "PATENTS.md", "TRADEMARK.md", "TRADEMARKS.md",
    # release notes
    "CHANGELOG.md", "CHANGELOG.rst", "CHANGES.md", "CHANGES.txt", "HISTORY.md",
    "HISTORY.rst", "NEWS.md", "NEWS", "RELEASES.md", "RELEASE_NOTES.md", "UPGRADING.md",
    "MIGRATING.md", "MIGRATION.md",
    # long-standing root docs
    "README.md", "README.rst", "LICENSE", "LICENSE.md", "NOTICE", "NOTICE.md", "COPYING",
)

MOVABLE = (
    "notes.md", "todo.md", "design.md", "meeting-2026-01-01.md", "support-matrix.md",
    "SUPPORTED_VERSIONS.md", "authors-guide.md", "history-of-project.md", "news-2026.md",
    "governance-notes.md", "AUTHORSHIP.md", "change-proposal-draft.txt", "Contributors-call.md",
    "ROADMAP.md", "roadmap.md", "plan.txt", "gemini-notes.md", "release-plan.md",
    "migrating-notes.md", "upgrading_tips.md",
)


def test_table_is_large_enough() -> None:
    assert len(PROTECTED) + len(MOVABLE) >= 60


def _write_rules(proj: Path) -> None:
    (proj / ".adopt").mkdir(parents=True, exist_ok=True)
    (proj / ".adopt" / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")


@pytest.mark.parametrize("mode", [TRUST_MODE_FULL, TRUST_MODE_DECLARED_ONLY])
@pytest.mark.parametrize("name", PROTECTED)
def test_wellknown_root_file_stays_at_root(tmp_path: Path, mode: str, name: str) -> None:
    _write_rules(tmp_path)
    assert resolve_placement_for_new_path(tmp_path, name, RULES, mode=mode) is None
    assert is_protected_root_path(name)


@pytest.mark.parametrize("mode", [TRUST_MODE_FULL, TRUST_MODE_DECLARED_ONLY])
@pytest.mark.parametrize("name", MOVABLE)
def test_ordinary_root_note_still_moves(tmp_path: Path, mode: str, name: str) -> None:
    _write_rules(tmp_path)
    out = resolve_placement_for_new_path(tmp_path, name, RULES, mode=mode)
    assert out is not None and out["placed_rel"] == f"docs/{name}", out


def test_adopt_apply_plan_keeps_wellknown_and_moves_ordinary() -> None:
    names = PROTECTED + MOVABLE
    inventory = {"files": [{"path": n, "size": 1, "tracked": True, "sha256": "x"} for n in names]}
    exts = sorted({Path(n).suffix for n in names if Path(n).suffix})
    spec = {
        "project_slug": "demo",
        "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
        "folder_rules": [
            {"match": ".", "ext": exts, "disposition": "move", "git_policy": "track",
             "to": "docs", "reason": "notes"},
        ],
    }
    plan = expand_rules(inventory, spec)
    rows = {e["source_path"]: e for e in plan["files"]}
    for n in PROTECTED:
        assert rows[n]["disposition"] == "keep" and rows[n]["dest_path"] == n, rows[n]
    for n in MOVABLE:
        assert rows[n]["dest_path"] == f"docs/{n}", rows[n]


# Frozen copy of every name the tables protected before this change.
_OLD_FILES = (
    "AGENTS.md", "CLAUDE.md", "README.md", "LICENSE", "CHANGELOG.md", "THEMING.md", "TOOLS.lock",
    "package.json", "package-lock.json", "tsconfig.json", "pyproject.toml", "Cargo.toml",
    "Makefile", ".gitignore", ".gitattributes", ".editorconfig", ".worktreeinclude",
)
_OLD_GOV_EXACT = ("AGENTS.md", "CLAUDE.md", "TOOLS.lock", "THEMING.md", "COMPONENTS.md", "00-INDEX.md")
_OLD_GOV_GLOBS = (
    "README*", "LICENSE*", "LICENCE*", "COPYING*", "NOTICE*",
    "CHANGELOG*", "CHANGES*", "CONTRIBUTING*", "CODE_OF_CONDUCT*", "SECURITY*",
)


def test_nothing_previously_protected_becomes_movable() -> None:
    assert set(_OLD_FILES) <= PROTECTED_ROOT_FILES
    gov = next(r for r in PROTECTED_ROOT_TABLE if r["category"] == "governance_and_docs")
    assert set(_OLD_GOV_EXACT) <= set(gov["exact"])
    assert set(_OLD_GOV_GLOBS) <= set(gov["globs"])
    for g in _OLD_GOV_GLOBS:
        stem = g.rstrip("*")
        for probe in (stem, stem + ".md", stem.lower() + ".md", stem.lower() + "-notes.md"):
            assert is_protected_root_path(probe), probe


@pytest.mark.parametrize("mode", [TRUST_MODE_FULL, TRUST_MODE_DECLARED_ONLY])
def test_every_template_root_file_still_protected(tmp_path: Path, mode: str) -> None:
    _write_rules(tmp_path)
    seen = 0
    for spec in load_templates():
        for repo_spec in spec.repos:
            for entry in sorted((spec.root / repo_spec.name).iterdir()):
                # Full mode protects only named root files; manifests such as CMakeLists.txt
                # are full-mode placement by design, so there only root Markdown is checked.
                if entry.is_file() and (mode == TRUST_MODE_DECLARED_ONLY or entry.suffix == ".md"):
                    seen += 1
                    assert resolve_placement_for_new_path(tmp_path, entry.name, RULES, mode=mode) is None, (
                        spec.id, entry.name)
    assert seen > 7
