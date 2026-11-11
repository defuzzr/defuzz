"""Root-write placement table for the layered .NET template (dotnet-golden).

The template has no test project and no assets folder, and its four layers each
own a project. So notes, guides and diagram sources go to docs/, shell and
PowerShell scripts to scripts/. C# sources, tests, images and data stay where
they were written: picking a layer by file name would be a guess. The shared
block of cases lives in tests/layered_placement_cases.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.placer import (  # noqa: E402
    _is_valid_adopted_rules,
    resolve_placement_for_new_path,
)
from hermes_plugins.defuzz.templates import TemplateSpec, load_templates  # noqa: E402
from tests.layered_placement_cases import (  # noqa: E402
    STAY,
    assert_shared_rules,
    assert_stays_in_both_modes,
    build_table,
    run_own_check_after_routed_writes,
    run_root_write_table,
    slow_skip_marker,
)
from tests.test_template_placement_rules import _cheap_scaffold  # noqa: E402

TEMPLATE_ID = "dotnet-golden"
HAS_ADR_DIR = False

MOVED: tuple[tuple[str, str], ...] = (
    ("layering-notes.md", "docs/layering-notes.md"),
    ("adr-0002-logging.md", "docs/adr-0002-logging.md"),
    ("RUNBOOK.MD", "docs/RUNBOOK.MD"),
    ("release notes.md", "docs/release notes.md"),
    ("设计.md", "docs/设计.md"),
    ("build.ps1", "scripts/build.ps1"),
    # No longer protected by a template pattern: the shared list keeps only exact stems.
    ("HISTORY-2025.md", "docs/HISTORY-2025.md"),
    ("TODO-later.md", "docs/TODO-later.md"),
)

STAYS: tuple[tuple[str, str], ...] = (
    # build, SDK and package configuration
    ("Other.sln", "config"),
    ("Other.slnx", "config"),
    ("Extra.csproj", "config"),
    ("Directory.Packages.props", "config"),
    ("Custom.props", "config"),
    ("Custom.targets", "config"),
    ("nuget.config", "config"),
    ("dotnet-tools.json", "config"),
    ("packages.lock.json", "config"),
    (".editorconfig.local", "dotfile"),
    (".config/dotnet-tools.json", "dotfolder"),
    (".github/workflows/release.yml", "dotfolder"),
    # governance files
    ("CONTRIBUTING.md", "governance"),
    ("HISTORY.rst", "root file"),
    (".windsurfrules", "root file"),
    # C# sources and tests: no single project owns them
    ("WidgetTest.cs", "ambiguous test"),
    ("Program.cs", "ambiguous source"),
    ("GlobalUsings.cs", "ambiguous source"),
    ("Script.csx", "ambiguous source"),
    ("Module.fs", "ambiguous source"),
    ("View.razor", "ambiguous source"),
    # Windows batch files are not shell or PowerShell scripts
    ("setup.cmd", "not a shell script"),
    # assets and data: no assets folder in this layout
    ("appsettings.json", "config or data"),
    ("fixture.xml", "no data folder"),
    ("local.yaml", "config or data"),
)

TEMPLATE_ROWS: tuple[tuple[str, str | None], ...] = (
    *MOVED,
    *((rel, STAY) for rel, _ in STAYS),
)

# Entries taken out of protected_root_files because the shared list keeps them. The
# old patterns (GEMINI.*, AUTHORS*, ...) are proved through the names they were for.
REMOVED_PROTECTED_ENTRIES = (
    "TOOLS.lock", ".editorconfig", "GEMINI.md", "COPILOT.md", "AUTHORS.md", "AUTHORS.rst",
    "CONTRIBUTORS.md", "MAINTAINERS.md", "GOVERNANCE.md", "SUPPORT.md", "HISTORY.md",
    "HISTORY.rst", "CHANGES.md", "NEWS.md", "PULL_REQUEST_TEMPLATE.md", "ISSUE_TEMPLATE.md",
)
REMOVED_PATTERNS = (
    "TOOLS.lock", ".editorconfig", "GEMINI.*", "COPILOT.*", "AUTHORS*", "CONTRIBUTORS*",
    "MAINTAINERS*", "GOVERNANCE*", "SUPPORT*", "HISTORY*", "CHANGES*", "NEWS*", "TODO*",
    "PULL_REQUEST_TEMPLATE*", "ISSUE_TEMPLATE*",
)


def _spec() -> TemplateSpec:
    return next(s for s in load_templates() if s.id == TEMPLATE_ID)


def _rules(dest: Path) -> dict:
    return json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))


def test_rules_file_validates_and_reasons_are_plain(tmp_path: Path) -> None:
    raw = json.loads((_spec().root / "rules.json").read_text(encoding="utf-8"))
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    assert _is_valid_adopted_rules(_rules(dest))
    assert_shared_rules(raw, HAS_ADR_DIR)
    for pr in raw["placement_rules"]:
        words = set(pr["reason"].lower().replace(",", " ").split())
        assert not words & {"glob", "regex", "fnmatch", "ext", "match_ext"}


def test_root_write_table(tmp_path: Path) -> None:
    dest, db = _cheap_scaffold(tmp_path, _spec())
    moved = run_root_write_table(dest, db, _rules(dest), build_table(HAS_ADR_DIR, TEMPLATE_ROWS), "dotnet")
    assert moved == 25 + len(MOVED)


def test_removed_protected_entries_still_stay_in_both_modes(tmp_path: Path) -> None:
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    rules_data = _rules(dest)
    for pat in REMOVED_PATTERNS:
        assert pat not in rules_data["protected_root_files"], pat
    assert_stays_in_both_modes(dest, rules_data, REMOVED_PROTECTED_ENTRIES)


def test_template_root_files_are_never_moved(tmp_path: Path) -> None:
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    rules_data = _rules(dest)
    tree = _spec().root / "tmpl_prefix"
    names = sorted(p.name.replace("TmplPrefix", "ProofApp") for p in tree.iterdir())
    assert "README.md" in names and "ProofApp.sln" in names
    for name in names:
        hit = resolve_placement_for_new_path(dest, name, rules_data, mode="declared_only")
        assert hit is None, (name, hit)


@slow_skip_marker()
def test_ten_routed_writes_keep_template_check_green(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_own_check_after_routed_writes(_spec(), tmp_path, monkeypatch, HAS_ADR_DIR, "dotnet_ci")
