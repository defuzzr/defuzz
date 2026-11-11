"""Root-write placement table for the cpp-golden template.

Notes and diagrams have one clear home (docs/), shell scripts another (scripts/).
Sources, headers and tests stay where they were written: the template has three
libraries plus apps/cli, and tests/CMakeLists.txt lists its sources by name, so a
move would either guess a library or add a file the build ignores. CMake modules
stay too: cmake/ is a locked folder and the build sets no CMAKE_MODULE_PATH.
The shared block of cases lives in tests/layered_placement_cases.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.placer import inspect_project_trust  # noqa: E402
from hermes_plugins.defuzz.rules import is_protected_root_path  # noqa: E402
from hermes_plugins.defuzz.templates import TemplateSpec, load_templates  # noqa: E402
from tests.layered_placement_cases import (  # noqa: E402
    STAY,
    assert_shared_rules,
    assert_stays_in_both_modes,
    build_table,
    route_write,
    run_own_check_after_routed_writes,
    run_root_write_table,
    slow_skip_marker,
)
from tests.test_template_placement_rules import _cheap_scaffold  # noqa: E402

TEMPLATE_ID = "cpp-golden"
HAS_ADR_DIR = False

MOVED: tuple[tuple[str, str], ...] = (
    ("design-notes.md", "docs/design-notes.md"),
    ("BUILD_GUIDE.md", "docs/BUILD_GUIDE.md"),
    ("layering.md", "docs/layering.md"),
    ("ADR-0006-ports.md", "docs/ADR-0006-ports.md"),
    ("benchmark results.md", "docs/benchmark results.md"),
    ("PORTING.MD", "docs/PORTING.MD"),
    ("toolchain-notes.md", "docs/toolchain-notes.md"),
    ("test-strategy.md", "docs/test-strategy.md"),
    ("bootstrap.ps1", "scripts/bootstrap.ps1"),
    ("run-sanitizers.sh", "scripts/run-sanitizers.sh"),
)

# Build and tool configuration and dotfiles: never moved.
PROTECTED: tuple[str, ...] = (
    "CMakePresets.json",
    "CMakeUserPresets.json",
    "vcpkg.json",
    "vcpkg-configuration.json",
    "conanfile.txt",
    "conanfile.py",
    "conandata.yml",
    "CTestConfig.cmake",
    "CTestCustom.cmake",
    "CPackConfig.cmake",
    "compile_commands.json",
    "meson.build",
    "Makefile",
    ".clangd",
    ".clang-format-ignore",
    "CODEOWNERS.md",
    "NOTICE.md",
)

# No unambiguous home: left where they were written.
LEFT_ALONE: tuple[str, ...] = (
    "widget.cpp",
    "widget.hpp",
    "widget.h",
    "widget.cc",
    "widget.cxx",
    "widget_test.cpp",
    "test_widget.cpp",
    "widget_tests.cpp",
    "main.cpp",
    "FindWidget.cmake",
    "warnings.cmake",
    "sample.csv",
)

TEMPLATE_ROWS: tuple[tuple[str, str | None], ...] = (
    *MOVED,
    *((rel, STAY) for rel in PROTECTED),
    *((rel, STAY) for rel in LEFT_ALONE),
)

# Entries taken out of protected_root_files because the shared list keeps them.
REMOVED_PROTECTED_ENTRIES = (
    "GEMINI.md", "COPILOT.md", "CONVENTIONS.md", "AUTHORS.md", "CONTRIBUTORS.md",
    "MAINTAINERS.md", "GOVERNANCE.md", "SUPPORT.md", "HISTORY.md", "PULL_REQUEST_TEMPLATE.md",
    "ISSUE_TEMPLATE.md", "CODEOWNERS.md", "THIRD_PARTY_NOTICES.md", "CODEOWNERS",
    "CITATION.cff", "FUNDING.yml",
)


def _spec() -> TemplateSpec:
    return next(s for s in load_templates() if s.id == TEMPLATE_ID)


def test_rules_file_validates(tmp_path: Path) -> None:
    raw = json.loads((_spec().root / "rules.json").read_text(encoding="utf-8"))
    assert_shared_rules(raw, HAS_ADR_DIR)
    dest, db = _cheap_scaffold(tmp_path, _spec())
    trust = inspect_project_trust(dest, db_path=db)
    assert trust["trusted"] is True, trust["reason"]
    shipped = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    assert shipped.get("protected_root_files") == raw["protected_root_files"]


def test_root_write_table(tmp_path: Path) -> None:
    dest, db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    for rel in PROTECTED:
        assert is_protected_root_path(rel, proj_root=dest, rules_data=rules_data), rel
    moved = run_root_write_table(dest, db, rules_data, build_table(HAS_ADR_DIR, TEMPLATE_ROWS), "cpp")
    assert moved == 25 + len(MOVED)


def test_removed_protected_entries_still_stay_in_both_modes(tmp_path: Path) -> None:
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    for name in REMOVED_PROTECTED_ENTRIES:
        assert name not in rules_data["protected_root_files"], name
    assert_stays_in_both_modes(dest, rules_data, REMOVED_PROTECTED_ENTRIES)


def test_template_root_files_never_move(tmp_path: Path) -> None:
    dest, db = _cheap_scaffold(tmp_path, _spec())
    root_files = [p.name for p in dest.iterdir() if p.is_file()]
    assert {"CMakeLists.txt", "README.md", "AGENTS.md", "00-INDEX.md"} <= set(root_files)
    for idx, name in enumerate(sorted(root_files)):
        assert route_write(dest, db, name, f"cpp_root_{idx}") is None, name


@slow_skip_marker()
def test_project_check_passes_after_ten_routed_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_own_check_after_routed_writes(_spec(), tmp_path, monkeypatch, HAS_ADR_DIR, "cpp_ci")
