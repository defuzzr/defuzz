"""Root-write placement for the go-golden template.

Go ties a file to a package by its folder, so a loose ``*.go`` or ``*_test.go`` at
the root has no single right home and must stay where it was written. Only kinds
with one documented home (notes and diagrams in docs/, helper scripts in scripts/)
are moved. The shared block of cases lives in tests/layered_placement_cases.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.placer import _reset_notice_state_for_tests  # noqa: E402
from hermes_plugins.defuzz.rules import is_protected_root_path  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402
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

TEMPLATE_ID = "go-golden"
HAS_ADR_DIR = False

# Template rows, added to the shared block: (root write, expected final path or STAY)
TEMPLATE_ROWS: tuple[tuple[str, str | None], ...] = (
    ("gen-mocks.sh", "scripts/gen-mocks.sh"),
    # Go sources and tests: the package is ambiguous, so they stay.
    ("helper.go", STAY),
    ("ledger.go", STAY),
    ("doc.go", STAY),
    ("ledger_test.go", STAY),
    ("example_test.go", STAY),
    ("bench_test.go", STAY),
    ("tools.go", STAY),
    ("asm_amd64.s", STAY),
    # Go build and tool config stays at the root.
    ("go.work", STAY),
    ("go.work.sum", STAY),
    (".golangci.yaml", STAY),
    ("Makefile", STAY),
    ("GNUmakefile", STAY),
    ("Taskfile.yml", STAY),
    ("Taskfile.yaml", STAY),
    (".goreleaser.yaml", STAY),
    ("Dockerfile", STAY),
    ("NOTICE", STAY),
    # No documented home: other data and scripts stay.
    ("golden.txt", STAY),
    ("gen.py", STAY),
    ("config.yaml", STAY),
    (".env.example", STAY),
)

PROTECTED = ("go.work", "go.work.sum", "Makefile", "GNUmakefile", "Taskfile.yml", "Taskfile.yaml")

# Entries taken out of protected_root_files because the shared list keeps them.
REMOVED_PROTECTED_ENTRIES = (
    "TOOLS.lock", ".gitignore", ".worktreeinclude", "GEMINI.md", "COPILOT.md", "AUTHORS.md",
    "CONTRIBUTORS.md", "MAINTAINERS.md", "GOVERNANCE.md", "SUPPORT.md", "HISTORY.md",
    "PULL_REQUEST_TEMPLATE.md", "ISSUE_TEMPLATE.md", "CONVENTIONS.md", "NEWS.md",
)


def _spec():
    return next(s for s in load_templates() if s.id == TEMPLATE_ID)


def _raw_rules() -> dict:
    return json.loads((_spec().root / "rules.json").read_text(encoding="utf-8"))


def test_rules_file_declares_every_destination() -> None:
    data = _raw_rules()
    assert_shared_rules(data, HAS_ADR_DIR)
    for pr in data["placement_rules"]:
        assert ".go" not in pr["match_ext"], "Go files must never be routed"


def test_root_write_table(tmp_path: Path) -> None:
    dest, db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    for rel in PROTECTED:
        assert is_protected_root_path(rel, proj_root=dest, rules_data=rules_data), rel
    moved = run_root_write_table(dest, db, rules_data, build_table(HAS_ADR_DIR, TEMPLATE_ROWS), "go")
    assert moved == 26


def test_removed_protected_entries_still_stay_in_both_modes(tmp_path: Path) -> None:
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    for name in REMOVED_PROTECTED_ENTRIES:
        assert name not in rules_data["protected_root_files"], name
    assert_stays_in_both_modes(dest, rules_data, REMOVED_PROTECTED_ENTRIES)


def test_template_own_root_files_never_move(tmp_path: Path) -> None:
    _reset_notice_state_for_tests()
    dest, db = _cheap_scaffold(tmp_path, _spec())
    root_files = [p.name for p in dest.iterdir() if p.is_file()]
    assert "go.mod" in root_files and "README.md" in root_files
    for idx, name in enumerate(root_files):
        pre = route_write(dest, db, name, f"go_own_{idx}")
        assert pre is None, f"Template root file {name!r} was moved: {pre!r}"


@slow_skip_marker()
def test_project_check_passes_after_ten_routed_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_own_check_after_routed_writes(_spec(), tmp_path, monkeypatch, HAS_ADR_DIR, "go_ci")

