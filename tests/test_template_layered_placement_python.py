"""Root-write placement table for the python-golden layered template.

python-golden is a uv workspace with layered packages (foundation, domain,
adapters, apps), each with its own tests. A loose root test or source file
cannot be given a layer by its name, and the template has no assets folder, so
those writes stay where they were written. Notes and diagrams go to docs/,
decision records to docs/adr/ and shell scripts to scripts/. The shared block
of cases lives in tests/layered_placement_cases.py.
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
from hermes_plugins.defuzz.rules import _validate_glob_patterns  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402
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

TEMPLATE_ID = "python-golden"
HAS_ADR_DIR = True

# Template rows, added to the shared block: (root write, expected final path or STAY)
TEMPLATE_ROWS: tuple[tuple[str, str | None], ...] = (
    ("overview.md", "docs/overview.md"),
    ("PLAN.md", "docs/PLAN.md"),
    ("adr-0007-queue.md", "docs/adr/adr-0007-queue.md"),
    ("0042-retry-policy.md", "docs/adr/0042-retry-policy.md"),
    # Tests: every package has its own tests/ folder, so the layer is unknown.
    ("test_widget_layer.py", STAY),
    ("accounts_test.py", STAY),
    ("test_http_contract_extra.py", STAY),
    ("conftest.py", STAY),
    # Sources: no name tells foundation, domain, adapters or apps apart.
    ("ledger.py", STAY),
    ("main.py", STAY),
    ("__init__.py", STAY),
    ("__main__.py", STAY),
    ("models.pyi", STAY),
    ("py.typed", STAY),
    ("settings.py", STAY),
    ("component.py.tmpl", STAY),
    # Python automation is code: tools/ is the xtask package, not a dump.
    ("seed_db.py", STAY),
    # Assets and data: the template has no assets or fixtures folder.
    ("sample.json", STAY),
    ("fixtures.yaml", STAY),
    # Build, tool and governance files that must stay at the root.
    ("pyproject.toml", STAY),
    ("uv.lock", STAY),
    ("uv.toml", STAY),
    (".python-version", STAY),
    ("NOTICE", STAY),
    ("ruff.toml", STAY),
    ("mypy.ini", STAY),
    ("noxfile.py", STAY),
    ("tox.ini", STAY),
    ("requirements-dev.txt", STAY),
    ("Makefile", STAY),
    ("Dockerfile", STAY),
    (".pre-commit-config.yaml", STAY),
    ("THEMING.md", STAY),
)

# Files the template itself ships at the root: they stay too.
SHIPPED_ROOT_STAYS = ("README.md", "COMPONENTS.md", "CONTRIBUTING.md", "00-INDEX.md", ".env.example")

# Entries taken out of protected_root_files because the shared list keeps them.
REMOVED_PROTECTED_ENTRIES = (
    "00-INDEX.md", "COMPONENTS.md", "CONTRIBUTING.md", ".env.example", ".worktreeinclude",
    "GEMINI.md", "COPILOT.md", "AUTHORS.md", "CONTRIBUTORS.md", "MAINTAINERS.md",
    "GOVERNANCE.md", "SUPPORT.md", "HISTORY.md", "NEWS.md", "CONVENTIONS.md", "UPGRADING.md",
    "PULL_REQUEST_TEMPLATE.md", "ISSUE_TEMPLATE.md",
)


def _spec():
    return next(s for s in load_templates() if s.id == TEMPLATE_ID)


def _rules_file() -> dict:
    return json.loads((_spec().root / "rules.json").read_text(encoding="utf-8"))


def test_rules_file_validates_and_reasons_are_plain() -> None:
    data = _rules_file()
    assert _is_valid_adopted_rules({**data, "schema": 1, "project_slug": "proof-app"})
    for pr in data["placement_rules"]:
        _validate_glob_patterns(pr.get("match_glob"), "match_glob")
    _validate_glob_patterns(data["protected_root_files"], "protected_root_files")
    assert_shared_rules(data, HAS_ADR_DIR)
    assert "RELEASING.md" not in data["protected_root_files"]


def test_root_write_table(tmp_path: Path) -> None:
    dest, db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    moved = run_root_write_table(dest, db, rules_data, build_table(HAS_ADR_DIR, TEMPLATE_ROWS), "pyplace")
    assert moved == 29
    for name in SHIPPED_ROOT_STAYS:
        assert (dest / name).is_file(), name
        assert resolve_placement_for_new_path(dest, name, rules_data, mode="declared_only") is None


def test_removed_protected_entries_still_stay_in_both_modes(tmp_path: Path) -> None:
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    for name in REMOVED_PROTECTED_ENTRIES:
        assert name not in rules_data["protected_root_files"], name
    assert_stays_in_both_modes(dest, rules_data, REMOVED_PROTECTED_ENTRIES)


def test_template_root_files_are_never_moved(tmp_path: Path) -> None:
    dest, _db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    root_files = sorted(
        p.name for p in (_spec().root / "tmpl_prefix").iterdir() if p.is_file()
    )
    assert "pyproject.toml" in root_files and "README.md" in root_files
    for name in root_files:
        got = resolve_placement_for_new_path(dest, name, rules_data, mode="declared_only")
        assert got is None, f"template root file {name!r} would move: {got!r}"


@slow_skip_marker()
def test_project_check_passes_after_ten_routed_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_own_check_after_routed_writes(_spec(), tmp_path, monkeypatch, HAS_ADR_DIR, "pyci")
