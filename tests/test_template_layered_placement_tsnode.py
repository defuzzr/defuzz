"""Root-write placement table for the ts-node-golden layered template.

Notes and diagrams (docs/), decision records (docs/adr/) and shell scripts
(scripts/) have one clear home. TypeScript sources, tests and assets belong to a
layered package that a file name alone cannot pick, so they must stay where they
were written. The shared block of cases lives in tests/layered_placement_cases.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.rules import is_protected_root_path, validate_rules_spec  # noqa: E402
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

TEMPLATE_ID = "ts-node-golden"
HAS_ADR_DIR = True

MOVED: tuple[tuple[str, str], ...] = (
    ("DESIGN_NOTES.md", "docs/DESIGN_NOTES.md"),
    ("api-overview.MD", "docs/api-overview.MD"),
    ("release notes 2026.md", "docs/release notes 2026.md"),
    ("layer-rules.md", "docs/layer-rules.md"),
    ("adr-0003-caching.md", "docs/adr/adr-0003-caching.md"),
    ("0042-retry-policy.md", "docs/adr/0042-retry-policy.md"),
    ("release.ps1", "scripts/release.ps1"),
)

STAYS_PROTECTED: tuple[str, ...] = (
    # Workspace, compiler, lint and test configuration.
    "tsconfig.build.json",
    "tsconfig.test.json",
    "vitest.config.ts",
    "vitest.config.mts",
    "vitest.workspace.ts",
    "pnpm-workspace.yml",
    "biome.jsonc",
    ".node-version",
    "package-lock.json",
    "global.d.ts",
    "index.test-d.ts",
)

# No single package or layer can be picked from the name: leave them in place.
STAYS_AMBIGUOUS: tuple[str, ...] = (
    "main.ts",
    "index.ts",
    "ledger.mts",
    "config.cts",
    "widget.spec.ts",
    "ledger.test.mts",
    "legacy.js",
    "accounts.json",
    "component.ts.tmpl",
)

TEMPLATE_ROWS: tuple[tuple[str, str | None], ...] = (
    *MOVED,
    *((rel, STAY) for rel in STAYS_PROTECTED + STAYS_AMBIGUOUS),
)

# Entries taken out of protected_root_files because the shared list keeps them.
REMOVED_PROTECTED_ENTRIES = (
    "GEMINI.md", "COPILOT.md", "AUTHORS.md", "CONTRIBUTORS.md", "MAINTAINERS.md",
    "GOVERNANCE.md", "SUPPORT.md", "HISTORY.md", "PULL_REQUEST_TEMPLATE.md",
)


def _scaffold(tmp_path: Path, spec: TemplateSpec) -> tuple[Path, Path]:
    db = tmp_path / "state.db"
    with mock.patch.object(
        scaffolder.toolchk,
        "probe",
        side_effect=lambda name, entry, *a, **kw: ("99.0.0", "/fixture/tool"),
    ):
        proposal = scaffolder.propose(
            spec,
            "Proof App",
            {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
            dest_root=tmp_path / "projects",
            staging_parent=tmp_path / "staging",
            db_path=db,
        )
        try:
            for plan in proposal.repos:
                plan.check = None
            accepted = scaffolder.accept(
                proposal,
                register=lambda name, path: json.dumps({"success": True, "id": name}),
                db_path=db,
                remember_options=False,
            )
        finally:
            scaffolder.discard(proposal)
    return Path(accepted.repos[0]["path"]), db


def _spec() -> TemplateSpec:
    return next(s for s in load_templates() if s.id == TEMPLATE_ID)


def _rules(dest: Path) -> dict:
    return json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))


def test_rules_file_validates_and_reasons_are_plain(tmp_path: Path) -> None:
    raw = json.loads((_spec().root / "rules.json").read_text(encoding="utf-8"))
    dest, _ = _scaffold(tmp_path, _spec())
    validate_rules_spec(_rules(dest))
    assert_shared_rules(raw, HAS_ADR_DIR)


def test_root_write_table(tmp_path: Path) -> None:
    dest, db = _scaffold(tmp_path, _spec())
    rules_data = _rules(dest)
    for rel in STAYS_PROTECTED:
        assert is_protected_root_path(rel, proj_root=dest, rules_data=rules_data), rel
    moved = run_root_write_table(dest, db, rules_data, build_table(HAS_ADR_DIR, TEMPLATE_ROWS), "tsnode")
    assert moved == 25 + len(MOVED)


def test_removed_protected_entries_still_stay_in_both_modes(tmp_path: Path) -> None:
    dest, _db = _scaffold(tmp_path, _spec())
    rules_data = _rules(dest)
    for name in REMOVED_PROTECTED_ENTRIES:
        assert name not in rules_data["protected_root_files"], name
    assert_stays_in_both_modes(dest, rules_data, REMOVED_PROTECTED_ENTRIES)


def test_template_root_files_are_never_moved(tmp_path: Path) -> None:
    spec = _spec()
    dest, db = _scaffold(tmp_path, spec)
    names = {p.name for p in (spec.root / "tmpl_prefix").iterdir() if p.is_file()}
    names |= {p.name for p in dest.iterdir() if p.is_file()}
    assert {"README.md", "00-INDEX.md", "package.json", "pnpm-lock.yaml", "biome.json"} <= names
    for idx, name in enumerate(sorted(names)):
        pre = route_write(dest, db, name, f"tsnode_root_{idx}")
        assert pre is None, f"template root file {name!r} would be moved: {pre!r}"


@slow_skip_marker()
def test_project_check_passes_after_ten_routed_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_own_check_after_routed_writes(_spec(), tmp_path, monkeypatch, HAS_ADR_DIR, "tsnode_ci")
