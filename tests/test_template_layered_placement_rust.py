"""Root-write placement table for the rust-golden template.

The workspace has one home per crate (foundation, domain, adapters, apps/cli,
xtask), so a loose Rust source or test at the root has no single right crate:
it must stay where it was written. Notes and diagrams go to docs/, shell scripts
to scripts/. Build and tool configuration stays at the root. The shared block of
cases lives in tests/layered_placement_cases.py.
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
    build_table,
    route_write,
    run_own_check_after_routed_writes,
    run_root_write_table,
    slow_skip_marker,
)
from tests.test_template_placement_rules import _cheap_scaffold  # noqa: E402

TEMPLATE_ID = "rust-golden"
HAS_ADR_DIR = False

# Template rows, added to the shared block: (root write, expected final path or STAY)
TEMPLATE_ROWS: tuple[tuple[str, str | None], ...] = (
    ("crate-map.md", "docs/crate-map.md"),
    ("msrv-policy.md", "docs/msrv-policy.md"),
    ("release.sh", "scripts/release.sh"),
    ("bump.ps1", "scripts/bump.ps1"),
    # Cargo, toolchain and lint configuration stays at the root
    ("build.rs", STAY),
    ("deny.toml", STAY),
    ("Cross.toml", STAY),
    ("release.toml", STAY),
    ("cliff.toml", STAY),
    ("typos.toml", STAY),
    ("_typos.toml", STAY),
    ("taplo.toml", STAY),
    ("dist-workspace.toml", STAY),
    ("rust-toolchain", STAY),
    (".rustfmt.toml", STAY),
    (".clippy.toml", STAY),
    (".cargo/audit.toml", STAY),
    ("CONTRIBUTING.md", STAY),
    ("LICENSE-MIT", STAY),
    ("LICENSE-APACHE", STAY),
    ("NOTICE", STAY),
    # Rust sources and tests: the crate is ambiguous, so they stay
    ("main.rs", STAY),
    ("ledger.rs", STAY),
    ("test_ledger.rs", STAY),
    ("integration_tests.rs", STAY),
    ("bench_ledger.rs", STAY),
    ("example_cli.rs", STAY),
    ("mod.rs", STAY),
    # Other automation, assets and data: no folder for them
    ("gen_fixtures.py", STAY),
    ("sample.csv", STAY),
    ("config.yaml", STAY),
)


def _spec() -> TemplateSpec:
    return next(s for s in load_templates() if s.id == TEMPLATE_ID)


def test_rules_file_validates_and_is_root_only(tmp_path: Path) -> None:
    raw = json.loads((_spec().root / "rules.json").read_text(encoding="utf-8"))
    dest, db = _cheap_scaffold(tmp_path, _spec())
    trust = inspect_project_trust(dest, db_path=db)
    assert trust["trusted"] is True and trust["mode"] == "declared_only", trust["reason"]
    assert_shared_rules(raw, HAS_ADR_DIR)
    for name in ("Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml",
                 "clippy.toml", "rustfmt.toml", "deny.toml"):
        assert name in raw["protected_root_files"]


def test_root_write_table(tmp_path: Path) -> None:
    dest, db = _cheap_scaffold(tmp_path, _spec())
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    table = build_table(HAS_ADR_DIR, TEMPLATE_ROWS)
    moved = run_root_write_table(dest, db, rules_data, table, "rust_place")
    assert moved == 29
    # Every protected entry is recognised by the shared check.
    for rel, expected in TEMPLATE_ROWS:
        if expected is STAY and "/" not in rel and rel.endswith(".toml"):
            assert is_protected_root_path(rel, proj_root=dest, rules_data=rules_data), rel


def test_no_rule_moves_a_file_the_template_ships_at_its_root(tmp_path: Path) -> None:
    spec = _spec()
    dest, db = _cheap_scaffold(tmp_path, spec)
    shipped = sorted(p.name for p in (spec.root / "tmpl_prefix").iterdir() if p.is_file())
    assert "Cargo.toml" in shipped and "00-INDEX.md" in shipped
    for idx, name in enumerate(shipped):
        target = dest / name
        pre = route_write(dest, db, name, f"rust_own_{idx}", target.read_text(encoding="utf-8"))
        assert pre is None, f"{name!r} must stay at the root, got {pre!r}"


@slow_skip_marker()
def test_project_passes_own_check_after_ten_routed_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_own_check_after_routed_writes(_spec(), tmp_path, monkeypatch, HAS_ADR_DIR, "rust_ci")
