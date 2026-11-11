"""Table-driven placement proof and build-safety tests for bundled templates."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.placer import (  # noqa: E402
    _explicit_declared_dir_prefixes,
    _reset_notice_state_for_tests,
    inspect_project_trust,
    on_pre_tool_call,
    on_transform_tool_result,
)
from hermes_plugins.defuzz.rules import is_protected_root_path  # noqa: E402
from hermes_plugins.defuzz.templates import TemplateSpec, load_templates  # noqa: E402
from tests.template_lint_known import assert_lint_clean_or_known  # noqa: E402
from tests.toolchain_needs import check_tools, need, need_lint_tools  # noqa: E402

TEMPLATES_WITH_ADR_DIR: frozenset[str] = frozenset({"python-golden", "ts-node-golden"})

# 40 protected root build/manifest/lock/config/governance/CI paths (those a template already ships are skipped).
COMMON_PROTECTED_NEW_PATHS: tuple[str, ...] = (
    "Dockerfile",
    "Dockerfile.prod",
    "Containerfile",
    "docker-compose.yml",
    "compose.yaml",
    "Makefile",
    "Justfile",
    "Taskfile.yml",
    "CMakePresets.json",
    "CMakeUserPresets.json",
    "requirements.txt",
    "requirements-dev.txt",
    "setup.py",
    "setup.cfg",
    "ruff.toml",
    "pytest.ini",
    "mypy.ini",
    "package-lock.json",
    "yarn.lock",
    "tsconfig.build.json",
    "vite.config.ts",
    "eslint.config.mjs",
    "vitest.config.ts",
    "build.rs",
    "deny.toml",
    "Cross.toml",
    "go.work",
    "Directory.Packages.props",
    "ExtraSolution.sln",
    "ExtraProject.csproj",
    "build.gradle.kts",
    "README.rst",
    "LICENSE",
    "LICENSE.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    ".env.local",
    ".github/workflows/deploy.yml",
)

DECLARED_FOLDER_NEW_PATHS: dict[str, tuple[str, ...]] = {
    "cpp-golden": (
        "docs/architecture.md",
        "docs/sub/guide.md",
        "foundation/include/foundation/metrics.hpp",
        "foundation/src/metrics.cpp",
        "domain/include/domain/ledger.hpp",
        "domain/src/ledger.cpp",
        "adapters/include/adapters/cache.hpp",
        "adapters/src/cache.cpp",
        "apps/cli/src/flags.cpp",
        "tests/extra_check.cpp",
        "cmake/sanitizers.cmake",
        "docs/adr-draft.md",
    ),
    "dotnet-golden": (
        "docs/architecture.md",
        "docs/sub/guide.md",
        "foundation/Metrics.cs",
        "foundation/SpanHelper.cs",
        "domain/Ledger.cs",
        "domain/Policy.cs",
        "adapters/HttpAdapter.cs",
        "adapters/MemoryStore.cs",
        "apps/cli/Commands.cs",
        "apps/cli/Banner.cs",
        "xtask/ExtraCheck.cs",
        "docs/adr-draft.md",
    ),
    "go-golden": (
        "docs/architecture.md",
        "docs/sub/guide.md",
        "foundation/metrics.go",
        "foundation/metrics_test.go",
        "domain/ledger.go",
        "domain/ledger_test.go",
        "adapters/http_client.go",
        "adapters/http_client_test.go",
        "apps/cli/flags.go",
        "apps/cli/flags_test.go",
        "xtask/release.go",
        "docs/adr-draft.md",
    ),
    "python-golden": (
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "packages/foundation/proof-app-core/src/proof_app_core/metrics.py",
        "packages/foundation/proof-app-core/tests/test_metrics.py",
        "packages/domain/proof-app-accounts/src/proof_app_accounts/ledger.py",
        "packages/domain/proof-app-accounts/tests/test_ledger.py",
        "packages/adapters/proof-app-http-fastapi/src/proof_app_http_fastapi/middleware.py",
        "packages/adapters/tests/test_extra_contract.py",
        "packages/apps/proof-app-cli/src/proof_app_cli/commands.py",
        "tools/xtask/src/xtask/release.py",
        "templates/endpoint.py.tmpl",
        "componentize/custom.json",
    ),
    "rust-golden": (
        "docs/architecture.md",
        "docs/sub/guide.md",
        "foundation/src/metrics.rs",
        "foundation/tests/metrics_test.rs",
        "domain/src/ledger.rs",
        "domain/tests/ledger_test.rs",
        "adapters/src/http_client.rs",
        "adapters/tests/http_test.rs",
        "apps/cli/src/commands.rs",
        "apps/cli/tests/cli_smoke.rs",
        "xtask/src/release.rs",
        "docs/adr-draft.md",
    ),
    "ts-node-golden": (
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "packages/foundation/proof-app-core/src/metrics.ts",
        "packages/foundation/proof-app-core/src/metrics.test.ts",
        "packages/domain/proof-app-accounts/src/ledger.ts",
        "packages/domain/proof-app-accounts/src/ledger.test.ts",
        "packages/adapters/proof-app-http-hono/src/middleware.ts",
        "packages/adapters/proof-app-http-hono/src/middleware.test.ts",
        "packages/apps/proof-app-cli/src/commands.ts",
        "packages/apps/proof-app-server/src/routes.ts",
        "tools/xtask/release.ts",
        "templates/endpoint.ts.tmpl",
    ),
    "web-golden": (
        "docs/architecture.md",
        "docs/sub/guide.md",
        "src/pages/contact/index.html",
        "src/components/card.html",
        "src/components/card.ts",
        "src/styles/print.css",
        "src/lib/format.ts",
        "tests/unit/format.test.ts",
        "tests/e2e/contact.e2e.ts",
        "design/specs/home.md",
        "scripts/sitemap.ts",
        "tools/xtask/release.ts",
    ),
}

# Root files a template's own rules route somewhere (beyond the shared docs cases); they
# are taken out of UNROUTED_ROOT_NEW_PATHS for that template.
EXTRA_ROUTED_CASES: dict[str, tuple[tuple[str, str], ...]] = {
    "web-golden": (
        ("widget.test.ts", "tests/unit/widget.test.ts"),
        ("widget.spec.ts", "tests/unit/widget.spec.ts"),
    ),
    **{
        template_id: (
            ("deploy.sh", "scripts/deploy.sh"),
            ("setup.ps1", "scripts/setup.ps1"),
            ("guide.rst", "docs/guide.rst"),
            ("layers.mmd", "docs/layers.mmd"),
            ("TODO.md", "docs/TODO.md"),
            ("ROADMAP.md", "docs/ROADMAP.md"),
            (
                "0003-storage-choice.md",
                f"{'docs/adr' if template_id in TEMPLATES_WITH_ADR_DIR else 'docs'}/0003-storage-choice.md",
            ),
        )
        for template_id in (
            "python-golden",
            "rust-golden",
            "go-golden",
            "cpp-golden",
            "dotnet-golden",
            "ts-node-golden",
        )
    },
}

# An existing Markdown file under docs/ in each scaffolded template, used for the
# destination-name clash case.
CLASH_DOC_DEFAULT = "component-boundaries.md"
CLASH_DOC: dict[str, str] = {"web-golden": "accessibility.md"}

# 33 root-level files whose move could break imports/builds or guess nonexistent folders.
UNROUTED_ROOT_NEW_PATHS: tuple[str, ...] = (
    # Root test files across the template ecosystems (ambiguous package/crate/csproj or explicit CMake list)
    "test_widget.py",
    "widget_test.py",
    "widget.test.ts",
    "widget.spec.ts",
    "widget_test.go",
    "widget_test.rs",
    "widget_test.cpp",
    "WidgetTests.cs",
    # Root source, headers, benches, examples, type-tests, CMake/tmpl files
    "helper.py",
    "conftest.py",
    "testing.go",
    "main.go",
    "lib.rs",
    "bench_hash.rs",
    "example_cli.rs",
    "helper.ts",
    "index.test-d.ts",
    "helper.cpp",
    "helper.hpp",
    "Helper.cs",
    "FindExtra.cmake",
    "CTestConfig.cmake",
    "widget.py.tmpl",
    # Root scripts, binary/image assets, data tables, plain text, configs
    "deploy.sh",
    "setup.cmd",
    "seed.mjs",
    "logo.png",
    "diagram.svg",
    "model.glb",
    "seed.csv",
    "local.yaml",
    "notes.txt",
    "adr-0003-script.py",
)

# 11 tricky hidden and nested undeclared-folder paths (must never be pulled out of their folder).
HIDDEN_AND_NESTED_UNTOUCHED: tuple[str, ...] = (
    ".notes.md",
    ".adr-0003-secret.md",
    ".hidden_doc.md",
    "notes/rfc-01.md",
    "notes/adr-0003-cache.md",
    "experimental/README.md",
    "experimental/design.md",
    "sandbox/test_plan.md",
    "notes with spaces/plan.md",
    "笔记/说明.md",
    "other_service/package.json",
)


def _fixture_version(name: str, entry: dict) -> str:
    """A fixture tool that meets the floor it is asked about (the template's `minimum`, if any)."""
    del name
    return str(entry.get("version") or entry.get("minimum") or "1.0.0")


def _cheap_scaffold(
    tmp_path: Path, spec: TemplateSpec, answer=_fixture_version
) -> tuple[Path, Path]:
    db = tmp_path / "state.db"
    with mock.patch.object(
        scaffolder.toolchk,
        "probe",
        side_effect=lambda name, entry, *a, **kw: (answer(name, entry), "/fixture/tool"),
    ):
        proposal = scaffolder.propose(
            spec,
            "Proof App",
            {
                "building": spec.kind,
                "layout": spec.layout,
                "languages": list(spec.languages),
            },
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


# Templates whose creation preflight enforces a tool floor: a floor lock (cpp, dotnet, go) or `.nvmrc` (node).
TEMPLATES_WITH_ENFORCED_FLOOR: dict[str, dict[str, str]] = {
    "cpp-golden": {"clang": "14.0", "clang-format": "23.1", "clang-tidy": "23.1", "cmake": "3.20", "ninja": "1.10"},
    "dotnet-golden": {"dotnet": "10.0.100"},
    "go-golden": {"go": "1.22", "golangci-lint": "2.0.0"},
    "ts-node-golden": {"node": "24"},
    "web-golden": {"node": "24"},
}


def test_every_listed_floor_template_is_bundled() -> None:
    assert set(TEMPLATES_WITH_ENFORCED_FLOOR) <= {s.id for s in load_templates()}


@pytest.mark.parametrize(
    "spec",
    [s for s in load_templates() if s.id in TEMPLATES_WITH_ENFORCED_FLOOR],
    ids=lambda s: s.id,
)
def test_tool_older_than_a_template_floor_blocks_creation(tmp_path: Path, spec: TemplateSpec) -> None:
    """A fixture tool below a floor the template states is blocked at creation, for every template with a floor."""
    floored: dict[str, str] = {}

    def too_old(name: str, entry: dict) -> str:
        if entry.get("minimum"):
            floored[name] = str(entry["minimum"])
            return "0.0.1"
        return _fixture_version(name, entry)

    reports: list[dict] = []
    real_record = scaffolder.toolchk.record

    def keep_report(report: dict, directory):
        reports.append(dict(report))
        return real_record(report, directory)

    with pytest.raises(scaffolder.ScaffoldError) as excinfo, mock.patch.object(
        scaffolder.toolchk, "record", side_effect=keep_report
    ):
        _cheap_scaffold(tmp_path, spec, answer=too_old)
    assert floored, f"{spec.id} states no tool floor"
    for name, minimum in TEMPLATES_WITH_ENFORCED_FLOOR[spec.id].items():
        assert floored.get(name) == minimum, floored
    assert excinfo.value.reason == "preflight-failed"
    blocked = [line for report in reports for line in report.get("blocked") or []]
    for name, minimum in floored.items():
        assert any(f"{name}: found 0.0.1, need >= {minimum}" in line for line in blocked), blocked


def _expected_routed_cases(template_id: str) -> list[tuple[str, str]]:
    adr_dest = "docs/adr" if template_id in TEMPLATES_WITH_ADR_DIR else "docs"
    return [
        ("architecture.md", "docs/architecture.md"),
        ("DESIGN_NOTES.md", "docs/DESIGN_NOTES.md"),
        ("runbook.md", "docs/runbook.md"),
        ("test_plan.md", "docs/test_plan.md"),
        ("API_OVERVIEW.MD", "docs/API_OVERVIEW.MD"),
        ("setup-guide.md", "docs/setup-guide.md"),
        ("release notes 2026.md", "docs/release notes 2026.md"),
        ("架构说明.md", "docs/架构说明.md"),
        ("adr-0003-caching.md", f"{adr_dest}/adr-0003-caching.md"),
        ("ADR-0004-auth.md", f"{adr_dest}/ADR-0004-auth.md"),
    ]


@pytest.mark.parametrize("spec", load_templates(), ids=lambda s: s.id)
def test_bundled_templates_ship_explicit_root_only_rules_as_data(
    tmp_path: Path, spec: TemplateSpec
) -> None:
    raw_rules_file = spec.root / "rules.json"
    assert raw_rules_file.is_file(), f"Missing data-only rules file: {raw_rules_file}"
    raw_rules = json.loads(raw_rules_file.read_text(encoding="utf-8"))
    assert isinstance(raw_rules.get("declared_dirs"), list) and raw_rules["declared_dirs"]
    assert isinstance(raw_rules.get("placement_rules"), list) and raw_rules["placement_rules"]
    for pr in raw_rules["placement_rules"]:
        assert pr.get("source") == "explicit", f"Rule in {spec.id} missing source='explicit': {pr}"
        assert pr.get("root_only") is True, f"Rule in {spec.id} missing root_only=True: {pr}"
        assert isinstance(pr.get("reason"), str) and 10 <= len(pr["reason"]) <= 100

    dest, db = _cheap_scaffold(tmp_path, spec)
    trust = inspect_project_trust(dest, db_path=db)
    assert trust["trusted"] is True, trust["reason"]
    assert trust["mode"] == "declared_only"

    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    declared = _explicit_declared_dir_prefixes(rules_data)
    assert "docs" in declared
    if spec.id in TEMPLATES_WITH_ADR_DIR:
        assert "docs/adr" in declared

    shipped = rules_data["placement_rules"]
    assert shipped, f"Scaffolded {spec.id} has empty placement_rules"
    for pr in shipped:
        assert pr.get("source") == "explicit"
        assert pr.get("root_only") is True
        assert any(
            pr["dest_dir"] == d or pr["dest_dir"].startswith(d + "/") for d in declared
        )

    if spec.id == "ts-node-golden":
        for ts_prot in ("global.d.ts", "env.d.mts", "types.d.cts", "index.test-d.ts", "vitest.config.cts"):
            assert is_protected_root_path(ts_prot, proj_root=dest, rules_data=rules_data), (
                f"Expected {ts_prot!r} to be protected in ts-node-golden"
            )


@pytest.mark.parametrize("spec", load_templates(), ids=lambda s: s.id)
def test_per_template_placement_matrix_80_plus_writes(
    tmp_path: Path, spec: TemplateSpec
) -> None:
    _reset_notice_state_for_tests()
    dest, db = _cheap_scaffold(tmp_path, spec)
    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    reasons = {pr["reason"] for pr in rules_data["placement_rules"]}

    protected_cases: list[tuple[str, str | None, str]] = [
        (rel, None, "protected") for rel in COMMON_PROTECTED_NEW_PATHS if not (dest / rel).exists()
    ]
    ts_only_protected = ("global.d.ts", "env.d.mts", "types.d.cts", "vitest.config.cts", "index.test-d.ts")
    if spec.id == "ts-node-golden":
        protected_cases.extend((rel, None, "protected") for rel in ts_only_protected)

    declared_cases: list[tuple[str, str | None, str]] = [
        (rel, None, "declared_folder") for rel in DECLARED_FOLDER_NEW_PATHS[spec.id]
    ]
    extra_routed = EXTRA_ROUTED_CASES.get(spec.id, ())
    routed_cases: list[tuple[str, str | None, str]] = [
        (rel, expected, "routed") for rel, expected in (*_expected_routed_cases(spec.id), *extra_routed)
    ]
    extra_routed_names = {rel for rel, _ in extra_routed}
    unrouted_cases: list[tuple[str, str | None, str]] = [
        (rel, None, "unrouted")
        for rel in UNROUTED_ROOT_NEW_PATHS
        if not (spec.id == "ts-node-golden" and rel in ts_only_protected) and rel not in extra_routed_names
    ]
    tricky_cases: list[tuple[str, str | None, str]] = [
        (rel, None, "tricky_untouched") for rel in HIDDEN_AND_NESTED_UNTOUCHED
    ]

    # Destination name clashes: an existing docs/*.md file (and docs/adr/adr-clash.md)
    clash_doc = CLASH_DOC.get(spec.id, CLASH_DOC_DEFAULT)
    assert (dest / "docs" / clash_doc).is_file()
    clash_cases: list[tuple[str, str | None, str]] = [
        (clash_doc, None, "clash")
    ]
    if spec.id in TEMPLATES_WITH_ADR_DIR:
        (dest / "docs" / "adr" / "adr-0001-clash.md").write_text("# Existing\n", encoding="utf-8")
        clash_cases.append(("adr-0001-clash.md", None, "clash"))

    matrix = (
        protected_cases
        + declared_cases
        + routed_cases
        + unrouted_cases
        + tricky_cases
        + clash_cases
    )
    assert len(matrix) >= 80, f"Expected >= 80 simulated writes for {spec.id}, got {len(matrix)}"

    seen_inputs: set[str] = set()
    moved_count = 0
    protected_count = 0
    left_alone_count = 0

    for idx, (rel, expected_dest, category) in enumerate(matrix):
        assert rel not in seen_inputs, f"Duplicate matrix case {rel!r} in {spec.id}"
        seen_inputs.add(rel)
        target = dest / rel
        assert not target.exists(), f"Simulated new write {rel!r} already exists in {spec.id}"

        if category == "protected":
            assert is_protected_root_path(rel, proj_root=dest, rules_data=rules_data), (
                f"Matrix protected path {rel!r} was not recognized by is_protected_root_path in {spec.id}"
            )

        tc_id = f"{spec.id}_m_{idx}"
        pre = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(target), "content": "# Simulated\n"},
            tool_call_id=tc_id,
            db_path=db,
        )

        if expected_dest is None:
            assert pre is None, (
                f"{spec.id} [{category}]: {rel!r} should stay at {rel!r}, got {pre!r}"
            )
            if category == "protected":
                protected_count += 1
            else:
                left_alone_count += 1
        else:
            assert pre is not None and pre.get("action") == "modify", (
                f"{spec.id} [{category}]: expected {rel!r} -> {expected_dest!r}, got {pre!r}"
            )
            placed_full = Path(pre["args"]["path"])
            actual_rel = placed_full.relative_to(dest).as_posix()
            assert actual_rel == expected_dest, (
                f"{spec.id}: expected {rel!r} -> {expected_dest!r}, got {actual_rel!r}"
            )
            moved_count += 1

            # Verify truthful, single-line, length-capped redirect notice
            placed_full.parent.mkdir(parents=True, exist_ok=True)
            placed_full.write_text("# Simulated\n", encoding="utf-8")
            try:
                transformed = on_transform_tool_result(
                    tool_name="write_file",
                    args=pre["args"],
                    result=json.dumps({"verified": True, "resolved_path": str(placed_full)}),
                    tool_call_id=tc_id,
                )
                assert transformed is not None
                parsed_res = json.loads(transformed)
                notice = parsed_res["defuzz_notice"]
                assert expected_dest in notice
                assert any(r in notice for r in reasons), f"Notice missing rule reason: {notice!r}"
                assert "\n" not in notice
                assert len(notice) <= 600
            finally:
                placed_full.unlink(missing_ok=True)

    assert moved_count == len(routed_cases)
    assert moved_count + protected_count + left_alone_count == len(matrix)
    print(
        f"PROOF[{spec.id}]: total={len(matrix)} moved={moved_count} "
        f"left_alone={left_alone_count} protected={protected_count}"
    )


SAMPLE_FILE_BY_RULE_KIND: dict[str, tuple[str, str]] = {
    "docs": (
        "architecture-overview.md",
        "# Architecture Overview\n\nRouting build-safety verification note.\n",
    ),
    "adr": (
        "adr-0003-routing-safety.md",
        "# ADR 0003: Routing Safety\n\nVerified placement into docs/adr/.\n",
    ),
    "test": (
        "routing-safety.test.ts",
        'import { expect, it } from "vitest";\n\nit("adds two numbers", () => {\n  expect(1 + 1).toBe(2);\n});\n',
    ),
    "scripts": (
        "routing-safety.sh",
        "#!/bin/sh\necho ok\n",
    ),
}


@pytest.mark.skipif(os.environ.get("ADOPT_SKIP_SLOW") == "1", reason="ADOPT_SKIP_SLOW=1")
@pytest.mark.parametrize("spec", load_templates(), ids=lambda s: s.id)
def test_routed_files_pass_template_own_ci_and_defuzz_lint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spec: TemplateSpec
) -> None:
    """Route one real file of each shipped rule kind via hooks, then run the template's own CI."""
    from hermes_plugins.defuzz.linter import run_lint

    _reset_notice_state_for_tests()
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)

    need(*check_tools(spec))

    db_path = tmp_path / "state.db"
    proposal = scaffolder.propose(
        spec,
        "routing-ci-app",
        {
            "building": spec.kind,
            "layout": spec.layout,
            "languages": list(spec.languages),
        },
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging",
    )
    accepted = scaffolder.accept(
        proposal,
        register=lambda *_: json.dumps({"success": True, "id": "routing-ci-app"}),
        db_path=db_path,
        timeout_s=900,
    )
    assert accepted.repos[0]["check"] == "ok", accepted.repos[0]
    repo = Path(accepted.repos[0]["path"])

    rules_data = json.loads((repo / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    shipped_rules = [
        pr
        for pr in rules_data["placement_rules"]
        if isinstance(pr, dict) and pr.get("source") != "fallback"
    ]
    assert shipped_rules, f"Expected explicit rules in {spec.id}"

    for idx, pr in enumerate(shipped_rules):
        kind = pr["kind"]
        assert kind in SAMPLE_FILE_BY_RULE_KIND, (
            f"Add a real valid sample in SAMPLE_FILE_BY_RULE_KIND for rule kind {kind!r} ({spec.id})"
        )
        root_filename, valid_content = SAMPLE_FILE_BY_RULE_KIND[kind]
        tc_id = f"ci_{spec.id}_{idx}"
        pre = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(repo / root_filename), "content": valid_content},
            tool_call_id=tc_id,
            db_path=db_path,
        )
        assert pre is not None and pre.get("action") == "modify", (
            f"Expected {root_filename!r} to be routed for rule {kind!r} in {spec.id}"
        )
        placed_path = Path(pre["args"]["path"])
        expected_rel = f"{pr['dest_dir']}/{root_filename}"
        assert placed_path.relative_to(repo).as_posix() == expected_rel
        placed_path.write_text(valid_content, encoding="utf-8")

        transformed = on_transform_tool_result(
            tool_name="write_file",
            args=pre["args"],
            result=json.dumps({"verified": True, "resolved_path": str(placed_path)}),
            tool_call_id=tc_id,
        )
        assert transformed is not None
        assert pr["reason"] in json.loads(transformed)["defuzz_notice"]

    check_spec = spec.repos[0].check
    assert check_spec is not None
    check_cwd = repo if check_spec.cwd == "." else (repo / check_spec.cwd)
    for command in [list(cmd) for cmd in check_spec.ci_commands()]:
        proc = subprocess.run(
            command,
            cwd=check_cwd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        assert proc.returncode == 0, f"{spec.id} {command}\n{proc.stdout}\n{proc.stderr}"

    lint_report = run_lint(repo, env=dict(os.environ), db_path=db_path)
    need_lint_tools(lint_report)
    assert_lint_clean_or_known(spec.id, lint_report)

