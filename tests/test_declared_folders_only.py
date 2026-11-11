"""Tests for 'declared folders only' placement mode, protected root table, and template auto-trust."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import placer  # noqa: E402
from hermes_plugins.defuzz import rules as rules_mod  # noqa: E402
from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.placer import (  # noqa: E402
    _reset_notice_state_for_tests,
    inspect_project_trust,
    on_pre_tool_call,
    on_transform_tool_result,
    resolve_placement_for_new_path,
    trust_project,
)
from hermes_plugins.defuzz.rules import (  # noqa: E402
    PROTECTED_ROOT_FILES,
    PROTECTED_ROOT_TABLE,
    extract_manifest_entry_files,
    is_protected_root_path,
    validate_rules_spec,
)
from hermes_plugins.defuzz.safety import SafetyError  # noqa: E402
from hermes_plugins.defuzz.state_store import get_project  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402


def _fixture_version(entry: dict) -> str:
    """A fixture tool that meets the template's floor (`minimum`), else its locked version."""
    from hermes_plugins.defuzz.toolchk import version_below

    version = str(entry.get("version") or "1.0.0")
    minimum = entry.get("minimum")
    if minimum and version_below(version, str(minimum)):
        return str(minimum)
    return version


def test_protected_root_table_is_structured_data_and_covers_required_ecosystems(tmp_path: Path) -> None:
    assert isinstance(PROTECTED_ROOT_TABLE, tuple)
    assert len(PROTECTED_ROOT_TABLE) >= 6
    for row in PROTECTED_ROOT_TABLE:
        assert isinstance(row, dict)
        assert row.get("category") and row.get("description")

    # Every legacy PROTECTED_ROOT_FILES item is covered by the table
    for legacy_name in PROTECTED_ROOT_FILES:
        assert is_protected_root_path(legacy_name), f"Legacy protected file not covered: {legacy_name}"

    must_protect = (
        # Known misplacement regressions (build/manifest/config at root)
        "Dockerfile",
        "Dockerfile.prod",
        "docker-compose.yml",
        "docker-compose.dev.yaml",
        "Makefile",
        "CMakeLists.txt",
        "build.rs",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "Demo.sln",
        "Demo.csproj",
        "Directory.Build.props",
        "Directory.Build.targets",
        "NuGet.Config",
        "global.json",
        "go.mod",
        "go.sum",
        "go.work",
        "requirements.txt",
        "requirements-dev.txt",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "rustfmt.toml",
        "clippy.toml",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "yarn.lock",
        "tsconfig.json",
        "tsconfig.base.json",
        "biome.json",
        # Dotfiles and CI folders
        ".gitignore",
        ".editorconfig",
        ".env.example",
        ".npmrc",
        ".nvmrc",
        ".clang-format",
        ".clang-tidy",
        ".golangci.yml",
        ".worktreeinclude",
        ".github/workflows/ci.yml",
        ".gitlab/ci.yml",
        ".circleci/config.yml",
        # Root governance & metadata
        "README",
        "README.md",
        "README.rst",
        "LICENSE",
        "LICENSE.txt",
        "AGENTS.md",
        "TOOLS.lock",
        "CONTRIBUTING.md",
        "COMPONENTS.md",
        "00-INDEX.md",
    )
    for rel in must_protect:
        assert is_protected_root_path(rel, proj_root=tmp_path), f"Expected protected root path: {rel}"

    # Ordinary loose files at root are NOT protected by default
    for ordinary in ("design-notes.md", "architecture-plan.md", "diagram.svg", "scratch_helper.py", "sample.csv"):
        assert not is_protected_root_path(ordinary, proj_root=tmp_path), f"Unexpectedly protected: {ordinary}"


def test_manifest_entry_files_and_rules_json_extensions_are_protected(tmp_path: Path) -> None:
    # 1. Python pyproject.toml script & py-modules entry files
    py_proj = tmp_path / "py_proj"
    py_proj.mkdir()
    (py_proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n'
        '[project.scripts]\ndemo = "main:run"\n'
        '[tool.setuptools]\npy-modules = ["cli_entry"]\n',
        encoding="utf-8",
    )
    assert {"main.py", "cli_entry.py"} <= extract_manifest_entry_files(py_proj)
    assert is_protected_root_path("main.py", proj_root=py_proj)
    assert is_protected_root_path("cli_entry.py", proj_root=py_proj)
    assert not is_protected_root_path("other_script.py", proj_root=py_proj)

    # 2. Node package.json main / bin / exports entry files
    js_proj = tmp_path / "js_proj"
    js_proj.mkdir()
    (js_proj / "package.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "main": "./server.mjs",
                "bin": {"demo-cli": "cli.js"},
                "exports": {".": {"default": "./index.mjs"}},
            }
        ),
        encoding="utf-8",
    )
    assert {"server.mjs", "cli.js", "index.mjs"} <= extract_manifest_entry_files(js_proj)
    assert is_protected_root_path("server.mjs", proj_root=js_proj)
    assert is_protected_root_path("cli.js", proj_root=js_proj)
    assert is_protected_root_path("index.mjs", proj_root=js_proj)

    # 3. Rust Cargo.toml custom build script and root bin path
    rs_proj = tmp_path / "rs_proj"
    rs_proj.mkdir()
    (rs_proj / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nbuild = "codegen.rs"\n'
        '[[bin]]\nname = "demo"\npath = "main.rs"\n',
        encoding="utf-8",
    )
    assert {"codegen.rs", "main.rs"} <= extract_manifest_entry_files(rs_proj)
    assert is_protected_root_path("codegen.rs", proj_root=rs_proj)
    assert is_protected_root_path("main.rs", proj_root=rs_proj)

    # 4. Project extension via rules.json protected_root_files
    validated = validate_rules_spec(
        {
            "project_slug": "demo",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
            "folder_rules": [],
            "placement_rules": [],
            "ignore_patterns": [],
            "lfs_patterns": [],
            "protected_root_files": ["CustomRunner.py", "bench-*.txt"],
        }
    )
    assert validated["protected_root_files"] == ["CustomRunner.py", "bench-*.txt"]
    assert is_protected_root_path("CustomRunner.py", proj_root=tmp_path, rules_data=validated)
    assert is_protected_root_path("bench-smoke.txt", proj_root=tmp_path, rules_data=validated)
    assert not is_protected_root_path("CustomRunner.py", proj_root=tmp_path, rules_data={})


@pytest.mark.parametrize("spec", load_templates(), ids=lambda s: s.id)
def test_every_bundled_template_root_files_are_covered(tmp_path: Path, spec) -> None:
    assert spec.repos, f"Template {spec.id} has no repos"
    # Check raw template repo root entries
    for repo_spec in spec.repos:
        raw_repo = spec.root / repo_spec.name
        for entry in sorted(raw_repo.iterdir()):
            if entry.is_file():
                assert is_protected_root_path(entry.name, proj_root=raw_repo), (
                    f"Bundled template {spec.id} raw root file {entry.name!r} is not covered by PROTECTED_ROOT_TABLE"
                )
            elif entry.is_dir() and entry.name.startswith("."):
                assert is_protected_root_path(f"{entry.name}/probe", proj_root=raw_repo), (
                    f"Bundled template {spec.id} raw dot-dir {entry.name!r} is not covered by PROTECTED_ROOT_TABLE"
                )

    # Also check scaffolded root files after substitution + _generate_scaffold_context
    with mock.patch.object(
        scaffolder.toolchk,
        "probe",
        side_effect=lambda name, entry, *a, **kw: (_fixture_version(entry), "/fixture/tool"),
    ):
        proposal = scaffolder.propose(
            spec,
            "Root Check App",
            {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
            dest_root=tmp_path / "projects",
            staging_parent=tmp_path / "staging",
            db_path=tmp_path / "state.db",
        )
        try:
            for plan in proposal.repos:
                plan.check = None
            accepted = scaffolder.accept(
                proposal,
                register=lambda name, path: json.dumps({"success": True, "id": name}),
                db_path=tmp_path / "state.db",
                remember_options=False,
            )
            for repo_info in accepted.repos:
                dest = Path(repo_info["path"])
                rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
                for entry in sorted(dest.iterdir()):
                    if entry.is_file():
                        assert is_protected_root_path(entry.name, proj_root=dest, rules_data=rules_data), (
                            f"Scaffolded template {spec.id} root file {entry.name!r} is not covered"
                        )
                    elif entry.is_dir() and entry.name.startswith("."):
                        assert is_protected_root_path(f"{entry.name}/probe", proj_root=dest, rules_data=rules_data), (
                            f"Scaffolded template {spec.id} dot-dir {entry.name!r} is not covered"
                        )
        finally:
            scaffolder.discard(proposal)


def test_fallback_rules_are_marked_fallback_while_user_rules_stay_explicit() -> None:
    fb = rules_mod.build_deterministic_fallback_rules(
        {"dir_summaries": {".": {}, "docs": {}, "packages": {}}}
    )
    assert fb["placement_rules"]
    for pr in fb["placement_rules"]:
        assert pr.get("source") == "fallback", f"Fallback rule missing source='fallback': {pr}"

    by_dir = {d["dir"]: d for d in fb["declared_dirs"]}
    assert by_dir["docs"].get("source") != "fallback"
    assert by_dir["packages"].get("source") != "fallback"
    assert by_dir["assets"].get("source") == "fallback"
    assert by_dir["_inbox"].get("source") == "fallback"
    assert by_dir["_archive"].get("source") == "fallback"

    # Explicit user/template rules validated by validate_rules_spec do NOT get source='fallback'
    explicit = validate_rules_spec(
        {
            "project_slug": "demo",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
            "folder_rules": [],
            "placement_rules": [
                {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
            ],
            "ignore_patterns": [],
            "lfs_patterns": [],
        }
    )
    assert explicit["placement_rules"][0].get("source") is None


def _write_project_rules(proj: Path, rules_payload: dict) -> Path:
    (proj / ".adopt").mkdir(parents=True, exist_ok=True)
    for d in rules_payload.get("declared_dirs") or ():
        if isinstance(d, dict) and d.get("dir") and d.get("source") != "fallback":
            (proj / str(d["dir"])).mkdir(parents=True, exist_ok=True)
    rules_file = proj / ".adopt" / "rules.json"
    rules_file.write_text(json.dumps(rules_payload, indent=2) + "\n", encoding="utf-8")
    return rules_file


def test_trust_mode_storage_manual_defaults_and_hash_mismatch(tmp_path: Path) -> None:
    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"
    proj = tmp_path / "proj_trust"
    _write_project_rules(
        proj,
        {
            "schema": 1,
            "schema_version": 1,
            "project_slug": "proj-trust",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
            "folder_rules": [],
            "placement_rules": [],
            "ignore_patterns": [],
            "lfs_patterns": [],
        },
    )

    # Default manual trust -> full mode
    res_full = trust_project(proj, db_path=db)
    assert res_full["trusted"] is True
    assert res_full["mode"] == "full"
    info_full = inspect_project_trust(proj, db_path=db)
    assert info_full["trusted"] is True
    assert info_full["mode"] == "full"
    assert get_project(proj, db_path=db)["trust_mode"] == "full"

    # Explicit --declared-only flag -> declared_only mode
    res_decl = trust_project(proj, declared_only=True, db_path=db)
    assert res_decl["mode"] == "declared_only"
    info_decl = inspect_project_trust(proj, db_path=db)
    assert info_decl["trusted"] is True
    assert info_decl["mode"] == "declared_only"
    assert get_project(proj, db_path=db)["trust_mode"] == "declared_only"

    # Explicit mode="full" upgrades back to full
    assert trust_project(proj, mode="full", db_path=db)["mode"] == "full"
    assert inspect_project_trust(proj, db_path=db)["mode"] == "full"

    # Re-trust in declared_only, then edit rules.json -> hash mismatch drops trust
    trust_project(proj, mode="declared_only", db_path=db)
    rules_path = proj / ".adopt" / "rules.json"
    edited = json.loads(rules_path.read_text(encoding="utf-8"))
    edited["project_slug"] = "proj-trust-edited"
    rules_path.write_text(json.dumps(edited, indent=2) + "\n", encoding="utf-8")

    info_after_edit = inspect_project_trust(proj, db_path=db)
    assert info_after_edit["trusted"] is False
    assert info_after_edit["mode"] is None
    assert "hash mismatch" in info_after_edit["reason"].lower()

    # Invalid mode argument raises SafetyError
    with pytest.raises(SafetyError):
        trust_project(proj, mode="unknown_mode", db_path=db)
    with pytest.raises(SafetyError):
        trust_project(proj, mode="full", declared_only=True, db_path=db)

    # Corrupt trust_mode stored directly in SQLite fails closed (untrusted)
    import sqlite3
    from contextlib import closing

    trust_project(proj, declared_only=True, db_path=db)
    with closing(sqlite3.connect(str(db))) as conn:
        with conn:
            conn.execute("UPDATE projects SET trust_mode = 'corrupt_mode'")
    corrupt_info = inspect_project_trust(proj, db_path=db)
    assert corrupt_info["trusted"] is False
    assert corrupt_info["mode"] is None


def test_declared_only_mode_redirects_only_explicit_rules_and_never_protected_roots(tmp_path: Path) -> None:
    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"

    # 1. Project with fallback rules (like build_deterministic_fallback_rules): zero redirects!
    fb_proj = tmp_path / "fb_proj"
    fb_proj.mkdir()
    (fb_proj / "docs").mkdir()
    fb_rules = rules_mod.build_deterministic_fallback_rules(
        {"dir_summaries": {".": {}, "docs": {}, "packages": {}}}
    )
    fb_rules["project_slug"] = "fb-proj"
    _write_project_rules(fb_proj, fb_rules)
    trust_project(fb_proj, declared_only=True, db_path=db)

    for rel in ("Dockerfile", "build.rs", "requirements.txt", "main.py", "notes.md", "mystery.xyz"):
        assert (
            on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(fb_proj / rel), "content": "x"},
                db_path=db,
            )
            is None
        ), f"Fallback rule must never redirect {rel!r} in declared_only mode"

    # 2. Project with broad explicit rules + glob rule + manifest entry + undeclared rule target
    exp_proj = tmp_path / "exp_proj"
    exp_proj.mkdir()
    (exp_proj / "pyproject.toml").write_text(
        '[project]\nname = "exp"\nversion = "0.1.0"\n[project.scripts]\nexp = "main:cli"\n',
        encoding="utf-8",
    )
    _write_project_rules(
        exp_proj,
        {
            "schema": 1,
            "schema_version": 1,
            "project_slug": "exp-proj",
            "declared_dirs": [
                {"dir": "docs", "summary": "documentation", "why": "architecture and plans"},
                {"dir": "scripts", "summary": "helper scripts", "why": "automation"},
            ],
            "folder_rules": [],
            "placement_rules": [
                {
                    "kind": "adr",
                    "match_ext": [".md"],
                    "match_glob": ["adr-*.md"],
                    "dest_dir": "docs/adr",
                    "lfs": False,
                    "reason": "ADR documents belong in docs/adr",
                },
                {
                    "kind": "docs",
                    "match_ext": [".md", ".txt"],
                    "dest_dir": "docs",
                    "lfs": False,
                    "reason": "documentation notes belong in docs",
                },
                {
                    "kind": "py_scripts",
                    "match_ext": [".py"],
                    "dest_dir": "scripts",
                    "lfs": False,
                    "reason": "standalone python scripts belong in scripts",
                },
                {
                    "kind": "undeclared_target",
                    "match_ext": [".csv"],
                    "dest_dir": "undeclared_data",
                    "lfs": False,
                    "reason": "targets folder not in declared_dirs",
                },
                {
                    "kind": "inbox_target",
                    "match_ext": [".bin"],
                    "dest_dir": "_inbox",
                    "lfs": False,
                    "reason": "inbox never allowed in declared_only",
                },
            ],
            "ignore_patterns": [],
            "lfs_patterns": [],
            "protected_root_files": ["TaskRunner.py"],
        },
    )
    trust_project(exp_proj, declared_only=True, db_path=db)

    # Protected root files NEVER redirect even when broad explicit .md / .txt / .py rules match!
    for protected in (
        "Dockerfile",
        "Dockerfile.dev",
        "docker-compose.yml",
        "Makefile",
        "CMakeLists.txt",
        "build.rs",
        "requirements.txt",
        "requirements-dev.txt",
        "setup.py",
        "pyproject.toml",
        "README.md",
        "LICENSE.txt",
        "AGENTS.md",
        "CONTRIBUTING.md",
        "00-INDEX.md",
        "COMPONENTS.md",
        "TOOLS.lock",
        ".env.example",
        ".github/workflows/ci.yml",
        "main.py",        # entry file named in pyproject.toml [project.scripts]
        "TaskRunner.py",  # extended via rules.json protected_root_files
    ):
        res_prot = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(exp_proj / protected), "content": "x"},
            db_path=db,
        )
        assert res_prot is None, f"Protected path {protected!r} must NEVER be redirected in declared_only mode"

    # Undeclared rule targets and unmatched extensions are left alone (never _inbox/)
    for untouched in ("table.csv", "blob.bin", "unknown.custom", "docs/already_in_docs.md", "new_folder/keep.rs"):
        assert (
            on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(exp_proj / untouched), "content": "x"},
                db_path=db,
            )
            is None
        ), f"Expected {untouched!r} to stay untouched"

    # Explicit matching rules targeting declared folders DO redirect!
    pre_adr = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(exp_proj / "adr-0009-storage.md"), "content": "# ADR"},
        tool_call_id="tc_adr",
        db_path=db,
    )
    assert pre_adr == {"action": "modify", "args": {"path": str(exp_proj / "docs" / "adr" / "adr-0009-storage.md")}}

    pre_doc = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(exp_proj / "design-overview.md"), "content": "# Design"},
        tool_call_id="tc_doc",
        db_path=db,
    )
    assert pre_doc == {"action": "modify", "args": {"path": str(exp_proj / "docs" / "design-overview.md")}}

    pre_helper = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(exp_proj / "migrate_seed.py"), "content": "print(1)"},
        tool_call_id="tc_py",
        db_path=db,
    )
    assert pre_helper == {"action": "modify", "args": {"path": str(exp_proj / "scripts" / "migrate_seed.py")}}


def test_root_only_rule_matches_project_root_and_leaves_nested_paths_untouched(tmp_path: Path) -> None:
    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"

    # Reject non-boolean root_only in validate_rules_spec
    with pytest.raises(SafetyError):
        validate_rules_spec(
            {
                "project_slug": "bad-root-only",
                "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs", "source": "explicit"}],
                "folder_rules": [],
                "placement_rules": [
                    {
                        "kind": "docs",
                        "match_ext": [".md"],
                        "root_only": "yes",
                        "dest_dir": "docs",
                        "lfs": False,
                        "reason": "docs",
                        "source": "explicit",
                    }
                ],
                "ignore_patterns": [],
                "lfs_patterns": [],
            }
        )

    validated = validate_rules_spec(
        {
            "project_slug": "root-only-proj",
            "declared_dirs": [
                {"dir": "docs", "summary": "docs", "why": "docs", "source": "explicit"},
                {"dir": "docs/adr", "summary": "adr", "why": "adr", "source": "explicit"},
            ],
            "folder_rules": [],
            "placement_rules": [
                {
                    "kind": "adr",
                    "match_ext": [".md"],
                    "match_glob": ["adr-*.md", "ADR-*.md"],
                    "root_only": True,
                    "dest_dir": "docs/adr",
                    "lfs": False,
                    "reason": "root ADR notes live in docs/adr/ in this workspace",
                    "source": "explicit",
                },
                {
                    "kind": "docs",
                    "match_ext": [".md"],
                    "root_only": True,
                    "dest_dir": "docs",
                    "lfs": False,
                    "reason": "root Markdown notes live in docs/ in this workspace",
                    "source": "explicit",
                },
            ],
            "ignore_patterns": [],
            "lfs_patterns": [],
        }
    )
    assert validated["declared_dirs"][0]["source"] == "explicit"
    assert validated["placement_rules"][0]["source"] == "explicit"
    assert validated["placement_rules"][0]["root_only"] is True
    assert validated["placement_rules"][1]["source"] == "explicit"
    assert validated["placement_rules"][1]["root_only"] is True

    proj = tmp_path / "root_only_proj"
    _write_project_rules(proj, validated)
    trust_project(proj, declared_only=True, db_path=db)

    # Root files matching explicit root_only rules redirect to expected declared destinations
    assert on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(proj / "adr-0003-cache.md"), "content": "# ADR\n"},
        db_path=db,
    ) == {"action": "modify", "args": {"path": str(proj / "docs" / "adr" / "adr-0003-cache.md")}}
    assert on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(proj / "design-notes.md"), "content": "# Notes\n"},
        db_path=db,
    ) == {"action": "modify", "args": {"path": str(proj / "docs" / "design-notes.md")}}

    # Files deliberately written in ANY nested folder (even undeclared) are NEVER pulled out
    for nested in (
        "notes/rfc-01.md",
        "notes/adr-0003-cache.md",
        "experimental/README.md",
        "sandbox/sub/plan.md",
        "docs/guide.md",
    ):
        assert (
            on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(proj / nested), "content": "# Nested\n"},
                db_path=db,
            )
            is None
        ), f"root_only rule must not pull {nested!r} out of its folder"


def test_declared_only_redirect_notice_escaping_length_cap_and_never_raises(tmp_path: Path) -> None:
    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"
    proj = tmp_path / "notice_proj"
    _write_project_rules(
        proj,
        {
            "schema": 1,
            "schema_version": 1,
            "project_slug": "notice-proj",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
            "folder_rules": [],
            "placement_rules": [
                {
                    "kind": "docs",
                    "match_ext": [".md"],
                    "dest_dir": "docs",
                    "lfs": False,
                    "reason": "markdown notes belong in docs/",
                }
            ],
            "ignore_patterns": [],
            "lfs_patterns": [],
        },
    )
    trust_project(proj, declared_only=True, db_path=db)

    # 1. Normal redirect emits one-sentence plain notice with destination and reason
    pre = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(proj / "roadmap.md"), "content": "# Roadmap"},
        tool_call_id="tc_n1",
        db_path=db,
    )
    assert pre is not None
    placed = Path(pre["args"]["path"])
    assert placed == proj / "docs" / "roadmap.md"
    placed.write_text("# Roadmap\n", encoding="utf-8")

    out_json = on_transform_tool_result(
        tool_name="write_file",
        args=pre["args"],
        result=json.dumps({"verified": True, "resolved_path": str(placed)}),
        tool_call_id="tc_n1",
    )
    assert out_json is not None
    parsed = json.loads(out_json)
    notice = parsed["defuzz_notice"]
    assert "docs/roadmap.md" in notice
    assert "roadmap.md" in notice
    assert "markdown notes belong in docs/" in notice
    assert "\n" not in notice
    assert len(notice) <= 600

    # 2. Control/bidi chars and huge multi-segment paths are escaped and capped <= 600 chars
    long_sub = "/".join(["seg_" + "a" * 60] * 8) + "/\x1b[31m\u202ebad"
    pre_long = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(proj / long_sub / "spec.md"), "content": "# Spec"},
        tool_call_id="tc_n2",
        db_path=db,
    )
    assert pre_long is not None
    placed_long = Path(pre_long["args"]["path"])
    placed_long.write_text("# Spec\n", encoding="utf-8")
    out_plain = on_transform_tool_result(
        tool_name="write_file",
        args=pre_long["args"],
        result="Wrote file",
        tool_call_id="tc_n2",
    )
    assert out_plain is not None
    notice_line = out_plain.split("\n", 1)[1]
    assert len(notice_line) <= 600
    for forbidden in ("\n", "\x1b", "\u202e"):
        assert forbidden not in notice_line

    # Overlong single component (> NAME_MAX) hits OS error -> returns None without raising
    assert (
        on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(proj / ("a" * 500) / "spec.md"), "content": "# Spec"},
            tool_call_id="tc_enametoolong",
            db_path=db,
        )
        is None
    )

    # 3. Collision at destination in declared_only mode does NOT block or raise -> returns None
    (proj / "docs" / "collide.md").write_text("existing\n", encoding="utf-8")
    assert (
        on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(proj / "collide.md"), "content": "new"},
            tool_call_id="tc_collide",
            db_path=db,
        )
        is None
    )

    # 4. Injected error in declared_only mode NEVER raises and returns None (do not redirect)
    with mock.patch.object(placer, "resolve_placement_for_new_path", side_effect= SafetyError("boom")):
        assert (
            on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(proj / "safe_err.md"), "content": "new"},
                tool_call_id="tc_safe_err",
                db_path=db,
            )
            is None
        )
    with mock.patch.object(placer, "find_adopted_root", side_effect=RuntimeError("unexpected")):
        assert (
            on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(proj / "root_err.md"), "content": "new"},
                tool_call_id="tc_root_err",
                db_path=db,
            )
            is None
        )


def test_full_mode_differential_parity(tmp_path: Path) -> None:
    """Full mode for manually trusted projects keeps today's exact behaviour."""
    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"
    proj = tmp_path / "full_proj"
    proj.mkdir()
    (proj / "docs").mkdir()
    (proj / "_inbox").mkdir()
    fb = rules_mod.build_deterministic_fallback_rules(
        {"dir_summaries": {".": {}, "docs": {}}}
    )
    fb["project_slug"] = "full-proj"
    _write_project_rules(proj, fb)
    trust_project(proj, db_path=db)  # default manual trust -> full mode

    # In full mode, fallback rules and _inbox routing still operate identically to legacy behaviour
    assert resolve_placement_for_new_path(proj, "Dockerfile", fb)["placed_rel"] == "_inbox/Dockerfile"
    assert resolve_placement_for_new_path(proj, "requirements.txt", fb)["placed_rel"] == "docs/requirements.txt"
    assert resolve_placement_for_new_path(proj, "main.py", fb)["placed_rel"] == "scripts/main.py"
    assert resolve_placement_for_new_path(proj, "README.md", fb) is None

    # Collision in full mode still blocks
    (proj / "docs" / "existing.md").write_text("already\n", encoding="utf-8")
    block_res = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(proj / "existing.md"), "content": "dup"},
        db_path=db,
    )
    assert block_res is not None and block_res["action"] == "block"

    # Redirect in full mode sets placed_by_adopt without defuzz_notice
    pre_ok = on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(proj / "note.md"), "content": "hi"},
        tool_call_id="tc_full_1",
        db_path=db,
    )
    assert pre_ok is not None
    Path(pre_ok["args"]["path"]).write_text("hi\n", encoding="utf-8")
    out_ok = on_transform_tool_result(
        tool_name="write_file",
        args=pre_ok["args"],
        result=json.dumps({"verified": True}),
        tool_call_id="tc_full_1",
    )
    parsed_ok = json.loads(out_ok)
    assert "placed_by_adopt" in parsed_ok
    assert "defuzz_notice" not in parsed_ok


def _fake_fixture_template(tmp_path: Path, check_cmd: list[str] | None = None):
    import shutil
    from hermes_plugins.defuzz.templates import load_template

    fixture = Path(__file__).resolve().parent / "fixtures" / "templates" / "fake-rust-game"
    root = tmp_path / "tpl" / "fake-rust-game"
    shutil.copytree(fixture, root)
    lines = [
        "id: fake-rust-game",
        "name: Fake Rust Game",
        "summary: Minimal game for trust tests.",
        "kind: game",
        "layout: mono",
        "languages: [rust]",
        "engine: bevy",
        "needs: [cargo]",
        "placeholder: tmpl_prefix",
        'substitute_in: ["**/*.rs", "**/*.toml", "**/*.md"]',
        "repos:",
        "  - name: tmpl_prefix",
    ]
    if check_cmd is not None:
        lines += ["    check:", f"      cmd: {json.dumps(check_cmd)}", '      cwd: "."']
    (root / "template.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return load_template(root)


def test_template_scaffold_auto_trusts_in_declared_only_and_rejects_tampering(tmp_path: Path) -> None:
    import subprocess
    import sys
    from hermes_plugins.defuzz.placer import compute_rules_hash
    from hermes_plugins.defuzz.safety import run_git_hardened
    from hermes_plugins.defuzz.scaffolder import ScaffoldError, accept, propose

    _reset_notice_state_for_tests()
    with mock.patch.object(
        scaffolder.toolchk,
        "probe",
        side_effect=lambda name, entry, *a, **kw: (_fixture_version(entry), "/fixture/tool"),
    ):
        # 1. Freshly scaffolded template project is trusted immediately in declared_only mode
        db1 = tmp_path / "state1.db"
        prop1 = propose(
            _fake_fixture_template(tmp_path / "c1"),
            "Trust Game",
            {"building": "game", "languages": ["rust"]},
            dest_root=tmp_path / "projects1",
            staging_parent=tmp_path / "staging1",
        )
        res1 = accept(prop1, register=lambda n, p: json.dumps({"success": True, "id": n}), db_path=db1)
        dest1 = Path(res1.repos[0]["path"])

        rec1 = get_project(dest1.resolve(), db_path=db1)
        assert rec1 is not None
        assert rec1["rules_hash"] == compute_rules_hash(dest1)
        assert rec1["trust_mode"] == "declared_only"
        info1 = inspect_project_trust(dest1, db_path=db1)
        assert info1["trusted"] is True, info1["reason"]
        assert info1["mode"] == "declared_only"

        # Editing .adopt/rules.json after scaffold drops trust
        rules_p1 = dest1 / ".adopt" / "rules.json"
        d1 = json.loads(rules_p1.read_text(encoding="utf-8"))
        d1["project_slug"] = "trust-game-edited"
        rules_p1.write_text(json.dumps(d1, indent=2) + "\n", encoding="utf-8")
        info1_after = inspect_project_trust(dest1, db_path=db1)
        assert info1_after["trusted"] is False
        assert "hash mismatch" in info1_after["reason"].lower()

        # 2. Check command rewriting .adopt/rules.json during staging is NOT auto-trusted
        tamper_script = (
            "import json,pathlib;p=pathlib.Path('.adopt/rules.json');d=json.loads(p.read_text());"
            "d['project_slug']='tampered';p.write_text(json.dumps(d))"
        )
        db2 = tmp_path / "state2.db"
        prop2 = propose(
            _fake_fixture_template(tmp_path / "c2", check_cmd=[sys.executable, "-c", tamper_script]),
            "Tampered Game",
            {"building": "game", "languages": ["rust"]},
            dest_root=tmp_path / "projects2",
            staging_parent=tmp_path / "staging2",
        )
        res2 = accept(prop2, register=lambda n, p: json.dumps({"success": True, "id": n}), db_path=db2)
        dest2 = Path(res2.repos[0]["path"])
        rec2 = get_project(dest2.resolve(), db_path=db2)
        assert rec2 is not None
        assert not rec2["rules_hash"]
        assert inspect_project_trust(dest2, db_path=db2)["trusted"] is False

        # 3. Failed scaffold records no trust
        db3 = tmp_path / "state3.db"
        prop3 = propose(
            _fake_fixture_template(tmp_path / "c3"),
            "Failed Game",
            {"building": "game", "languages": ["rust"]},
            dest_root=tmp_path / "projects3",
            staging_parent=tmp_path / "staging3",
        )
        dest3 = prop3.repos[0].dest

        def failing_git(repo_dir, args, **kwargs):
            if "commit" in args:
                return subprocess.CompletedProcess(list(args), 1, b"", b"simulated commit failure")
            return run_git_hardened(repo_dir, args, **kwargs)

        with pytest.raises(ScaffoldError):
            accept(
                prop3,
                register=lambda n, p: json.dumps({"success": True, "id": n}),
                git=failing_git,
                db_path=db3,
            )
        if db3.exists():
            assert get_project(dest3.resolve(), db_path=db3) is None

        # 4. Existing folder with .adopt/rules.json is still untrusted until manual trust
        existing_dir = tmp_path / "existing_untrusted"
        _write_project_rules(
            existing_dir,
            {
                "schema": 1,
                "schema_version": 1,
                "project_slug": "existing-untrusted",
                "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
                "folder_rules": [],
                "placement_rules": [],
                "ignore_patterns": [],
                "lfs_patterns": [],
            },
        )
        assert inspect_project_trust(existing_dir, db_path=db1)["trusted"] is False


KNOWN_MISPLACEMENTS: tuple[str, ...] = (
    "Dockerfile",
    "build.rs",
    "requirements.txt",
    "main.py",
)

COMMON_PROTECTED_ROOT_PROBES: tuple[str, ...] = (
    "Dockerfile.prod",
    "docker-compose.yml",
    "Makefile",
    "CMakeLists.txt",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "go.work",
    "setup.py",
    "build.gradle.kts",
    "Solution.sln",
    "Project.csproj",
    ".env.local",
    ".github/workflows/deploy.yml",
    "README.rst",
    "LICENSE.md",
    "CHANGELOG.md",
)

ECOSYSTEM_CORPUS: dict[str, list[str]] = {
    "python-golden": [
        "ruff.toml",
        # Declared source folders (6)
        "packages/foundation/proof-app-core/src/proof_app_core/metrics.py",
        "packages/domain/proof-app-accounts/src/proof_app_accounts/ledger.py",
        "packages/adapters/proof-app-http-fastapi/src/proof_app_http_fastapi/middleware.py",
        "packages/apps/proof-app-cli/src/proof_app_cli/commands.py",
        "tools/xtask/src/xtask/release.py",
        "componentize/custom.json",
        # Test files (4)
        "tests/unit/test_ledger.py",
        "tests/integration/test_api.py",
        "test/smoke_test.py",
        "packages/domain/proof-app-accounts/tests/test_policy.py",
        # Docs (4)
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        # Scripts (4)
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        # Configs (4)
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        # Assets & data (4)
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        # New package folder manifests (3)
        "packages/domain/proof-app-billing/pyproject.toml",
        "other_service/package.json",
        "subproject/Cargo.toml",
        # Undeclared new folders (3)
        "experimental/prototype.py",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
    "ts-node-golden": [
        "tsconfig.build.json",
        "packages/foundation/proof-app-core/src/metrics.ts",
        "packages/domain/proof-app-accounts/src/ledger.ts",
        "packages/adapters/proof-app-http-hono/src/middleware.ts",
        "packages/apps/proof-app-cli/src/commands.ts",
        "tools/xtask/release.ts",
        "templates/endpoint.ts.tmpl",
        "tests/unit/ledger.test.ts",
        "tests/integration/api.test.ts",
        "test/smoke.test.ts",
        "packages/domain/proof-app-accounts/src/policy.test.ts",
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        "packages/domain/proof-app-billing/package.json",
        "other_service/pyproject.toml",
        "subproject/Cargo.toml",
        "experimental/prototype.ts",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
    "rust-golden": [
        "deny.toml",
        "foundation/src/metrics.rs",
        "domain/src/ledger.rs",
        "adapters/src/http_client.rs",
        "apps/cli/src/commands.rs",
        "xtask/src/release.rs",
        "foundation/src/error_ext.rs",
        "tests/integration_cli.rs",
        "test/smoke.rs",
        "domain/tests/ledger_test.rs",
        "adapters/tests/http_test.rs",
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        "apps/worker/Cargo.toml",
        "other_service/Cargo.toml",
        "subproject/package.json",
        "experimental/prototype.rs",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
    "go-golden": [
        "Taskfile.yml",
        "foundation/metrics.go",
        "domain/ledger.go",
        "adapters/http_client.go",
        "apps/cli/commands.go",
        "xtask/release.go",
        "domain/policy.go",
        "tests/e2e_test.go",
        "test/smoke_test.go",
        "domain/ledger_extra_test.go",
        "adapters/http_client_test.go",
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        "apps/worker/go.mod",
        "other_service/go.mod",
        "subproject/package.json",
        "experimental/prototype.go",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
    "cpp-golden": [
        "CMakePresets.json",
        "foundation/src/metrics.cpp",
        "foundation/include/metrics.hpp",
        "domain/src/ledger.cpp",
        "adapters/src/storage.cpp",
        "apps/cli/src/commands.cpp",
        "cmake/sanitizers.cmake",
        "tests/ledger_test.cpp",
        "tests/storage_test.cpp",
        "test/smoke_test.cpp",
        "domain/tests/unit_test.cpp",
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        "apps/worker/CMakeLists.txt",
        "other_service/CMakeLists.txt",
        "subproject/Cargo.toml",
        "experimental/prototype.cpp",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
    "dotnet-golden": [
        "Directory.Packages.props",
        "foundation/Metrics.cs",
        "domain/Ledger.cs",
        "adapters/HttpAdapter.cs",
        "apps/cli/Commands.cs",
        "xtask/Release.cs",
        "domain/Policy.cs",
        "tests/LedgerTests.cs",
        "tests/AdapterTests.cs",
        "test/SmokeTests.cs",
        "domain/PolicyTests.cs",
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        "apps/worker/ProofApp.Worker.csproj",
        "other_service/package.json",
        "subproject/Cargo.toml",
        "experimental/Prototype.cs",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
    "web-golden": [
        "vitest.config.ts",
        "src/pages/contact/index.html",
        "src/components/card.html",
        "src/styles/print.css",
        "src/lib/format.ts",
        "tools/xtask/release.ts",
        "design/tokens/brand.css",
        "tests/unit/format.test.ts",
        "tests/integration/api.test.ts",
        "test/smoke.test.ts",
        "tests/e2e/contact.e2e.ts",
        "docs/architecture.md",
        "docs/adr/0009-caching.md",
        "DESIGN_NOTES.md",
        "notes/rfc-01.md",
        "deploy.sh",
        "scripts/bootstrap.sh",
        "scripts/seed_db.py",
        "scripts/check.mjs",
        "config/local.yaml",
        "config/production.toml",
        "deploy/k8s/service.yaml",
        "infra/main.tf",
        "logo.png",
        "assets/banner.svg",
        "assets/model.glb",
        "data/seed.csv",
        "src/lib/widget/package.json",
        "other_service/pyproject.toml",
        "subproject/Cargo.toml",
        "experimental/prototype.ts",
        "sandbox/scratch.txt",
        "vendor_custom/blob.bin",
    ],
}


# Root files added after the template rules grew: each has one declared home, or none.
PLACEMENT_PROBES: tuple[str, ...] = (
    "install.ps1",
    "setup.bash",
    "overview.rst",
    "guide.adoc",
    "flow.mmd",
    "sequence.puml",
    "architecture.drawio",
    "0007-use-postgres.md",
    "TODO.md",
    "ROADMAP.md",
    # Well-known root names stay at the root.
    "GEMINI.md",
    "AUTHORS.md",
    "AGENT.md",
    "WARP.md",
    "DCO.md",
    # Loose sources, tests and assets stay.
    "helper.py",
    "scratch.rs",
    "util.ts",
    "widget.test.ts",
    "ledger_test.go",
    "icon.svg",
    # Scripts with an extension no rule names stay.
    "deploy.py",
    "run.mjs",
)

_LAYERED_DOCS_EXTS = (".rst", ".adoc", ".mmd", ".puml", ".drawio")


def _expected_default_redirects(template_id: str) -> dict[str, str]:
    """Out-of-the-box redirects, written from each template's declared rules (templates/*/rules.json)."""
    moved_md = ("DESIGN_NOTES.md", "TODO.md", "ROADMAP.md")
    expected = {name: f"docs/{name}" for name in moved_md}
    if template_id == "web-golden":
        # Flat website rules: root .md -> docs/, root *.test.ts -> tests/unit/. No scripts or diagram rule.
        expected["0007-use-postgres.md"] = "docs/0007-use-postgres.md"
        expected["widget.test.ts"] = "tests/unit/widget.test.ts"
        return expected
    # Six layered templates share one policy: docs formats -> docs/, .sh/.bash/.ps1 -> scripts/.
    for name in ("deploy.sh", "install.ps1", "setup.bash"):
        expected[name] = f"scripts/{name}"
    for name in ("overview.rst", "guide.adoc", "flow.mmd", "sequence.puml", "architecture.drawio"):
        expected[name] = f"docs/{name}"
    # Numbered decision records have their own folder only where docs/adr is declared.
    adr_home = "docs/adr" if template_id in ("python-golden", "ts-node-golden") else "docs"
    expected["0007-use-postgres.md"] = f"{adr_home}/0007-use-postgres.md"
    return expected


@pytest.mark.parametrize("spec", load_templates(), ids=lambda s: s.id)
def test_per_template_proof_against_misplacements(tmp_path: Path, spec) -> None:
    from hermes_plugins.defuzz.placer import _explicit_declared_dir_prefixes, add_placement_rule

    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"

    with mock.patch.object(
        scaffolder.toolchk,
        "probe",
        side_effect=lambda name, entry, *a, **kw: (_fixture_version(entry), "/fixture/tool"),
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

    dest = Path(accepted.repos[0]["path"])
    trust = inspect_project_trust(dest, db_path=db)
    assert trust["trusted"] is True, trust["reason"]
    assert trust["mode"] == "declared_only"

    extra_paths = ECOSYSTEM_CORPUS[spec.id]
    new_common_probes = [p for p in COMMON_PROTECTED_ROOT_PROBES if not (dest / p).exists()]
    corpus = list(KNOWN_MISPLACEMENTS) + new_common_probes + list(extra_paths) + list(PLACEMENT_PROBES)
    assert len(corpus) - len(KNOWN_MISPLACEMENTS) >= 40, (
        f"Expected >= 40 ecosystem paths beyond the 4 known misplacements, got {len(corpus) - 4}"
    )

    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    declared_prefixes = _explicit_declared_dir_prefixes(rules_data)
    explicit_rules = [
        pr for pr in (rules_data.get("placement_rules") or [])
        if isinstance(pr, dict) and pr.get("source") != "fallback"
    ]

    # Pass 1: Out-of-the-box scaffolded template
    redirected_default: list[tuple[str, str]] = []
    for idx, rel in enumerate(corpus):
        target = dest / rel
        assert not target.exists(), f"Corpus path {rel!r} already exists in {spec.id}"
        pre = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(target), "content": "probe\n"},
            tool_call_id=f"{spec.id}_p1_{idx}",
            db_path=db,
        )
        if pre is not None:
            assert pre["action"] == "modify"
            placed_rel = Path(pre["args"]["path"]).relative_to(dest).as_posix()
            redirected_default.append((rel, placed_rel))
            assert not is_protected_root_path(rel, proj_root=dest, rules_data=rules_data), (
                f"Protected root path {rel!r} was redirected to {placed_rel!r} in {spec.id}"
            )
            assert explicit_rules, f"Redirect {rel} -> {placed_rel} happened with zero explicit rules"
            assert any(
                placed_rel == d or placed_rel.startswith(d + "/") for d in declared_prefixes
            ), f"Redirect {rel} -> {placed_rel} landed outside template declared dirs {declared_prefixes}"

    for known in KNOWN_MISPLACEMENTS:
        assert all(orig != known for orig, _ in redirected_default), (
            f"Known misplacement {known!r} was redirected in {spec.id}: {redirected_default}"
        )
    assert explicit_rules, f"Expected bundled template {spec.id} to ship explicit placement_rules"
    expected_default = _expected_default_redirects(spec.id)
    assert len(redirected_default) == len(dict(redirected_default))
    assert dict(redirected_default) == expected_default, (
        f"Unexpected out-of-the-box redirects in {spec.id}: {redirected_default}"
    )

    # Pass 2: With an explicit rule declared on the template's docs/ folder
    add_placement_rule(dest, ".md", "docs", kind="docs", reason="markdown docs belong in docs", db_path=db)
    assert inspect_project_trust(dest, db_path=db)["mode"] == "declared_only"
    rules_after = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))

    redirected_explicit: list[tuple[str, str]] = []
    for idx, rel in enumerate(corpus):
        target = dest / rel
        pre = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(target), "content": "# Probe\n"},
            tool_call_id=f"{spec.id}_p2_{idx}",
            db_path=db,
        )
        if pre is not None:
            assert pre["action"] == "modify"
            placed_path = Path(pre["args"]["path"])
            placed_rel = placed_path.relative_to(dest).as_posix()
            redirected_explicit.append((rel, placed_rel))
            assert not is_protected_root_path(rel, proj_root=dest, rules_data=rules_after), (
                f"Protected root path {rel!r} redirected even under broad .md rule in {spec.id}"
            )
            assert any(
                placed_rel == d or placed_rel.startswith(d + "/") for d in declared_prefixes
            ), f"Explicit redirect {rel} -> {placed_rel} landed outside declared dirs {declared_prefixes}"
            # Verify redirect notice in transform_tool_result
            placed_path.write_text("# Probe\n", encoding="utf-8")
            transformed = on_transform_tool_result(
                tool_name="write_file",
                args=pre["args"],
                result=json.dumps({"verified": True}),
                tool_call_id=f"{spec.id}_p2_{idx}",
            )
            assert transformed is not None
            notice = json.loads(transformed)["defuzz_notice"]
            if rel.endswith(".md") and not placed_rel.startswith("docs/adr/"):
                reason = "markdown docs belong in docs"
            else:
                parent = placed_rel.rsplit("/", 1)[0]
                reason = next(str(pr["reason"]) for pr in explicit_rules if pr.get("dest_dir") == parent)
            assert placed_rel in notice and reason in notice, (rel, notice)

    for known in KNOWN_MISPLACEMENTS:
        assert all(orig != known for orig, _ in redirected_explicit)
    # The broad .md rule adds only the one non-protected .md outside a declared folder.
    expected_explicit = dict(expected_default)
    expected_explicit["notes/rfc-01.md"] = "docs/notes/rfc-01.md"
    # The template's docs rule only gives up .md, so its other formats still move, and the
    # decision-records pattern rule stays first, so numbered records still reach docs/adr/.
    assert len(redirected_explicit) == len(dict(redirected_explicit))
    assert dict(redirected_explicit) == expected_explicit, redirected_explicit





def test_trust_command_accepts_declared_only_and_passes_it_through(tmp_path: Path, monkeypatch, capsys) -> None:
    import argparse
    import io

    from tests.conftest import load_submodule

    cli = load_submodule("cli")
    parser = argparse.ArgumentParser()
    cli.setup_defuzz_cli(parser)
    assert parser.parse_args(["trust", str(tmp_path)]).declared_only is False
    assert parser.parse_args(["trust", str(tmp_path), "--declared-only"]).declared_only is True

    class _Tty:
        def isatty(self):
            return True

    monkeypatch.setattr(cli.sys, "stdin", _Tty())
    monkeypatch.setattr(cli, "assert_safe_root", lambda folder, role=None: Path(folder))
    monkeypatch.setattr(cli, "_read_rules_bytes_nofollow", lambda root: b"{}")
    monkeypatch.setattr(cli, "_parse_rules_bytes", lambda raw, root: {"project_slug": "proj"})
    monkeypatch.setattr(cli, "_is_valid_adopted_rules", lambda data: True)
    for flag, shown in ((True, "declared folders only"), (False, "full")):
        seen = {}
        monkeypatch.setattr(cli, "_open_controlling_tty", lambda: io.StringIO("proj\n"))
        monkeypatch.setattr(cli, "trust_project", lambda folder, **kw: seen.update(kw) or {"trusted": True})
        assert cli._handle_trust_subcommand(str(tmp_path), declared_only=flag) == {"trusted": True}
        assert seen == {"declared_only": flag}
        assert f"Placement mode: {shown}" in capsys.readouterr().out
