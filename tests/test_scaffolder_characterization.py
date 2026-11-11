"""Characterization tests for scaffolder.py and new_project.py."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import new_project, scaffolder  # noqa: E402
from hermes_plugins.defuzz.naming import forms_from_placeholder, forms_from_slug  # noqa: E402
from hermes_plugins.defuzz.scaffolder import (  # noqa: E402
    AcceptResult,
    ProjectRegistrationUnavailable,
    Proposal,
    RepoPlan,
    ScaffoldError,
    ScaffoldTimeout,
    accept,
    default_project_create,
    discard,
    poly_dest_name,
    projects_root,
    propose,
    resolve_plugin_commit,
)
from hermes_plugins.defuzz.templates import CheckSpec, OptionSpec, RepoSpec, TemplateSpec, load_template  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEMPLATES_FIXTURES = FIXTURES_DIR / "fixtures" if (FIXTURES_DIR / "fixtures").exists() else FIXTURES_DIR / "templates"


def test_scaffolder_compatibility_facade_exports() -> None:
    """Verify every public, imported, re-exported, and internal helper name remains on scaffolder."""
    expected_attrs = (
        "ScaffoldError",
        "ScaffoldTimeout",
        "ProjectRegistrationUnavailable",
        "RepoPlan",
        "Proposal",
        "AcceptResult",
        "projects_root",
        "_check_not_live_hermes",
        "_read_packed_ref",
        "_resolve_git_head_from_files",
        "resolve_plugin_commit",
        "_matches_locked_glob",
        "_compute_locked_hashes",
        "_matches_substitute_glob",
        "_stage_and_rename_repo",
        "_resolve_template_options",
        "_rewrite_env_example_for_option",
        "_apply_options_to_staged_repos",
        "_build_proposed_tree",
        "_validate_single_path_component",
        "poly_dest_name",
        "_generate_scaffold_context",
        "propose",
        "default_project_create",
        "discard",
        "_format_completed_note",
        "_raise_scaffold_error",
        "_check_deadline",
        "_is_cancelled",
        "_check_cancelled",
        "_resolve_contained_check_cwd",
        "_strip_build_caches",
        "_combine_output",
        "_run_git_step",
        "_resolve_locked_globs_for_proposal",
        "_resolve_option_specs_for_proposal",
        "_scaffold_preflight_error",
        "accept",
        # Monkeypatch seams
        "run_git_hardened",
        "save_answers",
        "record_project",
        "record_template_options",
        "get_template_options",
        "tool_seed",
        "toolchk",
        "time",
        "subprocess",
        "shutil",
    )
    for attr in expected_attrs:
        assert hasattr(scaffolder, attr), f"Missing attribute on scaffolder: {attr}"


def test_new_project_compatibility_facade_exports() -> None:
    """Verify every public, imported, re-exported, and internal helper name remains on new_project."""
    expected_attrs = (
        "VALID_FLOW_STATUSES",
        "FlowResult",
        "run_new_project_flow",
        "_load_kit_catalog",
        # Monkeypatch seams
        "propose",
        "accept",
        "discard",
        "default_project_create",
        "propose_kit",
        "accept_kit",
        "discard_kit",
        "parse_prompt",
        "run_questionnaire",
        "_call_with_budget",
        "best_matches",
        "match_kits",
        "load_templates",
        "default_templates_root",
        "componentize_bridge",
        "time",
    )
    for attr in expected_attrs:
        assert hasattr(new_project, attr), f"Missing attribute on new_project: {attr}"
    # Guess-based selection and the no-match hand-off are gone.
    for gone in (
        "_resolve_chosen_template",
        "_handle_no_match_handoff",
        "build_handoff",
        "request_handoff",
        "closest",
    ):
        assert not hasattr(new_project, gone), f"Removed name still on new_project: {gone}"
    assert "handoff" not in new_project.FlowResult.__dataclass_fields__
    assert "no_match_handoff" not in new_project.VALID_FLOW_STATUSES


def test_git_head_resolution_worktree_commondir_and_packed_refs(tmp_path: Path) -> None:
    """Characterize _read_packed_ref and _resolve_git_head_from_files across gitdir files, commondir, and packed-refs."""
    sha = "a" * 40
    common_git = tmp_path / "common_git"
    worktree_git = common_git / "worktrees" / "wt1"
    worktree_git.mkdir(parents=True)

    (common_git / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{sha} refs/heads/packed-branch\n^bbbb\n",
        encoding="utf-8",
    )
    (worktree_git / "commondir").write_text("../..\n", encoding="utf-8")
    (worktree_git / "HEAD").write_text("ref: refs/heads/packed-branch\n", encoding="utf-8")

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").write_text(f"gitdir: {worktree_git}\n", encoding="utf-8")

    assert scaffolder._read_packed_ref(common_git, "refs/heads/packed-branch") == sha
    assert scaffolder._read_packed_ref(common_git, "refs/heads/missing") is None
    assert resolve_plugin_commit(checkout) == sha

    # Direct loose ref chain
    ref_dir = common_git / "refs" / "heads"
    ref_dir.mkdir(parents=True)
    loose_sha = "B" * 40
    (ref_dir / "main").write_text(loose_sha + "\n", encoding="utf-8")
    (worktree_git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert resolve_plugin_commit(checkout) == loose_sha.lower()

    # Path traversal in ref is rejected
    (worktree_git / "HEAD").write_text("ref: ../outside\n", encoding="utf-8")
    assert resolve_plugin_commit(checkout) == "unknown"


def test_glob_matching_and_locked_hashes(tmp_path: Path) -> None:
    """Characterize _matches_locked_glob, _matches_substitute_glob, and _compute_locked_hashes."""
    assert scaffolder._matches_locked_glob("Cargo.toml", ["Cargo.toml"]) is True
    assert scaffolder._matches_locked_glob("sub/Cargo.toml", ["Cargo.toml"]) is False
    assert scaffolder._matches_locked_glob("Cargo.toml", ["**/Cargo.toml"]) is True
    assert scaffolder._matches_locked_glob("sub/Cargo.toml", ["**/Cargo.toml"]) is True
    assert scaffolder._matches_locked_glob("", ["*"]) is False

    assert scaffolder._matches_substitute_glob("src/main.rs", ["**/*.rs"]) is True
    assert scaffolder._matches_substitute_glob("main.rs", ["**/*.rs"]) is True
    assert scaffolder._matches_substitute_glob("README.md", ["*.rs"]) is False
    assert scaffolder._matches_substitute_glob("", ["*"]) is True
    assert scaffolder._matches_locked_glob(r"a\b.py", ["*.py"]) is True

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "config").write_text("ignored", encoding="utf-8")
    (repo / "sub").mkdir()
    (repo / "Cargo.toml").write_bytes(b"root-cargo")
    (repo / "sub" / "Cargo.toml").write_bytes(b"sub-cargo")
    (repo / r"a\b.py").write_bytes(b"backslash-py")
    os.symlink(str(repo / "Cargo.toml"), str(repo / "link.toml"))

    hashes = scaffolder._compute_locked_hashes(repo, ["Cargo.toml", "**/Cargo.toml", "*.toml", "*.py"])
    assert set(hashes.keys()) == {"Cargo.toml", "sub/Cargo.toml", r"a\b.py"}
    assert hashes["Cargo.toml"] == hashlib.sha256(b"root-cargo").hexdigest()
    assert hashes["sub/Cargo.toml"] == hashlib.sha256(b"sub-cargo").hexdigest()
    assert hashes[r"a\b.py"] == hashlib.sha256(b"backslash-py").hexdigest()


def test_glob_helpers_do_not_depend_on_auditor_vendor() -> None:
    """Verify scaffolder glob helpers are scaffold-owned and never import audit.vendor.template_drift."""
    import builtins

    original_import = builtins.__import__

    def forbid_auditor(name: str, *args: Any, **kwargs: Any) -> Any:
        if "template_drift" in name or name.startswith("audit.") or ".audit." in name:
            raise ModuleNotFoundError("auditor vendor import is forbidden in scaffolder")
        return original_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=forbid_auditor):
        assert scaffolder._matches_locked_glob("Cargo.toml", ["Cargo.toml"]) is True
        assert scaffolder._matches_substitute_glob("src/lib.rs", ["**/*.rs"]) is True


def test_propose_and_accept_rewrite_options_across_all_poly_repos(tmp_path: Path) -> None:
    """Verify propose() and accept-time option overrides rewrite .env.example in every repo, not just the first."""
    fixture = tmp_path / "fixture"
    for repo_name in ("tmpl_prefix_api", "tmpl_prefix_web"):
        repo_dir = fixture / repo_name
        repo_dir.mkdir(parents=True)
        (repo_dir / ".env.example").write_text("TMPL_PREFIX_MODE=old\n", encoding="utf-8")
    (fixture / "template.yaml").write_text(
        json.dumps(
            {
                "id": "fixture",
                "name": "Poly Opt Fixture",
                "summary": "Two-repo option rewrite test",
                "kind": "app",
                "layout": "poly",
                "languages": ["python"],
                "placeholder": "tmpl_prefix",
                "substitute_in": [".env.example"],
                "repos": [{"name": "tmpl_prefix_api"}, {"name": "tmpl_prefix_web"}],
                "options": {
                    "mode": {
                        "label": "Mode",
                        "choices": ["old", "new", "override"],
                        "default": "old",
                        "env_key": "TMPL_PREFIX_MODE",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    template = load_template(fixture)
    proposal = propose(
        template,
        "app",
        {},
        options={"mode": "new"},
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging",
    )
    try:
        staged_envs = [(plan.staged / ".env.example").read_text(encoding="utf-8") for plan in proposal.repos]
        assert staged_envs == ["APP_MODE=new\n", "APP_MODE=new\n"]

        scaffolder._refresh_proposal_options_on_accept(
            proposal,
            {"mode": "override"},
            proposal.option_specs,
            proposal.locked,
            db_path=None,
        )
        refreshed_envs = [(plan.staged / ".env.example").read_text(encoding="utf-8") for plan in proposal.repos]
        assert refreshed_envs == ["APP_MODE=override\n", "APP_MODE=override\n"]
    finally:
        discard(proposal)


def test_rewrite_env_example_preserves_line_endings_and_handles_export(tmp_path: Path) -> None:
    """Characterize _rewrite_env_example_for_option with CRLF, LF, export prefix, and comments."""
    repo = tmp_path / "staged"
    repo.mkdir()
    env_file = repo / ".env.example"
    env_file.write_bytes(
        b"# comment=ignored\r\n"
        b"export MY_APP_ADAPTER=old_val\r\n"
        b"OTHER_KEY=keep\n"
    )
    rewritten = scaffolder._rewrite_env_example_for_option(
        repo,
        "adapter",
        "MY_APP_ADAPTER",
        "TMPL_PREFIX_ADAPTER",
        "new_val",
    )
    assert rewritten is True
    assert env_file.read_bytes() == (
        b"# comment=ignored\n"
        b"MY_APP_ADAPTER=new_val\n"
        b"OTHER_KEY=keep\n"
    )


def test_combine_output_and_cancellation_helpers(tmp_path: Path) -> None:
    """Characterize _combine_output, _is_cancelled, and _check_cancelled."""
    combined, out_s, err_s = scaffolder._combine_output(b"out line\n", "err line\n")
    assert combined == "out line\nerr line"
    assert out_s == "out line\n"
    assert err_s == "err line\n"

    assert scaffolder._is_cancelled(None) is False
    assert scaffolder._is_cancelled(False) is False
    assert scaffolder._is_cancelled(True) is True
    assert scaffolder._is_cancelled(lambda: True) is True

    with pytest.raises(ScaffoldError) as exc_info:
        scaffolder._check_cancelled(True, tmp_path, step="unit-test", output="stopped", returncode=130)
    assert exc_info.value.cancelled is True
    assert exc_info.value.keep_staging is True
    assert exc_info.value.returncode == 130
    assert "stopped" in str(exc_info.value)


def test_new_project_flow_early_timeouts_and_prompt_errors(tmp_path: Path) -> None:
    """Characterize timeout and error branches across run_new_project_flow stages."""
    spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")

    # Non-positive timeout_s
    res0 = new_project.run_new_project_flow(
        confirm=lambda _: True,
        timeout_s=0,
    )
    assert res0.status == "timeout"
    assert "positive" in res0.message

    # Prompt parse exception -> status='error'
    with mock.patch.object(new_project, "parse_prompt", side_effect=RuntimeError("bad prompt parse")):
        res_err = new_project.run_new_project_flow(
            prompt="build something",
            templates=[spec],
            confirm=lambda _: True,
        )
    assert res_err.status == "error"
    assert "bad prompt parse" in res_err.message

    # Missing name_provider without prompt name -> status='timeout'
    res_no_name = new_project.run_new_project_flow(
        template_id="fake-rust-game",
        ask=lambda q, _: {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}.get(q.id),
        templates=[spec],
        name_provider=None,
        confirm=lambda _: True,
    )
    assert res_no_name.status == "timeout"
    assert "project name" in res_no_name.message
