"""A project manifest placed below the project root is reported as a nested project.

Root manifests and non-manifest protected files keep their old 'leave alone'
behaviour; declared workspace members and dependency/build folders are quiet.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import placer as placer_mod  # noqa: E402
from hermes_plugins.defuzz.placer import (  # noqa: E402
    NESTED_PROJECT_MANIFESTS,
    _format_nested_manifest_notice,
    _reset_notice_state_for_tests,
    check_nested_project_manifest,
    on_pre_tool_call,
    on_transform_tool_result,
    resolve_placement_for_new_path,
    trust_project,
)
from hermes_plugins.defuzz.rules import PROTECTED_ROOT_FILES  # noqa: E402

RULES = {
    "schema": 1,
    "schema_version": 1,
    "project_slug": "demo_proj",
    "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
    "placement_rules": [
        {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
    ],
}


def _check(root: Path, rel: str, rules=None):
    return check_nested_project_manifest(root, rel, rules if rules is not None else RULES)


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_manifest_set_is_derived_from_protected_list():
    assert NESTED_PROJECT_MANIFESTS <= PROTECTED_ROOT_FILES
    assert {"package.json", "pyproject.toml", "Cargo.toml"} <= NESTED_PROJECT_MANIFESTS
    for not_manifest in ("README.md", "LICENSE", ".gitignore", "Makefile", "package-lock.json"):
        assert not_manifest not in NESTED_PROJECT_MANIFESTS


# (a) root manifests keep today's behaviour
@pytest.mark.parametrize("name", ["package.json", "pyproject.toml", "Cargo.toml"])
def test_root_manifest_unchanged(tmp_path, name):
    assert resolve_placement_for_new_path(tmp_path, name, RULES) is None
    assert _check(tmp_path, name) is None


# (b) a manifest below the root is reported
@pytest.mark.parametrize("name", ["package.json", "pyproject.toml", "Cargo.toml"])
def test_nested_manifest_reported(tmp_path, name):
    rel = f"sub/{name}"
    assert resolve_placement_for_new_path(tmp_path, rel, RULES) is None  # still not moved
    found = _check(tmp_path, rel)
    assert found is not None
    assert found["code"] == "nested_project_manifest"
    assert found["rel"] == rel
    assert found["folder"] == "sub"
    assert "second project" in found["message"]
    assert found["verified"] is True


def test_nested_manifest_under_exempt_top_dir_reported(tmp_path):
    assert _check(tmp_path, "src/other_app/package.json")["code"] == "nested_project_manifest"


def test_declared_prefix_is_quiet(tmp_path):
    rules = dict(RULES, declared_dirs=[{"dir": "apps", "summary": "a", "why": "a"}])
    assert _check(tmp_path, "apps/web/package.json", rules) is None
    assert _check(tmp_path, "tools/x/package.json", rules) is not None


# (c) protected non-manifest files in sub-folders keep today's behaviour
@pytest.mark.parametrize("name", ["README.md", "LICENSE", ".gitignore", "Makefile", "package-lock.json"])
def test_nested_non_manifest_not_reported(tmp_path, name):
    rel = f"sub/{name}"
    before = resolve_placement_for_new_path(tmp_path, rel, RULES)
    assert _check(tmp_path, rel) is None
    assert resolve_placement_for_new_path(tmp_path, rel, RULES) == before


# (d) declared monorepo members
def _npm_monorepo(root: Path, workspaces) -> None:
    _write(root, "package.json", json.dumps({"name": "mono", "private": True, "workspaces": workspaces}))


def test_npm_workspaces_members_quiet_deeper_one_reported(tmp_path):
    _npm_monorepo(tmp_path, ["apps/*", "packages/*"])
    rels = ["apps/web/package.json", "packages/ui/package.json", "apps/web/experiments/thing/package.json"]
    reports = [r for r in (_check(tmp_path, rel) for rel in rels) if r is not None]
    assert [r["rel"] for r in reports] == ["apps/web/experiments/thing/package.json"]


def test_npm_workspaces_object_form(tmp_path):
    _npm_monorepo(tmp_path, {"packages": ["packages/*"]})
    assert _check(tmp_path, "packages/ui/package.json") is None
    assert _check(tmp_path, "apps/web/package.json") is not None


def test_npm_workspaces_negation_and_globstar(tmp_path):
    _npm_monorepo(tmp_path, ["libs/**", "!libs/legacy"])
    assert _check(tmp_path, "libs/a/b/package.json") is None
    assert _check(tmp_path, "libs/legacy/package.json") is not None


def test_pnpm_workspace_yaml(tmp_path):
    _write(tmp_path, "pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n  - \"packages/*\"  # libs\n")
    assert _check(tmp_path, "apps/web/package.json") is None
    assert _check(tmp_path, "packages/ui/package.json") is None
    assert _check(tmp_path, "other/x/package.json") is not None


def test_cargo_workspace_members(tmp_path):
    _write(tmp_path, "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n')
    assert _check(tmp_path, "crates/core/Cargo.toml") is None
    assert _check(tmp_path, "tools/gen/Cargo.toml") is not None


def test_go_work_use(tmp_path):
    _write(tmp_path, "go.work", "go 1.22\n\nuse (\n\t./svc/api\n\t./svc/worker // w\n)\nuse ./cli\n")
    assert _check(tmp_path, "svc/api/package.json") is None
    assert _check(tmp_path, "cli/package.json") is None
    assert _check(tmp_path, "svc/other/package.json") is not None


def test_unreadable_declaration_fails_closed(tmp_path):
    _write(tmp_path, "package.json", "{not json")
    found = _check(tmp_path, "apps/web/package.json")
    assert found is not None
    assert found["verified"] is False
    assert "could not be verified" in found["message"]


# (e) dependency/build folders are never reported
@pytest.mark.parametrize("folder", ["node_modules/left-pad", "apps/web/node_modules/x", ".next/x", "dist", "build/x",
                                    ".venv/lib/x", "target/debug", "vendor/x", ".git/x"])
def test_dependency_and_build_folders_quiet(tmp_path, folder):
    assert _check(tmp_path, f"{folder}/package.json") is None


# Hook: the write still goes where it was asked; the agent gets a notice.
def test_hook_reports_nested_manifest_without_moving(tmp_path):
    home = tmp_path / "hermes_home"
    home.mkdir()
    proj = tmp_path / "proj"
    (proj / ".adopt").mkdir(parents=True)
    (proj / "docs").mkdir()
    (proj / ".adopt" / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
    with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}):
        _reset_notice_state_for_tests()
        try:
            trust_project(proj)
            target = proj / "site2" / "package.json"
            pre = on_pre_tool_call(tool_name="write_file", args={"path": str(target)}, tool_call_id="tc_n1")
            assert pre is None
            out = on_transform_tool_result(
                tool_name="write_file", args={"path": str(target)}, result=json.dumps({"ok": True}),
                tool_call_id="tc_n1",
            )
            notice = json.loads(out)["defuzz_notice"]
            assert "nested_project_manifest" in notice
            assert "in site2/" in notice and "(package.json)" in notice

            root_target = proj / "package.json"
            assert on_pre_tool_call(tool_name="write_file", args={"path": str(root_target)}, tool_call_id="tc_n2") is None
            assert on_transform_tool_result(
                tool_name="write_file", args={"path": str(root_target)}, result=json.dumps({"ok": True}),
                tool_call_id="tc_n2",
            ) is None
        finally:
            _reset_notice_state_for_tests()


# --- final-review hardening -------------------------------------------------

def _pnpm(root: Path, text: str) -> None:
    _write(root, "pnpm-workspace.yaml", text)


@pytest.mark.parametrize("text", [
    "packages: ['apps/*', \"packages/*\"]\n",
    "packages: [apps/*, packages/*]\n",
    "packages: [ 'apps/*' , packages/* ]  # members\n",
    "packages: [\n  'apps/*',  # web apps\n  \"packages/*\",\n]\n",
    "packages:\n  [\n    apps/*,\n    packages/*\n  ]\n",
    "---\ncatalog:\n  react: ^18\npackages: ['apps/*', 'packages/*']\nonlyBuiltDependencies: [esbuild]\n",
    "packages:\n- apps/*\n- 'packages/*'\n",
])
def test_pnpm_flow_and_block_lists(tmp_path, text):
    _pnpm(tmp_path, text)
    assert _check(tmp_path, "apps/web/package.json") is None
    assert _check(tmp_path, "packages/ui/package.json") is None
    found = _check(tmp_path, "other/x/package.json")
    assert found is not None and found["verified"] is True


@pytest.mark.parametrize("text", [
    "packages: ['apps/*', '!apps/legacy']\n",
    "packages: [\n  \"apps/*\",\n  \"!apps/legacy\", # old\n]\n",
    "packages:\n  - 'apps/*'\n  - '!apps/legacy'\n",
])
def test_pnpm_negation(tmp_path, text):
    _pnpm(tmp_path, text)
    assert _check(tmp_path, "apps/web/package.json") is None
    found = _check(tmp_path, "apps/legacy/package.json")
    assert found is not None and found["verified"] is True


@pytest.mark.parametrize("text", [
    "packages: ['apps/*'\n",                 # unclosed flow list
    "packages: 'apps/*'\n",                  # scalar, not a list
    "packages: {a: b}\n",                    # mapping
    "packages: *anchor\n",
    "packages: |\n  apps/*\n",
    "packages:\n  - [apps/*]\n",
    "packages: [apps/*] trailing\n",
    "packages: ['apps/*']\npackages: ['x/*']\n",  # duplicate key
    "packages:\n  - !apps/legacy\n",          # unquoted '!' is a YAML tag
    "  : garbage [\n",
])
def test_pnpm_unparseable_is_unknown(tmp_path, text):
    _pnpm(tmp_path, text)
    found = _check(tmp_path, "apps/web/package.json")
    assert found is not None
    assert found["verified"] is False
    assert "could not be verified" in found["message"]
    assert "not declared as a workspace member" not in found["message"]


@pytest.mark.parametrize("name,text", [
    ("Cargo.toml", "[workspace]\nmembers = [\"apps/*\"]\nexclude = 5\n"),
    ("Cargo.toml", "[workspace]\nmembers = \"apps/web\"\n"),
    ("Cargo.toml", "[workspace]\nmembers = [\"apps/*\", 3]\n"),
    ("Cargo.toml", "workspace = 5\n"),
    ("pyproject.toml", "[tool.uv.workspace]\nmembers = [\"apps/*\"]\nexclude = \"apps/web\"\n"),
    ("pyproject.toml", "[tool]\nuv = 3\n"),
    ("package.json", json.dumps({"workspaces": 7})),
    ("package.json", json.dumps({"workspaces": {"packages": "apps/*"}})),
    ("package.json", json.dumps({"workspaces": ["apps/*", None]})),
    ("go.work", "go 1.22\nthis is garbage\n"),
    ("go.work", "use (\n  ./apps/web\n"),
    ("go.work", "use ./a ./b\n"),
])
def test_malformed_declarations_are_unknown_never_raise(tmp_path, name, text):
    _write(tmp_path, name, text)
    found = _check(tmp_path, "apps/web/package.json")
    assert found is not None
    assert found["verified"] is False


def test_valid_excludes_and_nohoist(tmp_path):
    _write(tmp_path, "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/old"]\n')
    assert _check(tmp_path, "crates/core/Cargo.toml") is None
    assert _check(tmp_path, "crates/old/Cargo.toml")["verified"] is True
    _write(tmp_path, "pyproject.toml", '[tool.uv.workspace]\nmembers = ["py/*"]\nexclude = ["py/x"]\n')
    assert _check(tmp_path, "py/a/pyproject.toml") is None
    assert _check(tmp_path, "py/x/pyproject.toml")["verified"] is True
    _npm_monorepo(tmp_path, {"packages": ["js/*"], "nohoist": ["**/react"]})
    assert _check(tmp_path, "js/a/package.json") is None
    assert _check(tmp_path, "react/package.json")["verified"] is True
    _npm_monorepo(tmp_path, {"nohoist": ["**/react"]})
    assert _check(tmp_path, "js/a/package.json")["verified"] is True


def test_go_work_quoted_and_other_directives(tmp_path):
    _write(tmp_path, "go.work", 'go 1.22\ntoolchain go1.22.1\nuse "./svc/a"\nreplace (\n  x => ./y\n)\n'
                                'godebug default=go1.21\nuse (\n  "./svc/b" // b\n)\n')
    assert _check(tmp_path, "svc/a/package.json") is None
    assert _check(tmp_path, "svc/b/package.json") is None
    assert _check(tmp_path, "svc/c/package.json")["verified"] is True


def test_control_and_bidi_chars_escaped_in_notice(tmp_path):
    rel = "we\nird\x1b[31m\u202e\x85dir/package.json"
    found = _check(tmp_path, rel)
    assert found is not None
    notice = _format_nested_manifest_notice(found)
    for bad in ("\n", "\x1b", "\u202e", "\x85"):
        assert bad not in notice
        assert bad not in found["message"]
    assert "we" in notice and "dir/" in notice


@pytest.mark.parametrize("verified_decl", [None, "{not json"])
def test_long_path_notice_is_capped(tmp_path, verified_decl):
    if verified_decl:
        _write(tmp_path, "package.json", verified_decl)
    rel = "a" * 2000 + "/" + "\x01" * 2000 + "/package.json"
    found = _check(tmp_path, rel)
    notice = _format_nested_manifest_notice(found)
    assert len(notice) <= 600
    assert "..." in notice
    assert "ask the user where it should live before writing more files there." in notice


def test_notice_wording_is_safe(tmp_path):
    notice = _format_nested_manifest_notice(_check(tmp_path, "sub/package.json"))
    assert "A project manifest (package.json) was written below the project root, in sub/." in notice
    assert "The file was written where you asked; nothing was moved." in notice
    assert "If this folder is meant to be part of this project, declare it in the root workspace settings." in notice
    assert "If it is a separate project, ask the user where it should live before writing more files there." in notice
    low = notice.lower()
    for bad in ("own folder", "move it", "move the", "delete", "remove"):
        assert bad not in low


@pytest.mark.parametrize("helper", ["_workspace_patterns", "_workspace_glob_matches", "_declared_dir_prefixes",
                                    "_read_root_text"])
def test_unexpected_helper_exception_returns_none(tmp_path, monkeypatch, helper):
    _npm_monorepo(tmp_path, ["apps/*"])

    def boom(*a, **k):
        raise RuntimeError("injected")

    monkeypatch.setattr(placer_mod, helper, boom)
    assert _check(tmp_path, "apps/web/package.json") is None
    assert _check(tmp_path, "other/x/package.json") is None


def test_formatter_never_raises():
    assert isinstance(_format_nested_manifest_notice({}), str)
