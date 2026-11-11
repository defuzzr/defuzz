"""Tests for the web-golden template: manifest, rules, substitution, real creation, own CI and placement."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import toolchk  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.agents_md import DETAILS_PATH  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.linter import run_lint  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.naming import MAX_NAME_LENGTH, forms_from_slug, slugify  # noqa: E402
from hermes_plugins.defuzz.placer import (  # type: ignore[import-not-found]  # noqa: E402
    _reset_notice_state_for_tests,
    on_pre_tool_call,
)
from hermes_plugins.defuzz.scaffolder import (  # type: ignore[import-not-found]  # noqa: E402
    _matches_substitute_glob,
    accept,
    discard,
    propose,
)
from hermes_plugins.defuzz.templates import load_template  # type: ignore[import-not-found]  # noqa: E402
from tests.template_lint_known import assert_lint_clean_or_known  # noqa: E402
from tests.toolchain_needs import check_tools, need, need_lint_tools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "web-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"
TOKEN = "tmpl_prefix"
LEFTOVER_TOKENS = ("tmpl_prefix", "tmpl-prefix", "TMPL_PREFIX", "TmplPrefix")
LONG_HYPHENATED = "very-long-project-name-very-long-project-name-very-long-projectx"
NAMES = ("a", "my-site", LONG_HYPHENATED)
# Same key order as the other bundled manifests (ts-node-golden without `options`).
EXPECTED_KEYS = [
    "id", "name", "summary", "kind", "layout", "languages", "tags", "needs",
    "placeholder", "substitute_in", "locked", "approved_deps", "repos",
]
GENERATED_FOLDERS = ("node_modules", "dist", ".xtask-cache")


def _lockfile_package_names() -> list[str]:
    """Every package name in pnpm-lock.yaml: packages/snapshots keys and the packages they name."""
    names: set[str] = set()

    def base(key: str) -> str:
        key = key.split("(", 1)[0]
        return key.rsplit("@", 1)[0] if key.rfind("@") > 0 else key

    for doc in yaml.safe_load_all((TMPL_REPO_DIR / "pnpm-lock.yaml").read_text(encoding="utf-8")):
        if not isinstance(doc, dict):
            continue
        for section in ("packages", "snapshots"):
            for key, body in (doc.get(section) or {}).items():
                names.add(base(str(key)))
                for dep_kind in ("dependencies", "optionalDependencies"):
                    names.update(str(n) for n in ((body or {}).get(dep_kind) or {}))
        for importer in (doc.get("importers") or {}).values():
            for dep_kind in ("dependencies", "devDependencies", "optionalDependencies"):
                names.update(str(n) for n in ((importer or {}).get(dep_kind) or {}))
    return sorted(names)


def test_manifest_keys_values_and_loader() -> None:
    data = yaml.safe_load(TEMPLATE_YAML.read_text(encoding="utf-8"))
    assert list(data) == EXPECTED_KEYS
    assert data["id"] == TEMPLATE_DIR.name == "web-golden"
    assert (data["kind"], data["layout"], data["languages"]) == ("app", "mono", ["typescript"])
    assert data["needs"] == ["node", "pnpm"]
    assert "website" in data["tags"] and "static" in data["tags"]
    assert data["placeholder"] == TOKEN

    spec = load_template(TEMPLATE_DIR)
    assert spec.repos[0].name == TOKEN
    check = spec.repos[0].check
    assert check is not None
    assert check.prepare == ("pnpm", "xtask", "prepare-scaffold")
    assert check.cmd == ("pnpm", "xtask", "ci")
    assert check.cwd == "."
    for pattern in spec.locked:
        hits = [p for p in TMPL_REPO_DIR.rglob("*") if p.is_file() and _glob_hit(p, pattern)]
        assert hits, f"locked glob {pattern!r} matches no shipped file"


def _glob_hit(path: Path, pattern: str) -> bool:
    from hermes_plugins.defuzz.scaffolder import _matches_locked_glob

    return _matches_locked_glob(path.relative_to(TMPL_REPO_DIR).as_posix(), [pattern])


def test_approved_deps_equal_every_package_in_the_lockfile() -> None:
    spec = load_template(TEMPLATE_DIR)
    assert dict(spec.approved_deps) == {"typescript": tuple(_lockfile_package_names())}


def test_shipped_files_leave_creation_files_to_the_scaffolder() -> None:
    names = {p.relative_to(TMPL_REPO_DIR).as_posix() for p in TMPL_REPO_DIR.rglob("*")}
    assert "TOOLS.lock" not in names, "floors live in .nvmrc / engines / packageManager, as in ts-node-golden"
    assert not any(n == ".adopt" or n.startswith(".adopt/") for n in names)
    assert not any(part in GENERATED_FOLDERS for n in names for part in Path(n).parts)
    # The template's own agent rules; creation keeps them as docs/AGENTS.template.md.
    agents = (TMPL_REPO_DIR / "AGENTS.md").read_text(encoding="utf-8")
    assert agents.startswith("# Rules for agents working in this project\n\n")
    assert "Proposal for the integrator" not in agents
    assert "pnpm xtask ci" in agents


def test_tool_floors_match_ts_node_golden() -> None:
    """Same floors as ts-node-golden, stated the same way: node >= 24, pnpm 12.15.0."""
    for template in ("web-golden", "ts-node-golden"):
        root = REPO_ROOT / "templates" / template / "tmpl_prefix"
        pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
        assert (root / ".nvmrc").read_text(encoding="utf-8").strip() == "24", template
        assert pkg["engines"] == {"node": ">=24"}, template
        assert pkg["packageManager"] == "pnpm@12.15.0", template
        assert "engine-strict=true" in (root / ".npmrc").read_text(encoding="utf-8"), template


def test_rules_validate_and_every_declared_folder_exists() -> None:
    rules = json.loads((TEMPLATE_DIR / "rules.json").read_text(encoding="utf-8"))
    assert set(rules) == {"declared_dirs", "placement_rules", "protected_root_files"}
    for entry in rules["declared_dirs"]:
        assert entry["source"] == "explicit"
        assert (TMPL_REPO_DIR / entry["dir"]).is_dir(), entry["dir"]
    kinds = {pr["kind"]: pr for pr in rules["placement_rules"]}
    assert set(kinds) == {"docs", "test"}
    assert kinds["test"]["match_glob"] == ["*.test.ts", "*.spec.ts"]
    assert kinds["test"]["dest_dir"] == "tests/unit"
    assert ".xtask-cache" in rules["protected_root_files"]


def _substituted_files(text_root: Path, spec, slug: str) -> dict[str, bytes]:
    snake = forms_from_slug(slug).snake
    out: dict[str, bytes] = {}
    for path in sorted(text_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(text_root).as_posix()
        data = path.read_bytes()
        if _matches_substitute_glob(rel, spec.substitute_in):
            data = data.replace(TOKEN.encode(), snake.encode())
        out[rel] = data
    return out


@pytest.mark.parametrize("name", NAMES, ids=lambda n: f"len-{len(n)}-{n[:12]}")
def test_propose_substitutes_every_occurrence_and_nothing_else(tmp_path: Path, name: str) -> None:
    assert len(LONG_HYPHENATED) == MAX_NAME_LENGTH
    spec = load_template(TEMPLATE_DIR)
    shipped = sum(
        p.read_text(encoding="utf-8").count(TOKEN)
        for p in TMPL_REPO_DIR.rglob("*")
        if p.is_file() and _matches_substitute_glob(p.relative_to(TMPL_REPO_DIR).as_posix(), spec.substitute_in)
    )
    assert shipped > 0
    proposal = propose(
        spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=tmp_path / "dest", staging_parent=tmp_path / "staging",
    )
    try:
        slug = slugify(name)
        staged = proposal.repos[0].staged
        got = {
            p.relative_to(staged).as_posix(): p.read_bytes() for p in sorted(staged.rglob("*")) if p.is_file()
        }
        assert got == _substituted_files(TMPL_REPO_DIR, spec, slug)
        for rel, data in got.items():
            for token in LEFTOVER_TOKENS:
                assert token not in rel and token.encode() not in data, f"leftover {token!r} in {rel}"
        pkg = json.loads(got["package.json"])
        assert pkg["name"] == forms_from_slug(slug).snake
    finally:
        discard(proposal)


def _run(cmd: list[str], cwd: Path, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


@pytest.mark.skipif(os.environ.get("ADOPT_SKIP_SLOW") == "1", reason="ADOPT_SKIP_SLOW=1")
@pytest.mark.parametrize("name", NAMES, ids=lambda n: f"len-{len(n)}-{n[:12]}")
def test_created_project_passes_its_checks_and_places_root_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)
    spec = load_template(TEMPLATE_DIR)
    need(*check_tools(spec))
    projects = tmp_path / "projects"
    db_path = tmp_path / "state.db"
    proposal = propose(
        spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=projects, staging_parent=tmp_path / "staging",
    )
    result = accept(
        proposal, register=lambda *_: json.dumps({"success": True, "id": "web-golden-test"}),
        db_path=db_path, timeout_s=900,
    )
    repo_info = result.repos[0]
    assert repo_info["check"] == "ok", repo_info
    repo = Path(repo_info["path"])
    assert repo.parent == projects and repo.name == slugify(name)

    # Files the scaffolder writes at creation.
    rules = json.loads((repo / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    shipped_rules = json.loads((TEMPLATE_DIR / "rules.json").read_text(encoding="utf-8"))
    assert rules["project_slug"] == slugify(name)
    assert rules["placement_rules"] == shipped_rules["placement_rules"]
    assert rules["protected_root_files"] == shipped_rules["protected_root_files"]
    assert [d["dir"] for d in rules["declared_dirs"]] == [d["dir"] for d in shipped_rules["declared_dirs"]]
    agents = (repo / "AGENTS.md").read_text(encoding="utf-8")
    assert agents.startswith(f"# {slugify(name)}\n")
    details = repo / DETAILS_PATH
    guide = agents + (details.read_text(encoding="utf-8") if details.is_file() else "")
    for declared in ("design/tokens/", "src/pages/", "tests/unit/", "tools/xtask/"):
        assert f"`{declared}`" in guide, declared
    assert "`tests/unit/`" in guide and "`.ts` files go in" in guide
    assert (repo / "docs" / "AGENTS.template.md").read_text(encoding="utf-8") == (
        TMPL_REPO_DIR / "AGENTS.md"
    ).read_text(encoding="utf-8")
    lock = toolchk.load_lock(repo / "TOOLS.lock")
    assert set(lock["tools"]) == {"node", "pnpm"}
    assert all(entry["source"] == "auto" for entry in lock["tools"].values())
    # The lock records the node found on this machine; `.nvmrc`'s 24 is kept as the floor.
    node_entry = lock["tools"]["node"]
    assert node_entry["minimum"] == "24"
    assert node_entry["version"] == toolchk.probe("node", node_entry, repo)[0]
    assert not toolchk.version_below(node_entry["version"], "24")
    assert not toolchk.version_below(lock["tools"]["pnpm"]["version"], "12.15.0")
    assert _run(["git", "status", "--porcelain"], repo).stdout == ""
    committed = _run(["git", "ls-files"], repo).stdout.splitlines()
    assert not any(part in GENERATED_FOLDERS for rel in committed for part in Path(rel).parts)

    # The project's own checks, in the delivered tree.
    for cmd in (["pnpm", "xtask", "prepare-scaffold"], ["pnpm", "xtask", "ci"]):
        proc = _run(cmd, repo)
        assert proc.returncode == 0, f"{cmd}\n{proc.stdout}\n{proc.stderr}"
        assert proc.stdout.rstrip().splitlines()[-1].startswith("xtask: "), proc.stdout
    assert (repo / ".xtask-cache").is_dir()
    assert _run(["git", "status", "--porcelain"], repo).stdout == ""

    # Placement: loose root files the rules cover move; nothing else does.
    _reset_notice_state_for_tests()
    cases = {
        "notes.md": "docs/notes.md",
        "thing.test.ts": "tests/unit/thing.test.ts",
        "thing.spec.ts": "tests/unit/thing.spec.ts",
        "hero.png": None,
        "logo.svg": None,
        "home.e2e.ts": None,
        "helper.ts": None,
        "CHANGELOG.md": None,
        "README.md": None,
        "vite.config.ts": None,
        ".xtask-cache/tmp/scratch.md": None,
        "dist/notes.md": None,
        "src/pages/notes.md": None,
    }
    for idx, (rel, expected) in enumerate(cases.items()):
        pre = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(repo / rel), "content": "x\n"},
            tool_call_id=f"wg_place_{idx}",
            db_path=db_path,
        )
        if expected is None:
            assert pre is None, f"{rel} should stay, got {pre!r}"
        else:
            assert pre is not None and pre["action"] == "modify", f"{rel} should move to {expected}"
            assert Path(pre["args"]["path"]).relative_to(repo).as_posix() == expected

    # The same lint gate the other template tests run.
    report = run_lint(repo, env=dict(os.environ), db_path=db_path)
    need_lint_tools(report)
    assert_lint_clean_or_known(spec.id, report)
    assert "pnpm-lock.yaml" in report["skipped_generated"], report
