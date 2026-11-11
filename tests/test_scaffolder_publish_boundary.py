"""Template accept must not publish a half-made project or follow a swapped projects folder."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError, accept, propose  # noqa: E402
from hermes_plugins.defuzz.templates import CheckSpec, RepoSpec, TemplateSpec  # noqa: E402


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "p1"})


def _template(tmp_path: Path, *, marker: Path | None = None) -> TemplateSpec:
    root = tmp_path / "tpl"
    repo = root / "tmpl_prefix"
    repo.mkdir(parents=True)
    (repo / "README.md").write_text("tmpl_prefix\n", encoding="utf-8")
    check = None
    if marker is not None:
        check = CheckSpec(cmd=(sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"))
    return TemplateSpec(
        id="mini",
        name="Mini",
        summary="Minimal template.",
        kind="lib",
        layout="mono",
        languages=("python",),
        engine=None,
        tags=(),
        needs=(),
        placeholder="tmpl_prefix",
        substitute_in=("**/*.md",),
        repos=(RepoSpec(name="tmpl_prefix", check=check),),
        root=root,
    )


def _snapshot(path: Path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


def test_accept_without_git_refuses_before_check_and_publishes_nothing(tmp_path, monkeypatch):
    marker = tmp_path / "check-ran"
    spec = _template(tmp_path, marker=marker)
    projects = tmp_path / "projects"
    projects.mkdir()
    proposal = propose(spec, "Demo", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))

    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")

    message = str(caught.value)
    assert "git is required" in message
    assert "Traceback" not in message
    assert not marker.exists(), "the check ran although git was missing"
    assert not os.path.lexists(projects / "demo")
    assert list(projects.iterdir()) == []


def test_accept_refuses_projects_folder_swapped_for_link_after_propose(tmp_path):
    spec = _template(tmp_path)
    projects = tmp_path / "projects"
    projects.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel.txt").write_text("keep", encoding="utf-8")
    proposal = propose(spec, "Demo", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")

    moved = tmp_path / "projects-moved"
    projects.rename(moved)
    projects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db")

    assert "changed" in str(caught.value)
    assert _snapshot(outside) == ["sentinel.txt"]
    assert (outside / "sentinel.txt").read_text(encoding="utf-8") == "keep"
    assert list(moved.iterdir()) == []
    assert proposal.repos[0].staged.is_dir(), "staging must be kept for discard"


def test_accept_refuses_missing_projects_folder_created_as_link_after_propose(tmp_path):
    spec = _template(tmp_path)
    base = tmp_path / "base"
    base.mkdir()
    projects = base / "projects"  # does not exist yet; accept would create it
    outside = tmp_path / "outside"
    outside.mkdir()
    proposal = propose(spec, "Demo", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")

    projects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ScaffoldError):
        accept(proposal, register=_register, db_path=tmp_path / "s.db")

    assert _snapshot(outside) == []


def test_accept_refuses_projects_folder_replaced_by_other_folder(tmp_path):
    spec = _template(tmp_path)
    projects = tmp_path / "projects"
    projects.mkdir()
    proposal = propose(spec, "Demo", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")

    projects.rename(tmp_path / "projects-old")
    projects.mkdir()

    with pytest.raises(ScaffoldError):
        accept(proposal, register=_register, db_path=tmp_path / "s.db")

    assert list(projects.iterdir()) == []


def test_accept_keeps_configured_symlinked_projects_folder(tmp_path):
    spec = _template(tmp_path)
    real = tmp_path / "real-projects"
    real.mkdir()
    link = tmp_path / "projects-link"
    link.symlink_to(real, target_is_directory=True)
    proposal = propose(spec, "Demo", {}, dest_root=link, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")

    result = accept(proposal, register=_register, db_path=tmp_path / "s.db")

    assert result.repos[0]["path"] == str(link / "demo")
    assert (real / "demo" / "README.md").read_text(encoding="utf-8") == "demo\n"
    assert (real / "demo" / ".git").is_dir()
    assert link.is_symlink()


def test_accept_creates_missing_projects_folder(tmp_path):
    spec = _template(tmp_path)
    projects = tmp_path / "a" / "b" / "projects"
    proposal = propose(spec, "Demo", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")

    result = accept(proposal, register=_register, db_path=tmp_path / "s.db")

    assert result.repos[0]["path"] == str(projects / "demo")
    assert (projects / "demo" / ".git").is_dir()
    assert not os.path.islink(projects)


def test_accept_refusal_does_not_remove_existing_user_folder(tmp_path):
    spec = _template(tmp_path)
    projects = tmp_path / "projects"
    projects.mkdir()
    proposal = propose(spec, "Demo", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")
    mine = projects / "demo"
    mine.mkdir()
    (mine / "notes.txt").write_text("mine", encoding="utf-8")

    with pytest.raises(ScaffoldError):
        accept(proposal, register=_register, db_path=tmp_path / "s.db")

    assert (mine / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert _snapshot(mine) == ["notes.txt"]
    shutil.rmtree(proposal.staging_dir, ignore_errors=True)


def test_two_previews_share_a_projects_folder_created_by_the_first_accept(tmp_path):
    spec = _template(tmp_path)
    projects = tmp_path / "new-root"
    first = propose(spec, "One", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")
    second = propose(spec, "Two", {}, dest_root=projects, staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")

    accept(first, register=_register, db_path=tmp_path / "s.db")
    accept(second, register=_register, db_path=tmp_path / "s.db")

    assert sorted(p.name for p in projects.iterdir()) == ["one", "two"]
