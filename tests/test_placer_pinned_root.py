"""Automatic placement creates folders under the project root that the registry checked.

The tool call names a path; the project found above it is checked against the registry by
its real path. The folder that receives the file is created below that registered real
root, opened without following links, so a parent swapped for a link after the check
cannot move the new folder somewhere else. A project reached through a link the person
made (for example `~/Work -> /mnt/disk`) still works. Everything runs under tmp_path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

import hermes_plugins.defuzz.placer as placer  # noqa: E402

LAYOUTS = ["plain", "parent_link", "projects_link"]


def _rules() -> dict:
    return {
        "schema": 1,
        "schema_version": 1,
        "project_slug": "demo_proj",
        "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
        "placement_rules": [
            {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
        ],
    }


@pytest.fixture(params=LAYOUTS)
def project(request, tmp_path: Path, monkeypatch):
    kind = request.param
    hermes_home = tmp_path / "hermes_home"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    disk = tmp_path / "disk"
    disk.mkdir()
    if kind == "parent_link":
        (tmp_path / "Work").symlink_to(disk, target_is_directory=True)
        projects = tmp_path / "Work"
    elif kind == "projects_link":
        (tmp_path / "Projects").symlink_to(disk, target_is_directory=True)
        projects = tmp_path / "Projects"
    else:
        projects = disk
    real_root = disk / "proj"
    (real_root / ".adopt").mkdir(parents=True)
    (real_root / ".adopt" / "rules.json").write_text(json.dumps(_rules()), encoding="utf-8")
    placer.trust_project(projects / "proj")
    decoy_parent = tmp_path / "decoy"
    (decoy_parent / "proj").mkdir(parents=True)
    placer._reset_notice_state_for_tests()
    yield {"tmp": tmp_path, "disk": disk, "root": projects / "proj", "real_root": real_root, "decoy": decoy_parent}
    placer._reset_notice_state_for_tests()


def _pre(path: Path, call_id: str):
    return placer.on_pre_tool_call(tool_name="write_file", args={"path": str(path), "content": "# n"}, tool_call_id=call_id)


def test_placement_works_through_the_persons_links(project):
    result = _pre(project["root"] / "note.md", "tc_ok")
    assert result == {"action": "modify", "args": {"path": str(project["root"] / "docs" / "note.md")}}
    assert (project["real_root"] / "docs").is_dir()
    assert not os.path.islink(project["real_root"] / "docs")


def test_parent_swapped_after_the_check_is_refused(project, monkeypatch):
    real_check = placer._inspect_and_load_project_trust

    def check_then_swap(*a, **k):
        out = real_check(*a, **k)
        os.rename(project["disk"], project["tmp"] / "disk.held")
        project["disk"].symlink_to(project["decoy"], target_is_directory=True)
        return out

    monkeypatch.setattr(placer, "_inspect_and_load_project_trust", check_then_swap)
    result = _pre(project["root"] / "note.md", "tc_swap")
    assert result is not None and result["action"] == "block", result
    assert "defuzz safety refusal" in result["message"]
    assert sorted(p.name for p in (project["decoy"] / "proj").iterdir()) == []
    assert not (project["tmp"] / "disk.held" / "proj" / "docs").exists()


def test_project_folder_swapped_for_link_after_the_check_is_refused(project, monkeypatch):
    real_check = placer._inspect_and_load_project_trust

    def check_then_swap(*a, **k):
        out = real_check(*a, **k)
        os.rename(project["real_root"], project["disk"] / "proj.held")
        project["real_root"].symlink_to(project["decoy"] / "proj", target_is_directory=True)
        return out

    monkeypatch.setattr(placer, "_inspect_and_load_project_trust", check_then_swap)
    result = _pre(project["root"] / "note.md", "tc_swap2")
    assert result is not None and result["action"] == "block", result
    assert sorted(p.name for p in (project["decoy"] / "proj").iterdir()) == []
