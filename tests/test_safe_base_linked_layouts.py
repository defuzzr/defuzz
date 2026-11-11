"""Adopt flows keep working when the projects folder is reached through a link.

The folder a person chooses (a copy destination, a report folder) is trusted even when it is
reached through a link they made, for example `~/Work -> /mnt/disk`. Links found BELOW that
folder (inside the copy or the project) are still refused. Every case runs in a fake home
under pytest's tmp_path.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli, output_file, scaffolder, state_store, workspace_root  # noqa: E402
from hermes_plugins.defuzz.safety import SafetyError  # noqa: E402

LAYOUTS = ["plain", "projects_link", "parent_link", "home_link"]
OUTSIDE_BYTES = b"precious outside data\n"
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=LAYOUTS)
def layout(request, tmp_path: Path, monkeypatch):
    kind = request.param
    real_home = tmp_path / "realhome"
    real_home.mkdir()
    home = tmp_path / "home"
    if kind == "home_link":
        home.symlink_to(real_home, target_is_directory=True)
    else:
        home.mkdir()
    disk = tmp_path / "disk"
    disk.mkdir()
    if kind == "projects_link":
        projects = home / "Projects"
        projects.symlink_to(disk, target_is_directory=True)
    elif kind == "parent_link":
        (home / "Work").symlink_to(disk, target_is_directory=True)
        projects = home / "Work" / "Projects"
        projects.mkdir()
    else:
        projects = home / "Projects"
        projects.mkdir()
    hermes_home = home / ".hermes"
    hermes_home.mkdir()
    for key, val in (("HOME", home), ("USERPROFILE", home), ("HERMES_REAL_HOME", home), ("HERMES_HOME", hermes_home)):
        monkeypatch.setenv(key, str(val))
    monkeypatch.delenv("HERMES_PROJECTS_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    (source / "README.md").write_text("# Example\n", encoding="utf-8")
    (source / "main.py").write_text("print(1)\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.txt").write_bytes(OUTSIDE_BYTES)
    return {"kind": kind, "tmp": tmp_path, "home": home, "projects": projects, "source": source, "outside": outside}


def _main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main([str(a) for a in argv])
    return rc, out.getvalue() + err.getvalue()


def _outside_untouched(lay) -> None:
    assert sorted(p.name for p in lay["outside"].iterdir()) == ["victim.txt"]
    assert (lay["outside"] / "victim.txt").read_bytes() == OUTSIDE_BYTES


def _assert_run_done(lay, rc: int, text: str, dest: Path) -> None:
    """`run --source` copied, adopted, reported and wrote its completion marker last, in every
    layout: the marker is written below the copy folder the person chose."""
    assert rc == 0, text
    assert (dest / ".adopt" / "report.json").is_file(), text
    assert (dest / ".adopt" / "adopt-complete.json").is_file(), text
    _outside_untouched(lay)


def test_run_with_source_twice_reuses_finished_copy(layout):
    dest = layout["projects"] / "adopted-twice"
    argv = ["run", dest, "--source", layout["source"], "--inventory", layout["tmp"] / "inv-twice.json", "--deterministic"]
    rc, text = _main(argv)
    _assert_run_done(layout, rc, text, dest)
    rc, text = _main(argv)
    _assert_run_done(layout, rc, text, dest)


def test_run_marker_folder_that_is_a_link_still_refused(layout):
    dest = layout["projects"] / "adopted-planted"
    shutil.copytree(layout["source"], dest)
    (dest / ".adopt").symlink_to(layout["outside"], target_is_directory=True)
    with pytest.raises(SafetyError, match="symlink"):
        output_file.write_output_text(
            dest / ".adopt" / "adopt-complete.json", "{}\n", role="copy marker", base=dest
        )
    _outside_untouched(layout)


def _adopted(lay, name: str) -> Path:
    project = lay["projects"] / name
    shutil.copytree(lay["source"], project)
    return project


# ------------------------------------------------------------------ the folder setting itself


def test_folder_set_matches_old_behaviour(layout, monkeypatch):
    monkeypatch.setattr(workspace_root, "is_interactive_terminal", lambda *a, **k: True)
    rc, text = _main(["folder", "set", layout["projects"]])
    if layout["kind"] == "projects_link":
        # Unchanged older rule: a projects folder that is itself a link is refused.
        assert rc == 1 and "symbolic link" in text
    else:
        assert rc == 0, text
        assert workspace_root.resolve_projects_root().path is not None


# ------------------------------------------------------------------ copy / scan / run


def test_copy_into_new_folder(layout):
    dest = layout["projects"] / "copied"
    rc, text = _main(["copy", layout["source"], dest])
    assert rc == 0, text
    assert (dest / "README.md").read_bytes() == b"# Example\n"
    assert (dest / "main.py").is_file()


def test_copy_into_new_nested_folder(layout):
    dest = layout["projects"] / "group" / "deeper" / "copied"
    rc, text = _main(["copy", layout["source"], dest])
    assert rc == 0, text
    assert (dest / "README.md").is_file()


def test_copy_into_existing_empty_folder(layout):
    dest = layout["projects"] / "precreated"
    dest.mkdir()
    rc, text = _main(["copy", layout["source"], dest])
    assert rc == 0, text
    assert (dest / "README.md").is_file()


def test_copy_into_destination_that_is_a_link_stays_refused(layout):
    target = layout["tmp"] / "elsewhere"
    target.mkdir()
    dest = layout["projects"] / "linked-copy"
    dest.symlink_to(target, target_is_directory=True)
    rc, text = _main(["copy", layout["source"], dest])
    assert rc == 1
    assert list(target.iterdir()) == []


def test_scan_with_source_creates_copy(layout):
    dest = layout["projects"] / "scanned"
    rc, text = _main(["scan", dest, "--source", layout["source"], "--out", layout["tmp"] / "scan-inventory.json"])
    assert rc == 0, text
    assert (dest / "README.md").is_file()
    assert (layout["tmp"] / "scan-inventory.json").is_file()


def test_run_with_source_deterministic(layout):
    dest = layout["projects"] / "adopted"
    rc, text = _main(
        ["run", dest, "--source", layout["source"], "--inventory", layout["tmp"] / "inventory.json", "--deterministic"]
    )
    _assert_run_done(layout, rc, text, dest)
    assert (dest / "AGENTS.md").is_file()


# ------------------------------------------------------------------ external report


def test_apply_report_into_new_folder(layout):
    project = _adopted(layout, "existing")
    report = layout["projects"] / "reports" / "new" / "report.json"
    rc, text = _main(["apply", project, "--report", report])
    assert rc == 0, text
    assert json.loads(report.read_text(encoding="utf-8"))["copy_root"]
    assert (project / ".adopt" / "report.json").is_file()
    assert state_store.get_project(project) is not None


def test_apply_report_into_existing_folder(layout):
    project = _adopted(layout, "existing2")
    report = layout["projects"] / "reports" / "report.json"
    report.parent.mkdir()
    rc, text = _main(["apply", project, "--report", report])
    assert rc == 0, text
    assert report.is_file()


def test_run_report_into_new_folder(layout):
    dest = layout["projects"] / "adopted-r"
    report = layout["projects"] / "run-reports" / "report.json"
    rc, text = _main(
        [
            "run", dest, "--source", layout["source"], "--inventory", layout["tmp"] / "inv2.json",
            "--deterministic", "--report", report,
        ]
    )
    _assert_run_done(layout, rc, text, dest)
    assert report.is_file()


def test_report_folder_that_is_a_link_refused_before_any_work(layout):
    # Unchanged older rule: the folder that receives the report may not itself be a link.
    # It is now refused at the start: nothing is committed or registered.
    project = _adopted(layout, "existing3")
    elsewhere = layout["tmp"] / "elsewhere-reports"
    elsewhere.mkdir()
    linked = layout["projects"] / "linked-reports"
    linked.symlink_to(elsewhere, target_is_directory=True)
    rc, text = _main(["apply", project, "--report", linked / "report.json"])
    assert rc == 1
    assert list(elsewhere.iterdir()) == []
    assert not (project / ".adopt").exists()
    assert not (project / ".git").exists()
    assert state_store.get_project(project) is None


def test_run_report_folder_that_is_a_link_refused_before_copying(layout):
    elsewhere = layout["tmp"] / "elsewhere-run-reports"
    elsewhere.mkdir()
    linked = layout["projects"] / "linked-run-reports"
    linked.symlink_to(elsewhere, target_is_directory=True)
    dest = layout["projects"] / "never-copied"
    rc, text = _main(
        [
            "run", dest, "--source", layout["source"], "--inventory", layout["tmp"] / "inv3.json",
            "--deterministic", "--report", linked / "report.json",
        ]
    )
    assert rc == 1
    assert "symlink" in text
    assert not os.path.lexists(dest)
    assert list(elsewhere.iterdir()) == []


@pytest.mark.parametrize("flow", ["apply", "run"])
def test_report_parent_swapped_for_link_mid_run_is_refused(layout, monkeypatch, flow):
    # The report folder is opened at the start and kept: when a link is swapped into one of
    # its parent folders while the adoption runs, the chosen path no longer names that
    # folder, so the report is refused: nothing in the moved-away original, nothing elsewhere.
    from hermes_plugins.defuzz import applier

    reports = layout["projects"] / f"reports-{flow}"
    (reports / "inner").mkdir(parents=True)
    elsewhere = layout["tmp"] / f"elsewhere-{flow}"
    (elsewhere / "inner").mkdir(parents=True)
    held = layout["projects"] / f"reports-{flow}.held"
    # apply: swap once the adoption has started; run: swap between the copy and the adoption
    owner, attr = (applier, "_write_git_policy_files") if flow == "apply" else (cli, "scan_folder")
    real_step = getattr(owner, attr)

    def swap_then_continue(*a, **k):
        os.rename(reports, held)
        reports.symlink_to(elsewhere, target_is_directory=True)
        return real_step(*a, **k)

    monkeypatch.setattr(owner, attr, swap_then_continue)
    report = reports / "inner" / "report.json"
    if flow == "apply":
        argv = ["apply", _adopted(layout, "swap-apply"), "--report", report]
    else:
        argv = [
            "run", layout["projects"] / "swap-run", "--source", layout["source"],
            "--inventory", layout["tmp"] / "inv-swap.json", "--deterministic", "--report", report,
        ]
    rc, text = _main(argv)
    assert rc == 1, text
    assert "moved after it was opened" in text
    assert "Traceback" not in text
    assert not (held / "inner" / "report.json").exists(), text
    assert list((elsewhere / "inner").iterdir()) == []


def test_report_name_that_is_a_folder_refused_before_any_work(layout):
    project = _adopted(layout, "existing4")
    reports = layout["projects"] / "reports4"
    (reports / "report.json").mkdir(parents=True)
    rc, text = _main(["apply", project, "--report", reports / "report.json"])
    assert rc == 1
    assert not (project / ".adopt").exists()
    assert state_store.get_project(project) is None


# ------------------------------------------------------------------ links BELOW the chosen folder


def test_link_inside_project_still_refused(layout):
    project = _adopted(layout, "planted")
    (project / ".adopt").symlink_to(layout["outside"], target_is_directory=True)
    rc, text = _main(["apply", project])
    assert rc == 1
    _outside_untouched(layout)


def test_link_inside_report_folder_still_refused(layout):
    project = _adopted(layout, "planted2")
    report = layout["projects"] / "reports5" / "report.json"
    report.parent.mkdir()
    report.symlink_to(layout["outside"] / "victim.txt")
    rc, text = _main(["apply", project, "--report", report])
    assert rc == 1
    _outside_untouched(layout)
    assert not (project / ".adopt").exists()


# ------------------------------------------------------------------ creation flows (not changed here)


def test_new_template_through_layout(layout, monkeypatch):
    monkeypatch.setattr(scaffolder.toolchk, "probe", lambda *a, **k: ("1.0.0", "fixture-tool"))
    monkeypatch.setattr(
        cli, "REGISTER_PROJECT",
        lambda name, path: json.dumps({"success": True, "id": "t", "name": name, "path": path}),
    )
    answers = json.dumps({"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"})
    rc, text = _main(
        [
            "new", "--template", "fake-rust-game", "--name", "Linked Game",
            "--templates-root", REPO_ROOT / "tests" / "fixtures" / "templates",
            "--answers", answers, "--dest-root", layout["projects"], "--yes",
        ]
    )
    if layout["kind"] == "projects_link":
        # Unchanged older rule: a projects folder that is itself a link is refused.
        assert rc == 1 and "symbolic link" in text
        return
    assert rc == 0, text
    assert (layout["projects"] / "linked-game" / "Cargo.toml").is_file()
