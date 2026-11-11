"""Project-side writes must not follow links planted inside the project.

The preflight record lands in ``<project>/.adopt/preflight.json``. A project the user did not create (for example a
cloned repository) may ship ``.adopt`` or ``.adopt/preflight.json`` as a symlink; the record must never write through
either. Every victim file and folder lives under pytest's ``tmp_path``.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import threading

import pytest
from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli, toolchk  # noqa: E402

LOCK_TEXT = '[lock]\nschema = 1\nenforce = "warn"\nage_nudge_months = 12\nnetwork = false\n'


@pytest.fixture(autouse=True)
def _private_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    return home


def _project(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "TOOLS.lock").write_text(LOCK_TEXT, encoding="utf-8")
    return proj


def _report():
    return {"ok": True, "summary": "preflight ok", "tools": {}}


def _snapshot(folder):
    return sorted((p.name, p.read_bytes() if p.is_file() else None) for p in folder.iterdir())


def _run_bounded(fn, seconds=10.0):
    result: dict = {}

    def target():
        try:
            result["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test thread
            result["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "record hung"
    return result


# --- toolchk.record directly -------------------------------------------------------------------------------------


def test_normal_record_location_and_content_unchanged(tmp_path):
    proj = _project(tmp_path)
    report = _report()
    out = toolchk.record(report, proj / ".adopt")
    assert out == proj / ".adopt" / "preflight.json"
    assert out.read_text(encoding="utf-8") == json.dumps(report, indent=2) + "\n"
    assert stat.S_ISREG(os.lstat(out).st_mode)
    # Overwrites an existing regular record and leaves no temporary files behind.
    toolchk.record({"ok": False}, proj / ".adopt")
    assert json.loads(out.read_text(encoding="utf-8")) == {"ok": False}
    assert sorted(p.name for p in (proj / ".adopt").iterdir()) == ["preflight.json"]


def test_adopt_symlink_to_folder_is_refused_and_target_unchanged(tmp_path):
    proj = _project(tmp_path)
    victim = tmp_path / "home" / ".hermes"
    (victim / "keep.txt").write_text("keep", encoding="utf-8")
    before = _snapshot(victim)
    (proj / ".adopt").symlink_to(victim, target_is_directory=True)
    with pytest.raises(toolchk.PreflightError) as info:
        toolchk.record(_report(), proj / ".adopt")
    assert ".adopt" in info.value.report["summary"]
    assert "\n" not in info.value.report["summary"]
    assert _snapshot(victim) == before
    assert not (victim / "preflight.json").exists()


def test_leaf_symlink_is_replaced_and_target_byte_identical(tmp_path):
    proj = _project(tmp_path)
    victim = tmp_path / "outside.txt"
    victim.write_bytes(b"precious\x00bytes\n")
    (proj / ".adopt").mkdir()
    leaf = proj / ".adopt" / "preflight.json"
    leaf.symlink_to(victim)
    out = toolchk.record(_report(), proj / ".adopt")
    assert victim.read_bytes() == b"precious\x00bytes\n"
    assert not os.path.islink(out)
    assert stat.S_ISREG(os.lstat(out).st_mode)
    assert json.loads(out.read_text(encoding="utf-8"))["summary"] == "preflight ok"


def test_dangling_leaf_symlink_creates_nothing_outside(tmp_path):
    proj = _project(tmp_path)
    (proj / ".adopt").mkdir()
    missing = tmp_path / "elsewhere" / "created.json"
    (tmp_path / "elsewhere").mkdir()
    (proj / ".adopt" / "preflight.json").symlink_to(missing)
    out = toolchk.record(_report(), proj / ".adopt")
    assert not missing.exists()
    assert stat.S_ISREG(os.lstat(out).st_mode)


def test_dangling_adopt_symlink_is_refused(tmp_path):
    proj = _project(tmp_path)
    target = tmp_path / "not-yet"
    (proj / ".adopt").symlink_to(target, target_is_directory=True)
    with pytest.raises(toolchk.PreflightError):
        toolchk.record(_report(), proj / ".adopt")
    assert not target.exists()


def test_adopt_regular_file_is_refused(tmp_path):
    proj = _project(tmp_path)
    (proj / ".adopt").write_text("not a folder", encoding="utf-8")
    with pytest.raises(toolchk.PreflightError):
        toolchk.record(_report(), proj / ".adopt")
    assert (proj / ".adopt").read_text(encoding="utf-8") == "not a folder"


def test_fifo_at_leaf_does_not_hang(tmp_path):
    proj = _project(tmp_path)
    (proj / ".adopt").mkdir()
    os.mkfifo(proj / ".adopt" / "preflight.json")
    result = _run_bounded(lambda: toolchk.record(_report(), proj / ".adopt"))
    if "error" in result:
        assert isinstance(result["error"], toolchk.PreflightError)
    else:
        assert stat.S_ISREG(os.lstat(result["value"]).st_mode)


def test_folder_at_leaf_is_refused(tmp_path):
    proj = _project(tmp_path)
    (proj / ".adopt" / "preflight.json").mkdir(parents=True)
    with pytest.raises(toolchk.PreflightError):
        toolchk.record(_report(), proj / ".adopt")
    assert (proj / ".adopt" / "preflight.json").is_dir()


def test_project_reached_through_user_symlink_is_allowed(tmp_path):
    proj = _project(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(proj, target_is_directory=True)
    out = toolchk.record(_report(), alias / ".adopt")
    assert stat.S_ISREG(os.lstat(proj / ".adopt" / "preflight.json").st_mode)
    assert out == alias / ".adopt" / "preflight.json"


# --- the lint command entry (shared with the /defuzz lint chat command) -------------------------------------------


def _lint(proj, monkeypatch, as_json=False):
    monkeypatch.setattr(cli, "run_lint", lambda *a, **k: {"ok": True, "findings": []})
    return cli._handle_lint_subcommand(argparse.Namespace(project=str(proj), mode="both", as_json=as_json))


def test_lint_normal_project_records_preflight(tmp_path, monkeypatch, capsys):
    proj = _project(tmp_path)
    assert _lint(proj, monkeypatch) == 0
    data = json.loads((proj / ".adopt" / "preflight.json").read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert "No findings." in capsys.readouterr().out


def test_lint_adopt_symlink_refused_one_plain_line(tmp_path, monkeypatch, capsys):
    proj = _project(tmp_path)
    victim = tmp_path / "home" / ".hermes"
    before = _snapshot(victim)
    (proj / ".adopt").symlink_to(victim, target_is_directory=True)
    rc = _lint(proj, monkeypatch)
    captured = capsys.readouterr()
    assert rc != 0
    assert _snapshot(victim) == before
    assert "Traceback" not in captured.err + captured.out
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 1, captured.err
    assert ".adopt" in lines[0]


def test_lint_leaf_symlink_does_not_overwrite_outside_file(tmp_path, monkeypatch, capsys):
    proj = _project(tmp_path)
    victim = tmp_path / "outside.txt"
    victim.write_bytes(b"do not touch\n")
    (proj / ".adopt").mkdir()
    (proj / ".adopt" / "preflight.json").symlink_to(victim)
    assert _lint(proj, monkeypatch) == 0
    assert victim.read_bytes() == b"do not touch\n"
    assert not os.path.islink(proj / ".adopt" / "preflight.json")
    assert "Traceback" not in capsys.readouterr().err


def test_toolchk_main_record_refused_returns_code_without_traceback(tmp_path, capsys):
    proj = _project(tmp_path)
    victim = tmp_path / "victim-dir"
    victim.mkdir()
    (proj / ".adopt").symlink_to(victim, target_is_directory=True)
    rc = toolchk.main(["--all", "--project", str(proj), "--record", str(proj / ".adopt")])
    err = capsys.readouterr().err
    assert rc == 4
    assert list(victim.iterdir()) == []
    assert "Traceback" not in err
    assert "preflight record refused" in err
