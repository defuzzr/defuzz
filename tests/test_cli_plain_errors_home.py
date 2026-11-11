"""Clean-machine errors: a read-only Hermes home gives one plain line; a dry run still works."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli as cli_mod  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"
_IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def _one_plain_line(err: str) -> str:
    assert "Traceback" not in err
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    return lines[0]


def _make_read_only(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        p = Path(dirpath)
        p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _restore_writable(root: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(root):
        Path(dirpath).chmod(0o755)
        for name in filenames:
            (Path(dirpath) / name).chmod(0o644)


@pytest.fixture
def read_only_home(tmp_path, monkeypatch):
    """A Hermes home (with the Hermes-set TMPDIR inside it) that cannot be written."""
    if _IS_ROOT:
        pytest.skip("root ignores file permissions")
    hermes_home = tmp_path / "hermes_home"
    scratch = hermes_home / "cache" / "scratch"
    scratch.mkdir(parents=True)
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    monkeypatch.setenv("TMPDIR", str(scratch))
    _make_read_only(hermes_home)
    try:
        yield hermes_home, projects
    finally:
        _restore_writable(hermes_home)


# --- [H1] read-only Hermes home -------------------------------------------------------------


def test_audit_quick_read_only_home_is_one_plain_line(read_only_home, capsys):
    hermes_home, _ = read_only_home
    rc = cli_main(["audit", "--quick"])
    err = capsys.readouterr().err
    assert rc == 1
    from hermes_plugins.defuzz.audit_surface import AUDIT_SCOPE_DISCLOSURE

    line = _one_plain_line(err.replace(AUDIT_SCOPE_DISCLOSURE, ""))
    assert "defuzz audit" in line and "not writable" in line
    assert str(hermes_home) in line


def test_run_read_only_home_is_one_plain_line(read_only_home, tmp_path, capsys):
    hermes_home, _ = read_only_home
    src = tmp_path / "src"
    src.mkdir()
    (src / "notes.md").write_text("n\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    rc = cli_main(["run", str(tmp_path / "copy"), "--source", str(src), "--staging", str(staging),
                   "--deterministic"])
    line = _one_plain_line(capsys.readouterr().err)
    assert rc == 1
    assert "defuzz run" in line and "not writable" in line and str(hermes_home) in line


def test_new_dry_run_read_only_home_still_works(read_only_home, capsys):
    _, projects = read_only_home
    rc = cli_main(["new", "--template", "fake-rust-game", "--name", "Ro Demo",
                   "--templates-root", str(FIXTURES)])
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert "Traceback" not in err
    assert f"Proposed repository: ro-demo -> {projects / 'ro-demo'}" in out
    assert not (projects / "ro-demo").exists()


def test_new_yes_read_only_home_is_one_plain_line(read_only_home, capsys, monkeypatch):
    hermes_home, projects = read_only_home
    monkeypatch.setattr(cli_mod, "REGISTER_PROJECT",
                        lambda name, path: json.dumps({"success": True, "id": "p1", "name": name, "path": path}))
    rc = cli_main(["new", "--template", "fake-rust-game", "--name", "Ro Demo", "--yes",
                   "--templates-root", str(FIXTURES)])
    line = _one_plain_line(capsys.readouterr().err)
    assert rc != 0
    assert "not writable" in line and str(hermes_home) in line
