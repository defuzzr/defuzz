"""Clean-machine errors: a missing or too-old git gives one plain line, never a traceback."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import safety  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402

_REAL_GIT = shutil.which("git")


def _git_repo(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "README.md").write_text("# demo\n", encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(path.parent), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(["git", "init", "-q", str(path)], check=True, env=env)


def _bin_dir(tmp_path: Path, git_version: str | None) -> Path:
    """A PATH entry with no real git; optionally a fake git that only reports a version."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if git_version is not None:
        fake = bin_dir / "git"
        fake.write_text(f'#!/bin/sh\necho "git version {git_version}"\n', encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def _assert_one_plain_line(err: str, *needles: str) -> None:
    assert "Traceback" not in err
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    for needle in needles:
        assert needle in lines[0], lines[0]


@pytest.fixture(autouse=True)
def _fresh_git_check():
    getattr(safety, "_GIT_CHECKED", {}).clear()
    yield
    getattr(safety, "_GIT_CHECKED", {}).clear()


@pytest.mark.skipif(_REAL_GIT is None, reason="building the fixture repository needs git")
def test_scan_without_git_is_one_plain_line(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "proj"
    _git_repo(repo)
    monkeypatch.setenv("PATH", str(_bin_dir(tmp_path, None)))
    rc = cli_main(["scan", str(repo)])
    err = capsys.readouterr().err
    assert rc == 1
    _assert_one_plain_line(err, "defuzz scan", "git is required", "PATH")


def test_run_without_git_is_one_plain_line(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "notes.md").write_text("n\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setenv("PATH", str(_bin_dir(tmp_path, None)))
    rc = cli_main(["run", str(tmp_path / "copy"), "--source", str(src), "--staging", str(staging),
                   "--deterministic"])
    err = capsys.readouterr().err
    assert rc == 1
    _assert_one_plain_line(err, "defuzz run", "git is required")


def test_copy_works_without_git(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "notes.md").write_text("n\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(_bin_dir(tmp_path, None)))
    rc = cli_main(["copy", str(src), str(tmp_path / "copy")])
    assert rc == 0, capsys.readouterr().err
    assert (tmp_path / "copy" / "notes.md").is_file()


def test_old_git_is_one_plain_line_naming_both_versions(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "notes.md").write_text("n\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setenv("PATH", str(_bin_dir(tmp_path, "2.20.1")))
    rc = cli_main(["run", str(tmp_path / "copy"), "--source", str(src), "--staging", str(staging),
                   "--deterministic"])
    err = capsys.readouterr().err
    assert rc == 1
    _assert_one_plain_line(err, "defuzz run", "2.23.0", "2.20.1")


@pytest.mark.parametrize("text, ok", [
    ("git version 2.23.0", True),
    ("git version 2.43.0.windows.1", True),
    ("git version 2.39.3 (Apple Git-145)", True),
    ("git version 2.22.5", False),
    ("git version 1.9.1", False),
])
def test_git_version_parse(text, ok):
    found = safety._parse_git_version(text)
    assert found is not None
    assert (found >= safety.MIN_GIT_VERSION) is ok


@pytest.mark.skipif(_REAL_GIT is None, reason="needs a real git")
def test_installed_git_passes_the_check_once(tmp_path, monkeypatch):
    calls = []
    real_run = subprocess.run

    def counting(cmd, *a, **kw):
        if list(cmd[-1:]) == ["--version"]:
            calls.append(cmd)
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(safety.subprocess, "run", counting)
    repo = tmp_path / "proj"
    _git_repo(repo)
    for _ in range(3):
        assert safety.run_git_hardened(repo, ["rev-parse", "--git-dir"]).returncode == 0
    assert len(calls) == 1


@pytest.mark.skipif(_REAL_GIT is None, reason="adopting the fixture project needs git")
def test_place_without_git_is_one_plain_line(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "notes.md").write_text("n\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    copy_dir = tmp_path / "copy"
    assert cli_main(["run", str(copy_dir), "--source", str(src), "--staging", str(staging),
                     "--deterministic"]) == 0
    (copy_dir / "drop.unknown").write_text("payload\n", encoding="utf-8")
    capsys.readouterr()
    safety._GIT_CHECKED.clear()
    monkeypatch.setenv("PATH", str(_bin_dir(tmp_path, None)))
    # Placing a file needs no git, so it keeps working without it.
    assert cli_main(["place", "drop.unknown", "--root", str(copy_dir)]) == 0, capsys.readouterr().err
    assert (copy_dir / "_inbox" / "drop.unknown").is_file()
    capsys.readouterr()
    # Adding a rule commits the rules file, which needs git.
    rc = cli_main(["place", "--rule", ".xyz", "assets", "--root", str(copy_dir)])
    err = capsys.readouterr().err
    assert rc == 1
    _assert_one_plain_line(err, "defuzz place", "git is required")
