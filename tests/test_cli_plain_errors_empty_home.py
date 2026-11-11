"""Clean-machine errors: an empty HOME never turns into a folder at the filesystem root."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import workspace_root  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"


def _one_plain_line(err: str) -> str:
    assert "Traceback" not in err
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    return lines[0]


# --- [L2] empty HOME ------------------------------------------------------------------------


class _Account:
    def __init__(self, home: str) -> None:
        self.pw_dir = home


@pytest.fixture
def no_home(monkeypatch, tmp_path):
    """HOME is empty and the account database has no usable entry."""
    pwd = pytest.importorskip("pwd")

    def missing(_uid):
        raise KeyError("no account")

    monkeypatch.setattr(pwd, "getpwuid", missing)
    monkeypatch.setenv("HOME", "")
    monkeypatch.delenv("HERMES_REAL_HOME", raising=False)
    monkeypatch.setenv("TMPDIR", str(tmp_path))


@pytest.mark.parametrize("home", ["", "  "])
def test_empty_home_uses_the_account_home(monkeypatch, tmp_path, home):
    pwd = pytest.importorskip("pwd")
    account = tmp_path / "acct"
    account.mkdir()
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: _Account(str(account)))
    monkeypatch.setenv("HOME", home)
    assert workspace_root.default_projects_root() == account / workspace_root.DEFAULT_FOLDER_NAME


def test_empty_home_without_account_is_a_plain_error(no_home):
    with pytest.raises(workspace_root.WorkspaceRootError, match="HOME is empty or unset"):
        workspace_root.default_projects_root()


def test_account_home_at_root_is_refused(monkeypatch):
    pwd = pytest.importorskip("pwd")
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: _Account("/"))
    monkeypatch.setenv("HOME", "")
    with pytest.raises(workspace_root.WorkspaceRootError):
        workspace_root.default_projects_root()


def test_new_with_tilde_root_and_no_home_is_one_plain_line(no_home, monkeypatch, capsys):
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", "~/Projects")
    rc = cli_main(["new", "--template", "fake-rust-game", "--name", "Empty Home Demo",
                   "--templates-root", str(FIXTURES)])
    out, err = capsys.readouterr()
    assert rc == 1
    assert "/Projects/empty-home-demo" not in out
    assert "HOME is empty or unset" in _one_plain_line(err)


def test_folder_with_no_home_is_one_plain_line(no_home, monkeypatch, capsys):
    monkeypatch.delenv("HERMES_PROJECTS_ROOT", raising=False)
    rc = cli_main(["folder"])
    out, err = capsys.readouterr()
    assert rc == 1
    assert "/Tools" not in out
    line = _one_plain_line(err)
    assert line.startswith("defuzz folder: ") and "HOME is empty or unset" in line
    assert "Traceback" not in line and "DEFUZZ_DEBUG" not in line
