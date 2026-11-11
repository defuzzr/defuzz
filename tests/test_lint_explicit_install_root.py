"""Explicit caller-chosen install roots retain setup safety and env filtering."""
import os
from pathlib import Path

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import lint_env, lint_setup


def test_explicit_install_root_is_shared_by_setup_and_execution(tmp_path):
    root = tmp_path / "work" / "lint-tools"
    (root / "bin").mkdir(parents=True)
    base = {"HOME": str(tmp_path / "home"), "PATH": "/usr/bin", "DEFUZZ_INSTALL_ROOT": str(root), "SECRET_TOKEN": "not-for-child"}
    assert lint_setup.install_root(base) == root
    env = lint_env.build_env(base)
    assert env["PATH"].split(os.pathsep)[0] == str(root / "bin")
    assert "SECRET_TOKEN" not in env
    assert "DEFUZZ_INSTALL_ROOT" not in env
    lint_setup._assert_managed_path(root / "bin", root, env=base)


def test_relative_explicit_install_root_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        lint_setup.install_root({"DEFUZZ_INSTALL_ROOT": "relative/tools"})


def test_side_environment_wins_without_exporting_configuration(tmp_path):
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    interpreter = venv / "bin/python"
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o755)
    env = lint_env.build_env({"DEFUZZ_LINT_PYTHON": str(interpreter), "PATH": "/usr/bin"})
    assert env["PATH"].split(os.pathsep)[0] == str(interpreter.parent)
    assert "DEFUZZ_LINT_PYTHON" not in env


@pytest.mark.parametrize("value", ["relative/python", "/nonexistent/venv/bin/python"])
def test_invalid_side_environment_fails_closed(value):
    with pytest.raises(ValueError, match="DEFUZZ_LINT_PYTHON"):
        lint_env.build_env({"DEFUZZ_LINT_PYTHON": value})


def test_manual_lint_does_not_check_global_setup(monkeypatch, tmp_path, capsys):
    from argparse import Namespace
    from hermes_plugins.defuzz import cli

    def forbidden():
        raise AssertionError("manual lint must not inspect unrelated toolchains")

    monkeypatch.setattr(cli, "status", forbidden)
    monkeypatch.setattr(cli, "run_lint", lambda *a: {"ok": True, "findings": []})
    assert cli._handle_lint_subcommand(Namespace(project=str(tmp_path), mode="both", as_json=True)) == 0
    assert '"ok": true' in capsys.readouterr().out
