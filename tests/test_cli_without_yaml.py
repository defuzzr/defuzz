"""The defuzz CLI sets up without PyYAML; YAML-parsing commands name the missing package in one line."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Loads the plugin package with ``yaml`` unimportable, builds the CLI parser and runs argv.
_PROBE = r'''
import argparse, importlib, importlib.abc, importlib.util, sys

class _BlockYaml(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "yaml" or name.startswith("yaml."):
            raise ModuleNotFoundError("No module named 'yaml'", name="yaml")
        return None

sys.meta_path.insert(0, _BlockYaml())
for key in [k for k in sys.modules if k == "yaml" or k.startswith("yaml.")]:
    del sys.modules[key]
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("defuzz_noyaml", root + "/__init__.py",
                                              submodule_search_locations=[root])
module = importlib.util.module_from_spec(spec)
sys.modules["defuzz_noyaml"] = module
spec.loader.exec_module(module)
cli = importlib.import_module("defuzz_noyaml.cli")
parser = argparse.ArgumentParser(prog="defuzz")
cli.setup_defuzz_cli(parser)
ns = parser.parse_args(sys.argv[2:])
sys.exit(cli.handle_defuzz_cli(ns))
'''

_SUBCOMMANDS = (
    "tools", "audit", "check", "scan", "copy", "rules", "apply", "run", "place", "trust",
    "templates", "kits", "new", "lint", "setup-tools", "folder",
)


def _run(tmp_path: Path, *argv: str) -> subprocess.CompletedProcess:
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("DEFUZZ")}
    env.update(HOME=str(home), HERMES_HOME=str(home / ".hermes"))
    return subprocess.run([sys.executable, "-c", _PROBE, str(REPO_ROOT), *argv], capture_output=True,
                          text=True, env=env, cwd=str(tmp_path), stdin=subprocess.DEVNULL, timeout=120)


@pytest.mark.parametrize("argv", [("--help",)] + [(cmd, "--help") for cmd in _SUBCOMMANDS])
def test_help_works_without_pyyaml(tmp_path: Path, argv: tuple) -> None:
    proc = _run(tmp_path, *argv)
    assert proc.returncode == 0, proc.stderr
    assert "usage:" in proc.stdout
    assert "Traceback" not in proc.stderr


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (("audit", "status"), "audit"),
        (("templates",), "templates"),
        (("new", "--template", "python-golden", "--name", "x"), "new"),
        (("folder", "set", "somewhere"), "folder set"),
    ],
)
def test_yaml_commands_name_the_missing_package(tmp_path: Path, argv: tuple, command: str) -> None:
    proc = _run(tmp_path, *argv)
    assert proc.returncode != 0
    assert proc.stderr.strip() == f"defuzz {command} needs the Python package PyYAML, which is not installed."


def test_folder_show_works_without_pyyaml(tmp_path: Path) -> None:
    proc = _run(tmp_path, "folder")
    assert proc.returncode == 0, proc.stderr
    assert "Projects folder" in proc.stdout


def test_scan_works_without_pyyaml(tmp_path: Path) -> None:
    target = tmp_path / "proj"
    target.mkdir()
    (target / "README.md").write_text("hi\n", encoding="utf-8")
    proc = _run(tmp_path, "scan", str(target))
    assert proc.returncode == 0, proc.stderr
    assert "PyYAML" not in proc.stderr
