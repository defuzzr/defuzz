"""Manifest and packaging portability: optional-dependency import guard, ranges, platforms."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Loads the plugin package with ``yaml`` unimportable, registers it and calls the audit tool.
_PROBE = r'''
import importlib.abc, importlib.util, json, sys

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
tools = {}

class Ctx:
    def get_config(self, key, default):
        return default
    def register_tool(self, **kw):
        tools[kw["name"]] = kw
    def register_hook(self, *a, **kw):
        pass
    def register_cli_command(self, **kw):
        pass
    def register_command(self, **kw):
        pass

module.register(Ctx())
print(json.dumps({"tools": sorted(tools),
                  "audit": json.loads(tools["defuzz_audit"]["handler"]({"action": "status"}))}))
'''


def _manifest() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))


def test_plugin_registers_without_pyyaml_and_audit_names_the_package():
    proc = subprocess.run([sys.executable, "-c", _PROBE, str(REPO_ROOT)], capture_output=True,
                          text=True, timeout=120, env=dict(os.environ))
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["tools"] == ["defuzz_audit", "defuzz_place", "defuzz_project"]
    assert out["audit"]["ok"] is False
    assert out["audit"]["error"] == "defuzz audit needs the Python package PyYAML, which is not installed."


def test_python_dependencies_are_bounded_ranges_not_exact_pins():
    deps = _manifest()["python_dependencies"]
    assert len(deps) == 11
    for dep in deps:
        spec = dep.split(";", 1)[0]
        assert "==" not in spec, dep
        assert ">=" in spec and "<" in spec.replace("<=", ""), dep
    assert "PyYAML>=6.0.3,<7" in deps


def test_platforms_declared_linux():
    assert _manifest()["platforms"] == ["linux"]


def test_pytest_config_ships_importlib_mode():
    text = (REPO_ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert "--import-mode=importlib" in text
    assert "testpaths = tests" in text


@pytest.mark.parametrize("platform", ["darwin", "win32", "cygwin", "freebsd14"])
def test_register_refuses_every_system_but_linux(monkeypatch, caplog, platform):
    from tests import ensure_test_package
    plugin_init = ensure_test_package()
    calls = []

    class Ctx:
        def __getattr__(self, name):
            return lambda *a, **kw: calls.append(name)

    monkeypatch.setattr(sys, "platform", platform)
    with caplog.at_level("WARNING"):
        plugin_init.register(Ctx())
    assert calls == []
    assert "Defuzz supports Linux only." in caplog.text


@pytest.mark.parametrize("version", [(3, 11, 9), (3, 12, 7)])
def test_register_refuses_python_older_than_3_13(monkeypatch, caplog, version):
    from tests import ensure_test_package
    plugin_init = ensure_test_package()
    calls = []

    class Ctx:
        def __getattr__(self, name):
            return lambda *a, **kw: calls.append(name)

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "version_info", version + ("final", 0))
    with caplog.at_level("WARNING"):
        plugin_init.register(Ctx())
    assert calls == []
    assert "Defuzz needs Python 3.13 or newer." in caplog.text


@pytest.mark.parametrize("version", [(3, 13, 0), (3, 14, 9)])
def test_register_proceeds_on_python_3_13_and_newer(monkeypatch, caplog, version):
    from tests import ensure_test_package
    plugin_init = ensure_test_package()
    calls = []

    class Ctx:
        def get_config(self, key, default=None):
            return default

        def __getattr__(self, name):
            return lambda *a, **kw: calls.append(name)

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "version_info", version + ("final", 0))
    with caplog.at_level("WARNING"):
        plugin_init.register(Ctx())
    assert "register_tool" in calls and "register_cli_command" in calls
    assert "Defuzz needs Python" not in caplog.text
