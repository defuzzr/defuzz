"""Packaging ranges: the audit's PyYAML range rests on behaviour; the suite needs the SDK."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, load_submodule

structured = load_submodule("audit.outward_structured")
facts = load_submodule("audit.facts")
yaml = pytest.importorskip("yaml")


@pytest.fixture
def fresh_probe(monkeypatch):
    monkeypatch.setattr(structured, "_yaml_probed", set())


def test_accepted_range_matches_manifest():
    manifest = yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text())
    assert f"PyYAML{structured.YAML_ACCEPTED}" in manifest["python_dependencies"]


@pytest.mark.parametrize("version", ["6.0.3", "6.0.4", "6.0.10", "6.1", "6.9.9"])
def test_versions_inside_range_are_accepted(monkeypatch, fresh_probe, version):
    monkeypatch.setattr(yaml, "__version__", version)
    structured.check_audit_yaml(yaml)
    assert facts._parse_simple_yaml_mapping("a: 1\n") == {"a": 1}


@pytest.mark.parametrize("version", ["6.0.2", "6.0", "5.4.1", "7.0", "7.0.0", "7.0.0.dev0", "6.1.0rc1", "", None])
def test_versions_outside_range_fail_with_one_line(monkeypatch, fresh_probe, version):
    if version is None:
        monkeypatch.delattr(yaml, "__version__")
    else:
        monkeypatch.setattr(yaml, "__version__", version)
    expected = f"Audit requires PyYAML >=6.0.3,<7; found {version or 'unknown'}"
    for call in (lambda: structured.check_audit_yaml(yaml),
                 lambda: facts._parse_simple_yaml_mapping("a: 1\n"),
                 lambda: structured.parse_data(Path("x.yaml"), b"a: 1\n")):
        with pytest.raises(ValueError) as info:
            call()
        assert str(info.value) == expected


def test_missing_parser_names_it(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(ValueError, match=r"^Audit requires PyYAML >=6\.0\.3,<7; found none$"):
        structured.parse_data(Path("x.yaml"), b"a: 1\n")


# Behaviour the audit relies on, checked on whatever PyYAML is installed.

def test_installed_parser_passes_probe():
    assert structured._yaml_probe(yaml) is None


@pytest.mark.parametrize("doc", ["!!python/object/apply:os.getcwd []", "a: !!python/name:os.system\n",
                                 "a: !custom 1\n", "a: !!binary aGk=\n"])
def test_tags_never_construct_objects(doc):
    with pytest.raises(ValueError):
        facts._parse_simple_yaml_mapping(doc)


def test_duplicate_keys_rejected_and_merge_override_allowed():
    with pytest.raises(facts.DuplicateConfigKeyError):
        facts._parse_simple_yaml_mapping("a: 1\na: 2\n", reject_duplicate_keys=True)
    with pytest.raises(facts.DuplicateConfigKeyError):
        facts._parse_simple_yaml_mapping("x: {k: 1, k: 2}\n", reject_duplicate_keys=True)
    assert facts._parse_simple_yaml_mapping("a: 1\na: 2\n") == {"a": 2}  # documented default
    merged = facts._parse_simple_yaml_mapping("b: &b {k: 1}\nx: {<<: *b, k: 2}\n", reject_duplicate_keys=True)
    assert merged["x"] == {"k": 2}


def test_aliases_are_bounded_and_recursion_rejected():
    laughs = "a: &a [x, x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{', '.join('*' + chr(97 + i) for _ in range(10))}]\n" for i in range(5))
    with pytest.raises(ValueError, match="budget"):
        facts._parse_simple_yaml_mapping(laughs)
    with pytest.raises(ValueError):
        facts._parse_simple_yaml_mapping("a: &a [*a]\n")
    with pytest.raises(ValueError):
        structured.parse_data(Path("x.yaml"), laughs.encode())


def test_changed_mapping_hook_fails_closed(monkeypatch, fresh_probe):
    """A release that stops calling flatten_mapping must be refused, not trusted by version."""
    safe, base = yaml.constructor.SafeConstructor, yaml.constructor.BaseConstructor
    original_flatten = safe.flatten_mapping

    def construct_mapping(self, node, deep=False):  # merges still work, override bypassed
        if isinstance(node, yaml.MappingNode):
            original_flatten(self, node)
        return base.construct_mapping(self, node, deep=deep)

    monkeypatch.setattr(safe, "construct_mapping", construct_mapping)
    with pytest.raises(ValueError) as info:
        facts._parse_simple_yaml_mapping("a: 1\n")
    assert str(info.value) == (f"Audit requires PyYAML >=6.0.3,<7; found {yaml.__version__}, "
                               "which fails the check: mapping hook called for every mapping")


def _collect_without_sdk(tmp_path, folder_name):
    """Collect one test file in a copy of the checkout named folder_name, SDK hidden."""
    import shutil
    shadow = tmp_path / "shadow"
    shadow.mkdir(exist_ok=True)
    (shadow / "plugins.py").write_text("")  # `plugins` is not a package: SDK unimportable
    copy = tmp_path / folder_name
    shutil.copytree(REPO_ROOT, copy, symlinks=True, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", ".pytest_cache", ".worktrees", "templates"))
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTEST_ADDOPTS"}}
    env["PYTHONPATH"] = str(shadow)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         "tests/test_manifest_portability.py"],
        cwd=copy, env=env, capture_output=True, text=True, timeout=120)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def test_suite_without_hermes_sdk_stops_with_one_line(tmp_path):
    # A folder name that is not a Python identifier (GitHub's ZIP gives `defuzz-main`):
    # the root is no package, tests/conftest.py runs first and prints one line.
    status, output = _collect_without_sdk(tmp_path, "defuzz-main")
    assert status == 4, output
    assert "Traceback" not in output and "ImportError while loading" not in output
    lines = output.splitlines()
    assert len(lines) == 1, output
    assert lines[0].startswith("Defuzz tests need a Hermes Agent source checkout on the import path (")
    assert "`PYTHONPATH=/path/to/hermes-agent python -m pytest tests/...`" in lines[0]


def test_suite_without_hermes_sdk_in_defuzz_folder_stops_with_import_error(tmp_path):
    # `git clone` and `hermes plugins install` give `defuzz`, a valid identifier: pytest
    # imports the root package before tests/conftest.py, so the run stops on its import.
    status, output = _collect_without_sdk(tmp_path, "defuzz")
    assert status == 4, output
    assert "ImportError while loading conftest" in output
    assert "No module named 'plugins" in output
    assert "Defuzz tests need a Hermes Agent" not in output
