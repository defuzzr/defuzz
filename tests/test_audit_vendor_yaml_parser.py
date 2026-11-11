"""Public inventory entry points must not guess YAML without the approved parser."""
import sys

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.audit.vendor import executable_inventory as inventory


CASES = [
    ({"plugin_manifests": [{"source_path": "/plugins/demo/plugin.yaml",
                            "manifest_text": "name: demo\nversion: '1'\n"}]},
     "executable_inventory.plugin_manifest_unverified"),
    ({"profiles": [{"config_path": "/profile/config.yaml",
                    "config_text": "hooks: {}\nmcp_servers: {}\n"}]},
     "executable_inventory.config_unverified"),
    ({"plugin_manifests": [{"plugin_dir": "/plugins/demo",
                            "manifest_data": {"name": "demo"},
                            "mcp_json_text": "mcpServers: {}\n"}]},
     "executable_inventory.mcp_declaration_unverified"),
]


@pytest.mark.parametrize("entry", [inventory.run, inventory.audit_executable_inventory])
@pytest.mark.parametrize("inputs,rule", CASES)
@pytest.mark.parametrize("parser_state", ["missing", "wrong_version"])
def test_unapproved_yaml_fails_closed(monkeypatch, entry, inputs, rule, parser_state):
    if parser_state == "missing":
        monkeypatch.setitem(sys.modules, "yaml", None)
    else:
        import yaml
        monkeypatch.setattr(yaml, "__version__", "6.0.2")
    result = entry(inputs)
    assert result["coverage"] == "could_not_verify"
    failures = [f for f in result["findings"] if f["id"] == rule]
    assert len(failures) == 1
    assert failures[0]["coverage"] == "could_not_verify"
    assert result["inventory"]["hooks"] == []
    assert result["inventory"]["mcp_servers"] == []
    if rule.endswith("plugin_manifest_unverified"):
        assert result["inventory"]["plugins"][0]["kind"] == "unknown"
        assert result["inventory"]["plugins"][0]["coverage"] == "could_not_verify"


@pytest.mark.parametrize("entry", [inventory.run, inventory.audit_executable_inventory])
@pytest.mark.parametrize("inputs,rule", CASES)
def test_approved_yaml_is_verified(entry, inputs, rule):
    import yaml
    from hermes_plugins.defuzz.audit.outward_structured import check_audit_yaml
    check_audit_yaml(yaml)  # installed PyYAML is inside the accepted range and behaves
    result = entry(inputs)
    assert result["coverage"] == "verified"
    assert not any(f["id"] == rule for f in result["findings"])
    if rule.endswith("plugin_manifest_unverified"):
        assert result["inventory"]["plugins"][0]["plugin_id"] == "demo"
        assert result["inventory"]["plugins"][0]["version"] == "1"


@pytest.mark.parametrize("text", ["", "# comment only", "name: [broken", "- scalar"])
def test_yaml_cannot_bypass_missing_parser(monkeypatch, text):
    monkeypatch.setitem(sys.modules, "yaml", None)
    result = inventory.run({"profiles": [{"config_text": text}]})
    assert result["coverage"] == "could_not_verify"
    assert result["findings"][0]["id"] == "executable_inventory.config_unverified"


def test_json_and_preparsed_data_do_not_require_yaml(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    result = inventory.run({
        "profiles": [{"config_text": '{"hooks": {}, "mcp_servers": {}}'}],
        "plugin_manifests": [{"manifest_data": {"name": "demo"},
                              "mcp_json_text": '{"mcpServers": {}}'}],
    })
    assert result["coverage"] == "verified"
    assert result["inventory"]["plugins"][0]["plugin_id"] == "demo"
