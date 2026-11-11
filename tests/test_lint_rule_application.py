"""Saved lint preferences affect real runner results, not just UI state."""
import json
import subprocess

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import lint_env, linter, safe_state_store


def run_saved(tmp_path, monkeypatch, rules, *, output=None, rc=1, mode="post", **kwargs):
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "run.sh").write_text("#!/bin/sh\necho $x\n")
    db = tmp_path / "state.db"
    safe_state_store.save_state(db, "workspace-ui", "settings", {"rules": rules}, 1)
    calls = []

    def runner(argv, **unused):
        calls.append(argv)
        payload = output if output is not None else json.dumps([
            {"file": "run.sh", "line": 2, "level": "warning", "code": 2086, "message": "Quote this"},
            {"file": "run.sh", "line": 3, "level": "warning", "code": 2154, "message": "Unset"},
        ])
        return subprocess.CompletedProcess(argv, rc, payload, "")

    monkeypatch.setattr(lint_env, "which", lambda name, env: "/fake/" + name)
    result = linter.run_lint(project, mode, env={}, db_path=db, runner=runner, **kwargs)
    return result, calls


@pytest.mark.parametrize("severity", ["error", "warning", "info"])
def test_rule_without_severity_preserves_native_diagnostic(tmp_path, monkeypatch, severity):
    result, _ = run_saved(tmp_path, monkeypatch, [
        {"id": "shellcheck", "enabled": True, "mode": "both"},
        {"id": "shellcheck:SC2086", "enabled": True},
    ], output=json.dumps([{"file": "run.sh", "line": 2, "level": severity,
                           "code": 2086, "message": "Native severity"}]))
    assert [f["severity"] for f in result["findings"]] == [severity]


def test_saved_rule_disable_and_severity_apply_before_counts_and_limit(tmp_path, monkeypatch):
    result, calls = run_saved(tmp_path, monkeypatch, [
        {"id": "shellcheck:SC2086", "enabled": False, "mode": "both"},
        {"id": "shellcheck:SC2154", "severity": "error", "mode": "post"},
    ], max_findings=1)
    assert calls
    assert [(f["rule"], f["severity"]) for f in result["findings"]] == [("SC2154", "error")]
    assert result["tools_run"][0]["findings"] == 1
    assert result["tool_statuses"][0]["findings"] == 1
    assert not any("truncated" in w for w in result["warnings"])


@pytest.mark.parametrize("rule_id", ["shellcheck", "analysis"])
def test_disabled_tool_skips_execution(tmp_path, monkeypatch, rule_id):
    result, calls = run_saved(tmp_path, monkeypatch, [
        {"id": rule_id, "enabled": False, "mode": "post"},
    ])
    assert calls == []
    assert result["status"] == "clean"
    assert result["tool_errors"] == []
    assert result["tool_statuses"][0]["status"] == "disabled"


@pytest.mark.parametrize("tool_mode,expected", [("both", True), ("post", True), ("pre", False)])
def test_explicit_tool_enable_overrides_disabled_group(tmp_path, monkeypatch, tool_mode, expected):
    result, calls = run_saved(tmp_path, monkeypatch, [
        {"id": "analysis", "enabled": False},
        {"id": "shellcheck", "enabled": True, "mode": tool_mode},
    ])
    assert bool(calls) is expected
    assert (result["tool_statuses"][0]["status"] == "disabled") is (not expected)


def test_rule_severity_overrides_tool_and_group_defaults(tmp_path, monkeypatch):
    result, _ = run_saved(tmp_path, monkeypatch, [
        {"id": "shellcheck:SC2086", "severity": "info"},
        {"id": "shellcheck", "severity": "error"},
        {"id": "analysis", "severity": "warning"},
    ])
    assert [f["severity"] for f in result["findings"]] == ["info", "error"]


@pytest.mark.parametrize("rules", [
    None, {}, [None], [{"id": "shellcheck", "enabled": "false"}],
    [{"id": "shellcheck", "mode": "invalid"}],
    [{"id": "shellcheck", "severity": "critical"}],
    [{"id": "shellcheck"}, {"id": "shellcheck"}],
    [{"id": " shellcheck"}],
])
def test_invalid_saved_preferences_fail_before_execution(tmp_path, monkeypatch, rules):
    result, calls = run_saved(tmp_path, monkeypatch, rules)
    assert calls == []
    assert result["status"] == "error"
    assert "lint settings" in result["error"]


@pytest.mark.parametrize("rc,output,status", [
    (1, None, "clean"),
    (-11, None, "incomplete"),
    (2, "not json", "incomplete"),
    (lint_env.TIMEOUT_RC, "", "incomplete"),
])
def test_suppression_never_hides_execution_failures(tmp_path, monkeypatch, rc, output, status):
    result, _ = run_saved(tmp_path, monkeypatch, [
        {"id": "shellcheck:SC2086", "enabled": False},
        {"id": "shellcheck:SC2154", "enabled": False},
        {"id": "shellcheck:parse-error", "enabled": False},
    ], rc=rc, output=output)
    assert result["findings"] == []
    assert result["status"] == status
    assert result["ok"] is (status == "clean")
    assert result["tools_run"][0]["findings"] == 0


def test_modes_and_exact_tool_rule_ids_do_not_leak(tmp_path, monkeypatch):
    result, _ = run_saved(tmp_path, monkeypatch, [
        {"id": "shellcheck:SC2086", "enabled": False, "mode": "pre"},
        {"id": "other:SC2154", "enabled": False},
        {"id": "custom-review", "label": "shellcheck", "enabled": False},
    ])
    assert [f["rule"] for f in result["findings"]] == ["SC2086", "SC2154"]
    assert result["status"] == "findings"


@pytest.mark.parametrize("tool,mode,group", [
    ("shfmt", "pre", "format"), ("clippy", "post", "repo"),
    ("biome", "pre", "repo"), ("biome", "post", "repo"),
    ("pwsh-parse", "pre", "analysis"),
])
def test_group_gates_run_before_binary_and_configuration_checks(tmp_path, monkeypatch, tool, mode, group):
    from hermes_plugins.defuzz import lint_tools
    monkeypatch.setattr(linter, "detect_for_project", lambda *a, **kw: ([lint_tools.by_name(tool)], []))
    result, calls = run_saved(tmp_path, monkeypatch, [{"id": group, "enabled": False}], mode=mode)
    assert calls == []
    assert result["tools_missing"] == []
    assert result["tool_errors"] == []
    assert result["tool_statuses"][0]["status"] == "disabled"


def test_unreadable_settings_fail_closed(tmp_path, monkeypatch):
    def broken(*args):
        raise OSError("unreadable state")
    monkeypatch.setattr(safe_state_store, "get_entry", broken)
    result, calls = run_saved(tmp_path, monkeypatch, [])
    assert calls == []
    assert result["status"] == "error"
    assert "unreadable state" in result["error"]
