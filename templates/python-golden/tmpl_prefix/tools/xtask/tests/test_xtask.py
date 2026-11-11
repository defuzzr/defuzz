"""Unit tests for xtask workspace automation, checker, and context-aware renamer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from xtask.checker import format_graph, run_check
from xtask.ci import bump_python
from xtask.renamer import replace_prefix_in_text
from xtask.workspace import (
    PREFIX,
    derive_forms,
    find_workspace_root,
)

if TYPE_CHECKING:
    import pytest


def test_derive_forms_and_round_trip_text_replacement() -> None:
    """Verify multi-word -> single-word -> multi-word replacement is lossless."""
    orig = derive_forms("alpha_beta")
    multi = derive_forms("acme_cloud")
    single = derive_forms("zenith")

    py_sample = (
        "from alpha_beta_core import AlphaBetaError\n"
        'ENV_KEY = "ALPHA_BETA_HTTP__PORT"\n'
        'SERVICE = "alpha-beta-server"\n'
        'PREFIX = "alpha_beta"\n'
    )
    step1 = replace_prefix_in_text(py_sample, orig, multi, bare_mode="snake")
    assert "acme_cloud_core" in step1
    assert "AcmeCloudError" in step1
    assert "ACME_CLOUD_HTTP__PORT" in step1
    assert "acme-cloud-server" in step1
    assert 'PREFIX = "acme_cloud"' in step1

    step2 = replace_prefix_in_text(step1, multi, single, bare_mode="snake")
    assert "zenith_core" in step2
    assert "ZenithError" in step2
    assert "ZENITH_HTTP__PORT" in step2
    assert "zenith-server" in step2
    assert 'PREFIX = "zenith"' in step2

    step3 = replace_prefix_in_text(step2, single, orig, bare_mode="snake")
    assert step3 == py_sample

    toml_sample = (
        "[project]\n"
        'name = "alpha-beta-cli"\n'
        "[project.scripts]\n"
        'alpha-beta = "alpha_beta_cli.main:main"\n'
    )
    t1 = replace_prefix_in_text(toml_sample, orig, single, bare_mode="kebab")
    assert 'name = "zenith-cli"' in t1
    assert 'zenith = "zenith_cli.main:main"' in t1
    t2 = replace_prefix_in_text(t1, single, orig, bare_mode="kebab")
    assert t2 == toml_sample


def test_format_graph_and_run_check_pass_on_workspace() -> None:
    """Verify format_graph and run_check succeed on the workspace."""
    root = find_workspace_root()
    output = format_graph(root, prefix=PREFIX)
    assert "Layer 0 (foundation):" in output
    assert "Layer 1 (domain):" in output
    assert "Layer 2 (adapters):" in output
    assert "Layer 3 (apps):" in output
    assert f"{PREFIX.replace('_', '-')}-core" in output
    assert f"{PREFIX.replace('_', '-')}-server" in output
    assert run_check(root, prefix=PREFIX) == []


def test_bump_python_rejects_invalid_and_missing_interpreter(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify bump_python validates format and prints install hint when missing."""
    root = find_workspace_root()
    assert bump_python(root, "invalid") == 1
    assert "Invalid Python version" in capsys.readouterr().err

    assert bump_python(root, "3.99") == 1
    assert "uv python install 3.99" in capsys.readouterr().err
