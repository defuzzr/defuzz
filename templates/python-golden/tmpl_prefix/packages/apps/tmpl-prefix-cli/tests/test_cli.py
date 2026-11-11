"""Unit tests for the workspace using capsys."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tmpl_prefix_cli import (
    TmplPrefixCliRunner,
    run,
)

if TYPE_CHECKING:
    import pytest


def test_cli_health_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify the health subcommand emits a healthy JSON report."""
    code = run(["health"], env={})
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert payload["status"] == "healthy"
    assert payload["serving"] is True


def test_cli_accounts_register_and_list(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify accounts register and accounts list subcommands share state on a runner."""
    runner = TmplPrefixCliRunner(env={})

    code_reg = run(
        ["accounts", "register", "Alice@Example.com", "Alice Smith"],
        runner=runner,
    )
    assert code_reg == 0
    reg_out = json.loads(capsys.readouterr().out.strip())
    assert reg_out["email"] == "alice@example.com"
    assert reg_out["display_name"] == "Alice Smith"
    assert reg_out["status"] == "active"

    code_list = run(["accounts", "list"], runner=runner)
    assert code_list == 0
    list_out = json.loads(capsys.readouterr().out.strip())
    assert len(list_out["accounts"]) == 1
    assert list_out["accounts"][0]["email"] == "alice@example.com"


def test_cli_accounts_register_invalid_email_returns_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify invalid email input emits structured JSON error to stderr and exits 1."""
    code = run(["accounts", "register", "invalid-email", "Bad User"], env={})
    assert code == 1
    captured = capsys.readouterr()
    err_lines = [line for line in captured.err.splitlines() if line.strip()]
    err_payload = json.loads(err_lines[-1])
    assert err_payload["kind"] == "invalid_input"
