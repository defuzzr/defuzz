"""The CLI never shows a traceback as its message; DEFUZZ_DEBUG=1 keeps the traceback reachable."""

from __future__ import annotations

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli as cli_mod  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402


def _boom(_ns):
    raise KeyError("unexpected\nmulti-line detail")


def test_unexpected_error_is_one_plain_line(monkeypatch, capsys):
    monkeypatch.delenv(cli_mod.DEBUG_ENV_VAR, raising=False)
    monkeypatch.setattr(cli_mod, "_handle_templates_subcommand", _boom)
    rc = cli_main(["templates"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    assert lines[0].startswith("defuzz templates: ")
    assert "KeyError" in lines[0] and "DEFUZZ_DEBUG=1" in lines[0]


def test_debug_env_reraises_for_the_traceback(monkeypatch):
    monkeypatch.setenv(cli_mod.DEBUG_ENV_VAR, "1")
    monkeypatch.setattr(cli_mod, "_handle_templates_subcommand", _boom)
    with pytest.raises(KeyError):
        cli_main(["templates"])
