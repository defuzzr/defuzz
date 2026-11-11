"""`defuzz new --prompt` over the parser's length cap prints one plain line and writes nothing."""

from __future__ import annotations

import time

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402
from hermes_plugins.defuzz.prompt_parse import MAX_PROMPT_CHARS, parse_deterministic  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch):
    projects = tmp_path / "projects"
    projects.mkdir()
    for var, sub in (("HOME", "home"), ("HERMES_HOME", "hermes"), ("TMPDIR", "tmp")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    monkeypatch.delenv("DEFUZZ_DEBUG", raising=False)
    return projects


@pytest.mark.parametrize("length", [MAX_PROMPT_CHARS + 1, 2 * 1024 * 1024])
def test_over_long_prompt_is_one_plain_line(env, capsys, length):
    prompt = ("a rust game called Foo " * (length // 23 + 1))[:length]
    start = time.monotonic()
    rc = cli_main(["new", "--prompt", prompt, "--yes", "--timeout", "5"])
    elapsed = time.monotonic() - start
    out, err = capsys.readouterr()
    assert rc == 1
    assert elapsed < 1.0
    assert out == ""
    lines = err.strip().splitlines()
    assert len(lines) == 1, err
    assert lines[0].startswith(f"Prompt is too long: {length} characters (limit {MAX_PROMPT_CHARS}).")
    assert "Traceback" not in err and "PromptTooLongError" not in err
    assert list(env.iterdir()) == []


def test_boundary_prompt_still_parses():
    parse_deterministic("x" * MAX_PROMPT_CHARS)
