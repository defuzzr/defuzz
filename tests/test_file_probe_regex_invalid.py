"""An invalid file-probe regex is a validation error (ValueError/TemplateError), never a bare re.error."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import toolchk  # noqa: E402
from hermes_plugins.defuzz.templates import TemplateError, load_template  # noqa: E402
from hermes_plugins.defuzz.toolchk import (  # noqa: E402
    _compile_safe_file_regex,
    check,
    load_lock,
    probe,
)

BAD_PATTERNS = ["(", "[", "a{2,1}", "*", "(?P<x", "\\", "(?<=a+)b"]
# Repeat counts >= MAXREPEAT make re raise OverflowError (not re.error) while parsing.
OVERFLOW_PATTERNS = ["a{4294967295}", "a{4294967296}", "a{1,4294967296}", "(\\d+){99999999999}"]


def _re_message(pattern: str) -> str:
    try:
        re.compile(pattern)
    except re.error as exc:
        return str(exc)
    raise AssertionError(f"pattern {pattern!r} unexpectedly compiles")


def _overflow_message(pattern: str) -> str:
    try:
        re.compile(pattern)
    except OverflowError as exc:
        return str(exc)
    raise AssertionError(f"pattern {pattern!r} unexpectedly compiles")


@pytest.mark.parametrize("pattern", BAD_PATTERNS)
def test_compile_safe_file_regex_converts_re_error(pattern: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        _compile_safe_file_regex(pattern)
    exc = exc_info.value
    assert not isinstance(exc, re.error)
    assert str(exc) == f"file probe regex is invalid: {_re_message(pattern)}"
    assert isinstance(exc.__cause__, re.error)


@pytest.mark.parametrize("pattern", OVERFLOW_PATTERNS)
def test_compile_safe_file_regex_converts_overflow_error(pattern: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        _compile_safe_file_regex(pattern)
    exc = exc_info.value
    assert str(exc) == f"file probe regex is invalid: {_overflow_message(pattern)}"
    assert isinstance(exc.__cause__, OverflowError)


def test_existing_messages_and_valid_regexes_unchanged() -> None:
    with pytest.raises(ValueError, match=r"^file probe regex must be a non-empty string$"):
        _compile_safe_file_regex("")
    long_re = "a" * (toolchk.MAX_FILE_REGEX_CHARS + 1)
    with pytest.raises(ValueError) as exc_long:
        _compile_safe_file_regex(long_re)
    assert str(exc_long.value) == (
        f"file probe regex exceeds {toolchk.MAX_FILE_REGEX_CHARS} characters ({len(long_re)})"
    )
    with pytest.raises(ValueError) as exc_back:
        _compile_safe_file_regex(r"(a)\1")
    assert str(exc_back.value) == "backreferences are not allowed in file probe regex: '(a)\\\\1'"
    with pytest.raises(ValueError) as exc_nested:
        _compile_safe_file_regex(r"(a+)+$")
    assert str(exc_nested.value) == "unsafe nested quantifier in file probe regex: '(a+)+$'"
    for good in (r"^\s*go\s+(\d+(?:\.\d+)*)", r"v?(\d+\.\d+\.\d+)", r"(\d+)"):
        assert _compile_safe_file_regex(good).pattern == good


def _template_with_regex(tmp_path: Path, regex: str) -> Path:
    """Write a minimal valid template whose gofmt version probe is a file probe using regex."""
    tdir = tmp_path / "templates" / "regex-probe"
    repo_dir = tdir / "tmpl_prefix"
    repo_dir.mkdir(parents=True)
    (repo_dir / "README.md").write_text("# TmplPrefix\n\n`tmpl-prefix`\n", encoding="utf-8")
    descriptor: dict[str, Any] = {
        "id": "regex-probe",
        "name": "Dummy regex-probe",
        "summary": "Synthetic data-only template descriptor for file-probe regex validation.",
        "kind": "tool",
        "layout": "mono",
        "languages": ["python"],
        "needs": ["go", "gofmt"],
        "placeholder": "tmpl_prefix",
        "substitute_in": ["**/*.md"],
        "repos": [
            {
                "name": "tmpl_prefix",
                "check": {
                    "cmd": ["python3", "-c", "import pathlib; assert pathlib.Path('README.md').is_file()"],
                    "cwd": ".",
                    "format_cmds": [["ruff", "check", "."]],
                },
            }
        ],
        "version_probes": {
            "go": ["go", "version"],
            "gofmt": {"probe": "file", "file": "go.mod", "regex": regex},
        },
    }
    (tdir / "template.yaml").write_text(yaml.safe_dump(descriptor, sort_keys=False), encoding="utf-8")
    return tdir


def test_template_valid_file_regex_loads(tmp_path: Path) -> None:
    load_template(_template_with_regex(tmp_path, r"^\s*go\s+(\d+(?:\.\d+)*)"))


def test_template_invalid_file_regex_is_template_error(tmp_path: Path) -> None:
    tdir = _template_with_regex(tmp_path, "(")
    with pytest.raises(TemplateError) as exc_info:
        load_template(tdir)
    assert str(exc_info.value) == (
        "template 'regex-probe' key 'version_probes.gofmt.regex': "
        f"file probe regex is invalid: {_re_message('(')}"
    )
    assert isinstance(exc_info.value.__cause__, ValueError)


@pytest.mark.parametrize("pattern", OVERFLOW_PATTERNS)
def test_template_overflow_file_regex_is_template_error(tmp_path: Path, pattern: str) -> None:
    tdir = _template_with_regex(tmp_path, pattern)
    with pytest.raises(TemplateError) as exc_info:
        load_template(tdir)
    assert str(exc_info.value) == (
        "template 'regex-probe' key 'version_probes.gofmt.regex': "
        f"file probe regex is invalid: {_overflow_message(pattern)}"
    )
    cause = exc_info.value.__cause__
    assert isinstance(cause, ValueError)
    assert isinstance(cause.__cause__, OverflowError)


def test_probe_invalid_regex_raises_value_error(tmp_path: Path) -> None:
    (tmp_path / "VERSION").write_text("1.2.3\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc_info:
        probe("bad", {"probe": "file", "file": "VERSION", "regex": "("}, tmp_path)
    assert not isinstance(exc_info.value, re.error)
    assert str(exc_info.value).startswith("file probe regex is invalid: ")


def test_tools_lock_invalid_regex_is_probe_failed(tmp_path: Path) -> None:
    """TOOLS.lock accepts the entry (only non-empty is checked at load); check() reports probe-failed."""
    (tmp_path / "VERSION").write_text("1.2.3\n", encoding="utf-8")
    lock_text = (
        '[bad]\nversion = "1.2.3"\nchosen = "2026-11-06"\nreason = "r"\n'
        'probe = "file"\nfile = "VERSION"\nregex = "("\n'
    )
    (tmp_path / "TOOLS.lock").write_text(lock_text, encoding="utf-8")
    assert load_lock(tmp_path / "TOOLS.lock")["tools"]["bad"]["regex"] == "("
    rep = check(["bad"], None, tmp_path)
    assert rep["ok"] is False
    row = rep["tools"]["bad"]
    assert row["status"] == "probe-failed"
    expected = f"ValueError: file probe regex is invalid: {_re_message('(')}"
    assert row["error"] == expected
    assert rep["probe_failed"] == [f"bad: {expected}"]


@pytest.mark.parametrize("pattern", OVERFLOW_PATTERNS)
def test_tools_lock_overflow_regex_is_probe_failed(tmp_path: Path, pattern: str) -> None:
    (tmp_path / "VERSION").write_text("1.2.3\n", encoding="utf-8")
    toml_regex = pattern.replace("\\", "\\\\")
    lock_text = (
        '[bad]\nversion = "1.2.3"\nchosen = "2026-11-06"\nreason = "r"\n'
        f'probe = "file"\nfile = "VERSION"\nregex = "{toml_regex}"\n'
    )
    (tmp_path / "TOOLS.lock").write_text(lock_text, encoding="utf-8")
    assert load_lock(tmp_path / "TOOLS.lock")["tools"]["bad"]["regex"] == pattern
    rep = check(["bad"], None, tmp_path)
    assert rep["ok"] is False
    row = rep["tools"]["bad"]
    assert row["status"] == "probe-failed"
    expected = f"ValueError: file probe regex is invalid: {_overflow_message(pattern)}"
    assert row["error"] == expected
    assert rep["probe_failed"] == [f"bad: {expected}"]
