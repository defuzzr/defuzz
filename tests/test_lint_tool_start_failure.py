"""A lint tool that cannot start is reported with one plain line.

When a tool exits non-zero and its output shows it could not start (today: the
.NET launcher could not find the runtime), the lint run reports that tool as
crashed with one plain line, not the raw launcher output. These tests go through
the real lint run with a fake csharpier on PATH.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_env, linter  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")

PLAIN = "csharpier could not find the .NET runtime; set DOTNET_ROOT or install .NET in a default location"


def _exe(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_csharpier(bin_dir: Path, *, stdout: str = "", stderr: str = "", rc: int) -> Path:
    def lines(text: str, stream: str) -> str:
        redirect = " >&2" if stream == "err" else ""
        return "".join(f"echo '{line}'{redirect}\n" for line in text.splitlines())

    return _exe(
        bin_dir / "csharpier",
        "#!/bin/sh\n" + lines(stdout, "out") + lines(stderr, "err") + f"exit {rc}\n",
    )


# What the real .NET launcher prints when it cannot find the runtime.
_LAUNCHER_ERR = (
    "You must install .NET to run this application.\n"
    "App: {app}\n"
    "Architecture: x64\n"
    ".NET location: Not found\n"
)


def _csharp_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Demo.csproj").write_text("<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n", encoding="utf-8")
    (proj / "Program.cs").write_text("class Program { static void Main() { } }\n", encoding="utf-8")
    return proj


def _lint(tmp_path: Path, bin_dir: Path) -> dict:
    home = tmp_path / "home"
    home.mkdir()
    with mock.patch.object(lint_env, "real_home", return_value=home):
        env = lint_env.build_env({"PATH": f"{bin_dir}:/bin", "HOME": str(home)})
    return linter.run_lint(_csharp_project(tmp_path), mode="pre", env=env, db_path=tmp_path / "state.db")


def _csharpier(res: dict) -> list[dict]:
    return [s for s in res["tool_statuses"] if s["tool"] == "csharpier"]


def test_runtime_not_found_is_one_plain_crashed_line(tmp_path: Path) -> None:
    bin_dir = tmp_path / "tools-bin"
    app = bin_dir / "csharpier"
    _fake_csharpier(bin_dir, stderr=_LAUNCHER_ERR.format(app=app), rc=131)
    res = _lint(tmp_path, bin_dir)

    statuses = _csharpier(res)
    assert [s["status"] for s in statuses] == ["crashed"], statuses
    assert [s["message"] for s in statuses] == [PLAIN]
    assert statuses[0]["findings"] == 0

    errors = [e for e in res["tool_errors"] if e["tool"] == "csharpier"]
    assert [(e["status"], e["message"]) for e in errors] == [("crashed", PLAIN)]
    assert res["status"] == "incomplete"

    # Exactly one plain line, never the raw launcher output or a path.
    assert res["warnings"].count(PLAIN) == 1
    everything = [PLAIN, *res["warnings"], *(e["message"] for e in res["tool_errors"])]
    for text in everything:
        assert "You must install" not in text, text
        assert ".NET location" not in text, text
        assert "App:" not in text, text
        assert str(tmp_path) not in text, text
        assert "/" not in text, text


def test_ordinary_findings_with_a_non_zero_exit_are_unaffected(tmp_path: Path) -> None:
    bin_dir = tmp_path / "tools-bin"
    _fake_csharpier(bin_dir, stdout="Error Program.cs - Was not formatted.", rc=1)
    res = _lint(tmp_path, bin_dir)

    statuses = _csharpier(res)
    assert len(statuses) == 1, statuses
    assert statuses[0]["status"] != "crashed", statuses
    assert statuses[0]["findings"] == 1, statuses
    assert PLAIN not in res["warnings"]
    assert not [e for e in res["tool_errors"] if e["tool"] == "csharpier"]
    findings = [f for f in res["findings"] if f.get("tool") == "csharpier"]
    assert len(findings) == 1, findings


def test_launcher_text_with_exit_zero_is_not_a_start_failure(tmp_path: Path) -> None:
    bin_dir = tmp_path / "tools-bin"
    _fake_csharpier(bin_dir, stdout="You must install .NET to run this application.", rc=0)
    res = _lint(tmp_path, bin_dir)

    statuses = _csharpier(res)
    assert len(statuses) == 1, statuses
    assert statuses[0]["status"] != "crashed", statuses
    assert PLAIN not in res["warnings"]
    assert all(e["message"] != PLAIN for e in res["tool_errors"])
