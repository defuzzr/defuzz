"""Lint children find a .NET runtime installed outside the default places.

A .NET tool such as csharpier starts through a small launcher (the app host).
The launcher looks for the runtime in DOTNET_ROOT, then in a fixed default
folder. When .NET lives elsewhere (``dotnet-install.sh`` into ``~/.dotnet``,
Homebrew) and DOTNET_ROOT is unset, the tool cannot start. These tests use a
fake .NET layout in a temporary folder and a fake csharpier that behaves like
the real launcher.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_env, linter  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts and symlinks")


def _exe(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_dotnet_install(root: Path, *, marker: bool = True) -> Path:
    """A folder shaped like a .NET install: the dotnet binary and host/fxr/<version>."""
    _exe(root / "dotnet", "#!/bin/sh\necho 10.0.100\n")
    if marker:
        (root / "host" / "fxr" / "10.0.0").mkdir(parents=True)
    return root


def _fake_csharpier(bin_dir: Path, log: Path) -> Path:
    """Behaves like the real app host: starts only when DOTNET_ROOT names a .NET install."""
    return _exe(
        bin_dir / "csharpier",
        "#!/bin/sh\n"
        f"echo \"DOTNET_ROOT=${{DOTNET_ROOT-<unset>}}\" > '{log}'\n"
        "if [ -z \"${DOTNET_ROOT-}\" ] || [ ! -d \"$DOTNET_ROOT/host/fxr\" ]; then\n"
        "  echo 'You must install .NET to run this application.' >&2\n"
        "  echo \"App: $0\" >&2\n"
        "  echo '.NET location: Not found' >&2\n"
        "  exit 131\n"
        "fi\n"
        "exit 0\n",
    )


def _build(base: dict[str, str], home: Path) -> dict[str, str]:
    with mock.patch.object(lint_env, "real_home", return_value=home):
        return lint_env.build_env(base)


@pytest.fixture()
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


def test_user_install_in_home_dotnet_with_only_path_set(tmp_path: Path, home: Path) -> None:
    """The dotnet-install.sh case: ~/.dotnet is on PATH and DOTNET_ROOT is not set."""
    root = _fake_dotnet_install(home / ".dotnet")
    env = _build({"PATH": f"{root}:/bin", "HOME": str(home)}, home)
    assert env["DOTNET_ROOT"] == str(root)


def test_symlink_in_a_bin_folder_points_at_the_user_install(tmp_path: Path, home: Path) -> None:
    """The macOS runner case: /usr/local/bin/dotnet is a symlink into ~/.dotnet."""
    root = _fake_dotnet_install(home / ".dotnet")
    shim_bin = tmp_path / "usr-local-bin"
    shim_bin.mkdir()
    (shim_bin / "dotnet").symlink_to(root / "dotnet")
    env = _build({"PATH": f"{shim_bin}:/bin", "HOME": str(home)}, home)
    assert env["DOTNET_ROOT"] == str(root)
    assert env["PATH"].split(os.pathsep)[-2:] == [str(shim_bin), "/bin"]


def test_homebrew_layout_resolves_into_the_cellar_libexec(tmp_path: Path, home: Path) -> None:
    prefix = tmp_path / "homebrew"
    libexec = _fake_dotnet_install(prefix / "Cellar" / "dotnet" / "10.0.100" / "libexec")
    cellar_bin = prefix / "Cellar" / "dotnet" / "10.0.100" / "bin"
    cellar_bin.mkdir(parents=True)
    (cellar_bin / "dotnet").symlink_to(Path("..") / "libexec" / "dotnet")
    (prefix / "bin").mkdir()
    (prefix / "bin" / "dotnet").symlink_to(Path("..") / "Cellar" / "dotnet" / "10.0.100" / "bin" / "dotnet")
    env = _build({"PATH": f"{prefix / 'bin'}:/bin", "HOME": str(home)}, home)
    assert env["DOTNET_ROOT"] == str(libexec.resolve())


@pytest.mark.parametrize("key", ["DOTNET_ROOT", "DOTNET_ROOT_ARM64", "DOTNET_ROOT_X64"])
def test_a_root_the_user_set_wins_and_nothing_is_derived(tmp_path: Path, home: Path, key: str) -> None:
    root = _fake_dotnet_install(home / ".dotnet")
    chosen = str(tmp_path / "chosen-dotnet")
    env = _build({"PATH": f"{root}:/bin", "HOME": str(home), key: chosen}, home)
    assert env[key] == chosen
    if key != "DOTNET_ROOT":
        assert "DOTNET_ROOT" not in env


def test_no_guess_without_the_host_fxr_marker(tmp_path: Path, home: Path) -> None:
    """A wrapper script, or any folder that is not a .NET install, is never used."""
    root = _fake_dotnet_install(tmp_path / "not-an-install", marker=False)
    env = _build({"PATH": f"{root}:/bin", "HOME": str(home)}, home)
    assert "DOTNET_ROOT" not in env


def test_no_guess_from_a_relative_path_entry(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dotnet_install(tmp_path / "rel")
    monkeypatch.chdir(tmp_path)
    env = _build({"PATH": "rel:/bin", "HOME": str(home)}, home)
    assert "DOTNET_ROOT" not in env


def test_default_install_location_changes_nothing(tmp_path: Path, home: Path) -> None:
    """The launcher finds a default install by itself: no variable is added."""
    assert {"/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet"} <= set(
        lint_env._DOTNET_DEFAULT_ROOTS
    )
    root = _fake_dotnet_install(tmp_path / "usr" / "share" / "dotnet")
    with mock.patch.object(lint_env, "_DOTNET_DEFAULT_ROOTS", (str(root),)):
        env = _build({"PATH": f"{root}:/bin", "HOME": str(home)}, home)
    assert "DOTNET_ROOT" not in env


def test_dotnet_missing_adds_nothing(tmp_path: Path, home: Path) -> None:
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    env = _build({"PATH": str(empty), "HOME": str(home)}, home)
    assert "DOTNET_ROOT" not in env


def test_managed_dotnet_install_still_wins(tmp_path: Path, home: Path) -> None:
    managed = _fake_dotnet_install(home / lint_env.INSTALL_ROOT_REL / "dotnet")
    other = _fake_dotnet_install(tmp_path / "other-dotnet")
    env = _build({"PATH": f"{other}:/bin", "HOME": str(home)}, home)
    assert env["DOTNET_ROOT"] == str(managed)


def _csharp_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Demo.csproj").write_text("<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n", encoding="utf-8")
    (proj / "Program.cs").write_text("class Program { static void Main() { } }\n", encoding="utf-8")
    return proj


def _csharpier_result(res: dict) -> list[dict]:
    return [s for s in res["tool_statuses"] if s["tool"] == "csharpier"]


def test_csharpier_starts_under_defuzz_lint_with_a_user_install(tmp_path: Path, home: Path) -> None:
    """End to end: the real lint run gives the fake csharpier the derived DOTNET_ROOT."""
    root = _fake_dotnet_install(home / ".dotnet")
    log = tmp_path / "csharpier-env.txt"
    tools_bin = tmp_path / "tools-bin"
    _fake_csharpier(tools_bin, log)
    env = _build({"PATH": f"{tools_bin}:{root}:/bin", "HOME": str(home)}, home)
    res = linter.run_lint(_csharp_project(tmp_path), mode="pre", env=env, db_path=tmp_path / "state.db")
    assert log.read_text(encoding="utf-8").strip() == f"DOTNET_ROOT={root}"
    statuses = _csharpier_result(res)
    assert [s["status"] for s in statuses] == ["clean"], statuses


def test_csharpier_missing_keeps_the_plain_not_installed_line(tmp_path: Path, home: Path) -> None:
    root = _fake_dotnet_install(home / ".dotnet")
    env = _build({"PATH": f"{root}:/bin", "HOME": str(home)}, home)
    res = linter.run_lint(_csharp_project(tmp_path), mode="pre", env=env, db_path=tmp_path / "state.db")
    assert "csharpier" in res["tools_missing"]
    assert "tool csharpier is not installed (missing binary: csharpier)" in res["warnings"]


def test_runtime_not_found_output_becomes_one_plain_line() -> None:
    stderr = (
        "You must install .NET to run this application.\n\n"
        "App: /work/csharpier/csharpier\nArchitecture: arm64\n.NET location: Not found\n"
    )
    assert lint_env.tool_start_failure_message("csharpier", "", stderr) == (
        "csharpier could not find the .NET runtime; set DOTNET_ROOT or install .NET in a default location"
    )
    assert lint_env.tool_start_failure_message("csharpier", "Warning a.cs - x\n", "") is None
    assert lint_env.tool_start_failure_message("csharpier", "", "") is None


def test_one_failed_start_is_counted_once_per_lint_run(tmp_path: Path, home: Path) -> None:
    """csharpier gets every C# file in one call, so a failed start is one error, not one per file."""
    log = tmp_path / "csharpier-env.txt"
    tools_bin = tmp_path / "tools-bin"
    _fake_csharpier(tools_bin, log)
    empty = tmp_path / "no-dotnet"
    empty.mkdir()
    env = _build({"PATH": f"{tools_bin}:{empty}", "HOME": str(home)}, home)
    proj = _csharp_project(tmp_path)
    for i in range(5):
        (proj / f"File{i}.cs").write_text("class A { }\n", encoding="utf-8")
    res = linter.run_lint(proj, mode="both", env=env, db_path=tmp_path / "state.db")
    errors = [e for e in res["tool_errors"] if e["tool"] == "csharpier"]
    assert len(errors) == 1, errors
    assert res["status"] == "incomplete"
