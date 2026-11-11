"""Full pre-release versions survive seeding and checking; version commands run from a neutral folder."""

from __future__ import annotations

import os
import re
import tempfile
import time
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import toolchk  # noqa: E402
from hermes_plugins.defuzz.tool_seed import lock_path, seed_lock  # noqa: E402

TODAY = "2026-11-10"
OLD_VERSION_RE = re.compile(r"\d+(?:\.\d+)+(?:[-+.][0-9A-Za-z.]{1,18})?")


def _fake_tool(bin_dir: Path, name: str, body: str) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe = bin_dir / name
    exe.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    exe.chmod(0o755)
    return exe


def _use_path(monkeypatch: pytest.MonkeyPatch, bin_dir: Path) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]))


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    return proj


@pytest.mark.parametrize(
    ("printed", "expected"),
    [
        ("dotnet 10.0.100-rc.2.25502.107", "10.0.100-rc.2.25502.107"),
        ("rustc 1.97.1 (abc 2026-01-01)", "1.97.1"),
        ("rustc 1.97.1-nightly (abc 2026-01-01)", "1.97.1-nightly"),
        ("2.0.0-alpha.20260101.1234", "2.0.0-alpha.20260101.1234"),
        ("1.2.3-beta-1", "1.2.3-beta-1"),
        ("1.2.3+build.5", "1.2.3+build.5"),
        ("1.2.3-rc.1+build.5", "1.2.3-rc.1+build.5"),
        ("v24.0.0", "24.0.0"),
        ("go version go1.24.3 linux/amd64", "1.24.3"),
        ("biome 2.6.4.", "2.6.4"),
        ("tool 1.2.3-rc.", "1.2.3-rc"),
        ("tool (1.2.3-rc.1)", "1.2.3-rc.1"),
        ("tool [1.2.3]", "1.2.3"),
        ("pip 24.0.post1", "24.0.post1"),
    ],
)
def test_version_pattern_keeps_the_whole_version(printed: str, expected: str) -> None:
    m = toolchk.VERSION_RE.search(printed)
    assert m is not None and m.group(0) == expected
    assert toolchk.SAFE_VERSION_TOKEN_RE.fullmatch(expected)


def test_version_pattern_agrees_with_old_one_when_old_did_not_cut() -> None:
    for text in ("node v18.20.4", "rustc 1.82.0-nightly (x)", "cmake version 3.31.6", "1.2.3.4", "24.0.post1"):
        old = OLD_VERSION_RE.search(text)
        assert old is not None
        assert toolchk.VERSION_RE.search(text).group(0) == old.group(0)


@pytest.mark.parametrize("blob", ["1." * 500_000, "1" * 1_000_000 + "-", ("1.2.3-" + "a." * 20) * 20_000])
def test_version_pattern_is_fast_on_large_input(blob: str) -> None:
    started = time.monotonic()
    toolchk.VERSION_RE.search(blob)
    list(toolchk.VERSION_RE.finditer(blob[:200_000]))
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize(
    ("printed", "expected"),
    [
        ("10.0.100-rc.2.25502.107", "10.0.100-rc.2.25502.107"),
        ("rustc 1.97.1-nightly (abc 2026-01-01)", "1.97.1-nightly"),
        ("2.0.0-alpha.20260101.1234", "2.0.0-alpha.20260101.1234"),
        ("1.2.3-beta-1", "1.2.3-beta-1"),
        ("v18.20.4", "18.20.4"),
    ],
)
def test_seeded_version_is_the_full_version_the_tool_prints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, printed: str, expected: str
) -> None:
    proj = _project(tmp_path)
    (proj / ".nvmrc").write_text("1\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "node", f'echo "{printed}"')
    _use_path(monkeypatch, bin_dir)

    summary = seed_lock(proj, event="project creation", today=TODAY)
    assert summary["probe_failed"] == {}
    loaded = toolchk.load_lock(lock_path(proj))
    assert loaded["tools"]["node"]["version"] == expected
    assert toolchk.check(["node"], loaded, proj)["ok"] is True


def _lock_with(version: str) -> dict:
    return {
        "lock": {"enforce": "block"},
        "tools": {"node": {"version": version, "chosen": TODAY, "reason": "test", "probe": "command", "argv": ["node", "--version"]}},
    }


def test_old_lock_that_was_not_cut_still_checks_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "node", 'echo "v1.82.0-nightly"')
    _use_path(monkeypatch, bin_dir)
    stored = OLD_VERSION_RE.search("v1.82.0-nightly").group(0)
    assert toolchk.check(["node"], _lock_with(stored), proj)["ok"] is True


def test_old_lock_that_was_cut_reports_a_plain_difference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "node", 'echo "2.0.0-alpha.20260101.1234"')
    _use_path(monkeypatch, bin_dir)
    stored = OLD_VERSION_RE.search("2.0.0-alpha.20260101.1234").group(0)
    assert stored != "2.0.0-alpha.20260101.1234"
    result = toolchk.check(["node"], _lock_with(stored), proj)
    assert result["ok"] is False
    assert len(result["blocked"]) == 1
    line = result["blocked"][0]
    assert "\n" not in line and "Traceback" not in line
    assert "2.0.0-alpha.20260101.1234" in line


def test_rust_probe_does_not_depend_on_the_current_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    (proj / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "0.1.0"\n', encoding="utf-8")
    (proj / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\n', encoding="utf-8")
    bin_dir = tmp_path / "bin"
    cwd_file = tmp_path / "cwd.txt"
    # Like a rustup proxy: fails when a toolchain file is in the current folder.
    _fake_tool(
        bin_dir,
        "rustc",
        f'pwd > "{cwd_file}"\n'
        'if [ -e rust-toolchain.toml ]; then echo "error: no default toolchain" >&2; exit 1; fi\n'
        'echo "rustc 1.97.1 (abc 2026-01-01)"',
    )
    _use_path(monkeypatch, bin_dir)
    monkeypatch.chdir(proj)

    installed, _where = toolchk.probe("rust", {"probe": "command", "argv": ["rustc", "--version"]}, proj)
    assert installed == "1.97.1"
    child_cwd = Path(cwd_file.read_text(encoding="utf-8").strip()).resolve()
    assert child_cwd == Path(tempfile.gettempdir()).resolve()
    assert not child_cwd.is_relative_to(proj.resolve())
    for home in toolchk._hermes_home_paths():
        assert not child_cwd.is_relative_to(home)


def test_probe_folder_skips_temp_inside_the_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    inner = proj / "tmp"
    inner.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(inner))
    chosen = Path(toolchk._neutral_probe_cwd(proj)).resolve()
    assert not chosen.is_relative_to(proj.resolve())
    for home in toolchk._hermes_home_paths():
        assert not chosen.is_relative_to(home)


def test_project_programs_are_still_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    _fake_tool(proj / "bin", "rustc", 'echo "rustc 9.9.9"')
    _use_path(monkeypatch, proj / "bin")
    with pytest.raises(FileNotFoundError):
        toolchk.probe("rust", {"probe": "command", "argv": ["rustc", "--version"]}, proj)
