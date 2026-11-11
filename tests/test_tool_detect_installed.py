"""Seeding and checking ask the installed program, with fake tools on a temporary PATH."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import toolchk  # noqa: E402
from hermes_plugins.defuzz.tool_detect import detect_tools  # noqa: E402
from hermes_plugins.defuzz.tool_seed import lock_path, seed_lock  # noqa: E402

TODAY = "2026-11-10"


def _fake_tool(bin_dir: Path, name: str, body: str) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe = bin_dir / name
    exe.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    exe.chmod(0o755)


def _use_path(monkeypatch: pytest.MonkeyPatch, bin_dir: Path) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]))


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    return proj


def test_node_floor_from_nvmrc_is_checked_against_installed_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _project(tmp_path)
    (proj / ".nvmrc").write_text("24\n", encoding="utf-8")
    (proj / "package.json").write_text('{"name": "web"}\n', encoding="utf-8")
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "node", 'echo "v18.20.4"')
    _use_path(monkeypatch, bin_dir)

    detected = detect_tools(proj, chosen=TODAY, event="project creation")
    assert detected["node"]["probe"] == "command"
    assert detected["node"]["argv"] == ["node", "--version"]
    assert detected["node"]["minimum"] == "24"

    seed_lock(proj, event="project creation", today=TODAY)
    loaded = toolchk.load_lock(lock_path(proj))
    assert loaded["tools"]["node"]["version"] == "18.20.4"
    assert loaded["tools"]["node"]["minimum"] == "24"

    rep = toolchk.check(["node"], loaded, proj)
    assert rep["ok"] is False
    assert any("found 18.20.4, need >= 24" in line for line in rep["blocked"])


def test_node_at_or_above_nvmrc_floor_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = _project(tmp_path)
    (proj / ".nvmrc").write_text("v24.0.0\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "node", 'echo "v24.22.2"')
    _use_path(monkeypatch, bin_dir)

    seed_lock(proj, event="project creation", today=TODAY)
    loaded = toolchk.load_lock(lock_path(proj))
    assert loaded["tools"]["node"]["version"] == "24.22.2"
    assert toolchk.check(["node"], loaded, proj)["ok"] is True


def test_nvmrc_alias_without_a_number_still_probes_installed_node(tmp_path: Path) -> None:
    proj = _project(tmp_path)
    (proj / ".nvmrc").write_text("lts/*\n", encoding="utf-8")
    entry = detect_tools(proj, chosen=TODAY, event="project creation")["node"]
    assert entry["probe"] == "command"
    assert "minimum" not in entry


def test_rust_concrete_channel_is_a_floor_for_the_installed_rustc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _project(tmp_path)
    (proj / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.88.0"\n', encoding="utf-8")
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "rustc", 'echo "rustc 1.80.1 (3f5fd8dd4 2024-08-06)"')
    _fake_tool(bin_dir, "cargo", 'echo "cargo 1.80.1 (376290515 2024-07-16)"')
    _use_path(monkeypatch, bin_dir)

    entry = detect_tools(proj, chosen=TODAY, event="project creation")["rust"]
    assert entry["probe"] == "command"
    assert entry["argv"] == ["rustc", "--version"]
    assert entry["minimum"] == "1.88.0"

    seed_lock(proj, event="project creation", today=TODAY)
    loaded = toolchk.load_lock(lock_path(proj))
    assert loaded["tools"]["rust"]["version"] == "1.80.1"
    rep = toolchk.check(["rust"], loaded, proj)
    assert rep["ok"] is False


def test_newer_node_after_creation_warns_and_does_not_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock records the installed node; a later upgrade inside the floor is drift, a warning under `warn`."""
    proj = _project(tmp_path)
    (proj / ".nvmrc").write_text("24\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "node", 'echo "v24.22.2"')
    _use_path(monkeypatch, bin_dir)
    seed_lock(proj, event="project creation", today=TODAY)
    loaded = toolchk.load_lock(lock_path(proj))
    assert loaded["lock"]["enforce"] == "warn"
    assert loaded["tools"]["node"]["version"] == "24.22.2"

    _fake_tool(bin_dir, "node", 'echo "v24.23.0"')
    rep = toolchk.check(["node"], loaded, proj)
    assert rep["ok"] is True
    assert rep["blocked"] == []
    assert any("node" in line for line in rep["warnings"])


@pytest.mark.parametrize(
    ("tool", "program", "version_file", "text"),
    [
        ("node", "node", ".nvmrc", "24\n"),
        ("rust", "rustc", "rust-toolchain.toml", '[toolchain]\nchannel = "1.88.0"\n'),
    ],
)
def test_missing_program_is_one_plain_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, program: str, version_file: str, text: str
) -> None:
    """Without the program installed, seeding notes the failure and the check says which tool is missing."""
    proj = _project(tmp_path)
    (proj / version_file).write_text(text, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if tool == "rust":
        _fake_tool(bin_dir, "cargo", 'echo "cargo 1.90.0 (0 2026-01-01)"')
    monkeypatch.setenv("PATH", str(bin_dir))
    assert shutil.which(program) is None

    summary = seed_lock(proj, event="project creation", today=TODAY)
    assert tool in summary["probe_failed"]

    loaded = toolchk.load_lock(lock_path(proj))
    rep = toolchk.check([tool], loaded, proj)
    assert rep["ok"] is False
    lines = rep["probe_failed"] + rep["blocked"]
    assert lines and all("None" not in item for item in lines)
    assert any(
        item.startswith(f"{tool}: not found on PATH") and "hermes defuzz setup-tools" in item for item in lines
    ), lines
