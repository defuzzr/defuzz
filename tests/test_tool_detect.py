"""Unit tests for tool_detect.py."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import tool_detect  # noqa: E402
from hermes_plugins.defuzz.tool_detect import (  # noqa: E402
    DETECTORS,
    HERMES_PM_TOOLS,
    detect_tools,
    format_reason,
)

CHOSEN = "2026-11-06"
EVENT = "project creation"


@pytest.fixture(autouse=True)
def forbid_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tool_detect never spawns a subprocess."""

    def _fail(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"subprocess call forbidden in tool_detect: {args!r}")

    monkeypatch.setattr(subprocess, "run", _fail)
    monkeypatch.setattr(subprocess, "Popen", _fail)
    monkeypatch.setattr(subprocess, "call", _fail)
    monkeypatch.setattr(subprocess, "check_call", _fail)
    monkeypatch.setattr(subprocess, "check_output", _fail)


def _assert_common_entry(
    entry: dict[str, Any],
    *,
    probe: str,
    evidence: str,
    chosen: str = CHOSEN,
    event: str = EVENT,
) -> None:
    assert entry["version"] == ""
    assert entry["chosen"] == chosen
    assert entry["probe"] == probe
    assert entry["source"] == "auto"
    assert entry["reason"] == (
        f"Detected from {evidence} at {event} (auto). "
        "Edit this reason when you make a deliberate choice."
    )


def test_detectors_table_structure() -> None:
    assert len(DETECTORS) >= 9
    names = [rule.name for rule in DETECTORS]
    assert len(names) == len(set(names))
    for rule in DETECTORS:
        assert rule.detect_globs
        assert callable(rule.detector)


def test_rust_toolchain_concrete_version_is_floor_for_command_probe(tmp_path: Path) -> None:
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.82.0"\ncomponents = ["rustfmt", "clippy"]\n',
        encoding="utf-8",
    )
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["cargo", "rust"]

    _assert_common_entry(res["rust"], probe="command", evidence="rust-toolchain.toml")
    assert res["rust"]["argv"] == ["rustc", "--version"]
    assert res["rust"]["minimum"] == "1.82.0"

    _assert_common_entry(res["cargo"], probe="command", evidence="rust-toolchain.toml")
    assert res["cargo"]["argv"] == ["cargo", "--version"]


def test_rust_toolchain_symbolic_channel_uses_command_probe(tmp_path: Path) -> None:
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "stable"\n',
        encoding="utf-8",
    )
    res = detect_tools(tmp_path, chosen=CHOSEN, event="adoption")
    assert list(res.keys()) == ["cargo", "rust"]

    _assert_common_entry(
        res["rust"],
        probe="command",
        evidence="rust-toolchain.toml",
        event="adoption",
    )
    assert res["rust"]["argv"] == ["rustc", "--version"]
    assert "file" not in res["rust"]
    assert "key" not in res["rust"]

    _assert_common_entry(
        res["cargo"],
        probe="command",
        evidence="rust-toolchain.toml",
        event="adoption",
    )
    assert res["cargo"]["argv"] == ["cargo", "--version"]


def test_go_mod_with_go_or_toolchain_line(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/demo\n\ngo 1.23.2\n",
        encoding="utf-8",
    )
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["go"]
    _assert_common_entry(res["go"], probe="command", evidence="go.mod")
    assert res["go"]["argv"] == ["go", "version"]

    # Also test toolchain goX line
    sub = tmp_path / "tc"
    sub.mkdir()
    (sub / "go.mod").write_text(
        "module example.com/tc\n\ntoolchain go1.24.0\n",
        encoding="utf-8",
    )
    res_tc = detect_tools(sub, chosen=CHOSEN, event=EVENT)
    assert list(res_tc.keys()) == ["go"]
    assert res_tc["go"]["argv"] == ["go", "version"]

    # go.mod without go 1.x or toolchain goX does not emit go
    empty_go = tmp_path / "no_ver"
    empty_go.mkdir()
    (empty_go / "go.mod").write_text("module example.com/bare\n", encoding="utf-8")
    assert detect_tools(empty_go, chosen=CHOSEN, event=EVENT) == {}


@pytest.mark.parametrize(
    ("pm_field", "expected_pm"),
    [
        ("pnpm@9.12.0", "pnpm"),
        ("yarn@4.5.1+sha256.abcdef", "yarn"),
        ("npm@10.8.3", "npm"),
    ],
)
def test_package_json_package_manager_field(
    tmp_path: Path, pm_field: str, expected_pm: str
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo", "packageManager": pm_field}),
        encoding="utf-8",
    )
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert set(res.keys()) == {"node", expected_pm}
    assert list(res.keys()) == sorted(res.keys())

    _assert_common_entry(res["node"], probe="command", evidence="package.json")
    assert res["node"]["argv"] == ["node", "--version"]

    _assert_common_entry(res[expected_pm], probe="command", evidence="package.json")
    assert res[expected_pm]["argv"] == [expected_pm, "--version"]


@pytest.mark.parametrize(
    ("lockfile", "expected_pm"),
    [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
    ],
)
def test_package_json_lockfile_detection(
    tmp_path: Path, lockfile: str, expected_pm: str
) -> None:
    (tmp_path / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    (tmp_path / lockfile).write_text("# lock\n", encoding="utf-8")

    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert set(res.keys()) == {"node", expected_pm}
    _assert_common_entry(res["node"], probe="command", evidence="package.json")
    assert res["node"]["argv"] == ["node", "--version"]
    _assert_common_entry(res[expected_pm], probe="command", evidence=lockfile)
    assert res[expected_pm]["argv"] == [expected_pm, "--version"]


def test_nvmrc_wins_over_package_json_for_node(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name": "web", "packageManager": "pnpm@9.1.0"}\n',
        encoding="utf-8",
    )
    (tmp_path / ".nvmrc").write_text("v20.18.0\n", encoding="utf-8")

    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["node", "pnpm"]

    _assert_common_entry(res["node"], probe="command", evidence=".nvmrc")
    assert res["node"]["argv"] == ["node", "--version"]
    assert res["node"]["minimum"] == "20.18.0"
    assert "file" not in res["node"]

    # Package manager from package.json is still preserved alongside .nvmrc node
    _assert_common_entry(res["pnpm"], probe="command", evidence="package.json")
    assert res["pnpm"]["argv"] == ["pnpm", "--version"]


def test_python_from_pyproject_and_requirements(tmp_path: Path) -> None:
    proj1 = tmp_path / "p1"
    proj1.mkdir()
    (proj1 / "pyproject.toml").write_text('[project]\nname = "p1"\n', encoding="utf-8")
    res1 = detect_tools(proj1, chosen=CHOSEN, event=EVENT)
    assert list(res1.keys()) == ["python"]
    _assert_common_entry(res1["python"], probe="interpreter", evidence="pyproject.toml")

    proj2 = tmp_path / "p2"
    proj2.mkdir()
    (proj2 / "requirements-dev.txt").write_text("pytest>=8.0\n", encoding="utf-8")
    res2 = detect_tools(proj2, chosen=CHOSEN, event=EVENT)
    assert list(res2.keys()) == ["python"]
    _assert_common_entry(
        res2["python"], probe="interpreter", evidence="requirements-dev.txt"
    )


def test_unreal_uproject_detector(tmp_path: Path) -> None:
    game_dir = tmp_path / "Game"
    game_dir.mkdir()
    uproj = game_dir / "GreyboxTD.uproject"
    uproj.write_text('{"EngineAssociation": "5.6.1"}\n', encoding="utf-8")

    res = detect_tools(tmp_path, chosen=CHOSEN, event="adoption")
    assert list(res.keys()) == ["unreal"]
    _assert_common_entry(
        res["unreal"],
        probe="file",
        evidence="Game/GreyboxTD.uproject",
        event="adoption",
    )
    assert res["unreal"]["file"] == "Game/GreyboxTD.uproject"
    assert res["unreal"]["key"] == "EngineAssociation"


@pytest.mark.parametrize(
    "filename",
    ["scene.hip", "scene.hiplc", "scene.hipnc", "houdini.version"],
)
def test_houdini_detector(tmp_path: Path, filename: str) -> None:
    (tmp_path / filename).write_text("houdini\n", encoding="utf-8")
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["houdini"]
    _assert_common_entry(res["houdini"], probe="command", evidence=filename)
    assert res["houdini"]["argv"] == ["houdini", "--version"]


def test_blender_detector(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "character.blend").write_bytes(b"BLENDER-v402")
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["blender"]
    _assert_common_entry(
        res["blender"], probe="command", evidence="assets/character.blend"
    )
    assert res["blender"]["argv"] == ["blender", "--version"]


def test_dockerfile_detector(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\n", encoding="utf-8")
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["docker"]
    _assert_common_entry(res["docker"], probe="command", evidence="Dockerfile")
    assert res["docker"]["argv"] == ["docker", "--version"]


def test_github_workflows_yml_is_ignored(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: CI\non: push\n", encoding="utf-8")
    (wf / "release.yaml").write_text("name: Release\n", encoding="utf-8")

    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert res == {}


def test_template_needs_merge_and_hermes_pm_tools(tmp_path: Path) -> None:
    # Project has rust-toolchain.toml (which detects cargo and rust)
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.82.0"\n',
        encoding="utf-8",
    )
    res = detect_tools(
        tmp_path,
        chosen=CHOSEN,
        event=EVENT,
        template_needs=["cargo", "xdotool", "cua-driver", "ffmpeg", "ripgrep", "chromium", "node"],
    )

    # Sorted by tool name
    assert list(res.keys()) == [
        "cargo",
        "chromium",
        "cua-driver",
        "ffmpeg",
        "node",
        "ripgrep",
        "rust",
        "xdotool",
    ]

    # cargo was already detected from rust-toolchain.toml -> not overridden by template_needs
    assert res["cargo"]["reason"] == format_reason("rust-toolchain.toml", EVENT)
    assert res["cargo"]["probe"] == "command"
    assert res["cargo"]["argv"] == ["cargo", "--version"]

    # Non-Hermes template_needs tool gets probe=command argv=[NAME, "--version"]
    _assert_common_entry(res["xdotool"], probe="command", evidence="template needs")
    assert res["xdotool"]["argv"] == ["xdotool", "--version"]

    # Hermes-managed tools (including node when no project node evidence exists) get probe="pm"
    for pm_tool in ("cua-driver", "ffmpeg", "ripgrep", "chromium", "node"):
        assert pm_tool in HERMES_PM_TOOLS
        _assert_common_entry(res[pm_tool], probe="pm", evidence="template needs")
        assert "argv" not in res[pm_tool]


def test_project_node_evidence_not_overridden_by_template_needs_node(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    res = detect_tools(
        tmp_path,
        chosen=CHOSEN,
        event=EVENT,
        template_needs=["node", "cua-driver"],
    )
    assert list(res.keys()) == ["cua-driver", "node"]
    # node comes from package.json (probe=command), not probe=pm
    _assert_common_entry(res["node"], probe="command", evidence="package.json")
    assert res["node"]["argv"] == ["node", "--version"]
    # cua-driver comes from template_needs (probe=pm)
    _assert_common_entry(res["cua-driver"], probe="pm", evidence="template needs")


def test_walk_skips_node_modules_and_dot_git_and_bounds_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for ignored in (".git", "node_modules", "target", ".venv", "__pycache__", ".adopt", ".worktrees"):
        d = tmp_path / ignored
        d.mkdir(parents=True)
        (d / "package.json").write_text('{"packageManager": "yarn@4.0.0"}\n', encoding="utf-8")
        (d / "pyproject.toml").write_text('[project]\nname = "ignored"\n', encoding="utf-8")
        (d / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (d / "Rogue.uproject").write_text("{}\n", encoding="utf-8")

    assert detect_tools(tmp_path, chosen=CHOSEN, event=EVENT) == {}

    # Verify walk is bounded by MAX_DETECT_WALK_ENTRIES
    for i in range(10):
        (tmp_path / f"a_filler_{i:02d}.txt").write_text("x\n", encoding="utf-8")
    (tmp_path / "z_late_Dockerfile" / "Dockerfile").parent.mkdir()
    (tmp_path / "z_late_Dockerfile" / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")

    # Positive control: with default MAX_DETECT_WALK_ENTRIES, z_late_Dockerfile/Dockerfile IS reached and detected
    pos_res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(pos_res.keys()) == ["docker"]
    assert pos_res["docker"]["reason"] == format_reason("z_late_Dockerfile/Dockerfile", EVENT)

    monkeypatch.setattr(tool_detect, "MAX_DETECT_WALK_ENTRIES", 5)
    assert detect_tools(tmp_path, chosen=CHOSEN, event=EVENT) == {}


@pytest.mark.parametrize(
    "evil_pm",
    [
        "/tmp/evil-bin@1.0.0",
        "../evil-bin@1.0.0",
        "./evil@1.0.0",
        "evil-bin@1.0.0",
        "custom_pm@2.0.0",
        "bash@5.0",
        "python3@3.12",
    ],
)
def test_package_manager_rce_repro_rejects_non_allowlisted_package_manager(
    tmp_path: Path, evil_pm: str
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "untrusted", "packageManager": evil_pm}),
        encoding="utf-8",
    )
    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert list(res.keys()) == ["node"]
    for entry in res.values():
        argv = entry.get("argv")
        if argv is not None:
            assert all("/" not in tok for tok in argv)


def test_all_detectors_argv_tokens_in_constant_allowlist_and_never_from_repo_content(
    tmp_path: Path,
) -> None:
    constant_allowlist = {
        "rustc",
        "cargo",
        "go",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "bun",
        "houdini",
        "blender",
        "docker",
        "--version",
        "version",
    }
    assert tool_detect.ALLOWED_DETECTOR_ARGV_TOKENS == constant_allowlist

    # Populate a repo with hostile/crafted content across all detected file types
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "/tmp/evil-rust"\n', encoding="utf-8"
    )
    (tmp_path / "go.mod").write_text(
        "module /tmp/evil\n\ntoolchain go/tmp/evil-go\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "evil", "packageManager": "/tmp/evil-bin@1.0.0"}),
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / ".nvmrc").write_text("/tmp/evil-node\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "/tmp/evil"\n', encoding="utf-8")
    (tmp_path / "Evil.uproject").write_text('{"EngineAssociation": "/tmp/evil-ue"}\n', encoding="utf-8")
    (tmp_path / "scene.hip").write_text("/tmp/evil-houdini\n", encoding="utf-8")
    (tmp_path / "scene.blend").write_text("/tmp/evil-blender\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM /tmp/evil-docker\n", encoding="utf-8")

    res = detect_tools(tmp_path, chosen=CHOSEN, event=EVENT)
    assert res
    for name, entry in res.items():
        assert "/" not in name
        assert "module" not in entry
        if "argv" in entry:
            argv = entry["argv"]
            assert isinstance(argv, list) and argv
            for tok in argv:
                assert "/" not in tok
                assert "\\" not in tok
                assert tok in constant_allowlist
        if "file" in entry:
            # file must be a relative path from the walk
            assert not Path(entry["file"]).is_absolute()
            assert ".." not in Path(entry["file"]).parts
        if "regex" in entry:
            assert entry["regex"] == tool_detect._NVMRC_REGEX


