"""Portable tool pins: `minimum`, `enforce`, and creation-time seeding of TOOLS.lock.

A shipped template states the oldest tool version its build files actually need (`minimum`);
the new project's own TOOLS.lock is seeded from the user's machine at creation time. These
tests simulate tool versions through the `toolchk.probe` injection point; nothing is installed.
"""

from __future__ import annotations

import io
import json
import re
import shutil
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import setup_manifest, tool_seed, toolchk  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = REPO_ROOT / "templates"
SEEDED_TEMPLATES = ("python-golden", "ts-node-golden", "rust-golden", "web-golden")
FLOOR_TEMPLATES = ("cpp-golden", "dotnet-golden", "go-golden")
ALL_TEMPLATES = SEEDED_TEMPLATES + FLOOR_TEMPLATES
HINT = "or run `hermes defuzz setup-tools` to see what it can install."

# The floor each template's build files need (see the reason in each shipped TOOLS.lock).
EXPECTED_MINIMUMS = {
    "cpp-golden": {
        "cmake": "3.20",
        "ninja": "1.10",
        "clang": "14.0",
        "clang-format": "23.1",
        "clang-tidy": "23.1",
    },
    "dotnet-golden": {"dotnet": "10.0.100"},
    "go-golden": {"go": "1.22", "golangci-lint": "2.0.0"},
}


def _header(enforce: str = "warn") -> dict[str, Any]:
    return {"schema": 1, "enforce": enforce, "age_nudge_months": 0, "network": False}


def _entry(version: str, minimum: str | None = None, source: str = "auto") -> dict[str, Any]:
    entry: dict[str, Any] = {
        "version": version,
        "chosen": "2026-11-10",
        "reason": "test",
        "probe": "command",
        "argv": ["clang", "--version"],
        "source": source,
    }
    if minimum is not None:
        entry["minimum"] = minimum
    return entry


def fake_probe(versions: dict[str, str]):
    def _probe(name: str, entry: dict, project_root: Any = None, timeout: float = 20.0) -> tuple[str, str]:
        if name not in versions:
            raise FileNotFoundError(name)
        return versions[name], f"/bin/{name}"

    return _probe


def _check(tools: dict[str, dict[str, Any]], versions: dict[str, str], tmp_path: Path, enforce: str = "warn") -> dict:
    with patch.object(toolchk, "probe", side_effect=fake_probe(versions)):
        return toolchk.check(list(tools), {"lock": _header(enforce), "tools": tools}, tmp_path)


def _bump(version: str) -> str:
    parts = version.split(".")
    parts[0] = str(int(parts[0]) + 1)
    return ".".join(parts)


def _lower(version: str) -> str:
    parts = [int(p) for p in version.split(".")]
    for idx in range(len(parts) - 1, -1, -1):
        if parts[idx] > 0:
            parts[idx] -= 1
            break
    return ".".join(str(p) for p in parts)


# --- check(): exact, minimum, warn, block, missing ------------------------------------------


def test_exact_pin_match_is_ok(tmp_path: Path) -> None:
    rep = _check({"clang": _entry("18.1.3", source="human")}, {"clang": "18.1.3"}, tmp_path)
    assert rep["ok"] and rep["blocked"] == [] and rep["warnings"] == []
    assert rep["summary"] == "preflight ok"


def test_exact_pin_without_minimum_blocks_any_mismatch_even_under_warn(tmp_path: Path) -> None:
    """No `minimum` means only the locked version is compatible: a mismatch is not 'drift within range'."""
    rep = _check({"clang": _entry("18.1.3", source="human")}, {"clang": "18.1.8"}, tmp_path)
    assert not rep["ok"]
    assert rep["blocked"] == ["clang: installed 18.1.8 != locked 18.1.3 (/bin/clang)"]


def test_warn_reports_drift_inside_minimum_and_exits_zero(tmp_path: Path) -> None:
    lock = {"lock": _header("warn"), "tools": {"clang": _entry("18.1.3", minimum="14.0")}}
    with patch.object(toolchk, "probe", side_effect=fake_probe({"clang": "19.1.0"})):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rep = toolchk.require(["clang"], tmp_path, lock=lock)
    assert rep["ok"] is True
    assert rep["blocked"] == []
    assert rep["tools"]["clang"]["status"] == "drift"
    assert rep["warnings"] == [
        'clang: installed 19.1.0 != locked 18.1.3 (/bin/clang); meets minimum 14.0, warning only (enforce = "warn")'
    ]
    assert rep["summary"].startswith("preflight ok with 1 warning: clang: installed 19.1.0")
    assert "DRIFT" in stderr.getvalue()


def test_warn_also_covers_older_than_locked_but_not_below_minimum(tmp_path: Path) -> None:
    rep = _check({"clang": _entry("18.1.3", minimum="14.0")}, {"clang": "14.0.6"}, tmp_path)
    assert rep["ok"] and len(rep["warnings"]) == 1


def test_block_turns_drift_inside_minimum_into_exit_2(tmp_path: Path) -> None:
    lock = {"lock": _header("block"), "tools": {"clang": _entry("18.1.3", minimum="14.0")}}
    with patch.object(toolchk, "probe", side_effect=fake_probe({"clang": "19.1.0"})):
        with pytest.raises(toolchk.PreflightError) as exc, redirect_stderr(io.StringIO()):
            toolchk.require(["clang"], tmp_path, lock=lock)
    assert exc.value.code == 2
    assert exc.value.report["blocked"] == ["clang: installed 19.1.0 != locked 18.1.3 (/bin/clang)"]
    assert exc.value.report["warnings"] == []


@pytest.mark.parametrize("enforce", ["warn", "block"])
def test_below_minimum_always_blocks_with_one_plain_line(tmp_path: Path, enforce: str) -> None:
    rep = _check({"clang": _entry("14.0.6", minimum="16.0")}, {"clang": "14.0.6"}, tmp_path, enforce)
    assert not rep["ok"]
    assert rep["blocked"] == [f"clang: found 14.0.6, need >= 16.0 (/bin/clang). Upgrade clang, {HINT}"]
    assert rep["tools"]["clang"]["below_minimum"] is True
    assert "TOO-OLD" in rep["text"]


def test_missing_tool_fails_with_one_plain_line_code_3(tmp_path: Path) -> None:
    lock = {"lock": _header("warn"), "tools": {"clang": _entry("14.0", minimum="14.0")}}
    with patch.object(toolchk, "probe", side_effect=fake_probe({})):
        with pytest.raises(toolchk.PreflightError) as exc, redirect_stderr(io.StringIO()):
            toolchk.require(["clang"], tmp_path, lock=lock)
    assert exc.value.code == 3
    assert exc.value.report["probe_failed"] == [f"clang: not found on PATH, need >= 14.0. Install clang, {HINT}"]


def test_missing_tool_without_minimum_also_plain(tmp_path: Path) -> None:
    rep = _check({"clang": _entry("18.1.3", source="human")}, {}, tmp_path)
    assert rep["probe_failed"] == [f"clang: not found on PATH. Install clang, {HINT}"]


@pytest.mark.parametrize(
    ("installed", "minimum", "below"),
    [
        ("1.10.0", "1.9", False),
        ("1.9.9", "1.10", True),
        ("3.20", "3.20.0", False),
        ("10.0.99", "10.0.100", True),
        ("1.11.1.git", "1.10", False),
        ("2.15.0", "2.0.0", False),
    ],
)
def test_minimum_compares_numerically(installed: str, minimum: str, below: bool) -> None:
    assert toolchk.version_below(installed, minimum) is below


def test_load_lock_validates_minimum(tmp_path: Path) -> None:
    lock_file = tmp_path / "TOOLS.lock"
    base = '[clang]\nversion = "18.1.3"\nchosen = "2026-11-10"\nreason = "r"\nprobe = "command"\nargv = ["clang", "--version"]\n'
    lock_file.write_text(base + 'minimum = "fourteen"\n', encoding="utf-8")
    with pytest.raises(toolchk.PreflightError) as exc:
        toolchk.load_lock(lock_file)
    assert exc.value.code == 4 and "minimum" in exc.value.report["summary"]
    lock_file.write_text(base + 'minimum = "14.0"\n', encoding="utf-8")
    loaded = toolchk.load_lock(lock_file)
    assert loaded["tools"]["clang"]["minimum"] == "14.0"
    toolchk.dump_lock(lock_file, loaded)
    assert toolchk.load_lock(lock_file)["tools"]["clang"]["minimum"] == "14.0"


# --- shipped template locks ------------------------------------------------------------------


@pytest.mark.parametrize("template", SEEDED_TEMPLATES)
def test_templates_without_floor_ship_no_lock(template: str) -> None:
    """python/ts-node/rust/web never failed elsewhere: they ship no lock, so creation seeds it.

    Their floors live in their own build files (ts-node-golden and web-golden: `.nvmrc` 24,
    `engines.node` >=24, `packageManager` pnpm@12.15.0; see tests/test_template_web_golden.py).
    """
    assert not (TEMPLATES / template / "tmpl_prefix" / "TOOLS.lock").exists()


@pytest.mark.parametrize("template", FLOOR_TEMPLATES)
def test_shipped_lock_states_floors_not_author_versions(template: str) -> None:
    loaded = toolchk.load_lock(TEMPLATES / template / "tmpl_prefix" / "TOOLS.lock")
    assert loaded["lock"]["enforce"] == "warn"
    mins = {name: entry.get("minimum") for name, entry in loaded["tools"].items()}
    assert mins == EXPECTED_MINIMUMS[template]
    for name, entry in loaded["tools"].items():
        assert entry["source"] == "auto", f"{template}:{name} must be re-seeded from the user's machine"
        assert entry["version"] == entry["minimum"], f"{template}:{name} version must be the floor placeholder"
        assert "/usr/" not in entry["reason"] and "/home/" not in entry["reason"]


@pytest.mark.parametrize("template", FLOOR_TEMPLATES)
def test_shipped_lock_passes_at_minimum_and_newer_fails_below(template: str, tmp_path: Path) -> None:
    loaded = toolchk.load_lock(TEMPLATES / template / "tmpl_prefix" / "TOOLS.lock")
    floors = EXPECTED_MINIMUMS[template]
    tools = loaded["tools"]
    at_min = _check(tools, dict(floors), tmp_path)
    assert at_min["ok"] and at_min["warnings"] == [], at_min["summary"]
    newer = _check(tools, {k: _bump(v) for k, v in floors.items()}, tmp_path)
    assert newer["ok"], newer["summary"]
    for name, floor in floors.items():
        versions = dict(floors)
        versions[name] = _lower(floor)
        below = _check(tools, versions, tmp_path)
        assert not below["ok"]
        assert below["blocked"] == [
            f"{name}: found {_lower(floor)}, need >= {floor} (/bin/{name}). Upgrade {name}, {HINT}"
        ]


def _seed_copy(template: str, tmp_path: Path, machine: dict[str, str] | None, default: str) -> Path:
    spec = load_template(TEMPLATES / template)
    root = tmp_path / template
    shutil.copytree(TEMPLATES / template / "tmpl_prefix", root)

    def _probe(name: str, entry: dict, project_root: Any = None, timeout: float = 20.0) -> tuple[str, str]:
        if machine is not None and name in machine:
            return machine[name], f"/bin/{name}"
        return entry.get("minimum") or default, f"/bin/{name}"

    with patch.object(toolchk, "probe", side_effect=_probe):
        summary = tool_seed.seed_lock(root, event="project creation", template_needs=spec.needs, today="2026-11-10")
    assert summary["probe_failed"] == {}
    return root


@pytest.mark.parametrize("template", ALL_TEMPLATES)
def test_creation_seeds_lock_from_the_users_machine(template: str, tmp_path: Path) -> None:
    floors = EXPECTED_MINIMUMS.get(template, {})
    machine = {k: _bump(v) for k, v in floors.items()}
    root = _seed_copy(template, tmp_path, machine, default="99.1.0")
    loaded = toolchk.load_lock(root / "TOOLS.lock")
    for need in load_template(TEMPLATES / template).needs:
        assert str(need) in loaded["tools"]
    for name, entry in loaded["tools"].items():
        assert entry["source"] == "auto"
        assert entry["chosen"] == "2026-11-10"
        if name in floors:
            assert entry["version"] == machine[name], "seeded version must be the user's, not the author's"
            assert entry["minimum"] == floors[name], "seeding must keep the template floor"
    with patch.object(toolchk, "probe", side_effect=fake_probe({n: e["version"] for n, e in loaded["tools"].items()})):
        rep = toolchk.check(list(loaded["tools"]), loaded, root)
    assert rep["ok"] and rep["warnings"] == [], rep["summary"]


@pytest.mark.parametrize("template", FLOOR_TEMPLATES)
def test_creation_on_machine_below_floor_fails_plainly(template: str, tmp_path: Path) -> None:
    floors = EXPECTED_MINIMUMS[template]
    name, floor = next(iter(floors.items()))
    root = _seed_copy(template, tmp_path, {name: _lower(floor)}, default="99.1.0")
    loaded = toolchk.load_lock(root / "TOOLS.lock")
    assert loaded["tools"][name]["version"] == _lower(floor)
    with patch.object(toolchk, "probe", side_effect=fake_probe({n: e["version"] for n, e in loaded["tools"].items()})):
        rep = toolchk.check(list(loaded["tools"]), loaded, root)
    assert rep["blocked"] == [f"{name}: found {_lower(floor)}, need >= {floor} (/bin/{name}). Upgrade {name}, {HINT}"]


# --- build files agree with the floors -------------------------------------------------------


def _setup_item(name: str) -> Any:
    return next(item for item in setup_manifest.ITEMS if item.name == name)


def test_cpp_floor_matches_cmake_minimum_required() -> None:
    text = (TEMPLATES / "cpp-golden/tmpl_prefix/CMakeLists.txt").read_text(encoding="utf-8")
    m = re.search(r"cmake_minimum_required\(VERSION ([0-9.]+)\.\.\.([0-9.]+)\)", text)
    assert m, "use the min...policy_max form so older CMake is accepted with the newest policies"
    assert m.group(1) == EXPECTED_MINIMUMS["cpp-golden"]["cmake"]
    assert "CMAKE_CXX_STANDARD 20" in text


def test_go_floor_matches_go_mod_and_setup_tools() -> None:
    go_mod = (TEMPLATES / "go-golden/tmpl_prefix/go.mod").read_text(encoding="utf-8")
    assert re.search(r"^go 1\.22$", go_mod, re.M)
    floors = EXPECTED_MINIMUMS["go-golden"]
    assert not toolchk.version_below(_setup_item("go").version, floors["go"])
    assert not toolchk.version_below(_setup_item("golangci-lint").version, floors["golangci-lint"])
    ci = (TEMPLATES / "go-golden/tmpl_prefix/xtask/main_test.go").read_text(encoding="utf-8")
    assert "go 1.27.3" not in ci


def test_dotnet_global_json_matches_floor_and_target_framework() -> None:
    root = TEMPLATES / "dotnet-golden/tmpl_prefix"
    sdk = json.loads((root / "global.json").read_text(encoding="utf-8"))["sdk"]
    assert sdk == {"version": EXPECTED_MINIMUMS["dotnet-golden"]["dotnet"], "rollForward": "latestFeature"}
    tfm = re.search(r"<TargetFramework>net(\d+)\.0</TargetFramework>", (root / "Directory.Build.props").read_text())
    assert tfm and sdk["version"].split(".")[0] == tfm.group(1)


def test_dotnet_setup_tools_installs_an_sdk_the_template_accepts() -> None:
    floor = EXPECTED_MINIMUMS["dotnet-golden"]["dotnet"]
    installed = _setup_item("dotnet").version
    assert installed.split(".")[0] == floor.split(".")[0] and not toolchk.version_below(installed, floor)
