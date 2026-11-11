"""Which real tools a test needs, and a stand-in toolchain for tests that only need a tool to answer.

Two kinds of test touch a template's toolchain:

* A test whose job needs the real tool (it builds, formats or lints a project with it)
  calls ``need(...)``. It skips with the reason "<tool> not installed" exactly when that
  tool is absent, and runs unchanged when it is present.
* A test of the plugin's own logic (naming, rules, registration) that reaches a tool
  only because project creation probes its version, or runs a check whose result is not
  what is tested, runs inside ``fake_toolchain(...)``: small scripts that report a
  version and succeed. Those tests run on every machine.

The tables below are checked against the template files by
``test_template_kit.test_toolchain_needs_tables_match_template_files``.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

# The Markdown and YAML linters templates.format_check_commands runs on every template.
SCAFFOLD_LINT_TOOLS: tuple[str, ...] = ("yamllint", "rumdl")

# What creating a project from a bundled template and running its own check calls, in
# this order: template.yaml `needs`, the other tools TOOLS.lock is seeded with at
# creation, the check commands, then tools only the template's xtask looks up.
TEMPLATE_CHECK_TOOLS: dict[str, tuple[str, ...]] = {
    "cpp-golden": ("cmake", "ninja", "clang", "clang-format", "clang-tidy", "ctest", "clang++"),
    "dotnet-golden": ("dotnet",),
    "go-golden": ("go", "golangci-lint", "gofmt"),
    "python-golden": ("uv",),
    "rust-golden": ("cargo", "rustc"),
    "ts-node-golden": ("node", "pnpm"),
    "web-golden": ("node", "pnpm"),
}

# What templates.format_check_commands requires for each bundled template, in the order
# it looks them up: `needs`, the two scaffold linters, then each format command.
TEMPLATE_FORMAT_TOOLS: dict[str, tuple[str, ...]] = {
    "cpp-golden": ("cmake", "ninja", "clang", "clang-format", "clang-tidy", "yamllint", "rumdl"),
    "dotnet-golden": ("dotnet", "yamllint", "rumdl"),
    "go-golden": ("go", "golangci-lint", "gofmt", "yamllint", "rumdl"),
    "python-golden": ("uv", "yamllint", "rumdl", "ruff"),
    "rust-golden": ("cargo", "yamllint", "rumdl"),
    "ts-node-golden": ("node", "pnpm", "yamllint", "rumdl", "biome"),
    "web-golden": ("node", "pnpm", "yamllint", "rumdl", "biome"),
}

FAKE_TOOL_VERSION = "99.0.0"

_MISSING_BINARY = re.compile(r"missing binary: ([^)]+)\)")


def missing_tool(*tools: str) -> str | None:
    """The first of `tools` not found on PATH, or None when all are installed."""
    for tool in tools:
        if tool.strip() and shutil.which(tool) is None:
            return tool
    return None


def need(*tools: str) -> None:
    """Skip the calling test with "<tool> not installed" when any of `tools` is absent."""
    tool = missing_tool(*tools)
    if tool is not None:
        pytest.skip(f"{tool} not installed")


def _found_version(tool: str, entry: Mapping[str, Any] | None = None) -> str | None:
    """The version `tool` reports, read the way the product probes it, or None if unreadable."""
    from hermes_plugins.defuzz import toolchk

    probe_entry = dict(entry) if entry is not None else {
        "probe": "command",
        "argv": [tool, "--version"],
    }
    try:
        version, _where = toolchk.probe(tool, probe_entry)
    except Exception:  # noqa: BLE001 - unreadable versions must not skip
        return None
    text = str(version).strip()
    return text or None


def need_at_least(tool: str, minimum: str, entry: Mapping[str, Any] | None = None) -> None:
    """Skip when `tool` is absent or its installed version is older than `minimum`.

    The reasons are "<tool> not installed" and "<tool> <found> is older than <minimum>".
    A version that cannot be read does not skip: the test runs and fails loudly.
    """
    from hermes_plugins.defuzz import toolchk

    if shutil.which(tool) is None:
        pytest.skip(f"{tool} not installed")
    version = _found_version(tool, entry)
    if version is not None and toolchk.version_below(version, minimum):
        pytest.skip(f"{tool} {version} is older than {minimum}")


def template_floor_entries(template_id: str) -> dict[str, dict[str, Any]]:
    """The `minimum` entries a bundled template ships in its own TOOLS.lock."""
    from hermes_plugins.defuzz import toolchk
    from hermes_plugins.defuzz.templates import templates_root

    entries: dict[str, dict[str, Any]] = {}
    for lock_path in sorted((templates_root() / template_id).glob("*/TOOLS.lock")):
        for name, entry in toolchk.load_lock(lock_path)["tools"].items():
            if entry.get("minimum"):
                entries[str(name)] = dict(entry)
    return entries


def template_floors(template_id: str) -> dict[str, str]:
    """The oldest version each tool may be for this template, as its TOOLS.lock states it."""
    return {
        name: str(entry["minimum"]) for name, entry in template_floor_entries(template_id).items()
    }


def need_template_tools(spec: Any) -> None:
    """Skip when a tool `spec` needs is absent, or older than the template's own floor.

    The floors come from the bundled template's TOOLS.lock, the same file the product
    reads, so a template states its minimum in one place only.
    """
    needs = [n for n in getattr(spec, "needs", ()) if n.strip()]
    missing = missing_tool(*needs)
    if missing is not None:
        pytest.skip(f"{missing} not installed")
    if not _is_bundled(spec):
        return
    entries = template_floor_entries(spec.id)
    for name in needs:
        entry = entries.get(name)
        if entry is not None:
            need_at_least(name, str(entry["minimum"]), entry)


def _is_bundled(spec: Any) -> bool:
    from hermes_plugins.defuzz.templates import templates_root

    try:
        return Path(spec.root).resolve().parent == templates_root().resolve()
    except (AttributeError, OSError):
        return False


def check_tools(spec: Any) -> tuple[str, ...]:
    """Tools creating a project from `spec` and running its own check call.

    A bundled template uses TEMPLATE_CHECK_TOOLS; any other template (a test's own
    descriptor) is held to what it declares in `needs`.
    """
    if _is_bundled(spec) and spec.id in TEMPLATE_CHECK_TOOLS:
        return TEMPLATE_CHECK_TOOLS[spec.id]
    return tuple(n for n in spec.needs if n.strip())


def format_tools(spec: Any) -> tuple[str, ...]:
    """Tools templates.format_check_commands requires for `spec`, in the order it checks them."""
    if _is_bundled(spec) and spec.id in TEMPLATE_FORMAT_TOOLS:
        return TEMPLATE_FORMAT_TOOLS[spec.id]
    tools = [n for n in spec.needs if n.strip()]
    tools.extend(SCAFFOLD_LINT_TOOLS)
    check = spec.repos[0].check if spec.repos else None
    for entry in check.format_cmds if check is not None else ():
        tools.append(getattr(entry, "cmd", entry)[0])
    return tuple(dict.fromkeys(tools))


def need_lint_tools(report: Mapping[str, Any]) -> None:
    """Skip when a Defuzz lint report could not run a tool because its program is absent.

    linter.run_lint lists such a tool in `tools_missing` only when one of its programs
    is not found; any other problem still fails the caller's assertions.
    """
    if not report.get("tools_missing"):
        return
    for error in report.get("tool_errors") or []:
        if error.get("status") == "not_installed":
            match = _MISSING_BINARY.search(str(error.get("message", "")))
            if match:
                pytest.skip(f"{match.group(1).split(',')[0].strip()} not installed")
    pytest.skip(f"{report['tools_missing'][0]} not installed")


def write_fake_tool(directory: Path, tool: str) -> Path:
    """Write a stand-in `tool` into `directory`: it prints a version and exits 0."""
    script = directory / tool
    script.write_text(
        "#!/bin/sh\n"
        f"# Stand-in {tool} for tests: it reports a version and succeeds.\n"
        f"echo '{tool} version {FAKE_TOOL_VERSION}'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


@contextlib.contextmanager
def fake_toolchain(directory: Path, tools: Iterable[str]) -> Iterator[Path]:
    """Put stand-in `tools` first on PATH for the duration of the block.

    Each one prints "<tool> version 99.0.0" and exits 0 whatever its arguments, so a
    version probe passes any minimum and a check command succeeds. Works in pytest
    functions, unittest methods and plain calls alike (PATH is restored afterwards).
    """
    bin_dir = Path(directory)
    bin_dir.mkdir(parents=True, exist_ok=True)
    for tool in dict.fromkeys(t for t in tools if t.strip()):
        write_fake_tool(bin_dir, tool)
    old_path = os.environ.get("PATH")
    os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}" if old_path else str(bin_dir)
    try:
        yield bin_dir
    finally:
        if old_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = old_path


@pytest.fixture
def fake_rust_toolchain(tmp_path: Path) -> Iterator[Path]:
    """Stand-in `cargo` and `rustc` first on PATH, for tests that create a Rust project.

    Use it where creating the project only probes the toolchain or runs its check and the
    real tool is not what the test is about.
    """
    with fake_toolchain(tmp_path / "fake-bin", ("cargo", "rustc")) as bin_dir:
        yield bin_dir
