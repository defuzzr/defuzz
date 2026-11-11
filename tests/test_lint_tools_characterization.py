"""Characterization tests for lint_tools, toolchk, tool_guard and tool_doctor."""

from __future__ import annotations

import io
import json
import os
import sqlite3
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import (  # noqa: E402
    lint_tools,
    safety,
    state_store,
    tool_doctor,
    tool_guard,
    tool_seed,
    toolchk,
)


def test_lint_tools_exports_and_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert len(lint_tools.TOOLS) == 27
    for spec in lint_tools.TOOLS:
        assert lint_tools.by_name(spec.name) is spec

    assert lint_tools.is_generated_lockfile("sub/pnpm-lock.yaml") is True
    assert lint_tools.is_generated_lockfile("sub/pyproject.toml") is False

    assert lint_tools.derive_glsl_stage("shader.vert") == "vert"
    assert lint_tools.derive_glsl_stage("shader.frag.glsl") == "frag"
    assert lint_tools.derive_glsl_stage("shader.glsl") is None
    assert lint_tools.derive_glsl_stage("noext") is None

    assert lint_tools.detect_rust_edition(tmp_path) == "2024"
    (tmp_path / "Cargo.toml").write_text('edition = "2018"\n', encoding="utf-8")
    assert lint_tools.detect_rust_edition(tmp_path) == "2018"

    assert lint_tools._ps_quote("a'b") == "'a''b'"
    assert lint_tools._targets(["a.py", "  "], ".") == ["a.py"]
    assert lint_tools._targets([], ".") == []
    assert lint_tools._targets([], "fallback") == ["fallback"]

    assert lint_tools._glob_matches_path("**/*.py", "a/b/c.py") is True
    assert lint_tools._glob_matches_path("**/foo/*.py", "foo/bar.py") is True
    assert lint_tools._glob_matches_path("Cargo.toml", "Cargo.toml") is True
    assert lint_tools._glob_matches_path("Cargo.toml", "sub/Cargo.toml") is False
    assert lint_tools._glob_matches_path("a/*.py", "a/b.py") is True

    calls: list[Path] = []
    orig_scan = lint_tools.scan

    def spy_scan(root: Path, max_entries: int = lint_tools.MAX_DETECT_WALK_ENTRIES) -> lint_tools.ScanResult:
        calls.append(Path(root))
        return orig_scan(root, max_entries=max_entries)

    monkeypatch.setattr(lint_tools, "scan", spy_scan)
    rels = lint_tools._collect_project_relpaths(tmp_path)
    assert rels == ["Cargo.toml"]
    assert len(calls) == 1


def test_lint_tools_argv_all_specs_snapshot(tmp_path: Path) -> None:
    (tmp_path / "compile_commands.json").write_text("[]", encoding="utf-8")
    files = ["src/a.cpp", "src/b.vert.glsl", "src/c.hlsl"]
    expected: dict[tuple[str, str], list[str]] = {
        ("ruff", "pre"): ["ruff", "check", "--select", "E9,F63,F7,F82", "--output-format", "json", "."],
        ("ruff", "post"): ["ruff", "check", "--output-format", "json", "."],
        ("ruff-format", "pre"): ["ruff", "format", "--check", "."],
        ("rustfmt", "pre"): ["rustfmt", "--check", "--edition", "2024", *files],
        ("clippy", "post"): ["cargo", "clippy", "--all-targets", "--offline", "--message-format", "json", "--", "-D", "warnings"],
        ("biome", "pre"): [
            "biome", "check", "--formatter-enabled=true", "--linter-enabled=false",
            "--assist-enabled=false", "--reporter", "json", *files,
        ],
        ("biome", "post"): ["biome", "ci", "--reporter", "json", *files],
        ("oxlint", "post"): ["oxlint", "--deny-warnings", "--format", "json", *files],
        ("gofmt", "pre"): ["gofmt", "-e", "-l", *files],
        ("go-vet", "post"): ["go", "vet", "./..."],
        ("golangci-lint", "post"): ["golangci-lint", "run", "--output.json.path", "stdout", "--show-stats=false", "./..."],
        ("clang-format", "pre"): ["clang-format", "--dry-run", "-Werror", *files],
        ("clang-tidy", "post"): ["clang-tidy", "-p", str(tmp_path), *files],
        ("csharpier", "pre"): ["csharpier", "check", *files],
        ("dotnet-format", "post"): ["dotnet", "format", "--verify-no-changes", "--no-restore", "--include", *files],
        ("gdformat", "pre"): ["gdformat", "--check", *files],
        ("gdlint", "post"): ["gdlint", *files],
        ("stylua", "pre"): ["stylua", "--check", *files],
        ("selene", "post"): ["selene", "--display-style", "json2", "--no-summary", *files],
        ("glslangValidator", "pre"): ["glslangValidator", "-V", "-S", "vert", "-o", os.devnull, "src/b.vert.glsl"],
        ("glslangValidator", "post"): ["glslangValidator", "-V", "-S", "vert", "--spirv-val", "-o", os.devnull, "src/b.vert.glsl"],
        ("dxc", "pre"): ["dxc", "-T", "lib_6_x", "-Fo", os.devnull, *files],
        ("dxc", "post"): ["dxc", "-Weverything", "-T", "lib_6_x", "-Fo", os.devnull, *files],
        ("shfmt", "pre"): ["shfmt", "-d", *files],
        ("shellcheck", "post"): ["shellcheck", "-f", "json", *files],
        ("yamllint", "pre"): ["yamllint", "-f", "parsable", "-d", "{extends: relaxed, rules: {line-length: disable}}", *files],
        ("yamllint", "post"): ["yamllint", "-f", "parsable", "--strict", *files],
        ("taplo", "pre"): ["taplo", "format", "--check", *files],
        ("taplo", "post"): ["taplo", "lint", "--no-schema", *files],
        ("rumdl", "pre"): ["rumdl", "check", "--output-format", "json", *files],
        ("rumdl", "post"): ["rumdl", "check", "--output-format", "json", *files],
        ("hadolint", "pre"): ["hadolint", "-f", "json", *files],
        ("hadolint", "post"): ["hadolint", "-f", "json", "--failure-threshold", "warning", *files],
    }
    for (name, mode), exp_cmd in expected.items():
        spec = lint_tools.by_name(name)
        assert lint_tools.argv(spec, mode, tmp_path, files) == exp_cmd


def test_toolchk_validation_and_seams(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock_file = tmp_path / "TOOLS.lock"

    # Header validation errors
    for bad_toml, match_sub in (
        ('lock = "not-a-table"\n', "[lock] must be a table"),
        ('[lock]\nschema = 2\n', "unsupported [lock].schema"),
        ('[lock]\nenforce = "invalid"\n', "invalid [lock].enforce"),
        ('[lock]\nage_nudge_months = -1\n', "age_nudge_months"),
        ('[lock]\nage_nudge_months = true\n', "age_nudge_months"),
        ('[lock]\nnetwork = "no"\n', "[lock].network must be a boolean"),
        ('["bad/name"]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "interpreter"\n', "invalid tool table name"),
        ('a = "not-a-table"\n', "[a] must be a table"),
        ('[a]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "interpreter"\nsource = "alien"\n', "invalid source"),
        ('[a]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "module"\nmodule = ""\n', "module probe 'module' must be a non-empty string"),
        ('[a]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "pm"\npackage = "   "\n', "pm probe 'package' must be a non-empty string"),
        ('[a]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "file"\nfile = "f"\nkey = ""\n', "file probe 'key' must be a non-empty string"),
        ('[a]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "file"\nfile = "f"\nregex = ""\n', "file probe 'regex' must be a non-empty string"),
        ('[a]\nversion = "1"\nchosen = "2026-01-01"\nreason = "r"\nprobe = "interpreter"\nadvisory = "bad"\n', "'advisory' must be a table"),
    ):
        lock_file.write_text(bad_toml, encoding="utf-8")
        with pytest.raises(toolchk.PreflightError) as exc_info:
            toolchk.load_lock(lock_file)
        assert exc_info.value.code == 4
        assert match_sub in exc_info.value.report["summary"]

    # Monkeypatch seams on _resolve_command and _run_bounded_command
    monkeypatch.setattr(toolchk, "_resolve_command", lambda *a, **k: ["/fake/tool", "--version"])
    monkeypatch.setattr(toolchk, "_run_bounded_command", lambda *a, **k: ("tool 4.2.0\n", ""))
    ver, where = toolchk.probe("tool", {"probe": "command", "argv": ["tool", "--version"]}, tmp_path)
    assert (ver, where) == ("4.2.0", "/fake/tool")


def test_tool_guard_provenance_edit_and_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "state" / "state.db"

    # Missing lock -> static_lock_summary could_not_verify
    summary_missing = tool_guard.static_lock_summary(root, db_path=db)
    assert summary_missing["coverage"] == "could_not_verify"
    assert summary_missing["trust"]["status"] == "unknown"

    # Malformed lock -> static_lock_summary Invalid TOOLS.lock
    (root / "TOOLS.lock").write_text("[broken", encoding="utf-8")
    summary_bad = tool_guard.static_lock_summary(root, db_path=db)
    assert summary_bad["coverage"] == "could_not_verify"
    assert summary_bad.get("error") == "Invalid TOOLS.lock"

    # Valid lock
    toolchk.dump_lock(
        root / "TOOLS.lock",
        {
            "lock": dict(toolchk.DEFAULT_HEADER),
            "tools": {
                "python": {
                    "version": "3.12.0",
                    "chosen": "2026-11-01",
                    "reason": "initial auto seed",
                    "probe": "interpreter",
                    "source": "auto",
                }
            },
        },
    )
    summary_ok = tool_guard.static_lock_summary(root, db_path=db)
    assert summary_ok["coverage"] == "verified"
    assert summary_ok["tools"] == [{"name": "python", "version": "3.12.0", "source": "auto"}]

    # Trust and edit_lock (auto -> human on reason edit, log_warning when log write fails)
    state = tool_guard.inspect_lock_trust(root, db_path=db)
    tool_guard.trust_lock(root, expected_hash=state["tools_lock_hash"], db_path=db)
    monkeypatch.setattr(toolchk, "probe", lambda *a, **k: ("3.12.0", "/usr/bin/python"))
    monkeypatch.setattr(
        tool_seed,
        "_append_tools_log_entries",
        lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
    )
    row = tool_guard.edit_lock(root, "python", "reviewed reason", action="reason", db_path=db)
    assert row["by"] == "human"
    assert row["reason"] == "reviewed reason"
    assert row["log_warning"] == "Lock saved; advisory log could not be written"
    assert tool_guard.inspect_lock_trust(root, db_path=db)["trusted"] is True


def test_tool_doctor_statuses_and_timeout_seam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "state.db"
    assert tool_doctor.registered_project_paths(db_path=db_file) == []

    # Empty file -> []
    db_file.write_bytes(b"")
    assert tool_doctor.registered_project_paths(db_path=db_file) == []
    db_file.unlink()

    # Valid DB without projects table -> []
    with sqlite3.connect(db_file) as conn:
        conn.execute("CREATE TABLE other (id INT)")
    assert tool_doctor.registered_project_paths(db_path=db_file) == []
    db_file.unlink()

    # Project with probe-failed and unlisted tools, and broken check
    proj_fail = tmp_path / "proj-fail"
    proj_fail.mkdir()
    toolchk.dump_lock(
        proj_fail / "TOOLS.lock",
        {
            "lock": dict(toolchk.DEFAULT_HEADER),
            "tools": {
                "ruff": {
                    "version": "0.7.0",
                    "chosen": "2026-11-06",
                    "reason": "pinned",
                    "probe": "command",
                    "argv": ["ruff", "--version"],
                    "source": "human",
                }
            },
        },
    )

    def failing_probe(*args: Any, **kwargs: Any) -> tuple[str, str]:
        raise RuntimeError("boom\nmultiline")

    monkeypatch.setattr(toolchk, "probe", failing_probe)
    rep = tool_doctor.doctor_report([proj_fail], timeout=1.5)
    assert rep["ok"] is False
    assert rep["projects"][0]["status"] == "drift"
    assert "ruff probe failed (RuntimeError: boom multiline) != 0.7.0" in rep["lines"][0]

    # When toolchk.check raises PreflightError or generic Exception
    monkeypatch.setattr(
        toolchk,
        "check",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("check exploded\nline2")),
    )
    rep_broken = tool_doctor.doctor_report([proj_fail])
    assert rep_broken["projects"][0]["status"] == "broken"
    assert rep_broken["lines"][0] == "  BROKEN proj-fail  check exploded line2"


def test_internal_helpers_and_facade(tmp_path: Path) -> None:
    # lint_tools internal helpers
    assert lint_tools._find_in_root_or_build_dirs(tmp_path, "compile_commands.json") is None
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "compile_commands.json").write_text("[]", encoding="utf-8")
    assert lint_tools._find_in_root_or_build_dirs(tmp_path, "compile_commands.json") == tmp_path / "out"

    # toolchk internal helpers
    assert toolchk._ordered_keys({"z": 1, "version": 2, "a": 3}, ("version", "chosen")) == ["version", "a", "z"]
    header, enforce = toolchk._validate_lock_header(tmp_path / "TOOLS.lock", {"enforce": "block"})
    assert enforce == "block" and header["schema"] == 1
    toml_str = toolchk._serialize_lock_toml(
        {"lock": header, "tools": {"py": {"version": "3.12", "chosen": "2026-01-01", "reason": "ok", "probe": "interpreter"}}},
        ["# top"],
    )
    assert toml_str.startswith("# top\n\n[lock]\n")

    # tool_doctor internal helpers
    assert tool_doctor._drift_detail(
        ["a", "b", "c"],
        {
            "a": {"status": "drift", "installed": "2.0", "locked": "1.0"},
            "b": {"status": "unlisted"},
            "c": {"status": "ok"},
        },
        "fallback",
    ) == "a 2.0 != 1.0; b unlisted"
    broken = tool_doctor._broken_project(tmp_path, "demo", ValueError("line1\nline2"))
    assert broken["status"] == "broken" and broken["line"] == "  BROKEN demo  line1 line2"


def test_advisory_kind_empty_string_not_treated_as_omitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "latest.json").write_text('{"v": "2.3.4"}', encoding="utf-8")
    lock = {
        "lock": {**toolchk.DEFAULT_HEADER, "network": False},
        "tools": {
            "python": {
                "version": "3.12.0",
                "chosen": "2026-11-01",
                "reason": "pinned",
                "probe": "interpreter",
                "source": "human",
                "advisory": {"kind": "", "json": "latest.json", "key": "v"},
            }
        },
    }
    monkeypatch.setattr(toolchk, "probe", lambda *a, **k: ("3.12.0", "/usr/bin/python"))
    rep = toolchk.check(["python"], lock, tmp_path)
    py_rep = rep["tools"]["python"]
    assert py_rep.get("upstream_latest") is None
    assert py_rep["advisory_error"] == "advisory kind '' refused: [lock].network is false"
    assert py_rep["error"] == "advisory kind '' refused: [lock].network is false"


def test_tool_guard_runtime_safety_monkeypatch_seams(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "state" / "state.db"
    lock_file = root / "TOOLS.lock"
    toolchk.dump_lock(
        lock_file,
        {
            "lock": dict(toolchk.DEFAULT_HEADER),
            "tools": {
                "python": {
                    "version": "3.12.0",
                    "chosen": "2026-11-01",
                    "reason": "initial",
                    "probe": "interpreter",
                    "source": "human",
                }
            },
        },
    )
    before_bytes = lock_file.read_bytes()

    with monkeypatch.context() as mp:
        mp.setattr(
            safety,
            "verify_nofollow_within_root",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("nofollow blocked")),
        )
        with pytest.raises(RuntimeError, match="nofollow blocked"):
            tool_guard._replace_lock(root, b"replacement")
        assert lock_file.read_bytes() == before_bytes

    with monkeypatch.context() as mp:
        mp.setattr(
            safety,
            "assert_safe_root",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("safe_root blocked")),
        )
        with pytest.raises(RuntimeError, match="safe_root blocked"):
            tool_guard.edit_lock(root, "python", "updated reason", action="reason", db_path=db)
        assert lock_file.read_bytes() == before_bytes
