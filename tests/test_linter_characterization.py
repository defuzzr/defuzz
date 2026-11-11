"""Characterization tests for linter.py."""

from __future__ import annotations

import inspect
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_env, lint_tools, linter, safe_state_store  # noqa: E402


EXPECTED_FUNCTIONS = (
    "_to_posix",
    "_norm_posix",
    "_is_windows_drive_path",
    "_is_valid_int",
    "_is_crash_exit",
    "relpath",
    "_split_location",
    "_normalize_severity",
    "make_finding",
    "_format_unparseable_message",
    "_make_parse_error_marker",
    "_unparseable_fallback",
    "_combined_text",
    "_load_json_payload",
    "_parse_ruff",
    "_parse_ruff_format",
    "_parse_rustfmt",
    "_parse_cargo_json",
    "_parse_biome_json",
    "_parse_oxlint_json",
    "_parse_gofmt",
    "_parse_go_vet",
    "_parse_golangci_json",
    "_parse_clang_format",
    "_parse_clang_tidy",
    "_parse_csharpier",
    "_parse_dotnet_format",
    "_parse_gdformat",
    "_parse_gdlint",
    "_parse_stylua",
    "_parse_selene_json",
    "_parse_glslang",
    "_parse_dxc",
    "_parse_shfmt",
    "_parse_shellcheck_json",
    "_parse_pwsh_parse_json",
    "_parse_psscriptanalyzer_json",
    "_parse_yamllint_parsable",
    "_parse_taplo",
    "_parse_rumdl_json",
    "_parse_hadolint_json",
    "detect_for_project",
    "_matching_files_for_spec",
    "_dedupe_and_sort_findings",
    "_error_response",
    "_load_rule_settings",
    "_settings_group",
    "run_lint",
)


def test_public_and_private_facade_inventory():
    assert linter.MAX_FILES_PER_TOOL == 2000
    assert "clippy" in linter.REPO_CODE_WARNING
    assert "clean" in linter.VALID_TOOL_STATUSES
    assert issubclass(linter.LintError, RuntimeError)
    assert linter.ToolSpec is lint_tools.ToolSpec
    for fn_name in EXPECTED_FUNCTIONS:
        fn = getattr(linter, fn_name, None)
        assert callable(fn), f"Missing callable {fn_name} on linter"
    sig = inspect.signature(linter.run_lint)
    assert list(sig.parameters) == [
        "root",
        "mode",
        "env",
        "runner",
        "db_path",
        "timeout_scale",
        "max_findings",
    ]


def test_primitive_and_path_helpers():
    assert linter._to_posix("") == ""
    assert linter._to_posix("   ") == ""
    assert linter._to_posix(".") == ""
    assert linter._to_posix("././a\\b\\c.py") == "a/b/c.py"
    assert linter._norm_posix("//server/share/file.py") == "/server/share/file.py"
    assert linter._norm_posix("./") == ""
    assert linter._is_windows_drive_path("C:/foo") is True
    assert linter._is_windows_drive_path("z:") is True
    assert linter._is_windows_drive_path("/posix/path") is False

    assert linter._is_valid_int(0, min_value=0) is True
    assert linter._is_valid_int(True, min_value=0) is False
    assert linter._is_valid_int(False, min_value=0) is False
    assert linter._is_valid_int(-1, min_value=0) is False
    assert linter._is_valid_int("1", min_value=0) is False

    assert linter._is_crash_exit(-9) is True
    assert linter._is_crash_exit(0) is False
    assert linter._is_crash_exit(0xFFFFFFFF) is False
    assert linter._is_crash_exit(0x1_0000_0000) is False
    assert linter._is_crash_exit(0xC0000005) is True
    assert linter._is_crash_exit(0x80004005) is False

    assert linter.relpath("/repo", None) == ""
    assert linter.relpath(None, "./a/b.py") == "a/b.py"
    assert linter._normalize_severity(2) == "error"
    assert linter._normalize_severity(1) == "warning"
    assert linter._normalize_severity(0) == "info"
    assert linter._normalize_severity("fatal") == "error"
    assert linter._normalize_severity("medium") == "warning"
    assert linter._normalize_severity("note") == "info"
    assert linter._normalize_severity("unknown-sev", default="warning") == "warning"

    finding = linter.make_finding(
        file="/repo/a.py", line="not-an-int", rule=None, message=None, tool=None, severity=-1, root="/repo"
    )
    assert finding == {
        "file": "a.py",
        "line": 0,
        "rule": "",
        "message": "",
        "tool": "",
        "severity": "info",
    }
    assert linter.make_finding(line=-5)["line"] == 0


def test_parser_variants_and_fallback_paths():
    root = Path("/repo")
    # Biome location via UTF-8 byte span and message parts list
    biome_span_payload = (
        '{"diagnostics":[{"category":"lint/style","severity":"information",'
        '"message":[{"content":"Line "},{"content":"two"}],'
        '"location":{"path":"src/a.ts","sourceCode":"first\\nsecond\\n","span":[6,12]}}]}'
    )
    biome_out = linter._parse_biome_json(
        linter.ParseInput(stdout=biome_span_payload, returncode=1, root=root, tool="biome")
    )
    assert biome_out == [
        {
            "file": "src/a.ts",
            "line": 2,
            "rule": "lint/style",
            "message": "Line two",
            "tool": "biome",
            "severity": "info",
        }
    ]

    # Biome location via start.line and string description
    biome_start_payload = (
        '{"diagnostics":[{"category":"lint/correctness","severity":"error",'
        '"description":"bad","location":{"path":{"file":"src/b.ts"},"start":{"line":9}}}]}'
    )
    assert linter._parse_biome_json(
        linter.ParseInput(stdout=biome_start_payload, returncode=1, root=root, tool="biome")
    )[0]["line"] == 9

    # Oxlint top-level list variant
    ox_list_payload = '[{"file":"src/x.js","line":4,"rule_id":"no-eval","message":"bad eval","severity":"warn"}]'
    assert linter._parse_oxlint_json(
        linter.ParseInput(stdout=ox_list_payload, returncode=1, root=root, tool="oxlint")
    ) == [
        {
            "file": "src/x.js",
            "line": 4,
            "rule": "no-eval",
            "message": "bad eval",
            "tool": "oxlint",
            "severity": "warning",
        }
    ]

    # golangci-lint Issues: null at rc=0 vs rc=1
    assert (
        linter._parse_golangci_json(
            linter.ParseInput(stdout='{"Issues": null}', returncode=0, root=root, tool="golangci-lint")
        )
        == []
    )
    assert (
        linter._parse_golangci_json(
            linter.ParseInput(stdout='{"Issues": null}', returncode=1, root=root, tool="golangci-lint")
        )[0]["rule"]
        == "parse-error"
    )

    # Cargo skips .cargo/registry spans
    cargo_reg = (
        '{"reason":"compiler-message","message":{"code":{"code":"W1"},"level":"warning",'
        '"message":"dep warn","spans":[{"file_name":"/srv/user/.cargo/registry/src/x.rs","line_start":3,"is_primary":true}]}}\n'
    )
    assert (
        linter._parse_cargo_json(
            linter.ParseInput(stdout=cargo_reg, returncode=0, root=root, tool="clippy")
        )
        == []
    )

    # glslang replaces file token "0" when single input file is provided
    glsl_out = linter._parse_glslang(
        linter.ParseInput(
            stdout="WARNING: 0:12: precision caveat\n",
            returncode=0,
            root=root,
            files=("shaders/sky.frag",),
            tool="glslangValidator",
        )
    )
    assert glsl_out[0]["file"] == "shaders/sky.frag"
    assert glsl_out[0]["severity"] == "warning"

    # rumdl dict keys ("warnings", "findings", "diagnostics", singleton)
    for wrapper in (
        '{"warnings":[{"file":"a.md","line":1,"rule":"MD1","message":"m"}]}',
        '{"findings":[{"filename":"a.md","line":1,"code":"MD1","message":"m"}]}',
        '{"diagnostics":[{"file":"a.md","line":1,"rule":"MD1","message":"m"}]}',
        '{"file":"a.md","line":1,"rule":"MD1","message":"m"}',
    ):
        res = linter._parse_rumdl_json(
            linter.ParseInput(stdout=wrapper, returncode=1, root=root, tool="rumdl")
        )
        assert res == [
            {
                "file": "a.md",
                "line": 1,
                "rule": "MD1",
                "message": "m",
                "tool": "rumdl",
                "severity": "warning",
            }
        ]

    # taplo bare .toml filename line
    taplo_out = linter._parse_taplo(
        linter.ParseInput(stdout="Cargo.toml\n", returncode=1, root=root, tool="taplo")
    )
    assert taplo_out[0]["file"] == "Cargo.toml"
    assert taplo_out[0]["message"] == "TOML file needs formatting"


def test_run_lint_unregistered_parser_and_custom_requires(tmp_path):
    from dataclasses import replace

    base_spec = lint_tools.by_name("shfmt")
    bad_parser_spec = replace(base_spec, parser="missing-parser", input_globs=())
    with (
        mock.patch.object(linter, "detect_for_project", return_value=([bad_parser_spec], [])),
        mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"),
    ):
        res = linter.run_lint(
            tmp_path,
            "pre",
            env={},
            db_path=tmp_path / "state.db",
            runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""),
        )
    assert res["ok"] is False
    assert res["status"] == "incomplete"
    assert res["tool_errors"][0]["status"] == "crashed"
    assert "No parser registered" in res["tool_errors"][0]["message"]

    req_spec = replace(base_spec, requires=("custom_req.json",), input_globs=())
    with mock.patch.object(linter, "detect_for_project", return_value=([req_spec], [])):
        res_req = linter.run_lint(tmp_path, "pre", env={}, db_path=tmp_path / "state.db")
    assert res_req["ok"] is False
    assert res_req["tool_errors"][0]["status"] == "not_configured"
    assert "missing required custom_req.json" in res_req["tool_errors"][0]["message"]


def test_load_rule_settings_and_dedupe_sorting(tmp_path):
    db = tmp_path / "state.db"
    safe_state_store.save_state(db, "workspace-ui", "settings", "not-a-dict", 1)
    with pytest.raises(linter.LintError, match="settings must be an object"):
        linter._load_rule_settings(db)

    f1 = linter.make_finding(file="b.py", line=2, rule="R2", message="m", tool="t", severity="warning")
    f2 = linter.make_finding(file="a.py", line=1, rule="R1", message="m", tool="t", severity="error")
    f3 = dict(f1)
    assert linter._dedupe_and_sort_findings([f1, f2, f3]) == [f2, f1]


def test_relpath_preserves_whitespace_and_spaced_dot_suffix():
    assert linter.relpath("/repo", "/repo/ . ") == " . "
    assert linter.relpath("/repo", "/repo/ ") == " "
    assert linter.relpath("C:/repo", "c:/repo/ . ") == " . "
    assert linter.relpath("C:/repo", "c:/repo/ ") == " "
    assert linter.relpath("/repo", "/repo/./a.py") == "a.py"
    assert linter.relpath("C:/repo", "c:/repo/./a.py") == "a.py"


def test_parse_cargo_json_skips_registry_before_validating_code():
    root = Path("/repo")
    ndjson = (
        '{"reason":"compiler-message","message":{"code":{"code":"clippy::needless_return"},"level":"warning",'
        '"message":"unneeded return","spans":[{"file_name":"/repo/src/lib.rs","line_start":10,"is_primary":true}]}}\n'
        '{"reason":"compiler-message","message":{"code":"invalid-non-dict-code","level":"warning",'
        '"message":"dep warning","spans":[{"file_name":"/srv/u/.cargo/registry/src/dep/lib.rs","line_start":4,"is_primary":true}]}}\n'
    )
    out = linter._parse_cargo_json(
        linter.ParseInput(stdout=ndjson, returncode=0, root=root, tool="clippy")
    )
    assert out == [
        {
            "file": "src/lib.rs",
            "line": 10,
            "rule": "clippy::needless_return",
            "message": "unneeded return",
            "tool": "clippy",
            "severity": "warning",
        }
    ]


def test_relpath_keeps_lexical_root_candidate_when_realpath_raises(monkeypatch):
    monkeypatch.setattr(linter.os.path, "realpath", mock.Mock(side_effect=OSError("realpath failed")))
    assert linter.relpath(".", Path.cwd() / "file.py") == "file.py"


def test_spirv_temp_cleanup_semantics_and_duration_timing(tmp_path, monkeypatch):
    spec = lint_tools.by_name("glslangValidator")
    created_paths: list[Path] = []
    orig_unlink = Path.unlink

    # 1. KeyboardInterrupt must not trigger unlink (and PermissionError in unlink must not mask it)
    unlink_called_on_kb = False

    def fail_unlink(self, *args, **kwargs):
        nonlocal unlink_called_on_kb
        unlink_called_on_kb = True
        raise PermissionError("unlink forbidden")

    def raise_kb(cmd, *args, **kwargs):
        if "-o" in cmd:
            created_paths.append(Path(cmd[cmd.index("-o") + 1]))
        raise KeyboardInterrupt("abort")

    with (
        mock.patch.object(lint_env, "run", side_effect=raise_kb),
        mock.patch.object(Path, "unlink", fail_unlink),
    ):
        with pytest.raises(KeyboardInterrupt, match="abort"):
            linter._execute_tool_mode(
                spec,
                "pre",
                tmp_path,
                ["shader.vert"],
                {"glslangValidator": "/usr/bin/glslangValidator"},
                {},
                10,
                None,
            )
    assert unlink_called_on_kb is False
    for p in created_paths:
        orig_unlink(p, missing_ok=True)

    # 2. Cleanup time is included in duration_ms for both success and Exception paths
    clock = [100.0]

    def fake_monotonic():
        return clock[0]

    def slow_unlink(self, *args, **kwargs):
        clock[0] += 0.250
        return orig_unlink(self, *args, **kwargs)

    monkeypatch.setattr(linter.time, "monotonic", fake_monotonic)
    with (
        mock.patch.object(
            lint_env,
            "run",
            side_effect=lambda *a, **kw: (
                clock.__setitem__(0, clock[0] + 0.125)
                or subprocess.CompletedProcess(a[0], 0, "", "")
            ),
        ),
        mock.patch.object(Path, "unlink", slow_unlink),
    ):
        _, cp, duration_ms, exc = linter._execute_tool_mode(
            spec,
            "pre",
            tmp_path,
            ["shader.vert"],
            {"glslangValidator": "/usr/bin/glslangValidator"},
            {},
            10,
            None,
        )
    assert exc is None
    assert cp.returncode == 0
    assert duration_ms == 375

    clock[0] = 200.0

    def run_then_fail(*a, **kw):
        clock[0] += 0.125
        raise RuntimeError("boom")

    with (
        mock.patch.object(lint_env, "run", side_effect=run_then_fail),
        mock.patch.object(Path, "unlink", slow_unlink),
    ):
        _, cp_err, duration_err_ms, exc_err = linter._execute_tool_mode(
            spec,
            "pre",
            tmp_path,
            ["shader.vert"],
            {"glslangValidator": "/usr/bin/glslangValidator"},
            {},
            10,
            None,
        )
    assert cp_err is None
    assert isinstance(exc_err, RuntimeError)
    assert duration_err_ms == 375

