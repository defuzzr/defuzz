"""Unit tests for linter.py (parsers, detect_for_project, and run_lint)."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_env, lint_tools, linter, state_store  # noqa: E402

PARSERS = linter.PARSERS
LintError = linter.LintError
ParseInput = linter.ParseInput
detect_for_project = linter.detect_for_project
make_finding = linter.make_finding
relpath = linter.relpath
run_lint = linter.run_lint

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "lint_outputs"

# Provenance of fixture samples under tests/fixtures/lint_outputs/<parser>.txt:
# - ruff.txt: documented Ruff `--output-format json` schema (docs.astral.sh/ruff/linter/#json)
# - ruff-format.txt: documented `ruff format --check` output (docs.astral.sh/ruff/formatter/)
# - rustfmt.txt: documented `rustfmt --check` Diff in header format (rust-lang/rustfmt)
# - cargo-json.txt: documented Cargo `--message-format json` compiler-message NDJSON (doc.rust-lang.org/cargo/reference/external-tools.html)
# - biome-json.txt: documented Biome `--reporter json` diagnostics format (biomejs.dev/reference/reporters/#json)
# - oxlint-json.txt: documented Oxlint `--format json` miette diagnostic schema (oxc.rs/docs/guide/usage/linter/cli.html)
# - gofmt.txt: documented `gofmt -e -l` stdout file list + stderr syntax error format (pkg.go.dev/cmd/gofmt)
# - go-vet.txt: documented `go vet` package header + file:line:col stderr format (pkg.go.dev/cmd/vet)
# - golangci-json.txt: documented golangci-lint JSON Issues array schema (golangci-lint.run)
# - clang-format.txt: documented `clang-format --dry-run -Werror` -Wclang-format-violations diagnostic (clang.llvm.org/docs/ClangFormat.html)
# - clang-tidy.txt: documented clang-tidy `file:line:col: severity: msg [check]` format (clang.llvm.org/extra/clang-tidy/)
# - csharpier.txt: documented `csharpier check` Warning/Error line format (csharpier.com/docs/CLI)
# - dotnet-format.txt: documented `dotnet format --verify-no-changes` MSBuild diagnostic format (learn.microsoft.com/en-us/dotnet/core/tools/dotnet-format)
# - gdformat.txt: faithful hand-written sample from gdtoolkit `gdformat --check` output (Scony/godot-gdscript-toolkit)
# - gdlint.txt: documented gdtoolkit `gdlint` `path:line: Error: msg (rule)` output (Scony/godot-gdscript-toolkit)
# - stylua.txt: documented `stylua --check` `Diff in path:` header output (JohnnyMorganz/StyLua)
# - selene-json.txt: documented `selene --display-style json` NDJSON Diagnostic + Summary lines (kampfkarren.github.io/selene)
# - glslang.txt: documented `glslangValidator` `ERROR: path:line: msg` format (KhronosGroup/glslang)
# - dxc.txt: documented DirectXShaderCompiler `path:line:col: error|warning: msg` Clang-style diagnostic (microsoft/DirectXShaderCompiler)
# - shfmt.txt: documented `shfmt -d` unified diff headers + syntax error line (mvdan/sh)
# - shellcheck-json.txt: documented `shellcheck -f json` array format (github.com/koalaman/shellcheck)
# - pwsh-parse-json.txt: faithful hand-written sample of PowerShell `[Parser]::ParseFile` ParseError serialized via `ConvertTo-Json`
# - psscriptanalyzer-json.txt: documented `Invoke-ScriptAnalyzer | ConvertTo-Json` DiagnosticRecord schema (learn.microsoft.com/en-us/powershell/module/psscriptanalyzer)
# - yamllint-parsable.txt: documented `yamllint -f parsable` format (yamllint.readthedocs.io/en/stable/quickstart.html)
# - taplo.txt: faithful hand-written sample combining `taplo format --check` and `taplo lint` diagnostics (taplo.tamasfe.dev)
# - rumdl-json.txt: faithful hand-written sample matching `rumdl check --output-format json` array schema (rvben/rumdl)
# - hadolint-json.txt: documented `hadolint -f json` array format (github.com/hadolint/hadolint)

JSON_PARSERS = {
    "ruff",
    "cargo-json",
    "biome-json",
    "oxlint-json",
    "golangci-json",
    "selene-json",
    "shellcheck-json",
    "pwsh-parse-json",
    "psscriptanalyzer-json",
    "rumdl-json",
    "hadolint-json",
}


class TestHelpers(unittest.TestCase):
    def test_relpath_normalizes_paths(self) -> None:
        root = Path("/repo")
        self.assertEqual(relpath(root, "/repo/src/main.py"), "src/main.py")
        self.assertEqual(relpath(root, "./src/main.py"), "src/main.py")
        self.assertEqual(relpath(root, ".\\src\\sub\\main.py"), "src/sub/main.py")
        self.assertEqual(relpath(root, "/repo\\src\\win.py"), "src/win.py")
        self.assertEqual(relpath(root, "/other/outside.py"), "/other/outside.py")
        self.assertEqual(relpath(root, "../outside.py"), "../outside.py")
        self.assertEqual(relpath(root, ""), "")
        self.assertEqual(relpath(root, "."), "")
        # Normalise both sides before containment; root '/' works; traversal outside stays absolute normalised; whitespace preserved
        self.assertEqual(relpath("/", "/src/a.py"), "src/a.py")
        self.assertEqual(relpath("/", "/"), "")
        self.assertEqual(relpath(root, "/repo/../outside.py"), "/outside.py")
        self.assertEqual(relpath(root, "/repo/src/../a.py"), "a.py")
        self.assertEqual(relpath("/repo/sub/..", "/repo/src/a.py"), "src/a.py")
        self.assertEqual(relpath(root, "/repo/dir with space/my file.py"), "dir with space/my file.py")
        self.assertEqual(relpath(root, "/repo/ leading and trailing .py "), " leading and trailing .py ")
        self.assertEqual(relpath(root, " leading and trailing .py "), " leading and trailing .py ")

    def test_relpath_windows_case_insensitive_and_symlink_inside_root(self) -> None:
        self.assertEqual(relpath("C:\\Repo", "c:\\repo\\a.py"), "a.py")
        self.assertEqual(relpath("c:/repo/sub", "C:\\Repo\\SUB\\dir\\File.py"), "dir/File.py")
        self.assertEqual(relpath("C:\\Repo", "C:\\repo"), "")
        self.assertEqual(relpath("C:\\Repo", "D:\\repo\\a.py"), "D:/repo/a.py")
        with tempfile.TemporaryDirectory() as tmp:
            real_root = Path(tmp) / "real_repo"
            real_root.mkdir()
            sub = real_root / "src"
            sub.mkdir()
            target_file = sub / "mod.py"
            target_file.write_text("x = 1\n", encoding="utf-8")
            link_dir = real_root / "linked_src"
            os.symlink(str(sub), str(link_dir))
            alias_root = Path(tmp) / "alias_repo"
            os.symlink(str(real_root), str(alias_root))
            self.assertEqual(relpath(real_root, link_dir / "mod.py"), "linked_src/mod.py")
            self.assertEqual(relpath(alias_root, real_root / "src" / "mod.py"), "src/mod.py")
            self.assertEqual(relpath(real_root, alias_root / "src" / "mod.py"), "src/mod.py")

    def test_split_location_helper(self) -> None:
        split_loc = getattr(linter, "_split_location", None)
        self.assertTrue(callable(split_loc), "_split_location helper must exist")
        self.assertEqual(
            split_loc("/repo/src/engine.cpp:27:15: error: bad format"),
            ("/repo/src/engine.cpp", 27, 15, "error: bad format"),
        )
        self.assertEqual(
            split_loc("scripts/player.gd:15: Error: bad name (function-name)"),
            ("scripts/player.gd", 15, None, "Error: bad name (function-name)"),
        )
        self.assertEqual(
            split_loc("./pyproject.toml:9:5"),
            ("./pyproject.toml", 9, 5, ""),
        )
        self.assertIsNone(split_loc("not a location line"))

    def test_make_finding_schema(self) -> None:
        f = make_finding(
            file="/repo/src/a.py",
            line=10,
            rule="F401",
            message="unused import",
            tool="ruff",
            severity="ERROR",
            root=Path("/repo"),
        )
        self.assertEqual(
            f,
            {
                "file": "src/a.py",
                "line": 10,
                "rule": "F401",
                "message": "unused import",
                "tool": "ruff",
                "severity": "error",
            },
        )
        self.assertTrue(issubclass(LintError, RuntimeError))


class TestParsers(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("/repo")

    def _run_fixture(self, parser_id: str, tool_name: str | None = None) -> list[dict]:
        fixture_path = FIXTURES_DIR / f"{parser_id}.txt"
        self.assertTrue(fixture_path.is_file(), f"Missing fixture {fixture_path}")
        raw = fixture_path.read_text(encoding="utf-8")
        inp = ParseInput(
            stdout=raw,
            stderr="",
            returncode=1,
            root=self.root,
            files=("sample",),
            tool=tool_name or parser_id,
        )
        return PARSERS[parser_id](inp)

    def test_all_tool_parsers_registered_and_have_fixtures(self) -> None:
        expected_ids = {s.parser for s in lint_tools.TOOLS}
        self.assertEqual(len(expected_ids), 27)
        self.assertEqual(set(PARSERS.keys()), expected_ids)
        for pid in expected_ids:
            self.assertTrue((FIXTURES_DIR / f"{pid}.txt").is_file(), f"Missing fixture for {pid}")

    def test_every_parser_handles_empty_and_garbage_input(self) -> None:
        for pid, fn in PARSERS.items():
            with self.subTest(parser=pid, case="empty"):
                res_empty = fn(
                    ParseInput(stdout="", stderr="", returncode=0, root=self.root, files=(), tool=pid)
                )
                self.assertEqual(res_empty, [])

            with self.subTest(parser=pid, case="garbage_rc0"):
                res_rc0 = fn(
                    ParseInput(
                        stdout="garbage{",
                        stderr="garbage{",
                        returncode=0,
                        root=self.root,
                        files=(),
                        tool=pid,
                    )
                )
                if pid in JSON_PARSERS:
                    self.assertEqual(len(res_rc0), 1, f"{pid} must reject unparseable output even on rc=0")
                    self.assertEqual(res_rc0[0]["rule"], "parse-error")
                else:
                    self.assertEqual(res_rc0, [])

            with self.subTest(parser=pid, case="garbage_rc1"):
                res_rc1 = fn(
                    ParseInput(
                        stdout="garbage{",
                        stderr="fatal cli error",
                        returncode=1,
                        root=self.root,
                        files=(),
                        tool=pid,
                    )
                )
                self.assertEqual(len(res_rc1), 1, f"{pid} must not return [] on rc=1 with unparseable output")
                self.assertEqual(res_rc1[0]["file"], "")
                self.assertEqual(res_rc1[0]["line"], 0)
                self.assertEqual(res_rc1[0]["rule"], "parse-error")
                self.assertEqual(res_rc1[0]["tool"], pid)
                self.assertEqual(res_rc1[0]["severity"], "error")
                self.assertIn("rc=1", res_rc1[0]["message"])
                self.assertIn("garbage{", res_rc1[0]["message"])

            with self.subTest(parser=pid, case="empty_rc1"):
                res_empty_rc1 = fn(
                    ParseInput(
                        stdout="",
                        stderr="",
                        returncode=2,
                        root=self.root,
                        files=(),
                        tool=pid,
                    )
                )
                self.assertEqual(len(res_empty_rc1), 1, f"{pid} must not return [] on rc=2 with empty output")
                self.assertEqual(res_empty_rc1[0]["rule"], "parse-error")
                self.assertEqual(res_empty_rc1[0]["severity"], "error")
                self.assertEqual(res_empty_rc1[0]["tool"], pid)
                self.assertIn("rc=2", res_empty_rc1[0]["message"])

    def test_nonzero_exit_with_zero_json_diagnostics_emits_error_finding(self) -> None:
        empty_json_cases = {
            "ruff": "[]",
            "cargo-json": '{"reason":"build-finished","success":false}\n',
            "biome-json": '{"diagnostics": []}',
            "oxlint-json": '{"diagnostics": []}',
            "golangci-json": '{"Issues": []}',
            "selene-json": '{"type":"Summary","errors":0,"warnings":0}\n',
            "shellcheck-json": '{"comments": []}',
            "pwsh-parse-json": "[]",
            "psscriptanalyzer-json": "[]",
            "rumdl-json": "[]",
            "hadolint-json": "[]",
        }
        for pid, payload in empty_json_cases.items():
            with self.subTest(parser=pid):
                out = PARSERS[pid](
                    ParseInput(
                        stdout=payload,
                        stderr="fatal configuration or build failure",
                        returncode=1,
                        root=self.root,
                        files=(),
                        tool=pid,
                    )
                )
                self.assertEqual(len(out), 1, f"{pid} returned [] on rc=1 with 0 JSON diagnostics")
                self.assertEqual(out[0]["severity"], "error")
                self.assertEqual(out[0]["rule"], "parse-error")
                self.assertEqual(out[0]["tool"], pid)
                self.assertIn("fatal configuration or build failure", out[0]["message"])

    def test_ndjson_rejects_malformed_json_lines_even_when_other_lines_parse(self) -> None:
        cargo_repro = '{"reason":"build-finished","success":true}\n{broken'
        out_cargo_repro = PARSERS["cargo-json"](
            ParseInput(stdout=cargo_repro, returncode=0, root=self.root, tool="clippy")
        )
        self.assertEqual(len(out_cargo_repro), 1)
        self.assertEqual(out_cargo_repro[0]["rule"], "parse-error")

        selene_repro = '{"type":"Summary","errors":0,"warnings":0}\n{broken'
        out_selene_repro = PARSERS["selene-json"](
            ParseInput(stdout=selene_repro, returncode=0, root=self.root, tool="selene")
        )
        self.assertEqual(len(out_selene_repro), 1)
        self.assertEqual(out_selene_repro[0]["rule"], "parse-error")

        # Non-JSON human text on stderr stays allowed alongside valid NDJSON on stdout
        cargo_stderr_ok = PARSERS["cargo-json"](
            ParseInput(
                stdout='{"reason":"compiler-message","message":{"code":{"code":"E0001"},"level":"error","message":"boom","spans":[]}}\n',
                stderr="    Checking demo v0.1.0 (/repo)\n",
                returncode=1,
                root=self.root,
                tool="clippy",
            )
        )
        self.assertEqual(
            cargo_stderr_ok,
            [
                {
                    "file": "",
                    "line": 0,
                    "rule": "E0001",
                    "message": "boom",
                    "tool": "clippy",
                    "severity": "error",
                }
            ],
        )

        selene_stderr_ok = PARSERS["selene-json"](
            ParseInput(
                stdout='{"type":"Diagnostic","severity":"Warning","code":"unused_variable","message":"unused x","primary_label":{"filename":"src/a.lua","span":{"start_line":2}}}\n',
                stderr="selene: checking 1 file\n",
                returncode=1,
                root=self.root,
                tool="selene",
            )
        )
        self.assertEqual(
            selene_stderr_ok,
            [
                {
                    "file": "src/a.lua",
                    "line": 3,
                    "rule": "unused_variable",
                    "message": "unused x",
                    "tool": "selene",
                    "severity": "warning",
                }
            ],
        )

        # Populated Cargo span records must have string file_name and int line_start >= 1
        cargo_bad_span = '{"reason":"compiler-message","message":{"message":"oops","spans":[{}]}}'
        out_bad_span = PARSERS["cargo-json"](
            ParseInput(stdout=cargo_bad_span, returncode=1, root=self.root, tool="clippy")
        )
        self.assertEqual(len(out_bad_span), 1)
        self.assertEqual(out_bad_span[0]["rule"], "parse-error")

        for bad_span_item in (
            '{"file_name":"","line_start":1}',
            '{"file_name":"src/lib.rs","line_start":0}',
            '{"file_name":"src/lib.rs","line_start":true}',
            '{"file_name":123,"line_start":1}',
        ):
            payload = f'{{"reason":"compiler-message","message":{{"message":"oops","spans":[{bad_span_item}]}}}}'
            res_bad = PARSERS["cargo-json"](
                ParseInput(stdout=payload, returncode=1, root=self.root, tool="clippy")
            )
            self.assertEqual(len(res_bad), 1)
            self.assertEqual(res_bad[0]["rule"], "parse-error")

    def test_parse_ruff(self) -> None:
        out = self._run_fixture("ruff", "ruff")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/app.py",
                    "line": 3,
                    "rule": "F401",
                    "message": "`os` imported but unused",
                    "tool": "ruff",
                    "severity": "error",
                },
                {
                    "file": "src/utils.py",
                    "line": 14,
                    "rule": "E501",
                    "message": "Line too long (120 > 88)",
                    "tool": "ruff",
                    "severity": "warning",
                },
                {
                    "file": "src/defs.py",
                    "line": 7,
                    "rule": "B006",
                    "message": "Do not use mutable data structures for argument defaults",
                    "tool": "ruff",
                    "severity": "error",
                },
                {
                    "file": "src/broken.py",
                    "line": 9,
                    "rule": "invalid-syntax",
                    "message": "Expected `:`, found newline",
                    "tool": "ruff",
                    "severity": "error",
                },
                {
                    "file": "src/legacy_syntax.py",
                    "line": 2,
                    "rule": "syntax-error",
                    "message": "SyntaxError: Simple statements must be separated by newlines or semicolons",
                    "tool": "ruff",
                    "severity": "error",
                },
            ],
        )

    def test_parse_ruff_format(self) -> None:
        out = self._run_fixture("ruff-format", "ruff-format")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/app.py",
                    "line": 0,
                    "rule": "format",
                    "message": "Would reformat",
                    "tool": "ruff-format",
                    "severity": "warning",
                },
                {
                    "file": "tests/test_app.py",
                    "line": 0,
                    "rule": "format",
                    "message": "Would reformat",
                    "tool": "ruff-format",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_ruff_format_real_0174_golden_output(self) -> None:
        # Captured from Ruff 0.17.4 format --check --no-cache on a
        # Python golden supplementary tree (exit 1), not a synthetic diff.
        text = (FIXTURES_DIR / "ruff-format-full.txt").read_text()
        expected = [
            ("packages/domain/t5-python-supplement-accounts/tests/test_accounts.py", 124),
            ("packages/foundation/t5-python-supplement-core/tests/test_core.py", 113),
            ("tools/xtask/src/xtask/ci.py", 104),
            ("tools/xtask/src/xtask/generators.py", 58),
            ("tools/xtask/src/xtask/renamer.py", 92),
            ("tools/xtask/src/xtask/workspace.py", 54),
        ]
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                inp = ParseInput(**{stream: text, **({"stdout": ""} if stream == "stderr" else {})}, returncode=1, tool="ruff-format")
                self.assertEqual(PARSERS["ruff-format"](inp), [
                    {"file": path, "line": line, "rule": "format",
                     "message": "Would reformat", "tool": "ruff-format", "severity": "warning"}
                    for path, line in expected
                ])

    def test_parse_rustfmt(self) -> None:
        out = self._run_fixture("rustfmt", "rustfmt")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/main.rs",
                    "line": 12,
                    "rule": "rustfmt",
                    "message": "File is not formatted with rustfmt",
                    "tool": "rustfmt",
                    "severity": "warning",
                },
                {
                    "file": "src/lib.rs",
                    "line": 45,
                    "rule": "rustfmt",
                    "message": "File is not formatted with rustfmt",
                    "tool": "rustfmt",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_cargo_json(self) -> None:
        out = self._run_fixture("cargo-json", "clippy")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/lib.rs",
                    "line": 8,
                    "rule": "clippy::needless_return",
                    "message": "unneeded `return` statement",
                    "tool": "clippy",
                    "severity": "warning",
                },
                {
                    "file": "",
                    "line": 0,
                    "rule": "E0463",
                    "message": "can't find crate for `std`",
                    "tool": "clippy",
                    "severity": "error",
                },
                {
                    "file": "",
                    "line": 0,
                    "rule": "clippy",
                    "message": "1 warning emitted",
                    "tool": "clippy",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_biome_json(self) -> None:
        out = self._run_fixture("biome-json", "biome")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/index.ts",
                    "line": 8,
                    "rule": "lint/suspicious/noDoubleEquals",
                    "message": "Use === instead of ==.",
                    "tool": "biome",
                    "severity": "error",
                },
                {
                    "file": "src/util.ts",
                    "line": 2,
                    "rule": "format",
                    "message": "Formatter would have printed the following content.",
                    "tool": "biome",
                    "severity": "warning",
                },
            ],
        )

    def test_biome_json_terminal_sgr_envelope(self) -> None:
        # Real installed Biome emits ESC[0m before its JSON report.
        raw = (FIXTURES_DIR / "biome-json.txt").read_text()
        parser = PARSERS["biome-json"]
        expected = parser(ParseInput(stdout=raw, stderr="", returncode=1, root=Path("/repo"), tool="biome"))
        for prefix, suffix in [("\x1b[0m", ""), (" \x1b[1;31m\x1b[0m\n", "\n\x1b[0m ")]:
            for stream in ("stdout", "stderr"):
                with self.subTest(prefix=prefix, stream=stream):
                    streams = {"stdout": "", "stderr": ""}
                    streams[stream] = prefix + raw + suffix
                    self.assertEqual(parser(ParseInput(**streams, returncode=1, root=Path("/repo"), tool="biome")), expected)

    def test_biome_json_sgr_does_not_hide_invalid_output(self) -> None:
        for raw in ["\x1b[0m", '\x1b[0m{"diagnostics":',
                    '\x1b[0m{"diagnostics": []} garbage',
                    'warning\n\x1b[0m{"diagnostics": []}',
                    '\x1b[0m{"diagnostics": []} {}',
                    '\x1b[2J{"diagnostics": []}',
                    '{"diagnostics"\x1b[0m: []}',
                    '\x1b[0m{"diagnostics": [null]}']:
            for rc in (0, 1):
                with self.subTest(raw=raw, rc=rc):
                    result = PARSERS["biome-json"](ParseInput(stdout=raw, stderr="", returncode=rc, root=Path("/repo"), tool="biome"))
                    self.assertEqual(result[0]["rule"], "parse-error")

    def test_parse_oxlint_json(self) -> None:
        out = self._run_fixture("oxlint-json", "oxlint")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/app.tsx",
                    "line": 21,
                    "rule": "eslint(no-debugger)",
                    "message": "Unexpected `debugger` statement",
                    "tool": "oxlint",
                    "severity": "error",
                },
                {
                    "file": "src/helper.ts",
                    "line": 7,
                    "rule": "eslint(no-unused-vars)",
                    "message": "Variable `unused` is declared but never used",
                    "tool": "oxlint",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_gofmt(self) -> None:
        out = self._run_fixture("gofmt", "gofmt")
        self.assertEqual(
            out,
            [
                {
                    "file": "cmd/server/main.go",
                    "line": 0,
                    "rule": "gofmt",
                    "message": "File is not gofmt-formatted",
                    "tool": "gofmt",
                    "severity": "warning",
                },
                {
                    "file": "pkg/util/util.go",
                    "line": 0,
                    "rule": "gofmt",
                    "message": "File is not gofmt-formatted",
                    "tool": "gofmt",
                    "severity": "warning",
                },
                {
                    "file": "pkg/broken/bad.go",
                    "line": 19,
                    "rule": "syntax",
                    "message": "expected '}', found 'EOF'",
                    "tool": "gofmt",
                    "severity": "error",
                },
            ],
        )

    def test_parse_go_vet(self) -> None:
        out = self._run_fixture("go-vet", "go-vet")
        self.assertEqual(
            out,
            [
                {
                    "file": "pkg/api/handler.go",
                    "line": 34,
                    "rule": "vet",
                    "message": "Printf format %d has arg name of wrong type string",
                    "tool": "go-vet",
                    "severity": "error",
                },
                {
                    "file": "main.go",
                    "line": 10,
                    "rule": "vet",
                    "message": "unreachable code",
                    "tool": "go-vet",
                    "severity": "error",
                },
            ],
        )

    def test_parse_golangci_json(self) -> None:
        out = self._run_fixture("golangci-json", "golangci-lint")
        self.assertEqual(
            out,
            [
                {
                    "file": "pkg/client/http.go",
                    "line": 42,
                    "rule": "errcheck",
                    "message": "Error return value of `resp.Body.Close` is not checked",
                    "tool": "golangci-lint",
                    "severity": "error",
                },
                {
                    "file": "cmd/worker.go",
                    "line": 15,
                    "rule": "gosimple",
                    "message": "S1000: should use a simple channel send/receive instead of select with a single case",
                    "tool": "golangci-lint",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_clang_format(self) -> None:
        out = self._run_fixture("clang-format", "clang-format")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/engine.cpp",
                    "line": 27,
                    "rule": "clang-format",
                    "message": "code should be clang-formatted",
                    "tool": "clang-format",
                    "severity": "warning",
                },
                {
                    "file": "include/engine.h",
                    "line": 8,
                    "rule": "clang-format",
                    "message": "code should be clang-formatted",
                    "tool": "clang-format",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_clang_tidy(self) -> None:
        out = self._run_fixture("clang-tidy", "clang-tidy")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/engine.cpp",
                    "line": 42,
                    "rule": "modernize-use-nullptr",
                    "message": "use nullptr",
                    "tool": "clang-tidy",
                    "severity": "warning",
                },
                {
                    "file": "src/render.cpp",
                    "line": 108,
                    "rule": "clang-analyzer-core.DivideZero",
                    "message": "division by zero is undefined",
                    "tool": "clang-tidy",
                    "severity": "error",
                },
            ],
        )

    def test_parse_csharpier(self) -> None:
        out = self._run_fixture("csharpier", "csharpier")
        self.assertEqual(
            out,
            [
                {
                    "file": "Assets/Scripts/Player.cs",
                    "line": 0,
                    "rule": "csharpier",
                    "message": "Was not formatted.",
                    "tool": "csharpier",
                    "severity": "warning",
                },
                {
                    "file": "Assets/Scripts/Broken.cs",
                    "line": 0,
                    "rule": "csharpier",
                    "message": "Failed to compile so was not formatted.",
                    "tool": "csharpier",
                    "severity": "error",
                },
            ],
        )

    def test_parse_dotnet_format(self) -> None:
        out = self._run_fixture("dotnet-format", "dotnet-format")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/Game/Player.cs",
                    "line": 18,
                    "rule": "IDE0055",
                    "message": "Fix formatting",
                    "tool": "dotnet-format",
                    "severity": "warning",
                },
                {
                    "file": "src/Game/Combat.cs",
                    "line": 64,
                    "rule": "CA2000",
                    "message": "Call System.IDisposable.Dispose on object",
                    "tool": "dotnet-format",
                    "severity": "error",
                },
            ],
        )

    def test_parse_gdformat(self) -> None:
        out = self._run_fixture("gdformat", "gdformat")
        self.assertEqual(
            out,
            [
                {
                    "file": "scripts/player.gd",
                    "line": 0,
                    "rule": "gdformat",
                    "message": "would reformat",
                    "tool": "gdformat",
                    "severity": "warning",
                },
                {
                    "file": "scripts/enemy.gd",
                    "line": 0,
                    "rule": "gdformat",
                    "message": "would reformat",
                    "tool": "gdformat",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_gdlint(self) -> None:
        out = self._run_fixture("gdlint", "gdlint")
        self.assertEqual(
            out,
            [
                {
                    "file": "scripts/player.gd",
                    "line": 15,
                    "rule": "function-name",
                    "message": 'Function name "Move_Player" is not valid',
                    "tool": "gdlint",
                    "severity": "error",
                },
                {
                    "file": "scripts/enemy.gd",
                    "line": 44,
                    "rule": "max-line-length",
                    "message": "Max line length exceeded",
                    "tool": "gdlint",
                    "severity": "error",
                },
            ],
        )

    def test_parse_stylua(self) -> None:
        out = self._run_fixture("stylua", "stylua")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/init.lua",
                    "line": 0,
                    "rule": "stylua",
                    "message": "Diff in file",
                    "tool": "stylua",
                    "severity": "warning",
                },
                {
                    "file": "scripts/combat.luau",
                    "line": 0,
                    "rule": "stylua",
                    "message": "Diff in file",
                    "tool": "stylua",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_selene_json(self) -> None:
        out = self._run_fixture("selene-json", "selene")
        self.assertEqual(
            out,
            [
                {
                    "file": "src/init.lua",
                    "line": 5,
                    "rule": "unused_variable",
                    "message": "x is assigned a value, but never used",
                    "tool": "selene",
                    "severity": "warning",
                },
                {
                    "file": "src/broken.lua",
                    "line": 10,
                    "rule": "parse_error",
                    "message": "unexpected token `)`",
                    "tool": "selene",
                    "severity": "error",
                },
            ],
        )

    def test_parse_glslang(self) -> None:
        out = self._run_fixture("glslang", "glslangValidator")
        self.assertEqual(
            out,
            [
                {
                    "file": "shaders/water.frag",
                    "line": 23,
                    "rule": "shader",
                    "message": "'uv_coord' : undeclared identifier",
                    "tool": "glslangValidator",
                    "severity": "error",
                },
                {
                    "file": "shaders/water.frag",
                    "line": 24,
                    "rule": "shader",
                    "message": "'' : compilation terminated",
                    "tool": "glslangValidator",
                    "severity": "error",
                },
            ],
        )

    def test_parse_dxc(self) -> None:
        out = self._run_fixture("dxc", "dxc")
        self.assertEqual(
            out,
            [
                {
                    "file": "shaders/lit.hlsl",
                    "line": 31,
                    "rule": "shader",
                    "message": "undeclared identifier 'albedoTex'",
                    "tool": "dxc",
                    "severity": "error",
                },
                {
                    "file": "shaders/lit.hlsl",
                    "line": 12,
                    "rule": "shader",
                    "message": "implicit truncation of vector type [-Wconversion]",
                    "tool": "dxc",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_shfmt(self) -> None:
        out = self._run_fixture("shfmt", "shfmt")
        self.assertEqual(
            out,
            [
                {
                    "file": "scripts/deploy.sh",
                    "line": 0,
                    "rule": "shfmt",
                    "message": "File differs from shfmt formatting",
                    "tool": "shfmt",
                    "severity": "warning",
                },
                {
                    "file": "scripts/broken.sh",
                    "line": 9,
                    "rule": "shfmt",
                    "message": "`then` must be followed by a statement list",
                    "tool": "shfmt",
                    "severity": "error",
                },
            ],
        )

    def test_parse_shellcheck_json(self) -> None:
        out = self._run_fixture("shellcheck-json", "shellcheck")
        self.assertEqual(
            out,
            [
                {
                    "file": "scripts/deploy.sh",
                    "line": 12,
                    "rule": "SC2086",
                    "message": "Double quote to prevent globbing and word splitting.",
                    "tool": "shellcheck",
                    "severity": "warning",
                },
                {
                    "file": "scripts/deploy.sh",
                    "line": 20,
                    "rule": "SC2006",
                    "message": "Use $(...) notation instead of legacy backticks `...`.",
                    "tool": "shellcheck",
                    "severity": "info",
                },
            ],
        )

    def test_parse_pwsh_parse_json(self) -> None:
        out = self._run_fixture("pwsh-parse-json", "pwsh-parse")
        self.assertEqual(
            out,
            [
                {
                    "file": "scripts/setup.ps1",
                    "line": 14,
                    "rule": "MissingEndCurlyBrace",
                    "message": "Missing closing '}' in statement block or type definition.",
                    "tool": "pwsh-parse",
                    "severity": "error",
                }
            ],
        )

    def test_parse_psscriptanalyzer_json(self) -> None:
        out = self._run_fixture("psscriptanalyzer-json", "psscriptanalyzer")
        self.assertEqual(
            out,
            [
                {
                    "file": "scripts/build.ps1",
                    "line": 8,
                    "rule": "PSAvoidUsingCmdletAliases",
                    "message": "'% ' is an alias of 'ForEach-Object'. Alias can introduce possible problems.",
                    "tool": "psscriptanalyzer",
                    "severity": "warning",
                },
                {
                    "file": "scripts/clean.ps1",
                    "line": 22,
                    "rule": "PSUseDeclaredVarsMoreThanAssignments",
                    "message": "The variable 'unusedVar' is assigned but never used.",
                    "tool": "psscriptanalyzer",
                    "severity": "error",
                },
            ],
        )

    def test_parse_yamllint_parsable(self) -> None:
        out = self._run_fixture("yamllint-parsable", "yamllint")
        self.assertEqual(
            out,
            [
                {
                    "file": ".github/workflows/ci.yml",
                    "line": 11,
                    "rule": "indentation",
                    "message": "wrong indentation: expected 4 but found 2",
                    "tool": "yamllint",
                    "severity": "error",
                },
                {
                    "file": "config.yaml",
                    "line": 4,
                    "rule": "document-start",
                    "message": 'missing document start "---"',
                    "tool": "yamllint",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_taplo(self) -> None:
        out = self._run_fixture("taplo", "taplo")
        self.assertEqual(
            out,
            [
                {
                    "file": "Cargo.toml",
                    "line": 0,
                    "rule": "taplo",
                    "message": "TOML file is not properly formatted",
                    "tool": "taplo",
                    "severity": "warning",
                },
                {
                    "file": "pyproject.toml",
                    "line": 9,
                    "rule": "taplo",
                    "message": "unexpected key",
                    "tool": "taplo",
                    "severity": "error",
                },
            ],
        )

    def test_parse_rumdl_json(self) -> None:
        out = self._run_fixture("rumdl-json", "rumdl")
        self.assertEqual(
            out,
            [
                {
                    "file": "README.md",
                    "line": 12,
                    "rule": "MD013",
                    "message": "Line length is 140, expected at most 120",
                    "tool": "rumdl",
                    "severity": "warning",
                },
                {
                    "file": "docs/guide.md",
                    "line": 3,
                    "rule": "MD041",
                    "message": "First line in a file should be a top-level heading",
                    "tool": "rumdl",
                    "severity": "warning",
                },
            ],
        )

    def test_parse_hadolint_json(self) -> None:
        out = self._run_fixture("hadolint-json", "hadolint")
        self.assertEqual(
            out,
            [
                {
                    "file": "Dockerfile",
                    "line": 5,
                    "rule": "DL3008",
                    "message": "Pin versions in apt get install.",
                    "tool": "hadolint",
                    "severity": "warning",
                },
                {
                    "file": "docker/Dockerfile.prod",
                    "line": 12,
                    "rule": "DL3059",
                    "message": "Multiple consecutive `RUN` instructions.",
                    "tool": "hadolint",
                    "severity": "info",
                },
            ],
        )


class TestDetectAndRunLint(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.db_path = self.tmp_root / "state.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_detect_for_project_uses_state_store_and_warns_on_truncation_or_db_error(self) -> None:
        proj = self.tmp_root / "my_proj"
        proj.mkdir()
        state_store.record_project(
            path=proj,
            name="my_proj",
            slug="my-proj",
            template_id=None,
            answers={"languages": ["python"]},
            hermes_project_id=None,
            db_path=self.db_path,
        )
        specs, warnings = detect_for_project(proj, db_path=self.db_path)
        names = [s.name for s in specs]
        self.assertIn("ruff", names)
        self.assertIn("ruff-format", names)
        self.assertEqual(warnings, [])

        with mock.patch.object(
            lint_tools,
            "scan",
            return_value=lint_tools.ScanResult(files=(), truncated=True),
        ):
            _, trunc_warnings = detect_for_project(proj, db_path=self.db_path)
            self.assertTrue(any("truncated" in w.lower() for w in trunc_warnings))

        with mock.patch.object(
            state_store,
            "get_project",
            side_effect=RuntimeError("db locked"),
        ):
            _, db_warnings = detect_for_project(proj, db_path=self.db_path)
            self.assertTrue(any("state_store" in w and "db locked" in w for w in db_warnings))

    def test_run_lint_scans_project_exactly_once(self) -> None:
        proj = self.tmp_root / "single_scan_proj"
        proj.mkdir()
        (proj / "deploy.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

        with (
            mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"),
            mock.patch.object(lint_tools, "scan", wraps=lint_tools.scan) as spy_scan,
        ):
            res = run_lint(
                proj,
                mode="pre",
                runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
                db_path=self.db_path,
            )

        self.assertTrue(res["ok"])
        self.assertEqual(spy_scan.call_count, 1)

    def test_input_globs_selection_and_skip_file_tool_with_zero_files(self) -> None:
        self.assertFalse(hasattr(linter, "_MANIFEST_ONLY_GLOBS"))
        proj = self.tmp_root / "manifest_proj"
        proj.mkdir()
        (proj / "Cargo.toml").write_text("[package]\nname = 'demo'\n", encoding="utf-8")
        (proj / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        docker_dir = proj / "docker"
        docker_dir.mkdir()
        (docker_dir / "Dockerfile.dev").write_text("FROM alpine:3.19\n", encoding="utf-8")

        scan_res = lint_tools.scan(proj)
        self.assertEqual(
            linter._matching_files_for_spec(lint_tools.by_name("rustfmt"), scan_res.files),
            [],
        )
        self.assertEqual(
            linter._matching_files_for_spec(lint_tools.by_name("hadolint"), scan_res.files),
            ["Dockerfile", "docker/Dockerfile.dev"],
        )
        self.assertEqual(
            linter._matching_files_for_spec(lint_tools.by_name("taplo"), scan_res.files),
            ["Cargo.toml"],
        )
        self.assertEqual(
            linter._matching_files_for_spec(lint_tools.by_name("clippy"), scan_res.files),
            [],
        )

        with mock.patch.object(lint_env, "which", side_effect=lambda b, env, **kw: f"/usr/bin/{b}"):
            res = run_lint(
                proj,
                mode="pre",
                runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
                db_path=self.db_path,
            )

        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "clean")
        self.assertEqual(res["tool_errors"], [])
        self.assertEqual(res["warnings"], [])
        tools_by_name = {entry["tool"]: entry for entry in res["tools_run"]}
        self.assertNotIn("rustfmt", tools_by_name)
        self.assertIn("taplo", tools_by_name)
        self.assertEqual(tools_by_name["taplo"]["argv"][-1:], ["Cargo.toml"])
        self.assertEqual(tools_by_name["taplo"]["status"], "clean")
        self.assertIn("hadolint", tools_by_name)
        self.assertEqual(
            tools_by_name["hadolint"]["argv"][-2:],
            ["Dockerfile", "docker/Dockerfile.dev"],
        )
        statuses_by_tool = {entry["tool"]: entry["status"] for entry in res["tool_statuses"]}
        self.assertEqual(statuses_by_tool["rustfmt"], "no_files")
        self.assertEqual(statuses_by_tool["taplo"], "clean")
        self.assertEqual(statuses_by_tool["hadolint"], "clean")

    def test_run_lint_shell_project_populates_findings_tools_run_and_missing(self) -> None:
        proj = self.tmp_root / "sh_proj"
        proj.mkdir()
        (proj / "deploy.sh").write_text("#!/bin/sh\necho $FOO\n", encoding="utf-8")

        sc_json = (FIXTURES_DIR / "shellcheck-json.txt").read_text(encoding="utf-8")
        shfmt_out = (FIXTURES_DIR / "shfmt.txt").read_text(encoding="utf-8")

        def fake_which(name: str, env, *, is_windows=None):
            if name == "shellcheck":
                return "/opt/bin/shellcheck"
            if name == "shfmt":
                return "/opt/bin/shfmt"
            return None

        def fake_runner(argv, *, cwd, env, timeout_s):
            if argv[0] == "/opt/bin/shfmt":
                return subprocess.CompletedProcess(argv, 1, stdout=shfmt_out, stderr="")
            if argv[0] == "/opt/bin/shellcheck":
                return subprocess.CompletedProcess(argv, 1, stdout=sc_json, stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch.object(lint_env, "which", side_effect=fake_which):
            res = run_lint(proj, mode="both", runner=fake_runner, db_path=self.db_path)

        self.assertTrue(res["ok"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["mode"], "both")
        self.assertEqual(res["tools_missing"], [])
        self.assertEqual(len(res["tools_run"]), 2)
        self.assertEqual(res["tools_run"][0]["tool"], "shfmt")
        self.assertEqual(res["tools_run"][0]["mode"], "pre")
        self.assertEqual(res["tools_run"][0]["argv"][0], "/opt/bin/shfmt")
        self.assertEqual(res["tools_run"][1]["tool"], "shellcheck")
        self.assertEqual(res["tools_run"][1]["mode"], "post")
        self.assertEqual(res["tools_run"][1]["argv"][0], "/opt/bin/shellcheck")

        # Findings are sorted by (file, line, tool) and have relative posix paths
        files_lines = [(f["file"], f["line"], f["tool"]) for f in res["findings"]]
        self.assertEqual(files_lines, sorted(files_lines))
        for f in res["findings"]:
            self.assertFalse(f["file"].startswith("./"))

    def test_run_lint_missing_tools_recorded_once_and_mode_filtering(self) -> None:
        proj = self.tmp_root / "py_sh_proj"
        proj.mkdir()
        (proj / "app.py").write_text("import os\n", encoding="utf-8")
        (proj / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")

        def fake_which(name: str, env, *, is_windows=None):
            if name == "shfmt":
                return "/usr/bin/shfmt"
            return None  # ruff and shellcheck missing

        calls = []

        def fake_runner(argv, *, cwd, env, timeout_s):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch.object(lint_env, "which", side_effect=fake_which):
            res_pre = run_lint(proj, mode="pre", runner=fake_runner, db_path=self.db_path)

        # Unknown is not a verdict: missing tools must set ok=False, status='incomplete', and tool_errors (no synthetic findings)
        self.assertFalse(res_pre["ok"])
        self.assertEqual(res_pre["status"], "incomplete")
        self.assertTrue(res_pre["error"])
        # In mode='pre', ruff and ruff-format are checked and missing (once per tool), shfmt runs, shellcheck is post-only
        self.assertIn("ruff", res_pre["tools_missing"])
        self.assertIn("ruff-format", res_pre["tools_missing"])
        self.assertNotIn("shellcheck", res_pre["tools_missing"])
        self.assertEqual(len(res_pre["tools_missing"]), len(set(res_pre["tools_missing"])))
        self.assertEqual(len(res_pre["tools_run"]), 1)
        self.assertEqual(res_pre["tools_run"][0]["tool"], "shfmt")
        self.assertEqual(res_pre["tools_run"][0]["status"], "clean")
        err_tools = {e["tool"]: e["status"] for e in res_pre["tool_errors"]}
        self.assertEqual(err_tools, {"ruff": "not_installed", "ruff-format": "not_installed"})
        self.assertEqual(res_pre["findings"], [])
        st_by_tool = {e["tool"]: e for e in res_pre["tool_statuses"]}
        self.assertEqual(st_by_tool["ruff"]["findings"], 0)
        self.assertEqual(st_by_tool["ruff-format"]["findings"], 0)

    def test_run_lint_refuses_live_hermes_and_nonexistent_root(self) -> None:
        live_path = Path(os.path.expanduser("~/.hermes/plugins/defuzz"))
        res_live = run_lint(live_path, mode="pre", db_path=self.db_path)
        self.assertFalse(res_live["ok"])
        self.assertTrue(res_live["error"])
        self.assertIn(".hermes", res_live["error"])

        missing_root = self.tmp_root / "does_not_exist"
        res_missing = run_lint(missing_root, mode="pre", db_path=self.db_path)
        self.assertFalse(res_missing["ok"])
        self.assertTrue(res_missing["error"])

    def test_run_lint_timeout_and_executes_repo_code_warning_once(self) -> None:
        proj = self.tmp_root / "rust_cs_proj"
        proj.mkdir()
        (proj / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
        (proj / "App.csproj").write_text("<Project/>\n", encoding="utf-8")

        def fake_which(name: str, env, *, is_windows=None):
            return f"/usr/bin/{name}"

        def fake_runner(argv, *, cwd, env, timeout_s):
            if argv[0].endswith("/cargo"):
                return subprocess.CompletedProcess(
                    argv, lint_env.TIMEOUT_RC, stdout="", stderr=f"timeout after {timeout_s}s"
                )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch.object(lint_env, "which", side_effect=fake_which):
            res = run_lint(proj, mode="post", runner=fake_runner, db_path=self.db_path)

        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "incomplete")
        self.assertEqual(len(res["tool_errors"]), 1)
        self.assertEqual(res["tool_errors"][0]["tool"], "clippy")
        self.assertEqual(res["tool_errors"][0]["status"], "timed_out")
        # Timeout warning in warnings + tool_errors, but no synthetic finding in findings
        self.assertTrue(any("clippy timed out after" in w for w in res["warnings"]))
        self.assertEqual(res["findings"], [])

        # Both clippy and dotnet-format have executes_repo_code=True, but warning appears only once
        repo_code_warnings = [
            w
            for w in res["warnings"]
            if w == "POST tools that execute repo code (clippy, dotnet) ran on the host without a sandbox"
        ]
        self.assertEqual(len(repo_code_warnings), 1)

    def test_run_lint_dedupes_and_truncates_max_findings(self) -> None:
        proj = self.tmp_root / "dup_proj"
        proj.mkdir()
        (proj / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")

        dup_sc = """[
          {"file": "run.sh", "line": 2, "level": "warning", "code": 2086, "message": "Quote this"},
          {"file": "run.sh", "line": 2, "level": "warning", "code": 2086, "message": "Quote this"},
          {"file": "run.sh", "line": 3, "level": "warning", "code": 2086, "message": "Quote this 3"},
          {"file": "run.sh", "line": 4, "level": "warning", "code": 2086, "message": "Quote this 4"}
        ]"""

        with mock.patch.object(lint_env, "which", return_value="/usr/bin/shellcheck"):
            res = run_lint(
                proj,
                mode="post",
                runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout=dup_sc, stderr=""),
                db_path=self.db_path,
                max_findings=2,
            )

        self.assertEqual(len(res["findings"]), 2)
        self.assertTrue(any("truncated" in w.lower() for w in res["warnings"]))

    def test_run_lint_caps_files_at_2000_and_invalid_mode(self) -> None:
        proj = self.tmp_root / "cap_proj"
        proj.mkdir()
        (proj / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")

        many_files = tuple(f"scripts/s_{i}.sh" for i in range(2005))
        fake_scan = lint_tools.ScanResult(files=many_files, truncated=False)

        captured_argv: list[list[str]] = []

        def fake_runner(argv, *, cwd, env, timeout_s):
            captured_argv.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with (
            mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"),
            mock.patch.object(lint_tools, "scan", return_value=fake_scan),
        ):
            res = run_lint(proj, mode="pre", runner=fake_runner, db_path=self.db_path)

        self.assertTrue(res["ok"])
        self.assertTrue(any("2000" in w for w in res["warnings"]))
        # shfmt -d <2000 files> -> 2 + 2000 = 2002 args
        self.assertEqual(len(captured_argv[0]), 2002)

        bad_mode = run_lint(proj, mode="invalid_mode", db_path=self.db_path)
        self.assertFalse(bad_mode["ok"])
        self.assertTrue(bad_mode["error"])

    def test_run_lint_returns_structured_error_when_env_build_fails(self) -> None:
        proj = self.tmp_root / "env_fail_proj"
        proj.mkdir()
        with mock.patch.object(lint_env, "build_env", side_effect=OSError("boom")):
            res = run_lint(proj, mode="pre", db_path=self.db_path)
        self.assertEqual(
            res,
            {
                "ok": False,
                "status": "error",
                "project": str(proj.resolve()),
                "mode": "pre",
                "findings": [],
                "tools_run": [],
                "tools_missing": [],
                "tool_statuses": [],
                "tool_errors": [],
                "warnings": [],
                "error": "environment build failed: boom",
            },
        )

    def test_unknown_is_not_a_verdict_spawn_crash_parser_crash_unparseable_and_not_configured(self) -> None:
        # 1. Subprocess spawn exception -> status 'crashed', ok=False, no synthetic findings
        proj = self.tmp_root / "crash_proj"
        proj.mkdir()
        (proj / "deploy.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

        def crash_runner(argv, *, cwd, env, timeout_s):
            raise OSError("exec format error")

        with mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"):
            res_crash = run_lint(proj, mode="pre", runner=crash_runner, db_path=self.db_path)

        self.assertFalse(res_crash["ok"])
        self.assertEqual(res_crash["status"], "incomplete")
        self.assertEqual(len(res_crash["tool_errors"]), 1)
        self.assertEqual(res_crash["tool_errors"][0]["tool"], "shfmt")
        self.assertEqual(res_crash["tool_errors"][0]["status"], "crashed")
        self.assertEqual(res_crash["findings"], [])
        self.assertEqual(res_crash["tools_run"][0]["findings"], 0)
        self.assertEqual(res_crash["tool_statuses"][0]["findings"], 0)

        # 2. Parser exception -> status 'crashed', ok=False, no synthetic findings
        def ok_runner(argv, *, cwd, env, timeout_s):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with (
            mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"),
            mock.patch.dict(PARSERS, {"shfmt": mock.Mock(side_effect=ValueError("parser exploded"))}),
        ):
            res_pcrash = run_lint(proj, mode="pre", runner=ok_runner, db_path=self.db_path)

        self.assertFalse(res_pcrash["ok"])
        self.assertEqual(res_pcrash["status"], "incomplete")
        self.assertEqual(res_pcrash["tool_errors"][0]["status"], "crashed")
        self.assertEqual(res_pcrash["findings"], [])

        # 3. Non-zero exit with empty output -> status 'crashed', ok=False, no synthetic findings
        def empty_fail_runner(argv, *, cwd, env, timeout_s):
            return subprocess.CompletedProcess(argv, 139, stdout="", stderr="")

        with mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"):
            res_sig = run_lint(proj, mode="pre", runner=empty_fail_runner, db_path=self.db_path)

        self.assertFalse(res_sig["ok"])
        self.assertEqual(res_sig["status"], "incomplete")
        self.assertEqual(res_sig["tool_errors"][0]["status"], "crashed")
        self.assertEqual(res_sig["findings"], [])

        # 4. Non-zero exit with unparseable output -> status 'unparseable', ok=False, no synthetic findings
        def unparseable_runner(argv, *, cwd, env, timeout_s):
            return subprocess.CompletedProcess(argv, 2, stdout="weird unknown flag --foo", stderr="")

        with mock.patch.object(lint_env, "which", return_value="/usr/bin/shfmt"):
            res_unp = run_lint(proj, mode="pre", runner=unparseable_runner, db_path=self.db_path)

        self.assertFalse(res_unp["ok"])
        self.assertEqual(res_unp["status"], "incomplete")
        self.assertEqual(res_unp["tool_errors"][0]["status"], "unparseable")
        self.assertEqual(res_unp["findings"], [])

        # 5. C++ project with .cpp sources but without compile_commands.json -> clang-tidy is 'not_configured', ok=False, status='incomplete'
        cpp_proj = self.tmp_root / "cpp_proj"
        cpp_proj.mkdir()
        (cpp_proj / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        (cpp_proj / "header.h").write_text("#pragma once\n", encoding="utf-8")

        with mock.patch.object(lint_env, "which", side_effect=lambda b, env, **kw: f"/usr/bin/{b}"):
            res_cpp = run_lint(cpp_proj, mode="both", runner=ok_runner, db_path=self.db_path)

        self.assertFalse(res_cpp["ok"])
        self.assertEqual(res_cpp["status"], "incomplete")
        self.assertEqual(len(res_cpp["tool_errors"]), 1)
        self.assertEqual(res_cpp["tool_errors"][0]["tool"], "clang-tidy")
        self.assertEqual(res_cpp["tool_errors"][0]["status"], "not_configured")
        self.assertIn("compile_commands.json", res_cpp["tool_errors"][0]["message"])
        self.assertIn("build/", res_cpp["tool_errors"][0]["message"])
        self.assertIn("out/", res_cpp["tool_errors"][0]["message"])
        self.assertIn("CMAKE_EXPORT_COMPILE_COMMANDS", res_cpp["tool_errors"][0]["message"])
        st_map = {e["tool"]: e["status"] for e in res_cpp["tool_statuses"]}
        self.assertEqual(st_map["clang-format"], "clean")
        self.assertEqual(st_map["clang-tidy"], "not_configured")

        # 6. C++ header-only project without .c/.cc/.cpp/.cxx files -> clang-tidy has no matching inputs -> status 'no_files', ok=True
        hdr_proj = self.tmp_root / "hdr_only_proj"
        hdr_proj.mkdir()
        (hdr_proj / "header.h").write_text("#pragma once\n", encoding="utf-8")
        with mock.patch.object(lint_env, "which", side_effect=lambda b, env, **kw: f"/usr/bin/{b}"):
            res_hdr = run_lint(hdr_proj, mode="both", runner=ok_runner, db_path=self.db_path)
        self.assertTrue(res_hdr["ok"])
        self.assertEqual(res_hdr["status"], "clean")
        self.assertEqual(res_hdr["tool_errors"], [])
        hdr_st_map = {e["tool"]: e["status"] for e in res_hdr["tool_statuses"]}
        self.assertEqual(hdr_st_map["clang-format"], "clean")
        self.assertEqual(hdr_st_map["clang-tidy"], "no_files")

    def test_structured_parse_validity_independent_of_rc_and_crash_signals_and_biome_pre(self) -> None:
        from dataclasses import replace

        base_spec = lint_tools.by_name("ruff")

        def run_one(parser_name: str, rc: int = 0, out: str = "") -> dict:
            spec = replace(base_spec, parser=parser_name, modes=("pre",), input_globs=())
            with (
                mock.patch.object(linter, "detect_for_project", return_value=([spec], [])),
                mock.patch.object(lint_env, "which", return_value="/fake/tool"),
            ):
                return run_lint(
                    self.tmp_root,
                    "pre",
                    env={},
                    runner=lambda *a, **kw: subprocess.CompletedProcess(a[0], rc, out, ""),
                )

        # rc 0 with unparseable output -> unparseable, ok False, tool_errors
        for parser_name in ("ruff", "biome-json", "cargo-json", "selene-json", "oxlint-json", "golangci-json", "shellcheck-json", "pwsh-parse-json", "psscriptanalyzer-json", "rumdl-json", "hadolint-json"):
            with self.subTest(parser=parser_name, case="rc0_not_json"):
                r = run_one(parser_name, rc=0, out="not json")
                self.assertFalse(r["ok"])
                self.assertEqual(r["status"], "incomplete")
                self.assertEqual(r["findings"], [])
                self.assertEqual(len(r["tool_errors"]), 1)
                self.assertEqual(r["tool_errors"][0]["status"], "unparseable")

        # Malformed diagnostic schemas -> unparseable, not blank findings
        malformed_cases = [
            ("ruff", 2, "[{}]"),
            ("ruff", 0, '[{"filename": "a.py"}]'),
            ("pwsh-parse-json", 2, "{}"),
            ("psscriptanalyzer-json", 1, "{}"),
            ("biome-json", 1, '{"diagnostics": [{}]}'),
            ("oxlint-json", 1, '{"diagnostics": [{}]}'),
            ("golangci-json", 1, '{"Issues": [{}]}'),
            ("shellcheck-json", 1, "[{}]"),
            ("hadolint-json", 1, "[{}]"),
            ("rumdl-json", 1, "[{}]"),
            ("cargo-json", 1, '{"reason": "compiler-message", "message": {}}\n'),
            ("selene-json", 1, '{"type": "Diagnostic", "primary_label": {}}\n'),
        ]
        for parser_name, rc, payload in malformed_cases:
            with self.subTest(parser=parser_name, payload=payload):
                r = run_one(parser_name, rc=rc, out=payload)
                self.assertFalse(r["ok"], f"{parser_name} with {payload!r} should fail")
                self.assertEqual(r["status"], "incomplete")
                self.assertEqual(r["findings"], [])
                self.assertEqual(r["tool_errors"][0]["status"], "unparseable")

        # Valid empty diagnostics on rc=0 stay clean
        self.assertEqual(run_one("ruff", rc=0, out="[]")["status"], "clean")
        self.assertEqual(run_one("biome-json", rc=0, out='{"diagnostics": []}')["status"], "clean")
        self.assertEqual(
            run_one("cargo-json", rc=0, out='{"reason":"build-finished","success":true}\n')["status"],
            "clean",
        )
        self.assertEqual(
            run_one("selene-json", rc=0, out='{"type":"Summary","errors":0,"warnings":0}\n')["status"],
            "clean",
        )

        # Literal JSON null / wrong top-level JSON types at rc 0 -> unparseable
        for parser_name in JSON_PARSERS:
            for bad_top in ("null", "123", '"hello"', "true"):
                with self.subTest(parser=parser_name, bad_top=bad_top):
                    r_top = run_one(parser_name, rc=0, out=bad_top)
                    self.assertFalse(r_top["ok"], f"{parser_name} with {bad_top} at rc=0 should be unparseable")
                    self.assertEqual(r_top["status"], "incomplete")
                    self.assertEqual(r_top["findings"], [])
                    self.assertEqual(r_top["tool_errors"][0]["status"], "unparseable")

        # Array-only parsers reject top-level {} and object-only parsers reject top-level []
        for array_only in ("ruff", "hadolint-json"):
            r_obj = run_one(array_only, rc=0, out="{}")
            self.assertFalse(r_obj["ok"])
            self.assertEqual(r_obj["tool_errors"][0]["status"], "unparseable")
        for obj_only in ("biome-json", "golangci-json"):
            r_arr = run_one(obj_only, rc=0, out="[]")
            self.assertFalse(r_arr["ok"])
            self.assertEqual(r_arr["tool_errors"][0]["status"], "unparseable")

        # Crash exit classification:
        # POSIX: crashed only if rc < 0 (e.g. -11, -6); positive 130, 139 are NOT treated as crash signals
        # Windows: crashed only for NTSTATUS exception codes (0xC0000000 severity bits like 0xC0000005, 0xC00000FD, 0xC0000409),
        # NOT HRESULT failures like 0x80004005 (E_FAIL) returned by DXC on ordinary compile errors.
        for crash_rc in (-11, -6, 0xC0000005, 0xC00000FD, 0xC0000409):
            with self.subTest(crash_rc=crash_rc):
                r_sig = run_one(
                    "ruff",
                    rc=crash_rc,
                    out='[{"filename":"a.py","code":"F401","message":"unused","location":{"row":1}}]',
                )
                self.assertFalse(r_sig["ok"])
                self.assertEqual(r_sig["status"], "incomplete")
                self.assertEqual(len(r_sig["findings"]), 1)
                self.assertEqual(r_sig["findings"][0]["rule"], "F401")
                self.assertEqual(r_sig["tool_errors"][0]["status"], "crashed")
                self.assertEqual(r_sig["tool_statuses"][0]["status"], "crashed")
                self.assertEqual(r_sig["tool_statuses"][0]["findings"], 1)

        for non_crash_rc in (130, 139):
            with self.subTest(non_crash_rc=non_crash_rc):
                r_pos = run_one(
                    "ruff",
                    rc=non_crash_rc,
                    out='[{"filename":"a.py","code":"F401","message":"unused","location":{"row":1}}]',
                )
                self.assertTrue(r_pos["ok"])
                self.assertEqual(r_pos["status"], "findings")
                self.assertEqual(r_pos["tool_errors"], [])
                self.assertEqual(r_pos["tool_statuses"][0]["status"], "findings")
                self.assertEqual(len(r_pos["findings"]), 1)

        dxc_out = (FIXTURES_DIR / "dxc.txt").read_text(encoding="utf-8")
        r_dxc_hresult = run_one("dxc", rc=0x80004005, out=dxc_out)
        self.assertTrue(r_dxc_hresult["ok"])
        self.assertEqual(r_dxc_hresult["status"], "findings")
        self.assertEqual(r_dxc_hresult["tool_errors"], [])
        self.assertEqual(r_dxc_hresult["tool_statuses"][0]["status"], "findings")
        self.assertEqual(len(r_dxc_hresult["findings"]), 2)

        r_dxc_ntstatus = run_one("dxc", rc=0xC0000005, out=dxc_out)
        self.assertFalse(r_dxc_ntstatus["ok"])
        self.assertEqual(r_dxc_ntstatus["status"], "incomplete")
        self.assertEqual(r_dxc_ntstatus["tool_errors"][0]["status"], "crashed")
        self.assertEqual(r_dxc_ntstatus["tool_statuses"][0]["status"], "crashed")

        # Both Biome modes receive the same scanned/capped file targets.
        biome_proj = self.tmp_root / "biome_proj"
        biome_proj.mkdir()
        (biome_proj / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (biome_proj / "index.ts").write_text("const x = 1;\n", encoding="utf-8")
        seen_cmds: list[list[str]] = []

        def biome_runner(argv, *, cwd, env, timeout_s):
            seen_cmds.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout='{"diagnostics": []}', stderr="")

        with mock.patch.object(lint_env, "which", side_effect=lambda b, env, **kw: f"/usr/bin/{b}"):
            res_biome = run_lint(biome_proj, mode="both", runner=biome_runner, db_path=self.db_path)

        self.assertTrue(res_biome["ok"])
        biome_runs = [tr for tr in res_biome["tools_run"] if tr["tool"] == "biome"]
        self.assertEqual(len(biome_runs), 2)
        self.assertEqual(
            biome_runs[0]["argv"],
            [
                "/usr/bin/biome",
                "check",
                "--formatter-enabled=true",
                "--linter-enabled=false",
                "--assist-enabled=false",
                "--reporter",
                "json",
                "index.ts",
                "package.json",
            ],
        )
        self.assertEqual(
            biome_runs[1]["argv"],
            ["/usr/bin/biome", "ci", "--reporter", "json", "index.ts", "package.json"],
        )

    def test_run_lint_glslang_skips_stageless_and_uses_temp_spirv_output(self) -> None:
        proj = self.tmp_root / "glsl_proj"
        proj.mkdir()
        (proj / "pixel.hlsl").write_text("float4 main() : SV_Target { return 0; }\n", encoding="utf-8")
        (proj / "effect.gdshader").write_text("shader_type canvas_item;\n", encoding="utf-8")
        (proj / "unknown.glsl").write_text("void main() {}\n", encoding="utf-8")
        (proj / "water.vert").write_text("#version 450\nvoid main() {}\n", encoding="utf-8")

        seen_glslang_cmds: list[list[str]] = []

        def shader_runner(argv, *, cwd, env, timeout_s):
            if "glslangValidator" in argv[0]:
                seen_glslang_cmds.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch.object(lint_env, "which", side_effect=lambda b, env, **kw: f"/usr/bin/{b}"):
            res = run_lint(proj, mode="both", runner=shader_runner, db_path=self.db_path)

        self.assertTrue(res["ok"])
        self.assertEqual(len(seen_glslang_cmds), 2)
        for cmd in seen_glslang_cmds:
            self.assertIn("-V", cmd)
            self.assertIn("-o", cmd)
            o_idx = cmd.index("-o")
            spv_path = Path(cmd[o_idx + 1])
            self.assertNotEqual(str(spv_path), os.devnull)
            self.assertFalse(spv_path.exists(), "temporary SPIR-V output file must be cleaned up")
            self.assertIn("water.vert", cmd)
            self.assertNotIn("unknown.glsl", cmd)
            self.assertNotIn("pixel.hlsl", cmd)
            self.assertNotIn("effect.gdshader", cmd)
        self.assertNotIn("--spirv-val", seen_glslang_cmds[0])
        self.assertIn("--spirv-val", seen_glslang_cmds[1])

    def test_conventions_docstrings_and_no_logging(self) -> None:
        assert linter.__file__ is not None
        src = Path(linter.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import logging", src)
        for name, obj in vars(linter).items():
            if callable(obj) and getattr(obj, "__module__", None) == linter.__name__:
                doc = (obj.__doc__ or "").strip()
                self.assertTrue(doc, f"{name} must have a docstring")
                self.assertEqual(len(doc.splitlines()), 1, f"{name} docstring must be 1 line")


if __name__ == "__main__":
    unittest.main()


def test_windows_exit_minus_one_is_not_a_crash():
    from hermes_plugins.defuzz import linter as _l

    assert _l._is_crash_exit(0xFFFFFFFF) is False  # exit(-1) as Windows reports it
    assert _l._is_crash_exit(0xC0000005) is True
    assert _l._is_crash_exit(-1) is True  # POSIX: killed by signal 1
