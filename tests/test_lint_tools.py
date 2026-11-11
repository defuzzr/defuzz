"""Unit tests for lint_tools.py."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.lint_tools import (  # noqa: E402
    TOOLS,
    VALID_KINDS,
    VALID_LANGUAGES,
    VALID_MODES,
    WHEEL_PACKAGES,
    ScanResult,
    ToolSpec,
    _ps_quote,
    _targets,
    all_binaries,
    argv,
    by_name,
    detect,
    find_compile_commands_dir,
    scan,
    tool_satisfied,
)
from hermes_plugins.defuzz import lint_tools  # noqa: E402


class TestLintToolsTable(unittest.TestCase):
    def test_tools_non_empty_and_unique_names(self) -> None:
        self.assertGreaterEqual(len(TOOLS), 20)
        names = [spec.name for spec in TOOLS]
        self.assertEqual(len(names), len(set(names)))
        for spec in TOOLS:
            self.assertEqual(spec.tool, spec.name)

    def test_every_tool_has_valid_fields(self) -> None:
        for spec in TOOLS:
            with self.subTest(tool=spec.name):
                self.assertIsInstance(spec, ToolSpec)
                self.assertIn(spec.kind, VALID_KINDS)
                self.assertTrue(spec.modes, f"{spec.name} must have at least 1 mode")
                for m in spec.modes:
                    self.assertIn(m, VALID_MODES)
                self.assertTrue(spec.languages, f"{spec.name} must declare languages")
                for lang in spec.languages:
                    self.assertIn(lang, VALID_LANGUAGES)
                    self.assertEqual(lang, lang.lower())
                self.assertTrue(spec.detect_globs, f"{spec.name} must have detect_globs")
                self.assertTrue(spec.parser.strip(), f"{spec.name} parser must be non-empty")
                self.assertGreater(spec.timeout_s, 0)
                self.assertIsInstance(spec.executes_repo_code, bool)
                self.assertTrue(spec.binaries, f"{spec.name} must declare binaries")
                for b in spec.binaries:
                    self.assertTrue(b.strip())

    def test_by_name_and_unknown_raises(self) -> None:
        for spec in TOOLS:
            self.assertIs(by_name(spec.name), spec)
        with self.assertRaises(KeyError):
            by_name("nonexistent-linter-xyz")

    def test_all_binaries_covers_every_spec_and_wheel(self) -> None:
        bins = all_binaries()
        self.assertIsInstance(bins, list)
        self.assertEqual(len(bins), len(set(bins)))
        for spec in TOOLS:
            for b in spec.binaries:
                self.assertIn(b, bins)

    def test_wheel_packages_cover_expected_wheels(self) -> None:
        expected_keys = {
            "ruff",
            "yamllint",
            "taplo",
            "rumdl",
            "shfmt-py",
            "shellcheck-py",
            "hadolint-py",
            "clang-format",
            "clang-tidy",
            "gdtoolkit",
        }
        self.assertTrue(expected_keys.issubset(set(WHEEL_PACKAGES.keys())))
        gd_val = WHEEL_PACKAGES["gdtoolkit"]
        if isinstance(gd_val, tuple):
            self.assertIn("gdlint", gd_val)
            self.assertIn("gdformat", gd_val)
        else:
            self.assertIn("gdlint", gd_val)

    def test_executes_repo_code_flags(self) -> None:
        self.assertTrue(by_name("clippy").executes_repo_code)
        self.assertTrue(by_name("dotnet-format").executes_repo_code)
        self.assertTrue(by_name("biome").executes_repo_code)
        self.assertTrue(by_name("oxlint").executes_repo_code)
        self.assertTrue(by_name("golangci-lint").executes_repo_code)
        self.assertFalse(by_name("ruff").executes_repo_code)
        self.assertFalse(by_name("rustfmt").executes_repo_code)
        self.assertFalse(by_name("shellcheck").executes_repo_code)

    def test_input_globs_configured_for_file_taking_and_whole_project_tools(self) -> None:
        file_taking = {
            "oxlint",
            "rumdl",
            "rustfmt",
            "biome",
            "gofmt",
            "clang-format",
            "clang-tidy",
            "csharpier",
            "gdformat",
            "gdlint",
            "stylua",
            "selene",
            "glslangValidator",
            "dxc",
            "shfmt",
            "shellcheck",
            "pwsh-parse",
            "yamllint",
            "taplo",
            "hadolint",
        }
        for spec in TOOLS:
            with self.subTest(tool=spec.name):
                self.assertIsInstance(spec.input_globs, tuple)
                if spec.name in file_taking:
                    self.assertTrue(
                        len(spec.input_globs) > 0,
                        f"{spec.name} should declare non-empty input_globs",
                    )
                else:
                    self.assertEqual(
                        spec.input_globs,
                        (),
                        f"{spec.name} is whole-project and should have empty input_globs",
                    )


class TestArgvGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_clippy_argv_contains_json_and_offline(self) -> None:
        spec = by_name("clippy")
        cmd = argv(spec, "post", self.root, ["src/lib.rs"])
        self.assertEqual(cmd[0], "cargo")
        self.assertIn("clippy", cmd)
        self.assertIn("--all-targets", cmd)
        self.assertIn("--message-format", cmd)
        msg_idx = cmd.index("--message-format")
        self.assertEqual(cmd[msg_idx + 1], "json")
        self.assertIn("--offline", cmd)
        self.assertIn("-D", cmd)
        self.assertIn("warnings", cmd)

    def test_ruff_pre_and_post_argv(self) -> None:
        spec = by_name("ruff")
        pre_cmd = argv(spec, "pre", self.root, ["app.py"])
        post_cmd = argv(spec, "post", self.root, ["app.py"])
        self.assertEqual(
            pre_cmd,
            ["ruff", "check", "--select", "E9,F63,F7,F82", "--output-format", "json", "."],
        )
        self.assertEqual(
            post_cmd,
            ["ruff", "check", "--output-format", "json", "."],
        )
        self.assertEqual(spec.argv("pre", self.root, ["app.py"]), pre_cmd)

        fmt_spec = by_name("ruff-format")
        self.assertEqual(fmt_spec.modes, ("pre",))
        self.assertEqual(fmt_spec.tool, "ruff-format")
        fmt_cmd = argv(fmt_spec, "pre", self.root, ["app.py"])
        self.assertEqual(fmt_cmd, ["ruff", "format", "--check", "."])

    def test_powershell_pre_and_post_argv(self) -> None:
        self.assertEqual(_ps_quote("a'b.ps1"), "'a''b.ps1'")
        pwsh_pre = by_name("pwsh-parse")
        self.assertEqual(pwsh_pre.modes, ("pre",))
        self.assertEqual(pwsh_pre.parser, "pwsh-parse-json")
        pre_cmd = argv(pwsh_pre, "pre", self.root, ["scripts/a'b.ps1", "run.ps1"])
        self.assertEqual(pre_cmd[:4], ["pwsh", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertEqual(len(pre_cmd), 5)
        script = pre_cmd[4]
        self.assertIn("[System.Management.Automation.Language.Parser]::ParseFile($f,[ref]$null,[ref]$e) | Out-Null;", script)
        self.assertIn("if($e){ $e | ConvertTo-Json -Depth 4; exit 1 }", script)
        self.assertIn("'scripts/a''b.ps1'", script)
        self.assertIn("'run.ps1'", script)

        pssa_post = by_name("psscriptanalyzer")
        self.assertEqual(pssa_post.modes, ("post",))
        self.assertEqual(pssa_post.parser, "psscriptanalyzer-json")
        root_with_quote = self.root / "dir'name"
        post_cmd = argv(pssa_post, "post", root_with_quote, ["run.ps1"])
        self.assertEqual(post_cmd[:4], ["pwsh", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertEqual(len(post_cmd), 5)
        self.assertEqual(
            post_cmd[4],
            f"Invoke-ScriptAnalyzer -Path {_ps_quote(str(root_with_quote))} -Recurse | ConvertTo-Json -Depth 4",
        )

    def test_oxlint_gofmt_yamllint_golangci_flags(self) -> None:
        ox = argv(by_name("oxlint"), "post", self.root, ["index.ts"])
        self.assertEqual(ox, ["oxlint", "--deny-warnings", "--format", "json", "index.ts"])

        gf = argv(by_name("gofmt"), "pre", self.root, ["main.go"])
        self.assertEqual(gf, ["gofmt", "-e", "-l", "main.go"])

        yl_pre = argv(by_name("yamllint"), "pre", self.root, ["a.yaml"])
        self.assertEqual(
            yl_pre,
            ["yamllint", "-f", "parsable", "-d", "{extends: relaxed, rules: {line-length: disable}}", "a.yaml"],
        )
        yl_post = argv(by_name("yamllint"), "post", self.root, ["a.yaml"])
        self.assertEqual(yl_post, ["yamllint", "-f", "parsable", "--strict", "a.yaml"])

        gl = argv(by_name("golangci-lint"), "post", self.root, ["main.go"])
        self.assertEqual(gl, ["golangci-lint", "run", "--output.json.path", "stdout", "--show-stats=false", "./..."])

        biome_spec = by_name("biome")
        biome_pre = argv(biome_spec, "pre", self.root, ["src/index.ts", "package.json"])
        self.assertEqual(
            biome_pre,
            [
                "biome",
                "check",
                "--formatter-enabled=true",
                "--linter-enabled=false",
                "--assist-enabled=false",
                "--reporter",
                "json",
                "src/index.ts",
                "package.json",
            ],
        )
        biome_post = argv(biome_spec, "post", self.root, ["src/index.ts", "package.json"])
        self.assertEqual(biome_post, ["biome", "ci", "--reporter", "json", "src/index.ts", "package.json"])
        with self.assertRaises(ValueError):
            argv(biome_spec, "pre", self.root, [])

    def test_rustfmt_reads_edition_from_cargo_toml(self) -> None:
        spec = by_name("rustfmt")
        # Default fallback when Cargo.toml is absent
        self.assertEqual(
            argv(spec, "pre", self.root, ["src/lib.rs"]),
            ["rustfmt", "--check", "--edition", "2024", "src/lib.rs"],
        )
        # Reads edition from Cargo.toml when present
        (self.root / "Cargo.toml").write_text(
            '[package]\nname = "demo"\nedition = "2021"\n',
            encoding="utf-8",
        )
        self.assertEqual(
            argv(spec, "pre", self.root, ["src/lib.rs"]),
            ["rustfmt", "--check", "--edition", "2021", "src/lib.rs"],
        )

    def test_dotnet_format_cwd_and_per_file_include(self) -> None:
        spec = by_name("dotnet-format")
        self.assertEqual(
            argv(spec, "post", self.root, []),
            ["dotnet", "format", "--verify-no-changes", "--no-restore"],
        )
        self.assertEqual(
            argv(spec, "post", self.root, ["src/Player.cs", "src/Enemy.cs"]),
            [
                "dotnet",
                "format",
                "--verify-no-changes",
                "--no-restore",
                "--include",
                "src/Player.cs",
                "src/Enemy.cs",
            ],
        )

    def test_dxc_live_integration_when_installed(self) -> None:
        import shutil
        import subprocess

        dxc_bin = shutil.which("dxc")
        if dxc_bin is None:
            self.skipTest("dxc binary not installed on PATH")
        shader = self.root / "pixel.hlsl"
        shader.write_text(
            "float4 main() : SV_Target { return float4(1.0, 0.0, 0.0, 1.0); }\n",
            encoding="utf-8",
        )
        spec = by_name("dxc")
        cmd = argv(spec, "pre", self.root, [str(shader)])
        cmd[0] = dxc_bin
        cp = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, check=False)
        self.assertEqual(cp.returncode, 0, msg=f"dxc failed: {cp.stderr or cp.stdout}")

    def test_argv_docstring_is_one_line(self) -> None:
        doc = (argv.__doc__ or "").strip()
        self.assertTrue(doc)
        self.assertEqual(len(doc.splitlines()), 1)

    def test_taplo_offline_no_schema_in_post(self) -> None:
        spec = by_name("taplo")
        pre_cmd = argv(spec, "pre", self.root, ["Cargo.toml"])
        post_cmd = argv(spec, "post", self.root, ["Cargo.toml"])
        self.assertEqual(pre_cmd[:3], ["taplo", "format", "--check"])
        self.assertEqual(post_cmd[:3], ["taplo", "lint", "--no-schema"])

    def test_glslang_spirv_flags_stage_derivation_and_no_hlsl_or_gdshader(self) -> None:
        spec = by_name("glslangValidator")
        for non_glsl in ("**/*.hlsl", "**/*.fx", "**/*.ush", "**/*.usf", "**/*.shader", "**/*.gdshader"):
            self.assertNotIn(non_glsl, spec.detect_globs)
            self.assertNotIn(non_glsl, spec.input_globs)

        cmd_pre = argv(spec, "pre", self.root, ["shaders/test.frag"])
        self.assertEqual(
            cmd_pre,
            ["glslangValidator", "-V", "-o", os.devnull, "shaders/test.frag"],
        )
        self.assertNotIn("-D", cmd_pre)

        cmd_post = argv(spec, "post", self.root, ["shaders/water.vert.glsl"])
        self.assertEqual(
            cmd_post,
            [
                "glslangValidator",
                "-V",
                "-S",
                "vert",
                "--spirv-val",
                "-o",
                os.devnull,
                "shaders/water.vert.glsl",
            ],
        )

        # Files with no derivable GLSL stage (e.g. plain .glsl, .hlsl, .gdshader, .shader) are skipped;
        # if none have a derivable stage, ValueError is raised.
        with self.assertRaises(ValueError):
            argv(spec, "pre", self.root, ["shaders/pixel.hlsl", "shaders/effect.gdshader", "shaders/unknown.glsl"])

    def test_clang_tidy_requires_compile_commands(self) -> None:
        spec = by_name("clang-tidy")
        self.assertIn("compile_commands.json", spec.requires)
        self.assertFalse(tool_satisfied(spec, self.root))
        self.assertFalse(spec.is_satisfied(self.root))
        with self.assertRaises(ValueError):
            argv(spec, "post", self.root, ["src/main.cpp"])
        (self.root / "compile_commands.json").write_text("[]", encoding="utf-8")
        self.assertTrue(tool_satisfied(spec, self.root))
        self.assertTrue(spec.is_satisfied(self.root))
        (self.root / "compile_commands.json").unlink()

        for sub in ("build", "out"):
            sub_dir = self.root / sub
            sub_dir.mkdir(exist_ok=True)
            cc = sub_dir / "compile_commands.json"
            cc.write_text("[]", encoding="utf-8")
            self.assertTrue(tool_satisfied(spec, self.root))
            self.assertTrue(spec.is_satisfied(self.root))
            self.assertEqual(find_compile_commands_dir(self.root), sub_dir)
            cmd_sub = argv(spec, "post", self.root, ["src/main.cpp", "include/main.h", "include/main.hpp"])
            self.assertEqual(cmd_sub, ["clang-tidy", "-p", str(sub_dir), "src/main.cpp"])
            cc.unlink()

        (self.root / "compile_commands.json").write_text("[]", encoding="utf-8")
        self.assertEqual(find_compile_commands_dir(self.root), self.root)
        cmd_root = argv(spec, "post", self.root, ["src/main.cpp", "src/util.cc", "include/a.h"])
        self.assertEqual(cmd_root, ["clang-tidy", "-p", str(self.root), "src/main.cpp", "src/util.cc"])
        (self.root / "compile_commands.json").unlink()
        self.assertIsNone(find_compile_commands_dir(self.root))

        self.assertNotIn("**/*.h", spec.input_globs)
        self.assertNotIn("**/*.hpp", spec.input_globs)
        with self.assertRaises(ValueError):
            argv(spec, "post", self.root, ["include/only.h", "include/only.hpp"])

    def test_dxc_has_fo_devnull_and_excludes_ush_usf(self) -> None:
        spec = by_name("dxc")
        self.assertNotIn("**/*.ush", spec.input_globs)
        self.assertNotIn("**/*.usf", spec.input_globs)
        pre_cmd = argv(spec, "pre", self.root, ["shaders/ps.hlsl", "shaders/inc.ush", "shaders/common.usf"])
        self.assertEqual(
            pre_cmd,
            ["dxc", "-T", "lib_6_x", "-Fo", os.devnull, "shaders/ps.hlsl"],
        )
        post_cmd = argv(spec, "post", self.root, ["shaders/ps.fx", "shaders/inc.ush"])
        self.assertEqual(
            post_cmd,
            ["dxc", "-Weverything", "-T", "lib_6_x", "-Fo", os.devnull, "shaders/ps.fx"],
        )
        with self.assertRaises(ValueError):
            argv(spec, "pre", self.root, ["shaders/inc.ush", "shaders/common.usf"])

    def test_targets_never_passes_dot_to_file_only_tools(self) -> None:
        self.assertEqual(_targets([], "."), [])
        self.assertEqual(_targets(["  ", ""], "."), [])
        self.assertEqual(_targets(["a.py", " b.py "], "."), ["a.py", " b.py "])
        for spec in TOOLS:
            if spec.input_globs:
                for mode in spec.modes:
                    with self.subTest(tool=spec.name, mode=mode):
                        with self.assertRaises(ValueError):
                            argv(spec, mode, self.root, [])

    def test_all_tools_and_modes_produce_safe_argv_lists(self) -> None:
        (self.root / "compile_commands.json").write_text("[]", encoding="utf-8")
        sample_files = ["sample.cpp", "sub/file.vert", "sub/file.hlsl"]
        for spec in TOOLS:
            for mode in spec.modes:
                with self.subTest(tool=spec.name, mode=mode):
                    cmd = argv(spec, mode, self.root, sample_files)
                    self.assertIsInstance(cmd, list)
                    self.assertGreaterEqual(len(cmd), 1)
                    self.assertIn(
                        cmd[0],
                        spec.binaries,
                        f"{spec.name} ({mode}): argv[0]={cmd[0]!r} not in {spec.binaries}",
                    )
                    for idx, token in enumerate(cmd):
                        self.assertIsInstance(token, str)
                        self.assertTrue(len(token) > 0)
                        self.assertNotIn("&&", token)
                        is_pwsh_command_arg = idx > 0 and cmd[idx - 1] == "-Command"
                        if not is_pwsh_command_arg:
                            self.assertNotIn(";", token)
                            self.assertNotIn("|", token)
                        if token.startswith("-"):
                            self.assertNotIn(
                                " ",
                                token,
                                f"Flag token {token!r} in {spec.name} must not contain spaces",
                            )

    def test_invalid_mode_raises_value_error(self) -> None:
        spec = by_name("clippy")
        with self.assertRaises(ValueError):
            argv(spec, "pre", self.root, ["src/main.rs"])
        with self.assertRaises(ValueError):
            argv(spec, "unknown_mode", self.root, ["src/main.rs"])


class TestDetect(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_detect_cargo_sh_dockerfile_excludes_ruff(self) -> None:
        (self.root / "Cargo.toml").write_text("[package]\nname = 'demo'\n", encoding="utf-8")
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "run.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
        (self.root / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")

        found = detect(self.root)
        names = [t.name for t in found]

        for expected in ("clippy", "rustfmt", "shellcheck", "shfmt", "hadolint"):
            self.assertIn(expected, names)
        self.assertNotIn("ruff", names)

        indices = [TOOLS.index(t) for t in found]
        self.assertEqual(indices, sorted(indices))

    def test_saved_languages_adds_ruff(self) -> None:
        (self.root / "Cargo.toml").write_text("[package]\nname = 'demo'\n", encoding="utf-8")
        found = detect(self.root, saved_languages=["python"])
        names = [t.name for t in found]
        self.assertIn("ruff", names)
        self.assertIn("ruff-format", names)
        self.assertIn("clippy", names)
        self.assertIn("rustfmt", names)

    def test_detect_excludes_clang_tidy_without_compile_commands(self) -> None:
        (self.root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        found_no_cc = [t.name for t in detect(self.root)]
        self.assertIn("clang-format", found_no_cc)
        self.assertNotIn("clang-tidy", found_no_cc)

        found_saved_no_cc = [t.name for t in detect(self.root, saved_languages=["cpp"])]
        self.assertIn("clang-format", found_saved_no_cc)
        self.assertNotIn("clang-tidy", found_saved_no_cc)

        build_dir = self.root / "build"
        build_dir.mkdir()
        (build_dir / "compile_commands.json").write_text("[]\n", encoding="utf-8")
        found_with_cc = [t.name for t in detect(self.root)]
        self.assertIn("clang-format", found_with_cc)
        self.assertIn("clang-tidy", found_with_cc)

    def test_detect_skips_ignored_directories_and_symlinks(self) -> None:
        for ignored in (".git", "node_modules", "target", ".venv", "__pycache__"):
            d = self.root / ignored
            d.mkdir(parents=True, exist_ok=True)
            (d / "sneaky.py").write_text("x = 1\n", encoding="utf-8")
            (d / "package.json").write_text("{}\n", encoding="utf-8")

        outside = self.root.parent / f"outside_{self.root.name}"
        outside.mkdir(exist_ok=True)
        try:
            (outside / "secret.py").write_text("y = 2\n", encoding="utf-8")
            os.symlink(str(outside), str(self.root / "linked_dir"))
            os.symlink(str(outside / "secret.py"), str(self.root / "linked.py"))
            found = detect(self.root)
            self.assertEqual(found, [])
        finally:
            if (outside / "secret.py").exists():
                (outside / "secret.py").unlink()
            if outside.exists():
                outside.rmdir()

    def test_walk_cap_bounds_file_collection(self) -> None:
        for i in range(15):
            (self.root / f"file_{i:02d}.txt").write_text("hi\n", encoding="utf-8")
        res = scan(self.root, max_entries=5)
        self.assertIsInstance(res, ScanResult)
        self.assertTrue(res.truncated)
        self.assertEqual(len(res.files), 5)

    def test_walk_cap_stops_on_many_empty_dirs(self) -> None:
        for i in range(20):
            (self.root / f"empty_{i:02d}").mkdir()
        (self.root / "z_last" / "app.py").parent.mkdir()
        (self.root / "z_last" / "app.py").write_text("x = 1\n", encoding="utf-8")

        res = scan(self.root, max_entries=5)
        self.assertTrue(res.truncated)
        self.assertEqual(res.files, ())
        self.assertEqual(detect(self.root, max_entries=5), [])

    def test_detect_accepts_precomputed_scan_result_without_rescanning(self) -> None:
        from unittest import mock

        pre_scan = ScanResult(files=("Cargo.toml", "Dockerfile"), truncated=False)
        with mock.patch.object(lint_tools, "scan", side_effect=AssertionError("scan should not be called")):
            found = detect(self.root, scan_result=pre_scan)
        names = [t.name for t in found]
        self.assertIn("clippy", names)
        self.assertIn("hadolint", names)
        self.assertIn("taplo", names)


if __name__ == "__main__":
    unittest.main()
