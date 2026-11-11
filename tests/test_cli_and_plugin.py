"""Unit tests for cli.py and plugin registration (__init__.py)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest import mock

import pytest

from tests import ensure_test_package
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

plugin_init = ensure_test_package()

from hermes_plugins.defuzz import cli as cli_mod  # noqa: E402
from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402
from hermes_plugins.defuzz.state_store import state_db_path  # noqa: E402


class _MockPluginContext:
    def __init__(self) -> None:
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        self.cli_commands: Dict[str, Dict[str, Any]] = {}
        self.slash_commands: Dict[str, Dict[str, Any]] = {}
        self.llm = None

    def get_config(self, key: str, default: Any = None) -> Any:
        return default

    def register_tool(self, name: str, toolset: str, schema: Dict[str, Any], handler: Callable) -> None:
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_hook(self, hook_name: str, callback: Callable) -> None:
        self.hooks.setdefault(hook_name, []).append(callback)

    def register_cli_command(
        self,
        name: str,
        help: str,
        setup_fn: Callable,
        handler_fn: Callable,
        description: str = "",
    ) -> None:
        self.cli_commands[name] = {
            "help": help,
            "setup_fn": setup_fn,
            "handler_fn": handler_fn,
            "description": description,
        }

    def register_command(self, name: str, handler: Callable, description: str = "", args_hint: str = "") -> None:
        self.slash_commands[name] = {"handler": handler, "description": description, "args_hint": args_hint}


class TestCliAndPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self._env_tmp = tempfile.TemporaryDirectory()
        env_base = Path(self._env_tmp.name)
        self.hermes_home = env_base / "hermes_home"
        self.projects_root = env_base / "projects_root"
        self.tmp_dir = env_base / "tmpdir"
        self.hermes_home.mkdir(parents=True, exist_ok=True)
        self.projects_root.mkdir(parents=True, exist_ok=True)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self._real_home_db = Path("~/.hermes/plugin-data/defuzz/state.db").expanduser()
        self._real_home_db_existed = self._real_home_db.exists()
        self._real_home_db_mtime = (
            self._real_home_db.stat().st_mtime_ns if self._real_home_db_existed else None
        )
        self._env_patcher = mock.patch.dict(
            os.environ,
            {
                "HERMES_HOME": str(self.hermes_home),
                "HERMES_PROJECTS_ROOT": str(self.projects_root),
                "TMPDIR": str(self.tmp_dir),
            },
        )
        self._env_patcher.start()

    def tearDown(self) -> None:
        self._env_patcher.stop()
        if not self._real_home_db_existed:
            self.assertFalse(self._real_home_db.exists())
        else:
            self.assertEqual(self._real_home_db.stat().st_mtime_ns, self._real_home_db_mtime)
        self._env_tmp.cleanup()

    def test_plugin_registers_tools_hooks_cli_and_slash(self) -> None:
        ctx = _MockPluginContext()
        plugin_init.register(ctx)
        self.assertEqual(sorted(ctx.tools.keys()), ["defuzz_audit", "defuzz_place", "defuzz_project"])
        self.assertEqual(
            sorted(ctx.hooks.keys()),
            ["pre_tool_call", "transform_tool_result"],
        )
        self.assertEqual([len(v) for v in ctx.hooks.values()], [1, 1])
        self.assertEqual(
            ctx.hooks["transform_tool_result"][0].__module__,
            "hermes_plugins.defuzz.placer",
        )
        self.assertIn("defuzz", ctx.cli_commands)
        self.assertIn("defuzz", ctx.slash_commands)

    def test_plugin_manifest_requires_hermes_covers_ctx_files(self) -> None:
        import yaml

        manifest_path = Path(__file__).resolve().parent.parent / "plugin.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        # The minimum Hermes version includes the scoped Desktop SDK used by this plugin.
        self.assertEqual(manifest.get("requires_hermes"), ">=0.23.0")

    def test_cli_end_to_end_copy_scan_run_and_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            src = base / "messy_src"
            copy_dir = base / "messy_copy"
            staging = base / "staging"
            src.mkdir()
            staging.mkdir()

            for i in range(6):
                (src / f"note_{i}.md").write_text(f"Note {i}\n", encoding="utf-8")
            (src / "README.md").write_text("# Demo\n", encoding="utf-8")

            rc_run = cli_main([
                "run",
                str(copy_dir),
                "--source",
                str(src),
                "--staging",
                str(staging),
                "--deterministic",
            ])
            self.assertEqual(rc_run, 0)
            self.assertTrue((copy_dir / "AGENTS.md").is_file())
            self.assertTrue((copy_dir / ".adopt" / "report.json").is_file())
            self.assertTrue((copy_dir / "docs" / "note_0.md").is_file())
            self.assertTrue((staging / "inventory.json").is_file())

            # Test CLI place of a loose unknown file -> _inbox/
            (copy_dir / "drop.unknown").write_text("payload\n", encoding="utf-8")
            rc_place = cli_main([
                "place",
                "drop.unknown",
                "--root",
                str(copy_dir),
            ])
            self.assertEqual(rc_place, 0)
            self.assertTrue((copy_dir / "_inbox" / "drop.unknown").is_file())

    def test_cli_templates_lists_fixtures_and_lenient_errors(self) -> None:
        import io
        import shutil
        from contextlib import redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        with tempfile.TemporaryDirectory() as tmp:
            t_root = Path(tmp) / "templates"
            shutil.copytree(fixtures_dir, t_root)
            bad_dir = t_root / "bad-one"
            bad_dir.mkdir(parents=True)
            (bad_dir / "template.yaml").write_text("id: wrong-id\n", encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["templates", "--templates-root", str(t_root)])

            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("fake-rust-game", out)
            self.assertIn("fake-py-service", out)
            self.assertIn("game", out)
            self.assertIn("service", out)
            self.assertIn("mono", out)
            self.assertIn("poly", out)
            self.assertIn("rust", out)
            self.assertIn("cargo", out)
            self.assertIn("bad-one", out)

    def test_cli_new_dry_run_prints_tree_and_creates_nothing(self) -> None:
        import io
        from contextlib import redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        answers_json = json.dumps({
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        })
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dest_root = base / "projects"
            hermes_home = base / "hermes_home"
            tmp_dir = base / "tmpdir"
            dest_root.mkdir()
            hermes_home.mkdir()
            tmp_dir.mkdir()
            buf = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {
                    "HERMES_HOME": str(hermes_home),
                    "HERMES_PROJECTS_ROOT": str(dest_root),
                    "TMPDIR": str(tmp_dir),
                },
            ):
                with redirect_stdout(buf):
                    rc = cli_main([
                        "new",
                        "--answers",
                        answers_json,
                        "--name",
                        "Dry Run Game",
                        "--template",
                        "fake-rust-game",
                        "--dest-root",
                        str(dest_root),
                        "--templates-root",
                        str(fixtures_dir),
                    ])
                self.assertFalse(state_db_path().exists())
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn(f"Proposed repository: dry-run-game -> {dest_root / 'dry-run-game'}", out)
            self.assertIn("Cargo.toml", out)
            self.assertIn("src/main.rs", out)
            self.assertIn("Re-run with --yes to create.", out)
            self.assertFalse((dest_root / "dry-run-game").exists())
            self.assertFalse((hermes_home / "plugin-data" / "defuzz" / "state.db").exists())
            self.assertEqual(list(tmp_dir.iterdir()), [])

    def test_cli_new_explicit_template_dry_run_creates_no_db_or_staging(self) -> None:
        import io
        from contextlib import redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        answers_json = json.dumps({
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        })
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dest_root = base / "projects"
            hermes_home = base / "hermes_home"
            tmp_dir = base / "tmpdir"
            dest_root.mkdir()
            hermes_home.mkdir()
            tmp_dir.mkdir()
            buf = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {
                    "HERMES_HOME": str(hermes_home),
                    "HERMES_PROJECTS_ROOT": str(dest_root),
                    "TMPDIR": str(tmp_dir),
                },
            ):
                with redirect_stdout(buf):
                    rc = cli_main([
                        "new",
                        "--answers",
                        answers_json,
                        "--name",
                        "Explicit Dry Run",
                        "--template",
                        "fake-rust-game",
                        "--dest-root",
                        str(dest_root),
                        "--templates-root",
                        str(fixtures_dir),
                    ])
                self.assertFalse(state_db_path().exists())
            self.assertEqual(rc, 0)
            self.assertIn("Re-run with --yes to create.", buf.getvalue())
            self.assertFalse((dest_root / "explicit-dry-run").exists())
            self.assertFalse((hermes_home / "plugin-data" / "defuzz" / "state.db").exists())
            self.assertEqual(list(tmp_dir.iterdir()), [])

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_cli_new_yes_creates_and_registers_via_hook(self) -> None:
        import io
        from contextlib import redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        answers_json = json.dumps({
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        })
        reg_calls: List[Any] = []

        def fake_reg(name: str, path: str) -> str:
            reg_calls.append((name, path))
            return json.dumps({"success": True, "id": "proj-cli-1", "name": name, "path": path})

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dest_root = base / "projects"
            hermes_home = base / "hermes_home"
            dest_root.mkdir()
            hermes_home.mkdir()
            buf = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {"HERMES_HOME": str(hermes_home), "HERMES_PROJECTS_ROOT": str(dest_root)},
            ):
                with mock.patch.object(cli_mod, "REGISTER_PROJECT", fake_reg):
                    # --yes alone never chooses: without --template/--kit nothing is created.
                    refused = io.StringIO()
                    with redirect_stdout(refused):
                        rc_refused = cli_main([
                            "new",
                            "--answers",
                            answers_json,
                            "--name",
                            "Created Game",
                            "--yes",
                            "--dest-root",
                            str(dest_root),
                            "--templates-root",
                            str(fixtures_dir),
                        ])
                    self.assertEqual(rc_refused, 2)
                    self.assertTrue(refused.getvalue().rstrip().endswith(
                        "Nothing was created. Run again with --template ID or --kit ID."
                    ))
                    self.assertEqual(list(dest_root.iterdir()), [])
                    self.assertEqual(reg_calls, [])
                    with redirect_stdout(buf):
                        rc = cli_main([
                            "new",
                            "--answers",
                            answers_json,
                            "--name",
                            "Created Game",
                            "--template",
                            "fake-rust-game",
                            "--yes",
                            "--dest-root",
                            str(dest_root),
                            "--templates-root",
                            str(fixtures_dir),
                        ])
            self.assertEqual(rc, 0)
            target = dest_root / "created-game"
            self.assertTrue(target.is_dir())
            self.assertTrue((target / ".git").is_dir())
            self.assertIn(str(target), buf.getvalue())
            self.assertEqual(len(reg_calls), 1)
            self.assertEqual(reg_calls[0], ("Created Game", str(target)))

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_cli_new_with_template_flag_skips_matching(self) -> None:
        import io
        from contextlib import redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        # Answers wouldn't match fake-rust-game (tool + go), but --template overrides matching
        answers_json = json.dumps({
            "building": "tool",
            "layout": "single",
            "languages": ["go"],
        })
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dest_root = base / "projects"
            hermes_home = base / "hermes_home"
            dest_root.mkdir()
            hermes_home.mkdir()
            buf = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {"HERMES_HOME": str(hermes_home), "HERMES_PROJECTS_ROOT": str(dest_root)},
            ):
                with mock.patch.object(
                    cli_mod,
                    "REGISTER_PROJECT",
                    lambda n, p: json.dumps({"success": True, "id": "p-tmpl"}),
                ):
                    with redirect_stdout(buf):
                        rc = cli_main([
                            "new",
                            "--answers",
                            answers_json,
                            "--name",
                            "Forced Template",
                            "--template",
                            "fake-rust-game",
                            "--yes",
                            "--dest-root",
                            str(dest_root),
                            "--templates-root",
                            str(fixtures_dir),
                        ])
            self.assertEqual(rc, 0)
            self.assertTrue((dest_root / "forced-template").is_dir())

    def test_cli_new_without_template_or_kit_prints_list_and_exits_2(self) -> None:
        import io
        from contextlib import redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        answers_json = json.dumps({
            "building": "tool",
            "layout": "single",
            "languages": ["go"],
        })
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dest_root = base / "projects"
            hermes_home = base / "hermes_home"
            dest_root.mkdir()
            hermes_home.mkdir()
            buf = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {"HERMES_HOME": str(hermes_home), "HERMES_PROJECTS_ROOT": str(dest_root)},
            ):
                with redirect_stdout(buf):
                    rc = cli_main([
                        "new",
                        "--answers",
                        answers_json,
                        "--name",
                        "No Match Tool",
                        "--dest-root",
                        str(dest_root),
                        "--templates-root",
                        str(fixtures_dir),
                    ])
            self.assertEqual(rc, 2)
            out = buf.getvalue()
            self.assertNotIn("do not push or publish anything", out.lower())
            self.assertIn("[--template fake-rust-game]", out)
            self.assertIn("[--template fake-py-service]", out)
            self.assertEqual(
                out.rstrip("\n").splitlines()[-1],
                "Nothing was created. Run again with --template ID or --kit ID.",
            )
            self.assertEqual(list(dest_root.iterdir()), [])

    def test_cli_new_explicit_template_fills_missing_answers_from_template(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        # The explicit template answers "layout" and "languages"; no questionnaire wait (exit 0, not 3).
        incomplete_answers = json.dumps({"building": "game"})
        err_buf = io.StringIO()
        with redirect_stderr(err_buf), redirect_stdout(io.StringIO()):
            rc = cli_main([
                "new",
                "--answers",
                incomplete_answers,
                "--name",
                "Timeout Explicit",
                "--template",
                "fake-rust-game",
                "--dest-root",
                str(self.projects_root),
                "--templates-root",
                str(fixtures_dir),
            ])
        self.assertEqual(rc, 0, err_buf.getvalue())
        self.assertFalse(state_db_path().exists())
        self.assertEqual(list(self.tmp_dir.iterdir()), [])

    def test_cli_new_explicit_template_dry_run_deadline_after_propose_exits_3(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        answers_json = json.dumps({
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        })
        # monotonic() calls in _handle_new_subcommand (and run_questionnaire):
        # 1: deadline = time.monotonic() + timeout_s (100 + 10 = 110)
        # 2: rem before run_questionnaire (101 -> rem = 9)
        # 3..N inside run_questionnaire (uses time.monotonic, returns 102)
        # after propose(): rem = deadline - time.monotonic() -> returns 120 -> rem = -10 <= 0
        orig_propose = cli_mod.propose
        clock_val = 100.0

        def fake_monotonic() -> float:
            return clock_val

        def slow_propose(*args: Any, **kwargs: Any) -> Any:
            nonlocal clock_val
            res = orig_propose(*args, **kwargs)
            clock_val = 200.0
            return res

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with mock.patch.object(cli_mod.time, "monotonic", side_effect=fake_monotonic):
            with mock.patch.object(cli_mod, "propose", side_effect=slow_propose):
                with redirect_stdout(out_buf), redirect_stderr(err_buf):
                    rc = cli_main([
                        "new",
                        "--answers",
                        answers_json,
                        "--name",
                        "Slow Dry Run",
                        "--template",
                        "fake-rust-game",
                        "--timeout",
                        "10",
                        "--dest-root",
                        str(self.projects_root),
                        "--templates-root",
                        str(fixtures_dir),
                    ])
        self.assertEqual(rc, 3)
        self.assertEqual(out_buf.getvalue(), "")
        self.assertFalse(state_db_path().exists())
        self.assertEqual(list(self.tmp_dir.iterdir()), [])

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_cli_new_explicit_template_accept_permission_error_discards_staging(self) -> None:
        import io
        from contextlib import redirect_stderr

        fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "templates"
        answers_json = json.dumps({
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        })
        err_buf = io.StringIO()
        real_rename = os.rename

        def denied(src, dst, *a, **k):
            if dst == "perm-error-cli" and k.get("dst_dir_fd") is not None:  # the move into the projects folder
                raise PermissionError(13, "Permission denied")
            return real_rename(src, dst, *a, **k)

        with mock.patch.object(os, "rename", side_effect=denied):
            with redirect_stderr(err_buf):
                rc = cli_main([
                    "new",
                    "--answers",
                    answers_json,
                    "--name",
                    "Perm Error CLI",
                    "--template",
                    "fake-rust-game",
                    "--yes",
                    "--dest-root",
                    str(self.projects_root),
                    "--templates-root",
                    str(fixtures_dir),
                ])
        self.assertEqual(rc, 1)
        self.assertIn("permission was denied", err_buf.getvalue())
        self.assertEqual(list(self.tmp_dir.iterdir()), [])
        self.assertFalse(state_db_path().exists())

    def test_cli_unknown_subcommand_lists_templates_and_new(self) -> None:
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main([])
        self.assertEqual(rc, 2)
        payload = json.loads(buf.getvalue())
        self.assertFalse(payload["ok"])
        self.assertIn("templates", payload["error"])
        self.assertIn("new", payload["error"])
        self.assertIn("lint", payload["error"])
        self.assertIn("setup-tools", payload["error"])

    def test_cli_lint_reports_selected_tool_result_when_setup_incomplete(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hermes_plugins.defuzz import lint_setup

        incomplete_st = lint_setup.SetupStatus(
            items=[],
            complete=False,
            pending_mb=120,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
            blocked_reason=None,
        )
        buf = io.StringIO()
        with (
            mock.patch.object(cli_mod, "status", return_value=incomplete_st),
            mock.patch.object(
                cli_mod,
                "headless_message",
                return_value="Lint-tool setup is pending. Run `hermes defuzz setup-tools --yes`.",
            ),
            mock.patch.object(cli_mod, "run_lint", return_value={"ok": True, "findings": []}) as run,
            redirect_stdout(buf),
        ):
            rc = cli_main(["lint", str(self.projects_root)])
        self.assertEqual(rc, 0)
        run.assert_called_once()
        self.assertIn("No findings", buf.getvalue())

    def test_cli_lint_exits_0_when_no_error_findings_and_1_on_errors(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hermes_plugins.defuzz import lint_setup

        ready_st = lint_setup.SetupStatus(
            items=[],
            complete=True,
            pending_mb=0,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
            blocked_reason=None,
        )
        warn_only_res = {
            "ok": True,
            "project": str(self.projects_root),
            "mode": "both",
            "findings": [
                {
                    "file": "src/app.py",
                    "line": 4,
                    "rule": "W1",
                    "message": "minor style warning",
                    "tool": "ruff",
                    "severity": "warning",
                }
            ],
            "tools_run": [],
            "tools_missing": [],
            "warnings": [],
            "error": None,
        }
        buf = io.StringIO()
        with (
            mock.patch.object(cli_mod, "status", return_value=ready_st),
            mock.patch.object(cli_mod, "run_lint", return_value=warn_only_res) as m_lint,
            redirect_stdout(buf),
        ):
            rc0 = cli_main(["lint", str(self.projects_root), "--mode", "pre"])
            m_lint.assert_called_once_with(str(self.projects_root), "pre")
        self.assertEqual(rc0, 0)
        self.assertIn("src/app.py:4", buf.getvalue())

        err_res = {
            **warn_only_res,
            "findings": [
                {
                    "file": "src/app.py",
                    "line": 9,
                    "rule": "F821",
                    "message": "undefined name x",
                    "tool": "ruff",
                    "severity": "error",
                }
            ],
        }
        json_buf = io.StringIO()
        with (
            mock.patch.object(cli_mod, "status", return_value=ready_st),
            mock.patch.object(cli_mod, "run_lint", return_value=err_res),
            redirect_stdout(json_buf),
        ):
            rc1 = cli_main(["lint", str(self.projects_root), "--json"])
        self.assertEqual(rc1, 1)
        parsed = json.loads(json_buf.getvalue())
        self.assertEqual(parsed["findings"][0]["rule"], "F821")

    def test_cli_lint_exits_2_on_internal_error(self) -> None:
        import io
        from contextlib import redirect_stderr

        from hermes_plugins.defuzz import lint_setup

        ready_st = lint_setup.SetupStatus(
            items=[],
            complete=True,
            pending_mb=0,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
            blocked_reason=None,
        )
        internal_err_res = {
            "ok": False,
            "project": "/bad",
            "mode": "both",
            "findings": [],
            "tools_run": [],
            "tools_missing": [],
            "warnings": [],
            "error": "Project root does not exist",
        }
        err_buf = io.StringIO()
        with (
            mock.patch.object(cli_mod, "status", return_value=ready_st),
            mock.patch.object(cli_mod, "run_lint", return_value=internal_err_res),
            redirect_stderr(err_buf),
        ):
            rc = cli_main(["lint", "/bad"])
        self.assertEqual(rc, 2)
        self.assertIn("Project root does not exist", err_buf.getvalue())

    def test_cli_setup_tools_status_plan_noninteractive_and_yes(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from hermes_plugins.defuzz import lint_setup

        fake_st = lint_setup.SetupStatus(
            items=[
                lint_setup.ItemStatus(
                    name="biome",
                    kind="binary",
                    version="2.6.6",
                    size_mb=28,
                    state="missing",
                )
            ],
            complete=False,
            pending_mb=28,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
            blocked_reason=None,
        )
        fake_plan = [
            {
                "name": "biome",
                "kind": "binary",
                "version": "2.6.6",
                "size_mb": 28,
                "url": "https://github.com/biomejs/biome/releases/download/v2.6.6/biome",
                "hash": "abc",
                "hash_algo": "sha256",
                "install_dir": "/tmp/opt/biome",
                "post_install": [],
                "post_install_argv": [],
            }
        ]

        # --status
        st_buf = io.StringIO()
        with mock.patch.object(cli_mod, "status", return_value=fake_st), redirect_stdout(st_buf):
            rc_st = cli_main(["setup-tools", "--status"])
        self.assertEqual(rc_st, 0)
        self.assertFalse(json.loads(st_buf.getvalue())["complete"])

        # --plan
        plan_buf = io.StringIO()
        with (
            mock.patch.object(cli_mod, "describe_plan", return_value=fake_plan),
            redirect_stdout(plan_buf),
        ):
            rc_plan = cli_main(["setup-tools", "--plan"])
        self.assertEqual(rc_plan, 0)
        self.assertEqual(json.loads(plan_buf.getvalue())[0]["name"], "biome")

        # Non-interactive without --yes -> exit 3
        headless_buf = io.StringIO()
        fake_stdin = mock.MagicMock()
        fake_stdin.isatty.return_value = False
        with (
            mock.patch.object(cli_mod.sys, "stdin", fake_stdin),
            mock.patch.object(
                cli_mod,
                "headless_message",
                return_value="Lint-tool setup is pending. Run setup-tools --yes.",
            ),
            redirect_stdout(headless_buf),
        ):
            rc_no_tty = cli_main(["setup-tools"])
        self.assertEqual(rc_no_tty, 3)
        self.assertIn("setup-tools --yes", headless_buf.getvalue())

        # --yes runs setup and prints progress to stderr
        def _fake_setup(cb: Any) -> Any:
            cb(
                lint_setup.Progress(
                    item="biome",
                    step="done",
                    item_index=0,
                    item_count=1,
                    bytes_done=100,
                    bytes_total=100,
                    percent=100.0,
                    message="Installed biome 2.6.6",
                )
            )
            return lint_setup.SetupResult(
                ok=True,
                installed=["biome"],
                skipped=[],
                failed={},
                error=None,
                log=["installed biome"],
            )

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with (
            mock.patch.object(cli_mod, "run_setup", side_effect=_fake_setup),
            redirect_stdout(out_buf),
            redirect_stderr(err_buf),
        ):
            rc_yes = cli_main(["setup-tools", "--yes"])
        self.assertEqual(rc_yes, 0)
        self.assertIn("Installed biome 2.6.6", err_buf.getvalue())
        self.assertEqual(json.loads(out_buf.getvalue())["installed"], ["biome"])

        # Interactive without --yes prompts Proceed? [y/N]
        tty_stdin = mock.MagicMock()
        tty_stdin.isatty.return_value = True
        prompt_out = io.StringIO()
        prompt_err = io.StringIO()
        with (
            mock.patch.object(cli_mod.sys, "stdin", tty_stdin),
            mock.patch.object(cli_mod, "describe_plan", return_value=fake_plan),
            mock.patch("builtins.input", return_value="y") as m_input,
            mock.patch.object(cli_mod, "run_setup", side_effect=_fake_setup),
            redirect_stdout(prompt_out),
            redirect_stderr(prompt_err),
        ):
            rc_tty = cli_main(["setup-tools"])
            m_input.assert_called_once_with("Proceed? [y/N] ")
        self.assertEqual(rc_tty, 0)
        self.assertIn("Lint tool setup plan", prompt_out.getvalue())

    def test_cli_setup_tools_counts_pending_only_and_labels_the_csharpier_entry(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hermes_plugins.defuzz import lint_setup

        def _st(name: str, version: str, size: int, state: str) -> Any:
            return lint_setup.ItemStatus(name=name, kind="sdk", version=version, size_mb=size, state=state)

        fake_st = lint_setup.SetupStatus(
            items=[_st("biome", "2.6.6", 28, "present"), _st("dotnet", "10.0.404", 450, "missing")],
            complete=False,
            pending_mb=450,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
        )
        fake_plan = [
            {"name": "biome", "kind": "binary", "version": "2.6.6", "size_mb": 28,
             "url": "https://example.invalid/biome", "post_install": [], "post_install_argv": []},
            {"name": "dotnet", "kind": "sdk", "version": "1.3.0", "size_mb": 3,
             "url": "https://example.invalid/csharpier.1.3.0.nupkg", "post_install": [], "post_install_argv": []},
        ]
        tty_stdin = mock.MagicMock()
        tty_stdin.isatty.return_value = True
        out = io.StringIO()
        with (
            mock.patch.object(cli_mod.sys, "stdin", tty_stdin),
            mock.patch.object(cli_mod, "status", return_value=fake_st),
            mock.patch.object(cli_mod, "describe_plan", return_value=fake_plan),
            mock.patch("builtins.input", return_value="n"),
            redirect_stdout(out),
        ):
            rc = cli_main(["setup-tools"])
        self.assertEqual(rc, 1)
        text = out.getvalue()
        self.assertIn("Lint tool setup plan (1 to install, ~3 MB):", text)
        self.assertIn("  - csharpier 1.3.0 (dotnet tool) (3 MB) -> https://example.invalid/csharpier", text)
        self.assertIn("Already installed: biome.", text)
        self.assertNotIn("dotnet 1.3.0", text)
        self.assertNotIn("example.invalid/biome", text)

        plan_buf = io.StringIO()
        with mock.patch.object(cli_mod, "describe_plan", return_value=fake_plan), redirect_stdout(plan_buf):
            cli_main(["setup-tools", "--plan"])
        labels = [e["label"] for e in json.loads(plan_buf.getvalue())]
        self.assertEqual(labels, ["biome 2.6.6", "csharpier 1.3.0 (dotnet tool)"])

    def test_cli_direct_references_without_orig_indirection(self) -> None:
        for attr in (
            "_ORIG_RUN_LINT",
            "_ORIG_STATUS",
            "_ORIG_RUN_SETUP",
            "_ORIG_DESCRIBE_PLAN",
            "_ORIG_HEADLESS_MESSAGE",
            "_call_status",
            "_call_run_lint",
            "_call_run_setup",
            "_call_describe_plan",
            "_call_headless_message",
        ):
            self.assertFalse(hasattr(cli_mod, attr), f"cli should not have indirection helper {attr}")

    def test_cli_script_mode_cannot_be_shadowed_by_linter_dir_or_foreign_modules(self) -> None:
        import subprocess

        repo_root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            shadow_parent = Path(tmp)
            shadow_linter_dir = shadow_parent / "linter"
            shadow_linter_dir.mkdir()
            (shadow_linter_dir / "__init__.py").write_text(
                "raise RuntimeError('shadow linter package imported')\n",
                encoding="utf-8",
            )
            code = f"""
import pathlib, sys, types
sys.path.insert(0, {str(shadow_parent)!r})
for name in ("safety", "cli", "linter", "lint_tools", "state_store"):
    mod = types.ModuleType(name)
    mod.__file__ = f"/foreign/{{name}}.py"
    sys.modules[name] = mod

import runpy
try:
    runpy.run_path({str(repo_root / "cli.py")!r}, run_name="__main__")
except SystemExit as exc:
    assert exc.code == 0, f"unexpected exit code: {{exc.code}}"

pkg = sys.modules["hermes_plugins.defuzz"]
linter_mod = sys.modules["hermes_plugins.defuzz.linter"]
assert pathlib.Path(linter_mod.__file__).resolve() == pathlib.Path({str(repo_root / "linter.py")!r}).resolve()
for name in ("safety", "cli", "linter", "lint_tools", "state_store"):
    assert sys.modules[name].__file__ == f"/foreign/{{name}}.py"
"""
            proc = subprocess.run(
                [sys.executable, "-c", code, "setup-tools", "--plan"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            plan = json.loads(proc.stdout)
            self.assertIsInstance(plan, list)
            self.assertGreater(len(plan), 0)

    def test_foreign_module_collision_isolation_in_subprocess(self) -> None:
        import subprocess

        repo_root = Path(__file__).resolve().parent.parent
        all_siblings = (
            "agents_md",
            "applier",
            "cli",
            "handoff",
            "lint_env",
            "lint_setup",
            "lint_tools",
            "linter",
            "matcher",
            "naming",
            "new_project",
            "placer",
            "questionnaire",
            "rules",
            "safety",
            "scaffolder",
            "scanner",
            "schemas",
            "setup_manifest",
            "state_store",
            "templates",
        )
        code = f"""
import importlib, importlib.util, pathlib, sys, types

repo_root = pathlib.Path({str(repo_root)!r}).resolve()
preloaded = ("safety", "cli", "linter", "lint_tools", "state_store")
foreign_objs = {{}}
for name in preloaded:
    m = types.ModuleType(name)
    m.__file__ = f"/foreign/{{name}}.py"
    m.FOREIGN_SENTINEL = name
    sys.modules[name] = m
    foreign_objs[name] = m

before_keys = set(sys.modules.keys())
before_path = list(sys.path)

# 1. Load the plugin package under hermes_plugins.defuzz
ns = types.ModuleType("hermes_plugins")
ns.__path__ = []
ns.__package__ = "hermes_plugins"
sys.modules["hermes_plugins"] = ns

pkg_name = "hermes_plugins.defuzz"
spec = importlib.util.spec_from_file_location(
    pkg_name,
    repo_root / "__init__.py",
    submodule_search_locations=[str(repo_root)],
)
assert spec is not None and spec.loader is not None
pkg = importlib.util.module_from_spec(spec)
pkg.__package__ = pkg_name
pkg.__path__ = [str(repo_root)]
sys.modules[pkg_name] = pkg
spec.loader.exec_module(pkg)

for sub in {all_siblings!r}:
    mod = importlib.import_module(f"{{pkg_name}}.{{sub}}")
    mod_file = pathlib.Path(mod.__file__).resolve()
    assert mod_file == (repo_root / f"{{sub}}.py").resolve(), f"{{sub}} resolved to {{mod_file}}"

# 2. Load the dashboard router if fastapi is available, else verify _ensure_plugin_package / _load
api_path = repo_root / "dashboard" / "plugin_api.py"
try:
    import fastapi  # noqa: F401
    has_fastapi = True
except ImportError:
    has_fastapi = False

if has_fastapi:
    api_spec = importlib.util.spec_from_file_location("hermes_dashboard_plugin_defuzz", api_path)
    assert api_spec is not None and api_spec.loader is not None
    api_mod = importlib.util.module_from_spec(api_spec)
    sys.modules["hermes_dashboard_plugin_defuzz"] = api_mod
    api_spec.loader.exec_module(api_mod)
    assert api_mod.router is not None
    for sub in ("linter", "lint_setup", "lint_tools", "setup_manifest"):
        loaded = api_mod._load(sub)
        assert pathlib.Path(loaded.__file__).resolve() == (repo_root / f"{{sub}}.py").resolve()

# Assert sys.path untouched
assert sys.path == before_path, f"sys.path mutated: {{sys.path}} != {{before_path}}"

# Assert preloaded foreign modules were not replaced
for name, obj in foreign_objs.items():
    assert sys.modules.get(name) is obj, f"foreign module {{name}} was replaced"

# Assert no bare sibling names were added to sys.modules
for sub in {all_siblings!r}:
    if sub not in foreign_objs:
        assert sub not in sys.modules, f"bare sibling {{sub!r}} leaked into sys.modules"
"""
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_defuzz_place_tool_rejects_trust_and_leaves_db_unchanged(self) -> None:
        from hermes_plugins.defuzz.placer import inspect_project_trust
        from hermes_plugins.defuzz.safety import SafetyError

        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "untrusted_proj"
            (proj / ".adopt").mkdir(parents=True)
            (proj / ".adopt" / "rules.json").write_text(
                json.dumps({
                    "schema": 1,
                    "schema_version": 1,
                    "project_slug": "untrusted-proj",
                    "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
                    "placement_rules": [
                        {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
                    ],
                    "ignore_patterns": ["node_modules/"],
                    "lfs_patterns": ["*.png"],
                }),
                encoding="utf-8",
            )

            raw_res = plugin_init._handle_defuzz_place_tool({"action": "trust", "project_root": str(proj)})
            parsed = json.loads(raw_res)
            self.assertFalse(parsed["ok"])
            self.assertIn("trust", parsed["error"])

            with self.assertRaises(SafetyError):
                cli_mod.execute_defuzz_place({"action": "trust", "project_root": str(proj)})

            self.assertFalse(state_db_path().exists())
            self.assertFalse(inspect_project_trust(proj)["trusted"])

    def test_cli_trust_requires_tty_and_slug_confirmation(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from hermes_plugins.defuzz.placer import compute_rules_hash, inspect_project_trust

        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "tty_proj"
            (proj / ".adopt").mkdir(parents=True)
            (proj / ".adopt" / "rules.json").write_text(
                json.dumps({
                    "schema": 1,
                    "schema_version": 1,
                    "project_slug": "tty-proj-slug",
                    "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
                    "placement_rules": [
                        {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
                    ],
                    "ignore_patterns": ["node_modules/"],
                    "lfs_patterns": ["*.blend"],
                }),
                encoding="utf-8",
            )
            expected_hash = compute_rules_hash(proj)

            # 1. Refused when stdin is not a TTY
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch.object(sys.stdin, "isatty", return_value=False):
                with redirect_stdout(out_buf), redirect_stderr(err_buf):
                    rc_no_tty = cli_main(["trust", str(proj)])
            self.assertEqual(rc_no_tty, 1)
            self.assertIn("tty", err_buf.getvalue().lower())
            self.assertFalse(state_db_path().exists())
            self.assertFalse(inspect_project_trust(proj)["trusted"])

            # 2. Refused when /dev/tty (or CONIN$) is unavailable
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                with mock.patch.object(cli_mod, "_open_controlling_tty", side_effect=OSError("no controlling tty")):
                    with redirect_stdout(out_buf), redirect_stderr(err_buf):
                        rc_no_dev_tty = cli_main(["trust", str(proj)])
            self.assertEqual(rc_no_dev_tty, 1)
            self.assertIn("terminal", err_buf.getvalue().lower())
            self.assertFalse(state_db_path().exists())
            self.assertFalse(inspect_project_trust(proj)["trusted"])

            # 3. Refused when user types wrong slug
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                with mock.patch.object(cli_mod, "_open_controlling_tty", return_value=io.StringIO("wrong-slug\n")):
                    with redirect_stdout(out_buf), redirect_stderr(err_buf):
                        rc_wrong = cli_main(["trust", str(proj)])
            self.assertEqual(rc_wrong, 1)
            printed = out_buf.getvalue()
            self.assertIn(str(proj.resolve()), printed)
            self.assertIn("tty-proj-slug", printed)
            self.assertIn(expected_hash, printed)
            self.assertIn("declared_dirs", printed)
            self.assertIn("placement_rules", printed)
            self.assertIn("ignore_patterns", printed)
            self.assertIn("lfs_patterns", printed)
            self.assertFalse(state_db_path().exists())
            self.assertFalse(inspect_project_trust(proj)["trusted"])

            # 4. Accepted when user types exact project slug
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                with mock.patch.object(cli_mod, "_open_controlling_tty", return_value=io.StringIO("tty-proj-slug\n")):
                    with redirect_stdout(out_buf), redirect_stderr(err_buf):
                        rc_ok = cli_main(["trust", str(proj)])
            self.assertEqual(rc_ok, 0)
            self.assertTrue(inspect_project_trust(proj)["trusted"])

    def test_cli_lint_runs_tools_lock_preflight_and_blocks_with_exit_codes_2_3_4(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from hermes_plugins.defuzz import lint_setup, toolchk

        ready_st = lint_setup.SetupStatus(
            items=[],
            complete=True,
            pending_mb=0,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
            blocked_reason=None,
        )
        ok_lint_res = {
            "ok": True,
            "project": str(self.projects_root),
            "mode": "both",
            "findings": [],
            "tools_run": [],
            "tools_missing": [],
            "warnings": [],
            "error": None,
        }

        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "lint_proj"
            proj.mkdir()
            toolchk.dump_lock(
                proj / "TOOLS.lock",
                {
                    "lock": dict(toolchk.DEFAULT_HEADER),
                    "tools": {
                        "node": {
                            "version": "22.1.0",
                            "chosen": "2026-11-06",
                            "reason": "Pinned for lint gate test.",
                            "probe": "command",
                            "argv": ["node", "--version"],
                            "source": "human",
                        }
                    },
                },
            )

            # 1. Version drift -> exit 2, run_lint not called, preflight.json recorded in .adopt/
            err2 = io.StringIO()
            with (
                mock.patch.object(cli_mod, "status", return_value=ready_st),
                mock.patch.object(cli_mod, "run_lint", return_value=ok_lint_res) as m_lint,
                mock.patch.object(toolchk, "probe", return_value=("23.0.0", "/usr/bin/node")),
                redirect_stderr(err2),
            ):
                rc2 = cli_main(["lint", str(proj)])
                m_lint.assert_not_called()
            self.assertEqual(rc2, 2)
            self.assertIn("preflight BLOCKED", err2.getvalue())
            self.assertTrue((proj / ".adopt" / "preflight.json").is_file())
            rec_data = json.loads((proj / ".adopt" / "preflight.json").read_text(encoding="utf-8"))
            self.assertFalse(rec_data["ok"])

            # 2. Probe failure -> exit 3, run_lint not called
            err3 = io.StringIO()
            with (
                mock.patch.object(cli_mod, "status", return_value=ready_st),
                mock.patch.object(cli_mod, "run_lint", return_value=ok_lint_res) as m_lint,
                mock.patch.object(toolchk, "probe", side_effect=FileNotFoundError("node missing")),
                redirect_stderr(err3),
            ):
                rc3 = cli_main(["lint", str(proj)])
                m_lint.assert_not_called()
            self.assertEqual(rc3, 3)
            self.assertIn("preflight BLOCKED", err3.getvalue())

            # 3. Matching version -> preflight passes, run_lint executes and exits 0
            out0 = io.StringIO()
            err0 = io.StringIO()
            with (
                mock.patch.object(cli_mod, "status", return_value=ready_st),
                mock.patch.object(cli_mod, "run_lint", return_value=ok_lint_res) as m_lint,
                mock.patch.object(toolchk, "probe", return_value=("22.1.0", "/usr/bin/node")),
                redirect_stdout(out0),
                redirect_stderr(err0),
            ):
                rc0 = cli_main(["lint", str(proj)])
                m_lint.assert_called_once_with(str(proj), "both")
            self.assertEqual(rc0, 0)

            # 4. Malformed lock -> exit 4, run_lint not called
            (proj / "TOOLS.lock").write_text("[node]\nversion = '22.1.0'\n", encoding="utf-8")
            err4 = io.StringIO()
            with (
                mock.patch.object(cli_mod, "status", return_value=ready_st),
                mock.patch.object(cli_mod, "run_lint", return_value=ok_lint_res) as m_lint,
                redirect_stderr(err4),
            ):
                rc4 = cli_main(["lint", str(proj)])
                m_lint.assert_not_called()
            self.assertEqual(rc4, 4)
            self.assertIn("missing", err4.getvalue())



if __name__ == "__main__":
    unittest.main()
