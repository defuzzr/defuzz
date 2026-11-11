"""Characterization tests for cli, scanner, placer and applier."""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import applier, cli, componentize_bridge, placer, scanner  # noqa: E402
from hermes_plugins.defuzz.rules import build_deterministic_fallback_rules  # noqa: E402
from hermes_plugins.defuzz.safety import SafetyError, copy_tree_nofollow, run_git_hardened  # noqa: E402


class TestCliScannerPlacerCharacterization(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.hermes_home = self.base / "hermes_home"
        self.projects_root = self.base / "projects_root"
        self.tmp_dir = self.base / "tmpdir"
        self.hermes_home.mkdir(parents=True, exist_ok=True)
        self.projects_root.mkdir(parents=True, exist_ok=True)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
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
        self._tmp.cleanup()

    def test_module_facade_exports_and_monkeypatch_seams_present(self) -> None:
        for attr in (
            "REGISTER_PROJECT",
            "_default_inventory_out",
            "execute_defuzz_project",
            "execute_defuzz_place",
            "setup_defuzz_cli",
            "_print_proposal_dry_run",
            "_handle_templates_subcommand",
            "_handle_new_subcommand",
            "_open_controlling_tty",
            "_handle_trust_subcommand",
            "_handle_lint_subcommand",
            "_handle_setup_tools_subcommand",
            "_extract_tool_and_dir",
            "_handle_tools_subcommand",
            "handle_defuzz_cli",
            "main",
            "status",
            "run_lint",
            "run_setup",
            "describe_plan",
            "headless_message",
            "propose",
            "accept",
            "discard",
            "run_new_project_flow",
            "load_templates",
            "run_questionnaire",
        ):
            self.assertTrue(hasattr(cli, attr), f"cli missing {attr}")

        for attr in (
            "UnsupportedGitLayoutError",
            "JUNK_DIR_NAMES",
            "SPECIAL_TOP_DIRS",
            "LFS_EXTENSIONS",
            "SECRET_FILENAME_EXACT",
            "SECRET_FILENAME_SAFE_SUFFIXES",
            "SECRET_EXTENSIONS",
            "_SECRET_CONTENT_PATTERNS",
            "_PLAN_DOC_RE",
            "_is_secret_filename",
            "_sniff_file_for_secrets",
            "_sha256_nofollow",
            "_collapse_junk_dir_stats",
            "classify_symlink",
            "inspect_git_layout",
            "scan_folder",
        ):
            self.assertTrue(hasattr(scanner, attr), f"scanner missing {attr}")

        for attr in (
            "EXEMPT_TOP_DIRS",
            "_PENDING_NOTES_LOCK",
            "_RULES_MUTATION_LOCK",
            "_PENDING_NOTES",
            "_LAST_HOOK_SKIP_REASON",
            "get_last_hook_skip_reason",
            "find_adopted_root",
            "_is_valid_adopted_rules",
            "_read_rules_bytes_nofollow",
            "_parse_rules_bytes",
            "compute_rules_hash",
            "_inspect_and_load_project_trust",
            "inspect_project_trust",
            "trust_project",
            "_require_registered_project",
            "load_project_rules",
            "_load_place_log",
            "_append_place_log",
            "_declared_dir_prefixes",
            "resolve_placement_for_new_path",
            "_write_succeeded",
            "on_pre_tool_call",
            "on_transform_tool_result",
            "place_existing_files",
            "sweep_inbox",
            "add_placement_rule",
            "undo_placements",
        ):
            self.assertTrue(hasattr(placer, attr), f"placer missing {attr}")

        for attr in (
            "_merge_lines_preserving_existing",
            "_read_existing_nofollow",
            "_move_special_runtime_dirs",
            "_rewrite_internal_symlinks",
            "apply_rules_to_copy",
            "run_git_hardened",
            "write_agents_md",
        ):
            self.assertTrue(hasattr(applier, attr), f"applier missing {attr}")

    def test_scanner_helpers_and_scan_folder_characterization(self) -> None:
        self.assertTrue(scanner._is_secret_filename(".env"))
        self.assertTrue(scanner._is_secret_filename("sub/.env.local"))
        self.assertTrue(scanner._is_secret_filename("keys/server.pem"))
        self.assertFalse(scanner._is_secret_filename(".env.example"))
        self.assertFalse(scanner._is_secret_filename(".env.local.template"))
        self.assertFalse(scanner._is_secret_filename("README.md"))

        src = self.base / "scan_src"
        copy_dir = self.base / "scan_copy"
        staging = self.base / "scan_staging"
        src.mkdir()
        staging.mkdir()

        # Populate special dirs (.hermes/plans vs .hermes/scratch), empty dir, duplicate files, plan doc, LFS ext
        (src / ".hermes" / "plans").mkdir(parents=True)
        (src / ".hermes" / "plans" / "roadmap.md").write_text("# Plan\n", encoding="utf-8")
        (src / ".hermes" / "scratch").mkdir(parents=True)
        (src / ".hermes" / "scratch" / "dump.txt").write_text("scratch\n", encoding="utf-8")
        (src / "empty_subdir").mkdir()
        (src / "dup_a.txt").write_text("identical content\n", encoding="utf-8")
        (src / "dup_b.txt").write_text("identical content\n", encoding="utf-8")
        (src / "model.glb").write_bytes(b"glTF" + b"\x00" * 32)

        copy_tree_nofollow(src, copy_dir, staging_root=staging)
        inv = scanner.scan_folder(copy_dir, source_root=src)

        self.assertEqual(inv["empty_dirs"], ["empty_subdir"])
        self.assertEqual(len(inv["duplicate_hashes"]), 1)
        self.assertEqual(inv["duplicate_hashes"][0]["paths"], ["dup_a.txt", "dup_b.txt"])
        self.assertIn(".hermes/plans/roadmap.md", inv["plan_docs"])
        self.assertEqual([c["path"] for c in inv["lfs_candidates"]], ["model.glb"])
        sp_kinds = {sp["path"]: sp["kind"] for sp in inv["special_paths"]}
        self.assertEqual(sp_kinds[".hermes/plans"], "hermes_plans")
        self.assertEqual(sp_kinds[".hermes/scratch"], "hermes_runtime")

    def test_placer_trust_states_and_placement_resolution(self) -> None:
        proj = self.base / "place_proj"
        proj.mkdir()

        # 1. Missing .adopt/rules.json
        t_missing = placer.inspect_project_trust(proj)
        self.assertFalse(t_missing["trusted"])
        self.assertIsNone(t_missing["rules_hash"])

        # 2. Invalid rules.json
        (proj / ".adopt").mkdir()
        (proj / ".adopt" / "rules.json").write_text('{"schema": 999}\n', encoding="utf-8")
        t_invalid = placer.inspect_project_trust(proj)
        self.assertFalse(t_invalid["trusted"])
        self.assertIn("invalid .adopt/rules.json", t_invalid["reason"])

        # 3. Valid rules.json, state DB absent -> untrusted with actual rules_hash populated
        valid_rules = {
            "schema": 1,
            "schema_version": 1,
            "project_slug": "place-proj",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
            "placement_rules": [
                {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
            ],
        }
        (proj / ".adopt" / "rules.json").write_text(json.dumps(valid_rules), encoding="utf-8")
        t_nodb = placer.inspect_project_trust(proj)
        self.assertFalse(t_nodb["trusted"])
        self.assertIsNotNone(t_nodb["rules_hash"])
        self.assertIn("state DB does not exist", t_nodb["reason"])

        # 4. Trust project -> trusted
        trust_res = placer.trust_project(proj)
        self.assertTrue(trust_res["trusted"])
        self.assertEqual(placer.inspect_project_trust(proj)["status"], "trusted")

        # 5. Placement resolution checks
        self.assertIsNone(placer.resolve_placement_for_new_path(proj, "README.md", valid_rules))
        self.assertIsNone(placer.resolve_placement_for_new_path(proj, ".hidden", valid_rules))
        self.assertIsNone(placer.resolve_placement_for_new_path(proj, "src/code.py", valid_rules))
        self.assertIsNone(placer.resolve_placement_for_new_path(proj, "docs/guide.md", valid_rules))

        dec_md = placer.resolve_placement_for_new_path(proj, "_inbox/sub/note.md", valid_rules)
        assert dec_md is not None
        self.assertEqual(dec_md["placed_rel"], "docs/sub/note.md")

        dec_unk = placer.resolve_placement_for_new_path(proj, "loose.unknown", valid_rules)
        assert dec_unk is not None
        self.assertEqual(dec_unk["placed_rel"], "_inbox/loose.unknown")

    def test_applier_helpers_and_cli_project_dispatcher(self) -> None:
        merged = applier._merge_lines_preserving_existing("a\n# comment\nb\n", ["b", "c"], "header")
        self.assertEqual(merged, "a\n# comment\nb\n# header\nc\n")
        unchanged = applier._merge_lines_preserving_existing("a\nb", ["a"], "header")
        self.assertEqual(unchanged, "a\nb\n")

        src = self.base / "cli_src"
        copy_dir = self.base / "cli_copy"
        staging = self.base / "cli_staging"
        src.mkdir()
        staging.mkdir()
        (src / "README.md").write_text("# CLI Test\n", encoding="utf-8")
        for i in range(6):
            (src / f"n{i}.md").write_text(f"# Note {i}\n", encoding="utf-8")

        scan_res = cli.execute_defuzz_project(
            {
                "action": "scan",
                "source_path": str(src),
                "copy_path": str(copy_dir),
                "staging_path": str(staging),
            }
        )
        self.assertTrue(scan_res["ok"])
        self.assertEqual(scan_res["action"], "scan")

        prop_res = cli.execute_defuzz_project(
            {
                "action": "propose_rules",
                "source_path": str(src),
                "copy_path": str(copy_dir),
                "staging_path": str(staging),
                "use_fallback_rules": True,
            }
        )
        self.assertTrue(prop_res["ok"])
        self.assertTrue(Path(prop_res["rules_path"]).is_file())

        apply_res = cli.execute_defuzz_project(
            {
                "action": "apply",
                "source_path": str(src),
                "copy_path": str(copy_dir),
                "staging_path": str(staging),
            }
        )
        self.assertTrue(apply_res["ok"])
        self.assertEqual(apply_res["report"]["counts"]["moved"], 6)

        rep_res = cli.execute_defuzz_project({"action": "report", "copy_path": str(copy_dir)})
        self.assertTrue(rep_res["ok"])
        self.assertEqual(rep_res["report"]["adopted_commit_sha"], apply_res["report"]["adopted_commit_sha"])

    def test_cli_lint_and_tools_formatting_and_argument_extraction(self) -> None:
        ns_pos = argparse.Namespace(args=["ruff", str(self.projects_root)], dir=None)
        tool_name, proj_root = cli._extract_tool_and_dir(ns_pos)
        self.assertEqual(tool_name, "ruff")
        # An explicit folder is kept as written (lexical), not resolved through links.
        self.assertEqual(proj_root, Path(os.path.abspath(self.projects_root)))

        with self.assertRaises(ValueError):
            cli._extract_tool_and_dir(argparse.Namespace(args=["a", "b", "c"], dir=None))

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        fake_res = {
            "ok": True,
            "skipped_generated": ["gen/pb.py"],
            "findings": [
                {
                    "severity": "warning",
                    "tool": "ruff",
                    "file": "src/a.py",
                    "line": 12,
                    "rule": "E501",
                    "message": "line too long",
                }
            ],
            "warnings": ["minor tool notice"],
        }
        with (
            mock.patch.object(cli, "run_lint", return_value=fake_res),
            redirect_stdout(out_buf),
            redirect_stderr(err_buf),
        ):
            rc = cli._handle_lint_subcommand(
                argparse.Namespace(project=str(self.projects_root), mode="both", as_json=False)
            )
        self.assertEqual(rc, 0)
        self.assertIn("Skipped generated: gen/pb.py", out_buf.getvalue())
        self.assertIn("src/a.py:12", out_buf.getvalue())
        self.assertIn("warning: minor tool notice", err_buf.getvalue())

    def test_applier_agents_md_readability_checkpoint_before_tool_seeding(self) -> None:
        for mode, expected_exc in (
            ("missing", FileNotFoundError),
            ("invalid_utf8", UnicodeDecodeError),
        ):
            with self.subTest(mode=mode):
                src = self.base / f"chk_src_{mode}"
                copy_dir = self.base / f"chk_copy_{mode}"
                staging = self.base / f"chk_staging_{mode}"
                src.mkdir()
                staging.mkdir()
                (src / "README.md").write_text("# Checkpoint Test\n", encoding="utf-8")

                copy_tree_nofollow(src, copy_dir, staging_root=staging)
                inv = scanner.scan_folder(copy_dir, source_root=src)
                rules = build_deterministic_fallback_rules(inv)

                real_write_agents_md = applier.write_agents_md

                def _corrupt_write_agents_md(root: Path, *args: object, **kwargs: object) -> dict[str, object]:
                    res = real_write_agents_md(root, *args, **kwargs)
                    agents_path = Path(root) / "AGENTS.md"
                    if mode == "missing":
                        agents_path.unlink()
                    else:
                        agents_path.write_bytes(b"\xff")
                    return res

                with (
                    mock.patch.object(applier, "write_agents_md", side_effect=_corrupt_write_agents_md),
                    mock.patch.object(componentize_bridge, "survey_after_apply") as mock_survey,
                ):
                    with self.assertRaises(expected_exc):
                        applier.apply_rules_to_copy(
                            copy_dir,
                            inv,
                            rules,
                            source_root=src,
                            staging_root=staging,
                        )
                    mock_survey.assert_not_called()

                self.assertFalse((copy_dir / "TOOLS.lock").exists())
                self.assertFalse((copy_dir / "_inbox" / ".gitkeep").exists())


if __name__ == "__main__":
    unittest.main()
