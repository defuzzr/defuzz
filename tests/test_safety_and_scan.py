"""Unit tests for safety.py and scanner.py."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.safety import (  # noqa: E402
    SafetyError,
    assert_disjoint_roots,
    assert_not_live_hermes,
    copy_tree_nofollow,
    run_git_hardened,
    safe_write_text,
)
from hermes_plugins.defuzz.scanner import UnsupportedGitLayoutError, scan_folder  # noqa: E402


class TestSafetyAndScan(unittest.TestCase):
    def test_disjoint_roots_refuses_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "project"
            sub = src / "nested"
            src.mkdir()
            sub.mkdir()
            with self.assertRaises(SafetyError):
                assert_disjoint_roots(source=src, output=src)
            with self.assertRaises(SafetyError):
                assert_disjoint_roots(source=src, output=sub)
            with self.assertRaises(SafetyError):
                assert_disjoint_roots(source=sub, staging=src)

    def test_refuses_live_hermes_profile(self) -> None:
        live_cfg = os.path.expanduser("~/.hermes/config.yaml")
        with self.assertRaises(SafetyError):
            assert_not_live_hermes(live_cfg)

    def test_refuses_custom_env_and_context_override_hermes_homes(self) -> None:
        from unittest import mock
        from hermes_plugins.defuzz.safety import resolve_hermes_home

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            env_home = base / "custom_env_home"
            explicit_home = base / "explicit_protected_home"
            fake_ctx_home = base / "invented_ctx_home"
            safe_dir = base / "safe_project"
            for d in (env_home, explicit_home, fake_ctx_home, safe_dir):
                d.mkdir(parents=True)

            # 1. Custom HERMES_HOME env is protected (except its cache/scratch)
            with mock.patch.dict(os.environ, {"HERMES_HOME": str(env_home)}):
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(env_home / "config.yaml")
                with self.assertRaises(SafetyError):
                    safe_write_text(env_home, "pwn.txt", "nope")
                # Scratch inside custom HERMES_HOME is allowed
                assert_not_live_hermes(env_home / "cache" / "scratch" / "probe.txt")
                # Default ~/.hermes is still protected even when HERMES_HOME points elsewhere
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(os.path.expanduser("~/.hermes/config.yaml"))

                # 2. Invented ctx.home_path / ctx.hermes_home / ctx._manager probes are NOT used
                class _InventedMgr:
                    home_path = fake_ctx_home

                class _InventedCtx:
                    home_path = fake_ctx_home
                    hermes_home = fake_ctx_home
                    _manager = _InventedMgr()

                self.assertEqual(resolve_hermes_home(ctx=_InventedCtx()), env_home)

                # 3. Explicit protected_roots ADDS to default protected set rather than replacing it;
                # empty list must not unprotect the live home.
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(explicit_home / "secret.txt", protected_roots=[explicit_home])
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(env_home / "config.yaml", protected_roots=[explicit_home])
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(os.path.expanduser("~/.hermes/config.yaml"), protected_roots=[explicit_home])
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(env_home / "config.yaml", protected_roots=[])
                with self.assertRaises(SafetyError):
                    assert_not_live_hermes(os.path.expanduser("~/.hermes/config.yaml"), protected_roots=[])
                assert_not_live_hermes(safe_dir / "file.txt", protected_roots=[explicit_home])

    def test_isolated_profile_home_is_protected(self) -> None:
        from hermes_plugins.defuzz.safety import resolve_hermes_home
        routed_home = Path(os.environ["HERMES_HOME"])
        self.assertEqual(resolve_hermes_home(), routed_home)
        with self.assertRaises(SafetyError):
            assert_not_live_hermes(routed_home / "state.db")
        assert_not_live_hermes(routed_home / "cache" / "scratch" / "ok.txt")

    def test_nofollow_write_refuses_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "copy"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            os.symlink(str(outside), str(root / "escape_dir"))
            with self.assertRaises(SafetyError):
                safe_write_text(root, "escape_dir/pwn.txt", "nope")
            self.assertFalse((outside / "pwn.txt").exists())

    def test_refuses_worktree_gitfile_submodule_and_alternates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)

            # 1. Worktree gitfile (.git is a file)
            wt_dir = base / "wt_case"
            wt_dir.mkdir()
            (wt_dir / ".git").write_text("gitdir: /some/other/.git/worktrees/wt\n", encoding="utf-8")
            with self.assertRaises(UnsupportedGitLayoutError) as ctx1:
                scan_folder(wt_dir)
            self.assertEqual(ctx1.exception.reasons[0]["kind"], "worktree_gitfile")

            # 2. Submodule (.gitmodules present)
            sub_dir = base / "sub_case"
            sub_dir.mkdir()
            (sub_dir / ".gitmodules").write_text('[submodule "foo"]\n', encoding="utf-8")
            with self.assertRaises(UnsupportedGitLayoutError) as ctx2:
                scan_folder(sub_dir)
            self.assertEqual(ctx2.exception.reasons[0]["kind"], "submodule")

            # 3. Git alternates (.git/objects/info/alternates non-empty)
            alt_dir = base / "alt_case"
            alt_Info = alt_dir / ".git" / "objects" / "info"
            alt_Info.mkdir(parents=True)
            (alt_Info / "alternates").write_text("/shared/objects\n", encoding="utf-8")
            with self.assertRaises(UnsupportedGitLayoutError) as ctx3:
                scan_folder(alt_dir)
            self.assertEqual(ctx3.exception.reasons[0]["kind"], "git_alternates")

    def test_scan_collapses_untracked_junk_preserves_mixed_dist_and_classifies_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            src = base / "src_repo"
            copy_dir = base / "copy_repo"
            staging = base / "staging"
            src.mkdir()
            staging.mkdir()

            run_git_hardened(src, ["init", "-b", "main"], allow_literal_pathspecs=False)
            run_git_hardened(src, ["config", "user.name", "Test"], allow_literal_pathspecs=False)
            run_git_hardened(src, ["config", "user.email", "t@example.com"], allow_literal_pathspecs=False)

            # Untracked node_modules -> collapsed as junk_dir
            nm = src / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

            # Mixed dist/ directory: tracked icon.svg + untracked bundle.js -> NOT collapsed as junk
            dist_dir = src / "dist"
            dist_dir.mkdir()
            (dist_dir / "icon.svg").write_text("<svg></svg>\n", encoding="utf-8")
            (dist_dir / "bundle.js").write_text("console.log(1);\n", encoding="utf-8")
            run_git_hardened(src, ["add", "--", "dist/icon.svg"])
            run_git_hardened(src, ["commit", "-m", "init"], allow_literal_pathspecs=False)

            # Secret file (constructed dynamically so static scanners see no literal token)
            fake_tok = "sk-" + ("A1b2C3d4" * 4)
            (src / ".env").write_text(f"OPENAI_API_KEY={fake_tok}\n", encoding="utf-8")

            # Symlinks: internal-relative, internal-absolute, external
            os.symlink("dist/icon.svg", str(src / "rel_link.svg"))
            os.symlink(str(src / "dist" / "icon.svg"), str(src / "abs_link.svg"))
            os.symlink(str(base), str(src / "ext_link"))

            copy_tree_nofollow(src, copy_dir, staging_root=staging)
            inv_path = staging / "inventory.json"
            inv = scan_folder(copy_dir, source_root=src, out_path=inv_path)

            self.assertTrue(inv_path.is_file())
            raw_inv_text = inv_path.read_text(encoding="utf-8")
            # Raw secret must NEVER appear anywhere in inventory.json
            self.assertNotIn(fake_tok, raw_inv_text)
            self.assertEqual(len(inv["secrets_flagged"]), 1)
            self.assertEqual(inv["secrets_flagged"][0]["placeholder"], "<secret-1>")
            self.assertEqual(inv["secrets_flagged"][0]["git_policy"], "ignore")

            # node_modules collapsed; dist recorded as mixed_cache_dir
            self.assertEqual([j["path"] for j in inv["junk_dirs"]], ["node_modules"])
            self.assertEqual([m["path"] for m in inv["mixed_cache_dirs"]], ["dist"])

            link_map = {ln["path"]: ln["link_class"] for ln in inv["links"]}
            self.assertEqual(link_map["rel_link.svg"], "internal-relative")
            self.assertEqual(link_map["abs_link.svg"], "internal-absolute")
            self.assertEqual(link_map["ext_link"], "external")


if __name__ == "__main__":
    unittest.main()
