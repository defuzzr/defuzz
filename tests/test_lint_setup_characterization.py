"""Characterization tests for lint_setup, setup_manifest and lint_env."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_env, lint_setup, setup_manifest  # noqa: E402
from hermes_plugins.defuzz.setup_manifest import Binary, Download, SetupItem  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestFacadeExports(unittest.TestCase):
    """Verify every public, imported, re-exported, and test-referenced symbol stays present."""

    def test_lint_env_symbols(self) -> None:
        expected = (
            "LINT_ENV_KEYS",
            "INSTALL_ROOT_REL",
            "TIMEOUT_RC",
            "_WINDOWS_SUFFIXES",
            "_hermes_get_real_home",
            "_norm_path",
            "_profile_home_str",
            "real_home",
            "_dedupe_path_entries",
            "managed_install_root",
            "build_env",
            "which",
            "resolve_binaries",
            "_kill_process_group",
            "run",
        )
        for name in expected:
            self.assertTrue(hasattr(lint_env, name), f"lint_env missing {name}")

    def test_setup_manifest_symbols(self) -> None:
        expected = (
            "OFFICIAL_HOSTS",
            "_ALLOWED_PLACEHOLDERS",
            "_HASH_LENGTHS",
            "_HEX_RE",
            "_BRACE_RE",
            "Binary",
            "Download",
            "SetupItem",
            "exe_name",
            "ITEMS",
            "current_platform",
            "downloads_for",
            "total_size_mb",
            "validate",
        )
        for name in expected:
            self.assertTrue(hasattr(setup_manifest, name), f"setup_manifest missing {name}")

    def test_lint_setup_symbols(self) -> None:
        expected = (
            "INSTALL_ROOT_REL",
            "build_env",
            "real_home",
            "run",
            "which",
            "ITEMS",
            "OFFICIAL_HOSTS",
            "Binary",
            "Download",
            "SetupItem",
            "current_platform",
            "exe_name",
            "total_size_mb",
            "WHEEL_PACKAGES",
            "ARM_BINARY_ITEMS",
            "_ARM_BINARY_NAMES",
            "_ARM_WHEEL_KEYS",
            "_hermes_lazy_installs_allowed",
            "_hermes_plugin_data_dir",
            "SetupError",
            "_CancelledError",
            "ItemStatus",
            "SetupStatus",
            "Progress",
            "SetupResult",
            "lazy_installs_allowed",
            "_check_lazy_installs_allowed",
            "_active_items",
            "downloads_for",
            "_get_downloads",
            "install_root",
            "default_cache_dir",
            "_resolve_paths",
            "_assert_managed_path",
            "_remove_managed_path",
            "_migrate_legacy_rustup_bin",
            "_prepare_env",
            "_marker_and_binaries_present",
            "_is_under_managed_dirs",
            "_is_item_present",
            "_missing_wheels",
            "_format_blocked_reason",
            "status",
            "installed_tool_versions",
            "_default_fetch",
            "_verify_checksum",
            "_validate_and_strip_member_path",
            "_extract_tar",
            "_extract_zip",
            "_extract_artifact",
            "_prepare_extracted_binaries",
            "_expose_binaries",
            "_substitute_cmd",
            "_post_install_env",
            "_pid_is_alive",
            "_acquire_setup_lock",
            "run_setup",
            "headless_message",
            "describe_plan",
        )
        for name in expected:
            self.assertTrue(hasattr(lint_setup, name), f"lint_setup missing {name}")


class TestLintEnvCharacterization(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_norm_path_and_dedupe_path_entries(self) -> None:
        self.assertEqual(lint_env._norm_path(None), "")
        self.assertEqual(lint_env._norm_path("   "), "")
        p = str(self.root / "a")
        self.assertEqual(lint_env._norm_path(p), os.path.normcase(os.path.abspath(p)))
        self.assertEqual(
            lint_env._dedupe_path_entries(["", "/a", "/b", "/a", ""]),
            f"/a{os.pathsep}/b",
        )

    def test_profile_home_str_and_managed_install_root(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HERMES_HOME", None)
            self.assertIsNone(lint_env._profile_home_str({}))
        hh = self.root / "hh"
        self.assertEqual(lint_env._profile_home_str({"HERMES_HOME": str(hh)}), str(hh / "home"))

        custom_root = self.root / "custom" / "opt"
        self.assertEqual(
            lint_env.managed_install_root({"DEFUZZ_INSTALL_ROOT": str(custom_root)}),
            custom_root,
        )
        with self.assertRaises(ValueError):
            lint_env.managed_install_root({"DEFUZZ_INSTALL_ROOT": "relative/path"})

    def test_build_env_respects_custom_dotnet_root(self) -> None:
        fake_home = self.root / "home"
        fake_home.mkdir()
        custom_dotnet = self.root / "custom_dotnet"
        custom_dotnet.mkdir()
        env = lint_env.build_env(
            {
                "HOME": str(fake_home),
                "HERMES_REAL_HOME": str(fake_home),
                "DOTNET_ROOT": str(custom_dotnet),
                "PATH": "/usr/bin",
            }
        )
        self.assertEqual(env["DOTNET_ROOT"], str(custom_dotnet))
        self.assertIn(str(custom_dotnet), env["PATH"].split(os.pathsep))

    def test_toolchain_defaults_and_managed_path_dirs_helpers(self) -> None:
        rhome = self.root / "rhome"
        inst = self.root / "inst"
        (inst / "dotnet").mkdir(parents=True)
        env: dict[str, str] = {"CARGO_HOME": "/custom/cargo"}
        lint_env._apply_toolchain_defaults(env, rhome, inst, overwrite=False)
        self.assertEqual(env["CARGO_HOME"], "/custom/cargo")
        self.assertEqual(env["RUSTUP_HOME"], str(rhome / ".rustup"))
        self.assertEqual(env["GOPATH"], str(rhome / "go"))
        self.assertEqual(env["DOTNET_ROOT"], str(inst / "dotnet"))

        lint_env._apply_toolchain_defaults(env, rhome, inst, overwrite=True)
        self.assertEqual(env["CARGO_HOME"], str(rhome / ".cargo"))

        dirs = lint_env._managed_path_dirs(inst, rhome, env)
        self.assertEqual(dirs[0], inst / "bin")
        self.assertEqual(dirs[1], rhome / ".cargo" / "bin")
        self.assertIsNone(lint_env._resolve_side_python_bin({}))


class TestSetupManifestCharacterization(unittest.TestCase):
    def test_manifest_items_exact_snapshot(self) -> None:
        expected_Snapshot = [
            (
                "rust",
                "sdk",
                "1.97.1",
                650,
                ("cargo", "rustc", "rustdoc", "rustfmt", "cargo-fmt", "cargo-clippy", "clippy-driver"),
            ),
            ("go", "sdk", "1.27.3", 350, ("go", "gofmt")),
            ("dotnet", "sdk", "10.0.404", 450, ("dotnet", "csharpier")),
            ("pwsh", "sdk", "7.6.9", 200, ("pwsh",)),
            ("golangci-lint", "binary", "2.15.0", 35, ("golangci-lint",)),
            ("biome", "binary", "2.6.6", 28, ("biome",)),
            ("oxlint", "binary", "1.92.0", 18, ("oxlint",)),
            ("stylua", "binary", "2.6.0", 6, ("stylua",)),
            ("selene", "binary", "0.32.0", 8, ("selene",)),
            ("glslang", "binary", "16.6.0", 5, ("glslangValidator",)),
            ("dxc", "binary", "1.9.2609", 45, ("dxc",)),
        ]
        actual = [
            (it.name, it.kind, it.version, it.size_mb, it.provides)
            for it in setup_manifest.ITEMS
        ]
        self.assertEqual(actual, expected_Snapshot)
        self.assertEqual(setup_manifest.validate(), [])
        total_downloads = sum(len(it.downloads) for it in setup_manifest.ITEMS)
        self.assertEqual(total_downloads, 49)

    def test_manifest_builder_and_validation_helpers(self) -> None:
        dl = setup_manifest._dl(
            "https://github.com/org/repo/releases/download/v1.0/tool.tar.gz",
            "a" * 64,
            "tar.gz",
            ("bin/tool", "tool"),
            strip=1,
        )
        self.assertEqual(
            dl,
            Download(
                url="https://github.com/org/repo/releases/download/v1.0/tool.tar.gz",
                hash="a" * 64,
                hash_algo="sha256",
                hash_source="published",
                archive="tar.gz",
                strip_components=1,
                binaries=(Binary(path="bin/tool", name="tool"),),
                chmod=True,
            ),
        )
        label, probs = setup_manifest._validate_platform_key("tool", ("linux", "x86_64"))
        self.assertEqual(label, "tool[linux/x86_64]")
        self.assertEqual(probs, [])
        self.assertEqual(setup_manifest._validate_post_install("tool", (("{install_dir}/tool",),)), [])

    def test_validate_additional_edge_cases(self) -> None:
        valid_dl = Download(
            url="https://github.com/org/repo/releases/download/v1.0.0/tool.tar.gz",
            hash="a" * 64,
            hash_algo="sha256",
            hash_source="published",
            archive="tar.gz",
            strip_components=0,
            binaries=(Binary(path="tool", name="tool"),),
        )
        bad_dl = Download(
            url="https://github.com/org/repo/releases/download/v1.0.0/tool.tar.gz",
            hash="a" * 64,
            hash_algo="sha256",
            hash_source="untrusted",
            archive="rar",
            strip_components=-1,
            binaries=(),
            chmod="yes",  # type: ignore[arg-type]
        )
        bad_item = SetupItem(
            name="",
            kind="unknown",
            version="1.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("tool",),
            skip_if_on_path=(),
            downloads={("linux", "x86_64"): bad_dl},
            post_install=((),),
        )
        with mock.patch.object(setup_manifest, "ITEMS", (bad_item,)):
            problems = "\n".join(setup_manifest.validate())
            self.assertIn("item with empty name", problems)
            self.assertIn("invalid kind", problems)
            self.assertIn("empty skip_if_on_path", problems)
            self.assertIn("invalid hash_source", problems)
            self.assertIn("invalid archive", problems)
            self.assertIn("negative strip_components", problems)
            self.assertIn("non-bool chmod", problems)
            self.assertIn("empty binaries", problems)
            self.assertIn("empty command in post_install", problems)

        # SDK with binary name outside provides
        sdk_bad_bin = SetupItem(
            name="mysdk",
            kind="sdk",
            version="1.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("sdk-a",),
            skip_if_on_path=("sdk-a",),
            downloads={
                ("linux", "x86_64"): Download(
                    url=valid_dl.url,
                    hash=valid_dl.hash,
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    binaries=(Binary(path="", name=""), Binary(path="sdk-b", name="sdk-b")),
                )
            },
        )
        with mock.patch.object(setup_manifest, "ITEMS", (sdk_bad_bin,)):
            problems2 = "\n".join(setup_manifest.validate())
            self.assertIn("invalid binary entry", problems2)
            self.assertIn("not in provides", problems2)
            self.assertIn("not a subset of provides", problems2)

    def test_validate_evaluates_provides_set_before_downloads(self) -> None:
        base_item = setup_manifest.ITEMS[0]
        for bad_provides in (None, ([],)):
            with self.subTest(bad_provides=bad_provides):
                item_no_dl = SetupItem(
                    name=base_item.name,
                    kind=base_item.kind,
                    version=base_item.version,
                    homepage=base_item.homepage,
                    size_mb=base_item.size_mb,
                    provides=bad_provides,  # type: ignore[arg-type]
                    skip_if_on_path=base_item.skip_if_on_path,
                    downloads={},
                    post_install=base_item.post_install,
                )
                with mock.patch.object(setup_manifest, "ITEMS", (item_no_dl,)):
                    with self.assertRaises(TypeError):
                        setup_manifest.validate()


class TestLintSetupCharacterization(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.inst_root = self.root / "opt" / "defuzz"
        self.bin_dir = self.inst_root / "bin"
        self.cache_dir = self.root / "cache" / "downloads"
        self.fake_home = self.root / "user_home"
        self.fake_home.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_arm_binary_items_snapshot(self) -> None:
        arm_names = [(it.name, it.version, it.kind) for it in lint_setup.ARM_BINARY_ITEMS]
        self.assertEqual(
            arm_names,
            [("taplo", "0.9.3", "binary"), ("shellcheck", "0.11.0", "binary")],
        )
        active_arm = lint_setup._active_items(None, plat=("linux", "aarch64"))
        self.assertEqual(
            [it.name for it in active_arm[-2:]],
            ["taplo", "shellcheck"],
        )
        active_x64 = lint_setup._active_items(None, plat=("linux", "x86_64"))
        self.assertNotIn("taplo", [it.name for it in active_x64])

    def test_verify_checksum_errors(self) -> None:
        missing = self.root / "missing.bin"
        with self.assertRaises(lint_setup.SetupError):
            lint_setup._verify_checksum(
                missing,
                url="https://github.com/x",
                expected_hash="0" * 64,
                hash_algo="sha256",
                cancel=None,
            )
        f = self.root / "file.bin"
        f.write_bytes(b"hello")
        with self.assertRaises(lint_setup.SetupError):
            lint_setup._verify_checksum(
                f,
                url="https://github.com/x",
                expected_hash="0" * 64,
                hash_algo="invalid_algo_xyz",
                cancel=None,
            )
        self.assertFalse(f.exists())

    def test_pid_is_alive_cases(self) -> None:
        self.assertFalse(lint_setup._pid_is_alive(0))
        self.assertFalse(lint_setup._pid_is_alive(-5))
        self.assertTrue(lint_setup._pid_is_alive(os.getpid()))
        self.assertFalse(lint_setup._pid_is_alive(99999999))

    def test_lint_setup_internal_helpers(self) -> None:
        for helper, expected in (
            (None, True),
            (False, False),
            (True, True),
            (0, True),
            (1, True),
            ("", True),
            ("no", True),
            (lambda: 0, False),
            (lambda: 1, True),
            (lambda: (_ for _ in ()).throw(RuntimeError("err")), True),
        ):
            with self.subTest(helper=helper):
                with mock.patch.object(lint_setup, "_hermes_lazy_installs_allowed", helper):
                    self.assertIs(lint_setup.lazy_installs_allowed(), expected)

        for seam, expected in (
            (None, False),
            (False, False),
            (True, True),
            (0, False),
            (1, True),
            ("", False),
            ("no", True),
            (lambda: False, False),
            (lambda: True, True),
            (lambda: (_ for _ in ()).throw(RuntimeError("err")), True),
        ):
            with self.subTest(seam=seam):
                with mock.patch.object(lint_setup, "lazy_installs_allowed", seam):
                    self.assertIs(lint_setup._check_lazy_installs_allowed(), expected)

        self.assertTrue(
            lint_setup._path_within_any([self.inst_root / "bin"], [self.inst_root])
        )
        self.assertFalse(
            lint_setup._path_within_any([self.fake_home / "bin"], [self.inst_root])
        )
        pins, err = lint_setup._read_wheel_pins()
        self.assertIsNone(err)
        self.assertEqual(pins.get("ruff"), "0.15.22")


if __name__ == "__main__":
    unittest.main()
