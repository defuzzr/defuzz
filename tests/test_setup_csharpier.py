"""Tests for provisioning csharpier when a system dotnet exists on PATH."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_setup, setup_manifest  # noqa: E402
from hermes_plugins.defuzz.lint_setup import (  # noqa: E402
    Progress,
    describe_plan,
    headless_message,
    run_setup,
    status,
)
from hermes_plugins.defuzz.setup_manifest import Binary, Download, SetupItem  # noqa: E402


def _make_tar_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class TestSetupCsharpier(unittest.TestCase):
    """Verify dotnet / csharpier provisioning across system-dotnet, both-present, and neither-present states."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name).resolve()  # the installer refuses a linked ancestor: use the real temp path
        self.inst_root = self.tmp_root / "opt" / "defuzz"
        self.bin_dir = self.inst_root / "bin"
        self.cache_dir = self.tmp_root / "plugin-data" / "defuzz" / "downloads"
        self.fake_home = self.tmp_root / "user_home"
        self.fake_home.mkdir(parents=True, exist_ok=True)
        self.ext_bin = self.tmp_root / "ext_bin"
        self.ext_bin.mkdir(parents=True, exist_ok=True)
        self.fixtures_dir = self.tmp_root / "fixtures"
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)
        self.plat = ("linux", "x86_64")

        self.dotnet_tar_bytes = _make_tar_bytes(
            {
                "dotnet": (
                    f"#!{sys.executable}\n"
                    "import pathlib, sys\n"
                    "args = sys.argv[1:]\n"
                    "if args[:3] == ['tool', 'install', 'csharpier']:\n"
                    "    tp = args[args.index('--tool-path') + 1]\n"
                    "    d = pathlib.Path(tp)\n"
                    "    d.mkdir(parents=True, exist_ok=True)\n"
                    "    c = d / 'csharpier'\n"
                    "    c.write_text('#!/bin/sh\\necho 1.3.0\\n')\n"
                    "    c.chmod(0o755)\n"
                ).encode("utf-8"),
            }
        )
        self.dotnet_tar_path = self.fixtures_dir / "dotnet-sdk.tar.gz"
        self.dotnet_tar_path.write_bytes(self.dotnet_tar_bytes)
        self.dotnet_tar_hash = hashlib.sha512(self.dotnet_tar_bytes).hexdigest()
        self.dotnet_url = "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-linux-x64.tar.gz"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("csharpier.nuspec", "<package/>")
            zf.writestr("tools/net10.0/any/DotnetToolSettings.xml", "<DotNetCliTool/>")
        self.nupkg_bytes = buf.getvalue()
        self.nupkg_hash = hashlib.sha512(self.nupkg_bytes).hexdigest()

        real_dotnet = next(it for it in setup_manifest.ITEMS if it.name == "dotnet")
        self.dotnet_item = SetupItem(
            name=real_dotnet.name,
            kind=real_dotnet.kind,
            version=real_dotnet.version,
            homepage=real_dotnet.homepage,
            size_mb=real_dotnet.size_mb,
            provides=real_dotnet.provides,
            skip_if_on_path=real_dotnet.skip_if_on_path,
            downloads={
                self.plat: Download(
                    url=self.dotnet_url,
                    hash=self.dotnet_tar_hash,
                    hash_algo="sha512",
                    hash_source="published",
                    archive="tar.gz",
                    strip_components=0,
                    binaries=(Binary(path="dotnet", name="dotnet"),),
                ),
            },
            post_install=real_dotnet.post_install,
            packages=(dataclasses.replace(setup_manifest.CSHARPIER, hash=self.nupkg_hash),),
        )

        # The csharpier .nupkg is served from a local fixture; its checksum check stays real.
        real_fetch_packages = lint_setup._fetch_verified_packages
        self.package_urls: list[str] = []

        def _fetch_packages(item, *, fetcher, **kwargs):
            def _serve(url, dest, cb):
                if url == setup_manifest.CSHARPIER.url:
                    self.package_urls.append(url)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(self.nupkg_bytes)
                    return None
                return fetcher(url, dest, cb)

            return real_fetch_packages(item, fetcher=_serve, **kwargs)

        patcher = mock.patch.object(lint_setup, "_fetch_verified_packages", side_effect=_fetch_packages)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_fake_system_dotnet(self, log_file: Path, *, exit_code: int = 0) -> Path:
        exe = self.ext_bin / "dotnet"
        script = (
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            f"log_path = pathlib.Path({str(log_file)!r})\n"
            "args = sys.argv[1:]\n"
            "entry = {'argv': sys.argv, 'args': args, 'dotnet_root': os.environ.get('DOTNET_ROOT')}\n"
            "prev = json.loads(log_path.read_text()) if log_path.exists() else []\n"
            "prev.append(entry)\n"
            "log_path.write_text(json.dumps(prev))\n"
            f"if {exit_code} != 0:\n"
            f"    sys.stderr.write('simulated dotnet tool failure\\n')\n"
            f"    raise SystemExit({exit_code})\n"
            "if args[:3] == ['tool', 'install', 'csharpier'] and '--tool-path' in args:\n"
            "    tp = pathlib.Path(args[args.index('--tool-path') + 1])\n"
            "    store_dir = tp / '.store' / 'csharpier' / '1.3.0'\n"
            "    store_dir.mkdir(parents=True, exist_ok=True)\n"
            "    (store_dir / 'CSharpier.dll').write_text('csharpier-1.3.0-payload\\n')\n"
            "    out = tp / 'csharpier'\n"
            "    out.write_text('#!/bin/sh\\necho 1.3.0\\n')\n"
            "    out.chmod(0o755)\n"
        )
        exe.write_text(script, encoding="utf-8")
        exe.chmod(0o755)
        return exe

    def _write_fake_csharpier(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / "csharpier"
        exe.write_text("#!/bin/sh\necho 1.3.0\n", encoding="utf-8")
        exe.chmod(0o755)
        return exe

    def test_manifest_dotnet_skip_if_on_path_requires_csharpier(self) -> None:
        dotnet = next(it for it in setup_manifest.ITEMS if it.name == "dotnet")
        self.assertEqual(dotnet.provides, ("dotnet", "csharpier"))
        self.assertIn("dotnet", dotnet.skip_if_on_path)
        self.assertIn("csharpier", dotnet.skip_if_on_path)
        self.assertEqual(setup_manifest.validate(), [])

    def test_system_dotnet_without_csharpier_reports_missing_and_provisions_csharpier_without_sdk_download(self) -> None:
        import json

        log_file = self.tmp_root / "dotnet_calls.json"
        sys_dotnet = self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        # 1. status() must report dotnet item as missing when csharpier is absent
        st_before = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(st_before.complete)
        self.assertEqual(st_before.items[0].name, "dotnet")
        self.assertEqual(st_before.items[0].state, "missing")

        # 2. describe_plan() uses the system dotnet (no SDK archive download needed)
        # and reports the versioned target pattern <install_root>/csharpier/1.3.0-<random>
        # plus the published symlink path <bin_dir>/csharpier -> <install_root>/csharpier/1.3.0-<random>/csharpier
        csharpier_root = self.inst_root / "csharpier"
        csharpier_target_pattern = csharpier_root / "1.3.0-<random>"
        published_link = self.bin_dir / "csharpier"
        versioned_binary = csharpier_target_pattern / "csharpier"
        plan = describe_plan(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertEqual(len(plan), 1)
        self.assertEqual(
            plan[0],
            {
                "name": "dotnet",
                "kind": "sdk",
                "version": "1.3.0",
                "size_mb": 23,
                "url": setup_manifest.CSHARPIER.url,
                "hash": self.nupkg_hash,
                "hash_algo": "sha512",
                "verification": "verified by checksum",
                "sources": [
                    {
                        "name": "csharpier",
                        "version": "1.3.0",
                        "url": setup_manifest.CSHARPIER.url,
                        "host": "api.nuget.org",
                        "hash_algo": "sha512",
                        "hash": self.nupkg_hash,
                        "verification": "verified by checksum",
                    }
                ],
                "install_dir": str(csharpier_target_pattern),
                "post_install": [
                    f"{sys_dotnet} tool install csharpier --version 1.3.0 --tool-path {csharpier_target_pattern}"
                    " --configfile <verified-packages-dir>/NuGet.config"
                    f" (symlink {published_link} -> {versioned_binary})"
                ],
                "post_install_argv": [
                    [
                        str(sys_dotnet),
                        "tool",
                        "install",
                        "csharpier",
                        "--version",
                        "1.3.0",
                        "--tool-path",
                        str(csharpier_target_pattern),
                        "--configfile",
                        "<verified-packages-dir>/NuGet.config",
                    ]
                ],
            },
        )

        # 3. run_setup() must NOT fetch the SDK archive, but MUST run
        # `dotnet tool install csharpier --version 1.3.0 --tool-path <install_root>/csharpier/1.3.0-<random>`
        # and publish a single atomic symlink at <bin_dir>/csharpier -> versioned dir's csharpier.
        fetch_called = False

        def forbidden_fetch(url: str, dest: Path, cb) -> None:
            nonlocal fetch_called
            fetch_called = True
            raise AssertionError(f"Should not download SDK when dotnet is on PATH: {url}")

        events: list[Progress] = []
        res = run_setup(
            events.append,
            platform=self.plat,
            env=env,
            fetch=forbidden_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res.ok, res.error)
        self.assertFalse(fetch_called)
        self.assertEqual(res.installed, ["dotnet"])
        self.assertEqual(res.skipped, [])
        self.assertEqual(res.failed, {})
        self.assertTrue((self.bin_dir / "csharpier").is_symlink())
        self.assertTrue((self.bin_dir / "csharpier").is_file())
        self.assertTrue(os.access(self.bin_dir / "csharpier", os.X_OK))
        self.assertFalse((self.bin_dir / ".store").exists())
        self.assertFalse((self.inst_root / "dotnet").exists())

        calls = json.loads(log_file.read_text(encoding="utf-8"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"][:6], ["tool", "install", "csharpier", "--version", "1.3.0", "--tool-path"])
        versioned_tp = Path(calls[0]["args"][6])
        self.assertEqual(versioned_tp.parent, csharpier_root)
        self.assertTrue(versioned_tp.name.startswith("1.3.0-"))
        self.assertTrue(versioned_tp.is_dir())
        self.assertEqual(
            os.path.realpath(self.bin_dir / "csharpier"),
            os.path.realpath(versioned_tp / "csharpier"),
        )
        self.assertEqual(Path(calls[0]["argv"][0]).resolve(), sys_dotnet.resolve())
        # Must not clobber DOTNET_ROOT to nonexistent ~/.local/opt/defuzz/dotnet when using system dotnet
        self.assertNotEqual(calls[0]["dotnet_root"], str(self.inst_root / "dotnet"))

        # 4. Subsequent status() and run_setup() see both present and skip
        st_after = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(st_after.complete)
        self.assertEqual(st_after.items[0].state, "present")

        res_second = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=forbidden_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res_second.ok, res_second.error)
        self.assertEqual(res_second.installed, [])
        self.assertEqual(res_second.skipped, ["dotnet"])
        self.assertEqual(len(json.loads(log_file.read_text(encoding="utf-8"))), 1)

    def test_both_dotnet_and_csharpier_on_path_skips_immediately(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        self._write_fake_csharpier(self.ext_bin)
        env = {"PATH": str(self.ext_bin)}

        st = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(st.complete)
        self.assertEqual(st.items[0].state, "present")
        self.assertEqual(st.pending_mb, 0)

        def forbidden_fetch(url: str, dest: Path, cb) -> None:
            raise AssertionError("fetch must not be called")

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=forbidden_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.installed, [])
        self.assertEqual(res.skipped, ["dotnet"])
        self.assertFalse(log_file.exists())

    def test_neither_present_downloads_sdk_and_installs_csharpier_unchanged_plan(self) -> None:
        env = {"PATH": ""}

        # Plan when neither is present is completely unchanged
        plan = describe_plan(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["url"], self.dotnet_url)
        self.assertEqual(plan[0]["size_mb"], 450)
        self.assertEqual(
            plan[0]["post_install_argv"],
            [
                [
                    str(self.inst_root / "dotnet" / "dotnet"),
                    "tool",
                    "install",
                    "csharpier",
                    "--version",
                    "1.3.0",
                    "--tool-path",
                    str(self.bin_dir),
                    "--configfile",
                    "<verified-packages-dir>/NuGet.config",
                ]
            ],
        )
        self.assertEqual(
            [(row["name"], row["host"], row["verification"]) for row in plan[0]["sources"]],
            [
                ("dotnet", "builds.dotnet.microsoft.com", "verified by checksum"),
                ("csharpier", "api.nuget.org", "verified by checksum"),
            ],
        )

        st_before = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(st_before.complete)
        self.assertEqual(st_before.pending_mb, 450)

        fetched_urls: list[str] = []

        def fake_fetch(url: str, dest: Path, report_cb) -> None:
            fetched_urls.append(url)
            data = self.dotnet_tar_path.read_bytes()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            report_cb(len(data), len(data))

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res.ok, res.error)
        self.assertEqual(fetched_urls, [self.dotnet_url])
        self.assertEqual(res.installed, ["dotnet"])
        self.assertTrue((self.bin_dir / "dotnet").is_symlink())
        self.assertTrue((self.bin_dir / "csharpier").is_file())
        self.assertTrue((self.inst_root / "dotnet" / ".adopt-installed-10.0.404").is_file())

        # If csharpier is later deleted from bin_dir, status() detects it missing again
        # and run_setup() re-provisions csharpier using the already-installed managed dotnet
        # without re-downloading the SDK archive.
        (self.bin_dir / "csharpier").unlink()
        st_missing_cs = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(st_missing_cs.complete)
        self.assertEqual(st_missing_cs.items[0].state, "missing")

        def forbidden_fetch(url: str, dest: Path, report_cb) -> None:
            raise AssertionError(f"Should not re-download SDK when managed dotnet is already installed: {url}")

        res_repair = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=forbidden_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res_repair.ok, res_repair.error)
        self.assertEqual(res_repair.installed, ["dotnet"])
        self.assertTrue((self.bin_dir / "csharpier").is_file())

    def test_system_dotnet_csharpier_install_failure_fails_closed(self) -> None:
        log_file = self.tmp_root / "dotnet_fail.json"
        self._write_fake_system_dotnet(log_file, exit_code=1)
        env = {"PATH": str(self.ext_bin)}

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res.ok)
        self.assertIn("dotnet", res.failed)
        self.assertIn("simulated dotnet tool failure", res.failed["dotnet"])
        self.assertEqual(res.installed, [])

    def test_partial_csharpier_install_rolls_back_and_does_not_satisfy_status_or_retry(self) -> None:
        exe = self.ext_bin / "dotnet"
        exe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "p = pathlib.Path(sys.argv[sys.argv.index('--tool-path') + 1]) / 'csharpier'\n"
            "p.parent.mkdir(parents=True, exist_ok=True)\n"
            "p.write_text('partial install')\n"
            "p.chmod(0o755)\n"
            "sys.stderr.write('failed after writing shim\\n')\n"
            "sys.exit(9)\n",
            encoding="utf-8",
        )
        exe.chmod(0o755)
        env = {"PATH": str(self.ext_bin)}

        def forbidden_fetch(url: str, dest: Path, cb) -> None:
            raise AssertionError("SDK fetch forbidden")

        first = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=forbidden_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(first.ok)
        self.assertIn("dotnet", first.failed)
        self.assertFalse((self.bin_dir / "csharpier").exists())

        after = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(after.complete)
        self.assertEqual(after.items[0].state, "missing")

        second = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=forbidden_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(second.ok)
        self.assertIn("dotnet", second.failed)
        self.assertEqual(second.skipped, [])
        self.assertFalse((self.bin_dir / "csharpier").exists())

    def test_corrupt_or_wrong_version_csharpier_in_bin_dir_or_path_not_considered_present(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        # Write a non-runnable / wrong-version csharpier directly into bin_dir
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        bad_cs = self.bin_dir / "csharpier"
        bad_cs.write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")
        bad_cs.chmod(0o755)

        st_bad = status(
            platform=self.plat,
            env=env,
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(st_bad.complete)
        self.assertEqual(st_bad.items[0].state, "missing")

        # Also if dotnet tool install produces a wrong version binary, run_setup must fail and roll back
        exe = self.ext_bin / "dotnet"
        exe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "tp = pathlib.Path(sys.argv[sys.argv.index('--tool-path') + 1])\n"
            "tp.mkdir(parents=True, exist_ok=True)\n"
            "p = tp / 'csharpier'\n"
            "p.write_text('#!/bin/sh\\necho 9.9.9\\n')\n"
            "p.chmod(0o755)\n",
            encoding="utf-8",
        )
        exe.chmod(0o755)
        bad_cs.unlink()

        res_bad_ver = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res_bad_ver.ok)
        self.assertIn("dotnet", res_bad_ver.failed)
        self.assertFalse((self.bin_dir / "csharpier").exists())

    def test_relative_path_entry_resolves_dotnet_to_absolute_path(self) -> None:
        rel_dir = self.tmp_root / "rel-external"
        rel_dir.mkdir(parents=True, exist_ok=True)
        exe = rel_dir / "dotnet"
        exe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "if args[:3] == ['tool', 'install', 'csharpier'] and '--tool-path' in args:\n"
            "    tp = pathlib.Path(args[args.index('--tool-path') + 1])\n"
            "    store_dir = tp / '.store' / 'csharpier' / '1.3.0'\n"
            "    store_dir.mkdir(parents=True, exist_ok=True)\n"
            "    (store_dir / 'CSharpier.dll').write_text('csharpier-1.3.0-payload\\n')\n"
            "    out = tp / 'csharpier'\n"
            "    out.write_text('#!/bin/sh\\necho 1.3.0\\n')\n"
            "    out.chmod(0o755)\n",
            encoding="utf-8",
        )
        exe.chmod(0o755)

        before = Path.cwd()
        try:
            os.chdir(self.tmp_root)
            env = {"PATH": "rel-external"}
            plan = describe_plan(
                platform=self.plat,
                env=env,
                install_root=self.inst_root,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
            self.assertEqual(plan[0]["post_install_argv"][0][0], str(exe.resolve()))
            self.assertTrue(os.path.isabs(plan[0]["post_install_argv"][0][0]))

            res = run_setup(
                lambda _: None,
                platform=self.plat,
                env=env,
                fetch=lambda *a: (_ for _ in ()).throw(AssertionError("SDK fetch forbidden")),
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
            self.assertTrue(res.ok, res.error)
            self.assertEqual(res.installed, ["dotnet"])
            self.assertTrue((self.bin_dir / "csharpier").is_file())
        finally:
            os.chdir(before)

    @staticmethod
    def _snapshot_tree(root: Path) -> dict[str, tuple[str, bytes | str, int]]:
        snap: dict[str, tuple[str, bytes | str, int]] = {}
        if not root.exists() and not root.is_symlink():
            return snap
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            filenames.sort()
            rel_dir = Path(dirpath).relative_to(root).as_posix()
            if rel_dir != ".":
                st = os.lstat(dirpath)
                snap[rel_dir] = ("dir", "", stat.S_IMODE(st.st_mode))
            for name in filenames:
                full = Path(dirpath) / name
                rel = full.relative_to(root).as_posix()
                st = os.lstat(full)
                if full.is_symlink():
                    snap[rel] = ("symlink", os.readlink(full), stat.S_IMODE(st.st_mode))
                else:
                    snap[rel] = ("file", full.read_bytes(), stat.S_IMODE(st.st_mode))
        return snap

    def test_repeat_install_creates_second_versioned_dir_swaps_link_and_cleans_old(self) -> None:
        import json

        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        other_payload = self.bin_dir / ".store" / "other-tool" / "payload.txt"
        other_payload.parent.mkdir(parents=True, exist_ok=True)
        other_payload.write_bytes(b"unrelated-store-payload-bytes")
        other_shim = self.bin_dir / "other-tool"
        other_shim.write_bytes(b"#!/bin/sh\necho other\n")
        other_shim.chmod(0o755)

        # Legacy non-symlink <bin_dir>/csharpier from old full SDK layout
        legacy_cs_shim = self.bin_dir / "csharpier"
        legacy_cs_shim.write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")
        legacy_cs_shim.chmod(0o755)

        # First install replaces legacy non-symlink shim with symlink -> first versioned dir
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: (_ for _ in ()).throw(AssertionError("SDK fetch forbidden")),
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res1.ok, res1.error)
        calls1 = json.loads(log_file.read_text(encoding="utf-8"))
        self.assertEqual(len(calls1), 1)
        first_ver_dir = Path(calls1[0]["args"][6])
        self.assertTrue(first_ver_dir.is_dir())
        self.assertTrue((self.bin_dir / "csharpier").is_symlink())
        self.assertEqual(
            os.path.realpath(self.bin_dir / "csharpier"),
            os.path.realpath(first_ver_dir / "csharpier"),
        )
        self.assertEqual(other_payload.read_bytes(), b"unrelated-store-payload-bytes")
        self.assertEqual(other_shim.read_bytes(), b"#!/bin/sh\necho other\n")

        #Also place an unrelated custom directory under csharpier/ that does NOT match <ver>-<random>
        unrelated_cs_entry = self.inst_root / "csharpier" / "custom-user-notes"
        unrelated_cs_entry.mkdir(parents=True, exist_ok=True)
        (unrelated_cs_entry / "keep.txt").write_text("keep", encoding="utf-8")

        # Corrupt the first versioned csharpier binary so a repeat tool-only install runs
        (first_ver_dir / "csharpier").write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")

        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: (_ for _ in ()).throw(AssertionError("SDK fetch forbidden")),
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res2.ok, res2.error)
        calls2 = json.loads(log_file.read_text(encoding="utf-8"))
        self.assertEqual(len(calls2), 2)
        second_ver_dir = Path(calls2[1]["args"][6])
        self.assertNotEqual(first_ver_dir, second_ver_dir)
        self.assertTrue(second_ver_dir.is_dir())
        self.assertFalse(first_ver_dir.exists())
        self.assertTrue(unrelated_cs_entry.is_dir())
        self.assertTrue((self.bin_dir / "csharpier").is_symlink())
        self.assertEqual(
            os.path.realpath(self.bin_dir / "csharpier"),
            os.path.realpath(second_ver_dir / "csharpier"),
        )
        self.assertEqual(other_payload.read_bytes(), b"unrelated-store-payload-bytes")
        self.assertEqual(other_shim.read_bytes(), b"#!/bin/sh\necho other\n")

    def test_failure_during_tool_install_or_wrong_version_leaves_bin_dir_byte_identical_and_removes_versioned_dir(
        self,
    ) -> None:
        import json

        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file, exit_code=1)
        env = {"PATH": str(self.ext_bin)}

        other_payload = self.bin_dir / ".store" / "other-tool" / "payload.txt"
        other_payload.parent.mkdir(parents=True, exist_ok=True)
        other_payload.write_bytes(b"keep-me-intact")
        old_cs_shim = self.bin_dir / "csharpier"
        old_cs_shim.write_bytes(b"#!/bin/sh\necho 0.29.0\n")
        old_cs_shim.chmod(0o755)

        before_snap = self._snapshot_tree(self.bin_dir)

        # Case 1: failure during tool install
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res1.ok)
        self.assertIn("dotnet", res1.failed)
        self.assertEqual(self._snapshot_tree(self.bin_dir), before_snap)
        calls1 = json.loads(log_file.read_text(encoding="utf-8"))
        failed_tp1 = Path(calls1[-1]["args"][6])
        self.assertFalse(failed_tp1.exists())

        # Case 2: wrong version produced by tool install
        exe = self.ext_bin / "dotnet"
        exe.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            f"log_path = pathlib.Path({str(log_file)!r})\n"
            "args = sys.argv[1:]\n"
            "prev = json.loads(log_path.read_text()) if log_path.exists() else []\n"
            "prev.append({'args': args})\n"
            "log_path.write_text(json.dumps(prev))\n"
            "tp = pathlib.Path(args[args.index('--tool-path') + 1])\n"
            "p = tp / 'csharpier'\n"
            "p.write_text('#!/bin/sh\\necho 9.9.9\\n')\n"
            "p.chmod(0o755)\n",
            encoding="utf-8",
        )
        exe.chmod(0o755)

        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res2.ok)
        self.assertIn("dotnet", res2.failed)
        self.assertEqual(self._snapshot_tree(self.bin_dir), before_snap)
        calls2 = json.loads(log_file.read_text(encoding="utf-8"))
        failed_tp2 = Path(calls2[-1]["args"][6])
        self.assertFalse(failed_tp2.exists())

        # Case 3: publish os.replace failure removes temp symlink and versioned dir, leaving bin_dir byte-identical
        self._write_fake_system_dotnet(log_file)
        with mock.patch("hermes_plugins.defuzz.lint_setup.os.replace", side_effect=OSError("injected replace error")):
            res3 = run_setup(
                lambda _: None,
                platform=self.plat,
                env=env,
                fetch=lambda *a: None,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
        self.assertFalse(res3.ok)
        self.assertIn("dotnet", res3.failed)
        self.assertEqual(self._snapshot_tree(self.bin_dir), before_snap)
        calls3 = json.loads(log_file.read_text(encoding="utf-8"))
        failed_tp3 = Path(calls3[-1]["args"][6])
        self.assertFalse(failed_tp3.exists())

    def test_simulated_crash_before_and_after_publish(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        other_shim = self.bin_dir / "other-tool"
        other_shim.parent.mkdir(parents=True, exist_ok=True)
        other_shim.write_bytes(b"#!/bin/sh\necho other\n")
        other_shim.chmod(0o755)
        old_target = self.tmp_root / "old_csharpier_target"
        old_target.write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")
        old_target.chmod(0o755)
        (self.bin_dir / "csharpier").symlink_to(old_target)

        before_snap = self._snapshot_tree(self.bin_dir)
        real_symlink = os.symlink
        real_replace = os.replace

        # 1. Crash BEFORE temp symlink / publish: bin_dir is completely unchanged
        class _CrashBeforePublish(BaseException):
            pass

        with mock.patch("hermes_plugins.defuzz.lint_setup.os.symlink", side_effect=_CrashBeforePublish("crash")):
            with self.assertRaises(_CrashBeforePublish):
                run_setup(
                    lambda _: None,
                    platform=self.plat,
                    env=env,
                    fetch=lambda *a: None,
                    install_root=self.inst_root,
                    cache_dir=self.cache_dir,
                    real_home=self.fake_home,
                    items=(self.dotnet_item,),
                )
        self.assertEqual(self._snapshot_tree(self.bin_dir), before_snap)

        # 2. Crash AFTER atomic os.replace publish (before old cleanup): new csharpier is active and runnable
        class _CrashAfterPublish(BaseException):
            pass

        with mock.patch(
            "hermes_plugins.defuzz.lint_setup._cleanup_old_csharpier_version_dirs",
            side_effect=_CrashAfterPublish("crash after publish"),
        ):
            with self.assertRaises(_CrashAfterPublish):
                run_setup(
                    lambda _: None,
                    platform=self.plat,
                    env=env,
                    fetch=lambda *a: None,
                    install_root=self.inst_root,
                    cache_dir=self.cache_dir,
                    real_home=self.fake_home,
                    items=(self.dotnet_item,),
                )
        self.assertTrue((self.bin_dir / "csharpier").is_symlink())
        cp = subprocess.run([str(self.bin_dir / "csharpier"), "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(cp.stdout.strip(), "1.3.0")
        self.assertEqual(other_shim.read_bytes(), b"#!/bin/sh\necho other\n")

    def test_symlinked_bin_dir_or_install_root_ancestor_rejected_with_no_writes_outside(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        outside = self.tmp_root / "outside_target"
        outside.mkdir(parents=True, exist_ok=True)
        (outside / "keep.txt").write_bytes(b"outside-untouched")
        outside_before = self._snapshot_tree(outside)

        # 1. bin_dir is a symlink -> outside
        inst1 = self.tmp_root / "case1" / "opt" / "defuzz"
        inst1.mkdir(parents=True, exist_ok=True)
        (inst1 / "bin").symlink_to(outside, target_is_directory=True)
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=inst1,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res1.ok)
        self.assertEqual(self._snapshot_tree(outside), outside_before)

        # 2. <install_root>/csharpier is a symlink -> outside
        inst2 = self.tmp_root / "case2" / "opt" / "defuzz"
        (inst2 / "bin").mkdir(parents=True, exist_ok=True)
        (inst2 / "csharpier").symlink_to(outside, target_is_directory=True)
        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=inst2,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res2.ok)
        self.assertEqual(self._snapshot_tree(outside), outside_before)

        # 3. install_root itself is a symlink -> outside
        inst3_parent = self.tmp_root / "case3" / "opt"
        inst3_parent.mkdir(parents=True, exist_ok=True)
        inst3 = inst3_parent / "defuzz"
        inst3.symlink_to(outside, target_is_directory=True)
        res3 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=inst3,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res3.ok)
        self.assertEqual(self._snapshot_tree(outside), outside_before)

        # 4. Ancestor above install_root is a symlink -> outside
        sym_anc = self.tmp_root / "case4_sym"
        sym_anc.symlink_to(outside, target_is_directory=True)
        inst4 = sym_anc / "opt" / "defuzz"
        res4 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=inst4,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res4.ok)
        self.assertEqual(self._snapshot_tree(outside), outside_before)
        self.assertFalse(log_file.exists())

    def test_status_dedupes_managed_csharpier_version_probe(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        bad_cs = self.bin_dir / "csharpier"
        bad_cs.write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")
        bad_cs.chmod(0o755)
        env = {"PATH": f"{self.bin_dir}{os.pathsep}{self.ext_bin}"}

        with mock.patch(
            "hermes_plugins.defuzz.lint_setup._verify_csharpier_binary",
            wraps=lint_setup._verify_csharpier_binary,
        ) as spy_verify:
            st = status(
                platform=self.plat,
                env=env,
                install_root=self.inst_root,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
        self.assertFalse(st.complete)
        self.assertEqual(spy_verify.call_count, 1)

    def test_keyboard_interrupt_immediately_after_os_replace_preserves_published_target_and_runs(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        self.bin_dir.mkdir(parents=True, exist_ok=True)
        old_cs = self.bin_dir / "csharpier"
        old_cs.write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")
        old_cs.chmod(0o755)

        real_replace = os.replace

        def replace_then_interrupt(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            real_replace(src, dst)
            raise KeyboardInterrupt("SIGINT immediately after os.replace")

        with mock.patch("hermes_plugins.defuzz.lint_setup.os.replace", side_effect=replace_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_setup(
                    lambda _: None,
                    platform=self.plat,
                    env=env,
                    fetch=lambda *a: None,
                    install_root=self.inst_root,
                    cache_dir=self.cache_dir,
                    real_home=self.fake_home,
                    items=(self.dotnet_item,),
                )

        published_link = self.bin_dir / "csharpier"
        self.assertTrue(published_link.is_symlink())
        self.assertTrue(published_link.exists())
        self.assertEqual(list(self.bin_dir.glob(".csharpier.tmp-*")), [])
        cp = subprocess.run([str(published_link), "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(cp.stdout.strip(), "1.3.0")

    def test_keyboard_interrupt_right_after_temp_symlink_creation_cleans_up_temp_link(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        self.bin_dir.mkdir(parents=True, exist_ok=True)
        old_cs = self.bin_dir / "csharpier"
        old_cs.write_text("#!/bin/sh\necho 0.29.0\n", encoding="utf-8")
        old_cs.chmod(0o755)
        before_snap = self._snapshot_tree(self.bin_dir)

        real_symlink = os.symlink

        def symlink_then_interrupt(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            real_symlink(src, dst)
            raise KeyboardInterrupt("SIGINT right after os.symlink")

        with mock.patch("hermes_plugins.defuzz.lint_setup.os.symlink", side_effect=symlink_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_setup(
                    lambda _: None,
                    platform=self.plat,
                    env=env,
                    fetch=lambda *a: None,
                    install_root=self.inst_root,
                    cache_dir=self.cache_dir,
                    real_home=self.fake_home,
                    items=(self.dotnet_item,),
                )

        self.assertEqual(list(self.bin_dir.glob(".csharpier.tmp-*")), [])
        self.assertEqual(self._snapshot_tree(self.bin_dir), before_snap)
        cp = subprocess.run([str(self.bin_dir / "csharpier"), "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(cp.stdout.strip(), "0.29.0")

    def test_failed_first_install_with_absent_bin_dir_does_not_create_bin_dir(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file, exit_code=1)
        env = {"PATH": str(self.ext_bin)}
        self.assertFalse(os.path.lexists(self.bin_dir))

        # 1. Failure during dotnet tool install
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res1.ok)
        self.assertFalse(os.path.lexists(self.bin_dir))

        # 2. Failure during os.replace at publish time when bin_dir was absent before
        self._write_fake_system_dotnet(log_file, exit_code=0)
        with mock.patch("hermes_plugins.defuzz.lint_setup.os.replace", side_effect=OSError("replace failed")):
            res2 = run_setup(
                lambda _: None,
                platform=self.plat,
                env=env,
                fetch=lambda *a: None,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
        self.assertFalse(res2.ok)
        self.assertFalse(os.path.lexists(self.bin_dir))

    def test_cleanup_whitelist_fullmatch_preserves_trailing_newline_dir(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}

        csharpier_root = self.inst_root / "csharpier"
        csharpier_root.mkdir(parents=True, exist_ok=True)
        newline_dir = csharpier_root / ("1.3.0-" + ("b" * 16) + "\n")
        newline_dir.mkdir()
        sentinel = newline_dir / "keep.txt"
        sentinel.write_text("must-not-delete", encoding="utf-8")

        old_valid_dir = csharpier_root / ("1.3.0-" + ("a" * 16))
        old_valid_dir.mkdir()
        (old_valid_dir / "old.txt").write_text("stale", encoding="utf-8")

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertTrue(res.ok, res.error)
        self.assertTrue(newline_dir.is_dir())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "must-not-delete")
        self.assertFalse(old_valid_dir.exists())

    def test_rollback_removes_only_its_own_temp_link_and_bin_dir(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        env = {"PATH": str(self.ext_bin)}

        # 1. A pre-existing user link that merely shares the temp prefix survives a failed install.
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        user_link = self.bin_dir / ".csharpier.tmp-user-backup"
        os.symlink("other-shim", user_link)
        self._write_fake_system_dotnet(log_file, exit_code=1)
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env=env,
            fetch=lambda *a: None,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.dotnet_item,),
        )
        self.assertFalse(res1.ok)
        self.assertTrue(os.path.islink(user_link))
        self.assertEqual(os.readlink(user_link), "other-shim")

        # 2. A bin dir created by someone else (not this run) is kept when the install fails.
        os.unlink(user_link)
        os.rmdir(self.bin_dir)
        self._write_fake_system_dotnet(log_file, exit_code=1)
        bin_dir = self.bin_dir
        real_run = lint_setup.run

        def creating_runner(*args, **kwargs):
            bin_dir.mkdir(parents=True, exist_ok=True)
            return real_run(*args, **kwargs)

        with mock.patch.object(lint_setup, "run", side_effect=creating_runner):
            res2 = run_setup(
                lambda _: None,
                platform=self.plat,
                env=env,
                fetch=lambda *a: None,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
        self.assertFalse(res2.ok)
        self.assertTrue(self.bin_dir.is_dir())

    def test_temp_name_collision_never_deletes_existing_link(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        clash = self.bin_dir / ".csharpier.tmp-0000000000000000"
        os.symlink("someone-elses-target", clash)
        with mock.patch.object(lint_setup.secrets, "token_hex", return_value="0000000000000000"):
            res = run_setup(
                lambda _: None,
                platform=self.plat,
                env=env,
                fetch=lambda *a: None,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.dotnet_item,),
            )
        self.assertFalse(res.ok)
        self.assertTrue(os.path.islink(clash))
        self.assertEqual(os.readlink(clash), "someone-elses-target")

    def test_interrupt_right_after_bin_creation_leaves_no_bin(self) -> None:
        log_file = self.tmp_root / "dotnet_calls.json"
        self._write_fake_system_dotnet(log_file)
        env = {"PATH": str(self.ext_bin)}
        self.assertFalse(os.path.lexists(self.bin_dir))
        real_chain = lint_setup._ensure_real_dir_chain
        bin_dir = self.bin_dir

        def chain_then_interrupt(path, root):
            real_chain(path, root)
            if Path(path) == bin_dir:
                raise KeyboardInterrupt

        with mock.patch.object(lint_setup, "_ensure_real_dir_chain", side_effect=chain_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_setup(
                    lambda _: None,
                    platform=self.plat,
                    env=env,
                    fetch=lambda *a: None,
                    install_root=self.inst_root,
                    cache_dir=self.cache_dir,
                    real_home=self.fake_home,
                    items=(self.dotnet_item,),
                )
        self.assertFalse(os.path.lexists(self.bin_dir))


if __name__ == "__main__":
    unittest.main()
