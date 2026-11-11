"""Unit tests for setup_manifest.py."""

from __future__ import annotations

import os
import sys
import unittest
import urllib.request
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.setup_manifest import (  # noqa: E402
    Binary,
    Download,
    ITEMS,
    OFFICIAL_HOSTS,
    SetupItem,
    current_platform,
    downloads_for,
    exe_name,
    total_size_mb,
    validate,
)

EXPECTED_NAMES = (
    "rust",
    "go",
    "dotnet",
    "pwsh",
    "golangci-lint",
    "biome",
    "oxlint",
    "stylua",
    "selene",
    "glslang",
    "dxc",
)

ALLOWED_OS = {"linux", "darwin", "windows"}
ALLOWED_ARCH = {"x86_64", "aarch64"}


class TestSetupManifest(unittest.TestCase):
    def test_validate_returns_empty_list(self) -> None:
        self.assertEqual(validate(), [])

    def test_items_cover_expected_names_and_types(self) -> None:
        names = tuple(item.name for item in ITEMS)
        self.assertEqual(set(names), set(EXPECTED_NAMES))
        self.assertEqual(len(names), len(EXPECTED_NAMES))
        for item in ITEMS:
            self.assertIsInstance(item, SetupItem)
            self.assertIn(item.kind, ("binary", "sdk"))
            self.assertTrue(item.version.strip())
            self.assertTrue(item.homepage.startswith("https://"))
            self.assertGreater(item.size_mb, 0)
            self.assertGreater(len(item.provides), 0)
            self.assertGreater(len(item.skip_if_on_path), 0)

    def test_every_item_has_linux_x86_64(self) -> None:
        for item in ITEMS:
            with self.subTest(item=item.name):
                self.assertIn(("linux", "x86_64"), item.downloads)
                dl = item.downloads[("linux", "x86_64")]
                self.assertIsInstance(dl, Download)
                self.assertGreater(len(dl.binaries), 0)
                for b in dl.binaries:
                    self.assertIsInstance(b, Binary)
                    self.assertTrue(b.path)
                    self.assertTrue(b.name)

    def test_binaries_mapping_and_chmod_metadata(self) -> None:
        by_name = {item.name: item for item in ITEMS}
        oxlint = by_name["oxlint"]
        self.assertEqual(
            oxlint.downloads[("linux", "x86_64")].binaries,
            (Binary(path="oxlint-x86_64-unknown-linux-gnu", name="oxlint"),),
        )
        glslang = by_name["glslang"]
        self.assertEqual(
            glslang.downloads[("windows", "x86_64")].binaries,
            (Binary(path="bin/glslang.exe", name="glslangValidator"),),
        )
        rust = by_name["rust"]
        for plat, dl in rust.downloads.items():
            exposed = [b.name for b in dl.binaries]
            # The pinned standalone toolchain is exposed directly; rustup is never installed.
            self.assertNotIn("rustup", exposed, f"rust[{plat}] must not expose rustup")
            self.assertNotIn("rustup-init", exposed)
            self.assertEqual(
                exposed, ["cargo", "rustc", "rustdoc", "rustfmt", "cargo-fmt", "cargo-clippy", "clippy-driver"]
            )
            self.assertEqual(dl.layout, "rust-components")
        forbidden_rust_proxies = {
            "rustup",
            "cargo",
            "rustc",
            "rustfmt",
            "cargo-fmt",
            "cargo-clippy",
            "clippy-driver",
        }
        for item in ITEMS:
            for plat, dl in item.downloads.items():
                for b in dl.binaries:
                    bare_name = b.name[:-4] if b.name.endswith(".exe") else b.name
                    if item.name == "rust":
                        continue
                    self.assertNotIn(
                        bare_name,
                        forbidden_rust_proxies,
                        f"{item.name}[{plat}] must not expose Rust proxy {b.name!r} in managed bin dir",
                    )
                self.assertIsInstance(dl.chmod, bool)
                if plat[0] in ("linux", "darwin"):
                    self.assertTrue(dl.chmod)

    def test_exe_name_helper(self) -> None:
        self.assertEqual(exe_name("oxlint", ("linux", "x86_64")), "oxlint")
        self.assertEqual(exe_name("oxlint", ("darwin", "aarch64")), "oxlint")
        self.assertEqual(exe_name("oxlint", ("windows", "x86_64")), "oxlint.exe")
        self.assertEqual(exe_name("oxlint.exe", ("windows", "x86_64")), "oxlint.exe")

    def test_all_hashes_lowercase_hex_of_right_length(self) -> None:
        expected_len = {"sha256": 64, "sha512": 128}
        hex_chars = set("0123456789abcdef")
        for item in ITEMS:
            for plat, dl in item.downloads.items():
                with self.subTest(item=item.name, plat=plat):
                    self.assertIn(dl.hash_algo, expected_len)
                    self.assertEqual(len(dl.hash), expected_len[dl.hash_algo])
                    self.assertTrue(all(c in hex_chars for c in dl.hash))
                    self.assertIn(dl.hash_source, ("published", "computed"))
                    self.assertIn(dl.archive, ("tar.gz", "tar.xz", "zip", "binary"))
                    self.assertGreaterEqual(dl.strip_components, 0)

    def test_hosts_allowlisted_and_no_latest_in_urls(self) -> None:
        self.assertIsInstance(OFFICIAL_HOSTS, frozenset)
        self.assertGreater(len(OFFICIAL_HOSTS), 0)
        for item in ITEMS:
            for plat, dl in item.downloads.items():
                with self.subTest(item=item.name, plat=plat):
                    self.assertEqual(len(plat), 2)
                    self.assertIn(plat[0], ALLOWED_OS)
                    self.assertIn(plat[1], ALLOWED_ARCH)
                    parsed = urlparse(dl.url)
                    self.assertEqual(parsed.scheme, "https")
                    self.assertIn(parsed.hostname, OFFICIAL_HOSTS)
                    self.assertNotIn("latest", dl.url.lower())

    def test_current_platform_returns_known_tuple(self) -> None:
        plat = current_platform()
        self.assertIsInstance(plat, tuple)
        self.assertEqual(len(plat), 2)
        self.assertIn(plat[0], ALLOWED_OS)
        self.assertIn(plat[1], ALLOWED_ARCH)

    def test_downloads_for_linux_x86_64_covers_every_item(self) -> None:
        pairs = downloads_for(("linux", "x86_64"))
        self.assertEqual(len(pairs), len(ITEMS))
        self.assertEqual(
            [item.name for item, _ in pairs],
            [item.name for item in ITEMS],
        )
        total = total_size_mb(("linux", "x86_64"))
        self.assertEqual(total, sum(item.size_mb for item in ITEMS))
        self.assertGreater(total, 0)

    def test_downloads_for_unknown_platform_returns_empty(self) -> None:
        self.assertEqual(downloads_for(("plan9", "mips")), [])
        self.assertEqual(total_size_mb(("plan9", "mips")), 0)

    def test_post_install_commands_pinned_and_valid(self) -> None:
        by_name = {item.name: item for item in ITEMS}
        rust = by_name["rust"]
        self.assertEqual(rust.post_install, ())
        self.assertEqual(rust.version, "1.97.1")
        dotnet = by_name["dotnet"]
        self.assertEqual(len(dotnet.post_install), 1)
        self.assertEqual(dotnet.post_install[0][:4], ("{install_dir}/dotnet", "tool", "install", "csharpier"))
        self.assertIn("--version", dotnet.post_install[0])
        self.assertIn("{bin_dir}", dotnet.post_install[0])
        self.assertEqual(dotnet.post_install[0][-2:], ("--configfile", "{pkg_dir}/NuGet.config"))
        self.assertEqual([p.name for p in dotnet.packages], ["csharpier"])

        pwsh = by_name["pwsh"]
        self.assertEqual(pwsh.post_install, ())
        self.assertEqual([(p.name, p.version, p.kind) for p in pwsh.packages], [("PSScriptAnalyzer", "1.25.0", "pwsh-module")])

    @unittest.skipUnless(os.environ.get("ADOPT_NET_TESTS") == "1", "Set ADOPT_NET_TESTS=1 to run live HEAD checks")
    def test_network_head_linux_x86_64_urls(self) -> None:
        for item, dl in downloads_for(("linux", "x86_64")):
            with self.subTest(item=item.name, url=dl.url):
                req = urllib.request.Request(
                    dl.url,
                    method="HEAD",
                    headers={"User-Agent": "defuzz-test/1.0"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self.assertIn(resp.status, (200, 302))

    def test_validate_catches_invalid_entries(self) -> None:
        from hermes_plugins.defuzz import setup_manifest as sm

        bad_dl = Download(
            url="http://evil.example.com/latest/bin",
            hash="ZZZ",
            hash_algo="sha256",
            hash_source="published",
            archive="tar.gz",
            strip_components=0,
            binaries=(Binary(path="bin", name="bad"),),
        )
        bad_item = SetupItem(
            name="bad",
            kind="binary",
            version="",
            homepage="https://example.com",
            size_mb=1,
            provides=(),
            skip_if_on_path=("bad",),
            downloads={("linux", "x86_64"): bad_dl},
            post_install=(("{unknown_var}/run",),),
        )
        with mock.patch.object(sm, "ITEMS", (bad_item,)):
            problems = sm.validate()
            joined = "\n".join(problems)
            self.assertIn("empty version", joined)
            self.assertIn("empty provides", joined)
            self.assertIn("url is not https", joined)
            self.assertIn("not in OFFICIAL_HOSTS", joined)
            self.assertIn("unpinned 'latest'", joined)
            self.assertIn("invalid sha256 hash", joined)
            self.assertIn("disallowed placeholder {unknown_var}", joined)

    def test_validate_negative_cases(self) -> None:
        from hermes_plugins.defuzz import setup_manifest as sm

        valid_hash = "a" * 64
        base_dl = Download(
            url="https://github.com/org/repo/releases/download/v1.0.0/tool.tar.gz",
            hash=valid_hash,
            hash_algo="sha256",
            hash_source="published",
            archive="tar.gz",
            strip_components=0,
            binaries=(Binary(path="tool", name="tool"),),
        )

        # 1. unmatched braces placeholder
        item_unmatched = SetupItem(
            name="unmatched",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("tool",),
            skip_if_on_path=("tool",),
            downloads={("linux", "x86_64"): base_dl},
            post_install=(("{install_dir/tool",),),
        )
        with mock.patch.object(sm, "ITEMS", (item_unmatched,)):
            problems = sm.validate()
            self.assertTrue(any("unmatched brace" in p for p in problems), problems)

        # 2. unsupported hash_algo
        dl_bad_algo = Download(
            url=base_dl.url,
            hash=valid_hash,
            hash_algo="md5",
            hash_source="published",
            archive="tar.gz",
            strip_components=0,
            binaries=(Binary(path="tool", name="tool"),),
        )
        item_bad_algo = SetupItem(
            name="bad_algo",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("tool",),
            skip_if_on_path=("tool",),
            downloads={("linux", "x86_64"): dl_bad_algo},
        )
        with mock.patch.object(sm, "ITEMS", (item_bad_algo,)):
            problems = sm.validate()
            self.assertTrue(any("unsupported hash_algo" in p for p in problems), problems)

        # 3. sha512 with wrong length
        dl_bad_sha512 = Download(
            url=base_dl.url,
            hash="a" * 64,
            hash_algo="sha512",
            hash_source="published",
            archive="tar.gz",
            strip_components=0,
            binaries=(Binary(path="tool", name="tool"),),
        )
        item_bad_sha512 = SetupItem(
            name="bad_sha512",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("tool",),
            skip_if_on_path=("tool",),
            downloads={("linux", "x86_64"): dl_bad_sha512},
        )
        with mock.patch.object(sm, "ITEMS", (item_bad_sha512,)):
            problems = sm.validate()
            self.assertTrue(any("invalid sha512 hash" in p for p in problems), problems)

        # 4. malformed platform key (non-2-tuple and unknown os/arch) - must not raise!
        item_bad_plat = SetupItem(
            name="bad_plat",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("tool",),
            skip_if_on_path=("tool",),
            downloads={
                ("linux",): base_dl,  # type: ignore[dict-item]
                "linux-x86_64": base_dl,  # type: ignore[dict-item]
                ("freebsd", "riscv64"): base_dl,
            },
        )
        with mock.patch.object(sm, "ITEMS", (item_bad_plat,)):
            problems = sm.validate()
            self.assertEqual(len([p for p in problems if "invalid platform" in p]), 3, problems)

        # 5. binary name not in provides (and missing provides coverage for binary-kind)
        dl_wrong_bin = Download(
            url=base_dl.url,
            hash=valid_hash,
            hash_algo="sha256",
            hash_source="published",
            archive="tar.gz",
            strip_components=0,
            binaries=(Binary(path="other", name="other"),),
        )
        item_wrong_bin = SetupItem(
            name="wrong_bin",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/org/repo",
            size_mb=1,
            provides=("tool",),
            skip_if_on_path=("tool",),
            downloads={("linux", "x86_64"): dl_wrong_bin},
        )
        with mock.patch.object(sm, "ITEMS", (item_wrong_bin,)):
            problems = sm.validate()
            self.assertTrue(any("not in provides" in p for p in problems), problems)
            self.assertTrue(any("missing provides" in p for p in problems), problems)

    def test_current_platform_normalization(self) -> None:
        from hermes_plugins.defuzz import setup_manifest as sm

        cases = [
            (("Linux", "x86_64"), ("linux", "x86_64")),
            (("Darwin", "arm64"), ("darwin", "aarch64")),
            (("Windows", "AMD64"), ("windows", "x86_64")),
            (("Linux", "aarch64"), ("linux", "aarch64")),
        ]
        for (sys_val, mach_val), expected in cases:
            with mock.patch.object(sm.platform, "system", return_value=sys_val), mock.patch.object(
                sm.platform, "machine", return_value=mach_val
            ):
                self.assertEqual(sm.current_platform(), expected)


if __name__ == "__main__":
    unittest.main()
