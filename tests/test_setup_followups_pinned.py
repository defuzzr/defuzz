"""Rule 17: every setup-time download (incl. Rust, csharpier, PSScriptAnalyzer) is official and checksum-pinned.

No real installs: the downloader and the subprocess runner are faked; everything
lands in a temporary prefix.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_setup, setup_manifest  # noqa: E402
from hermes_plugins.defuzz.lint_setup import SetupError, describe_plan, run_setup, status  # noqa: E402
from hermes_plugins.defuzz.setup_manifest import (  # noqa: E402
    CSHARPIER,
    ITEMS,
    OFFICIAL_HOSTS,
    OFFICIAL_REDIRECT_HOSTS,
    PSSCRIPTANALYZER,
    RUST_CHANNEL_MANIFEST_SHA256,
    RUST_VERSION,
    Binary,
    Download,
    SetupItem,
)

PLAT = ("linux", "x86_64")
_HASH_LEN = {"sha256": 64, "sha512": 128}
_UNPINNED = re.compile(r"(?<![A-Za-z])(stable|latest|nightly|beta)(?![A-Za-z])", re.IGNORECASE)


def _all_items() -> tuple[SetupItem, ...]:
    return (*ITEMS, *lint_setup.ARM_BINARY_ITEMS)


def _artifacts():
    """(label, url, hash, algo) for every downloadable artifact on every platform."""
    for item in _all_items():
        for plat, dl in item.downloads.items():
            yield f"{item.name}[{plat[0]}/{plat[1]}]", dl.url, dl.hash, dl.hash_algo
        for pkg in item.packages:
            yield f"{item.name}/{pkg.name}", pkg.url, pkg.hash, pkg.hash_algo


def _nupkg(entries: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buf.getvalue()


def _tar(entries: dict[str, bytes], *, mode: str = "w:gz") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _tree(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*")) if root.exists() else []


class _Sandbox(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()  # the installer refuses a linked ancestor: use the real temp path
        self.inst_root = self.root / "opt" / "defuzz"
        self.bin_dir = self.inst_root / "bin"
        self.cache_dir = self.root / "plugin-data" / "defuzz" / "downloads"
        self.home = self.root / "user_home"
        self.home.mkdir()
        self.served: dict[str, bytes] = {}
        self.fetched: list[str] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def fetch(self, url: str, dest: Path, cb) -> None:
        self.fetched.append(url)
        if url not in self.served:
            raise AssertionError(f"unexpected download {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.served[url])
        cb(len(self.served[url]), len(self.served[url]))

    def setup(self, items, runner=None):
        return run_setup(
            lambda _: None,
            platform=PLAT,
            env={"PATH": ""},
            fetch=self.fetch,
            runner=runner,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.home,
            items=tuple(items),
        )


class TestManifestTableIsPinned(unittest.TestCase):
    def test_every_artifact_on_every_platform_has_an_official_https_url_and_a_checksum(self) -> None:
        rows = list(_artifacts())
        self.assertGreater(len(rows), 50)
        for label, url, hash_val, algo in rows:
            with self.subTest(label):
                parsed = urlparse(url)
                self.assertEqual(parsed.scheme, "https")
                self.assertIn(parsed.hostname, OFFICIAL_HOSTS)
                self.assertIn(algo, _HASH_LEN)
                self.assertRegex(hash_val, rf"^[0-9a-f]{{{_HASH_LEN[algo]}}}$")
                self.assertIsNone(_UNPINNED.search(url), url)

    def test_no_floating_channel_or_unpinned_version_anywhere_in_the_constants(self) -> None:
        for item in _all_items():
            with self.subTest(item.name):
                self.assertRegex(item.version, r"^\d+(\.\d+)+$")
                blob = repr((item.version, item.post_install, item.downloads, item.packages))
                self.assertIsNone(_UNPINNED.search(blob), item.name)
                for pkg in item.packages:
                    self.assertRegex(pkg.version, r"^\d+(\.\d+)+$")
                    self.assertIn(f"/{pkg.version}", pkg.url)
        source = (Path(setup_manifest.__file__)).read_text(encoding="utf-8")
        self.assertNotIn('"--default-toolchain"', source)
        self.assertNotIn("Install-Module PSScriptAnalyzer", source)
        self.assertEqual(setup_manifest.validate(), [])

    def test_follow_up_tools_are_pinned_on_both_linux_architectures(self) -> None:
        by_name = {it.name: it for it in ITEMS}
        self.assertNotIn("rustup", by_name)
        rust = by_name["rust"]
        self.assertEqual(rust.version, RUST_VERSION)
        for arch, target in (("x86_64", "x86_64-unknown-linux-gnu"), ("aarch64", "aarch64-unknown-linux-gnu")):
            dl = rust.downloads[("linux", arch)]
            self.assertEqual(dl.url, f"https://static.rust-lang.org/dist/rust-{RUST_VERSION}-{target}.tar.xz")
            self.assertIn(f"rust-std-{target}", dl.include)
            dotnet = by_name["dotnet"].downloads[("linux", arch)]
            rid = "linux-x64" if arch == "x86_64" else "linux-arm64"
            self.assertEqual(
                dotnet.url, f"https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-{rid}.tar.gz"
            )
            self.assertEqual(dotnet.hash_algo, "sha512")
        self.assertRegex(RUST_CHANNEL_MANIFEST_SHA256, r"^[0-9a-f]{64}$")
        self.assertEqual(by_name["dotnet"].version, "10.0.404")
        self.assertEqual(by_name["dotnet"].packages, (CSHARPIER,))
        self.assertEqual(by_name["pwsh"].packages, (PSSCRIPTANALYZER,))
        self.assertEqual(CSHARPIER.url, "https://api.nuget.org/v3-flatcontainer/csharpier/1.3.0/csharpier.1.3.0.nupkg")
        self.assertEqual(PSSCRIPTANALYZER.url, "https://www.powershellgallery.com/api/v2/package/PSScriptAnalyzer/1.25.0")


class TestRedirectAllowlist(unittest.TestCase):
    def test_redirect_hops_must_stay_on_official_hosts_or_their_cdns(self) -> None:
        for good in (
            "https://release-assets.githubusercontent.com/x",
            "https://dl.google.com/go/go1.27.3.linux-amd64.tar.gz",
            "https://cdn.powershellgallery.com/packages/psscriptanalyzer.1.25.0.nupkg",
        ):
            lint_setup._check_redirect_url(good)
        for bad in (
            "https://evil.example.com/psscriptanalyzer.nupkg",
            "http://cdn.powershellgallery.com/packages/psscriptanalyzer.1.25.0.nupkg",
            "https://cdn.powershellgallery.com.evil.example/x",
        ):
            with self.assertRaises(SetupError):
                lint_setup._check_redirect_url(bad)

    def test_handler_refuses_redirect_before_following_it(self) -> None:
        handler = lint_setup._OfficialRedirectHandler()
        req = urllib.request.Request(PSSCRIPTANALYZER.url)
        with self.assertRaises(SetupError):
            handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example.com/p.nupkg")
        new_req = handler.redirect_request(
            req, None, 302, "Found", {}, "https://cdn.powershellgallery.com/packages/psscriptanalyzer.1.25.0.nupkg"
        )
        self.assertEqual(urlparse(new_req.full_url).hostname, "cdn.powershellgallery.com")

    def test_default_fetch_writes_nothing_when_redirected_off_the_allowlist(self) -> None:
        class _Opener:
            def open(self, req, timeout=None):
                handler = lint_setup._OfficialRedirectHandler()
                handler.redirect_request(req, None, 302, "Found", {}, "https://mirror.example.net/p.nupkg")
                raise AssertionError("redirect was followed")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "p.nupkg"
            with mock.patch("urllib.request.build_opener", return_value=_Opener()):
                with self.assertRaisesRegex(SetupError, "refusing redirect to untrusted URL: https://mirror.example.net"):
                    lint_setup._default_fetch(PSSCRIPTANALYZER.url, dest, lambda d, t: None)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_default_fetch_refuses_a_first_hop_off_the_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("urllib.request.build_opener", side_effect=AssertionError("no network")):
                with self.assertRaises(SetupError):
                    lint_setup._default_fetch("https://cdn.powershellgallery.com/x.nupkg", Path(tmp) / "x", lambda d, t: None)


class TestCsharpierFromVerifiedNupkg(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.nupkg = _nupkg({"csharpier.nuspec": b"<package/>", "tools/net10.0/any/DotnetToolSettings.xml": b"<x/>"})
        self.served[CSHARPIER.url] = self.nupkg
        self.log = self.root / "dotnet-calls.json"
        fake_dotnet = (
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "cfg = pathlib.Path(args[args.index('--configfile') + 1])\n"
            "src = cfg.parent\n"
            f"pathlib.Path({str(self.log)!r}).write_text(json.dumps({{'args': args, 'config': cfg.read_text(),"
            " 'files': sorted(p.name for p in src.iterdir())}))\n"
            "tp = pathlib.Path(args[args.index('--tool-path') + 1]); tp.mkdir(parents=True, exist_ok=True)\n"
            "c = tp / 'csharpier'; c.write_text('#!/bin/sh\\necho 1.3.0\\n'); c.chmod(0o755)\n"
        ).encode()
        self.sdk = _tar({"dotnet": fake_dotnet})
        self.sdk_url = "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-linux-x64.tar.gz"
        self.served[self.sdk_url] = self.sdk
        real = next(it for it in ITEMS if it.name == "dotnet")
        self.item = dataclasses.replace(
            real,
            downloads={
                PLAT: Download(
                    url=self.sdk_url,
                    hash=hashlib.sha512(self.sdk).hexdigest(),
                    hash_algo="sha512",
                    hash_source="published",
                    archive="tar.gz",
                    binaries=(Binary(path="dotnet", name="dotnet"),),
                )
            },
            packages=(dataclasses.replace(CSHARPIER, hash=hashlib.sha512(self.nupkg).hexdigest()),),
        )

    def test_correct_hash_installs_from_a_local_source_only(self) -> None:
        res = self.setup([self.item])
        self.assertTrue(res.ok, res.error)
        call = json.loads(self.log.read_text())
        self.assertEqual(call["files"], ["NuGet.config", "csharpier.1.3.0.nupkg"])
        sources = re.findall(r"<add key=\"[^\"]+\" value=\"([^\"]+)\"", call["config"])
        self.assertEqual(len(sources), 1)
        self.assertIn("<clear />", call["config"].split("</packageSources>")[0])
        self.assertNotIn("nuget.org", call["config"])
        self.assertEqual(call["args"][:6], ["tool", "install", "csharpier", "--version", "1.3.0", "--tool-path"])
        self.assertEqual(self.fetched, [CSHARPIER.url, self.sdk_url])
        self.assertTrue((self.bin_dir / "csharpier").is_file())
        # The staged package folder is removed afterwards.
        self.assertEqual([p for p in self.inst_root.iterdir() if "packages" in p.name], [])

    def test_wrong_hash_aborts_with_one_line_and_writes_nothing(self) -> None:
        bad = dataclasses.replace(self.item, packages=(dataclasses.replace(CSHARPIER, hash="0" * 128),))
        runner = mock.Mock(side_effect=AssertionError("dotnet must not run"))
        res = self.setup([bad], runner=runner)
        self.assertFalse(res.ok)
        self.assertEqual(len(res.error.splitlines()), 1)
        self.assertIn("csharpier 1.3.0: checksum mismatch", res.error)
        self.assertIn("nothing installed for dotnet", res.error)
        runner.assert_not_called()
        self.assertEqual(self.fetched, [CSHARPIER.url])  # the SDK is not even downloaded
        self.assertEqual([p for p in _tree(self.inst_root) if p != ".adopt-setup.lock"], [])
        self.assertFalse(self.log.exists())


class TestPSScriptAnalyzerFromVerifiedNupkg(_Sandbox):
    def setUp(self) -> None:
        super().setUp()
        self.module = {
            "PSScriptAnalyzer.psd1": b"@{ ModuleVersion = '1.25.0' }",
            "PSScriptAnalyzer.psm1": b"# module",
            "PSv7/Microsoft.Windows.PowerShell.ScriptAnalyzer.dll": b"MZ",
            "PSScriptAnalyzer.nuspec": b"<package/>",
            "_rels/.rels": b"<r/>",
            "[Content_Types].xml": b"<t/>",
            "package/services/metadata/core-properties/x.psmdcp": b"<p/>",
            ".signature.p7s": b"sig",
        }
        self.pwsh_tar = _tar({"pwsh": b"#!/bin/sh\necho pwsh\n"})
        self.pwsh_url = "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-linux-x64.tar.gz"
        self.served[self.pwsh_url] = self.pwsh_tar
        self.modules = self.home / ".local" / "share" / "powershell" / "Modules"
        real = next(it for it in ITEMS if it.name == "pwsh")
        self.base = dataclasses.replace(
            real,
            downloads={
                PLAT: Download(
                    url=self.pwsh_url,
                    hash=hashlib.sha256(self.pwsh_tar).hexdigest(),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    binaries=(Binary(path="pwsh", name="pwsh"),),
                )
            },
        )

    def _item(self, payload: bytes, *, hash_val: str | None = None) -> SetupItem:
        self.served[PSSCRIPTANALYZER.url] = payload
        pkg = dataclasses.replace(PSSCRIPTANALYZER, hash=hash_val or hashlib.sha512(payload).hexdigest())
        return dataclasses.replace(self.base, packages=(pkg,))

    def test_correct_hash_extracts_module_without_packaging_files(self) -> None:
        runner = mock.Mock(side_effect=AssertionError("no Install-Module / no pwsh run"))
        res = self.setup([self._item(_nupkg(self.module))], runner=runner)
        self.assertTrue(res.ok, res.error)
        runner.assert_not_called()
        target = self.modules / "PSScriptAnalyzer" / "1.25.0"
        self.assertEqual(
            _tree(target),
            [
                ".defuzz-installed",
                "PSScriptAnalyzer.psd1",
                "PSScriptAnalyzer.psm1",
                "PSv7",
                "PSv7/Microsoft.Windows.PowerShell.ScriptAnalyzer.dll",
            ],
        )
        self.assertEqual(_tree(self.modules / "PSScriptAnalyzer"), ["1.25.0", *[f"1.25.0/{p}" for p in _tree(target)]])
        self.assertTrue(any("installed PSScriptAnalyzer 1.25.0" in line for line in res.log))
        self.assertTrue((self.bin_dir / "pwsh").is_symlink())

    def test_wrong_hash_aborts_and_writes_nothing(self) -> None:
        res = self.setup([self._item(_nupkg(self.module), hash_val="f" * 128)])
        self.assertFalse(res.ok)
        self.assertEqual(len(res.error.splitlines()), 1)
        self.assertIn("PSScriptAnalyzer 1.25.0: checksum mismatch", res.error)
        self.assertFalse(self.modules.exists())
        self.assertEqual(self.fetched, [PSSCRIPTANALYZER.url])
        self.assertEqual([p for p in _tree(self.inst_root) if p != ".adopt-setup.lock"], [])

    def test_zip_slip_symlink_and_encoded_traversal_members_are_refused(self) -> None:
        cases = {
            "dotdot": _nupkg({**self.module, "../../escape.txt": b"x"}),
            "absolute": _nupkg({**self.module, "/tmp/escape.txt": b"x"}),
            "encoded": _nupkg({**self.module, "%2e%2e/escape.txt": b"x"}),
            "symlink": _nupkg(self.module, symlinks={"link": "/etc/passwd"}),
        }
        for label, payload in cases.items():
            with self.subTest(label):
                res = self.setup([self._item(payload)])
                self.assertFalse(res.ok, label)
                self.assertRegex(res.error, r"unsafe|refusing")
                self.assertEqual(_tree(self.modules / "PSScriptAnalyzer"), [])
                self.assertFalse((self.home / ".local" / "share" / "powershell" / "escape.txt").exists())
                self.assertFalse((self.root / "escape.txt").exists())
                self.assertFalse((self.inst_root / "pwsh").exists())

    def test_existing_user_installed_version_is_left_alone(self) -> None:
        mine = self.modules / "PSScriptAnalyzer" / "1.25.0"
        mine.mkdir(parents=True)
        (mine / "PSScriptAnalyzer.psd1").write_text("user copy", encoding="utf-8")
        res = self.setup([self._item(_nupkg(self.module))])
        self.assertTrue(res.ok, res.error)
        self.assertEqual((mine / "PSScriptAnalyzer.psd1").read_text(encoding="utf-8"), "user copy")
        self.assertTrue(any("kept existing PSScriptAnalyzer" in line for line in res.log))


class TestRustStandaloneInstaller(_Sandbox):
    TARGET = "x86_64-unknown-linux-gnu"

    def _installer(self, *, extra_manifest_line: str = "") -> bytes:
        top = f"rust-{RUST_VERSION}-{self.TARGET}"
        comps = {
            "rustc": ["bin/rustc", "bin/rustdoc", "lib/librustc_driver.so"],
            "cargo": ["bin/cargo"],
            "rustfmt-preview": ["bin/rustfmt", "bin/cargo-fmt"],
            "clippy-preview": ["bin/cargo-clippy", "bin/clippy-driver"],
            f"rust-std-{self.TARGET}": [f"lib/rustlib/{self.TARGET}/lib/libstd.rlib"],
            "rust-docs": ["share/doc/rust/html/index.html"],
        }
        entries: dict[str, bytes] = {f"{top}/install.sh": b"#!/bin/sh\nexit 1\n", f"{top}/components": b"\n".join(c.encode() for c in comps)}
        for comp, files in comps.items():
            lines = [f"file:{f}" for f in files]
            if comp == "cargo" and extra_manifest_line:
                lines.append(extra_manifest_line)
            entries[f"{top}/{comp}/manifest.in"] = ("\n".join(lines) + "\n").encode()
            for f in files:
                entries[f"{top}/{comp}/{f}"] = f"#!/bin/sh\necho {comp} {f}\n".encode()
        return _tar(entries, mode="w:xz")

    def _item(self, payload: bytes, *, hash_val: str | None = None) -> SetupItem:
        real = next(it for it in ITEMS if it.name == "rust")
        dl = real.downloads[PLAT]
        self.served[dl.url] = payload
        return dataclasses.replace(
            real, downloads={PLAT: dataclasses.replace(dl, hash=hash_val or hashlib.sha256(payload).hexdigest())}
        )

    def test_correct_hash_merges_only_the_needed_components_and_exposes_the_tools(self) -> None:
        runner = mock.Mock(side_effect=AssertionError("no rustup, no install.sh"))
        res = self.setup([self._item(self._installer())], runner=runner)
        self.assertTrue(res.ok, res.error)
        runner.assert_not_called()
        prefix = self.inst_root / "rust"
        self.assertEqual(
            _tree(prefix),
            [
                f".adopt-installed-{RUST_VERSION}",
                "bin",
                "bin/cargo",
                "bin/cargo-clippy",
                "bin/cargo-fmt",
                "bin/clippy-driver",
                "bin/rustc",
                "bin/rustdoc",
                "bin/rustfmt",
                "lib",
                "lib/librustc_driver.so",
                "lib/rustlib",
                f"lib/rustlib/{self.TARGET}",
                f"lib/rustlib/{self.TARGET}/lib",
                f"lib/rustlib/{self.TARGET}/lib/libstd.rlib",
            ],
        )
        for name in ("cargo", "rustc", "rustfmt", "cargo-clippy", "clippy-driver"):
            link = self.bin_dir / name
            self.assertTrue(link.is_symlink(), name)
            self.assertEqual(link.resolve(), (prefix / "bin" / name).resolve())
        self.assertFalse((self.bin_dir / "rustup").exists())

    def test_wrong_hash_aborts_and_writes_nothing(self) -> None:
        res = self.setup([self._item(self._installer(), hash_val="0" * 64)])
        self.assertFalse(res.ok)
        self.assertEqual(len(res.error.splitlines()), 1)
        self.assertIn("checksum mismatch", res.error)
        self.assertEqual([p for p in _tree(self.inst_root) if p != ".adopt-setup.lock"], [])

    def test_traversal_in_component_manifest_is_refused(self) -> None:
        res = self.setup([self._item(self._installer(extra_manifest_line="file:../../../escape"))])
        self.assertFalse(res.ok)
        self.assertIn("unsafe", res.error)
        self.assertFalse((self.inst_root / "rust").exists())
        self.assertFalse((self.root / "escape").exists())


class TestPlanAndStatusDisclosure(unittest.TestCase):
    def _kw(self, tmp: Path) -> dict:
        home = tmp / "home"
        home.mkdir(exist_ok=True)
        return {"platform": PLAT, "env": {"PATH": ""}, "install_root": tmp / "opt" / "defuzz", "real_home": home}

    def test_plan_lists_every_source_on_official_hosts_verified_by_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = describe_plan(**self._kw(Path(tmp)))
        rows = [row for item in plan for row in item["sources"]]
        hosts = {row["host"] for row in rows}
        self.assertLessEqual(hosts, set(OFFICIAL_HOSTS))
        self.assertIn("api.nuget.org", hosts)
        self.assertIn("www.powershellgallery.com", hosts)
        self.assertIn("static.rust-lang.org", hosts)
        for row in rows:
            self.assertEqual(row["verification"], "verified by checksum")
            self.assertRegex(row["hash"], rf"^[0-9a-f]{{{_HASH_LEN[row['hash_algo']]}}}$")
        for item in plan:
            self.assertEqual(item["verification"], "verified by checksum")
            for line in item["post_install"]:
                self.assertIsNone(_UNPINNED.search(line), line)
                self.assertNotIn("Install-Module", line)
        by_name = {item["name"]: item for item in plan}
        self.assertEqual([r["name"] for r in by_name["dotnet"]["sources"]], ["dotnet", "csharpier"])
        self.assertEqual([r["name"] for r in by_name["pwsh"]["sources"]], ["pwsh", "PSScriptAnalyzer"])
        self.assertIn("PSScriptAnalyzer", by_name["pwsh"]["post_install"][0])
        self.assertIn("verified by checksum", by_name["pwsh"]["post_install"][0])

    def test_status_lists_the_same_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kw = self._kw(Path(tmp))
            st = status(**kw)
            plan = describe_plan(**kw)
        self.assertEqual(st.sources, [row for item in plan for row in item["sources"]])
        self.assertTrue(all(row["verification"] == "verified by checksum" for row in st.sources))


if __name__ == "__main__":
    unittest.main()
