"""Unit tests for lint_setup.py with fake manifest and mocked downloads."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_setup  # noqa: E402
from hermes_plugins.defuzz.lint_setup import (  # noqa: E402
    ItemStatus,
    Progress,
    SetupError,
    SetupResult,
    SetupStatus,
    describe_plan,
    headless_message,
    install_root,
    run_setup,
    status,
)
from hermes_plugins.defuzz.setup_manifest import Binary, Download, SetupItem  # noqa: E402


class ArchiveSymlinkTests(unittest.TestCase):
    def test_tar_refused_without_the_data_filter(self):
        # Python 3.11.0-3.11.3 has no tarfile.data_filter: refuse instead of extracting unfiltered.
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "archive"
            dest = Path(td) / "dest"
            dest.mkdir()
            archive.write_bytes(_make_tar_bytes({"bin/tool": b"binary"}))
            with mock.patch.object(tarfile, "data_filter", None):
                with self.assertRaises(SetupError) as ctx:
                    lint_setup._extract_tar(archive, dest, mode="r:gz", strip_components=0, cancel=None)
            self.assertIn("3.11.4", str(ctx.exception))
            self.assertEqual(list(dest.iterdir()), [])

    def test_internal_symlinks_and_escape_rejection(self):
        cases = [
            ({"bin/tool": b"binary", "bin/alias": ("symlink", "tool")}, True),
            ({"bin/alias": ("symlink", "tool"), "bin/tool": b"binary"}, True),
            ({"bin/tool": b"binary", "bin/alias": ("symlink", "next"),
              "bin/next": ("symlink", "tool")}, True),
            ({"alias": ("symlink", "d/../outside"), "d": ("symlink", ".")}, False),
            ({"bin/alias": ("symlink", "../../outside")}, False),
            ({"bin/alias": ("symlink", "/outside")}, False),
            ({"bin/alias": ("symlink", "next"),
              "bin/next": ("symlink", "../../outside")}, False),
        ]
        for archive_type in ("zip", "tar"):
            for entries, safe in cases:
                with self.subTest(archive=archive_type, entries=entries):
                    with tempfile.TemporaryDirectory() as td:
                        root = Path(td)
                        archive = root / "archive"
                        dest = root / "dest"
                        dest.mkdir()
                        if archive_type == "tar":
                            archive.write_bytes(_make_tar_bytes(entries))
                            extract = lambda: lint_setup._extract_tar(
                                archive, dest, mode="r:gz", strip_components=0, cancel=None)
                        else:
                            with zipfile.ZipFile(archive, "w") as zf:
                                for name, payload in entries.items():
                                    info = zipfile.ZipInfo(name)
                                    info.create_system = 3
                                    if isinstance(payload, tuple):
                                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                                        zf.writestr(info, payload[1])
                                    else:
                                        info.external_attr = (stat.S_IFREG | 0o755) << 16
                                        zf.writestr(info, payload)
                            extract = lambda: lint_setup._extract_zip(
                                archive, dest, strip_components=0, cancel=None)
                        if safe:
                            extract()
                            self.assertTrue((dest / "bin/alias").is_symlink())
                            self.assertEqual((dest / "bin/alias").read_bytes(), b"binary")
                        elif "alias" in entries and archive_type == "tar":
                            # New tarfile data filters normalize this target;
                            # older versions reject it in our final chain check.
                            try:
                                extract()
                            except SetupError:
                                pass
                            else:
                                self.assertTrue((dest / "alias").resolve().is_relative_to(dest.resolve()))
                        else:
                            with self.assertRaises(SetupError):
                                extract()


def _sha256_bytes(data: bytes) -> str:
    """Return lowercase hex sha256 digest for data."""
    return hashlib.sha256(data).hexdigest()


def _sha512_bytes(data: bytes) -> str:
    """Return lowercase hex sha512 digest for data."""
    return hashlib.sha512(data).hexdigest()


def _make_tar_bytes(
    entries: dict[str, bytes | tuple[str, str]],
    *,
    compression: str = "gz",
) -> bytes:
    """Build an in-memory tar.gz or tar.xz archive from a dict of path -> bytes or ('symlink', target)."""
    buf = io.BytesIO()
    tf_ctx = (
        tarfile.open(fileobj=buf, mode="w:xz")
        if compression == "xz"
        else tarfile.open(fileobj=buf, mode="w:gz")
    )
    with tf_ctx as tf:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name=name)
            if isinstance(payload, tuple) and payload[0] == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload[1]
                info.mode = 0o777
                tf.addfile(info)
            else:
                assert isinstance(payload, bytes)
                info.size = len(payload)
                info.mode = 0o755
                tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _make_zip_bytes(entries: dict[str, bytes | tuple[str, str]]) -> bytes:
    """Build an in-memory zip archive from a dict of path -> bytes or ('symlink', target)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zi = zipfile.ZipInfo(filename=name)
            if isinstance(payload, tuple) and payload[0] == "symlink":
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zi, payload[1].encode("utf-8"))
            else:
                assert isinstance(payload, bytes)
                zi.external_attr = (0o100755 & 0xFFFF) << 16
                zf.writestr(zi, payload)
    return buf.getvalue()


class TestInstalledVersions(unittest.TestCase):
    def test_probe_unexpected_errors_are_per_row(self):
        items = lint_setup.ITEMS[:2]
        for error in (KeyError('pin'), ValueError('bad output'), RuntimeError('broken')):
            with self.subTest(error=error), mock.patch.object(lint_setup, 'which', side_effect=[error, None]):
                rows = lint_setup.installed_tool_versions(items=items)
            self.assertEqual(rows[0]['status'], 'could_not_verify')
            self.assertIn(str(error), rows[0]['error'])
            self.assertEqual(rows[1]['status'], 'missing')


    def test_wheel_pin_failures_keep_rows_and_metadata(self):
        import yaml
        for failure in (None, yaml.YAMLError("invalid YAML")):
            with self.subTest(failure=failure), mock.patch.object(lint_setup, 'WHEEL_PACKAGES', {'unknown': 'wheeltool'}), mock.patch('yaml.safe_load', side_effect=failure, return_value={}), mock.patch.object(lint_setup, 'which', return_value=None):
                rows = lint_setup.installed_tool_versions()
                row = next(row for row in rows if row['name'] == 'wheeltool')
                self.assertEqual(row['status'], 'could_not_verify')
                self.assertTrue(row['error'])
                self.assertEqual(row['kind'], 'wheel')
                self.assertEqual(row['size_mb'], 0)
                self.assertIn('version', row)
                self.assertEqual(row['state'], 'missing')

    def test_probes_strip_empty_and_relative_path_entries(self):
        dirty = os.pathsep.join(['', '.', 'relative/bin', '/trusted', ''])
        with mock.patch.object(lint_setup, 'build_env', return_value={'PATH': dirty}), mock.patch.object(lint_setup, 'which', return_value=None) as lookup:
            lint_setup.installed_tool_versions(items=lint_setup.ITEMS[:1])
        self.assertEqual(lookup.call_args.args[1]['PATH'], '/trusted')

    def test_probes_are_bounded_concurrent_and_obey_overall_deadline(self):
        import time
        from dataclasses import replace

        release = threading.Event()
        lock = threading.Lock()
        active = peak = 0
        def blocked_run(argv, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            release.wait(2)
            with lock:
                active -= 1
            return subprocess.CompletedProcess(argv, 0, 'tool 1.2.3', '')

        items = [replace(lint_setup.ITEMS[0], name=f'tool{i}') for i in range(12)]
        try:
            with mock.patch.object(lint_setup, 'which', side_effect=lambda name, env: '/tools/' + name), mock.patch.object(lint_setup, 'run', side_effect=blocked_run):
                started = time.monotonic()
                rows = lint_setup.installed_tool_versions(items=items, timeout_s=1, overall_timeout_s=0.15, max_workers=3)
                elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.8)
            self.assertEqual(peak, 3)
            self.assertEqual([row['name'] for row in rows], [item.name for item in items])
            self.assertTrue(all(row['status'] == 'could_not_verify' and row['error'] for row in rows))
        finally:
            release.set()

    def test_runner_exceptions_do_not_abort_other_probes(self):
        def runner(argv, **kwargs):
            if argv[0].endswith('rustc'):
                raise ValueError('unexpected runner failure')
            return subprocess.CompletedProcess(argv, 0, 'tool 1.2.3', '')

        with mock.patch.object(lint_setup, 'which', side_effect=lambda name, env: '/tools/' + name), mock.patch.object(lint_setup, 'run', side_effect=runner):
            rows = lint_setup.installed_tool_versions(items=lint_setup.ITEMS[:2])
        self.assertEqual(rows[0]['status'], 'could_not_verify')
        self.assertIn('unexpected runner failure', rows[0]['error'])
        self.assertEqual(rows[1]['installed_version'], '1.2.3')

    def test_lint_environment_overlay_wins_over_system_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            managed = root / "managed" / "bin"
            system = root / "system"
            side = root / "venv" / "bin"
            for directory, version in [(managed, "2.6.6"), (system, "1.0.0"), (side, "3.0.0")]:
                directory.mkdir(parents=True)
                exe = directory / "biome"
                exe.write_text(f"#!{sys.executable}\nprint('biome {version}')\n")
                exe.chmod(0o755)
            python = side / "python"
            python.symlink_to(sys.executable)
            (side.parent / "pyvenv.cfg").write_text("home = /unused\n")
            env = {"HOME": tmp, "HERMES_REAL_HOME": tmp, "PATH": str(system),
                   "DEFUZZ_INSTALL_ROOT": str(managed.parent)}
            item = next(i for i in lint_setup.ITEMS if i.name == "biome")
            first = lint_setup.installed_tool_versions(env, items=[item])[0]
            self.assertEqual(first["executable_path"], str(managed / "biome"))
            self.assertEqual(first["status"], "match")
            env["DEFUZZ_LINT_PYTHON"] = str(python)
            second = lint_setup.installed_tool_versions(env, items=[item])[0]
            self.assertEqual(second["executable_path"], str(side / "biome"))
            self.assertEqual(second["installed_version"], "3.0.0")
            self.assertEqual(second["status"], "mismatch")

    def test_wheel_tools_use_plugin_manifest_pins(self):
        with mock.patch.object(lint_setup, "build_env", return_value={"PATH": "/nonexistent"}):
            rows = lint_setup.installed_tool_versions()
        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["ruff"]["expected_version"], "0.15.22")
        self.assertEqual(by_name["ruff"]["status"], "missing")
        self.assertEqual(by_name["ruff"]["kind"], "wheel")
        self.assertEqual(by_name["ruff"]["version"], "0.15.22")
        self.assertEqual(by_name["ruff"]["size_mb"], 0)
        self.assertEqual(by_name["ruff"]["state"], "missing")
        self.assertIn("gdlint", by_name)
        self.assertIn("gdformat", by_name)

    def test_probe_failure_states_and_request_cache(self):
        cases = [
            ("print('biome 1.0.0')", "mismatch", "1.0.0"),
            ("print('not a version')", "could_not_verify", None),
            ("import time; time.sleep(5)", "could_not_verify", None),
            ("raise SystemExit(2)", "could_not_verify", None),
            (None, "missing", None),
        ]
        item = next(i for i in lint_setup.ITEMS if i.name == "biome")
        for script, expected, version in cases:
            with self.subTest(status=expected, script=script), tempfile.TemporaryDirectory() as tmp:
                exe = Path(tmp) / "biome"
                if script:
                    exe.write_text(f"#!{sys.executable}\n{script}\n")
                    exe.chmod(0o755)
                with mock.patch.object(lint_setup, "build_env", return_value={"PATH": tmp}), mock.patch.object(
                    lint_setup, "run", wraps=lint_setup.run
                ) as runner:
                    rows = lint_setup.installed_tool_versions(items=[item, item], timeout_s=0.05)
                    self.assertEqual(runner.call_count, 1 if script else 0)
                    self.assertEqual(rows[0]["status"], expected)
                    self.assertEqual(rows[0]["installed_version"], version)
                    self.assertEqual(rows[0]["executable_path"], str(exe) if script else None)
                    lint_setup.installed_tool_versions(items=[item], timeout_s=0.05)
                    self.assertEqual(runner.call_count, 2 if script else 0)

    def test_go_version_command_and_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "go"
            exe.write_text(f"#!{sys.executable}\nimport sys\nassert sys.argv[1:] == ['version']\nprint('go version go1.27.3 linux/amd64', file=sys.stderr)\n")
            exe.chmod(0o755)
            item = next(i for i in lint_setup.ITEMS if i.name == "go")
            with mock.patch.object(lint_setup, "build_env", return_value={"PATH": tmp}):
                self.assertEqual(lint_setup.installed_tool_versions(items=[item])[0]["status"], "match")


    def test_executable_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "biome"
            exe.write_text(f"#!{sys.executable}\nprint('Version: 2.6.6')\n")
            exe.chmod(0o755)
            item = next(i for i in lint_setup.ITEMS if i.name == "biome")
            with mock.patch.object(lint_setup, "build_env", return_value={"PATH": tmp}):
                rows = lint_setup.installed_tool_versions(items=[item])
            self.assertEqual(rows[0]["installed_version"], "2.6.6")
            self.assertEqual(rows[0]["expected_version"], item.version)
            self.assertEqual(rows[0]["executable_path"], str(exe))
            self.assertEqual(rows[0]["status"], "match")


class TestVersionRange(unittest.TestCase):
    """Installed wheel tools are compared with the manifest range, not its floor."""

    def test_version_in_range_clauses(self):
        cases = [
            ("0.15.22", ">=0.15.22,<0.16", True),     # at floor
            ("0.15.30", ">=0.15.22,<0.16", True),     # inside range
            ("0.15.9", ">=0.15.22,<0.16", False),     # below floor (numeric, not string)
            ("0.16.0", ">=0.15.22,<0.16", False),     # at ceiling
            ("1.0.0", ">=0.15.22,<0.16", False),      # above ceiling
            ("6.0.10", ">=6.0.3,<7", True),
            ("7.0.0", ">=6.0.3,<7", False),
            ("2.6.6", "==2.6.6", True),               # exact pin
            ("2.6.7", "==2.6.6", False),
            ("0.11.0.1", ">=0.11.0.1,<0.12", True),   # four-part at floor
            ("0.11.0.2", ">=0.11.0.1,<0.12", True),
            ("0.11.0.0", ">=0.11.0.1,<0.12", False),
            ("0.11.0", ">=0.11.0.1,<0.12", True),     # binary omits the wheel revision
            ("2.15.1", ">=2.15.1.3,<3", True),
            ("2.15.0", ">=2.15.1.3,<3", False),
            ("0.11.0", "==0.11.0.1", True),
            ("1.2.3-beta", ">=1.0.0,<2", False),      # unparseable installed version
            ("1.2.3", ">=1.x,<2", False),             # unparseable clause
            ("1.2.3", "~=1.2", False),                # unsupported operator
            ("1.2.3", "", False),
        ]
        for installed, spec, expected in cases:
            with self.subTest(installed=installed, spec=spec):
                self.assertIs(lint_setup.version_in_range(installed, spec), expected)

    def test_manifest_ranges_and_floor_pins(self):
        ranges, err = lint_setup._read_wheel_ranges()
        self.assertIsNone(err)
        self.assertEqual(ranges["ruff"], ">=0.15.22,<0.16")
        self.assertEqual(ranges["shellcheck-py"], ">=0.11.0.1,<0.12")
        pins, err = lint_setup._read_wheel_pins()
        self.assertIsNone(err)
        self.assertEqual(pins["ruff"], "0.15.22")
        self.assertEqual(pins["PyYAML"], "6.0.3")

    def test_status_uses_range_for_wheel_tools(self):
        for version, expected in (("0.15.22", "match"), ("0.15.30", "match"),
                                  ("0.15.21", "mismatch"), ("0.16.0", "mismatch")):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                exe = Path(tmp) / "ruff"
                exe.write_text(f"#!{sys.executable}\nprint('ruff {version}')\n")
                exe.chmod(0o755)
                with mock.patch.object(lint_setup, "build_env", return_value={"PATH": tmp}):
                    rows = lint_setup.installed_tool_versions()
                row = next(r for r in rows if r["name"] == "ruff")
                self.assertEqual(row["installed_version"], version)
                self.assertEqual(row["expected_version"], "0.15.22")
                self.assertEqual(row["allowed_versions"], ">=0.15.22,<0.16")
                self.assertEqual(row["status"], expected)


class TestLintSetup(unittest.TestCase):
    """Tests for status, run_setup, describe_plan, and headless_message."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name).resolve()  # the installer refuses a linked ancestor: use the real temp path
        self.inst_root = self.tmp_root / "opt" / "defuzz"
        self.bin_dir = self.inst_root / "bin"
        self.cache_dir = self.tmp_root / "plugin-data" / "defuzz" / "downloads"
        self.fake_home = self.tmp_root / "home"
        self.fake_home.mkdir(parents=True, exist_ok=True)
        self.fixtures_dir = self.tmp_root / "fixtures"
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)
        self.plat = ("linux", "x86_64")

        # Build tiny fixture archives:
        # 1. oxlint-style tar.gz with strip_components=1, binary rename, and post_install
        self.tar_bytes = _make_tar_bytes(
            {
                "pkg-1.0.0/bin/oxlint-x86_64-unknown-linux-gnu": b"#!/bin/sh\necho oxlint\n",
                "pkg-1.0.0/README.txt": b"readme\n",
            }
        )
        self.tar_path = self.fixtures_dir / "oxlint.tar.gz"
        self.tar_path.write_bytes(self.tar_bytes)
        self.tar_hash = _sha256_bytes(self.tar_bytes)

        # 2. stylua-style zip archive
        self.zip_bytes = _make_zip_bytes(
            {
                "stylua": b"#!/bin/sh\necho stylua\n",
            }
        )
        self.zip_path = self.fixtures_dir / "stylua.zip"
        self.zip_path.write_bytes(self.zip_bytes)
        self.zip_hash = _sha256_bytes(self.zip_bytes)

        # 3. rustup-style raw binary archive with post_install
        self.bin_bytes = b"#!/bin/sh\necho rustup-init\n"
        self.bin_path = self.fixtures_dir / "rustup-init"
        self.bin_path.write_bytes(self.bin_bytes)
        self.bin_hash = _sha256_bytes(self.bin_bytes)

        self.url_map: dict[str, Path] = {
            "https://github.com/oxc-project/oxc/releases/download/v1.0.0/oxlint.tar.gz": self.tar_path,
            "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua.zip": self.zip_path,
            "https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-unknown-linux-gnu/rustup-init": self.bin_path,
        }

        self.fake_items = (
            SetupItem(
                name="oxlint",
                kind="binary",
                version="1.0.0",
                homepage="https://oxc.rs/",
                size_mb=20,
                provides=("oxlint",),
                skip_if_on_path=("oxlint",),
                downloads={
                    self.plat: Download(
                        url="https://github.com/oxc-project/oxc/releases/download/v1.0.0/oxlint.tar.gz",
                        hash=self.tar_hash,
                        hash_algo="sha256",
                        hash_source="published",
                        archive="tar.gz",
                        strip_components=1,
                        binaries=(Binary(path="bin/oxlint-x86_64-unknown-linux-gnu", name="oxlint"),),
                        chmod=True,
                    ),
                },
                post_install=(
                    (
                        "{install_dir}/bin/oxlint-x86_64-unknown-linux-gnu",
                        "--init",
                        "{bin_dir}",
                        "{real_home}",
                    ),
                ),
            ),
            SetupItem(
                name="stylua",
                kind="binary",
                version="2.6.0",
                homepage="https://github.com/JohnnyMorganz/StyLua",
                size_mb=10,
                provides=("stylua",),
                skip_if_on_path=("stylua",),
                downloads={
                    self.plat: Download(
                        url="https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/stylua.zip",
                        hash=self.zip_hash,
                        hash_algo="sha256",
                        hash_source="published",
                        archive="zip",
                        strip_components=0,
                        binaries=(Binary(path="stylua", name="stylua"),),
                        chmod=True,
                    ),
                },
                post_install=(),
            ),
            SetupItem(
                name="rustup",
                kind="sdk",
                version="1.29.3",
                homepage="https://rustup.rs/",
                size_mb=70,
                provides=("rustup-init", "rustup", "cargo", "rustfmt", "cargo-clippy"),
                skip_if_on_path=("cargo", "rustfmt", "cargo-clippy"),
                downloads={
                    self.plat: Download(
                        url="https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-unknown-linux-gnu/rustup-init",
                        hash=self.bin_hash,
                        hash_algo="sha256",
                        hash_source="published",
                        archive="binary",
                        strip_components=0,
                        binaries=(Binary(path="rustup-init", name="rustup-init"),),
                        chmod=True,
                    ),
                },
                post_install=(
                    (
                        "{install_dir}/rustup-init",
                        "-y",
                        "--no-modify-path",
                    ),
                ),
            ),
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _fake_fetch(self, url: str, dest: Path, report_cb) -> None:
        src = self.url_map[url]
        data = src.read_bytes()
        dest.parent.mkdir(parents=True, exist_ok=True)
        mid = max(1, len(data) // 2)
        dest.write_bytes(data)
        report_cb(mid, len(data))
        report_cb(len(data), len(data))

    def test_install_root_helper(self) -> None:
        env = {"HERMES_REAL_HOME": str(self.fake_home), "HOME": str(self.fake_home)}
        self.assertEqual(install_root(env), self.fake_home / ".local" / "opt" / "defuzz")

    def test_status_empty_tmp_root_all_missing(self) -> None:
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        self.assertIsInstance(st, SetupStatus)
        self.assertFalse(st.complete)
        self.assertEqual(st.pending_mb, 100)
        self.assertEqual(st.platform, self.plat)
        self.assertEqual(st.install_root, self.inst_root)
        self.assertTrue(st.lazy_installs_allowed)
        self.assertIsNone(st.blocked_reason)
        self.assertEqual([i.state for i in st.items], ["missing", "missing", "missing"])
        self.assertIn("ruff", st.wheels_missing)
        self.assertIn("gdlint", st.wheels_missing)

    def test_status_present_via_marker_and_binary(self) -> None:
        ox_dir = self.inst_root / "oxlint"
        (ox_dir / "bin").mkdir(parents=True, exist_ok=True)
        bin_file = ox_dir / "bin" / "oxlint-x86_64-unknown-linux-gnu"
        bin_file.write_bytes(b"#!/bin/sh\n")
        (ox_dir / ".adopt-installed-1.0.0").write_text("ok\n", encoding="utf-8")

        # Marker + extracted src alone (without exposed bin_dir/oxlint) must NOT count as present
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st_no_dst = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        self.assertEqual({i.name: i.state for i in st_no_dst.items}["oxlint"], "missing")

        self.bin_dir.mkdir(parents=True, exist_ok=True)
        dst_link = self.bin_dir / "oxlint"
        dst_link.symlink_to(bin_file)

        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        by_name = {i.name: i for i in st.items}
        self.assertEqual(by_name["oxlint"].state, "present")
        self.assertEqual(by_name["stylua"].state, "missing")
        self.assertEqual(st.pending_mb, 80)

        # Removing the exposed dst link makes it missing again so setup re-exposes it
        dst_link.unlink()
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st_missing_dst = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        self.assertEqual({i.name: i.state for i in st_missing_dst.items}["oxlint"], "missing")

        # Re-create dst link, then remove underlying src binary -> broken symlink -> missing
        dst_link.symlink_to(bin_file)
        bin_file.unlink()
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st2 = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        self.assertEqual({i.name: i.state for i in st2.items}["oxlint"], "missing")

    def test_status_present_via_skip_if_on_path(self) -> None:
        ext_bin = self.tmp_root / "ext_bin"
        ext_bin.mkdir(parents=True, exist_ok=True)
        for cmd in ("cargo", "rustfmt", "cargo-clippy"):
            exe = ext_bin / cmd
            exe.write_text("#!/bin/sh\n", encoding="utf-8")
            exe.chmod(0o755)

        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st = status(
                platform=self.plat,
                env={"PATH": str(ext_bin)},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        by_name = {i.name: i for i in st.items}
        self.assertEqual(by_name["rustup"].state, "present")
        self.assertEqual(by_name["oxlint"].state, "missing")
        self.assertEqual(st.pending_mb, 30)

    def test_status_unsupported_platform(self) -> None:
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st = status(
                platform=("darwin", "aarch64"),
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        self.assertTrue(all(i.state == "unsupported" for i in st.items))
        self.assertTrue(st.complete)
        self.assertEqual(st.pending_mb, 0)

    def test_blocked_when_lazy_installs_disallowed(self) -> None:
        fetch_called = False

        def forbidden_fetch(url: str, dest: Path, cb) -> None:
            nonlocal fetch_called
            fetch_called = True

        with mock.patch.object(lint_setup, "ITEMS", self.fake_items), mock.patch.object(
            lint_setup, "lazy_installs_allowed", return_value=False
        ):
            st = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
            self.assertFalse(st.lazy_installs_allowed)
            self.assertIsNotNone(st.blocked_reason)
            assert st.blocked_reason is not None
            self.assertIn("security.allow_lazy_installs is false in config.yaml", st.blocked_reason)
            self.assertIn("~100 MB", st.blocked_reason)
            self.assertIn("~/.local/opt/defuzz", st.blocked_reason)

            events: list[Progress] = []
            res = run_setup(
                events.append,
                platform=self.plat,
                env={"PATH": ""},
                fetch=forbidden_fetch,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
            )
            self.assertFalse(res.ok)
            self.assertEqual(res.error, st.blocked_reason)
            self.assertEqual(res.installed, [])
            self.assertFalse(fetch_called)
            self.assertEqual(events, [])

    def test_happy_path_tar_zip_binary_symlinks_post_install_and_progress(self) -> None:
        recorded_runs: list[tuple[list[str], Path, dict[str, str], int]] = []

        def fake_runner(argv: list[str], *, cwd: Path, env: dict[str, str], timeout_s: int):
            recorded_runs.append((list(argv), cwd, dict(env), timeout_s))
            return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

        events: list[Progress] = []
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            res = run_setup(
                events.append,
                platform=self.plat,
                env={"PATH": ""},
                fetch=self._fake_fetch,
                runner=fake_runner,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
            )

        self.assertIsInstance(res, SetupResult)
        self.assertTrue(res.ok, res.error)
        self.assertIsNone(res.error)
        self.assertEqual(res.installed, ["oxlint", "stylua", "rustup"])
        self.assertEqual(res.skipped, [])
        self.assertEqual(res.failed, {})

        # 1. Verify tar.gz with strip_components=1 and symlink rename
        ox_src = self.inst_root / "oxlint" / "bin" / "oxlint-x86_64-unknown-linux-gnu"
        ox_link = self.bin_dir / "oxlint"
        self.assertTrue(ox_src.is_file())
        self.assertTrue((self.inst_root / "oxlint" / ".adopt-installed-1.0.0").is_file())
        self.assertTrue(ox_link.is_symlink())
        self.assertEqual(ox_link.resolve(), ox_src.resolve())
        self.assertTrue(os.access(ox_src, os.X_OK))

        # 2. Verify zip extraction and symlink
        sty_src = self.inst_root / "stylua" / "stylua"
        sty_link = self.bin_dir / "stylua"
        self.assertTrue(sty_src.is_file())
        self.assertTrue((self.inst_root / "stylua" / ".adopt-installed-2.6.0").is_file())
        self.assertTrue(sty_link.is_symlink())
        self.assertEqual(sty_link.resolve(), sty_src.resolve())

        # 3. Verify 'binary' archive and chmod +x (exposed as rustup-init, never bin/rustup)
        rust_src = self.inst_root / "rustup" / "rustup-init"
        rust_link = self.bin_dir / "rustup-init"
        self.assertTrue(rust_src.is_file())
        self.assertTrue(os.access(rust_src, os.X_OK))
        self.assertTrue((self.inst_root / "rustup" / ".adopt-installed-1.29.3").is_file())
        self.assertTrue(rust_link.is_symlink())
        self.assertEqual(rust_link.resolve(), rust_src.resolve())
        self.assertFalse((self.bin_dir / "rustup").exists())
        self.assertFalse((self.bin_dir / "rustup").is_symlink())

        # 4. Verify post_install placeholder substitution and rustup env vars
        self.assertEqual(len(recorded_runs), 2)
        ox_argv, ox_cwd, _, ox_timeout = recorded_runs[0]
        self.assertEqual(
            ox_argv,
            [
                str(ox_src),
                "--init",
                str(self.bin_dir),
                str(self.fake_home),
            ],
        )
        self.assertEqual(ox_cwd, self.inst_root / "oxlint")
        self.assertEqual(ox_timeout, 1800)

        rust_argv, rust_cwd, rust_env, _ = recorded_runs[1]
        self.assertEqual(rust_argv, [str(rust_src), "-y", "--no-modify-path"])
        self.assertEqual(rust_cwd, self.inst_root / "rustup")
        self.assertEqual(rust_env.get("RUSTUP_INIT_SKIP_PATH_CHECK"), "yes")
        self.assertIn("RUSTUP_HOME", rust_env)
        self.assertIn("CARGO_HOME", rust_env)

        # 5. Verify Progress steps and final 100%
        steps_seen = {e.step for e in events}
        for expected_step in ("download", "verify", "extract", "post_install", "done"):
            self.assertIn(expected_step, steps_seen)
        self.assertAlmostEqual(events[-1].percent, 100.0)

        # 6. Re-running setup now skips all 3 items and emits 'skipped'
        events_2: list[Progress] = []
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            st_after = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
            self.assertTrue(st_after.complete)
            self.assertEqual(st_after.pending_mb, 0)

            res2 = run_setup(
                events_2.append,
                platform=self.plat,
                env={"PATH": ""},
                fetch=self._fake_fetch,
                runner=fake_runner,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
            )
        self.assertTrue(res2.ok)
        self.assertEqual(res2.installed, [])
        self.assertEqual(res2.skipped, ["oxlint", "stylua", "rustup"])
        self.assertTrue(all(e.step == "skipped" for e in events_2))
        self.assertAlmostEqual(events_2[-1].percent, 100.0)

    def test_checksum_mismatch_deletes_file_and_stops_before_post_install(self) -> None:
        bad_item = SetupItem(
            name="oxlint",
            kind="binary",
            version="1.0.0",
            homepage="https://oxc.rs/",
            size_mb=20,
            provides=("oxlint",),
            skip_if_on_path=("oxlint",),
            downloads={
                self.plat: Download(
                    url="https://github.com/oxc-project/oxc/releases/download/v1.0.0/oxlint.tar.gz",
                    hash="0" * 64,
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    strip_components=1,
                    binaries=(Binary(path="bin/oxlint-x86_64-unknown-linux-gnu", name="oxlint"),),
                ),
            },
            post_install=(("{install_dir}/bin/oxlint-x86_64-unknown-linux-gnu",),),
        )
        runner_called = False

        def fail_if_called(argv, *, cwd, env, timeout_s):
            nonlocal runner_called
            runner_called = True
            return subprocess.CompletedProcess(argv, 0, "", "")

        events: list[Progress] = []
        with mock.patch.object(lint_setup, "ITEMS", (bad_item, self.fake_items[1])):
            res = run_setup(
                events.append,
                platform=self.plat,
                env={"PATH": ""},
                fetch=self._fake_fetch,
                runner=fail_if_called,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
            )

        self.assertFalse(res.ok)
        self.assertIn("oxlint", res.failed)
        self.assertIn("checksum mismatch for", res.failed["oxlint"])
        self.assertIn("expected " + ("0" * 64), res.failed["oxlint"])
        self.assertIn("got " + self.tar_hash, res.failed["oxlint"])
        self.assertEqual(res.installed, [])
        self.assertFalse(runner_called)
        # Cached file must be deleted on checksum mismatch
        cached_file = self.cache_dir / "oxlint-1.0.0-oxlint.tar.gz"
        self.assertFalse(cached_file.exists())

    def test_tar_with_path_traversal_and_unsafe_symlink_rejected(self) -> None:
        evil_tar = _make_tar_bytes({"../evil.sh": b"#!/bin/sh\necho pwned\n"})
        evil_path = self.fixtures_dir / "evil.tar.gz"
        evil_path.write_bytes(evil_tar)
        evil_url = "https://github.com/oxc-project/oxc/releases/download/v1.0.0/evil.tar.gz"
        self.url_map[evil_url] = evil_path

        evil_item = SetupItem(
            name="evil",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/oxc-project/oxc",
            size_mb=5,
            provides=("evil",),
            skip_if_on_path=("evil",),
            downloads={
                self.plat: Download(
                    url=evil_url,
                    hash=_sha256_bytes(evil_tar),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    strip_components=0,
                    binaries=(Binary(path="evil.sh", name="evil"),),
                ),
            },
        )
        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(evil_item,),
        )
        self.assertFalse(res.ok)
        self.assertIn("evil", res.failed)
        self.assertFalse((self.inst_root / "evil.sh").exists())
        self.assertFalse((self.tmp_root / "evil.sh").exists())

        # Also test symlink pointing outside extraction root
        sym_tar = _make_tar_bytes({"escape": ("symlink", "../../etc/passwd")})
        sym_path = self.fixtures_dir / "sym.tar.gz"
        sym_path.write_bytes(sym_tar)
        sym_url = "https://github.com/oxc-project/oxc/releases/download/v1.0.0/sym.tar.gz"
        self.url_map[sym_url] = sym_path
        sym_item = SetupItem(
            name="sym",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/oxc-project/oxc",
            size_mb=5,
            provides=("sym",),
            skip_if_on_path=("sym",),
            downloads={
                self.plat: Download(
                    url=sym_url,
                    hash=_sha256_bytes(sym_tar),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    strip_components=0,
                    binaries=(Binary(path="escape", name="sym"),),
                ),
            },
        )
        res_sym = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(sym_item,),
        )
        self.assertFalse(res_sym.ok)
        self.assertIn("sym", res_sym.failed)

    def test_zip_with_path_traversal_rejected(self) -> None:
        evil_zip = _make_zip_bytes({"../evil_zip.sh": b"pwn"})
        evil_zip_path = self.fixtures_dir / "evil.zip"
        evil_zip_path.write_bytes(evil_zip)
        url = "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/evil.zip"
        self.url_map[url] = evil_zip_path

        item = SetupItem(
            name="evilzip",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/JohnnyMorganz/StyLua",
            size_mb=5,
            provides=("evilzip",),
            skip_if_on_path=("evilzip",),
            downloads={
                self.plat: Download(
                    url=url,
                    hash=_sha256_bytes(evil_zip),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="zip",
                    strip_components=0,
                    binaries=(Binary(path="evil_zip.sh", name="evilzip"),),
                ),
            },
        )
        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(item,),
        )
        self.assertFalse(res.ok)
        self.assertIn("evilzip", res.failed)
        self.assertFalse((self.inst_root / "evil_zip.sh").exists())

    def test_cancel_event_honoured(self) -> None:
        cancel = threading.Event()

        def cancelling_fetch(url: str, dest: Path, report_cb) -> None:
            src = self.url_map[url]
            data = src.read_bytes()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            cancel.set()
            report_cb(len(data), len(data))

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=cancelling_fetch,
            cancel=cancel,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=self.fake_items,
        )
        self.assertFalse(res.ok)
        self.assertEqual(res.error, "cancelled")
        self.assertEqual(res.installed, [])

    def test_post_install_nonzero_exit_fails_closed(self) -> None:
        def failing_runner(argv, *, cwd, env, timeout_s):
            return subprocess.CompletedProcess(argv, 2, stdout="", stderr="fatal: network error\n")

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            runner=failing_runner,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
        )
        self.assertFalse(res.ok)
        self.assertIn("oxlint", res.failed)
        self.assertIn("fatal: network error", res.failed["oxlint"])
        self.assertFalse((self.inst_root / "oxlint" / ".adopt-installed-1.0.0").exists())

    def test_dotnet_post_install_env_and_windows_copy(self) -> None:
        win_plat = ("windows", "x86_64")
        dotnet_zip = _make_zip_bytes({"dotnet.exe": b"MZ-fake-dotnet"})
        dotnet_path = self.fixtures_dir / "dotnet.zip"
        dotnet_path.write_bytes(dotnet_zip)
        url = "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.427/dotnet-sdk-8.0.427-win-x64.zip"
        self.url_map[url] = dotnet_path

        dotnet_item = SetupItem(
            name="dotnet",
            kind="sdk",
            version="8.0.427",
            homepage="https://dotnet.microsoft.com/",
            size_mb=450,
            provides=("dotnet", "csharpier"),
            skip_if_on_path=("dotnet",),
            downloads={
                win_plat: Download(
                    url=url,
                    hash=_sha512_bytes(dotnet_zip),
                    hash_algo="sha512",
                    hash_source="published",
                    archive="zip",
                    strip_components=0,
                    binaries=(Binary(path="dotnet.exe", name="dotnet"),),
                ),
            },
            post_install=(
                (
                    "{install_dir}/dotnet",
                    "tool",
                    "install",
                    "csharpier",
                    "--version",
                    "1.3.0",
                    "--tool-path",
                    "{bin_dir}",
                ),
            ),
        )
        captured_envs: list[dict[str, str]] = []

        def win_runner(argv, *, cwd, env, timeout_s):
            captured_envs.append(dict(env))
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

        res = run_setup(
            lambda _: None,
            platform=win_plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            runner=win_runner,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(dotnet_item,),
        )
        self.assertTrue(res.ok, res.error)
        bin_copy = self.bin_dir / "dotnet.exe"
        self.assertTrue(bin_copy.is_file())
        self.assertFalse(bin_copy.is_symlink())
        self.assertEqual(len(captured_envs), 1)
        self.assertEqual(captured_envs[0]["DOTNET_ROOT"], str(self.inst_root / "dotnet"))
        self.assertEqual(captured_envs[0]["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")
        self.assertEqual(captured_envs[0]["DOTNET_NOLOGO"], "1")

    def test_describe_plan_and_headless_message(self) -> None:
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            plan = describe_plan(
                platform=self.plat,
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
            msg = headless_message(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
        self.assertEqual(len(plan), 3)
        first = plan[0]
        self.assertEqual(first["name"], "oxlint")
        self.assertEqual(first["version"], "1.0.0")
        self.assertEqual(first["size_mb"], 20)
        self.assertEqual(first["hash_algo"], "sha256")
        self.assertEqual(first["install_dir"], str(self.inst_root / "oxlint"))
        self.assertTrue(first["post_install"])
        self.assertIn(str(self.bin_dir), " ".join(first["post_install"]))

        self.assertIn("Lint-tool setup is pending.", msg)
        self.assertIn("~100 MB", msg)
        self.assertIn("hermes defuzz setup-tools --yes", msg)

    def test_tar_xz_and_default_fetch_and_bool_lazy_flag(self) -> None:
        xz_bytes = _make_tar_bytes({"bin/tool_xz": b"#!/bin/sh\necho xz\n"}, compression="xz")
        xz_hash = _sha256_bytes(xz_bytes)
        url = "https://github.com/KhronosGroup/glslang/releases/download/16.6.0/tool.tar.xz"
        xz_item = SetupItem(
            name="xztool",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/KhronosGroup/glslang",
            size_mb=5,
            provides=("tool_xz",),
            skip_if_on_path=("tool_xz",),
            downloads={
                self.plat: Download(
                    url=url,
                    hash=xz_hash,
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.xz",
                    strip_components=1,
                    binaries=(Binary(path="tool_xz", name="tool_xz"),),
                ),
            },
        )

        class _FakeResp:
            def __init__(self, payload: bytes) -> None:
                self._buf = io.BytesIO(payload)
                self.headers = {"Content-Length": str(len(payload))}

            def read(self, n: int = -1) -> bytes:
                return self._buf.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        captured_reqs: list[tuple[urllib.request.Request, int | None]] = []

        def fake_urlopen(req: urllib.request.Request, timeout: int | None = None):
            captured_reqs.append((req, timeout))
            return _FakeResp(xz_bytes)

        class _FakeOpener:
            def __init__(self, *handlers) -> None:
                self.handlers = handlers

            def open(self, req, timeout=None):
                return fake_urlopen(req, timeout=timeout)

        with mock.patch("urllib.request.build_opener", side_effect=_FakeOpener):
            res = run_setup(
                lambda _: None,
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(xz_item,),
            )
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.installed, ["xztool"])
        self.assertTrue((self.bin_dir / "tool_xz").is_symlink())
        self.assertEqual(len(captured_reqs), 1)
        req_obj, timeout_val = captured_reqs[0]
        self.assertEqual(timeout_val, 60)
        import yaml
        version = yaml.safe_load((Path(lint_setup.__file__).with_name("plugin.yaml")).read_text(encoding="utf-8"))["version"]
        self.assertEqual(req_obj.get_header("User-agent"), f"defuzz/{version}")
        self.assertNotIn("hermes", req_obj.get_header("User-agent"))

        # Also verify monkeypatching lazy_installs_allowed with a boolean False
        with mock.patch.object(lint_setup, "lazy_installs_allowed", False):
            st_blocked = status(
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
                items=(xz_item,),
            )
            self.assertFalse(st_blocked.lazy_installs_allowed)
            self.assertIsNotNone(st_blocked.blocked_reason)

    def test_hermes_optional_imports_fail_gracefully(self) -> None:
        import importlib
        import types

        class _Raiser(types.ModuleType):
            def __getattr__(self, name: str):
                raise RuntimeError("hermes unavailable")

        saved = {
            k: sys.modules.get(k)
            for k in ("hermes_plugins.defuzz.lint_setup", "pm", "plugins", "plugins.plugin_storage")
        }
        try:
            sys.modules["pm"] = _Raiser("pm")
            sys.modules["plugins"] = _Raiser("plugins")
            sys.modules["plugins.plugin_storage"] = _Raiser("plugins.plugin_storage")
            sys.modules.pop("hermes_plugins.defuzz.lint_setup", None)
            mod = importlib.import_module("hermes_plugins.defuzz.lint_setup")
            self.assertTrue(mod.lazy_installs_allowed())
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_verify_to_extract_toctou_isolated_from_cache_swap(self) -> None:
        tampered_tar = _make_tar_bytes(
            {
                "pkg-1.0.0/bin/oxlint-x86_64-unknown-linux-gnu": b"#!/bin/sh\necho PWNED\n",
            }
        )
        cached_file = self.cache_dir / "oxlint-1.0.0-oxlint.tar.gz"

        def swapping_progress(ev: Progress) -> None:
            if ev.item == "oxlint" and ev.step == "extract":
                cached_file.write_bytes(tampered_tar)

        res = run_setup(
            swapping_progress,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
            runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""),
        )
        self.assertTrue(res.ok, res.error)
        installed_bin = self.inst_root / "oxlint" / "bin" / "oxlint-x86_64-unknown-linux-gnu"
        self.assertEqual(installed_bin.read_bytes(), b"#!/bin/sh\necho oxlint\n")

    def test_symlink_chain_zip_slip_rejected_in_zip_and_tar(self) -> None:
        # 1. Zip with a crafted symlink chain: d -> . then b -> d/../victim
        chain_zip = _make_zip_bytes(
            {
                "d": ("symlink", "."),
                "b": ("symlink", "d/../victim_zip"),
                "tool": b"#!/bin/sh\necho ok\n",
            }
        )
        zip_path = self.fixtures_dir / "chain.zip"
        zip_path.write_bytes(chain_zip)
        zip_url = "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/chain.zip"
        self.url_map[zip_url] = zip_path

        zip_item = SetupItem(
            name="chainzip",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/JohnnyMorganz/StyLua",
            size_mb=1,
            provides=("chainzip",),
            skip_if_on_path=("chainzip",),
            downloads={
                self.plat: Download(
                    url=zip_url,
                    hash=_sha256_bytes(chain_zip),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="zip",
                    strip_components=0,
                    binaries=(Binary(path="tool", name="chainzip"),),
                ),
            },
        )
        res_zip = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(zip_item,),
        )
        self.assertFalse(res_zip.ok)
        self.assertIn("chainzip", res_zip.failed)

        # Internal relative symlinks are supported (upstream glslang uses one).
        benign_sym_zip = _make_zip_bytes(
            {
                "tool": b"#!/bin/sh\necho ok\n",
                "alias": ("symlink", "tool"),
            }
        )
        bzip_path = self.fixtures_dir / "benign_sym.zip"
        bzip_path.write_bytes(benign_sym_zip)
        bzip_url = "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/benign_sym.zip"
        self.url_map[bzip_url] = bzip_path
        bzip_item = SetupItem(
            name="bzip",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/JohnnyMorganz/StyLua",
            size_mb=1,
            provides=("bzip",),
            skip_if_on_path=("bzip",),
            downloads={
                self.plat: Download(
                    url=bzip_url,
                    hash=_sha256_bytes(benign_sym_zip),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="zip",
                    strip_components=0,
                    binaries=(Binary(path="tool", name="bzip"),),
                ),
            },
        )
        res_bzip = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(bzip_item,),
        )
        self.assertTrue(res_bzip.ok)

        # 2. Tar with a crafted symlink chain: d -> . then b -> d/../victim_tar
        # Verify our own realpath check catches it even without tarfile.data_filter
        chain_tar = _make_tar_bytes(
            {
                "d": ("symlink", "."),
                "b": ("symlink", "d/../victim_tar"),
                "tool": b"#!/bin/sh\necho ok\n",
            }
        )
        tar_path = self.fixtures_dir / "chain.tar.gz"
        tar_path.write_bytes(chain_tar)
        tar_url = "https://github.com/oxc-project/oxc/releases/download/v1.0.0/chain.tar.gz"
        self.url_map[tar_url] = tar_path

        tar_item = SetupItem(
            name="chaintar",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/oxc-project/oxc",
            size_mb=1,
            provides=("chaintar",),
            skip_if_on_path=("chaintar",),
            downloads={
                self.plat: Download(
                    url=tar_url,
                    hash=_sha256_bytes(chain_tar),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    strip_components=0,
                    binaries=(Binary(path="tool", name="chaintar"),),
                ),
            },
        )
        res_tar = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(tar_item,),
        )
        self.assertFalse(res_tar.ok)
        self.assertIn("chaintar", res_tar.failed)

        # 3. Hardlink in tar must be rejected
        hl_buf = io.BytesIO()
        with tarfile.open(fileobj=hl_buf, mode="w:gz") as tf:
            ti_file = tarfile.TarInfo("tool")
            payload = b"#!/bin/sh\necho ok\n"
            ti_file.size = len(payload)
            ti_file.mode = 0o755
            tf.addfile(ti_file, io.BytesIO(payload))
            ti_lnk = tarfile.TarInfo("tool_hardlink")
            ti_lnk.type = tarfile.LNKTYPE
            ti_lnk.linkname = "tool"
            tf.addfile(ti_lnk)
        hl_bytes = hl_buf.getvalue()
        hl_path = self.fixtures_dir / "hl.tar.gz"
        hl_path.write_bytes(hl_bytes)
        hl_url = "https://github.com/oxc-project/oxc/releases/download/v1.0.0/hl.tar.gz"
        self.url_map[hl_url] = hl_path
        hl_item = SetupItem(
            name="hltar",
            kind="binary",
            version="1.0.0",
            homepage="https://github.com/oxc-project/oxc",
            size_mb=1,
            provides=("hltar",),
            skip_if_on_path=("hltar",),
            downloads={
                self.plat: Download(
                    url=hl_url,
                    hash=_sha256_bytes(hl_bytes),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="tar.gz",
                    strip_components=0,
                    binaries=(Binary(path="tool", name="hltar"),),
                ),
            },
        )
        res_hl = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(hl_item,),
        )
        self.assertFalse(res_hl.ok)
        self.assertIn("hltar", res_hl.failed)

    def test_atomic_replace_restores_old_install_on_replace_failure(self) -> None:
        old_dir = self.inst_root / "stylua"
        old_dir.mkdir(parents=True, exist_ok=True)
        old_bin = old_dir / "stylua"
        old_bin.write_bytes(b"#!/bin/sh\necho old-stylua\n")
        old_extra = old_dir / "keep.txt"
        old_extra.write_text("precious", encoding="utf-8")

        real_replace = os.replace

        def flaky_replace(src, dst, *args, **kwargs):
            if Path(dst) == old_dir and ".stylua-tmp-" in Path(src).name:
                raise OSError("simulated rename failure into install_dir")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch("os.replace", side_effect=flaky_replace):
            res = run_setup(
                lambda _: None,
                platform=self.plat,
                env={"PATH": ""},
                fetch=self._fake_fetch,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.fake_items[1],),
            )
        self.assertFalse(res.ok)
        self.assertIn("stylua", res.failed)
        self.assertTrue(old_dir.is_dir())
        self.assertEqual(old_bin.read_bytes(), b"#!/bin/sh\necho old-stylua\n")
        self.assertEqual(old_extra.read_text(encoding="utf-8"), "precious")
        self.assertEqual(list(self.inst_root.glob("stylua.old-*")), [])

    def test_guarded_rmtree_rejects_unmanaged_install_root_and_preserves_files(self) -> None:
        personal = self.fake_home / "oxlint" / "personal.txt"
        personal.parent.mkdir(parents=True, exist_ok=True)
        personal.write_text("do not delete me", encoding="utf-8")

        with self.assertRaises(SetupError):
            lint_setup._assert_managed_path(self.fake_home / "oxlint", self.fake_home)

        with self.assertRaises(SetupError):
            lint_setup._assert_managed_path(Path("/"), Path("/"))

        with self.assertRaises(SetupError):
            lint_setup._assert_managed_path(Path("/tmp/a"), Path("/tmp"))

        with self.assertRaises(SetupError):
            lint_setup._assert_managed_path(self.inst_root, self.inst_root)

        with self.assertRaises(SetupError):
            lint_setup._extract_artifact(
                self.tar_path,
                self.fake_items[0].downloads[self.plat],
                self.fake_home / "oxlint",
                self.fake_home,
                None,
            )
        self.assertTrue(personal.is_file())

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.fake_home,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
        )
        self.assertFalse(res.ok)
        self.assertTrue(personal.is_file())
        self.assertEqual(personal.read_text(encoding="utf-8"), "do not delete me")

    def test_upgrade_detected_when_old_version_in_managed_bin_dir(self) -> None:
        # Install oxlint 1.0.0 first
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""),
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
        )
        self.assertTrue(res1.ok)
        self.assertTrue((self.inst_root / "oxlint" / ".adopt-installed-1.0.0").is_file())
        self.assertTrue((self.bin_dir / "oxlint").exists())

        # Now manifest bumps oxlint to 2.0.0
        upgraded_item = SetupItem(
            name="oxlint",
            kind="binary",
            version="2.0.0",
            homepage="https://oxc.rs/",
            size_mb=20,
            provides=("oxlint",),
            skip_if_on_path=("oxlint",),
            downloads=self.fake_items[0].downloads,
            post_install=(),
        )
        st = status(
            platform=self.plat,
            env={"PATH": ""},
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(upgraded_item,),
        )
        self.assertEqual(st.items[0].state, "missing")
        self.assertFalse(st.complete)

        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(upgraded_item,),
        )
        self.assertTrue(res2.ok)
        self.assertEqual(res2.installed, ["oxlint"])
        self.assertTrue((self.inst_root / "oxlint" / ".adopt-installed-2.0.0").is_file())

    def test_failed_post_install_cleans_up_and_second_run_retries(self) -> None:
        attempts = 0

        def flaky_runner(argv, *, cwd, env, timeout_s):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="transient error")
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            runner=flaky_runner,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
        )
        self.assertFalse(res1.ok)
        self.assertIn("oxlint", res1.failed)
        # Bin symlink must NOT have been exposed before post_install succeeded,
        # and partial install_dir must be cleaned up.
        self.assertFalse((self.bin_dir / "oxlint").exists())
        self.assertFalse((self.bin_dir / "oxlint").is_symlink())
        self.assertFalse((self.inst_root / "oxlint").exists())

        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            runner=flaky_runner,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
        )
        self.assertTrue(res2.ok, res2.error)
        self.assertEqual(res2.installed, ["oxlint"])
        self.assertEqual(attempts, 2)
        self.assertTrue((self.bin_dir / "oxlint").is_symlink())
        self.assertTrue((self.inst_root / "oxlint" / ".adopt-installed-1.0.0").is_file())

    def test_outer_exception_and_progress_callback_exception_handled(self) -> None:
        # 1. Error in status / env preparation returns SetupResult(ok=False) instead of raising
        with mock.patch.object(lint_setup, "status", side_effect=RuntimeError("boom in status")):
            res_err = run_setup(
                lambda _: None,
                platform=self.plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.fake_items[1],),
            )
        self.assertFalse(res_err.ok)
        self.assertIn("boom in status", res_err.error or "")

        # 2. Raising progress callback is caught, logged, and does not abort install
        def broken_progress(ev: Progress) -> None:
            raise ValueError(f"ui crash on {ev.step}")

        res_ok = run_setup(
            broken_progress,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[1],),
        )
        self.assertTrue(res_ok.ok, res_ok.error)
        self.assertEqual(res_ok.installed, ["stylua"])
        self.assertTrue(any("ui crash" in entry for entry in res_ok.log))

    def test_concurrent_run_setup_blocked_by_lock_and_stale_lock_recovered(self) -> None:
        in_fetch = threading.Event()
        release_fetch = threading.Event()

        def blocking_fetch(url: str, dest: Path, report_cb) -> None:
            in_fetch.set()
            release_fetch.wait(timeout=5.0)
            self._fake_fetch(url, dest, report_cb)

        first_result: list[SetupResult] = []

        def run_first() -> None:
            res = run_setup(
                lambda _: None,
                platform=self.plat,
                env={"PATH": ""},
                fetch=blocking_fetch,
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
                items=(self.fake_items[1],),
            )
            first_result.append(res)

        t1 = threading.Thread(target=run_first)
        t1.start()
        self.assertTrue(in_fetch.wait(timeout=5.0))

        # Second concurrent caller must fail immediately with lock error
        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[1],),
        )
        self.assertFalse(res2.ok)
        self.assertEqual(res2.error, f"setup already running (pid {os.getpid()})")

        release_fetch.set()
        t1.join(timeout=5.0)
        self.assertEqual(len(first_result), 1)
        self.assertTrue(first_result[0].ok, first_result[0].error)
        self.assertFalse((self.inst_root / ".adopt-setup.lock").exists())

        # Stale lock with dead PID is recovered on next run
        lock_file = self.inst_root / ".adopt-setup.lock"
        lock_file.write_text("99999999\n", encoding="utf-8")
        res3 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[1],),
        )
        self.assertTrue(res3.ok, res3.error)
        self.assertFalse(lock_file.exists())

    def test_default_cache_dir_uses_hermes_constants_get_hermes_home(self) -> None:
        import types

        custom_hermes = self.tmp_root / "custom_hermes_from_constants"
        fake_hc = types.ModuleType("hermes_constants")
        fake_hc.get_hermes_home = lambda: custom_hermes  # type: ignore[attr-defined]

        with mock.patch.object(lint_setup, "_hermes_plugin_data_dir", None), mock.patch.dict(
            sys.modules, {"hermes_constants": fake_hc}
        ):
            got = lint_setup.default_cache_dir()
            self.assertEqual(
                got,
                custom_hermes / "plugin-data" / "defuzz" / "downloads",
            )

        # When hermes_constants is unavailable, falls back to HERMES_HOME env then ~/.hermes
        class _BrokenHC(types.ModuleType):
            def __getattr__(self, name: str):
                raise RuntimeError("hermes_constants unavailable")

        env_hermes = self.tmp_root / "env_hermes_home"
        with mock.patch.object(lint_setup, "_hermes_plugin_data_dir", None), mock.patch.dict(
            sys.modules, {"hermes_constants": _BrokenHC("hermes_constants")}
        ), mock.patch.dict(os.environ, {"HERMES_HOME": str(env_hermes)}, clear=False):
            got_env = lint_setup.default_cache_dir()
            self.assertEqual(
                got_env,
                env_hermes / "plugin-data" / "defuzz" / "downloads",
            )

        with mock.patch.object(lint_setup, "_hermes_plugin_data_dir", None), mock.patch.dict(
            sys.modules, {"hermes_constants": _BrokenHC("hermes_constants")}
        ), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HERMES_HOME", None)
            got_default = lint_setup.default_cache_dir()
            self.assertEqual(
                got_default,
                Path("~/.hermes").expanduser() / "plugin-data" / "defuzz" / "downloads",
            )

    def test_missing_dst_link_triggers_re_expose_on_run_setup(self) -> None:
        # Install stylua normally
        res1 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[1],),
        )
        self.assertTrue(res1.ok, res1.error)
        sty_link = self.bin_dir / "stylua"
        self.assertTrue(sty_link.is_symlink())
        self.assertTrue((self.inst_root / "stylua" / ".adopt-installed-2.6.0").is_file())

        # Remove the exposed bin/stylua symlink while marker and extracted binary remain
        sty_link.unlink()
        st = status(
            platform=self.plat,
            env={"PATH": ""},
            install_root=self.inst_root,
            real_home=self.fake_home,
            items=(self.fake_items[1],),
        )
        self.assertEqual(st.items[0].state, "missing")

        # Running setup again re-exposes bin/stylua
        res2 = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[1],),
        )
        self.assertTrue(res2.ok, res2.error)
        self.assertEqual(res2.installed, ["stylua"])
        self.assertTrue(sty_link.is_symlink())
        self.assertTrue(sty_link.is_file())

    def test_symlinked_install_root_pointing_at_dot_hermes_is_refused(self) -> None:
        dot_hermes = self.tmp_root / "deep" / "nested" / ".hermes"
        dot_hermes.mkdir(parents=True, exist_ok=True)
        precious = dot_hermes / "oxlint" / "config.yaml"
        precious.parent.mkdir(parents=True, exist_ok=True)
        precious.write_text("secret: keep", encoding="utf-8")

        # Unresolved path ends with .local/opt/defuzz, but resolves to a .hermes directory
        spoofed_parent = self.tmp_root / "spoof" / ".local" / "opt"
        spoofed_parent.mkdir(parents=True, exist_ok=True)
        spoofed_root = spoofed_parent / "defuzz"
        spoofed_root.symlink_to(dot_hermes)

        with self.assertRaises(SetupError):
            lint_setup._assert_managed_path(
                spoofed_root / "oxlint",
                spoofed_root,
                r_home=self.fake_home,
            )

        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=spoofed_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(self.fake_items[0],),
        )
        self.assertFalse(res.ok)
        self.assertTrue(precious.is_file())
        self.assertEqual(precious.read_text(encoding="utf-8"), "secret: keep")

    def test_drive_letters_after_strip_components_and_backslash_zip_dirs(self) -> None:
        # 1. Drive letter in remaining part after strip_components=1 must be rejected
        with self.assertRaises(SetupError):
            lint_setup._validate_and_strip_member_path("pkg/C:/evil.exe", 1, self.inst_root)
        with self.assertRaises(SetupError):
            lint_setup._validate_and_strip_member_path("pkg/sub/D:evil.exe", 1, self.inst_root)

        # 2. Zip entry ending with backslash must be treated as a directory, not opened as a file
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zi_dir = zipfile.ZipInfo(filename="sub\\")
            zi_dir.external_attr = (0o040755 & 0xFFFF) << 16
            zf.writestr(zi_dir, b"")
            zi_file = zipfile.ZipInfo(filename="sub\\stylua")
            zi_file.external_attr = (0o100755 & 0xFFFF) << 16
            zf.writestr(zi_file, b"#!/bin/sh\necho stylua\n")
        bs_zip_bytes = buf.getvalue()
        bs_zip_path = self.fixtures_dir / "bs_dir.zip"
        bs_zip_path.write_bytes(bs_zip_bytes)
        bs_url = "https://github.com/JohnnyMorganz/StyLua/releases/download/v2.6.0/bs_dir.zip"
        self.url_map[bs_url] = bs_zip_path

        bs_item = SetupItem(
            name="stylua",
            kind="binary",
            version="2.6.0",
            homepage="https://github.com/JohnnyMorganz/StyLua",
            size_mb=1,
            provides=("stylua",),
            skip_if_on_path=("stylua",),
            downloads={
                self.plat: Download(
                    url=bs_url,
                    hash=_sha256_bytes(bs_zip_bytes),
                    hash_algo="sha256",
                    hash_source="published",
                    archive="zip",
                    strip_components=0,
                    binaries=(Binary(path="sub/stylua", name="stylua"),),
                ),
            },
        )
        res = run_setup(
            lambda _: None,
            platform=self.plat,
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(bs_item,),
        )
        self.assertTrue(res.ok, res.error)
        self.assertTrue((self.inst_root / "stylua" / "sub").is_dir())
        self.assertTrue((self.inst_root / "stylua" / "sub" / "stylua").is_file())
        self.assertTrue((self.bin_dir / "stylua").is_symlink())

    def test_prepare_env_managed_bin_wins_over_cargo_bin_and_rust_proxies_resolve_from_cargo_home(self) -> None:
        cargo_bin = self.fake_home / ".cargo" / "bin"
        cargo_bin.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)

        for tool in ("stylua", "selene"):
            for d in (self.bin_dir, cargo_bin):
                exe = d / tool
                exe.write_text("#!/bin/sh\n", encoding="utf-8")
                exe.chmod(0o755)

        for proxy in ("rustup", "cargo"):
            exe = cargo_bin / proxy
            exe.write_text("#!/bin/sh\n", encoding="utf-8")
            exe.chmod(0o755)

        eff = lint_setup._prepare_env(
            {"PATH": ""},
            inst_root=self.inst_root,
            b_dir=self.bin_dir,
            r_home=self.fake_home,
            paths={
                "install_root": self.inst_root,
                "bin_dir": self.bin_dir,
                "real_home": self.fake_home,
            },
        )
        path_entries = eff["PATH"].split(os.pathsep)
        self.assertLess(path_entries.index(str(self.bin_dir)), path_entries.index(str(cargo_bin)))
        self.assertEqual(lint_setup.which("stylua", eff, is_windows=False), str(self.bin_dir / "stylua"))
        self.assertEqual(lint_setup.which("selene", eff, is_windows=False), str(self.bin_dir / "selene"))
        self.assertEqual(lint_setup.which("rustup", eff, is_windows=False), str(cargo_bin / "rustup"))
        self.assertEqual(lint_setup.which("cargo", eff, is_windows=False), str(cargo_bin / "cargo"))

    def test_legacy_bin_rustup_removed_on_setup_and_no_rust_proxies_in_managed_bin_dir(self) -> None:
        # 1. Create a pre-existing managed rustup installation with legacy bin/rustup link
        rust_dir = self.inst_root / "rustup"
        rust_dir.mkdir(parents=True, exist_ok=True)
        rust_init = rust_dir / "rustup-init"
        rust_init.write_bytes(self.bin_bytes)
        rust_init.chmod(0o755)
        (rust_dir / ".adopt-installed-1.29.3").write_text("rustup 1.29.3\n", encoding="utf-8")

        self.bin_dir.mkdir(parents=True, exist_ok=True)
        (self.bin_dir / "rustup-init").symlink_to(rust_init)
        legacy_rustup = self.bin_dir / "rustup"
        legacy_rustup.symlink_to(rust_init)
        self.assertTrue(legacy_rustup.is_symlink())

        removed_paths: list[Path] = []
        orig_remove = lint_setup._remove_managed_path

        def spy_remove(p: Path, inst_root: Path, **kwargs):
            removed_paths.append(p)
            return orig_remove(p, inst_root, **kwargs)

        with mock.patch.object(lint_setup, "ITEMS", self.fake_items), mock.patch.object(
            lint_setup, "_remove_managed_path", side_effect=spy_remove
        ):
            res = run_setup(
                lambda _: None,
                platform=self.plat,
                env={"PATH": ""},
                fetch=self._fake_fetch,
                runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""),
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
            )

        self.assertTrue(res.ok, res.error)
        self.assertIn("rustup", res.skipped)
        self.assertIn(legacy_rustup, removed_paths)
        self.assertFalse(legacy_rustup.exists())
        self.assertFalse(legacy_rustup.is_symlink())
        self.assertTrue((self.bin_dir / "rustup-init").is_symlink())

        # Verify managed bin_dir never contains any Rust proxy names
        forbidden_proxies = {
            "rustup",
            "cargo",
            "rustc",
            "rustfmt",
            "cargo-fmt",
            "cargo-clippy",
            "clippy-driver",
        }
        bin_names = {
            p.name[:-4] if p.name.endswith(".exe") else p.name
            for p in self.bin_dir.iterdir()
        }
        self.assertTrue(bin_names.isdisjoint(forbidden_proxies), f"Found forbidden proxies in {bin_names}")

        # 2. If bin/rustup points OUTSIDE managed rustup install, migration leaves it untouched
        outside_target = self.tmp_root / "external_rustup"
        outside_target.write_text("#!/bin/sh\n", encoding="utf-8")
        outside_target.chmod(0o755)
        legacy_rustup.symlink_to(outside_target)
        with mock.patch.object(lint_setup, "ITEMS", self.fake_items):
            res_ext = run_setup(
                lambda _: None,
                platform=self.plat,
                env={"PATH": ""},
                fetch=self._fake_fetch,
                runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""),
                install_root=self.inst_root,
                cache_dir=self.cache_dir,
                real_home=self.fake_home,
            )
        self.assertTrue(res_ext.ok, res_ext.error)
        self.assertTrue(legacy_rustup.is_symlink())
        self.assertEqual(legacy_rustup.resolve(), outside_target.resolve())

    def test_aarch64_markers_in_plugin_yaml_and_arm_binary_setup_tier(self) -> None:
        import gzip
        import yaml

        plugin_yaml = Path(__file__).resolve().parent.parent / "plugin.yaml"
        manifest = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
        deps = manifest.get("python_dependencies", [])
        self.assertIn(
            "taplo>=0.9.3,<0.10; platform_machine != 'aarch64' and platform_machine != 'ARM64'",
            deps,
        )
        self.assertIn(
            "shellcheck-py>=0.11.0.1,<0.12; platform_machine != 'aarch64' and platform_machine != 'ARM64'",
            deps,
        )

        # On aarch64, downloads_for and status include taplo and shellcheck in the binary tier,
        # and wheels_missing excludes them (since they are binary setup items on ARM).
        for arm_plat in (("linux", "aarch64"), ("darwin", "aarch64")):
            arm_pairs = lint_setup.downloads_for(arm_plat)
            arm_names = [it.name for it, _ in arm_pairs]
            self.assertIn("taplo", arm_names)
            self.assertIn("shellcheck", arm_names)

            st_arm = status(
                platform=arm_plat,
                env={"PATH": ""},
                install_root=self.inst_root,
                real_home=self.fake_home,
            )
            st_item_names = {i.name: i.state for i in st_arm.items}
            self.assertEqual(st_item_names.get("taplo"), "missing")
            self.assertEqual(st_item_names.get("shellcheck"), "missing")
            self.assertNotIn("taplo", st_arm.wheels_missing)
            self.assertNotIn("shellcheck", st_arm.wheels_missing)

        # Test extracting a .gz single-binary archive (taplo ARM format)
        gz_payload = gzip.compress(b"#!/bin/sh\necho taplo-arm\n")
        gz_path = self.fixtures_dir / "taplo-linux-aarch64.gz"
        gz_path.write_bytes(gz_payload)
        gz_url = "https://github.com/tamasfe/taplo/releases/download/0.9.3/taplo-linux-aarch64.gz"
        self.url_map[gz_url] = gz_path
        taplo_arm_item = SetupItem(
            name="taplo",
            kind="binary",
            version="0.9.3",
            homepage="https://taplo.tamasfe.dev/",
            size_mb=5,
            provides=("taplo",),
            skip_if_on_path=("taplo",),
            downloads={
                ("linux", "aarch64"): Download(
                    url=gz_url,
                    hash=_sha256_bytes(gz_payload),
                    hash_algo="sha256",
                    hash_source="computed",
                    archive="gz",
                    strip_components=0,
                    binaries=(Binary(path="taplo", name="taplo"),),
                ),
            },
        )
        res_gz = run_setup(
            lambda _: None,
            platform=("linux", "aarch64"),
            env={"PATH": ""},
            fetch=self._fake_fetch,
            install_root=self.inst_root,
            cache_dir=self.cache_dir,
            real_home=self.fake_home,
            items=(taplo_arm_item,),
        )
        self.assertTrue(res_gz.ok, res_gz.error)
        self.assertEqual(res_gz.installed, ["taplo"])
        self.assertTrue((self.bin_dir / "taplo").is_symlink())
        self.assertEqual(
            (self.inst_root / "taplo" / "taplo").read_bytes(),
            b"#!/bin/sh\necho taplo-arm\n",
        )


if __name__ == "__main__":
    unittest.main()
