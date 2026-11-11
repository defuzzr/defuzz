"""Unit tests for toolchk.py (TOOLS.lock schema 1 and preflight enforcement)."""

from __future__ import annotations

import datetime as dt
import importlib.metadata
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import toolchk  # noqa: E402
from hermes_plugins.defuzz.toolchk import (  # noqa: E402
    PreflightError,
    check,
    dump_lock,
    load_lock,
    main,
    probe,
    record,
    require,
)

ENTRY = {
    "version": "1.2.3",
    "chosen": "2026-11-06",
    "reason": "because",
    "probe": "command",
    "argv": ["tool", "--version"],
    "source": "human",
}

EXPECTED_REPORT_KEYS = {
    "ok",
    "at",
    "lock",
    "enforce",
    "tools",
    "blocked",
    "probe_failed",
    "warnings",
    "summary",
    "text",
}


def fake_probe(versions: dict[str, str]):
    def _probe(name: str, entry: dict, project_root: Path | str | None = None) -> tuple[str, str]:
        if name not in versions:
            raise FileNotFoundError(name)
        return versions[name], f"/bin/{name}"

    return _probe


class ToolchkTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _check(self, needs: list[str], tools_dict: dict, versions: dict[str, str], header: dict | None = None) -> dict:
        lock = {"lock": header or {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False}, "tools": tools_dict}
        with patch.object(toolchk, "probe", side_effect=fake_probe(versions)):
            return check(needs, lock, self.root)

    def test_exact_match_passes(self) -> None:
        r = self._check(["a"], {"a": dict(ENTRY)}, {"a": "1.2.3"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["tools"]["a"]["status"], "ok")
        self.assertEqual(r["enforce"], "warn")

    def test_newer_installed_is_drift_too(self) -> None:
        r = self._check(["a"], {"a": dict(ENTRY)}, {"a": "1.9.0"})
        self.assertFalse(r["ok"])
        self.assertEqual(r["tools"]["a"]["status"], "drift")
        self.assertIn("installed 1.9.0 != locked 1.2.3", r["blocked"][0])

    def test_older_installed_is_drift(self) -> None:
        r = self._check(["a"], {"a": dict(ENTRY)}, {"a": "0.9.0"})
        self.assertFalse(r["ok"])
        self.assertEqual(r["tools"]["a"]["status"], "drift")

    def test_unlisted_tool_blocks(self) -> None:
        r = self._check(["a", "b"], {"a": dict(ENTRY)}, {"a": "1.2.3", "b": "7"})
        self.assertFalse(r["ok"])
        self.assertEqual(r["tools"]["b"]["status"], "unlisted")

    def test_missing_tool_is_probe_failure_code_3(self) -> None:
        lock = {"lock": {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False}, "tools": {"a": dict(ENTRY)}}
        with patch.object(toolchk, "probe", side_effect=fake_probe({})):
            with self.assertRaises(PreflightError) as cm, redirect_stderr(io.StringIO()):
                require(["a"], self.root, lock=lock)
        self.assertEqual(cm.exception.code, 3)

    def test_drift_raises_code_2(self) -> None:
        lock = {"lock": {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False}, "tools": {"a": dict(ENTRY)}}
        with patch.object(toolchk, "probe", side_effect=fake_probe({"a": "2.0.0"})):
            with self.assertRaises(PreflightError) as cm, redirect_stderr(io.StringIO()):
                require(["a"], self.root, lock=lock)
        self.assertEqual(cm.exception.code, 2)

    def test_lock_entry_without_reason_is_rejected_code_4(self) -> None:
        lock_file = self.root / "TOOLS.lock"
        lock_file.write_text('[a]\nversion = "1"\nchosen = "2026-11-06"\nprobe = "command"\nargv = ["a"]\n', encoding="utf-8")
        with self.assertRaises(PreflightError) as cm:
            load_lock(lock_file)
        self.assertEqual(cm.exception.code, 4)
        self.assertIn("reason", str(cm.exception))
        self.assertEqual(set(cm.exception.report.keys()), EXPECTED_REPORT_KEYS)
        self.assertEqual(cm.exception.report["blocked"], [cm.exception.report["summary"]])

    def test_load_lock_header_defaults_and_source_default(self) -> None:
        lock_file = self.root / "TOOLS.lock"
        lock_file.write_text(
            '# Top comment\n[a]\nversion = "1.0.0"\nchosen = "2026-05-01"\nreason = "pinned for test"\nprobe = "interpreter"\n',
            encoding="utf-8",
        )
        loaded = load_lock(lock_file)
        self.assertEqual(
            loaded["lock"],
            {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False},
        )
        self.assertIn("a", loaded["tools"])
        self.assertEqual(loaded["tools"]["a"]["source"], "human")

    def test_upstream_latest_advisory_json_and_legacy_never_affects_ok(self) -> None:
        # Adapted: advisory json paths must be relative to project_root or under allowed Hermes roots.
        hint = self.root / "vc.json"
        hint.write_text(json.dumps({"latest_version": "9.9.9", "nested": {"ver": "8.8.8"}}), encoding="utf-8")
        entry1 = dict(ENTRY, advisory={"kind": "json", "path": "vc.json", "key": "latest_version"})
        r1 = self._check(["a"], {"a": entry1}, {"a": "1.2.3"})
        self.assertTrue(r1["ok"])
        self.assertEqual(r1["tools"]["a"]["upstream_latest"], "9.9.9")
        self.assertIn("advisory only", r1["text"])

        # Legacy shape {json = ..., key = ...} and dotted key via fixed allowlist ~/.cua-driver/version_check.json
        fake_home = self.root / "fake_home"
        cua_hint = fake_home / ".cua-driver" / "version_check.json"
        cua_hint.parent.mkdir(parents=True)
        cua_hint.write_text(json.dumps({"nested": {"ver": "8.8.8"}}), encoding="utf-8")
        hermes_home = fake_home / ".hermes"
        hermes_home.mkdir(parents=True)
        (hermes_home / "vc.json").write_text(json.dumps({"nested": {"ver": "7.7.7"}}), encoding="utf-8")
        with patch.dict(os.environ, {"HOME": str(fake_home), "USERPROFILE": str(fake_home), "HERMES_HOME": str(hermes_home)}):
            entry2 = dict(ENTRY, advisory={"json": "~/.cua-driver/version_check.json", "key": "nested.ver"})
            r2 = self._check(["a"], {"a": entry2}, {"a": "1.2.3"})
            entry_hermes = dict(ENTRY, advisory={"json": str(hermes_home / "vc.json"), "key": "nested.ver"})
            r_hermes = self._check(["a"], {"a": entry_hermes}, {"a": "1.2.3"})
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["tools"]["a"]["upstream_latest"], "8.8.8")
        self.assertNotIn("upstream_latest", r_hermes["tools"]["a"])
        self.assertIn("advisory_path_not_allowed", r_hermes["tools"]["a"]["advisory_error"])

    def test_advisory_pm_kind_and_network_refusal(self) -> None:
        fake_pm = types.ModuleType("pm")
        fake_paths = types.ModuleType("pm.paths")
        lock_json = self.root / "pm_lock.json"
        lock_json.write_text(json.dumps({"schema": 1, "packages": {"cua-driver": {"version": "0.38.0"}}}), encoding="utf-8")
        fake_paths.lockfile_path = lambda: lock_json  # type: ignore[attr-defined]

        class FakeLockfile:
            def __init__(self, p: Path):
                self._data = json.loads(Path(p).read_text(encoding="utf-8"))["packages"]

            def version(self, name: str) -> str | None:
                return (self._data.get(name) or {}).get("version")

        fake_pm.Lockfile = FakeLockfile  # type: ignore[attr-defined]
        fake_pm.paths = fake_paths  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {"pm": fake_pm, "pm.paths": fake_paths}):
            entry_pm = dict(ENTRY, advisory={"kind": "pm"})
            r_pm = self._check(["cua-driver"], {"cua-driver": entry_pm}, {"cua-driver": "1.2.3"})
            self.assertTrue(r_pm["ok"])
            self.assertEqual(r_pm["tools"]["cua-driver"]["upstream_latest"], "0.38.0")

        # Network kind refused when network=False, recorded as advisory error, never affects ok
        entry_net = dict(ENTRY, advisory={"kind": "github-release", "repo": "trycua/cua"})
        r_net = self._check(["a"], {"a": entry_net}, {"a": "1.2.3"}, header={"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False})
        self.assertTrue(r_net["ok"])
        self.assertNotIn("upstream_latest", r_net["tools"]["a"])
        self.assertTrue(
            "advisory_error" in r_net["tools"]["a"] or "error" in r_net["tools"]["a"],
            f"Expected advisory error recorded in row: {r_net['tools']['a']}",
        )

    def test_age_months_computed_and_enforce_copied(self) -> None:
        today = dt.date.today()
        six_months_ago = (today - dt.timedelta(days=185)).isoformat()
        entry = dict(ENTRY, chosen=six_months_ago, source="auto")
        r = self._check(
            ["a"],
            {"a": entry},
            {"a": "1.2.3"},
            header={"schema": 1, "enforce": "block", "age_nudge_months": 12, "network": False},
        )
        self.assertTrue(r["ok"])
        self.assertEqual(r["enforce"], "block")
        self.assertGreaterEqual(r["tools"]["a"]["age_months"], 5)
        self.assertLessEqual(r["tools"]["a"]["age_months"], 7)
        self.assertEqual(r["tools"]["a"]["source"], "auto")

    def test_file_probe_json_key_toml_key_and_regex(self) -> None:
        # 1. JSON dotted key (.uproject)
        uproject = self.root / "GreyboxTD.uproject"
        uproject.write_text(json.dumps({"FileVersion": 3, "EngineAssociation": "5.6.1", "Nested": {" sub ": "2.0"}}), encoding="utf-8")
        v_json, w_json = probe("unreal", {"probe": "file", "file": "GreyboxTD.uproject", "key": "EngineAssociation"}, self.root)
        self.assertEqual(v_json, "5.6.1")
        self.assertEqual(Path(w_json), uproject.resolve())

        # 2. TOML dotted key (rust-toolchain.toml)
        rt = self.root / "rust-toolchain.toml"
        rt.write_text('[toolchain]\nchannel = "1.88.0"\n', encoding="utf-8")
        v_toml, w_toml = probe("rust", {"probe": "file", "file": "rust-toolchain.toml", "key": "toolchain.channel"}, self.root)
        self.assertEqual(v_toml, "1.88.0")
        self.assertEqual(Path(w_toml), rt.resolve())

        # 3. Regex first group (.nvmrc / houdini.version)
        nvmrc = self.root / ".nvmrc"
        nvmrc.write_text("v24.11.0\n", encoding="utf-8")
        v_re, w_re = probe("node", {"probe": "file", "file": ".nvmrc", "regex": r"v?(\d+\.\d+\.\d+)"}, self.root)
        self.assertEqual(v_re, "24.11.0")
        self.assertEqual(Path(w_re), nvmrc.resolve())

    def test_pm_probe_with_fake_pm_in_sys_modules(self) -> None:
        fake_pm = types.ModuleType("pm")

        class FakeInstalled:
            def __init__(self, version: str, path: Path, binary: Path | None = None):
                self.version = version
                self.path = path
                self.binary = binary

        def _installed_package(pkg: str):
            if pkg == "cua-driver":
                return FakeInstalled("0.21.0", Path("/store/cua"), Path("/store/cua/bin/cua-driver"))
            return None

        fake_pm.installed_package = _installed_package  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {"pm": fake_pm}):
            v, where = probe("cua-driver", {"probe": "pm"}, self.root)
            self.assertEqual(v, "0.21.0")
            self.assertIn("cua", where)

            # custom package name
            v2, _ = probe("my-cua", {"probe": "pm", "package": "cua-driver"}, self.root)
            self.assertEqual(v2, "0.21.0")

            # uninstalled package raises -> probe-failed in check()
            r_missing = check(
                ["missing-pkg"],
                {"lock": {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False}, "tools": {"missing-pkg": dict(ENTRY, probe="pm")}},
                self.root,
            )
            self.assertFalse(r_missing["ok"])
            self.assertEqual(r_missing["tools"]["missing-pkg"]["status"], "probe-failed")

        # When pm is unimportable -> probe-failed
        with patch.dict(sys.modules, {"pm": None}):
            r_no_pm = check(
                ["cua-driver"],
                {"lock": {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False}, "tools": {"cua-driver": dict(ENTRY, probe="pm")}},
                self.root,
            )
            self.assertFalse(r_no_pm["ok"])
            self.assertEqual(r_no_pm["tools"]["cua-driver"]["status"], "probe-failed")

    def test_interpreter_and_module_and_command_probes(self) -> None:
        v_py, w_py = probe("python", {"probe": "interpreter"}, self.root)
        self.assertEqual(w_py, sys.executable)
        self.assertRegex(v_py, r"^\d+\.\d+\.\d+")

        # Adapted: module probe uses importlib.metadata.version (never imports the module)
        with patch.object(importlib.metadata, "version", return_value="4.5.6") as mock_ver:
            v_m, w_m = probe("fake_mod", {"probe": "module", "module": "fake_test_mod_xyz"}, self.root)
            self.assertEqual(v_m, "4.5.6")
            self.assertEqual(w_m, "fake_test_mod_xyz")
            mock_ver.assert_called_once_with("fake_test_mod_xyz")

        # Command probe with resolve = "hermes-tools"
        hermes_home = self.root / "hermes_home"
        tool_dir = hermes_home / "tools" / "mytool-1.0"
        tool_dir.mkdir(parents=True)
        exe = tool_dir / "mytool"
        exe.write_text("#!/bin/sh\necho 'mytool version 7.8.9'\n", encoding="utf-8")
        exe.chmod(0o755)
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            v_cmd, w_cmd = probe("mytool", {"probe": "command", "argv": ["mytool", "--version"], "resolve": "hermes-tools"}, self.root)
            self.assertEqual(v_cmd, "7.8.9")
            self.assertEqual(Path(w_cmd), exe)

    def test_dump_and_load_round_trip(self) -> None:
        lock_path = self.root / "TOOLS.lock"
        original = {
            "lock": {
                "schema": 1,
                "enforce": "block",
                "age_nudge_months": 6,
                "network": True,
            },
            "tools": {
                "cua-driver": {
                    "version": "0.21.0",
                    "chosen": "2026-11-06",
                    "reason": 'Pinned for "T4" bench\nand multi-line reason.',
                    "probe": "command",
                    "argv": ["cua-driver", "--version"],
                    "resolve": "hermes-tools",
                    "source": "auto",
                    "advisory": {"kind": "json", "path": "~/.cua-driver/version_check.json", "key": "latest_version"},
                },
                "unreal": {
                    "version": "5.6.1",
                    "chosen": "2026-11-06",
                    "reason": "Engine association",
                    "probe": "file",
                    "file": "GreyboxTD.uproject",
                    "key": "EngineAssociation",
                    "source": "human",
                },
            },
        }
        dump_lock(lock_path, original)
        text1 = lock_path.read_text(encoding="utf-8")
        loaded = load_lock(lock_path)
        self.assertEqual(loaded, original)

        # Deterministic second dump
        dump_lock(lock_path, loaded)
        text2 = lock_path.read_text(encoding="utf-8")
        self.assertEqual(text1, text2)

        # Header comments preserved across dump_lock when file had leading # comments
        lock_path.write_text("# Leading comment line 1\n# Leading comment line 2\n\n" + text1, encoding="utf-8")
        loaded_with_comments = load_lock(lock_path)
        dump_lock(lock_path, loaded_with_comments)
        text_after = lock_path.read_text(encoding="utf-8")
        self.assertTrue(text_after.startswith("# Leading comment line 1\n# Leading comment line 2\n"))
        self.assertEqual(load_lock(lock_path)["tools"], original["tools"])

    def test_record_writes_report_on_block_and_cli_exit_codes(self) -> None:
        lock_path = self.root / "TOOLS.lock"
        lock_data = {
            "lock": {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False},
            "tools": {"a": dict(ENTRY)},
        }
        dump_lock(lock_path, lock_data)
        rec_dir = self.root / "evidence"

        # 0: exact match via main(--all)
        with patch.object(toolchk, "probe", side_effect=fake_probe({"a": "1.2.3"})), redirect_stderr(io.StringIO()):
            rc0 = main(["--all", "--project", str(self.root), "--record", str(rec_dir)])
        self.assertEqual(rc0, 0)
        saved0 = json.loads((rec_dir / "preflight.json").read_text(encoding="utf-8"))
        self.assertTrue(saved0["ok"])

        # 2: drift via main(--need a)
        with patch.object(toolchk, "probe", side_effect=fake_probe({"a": "2.0.0"})), redirect_stderr(io.StringIO()):
            rc2 = main(["--need", "a", "--project", str(self.root), "--record", str(rec_dir)])
        self.assertEqual(rc2, 2)
        saved2 = json.loads((rec_dir / "preflight.json").read_text(encoding="utf-8"))
        self.assertFalse(saved2["ok"])
        self.assertEqual(saved2["tools"]["a"]["installed"], "2.0.0")

        # 2: unlisted tool via main(--need unlisted)
        with patch.object(toolchk, "probe", side_effect=fake_probe({"a": "1.2.3"})), redirect_stderr(io.StringIO()):
            rc_unlisted = main(["--need", "unlisted", "--project", str(self.root)])
        self.assertEqual(rc_unlisted, 2)

        # 3: probe failed via main(--need a)
        with patch.object(toolchk, "probe", side_effect=fake_probe({})), redirect_stderr(io.StringIO()):
            rc3 = main(["--need", "a", "--project", str(self.root), "--record", str(rec_dir)])
        self.assertEqual(rc3, 3)

        # 4: broken lock via main(--all) AND --record writes preflight.json on code 4
        rec_dir4 = self.root / "evidence_broken"
        lock_path.write_text('[a]\nversion = "1.0"\n', encoding="utf-8")
        with redirect_stderr(io.StringIO()):
            rc4 = main(["--all", "--project", str(self.root), "--record", str(rec_dir4)])
        self.assertEqual(rc4, 4)
        saved4 = json.loads((rec_dir4 / "preflight.json").read_text(encoding="utf-8"))
        self.assertFalse(saved4["ok"])
        self.assertEqual(set(saved4.keys()), EXPECTED_REPORT_KEYS)
        self.assertEqual(saved4["blocked"], [saved4["summary"]])

    # ------------------------------------------------------------------
    # (1) Command probe hardening tests
    # ------------------------------------------------------------------
    def test_command_probe_rejects_path_separators_mismatch_and_extra_flags_without_executing(self) -> None:
        sentinel = self.root / "pwned"
        evil_script = self.root / "evil.sh"
        evil_script.write_text(f"#!/bin/sh\ntouch {sentinel}\necho 1.2.3\n", encoding="utf-8")
        evil_script.chmod(0o755)

        cases = [
            ("mytool", [str(evil_script), "--version"]),
            ("mytool", ["./evil.sh", "--version"]),
            ("mytool", ["../evil.sh", "--version"]),
            ("../mytool", ["../mytool", "--version"]),
            ("mytool", ["othertool", "--version"]),
            ("mytool", ["mytool", "-c", f"touch {sentinel}"]),
            ("mytool", ["mytool", "--version", "--eval=evil"]),
        ]
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("Popen must not be called")):
            for tool_name, bad_argv in cases:
                entry = dict(ENTRY, probe="command", argv=bad_argv)
                rep = check([tool_name], {"tools": {tool_name: entry}}, self.root)
                self.assertFalse(rep["ok"], f"expected failure for {tool_name} {bad_argv}")
                self.assertEqual(rep["tools"][tool_name]["status"], "probe-failed")
                self.assertIn("ValueError", rep["tools"][tool_name]["error"])
        self.assertFalse(sentinel.exists())

    def test_command_probe_allows_aliases_and_ignores_project_and_relative_path(self) -> None:
        # Create fake bin outside project_root vs fake malicious bin inside project_root
        with tempfile.TemporaryDirectory() as ext_tmp:
            ext_bin = Path(ext_tmp)
            rustc_bin = ext_bin / "rustc"
            rustc_bin.write_text("#!/bin/sh\necho 'rustc 1.82.0'\n", encoding="utf-8")
            rustc_bin.chmod(0o755)

            go_bin = ext_bin / "go"
            go_bin.write_text("#!/bin/sh\necho 'go version go1.23.2 linux/amd64'\n", encoding="utf-8")
            go_bin.chmod(0o755)

            # Place a poisoned rustc inside project_root and in a relative PATH entry
            proj_bin = self.root / "bin"
            proj_bin.mkdir(parents=True)
            poison = proj_bin / "rustc"
            poison.write_text("#!/bin/sh\necho 'rustc 9.9.9'\n", encoding="utf-8")
            poison.chmod(0o755)

            crafted_path = os.pathsep.join([".", "bin", str(proj_bin), str(ext_bin)])
            with patch.dict(os.environ, {"PATH": crafted_path}):
                v_rust, w_rust = probe("rust", {"probe": "command", "argv": ["rustc", "--version"]}, self.root)
                self.assertEqual(v_rust, "1.82.0")
                self.assertEqual(Path(w_rust), rustc_bin)

                v_go, w_go = probe("go", {"probe": "command", "argv": ["go", "version"]}, self.root)
                self.assertEqual(v_go, "1.23.2")
                self.assertEqual(Path(w_go), go_bin)

            # If the ONLY PATH entries are relative or inside project_root, resolution raises FileNotFoundError
            only_unsafe_path = os.pathsep.join([".", "bin", str(proj_bin)])
            with patch.dict(os.environ, {"PATH": only_unsafe_path}):
                with self.assertRaises(FileNotFoundError):
                    probe("rust", {"probe": "command", "argv": ["rustc", "--version"]}, self.root)

    def test_command_probe_hermes_tools_uses_validated_name_and_env_stdin_timeout_and_output_cap(self) -> None:
        hermes_home = self.root / "hermes_home"
        # Tool "python" with allowed alias argv[0]="python3" must glob tools/python-*/python (validated name)
        tool_dir = hermes_home / "tools" / "mytool-2.0"
        tool_dir.mkdir(parents=True)
        script = tool_dir / "mytool"
        # Reads stdin (must get EOF immediately from DEVNULL), checks SECRET_TOKEN is absent,
        # and emits > 100 KB after the version token.
        script.write_text(
            "#!/bin/sh\n"
            "cat >/dev/null\n"
            'if [ -n "$SECRET_TOKEN" ]; then echo "LEAKED" >&2; exit 1; fi\n'
            'echo "mytool 3.4.5"\n'
            "dd if=/dev/zero bs=1024 count=100 2>/dev/null | tr '\\0' 'x'\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home), "SECRET_TOKEN": "topsecret"}):
            v, w = probe(
                "mytool",
                {"probe": "command", "argv": ["mytool", "--version"], "resolve": "hermes-tools"},
                self.root,
                timeout=5.0,
            )
            self.assertEqual(v, "3.4.5")
            self.assertEqual(Path(w), script)

            # Also verify _run_bounded_command caps stdout/stderr at 64 KB
            out_s, err_s = toolchk._run_bounded_command(
                [str(script), "--version"],
                env=toolchk._minimal_probe_env("/usr/bin:/bin"),
                timeout=5.0,
            )
            self.assertLessEqual(len(out_s.encode("utf-8")), 64 * 1024)
            self.assertLessEqual(len(err_s.encode("utf-8")), 64 * 1024)

        # Timeout parameter is honored and kills hanging subprocess quickly
        hang_dir = hermes_home / "tools" / "hangtool-1.0"
        hang_dir.mkdir(parents=True)
        hang_script = hang_dir / "hangtool"
        hang_script.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
        hang_script.chmod(0o755)
        t0 = time.monotonic()
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            rep = check(
                ["hangtool"],
                {
                    "tools": {
                        "hangtool": dict(
                            ENTRY,
                            probe="command",
                            argv=["hangtool", "--version"],
                            resolve="hermes-tools",
                        )
                    }
                },
                self.root,
                timeout=0.15,
            )
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 2.0)
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["tools"]["hangtool"]["status"], "probe-failed")
        self.assertIn("TimeoutExpired", rep["tools"]["hangtool"]["error"])

    # ------------------------------------------------------------------
    # (2) Module probe hardening tests
    # ------------------------------------------------------------------
    def test_module_probe_never_imports_sentinel_module_on_sys_path(self) -> None:
        sentinel_file = self.root / "module_imported_sentinel"
        evil_mod = self.root / "evil_sentinel_pkg.py"
        evil_mod.write_text(
            f"from pathlib import Path\nPath({str(sentinel_file)!r}).write_text('pwned')\n__version__ = '1.0.0'\n",
            encoding="utf-8",
        )
        sys.path.insert(0, str(self.root))
        try:
            rep = check(
                ["evil_sentinel_pkg"],
                {
                    "tools": {
                        "evil_sentinel_pkg": dict(
                            ENTRY,
                            probe="module",
                            module="evil_sentinel_pkg",
                        )
                    }
                },
                self.root,
            )
            self.assertFalse(sentinel_file.exists(), "module probe must NEVER import/execute module code")
            self.assertNotIn("evil_sentinel_pkg", sys.modules)
            self.assertFalse(rep["ok"])
            self.assertEqual(rep["tools"]["evil_sentinel_pkg"]["status"], "probe-failed")
            self.assertIn("PackageNotFoundError", rep["tools"]["evil_sentinel_pkg"]["error"])

            # Invalid module names rejected with ValueError
            for bad_mod in ("../evil", "foo/bar", "os;id", "__import__('os')"):
                with self.assertRaises(ValueError):
                    probe("mod", {"probe": "module", "module": bad_mod}, self.root)
        finally:
            if str(self.root) in sys.path:
                sys.path.remove(str(self.root))

    # ------------------------------------------------------------------
    # (3) File probe and advisory json hardening tests
    # ------------------------------------------------------------------
    def test_file_probe_blocks_traversal_symlink_fifo_oversize_and_redos(self) -> None:
        # 1. Path traversal outside project_root
        outside_secret = self.root.parent / f"secret_{os.getpid()}.txt"
        outside_secret.write_text("1.2.3\n", encoding="utf-8")
        try:
            for bad_rel in ("../" + outside_secret.name, "../../.hermes/.env", str(outside_secret)):
                with self.assertRaises(ValueError):
                    probe("sec", {"probe": "file", "file": bad_rel, "regex": r"(\d+\.\d+\.\d+)"}, self.root)

            # 2. Symlink inside project_root pointing to outside_secret (using allowlisted name)
            (self.root / "sym").mkdir()
            sym = self.root / "sym" / "VERSION"
            sym.symlink_to(outside_secret)
            with self.assertRaises(ValueError):
                probe("sec", {"probe": "file", "file": "sym/VERSION", "regex": r"(\d+\.\d+\.\d+)"}, self.root)
        finally:
            outside_secret.unlink(missing_ok=True)

        # 3. FIFO via os.mkfifo does not hang and is rejected as non-regular file
        (self.root / "fifo").mkdir()
        fifo_path = self.root / "fifo" / "VERSION"
        os.mkfifo(fifo_path)
        t0 = time.monotonic()
        with self.assertRaises((ValueError, OSError)):
            probe("fifo_tool", {"probe": "file", "file": "fifo/VERSION", "regex": r"(\d+\.\d+\.\d+)"}, self.root)
        self.assertLess(time.monotonic() - t0, 1.0)

        # 4. Size capped at 64 KiB: oversized file is rejected
        (self.root / "big").mkdir()
        big_file = self.root / "big" / "VERSION"
        big_file.write_text(("x" * 100 + "\n") * 800 + "1.2.3\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            probe("big", {"probe": "file", "file": "big/VERSION", "regex": r"(\d+\.\d+\.\d+)"}, self.root)

        # 5. Regex > 128 chars rejected; lines truncated to 512 chars
        long_re = "(" + "a" * 120 + r"\d+\.\d+\.\d+)"
        self.assertGreater(len(long_re), 128)
        with self.assertRaises(ValueError):
            probe("re_long", {"probe": "file", "file": "big/VERSION", "regex": long_re}, self.root)

        (self.root / "trunc").mkdir()
        long_line_file = self.root / "trunc" / "VERSION"
        long_line_file.write_text("x" * 600 + " 4.5.6\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            probe("line_trunc", {"probe": "file", "file": "trunc/VERSION", "regex": r"(\d+\.\d+\.\d+)"}, self.root)

        # 6. ReDoS pattern completes under 1s and fails safely
        (self.root / "redos").mkdir()
        redos_file = self.root / "redos" / "VERSION"
        redos_file.write_text("a" * 400 + "!\n", encoding="utf-8")
        t_redos = time.monotonic()
        rep = check(
            ["redos"],
            {
                "tools": {
                    "redos": dict(
                        ENTRY,
                        probe="file",
                        file="redos/VERSION",
                        regex=r"(a+)+$",
                    )
                }
            },
            self.root,
        )
        self.assertLess(time.monotonic() - t_redos, 1.0)
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["tools"]["redos"]["status"], "probe-failed")

        # 7. Extracted version must match strict version grammar
        (self.root / "badver").mkdir()
        bad_ver_file = self.root / "badver" / "package.json"
        bad_ver_file.write_text(json.dumps({"ver": "API_KEY=secret value with spaces"}), encoding="utf-8")
        with self.assertRaises(ValueError):
            probe("bad_ver", {"probe": "file", "file": "badver/package.json", "key": "ver"}, self.root)

    def test_advisory_json_path_restrictions(self) -> None:
        outside = self.root.parent / f"outside_adv_{os.getpid()}.json"
        outside.write_text(json.dumps({"latest_version": "9.9.9"}), encoding="utf-8")
        try:
            # Arbitrary absolute path outside ~/.hermes, ~/.hermes-dev, ~/.cua-driver, $HERMES_HOME is refused
            entry_abs = dict(ENTRY, advisory={"kind": "json", "path": str(outside), "key": "latest_version"})
            r_abs = self._check(["a"], {"a": entry_abs}, {"a": "1.2.3"})
            self.assertTrue(r_abs["ok"])
            self.assertNotIn("upstream_latest", r_abs["tools"]["a"])
            self.assertIn("advisory_error", r_abs["tools"]["a"])

            # Relative traversal '../...' is refused
            entry_rel = dict(ENTRY, advisory={"kind": "json", "path": f"../{outside.name}", "key": "latest_version"})
            r_rel = self._check(["a"], {"a": entry_rel}, {"a": "1.2.3"})
            self.assertNotIn("upstream_latest", r_rel["tools"]["a"])
            self.assertIn("advisory_error", r_rel["tools"]["a"])
        finally:
            outside.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # (4) load_lock size cap, UTF-8, chosen ISO date, probe validation
    # ------------------------------------------------------------------
    def test_load_lock_50mb_rejected_fast_and_utf8_chosen_and_probe_validation(self) -> None:
        # 1. 50 MB lock rejected fast (< 0.5s) via fstat size check
        huge_lock = self.root / "HUGE.lock"
        with open(huge_lock, "wb") as f:
            f.truncate(50 * 1024 * 1024)
        t0 = time.monotonic()
        with self.assertRaises(PreflightError) as cm_huge:
            load_lock(huge_lock)
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertEqual(cm_huge.exception.code, 4)
        self.assertEqual(set(cm_huge.exception.report.keys()), EXPECTED_REPORT_KEYS)
        self.assertEqual(cm_huge.exception.report["blocked"], [cm_huge.exception.report["summary"]])
        huge_lock.unlink()

        # 2. UnicodeDecodeError becomes PreflightError code 4
        bad_utf8 = self.root / "UTF8.lock"
        bad_utf8.write_bytes(b"\xff\xfe\x00invalid utf-8")
        with self.assertRaises(PreflightError) as cm_utf8:
            load_lock(bad_utf8)
        self.assertEqual(cm_utf8.exception.code, 4)
        self.assertEqual(set(cm_utf8.exception.report.keys()), EXPECTED_REPORT_KEYS)

        # 3. Invalid chosen date rejected with code 4
        bad_date = self.root / "DATE.lock"
        for invalid_chosen in ("not-a-date", "2026-13-01", "2026-02-30", "2026/11/06", "2026-11-06T00:00:00"):
            bad_date.write_text(
                f'[a]\nversion = "1.0"\nchosen = "{invalid_chosen}"\nreason = "r"\nprobe = "interpreter"\n',
                encoding="utf-8",
            )
            with self.assertRaises(PreflightError) as cm_date:
                load_lock(bad_date)
            self.assertEqual(cm_date.exception.code, 4)
            self.assertIn("chosen", cm_date.exception.report["summary"])

        # 4. Unknown probe kind and malformed probe fields rejected with code 4 at load_lock time
        bad_probe_Payloads = [
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "unknown_kind"\n',
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "command"\n',
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "command"\nargv = []\n',
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "command"\nargv = ["a"]\nresolve = "bad"\n',
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "file"\n',
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "file"\nfile = "x.json"\n',
            '[a]\nversion = "1.0"\nchosen = "2026-11-06"\nreason = "r"\nprobe = "file"\nfile = "x.json"\nkey = "k"\nregex = "r"\n',
        ]
        bad_probe_file = self.root / "PROBE.lock"
        for payload in bad_probe_Payloads:
            bad_probe_file.write_text(payload, encoding="utf-8")
            with self.assertRaises(PreflightError) as cm_p:
                load_lock(bad_probe_file)
            self.assertEqual(cm_p.exception.code, 4, f"Expected code 4 for payload:\n{payload}")
            self.assertEqual(set(cm_p.exception.report.keys()), EXPECTED_REPORT_KEYS)
            self.assertEqual(cm_p.exception.report["blocked"], [cm_p.exception.report["summary"]])

    # ------------------------------------------------------------------
    # (5) dump_lock control-char escaping and mode 0644
    # ------------------------------------------------------------------
    def test_dump_lock_escapes_control_chars_and_sets_mode_0644(self) -> None:
        lock_path = self.root / "CTRL.lock"
        ctrl_reason = "Reason with \x00 null, \x07 bell, \x1b[31mANSI\x1b[0m, \x7f DEL, \"quotes\" and \\backslash"
        payload = {
            "lock": {"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False},
            "tools": {
                "python": {
                    "version": "3.12.0",
                    "chosen": "2026-11-06",
                    "reason": ctrl_reason,
                    "probe": "interpreter",
                    "source": "human",
                }
            },
        }
        dump_lock(lock_path, payload)
        raw_toml = lock_path.read_text(encoding="utf-8")
        self.assertIn("\\u0000", raw_toml)
        self.assertIn("\\u0007", raw_toml)
        self.assertIn("\\u001b", raw_toml)
        self.assertIn("\\u007f", raw_toml)
        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o644)

        loaded = load_lock(lock_path)
        self.assertEqual(loaded["tools"]["python"]["reason"], ctrl_reason)

    # ------------------------------------------------------------------
    # (7) Age nudge and (8) Table alignment + dead constants
    # ------------------------------------------------------------------
    def test_age_nudge_in_text_never_affects_ok(self) -> None:
        today = dt.date.today()
        fourteen_months_ago = (today - dt.timedelta(days=430)).isoformat()
        entry = dict(ENTRY, chosen=fourteen_months_ago)
        r = self._check(
            ["a"],
            {"a": entry},
            {"a": "1.2.3"},
            header={"schema": 1, "enforce": "warn", "age_nudge_months": 12, "network": False},
        )
        self.assertTrue(r["ok"])
        age = r["tools"]["a"]["age_months"]
        self.assertGreaterEqual(age, 12)
        self.assertIn(f" · chosen {age} months ago, re-decide?", r["text"])

        # Disabled when age_nudge_months = 0
        r_disabled = self._check(
            ["a"],
            {"a": entry},
            {"a": "1.2.3"},
            header={"schema": 1, "enforce": "warn", "age_nudge_months": 0, "network": False},
        )
        self.assertTrue(r_disabled["ok"])
        self.assertNotIn("re-decide?", r_disabled["text"])

    def test_table_header_and_dynamic_name_column_width_and_no_dead_constants(self) -> None:
        self.assertFalse(hasattr(toolchk, "LOCAL_ADVISORY_KINDS"))
        long_name = "my-very-long-tool-identifier-name"
        r = self._check(
            ["short", long_name],
            {"short": dict(ENTRY), long_name: dict(ENTRY)},
            {"short": "1.2.3", long_name: "1.2.3"},
        )
        lines = r["text"].splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn("STATUS", lines[0])
        self.assertIn("TOOL", lines[0])
        self.assertIn("DETAIL", lines[0])
        # Verify the DETAIL column starts at the exact same offset on header and both rows
        detail_col_header = lines[0].index("DETAIL")
        detail_col_short = lines[1].index("1.2.3")
        detail_col_long = lines[2].index("1.2.3")
        self.assertEqual(detail_col_header, detail_col_short)
        self.assertEqual(detail_col_short, detail_col_long)


if __name__ == "__main__":
    unittest.main()
