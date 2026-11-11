"""Unit tests for lint_env.py."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import lint_env  # noqa: E402
from hermes_plugins.defuzz.lint_env import (  # noqa: E402
    INSTALL_ROOT_REL,
    TIMEOUT_RC,
    build_env,
    real_home,
    resolve_binaries,
    run,
    which,
)


class TestLintEnv(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_install_root_rel_constant(self) -> None:
        self.assertEqual(INSTALL_ROOT_REL, Path(".local/opt/defuzz"))
        self.assertEqual(TIMEOUT_RC, 124)

    def test_real_home_never_returns_hermes_profile_home(self) -> None:
        hermes_home = self.tmp_root / "hermes_home"
        profile_home = hermes_home / "home"
        profile_home.mkdir(parents=True)
        real_user_home = self.tmp_root / "real_user"
        real_user_home.mkdir(parents=True)

        env = {
            "HERMES_HOME": str(hermes_home),
            "HOME": str(profile_home),
            "HERMES_REAL_HOME": str(real_user_home),
        }
        got = real_home(env)
        self.assertEqual(got, real_user_home)
        self.assertNotEqual(got, profile_home)

        # Fallback path when hermes_constants is unavailable:
        with mock.patch.object(lint_env, "_hermes_get_real_home", None):
            got_fb = real_home(env)
            self.assertEqual(got_fb, real_user_home)
            self.assertNotEqual(got_fb, profile_home)

    def test_build_env_sets_toolchain_vars_and_deduped_path(self) -> None:
        fake_real = self.tmp_root / "realhome"
        adopt_bin = fake_real / INSTALL_ROOT_REL / "bin"
        cargo_bin = fake_real / ".cargo" / "bin"
        go_bin = fake_real / "go" / "bin"
        adopt_go_bin = fake_real / INSTALL_ROOT_REL / "go" / "bin"
        dotnet_root = fake_real / INSTALL_ROOT_REL / "dotnet"
        dotnet_tools = fake_real / ".dotnet" / "tools"
        pwsh_dir = fake_real / INSTALL_ROOT_REL / "pwsh"
        local_bin = fake_real / ".local" / "bin"

        for d in (adopt_bin, cargo_bin, go_bin, adopt_go_bin, dotnet_root, dotnet_tools, pwsh_dir, local_bin):
            d.mkdir(parents=True, exist_ok=True)

        hermes_home = self.tmp_root / "hermes_home"
        (hermes_home / "home").mkdir(parents=True, exist_ok=True)

        base = {
            "PATH": f"/usr/bin{os.pathsep}/usr/bin{os.pathsep}{cargo_bin}",
            "HOME": "/tmp/fakehome",
            "PYTHONHOME": "/some/bad/pythonhome",
            "RUFF_CACHE_DIR": "/custom/ruff_cache",
        }
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}), mock.patch.object(
            lint_env, "real_home", return_value=fake_real
        ):
            env = build_env(base)

        self.assertEqual(env["RUSTUP_HOME"], str(fake_real / ".rustup"))
        self.assertEqual(env["CARGO_HOME"], str(fake_real / ".cargo"))
        self.assertEqual(env["GOPATH"], str(fake_real / "go"))
        self.assertEqual(env["DOTNET_ROOT"], str(dotnet_root))
        self.assertEqual(env["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")
        self.assertEqual(env["DOTNET_NOLOGO"], "1")
        self.assertEqual(env["RUFF_CACHE_DIR"], "/custom/ruff_cache")
        self.assertNotIn("PYTHONHOME", env)

        path_entries = env["PATH"].split(os.pathsep)
        self.assertEqual(len(path_entries), len(set(path_entries)), "PATH entries must be deduplicated")
        self.assertEqual(path_entries[0], str(adopt_bin))

        expected_prefix = [
            str(adopt_bin),
            str(cargo_bin),
            str(go_bin),
            str(adopt_go_bin),
            str(dotnet_root),
            str(dotnet_tools),
            str(pwsh_dir),
            str(local_bin),
            str(Path(sys.executable).parent),
        ]
        # Deduplicate expected_prefix just in case sys.executable parent equals one of them
        dedup_expected = list(dict.fromkeys(expected_prefix))
        self.assertEqual(path_entries[: len(dedup_expected)], dedup_expected)

        # Managed stylua and selene in adopt_bin win over cargo_bin copies
        for tool in ("stylua", "selene"):
            for d in (adopt_bin, cargo_bin):
                t_bin = d / tool
                t_bin.write_text("#!/bin/sh\n", encoding="utf-8")
                t_bin.chmod(0o755)
            self.assertEqual(which(tool, env, is_windows=False), str(adopt_bin / tool))

        # Rust proxies (not exposed in adopt_bin) resolve from cargo_bin
        for proxy in ("rustup", "cargo"):
            p_bin = cargo_bin / proxy
            p_bin.write_text("#!/bin/sh\n", encoding="utf-8")
            p_bin.chmod(0o755)
            self.assertEqual(which(proxy, env, is_windows=False), str(p_bin))

    def test_build_env_omits_dotnet_root_when_dir_missing_and_falls_back_without_hermes(self) -> None:
        fake_real = self.tmp_root / "minimal_home"
        adopt_bin = fake_real / INSTALL_ROOT_REL / "bin"
        adopt_bin.mkdir(parents=True)

        base = {"PATH": "/usr/bin:/usr/bin", "HOME": "/tmp/fakehome", "PYTHONHOME": "x"}
        with mock.patch.object(
            lint_env, "real_home", return_value=fake_real
        ):
            env = build_env(base)

        self.assertNotIn("DOTNET_ROOT", env)
        self.assertNotIn("PYTHONHOME", env)
        self.assertNotIn("RUFF_CACHE_DIR", env)
        self.assertEqual(env["HOME"], "/tmp/fakehome")
        entries = env["PATH"].split(os.pathsep)
        self.assertEqual(entries[0], str(adopt_bin))
        self.assertEqual(entries.count("/usr/bin"), 1)

    def test_which_windows_suffix_order_and_posix(self) -> None:
        bin_dir = self.tmp_root / "bin"
        bin_dir.mkdir(parents=True)

        foo_bare = bin_dir / "foo"
        foo_cmd = bin_dir / "foo.cmd"
        foo_exe = bin_dir / "foo.exe"
        for p in (foo_bare, foo_cmd, foo_exe):
            p.write_text("#!/bin/sh\n", encoding="utf-8")
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        env = {"PATH": str(bin_dir)}
        win_res = which("foo", env, is_windows=True)
        self.assertEqual(win_res, str(foo_cmd))

        # Remove .cmd -> .exe should win before bare
        foo_cmd.unlink()
        win_res_exe = which("foo", env, is_windows=True)
        self.assertEqual(win_res_exe, str(foo_exe))

        # On POSIX (is_windows=False), bare 'foo' resolves directly
        posix_res = which("foo", env, is_windows=False)
        self.assertEqual(posix_res, str(foo_bare))

        # Missing binary returns None
        self.assertIsNone(which("nonexistent_tool_xyz", env, is_windows=True))
        self.assertIsNone(which("nonexistent_tool_xyz", env, is_windows=False))

    def test_resolve_binaries(self) -> None:
        bin_dir = self.tmp_root / "bin2"
        bin_dir.mkdir(parents=True)
        tool_a = bin_dir / "tool_a"
        tool_a.write_text("#!/bin/sh\n", encoding="utf-8")
        tool_a.chmod(tool_a.stat().st_mode | stat.S_IXUSR)

        env = {"PATH": str(bin_dir)}
        resolved = resolve_binaries(["tool_a", "missing_tool_b"], env)
        self.assertEqual(resolved, {"tool_a": str(tool_a), "missing_tool_b": None})

    def test_run_success(self) -> None:
        env = build_env()
        cp = run([sys.executable, "-c", "print(1)"], cwd=self.tmp_root, env=env, timeout_s=5)
        self.assertEqual(cp.returncode, 0)
        self.assertEqual(cp.stdout.strip(), "1")
        self.assertEqual(cp.stderr, "")

    def test_run_timeout_kills_process_group_fast_and_returns_sentinel(self) -> None:
        pid_file = self.tmp_root / "child.pid"
        code = (
            "import os, subprocess, sys, time, pathlib; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); "
            "time.sleep(30)"
        )
        env = build_env()
        t0 = time.monotonic()
        cp = run([sys.executable, "-c", code], cwd=self.tmp_root, env=env, timeout_s=1)
        elapsed = time.monotonic() - t0

        self.assertEqual(cp.returncode, TIMEOUT_RC)
        self.assertEqual(cp.stderr, "timeout after 1s")
        self.assertLess(elapsed, 3.0)

        if pid_file.exists():
            grandchild_pid = int(pid_file.read_text().strip())
            # Give OS a brief moment if needed, then verify grandchild is dead (not alive or zombie)
            with self.assertRaises(ProcessLookupError):
                os.kill(grandchild_pid, 0)

    def test_run_custom_runner_injection(self) -> None:
        calls: list[tuple] = []

        def fake_runner(argv, *, cwd, env, timeout_s):
            calls.append((list(argv), cwd, dict(env), timeout_s))
            return subprocess.CompletedProcess(argv, 0, stdout="fake_out", stderr="")

        res = run(["echo", "hi"], cwd=self.tmp_root, env={"PATH": "/bin"}, timeout_s=10, runner=fake_runner)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, "fake_out")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], ["echo", "hi"])


if __name__ == "__main__":
    unittest.main()


class HermesImportFailureTests(unittest.TestCase):
    """Any import-time failure of optional Hermes helpers must leave the module importable."""

    def test_module_imports_when_hermes_import_raises_runtime_error(self):
        import importlib
        import sys as _sys
        import types

        broken = types.ModuleType("tools")
        broken.__path__ = []  # mark as package

        class _Raiser(types.ModuleType):
            def __getattr__(self, name):
                raise RuntimeError("boom")

        saved = {k: _sys.modules.get(k) for k in ("hermes_plugins.defuzz.lint_env", "tools", "tools.environments", "tools.environments.local", "hermes_constants")}
        try:
            _sys.modules["tools"] = broken
            _sys.modules["tools.environments"] = broken
            _sys.modules["tools.environments.local"] = _Raiser("tools.environments.local")
            _sys.modules["hermes_constants"] = _Raiser("hermes_constants")
            _sys.modules.pop("hermes_plugins.defuzz.lint_env", None)
            mod = importlib.import_module("hermes_plugins.defuzz.lint_env")
            self.assertIsNone(mod._hermes_get_real_home)
        finally:
            for k, v in saved.items():
                if v is None:
                    _sys.modules.pop(k, None)
                else:
                    _sys.modules[k] = v


class TelemetryOptOutTests(unittest.TestCase):
    """The lint child keeps the user's telemetry and network opt-outs and never a credential."""

    USER_OPTOUTS = {
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        "POWERSHELL_UPDATECHECK": "Off",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "true",
        "GOFLAGS": "-mod=mod",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GONOSUMDB": "example.invalid/*",
        "GONOPROXY": "example.invalid/*",
        "GOPRIVATE": "example.invalid/*",
        "GOTOOLCHAIN": "local",
        "GOTELEMETRY": "off",
        "CARGO_NET_OFFLINE": "true",
        "DO_NOT_TRACK": "1",
    }

    def _env(self, base):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            lint_env, "real_home", return_value=Path(td)
        ), mock.patch.dict(os.environ, {"DEFUZZ_INSTALL_ROOT": str(Path(td) / "root")}):
            return build_env({"PATH": "/usr/bin", "HOME": td, **base})

    def test_user_optouts_reach_the_child(self):
        env = self._env(dict(self.USER_OPTOUTS))
        for key, value in self.USER_OPTOUTS.items():
            self.assertEqual(env.get(key), value, key)

    def test_plugin_sets_safe_optouts_when_user_did_not(self):
        env = self._env({})
        self.assertEqual(env["POWERSHELL_TELEMETRY_OPTOUT"], "1")
        self.assertEqual(env["POWERSHELL_UPDATECHECK"], "Off")
        self.assertEqual(env["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")
        self.assertEqual(env["DOTNET_NOLOGO"], "1")

    def test_token_named_and_credential_url_values_still_dropped(self):
        env = self._env({
            "GITHUB_TOKEN": "synthetic",
            "GOAUTH": "netrc",
            "GOPROXY_TOKEN": "synthetic",
            "NPM_CONFIG__AUTHTOKEN": "synthetic",
            "GOPROXY": "https://user:synthetic@proxy.example.invalid",
            "GOSUMDB": "sum.example.invalid https://u:p@sum.example.invalid",
        })
        for key in ("GITHUB_TOKEN", "GOAUTH", "GOPROXY_TOKEN", "NPM_CONFIG__AUTHTOKEN", "GOPROXY", "GOSUMDB"):
            self.assertNotIn(key, env)

    def test_passthrough_names_never_look_like_credentials(self):
        from hermes_plugins.defuzz.child_env import SECRET_NAME_RE
        for key in lint_env.LINT_ENV_KEYS:
            self.assertIsNone(SECRET_NAME_RE.search(key), key)
