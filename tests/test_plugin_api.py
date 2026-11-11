"""Unit tests for dashboard/manifest.json and dashboard/plugin_api.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    HAS_FASTAPI = True
except ImportError:
    FastAPI = None  # type: ignore[assignment,misc]
    TestClient = None  # type: ignore[assignment,misc]
    HAS_FASTAPI = False


def _load_plugin_api() -> Any:
    """Load dashboard/plugin_api.py standalone via spec_from_file_location."""
    mod_name = "hermes_dashboard_plugin_defuzz"
    existing = sys.modules.get(mod_name)
    if existing is not None:
        return existing
    api_path = REPO_ROOT / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location(mod_name, api_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestDashboardManifest(unittest.TestCase):
    """Verify dashboard manifest and lint boundary."""

    def test_manual_lint_rejects_unsafe_root_before_setup_or_execution(self) -> None:
        if FastAPI is None or TestClient is None:
            self.skipTest("fastapi not available")
        api = _load_plugin_api()
        with mock.patch.object(api.lint_setup, "status") as status, mock.patch.object(api.linter, "run_lint") as run:
            status.return_value.complete = True
            run.return_value = {}
            app = FastAPI()
            app.include_router(api.router)
            response = TestClient(app).post('/lint', json={"project": "/", "mode": "both"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Refusing", response.json()["detail"])
        status.assert_not_called()
        run.assert_not_called()

    def test_manifest_json_fields(self) -> None:
        manifest_path = REPO_ROOT / "dashboard" / "manifest.json"
        self.assertTrue(manifest_path.is_file())
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(data["name"], "defuzz")
        self.assertEqual(data["label"], "Project Defuzz")
        self.assertEqual(data["description"], "Lint and tool-setup backend for defuzz.")
        self.assertEqual(data["icon"], "Shield")
        self.assertEqual(data["version"], "0.1.0")
        self.assertEqual(data["tab"], {"hidden": True})
        self.assertEqual(data["api"], "plugin_api.py")

    def test_load_does_not_permanently_mutate_sys_path(self) -> None:
        if not HAS_FASTAPI:
            self.skipTest("fastapi not available in this Python interpreter")
        api_path = REPO_ROOT / "dashboard" / "plugin_api.py"
        root_str = str(REPO_ROOT)

        saved_path = list(sys.path)
        saved_modules = {
            k: v
            for k, v in sys.modules.items()
            if k == "hermes_plugins"
            or k.startswith("hermes_plugins.")
            or k.startswith("defuzz_place_")
            or k.startswith("defuzz_place_dashboard_plugin_api_isolated")
            or k in ("linter", "lint_setup", "lint_tools", "setup_manifest", "lint_env", "safety", "state_store")
        }
        try:
            sys.path[:] = [p for p in sys.path if p != root_str]
            for k in list(saved_modules):
                sys.modules.pop(k, None)

            before_path = list(sys.path)
            spec = importlib.util.spec_from_file_location("defuzz_place_dashboard_plugin_api_isolated", api_path)
            assert spec is not None and spec.loader is not None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            priv_pkg = "defuzz_place_dashboard_plugin_api_isolated__pkg"
            self.assertEqual(sys.path, before_path)
            self.assertNotIn(root_str, sys.path)
            self.assertEqual(mod._PACKAGE_NAME, priv_pkg)
            self.assertIn(priv_pkg, sys.modules)
            self.assertIn(f"{priv_pkg}.linter", sys.modules)
            self.assertNotIn("hermes_plugins.defuzz", sys.modules)
            self.assertNotIn("hermes_plugins", sys.modules)
            for bare in ("linter", "lint_setup", "lint_tools", "setup_manifest", "lint_env", "safety", "state_store"):
                self.assertNotIn(bare, sys.modules)

            # Subsequent _load calls also keep sys.path untouched
            sys.modules.pop(f"{priv_pkg}.linter", None)
            reloaded = mod._load("linter")
            self.assertIsNotNone(reloaded)
            self.assertIs(reloaded, sys.modules[f"{priv_pkg}.linter"])
            self.assertEqual(sys.path, before_path)
            self.assertNotIn(root_str, sys.path)
        finally:
            for k in [
                m
                for m in sys.modules
                if m == "hermes_plugins"
                or m.startswith("hermes_plugins.")
                or m.startswith("defuzz_place_")
                or m.startswith("defuzz_place_dashboard_plugin_api_isolated")
            ]:
                sys.modules.pop(k, None)
            sys.modules.update(saved_modules)
            sys.path[:] = saved_path

    def test_collision_with_preloaded_foreign_modules_in_subprocess(self) -> None:
        import subprocess

        if not HAS_FASTAPI:
            self.skipTest("fastapi not available in this Python interpreter")

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

repo_root = pathlib.Path({str(REPO_ROOT)!r}).resolve()
preloaded = ("safety", "cli", "linter", "lint_tools", "state_store")
foreign = {{}}
for name in preloaded:
    m = types.ModuleType(name)
    m.__file__ = f"/foreign/{{name}}.py"
    sys.modules[name] = m
    foreign[name] = m

before_path = list(sys.path)

# Load dashboard router first (which loads its private package from scratch, never touching hermes_plugins.*)
api_path = repo_root / "dashboard" / "plugin_api.py"
api_spec = importlib.util.spec_from_file_location("hermes_dashboard_plugin_defuzz", api_path)
assert api_spec is not None and api_spec.loader is not None
api_mod = importlib.util.module_from_spec(api_spec)
sys.modules["hermes_dashboard_plugin_defuzz"] = api_mod
api_spec.loader.exec_module(api_mod)

priv_pkg_name = "hermes_dashboard_plugin_defuzz__pkg"
assert api_mod.router is not None
assert api_mod._PACKAGE_NAME == priv_pkg_name
assert priv_pkg_name in sys.modules
assert "hermes_plugins" not in sys.modules
assert not [k for k in sys.modules if k.startswith("hermes_plugins.")]
pkg = sys.modules[priv_pkg_name]
assert pathlib.Path(pkg.__file__).resolve() == (repo_root / "__init__.py").resolve()

for sub in {all_siblings!r}:
    mod = importlib.import_module(f"{{priv_pkg_name}}.{{sub}}")
    assert pathlib.Path(mod.__file__).resolve() == (repo_root / f"{{sub}}.py").resolve()

assert sys.path == before_path
for name, obj in foreign.items():
    assert sys.modules.get(name) is obj, f"foreign {{name}} replaced"
for sub in {all_siblings!r}:
    if sub not in foreign:
        assert sub not in sys.modules, f"bare sibling {{sub}} added to sys.modules"
"""
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

    def test_private_package_isolated_from_preloaded_profile_packages_in_subprocess(self) -> None:
        import subprocess

        if not HAS_FASTAPI:
            self.skipTest("fastapi not available in this Python interpreter")

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
        with tempfile.TemporaryDirectory() as alt_tmp:
            alt_root = Path(alt_tmp) / "alt_defuzz_place"
            alt_root.mkdir(parents=True)
            (alt_root / "__init__.py").write_text("ALT_MARKER = True\n", encoding="utf-8")
            for sub in ("linter", "lint_setup", "lint_tools", "setup_manifest"):
                (alt_root / f"{sub}.py").write_text(f"ALT_SUB = {sub!r}\n", encoding="utf-8")

            # Combinations of source paths and preload orders for:
            # - hermes_plugins.defuzz
            # - hermes_plugins.defuzz__home_abc123
            cases = [
                # (bare_source, home_source, preload_order)
                (str(REPO_ROOT), str(REPO_ROOT), ("bare", "home")),
                (str(REPO_ROOT), str(REPO_ROOT), ("home", "bare")),
                (str(alt_root), str(alt_root), ("bare", "home")),
                (str(alt_root), str(alt_root), ("home", "bare")),
                (str(REPO_ROOT), str(alt_root), ("bare", "home")),
                (str(REPO_ROOT), str(alt_root), ("home", "bare")),
                (str(alt_root), str(REPO_ROOT), ("bare", "home")),
                (str(alt_root), str(REPO_ROOT), ("home", "bare")),
            ]

            for bare_src, home_src, order in cases:
                with self.subTest(bare_src=bare_src, home_src=home_src, order=order):
                    code = f"""
import importlib, importlib.util, pathlib, sys, types

repo_root = pathlib.Path({str(REPO_ROOT)!r}).resolve()
bare_root = pathlib.Path({bare_src!r}).resolve()
home_root = pathlib.Path({home_src!r}).resolve()
order = {order!r}
all_siblings = {all_siblings!r}

ns = types.ModuleType("hermes_plugins")
ns.__path__ = []
ns.__package__ = "hermes_plugins"
sys.modules["hermes_plugins"] = ns

def _preload_pkg(pkg_name: str, src_dir: pathlib.Path, sentinel: str) -> tuple[types.ModuleType, dict[str, object], dict[str, types.ModuleType]]:
    init_file = src_dir / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        init_file,
        submodule_search_locations=[str(src_dir)],
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = pkg_name
    mod.__path__ = [str(src_dir)]
    mod.PRELOAD_SENTINEL = sentinel
    sys.modules[pkg_name] = mod
    spec.loader.exec_module(mod)
    sub_mods = {{}}
    for sub in ("linter", "lint_setup", "lint_tools", "setup_manifest"):
        sm = importlib.import_module(f".{{sub}}", pkg_name)
        sm.SUB_SENTINEL = f"{{sentinel}}:{{sub}}"
        sub_mods[sub] = sm
    return mod, dict(mod.__dict__), sub_mods

bare_name = "hermes_plugins.defuzz"
home_name = "hermes_plugins.defuzz__home_abc123"

loaded = {{}}
for which in order:
    if which == "bare":
        loaded["bare"] = _preload_pkg(bare_name, bare_root, "BARE_SCOPE")
    else:
        loaded["home"] = _preload_pkg(home_name, home_root, "HOME_ABC123_SCOPE")

bare_pkg, bare_attrs_before, bare_subs_before = loaded["bare"]
home_pkg, home_attrs_before, home_subs_before = loaded["home"]
hermes_keys_before = {{k: v for k, v in sys.modules.items() if k == "hermes_plugins" or k.startswith("hermes_plugins.")}}

api_path = repo_root / "dashboard" / "plugin_api.py"
api_name = "hermes_dashboard_plugin_defuzz"
api_spec = importlib.util.spec_from_file_location(api_name, api_path)
assert api_spec is not None and api_spec.loader is not None
api_mod = importlib.util.module_from_spec(api_spec)
sys.modules[api_name] = api_mod
api_spec.loader.exec_module(api_mod)

priv_name = "hermes_dashboard_plugin_defuzz__pkg"
assert api_mod._PACKAGE_NAME == priv_name, f"unexpected _PACKAGE_NAME: {{api_mod._PACKAGE_NAME}}"
priv_pkg = api_mod._ensure_plugin_package()
assert priv_pkg is sys.modules[priv_name]
assert priv_pkg.__name__ == priv_name
assert pathlib.Path(priv_pkg.__file__).resolve() == (repo_root / "__init__.py").resolve()

# Private package is distinct from both preloaded profile packages
assert priv_pkg is not bare_pkg
assert priv_pkg is not home_pkg
assert not hasattr(priv_pkg, "PRELOAD_SENTINEL")

# Submodules used by dashboard API belong to private package, not either preloaded package
for sub in ("linter", "lint_setup", "lint_tools", "setup_manifest"):
    api_sub = getattr(api_mod, sub)
    loaded_sub = api_mod._load(sub)
    assert api_sub is loaded_sub
    assert api_sub is sys.modules[f"{{priv_name}}.{{sub}}"]
    assert api_sub.__name__ == f"{{priv_name}}.{{sub}}"
    assert api_sub.__package__ == priv_name
    assert pathlib.Path(api_sub.__file__).resolve() == (repo_root / f"{{sub}}.py").resolve()
    assert api_sub is not bare_subs_before[sub]
    assert api_sub is not home_subs_before[sub]
    assert not hasattr(api_sub, "SUB_SENTINEL")

# Neither preloaded package nor any hermes_plugins.* entry was replaced or mutated
assert sys.modules[bare_name] is bare_pkg
assert sys.modules[home_name] is home_pkg
assert dict(bare_pkg.__dict__) == bare_attrs_before
assert dict(home_pkg.__dict__) == home_attrs_before
for sub in ("linter", "lint_setup", "lint_tools", "setup_manifest"):
    assert sys.modules[f"{{bare_name}}.{{sub}}"] is bare_subs_before[sub]
    assert sys.modules[f"{{home_name}}.{{sub}}"] is home_subs_before[sub]
    assert bare_subs_before[sub].SUB_SENTINEL == f"BARE_SCOPE:{{sub}}"
    assert home_subs_before[sub].SUB_SENTINEL == f"HOME_ABC123_SCOPE:{{sub}}"

hermes_keys_after = {{k: v for k, v in sys.modules.items() if k == "hermes_plugins" or k.startswith("hermes_plugins.")}}
assert hermes_keys_after == hermes_keys_before

# No bare sibling names leaked into sys.modules
for sub in all_siblings:
    assert sub not in sys.modules, f"bare sibling {{sub!r}} leaked into sys.modules"
"""
                    proc = subprocess.run(
                        [sys.executable, "-c", code],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)


class TestPluginApi(unittest.TestCase):
    """Test FastAPI routes exported by dashboard/plugin_api.py."""

    def setUp(self) -> None:
        if not HAS_FASTAPI:
            self.skipTest("fastapi / starlette TestClient not available in this Python interpreter")
        self.plugin_api = _load_plugin_api()
        self.linter_mod = self.plugin_api._load("linter")
        self.setup_mod = self.plugin_api._load("lint_setup")

        with self.plugin_api._LINT_JOBS_LOCK:
            self.plugin_api._LINT_JOBS.clear()
        with self.plugin_api._SETUP_LOCK:
            self.plugin_api._SETUP_CANCEL_EVENT = None
            self.plugin_api._SETUP_THREAD = None
            self.plugin_api._SETUP_STATE.update(
                {
                    "state": "idle",
                    "percent": 0.0,
                    "item": None,
                    "step": None,
                    "message": "",
                    "started_at": None,
                    "finished_at": None,
                    "result": None,
                }
            )

        assert FastAPI is not None and TestClient is not None
        app = FastAPI()
        app.include_router(self.plugin_api.router)
        self.client = TestClient(app)

    def _fake_status(
        self,
        *,
        complete: bool = True,
        lazy_installs_allowed: bool = True,
        blocked_reason: str | None = None,
    ) -> Any:
        return self.setup_mod.SetupStatus(
            items=[
                self.setup_mod.ItemStatus(
                    name="biome",
                    kind="binary",
                    version="2.6.6",
                    size_mb=28,
                    state="present" if complete else "missing",
                )
            ],
            complete=complete,
            pending_mb=0 if complete else 28,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/defuzz-opt"),
            lazy_installs_allowed=lazy_installs_allowed,
            wheels_missing=[],
            blocked_reason=blocked_reason,
        )

    def test_lint_400_missing_or_invalid_project(self) -> None:
        r1 = self.client.post("/lint", json={})
        self.assertEqual(r1.status_code, 400)

        r2 = self.client.post("/lint", json={"project": "/nonexistent/defuzz/path/xyz"})
        self.assertEqual(r2.status_code, 400)

        with tempfile.TemporaryDirectory() as tmp:
            r3 = self.client.post("/lint", json={"project": tmp, "mode": "invalid"})
            self.assertEqual(r3.status_code, 400)

    def test_non_object_json_bodies_and_unknown_tilde_user_return_400(self) -> None:
        for bad_body in (["not", "an", "object"], "just-a-string", 123, True):
            r_lint = self.client.post("/lint", json=bad_body)
            self.assertEqual(r_lint.status_code, 400, f"POST /lint with {bad_body!r} returned {r_lint.status_code}")
            self.assertTrue(str(r_lint.json().get("detail", "")).strip())

            r_setup = self.client.post("/setup", json=bad_body)
            self.assertEqual(r_setup.status_code, 400, f"POST /setup with {bad_body!r} returned {r_setup.status_code}")
            self.assertTrue(str(r_setup.json().get("detail", "")).strip())

        r_tilde = self.client.post("/lint", json={"project": "~nosuchuser_adopt_99999/x"})
        self.assertEqual(r_tilde.status_code, 400)
        self.assertTrue(str(r_tilde.json().get("detail", "")).strip())

    def test_lint_runs_available_tools_when_global_setup_pending(self) -> None:
        import subprocess

        pending_st = self._fake_status(complete=False)  # Unrelated biome is missing.
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "main.py").write_text("x = 1\n", encoding="utf-8")
            (project / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            with (
                mock.patch.object(self.setup_mod, "status", return_value=pending_st),
                mock.patch.object(self.linter_mod, "_load_rule_settings", return_value=[]),
                mock.patch.object(self.linter_mod.lint_env, "build_env", return_value={}),
                mock.patch.object(self.linter_mod.lint_env, "which",
                                  side_effect=lambda binary, env: "/tools/ruff" if binary == "ruff" else None),
                mock.patch.object(self.linter_mod.lint_env, "run",
                                  return_value=subprocess.CompletedProcess([], 0, "", "")) as run,
            ):
                resp = self.client.post("/lint", json={"project": tmp, "mode": "pre"})
        self.assertEqual(resp.status_code, 200)
        result = resp.json()
        self.assertEqual({row["tool"] for row in result["tools_run"]}, {"ruff", "ruff-format"})
        self.assertEqual(run.call_count, 2)
        self.assertEqual(result["tools_missing"], ["rustfmt"])
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["ok"])

    def test_lint_409_tools_drift_when_tools_lock_preflight_fails(self) -> None:
        ready_st = self._fake_status(complete=True)
        toolchk_mod = self.plugin_api._load("toolchk")
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp)
            toolchk_mod.dump_lock(
                proj / "TOOLS.lock",
                {
                    "lock": dict(toolchk_mod.DEFAULT_HEADER),
                    "tools": {
                        "node": {
                            "version": "20.11.0",
                            "chosen": "2026-11-06",
                            "reason": "Dashboard lint preflight test.",
                            "probe": "command",
                            "argv": ["node", "--version"],
                            "source": "human",
                        }
                    },
                },
            )
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(toolchk_mod, "probe", return_value=("22.0.0", "/usr/bin/node")),
                mock.patch.object(self.linter_mod, "run_lint") as m_lint,
            ):
                resp = self.client.post("/lint", json={"project": str(proj), "mode": "both"})
                m_lint.assert_not_called()

            self.assertEqual(resp.status_code, 409)
            detail = resp.json()["detail"]
            self.assertEqual(detail["reason"], "tools_drift")
            self.assertFalse(detail["report"]["ok"])
            self.assertIn("node", detail["report"]["tools"])
            self.assertEqual(detail["report"]["tools"]["node"]["status"], "drift")
            self.assertTrue((proj / ".adopt" / "preflight.json").is_file())

    def test_lint_200_returns_findings(self) -> None:
        ready_st = self._fake_status(complete=True)
        fake_res = {
            "ok": True,
            "project": "/tmp/proj",
            "mode": "pre",
            "findings": [
                {
                    "file": "a.py",
                    "line": 1,
                    "rule": "F821",
                    "message": "Undefined name",
                    "tool": "ruff",
                    "severity": "error",
                }
            ],
            "tools_run": [{"tool": "ruff", "mode": "pre", "argv": ["ruff"], "exit_code": 1, "duration_ms": 5}],
            "tools_missing": [],
            "warnings": [],
            "error": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(self.linter_mod, "run_lint", return_value=fake_res) as m_lint,
            ):
                resp = self.client.post("/lint", json={"project": tmp, "mode": "pre"})
                m_lint.assert_called_once_with(tmp, "pre")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(len(body["findings"]), 1)
        self.assertEqual(body["findings"][0]["rule"], "F821")

    def test_lint_202_and_poll_for_slow_run_lint(self) -> None:
        ready_st = self._fake_status(complete=True)
        release_event = threading.Event()
        entered_event = threading.Event()

        def _slow_lint(project: str, mode: str) -> dict[str, Any]:
            entered_event.set()
            release_event.wait(timeout=5.0)
            return {
                "ok": True,
                "project": project,
                "mode": mode,
                "findings": [
                    {
                        "file": "src/lib.rs",
                        "line": 10,
                        "rule": "clippy::needless_return",
                        "message": "unneeded return",
                        "tool": "clippy",
                        "severity": "warning",
                    }
                ],
                "tools_run": [],
                "tools_missing": [],
                "warnings": [],
                "error": None,
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(self.linter_mod, "run_lint", side_effect=_slow_lint),
                mock.patch.object(self.plugin_api, "_LINT_WAIT_TIMEOUT_S", 0.05),
            ):
                resp = self.client.post("/lint", json={"project": tmp, "mode": "post"})
                self.assertEqual(resp.status_code, 202)
                data_202 = resp.json()
                self.assertEqual(data_202["state"], "running")
                job_id = data_202["job_id"]
                self.assertTrue(entered_event.wait(timeout=2.0))

                poll_running = self.client.get(f"/lint/{job_id}")
                self.assertEqual(poll_running.status_code, 200)
                self.assertEqual(poll_running.json()["state"], "running")

                release_event.set()
                deadline = time.monotonic() + 2.0
                final_payload = None
                while time.monotonic() < deadline:
                    poll_done = self.client.get(f"/lint/{job_id}")
                    self.assertEqual(poll_done.status_code, 200)
                    payload = poll_done.json()
                    if payload["state"] == "done":
                        final_payload = payload
                        break
                    time.sleep(0.02)

                self.assertIsNotNone(final_payload)
                assert final_payload is not None
                self.assertEqual(final_payload["state"], "done")
                self.assertEqual(len(final_payload["findings"]), 1)
                self.assertEqual(final_payload["result"]["findings"][0]["tool"], "clippy")

    def test_lint_incomplete_report_passed_through_intact_sync_and_poll(self) -> None:
        ready_st = self._fake_status(complete=True)
        incomplete_report = {
            "ok": False,
            "status": "incomplete",
            "project": "/tmp/proj",
            "mode": "both",
            "findings": [],
            "tools_run": [
                {
                    "tool": "ruff",
                    "mode": "pre",
                    "argv": ["ruff"],
                    "exit_code": 2,
                    "duration_ms": 4,
                    "findings": 0,
                    "status": "unparseable",
                }
            ],
            "tools_missing": ["shellcheck"],
            "tool_statuses": [
                {
                    "tool": "ruff",
                    "mode": "pre",
                    "status": "unparseable",
                    "findings": 0,
                    "exit_code": 2,
                    "message": "tool output not parseable (rc=2): broken",
                },
                {
                    "tool": "shellcheck",
                    "mode": "post",
                    "status": "not_installed",
                    "findings": 0,
                    "exit_code": None,
                    "message": "tool shellcheck is not installed (missing binary: shellcheck)",
                },
            ],
            "tool_errors": [
                {
                    "tool": "ruff",
                    "mode": "pre",
                    "status": "unparseable",
                    "message": "tool output not parseable (rc=2): broken",
                },
                {
                    "tool": "shellcheck",
                    "mode": "post",
                    "status": "not_installed",
                    "message": "tool shellcheck is not installed (missing binary: shellcheck)",
                },
            ],
            "warnings": [
                "tool output not parseable (rc=2): broken",
                "tool shellcheck is not installed (missing binary: shellcheck)",
            ],
            "error": "Tool(s) failed or could not run: ruff (unparseable), shellcheck (not_installed)",
        }

        # 1. Sync POST /lint returns incomplete report intact with HTTP 200
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(self.linter_mod, "run_lint", return_value=incomplete_report),
            ):
                resp_sync = self.client.post("/lint", json={"project": tmp, "mode": "both"})

        self.assertEqual(resp_sync.status_code, 200)
        body_sync = resp_sync.json()
        self.assertFalse(body_sync["ok"])
        self.assertEqual(body_sync["status"], "incomplete")
        self.assertEqual(body_sync["findings"], [])
        self.assertEqual(body_sync["tool_errors"], incomplete_report["tool_errors"])
        self.assertEqual(body_sync["tool_statuses"], incomplete_report["tool_statuses"])
        self.assertEqual(body_sync["error"], incomplete_report["error"])

        # 2. Async 202 + GET /lint/{job_id} polling passes incomplete report through intact
        release_event = threading.Event()
        entered_event = threading.Event()

        def _slow_incomplete_lint(project: str, mode: str) -> dict[str, Any]:
            entered_event.set()
            release_event.wait(timeout=5.0)
            return dict(incomplete_report, project=project, mode=mode)

        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(self.linter_mod, "run_lint", side_effect=_slow_incomplete_lint),
                mock.patch.object(self.plugin_api, "_LINT_WAIT_TIMEOUT_S", 0.05),
            ):
                resp_202 = self.client.post("/lint", json={"project": tmp, "mode": "both"})
                self.assertEqual(resp_202.status_code, 202)
                job_id = resp_202.json()["job_id"]
                self.assertTrue(entered_event.wait(timeout=2.0))

                release_event.set()
                deadline = time.monotonic() + 2.0
                final_poll = None
                while time.monotonic() < deadline:
                    poll_resp = self.client.get(f"/lint/{job_id}")
                    self.assertEqual(poll_resp.status_code, 200)
                    payload = poll_resp.json()
                    if payload["state"] == "done":
                        final_poll = payload
                        break
                    time.sleep(0.02)

                self.assertIsNotNone(final_poll)
                assert final_poll is not None
                self.assertEqual(final_poll["state"], "done")
                self.assertFalse(final_poll["ok"])
                self.assertEqual(final_poll["status"], "incomplete")
                self.assertEqual(final_poll["findings"], [])
                self.assertEqual(final_poll["tool_errors"], incomplete_report["tool_errors"])
                self.assertEqual(final_poll["tool_statuses"], incomplete_report["tool_statuses"])
                self.assertFalse(final_poll["result"]["ok"])
                self.assertEqual(final_poll["result"]["status"], "incomplete")
                self.assertEqual(final_poll["result"]["findings"], [])
                self.assertEqual(final_poll["result"]["tool_errors"], incomplete_report["tool_errors"])

    def test_lint_job_eviction_preserves_running_jobs_and_rejects_when_all_running(self) -> None:
        ready_st = self._fake_status(complete=True)
        now = time.time()
        with self.plugin_api._LINT_JOBS_LOCK:
            for i in range(15):
                self.plugin_api._LINT_JOBS[f"run-{i}"] = {
                    "job_id": f"run-{i}",
                    "state": "running",
                    "project": "/tmp/p",
                    "mode": "both",
                    "started_at": now - 500 + i,
                    "finished_at": None,
                    "result": None,
                    "error": None,
                }
            for i in range(5):
                self.plugin_api._LINT_JOBS[f"done-{i}"] = {
                    "job_id": f"done-{i}",
                    "state": "done",
                    "project": "/tmp/p",
                    "mode": "both",
                    "started_at": now - 100 + i,
                    "finished_at": now - 50 + i,
                    "result": {"ok": True, "findings": []},
                    "error": None,
                }

        fake_res = {
            "ok": True,
            "project": "/tmp/proj",
            "mode": "pre",
            "findings": [],
            "tools_run": [],
            "tools_missing": [],
            "warnings": [],
            "error": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(self.linter_mod, "run_lint", return_value=fake_res),
            ):
                resp = self.client.post("/lint", json={"project": tmp, "mode": "pre"})
            self.assertEqual(resp.status_code, 200)
            with self.plugin_api._LINT_JOBS_LOCK:
                self.assertNotIn("done-0", self.plugin_api._LINT_JOBS)
                for i in range(15):
                    self.assertIn(f"run-{i}", self.plugin_api._LINT_JOBS)

            # Now fill all 20 slots with running jobs (started oldest-first)
            with self.plugin_api._LINT_JOBS_LOCK:
                self.plugin_api._LINT_JOBS.clear()
                for i in range(20):
                    self.plugin_api._LINT_JOBS[f"active-{i}"] = {
                        "job_id": f"active-{i}",
                        "state": "running",
                        "project": tmp,
                        "mode": "both",
                        "started_at": now - 200 + i,
                        "finished_at": None,
                        "result": None,
                        "error": None,
                    }

            # Polling when 20 jobs are running must NOT evict any running job
            poll_resp = self.client.get("/lint/active-0")
            self.assertEqual(poll_resp.status_code, 200)
            self.assertEqual(poll_resp.json()["state"], "running")
            with self.plugin_api._LINT_JOBS_LOCK:
                self.assertEqual(len(self.plugin_api._LINT_JOBS), 20)
                for i in range(20):
                    self.assertIn(f"active-{i}", self.plugin_api._LINT_JOBS)

            # Starting a 21st job while all 20 are running must reject with 429 and keep all 20
            with (
                mock.patch.object(self.setup_mod, "status", return_value=ready_st),
                mock.patch.object(self.linter_mod, "run_lint", return_value=fake_res) as m_lint_capped,
            ):
                cap_resp = self.client.post("/lint", json={"project": tmp, "mode": "pre"})
                m_lint_capped.assert_not_called()
            self.assertEqual(cap_resp.status_code, 429)
            self.assertTrue(str(cap_resp.json().get("detail", "")).strip())
            with self.plugin_api._LINT_JOBS_LOCK:
                self.assertEqual(len(self.plugin_api._LINT_JOBS), 20)
                for i in range(20):
                    self.assertIn(f"active-{i}", self.plugin_api._LINT_JOBS)

    def test_tools_status_installed_readback_off_event_loop(self) -> None:
        ready_st = self._fake_status(complete=False)
        row = dict(name="biome", expected_version="2.6.6", installed_version="1.0.0",
                   executable_path="/opt/bin/biome", status="mismatch")
        def probe():
            import asyncio
            with self.assertRaises(RuntimeError):
                asyncio.get_running_loop()
            return [row]
        with mock.patch.object(self.setup_mod, "status", return_value=ready_st), mock.patch.object(
            self.setup_mod, "installed_tool_versions", side_effect=probe
        ) as versions:
            data = self.client.get("/tools/status").json()
        self.assertTrue(any(item.get("status") == "mismatch" and item.get("installed_version") == "1.0.0" for item in data["items"]))
        versions.assert_called_once_with()

    def test_tools_status_shape(self) -> None:
        ready_st = self._fake_status(complete=False)
        with mock.patch.object(self.setup_mod, "status", return_value=ready_st):
            resp = self.client.get("/tools/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("items", data)
        self.assertIn("complete", data)
        self.assertIn("pending_mb", data)
        self.assertIn("wheel_packages", data)
        self.assertIn("plan", data)
        self.assertIn("total_mb", data)
        self.assertIn("ruff", data["wheel_packages"])
        self.assertIsInstance(data["plan"], list)
        self.assertGreater(data["total_mb"], 0)

    def test_setup_503_when_blocked(self) -> None:
        blocked_st = self._fake_status(
            complete=False,
            lazy_installs_allowed=False,
            blocked_reason="security.allow_lazy_installs is false in config.yaml",
        )
        with mock.patch.object(self.setup_mod, "status", return_value=blocked_st):
            resp = self.client.post("/setup", json={"confirm": True})
        self.assertEqual(resp.status_code, 503)
        self.assertIn("security.allow_lazy_installs", resp.json()["detail"])

    def test_setup_running_progress_double_start_409_and_done(self) -> None:
        ready_st = self._fake_status(complete=False, lazy_installs_allowed=True)
        in_progress_event = threading.Event()
        finish_event = threading.Event()

        def _fake_run_setup(progress_cb: Any, *, cancel: threading.Event | None = None) -> Any:
            progress_cb(
                self.setup_mod.Progress(
                    item="biome",
                    step="download",
                    item_index=0,
                    item_count=1,
                    bytes_done=512,
                    bytes_total=1024,
                    percent=42.5,
                    message="Downloading biome 2.6.6",
                )
            )
            in_progress_event.set()
            finish_event.wait(timeout=5.0)
            return self.setup_mod.SetupResult(
                ok=True,
                installed=["biome"],
                skipped=[],
                failed={},
                error=None,
                log=["installed biome 2.6.6"],
            )

        with (
            mock.patch.object(self.setup_mod, "status", return_value=ready_st),
            mock.patch.object(self.setup_mod, "run_setup", side_effect=_fake_run_setup),
        ):
            r_start = self.client.post("/setup", json={"confirm": True})
            self.assertEqual(r_start.status_code, 200)
            self.assertEqual(r_start.json(), {"state": "running"})

            self.assertTrue(in_progress_event.wait(timeout=2.0))

            # Double start while running -> 409
            r_dup = self.client.post("/setup", json={"confirm": True})
            self.assertEqual(r_dup.status_code, 409)

            # Check progress snapshot
            r_prog = self.client.get("/setup/status")
            self.assertEqual(r_prog.status_code, 200)
            prog_data = r_prog.json()
            self.assertEqual(prog_data["state"], "running")
            self.assertEqual(prog_data["item"], "biome")
            self.assertEqual(prog_data["step"], "download")
            self.assertAlmostEqual(prog_data["percent"], 42.5)

            finish_event.set()
            deadline = time.monotonic() + 2.0
            final_st = None
            while time.monotonic() < deadline:
                st_resp = self.client.get("/setup/status").json()
                if st_resp["state"] == "done":
                    final_st = st_resp
                    break
                time.sleep(0.02)

            self.assertIsNotNone(final_st)
            assert final_st is not None
            self.assertEqual(final_st["state"], "done")
            self.assertEqual(final_st["percent"], 100.0)
            self.assertTrue(final_st["result"]["ok"])
            self.assertEqual(final_st["result"]["installed"], ["biome"])

    def test_setup_cancel_sets_event(self) -> None:
        ready_st = self._fake_status(complete=False, lazy_installs_allowed=True)
        started_event = threading.Event()
        observed_cancel = threading.Event()

        def _cancellable_setup(progress_cb: Any, *, cancel: threading.Event | None = None) -> Any:
            started_event.set()
            assert cancel is not None
            if cancel.wait(timeout=5.0):
                observed_cancel.set()
            return self.setup_mod.SetupResult(
                ok=False,
                installed=[],
                skipped=[],
                failed={},
                error="cancelled",
                log=["cancelled"],
            )

        with (
            mock.patch.object(self.setup_mod, "status", return_value=ready_st),
            mock.patch.object(self.setup_mod, "run_setup", side_effect=_cancellable_setup),
        ):
            r_start = self.client.post("/setup", json={"confirm": True})
            self.assertEqual(r_start.status_code, 200)
            self.assertTrue(started_event.wait(timeout=2.0))

            r_cancel = self.client.post("/setup/cancel")
            self.assertEqual(r_cancel.status_code, 200)
            self.assertTrue(r_cancel.json()["ok"])
            self.assertTrue(observed_cancel.wait(timeout=2.0))

            deadline = time.monotonic() + 2.0
            final_st = None
            while time.monotonic() < deadline:
                st_resp = self.client.get("/setup/status").json()
                if st_resp["state"] == "failed":
                    final_st = st_resp
                    break
                time.sleep(0.02)

            self.assertIsNotNone(final_st)
            assert final_st is not None
            self.assertEqual(final_st["state"], "failed")
            self.assertEqual(final_st["result"]["error"], "cancelled")

    def test_tools_lock_endpoints_happy_and_400_404(self) -> None:
        toolchk_mod = self.plugin_api._load("toolchk")
        state_store_mod = self.plugin_api._load("state_store")

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fake_home = base / "home"
            fake_hermes = fake_home / ".hermes"
            fake_hermes.mkdir(parents=True)
            proj = base / "proj"
            proj.mkdir()
            (proj / "package.json").write_text('{"name": "api-proj"}\n', encoding="utf-8")

            with (
                mock.patch.dict(
                    "os.environ",
                    {"HOME": str(fake_home), "HERMES_HOME": str(fake_hermes)},
                ),
                mock.patch.object(
                    state_store_mod,
                    "state_db_path",
                    return_value=fake_hermes / "plugin-data" / "defuzz" / "state.db",
                ),
                mock.patch.object(toolchk_mod, "probe", return_value=("20.11.0", "/usr/bin/node")),
            ):
                # 1. GET /tools-lock when no TOOLS.lock exists -> lock: None, rows: []
                r_empty = self.client.get("/tools-lock", params={"project": str(proj)})
                self.assertEqual(r_empty.status_code, 200)
                self.assertEqual(
                    r_empty.json(),
                    {
                        "lock": None,
                        "enforce": "warn",
                        "rows": [],
                        "summary": "No TOOLS.lock present",
                    },
                )

                # 404 when calling accept / reason / snooze before TOOLS.lock exists
                r_acc_404_nolock = self.client.post(
                    "/tools-lock/accept",
                    json={"project": str(proj), "tool": "node", "reason": "ok"},
                )
                self.assertEqual(r_acc_404_nolock.status_code, 404)

                # 400 when calling init without confirm:true
                r_init_400 = self.client.post("/tools-lock/init", json={"project": str(proj)})
                self.assertEqual(r_init_400.status_code, 400)

                # 400 when calling init on unsafe root (e.g. $HOME)
                r_init_unsafe = self.client.post(
                    "/tools-lock/init",
                    json={"project": str(fake_home), "confirm": True},
                )
                self.assertEqual(r_init_unsafe.status_code, 400)

                # 2. POST /tools-lock/init happy path
                r_init = self.client.post(
                    "/tools-lock/init",
                    json={"project": str(proj), "confirm": True},
                )
                self.assertEqual(r_init.status_code, 200)
                init_body = r_init.json()
                self.assertEqual(init_body["added"], ["node"])
                self.assertTrue((proj / "TOOLS.lock").is_file())

                # 3. GET /tools-lock with TOOLS.lock present
                r_get = self.client.get("/tools-lock", params={"project": str(proj)})
                self.assertEqual(r_get.status_code, 200)
                get_body = r_get.json()
                self.assertIsNotNone(get_body["lock"])
                self.assertEqual(get_body["enforce"], "warn")
                self.assertEqual(len(get_body["rows"]), 1)
                self.assertEqual(get_body["rows"][0]["tool"], "node")
                self.assertEqual(get_body["rows"][0]["chosen"], "20.11.0")
                self.assertEqual(get_body["rows"][0]["by"], "auto")

            # Simulate installed version bumping to 22.1.0
            with (
                mock.patch.dict(
                    "os.environ",
                    {"HOME": str(fake_home), "HERMES_HOME": str(fake_hermes)},
                ),
                mock.patch.object(
                    state_store_mod,
                    "state_db_path",
                    return_value=fake_hermes / "plugin-data" / "defuzz" / "state.db",
                ),
                mock.patch.object(toolchk_mod, "probe", return_value=("22.1.0", "/usr/bin/node")),
            ):
                # 4. POST /tools-lock/accept: 400 on empty reason, 404 on unknown tool, 200 happy path
                r_acc_400 = self.client.post(
                    "/tools-lock/accept",
                    json={"project": str(proj), "tool": "node", "reason": "   "},
                )
                self.assertEqual(r_acc_400.status_code, 400)

                r_acc_404 = self.client.post(
                    "/tools-lock/accept",
                    json={"project": str(proj), "tool": "missing-tool", "reason": "valid"},
                )
                self.assertEqual(r_acc_404.status_code, 404)

                r_acc_200 = self.client.post(
                    "/tools-lock/accept",
                    json={"project": str(proj), "tool": "node", "reason": "Accepted 22.1.0 in dashboard"},
                )
                self.assertEqual(r_acc_200.status_code, 200)
                acc_row = r_acc_200.json()
                self.assertEqual(acc_row["tool"], "node")
                self.assertEqual(acc_row["chosen"], "22.1.0")
                self.assertEqual(acc_row["installed"], "22.1.0")
                self.assertEqual(acc_row["by"], "human")
                self.assertEqual(acc_row["reason"], "Accepted 22.1.0 in dashboard")
                self.assertEqual(acc_row["status"], "ok")

                # 5. POST /tools-lock/reason: 400 on empty reason, 404 on unknown tool, 200 happy path
                r_rsn_400 = self.client.post(
                    "/tools-lock/reason",
                    json={"project": str(proj), "tool": "node", "reason": ""},
                )
                self.assertEqual(r_rsn_400.status_code, 400)

                r_rsn_404 = self.client.post(
                    "/tools-lock/reason",
                    json={"project": str(proj), "tool": "missing-tool", "reason": "valid"},
                )
                self.assertEqual(r_rsn_404.status_code, 404)

                r_rsn_200 = self.client.post(
                    "/tools-lock/reason",
                    json={"project": str(proj), "tool": "node", "reason": "Refined reason in dashboard"},
                )
                self.assertEqual(r_rsn_200.status_code, 200)
                self.assertEqual(r_rsn_200.json()["reason"], "Refined reason in dashboard")

                # 6. POST /tools-lock/snooze: 400 on negative days, 404 on unknown tool, 200 happy path
                r_snz_400 = self.client.post(
                    "/tools-lock/snooze",
                    json={"project": str(proj), "tool": "node", "days": -5},
                )
                self.assertEqual(r_snz_400.status_code, 400)

                r_snz_404 = self.client.post(
                    "/tools-lock/snooze",
                    json={"project": str(proj), "tool": "missing-tool", "days": 30},
                )
                self.assertEqual(r_snz_404.status_code, 404)

                r_snz_200 = self.client.post(
                    "/tools-lock/snooze",
                    json={"project": str(proj), "tool": "node", "days": 30},
                )
                self.assertEqual(r_snz_200.status_code, 200)
                self.assertIsNotNone(r_snz_200.json()["snoozed_until"])


class TestPluginApiPostLintPreflightDirect(unittest.TestCase):
    """Test post_lint TOOLS.lock preflight directly without requiring starlette TestClient."""

    def test_post_lint_raises_409_tools_drift_directly(self) -> None:
        if not HAS_FASTAPI:
            api_path = REPO_ROOT / "dashboard" / "plugin_api.py"
            fake_fastapi = mock.MagicMock()

            class _FakeHTTPException(Exception):
                def __init__(self, status_code: int, detail: Any = None) -> None:
                    super().__init__(str(detail))
                    self.status_code = status_code
                    self.detail = detail

            fake_fastapi.HTTPException = _FakeHTTPException
            fake_fastapi.Body = lambda **kw: None
            fake_router = mock.MagicMock()
            fake_router.post.return_value = lambda fn: fn
            fake_router.get.return_value = lambda fn: fn
            fake_fastapi.APIRouter.return_value = fake_router
            fake_responses = mock.MagicMock()

            with mock.patch.dict(
                sys.modules,
                {"fastapi": fake_fastapi, "fastapi.responses": fake_responses},
            ):
                spec = importlib.util.spec_from_file_location(
                    "defuzz_place_plugin_api_direct_test", api_path
                )
                assert spec is not None and spec.loader is not None
                api_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(api_mod)
        else:
            api_mod = _load_plugin_api()

        setup_mod = api_mod._load("lint_setup")
        linter_mod = api_mod._load("linter")
        toolchk_mod = api_mod._load("toolchk")
        ready_st = setup_mod.SetupStatus(
            items=[],
            complete=True,
            pending_mb=0,
            platform=("linux", "x86_64"),
            install_root=Path("/tmp/defuzz-opt"),
            lazy_installs_allowed=True,
            wheels_missing=[],
            blocked_reason=None,
        )

        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp)
            toolchk_mod.dump_lock(
                proj / "TOOLS.lock",
                {
                    "lock": dict(toolchk_mod.DEFAULT_HEADER),
                    "tools": {
                        "node": {
                            "version": "20.11.0",
                            "chosen": "2026-11-06",
                            "reason": "Direct post_lint preflight test.",
                            "probe": "command",
                            "argv": ["node", "--version"],
                            "source": "human",
                        }
                    },
                },
            )
            with (
                mock.patch.object(setup_mod, "status", return_value=ready_st),
                mock.patch.object(toolchk_mod, "probe", return_value=("22.0.0", "/usr/bin/node")),
                mock.patch.object(linter_mod, "run_lint") as m_lint,
            ):
                with self.assertRaises(api_mod.HTTPException) as ctx:
                    api_mod.post_lint({"project": str(proj), "mode": "both"})
                m_lint.assert_not_called()

            exc = ctx.exception
            self.assertEqual(exc.status_code, 409)
            self.assertEqual(exc.detail["reason"], "tools_drift")
            self.assertFalse(exc.detail["report"]["ok"])
            self.assertEqual(exc.detail["report"]["tools"]["node"]["status"], "drift")
            self.assertTrue((proj / ".adopt" / "preflight.json").is_file())

    def test_tools_lock_endpoints_direct(self) -> None:
        if not HAS_FASTAPI:
            api_path = REPO_ROOT / "dashboard" / "plugin_api.py"
            fake_fastapi = mock.MagicMock()

            class _FakeHTTPException(Exception):
                def __init__(self, status_code: int, detail: Any = None) -> None:
                    super().__init__(str(detail))
                    self.status_code = status_code
                    self.detail = detail

            fake_fastapi.HTTPException = _FakeHTTPException
            fake_fastapi.Body = lambda **kw: None
            fake_router = mock.MagicMock()
            fake_router.post.return_value = lambda fn: fn
            fake_router.get.return_value = lambda fn: fn
            fake_fastapi.APIRouter.return_value = fake_router
            fake_responses = mock.MagicMock()

            with mock.patch.dict(
                sys.modules,
                {"fastapi": fake_fastapi, "fastapi.responses": fake_responses},
            ):
                spec = importlib.util.spec_from_file_location(
                    "defuzz_place_plugin_api_direct_tools_test", api_path
                )
                assert spec is not None and spec.loader is not None
                api_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(api_mod)
        else:
            api_mod = _load_plugin_api()

        toolchk_mod = api_mod._load("toolchk")
        state_store_mod = api_mod._load("state_store")

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fake_home = base / "home"
            fake_hermes = fake_home / ".hermes"
            fake_hermes.mkdir(parents=True)
            proj = base / "proj"
            proj.mkdir()
            (proj / "package.json").write_text('{"name": "direct-proj"}\n', encoding="utf-8")

            with (
                mock.patch.dict(
                    "os.environ",
                    {"HOME": str(fake_home), "HERMES_HOME": str(fake_hermes)},
                ),
                mock.patch.object(
                    state_store_mod,
                    "state_db_path",
                    return_value=fake_hermes / "plugin-data" / "defuzz" / "state.db",
                ),
                mock.patch.object(toolchk_mod, "probe", return_value=("20.11.0", "/usr/bin/node")),
            ):
                # 1. GET /tools-lock when no lock exists
                empty_res = api_mod.get_tools_lock(project=str(proj))
                self.assertIsNone(empty_res["lock"])
                self.assertEqual(empty_res["rows"], [])

                # 404 before lock exists
                with self.assertRaises(api_mod.HTTPException) as ctx_404:
                    api_mod.post_tools_lock_accept(
                        {"project": str(proj), "tool": "node", "reason": "ok"}
                    )
                self.assertEqual(ctx_404.exception.status_code, 404)

                # 400 on init without confirm:true and on unsafe root
                with self.assertRaises(api_mod.HTTPException) as ctx_init_400:
                    api_mod.post_tools_lock_init({"project": str(proj)})
                self.assertEqual(ctx_init_400.exception.status_code, 400)

                with self.assertRaises(api_mod.HTTPException) as ctx_unsafe:
                    api_mod.post_tools_lock_init({"project": str(fake_home), "confirm": True})
                self.assertEqual(ctx_unsafe.exception.status_code, 400)

                # 2. POST /tools-lock/init happy
                init_res = api_mod.post_tools_lock_init(
                    {"project": str(proj), "confirm": True}
                )
                self.assertEqual(init_res["added"], ["node"])

                # 3. GET /tools-lock with lock present
                get_res = api_mod.get_tools_lock(project=str(proj))
                self.assertIsNotNone(get_res["lock"])
                self.assertEqual(len(get_res["rows"]), 1)
                self.assertEqual(get_res["rows"][0]["tool"], "node")

            with (
                mock.patch.dict(
                    "os.environ",
                    {"HOME": str(fake_home), "HERMES_HOME": str(fake_hermes)},
                ),
                mock.patch.object(
                    state_store_mod,
                    "state_db_path",
                    return_value=fake_hermes / "plugin-data" / "defuzz" / "state.db",
                ),
                mock.patch.object(toolchk_mod, "probe", return_value=("22.1.0", "/usr/bin/node")),
            ):
                # 4. POST /tools-lock/accept 400, 404, 200
                with self.assertRaises(api_mod.HTTPException) as ctx_acc_400:
                    api_mod.post_tools_lock_accept(
                        {"project": str(proj), "tool": "node", "reason": "  "}
                    )
                self.assertEqual(ctx_acc_400.exception.status_code, 400)

                with self.assertRaises(api_mod.HTTPException) as ctx_acc_404:
                    api_mod.post_tools_lock_accept(
                        {"project": str(proj), "tool": "unknown", "reason": "ok"}
                    )
                self.assertEqual(ctx_acc_404.exception.status_code, 404)

                acc_row = api_mod.post_tools_lock_accept(
                    {"project": str(proj), "tool": "node", "reason": "Accepted 22.1.0"}
                )
                self.assertEqual(acc_row["chosen"], "22.1.0")
                self.assertEqual(acc_row["by"], "human")

                # 5. POST /tools-lock/reason 400, 404, 200
                with self.assertRaises(api_mod.HTTPException) as ctx_rsn_400:
                    api_mod.post_tools_lock_reason(
                        {"project": str(proj), "tool": "node", "reason": ""}
                    )
                self.assertEqual(ctx_rsn_400.exception.status_code, 400)

                with self.assertRaises(api_mod.HTTPException) as ctx_rsn_404:
                    api_mod.post_tools_lock_reason(
                        {"project": str(proj), "tool": "unknown", "reason": "ok"}
                    )
                self.assertEqual(ctx_rsn_404.exception.status_code, 404)

                rsn_row = api_mod.post_tools_lock_reason(
                    {"project": str(proj), "tool": "node", "reason": "Updated reason"}
                )
                self.assertEqual(rsn_row["reason"], "Updated reason")

                # 6. POST /tools-lock/snooze 400, 404, 200
                with self.assertRaises(api_mod.HTTPException) as ctx_snz_400:
                    api_mod.post_tools_lock_snooze(
                        {"project": str(proj), "tool": "node", "days": -1}
                    )
                self.assertEqual(ctx_snz_400.exception.status_code, 400)

                with self.assertRaises(api_mod.HTTPException) as ctx_snz_404:
                    api_mod.post_tools_lock_snooze(
                        {"project": str(proj), "tool": "unknown", "days": 30}
                    )
                self.assertEqual(ctx_snz_404.exception.status_code, 404)

                snz_row = api_mod.post_tools_lock_snooze(
                    {"project": str(proj), "tool": "node", "days": 30}
                )
                self.assertIsNotNone(snz_row["snoozed_until"])


if __name__ == "__main__":
    unittest.main()
