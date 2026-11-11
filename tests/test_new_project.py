"""Unit tests for new_project.py (run_new_project_flow orchestrator with shared deadline)."""

from __future__ import annotations

import os
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import pytest

from tests import ensure_test_package
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.new_project import (  # noqa: E402
    VALID_FLOW_STATUSES,
    FlowResult,
    run_new_project_flow,
)
from hermes_plugins.defuzz.questionnaire import Question  # noqa: E402
from hermes_plugins.defuzz.safety import run_git_hardened  # noqa: E402
from hermes_plugins.defuzz.scaffolder import Proposal  # noqa: E402
from hermes_plugins.defuzz.state_store import (  # noqa: E402
    get_project,
    get_template_option,
    list_projects,
    list_template_options,
)
from hermes_plugins.defuzz.templates import (  # noqa: E402
    CheckSpec,
    OptionSpec,
    RepoSpec,
    TemplateSpec,
    load_template,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEMPLATES_FIXTURES = FIXTURES_DIR / "templates"


def _scripted_ask(script: Dict[str, Optional[Any]]):
    def _ask(q: Question, _prefill: List[str]) -> Optional[Any]:
        return script.get(q.id)

    return _ask


class TestNewProjectFlow(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.dest_root = self.tmp_root / "projects"
        self.staging_parent = self.tmp_root / "staging"
        self.hermes_home = self.tmp_root / "hermes_home"
        self.db_path = self.tmp_root / "state.db"
        self.dest_root.mkdir(parents=True, exist_ok=True)
        self.staging_parent.mkdir(parents=True, exist_ok=True)
        self.hermes_home.mkdir(parents=True, exist_ok=True)
        self._real_home_db = Path("~/.hermes/plugin-data/defuzz/state.db").expanduser()
        self._real_home_db_existed = self._real_home_db.exists()
        self._real_home_db_mtime = (
            self._real_home_db.stat().st_mtime_ns if self._real_home_db_existed else None
        )
        self._env_patcher = mock.patch.dict(
            os.environ,
            {
                "HERMES_HOME": str(self.hermes_home),
                "HERMES_PROJECTS_ROOT": str(self.dest_root),
            },
        )
        self._env_patcher.start()

    def tearDown(self) -> None:
        self._env_patcher.stop()
        if not self._real_home_db_existed:
            self.assertFalse(self._real_home_db.exists())
        else:
            self.assertEqual(self._real_home_db.stat().st_mtime_ns, self._real_home_db_mtime)
        self._tmp.cleanup()

    def _answers_rows(self) -> List[Tuple[int, str, Optional[str]]]:
        if not self.db_path.exists():
            return []
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            return list(
                conn.execute(
                    "SELECT id, answers_json, project_path FROM answers ORDER BY id ASC"
                ).fetchall()
            )

    # Registration reporting must not depend on the host's installed toolchain.
    @mock.patch.object(scaffolder.toolchk, "probe", return_value=("1.0.0", "fixture-tool"))
    def test_registration_failures_are_in_chat_message(self, _probe) -> None:
        reason = 'denied "access"\nretry'
        calls = []

        def register(name, path):
            calls.append((name, path))
            return json.dumps({"error": reason})

        res = run_new_project_flow(
            ask=_scripted_ask({"building": "service", "layout": "poly", "languages": ["python", "typescript"]}),
            template_id="fake-py-service", name_provider=lambda: 'Chat Service',
            confirm=lambda _: True, templates_root=TEMPLATES_FIXTURES,
            register=register, db_path=self.db_path, dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        self.assertEqual(res.status, "created")
        self.assertEqual(len(calls), 2)
        self.assertEqual(res.message.count("Desktop registration failed:"), 2)
        for name, path in calls:
            self.assertIn(json.dumps(reason), res.message)
            self.assertIn("desktop_project " + json.dumps({"action": "create", "name": name, "path": path}), res.message)

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_happy_path_mono_creates_project_git_commit_and_saves_state(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        reg_calls: List[Tuple[str, str]] = []

        def fake_register(name: str, path: str) -> str:
            reg_calls.append((name, path))
            return json.dumps({"success": True, "id": "proj-1", "name": name, "path": path})

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: "Star Cruiser",
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            register=fake_register,
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertIsInstance(res, FlowResult)
        self.assertIn(res.status, VALID_FLOW_STATUSES)
        self.assertEqual(res.status, "created")
        self.assertEqual(res.matches, [])  # an explicit id is not matched
        self.assertIsNotNone(res.proposal)
        self.assertIsNotNone(res.accept)

        dest = self.dest_root / "star-cruiser"
        self.assertTrue(dest.is_dir())
        self.assertTrue((dest / ".git").is_dir())
        assert res.proposal is not None
        self.assertFalse(res.proposal.staging_dir.exists())

        log_proc = run_git_hardened(dest, ["log", "--oneline"], check=True)
        commits = [ln for ln in log_proc.stdout.decode("utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(commits), 1)
        self.assertIn("fake-rust-game", commits[0])

        self.assertEqual(len(reg_calls), 1)
        self.assertEqual(reg_calls[0], ("Star Cruiser", str(dest)))
        proj_row = get_project(dest, db_path=self.db_path)
        self.assertIsNotNone(proj_row)
        assert proj_row is not None
        self.assertEqual(proj_row["name"], "Star Cruiser")

        rows = self._answers_rows()
        self.assertGreaterEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0][1]), answers_script)

    def test_no_id_with_unmatched_answers_returns_needs_choice_and_saves_nothing(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "single",
            "languages": ["cpp"],
            "engine": "unreal",
        }
        sent_payloads: List[Dict[str, Any]] = []

        def fake_sender(payload: Dict[str, Any], *, timeout: Optional[float] = None) -> Dict[str, Any]:
            sent_payloads.append(dict(payload))
            return {"dispatched": True}

        res = run_new_project_flow(
            initial_answers=answers_script,
            ask=lambda _q, _p: self.fail("ask must not be called without an id"),
            name_provider=lambda: "Unreal Demo",
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            kits=[],
            db_path=self.db_path,
            dest_root=self.dest_root,
        )

        self.assertEqual(res.status, "needs_choice")
        self.assertIn(res.status, VALID_FLOW_STATUSES)
        self.assertEqual(res.message, "")
        self.assertEqual(res.matches, [])
        self.assertIsNone(res.proposal)
        self.assertIsNone(res.accept)
        self.assertEqual(sent_payloads, [])
        self.assertFalse(self.db_path.exists())
        self.assertEqual(list(self.dest_root.iterdir()), [])

    def test_no_id_with_matching_answers_returns_needs_choice_with_matches_and_saves_nothing(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }

        res = run_new_project_flow(
            initial_answers=answers_script,
            name_provider=lambda: "Rust Game",
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            kits=[],
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertEqual(res.status, "needs_choice")
        self.assertEqual(res.message, "")
        self.assertEqual([m.template.id for m in res.matches], ["fake-rust-game"])
        self.assertFalse(self.db_path.exists())
        self.assertEqual(self._answers_rows(), [])
        self.assertEqual(list(self.dest_root.iterdir()), [])
        self.assertEqual(list(self.staging_parent.iterdir()), [])

    def test_ask_returns_none_times_out(self) -> None:
        answers_script = {
            "building": "game",
            "layout": None,
        }

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: "Game",
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            db_path=self.db_path,
            dest_root=self.dest_root,
        )

        self.assertEqual(res.status, "timeout")
        self.assertIsNone(res.proposal)
        self.assertIsNone(res.accept)

    def test_name_provider_returns_none_times_out(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: None,
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            db_path=self.db_path,
            dest_root=self.dest_root,
        )

        self.assertEqual(res.status, "timeout")
        self.assertIsNone(res.proposal)
        self.assertEqual(len(self._answers_rows()), 0)

    def test_confirm_false_declines_and_removes_staging(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        seen_staging: List[Path] = []

        def confirm_decline(prop: Proposal) -> bool:
            seen_staging.append(prop.staging_dir)
            self.assertTrue(prop.staging_dir.exists())
            return False

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: "Declined Game",
            confirm=confirm_decline,
            templates_root=TEMPLATES_FIXTURES,
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertEqual(res.status, "declined")
        self.assertIsNotNone(res.proposal)
        self.assertIsNone(res.accept)
        self.assertEqual(len(seen_staging), 1)
        self.assertFalse(seen_staging[0].exists())
        self.assertFalse((self.dest_root / "declined-game").exists())
        self.assertEqual(len(self._answers_rows()), 0)
        self.assertFalse(self.db_path.exists())

    def test_confirm_none_times_out_and_removes_staging(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        seen_staging: List[Path] = []

        def confirm_timeout(prop: Proposal) -> Optional[bool]:
            seen_staging.append(prop.staging_dir)
            self.assertTrue(prop.staging_dir.exists())
            return None

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: "Timed Out Game",
            confirm=confirm_timeout,
            templates_root=TEMPLATES_FIXTURES,
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertEqual(res.status, "timeout")
        self.assertIsNotNone(res.proposal)
        self.assertIsNone(res.accept)
        self.assertEqual(len(seen_staging), 1)
        self.assertFalse(seen_staging[0].exists())
        self.assertFalse((self.dest_root / "timed-out-game").exists())
        self.assertEqual(len(self._answers_rows()), 0)

    def test_shared_deadline_across_callbacks_times_out_and_cleans_staging(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        now = 100.0

        def clock() -> float:
            return now

        def slow_confirm(prop: Proposal) -> bool:
            nonlocal now
            # Advance clock past the 10s deadline during confirm
            now = 115.0
            return True

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: "Clock Game",
            confirm=slow_confirm,
            templates_root=TEMPLATES_FIXTURES,
            timeout_s=10.0,
            clock=clock,
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertEqual(res.status, "timeout")
        assert res.proposal is not None
        self.assertFalse(res.proposal.staging_dir.exists())
        self.assertFalse((self.dest_root / "clock-game").exists())

    def test_wall_clock_budget_enforced_across_flow_callbacks(self) -> None:
        import contextvars
        import threading
        import time

        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        cvar: contextvars.ContextVar[str] = contextvars.ContextVar("flow_cvar", default="missing")
        seen_cvars: Dict[str, str] = {}
        release_confirm = threading.Event()
        confirm_finished = threading.Event()

        def ask_cb(q: Question, _prefill: List[str]) -> Optional[Any]:
            seen_cvars[f"ask:{q.id}"] = cvar.get()
            return answers_script.get(q.id)

        def name_cb() -> str:
            seen_cvars["name"] = cvar.get()
            return "Wall Clock Game"

        def slow_confirm(prop: Proposal) -> bool:
            seen_cvars["confirm"] = cvar.get()
            # Mutate the callback's proposal copy before and after timeout
            prop.staging_dir = self.tmp_root / "mutated-staging"
            prop.repos.clear()
            release_confirm.wait(timeout=5.0)
            confirm_finished.set()
            return True

        token = cvar.set("ctx-ok")
        try:
            started = time.monotonic()
            res = run_new_project_flow(
                ask=ask_cb,
                template_id="fake-rust-game",
                name_provider=name_cb,
                confirm=slow_confirm,
                templates_root=TEMPLATES_FIXTURES,
                # Budget must cover template loading under load so the flow reliably
                # reaches confirm; confirm then blocks far past it (5 s).
                timeout_s=0.5,
                db_path=self.db_path,
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(res.status, "timeout")
            self.assertLess(elapsed, 2.0)
            release_confirm.set()
            self.assertTrue(confirm_finished.wait(timeout=5.0))

            # Even after confirm released late and returned True, flow outcome remains timeout
            # and staging directory was properly cleaned up despite confirm mutating its copy.
            self.assertIsNotNone(res.proposal)
            assert res.proposal is not None
            self.assertEqual(len(res.proposal.repos), 1)
            self.assertFalse(res.proposal.staging_dir.exists())
            self.assertEqual(list(self.staging_parent.iterdir()), [])
            self.assertFalse((self.dest_root / "wall-clock-game").exists())
            self.assertEqual(seen_cvars.get("ask:building"), "ctx-ok")
            self.assertEqual(seen_cvars.get("name"), "ctx-ok")
            self.assertEqual(seen_cvars.get("confirm"), "ctx-ok")
        finally:
            cvar.reset(token)

    def test_scaffold_error_returns_error_status_with_message(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        # Pre-create destination to trigger ScaffoldError in propose()
        (self.dest_root / "taken-game").mkdir(parents=True)

        res = run_new_project_flow(
            ask=_scripted_ask(answers_script),
            template_id="fake-rust-game",
            name_provider=lambda: "Taken Game",
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertEqual(res.status, "error")
        self.assertIn("taken-game", res.message)
        self.assertEqual(len(self._answers_rows()), 0)

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_permission_error_discards_staging_and_returns_error_status(self) -> None:
        answers_script = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        seen_staging: List[Path] = []

        def capture_confirm(prop: Proposal) -> bool:
            seen_staging.append(prop.staging_dir)
            self.assertTrue(prop.staging_dir.exists())
            return True

        real_rename = os.rename

        def denied(src, dst, *a, **k):
            if dst == "perm-denied-game" and k.get("dst_dir_fd") is not None:  # the move into the projects folder
                raise PermissionError(13, "Permission denied")
            return real_rename(src, dst, *a, **k)

        with mock.patch.object(os, "rename", side_effect=denied):
            res = run_new_project_flow(
                ask=_scripted_ask(answers_script),
                template_id="fake-rust-game",
                name_provider=lambda: "Perm Denied Game",
                confirm=capture_confirm,
                templates_root=TEMPLATES_FIXTURES,
                db_path=self.db_path,
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )

        self.assertEqual(res.status, "error")
        self.assertIn("permission was denied", res.message)
        self.assertEqual(len(seen_staging), 1)
        self.assertFalse(seen_staging[0].exists())
        self.assertEqual(list(self.staging_parent.iterdir()), [])
        self.assertFalse(self.db_path.exists())

    def test_flow_with_free_text_prompt_options_and_check_failure_retains_staging(self) -> None:
        # Create a service template with options and a configurable check command
        tmpl_root = self.tmp_root / "custom_templates"
        svc_dir = tmpl_root / "ts-svc"
        repo_dir = svc_dir / "tmpl_prefix"
        repo_dir.mkdir(parents=True)
        (repo_dir / ".env.example").write_text(
            "TMPL_PREFIX_HTTP_ADAPTER=hono\n",
            encoding="utf-8",
        )
        (repo_dir / "index.ts").write_text(
            "export const SERVICE = 'tmpl_prefix';\n",
            encoding="utf-8",
        )
        (svc_dir / "template.yaml").write_text(
            "id: ts-svc\n"
            "name: TS Service\n"
            "summary: TypeScript service with options\n"
            "kind: service\n"
            "layout: mono\n"
            "languages: [typescript]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in: [\".env.example\", \"**/*.ts\"]\n"
            "options:\n"
            "  http_adapter:\n"
            "    label: \"HTTP adapter\"\n"
            "    choices: [hono, node_http]\n"
            "    default: hono\n"
            "    env_key: TMPL_PREFIX_HTTP_ADAPTER\n"
            "repos:\n"
            "  - name: tmpl_prefix\n"
            "    check:\n"
            f"      cmd: [{json.dumps(sys.executable)}, \"-c\", \"print('ci ok')\"]\n"
            "      cwd: \".\"\n",
            encoding="utf-8",
        )

        # 1. Free-text prompt + choose_options callback -> created, chips populated, template_options recorded
        res = run_new_project_flow(
            prompt="Invoice tracker API for my shop — TypeScript",
            template_id="ts-svc",
            choose_options=lambda _tmpl, defaults: {**defaults, "http_adapter": "node_http"},
            confirm=lambda _prop: True,
            templates_root=tmpl_root,
            register=lambda name, path: json.dumps({"success": True, "id": "p-inv", "name": name, "path": path}),
            db_path=self.db_path,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        self.assertEqual(res.status, "created")
        self.assertIsNotNone(res.parsed_prompt)
        assert res.parsed_prompt is not None
        self.assertEqual(res.parsed_prompt.chips_text, 'service · typescript · "Invoice Tracker"')
        self.assertEqual(res.options, {"http_adapter": "node_http"})
        created_dir = self.dest_root / "invoice-tracker"
        self.assertTrue(created_dir.is_dir())
        self.assertIn(
            "INVOICE_TRACKER_HTTP_ADAPTER=node_http",
            (created_dir / ".env.example").read_text(encoding="utf-8"),
        )
        opt_row = get_template_option("ts-svc", "http_adapter", db_path=self.db_path)
        self.assertIsNotNone(opt_row)
        assert opt_row is not None
        self.assertEqual(opt_row["choice"], "node_http")

        # 2. Check failure during accept in flow -> status='error', output returned, staging kept, no dest or DB row
        fail_db = self.tmp_root / "fail_state.db"
        fail_dest_root = self.tmp_root / "fail_projects"
        fail_dest_root.mkdir(parents=True, exist_ok=True)
        (svc_dir / "template.yaml").write_text(
            "id: ts-svc\n"
            "name: TS Service\n"
            "summary: TypeScript service with failing check\n"
            "kind: service\n"
            "layout: mono\n"
            "languages: [typescript]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in: [\".env.example\", \"**/*.ts\"]\n"
            "options:\n"
            "  http_adapter:\n"
            "    label: \"HTTP adapter\"\n"
            "    choices: [hono, node_http]\n"
            "    default: hono\n"
            "    env_key: TMPL_PREFIX_HTTP_ADAPTER\n"
            "repos:\n"
            "  - name: tmpl_prefix\n"
            "    check:\n"
            f"      cmd: [{json.dumps(sys.executable)}, \"-c\", \"import sys; sys.stderr.write('xtask check failed: layer violation\\\\n'); sys.exit(1)\"]\n"
            "      cwd: \".\"\n",
            encoding="utf-8",
        )
        res_fail = run_new_project_flow(
            prompt="Billing webhook API — TypeScript",
            template_id="ts-svc",
            confirm=lambda _prop: True,
            templates_root=tmpl_root,
            register=lambda name, path: json.dumps({"success": True, "id": "p-never"}),
            db_path=fail_db,
            dest_root=fail_dest_root,
            staging_parent=self.staging_parent,
        )
        self.assertEqual(res_fail.status, "error")
        self.assertIn("xtask check failed: layer violation", res_fail.output)
        self.assertIn("xtask check failed: layer violation", res_fail.message)
        self.assertIsNotNone(res_fail.proposal)
        assert res_fail.proposal is not None
        # Staging must be kept on check failure!
        self.assertTrue(res_fail.proposal.staging_dir.is_dir())
        self.assertEqual(list(fail_dest_root.iterdir()), [])
        self.assertFalse(fail_db.exists())
        scaffolder.discard(res_fail.proposal)

        # 3. Headless timeout in choose_options callback returns status='timeout'
        res_opt_timeout = run_new_project_flow(
            prompt="Order API — TypeScript",
            template_id="ts-svc",
            choose_options=lambda _tmpl, _defaults: None,
            confirm=lambda _prop: True,
            templates_root=tmpl_root,
            register=lambda name, path: json.dumps({"success": True, "id": "p-never"}),
            db_path=fail_db,
            dest_root=fail_dest_root,
            staging_parent=self.staging_parent,
        )
        self.assertEqual(res_opt_timeout.status, "timeout")
        self.assertEqual(list(fail_dest_root.iterdir()), [])
        self.assertFalse(fail_db.exists())


if __name__ == "__main__":
    unittest.main()


class ToolNeedCopyTests(unittest.TestCase):
    def test_go_template_tool_needs_survive_copy_deepcopy_and_pickle(self) -> None:
        import copy
        import pickle
        from types import MappingProxyType

        from hermes_plugins.defuzz import new_project, templates as templates_mod

        specs = {s.id: s for s in templates_mod.load_templates(new_project.default_templates_root())}
        needs = [n for n in specs["go-golden"].needs if isinstance(n, templates_mod._ToolNeedStr)]
        self.assertTrue(any(isinstance(n.version_probe, MappingProxyType) for n in needs))
        for need in needs:
            for twin in (copy.copy(need), copy.deepcopy(need), pickle.loads(pickle.dumps(need))):
                self.assertIsInstance(twin, templates_mod._ToolNeedStr)
                self.assertEqual(twin, need)
                self.assertEqual(hash(twin), hash(need))
                self.assertEqual(type(twin.version_probe), type(need.version_probe))
                if isinstance(need.version_probe, MappingProxyType):
                    self.assertEqual(dict(twin.version_probe), dict(need.version_probe))
                else:
                    self.assertEqual(twin.version_probe, need.version_probe)


class RemovedFlowParametersTest(unittest.TestCase):
    def test_removed_parameters_are_no_longer_accepted(self) -> None:
        for name in ("choose", "sender", "llm", "ctx"):
            with self.subTest(name=name):
                with self.assertRaises(TypeError):
                    run_new_project_flow(**{name: None}, templates=[], kits=[])
