"""Rules-derived text written into AGENTS.md is escaped; template checks get opt-out defaults."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import agents_md, catalog_list, scaffolder  # noqa: E402
from hermes_plugins.defuzz.agents_md import render_from_rules  # noqa: E402
from hermes_plugins.defuzz.lint_env import LINT_OPTOUT_DEFAULTS  # noqa: E402
from hermes_plugins.defuzz.scaffolder import accept, propose  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # noqa: E402

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"

HOSTILE = ["\u202e", "\u200b", "\u2066", "\x1b", "\x00", "\x7f", "\ufeff", "\u00ad"]


def _rules(text: str) -> Dict[str, Any]:
    return {
        "project_slug": f"proj{text}",
        "declared_dirs": [{"dir": "src", "summary": f"code{text}here", "why": f"why{text}"}],
        "placement_rules": [{"match_ext": [f".rs{text}"], "dest_dir": "src", "reason": f"keep{text}tidy"}],
        "lfs_patterns": [f"*.bin{text}"],
        "ignore_patterns": [f"target{text}"],
        "local_only_branches": [f"scratch{text}"],
    }


def _all_text(files: Dict[str, str]) -> str:
    return "".join(files.values())


class TestAgentsMdTextSafety(unittest.TestCase):
    def test_hostile_characters_never_reach_agents_md(self) -> None:
        for ch in HOSTILE:
            with self.subTest(ch=repr(ch)):
                out = _all_text(render_from_rules(_rules(ch)))
                self.assertNotIn(ch, out)
                self.assertIn("keep" + catalog_list.escape_text(ch) + "tidy", out)
                self.assertIn("code" + catalog_list.escape_text(ch) + "here", out)
                self.assertIn("proj" + catalog_list.escape_text(ch), out)
                self.assertIn("scratch" + catalog_list.escape_text(ch), out)

    def test_kit_ids_escaped(self) -> None:
        out = _all_text(render_from_rules(_rules(""), kit_ids=["kit\u202eevil"]))
        self.assertNotIn("\u202e", out)
        self.assertIn("kit\\u202eevil", out)

    def test_already_escaped_text_is_not_escaped_twice(self) -> None:
        # placer escapes a reason before it is stored; rendering it again must not change it.
        once = catalog_list.escape_text("keep\u202etidy")
        out = _all_text(render_from_rules(_rules("") | {
            "placement_rules": [{"match_ext": [".rs"], "dest_dir": "src", "reason": once}],
        }))
        self.assertIn(f"({once}).", out)
        self.assertNotIn("\\\\u202e", out)
        self.assertEqual(agents_md._sanitize_token(once), agents_md._sanitize_token("keep\u202etidy"))

    def test_bundled_templates_render_byte_identical(self) -> None:
        paths = sorted((PLUGIN_ROOT / "templates").glob("*/rules.json"))
        self.assertGreaterEqual(len(paths), 7)
        for path in paths:
            with self.subTest(template=path.parent.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                after = render_from_rules(data)
                with mock.patch.object(agents_md, "escape_text", lambda s: s):
                    before = render_from_rules(data)
                self.assertEqual(after, before)

    def test_plain_text_unchanged(self) -> None:
        self.assertEqual(agents_md._sanitize_token("  plain\ttext \n here  "), "plain text here")
        self.assertEqual(agents_md._sanitize_token("café — ok"), "café — ok")


class TestTemplateCheckOptOuts(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.dest_root = self.tmp_root / "projects"
        self.staging_parent = self.tmp_root / "staging"
        self.dest_root.mkdir()
        self.staging_parent.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _check_envs(self, environ: Dict[str, str]) -> List[Dict[str, str]]:
        seen: List[Dict[str, str]] = []
        real_run = scaffolder._run_check_command

        # The check child is started by _run_check_command; a fake one records its
        # environment, so the test needs no real cargo.
        def fake_run(args, *a, **kw):  # type: ignore[no-untyped-def]
            if list(args)[:1] == ["cargo"]:
                seen.append(dict(kw.get("env") or {}))
                return subprocess.CompletedProcess(list(args), 0, "", "")
            return real_run(args, *a, **kw)

        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        proposal = propose(
            spec, "My Game", {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
            dest_root=self.dest_root, staging_parent=self.staging_parent,
        )
        with mock.patch.dict(os.environ, environ), \
                mock.patch.object(scaffolder.toolchk, "probe", return_value=("1.0", "/fixture/tool")), \
                mock.patch.object(scaffolder, "_run_check_command", side_effect=fake_run):
            accept(
                proposal,
                register=lambda n, p: json.dumps({"success": True, "id": "p1", "name": n, "path": p}),
                db_path=self.tmp_root / "state.db",
                timeout_s=60.0,
            )
        self.assertTrue(seen, "template check did not run")
        return seen

    def test_check_child_gets_optout_defaults(self) -> None:
        cleared = {k: "" for k in LINT_OPTOUT_DEFAULTS}
        with mock.patch.dict(os.environ, cleared):
            for k in LINT_OPTOUT_DEFAULTS:
                os.environ.pop(k, None)
            envs = self._check_envs({})
        for env in envs:
            for key, value in LINT_OPTOUT_DEFAULTS.items():
                self.assertEqual(env.get(key), value)

    def test_users_own_value_is_kept(self) -> None:
        envs = self._check_envs({"POWERSHELL_UPDATECHECK": "LTS", "DOTNET_NOLOGO": "0"})
        for env in envs:
            self.assertEqual(env["POWERSHELL_UPDATECHECK"], "LTS")
            self.assertEqual(env["DOTNET_NOLOGO"], "0")
            self.assertEqual(env["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")


if __name__ == "__main__":
    unittest.main()
