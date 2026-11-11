"""Unit tests for scaffolder.py (propose, accept, discard, default_project_create, and timeout)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import pytest
from contextlib import closing
from pathlib import Path
from typing import Any, List, Tuple
from unittest import mock

from tests import ensure_test_package
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.naming import PrefixForms, forms_from_placeholder, forms_from_slug  # noqa: E402
from hermes_plugins.defuzz.safety import run_git_hardened  # noqa: E402
from hermes_plugins.defuzz.scaffolder import (  # noqa: E402
    AcceptResult,
    Proposal,
    RepoPlan,
    ScaffoldError,
    ScaffoldTimeout,
    accept,
    default_project_create,
    discard,
    poly_dest_name,
    projects_root,
    propose,
    resolve_plugin_commit,
)
from hermes_plugins.defuzz.state_store import (  # noqa: E402
    get_project,
    get_template_option,
    get_template_options,
    list_projects,
    list_template_options,
)
from hermes_plugins.defuzz.templates import (  # noqa: E402
    CheckSpec,
    OptionSpec,
    RepoSpec,
    TemplateSpec,
    load_template,
    templates_root,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEMPLATES_FIXTURES = FIXTURES_DIR / "templates"


@pytest.fixture
def componentize_live():
    pass


class TestScaffolder(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.dest_root = self.tmp_root / "projects"
        self.staging_parent = self.tmp_root / "staging"
        self.db_path = self.tmp_root / "state.db"
        self.dest_root.mkdir(parents=True, exist_ok=True)
        self.staging_parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @pytest.mark.usefixtures("componentize_live")
    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_new_survey_real_bridge_independent_of_adopt_flag(self):
        from hermes_plugins.defuzz import componentize_settings
        executable = self.tmp_root / 'survey-cli'
        marker = self.tmp_root / 'survey-called'
        executable.write_text('#!' + sys.executable + '\n' +
            'import json, sys\nfrom pathlib import Path\n' +
            'if "--version" in sys.argv: print("stub 1"); sys.exit(0)\n' +
            f'Path({str(marker)!r}).write_text("called")\n' +
            'print(json.dumps(dict(schema="componentize.survey/1", ok=True, status="ok", error=None, findings=[], path=sys.argv[2], exit=0, files=[], proposed_splits=[])))\n')
        executable.chmod(0o755)
        for enabled in (True, False):
            with self.subTest(new=enabled):
                marker.unlink(missing_ok=True)
                proposal = propose(load_template(TEMPLATES_FIXTURES / 'fake-rust-game'),
                    'Independent ' + str(enabled), {'languages': ['rust']},
                    dest_root=self.dest_root, staging_parent=self.staging_parent)
                prefs = {**componentize_settings.DEFAULTS, 'enabled_on_adopt': False,
                         'run_survey_on_new': enabled, 'cli_path_override': str(executable)}
                with mock.patch.object(componentize_settings, 'load', return_value=prefs):
                    result = accept(proposal, register=lambda n, p: json.dumps({'success': True, 'id': n}), db_path=self.db_path)
                dest = proposal.repos[0].dest
                self.assertEqual(marker.exists(), enabled)
                self.assertEqual((dest / '.adopt/componentize-survey.json').exists(), enabled)
                self.assertEqual(run_git_hardened(dest, ['status', '--porcelain'], check=True).stdout, b'')

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_componentize_survey_after_success_is_committed(self) -> None:
        from hermes_plugins.defuzz import componentize_settings, componentize_bridge
        proposal = propose(load_template(TEMPLATES_FIXTURES / 'fake-rust-game'),
                           'Survey Game', {'languages': ['rust']},
                           dest_root=self.dest_root, staging_parent=self.staging_parent)
        def survey(root):
            self.assertFalse(proposal.staging_dir.exists())
            self.assertIsNotNone(get_project(root, db_path=self.db_path))
            (root / '.adopt').mkdir(exist_ok=True)
            (root / '.adopt/componentize-survey.json').write_text('{}\n')
            (root / 'AGENTS.md').write_text('Review candidates\n')
            return {'status': 'ok', 'exit': 0}
        with mock.patch.object(componentize_settings, 'load', return_value={**componentize_settings.DEFAULTS, 'run_survey_on_new': True}), \
             mock.patch.object(componentize_bridge, 'survey_project', side_effect=survey) as run:
            result = accept(proposal, register=lambda n, p: json.dumps({'success': True, 'id': 'survey'}), db_path=self.db_path)
        run.assert_called_once_with(proposal.repos[0].dest)
        self.assertEqual(result.repos[0]['componentize']['status'], 'ok')
        dest = proposal.repos[0].dest
        self.assertEqual(run_git_hardened(dest, ['status', '--porcelain'], check=True).stdout, b'')
        self.assertEqual(result.repos[0]['commit'], run_git_hardened(dest, ['rev-parse', 'HEAD^'], check=True).stdout.decode().strip())
        self.assertEqual(result.repos[0]['survey_commit'], run_git_hardened(dest, ['rev-parse', 'HEAD'], check=True).stdout.decode().strip())

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_componentize_commit_failure_restores_survey_files(self) -> None:
        from hermes_plugins.defuzz import componentize_settings, componentize_bridge
        for existing in (False, True):
            with self.subTest(existing=existing):
                proposal = propose(load_template(TEMPLATES_FIXTURES / 'fake-rust-game'),
                                   'Survey rollback ' + str(existing), {'languages': ['rust']},
                                   dest_root=self.dest_root, staging_parent=self.staging_parent)
                originals = {}
                def survey(root):
                    for path in ('AGENTS.md', componentize_bridge.SURVEY_PATH):
                        target = root / path
                        if existing:
                            target.parent.mkdir(exist_ok=True)
                            target.write_text('Original content\n')
                            run_git_hardened(root, ['add', '--', path], check=True)
                    if existing:
                        run_git_hardened(root, ['-c', 'user.name=Test', '-c', 'user.email=test@example.com',
                                               'commit', '-qm', 'existing survey files'], check=True)
                    for path in ('AGENTS.md', componentize_bridge.SURVEY_PATH):
                        target = root / path
                        originals[path] = target.read_bytes() if target.exists() else None
                        target.parent.mkdir(exist_ok=True)
                        target.write_text('Uncommitted survey output\n')
                    return {'status': 'ok', 'exit': 0}
                def git(root, args, **kwargs):
                    if 'chore: record optional componentize survey' in args:
                        raise subprocess.CalledProcessError(1, args, stderr=b'commit rejected')
                    return run_git_hardened(root, args, **kwargs)
                with mock.patch.object(componentize_settings, 'load', return_value={**componentize_settings.DEFAULTS, 'run_survey_on_new': True}), \
                     mock.patch.object(componentize_bridge, 'survey_project', side_effect=survey), \
                     mock.patch.object(scaffolder, 'run_git_hardened', side_effect=git):
                    result = accept(proposal, register=lambda n, p: json.dumps({'success': True, 'id': n}), db_path=self.db_path)
                dest = proposal.repos[0].dest
                self.assertEqual(run_git_hardened(dest, ['status', '--porcelain'], check=True).stdout, b'')
                for path, content in originals.items():
                    if content is None:
                        self.assertFalse((dest / path).exists())
                    else:
                        self.assertEqual((dest / path).read_bytes(), content)
                self.assertNotIn('survey_commit', result.repos[0])
                self.assertEqual(result.repos[0]['componentize']['status'], 'skipped')
                self.assertIn('project creation succeeded', result.repos[0]['componentize']['notice'])

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_componentize_optional_failures_and_default_off(self) -> None:
        from hermes_plugins.defuzz import componentize_settings, componentize_bridge
        for mode in ('default', 'settings-error', 'survey-error', 'skipped'):
            with self.subTest(mode=mode):
                proposal = propose(load_template(TEMPLATES_FIXTURES / 'fake-rust-game'),
                                   'Survey ' + mode, {'languages': ['rust']},
                                   dest_root=self.dest_root, staging_parent=self.staging_parent)
                prefs = {**componentize_settings.DEFAULTS, 'run_survey_on_new': mode != 'default'}
                with mock.patch.object(componentize_settings, 'load', return_value=prefs,
                                       side_effect=ValueError('corrupt') if mode == 'settings-error' else None), \
                     mock.patch.object(componentize_bridge, 'survey_project',
                                       return_value={'status': 'skipped', 'exit': 0},
                                       side_effect=OSError('failed') if mode == 'survey-error' else None) as run:
                    result = accept(proposal, register=lambda n, p: json.dumps({'success': True, 'id': mode}), db_path=self.db_path)
                self.assertTrue(proposal.repos[0].dest.is_dir())
                self.assertGreater(result.answers_id, 0)
                if mode in ('default', 'settings-error'):
                    run.assert_not_called()
                if mode == 'default':
                    self.assertNotIn('componentize', result.repos[0])
                else:
                    self.assertEqual(result.repos[0]['componentize']['status'], 'skipped')
                    self.assertTrue(result.repos[0]['componentize']['notice'])

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_componentize_not_run_when_acceptance_fails(self) -> None:
        from hermes_plugins.defuzz import componentize_settings, componentize_bridge
        proposal = propose(load_template(TEMPLATES_FIXTURES / 'fake-rust-game'),
                           'Survey Failure', {'languages': ['rust']},
                           dest_root=self.dest_root, staging_parent=self.staging_parent)
        with mock.patch.object(componentize_settings, 'load') as load, \
             mock.patch.object(componentize_bridge, 'survey_project') as run, \
             mock.patch.object(scaffolder, 'save_answers', side_effect=OSError('failed')):
            # save_answers runs after the project folder is in place, so the error says the
            # folder exists (created_dirs) and keeps the original error as its cause.
            with self.assertRaises(ScaffoldError) as ctx:
                accept(proposal, register=lambda n, p: json.dumps({'success': True, 'id': 'failure'}), db_path=self.db_path)
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        self.assertEqual(str(ctx.exception.__cause__), 'failed')
        self.assertEqual(ctx.exception.created_dirs, [proposal.repos[0].dest])
        self.assertTrue(proposal.repos[0].dest.is_dir())
        load.assert_not_called()
        run.assert_not_called()

    def test_projects_root_env_and_default(self) -> None:
        custom = self.tmp_root / "custom_projects"
        with mock.patch.dict(os.environ, {"HERMES_PROJECTS_ROOT": str(custom)}):
            self.assertEqual(projects_root(), custom)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HERMES_PROJECTS_ROOT", None)
            home = self.tmp_root / "home"
            (home / ".hermes").mkdir(parents=True)
            with mock.patch.dict(os.environ, {"HOME": str(home), "HERMES_HOME": str(home / ".hermes")}):
                with self.assertRaisesRegex(ScaffoldError, "No projects folder has been chosen yet"):
                    projects_root()
            self.assertFalse((home / "Projects").exists())

    def test_propose_mono_fake_rust_game(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        answers = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}

        proposal = propose(
            spec,
            "My Game",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertIsInstance(proposal, Proposal)
        self.assertEqual(proposal.template_id, "fake-rust-game")
        self.assertEqual(proposal.slug, "my-game")
        self.assertEqual(proposal.display_name, "My Game")
        self.assertEqual(
            proposal.forms,
            PrefixForms(
                kebab="my-game",
                snake="my_game",
                screaming="MY_GAME",
                pascal="MyGame",
            ),
        )
        self.assertEqual(proposal.answers, answers)
        self.assertTrue(proposal.staging_dir.is_dir())
        self.assertEqual(proposal.staging_dir.parent, self.staging_parent)
        self.assertTrue(proposal.staging_dir.name.startswith("adopt-scaffold-"))

        self.assertEqual(len(proposal.repos), 1)
        plan = proposal.repos[0]
        self.assertIsInstance(plan, RepoPlan)
        self.assertEqual(plan.name, "my_game")
        self.assertEqual(plan.dest, self.dest_root / "my-game")
        self.assertEqual(plan.staged, proposal.staging_dir / "my_game")
        self.assertTrue(plan.staged.is_dir())
        # Destination should NOT exist yet during propose()
        self.assertFalse(plan.dest.exists())

        # Check renamed file contents
        cargo_toml = (plan.staged / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('name = "my_game"', cargo_toml)
        self.assertNotIn("tmpl_prefix", cargo_toml)

        main_rs = (plan.staged / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertIn("MyGameApp", main_rs)
        self.assertIn("MY_GAME_VERSION", main_rs)
        self.assertNotIn("TmplPrefix", main_rs)
        self.assertNotIn("TMPL_PREFIX", main_rs)

        readme = (plan.staged / "README.md").read_text(encoding="utf-8")
        self.assertIn("# my-game", readme)
        self.assertIn("`my_game`", readme)
        self.assertIn("`MyGame`", readme)
        self.assertIn("`MY_GAME`", readme)

        # Path renamed: tmpl_prefix_core/lib.rs -> my_game_core/lib.rs
        core_lib = plan.staged / "my_game_core" / "lib.rs"
        self.assertTrue(core_lib.is_file())
        self.assertFalse((plan.staged / "tmpl_prefix_core").exists())
        self.assertIn("MyGameCore", core_lib.read_text(encoding="utf-8"))

        # Binary file untouched (byte-identical)
        orig_logo = (TEMPLATES_FIXTURES / "fake-rust-game" / "tmpl_prefix" / "assets" / "logo.png").read_bytes()
        staged_logo = (plan.staged / "assets" / "logo.png").read_bytes()
        self.assertEqual(staged_logo, orig_logo)
        self.assertEqual(len(orig_logo), 26)
        self.assertEqual(hashlib.sha256(orig_logo).hexdigest(),
                         '4180453a1d9bc0ec080951f7734657912f8d2bec001389ed3e23c7176a3fdfd8')
        self.assertIn(b"\x00", staged_logo)

        # Tree lines sorted with directories ending in '/'
        self.assertEqual(plan.tree, sorted(plan.tree))
        self.assertIn("assets/", plan.tree)
        self.assertIn("assets/logo.png", plan.tree)
        self.assertIn("my_game_core/", plan.tree)
        self.assertIn("my_game_core/lib.rs", plan.tree)
        self.assertIn("src/", plan.tree)
        self.assertIn("src/main.rs", plan.tree)
        self.assertIn("Cargo.toml", plan.tree)
        self.assertIn("README.md", plan.tree)
        for entry in plan.tree:
            if (plan.staged / entry.rstrip("/")).is_dir():
                self.assertTrue(entry.endswith("/"), f"Dir entry {entry!r} must end with '/'")
            else:
                self.assertFalse(entry.endswith("/"), f"File entry {entry!r} must not end with '/'")

        discard(proposal)
        self.assertFalse(proposal.staging_dir.exists())

    def test_propose_poly_fake_py_service(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-py-service")
        answers = {"building": "service", "layout": "poly", "languages": ["python", "typescript"]}

        proposal = propose(
            spec,
            "My Svc",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        self.assertEqual(proposal.slug, "my-svc")
        self.assertEqual(len(proposal.repos), 2)

        api_plan, web_plan = proposal.repos[0], proposal.repos[1]
        self.assertEqual(api_plan.name, "my_svc_api")
        self.assertEqual(api_plan.dest, self.dest_root / "my-svc-api")
        self.assertEqual(web_plan.name, "my_svc_web")
        self.assertEqual(web_plan.dest, self.dest_root / "my-svc-web")

        # Verify nested package dir renamed in api repo
        init_py = api_plan.staged / "my_svc" / "__init__.py"
        self.assertTrue(init_py.is_file())
        self.assertIn('SERVICE_NAME = "my-svc"', init_py.read_text(encoding="utf-8"))

        # Verify package.json name in web repo
        pkg_json = json.loads((web_plan.staged / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(pkg_json["name"], "my-svc-web")

        discard(proposal)

    def test_propose_tree_capped_at_400_lines_with_more_tail(self) -> None:
        # Build a custom template with > 400 files to test the 400-line cap
        tmpl_dir = self.tmp_root / "many-files-tmpl"
        repo_dir = tmpl_dir / "tmpl_prefix"
        repo_dir.mkdir(parents=True)
        (tmpl_dir / "template.yaml").write_text(
            "id: many-files-tmpl\n"
            "name: Many Files\n"
            "summary: Template with over 400 entries\n"
            "kind: tool\n"
            "layout: single\n"
            "languages: [python]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in: [\"**/*.py\"]\n"
            "repos:\n"
            "  - name: tmpl_prefix\n",
            encoding="utf-8",
        )
        for i in range(420):
            (repo_dir / f"file_{i:04d}.txt").write_text(f"hello {i}\n", encoding="utf-8")

        spec = load_template(tmpl_dir)
        proposal = propose(
            spec,
            "Big Tool",
            {"building": "tool", "layout": "single", "languages": ["python"]},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        tree = proposal.repos[0].tree
        self.assertEqual(len(tree), 400)
        self.assertEqual(tree[-1], "… 21 more")
        discard(proposal)

    def test_propose_skips_symlinks_and_never_writes_outside_staging(self) -> None:
        # Repro for review finding #1:
        # In a temp copy of fake-rust-game add symlink `tmpl_prefix/my_game_core -> <outside dir>`;
        # propose('My Game') renames tmpl_prefix_core/lib.rs -> my_game_core/lib.rs.
        # Symlink must be skipped (recorded in Proposal.skipped) and nothing written to outside dir.
        outside_dir = self.tmp_root / "outside_escape_target"
        outside_dir.mkdir(parents=True)

        tmpl_copy = self.tmp_root / "fake-rust-game"
        shutil.copytree(TEMPLATES_FIXTURES / "fake-rust-game", tmpl_copy)
        os.symlink(str(outside_dir), str(tmpl_copy / "tmpl_prefix" / "my_game_core"))
        os.symlink(str(outside_dir / "secret.txt"), str(tmpl_copy / "tmpl_prefix" / "dangling_link.rs"))

        spec = load_template(tmpl_copy)
        proposal = propose(
            spec,
            "My Game",
            {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        # Outside dir must remain completely empty!
        self.assertEqual(list(outside_dir.iterdir()), [])
        self.assertIn("my_game_core", proposal.skipped)
        self.assertIn("dangling_link.rs", proposal.skipped)

        staged = proposal.repos[0].staged
        self.assertFalse((staged / "dangling_link.rs").exists())
        self.assertFalse(os.path.islink(staged / "my_game_core"))
        self.assertTrue((staged / "my_game_core" / "lib.rs").is_file())
        discard(proposal)

    def test_propose_raises_on_renamed_path_collision(self) -> None:
        # Both `tmpl_prefix_core/lib.rs` (renamed) and a pre-existing plain file `my_game_core/lib.rs`
        # map to `my_game_core/lib.rs` when proposing "My Game". Must raise ScaffoldError.
        tmpl_copy = self.tmp_root / "fake-rust-game"
        shutil.copytree(TEMPLATES_FIXTURES / "fake-rust-game", tmpl_copy)
        colliding_dir = tmpl_copy / "tmpl_prefix" / "my_game_core"
        colliding_dir.mkdir(parents=True)
        (colliding_dir / "lib.rs").write_text("// colliding file\n", encoding="utf-8")

        spec = load_template(tmpl_copy)
        with self.assertRaises(ScaffoldError) as ctx:
            propose(
                spec,
                "My Game",
                {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )
        self.assertIn("collision", str(ctx.exception).lower())

    def test_propose_refuses_when_dest_exists(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        existing = self.dest_root / "my-game"
        existing.mkdir(parents=True)

        with self.assertRaises(ScaffoldError):
            propose(
                spec,
                "My Game",
                {"building": "game"},
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )

    def test_propose_refuses_when_dest_inside_live_hermes_dir(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        fake_hermes_home = self.tmp_root / "fake_hermes_home"
        fake_dest_root = fake_hermes_home / "projects"
        fake_dest_root.mkdir(parents=True)

        with mock.patch.dict(os.environ, {"HERMES_HOME": str(fake_hermes_home)}):
            with self.assertRaises(ScaffoldError):
                propose(
                    spec,
                    "My Game",
                    {"building": "game"},
                    dest_root=fake_dest_root,
                    staging_parent=self.staging_parent,
                )

    @mock.patch.object(scaffolder.toolchk, "probe", return_value=("1.0", "/fixture/tool"))
    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_mono_and_poly_success(self, _probe) -> None:
        # 1. Mono repo accept
        spec_mono = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        answers_mono = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
        proposal_mono = propose(
            spec_mono,
            "My Game",
            answers_mono,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        reg_calls: List[Tuple[str, str]] = []

        def fake_register(name: str, path: str) -> str:
            reg_calls.append((name, path))
            return json.dumps({"success": True, "id": f"p{len(reg_calls)}", "name": name, "path": path})

        result_mono = accept(
            proposal_mono,
            register=fake_register,
            db_path=self.db_path,
            timeout_s=60.0,
        )

        self.assertIsInstance(result_mono, AcceptResult)
        self.assertEqual(len(result_mono.repos), 1)
        dest_mono = self.dest_root / "my-game"
        self.assertTrue(dest_mono.is_dir())
        self.assertTrue((dest_mono / ".git").is_dir())
        self.assertTrue((dest_mono / "TOOLS.lock").is_file())
        # Runtime worktrees are local metadata, not shared ignore policy.
        exclude = dest_mono / '.git' / 'info' / 'exclude'
        self.assertIn('.worktrees/', exclude.read_text().splitlines())
        ignored = subprocess.run(['git', '-C', str(dest_mono), 'check-ignore', '.worktrees/child/probe'],
                                 check=True, capture_output=True)
        self.assertIn(b'.worktrees/child/probe', ignored.stdout)
        tracked = run_git_hardened(dest_mono, ['ls-files', '.git/info/exclude'], check=True)
        self.assertEqual(tracked.stdout, b'')
        self.assertFalse(proposal_mono.staging_dir.exists())

        repo_info = result_mono.repos[0]
        self.assertEqual(repo_info["path"], str(dest_mono))
        self.assertEqual(repo_info["hermes_project_id"], "p1")
        self.assertTrue(repo_info["commit"])

        # Verify git log shows 1 commit with message containing the template id
        log_proc = run_git_hardened(dest_mono, ["log", "--oneline"], check=True)
        log_lines = [ln for ln in log_proc.stdout.decode("utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(log_lines), 1)
        self.assertIn("fake-rust-game", log_lines[0])
        self.assertIn("chore: scaffold from template fake-rust-game", log_lines[0])

        # Verify register called once with (name, path)
        self.assertEqual(len(reg_calls), 1)
        self.assertEqual(reg_calls[0], ("My Game", str(dest_mono)))

        # Verify state DB has record_project row and save_answers row linked to project_path
        proj_row = get_project(dest_mono, db_path=self.db_path)
        self.assertIsNotNone(proj_row)
        assert proj_row is not None
        self.assertEqual(proj_row["name"], "My Game")
        self.assertEqual(proj_row["template_id"], "fake-rust-game")
        self.assertEqual(proj_row["hermes_project_id"], "p1")
        self.assertEqual(proj_row["slug"], "my-game")

        with closing(sqlite3.connect(str(self.db_path))) as conn:
            ans_row = conn.execute(
                "SELECT id, answers_json, project_path FROM answers WHERE id = ?",
                (result_mono.answers_id,),
            ).fetchone()
        self.assertIsNotNone(ans_row)
        self.assertEqual(json.loads(ans_row[1]), answers_mono)
        # The store keeps the resolved path (macOS temp folders sit behind the /var link).
        self.assertEqual(ans_row[2], str(dest_mono.resolve()))

        # 2. Poly repo accept
        spec_poly = load_template(TEMPLATES_FIXTURES / "fake-py-service")
        answers_poly = {"building": "service", "layout": "poly", "languages": ["python", "typescript"]}
        proposal_poly = propose(
            spec_poly,
            "My Svc",
            answers_poly,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        reg_calls.clear()
        result_poly = accept(
            proposal_poly,
            register=fake_register,
            db_path=self.db_path,
            timeout_s=60.0,
        )
        self.assertEqual(len(result_poly.repos), 2)
        self.assertEqual(
            reg_calls,
            [
                ("My Svc (api)", str(self.dest_root / "my-svc-api")),
                ("My Svc (web)", str(self.dest_root / "my-svc-web")),
            ],
        )
        expected_poly_names = {
            self.dest_root / "my-svc-api": "My Svc (api)",
            self.dest_root / "my-svc-web": "My Svc (web)",
        }
        for rplan in proposal_poly.repos:
            self.assertTrue(rplan.dest.is_dir())
            self.assertTrue((rplan.dest / ".git").is_dir())
            p_row = get_project(rplan.dest, db_path=self.db_path)
            self.assertIsNotNone(p_row)
            assert p_row is not None
            self.assertEqual(p_row["name"], expected_poly_names[rplan.dest])
        self.assertFalse(proposal_poly.staging_dir.exists())

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_when_register_returns_success_false_keeps_project(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        proposal = propose(
            spec,
            "Fail Reg",
            {"building": "game", "layout": "mono", "languages": ["rust"]},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        dest = self.dest_root / "fail-reg"

        def failing_register(name: str, path: str) -> str:
            return json.dumps({"success": False, "error": "duplicate project name"})

        result = accept(proposal, register=failing_register, db_path=self.db_path, timeout_s=60.0)
        self.assertEqual(result.repos[0]["registration_result"], {
            "registered": False, "reason": "duplicate project name",
        })
        # Folder must be kept and have git initialized!
        self.assertTrue(dest.is_dir())
        self.assertTrue((dest / ".git").is_dir())

    @mock.patch.object(scaffolder.toolchk, "probe", return_value=("1.0", "/fixture/tool"))
    def test_accept_poly_registration_error_completes_all_repos(self, _probe) -> None:
        spec_poly = load_template(TEMPLATES_FIXTURES / "fake-py-service")
        answers_poly = {"building": "service", "layout": "poly", "languages": ["python", "typescript"]}
        proposal_poly = propose(
            spec_poly,
            "Partial Svc",
            answers_poly,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        repo1_dest = proposal_poly.repos[0].dest
        repo2_dest = proposal_poly.repos[1].dest
        calls: List[Tuple[str, str]] = []

        def fail_on_second_register(name: str, path: str) -> str:
            calls.append((name, path))
            if len(calls) == 1:
                return json.dumps({"success": True, "id": "proj-api-1", "name": name, "path": path})
            return json.dumps({"success": False, "error": "web repo registration failed"})

        result = accept(proposal_poly, register=fail_on_second_register, db_path=self.db_path, timeout_s=60.0)
        self.assertEqual(len(result.repos), 2)
        self.assertEqual(result.repos[0]["hermes_project_id"], "proj-api-1")
        self.assertEqual(result.repos[1]["registration_result"], {
            "registered": False, "reason": "web repo registration failed",
        })
        for repo in result.repos:
            self.assertTrue(repo["commit"])
            self.assertIsNotNone(get_project(Path(repo["path"]), db_path=self.db_path))

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_deadline_checked_after_persistence_and_cleanup(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        # 1. Timeout right after record_project
        proposal1 = propose(
            spec,
            "Late Timeout One",
            {"building": "game"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        now_val = 0.0

        def clock1() -> float:
            return now_val

        orig_record = scaffolder.record_project

        def slow_record(*args: Any, **kwargs: Any) -> Any:
            nonlocal now_val
            res = orig_record(*args, **kwargs)
            now_val = 100.0
            return res

        with mock.patch.object(scaffolder, "record_project", side_effect=slow_record):
            with self.assertRaises(ScaffoldTimeout) as ctx1:
                accept(
                    proposal1,
                    register=lambda n, p: json.dumps({"success": True, "id": "p1"}),
                    db_path=self.db_path,
                    timeout_s=1.0,
                    clock=clock1,
                )
        dest1 = self.dest_root / "late-timeout-one"
        self.assertTrue(dest1.is_dir())
        self.assertIn("remain on disk", str(ctx1.exception))
        self.assertIn(str(dest1), str(ctx1.exception))
        discard(proposal1)

        # 2. Timeout right after save_answers (still raises before cleanup)
        proposal2 = propose(
            spec,
            "Late Timeout Two",
            {"building": "game"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        now_val2 = 0.0

        def clock2() -> float:
            return now_val2

        orig_save = scaffolder.save_answers

        def slow_save_answers(*args: Any, **kwargs: Any) -> int:
            nonlocal now_val2
            res = orig_save(*args, **kwargs)
            now_val2 = 100.0
            return res

        with mock.patch.object(scaffolder, "save_answers", side_effect=slow_save_answers):
            with self.assertRaises(ScaffoldTimeout) as ctx2:
                accept(
                    proposal2,
                    register=lambda n, p: json.dumps({"success": True, "id": "p2"}),
                    db_path=self.db_path,
                    timeout_s=1.0,
                    clock=clock2,
                )
        dest2 = self.dest_root / "late-timeout-two"
        self.assertTrue(dest2.is_dir())
        self.assertIn("remain on disk", str(ctx2.exception))
        self.assertIn(str(dest2), str(ctx2.exception))
        discard(proposal2)

        # 3. Clock advancing during discard/cleanup after full persistence does NOT raise timeout
        proposal3 = propose(
            spec,
            "Cleanup After Persistence",
            {"building": "game"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        now_val3 = 0.0

        def clock3() -> float:
            return now_val3

        orig_discard = scaffolder.discard

        def slow_discard(prop: Proposal) -> None:
            nonlocal now_val3
            orig_discard(prop)
            now_val3 = 100.0

        with mock.patch.object(scaffolder, "discard", side_effect=slow_discard):
            res3 = accept(
                proposal3,
                register=lambda n, p: json.dumps({"success": True, "id": "p3"}),
                db_path=self.db_path,
                timeout_s=1.0,
                clock=clock3,
            )
        dest3 = self.dest_root / "cleanup-after-persistence"
        self.assertEqual(len(res3.repos), 1)
        self.assertTrue(dest3.is_dir())
        self.assertFalse(proposal3.staging_dir.exists())

    def test_accept_deadline_raises_scaffold_timeout_before_moving(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")

        # 1. With timeout_s=0 after monkeypatching time.monotonic
        proposal1 = propose(
            spec,
            "Timed Out One",
            {"building": "game"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        with mock.patch.object(scaffolder.time, "monotonic", side_effect=[100.0, 100.1]):
            with self.assertRaises(ScaffoldTimeout):
                accept(
                    proposal1,
                    register=lambda n, p: json.dumps({"success": True, "id": "p1"}),
                    db_path=self.db_path,
                    timeout_s=0,
                )
        self.assertFalse((self.dest_root / "timed-out-one").exists())
        self.assertTrue(proposal1.repos[0].staged.is_dir())
        discard(proposal1)

        # 2. With injected clock advancing past deadline before move
        proposal2 = propose(
            spec,
            "Timed Out Two",
            {"building": "game"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        ticks = iter([50.0, 60.0])
        with self.assertRaises(ScaffoldTimeout):
            accept(
                proposal2,
                register=lambda n, p: json.dumps({"success": True, "id": "p1"}),
                db_path=self.db_path,
                timeout_s=5.0,
                clock=lambda: next(ticks),
            )
        self.assertFalse((self.dest_root / "timed-out-two").exists())
        self.assertTrue(proposal2.repos[0].staged.is_dir())
        discard(proposal2)

    def test_discard_removes_staging_idempotently(self) -> None:
        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        proposal = propose(
            spec,
            "Discard Me",
            {"building": "game"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        self.assertTrue(proposal.staging_dir.exists())
        discard(proposal)
        self.assertFalse(proposal.staging_dir.exists())
        # Calling discard a second time should not raise
        discard(proposal)

    def test_propose_rejects_unsafe_repo_name_and_creates_nothing(self) -> None:
        base_spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        for bad_name in ("../tmpl_prefix", "sub/tmpl_prefix", "sub\\tmpl_prefix", "..", ".", ""):
            spec = TemplateSpec(
                id=base_spec.id,
                name=base_spec.name,
                summary=base_spec.summary,
                kind=base_spec.kind,
                layout=base_spec.layout,
                languages=base_spec.languages,
                engine=base_spec.engine,
                tags=base_spec.tags,
                needs=base_spec.needs,
                placeholder=base_spec.placeholder,
                substitute_in=base_spec.substitute_in,
                repos=(RepoSpec(name=bad_name),),
                root=base_spec.root,
            )
            with self.assertRaises(ScaffoldError):
                propose(
                    spec,
                    "My Game",
                    {"building": "game"},
                    dest_root=self.dest_root,
                    staging_parent=self.staging_parent,
                )
        self.assertEqual(list(self.staging_parent.iterdir()), [])
        self.assertEqual(list(self.dest_root.iterdir()), [])

    @mock.patch.object(scaffolder.toolchk, "probe", return_value=("1.0", "/fixture/tool"))
    def test_accept_poly_register_runtime_error_completes_all_repos(self, _probe) -> None:
        spec_poly = load_template(TEMPLATES_FIXTURES / "fake-py-service")
        answers_poly = {"building": "service", "layout": "poly", "languages": ["python", "typescript"]}
        proposal_poly = propose(
            spec_poly,
            "Runtime Svc",
            answers_poly,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        repo1_dest = proposal_poly.repos[0].dest
        repo2_dest = proposal_poly.repos[1].dest
        calls: List[Tuple[str, str]] = []

        def raise_on_second_register(name: str, path: str) -> str:
            calls.append((name, path))
            if len(calls) == 1:
                return json.dumps({"success": True, "id": "proj-api-1", "name": name, "path": path})
            raise RuntimeError("boom in register")

        result = accept(proposal_poly, register=raise_on_second_register, db_path=self.db_path, timeout_s=60.0)
        self.assertEqual(len(result.repos), 2)
        self.assertEqual(result.repos[0]["hermes_project_id"], "proj-api-1")
        self.assertEqual(result.repos[1]["registration_result"], {
            "registered": False, "reason": "boom in register",
        })
        for repo in result.repos:
            self.assertTrue(repo["commit"])
            self.assertIsNotNone(get_project(Path(repo["path"]), db_path=self.db_path))

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_completes_when_public_project_tool_is_absent(self) -> None:
        from tools.registry import registry

        proposal = propose(
            load_template(TEMPLATES_FIXTURES / "fake-rust-game"),
            "Unregistered Game",
            {"building": "game", "layout": "mono", "languages": ["rust"]},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        with (
            mock.patch.object(registry, "get_entry", return_value=None),
            mock.patch.object(registry, "dispatch", return_value={"error": "Unknown tool: desktop_project"}) as dispatch,
        ):
            result = accept(proposal, db_path=self.db_path)
        dispatch.assert_not_called()
        repo = result.repos[0]
        self.assertEqual(repo["registration"], "skipped")
        self.assertIn("desktop_project unavailable", repo["registration_reason"])
        self.assertEqual(repo["registration_result"], {"registered": False, "reason": repo["registration_reason"]})
        self.assertEqual(repo["hermes_project_id"], "")
        self.assertTrue(repo["commit"])
        self.assertFalse(proposal.staging_dir.exists())
        stored = get_project(Path(repo["path"]), db_path=self.db_path)
        self.assertEqual(stored["hermes_project_id"], "")

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_present_project_tool_errors_are_nonfatal(self) -> None:
        from tools.registry import registry

        for index, response in enumerate((
            {"error": "permission denied"},
            {"error": "Unknown tool: desktop_project"},
            "not json",
            RuntimeError("dispatcher failed"),
        )):
            with self.subTest(response=response):
                proposal = propose(
                    load_template(TEMPLATES_FIXTURES / "fake-rust-game"),
                    f"Failed Registration {index}",
                    {"building": "game", "layout": "mono", "languages": ["rust"]},
                    dest_root=self.dest_root,
                    staging_parent=self.staging_parent,
                )
                with (
                    mock.patch.object(registry, "get_entry", return_value=object()),
                    mock.patch.object(
                        registry, "dispatch", return_value=response,
                        side_effect=response if isinstance(response, Exception) else None,
                    ),
                    mock.patch("sys.stderr", new_callable=__import__("io").StringIO) as stderr,
                ):
                    result = accept(proposal, db_path=self.db_path)
                repo = result.repos[0]
                self.assertFalse(repo["registration_result"]["registered"])
                self.assertTrue(repo["registration_result"]["reason"])
                if isinstance(response, dict):
                    self.assertEqual(repo["registration_result"]["reason"], response["error"])
                if isinstance(response, Exception):
                    self.assertEqual(repo["registration_result"]["reason"], str(response))
                self.assertTrue(repo["commit"])
                self.assertIsNotNone(get_project(proposal.repos[0].dest, db_path=self.db_path))
                self.assertFalse(proposal.staging_dir.exists())
                self.assertNotIn("Desktop registration failed:", stderr.getvalue())
                self.assertNotIn("Register manually", stderr.getvalue())

    def test_default_project_create_raises_scaffold_error_when_unimportable(self) -> None:
        with mock.patch.dict(sys.modules, {"tools": None, "tools.registry": None}):
            with self.assertRaises(ScaffoldError) as ctx:
                default_project_create("My Game", str(self.dest_root / "my-game"))
            self.assertIn("project_create unavailable", str(ctx.exception))

    def test_poly_dest_name_all_branches_and_validation(self) -> None:
        placeholder_forms = forms_from_placeholder("tmpl_prefix")

        # 1. Exact match with placeholder snake -> folder = slug
        self.assertEqual(
            poly_dest_name("shop-api", "tmpl_prefix", placeholder_forms),
            "shop-api",
        )

        # 2. Starts with placeholder snake + '_' -> folder = slug + '-' + remainder with '_' -> '-'
        self.assertEqual(
            poly_dest_name("shop-api", "tmpl_prefix_api", placeholder_forms),
            "shop-api-api",
        )
        self.assertEqual(
            poly_dest_name("shop-api", "tmpl_prefix_web", placeholder_forms),
            "shop-api-web",
        )
        self.assertEqual(
            poly_dest_name("shop-api", "tmpl_prefix_admin_worker", placeholder_forms),
            "shop-api-admin-worker",
        )

        # 3. Otherwise -> slug + '-' + kebab(repo_name)
        self.assertEqual(
            poly_dest_name("shop-api", "billing_service", placeholder_forms),
            "shop-api-billing-service",
        )
        self.assertEqual(
            poly_dest_name("shop-api", "frontend", placeholder_forms),
            "shop-api-frontend",
        )

        # Validation of unsafe components
        for bad_repo in ("../api", "sub/api", "sub\\api", "..", ".", "", "tmpl_prefix_"):
            with self.assertRaises(ScaffoldError):
                poly_dest_name("shop-api", bad_repo, placeholder_forms)

    def test_propose_poly_detects_dest_collision_between_repos(self) -> None:
        base_spec = load_template(TEMPLATES_FIXTURES / "fake-py-service")
        # Both 'tmpl_prefix_api_v1' and 'api-v1' map to 'shop-api-api-v1' under poly_dest_name
        spec = TemplateSpec(
            id=base_spec.id,
            name=base_spec.name,
            summary=base_spec.summary,
            kind=base_spec.kind,
            layout="poly",
            languages=base_spec.languages,
            engine=base_spec.engine,
            tags=base_spec.tags,
            needs=base_spec.needs,
            placeholder="tmpl_prefix",
            substitute_in=base_spec.substitute_in,
            repos=(RepoSpec(name="tmpl_prefix_api"), RepoSpec(name="api")),
            root=base_spec.root,
        )
        with self.assertRaises(ScaffoldError) as ctx:
            propose(
                spec,
                "Shop Api",
                {"building": "service", "layout": "poly"},
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )
        self.assertIn("shop-api-api", str(ctx.exception))

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_accept_records_provenance_and_locked_hashes_after_substitution(self) -> None:
        rust_spec = load_template(templates_root() / "rust-golden")
        answers = {"building": "app", "layout": "mono", "languages": ["rust"]}

        proposal = propose(
            rust_spec,
            "My Probe App",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        res = accept(
            proposal,
            register=lambda name, path: json.dumps({"success": True, "id": "p-rust-1", "name": name, "path": path}),
            db_path=self.db_path,
            timeout_s=60.0,
        )

        dest = self.dest_root / "my-probe-app"
        self.assertTrue(dest.is_dir())
        proj = get_project(dest, db_path=self.db_path)
        self.assertIsNotNone(proj)
        assert proj is not None

        self.assertEqual(proj["template_id"], "rust-golden")
        self.assertEqual(proj["prefix"], "my_probe_app")
        # A git checkout records its HEAD; a download without .git records exactly "unknown".
        self.assertEqual(proj["plugin_commit"], resolve_plugin_commit())
        if (Path(scaffolder.__file__).resolve().parent / ".git").exists():
            self.assertRegex(proj["plugin_commit"], r"^[0-9a-f]{40,64}$")
        else:
            self.assertEqual(proj["plugin_commit"], "unknown")

        locked_hashes = proj["locked_hashes"]
        self.assertIsInstance(locked_hashes, dict)
        assert isinstance(locked_hashes, dict)

        expected_locked_files = {
            "Cargo.toml",
            "clippy.toml",
            "rustfmt.toml",
            "rust-toolchain.toml",
            ".github/workflows/ci.yml",
            "xtask/Cargo.toml",
            "xtask/src/main.rs",
        }
        self.assertEqual(set(locked_hashes.keys()), expected_locked_files)

        # Every recorded hash must match the SHA-256 of the file AS WRITTEN after substitution
        for rel_path in expected_locked_files:
            written_bytes = (dest / rel_path).read_bytes()
            self.assertEqual(
                locked_hashes[rel_path],
                hashlib.sha256(written_bytes).hexdigest(),
                f"locked hash mismatch for {rel_path}",
            )

        # Verify that substituted files have a different hash than the raw template before substitution
        raw_cargo_toml = (rust_spec.root / "tmpl_prefix" / "Cargo.toml").read_bytes()
        raw_xtask_main = (rust_spec.root / "tmpl_prefix" / "xtask" / "src" / "main.rs").read_bytes()
        self.assertNotEqual(
            locked_hashes["Cargo.toml"],
            hashlib.sha256(raw_cargo_toml).hexdigest(),
        )
        self.assertNotEqual(
            locked_hashes["xtask/src/main.rs"],
            hashlib.sha256(raw_xtask_main).hexdigest(),
        )

        # AcceptResult repo dict also exposes provenance
        self.assertEqual(res.repos[0]["template_id"], "rust-golden")
        self.assertEqual(res.repos[0]["prefix"], "my_probe_app")
        self.assertEqual(res.repos[0]["plugin_commit"], proj["plugin_commit"])
        self.assertEqual(res.repos[0]["locked_hashes"], locked_hashes)

    @pytest.mark.usefixtures("fake_rust_toolchain")
    def test_resolve_plugin_commit_returns_unknown_when_not_a_checkout(self) -> None:
        non_git_dir = self.tmp_root / "not_a_git_checkout"
        non_git_dir.mkdir(parents=True)
        self.assertEqual(resolve_plugin_commit(non_git_dir), "unknown")

        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        proposal = propose(
            spec,
            "No Git Plugin Test",
            {"building": "game", "layout": "mono", "languages": ["rust"]},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        accept(
            proposal,
            register=lambda name, path: json.dumps({"success": True, "id": "p-unk", "name": name, "path": path}),
            db_path=self.db_path,
            plugin_root=non_git_dir,
        )
        proj = get_project(self.dest_root / "no-git-plugin-test", db_path=self.db_path)
        assert proj is not None
        self.assertEqual(proj["plugin_commit"], "unknown")
        self.assertEqual(proj["prefix"], "no_git_plugin_test")
        self.assertEqual(proj["locked_hashes"], {})

    def test_accept_preflight_failure_blocks_accept_and_preserves_staging(self) -> None:
        from hermes_plugins.defuzz import toolchk

        spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        proposal = propose(
            spec,
            "Preflight Skip Game",
            {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        with mock.patch.object(
            toolchk,
            "probe",
            side_effect=FileNotFoundError("cargo not found"),
        ), self.assertRaises(ScaffoldError) as caught:
            accept(
                proposal,
                register=lambda *_: self.fail("must not register"),
                db_path=self.db_path,
                timeout_s=60.0,
            )

        dest = self.dest_root / "preflight-skip-game"
        self.assertFalse(dest.exists())
        self.assertTrue(caught.exception.keep_staging)
        staged = proposal.repos[0].staged
        loaded_lock = toolchk.load_lock(staged / "TOOLS.lock")
        self.assertEqual(loaded_lock["tools"]["cargo"]["version"], "unknown")
        self.assertIn("Probe failed at seeding:", loaded_lock["tools"]["cargo"]["reason"])

        self.assertEqual(caught.exception.reason, "preflight-failed")
        self.assertTrue((staged / ".adopt" / "preflight.json").is_file())

    def test_accept_check_cmd_uses_remaining_deadline_instead_of_hardcoded_600(self) -> None:
        from hermes_plugins.defuzz import toolchk

        base_spec = load_template(TEMPLATES_FIXTURES / "fake-rust-game")
        spec_with_check = TemplateSpec(
            id=base_spec.id,
            name=base_spec.name,
            summary=base_spec.summary,
            kind=base_spec.kind,
            layout=base_spec.layout,
            languages=base_spec.languages,
            engine=base_spec.engine,
            tags=base_spec.tags,
            needs=base_spec.needs,
            placeholder=base_spec.placeholder,
            substitute_in=base_spec.substitute_in,
            repos=(
                RepoSpec(
                    name=base_spec.repos[0].name,
                    check=CheckSpec(cmd=("echo", "ok"), cwd="."),
                ),
            ),
            root=base_spec.root,
        )
        proposal = propose(
            spec_with_check,
            "Bounded Check Game",
            {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        observed_timeouts: List[Any] = []
        # The check is started by scaffolder._run_check_command (a cancellable subprocess.run).
        orig_run_check = scaffolder._run_check_command

        def spy_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
            if list(cmd) == ["echo", "ok"]:
                observed_timeouts.append(kwargs.get("timeout"))
            return orig_run_check(cmd, *args, **kwargs)

        now_val = 100.0

        def fake_clock() -> float:
            nonlocal now_val
            now_val += 0.5
            return now_val

        with (
            mock.patch.object(toolchk, "probe", return_value=("1.82.0", "/usr/bin/cargo")),
            mock.patch.object(scaffolder, "_run_check_command", side_effect=spy_run),
        ):
            res = accept(
                proposal,
                register=lambda name, path: json.dumps({"success": True, "id": "p-chk", "name": name, "path": path}),
                db_path=self.db_path,
                timeout_s=15.0,
                clock=fake_clock,
            )

        self.assertEqual(res.repos[0]["check"], "ok")
        self.assertEqual(len(observed_timeouts), 1)
        self.assertLess(observed_timeouts[0], 15.0)
        self.assertGreater(observed_timeouts[0], 0.0)
        self.assertNotEqual(observed_timeouts[0], 600)

        # Also verify that if deadline has expired right before check, ScaffoldTimeout is raised
        proposal2 = propose(
            spec_with_check,
            "Expired Check Game",
            {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        clock_expired = 100.0

        def expire_during_require(*args: Any, **kwargs: Any) -> dict[str, Any]:
            nonlocal clock_expired
            clock_expired = 200.0
            return {"ok": True}

        with (
            mock.patch.object(toolchk, "probe", return_value=("1.82.0", "/usr/bin/cargo")),
            mock.patch.object(toolchk, "require", side_effect=expire_during_require),
        ):
            with self.assertRaises(ScaffoldTimeout):
                accept(
                    proposal2,
                    register=lambda name, path: json.dumps({"success": True, "id": "p-chk2", "name": name, "path": path}),
                    db_path=self.db_path,
                    timeout_s=10.0,
                    clock=lambda: clock_expired,
                )
        discard(proposal2)

    def test_options_rewrite_env_example_only_and_record_in_template_options(self) -> None:
        # Build a synthetic template with options (both single and double underscore env_key)
        tmpl_dir = self.tmp_root / "opt-service-tmpl"
        repo_dir = tmpl_dir / "tmpl_prefix"
        repo_dir.mkdir(parents=True)
        (tmpl_dir / "template.yaml").write_text(
            "id: opt-service-tmpl\n"
            "name: Option Service Template\n"
            "summary: Service template with http_adapter option\n"
            "kind: service\n"
            "layout: mono\n"
            "languages: [typescript]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in:\n"
            "  - \".env.example\"\n"
            "  - \"**/*.ts\"\n"
            "options:\n"
            "  http_adapter:\n"
            "    label: \"HTTP adapter\"\n"
            "    choices: [hono, node_http]\n"
            "    default: hono\n"
            "    env_key: TMPL_PREFIX_HTTP_ADAPTER\n"
            "    description: \"Both adapters ship; this picks the default wired in config.\"\n"
            "repos:\n"
            "  - name: tmpl_prefix\n"
            "    check:\n"
            f"      cmd: [{json.dumps(sys.executable)}, \"-c\", \"print('check ok')\"]\n"
            "      cwd: \".\"\n",
            encoding="utf-8",
        )
        (repo_dir / ".env.example").write_text(
            "# Service config\n"
            "TMPL_PREFIX_PORT=3000\n"
            "TMPL_PREFIX_HTTP_ADAPTER=hono\n",
            encoding="utf-8",
        )
        (repo_dir / "main.ts").write_text(
            "export const APP = 'tmpl_prefix';\n"
            "export const DEFAULT_ADAPTER = 'hono';\n",
            encoding="utf-8",
        )

        spec = load_template(tmpl_dir)
        answers = {"building": "service", "layout": "mono", "languages": ["typescript"]}

        # 1. Propose + accept with non-default choice 'node_http'
        prop_node = propose(
            spec,
            "Invoice Tracker",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
            options={"http_adapter": "node_http"},
        )
        env_staged = (prop_node.repos[0].staged / ".env.example").read_text(encoding="utf-8")
        self.assertIn("INVOICE_TRACKER_HTTP_ADAPTER=node_http", env_staged)
        self.assertIn("INVOICE_TRACKER_PORT=3000", env_staged)
        # No other file is rewritten for options
        main_staged = (prop_node.repos[0].staged / "main.ts").read_text(encoding="utf-8")
        self.assertIn("export const DEFAULT_ADAPTER = 'hono';", main_staged)

        res = accept(
            prop_node,
            register=lambda n, p: json.dumps({"success": True, "id": "p-opt-1", "name": n, "path": p}),
            db_path=self.db_path,
        )
        self.assertEqual(res.options, {"http_adapter": "node_http"})
        dest = self.dest_root / "invoice-tracker"
        self.assertIn(
            "INVOICE_TRACKER_HTTP_ADAPTER=node_http",
            (dest / ".env.example").read_text(encoding="utf-8"),
        )
        opt_row = get_template_option("opt-service-tmpl", "http_adapter", db_path=self.db_path)
        self.assertIsNotNone(opt_row)
        assert opt_row is not None
        self.assertEqual(opt_row["choice"], "node_http")
        self.assertIsInstance(opt_row["chosen_at"], int)

        # 2. Missing env_key line in .env.example raises ScaffoldError
        (repo_dir / ".env.example").write_text("TMPL_PREFIX_PORT=3000\n", encoding="utf-8")
        spec_missing_key = load_template(tmpl_dir)
        with self.assertRaises(ScaffoldError) as err_ctx:
            propose(
                spec_missing_key,
                "Another Tracker",
                answers,
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )
        self.assertIn("ANOTHER_TRACKER_HTTP_ADAPTER", str(err_ctx.exception))

        # 3. Unknown option or invalid choice raises ScaffoldError
        with self.assertRaises(ScaffoldError):
            propose(
                spec,
                "Bad Choice Tracker",
                answers,
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
                options={"http_adapter": "express"},
            )
        with self.assertRaises(ScaffoldError):
            propose(
                spec,
                "Unknown Opt Tracker",
                answers,
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
                options={"db_driver": "postgres"},
            )
        # 4. Double-underscore env_key (TMPL_PREFIX_HTTP__ADAPTER, choices fastapi | stdlib_http per OPTIONS.md)
        py_tmpl_dir = self.tmp_root / "opt-py-tmpl"
        py_repo_dir = py_tmpl_dir / "tmpl_prefix"
        py_repo_dir.mkdir(parents=True)
        (py_tmpl_dir / "template.yaml").write_text(
            "id: opt-py-tmpl\n"
            "name: Option Python Template\n"
            "summary: Python service template with double-underscore env_key\n"
            "kind: service\n"
            "layout: mono\n"
            "languages: [python]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in:\n"
            "  - \".env.example\"\n"
            "  - \"**/*.py\"\n"
            "options:\n"
            "  http_adapter:\n"
            "    label: \"HTTP adapter\"\n"
            "    choices: [fastapi, stdlib_http]\n"
            "    default: fastapi\n"
            "    env_key: TMPL_PREFIX_HTTP__ADAPTER\n"
            "repos:\n"
            "  - name: tmpl_prefix\n"
            "    check:\n"
            f"      cmd: [{json.dumps(sys.executable)}, \"-c\", \"print('py check ok')\"]\n"
            "      cwd: \".\"\n",
            encoding="utf-8",
        )
        (py_repo_dir / ".env.example").write_text(
            "TMPL_PREFIX_HTTP__ADAPTER=fastapi\n",
            encoding="utf-8",
        )
        (py_repo_dir / "main.py").write_text("APP = 'tmpl_prefix'\n", encoding="utf-8")

        py_spec = load_template(py_tmpl_dir)
        py_prop = propose(
            py_spec,
            "Ledger Service",
            {"building": "service", "layout": "mono", "languages": ["python"]},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
            options={"http_adapter": "stdlib_http"},
        )
        self.assertIn(
            "LEDGER_SERVICE_HTTP__ADAPTER=stdlib_http",
            (py_prop.repos[0].staged / ".env.example").read_text(encoding="utf-8"),
        )
        accept(
            py_prop,
            register=lambda n, p: json.dumps({"success": True, "id": "p-py-opt", "name": n, "path": p}),
            db_path=self.db_path,
        )
        py_opt_row = get_template_option("opt-py-tmpl", "http_adapter", db_path=self.db_path)
        self.assertIsNotNone(py_opt_row)
        assert py_opt_row is not None
        self.assertEqual(py_opt_row["choice"], "stdlib_http")

    def test_accept_runs_check_in_staging_before_move_and_strips_build_caches(self) -> None:
        tmpl_dir = self.tmp_root / "check-order-tmpl"
        repo_dir = tmpl_dir / "tmpl_prefix"
        repo_dir.mkdir(parents=True)
        # Check command verifies dest does NOT exist yet, verifies cwd is inside staging,
        # and creates target/, node_modules/, dist/, __pycache__/, and tsconfig.tsbuildinfo
        check_script = (
            "import os, pathlib, sys; "
            "cwd = pathlib.Path.cwd(); "
            "dest = pathlib.Path(sys.argv[1]); "
            "assert not dest.exists(), f'dest already existed during check: {dest}'; "
            "(cwd / 'target' / 'debug').mkdir(parents=True, exist_ok=True); "
            "(cwd / 'target' / 'debug' / 'app.bin').write_bytes(b'bin'); "
            "(cwd / 'node_modules' / 'pkg').mkdir(parents=True, exist_ok=True); "
            "(cwd / 'node_modules' / 'pkg' / 'index.js').write_text('module.exports = 1;'); "
            "(cwd / 'dist').mkdir(parents=True, exist_ok=True); "
            "(cwd / 'dist' / 'bundle.js').write_text('console.log(1);'); "
            "(cwd / '__pycache__').mkdir(parents=True, exist_ok=True); "
            "(cwd / '__pycache__' / 'mod.cpython-312.pyc').write_bytes(b'0'); "
            "(cwd / 'tsconfig.tsbuildinfo').write_text('{}'); "
            "print('staging check passed cleanly')"
        )
        expected_dest = self.dest_root / "clean-cache-app"
        (tmpl_dir / "template.yaml").write_text(
            "id: check-order-tmpl\n"
            "name: Check Order Template\n"
            "summary: Verifies check runs in staging before move and strips caches\n"
            "kind: app\n"
            "layout: single\n"
            "languages: [python]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in: [\"**/*.py\"]\n"
            "repos:\n"
            "  - name: tmpl_prefix\n"
            "    check:\n"
            f"      cmd: [{json.dumps(sys.executable)}, \"-c\", {json.dumps(check_script)}, {json.dumps(str(expected_dest))}]\n"
            "      cwd: \".\"\n",
            encoding="utf-8",
        )
        # Deliberately omit .gitignore so only scaffolder cache stripping can keep caches out of git
        (repo_dir / "app.py").write_text("APP_NAME = 'tmpl_prefix'\n", encoding="utf-8")

        spec = load_template(tmpl_dir)
        proposal = propose(
            spec,
            "Clean Cache App",
            {"building": "app", "layout": "single", "languages": ["python"]},
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )

        res = accept(
            proposal,
            register=lambda n, p: json.dumps({"success": True, "id": "p-clean", "name": n, "path": p}),
            db_path=self.db_path,
        )
        self.assertEqual(res.repos[0]["check"], "ok")
        self.assertIn("staging check passed cleanly", res.repos[0]["check_output"])
        self.assertTrue(expected_dest.is_dir())

        # Verify first commit has app.py and TOOLS.lock, and ZERO build cache files
        ls_proc = run_git_hardened(expected_dest, ["ls-files"], check=True)
        tracked = set(ls_proc.stdout.decode("utf-8").splitlines())
        self.assertIn("app.py", tracked)
        self.assertIn("TOOLS.lock", tracked)
        for tracked_file in tracked:
            self.assertFalse(tracked_file.startswith("target/"), f"Cache leaked: {tracked_file}")
            self.assertFalse(tracked_file.startswith("node_modules/"), f"Cache leaked: {tracked_file}")
            self.assertFalse(tracked_file.startswith("dist/"), f"Cache leaked: {tracked_file}")
            self.assertFalse(tracked_file.startswith("__pycache__/"), f"Cache leaked: {tracked_file}")
            self.assertNotEqual(tracked_file, "tsconfig.tsbuildinfo")

    def test_accept_check_failure_timeout_cancel_and_cwd_containment_keep_staging_and_touch_nothing(self) -> None:
        tmpl_dir = self.tmp_root / "fail-check-tmpl"
        repo_dir = tmpl_dir / "tmpl_prefix"
        repo_dir.mkdir(parents=True)
        (repo_dir / ".env.example").write_text("TMPL_PREFIX_HTTP_ADAPTER=hono\n", encoding="utf-8")
        (repo_dir / "app.py").write_text("APP_NAME = 'tmpl_prefix'\n", encoding="utf-8")
        (tmpl_dir / "template.yaml").write_text(
            "id: fail-check-tmpl\n"
            "name: Fail Check Template\n"
            "summary: Template for testing check failure, timeout, cancel, and cwd containment\n"
            "kind: service\n"
            "layout: mono\n"
            "languages: [python]\n"
            "placeholder: tmpl_prefix\n"
            "substitute_in: [\".env.example\", \"**/*.py\"]\n"
            "options:\n"
            "  http_adapter:\n"
            "    label: \"HTTP adapter\"\n"
            "    choices: [hono, node_http]\n"
            "    default: hono\n"
            "    env_key: TMPL_PREFIX_HTTP_ADAPTER\n"
            "repos:\n"
            "  - name: tmpl_prefix\n"
            "    check:\n"
            f"      cmd: [{json.dumps(sys.executable)}, \"-c\", \"import sys; sys.stdout.write('lint err line 1\\\\n'); sys.stderr.write('typecheck failed\\\\n'); sys.exit(2)\"]\n"
            "      cwd: \".\"\n",
            encoding="utf-8",
        )
        spec = load_template(tmpl_dir)
        answers = {"building": "service", "layout": "mono", "languages": ["python"]}
        reg_calls: List[Tuple[str, str]] = []

        def spy_register(name: str, path: str) -> str:
            reg_calls.append((name, path))
            return json.dumps({"success": True, "id": "p-never"})

        # 1. Non-zero check exit code -> raises ScaffoldError with output, keeps staging, nothing in dest_root or state.db
        prop_fail = propose(
            spec,
            "Fail Svc",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
            options={"http_adapter": "node_http"},
        )
        with self.assertRaises(ScaffoldError) as fail_ctx:
            accept(prop_fail, register=spy_register, db_path=self.db_path)

        self.assertIn("lint err line 1", fail_ctx.exception.output)
        self.assertIn("typecheck failed", fail_ctx.exception.output)
        self.assertIn("lint err line 1", str(fail_ctx.exception))
        self.assertEqual(fail_ctx.exception.returncode, 2)
        self.assertTrue(fail_ctx.exception.keep_staging)
        self.assertTrue(prop_fail.staging_dir.is_dir())
        self.assertTrue(prop_fail.repos[0].staged.is_dir())
        self.assertEqual(list(self.dest_root.iterdir()), [])
        self.assertEqual(reg_calls, [])
        self.assertFalse(self.db_path.exists())
        discard(prop_fail)

        # 2. Subprocess timeout during check -> raises ScaffoldTimeout with partial output, keeps staging, nothing in dest_root or state.db
        slow_cmd = (
            sys.executable,
            "-c",
            "import sys, time; sys.stdout.write('starting slow ci...\\n'); sys.stdout.flush(); time.sleep(5)",
        )
        spec_slow = TemplateSpec(
            id=spec.id,
            name=spec.name,
            summary=spec.summary,
            kind=spec.kind,
            layout=spec.layout,
            languages=spec.languages,
            engine=spec.engine,
            tags=spec.tags,
            needs=spec.needs,
            placeholder=spec.placeholder,
            substitute_in=spec.substitute_in,
            repos=(RepoSpec(name="tmpl_prefix", check=CheckSpec(cmd=slow_cmd, cwd=".")),),
            root=spec.root,
            options=spec.options,
        )
        prop_timeout = propose(
            spec_slow,
            "Timeout Svc",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        with self.assertRaises(ScaffoldTimeout) as to_ctx:
            accept(
                prop_timeout,
                register=spy_register,
                db_path=self.db_path,
                timeout_s=0.15,
            )
        self.assertIn("starting slow ci...", to_ctx.exception.output)
        self.assertTrue(to_ctx.exception.keep_staging)
        self.assertTrue(prop_timeout.staging_dir.is_dir())
        self.assertEqual(list(self.dest_root.iterdir()), [])
        self.assertEqual(reg_calls, [])
        self.assertFalse(self.db_path.exists())
        discard(prop_timeout)

        # 3. Cancellation via cancel event -> raises ScaffoldError(cancelled=True), keeps staging, nothing in dest_root or state.db
        import threading

        cancel_ev = threading.Event()
        cancel_ev.set()
        prop_cancel = propose(
            spec,
            "Cancel Svc",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        with self.assertRaises(ScaffoldError) as cancel_ctx:
            accept(
                prop_cancel,
                register=spy_register,
                db_path=self.db_path,
                cancel=cancel_ev,
            )
        self.assertTrue(cancel_ctx.exception.cancelled)
        self.assertTrue(cancel_ctx.exception.keep_staging)
        self.assertTrue(prop_cancel.staging_dir.is_dir())
        self.assertEqual(list(self.dest_root.iterdir()), [])
        self.assertEqual(reg_calls, [])
        self.assertFalse(self.db_path.exists())
        discard(prop_cancel)

        # 4. CWD containment: escaping relative cwd ('../outside') or symlink cwd inside staging is refused before execution
        for bad_cwd in ("..", "../outside", "/tmp"):
            prop_cwd = propose(
                spec,
                "Bad Cwd Svc",
                answers,
                dest_root=self.dest_root,
                staging_parent=self.staging_parent,
            )
            prop_cwd.repos[0].check = CheckSpec(cmd=(sys.executable, "-c", "print('ran')"), cwd=bad_cwd)
            with self.assertRaises(ScaffoldError) as cwd_ctx:
                accept(prop_cwd, register=spy_register, db_path=self.db_path)
            self.assertTrue(cwd_ctx.exception.keep_staging)
            self.assertTrue(prop_cwd.staging_dir.is_dir())
            self.assertEqual(list(self.dest_root.iterdir()), [])
            self.assertEqual(reg_calls, [])
            self.assertFalse(self.db_path.exists())
            discard(prop_cwd)

        # Symlink directory inside staged repo targeting outside dir is also refused by cwd containment
        outside_dir = self.tmp_root / "outside_cwd_target"
        outside_dir.mkdir(parents=True, exist_ok=True)
        prop_sym_cwd = propose(
            spec,
            "Sym Cwd Svc",
            answers,
            dest_root=self.dest_root,
            staging_parent=self.staging_parent,
        )
        os.symlink(str(outside_dir), str(prop_sym_cwd.repos[0].staged / "escaped_sub"))
        prop_sym_cwd.repos[0].check = CheckSpec(
            cmd=(sys.executable, "-c", "print('ran')"),
            cwd="escaped_sub",
        )
        with self.assertRaises(ScaffoldError) as sym_ctx:
            accept(prop_sym_cwd, register=spy_register, db_path=self.db_path)
        self.assertTrue(sym_ctx.exception.keep_staging)
        self.assertTrue(prop_sym_cwd.staging_dir.is_dir())
        self.assertEqual(list(self.dest_root.iterdir()), [])
        self.assertFalse(self.db_path.exists())
        discard(prop_sym_cwd)



if __name__ == "__main__":
    unittest.main()
