"""Unit tests for templates.py (strict template.yaml schema loader and fixtures)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.templates import (  # noqa: E402
    CheckSpec,
    OptionSpec,
    RepoSpec,
    TemplateError,
    TemplateSpec,
    load_template,
    load_templates,
    load_templates_lenient,
    options_as_json,
    templates_root,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEMPLATES_FIXTURES = FIXTURES_DIR / "templates"
BAD_TEMPLATES_FIXTURES = FIXTURES_DIR / "bad_templates"


class TestTemplates(unittest.TestCase):
    def test_load_fake_rust_game_fixture(self) -> None:
        tmpl_dir = TEMPLATES_FIXTURES / "fake-rust-game"
        spec = load_template(tmpl_dir)
        self.assertIsInstance(spec, TemplateSpec)
        self.assertEqual(spec.id, "fake-rust-game")
        self.assertTrue(spec.name)
        self.assertTrue(spec.summary)
        self.assertEqual(spec.kind, "game")
        self.assertEqual(spec.layout, "mono")
        self.assertEqual(spec.languages, ("rust",))
        self.assertEqual(spec.engine, "bevy")
        self.assertEqual(spec.tags, ("game", "ecs"))
        self.assertEqual(spec.needs, ("cargo",))
        self.assertEqual(spec.placeholder, "tmpl_prefix")
        self.assertEqual(spec.substitute_in, ("**/*.rs", "**/*.toml", "**/*.md"))
        self.assertEqual(spec.locked, ())
        self.assertEqual(dict(spec.approved_deps), {})
        self.assertEqual(spec.options, {})
        self.assertEqual(spec.options_as_json(), [])
        self.assertEqual(options_as_json(spec), [])
        self.assertEqual(spec.root, tmpl_dir.resolve())
        self.assertEqual(
            spec.repos,
            (
                RepoSpec(
                    name="tmpl_prefix",
                    check=CheckSpec(cmd=("cargo", "check"), cwd="."),
                ),
            ),
        )
        # Verify fixture files exist and binary asset has NUL byte
        repo_root = tmpl_dir / "tmpl_prefix"
        self.assertTrue((repo_root / "Cargo.toml").is_file())
        self.assertTrue((repo_root / "src" / "main.rs").is_file())
        self.assertTrue((repo_root / "README.md").is_file())
        self.assertTrue((repo_root / "tmpl_prefix_core" / "lib.rs").is_file())
        self.assertTrue((repo_root / ".gitignore").is_file())
        self.assertTrue((repo_root / "AGENTS.md").is_file())
        logo_bytes = (repo_root / "assets" / "logo.png").read_bytes()
        self.assertIn(b"\x00", logo_bytes)

    def test_load_fake_py_service_fixture(self) -> None:
        tmpl_dir = TEMPLATES_FIXTURES / "fake-py-service"
        spec = load_template(tmpl_dir)
        self.assertEqual(spec.id, "fake-py-service")
        self.assertEqual(spec.kind, "service")
        self.assertEqual(spec.layout, "poly")
        self.assertEqual(spec.languages, ("python", "typescript"))
        self.assertIsNone(spec.engine)
        self.assertEqual(spec.tags, ("api",))
        self.assertEqual(spec.needs, ("python", "node"))
        self.assertEqual(spec.placeholder, "tmpl_prefix")
        self.assertEqual(spec.substitute_in, ("**/*.py", "**/*.md", "**/*.json"))
        self.assertEqual(
            spec.repos,
            (
                RepoSpec(name="tmpl_prefix_api", check=None),
                RepoSpec(
                    name="tmpl_prefix_web",
                    check=CheckSpec(cmd=("node", "--version"), cwd="."),
                ),
            ),
        )
        self.assertTrue((tmpl_dir / "tmpl_prefix_api" / "tmpl_prefix" / "__init__.py").is_file())
        self.assertTrue((tmpl_dir / "tmpl_prefix_api" / "README.md").is_file())
        self.assertTrue((tmpl_dir / "tmpl_prefix_web" / "package.json").is_file())

    def test_load_templates_sorts_by_id_and_skips_folders_without_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(TEMPLATES_FIXTURES / "fake-rust-game", root / "fake-rust-game")
            shutil.copytree(TEMPLATES_FIXTURES / "fake-py-service", root / "fake-py-service")
            # Folder without template.yaml and loose file must be skipped
            (root / "notes-folder").mkdir()
            (root / "notes-folder" / "README.md").write_text("not a template\n", encoding="utf-8")
            (root / "README.md").write_text("root readme\n", encoding="utf-8")

            specs = load_templates(root)
            self.assertEqual([s.id for s in specs], ["fake-py-service", "fake-rust-game"])

    def test_missing_root_returns_empty_and_templates_root_points_to_repo_templates(self) -> None:
        missing = FIXTURES_DIR / "does-not-exist-at-all"
        self.assertEqual(load_templates(missing), [])
        self.assertEqual(load_templates_lenient(missing), ([], []))
        self.assertEqual(
            templates_root(),
            Path(__file__).resolve().parent.parent / "templates",
        )

    def test_every_bad_template_fixture_raises_with_folder_and_key(self) -> None:
        expected_keys = {
            "missing-required": "summary",
            "unknown-key": "extra_field",
            "id-mismatch": "id",
            "poly-one-repo": "repos",
            "repo-folder-missing": "repos",
            "bad-placeholder": "placeholder",
            "bad-languages-type": "languages",
        }
        discovered = sorted(p.name for p in BAD_TEMPLATES_FIXTURES.iterdir() if p.is_dir())
        self.assertEqual(discovered, sorted(expected_keys.keys()))

        for case_name, expected_key in expected_keys.items():
            case_dir = BAD_TEMPLATES_FIXTURES / case_name
            with self.subTest(case=case_name):
                with self.assertRaises(TemplateError) as ctx:
                    load_template(case_dir)
                msg = str(ctx.exception)
                self.assertIn(case_name, msg)
                self.assertIn(expected_key, msg)

        # Strict load_templates on bad_templates root also raises TemplateError
        with self.assertRaises(TemplateError):
            load_templates(BAD_TEMPLATES_FIXTURES)

    def test_load_templates_lenient_returns_valid_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(TEMPLATES_FIXTURES / "fake-rust-game", root / "fake-rust-game")
            shutil.copytree(TEMPLATES_FIXTURES / "fake-py-service", root / "fake-py-service")
            shutil.copytree(BAD_TEMPLATES_FIXTURES / "unknown-key", root / "unknown-key")
            shutil.copytree(BAD_TEMPLATES_FIXTURES / "missing-required", root / "missing-required")
            (root / "empty-dir").mkdir()

            valid, errors = load_templates_lenient(root)
            self.assertEqual([s.id for s in valid], ["fake-py-service", "fake-rust-game"])
            self.assertEqual(len(errors), 2)
            joined = "\n".join(errors)
            self.assertIn("unknown-key", joined)
            self.assertIn("extra_field", joined)
            self.assertIn("missing-required", joined)
            self.assertIn("summary", joined)

    def test_non_mapping_top_level_and_invalid_yaml_raise_template_error(self) -> None:
        for idx, content in enumerate(["- just\n- a\n- list\n", '"just a string"\n', "null\n", "id: [unclosed\n"]):
            with tempfile.TemporaryDirectory() as tmp:
                case_dir = Path(tmp) / f"bad-yaml-{idx}"
                case_dir.mkdir()
                (case_dir / "template.yaml").write_text(content, encoding="utf-8")
                with self.assertRaises(TemplateError) as ctx:
                    load_template(case_dir)
                self.assertIn(f"bad-yaml-{idx}", str(ctx.exception))

    def test_nested_and_value_constraints(self) -> None:
        def render_yaml(folder_name: str, **overrides: str) -> str:
            fields = {
                "id": f'"{folder_name}"',
                "name": '"Constraint Test"',
                "summary": '"Testing nested schema constraints."',
                "kind": '"tool"',
                "layout": '"single"',
                "languages": '["rust"]',
                "placeholder": '"tmpl_prefix"',
                "substitute_in": '["**/*.rs"]',
                "repos": '\n  - name: "tmpl_prefix"',
            }
            fields.update(overrides)
            lines = []
            for k, v in fields.items():
                if v.startswith("\n"):
                    lines.append(f"{k}:{v}")
                else:
                    lines.append(f"{k}: {v}")
            return "\n".join(lines) + "\n"

        cases = [
            (
                "mono-two-repos",
                {
                    "layout": '"mono"',
                    "repos": '\n  - name: "tmpl_prefix"\n  - name: "tmpl_prefix_two"',
                },
                "repos",
            ),
            (
                "bad-kind",
                {"kind": '"microservice"'},
                "kind",
            ),
            (
                "bad-layout",
                {"layout": '"hybrid"'},
                "layout",
            ),
            (
                "uppercase-lang",
                {"languages": '["Rust"]'},
                "languages",
            ),
            (
                "empty-lang-item",
                {"languages": '[""]'},
                "languages",
            ),
            (
                "uppercase-engine",
                {"engine": '"Bevy"'},
                "engine",
            ),
            (
                "repo-unknown-key",
                {"repos": '\n  - name: "tmpl_prefix"\n    bogus: 1'},
                "bogus",
            ),
            (
                "check-null",
                {"repos": '\n  - name: "tmpl_prefix"\n    check: null'},
                "repos.check",
            ),
            (
                "check-unknown-key",
                {"repos": '\n  - name: "tmpl_prefix"\n    check: {cmd: ["cargo"], extra: 1}'},
                "extra",
            ),
            (
                "check-empty-cmd",
                {"repos": '\n  - name: "tmpl_prefix"\n    check: {cmd: []}'},
                "cmd",
            ),
            (
                "check-bad-cwd",
                {"repos": '\n  - name: "tmpl_prefix"\n    check: {cmd: ["cargo"], cwd: "../outside"}'},
                "cwd",
            ),
            (
                "placeholder-trailing-newline",
                {"placeholder": '"tmpl_prefix\\n"'},
                "placeholder",
            ),
            (
                "id-trailing-newline",
                {"id": '"id-trailing-newline\\n"'},
                "id",
            ),
        ]
        for folder_name, overrides, expected_key in cases:
            with tempfile.TemporaryDirectory() as tmp:
                tdir = Path(tmp) / folder_name
                (tdir / "tmpl_prefix").mkdir(parents=True)
                (tdir / "tmpl_prefix_two").mkdir(parents=True)
                yaml_text = render_yaml(folder_name, **overrides)
                (tdir / "template.yaml").write_text(yaml_text, encoding="utf-8")
                with self.subTest(case=folder_name):
                    with self.assertRaises(TemplateError) as ctx:
                        load_template(tdir)
                    msg = str(ctx.exception)
                    self.assertIn(folder_name, msg)
                    self.assertIn(expected_key, msg)

    def test_cmd_tags_needs_allow_empty_string_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "allow-empty-str-items"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            yaml_text = (
                'id: "allow-empty-str-items"\n'
                'name: "Empty String Items"\n'
                'summary: "Verify check.cmd, tags, and needs allow empty strings."\n'
                'kind: "tool"\n'
                'layout: "single"\n'
                'languages: ["rust"]\n'
                'tags: ["", "cli"]\n'
                'needs: [""]\n'
                'placeholder: "tmpl_prefix"\n'
                'substitute_in: ["**/*.rs"]\n'
                "repos:\n"
                '  - name: "tmpl_prefix"\n'
                '    check: {cmd: ["printf", ""], cwd: "."}\n'
            )
            (tdir / "template.yaml").write_text(yaml_text, encoding="utf-8")
            spec = load_template(tdir)
            self.assertEqual(spec.tags, ("", "cli"))
            self.assertEqual(spec.needs, ("",))
            self.assertIsNotNone(spec.repos[0].check)
            assert spec.repos[0].check is not None
            self.assertEqual(spec.repos[0].check.cmd, ("printf", ""))

    def test_invalid_utf8_in_template_yaml_raises_and_lenient_collects_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(TEMPLATES_FIXTURES / "fake-rust-game", root / "fake-rust-game")
            bad_dir = root / "bad-utf8-template"
            bad_dir.mkdir()
            (bad_dir / "template.yaml").write_bytes(b"\xff\xfe")

            with self.assertRaises(TemplateError) as ctx:
                load_template(bad_dir)
            self.assertIn("bad-utf8-template", str(ctx.exception))
            self.assertIn("template.yaml", str(ctx.exception))

            valid, errors = load_templates_lenient(root)
            self.assertEqual([s.id for s in valid], ["fake-rust-game"])
            self.assertEqual(len(errors), 1)
            self.assertIn("bad-utf8-template", errors[0])
            self.assertIn("template.yaml", errors[0])

    def test_locked_and_approved_deps_both_or_neither_and_validation(self) -> None:
        base_fields = (
            'name: "Locked And Approved Test"\n'
            'summary: "Verify locked and approved_deps pairing and schema."\n'
            'kind: "app"\n'
            'layout: "mono"\n'
            'languages: ["rust"]\n'
            'placeholder: "tmpl_prefix"\n'
            'substitute_in: ["**/*.rs", "**/*.toml"]\n'
            "repos:\n"
            '  - name: "tmpl_prefix"\n'
        )

        # 1. Both present -> valid
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "with-both"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            (tdir / "template.yaml").write_text(
                'id: "with-both"\n'
                + base_fields
                + 'locked: ["Cargo.toml", ".github/workflows/*", "xtask/**"]\n'
                + "approved_deps:\n"
                + '  rust: ["serde", "toml"]\n',
                encoding="utf-8",
            )
            spec = load_template(tdir)
            self.assertEqual(
                spec.locked,
                ("Cargo.toml", ".github/workflows/*", "xtask/**"),
            )
            self.assertEqual(dict(spec.approved_deps), {"rust": ("serde", "toml")})

        # 2. Only locked -> raises TemplateError naming approved_deps
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "only-locked"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            (tdir / "template.yaml").write_text(
                'id: "only-locked"\n'
                + base_fields
                + 'locked: ["Cargo.toml"]\n',
                encoding="utf-8",
            )
            with self.assertRaises(TemplateError) as ctx:
                load_template(tdir)
            self.assertIn("only-locked", str(ctx.exception))
            self.assertIn("approved_deps", str(ctx.exception))

        # 3. Only approved_deps -> raises TemplateError naming locked
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "only-approved"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            (tdir / "template.yaml").write_text(
                'id: "only-approved"\n'
                + base_fields
                + "approved_deps:\n"
                + '  rust: ["serde"]\n',
                encoding="utf-8",
            )
            with self.assertRaises(TemplateError) as ctx:
                load_template(tdir)
            self.assertIn("only-approved", str(ctx.exception))
            self.assertIn("locked", str(ctx.exception))

        # 4. Invalid locked or approved_deps values
        invalid_cases = [
            ("locked-empty", 'locked: []\napproved_deps: {rust: ["serde"]}\n', "locked"),
            ("locked-parent", 'locked: ["../Cargo.toml"]\napproved_deps: {rust: ["serde"]}\n', "locked"),
            ("locked-abs", 'locked: ["/etc/passwd"]\napproved_deps: {rust: ["serde"]}\n', "locked"),
            ("deps-empty-map", 'locked: ["Cargo.toml"]\napproved_deps: {}\n', "approved_deps"),
            ("deps-upper-eco", 'locked: ["Cargo.toml"]\napproved_deps: {Rust: ["serde"]}\n', "approved_deps"),
            ("deps-empty-item", 'locked: ["Cargo.toml"]\napproved_deps: {rust: [""]}\n', "approved_deps"),
            ("deps-bad-type", 'locked: ["Cargo.toml"]\napproved_deps: "serde"\n', "approved_deps"),
        ]
        for case_name, extra_yaml, expected_key in invalid_cases:
            with tempfile.TemporaryDirectory() as tmp:
                tdir = Path(tmp) / case_name
                (tdir / "tmpl_prefix").mkdir(parents=True)
                (tdir / "template.yaml").write_text(
                    f'id: "{case_name}"\n' + base_fields + extra_yaml,
                    encoding="utf-8",
                )
                with self.subTest(case=case_name):
                    with self.assertRaises(TemplateError) as ctx:
                        load_template(tdir)
                    self.assertIn(case_name, str(ctx.exception))
                    self.assertIn(expected_key, str(ctx.exception))

    def test_options_block_validation_and_options_as_json(self) -> None:
        valid_yaml = (TEMPLATES_FIXTURES / "options_valid.yaml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "options-valid"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            (tdir / "template.yaml").write_text(valid_yaml, encoding="utf-8")
            spec = load_template(tdir)
            self.assertIn("http_adapter", spec.options)
            opt = spec.options["http_adapter"]
            self.assertIsInstance(opt, OptionSpec)
            self.assertEqual(opt.id, "http_adapter")
            self.assertEqual(opt.label, "HTTP adapter")
            self.assertEqual(opt.choices, ("hono", "node_http"))
            self.assertEqual(opt.default, "hono")
            self.assertEqual(opt.env_key, "TMPL_PREFIX_HTTP_ADAPTER")
            self.assertEqual(
                opt.description,
                "Both adapters ship; this picks the default wired in config.",
            )
            expected_json = [
                {
                    "id": "http_adapter",
                    "label": "HTTP adapter",
                    "choices": ["hono", "node_http"],
                    "default": "hono",
                    "env_key": "TMPL_PREFIX_HTTP_ADAPTER",
                    "description": "Both adapters ship; this picks the default wired in config.",
                }
            ]
            self.assertEqual(spec.options_as_json(), expected_json)
            self.assertEqual(options_as_json(spec), expected_json)
            self.assertEqual(options_as_json(spec.options), expected_json)
            self.assertEqual(options_as_json(tdir), expected_json)
            self.assertEqual(
                options_as_json(Path(tmp)),
                {"options-valid": expected_json},
            )

        bad_fixtures = [
            ("options-unknown-key", "options_unknown_key.yaml", "unknown_field"),
            (
                "options-default-not-in-choices",
                "options_default_not_in_choices.yaml",
                "default",
            ),
            ("options-duplicate-choice", "options_duplicate_choice.yaml", "choices"),
            (
                "options-duplicate-option-id",
                "options_duplicate_option_id.yaml",
                "http_adapter",
            ),
        ]
        for folder_name, fixture_file, expected_key in bad_fixtures:
            raw_yaml = (TEMPLATES_FIXTURES / fixture_file).read_text(encoding="utf-8")
            with tempfile.TemporaryDirectory() as tmp:
                tdir = Path(tmp) / folder_name
                (tdir / "tmpl_prefix").mkdir(parents=True)
                (tdir / "template.yaml").write_text(raw_yaml, encoding="utf-8")
                with self.subTest(case=folder_name):
                    with self.assertRaises(TemplateError) as ctx:
                        load_template(tdir)
                    msg = str(ctx.exception)
                    self.assertIn(folder_name, msg)
                    self.assertIn(expected_key, msg)

        base_fields = (
            'name: "Options Constraint Test"\n'
            'summary: "Verify options schema edge cases."\n'
            'kind: "service"\n'
            'layout: "mono"\n'
            'languages: ["typescript"]\n'
            'placeholder: "tmpl_prefix"\n'
            'substitute_in: ["**/*.ts"]\n'
            "repos:\n"
            '  - name: "tmpl_prefix"\n'
        )
        inline_bad_cases = [
            ("opt-not-map", 'options: ["http_adapter"]\n', "options"),
            (
                "opt-bad-id",
                "options:\n  HTTP-Adapter:\n    label: \"HTTP\"\n    choices: [hono, node_http]\n    default: hono\n    env_key: TMPL_PREFIX_HTTP_ADAPTER\n",
                "HTTP-Adapter",
            ),
            (
                "opt-one-choice",
                "options:\n  http_adapter:\n    label: \"HTTP\"\n    choices: [hono]\n    default: hono\n    env_key: TMPL_PREFIX_HTTP_ADAPTER\n",
                "choices",
            ),
            (
                "opt-seven-choices",
                "options:\n  http_adapter:\n    label: \"HTTP\"\n    choices: [a, b, c, d, e, f, g]\n    default: a\n    env_key: TMPL_PREFIX_HTTP_ADAPTER\n",
                "choices",
            ),
            (
                "opt-bad-choice-id",
                "options:\n  http_adapter:\n    label: \"HTTP\"\n    choices: [hono, Node-Http]\n    default: hono\n    env_key: TMPL_PREFIX_HTTP_ADAPTER\n",
                "choices",
            ),
            (
                "opt-bad-env-key",
                "options:\n  http_adapter:\n    label: \"HTTP\"\n    choices: [hono, node_http]\n    default: hono\n    env_key: tmpl_prefix_http_adapter\n",
                "env_key",
            ),
            (
                "opt-missing-label",
                "options:\n  http_adapter:\n    choices: [hono, node_http]\n    default: hono\n    env_key: TMPL_PREFIX_HTTP_ADAPTER\n",
                "label",
            ),
        ]
        for case_name, extra_yaml, expected_key in inline_bad_cases:
            with tempfile.TemporaryDirectory() as tmp:
                tdir = Path(tmp) / case_name
                (tdir / "tmpl_prefix").mkdir(parents=True)
                (tdir / "template.yaml").write_text(
                    f'id: "{case_name}"\n' + base_fields + extra_yaml,
                    encoding="utf-8",
                )
                with self.subTest(case=case_name):
                    with self.assertRaises(TemplateError) as ctx:
                        load_template(tdir)
                    msg = str(ctx.exception)
                    self.assertIn(case_name, msg)
                    self.assertIn(expected_key, msg)


if __name__ == "__main__":
    unittest.main()
