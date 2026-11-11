"""Regression coverage for the adopted-project review contract (stdlib only)."""
import unittest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.agents_md import SCHEMA_MARKER, render_agents_md, validate_agents_md
from hermes_plugins.defuzz.rules import build_deterministic_fallback_rules, expand_rules, validate_rules_spec
from hermes_plugins.defuzz.safety import SafetyError
from hermes_plugins.defuzz.schemas import DEFUZZ_PROJECT


def spec(prefix=".", disposition="keep"):
    return {"folder_rules": [{"match": prefix, "disposition": disposition,
                              "git_policy": "track", "to": "_archive/old"}]}


class ReviewContractTests(unittest.TestCase):
    def test_source_and_test_trees_reject_relocation(self):
        for prefix in ("src", "src/core", "tests", "tests/unit", "test", "test/unit"):
            for disposition in ("move", "archive"):
                with self.subTest(prefix=prefix, disposition=disposition):
                    with self.assertRaises(SafetyError):
                        validate_rules_spec(spec(prefix, disposition))
                    with self.assertRaises(SafetyError):
                        expand_rules({"files": [{"path": prefix + "/a.py"}]},
                                     spec(prefix, disposition))

    def test_root_relocation_leaves_nested_files_in_place(self):
        paths = ["note.md", "src/note.md", "tests/note.md", "test/note.md", "docs/note.md"]
        for disposition in ("move", "archive"):
            result = expand_rules({"files": [{"path": p} for p in paths]}, spec(".", disposition))
            self.assertEqual(result["files"][0]["disposition"], disposition)
            for entry in result["files"][1:]:
                self.assertEqual(entry["disposition"], "keep")
                self.assertEqual(entry["dest_path"], entry["source_path"])

    def test_fallback_declares_existing_top_level_directories(self):
        inventory = {"dir_summaries": {d: {} for d in
                     (".", "src", "wiki", "tests", "test", "custom", "assets", "custom/nested")}}
        result = build_deterministic_fallback_rules(inventory)
        names = [d["dir"] for d in result["declared_dirs"]]
        self.assertTrue({"src", "wiki", "tests", "test", "custom", "assets"} <= set(names))
        self.assertNotIn(".", names)
        self.assertNotIn("custom/nested", names)
        self.assertEqual(len(names), len(set(names)))

    def test_sanitization_removes_newly_exposed_forbidden_tokens(self):
        for value in ("ht;tp://example", "ht&;;&tp://example", "$;HOME", "ft|p://host"):
            with self.subTest(value=value):
                content = render_agents_md(project_slug=value, placement_rules=[],
                                           declared_dirs={"docs": (value, value)})
                self.assertTrue(validate_agents_md(content))
                for token in (";", "://", "$", "|", "&&"):
                    self.assertNotIn(token, content)

    def test_nested_directory_fact_is_rendered(self):
        content = render_agents_md(project_slug="demo", placement_rules=[],
                                   declared_dirs={"assets/3d": ("models", "source models")})
        sections = validate_agents_md(content, allowed_dirs={"assets/3d", "_inbox", "_archive"})
        layout = next(s for s in sections if s["heading"] == "Layout")
        self.assertTrue(any(ln.startswith("- `assets/3d/`") for ln in layout["lines"]))
        with self.assertRaises(SafetyError):
            validate_agents_md(content, allowed_dirs={"_inbox", "_archive"})

    def test_rules_and_guide_expose_contract_version(self):
        validated = validate_rules_spec(spec())
        self.assertEqual(validated.get("schema_version"), 1)
        self.assertEqual(validated["schema"], 1)
        fallback = build_deterministic_fallback_rules({})
        self.assertEqual(fallback.get("schema_version"), 1)
        content = render_agents_md(project_slug="demo", declared_dirs={}, placement_rules=[])
        self.assertIn(SCHEMA_MARKER, content.splitlines())
        self.assertIn("schema_version: 1", SCHEMA_MARKER)
        validate_agents_md(content)

    def test_project_schema_exposes_report_path(self):
        properties = DEFUZZ_PROJECT["parameters"]["properties"]
        self.assertIn("report_path", properties)
        self.assertEqual(properties["report_path"]["type"], "string")
        self.assertNotIn("report_path", DEFUZZ_PROJECT["parameters"]["required"])

    def test_safe_path_character_contract(self):
        name = "assets/@scope/foo+bar,(v2)~draft=1-_.png"
        result = expand_rules({"files": [{"path": name}]}, spec())
        self.assertEqual(result["files"][0]["dest_path"], name)
        bracketed = "app/[id]/page.tsx"
        self.assertTrue(validate_rules_spec(spec("app/[id]")))
        result = expand_rules({"files": [{"path": bracketed}]}, spec())
        self.assertEqual(result["files"][0]["dest_path"], bracketed)
        for name in ("has space", "bad;command", "bad$file", "bad`file"):
            with self.subTest(name=name), self.assertRaises(SafetyError):
                validate_rules_spec(spec(name))
