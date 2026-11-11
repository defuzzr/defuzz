"""Characterization tests for `audit/facts.py`."""

from __future__ import annotations

import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit import facts  # type: ignore[import-not-found] # noqa: E402
from hermes_plugins.defuzz.audit.contract import (  # type: ignore[import-not-found] # noqa: E402
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
)


class TestAuditFactsCharacterization(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_compatibility_facade_exports_and_signatures(self) -> None:
        expected_Attributes = (
            "FACTS_ADAPTER_VERSION",
            "TOKEN_ESTIMATOR_VERSION",
            "CHARS_PER_TOKEN",
            "TIER_PROJECT",
            "TIER_LOCAL",
            "TIER_CREATE_DIR",
            "TIER_EXTERNAL",
            "PROJECT_SKILLS_SUBDIRS",
            "EXCLUDED_SKILL_DIRS",
            "SKILL_SUPPORT_DIRS",
            "ESSENTIAL_SKILLS",
            "_PROFILE_ID_RE",
            "_PROFILE_IDENTITY_MARKERS",
            "_CJK_DENSE_RE",
            "DEFAULT_CONTEXT_FILE_MAX_CHARS",
            "CONTEXT_TRUNCATE_HEAD_RATIO",
            "CONTEXT_TRUNCATE_TAIL_RATIO",
            "SKILL_PROMPT_DESC_LIMIT",
            "DEFAULT_AGENT_IDENTITY",
            "HERMES_AGENT_HELP_GUIDANCE",
            "HERMES_AGENT_HELP_GUIDANCE_NO_SKILLS",
            "TASK_COMPLETION_GUIDANCE",
            "PARALLEL_TOOL_CALL_GUIDANCE",
            "SKILLS_GUIDANCE",
            "SESSION_SEARCH_GUIDANCE",
            "STEER_MARKER_OPEN",
            "STEER_MARKER_CLOSE",
            "STEER_CHANNEL_NOTE",
            "TOOL_USE_ENFORCEMENT_GUIDANCE",
            "GOOGLE_MODEL_OPERATIONAL_GUIDANCE",
            "OPENAI_MODEL_EXECUTION_GUIDANCE",
            "TOOL_USE_ENFORCEMENT_MODELS",
            "EXECUTION_GUIDANCE_MODELS",
            "_GATE_WORDS",
            "EntrySecurityCheck",
            "ProfileEnumerationResult",
            "estimate_tokens_rough",
            "_resolve_official_profile_fns",
            "resolve_mcp_entry_security_check",
            "resolve_active_profile_name",
            "enumerate_profiles",
            "_parse_simple_yaml_mapping",
            "parse_frontmatter_stdlib",
            "resolve_profile_memory_facts",
            "_expand_skill_config_dir",
            "_normalize_str_list",
            "resolve_profile_skill_roots",
            "_scan_skills_in_root",
            "resolve_profile_skills_facts",
            "_scan_static_plugin_count",
            "_fallback_newest_mtime",
            "collect_profile_last_use_evidence",
            "evaluate_profile_age_and_unused",
            "order_profile_units",
            "order_project_units",
            "choose_duplicate_survivor",
            "discover_optional_root_repos",
            "resolve_project_context_chain_facts",
            "_model_gate_facts",
            "_build_memory_guidance_facts",
            "resolve_core_guidance_facts",
            "observe_memory_path_references",
            "collect_profile_unit_facts",
            "collect_system_inventory_facts",
        )
        for attr in expected_Attributes:
            self.assertTrue(hasattr(facts, attr), f"Missing attribute on audit.facts: {attr}")

        sig_collect = inspect.signature(facts.collect_profile_unit_facts)
        self.assertEqual(
            list(sig_collect.parameters.keys()),
            [
                "profile_name",
                "profile_dir",
                "is_default",
                "is_active",
                "descendant_profile_roots",
                "as_of",
                "unused_threshold_days",
                "rule_versions",
            ],
        )

    def test_estimate_tokens_rough_variants(self) -> None:
        empty = facts.estimate_tokens_rough("")
        self.assertEqual(empty["characters"], 0)
        self.assertEqual(empty["utf8_bytes"], 0)
        self.assertEqual(empty["estimated_tokens"], 0)
        self.assertFalse(empty["is_exact"])

        ascii_res = facts.estimate_tokens_rough("abcdefgh")
        self.assertEqual(ascii_res["characters"], 8)
        self.assertEqual(ascii_res["utf8_bytes"], 8)
        self.assertEqual(ascii_res["estimated_tokens"], 2)

        cjk_res = facts.estimate_tokens_rough("你好abcd")
        self.assertEqual(cjk_res["characters"], 6)
        self.assertEqual(cjk_res["utf8_bytes"], 10)
        self.assertEqual(cjk_res["estimated_tokens"], 2 + 1)

    def test_yaml_and_frontmatter_parsing(self) -> None:
        self.assertEqual(facts._parse_simple_yaml_mapping(""), {})
        self.assertEqual(facts._parse_simple_yaml_mapping("# just comment\n"), {})

        fm, body = facts.parse_frontmatter_stdlib("\ufeff---\nname: demo\ndescription: hi\n---\nBody text\n")
        self.assertEqual(fm, {"name": "demo", "description": "hi"})
        self.assertEqual(body, "Body text\n")

        fm_none, body_raw = facts.parse_frontmatter_stdlib("No frontmatter here")
        self.assertEqual(fm_none, {})
        self.assertEqual(body_raw, "No frontmatter here")

        fm_unclosed, body_unclosed = facts.parse_frontmatter_stdlib("---\nname: demo\nNo closing marker")
        self.assertEqual(fm_unclosed, {})
        self.assertTrue(body_unclosed.startswith("---"))

    def test_normalize_str_list_and_expand_skill_dir(self) -> None:
        self.assertEqual(facts._normalize_str_list("  hello "), ["hello"])
        self.assertEqual(facts._normalize_str_list(""), [])
        self.assertEqual(facts._normalize_str_list("['a', ' b ', '']"), ["a", "b"])
        self.assertEqual(facts._normalize_str_list("[unclosed"), ["[unclosed"])
        self.assertEqual(facts._normalize_str_list(["x", " y ", ""]), ["x", "y"])
        self.assertEqual(facts._normalize_str_list(None), [])

        pdir = self.tmp_root / "prof"
        self.assertEqual(facts._expand_skill_config_dir("custom/skills", pdir), pdir / "custom/skills")
        self.assertEqual(facts._expand_skill_config_dir("/abs/skills", pdir), Path("/abs/skills"))

    def test_resolve_active_profile_and_enumerate_profiles_edges(self) -> None:
        def_dir = self.tmp_root / "hermes_home"
        def_dir.mkdir(parents=True)
        (def_dir / "active_profile").write_text("coder_1\n", encoding="utf-8")

        with mock.patch("hermes_constants.profile_name_for_home", return_value=None):
            with mock.patch.dict(os.environ, {"HERMES_HOME": ""}, clear=False):
                active = facts.resolve_active_profile_name(
                    default_root=def_dir,
                    get_profile_dir_fn=lambda n: def_dir if n == "default" else def_dir / "profiles" / n,
                )
                self.assertEqual(active, "coder_1")

        # Symlinked default root -> could_not_verify
        sym_def = self.tmp_root / "sym_hermes"
        sym_def.symlink_to(def_dir, target_is_directory=True)
        enum_sym = facts.enumerate_profiles(
            list_profile_names_fn=lambda: ["default", "default"],
            get_profile_dir_fn=lambda n: sym_def,
            active_profile="default",
        )
        self.assertEqual(enum_sym.coverage, COVERAGE_COULD_NOT_VERIFY)
        self.assertFalse(enum_sym.enumeration_complete)
        self.assertEqual(len(enum_sym.profiles), 1)
        self.assertEqual(enum_sym.to_dict()["active_profile"], "default")

    def test_memory_facts_and_path_observations(self) -> None:
        pdir = self.tmp_root / "prof_mem"
        mem_dir = pdir / "memories"
        mem_dir.mkdir(parents=True)
        existing_ref = self.tmp_root / "existing_target.txt"
        existing_ref.write_text("hi", encoding="utf-8")

        (mem_dir / "MEMORY.md").write_text(
            f"Check ~/existing_target.txt and ~/missing_target.txt and /opt/outside/file.txt\n§\nSecond entry\n",
            encoding="utf-8",
        )
        # USER.md as symlink
        (mem_dir / "USER.md").symlink_to(existing_ref)

        mem_facts = facts.resolve_profile_memory_facts(
            "default",
            pdir,
            config={"memory": {"memory_enabled": False, "user_profile_enabled": True}},
        )
        self.assertEqual(mem_facts["coverage"], COVERAGE_VERIFIED)
        mem_file = mem_facts["files"]["memory"]
        self.assertTrue(mem_file["exists"])
        self.assertFalse(mem_file["enabled"])
        self.assertEqual(len(mem_file["entries"]), 2)
        self.assertEqual(mem_file["token_metrics"]["characters"], 0)
        self.assertGreater(mem_file["raw_token_metrics"]["characters"], 0)

        user_file = mem_facts["files"]["user"]
        self.assertTrue(user_file["is_symlink"])
        self.assertEqual(user_file["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(user_file["entries"], [])

        # Exceeding max_bytes yields could_not_verify
        oversized = facts.resolve_profile_memory_facts("default", pdir, max_bytes=4)
        self.assertEqual(oversized["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(oversized["files"]["memory"]["coverage"], COVERAGE_COULD_NOT_VERIFY)

        obs = facts.observe_memory_path_references(
            mem_facts,
            home_dir=self.tmp_root,
            accessible_roots=[self.tmp_root],
        )
        self.assertTrue(obs[str(existing_ref)]["exists"])
        self.assertFalse(obs[str(self.tmp_root / "missing_target.txt")]["exists"])
        self.assertEqual(obs["/opt/outside/file.txt"]["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(obs["/opt/outside/file.txt"]["reason"], "outside_accessible_namespace")

    def test_skills_facts_shadowing_duplicates_and_essential(self) -> None:
        pdir = self.tmp_root / "prof_skills"
        local_skills = pdir / "skills"
        ext_a = self.tmp_root / "ext_a"
        ext_b = self.tmp_root / "ext_b"
        proj_root = self.tmp_root / "proj"

        # Project skill shadows local skill
        (proj_root / ".hermes" / "skills" / "shared-skill").mkdir(parents=True)
        (proj_root / ".hermes" / "skills" / "shared-skill" / "SKILL.md").write_text(
            "---\nname: shared-skill\ndescription: Project version\n---\nProj body\n",
            encoding="utf-8",
        )
        (local_skills / "shared-skill").mkdir(parents=True)
        (local_skills / "shared-skill" / "SKILL.md").write_text(
            "---\nname: shared-skill\ndescription: Local version\n---\nLocal body\n",
            encoding="utf-8",
        )
        # Essential skill cannot be disabled
        (local_skills / "hermes-agent" / "references").mkdir(parents=True)
        (local_skills / "hermes-agent" / "SKILL.md").write_text(
            "---\nname: hermes-agent\ndescription: Essential skill\n---\nEssential body\n",
            encoding="utf-8",
        )
        (local_skills / "hermes-agent" / "references" / "ref.md").write_text("Ref content\n", encoding="utf-8")

        # Same-tier ambiguous vs byte-identical skills in external_dirs
        (ext_a / "ambig").mkdir(parents=True)
        (ext_b / "ambig").mkdir(parents=True)
        (ext_a / "ambig" / "SKILL.md").write_text("---\nname: ambig\n---\nBody A\n", encoding="utf-8")
        (ext_b / "ambig" / "SKILL.md").write_text("---\nname: ambig\n---\nBody B\n", encoding="utf-8")

        (ext_a / "ident").mkdir(parents=True)
        (ext_b / "nested" / "ident").mkdir(parents=True)
        ident_md = "---\nname: ident\n---\nSame body\n"
        (ext_a / "ident" / "SKILL.md").write_text(ident_md, encoding="utf-8")
        (ext_b / "nested" / "ident" / "SKILL.md").write_text(ident_md, encoding="utf-8")

        cfg = {
            "skills": {
                "trusted_project_dirs": [str(proj_root)],
                "external_dirs": [str(ext_a), str(ext_b)],
                "disabled": ["hermes-agent", "ident"],
                "auto_load": ["hermes-agent"],
            }
        }
        sf = facts.resolve_profile_skills_facts("default", pdir, config=cfg, project_root=proj_root)
        self.assertEqual(sf["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(sf["profile_carried_count"], 2)
        self.assertNotIn("hermes-agent", sf["disabled_skill_names"])

        by_name_tier = {(s["name"], s["tier"], s["relative_path"]): s for s in sf["skills"]}
        self.assertEqual(by_name_tier[("shared-skill", facts.TIER_PROJECT, "shared-skill")]["status"], "unique")
        self.assertEqual(by_name_tier[("shared-skill", facts.TIER_LOCAL, "shared-skill")]["status"], "shadowed")
        self.assertTrue(by_name_tier[("hermes-agent", facts.TIER_LOCAL, "hermes-agent")]["auto_loaded"])
        self.assertFalse(by_name_tier[("hermes-agent", facts.TIER_LOCAL, "hermes-agent")]["disabled"])
        self.assertEqual(
            by_name_tier[("hermes-agent", facts.TIER_LOCAL, "hermes-agent")]["supporting_files"],
            ["references/ref.md"],
        )
        self.assertEqual(by_name_tier[("ambig", facts.TIER_EXTERNAL, "ambig")]["status"], "ambiguous")
        self.assertEqual(by_name_tier[("ident", facts.TIER_EXTERNAL, "ident")]["status"], "unique")
        self.assertEqual(by_name_tier[("ident", facts.TIER_EXTERNAL, "nested/ident")]["status"], "shadowed")

    def test_plugins_last_use_ordering_and_core_guidance(self) -> None:
        pdir = self.tmp_root / "prof_misc"
        (pdir / "plugins" / "p_yaml").mkdir(parents=True)
        (pdir / "plugins" / "p_yaml" / "plugin.yaml").write_text("name: p_yaml\n", encoding="utf-8")
        (pdir / "plugins" / "p_dash" / "dashboard").mkdir(parents=True)
        (pdir / "plugins" / "p_dash" / "dashboard" / "manifest.json").write_text("{}", encoding="utf-8")
        (pdir / "plugins" / ".hidden").mkdir(parents=True)

        count, cov, manifests = facts._scan_static_plugin_count(pdir)
        self.assertEqual(count, 2)
        self.assertEqual(cov, COVERAGE_VERIFIED)
        self.assertEqual([m["name"] for m in manifests], ["p_dash", "p_yaml"])

        # Fallback newest mtime from sessions/
        (pdir / "sessions").mkdir(parents=True)
        sess_file = pdir / "sessions" / "s1.json"
        sess_file.write_text("{}", encoding="utf-8")
        os.utime(sess_file, (1700000123, 1700000123))
        ev = facts.collect_profile_last_use_evidence(pdir)
        self.assertEqual(ev["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(ev["last_use_source"], "mtime:sessions/s1.json")
        self.assertAlmostEqual(ev["last_use_timestamp"], 1700000123.0, places=0)

        # Ordering projects
        ordered_proj = facts.order_project_units([
            {"canonical_path": "/b", "last_use_timestamp": None, "created_at": 100},
            {"canonical_path": "/a", "last_use_timestamp": 200},
            {"canonical_path": "/c", "last_use_timestamp": None, "created_at": None},
        ])
        self.assertEqual([p["canonical_path"] for p in ordered_proj], ["/a", "/b", "/c"])

        # Core guidance with gemini model and disabled memory
        cg = facts.resolve_core_guidance_facts(
            config={"model": {"default": "gemini-2.5-pro"}, "agent": {"execution_guidance": "always"}},
            memory_enabled=False,
            user_profile_enabled=True,
            has_hermes_agent_skill_in_index=False,
        )
        self.assertIn("google_model_operational_guidance", cg["sections"])
        self.assertIn("openai_model_execution_guidance", cg["sections"])
        self.assertIn(facts.HERMES_AGENT_HELP_GUIDANCE_NO_SKILLS, cg["rendered_text"])

    def test_monkeypatch_seams_preserved(self) -> None:
        pdir = self.tmp_root / "prof_seam"
        pdir.mkdir(parents=True)
        (pdir / "config.yaml").write_text("model: gpt-4o\n", encoding="utf-8")

        called = []
        orig_mem = facts.resolve_profile_memory_facts

        def _spy_mem(*args, **kwargs):
            called.append("memory")
            return orig_mem(*args, **kwargs)

        with mock.patch.object(facts, "resolve_profile_memory_facts", side_effect=_spy_mem):
            unit = facts.collect_profile_unit_facts(
                profile_name="default",
                profile_dir=pdir,
                is_default=True,
                is_active=True,
                as_of=1710000000,
            )
        self.assertEqual(called, ["memory"])
        self.assertEqual(unit["name"], "default")

    def test_gate_words_monkeypatch_seam_and_vendor_independence(self) -> None:
        from hermes_plugins.defuzz.audit.vendor import profile_context  # type: ignore[import-not-found]

        self.assertIsNot(facts._GATE_WORDS, profile_context._GATE_WORDS)
        with mock.patch.dict(profile_context._GATE_WORDS, {"always": False, "__vendor_only__": True}):
            self.assertTrue(facts._GATE_WORDS["always"])
            self.assertNotIn("__vendor_only__", facts._GATE_WORDS)

        with mock.patch.object(facts, "_GATE_WORDS", {"always": False}):
            cg = facts.resolve_core_guidance_facts(
                config={"model": "claude", "agent": {"execution_guidance": "always"}}
            )
        self.assertNotIn("openai_model_execution_guidance", cg["sections"])
        self.assertEqual(cg["token_metrics"]["estimated_tokens"], 1009)


if __name__ == "__main__":
    unittest.main()
