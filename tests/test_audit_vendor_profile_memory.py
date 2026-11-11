"""Packaged-provenance and end-to-end integration tests for `audit/vendor/profile_context.py` and `audit/vendor/memory.py` (§2, §5, §6, §11, §12, §13.4, §13.5)."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.vendor import (  # type: ignore[import-not-found] # noqa: E402
    memory as vendor_memory,
    profile_context as vendor_profile_context,
)
from tests.test_audit_tripwires import sweep_forbidden_call_tripwires  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = REPO_ROOT / "audit" / "vendor"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "audit_profile"



class TestAuditVendorProfileMemory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_packaged_vendor_provenance(self) -> None:
        from tests.vendor_provenance import assert_packaged_vendor
        assert_packaged_vendor(self, ['profile_context.py', 'memory.py'])


    def test_profile_context_and_ranking_from_live_facts_adapter_under_tripwires(self) -> None:
        """§2, §5, §6, §11, §13.4:
        - `collect_profile_unit_facts` feeds `audit_profile_context` under strict tripwires.
        - Auto-loaded skills contribute full rendered bodies + supporting file listings (not bodies).
        - Non-auto-loaded skills contribute index lines only; shadowed/disabled contribute 0.
        - Ranking uses static profile base only; per-project context additions are in a separate column.
        - Fixed `could_not_verify` line for dynamic contributions keeps `can_claim_clean == False`.
        """
        default_dir = self.tmp_root / "hermes_home"
        coder_dir = default_dir / "profiles" / "coder"
        ext_skills_dir = self.tmp_root / "shared_external_skills"

        (default_dir / "memories").mkdir(parents=True)
        (default_dir / "skills" / "workflows" / "pinned-skill" / "references").mkdir(parents=True)
        (default_dir / "skills" / "workflows" / "on-demand-skill").mkdir(parents=True)
        (default_dir / "skills" / "workflows" / "disabled-skill").mkdir(parents=True)
        (ext_skills_dir / "workflows" / "on-demand-skill").mkdir(parents=True)
        (coder_dir / "memories").mkdir(parents=True)
        (coder_dir / "skills").mkdir(parents=True)

        (default_dir / "config.yaml").write_text(
            f"model: gemini-4-argon-high\n"
            f"skills:\n"
            f"  auto_load:\n"
            f"    - pinned-skill\n"
            f"  disabled:\n"
            f"    - disabled-skill\n"
            f"  external_dirs:\n"
            f"    - {ext_skills_dir}\n",
            encoding="utf-8",
        )
        (default_dir / "SOUL.md").write_text("You are the default profile persona.\n" * 10, encoding="utf-8")
        (default_dir / "memories" / "MEMORY.md").write_text(
            "Default memory note one.\n§\nDefault memory note two.\n",
            encoding="utf-8",
        )
        (default_dir / "memories" / "USER.md").write_text("User prefers concise answers.\n", encoding="utf-8")

        pinned_body = "Pinned skill full instructions body.\n" * 30
        (default_dir / "skills" / "workflows" / "pinned-skill" / "SKILL.md").write_text(
            f"---\nname: pinned-skill\ndescription: Pinned workflow skill\n---\n{pinned_body}",
            encoding="utf-8",
        )
        # Supporting file whose body must NOT be injected (only its relative name is listed)
        (default_dir / "skills" / "workflows" / "pinned-skill" / "references" / "huge_ref.md").write_text(
            "HUGE SUPPORTING FILE BODY " * 500,
            encoding="utf-8",
        )
        (default_dir / "skills" / "workflows" / "on-demand-skill" / "SKILL.md").write_text(
            "---\nname: on-demand-skill\ndescription: Local winner skill\n---\n" + ("On demand body.\n" * 100),
            encoding="utf-8",
        )
        (ext_skills_dir / "workflows" / "on-demand-skill" / "SKILL.md").write_text(
            "---\nname: on-demand-skill\ndescription: External shadowed copy\n---\nShadowed body.\n",
            encoding="utf-8",
        )
        (default_dir / "skills" / "workflows" / "disabled-skill" / "SKILL.md").write_text(
            "---\nname: disabled-skill\ndescription: Disabled skill\n---\nDisabled body.\n",
            encoding="utf-8",
        )

        # Named profile `coder` has a smaller static base, but a huge project AGENTS.md
        (coder_dir / "config.yaml").write_text("model: claude-sonnet\n", encoding="utf-8")
        (coder_dir / "SOUL.md").write_text("Short coder soul.\n", encoding="utf-8")

        proj_dir = self.tmp_root / "coder_project"
        proj_dir.mkdir(parents=True)
        (proj_dir / "AGENTS.md").write_text("Project AGENTS instructions.\n" * 400, encoding="utf-8")
        (proj_dir / "CLAUDE.md").write_text("Shadowed CLAUDE instructions.\n" * 100, encoding="utf-8")

        from hermes_plugins.defuzz import audit as audit_pkg  # type: ignore[import-not-found]

        from hermes_plugins.defuzz.audit.key import key_scope
        # Provision the private plugin key before the read-only capture tripwire.
        with key_scope(self.tmp_root / 'audit-store' / 'audit.db'), sweep_forbidden_call_tripwires(allowed_write_root=None):
            def_facts = audit_pkg.collect_profile_unit_facts(
                profile_name="default",
                profile_dir=default_dir,
                is_default=True,
                is_active=True,
                descendant_profile_roots=[coder_dir],
                as_of=1750000000,
            )
            coder_facts = audit_pkg.collect_profile_unit_facts(
                profile_name="coder",
                profile_dir=coder_dir,
                is_default=False,
                is_active=False,
                as_of=1750000000,
            )
            proj_ctx = audit_pkg.resolve_project_context_chain_facts(proj_dir)

            def_ctx_env = vendor_profile_context.audit_profile_context(
                profile_facts=def_facts,
                project_contexts=[],
            )
            coder_ctx_env = vendor_profile_context.audit_profile_context(
                profile_facts=coder_facts,
                project_contexts=[proj_ctx],
            )
            ranked = vendor_profile_context.rank_profiles_by_static_base([coder_ctx_env, def_ctx_env])

        # Verify core_guidance was populated by facts.py and used by audit_profile_context
        self.assertIn("core_guidance", def_facts)
        self.assertGreater(def_facts["core_guidance"]["token_metrics"]["characters"], 500)

        # Auto-loaded skill has supporting file listed, 0 supporting body chars injected
        loaded_auto = def_ctx_env["static_profile_base"]["components"]["auto_loaded_skill_bodies"]["loaded_skills"]
        self.assertEqual(len(loaded_auto), 1)
        self.assertEqual(loaded_auto[0]["supporting_file_names"], ["references/huge_ref.md"])
        self.assertEqual(loaded_auto[0]["supporting_bodies_injected_chars"], 0)
        self.assertLess(loaded_auto[0]["injected_chars"], 3000)

        # Ranking places `default` #1 (larger static base) and `coder` #2 despite `coder` having >10k project context chars
        self.assertEqual([r["profile_name"] for r in ranked], ["default", "coder"])
        self.assertEqual(ranked[0]["project_context_additions_chars"], 0)
        self.assertGreater(ranked[1]["project_context_additions_chars"], 10000)

        # Adapt component result into §6 headline contract
        adapted_def = audit_pkg.adapt_component_result(def_ctx_env, component_id="profile_context", affected_identities=["default"])
        headline = audit_pkg.compute_headline(component_results=[adapted_def])
        self.assertEqual(headline["coverage"], "could_not_verify")
        self.assertFalse(headline["can_claim_clean"])

    def test_memory_fixtures_duplicates_age_paths_and_project_mapping(self) -> None:
        """§5, §11, §12, §13.5: Exercises `tests/fixtures/audit_profile/profile_memory_scenarios.json`."""
        fixture_data = json.loads((FIXTURES_DIR / "profile_memory_scenarios.json").read_text(encoding="utf-8"))
        entries_map = fixture_data["memory_entries"]
        as_of = int(fixture_data["as_of"])
        stale_days = int(fixture_data["stale_age_days"])

        # Set up isolated home dir on disk so `observe_memory_path_references` can verify existing vs missing paths
        home_dir = self.tmp_root / "user_home"
        existing_cfg = home_dir / "Projects" / "acme" / "billing-service" / "config.toml"
        existing_cfg.parent.mkdir(parents=True)
        existing_cfg.write_text("port = 8080\n", encoding="utf-8")

        def _mk_entry(idx: int, text: str, auth_ts: float | None = None) -> dict:
            norm_ws = " ".join(text.split())
            return {
                "index": idx,
                "text": text,
                "sha256_exact": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "sha256_normalized_ws": hashlib.sha256(norm_ws.encode("utf-8")).hexdigest(),
                "char_count": len(text),
                "authoritative_created_at": auth_ts,
            }

        mem_facts = {
            "profile_name": "default",
            "coverage": "verified",
            "files": {
                "memory": {
                    "target": "memory",
                    "path": str(home_dir / ".hermes" / "memories" / "MEMORY.md"),
                    "exists": True,
                    "enabled": True,
                    "char_limit": 2200,
                    "is_symlink": False,
                    "coverage": "verified",
                    "file_mtime_ns": 1_200_000_000_000_000_000,  # old file mtime (must never become entry age)
                    "entries": [
                        _mk_entry(0, entries_map["exact_duplicate"]),
                        _mk_entry(1, entries_map["ws_duplicate_a"]),
                        _mk_entry(2, entries_map["ws_duplicate_b"]),
                        _mk_entry(3, entries_map["mapped_exact_path"]),
                        _mk_entry(4, entries_map["ambiguous_name"]),
                        _mk_entry(5, entries_map["cross_project_directive"], auth_ts=as_of - 150 * 86400),
                        _mk_entry(6, entries_map["stale_missing_path"]),
                        _mk_entry(7, entries_map["unverified_mount_path"]),
                        _mk_entry(8, entries_map["general_preference"]),
                    ],
                },
                "user": {
                    "target": "user",
                    "path": str(home_dir / ".hermes" / "memories" / "USER.md"),
                    "exists": True,
                    "enabled": True,
                    "char_limit": 1375,
                    "is_symlink": False,
                    "coverage": "verified",
                    "file_mtime_ns": 1_200_000_000_000_000_000,
                    "entries": [
                        _mk_entry(0, entries_map["exact_duplicate"]),
                    ],
                },
            },
        }

        # Rewrite fixture canonical_paths to sit under our temporary `home_dir`
        reg_projects = []
        for p in fixture_data["registered_projects"]:
            rel_suffix = p["canonical_path"].removeprefix("/home/user/")
            reg_projects.append({
                **p,
                "canonical_path": str(home_dir / rel_suffix),
            })
        # Also rewrite the stale_missing_path entry to point inside `home_dir / "Projects"`
        stale_path_str = str(home_dir / "Projects" / "deleted-legacy-app" / "README.md")
        mem_facts["files"]["memory"]["entries"][6] = _mk_entry(
            6, f"Legacy notes live at {stale_path_str}."
        )

        from hermes_plugins.defuzz import audit as audit_pkg  # type: ignore[import-not-found]

        with sweep_forbidden_call_tripwires(allowed_write_root=None):
            path_obs = audit_pkg.facts.observe_memory_path_references(
                mem_facts,
                home_dir=home_dir,
                accessible_roots=[home_dir / "Projects"],
            )
            res = vendor_memory.audit_profile_memory(
                profile_name="default",
                memory_facts=mem_facts,
                registered_projects=reg_projects,
                as_of=as_of,
                stale_age_days=stale_days,
                home_dir=str(home_dir),
                local_identity_verified=True,
                accessible_namespace_roots=[str(home_dir / "Projects")],
                path_observations=path_obs,
            )

        finding_ids = {f["id"] for f in res["findings"]}
        self.assertIn("memory.duplicate_entry_exact", finding_ids)
        self.assertIn("memory.duplicate_entry_similar_whitespace", finding_ids)
        self.assertIn("memory.ambiguous_project_mapping", finding_ids)
        self.assertIn("memory.cross_project_exposure", finding_ids)
        self.assertIn("memory.unrelated_operational_directive", finding_ids)
        self.assertIn("memory.authoritative_entry_stale", finding_ids)
        self.assertIn("memory.stale_missing_path", finding_ids)
        self.assertIn("memory.path_reference_unverified", finding_ids)
        self.assertIn("memory.entry_age_unverified", finding_ids)

        # Verify mapping counts
        self.assertEqual(
            res["mapping_counts"],
            {
                "mapped": 2,
                "ambiguous": 1,
                "unmatched": 2,
                "general": 5,
            },
        )


if __name__ == "__main__":
    unittest.main()
