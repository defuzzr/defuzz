"""Unit and end-to-end tests for `audit/context_load.py` and `report['context_load']`."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import load_submodule


def _make_base_fixture(
    *,
    profile_name: str = "default",
    persona_tokens: int = 100,
    persona_raw_chars: int = 400,
    persona_injected_chars: int = 400,
    persona_truncated: bool = False,
    core_tokens: int = 500,
    memory_tokens: int = 100,
    memory_entries: int = 2,
    auto_skills: list[dict] | None = None,
    index_tokens: int = 200,
    listed_skill_count: int = 10,
    projects: list[dict] | None = None,
) -> dict:
    auto_skills = auto_skills or []
    auto_chars = sum(int(s.get("injected_chars", s.get("estimated_tokens", 0) * 4)) for s in auto_skills)
    auto_tokens = sum(int(s.get("estimated_tokens", (int(s.get("injected_chars", 0)) + 3) // 4)) for s in auto_skills)
    total_tokens = persona_tokens + core_tokens + memory_tokens + auto_tokens + index_tokens
    total_chars = (
        persona_injected_chars
        + core_tokens * 4
        + memory_tokens * 4
        + auto_chars
        + index_tokens * 4
    )
    return {
        "profile_name": profile_name,
        "static_profile_base": {
            "profile_name": profile_name,
            "estimator_version": "hermes-rough-bytes4-cjk1-v1",
            "components": {
                "identity_soul": {
                    "source": "SOUL.md",
                    "path": "/tmp/profile/SOUL.md",
                    "coverage": "verified",
                    "raw_chars": persona_raw_chars,
                    "characters": persona_injected_chars,
                    "utf8_bytes": persona_injected_chars,
                    "estimated_tokens": persona_tokens,
                    "truncated": persona_truncated,
                },
                "core_guidance": {
                    "coverage": "verified",
                    "characters": core_tokens * 4,
                    "utf8_bytes": core_tokens * 4,
                    "estimated_tokens": core_tokens,
                },
                "enabled_memory_files": {
                    "coverage": "verified",
                    "characters": memory_tokens * 4,
                    "utf8_bytes": memory_tokens * 4,
                    "estimated_tokens": memory_tokens,
                    "memory": {
                        "path": "/tmp/profile/memories/MEMORY.md",
                        "exists": True,
                        "enabled": True,
                        "coverage": "verified",
                        "entry_count_on_disk": memory_entries,
                        "unique_entry_count_injected": memory_entries,
                    },
                    "user": {
                        "path": "/tmp/profile/memories/USER.md",
                        "exists": False,
                        "enabled": True,
                        "coverage": "verified",
                        "entry_count_on_disk": 0,
                        "unique_entry_count_injected": 0,
                    },
                },
                "auto_loaded_skill_bodies": {
                    "coverage": "verified",
                    "characters": auto_chars,
                    "utf8_bytes": auto_chars,
                    "estimated_tokens": auto_tokens,
                    "loaded_skills": auto_skills,
                },
                "skills_index_text": {
                    "coverage": "verified",
                    "characters": index_tokens * 4,
                    "utf8_bytes": index_tokens * 4,
                    "estimated_tokens": index_tokens,
                    "listed_skill_count": listed_skill_count,
                    "zero_counted_skill_count": 0,
                },
            },
            "totals": {
                "characters": total_chars,
                "utf8_bytes": total_chars,
                "estimated_tokens": total_tokens,
                "estimator_version": "hermes-rough-bytes4-cjk1-v1",
                "is_exact": False,
            },
        },
        "project_context_additions": projects or [],
    }


def test_context_load_threshold_boundaries():
    ctx_mod = load_submodule("audit.context_load")

    # 1. Persona thresholds: <2000 none, 2000 review_suggested, 4000 warning
    _, f_below = ctx_mod.evaluate_context_load(_make_base_fixture(persona_tokens=1999, persona_injected_chars=7996))
    assert not any(f["id"] == "context_load.persona_oversized" for f in f_below)

    _, f_rev = ctx_mod.evaluate_context_load(_make_base_fixture(persona_tokens=2000, persona_injected_chars=8000))
    p_rev = next(f for f in f_rev if f["id"] == "context_load.persona_oversized")
    assert p_rev["classification"] == "review_suggested"
    assert p_rev["evidence"]["estimated_tokens"] == 2000

    _, f_warn = ctx_mod.evaluate_context_load(_make_base_fixture(persona_tokens=4000, persona_injected_chars=16000))
    p_warn = next(f for f in f_warn if f["id"] == "context_load.persona_oversized")
    assert p_warn["classification"] == "warning"
    assert p_warn["evidence"]["estimated_tokens"] == 4000

    # 2. Auto-loaded skill thresholds: <2000 none, 2000 review_suggested, 5000 warning
    _, f_sk_below = ctx_mod.evaluate_context_load(
        _make_base_fixture(auto_skills=[{"name": "s1", "skill_md_path": "/tmp/s1/SKILL.md", "injected_chars": 7996, "estimated_tokens": 1999}])
    )
    assert not any(f["id"] == "context_load.auto_loaded_skill_oversized" for f in f_sk_below)

    _, f_sk_rev = ctx_mod.evaluate_context_load(
        _make_base_fixture(auto_skills=[{"name": "s1", "skill_md_path": "/tmp/s1/SKILL.md", "injected_chars": 8000, "estimated_tokens": 2000}])
    )
    sk_rev = next(f for f in f_sk_rev if f["id"] == "context_load.auto_loaded_skill_oversized")
    assert sk_rev["classification"] == "review_suggested"
    assert sk_rev["evidence"]["skill_md_path"] == "/tmp/s1/SKILL.md"
    assert sk_rev["evidence"]["estimated_tokens"] == 2000

    _, f_sk_warn = ctx_mod.evaluate_context_load(
        _make_base_fixture(auto_skills=[{"name": "s1", "skill_md_path": "/tmp/s1/SKILL.md", "injected_chars": 20000, "estimated_tokens": 5000}])
    )
    sk_warn = next(f for f in f_sk_warn if f["id"] == "context_load.auto_loaded_skill_oversized")
    assert sk_warn["classification"] == "warning"
    assert sk_warn["evidence"]["estimated_tokens"] == 5000

    # 3. Skills index thresholds: tokens (1500 review, 4000 warning) or listed count (60 review, 150 warning)
    _, f_idx_below = ctx_mod.evaluate_context_load(_make_base_fixture(index_tokens=1499, listed_skill_count=59))
    assert not any(f["id"] == "context_load.skills_index_oversized" for f in f_idx_below)

    _, f_idx_rev_tok = ctx_mod.evaluate_context_load(_make_base_fixture(index_tokens=1500, listed_skill_count=10))
    assert next(f for f in f_idx_rev_tok if f["id"] == "context_load.skills_index_oversized")["classification"] == "review_suggested"

    _, f_idx_rev_cnt = ctx_mod.evaluate_context_load(_make_base_fixture(index_tokens=500, listed_skill_count=60))
    assert next(f for f in f_idx_rev_cnt if f["id"] == "context_load.skills_index_oversized")["classification"] == "review_suggested"

    _, f_idx_warn_tok = ctx_mod.evaluate_context_load(_make_base_fixture(index_tokens=4000, listed_skill_count=10))
    assert next(f for f in f_idx_warn_tok if f["id"] == "context_load.skills_index_oversized")["classification"] == "warning"

    _, f_idx_warn_cnt = ctx_mod.evaluate_context_load(_make_base_fixture(index_tokens=500, listed_skill_count=150))
    assert next(f for f in f_idx_warn_cnt if f["id"] == "context_load.skills_index_oversized")["classification"] == "warning"

    # 4. Memory thresholds: <1500 none, 1500 review_suggested, 3000 warning
    _, f_mem_below = ctx_mod.evaluate_context_load(_make_base_fixture(memory_tokens=1499))
    assert not any(f["id"] == "context_load.memory_oversized" for f in f_mem_below)

    _, f_mem_rev = ctx_mod.evaluate_context_load(_make_base_fixture(memory_tokens=1500))
    assert next(f for f in f_mem_rev if f["id"] == "context_load.memory_oversized")["classification"] == "review_suggested"

    _, f_mem_warn = ctx_mod.evaluate_context_load(_make_base_fixture(memory_tokens=3000))
    assert next(f for f in f_mem_warn if f["id"] == "context_load.memory_oversized")["classification"] == "warning"

    # 5. Fixed prompt thresholds: <10000 none, 10000 review_suggested, 32000 warning
    _, f_fp_below = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=9199))  # 100+9199+100+0+200 = 9599
    assert not any(f["id"] == "context_load.fixed_prompt_oversized" for f in f_fp_below)

    _, f_fp_9999 = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=9599))  # total = 9999
    assert not any(f["id"] == "context_load.fixed_prompt_oversized" for f in f_fp_9999)

    _, f_fp_rev = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=9600))  # total = 10000
    assert next(f for f in f_fp_rev if f["id"] == "context_load.fixed_prompt_oversized")["classification"] == "review_suggested"

    _, f_fp_warn = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=31600))  # total = 32000
    assert next(f for f in f_fp_warn if f["id"] == "context_load.fixed_prompt_oversized")["classification"] == "warning"

    # 6. Project context oversized, truncated, parent_context_injected
    proj_below = [{
        "project_root": "/tmp/ws/proj",
        "winning_kind": "agents_md",
        "coverage": "verified",
        "injected_chars": 9996,
        "estimated_tokens": 2499,
        "injected_files": [{
            "path": "/tmp/ws/proj/AGENTS.md",
            "kind": "agents_md",
            "raw_chars": 9996,
            "injected_chars": 9996,
            "estimated_tokens": 2499,
            "truncated": False,
        }],
        "shadowed_files": [],
    }]
    _, f_proj_below = ctx_mod.evaluate_context_load(_make_base_fixture(projects=proj_below))
    assert not any(f["id"].startswith("context_load.project_context_") or f["id"] == "context_load.parent_context_injected" for f in f_proj_below)

    proj_rev = [{
        "project_root": "/tmp/ws/proj",
        "winning_kind": "agents_md",
        "coverage": "verified",
        "injected_chars": 10000,
        "estimated_tokens": 2500,
        "injected_files": [{
            "path": "/tmp/ws/proj/AGENTS.md",
            "kind": "agents_md",
            "raw_chars": 10000,
            "injected_chars": 10000,
            "estimated_tokens": 2500,
            "truncated": False,
        }],
        "shadowed_files": [],
    }]
    _, f_proj_rev = ctx_mod.evaluate_context_load(_make_base_fixture(projects=proj_rev))
    assert next(f for f in f_proj_rev if f["id"] == "context_load.project_context_oversized")["classification"] == "review_suggested"

    proj_warn_parent_trunc = [{
        "project_root": "/tmp/ws/proj",
        "winning_kind": "agents_md",
        "coverage": "verified",
        "injected_chars": 20400,
        "estimated_tokens": 5100,
        "injected_files": [
            {
                "path": "/tmp/ws/AGENTS.md",
                "kind": "agents_md",
                "raw_chars": 400,
                "injected_chars": 400,
                "estimated_tokens": 100,
                "truncated": False,
            },
            {
                "path": "/tmp/ws/proj/AGENTS.md",
                "kind": "agents_md",
                "raw_chars": 28000,
                "injected_chars": 20000,
                "estimated_tokens": 5000,
                "truncated": True,
            },
        ],
        "shadowed_files": [{"path": "/tmp/ws/proj/CLAUDE.md", "kind": "claude_md", "raw_chars": 120}],
    }]
    sec_proj, f_proj_warn = ctx_mod.evaluate_context_load(_make_base_fixture(projects=proj_warn_parent_trunc))
    assert next(f for f in f_proj_warn if f["id"] == "context_load.project_context_oversized")["classification"] == "warning"
    trunc_f = next(f for f in f_proj_warn if f["id"] == "context_load.project_context_truncated")
    assert trunc_f["classification"] == "review_suggested"
    assert trunc_f["evidence"]["raw_chars"] == 28000
    assert trunc_f["evidence"]["injected_chars"] == 20000
    parent_f = next(f for f in f_proj_warn if f["id"] == "context_load.parent_context_injected")
    assert parent_f["classification"] == "review_suggested"
    assert parent_f["evidence"]["path"] == "/tmp/ws/AGENTS.md"
    assert parent_f["evidence"]["injected_chars"] == 400
    assert sec_proj["projects"][0]["injected_files"][0]["from_parent"] is True
    assert sec_proj["projects"][0]["injected_files"][1]["from_parent"] is False

    # 7. Per-turn window share: <8000 (25% of 32k) none, 8000 review_suggested, 32000 (25% of 128k) warning
    _, f_ws_below = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=7599))  # total = 7999
    assert not any(f["id"] == "context_load.per_turn_window_share" for f in f_ws_below)

    _, f_ws_rev = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=7600))  # total = 8000
    assert next(f for f in f_ws_rev if f["id"] == "context_load.per_turn_window_share")["classification"] == "review_suggested"

    _, f_ws_warn = ctx_mod.evaluate_context_load(_make_base_fixture(core_tokens=31600))  # total = 32000
    assert next(f for f in f_ws_warn if f["id"] == "context_load.per_turn_window_share")["classification"] == "warning"

    # 8. External memory provider
    sec_ext, f_ext = ctx_mod.evaluate_context_load(
        _make_base_fixture(),
        config={"memory": {"provider": "byterover"}},
    )
    assert sec_ext["external_memory_provider"]["configured"] is True
    assert sec_ext["external_memory_provider"]["coverage"] == "could_not_verify"
    assert sec_ext["external_memory_provider"]["measured"] is False
    assert sec_ext["external_memory_provider"]["provider"] == "byterover"
    ext_f = next(f for f in f_ext if f["id"] == "context_load.external_memory_provider_unmeasured")
    assert ext_f["classification"] == "review_suggested"
    assert ext_f["coverage"] == "could_not_verify"


def test_e2e_bloated_profile_and_privacy_and_determinism(tmp_path, monkeypatch):
    git = load_submodule("audit.outward_git")
    discover = git.discover_git_context
    monkeypatch.setattr(
        git,
        "discover_git_context",
        lambda *args, **kwargs: discover(*args, **kwargs, system_config=tmp_path / "absent-gitconfig"),
    )
    surface = load_submodule("audit_surface")

    home = tmp_path / "home" / ".hermes"
    home.mkdir(parents=True)

    soul_marker = "PRIVACY_MARKER_SOUL_991827"
    mem_marker = "PRIVACY_MARKER_MEMORY_882716"
    skill_desc_marker = "PRIVACY_MARKER_SKILL_DESC_773615"
    provider_marker = "PRIVACY_MARKER_PROVIDER_664514"

    # 17,200-char SOUL.md (> 4000 est tokens -> persona_oversized warning)
    soul_text = f"{soul_marker} " + ("Persona instructions line for agent behavior.\n" * 380)
    assert len(soul_text) > 16500
    (home / "SOUL.md").write_text(soul_text, encoding="utf-8")

    # 150 skills + 1 large auto-loaded skill (> 20,000 chars -> > 5000 est tokens -> auto_loaded_skill_oversized warning)
    skills_dir = home / "skills"
    skills_dir.mkdir()
    for i in range(150):
        sdir = skills_dir / f"skill-{i:03d}"
        sdir.mkdir()
        desc = f"{skill_desc_marker} Skill number {i:03d} for testing index bloat"
        (sdir / "SKILL.md").write_text(
            f"---\nname: skill-{i:03d}\ndescription: \"{desc}\"\n---\nSmall skill body {i}\n",
            encoding="utf-8",
        )

    auto_dir = skills_dir / "huge-auto-skill"
    auto_dir.mkdir()
    huge_body = "Auto-loaded skill detailed reference content.\n" * 600  # ~27,600 chars
    (auto_dir / "SKILL.md").write_text(
        f"---\nname: huge-auto-skill\ndescription: \"Auto loaded heavy skill\"\n---\n{huge_body}",
        encoding="utf-8",
    )

    # Large memories/MEMORY.md with entries separated by '\n§\n' (> 12,000 chars -> > 3000 est tokens -> memory_oversized warning)
    existing_mem_dir_marker = "PRIVACY_MARKER_EXISTING_DIR_554433"
    existing_mem_dir = tmp_path / existing_mem_dir_marker
    existing_mem_dir.mkdir()
    mem_dir = home / "memories"
    mem_dir.mkdir()
    mem_entries = [
        f"{mem_marker} Entry {idx} (ref {existing_mem_dir} and /etc/hostname): "
        + ("Detailed persistent note about architecture. " * 25)
        for idx in range(12)
    ]
    (mem_dir / "MEMORY.md").write_text("\n§\n".join(mem_entries), encoding="utf-8")
    (mem_dir / "USER.md").write_text("User profile entry one.", encoding="utf-8")

    # Config with auto_load and external memory provider
    (home / "config.yaml").write_text(
        f"memory:\n  provider: {provider_marker}\nskills:\n  auto_load:\n    - huge-auto-skill\n",
        encoding="utf-8",
    )

    # Workspace git root with parent AGENTS.md and child project AGENTS.md > 20,000 chars
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").mkdir()
    (workspace / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    parent_agents_text = "Parent workspace instructions that leak into child projects.\n" * 20
    (workspace / "AGENTS.md").write_text(parent_agents_text, encoding="utf-8")

    project = workspace / "bloated-project"
    project.mkdir()
    proj_agents_text = "Project specific AGENTS instructions.\n" * 700  # ~26,600 chars (> 20,000 truncation limit)
    assert len(proj_agents_text) > 20000
    (project / "AGENTS.md").write_text(proj_agents_text, encoding="utf-8")
    (project / "CLAUDE.md").write_text("Shadowed CLAUDE.md instructions.\n" * 10, encoding="utf-8")

    monkeypatch.setenv("HERMES_HOME", str(home))
    original_inventory = surface._active_inventory

    def inventory(*args):
        value = original_inventory(*args)
        value["project_units"] = [{"canonical_path": str(project), "coverage": "verified"}]
        return value

    monkeypatch.setattr(surface, "_active_inventory", inventory)

    db = tmp_path / "store" / "audit.db"
    result = surface.execute_audit({"action": "run", "root": str(project), "as_of": 1750000000}, db_path=db, wait=True)
    assert result["status"] == "completed"

    report = result["report"]
    assert "context_load" in report
    cl = report["context_load"]
    assert cl["estimator_version"] == "hermes-rough-bytes4-cjk1-v1"
    assert cl["is_exact"] is False

    # Profile breakdown checks
    prof = cl["profile"]
    assert prof["name"] == "default"
    sources_by_name = {row["source"]: row for row in prof["sources"]}
    assert set(sources_by_name.keys()) == {
        "identity_soul",
        "core_guidance",
        "enabled_memory_files",
        "auto_loaded_skill_bodies",
        "skills_index_text",
    }
    assert sources_by_name["identity_soul"]["characters"] == len(soul_text.strip())
    assert sources_by_name["identity_soul"]["estimated_tokens"] == (len(soul_text.strip()) + 3) // 4
    assert sources_by_name["auto_loaded_skill_bodies"]["characters"] > 27000
    assert prof["skill_counts"]["listed_skill_count"] == 151
    assert "listed_in_index" not in prof["skill_counts"]
    assert prof["skill_counts"]["auto_loaded_count"] == 1
    assert prof["skill_counts"]["largest_auto_loaded_injected_chars"] > 27000
    assert prof["persona"]["raw_chars"] == len(soul_text.strip())
    assert prof["persona"]["injected_chars"] == len(soul_text.strip())
    assert prof["persona"]["truncated"] is False
    assert prof["memory"]["entry_count"] == 13
    assert prof["fixed_prompt"]["characters"] == sum(r["characters"] for r in prof["sources"])
    assert prof["fixed_prompt"]["estimated_tokens"] == sum(r["estimated_tokens"] for r in prof["sources"])

    # Project context checks (head 14000 + tail 4000 + marker ~300 chars)
    assert len(cl["projects"]) == 1
    p_entry = cl["projects"][0]
    assert p_entry["project_root"] == str(project)
    assert p_entry["winning_kind"] == "agents_md"
    assert len(p_entry["injected_files"]) == 2
    by_path = {f["path"]: f for f in p_entry["injected_files"]}
    assert by_path[str(workspace / "AGENTS.md")]["from_parent"] is True
    assert by_path[str(workspace / "AGENTS.md")]["truncated"] is False
    assert by_path[str(workspace / "AGENTS.md")]["injected_chars"] == len(parent_agents_text.strip())
    assert by_path[str(project / "AGENTS.md")]["from_parent"] is False
    assert by_path[str(project / "AGENTS.md")]["truncated"] is True
    assert by_path[str(project / "AGENTS.md")]["raw_chars"] == len(proj_agents_text.strip())
    assert 18200 < by_path[str(project / "AGENTS.md")]["injected_chars"] < 18600
    assert p_entry["injected_chars"] == (
        len(parent_agents_text.strip()) + by_path[str(project / "AGENTS.md")]["injected_chars"]
    )
    assert len(p_entry["shadowed_files"]) == 1
    assert p_entry["shadowed_files"][0]["path"] == str(project / "CLAUDE.md")

    # Per-turn total, window share, resend cost, external provider, unmeasured, context_file_max_chars
    expected_per_turn_chars = prof["fixed_prompt"]["characters"] + p_entry["injected_chars"]
    expected_per_turn_tokens = prof["fixed_prompt"]["estimated_tokens"] + p_entry["estimated_tokens"]
    assert cl["per_turn_total"]["characters"] == expected_per_turn_chars
    assert cl["per_turn_total"]["estimated_tokens"] == expected_per_turn_tokens
    assert cl["window_share"]["32000"] == round(expected_per_turn_tokens / 32000, 4)
    assert cl["window_share"]["128000"] == round(expected_per_turn_tokens / 128000, 4)
    assert cl["window_share"]["200000"] == round(expected_per_turn_tokens / 200000, 4)
    assert cl["resend_cost"]["turns_10"] == expected_per_turn_tokens * 10
    assert cl["resend_cost"]["turns_50"] == expected_per_turn_tokens * 50
    assert cl["resend_cost"]["turns_100"] == expected_per_turn_tokens * 100
    assert "10" not in cl["resend_cost"]
    assert "50" not in cl["resend_cost"]
    assert "100" not in cl["resend_cost"]
    assert cl["context_file_max_chars"] == {"value": 20000, "source": "assumed_default"}
    assert cl["external_memory_provider"]["configured"] is True
    assert cl["external_memory_provider"]["coverage"] == "could_not_verify"
    assert cl["external_memory_provider"]["measured"] is False
    assert isinstance(cl["external_memory_provider"]["provider"], dict)
    assert "hmac" in cl["external_memory_provider"]["provider"]
    assert "mcp_tool_schemas" in cl["unmeasured"]
    assert "builtin_tool_schemas" in cl["unmeasured"]

    # Expected findings with numeric evidence and specific non-generic consequence text
    findings_by_id = {f["id"]: f for f in report["findings"]}
    expected_rules = {
        "context_load.persona_oversized",
        "context_load.auto_loaded_skill_oversized",
        "context_load.skills_index_oversized",
        "context_load.memory_oversized",
        "context_load.fixed_prompt_oversized",
        "context_load.project_context_oversized",
        "context_load.project_context_truncated",
        "context_load.parent_context_injected",
        "context_load.external_memory_provider_unmeasured",
        "context_load.per_turn_window_share",
    }
    assert expected_rules <= set(findings_by_id.keys())
    generic_text = "Static audit finding; review the referenced source."
    for rule_id in expected_rules:
        finding = findings_by_id[rule_id]
        assert finding["consequence"] != generic_text
        assert isinstance(finding["consequence"], str) and len(finding["consequence"]) > 20
        assert "source_digest" in finding["evidence"]

    assert findings_by_id["context_load.persona_oversized"]["evidence"]["estimated_tokens"] > 4000
    assert findings_by_id["context_load.auto_loaded_skill_oversized"]["evidence"]["skill_md_path"] == str(
        auto_dir / "SKILL.md"
    )
    assert findings_by_id["context_load.skills_index_oversized"]["evidence"]["listed_skill_count"] == 151
    assert findings_by_id["context_load.project_context_truncated"]["evidence"]["raw_chars"] == len(
        proj_agents_text.strip()
    )
    assert findings_by_id["context_load.project_context_truncated"]["coverage"] == "could_not_verify"
    assert "20,000" in findings_by_id["context_load.project_context_truncated"]["consequence"]
    assert "context window" in findings_by_id["context_load.project_context_truncated"]["consequence"]
    assert findings_by_id["context_load.parent_context_injected"]["evidence"]["path"] == str(workspace / "AGENTS.md")

    # Re-reading via action='report' returns identical report
    reread = surface.execute_audit({"action": "report", "run_id": result["run_id"]}, db_path=db)
    assert reread["report"] == report

    # Privacy check: none of the markers (including existing tmp dir path in MEMORY.md) appear in JSON report or db
    dumped_report = json.dumps(report)
    for marker in (soul_marker, mem_marker, skill_desc_marker, provider_marker, existing_mem_dir_marker):
        assert marker not in dumped_report
        for file in db.parent.rglob("*"):
            if file.is_file():
                assert marker.encode("utf-8") not in file.read_bytes()

    # Determinism check: second run with same as_of over same tree gives identical context_load
    db2 = tmp_path / "store2" / "audit.db"
    result2 = surface.execute_audit({"action": "run", "root": str(project), "as_of": 1750000000}, db_path=db2, wait=True)
    cl1_clean = dict(cl)
    cl2_clean = dict(result2["report"]["context_load"])
    # Unknown provider name uses per-run HMAC; compare everything else for exact equality
    cl1_emp = dict(cl1_clean.pop("external_memory_provider"))
    cl2_emp = dict(cl2_clean.pop("external_memory_provider"))
    cl1_emp.pop("provider", None)
    cl2_emp.pop("provider", None)
    assert cl1_clean == cl2_clean
    assert cl1_emp == cl2_emp


def test_e2e_lean_profile_and_quick_mode(tmp_path, monkeypatch):
    git = load_submodule("audit.outward_git")
    discover = git.discover_git_context
    monkeypatch.setattr(
        git,
        "discover_git_context",
        lambda *args, **kwargs: discover(*args, **kwargs, system_config=tmp_path / "absent-gitconfig"),
    )
    surface = load_submodule("audit_surface")

    home = tmp_path / "lean_home" / ".hermes"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    (home / "SOUL.md").write_text("Be direct and concise.\n", encoding="utf-8")
    (home / "memories").mkdir()
    (home / "memories" / "MEMORY.md").write_text("User uses pytest.\n", encoding="utf-8")
    (home / "skills" / "tiny-skill").mkdir(parents=True)
    (home / "skills" / "tiny-skill" / "SKILL.md").write_text(
        "---\nname: tiny-skill\ndescription: \"Tiny skill\"\n---\nShort body.\n",
        encoding="utf-8",
    )

    project = tmp_path / "lean_project"
    project.mkdir()
    (project / ".git").mkdir()
    (project / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    (project / "AGENTS.md").write_text("Run pytest before committing.\n", encoding="utf-8")

    monkeypatch.setenv("HERMES_HOME", str(home))
    original_inventory = surface._active_inventory

    def inventory(*args):
        value = original_inventory(*args)
        value["project_units"] = [{"canonical_path": str(project), "coverage": "verified"}]
        return value

    monkeypatch.setattr(surface, "_active_inventory", inventory)

    # Full mode on lean profile -> small numbers and NO context_load.* findings
    db_full = tmp_path / "store_full" / "audit.db"
    res_full = surface.execute_audit({"action": "run", "root": str(project), "as_of": 1750000000}, db_path=db_full, wait=True)
    assert res_full["status"] == "completed"
    cl = res_full["report"]["context_load"]
    assert cl["coverage"] == "verified"
    assert 0 < cl["profile"]["fixed_prompt"]["estimated_tokens"] < 3000
    assert 0 < cl["projects"][0]["estimated_tokens"] < 100
    assert cl["external_memory_provider"]["configured"] is False
    ctx_findings = [f for f in res_full["report"]["findings"] if isinstance(f["id"], str) and f["id"].startswith("context_load.")]
    assert ctx_findings == []

    # Determinism on lean profile: identical context_load across two runs
    db_full2 = tmp_path / "store_full2" / "audit.db"
    res_full2 = surface.execute_audit({"action": "run", "root": str(project), "as_of": 1750000000}, db_path=db_full2, wait=True)
    assert res_full2["report"]["context_load"] == cl

    # Quick mode -> context_load is could_not_verify, not zeros
    db_quick = tmp_path / "store_quick" / "audit.db"
    res_quick = surface.execute_audit(
        {"action": "run", "quick": True, "selected_projects": [str(project)], "as_of": 1750000000},
        db_path=db_quick,
        wait=True,
    )
    assert res_quick["status"] == "completed"
    cl_quick = res_quick["report"]["context_load"]
    assert cl_quick["coverage"] == "could_not_verify"
    assert isinstance(cl_quick["reason"], str) and cl_quick["reason"]
    assert "profile" not in cl_quick


def test_credential_policy_and_collector_failure_and_specific_dto_consequences(tmp_path, monkeypatch):
    import os
    import sys

    git = load_submodule("audit.outward_git")
    discover = git.discover_git_context
    monkeypatch.setattr(
        git,
        "discover_git_context",
        lambda *args, **kwargs: discover(*args, **kwargs, system_config=tmp_path / "absent-gitconfig"),
    )
    surface = load_submodule("audit_surface")
    pers_mod = load_submodule("audit.persistence")

    # 1. Specific finding consequences and numeric evidence in finding_dto for profile_context.* and memory.*
    f_soul = pers_mod.finding_dto({
        "id": "profile_context.soul_truncated",
        "classification": "review_suggested",
        "coverage": "verified",
        "consequence": "Raw source consequence with secret text",
        "evidence": {
            "profile": "secret_profile_name",
            "raw_chars": 25000,
            "injected_chars": 18200,
            "context_file_max_chars": 20000,
        },
    })
    assert f_soul["consequence"] == "Profile SOUL.md exceeds the character limit and is head/tail truncated in the prompt."
    assert f_soul["evidence"]["raw_chars"] == 25000
    assert f_soul["evidence"]["injected_chars"] == 18200
    assert "profile" not in f_soul["evidence"]

    f_mem = pers_mod.finding_dto({
        "id": "memory.duplicate_entry_exact",
        "classification": "warning",
        "coverage": "verified",
        "consequence": "Raw memory duplicate text",
        "evidence": {
            "profile": "secret_profile_name",
            "duplicate_count": 3,
            "selected_by_default": False,
        },
    })
    assert f_mem["consequence"] == "Profile memory contains byte-identical duplicate entries that waste prompt budget on every session."
    assert f_mem["evidence"]["duplicate_count"] == 3
    assert f_mem["evidence"]["selected_by_default"] is False
    assert "profile" not in f_mem["evidence"]

    # 2. Credential policy on project AGENTS.md: declared credential context file is never opened
    home = tmp_path / "cred_home" / ".hermes"
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("memory:\n  provider: retaindb\n", encoding="utf-8")

    project = tmp_path / "cred_project"
    project.mkdir()
    (project / ".git").mkdir()
    (project / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    protected_agents = (project / "AGENTS.md").resolve()
    protected_agents.write_text("SECRET_AGENTS_CREDENTIAL_CONTENT\n", encoding="utf-8")
    (project / "settings.json").write_text(
        json.dumps({"credential_file": str(protected_agents)}),
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_HOME", str(home))
    original_inventory = surface._active_inventory

    def inventory(*args):
        value = original_inventory(*args)
        value["project_units"] = [{"canonical_path": str(project), "coverage": "verified"}]
        return value

    monkeypatch.setattr(surface, "_active_inventory", inventory)

    opened_protected: list[str] = []
    enabled = [True]

    def hook(event, args):
        if enabled[0] and event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            p = Path(os.path.abspath(os.fsdecode(args[0])))
            if p == protected_agents:
                opened_protected.append(str(p))

    sys.addaudithook(hook)
    db_cred = tmp_path / "store_cred" / "audit.db"
    try:
        res_cred = surface.execute_audit({"action": "run", "root": str(project), "as_of": 1750000000}, db_path=db_cred, wait=True)
    finally:
        enabled[0] = False

    assert opened_protected == []
    assert res_cred["status"] == "completed"
    cl_cred = res_cred["report"]["context_load"]
    assert cl_cred["projects"][0]["coverage"] == "could_not_verify"
    assert any(f["id"] == "context_load.project_context_unverified" for f in res_cred["report"]["findings"])
    assert cl_cred["external_memory_provider"]["provider"] == "retaindb"
    assert "SECRET_AGENTS_CREDENTIAL_CONTENT" not in json.dumps(res_cred["report"])

    # 3. Collector failure degrades gracefully to could_not_verify
    monkeypatch.setattr(
        surface.context_load,
        "audit_context_load",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("SYNTHETIC_COLLECTOR_CRASH")),
    )
    db_err = tmp_path / "store_err" / "audit.db"
    res_err = surface.execute_audit({"action": "run", "root": str(project), "as_of": 1750000000}, db_path=db_err, wait=True)
    assert res_err["status"] == "completed"
    assert res_err["report"]["context_load"]["coverage"] == "could_not_verify"
    assert any(f["id"] == "context_load.unverified" for f in res_err["report"]["findings"])
    assert "SYNTHETIC_COLLECTOR_CRASH" not in json.dumps(res_err["report"])


def test_c1_i4_non_git_walk_dangling_git_and_empty_hermes_md(tmp_path):
    facts_mod = load_submodule("audit.facts")
    ctx_mod = load_submodule("audit.context_load")

    # C1a: Non-git project with AGENTS.md and .hermes.md in ancestors -> ancestors not read,
    # no parent_context_injected finding, from_parent False everywhere.
    anc = tmp_path / "non_git_anc"
    anc.mkdir()
    (anc / "AGENTS.md").write_text("ANCESTOR_AGENTS_SHOULD_NOT_BE_READ\n", encoding="utf-8")
    (anc / ".hermes.md").write_text("ANCESTOR_HERMES_SHOULD_NOT_BE_READ\n", encoding="utf-8")
    proj = anc / "nested" / "non_git_project"
    proj.mkdir(parents=True)
    (proj / "AGENTS.md").write_text("Local project instructions only.\n", encoding="utf-8")

    ctx_non_git = facts_mod.resolve_project_context_chain_facts(proj)
    assert ctx_non_git["winning_kind"] == "agents_md"
    assert [f["path"] for f in ctx_non_git["files"]] == [str(proj / "AGENTS.md")]
    sec_ng, f_ng = ctx_mod.evaluate_context_load(_make_base_fixture(projects=[ctx_non_git]))
    assert not any(f["id"] == "context_load.parent_context_injected" for f in f_ng)
    assert all(f["from_parent"] is False for p in sec_ng["projects"] for f in p["injected_files"])

    # C1b: Dangling .git symlink in ancestor is NOT treated as a git root (Hermes uses .exists(), not lexists)
    dangling_anc = tmp_path / "dangling_git_anc"
    dangling_anc.mkdir()
    (dangling_anc / ".git").symlink_to(tmp_path / "nonexistent_git_target")
    (dangling_anc / "AGENTS.md").write_text("DANGLING_ANCESTOR_AGENTS\n", encoding="utf-8")
    dangling_proj = dangling_anc / "child"
    dangling_proj.mkdir()
    (dangling_proj / "AGENTS.md").write_text("Child under dangling git symlink.\n", encoding="utf-8")

    ctx_dangling = facts_mod.resolve_project_context_chain_facts(dangling_proj)
    assert [f["path"] for f in ctx_dangling["files"]] == [str(dangling_proj / "AGENTS.md")]

    # I4: Nearest existing .hermes.md/HERMES.md stops walk even if empty, then falls back to AGENTS.md
    i4_repo = tmp_path / "i4_repo"
    i4_repo.mkdir()
    (i4_repo / ".git").mkdir()
    (i4_repo / ".hermes.md").write_text("Parent hermes instructions that should not be reached.\n", encoding="utf-8")
    i4_sub = i4_repo / "sub"
    i4_sub.mkdir()
    (i4_sub / ".hermes.md").write_text("", encoding="utf-8")
    (i4_sub / "HERMES.md").write_text("Sibling HERMES.md in same dir after empty .hermes.md.\n", encoding="utf-8")
    (i4_sub / "AGENTS.md").write_text("Fallback AGENTS instructions.\n", encoding="utf-8")

    ctx_i4 = facts_mod.resolve_project_context_chain_facts(i4_repo, cwd=i4_sub)
    assert ctx_i4["winning_kind"] == "agents_md"
    hermes_files = [f for f in ctx_i4["files"] if f["kind"] == "hermes_md"]
    assert len(hermes_files) == 1
    assert hermes_files[0]["path"] == str(i4_sub / ".hermes.md")
    assert hermes_files[0]["injected"] is False


def test_c2_memory_and_non_context_load_findings_withhold_paths(tmp_path):
    pers_mod = load_submodule("audit.persistence")
    existing_dir = tmp_path / "PRIVACY_MARKER_C2_UNIT_DIR_778899"
    existing_dir.mkdir()

    # memory.path_reference_unverified must NOT persist resolved_path or raw_path even when path exists on disk
    dto_mem = pers_mod.finding_dto({
        "id": "memory.path_reference_unverified",
        "classification": "info",
        "coverage": "could_not_verify",
        "consequence": "Memory entry references path",
        "evidence": {
            "profile": "default",
            "entry_id": "default:MEMORY.md:0",
            "raw_path": str(existing_dir),
            "resolved_path": str(existing_dir),
            "target": str(existing_dir),
            "path": str(existing_dir),
            "reason": "outside_accessible_namespace",
        },
    })
    assert "resolved_path" not in dto_mem["evidence"]
    assert "raw_path" not in dto_mem["evidence"]
    assert "target" not in dto_mem["evidence"]
    assert "path" not in dto_mem["evidence"]
    assert dto_mem["evidence"]["reason"] == "outside_accessible_namespace"
    assert "PRIVACY_MARKER_C2_UNIT_DIR_778899" not in json.dumps(dto_mem)

    # profile_context.* also withholds path keys in evidence
    dto_prof = pers_mod.finding_dto({
        "id": "profile_context.soul_unreadable",
        "classification": "info",
        "coverage": "could_not_verify",
        "consequence": "Unreadable soul",
        "evidence": {
            "profile": "default",
            "path": str(existing_dir),
        },
    })
    assert "path" not in dto_prof["evidence"]
    assert "PRIVACY_MARKER_C2_UNIT_DIR_778899" not in json.dumps(dto_prof)

    # context_load.* keeps only its own file-location keys (path, project_root, skill_md_path), never resolved_path/target
    dto_cl = pers_mod.finding_dto({
        "id": "context_load.parent_context_injected",
        "classification": "review_suggested",
        "coverage": "verified",
        "consequence": "Parent context injected",
        "evidence": {
            "path": str(existing_dir),
            "project_root": str(existing_dir),
            "resolved_path": str(existing_dir),
            "target": str(existing_dir),
            "injected_chars": 400,
        },
    })
    assert dto_cl["evidence"]["path"] == str(existing_dir)
    assert dto_cl["evidence"]["project_root"] == str(existing_dir)
    assert "resolved_path" not in dto_cl["evidence"]
    assert "target" not in dto_cl["evidence"]


def test_i1_secret_key_redaction_token_exemption_numeric_only():
    contract = load_submodule("audit.contract")

    sanitized = contract.sanitize_evidence({
        "tokens": "ghp_secret_token_value",
        "token_label": "ghp_secret_label",
        "token_metrics": {"x": "ghp_secret_nested"},
        "estimated_tokens": "ghp_secret_est",
        "exact_tokens": True,
        "threshold_tokens": ["ghp_secret_list"],
        "persona_injected_tokens": 2048,
        "memory_tokens": 512.5,
    })
    assert sanitized["tokens"] == "<redacted>"
    assert sanitized["token_label"] == "<redacted>"
    assert sanitized["token_metrics"] == "<redacted>"
    assert sanitized["estimated_tokens"] == "<redacted>"
    assert sanitized["exact_tokens"] == "<redacted>"
    assert sanitized["threshold_tokens"] == "<redacted>"
    assert sanitized["persona_injected_tokens"] == 2048
    assert sanitized["memory_tokens"] == 512.5


def test_i2_injected_chars_match_real_hermes_truncation(tmp_path):
    facts_mod = load_submodule("audit.facts")

    # 1. AGENTS chain 15k + 15k
    r_agents = tmp_path / "agents_repo"
    (r_agents / ".git").mkdir(parents=True)
    sub_agents = r_agents / "sub"
    sub_agents.mkdir()
    (r_agents / "AGENTS.md").write_text("a" * 15000, encoding="utf-8")
    (sub_agents / "AGENTS.md").write_text("b" * 15000, encoding="utf-8")
    ctx_agents = facts_mod.resolve_project_context_chain_facts(r_agents, cwd=sub_agents)
    expected_agents_marker = (
        f"\n\n[...truncated AGENTS.md (directory chain): kept 14000+4000 of 30031 chars. The middle is "
        f"omitted. Omitted sections: AGENTS.md. If you need the full instructions, read the complete file with the read_file "
        f"tool: { (sub_agents / 'AGENTS.md').resolve() }]\n\n"
    )
    assert ctx_agents["total_injected_chars"] == 18000 + len(expected_agents_marker)
    assert sum(f["injected_chars"] for f in ctx_agents["files"] if f["injected"]) == ctx_agents["total_injected_chars"]
    assert all(f["truncated"] is True for f in ctx_agents["files"] if f["injected"])

    # 2. .cursorrules 15k + .mdc 15k
    r_cursor = tmp_path / "cursor_repo"
    (r_cursor / ".cursor" / "rules").mkdir(parents=True)
    (r_cursor / ".cursorrules").write_text("a" * 15000, encoding="utf-8")
    (r_cursor / ".cursor" / "rules" / "a.mdc").write_text("b" * 15000, encoding="utf-8")
    ctx_cursor = facts_mod.resolve_project_context_chain_facts(r_cursor)
    expected_cursor_marker = (
        f"\n\n[...truncated .cursorrules: kept 14000+4000 of 30045 chars. The middle is "
        f"omitted. Omitted sections: .cursor/rules/a.mdc. If you need the full instructions, read the complete file with the read_file "
        f"tool: { (r_cursor / '.cursorrules').resolve() }]\n\n"
    )
    assert ctx_cursor["total_injected_chars"] == 18000 + len(expected_cursor_marker)
    assert sum(f["injected_chars"] for f in ctx_cursor["files"] if f["injected"]) == ctx_cursor["total_injected_chars"]
    assert all(f["truncated"] is True for f in ctx_cursor["files"] if f["injected"])

    # 3. Single 26.6k CLAUDE.md
    r_claude = tmp_path / "claude_repo"
    r_claude.mkdir()
    claude_txt = ("Project specific AGENTS instructions.\n" * 700).strip()
    (r_claude / "CLAUDE.md").write_text(claude_txt, encoding="utf-8")
    ctx_claude = facts_mod.resolve_project_context_chain_facts(r_claude)
    claude_header = '## CLAUDE.md\\n\\n'  # kept outside the f-string for Python 3.11
    expected_claude_marker = (
        f"\n\n[...truncated CLAUDE.md: kept 14000+4000 of {len(claude_txt) + len(claude_header)} chars. The middle is "
        f"omitted. If you need the full instructions, read the complete file with the read_file "
        f"tool: { (r_claude / 'CLAUDE.md').resolve() }]\n\n"
    )
    assert ctx_claude["total_injected_chars"] == 18000 + len(expected_claude_marker)
    assert ctx_claude["files"][0]["injected_chars"] == ctx_claude["total_injected_chars"]
    assert ctx_claude["files"][0]["truncated"] is True


def test_i2_crosscheck_against_hermes_prompt_builder(tmp_path):
    pb = pytest.importorskip("agent.prompt_builder")
    facts_mod = load_submodule("audit.facts")

    # 1. AGENTS chain 15k + 15k vs prompt_builder._load_agents_md
    r_agents = tmp_path / "pb_agents"
    (r_agents / ".git").mkdir(parents=True)
    sub_agents = r_agents / "sub"
    sub_agents.mkdir()
    (r_agents / "AGENTS.md").write_text("a" * 15000, encoding="utf-8")
    (sub_agents / "AGENTS.md").write_text("b" * 15000, encoding="utf-8")
    ctx_agents = facts_mod.resolve_project_context_chain_facts(r_agents, cwd=sub_agents)
    assert ctx_agents["total_injected_chars"] == len(pb._load_agents_md(sub_agents))

    # 2. .cursorrules 15k + .mdc 15k vs prompt_builder._load_cursorrules
    r_cursor = tmp_path / "pb_cursor"
    (r_cursor / ".cursor" / "rules").mkdir(parents=True)
    (r_cursor / ".cursorrules").write_text("a" * 15000, encoding="utf-8")
    (r_cursor / ".cursor" / "rules" / "a.mdc").write_text("b" * 15000, encoding="utf-8")
    ctx_cursor = facts_mod.resolve_project_context_chain_facts(r_cursor)
    assert ctx_cursor["total_injected_chars"] == len(pb._load_cursorrules(r_cursor))

    # 3. Single 26.6k CLAUDE.md vs prompt_builder._load_claude_md
    r_claude = tmp_path / "pb_claude"
    r_claude.mkdir()
    (r_claude / "CLAUDE.md").write_text("Project specific AGENTS instructions.\n" * 700, encoding="utf-8")
    ctx_claude = facts_mod.resolve_project_context_chain_facts(r_claude)
    assert ctx_claude["total_injected_chars"] == len(pb._load_claude_md(r_claude))


def test_i3_m1_m2_m3_m4_m5_semantics(tmp_path):
    ctx_mod = load_submodule("audit.context_load")
    pers_mod = load_submodule("audit.persistence")
    prof_ctx_mod = load_submodule("audit.vendor.profile_context")
    facts_mod = load_submodule("audit.facts")

    # I3: context_file_max_chars source='assumed_default' vs 'config'
    trunc_proj = [{
        "project_root": "/tmp/ws/proj",
        "winning_kind": "agents_md",
        "coverage": "verified",
        "injected_chars": 18318,
        "estimated_tokens": 4580,
        "injected_files": [{
            "path": "/tmp/ws/proj/AGENTS.md",
            "kind": "agents_md",
            "raw_chars": 26600,
            "injected_chars": 18318,
            "estimated_tokens": 4580,
            "truncated": True,
        }],
        "shadowed_files": [],
    }]
    sec_def, f_def = ctx_mod.evaluate_context_load(_make_base_fixture(projects=trunc_proj), config={})
    assert sec_def["context_file_max_chars"] == {"value": 20000, "source": "assumed_default"}
    tf_def = next(f for f in f_def if f["id"] == "context_load.project_context_truncated")
    assert tf_def["coverage"] == "could_not_verify"
    assert "context window" in tf_def["consequence"]
    assert "20,000" in tf_def["consequence"]
    dto_tf_def = pers_mod.finding_dto(tf_def)
    assert dto_tf_def["consequence"] == tf_def["consequence"]
    assert dto_tf_def["coverage"] == "could_not_verify"

    sec_cfg, f_cfg = ctx_mod.evaluate_context_load(
        _make_base_fixture(projects=trunc_proj),
        config={"context_file_max_chars": 20000},
    )
    assert sec_cfg["context_file_max_chars"] == {"value": 20000, "source": "config"}
    tf_cfg = next(f for f in f_cfg if f["id"] == "context_load.project_context_truncated")
    assert tf_cfg["coverage"] == "verified"
    assert tf_cfg["consequence"] == "A project context file exceeds the character limit and is head/tail truncated in the prompt."

    # M1: No duplicate keys in resend_cost or skill_counts
    assert set(sec_def["resend_cost"].keys()) == {
        "turns_10", "turns_50", "turns_100", "is_estimate", "ignores_prompt_caching", "note"
    }
    assert "listed_in_index" not in sec_def["profile"]["skill_counts"]
    assert "listed_skill_count" in sec_def["profile"]["skill_counts"]

    # M2: context_file_max_chars: True (bool) rejected consistently for both SOUL and projects
    limit_info = ctx_mod.resolve_context_file_max_chars({"context_file_max_chars": True})
    assert limit_info == {"value": 20000, "source": "assumed_default"}
    raw_profile_facts = {
        "name": "default",
        "path": "/tmp/prof",
        "config": {"context_file_max_chars": True},
        "soul": {"exists": True, "path": "/tmp/prof/SOUL.md", "coverage": "verified", "raw_text": "S" * 500},
        "skills": {"coverage": "verified", "skills": [], "auto_load_skill_names": []},
        "memory": {"coverage": "verified", "files": {}},
    }
    sanitized_pf = ctx_mod.sanitize_profile_facts_for_context(raw_profile_facts)
    pctx_res = prof_ctx_mod.audit_profile_context(
        profile_facts=sanitized_pf,
        context_file_max_chars=limit_info["value"],
    )
    assert pctx_res["static_profile_base"]["components"]["identity_soul"]["truncated"] is False
    assert pctx_res["static_profile_base"]["components"]["identity_soul"]["characters"] == 500
    assert not any(f["id"] == "profile_context.soul_truncated" for f in pctx_res["findings"])

    # M3: CJK-heavy auto-loaded skill uses estimate_tokens_rough-equivalent logic, not chars/4;
    # char-only skill row marks estimator_version='chars_div_4_fallback'
    cjk_body = "漢字テスト" * 450  # 2,250 chars (< 8,000 chars so chars/4 = 562 < 2000, but CJK tokens = 2,250 >= 2000)
    cjk_skill_entry = {
        "name": "cjk-skill",
        "load_name": "cjk-skill",
        "skill_md_path": "/tmp/prof/skills/cjk-skill/SKILL.md",
        "relative_path": "cjk-skill",
        "status": "unique",
        "disabled": False,
        "auto_loaded": True,
        "body_text": cjk_body,
        "body_char_count": len(cjk_body),
        "supporting_files": [],
        "coverage": "verified",
        "token_metrics": facts_mod.estimate_tokens_rough(cjk_body),
    }
    cjk_pf = {
        "name": "default",
        "path": "/tmp/prof",
        "config": {"skills": {"auto_load": ["cjk-skill"]}},
        "soul": {"exists": False, "coverage": "verified", "raw_text": ""},
        "skills": {"coverage": "verified", "skills": [cjk_skill_entry], "auto_load_skill_names": ["cjk-skill"]},
        "memory": {"coverage": "verified", "files": {}},
    }
    cjk_pctx = prof_ctx_mod.audit_profile_context(profile_facts=cjk_pf)
    cjk_cl_env = ctx_mod.audit_context_load(profile_facts=cjk_pf, profile_context_result=cjk_pctx)
    cjk_f = next(f for f in cjk_cl_env["findings"] if f["id"] == "context_load.auto_loaded_skill_oversized")
    assert cjk_f["classification"] == "review_suggested"
    assert cjk_f["evidence"]["estimated_tokens"] >= 2250
    assert cjk_f["evidence"]["estimator_version"] == "hermes-rough-bytes4-cjk1-v1"

    # Char-only skill row without text or profile_facts marks estimator_version='chars_div_4_fallback'
    _, f_char_only = ctx_mod.evaluate_context_load(
        _make_base_fixture(auto_skills=[{"name": "char-only", "skill_md_path": "/tmp/s/SKILL.md", "injected_chars": 8400}])
    )
    char_only_f = next(f for f in f_char_only if f["id"] == "context_load.auto_loaded_skill_oversized")
    assert char_only_f["evidence"]["estimated_tokens"] == 2100
    assert char_only_f["evidence"]["estimator_version"] == "chars_div_4_fallback"

    # M4: Failed project chain resolve (coverage='could_not_verify', 0 chars) emits context_load.project_context_unverified
    unv_proj = [{
        "project_root": "/tmp/ws/failed_proj",
        "cwd": "/tmp/ws/failed_proj",
        "coverage": "could_not_verify",
        "winning_kind": None,
        "total_injected_chars": 0,
        "estimated_tokens": 0,
        "files": [],
    }]
    sec_unv, f_unv = ctx_mod.evaluate_context_load(_make_base_fixture(), project_contexts=unv_proj)
    assert sec_unv["coverage"] == "could_not_verify"
    unv_f = next(f for f in f_unv if f["id"] == "context_load.project_context_unverified")
    assert unv_f["classification"] == "review_suggested"
    assert unv_f["coverage"] == "could_not_verify"
    assert unv_f["evidence"]["project_root"] == "/tmp/ws/failed_proj"
    dto_unv = pers_mod.finding_dto(unv_f)
    assert dto_unv["consequence"] == unv_f["consequence"]

    # M5: unmeasured list matches vendor profile_context dynamic_sources + builtin_tool_schemas
    assert sec_def["unmeasured"] == [
        "dynamic_plugin_prompt_sections",
        "plugin_registered_skills",
        "builtin_tool_schemas",
        "mcp_tool_schemas",
        "external_memory_provider_prefetch_and_blocks",
        "caller_ephemeral_system_message",
        "workspace_git_status_snapshot",
        "runtime_environment_metadata",
    ]


