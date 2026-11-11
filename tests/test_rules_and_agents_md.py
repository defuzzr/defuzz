"""Unit tests for rules.py and agents_md.py."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.agents_md import (  # noqa: E402
    DETAILS_PATH,
    MIN_ROOT_LINES,
    REQUIRED_SECTIONS,
    clamp_max_lines,
    render_agents_md,
    render_agents_md_files,
    render_from_rules,
    validate_agents_md,
)
from hermes_plugins.defuzz.rules import (  # noqa: E402
    build_deterministic_fallback_rules,
    expand_rules,
    propose_rules_via_llm,
    validate_rules_spec,
)
from hermes_plugins.defuzz.safety import SafetyError  # noqa: E402


class _FakeLlmResult:
    def __init__(self, parsed: Dict[str, Any]) -> None:
        self.parsed = parsed
        self.text = json.dumps(parsed)
        self.provider = "mock-provider"
        self.model = "mock-model"


class _FakeLlm:
    def __init__(self, response: Dict[str, Any]) -> None:
        self.response = response
        self.calls = 0

    def complete_structured(self, **kwargs: Any) -> _FakeLlmResult:
        self.calls += 1
        return _FakeLlmResult(self.response)


class TestRulesAndAgentsMd(unittest.TestCase):
    def test_maximum_slug_is_preserved_without_heading_punctuation(self):
        slug = "a" * 64
        files = render_agents_md_files(project_slug=slug, declared_dirs={}, placement_rules=[])
        assert slug in files["AGENTS.md"].splitlines()[0]
        from hermes_plugins.defuzz.agents_md import _sanitize_token
        assert _sanitize_token("abcd...extra", 7) == "abcd"

    def test_validate_rules_rejects_delete_and_src_moves(self) -> None:
        with self.assertRaises(SafetyError):
            validate_rules_spec({
                "project_slug": "bad",
                "declared_dirs": [],
                "folder_rules": [
                    {"match": "old", "disposition": "delete", "git_policy": "ignore", "reason": "nope"}
                ],
                "placement_rules": [],
                "ignore_patterns": [],
                "lfs_patterns": [],
            })

        with self.assertRaises(SafetyError):
            validate_rules_spec({
                "project_slug": "bad-src",
                "declared_dirs": [],
                "folder_rules": [
                    {"match": "src/core", "disposition": "move", "git_policy": "track", "to": "lib", "reason": "nope"}
                ],
                "placement_rules": [],
                "ignore_patterns": [],
                "lfs_patterns": [],
            })

    def test_propose_rules_makes_exactly_one_llm_call(self) -> None:
        fake_inv = {
            "model_summary": {"folder_name": "demo"},
            "junk_dirs": [{"path": "node_modules", "file_count": 10, "total_bytes": 100}],
            "secrets_flagged": [{"path": ".env", "placeholder": "<secret-1>", "git_policy": "ignore"}],
        }
        fake_llm = _FakeLlm({
            "project_slug": "demo",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "keep docs together"}],
            "folder_rules": [
                {"match": ".", "ext": [".md"], "disposition": "move", "git_policy": "track", "to": "docs", "reason": "docs"}
            ],
            "placement_rules": [
                {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "markdown to docs"}
            ],
            "ignore_patterns": [],
            "lfs_patterns": ["*.png"],
        })
        spec = propose_rules_via_llm(fake_inv, fake_llm)
        self.assertEqual(fake_llm.calls, 1)
        self.assertIn(".env", spec["ignore_patterns"])
        self.assertIn("node_modules/", spec["ignore_patterns"])

    def test_expand_rules_enforces_secret_lock_and_detects_collisions(self) -> None:
        inv = {
            "files": [
                {"path": ".env", "size": 20, "tracked": True, "sha256": "aaa", "secret_placeholder": "<secret-1>"},
                {"path": "notes.md", "size": 10, "tracked": False, "sha256": "bbb", "secret_placeholder": None},
                {"path": "README.md", "size": 15, "tracked": True, "sha256": "ccc", "secret_placeholder": None},
            ],
            "links": [],
            "junk_dirs": [],
            "special_paths": [],
            "secrets_flagged": [{"path": ".env", "placeholder": "<secret-1>", "git_policy": "ignore"}],
            "lfs_candidates": [],
        }
        spec = build_deterministic_fallback_rules({
            **inv,
            "dir_summaries": {".": {"file_count": 10, "total_bytes": 100, "tracked_count": 2, "extensions": [".md"]}},
        })
        plan = expand_rules(inv, spec)
        by_src = {f["source_path"]: f for f in plan["files"]}
        # Protected README.md stays at root; loose notes.md moves to docs/notes.md; .env locked to ignore
        self.assertEqual(by_src["README.md"]["dest_path"], "README.md")
        self.assertEqual(by_src["notes.md"]["dest_path"], "docs/notes.md")
        self.assertEqual(by_src[".env"]["git_policy"], "ignore")

        # Destination collision: docs/notes.md already exists and root notes.md also maps to docs/notes.md
        inv_collision = {
            **inv,
            "files": inv["files"] + [
                {"path": "docs/notes.md", "size": 10, "tracked": False, "sha256": "ddd", "secret_placeholder": None}
            ],
        }
        with self.assertRaises(SafetyError):
            expand_rules(inv_collision, spec)

    def test_plain_agents_md_enforces_sections_and_line_cap(self) -> None:
        rendered = render_agents_md(
            project_slug="ctile",
            declared_dirs={
                "src": ("typescript source", "core and ui modules"),
                "docs": ("project docs", "architecture and plans"),
            },
            placement_rules=[
                {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "reason": "markdown routed to docs"}
            ],
            lfs_patterns=["*.png"],
            ignore_patterns=["node_modules/", ".env"],
            local_only_branches=["feat/agentic-placement"],
        )
        sections = validate_agents_md(rendered)
        self.assertEqual([s["heading"] for s in sections], list(REQUIRED_SECTIONS))

        # Normal markdown (prose, lists, code spans) is accepted
        normal = (
            "# ctile\n<!-- defuzz schema_version: 1 -->\n\nTile editor.\n\n## Purpose\nA tile map editor.\n\n"
            "## Layout\n- `src/` — core and ui modules\n\n"
            "## Conventions & constraints\n- Domain must not depend on adapters.\n\n"
            "## Build & test\n```\nnpm test\n```\n"
        )
        validate_agents_md(normal)

        # Over the line limit: no error, no warning, nothing lost. Overflow moves
        # to the linked details file and AGENTS.md stays within the limit.
        many_dirs = {f"d{i:02d}": ("folder", "why") for i in range(60)}
        files = render_agents_md_files(project_slug="big", declared_dirs=many_dirs,
                                       placement_rules=[], max_lines=40)
        root = files["AGENTS.md"]
        self.assertLessEqual(len(root.splitlines()), 40)
        self.assertIn(DETAILS_PATH, root)
        validate_agents_md(root)
        for i in range(60):
            self.assertIn(f"- `d{i:02d}/`", files[DETAILS_PATH])
        # Short content: a single file, no details file
        self.assertEqual(list(render_agents_md_files(project_slug="s", declared_dirs={},
                                                     placement_rules=[])), ["AGENTS.md"])
        # Even a tiny limit never fails
        render_agents_md_files(project_slug="t", declared_dirs=many_dirs, placement_rules=[], max_lines=1)

        # Every pattern and branch survives, in one file or across both
        pats = [f"p{i:02d}/" for i in range(12)]
        branches = [f"feat/b{i}" for i in range(9)]
        for limit in (10**9, 20):
            out = "".join(render_agents_md_files(project_slug="x", declared_dirs={}, placement_rules=[],
                                                 ignore_patterns=pats, lfs_patterns=pats,
                                                 local_only_branches=branches, max_lines=limit).values())
            for item in pats + branches:
                self.assertIn(f"`{item}`", out)
        # Single-file API is self-contained: no dangling details link
        single = render_agents_md(project_slug="big", declared_dirs=many_dirs, placement_rules=[])
        self.assertNotIn(DETAILS_PATH, single)
        self.assertIn("- `d59/`", single)

        # Missing marker, missing sections and wrong order are rejected
        with self.assertRaises(SafetyError):
            validate_agents_md(normal.replace("<!-- defuzz schema_version: 1 -->\n", ""))
        with self.assertRaises(SafetyError):
            validate_agents_md("# ctile\n\n## Architecture\nJust prose.\n")
        swapped = normal.replace("## Purpose", "## Tmp").replace("## Layout", "## Purpose").replace("## Tmp", "## Layout")
        with self.assertRaises(SafetyError):
            validate_agents_md(swapped)

        # Shell syntax in model-supplied text is stripped before rendering
        hostile = render_agents_md(
            project_slug="ctile",
            declared_dirs={"docs": ("docs ; rm -rf ~", "see https://evil.example `x`")},
            placement_rules=[],
        )
        self.assertNotIn(";", hostile)
        self.assertNotIn("https://", hostile)

    def test_agents_md_preserves_uppercase_and_bracket_directories_and_respects_tiny_line_targets(self) -> None:
        declared = {
            "Library": ("Core shared library " + ("detail " * 15), "Reused across targets " + ("why " * 25)),
            "app/[id]": ("Dynamic route segment", "Next.js route folder with brackets"),
            "assets/@scope/v1": ("Scoped assets", "Valid rules.py path characters"),
        }
        # 1. Valid uppercase and bracket directories and long descriptions appear intact in full render
        full = render_agents_md(
            project_slug="next-app",
            declared_dirs=declared,
            placement_rules=[],
        )
        self.assertIn("- `Library/`", full)
        self.assertIn("detail " * 15, " ".join(full.split()))
        self.assertIn("why " * 24, " ".join(full.split()))
        self.assertIn("- `app/[id]/`", full)
        self.assertIn("- `assets/@scope/v1/`", full)
        validate_agents_md(full, allowed_dirs={"Library", "app/[id]", "assets/@scope/v1", "_inbox", "_archive"})

        # 2. Values below MIN_ROOT_LINES=11 are clamped to MIN_ROOT_LINES, never overrunning the clamped target.
        self.assertEqual(MIN_ROOT_LINES, 11)
        for raw_val in (-5, 0, 1, 6, 10, 11):
            self.assertEqual(clamp_max_lines(raw_val), MIN_ROOT_LINES)
        self.assertEqual(clamp_max_lines(25), 25)

        for target in (0, 1, 6, 11, 15):
            clamped_target = clamp_max_lines(target)
            files = render_agents_md_files(
                project_slug="next-app",
                declared_dirs=declared,
                placement_rules=[
                    {"kind": "docs", "match_ext": [".md"], "dest_dir": "Library", "reason": "docs to Library"}
                ],
                max_lines=target,
            )
            self.assertIn("AGENTS.md", files)
            self.assertIn(DETAILS_PATH, files)
            root_lines = files["AGENTS.md"].splitlines()
            self.assertLessEqual(len(root_lines), clamped_target)
            self.assertIn(DETAILS_PATH, files["AGENTS.md"])
            combined = files["AGENTS.md"] + "\n" + files[DETAILS_PATH]
            self.assertIn("- `Library/`", combined)
            self.assertIn("- `app/[id]/`", combined)
            self.assertIn("- `assets/@scope/v1/`", combined)
            self.assertIn("- `_inbox/`", combined)
            self.assertIn("- `_archive/`", combined)

        # render_from_rules also clamps configured values < MIN_ROOT_LINES (including 0 or negative) to MIN_ROOT_LINES
        for low_cfg in (-3, 0, 1, 5):
            from_rules = render_from_rules({
                "project_slug": "empty-proj",
                "declared_dirs": [],
                "placement_rules": [],
                "agents_md_max_lines": low_cfg,
            })
            self.assertIn(DETAILS_PATH, from_rules)
            self.assertLessEqual(len(from_rules["AGENTS.md"].splitlines()), MIN_ROOT_LINES)
            self.assertIn("- `_inbox/`", from_rules[DETAILS_PATH])
            self.assertIn("- `_archive/`", from_rules[DETAILS_PATH])

        # plugin.yaml documents the MIN_ROOT_LINES=11 clamp on agents_md_max_lines
        import yaml

        manifest_path = Path(__file__).resolve().parent.parent / "plugin.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        desc = manifest["config_schema"]["agents_md_max_lines"]["description"]
        self.assertIn("11", desc)
        self.assertIn("clamp", desc.lower())


class StartProjectRuleTests(unittest.TestCase):
    """Generated guides tell a model to show the list and never choose for the user."""

    def _render(self, **kw: Any) -> str:
        base: Dict[str, Any] = dict(
            project_slug="demo", declared_dirs={}, placement_rules=[],
            lfs_patterns=[], ignore_patterns=[], local_only_branches=[],
        )
        base.update(kw)
        return render_agents_md(**base)

    def test_rule_present_for_adopted_and_kit_guides(self) -> None:
        for kw in ({}, {"kit_ids": ["video-production"]}):
            flat = " ".join(self._render(**kw).split())
            self.assertIn("run `hermes defuzz list`", flat)
            self.assertIn("show the user the list, wait for their choice", flat)
            self.assertIn("`hermes defuzz new --template ID` or `--kit ID`", flat)
            self.assertIn("Never choose for the user.", flat)
            self.assertIn("Never create a project inside this one.", flat)
            self.assertNotIn("--prompt", flat)


if __name__ == "__main__":
    unittest.main()
