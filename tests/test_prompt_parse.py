"""Unit tests for prompt_parse.py (deterministic free-text parsing, editable chips)."""

from __future__ import annotations

import unittest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # type: ignore[import-not-found]  # noqa: E402
    KitInfo,
    best_matches,
    choose_catalog_entry,
    match_kits,
)
from hermes_plugins.defuzz.naming import PrefixForms  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.prompt_parse import (  # type: ignore[import-not-found]  # noqa: E402
    Chip,
    ParsedPrompt,
    PromptChip,
    apply_chip_edit,
    build_chips,
    explicit_code_from,
    format_chips,
    merge_parsed_answers,
    parse_deterministic,
    parse_prompt,
)
from hermes_plugins.defuzz.questionnaire import next_question  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # type: ignore[import-not-found]  # noqa: E402
from tests.fake_kit_bridge import load_list_fixture  # noqa: E402


class TestPromptParse(unittest.TestCase):
    def test_deterministic_invoice_tracker_api_typescript_example(self) -> None:
        res = parse_prompt("Invoice tracker API for my shop — TypeScript")
        self.assertIsInstance(res, ParsedPrompt)
        self.assertFalse(res.ambiguous)
        self.assertFalse(res.used_llm)
        self.assertEqual(res.source, "deterministic")

        self.assertEqual(res.name, "Invoice Tracker")
        self.assertEqual(res.slug, "invoice-tracker")
        self.assertEqual(res.prefix, "invoice_tracker")
        self.assertEqual(res.env, "INVOICE_TRACKER_*")
        self.assertEqual(res.env_prefix, "INVOICE_TRACKER_*")
        self.assertEqual(
            res.forms,
            PrefixForms(
                kebab="invoice-tracker",
                snake="invoice_tracker",
                screaming="INVOICE_TRACKER",
                pascal="InvoiceTracker",
            ),
        )
        self.assertEqual(
            res.answers,
            {
                "building": "service",
                "layout": "mono",
                "languages": ["typescript"],
            },
        )
        self.assertIsNone(next_question(res.answers))

        # Stage-1 editable chips match design: service · typescript · "Invoice Tracker"
        self.assertEqual(res.chips_text, 'service · typescript · "Invoice Tracker"')
        self.assertEqual(format_chips(res), 'service · typescript · "Invoice Tracker"')
        self.assertEqual(len(res.chips), 3)
        self.assertEqual(res.chips[0].id, "building")
        self.assertEqual(res.chips[0].value, "service")
        self.assertEqual(res.chips[0].label, "service")
        self.assertTrue(res.chips[0].editable)
        self.assertEqual(res.chips[1].id, "languages")
        self.assertEqual(res.chips[1].value, "typescript")
        self.assertEqual(res.chips[1].label, "typescript")
        self.assertTrue(res.chips[1].editable)
        self.assertEqual(res.chips[2].id, "name")
        self.assertEqual(res.chips[2].value, "Invoice Tracker")
        self.assertEqual(res.chips[2].label, '"Invoice Tracker"')
        self.assertTrue(res.chips[2].editable)

        # Dict-like access works on both ParsedPrompt and PromptChip
        self.assertEqual(res["name"], "Invoice Tracker")
        self.assertEqual(res["slug"], "invoice-tracker")
        self.assertEqual(res["chips"][0]["value"], "service")
        self.assertEqual(res.chips[0]["label"], "service")

    def test_deterministic_parse_across_building_kinds_and_languages(self) -> None:
        cases = [
            (
                "Rust CLI tool for log scrubbing",
                "tool",
                "mono",
                ["rust"],
                None,
                "Log Scrubbing",
                "log-scrubbing",
            ),
            (
                "Bevy game called Star Cruiser",
                "game",
                "mono",
                ["rust"],
                "bevy",
                "Star Cruiser",
                "star-cruiser",
            ),
            (
                "Python library for rate limiting",
                "library",
                "mono",
                ["python"],
                None,
                "Rate Limiting",
                "rate-limiting",
            ),
            (
                "Budget planner web app in TypeScript",
                "app",
                "mono",
                ["typescript"],
                None,
                "Budget Planner",
                "budget-planner",
            ),
            (
                "Poly-repo game studio in Godot — Pixel Forge",
                "studio",
                "poly",
                ["gdscript"],
                "godot",
                "Pixel Forge",
                "pixel-forge",
            ),
        ]
        for sentence, exp_b, exp_layout, exp_langs, exp_eng, exp_name, exp_slug in cases:
            with self.subTest(sentence=sentence):
                res = parse_deterministic(sentence)
                self.assertFalse(res.ambiguous, f"Expected unambiguous for {sentence!r}")
                self.assertEqual(res.answers["building"], exp_b)
                self.assertEqual(res.answers["layout"], exp_layout)
                self.assertEqual(res.answers["languages"], exp_langs)
                self.assertEqual(res.answers.get("engine"), exp_eng)
                self.assertEqual(res.name, exp_name)
                self.assertEqual(res.slug, exp_slug)

    def test_ambiguous_prompt_parses_without_a_model(self) -> None:
        res_no_llm = parse_prompt("Mystery project")
        self.assertTrue(res_no_llm.ambiguous)
        self.assertFalse(res_no_llm.used_llm)
        self.assertEqual(res_no_llm.name, "Mystery")
        self.assertEqual(res_no_llm.slug, "mystery")
        self.assertTrue(len(res_no_llm.chips) >= 3)

    def test_editable_chips_recompute_answers_and_naming_forms(self) -> None:
        res = parse_prompt("Invoice tracker API for my shop — TypeScript")
        # Edit language chip from typescript -> python
        edited_lang = res.with_edit("languages", ["python"])
        self.assertEqual(edited_lang.answers["languages"], ["python"])
        self.assertEqual(edited_lang.chips_text, 'service · python · "Invoice Tracker"')

        # Edit building chip from service -> tool
        edited_kind = apply_chip_edit(edited_lang, "building", "tool")
        self.assertEqual(edited_kind.answers["building"], "tool")
        self.assertEqual(edited_kind.chips_text, 'tool · python · "Invoice Tracker"')

        # Edit name chip -> recomputes slug, prefix, env via naming.py
        edited_name = edited_kind.with_edit("name", "Shop Ledger")
        self.assertEqual(edited_name.name, "Shop Ledger")
        self.assertEqual(edited_name.slug, "shop-ledger")
        self.assertEqual(edited_name.prefix, "shop_ledger")
        self.assertEqual(edited_name.env, "SHOP_LEDGER_*")
        self.assertEqual(edited_name.chips_text, 'tool · python · "Shop Ledger"')

        with self.assertRaises(ValueError):
            edited_name.with_edit("building", "not_a_kind")
        with self.assertRaises(ValueError):
            edited_name.with_edit("unknown_field", "val")

    def test_deterministic_kit_kinds_video_images_assets_and_precedence(self) -> None:
        # 1. 'set up a video production project' -> building 'video', no languages, not ambiguous, name without 'Set Up'
        res_setup = parse_deterministic("set up a video production project")
        self.assertEqual(res_setup.answers, {"building": "video"})
        self.assertNotIn("languages", res_setup.answers)
        self.assertNotIn("layout", res_setup.answers)
        self.assertNotIn("engine", res_setup.answers)
        self.assertFalse(res_setup.ambiguous)
        self.assertFalse(res_setup.name.lower().startswith("set up"))
        self.assertNotIn("set up", res_setup.name.lower())
        self.assertEqual([c.id for c in res_setup.chips], ["building", "name"])
        self.assertEqual(res_setup.chips[0].value, "video")

        # 2. 'storyboard for a short film' -> video
        res_film = parse_deterministic("storyboard for a short film")
        self.assertEqual(res_film.answers, {"building": "video"})
        self.assertFalse(res_film.ambiguous)
        self.assertEqual([c.id for c in res_film.chips], ["building", "name"])

        # 3. 'concept art illustration pack' -> images
        res_images = parse_deterministic("concept art illustration pack")
        self.assertEqual(res_images.answers, {"building": "images"})
        self.assertFalse(res_images.ambiguous)
        self.assertEqual([c.id for c in res_images.chips], ["building", "name"])

        # 4. 'blender and houdini 3d asset library' -> assets
        res_assets = parse_deterministic("blender and houdini 3d asset library")
        self.assertEqual(res_assets.answers, {"building": "assets"})
        self.assertFalse(res_assets.ambiguous)
        self.assertEqual([c.id for c in res_assets.chips], ["building", "name"])

        # Additional phrase coverage across video, images, assets
        phrase_cases = [
            ("music video trailer for Neon Dreams", "video"),
            ("vfx shots and animatic footage for Orbit", "video"),
            ("tv commercial animation movie called Sunburst", "video"),
            ("image set and photo set for Summer Zine", "images"),
            ("comic poster artwork pack for Cyber City", "images"),
            ("kitbash model library and asset pack for Mechs", "assets"),
            ("3d assets and blender models for Dungeon Props", "assets"),
            ("houdini assets for terrain generation", "assets"),
        ]
        for phrase, expected_kind in phrase_cases:
            with self.subTest(phrase=phrase):
                parsed = parse_deterministic(phrase)
                self.assertEqual(parsed.answers, {"building": expected_kind})
                self.assertFalse(parsed.ambiguous)
                self.assertEqual([c.id for c in parsed.chips], ["building", "name"])

        # 5. Precedence: 'make a video game in rust with bevy' -> game with rust (unchanged)
        res_game = parse_deterministic("make a video game in rust with bevy")
        self.assertEqual(res_game.answers["building"], "game")
        self.assertEqual(res_game.answers["languages"], ["rust"])
        self.assertEqual(res_game.answers["engine"], "bevy")
        self.assertEqual(res_game.answers["layout"], "mono")

        # 6. 'python backend service' -> service with python (unchanged)
        res_service = parse_deterministic("python backend service")
        self.assertEqual(res_service.answers["building"], "service")
        self.assertEqual(res_service.answers["languages"], ["python"])
        self.assertEqual(res_service.answers["layout"], "mono")

    def test_chip_edits_support_kit_kinds(self) -> None:
        # Editing a code project to a kit kind drops language/layout/engine
        code_res = parse_deterministic("Invoice tracker API for my shop — TypeScript")
        as_kit = code_res.with_edit("building", "images")
        self.assertEqual(as_kit.answers, {"building": "images"})
        self.assertEqual(as_kit.chips_text, 'images · "Invoice Tracker"')

    def test_code_signals_beat_kit_kinds(self) -> None:
        code_with_lang_cases = [
            ("video player library in rust", "library", "rust"),
            ("image processing service in python", "service", "python"),
            ("photo gallery app in typescript", "app", "typescript"),
            ("asset pack loader library in rust", "library", "rust"),
            ("make a video game in rust with bevy", "game", "rust"),
        ]
        for sentence, exp_building, exp_lang in code_with_lang_cases:
            with self.subTest(sentence=sentence):
                res = parse_deterministic(sentence)
                self.assertEqual(res.answers["building"], exp_building)
                self.assertIn(exp_lang, res.answers["languages"])

        code_building_cases = [
            ("comic reader app", "app"),
            ("movie database backend service", "service"),
            ("animation library for react", "library"),
            ("poster generator web app", "app"),
            ("a commercial saas app", "app"),
            ("a web app for streaming video", "app"),
            ("a cli tool to resize images", "tool"),
        ]
        for sentence, exp_building in code_building_cases:
            with self.subTest(sentence=sentence):
                res = parse_deterministic(sentence)
                self.assertEqual(res.answers["building"], exp_building)

        # 'film festival website' -> NOT a kit kind (matches parent commit's 'other')
        res_website = parse_deterministic("film festival website")
        self.assertNotIn(res_website.answers["building"], {"video", "images", "assets"})
        self.assertEqual(res_website.answers["building"], "other")

        kit_cases = [
            ("set up a video production project", "video"),
            ("new video project", "video"),
            ("youtube video series", "video"),
            ("storyboard for a short film", "video"),
            ("a set of product photos", "images"),
            ("character concept art", "images"),
            ("concept art illustration pack", "images"),
            ("blender and houdini 3d asset library", "assets"),
            ("kitbashing a 3d asset pack", "assets"),
            ("kitbashed models for a sci-fi asset pack", "assets"),
            ("tv commercial for a shoe brand", "video"),
            ("commercial spot for a coffee brand", "video"),
            ("commercial shoot for summer campaign", "video"),
            ("ad spot for a local bakery", "video"),
        ]
        for sentence, exp_kit in kit_cases:
            with self.subTest(sentence=sentence):
                res = parse_deterministic(sentence)
                self.assertEqual(res.answers["building"], exp_kit)
                self.assertEqual(res.answers, {"building": exp_kit})

    def test_two_kit_kinds_stay_ambiguous(self) -> None:
        det_kit = parse_deterministic("video and concept art")
        self.assertEqual(det_kit.answers, {"building": "video"})
        self.assertTrue(det_kit.ambiguous)

    def test_parse_prompt_takes_no_model(self) -> None:
        for name in ("llm", "ctx"):
            with self.subTest(name=name):
                with self.assertRaises(TypeError):
                    parse_prompt("Mystery project", **{name: None})
        self.assertEqual(parse_prompt("Mystery project"), parse_deterministic("Mystery project"))

    def test_leading_filler_requires_article_no_bare_verb_stripping(self) -> None:
        res_setup = parse_deterministic("set up a video production project")
        self.assertNotIn("set up", res_setup.name.lower())
        self.assertEqual(res_setup.name, "Video Production")

        res_waves = parse_deterministic('rust cli tool called "Make Waves"')
        self.assertEqual(res_waves.name, "Make Waves")

        res_shop = parse_deterministic('typescript web app called "Set Up Shop"')
        self.assertEqual(res_shop.name, "Set Up Shop")

        res_start = parse_deterministic("Start Page web app in typescript")
        self.assertEqual(res_start.name, "Start Page")

    def test_parent_commit_regression_guard_answers(self) -> None:
        cases = [
            (
                "python backend service",
                {
                    "building": "service",
                    "layout": "mono",
                    "languages": ["python"],
                },
            ),
            (
                "a rust cli tool",
                {
                    "building": "tool",
                    "layout": "mono",
                    "languages": ["rust"],
                },
            ),
            (
                "typescript web app with a mono repo",
                {
                    "building": "app",
                    "layout": "mono",
                    "languages": ["typescript"],
                },
            ),
            (
                "godot game in gdscript",
                {
                    "building": "game",
                    "layout": "mono",
                    "languages": ["gdscript"],
                    "engine": "godot",
                },
            ),
            (
                "a studio of several games in rust",
                {
                    "building": "studio",
                    "layout": "poly",
                    "languages": ["rust"],
                    "engine": "bevy",
                },
            ),
        ]
        for prompt, expected_answers in cases:
            with self.subTest(prompt=prompt):
                res = parse_deterministic(prompt)
                self.assertEqual(res.answers, expected_answers)

    def test_explicit_code_distinguishes_named_language_or_framework_from_prefill(self) -> None:
        # Unnamed language -> languages is ['other'], explicit_code is False
        res_prefill = parse_deterministic("home server infrastructure with network rules and runbooks")
        self.assertEqual(res_prefill.answers["building"], "service")
        self.assertEqual(res_prefill.answers["languages"], ["other"])
        self.assertFalse(res_prefill.explicit_code)
        self.assertFalse(res_prefill["explicit_code"])

        # Explicitly named language -> explicit_code is True
        res_py = parse_deterministic("python backend service")
        self.assertTrue(res_py.explicit_code)

        # Implied framework (react) -> language is typescript, explicit_code is False so strong kits/websites win
        res_react = parse_deterministic("react component library")
        self.assertFalse(res_react.explicit_code)
        self.assertEqual(res_react.answers["languages"], ["typescript"])

        # explicit_code_from combines parsed.explicit_code and caller-supplied answers['languages']
        self.assertFalse(explicit_code_from(res_prefill, None))
        self.assertFalse(explicit_code_from(res_prefill, {"building": "tool"}))
        self.assertTrue(explicit_code_from(res_prefill, {"building": "tool", "languages": ["python"]}))
        self.assertTrue(explicit_code_from(None, {"languages": "python"}))
        self.assertFalse(explicit_code_from(None, {"languages": "  "}))
        self.assertFalse(explicit_code_from(None, {"languages": []}))
        self.assertTrue(explicit_code_from(res_prefill, {"languages": ("rust",)}))
        self.assertTrue(explicit_code_from(res_py, None))
        self.assertTrue(explicit_code_from(None, {"languages": ["python"]}))
        self.assertFalse(explicit_code_from(None, {"languages": []}))
        self.assertFalse(explicit_code_from(None, {"languages": ["  "]}))
        self.assertFalse(explicit_code_from(None, {"languages": [123]}))
        self.assertFalse(explicit_code_from(res_prefill, {"languages": ["other"]}))
        self.assertFalse(explicit_code_from(None, {"languages": ["other"]}))
        self.assertFalse(explicit_code_from(None, {"languages": "other"}))
        self.assertTrue(explicit_code_from(None, {"languages": ["other", "python"]}))

        # merge_parsed_answers treats caller languages == ['other'] as absent when the prompt named a language
        merged_named = merge_parsed_answers(res_py, {"languages": ["other"]})
        self.assertEqual(merged_named["languages"], ["python"])
        merged_named_str = merge_parsed_answers(res_py, {"languages": "other"})
        self.assertEqual(merged_named_str["languages"], ["python"])

        # When the prompt named no language, caller languages == ['other'] is preserved unchanged
        merged_unnamed = merge_parsed_answers(res_prefill, {"languages": ["other"]})
        self.assertEqual(merged_unnamed["languages"], ["other"])

    def test_three_js_not_language_and_multi_tool_not_tool_building(self) -> None:
        res_studio_three = parse_deterministic(
            "multi-tool 3d studio workspace with blender and three.js"
        )
        self.assertEqual(res_studio_three.answers["building"], "studio")
        self.assertFalse(res_studio_three.explicit_code)
        self.assertNotIn("typescript", res_studio_three.answers["languages"])

        res_three_only = parse_deterministic("blender houdini and three.js 3d studio")
        self.assertEqual(res_three_only.answers["building"], "studio")
        self.assertFalse(res_three_only.explicit_code)

        res_multi_tool = parse_deterministic("multi-tool 3d design studio workspace")
        self.assertEqual(res_multi_tool.answers["building"], "studio")

        # Ordinary node.js / js and tool mentions still work
        res_node = parse_deterministic("node.js cli tool")
        self.assertEqual(res_node.answers["building"], "tool")
        self.assertEqual(res_node.answers["languages"], ["typescript"])
        self.assertTrue(res_node.explicit_code)

    def test_game_plus_explicit_code_kind_without_engine_uses_code_kind(self) -> None:
        res_cpp = parse_deterministic("game asset checksum cli tool in c++")
        self.assertEqual(res_cpp.answers["building"], "tool")
        self.assertEqual(res_cpp.answers["languages"], ["cpp"])
        self.assertNotIn("engine", res_cpp.answers)

        templates = load_templates()
        kits = [k for raw in load_list_fixture()["kits"] if (k := KitInfo.from_dict(raw)) is not None]
        t_matches = best_matches(templates, res_cpp.answers)
        k_matches = match_kits(kits, "game asset checksum cli tool in c++", res_cpp.answers)
        cat, chosen = choose_catalog_entry(
            t_matches, k_matches, res_cpp.answers, explicit_code=res_cpp.explicit_code
        )
        self.assertEqual(cat, "template")
        self.assertEqual(chosen.template.id, "cpp-golden")

        for sentence, exp_kind, exp_lang in (
            ("game save parser library in rust", "library", "rust"),
            ("game matchmaking backend service in go", "service", "go"),
            ("game leaderboard api in python", "service", "python"),
            ("game analytics sdk in typescript", "library", "typescript"),
        ):
            with self.subTest(sentence=sentence):
                parsed = parse_deterministic(sentence)
                self.assertEqual(parsed.answers["building"], exp_kind)
                self.assertEqual(parsed.answers["languages"], [exp_lang])
                self.assertNotIn("engine", parsed.answers)

        # Requests with a game engine remain 'game'
        res_bevy = parse_deterministic("make a rust bevy game")
        self.assertEqual(res_bevy.answers["building"], "game")
        self.assertEqual(res_bevy.answers["languages"], ["rust"])
        self.assertEqual(res_bevy.answers["engine"], "bevy")

        res_godot = parse_deterministic("godot game called Hop")
        self.assertEqual(res_godot.answers["building"], "game")
        self.assertEqual(res_godot.answers["languages"], ["gdscript"])
        self.assertEqual(res_godot.answers["engine"], "godot")
        self.assertEqual(res_godot.name, "Hop")

    def test_non_scaffolding_openers_set_not_a_project_request(self) -> None:
        non_project_sentences = (
            "summarize this video",
            "write a poem about servers",
            "what is a lora",
            "draft an email to my client about the invoice",
            "compare blender and houdini for vfx",
            "list the top ten indie games of the year",
            "rename my photos",
        )
        for sentence in non_project_sentences:
            with self.subTest(sentence=sentence):
                res = parse_deterministic(sentence)
                self.assertTrue(res.not_a_project_request)
                self.assertTrue(res["not_a_project_request"])

        project_sentences = (
            "review tool for pull requests in go",
            "set up a code review tool for pull requests in go",
            "rust cli tool to rename photos and summarize logs",
            "python service to translate documents and compare versions",
        )
        for sentence in project_sentences:
            with self.subTest(sentence=sentence):
                res = parse_deterministic(sentence)
                self.assertFalse(res.not_a_project_request)
                self.assertFalse(res["not_a_project_request"])


if __name__ == "__main__":
    unittest.main()
