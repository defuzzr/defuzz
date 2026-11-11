"""Unit tests for project kit matching and catalog entry selection in matcher.py."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # type: ignore[import-not-found]  # noqa: E402
    _BUILDING_KIT_TAGS,
    KitInfo,
    KitMatch,
    best_matches,
    choose_catalog_entry,
    match_kits,
)
from hermes_plugins.defuzz.prompt_parse import parse_deterministic  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.questionnaire import KIT_BUILDING_KINDS  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # type: ignore[import-not-found]  # noqa: E402
from tests.fake_kit_bridge import load_list_fixture  # noqa: E402


def _sample_kits() -> list[KitInfo]:
    raw = [
        {
            "id": "video-production",
            "name": "Video production",
            "summary": (
                "AI-assisted video or storyboard production: locked canon references, "
                "generated candidates, approved assets, footage, renders and numbered deliverables."
            ),
            "tags": ["video", "storyboard", "image", "production", "generative", "lfs"],
            "version": 1,
        },
        {
            "id": "game-assets",
            "name": "Game workspace: Unreal + Blender + Houdini",
            "summary": "Game workspace with one folder per source asset and Git LFS rules.",
            "tags": ["game", "unreal", "ue5", "blender", "houdini", "assets", "lfs"],
            "version": 1,
        },
        {
            "id": "component-library",
            "name": "Component library",
            "summary": "One folder of reusable Python components, their index, thin runners and componentize specs.",
            "tags": ["python", "components", "reuse", "componentize"],
            "version": 1,
        },
    ]
    out: list[KitInfo] = []
    for entry in raw:
        kit = KitInfo.from_dict(entry)
        assert kit is not None
        out.append(kit)
    return out


class TestKitMatching(unittest.TestCase):
    def setUp(self) -> None:
        self.kits = _sample_kits()

    def test_kit_info_from_dict_valid_and_frozen(self) -> None:
        raw = {
            "id": "video-production",
            "name": "Video production",
            "summary": "Video summary",
            "tags": ["video", "production"],
            "version": 2,
        }
        kit = KitInfo.from_dict(raw)
        self.assertIsNotNone(kit)
        assert kit is not None
        self.assertEqual(kit.id, "video-production")
        self.assertEqual(kit.name, "Video production")
        self.assertEqual(kit.summary, "Video summary")
        self.assertEqual(kit.tags, ("video", "production"))
        self.assertEqual(kit.version, 2)
        with self.assertRaises(FrozenInstanceError):
            kit.version = 3  # type: ignore[misc]

    def test_kit_info_from_dict_malformed_returns_none(self) -> None:
        malformed_cases = [
            None,
            "not-a-dict",
            [],
            {},
            # missing keys
            {"id": "k", "name": "N", "summary": "S", "tags": ["a"]},
            {"id": "k", "name": "N", "summary": "S", "version": 1},
            # empty required strings
            {"id": "", "name": "N", "summary": "S", "tags": [], "version": 1},
            {"id": "k", "name": "", "summary": "S", "tags": [], "version": 1},
            # wrong types
            {"id": 123, "name": "N", "summary": "S", "tags": [], "version": 1},
            {"id": "k", "name": "N", "summary": None, "tags": [], "version": 1},
            {"id": "k", "name": "N", "summary": "S", "tags": "video", "version": 1},
            {"id": "k", "name": "N", "summary": "S", "tags": [123], "version": 1},
            {"id": "k", "name": "N", "summary": "S", "tags": [""], "version": 1},
            {"id": "k", "name": "N", "summary": "S", "tags": [], "version": "1"},
            {"id": "k", "name": "N", "summary": "S", "tags": [], "version": True},
        ]
        for bad in malformed_cases:
            with self.subTest(bad=bad):
                self.assertIsNone(KitInfo.from_dict(bad))

    def test_video_production_prompt_ranks_video_production_first(self) -> None:
        matches = match_kits(self.kits, "set up a video production project")
        self.assertTrue(matches)
        self.assertIsInstance(matches[0], KitMatch)
        self.assertEqual(matches[0].kit.id, "video-production")
        self.assertGreaterEqual(matches[0].score, 6)
        self.assertIn("matches tag 'video'", matches[0].reasons)
        self.assertIn("matches tag 'production'", matches[0].reasons)

    def test_unreal_game_asset_prompt_ranks_game_assets_first(self) -> None:
        matches = match_kits(
            self.kits,
            "new unreal game asset workspace with blender and houdini",
        )
        self.assertTrue(matches)
        self.assertEqual(matches[0].kit.id, "game-assets")

    def test_python_component_library_prompt_ranks_component_library_first(self) -> None:
        matches = match_kits(
            self.kits,
            "python component library for reusable components",
        )
        self.assertTrue(matches)
        self.assertEqual(matches[0].kit.id, "component-library")

    def test_rust_cli_prompt_matches_no_kits(self) -> None:
        matches = match_kits(self.kits, "build a rust command line tool")
        self.assertEqual(matches, [])

    def test_plural_handling_matches_videos_and_components(self) -> None:
        video_matches = match_kits(self.kits, "videos")
        self.assertEqual([m.kit.id for m in video_matches], ["video-production"])
        self.assertEqual(video_matches[0].score, 3)

        comp_matches = match_kits(self.kits, "component")
        self.assertEqual([m.kit.id for m in comp_matches], ["component-library"])
        self.assertEqual(comp_matches[0].score, 3)

        plural_comp_matches = match_kits(self.kits, "components")
        self.assertEqual([m.kit.id for m in plural_comp_matches], ["component-library"])
        self.assertEqual(plural_comp_matches[0].score, 3)

    def test_stopwords_and_empty_prompts_return_empty(self) -> None:
        self.assertEqual(match_kits(self.kits, ""), [])
        self.assertEqual(match_kits(self.kits, "   \t\n  "), [])
        self.assertEqual(
            match_kits(
                self.kits,
                "please make and set up a new project workspace folder with some",
            ),
            [],
        )

    def test_id_part_and_name_or_summary_word_scoring_without_double_counting(self) -> None:
        kit2 = KitInfo(
            id="alpha-library",
            name="Custom Library Guide",
            summary="A library with canon workflows",
            tags=("canon", "extra"),
            version=1,
        )
        # 'canon' is a tag (+3) and in summary (not counted again)
        # 'alpha' is an id part (+2)
        # 'library' is an id part (+2) and in name/summary (not counted again)
        # 'guide' is in name (+1)
        # 'workflows' is in summary (+1)
        matches = match_kits([kit2], "canon alpha library guide workflows")
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m.score, 3 + 2 + 2 + 1 + 1)
        self.assertIn("matches tag 'canon'", m.reasons)
        self.assertIn("matches id part 'alpha'", m.reasons)
        self.assertIn("matches id part 'library'", m.reasons)
        self.assertIn("matches name word 'guide'", m.reasons)
        self.assertIn("matches summary word 'workflows'", m.reasons)

        # Also verify malformed dicts inside kits sequence are skipped by match_kits
        # (using two tag hits 'canon extra' so kit2 qualifies under the new qualification rule)
        mixed = [{"id": 123}, kit2, {"missing": "fields"}]
        self.assertEqual([x.kit.id for x in match_kits(mixed, "canon extra")], ["alpha-library"])

    def test_answers_building_boost(self) -> None:
        # Empty prompt with building='video' gives +3 to video-production (has 'video'/'storyboard' tags)
        video_matches = match_kits(self.kits, "", answers={"building": "video"})
        self.assertEqual([m.kit.id for m in video_matches], ["video-production"])
        self.assertEqual(video_matches[0].score, 3)
        self.assertIn("you said you are making video", video_matches[0].reasons)

        # building='images' boosts video-production (has 'image' tag)
        image_matches = match_kits(self.kits, "", answers={"building": "images"})
        self.assertEqual([m.kit.id for m in image_matches], ["video-production"])
        self.assertEqual(image_matches[0].score, 3)
        self.assertIn("you said you are making images", image_matches[0].reasons)

        # building='assets' boosts game-assets (have 'blender'/'houdini'/'assets'/'unreal')
        asset_matches = match_kits(self.kits, "", answers={"building": "assets"})
        self.assertEqual(
            [m.kit.id for m in asset_matches],
            ["game-assets"],
        )
        self.assertTrue(all(m.score == 3 for m in asset_matches))

    def test_ordering_ties_broken_by_kit_id(self) -> None:
        k_b = KitInfo(id="b-render", name="Render Kit", summary="S", tags=("render",), version=1)
        k_a = KitInfo(id="a-render", name="Render Kit", summary="S", tags=("render",), version=1)
        k_c = KitInfo(id="c-render", name="Render Kit", summary="S", tags=("render",), version=1)
        matches = match_kits([k_b, k_c, k_a], "render")
        self.assertEqual([m.kit.id for m in matches], ["a-render", "b-render", "c-render"])
        self.assertTrue(all(m.score == 3 for m in matches))

    def test_single_generic_tag_hit_does_not_qualify(self) -> None:
        for prompt in (
            "image generation pipeline for my comic",
            "python backend service",
            "lfs setup for my repo",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(match_kits(self.kits, prompt), [])

    def test_qualification_by_id_part_two_tags_or_building_boost(self) -> None:
        # 'new video project' -> video-production first (qualifies by id part 'video')
        video_proj = match_kits(self.kits, "new video project")
        self.assertTrue(video_proj)
        self.assertEqual(video_proj[0].kit.id, "video-production")

        # A single generic 'houdini' tag hit does not qualify game-assets.
        houdini_renders = match_kits(self.kits, "houdini fx renders")
        self.assertEqual([m.kit.id for m in houdini_renders], [])

        # 'make a rust bevy game' -> game-assets present (id part 'game')
        bevy_game = match_kits(self.kits, "make a rust bevy game")
        self.assertIn("game-assets", [m.kit.id for m in bevy_game])

        # 'image generation pipeline for my comic' with answers {'building': 'images'} -> video-production first
        comic_with_ans = match_kits(
            self.kits,
            "image generation pipeline for my comic",
            answers={"building": "images"},
        )
        self.assertTrue(comic_with_ans)
        self.assertEqual(comic_with_ans[0].kit.id, "video-production")

        # Non-empty prompt with building boost but zero id-part or tag hits does NOT qualify
        self.assertEqual(
            match_kits(self.kits, "rename my photos", answers={"building": "images"}),
            [],
        )
        self.assertEqual(
            match_kits(self.kits, "summarize this clip", answers={"building": "video"}),
            [],
        )

    def test_defensive_inputs_and_custom_min_score(self) -> None:
        # prompt None and non-string prompt -> []
        self.assertEqual(match_kits(self.kits, None), [])  # type: ignore[arg-type]
        self.assertEqual(match_kits(self.kits, 12345), [])  # type: ignore[arg-type]

        # answers not a mapping -> ignored safely
        self.assertEqual(match_kits(self.kits, "videos", answers=["not", "a", "mapping"]), [  # type: ignore[arg-type]
            KitMatch(kit=self.kits[0], score=3, reasons=["matches tag 'video'"], tag_hits=1),
        ])
        self.assertEqual(
            choose_catalog_entry(["tmpl"], [KitMatch(kit=self.kits[0], score=3, reasons=[])], answers="bad"),  # type: ignore[arg-type]
            ("template", "tmpl"),
        )

        # building given as a list -> ignored safely by _str_answer
        self.assertEqual(match_kits(self.kits, "", answers={"building": ["video"]}), [])

        # kits containing None and a valid plain dict alongside invalid dicts
        raw_dict_kit = {
            "id": "video-production",
            "name": "Video production",
            "summary": "Video summary",
            "tags": ["video", "production"],
            "version": 1,
        }
        mixed_kits = [None, {"bad": "dict"}, raw_dict_kit]
        res = match_kits(mixed_kits, "video")
        self.assertEqual([m.kit.id for m in res], ["video-production"])

        # valid kit with empty tags (qualifies via id-part hit + name/summary hits)
        tagless_kit = KitInfo(
            id="custom-render",
            name="Custom Render",
            summary="Render workflow",
            tags=(),
            version=1,
        )
        # 'render' -> id part (+2), 'custom' -> id part (+2) => score 4 >= 3, qualifies via id part
        tagless_matches = match_kits([tagless_kit], "custom render")
        self.assertEqual([m.kit.id for m in tagless_matches], ["custom-render"])
        self.assertEqual(tagless_matches[0].score, 4)

        # custom min_score
        self.assertEqual(match_kits(self.kits, "videos", min_score=4), [])
        self.assertEqual(
            [m.kit.id for m in match_kits([tagless_kit], "render", min_score=2)],
            ["custom-render"],
        )

    def test_choose_catalog_entry_all_four_branches(self) -> None:
        from hermes_plugins.defuzz.matcher import STRONG_KIT_SCORE

        self.assertEqual(STRONG_KIT_SCORE, 6)
        tmpl_match = object()
        kit_match = KitMatch(kit=self.kits[0], score=STRONG_KIT_SCORE, reasons=["matches tag 'video'"])

        # 1. answers['building'] in {'video', 'images', 'assets'} and kit_matches non-empty -> ('kit', best_kit)
        for b_val in ("video", "images", "assets"):
            kind, chosen = choose_catalog_entry(
                [tmpl_match],
                [kit_match],
                answers={"building": b_val},
            )
            self.assertEqual(kind, "kit")
            self.assertIs(chosen, kit_match)

        # 2. Else if template_matches non-empty -> ('template', best_template)
        kind, chosen = choose_catalog_entry(
            [tmpl_match],
            [kit_match],
            answers={"building": "service"},
        )
        self.assertEqual(kind, "template")
        self.assertIs(chosen, tmpl_match)

        kind_no_ans, chosen_no_ans = choose_catalog_entry([tmpl_match], [kit_match])
        self.assertEqual(kind_no_ans, "template")
        self.assertIs(chosen_no_ans, tmpl_match)

        # Also when building='video' but kit_matches is empty -> falls through to template
        kind_empty_kit, chosen_empty_kit = choose_catalog_entry(
            [tmpl_match],
            [],
            answers={"building": "video"},
        )
        self.assertEqual(kind_empty_kit, "template")
        self.assertIs(chosen_empty_kit, tmpl_match)

        # 3. Else if kit_matches non-empty with score >= STRONG_KIT_SCORE (6) -> ('kit', best_kit)
        kind_kit_fallback, chosen_kit_fallback = choose_catalog_entry(
            [],
            [kit_match],
            answers={"building": "tool"},
        )
        self.assertEqual(kind_kit_fallback, "kit")
        self.assertIs(chosen_kit_fallback, kit_match)

        # Weak kit match (score 3 < STRONG_KIT_SCORE) without kit building kind -> ('none', None)
        weak_kit_match = KitMatch(kit=self.kits[1], score=3, reasons=["matches tag 'game'"])
        kind_weak_kit, chosen_weak_kit = choose_catalog_entry(
            [],
            [weak_kit_match],
            answers={"building": "game"},
        )
        self.assertEqual(kind_weak_kit, "none")
        self.assertIsNone(chosen_weak_kit)

        # 4. Else -> ('none', None)
        kind_none, chosen_none = choose_catalog_entry([], [], answers={"building": "video"})
        self.assertEqual(kind_none, "none")
        self.assertIsNone(chosen_none)

    def test_strong_kit_with_two_tags_beats_template_only_when_no_explicit_code(self) -> None:
        templates = load_templates()
        all_kits = [KitInfo.from_dict(raw) for raw in load_list_fixture()["kits"]]
        kits = [k for k in all_kits if k is not None]

        def _route(sentence: str) -> tuple[str, str | None, bool]:
            parsed = parse_deterministic(sentence)
            t_matches = best_matches(
                templates, parsed.answers, prompt=sentence, explicit_code=parsed.explicit_code
            )
            k_matches = match_kits(kits, sentence, parsed.answers)
            cat, chosen = choose_catalog_entry(
                t_matches, k_matches, parsed.answers, explicit_code=parsed.explicit_code
            )
            chosen_id = (
                chosen.template.id
                if cat == "template"
                else (chosen.kit.id if cat == "kit" else None)
            )
            return cat, chosen_id, parsed.explicit_code

        # 1. 'home server infrastructure with network rules and runbooks' -> kit homelab (no explicit language)
        cat1, id1, exp1 = _route("home server infrastructure with network rules and runbooks")
        self.assertFalse(exp1)
        self.assertEqual((cat1, id1), ("kit", "homelab"))

        # 2. 'python backend service' -> template python-golden (explicit language)
        cat2, id2, exp2 = _route("python backend service")
        self.assertTrue(exp2)
        self.assertEqual((cat2, id2), ("template", "python-golden"))

        # 3. 'homelab dashboard web app in typescript' -> template ts-node-golden (explicit language)
        cat3, id3, exp3 = _route("homelab dashboard web app in typescript")
        self.assertTrue(exp3)
        self.assertEqual((cat3, id3), ("template", "ts-node-golden"))

        # 4. 'react frontend with figma design tokens' -> implied framework yields to website kit;
        #    naming an explicit language ('typescript frontend...') selects ts-node-golden.
        cat4, id4, exp4 = _route("react frontend with figma design tokens")
        self.assertFalse(exp4)
        self.assertEqual((cat4, id4), ("kit", "web-app"))

        cat5, id5, exp5 = _route("typescript frontend with figma design tokens")
        self.assertTrue(exp5)
        self.assertEqual((cat5, id5), ("template", "ts-node-golden"))

        cat6, id6, exp6 = _route("express api server")
        self.assertFalse(exp6)
        self.assertEqual((cat6, id6), ("template", "ts-node-golden"))

    def test_building_kit_tags_keys_equal_kit_building_kinds(self) -> None:
        self.assertEqual(set(_BUILDING_KIT_TAGS.keys()), set(KIT_BUILDING_KINDS))


if __name__ == "__main__":
    unittest.main()


# --------------------------------------------------------------- parser skips
import time as _time  # noqa: E402

from hermes_plugins.defuzz.matcher import parse_kit_list, parse_kit_list_detailed  # noqa: E402

_SECRET = "ZZBADKITTEXT"


def _bad_kits(n: int) -> list:
    """Entries the bridge accepts but the parser skips (empty name / empty tag)."""
    out = []
    for i in range(n):
        if i % 2:
            out.append({"id": f"bad-{i}", "name": "", "summary": _SECRET, "tags": [], "version": 1})
        else:
            out.append({"id": f"bad-{i}", "name": _SECRET, "summary": _SECRET, "tags": [""], "version": 1})
    return out


_SKIP_LINES = {
    0: "",
    1: "1 kit was skipped because its description is not valid. Run `hermes defuzz kits`.",
    3: "3 kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`.",
}


class ParseKitListSkippedTests(unittest.TestCase):
    def _reply(self, kits):
        return {"status": "ok", "data": {"kits": kits}}

    def test_counts_skipped_and_keeps_valid(self) -> None:
        good = load_list_fixture()["kits"]
        for n in (0, 1, 3):
            res = parse_kit_list_detailed(self._reply(list(good) + _bad_kits(n)))
            self.assertEqual(res.skipped, n)
            self.assertEqual(res.status, "ok")
            self.assertEqual(res.notice, "")
            self.assertEqual([k.id for k in res.infos], [k["id"] for k in good])
            self.assertEqual(parse_kit_list(self._reply(list(good) + _bad_kits(n))), (res.infos, "", "ok"))

    def test_non_mapping_entries_count(self) -> None:
        res = parse_kit_list_detailed(self._reply([7, None, "x", {"id": "a"}]))
        self.assertEqual((res.infos, res.skipped, res.status), ([], 4, "ok"))

    def test_all_malformed_stays_ok(self) -> None:
        res = parse_kit_list_detailed(self._reply(_bad_kits(3)))
        self.assertEqual((res.infos, res.status, res.skipped), ([], "ok", 3))

    def test_duplicates_are_kept_not_skipped(self) -> None:
        kit = load_list_fixture()["kits"][0]
        res = parse_kit_list_detailed(self._reply([kit, dict(kit)]))
        self.assertEqual(res.skipped, 0)
        self.assertEqual([k.id for k in res.infos], [kit["id"], kit["id"]])

    def test_error_reply_has_zero_skipped(self) -> None:
        res = parse_kit_list_detailed({"status": "error", "notice": "boom", "data": None})
        self.assertEqual((res.infos, res.status, res.skipped, res.notice), ([], "error", 0, "boom"))

    def test_ten_thousand_entries_are_fast(self) -> None:
        kit = load_list_fixture()["kits"][0]
        kits = [dict(kit, id=f"k-{i}") for i in range(5000)] + _bad_kits(5000)
        t0 = _time.perf_counter()
        res = parse_kit_list_detailed(self._reply(kits))
        self.assertLess(_time.perf_counter() - t0, 2.0)
        self.assertEqual((len(res.infos), res.skipped), (5000, 5000))
