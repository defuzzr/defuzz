"""Negated clauses in kit name/summary text are not positive match evidence."""

from __future__ import annotations

import re
import time
import unittest
from unittest.mock import patch

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # type: ignore[import-not-found]  # noqa: E402
    KitInfo,
    match_kits,
    positive_kit_text,
)
from tests.fake_kit_bridge import load_list_fixture  # noqa: E402

_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _words(text: str) -> set[str]:
    return {w.lower() for w in _WORD_RE.findall(text)}


class _Case:
    def __init__(
        self,
        name: str,
        text: str,
        *,
        kept: tuple[str, ...] = (),
        excluded: tuple[str, ...] = (),
        identical: bool = False,
    ) -> None:
        self.name = name
        self.text = text
        self.kept = kept
        self.excluded = excluded
        self.identical = identical


# At least 40 kit summaries. `identical` means the helper must return the
# input unchanged (no negation, or a lookalike that must stay positive).
_CASES: tuple[_Case, ...] = (
    _Case(
        "studio-3d real clause",
        "Multi-tool 3D design studio workspace: per-asset sources/exports, "
        "Blender and Houdini DCC trees, UE5, Godot and Three.js targets, "
        "shots and deliveries; not a single-engine game project or an Unreal asset pipeline.",
        kept=("multi", "tool", "3d", "design", "studio", "workspace", "per", "asset",
              "sources", "exports", "blender", "houdini", "dcc", "trees", "ue5",
              "godot", "three", "js", "targets", "shots", "deliveries"),
        excluded=("single", "engine", "game", "project", "unreal", "pipeline"),
    ),
    _Case(
        "component-library real clause",
        "Reusable Python code library: snake_case.py modules with a COMPONENTS.md "
        "index and tests, thin runner scripts and componentize specs; not a UI or "
        "design-system component library.",
        kept=("reusable", "python", "code", "library", "snake", "case", "py", "modules",
              "components", "md", "index", "tests", "thin", "runner", "scripts",
              "componentize", "specs"),
        excluded=("ui", "design", "system", "component"),
    ),
    _Case(
        "video-production real clause",
        "AI-assisted video production workspace: locked canon references, generated "
        "candidates, approved assets, storyboards, footage, audio, renders and "
        "numbered deliverables; not a YouTube channel or a comic.",
        kept=("ai", "assisted", "video", "production", "workspace", "locked", "canon",
              "references", "generated", "candidates", "approved", "assets",
              "storyboards", "footage", "audio", "renders", "numbered", "deliverables"),
        excluded=("youtube", "channel", "comic"),
    ),
    _Case(
        "image-set real clause",
        "AI still-image generation workspace: read-only references, prompts, ComfyUI "
        "workflows, model notes, staged outputs from raw to approved finals, and "
        "contact sheets; not LoRA training or a render queue.",
        kept=("ai", "still", "image", "generation", "workspace", "read", "only",
              "references", "prompts", "comfyui", "workflows", "model", "notes",
              "staged", "outputs", "raw", "approved", "finals", "contact", "sheets"),
        excluded=("lora", "training", "render", "queue"),
    ),
    _Case(
        "lora-training real clause",
        "LoRA adapter training workspace for image or text models: staged dataset "
        "and captions, datasheets, configs, isolated run folders, fixed evaluation "
        "sets and versioned releases; not prompt-based image generation.",
        kept=("lora", "adapter", "training", "workspace", "image", "text", "models",
              "staged", "dataset", "captions", "datasheets", "configs", "isolated",
              "run", "folders", "fixed", "evaluation", "sets", "versioned", "releases"),
        excluded=("prompt", "based", "generation"),
    ),
    _Case(
        "sentence-initial Not for",
        "Not for Unreal game pipelines. A Blender studio workspace.",
        kept=("blender", "studio", "workspace"),
        excluded=("unreal", "game", "pipelines"),
    ),
    _Case(
        "clause in parentheses",
        "A video production workspace (not a YouTube channel or a comic) with footage.",
        kept=("video", "production", "workspace", "footage"),
        excluded=("youtube", "channel", "comic"),
    ),
    _Case(
        "two negated clauses",
        "Alpha workspace; not a beta pipeline. Gamma tools; never a delta queue.",
        kept=("alpha", "workspace", "gamma", "tools"),
        excluded=("beta", "pipeline", "delta", "queue"),
    ),
    _Case(
        "not only but also at a clause boundary stays positive",
        "Blender workspace; not only Houdini but also Godot.",
        identical=True,
        kept=("blender", "workspace", "houdini", "godot"),
    ),
    _Case(
        "not only mid-phrase stays positive",
        "A studio that is not only Blender but also Houdini.",
        identical=True,
    ),
    _Case(
        "words containing not or no stay positive",
        "A notebook of notes about node graphs, nonprofit annotation, and no-code tools.",
        identical=True,
        kept=("notebook", "notes", "node", "nonprofit", "annotation", "code", "tools"),
    ),
    _Case(
        "rather than at a comma",
        "A Blender studio, rather than an Unreal game pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "game", "pipeline"),
    ),
    _Case(
        "instead of at a semicolon",
        "A video workspace; instead of a YouTube channel.",
        kept=("video", "workspace"),
        excluded=("youtube", "channel"),
    ),
    _Case(
        "without at a semicolon",
        "Image generation workspace; without LoRA training.",
        kept=("image", "generation", "workspace"),
        excluded=("lora", "training"),
    ),
    _Case(
        "without mid-phrase is not a clause and stays positive",
        "Image generation without LoRA training.",
        identical=True,
    ),
    _Case(
        "no negation is byte-identical",
        "Game workspace with one folder per source asset and Git LFS rules.",
        identical=True,
    ),
    _Case("empty", "", identical=True),
    _Case(
        "em dash",
        "A Blender studio \u2014 not an Unreal pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipeline"),
    ),
    _Case(
        "en dash",
        "A Blender studio \u2013 not an Unreal pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipeline"),
    ),
    _Case(
        "spaced hyphen dash",
        "A Blender studio - not an Unreal pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipeline"),
    ),
    _Case(
        "never at a semicolon",
        "A video workspace; never a YouTube channel.",
        kept=("video", "workspace"),
        excluded=("youtube", "channel"),
    ),
    _Case(
        "no at a comma",
        "A Blender studio, no Unreal pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipeline"),
    ),
    _Case(
        "unlike at a semicolon",
        "A Blender studio; unlike an Unreal pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipeline"),
    ),
    _Case(
        "excluding in parentheses",
        "A Blender studio (excluding Unreal pipelines) for shots.",
        kept=("blender", "studio", "shots"),
        excluded=("unreal", "pipelines"),
    ),
    _Case(
        "except at a semicolon",
        "A Blender studio; except Unreal pipelines.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipelines"),
    ),
    _Case(
        "sentence-initial not an",
        "Not an Unreal asset pipeline. Blender shots stay.",
        kept=("blender", "shots", "stay"),
        excluded=("unreal", "asset", "pipeline"),
    ),
    _Case(
        "commas and or stay inside the clause",
        "Video workspace; not a YouTube channel, a comic, or a blog.",
        kept=("video", "workspace"),
        excluded=("youtube", "channel", "comic", "blog"),
    ),
    _Case(
        "semicolon ends the clause and the next sentence stays",
        "Video workspace; not a YouTube channel; comics stay positive.",
        kept=("video", "workspace", "comics", "stay", "positive"),
        excluded=("youtube", "channel"),
    ),
    _Case(
        "period ends the clause",
        "Not for channels. Comics stay.",
        kept=("comics", "stay"),
        excluded=("channels",),
    ),
    _Case(
        "close paren ends the clause",
        "Video workspace (not a channel) comics stay.",
        kept=("video", "workspace", "comics", "stay"),
        excluded=("channel",),
    ),
    _Case(
        "not mid-phrase without a clause boundary stays positive",
        "This kit is not Unreal only in name but a studio.",
        identical=True,
    ),
    _Case(
        "no-code at the start is not a cue",
        "no-code notebook workspace for notes.",
        identical=True,
    ),
    _Case(
        "cannot and notebook stay positive",
        "A workspace that cannot replace notebooks.",
        identical=True,
    ),
    _Case(
        "nothing is not a listed cue",
        "Nothing here is special about widgets.",
        identical=True,
    ),
    _Case(
        "none is not a listed cue",
        "None of the folders are special widgets.",
        identical=True,
    ),
    _Case(
        "name-shaped negated clause",
        "Studio kit; not a game.",
        kept=("studio", "kit"),
        excluded=("game",),
    ),
    _Case(
        "extra whitespace after the boundary",
        "Video workspace;   not a channel.",
        kept=("video", "workspace"),
        excluded=("channel",),
    ),
    _Case(
        "uppercase sentence-initial cue",
        "NOT A CHANNEL. Video production stays.",
        kept=("video", "production", "stays"),
        excluded=("channel",),
    ),
    _Case(
        "nor stays inside the clause",
        "Video workspace; not a channel nor a comic.",
        kept=("video", "workspace"),
        excluded=("channel", "comic"),
    ),
    _Case(
        "and stays inside the clause",
        "Video workspace; not a channel and a comic.",
        kept=("video", "workspace"),
        excluded=("channel", "comic"),
    ),
    _Case(
        "notable nevertheless annotation are not cues",
        "Notable nevertheless annotation of notebooks and notes.",
        identical=True,
    ),
    _Case(
        "colon is not a clause boundary",
        "A studio: not a game project.",
        identical=True,
    ),
    _Case(
        "rather than mid-phrase stays positive",
        "Choose blender rather than unreal.",
        identical=True,
    ),
    _Case(
        "instead of mid-phrase stays positive",
        "Choose video instead of youtube.",
        identical=True,
    ),
    _Case(
        "not only then a later real clause",
        "Not only Blender but also Houdini; not a game.",
        kept=("blender", "houdini"),
        excluded=("game",),
    ),
    _Case(
        "em dash with no spaces",
        "Blender studio\u2014not an Unreal pipeline.",
        kept=("blender", "studio"),
        excluded=("unreal", "pipeline"),
    ),
    _Case(
        "never and without as two clauses",
        "Alpha tools; never a beta queue. Gamma kit; without a delta pipeline.",
        kept=("alpha", "tools", "gamma", "kit"),
        excluded=("beta", "queue", "delta", "pipeline"),
    ),
    _Case(
        "exception does not match the except cue",
        "Exception handling workspace for notebooks.",
        identical=True,
    ),
    _Case(
        "newline ends a negated clause",
        "Video workspace; not a channel\nComics stay positive.",
        kept=("video", "workspace", "comics", "stay", "positive"),
        excluded=("channel",),
    ),
)


def _kit(kit_id: str, name: str, summary: str, tags: tuple[str, ...]) -> KitInfo:
    kit = KitInfo.from_dict(
        {"id": kit_id, "name": name, "summary": summary, "tags": list(tags), "version": 1}
    )
    assert kit is not None
    return kit


# Kit A already matches the shared tags. Its summary's "not beta" clause is the
# only extra point that would outrank kit B. Masking that clause ties the score
# and B wins on an id-part hit.
_B_PROMPT = "set up marker beta shared"
_A_PROMPT = "set up an alpha studio marker shared"
_SUMMARY_KITS = [
    _kit(
        "alpha-studio",
        "Alpha studio",
        "Alpha studio workspace for marker projects; not a beta pipeline.",
        ("marker", "shared"),
    ),
    _kit(
        "beta-kit",
        "Beta kit",
        "Beta workspace for shared projects.",
        ("beta", "shared"),
    ),
]
_NAME_KITS = [
    _kit(
        "alpha-studio",
        "Alpha studio; not beta",
        "Alpha studio workspace.",
        ("marker", "shared"),
    ),
    _kit(
        "beta-kit",
        "Beta kit",
        "Beta workspace.",
        ("beta", "shared"),
    ),
]


# Words each fixture kit's negated clause excludes. Kits not listed here have no
# negated clause and must come back byte-identical.
_FIXTURE_EXCLUDED: dict[str, tuple[str, ...]] = {
    "component-library": ("ui", "design", "system", "component"),
    "image-set": ("lora", "training", "render", "queue"),
    "lora-training": ("prompt", "based", "generation"),
    "studio-3d": ("single", "engine", "game", "project", "unreal", "pipeline"),
    "video-production": ("youtube", "channel", "comic"),
}


class TestPositiveKitText(unittest.TestCase):
    def test_at_least_40_summaries(self) -> None:
        self.assertGreaterEqual(len(_CASES), 40)

    def test_summaries(self) -> None:
        for case in _CASES:
            with self.subTest(case=case.name):
                got = positive_kit_text(case.text)
                words = _words(got)
                if case.identical:
                    self.assertEqual(got, case.text)
                for word in case.kept:
                    self.assertIn(word, words, case.text)
                for word in case.excluded:
                    self.assertNotIn(word, words, got)

    def test_real_clauses_keep_the_prefix_bytes(self) -> None:
        for case in (c for c in _CASES if c.name.endswith("real clause")):
            with self.subTest(case=case.name):
                cut = case.text.lower().rfind("; not ")
                self.assertGreater(cut, 0)
                self.assertEqual(positive_kit_text(case.text)[:cut], case.text[:cut])

    def test_empty_and_long_input(self) -> None:
        self.assertEqual(positive_kit_text(""), "")
        plain = ("alpha studio workspace " * 5000)[:100_000]
        started = time.perf_counter()
        self.assertEqual(positive_kit_text(plain), plain)
        self.assertLess(time.perf_counter() - started, 0.5)

        bounded = ("; " * 50_000)[:100_000]
        started = time.perf_counter()
        self.assertEqual(positive_kit_text(bounded), bounded)
        self.assertLess(time.perf_counter() - started, 0.5)

        trailed = plain + "; not a beta pipeline."
        started = time.perf_counter()
        masked = positive_kit_text(trailed)
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertTrue(masked.startswith(plain))
        self.assertNotIn("beta", _words(masked))
        self.assertNotIn("pipeline", _words(masked))

    def test_fixture_positive_text_is_a_prefix_preserving_reduction(self) -> None:
        kits = load_list_fixture()["kits"]
        self.assertGreaterEqual(len(kits), 1)
        seen = set()
        for kit in kits:
            with self.subTest(kit=kit["id"]):
                summary = kit["summary"]
                got = positive_kit_text(summary)
                self.assertEqual(positive_kit_text(kit["name"]), kit["name"])
                cut = summary.lower().find("; not ")
                excluded = _FIXTURE_EXCLUDED.get(kit["id"])
                if excluded is None:
                    self.assertEqual(cut, -1, summary)
                    self.assertEqual(got, summary)
                    continue
                seen.add(kit["id"])
                self.assertGreater(cut, 0, summary)
                self.assertEqual(got[:cut], summary[:cut])
                self.assertNotEqual(got, summary)
                words = _words(got)
                for word in excluded:
                    self.assertNotIn(word, words, got)
        self.assertEqual(seen, set(_FIXTURE_EXCLUDED))


class TestNegatedKitTextDoesNotRoute(unittest.TestCase):
    def test_b_request_routes_to_b_not_the_kit_that_excludes_it(self) -> None:
        matches = match_kits(_SUMMARY_KITS, _B_PROMPT)
        self.assertTrue(matches)
        self.assertEqual(
            matches[0].kit.id,
            "beta-kit",
            [(m.kit.id, m.score, m.reasons) for m in matches],
        )
        alpha = next(m for m in matches if m.kit.id == "alpha-studio")
        self.assertFalse(any("beta" in reason for reason in alpha.reasons))

    def test_disabling_the_helper_lets_the_negated_clause_steal_the_match(self) -> None:
        with patch(
            "hermes_plugins.defuzz.matcher.positive_kit_text",
            side_effect=lambda text: text,
        ):
            matches = match_kits(_SUMMARY_KITS, _B_PROMPT)
        self.assertTrue(matches)
        self.assertEqual(matches[0].kit.id, "alpha-studio")

    def test_a_request_still_routes_to_a(self) -> None:
        matches = match_kits(_SUMMARY_KITS, _A_PROMPT)
        self.assertTrue(matches)
        self.assertEqual(matches[0].kit.id, "alpha-studio")

    def test_negated_name_does_not_steal_the_match(self) -> None:
        matches = match_kits(_NAME_KITS, _B_PROMPT)
        self.assertTrue(matches)
        self.assertEqual(matches[0].kit.id, "beta-kit")

    def test_tags_are_not_masked(self) -> None:
        kits = [
            _kit(
                "alpha-studio",
                "Alpha studio",
                "Alpha workspace; not a beta pipeline.",
                ("beta", "shared", "marker"),
            )
        ]
        matches = match_kits(kits, "beta shared marker")
        self.assertTrue(matches)
        self.assertIn("matches tag 'beta'", matches[0].reasons)
