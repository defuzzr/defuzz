"""Unit tests for matcher.py (rank templates by questionnaire answers with reasons)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # noqa: E402
    Match,
    best_matches,
    closest,
    rank_templates,
    template_families,
)
from hermes_plugins.defuzz.templates import (  # noqa: E402
    RepoSpec,
    TemplateSpec,
    load_templates,
)

FIXTURES_TEMPLATES = Path(__file__).resolve().parent / "fixtures" / "templates"


def _make_stub_template(
    *,
    template_id: str = "stub-tmpl",
    name: str = "Stub Template",
    summary: str = "In-memory stub template",
    kind: str = "library",
    layout: str = "single",
    languages: tuple[str, ...] = ("rust",),
    engine: str | None = None,
    tags: tuple[str, ...] = (),
    needs: tuple[str, ...] = (),
) -> TemplateSpec:
    """Construct a stub TemplateSpec in memory without touching disk."""
    return TemplateSpec(
        id=template_id,
        name=name,
        summary=summary,
        kind=kind,
        layout=layout,
        languages=languages,
        engine=engine,
        tags=tags,
        needs=needs,
        placeholder="tmpl_prefix",
        substitute_in=("**/*.rs",),
        repos=(RepoSpec(name="tmpl_prefix", check=None),),
        root=Path("/nonexistent/stub"),
    )


class TestMatcher(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = load_templates(FIXTURES_TEMPLATES)
        self.assertEqual([t.id for t in self.fixtures], ["fake-py-service", "fake-rust-game"])

    def test_game_mono_rust_bevy_ranks_fake_rust_game_first_with_reasons_and_needs(self) -> None:
        answers = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust"],
            "engine": "bevy",
        }
        ranked = rank_templates(self.fixtures, answers)
        self.assertEqual(len(ranked), 2)
        top = ranked[0]
        self.assertIsInstance(top, Match)
        self.assertEqual(top.template.id, "fake-rust-game")
        self.assertIn("kind: game", top.reasons)
        self.assertIn("layout: mono", top.reasons)
        self.assertIn("language: rust", top.reasons)
        self.assertIn("engine: bevy", top.reasons)
        self.assertEqual(top.needs, ["cargo"])
        # Score: kind(+3) + layout(+3) + lang(+2) + engine(+3) + tag 'game'(+1) = 12
        self.assertEqual(top.score, 12)

        best = best_matches(self.fixtures, answers)
        self.assertEqual([m.template.id for m in best], ["fake-rust-game"])

    def test_service_poly_python_ranks_fake_py_service_first_and_rust_game_below_min_score(self) -> None:
        answers = {
            "building": "service",
            "layout": "poly",
            "languages": ["python"],
        }
        ranked = rank_templates(self.fixtures, answers)
        self.assertEqual([m.template.id for m in ranked], ["fake-py-service", "fake-rust-game"])
        self.assertEqual(ranked[0].score, 8)  # kind(+3) + layout(+3) + lang(+2)
        self.assertIn("kind: service", ranked[0].reasons)
        self.assertIn("layout: poly", ranked[0].reasons)
        self.assertIn("language: python", ranked[0].reasons)
        self.assertEqual(ranked[0].needs, ["python", "node"])

        # fake-rust-game gets layout differs (-2) and zero language overlap (-3) -> -5 < min_score (3)
        self.assertLess(ranked[1].score, 3)

        best = best_matches(self.fixtures, answers)
        self.assertEqual([m.template.id for m in best], ["fake-py-service"])

    def test_godot_engine_excludes_fake_rust_game_and_closest_returns_remaining(self) -> None:
        answers = {
            "building": "game",
            "engine": "godot",
        }
        ranked = rank_templates(self.fixtures, answers)
        # fake-rust-game has engine='bevy' != 'godot' -> EXCLUDED
        # fake-py-service has engine=None -> not excluded, score 1 (tag 'game'? No, tags=('api',), so score 0)
        self.assertEqual([m.template.id for m in ranked], ["fake-py-service"])
        self.assertEqual(ranked[0].score, 0)

        best = best_matches(self.fixtures, answers)
        self.assertEqual(best, [])

        close = closest(self.fixtures, answers)
        self.assertIsNotNone(close)
        assert close is not None
        self.assertEqual(close.template.id, "fake-py-service")

        # When all templates are excluded by engine mismatch, closest returns None
        only_bevy = [t for t in self.fixtures if t.id == "fake-rust-game"]
        self.assertEqual(rank_templates(only_bevy, answers), [])
        self.assertIsNone(closest(only_bevy, answers))

    def test_studio_answer_matches_studio_plus_3_and_game_poly_plus_2(self) -> None:
        tmpl_studio = _make_stub_template(
            template_id="studio-tmpl",
            kind="studio",
            layout="poly",
            languages=("rust",),
        )
        tmpl_game_poly = _make_stub_template(
            template_id="game-poly-tmpl",
            kind="game",
            layout="poly",
            languages=("rust",),
        )
        tmpl_game_mono = _make_stub_template(
            template_id="game-mono-tmpl",
            kind="game",
            layout="mono",
            languages=("rust",),
        )
        answers = {"building": "studio"}
        ranked = rank_templates([tmpl_game_mono, tmpl_game_poly, tmpl_studio], answers)
        by_id = {m.template.id: m for m in ranked}

        self.assertEqual(by_id["studio-tmpl"].score, 3)
        self.assertIn("kind: studio", by_id["studio-tmpl"].reasons)

        self.assertEqual(by_id["game-poly-tmpl"].score, 2)
        self.assertTrue(any("game" in r and "poly" in r for r in by_id["game-poly-tmpl"].reasons))

        # game + mono does not get the studio->game+poly bonus
        self.assertEqual(by_id["game-mono-tmpl"].score, 0)

    def test_building_other_matches_nothing_on_kind(self) -> None:
        tmpl_other = _make_stub_template(template_id="other-tmpl", kind="other", layout="single")
        ranked = rank_templates([tmpl_other], {"building": "other"})
        self.assertEqual(ranked[0].score, 0)
        self.assertFalse(any(r.startswith("kind:") for r in ranked[0].reasons))

    def test_layout_differs_penalty_and_exact_reason_text(self) -> None:
        answers = {"building": "service", "layout": "mono"}
        # fake-py-service has layout="poly"
        ranked = rank_templates(self.fixtures, answers)
        by_id = {m.template.id: m for m in ranked}
        py_match = by_id["fake-py-service"]
        self.assertIn("layout differs: template is poly, you want mono", py_match.reasons)
        # kind service (+3) + layout differs (-2) = 1
        self.assertEqual(py_match.score, 1)

    def test_language_overlap_bonus_and_zero_overlap_penalty(self) -> None:
        # Multi-language overlap on fake-py-service (python + typescript)
        ranked_both = rank_templates(
            self.fixtures,
            {"languages": ["python", "typescript"]},
        )
        by_id_both = {m.template.id: m for m in ranked_both}
        self.assertEqual(by_id_both["fake-py-service"].score, 4)
        self.assertIn("language: python", by_id_both["fake-py-service"].reasons)
        self.assertIn("language: typescript", by_id_both["fake-py-service"].reasons)

        # Zero overlap on fake-rust-game gives -3
        self.assertEqual(by_id_both["fake-rust-game"].score, -3)

    def test_tags_bonus_when_tag_matches_any_answer_value(self) -> None:
        tmpl_tagged = _make_stub_template(
            template_id="tagged-tmpl",
            kind="tool",
            layout="single",
            languages=("python",),
            tags=("cli", "python", "single"),
        )
        # Answer has layout='single' and languages=['python'] -> tags 'python' and 'single' match (+2)
        ranked = rank_templates(
            [tmpl_tagged],
            {"building": "library", "layout": "single", "languages": ["python"]},
        )
        m = ranked[0]
        # layout(+3) + language(+2) + 2 matching tags(+2) = 7
        self.assertEqual(m.score, 7)
        self.assertIn("tag: python", m.reasons)
        self.assertIn("tag: single", m.reasons)

    def test_tags_require_exact_equality_without_normalization(self) -> None:
        tmpl = _make_stub_template(
            template_id="unnormalized-tags",
            kind="tool",
            layout="single",
            languages=("python",),
            tags=("Python", " python "),
        )
        ranked = rank_templates([tmpl], {"languages": ["python"]})
        m = ranked[0]
        # language(+2) + 0 tag bonus (neither 'Python' nor ' python ' == 'python') = 2
        self.assertEqual(m.score, 2)
        self.assertFalse(any(r.startswith("tag:") for r in m.reasons))

    def test_deterministic_tie_break_by_template_id(self) -> None:
        t_b = _make_stub_template(template_id="b-template", kind="tool", layout="single")
        t_a = _make_stub_template(template_id="a-template", kind="tool", layout="single")
        t_c = _make_stub_template(template_id="c-template", kind="tool", layout="single")

        ranked = rank_templates([t_b, t_c, t_a], {"building": "tool", "layout": "single"})
        self.assertEqual([m.template.id for m in ranked], ["a-template", "b-template", "c-template"])
        self.assertTrue(all(m.score == 6 for m in ranked))

    def test_engine_none_penalizes_template_with_engine_but_does_not_exclude(self) -> None:
        answers = {"building": "game", "engine": "none"}
        ranked = rank_templates(self.fixtures, answers)
        by_id = {m.template.id: m for m in ranked}

        self.assertIn("fake-rust-game", by_id)
        # fake-rust-game: kind game (+3), tag 'game' (+1), engine 'none' vs 'bevy' (-2) = 2
        self.assertEqual(by_id["fake-rust-game"].score, 2)
        # fake-py-service has engine=None -> no penalty (score 0)
        self.assertEqual(by_id["fake-py-service"].score, 0)

    def test_stub_template_spec_works_without_fixture_files(self) -> None:
        stub = _make_stub_template(
            template_id="in-memory-app",
            kind="app",
            layout="mono",
            languages=("typescript",),
            engine=None,
            tags=("web", "app"),
            needs=("pnpm",),
        )
        answers = {"building": "app", "layout": "mono", "languages": ["typescript"]}
        matches = best_matches([stub], answers)
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertIs(m.template, stub)
        # kind(+3) + layout(+3) + language(+2) + tag 'app'(+1) = 9
        self.assertEqual(m.score, 9)
        self.assertEqual(m.needs, ["pnpm"])

    def test_python_app_mono_does_not_offer_rust_golden_in_best_matches(
        self, templates_dir: Path | None = None
    ) -> None:
        shipped = load_templates(templates_dir)
        self.assertTrue(shipped, "Expected at least one template in templates/")
        for spec in shipped:
            answers = {
                "building": spec.kind,
                "layout": spec.layout,
                "languages": list(spec.languages),
            }
            if spec.engine is not None:
                answers["engine"] = spec.engine
            # A family template (tags hold a kit family such as 'website') is offered only for
            # a request in that family, so its own answers come with a request for it.
            families = sorted(template_families(spec))
            prompt = f"a {families[0]}" if families else None
            matches = best_matches(shipped, answers, prompt=prompt)
            matched_ids = [m.template.id for m in matches]
            self.assertIn(spec.id, matched_ids)
            non_overlapping = [
                t for t in shipped if not set(t.languages).intersection(spec.languages)
            ]
            for other in non_overlapping:
                self.assertNotIn(other.id, matched_ids)
            self.assertEqual(best_matches(non_overlapping, answers), [])
            if non_overlapping:
                near = closest(non_overlapping, answers)
                self.assertIsNotNone(near)
                assert near is not None
                self.assertIn(near.template.id, {t.id for t in non_overlapping})
                self.assertIn("language: no overlap", near.reasons)


if __name__ == "__main__":
    unittest.main()
