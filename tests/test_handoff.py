"""Unit tests for handoff.py (build_handoff)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.handoff import (  # noqa: E402
    build_handoff,
)
from hermes_plugins.defuzz.matcher import Match, closest  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEMPLATES_FIXTURES = FIXTURES_DIR / "templates"


class TestHandoff(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.templates = load_templates(TEMPLATES_FIXTURES)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_build_handoff_with_closest_match(self) -> None:
        answers = {
            "building": "game",
            "layout": "poly",
            "languages": ["rust", "gdscript"],
            "engine": "bevy",
        }
        near = closest(self.templates, answers)
        self.assertIsNotNone(near)
        assert isinstance(near, Match)

        payload = build_handoff(
            answers,
            near,
            templates_root=TEMPLATES_FIXTURES,
        )

        self.assertEqual(payload["title"], "Adapt template for game")
        self.assertEqual(payload["cwd"], str(TEMPLATES_FIXTURES))
        self.assertEqual(payload["answers"], answers)

        text = payload["text"]
        self.assertIsInstance(text, str)
        # Lists the answers
        self.assertIn("game", text)
        self.assertIn("poly", text)
        self.assertIn("rust", text)
        self.assertIn("gdscript", text)
        self.assertIn("bevy", text)
        # Names the closest template folder and why it is close (its Match.reasons)
        self.assertIn(near.template.id, text)
        self.assertIn(str(near.template.root), text)
        self.assertIn("Why it is close:", text)
        for reason in near.reasons:
            self.assertIn(reason, text)
        # Asks to adapt under templates/ following template.yaml contract
        self.assertIn("templates/", text)
        self.assertIn("template.yaml", text)
        # Safety instruction
        self.assertIn("do not push or publish anything", text.lower())

    def test_build_handoff_with_non_positive_score_says_poor_fit(self) -> None:
        answers = {
            "building": "tool",
            "layout": "single",
            "languages": ["go"],
        }
        near = closest(self.templates, answers)
        self.assertIsNotNone(near)
        assert isinstance(near, Match)
        self.assertLessEqual(near.score, 0)

        payload = build_handoff(
            answers,
            near,
            templates_root=TEMPLATES_FIXTURES,
        )
        text = payload["text"]
        self.assertIn("Nearest available template (poor fit):", text)
        self.assertNotIn("Why it is close:", text)

    def test_build_handoff_without_closest_match(self) -> None:
        answers = {
            "building": "tool",
            "layout": "single",
            "languages": ["go"],
        }
        payload = build_handoff(
            answers,
            None,
            templates_root=TEMPLATES_FIXTURES,
        )

        self.assertEqual(payload["title"], "Adapt template for tool")
        self.assertEqual(payload["cwd"], str(TEMPLATES_FIXTURES))
        self.assertEqual(payload["answers"], answers)

        text = payload["text"]
        self.assertIn("tool", text)
        self.assertIn("single", text)
        self.assertIn("go", text)
        self.assertIn("no template is close", text.lower())
        self.assertIn("draft a new", text.lower())
        self.assertIn("templates/", text)
        self.assertIn("template.yaml", text)
        self.assertIn("do not push or publish anything", text.lower())
