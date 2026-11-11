"""Unit tests for questionnaire.py (question flow as data + headless runner with timeout)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any, List, Optional
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import questionnaire  # noqa: E402
from hermes_plugins.defuzz.questionnaire import (  # noqa: E402
    KIT_BUILDING_KINDS,
    QUESTIONS,
    Choice,
    Question,
    QuestionnaireTimeout,
    is_kit_kind,
    next_question,
    prefill,
    questions_as_json,
    run_questionnaire,
    validate_answer,
)


class TestQuestionnaire(unittest.TestCase):
    def test_questions_order_and_ids(self) -> None:
        self.assertIsInstance(QUESTIONS, tuple)
        self.assertEqual([q.id for q in QUESTIONS], ["building", "layout", "languages", "engine"])
        by_id = {q.id: q for q in QUESTIONS}

        self.assertFalse(by_id["building"].multi)
        self.assertEqual(
            [c.value for c in by_id["building"].choices],
            [
                "game",
                "studio",
                "app",
                "service",
                "library",
                "tool",
                "video",
                "images",
                "assets",
                "other",
            ],
        )
        self.assertEqual(
            [(c.value, c.label) for c in by_id["building"].choices if c.value in {"video", "images", "assets"}],
            [
                ("video", "video or film"),
                ("images", "images or art"),
                ("assets", "3D or game assets"),
            ],
        )

        self.assertFalse(by_id["layout"].multi)
        self.assertEqual([c.value for c in by_id["layout"].choices], ["mono", "poly", "single"])

        self.assertTrue(by_id["languages"].multi)
        self.assertEqual(
            [c.value for c in by_id["languages"].choices],
            ["rust", "python", "typescript", "go", "csharp", "cpp", "gdscript", "other"],
        )

        self.assertFalse(by_id["engine"].multi)
        self.assertEqual(
            [c.value for c in by_id["engine"].choices],
            ["godot", "bevy", "unity", "unreal", "none"],
        )

    def test_engine_skipped_for_app_and_asked_for_game_and_studio(self) -> None:
        # Step through for building="app": engine must be skipped
        answers_app: dict[str, Any] = {}
        q1 = next_question(answers_app)
        self.assertIsNotNone(q1)
        assert q1 is not None
        self.assertEqual(q1.id, "building")
        answers_app["building"] = "app"

        q2 = next_question(answers_app)
        self.assertIsNotNone(q2)
        assert q2 is not None
        self.assertEqual(q2.id, "layout")
        answers_app["layout"] = "single"

        q3 = next_question(answers_app)
        self.assertIsNotNone(q3)
        assert q3 is not None
        self.assertEqual(q3.id, "languages")
        answers_app["languages"] = ["typescript"]

        self.assertIsNone(next_question(answers_app))

        # For building="game" and building="studio", engine is asked after languages
        for kind in ("game", "studio"):
            ans = {"building": kind, "layout": "mono", "languages": ["rust"]}
            q4 = next_question(ans)
            self.assertIsNotNone(q4)
            assert q4 is not None
            self.assertEqual(q4.id, "engine")
            ans["engine"] = "bevy"
            self.assertIsNone(next_question(ans))

    def test_validate_answer_rejects_unknown_and_normalizes_multi_select(self) -> None:
        by_id = {q.id: q for q in QUESTIONS}
        q_building = by_id["building"]
        q_languages = by_id["languages"]

        self.assertEqual(validate_answer(q_building, "game"), "game")
        self.assertEqual(validate_answer(q_building, "  STUDIO "), "studio")

        with self.assertRaises(ValueError):
            validate_answer(q_building, "blockchain")
        with self.assertRaises(ValueError):
            validate_answer(q_building, "")
        with self.assertRaises(ValueError):
            validate_answer(q_building, ["game"])

        # Multi-select normalizes to list, deduplicates, and preserves first-seen order
        norm = validate_answer(q_languages, ["rust", "python", "rust", "gdscript", "python"])
        self.assertEqual(norm, ["rust", "python", "gdscript"])
        self.assertIsInstance(norm, list)

        # Single string or comma-separated string also normalizes to list
        self.assertEqual(validate_answer(q_languages, "rust"), ["rust"])
        self.assertEqual(validate_answer(q_languages, "python, typescript, python"), ["python", "typescript"])

        # Unknown choice or empty selection in multi-select raises ValueError
        with self.assertRaises(ValueError):
            validate_answer(q_languages, ["rust", "cobol"])
        with self.assertRaises(ValueError):
            validate_answer(q_languages, [])

    def test_prefill_tables(self) -> None:
        # game + godot -> gdscript included
        pf_godot = prefill("languages", {"building": "game", "engine": "godot"})
        self.assertIn("gdscript", pf_godot)
        self.assertIn("gdscript", prefill({"building": "game", "engine": "godot"}))

        # service -> python
        self.assertEqual(prefill("languages", {"building": "service"}), ["python"])
        self.assertEqual(prefill({"building": "service"}), ["python"])

        # app -> typescript
        self.assertEqual(prefill("languages", {"building": "app"}), ["typescript"])

        # studio / game default includes rust and gdscript
        pf_game = prefill("languages", {"building": "game"})
        self.assertIn("rust", pf_game)
        self.assertIn("gdscript", pf_game)
        pf_studio = prefill("languages", {"building": "studio"})
        self.assertIn("rust", pf_studio)
        self.assertIn("gdscript", pf_studio)

        # layout prefill: studio -> poly, others -> single
        self.assertEqual(prefill("layout", {"building": "studio"}), ["poly"])
        self.assertEqual(prefill("layout", {"building": "service"}), ["single"])

    def test_run_questionnaire_happy_path(self) -> None:
        scripted = {
            "building": "game",
            "layout": "mono",
            "languages": ["rust", "gdscript", "rust"],
            "engine": "bevy",
        }
        seen_questions: List[str] = []
        seen_prefills: dict[str, List[str]] = {}

        def ask(q: Question, suggested: List[str]) -> Any:
            seen_questions.append(q.id)
            seen_prefills[q.id] = list(suggested)
            return scripted[q.id]

        result = run_questionnaire(ask, timeout_s=30.0)
        self.assertEqual(seen_questions, ["building", "layout", "languages", "engine"])
        self.assertEqual(
            result,
            {
                "building": "game",
                "layout": "mono",
                "languages": ["rust", "gdscript"],
                "engine": "bevy",
            },
        )
        self.assertEqual(seen_prefills["layout"], ["single"])
        self.assertIn("rust", seen_prefills["languages"])

        # Also check non-game flow skips engine
        scripted_app = {
            "building": "service",
            "layout": "poly",
            "languages": ["python"],
        }
        result_app = run_questionnaire(lambda q, _pf: scripted_app[q.id], timeout_s=30.0)
        self.assertEqual(
            result_app,
            {"building": "service", "layout": "poly", "languages": ["python"]},
        )

    def test_run_questionnaire_ask_returning_none_raises_timeout_with_partial_answers(self) -> None:
        def ask(q: Question, _suggested: List[str]) -> Optional[Any]:
            if q.id == "building":
                return "studio"
            if q.id == "layout":
                return "poly"
            return None

        with self.assertRaises(QuestionnaireTimeout) as ctx:
            run_questionnaire(ask, timeout_s=30.0)

        self.assertEqual(ctx.exception.answers, {"building": "studio", "layout": "poly"})

    def test_run_questionnaire_deadline_exceeded_with_clock_and_monkeypatch(self) -> None:
        # 1. Injected clock parameter
        now = [100.0]

        def fake_clock() -> float:
            return now[0]

        def slow_ask(q: Question, _suggested: List[str]) -> Any:
            if q.id == "building":
                now[0] += 2.0
                return "game"
            if q.id == "layout":
                now[0] += 10.0  # exceeds timeout_s=5.0
                return "mono"
            return ["rust"]

        with self.assertRaises(QuestionnaireTimeout) as ctx:
            run_questionnaire(slow_ask, timeout_s=5.0, clock=fake_clock)
        self.assertEqual(ctx.exception.answers, {"building": "game"})

        # 2. Monkeypatching time.monotonic
        mono_values = iter([0.0, 1.0, 2.0, 3.0, 20.0])
        with mock.patch.object(questionnaire.time, "monotonic", side_effect=lambda: next(mono_values)):
            with self.assertRaises(QuestionnaireTimeout) as ctx2:
                run_questionnaire(
                    lambda q, _pf: "app" if q.id == "building" else "single",
                    timeout_s=5.0,
                )
            self.assertEqual(ctx2.exception.answers, {"building": "app"})

    def test_run_questionnaire_enforces_wall_clock_budget_on_blocking_callback(self) -> None:
        import contextvars
        import threading
        import time

        cvar: contextvars.ContextVar[str] = contextvars.ContextVar("test_q_cvar", default="missing")
        seen_cvar: List[str] = []
        release = threading.Event()
        finished = threading.Event()

        def blocking_ask(_q: Question, _suggested: List[str]) -> Any:
            seen_cvar.append(cvar.get())
            release.wait(timeout=1.0)
            finished.set()
            return "game"

        token = cvar.set("propagated-into-worker")
        try:
            started = time.monotonic()
            with self.assertRaises(QuestionnaireTimeout):
                run_questionnaire(blocking_ask, timeout_s=0.02)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.12)
            release.set()
            self.assertTrue(finished.wait(timeout=1.0))
            self.assertEqual(seen_cvar, ["propagated-into-worker"])
        finally:
            cvar.reset(token)

    def test_questions_as_json_serializable_and_structure(self) -> None:
        payload = questions_as_json()
        raw_json = json.dumps(payload)
        roundtrip = json.loads(raw_json)
        self.assertEqual(len(roundtrip), 4)
        self.assertEqual([item["id"] for item in roundtrip], ["building", "layout", "languages", "engine"])
        for item in roundtrip:
            self.assertIn("text", item)
            self.assertIn("multi", item)
            self.assertIn("choices", item)
            self.assertTrue(len(item["choices"]) > 0)
            for choice in item["choices"]:
                self.assertIn("value", choice)
                self.assertIn("label", choice)
                self.assertIsInstance(choice["value"], str)
                self.assertIsInstance(choice["label"], str)
                self.assertTrue(choice["value"])
                self.assertTrue(choice["label"])
        building_json = next(item for item in roundtrip if item["id"] == "building")
        self.assertEqual(
            [c["value"] for c in building_json["choices"]],
            [
                "game",
                "studio",
                "app",
                "service",
                "library",
                "tool",
                "video",
                "images",
                "assets",
                "other",
            ],
        )

    def test_kit_building_kinds_skip_layout_languages_and_engine(self) -> None:
        self.assertEqual(KIT_BUILDING_KINDS, frozenset({"video", "images", "assets"}))
        self.assertFalse(is_kit_kind({}))
        self.assertFalse(is_kit_kind({"building": "game"}))
        self.assertFalse(is_kit_kind({"building": "tool"}))
        self.assertFalse(is_kit_kind({"building": "other"}))

        for kind in ("video", "images", "assets"):
            with self.subTest(kind=kind):
                self.assertTrue(is_kit_kind({"building": kind}))
                self.assertEqual(validate_answer("building", kind), kind)
                self.assertEqual(validate_answer("building", f"  {kind.upper()} "), kind)
                self.assertIsNone(next_question({"building": kind}))
                self.assertEqual(prefill("languages", {"building": kind}), [])
                self.assertEqual(prefill({"building": kind}), [])

        # run_questionnaire happy path for 'video': finishes after 'building' with only what was asked
        seen_questions: List[str] = []

        def ask_video(q: Question, _suggested: List[str]) -> Any:
            seen_questions.append(q.id)
            return "video"

        result_video = run_questionnaire(ask_video, timeout_s=30.0)
        self.assertEqual(seen_questions, ["building"])
        self.assertEqual(result_video, {"building": "video"})

        # Initial answers for a kit kind ask no questions at all
        seen_initial: List[str] = []
        result_initial = run_questionnaire(
            lambda q, _pf: seen_initial.append(q.id) or "other",
            initial_answers={"building": "images"},
            timeout_s=30.0,
        )
        self.assertEqual(seen_initial, [])
        self.assertEqual(result_initial, {"building": "images"})


if __name__ == "__main__":
    unittest.main()
