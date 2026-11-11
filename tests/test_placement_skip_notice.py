"""Unit tests for one-time skip and error notices in automatic file placement."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

import hermes_plugins.defuzz.placer as placer_mod  # noqa: E402
from hermes_plugins.defuzz.placer import (  # noqa: E402
    _reset_notice_state_for_tests,
    get_last_hook_skip_reason,
    on_pre_tool_call,
    on_transform_tool_result,
    trust_project,
)


def _make_adopted_proj(root: Path, slug: str = "demo_proj") -> Path:
    (root / ".adopt").mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(exist_ok=True)
    (root / "_inbox").mkdir(exist_ok=True)
    (root / ".adopt" / "rules.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "schema_version": 1,
                "project_slug": slug,
                "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
                "placement_rules": [
                    {
                        "kind": "docs",
                        "match_ext": [".md"],
                        "dest_dir": "docs",
                        "lfs": False,
                        "reason": "docs",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return root


class TestPlacementSkipNotice(unittest.TestCase):
    def setUp(self) -> None:
        self._env_tmp = tempfile.TemporaryDirectory()
        self.hermes_home = Path(self._env_tmp.name) / "hermes_home"
        self.hermes_home.mkdir(parents=True, exist_ok=True)
        self._env_patcher = mock.patch.dict(
            os.environ,
            {"HERMES_HOME": str(self.hermes_home)},
        )
        self._env_patcher.start()
        _reset_notice_state_for_tests()

    def tearDown(self) -> None:
        _reset_notice_state_for_tests()
        self._env_patcher.stop()
        self._env_tmp.cleanup()

    def test_untrusted_project_emits_notice_once_and_preserves_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proj = _make_adopted_proj(Path(tmp) / "untrusted_proj")
            target1 = proj / "note1.md"

            pre1 = on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(target1), "content": "# 1"},
                tool_call_id="tc_u1",
            )
            self.assertIsNone(pre1)
            self.assertIsNotNone(get_last_hook_skip_reason())

            raw_json_res = json.dumps({"verified": True, "path": str(target1)})
            out1 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target1), "content": "# 1"},
                result=raw_json_res,
                tool_call_id="tc_u1",
            )
            self.assertIsNotNone(out1)
            assert out1 is not None
            parsed1 = json.loads(out1)
            self.assertEqual(parsed1["path"], str(target1))
            self.assertNotIn("placed_by_adopt", parsed1)
            self.assertIn("defuzz_notice", parsed1)
            notice = parsed1["defuzz_notice"]
            self.assertEqual(
                notice,
                f"[defuzz: automatic file placement is OFF for {proj}: project is not trusted yet. "
                f"Do not run the trust command yourself; tell the user they can turn it on with: hermes defuzz trust {proj}]",
            )
            self.assertNotIn("\n", notice)

            # Second write in the same untrusted root -> silent (throttled)
            target2 = proj / "note2.md"
            pre2 = on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(target2), "content": "# 2"},
                tool_call_id="tc_u2",
            )
            self.assertIsNone(pre2)
            out2 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target2), "content": "# 2"},
                result=json.dumps({"verified": True, "path": str(target2)}),
                tool_call_id="tc_u2",
            )
            self.assertIsNone(out2)

    def test_rules_changed_after_trust_emits_changed_phrase_and_plain_text_appends_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proj = _make_adopted_proj(Path(tmp) / "edited_proj")
            trust_project(proj)

            # Edit .adopt/rules.json after trust
            rules_path = proj / ".adopt" / "rules.json"
            data = json.loads(rules_path.read_text(encoding="utf-8"))
            data["placement_rules"].append(
                {
                    "kind": "txt",
                    "match_ext": [".txt"],
                    "dest_dir": "docs",
                    "lfs": False,
                    "reason": "txt",
                }
            )
            rules_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

            target = proj / "draft.md"
            pre = on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(target), "content": "hello"},
                tool_call_id="tc_edit_1",
            )
            self.assertIsNone(pre)
            self.assertIn("hash mismatch", (get_last_hook_skip_reason() or "").lower())

            plain_res = "Wrote 5 bytes to draft.md"
            out = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target), "content": "hello"},
                result=plain_res,
                tool_call_id="tc_edit_1",
            )
            self.assertIsNotNone(out)
            assert out is not None
            expected_notice = (
                f"[defuzz: automatic file placement is OFF for {proj}: "
                f"its rules file changed since it was trusted. "
                f"Do not run the trust command yourself; tell the user they can turn it on with: hermes defuzz trust {proj}]"
            )
            self.assertEqual(out, f"{plain_res}\n{expected_notice}")

            # Subsequent write in the same root is throttled
            target2 = proj / "draft2.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target2), "content": "hello2"},
                    tool_call_id="tc_edit_2",
                )
            )
            self.assertIsNone(
                on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(target2), "content": "hello2"},
                    result="Wrote 6 bytes",
                    tool_call_id="tc_edit_2",
                )
            )

    def test_trusted_project_places_normally_without_skip_notice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proj = _make_adopted_proj(Path(tmp) / "trusted_proj")
            trust_project(proj)

            target = proj / "guide.md"
            pre = on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(target), "content": "# Guide"},
                tool_call_id="tc_ok",
            )
            self.assertIsNotNone(pre)
            assert pre is not None
            self.assertEqual(pre["action"], "modify")
            placed_path = Path(pre["args"]["path"])
            self.assertEqual(placed_path, proj / "docs" / "guide.md")
            placed_path.write_text("# Guide\n", encoding="utf-8")

            out = on_transform_tool_result(
                tool_name="write_file",
                args=pre["args"],
                result=json.dumps({"verified": True, "path": str(placed_path)}),
                tool_call_id="tc_ok",
            )
            self.assertIsNotNone(out)
            assert out is not None
            parsed = json.loads(out)
            self.assertIn("placed_by_adopt", parsed)
            self.assertNotIn("defuzz_notice", parsed)

    def test_no_notice_when_not_write_file_existing_file_no_root_or_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            proj = _make_adopted_proj(base / "untrusted_proj")
            existing = proj / "existing.md"
            existing.write_text("already here\n", encoding="utf-8")
            outside = base / "outside" / "note.md"

            # 1. Non-write_file tool
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="read_file",
                    args={"path": str(proj / "new.md")},
                    tool_call_id="tc_read",
                )
            )
            self.assertIsNone(
                on_transform_tool_result(
                    tool_name="read_file",
                    args={"path": str(proj / "new.md")},
                    result="{}",
                    tool_call_id="tc_read",
                )
            )

            # 2. Existing file inside untrusted adopted root
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(existing), "content": "edit"},
                    tool_call_id="tc_exist",
                )
            )
            self.assertIsNone(
                on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(existing), "content": "edit"},
                    result=json.dumps({"verified": True}),
                    tool_call_id="tc_exist",
                )
            )

            # 3. No adopted root
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(outside), "content": "new"},
                    tool_call_id="tc_out",
                )
            )
            self.assertIsNone(
                on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(outside), "content": "new"},
                    result=json.dumps({"verified": True}),
                    tool_call_id="tc_out",
                )
            )

            # 4. auto_place_enabled=False
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(proj / "disabled.md"), "content": "new"},
                    tool_call_id="tc_dis",
                    auto_place_enabled=False,
                )
            )
            self.assertIsNone(
                on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(proj / "disabled.md"), "content": "new"},
                    result=json.dumps({"verified": True}),
                    tool_call_id="tc_dis",
                )
            )

    def test_unexpected_exception_emits_error_notice_once_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proj = _make_adopted_proj(Path(tmp) / "err_proj")
            trust_project(proj)

            target1 = proj / "boom1.md"
            with mock.patch.object(
                placer_mod,
                "resolve_placement_for_new_path",
                side_effect=RuntimeError("secret internal detail"),
            ):
                pre1 = on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target1), "content": "x"},
                    tool_call_id="tc_err1",
                )
                self.assertIsNone(pre1)

                out1 = on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(target1), "content": "x"},
                    result=json.dumps({"verified": True, "path": str(target1)}),
                    tool_call_id="tc_err1",
                )
                self.assertIsNotNone(out1)
                assert out1 is not None
                parsed1 = json.loads(out1)
                self.assertEqual(
                    parsed1.get("defuzz_notice"),
                    "[defuzz: automatic file placement skipped for this write (RuntimeError)]",
                )
                self.assertNotIn("secret internal detail", out1)

                # Second unexpected error in the same root is throttled
                target2 = proj / "boom2.md"
                pre2 = on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target2), "content": "y"},
                    tool_call_id="tc_err2",
                )
                self.assertIsNone(pre2)
                out2 = on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(target2), "content": "y"},
                    result=json.dumps({"verified": True, "path": str(target2)}),
                    tool_call_id="tc_err2",
                )
                self.assertIsNone(out2)

    def test_root_with_newline_in_name_omits_path_from_notice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            weird_root = _make_adopted_proj(Path(tmp) / "proj_with\nnewline")
            target = weird_root / "note.md"

            pre = on_pre_tool_call(
                tool_name="write_file",
                args={"path": str(target), "content": "hi"},
                tool_call_id="tc_nl",
            )
            self.assertIsNone(pre)

            out = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target), "content": "hi"},
                result="Wrote file",
                tool_call_id="tc_nl",
            )
            self.assertIsNotNone(out)
            assert out is not None
            notice_line = out.split("\n", 1)[1]
            self.assertNotIn("\n", notice_line)
            self.assertNotIn(str(weird_root), notice_line)
            self.assertIn("automatic file placement is OFF", notice_line)
            self.assertIn("project is not trusted yet", notice_line)
            self.assertIn("hermes defuzz trust", notice_line)

    def test_throttle_cache_evicts_oldest_beyond_256_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            first_root = _make_adopted_proj(base / "root_0")

            # Trigger notice for root_0
            t0 = first_root / "a.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(t0), "content": "0"},
                    tool_call_id="tc_0",
                )
            )
            self.assertIsNotNone(
                on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(t0), "content": "0"},
                    result="ok",
                    tool_call_id="tc_0",
                )
            )

            # Fill 256 more distinct roots in the throttle set to evict root_0
            for i in range(1, 257):
                fake_root = base / f"root_{i}"
                placer_mod._record_notified_root(placer_mod._NOTIFIED_TRUST_ROOTS, str(fake_root))

            self.assertLessEqual(len(placer_mod._NOTIFIED_TRUST_ROOTS), 256)
            self.assertNotIn(str(first_root), placer_mod._NOTIFIED_TRUST_ROOTS)

            # Now root_0 notifies again because it was evicted
            t0_again = first_root / "b.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(t0_again), "content": "0"},
                    tool_call_id="tc_0_again",
                )
            )
            self.assertIsNotNone(
                on_transform_tool_result(
                    tool_name="write_file",
                    args={"path": str(t0_again), "content": "0"},
                    result="ok",
                    tool_call_id="tc_0_again",
                )
            )

    def test_f1_no_stale_or_duplicate_attachment_across_calls_and_empty_id_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proj = _make_adopted_proj(Path(tmp) / "f1_proj")
            target = proj / "same.md"

            # Call A (id 'a') is skipped and never delivers immediately
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target), "content": "A"},
                    tool_call_id="a",
                )
            )
            # Call B (id 'b') writes the same path in the same root (throttled -> stashes nothing)
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target), "content": "B"},
                    tool_call_id="b",
                )
            )
            # B's result carries NO notice
            out_b = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target), "content": "B"},
                result=json.dumps({"verified": True, "path": str(target)}),
                tool_call_id="b",
            )
            self.assertIsNone(out_b)

            # A's result is delivered and carries the notice exactly once
            out_a1 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target), "content": "A"},
                result=json.dumps({"verified": True, "path": str(target)}),
                tool_call_id="a",
            )
            self.assertIsNotNone(out_a1)
            assert out_a1 is not None
            self.assertIn("defuzz_notice", json.loads(out_a1))

            # Delivering A again carries nothing
            out_a2 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target), "content": "A"},
                result=json.dumps({"verified": True, "path": str(target)}),
                tool_call_id="a",
            )
            self.assertIsNone(out_a2)

            # Empty tool_call_id still gets its notice via the path key, once
            proj2 = _make_adopted_proj(Path(tmp) / "f1_proj2")
            target2 = proj2 / "noid.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target2), "content": "noid"},
                    tool_call_id="",
                )
            )
            out_noid1 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target2), "content": "noid"},
                result=json.dumps({"verified": True, "path": str(target2)}),
                tool_call_id="",
            )
            self.assertIsNotNone(out_noid1)
            assert out_noid1 is not None
            self.assertIn("defuzz_notice", json.loads(out_noid1))

            out_noid2 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target2), "content": "noid"},
                result=json.dumps({"verified": True, "path": str(target2)}),
                tool_call_id="",
            )
            self.assertIsNone(out_noid2)

    def test_f2_pending_skip_notices_bounded_to_64_with_oldest_eviction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for i in range(70):
                proj = _make_adopted_proj(base / f"proj_{i}")
                target = proj / "note.md"
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target), "content": str(i)},
                    tool_call_id=f"tc_{i}",
                )
            self.assertLessEqual(len(placer_mod._PENDING_SKIP_NOTICES), 64)
            self.assertEqual(len(placer_mod._PENDING_SKIP_NOTICES), 64)
            # Oldest 6 (0..5) evicted, 6..69 retained
            for i in range(6):
                self.assertNotIn(f"id:tc_{i}", placer_mod._PENDING_SKIP_NOTICES)
            for i in range(6, 70):
                self.assertIn(f"id:tc_{i}", placer_mod._PENDING_SKIP_NOTICES)

    def test_f3_c1_control_char_omits_path_while_space_and_non_ascii_keep_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            c1_root = _make_adopted_proj(base / "proj_\u0085_nel")
            t_c1 = c1_root / "note.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(t_c1), "content": "x"},
                    tool_call_id="tc_c1",
                )
            )
            out_c1 = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(t_c1), "content": "x"},
                result="ok",
                tool_call_id="tc_c1",
            )
            self.assertIsNotNone(out_c1)
            assert out_c1 is not None
            notice_c1 = out_c1.split("\n", 1)[1]
            self.assertNotIn(str(c1_root), notice_c1)
            self.assertEqual(
                notice_c1,
                "[defuzz: automatic file placement is OFF: project is not trusted yet. "
                "Do not run the trust command yourself; tell the user they can turn it on with: hermes defuzz trust]",
            )

            unicode_root = _make_adopted_proj(base / "café project")
            t_uni = unicode_root / "note.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(t_uni), "content": "x"},
                    tool_call_id="tc_uni",
                )
            )
            out_uni = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(t_uni), "content": "x"},
                result="ok",
                tool_call_id="tc_uni",
            )
            self.assertIsNotNone(out_uni)
            assert out_uni is not None
            notice_uni = out_uni.split("\n", 1)[1]
            self.assertIn(f"is OFF for {unicode_root}:", notice_uni)

    def test_f4_command_quotes_root_with_space_and_semicolon(self) -> None:
        import shlex

        with tempfile.TemporaryDirectory() as tmp:
            special_root = _make_adopted_proj(Path(tmp) / "my proj;ect")
            target = special_root / "note.md"
            self.assertIsNone(
                on_pre_tool_call(
                    tool_name="write_file",
                    args={"path": str(target), "content": "x"},
                    tool_call_id="tc_quote",
                )
            )
            out = on_transform_tool_result(
                tool_name="write_file",
                args={"path": str(target), "content": "x"},
                result="ok",
                tool_call_id="tc_quote",
            )
            self.assertIsNotNone(out)
            assert out is not None
            notice = out.split("\n", 1)[1]
            quoted = shlex.quote(str(special_root))
            self.assertNotEqual(quoted, str(special_root))
            self.assertEqual(
                notice,
                f"[defuzz: automatic file placement is OFF for {special_root}: project is not trusted yet. "
                f"Do not run the trust command yourself; tell the user they can turn it on with: hermes defuzz trust {quoted}]",
            )


if __name__ == "__main__":
    unittest.main()
