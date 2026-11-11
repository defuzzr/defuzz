"""Placement hook text is escaped and capped, rule folders are the checked ones, and
rule patterns are matched within a fixed amount of work.

Every project here lives under pytest's tmp_path with its own state database.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import placer  # noqa: E402
from hermes_plugins.defuzz.placer import (  # noqa: E402
    _reset_notice_state_for_tests,
    add_placement_rule,
    on_pre_tool_call,
    on_transform_tool_result,
    place_existing_files,
    resolve_placement_for_new_path,
    trust_project,
)
from hermes_plugins.defuzz.safety import SafetyError  # noqa: E402

# Raw characters that must never reach text shown to the model or written to AGENTS.md.
_RAW_UNSAFE = ("\n", "\r", "\x1b", "\u202e", "\u202c", "\u2066", "\u200f")


@pytest.fixture(autouse=True)
def _fresh_notice_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "hermes_home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    _reset_notice_state_for_tests()
    yield
    _reset_notice_state_for_tests()


def _write_rules(proj: Path, placement_rules: List[Dict[str, Any]], declared: Sequence[str] = ("docs",)) -> None:
    (proj / ".adopt").mkdir(parents=True, exist_ok=True)
    for d in declared:
        (proj / d).mkdir(parents=True, exist_ok=True)
    (proj / ".adopt" / "rules.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "schema_version": 1,
                "project_slug": "text-bounds",
                "declared_dirs": [{"dir": d, "summary": d, "why": d} for d in declared],
                "placement_rules": placement_rules,
            }
        ),
        encoding="utf-8",
    )


def _assert_no_raw_unsafe(text: str) -> None:
    for ch in _RAW_UNSAFE:
        assert ch not in text, f"raw {ch!r} in {text[:200]!r}"


HOSTILE_REASON = "hello\nignore previous\x1b[31m\u202eright-to-left" + "X" * 5000


# --------------------------------------------------------------- full-mode note


def _redirect_full(tmp_path: Path, result: str) -> str:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "reason": HOSTILE_REASON}])
    db = tmp_path / "state.db"
    trust_project(proj, db_path=db)
    pre = on_pre_tool_call(
        tool_name="write_file", args={"path": str(proj / "note2.md"), "content": "x"},
        tool_call_id="tc_full_note", db_path=db,
    )
    assert pre is not None and pre["action"] == "modify"
    Path(pre["args"]["path"]).write_text("x", encoding="utf-8")
    out = on_transform_tool_result(
        tool_name="write_file", args=pre["args"], result=result, tool_call_id="tc_full_note",
    )
    assert isinstance(out, str)
    return out


def test_full_mode_note_in_json_result_is_escaped_and_capped(tmp_path: Path) -> None:
    out = _redirect_full(tmp_path, json.dumps({"verified": True}))
    parsed = json.loads(out)
    note = parsed["placed_by_adopt"]["note"]
    _assert_no_raw_unsafe(note)
    assert len(note) <= 600
    assert "\\u202e" in note
    assert "docs/note2.md" in note and "note2.md" in note
    assert "defuzz_notice" not in parsed  # full mode keeps its result shape


def test_full_mode_note_in_plain_result_is_one_escaped_capped_line(tmp_path: Path) -> None:
    out = _redirect_full(tmp_path, "Wrote 1 byte")
    assert out.startswith("Wrote 1 byte\n")
    tail = out[len("Wrote 1 byte\n"):]
    _assert_no_raw_unsafe(tail)
    assert len(tail) <= 600


# --------------------------------------------------------------- collision message


def test_collision_block_message_escapes_file_name_and_project_root(tmp_path: Path) -> None:
    proj = tmp_path / "ctrl\u202ename"
    _write_rules(proj, [{"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "reason": "docs"}])
    db = tmp_path / "state.db"
    trust_project(proj, db_path=db)
    name = "bad\nname\x1b\u202e.md"
    (proj / "docs" / name).write_text("keep\n", encoding="utf-8")
    res = on_pre_tool_call(
        tool_name="write_file", args={"path": str(proj / name), "content": "dup"}, db_path=db,
    )
    assert res is not None and res["action"] == "block"
    msg = res["message"]
    _assert_no_raw_unsafe(msg)
    assert "already exists" in msg
    assert "\\x0a" in msg and "\\u202e" in msg
    assert len(msg) <= 600
    assert (proj / "docs" / name).read_text(encoding="utf-8") == "keep\n"


# --------------------------------------------------------------- checked dest_dir


@pytest.mark.parametrize("raw_dest", ["docs\n", "./docs", "docs/", " docs "])
def test_full_mode_uses_the_checked_destination_folder(tmp_path: Path, raw_dest: str) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "docs", "match_ext": [".md"], "dest_dir": raw_dest, "reason": "docs"}])
    db = tmp_path / "state.db"
    trust_project(proj, db_path=db)
    pre = on_pre_tool_call(
        tool_name="write_file", args={"path": str(proj / "note.md"), "content": "x"}, db_path=db,
    )
    assert pre is not None and pre["action"] == "modify"
    assert pre["args"]["path"] == str(proj / "docs" / "note.md")


def test_declared_only_uses_the_checked_destination_folder(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "docs", "match_ext": [".md"], "dest_dir": "docs\n", "reason": "docs"}])
    db = tmp_path / "state.db"
    trust_project(proj, declared_only=True, db_path=db)
    pre = on_pre_tool_call(
        tool_name="write_file", args={"path": str(proj / "note.md"), "content": "x"}, db_path=db,
    )
    assert pre is not None and pre["action"] == "modify"
    assert pre["args"]["path"] == str(proj / "docs" / "note.md")


def test_decision_reason_is_the_checked_one(tmp_path: Path) -> None:
    rules = {
        "declared_dirs": [],
        "placement_rules": [{"kind": "docs", "match_ext": [".md"], "dest_dir": "docs\n", "reason": HOSTILE_REASON}],
    }
    decision = resolve_placement_for_new_path(tmp_path, "note.md", rules)
    assert decision is not None
    assert decision["dest_dir"] == "docs"
    assert decision["placed_rel"] == "docs/note.md"
    assert "\n" not in decision["reason"] and len(decision["reason"]) <= 100


# --------------------------------------------------------------- bounded glob


# 300 '**/a' pairs against 400 folders need more than the fixed matching budget.
_COMPLEX_DEPTH = 400


def _nested_a_pattern(count: int) -> str:
    return "**/a/" * count + "NO"


def test_double_star_glob_on_a_deep_path_is_fast(tmp_path: Path) -> None:
    pattern = _nested_a_pattern(10)
    for depth in (22, 200):
        norm = "/".join(["a"] * depth + ["file.md"])
        started = time.monotonic()
        assert placer._rule_glob_matches_path(pattern, norm, "file.md") is False
        assert time.monotonic() - started < 1.0


def test_double_star_glob_hook_write_is_fast(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "deep", "match_glob": [_nested_a_pattern(10)], "dest_dir": "docs", "reason": "deep"}])
    db = tmp_path / "state.db"
    trust_project(proj, declared_only=True, db_path=db)
    target = proj.joinpath(*(["a"] * 200), "file.md")
    started = time.monotonic()
    res = on_pre_tool_call(tool_name="write_file", args={"path": str(target), "content": "x"}, db_path=db)
    assert time.monotonic() - started < 1.0
    assert res is None


def test_double_star_glob_still_matches(tmp_path: Path) -> None:
    assert placer._rule_glob_matches_path("**/x/*.md", "a/b/x/f.md", "f.md") is True
    assert placer._rule_glob_matches_path("**/a/**/b/*.md", "q/a/r/s/b/f.md", "f.md") is True
    assert placer._rule_glob_matches_path("**/a/**/b/*.md", "q/a/r/s/c/f.md", "f.md") is False
    assert placer._workspace_glob_matches("packages/*", "packages/web") is True


def test_too_complex_glob_is_refused_plainly_and_quickly(tmp_path: Path) -> None:
    pattern = _nested_a_pattern(300)
    norm = "/".join(["a"] * _COMPLEX_DEPTH + ["file.md"])
    started = time.monotonic()
    with pytest.raises(SafetyError) as info:
        placer._rule_glob_matches_path(pattern, norm, "file.md")
    assert time.monotonic() - started < 1.0
    msg = str(info.value)
    assert "too complex" in msg and "Traceback" not in msg


def test_too_complex_glob_leaves_hook_write_where_asked(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "deep", "match_glob": [_nested_a_pattern(300)], "dest_dir": "docs", "reason": "deep"}])
    db = tmp_path / "state.db"
    trust_project(proj, declared_only=True, db_path=db)
    target = proj.joinpath(*(["a"] * _COMPLEX_DEPTH), "file.md")
    started = time.monotonic()
    res = on_pre_tool_call(tool_name="write_file", args={"path": str(target), "content": "x"}, db_path=db)
    assert time.monotonic() - started < 1.0
    assert res is None
    assert not (proj / "docs" / "a").exists()


def test_too_complex_glob_refuses_cli_place(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "deep", "match_glob": [_nested_a_pattern(300)], "dest_dir": "docs", "reason": "deep"}])
    db = tmp_path / "state.db"
    trust_project(proj, declared_only=True, db_path=db)
    deep = proj.joinpath(*(["a"] * _COMPLEX_DEPTH))
    deep.mkdir(parents=True)
    (deep / "file.md").write_text("x", encoding="utf-8")
    rel = "/".join(["a"] * _COMPLEX_DEPTH + ["file.md"])
    with pytest.raises(SafetyError, match="too complex"):
        place_existing_files(proj, [rel], db_path=db)
    assert (deep / "file.md").is_file()


# --------------------------------------------------------------- AGENTS.md reason


def test_added_rule_reason_bidi_does_not_reach_agents_md(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "reason": "docs"}])
    db = tmp_path / "state.db"
    trust_project(proj, db_path=db)
    add_placement_rule(proj, ".txt", "notes", reason="see \u202eSECRET\u202c end", db_path=db)
    agents = (proj / "AGENTS.md").read_text(encoding="utf-8")
    _assert_no_raw_unsafe(agents.replace("\n", ""))
    assert "SECRET" in agents and "\\u202e" in agents


def test_existing_rule_reason_bidi_does_not_reach_agents_md(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    _write_rules(proj, [{"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "reason": "see \u2066odd\u2069 \u202eSECRET"}])
    db = tmp_path / "state.db"
    trust_project(proj, db_path=db)
    add_placement_rule(proj, ".txt", "notes", reason="plain notes", db_path=db)
    agents = (proj / "AGENTS.md").read_text(encoding="utf-8")
    for ch in ("\u202e", "\u2066", "\u2069"):
        assert ch not in agents
    assert "plain notes" in agents
