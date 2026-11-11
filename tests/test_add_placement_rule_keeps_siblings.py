"""Adding a rule for one extension takes only that extension away from other rules.

A rule that lists several extensions keeps the others, a narrower pattern rule (such as
decision records) keeps winning, and the declared folders stay consistent.
Every project here lives under pytest's tmp_path with its own state database.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.placer import (  # noqa: E402
    _reset_notice_state_for_tests,
    add_placement_rule,
    inspect_project_trust,
    resolve_placement_for_new_path,
    trust_project,
)
from hermes_plugins.defuzz.rules import validate_rules_spec  # noqa: E402

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
LAYERED = ("cpp-golden", "dotnet-golden", "go-golden", "python-golden", "rust-golden", "ts-node-golden")
DOCS_EXTS = [".md", ".rst", ".adoc", ".mmd", ".puml", ".drawio"]
ADR_GLOBS = ["adr-*.md", "ADR-*.md", "0[0-9][0-9][0-9]-*.md"]


@pytest.fixture(autouse=True)
def _fresh_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "hermes_home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    _reset_notice_state_for_tests()
    yield
    _reset_notice_state_for_tests()


def _project(tmp_path: Path, rules: List[Dict[str, Any]], declared: Optional[Sequence[str]] = None) -> tuple[Path, Path]:
    proj = tmp_path / "proj"
    (proj / ".adopt").mkdir(parents=True)
    if declared is None:
        declared = sorted({r["dest_dir"].split("/")[0] for r in rules})
    for d in declared:
        (proj / d).mkdir(parents=True, exist_ok=True)
    (proj / ".adopt" / "rules.json").write_text(
        json.dumps({
            "schema": 1,
            "schema_version": 1,
            "project_slug": "siblings",
            "declared_dirs": [{"dir": d, "summary": d, "why": d} for d in declared],
            "placement_rules": rules,
        }),
        encoding="utf-8",
    )
    db = tmp_path / "state.db"
    trust_project(proj, declared_only=True, db_path=db)
    return proj, db


def _rules(proj: Path) -> Dict[str, Any]:
    return json.loads((proj / ".adopt" / "rules.json").read_text(encoding="utf-8"))


def _where(proj: Path, rel: str) -> Optional[str]:
    res = resolve_placement_for_new_path(proj, rel, _rules(proj), mode="declared_only")
    return res["placed_rel"] if res else None


def _rule(kind: str, exts: List[str], dest: str, globs: Optional[List[str]] = None) -> Dict[str, Any]:
    r: Dict[str, Any] = {"kind": kind, "match_ext": exts, "dest_dir": dest, "lfs": False, "reason": f"{kind} here", "root_only": True}
    if globs:
        r["match_glob"] = globs
    return r


def _assert_valid_and_trusted(proj: Path, db: Path) -> None:
    data = _rules(proj)
    validate_rules_spec({**data, "folder_rules": data.get("folder_rules") or []})
    trust = inspect_project_trust(proj, db_path=db)
    assert trust["trusted"] is True, trust["reason"]
    dirs = [d["dir"] for d in _rules(proj)["declared_dirs"]]
    assert len(dirs) == len(set(dirs)), dirs


def test_single_extension_rule_is_replaced(tmp_path: Path) -> None:
    proj, db = _project(tmp_path, [_rule("docs", [".md"], "docs"), _rule("scripts", [".sh"], "scripts")])
    add_placement_rule(proj, ".md", "notes", db_path=db)
    kinds = [(r["kind"], r["match_ext"]) for r in _rules(proj)["placement_rules"]]
    assert kinds == [("custom_md", [".md"]), ("scripts", [".sh"])]
    assert _where(proj, "a.md") == "notes/a.md"
    assert _where(proj, "a.sh") == "scripts/a.sh"
    _assert_valid_and_trusted(proj, db)


def test_multi_extension_rule_is_narrowed_not_deleted(tmp_path: Path) -> None:
    proj, db = _project(tmp_path, [_rule("docs", list(DOCS_EXTS), "docs"), _rule("scripts", [".sh"], "scripts")])
    result = add_placement_rule(proj, ".md", "notes", db_path=db)
    rules = _rules(proj)["placement_rules"]
    assert [r["kind"] for r in rules] == ["custom_md", "docs", "scripts"]
    assert rules[1]["match_ext"] == [e for e in DOCS_EXTS if e != ".md"]
    assert _where(proj, "a.md") == "notes/a.md"
    for name in ("o.rst", "g.adoc", "f.mmd", "s.puml", "a.drawio"):
        assert _where(proj, name) == f"docs/{name}"
    msg = result["message"]
    assert "notes/" in msg and "docs/" in msg and ".md" in msg
    assert "\n" not in msg
    _assert_valid_and_trusted(proj, db)


def test_glob_rule_is_kept_and_still_wins(tmp_path: Path) -> None:
    proj, db = _project(
        tmp_path,
        [_rule("adr", [".md"], "docs/adr", ADR_GLOBS), _rule("docs", list(DOCS_EXTS), "docs")],
        declared=("docs",),
    )
    result = add_placement_rule(proj, ".md", "notes", db_path=db)
    rules = _rules(proj)["placement_rules"]
    assert [r["kind"] for r in rules] == ["adr", "custom_md", "docs"]
    assert rules[0]["match_glob"] == ADR_GLOBS and rules[0]["match_ext"] == [".md"]
    assert _where(proj, "0007-use-postgres.md") == "docs/adr/0007-use-postgres.md"
    assert _where(proj, "adr-x.md") == "docs/adr/adr-x.md"
    assert _where(proj, "a.md") == "notes/a.md"
    assert _where(proj, "o.rst") == "docs/o.rst"
    assert "docs/adr/" in result["message"]
    _assert_valid_and_trusted(proj, db)


def test_adding_the_same_rule_twice_is_idempotent(tmp_path: Path) -> None:
    proj, db = _project(tmp_path, [_rule("docs", list(DOCS_EXTS), "docs")])
    add_placement_rule(proj, ".md", "notes", db_path=db)
    first = _rules(proj)
    add_placement_rule(proj, ".md", "notes", db_path=db)
    assert _rules(proj) == first
    _assert_valid_and_trusted(proj, db)


def test_replacing_an_added_rule_drops_its_orphaned_folder(tmp_path: Path) -> None:
    proj, db = _project(tmp_path, [_rule("docs", list(DOCS_EXTS), "docs")])
    add_placement_rule(proj, ".md", "notes", db_path=db)
    add_placement_rule(proj, ".md", "wiki", db_path=db)
    dirs = [d["dir"] for d in _rules(proj)["declared_dirs"]]
    assert dirs == ["docs", "wiki"]
    assert _where(proj, "a.md") == "wiki/a.md"
    _assert_valid_and_trusted(proj, db)


def test_extension_no_rule_mentions(tmp_path: Path) -> None:
    proj, db = _project(tmp_path, [_rule("docs", list(DOCS_EXTS), "docs")])
    result = add_placement_rule(proj, ".fbx", "assets", db_path=db)
    rules = _rules(proj)["placement_rules"]
    assert [r["kind"] for r in rules] == ["custom_fbx", "docs"]
    assert rules[1]["match_ext"] == DOCS_EXTS
    assert "assets/" in result["message"]
    _assert_valid_and_trusted(proj, db)


CORPUS = ("notes.md", "0007-use-postgres.md", "adr-001.md", "overview.rst", "flow.mmd", "deploy.sh", "unit.test.ts")


def _template_project(tmp_path: Path, template_id: str) -> tuple[Path, Path]:
    raw = json.loads((TEMPLATES / template_id / "rules.json").read_text(encoding="utf-8"))
    rules = raw["placement_rules"]
    return _project(tmp_path, rules, declared=sorted({r["dest_dir"] for r in rules}))


@pytest.mark.parametrize("template_id", LAYERED + ("web-golden",))
def test_template_after_adding_md_rule(tmp_path: Path, template_id: str) -> None:
    proj, db = _template_project(tmp_path, template_id)
    before = {rel: _where(proj, rel) for rel in CORPUS}
    add_placement_rule(proj, ".md", "notes", db_path=db)
    after = {rel: _where(proj, rel) for rel in CORPUS}
    has_adr = template_id in ("python-golden", "ts-node-golden")
    expected = dict(before)
    expected["notes.md"] = "notes/notes.md"
    if not has_adr:
        expected["0007-use-postgres.md"] = "notes/0007-use-postgres.md"
        expected["adr-001.md"] = "notes/adr-001.md"
    else:
        assert before["0007-use-postgres.md"] == "docs/adr/0007-use-postgres.md"
    assert after == expected, (before, after)
    if template_id != "web-golden":
        assert after["overview.rst"] == "docs/overview.rst"
        assert after["deploy.sh"] == "scripts/deploy.sh"
    else:
        assert after["unit.test.ts"] == "tests/unit/unit.test.ts"
    _assert_valid_and_trusted(proj, db)
