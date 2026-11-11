"""Root-write cases shared by the six layered templates (imported, not collected).

python-golden, rust-golden, go-golden, cpp-golden, dotnet-golden and ts-node-golden
route the same kinds of root writes the same way:

- notes, guides and diagram sources (``.md .rst .adoc .mmd .puml .drawio``) go to
  ``docs/``, numbered decision records (``adr-*.md``, ``0003-*.md``) to ``docs/adr/``
  where the template has that folder;
- shell and PowerShell scripts (``.sh .bash .ps1``) go to ``scripts/``;
- ``TODO.md``, ``ROADMAP.md`` and ``RELEASING.md`` are ordinary notes;
- the shared well-known root files stay at the root;
- loose sources, tests and assets stay where they were written, since the root cannot
  tell which package, crate, project or library owns them.

Each per-template test file adds its own rows to ``shared_root_writes(...)``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.placer import (  # noqa: E402
    _reset_notice_state_for_tests,
    on_pre_tool_call,
    on_transform_tool_result,
    resolve_placement_for_new_path,
)
from hermes_plugins.defuzz.templates import TemplateSpec  # noqa: E402
from tests.toolchain_needs import need_template_tools  # noqa: E402

STAY: None = None

LAYERED_TEMPLATES: tuple[str, ...] = (
    "python-golden",
    "rust-golden",
    "go-golden",
    "cpp-golden",
    "dotnet-golden",
    "ts-node-golden",
)

DOC_EXTS: tuple[str, ...] = (".md", ".rst", ".adoc", ".mmd", ".puml", ".drawio")
SCRIPT_EXTS: tuple[str, ...] = (".sh", ".bash", ".ps1")
DOC_REASON = "Notes, guides and diagram sources live in docs/ in this workspace"
SCRIPT_REASON = "Shell and PowerShell scripts live in scripts/ in this workspace"
ADR_REASON = (
    "Decision records such as adr-0003-name.md or 0003-name.md live in docs/adr/ in this workspace"
)
ADR_GLOBS: tuple[str, ...] = ("adr-*.md", "ADR-*.md", "0[0-9][0-9][0-9]-*.md")

# Root files that are not in the shared well-known list but are read from the root by
# agent hosts and community tools; every layered template protects the same set.
COMMON_EXTRA_PROTECTED: tuple[str, ...] = (
    "AGENT.md",
    "WARP.md",
    "QWEN.md",
    "CRUSH.md",
    "DCO.md",
    "ACKNOWLEDGMENTS.md",
)

SCRIPT_WRITES: tuple[tuple[str, str], ...] = (
    ("deploy.sh", "scripts/deploy.sh"),
    ("bootstrap.sh", "scripts/bootstrap.sh"),
    ("release.bash", "scripts/release.bash"),
    ("setup.ps1", "scripts/setup.ps1"),
    ("Install Tools.ps1", "scripts/Install Tools.ps1"),
    ("ci-local.SH", "scripts/ci-local.SH"),
)

DOC_WRITES: tuple[tuple[str, str], ...] = (
    ("architecture.md", "docs/architecture.md"),
    ("design notes.md", "docs/design notes.md"),
    ("API.MD", "docs/API.MD"),
    ("runbook.md", "docs/runbook.md"),
    ("说明.md", "docs/说明.md"),
    ("guide.rst", "docs/guide.rst"),
    ("onboarding.adoc", "docs/onboarding.adoc"),
    ("layers.mmd", "docs/layers.mmd"),
    ("sequence.puml", "docs/sequence.puml"),
    ("context.drawio", "docs/context.drawio"),
    ("2026-review.md", "docs/2026-review.md"),
    ("123-not-numbered-adr.md", "docs/123-not-numbered-adr.md"),
    # Ordinary notes: not in the shared well-known list.
    ("TODO.md", "docs/TODO.md"),
    ("ROADMAP.md", "docs/ROADMAP.md"),
    ("RELEASING.md", "docs/RELEASING.md"),
    ("SUPPORTED_VERSIONS.md", "docs/SUPPORTED_VERSIONS.md"),
)

ADR_NAMES: tuple[str, ...] = ("adr-0002-storage.md", "ADR-0005-auth.md", "0003-storage-choice.md")

# Shared well-known root files (rules.WELLKNOWN_ROOT_FILES) plus the common extra set.
WELLKNOWN_STAYS: tuple[str, ...] = (
    "AUTHORS.md",
    "AUTHORS.rst",
    "CONTRIBUTORS.md",
    "MAINTAINERS.md",
    "GOVERNANCE.md",
    "SUPPORT.md",
    "HISTORY.md",
    "HISTORY.adoc",
    "NEWS.md",
    "CHANGES.md",
    "UPGRADING.md",
    "MIGRATING.md",
    "GEMINI.md",
    "COPILOT.md",
    "CONVENTIONS.md",
    "CLAUDE.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "PULL_REQUEST_TEMPLATE.md",
    "ISSUE_TEMPLATE.md",
    "THIRD_PARTY_NOTICES.md",
    "CODEOWNERS",
    "CITATION.cff",
    "FUNDING.yml",
    "LICENSE",
    "LICENSE.md",
    "README.rst",
    "llms.txt",
    ".cursorrules",
    *COMMON_EXTRA_PROTECTED,
)

# Loose sources, tests and assets: no single owner, so they stay where written.
AMBIGUOUS_STAYS: tuple[str, ...] = (
    "helper.py",
    "test_widget.py",
    "main.go",
    "widget_test.go",
    "lib.rs",
    "widget_test.rs",
    "helper.cpp",
    "helper.hpp",
    "Helper.cs",
    "WidgetTests.cs",
    "helper.ts",
    "widget.test.ts",
    "seed.mjs",
    "logo.png",
    "diagram.svg",
    "seed.csv",
    "fixture.json",
    "notes.txt",
    "0003-name.txt",
    ".deploy.sh",
    ".notes.md",
    ".env.local",
)


def shared_root_writes(has_adr_dir: bool) -> tuple[tuple[str, Optional[str]], ...]:
    """The shared block: (root write, expected final path or STAY)."""
    adr_dest = "docs/adr" if has_adr_dir else "docs"
    return (
        *SCRIPT_WRITES,
        *DOC_WRITES,
        *((name, f"{adr_dest}/{name}") for name in ADR_NAMES),
        *((name, STAY) for name in WELLKNOWN_STAYS),
        *((name, STAY) for name in AMBIGUOUS_STAYS),
    )


def build_table(
    has_adr_dir: bool, specific: Iterable[tuple[str, Optional[str]]]
) -> tuple[tuple[str, Optional[str]], ...]:
    """The shared block followed by a template's own rows; no name may repeat."""
    table = (*shared_root_writes(has_adr_dir), *specific)
    names = [rel for rel, _ in table]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"Rows repeated between the shared block and the template rows: {dupes}"
    return table


_PLAIN_WORDS = re.compile(r"^[A-Za-z0-9 ./_\-,'()]+$")


def is_plain_reason(reason: str) -> bool:
    return (
        10 <= len(reason) <= 100
        and "\n" not in reason
        and reason.isascii()
        and bool(_PLAIN_WORDS.match(reason))
        and not any(w in reason.lower() for w in ("glob", "regex", "hook", "precedence", "fnmatch"))
    )


def assert_shared_rules(raw_rules: dict[str, Any], has_adr_dir: bool) -> None:
    """The rules file routes docs, scripts (and decision records) the shared way."""
    declared = {d["dir"] for d in raw_rules["declared_dirs"]}
    assert {"docs", "scripts"} <= declared
    assert ("docs/adr" in declared) is has_adr_dir
    by_kind = {pr["kind"]: pr for pr in raw_rules["placement_rules"]}
    assert set(by_kind) == ({"adr", "docs", "scripts"} if has_adr_dir else {"docs", "scripts"})
    for pr in raw_rules["placement_rules"]:
        assert pr["root_only"] is True and pr["source"] == "explicit", pr
        assert pr["dest_dir"] in declared, pr
        assert is_plain_reason(pr["reason"]), pr["reason"]
        assert "**" not in "".join(pr.get("match_glob") or [])
    assert tuple(by_kind["docs"]["match_ext"]) == DOC_EXTS
    assert by_kind["docs"]["reason"] == DOC_REASON and by_kind["docs"]["dest_dir"] == "docs"
    assert tuple(by_kind["scripts"]["match_ext"]) == SCRIPT_EXTS
    assert by_kind["scripts"]["reason"] == SCRIPT_REASON
    assert by_kind["scripts"]["dest_dir"] == "scripts"
    if has_adr_dir:
        assert tuple(by_kind["adr"]["match_glob"]) == ADR_GLOBS
        assert by_kind["adr"]["reason"] == ADR_REASON
        assert by_kind["adr"]["dest_dir"] == "docs/adr"
        kinds = [pr["kind"] for pr in raw_rules["placement_rules"]]
        assert kinds.index("adr") < kinds.index("docs"), "decision records must match first"
    protected = list(raw_rules.get("protected_root_files") or [])
    for name in COMMON_EXTRA_PROTECTED:
        assert name in protected, name


def route_write(dest: Path, db: Path, rel: str, tc_id: str, content: str = "x\n") -> Optional[dict]:
    return on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(dest / rel), "content": content},
        tool_call_id=tc_id,
        db_path=db,
    )


def finish_write(pre: dict, tc_id: str, content: str = "x\n") -> str:
    """Write the redirected file, run the result hook and return its notice."""
    placed = Path(pre["args"]["path"])
    placed.parent.mkdir(parents=True, exist_ok=True)
    placed.write_text(content, encoding="utf-8")
    out = on_transform_tool_result(
        tool_name="write_file",
        args=pre["args"],
        result=json.dumps({"verified": True, "resolved_path": str(placed)}),
        tool_call_id=tc_id,
    )
    assert out is not None
    return json.loads(out)["defuzz_notice"]


def run_root_write_table(
    dest: Path,
    db: Path,
    rules_data: dict[str, Any],
    table: Sequence[tuple[str, Optional[str]]],
    tc_prefix: str,
) -> int:
    """Drive every root write through the hooks; return how many were moved."""
    assert len(table) >= 40
    _reset_notice_state_for_tests()
    reasons = {pr["reason"] for pr in rules_data["placement_rules"]}
    moved = 0
    wrongly_moved: list[str] = []
    for idx, (rel, expected) in enumerate(table):
        # A row that must stay may name a file the template ships (rewriting it stays put).
        if expected is not STAY or rel in {r for r, _ in shared_root_writes(True)}:
            assert not (dest / rel).exists(), f"{rel!r} already exists in the scaffold"
        tc_id = f"{tc_prefix}_{idx}"
        pre = route_write(dest, db, rel, tc_id)
        if expected is STAY:
            if pre is not None:
                wrongly_moved.append(f"{rel} -> {pre['args']['path']}")
            continue
        assert pre is not None and pre.get("action") == "modify", f"{rel!r}: {pre!r}"
        placed = Path(pre["args"]["path"])
        assert placed.relative_to(dest).as_posix() == expected, rel
        try:
            notice = finish_write(pre, tc_id)
            used = [r for r in reasons if r in notice]
            assert used and all(is_plain_reason(r) for r in used), notice
            assert expected in notice and "\n" not in notice
        finally:
            placed.unlink(missing_ok=True)
        moved += 1
    assert wrongly_moved == [], f"These must stay at the root: {wrongly_moved}"
    assert moved == sum(1 for _, e in table if e is not STAY)
    return moved


def assert_stays_in_both_modes(dest: Path, rules_data: dict[str, Any], names: Iterable[str]) -> None:
    """Each name stays at the root in 'declared_only' mode and in 'full' mode."""
    for name in names:
        for mode in ("declared_only", "full"):
            got = resolve_placement_for_new_path(dest, name, rules_data, mode=mode)
            assert got is None, f"{name!r} would move in {mode} mode: {got!r}"


def own_check_writes(has_adr_dir: bool) -> tuple[tuple[str, str, str], ...]:
    """Ten real root writes (name, content, expected path) used before the own check."""
    adr_dest = "docs/adr" if has_adr_dir else "docs"
    return (
        ("overview.md", "# Overview\n\nNotes.\n", "docs/overview.md"),
        ("TODO.md", "# To do\n\n- Nothing yet.\n", "docs/TODO.md"),
        ("guide.rst", "Guide\n=====\n\nSteps.\n", "docs/guide.rst"),
        ("onboarding.adoc", "= Onboarding\n\nSteps.\n", "docs/onboarding.adoc"),
        ("layers.mmd", "graph TD\n  A --> B\n", "docs/layers.mmd"),
        (
            "0004-error-model.md",
            "# 0004: Error model\n\nDecision.\n",
            f"{adr_dest}/0004-error-model.md",
        ),
        ("deploy.sh", "#!/bin/sh\necho deploy\n", "scripts/deploy.sh"),
        ("lint.sh", "#!/bin/sh\necho lint\n", "scripts/lint.sh"),
        ("release.bash", "#!/usr/bin/env bash\necho release\n", "scripts/release.bash"),
        ("setup.ps1", "Write-Output 'setup'\n", "scripts/setup.ps1"),
    )


def run_own_check_after_routed_writes(
    spec: TemplateSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    has_adr_dir: bool,
    tc_prefix: str,
) -> None:
    """Create a real project, route the ten writes, then run the template's own check."""
    need_template_tools(spec)
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)
    _reset_notice_state_for_tests()
    db = tmp_path / "state.db"
    proposal = scaffolder.propose(
        spec,
        "routing-ci-app",
        {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging",
    )
    accepted = scaffolder.accept(
        proposal,
        register=lambda *_: json.dumps({"success": True, "id": "routing-ci-app"}),
        db_path=db,
        timeout_s=900,
    )
    assert accepted.repos[0]["check"] == "ok", accepted.repos[0]
    repo = Path(accepted.repos[0]["path"])
    writes = own_check_writes(has_adr_dir)
    assert len(writes) == 10 and any(exp.startswith("scripts/") for _, _, exp in writes)
    for idx, (name, content, expected) in enumerate(writes):
        tc_id = f"{tc_prefix}_{idx}"
        pre = route_write(repo, db, name, tc_id, content)
        assert pre is not None and pre.get("action") == "modify", name
        assert Path(pre["args"]["path"]).relative_to(repo).as_posix() == expected
        finish_write(pre, tc_id, content)
    for _, _, expected in writes:
        assert (repo / expected).is_file(), expected
    check = spec.repos[0].check
    assert check is not None
    cwd = repo if check.cwd == "." else repo / check.cwd
    for command in [list(c) for c in check.ci_commands()]:
        proc = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=900, check=False
        )
        assert proc.returncode == 0, f"{command}\n{proc.stdout[-4000:]}\n{proc.stderr[-4000:]}"


def slow_skip_marker() -> Any:
    return pytest.mark.skipif(os.environ.get("ADOPT_SKIP_SLOW") == "1", reason="ADOPT_SKIP_SLOW=1")
