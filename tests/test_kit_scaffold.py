"""Tests for kit_scaffold.py and AGENTS.md kit block preservation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import placer  # noqa: E402
from hermes_plugins.defuzz.agents_md import (  # noqa: E402
    render_from_rules,
    validate_agents_md,
    write_agents_md,
)
from hermes_plugins.defuzz.kit_scaffold import (  # noqa: E402
    KitProposal,
    KitUnavailable,
    accept_kit,
    discard_kit,
    propose_kit,
)
from hermes_plugins.defuzz.rules import validate_rules_spec  # noqa: E402
from hermes_plugins.defuzz.safety import run_git_hardened  # noqa: E402
from hermes_plugins.defuzz.scaffolder import AcceptResult, ScaffoldError, ScaffoldTimeout  # noqa: E402
from hermes_plugins.defuzz.state_store import get_project, state_db_path  # noqa: E402


# The recorded video-production kit (tests/fixtures/kit_contract/shows/), not a hand model.
from tests.fake_kit_bridge import (  # noqa: E402
    VIDEO_DECLARED_DIRS,
    VIDEO_KIT_BLOCK,
    VIDEO_PLACEMENT_RULES,
)


class FakeVideoBridge:
    """Fake componentize_bridge object creating a real video-production kit tree on disk."""

    def __init__(
        self,
        *,
        apply_status: str = "ok",
        apply_ok: bool = True,
        apply_env_status: str = "pass",
        apply_notice: str = "componentize kit apply pass.",
        apply_findings: Optional[List[Dict[str, Any]]] = None,
        check_status: str = "ok",
        check_ok: bool = True,
        check_env_status: str = "pass",
        check_notice: str = "componentize kit check pass.",
        check_findings: Optional[List[Dict[str, Any]]] = None,
        declared_dirs: Optional[List[Dict[str, str]]] = None,
        placement_rules: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.apply_status = apply_status
        self.apply_ok = apply_ok
        self.apply_env_status = apply_env_status
        self.apply_notice = apply_notice
        self.apply_findings = list(apply_findings) if apply_findings is not None else []
        self.check_status = check_status
        self.check_ok = check_ok
        self.check_env_status = check_env_status
        self.check_notice = check_notice
        self.check_findings = list(check_findings) if check_findings is not None else []
        self.declared_dirs = (
            [dict(d) for d in declared_dirs]
            if declared_dirs is not None
            else [dict(d) for d in VIDEO_DECLARED_DIRS]
        )
        self.placement_rules = (
            [dict(r) for r in placement_rules]
            if placement_rules is not None
            else [dict(r) for r in VIDEO_PLACEMENT_RULES]
        )
        self.apply_calls: List[Dict[str, Any]] = []
        self.check_calls: List[Dict[str, Any]] = []

    def kit_apply(
        self,
        kit_id: str,
        dest: Path | str,
        variables: Optional[Dict[str, str]] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        dest_path = Path(dest)
        self.apply_calls.append(
            {"kit_id": kit_id, "dest": dest_path, "variables": variables, "timeout": timeout}
        )
        if self.apply_status != "ok":
            return {
                "status": self.apply_status,
                "data": None,
                "notice": self.apply_notice,
                "exit": None if self.apply_status == "unavailable" else 2,
            }
        if not self.apply_ok or self.apply_env_status != "pass":
            return {
                "status": "ok",
                "data": {
                    "schema": "componentize.kit/1",
                    "ok": self.apply_ok,
                    "status": self.apply_env_status,
                    "error": None,
                    "findings": list(self.apply_findings),
                    "root": str(dest_path),
                    "kit": kit_id,
                    "items": [],
                    "declared_dirs": [dict(d) for d in self.declared_dirs],
                    "placement_rules": [dict(r) for r in self.placement_rules],
                },
                "notice": self.apply_notice,
                "exit": 1,
            }

        dest_path.mkdir(parents=True, exist_ok=True)
        items: List[Dict[str, str]] = []
        for entry in VIDEO_DECLARED_DIRS:
            rel_dir = entry["dir"]
            folder = dest_path / rel_dir
            folder.mkdir(parents=True, exist_ok=True)
            (folder / ".gitkeep").write_text("", encoding="utf-8")
            items.append({"path": rel_dir, "state": "created"})

        (dest_path / "assets" / "canon" / "CANON.md").write_text(
            "# Canon Reference\n", encoding="utf-8"
        )
        (dest_path / ".gitignore").write_text("*.tmp\n", encoding="utf-8")
        agents_text = f"# {dest_path.name}\n\n{VIDEO_KIT_BLOCK}\n"
        (dest_path / "AGENTS.md").write_text(agents_text, encoding="utf-8")

        return {
            "status": "ok",
            "data": {
                "schema": "componentize.kit/1",
                "ok": True,
                "status": "pass",
                "error": None,
                "findings": [],
                "root": str(dest_path),
                "kit": kit_id,
                "items": items,
                "declared_dirs": [dict(d) for d in self.declared_dirs],
                "placement_rules": [dict(r) for r in self.placement_rules],
            },
            "notice": self.apply_notice,
            "exit": 0,
        }

    def kit_check(self, kit_id: str, dest: Path | str, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        dest_path = Path(dest)
        self.check_calls.append({"kit_id": kit_id, "dest": dest_path, "timeout": timeout})
        if self.check_status != "ok":
            return {
                "status": self.check_status,
                "data": None,
                "notice": self.check_notice,
                "exit": None if self.check_status == "unavailable" else 2,
            }
        return {
            "status": "ok",
            "data": {
                "schema": "componentize.kit/1",
                "ok": self.check_ok,
                "status": self.check_env_status,
                "error": None,
                "findings": list(self.check_findings),
                "root": str(dest_path),
                "kit": kit_id,
                "items": [
                    {"path": d["dir"], "state": "present"} for d in self.declared_dirs
                ],
                "declared_dirs": [dict(d) for d in self.declared_dirs],
                "placement_rules": [dict(r) for r in self.placement_rules],
            },
            "notice": self.check_notice,
            "exit": 0 if (self.check_ok and self.check_env_status == "pass") else 1,
        }


def _fake_register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "hermes-kit-proj-1", "name": name, "path": path})


@pytest.fixture(autouse=True)
def _reset_placer_notices() -> None:
    placer._reset_notice_state_for_tests()


def test_propose_writes_nothing_at_dest_and_returns_tree(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeVideoBridge()
    answers = {"building": "video", "layout": "single", "languages": []}

    proposal = propose_kit(
        "video-production",
        "Launch Trailer",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        variables={"fps": "24"},
        bridge=bridge,
    )

    assert isinstance(proposal, KitProposal)
    assert proposal.kit_id == "video-production"
    assert proposal.slug == "launch-trailer"
    assert proposal.display_name == "Launch Trailer"
    assert proposal.dest == dest_root / "launch-trailer"
    assert not proposal.dest.exists()
    assert list(dest_root.iterdir()) == []
    assert proposal.staging_dir.is_dir()
    assert proposal.staged == proposal.staging_dir / "launch-trailer"
    assert proposal.staged.is_dir()
    assert "AGENTS.md" in proposal.tree
    assert ".gitignore" in proposal.tree
    assert "assets/canon/CANON.md" in proposal.tree
    for entry in VIDEO_DECLARED_DIRS:
        assert f"{entry['dir']}/" in proposal.tree
        assert f"{entry['dir']}/.gitkeep" in proposal.tree
    assert len(bridge.apply_calls) == 1
    assert bridge.apply_calls[0]["variables"] == {"fps": "24"}

    discard_kit(proposal)
    assert not proposal.staging_dir.exists()


def test_accept_creates_repo_rules_agents_and_enables_trusted_placement(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()
    bridge = FakeVideoBridge()
    answers = {"building": "video", "layout": "single", "languages": []}

    proposal = propose_kit(
        "video-production",
        "Launch Trailer",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge,
    )
    staging_dir = proposal.staging_dir
    dest = proposal.dest

    res = accept_kit(
        proposal,
        register=_fake_register,
        db_path=db_path,
        bridge=bridge,
    )

    # (b) destination created with kit folders, git repo with 1 commit, staging removed
    assert isinstance(res, AcceptResult)
    assert not staging_dir.exists()
    assert dest.is_dir()
    assert (dest / ".git").is_dir()
    for entry in VIDEO_DECLARED_DIRS:
        assert (dest / entry["dir"]).is_dir()
    assert (dest / "_inbox").is_dir()
    assert not (dest / "_archive").exists()
    assert (dest / "assets" / "canon" / "CANON.md").is_file()

    log_proc = run_git_hardened(dest, ["log", "--oneline"], check=True)
    commits = [ln for ln in log_proc.stdout.decode("utf-8").splitlines() if ln.strip()]
    assert len(commits) == 1

    assert len(res.repos) == 1
    repo_entry = res.repos[0]
    assert repo_entry["path"] == str(dest)
    assert repo_entry["registration"] == "registered"
    assert repo_entry["registration_result"] == {"registered": True, "reason": None}
    assert repo_entry["registration_name"] == "Launch Trailer"
    assert repo_entry["hermes_project_id"] == "hermes-kit-proj-1"
    assert repo_entry["template_id"] == "kit:video-production"
    assert repo_entry["kit_id"] == "video-production"
    assert repo_entry["rules_hash"] == placer.compute_rules_hash(dest)
    assert repo_entry["commit"]
    assert repo_entry["plugin_commit"]

    proj_row = get_project(dest, db_path=db_path)
    assert proj_row is not None
    assert proj_row["template_id"] == "kit:video-production"
    assert proj_row["rules_hash"] == placer.compute_rules_hash(dest)

    # (c) .adopt/rules.json passes validate_rules_spec and contains every kit folder & all 3 rules
    rules_path = dest / ".adopt" / "rules.json"
    assert rules_path.is_file()
    rules_data = json.loads(rules_path.read_text(encoding="utf-8"))
    validated = validate_rules_spec(rules_data)
    declared_names = [d["dir"] for d in validated["declared_dirs"]]
    for entry in VIDEO_DECLARED_DIRS:
        assert entry["dir"] in declared_names
    assert "_inbox" in declared_names
    assert "_archive" not in declared_names
    assert len(declared_names) == len(set(declared_names))
    assert len(validated["placement_rules"]) == len(VIDEO_PLACEMENT_RULES)
    by_kind = {r["kind"]: r for r in validated["placement_rules"]}
    for rule in VIDEO_PLACEMENT_RULES:
        assert by_kind[rule["kind"]]["dest_dir"] == rule["dest_dir"]
        assert sorted(by_kind[rule["kind"]]["match_ext"]) == sorted(rule["match_ext"])

    # (d) AGENTS.md contains the kit block byte-identical once; Defuzz Layout does not repeat kit folders
    agents_text = (dest / "AGENTS.md").read_text(encoding="utf-8")
    expected_video_agents = (
        "# launch-trailer\n"
        "\n"
        "<!-- defuzz schema_version: 1 -->\n"
        "<!-- Generated by defuzz from .adopt/rules.json. Do not edit by hand: it is rewritten whenever the rules change. -->\n"
        "\n"
        "## Purpose\n"
        "\n"
        "`launch-trailer` was set up by defuzz from the video-production kit. Its folders and rules are in the kit section below.\n"
        "\n"
        "## Layout\n"
        "\n"
        "- `_inbox/` — files with no placement rule are moved here; ask where they\n"
        "  belong, then move them\n"
        "\n"
        "## Conventions & constraints\n"
        "\n"
        "- Never delete files without approval.\n"
        "- New files are placed by the rules in `.adopt/rules.json`.\n"
        "- To start a project: run `hermes defuzz list`, show the user the list, wait for\n"
        "  their choice, then run `hermes defuzz new --template ID` or `--kit ID`. Never\n"
        "  choose for the user. Never create a project inside this one.\n"
        "- `.jpeg`, `.jpg`, `.png`, `.webp` files go in `assets/generated/` (unreviewed\n"
        "  generator output, approved by moving it out).\n"
        "- `.mkv`, `.mov`, `.mp4`, `.webm` files go in `renders/` (declared by the\n"
        "  video-production kit).\n"
        "- `.flac`, `.mp3`, `.ogg`, `.wav` files go in `audio/` (declared by the\n"
        "  video-production kit).\n"
        "- Git ignores `.adopt/place-log.json`, `.hermes/scratch/`, `.hermes/sessions/`.\n"
        "\n"
        "## Build & test\n"
        "\n"
        "- Not detected yet.\n"
        "\n"
        + VIDEO_KIT_BLOCK
        + "\n"
    )
    assert agents_text == expected_video_agents
    sections = validate_agents_md(agents_text)
    assert agents_text.count(VIDEO_KIT_BLOCK) == 1
    assert agents_text.endswith("\n\n" + VIDEO_KIT_BLOCK + "\n")
    defuzz_part = agents_text[: agents_text.index(VIDEO_KIT_BLOCK)]
    layout_section = next(s for s in sections if s["heading"] == "Layout")
    for entry in VIDEO_DECLARED_DIRS:
        assert f"- `{entry['dir']}/`" not in defuzz_part
        assert all(f"- `{entry['dir']}/`" not in ln for ln in layout_section["lines"])

    # (e) KEY TEST: automatic placement via placer.on_pre_tool_call
    assert placer.inspect_project_trust(dest, db_path=db_path)["trusted"] is True

    r_png = placer.on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(dest / "shot03.png"), "content": "frame"},
        tool_call_id="tc-png",
        db_path=db_path,
    )
    assert r_png == {
        "action": "modify",
        "args": {"path": str(dest / "assets" / "generated" / "shot03.png")},
    }

    r_mp4 = placer.on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(dest / "take1.mp4"), "content": "video"},
        tool_call_id="tc-mp4",
        db_path=db_path,
    )
    assert r_mp4 == {
        "action": "modify",
        "args": {"path": str(dest / "renders" / "take1.mp4")},
    }

    r_xyz = placer.on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(dest / "notes.xyz"), "content": "misc"},
        tool_call_id="tc-xyz",
        db_path=db_path,
    )
    assert r_xyz == {
        "action": "modify",
        "args": {"path": str(dest / "_inbox" / "notes.xyz")},
    }

    r_canon = placer.on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(dest / "assets" / "canon" / "ref.png"), "content": "canon"},
        tool_call_id="tc-canon",
        db_path=db_path,
    )
    assert r_canon is None
    assert placer.get_last_hook_skip_reason() is None
    assert (
        placer.on_transform_tool_result(
            tool_name="write_file",
            args={"path": str(dest / "assets" / "canon" / "ref.png")},
            result=json.dumps({"verified": True}),
            tool_call_id="tc-canon",
        )
        is None
    )

    # (f) Regenerating AGENTS.md later via placer.add_placement_rule and direct write_agents_md keeps kit block
    placer.add_placement_rule(
        dest,
        ".flac",
        "audio",
        kind="flac_audio",
        lfs=True,
        reason="Route lossless audio to audio",
        db_path=db_path,
    )
    agents_after_rule = (dest / "AGENTS.md").read_text(encoding="utf-8")
    validate_agents_md(agents_after_rule)
    assert agents_after_rule.count(VIDEO_KIT_BLOCK) == 1
    assert "`.flac`" in agents_after_rule
    defuzz_part_after = agents_after_rule[: agents_after_rule.index(VIDEO_KIT_BLOCK)]
    for entry in VIDEO_DECLARED_DIRS:
        assert f"- `{entry['dir']}/`" not in defuzz_part_after

    updated_rules = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    direct_res = write_agents_md(dest, updated_rules, preserve_kit_blocks=True)
    assert direct_res["kit_blocks_preserved"] == ["video-production"]
    assert direct_res["kit_blocks_dropped"] == []
    agents_after_direct = (dest / "AGENTS.md").read_text(encoding="utf-8")
    assert agents_after_direct.count(VIDEO_KIT_BLOCK) == 1

    # (g) Foreign kit block injected into a kit project's AGENTS.md is dropped on placer regeneration
    foreign_block = (
        "<!-- kit:foreign-kit v1 begin -->\n"
        "## Kit: Foreign\n"
        "- `foreign/`: untrusted block\n"
        "<!-- kit:foreign-kit end -->\n"
    )
    (dest / "AGENTS.md").write_text(
        agents_after_direct + "\n" + foreign_block,
        encoding="utf-8",
    )
    placer.add_placement_rule(
        dest,
        ".ogg",
        "audio",
        kind="ogg_audio",
        lfs=True,
        reason="Route ogg audio to audio",
        db_path=db_path,
    )
    agents_after_foreign = (dest / "AGENTS.md").read_text(encoding="utf-8")
    assert agents_after_foreign.count(VIDEO_KIT_BLOCK) == 1
    assert "foreign-kit" not in agents_after_foreign
    assert "Kit: Foreign" not in agents_after_foreign


def test_negative_paths_and_discard(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    answers = {"building": "video", "layout": "single", "languages": []}

    # 1. bridge 'unavailable' -> KitUnavailable, staging removed, nothing at destination
    unavail_bridge = FakeVideoBridge(
        apply_status="unavailable",
        apply_notice="componentize CLI is unavailable.",
    )
    with pytest.raises(KitUnavailable, match="componentize CLI is unavailable"):
        propose_kit(
            "video-production",
            "Unavailable Video",
            answers,
            dest_root=dest_root,
            staging_parent=staging_parent,
            bridge=unavail_bridge,
        )
    assert list(staging_parent.iterdir()) == []
    assert list(dest_root.iterdir()) == []

    # 2. bridge 'error' -> ScaffoldError, staging removed, nothing at destination
    err_bridge = FakeVideoBridge(
        apply_status="error",
        apply_notice="componentize kit apply error (exit 2): unknown kit",
    )
    with pytest.raises(ScaffoldError, match="unknown kit"):
        propose_kit(
            "video-production",
            "Error Video",
            answers,
            dest_root=dest_root,
            staging_parent=staging_parent,
            bridge=err_bridge,
        )
    assert list(staging_parent.iterdir()) == []
    assert list(dest_root.iterdir()) == []

    # 3. bridge fail envelope -> ScaffoldError with finding detail, staging removed
    fail_env_bridge = FakeVideoBridge(
        apply_ok=False,
        apply_env_status="fail",
        apply_notice="componentize kit apply fail.",
        apply_findings=[
            {
                "id": "conflict-file",
                "severity": "error",
                "detail": "assets/generated exists as a file where a folder is expected",
            }
        ],
    )
    with pytest.raises(
        ScaffoldError,
        match="assets/generated exists as a file where a folder is expected",
    ):
        propose_kit(
            "video-production",
            "Fail Envelope Video",
            answers,
            dest_root=dest_root,
            staging_parent=staging_parent,
            bridge=fail_env_bridge,
        )
    assert list(staging_parent.iterdir()) == []
    assert list(dest_root.iterdir()) == []

    # 4. destination already existing -> ScaffoldError at propose
    existing_dest = dest_root / "taken-video"
    existing_dest.mkdir()
    ok_bridge = FakeVideoBridge()
    with pytest.raises(ScaffoldError, match="Destination already exists"):
        propose_kit(
            "video-production",
            "Taken Video",
            answers,
            dest_root=dest_root,
            staging_parent=staging_parent,
            bridge=ok_bridge,
        )
    assert list(staging_parent.iterdir()) == []

    # 5. kit_check failing at accept -> ScaffoldError and staging kept
    check_fail_bridge = FakeVideoBridge(
        check_ok=False,
        check_env_status="fail",
        check_notice="componentize kit check fail.",
        check_findings=[
            {
                "id": "missing-dir",
                "severity": "error",
                "detail": "renders directory is missing",
            }
        ],
    )
    prop_check_fail = propose_kit(
        "video-production",
        "Check Fail Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=check_fail_bridge,
    )
    with pytest.raises(ScaffoldError, match="renders directory is missing"):
        accept_kit(prop_check_fail, register=_fake_register, bridge=check_fail_bridge)
    assert prop_check_fail.staging_dir.is_dir()
    assert not prop_check_fail.dest.exists()
    discard_kit(prop_check_fail)
    assert not prop_check_fail.staging_dir.exists()

    # 6. placement rule pointing at an undeclared folder -> ScaffoldError naming the rule at accept
    bad_rule_bridge = FakeVideoBridge(
        placement_rules=[
            *VIDEO_PLACEMENT_RULES,
            {
                "kind": " rogue_models ",
                "match_ext": [".glb"],
                "dest_dir": "assets/undeclared_3d",
                "lfs": True,
                "reason": "Points to undeclared folder",
            },
        ]
    )
    prop_bad_rule = propose_kit(
        "video-production",
        "Bad Rule Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bad_rule_bridge,
    )
    with pytest.raises(ScaffoldError, match="rogue_models"):
        accept_kit(prop_bad_rule, register=_fake_register, bridge=bad_rule_bridge)
    assert not prop_bad_rule.dest.exists()
    discard_kit(prop_bad_rule)
    assert not prop_bad_rule.staging_dir.exists()


def test_write_agents_md_without_kit_blocks_is_byte_identical_and_drops_malformed(
    tmp_path: Path,
) -> None:
    rules = {
        "project_slug": "plain-proj",
        "declared_dirs": [
            {"dir": "docs", "summary": "project docs", "why": "keep docs together"},
            {"dir": "_inbox", "summary": "unclassified incoming files", "why": "catch unknown file kinds"},
            {"dir": "_archive", "summary": "archived scratch", "why": "preserve retired bytes"},
        ],
        "placement_rules": [
            {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "markdown to docs"}
        ],
        "ignore_patterns": ["_archive/"],
        "lfs_patterns": [],
    }

    # (i) Folder without kit blocks is byte-identical to render_from_rules
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    expected_bytes = render_from_rules(rules)["AGENTS.md"].encode("utf-8")
    res_plain = write_agents_md(plain_dir, rules)
    assert res_plain["kit_blocks_preserved"] == []
    assert res_plain["kit_blocks_dropped"] == []
    assert (plain_dir / "AGENTS.md").read_bytes() == expected_bytes

    # Default preserve_kit_blocks=False ignores even well-formed kit blocks
    default_ignore_dir = tmp_path / "default-ignore"
    default_ignore_dir.mkdir()
    (default_ignore_dir / "AGENTS.md").write_text(
        f"# plain-proj\n\n{VIDEO_KIT_BLOCK}\n",
        encoding="utf-8",
    )
    res_default = write_agents_md(default_ignore_dir, rules)
    assert res_default["kit_blocks_preserved"] == []
    assert res_default["kit_blocks_dropped"] == []
    assert (default_ignore_dir / "AGENTS.md").read_bytes() == expected_bytes

    # Malformed block (begin without matching end) and duplicate ids are dropped and reported when preserve_kit_blocks=True
    malformed_dir = tmp_path / "malformed"
    malformed_dir.mkdir()
    (malformed_dir / "AGENTS.md").write_text(
        "# plain-proj\n\n"
        "<!-- kit:unclosed-kit v1 begin -->\n"
        "- `docs/`: should not be preserved\n\n"
        "<!-- kit:dup-kit v1 begin -->\n"
        "first dup\n"
        "<!-- kit:dup-kit end -->\n\n"
        "<!-- kit:dup-kit v1 begin -->\n"
        "second dup\n"
        "<!-- kit:dup-kit end -->\n",
        encoding="utf-8",
    )
    res_mal = write_agents_md(malformed_dir, rules, preserve_kit_blocks=True)
    assert res_mal["kit_blocks_preserved"] == []
    assert "unclosed-kit" in res_mal["kit_blocks_dropped"]
    assert "dup-kit" in res_mal["kit_blocks_dropped"]
    assert (malformed_dir / "AGENTS.md").read_bytes() == expected_bytes


def test_kit_blocks_preserved_in_order_and_excluded_from_line_budget(
    tmp_path: Path,
) -> None:
    block_one = (
        "<!-- kit:first-kit v1 begin -->\n"
        "### Layout\n"
        "- `renders/`: Rendered video takes\n"
        "<!-- kit:first-kit end -->"
    )
    block_two = (
        "<!-- kit:second-kit v2 begin (managed) -->\n"
        "### Layout\n"
        "- `audio/`: Audio stems\n"
        "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\nLine 7\nLine 8\nLine 9\nLine 10\n"
        "<!-- kit:second-kit end -->"
    )
    proj = tmp_path / "multi-kit"
    proj.mkdir()
    (proj / "AGENTS.md").write_text(
        f"# multi-kit\n\n{block_one}\n\n{block_two}\n",
        encoding="utf-8",
    )
    rules = {
        "project_slug": "multi-kit",
        "agents_md_max_lines": 40,
        "declared_dirs": [
            {"dir": "renders", "summary": "Rendered video takes", "why": "renders"},
            {"dir": "audio", "summary": "Audio stems", "why": "audio"},
            {"dir": "docs", "summary": "Project docs", "why": "docs"},
        ],
        "placement_rules": [],
    }
    res = write_agents_md(proj, rules, preserve_kit_blocks=True)
    assert res["kit_blocks_preserved"] == ["first-kit", "second-kit"]
    assert res["kit_blocks_dropped"] == []
    assert res["overflow"] is False

    text = (proj / "AGENTS.md").read_text(encoding="utf-8")
    validate_agents_md(text)
    assert text.endswith(f"\n\n{block_one}\n\n{block_two}\n")
    defuzz_part = text[: text.index(block_one)].rstrip("\n")
    assert len(defuzz_part.splitlines()) <= 40
    assert "- `renders/`" not in defuzz_part
    assert "- `audio/`" not in defuzz_part
    assert "- `docs/`" in defuzz_part
    sections = validate_agents_md(text)
    purpose_lines = next(s["lines"] for s in sections if s["heading"] == "Purpose")
    assert " ".join(purpose_lines) == (
        "`multi-kit` was set up by defuzz from the first-kit, second-kit kits. "
        "Its folders and rules are in the kit section below."
    )


def test_f1_damaged_or_missing_kit_section_fails_accept(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    answers = {"building": "video", "layout": "single", "languages": []}

    # Case 1: unclosed/damaged kit section in staged AGENTS.md
    bridge1 = FakeVideoBridge()
    prop1 = propose_kit(
        "video-production",
        "Damaged Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge1,
    )
    (prop1.staged / "AGENTS.md").write_text(
        "# damaged-video\n\n<!-- kit:video-production v1 begin -->\n## Kit: Video\n",
        encoding="utf-8",
    )
    with pytest.raises(ScaffoldError, match=r"AGENTS\.md.*missing or damaged") as exc1:
        accept_kit(prop1, register=_fake_register, bridge=bridge1)
    assert exc1.value.keep_staging is True
    assert prop1.staging_dir.is_dir()
    assert not prop1.dest.exists()
    discard_kit(prop1)

    # Case 2: proposal's kit id missing (different kit id present, no dropped blocks)
    bridge2 = FakeVideoBridge()
    prop2 = propose_kit(
        "video-production",
        "Wrong Id Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge2,
    )
    (prop2.staged / "AGENTS.md").write_text(
        "# wrong-id-video\n\n<!-- kit:other-kit v1 begin -->\nok\n<!-- kit:other-kit end -->\n",
        encoding="utf-8",
    )
    with pytest.raises(ScaffoldError, match=r"AGENTS\.md.*missing or damaged") as exc2:
        accept_kit(prop2, register=_fake_register, bridge=bridge2)
    assert exc2.value.keep_staging is True
    assert prop2.staging_dir.is_dir()
    assert not prop2.dest.exists()
    discard_kit(prop2)

    # Case 3: extra damaged block alongside valid proposal kit block (kit_blocks_dropped non-empty)
    bridge3 = FakeVideoBridge()
    prop3 = propose_kit(
        "video-production",
        "Extra Damaged Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge3,
    )
    (prop3.staged / "AGENTS.md").write_text(
        f"# extra-damaged-video\n\n{VIDEO_KIT_BLOCK}\n\n<!-- kit:broken-extra v1 begin -->\noops\n",
        encoding="utf-8",
    )
    with pytest.raises(ScaffoldError, match=r"AGENTS\.md.*missing or damaged") as exc3:
        accept_kit(prop3, register=_fake_register, bridge=bridge3)
    assert exc3.value.keep_staging is True
    assert prop3.staging_dir.is_dir()
    assert not prop3.dest.exists()
    discard_kit(prop3)


def test_f2_purpose_text_for_kit_and_regeneration(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()
    bridge = FakeVideoBridge()
    answers = {"building": "video", "layout": "single", "languages": []}

    prop = propose_kit(
        "video-production",
        "Launch Trailer",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge,
    )
    accept_kit(prop, register=_fake_register, db_path=db_path, bridge=bridge)
    dest = prop.dest

    expected_purpose = (
        "`launch-trailer` was set up by defuzz from the video-production kit. "
        "Its folders and rules are in the kit section below."
    )
    for step in ("initial", "after_rule"):
        if step == "after_rule":
            placer.add_placement_rule(
                dest,
                ".flac",
                "audio",
                kind="flac_audio",
                lfs=True,
                reason="Route lossless audio to audio",
                db_path=db_path,
            )
        agents_text = (dest / "AGENTS.md").read_text(encoding="utf-8")
        assert "adopted by defuzz" not in agents_text
        assert "original folder was never modified" not in agents_text
        sections = validate_agents_md(agents_text)
        purpose_lines = next(s["lines"] for s in sections if s["heading"] == "Purpose")
        assert " ".join(purpose_lines) == expected_purpose
        # Under readable budget, check raw Purpose paragraph before ## Layout
        defuzz_head = agents_text.split("## Layout", 1)[0]
        purpose_raw = defuzz_head.split("## Purpose\n\n", 1)[1].strip()
        assert "\n" not in purpose_raw
        assert purpose_raw == expected_purpose


def test_f3_non_code_ignore_patterns_and_gitignore_sync(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()
    bridge = FakeVideoBridge()
    answers = {"building": "video", "layout": "single", "languages": []}

    prop = propose_kit(
        "video-production",
        "Clean Gitignore Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge,
    )
    accept_kit(prop, register=_fake_register, db_path=db_path, bridge=bridge)
    dest = prop.dest

    rules_data = json.loads((dest / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    expected_ignores = [
        ".hermes/scratch/",
        ".hermes/sessions/",
        ".adopt/place-log.json",
    ]
    assert rules_data["ignore_patterns"] == expected_ignores
    assert "_archive/" not in rules_data["ignore_patterns"]

    gitignore_text = (dest / ".gitignore").read_text(encoding="utf-8")
    assert gitignore_text.endswith("\n")
    gitignore_lines = gitignore_text.splitlines()
    assert "*.tmp" in gitignore_lines
    assert "_archive/" not in gitignore_lines
    for pat in expected_ignores:
        assert pat in gitignore_lines
    assert gitignore_lines.index("*.tmp") < gitignore_lines.index(".hermes/scratch/")

    agents_text = (dest / "AGENTS.md").read_text(encoding="utf-8")
    for dropped in ("node_modules/", ".venv/", "__pycache__/", ".pytest_cache/", "_archive/"):
        assert dropped not in agents_text

    status_proc = run_git_hardened(dest, ["status", "--porcelain"], check=True)
    assert status_proc.stdout.decode("utf-8").strip() == ""


def test_kit_agents_md_one_voice_without_archive(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()
    bridge = FakeVideoBridge()
    answers = {"building": "video", "layout": "single", "languages": []}

    prop = propose_kit(
        "video-production",
        "One Voice Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge,
    )
    accept_kit(prop, register=_fake_register, db_path=db_path, bridge=bridge)
    dest = prop.dest

    assert not (dest / "_archive").exists()
    agents_text = (dest / "AGENTS.md").read_text(encoding="utf-8")
    assert "Move retired ones to `_archive/`" not in agents_text
    assert "- `_archive/`" not in agents_text
    assert "- Never delete files without approval." in agents_text
    assert "files with no placement rule are moved here; ask where they" in agents_text
    assert "belong, then move them" in agents_text


def test_f4_rejects_absolute_kit_folders(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    answers = {"building": "video", "layout": "single", "languages": []}

    # Case 1: absolute declared_dirs entry
    abs_dir_bridge = FakeVideoBridge(
        declared_dirs=[
            *VIDEO_DECLARED_DIRS,
            {"dir": "/abs/x", "summary": "bad abs dir", "why": "should fail"},
        ]
    )
    prop_abs_dir = propose_kit(
        "video-production",
        "Abs Dir Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=abs_dir_bridge,
    )
    with pytest.raises(ScaffoldError, match=r"/abs/x"):
        accept_kit(prop_abs_dir, register=_fake_register, bridge=abs_dir_bridge)
    assert not (prop_abs_dir.staged / "abs").exists()
    assert not (prop_abs_dir.staged / "_inbox").exists()
    assert not prop_abs_dir.dest.exists()
    discard_kit(prop_abs_dir)

    # Case 2: absolute placement_rules dest_dir
    abs_dest_bridge = FakeVideoBridge(
        declared_dirs=[
            *VIDEO_DECLARED_DIRS,
            {"dir": "abs/x", "summary": "rel dir", "why": "rel"},
        ],
        placement_rules=[
            *VIDEO_PLACEMENT_RULES,
            {
                "kind": "abs_rule",
                "match_ext": [".mov"],
                "dest_dir": "/abs/x",
                "lfs": True,
                "reason": "abs dest",
            },
        ],
    )
    prop_abs_dest = propose_kit(
        "video-production",
        "Abs Dest Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=abs_dest_bridge,
    )
    with pytest.raises(ScaffoldError, match=r"/abs/x"):
        accept_kit(prop_abs_dest, register=_fake_register, bridge=abs_dest_bridge)
    assert not (prop_abs_dest.staged / "abs").exists()
    assert not (prop_abs_dest.staged / "_inbox").exists()
    assert not prop_abs_dest.dest.exists()
    discard_kit(prop_abs_dest)


def test_f5_marker_detection_ignores_fences_and_requires_column_zero(tmp_path: Path) -> None:
    rules = {
        "project_slug": "fence-proj",
        "declared_dirs": [
            {"dir": "docs", "summary": "project docs", "why": "keep docs together"},
        ],
        "placement_rules": [],
    }
    proj = tmp_path / "fence-proj"
    proj.mkdir()
    (proj / "AGENTS.md").write_text(
        "# fence-proj\n\n"
        "```markdown\n"
        "<!-- kit:fenced-backtick v1 begin -->\n"
        "## Fake Heading Inside Backticks\n"
        "<!-- kit:fenced-backtick end -->\n"
        "<!-- kit:unclosed-in-fence v1 begin -->\n"
        "```\n\n"
        "~~~\n"
        "<!-- kit:fenced-tilde v1 begin -->\n"
        "<!-- kit:fenced-tilde end -->\n"
        "~~~\n\n"
        "  <!-- kit:indented-kit v1 begin -->\n"
        "indented body\n"
        "  <!-- kit:indented-kit end -->\n",
        encoding="utf-8",
    )
    res = write_agents_md(proj, rules, preserve_kit_blocks=True)
    assert res["kit_blocks_preserved"] == []
    assert res["kit_blocks_dropped"] == []

    # validate_agents_md also ignores fenced markers and requires column 0 for kit markers
    doc_with_fenced_and_indented = (
        "# fence-proj\n"
        "<!-- defuzz schema_version: 1 -->\n\n"
        "## Purpose\n"
        "Workspace purpose.\n"
        "```\n"
        "<!-- kit:unclosed-fence v1 begin -->\n"
        "```\n"
        "  <!-- kit:indented-open v1 begin -->\n\n"
        "## Layout\n"
        "- `_inbox/` — incoming\n\n"
        "## Conventions & constraints\n"
        "- Keep tidy.\n\n"
        "## Build & test\n"
        "- Not detected yet.\n"
    )
    sections = validate_agents_md(doc_with_fenced_and_indented)
    assert [s["heading"] for s in sections] == ["Purpose", "Layout", "Conventions & constraints", "Build & test"]


def test_f6_crlf_kit_block_preserved_byte_identical(tmp_path: Path) -> None:
    crlf_block = (
        b"<!-- kit:crlf-kit v1 begin (managed) -->\r\n"
        b"## Kit: CRLF\r\n"
        b"\r\n"
        b"### Layout\r\n"
        b"- `renders/`: Rendered takes\r\n"
        b"<!-- kit:crlf-kit end -->\r\n"
    )
    proj = tmp_path / "crlf-proj"
    proj.mkdir()
    (proj / "AGENTS.md").write_bytes(b"# crlf-proj\r\n\r\n" + crlf_block)

    rules = {
        "project_slug": "crlf-proj",
        "declared_dirs": [
            {"dir": "renders", "summary": "Rendered takes", "why": "renders"},
        ],
        "placement_rules": [],
    }
    res = write_agents_md(proj, rules, preserve_kit_blocks=True)
    assert res["kit_blocks_preserved"] == ["crlf-kit"]
    assert res["kit_blocks_dropped"] == []

    out_bytes = (proj / "AGENTS.md").read_bytes()
    assert crlf_block in out_bytes
    assert out_bytes.endswith(b"\n\n" + crlf_block)
    validate_agents_md(out_bytes.decode("utf-8"))


def test_propose_kit_and_accept_kit_pass_timeout_to_bridge_and_fail_after_deadline(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    answers = {"building": "video", "layout": "single", "languages": []}

    bridge = FakeVideoBridge()
    now = [100.0]
    clock = lambda: now[0]

    # 1. propose_kit with timeout_s passes remaining time to kit_apply
    prop = propose_kit(
        "video-production",
        "Timed Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge,
        timeout_s=7.5,
        clock=clock,
    )
    assert len(bridge.apply_calls) == 1
    assert bridge.apply_calls[0]["timeout"] == 7.5

    # 2. accept_kit passes remaining time from deadline to kit_check
    res = accept_kit(
        prop,
        register=_fake_register,
        db_path=state_db_path(),
        timeout_s=9.25,
        clock=clock,
        bridge=bridge,
    )
    assert isinstance(res, AcceptResult)
    assert len(bridge.check_calls) == 1
    assert bridge.check_calls[0]["timeout"] == 9.25

    # 3. Non-positive timeout_s in propose_kit raises ScaffoldTimeout without calling kit_apply
    bridge_expired = FakeVideoBridge()
    with pytest.raises(ScaffoldTimeout):
        propose_kit(
            "video-production",
            "Expired Video",
            answers,
            dest_root=dest_root,
            staging_parent=staging_parent,
            bridge=bridge_expired,
            timeout_s=0.0,
            clock=clock,
        )
    assert bridge_expired.apply_calls == []
    assert list(staging_parent.iterdir()) == []


def test_add_placement_rule_preserves_kit_block_when_record_lookup_fails_or_reuses_loaded_record(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()
    bridge = FakeVideoBridge()
    answers = {"building": "video", "layout": "single", "languages": []}

    prop = propose_kit(
        "video-production",
        "Lookup Fail Video",
        answers,
        dest_root=dest_root,
        staging_parent=staging_parent,
        bridge=bridge,
    )
    accept_kit(prop, register=_fake_register, db_path=db_path, bridge=bridge)
    dest = prop.dest

    assert not hasattr(placer, "_ORIG_REQUIRE_REGISTERED_PROJECT")

    # 1. When the project-record lookup raises via the registry seam,
    # existing kit blocks in AGENTS.md are preserved byte-identical rather than dropped.
    class RaisingRegistry:
        def get_project(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("simulated DB failure during record lookup")

    placer.add_placement_rule(
        dest,
        ".aac",
        "audio",
        kind="aac_audio",
        lfs=True,
        reason="Route aac audio to audio",
        db_path=db_path,
        registry=RaisingRegistry(),
    )
    agents_after = (dest / "AGENTS.md").read_text(encoding="utf-8")
    assert VIDEO_KIT_BLOCK in agents_after
    assert agents_after.count(VIDEO_KIT_BLOCK) == 1

    # 2. Normal add_placement_rule preserves the kit block for a kit-created project
    placer.add_placement_rule(
        dest,
        ".flac",
        "audio",
        kind="flac_audio",
        lfs=True,
        reason="Route lossless audio to audio",
        db_path=db_path,
    )
    assert VIDEO_KIT_BLOCK in (dest / "AGENTS.md").read_text(encoding="utf-8")




