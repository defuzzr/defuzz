"""Tests for project kit routing in run_new_project_flow and the defuzz CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tests.conftest import ensure_test_package, load_submodule
from tests.fake_kit_bridge import VIDEO_DECLARED_DIRS, FakeKitBridge, load_list_fixture

ensure_test_package()

from hermes_plugins.defuzz import cli, componentize_bridge, new_project, placer  # noqa: E402
from hermes_plugins.defuzz.kit_scaffold import KitProposal  # noqa: E402
from hermes_plugins.defuzz.matcher import KitInfo  # noqa: E402
from hermes_plugins.defuzz.new_project import run_new_project_flow  # noqa: E402
from hermes_plugins.defuzz.state_store import state_db_path  # noqa: E402

TEMPLATES_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"
_FIXTURE_KIT_IDS = [k["id"] for k in load_list_fixture()["kits"]]


def _fake_register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "hermes-kit-flow-1", "name": name, "path": path})


def _listing(*roots: Path) -> List[List[str]]:
    return [sorted(str(p.relative_to(r)) for p in r.rglob("*")) for r in roots]


@pytest.fixture(autouse=True)
def _reset_placer_notices() -> None:
    placer._reset_notice_state_for_tests()


def test_flow_video_prompt_suggests_kit_and_explicit_kit_id_creates_it(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()

    # Without an id the prompt only suggests the kit; nothing is staged or written.
    suggest_bridge = FakeKitBridge()
    res_choice = run_new_project_flow(
        prompt="set up a video production project called Night Shoot",
        confirm=lambda _prop: pytest.fail("confirm must never be called without an id"),
        confirm_kit=lambda _prop: pytest.fail("confirm_kit must never be called without an id"),
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=db_path,
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=suggest_bridge,
    )
    assert res_choice.status == "needs_choice"
    assert res_choice.message == ""
    assert res_choice.kit_matches[0].kit.id == "video-production"
    assert res_choice.kit_proposal is None and res_choice.proposal is None
    assert suggest_bridge.apply_calls == []
    assert list(dest_root.iterdir()) == []
    assert list(staging_parent.iterdir()) == []

    bridge = FakeKitBridge()

    seen_proposals: List[KitProposal] = []

    def confirm_kit_cb(prop: KitProposal) -> bool:
        assert isinstance(prop, KitProposal)
        seen_proposals.append(prop)
        return True

    res = run_new_project_flow(
        prompt="set up a video production project called Night Shoot",
        kit_id="video-production",
        confirm=lambda _prop: False,
        confirm_kit=confirm_kit_cb,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=db_path,
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )

    assert res.status == "created"
    assert res.catalog == "kit"
    assert not hasattr(res, "handoff")
    assert bridge.list_calls == []
    assert res.kit_proposal is not None
    assert res.kit_proposal.kit_id == "video-production"
    assert len(seen_proposals) == 1

    dest = dest_root / "night-shoot"
    assert dest.is_dir()
    assert (dest / ".git").is_dir()
    for entry in VIDEO_DECLARED_DIRS:
        assert (dest / entry["dir"]).is_dir()
    assert (dest / "_inbox").is_dir()
    assert not (dest / "_archive").exists()
    assert (dest / "AGENTS.md").is_file()
    assert not res.kit_proposal.staging_dir.exists()

    # Verify automatic file placement is active on the created kit project
    assert placer.inspect_project_trust(dest, db_path=db_path)["trusted"] is True
    hook_res = placer.on_pre_tool_call(
        tool_name="write_file",
        args={"path": str(dest / "frame01.png"), "content": "img"},
        tool_call_id="tc-flow-1",
        db_path=db_path,
    )
    assert hook_res == {
        "action": "modify",
        "args": {"path": str(dest / "assets" / "generated" / "frame01.png")},
    }


def test_flow_video_prompt_when_bridge_unavailable_needs_choice_and_kit_id_fails_closed(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeKitBridge(
        status="unavailable",
        notice="componentize CLI is unavailable.",
    )

    sent_payloads: List[Dict[str, Any]] = []

    def recording_sender(payload: Dict[str, Any], *, timeout: Any = None) -> Dict[str, Any]:
        sent_payloads.append(dict(payload))
        return {"dispatched": True, "timeout": timeout}

    for sender in (recording_sender, None):
        res = run_new_project_flow(
            prompt="set up a video production project called Night Shoot",
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            register=_fake_register,
            db_path=state_db_path(),
            dest_root=dest_root,
            staging_parent=staging_parent,
            kit_bridge=bridge,
        )
        assert res.status == "needs_choice"
        assert res.message == ""
        assert res.kit_matches == []
        assert res.kits_notice == "componentize CLI is unavailable."
        assert res.proposal is None and res.kit_proposal is None
        assert sent_payloads == []
        assert list(dest_root.iterdir()) == []
        assert list(staging_parent.iterdir()) == []

    # An explicit kit id while kits are unavailable fails closed and writes nothing.
    res_kit = run_new_project_flow(
        prompt="set up a video production project called Night Shoot",
        kit_id="video-production",
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )
    assert res_kit.status == "no_match"
    assert res_kit.message == (
        "Project kits are unavailable: componentize CLI is unavailable. "
        "Install and enable the componentize plugin to create this kind of project."
    )
    assert res_kit.kits_notice == "componentize CLI is unavailable."
    assert res_kit.accept is None
    assert sent_payloads == []
    assert list(dest_root.iterdir()) == []
    assert list(staging_parent.iterdir()) == []


def test_flow_kit_kind_when_no_kit_matches_returns_needs_choice_without_suggestion(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeKitBridge()
    unrelated_kit = KitInfo(
        id="custom-docs",
        name="Custom Docs",
        summary="Documentation workspace",
        tags=("docs", "notes"),
        version=1,
    )

    before = _listing(dest_root, staging_parent)
    res = run_new_project_flow(
        prompt="set up a video production project called Night Shoot",
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kits=[unrelated_kit],
        kit_bridge=bridge,
    )

    assert res.status == "needs_choice"
    assert res.message == ""
    assert res.kit_matches == []
    assert res.proposal is None and res.kit_proposal is None
    assert bridge.list_calls == []
    assert bridge.apply_calls == []
    assert _listing(dest_root, staging_parent) == before
    assert list(dest_root.iterdir()) == []


def test_flow_code_prompt_with_explicit_template_id_takes_template_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeKitBridge()

    def _forbid_kit_list() -> Dict[str, Any]:
        raise AssertionError("kit_list must not be called on the template path or with explicit kits")

    monkeypatch.setattr(bridge, "kit_list", _forbid_kit_list)
    monkeypatch.setattr(
        load_submodule("scaffolder").toolchk,
        "probe",
        lambda *a, **k: ("1.0.0", "fixture-tool"),
    )

    res = run_new_project_flow(
        prompt="python backend service called Api",
        template_id="fake-py-service",
        ask=lambda q, _prefill: {"layout": "poly", "languages": ["python", "typescript"]}.get(q.id),
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )

    assert res.status == "created"
    assert res.catalog == "template"
    assert res.kits_notice == ""
    assert res.proposal is not None
    assert res.kit_proposal is None
    assert (dest_root / "api-api").is_dir()
    assert (dest_root / "api-web").is_dir()

    # Explicit kits passed in are used as-is without calling kit_bridge.kit_list
    explicit_kit = KitInfo(
        id="component-library",
        name="Component library",
        summary="Reusable python components",
        tags=("python", "backend"),
        version=1,
    )
    res_explicit_kits_choice = run_new_project_flow(
        prompt="python backend service called ApiTwo",
        ask=lambda q, _prefill: {"layout": "poly", "languages": ["python", "typescript"]}.get(q.id),
        confirm=lambda _prop: pytest.fail("confirm must never be called without an id"),
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kits=[explicit_kit],
        kit_bridge=bridge,
    )
    assert res_explicit_kits_choice.status == "needs_choice"
    assert res_explicit_kits_choice.kits_notice == ""
    assert len(res_explicit_kits_choice.kit_matches) == 1
    assert res_explicit_kits_choice.kit_matches[0].kit.id == "component-library"
    assert not (dest_root / "api-two-api").exists()

    res_explicit_kits = run_new_project_flow(
        prompt="python backend service called ApiTwo",
        template_id="fake-py-service",
        ask=lambda q, _prefill: {"layout": "poly", "languages": ["python", "typescript"]}.get(q.id),
        confirm=lambda _prop: False,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kits=[explicit_kit],
        kit_bridge=bridge,
    )
    assert res_explicit_kits.status == "declined"
    assert res_explicit_kits.catalog == "template"
    assert res_explicit_kits.kits_notice == ""
    assert res_explicit_kits.kit_matches == []
    assert sorted(p.name for p in dest_root.iterdir()) == ["api-api", "api-web"]

    # Caller-supplied language in initial_answers alongside a prompt without a language
    # suggests the Python template, whereas omitting languages suggests the strong kit;
    # each is created only from its explicit id.
    fresh_bridge = FakeKitBridge()
    video_prompt = "a video editing pipeline for film storyboards"
    for answers, top_template, top_kit in (
        ({"building": "tool", "languages": ["python"]}, "python-golden", None),
        ({"building": "tool"}, None, "video-channel"),
        ({"building": "tool", "languages": ["other"]}, None, "video-channel"),
    ):
        res_choice = run_new_project_flow(
            prompt=video_prompt,
            initial_answers=answers,
            confirm=lambda _prop: pytest.fail("confirm must never be called without an id"),
            register=_fake_register,
            db_path=state_db_path(),
            dest_root=dest_root,
            staging_parent=staging_parent,
            kit_bridge=fresh_bridge,
        )
        assert res_choice.status == "needs_choice", answers
        if top_template is not None:
            assert res_choice.matches[0].template.id == top_template, answers
        if top_kit is not None:
            assert res_choice.kit_matches[0].kit.id == top_kit, answers
    assert fresh_bridge.apply_calls == []
    assert sorted(p.name for p in dest_root.iterdir()) == ["api-api", "api-web"]
    assert list(staging_parent.iterdir()) == []
    res_caller_lang = run_new_project_flow(
        prompt="a video editing pipeline for film storyboards",
        initial_answers={"building": "tool", "languages": ["python"]},
        template_id="python-golden",
        confirm=lambda _prop: False,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=fresh_bridge,
    )
    assert res_caller_lang.status == "declined"
    assert res_caller_lang.catalog == "template"
    assert res_caller_lang.proposal is not None
    assert res_caller_lang.proposal.template_id == "python-golden"

    res_no_caller_lang = run_new_project_flow(
        prompt="a video editing pipeline for film storyboards",
        initial_answers={"building": "tool"},
        kit_id="video-channel",
        confirm=lambda _prop: False,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=fresh_bridge,
    )
    assert res_no_caller_lang.status == "declined"
    assert res_no_caller_lang.catalog == "kit"
    assert res_no_caller_lang.kit_proposal is not None
    assert res_no_caller_lang.kit_proposal.kit_id == "video-channel"

    # ['other'] in initial_answers does not count as naming a code language
    res_other_lang = run_new_project_flow(
        prompt="a video editing pipeline for film storyboards",
        initial_answers={"building": "tool", "languages": ["other"]},
        kit_id="video-channel",
        confirm=lambda _prop: False,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=fresh_bridge,
    )
    assert res_other_lang.status == "declined"
    assert res_other_lang.catalog == "kit"
    assert res_other_lang.kit_proposal is not None
    assert res_other_lang.kit_proposal.kit_id == "video-channel"
    assert sorted(p.name for p in dest_root.iterdir()) == ["api-api", "api-web"]
    assert list(staging_parent.iterdir()) == []


def test_flow_weak_kit_hit_on_code_game_prompt_needs_choice_while_explicit_kit_id_creates_kit(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeKitBridge()

    # 1. Weak kit match for a code request with no template match: nothing is chosen or
    #    written, whatever sender is passed (the hand-off is gone).
    for sender in (None, lambda payload, timeout=None: pytest.fail("sender must never be called")):
        res_weak = run_new_project_flow(
            prompt="make a rust bevy game called Star Dust",
            confirm=lambda _prop: True,
            templates=[],
            templates_root=TEMPLATES_FIXTURES,
            register=_fake_register,
            db_path=state_db_path(),
            dest_root=dest_root,
            staging_parent=staging_parent,
            kit_bridge=bridge,
        )
        assert res_weak.status == "needs_choice"
        assert res_weak.message == ""
        assert res_weak.catalog == ""
        assert res_weak.matches == []
        assert res_weak.kit_proposal is None
        assert bridge.apply_calls == []
        assert list(dest_root.iterdir()) == []
        assert list(staging_parent.iterdir()) == []

    # 2. Strong kit match is only a suggestion; the explicit id creates kit 'game-assets'
    strong_prompt = "new unreal game asset workspace with blender and houdini called Vault"
    res_suggest = run_new_project_flow(
        prompt=strong_prompt,
        confirm=lambda _prop: True,
        templates=[],
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )
    assert res_suggest.status == "needs_choice"
    assert res_suggest.kit_matches[0].kit.id == "game-assets"
    assert bridge.apply_calls == []
    assert list(dest_root.iterdir()) == []

    res_strong = run_new_project_flow(
        prompt=strong_prompt,
        kit_id="game-assets",
        confirm=lambda _prop: True,
        templates=[],
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )
    assert res_strong.status == "created"
    assert res_strong.catalog == "kit"
    assert res_strong.kit_proposal is not None
    assert res_strong.kit_proposal.kit_id == "game-assets"
    assert (dest_root / "vault").is_dir()
    assert [p.name for p in dest_root.iterdir()] == ["vault"]


def test_flow_explicit_kit_id_skips_matching_and_decline_removes_staging(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeKitBridge()
    seen_staging: List[Path] = []

    def confirm_decline(prop: KitProposal) -> bool:
        assert isinstance(prop, KitProposal)
        assert prop.staging_dir.is_dir()
        seen_staging.append(prop.staging_dir)
        return False

    res = run_new_project_flow(
        kit_id="video-production",
        name_provider=lambda: "Trailer Cut",
        confirm=confirm_decline,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )

    assert res.status == "declined"
    assert res.catalog == "kit"
    assert res.kit_proposal is not None
    assert res.kit_proposal.kit_id == "video-production"
    assert bridge.list_calls == []
    assert len(bridge.apply_calls) == 1
    assert len(seen_staging) == 1
    assert not seen_staging[0].exists()
    assert list(staging_parent.iterdir()) == []
    assert list(dest_root.iterdir()) == []


def test_cli_new_kit_dry_run_and_yes_and_mutual_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dest_root = tmp_path / "projects"
    dest_root.mkdir()
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(cli, "REGISTER_PROJECT", _fake_register)

    # 1. Dry-run without --yes prints kit id, destination, folder tree, and Re-run instruction; creates nothing
    rc_dry = cli.main(
        [
            "new",
            "--kit",
            "video-production",
            "--prompt",
            "set up a video production project called Night Shoot",
            "--dest-root",
            str(dest_root),
            "--templates-root",
            str(TEMPLATES_FIXTURES),
        ]
    )
    out_dry = capsys.readouterr()
    assert rc_dry == 0
    assert "video-production" in out_dry.out
    assert str(dest_root / "night-shoot") in out_dry.out
    assert "assets/generated/" in out_dry.out
    assert "Re-run with --yes to create." in out_dry.out
    assert not (dest_root / "night-shoot").exists()

    # 2. With --yes creates the project and prints destination path and that automatic file placement is on
    rc_yes = cli.main(
        [
            "new",
            "--kit",
            "video-production",
            "--prompt",
            "set up a video production project called Night Shoot",
            "--dest-root",
            str(dest_root),
            "--templates-root",
            str(TEMPLATES_FIXTURES),
            "--yes",
        ]
    )
    out_yes = capsys.readouterr()
    assert rc_yes == 0
    assert str(dest_root / "night-shoot") in out_yes.out
    assert "placement" in out_yes.out.lower() and "on" in out_yes.out.lower()
    assert (dest_root / "night-shoot" / ".git").is_dir()
    assert (dest_root / "night-shoot" / "assets" / "generated").is_dir()

    # 3. Explicit --kit with --yes
    rc_explicit = cli.main(
        [
            "new",
            "--kit",
            "video-production",
            "--name",
            "Explicit Video",
            "--dest-root",
            str(dest_root),
            "--yes",
        ]
    )
    out_explicit = capsys.readouterr()
    assert rc_explicit == 0
    assert str(dest_root / "explicit-video") in out_explicit.out
    assert (dest_root / "explicit-video" / "AGENTS.md").is_file()
    assert len(bridge.apply_calls) == 3

    # 4. --kit and --template together is refused by the command itself, first, in either order:
    #    exit 2, exactly one stderr line (no usage block), empty stdout, nothing created, no bridge call
    before = sorted(p.relative_to(dest_root) for p in dest_root.rglob("*"))
    calls_before = len(bridge.apply_calls)
    list_before = len(bridge.list_calls)
    for argv in (
        ["new", "--kit", "video-production", "--template", "fake-rust-game"],
        ["new", "--template", "fake-rust-game", "--kit", "video-production"],
    ):
        rc_both = cli.main(
            argv + ["--name", "Conflict", "--dest-root", str(dest_root), "--yes"]
        )
        out_both = capsys.readouterr()
        assert rc_both == 2
        assert out_both.err == cli.BOTH_IDS_LINE + "\n"
        assert out_both.err == "Give either --template ID or --kit ID, not both.\n"
        assert "usage" not in out_both.err.lower()
        assert out_both.out == ""
        assert not (dest_root / "conflict").exists()
        assert sorted(p.relative_to(dest_root) for p in dest_root.rglob("*")) == before
        assert len(bridge.apply_calls) == calls_before
        assert len(bridge.list_calls) == list_before

    # 5. Video prompt without --kit when kits are unavailable: the template list plus one notice
    #    line, then the refusal; exit 2, no hand-off, nothing created
    unavail_dest_root = tmp_path / "unavail_projects"
    unavail_dest_root.mkdir()
    FakeKitBridge(
        status="unavailable",
        notice="componentize CLI is unavailable.",
    ).install(monkeypatch, componentize_bridge)
    rc_unavail = cli.main(
        [
            "new",
            "--prompt",
            "set up a video production project called Night Shoot",
            "--dest-root",
            str(unavail_dest_root),
            "--templates-root",
            str(TEMPLATES_FIXTURES),
        ]
    )
    out_unavail = capsys.readouterr()
    assert rc_unavail == 2
    assert "hand-off" not in out_unavail.out
    assert "[--template fake-rust-game]" in out_unavail.out
    assert "[--kit " not in out_unavail.out
    assert sum("defuzz-componentize" in ln for ln in out_unavail.out.splitlines()) == 1
    assert out_unavail.out.rstrip("\n").splitlines()[-1] == (
        "Nothing was created. Run again with --template ID or --kit ID."
    )
    assert out_unavail.err == ""
    assert list(unavail_dest_root.iterdir()) == []


def test_cli_kits_subcommand_available_and_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. Available: lists 4 kits from the contract fixture and exits 0
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(["kits"])
    captured = capsys.readouterr()
    assert rc == 0
    for kit_id in ("component-library", "game-assets", "video-production"):
        assert kit_id in captured.out
    video = next(k for k in load_list_fixture()["kits"] if k["id"] == "video-production")
    assert video["summary"] in captured.out

    # --json mode
    rc_json = cli.main(["kits", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc_json == 0
    assert [k["id"] for k in payload["kits"]] == _FIXTURE_KIT_IDS
    assert isinstance(payload["notice"], str)

    # 2. Unavailable: prints one line saying kits are unavailable with the notice and exits 0
    FakeKitBridge(
        status="unavailable",
        notice="componentize CLI is unavailable.",
    ).install(monkeypatch, componentize_bridge)
    rc_unavail = cli.main(["kits"])
    out_unavail = capsys.readouterr().out.strip().splitlines()
    assert rc_unavail == 0
    assert len(out_unavail) == 1
    assert "unavailable" in out_unavail[0].lower()
    assert "componentize CLI is unavailable." in out_unavail[0]

    rc_unavail_json = cli.main(["kits", "--json"])
    payload_unavail = json.loads(capsys.readouterr().out)
    assert rc_unavail_json == 0
    assert payload_unavail["kits"] == []
    assert "componentize CLI is unavailable." in payload_unavail["notice"]


def test_flow_non_project_request_returns_needs_choice_without_matches(tmp_path: Path) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    bridge = FakeKitBridge()

    res = run_new_project_flow(
        prompt="summarize this video",
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )
    assert res.status == "needs_choice"
    assert res.message == ""
    assert res.parsed_prompt is not None and res.parsed_prompt.not_a_project_request
    assert res.matches == []
    assert res.kit_matches == []
    assert bridge.list_calls == []
    assert bridge.apply_calls == []
    assert list(dest_root.iterdir()) == []
    assert list(staging_parent.iterdir()) == []


def test_flow_kit_calls_receive_shared_deadline_and_do_not_spawn_past_deadline(
    tmp_path: Path,
) -> None:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    db_path = state_db_path()
    bridge = FakeKitBridge()

    now = [50.0]

    def clock() -> float:
        return now[0]

    def ask_cb(q: Any, _prefill: List[str]) -> Any:
        now[0] += 2.0
        return {"building": "video"}.get(q.id)

    def name_cb() -> str:
        now[0] += 1.5
        return "Deadline Shoot"

    def confirm_cb(_prop: KitProposal) -> bool:
        now[0] += 1.0
        return True

    res = run_new_project_flow(
        kit_id="video-production",
        ask=ask_cb,
        name_provider=name_cb,
        confirm_kit=confirm_cb,
        timeout_s=10.0,
        clock=clock,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=db_path,
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=bridge,
    )
    assert res.status == "created"
    assert bridge.list_calls == []  # an explicit kit id skips the kit list
    assert len(bridge.apply_calls) == 1
    assert bridge.apply_calls[0]["timeout"] == 6.5
    assert len(bridge.check_calls) == 1
    assert bridge.check_calls[0]["timeout"] == 5.5

    # 2. Without an id, when kit_list consumes the remaining budget the flow times out
    #    and kit_apply is never spawned
    list_exp_bridge = FakeKitBridge()
    orig_kit_list = list_exp_bridge.kit_list

    def consuming_kit_list(*, timeout: float | None = None) -> Dict[str, Any]:
        out = orig_kit_list(timeout=timeout)
        now[0] += 10.0
        return out

    list_exp_bridge.kit_list = consuming_kit_list  # type: ignore[method-assign]
    now[0] = 100.0
    res_exp_list = run_new_project_flow(
        ask=lambda _q, _p: pytest.fail("nothing is asked without an id"),
        name_provider=lambda: "Late Video",
        confirm_kit=lambda _p: True,
        timeout_s=10.0,
        clock=clock,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=db_path,
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=list_exp_bridge,
    )
    assert res_exp_list.status == "timeout"
    assert res_exp_list.message == "New-project flow timed out during kit matching"
    assert len(list_exp_bridge.list_calls) == 1
    assert list_exp_bridge.list_calls[0]["timeout"] == 10.0
    assert list_exp_bridge.apply_calls == []
    assert list_exp_bridge.check_calls == []

    # 3. When deadline is exceeded during name_provider, kit_apply is never spawned
    expired_bridge = FakeKitBridge()
    now[0] = 200.0

    def over_budget_name() -> str:
        now[0] += 10.0
        return "Late Video"

    res_exp_propose = run_new_project_flow(
        kit_id="video-production",
        name_provider=over_budget_name,
        confirm_kit=lambda _p: True,
        timeout_s=10.0,
        clock=clock,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=db_path,
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=expired_bridge,
    )
    assert res_exp_propose.status == "timeout"
    assert expired_bridge.apply_calls == []
    assert expired_bridge.check_calls == []
    assert list(staging_parent.iterdir()) == []

    # 4. When deadline is exceeded during confirm_kit, kit_check is never spawned and staging is discarded
    confirm_exp_bridge = FakeKitBridge()
    now[0] = 300.0

    def over_budget_confirm(_prop: KitProposal) -> bool:
        now[0] += 9.0
        return True

    def confirm_exp_name_cb() -> str:
        now[0] += 1.5
        return "Confirm Expire Shoot"

    res_exp_accept = run_new_project_flow(
        kit_id="video-production",
        name_provider=confirm_exp_name_cb,
        confirm_kit=over_budget_confirm,
        timeout_s=10.0,
        clock=clock,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=db_path,
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=confirm_exp_bridge,
    )
    assert res_exp_accept.status == "timeout"
    assert len(confirm_exp_bridge.apply_calls) == 1
    assert confirm_exp_bridge.apply_calls[0]["timeout"] == 8.5
    assert confirm_exp_bridge.check_calls == []
    assert list(staging_parent.iterdir()) == []


def test_load_kit_catalog_inspects_signature_without_retrying_on_type_error() -> None:
    new_project_mod = load_submodule("new_project")
    _load_kit_catalog = new_project_mod._load_kit_catalog

    # 1. Bridge whose kit_list accepts timeout and raises TypeError inside the call
    # must NOT be called a second time without timeout.
    calls_with_timeout: List[float | None] = []

    class RaisingBridge:
        def kit_list(self, *, timeout: float | None = None) -> Dict[str, Any]:
            calls_with_timeout.append(timeout)
            raise TypeError("internal type bug inside kit_list")

    with pytest.raises(TypeError, match="internal type bug inside kit_list"):
        _load_kit_catalog(None, RaisingBridge(), timeout=5.0)
    assert calls_with_timeout == [5.0]

    # 2. Legacy bridge whose kit_list takes no timeout parameter is called once without timeout
    no_arg_calls: List[int] = []

    class NoTimeoutBridge:
        def kit_list(self) -> Dict[str, Any]:
            no_arg_calls.append(1)
            return {"status": "ok", "data": {"kits": load_list_fixture()["kits"]}}

    infos, notice, unavail = _load_kit_catalog(None, NoTimeoutBridge(), timeout=5.0)
    assert no_arg_calls == [1]
    assert not unavail
    assert notice == ""
    assert len(infos) == len(_FIXTURE_KIT_IDS)

