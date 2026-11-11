"""List-first new-project flow: create only from an explicit template or kit id.

Without an id, run_new_project_flow returns status ``needs_choice`` with the template and
kit matches it computed (so a caller can mark suggestions) and creates nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import FakeKitBridge
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

from hermes_plugins.defuzz import catalog_list, new_project, scaffolder  # noqa: E402
from hermes_plugins.defuzz.new_project import (  # noqa: E402
    VALID_FLOW_STATUSES,
    run_new_project_flow,
)
from hermes_plugins.defuzz.safety import run_git_hardened  # noqa: E402
from hermes_plugins.defuzz.state_store import state_db_path  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402

TEMPLATES_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"
RUST_ANSWERS = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
VIDEO_PROMPT = "set up a video production project called Night Shoot"
CODE_PROMPT = "a Rust bevy game called Night Shoot"


def _tree_digest(*roots: Path) -> str:
    """Hash every path, file content and directory under the roots."""
    h = hashlib.sha256()
    for root in roots:
        h.update(f"root:{root}\n".encode())
        if not root.exists():
            h.update(b"absent\n")
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            rel = os.path.relpath(dirpath, root)
            h.update(f"d:{rel}\n".encode())
            for name in sorted(filenames):
                p = Path(dirpath) / name
                h.update(f"f:{rel}/{name}\n".encode())
                h.update(p.read_bytes())
    return h.hexdigest()


def _never(label: str):
    def _cb(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail(f"{label} must not be called when no template or kit id is given")

    return _cb


def _fake_register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "list-first-1", "name": name, "path": path})


@pytest.fixture
def dirs(tmp_path: Path) -> Dict[str, Path]:
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    state_dir = Path(os.environ["HERMES_HOME"])
    db_path = state_db_path()  # resolving the path creates the (empty) state folder
    return {
        "db": db_path,
        "dest_root": dest_root,
        "staging_parent": staging_parent,
        "state_dir": state_dir,
        "tmp": tmp_path,
    }


def _no_id_flow(dirs: Dict[str, Path], **kwargs: Any):
    return run_new_project_flow(
        ask=_never("ask"),
        name_provider=_never("name_provider"),
        confirm=_never("confirm"),
        confirm_kit=_never("confirm_kit"),
        choose_options=_never("choose_options"),
        register=_never("register"),
        templates_root=TEMPLATES_FIXTURES,
        db_path=dirs["db"],
        dest_root=dirs["dest_root"],
        staging_parent=dirs["staging_parent"],
        **kwargs,
    )


def test_needs_choice_is_a_valid_status_and_the_hand_off_status_is_gone() -> None:
    assert "needs_choice" in VALID_FLOW_STATUSES
    assert "no_match_handoff" not in VALID_FLOW_STATUSES


def test_no_id_video_prompt_returns_needs_choice_with_kit_matches_and_writes_nothing(
    dirs: Dict[str, Path],
) -> None:
    roots = (dirs["dest_root"], dirs["staging_parent"], dirs["state_dir"])
    before = _tree_digest(*roots)
    bridge = FakeKitBridge()

    res = _no_id_flow(dirs, prompt=VIDEO_PROMPT, kit_bridge=bridge)

    assert res.status == "needs_choice"
    assert res.message == ""
    assert res.proposal is None and res.kit_proposal is None and res.accept is None
    assert [km.kit.id for km in res.kit_matches][:1] == ["video-production"]
    assert bridge.apply_calls == []
    assert _tree_digest(*roots) == before
    assert list(dirs["dest_root"].iterdir()) == []
    assert list(dirs["staging_parent"].iterdir()) == []
    assert not dirs["db"].exists()


def test_no_id_code_answers_return_needs_choice_with_template_matches_and_write_nothing(
    dirs: Dict[str, Path],
) -> None:
    roots = (dirs["dest_root"], dirs["staging_parent"], dirs["state_dir"])
    before = _tree_digest(*roots)

    res = _no_id_flow(
        dirs, prompt=CODE_PROMPT, initial_answers=RUST_ANSWERS, kits=[]
    )

    assert res.status == "needs_choice"
    assert res.message == ""
    assert [m.template.id for m in res.matches][:1] == ["fake-rust-game"]
    assert res.proposal is None and res.accept is None
    assert _tree_digest(*roots) == before
    assert not dirs["db"].exists()


def test_no_id_matches_feed_suggested_ids(dirs: Dict[str, Path]) -> None:
    bridge = FakeKitBridge()
    res = _no_id_flow(dirs, prompt=VIDEO_PROMPT, kit_bridge=bridge)
    assert res.status == "needs_choice"

    from hermes_plugins.defuzz.matcher import parse_kit_list

    infos, _notice, _status = parse_kit_list(bridge.kit_list())
    entries = catalog_list.build_catalog(load_templates(TEMPLATES_FIXTURES), infos)
    suggested = catalog_list.suggested_ids(entries, res.matches, res.kit_matches, None)
    assert suggested[:1] == ["kit:video-production"]
    text = catalog_list.render_text(entries, suggested=suggested)
    for entry in entries:
        assert text.count(entry["flag"]) == (0 if entry.get("coming_soon") else 1), entry["flag"]
        if entry.get("coming_soon"):
            assert entry["title"] + "  [coming soon]" in text
    suggested_lines = [ln for ln in text.splitlines() if "(suggested)" in ln]
    assert len(suggested_lines) == len(suggested)
    assert any("--kit video-production" in ln for ln in suggested_lines)


def test_no_id_non_project_prompt_returns_needs_choice_without_matches(
    dirs: Dict[str, Path],
) -> None:
    before = _tree_digest(dirs["dest_root"], dirs["staging_parent"], dirs["state_dir"])
    res = _no_id_flow(dirs, prompt="what is the weather today", kit_bridge=FakeKitBridge())
    assert res.status == "needs_choice"
    assert res.message == ""
    assert res.matches == [] and res.kit_matches == []
    assert _tree_digest(dirs["dest_root"], dirs["staging_parent"], dirs["state_dir"]) == before


def test_no_id_without_prompt_or_answers_still_returns_needs_choice(dirs: Dict[str, Path]) -> None:
    res = _no_id_flow(dirs, kits=[])
    assert res.status == "needs_choice"
    assert res.message == ""
    assert list(dirs["dest_root"].iterdir()) == []


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_explicit_template_id_creates_that_template_even_when_prompt_points_to_a_kit(
    dirs: Dict[str, Path],
) -> None:
    bridge = FakeKitBridge()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(scaffolder.toolchk, "probe", lambda *_a, **_k: ("1.0.0", "fixture-tool"))
        res = run_new_project_flow(
            template_id="fake-rust-game",
            prompt=VIDEO_PROMPT,
            initial_answers=RUST_ANSWERS,
            confirm=lambda _prop: True,
            templates_root=TEMPLATES_FIXTURES,
            register=_fake_register,
            db_path=dirs["db"],
            dest_root=dirs["dest_root"],
            staging_parent=dirs["staging_parent"],
            kit_bridge=bridge,
        )

    assert res.status == "created", res.message
    assert res.catalog == "template"
    assert res.proposal is not None and res.proposal.template_id == "fake-rust-game"
    assert bridge.apply_calls == []
    dest = dirs["dest_root"] / "night-shoot"
    assert dest.is_dir()
    log = run_git_hardened(dest, ["log", "--oneline"], check=True).stdout.decode("utf-8")
    assert "fake-rust-game" in log


def test_explicit_kit_id_creates_that_kit_even_when_prompt_points_to_a_template(
    dirs: Dict[str, Path],
) -> None:
    bridge = FakeKitBridge()
    res = run_new_project_flow(
        kit_id="video-production",
        prompt=CODE_PROMPT,
        initial_answers=RUST_ANSWERS,
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_fake_register,
        db_path=dirs["db"],
        dest_root=dirs["dest_root"],
        staging_parent=dirs["staging_parent"],
        kit_bridge=bridge,
    )

    assert res.status == "created", res.message
    assert res.catalog == "kit"
    assert res.kit_proposal is not None and res.kit_proposal.kit_id == "video-production"
    assert len(bridge.apply_calls) >= 1
    assert {call["kit_id"] for call in bridge.apply_calls} == {"video-production"}
    assert (dirs["dest_root"] / "night-shoot").is_dir()


def test_unknown_template_id_is_an_error_and_creates_nothing(dirs: Dict[str, Path]) -> None:
    before = _tree_digest(dirs["dest_root"], dirs["staging_parent"], dirs["state_dir"])
    res = run_new_project_flow(
        template_id="no-such-template",
        name_provider=lambda: "Ghost",
        initial_answers=RUST_ANSWERS,
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_never("register"),
        db_path=dirs["db"],
        dest_root=dirs["dest_root"],
        staging_parent=dirs["staging_parent"],
    )
    assert res.status == "error"
    assert res.message == "Template not found: no-such-template"
    assert _tree_digest(dirs["dest_root"], dirs["staging_parent"], dirs["state_dir"]) == before


def test_unknown_kit_id_keeps_the_bridge_error(dirs: Dict[str, Path]) -> None:
    res = run_new_project_flow(
        kit_id="no-such-kit",
        name_provider=lambda: "Ghost",
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        register=_never("register"),
        db_path=dirs["db"],
        dest_root=dirs["dest_root"],
        staging_parent=dirs["staging_parent"],
        kit_bridge=FakeKitBridge(),
    )
    assert res.status == "error"
    assert "unknown kit 'no-such-kit'" in res.message
    assert list(dirs["dest_root"].iterdir()) == []
    assert list(dirs["staging_parent"].iterdir()) == []


def test_both_ids_is_an_error_and_creates_nothing(dirs: Dict[str, Path]) -> None:
    res = run_new_project_flow(
        template_id="fake-rust-game",
        kit_id="video-production",
        name_provider=lambda: "Both",
        confirm=lambda _prop: True,
        templates_root=TEMPLATES_FIXTURES,
        db_path=dirs["db"],
        dest_root=dirs["dest_root"],
        staging_parent=dirs["staging_parent"],
        kit_bridge=FakeKitBridge(),
    )
    assert res.status == "error"
    assert list(dirs["dest_root"].iterdir()) == []


@pytest.mark.parametrize("ids", [{}, {"template_id": "fake-rust-game"}, {"kit_id": "video-production"}])
def test_non_positive_timeout_keeps_its_result(dirs: Dict[str, Path], ids: Dict[str, str]) -> None:
    res = run_new_project_flow(
        timeout_s=0,
        templates_root=TEMPLATES_FIXTURES,
        db_path=dirs["db"],
        dest_root=dirs["dest_root"],
        staging_parent=dirs["staging_parent"],
        kit_bridge=FakeKitBridge(),
        **ids,
    )
    assert res.status == "timeout"
    assert res.message == "Flow timeout_s must be positive"


def test_no_id_deadline_during_kit_catalog_keeps_timeout_result(dirs: Dict[str, Path]) -> None:
    now = [100.0]

    class SlowBridge(FakeKitBridge):
        def kit_list(self, *, timeout: Optional[float] = None) -> Dict[str, Any]:
            now[0] += 50.0
            return super().kit_list(timeout=timeout)

    res = _no_id_flow(
        dirs, prompt=VIDEO_PROMPT, kit_bridge=SlowBridge(), timeout_s=10.0, clock=lambda: now[0]
    )
    assert res.status == "timeout"
    assert res.message == "New-project flow timed out during kit matching"
    assert list(dirs["dest_root"].iterdir()) == []


def test_guess_helpers_are_gone_from_the_flow_module() -> None:
    for name in (
        "choose_catalog_entry",
        "_handle_no_match_handoff",
        "_resolve_chosen_template",
        "_format_kits_unavailable_handoff_sentence",
        "build_handoff",
        "request_handoff",
    ):
        assert not hasattr(new_project, name), name


def _bundled_template_ids() -> list:
    return sorted(spec.id for spec in load_templates(new_project.default_templates_root()))


def _first_choice(question: Any, _prefill: Any) -> Any:
    value = question.choices[0].value
    return [value] if question.multi else value


@pytest.mark.parametrize("template_id", _bundled_template_ids())
def test_every_bundled_template_reaches_confirmation_with_a_copy_of_the_proposal(
    dirs: Dict[str, Path], template_id: str
) -> None:
    seen: list = []

    def confirm(prop: Any) -> bool:
        seen.append(prop)
        return False

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(scaffolder.toolchk, "probe", lambda *_a, **_k: ("1.0.0", "fixture-tool"))
        res = run_new_project_flow(
            template_id=template_id,
            ask=_first_choice,
            name_provider=lambda: "demo-app",
            choose_options=lambda _spec, current: current,
            confirm=confirm,
            register=_never("register"),
            db_path=dirs["db"],
            dest_root=dirs["dest_root"],
            staging_parent=dirs["staging_parent"],
            kits=[],
        )

    assert len(seen) == 1, (res.status, res.message)
    assert seen[0].template_id == template_id
    assert seen[0] is not res.proposal
    assert res.status not in ("created", "needs_choice"), res.status
    assert list(dirs["dest_root"].iterdir()) == []


def test_flow_no_longer_accepts_persist_answers() -> None:
    import inspect

    assert "persist_answers" not in inspect.signature(run_new_project_flow).parameters


def test_handoff_module_keeps_only_the_brief_builder() -> None:
    from hermes_plugins.defuzz import handoff

    assert hasattr(handoff, "build_handoff")
    for name in ("request_handoff", "HandoffTimeout", "HandoffUnavailable", "HandoffSenderContractError"):
        assert not hasattr(handoff, name), name
