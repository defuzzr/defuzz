"""Tests for project kit support in dashboard/routes/workspace_routes.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule
from tests.fake_kit_bridge import VIDEO_DECLARED_DIRS, FakeKitBridge, load_list_fixture, load_show_fixture
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

_FIXTURE_KIT_IDS = [k["id"] for k in load_list_fixture()["kits"]]


@pytest.fixture(autouse=True)
def _reset_workspace_routes_kit_cache() -> None:
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    routes._reset_kit_cache_for_tests()
    load_submodule("dashboard.routes.workspace_routes")._reset_kit_cache_for_tests()


def _build_client(monkeypatch: pytest.MonkeyPatch, fake_bridge: FakeKitBridge) -> TestClient:
    bridge_mod = load_submodule("componentize_bridge")
    fake_bridge.install(monkeypatch, bridge_mod)
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    fake_bridge.install(monkeypatch, routes.componentize_bridge)
    routes._reset_kit_cache_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    return TestClient(app)


def test_match_route_video_request_prefers_kit_and_suppresses_code_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    resp = client.post(
        "/scaffold/match",
        json={
            "answers": {"building": "video"},
            "prompt": "set up a video production project called Night Shoot",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["preferred"] == "kit"
    assert len(data["kits"]) >= 1
    assert data["kits"][0]["kit_id"] == "video-production"
    assert data["kits"][0]["score"] >= 3
    assert data["kits"][0]["reasons"]
    assert set(data["kits"][0].keys()) >= {
        "kit_id",
        "name",
        "summary",
        "tags",
        "score",
        "reasons",
    }
    assert [k["kit_id"] for k in data["kit_catalog"]] == _FIXTURE_KIT_IDS
    assert data["kits_notice"] == ""
    assert data["closest"] == []
    assert data["handoff"] is None

    # When kits are unavailable, a kit-kind request goes back to closest/handoff as before kits existed
    unavail_client = _build_client(
        monkeypatch,
        FakeKitBridge(status="unavailable", notice="componentize CLI is unavailable."),
    )
    resp_unavail = unavail_client.post(
        "/scaffold/match",
        json={"answers": {"building": "video"}},
    )
    assert resp_unavail.status_code == 200
    unavail_data = resp_unavail.json()
    assert unavail_data["preferred"] == "none"
    assert unavail_data["kits"] == []
    assert unavail_data["kit_catalog"] == []
    assert "unavailable" in unavail_data["kits_notice"].lower()
    assert len(unavail_data["closest"]) == 1
    assert unavail_data["handoff"] is not None
    assert "text" in unavail_data["handoff"]


def test_match_route_code_request_unchanged_apart_from_added_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    code_answers = {"building": "service", "layout": "single", "languages": ["python"]}
    resp = client.post("/scaffold/match", json={"answers": code_answers})
    assert resp.status_code == 200
    data = resp.json()
    assert data["preferred"] == "template"
    assert len(data["matches"]) >= 1
    assert data["matches"][0]["template_id"] == "python-golden"
    assert data["closest"] == []
    assert data["handoff"] is None
    assert data["kits_notice"] == ""
    assert len(data["kit_catalog"]) == len(_FIXTURE_KIT_IDS)

    # Explicit language answers chosen by caller alongside a prompt that omits language
    # must route to the Python template, not to a kit.
    repro_resp = client.post(
        "/scaffold/match",
        json={
            "prompt": "a video editing pipeline for film storyboards",
            "answers": {"building": "tool", "languages": ["python"]},
            "languages_chosen": True,
        },
    )
    assert repro_resp.status_code == 200
    repro_data = repro_resp.json()
    assert repro_data["preferred"] == "template"
    assert repro_data["matches"][0]["template_id"] == "python-golden"

    # A prompt with no language and no language answers still reaches a strong kit
    no_lang_resp = client.post(
        "/scaffold/match",
        json={
            "prompt": "a video editing pipeline for film storyboards",
            "answers": {"building": "tool"},
        },
    )
    assert no_lang_resp.status_code == 200
    no_lang_data = no_lang_resp.json()
    assert no_lang_data["preferred"] == "kit"
    assert no_lang_data["kits"][0]["kit_id"] == "video-channel"
    # Weak kit hit on an unmatched code game request must not set preferred='kit' or suppress closest/handoff
    weak_resp = client.post(
        "/scaffold/match",
        json={"prompt": "make a rust bevy game called Star Dust"},
    )
    assert weak_resp.status_code == 200
    weak_data = weak_resp.json()
    assert weak_data["matches"] == []
    assert weak_data["preferred"] == "none"
    assert len(weak_data["closest"]) == 1
    assert isinstance(weak_data["handoff"], dict)
    assert "text" in weak_data["handoff"]


_DEFAULT_SYNC_ANSWERS = {
    "building": "service",
    "layout": "mono",
    "languages": ["typescript"],
}

_DEFAULT_SYNC_KIT_CASES = [
    ("set up a video project", "video-channel"),
    ("a video editing pipeline for film storyboards", "video-channel"),
    ("home server inventory for my homelab", "homelab"),
    ("storyboard for my comic", "comic-storyboard"),
    ("music production workspace", "music-production"),
    ("godot game called Hop", "godot-game"),
]


def test_match_route_desktop_default_languages_vs_languages_chosen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    # (a) Exact body shape sent by desktop's automatic syncModalOptionsFromMatch (default ts-node-golden)
    # when languages_chosen is absent or False: unchosen defaults must never override what the prompt says.
    for prompt_text, expected_kit in _DEFAULT_SYNC_KIT_CASES:
        auto_body = {
            "answers": dict(_DEFAULT_SYNC_ANSWERS),
            "prompt": prompt_text,
        }
        resp = client.post("/scaffold/match", json=auto_body)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["preferred"] == "kit", f"{prompt_text!r} expected kit, got {data['preferred']!r}"
        assert data["kits"][0]["kit_id"] == expected_kit

        # Also when languages_chosen is explicitly False
        resp_false = client.post(
            "/scaffold/match",
            json={**auto_body, "languages_chosen": False},
        )
        assert resp_false.status_code == 200
        assert resp_false.json()["preferred"] == "kit"
        assert resp_false.json()["kits"][0]["kit_id"] == expected_kit

    # Plain code prompt with the same default body still gets its template
    code_resp = client.post(
        "/scaffold/match",
        json={
            "answers": dict(_DEFAULT_SYNC_ANSWERS),
            "prompt": "python backend service called Api",
        },
    )
    assert code_resp.status_code == 200, code_resp.text
    code_data = code_resp.json()
    assert code_data["preferred"] == "template"
    assert code_data["matches"][0]["template_id"] == "python-golden"

    rust_resp = client.post(
        "/scaffold/match",
        json={
            "answers": dict(_DEFAULT_SYNC_ANSWERS),
            "prompt": "rust cli tool called Rn",
        },
    )
    assert rust_resp.status_code == 200, rust_resp.text
    rust_data = rust_resp.json()
    assert rust_data["preferred"] == "template"
    assert rust_data["matches"][0]["template_id"] == "rust-golden"

    # Prompts that name a code kind without naming a language ask ('none') instead of
    # guessing python-golden or inheriting an unchosen ts-node default.
    for unnamed_lang_prompt in (
        "backend service called Api",
        "cli tool for renaming files",
        "a library called Utils",
        "Inventory API for my shop",
        "an app",
        "notes app",
    ):
        resp_default = client.post(
            "/scaffold/match",
            json={
                "answers": dict(_DEFAULT_SYNC_ANSWERS),
                "prompt": unnamed_lang_prompt,
            },
        )
        assert resp_default.status_code == 200, resp_default.text
        default_data = resp_default.json()
        assert default_data["preferred"] == "none", unnamed_lang_prompt
        assert default_data["matches"] == [], unnamed_lang_prompt
        assert default_data["closest"] == [], unnamed_lang_prompt

    for prompt_text, expected_no_ans in (
        ("backend service called Api", ("none", None)),
        ("cli tool for renaming files", ("none", None)),
        ("a library called Utils", ("none", None)),
        ("Inventory API for my shop", ("none", None)),
        ("rust cli tool called Rn", ("template", "rust-golden")),
        ("python backend service called Api", ("template", "python-golden")),
        ("set up a video project", ("kit", "video-channel")),
        ("a video editing pipeline for film storyboards", ("kit", "video-channel")),
        ("home server inventory for my homelab", ("kit", "homelab")),
        ("storyboard for my comic", ("kit", "comic-storyboard")),
        ("music production workspace", ("kit", "music-production")),
        ("godot game called Hop", ("kit", "godot-game")),
    ):
        resp_no_ans = client.post(
            "/scaffold/match",
            json={"prompt": prompt_text},
        )
        assert resp_no_ans.status_code == 200, resp_no_ans.text
        no_ans_data = resp_no_ans.json()
        exp_kind, exp_id = expected_no_ans
        assert no_ans_data["preferred"] == exp_kind, prompt_text
        if exp_kind == "kit":
            assert no_ans_data["kits"][0]["kit_id"] == exp_id, prompt_text
        elif exp_kind == "template":
            assert no_ans_data["matches"][0]["template_id"] == exp_id, prompt_text
        else:
            assert no_ans_data["matches"] == [], prompt_text
            assert no_ans_data["closest"] == [], prompt_text

    # Vague prompt with no detectable kind + unchosen default body asks instead of
    # silently defaulting to ts-node-golden, mirroring the standalone matcher.
    no_kind_resp = client.post(
        "/scaffold/match",
        json={
            "answers": dict(_DEFAULT_SYNC_ANSWERS),
            "prompt": "mystery project",
        },
    )
    assert no_kind_resp.status_code == 200, no_kind_resp.text
    no_kind_data = no_kind_resp.json()
    assert no_kind_data["preferred"] == "none"
    assert no_kind_data["matches"] == []
    assert no_kind_data["closest"] == []

    for prompt_text, expected_kit in (
        ("home server inventory for my homelab", "homelab"),
        ("a video editing pipeline for film storyboards", "video-channel"),
    ):
        # (b) Same bodies plus languages_chosen: True and languages: ['python'] -> python-golden
        chosen_body = {
            "answers": {
                "building": "service",
                "layout": "mono",
                "languages": ["python"],
            },
            "prompt": prompt_text,
            "languages_chosen": True,
        }
        resp_chosen = client.post("/scaffold/match", json=chosen_body)
        assert resp_chosen.status_code == 200, resp_chosen.text
        chosen_data = resp_chosen.json()
        assert chosen_data["preferred"] == "template"
        assert chosen_data["matches"][0]["template_id"] == "python-golden"

        # (d) languages: ['other'] does not count as naming a language even with languages_chosen: True
        other_body = {
            "answers": {
                "building": "service",
                "layout": "mono",
                "languages": ["other"],
            },
            "prompt": prompt_text,
            "languages_chosen": True,
        }
        resp_other = client.post("/scaffold/match", json=other_body)
        assert resp_other.status_code == 200, resp_other.text
        other_data = resp_other.json()
        assert other_data["preferred"] == "kit"
        assert other_data["kits"][0]["kit_id"] == expected_kit

    # (e) Non-boolean languages_chosen values ('true', 1, 0, [True], None, False) are treated as False, never 400
    for non_true_val in ("true", 1, 0, [True], None, False, {}, "false"):
        resp_non_bool = client.post(
            "/scaffold/match",
            json={
                "answers": dict(_DEFAULT_SYNC_ANSWERS),
                "prompt": "set up a video project",
                "languages_chosen": non_true_val,
            },
        )
        assert resp_non_bool.status_code == 200, f"{non_true_val!r} returned {resp_non_bool.status_code}"
        assert resp_non_bool.json()["preferred"] == "kit"
        assert resp_non_bool.json()["kits"][0]["kit_id"] == "video-channel"


_AGREEMENT_PROMPTS = [
    ("kit-video", "a video editing pipeline for film storyboards"),
    ("kit-homelab", "home server inventory for my homelab"),
    ("code-python", "python backend service"),
    ("none", None),
]

_AGREEMENT_ANSWERS = [
    ("absent", None, False, False),
    ("building_tool", {"building": "tool"}, False, False),
    ("lang_python_chosen", {"languages": ["python"]}, True, False),
    ("lang_python_not_chosen", {"languages": ["python"]}, False, True),
    ("desktop_default", dict(_DEFAULT_SYNC_ANSWERS), False, True),
    ("tool_and_python_chosen", {"building": "tool", "languages": ["python"]}, True, False),
    ("lang_other", {"languages": ["other"]}, True, False),
]

_AGREEMENT_EXPECTED = {
    ("kit-video", "absent"): ("kit", "video-channel"),
    ("kit-video", "building_tool"): ("kit", "video-channel"),
    ("kit-video", "lang_python_chosen"): ("kit", "video-channel"),
    ("kit-video", "lang_python_not_chosen"): ("kit", "video-channel"),
    ("kit-video", "desktop_default"): ("kit", "video-channel"),
    ("kit-video", "tool_and_python_chosen"): ("template", "python-golden"),
    ("kit-video", "lang_other"): ("kit", "video-channel"),
    ("kit-homelab", "absent"): ("kit", "homelab"),
    ("kit-homelab", "building_tool"): ("kit", "homelab"),
    ("kit-homelab", "lang_python_chosen"): ("template", "python-golden"),
    ("kit-homelab", "lang_python_not_chosen"): ("kit", "homelab"),
    ("kit-homelab", "desktop_default"): ("kit", "homelab"),
    ("kit-homelab", "tool_and_python_chosen"): ("template", "python-golden"),
    ("kit-homelab", "lang_other"): ("kit", "homelab"),
    ("code-python", "absent"): ("template", "python-golden"),
    ("code-python", "building_tool"): ("template", "python-golden"),
    ("code-python", "lang_python_chosen"): ("template", "python-golden"),
    ("code-python", "lang_python_not_chosen"): ("template", "python-golden"),
    ("code-python", "desktop_default"): ("template", "python-golden"),
    ("code-python", "tool_and_python_chosen"): ("template", "python-golden"),
    ("code-python", "lang_other"): ("template", "python-golden"),
    # The five "none" rows below were skipped while the flow half needed a questionnaire;
    # the flow no longer asks without an id, so all 28 combinations now run.
    ("none", "absent"): ("none", None),
    ("none", "building_tool"): ("none", None),
    ("none", "lang_python_chosen"): ("template", "python-golden"),
    ("none", "lang_python_not_chosen"): ("template", "python-golden"),
    ("none", "tool_and_python_chosen"): ("template", "python-golden"),
    ("none", "lang_other"): ("none", None),
    ("none", "desktop_default"): ("template", "ts-node-golden"),
}


@pytest.mark.parametrize("prompt_label,prompt_text", _AGREEMENT_PROMPTS)
@pytest.mark.parametrize(
    "ans_label,caller_answers,languages_chosen,route_only",
    _AGREEMENT_ANSWERS,
)
def test_flow_and_route_catalog_agreement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prompt_label: str,
    prompt_text: str | None,
    ans_label: str,
    caller_answers: dict[str, Any] | None,
    languages_chosen: bool,
    route_only: bool,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    route_body: dict[str, Any] = {}
    if prompt_text is not None:
        route_body["prompt"] = prompt_text
    if caller_answers is not None:
        route_body["answers"] = dict(caller_answers)
    if languages_chosen:
        route_body["languages_chosen"] = True

    resp = client.post("/scaffold/match", json=route_body)
    assert resp.status_code == 200, resp.text
    r_data = resp.json()
    route_kind = r_data["preferred"]
    if route_kind == "kit":
        route_id = r_data["kits"][0]["kit_id"]
    elif route_kind == "template":
        route_id = r_data["matches"][0]["template_id"]
    else:
        route_id = None

    expected = _AGREEMENT_EXPECTED[(prompt_label, ans_label)]
    assert (route_kind, route_id) == expected

    # The route's list marks the preferred pick first: catalog_list.suggested_ids puts the
    # matches of the preferred kind first, in matcher order, so suggested[0] is that pick.
    catalog = r_data["catalog"]
    entry_keys = [f"{e['kind']}:{e['id']}" for e in catalog["entries"]]
    assert len(entry_keys) == len(set(entry_keys))
    assert set(catalog["suggested"]) <= set(entry_keys)
    assert len(catalog["suggested"]) <= 3
    if route_kind == "none":
        # suggested_ids merges both kinds by score; the route has no matches here.
        assert r_data["matches"] == [] and r_data["kits"] == []
        assert catalog["suggested"] == []
    else:
        assert catalog["suggested"][0] == f"{route_kind}:{route_id}"

    # The flow no longer chooses: for the same input, without an id, it returns
    # needs_choice, asks nothing and writes nothing.
    new_project_mod = load_submodule("new_project")
    state_store_mod = load_submodule("state_store")
    dest_root = tmp_path / "projects"
    staging_parent = tmp_path / "staging"
    dest_root.mkdir()
    staging_parent.mkdir()
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))

    def _never(label: str) -> Any:
        def _cb(*_a: Any, **_k: Any) -> Any:
            pytest.fail(f"{label} called without an explicit id in {prompt_label} x {ans_label}")

        return _cb

    flow_res = new_project_mod.run_new_project_flow(
        prompt=prompt_text,
        initial_answers=dict(caller_answers) if caller_answers is not None else None,
        ask=_never("ask"),
        name_provider=_never("name_provider"),
        confirm=_never("confirm"),
        confirm_kit=_never("confirm_kit"),
        register=_never("register"),
        db_path=state_store_mod.state_db_path(),
        dest_root=dest_root,
        staging_parent=staging_parent,
        kit_bridge=FakeKitBridge(),
    )
    assert flow_res.status == "needs_choice", flow_res.message
    assert flow_res.message == ""
    assert flow_res.proposal is None
    assert flow_res.kit_proposal is None
    assert flow_res.accept is None
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    assert list(dest_root.iterdir()) == []
    assert list(staging_parent.iterdir()) == []


def test_get_kit_route_happy_path_bad_id_and_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    # 1. Valid kit_id returns kit, tree, declared_dirs, placement_rules
    resp = client.get("/scaffold/kits/video-production")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    expected_show = load_show_fixture()
    assert data == {
        "kit": expected_show["kit"],
        "tree": expected_show["tree"],
        "declared_dirs": expected_show["declared_dirs"],
        "placement_rules": expected_show["placement_rules"],
    }
    assert "AGENTS.md" in data["tree"]

    # 2. Bad id format -> 404 without calling kit_show
    bridge.show_calls.clear()
    for bad_id in ("Invalid_ID", "-bad", "bad--id"):
        r_bad = client.get(f"/scaffold/kits/{bad_id}")
        assert r_bad.status_code == 404
    assert bridge.show_calls == []

    # 3. Unknown valid-format id -> 404
    r_unknown = client.get("/scaffold/kits/nonexistent-kit")
    assert r_unknown.status_code == 404

    # 4. Unavailable bridge -> 503 with notice
    unavail_client = _build_client(
        monkeypatch,
        FakeKitBridge(status="unavailable", notice="componentize CLI is unavailable."),
    )
    r_503 = unavail_client.get("/scaffold/kits/video-production")
    assert r_503.status_code == 503
    assert "componentize CLI is unavailable" in r_503.text

    # 5. Kit id is in the cached catalog, but kit_show returns bridge status 'error' -> 502 with notice
    err_show_client = _build_client(
        monkeypatch,
        FakeKitBridge(
            list_status="ok",
            show_status="error",
            show_notice="componentize kit show envelope validation failed.",
        ),
    )
    r_502 = err_show_client.get("/scaffold/kits/video-production")
    assert r_502.status_code == 502
    assert "componentize kit show envelope validation failed." in r_502.text


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_propose_accept_discard_kit_and_template_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()

    # 1. Propose with both template_id and kit_id or neither -> 400
    assert (
        client.post(
            "/scaffold/propose",
            json={
                "template_id": "python-golden",
                "kit_id": "video-production",
                "name": "Both",
                "dest_root": str(projects_dir),
            },
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/scaffold/propose",
            json={"name": "Neither", "dest_root": str(projects_dir)},
        ).status_code
        == 400
    )

    # 2. Propose with kit_id then discard removes staging
    prop_discard = client.post(
        "/scaffold/propose",
        json={
            "kit_id": "video-production",
            "name": "Discard Shoot",
            "answers": {"building": "video"},
            "dest_root": str(projects_dir),
        },
    )
    assert prop_discard.status_code == 200, prop_discard.text
    p_disc_data = prop_discard.json()
    assert p_disc_data["kind"] == "kit"
    assert p_disc_data["kit_id"] == "video-production"
    assert p_disc_data["slug"] == "discard-shoot"
    assert len(p_disc_data["tree"]) == 1
    assert p_disc_data["tree"][0]["name"] == "discard-shoot"
    assert p_disc_data["tree"][0]["dest"] == str(projects_dir / "discard-shoot")
    assert "AGENTS.md" in p_disc_data["tree"][0]["files"]
    assert p_disc_data["declared_dirs"]
    assert p_disc_data["placement_rules"]

    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    staged_obj = routes._PROPOSALS[p_disc_data["proposal_id"]]["proposal"]
    staging_dir = staged_obj.staging_dir
    assert staging_dir.is_dir()

    disc_resp = client.post(
        "/scaffold/discard", json={"proposal_id": p_disc_data["proposal_id"]}
    )
    assert disc_resp.status_code == 200
    assert not staging_dir.exists()
    assert not (projects_dir / "discard-shoot").exists()

    # 3. Propose with kit_id then accept creates the project under tmp_path and returns placement: 'on'
    prop_accept = client.post(
        "/scaffold/propose",
        json={
            "kit_id": "video-production",
            "name": "Night Shoot",
            "answers": {"building": "video"},
            "dest_root": str(projects_dir),
        },
    )
    assert prop_accept.status_code == 200, prop_accept.text
    p_acc_data = prop_accept.json()

    acc_resp = client.post(
        "/scaffold/accept",
        json={"proposal_id": p_acc_data["proposal_id"], "confirm": True},
    )
    assert acc_resp.status_code == 200, acc_resp.text
    acc_data = acc_resp.json()
    assert acc_data["status"] == "created"
    assert acc_data["placement"] == "on"
    dest_path = projects_dir / "night-shoot"
    assert acc_data.get("dest") == str(dest_path) or acc_data["repos"][0]["path"] == str(dest_path)
    assert dest_path.is_dir()
    assert (dest_path / ".git").is_dir()
    for entry in VIDEO_DECLARED_DIRS:
        assert (dest_path / entry["dir"]).is_dir()

    # 4. Template propose/accept round trip still works
    fixtures_templates = Path(__file__).resolve().parent / "fixtures" / "templates"
    orig_load_templates = routes.templates.load_templates
    monkeypatch.setattr(
        routes.templates,
        "load_templates",
        lambda root=None: orig_load_templates(fixtures_templates if root is None else root),
    )

    tmpl_prop = client.post(
        "/scaffold/propose",
        json={
            "template_id": "fake-rust-game",
            "name": "Star Cruiser",
            "answers": {
                "building": "game",
                "layout": "mono",
                "languages": ["rust"],
                "engine": "bevy",
            },
            "dest_root": str(projects_dir),
        },
    )
    assert tmpl_prop.status_code == 200, tmpl_prop.text
    t_data = tmpl_prop.json()
    assert t_data["tree"]

    tmpl_acc = client.post(
        "/scaffold/accept",
        json={"proposal_id": t_data["proposal_id"], "confirm": True},
    )
    assert tmpl_acc.status_code == 200, tmpl_acc.text
    assert tmpl_acc.json()["status"] == "created"
    assert (projects_dir / "star-cruiser" / ".git").is_dir()

    # 5. KitUnavailable on propose -> 503 and slot released
    unavail_client = _build_client(
        monkeypatch,
        FakeKitBridge(status="unavailable", notice="componentize CLI is unavailable."),
    )
    r_unavail = unavail_client.post(
        "/scaffold/propose",
        json={
            "kit_id": "video-production",
            "name": "Unavail Shoot",
            "answers": {"building": "video"},
            "dest_root": str(projects_dir),
        },
    )
    assert r_unavail.status_code == 503
    assert routes._PROPOSALS == {}


def test_hermetic_guard_covers_dashboard_bridge_copy_without_spawning_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    routes._reset_kit_cache_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()

    def _forbid_popen(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("subprocess.Popen must not be called under hermetic guard")

    monkeypatch.setattr(routes.componentize_bridge.subprocess, "Popen", _forbid_popen)

    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)

    resp = client.post(
        "/scaffold/match",
        json={"answers": {"building": "video"}},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "unavailable" in data["kits_notice"].lower()


def test_match_route_caches_kit_catalog_across_consecutive_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    r1 = client.post("/scaffold/match", json={"answers": {"building": "video"}})
    r2 = client.post("/scaffold/match", json={"answers": {"building": "video"}})
    r3 = client.get("/scaffold/kits/video-production")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 200
    assert len(bridge.list_calls) == 1

    # Non-ok status ('unavailable' / 'error') is cached for 5 seconds; advancing clock past 5 s re-queries
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    routes._reset_kit_cache_for_tests()
    bridge.list_calls.clear()
    fake_now = [100.0]
    monkeypatch.setattr(routes.time, "monotonic", lambda: fake_now[0])

    bridge.list_status = "unavailable"
    r_unavail_1 = client.post("/scaffold/match", json={"answers": {"building": "video"}})
    assert r_unavail_1.status_code == 200
    assert r_unavail_1.json()["kit_catalog"] == []
    assert len(bridge.list_calls) == 1

    fake_now[0] += 2.0
    r_unavail_2 = client.post("/scaffold/match", json={"answers": {"building": "video"}})
    assert r_unavail_2.status_code == 200
    assert r_unavail_2.json()["kit_catalog"] == []
    assert len(bridge.list_calls) == 1

    # Advance past 5 s TTL -> calls bridge again
    fake_now[0] += 3.5
    bridge.list_status = "ok"
    r_recovered = client.post("/scaffold/match", json={"answers": {"building": "video"}})
    assert r_recovered.status_code == 200
    assert len(r_recovered.json()["kit_catalog"]) == len(_FIXTURE_KIT_IDS)
    assert len(bridge.list_calls) == 2


def test_notice_helper_falls_back_when_bridge_dict_lacks_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    monkeypatch.setattr(
        routes.componentize_bridge,
        "kit_list",
        lambda **_kwargs: {"status": "unavailable", "data": None, "notice": None, "exit": None},
    )

    resp = client.post("/scaffold/match", json={"answers": {"building": "video"}})
    assert resp.status_code == 200
    assert resp.json()["kits_notice"] == "componentize CLI is unavailable"


def test_match_route_non_project_request_returns_no_match_without_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = FakeKitBridge()
    client = _build_client(monkeypatch, bridge)

    resp = client.post("/scaffold/match", json={"prompt": "summarize this video"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["preferred"] == "none"
    assert data["matches"] == []
    assert data["kits"] == []
    assert data["closest"] == []
    assert data["handoff"] is None
    assert data["message"] == "This does not look like a request to set up a new project."


def _propose_kit(client: TestClient, projects_dir: Path, name: str) -> dict:
    resp = client.post(
        "/scaffold/propose",
        json={"kit_id": "video-production", "name": name, "answers": {"building": "video"},
              "dest_root": str(projects_dir)},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_proposal_is_bound_to_the_hermes_home_that_made_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    routes = load_submodule("dashboard.plugin_api")._load("dashboard.routes.workspace_routes")
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    pid = _propose_kit(client, projects_dir, "Home Bound")["proposal_id"]
    staging_dir = routes._PROPOSALS[pid]["proposal"].staging_dir
    home_a = __import__("os").environ["HERMES_HOME"]
    other = tmp_path / "other-home"
    other.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(other))
    for path, body in (("/scaffold/accept", {"proposal_id": pid, "confirm": True}),
                       ("/scaffold/discard", {"proposal_id": pid})):
        resp = client.post(path, json=body)
        assert resp.status_code == 404, resp.text
        assert resp.json() == {"detail": "Unknown or consumed proposal_id"}
    assert routes._PROPOSALS[pid]["state"] == "ready"
    assert staging_dir.is_dir()
    assert not (projects_dir / "home-bound").exists()
    monkeypatch.setenv("HERMES_HOME", home_a)
    assert client.post("/scaffold/discard", json={"proposal_id": pid}).status_code == 200
    assert not staging_dir.exists()


def test_abandoned_proposals_expire_but_one_being_accepted_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    routes = load_submodule("dashboard.plugin_api")._load("dashboard.routes.workspace_routes")
    assert routes._PROPOSAL_TTL_S == 30 * 60
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    old = _propose_kit(client, projects_dir, "Old One")["proposal_id"]
    busy = _propose_kit(client, projects_dir, "Busy One")["proposal_id"]
    old_staging = routes._PROPOSALS[old]["proposal"].staging_dir
    with routes._LOCK:
        routes._PROPOSALS[busy]["state"] = "accepting"
    # Not yet expired: still there after the table is touched again.
    fresh = _propose_kit(client, projects_dir, "Fresh One")["proposal_id"]
    assert old in routes._PROPOSALS
    monkeypatch.setattr(routes, "_PROPOSAL_TTL_S", 0.0)
    assert client.post("/scaffold/accept", json={"proposal_id": old, "confirm": True}).status_code == 404
    assert old not in routes._PROPOSALS and fresh not in routes._PROPOSALS
    assert not old_staging.exists()
    assert routes._PROPOSALS[busy]["state"] == "accepting"
    # Expired slots are free again: fill the table once more without a 429.
    monkeypatch.setattr(routes, "_PROPOSAL_TTL_S", 30 * 60.0)
    with routes._LOCK:
        for i in range(routes._MAX_PROPOSALS):
            routes._PROPOSALS[f"stale{i}"] = {"state": "ready", "kind": "kit", "proposal": None,
                                               "created": 0.0, "home": "x"}
    monkeypatch.setattr(routes, "_PROPOSAL_TTL_S", 0.0)
    _propose_kit(client, projects_dir, "After Expiry")
    assert not any(k.startswith("stale") for k in routes._PROPOSALS)
    with routes._LOCK:
        routes._PROPOSALS.clear()


def test_retired_render_provider_is_never_listed_or_suggested(monkeypatch):
    # Keep the retired provider's name out of the published source catalog.
    import json

    provider = "Co" + "lab"
    client = _build_client(monkeypatch, FakeKitBridge())
    response = client.post('/scaffold/match', json={
        'prompt': f'render Blender scenes on {provider}',
    })
    assert response.status_code == 200
    data = response.json()
    kits = [e for e in data['catalog']['entries'] if e['kind'] == 'kit']
    assert len(kits) == 14
    assert all(e.get('selectable', True) for e in kits)
    assert provider.lower() not in json.dumps([data['catalog'], data['kits'], data['kit_catalog']]).lower()
