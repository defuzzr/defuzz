"""Beginner first requests: site and page words reach the web-golden template, web-app and
design-handoff words reach the web-app kit, vague requests ask,
component-library requests reach their kit (routes, matcher, and headless new flow)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import pytest

from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import FakeKitBridge, load_list_fixture
from tests.test_kit_routes import _DEFAULT_SYNC_ANSWERS, _build_client

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # noqa: E402
    KitInfo,
    KitMatch,
    Match,
    _tokenize_prompt,
    choose_catalog_entry,
    closest,
    match_kits,
)
from hermes_plugins.defuzz.new_project import run_new_project_flow  # noqa: E402
from hermes_plugins.defuzz.prompt_parse import parse_deterministic  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402

_KITS: List[KitInfo] = [k for k in (KitInfo.from_dict(r) for r in load_list_fixture()["kits"]) if k]

WEBSITE_PROMPTS = [
    "make me a website",
    "a website for my band",
    "build a landing page",
    "portfolio site",
    "a web site for my bakery",
    "a homepage for my club",
    "my home page",
    "a blog",
    "a simple web page",
    "two webpages for my shop",
    "personal portfolios",
]

COMPONENT_PROMPTS = [
    "component library",
    "reusable components",
    "reusable python component library",
    "personal toolbox of reusable python functions",
]

UI_NON_PYTHON_COMPONENT_PROMPTS = [
    "ui kit",
    "design system components",
    "storybook style component kit",
    "a set of reusable buttons and cards",
]


def _match(client: Any, prompt: str, answers: Dict[str, Any] | None, **extra: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {"answers": dict(answers or {}), "prompt": prompt, **extra}
    resp = client.post("/scaffold/match", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


# (1) word normalisation


def test_two_letter_kit_words_ui_and_3d_are_kept() -> None:
    assert "ui" in _tokenize_prompt("a ui for my shop")
    assert "3d" in _tokenize_prompt("a 3d studio")
    # other short words are still dropped
    assert _tokenize_prompt("me a go at it") == []


@pytest.mark.parametrize("prompt", WEBSITE_PROMPTS)
def test_website_family_words_rank_web_app_kit_first_and_strong(prompt: str) -> None:
    km = match_kits(_KITS, prompt, parse_deterministic(prompt).answers)
    assert km, f"no kit matched {prompt!r}"
    assert km[0].kit.id == "web-app"
    assert km[0].score >= 6
    assert any("website" in r for r in km[0].reasons)


# (2) website prompts prefer the web-golden template when no language is named
# (changed when web-golden was added: these site/page requests used to reach the web-app kit,
# which had been their only home; the kit still ranks first among kits, see test above)


@pytest.mark.parametrize("prompt", WEBSITE_PROMPTS)
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_website_prompt_prefers_web_golden_template(monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "template", data["preferred"]
    assert data["matches"][0]["template_id"] == "web-golden"
    assert [m["template_id"] for m in data["matches"]] == ["web-golden"]
    assert data["kits"][0]["kit_id"] == "web-app"
    assert data["closest"] == []


def test_chosen_language_menu_still_wins_for_website(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    data = _match(client, "make me a website", _DEFAULT_SYNC_ANSWERS, languages_chosen=True)
    assert data["preferred"] == "template"
    assert data["matches"][0]["template_id"] == "ts-node-golden"


@pytest.mark.parametrize("answers", [None, _DEFAULT_SYNC_ANSWERS])
def test_named_language_website_keeps_python_template(monkeypatch: pytest.MonkeyPatch, answers: Any) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    data = _match(client, "python website with flask", answers)
    assert data["preferred"] == "template"
    assert data["matches"][0]["template_id"] == "python-golden"


def test_web_app_prompt_unchanged_surfaces_kit_prefers_template(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    data = _match(client, "make me a web app", _DEFAULT_SYNC_ANSWERS)
    assert data["preferred"] == "kit"
    assert data["kits"][0]["kit_id"] == "web-app"

    rust_data = _match(client, "web app in rust", _DEFAULT_SYNC_ANSWERS)
    assert rust_data["preferred"] == "template"
    assert rust_data["matches"][0]["template_id"] == "rust-golden"


# (3) no silent fall-through to an unrelated language template


@pytest.mark.parametrize("prompt", ["discord bot", "something cool"])
def test_vague_prompt_without_answers_asks_and_names_no_template(
    monkeypatch: pytest.MonkeyPatch, prompt: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    data = _match(client, prompt, None)
    assert data["preferred"] == "none"
    assert data["matches"] == []
    assert data["closest"] == []
    handoff = data["handoff"]
    assert handoff is None or "Closest template folder" not in handoff["text"]


@pytest.mark.parametrize("answers", [None, _DEFAULT_SYNC_ANSWERS])
def test_make_a_game_asks_when_no_game_kit_is_strong(monkeypatch: pytest.MonkeyPatch, answers: Any) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    data = _match(client, "make a game", answers)
    assert data["preferred"] == "none", data


def test_closest_returns_none_when_only_other_language_and_tie() -> None:
    templates = load_templates()
    answers = {"building": "other", "layout": "mono", "languages": ["other"]}
    assert closest(templates, answers) is None
    # a real language still yields a closest candidate
    assert closest(templates, {"building": "tool", "layout": "mono", "languages": ["rust"]}) is not None


_NOTHING_CREATED = "Nothing was created. Run again with --template ID or --kit ID."
_FLAG_RE = re.compile(r"\[--(template|kit) ([^\]\s]+)\]")


def _headless_new(tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any, prompt: str) -> List[str]:
    """Run `hermes defuzz new --prompt ... --yes` without an id; return the suggested rows.

    Asserts exit 2, the whole list printed, the closing line, and nothing written anywhere.
    """
    from hermes_plugins.defuzz import cli, componentize_bridge  # type: ignore[import-not-found]

    FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(
        cli,
        "REGISTER_PROJECT",
        lambda *_a, **_k: pytest.fail("nothing may be registered without an explicit id"),
    )
    dest = tmp_path / "dest"
    dest.mkdir()
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    rc = cli.main(["new", "--prompt", prompt, "--yes", "--dest-root", str(dest)])
    out = capsys.readouterr().out
    assert rc == 2, (prompt, rc, out)
    lines = out.rstrip().splitlines()
    assert lines[-1] == _NOTHING_CREATED, out
    flags = [f"{m.group(1)}:{m.group(2)}" for m in map(_FLAG_RE.search, lines) if m]
    assert "template:web-golden" in flags and "kit:web-app" in flags, out  # the whole list
    assert len(flags) == len(set(flags))
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    assert list(dest.iterdir()) == []
    suggested = []
    for line in lines:
        if line.rstrip().endswith("(suggested)"):
            m = _FLAG_RE.search(line)
            assert m, line
            suggested.append(f"{m.group(1)}:{m.group(2)}")
    assert len(suggested) <= 3
    return suggested


def test_headless_new_make_me_a_website_picks_web_golden_template(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    # A plain website request marks the web-golden row first; nothing is created without an id.
    suggested = _headless_new(tmp_path, monkeypatch, capsys, "make me a website")
    assert suggested[:1] == ["template:web-golden"], suggested
    assert "template:cpp-golden" not in suggested


@pytest.mark.parametrize("prompt", ["discord bot", "something cool"])
def test_headless_new_vague_prompt_hands_off_without_tiebreak_template(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any, prompt: str
) -> None:
    # A vague request suggests nothing (no tie-break template) and creates nothing.
    suggested = _headless_new(tmp_path, monkeypatch, capsys, prompt)
    assert suggested == [], suggested


# (4) component-library requests reach their kit


@pytest.mark.parametrize("prompt", COMPONENT_PROMPTS)
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_component_prompt_prefers_component_library_kit(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "kit", data["preferred"]
    assert data["kits"][0]["kit_id"] == "component-library"


def test_react_component_library_surfaces_kit_but_named_language_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    data = _match(client, "a react component library", None)
    assert all(k["kit_id"] != "component-library" for k in data["kits"])
    assert data["preferred"] == "template"
    assert data["matches"][0]["template_id"] == "ts-node-golden"

    for ui_prompt in UI_NON_PYTHON_COMPONENT_PROMPTS:
        ui_data = _match(client, ui_prompt, _DEFAULT_SYNC_ANSWERS)
        assert ui_data["preferred"] == "none", (ui_prompt, ui_data)
        assert all(k["kit_id"] != "component-library" for k in ui_data["kits"])


# (5) bare 'site' / 'portfolio' / 'blog' and website words in requests for another kind of thing

# prompt -> template id expected when a language was named (None: no template language named)
NOT_WEBSITE_PROMPTS = {
    "blog post summarizer script": None,
    "a cli that checks if a site is up": None,
    "web scraper for a news site": None,
    "stock portfolio tracker": None,
    "a portfolio rebalancing bot": None,
    "camping site booking system in java": None,
    "site visit tracker cli in rust": "rust-golden",
    "portfolio optimizer in python": "python-golden",
    "landing gear simulator": None,
}

# Named languages that have no template: the request must ask, never pick a kit or template.
NAMED_LANGUAGE_WITHOUT_TEMPLATE = {"camping site booking system in java"}

STILL_WEBSITE_PROMPTS = [
    "make me a website",
    "a website for my band",
    "build a landing page",
    "portfolio site",
    "my portfolio",
    "a blog",
    "a blog about cooking",
    "personal site",
    "photography portfolio",
    "company website with a contact form",
    "homepage for my school club",
]


@pytest.mark.parametrize("prompt", sorted(NOT_WEBSITE_PROMPTS))
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_website_word_in_other_kind_of_request_does_not_pick_web_app_kit(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert not any(
        "website" in " ".join(k["reasons"]) for k in data["kits"]
    ), data["kits"]
    assert data["preferred"] != "kit", (data["preferred"], data["kits"][:1])
    expected = NOT_WEBSITE_PROMPTS[prompt]
    if expected is not None:
        assert data["preferred"] == "template"
        assert data["matches"][0]["template_id"] == expected
    elif prompt in NAMED_LANGUAGE_WITHOUT_TEMPLATE:
        assert data["preferred"] == "none", data["preferred"]
        assert data["matches"] == []
        assert data["closest"] == []
    # Routing is the same as with the website word replaced by a neutral word.
    neutral = re.sub(r"\b(?:site|portfolio|blog)\b", "host", prompt)
    same = _match(client, neutral, answers)
    assert (data["preferred"], _first_ids(data)) == (same["preferred"], _first_ids(same))


def _first_ids(data: Dict[str, Any]) -> tuple:
    return (
        data["matches"][0]["template_id"] if data["matches"] else None,
        data["closest"][0]["template_id"] if data["closest"] else None,
        data["kits"][0]["kit_id"] if data["preferred"] == "kit" else None,
    )


@pytest.mark.parametrize("prompt", sorted(NOT_WEBSITE_PROMPTS))
def test_website_word_in_other_kind_of_request_is_not_a_family_hit(prompt: str) -> None:
    km = match_kits(_KITS, prompt, parse_deterministic(prompt).answers)
    assert not any(m.family_hit and m.kit.id == "web-app" for m in km)


@pytest.mark.parametrize("prompt", STILL_WEBSITE_PROMPTS)
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_real_website_request_still_prefers_web_golden_template(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    # Changed when web-golden was added (was: the web-app kit); see section (2).
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "template", data["preferred"]
    assert data["matches"][0]["template_id"] == "web-golden"


@pytest.mark.parametrize(
    "prompt", ["booking system in java", "a kotlin app", "php blog engine", "a ruby gem", "swift ios thing"]
)
def test_language_without_template_counts_as_named(prompt: str) -> None:
    parsed = parse_deterministic(prompt)
    assert parsed.explicit_code
    assert parsed.answers["languages"] == ["other"]


@pytest.mark.parametrize("prompt", ["a java cli", "a java api", "a java website", "a kotlin app"])
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_named_language_without_template_asks(monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "none", data["preferred"]
    assert data["matches"] == []
    assert data["closest"] == []


# (6) vague prompts with desktop defaults ask; Godot games reach godot-game; ties ask


@pytest.mark.parametrize("prompt", ["discord bot", "something cool", "mystery project"])
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_vague_prompt_asks_with_or_without_desktop_defaults(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "none", (prompt, shape, data["preferred"])
    assert data["matches"] == []
    assert data["closest"] == []


@pytest.mark.parametrize(
    "prompt",
    [
        "godot platformer",
        "2d rpg in godot",
        "gdscript tower defense",
        "make me a breakout clone with gdscript",
    ],
)
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_godot_game_prompts_reach_godot_game_kit_and_never_cpp_golden(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "kit", data
    assert data["kits"][0]["kit_id"] == "godot-game"
    assert data["matches"] == []
    assert data["closest"] == []

    unavail_client = _build_client(
        monkeypatch,
        FakeKitBridge(status="unavailable", notice="componentize CLI is unavailable."),
    )
    unavail_data = _match(unavail_client, prompt, answers)
    assert unavail_data["preferred"] == "none"
    assert unavail_data["matches"] == []
    assert unavail_data["closest"] == []


@pytest.mark.parametrize(
    "prompt,expected_kit",
    [
        ("I want a web app where people can sign up", "web-app"),
        ("online store", "web-app"),
        ("dashboard for my data", "web-app"),
        ("folder of reusable python components", "component-library"),
        ("reusable python components with componentize specs", "component-library"),
        ("python component collection with thin runners", "component-library"),
    ],
)
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_expanded_beginner_website_and_component_prompts_reach_kit(
    monkeypatch: pytest.MonkeyPatch, prompt: str, expected_kit: str, shape: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "kit", (prompt, shape, data)
    assert data["kits"][0]["kit_id"] == expected_kit


# Moved from the kit list above when web-golden was added: these name a page, not an app.
@pytest.mark.parametrize("prompt", ["build a landing page for my band", "simple page with a contact form"])
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_expanded_beginner_page_prompts_reach_web_golden(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    client = _build_client(monkeypatch, FakeKitBridge())
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "template", (prompt, shape, data)
    assert data["matches"][0]["template_id"] == "web-golden"


def test_ties_between_distinct_kits_or_kit_and_template_ask() -> None:
    templates = load_templates()
    web_kit = next(k for k in _KITS if k.id == "web-app")
    comp_kit = next(k for k in _KITS if k.id == "component-library")

    # Two distinct-domain kits tied on score, family_hit, and id_part_hits -> ask ('none')
    km_a = KitMatch(kit=comp_kit, score=9, reasons=["you asked for a ui kit"], tag_hits=1, family_hit=True, id_part_hits=0)
    km_b = KitMatch(kit=web_kit, score=9, reasons=["you asked for a website"], tag_hits=1, family_hit=True, id_part_hits=0)
    assert choose_catalog_entry([], [km_a, km_b], {"building": "other"}) == ("none", None)

    # Kit and template tied at >= STRONG_KIT_SCORE without decisive 2-tag/family signal -> ask ('none')
    tmpl_match = Match(template=templates[0], score=6, reasons=["layout: mono"], needs=[])
    tied_kit = KitMatch(kit=web_kit, score=6, reasons=["matches id part 'web'"], tag_hits=1, family_hit=False, id_part_hits=1)
    assert choose_catalog_entry([tmpl_match], [tied_kit], {"building": "app"}, explicit_code=False) == ("none", None)


@pytest.mark.parametrize("prompt", ["make me a web app", "a web app", "browser app"])
@pytest.mark.parametrize("shape", ["desktop-defaults", "no-answers"])
def test_web_app_without_kits_asks_and_never_falls_to_ts_node(
    monkeypatch: pytest.MonkeyPatch, prompt: str, shape: str
) -> None:
    """A web app with no language named used to fall through to ts-node-golden without kits."""
    client = _build_client(
        monkeypatch, FakeKitBridge(status="unavailable", notice="componentize CLI is unavailable.")
    )
    answers = _DEFAULT_SYNC_ANSWERS if shape == "desktop-defaults" else None
    data = _match(client, prompt, answers)
    assert data["preferred"] == "none", data
    assert data["matches"] == []
    assert all(c["template_id"] != "ts-node-golden" for c in data["closest"])


def test_questionnaire_answers_alone_never_offer_the_website_template() -> None:
    from hermes_plugins.defuzz.matcher import best_matches

    answers = {"building": "app", "layout": "mono", "languages": ["typescript"]}
    assert "web-golden" not in [m.template.id for m in best_matches(load_templates(), answers)]
    with_prompt = best_matches(load_templates(), answers, prompt="a typescript website", explicit_code=True)
    assert with_prompt[0].template.id == "web-golden"
