"""picker_text.json: the words of the project pick-list (plain JSON checks only)."""
import json
import re
import unicodedata

import pytest
import yaml

from .conftest import REPO_ROOT

PICKER = REPO_ROOT / "picker_text.json"
KIT_LIST = REPO_ROOT / "tests" / "fixtures" / "kit_contract" / "list.json"
GROUP_IDS = ["code", "workspace"]
ENTRY_KEYS = {"title", "line", "group", "order"}
BANNED = ("golden", "layered", "scaffold", "monorepo", "workspace template")
TITLE_MAX = 40
LINE_MAX = 100


@pytest.fixture(scope="module")
def picker():
    return json.loads(PICKER.read_text(encoding="utf-8"))


def _template_ids():
    ids = set()
    for manifest in sorted((REPO_ROOT / "templates").glob("*/template.yaml")):
        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        assert data["id"] == manifest.parent.name
        ids.add(data["id"])
    return ids


def _kit_ids():
    return {kit["id"] for kit in json.loads(KIT_LIST.read_text(encoding="utf-8"))["kits"]}


def _texts(picker):
    for group in picker["groups"]:
        yield f"group {group['id']} title", group["title"]
    for key, entry in picker["entries"].items():
        yield f"{key} title", entry["title"]
        yield f"{key} line", entry["line"]


def test_top_level_schema(picker):
    assert set(picker) == {"groups", "entries"}
    assert isinstance(picker["groups"], list)
    assert [group["id"] for group in picker["groups"]] == GROUP_IDS
    for group in picker["groups"]:
        assert set(group) == {"id", "title"}
        assert isinstance(group["title"], str) and group["title"].strip()
    assert isinstance(picker["entries"], dict) and picker["entries"]


def test_entry_schema(picker):
    for key, entry in picker["entries"].items():
        assert re.fullmatch(r"(template|kit):[a-z0-9][a-z0-9-]*", key), key
        assert set(entry) == ENTRY_KEYS, key
        assert isinstance(entry["title"], str) and entry["title"].strip(), key
        assert isinstance(entry["line"], str) and entry["line"].strip(), key
        assert entry["title"] == entry["title"].strip(), key
        assert entry["line"] == entry["line"].strip(), key
        assert entry["group"] in GROUP_IDS, key
        assert isinstance(entry["order"], int) and not isinstance(entry["order"], bool), key
        assert entry["order"] > 0, key


def test_templates_are_code_and_kits_are_workspaces(picker):
    for key, entry in picker["entries"].items():
        expected = "code" if key.startswith("template:") else "workspace"
        assert entry["group"] == expected, key


def test_every_template_and_kit_has_exactly_one_entry(picker):
    expected = ({f"template:{tid}" for tid in _template_ids()}
                | {f"kit:{kid}" for kid in _kit_ids()})
    assert len(_template_ids()) == 7
    assert len(_kit_ids()) == 14
    keys = set(picker["entries"])
    assert sorted(expected - keys) == [], "ids without picker text"
    assert sorted(keys - expected) == [], "picker text for ids that do not exist"


def test_length_limits(picker):
    for key, entry in picker["entries"].items():
        assert len(entry["title"]) <= TITLE_MAX, (key, len(entry["title"]))
        assert len(entry["line"]) <= LINE_MAX, (key, len(entry["line"]))


def test_titles_are_unique(picker):
    titles = [entry["title"].casefold() for entry in picker["entries"].values()]
    assert len(titles) == len(set(titles))


def test_group_order_pairs_are_unique(picker):
    pairs = [(entry["group"], entry["order"]) for entry in picker["entries"].values()]
    assert len(pairs) == len(set(pairs))


def test_website_comes_first_among_code(picker):
    code = sorted((entry["order"], key) for key, entry in picker["entries"].items()
                  if entry["group"] == "code")
    assert code[0][1] == "template:web-golden"


CREATIVE_KITS = ["kit:image-set", "kit:video-production", "kit:video-channel",
                 "kit:music-production", "kit:comic-storyboard", "kit:studio-3d",
                 "kit:game-assets", "kit:godot-game", "kit:lora-training"]


def test_creative_kits_come_first_among_workspaces(picker):
    entries = picker["entries"]
    workspace = sorted((entry["order"], key) for key, entry in entries.items()
                       if entry["group"] == "workspace")
    assert workspace[0][1] == "kit:image-set"
    others = [key for _, key in workspace if key not in CREATIVE_KITS]
    assert others
    assert max(entries[k]["order"] for k in CREATIVE_KITS) < min(
        entries[k]["order"] for k in others)


def test_no_control_characters(picker):
    for where, text in _texts(picker):
        bad = [char for char in text if unicodedata.category(char).startswith("C")]
        assert not bad, (where, bad)


def test_no_banned_words(picker):
    for where, text in _texts(picker):
        lowered = text.casefold()
        for word in BANNED:
            assert word not in lowered, (where, word)


@pytest.mark.parametrize("left, right", [
    ("template:web-golden", "kit:web-app"),
    ("kit:game-assets", "kit:studio-3d"),
    ("kit:image-set", "kit:lora-training"),
    ("kit:component-library", "template:python-golden"),
])
def test_confusable_pairs_each_name_the_difference(picker, left, right):
    entries = picker["entries"]
    for key in (left, right):
        line = entries[key]["line"].casefold()
        assert re.search(r"\bnot\b|\bpick\b|\bfor\b", line), key
    assert entries[left]["line"] != entries[right]["line"]
