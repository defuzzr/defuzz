"""Linear-time suggestion matching in matcher.py, pinned against the base module.

The matcher only builds SUGGESTIONS for the project pick-list, so it must be cheap and
must never hang. Before this change several helpers rescanned the prompt once per regex
match: ``build_target_end`` re-tokenised the whole prefix for every subject word ("kit of
kit of ..."), ``mask_website_subject`` tested every character against every kept stack
span, and the website pass of ``kit_families_in`` / ``family_request`` re-ran whole-prompt
regex searches and prefix/suffix tokenisation for every candidate match ("site site ...",
"page page ..."). ``match_kits`` scored every prompt token against every kit, and
``choose_catalog_entry`` rebuilt the family template's vocabulary once per strong kit.

The answers must not change. Proof, two ways:

* ``test_differential_against_base_module`` compares every public answer on the routing
  sentences plus ``SYNTHETIC_PROMPTS`` generated prompts, with the real templates and kit
  fixture, against digests recorded once from the base module in
  ``tests/fixtures/linear_baseline/matcher.json`` (``scripts/gen_history_baseline.py``).
* ``test_recorded_answers_match_fixture`` compares the same answers, for the
  self-contained synthetic inputs, against digests recorded once from the base module
  in ``tests/fixtures/matcher_linear_expected.json``.

Neither needs repository history.

Hostile timing runs in a subprocess with a hard timeout so a regression fails instead of
hanging the suite; limits are generous because the test machine is often loaded.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import textwrap
import zlib
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import pytest

from tests.conftest import REPO_ROOT, load_submodule

matcher = load_submodule("matcher")
templates_mod = load_submodule("templates")

DIFF_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "linear_baseline" / "matcher.json"
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "matcher_linear_expected.json"
SEED = 20261111
SYNTHETIC_PROMPTS = 3200
SYNTHETIC_KIT_TEXTS = 3200
HARD_TIMEOUT_S = 60
BUDGET_S = 2.0
SCALE_RATIO_LIMIT = 24.0  # 8x more input: linear ~8x, quadratic ~64x

# --- deterministic inputs (shared with scripts/gen_matcher_linear_fixture.py) ---------

_OPENERS = (
    "", "", "", "build ", "make ", "create ", "i want to make ", "i need ", "can you build me ",
    "hey, could you please help me set up ", "i'm looking for ", "looking to build ", "start ",
    "please scaffold ", "spin up ", "put together ", "i'd like ",
)
_DETERMINERS = ("a", "an", "the", "my", "our", "your", "new", "some", "this", "that")
_SUBJECT = ("for", "about", "of", "where", "that", "which", "who", "to", "with")
_CONTAINERS = ("set", "folder", "collection", "library", "pack", "kit", "catalog", "repo",
               "studio", "toolbox", "suite", "bundle", "series", "list", "pair", "bunch")
_STACK = ("react", "python", "rust", "typescript", "go", "node.js", "c++", "c#", "godot", "vue.js",
          "next.js", "django", "flask", "unity", "unreal engine", "java", "php", "zig", "js")
_STACK_INTROS = ("in", "using", "with", "written in", "built with", "made in", "powered by")
_KIT_WORDS = (
    "video", "film", "storyboard", "image", "images", "art", "illustration", "assets", "3d",
    "blender", "houdini", "unreal", "ue5", "game", "games", "godot", "gdscript", "comic", "manga",
    "panels", "music", "song", "album", "mixing", "podcast", "youtube", "shorts", "vlog",
    "research", "paper", "thesis", "essay", "lora", "training", "dataset", "homelab", "servers",
    "client", "freelance", "invoice", "render", "queue", "notebook", "gpu", "python", "modules",
    "components", "component", "reuse", "reusable", "shared", "toolbox", "helpers", "snippets",
    "frontend", "website", "figma", "tokens", "css", "handoff", "ui", "studio", "lfs", "ai",
    "footage", "production", "generative", "comfyui", "diffusion", "stills", "upscale",
)
_FILLER = (
    "coffee", "shop", "dog", "grooming", "business", "band", "school", "travel", "food", "photo",
    "wedding", "recipes", "rent", "roommates", "news", "prices", "weather", "space", "invaders",
    "platformer", "2d", "puzzle", "tiny", "quick", "simple", "small", "little", "personal",
    "company", "static", "docs", "marketing", "resume", "people", "can", "sign", "post", "posts",
    "entry", "feed", "rss", "comments", "engine", "where", "and", "or", "plus", "is", "it",
    "x", "go", "me", "us", "at", "on", "in", "by", "code", "design", "web", "page", "pages",
)


def _table_words() -> List[str]:
    m = matcher
    words: List[str] = []
    words += [phrase for phrase, _tag in m.KIT_FAMILY_SYNONYMS]
    for table in (m.NON_WEB_PLATFORM_WORDS, m.NOT_A_WEBSITE_WORDS, m.NOT_A_WEBPAGE_WORDS,
                  m.NOT_A_COMPONENT_LIBRARY_WORDS, m.UI_COMPONENT_WORDS, m.NOT_A_GODOT_GAME_WORDS,
                  m.SITE_STACK_WORDS):
        words += list(table)
    for table in (m._BLOG_NON_SITE_AFTER, m._BARE_WEBSITE_BEFORE, m._BARE_WEBSITE_AFTER,
                  m._BARE_PAGE_BEFORE, m._BARE_PAGE_AFTER, m._PYTHON_CODE_PIECE_WORDS,
                  m._COMPONENT_QUALIFIER_WORDS, m._PYTHON_REUSE_QUALIFIER_WORDS, m._KIT_STOPWORDS):
        words += sorted(table)
    return words


_SEPARATORS = (" ", " ", " ", " ", "  ", "-", "'", ", ", ". ", "\n", " - ", "\u2014", "\t", "\u00a0",
               "; ", "! ", "? ", " (", ") ", ": ", "/", "--", "\u3000", "_")
_ODD = ("\u0130", "\u03a3", "\u00e9", "\u212a", "\u017f", "caf\u00e9", "na\u00efve", "\u0130stanbul")


def _piece(rng: random.Random, words: Sequence[str]) -> str:
    r = rng.random()
    if r < 0.30:
        w = rng.choice(words)
    elif r < 0.45:
        w = rng.choice(_KIT_WORDS)
    elif r < 0.58:
        w = rng.choice(_FILLER)
    elif r < 0.64:
        w = rng.choice(_DETERMINERS)
    elif r < 0.72:
        w = rng.choice(_SUBJECT)
    elif r < 0.77:
        w = rng.choice(_CONTAINERS) + " of"
    elif r < 0.84:
        w = rng.choice(_STACK_INTROS) + " " + rng.choice(_STACK)
    elif r < 0.87:
        w = "design to " + rng.choice(("code", "  code", "Code", "codex", "x"))
    elif r < 0.90:
        w = rng.choice(_ODD)
    else:
        w = rng.choice(words) + rng.choice(("s", "es", "ies", "'s", "-y", ""))
    if rng.random() < 0.12:
        w = w.upper() if rng.random() < 0.5 else w.title()
    return w


def synthetic_prompts(count: int = SYNTHETIC_PROMPTS, seed: int = SEED) -> List[str]:
    """Deterministic prompts that exercise every branch the linear rewrite touches."""
    rng = random.Random(seed)
    words = _table_words()
    out: List[str] = []
    for i in range(count):
        if i % 200 == 199:
            target = rng.randint(600, 2048)  # some long prompts up to the parser cap
        else:
            target = rng.randint(1, 160)
        parts = [rng.choice(_OPENERS)]
        size = len(parts[0])
        while size < target:
            p = _piece(rng, words)
            sep = rng.choice(_SEPARATORS) if rng.random() < 0.35 else " "
            parts.append(p + sep)
            size += len(p) + len(sep)
        text = "".join(parts)
        if rng.random() < 0.2:
            text = text.rstrip()
        if rng.random() < 0.05:
            text = "  " + text
        out.append(text[: max(target, 1)] if i % 200 == 199 else text)
    out[0] = ""
    out[1] = "   "
    return out


_CUES = ("not", "not for", "not a", "not an", "not only", "not  only", "no", "no-code", "never",
         "rather than", "rather  than", "instead of", "unlike", "excluding", "except", "without",
         "nothing", "notably", "Not", "NO", "nor", "or", "and")
_KIT_PUNCT = (";", ",", "(", ")", ".", "!", "?", "\n", "\u2014", "\u2013", " - ", ":", "-", "  ",
              " ", " ", " ", "\t")


def synthetic_kit_texts(count: int = SYNTHETIC_KIT_TEXTS, seed: int = SEED + 1) -> List[str]:
    rng = random.Random(seed)
    out: List[str] = []
    for i in range(count):
        n = rng.randint(0, 30) if i % 100 else rng.randint(200, 600)
        parts: List[str] = []
        for _ in range(n):
            r = rng.random()
            if r < 0.25:
                parts.append(rng.choice(_CUES))
            elif r < 0.55:
                parts.append(rng.choice(_KIT_PUNCT))
            else:
                parts.append(rng.choice(_KIT_WORDS + _FILLER))
            parts.append(rng.choice((" ", " ", "", "  ")))
        out.append("".join(parts))
    return out


_KIT_TABLE = (
    ("web-app", "Web app", ("frontend", "website", "figma", "tokens", "css", "handoff", "ui")),
    ("component-library", "Component library", ("python", "code", "modules", "components", "reuse",
                                                "componentize")),
    ("godot-game", "Godot game", ("godot", "game", "gdscript", "scenes", "shaders", "indie", "games")),
    ("game-assets", "Game assets", ("game", "unreal", "ue5", "blender", "houdini", "assets", "lfs")),
    ("studio-3d", "3D studio", ("3d", "studio", "dcc", "blender", "houdini", "unreal", "godot", "web",
                                "assets", "lfs")),
    ("video-production", "Video production", ("video", "ai", "storyboard", "footage", "production",
                                              "generative", "lfs")),
    ("video-channel", "Video channel", ("video", "channel", "youtube", "shorts", "editing", "vlog")),
    ("image-set", "Image set", ("image", "images", "stills", "comfyui", "diffusion", "generative")),
    ("comic-storyboard", "Comic / storyboard", ("comic", "storyboard", "manga", "panels",
                                                "illustration", "comics", "storyboards")),
    ("music-production", "Music production", ("music", "production", "audio", "song", "album",
                                              "mixing")),
    ("research-writing", "Research writing", ("research", "writing", "paper", "thesis", "essay")),
    ("lora-training", "LoRA training", ("lora", "training", "dataset", "captions", "checkpoint")),
    ("homelab", "Homelab", ("homelab", "infra", "servers", "network", "lab")),
    ("client-job", "Client job", ("client", "job", "freelance", "invoice", "contract")),
)


def synthetic_kits(seed: int = SEED + 2) -> List[Dict[str, Any]]:
    """Kit dicts in the componentize ``kit list --json`` shape, built at run time."""
    rng = random.Random(seed)
    texts = synthetic_kit_texts(60, seed + 1)
    kits: List[Dict[str, Any]] = []
    for i, (kit_id, name, tags) in enumerate(_KIT_TABLE):
        summary = f"{name} workspace for {' '.join(tags[:3])}, " + texts[i]
        kits.append({"id": kit_id, "name": name, "summary": summary, "tags": list(tags), "version": 1})
    for i in range(25):
        words = [rng.choice(_KIT_WORDS + _FILLER) for _ in range(rng.randint(1, 3))]
        tags = [rng.choice(_KIT_WORDS) for _ in range(rng.randint(0, 9))]
        if rng.random() < 0.3:
            tags.append(rng.choice(sorted(matcher.FAMILY_TAGS)))
        kits.append({
            "id": "-".join(words) + f"-{i}", "name": " ".join(rng.choice(_KIT_WORDS) for _ in range(2)),
            "summary": texts[15 + i], "tags": tags or ["misc"], "version": 1,
        })
    kits.append({"id": "", "name": "bad", "summary": "", "tags": [], "version": 1})  # dropped
    kits.append({"id": "bad-tags", "name": "Bad", "summary": "", "tags": [""], "version": 1})
    return kits


def synthetic_templates() -> List[Any]:
    def spec(tid: str, kind: str, layout: str, langs: Tuple[str, ...], engine: Optional[str],
             tags: Tuple[str, ...], summary: str) -> Any:
        return templates_mod.TemplateSpec(
            id=tid, name=tid.replace("-", " ").title(), summary=summary, kind=kind, layout=layout,
            languages=langs, engine=engine, tags=tags, needs=langs, placeholder="tmpl_prefix",
            substitute_in=("**/*",), repos=(templates_mod.RepoSpec(name="tmpl_prefix", check=None),),
            root=Path("stub"),
        )

    return [
        spec("python-golden", "service", "mono", ("python",), None,
             ("python", "uv", "workspace", "fastapi", "service"), "Python service workspace"),
        spec("rust-golden", "app", "mono", ("rust",), None, ("rust", "workspace", "cli"),
             "Rust app workspace"),
        spec("rust-game", "game", "poly", ("rust",), "bevy", ("rust", "bevy", "game"),
             "Rust game with bevy"),
        spec("ts-node-golden", "service", "mono", ("typescript",), None,
             ("typescript", "node", "hono", "service"), "TypeScript service"),
        spec("web-golden", "app", "mono", ("typescript",), None,
             ("website", "static", "frontend", "vite", "typescript", "react"),
             "Static website with pages, docs and a portfolio"),
        spec("cpp-golden", "tool", "mono", ("cpp",), None, ("cpp", "cmake", "cli"), "C++ tool"),
    ]


_BUILDINGS = (None, None, "web", "app", "game", "studio", "video", "images", "assets", "tool",
              "library", "service", "other", "components")
_LANGS = ("python", "rust", "typescript", "gdscript", "other", "go", "cpp")


def synthetic_answers(rng: random.Random) -> Tuple[Dict[str, Any], bool, Optional[str]]:
    answers: Dict[str, Any] = {}
    building = rng.choice(_BUILDINGS)
    if building is not None:
        answers["building"] = building
    if rng.random() < 0.6:
        answers["languages"] = rng.sample(_LANGS, rng.randint(0, 2))
    if rng.random() < 0.4:
        answers["layout"] = rng.choice(("mono", "poly", "single"))
    if rng.random() < 0.2:
        answers["engine"] = rng.choice(("none", "bevy", "godot", "unreal"))
    if rng.random() < 0.1:
        answers["framework"] = rng.choice(("none", "react", "pygame"))
    explicit_building = rng.choice((None, None, "tool", "library", "service", "web", "game"))
    return answers, rng.random() < 0.4, explicit_building


def synthetic_cases() -> Iterator[Tuple[str, Dict[str, Any], bool, Optional[str]]]:
    rng = random.Random(SEED + 3)
    for prompt in synthetic_prompts():
        answers, explicit_code, explicit_building = synthetic_answers(rng)
        yield prompt, answers, explicit_code, explicit_building


def _kit_row(k: Any) -> List[Any]:
    return [k.kit.id, k.score, list(k.reasons), k.tag_hits, k.family_hit, k.id_part_hits, k.disqualified]


def _choice_id(chosen: Any) -> Optional[str]:
    if chosen is None:
        return None
    if hasattr(chosen, "kit"):
        return "kit:" + chosen.kit.id
    return "template:" + chosen.template.id


def snapshot(m: Any, prompt: str, answers: Dict[str, Any], explicit_code: bool,
             explicit_building: Optional[str], kits: Sequence[Any], templates: Sequence[Any]) -> Dict[str, Any]:
    """Every public answer the matcher gives for one prompt, as plain JSON data."""
    out: Dict[str, Any] = {}
    out["bte"] = m.build_target_end(prompt)
    out["mask"] = m.mask_website_subject(prompt)
    out["fam"] = m.kit_families_in(prompt)
    out["fam_b"] = m.kit_families_in(prompt, _explicit_building=explicit_building)
    req = m.family_request(prompt)
    out["req"] = None if req is None else [req.family, req.kind, sorted(req.stacks)]
    out["tok"] = m._tokenize_prompt(prompt)
    tms = m.best_matches(templates, answers, prompt=prompt, explicit_code=explicit_code)
    out["tm"] = [[t.template.id, t.score, list(t.reasons), list(t.needs), t.family] for t in tms]
    kms = m.match_kits(kits, prompt, answers)
    out["km"] = [_kit_row(k) for k in kms]
    kms_low = m.match_kits(kits, prompt, None, min_score=1)
    out["km1"] = [_kit_row(k) for k in kms_low]
    for flag in (False, True):
        kind, chosen = m.choose_catalog_entry(tms, kms, answers, explicit_code=flag)
        out[f"choice{int(flag)}"] = [kind, _choice_id(chosen)]
    kind, chosen = m.choose_catalog_entry(tms, kms_low, answers, explicit_code=explicit_code)
    out["choice_low"] = [kind, _choice_id(chosen)]
    return out


def digest(data: Any) -> int:
    return zlib.crc32(json.dumps(data, sort_keys=True, ensure_ascii=True).encode("ascii"))


def kit_reply(rng: random.Random, kits: Sequence[Dict[str, Any]]) -> Any:
    shape = rng.random()
    if shape < 0.1:
        return rng.choice((None, [], "x", {"status": "error"}, {"status": "missing", "notice": "  gone "},
                           {"status": "ok"}, {"status": "ok", "data": []}, {"status": "ok", "data": {"kits": None}}))
    picked = [dict(k) for k in rng.sample(list(kits), rng.randint(0, len(kits)))]
    if rng.random() < 0.3 and picked:
        picked[0]["version"] = True
    return {"status": "ok", "data": {"kits": picked}}


def parse_row(m: Any, reply: Any) -> Any:
    infos, notice, status = m.parse_kit_list(reply)
    return [[i.id, i.name, i.summary, list(i.tags), i.version] for i in infos], notice, status


def recorded_answers(m: Any) -> Dict[str, Any]:
    """Digests of every answer ``m`` gives on the self-contained synthetic inputs."""
    kits = synthetic_kits()
    templates = synthetic_templates()
    prompts = [digest(snapshot(m, p, a, e, b, kits, templates)) for p, a, e, b in synthetic_cases()]
    texts = [digest(m.positive_kit_text(t)) for t in synthetic_kit_texts()]
    rng = random.Random(SEED + 4)
    replies = [digest(parse_row(m, kit_reply(rng, kits))) for _ in range(200)]
    return {"prompts": prompts, "kit_texts": texts, "kit_lists": replies}


# --- differential inputs (real templates, real kit fixture) -----------------------------


def _routing_sentences() -> List[str]:
    from tests.routing_corpus import iter_cases

    out = [sentence for sentence, _cat, _id, _group in iter_cases()]
    fixtures = Path(__file__).resolve().parent / "fixtures"

    def walk(node: Any) -> Iterator[str]:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "prompt" and isinstance(value, str):
                    yield value
                else:
                    yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                if isinstance(value, str):
                    yield value
                else:
                    yield from walk(value)

    for name in ("routing_holdout.json", "routing_error_classes.json"):
        data = json.loads((fixtures / name).read_text(encoding="utf-8"))
        out.extend(walk({k: v for k, v in data.items() if k not in {"schema", "description"}}))
    return out


def differential_answers(m: Any) -> Dict[str, Any]:
    """Digests of every answer ``m`` gives on the differential inputs."""
    from tests.fake_kit_bridge import load_list_fixture

    pp = load_submodule("prompt_parse")
    real_kits = load_list_fixture()["kits"]
    kits = real_kits + synthetic_kits()
    real_templates = templates_mod.load_templates()
    fake_templates = synthetic_templates()
    sentences = _routing_sentences()
    prompts = sentences + synthetic_prompts()
    rng = random.Random(SEED + 5)
    answers_out: List[int] = []
    for index, prompt in enumerate(prompts):
        try:
            parsed = pp.parse_deterministic(prompt)
            answers, explicit_code = dict(parsed.answers), bool(parsed.explicit_code)
        except ValueError:
            answers, explicit_code = {}, False
        explicit_building = rng.choice((None, "tool", "library", "service", "web"))
        templates = real_templates if index % 2 == 0 else fake_templates
        answers_out.append(digest(snapshot(m, prompt, answers, explicit_code, explicit_building, kits, templates)))
    texts = [digest(m.positive_kit_text(text)) for text in synthetic_kit_texts()]
    replies = [digest(parse_row(m, kit_reply(rng, kits))) for _ in range(300)]
    return {"inputs_crc": digest(prompts), "sentences": len(sentences), "prompts": answers_out,
            "kit_texts": texts, "kit_lists": replies}


def record_base_outputs(base_mod: Any, base_file: Any) -> Dict[str, Any]:
    """Run the base module on this file's inputs (scripts/gen_history_baseline.py only)."""
    return differential_answers(base_mod)


def test_differential_against_base_module() -> None:
    """Real templates, real kit fixture and parsed answers: every answer equals the base."""
    expected = json.loads(DIFF_FIXTURE.read_text(encoding="utf-8"))
    actual = differential_answers(matcher)
    assert actual["sentences"] > 500
    assert actual["inputs_crc"] == expected["inputs_crc"], "inputs changed; re-record the fixture"
    assert len(actual["prompts"]) >= 3000
    for key in ("prompts", "kit_texts", "kit_lists"):
        assert len(actual[key]) == len(expected[key]), key
        diffs = [i for i, (x, y) in enumerate(zip(actual[key], expected[key])) if x != y]
        assert not diffs, f"{key}: {len(diffs)} answers differ from the base, first indexes {diffs[:10]}"


def test_recorded_answers_match_fixture() -> None:
    """Self-contained inputs against digests recorded from the base module (no git needed)."""
    expected = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert expected["seed"] == SEED
    assert len(expected["prompts"]) >= 3000
    actual = recorded_answers(matcher)
    for key in ("prompts", "kit_texts", "kit_lists"):
        diffs = [i for i, (a, b) in enumerate(zip(actual[key], expected[key])) if a != b]
        assert len(actual[key]) == len(expected[key]), key
        assert not diffs, f"{key}: {len(diffs)} answers differ, first indexes {diffs[:10]}"


def test_lowercase_assumptions_hold() -> None:
    """The linear scans rely on these facts about str.lower() and regex classes."""
    import re

    word = re.compile(r"\w")
    space = re.compile(r"\s")
    token_char = re.compile(r"[a-z0-9'-]")
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        c = chr(cp)
        # A non-word character never lowercases into a word-token character, so a
        # prefix cut at a regex word boundary never splits a lowercased word.
        if not word.match(c) and c not in "'-":
            assert not token_char.search(c.lower()), hex(cp)
        # Regex whitespace is exactly str.isspace() (positive_kit_text uses both).
        assert bool(space.match(c)) == c.isspace(), hex(cp)


# --- hard bounds ------------------------------------------------------------------------


def _kit(kit_id: str, tags: Sequence[str], summary: str = "", name: str = "Kit") -> Any:
    return matcher.KitInfo(id=kit_id, name=name, summary=summary, tags=tuple(tags), version=1)


def test_bounds_are_documented_constants() -> None:
    pp = load_submodule("prompt_parse")
    assert matcher.MAX_MATCH_PROMPT_CHARS >= 4 * pp.MAX_PROMPT_CHARS
    assert matcher.MAX_KITS_SCORED >= 10_000
    assert matcher.MAX_KIT_SUMMARY_CHARS >= 1024
    assert matcher.MAX_KIT_NAME_CHARS >= 128
    doc = matcher.__doc__ or ""
    for name in ("MAX_MATCH_PROMPT_CHARS", "MAX_KITS_SCORED", "MAX_KIT_SUMMARY_CHARS", "MAX_KIT_NAME_CHARS"):
        assert name in doc


def test_prompt_beyond_bound_is_ignored() -> None:
    limit = matcher.MAX_MATCH_PROMPT_CHARS
    head = ("make a storyboard video " * (limit // 24 + 1))[:limit]
    long_prompt = head + " website figma react godot comic " * 50
    kits = [_kit("video-production", ("video", "storyboard")), _kit("web-app", ("website", "figma")),
            _kit("comic-storyboard", ("comic", "storyboard"))]
    assert matcher.kit_families_in(long_prompt) == matcher.kit_families_in(head)
    assert matcher.family_request(long_prompt) == matcher.family_request(head)
    assert [_kit_row(k) for k in matcher.match_kits(kits, long_prompt)] == [
        _kit_row(k) for k in matcher.match_kits(kits, head)
    ]
    tmpls = synthetic_templates()
    ans = {"languages": ["typescript"]}
    assert [m.template.id for m in matcher.best_matches(tmpls, ans, prompt=long_prompt)] == [
        m.template.id for m in matcher.best_matches(tmpls, ans, prompt=head)
    ]
    assert "website" not in matcher.kit_families_in(head)


def test_kits_beyond_bound_are_not_scored() -> None:
    limit = matcher.MAX_KITS_SCORED
    filler = [_kit(f"filler-{i}", ("misc",)) for i in range(limit - 1)]
    last_in = _kit("storyboard-in", ("storyboard", "video"))
    first_out = _kit("storyboard-out", ("storyboard", "video"))
    ranked = matcher.match_kits(filler + [last_in, first_out], "a storyboard video")
    assert [k.kit.id for k in ranked] == ["storyboard-in"]


def test_kit_text_beyond_bound_is_ignored() -> None:
    pad = "x " * matcher.MAX_KIT_SUMMARY_CHARS
    inside = _kit("alpha-kit", ("misc",), summary="storyboard footage " + pad)
    outside = _kit("beta-kit", ("misc",), summary=pad + " storyboard footage")
    ranked = matcher.match_kits([inside, outside], "alpha beta storyboard footage", min_score=1)
    by_id = {k.kit.id: k for k in ranked}
    assert "matches summary word 'storyboard'" in by_id["alpha-kit"].reasons
    assert "matches summary word 'storyboard'" not in by_id["beta-kit"].reasons
    long_name = _kit("gamma-kit", ("misc",), name="Kit " + "y " * matcher.MAX_KIT_NAME_CHARS + "storyboard")
    (only,) = matcher.match_kits([long_name], "gamma storyboard", min_score=1)
    assert "matches name word 'storyboard'" not in only.reasons


@pytest.mark.parametrize(
    "prompt",
    ["", "   ", None, 42, "\x00" * 10, "site " * 3000, "\u0130" * 5000, ("page-" * 4000) + "page"],
)
def test_hostile_inputs_never_raise(prompt: Any) -> None:
    kits: List[Any] = [_kit("web-app", ("website",)), {"id": 3}, None, "kit", _kit("a", ())]
    matcher.match_kits(kits, prompt, {"building": "video"})
    if isinstance(prompt, str):
        matcher.kit_families_in(prompt)
        matcher.family_request(prompt)
        matcher.best_matches(synthetic_templates(), {"languages": ["typescript"]}, prompt=prompt)
        matcher.build_target_end(prompt)
        matcher.mask_website_subject(prompt)
        matcher.positive_kit_text(prompt)


# --- hostile timing (subprocess, hard timeout) -----------------------------------------

_CHILD = textwrap.dedent(
    """
    import json
    import sys
    import time

    repo, case, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
    sys.path.insert(0, repo)
    from tests.test_matcher_linear import build_case
    fn = build_case(case, size)
    best = None
    for _ in range(2):
        started = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    json.dump({'elapsed': best}, sys.stdout)
    """
)


def _unit(u: str, n: int) -> str:
    return (u * (n // len(u) + 1))[:n]


def _diverse(n: int, seed: int = 1) -> str:
    rng = random.Random(seed)
    words = list(_KIT_WORDS + _FILLER) + _table_words()
    parts: List[str] = []
    size = i = 0
    while size < n:
        w = rng.choice(words) if rng.random() < 0.5 else f"w{i}x"
        i += 1
        parts.append(w)
        size += len(w) + 1
    return " ".join(parts)[:n]


PROMPT_SHAPES = {
    "diverse": _diverse,
    "site": lambda n: _unit("site ", n),
    "page": lambda n: _unit("page ", n),
    "page_hyphen": lambda n: _unit("page-", n),
    "blog_post": lambda n: _unit("blog post ", n),
    "kit_of": lambda n: _unit("kit of ", n),
    "design_to_code": lambda n: "x " + _unit("design to code ", n),
    "website_stack": lambda n: "a website for you " + _unit("in react ", n),
    "website_tool": lambda n: _unit("website ", n - 5) + " tool",
    "figma": lambda n: _unit("figma ", n),
    "dotted_i": lambda n: _unit("\u0130 my-site ", n),
}


def _many_kits(count: int, summary_len: int = 160, ntags: int = 6) -> List[Any]:
    rng = random.Random(7)
    words = list(_KIT_WORDS)
    kits = []
    for i in range(count):
        body = "Workspace for " + " ".join(rng.choice(words) for _ in range(10)) + ", not for games; "
        kits.append(matcher.KitInfo(
            id=f"{rng.choice(words)}-{i}", name=f"Kit {rng.choice(words)} {i}",
            summary=_unit(body, summary_len), tags=tuple(rng.choice(words) for _ in range(ntags)), version=1,
        ))
    return kits


def _pipeline(kits: Sequence[Any], prompt: str) -> Any:
    answers = {"building": "web", "languages": ["typescript"]}
    tms = matcher.best_matches(synthetic_templates(), answers, prompt=prompt)
    kms = matcher.match_kits(kits, prompt, answers)
    return matcher.choose_catalog_entry(tms, kms, answers)


def build_case(case: str, size: int) -> Any:
    """Callable for one timing case (used by the subprocess child)."""
    kind, _, shape = case.partition(":")
    if kind == "pipeline":  # size = prompt chars, 10,000 kits
        kits = _many_kits(10_000)
        prompt = PROMPT_SHAPES[shape](size)
        return lambda: _pipeline(kits, prompt)
    if kind == "prompt":  # size = prompt chars, real-sized kit list
        kits = _many_kits(20)
        prompt = PROMPT_SHAPES[shape](size)

        def run() -> None:
            matcher.kit_families_in(prompt)
            matcher.kit_families_in(prompt, _explicit_building="tool")
            matcher.family_request(prompt)
            _pipeline(kits, prompt)
        return run
    if kind == "helper":  # unbounded text helpers, size = chars
        prompt = PROMPT_SHAPES[shape](size)
        return lambda: (matcher.build_target_end(prompt), matcher.mask_website_subject(prompt))
    if kind == "kit_text":
        text = {"not": _unit("not a comic, ", size), "ws": _unit("rather" + " " * 40 + "x,", size),
                "plain": _unit("video and film ", size), "dash": _unit("a - no b ", size)}[shape]
        return lambda: matcher.positive_kit_text(text)
    if kind == "summary":  # 10 kits with `size`-char summaries
        kits = [matcher.KitInfo(id=f"k-{i}", name="K", summary=_unit("not a comic, storyboard video ", size),
                                tags=("video",), version=1) for i in range(10)]
        return lambda: matcher.match_kits(kits, "a storyboard video kit", {"building": "video"})
    if kind == "tags":  # 100 kits with `size` tags each, 2048-char prompt
        kits = _many_kits(100, ntags=size)
        prompt = _diverse(2048)
        return lambda: matcher.match_kits(kits, prompt, {"building": "video"})
    if kind == "choose":  # `size` strong kits against a family template
        tmpl = synthetic_templates()[4]
        top = matcher.Match(template=tmpl, score=9, reasons=[], needs=[], family="website")
        kit = matcher.KitInfo(id="site-x", name="X", summary="", tags=("website", "astro"), version=1)
        kms = [matcher.KitMatch(kit=kit, score=9, reasons=["matches tag 'astro'", "matches tag 'website'"],
                                tag_hits=2, family_hit=True) for _ in range(size)]
        return lambda: matcher.choose_catalog_entry([top], kms, {"building": "web"})
    if kind == "parse":  # `size` kit entries
        reply = {"status": "ok", "data": {"kits": [
            {"id": f"k{i}", "name": "K", "summary": "s", "tags": ["a", "b"], "version": 1} for i in range(size)]}}
        return lambda: matcher.parse_kit_list(reply)
    raise ValueError(case)


def _child(case: str, size: int) -> float:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, str(REPO_ROOT), case, str(size)],
            capture_output=True, text=True, timeout=HARD_TIMEOUT_S, cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{case} size={size} exceeded hard timeout {HARD_TIMEOUT_S}s")
        raise
    assert proc.returncode == 0, proc.stderr[-800:]
    elapsed = float(json.loads(proc.stdout)["elapsed"])
    print(f"TIMING {case} size={size} {elapsed:.4f}s")
    return elapsed


MIB = 1024 * 1024


@pytest.mark.parametrize("shape", sorted(PROMPT_SHAPES))
def test_2048_char_prompt_with_10000_kits_under_budget(shape: str) -> None:
    assert _child(f"pipeline:{shape}", 2048) < BUDGET_S


@pytest.mark.parametrize("shape", sorted(PROMPT_SHAPES))
def test_one_mib_prompt_passed_directly_under_budget(shape: str) -> None:
    assert _child(f"prompt:{shape}", MIB) < BUDGET_S


@pytest.mark.parametrize("shape", ["site", "page", "page_hyphen", "kit_of", "website_tool", "dotted_i"])
def test_bounded_prompt_work_scales_linearly(shape: str) -> None:
    small = _child(f"prompt:{shape}", matcher.MAX_MATCH_PROMPT_CHARS // 8)
    big = _child(f"prompt:{shape}", matcher.MAX_MATCH_PROMPT_CHARS)
    assert big < BUDGET_S
    assert big / max(small, 1e-3) < SCALE_RATIO_LIMIT


@pytest.mark.parametrize("shape", ["kit_of", "design_to_code", "website_stack", "page_hyphen"])
def test_unbounded_text_helpers_are_linear(shape: str) -> None:
    small = _child(f"helper:{shape}", MIB // 8)
    big = _child(f"helper:{shape}", MIB)
    assert big < BUDGET_S
    assert big / max(small, 1e-3) < SCALE_RATIO_LIMIT


@pytest.mark.parametrize("shape", ["not", "ws", "plain", "dash"])
def test_positive_kit_text_is_linear(shape: str) -> None:
    small = _child(f"kit_text:{shape}", MIB // 8)
    big = _child(f"kit_text:{shape}", MIB)
    assert big < BUDGET_S
    assert big / max(small, 1e-3) < SCALE_RATIO_LIMIT


def test_one_mib_kit_summaries_under_budget() -> None:
    assert _child("summary:", MIB) < BUDGET_S


def test_many_tags_under_budget() -> None:
    assert _child("tags:", 1000) < BUDGET_S


def test_choose_with_10000_strong_kits_under_budget() -> None:
    assert _child("choose:", 10_000) < BUDGET_S


def test_parse_10000_kits_under_budget() -> None:
    assert _child("parse:", 10_000) < BUDGET_S
