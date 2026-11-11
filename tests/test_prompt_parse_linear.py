"""Linear-time prompt parsing in prompt_parse.py, pinned against the old regex bodies.

A 2 MB prompt sent to /scaffold/parse-idea froze the backend: the residual-name step ran
``re.split(r"\\s*(?:[\\u2014\\u2013]+|--+|\\s-\\s)\\s*", ...)`` whose leading ``\\s*``
restarts on every character of a blank run and walks the whole run each time, and
``re.sub(r"\\([^)]*\\)|\\[[^\\]]*\\]", ...)`` rescans to the end from every unclosed
bracket. Other per-match prefix slices (prose-word checks, kit-span containment,
stopword ``pop(0)``, the LLM JSON regexes) were quadratic too.

The parser now uses hand scans with identical results and refuses prompts longer than
``MAX_PROMPT_CHARS`` with ``PromptTooLongError`` (a ``ValueError``). The OLD bodies are
copied below as references. For the end-to-end differential, the whole old module was
run once on this file's corpus and its answers are stored, hashed, in
``tests/fixtures/linear_baseline/prompt_parse.json`` (written by
``scripts/gen_history_baseline.py``), so no repository history is needed. Hostile timing runs in a
subprocess with a hard timeout so a regression fails instead of hanging the suite.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import random
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from tests.conftest import REPO_ROOT, load_submodule

pp = load_submodule("prompt_parse")
questionnaire = load_submodule("questionnaire")

FIXTURE = Path(REPO_ROOT) / "tests" / "fixtures" / "linear_baseline" / "prompt_parse.json"
HARD_TIMEOUT_S = 30
BUDGET_S = 1.0
SCALE_RATIO_LIMIT = 24.0  # 8x more input: linear ~8x, quadratic ~64x

# --- OLD bodies (before the linear rewrite), verbatim apart from module-name qualification ---------

_OLD_BRACKET_RE = r"\([^)]*\)|\[[^\]]*\]"
_OLD_DASH_SPLIT_RE = r"\s*(?:[\u2014\u2013]+|--+|\s-\s)\s*"


def old_clean_phrase_tokens(text: str) -> List[str]:
    cleaned = pp._LEADING_FILLER_RE.sub("", text.strip())
    cleaned = pp._LANG_INTRO_RE.sub("", cleaned.strip())
    words = [w for w in re.findall(r"[A-Za-z0-9]+", cleaned) if w]
    while words and words[0].lower() in pp._EDGE_STOPWORDS:
        words.pop(0)
    while words and words[-1].lower() in pp._EDGE_STOPWORDS:
        words.pop()
    return words


def old_extract_name_from_residual(original: str, spans: List[Tuple[int, int]]) -> str:
    explicit_match = pp._EXPLICIT_NAME_RE.search(original)
    if explicit_match:
        raw_explicit = (explicit_match.group(1) or explicit_match.group(2) or "").strip()
        explicit_words = old_clean_phrase_tokens(raw_explicit)
        if explicit_words:
            return pp._title_case_words(explicit_words)

    residual = pp._strip_detected_spans(original, spans)
    residual = re.sub(r"\([^)]*\)|\[[^\]]*\]", " ", residual)

    segments = [seg.strip() for seg in re.split(r"\s*(?:[\u2014\u2013]+|--+|\s-\s)\s*", residual) if seg.strip()]
    if not segments:
        segments = [residual]

    for seg in segments:
        clause_split = re.split(r"\b(?:for|that|which)\b", seg, maxsplit=1, flags=re.IGNORECASE)
        head_words = old_clean_phrase_tokens(clause_split[0])
        if head_words:
            return pp._title_case_words(head_words)
        if len(clause_split) > 1:
            tail_words = old_clean_phrase_tokens(clause_split[1])
            if tail_words:
                return pp._title_case_words(tail_words)

    all_words = old_clean_phrase_tokens(residual)
    return pp._title_case_words(all_words)


def old_has_project_head_noun_after(tail: str) -> bool:
    for pm in pp._PROJECT_HEAD_NOUN_RE.finditer(tail):
        between = tail[: pm.start()]
        if not pp._PROSE_OBJECT_BREAK_RE.search(between):
            return True
    return False


def old_is_non_project_request(raw_prompt: str) -> bool:
    if not raw_prompt:
        return False
    if pp._NON_PROJECT_OPENER_RE.match(raw_prompt) or pp._COMPARISON_QUERY_RE.search(raw_prompt):
        return True
    if pp._RESEARCH_ACADEMIC_RE.search(raw_prompt):
        return False

    build_target_end = load_submodule("matcher").build_target_end

    head = raw_prompt[: build_target_end(raw_prompt)]
    if pp._WORKSPACE_SETUP_RE.search(head):
        return False

    for m in pp._PROSE_ARTIFACT_RE.finditer(head):
        if old_has_project_head_noun_after(head[m.end() :]):
            continue
        return True

    for m in pp._CONTEXTUAL_PROSE_RE.finditer(head):
        if old_has_project_head_noun_after(head[m.end() :]):
            continue
        if pp._PROSE_WRITE_VERB_RE.search(head[: m.start()]) or pp._TOPICAL_PROSE_FOLLOW_RE.match(
            raw_prompt[m.end() :]
        ):
            return True
    return False


def old_drop_spans_inside(raw_building_spans, kit_spans):
    building_spans = []
    for start, end, b_kind in raw_building_spans:
        if b_kind not in questionnaire.KIT_BUILDING_KINDS and any(
            k_start <= start and end <= k_end for k_start, k_end in kit_spans
        ):
            continue
        building_spans.append((start, end, b_kind))
    return building_spans


# --- generated corpus -------------------------------------------------------------------

_VOCAB = {
    "sep": [" - ", "-", "--", "---", " -- ", " \u2014 ", "\u2014", "\u2013", " \u2013 ", "\u2014\u2013",
            " -x", "- ", " -\t", "\n-\n", "\u3000-\u3000", " - - ", "x-y"],
    "bracket": ["(", "[", ")", "]", "(beta)", "[wip]", "(in rust)", "[", "((", "]]", "(x[", "])"],
    "ws": [" ", "  ", "\t", "\n", "\u3000", "\u00a0", "\u2028", "   \t ", "\x1c", "\u2003"],
    "lang": ["typescript", "Rust", "python", "go", "golang", "c#", "c++", ".net", "java", "node.js",
             "three.js", "react", "next", "in next", "fastapi", "gin", "gin rummy", "lua", "gdscript"],
    "engine": ["godot", "unity", "bevy", "unreal engine", "ue5", "pygame", "qt", "sdl2", "raylib", "phaser"],
    "kind": ["game", "games", "api", "rest api", "cli tool", "command-line tool", "library", "app",
             "web app", "video", "music video", "images", "concept art", "asset library", "3d assets",
             "blender models", "studio", "game studio", "website", "web site", "blog", "page",
             "landing page", "service", "backend", "tools", "multi-tool", "dashboard", "kitbash"],
    "layout": ["monorepo", "poly-repo", "workspace", "single project", "multi repo"],
    "prose": ["blog post", "blog-post", "tweet", "tweets", "email", "e-mail", "post", "posts", "report",
              "thread", "letter", "guide", "summary", "essay", "man page", "linkedin post"],
    "head": ["tool", "script", "bot", "site", "generator", "summarizer", "cli", "pipeline", "website"],
    "brk": ["a", "an", "the", "our", "how", "announcing", "about", "why", "my", "this"],
    "verb": ["write", "draft", "compose", "pen", "writing"],
    "topic": ["about", "on", "to", "asking", "why", "explaining"],
    "opener": ["explain", "how do i", "fix", "review", "hey", "hi,", "please", "can you", "what is",
               "i want to", "build", "make me", "create a new", "set up", "summarize", "pros and cons of"],
    "name": ["called", "named", "'Foo Bar'", '"Zap"', "called 'Neon Rush'", 'named "x"', "'", '"'],
    "clause": ["for", "that", "which", "of", "with", "in", "using", "list of", "set of", "written in",
               "built with", "powered by", "vs", "versus"],
    "academic": ["citations", "thesis", "outline", "literature", "reading notes"],
    "json": ["{", "}", "```", "```json", "```JSON", '{"building": "game"}', "} ```", "{}", "```{"],
    "punct": [",", ".", "!", "?", "/", ";", ":", "'", "&"],
    "word": ["invoice", "tracker", "neon", "rush", "pixel", "farm", "notes", "weather", "Foo", "x", "42",
             "new", "project", "my", "and", "or"],
}
_WEIGHTS = {
    "sep": 6, "bracket": 5, "ws": 6, "lang": 3, "engine": 2, "kind": 4, "layout": 1, "prose": 3,
    "head": 3, "brk": 3, "verb": 1, "topic": 2, "opener": 1, "name": 1, "clause": 3, "academic": 1,
    "json": 1, "punct": 2, "word": 5,
}


def _gen_prompt(rng: random.Random) -> str:
    cats = list(_WEIGHTS)
    weights = [_WEIGHTS[c] for c in cats]
    parts: List[str] = []
    if rng.random() < 0.3:
        parts.append(rng.choice(_VOCAB["opener"]))
    for _ in range(rng.randint(1, 18)):
        cat = rng.choices(cats, weights)[0]
        tok = rng.choice(_VOCAB[cat])
        parts.append(tok)
        parts.append(rng.choice(["", " ", " ", " ", "  ", "\t"]))
    return "".join(parts)


def _corpus(n: int = 3000, seed: int = 20261111) -> List[str]:
    rng = random.Random(seed)
    rows = [_gen_prompt(rng) for _ in range(n)]
    rows += [
        "", " ", "-", "--", " - ", "\u2014", "(", "[", "()", "[]", "a - b", "a -b", "a- b", "a --b",
        "Build a REST API in TypeScript called Invoice Tracker - for (small) teams [beta]",
        "write a blog post about our new website", "a tweet archiver cli", "the the the game",
        "game \u2014 Neon Rush \u2014 for kids", "  -  -  -  ", "x \u2014 - \u2014b",
        "a - \u2014b", "a - --b", "video library app", "asset library for games",
    ]
    return rows


CORPUS = _corpus()


def _rand_spans(rng: random.Random, n: int) -> List[Tuple[int, int]]:
    spans = []
    for _ in range(rng.randint(0, 4)):
        a = rng.randint(0, max(0, n))
        b = rng.randint(a, max(a, n))
        spans.append((a, b))
    return spans


# --- exhaustive small-alphabet equivalence ----------------------------------------------


def _all_strings(alphabet: str, max_len: int):
    for n in range(max_len + 1):
        for tup in itertools.product(alphabet, repeat=n):
            yield "".join(tup)


def test_bracket_blanking_equals_old_regex_exhaustively() -> None:
    for s in _all_strings("(x)[ ]", 7):
        assert pp._blank_bracket_groups(s) == re.sub(_OLD_BRACKET_RE, " ", s), repr(s)


def test_dash_split_equals_old_regex_exhaustively() -> None:
    for s in _all_strings(" -\u2014\u2013x\u3000", 7):
        assert pp._split_on_dash_separators(s) == re.split(_OLD_DASH_SPLIT_RE, s), repr(s)


def test_whitespace_class_matches_isspace_on_every_code_point() -> None:
    ws = re.compile(r"\s")
    assert [c for c in range(sys.maxunicode + 1) if bool(ws.match(chr(c))) != chr(c).isspace()] == []


# --- differential on the generated corpus -----------------------------------------------


def test_regex_replacements_equal_old_on_corpus() -> None:
    for s in CORPUS:
        assert pp._blank_bracket_groups(s) == re.sub(_OLD_BRACKET_RE, " ", s), repr(s)
        assert pp._split_on_dash_separators(s) == re.split(_OLD_DASH_SPLIT_RE, s), repr(s)


def test_name_and_token_helpers_equal_old_on_corpus() -> None:
    rng = random.Random(7)
    for s in CORPUS:
        assert pp._clean_phrase_tokens(s) == old_clean_phrase_tokens(s), repr(s)
        assert pp._extract_name_from_residual(s, []) == old_extract_name_from_residual(s, []), repr(s)
        spans = _rand_spans(rng, len(s))
        assert pp._extract_name_from_residual(s, spans) == old_extract_name_from_residual(s, spans), repr(s)


def test_prose_helpers_equal_old_on_corpus() -> None:
    for s in CORPUS:
        assert pp._has_project_head_noun_after(s) == old_has_project_head_noun_after(s), repr(s)
        assert pp._is_non_project_request(s) == old_is_non_project_request(s), repr(s)
        stripped = s.strip()
        assert pp._is_non_project_request(stripped) == old_is_non_project_request(stripped), repr(s)


def test_kit_span_containment_equals_old_on_random_spans() -> None:
    rng = random.Random(11)
    kinds = ["game", "service", "video", "images", "assets", "library", "app", "studio"]
    for _ in range(4000):
        raw = []
        for _ in range(rng.randint(0, 8)):
            a = rng.randint(0, 30)
            raw.append((a, a + rng.randint(0, 10), rng.choice(kinds)))
        kits = []
        for _ in range(rng.randint(0, 5)):
            a = rng.randint(0, 30)
            kits.append((a, a + rng.randint(0, 12)))
        assert pp._drop_spans_inside(raw, kits) == old_drop_spans_inside(raw, kits), (raw, kits)


# --- end-to-end differential against the recorded base answers ------------------------


def _snapshot(parsed: Any) -> Dict[str, Any]:
    data = parsed.as_json()
    data["explicit_keys"] = sorted(parsed.explicit_keys)
    return data


def _hash(data: Any) -> str:
    """Short digest of one answer (answers can quote the prompt, so only the hash is kept)."""
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("ascii")).hexdigest()[:16]


def _deterministic_hashes(m: Any) -> List[str]:
    return [_hash(_snapshot(m.parse_deterministic(s))) for s in CORPUS]


def record_base_outputs(base_mod: Any, base_file: Any) -> Dict[str, Any]:
    """Run the base module on this file's inputs (scripts/gen_history_baseline.py only)."""
    return {
        "corpus_sha": _hash(CORPUS),
        "parse_deterministic": _deterministic_hashes(base_mod),
    }


def _expected() -> Dict[str, Any]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert data["corpus_sha"] == _hash(CORPUS), "corpus changed; re-record the fixture"
    return data


def _assert_same(actual: List[str], expected: List[str], rows: List[str]) -> None:
    assert len(actual) == len(expected)
    diffs = [i for i, (a, b) in enumerate(zip(actual, expected)) if a != b]
    assert not diffs, f"{len(diffs)} answers differ from the base; first: {rows[diffs[0]]!r}"


def test_parse_deterministic_equals_base_module_on_corpus() -> None:
    expected = _expected()["parse_deterministic"]
    _assert_same(_deterministic_hashes(pp), expected, CORPUS)


# --- input cap --------------------------------------------------------------------------


def test_cap_is_documented_and_generous() -> None:
    assert pp.MAX_PROMPT_CHARS >= 2048
    assert issubclass(pp.PromptTooLongError, ValueError)


def test_prompt_at_cap_parses_and_one_more_char_is_refused() -> None:
    at_cap = ("Build a game in rust called Neon Rush " * 1000)[: pp.MAX_PROMPT_CHARS]
    assert len(at_cap) == pp.MAX_PROMPT_CHARS
    assert pp.parse_deterministic(at_cap).answers["building"] == "game"
    with pytest.raises(pp.PromptTooLongError) as info:
        pp.parse_deterministic(at_cap + "x")
    assert info.value.length == pp.MAX_PROMPT_CHARS + 1
    assert info.value.limit == pp.MAX_PROMPT_CHARS
    assert str(pp.MAX_PROMPT_CHARS) in str(info.value)


def test_cap_counts_surrounding_whitespace() -> None:
    with pytest.raises(pp.PromptTooLongError):
        pp.parse_deterministic("game" + " " * pp.MAX_PROMPT_CHARS)


# --- hostile timing (subprocess, hard timeout) -----------------------------------------

_CHILD = textwrap.dedent(
    """
    import json
    import sys
    import time

    repo, kind, size, mode = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    sys.path.insert(0, repo)
    from tests.conftest import load_submodule
    pp = load_submodule('prompt_parse')

    def unit(u, n):
        return (u * (n // len(u) + 1))[:n]

    shapes = {
        'spaces': lambda n: 'a' + ' ' * (n - 2) + 'b',
        'hyphens': lambda n: unit('-', n),
        'spaced_single_hyphen': lambda n: unit('x -y ', n),
        'dashes': lambda n: unit('\\u2014', n),
        'ws_runs': lambda n: unit(' ' * 50 + 'x', n),
        'unclosed_paren': lambda n: unit('(', n),
        'unclosed_bracket': lambda n: unit('[a', n),
        'alt_separators': lambda n: unit(' - \\u2013 -- ', n),
        'long_token': lambda n: unit('a', n),
        'short_segments': lambda n: unit('ab \\u2014 ', n),
        'unicode_ws': lambda n: unit('\\u3000\\u00a0\\u2028\\t', n),
        'stopwords': lambda n: unit('the ', n),
        'game_app': lambda n: unit('game app video asset library ', n),
        'prose_heads': lambda n: unit('post tool email script ', n),
        'prose_breaks': lambda n: unit('tweet the tool ', n),
        'contextual': lambda n: unit('report ', n),
        'braces': lambda n: unit('{', n),
        'fences': lambda n: unit('```{', n),
        # Matcher helpers the parser calls (bounded only by the cap).
        'pages': lambda n: unit('page ', n),
        'blog_posts': lambda n: unit('blog post ', n),
        'list_of': lambda n: unit('list of ', n),
        'website_stack': lambda n: unit('website with react, ', n),
    }
    text = shapes[kind](size)

    def run():
        if mode == 'parse':
            try:
                return pp.parse_deterministic(text).name
            except pp.PromptTooLongError as exc:
                return 'refused:%d' % exc.length
        if mode == 'helpers':
            pp._split_on_dash_separators(text)
            pp._blank_bracket_groups(text)
            pp._clean_phrase_tokens(text)
            pp._extract_name_from_residual(text, [])
            pp._has_project_head_noun_after(text)
            pp._HeadNounIndex(text).after(0)
            spans = [(i, i + 4, 'game') for i in range(0, len(text), 8)]
            pp._drop_spans_inside(spans, [(i, i + 2) for i in range(0, len(text), 8)])
            return 'ok'
        raise SystemExit('unknown mode ' + mode)

    best = None
    out = None
    for _ in range(3 if size <= 300000 else 1):
        started = time.perf_counter()
        out = run()
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    json.dump({'elapsed': best, 'out': out}, sys.stdout)
    """
)

SHAPES = ("spaces", "hyphens", "spaced_single_hyphen", "dashes", "ws_runs", "unclosed_paren",
          "unclosed_bracket", "alt_separators", "long_token", "short_segments", "unicode_ws",
          "stopwords", "game_app", "prose_heads", "prose_breaks", "contextual", "braces", "fences")

MIB2 = 2 * 1024 * 1024


def _child(kind: str, size: int, mode: str) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, str(REPO_ROOT), kind, str(size), mode],
            capture_output=True, text=True, timeout=HARD_TIMEOUT_S, cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{kind} {mode} size={size} exceeded hard timeout {HARD_TIMEOUT_S}s")
        raise
    assert proc.returncode == 0, proc.stderr[-800:]
    payload = json.loads(proc.stdout)
    print(f"TIMING {mode} {kind} size={size} {payload['elapsed']:.4f}s out={str(payload['out'])[:40]}")
    return payload


@pytest.mark.parametrize("kind", SHAPES)
def test_two_mib_prompt_is_refused_well_under_a_second(kind: str) -> None:
    payload = _child(kind, MIB2, "parse")
    assert payload["out"] == f"refused:{MIB2}"
    assert payload["elapsed"] < 0.1


MATCHER_SHAPES = ("pages", "blog_posts", "list_of", "website_stack")


@pytest.mark.parametrize("kind", SHAPES + MATCHER_SHAPES)
def test_prompt_at_cap_parses_fast(kind: str) -> None:
    payload = _child(kind, pp.MAX_PROMPT_CHARS, "parse")
    assert not str(payload["out"]).startswith("refused")
    assert payload["elapsed"] < BUDGET_S


@pytest.mark.parametrize("kind", SHAPES)
def test_helpers_are_linear_at_two_mib(kind: str) -> None:
    small = _child(kind, MIB2 // 8, "helpers")
    big = _child(kind, MIB2, "helpers")
    # Absolute guard only (ten pure-Python helpers over 2 MiB); the ratio is the real check.
    assert big["elapsed"] < 10.0
    # Generous: linear is ~8x, the old quadratic bodies were ~64x or never finished.
    assert big["elapsed"] <= max(small["elapsed"], 0.005) * SCALE_RATIO_LIMIT
