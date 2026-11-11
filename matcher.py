"""Rank project templates against questionnaire answers with human-readable reasons.

The matcher only builds SUGGESTIONS for the project pick-list (it never selects or
creates a project), so it must stay cheap and must never hang.

Cost
----
Every public entry point is linear (or n log n) in each input: prompt length, number of
kits, kit name/summary length and number of tags. Prompt-wide facts (whole-prompt regex
searches, the lowercased word tokens) are computed once per call and per-match queries
are answered from them; kit words are matched through a token index, so a long prompt
does not multiply with a long kit list.

Hard bounds (second line of defence)
------------------------------------
Input past a bound is ignored, never an error:

* ``MAX_MATCH_PROMPT_CHARS``: ``kit_families_in``, ``family_request``,
  ``best_matches(prompt=...)`` and ``match_kits`` consider only the first this-many
  characters of the prompt (the rest is treated as absent). ``build_target_end`` and
  ``mask_website_subject`` answer about the whole string they are given (an index into
  it, a string of the same length); they are linear and unbounded.
* ``MAX_KITS_SCORED``: ``match_kits`` scores only the first this-many entries of
  ``kits``; later entries are never suggested.
* ``MAX_KIT_SUMMARY_CHARS`` / ``MAX_KIT_NAME_CHARS``: ``match_kits`` reads only the first
  this-many characters of each kit's summary / name (tags and id are read in full).
"""

from __future__ import annotations

import bisect
import itertools
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, List, Optional, Sequence, Tuple

from . import componentize_bridge
from .questionnaire import KIT_BUILDING_KINDS
from .templates import TemplateSpec

# Hard bounds; see the module docstring. The prompt parser already refuses prompts over
# prompt_parse.MAX_PROMPT_CHARS (2048), so real prompts are always inside this bound.
MAX_MATCH_PROMPT_CHARS: int = 8192
MAX_KITS_SCORED: int = 10_000
MAX_KIT_SUMMARY_CHARS: int = 4096
MAX_KIT_NAME_CHARS: int = 512


def _bounded_prompt(prompt: str) -> str:
    """Return prompt cut to MAX_MATCH_PROMPT_CHARS characters."""
    return prompt[:MAX_MATCH_PROMPT_CHARS] if len(prompt) > MAX_MATCH_PROMPT_CHARS else prompt


@dataclass
class Match:
    """Ranked template match with score, human-readable reasons, and required toolchains."""

    template: TemplateSpec
    score: int
    reasons: List[str]
    needs: List[str]
    # Kit family tag ('website') when a family template matched a request in that family.
    family: Optional[str] = None


def _str_answer(val: Any) -> Optional[str]:
    """Return a non-empty string answer as-is, or None."""
    if not isinstance(val, str) or not val:
        return None
    return val


def _list_answer(val: Any) -> List[str]:
    """Return a deduplicated list of non-empty strings from a str or list[str] answer."""
    if isinstance(val, str):
        raw_items = [val]
    elif isinstance(val, list):
        raw_items = val
    else:
        return []

    out: List[str] = []
    seen: set[str] = set()
    for item in raw_items:
        if isinstance(item, str) and item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _collect_answer_values(answers: Mapping[str, Any]) -> set[str]:
    """Collect all exact string values from str or list[str] entries in answers."""
    values: set[str] = set()
    for raw in answers.values():
        if isinstance(raw, str) and raw:
            values.add(raw)
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item:
                    values.add(item)
    return values


def _score_template(template: TemplateSpec, answers: Mapping[str, Any]) -> Optional[Match]:
    """Score a single TemplateSpec against answers; return None when excluded by engine mismatch."""
    building = _str_answer(answers.get("building"))
    layout = _str_answer(answers.get("layout"))
    user_languages = _list_answer(answers.get("languages"))
    engine = _str_answer(answers.get("engine"))
    answer_values = _collect_answer_values(answers)

    tmpl_engine = template.engine

    # Engine check first (may exclude template completely)
    engine_score = 0
    engine_reasons: List[str] = []
    if engine is not None:
        if engine == "none":
            if tmpl_engine is not None:
                engine_score -= 2
                engine_reasons.append(f"engine differs: template uses {tmpl_engine}, you want none")
        else:
            if tmpl_engine is not None:
                if tmpl_engine == engine:
                    engine_score += 3
                    engine_reasons.append(f"engine: {engine}")
                else:
                    return None

    score = 0
    reasons: List[str] = []

    # 1. building vs kind
    tmpl_kind = template.kind
    tmpl_layout = template.layout
    if building is not None and building != "other":
        if building == tmpl_kind:
            score += 3
            reasons.append(f"kind: {tmpl_kind}")
        elif building == "studio" and tmpl_kind == "game" and tmpl_layout == "poly":
            score += 2
            reasons.append("kind: game (poly layout fits studio)")

    # 2. layout
    if layout is not None:
        if layout == tmpl_layout:
            score += 3
            reasons.append(f"layout: {tmpl_layout}")
        else:
            score -= 2
            reasons.append(f"layout differs: template is {tmpl_layout}, you want {layout}")

    # 3. languages
    if user_languages:
        tmpl_lang_set = set(template.languages)
        matched_langs = [lang for lang in user_languages if lang in tmpl_lang_set]
        if matched_langs:
            for lang in matched_langs:
                score += 2
                reasons.append(f"language: {lang}")
        else:
            score -= 3
            reasons.append("language: no overlap")

    # 4. engine score & reasons
    score += engine_score
    reasons.extend(engine_reasons)

    # 5. tags bonus
    for tag in template.tags:
        if tag in answer_values:
            score += 1
            reasons.append(f"tag: {tag}")

    return Match(
        template=template,
        score=score,
        reasons=reasons,
        needs=list(template.needs),
    )


def rank_templates(
    templates: Sequence[TemplateSpec],
    answers: Mapping[str, Any],
) -> List[Match]:
    """Score and rank non-excluded templates by (-score, template.id)."""
    matches: List[Match] = []
    for template in templates:
        match = _score_template(template, answers)
        if match is not None:
            matches.append(match)
    matches.sort(key=lambda m: (-m.score, m.template.id))
    return matches


def _template_fits_kind_spec(template: TemplateSpec, building: str) -> bool:
    """Return True when a TemplateSpec's kind fits the requested building kind."""
    if template.kind == building:
        return True
    return building == "studio" and template.kind == "game" and template.layout == "poly"


def _is_viable_match(template: TemplateSpec, answers: Mapping[str, Any]) -> bool:
    """Return True if template satisfies hard compatibility constraints for best_matches().

    Templates require at least one real template language in answers['languages']:
    empty languages, 'gdscript', or 'other' never match a code template. Game and
    studio requests only fit game/studio templates, and untemplated engines/toolkits
    in answers['engine'] or answers['framework'] exclude templates that lack them.
    """
    if not _names_real_language(answers):
        return False
    building = _str_answer(answers.get("building"))
    if building in _DEFAULT_ONLY_TEMPLATE_KINDS and not _template_fits_kind_spec(template, building):
        return False
    user_languages = [lang for lang in _list_answer(answers.get("languages")) if lang != "other"]
    if user_languages:
        tmpl_lang_set = set(template.languages)
        if not any(lang in tmpl_lang_set for lang in user_languages):
            return False

    engine = _str_answer(answers.get("engine"))
    if engine is not None and engine != "none":
        if template.engine != engine:
            return False

    framework = _str_answer(answers.get("framework"))
    if framework is not None and framework != "none":
        if template.engine != framework:
            return False
    return True


def best_matches(
    templates: Sequence[TemplateSpec],
    answers: Mapping[str, Any],
    *,
    min_score: int = 3,
    prompt: Optional[str] = None,
    explicit_code: bool = False,
) -> List[Match]:
    """Return ranked template matches that are language/engine compatible and score at least min_score.

    With ``prompt``, a family template (manifest `tags` hold a kit family tag such as
    `website`) is a candidate only for a request in that family that it serves (see
    ``family_request``); without a prompt it is never one. When the prompt is a website-family
    request and no language was named explicitly, or it names a site stack (React, Next.js,
    WordPress...), other code templates are not candidates: a default or implied language
    alone does not turn a website into a backend, and no bundled template has those stacks.
    """
    request = family_request(prompt) if prompt is not None else None
    out: List[Match] = []
    for template in templates:
        if template_families(template):
            match = _family_match(template, answers, request, explicit_code)
            if match is not None and match.score >= min_score:
                out.append(match)
            continue
        if request is not None and (request.stacks or not explicit_code):
            continue
        match = _score_template(template, answers)
        if match is not None and match.score >= min_score and _is_viable_match(template, answers):
            out.append(match)
    out.sort(key=lambda m: (-m.score, m.template.id))
    return out


_NON_TEMPLATE_LANGUAGES: frozenset[str] = frozenset({"other", "gdscript"})


def _names_real_language(answers: Mapping[str, Any]) -> bool:
    """Return True when answers['languages'] holds at least one code-template language."""
    return any(lang not in _NON_TEMPLATE_LANGUAGES for lang in _list_answer(answers.get("languages")))


def _names_only_other_language(answers: Mapping[str, Any]) -> bool:
    """Return True when answers['languages'] is non-empty and holds only 'other'."""
    langs = _list_answer(answers.get("languages"))
    return bool(langs) and all(lang == "other" for lang in langs)


def closest(
    templates: Sequence[TemplateSpec],
    answers: Mapping[str, Any],
) -> Optional[Match]:
    """Return the highest-ranked non-excluded template regardless of min_score, or None.

    When the request is a code kind, names no real language (empty or only 'other') and
    the top score is tied, the winner would be picked by template id alone (e.g.
    'cpp-golden' first in the alphabet), so return None and let the caller ask instead
    of naming an unrelated template. Kit kinds (video/images/assets) keep their
    nearest-template hand-off for when the kit catalog is unavailable.
    """
    if _names_only_other_language(answers) and _str_answer(answers.get("building")) not in KIT_BUILDING_KINDS:
        # The named language has no template: ask rather than suggest another language's.
        return None
    ranked = rank_templates(templates, answers)
    if not ranked:
        return None
    if (
        len(ranked) > 1
        and _str_answer(answers.get("building")) not in KIT_BUILDING_KINDS
        and not _names_real_language(answers)
    ):
        return None
    return ranked[0]


_KIT_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "new",
        "set",
        "make",
        "create",
        "build",
        "project",
        "with",
        "need",
        "want",
        "start",
        "please",
        "setup",
        "folder",
        "workspace",
        "some",
        "that",
        "this",
        "from",
        "into",
        "about",
    }
)

_BUILDING_KIT_TAGS: Mapping[str, frozenset[str]] = {
    "video": frozenset({"video", "film", "storyboard"}),
    "images": frozenset({"image", "images", "art", "illustration"}),
    "assets": frozenset({"assets", "3d", "blender", "houdini", "unreal"}),
}

_ALNUM_WORD_RE = re.compile(r"[a-z0-9]+")

# Two-letter words that still mean something as kit words (normally words under 3
# letters are dropped as noise).
_SHORT_KIT_WORDS: frozenset[str] = frozenset({"ui", "3d"})

# Everyday words for a kind of project -> the kit family tag that kind's kit carries
# ('website' on web-app, 'components' on component-library, 'gdscript' on godot-game).
# Kit definitions live in the componentize plugin; this table only maps a beginner's
# words onto tags those kits already have. Each phrase also matches its plural and
# optional spacing or hyphens between words ("web site", "website", "web-sites").
KIT_FAMILY_SYNONYMS: Tuple[Tuple[str, str], ...] = (
    # web-app ('website' tag)
    ("web app", "website"),
    ("webapp", "website"),
    ("web application", "website"),
    ("website", "website"),
    ("web site", "website"),
    ("site", "website"),
    ("landing page", "website"),
    ("homepage", "website"),
    ("home page", "website"),
    ("portfolio", "website"),
    ("blog", "website"),
    ("web page", "website"),
    ("webpage", "website"),
    ("online store", "website"),
    ("online shop", "website"),
    ("online menu", "website"),
    ("web store", "website"),
    ("web shop", "website"),
    ("storefront", "website"),
    ("e commerce", "website"),
    ("single page", "website"),
    ("one page", "website"),
    ("simple page", "website"),
    ("launch page", "website"),
    ("coming soon page", "website"),
    ("product page", "website"),
    ("contact page", "website"),
    ("pricing page", "website"),
    ("booking page", "website"),
    ("ordering page", "website"),
    ("registration page", "website"),
    ("rsvp page", "website"),
    ("event page", "website"),
    ("profile page", "website"),
    ("about page", "website"),
    ("bio page", "website"),
    ("status page", "website"),
    ("waitlist page", "website"),
    ("signup page", "website"),
    ("login page", "website"),
    ("checkout page", "website"),
    ("faq page", "website"),
    ("splash page", "website"),
    ("links page", "website"),
    ("link page", "website"),
    ("promo page", "website"),
    ("showcase page", "website"),
    ("donate page", "website"),
    ("donation page", "website"),
    ("menu page", "website"),
    ("wedding page", "website"),
    ("fan page", "website"),
    ("page", "website"),
    ("contact form", "website"),
    ("booking form", "website"),
    ("signup form", "website"),
    ("sign up", "website"),
    ("browser app", "website"),
    ("customer portal", "website"),
    ("client portal", "website"),
    ("member portal", "website"),
    ("web portal", "website"),
    ("portal", "website"),
    ("dashboard", "website"),
    ("forum", "website"),
    ("web frontend", "website"),
    ("frontend workspace", "website"),
    ("frontend project", "website"),
    ("design token", "website"),
    ("design source", "website"),
    ("design asset", "website"),
    ("design handoff", "website"),
    ("handed over design", "website"),
    ("design to code", "website"),
    ("figma", "website"),
    # component-library ('components' tag: reusable Python code components, not frontend UI)
    ("component library", "components"),
    ("reusable component", "components"),
    ("shared component", "components"),
    ("code component", "components"),
    ("python component", "components"),
    ("component collection", "components"),
    ("component catalog", "components"),
    ("component catalogue", "components"),
    ("component pack", "components"),
    ("component kit", "components"),
    ("component set", "components"),
    ("component folder", "components"),
    ("component repo", "components"),
    ("component repository", "components"),
    ("component showcase", "components"),
    ("component index", "components"),
    ("componentize", "components"),
    # godot-game ('gdscript' tag, unique to godot-game)
    ("godot", "gdscript"),
    ("gdscript", "gdscript"),
    ("gdignore", "gdscript"),
)

# Languages carried by a kit family itself; naming only these in a prompt for that
# family describes the kit rather than overriding it with a generic code template.
KIT_FAMILY_NATIVE_LANGUAGES: Mapping[str, frozenset[str]] = {
    "components": frozenset({"python"}),
    "gdscript": frozenset({"gdscript"}),
}


def _family_phrase_re(phrase: str) -> re.Pattern[str]:
    words = phrase.split()
    escaped = [re.escape(w) for w in words[:-1]]
    last = words[-1]
    if len(last) > 2 and last.endswith("y") and last[-2].lower() not in "aeiou":
        tail = re.escape(last[:-1]) + r"(?:y|ies)"
    else:
        tail = re.escape(last) + r"(?:es|s)?"
    escaped.append(tail)
    return re.compile(r"\b" + r"[-\s]*".join(escaped) + r"\b", re.IGNORECASE)


_KIT_FAMILY_RES: Tuple[Tuple[re.Pattern[str], str, str], ...] = tuple(
    (_family_phrase_re(phrase), phrase, tag) for phrase, tag in KIT_FAMILY_SYNONYMS
)


def _word_list_body(words: Sequence[str]) -> str:
    return (
        r"(?:"
        + "|".join(r"[-\s]+".join(map(re.escape, re.split(r"[-\s]+", w))) for w in words)
        + r")s?\b"
    )


def _word_list_re(words: Sequence[str]) -> re.Pattern[str]:
    return re.compile(r"\b" + _word_list_body(words), re.IGNORECASE)


# Platform words in a build target that mean an app or dashboard is native/terminal, not web.
NON_WEB_PLATFORM_WORDS: Tuple[str, ...] = (
    "cli",
    "command-line",
    "terminal",
    "tui",
    "console",
    "headless",
    "desktop app",
    "desktop application",
    "mobile app",
    "mobile application",
    "ios",
    "android",
)

_NON_WEB_PLATFORM_RE = _word_list_re(NON_WEB_PLATFORM_WORDS)

# Words that say the build-target head noun is another kind of thing than a website.
NOT_A_WEBSITE_WORDS: Tuple[str, ...] = (
    "cli",
    "command-line",
    "terminal",
    "tui",
    "console",
    "script",
    "bot",
    "scraper",
    "crawler",
    "tracker",
    "monitor",
    "checker",
    "summarizer",
    "summariser",
    "optimizer",
    "optimiser",
    "rebalancing",
    "generator",
    "engine",
    "api",
    "sdk",
    "library",
    "simulator",
    "tool",
    "utility",
    "utilities",
    "linter",
    "formatter",
    "parser",
    "analyzer",
    "analyser",
    "allocator",
    "solver",
    "splitter",
    "exporter",
    "archiver",
    "backend",
    "server",
    "daemon",
    "worker",
    "plugin",
    "addon",
    "add-on",
    "extension",
    "booking system",
    "desktop app",
    "desktop application",
    "mobile app",
    "mobile application",
    "ios",
    "android",
    "webhook",
    "websocket",
    "webrtc",
    "webauthn",
    "headless",
    "3d",
    "blender",
    "houdini",
    "unreal",
    "ue5",
    "component",
    "componentize",
)

_NOT_A_WEBSITE_RE = _word_list_re(NOT_A_WEBSITE_WORDS)
# _NOT_A_WEBSITE_RE.search(s[k:]) without the slice: a match AT k (where the slice's start
# counts as a word boundary) or a match starting after k (boundary seen in full context).
_NOT_A_WEBSITE_AT_RE = re.compile(r"(?=\w)" + _word_list_body(NOT_A_WEBSITE_WORDS), re.IGNORECASE)
_NOT_A_WEBSITE_STARTS_RE = re.compile(r"(?=\b" + _word_list_body(NOT_A_WEBSITE_WORDS) + r")", re.IGNORECASE)

# Multi-word phrases where 'page(s)' means documentation, print/comics, or OS/algorithm concepts, never a web page.
NOT_A_WEBPAGE_WORDS: Tuple[str, ...] = (
    "page rank",
    "pagerank",
    "man page",
    "manpage",
    "manual page",
    "wiki page",
    "wikipedia page",
    "notion page",
    "confluence page",
    "comic page",
    "manga page",
    "storyboard page",
    "per page",
    "coloring page",
    "colouring page",
    "page table",
    "page fault",
    "page cache",
    "page replacement",
    "memory page",
    "huge page",
    "pdf page",
    "book page",
    "cover page",
    "title page",
    "page break",
    "page number",
    "yellow page",
    "white page",
)

_NOT_A_WEBPAGE_RE = _word_list_re(NOT_A_WEBPAGE_WORDS)

# Words that say 'component(s)' means electronics, ECS, math/graphs, or a CLI/server
# rather than a reusable Python code component library.
NOT_A_COMPONENT_LIBRARY_WORDS: Tuple[str, ...] = (
    "entity component",
    "ecs",
    "electronic",
    "electronics",
    "pcb",
    "bom",
    "resistor",
    "capacitor",
    "schematic",
    "circuit",
    "hardware",
    "rack",
    "principal component",
    "connected component",
    "symmetrical component",
    "fault current",
    "calculator",
    "converter",
    "cli",
    "command-line",
    "linter",
    "formatter",
    "daemon",
    "monitor",
    "benchmark",
    "physics",
    "graph",
    "scraper",
    "crawler",
    "webhook",
    "server",
    "backend",
    "api",
)

_NOT_A_COMPONENT_LIBRARY_RE = _word_list_re(NOT_A_COMPONENT_LIBRARY_WORDS)

# UI, design-system, and frontend framework words that disqualify the Python-only component-library kit.
UI_COMPONENT_WORDS: Tuple[str, ...] = (
    "ui",
    "user interface",
    "interface component",
    "interface",
    "frontend",
    "front-end",
    "web component",
    "button",
    "card",
    "modal",
    "dialog",
    "dropdown",
    "tooltip",
    "navbar",
    "sidebar",
    "form input",
    "form field",
    "form control",
    "form component",
    "reusable form",
    "input",
    "checkbox",
    "slider",
    "toggle",
    "badge",
    "avatar",
    "widget",
    "storybook",
    "design system",
    "design kit",
    "design token",
    "ui kit",
    "tailwind",
    "css",
    "scss",
    "sass",
    "shadcn",
    "radix",
    "chakra",
    "react",
    "vue",
    "vuejs",
    "vue.js",
    "svelte",
    "sveltekit",
    "angular",
    "nextjs",
    "next.js",
    "nuxt",
    "jsx",
    "tsx",
    "shadow dom",
    "figma",
)

_UI_COMPONENT_RE = _word_list_re(UI_COMPONENT_WORDS)

# Qualifier + noun tables for non-adjacent Python component-library phrasing
# (e.g. 'reusable python modules packaged as components').
_COMPONENT_QUALIFIER_WORDS: frozenset[str] = frozenset(
    {
        "reusable",
        "reuse",
        "shared",
        "componentize",
    }
)
_COMPONENT_NOUN_WORDS: frozenset[str] = frozenset({"component", "components"})

# Reuse/toolbox qualifiers and code-piece nouns for Python component-library paraphrases without 'component'.
_PYTHON_REUSE_QUALIFIER_WORDS: frozenset[str] = frozenset(
    {"reusable", "reuse", "shared", "toolbox"}
)
_PYTHON_CODE_PIECE_WORDS: frozenset[str] = frozenset(
    {
        "module",
        "modules",
        "function",
        "functions",
        "script",
        "scripts",
        "helper",
        "helpers",
        "snippet",
        "snippets",
        "block",
        "blocks",
        "runner",
        "runners",
    }
)

# Words that mark a Godot mention as a multi-tool 3D studio or non-game CLI/backend tool
# rather than a solo Godot game workspace.
NOT_A_GODOT_GAME_WORDS: Tuple[str, ...] = (
    "3d studio",
    "3d design studio",
    "multi-tool",
    "blender",
    "houdini",
    "unreal",
    "ue5",
    "three.js",
    "threejs",
    "cli",
    "command-line",
    "linter",
    "formatter",
    "parser",
    "converter",
    "server",
    "backend",
    "api",
    "bot",
    "scraper",
)

_NOT_A_GODOT_GAME_RE = _word_list_re(NOT_A_GODOT_GAME_WORDS)

# Parsed kinds that mean the request is for code that is not a website.
_NOT_A_WEBSITE_KINDS: frozenset[str] = frozenset({"tool", "library", "service"})

# Website phrases that name design/form features rather than a standalone site head noun.
_ASSET_OR_FEATURE_WEBSITE_PHRASES: frozenset[str] = frozenset(
    {
        "figma",
        "design token",
        "design source",
        "design asset",
        "design handoff",
        "handed over design",
        "design to code",
        "sign up",
        "contact form",
        "booking form",
        "signup form",
    }
)

# Website words that can also mean something else ('stock portfolio', 'camping site').
_BARE_WEBSITE_WORDS: frozenset[str] = frozenset({"site", "portfolio", "blog"})

# Words immediately after 'blog' that show 'blog' modifies a post or feed rather than naming a blog site.
_BLOG_NON_SITE_AFTER: frozenset[str] = frozenset(
    {
        "post",
        "posts",
        "entry",
        "entries",
        "article",
        "articles",
        "rss",
        "feed",
        "feeds",
        "engine",
        "comment",
        "comments",
    }
)

# Words before a bare website word that mark it as the thing being built.
_BARE_WEBSITE_BEFORE: frozenset[str] = frozenset(
    {
        "a", "an", "my", "our", "the", "personal", "company", "business", "band",
        "school", "photo", "photography", "art", "design", "travel", "food", "dev",
        "developer", "portfolio", "blog", "simple", "small", "new",
        "docs", "documentation", "static", "marketing", "resume",
    }
)
_BARE_WEBSITE_AFTER: frozenset[str] = frozenset({"for", "about", "with", "where", "to", "that"})

# Determiners and adjectives before bare 'page' when 'page' is the build target.
_BARE_PAGE_BEFORE: frozenset[str] = frozenset(
    {
        "a", "an", "my", "our", "the", "new", "simple", "quick", "small", "little",
        "lil", "clean", "nice", "public", "personal", "static", "interactive", "custom",
    }
)

# Clause introducers after bare 'page' that supply a relative clause or purpose ('a page where people can ...').
_BARE_PAGE_AFTER: frozenset[str] = frozenset({"where", "for", "to", "that", "which", "with"})

# Determiners ignored when checking whether a noun has already appeared before a clause boundary.
_TARGET_DETERMINERS: frozenset[str] = frozenset(
    {"a", "an", "the", "my", "our", "your", "new", "some", "this", "that"}
)

# Container nouns where a following 'of ...' names the items being built rather than a topic.
_CONTAINER_HEAD_WORDS: frozenset[str] = frozenset(
    {
        "set", "sets", "folder", "folders", "collection", "collections", "library",
        "libraries", "pack", "packs", "kit", "kits", "catalog", "catalogue", "index",
        "repo", "repository", "studio", "studios", "toolbox", "suite", "bundle",
        "series", "list", "pair", "couple", "bunch",
    }
)

# Prepositions and relative pronouns that introduce a build target's subject or purpose clause.
_SUBJECT_CLAUSE_WORDS: Tuple[str, ...] = (
    "for",
    "about",
    "of",
    "where",
    "that",
    "which",
    "who",
    "to",
    "with",
)
_SUBJECT_CLAUSE_RE = re.compile(
    r"\b(?:" + "|".join(_SUBJECT_CLAUSE_WORDS) + r")\b",
    re.IGNORECASE,
)

# Leading conversational request prefixes stripped when locating the build-target noun phrase.
_REQUEST_OPENER_RE = re.compile(
    r"^\s*(?:(?:hey|hi|hello)\b[,\s]*)?"
    r"(?:(?:can|could|would|will)\s+(?:you|u)\s+)?"
    r"(?:(?:please|plz|pls)\s+)?"
    r"(?:(?:help\s+me\s+(?:to\s+)?)|(?:i\s*(?:want|wanna|need|would\s+like|'d\s+like)\s+(?:to\s+)?)|"
    r"(?:(?:i'?m|i\s+am)\s+)?looking\s+(?:for|to\s+(?:build|make|create|start|set\s+up|scaffold))\s+)?"
    r"(?:(?:build|make|create|start|scaffold|set\s+up|setup|spin\s+up|put\s+together)\s+(?:me\s+|us\s+)?)?",
    re.IGNORECASE,
)

# Explicit stack prepositions + language/framework tokens preserved when masking a website's subject phrase.
_STACK_TOKEN_PAT = (
    r"(?:typescript|tsx|jsx|ts|node\.?js|nodejs|node|javascript|js|deno|bun|hono|fastify|"
    r"express(?:js)?|next\.?js|vite|react|vue(?:\.?js)?|svelte(?:kit)?|nuxt(?:\.?js)?|"
    r"rustlang|rust|cargo|tokio|axum|bevy|python3?|py|fastapi|flask|django|pydantic|pygame|tkinter|"
    r"golang|go|gin|cobra|\.net|c#|csharp|dotnet|asp\.?net|blazor|unity|"
    r"c\+\+|cpp|qt[56]?|sdl[23]?|unreal(?:\s+engine)?|ue[45]|gdscript|godot|"
    r"java|kotlin|php|ruby|swift|scala|elixir|erlang|haskell|perl|lua|clojure|ocaml|zig)"
)
_STACK_PHRASE_RE = re.compile(
    r"(?:\b(?:written\s+in|built\s+with|built\s+in|made\s+with|made\s+in|powered\s+by|"
    r"implemented\s+in|coded\s+in|using|in)\s+" + _STACK_TOKEN_PAT + r"(?=$|[\s,.)!?;:])|"
    r"\bwith\s+" + _STACK_TOKEN_PAT + r"(?=$|\s+(?:and|or|plus)\b|[,.!?;:]))",
    re.IGNORECASE,
)

_WORD_RE = re.compile(r"[a-z0-9]+(?:[-'][a-z0-9]+)*")
_WORD_CHAR_RE = re.compile(r"\w")
_WHITESPACE_RUN_RE = re.compile(r"\s*")


def _skip_whitespace(text: str, i: int) -> int:
    """Index of the first non-whitespace char at or after i (regex \\s is exactly str.isspace())."""
    m = _WHITESPACE_RUN_RE.match(text, i)
    return m.end() if m else i
# Stand-in for a word longer than any word the bare-word tables hold (never a member).
_LONG_WORD = "\x00long"
_LONG_WORD_CHARS = 64


def _follows_boundary(text: str, k: int) -> bool:
    """True when text[:k] ends at a regex word boundary before a word char (k == 0 included)."""
    return k == 0 or not _WORD_CHAR_RE.match(text[k - 1])


def build_target_end(prompt: str) -> int:
    """Return the character index in prompt where the primary build-target noun phrase ends."""
    if not prompt:
        return 0
    opener_match = _REQUEST_OPENER_RE.match(prompt)
    opener_end = opener_match.end() if opener_match else 0
    tail = prompt[opener_end:]
    # The last non-determiner word of tail[:m.start()], extended segment by segment. Each
    # cut is at a subject word's leading \b (a non-word char before it), and a non-word
    # char never lowercases into [a-z0-9], so no lowercased word spans a cut and the
    # segments' words concatenate to the prefix's words.
    head_last: Optional[str] = None
    scanned = 0
    n = len(tail)
    for m in _SUBJECT_CLAUSE_RE.finditer(tail):
        for w in _ALNUM_WORD_RE.findall(tail[scanned : m.start()].lower()):
            if w not in _TARGET_DETERMINERS:
                head_last = w
        scanned = m.start()
        if head_last is None:
            continue
        prep = m.group(0).lower()
        if prep == "of" and head_last in _CONTAINER_HEAD_WORDS:
            continue
        if prep == "to" and head_last == "design":
            p = m.end()
            while p < n and tail[p].isspace():  # == lstrip(); runs between matches are disjoint
                p += 1
            if tail[p : p + 4].lower().startswith("code"):
                continue
        return opener_end + m.start()
    return len(prompt)


def mask_website_subject(prompt: str) -> str:
    """Replace a website's trailing subject/purpose clause with spaces while preserving explicit stack phrases."""
    end = build_target_end(prompt)
    if end >= len(prompt):
        return prompt
    pieces = [prompt[:end]]
    pos = end
    for m in _STACK_PHRASE_RE.finditer(prompt[end:]):  # sorted, non-overlapping, non-empty
        start, stop = end + m.start(), end + m.end()
        pieces.append(" " * (start - pos))
        pieces.append(prompt[start:stop])
        pos = stop
    pieces.append(" " * (len(prompt) - pos))
    return "".join(pieces)


class _WebsiteScan:
    """Prompt-wide facts for the website pass, computed once and shared by every match.

    Each query returns exactly what the per-match slice expression in its docstring
    returned; prompt and build_target are fixed for the scan's lifetime.
    """

    def __init__(self, prompt: str, build_target: str) -> None:
        self.prompt = prompt
        self.build_target = build_target
        self._non_web: Optional[bool] = None
        self._not_webpage: Optional[bool] = None
        self._last_not_website_start: Optional[int] = None
        self._not_website_before_from: Optional[int] = None
        self._low: Optional[str] = None
        self._offsets: Optional[List[int]] = None
        self._starts: List[int] = []
        self._ends: List[int] = []

    def non_web_platform(self) -> bool:
        """bool(_NON_WEB_PLATFORM_RE.search(build_target))"""
        if self._non_web is None:
            self._non_web = bool(_NON_WEB_PLATFORM_RE.search(self.build_target))
        return self._non_web

    def not_a_webpage(self) -> bool:
        """bool(_NOT_A_WEBPAGE_RE.search(prompt))"""
        if self._not_webpage is None:
            self._not_webpage = bool(_NOT_A_WEBPAGE_RE.search(self.prompt))
        return self._not_webpage

    def not_a_website_after(self, k: int) -> bool:
        """bool(_NOT_A_WEBSITE_RE.search(build_target[k:]))"""
        bt = self.build_target
        if _NOT_A_WEBSITE_AT_RE.match(bt, k):
            return True
        if self._last_not_website_start is None:
            last = -1
            for m in _NOT_A_WEBSITE_STARTS_RE.finditer(bt):
                last = m.start()
            self._last_not_website_start = last
        return self._last_not_website_start > k

    def not_a_website_before(self, k: int) -> bool:
        """bool(_NOT_A_WEBSITE_RE.search(build_target[:k]))"""
        bt = self.build_target
        if self._not_website_before_from is not None and k >= self._not_website_before_from:
            return True
        found = _NOT_A_WEBSITE_RE.search(bt, 0, k) is not None  # endpos == slicing
        if found and _follows_boundary(bt, k):
            # Every match ends in a word char, so one inside bt[:k] ends before k and
            # stays a match inside every longer prefix: True from here on.
            self._not_website_before_from = k
        return found

    def _tokens(self) -> str:
        if self._low is None:
            low = self.prompt.lower()
            if len(low) != len(self.prompt):  # a char lowercased to several chars
                offsets = [0]
                total = 0
                for ch in self.prompt:
                    total += len(ch.lower())
                    offsets.append(total)
                self._offsets = offsets
            for m in _WORD_RE.finditer(low):
                self._starts.append(m.start())
                self._ends.append(m.end())
            self._low = low
        return self._low

    def _at(self, k: int) -> int:
        return k if self._offsets is None else self._offsets[k]

    def last_word_before(self, k: int) -> Optional[str]:
        """(_WORD_RE.findall(prompt[:k].lower()) or [None])[-1]; long words -> _LONG_WORD."""
        if not _follows_boundary(self.prompt, k):
            words = _WORD_RE.findall(self.prompt[:k].lower())
            return words[-1] if words else None
        low = self._tokens()
        cut = self._at(k)
        i = bisect.bisect_left(self._starts, cut) - 1
        if i < 0:
            return None
        start, end = self._starts[i], self._ends[i]
        if end > cut:
            # The word runs past the cut; low[cut - 1] is one of its single - or '
            # joiners, and the prefix tokenises its part as low[start:cut - 1].
            end = cut - 1
        return low[start:end] if end - start <= _LONG_WORD_CHARS else _LONG_WORD

    def first_word_after(self, k: int) -> Optional[str]:
        """(_WORD_RE.findall(prompt[k:].lower()) or [None])[0]; long words -> _LONG_WORD."""
        low = self._tokens()
        cut = self._at(k)
        i = bisect.bisect_right(self._starts, cut) - 1
        if i >= 0 and self._ends[i] > cut:
            # Inside a word: the suffix's first word starts at the first [a-z0-9] at or
            # after the cut (a joiner is always followed by one) and ends where it does.
            start = cut if low[cut].isalnum() and low[cut].isascii() else cut + 1
            end = self._ends[i]
        elif i + 1 < len(self._starts):
            start, end = self._starts[i + 1], self._ends[i + 1]
        else:
            return None
        return low[start:end] if end - start <= _LONG_WORD_CHARS else _LONG_WORD


def _bare_word_is_the_thing(scan: _WebsiteScan, start: int, end: int) -> bool:
    """Return True when the bare website word at prompt[start:end] is what is being built."""
    matched = scan.prompt[start:end].strip().lower()
    after = scan.first_word_after(end)
    if matched in {"blog", "blogs"} and after is not None and after in _BLOG_NON_SITE_AFTER:
        return False
    if after is None:
        return True
    before = scan.last_word_before(start)
    if before is not None and before in _BARE_WEBSITE_BEFORE:
        return True
    return after in _BARE_WEBSITE_AFTER


def _bare_page_is_the_thing(scan: _WebsiteScan, start: int, end: int) -> bool:
    """Return True when bare singular 'page' at prompt[start:end] is a web page build target with a purpose clause."""
    if scan.prompt[start:end].strip().lower() != "page":
        return False
    if scan.not_a_webpage():
        return False
    before = scan.last_word_before(start)
    if before is None or before not in _BARE_PAGE_BEFORE:
        return False
    after = scan.first_word_after(end)
    return after is not None and after in _BARE_PAGE_AFTER


def _website_match_is_valid(
    scan: _WebsiteScan,
    phrase: str,
    m: re.Match[str],
    explicit_building: Optional[str],
) -> bool:
    """Return True when a website-family match inside build_target names the thing being built."""
    if scan.non_web_platform():
        return False
    if scan.not_a_website_after(m.end()):
        return False
    if phrase in _ASSET_OR_FEATURE_WEBSITE_PHRASES:
        # Both tests are pure; the constant one goes first so the prefix search only runs
        # when its answer decides the match.
        if explicit_building is not None and explicit_building in _NOT_A_WEBSITE_KINDS:
            return False
        if scan.not_a_website_before(m.start()):
            return False
    if phrase == "page":
        return _bare_page_is_the_thing(scan, m.start(), m.end())
    if phrase.endswith(" page") and scan.not_a_webpage():
        return False
    if phrase in _BARE_WEBSITE_WORDS:
        return _bare_word_is_the_thing(scan, m.start(), m.end())
    return True


def kit_families_in(
    prompt: str,
    *,
    _explicit_building: Optional[str] = None,
) -> dict[str, str]:
    """Return {family tag: first matching phrase} for the family words found in prompt.

    Website words are matched in the primary build-target clause (before any 'for/about/of/where...'
    subject phrase) so subject words do not disqualify or trigger websites. Component-library is
    guarded by both non-code-component and frontend-UI exclusion tables. Only the first
    MAX_MATCH_PROMPT_CHARS characters of prompt are considered.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        return {}
    prompt = _bounded_prompt(prompt)
    if not prompt.strip():
        return {}
    return _kit_families(prompt, _explicit_building, _WebsiteScan(prompt, prompt[: build_target_end(prompt)]))


def _kit_families(prompt: str, _explicit_building: Optional[str], scan: _WebsiteScan) -> dict[str, str]:
    out: dict[str, str] = {}
    build_target = scan.build_target
    not_comp_lib: Optional[bool] = None
    not_godot_game: Optional[bool] = None

    # Pass 1: check website family on the build-target clause first.
    for pat, phrase, tag in _KIT_FAMILY_RES:
        if tag != "website":
            continue
        for m in pat.finditer(build_target):
            if _website_match_is_valid(scan, phrase, m, _explicit_building):
                out["website"] = phrase
                break
        if "website" in out:
            break

    # If the build target is a website, ignore words inside its subject phrase for other kit families.
    other_family_text = mask_website_subject(prompt) if "website" in out else prompt

    for pat, phrase, tag in _KIT_FAMILY_RES:
        if tag == "website" or tag in out:
            continue
        for _m in pat.finditer(other_family_text):
            if tag == "components":
                if not_comp_lib is None:
                    not_comp_lib = bool(
                        _NOT_A_COMPONENT_LIBRARY_RE.search(other_family_text)
                        or _UI_COMPONENT_RE.search(other_family_text)
                    )
                if not_comp_lib:
                    break
            elif tag == "gdscript":
                if not_godot_game is None:
                    not_godot_game = bool(_NOT_A_GODOT_GAME_RE.search(other_family_text))
                if not_godot_game:
                    break
            out[tag] = phrase
            break

    if "components" not in out:
        if not_comp_lib is None:
            not_comp_lib = bool(
                _NOT_A_COMPONENT_LIBRARY_RE.search(other_family_text)
                or _UI_COMPONENT_RE.search(other_family_text)
            )
        if not not_comp_lib:
            words = set(_ALNUM_WORD_RE.findall(other_family_text.lower()))
            if (words & _COMPONENT_QUALIFIER_WORDS) and (words & _COMPONENT_NOUN_WORDS):
                out["components"] = "reusable component"
            elif (
                "python" in words
                and (words & _PYTHON_REUSE_QUALIFIER_WORDS)
                and (words & _PYTHON_CODE_PIECE_WORDS)
            ):
                out["components"] = "reusable python component"

    return out


# --- Family templates ---------------------------------------------------------------------------
# A bundled template whose manifest `tags` include a kit family tag (such as `website`) is a
# *family template*: it is chosen for requests in that family, by the rules below, and never for
# a generic code request that only shares its kind or language.

FAMILY_TAGS: frozenset[str] = frozenset(tag for _phrase, tag in KIT_FAMILY_SYNONYMS)

# Website-family phrases that name an application (accounts, checkout, data) rather than a site
# of pages, and phrases that name a design-handoff workspace. A family template serves only the
# remaining phrases (site, website, landing page, portfolio, blog, docs/static site, web page...).
WEBSITE_APP_PHRASES: frozenset[str] = frozenset(
    {
        "web app", "webapp", "web application", "browser app", "online store", "online shop",
        "online menu", "web store", "web shop", "storefront", "e commerce", "login page",
        "checkout page", "signup page", "contact form", "booking form", "signup form", "sign up",
        "customer portal", "client portal", "member portal", "web portal", "portal", "dashboard",
        "forum", "web frontend", "frontend workspace", "frontend project",
    }
)
WEBSITE_DESIGN_PHRASES: frozenset[str] = frozenset(
    {
        "design token", "design source", "design asset", "design handoff", "handed over design",
        "design to code", "figma",
    }
)

# UI frameworks, CSS frameworks, site generators and site builders. A family template serves a
# request that names one of these only when the template's own `tags` name it too.
SITE_STACK_WORDS: Tuple[str, ...] = (
    "react", "reactjs", "react.js", "next.js", "nextjs", "vue", "vuejs", "vue.js", "nuxt",
    "nuxtjs", "nuxt.js", "svelte", "sveltekit", "angular", "solidjs", "solid.js", "preact",
    "qwik", "astro", "remix", "gatsby", "ember", "htmx", "tailwind", "tailwindcss", "hugo",
    "jekyll", "eleventy", "11ty", "docusaurus", "vitepress", "mkdocs", "wordpress", "drupal",
    "joomla", "ghost", "wix", "squarespace", "webflow", "shopify",
)
_SITE_STACK_RE = re.compile(
    r"(?<![\w.])(" + "|".join(re.escape(w) for w in sorted(SITE_STACK_WORDS, key=len, reverse=True)) + r")(?![\w])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FamilyRequest:
    """What a prompt asks for inside a kit family: the family tag, its kind, named site stacks."""

    family: str
    kind: str  # "site", "app" or "design"
    stacks: frozenset[str]


def family_request(prompt: Optional[str]) -> Optional[FamilyRequest]:
    """Classify a website-family build target as a site, an application, or a design handoff."""
    if not isinstance(prompt, str) or not prompt.strip():
        return None
    prompt = _bounded_prompt(prompt)
    if not prompt.strip():
        return None
    build_target = prompt[: build_target_end(prompt)]
    scan = _WebsiteScan(prompt, build_target)
    if "website" not in _kit_families(prompt, None, scan):
        return None
    phrases: set[str] = set()
    for pat, phrase, tag in _KIT_FAMILY_RES:
        if tag != "website":
            continue
        for m in pat.finditer(build_target):
            if _website_match_is_valid(scan, phrase, m, None):
                phrases.add(phrase)
                break
    if phrases & WEBSITE_DESIGN_PHRASES:
        kind = "design"
    elif phrases & WEBSITE_APP_PHRASES:
        kind = "app"
    else:
        kind = "site"
    stacks = frozenset(m.group(1).lower() for m in _SITE_STACK_RE.finditer(prompt))
    return FamilyRequest(family="website", kind=kind, stacks=stacks)


def template_families(template: Any) -> frozenset[str]:
    """Kit family tags a template carries in its manifest `tags` (empty for most templates)."""
    return frozenset(str(t).lower() for t in (getattr(template, "tags", ()) or ())) & FAMILY_TAGS


def _template_vocabulary(template: Any) -> set[str]:
    """Normalized words of a template's tags, name and summary."""
    text = " ".join(
        [*(str(t) for t in (getattr(template, "tags", ()) or ())), str(getattr(template, "name", "")),
         str(getattr(template, "summary", ""))]
    )
    return {_normalize_kit_word(w) for w in _ALNUM_WORD_RE.findall(text.lower())}


def _family_match(
    template: TemplateSpec,
    answers: Mapping[str, Any],
    request: Optional[FamilyRequest],
    explicit_code: bool,
) -> Optional[Match]:
    """Score a family template for a request, or None when it does not serve that request."""
    families = template_families(template)
    if request is None or request.family not in families or request.kind != "site":
        return None
    template_words = {str(t).lower() for t in template.tags}
    if request.stacks - template_words:
        return None
    building = _str_answer(answers.get("building"))
    if building in _DEFAULT_ONLY_TEMPLATE_KINDS:
        return None
    for key in ("engine", "framework"):
        value = _str_answer(answers.get(key))
        if value is not None and value != "none" and template.engine != value:
            return None
    named = [lang for lang in _list_answer(answers.get("languages")) if lang != "other"]
    if named and not set(named) & set(template.languages):
        return None
    if not named and explicit_code:
        return None  # an untemplated language (java, php...) was named: ask instead
    match = _score_template(template, {**dict(answers), "languages": named})
    if match is None:
        return None
    match.score += 3
    match.reasons.insert(0, f"you asked for a {request.family} ('{request.family}' template)")
    match.family = request.family
    return match


def _kit_outranks_family_template(km: KitMatch, match: Any, vocabulary: Optional[set[str]] = None) -> bool:
    """A kit beats a family template only on its own tags that the template does not describe.

    ``vocabulary`` is ``_template_vocabulary(match.template)``, passed in when checking many kits.
    """
    template = getattr(match, "template", None)
    if template is None:
        return True
    if vocabulary is None:
        vocabulary = _template_vocabulary(template)
    hit_tags = {
        r[len("matches tag '") : -1].lower()
        for r in km.reasons
        if r.startswith("matches tag '") and r.endswith("'")
    }
    return any(_normalize_kit_word(tag) not in vocabulary for tag in hit_tags - FAMILY_TAGS)


def _normalize_kit_word(word: str) -> str:
    """Lowercase word and strip one trailing 's' when longer than 3 characters."""
    w = word.lower()
    if len(w) > 3 and w.endswith("s"):
        return w[:-1]
    return w


def _tokenize_prompt(prompt: str) -> List[str]:
    """Tokenise prompt into distinct normalized alphanumeric words, dropping short words and stopwords."""
    if not isinstance(prompt, str) or not prompt.strip():
        return []
    out: List[str] = []
    seen: set[str] = set()
    for raw in _ALNUM_WORD_RE.findall(prompt.lower()):
        if (len(raw) < 3 and raw not in _SHORT_KIT_WORDS) or raw in _KIT_STOPWORDS:
            continue
        norm = _normalize_kit_word(raw)
        if (len(norm) < 3 and norm not in _SHORT_KIT_WORDS) or norm in _KIT_STOPWORDS:
            continue
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


@dataclass(frozen=True)
class KitInfo:
    """Metadata describing a non-code project kit from a sibling plugin."""

    id: str
    name: str
    summary: str
    tags: Tuple[str, ...]
    version: int

    @classmethod
    def from_dict(cls, data: Any) -> Optional[KitInfo]:
        """Parse a mapping into KitInfo, returning None if required fields or types are invalid."""
        if not isinstance(data, Mapping):
            return None
        kit_id = data.get("id")
        name = data.get("name")
        summary = data.get("summary")
        raw_tags = data.get("tags")
        version = data.get("version")

        if not isinstance(kit_id, str) or not kit_id:
            return None
        if not isinstance(name, str) or not name:
            return None
        if not isinstance(summary, str):
            return None
        if isinstance(version, bool) or not isinstance(version, int):
            return None
        if not isinstance(raw_tags, (list, tuple)):
            return None

        tags: List[str] = []
        for tag in raw_tags:
            if not isinstance(tag, str) or not tag:
                return None
            tags.append(tag)

        return cls(
            id=kit_id,
            name=name,
            summary=summary,
            tags=tuple(tags),
            version=version,
        )


@dataclass
class KitMatch:
    """Ranked project kit match with score and human-readable reasons."""

    kit: KitInfo
    score: int
    reasons: List[str]
    tag_hits: int = 0
    family_hit: bool = False
    id_part_hits: int = field(default=0, compare=False)
    disqualified: bool = field(default=False, compare=False)


def _coerce_kit(entry: Any) -> Optional[KitInfo]:
    """Return a KitInfo from either a KitInfo instance or a dict entry."""
    if isinstance(entry, KitInfo):
        return entry
    return KitInfo.from_dict(entry)


@dataclass(frozen=True)
class KitListResult:
    """A decoded kit list: valid infos, notice, status, and how many entries were skipped."""

    infos: List[KitInfo]
    notice: str
    status: str
    skipped: int = 0


def parse_kit_list_detailed(reply: Any) -> KitListResult:
    """Decode a componentize_bridge.kit_list() reply, counting entries that fail validation.

    Duplicates are kept as they are (not skipped). An ok reply where every entry
    is invalid stays ok with no infos.
    """
    status = str(reply.get("status") if isinstance(reply, Mapping) else "error")
    if status == "ok":
        data = reply.get("data") if isinstance(reply, Mapping) else None
        raw_kits = data.get("kits") if isinstance(data, Mapping) else None
        infos: List[KitInfo] = []
        skipped = 0
        for item in raw_kits or []:
            info = _coerce_kit(item)
            if info is None:
                skipped += 1
            else:
                infos.append(info)
        # Entries the bridge already dropped as malformed count as skipped too.
        dropped = data.get("skipped_kits") if isinstance(data, Mapping) else None
        if type(dropped) is int and dropped > 0:
            skipped += min(dropped, 100_000)
        return KitListResult(infos, "", "ok", skipped)
    raw_notice = reply.get("notice") if isinstance(reply, Mapping) else None
    notice = str(raw_notice).strip() if isinstance(raw_notice, str) else ""
    return KitListResult([], notice or componentize_bridge.UNAVAILABLE_NOTICE, status, 0)


def parse_kit_list(reply: Any) -> Tuple[List[KitInfo], str, str]:
    """Decode a componentize_bridge.kit_list() reply into (infos, notice, status)."""
    res = parse_kit_list_detailed(reply)
    return res.infos, res.notice, res.status


# A negated clause starts at one of these (or at the start of the text) and a
# cue must be the next word. Colon is not a boundary: a mid-sentence "not"
# would hide real content. "!", "?", and newline are sentence ends so the
# following sentence stays positive.
_KIT_TEXT_CLAUSE_STARTS: frozenset[str] = frozenset(
    {";", ",", "(", ".", "!", "?", "\n", "\u2014", "\u2013"}
)
# Strong ends. Commas, "or"/"and"/"nor", and dashes do not end a clause
# ("not a YouTube channel or a comic" excludes both).
_KIT_TEXT_STRONG_ENDS: frozenset[str] = frozenset({";", ".", ")", "!", "?", "\n"})
# Longer cues first. "not only" is not a cue; see _is_not_only.
_KIT_TEXT_NEGATION_CUES: Tuple[str, ...] = (
    "rather than",
    "instead of",
    "not for",
    "not a",
    "not an",
    "not",
    "never",
    "no",
    "unlike",
    "excluding",
    "except",
    "without",
)


def _kit_text_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


# Next clause start (or spaced hyphen) and next strong end, for positive_kit_text's jumps.
_KIT_TEXT_BOUNDARY_RE = re.compile(r"[;,(.!?\n\u2014\u2013]|(?<= )-(?= )")
_KIT_TEXT_STRONG_END_RE = re.compile(r"[;.)!?\n]")
_NON_SPACE_RE = re.compile(r"\S")


def _match_cue_phrase(text: str, start: int, cue: str) -> Optional[int]:
    """Return the index just after cue at start, allowing flexible whitespace."""
    i = start
    n = len(text)
    for part_i, part in enumerate(cue.split(" ")):
        if part_i:
            if i >= n or not text[i].isspace():
                return None
            i = _skip_whitespace(text, i)
        for ch in part:
            if i >= n or text[i].lower() != ch:
                return None
            i += 1
    return i


def _is_not_only(text: str, start: int) -> bool:
    """Return True when text[start:] is the positive phrase 'not only'."""
    if start + 3 > len(text) or text[start : start + 3].lower() != "not":
        return False
    after_not = start + 3
    if after_not < len(text) and (
        _kit_text_word_char(text[after_not]) or text[after_not] == "-"
    ):
        return False
    i = after_not
    if i >= len(text) or not text[i].isspace():
        return False
    while i < len(text) and text[i].isspace():
        i += 1
    if i + 4 > len(text) or text[i : i + 4].lower() != "only":
        return False
    after_only = i + 4
    return after_only >= len(text) or not (
        _kit_text_word_char(text[after_only]) or text[after_only] == "-"
    )


def _match_kit_negation_cue(text: str, start: int) -> Optional[int]:
    """Return the index just after a whole-word negation cue at start, or None."""
    if _is_not_only(text, start):
        return None
    n = len(text)
    for cue in _KIT_TEXT_NEGATION_CUES:
        end = _match_cue_phrase(text, start, cue)
        if end is None:
            continue
        if end < n and (_kit_text_word_char(text[end]) or text[end] == "-"):
            continue
        return end
    return None


def positive_kit_text(text: str) -> str:
    """Blank negated clauses in a kit name or summary; leave everything else unchanged.

    A clause starts at the start of the text or after ``;``, ``,``, ``(``,
    ``.``/``!``/``?``, a newline, an em/en dash, or `` - ``, when the next word
    is a cue (``not``, ``not for``, ``not a``/``an``, ``never``, ``no``,
    ``rather than``, ``instead of``, ``unlike``, ``excluding``, ``except``,
    ``without``). It runs to the next ``;``, ``.``, ``)``, ``!``, ``?``,
    newline, or end of text. Commas and ``or``/``and``/``nor`` stay inside.
    ``not only ... but also``, hyphenated ``no-code``, and words containing
    ``not``/``no`` are not cues. A cue that is not at a clause boundary is
    left alone. Tags must not be passed here.
    """
    if not text:
        return text
    n = len(text)
    spans: List[Tuple[int, int]] = []
    i = 0
    at_boundary = True
    while i < n:
        if at_boundary:
            j = _skip_whitespace(text, i)
            if j >= n:
                break
            cue_end = _match_kit_negation_cue(text, j)
            if cue_end is not None:
                strong = _KIT_TEXT_STRONG_END_RE.search(text, cue_end)
                k = strong.start() if strong else n
                spans.append((j, k))
                if k >= n:
                    break
                i = k + 1
                at_boundary = text[k] in _KIT_TEXT_CLAUSE_STARTS
                continue
            i = j
            at_boundary = False
            continue
        # Jump to the next clause start, or a hyphen with a space on each side.
        boundary = _KIT_TEXT_BOUNDARY_RE.search(text, i)
        if boundary is None:
            break
        i = boundary.start() + (2 if text[boundary.start()] == "-" else 1)
        at_boundary = True
    if not spans:
        return text
    pieces: List[str] = []
    pos = 0
    for start, end in spans:
        pieces.append(text[pos:start])
        pieces.append(_NON_SPACE_RE.sub(" ", text[start:end]))
        pos = end
    pieces.append(text[pos:])
    return "".join(pieces)


def _norm_index(words: Iterable[str], *, min_len: int = 3) -> dict[str, str]:
    """Map normalized kit words to their first seen canonical token."""
    out: dict[str, str] = {}
    for w in words:
        if len(w) >= min_len or w in _SHORT_KIT_WORDS:
            nw = _normalize_kit_word(w)
            if nw and nw not in out:
                out[nw] = w
    return out


def match_kits(
    kits: Sequence[Any],
    prompt: str,
    answers: Optional[Mapping[str, Any]] = None,
    *,
    min_score: int = 3,
) -> List[KitMatch]:
    """Rank project kits against a natural-language prompt and optional questionnaire answers.

    Hard bounds (see the module docstring): only the first MAX_MATCH_PROMPT_CHARS characters
    of prompt, the first MAX_KITS_SCORED entries of kits, and the first
    MAX_KIT_NAME_CHARS / MAX_KIT_SUMMARY_CHARS characters of each kit's name / summary
    are read.
    """
    if isinstance(prompt, str):
        prompt = _bounded_prompt(prompt)
    tokens = _tokenize_prompt(prompt)
    families = kit_families_in(prompt)
    non_subject_tokens = (
        _tokenize_prompt(mask_website_subject(prompt))
        if "website" in families
        else tokens
    )
    has_prompt = bool(isinstance(prompt, str) and prompt.strip())
    build_target = prompt[: build_target_end(prompt)] if has_prompt else ""
    web_excluded = (
        has_prompt
        and "website" not in families
        and bool(_NON_WEB_PLATFORM_RE.search(build_target) or _NOT_A_WEBSITE_RE.search(build_target))
    )
    ui_comp_excluded = has_prompt and bool(_UI_COMPONENT_RE.search(prompt))
    comp_excluded = has_prompt and bool(_NOT_A_COMPONENT_LIBRARY_RE.search(prompt))
    godot_excluded = has_prompt and bool(_NOT_A_GODOT_GAME_RE.search(prompt))
    building = _str_answer(answers.get("building")) if isinstance(answers, Mapping) else None
    building_tag_targets = _BUILDING_KIT_TAGS.get(building) if building is not None else None

    if not tokens and building_tag_targets is None:
        return []

    norm_target_tags = (
        {_normalize_kit_word(t) for t in building_tag_targets}
        if building_tag_targets is not None
        else set()
    )
    # Token -> position, so each kit is scored from its own (bounded) words instead of
    # testing every prompt token against every kit. Tokens are distinct.
    token_pos = {tok: i for i, tok in enumerate(tokens)}
    non_subject_pos = (
        token_pos
        if non_subject_tokens is tokens
        else {tok: i for i, tok in enumerate(non_subject_tokens)}
    )

    matches: List[KitMatch] = []
    for raw_kit in itertools.islice(kits, MAX_KITS_SCORED):
        kit = _coerce_kit(raw_kit)
        if kit is None:
            continue
        if kit.id == "component-library" and ui_comp_excluded:
            continue

        raw_kit_tags = {t.strip().lower() for t in kit.tags}
        use_non_subject = "website" in families and "website" not in raw_kit_tags
        kit_tokens = non_subject_tokens if use_non_subject else tokens
        kit_token_pos = non_subject_pos if use_non_subject else token_pos

        score = 0
        reasons: List[str] = []

        norm_tags = _norm_index((t.strip() for t in kit.tags), min_len=1)
        norm_id_parts = _norm_index(kit.id.lower().split("-"))
        norm_name_words = _norm_index(
            _ALNUM_WORD_RE.findall(positive_kit_text(kit.name[:MAX_KIT_NAME_CHARS]).lower())
        )
        norm_summary_words = _norm_index(
            _ALNUM_WORD_RE.findall(positive_kit_text(kit.summary[:MAX_KIT_SUMMARY_CHARS]).lower())
        )

        id_part_hits = 0
        tag_hits = 0
        building_boost = False

        # Only tokens found in one of the kit's word indexes can score; visit exactly
        # those, in prompt-token order, which is the order the reasons are listed in.
        hit_positions = {
            pos
            for index in (norm_tags, norm_id_parts, norm_name_words, norm_summary_words)
            for word in index
            if (pos := kit_token_pos.get(word)) is not None
        }
        for tok in (kit_tokens[pos] for pos in sorted(hit_positions)):
            if tok in norm_id_parts:
                id_part_hits += 1
            if tok in norm_tags:
                tag_hits += 1
                score += 3
                reasons.append(f"matches tag '{norm_tags[tok]}'")
            elif tok in norm_id_parts:
                score += 2
                reasons.append(f"matches id part '{norm_id_parts[tok]}'")
            elif tok in norm_name_words:
                score += 1
                reasons.append(f"matches name word '{norm_name_words[tok]}'")
            elif tok in norm_summary_words:
                score += 1
                reasons.append(f"matches summary word '{norm_summary_words[tok]}'")

        family_hit = False
        if families:
            for family_tag, phrase in families.items():
                if family_tag in raw_kit_tags:
                    # A named everyday word for this kit's kind is a strong, deliberate signal.
                    family_hit = True
                    score += STRONG_KIT_SCORE
                    reasons.append(f"you asked for a {phrase} ('{family_tag}' kit)")
                    break

        if building is not None and building_tag_targets is not None:
            raw_kit_tags_lower = {t.lower() for t in kit.tags}
            if (raw_kit_tags_lower & building_tag_targets) or (set(norm_tags.keys()) & norm_target_tags):
                building_boost = True
                score += 3
                reasons.append(f"you said you are making {building}")

        if not isinstance(prompt, str) or not prompt.strip():
            # Questionnaire path with no idea text: only answers['building'] is known,
            # so the building-kind boost alone qualifies the kit.
            qualifies = building_boost
        elif family_hit:
            qualifies = True
        elif building_boost:
            qualifies = id_part_hits >= 1 or tag_hits >= 1
        else:
            qualifies = id_part_hits >= 1 or tag_hits >= 2
        if score >= min_score and qualifies:
            is_disq = (
                (kit.id == "web-app" and web_excluded)
                or (kit.id == "component-library" and comp_excluded)
                or (kit.id == "godot-game" and godot_excluded)
            )
            matches.append(
                KitMatch(
                    kit=kit,
                    score=score,
                    reasons=reasons,
                    tag_hits=tag_hits,
                    family_hit=family_hit,
                    id_part_hits=id_part_hits,
                    disqualified=is_disq,
                )
            )

    matches.sort(key=lambda m: (-m.score, -int(m.family_hit), -m.id_part_hits, m.kit.id))
    return matches


STRONG_KIT_SCORE: int = 6

# Kits whose engine+kind tags ('unreal' + 'game') can reach STRONG_KIT_SCORE on a plain
# game request: require at least one asset/DCC tag from the kit before auto-selecting it.
KIT_STRONG_REQUIRED_TAGS: Mapping[str, frozenset[str]] = {
    "game-assets": frozenset({"assets", "blender", "houdini", "lfs"}),
}


def _kit_is_strong(km: KitMatch) -> bool:
    """Return True when a KitMatch is strong enough to auto-select without a kit building kind."""
    if km.disqualified or km.score < STRONG_KIT_SCORE:
        return False
    required = KIT_STRONG_REQUIRED_TAGS.get(km.kit.id)
    if required is not None:
        if not any(f"matches tag '{tag}'" in km.reasons for tag in required):
            return False
    return True

# Kinds whose language prefill (rust/gdscript) exists to pick a game engine, not a
# template: a template of another kind must not win for them on defaults alone.
_DEFAULT_ONLY_TEMPLATE_KINDS: frozenset[str] = frozenset({"game", "studio"})


def _template_fits_kind(match: Any, building: str) -> bool:
    """Return True when a template match's kind fits the requested building kind."""
    template = getattr(match, "template", None)
    kind = getattr(template, "kind", None)
    if kind == building:
        return True
    return building == "studio" and kind == "game" and getattr(template, "layout", None) == "poly"


def _kits_tied_at_top(kit_matches: Sequence[KitMatch]) -> bool:
    """Return True when the top two kits from distinct domains tie on score, family, and ID hits."""
    if len(kit_matches) < 2:
        return False
    top, runner_up = kit_matches[0], kit_matches[1]
    if (
        top.score != runner_up.score
        or top.family_hit != runner_up.family_hit
        or top.id_part_hits != runner_up.id_part_hits
    ):
        return False
    if top.kit.id.split("-")[0] == runner_up.kit.id.split("-")[0]:
        return False
    if top.tag_hits == 0 and not top.family_hit and all(
        r.startswith("you said you are making ") for r in top.reasons
    ):
        return False
    return True


def choose_catalog_entry(
    template_matches: Sequence[Any],
    kit_matches: Sequence[KitMatch],
    answers: Optional[Mapping[str, Any]] = None,
    *,
    explicit_code: bool = False,
) -> Tuple[str, Any]:
    """Choose between ranked template matches and kit matches based on answers.

    Both ``template_matches`` and ``kit_matches`` must already be ranked best-first.
    When two prompt-matched kits tie at the top, or when a kit and a template tie at
    ``>= STRONG_KIT_SCORE`` without a decisive kit signal, return ``('none', None)`` so
    the caller asks instead of guessing alphabetically.
    """
    building = _str_answer(answers.get("building")) if isinstance(answers, Mapping) else None
    if building in KIT_BUILDING_KINDS and kit_matches:
        if _kits_tied_at_top(kit_matches):
            return ("none", None)
        return ("kit", kit_matches[0])

    if explicit_code and _names_only_other_language(answers or {}):
        # The prompt named a language with no template (e.g. java): ask, never a kit
        # or another language's template.
        return ("none", None)

    if (
        template_matches
        and not explicit_code
        and building in _DEFAULT_ONLY_TEMPLATE_KINDS
        and not any(_template_fits_kind(m, building) for m in template_matches)
    ):
        # No language or engine was named and no template is of this kind: the template
        # matched only on filled-in defaults (layout, prefilled language), so ignore it.
        template_matches = []

    if template_matches:
        if not explicit_code:
            top_family = getattr(template_matches[0], "family", None)
            strong_kits = [
                km
                for km in kit_matches
                if _kit_is_strong(km) and (km.tag_hits >= 2 or km.family_hit)
            ]
            if top_family:
                # A family template serves its family's site requests; a kit of the same
                # family wins only on its own tags the template does not describe.
                top_template = getattr(template_matches[0], "template", None)
                vocabulary = (
                    _template_vocabulary(top_template) if strong_kits and top_template is not None else None
                )
                strong_kits = [
                    km for km in strong_kits if _kit_outranks_family_template(km, template_matches[0], vocabulary)
                ]
            if strong_kits:
                if _kits_tied_at_top(strong_kits):
                    return ("none", None)
                return ("kit", strong_kits[0])
            tmpl_score = getattr(template_matches[0], "score", None)
            if (
                not top_family
                and kit_matches
                and isinstance(tmpl_score, int)
                and _kit_is_strong(kit_matches[0])
                and kit_matches[0].score == tmpl_score
            ):
                return ("none", None)
        return ("template", template_matches[0])

    viable_kits = [km for km in kit_matches if _kit_is_strong(km)]
    if viable_kits:
        if _kits_tied_at_top(viable_kits):
            return ("none", None)
        return ("kit", viable_kits[0])
    return ("none", None)
