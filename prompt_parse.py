"""Deterministic free-text project prompt parser."""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from .naming import PrefixForms, forms_from_slug, slugify
from .questionnaire import (
    KIT_BUILDING_KINDS,
    QUESTIONS,
    is_kit_kind,
    prefill,
    validate_answer,
)

# Longest prompt, in characters (len() of the str passed in, before stripping), that the
# parser accepts. A project idea is a sentence or a short paragraph (the routing fixtures
# stay under 100 characters); 2048 characters is about 300 words. Longer input raises
# PromptTooLongError at once, before any regex runs. This parser's own work is linear
# in the prompt, but the matcher.py helpers it calls (kit_families_in, build_target_end,
# mask_website_subject) still rescan prefixes per match, about 0.3 s at this cap on
# their worst inputs and 4x that per doubling, so raise the cap only after they are linear.
MAX_PROMPT_CHARS = 2048


class PromptTooLongError(ValueError):
    """Raised when a prompt is longer than MAX_PROMPT_CHARS characters."""

    def __init__(self, length: int, limit: int = MAX_PROMPT_CHARS) -> None:
        super().__init__(
            f"Prompt is too long: {length} characters (limit {limit}). "
            "Describe the project in a sentence or a short paragraph."
        )
        self.length = length
        self.limit = limit


_VALID_QUESTION_IDS: frozenset[str] = frozenset(q.id for q in QUESTIONS)
_ALLOWED_LLM_KEYS: frozenset[str] = _VALID_QUESTION_IDS | {"name", "answers"}

# Ordered engine patterns: (regex, engine_id, implied_language)
_ENGINE_PATTERNS: Tuple[Tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\bgodot\b", re.IGNORECASE), "godot", "gdscript"),
    (re.compile(r"\bbevy\b", re.IGNORECASE), "bevy", "rust"),
    (re.compile(r"\bunity\b", re.IGNORECASE), "unity", "csharp"),
    (re.compile(r"\b(?:unreal(?:\s+engine)?|ue[45])\b", re.IGNORECASE), "unreal", "cpp"),
)

# Game libraries and native GUI frameworks that have no Defuzz template: imply a language for
# closest-template hints while setting answers['framework'] so routing asks instead of guessing.
_UNTEMPLATED_FRAMEWORK_PATTERNS: Tuple[Tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\bpygame\b", re.IGNORECASE), "pygame", "python"),
    (re.compile(r"\bqt[56]?\b", re.IGNORECASE), "qt", "cpp"),
    (re.compile(r"\bsdl[23]?\b", re.IGNORECASE), "sdl", "cpp"),
    (re.compile(r"\bsfml\b", re.IGNORECASE), "sfml", "cpp"),
    (re.compile(r"\bmonogame\b", re.IGNORECASE), "monogame", "csharp"),
    (re.compile(r"\bphaser\b", re.IGNORECASE), "phaser", "typescript"),
    (re.compile(r"\b(?:love2d|defold|gamemaker)\b", re.IGNORECASE), "other_engine", "other"),
    (re.compile(r"\braylib\b", re.IGNORECASE), "raylib", ""),
)

# Explicitly named programming languages and runtimes; ordered by match position when scanning.
_LANGUAGE_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?<!\bthree\.)\b(?:typescript|tsx|jsx|ts|node\.?js|nodejs|node|javascript|js)\b",
            re.IGNORECASE,
        ),
        "typescript",
    ),
    (
        re.compile(r"\b(?:rustlang|rust)\b", re.IGNORECASE),
        "rust",
    ),
    (
        re.compile(r"\b(?:python3?|py)\b", re.IGNORECASE),
        "python",
    ),
    (
        re.compile(
            r"\b(?:golang)\b|(?:(?<=^)|(?<=[\s\-\u2013\u2014,/(]))go(?=$|[\s\-\u2013\u2014,/)!?.])",
            re.IGNORECASE,
        ),
        "go",
    ),
    (
        re.compile(
            r"(?:(?<!\w)\.net\b(?<!\basp\.net)|(?<!\w)dotnet\b|\bc#|\bcsharp\b)",
            re.IGNORECASE,
        ),
        "csharp",
    ),
    (
        re.compile(r"(?:\bc\+\+|\bcpp\b)", re.IGNORECASE),
        "cpp",
    ),
    (
        re.compile(r"\bgdscript\b", re.IGNORECASE),
        "gdscript",
    ),
    (
        # Common languages with no template: they count only as 'a language was named'
        # (answer 'other'), so the request asks instead of picking a kit or another template.
        re.compile(
            r"\b(?:java|kotlin|php|ruby|swift|scala|elixir|erlang|haskell|perl|lua|clojure|ocaml|zig)\b",
            re.IGNORECASE,
        ),
        "other",
    ),
)

# Libraries, frameworks, and build tools that imply a language for non-kit, non-website requests
# without overriding a strong project kit or website build target.
_IMPLIED_LANGUAGE_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:express(?:js)?|next\.?js|vite|deno|bun|hono|fastify|react|vue(?:\.?js)?|svelte(?:kit)?|nuxt(?:\.?js)?|nest\.?js)\b"
            r"|(?:(?<=\bin\s)|(?<=\bwith\s)|(?<=\busing\s))next\b"
            r"(?!\s+(?:week|month|year|day|time|step|level|gen|generation|project|game|app|video|book|chapter|round|season|summer|winter|spring|fall)\b)",
            re.IGNORECASE,
        ),
        "typescript",
    ),
    (
        re.compile(r"\b(?:cargo|tokio|axum)\b", re.IGNORECASE),
        "rust",
    ),
    (
        re.compile(
            r"\b(?:fastapi|flask|django|pydantic|tkinter|pyqt[56]?|pyside[26]?)\b",
            re.IGNORECASE,
        ),
        "python",
    ),
    (
        re.compile(r"\b(?:gin(?!\s+rummy\b)|cobra)\b", re.IGNORECASE),
        "go",
    ),
    (
        re.compile(r"\b(?:asp\.?net|blazor)\b", re.IGNORECASE),
        "csharp",
    ),
)

# Building kind patterns: (regex, canonical_building_kind)
_BUILDING_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:game\s+studio|studio\s+of\s+(?:several\s+)?games|multi[-\s]?game\s+studio|studios?)\b",
            re.IGNORECASE,
        ),
        "studio",
    ),
    (
        re.compile(
            r"\b(?:video\s+games?|games?|rpg|platformers?|roguelikes?|metroidvanias?|shooters?|arcade|visual\s+novels?|tower\s+defen[cs]e|card\s+battlers?|dungeon\s+crawlers?|bullet\s+hell|breakout|pygame|raylib|love2d|phaser|monogame|gamemaker|defold)\b",
            re.IGNORECASE,
        ),
        "game",
    ),
    (
        re.compile(
            r"\b(?:rest\s+apis?|graphql\s+apis?|http\s+apis?|web\s+apis?|api\s+services?|backend\s+services?|micro[-\s]?services?|web\s+services?|apis?|services?|backends?|servers?|webhooks?|daemons?|workers?)\b",
            re.IGNORECASE,
        ),
        "service",
    ),
    (
        re.compile(
            r"\b(?:cli\s+tools?|command[-\s]+line\s+tools?|command[-\s]+line|clis?|(?<!\bmulti-)tools?|utilities|utility|linters?|formatters?)\b",
            re.IGNORECASE,
        ),
        "tool",
    ),
    (
        re.compile(
            r"\b(?:3d\s+(?:asset\s+(?:libraries|library|packs?)|assets?)|asset\s+libraries|asset\s+library|asset\s+packs?|model\s+libraries|model\s+library|(?:(?:blender|houdini)\s+(?:3d\s+)?(?:asset\s+(?:libraries|library|packs?)|model\s+(?:libraries|library)|assets?|models?))|kitbash(?:ing|ed)?)\b",
            re.IGNORECASE,
        ),
        "assets",
    ),
    (
        re.compile(
            r"\b(?:libraries|library|libs?|sdks?|crates?|packages?)\b",
            re.IGNORECASE,
        ),
        "library",
    ),
    (
        re.compile(
            r"\b(?:desktop\s+apps?|web\s+apps?|mobile\s+apps?|webapps?|applications?|apps?|dashboards?|frontends?)\b",
            re.IGNORECASE,
        ),
        "app",
    ),
    (
        re.compile(
            r"\b(?:video\s+productions?|music\s+videos?|short\s+films?|vfx\s+shots?|videos?(?!\s+games?\b)|films?|movies?|storyboards?|animatics?|animations?|footage|trailers?|tv\s+commercials?|commercial\s+spots?|commercial\s+shoots?|ad\s+spots?)\b",
            re.IGNORECASE,
        ),
        "video",
    ),
    (
        re.compile(
            r"\b(?:image\s+sets?|concept\s+art|art\s+packs?|photo\s+sets?|illustrations?|artworks?|images?|photos?|comics?|posters?)\b",
            re.IGNORECASE,
        ),
        "images",
    ),
)

_CODE_CONTEXT_RE = re.compile(
    r"\b(?:websites?|web\s+sites?|webapps?|web\s+apps?|saas|apis?|backends?|back\s+ends?|frontends?|front\s+ends?|clis?|sdks?|plugins?|extensions?|bots?|servers?|databases?|microservices?|scripts?|packages?|crates?|modules?|frameworks?)\b",
    re.IGNORECASE,
)

_EXPLICIT_CODE_KIND_PHRASE_RE = re.compile(
    r"\b(?:cli\s+tools?|command[-\s]+line\s+tools?|libraries|library|sdks?|services?|backends?|apis?)\b",
    re.IGNORECASE,
)

# Openers that are always chat/questions rather than new-project requests, even when
# followed by a technology noun like 'server' or 'tool'.
_UNCONDITIONAL_NON_PROJECT_OPENERS: Tuple[str, ...] = (
    "summarize",
    "summarise",
    "explain",
    "proofread",
    "critique",
    "paraphrase",
    "troubleshoot",
    "diagnose",
    "what is",
    "what are",
    "what's",
    "whats",
    "what does",
    "difference between",
    "how do i",
    "how can i",
    "how does",
    "how to",
    "why is",
    "why are",
    "why does",
    "why do",
    "list the",
    "write a poem",
    "draft an email",
    "tell me",
    "walk me through",
)

# Openers that are non-project imperatives unless modifying a project noun ('review tool').
_GUARDED_NON_PROJECT_OPENERS: Tuple[str, ...] = (
    "rename",
    "convert",
    "compare",
    "review",
    "fix",
    "debug",
    "translate",
    "refactor",
)

_NON_PROJECT_OPENERS: Tuple[str, ...] = (
    _UNCONDITIONAL_NON_PROJECT_OPENERS + _GUARDED_NON_PROJECT_OPENERS
)

# Conversational lead-ins permitted before non-project question or imperative openers.
_POLITE_NON_PROJECT_PREFIX = (
    r"^\s*(?:(?:hey|hi|hello)\b[,\s]*)?"
    r"(?:(?:can|could|would|will)\s+(?:you|u)\s+)?"
    r"(?:(?:please|plz|pls)\s+)?"
    r"(?:(?:help\s+(?:me\s+)?(?:to\s+)?)|(?:i\s+(?:want|wanna|need|would\s+like)\s+to\s+))?"
)

_NON_PROJECT_OPENER_RE = re.compile(
    _POLITE_NON_PROJECT_PREFIX
    + r"(?:(?:"
    + "|".join(
        re.escape(op).replace(r"\ ", r"\s+") for op in _UNCONDITIONAL_NON_PROJECT_OPENERS
    )
    + r")\b|(?:"
    + "|".join(
        re.escape(op).replace(r"\ ", r"\s+") for op in _GUARDED_NON_PROJECT_OPENERS
    )
    + r")\b(?!\s+(?:tools?|services?|apps?|applications?|libraries|library|sdks?|clis?|apis?|servers?|bots?|plugins?|workspaces?|projects?)\b))",
    re.IGNORECASE,
)

# Technology comparison queries ('godot vs unity', 'pros and cons of X') that ask for advice, not scaffolding.
_COMPARISON_QUERY_RE = re.compile(
    r"\b(?:pros\s+and\s+cons\s+of|comparison\s+(?:of|between)|difference\s+between)\b"
    r"|^\s*(?:[a-z0-9.+_#-]+\s+){1,3}(?:vs\.?|versus)\s+[a-z0-9.+_#-]+",
    re.IGNORECASE,
)

# Written prose artifacts (posts, articles, messages, summaries, tutorials) that are not scaffolded projects.
PROSE_ARTIFACT_WORDS: Tuple[str, ...] = (
    "blog post",
    "blog entry",
    "blog article",
    "guest post",
    "linkedin post",
    "reddit post",
    "forum post",
    "social post",
    "social media post",
    "substack post",
    "tweet",
    "twitter thread",
    "tweet thread",
    "email",
    "e-mail",
    "cover letter",
    "press release",
    "newsletter issue",
    "article",
    "essay",
    "summary",
    "executive summary",
    "tutorial",
    "tutorial text",
    "walkthrough",
    "explainer",
    "poem",
    "haiku",
    "wiki page",
    "man page",
)

# Contextual prose words ('post', 'report', 'thread', 'letter', 'guide') that mean prose when authored or topical.
_CONTEXTUAL_PROSE_WORDS: Tuple[str, ...] = (
    "post",
    "report",
    "thread",
    "letter",
    "guide",
)

# Verbs that frame a prose noun as writing text ('write a post', 'draft a report').
_PROSE_WRITE_VERB_RE = re.compile(
    r"\b(?:write|writing|draft|drafting|compose|composing|author|pen)\b",
    re.IGNORECASE,
)

# Academic and multi-artifact workspace words that distinguish the research-writing kit from one-shot prose.
_RESEARCH_ACADEMIC_WORDS: Tuple[str, ...] = (
    "citations",
    "citation",
    "bibtex",
    "outlines",
    "outline",
    "section draft",
    "section drafts",
    "reading note",
    "reading notes",
    "synthesis note",
    "synthesis notes",
    "literature",
    "dissertation",
    "thesis",
    "figures",
)
_RESEARCH_ACADEMIC_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in _RESEARCH_ACADEMIC_WORDS) + r")\b",
    re.IGNORECASE,
)

# Workspace container words in the build target that mark a multi-file project setup rather than one-shot prose.
_WORKSPACE_SETUP_RE = re.compile(
    r"\b(?:workspace|scaffold|set\s+up|setup|repo|repository|folder)\b",
    re.IGNORECASE,
)

# Software/project head nouns that turn a preceding prose word into a modifier ('blog post summarizer script').
_PROJECT_HEAD_NOUNS: Tuple[str, ...] = (
    "tool",
    "tools",
    "utility",
    "utilities",
    "cli",
    "clis",
    "script",
    "scripts",
    "app",
    "apps",
    "application",
    "applications",
    "service",
    "services",
    "api",
    "apis",
    "server",
    "servers",
    "bot",
    "bots",
    "scraper",
    "crawler",
    "generator",
    "summarizer",
    "summariser",
    "archiver",
    "parser",
    "formatter",
    "linter",
    "scheduler",
    "sender",
    "delivery",
    "client",
    "sdk",
    "library",
    "libraries",
    "plugin",
    "extension",
    "engine",
    "cms",
    "website",
    "site",
    "portal",
    "dashboard",
    "pipeline",
    "queue",
    "worker",
    "daemon",
)
_PROJECT_HEAD_NOUN_RE = re.compile(
    r"\b(?:" + "|".join(_PROJECT_HEAD_NOUNS) + r")\b",
    re.IGNORECASE,
)

_PROSE_ARTIFACT_RE = re.compile(
    r"\b(?:"
    + "|".join(r"[-\s]+".join(map(re.escape, re.split(r"[-\s]+", w))) for w in PROSE_ARTIFACT_WORDS)
    + r")s?\b",
    re.IGNORECASE,
)
_CONTEXTUAL_PROSE_RE = re.compile(
    r"\b(?:" + "|".join(_CONTEXTUAL_PROSE_WORDS) + r")s?\b",
    re.IGNORECASE,
)
_TOPICAL_PROSE_FOLLOW_RE = re.compile(
    r"^\s*(?:about|on|to|asking|announcing|explaining|why)\b",
    re.IGNORECASE,
)


# Determiners and topic participles that separate a prose noun from a later object noun phrase
# ('tweet announcing our new website' vs compound noun 'tweet archiver cli').
_PROSE_OBJECT_BREAK_RE = re.compile(
    r"\b(?:a|an|the|my|our|your|this|these|how|why|when|what|"
    r"announcing|explaining|covering|describing|discussing|regarding|asking|reviewing|comparing)\b",
    re.IGNORECASE,
)


# _TOPICAL_PROSE_FOLLOW_RE without '^', for .match(text, pos) at a prose word's end.
_TOPICAL_PROSE_FOLLOW_AT_RE = re.compile(
    r"\s*(?:about|on|to|asking|announcing|explaining|why)\b",
    re.IGNORECASE,
)


def _has_project_head_noun_after(tail: str) -> bool:
    """Return True when tail has a software/project head noun in the same noun phrase.

    Only the first head noun can qualify: a break word before it is also before every
    later one (both patterns match whole words and a head noun starts after a non-word
    character), so one search over that prefix decides, in time linear in tail.
    """
    pm = _PROJECT_HEAD_NOUN_RE.search(tail)
    return pm is not None and not _PROSE_OBJECT_BREAK_RE.search(tail, 0, pm.start())


class _HeadNounIndex:
    """Answer _has_project_head_noun_after(head[off:]) for prose-word ends off in O(log n).

    Valid for an off that ends a whole-word match (a word character before it, so a
    non-word character or the end at it): there the whole-word matches of head[off:] are
    exactly those of head that start at or after off.
    """

    def __init__(self, head: str) -> None:
        self._head = head
        self._nouns: Optional[List[int]] = None
        self._breaks: List[int] = []

    def after(self, off: int) -> bool:
        if self._nouns is None:  # built on first use: most prompts have no prose word
            self._nouns = [m.start() for m in _PROJECT_HEAD_NOUN_RE.finditer(self._head)]
            self._breaks = [m.start() for m in _PROSE_OBJECT_BREAK_RE.finditer(self._head)]
        i = bisect_left(self._nouns, off)
        if i == len(self._nouns):
            return False
        j = bisect_left(self._breaks, off)
        return j == len(self._breaks) or self._breaks[j] >= self._nouns[i]


def _is_non_project_request(raw_prompt: str) -> bool:
    """Return True when raw_prompt asks to explain/fix/compare or write prose rather than scaffold a project."""
    if not raw_prompt:
        return False
    if _NON_PROJECT_OPENER_RE.match(raw_prompt) or _COMPARISON_QUERY_RE.search(raw_prompt):
        return True
    if _RESEARCH_ACADEMIC_RE.search(raw_prompt):
        return False

    from .matcher import build_target_end

    head = raw_prompt[: build_target_end(raw_prompt)]
    if _WORKSPACE_SETUP_RE.search(head):
        return False

    # Linear form: no per-match slices of head; every query is answered from match indexes.
    index = _HeadNounIndex(head)
    for m in _PROSE_ARTIFACT_RE.finditer(head):
        if index.after(m.end()):
            continue
        return True

    first_verb: Optional[re.Match[str]] = None
    verb_searched = False
    for m in _CONTEXTUAL_PROSE_RE.finditer(head):
        if index.after(m.end()):
            continue
        if not verb_searched:
            first_verb, verb_searched = _PROSE_WRITE_VERB_RE.search(head), True
        # A whole-word verb inside head[:m.start()] is one that starts before m.
        if (first_verb is not None and first_verb.start() < m.start()) or (
            _TOPICAL_PROSE_FOLLOW_AT_RE.match(raw_prompt, m.end())
        ):
            return True
    return False

# Layout patterns: (regex, canonical_layout)
_LAYOUT_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:poly[-\s]?repos?|multi[-\s]?repos?|several\s+repos?|multiple\s+repos?)\b",
            re.IGNORECASE,
        ),
        "poly",
    ),
    (
        re.compile(
            r"\b(?:mono[-\s]?repos?|workspaces?)\b",
            re.IGNORECASE,
        ),
        "mono",
    ),
    (
        re.compile(
            r"\b(?:single[-\s]?repos?|single\s+projects?)\b",
            re.IGNORECASE,
        ),
        "single",
    ),
)

_EXPLICIT_NAME_RE = re.compile(
    r"""(?:\b(?:called|named)\s+["']?([A-Za-z][A-Za-z0-9 _-]{1,60})["']?)|(?:["']([A-Za-z][A-Za-z0-9 _-]{1,60})["'])""",
    re.IGNORECASE,
)

_LEADING_FILLER_RE = re.compile(
    r"^(?:please\s+)?(?:(?:i\s+(?:want|need|would\s+like)\s+(?:to\s+)?(?:build|make|create|start|scaffold|write|set\s+up)\s+)|(?:build|create|make|start|scaffold|write|set\s+up)\s+(?:me\s+)?)?(?:a\s+new|an|a|the|my|our|new)\b\s*",
    re.IGNORECASE,
)

_LANG_INTRO_RE = re.compile(
    r"\b(?:written\s+in|built\s+with|built\s+in|powered\s+by|using|in|with)\s*$",
    re.IGNORECASE,
)

_EDGE_STOPWORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "the",
        "my",
        "our",
        "your",
        "their",
        "his",
        "her",
        "its",
        "for",
        "in",
        "with",
        "using",
        "on",
        "of",
        "to",
        "from",
        "by",
        "and",
        "or",
        "new",
        "project",
        "written",
        "built",
        "powered",
    }
)

@dataclass(frozen=True)
class PromptChip:
    """Single editable Stage-1 chip representing a parsed answer or project name."""

    id: str
    value: str
    label: str
    editable: bool = True
    kind: str = ""

    def __post_init__(self) -> None:
        if not self.kind:
            object.__setattr__(self, "kind", "language" if self.id == "languages" else self.id)

    def as_json(self) -> Dict[str, Any]:
        """Return a JSON-serializable dict representation of this chip."""
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "label": self.label,
            "editable": self.editable,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Alias for as_json()."""
        return self.as_json()

    def __getitem__(self, key: str) -> Any:
        data = self.as_json()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_json().get(key, default)

    def keys(self) -> Any:
        return self.as_json().keys()

    def values(self) -> Any:
        return self.as_json().values()

    def items(self) -> Any:
        return self.as_json().items()

    def __iter__(self) -> Any:
        return iter(self.as_json())

    def __len__(self) -> int:
        return len(self.as_json())

    def __contains__(self, key: object) -> bool:
        return key in self.as_json()


Chip = PromptChip


def build_chips(answers: Mapping[str, Any], name: str) -> Tuple[PromptChip, ...]:
    """Construct ordered editable Stage-1 chips from normalized answers and display name."""
    chips: List[PromptChip] = []
    building = str(answers.get("building") or "").strip()
    if building:
        chips.append(
            PromptChip(
                id="building",
                value=building,
                label=building,
                editable=True,
                kind="building",
            )
        )

    if not is_kit_kind(answers):
        raw_langs = answers.get("languages") or []
        if isinstance(raw_langs, str):
            langs = [raw_langs]
        elif isinstance(raw_langs, Iterable):
            langs = [str(x).strip() for x in raw_langs if str(x).strip()]
        else:
            langs = []
        for lang in langs:
            chips.append(
                PromptChip(
                    id="languages",
                    value=lang,
                    label=lang,
                    editable=True,
                    kind="language",
                )
            )

        engine = str(answers.get("engine") or "").strip()
        if engine and engine != "none":
            chips.append(
                PromptChip(
                    id="engine",
                    value=engine,
                    label=engine,
                    editable=True,
                    kind="engine",
                )
            )

    clean_name = name.strip()
    if clean_name:
        chips.append(
            PromptChip(
                id="name",
                value=clean_name,
                label=f'"{clean_name}"',
                editable=True,
                kind="name",
            )
        )

    return tuple(chips)


def format_chips(chips_or_parsed: Union[Iterable[PromptChip], "ParsedPrompt"]) -> str:
    """Format chips as Stage-1 display text (e.g. 'service · typescript · \"Invoice Tracker\"')."""
    if isinstance(chips_or_parsed, ParsedPrompt):
        chips: Iterable[PromptChip] = chips_or_parsed.chips
    else:
        chips = chips_or_parsed
    return " · ".join(c.label for c in chips)


@dataclass(frozen=True)
class ParsedPrompt:
    """Result of parsing a free-text project idea sentence."""

    prompt: str
    name: str
    slug: str
    prefix: str
    env: str
    forms: PrefixForms
    answers: Dict[str, Any]
    chips: Tuple[PromptChip, ...]
    chips_text: str
    ambiguous: bool = False
    used_llm: bool = False
    explicit_code: bool = False
    not_a_project_request: bool = False
    explicit_keys: frozenset[str] = frozenset()

    @property
    def env_prefix(self) -> str:
        """Return the uppercase environment variable glob (e.g. 'INVOICE_TRACKER_*')."""
        return self.env

    @property
    def source(self) -> str:
        """Return 'llm' when the LLM fallback was used, else 'deterministic'."""
        return "llm" if self.used_llm else "deterministic"

    def as_json(self) -> Dict[str, Any]:
        """Return a JSON-serializable dict representation of the parsed prompt."""
        return {
            "prompt": self.prompt,
            "name": self.name,
            "slug": self.slug,
            "prefix": self.prefix,
            "env": self.env,
            "env_prefix": self.env,
            "forms": {
                "kebab": self.forms.kebab,
                "snake": self.forms.snake,
                "screaming": self.forms.screaming,
                "pascal": self.forms.pascal,
            },
            "answers": dict(self.answers),
            "chips": [c.as_json() for c in self.chips],
            "chips_text": self.chips_text,
            "ambiguous": self.ambiguous,
            "used_llm": self.used_llm,
            "explicit_code": self.explicit_code,
            "not_a_project_request": self.not_a_project_request,
            "source": self.source,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Alias for as_json()."""
        return self.as_json()

    def with_edit(self, field_id: str, value: Any) -> "ParsedPrompt":
        """Return a new ParsedPrompt after editing a chip ('building', 'languages', 'layout', 'engine', or 'name')."""
        return apply_chip_edit(self, field_id, value)

    def __getitem__(self, key: str) -> Any:
        data = self.as_json()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_json().get(key, default)

    def keys(self) -> Any:
        return self.as_json().keys()

    def values(self) -> Any:
        return self.as_json().values()

    def items(self) -> Any:
        return self.as_json().items()

    def __iter__(self) -> Any:
        return iter(self.as_json())

    def __len__(self) -> int:
        return len(self.as_json())

    def __contains__(self, key: object) -> bool:
        return key in self.as_json()


PromptParseResult = ParsedPrompt


def _derive_naming(raw_name: str) -> Tuple[str, str, str, str, PrefixForms]:
    """Derive display name, slug, snake prefix, screaming env pattern, and PrefixForms via naming.py."""
    candidate = raw_name.strip() if isinstance(raw_name, str) else ""
    if not candidate:
        candidate = "New Project"
    try:
        slug = slugify(candidate)
    except ValueError:
        # Prefix with a letter if candidate starts with digits or symbols
        try:
            slug = slugify(f"project-{candidate}")
        except ValueError:
            slug = "new-project"
            candidate = "New Project"
    forms = forms_from_slug(slug)
    return candidate, slug, forms.snake, f"{forms.screaming}_*", forms


_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]+")
_OPEN_BRACKET_RE = re.compile(r"[(\[]")
_OPEN_PAREN_ONLY_RE = re.compile(r"\(")
_OPEN_SQUARE_ONLY_RE = re.compile(r"\[")
# Dashes that can anchor a separator: an em/en dash, the first of 2+ hyphens, or a hyphen
# with whitespace on both sides (the caller still checks the whitespace before it lies
# after the previous separator).
_DASH_CANDIDATE_RE = re.compile(r"[\u2014\u2013]|--|(?<=\s)-(?=\s)")
_DASH_RUN_RE = re.compile(r"[\u2014\u2013]+")
_HYPHEN_RUN_RE = re.compile(r"-+")
_WS_RUN_RE = re.compile(r"\s*")


def _blank_bracket_groups(text: str) -> str:
    r"""Linear equivalent of re.sub(r"\([^)]*\)|\[[^\]]*\]", " ", text).

    The regex rescans to the end of text from every unclosed '(' or '[' (quadratic on
    '((((...'). Here the next ')' and next ']' are found once and reused until passed;
    a missing closer stays missing for every later opener.
    """
    out: List[str] = []
    last = pos = 0
    next_close = {"(": -2, "[": -2}  # -2: not looked up yet; -1: none after this point
    closer = {"(": ")", "[": "]"}
    opener_re = _OPEN_BRACKET_RE
    while True:
        m = opener_re.search(text, pos)
        if m is None:
            break
        start = m.start()
        opener = text[start]
        close = next_close[opener]
        if close == -2 or (close != -1 and close <= start):
            close = text.find(closer[opener], start + 1)
            next_close[opener] = close
        if close == -1:
            # No closer of this kind remains: later openers of this kind cannot match.
            other = "[" if opener == "(" else "("
            if next_close[other] == -1:
                break
            opener_re = _OPEN_PAREN_ONLY_RE if other == "(" else _OPEN_SQUARE_ONLY_RE
            pos = start + 1
            continue
        out.append(text[last:start])
        out.append(" ")
        last = pos = close + 1
    out.append(text[last:])
    return "".join(out)


def _split_on_dash_separators(text: str) -> List[str]:
    r"""Linear equivalent of re.split(r"\s*(?:[\u2014\u2013]+|--+|\s-\s)\s*", text).

    The regex restarts '\s*' at every character of a whitespace run and walks the whole
    run each time (quadratic on long blank runs). Every match of that pattern is anchored
    on a dash: a run of em/en dashes, a run of two or more hyphens, or one hyphen with
    whitespace on both sides. So scan dash to dash; on a hit the match starts where the
    whitespace run before the dash starts (not before the previous match end) and ends
    after the whitespace run that follows. '\s' and str.isspace() agree on every code point.
    """
    pieces: List[str] = []
    last = pos = 0
    while True:
        m = _DASH_CANDIDATE_RE.search(text, pos)
        if m is None:
            break
        dash = m.start()
        if text[dash] != "-":
            after = _DASH_RUN_RE.match(text, dash).end()  # type: ignore[union-attr]
        elif text.startswith("--", dash):
            after = _HYPHEN_RUN_RE.match(text, dash).end()  # type: ignore[union-attr]
        elif dash - 1 >= last:
            after = dash + 1  # spaced single hyphen (whitespace both sides, from the regex)
        else:
            pos = dash + 1
            continue
        start = dash
        while start > last and text[start - 1].isspace():
            start -= 1
        end = _WS_RUN_RE.match(text, after).end()  # type: ignore[union-attr]
        pieces.append(text[last:start])
        last = pos = end
    pieces.append(text[last:])
    return pieces


def _clean_phrase_tokens(text: str) -> List[str]:
    """Extract alphanumeric words and strip leading/trailing stopwords."""
    cleaned = _LEADING_FILLER_RE.sub("", text.strip())
    cleaned = _LANG_INTRO_RE.sub("", cleaned.strip())
    words = _ALNUM_RUN_RE.findall(cleaned)
    # Index walk, not repeated pop(0), so a run of stopwords costs linear time.
    lo, hi = 0, len(words)
    while lo < hi and words[lo].lower() in _EDGE_STOPWORDS:
        lo += 1
    while hi > lo and words[hi - 1].lower() in _EDGE_STOPWORDS:
        hi -= 1
    return words[lo:hi]


def _title_case_words(words: List[str]) -> str:
    """Title-case extracted words into a human-friendly project display name."""
    if not words:
        return ""
    return " ".join(w.capitalize() for w in words)


def _strip_detected_spans(text: str, spans: List[Tuple[int, int]]) -> str:
    """Replace matched keyword character spans with spaces."""
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for idx in range(max(0, start), min(len(chars), end)):
            chars[idx] = " "
    return "".join(chars)


def _extract_name_from_residual(original: str, spans: List[Tuple[int, int]]) -> str:
    """Extract a clean title-cased project name after removing detected language/kind/layout/engine spans."""
    explicit_match = _EXPLICIT_NAME_RE.search(original)
    if explicit_match:
        raw_explicit = (explicit_match.group(1) or explicit_match.group(2) or "").strip()
        explicit_words = _clean_phrase_tokens(raw_explicit)
        if explicit_words:
            return _title_case_words(explicit_words)

    residual = _strip_detected_spans(original, spans)
    # Remove parenthetical or bracketed fragments that became empty or held only stack notes
    residual = _blank_bracket_groups(residual)

    # Split on em-dash / en-dash / spaced hyphen separators
    segments = [seg.strip() for seg in _split_on_dash_separators(residual) if seg.strip()]
    if not segments:
        segments = [residual]

    for seg in segments:
        # Check if segment has a trailing 'for / that / which' clause
        clause_split = re.split(r"\b(?:for|that|which)\b", seg, maxsplit=1, flags=re.IGNORECASE)
        head_words = _clean_phrase_tokens(clause_split[0])
        if head_words:
            return _title_case_words(head_words)
        if len(clause_split) > 1:
            tail_words = _clean_phrase_tokens(clause_split[1])
            if tail_words:
                return _title_case_words(tail_words)

    all_words = _clean_phrase_tokens(residual)
    return _title_case_words(all_words)


def _drop_spans_inside(
    raw_building_spans: List[Tuple[int, int, str]],
    kit_spans: List[Tuple[int, int]],
) -> List[Tuple[int, int, str]]:
    """Drop non-kit building spans that lie inside some kit span, in O((n + k) log k).

    Same result as testing every kit span per building span: a span (s, e) is inside one
    iff, among kit spans starting at or before s, the furthest end reaches e.
    """
    if not kit_spans:
        return list(raw_building_spans)
    ordered = sorted(kit_spans)
    starts = [k_start for k_start, _k_end in ordered]
    reach: List[int] = []
    furthest = -1
    for _k_start, k_end in ordered:
        furthest = max(furthest, k_end)
        reach.append(furthest)
    kept: List[Tuple[int, int, str]] = []
    for start, end, b_kind in raw_building_spans:
        if b_kind not in KIT_BUILDING_KINDS:
            i = bisect_right(starts, start)
            if i and reach[i - 1] >= end:
                continue
        kept.append((start, end, b_kind))
    return kept


def _first_pattern_hit(
    patterns: Sequence[Tuple[Any, ...]],
    text: str,
    spans: List[Tuple[int, int]],
) -> Tuple[Optional[str], ...]:
    """Record every match span of every pattern in ``spans``; return the payload of the first
    pattern that matched, or a tuple of None as wide as one payload when none matched.

    Each row of ``patterns`` is ``(regex, *payload_strings)``; all rows have the same width.
    """
    first: Optional[Tuple[str, ...]] = None
    for pat, *payload in patterns:
        for m in pat.finditer(text):
            spans.append(m.span())
            if first is None:
                first = tuple(payload)
    if first is not None:
        return first
    return (None,) * (len(patterns[0]) - 1) if patterns else ()


def _distinct_by_position(hits: List[Tuple[int, str]]) -> List[str]:
    """Distinct ids ordered by first appearance position (stable for equal positions)."""
    return list(dict.fromkeys(item_id for _pos, item_id in sorted(hits, key=lambda item: item[0])))


def _detect_languages(
    scan_prompt: str,
    spans: List[Tuple[int, int]],
    engine_implied_lang: Optional[str],
    framework_implied_lang: Optional[str],
) -> Tuple[List[str], List[str]]:
    """Return (explicit languages, all languages incl. library/tool/engine-implied), ordered by appearance.

    Side effect: appends every explicit and implied language match span to ``spans``.
    """
    explicit_lang_hits: List[Tuple[int, str]] = []
    all_lang_hits: List[Tuple[int, str]] = []
    for pat, lang_id in _LANGUAGE_PATTERNS:
        for m in pat.finditer(scan_prompt):
            spans.append(m.span())
            explicit_lang_hits.append((m.start(), lang_id))
            all_lang_hits.append((m.start(), lang_id))
    for pat, lang_id in _IMPLIED_LANGUAGE_PATTERNS:
        for m in pat.finditer(scan_prompt):
            spans.append(m.span())
            all_lang_hits.append((m.start(), lang_id))

    explicit_languages = _distinct_by_position(explicit_lang_hits)
    languages = _distinct_by_position(all_lang_hits)
    if engine_implied_lang and engine_implied_lang not in languages:
        languages.append(engine_implied_lang)
    if framework_implied_lang and framework_implied_lang not in languages:
        languages.append(framework_implied_lang)
    # If both a real language and 'other' were matched (e.g. 'love2d lua' vs 'c++'), keep real first
    if len(languages) > 1 and "other" in languages:
        real_only = [lang for lang in languages if lang != "other"]
        if real_only:
            languages = real_only
    return explicit_languages, languages


def _detect_building(
    scan_prompt: str,
    spans: List[Tuple[int, int]],
    languages: List[str],
    detected_engine: Optional[str],
    detected_framework: Optional[str],
) -> Tuple[Optional[str], bool]:
    """Return (building kind or None, whether several distinct kinds conflicted).

    Side effect: appends the span of every building match that counted toward the result to
    ``spans`` (kit matches are dropped from it when the prompt carries a code signal).
    """
    raw_building_spans: List[Tuple[int, int, str]] = []
    kit_spans: List[Tuple[int, int]] = []
    for pat, b_kind in _BUILDING_PATTERNS:
        for m in pat.finditer(scan_prompt):
            raw_building_spans.append((m.start(), m.end(), b_kind))
            if b_kind in KIT_BUILDING_KINDS:
                kit_spans.append(m.span())

    # Ignore code-kind or code-context matches that fall inside a matched kit phrase span
    # (e.g. 'library' inside 'asset library' or 'model library').
    building_spans = _drop_spans_inside(raw_building_spans, kit_spans)

    non_kit_prompt = _strip_detected_spans(scan_prompt, kit_spans)
    has_code_signal = (
        any(b_kind not in KIT_BUILDING_KINDS for _s, _e, b_kind in building_spans)
        or bool(languages)
        or detected_engine is not None
        or detected_framework is not None
        or bool(_CODE_CONTEXT_RE.search(non_kit_prompt))
    )

    building_hits: List[Tuple[int, str]] = []
    for start, end, b_kind in (
        (
            (s, e, bk)
            for s, e, bk in raw_building_spans
            if bk not in KIT_BUILDING_KINDS
        )
        if has_code_signal
        else building_spans
    ):
        spans.append((start, end))
        building_hits.append((start, b_kind))
    distinct_buildings = _distinct_by_position(building_hits)

    # 'studio' naturally includes the word 'game(s)'; treat {'studio', 'game'} as 'studio'
    if "studio" in distinct_buildings and set(distinct_buildings) <= {"studio", "game"}:
        distinct_buildings = ["studio"]

    # When a request has both 'game' and an explicit code kind phrase with no game engine,
    # the building kind is the code kind, not 'game'.
    if (
        "game" in distinct_buildings
        and len(distinct_buildings) > 1
        and detected_engine is None
        and detected_framework is None
        and _EXPLICIT_CODE_KIND_PHRASE_RE.search(scan_prompt)
    ):
        distinct_buildings = [b for b in distinct_buildings if b != "game"]

    if distinct_buildings:
        return distinct_buildings[0], len(distinct_buildings) > 1
    if detected_engine is not None or (
        detected_framework is not None and detected_framework != "qt"
    ):
        return "game", False
    return None, False


def _fill_code_answers(
    answers: Dict[str, Any],
    *,
    eff_building: str,
    explicit_layout: Optional[str],
    languages: List[str],
    detected_engine: Optional[str],
    detected_framework: Optional[str],
) -> None:
    """Fill layout/languages/engine/framework answers for a non-kit (code) project."""
    eff_layout = explicit_layout or ("poly" if eff_building == "studio" else "mono")
    eff_languages = list(languages) if languages else ["other"]
    answers["layout"] = validate_answer("layout", eff_layout)
    answers["languages"] = validate_answer("languages", eff_languages)
    takes_framework = answers["building"] not in {"tool", "library", "service"}
    if answers["building"] in {"game", "studio"}:
        if detected_engine is not None:
            eff_engine = detected_engine
        else:
            prefilled_eng = prefill("engine", answers)
            eff_engine = prefilled_eng[0] if prefilled_eng else "none"
        answers["engine"] = validate_answer("engine", eff_engine)
    elif detected_engine is not None and takes_framework:
        answers["framework"] = detected_engine
    if detected_framework is not None and takes_framework:
        answers["framework"] = detected_framework


def _non_native_explicit_languages(
    raw_prompt: str, building: Optional[str], explicit_languages: List[str]
) -> List[str]:
    """Explicit languages not native to any kit family the prompt names (kit_families_in runs
    only when a language was named)."""
    if not explicit_languages:
        return []
    from .matcher import KIT_FAMILY_NATIVE_LANGUAGES, kit_families_in

    native_kit_langs: set[str] = set()
    for fam_tag in kit_families_in(raw_prompt, _explicit_building=building or ""):
        native_kit_langs.update(KIT_FAMILY_NATIVE_LANGUAGES.get(fam_tag, ()))
    return [lang for lang in explicit_languages if lang not in native_kit_langs]


def _detected_answer_keys(
    answers: Dict[str, Any],
    *,
    building: Optional[str],
    kit_project: bool,
    explicit_layout: Optional[str],
    explicit_code: bool,
    detected_engine: Optional[str],
) -> frozenset[str]:
    """Answer keys the prompt stated explicitly (not filled from defaults)."""
    detected_keys: set[str] = set()
    if building is not None:
        detected_keys.add("building")
    if not kit_project:
        if explicit_layout is not None:
            detected_keys.add("layout")
        if explicit_code:
            detected_keys.add("languages")
        if detected_engine is not None and answers.get("building") in {"game", "studio"}:
            detected_keys.add("engine")
    return frozenset(detected_keys)


def parse_deterministic(sentence: str) -> ParsedPrompt:
    """Deterministically parse a free-text sentence into questionnaire answers, name, naming forms, and chips.

    Raises PromptTooLongError (a ValueError) when len(sentence) > MAX_PROMPT_CHARS.
    """
    if not isinstance(sentence, str):
        raise ValueError("Prompt sentence must be a string")
    if len(sentence) > MAX_PROMPT_CHARS:
        raise PromptTooLongError(len(sentence))
    raw_prompt = sentence.strip()
    spans: List[Tuple[int, int]] = []

    from .matcher import kit_families_in, mask_website_subject

    initial_families = kit_families_in(raw_prompt)
    scan_prompt = mask_website_subject(raw_prompt) if "website" in initial_families else raw_prompt

    # 1. Detect engine and untemplated game/GUI frameworks
    detected_engine, engine_implied_lang = _first_pattern_hit(_ENGINE_PATTERNS, scan_prompt, spans)
    detected_framework, framework_implied_lang = _first_pattern_hit(
        _UNTEMPLATED_FRAMEWORK_PATTERNS, scan_prompt, spans
    )
    # raylib's table row implies no language (""): it has bindings for many, so treat it as
    # "no implied language" rather than adding an empty language id.
    framework_implied_lang = framework_implied_lang or None

    # 2. Detect explicit languages and library/tool-implied languages ordered by appearance
    explicit_languages, languages = _detect_languages(
        scan_prompt, spans, engine_implied_lang, framework_implied_lang
    )

    # 3. Detect building kind
    building, building_conflict = _detect_building(
        scan_prompt, spans, languages, detected_engine, detected_framework
    )

    # 4. Detect layout
    (explicit_layout,) = _first_pattern_hit(_LAYOUT_PATTERNS, scan_prompt, spans)

    # 5. Extract project name from remaining tokens
    extracted_name = _extract_name_from_residual(raw_prompt, spans)
    if not extracted_name and building in KIT_BUILDING_KINDS:
        extracted_name = _extract_name_from_residual(raw_prompt, [])

    eff_building = building if building is not None else "other"
    kit_project = is_kit_kind({"building": eff_building})

    explicit_code = bool(_non_native_explicit_languages(raw_prompt, building, explicit_languages))
    not_a_project_request = _is_non_project_request(raw_prompt)

    # Determine ambiguity before filling defaults
    ambiguous = (
        not raw_prompt
        or building is None
        or (not kit_project and len(languages) == 0)
        or building_conflict
        or not extracted_name
    )

    answers: Dict[str, Any] = {
        "building": validate_answer("building", eff_building),
    }
    if not kit_project:
        _fill_code_answers(
            answers,
            eff_building=eff_building,
            explicit_layout=explicit_layout,
            languages=languages,
            detected_engine=detected_engine,
            detected_framework=detected_framework,
        )

    final_name, slug, prefix, env, forms = _derive_naming(extracted_name or "New Project")
    chips = build_chips(answers, final_name)
    detected_keys = _detected_answer_keys(
        answers,
        building=building,
        kit_project=kit_project,
        explicit_layout=explicit_layout,
        explicit_code=explicit_code,
        detected_engine=detected_engine,
    )
    return ParsedPrompt(
        prompt=raw_prompt,
        name=final_name,
        slug=slug,
        prefix=prefix,
        env=env,
        forms=forms,
        answers=answers,
        chips=chips,
        chips_text=format_chips(chips),
        ambiguous=ambiguous,
        used_llm=False,
        explicit_code=explicit_code,
        not_a_project_request=not_a_project_request,
        explicit_keys=detected_keys,
    )


def _reconcile_building_fields(answers: Dict[str, Any]) -> None:
    """Strip kit-incompatible fields for kit kinds, or refill missing layout/engine fields for code kinds."""
    if is_kit_kind(answers):
        answers.pop("layout", None)
        answers.pop("languages", None)
        answers.pop("engine", None)
        answers.pop("framework", None)
    else:
        if "layout" not in answers:
            eff_layout = "poly" if answers.get("building") == "studio" else "mono"
            answers["layout"] = validate_answer("layout", eff_layout)
        if "languages" not in answers:
            eng = str(answers.get("engine") or "").strip().lower()
            eng_langs = prefill("languages", {"engine": eng}) if eng and eng != "none" else []
            answers["languages"] = validate_answer(
                "languages", eng_langs if eng_langs else ["other"]
            )
        if answers.get("building") not in {"game", "studio"}:
            answers.pop("engine", None)
        elif "engine" not in answers:
            prefilled_eng = prefill("engine", answers)
            answers["engine"] = validate_answer(
                "engine", prefilled_eng[0] if prefilled_eng else "none"
            )


def parse_prompt(sentence: str) -> ParsedPrompt:
    """Parse a free-text sentence into questionnaire answers + name (no model call)."""
    return parse_deterministic(sentence)


def apply_chip_edit(
    parsed: ParsedPrompt,
    field_id: str,
    new_value: Any,
) -> ParsedPrompt:
    """Apply a user edit to a Stage-1 chip and recompute validated answers, naming forms, and chips."""
    key = field_id.strip().lower()
    if key == "language":
        key = "languages"

    updated_answers = dict(parsed.answers)
    updated_name = parsed.name

    if key == "name":
        if not isinstance(new_value, str) or not new_value.strip():
            raise ValueError("Project name must be a non-empty string")
        updated_name = new_value.strip()
    elif key in _VALID_QUESTION_IDS:
        updated_answers[key] = validate_answer(key, new_value)
        _reconcile_building_fields(updated_answers)
    else:
        raise ValueError(f"Unknown chip field: {field_id!r}")

    edit_explicit_keys: set[str] = set(parsed.explicit_keys)
    if key in _VALID_QUESTION_IDS:
        edit_explicit_keys.add(key)
    if is_kit_kind(updated_answers):
        eff_explicit_code = False
        edit_explicit_keys &= {"building"}
    elif key == "languages":
        eff_explicit_code = (
            bool(updated_answers.get("languages"))
            and updated_answers.get("languages") != ["other"]
        )
        if not eff_explicit_code:
            edit_explicit_keys.discard("languages")
    else:
        eff_explicit_code = parsed.explicit_code
    if not is_kit_kind(updated_answers) and updated_answers.get("building") not in {"game", "studio"}:
        edit_explicit_keys.discard("engine")

    final_name, slug, prefix, env, forms = _derive_naming(updated_name)
    chips = build_chips(updated_answers, final_name)
    return ParsedPrompt(
        prompt=parsed.prompt,
        name=final_name,
        slug=slug,
        prefix=prefix,
        env=env,
        forms=forms,
        answers=updated_answers,
        chips=chips,
        chips_text=format_chips(chips),
        ambiguous=False,
        used_llm=parsed.used_llm,
        explicit_code=eff_explicit_code,
        explicit_keys=frozenset(edit_explicit_keys),
    )


def _is_only_other_language(raw_langs: Any) -> bool:
    """Return True when a caller languages value contains only 'other'."""
    if isinstance(raw_langs, str):
        return raw_langs.strip().lower() == "other"
    if isinstance(raw_langs, (list, tuple)):
        cleaned = [
            x.strip().lower()
            for x in raw_langs
            if isinstance(x, str) and x.strip()
        ]
        return bool(cleaned) and all(x == "other" for x in cleaned)
    return False


def merge_parsed_answers(
    parsed: Optional[ParsedPrompt],
    caller_answers: Optional[Mapping[str, Any]],
    *,
    caller_wins: bool = True,
) -> Dict[str, Any]:
    """Merge prompt-parsed answers with caller-supplied answers.

    When ``caller_wins`` is True (the CLI/flow default), caller-supplied answers
    take precedence and parsed values fill missing keys. When ``caller_wins`` is
    False (unchosen desktop defaults), values determined by the prompt take
    precedence and caller values only fill what the prompt did not determine.
    """
    caller_dict: Dict[str, Any] = (
        dict(caller_answers) if isinstance(caller_answers, Mapping) else {}
    )
    if parsed is None:
        return caller_dict
    if (
        parsed.explicit_code
        or parsed.answers.get("languages") not in (None, ["other"])
    ) and _is_only_other_language(caller_dict.get("languages")):
        caller_dict.pop("languages", None)
    if not caller_wins:
        # Unchosen UI defaults must never inject a language or building kind that the
        # prompt did not name; mirror the standalone matcher/parser answers.
        return dict(parsed.answers)

    merged = caller_dict
    for k, v in parsed.answers.items():
        merged.setdefault(k, v)
    # Only when the caller overrode a kit-kind prompt to a code kind: the parser
    # left layout/languages/engine out, without guessing a language from building.
    if (
        "building" in merged
        and is_kit_kind(parsed.answers)
        and not is_kit_kind(merged)
    ):
        if "layout" not in merged:
            merged["layout"] = (
                "poly" if merged.get("building") == "studio" else "mono"
            )
        if "languages" not in merged:
            eng = str(merged.get("engine") or "").strip().lower()
            eng_langs = prefill("languages", {"engine": eng}) if eng and eng != "none" else []
            merged["languages"] = eng_langs if eng_langs else ["other"]
        if merged.get("building") in {"game", "studio"} and "engine" not in merged:
            prefilled_eng = prefill("engine", merged)
            merged["engine"] = (
                prefilled_eng[0] if prefilled_eng else "none"
            )
    return merged


def explicit_code_from(
    parsed: Optional[ParsedPrompt],
    answers: Optional[Mapping[str, Any]],
) -> bool:
    """Return True when the parsed prompt named a code language or caller-supplied answers include a non-'other' language."""
    if parsed is not None and parsed.explicit_code:
        return True
    if not isinstance(answers, Mapping):
        return False
    if parsed is not None and dict(answers) == dict(parsed.answers):
        return parsed.explicit_code
    raw_langs = answers.get("languages")
    if isinstance(raw_langs, str):
        clean = raw_langs.strip().lower()
        return bool(clean) and clean != "other"
    if isinstance(raw_langs, (list, tuple)):
        return any(
            isinstance(x, str) and bool(x.strip()) and x.strip().lower() != "other"
            for x in raw_langs
        )
    return False
