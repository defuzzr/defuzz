"""Project scaffolding questionnaire as data and headless runner with timeout."""

from __future__ import annotations

import contextvars
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

Answers = Dict[str, Union[str, List[str]]]

KIT_BUILDING_KINDS: frozenset[str] = frozenset({"video", "images", "assets"})


def always(_answers: Mapping[str, Any]) -> bool:
    """Predicate that always applies regardless of prior answers."""
    return True


def is_kit_kind(answers: Mapping[str, Any]) -> bool:
    """Return True when the user is setting up a non-code kit project (video, images, or assets)."""
    building = str(answers.get("building") or "").strip().lower()
    return building in KIT_BUILDING_KINDS


def _is_not_kit_kind(answers: Mapping[str, Any]) -> bool:
    """Return True when the project is not a non-code kit kind."""
    return not is_kit_kind(answers)


def _is_game_or_studio(answers: Mapping[str, Any]) -> bool:
    """Return True when the user is building a game or game studio."""
    return answers.get("building") in {"game", "studio"}


@dataclass(frozen=True)
class Choice:
    """Single clickable choice for a questionnaire question."""

    value: str
    label: str


@dataclass(frozen=True)
class Question:
    """Single questionnaire step with ordered choices and applicability predicate."""

    id: str
    text: str
    choices: Tuple[Choice, ...]
    multi: bool = False
    applies: Callable[[Mapping[str, Any]], bool] = always

    def __post_init__(self) -> None:
        if not isinstance(self.choices, tuple):
            object.__setattr__(self, "choices", tuple(self.choices))


QUESTIONS: Tuple[Question, ...] = (
    Question(
        id="building",
        text="What are you building?",
        choices=(
            Choice("game", "game"),
            Choice("studio", "a studio of several games"),
            Choice("app", "app"),
            Choice("service", "backend service"),
            Choice("library", "library"),
            Choice("tool", "tool"),
            Choice("video", "video or film"),
            Choice("images", "images or art"),
            Choice("assets", "3D or game assets"),
            Choice("other", "other"),
        ),
        multi=False,
        applies=always,
    ),
    Question(
        id="layout",
        text="One repo or several?",
        choices=(
            Choice("mono", "mono"),
            Choice("poly", "poly"),
            Choice("single", "single"),
        ),
        multi=False,
        applies=_is_not_kit_kind,
    ),
    Question(
        id="languages",
        text="Main language(s)?",
        choices=(
            Choice("rust", "rust"),
            Choice("python", "python"),
            Choice("typescript", "typescript"),
            Choice("go", "go"),
            Choice("csharp", "csharp"),
            Choice("cpp", "cpp"),
            Choice("gdscript", "gdscript"),
            Choice("other", "other"),
        ),
        multi=True,
        applies=_is_not_kit_kind,
    ),
    Question(
        id="engine",
        text="Engine or framework?",
        choices=(
            Choice("godot", "godot"),
            Choice("bevy", "bevy"),
            Choice("unity", "unity"),
            Choice("unreal", "unreal"),
            Choice("none", "none"),
        ),
        multi=False,
        applies=_is_game_or_studio,
    ),
)

_QUESTIONS_BY_ID: Dict[str, Question] = {q.id: q for q in QUESTIONS}

_LANGUAGE_PREFILL_BY_ENGINE: Dict[str, List[str]] = {
    "godot": ["gdscript"],
    "bevy": ["rust"],
    "unity": ["csharp"],
    "unreal": ["cpp"],
}

_LANGUAGE_PREFILL_BY_BUILDING: Dict[str, List[str]] = {
    "game": ["rust", "gdscript"],
    "studio": ["rust", "gdscript"],
    "service": ["python"],
    "app": ["typescript"],
    "library": ["rust", "python"],
    "tool": ["python", "rust"],
}


class QuestionnaireTimeout(RuntimeError):
    """Raised when the headless questionnaire exceeds its deadline or receives None."""

    def __init__(
        self,
        message: str = "Questionnaire timed out",
        *,
        answers: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.answers: Answers = dict(answers) if answers is not None else {}


def _resolve_question(question: Union[Question, str]) -> Question:
    """Resolve a Question instance or question id string to a Question."""
    if isinstance(question, Question):
        return question
    if isinstance(question, str) and question in _QUESTIONS_BY_ID:
        return _QUESTIONS_BY_ID[question]
    raise ValueError(f"Unknown question: {question!r}")


def next_question(answers: Mapping[str, Any]) -> Optional[Question]:
    """Return the next unanswered Question whose applies(answers) is True, or None."""
    for q in QUESTIONS:
        if q.id not in answers and q.applies(answers):
            return q
    return None


def prefill(
    question_or_answers: Union[str, Question, Mapping[str, Any]],
    answers: Optional[Mapping[str, Any]] = None,
) -> List[str]:
    """Return suggested choice values for question_id given prior answers."""
    if isinstance(question_or_answers, Mapping) and answers is None:
        ans: Mapping[str, Any] = question_or_answers
        qid = "languages"
    else:
        ans = answers if answers is not None else {}
        if isinstance(question_or_answers, Question):
            qid = question_or_answers.id
        elif isinstance(question_or_answers, str):
            qid = question_or_answers
        else:
            raise ValueError(f"Invalid question identifier: {question_or_answers!r}")

    building = str(ans.get("building") or "").strip().lower()
    engine = str(ans.get("engine") or "").strip().lower()

    if qid == "layout":
        if building == "studio":
            return ["poly"]
        return ["single"]

    if qid == "languages":
        if is_kit_kind(ans):
            return []
        if engine in _LANGUAGE_PREFILL_BY_ENGINE:
            return list(_LANGUAGE_PREFILL_BY_ENGINE[engine])
        if building in _LANGUAGE_PREFILL_BY_BUILDING:
            return list(_LANGUAGE_PREFILL_BY_BUILDING[building])
        return []

    if qid == "engine":
        if building not in {"game", "studio"}:
            return []
        langs = ans.get("languages") or []
        if isinstance(langs, str):
            langs = [langs]
        lang_set = {str(x).strip().lower() for x in langs}
        if "gdscript" in lang_set and "rust" not in lang_set:
            return ["godot"]
        if "rust" in lang_set and "gdscript" not in lang_set:
            return ["bevy"]
        if "csharp" in lang_set:
            return ["unity"]
        if "cpp" in lang_set:
            return ["unreal"]
        return []

    return []


def validate_answer(question: Union[Question, str], raw: Any) -> Union[str, List[str]]:
    """Validate and normalize a raw answer for question; raise ValueError on unknown choice."""
    q = _resolve_question(question)
    valid_values = {c.value for c in q.choices}

    if not q.multi:
        if not isinstance(raw, str):
            raise ValueError(f"Expected a single string choice for {q.id!r}, got {type(raw).__name__}")
        val = raw.strip().lower()
        if not val or val not in valid_values:
            raise ValueError(f"Invalid choice {raw!r} for question {q.id!r}")
        return val

    if isinstance(raw, str):
        raw_items: List[Any] = [part for part in raw.split(",")] if "," in raw else ([raw] if raw.strip() else [])
    elif isinstance(raw, Iterable) and not isinstance(raw, (bytes, bytearray, Mapping)):
        raw_items = list(raw)
    else:
        raise ValueError(f"Expected a list of choices for multi-select question {q.id!r}")

    normalized: List[str] = []
    seen: set[str] = set()
    for item in raw_items:
        if not isinstance(item, str):
            raise ValueError(f"Invalid non-string choice {item!r} for question {q.id!r}")
        val = item.strip().lower()
        if not val or val not in valid_values:
            raise ValueError(f"Invalid choice {item!r} for question {q.id!r}")
        if val not in seen:
            seen.add(val)
            normalized.append(val)

    if not normalized:
        raise ValueError(f"At least one choice is required for multi-select question {q.id!r}")

    return normalized


def _call_with_budget(
    fn: Callable[..., Any],
    *args: Any,
    budget_s: float,
    timeout_exc_factory: Callable[[], BaseException],
) -> Any:
    """Invoke a side-effect-free decision callback on a daemon worker thread within budget_s.

    Decision callbacks (ask/choose/name_provider/confirm) follow the documented
    'return data only, no side effects' contract. Each worker runs under
    contextvars.copy_context().run and any late return/error after timeout is discarded.
    """
    if budget_s <= 0:
        raise timeout_exc_factory()
    lock = threading.Lock()
    abandoned = False
    box: Dict[str, Any] = {}

    def _worker() -> None:
        try:
            res = fn(*args)
        except BaseException as exc:
            with lock:
                if not abandoned:
                    box["error"] = exc
            return
        with lock:
            if not abandoned:
                box["result"] = res

    ctx = contextvars.copy_context()
    worker = threading.Thread(target=ctx.run, args=(_worker,), daemon=True)
    worker.start()
    worker.join(timeout=float(budget_s))
    with lock:
        if worker.is_alive() or ("result" not in box and "error" not in box):
            abandoned = True
            box.clear()
            raise timeout_exc_factory()
        if "error" in box:
            raise box["error"]
        return box.get("result")


# Routing-only passthrough keys preserved across run_questionnaire when supplied by prompt parsing.
_ROUTING_PASSTHROUGH_KEYS: frozenset[str] = frozenset({"framework"})


def run_questionnaire(
    ask: Callable[[Question, List[str]], Optional[Any]],
    *,
    timeout_s: float = 60.0,
    initial_answers: Optional[Mapping[str, Any]] = None,
    clock: Optional[Callable[[], float]] = None,
) -> Answers:
    """Drive the questionnaire headlessly with an overall monotonic deadline.

    The `ask` callback must follow the 'return data only, no side effects' contract.
    """
    now_fn = clock if clock is not None else time.monotonic
    answers: Answers = {}
    if initial_answers:
        for k, v in initial_answers.items():
            if k in _QUESTIONS_BY_ID:
                answers[k] = validate_answer(_QUESTIONS_BY_ID[k], v)
            elif k in _ROUTING_PASSTHROUGH_KEYS and isinstance(v, str) and v.strip():
                answers[k] = v.strip().lower()

    if timeout_s <= 0:
        raise QuestionnaireTimeout("Questionnaire timeout_s must be positive", answers=answers)

    deadline = now_fn() + float(timeout_s)

    while (q := next_question(answers)) is not None:
        rem = deadline - now_fn()
        if rem <= 0:
            raise QuestionnaireTimeout(
                f"Questionnaire deadline exceeded before question {q.id!r}",
                answers=answers,
            )
        suggested = prefill(q.id, answers)
        raw = _call_with_budget(
            ask,
            q,
            suggested,
            budget_s=rem,
            timeout_exc_factory=lambda qid=q.id: QuestionnaireTimeout(
                f"Questionnaire timed out waiting for answer to {qid!r}",
                answers=answers,
            ),
        )
        if raw is None:
            raise QuestionnaireTimeout(
                f"Questionnaire timed out waiting for answer to {q.id!r}",
                answers=answers,
            )
        if now_fn() >= deadline:
            raise QuestionnaireTimeout(
                f"Questionnaire deadline exceeded on question {q.id!r}",
                answers=answers,
            )
        answers[q.id] = validate_answer(q, raw)

    return answers


def questions_as_json() -> List[Dict[str, Any]]:
    """Export QUESTIONS as a JSON-serializable list of dicts for the desktop UI."""
    return [
        {
            "id": q.id,
            "text": q.text,
            "multi": q.multi,
            "choices": [{"value": c.value, "label": c.label} for c in q.choices],
        }
        for q in QUESTIONS
    ]
