"""The one project pick-list: code templates and workspace kits, in one ordered list.

A project is created only from an explicit choice out of this list. A typed idea may
mark up to three entries as suggested (``suggested_ids``), nothing more.

Standard library only. Importing this module reads no file and touches no network;
``load_picker_text`` reads ``picker_text.json`` (beside this file) only when called.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

__all__ = [
    "PICKER_TEXT_PATH",
    "build_catalog",
    "build_catalog_counted",
    "clean_field",
    "escape_text",
    "find_entry",
    "is_safe_id",
    "kits_notice_line",
    "load_picker_text",
    "render_text",
    "suggested_ids",
    "to_json",
]

PICKER_TEXT_PATH = Path(__file__).with_name("picker_text.json")

TITLE_MAX = 40
LINE_MAX = 100
WIDTH = 100
MAX_SUGGESTED = 3
_PICKER_MAX_BYTES = 1 << 20
_ELLIPSIS = "..."
_KINDS = ("template", "kit")
_KIND_RANK = {"template": 0, "kit": 1}
_DEFAULT_GROUPS = (("code", "Code projects"), ("workspace", "Workspace kits"))
_KIND_GROUP = {"template": "code", "kit": "workspace"}
_UNORDERED = 1 << 62
_SENTENCE_END_RE = re.compile(r"[.!?]+(?=\s+[^a-z\s])")
_TRAILING_PUNCT = ".,;:"
_CUT_TRIM = _TRAILING_PUNCT + "+&/-|"
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

ID_MAX = 64
MAX_TEMPLATES = 100
MAX_KITS = 200
_KIND_MAX = {"template": MAX_TEMPLATES, "kit": MAX_KITS}
# The kit id rule of the companion and the bridge (componentize_bridge._KIT_ID_RE:
# lowercase letters and digits in runs joined by single hyphens), narrowed to start with a
# letter (an all-digit id would read as a list number) and to ID_MAX characters.
_SAFE_ID_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", re.ASCII)
# Raw text read per field before escaping: far more than any shown title or line needs,
# so a huge name or summary costs nothing.
_RAW_READ = 4096
_FIELD_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


# --------------------------------------------------------------------------- text


def _escape_char(ch: str) -> str:
    code = ord(ch)
    if code < 0x100:
        return f"\\x{code:02x}"
    if code < 0x10000:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def is_safe_id(value: Any) -> bool:
    """True for an id that may be shown as a ``--template``/``--kit`` flag."""
    return isinstance(value, str) and len(value) <= ID_MAX and _SAFE_ID_RE.fullmatch(value) is not None


def escape_text(value: Any) -> str:
    """Multi-line text made safe to print: newlines and spaces kept, every other control,
    bidi and format character shown as an escape such as ``\\x1b`` or ``\\u202e``."""
    if not isinstance(value, str):
        return ""
    return "".join(
        ch if ch == "\n" or unicodedata.category(ch) not in _ESCAPED_CATEGORIES else _escape_char(ch)
        for ch in value
    )


def clean_field(value: Any, limit: int) -> str:
    """One companion-sourced field as one safe line of at most ``limit`` characters.

    Control, bidi and format characters are escaped (newline as ``\\n``, so a field can
    never start a new line); the cut is made after escaping.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text[: limit * 2 + _RAW_READ]
    out = "".join(
        _FIELD_ESCAPES.get(ch) or (_escape_char(ch) if unicodedata.category(ch) in _ESCAPED_CATEGORIES else ch)
        for ch in text
    )
    return _cut(out, limit)


def _clean(value: Any) -> str:
    """Return one plain display line: whitespace collapsed, control/bidi/format chars escaped."""
    if not isinstance(value, str):
        return ""
    out: List[str] = []
    for ch in value:
        if ch in "\t\n\r\x0b\x0c" or (ch.isspace() and unicodedata.category(ch) == "Zs"):
            out.append(" ")
        elif unicodedata.category(ch) in _ESCAPED_CATEGORIES:
            out.append(_escape_char(ch))
        else:
            out.append(ch)
    return " ".join("".join(out).split())


def _cut(text: str, limit: int) -> str:
    """Cut ``text`` to at most ``limit`` characters at a word boundary, marking the cut."""
    if len(text) <= limit:
        return text
    room = limit - len(_ELLIPSIS)
    head = text[: room + 1]
    space = head.rfind(" ")
    head = head[:space] if space > 0 else text[:room]
    while head and (head[-1].isspace() or head[-1] in _CUT_TRIM):
        head = head[:-1]
    return head + _ELLIPSIS


def _first_sentence(summary: str) -> str:
    match = _SENTENCE_END_RE.search(summary)
    sentence = summary[: match.end()] if match else summary
    if sentence.endswith(("!", "?")):
        sentence = sentence.rstrip(".")
    else:
        sentence = sentence.rstrip(_TRAILING_PUNCT).rstrip()
    return sentence


def _fallback_line(summary: Any) -> str:
    return _cut(_first_sentence(_clean(summary)), LINE_MAX)


def _char_cols(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _cols(text: str) -> int:
    return sum(_char_cols(ch) for ch in text)


def _split_long(word: str, width: int) -> List[str]:
    parts: List[str] = []
    cur, cur_w = "", 0
    for ch in word:
        w = _char_cols(ch)
        if cur and cur_w + w > width:
            parts.append(cur)
            cur, cur_w = "", 0
        cur += ch
        cur_w += w
    if cur:
        parts.append(cur)
    return parts


def _wrap(tokens: Sequence[str], first: str, rest: str, width: int = WIDTH) -> List[str]:
    """Greedy wrap by display columns; each token stays whole unless it alone is too wide.

    A token may start with extra spaces ("  [--kit x]") to set the gap before it; the
    gap is dropped when the token begins a new line.
    """
    lines: List[str] = []
    line, line_w, fresh = first, _cols(first), True
    for raw in tokens:
        word = raw.lstrip(" ")
        if not word:
            continue
        gap = raw[: len(raw) - len(word)] or " "
        w = _cols(word)
        if not fresh and line_w + len(gap) + w <= width:
            line += gap + word
            line_w += len(gap) + w
            continue
        if not fresh:
            lines.append(line)
            line, line_w = rest, _cols(rest)
        if line_w + w <= width:
            line += word
            line_w += w
        else:
            pieces = _split_long(word, max(1, width - line_w))
            for piece in pieces[:-1]:
                lines.append(line + piece)
                line, line_w = rest, _cols(rest)
            tail = pieces[-1]
            if line_w + _cols(tail) > width:
                for piece in _split_long(tail, max(1, width - line_w)):
                    lines.append(line + piece)
                    line, line_w = rest, _cols(rest)
                fresh = True
                continue
            line += tail
            line_w += _cols(tail)
        fresh = False
    if not fresh or line.strip():
        lines.append(line)
    return lines


# --------------------------------------------------------------------- picker text


def load_picker_text(path: Optional[Any] = None) -> dict:
    """Read picker_text.json (default: beside this module); missing or malformed -> {}."""
    target = Path(path) if path is not None else PICKER_TEXT_PATH
    try:
        with open(target, "rb") as fh:
            raw = fh.read(_PICKER_MAX_BYTES + 1)
        if len(raw) > _PICKER_MAX_BYTES:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def coming_soon_message(kind: str, item_id: Any) -> str:
    """Local availability policy, independent of the companion's version."""
    if not isinstance(item_id, str):
        return ""
    entry = _picker_entry(load_picker_text().get("entries"), f"{kind}:{item_id}")
    if entry and entry.get("coming_soon") is True:
        return f"{clean_field(item_id, ID_MAX)} is coming soon and cannot be created yet."
    return ""


def _picker_groups(picker: Mapping[str, Any]) -> List[tuple]:
    """Ordered (id, title) groups: the picker's valid groups, then the default ones."""
    groups: List[tuple] = []
    seen: set = set()
    defaults = dict(_DEFAULT_GROUPS)
    raw = picker.get("groups")
    for item in raw if isinstance(raw, list) else ():
        if not isinstance(item, Mapping):
            continue
        gid = item.get("id")
        if not isinstance(gid, str) or not gid.strip() or gid in seen:
            continue
        title = _clean(item.get("title")) or _clean(defaults.get(gid)) or _clean(gid)
        groups.append((gid, title))
        seen.add(gid)
    for gid, title in _DEFAULT_GROUPS:
        if gid not in seen:
            groups.append((gid, title))
            seen.add(gid)
    return groups


def _picker_entry(entries: Any, key: str) -> Optional[Mapping[str, Any]]:
    if not isinstance(entries, Mapping):
        return None
    item = entries.get(key)
    return item if isinstance(item, Mapping) else None


def _order_of(item: Mapping[str, Any]) -> int:
    order = item.get("order")
    if isinstance(order, int) and not isinstance(order, bool):
        return order
    return _UNORDERED


# ------------------------------------------------------------------------- catalog


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _raw(value: Any) -> Any:
    return value[:_RAW_READ] if isinstance(value, str) else value


def build_catalog(templates: Sequence[Any], kits: Sequence[Any], *, picker: Optional[Mapping[str, Any]] = None) -> List[dict]:
    """Build the ordered pick-list from template specs and kit infos (either may be empty).

    ``picker=None`` reads the default picker_text.json; pass ``{}`` for no picker text.
    Entries whose id is not a safe id (``is_safe_id``) and entries past MAX_TEMPLATES /
    MAX_KITS are left out; ``build_catalog_counted`` also says how many.
    """
    return build_catalog_counted(templates, kits, picker=picker)[0]


def build_catalog_counted(
    templates: Sequence[Any], kits: Sequence[Any], *, picker: Optional[Mapping[str, Any]] = None
) -> tuple:
    """``(entries, skipped)``: the pick-list and ``{"template": n, "kit": n}`` entries left out
    for an unsafe id or past the cap (MAX_TEMPLATES, MAX_KITS). Duplicates and entries
    without any id are dropped without being counted, as before."""
    skipped = {"template": 0, "kit": 0}
    if picker is None:
        picker = load_picker_text()
    if not isinstance(picker, Mapping):
        picker = {}
    groups = _picker_groups(picker)
    group_rank = {gid: i for i, (gid, _title) in enumerate(groups)}
    group_title = dict(groups)
    picker_entries = picker.get("entries")

    rows: List[tuple] = []
    seen: set = set()
    for kind, items in (("template", templates or ()), ("kit", kits or ())):
        for item in items:
            if item is None:
                continue
            item_id = _field(item, "id")
            if not isinstance(item_id, str) or not item_id.strip():
                continue
            if not is_safe_id(item_id):
                skipped[kind] += 1
                continue
            key = f"{kind}:{item_id}"
            if key in seen:
                continue
            seen.add(key)
            text: Mapping[str, Any] = _picker_entry(picker_entries, key) or {}
            title = _cut(_clean(_raw(text.get("title"))), TITLE_MAX) if text else ""
            line = _cut(_clean(_raw(text.get("line"))), LINE_MAX) if text else ""
            described = bool(title or line)
            if not title:
                title = _cut(_clean(_raw(_field(item, "name"))), TITLE_MAX) or _cut(_clean(item_id), TITLE_MAX)
            if not line:
                line = _fallback_line(_raw(_field(item, "summary")))
            group = text.get("group") if described else None
            if not isinstance(group, str) or group not in group_rank:
                group = _KIND_GROUP[kind]
            entry = {
                "kind": kind,
                "id": item_id,
                "title": title,
                "line": line,
                "group": group,
                "group_title": group_title[group],
                "flag": f"--{kind} {item_id}",
            }
            if text.get("coming_soon") is True:
                entry.update(coming_soon=True, selectable=False)
            sort_key = (
                group_rank[group],
                0 if described else 1,
                _order_of(text) if described else _UNORDERED,
                item_id,
                _KIND_RANK[kind],
            )
            rows.append((sort_key, entry))
    rows.sort(key=lambda r: r[0])
    shown = {"template": 0, "kit": 0}
    out: List[dict] = []
    for _key, entry in rows:
        kind = entry["kind"]
        if shown[kind] >= _KIND_MAX[kind]:
            skipped[kind] += 1
            continue
        shown[kind] += 1
        out.append(entry)
    return out, skipped


def _entry_key(entry: Mapping[str, Any]) -> str:
    return f"{entry.get('kind')}:{entry.get('id')}"


# ---------------------------------------------------------------------- suggestion


def _match_key(match: Any, kind: str) -> Optional[str]:
    if match is None or isinstance(match, (str, bytes, int, float)):
        return None
    if getattr(match, "disqualified", False) is True:
        return None
    inner = getattr(match, "template" if kind == "template" else "kit", None)
    item_id = getattr(inner, "id", None)
    if not isinstance(item_id, str) or not item_id:
        return None
    return f"{kind}:{item_id}"


def _match_score(match: Any) -> int:
    score = getattr(match, "score", 0)
    return score if isinstance(score, int) and not isinstance(score, bool) else 0


def suggested_ids(entries: Sequence[Mapping[str, Any]], template_matches: Sequence[Any], kit_matches: Sequence[Any], preferred: Any) -> List[str]:
    """Up to three entry keys ("template:<id>"/"kit:<id>"), best first; [] when nothing matched.

    ``preferred`` is the kind ``matcher.choose_catalog_entry`` picked ("template", "kit");
    its matches come first. For "none" (or anything else) matches of both kinds are merged
    by score, best first, templates before kits on a tie. Only keys in ``entries`` count.
    """
    known = {_entry_key(e) for e in entries or () if isinstance(e, Mapping) and not e.get("coming_soon")}
    ranked = {
        kind: [
            (key, _match_score(m))
            for m in (matches or ())
            for key in (_match_key(m, kind),)
            if key is not None and key in known
        ]
        for kind, matches in (("template", template_matches), ("kit", kit_matches))
    }
    if preferred in _KINDS:
        other = "kit" if preferred == "template" else "template"
        merged = [k for k, _s in ranked[preferred]] + [k for k, _s in ranked[other]]
    else:
        pool = [(-s, 0, i, k) for i, (k, s) in enumerate(ranked["template"])]
        pool += [(-s, 1, i, k) for i, (k, s) in enumerate(ranked["kit"])]
        merged = [k for *_rest, k in sorted(pool)]
    out: List[str] = []
    for key in merged:
        if key not in out:
            out.append(key)
        if len(out) == MAX_SUGGESTED:
            break
    return out


# -------------------------------------------------------------------------- lookup


def find_entry(entries: Sequence[Mapping[str, Any]], token: Any) -> Optional[dict]:
    """Find one entry by exact id, "template:<id>"/"kit:<id>", or 1-based number; else None.

    Surrounding whitespace is ignored. An id matches exactly, or case-insensitively when
    no exact match exists; never by prefix. A bare id shared by a template and a kit is
    ambiguous (None): use the "kind:id" form.
    """
    if not isinstance(token, str):
        return None
    token = token.strip()
    if not token:
        return None
    entries = [e for e in entries or () if isinstance(e, Mapping)]

    if re.fullmatch(r"[0-9]+", token, flags=re.ASCII):
        index = int(token)
        if 1 <= index <= len(entries):
            return None if entries[index - 1].get("coming_soon") else entries[index - 1]  # type: ignore[return-value]
        return None

    kind: Optional[str] = None
    ident = token
    head, sep, tail = token.partition(":")
    if sep and head.lower() in _KINDS:
        kind, ident = head.lower(), tail
        if not ident:
            return None
    pool = [e for e in entries if kind is None or e.get("kind") == kind]
    for same in (lambda a, b: a == b, lambda a, b: a.casefold() == b.casefold()):
        hits = [e for e in pool if isinstance(e.get("id"), str) and same(e["id"], ident)]
        if len(hits) == 1:
            return None if hits[0].get("coming_soon") else hits[0]  # type: ignore[return-value]
        if len(hits) > 1:
            return None
    return None


# ------------------------------------------------------------------------- render


def _suggested_keys(entries: Sequence[Mapping[str, Any]], suggested: Iterable[Any]) -> List[str]:
    known = {_entry_key(e) for e in entries if not e.get("coming_soon")}
    out: List[str] = []
    for key in suggested or ():
        if isinstance(key, str) and key in known and key not in out:
            out.append(key)
    return out


def _entry_lines(entry: Mapping[str, Any], number: int, num_width: int, is_suggested: bool) -> List[str]:
    """Two-line row: " NN. <title>  [<flag>]" then the line text, indented under the title."""
    prefix = f" {number:>{num_width}}. "
    indent = " " * len(prefix)
    title = _clean(entry.get("title")) or _clean(entry.get("id"))
    tail = ["  [coming soon]"] if entry.get("coming_soon") else [f"  [{_clean(entry.get('flag'))}]"]
    if is_suggested:
        tail.append("  (suggested)")
    first = prefix + title + "".join(tail)
    if _cols(first) <= WIDTH:
        out = [first]
    else:
        out = _wrap(title.split(" "), prefix, indent) + _wrap(tail, indent, indent)
    line = _clean(entry.get("line"))
    if line:
        out.extend(_wrap(line.split(" "), indent, indent))
    return out


def render_text(entries: Sequence[Mapping[str, Any]], *, suggested: Iterable[Any] = (), notice: str = "") -> str:
    """Plain text list: group title lines, numbered rows, optional notice; lines <= 100 columns."""
    entries = [e for e in entries or () if isinstance(e, Mapping)]
    marked = set(_suggested_keys(entries, suggested))
    lines: List[str] = []
    prev_group: Any = object()
    num_width = max(2, len(str(len(entries))))
    for number, entry in enumerate(entries, start=1):
        group = entry.get("group")
        if group != prev_group:
            if lines:
                lines.append("")
            title = _clean(entry.get("group_title")) or _clean(group) or "Projects"
            lines.extend(_wrap(title.split(" "), "", ""))
            prev_group = group
        lines.extend(_entry_lines(entry, number, num_width, _entry_key(entry) in marked))
    note = _clean(notice)
    if note:
        if lines:
            lines.append("")
        lines.extend(_wrap(note.split(" "), "", ""))
    return "".join(line.rstrip() + "\n" for line in lines)


def to_json(entries: Sequence[Mapping[str, Any]], *, suggested: Iterable[Any] = (), notice: str = "") -> dict:
    """JSON-ready dict {"entries": [...], "suggested": [...], "notice": str}; stable for equal input."""
    entries = [e for e in entries or () if isinstance(e, Mapping)]
    return {
        "entries": [
            {**{k: entry.get(k) for k in ("kind", "id", "title", "line", "group", "group_title", "flag")},
             **({"coming_soon": True, "selectable": False} if entry.get("coming_soon") else {})}
            for entry in entries
        ],
        "suggested": _suggested_keys(entries, suggested),
        "notice": _clean(notice),
    }


KITS_MISSING_NOTICE = "Kits need the defuzz-componentize plugin. Install it, then run `hermes defuzz kits`."
KITS_TIMEOUT_NOTICE = "The kit list did not answer in time. Try again, or run `hermes defuzz kits`."
KITS_SETTINGS_NOTICE = "Kits could not be listed: componentize settings are invalid. Run `hermes defuzz kits`."
KITS_ERROR_NOTICE = "Kits are unavailable right now. Run `hermes defuzz kits` for details."


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def kits_notice_line(status: str, notice: str, skipped: int = 0, *, templates_skipped: int = 0) -> str:
    """One plain line (<= 100 chars) for a kit list that could not be read or had skipped
    entries; "" when it was read cleanly.

    ``skipped`` counts kits left out (malformed, unsafe id, past the cap); a kit line wins
    over the ``templates_skipped`` line. The raw ``notice`` only picks the case; it is never
    echoed.
    """
    if status == "ok":
        skipped = _count(skipped)
        if not skipped:
            tskipped = _count(templates_skipped)
            if not tskipped:
                return ""
            if tskipped == 1:
                return "1 template was skipped because its id is not valid. Run `hermes defuzz templates`."
            return f"{tskipped} templates were skipped because their ids are not valid. Run `hermes defuzz templates`."
        if skipped == 1:
            return "1 kit was skipped because its description is not valid. Run `hermes defuzz kits`."
        return f"{skipped} kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`."
    text = (notice or "").lower()
    if status in ("unavailable", "absent"):
        return KITS_MISSING_NOTICE
    if "timed out" in text:
        return KITS_TIMEOUT_NOTICE
    if "componentize settings error" in text:
        return KITS_SETTINGS_NOTICE
    return KITS_ERROR_NOTICE
