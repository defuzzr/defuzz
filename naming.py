"""Slug and placeholder prefix transformations and path/content rename helpers."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath


# Bound generated package/path components while leaving room for template suffixes.
MAX_NAME_LENGTH = 64
# Filesystem limit for one path component, measured in UTF-8 bytes.
MAX_FOLDER_BYTES = 255

_SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_PLACEHOLDER_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class PrefixForms:
    """Four canonical case forms derived from a project slug or template placeholder."""

    kebab: str
    snake: str
    screaming: str
    pascal: str


def _ascii_slugify(name: str) -> str:
    """Original ASCII rule; results for ASCII names must never change."""
    collapsed = _NON_ALNUM_RE.sub("-", name.lower()).strip("-")
    if not collapsed:
        raise ValueError(f"Project name {name!r} produces an empty slug")
    if not collapsed[0].isalpha():
        raise ValueError(f"Slug {collapsed!r} from {name!r} must start with a letter")
    if len(collapsed) > MAX_NAME_LENGTH:
        raise ValueError(f"Project slug must be at most {MAX_NAME_LENGTH} characters")
    return collapsed


# Latin letters that NFKD does not decompose into an ASCII base letter.
_ASCII_FOLD = str.maketrans({
    "ß": "ss", "æ": "ae", "ø": "o", "œ": "oe", "ł": "l", "đ": "d", "ð": "d", "þ": "th", "ı": "i", "ŋ": "n",
})


# Device names Windows reserves, with or without an extension (checked for non-ASCII input).
_RESERVED_NAMES = frozenset(
    ["con", "prn", "aux", "nul"] + [f"{p}{d}" for p in ("com", "lpt") for d in "123456789"]
)


def _collapse(text: str) -> str:
    """Keep letters, digits and their marks; other visible characters separate words."""
    out: list[str] = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat[0] in "LN":
            out.append(ch)
        elif cat[0] == "M":
            if out and out[-1] != "-":
                out.append(ch)  # combining mark stays on its letter
        elif ch.isspace() or cat[0] in "PSZ":
            if out and out[-1] != "-":
                out.append("-")
        # Cc/Cf/Cs/Co/Cn: removed
    return unicodedata.normalize("NFC", "".join(out)).strip("-")


def folder_name(name: str) -> str:
    """Project folder name: letters and digits of any script, lowercase, '-' separated.

    ASCII names give exactly the same result as slugify. Other names are normalised
    first (NFKC: full-width and other compatibility forms become ordinary characters),
    lowercased, and stored composed (NFC), so names that differ only by case, accent
    encoding or compatibility form give the same folder. Control and format characters
    (bidi overrides, zero-width marks) are removed; other non-letters separate words, so
    slashes and dots never survive. A non-ASCII name that normalises to a Windows device
    name (con, nul, aux, com1, ...) is refused.
    """
    if not isinstance(name, str):
        raise ValueError("Project name must be a string")
    if name.isascii():
        return _ascii_slugify(name)
    text = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", name).lower())
    stem = _collapse(text.lstrip(" .").split(".", 1)[0]) if text.lstrip(" .") else ""
    if text.isascii():
        collapsed = _NON_ALNUM_RE.sub("-", text).strip("-")
        if collapsed and not (collapsed in _RESERVED_NAMES or stem in _RESERVED_NAMES):
            return _ascii_slugify(text)  # same folder as the plain ASCII spelling
    else:
        collapsed = _collapse(text)
    if collapsed in _RESERVED_NAMES or stem in _RESERVED_NAMES:
        raise ValueError(f"Project name {name!r} is a reserved device name; choose another name")
    if not collapsed:
        raise ValueError(f"Project name {name!r} has no letters or digits")
    if not collapsed[0].isalpha():
        raise ValueError(f"Folder name {collapsed!r} from {name!r} must start with a letter")
    if len(collapsed.encode("utf-8")) > MAX_FOLDER_BYTES:
        raise ValueError(f"Project folder name must be at most {MAX_FOLDER_BYTES} bytes")
    if len(collapsed) > MAX_NAME_LENGTH:
        raise ValueError(f"Project folder name must be at most {MAX_NAME_LENGTH} characters")
    return collapsed


def is_ascii_folder(folder: str) -> bool:
    """True when a folder name from folder_name() is plain ASCII (same as the code identifier)."""
    return isinstance(folder, str) and bool(folder) and folder.isascii()


def slugify(name: str) -> str:
    """Convert a project name into an ASCII kebab-case code identifier starting with a letter.

    Accents are stripped ('Café' -> 'cafe'); a name with no ASCII-convertible letters
    becomes 'project-' plus 8 hex digits of the SHA-256 of its folder name, so it is never empty.
    """
    if not isinstance(name, str):
        raise ValueError("Project name must be a string")
    if name.isascii():
        return _ascii_slugify(name)
    folder = folder_name(name)  # same refusals as the folder
    decomposed = unicodedata.normalize("NFKD", folder.translate(_ASCII_FOLD))
    ascii_text = "".join(ch for ch in decomposed if ch.isascii() and not unicodedata.combining(ch))
    collapsed = _NON_ALNUM_RE.sub("-", ascii_text.lower()).strip("-")
    if not collapsed or not collapsed[0].isalpha():
        digest = hashlib.sha256(folder.encode("utf-8")).hexdigest()[:8]
        return f"project-{digest}"
    if len(collapsed) > MAX_NAME_LENGTH:
        raise ValueError(f"Project slug must be at most {MAX_NAME_LENGTH} characters")
    return collapsed


def _forms_from_parts(parts: list[str]) -> PrefixForms:
    """Build PrefixForms from non-empty lowercase alphanumeric word tokens."""
    kebab = "-".join(parts)
    snake = "_".join(parts)
    screaming = snake.upper()
    pascal = "".join(part.capitalize() for part in parts)
    return PrefixForms(kebab=kebab, snake=snake, screaming=screaming, pascal=pascal)


def forms_from_slug(slug: str) -> PrefixForms:
    """Derive all four prefix forms from a validated kebab-case slug."""
    if not isinstance(slug, str) or not _SLUG_RE.fullmatch(slug):
        raise ValueError(f"Invalid kebab-case slug: {slug!r}")
    return _forms_from_parts(slug.split("-"))


def forms_from_placeholder(placeholder_snake: str) -> PrefixForms:
    """Derive all four prefix forms from a validated snake_case placeholder."""
    if not isinstance(placeholder_snake, str) or not _PLACEHOLDER_RE.fullmatch(placeholder_snake):
        raise ValueError(f"Invalid snake_case placeholder: {placeholder_snake!r}")
    kebab = placeholder_snake.replace("_", "-")
    snake = placeholder_snake
    screaming = snake.upper()
    pascal = "".join(part.capitalize() for part in snake.split("_") if part)
    return PrefixForms(kebab=kebab, snake=snake, screaming=screaming, pascal=pascal)


def rename_text(text: str, src: PrefixForms, dst: PrefixForms) -> str:
    """Replace all four prefix forms in text in a single longest-first regex pass."""
    if not text:
        return text
    # If snake and kebab are identical (single-word placeholder like 'app'),
    # prefer snake replacement when matched as a bare token so `app_core` -> `super_game_core`.
    pairs = [
        (src.snake, dst.snake),
        (src.kebab, dst.kebab),
        (src.screaming, dst.screaming),
        (src.pascal, dst.pascal),
    ]
    mapping: dict[str, str] = {}
    for s_val, d_val in pairs:
        if s_val and s_val not in mapping:
            mapping[s_val] = d_val
    if not mapping:
        return text
    ordered_keys = sorted(mapping.keys(), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(k) for k in ordered_keys))
    return pattern.sub(lambda m: mapping[m.group(0)], text)


def rename_path_parts(rel_path: str, src: PrefixForms, dst: PrefixForms) -> str:
    """Rename each path component of rel_path using rename_text."""
    norm = rel_path.replace("\\", "/")
    parts = [rename_text(part, src, dst) for part in PurePosixPath(norm).parts if part not in ("", ".")]
    return "/".join(parts)


def is_binary(data: bytes) -> bool:
    """Return True if data contains a NUL byte within the first 8 KiB."""
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]
