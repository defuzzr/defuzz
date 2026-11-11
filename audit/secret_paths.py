"""Recognizable credential tokens in one path segment.

Ported from the Tools executable-inventory prefix list. Not imported from
there. Private-key block markers are not filenames. Matching is linear and
bounded: a segment longer than 1024 characters is scanned only at its head
and tail, and every prefix body has a fixed upper bound.

A non-alphanumeric character must sit immediately before the prefix, so a
token glued to a letter or digit is not recognized. Minimum body lengths
follow the provider formats, not a generic long-string guess:

- ``sk-``: 20..200 of the key alphabet, and at least one digit (OpenAI /
  Anthropic shape). ``sk-learn-notes`` and other digit-free names stay.
- ``AKIA`` / ``ASIA``: exactly 16 uppercase letters or digits (AWS access
  key id), then a non-alphanumeric boundary.
- ``ghp_`` / ``gho_`` / ``ghu_`` / ``ghs_`` / ``ghr_``: 36..255 (GitHub
  classic token). ``ghp-pages`` has no underscore, so it stays.
- ``github_pat_``: 22..255, and at least one digit.
- ``xoxb-`` / ``xoxa-`` / ``xoxp-`` / ``xoxr-`` / ``xoxs-``: 16..200, and
  at least one digit.
- JWT: ``eyJ`` header, ``eyJ`` payload, signature, each 10..200.
- ``hf_``: 30..60 letters or digits (Hugging Face). ``hf_hub_download`` stays.
- ``AIza``: exactly 35 of ``[A-Za-z0-9_-]`` (Google API key).
- ``sk_live_`` / ``sk_test_`` / ``rk_live_`` / ``rk_test_`` / ``pk_live_``:
  16..128 letters or digits (Stripe). ``sk_live_demo`` stays.
- ``sk-ant-``: already covered by the ``sk-`` rule (real keys carry digits,
  for example ``api03``).
- ``glpat-``: 20..64 of ``[A-Za-z0-9_-]`` (GitLab personal access token).
- ``npm_``: exactly 36 letters or digits (npm automation token).
- ``pypi-``: 50..250 of ``[A-Za-z0-9_-]`` (PyPI upload token).
- Telegram bot token: 8..10 digits, ``:``, exactly 35 of ``[A-Za-z0-9_-]``.

Deliberately not recognized: a generic long hex or base64 run (digests,
UUIDs and build ids would be hidden), Slack webhook paths and Discord bot
tokens (no stable prefix that a filename would carry).
"""
from __future__ import annotations

import re

CREDENTIAL_IN_NAME = "credential_in_name"

_MAX_SEGMENT = 1024
_SPLIT = re.compile(r"[\\/]+")

# Bounded bodies. The digit lookaheads are themselves bounded, so a long
# segment of the key alphabet cannot force nested backtracking.
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-(?=[A-Za-z0-9_-]{0,200}[0-9])[A-Za-z0-9_-]{20,200}(?![A-Za-z0-9_-])"
    r"|AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"
    r"|ASIA[0-9A-Z]{16}(?![A-Za-z0-9])"
    r"|ghp_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"
    r"|gho_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"
    r"|ghu_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"
    r"|ghs_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"
    r"|ghr_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"
    r"|github_pat_(?=[A-Za-z0-9_]{0,255}[0-9])[A-Za-z0-9_]{22,255}(?![A-Za-z0-9_])"
    r"|xox[baprs]-(?=[A-Za-z0-9-]{0,200}[0-9])[A-Za-z0-9-]{16,200}(?![A-Za-z0-9-])"
    r"|hf_[A-Za-z0-9]{30,60}(?![A-Za-z0-9])"
    r"|AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,128}(?![A-Za-z0-9])"
    r"|pk_live_[A-Za-z0-9]{16,128}(?![A-Za-z0-9])"
    r"|glpat-[A-Za-z0-9_-]{20,64}(?![A-Za-z0-9_-])"
    r"|npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"
    r"|pypi-[A-Za-z0-9_-]{50,250}(?![A-Za-z0-9_-])"
    r"|[0-9]{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
    r"|eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}"
    r"(?![A-Za-z0-9_-])"
    r")"
)


def _windows(name: str) -> tuple[str, ...]:
    if len(name) <= _MAX_SEGMENT:
        return (name,)
    return (name[:_MAX_SEGMENT], name[-_MAX_SEGMENT:])


def credential_tokens_in_segment(name: str) -> tuple[str, ...]:
    """Matched token spellings inside one segment, in order, without duplicates."""
    if not isinstance(name, str) or not name:
        return ()
    found: list[str] = []
    seen: set[str] = set()
    for window in _windows(name):
        for match in _TOKEN_RE.finditer(window):
            token = match.group(0)
            if token not in seen:
                seen.add(token)
                found.append(token)
    return tuple(found)


def credential_like_segment(name: str) -> bool:
    """True when ``name`` contains a recognizable credential token."""
    return bool(credential_tokens_in_segment(name))


def segments(value: str) -> tuple[str, ...]:
    """Path segments, dropping empty, ``.`` and ``..``."""
    if not isinstance(value, str) or not value:
        return ()
    return tuple(part for part in _SPLIT.split(value) if part not in ("", ".", ".."))


def credential_tokens(value: str) -> tuple[str, ...]:
    """Token spellings in any segment of ``value``."""
    found: list[str] = []
    seen: set[str] = set()
    for part in segments(value):
        for token in credential_tokens_in_segment(part):
            if token not in seen:
                seen.add(token)
                found.append(token)
    return tuple(found)


def path_has_credential_segment(value: str) -> bool:
    """True when any segment of a path or path-shaped string is credential-like."""
    return bool(credential_tokens(value))
