"""Read-only structure check: is a folder ONE project, or does it hide nested project roots?

Invariants:
- Never writes, never runs a subprocess, never follows a symlink.
- Reads directory entry NAMES (os.scandir) everywhere, and opens only a fixed list of
  small declaration files at the checked root (DECLARATION_FILES). Nothing else is opened.
- A capped, unreadable or undecidable walk is reported as 'could_not_verify', never as clean.
- A Hermes home (HERMES_HOME, else ~/.hermes) is never listed or read.

Output shape (schema ``defuzz.structure-check/1``) is documented in docs/structure-check.md.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import time
import tomllib
import unicodedata
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

SCHEMA = "defuzz.structure-check/1"

MAX_DEPTH = 8
MAX_ENTRIES = 50_000
MAX_SECONDS = 5.0
MAX_DECLARATION_BYTES = 1 << 20

# Strong manifests: mark the checked root AND any folder below it as a project root.
FILE_MARKERS: Tuple[str, ...] = (
    "package.json", "pyproject.toml", "Cargo.toml", "go.mod", "pubspec.yaml", "pom.xml",
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "composer.json",
    "Gemfile", "mix.exs", "deno.json", "Package.swift",
)
# Weak markers: mark only the checked root as a project; a nested one never marks a nested
# project (such files are common in ordinary sub-folders of any project; `setup.py` is also a
# common module name, for example a CLI's `setup` command).
ROOT_ONLY_MARKERS: Tuple[str, ...] = (
    "go.work", "setup.py", "requirements.txt", "Pipfile", "setup.cfg", "manage.py", "Makefile", "CMakeLists.txt",
)
SLN_SUFFIX = ".sln"
# Strong, by suffix: files named *.sln / *.csproj, folders named *.xcodeproj.
FILE_SUFFIX_MARKERS: Tuple[str, ...] = (SLN_SUFFIX, ".csproj")
DIR_SUFFIX_MARKERS: Tuple[str, ...] = (".xcodeproj",)
# index.html is a marker only beside one of these folders, and never inside a folder
# whose own name says it holds a project's static files.
INDEX_ASSET_DIRS: Tuple[str, ...] = ("assets", "css", "js", "src", "img", "images", "static", "styles", "scripts")
STATIC_CONTAINER_NAMES = frozenset({"public", "static", "assets", "www", "templates", "client", "docs"})

SKIP_DIRS = frozenset({
    "node_modules", ".git", ".next", ".open-next", ".turbo", "dist", "build", "out",
    ".venv", "venv", "target", "vendor", "__pycache__", ".cache", "coverage", ".worktrees",
    ".svelte-kit", ".nuxt", ".output", ".parcel-cache", ".pytest_cache", ".mypy_cache", ".ruff_cache",
})

# Root-only declaration files, in reading order.  Nothing else is ever opened.
DECLARATION_FILES: Tuple[str, ...] = (
    "package.json", "pnpm-workspace.yaml", "Cargo.toml", "pyproject.toml", "go.work", ".gitmodules",
    ".adopt/rules.json",
)

# A folder with no marker and no member declarations that holds several projects side by
# side: nesting is evaluated inside each of the first FOLDER_PROJECTS_CAP top-level projects.
FOLDER_PROJECTS_CAP = 50
FOLDER_TEXT_CAP = 10

BLOCKING_IDS = frozenset({"nested_project", "git_inside_git", "root_is_home_or_agent_home"})
STATUSES = ("one_project", "nested_projects_found", "not_a_project", "could_not_verify")

# Names that look like a duplicate or leftover copy (also a strong nesting signal, below).
_DUP_SUFFIX_RE = re.compile(r"(?i)(?:[-_](?:v\d+|final|old|copy|backup|new)| copy| ?\(\d+\))$")
_DUP_MAX_DEPTH = 3

# ------------------------------------------------------------------ embedding patterns
#
# An undeclared project root that matches one of these well-known layouts is reported as
# `embedded_subproject` (information) instead of `nested_project`.  Checked in this order;
# the first match gives the `reason` token.  STRONG_NESTING_SIGNALS below always win.

MARKER_ECOSYSTEM = {
    "package.json": "js", "deno.json": "js", "pyproject.toml": "python", "setup.py": "python",
    "setup.cfg": "python", "requirements.txt": "python", "Pipfile": "python", "manage.py": "python",
    "Cargo.toml": "rust", "go.mod": "go", "go.work": "go", "pubspec.yaml": "dart",
    "pom.xml": "jvm", "build.gradle": "jvm", "build.gradle.kts": "jvm", "settings.gradle": "jvm",
    "settings.gradle.kts": "jvm", "composer.json": "php", "Gemfile": "ruby", "mix.exs": "elixir",
    "Package.swift": "swift", "CMakeLists.txt": "cpp",
}
SUFFIX_ECOSYSTEM = {".sln": "dotnet", ".csproj": "dotnet", ".xcodeproj": "swift"}
# Builds whose member lists live in files this check does not read (settings.gradle, pom.xml
# <modules>, a .sln, a Mix umbrella): a nested root of the same kind inside such a build is
# one of its modules.
MODULE_BUILD_KINDS = frozenset({"jvm", "dotnet", "elixir"})
MODULE_LABEL = "module of a Gradle, Maven, .NET or Mix build"
SHELL_LABEL = "mobile or desktop shell"
# Platform shells and build modules sit side by side by design: they never make a crowd.
CROWD_FREE_LABELS = frozenset({SHELL_LABEL, MODULE_LABEL})

# (a) template_or_fixture: an ANCESTOR folder (strictly above the nested root, below the
#     checked root) is template-like.  The nested folder's own name excuses it only when it
#     sits inside a declared workspace member (a fixture that belongs to that member).
TEMPLATE_FIXTURE_SEGMENTS = frozenset({
    "templates", "template", "fixtures", "fixture", "__fixtures__", "testdata", "test-data", "test_data",
    "examples", "example", "samples", "sample", "demos", "demo", "tests", "test", "__tests__", "e2e",
    "spec", "benchmarks", "bench", "mocks", "__mocks__", "scaffolds", "boilerplate", "starters", "starter-kits",
})
TEMPLATE_FIXTURE_SUFFIXES = ("-fixture", "-fixtures", "-template", "-example", "_fixture", "_template", "_example")
TEMPLATE_FIXTURE_PREFIXES = ("tmpl_", "tmpl-")
# Inside an ancestor with exactly one of these names at depth 1 or 2, the 'crowded parent'
# override does not apply; more than EMBEDDED_CROWD_CAP excused roots under one such ancestor
# add one info finding `many_embedded_subprojects`.
CROWD_EXEMPT_ANCESTORS = frozenset({
    "templates", "template", "fixtures", "__fixtures__", "testdata", "tests", "test", "__tests__", "examples"})
CROWD_EXEMPT_MAX_DEPTH = 2
EMBEDDED_CROWD_CAP = 12

# (d) vendored_code: any such segment.  (`vendor` itself is in SKIP_DIRS and never entered.)
VENDORED_SEGMENTS = frozenset({"third_party", "third-party", "external", "extern", "deps", "submodules"})

# (b) framework_layout: (own folder name(s), required marker, where it must sit).
#   marker: a marker file name, or "manifest" (any file marker).
#   where:  "any"; "parent_js_or_pubspec" (parent folder has package.json or pubspec.yaml);
#           "parent_firebase" (parent folder has firebase.json); "in_js_or_python" (nearest
#           enclosing project root is a JS or Python project); "parent_tools" (the parent
#           folder is named tools or scripts).
FRAMEWORK_LAYOUTS: Tuple[Tuple[frozenset, str, str, str], ...] = (
    (frozenset({"src-tauri"}), "Cargo.toml", "any", "Tauri crate"),
    (frozenset({"android", "ios", "macos", "windows", "linux"}), "manifest", "parent_js_or_pubspec", SHELL_LABEL),
    (frozenset({"functions"}), "package.json", "parent_firebase", "Firebase functions"),
    (frozenset({"native", "sidecar", "wasm", "rust", "core-rs"}), "Cargo.toml", "in_js_or_python", "native module"),
    # A sidecar is a helper process shipped beside the app, in any language.
    (frozenset({"sidecar"}), "manifest", "any", "helper process"),
    (frozenset({"bindings", "ffi"}), "manifest", "any", "language bindings"),
    (frozenset({"docs", "website", "docs-site"}), "package.json", "any", "documentation site"),
    (frozenset({"infra", "terraform", "deploy", "cdk"}), "manifest", "any", "infrastructure code"),
    (frozenset({"xtask"}), "manifest", "any", "repository tooling"),
    (None, "manifest", "parent_tools", "repository tooling"),  # tools/<name>, scripts/<name>
    (None, "manifest", "same_build", MODULE_LABEL),
)
TOOLS_PARENTS = frozenset({"tools", "scripts"})
PARENT_FILES_OF_INTEREST = frozenset({"package.json", "pubspec.yaml", "firebase.json"})

# (c) different_ecosystem: its manifest kinds are disjoint from the root's and every declared
#     member's, it is at depth <= 2, its folder holds fewer than 2,000 directory entries, its
#     name is not project-like (below), and it is the only undeclared root of its kind at
#     depth <= 3.  A static site (index.html rule) is too weak a marker to count as a language.
DIFFERENT_ECOSYSTEM_MAX_DEPTH = 2
DIFFERENT_ECOSYSTEM_UNIQUE_DEPTH = 3
DIFFERENT_ECOSYSTEM_MAX_ENTRIES = 2000
# Project-like names never get the second-language excuse: ends 'project', starts 'my',
# contains 'other', 'copy', 'backup' or 'test2', or starts/ends with (or has as a
# separated word) 'new' or 'old'.
_PROJECT_LIKE_RE = re.compile(
    r"(?i)(?:project$|^my|other|copy|backup|test2|^(?:new|old)|(?:new|old)$|[-_. ](?:new|old)[-_. ])")

# Strong nesting signals: these keep `nested_project` whatever pattern matches.
SCRATCH_SEGMENTS = frozenset({"_ai_temp", ".planning", "scratch", "tmp", "temp", "playground", "sandbox", "experiments", "wip"})
CROWDED_PARENT_MIN = 3  # this many undeclared roots in one parent folder (see CROWD_EXEMPT_ANCESTORS)

EMBEDDED_REASONS = {
    "template_or_fixture": "templates, examples and test fixtures",
    "framework_layout": "framework sub-packages such as a Tauri crate, a documentation site or repository tooling",
    "different_ecosystem": "a component written in a second language",
    "vendored_code": "vendored third-party code",
}
EMBEDDED_ORDER = ("template_or_fixture", "vendored_code", "framework_layout", "different_ecosystem")


def _is_template_segment(seg: str) -> bool:
    low = seg.lower()
    return (low in TEMPLATE_FIXTURE_SEGMENTS or low.endswith(TEMPLATE_FIXTURE_SUFFIXES)
            or low.startswith(TEMPLATE_FIXTURE_PREFIXES))


def _is_vendored_path(parts: Sequence[str]) -> bool:
    return any(p.lower() in VENDORED_SEGMENTS for p in parts)


def _ecosystems(markers: Sequence[str]) -> frozenset:
    kinds = set()
    for m in markers:
        if m in MARKER_ECOSYSTEM:
            kinds.add(MARKER_ECOSYSTEM[m])
        elif m.startswith("index.html+"):
            kinds.add("static_site")
        else:
            for suffix, kind in SUFFIX_ECOSYSTEM.items():
                if m.endswith(suffix):
                    kinds.add(kind)
    return frozenset(kinds)


def _has_manifest(markers: Sequence[str]) -> bool:
    return any(m != ".git" and not m.startswith("index.html+") for m in markers)


def _markers_for(names_nondir: set, dir_names: set, has_git: bool, is_root: bool) -> List[str]:
    markers = [".git"] if has_git else []
    markers.extend(n for n in FILE_MARKERS if n in names_nondir)
    if is_root:
        markers.extend(n for n in ROOT_ONLY_MARKERS if n in names_nondir)
    for suffix in FILE_SUFFIX_MARKERS:
        markers.extend(n for n in names_nondir if n.endswith(suffix) and len(n) > len(suffix))
    for suffix in DIR_SUFFIX_MARKERS:
        markers.extend(n for n in dir_names if n.endswith(suffix) and len(n) > len(suffix))
    return markers


def _framework_match(cand: Dict[str, Any]) -> Optional[str]:
    parts = cand["rel"].split("/")
    name = parts[-1].lower()
    parent = parts[-2].lower() if len(parts) > 1 else ""
    for names, marker, where, label in FRAMEWORK_LAYOUTS:
        if names is not None and name not in names:
            continue
        if marker == "manifest":
            if not _has_manifest(cand["markers"]):
                continue
        elif marker not in cand["markers"]:
            continue
        if where == "parent_js_or_pubspec" and not ({"package.json", "pubspec.yaml"} & cand["parent_files"]):
            continue
        if where == "parent_firebase" and "firebase.json" not in cand["parent_files"]:
            continue
        if where == "in_js_or_python" and not ({"js", "python"} & cand["enclosing_kinds"]):
            continue
        if where == "parent_tools" and parent not in TOOLS_PARENTS:
            continue
        if where == "same_build":
            kinds = cand["kinds"] - {"static_site"}
            if not kinds or not kinds <= MODULE_BUILD_KINDS or not kinds <= cand["enclosing_kinds"]:
                continue
        return label
    return None


def _crowd_exempt_ancestor(ancestors: Sequence[str]) -> Optional[str]:
    """The path of the first ancestor at depth 1..2 named exactly like a template/test folder."""
    for i, seg in enumerate(ancestors[:CROWD_EXEMPT_MAX_DEPTH]):
        if seg.lower() in CROWD_EXEMPT_ANCESTORS:
            return "/".join(ancestors[:i + 1])
    return None


def _resolve_embedded(cands: List[Dict[str, Any]], known_kinds: frozenset) -> List[Tuple[str, int]]:
    """Set cand['reason'] (an EMBEDDED_REASONS token) or None for each undeclared root.

    Returns [(ancestor path, count)] for each crowd-exempt ancestor holding more than
    EMBEDDED_CROWD_CAP excused roots."""
    for c in cands:
        c["kinds"] = c["kinds"] - {"static_site"}
        c["label"] = _framework_match(c)
    # Platform shells and build modules sit side by side by design: they never make a crowd.
    by_parent: Dict[str, int] = {}
    for c in cands:
        if c["label"] not in CROWD_FREE_LABELS:
            by_parent[c["parent"]] = by_parent.get(c["parent"], 0) + 1
    shallow_kinds: Dict[str, int] = {}
    for c in cands:
        if c["depth"] <= DIFFERENT_ECOSYSTEM_UNIQUE_DEPTH:
            for k in c["kinds"]:
                shallow_kinds[k] = shallow_kinds.get(k, 0) + 1
    exempt_counts: Dict[str, int] = {}
    for c in cands:
        c["reason"], c["rule"] = None, None
        parts = c["rel"].split("/")
        name = parts[-1]
        ancestors = parts[:-1]
        # Strong nesting signals first.
        if c["has_git"] or _DUP_SUFFIX_RE.search(name):
            continue
        if any(p.lower() in SCRATCH_SEGMENTS for p in ancestors):
            continue
        label = c.pop("label")
        exempt = _crowd_exempt_ancestor(ancestors)
        crowd_ok = exempt is not None or _is_vendored_path(ancestors) or label in CROWD_FREE_LABELS
        if by_parent.get(c["parent"], 0) >= CROWDED_PARENT_MIN and not crowd_ok:
            continue
        if any(_is_template_segment(p) for p in ancestors) or (c["in_member"] and _is_template_segment(name)):
            c["reason"] = "template_or_fixture"
        elif _is_vendored_path(parts):
            c["reason"] = "vendored_code"
        elif label:
            c["reason"], c["rule"] = "framework_layout", label
        elif (c["kinds"] and not (c["kinds"] & known_kinds)
              and c["depth"] <= DIFFERENT_ECOSYSTEM_MAX_DEPTH
              and c["entries"] < DIFFERENT_ECOSYSTEM_MAX_ENTRIES
              and not _PROJECT_LIKE_RE.search(name)
              and all(shallow_kinds.get(k, 0) == 1 for k in c["kinds"])):
            c["reason"] = "different_ecosystem"
        if c["reason"] and exempt is not None:
            exempt_counts[exempt] = exempt_counts.get(exempt, 0) + 1
    return sorted((a, n) for a, n in exempt_counts.items() if n > EMBEDDED_CROWD_CAP)


_NEXT = {
    "nested_project": "Move it out to its own folder beside this one (copy first, keep the original until the copy works), or declare it as a workspace member of this project.",
    "git_inside_git": "Decide whether it is its own project (move it out) or part of this one (remove its inner .git only after backing it up), or declare it as a submodule in .gitmodules.",
    "root_is_home_or_agent_home": "Run the check inside one project folder instead.",
    "root_is_symlink": "Run the check on the real folder the link points to.",
    "no_project_marker": "No project file was found at the top of this folder. If this is meant to be one project, add its manifest at the top, or run the check inside the project folder.",
    "git_only_root": "No action is needed; adding the project's manifest at the top makes the check more precise.",
    "many_embedded_subprojects": "Check that none of these is live work kept here by mistake; declaring them silences this note.",
    "duplicate_tree_names": "Check which copy is the live one and archive the other; no action is needed if both are intended.",
    "could_not_verify": "Fix the reason given, or run the check on a smaller folder, then run it again.",
    "embedded_subproject": "No action is needed; to silence this note, declare the folder as a workspace member or in .adopt/rules.json.",
    "folder_of_projects": "Run the check inside one of these projects; each one is checked on its own.",
    "depth_limit_reached": "No action is needed for an ordinary large project; to look deeper, run the check on a sub-folder.",
}


class _Unreadable(Exception):
    """A declaration file exists but could not be read or understood."""


# ------------------------------------------------------------------ text helpers

def escape_name(text: str) -> str:
    """Escape control and undecodable characters so a name cannot alter a terminal or log."""
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif unicodedata.category(ch) in ("Cc", "Cs", "Cf", "Zl", "Zp"):
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _show(rel: str) -> str:
    return escape_name(rel) if rel else "."


# ------------------------------------------------------------------ declarations

def _read_small(abs_path: str) -> Optional[bytes]:
    """Return bytes of a regular, non-symlink file; None if absent; raise _Unreadable otherwise."""
    try:
        st = os.lstat(abs_path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _Unreadable(f"cannot inspect ({exc.__class__.__name__})") from exc
    if not stat.S_ISREG(st.st_mode):
        raise _Unreadable("not a regular file (symlinks are never followed)")
    if st.st_size > MAX_DECLARATION_BYTES:
        raise _Unreadable("larger than 1 MiB")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(abs_path, flags)
    except OSError as exc:
        raise _Unreadable(f"cannot open ({exc.__class__.__name__})") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _Unreadable("not a regular file")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DECLARATION_BYTES:
                raise _Unreadable("larger than 1 MiB")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise _Unreadable(f"cannot read ({exc.__class__.__name__})") from exc
    finally:
        os.close(fd)


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _Unreadable("not UTF-8 text") from exc


def _norm_pattern(raw: Any) -> str:
    if not isinstance(raw, str):
        raise _Unreadable("a member entry is not a string")
    p = raw.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.rstrip("/")
    if not p or p == "." or p.startswith("/") or ".." in p.split("/"):
        return ""  # the root itself or outside the root: declares nothing below it
    return p


def _split_globs(items: Sequence[Any]) -> Tuple[List[str], List[str]]:
    inc: List[str] = []
    exc: List[str] = []
    for item in items:
        if isinstance(item, str) and item.strip().startswith("!"):
            p = _norm_pattern(item.strip()[1:])
            if p:
                exc.append(p)
        else:
            p = _norm_pattern(item)
            if p:
                inc.append(p)
    return inc, exc


def _parse_package_json(text: str) -> Tuple[List[str], List[str]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise _Unreadable("not valid JSON") from exc
    if not isinstance(data, dict):
        raise _Unreadable("top level is not an object")
    ws = data.get("workspaces")
    if ws is None:
        return [], []
    if isinstance(ws, dict):
        ws = ws.get("packages", [])
    if not isinstance(ws, list):
        raise _Unreadable("'workspaces' is neither a list nor an object with 'packages'")
    return _split_globs(ws)


def _strip_yaml_scalar(value: str) -> str:
    value = value.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        if end < 0:
            raise _Unreadable("unterminated quote")
        return value[1:end]
    return value.split(" #", 1)[0].strip()


def _parse_pnpm_yaml(text: str) -> Tuple[List[str], List[str]]:
    """Tolerant reader for the one key we need: top-level ``packages:`` as a block or flow list."""
    items: List[str] = []
    in_packages = False
    found = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indented = line[:1] in (" ", "\t")
        if not indented:
            in_packages = False
            if line.startswith("packages:"):
                found = True
                rest = line[len("packages:"):].split(" #", 1)[0].strip()
                if rest.startswith("["):
                    if not rest.endswith("]"):
                        raise _Unreadable("multi-line flow list is not supported")
                    inner = rest[1:-1].strip()
                    items.extend(_strip_yaml_scalar(p) for p in inner.split(",") if p.strip())
                elif rest:
                    raise _Unreadable("'packages' is not a list")
                else:
                    in_packages = True
            continue
        if in_packages:
            if not stripped.startswith("-"):
                raise _Unreadable("unexpected line inside 'packages'")
            items.append(_strip_yaml_scalar(stripped[1:]))
    if not found:
        return [], []
    return _split_globs(items)


def _parse_cargo(text: str) -> Tuple[List[str], List[str]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise _Unreadable("not valid TOML") from exc
    ws = data.get("workspace")
    if ws is None:
        return [], []
    if not isinstance(ws, dict):
        raise _Unreadable("[workspace] is not a table")
    members, exclude = ws.get("members", []), ws.get("exclude", [])
    if not isinstance(members, list) or not isinstance(exclude, list):
        raise _Unreadable("workspace members/exclude are not lists")
    inc = [p for p in (_norm_pattern(m) for m in members) if p]
    exc = [p for p in (_norm_pattern(m) for m in exclude) if p]
    return inc, exc


def _parse_pyproject(text: str) -> Tuple[List[str], List[str]]:
    """uv workspace members: ``[tool.uv.workspace] members / exclude``."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise _Unreadable("not valid TOML") from exc
    tool = data.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    ws = uv.get("workspace") if isinstance(uv, dict) else None
    if ws is None:
        return [], []
    if not isinstance(ws, dict):
        raise _Unreadable("[tool.uv.workspace] is not a table")
    members, exclude = ws.get("members", []), ws.get("exclude", [])
    if not isinstance(members, list) or not isinstance(exclude, list):
        raise _Unreadable("workspace members/exclude are not lists")
    inc = [p for p in (_norm_pattern(m) for m in members) if p]
    exc = [p for p in (_norm_pattern(m) for m in exclude) if p]
    return inc, exc


def _go_path(token: str) -> str:
    token = token.strip()
    if token[:1] in ('"', "`"):
        end = token.find(token[0], 1)
        if end < 0:
            raise _Unreadable("unterminated quote")
        token = token[1:end]
    return token


def _parse_go_work(text: str) -> Tuple[List[str], List[str]]:
    inc: List[str] = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if in_block:
            if line == ")":
                in_block = False
            else:
                inc.append(_go_path(line))
            continue
        if line.startswith("use"):
            rest = line[3:].strip()
            if rest == "(":
                in_block = True
            elif rest.startswith("(") and rest.endswith(")"):
                inc.extend(_go_path(t) for t in rest[1:-1].split())
            elif rest:
                inc.append(_go_path(rest))
    if in_block:
        raise _Unreadable("unterminated 'use (' block")
    pats = [p for p in (_norm_pattern(x) for x in inc) if p]
    return [glob_escape(p) for p in pats], []


def _parse_gitmodules(text: str) -> List[str]:
    paths: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        m = re.match(r"(?i)^path\s*=\s*(.+?)\s*$", line)
        if m:
            value = m.group(1)
            if value[:1] == '"' and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            p = _norm_pattern(value)
            if p:
                paths.append(p)
    return paths


def _parse_defuzz_rules(text: str) -> Tuple[List[str], List[str]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise _Unreadable("not valid JSON") from exc
    if not isinstance(data, dict):
        raise _Unreadable("top level is not an object")
    dirs = data.get("declared_dirs", [])
    if not isinstance(dirs, list):
        raise _Unreadable("'declared_dirs' is not a list")
    inc = []
    for item in dirs:  # tolerant: skip malformed items
        raw = item.get("dir") if isinstance(item, dict) else item
        if isinstance(raw, str):
            p = _norm_pattern(raw)
            if p:
                inc.append(glob_escape(p))
    return inc, []


def glob_escape(path: str) -> str:
    """Escape glob characters so an exact path declaration matches only itself."""
    return re.sub(r"([*?\[\]])", r"[\1]", path)


def _segments_match(pat: Sequence[str], parts: Sequence[str]) -> bool:
    if not pat:
        return not parts
    head = pat[0]
    if head == "**":
        return any(_segments_match(pat[1:], parts[i:]) for i in range(len(parts) + 1))
    return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and _segments_match(pat[1:], parts[1:])


def glob_match(pattern: str, rel: str) -> bool:
    """POSIX segment glob: '*' stays inside one segment, '**' spans zero or more segments."""
    return _segments_match(pattern.split("/"), rel.split("/"))


def _has_wildcard(pattern: str) -> bool:
    unescaped = re.sub(r"\[[*?\[\]]\]", "", pattern)
    return any(ch in unescaped for ch in "*?[")


# ------------------------------------------------------------------ boundaries

def _realpath(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def _hermes_homes() -> List[str]:
    """HERMES_HOME if set, and always the default ~/.hermes (a profile home may sit inside it)."""
    homes = []
    env = os.environ.get("HERMES_HOME")
    if env:
        homes.append(_realpath(env))
    default = _realpath(os.path.join(os.path.expanduser("~"), ".hermes"))
    if default not in homes:
        homes.append(default)
    return homes


def _within(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def _boundary_reason(real_root: str) -> Optional[str]:
    home = _realpath(os.path.expanduser("~"))
    if real_root == os.path.realpath(os.sep):
        return "the filesystem root"
    if any(_within(real_root, agent) for agent in _hermes_homes()):
        return "an agent (Hermes) home, or a folder inside one"
    if real_root == home:
        return "the home folder"
    if _within(home, real_root):
        return "a folder that contains the home folder"
    return None


# ------------------------------------------------------------------ main check

def _finding(fid: str, rel: str, sentence: str, **detail: Any) -> Dict[str, Any]:
    return {"id": fid, "path": _show(rel), "detail": detail, "sentence": sentence, "next": _NEXT[fid]}


def _empty_result(given: str, limits: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "path": escape_name(given),
        "status": "could_not_verify",
        "roots": [],
        "declared_members": 0,
        "declarations": {},
        "findings": [],
        "top_level_projects": [],
        "limits": limits,
        "skipped": {"ignored_dirs": 0, "symlinks": 0, "unreadable": 0, "agent_home": 0, "declared_submodules": 0},
    }


def _resolve_candidate_findings(roots, root_markers, candidates, findings) -> None:
    """Resolve undeclared roots after their complete subtrees have been counted."""
    known_kinds = set(_ecosystems(root_markers or []))
    for r in roots:
        if r["kind"] in ("declared_member", "declared_submodule"):
            known_kinds |= _ecosystems(r["markers"])
    many = _resolve_embedded(candidates, frozenset(known_kinds))
    for ancestor, count in many:
        findings.append(_finding(
            "many_embedded_subprojects", ancestor,
            f"This folder holds {count} separate packages noted as templates or fixtures, more than "
            f"{EMBEDDED_CROWD_CAP}; that many is unusual, so check that they are all templates or fixtures.",
            count=count, cap=EMBEDDED_CROWD_CAP))
    for c in candidates:
        if c["reason"]:
            c["root"]["kind"] = "embedded"
            detail = {"depth": c["depth"], "markers": c["markers"], "reason": c["reason"]}
            if c["rule"]:
                detail["rule"] = c["rule"]
            findings.append(_finding(
                "embedded_subproject", c["rel"],
                f"This folder is a separate package inside this project; this layout is common for "
                f"{EMBEDDED_REASONS[c['reason']]}, and declaring it silences this note.", **detail))
        else:
            findings.append(_root_finding("nested_project", c["rel"], c["depth"], c["markers"]))


def _read_declarations(lexical: str, res: dict[str, Any]):
    """Read root-only member and submodule declarations, recording uncertainty."""
    findings = res["findings"]
    ws_globs: List[Tuple[str, List[str], List[str]]] = []
    ws_unknown = False
    submodules: List[str] = []
    gitmodules_unknown = False
    parsers = {
        "package.json": _parse_package_json, "pnpm-workspace.yaml": _parse_pnpm_yaml,
        "Cargo.toml": _parse_cargo, "pyproject.toml": _parse_pyproject, "go.work": _parse_go_work, ".adopt/rules.json": _parse_defuzz_rules,
    }
    for name in DECLARATION_FILES:
        abs_path = os.path.join(lexical, *name.split("/"))
        try:
            if "/" in name:
                parent = os.path.join(lexical, name.split("/")[0])
                try:
                    pst = os.lstat(parent)
                except FileNotFoundError:
                    res["declarations"][name] = "absent"
                    continue
                if not stat.S_ISDIR(pst.st_mode):
                    raise _Unreadable("its folder is not a real folder")
            data = _read_small(abs_path)
            if data is None:
                res["declarations"][name] = "absent"
                continue
            text = _decode(data)
            if name == ".gitmodules":
                submodules = _parse_gitmodules(text)
            else:
                inc, exc = parsers[name](text)
                ws_globs.append((name, inc, exc))
            res["declarations"][name] = "read"
        except _Unreadable as err:
            res["declarations"][name] = "unreadable"
            if name == ".gitmodules":
                gitmodules_unknown = True
            else:
                ws_unknown = True
            findings.append(_finding(
                "could_not_verify", name,
                "This declaration file could not be read, so it is unknown which inner projects it declares.",
                reason=str(err)))
    return ws_globs, ws_unknown, submodules, gitmodules_unknown


def check_structure(
    path: Any = ".",
    *,
    clock: Callable[[], float] = time.monotonic,
    max_entries: int = MAX_ENTRIES,
    max_depth: int = MAX_DEPTH,
    max_seconds: float = MAX_SECONDS,
) -> Dict[str, Any]:
    """Report whether ``path`` is one project; read-only, bounded, deterministic."""
    given = os.fspath(path)
    limits: Dict[str, Any] = {
        "max_depth": max_depth, "max_entries": max_entries, "max_seconds": max_seconds,
        "hit": [], "entries_seen": 0, "dirs_scanned": 0, "folders_not_entered": 0,
    }
    res = _empty_result(given, limits)
    findings: List[Dict[str, Any]] = res["findings"]
    skipped = res["skipped"]

    lexical = os.path.abspath(given)
    stripped = given.rstrip("/" + os.sep) or given
    if os.path.islink(stripped):
        target = _realpath(stripped)
        findings.append(_finding(
            "root_is_symlink", "", "This path is a symbolic link, so its real location differs from the name given; the check does not follow links.",
            target=escape_name(target)))
        return _finish(res, root_scanned=False)
    try:
        st = os.lstat(lexical)
    except OSError:
        st = None
    if st is None or not stat.S_ISDIR(st.st_mode):
        findings.append(_finding("could_not_verify", "", "This path does not exist or is not a folder.", reason="not_a_folder"))
        return _finish(res, root_scanned=False)
    real_root = _realpath(lexical)
    reason = _boundary_reason(real_root)
    if reason:
        findings.append(_finding(
            "root_is_home_or_agent_home", "",
            f"This folder is {reason}; it holds many unrelated things and is not one project, so nothing inside it was read.",
            kind=reason))
        return _finish(res, root_scanned=False)

    ws_globs, ws_unknown, submodules, gitmodules_unknown = _read_declarations(lexical, res)
    submodule_set = set(submodules)

    agent_ids = set()
    for agent in _hermes_homes():
        try:
            agent_st = os.stat(agent)
        except OSError:
            continue
        agent_ids.add((agent_st.st_dev, agent_st.st_ino))

    start = clock()
    roots: List[Dict[str, Any]] = []
    root_markers: Optional[List[str]] = None
    member_roots: List[str] = []  # non-root project roots found so far (ancestor guard)
    root_kinds: Dict[str, str] = {}  # rel -> roots[].kind at classification time
    open_cands: List[Dict[str, Any]] = []  # candidates whose subtree is being walked
    candidates: List[Dict[str, Any]] = []  # undeclared roots, resolved after the walk
    root_name = os.path.basename(real_root)
    declares_any = any(inc for _n, inc, _e in ws_globs) or bool(submodules)
    folder_mode = False
    top_level: List[Tuple[str, int, List[str], bool]] = []  # (rel, depth, markers, has_git)
    hit = limits["hit"]
    depth_example: Optional[str] = None
    # (abs, rel, depth, parent's files of interest, nearest enclosing root's ecosystems); DFS, sorted
    stack: List[Tuple[str, str, int, frozenset, frozenset]] = [(lexical, "", 0, frozenset(), frozenset())]

    def stop(kind: str, rel: str, sentence: str) -> None:
        if kind not in hit:
            hit.append(kind)
            findings.append(_finding("could_not_verify", rel, sentence, reason=kind))

    while stack:
        if "entries" in hit:
            break
        if clock() - start > max_seconds:
            stop("time", stack[-1][1], f"The check stopped after its {max_seconds:g}-second time budget, so folders were left unchecked.")
            break
        abs_dir, rel, depth, parent_files, enclosing_kinds = stack.pop()
        try:
            with os.scandir(abs_dir) as it:
                entries = []
                for entry in it:
                    if limits["entries_seen"] >= max_entries:
                        stop("entries", rel, f"The check stopped after {max_entries} entries, so folders were left unchecked.")
                        break
                    limits["entries_seen"] += 1
                    entries.append(entry)
        except OSError as exc:
            skipped["unreadable"] += 1
            findings.append(_finding("could_not_verify", rel, "This folder could not be listed, so it is unknown whether it holds a project.",
                                     reason=exc.__class__.__name__))
            continue
        limits["dirs_scanned"] += 1
        # The walk is depth-first, so each candidate's subtree is scanned contiguously.
        while open_cands and not rel.startswith(open_cands[-1]["rel"] + "/"):
            open_cands.pop()
        for oc in open_cands:
            oc["entries"] += len(entries)
        entries.sort(key=lambda e: e.name)
        names_nondir = set()
        subdirs: List[os.DirEntry] = []
        has_git = False
        for entry in entries:
            name = entry.name
            try:
                is_link = entry.is_symlink()
                is_dir = (not is_link) and entry.is_dir(follow_symlinks=False)
            except OSError:
                is_link, is_dir = False, False
            if name == ".git":
                has_git = True
            if is_link:
                skipped["symlinks"] += 1
            if is_dir:
                subdirs.append(entry)
            else:
                names_nondir.add(name)
        dir_names = {e.name for e in subdirs}
        markers = _markers_for(names_nondir, dir_names, has_git, rel == "")
        if not _has_manifest(markers) and "index.html" in names_nondir:
            own_name = os.path.basename(rel) if rel else ""
            asset = next((d for d in INDEX_ASSET_DIRS if d in dir_names), None)
            if asset and own_name not in STATIC_CONTAINER_NAMES:
                markers.append("index.html+" + asset)
        markers.sort()
        descend = True
        parent_enclosing = enclosing_kinds
        if markers:
            enclosing_kinds = _ecosystems(markers)
        if rel == "":
            root_markers = markers
            if markers:
                roots.append({"path": ".", "depth": 0, "markers": markers, "kind": "root"})
            else:
                folder_mode = not (declares_any or ws_unknown or gitmodules_unknown)
        elif markers and folder_mode:
            # A separate project beside its siblings: looked inside later, on its own.
            top_level.append((rel, depth, markers, has_git))
            roots.append({"path": _show(rel), "depth": depth, "markers": markers, "kind": "separate_project"})
            continue
        elif markers:
            kind = _classify(rel, markers, has_git, ws_globs, ws_unknown, submodule_set, gitmodules_unknown, member_roots)
            entry_root = {"path": _show(rel), "depth": depth, "markers": markers, "kind": kind[0]}
            roots.append(entry_root)
            enclosing = max((a for a in member_roots if rel.startswith(a + "/")), key=len, default=None)
            for fid in kind[1]:
                if fid == "nested_project":
                    cand = {
                        "rel": rel, "depth": depth, "markers": markers, "has_git": has_git,
                        "parent": rel.rpartition("/")[0], "parent_files": parent_files,
                        "enclosing_kinds": parent_enclosing, "kinds": _ecosystems(markers), "root": entry_root,
                        "in_member": enclosing is not None and root_kinds.get(enclosing) == "declared_member",
                        "entries": len(entries),
                    }
                    candidates.append(cand)
                    open_cands.append(cand)
                else:
                    findings.append(_root_finding(fid, rel, depth, markers))
            if kind[0] == "declared_submodule":
                skipped["declared_submodules"] += 1
                descend = False
            member_roots.append(rel)
            root_kinds[rel] = kind[0]
        if not descend:
            continue
        child_parent_files = frozenset(PARENT_FILES_OF_INTEREST & names_nondir)
        # Children, pushed in reverse so the walk visits them in name order.
        parent_name = os.path.basename(rel) if rel else root_name
        child_items = []
        for entry in subdirs:
            name = entry.name
            child_rel = f"{rel}/{name}" if rel else name
            if name in SKIP_DIRS:
                skipped["ignored_dirs"] += 1
                continue
            if agent_ids:
                try:
                    est = entry.stat(follow_symlinks=False)
                    if (est.st_dev, est.st_ino) in agent_ids:
                        skipped["agent_home"] += 1
                        continue
                except OSError:
                    pass
            if depth + 1 <= _DUP_MAX_DEPTH and (name == parent_name or _DUP_SUFFIX_RE.search(name)):
                findings.append(_finding(
                    "duplicate_tree_names", child_rel,
                    "This folder name looks like a duplicate or leftover copy of another folder.",
                    depth=depth + 1))
            if depth + 1 > max_depth:
                # Not a could-not-verify on its own: the verdict stands on what was seen.
                if "depth" not in hit:
                    hit.append("depth")
                    depth_example = child_rel
                limits["folders_not_entered"] += 1
                continue
            child_items.append((entry.path, child_rel, depth + 1, child_parent_files, enclosing_kinds))
        stack.extend(reversed(child_items))

    res["roots"] = roots
    res["declared_members"] = sum(1 for r in roots if r["kind"] in ("declared_member", "declared_submodule"))
    _resolve_candidate_findings(roots, root_markers, candidates, findings)
    depth_shown = _show(depth_example or "")
    if folder_mode and top_level:
        sub_example = _check_each_project(res, lexical, top_level, clock=clock, start=start,
                                          max_entries=max_entries, max_depth=max_depth, max_seconds=max_seconds)
        if depth_example is None and sub_example is not None:
            depth_shown = sub_example  # already shown relative to PATH
    if "depth" in hit:
        findings.append(_finding(
            "depth_limit_reached", "",
            f"Folders deeper than {max_depth} levels were not entered; the verdict is based on everything above that.",
            folders_not_entered=limits["folders_not_entered"], max_depth=max_depth, example=depth_shown))
    if not (folder_mode and top_level) and root_markers is not None and not root_markers:
        findings.append(_finding("no_project_marker", "", "No project file was found at the top of this folder, and no project was found below it."))
    if root_markers == [".git"]:
        findings.append(_finding(
            "git_only_root", "",
            "This folder has no project file at the top, but it is a git repository, so it is checked as one project."))
    return _finish(res, root_scanned=root_markers is not None)


_PROJECT_FINDING_IDS = frozenset({
    "nested_project", "git_inside_git", "embedded_subproject", "could_not_verify", "duplicate_tree_names",
    "many_embedded_subprojects"})


def _check_each_project(res, lexical, top_level, *, clock, start, max_entries, max_depth, max_seconds) -> Optional[str]:
    """Folder of separate projects: report it, then run the ordinary check inside each of the
    first FOLDER_PROJECTS_CAP top-level projects (sorted by path) within the remaining budget."""
    findings, limits, hit = res["findings"], res["limits"], res["limits"]["hit"]
    top_level = sorted(top_level, key=lambda t: t[0])
    n, with_git = len(top_level), sum(1 for t in top_level if t[3])
    findings.append(_finding(
        "folder_of_projects", "",
        f"This folder is not a project itself; it holds {n} separate projects, and each can be checked on its own.",
        projects=n, with_git=with_git))
    depth_example = None
    stopped_by: Optional[str] = None  # "entries" or "time" when the budget ran out
    evaluated = 0
    for rel, depth, markers, _has_git in top_level[:FOLDER_PROJECTS_CAP]:
        remaining_s = max_seconds - (clock() - start)
        remaining_e = max_entries - limits["entries_seen"]
        if "entries" in hit or remaining_e <= 0:
            stopped_by = "entries"
        elif "time" in hit or remaining_s <= 0:
            stopped_by = "time"
        if stopped_by:
            break
        evaluated += 1
        sub = check_structure(os.path.join(lexical, *rel.split("/")), clock=clock, max_entries=remaining_e,
                              max_depth=max(0, max_depth - depth), max_seconds=remaining_s)
        prefix = _show(rel)
        for key in ("entries_seen", "dirs_scanned", "folders_not_entered"):
            limits[key] += sub["limits"][key]
        for key, value in sub["skipped"].items():
            res["skipped"][key] += value
        res["declared_members"] += sub["declared_members"]
        for kind in sub["limits"]["hit"]:
            if kind not in hit:
                hit.append(kind)
        for r in sub["roots"]:
            if r["path"] != ".":
                res["roots"].append(dict(r, path=f"{prefix}/{r['path']}", depth=r["depth"] + depth))
        nested_paths, embedded = set(), 0
        for f in sub["findings"]:
            if f["id"] == "depth_limit_reached":
                if depth_example is None:
                    ex = f["detail"]["example"]
                    depth_example = prefix if ex == "." else f"{prefix}/{ex}"
                continue
            if f["id"] not in _PROJECT_FINDING_IDS:
                continue
            g = dict(f, path=prefix if f["path"] == "." else f"{prefix}/{f['path']}", detail=dict(f["detail"]))
            if "depth" in g["detail"]:
                g["detail"]["depth"] += depth
            findings.append(g)
            if f["id"] in ("nested_project", "git_inside_git"):
                nested_paths.add(g["path"])
            elif f["id"] == "embedded_subproject":
                embedded += 1
        res["top_level_projects"].append(
            {"path": prefix, "markers": markers, "nested_count": len(nested_paths), "embedded_count": embedded})
    not_evaluated = n - evaluated
    if stopped_by:
        budget = f"{max_entries}-entry" if stopped_by == "entries" else f"{max_seconds:g}-second"
        findings.append(_finding(
            "could_not_verify", "",
            f"The check used up its {budget} budget after looking inside {evaluated} of {n} projects; "
            f"{not_evaluated} were not checked for nesting.",
            reason=stopped_by, evaluated=evaluated, not_evaluated=not_evaluated))
    elif not_evaluated:
        findings.append(_finding(
            "could_not_verify", "",
            f"Only the first {FOLDER_PROJECTS_CAP} of {n} projects in this folder were looked inside; "
            f"{not_evaluated} were not checked for nesting.",
            reason="project_cap", evaluated=evaluated, not_evaluated=not_evaluated))
    return depth_example


def _classify(rel, markers, has_git, ws_globs, ws_unknown, submodules, gitmodules_unknown, member_roots):
    """Return (kind, [finding ids]) for a project root below the checked root."""
    if rel in submodules:
        return "declared_submodule", []
    ancestor_root = any(rel.startswith(a + "/") for a in member_roots)
    declared = False
    for _name, inc, exc in ws_globs:
        for pat in inc:
            if glob_match(pat, rel) and not any(glob_match(x, rel) for x in exc):
                if _has_wildcard(pat) and ancestor_root and not _literal_reaches_inside(pat, rel, member_roots):
                    continue  # a wildcard never reaches inside another project
                declared = True
    if has_git and gitmodules_unknown:
        return ("declared_member" if declared else "unverified"), ["could_not_verify_git"]
    ids: List[str] = ["git_inside_git"] if has_git else []
    if declared:
        kind = "declared_member"
    elif ws_unknown:
        kind = "unverified"
        ids.insert(0, "could_not_verify_member")
    else:
        kind = "nested"
        ids.insert(0, "nested_project")
    return kind, ids


def _literal_reaches_inside(pattern: str, rel: str, member_roots: Sequence[str]) -> bool:
    """True when the pattern's literal (wildcard-free) leading segments already pass every
    enclosing project root, e.g. 'ui/packages/*' names a place inside the root 'ui' on purpose."""
    literal: List[str] = []
    for seg in pattern.split("/"):
        if _has_wildcard(seg):
            break
        literal.append(seg)
    prefix = "/".join(literal)
    return all(not rel.startswith(a + "/") or prefix.startswith(a + "/") for a in member_roots)


def _root_finding(fid: str, rel: str, depth: int, markers: List[str]) -> Dict[str, Any]:
    if fid == "nested_project":
        return _finding(fid, rel, "This folder is a separate project inside this one and no workspace declaration lists it.",
                        depth=depth, markers=markers)
    if fid == "git_inside_git":
        return _finding(fid, rel, "This folder has its own .git inside the outer project, so a clone of the outer project will contain an empty folder here and its files will be missing.",
                        depth=depth, markers=markers)
    if fid == "could_not_verify_git":
        return _finding("could_not_verify", rel, "This folder has its own .git, but .gitmodules could not be read, so it is unknown whether it is a declared submodule.",
                        depth=depth, markers=markers, reason="declaration_unreadable")
    return _finding("could_not_verify", rel, "This folder is a project, but a declaration file could not be read, so it is unknown whether it is a declared member.",
                    depth=depth, markers=markers, reason="declaration_unreadable")


_FINDING_ORDER = {
    "root_is_home_or_agent_home": 0, "root_is_symlink": 1, "no_project_marker": 2, "folder_of_projects": 2,
    "nested_project": 3, "git_inside_git": 4, "could_not_verify": 5, "embedded_subproject": 6,
    "duplicate_tree_names": 7, "depth_limit_reached": 8, "git_only_root": 9, "many_embedded_subprojects": 6,
}


def _finish(res: Dict[str, Any], *, root_scanned: bool) -> Dict[str, Any]:
    findings = res["findings"]
    findings.sort(key=lambda f: (f["path"] != ".", f["path"], _FINDING_ORDER[f["id"]]))
    ids = {f["id"] for f in findings}
    if "folder_of_projects" in ids:
        status = "not_a_project"  # a folder of separate projects; caps and nesting are findings
    elif ids & {"nested_project", "git_inside_git"}:
        status = "nested_projects_found"
    elif (ids & {"could_not_verify", "root_is_home_or_agent_home", "root_is_symlink"}
          or set(res["limits"]["hit"]) - {"depth"} or not root_scanned):
        status = "could_not_verify"
    elif "no_project_marker" in ids:
        status = "not_a_project"
    else:
        status = "one_project"
    res["status"] = status
    return res


def exit_code(result: Dict[str, Any]) -> int:
    """0 = one project; 1 = blocking finding; 2 = could not verify or not a project."""
    if result["status"] == "not_a_project":
        return 2
    if any(f["id"] in BLOCKING_IDS for f in result["findings"]):
        return 1
    return 0 if result["status"] == "one_project" else 2


# ------------------------------------------------------------------ text output

MAX_TEXT_LINES = 20
NEEDS_A_LOOK_IDS = ("root_is_home_or_agent_home", "root_is_symlink", "no_project_marker",
                    "nested_project", "git_inside_git", "could_not_verify")
DECLARE_HINT = ("To declare a folder as part of this project, list it in the root workspace declaration "
                "(package.json workspaces, pnpm-workspace.yaml, Cargo [workspace], go.work) "
                "or in .adopt/rules.json \"declared_dirs\".")


def format_text(result: Dict[str, Any]) -> str:
    """Short human summary: verdict, 'Needs a look', 'Noted, usually fine', what to do (<= 20 lines)."""
    path = result["path"]
    status = result["status"]
    findings = result["findings"]
    if any(f["id"] == "folder_of_projects" for f in findings):
        return _format_folder(result)
    count = lambda fid: sum(1 for f in findings if f["id"] == fid)  # noqa: E731
    nested, gits, embedded = count("nested_project"), count("git_inside_git"), count("embedded_subproject")
    if status == "one_project":
        noted = f"; {embedded} embedded sub-packages noted" if embedded else ""
        verdict = f"One project: {path} ({result['declared_members']} declared workspace members{noted})."
    elif status == "nested_projects_found":
        verdict = f"Not one project: {path} has {nested} undeclared project roots and {gits} inner .git folders inside it."
    elif status == "not_a_project":
        verdict = f"Not a project: {path} has no project file at the top."
    else:
        verdict = f"Could not verify {path}: the check could not finish or could not decide."
    for f in findings:
        if f["id"] == "root_is_home_or_agent_home":
            verdict = f"Not one project: {path} is {f['detail']['kind']}."

    look = [f for f in findings if f["id"] in NEEDS_A_LOOK_IDS]
    noted_lines: List[str] = []
    by_reason: Dict[str, List[str]] = {}
    for f in findings:
        if f["id"] == "embedded_subproject":
            by_reason.setdefault(f["detail"]["reason"], []).append(f["path"])
    for reason in EMBEDDED_ORDER:
        if reason in by_reason:
            paths = by_reason[reason]
            noted_lines.append(f"- [embedded_subproject] {len(paths)} x {reason}, e.g. {paths[0]}")
    for f in findings:
        if f["id"] == "many_embedded_subprojects":
            noted_lines.append(f"- [many_embedded_subprojects] {f['path']}: {f['detail']['count']} embedded "
                               f"sub-packages (more than {f['detail']['cap']}); check none is live work")
        elif f["id"] == "git_only_root":
            noted_lines.append(f"- [git_only_root] {f['path']}: {f['sentence']}")
    dups = [f["path"] for f in findings if f["id"] == "duplicate_tree_names"]
    if dups:
        noted_lines.append(f"- [duplicate_tree_names] {len(dups)} folder names look like copies, e.g. {', '.join(dups[:3])}")
    for f in findings:
        if f["id"] == "depth_limit_reached":
            noted_lines.append(f"- [depth_limit_reached] {f['detail']['folders_not_entered']} folders deeper than "
                               f"{f['detail']['max_depth']} levels not entered, e.g. {f['detail']['example']}")
    nexts: List[str] = []
    for f in look:
        if f["next"] not in nexts:
            nexts.append(f["next"])
    nexts = nexts[:3]

    fixed = 1 + (1 + len(noted_lines) if noted_lines else 0) + (1 + len(nexts) if nexts else 0) + 1
    lines = [verdict]
    if look:
        room = max(1, MAX_TEXT_LINES - fixed - 1)  # minus the 'Needs a look:' header
        shown = look if len(look) <= room else look[:room - 1]
        lines.append("Needs a look:")
        lines.extend(f"- [{f['id']}] {f['path']}: {f['sentence']}" for f in shown)
        if len(shown) < len(look):
            lines.append(f"... and {len(look) - len(shown)} more (use --json for all of them).")
    if noted_lines:
        lines.append("Noted, usually fine:")
        lines.extend(noted_lines)
    if nexts:
        lines.append("What to do:")
        lines.extend(f"  {i}. {n}" for i, n in enumerate(nexts, 1))
    lines.append(DECLARE_HINT)
    return "\n".join(lines[:MAX_TEXT_LINES - 1] + [DECLARE_HINT] if len(lines) > MAX_TEXT_LINES else lines)



def _format_folder(result: Dict[str, Any]) -> str:
    """Text for a folder of separate projects: plain verdict, then where nesting was found."""
    findings = result["findings"]
    fop = next(f for f in findings if f["id"] == "folder_of_projects")
    n = fop["detail"]["projects"]
    lines = [f"Not a project: {result['path']} is not a project itself; it holds {n} separate projects, "
             f"and each can be checked on its own."]
    nested = [t for t in result["top_level_projects"] if t["nested_count"]]
    lines.extend(f"Needs a look inside: {t['path']} ({t['nested_count']})" for t in nested[:FOLDER_TEXT_CAP])
    if len(nested) > FOLDER_TEXT_CAP:
        lines.append(f"... and {len(nested) - FOLDER_TEXT_CAP} more projects with nesting (use --json for all of them).")
    cnv = [f for f in findings if f["id"] == "could_not_verify"]
    if cnv:
        lines.append(f"Could not verify {len(cnv)} things, e.g. {cnv[0]['path']}: {cnv[0]['sentence']}")
    lines.append("What to do:")
    example = (nested or result["top_level_projects"] or [{"path": "<project>"}])[0]["path"]
    lines.append(f"  1. {fop['next']} For example: hermes defuzz check {result['path']}/{example}")
    return "\n".join(lines)
