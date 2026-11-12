"""One-call LLM folder-rule proposer, strict allowlist validator, and deterministic rule expander.

Invariants:
- Exactly ONE model call via Hermes's ctx.llm (never per-file model calls, never retries/loops).
- Model output is untrusted data: validated against fixed allowlists (keep/move/archive; track/lfs/ignore/untrack).
- 'delete' or 'remove' is never in the allowlist and is unconditionally rejected.
- Local secret locks (git_policy='ignore') and special-path rules cannot be weakened by model output.
- Expansion is deterministic and refuses equal-specificity conflicts or destination collisions.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .safety import SafetyError

ALLOWED_DISPOSITIONS: frozenset[str] = frozenset({"keep", "move", "archive"})
ALLOWED_GIT_POLICIES: frozenset[str] = frozenset({"track", "lfs", "ignore", "untrack"})

_SAFE_REL_RE = re.compile(r"^[A-Za-z0-9_./@+,()~=\[\]-]+$")
_SAFE_EXT_RE = re.compile(r"^\.[a-z0-9_+-]{1,16}$")
_SAFE_GLOB_RE = re.compile(r"^[A-Za-z0-9_.*+/?!\[\]-]+$")

FOLDER_RULES_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "project_slug": {"type": "string"},
        "declared_dirs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "dir": {"type": "string"},
                    "summary": {"type": "string"},
                    "why": {"type": "string"},
                    "source": {"type": "string", "enum": ["explicit", "fallback"]},
                },
                "required": ["dir", "summary", "why"],
            },
        },
        "folder_rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "match": {"type": "string", "description": "Directory prefix (e.g. 'dist', '.', '.hermes/plans')"},
                    "ext": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional lowercase extensions e.g. ['.png', '.md']",
                    },
                    "disposition": {"type": "string", "enum": ["keep", "move", "archive"]},
                    "git_policy": {"type": "string", "enum": ["track", "lfs", "ignore", "untrack"]},
                    "to": {"type": "string", "description": "Destination folder prefix for move/archive"},
                    "reason": {"type": "string"},
                },
                "required": ["match", "disposition", "git_policy", "reason"],
            },
        },
        "placement_rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string"},
                    "match_ext": {"type": "array", "items": {"type": "string"}},
                    "match_glob": {"type": "array", "items": {"type": "string"}},
                    "root_only": {"type": "boolean"},
                    "dest_dir": {"type": "string"},
                    "lfs": {"type": "boolean"},
                    "reason": {"type": "string"},
                    "source": {"type": "string", "enum": ["explicit", "fallback"]},
                },
                "required": ["kind", "match_ext", "dest_dir", "lfs", "reason"],
            },
        },
        "ignore_patterns": {"type": "array", "items": {"type": "string"}},
        "lfs_patterns": {"type": "array", "items": {"type": "string"}},
        "protected_root_files": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "project_slug",
        "declared_dirs",
        "folder_rules",
        "placement_rules",
        "ignore_patterns",
        "lfs_patterns",
    ],
}

# Well-known root files of today's ecosystems: agent instructions, governance and community
# files, and release notes. Case rule: the conventional UPPERCASE stem, alone or with one of
# the usual text extensions (so SUPPORT.md is kept, but support-matrix.md and
# SUPPORTED_VERSIONS.md are ordinary notes). Expanded to exact names so every mode, and
# adopt apply, read the same list. ROADMAP is left out: many projects keep it in docs/.
_WELLKNOWN_ROOT_STEMS: Tuple[str, ...] = (
    "AGENTS", "AGENT", "CLAUDE", "GEMINI", "COPILOT", "CONVENTIONS", "WARP", "QWEN", "CRUSH",
    "DCO", "ACKNOWLEDGMENTS", "ACKNOWLEDGEMENTS",
    "README", "LICENSE", "LICENCE", "COPYING", "NOTICE",
    "AUTHORS", "CONTRIBUTORS", "MAINTAINERS", "GOVERNANCE", "SUPPORT", "CODEOWNERS",
    "CODE_OF_CONDUCT", "SECURITY", "CONTRIBUTING", "PULL_REQUEST_TEMPLATE", "ISSUE_TEMPLATE",
    "THIRD_PARTY", "THIRD_PARTY_NOTICES", "THIRD_PARTY_LICENSES", "THIRD-PARTY-NOTICES",
    "THIRD-PARTY-LICENSES", "PATENTS", "TRADEMARK", "TRADEMARKS",
    "CHANGELOG", "CHANGES", "HISTORY", "NEWS", "RELEASES", "RELEASE_NOTES", "RELEASE-NOTES",
    "UPGRADING", "MIGRATING", "MIGRATION",
)
_WELLKNOWN_ROOT_EXTS: Tuple[str, ...] = ("", ".md", ".txt", ".rst", ".markdown", ".adoc", ".org")
WELLKNOWN_ROOT_FILES: Tuple[str, ...] = tuple(
    f"{stem}{ext}" for stem in _WELLKNOWN_ROOT_STEMS for ext in _WELLKNOWN_ROOT_EXTS
) + (
    "llms.txt", "llms-full.txt", "CITATION.cff", "CITATION.bib", "FUNDING.yml",
    ".cursorrules", ".windsurfrules", "COMPONENTS.md", "00-INDEX.md",
)

# Protected root files that must never be moved out of root (used by adopt apply and full
# placement mode; declared_only mode reads this set too, through PROTECTED_ROOT_TABLE)
PROTECTED_ROOT_FILES: frozenset[str] = frozenset(WELLKNOWN_ROOT_FILES) | frozenset({
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "THEMING.md",
    "TOOLS.lock",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "pyproject.toml",
    "Cargo.toml",
    "Makefile",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".worktreeinclude",
})

# Single documented table of protected root build, manifest, lockfile, tooling, CI, and governance
# paths for 'declared_only' placement mode. Root files matching any entry (or named as an entry
# file in a root manifest, or listed in rules.json 'protected_root_files') are never redirected.
PROTECTED_ROOT_TABLE: Tuple[Dict[str, Any], ...] = (
    {
        "category": "governance_and_docs",
        "description": "Root documentation, licensing, agent instructions, and tool lockfile",
        "exact": (
            "AGENTS.md", "CLAUDE.md", "TOOLS.lock", "THEMING.md", "COMPONENTS.md", "00-INDEX.md",
        ),
        "globs": (
            "README*", "LICENSE*", "LICENCE*", "COPYING*", "NOTICE*",
            "CHANGELOG*", "CHANGES*", "CONTRIBUTING*", "CODE_OF_CONDUCT*", "SECURITY*",
        ),
        "root_dirs": (),
    },
    {
        "category": "wellknown_root_files",
        "description": "Agent instructions, governance and community files, and release notes",
        "exact": WELLKNOWN_ROOT_FILES,
        "globs": (),
        "root_dirs": (),
    },
    {
        "category": "dotfiles_and_ci",
        "description": "Root dotfiles, editor/linter configs, and CI/VCS/tooling directories",
        "exact": (
            ".gitignore", ".gitattributes", ".gitmodules", ".editorconfig", ".env.example",
            ".worktreeinclude", ".npmrc", ".nvmrc", ".clang-format", ".clang-tidy",
            ".golangci.yml", ".golangci.yaml", ".dockerignore",
        ),
        "globs": (".*",),
        "root_dirs": (
            ".github", ".gitlab", ".circleci", ".buildkite", ".cargo", ".devcontainer",
            ".vscode", ".idea", ".husky", ".adopt", ".git", ".hermes", "ci", ".ci",
        ),
    },
    {
        "category": "containers_and_build",
        "description": "Containers, Compose specs, Make/CMake/Meson/Bazel/Ninja and task runners",
        "exact": (
            "Dockerfile", "Containerfile", "Makefile", "GNUmakefile", "makefile",
            "CMakeLists.txt", "CMakePresets.json", "CMakeUserPresets.json",
            "meson.build", "meson_options.txt", "meson.options", "conanfile.txt", "conanfile.py",
            "vcpkg.json", "Justfile", "justfile", "Taskfile.yml", "Taskfile.yaml",
            "Earthfile", "Tiltfile", "Vagrantfile", "Procfile", "Jenkinsfile",
            "BUILD", "BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel",
            "SConstruct", "Makefile.am", "configure.ac",
        ),
        "globs": (
            "Dockerfile*", "*.dockerfile", "Containerfile*",
            "docker-compose*", "compose.yml", "compose.yaml", "compose.*.yml", "compose.*.yaml",
            "*.mk",
        ),
        "root_dirs": (),
    },
    {
        "category": "python",
        "description": "Python manifests, lockfiles, packaging metadata, and tool configs",
        "exact": (
            "pyproject.toml", "setup.py", "setup.cfg", "MANIFEST.in", "requirements.txt",
            "Pipfile", "Pipfile.lock", "uv.lock", "poetry.lock", "pdm.lock", "pylock.toml",
            "conda-lock.yml", "environment.yml", "environment.yaml",
            "tox.ini", "noxfile.py", "pytest.ini", "mypy.ini", "ruff.toml",
            "pyrightconfig.json", "alembic.ini", "manage.py",
        ),
        "globs": ("requirements*.txt", "constraints*.txt"),
        "root_dirs": (),
    },
    {
        "category": "javascript_typescript",
        "description": "Node, TypeScript, Deno, and Bun manifests, lockfiles, workspaces, and bundler configs",
        "exact": (
            "package.json", "package-lock.json", "npm-shrinkwrap.json",
            "pnpm-lock.yaml", "pnpm-workspace.yaml", "yarn.lock", "bun.lock", "bun.lockb",
            "deno.json", "deno.jsonc", "deno.lock", "tsconfig.json", "jsconfig.json",
            "biome.json", "biome.jsonc", "turbo.json", "nx.json", "lerna.json",
        ),
        "globs": (
            "tsconfig*.json", "jsconfig*.json",
            "*.config.js", "*.config.cjs", "*.config.mjs", "*.config.ts", "*.config.mts",
        ),
        "root_dirs": (),
    },
    {
        "category": "rust",
        "description": "Cargo manifests, lockfiles, build scripts, and Rust toolchain/lint configs",
        "exact": (
            "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain",
            "rust-toolchain.toml", "rustfmt.toml", "clippy.toml", "deny.toml", "Cross.toml",
        ),
        "globs": (),
        "root_dirs": (),
    },
    {
        "category": "go",
        "description": "Go module and workspace manifests and checksum files",
        "exact": ("go.mod", "go.sum", "go.work", "go.work.sum"),
        "globs": (),
        "root_dirs": (),
    },
    {
        "category": "dotnet",
        "description": ".NET solutions, project files, MSBuild props/targets, NuGet, and SDK pins",
        "exact": (
            "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props",
            "NuGet.Config", "nuget.config", "global.json", "packages.lock.json", "dotnet-tools.json",
        ),
        "globs": ("*.sln", "*.slnx", "*.csproj", "*.fsproj", "*.vbproj", "*.props", "*.targets"),
        "root_dirs": (),
    },
    {
        "category": "jvm_and_polyglot",
        "description": "Gradle, Maven, Ruby, PHP, Elixir, Dart/Flutter, Swift, and Godot root manifests",
        "exact": (
            "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
            "gradle.properties", "gradlew", "gradlew.bat", "pom.xml", "mvnw", "mvnw.cmd",
            "Gemfile", "Gemfile.lock", "Rakefile", "composer.json", "composer.lock",
            "mix.exs", "mix.lock", "pubspec.yaml", "pubspec.lock",
            "Package.swift", "Package.resolved", "project.godot",
        ),
        "globs": ("build.gradle*", "settings.gradle*"),
        "root_dirs": (),
    },
)

_PROTECTED_ROOT_EXACT: frozenset[str] = frozenset(
    name for row in PROTECTED_ROOT_TABLE for name in row.get("exact", ())
) | PROTECTED_ROOT_FILES
_PROTECTED_ROOT_GLOBS_LOWER: Tuple[str, ...] = tuple(
    pat.lower() for row in PROTECTED_ROOT_TABLE for pat in row.get("globs", ())
)
_PROTECTED_ROOT_DIRS: frozenset[str] = frozenset(
    d for row in PROTECTED_ROOT_TABLE for d in row.get("root_dirs", ())
)
_MAX_MANIFEST_READ_BYTES = 1024 * 1024
_PY_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_CMAKE_TARGET_RE = re.compile(
    r"\badd_(?:executable|library)\s*\(\s*[^\s)]+\s+([^)]+)\)",
    re.IGNORECASE | re.MULTILINE,
)
_CMAKE_TARGET_KEYWORDS = frozenset({
    "STATIC", "SHARED", "MODULE", "OBJECT", "INTERFACE", "WIN32", "MACOSX_BUNDLE", "EXCLUDE_FROM_ALL",
})


def _read_manifest_nofollow(proj_root: Path, filename: str) -> Optional[str]:
    """Read a fixed non-secret root manifest without following symlinks; None on any error."""
    target = Path(proj_root) / filename
    try:
        st = os.lstat(target)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_MANIFEST_READ_BYTES:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target), flags)
    except OSError:
        return None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_size > _MAX_MANIFEST_READ_BYTES:
            os.close(fd)
            return None
        with os.fdopen(fd, "rb") as fh:
            return fh.read(_MAX_MANIFEST_READ_BYTES + 1).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _load_manifest_dict(root: Path, filename: str, loads: Any) -> Optional[Dict[str, Any]]:
    """Read a root manifest and parse it with ``loads``; None unless it parses to a dict."""
    raw = _read_manifest_nofollow(root, filename)
    if raw is None:
        return None
    try:
        data = loads(raw)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _clean_manifest_rel_path(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    val = raw.strip().replace("\\", "/")
    while val.startswith("./"):
        val = val[2:]
    val = val.strip("/")
    if not val or "*" in val or "?" in val or val.startswith(".."):
        return None
    parts = PurePosixPath(val).parts
    if any(p in ("", ".", "..", "node_modules") for p in parts):
        return None
    return "/".join(parts)


def _collect_package_json_exports(out: Set[str], node: Any, depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(node, str):
        cleaned = _clean_manifest_rel_path(node)
        if cleaned:
            out.add(cleaned)
    elif isinstance(node, dict):
        for val in node.values():
            _collect_package_json_exports(out, val, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _collect_package_json_exports(out, item, depth + 1)


def _add_clean_entry(entries: Set[str], raw: Any) -> None:
    cleaned = _clean_manifest_rel_path(raw)
    if cleaned:
        entries.add(cleaned)


def _add_py_module_entry(entries: Set[str], mod: str) -> None:
    rel_mod = mod.replace(".", "/") + ".py"
    entries.add(rel_mod)
    entries.add(f"src/{rel_mod}")


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _add_package_json_entries(entries: Set[str], root: Path) -> None:
    """package.json: main, module, types, typings, unpkg, jsdelivr, browser, bin, exports."""
    pkg = _load_manifest_dict(root, "package.json", json.loads)
    if pkg is None:
        return
    for key in ("main", "module", "types", "typings", "unpkg", "jsdelivr", "browser"):
        _add_clean_entry(entries, pkg.get(key))
    bin_field = pkg.get("bin")
    if isinstance(bin_field, str):
        _add_clean_entry(entries, bin_field)
    elif isinstance(bin_field, dict):
        for bval in bin_field.values():
            _add_clean_entry(entries, bval)
    if "exports" in pkg:
        _collect_package_json_exports(entries, pkg["exports"])


def _add_script_map_entries(entries: Set[str], script_map: Any) -> None:
    if not isinstance(script_map, dict):
        return
    for spec in script_map.values():
        if isinstance(spec, str):
            mod = spec.split(":", 1)[0].strip()
            if _PY_IDENT_RE.match(mod):
                _add_py_module_entry(entries, mod)


def _add_pyproject_entries(entries: Set[str], root: Path) -> None:
    """pyproject.toml: project.scripts, project.gui-scripts, tool.poetry.scripts, tool.setuptools.py-modules."""
    pyproj = _load_manifest_dict(root, "pyproject.toml", tomllib.loads)
    if pyproj is None:
        return
    proj_tbl = _dict_or_empty(pyproj.get("project"))
    tool_tbl = _dict_or_empty(pyproj.get("tool"))
    poetry_tbl = _dict_or_empty(tool_tbl.get("poetry"))
    for script_map in (
        proj_tbl.get("scripts"),
        proj_tbl.get("gui-scripts"),
        poetry_tbl.get("scripts"),
    ):
        _add_script_map_entries(entries, script_map)
    setuptools_tbl = _dict_or_empty(tool_tbl.get("setuptools"))
    py_mods = setuptools_tbl.get("py-modules")
    if isinstance(py_mods, list):
        for mod in py_mods:
            if isinstance(mod, str) and _PY_IDENT_RE.match(mod.strip()):
                _add_py_module_entry(entries, mod.strip())


def _add_cargo_entries(entries: Set[str], root: Path) -> None:
    """Cargo.toml: package.build, lib.path, [[bin]]/[[example]]/[[bench]]/[[test]].path."""
    cargo = _load_manifest_dict(root, "Cargo.toml", tomllib.loads)
    if cargo is None:
        return
    _add_clean_entry(entries, _dict_or_empty(cargo.get("package")).get("build"))
    _add_clean_entry(entries, _dict_or_empty(cargo.get("lib")).get("path"))
    for list_key in ("bin", "example", "bench", "test"):
        items = cargo.get(list_key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    _add_clean_entry(entries, item.get("path"))


def _add_cmake_entries(entries: Set[str], root: Path) -> None:
    """CMakeLists.txt: source files named directly in add_executable / add_library."""
    cmake_raw = _read_manifest_nofollow(root, "CMakeLists.txt")
    if cmake_raw is None:
        return
    for match in _CMAKE_TARGET_RE.finditer(cmake_raw):
        for tok in match.group(1).split():
            tok_clean = tok.strip("\"'")
            if "$" in tok_clean or tok_clean.upper() in _CMAKE_TARGET_KEYWORDS:
                continue
            if tok_clean.lower().endswith((".c", ".cc", ".cpp", ".cxx")):
                _add_clean_entry(entries, tok_clean)


def extract_manifest_entry_files(proj_root: Optional[Path]) -> Set[str]:
    """Extract normalized relative entry-file paths declared in root manifests (never raises)."""
    entries: Set[str] = set()
    if proj_root is None:
        return entries
    try:
        root = Path(proj_root)
    except Exception:
        return entries

    _add_package_json_entries(entries, root)
    _add_pyproject_entries(entries, root)
    _add_cargo_entries(entries, root)
    _add_cmake_entries(entries, root)
    return entries


def is_protected_root_path(
    rel_path: str,
    *,
    proj_root: Optional[Path] = None,
    rules_data: Optional[Dict[str, Any]] = None,
) -> bool:
    """Return True when rel_path is a protected root build/manifest/config/CI/entry path."""
    try:
        norm = os.path.normpath(str(rel_path)).replace("\\", "/").lstrip("/")
    except Exception:
        return False
    if not norm or norm == "." or norm.startswith(".."):
        return False
    parts = PurePosixPath(norm).parts
    if not parts or ".." in parts:
        return False

    top, filename = parts[0], parts[-1]
    if top.startswith(".") or top in _PROTECTED_ROOT_DIRS:
        return True

    if len(parts) == 1:
        if filename.startswith(".") or filename in _PROTECTED_ROOT_EXACT:
            return True
        fname_lower = filename.lower()
        if any(fnmatch.fnmatchcase(fname_lower, pat) for pat in _PROTECTED_ROOT_GLOBS_LOWER):
            return True

    if isinstance(rules_data, dict):
        for pat in rules_data.get("protected_root_files") or ():
            if not isinstance(pat, str) or not pat.strip():
                continue
            clean_pat = pat.strip().replace("\\", "/").lstrip("/")
            if "/" in clean_pat:
                if fnmatch.fnmatchcase(norm, clean_pat) or norm.startswith(clean_pat.rstrip("/") + "/"):
                    return True
            elif len(parts) == 1 and fnmatch.fnmatchcase(filename, clean_pat):
                return True

    if proj_root is not None and norm in extract_manifest_entry_files(proj_root):
        return True

    return False


def _validate_safe_rel_prefix(raw: str, field_name: str, *, allow_dot: bool = True) -> str:
    val = str(raw or "").strip().replace("\\", "/")
    if val == "." and allow_dot:
        return "."
    val = val.strip("/")
    if not val:
        if allow_dot:
            return "."
        raise SafetyError(f"Empty path in {field_name}")
    if not _SAFE_REL_RE.match(val):
        raise SafetyError(f"Unsafe characters in {field_name}: {raw!r}")
    parts = PurePosixPath(val).parts
    for p in parts:
        if p in ("", ".", "..") or p == ".git" or p == ".adopt":
            raise SafetyError(f"Forbidden path segment {p!r} in {field_name}: {raw!r}")
    return "/".join(parts)


def _validate_extensions(exts: Optional[Sequence[str]], field_name: str) -> List[str]:
    if not exts:
        return []
    out: List[str] = []
    for e in exts:
        s = str(e).strip().lower()
        if not s.startswith("."):
            s = "." + s
        if not _SAFE_EXT_RE.match(s):
            raise SafetyError(f"Invalid extension {e!r} in {field_name}")
        if s not in out:
            out.append(s)
    return sorted(out)


def _validate_glob_patterns(patterns: Optional[Sequence[str]], field_name: str) -> List[str]:
    if not patterns:
        return []
    out: List[str] = []
    for pat in patterns:
        s = str(pat).strip()
        if not s:
            continue
        if ".." in s or not _SAFE_GLOB_RE.match(s):
            raise SafetyError(f"Unsafe pattern {pat!r} in {field_name}")
        if s not in out:
            out.append(s)
    return out


def _validate_folder_rule(idx: int, r: dict[str, Any]) -> dict[str, Any]:
    disp = str(r.get("disposition") or "").strip().lower()
    if disp not in ALLOWED_DISPOSITIONS:
        raise SafetyError(
            f"folder_rules[{idx}].disposition={disp!r} is not in allowlist {sorted(ALLOWED_DISPOSITIONS)}"
        )
    git_pol = str(r.get("git_policy") or "").strip().lower()
    if git_pol not in ALLOWED_GIT_POLICIES:
        raise SafetyError(
            f"folder_rules[{idx}].git_policy={git_pol!r} is not in allowlist {sorted(ALLOWED_GIT_POLICIES)}"
        )
    match_prefix = _validate_safe_rel_prefix(r.get("match", "."), f"folder_rules[{idx}].match", allow_dot=True)
    exts = _validate_extensions(r.get("ext"), f"folder_rules[{idx}].ext")

    # Never reshuffle source or test trees.
    if match_prefix.split("/", 1)[0] in {"src", "tests", "test"} and disp != "keep":
        raise SafetyError(f"Refusing to move or archive inside src/, tests/, or test/: folder_rules[{idx}]")

    to_prefix = ""
    if disp == "move":
        to_prefix = _validate_safe_rel_prefix(r.get("to", ""), f"folder_rules[{idx}].to", allow_dot=False)
    elif disp == "archive":
        raw_to = r.get("to") or f"_archive/{match_prefix if match_prefix != '.' else 'root'}"
        to_prefix = _validate_safe_rel_prefix(raw_to, f"folder_rules[{idx}].to", allow_dot=False)
        if not (to_prefix == "_archive" or to_prefix.startswith("_archive/")):
            to_prefix = f"_archive/{to_prefix}"

    reason = " ".join(str(r.get("reason") or "organized by folder rule").split())[:120]
    return {
        "match": match_prefix,
        "ext": exts,
        "disposition": disp,
        "git_policy": git_pol,
        "to": to_prefix,
        "reason": reason,
    }


def _validate_placement_rule(idx: int, pr: dict[str, Any]) -> dict[str, Any]:
    kind = re.sub(r"[^a-z0-9_-]", "", str(pr.get("kind") or f"kind_{idx}").lower())[:24] or f"kind_{idx}"
    exts = _validate_extensions(pr.get("match_ext"), f"placement_rules[{idx}].match_ext")
    globs = _validate_glob_patterns(pr.get("match_glob"), f"placement_rules[{idx}].match_glob")
    if not exts and not globs:
        raise SafetyError(f"placement_rules[{idx}].match_ext must be non-empty")
    dest_dir = _validate_safe_rel_prefix(pr.get("dest_dir", "_inbox"), f"placement_rules[{idx}].dest_dir", allow_dot=False)
    lfs_flag = bool(pr.get("lfs", False))
    reason = " ".join(str(pr.get("reason") or f"route {kind} files to {dest_dir}").split())[:100]
    raw_root_only = pr.get("root_only")
    if raw_root_only is not None and not isinstance(raw_root_only, bool):
        raise SafetyError(f"placement_rules[{idx}].root_only={raw_root_only!r} must be a boolean")
    raw_source = pr.get("source")
    if raw_source is not None and raw_source not in ("explicit", "fallback"):
        raise SafetyError(f"placement_rules[{idx}].source={raw_source!r} must be 'explicit' or 'fallback'")
    clean_pr: Dict[str, Any] = {
        "kind": kind,
        "match_ext": exts,
        "dest_dir": dest_dir,
        "lfs": lfs_flag,
        "reason": reason,
    }
    if globs:
        clean_pr["match_glob"] = globs
    if raw_root_only is True:
        clean_pr["root_only"] = True
    if raw_source in ("explicit", "fallback"):
        clean_pr["source"] = raw_source
    return clean_pr


def _register_folder_rule_specificity(
    seen_specificity: Dict[Tuple[str, Tuple[str, ...]], Dict[str, Any]], clean_rule: Dict[str, Any]
) -> None:
    """Record clean_rule by (match, ext); refuse an equal-specificity rule with a different outcome."""
    match_prefix = clean_rule["match"]
    exts = clean_rule["ext"]
    spec_key = (match_prefix, tuple(exts))
    prev = seen_specificity.get(spec_key)
    if prev is not None and (
        prev["disposition"] != clean_rule["disposition"]
        or prev["to"] != clean_rule["to"]
        or prev["git_policy"] != clean_rule["git_policy"]
    ):
        raise SafetyError(
            f"Conflicting equal-specificity folder_rules for match={match_prefix!r} ext={exts!r}"
        )
    seen_specificity[spec_key] = clean_rule


def validate_rules_spec(raw_spec: Dict[str, Any], inventory: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate untrusted model/user rules spec against fixed allowlists."""
    if not isinstance(raw_spec, dict):
        raise SafetyError("Rules spec must be a JSON object")

    slug_raw = str(raw_spec.get("project_slug") or "adopted-project").strip().lower()
    slug = re.sub(r"[^a-z0-9_-]+", "-", slug_raw).strip("-") or "adopted-project"

    raw_folder_rules = raw_spec.get("folder_rules")
    if not isinstance(raw_folder_rules, list):
        raise SafetyError("folder_rules must be a list")
    if len(raw_folder_rules) > 100:
        raise SafetyError(f"Too many folder_rules ({len(raw_folder_rules)} > 100)")

    validated_folder_rules: List[Dict[str, Any]] = []
    seen_specificity: Dict[Tuple[str, Tuple[str, ...]], Dict[str, Any]] = {}

    for idx, r in enumerate(raw_folder_rules):
        if not isinstance(r, dict):
            raise SafetyError(f"folder_rules[{idx}] must be an object")
        clean_rule = _validate_folder_rule(idx, r)
        _register_folder_rule_specificity(seen_specificity, clean_rule)
        validated_folder_rules.append(clean_rule)

    # Validate placement_rules
    raw_place = raw_spec.get("placement_rules") or []
    if not isinstance(raw_place, list):
        raise SafetyError("placement_rules must be a list")
    validated_place: List[Dict[str, Any]] = []
    for idx, pr in enumerate(raw_place):
        if not isinstance(pr, dict):
            raise SafetyError(f"placement_rules[{idx}] must be an object")
        validated_place.append(_validate_placement_rule(idx, pr))

    # Validate declared_dirs
    raw_dirs = raw_spec.get("declared_dirs") or []
    declared_dirs: List[Dict[str, str]] = []
    if isinstance(raw_dirs, dict):
        for k, v in raw_dirs.items():
            if isinstance(v, dict):
                declared_dirs.append({
                    "dir": _validate_safe_rel_prefix(k, "declared_dirs.key", allow_dot=False),
                    "summary": str(v.get("summary") or "project directory")[:80],
                    "why": str(v.get("why") or "declared project folder")[:100],
                })
    elif isinstance(raw_dirs, list):
        for idx, item in enumerate(raw_dirs):
            if not isinstance(item, dict):
                continue
            d = _validate_safe_rel_prefix(item.get("dir", ""), f"declared_dirs[{idx}].dir", allow_dot=False)
            dir_source = item.get("source")
            if dir_source is not None and dir_source not in ("explicit", "fallback"):
                raise SafetyError(f"declared_dirs[{idx}].source={dir_source!r} must be 'explicit' or 'fallback'")
            entry_dir: Dict[str, str] = {
                "dir": d,
                "summary": str(item.get("summary") or "project directory")[:80],
                "why": str(item.get("why") or "declared project folder")[:100],
            }
            if dir_source in ("explicit", "fallback"):
                entry_dir["source"] = dir_source
            declared_dirs.append(entry_dir)

    ignore_patterns = _validate_glob_patterns(raw_spec.get("ignore_patterns"), "ignore_patterns")
    lfs_patterns = _validate_glob_patterns(raw_spec.get("lfs_patterns"), "lfs_patterns")
    protected_extra = _validate_glob_patterns(raw_spec.get("protected_root_files"), "protected_root_files")

    # Ensure mandatory ignore patterns for secrets and junk dirs from inventory
    if inventory is not None:
        for j in inventory.get("junk_dirs") or []:
            jp = f"{j['path'].rstrip('/')}/"
            if jp not in ignore_patterns:
                ignore_patterns.append(jp)
        for s in inventory.get("secrets_flagged") or []:
            sp = s["path"]
            if ".." not in sp and _SAFE_GLOB_RE.match(sp) and sp not in ignore_patterns:
                ignore_patterns.append(sp)
        if ".adopt/place-log.json" not in ignore_patterns:
            ignore_patterns.append(".adopt/place-log.json")

    out_spec: Dict[str, Any] = {
        "schema": 1,
        "schema_version": 1,
        "project_slug": slug,
        "declared_dirs": declared_dirs,
        "folder_rules": validated_folder_rules,
        "placement_rules": validated_place,
        "ignore_patterns": ignore_patterns,
        "lfs_patterns": lfs_patterns,
    }
    if protected_extra:
        out_spec["protected_root_files"] = protected_extra
    return out_spec


def build_deterministic_fallback_rules(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """Build deterministic folder & placement rules from inventory summary (used if LLM output is unavailable)."""
    summary = inventory.get("model_summary") or {}
    folder_name = str(summary.get("folder_name") or "project")
    slug = re.sub(r"[^a-z0-9_-]+", "-", folder_name.lower()).strip("-") or "project"

    dir_summaries = inventory.get("dir_summaries") or {}
    actual_top_dirs: Set[str] = {
        d.split("/", 1)[0]
        for d in (*dir_summaries.keys(), *(inventory.get("empty_dirs") or ()))
        if isinstance(d, str) and d and d != "."
    }

    folder_rules: List[Dict[str, Any]] = []
    declared_dirs: List[Dict[str, str]] = []
    for fixed_dir, fixed_summary, fixed_why in (
        ("docs", "documentation and plans", "centralize markdown docs and architecture notes"),
        ("assets", "static media and binary assets", "separate source assets from build output"),
        ("_inbox", "unclassified incoming files", "catch unknown file kinds without prompting"),
        ("_archive", "archived scratch and legacy clutter", "preserve retired bytes without deletion"),
    ):
        d_entry: Dict[str, str] = {"dir": fixed_dir, "summary": fixed_summary, "why": fixed_why}
        if fixed_dir not in actual_top_dirs or fixed_dir in {"_inbox", "_archive"}:
            d_entry["source"] = "fallback"
        declared_dirs.append(d_entry)

    dir_Set = {d["dir"] for d in declared_dirs}
    if "src" in dir_summaries and "src" not in dir_Set:
        declared_dirs.insert(0, {"dir": "src", "summary": "source code", "why": "preserve existing source package layout"})
        folder_rules.append({
            "match": "src",
            "ext": [],
            "disposition": "keep",
            "git_policy": "track",
            "to": "",
            "reason": "never reshuffle existing src package",
        })
    if "wiki" in dir_summaries and "wiki" not in dir_Set:
        declared_dirs.append({"dir": "wiki", "summary": "knowledge base", "why": "preserve structured wiki pages"})
        folder_rules.append({
            "match": "wiki",
            "ext": [],
            "disposition": "keep",
            "git_policy": "track",
            "to": "",
            "reason": "keep structured wiki intact",
        })

    existing_dirs = {d["dir"] for d in declared_dirs}
    for dirname in sorted(dir_summaries):
        if dirname != "." and "/" not in dirname and dirname not in existing_dirs:
            declared_dirs.append({
                "dir": dirname,
                "summary": "existing project directory",
                "why": "preserve existing top-level project layout",
            })
            existing_dirs.add(dirname)

    # Handle mixed cache dirs (e.g. dist/ in cTile containing tracked assets + untracked build output)
    for mcd in inventory.get("mixed_cache_dirs") or []:
        mpath = mcd["path"]
        folder_rules.extend([
            {
                "match": mpath,
                "ext": [".png", ".svg", ".jpg", ".jpeg", ".gif", ".ico", ".xml", ".compiled", ".css", ".json", ".sh"],
                "disposition": "move",
                "git_policy": "track",
                "to": "assets/dist-static",
                "reason": "preserve static assets from mixed build folder",
            },
            {
                "match": mpath,
                "ext": [".js", ".mjs", ".cjs", ".map"],
                "disposition": "archive",
                "git_policy": "ignore",
                "to": f"_archive/{mpath}-build",
                "reason": "archive ephemeral compiled JS output out of mixed dist folder",
            },
        ])

    # Handle .hermes/plans -> docs/plans
    if any(sp.get("path") == ".hermes/plans" for sp in (inventory.get("special_paths") or [])):
        folder_rules.append({
            "match": ".hermes/plans",
            "ext": [".md"],
            "disposition": "move",
            "git_policy": "track",
            "to": "docs/plans",
            "reason": "relocate project plans into canonical docs/plans folder",
        })

    # If root has loose .md files (for example a trashed design folder with hundreds of .md files), organize into docs/
    root_stats = dir_summaries.get(".") or {}
    if ".md" in (root_stats.get("extensions") or []) and root_stats.get("file_count", 0) > 5:
        folder_rules.append({
            "match": ".",
            "ext": [".md"],
            "disposition": "move",
            "git_policy": "track",
            "to": "docs",
            "reason": "consolidate root markdown notes into docs/",
        })

    placement_rules = [
        {
            "kind": "docs",
            "match_ext": [".md", ".txt", ".rst", ".adoc"],
            "dest_dir": "docs",
            "lfs": False,
            "reason": "documentation and notes belong in docs/",
            "source": "fallback",
        },
        {
            "kind": "assets_3d",
            "match_ext": [".blend", ".fbx", ".glb", ".gltf", ".obj", ".usd", ".uasset"],
            "dest_dir": "assets/3d",
            "lfs": True,
            "reason": "3D source and scene assets tracked with LFS",
            "source": "fallback",
        },
        {
            "kind": "assets_media",
            "match_ext": [".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".wav", ".mp3", ".mp4"],
            "dest_dir": "assets/media",
            "lfs": True,
            "reason": "image, audio, and video assets",
            "source": "fallback",
        },
        {
            "kind": "scripts",
            "match_ext": [".sh", ".py", ".mjs"],
            "dest_dir": "scripts",
            "lfs": False,
            "reason": "standalone helper scripts outside src/",
            "source": "fallback",
        },
        {
            "kind": "data",
            "match_ext": [".csv", ".tsv", ".parquet", ".sqlite", ".db"],
            "dest_dir": "data",
            "lfs": True,
            "reason": "datasets and structured tables",
            "source": "fallback",
        },
    ]

    lfs_exts: Set[str] = set()
    for cand in inventory.get("lfs_candidates") or []:
        ext = cand.get("ext")
        if ext and ext.startswith("."):
            lfs_exts.add(f"*{ext}")

    ignore_patterns = [
        "node_modules/",
        ".venv/",
        "__pycache__/",
        ".pytest_cache/",
        ".hermes/scratch/",
        ".hermes/sessions/",
        "_archive/",
        ".adopt/place-log.json",
    ]

    return validate_rules_spec(
        {
            "project_slug": slug,
            "declared_dirs": declared_dirs,
            "folder_rules": folder_rules,
            "placement_rules": placement_rules,
            "ignore_patterns": ignore_patterns,
            "lfs_patterns": sorted(lfs_exts),
        },
        inventory,
    )


def _extract_json_object(raw_text: str) -> Optional[Dict[str, Any]]:
    text = (raw_text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def propose_rules_via_llm(
    inventory: Dict[str, Any],
    llm: Any,
) -> Dict[str, Any]:
    """Make exactly ONE model call through Hermes's ctx.llm to propose folder rules (never per-file).

    Validates the response against our fixed allowlists and merges mandatory safety rules.
    """
    if llm is None:
        raise SafetyError("ctx.llm is required for propose_rules_via_llm")

    model_summary = inventory.get("model_summary") or {}
    instructions = (
        "You are configuring folder organization rules for a messy project copy. "
        "Return ONLY folder/prefix rules (NEVER a per-file list). "
        "Allowed dispositions: 'keep', 'move', 'archive' (NEVER delete). "
        "Allowed git_policy: 'track', 'lfs', 'ignore', 'untrack'. "
        "Do NOT move files inside an existing 'src' directory. "
        "If 'mixed_cache_dirs' has 'dist', move static assets (.png, .svg, .xml, .compiled, .css, .json) "
        "to 'assets/dist-static' and archive compiled '.js'/'.map' to '_archive/dist-build'. "
        "If '.hermes/plans' exists, move '.md' plans to 'docs/plans'. "
        "If root '.' has many loose '.md' files, move root '.md' files to 'docs'."
    )
    payload_text = json.dumps(model_summary, indent=2, sort_keys=True)

    parsed_obj: Optional[Dict[str, Any]] = None
    audit_meta: Dict[str, Any] = {"calls": 1}

    if hasattr(llm, "complete_structured"):
        res = llm.complete_structured(
            instructions=instructions,
            input=[{"type": "text", "text": payload_text}],
            json_schema=FOLDER_RULES_SCHEMA,
            schema_name="adopt.folder_rules",
            purpose="adopt.propose_rules",
            temperature=0.0,
            max_tokens=2048,
        )
        audit_meta["provider"] = getattr(res, "provider", "")
        audit_meta["model"] = getattr(res, "model", "")
        if isinstance(getattr(res, "parsed", None), dict):
            parsed_obj = res.parsed
        else:
            parsed_obj = _extract_json_object(getattr(res, "text", ""))
    elif hasattr(llm, "complete"):
        res = llm.complete(
            messages=[
                {"role": "system", "content": instructions + "\nRespond with valid JSON only."},
                {"role": "user", "content": payload_text},
            ],
            temperature=0.0,
            max_tokens=2048,
            purpose="adopt.propose_rules",
        )
        audit_meta["provider"] = getattr(res, "provider", "")
        audit_meta["model"] = getattr(res, "model", "")
        parsed_obj = _extract_json_object(getattr(res, "text", ""))
    else:
        raise SafetyError("Provided llm object supports neither complete_structured nor complete")

    if parsed_obj is None:
        raise SafetyError("LLM call did not return valid JSON folder rules")

    validated = validate_rules_spec(parsed_obj, inventory)
    validated["llm_audit"] = audit_meta
    return validated


def _rule_matches_path(rule: Dict[str, Any], rel_path: str) -> Optional[Tuple[int, int]]:
    """Return specificity tuple (prefix_depth, has_ext_filter) if rule matches rel_path, else None.

    Special case: match='.' only matches root-level files (no '/' in rel_path) when disposition='move'
    so moving root loose files (e.g. root .md -> docs/) does not accidentally flatten subdirectories.
    """
    match_prefix = rule["match"]
    exts = rule.get("ext") or []
    _, file_ext = os.path.splitext(rel_path.lower())

    if exts and file_ext not in exts:
        return None

    if match_prefix == ".":
        if rule["disposition"] in ("move", "archive") and "/" in rel_path:
            return None
        prefix_score = 0
    else:
        if rel_path == match_prefix or rel_path.startswith(match_prefix + "/"):
            prefix_score = len(PurePosixPath(match_prefix).parts)
        else:
            return None

    ext_score = 1 if exts else 0
    return (prefix_score, ext_score)


def _compute_destination(rel_path: str, rule: Dict[str, Any]) -> str:
    disp = rule["disposition"]
    if disp == "keep":
        return rel_path
    match_prefix = rule["match"]
    to_prefix = rule["to"].rstrip("/")
    if match_prefix == ".":
        tail = rel_path
    elif rel_path == match_prefix:
        tail = os.path.basename(rel_path)
    else:
        tail = rel_path[len(match_prefix) :].lstrip("/")
    return f"{to_prefix}/{tail}" if tail else to_prefix


def expand_rules(inventory: Dict[str, Any], rules_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Expand folder_rules + local secret/special rules into a collision-free per-item plan."""
    validated = validate_rules_spec(rules_spec, inventory)
    folder_rules = validated["folder_rules"]

    secret_paths: Set[str] = {
        s["path"] for s in (inventory.get("secrets_flagged") or [])
    }
    lfs_paths: Set[str] = {
        c["path"] for c in (inventory.get("lfs_candidates") or [])
    }
    link_paths: Set[str] = {
        ln["path"] for ln in (inventory.get("links") or [])
    }

    expanded_files: List[Dict[str, Any]] = []
    dest_owners: Dict[str, str] = {}

    for f_entry in inventory.get("files") or []:
        rel_path = f_entry["path"]
        is_secret = rel_path in secret_paths or bool(f_entry.get("secret_placeholder"))

        # 1. Protected root files stay in root
        if "/" not in rel_path and rel_path in PROTECTED_ROOT_FILES:
            disp = "keep"
            dest_path = rel_path
            git_pol = "ignore" if is_secret else "track"
            reason = "protected root file"
        # 2. Local special runtime paths (.hermes/scratch, .hermes/sessions, .worktrees)
        elif rel_path.startswith((".hermes/scratch/", ".hermes/sessions/", ".worktrees/")):
            disp = "archive"
            dest_path = f"_archive/{rel_path}"
            git_pol = "ignore"
            reason = "local runtime dump archived and git-ignored"
        else:
            # Find highest-specificity matching folder rule
            best_score: Optional[Tuple[int, int]] = None
            best_rules: List[Dict[str, Any]] = []
            for r in folder_rules:
                score = _rule_matches_path(r, rel_path)
                if score is None:
                    continue
                if best_score is None or score > best_score:
                    best_score = score
                    best_rules = [r]
                elif score == best_score:
                    best_rules.append(r)

            if len(best_rules) > 1:
                first = best_rules[0]
                if any(
                    br["disposition"] != first["disposition"]
                    or br["to"] != first["to"]
                    or br["git_policy"] != first["git_policy"]
                    for br in best_rules[1:]
                ):
                    raise SafetyError(f"Ambiguous equal-specificity rules matched {rel_path!r}")

            if best_rules:
                chosen = best_rules[0]
                disp = chosen["disposition"]
                dest_path = _compute_destination(rel_path, chosen)
                git_pol = chosen["git_policy"]
                reason = chosen["reason"]
            else:
                disp = "keep"
                dest_path = rel_path
                git_pol = "lfs" if rel_path in lfs_paths else "track"
                reason = "default keep"

        # Secret lock always forces git_policy = ignore
        if is_secret:
            git_pol = "ignore"

        # Validate destination path is safe and does not traverse a symlink
        dest_norm = _validate_safe_rel_prefix(dest_path, f"expanded dest for {rel_path}", allow_dot=False)
        for lp in link_paths:
            if dest_norm == lp or dest_norm.startswith(lp + "/"):
                raise SafetyError(
                    f"Expanded destination {dest_norm!r} for {rel_path!r} lands on or beneath symlink {lp!r}"
                )

        if dest_norm in dest_owners and dest_owners[dest_norm] != rel_path:
            raise SafetyError(
                f"Destination collision: {rel_path!r} and {dest_owners[dest_norm]!r} both map to {dest_norm!r}"
            )
        dest_owners[dest_norm] = rel_path

        expanded_files.append({
            "source_path": rel_path,
            "dest_path": dest_norm,
            "disposition": disp,
            "git_policy": git_pol,
            "tracked_in_source": bool(f_entry.get("tracked")),
            "sha256": f_entry.get("sha256"),
            "size": f_entry.get("size", 0),
            "secret_locked": is_secret,
            "left_behind": bool(f_entry.get("left_behind", False)),
            "reason": reason,
        })

    # Map symlinks as well (internal links have their targets updated if the referent moved)
    source_to_dest = {ef["source_path"]: ef["dest_path"] for ef in expanded_files}
    expanded_links: List[Dict[str, Any]] = []
    for ln in inventory.get("links") or []:
        ln_path = ln["path"]
        ln_class = ln["link_class"]
        target_rel = ln.get("target_rel")
        new_target_rel = target_rel
        if ln_class in ("internal-relative", "internal-absolute") and target_rel:
            if target_rel in source_to_dest:
                new_target_rel = source_to_dest[target_rel]
            else:
                # Check if target_rel is a directory prefix whose contents moved uniformly
                for r in folder_rules:
                    if r["disposition"] in ("move", "archive") and not r.get("ext"):
                        if target_rel == r["match"] or target_rel.startswith(r["match"] + "/"):
                            new_target_rel = _compute_destination(target_rel, r)
                            break
        expanded_links.append({
            "source_path": ln_path,
            "dest_path": ln_path,
            "link_class": ln_class,
            "old_raw_target": ln["raw_target"],
            "new_target_rel": new_target_rel,
        })

    return {
        "schema": 1,
        "project_slug": validated["project_slug"],
        "files": expanded_files,
        "links": expanded_links,
        "junk_dirs": inventory.get("junk_dirs") or [],
        "special_paths": inventory.get("special_paths") or [],
        "declared_dirs": validated["declared_dirs"],
        "placement_rules": validated["placement_rules"],
        "ignore_patterns": validated["ignore_patterns"],
        "lfs_patterns": validated["lfs_patterns"],
    }
