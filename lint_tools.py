"""Committed lint-tool table, detection rules, and pure argv builders for the Defuzz plugin."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from .path_match import (
    IGNORED_DIRS,
    MAX_DETECT_WALK_ENTRIES,
    ScanResult,
    _glob_matches_path,
    glob_matches_path,
    scan,
)

VALID_KINDS: frozenset[str] = frozenset({"wheel", "binary", "sdk"})
VALID_MODES: frozenset[str] = frozenset({"pre", "post"})
VALID_LANGUAGES: frozenset[str] = frozenset({
    "python", "rust", "javascript", "typescript", "go", "cpp", "csharp",
    "gdscript", "lua", "shader", "shell", "powershell", "json", "yaml",
    "toml", "markdown", "dockerfile",
})

# Dependency-manager output is not hand-authored style input. Keep it in the
# scan so callers can report exclusions explicitly.
GENERATED_LOCKFILES: frozenset[str] = frozenset({
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Cargo.lock", "uv.lock",
    "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum",
})


def is_generated_lockfile(path: str) -> bool:
    """Match exact dependency lock basenames at any project depth."""
    return Path(path).name in GENERATED_LOCKFILES


WHEEL_PACKAGES: Dict[str, Union[str, Tuple[str, ...]]] = {
    "ruff": "ruff",
    "yamllint": "yamllint",
    "taplo": "taplo",
    "rumdl": "rumdl",
    "shfmt-py": "shfmt",
    "shellcheck-py": "shellcheck",
    "hadolint-py": "hadolint",
    "clang-format": "clang-format",
    "clang-tidy": "clang-tidy",
    "gdtoolkit": ("gdlint", "gdformat"),
}


@dataclass(frozen=True)
class ToolSpec:
    """Immutable specification for a single committed lint or format tool."""

    name: str
    tool: str
    kind: str
    languages: Tuple[str, ...]
    detect_globs: Tuple[str, ...]
    modes: Tuple[str, ...]
    executes_repo_code: bool
    timeout_s: int
    parser: str
    binaries: Tuple[str, ...]
    requires: Tuple[str, ...] = ()
    input_globs: Tuple[str, ...] = ()

    def is_satisfied(self, root: Path) -> bool:
        """Return True if all required files (such as compile_commands.json) exist under root."""
        return tool_satisfied(self, root)

    def argv(self, mode: str, root: Path, files: List[str]) -> List[str]:
        """Return the exact subprocess argument list for this tool and mode."""
        return argv(self, mode, root, files)


_COMMON_BUILD_DIRS: Tuple[str, ...] = ("build", "out")
_CPP_HEADER_EXTENSIONS: frozenset[str] = frozenset({".h", ".hpp", ".hh", ".hxx", ".inl"})
_SHADER_HEADER_EXTENSIONS: frozenset[str] = frozenset({".ush", ".usf"})
_HLSL_EXTENSIONS: frozenset[str] = frozenset({".hlsl", ".fx", ".ush", ".usf"})
_GLSL_STAGE_TUPLE: Tuple[str, ...] = (
    "vert", "frag", "comp", "geom", "tesc", "tese", "mesh",
    "task", "rgen", "rint", "rahit", "rchit", "rmiss", "rcall",
)
_GLSL_STAGE_NAMES: frozenset[str] = frozenset(_GLSL_STAGE_TUPLE)
_CARGO_EDITION_RE = re.compile(r'^\s*edition\s*=\s*["\'](2015|2018|2021|2024)["\']', re.MULTILINE)

_PYTHON_DETECT_GLOBS: Tuple[str, ...] = ("pyproject.toml", "requirements.txt", "**/*.py")
_JS_TS_GLOBS: Tuple[str, ...] = ("**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx")
_JS_TS_EXT_GLOBS: Tuple[str, ...] = (*_JS_TS_GLOBS, "**/*.mjs", "**/*.cjs", "**/*.mts", "**/*.cts")
_GO_DETECT_GLOBS: Tuple[str, ...] = ("go.mod", "**/*.go")
_CPP_SOURCE_GLOBS: Tuple[str, ...] = ("**/*.c", "**/*.cc", "**/*.cpp", "**/*.cxx")
_CPP_ALL_GLOBS: Tuple[str, ...] = (*_CPP_SOURCE_GLOBS, "**/*.h", "**/*.hpp")
_CSHARP_DETECT_GLOBS: Tuple[str, ...] = (
    "*.csproj", "*.sln", "**/*.csproj", "**/*.sln", "ProjectSettings/ProjectVersion.txt", "**/*.cs",
)
_GDSCRIPT_DETECT_GLOBS: Tuple[str, ...] = ("project.godot", "**/*.gd")
_LUA_INPUT_GLOBS: Tuple[str, ...] = ("**/*.lua", "**/*.luau")
_LUA_BASE_DETECT_GLOBS: Tuple[str, ...] = (
    "*.rockspec", "conf.lua", "game.project", "default.project.json", "selene.toml",
)
_GLSL_GLOBS: Tuple[str, ...] = tuple(f"**/*.{ext}" for ext in (*_GLSL_STAGE_TUPLE, "glsl"))
_SHELL_GLOBS: Tuple[str, ...] = ("**/*.sh", "**/*.bash")
_PWSH_GLOBS: Tuple[str, ...] = ("**/*.ps1", "**/*.psm1", "**/*.psd1")
_YAML_GLOBS: Tuple[str, ...] = ("**/*.yml", "**/*.yaml")
_MD_GLOBS: Tuple[str, ...] = ("**/*.md", "**/*.markdown")
_DOCKER_GLOBS: Tuple[str, ...] = ("Dockerfile*", "**/Dockerfile*", "Containerfile*", "**/Containerfile*")

TOOLS: Tuple[ToolSpec, ...] = (
    # 1. General & systems languages
    ToolSpec(
        name="ruff", tool="ruff", kind="wheel", languages=("python",),
        detect_globs=_PYTHON_DETECT_GLOBS, modes=("pre", "post"),
        executes_repo_code=False, timeout_s=30, parser="ruff", binaries=("ruff",),
    ),
    ToolSpec(
        name="ruff-format", tool="ruff-format", kind="wheel", languages=("python",),
        detect_globs=_PYTHON_DETECT_GLOBS, modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="ruff-format", binaries=("ruff",),
    ),
    ToolSpec(
        name="rustfmt", tool="rustfmt", kind="sdk", languages=("rust",),
        detect_globs=("Cargo.toml", "**/*.rs"), input_globs=("**/*.rs",), modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="rustfmt", binaries=("rustfmt",),
    ),
    ToolSpec(
        name="clippy", tool="clippy", kind="sdk", languages=("rust",),
        detect_globs=("Cargo.toml",), modes=("post",),
        executes_repo_code=True, timeout_s=180, parser="cargo-json", binaries=("cargo",),
    ),
    ToolSpec(
        name="biome", tool="biome", kind="binary", languages=("javascript", "typescript", "json"),
        detect_globs=("package.json", "tsconfig.json", "biome.json", "biome.jsonc", *_JS_TS_GLOBS, "**/*.json", "**/*.jsonc"),
        input_globs=(
            *_JS_TS_GLOBS, "**/*.json", "**/*.jsonc", "**/*.mjs", "**/*.cjs", "**/*.mts", "**/*.cts",
            "**/*.css", "**/*.scss", "**/*.html", "**/*.vue", "**/*.svelte", "**/*.astro",
            "**/*.graphql", "**/*.gql", *_MD_GLOBS, "**/*.yaml", "**/*.yml",
        ),
        modes=("pre", "post"), executes_repo_code=True, timeout_s=60, parser="biome-json", binaries=("biome",),
    ),
    ToolSpec(
        name="oxlint", tool="oxlint", kind="binary", languages=("javascript", "typescript"),
        detect_globs=("package.json", "tsconfig.json", *_JS_TS_GLOBS), input_globs=_JS_TS_EXT_GLOBS,
        modes=("post",), executes_repo_code=True, timeout_s=60, parser="oxlint-json", binaries=("oxlint",),
    ),
    ToolSpec(
        name="gofmt", tool="gofmt", kind="sdk", languages=("go",),
        detect_globs=_GO_DETECT_GLOBS, input_globs=("**/*.go",), modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="gofmt", binaries=("gofmt",),
    ),
    ToolSpec(
        name="go-vet", tool="go-vet", kind="sdk", languages=("go",),
        detect_globs=_GO_DETECT_GLOBS, modes=("post",),
        executes_repo_code=False, timeout_s=90, parser="go-vet", binaries=("go",),
    ),
    ToolSpec(
        name="golangci-lint", tool="golangci-lint", kind="binary", languages=("go",),
        detect_globs=_GO_DETECT_GLOBS, modes=("post",),
        executes_repo_code=True, timeout_s=120, parser="golangci-json", binaries=("golangci-lint",),
    ),
    ToolSpec(
        name="clang-format", tool="clang-format", kind="wheel", languages=("cpp",),
        detect_globs=("CMakeLists.txt", "compile_commands.json", "*.uproject", ".clang-format", *_CPP_ALL_GLOBS),
        input_globs=_CPP_ALL_GLOBS, modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="clang-format", binaries=("clang-format",),
    ),
    ToolSpec(
        name="clang-tidy", tool="clang-tidy", kind="wheel", languages=("cpp",),
        detect_globs=("CMakeLists.txt", "compile_commands.json", "*.uproject", *_CPP_ALL_GLOBS),
        input_globs=_CPP_SOURCE_GLOBS, modes=("post",),
        executes_repo_code=False, timeout_s=120, parser="clang-tidy", binaries=("clang-tidy",),
        requires=("compile_commands.json",),
    ),
    # 2. Game-studio languages
    ToolSpec(
        name="csharpier", tool="csharpier", kind="sdk", languages=("csharp",),
        detect_globs=_CSHARP_DETECT_GLOBS, input_globs=("**/*.cs",), modes=("pre",),
        executes_repo_code=False, timeout_s=45, parser="csharpier", binaries=("csharpier",),
    ),
    ToolSpec(
        name="dotnet-format", tool="dotnet-format", kind="sdk", languages=("csharp",),
        detect_globs=_CSHARP_DETECT_GLOBS, modes=("post",),
        executes_repo_code=True, timeout_s=120, parser="dotnet-format", binaries=("dotnet",),
    ),
    ToolSpec(
        name="gdformat", tool="gdformat", kind="wheel", languages=("gdscript",),
        detect_globs=_GDSCRIPT_DETECT_GLOBS, input_globs=("**/*.gd",), modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="gdformat", binaries=("gdformat",),
    ),
    ToolSpec(
        name="gdlint", tool="gdlint", kind="wheel", languages=("gdscript",),
        detect_globs=_GDSCRIPT_DETECT_GLOBS, input_globs=("**/*.gd",), modes=("post",),
        executes_repo_code=False, timeout_s=45, parser="gdlint", binaries=("gdlint",),
    ),
    ToolSpec(
        name="stylua", tool="stylua", kind="binary", languages=("lua",),
        detect_globs=(*_LUA_BASE_DETECT_GLOBS, "stylua.toml", ".stylua.toml", *_LUA_INPUT_GLOBS),
        input_globs=_LUA_INPUT_GLOBS, modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="stylua", binaries=("stylua",),
    ),
    ToolSpec(
        name="selene", tool="selene", kind="binary", languages=("lua",),
        detect_globs=(*_LUA_BASE_DETECT_GLOBS, *_LUA_INPUT_GLOBS),
        input_globs=_LUA_INPUT_GLOBS, modes=("post",),
        executes_repo_code=False, timeout_s=45, parser="selene-json", binaries=("selene",),
    ),
    ToolSpec(
        name="glslangValidator", tool="glslangValidator", kind="binary", languages=("shader",),
        detect_globs=_GLSL_GLOBS, input_globs=_GLSL_GLOBS, modes=("pre", "post"),
        executes_repo_code=False, timeout_s=45, parser="glslang", binaries=("glslangValidator",),
    ),
    ToolSpec(
        name="dxc", tool="dxc", kind="binary", languages=("shader",),
        detect_globs=("**/*.hlsl", "**/*.fx", "**/*.ush", "**/*.usf"),
        input_globs=("**/*.hlsl", "**/*.fx"), modes=("pre", "post"),
        executes_repo_code=False, timeout_s=45, parser="dxc", binaries=("dxc",),
    ),
    # 3. Shell, scripting, config
    ToolSpec(
        name="shfmt", tool="shfmt", kind="wheel", languages=("shell",),
        detect_globs=_SHELL_GLOBS, input_globs=_SHELL_GLOBS, modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="shfmt", binaries=("shfmt",),
    ),
    ToolSpec(
        name="shellcheck", tool="shellcheck", kind="wheel", languages=("shell",),
        detect_globs=_SHELL_GLOBS, input_globs=_SHELL_GLOBS, modes=("post",),
        executes_repo_code=False, timeout_s=45, parser="shellcheck-json", binaries=("shellcheck",),
    ),
    ToolSpec(
        name="pwsh-parse", tool="pwsh-parse", kind="sdk", languages=("powershell",),
        detect_globs=_PWSH_GLOBS, input_globs=_PWSH_GLOBS, modes=("pre",),
        executes_repo_code=False, timeout_s=30, parser="pwsh-parse-json", binaries=("pwsh",),
    ),
    ToolSpec(
        name="psscriptanalyzer", tool="psscriptanalyzer", kind="sdk", languages=("powershell",),
        detect_globs=_PWSH_GLOBS, modes=("post",),
        executes_repo_code=False, timeout_s=60, parser="psscriptanalyzer-json", binaries=("pwsh",),
    ),
    ToolSpec(
        name="yamllint", tool="yamllint", kind="wheel", languages=("yaml",),
        detect_globs=_YAML_GLOBS, input_globs=_YAML_GLOBS, modes=("pre", "post"),
        executes_repo_code=False, timeout_s=30, parser="yamllint-parsable", binaries=("yamllint",),
    ),
    ToolSpec(
        name="taplo", tool="taplo", kind="wheel", languages=("toml",),
        detect_globs=("**/*.toml",), input_globs=("**/*.toml",), modes=("pre", "post"),
        executes_repo_code=False, timeout_s=30, parser="taplo", binaries=("taplo",),
    ),
    ToolSpec(
        name="rumdl", tool="rumdl", kind="wheel", languages=("markdown",),
        detect_globs=_MD_GLOBS, input_globs=_MD_GLOBS, modes=("pre", "post"),
        executes_repo_code=False, timeout_s=30, parser="rumdl-json", binaries=("rumdl",),
    ),
    ToolSpec(
        name="hadolint", tool="hadolint", kind="wheel", languages=("dockerfile",),
        detect_globs=_DOCKER_GLOBS, input_globs=_DOCKER_GLOBS, modes=("pre", "post"),
        executes_repo_code=False, timeout_s=30, parser="hadolint-json", binaries=("hadolint",),
    ),
)

_TOOLS_BY_NAME: Dict[str, ToolSpec] = {spec.name: spec for spec in TOOLS}


def by_name(name: str) -> ToolSpec:
    """Return the ToolSpec with the given name or raise KeyError."""
    return _TOOLS_BY_NAME[name]


def all_binaries() -> List[str]:
    """Return a deduplicated list of all executable binary names in TOOLS order."""
    out: List[str] = []
    seen: set[str] = set()
    for spec in TOOLS:
        for b in spec.binaries:
            if b not in seen:
                seen.add(b)
                out.append(b)
    for val in WHEEL_PACKAGES.values():
        items = (val,) if isinstance(val, str) else val
        for b in items:
            if b not in seen:
                seen.add(b)
                out.append(b)
    return out


def derive_glsl_stage(path: str | Path) -> Optional[str]:
    """Derive the glslangValidator shader stage name for path (e.g. .vert or .vert.glsl), or None."""
    parts = Path(path).name.lower().split(".")
    if len(parts) < 2:
        return None
    ext = parts[-1]
    if ext in _GLSL_STAGE_NAMES:
        return ext
    if ext == "glsl" and len(parts) >= 3 and parts[-2] in _GLSL_STAGE_NAMES:
        return parts[-2]
    return None


def detect_rust_edition(root: Path) -> str:
    """Read Rust edition from root/Cargo.toml (falling back to '2024' when absent or unreadable)."""
    manifest = Path(root) / "Cargo.toml"
    try:
        if manifest.is_file():
            m = _CARGO_EDITION_RE.search(manifest.read_text(encoding="utf-8", errors="replace"))
            if m:
                return m.group(1)
    except OSError:
        pass
    return "2024"


def _ps_quote(s: str) -> str:
    """Return a single-quoted PowerShell string literal with ' escaped as ''."""
    return "'" + str(s).replace("'", "''") + "'"


def _find_in_root_or_build_dirs(root: Path, rel_name: str) -> Optional[Path]:
    base = Path(root)
    for cand_dir in (base, *(base / d for d in _COMMON_BUILD_DIRS)):
        if (cand_dir / rel_name).is_file():
            return cand_dir
    return None


def find_compile_commands_dir(root: Path) -> Optional[Path]:
    """Return the first directory containing compile_commands.json in search order (root, build/, out/), else None."""
    return _find_in_root_or_build_dirs(root, "compile_commands.json")


def tool_satisfied(spec: ToolSpec, root: Path) -> bool:
    """Return True if all prerequisite files in spec.requires exist under root or common build dirs."""
    base = Path(root)
    for req in spec.requires:
        found = find_compile_commands_dir(base) if req == "compile_commands.json" else _find_in_root_or_build_dirs(base, req)
        if found is None:
            return False
    return True


def _targets(files: List[str], default: str = ".") -> List[str]:
    """Return non-empty file list without falling back to '.' when files is empty."""
    cleaned = [str(f) for f in files if str(f).strip()]
    if cleaned:
        return cleaned
    return [default] if (default and default != ".") else []


def _argv_clang_tidy(root: Path, file_args: List[str]) -> List[str]:
    cpp_files = [f for f in file_args if Path(f).suffix.lower() not in _CPP_HEADER_EXTENSIONS]
    if not cpp_files:
        raise ValueError("Tool 'clang-tidy' requires at least one non-header C/C++ source file")
    cc_dir = find_compile_commands_dir(Path(root))
    if cc_dir is None:
        raise ValueError("Tool 'clang-tidy' requires compile_commands.json in root, build/, or out/")
    return ["clang-tidy", "-p", str(cc_dir), *cpp_files]


def _argv_dotnet_format(files: List[str]) -> List[str]:
    cmd = ["dotnet", "format", "--verify-no-changes", "--no-restore"]
    explicit = [str(f) for f in files if str(f).strip() and str(f).strip() != "."]
    if explicit:
        cmd.extend(["--include", *explicit])
    return cmd


def _argv_glslang(mode: str, file_args: List[str]) -> List[str]:
    staged = [(f, st) for f in file_args if (st := derive_glsl_stage(f)) is not None]
    if not staged:
        raise ValueError("Tool 'glslangValidator' requires at least one GLSL file with a derivable shader stage")
    glsl_files = [f for f, _ in staged]
    stages = {st for _, st in staged}
    cmd: List[str] = ["glslangValidator", "-V"]
    if len(stages) == 1 and any(Path(f).suffix.lower() == ".glsl" for f in glsl_files):
        cmd.extend(["-S", next(iter(stages))])
    if mode == "post":
        cmd.append("--spirv-val")
    cmd.extend(["-o", os.devnull, *glsl_files])
    return cmd


def _argv_dxc(mode: str, file_args: List[str]) -> List[str]:
    hlsl_files = [f for f in file_args if Path(f).suffix.lower() not in _SHADER_HEADER_EXTENSIONS]
    if not hlsl_files:
        raise ValueError("Tool 'dxc' requires at least one non-header shader file")
    flags = ["-T", "lib_6_x"] if mode == "pre" else ["-Weverything", "-T", "lib_6_x"]
    return ["dxc", *flags, "-Fo", os.devnull, *hlsl_files]


def _argv_pwsh_parse(file_args: List[str]) -> List[str]:
    quoted_files = ",".join(_ps_quote(f) for f in file_args)
    script = (
        f"foreach($f in @({quoted_files})){{$e=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile($f,[ref]$null,[ref]$e) | Out-Null;"
        " if($e){ $e | ConvertTo-Json -Depth 4; exit 1 }"
        "}"
    )
    return ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script]


def argv(spec: ToolSpec, mode: str, root: Path, files: List[str]) -> List[str]:
    """Build the pure subprocess argument list for (spec, mode, root, files)."""
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid lint mode {mode!r}; expected one of {sorted(VALID_MODES)}")
    if mode not in spec.modes:
        raise ValueError(f"Tool {spec.name!r} does not support mode {mode!r} (modes={spec.modes})")

    name = spec.name
    file_args = _targets(files, default=".")
    if spec.input_globs and not file_args:
        raise ValueError(f"Tool {name!r} requires at least one input file; refusing to pass '.'")

    if name == "ruff":
        return (
            ["ruff", "check", "--select", "E9,F63,F7,F82", "--output-format", "json", "."]
            if mode == "pre"
            else ["ruff", "check", "--output-format", "json", "."]
        )
    if name == "ruff-format":
        return ["ruff", "format", "--check", "."]
    if name == "rustfmt":
        return ["rustfmt", "--check", "--edition", detect_rust_edition(Path(root)), *file_args]
    if name == "clippy":
        return ["cargo", "clippy", "--all-targets", "--offline", "--message-format", "json", "--", "-D", "warnings"]
    if name == "biome":
        return (
            ["biome", "check", "--formatter-enabled=true", "--linter-enabled=false", "--assist-enabled=false", "--reporter", "json", *file_args]
            if mode == "pre"
            else ["biome", "ci", "--reporter", "json", *file_args]
        )
    if name == "oxlint":
        return ["oxlint", "--deny-warnings", "--format", "json", *file_args]
    if name == "gofmt":
        return ["gofmt", "-e", "-l", *file_args]
    if name == "go-vet":
        return ["go", "vet", "./..."]
    if name == "golangci-lint":
        return ["golangci-lint", "run", "--output.json.path", "stdout", "--show-stats=false", "./..."]
    if name == "clang-format":
        return ["clang-format", "--dry-run", "-Werror", *file_args]
    if name == "clang-tidy":
        return _argv_clang_tidy(root, file_args)
    if name == "csharpier":
        return ["csharpier", "check", *file_args]
    if name == "dotnet-format":
        return _argv_dotnet_format(files)
    if name == "gdformat":
        return ["gdformat", "--check", *file_args]
    if name == "gdlint":
        return ["gdlint", *file_args]
    if name == "stylua":
        return ["stylua", "--check", *file_args]
    if name == "selene":
        return ["selene", "--display-style", "json2", "--no-summary", *file_args]
    if name == "glslangValidator":
        return _argv_glslang(mode, file_args)
    if name == "dxc":
        return _argv_dxc(mode, file_args)
    if name == "shfmt":
        return ["shfmt", "-d", *file_args]
    if name == "shellcheck":
        return ["shellcheck", "-f", "json", *file_args]
    if name == "pwsh-parse":
        return _argv_pwsh_parse(file_args)
    if name == "psscriptanalyzer":
        script = f"Invoke-ScriptAnalyzer -Path {_ps_quote(str(Path(root)))} -Recurse | ConvertTo-Json -Depth 4"
        return ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script]
    if name == "yamllint":
        return (
            ["yamllint", "-f", "parsable", "-d", "{extends: relaxed, rules: {line-length: disable}}", *file_args]
            if mode == "pre"
            else ["yamllint", "-f", "parsable", "--strict", *file_args]
        )
    if name == "taplo":
        return ["taplo", "format", "--check", *file_args] if mode == "pre" else ["taplo", "lint", "--no-schema", *file_args]
    if name == "rumdl":
        return ["rumdl", "check", "--output-format", "json", *file_args]
    if name == "hadolint":
        return (
            ["hadolint", "-f", "json", *file_args]
            if mode == "pre"
            else ["hadolint", "-f", "json", "--failure-threshold", "warning", *file_args]
        )
    raise ValueError(f"Unhandled tool specification: {name!r}")


def _collect_project_relpaths(root: Path, max_entries: int = MAX_DETECT_WALK_ENTRIES) -> List[str]:
    """Walk root deterministically skipping IGNORED_DIRS and return relative posix paths."""
    return list(scan(root, max_entries=max_entries).files)


def _spec_matches_files(spec: ToolSpec, relpaths: Iterable[str]) -> bool:
    """Return True if any detect_glob on spec matches at least one path in relpaths."""
    return any(_glob_matches_path(pat, rel) for pat in spec.detect_globs for rel in relpaths)


def detect(
    root: Path,
    saved_languages: Optional[Iterable[str]] = None,
    *,
    max_entries: int = MAX_DETECT_WALK_ENTRIES,
    scan_result: Optional[ScanResult] = None,
    include_unsatisfied: bool = False,
) -> List[ToolSpec]:
    """Return applicable ToolSpecs in TOOLS order based on project files or saved_languages."""
    base = Path(root)
    lang_set = {
        lang.strip().lower()
        for lang in (saved_languages or ())
        if isinstance(lang, str) and lang.strip()
    }
    scan_res = scan(base, max_entries=max_entries) if scan_result is None else scan_result
    relpaths = tuple(path for path in scan_res.files if not is_generated_lockfile(path))

    selected: List[ToolSpec] = []
    for spec in TOOLS:
        if not include_unsatisfied and not spec.is_satisfied(base):
            continue
        if (lang_set and any(lang in lang_set for lang in spec.languages)) or _spec_matches_files(spec, relpaths):
            selected.append(spec)
    return selected
