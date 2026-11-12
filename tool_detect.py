"""Static project tool detectors for seeding TOOLS.lock."""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .path_match import (
    IGNORED_DIRS,
    MAX_DETECT_WALK_ENTRIES,
    _glob_matches_path,
    _walk_project_files,
    glob_matches_path,
    walk_project_files,
)

HERMES_PM_TOOLS: frozenset[str] = frozenset(
    {
        "cua-driver",
        "ffmpeg",
        "ripgrep",
        "chromium",
        "node",
    }
)

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_ALLOWED_PROBE_ARGS: frozenset[str] = frozenset(
    {"--version", "-V", "-v", "version", "-version", "--help"}
)
_COMMAND_ALIASES: dict[str, frozenset[str]] = {
    "rust": frozenset({"rustc"}),
    "rustc": frozenset({"rust"}),
    "python": frozenset({"python3"}),
    "python3": frozenset({"python"}),
    "node": frozenset({"nodejs"}),
    "nodejs": frozenset({"node"}),
    "ripgrep": frozenset({"rg"}),
    "rg": frozenset({"ripgrep"}),
}

_CONCRETE_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$")
_GO_VERSION_LINE_RE = re.compile(
    r"^\s*(?:go\s+1\.\d+(?:\.\d+)?|toolchain\s+go\S+)(?:\s|$)"
)
_NVMRC_REGEX: str = r"^\s*v?(\d+(?:\.\d+)*)"
_KNOWN_PACKAGE_MANAGERS: frozenset[str] = frozenset({"npm", "pnpm", "yarn", "bun"})
_PM_ARGV_MAP: dict[str, list[str]] = {
    "npm": ["npm", "--version"],
    "pnpm": ["pnpm", "--version"],
    "yarn": ["yarn", "--version"],
    "bun": ["bun", "--version"],
}
ALLOWED_DETECTOR_ARGV_TOKENS: frozenset[str] = frozenset(
    {
        "rustc",
        "cargo",
        "go",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "bun",
        "houdini",
        "blender",
        "docker",
        "--version",
        "version",
    }
)
_PM_LOCKFILES: tuple[tuple[str, str], ...] = (
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
    ("bun.lockb", "bun"),
    ("bun.lock", "bun"),
)


def format_reason(evidence: str, event: str) -> str:
    """Format the standard auto-detection reason string for an evidence source and event."""
    return (
        f"Detected from {evidence} at {event} (auto). "
        "Edit this reason when you make a deliberate choice."
    )


def _base_entry(*, chosen: str, evidence: str, event: str, probe: str, **extra: Any) -> dict[str, Any]:
    """Build a lock entry dict with standard keys and probe-specific fields."""
    entry: dict[str, Any] = {
        "version": "",
        "chosen": chosen,
        "reason": format_reason(evidence, event),
        "probe": probe,
        "source": "auto",
    }
    entry.update(extra)
    return entry


def _is_concrete_rust_channel(channel: Any) -> bool:
    """Return True if a rust-toolchain channel string is a concrete version like '1.82.0'."""
    if not isinstance(channel, str):
        return False
    val = channel.strip()
    if not val:
        return False
    if _CONCRETE_VERSION_RE.match(val):
        return True
    # Also accept concrete version prefixed before target triple if starts with X.Y.Z
    prefix = val.split("-", 1)[0]
    return bool(_CONCRETE_VERSION_RE.match(prefix))


def _floor_from_text(text: str) -> str | None:
    """Return a dotted number usable as a lock `minimum` (at most four parts), or None."""
    val = text.strip()
    if re.fullmatch(r"\d{1,9}(?:\.\d{1,9}){0,3}", val):
        return val
    return None


def detect_rust_toolchain(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect rust and cargo from rust-toolchain.toml."""
    del rel_files
    full_path = project_root / rel_path
    channel: Any = None
    try:
        raw = full_path.read_text(encoding="utf-8", errors="replace")
        parsed = tomllib.loads(raw)
        if isinstance(parsed, dict):
            tc = parsed.get("toolchain")
            if isinstance(tc, dict):
                channel = tc.get("channel")
    except (OSError, tomllib.TOMLDecodeError):
        channel = None

    # Always ask the installed rustc; a concrete channel is the floor it must meet.
    rust_extra: dict[str, Any] = {}
    if _is_concrete_rust_channel(channel):
        floor = _floor_from_text(str(channel).split("-", 1)[0])
        if floor:
            rust_extra["minimum"] = floor
    rust_entry = _base_entry(
        chosen=chosen,
        evidence=rel_path,
        event=event,
        probe="command",
        argv=["rustc", "--version"],
        **rust_extra,
    )

    cargo_entry = _base_entry(
        chosen=chosen,
        evidence=rel_path,
        event=event,
        probe="command",
        argv=["cargo", "--version"],
    )
    return {"rust": rust_entry, "cargo": cargo_entry}


def detect_go_mod(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect go from go.mod when a 'go 1.x' or 'toolchain goX' directive line is present."""
    del rel_files
    full_path = project_root / rel_path
    try:
        text = full_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if _GO_VERSION_LINE_RE.match(line):
            return {
                "go": _base_entry(
                    chosen=chosen,
                    evidence=rel_path,
                    event=event,
                    probe="command",
                    argv=["go", "version"],
                )
            }
    return {}


def _parse_package_manager_field(raw_pm: Any) -> str | None:
    """Extract package manager binary name from package.json packageManager string (e.g. 'pnpm@9.1.0')."""
    if not isinstance(raw_pm, str):
        return None
    cleaned = raw_pm.strip()
    if not cleaned:
        return None
    name = cleaned.split("@", 1)[0].strip().lower()
    if name in _KNOWN_PACKAGE_MANAGERS:
        return name
    return None


def detect_package_json(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect node and package manager (pnpm/yarn/npm) from package.json and lockfiles."""
    full_path = project_root / rel_path
    entries: dict[str, dict[str, Any]] = {
        "node": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="command",
            argv=["node", "--version"],
        )
    }

    pm_name: str | None = None
    pm_evidence: str = rel_path
    try:
        data = json.loads(full_path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict):
            pm_name = _parse_package_manager_field(data.get("packageManager"))
    except (OSError, ValueError):
        pm_name = None

    if pm_name is None:
        rel_dir = os.path.dirname(rel_path)
        for lock_filename, candidate_pm in _PM_LOCKFILES:
            sibling = f"{rel_dir}/{lock_filename}" if rel_dir else lock_filename
            if sibling in rel_files:
                pm_name = candidate_pm
                pm_evidence = sibling
                break
            if lock_filename in rel_files:
                pm_name = candidate_pm
                pm_evidence = lock_filename
                break

    if pm_name in _PM_ARGV_MAP:
        entries[pm_name] = _base_entry(
            chosen=chosen,
            evidence=pm_evidence,
            event=event,
            probe="command",
            argv=list(_PM_ARGV_MAP[pm_name]),
        )

    return entries


def detect_nvmrc(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect node from .nvmrc (wins over package.json).

    The installed node is asked for its version; the number in .nvmrc is kept as the floor.
    """
    del rel_files
    extra: dict[str, Any] = {}
    try:
        with open(project_root / rel_path, "rb") as fh:
            head = fh.read(512).decode("utf-8", errors="replace")
    except OSError:
        head = ""
    m = re.match(_NVMRC_REGEX, head)
    floor = _floor_from_text(m.group(1)) if m else None
    if floor:
        extra["minimum"] = floor
    return {
        "node": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="command",
            argv=["node", "--version"],
            **extra,
        )
    }


def detect_python(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect python interpreter from pyproject.toml or requirements*.txt."""
    del project_root, rel_files
    return {
        "python": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="interpreter",
        )
    }


def detect_unreal(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect unreal engine from a *.uproject file."""
    del project_root, rel_files
    return {
        "unreal": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="file",
            file=rel_path,
            key="EngineAssociation",
        )
    }


def detect_houdini(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect houdini from *.hip, *.hiplc, *.hipnc, or houdini.version."""
    del project_root, rel_files
    return {
        "houdini": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="command",
            argv=["houdini", "--version"],
        )
    }


def detect_blender(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect blender from *.blend files."""
    del project_root, rel_files
    return {
        "blender": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="command",
            argv=["blender", "--version"],
        )
    }


def detect_docker(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Detect docker from Dockerfile."""
    del project_root, rel_files
    return {
        "docker": _base_entry(
            chosen=chosen,
            evidence=rel_path,
            event=event,
            probe="command",
            argv=["docker", "--version"],
        )
    }


def detect_ignore(
    project_root: Path,
    rel_path: str,
    rel_files: frozenset[str],
    *,
    chosen: str,
    event: str,
) -> dict[str, dict[str, Any]]:
    """Explicit no-op detector for non-tool files such as .github/workflows/*.yml."""
    del project_root, rel_path, rel_files, chosen, event
    return {}


DetectorFn = Callable[..., dict[str, dict[str, Any]]]


@dataclass(frozen=True)
class DetectorRule:
    """Mapping from evidence file globs to a pure detector function."""

    name: str
    detect_globs: tuple[str, ...]
    detector: DetectorFn
    override_existing: bool = False


DETECTORS: tuple[DetectorRule, ...] = (
    DetectorRule(
        name="github-workflows-ignore",
        detect_globs=(".github/workflows/*.yml", ".github/workflows/*.yaml"),
        detector=detect_ignore,
    ),
    DetectorRule(
        name="rust-toolchain",
        detect_globs=("rust-toolchain.toml", "**/rust-toolchain.toml"),
        detector=detect_rust_toolchain,
    ),
    DetectorRule(
        name="go-mod",
        detect_globs=("go.mod", "**/go.mod"),
        detector=detect_go_mod,
    ),
    DetectorRule(
        name="package-json",
        detect_globs=("package.json", "**/package.json"),
        detector=detect_package_json,
    ),
    DetectorRule(
        name="nvmrc",
        detect_globs=(".nvmrc", "**/.nvmrc"),
        detector=detect_nvmrc,
        override_existing=True,
    ),
    DetectorRule(
        name="python",
        detect_globs=(
            "pyproject.toml",
            "requirements*.txt",
            "**/pyproject.toml",
            "**/requirements*.txt",
        ),
        detector=detect_python,
    ),
    DetectorRule(
        name="unreal",
        detect_globs=("*.uproject", "**/*.uproject"),
        detector=detect_unreal,
    ),
    DetectorRule(
        name="houdini",
        detect_globs=(
            "*.hip",
            "*.hiplc",
            "*.hipnc",
            "houdini.version",
            "**/*.hip",
            "**/*.hiplc",
            "**/*.hipnc",
            "**/houdini.version",
        ),
        detector=detect_houdini,
    ),
    DetectorRule(
        name="blender",
        detect_globs=("*.blend", "**/*.blend"),
        detector=detect_blender,
    ),
    DetectorRule(
        name="docker",
        detect_globs=("Dockerfile", "**/Dockerfile"),
        detector=detect_docker,
    ),
)


def _match_rule_files(rule: DetectorRule, rel_files: tuple[str, ...]) -> list[str]:
    """Return matching relative paths for rule, preferring shallower paths then lexical order."""
    matched: list[str] = []
    seen: set[str] = set()
    for pat in rule.detect_globs:
        for rel in rel_files:
            if rel not in seen and _glob_matches_path(pat, rel):
                seen.add(rel)
                matched.append(rel)
    matched.sort(key=lambda p: (p.count("/"), p))
    return matched


def _validate_version_probe_argv(tool: str, raw_argv: Any) -> list[str]:
    """Validate an explicit per-tool version-probe argv sequence (fail closed on malformed)."""
    if not isinstance(tool, str) or not _TOOL_NAME_RE.fullmatch(tool):
        raise ValueError(f"invalid tool name {tool!r} in version_probes")
    if not isinstance(raw_argv, (list, tuple)) or len(raw_argv) < 2:
        raise ValueError(f"version probe for {tool!r} must be a sequence of at least 2 strings")
    if len(raw_argv) - 1 > len(_ALLOWED_PROBE_ARGS):
        raise ValueError(f"too many arguments in version probe for {tool!r}")
    out: list[str] = []
    for item in raw_argv:
        if not isinstance(item, str) or not item.strip() or item != item.strip() or "\x00" in item:
            raise ValueError(f"invalid version probe token {item!r} for {tool!r}")
        out.append(item)
    exe = out[0]
    if not _TOOL_NAME_RE.fullmatch(exe):
        raise ValueError(f"invalid version probe executable {exe!r} for {tool!r}")
    allowed_exes = {tool, *_COMMAND_ALIASES.get(tool, frozenset())}
    if exe not in allowed_exes:
        raise ValueError(f"version probe argv[0] {exe!r} does not match tool {tool!r}")
    for arg in out[1:]:
        if arg not in _ALLOWED_PROBE_ARGS:
            raise ValueError(
                f"disallowed version probe argument {arg!r} for {tool!r}; "
                f"allowed: {sorted(_ALLOWED_PROBE_ARGS)}"
            )
    return out


def _validate_file_version_probe(tool: str, raw_probe: Mapping) -> dict[str, Any]:
    """Validate the relative file and selector fields of a file version probe."""
    rel_file = raw_probe.get("file")
    if not isinstance(rel_file, str) or not rel_file.strip():
        raise ValueError(f"file version probe for {tool!r} requires non-empty 'file'")
    norm_file = rel_file.replace("\\", "/").strip("/")
    if (
        not norm_file
        or rel_file.startswith(("/", "\\"))
        or any(p in ("", ".", "..") for p in Path(norm_file).parts)
    ):
        raise ValueError(f"invalid relative file {rel_file!r} in version probe for {tool!r}")
    has_key = "key" in raw_probe and raw_probe["key"] is not None
    has_regex = "regex" in raw_probe and raw_probe["regex"] is not None
    if has_key == has_regex:
        raise ValueError(
            f"file version probe for {tool!r} requires exactly one of 'key' or 'regex'"
        )
    extra: dict[str, Any] = {"file": norm_file}
    if has_key:
        key_val = raw_probe["key"]
        if not isinstance(key_val, str) or not key_val.strip():
            raise ValueError(f"file version probe 'key' for {tool!r} must be a non-empty string")
        extra["key"] = key_val.strip()
    else:
        regex_val = raw_probe["regex"]
        if not isinstance(regex_val, str) or not regex_val.strip():
            raise ValueError(f"file version probe 'regex' for {tool!r} must be a non-empty string")
        extra["regex"] = regex_val
    return extra


def _build_entry_from_version_probe(
    tool: str,
    raw_probe: Any,
    *,
    chosen: str,
    event: str,
) -> dict[str, Any]:
    """Validate an attached version_probe spec from _ToolNeedStr and build a lock entry (fail closed)."""
    if not isinstance(tool, str) or not _TOOL_NAME_RE.fullmatch(tool):
        raise ValueError(f"invalid tool name {tool!r} in version probe")
    if isinstance(raw_probe, Mapping):
        allowed_keys = {"probe", "argv", "file", "key", "regex"}
        for k in raw_probe:
            if not isinstance(k, str) or k not in allowed_keys:
                raise ValueError(f"unknown key {k!r} in version probe for {tool!r}")
        probe_kind = raw_probe.get("probe")
        if probe_kind is None:
            if "file" in raw_probe:
                probe_kind = "file"
            elif "argv" in raw_probe:
                probe_kind = "command"
            else:
                raise ValueError(f"missing 'probe' or 'argv' in version probe for {tool!r}")
        if probe_kind == "command":
            argv = _validate_version_probe_argv(tool, raw_probe.get("argv"))
            return _base_entry(
                chosen=chosen,
                evidence="template needs",
                event=event,
                probe="command",
                argv=argv,
            )
        if probe_kind == "file":
            extra = _validate_file_version_probe(tool, raw_probe)
            return _base_entry(
                chosen=chosen,
                evidence="template needs",
                event=event,
                probe="file",
                **extra,
            )
        if probe_kind in ("pm", "module", "interpreter"):
            return _base_entry(
                chosen=chosen,
                evidence="template needs",
                event=event,
                probe=str(probe_kind),
            )
        raise ValueError(f"invalid probe kind {probe_kind!r} in version probe for {tool!r}")

    argv = _validate_version_probe_argv(tool, raw_probe)
    return _base_entry(
        chosen=chosen,
        evidence="template needs",
        event=event,
        probe="command",
        argv=argv,
    )


def detect_tools(
    project_root: Path,
    *,
    chosen: str,
    event: str,
    template_needs: Iterable[str] = (),
) -> dict[str, dict[str, Any]]:
    """Detect project tools statically from evidence files and merge template_needs, sorted by tool name."""
    root = Path(project_root)
    rel_files = _walk_project_files(root, max_entries=MAX_DETECT_WALK_ENTRIES)
    rel_files_set = frozenset(rel_files)

    detected: dict[str, dict[str, Any]] = {}

    for rule in DETECTORS:
        matches = _match_rule_files(rule, rel_files)
        for rel_path in matches:
            entries = rule.detector(
                root,
                rel_path,
                rel_files_set,
                chosen=chosen,
                event=event,
            )
            if not entries:
                continue
            for tool_name, entry in entries.items():
                if rule.override_existing or tool_name not in detected:
                    detected[tool_name] = entry
            if rule.override_existing:
                break

    for raw_need in template_needs:
        if not isinstance(raw_need, str):
            continue
        attached_probe = getattr(raw_need, "version_probe", None)
        need = raw_need.strip()
        if not need:
            continue
        if attached_probe is not None:
            detected[need] = _build_entry_from_version_probe(
                need,
                attached_probe,
                chosen=chosen,
                event=event,
            )
            continue
        if need in detected:
            continue
        if need in HERMES_PM_TOOLS:
            detected[need] = _base_entry(
                chosen=chosen,
                evidence="template needs",
                event=event,
                probe="pm",
            )
        else:
            detected[need] = _base_entry(
                chosen=chosen,
                evidence="template needs",
                event=event,
                probe="command",
                argv=[need, "--version"],
            )

    return {name: detected[name] for name in sorted(detected)}
