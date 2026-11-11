"""Strict template.yaml schema validator and template loader."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    class _MissingYaml:
        class YAMLError(Exception):
            pass

        @staticmethod
        def safe_load(_text: str) -> Any:
            raise _MissingYaml.YAMLError("PyYAML is not installed")

    yaml = _MissingYaml  # type: ignore[assignment]

from .lint_tools import _glob_matches_path, is_generated_lockfile
from .safety import _lexical_abs

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PLACEHOLDER_RE = re.compile(r"^[a-z][a-z0-9_]*$")
OPTION_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
CHOICE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")

ALLOWED_VERSION_PROBE_ARGS: frozenset[str] = frozenset(
    {"--version", "-V", "-v", "version", "-version", "--help"}
)
COMMAND_ALIASES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "rust": frozenset({"rustc"}),
        "rustc": frozenset({"rust"}),
        "python": frozenset({"python3"}),
        "python3": frozenset({"python"}),
        "node": frozenset({"nodejs"}),
        "nodejs": frozenset({"node"}),
        "ripgrep": frozenset({"rg"}),
        "rg": frozenset({"ripgrep"}),
    }
)

VALID_KINDS: frozenset[str] = frozenset(
    {"game", "studio", "app", "service", "library", "tool", "other"}
)
VALID_LAYOUTS: frozenset[str] = frozenset({"mono", "poly", "single"})

REQUIRED_TOP_KEYS: Tuple[str, ...] = (
    "id",
    "name",
    "summary",
    "kind",
    "layout",
    "languages",
    "placeholder",
    "substitute_in",
    "repos",
)
OPTIONAL_TOP_KEYS: Tuple[str, ...] = (
    "engine",
    "tags",
    "needs",
    "version_probes",
    "lockfiles",
    "locked",
    "approved_deps",
    "options",
)
ALLOWED_TOP_KEYS: frozenset[str] = frozenset(REQUIRED_TOP_KEYS + OPTIONAL_TOP_KEYS)

ALLOWED_REPO_KEYS: frozenset[str] = frozenset({"name", "check"})
ALLOWED_CHECK_KEYS: frozenset[str] = frozenset(
    {"cmd", "cwd", "prepare", "extra_cmds", "format_cmds"}
)
ALLOWED_FORMAT_CMD_KEYS: frozenset[str] = frozenset(
    {"cmd", "argv", "globs", "suffixes", "require_empty_stdout"}
)
ALLOWED_VERSION_PROBE_KEYS: frozenset[str] = frozenset(
    {"probe", "argv", "file", "key", "regex"}
)
VALID_PROBE_KINDS: frozenset[str] = frozenset(
    {"command", "file", "pm", "module", "interpreter"}
)

REQUIRED_OPTION_KEYS: Tuple[str, ...] = ("label", "choices", "default", "env_key")
OPTIONAL_OPTION_KEYS: Tuple[str, ...] = ("description",)
ALLOWED_OPTION_KEYS: frozenset[str] = frozenset(REQUIRED_OPTION_KEYS + OPTIONAL_OPTION_KEYS)


class TemplateError(ValueError):
    """Raised when a template directory or template.yaml violates the strict schema."""


class _ToolNeedStr(str):
    """String subclass carrying an explicit version_probe spec across tuple() copies."""

    version_probe: Optional[Any] = None

    def __new__(
        cls,
        value: str,
        version_probe: Optional[Any] = None,
    ) -> "_ToolNeedStr":
        obj = super().__new__(cls, value)
        if isinstance(version_probe, Mapping):
            obj.version_probe = MappingProxyType(dict(version_probe))
        elif version_probe is not None:
            obj.version_probe = tuple(version_probe)
        else:
            obj.version_probe = None
        return obj

    def __reduce__(self) -> Tuple[Any, ...]:
        # copy, deepcopy and pickle rebuild from plain values; a read-only mapping cannot be pickled.
        probe = self.version_probe
        if isinstance(probe, Mapping):
            probe = dict(probe)
        return (type(self), (str(self), probe))


@dataclass(frozen=True)
class FormatCmdSpec:
    """Declarative static formatter/lint command specification from template.yaml."""

    cmd: Tuple[str, ...]
    globs: Tuple[str, ...] = ()
    suffixes: Tuple[str, ...] = ()
    require_empty_stdout: bool = False


@dataclass(frozen=True)
class CheckSpec:
    """Optional repository verification command specification."""

    cmd: Tuple[str, ...]
    cwd: str = "."
    prepare: Tuple[str, ...] = ()
    extra_cmds: Tuple[Tuple[str, ...], ...] = ()
    format_cmds: Tuple[FormatCmdSpec | Tuple[str, ...], ...] = ()

    def ci_commands(self) -> Tuple[Tuple[str, ...], ...]:
        """Return the primary check command followed by any extra verification commands."""
        return (self.cmd, *self.extra_cmds)


@dataclass(frozen=True)
class RepoSpec:
    """Repository entry inside a template."""

    name: str
    check: Optional[CheckSpec] = None


@dataclass(frozen=True)
class OptionSpec:
    """Single configurable template option specification (A/B stack card)."""

    id: str
    label: str
    choices: Tuple[str, ...]
    default: str
    env_key: str
    description: str = ""

    def as_json(self) -> Dict[str, Any]:
        """Return a JSON-serializable dict representation of this option."""
        return {
            "id": self.id,
            "label": self.label,
            "choices": list(self.choices),
            "default": self.default,
            "env_key": self.env_key,
            "description": self.description,
        }

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


@dataclass(frozen=True)
class TemplateSpec:
    """Validated project template specification."""

    id: str
    name: str
    summary: str
    kind: str
    layout: str
    languages: Tuple[str, ...]
    engine: Optional[str]
    tags: Tuple[str, ...]
    needs: Tuple[str, ...]
    placeholder: str
    substitute_in: Tuple[str, ...]
    repos: Tuple[RepoSpec, ...]
    root: Path
    locked: Tuple[str, ...] = ()
    approved_deps: Mapping[str, Tuple[str, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    options: Mapping[str, OptionSpec] = field(
        default_factory=lambda: MappingProxyType({})
    )
    version_probes: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({})
    )
    lockfiles: Tuple[str, ...] = ()

    def options_as_json(self) -> List[Dict[str, Any]]:
        """Export this template's options as a JSON-serializable list of dicts for the UI."""
        return [opt.as_json() for opt in self.options.values()]

    def tool_version_probe(self, tool: str) -> Tuple[str, ...] | Dict[str, Any]:
        """Return the version-probe spec (argv tuple or typed probe dict) for tool."""
        if tool in self.version_probes:
            probe_val = self.version_probes[tool]
            if isinstance(probe_val, tuple):
                return probe_val
            if isinstance(probe_val, Mapping):
                if "argv" in probe_val and probe_val.get("probe", "command") == "command":
                    return tuple(probe_val["argv"])
                return dict(probe_val)
        return (tool, "--version")

    def tool_version_argv(self, tool: str) -> Tuple[str, ...] | Dict[str, Any]:
        """Return the version-probe argv tuple or typed probe dict for tool, honoring version_probes."""
        return self.tool_version_probe(tool)

    def generated_lockfiles(self, repo_root: Optional[Path] = None) -> Tuple[str, ...]:
        """Return sorted generated lockfile relative paths declared and present in this template."""
        target_root = repo_root
        if target_root is None and self.repos:
            cand = self.root / self.repos[0].name
            if cand.is_dir():
                target_root = cand

        found: set[str] = set()
        if target_root is not None and target_root.is_dir():
            rel_files: list[str] = []
            for path in target_root.rglob("*"):
                if path.is_file():
                    rel_posix = path.relative_to(target_root).as_posix()
                    rel_files.append(rel_posix)
                    if is_generated_lockfile(path.name):
                        found.add(rel_posix)
            for raw_pat in (*self.lockfiles, *self.substitute_in):
                norm = raw_pat.replace("\\", "/").strip("/")
                if not norm:
                    continue
                if any(ch in norm for ch in "*?["):
                    for rel_posix in rel_files:
                        if _glob_matches_path(norm, rel_posix) and is_generated_lockfile(rel_posix):
                            found.add(rel_posix)
                elif is_generated_lockfile(norm) and (target_root / norm).is_file():
                    found.add(PurePosixPath(norm).as_posix())
        else:
            for raw_pat in (*self.lockfiles, *self.substitute_in):
                norm = raw_pat.replace("\\", "/").strip("/")
                if norm and not any(ch in norm for ch in "*?[") and is_generated_lockfile(norm):
                    found.add(PurePosixPath(norm).as_posix())
        return tuple(sorted(found))


def _err(folder: str, key: str, detail: str) -> TemplateError:
    """Build a TemplateError naming both the template folder and offending key."""
    return TemplateError(f"template '{folder}' key '{key}': {detail}")


def _require_non_empty_str(val: Any, folder: str, key: str) -> str:
    """Validate that val is a non-empty string."""
    if not isinstance(val, str) or not val.strip():
        raise _err(folder, key, "must be a non-empty string")
    return val


def _require_str_list(
    val: Any,
    folder: str,
    key: str,
    *,
    non_empty: bool = False,
    non_empty_items: bool = False,
    lowercase: bool = False,
) -> Tuple[str, ...]:
    """Validate that val is a list of strings (with optional list/item constraints)."""
    if not isinstance(val, list):
        raise _err(folder, key, "must be a list of strings")
    if non_empty and len(val) == 0:
        raise _err(folder, key, "must be a non-empty list")
    out: List[str] = []
    for item in val:
        if not isinstance(item, str):
            raise _err(folder, key, "every item must be a string")
        if non_empty_items and not item.strip():
            raise _err(folder, key, "every item must be a non-empty string")
        if lowercase and (item != item.lower() or item != item.strip()):
            raise _err(folder, key, f"value {item!r} must be lowercase")
        out.append(item)
    return tuple(out)


def _validate_rel_subpath(raw: str, folder: str, key: str, *, allow_dot: bool = False) -> str:
    """Validate a safe relative subpath inside a template or repo."""
    if allow_dot and raw == ".":
        return "."
    norm = raw.replace("\\", "/").strip("/")
    if not norm or raw.startswith("/") or raw.startswith("\\"):
        raise _err(folder, key, f"invalid relative path {raw!r}")
    parts = PurePosixPath(norm).parts
    if any(p in ("", ".", "..") for p in parts):
        raise _err(folder, key, f"path {raw!r} must not contain '..' or '.' segments")
    return norm


def _parse_locked(raw: Any, folder: str) -> Tuple[str, ...]:
    """Validate the locked guardrail file globs list."""
    items = _require_str_list(
        raw,
        folder,
        "locked",
        non_empty=True,
        non_empty_items=True,
    )
    out: List[str] = []
    for item in items:
        if "\x00" in item:
            raise _err(folder, "locked", f"glob {item!r} must not contain NUL bytes")
        norm = item.replace("\\", "/").strip("/")
        if not norm or item.startswith("/") or item.startswith("\\"):
            raise _err(folder, "locked", f"invalid relative glob {item!r}")
        parts = PurePosixPath(norm).parts
        if any(p in ("", ".", "..") for p in parts):
            raise _err(folder, "locked", f"glob {item!r} must not contain '..' or '.' segments")
        out.append(norm)
    return tuple(out)


def _parse_approved_deps(raw: Any, folder: str) -> Mapping[str, Tuple[str, ...]]:
    """Validate the per-ecosystem approved_deps allowlist."""
    if isinstance(raw, list):
        deps = _require_str_list(
            raw,
            folder,
            "approved_deps",
            non_empty=False,
            non_empty_items=True,
        )
        return MappingProxyType({"default": deps})
    if not isinstance(raw, dict):
        raise _err(
            folder,
            "approved_deps",
            "must be a mapping of ecosystem -> list of dependency strings",
        )
    if len(raw) == 0:
        raise _err(folder, "approved_deps", "must be a non-empty mapping")
    parsed: Dict[str, Tuple[str, ...]] = {}
    for eco_raw, deps_raw in raw.items():
        if not isinstance(eco_raw, str) or not eco_raw.strip():
            raise _err(folder, "approved_deps", "ecosystem key must be a non-empty string")
        if eco_raw != eco_raw.lower() or eco_raw != eco_raw.strip():
            raise _err(
                folder,
                f"approved_deps.{eco_raw}",
                f"ecosystem key {eco_raw!r} must be lowercase",
            )
        deps = _require_str_list(
            deps_raw,
            folder,
            f"approved_deps.{eco_raw}",
            non_empty=False,
            non_empty_items=True,
        )
        parsed[eco_raw] = deps
    return MappingProxyType(parsed)


def _parse_options(raw: Any, folder: str) -> Mapping[str, OptionSpec]:
    """Validate the optional options mapping for template A/B stack choices."""
    if not isinstance(raw, dict):
        raise _err(folder, "options", "must be a mapping of option_id -> option spec")
    parsed: Dict[str, OptionSpec] = {}
    for opt_id_raw, opt_raw in raw.items():
        if not isinstance(opt_id_raw, str) or not opt_id_raw.strip():
            raise _err(folder, "options", "option id must be a non-empty string")
        if not OPTION_ID_RE.fullmatch(opt_id_raw):
            raise _err(
                folder,
                f"options.{opt_id_raw}",
                f"option id {opt_id_raw!r} must match {OPTION_ID_RE.pattern}",
            )
        if opt_id_raw in parsed:
            raise _err(
                folder,
                f"options.{opt_id_raw}",
                f"duplicate option id {opt_id_raw!r}",
            )
        if not isinstance(opt_raw, dict):
            raise _err(
                folder,
                f"options.{opt_id_raw}",
                "option entry must be a mapping",
            )
        for k in opt_raw:
            if not isinstance(k, str) or k not in ALLOWED_OPTION_KEYS:
                raise _err(
                    folder,
                    f"options.{opt_id_raw}.{k}",
                    f"unknown key {k!r} in option {opt_id_raw!r}",
                )
        for req in REQUIRED_OPTION_KEYS:
            if req not in opt_raw:
                raise _err(
                    folder,
                    f"options.{opt_id_raw}.{req}",
                    f"missing required key {req!r} in option {opt_id_raw!r}",
                )
        label = _require_non_empty_str(
            opt_raw["label"], folder, f"options.{opt_id_raw}.label"
        )
        choices = _require_str_list(
            opt_raw["choices"],
            folder,
            f"options.{opt_id_raw}.choices",
            non_empty=True,
            non_empty_items=True,
        )
        if not (2 <= len(choices) <= 6):
            raise _err(
                folder,
                f"options.{opt_id_raw}.choices",
                f"choices must contain 2..6 items, got {len(choices)}",
            )
        seen_choices: set[str] = set()
        for cid in choices:
            if not CHOICE_ID_RE.fullmatch(cid):
                raise _err(
                    folder,
                    f"options.{opt_id_raw}.choices",
                    f"choice id {cid!r} must match {CHOICE_ID_RE.pattern}",
                )
            if cid in seen_choices:
                raise _err(
                    folder,
                    f"options.{opt_id_raw}.choices",
                    f"duplicate choice id {cid!r} in option {opt_id_raw!r}",
                )
            seen_choices.add(cid)

        default_val = _require_non_empty_str(
            opt_raw["default"], folder, f"options.{opt_id_raw}.default"
        )
        if default_val not in seen_choices:
            raise _err(
                folder,
                f"options.{opt_id_raw}.default",
                f"default {default_val!r} must be one of choices {list(choices)!r}",
            )

        env_key = _require_non_empty_str(
            opt_raw["env_key"], folder, f"options.{opt_id_raw}.env_key"
        )
        if not ENV_KEY_RE.fullmatch(env_key):
            raise _err(
                folder,
                f"options.{opt_id_raw}.env_key",
                f"env_key {env_key!r} must match {ENV_KEY_RE.pattern}",
            )

        if "description" in opt_raw:
            description = _require_non_empty_str(
                opt_raw["description"], folder, f"options.{opt_id_raw}.description"
            )
        else:
            description = ""

        parsed[opt_id_raw] = OptionSpec(
            id=opt_id_raw,
            label=label,
            choices=choices,
            default=default_val,
            env_key=env_key,
            description=description,
        )
    return MappingProxyType(parsed)


def _check_no_duplicate_yaml_keys(node: Any, folder: str, path_prefix: str = "") -> None:
    """Recursively verify that no YAML mapping node contains duplicate keys."""
    if node is None:
        return
    value = getattr(node, "value", None)
    tag = str(getattr(node, "tag", ""))
    if isinstance(value, list) and tag.endswith(":map"):
        seen: set[str] = set()
        for pair in value:
            if not isinstance(pair, tuple) or len(pair) != 2:
                continue
            k_node, v_node = pair
            k_val = getattr(k_node, "value", None)
            if isinstance(k_val, str):
                err_key = f"{path_prefix}.{k_val}" if path_prefix else k_val
                if k_val in seen:
                    raise _err(folder, err_key, f"duplicate key {k_val!r}")
                seen.add(k_val)
                _check_no_duplicate_yaml_keys(v_node, folder, err_key)
            else:
                _check_no_duplicate_yaml_keys(v_node, folder, path_prefix)
    elif isinstance(value, list):
        for item_node in value:
            if not isinstance(item_node, tuple):
                _check_no_duplicate_yaml_keys(item_node, folder, path_prefix)


def _load_yaml_strict(raw_text: str, folder: str) -> Any:
    """Parse YAML safely while rejecting duplicate mapping keys."""
    compose_fn = getattr(yaml, "compose", None)
    if callable(compose_fn):
        root_node = compose_fn(raw_text)
        _check_no_duplicate_yaml_keys(root_node, folder)
    return yaml.safe_load(raw_text)


def _parse_cmd_matrix(raw: Any, folder: str, key: str) -> Tuple[Tuple[str, ...], ...]:
    """Validate a non-empty list of non-empty command argv lists."""
    if not isinstance(raw, list) or len(raw) == 0:
        raise _err(folder, key, "must be a non-empty list of command argv lists")
    cmds: List[Tuple[str, ...]] = []
    for idx, entry in enumerate(raw):
        cmds.append(
            _require_str_list(
                entry,
                folder,
                f"{key}[{idx}]",
                non_empty=True,
                non_empty_items=True,
            )
        )
    return tuple(cmds)


def _parse_lockfiles(raw: Any, folder: str) -> Tuple[str, ...]:
    """Validate optional lockfiles relative path/glob list in template.yaml."""
    items = _require_str_list(
        raw,
        folder,
        "lockfiles",
        non_empty=True,
        non_empty_items=True,
    )
    out: List[str] = []
    for item in items:
        if "\x00" in item:
            raise _err(folder, "lockfiles", f"lockfile entry {item!r} must not contain NUL bytes")
        norm = item.replace("\\", "/").strip("/")
        if not norm or item.startswith("/") or item.startswith("\\"):
            raise _err(folder, "lockfiles", f"invalid relative lockfile entry {item!r}")
        parts = PurePosixPath(norm).parts
        if any(p in ("", ".", "..") for p in parts):
            raise _err(folder, "lockfiles", f"lockfile entry {item!r} must not contain '..' or '.' segments")
        out.append(norm)
    return tuple(out)


def _parse_format_cmds(raw: Any, folder: str, key: str) -> Tuple[FormatCmdSpec | Tuple[str, ...], ...]:
    """Validate repos.check.format_cmds (argv lists or FormatCmdSpec dicts)."""
    if not isinstance(raw, list) or len(raw) == 0:
        raise _err(folder, key, "must be a non-empty list of format command specs")
    specs: List[FormatCmdSpec | Tuple[str, ...]] = []
    for idx, entry in enumerate(raw):
        item_key = f"{key}[{idx}]"
        if isinstance(entry, list):
            argv = _require_str_list(
                entry,
                folder,
                item_key,
                non_empty=True,
                non_empty_items=True,
            )
            specs.append(argv)
            continue
        if not isinstance(entry, dict):
            raise _err(folder, item_key, "must be a command argv list or mapping")
        for k in entry:
            if not isinstance(k, str) or k not in ALLOWED_FORMAT_CMD_KEYS:
                raise _err(folder, f"{item_key}.{k}", f"unknown key {k!r} in format_cmds entry")
        if "cmd" in entry and "argv" in entry:
            raise _err(folder, item_key, "specify either 'cmd' or 'argv', not both")
        cmd_raw = entry.get("cmd", entry.get("argv"))
        if cmd_raw is None:
            raise _err(folder, f"{item_key}.cmd", "missing required key 'cmd' (or 'argv')")
        cmd = _require_str_list(
            cmd_raw,
            folder,
            f"{item_key}.cmd",
            non_empty=True,
            non_empty_items=True,
        )
        globs: Tuple[str, ...] = ()
        if "globs" in entry:
            raw_globs = _require_str_list(
                entry["globs"],
                folder,
                f"{item_key}.globs",
                non_empty=True,
                non_empty_items=True,
            )
            norm_globs: List[str] = []
            for pat in raw_globs:
                if "\x00" in pat:
                    raise _err(folder, f"{item_key}.globs", f"glob {pat!r} must not contain NUL")
                norm = pat.replace("\\", "/").strip("/")
                if not norm or pat.startswith("/") or pat.startswith("\\"):
                    raise _err(folder, f"{item_key}.globs", f"invalid relative glob {pat!r}")
                if any(p in ("", ".", "..") for p in PurePosixPath(norm).parts):
                    raise _err(folder, f"{item_key}.globs", f"glob {pat!r} must not contain '..' or '.'")
                norm_globs.append(norm)
            globs = tuple(norm_globs)
        suffixes: Tuple[str, ...] = ()
        if "suffixes" in entry:
            raw_suffixes = _require_str_list(
                entry["suffixes"],
                folder,
                f"{item_key}.suffixes",
                non_empty=True,
                non_empty_items=True,
            )
            norm_suffixes: List[str] = []
            for sfx in raw_suffixes:
                cleaned = sfx.strip().lower()
                if not cleaned.startswith(".") or len(cleaned) < 2 or "/" in cleaned or "\\" in cleaned:
                    raise _err(folder, f"{item_key}.suffixes", f"invalid file suffix {sfx!r}")
                norm_suffixes.append(cleaned)
            suffixes = tuple(norm_suffixes)
        req_empty = False
        if "require_empty_stdout" in entry:
            if not isinstance(entry["require_empty_stdout"], bool):
                raise _err(
                    folder,
                    f"{item_key}.require_empty_stdout",
                    "must be a boolean",
                )
            req_empty = entry["require_empty_stdout"]
        specs.append(
            FormatCmdSpec(
                cmd=cmd,
                globs=globs,
                suffixes=suffixes,
                require_empty_stdout=req_empty,
            )
        )
    return tuple(specs)


def _validate_command_probe_argv(
    argv_raw: Any,
    tool_raw: str,
    folder: str,
    key: str,
) -> Tuple[str, ...]:
    argv = _require_str_list(
        argv_raw,
        folder,
        key,
        non_empty=True,
        non_empty_items=True,
    )
    if len(argv) < 2 or len(argv) - 1 > len(ALLOWED_VERSION_PROBE_ARGS):
        raise _err(
            folder,
            key,
            f"version probe argv must have 2..{len(ALLOWED_VERSION_PROBE_ARGS) + 1} tokens",
        )
    if any("\x00" in tok or tok != tok.strip() for tok in argv):
        raise _err(
            folder,
            key,
            "version probe argv tokens must not contain NUL or surrounding whitespace",
        )
    exe = argv[0]
    if not TOOL_NAME_RE.fullmatch(exe):
        raise _err(
            folder,
            key,
            f"invalid executable token {exe!r}",
        )
    allowed_exes = {tool_raw, *COMMAND_ALIASES.get(tool_raw, frozenset())}
    if exe not in allowed_exes:
        raise _err(
            folder,
            key,
            f"argv[0] {exe!r} does not match tool {tool_raw!r}",
        )
    for arg in argv[1:]:
        if arg not in ALLOWED_VERSION_PROBE_ARGS:
            raise _err(
                folder,
                key,
                f"disallowed version probe argument {arg!r}; allowed: {sorted(ALLOWED_VERSION_PROBE_ARGS)}",
            )
    return argv


def _parse_version_probes(
    raw: Any,
    needs: Tuple[str, ...],
    folder: str,
) -> Mapping[str, Any]:
    """Validate optional per-tool version_probes mapping in template.yaml (fail closed)."""
    if not isinstance(raw, dict) or len(raw) == 0:
        raise _err(
            folder,
            "version_probes",
            "must be a non-empty mapping of tool -> version-probe spec",
        )
    needs_set = {n.strip() for n in needs if isinstance(n, str) and n.strip()}
    parsed: Dict[str, Any] = {}
    for tool_raw, probe_raw in raw.items():
        if not isinstance(tool_raw, str) or not tool_raw.strip() or tool_raw != tool_raw.strip():
            raise _err(folder, "version_probes", "tool key must be a non-empty string")
        if not TOOL_NAME_RE.fullmatch(tool_raw):
            raise _err(
                folder,
                f"version_probes.{tool_raw}",
                f"invalid tool name {tool_raw!r}",
            )
        if tool_raw not in needs_set:
            raise _err(
                folder,
                f"version_probes.{tool_raw}",
                f"tool {tool_raw!r} must also be listed in 'needs'",
            )
        if isinstance(probe_raw, dict):
            for k in probe_raw:
                if not isinstance(k, str) or k not in ALLOWED_VERSION_PROBE_KEYS:
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}.{k}",
                        f"unknown key {k!r} in version_probes entry",
                    )
            probe_kind = probe_raw.get("probe")
            if probe_kind is None:
                if "argv" in probe_raw and set(probe_raw.keys()) == {"argv"}:
                    parsed[tool_raw] = _validate_command_probe_argv(
                        probe_raw["argv"],
                        tool_raw,
                        folder,
                        f"version_probes.{tool_raw}",
                    )
                    continue
                if "file" in probe_raw:
                    probe_kind = "file"
                elif "argv" in probe_raw:
                    probe_kind = "command"
                else:
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}.argv",
                        "missing required key 'argv' (or 'probe')",
                    )
            if not isinstance(probe_kind, str) or probe_kind not in VALID_PROBE_KINDS:
                raise _err(
                    folder,
                    f"version_probes.{tool_raw}.probe",
                    f"invalid probe kind {probe_kind!r}; expected one of {sorted(VALID_PROBE_KINDS)}",
                )
            if probe_kind == "command":
                if "argv" not in probe_raw:
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}.argv",
                        "missing required key 'argv'",
                    )
                extra_keys = set(probe_raw.keys()) - {"probe", "argv"}
                if extra_keys:
                    bad_k = sorted(extra_keys)[0]
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}.{bad_k}",
                        f"unexpected key {bad_k!r} for command probe",
                    )
                argv = _validate_command_probe_argv(
                    probe_raw["argv"],
                    tool_raw,
                    folder,
                    f"version_probes.{tool_raw}.argv",
                )
                parsed[tool_raw] = argv
                continue
            if probe_kind == "file":
                if "file" not in probe_raw:
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}.file",
                        "file probe requires 'file'",
                    )
                rel_file = _validate_rel_subpath(
                    _require_non_empty_str(
                        probe_raw["file"], folder, f"version_probes.{tool_raw}.file"
                    ),
                    folder,
                    f"version_probes.{tool_raw}.file",
                    allow_dot=False,
                )
                has_key = "key" in probe_raw and probe_raw["key"] is not None
                has_regex = "regex" in probe_raw and probe_raw["regex"] is not None
                if has_key == has_regex:
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}",
                        "file probe requires exactly one of 'key' or 'regex'",
                    )
                if "argv" in probe_raw:
                    raise _err(
                        folder,
                        f"version_probes.{tool_raw}.argv",
                        "file probe cannot specify 'argv'",
                    )
                spec_dict: Dict[str, Any] = {"probe": "file", "file": rel_file}
                if has_key:
                    spec_dict["key"] = _require_non_empty_str(
                        probe_raw["key"], folder, f"version_probes.{tool_raw}.key"
                    )
                else:
                    regex_str = _require_non_empty_str(
                        probe_raw["regex"], folder, f"version_probes.{tool_raw}.regex"
                    )
                    from .toolchk import _compile_safe_file_regex

                    try:
                        _compile_safe_file_regex(regex_str)
                    except ValueError as exc:
                        raise _err(
                            folder,
                            f"version_probes.{tool_raw}.regex",
                            str(exc),
                        ) from exc
                    spec_dict["regex"] = regex_str
                parsed[tool_raw] = MappingProxyType(spec_dict)
                continue
            extra_keys = set(probe_raw.keys()) - {"probe"}
            if extra_keys:
                bad_k = sorted(extra_keys)[0]
                raise _err(
                    folder,
                    f"version_probes.{tool_raw}.{bad_k}",
                    f"unexpected key {bad_k!r} for {probe_kind} probe",
                )
            parsed[tool_raw] = MappingProxyType({"probe": probe_kind})
            continue

        parsed[tool_raw] = _validate_command_probe_argv(
            probe_raw,
            tool_raw,
            folder,
            f"version_probes.{tool_raw}",
        )
    return MappingProxyType(parsed)


def _parse_check(raw: Any, folder: str) -> CheckSpec:
    """Validate and construct a CheckSpec."""
    if not isinstance(raw, dict):
        raise _err(folder, "repos.check", "must be a mapping")
    for k in raw:
        if k not in ALLOWED_CHECK_KEYS:
            raise _err(folder, f"repos.check.{k}", f"unknown key {k!r} in check")
    if "cmd" not in raw:
        raise _err(folder, "repos.check.cmd", "missing required key 'cmd'")
    cmd = _require_str_list(raw["cmd"], folder, "repos.check.cmd", non_empty=True)
    raw_cwd = raw.get("cwd", ".")
    cwd_str = _require_non_empty_str(raw_cwd, folder, "repos.check.cwd")
    cwd = _validate_rel_subpath(cwd_str, folder, "repos.check.cwd", allow_dot=True)
    prepare = (
        _require_str_list(raw["prepare"], folder, "repos.check.prepare", non_empty=True, non_empty_items=True)
        if "prepare" in raw else ()
    )
    extra_cmds = (
        _parse_cmd_matrix(raw["extra_cmds"], folder, "repos.check.extra_cmds")
        if "extra_cmds" in raw else ()
    )
    format_cmds = (
        _parse_format_cmds(raw["format_cmds"], folder, "repos.check.format_cmds")
        if "format_cmds" in raw else ()
    )
    return CheckSpec(
        cmd=cmd,
        cwd=cwd,
        prepare=prepare,
        extra_cmds=extra_cmds,
        format_cmds=format_cmds,
    )


def _parse_repos(
    raw_repos: Any,
    layout: str,
    template_dir: Path,
    folder: str,
) -> Tuple[RepoSpec, ...]:
    """Validate the repos list against layout and template folder contents."""
    if not isinstance(raw_repos, list) or len(raw_repos) == 0:
        raise _err(folder, "repos", "must be a non-empty list")
    if layout in ("mono", "single") and len(raw_repos) != 1:
        raise _err(
            folder,
            "repos",
            f"layout {layout!r} requires exactly 1 repo, got {len(raw_repos)}",
        )
    if layout == "poly" and len(raw_repos) < 2:
        raise _err(
            folder,
            "repos",
            f"layout 'poly' requires 2 or more repos, got {len(raw_repos)}",
        )

    specs: List[RepoSpec] = []
    seen_names: set[str] = set()
    for entry in raw_repos:
        if not isinstance(entry, dict):
            raise _err(folder, "repos", "each repo entry must be a mapping")
        for k in entry:
            if k not in ALLOWED_REPO_KEYS:
                raise _err(folder, f"repos.{k}", f"unknown key {k!r} in repo entry")
        if "name" not in entry:
            raise _err(folder, "repos.name", "missing required key 'name' in repo entry")
        raw_name = _require_non_empty_str(entry["name"], folder, "repos.name")
        rel_name = _validate_rel_subpath(raw_name, folder, "repos.name", allow_dot=False)
        if rel_name in seen_names:
            raise _err(folder, "repos.name", f"duplicate repo name {rel_name!r}")
        seen_names.add(rel_name)

        repo_dir = template_dir / rel_name
        if not repo_dir.exists() or repo_dir.is_symlink() or not repo_dir.is_dir():
            raise _err(
                folder,
                "repos",
                f"repo folder {rel_name!r} does not exist as a directory in template '{folder}'",
            )

        if "check" in entry:
            check_spec: Optional[CheckSpec] = _parse_check(entry["check"], folder)
        else:
            check_spec = None
        specs.append(RepoSpec(name=rel_name, check=check_spec))

    return tuple(specs)


def templates_root() -> Path:
    """Return default templates directory at the repository root."""
    return Path(__file__).resolve().parent / "templates"


def load_template(template_dir: os.PathLike[str] | str, *, opener: Any = None) -> TemplateSpec:
    """Load and strictly validate a single template directory containing template.yaml.

    `opener(path, flags) -> fd`, when given, opens template.yaml without following a
    link (the audit passes its checked opener, whose refusal propagates); without it the
    file is read by path.
    """
    tdir = _lexical_abs(template_dir)
    folder = tdir.name
    if not tdir.exists() or tdir.is_symlink() or not tdir.is_dir():
        raise _err(folder, "root", f"template directory does not exist: {tdir}")

    yaml_path = tdir / "template.yaml"
    if not yaml_path.exists() or yaml_path.is_symlink() or not yaml_path.is_file():
        raise _err(folder, "template.yaml", f"missing template.yaml in {tdir}")

    try:
        if opener is None:
            raw_text = yaml_path.read_text(encoding="utf-8")
        else:
            import stat  # noqa: PLC0415

            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
            with os.fdopen(opener(str(yaml_path), flags), "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise OSError(f"not a regular file: {yaml_path}")
                raw_text = handle.read().decode("utf-8")
        data = _load_yaml_strict(raw_text, folder)
    except TemplateError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise _err(folder, "template.yaml", f"invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise _err(folder, "root", "template.yaml top level must be a mapping")

    for k in data:
        if not isinstance(k, str) or k not in ALLOWED_TOP_KEYS:
            raise _err(folder, str(k), f"unknown key {k!r}")

    for req in REQUIRED_TOP_KEYS:
        if req not in data:
            raise _err(folder, req, f"missing required key {req!r}")

    raw_id = _require_non_empty_str(data["id"], folder, "id")
    if not ID_RE.fullmatch(raw_id):
        raise _err(folder, "id", f"id {raw_id!r} must match {ID_RE.pattern}")
    if raw_id != folder:
        raise _err(folder, "id", f"id {raw_id!r} must equal folder name {folder!r}")

    name = _require_non_empty_str(data["name"], folder, "name")
    summary = _require_non_empty_str(data["summary"], folder, "summary")

    kind = _require_non_empty_str(data["kind"], folder, "kind")
    if kind not in VALID_KINDS:
        raise _err(folder, "kind", f"invalid kind {kind!r}; expected one of {sorted(VALID_KINDS)}")

    layout = _require_non_empty_str(data["layout"], folder, "layout")
    if layout not in VALID_LAYOUTS:
        raise _err(
            folder,
            "layout",
            f"invalid layout {layout!r}; expected one of {sorted(VALID_LAYOUTS)}",
        )

    languages = _require_str_list(
        data["languages"],
        folder,
        "languages",
        non_empty=True,
        non_empty_items=True,
        lowercase=True,
    )

    raw_engine = data.get("engine")
    if raw_engine is None:
        engine: Optional[str] = None
    else:
        engine = _require_non_empty_str(raw_engine, folder, "engine")
        if engine != engine.lower() or engine != engine.strip():
            raise _err(folder, "engine", f"engine {engine!r} must be lowercase")

    tags = (
        _require_str_list(data["tags"], folder, "tags", non_empty=False)
        if "tags" in data
        else ()
    )
    raw_needs = (
        _require_str_list(data["needs"], folder, "needs", non_empty=False)
        if "needs" in data
        else ()
    )
    version_probes: Mapping[str, Any] = (
        _parse_version_probes(data["version_probes"], raw_needs, folder)
        if "version_probes" in data
        else MappingProxyType({})
    )
    needs: Tuple[str, ...] = tuple(
        _ToolNeedStr(item, version_probes[item]) if item in version_probes else item
        for item in raw_needs
    )
    lockfiles = (
        _parse_lockfiles(data["lockfiles"], folder)
        if "lockfiles" in data
        else ()
    )

    placeholder = _require_non_empty_str(data["placeholder"], folder, "placeholder")
    if not PLACEHOLDER_RE.fullmatch(placeholder):
        raise _err(
            folder,
            "placeholder",
            f"placeholder {placeholder!r} must match {PLACEHOLDER_RE.pattern}",
        )

    substitute_in = _require_str_list(
        data["substitute_in"],
        folder,
        "substitute_in",
        non_empty=True,
    )

    repos = _parse_repos(data["repos"], layout, tdir, folder)

    has_locked = "locked" in data
    has_approved_deps = "approved_deps" in data
    if has_locked != has_approved_deps:
        missing_pair = "approved_deps" if has_locked else "locked"
        present_pair = "locked" if has_locked else "approved_deps"
        raise _err(
            folder,
            missing_pair,
            f"template carrying {present_pair!r} must also carry {missing_pair!r}",
        )

    locked = _parse_locked(data["locked"], folder) if has_locked else ()
    approved_deps: Mapping[str, Tuple[str, ...]] = (
        _parse_approved_deps(data["approved_deps"], folder)
        if has_approved_deps
        else MappingProxyType({})
    )
    options: Mapping[str, OptionSpec] = (
        _parse_options(data["options"], folder)
        if "options" in data
        else MappingProxyType({})
    )

    return TemplateSpec(
        id=raw_id,
        name=name,
        summary=summary,
        kind=kind,
        layout=layout,
        languages=languages,
        engine=engine,
        tags=tags,
        needs=needs,
        placeholder=placeholder,
        substitute_in=substitute_in,
        repos=repos,
        root=tdir.resolve(),
        locked=locked,
        approved_deps=approved_deps,
        options=options,
        version_probes=version_probes,
        lockfiles=lockfiles,
    )


def load_templates(root: Optional[os.PathLike[str] | str] = None, *, excluded=None) -> List[TemplateSpec]:
    """Load all templates under root (sorted by id), skipping folders without template.yaml."""
    base = _lexical_abs(root) if root is not None else templates_root()
    if not base.exists() or base.is_symlink() or not base.is_dir():
        return []

    specs: List[TemplateSpec] = []
    for entry in sorted(base.iterdir(), key=lambda p: p.name):
        if excluded is not None and (excluded(entry) or excluded(entry / "template.yaml")):
            continue
        if entry.is_symlink() or not entry.is_dir():
            continue
        yaml_file = entry / "template.yaml"
        if not os.path.lexists(yaml_file):
            continue
        specs.append(load_template(entry))

    specs.sort(key=lambda s: s.id)
    return specs


def load_templates_lenient(
    root: Optional[os.PathLike[str] | str] = None,
) -> Tuple[List[TemplateSpec], List[str]]:
    """Load valid templates and collect TemplateError messages instead of raising."""
    base = _lexical_abs(root) if root is not None else templates_root()
    if not base.exists() or base.is_symlink() or not base.is_dir():
        return [], []

    specs: List[TemplateSpec] = []
    errors: List[str] = []
    for entry in sorted(base.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_dir():
            continue
        yaml_file = entry / "template.yaml"
        if not os.path.lexists(yaml_file):
            continue
        try:
            specs.append(load_template(entry))
        except TemplateError as exc:
            errors.append(str(exc))

    specs.sort(key=lambda s: s.id)
    return specs, errors


def options_as_json(
    target: Optional[
        TemplateSpec
        | Mapping[str, OptionSpec]
        | os.PathLike[str]
        | str
    ] = None,
    *,
    root: Optional[os.PathLike[str] | str] = None,
) -> Any:
    """Export template options as JSON-serializable dicts for the desktop UI.

    - Given a ``TemplateSpec``, ``Mapping[str, OptionSpec]``, template directory path,
      or template id string: returns ``List[Dict[str, Any]]`` (same style as
      ``questions_as_json()``).
    - Called with no arguments (or a templates root directory): returns a
      ``Dict[str, List[Dict[str, Any]]]`` mapping each template id to its option list.
    """
    if isinstance(target, TemplateSpec):
        return target.options_as_json()
    if isinstance(target, Mapping):
        out: List[Dict[str, Any]] = []
        for k, v in target.items():
            if isinstance(v, OptionSpec):
                out.append(v.as_json())
            elif isinstance(v, Mapping):
                entry = dict(v)
                entry.setdefault("id", str(k))
                if "choices" in entry and isinstance(entry["choices"], tuple):
                    entry["choices"] = list(entry["choices"])
                out.append(entry)
        return out
    if target is not None:
        base = _lexical_abs(root) if root is not None else templates_root()
        target_path = Path(target)
        if (target_path / "template.yaml").is_file():
            return load_template(target_path).options_as_json()
        if isinstance(target, str) and (base / target / "template.yaml").is_file():
            return load_template(base / target).options_as_json()
        if target_path.is_dir():
            return {spec.id: spec.options_as_json() for spec in load_templates(target_path)}
        raise _err(str(target), "options", f"cannot resolve template target {target!r}")
    return {spec.id: spec.options_as_json() for spec in load_templates(root)}


def _expand_format_cmd_spec(
    spec_id: str,
    entry: FormatCmdSpec | Tuple[str, ...],
    root: Path,
) -> Optional[Tuple[List[str], bool]]:
    """Resolve executable and optional file globs/suffixes for a single FormatCmdSpec."""
    import shutil

    if isinstance(entry, FormatCmdSpec):
        base_cmd = entry.cmd
        globs = entry.globs
        suffixes = entry.suffixes
        require_empty_stdout = entry.require_empty_stdout
    else:
        base_cmd = tuple(entry)
        globs = ()
        suffixes = ()
        require_empty_stdout = False

    executable = shutil.which(base_cmd[0])
    assert executable, f"Install {base_cmd[0]} for template {spec_id!r} format check"

    if not globs and not suffixes:
        return ([executable, *base_cmd[1:]], require_empty_stdout)

    suffix_set = {s.lower() for s in suffixes}
    matched_files: List[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or is_generated_lockfile(str(path)):
            continue
        rel_posix = path.relative_to(root).as_posix()
        rel_str = str(path.relative_to(root))
        by_suffix = bool(suffix_set and path.suffix.lower() in suffix_set)
        by_glob = bool(globs and any(_glob_matches_path(g, rel_posix) for g in globs))
        if by_suffix or by_glob:
            matched_files.append(rel_str)
    matched_files.sort()
    if not matched_files:
        return None
    return ([executable, *base_cmd[1:], *matched_files], require_empty_stdout)


def format_check_commands(
    spec: TemplateSpec,
    root: Path,
) -> List[Tuple[List[str], bool]]:
    """Build static formatter/lint commands for a staged template from its template.yaml data."""
    import shutil

    for need in spec.needs:
        if need.strip():
            assert shutil.which(need), f"Install required tool {need!r} for template {spec.id!r}"

    commands: List[Tuple[List[str], bool]] = []
    for tool, args, suffixes in (
        ("yamllint", ["--strict"], {".yaml", ".yml"}),
        ("rumdl", ["check", "--no-cache"], {".md"}),
    ):
        executable = shutil.which(tool)
        assert executable, f"Install {tool} for scaffold lint regression coverage"
        files = sorted(
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file()
            and path.suffix in suffixes
            and not is_generated_lockfile(str(path))
        )
        if files:
            commands.append(([executable, *args, *files], False))

    explicit_format_cmds: Tuple[FormatCmdSpec | Tuple[str, ...], ...] = ()
    if spec.repos and spec.repos[0].check is not None:
        explicit_format_cmds = spec.repos[0].check.format_cmds

    assert explicit_format_cmds, (
        f"Template {spec.id!r} must declare repos[0].check.format_cmds in template.yaml"
    )
    for entry in explicit_format_cmds:
        expanded = _expand_format_cmd_spec(spec.id, entry, root)
        if expanded is not None:
            commands.append(expanded)
    return commands


def run_scaffold_format_checks(spec: TemplateSpec, root: Path) -> None:
    """Execute all static formatter and doc/config lint checks for a staged template repo."""
    import subprocess

    for command, require_empty_stdout in format_check_commands(spec, root):
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"{command}\n{result.stdout}\n{result.stderr}"
        if require_empty_stdout:
            assert result.stdout.strip() == "", f"{command}\n{result.stdout}\n{result.stderr}"

