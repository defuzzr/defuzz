"""Read-only Hermes fact adapters for the Defuzz audit sweep (§2, §3, §4, §12, §13).

Settled invariants enforced here:
- Uses public `hermes_constants` profile identity/root helpers with an explicit
  task-local home, or injected callables for isolated tests. No private CLI imports.
- Because the name-list adapter suppresses `OSError`, `enumerate_profiles()`
  separately verifies readability of `<default_root>/profiles` and reports incomplete
  enumeration (`coverage="could_not_verify"`) instead of silently claiming only `default`
  exists (§2).
- Resolves built-in memory files (`memories/MEMORY.md` and `memories/USER.md`) with
  symlink detection and safe descriptor-relative reading (§2, §12).
- Resolves skill search roots in official precedence order (`TIER_PROJECT` > `TIER_LOCAL` >
  `TIER_CREATE_DIR` > `TIER_EXTERNAL`), distinguishing profile-carried vs effective
  available counts and recording shadowed skills (§2, §3).
- Resolves last-use evidence from read-only `state.db` `started_at` with fallback to
  newest mtime under `memories/` and `sessions/`; neither -> `could_not_verify`, never
  "unused" (§2, §8, §12, §13.5).
- Separates time-independent evidence from `as_of` / `threshold_days` evaluation so cached
  evidence can be re-evaluated at a new run's `as_of` timestamp while resume preserves its
  original `as_of` (§12 "Time-dependent cache results").
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .capture import coherent_profile_capture
from .contract import (
    CLASSIFICATION_INFO,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    make_finding,
)
from .fingerprint import (
    DEFAULT_MAX_FILE_BYTES,
    SafeReadResult,
    TreeFingerprintManifest,
    build_tree_fingerprint_manifest,
    classify_mode,
    safe_read_regular_file,
)
from .readonly_db import (
    ProfileRegistrationsSnapshot,
    ProfileSessionEvidence,
    read_profile_registrations_readonly,
    read_profile_session_evidence,
    union_profile_registrations,
)
from .vendor.profile_context import (
    CHARS_PER_TOKEN,
    CONTEXT_TRUNCATE_HEAD_RATIO,
    CONTEXT_TRUNCATE_TAIL_RATIO,
    DEFAULT_AGENT_IDENTITY,
    DEFAULT_CONTEXT_FILE_MAX_CHARS,
    ESSENTIAL_SKILLS,
    EXECUTION_GUIDANCE_MODELS,
    GOOGLE_MODEL_OPERATIONAL_GUIDANCE,
    HERMES_AGENT_HELP_GUIDANCE,
    HERMES_AGENT_HELP_GUIDANCE_NO_SKILLS,
    OPENAI_MODEL_EXECUTION_GUIDANCE,
    PARALLEL_TOOL_CALL_GUIDANCE,
    SESSION_SEARCH_GUIDANCE,
    SKILL_PROMPT_DESC_LIMIT,
    SKILLS_GUIDANCE,
    STEER_CHANNEL_NOTE,
    STEER_MARKER_CLOSE,
    STEER_MARKER_OPEN,
    TASK_COMPLETION_GUIDANCE,
    TOKEN_ESTIMATOR_VERSION,
    TOOL_USE_ENFORCEMENT_GUIDANCE,
    TOOL_USE_ENFORCEMENT_MODELS,
    _CJK_DENSE_RE,
    _build_memory_guidance as _build_memory_guidance_facts,
)

_GATE_WORDS = {
    **dict.fromkeys(("true", "always", "yes", "on"), True),
    **dict.fromkeys(("false", "never", "no", "off"), False),
}


def _model_gate_facts(setting: Any, model: str, default_models: Sequence[str]) -> bool:
    if setting is True or setting is False:
        return setting
    if isinstance(setting, str) and setting.strip().lower() in _GATE_WORDS:
        return _GATE_WORDS[setting.strip().lower()]
    model_lower = (model or "").lower()
    if isinstance(setting, (list, tuple, set, frozenset)):
        return any(str(p).lower() in model_lower for p in setting if str(p).strip())
    return any(p in model_lower for p in default_models)

FACTS_ADAPTER_VERSION = "1.0.0"

TIER_PROJECT, TIER_LOCAL, TIER_CREATE_DIR, TIER_EXTERNAL = range(4)
PROJECT_SKILLS_SUBDIRS: tuple[str, ...] = (".hermes/skills", ".agents/skills")
EXCLUDED_SKILL_DIRS: frozenset[str] = frozenset({
    ".git", ".github", ".hub", ".archive", ".curator_backups", ".locks",
    ".hermes-dist", ".venv", "venv", "node_modules", "site-packages",
    "__pycache__", ".tox", ".nox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
})
SKILL_SUPPORT_DIRS: frozenset[str] = frozenset({"references", "templates", "assets", "scripts"})
_OPTIONAL_ROOT_PRUNED_DIRS: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", "target", "__pycache__", ".git",
})

_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_PROFILE_IDENTITY_MARKERS: tuple[str, ...] = (
    "config.yaml", ".env", "SOUL.md", "profile.yaml", "auth.json", "state.db",
)
_MEMORY_PATH_REF_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>~/[A-Za-z0-9_./-]+|/(?:home|Users|root|opt|srv|var|tmp|etc|mnt|workspace|Projects|projects|work|repos|code)/[A-Za-z0-9_./-]+)"
)

EntrySecurityCheck = Callable[[str, dict[str, Any]], Sequence[str]]


def _abs_path(raw: Path | str, *, expand_vars: bool = False) -> Path:
    text = os.path.expandvars(os.fspath(raw)) if expand_vars else os.fspath(raw)
    return Path(os.path.abspath(os.path.expanduser(text)))


def estimate_tokens_rough(text: str) -> dict[str, Any]:
    """Deterministic rough token estimator matching `agent/model_metadata.py:2349-2366` (§2 "Token counts")."""
    s = str(text or "")
    char_count = len(s)
    utf8_bytes = len(s.encode("utf-8", "replace"))
    if not s:
        est = 0
    elif s.isascii():
        est = (char_count + 3) // CHARS_PER_TOKEN
    else:
        stripped = _CJK_DENSE_RE.sub("", s)
        dense = char_count - len(stripped)
        est = dense + ((len(stripped.encode("utf-8", "replace")) + 3) // CHARS_PER_TOKEN)
    return {
        "characters": char_count,
        "utf8_bytes": utf8_bytes,
        "estimated_tokens": est,
        "estimator_version": TOKEN_ESTIMATOR_VERSION,
        "is_exact": False,
    }


def _resolve_official_profile_fns(
    *,
    list_profile_names_fn: Callable[[], list[str]] | None = None,
    get_profile_dir_fn: Callable[[str], Path] | None = None,
) -> tuple[Callable[[], list[str]], Callable[[str], Path]]:
    """Resolve official `list_profile_names` and `get_profile_dir` callables."""
    if list_profile_names_fn is not None and get_profile_dir_fn is not None:
        return list_profile_names_fn, get_profile_dir_fn

    from hermes_constants import (
        get_default_hermes_root,
        get_hermes_home,
        named_profile_is_live,
    )

    default_root = get_default_hermes_root(home=get_hermes_home())

    def profile_dir(name: str) -> Path:
        canon = str(name).strip().lower()
        if canon == "default":
            return default_root
        if not _PROFILE_ID_RE.fullmatch(canon):
            raise ValueError(f"Invalid profile name: {name!r}")
        return default_root / "profiles" / canon

    def profile_names() -> list[str]:
        names = ["default"]
        container = default_root / "profiles"
        with contextlib.suppress(OSError):
            for entry in sorted(container.iterdir(), key=lambda p: p.name):
                if entry.name != "default" and _PROFILE_ID_RE.fullmatch(entry.name) and named_profile_is_live(entry):
                    names.append(entry.name)
        return names

    return list_profile_names_fn or profile_names, get_profile_dir_fn or profile_dir


def resolve_mcp_entry_security_check(
    *,
    check_fn: EntrySecurityCheck | None = None,
) -> EntrySecurityCheck | None:
    """Return an injected checker, otherwise unknown (no public core security API)."""
    return check_fn


def resolve_active_profile_name(
    *,
    default_root: Path | None = None,
    get_profile_dir_fn: Callable[[str], Path] | None = None,
) -> str:
    """Resolve the active profile name from context override, `$HERMES_HOME`, or `<default_root>/active_profile`."""
    _, get_dir = _resolve_official_profile_fns(get_profile_dir_fn=get_profile_dir_fn)
    def_home = Path(default_root) if default_root is not None else Path(get_dir("default"))

    with contextlib.suppress(Exception):
        from hermes_constants import get_hermes_home, profile_name_for_home  # type: ignore

        name = profile_name_for_home(get_hermes_home())
        if name:
            return str(name)

    env_home = os.environ.get("HERMES_HOME", "").strip()
    if env_home:
        env_path = Path(os.path.expanduser(os.path.expandvars(env_home)))
        if env_path.parent.name == "profiles" and _PROFILE_ID_RE.match(env_path.name):
            return env_path.name
        with contextlib.suppress(OSError):
            if env_path.resolve(strict=False) == def_home.resolve(strict=False):
                return "default"

    res = safe_read_regular_file(def_home, "active_profile", max_bytes=4096, retain_bytes=True)
    if res.kind == "regular" and res.stable and res.content:
        candidate = res.content.decode("utf-8", errors="replace").strip().lower()
        if candidate == "default" or _PROFILE_ID_RE.match(candidate):
            return candidate
    return "default"


@dataclass(frozen=True)
class ProfileEnumerationResult:
    """Result of official profile enumeration plus separate readability verification (§2)."""

    profiles: list[dict[str, Any]]
    default_root: str
    profiles_container: str
    active_profile: str
    coverage: str
    enumeration_complete: bool
    errors: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": self.profiles,
            "default_root": self.default_root,
            "profiles_container": self.profiles_container,
            "active_profile": self.active_profile,
            "coverage": self.coverage,
            "enumeration_complete": self.enumeration_complete,
            "errors": self.errors,
            "findings": self.findings,
        }


def _probe_dir_readable(path: Path | str) -> None:
    with os.scandir(path) as it:
        next(it, None)


def _verify_default_root_readability(default_dir: Path, errors: list[str]) -> None:
    try:
        st_def = os.lstat(default_dir)
        if stat.S_ISLNK(st_def.st_mode):
            errors.append(f"Default profile root is a symlink: {default_dir}")
        elif stat.S_ISDIR(st_def.st_mode):
            _probe_dir_readable(default_dir)
        else:
            errors.append(f"Default profile root is not a directory: {default_dir}")
    except FileNotFoundError:
        errors.append(f"Default profile root does not exist: {default_dir}")
    except OSError as exc:
        errors.append(f"Default profile root is unreadable ({default_dir}): {exc}")


def _verify_profiles_container_readability(profiles_container: Path, errors: list[str]) -> None:
    try:
        st_prof = os.lstat(profiles_container)
        if stat.S_ISLNK(st_prof.st_mode):
            errors.append(f"Named profiles container is a symlink: {profiles_container}")
            return
        if not stat.S_ISDIR(st_prof.st_mode):
            return
        with os.scandir(profiles_container) as it:
            entries = sorted(it, key=lambda e: e.name)
    except FileNotFoundError:
        return
    except OSError as exc:
        errors.append(f"Could not enumerate named profiles container ({profiles_container}): {exc}")
        return

    tombstone_dir = profiles_container / ".deleted"
    try:
        if stat.S_ISDIR(os.lstat(tombstone_dir).st_mode):
            _probe_dir_readable(tombstone_dir)
    except FileNotFoundError:
        pass
    except OSError as exc:
        errors.append(f"Tombstone directory unreadable ({tombstone_dir}): {exc}")

    for entry in entries:
        if entry.name.startswith(".") or entry.name == "default" or not _PROFILE_ID_RE.match(entry.name):
            continue
        try:
            est = entry.stat(follow_symlinks=False)
        except OSError as exc:
            errors.append(f"Could not stat named profile candidate {entry.path}: {exc}")
            continue
        if stat.S_ISDIR(est.st_mode):
            try:
                _probe_dir_readable(entry.path)
            except OSError as exc:
                errors.append(f"Named profile directory unreadable ({entry.path}): {exc}")


def enumerate_profiles(
    *,
    list_profile_names_fn: Callable[[], list[str]] | None = None,
    get_profile_dir_fn: Callable[[str], Path] | None = None,
    active_profile: str | None = None,
) -> ProfileEnumerationResult:
    """Enumerate official Hermes profiles and separately verify directory readability (§2)."""
    list_fn, dir_fn = _resolve_official_profile_fns(
        list_profile_names_fn=list_profile_names_fn,
        get_profile_dir_fn=get_profile_dir_fn,
    )
    default_dir = Path(dir_fn("default"))
    profiles_container = default_dir / "profiles"
    resolved_active = active_profile or resolve_active_profile_name(
        default_root=default_dir,
        get_profile_dir_fn=dir_fn,
    )

    errors: list[str] = []
    _verify_default_root_readability(default_dir, errors)
    _verify_profiles_container_readability(profiles_container, errors)

    try:
        raw_names = list(list_fn())
    except OSError as exc:
        raw_names = ["default"]
        errors.append(f"list_profile_names() raised OSError: {exc}")

    seen_names: set[str] = set()
    profile_rows: list[dict[str, Any]] = []
    for name in raw_names:
        canon = str(name).strip()
        if not canon or canon in seen_names:
            continue
        seen_names.add(canon)
        try:
            pdir = Path(dir_fn(canon))
        except Exception as exc:
            errors.append(f"get_profile_dir({canon!r}) failed: {exc}")
            continue
        profile_rows.append({
            "name": canon,
            "path": str(pdir),
            "is_default": canon == "default",
            "is_active": canon == resolved_active,
        })

    coverage = COVERAGE_COULD_NOT_VERIFY if errors else COVERAGE_VERIFIED
    findings = [
        make_finding(
            rule_id="inventory.profile_enumeration_incomplete",
            classification=CLASSIFICATION_INFO,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            affected_identities=["default"],
            source_paths=[str(profiles_container)],
            evidence={"errors": errors, "enumerated_profiles": [p["name"] for p in profile_rows]},
            consequence="Profile enumeration was incomplete because one or more profile directories could not be read.",
            limitations="; ".join(errors),
        )
    ] if errors else []

    return ProfileEnumerationResult(
        profiles=profile_rows,
        default_root=str(default_dir),
        profiles_container=str(profiles_container),
        active_profile=resolved_active,
        coverage=coverage,
        enumeration_complete=(coverage == COVERAGE_VERIFIED),
        errors=errors,
        findings=findings,
    )


class DuplicateConfigKeyError(ValueError):
    """Fixed classification only: never expose the duplicate key or source text."""


def _parse_simple_yaml_mapping(text: str, *, unbounded=False, reject_duplicate_keys=False) -> dict[str, Any]:
    """Pinned safe YAML parser; explicit JSON normalization, no heuristic fallback."""
    from datetime import date, datetime
    import math
    import yaml

    from .outward_structured import check_audit_yaml

    check_audit_yaml(yaml)  # accepted range + behaviour probe; one-line ValueError otherwise
    nodes_left = 10000

    def normalize(value: Any, ancestors: tuple[int, ...] = ()) -> Any:
        nonlocal nodes_left
        nodes_left -= 1
        if not unbounded and (nodes_left < 0 or len(ancestors) > 64):
            raise ValueError("YAML normalization budget exceeded")
        if isinstance(value, (date, datetime)):
            return value.isoformat()
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite YAML number")
        if value is None or type(value) in (str, int, float, bool):
            return value
        if id(value) in ancestors:
            raise ValueError("Recursive YAML aliases are unsupported")
        parents = (*ancestors, id(value))
        if isinstance(value, list):
            return [normalize(v, parents) for v in value]
        if isinstance(value, dict) and all(type(k) is str for k in value):
            return {k: normalize(v, parents) for k, v in value.items()}
        raise ValueError("Unsupported YAML value or non-string key")

    checked_nodes: set[int] = set()

    class UniqueKeyLoader(yaml.SafeLoader):
        # hermes_yaml.py:3,22-38: ruamel rejects duplicate mappings. Opt-in keeps
        # existing facts/frontmatter callers unchanged. Validate before merge expansion,
        # because an explicit key overriding an inherited merge is valid YAML.
        def flatten_mapping(self, node):
            if id(node) in checked_nodes:
                return
            checked_nodes.add(id(node))
            seen = set()
            for key, _ in node.value:
                if not isinstance(key, yaml.ScalarNode):
                    raise ValueError('Unsupported YAML mapping key')
                identity = (key.tag, key.value)
                if identity in seen:
                    raise DuplicateConfigKeyError('duplicate_config_key')
                seen.add(identity)
            super().flatten_mapping(node)

    try:
        value = normalize(yaml.load(text, Loader=UniqueKeyLoader) if reject_duplicate_keys else yaml.safe_load(text))
    except yaml.YAMLError as exc:
        raise ValueError("Invalid audit YAML") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Audit YAML must be a mapping")
    return value


def parse_frontmatter_stdlib(content: str) -> tuple[dict[str, Any], str]:
    """Parse YAML frontmatter from SKILL.md / markdown using stdlib-safe parsing (`agent/skill_utils.py:71-91`)."""
    cleaned = content.removeprefix("\ufeff")
    if not cleaned.startswith("---"):
        return {}, cleaned
    end_match = re.search(r"\n---\s*\n", cleaned[3:])
    if not end_match:
        return {}, cleaned
    yaml_text = cleaned[3 : end_match.start() + 3]
    body = cleaned[end_match.end() + 3 :]
    fm = _parse_simple_yaml_mapping(yaml_text)
    return (fm if isinstance(fm, dict) else {}), body


def _make_memory_file_record(
    *,
    target_key: str,
    rel_path: str,
    path: str,
    exists: bool,
    enabled: bool,
    char_limit: int,
    is_symlink: bool = False,
    symlink_target: str | None = None,
    coverage: str = COVERAGE_VERIFIED,
    stable: bool = True,
    size_bytes: int = 0,
    sha256: str | None = None,
    file_mtime_ns: int | None = None,
    entries: list[dict[str, Any]] | None = None,
    token_text: str = "",
    raw_token_text: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "target": target_key,
        "rel_path": rel_path,
        "path": path,
        "exists": exists,
        "enabled": enabled,
        "char_limit": char_limit,
        "is_symlink": is_symlink,
        "symlink_target": symlink_target,
        "coverage": coverage,
        "stable": stable,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "file_mtime_ns": file_mtime_ns,
        "entries": entries if entries is not None else [],
        "token_metrics": estimate_tokens_rough(token_text),
        "error": error,
    }
    if raw_token_text is not None:
        record["raw_token_metrics"] = estimate_tokens_rough(raw_token_text)
    return record


def _parse_memory_entries(raw_text: str) -> list[dict[str, Any]]:
    if not raw_text.strip():
        return []
    raw_entries = [e.strip() for e in raw_text.split("\n§\n") if e.strip()]
    parsed: list[dict[str, Any]] = []
    for idx, entry_text in enumerate(raw_entries):
        norm_ws = " ".join(entry_text.split())
        parsed.append({
            "index": idx,
            "text": entry_text,
            "sha256_exact": hashlib.sha256(entry_text.encode("utf-8")).hexdigest(),
            "sha256_normalized_ws": hashlib.sha256(norm_ws.encode("utf-8")).hexdigest(),
            "char_count": len(entry_text),
            "authoritative_created_at": None,
        })
    return parsed


def _resolve_single_memory_file(
    pdir: Path,
    target_key: str,
    rel_path: str,
    enabled: bool,
    char_limit: int,
    max_bytes: int,
) -> dict[str, Any]:
    read_res = safe_read_regular_file(pdir, rel_path, max_bytes=max_bytes, retain_bytes=True)
    if read_res.kind == "missing":
        return _make_memory_file_record(
            target_key=target_key,
            rel_path=rel_path,
            path=read_res.path,
            exists=False,
            enabled=enabled,
            char_limit=char_limit,
        )
    if read_res.kind == "symlink":
        return _make_memory_file_record(
            target_key=target_key,
            rel_path=rel_path,
            path=read_res.path,
            exists=True,
            enabled=enabled,
            char_limit=char_limit,
            is_symlink=True,
            symlink_target=read_res.symlink_target,
            coverage=read_res.coverage,
            stable=read_res.stable,
            size_bytes=read_res.size or 0,
            file_mtime_ns=read_res.mtime_ns,
            error=read_res.error,
        )
    if read_res.coverage != COVERAGE_VERIFIED or not read_res.stable or read_res.content is None:
        return _make_memory_file_record(
            target_key=target_key,
            rel_path=rel_path,
            path=read_res.path,
            exists=True,
            enabled=enabled,
            char_limit=char_limit,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            stable=read_res.stable,
            size_bytes=read_res.size or 0,
            sha256=read_res.sha256,
            file_mtime_ns=read_res.mtime_ns,
            error=read_res.error or "Unreadable memory file",
        )

    raw_text = read_res.content.decode("utf-8", errors="replace")
    return _make_memory_file_record(
        target_key=target_key,
        rel_path=rel_path,
        path=read_res.path,
        exists=True,
        enabled=enabled,
        char_limit=char_limit,
        size_bytes=int(read_res.size or 0),
        sha256=read_res.sha256,
        file_mtime_ns=read_res.mtime_ns,
        entries=_parse_memory_entries(raw_text),
        token_text=raw_text if enabled else "",
        raw_token_text=raw_text,
    )


def resolve_profile_memory_facts(
    profile_name: str,
    profile_dir: Path | str,
    *,
    config: Mapping[str, Any] | None = None,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Resolve built-in memory facts (`memories/MEMORY.md` and `memories/USER.md`) for a profile (§2, §5, §12)."""
    pdir = Path(profile_dir)
    raw_mem = (config or {}).get("memory")
    mem_cfg: Mapping[str, Any] = raw_mem if isinstance(raw_mem, Mapping) else {}
    specs = (
        ("memory", "memories/MEMORY.md", bool(mem_cfg.get("memory_enabled", True)), int(mem_cfg.get("memory_char_limit", 2200))),
        ("user", "memories/USER.md", bool(mem_cfg.get("user_profile_enabled", True)), int(mem_cfg.get("user_char_limit", 1375))),
    )

    files_out = {
        key: _resolve_single_memory_file(pdir, key, rel_path, enabled, char_limit, max_bytes)
        for key, rel_path, enabled, char_limit in specs
    }
    coverage = (
        COVERAGE_COULD_NOT_VERIFY
        if any(f["coverage"] != COVERAGE_VERIFIED for f in files_out.values())
        else COVERAGE_VERIFIED
    )
    return {
        "profile_name": profile_name,
        "coverage": coverage,
        "memory_bytes": sum(int(f["size_bytes"]) for f in files_out.values()),
        "files": files_out,
    }


def _expand_skill_config_dir(raw_entry: str, profile_dir: Path) -> Path:
    expanded = Path(os.path.expanduser(str(raw_entry).strip()))
    return expanded if expanded.is_absolute() else (profile_dir / expanded)


def _normalize_str_list(raw: Any) -> list[str]:
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("["):
            with contextlib.suppress(ValueError, SyntaxError):
                parsed = ast.literal_eval(s)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
        return [s] if s else []
    if isinstance(raw, (list, tuple, set, frozenset)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return []


def resolve_profile_skill_roots(
    profile_dir: Path | str,
    *,
    config: Mapping[str, Any] | None = None,
    project_root: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Resolve skill search roots in official `agent/skill_utils.py:402-424` precedence order (§2)."""
    pdir = _abs_path(profile_dir)
    local_skills = pdir / "skills"
    raw_skills_cfg = (config or {}).get("skills")
    skills_cfg: Mapping[str, Any] = raw_skills_cfg if isinstance(raw_skills_cfg, Mapping) else {}

    roots: list[tuple[int, str, Path]] = []

    if project_root is not None and skills_cfg.get("project_discovery") is not False:
        trusted_resolved = {
            str(_abs_path(t_entry, expand_vars=True))
            for t_entry in _normalize_str_list(skills_cfg.get("trusted_project_dirs"))
        }
        proj_abs = _abs_path(project_root)
        if str(proj_abs) in trusted_resolved:
            for sub in PROJECT_SKILLS_SUBDIRS:
                cand = proj_abs / sub
                if cand != local_skills and cand.is_dir():
                    roots.append((TIER_PROJECT, "project", cand))

    roots.append((TIER_LOCAL, "profile_local", local_skills))

    raw_create = skills_cfg.get("create_dir")
    if isinstance(raw_create, str) and raw_create.strip():
        create_path = Path(os.path.abspath(str(_expand_skill_config_dir(raw_create, pdir))))
        if create_path != local_skills:
            roots.append((TIER_CREATE_DIR, "create_dir", create_path))

    for ext_entry in _normalize_str_list(skills_cfg.get("external_dirs")):
        ext_path = Path(os.path.abspath(str(_expand_skill_config_dir(ext_entry, pdir))))
        if ext_path != local_skills:
            roots.append((TIER_EXTERNAL, "external_dir", ext_path))

    deduped: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for tier, source_kind, rpath in roots:
        key = str(rpath)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        cfg_key = "skills." + ("external_dirs" if source_kind == "external_dir" else source_kind)
        deduped.append({
            "tier": tier,
            "source_kind": source_kind,
            "path": key,
            "is_profile_owned": (tier == TIER_LOCAL),
            "blending": None if tier == TIER_LOCAL else {
                "source": str(pdir / "config.yaml"),
                "target": key,
                "relationship": "external_skill_root",
                "evidence": {"config_key": cfg_key},
            },
        })
    return deduped


def _collect_skill_support_hashes(root_path: Path, skill_pkg_root: Path) -> tuple[dict[str, str], str]:
    support_hashes: dict[str, str] = {}
    coverage = COVERAGE_VERIFIED
    for s_dir, s_subdirs, s_files in os.walk(str(skill_pkg_root), topdown=True, followlinks=False):
        s_subdirs[:] = sorted(d for d in s_subdirs if d not in EXCLUDED_SKILL_DIRS)
        for sf in sorted(s_files):
            if sf == "SKILL.md" and Path(s_dir) == skill_pkg_root:
                continue
            full_sf = os.path.join(s_dir, sf)
            sf_rel_to_root = os.path.relpath(full_sf, str(root_path)).replace("\\", "/")
            sf_rel_to_pkg = os.path.relpath(full_sf, str(skill_pkg_root)).replace("\\", "/")
            sf_res = safe_read_regular_file(root_path, sf_rel_to_root, retain_bytes=False)
            if sf_res.coverage == COVERAGE_VERIFIED and sf_res.sha256:
                support_hashes[sf_rel_to_pkg] = sf_res.sha256
            else:
                coverage = COVERAGE_COULD_NOT_VERIFY
    return support_hashes, coverage


def _read_skill_package(
    root_path: Path,
    dirpath: str,
    tier: int,
    source_kind: str,
) -> tuple[dict[str, Any] | None, str, list[str]]:
    rel_dir = os.path.relpath(dirpath, str(root_path)).replace("\\", "/")
    if rel_dir == ".":
        rel_skill_md = "SKILL.md"
        rel_dir = ""
    else:
        rel_skill_md = f"{rel_dir}/SKILL.md"

    read_res = safe_read_regular_file(root_path, rel_skill_md, retain_bytes=True)
    if read_res.coverage != COVERAGE_VERIFIED or not read_res.stable or read_res.content is None:
        return None, COVERAGE_COULD_NOT_VERIFY, [f"Could not safely read {root_path / rel_skill_md}: {read_res.error}"]

    text = read_res.content.decode("utf-8", errors="replace")
    try:
        fm, body = parse_frontmatter_stdlib(text)
    except (ValueError, ImportError, RecursionError):
        return None, COVERAGE_COULD_NOT_VERIFY, ["Skill frontmatter could not be parsed"]

    declared_name = str(fm.get("name") or Path(dirpath).name).strip()
    description = str(fm.get("description") or "").strip()
    support_hashes, sup_cov = _collect_skill_support_hashes(root_path, Path(dirpath))

    norm_ws_md = " ".join(text.split())
    rel_parts = [p for p in (rel_dir or declared_name).split("/") if p]
    category = "/".join(rel_parts[:-1]) if len(rel_parts) > 1 else "general"
    pkg_digest = hashlib.sha256(
        json.dumps(
            {
                "skill_md_sha256": read_res.sha256,
                "supporting_files": dict(sorted(support_hashes.items())),
                "platforms": fm.get("platforms"),
                "environments": fm.get("environments"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    return (
        {
            "name": declared_name,
            "description": description,
            "category": category,
            "tier": tier,
            "source_kind": source_kind,
            "root": str(root_path),
            "relative_path": rel_dir or declared_name,
            "skill_md_path": read_res.path,
            "skill_md_sha256": read_res.sha256,
            "skill_md_ws_sha256": hashlib.sha256(norm_ws_md.encode("utf-8")).hexdigest(),
            "supporting_files": sorted(support_hashes.keys()),
            "supporting_files_sha256": support_hashes,
            "package_sha256": pkg_digest,
            "size_bytes": int(read_res.size or 0),
            "body_text": body,
            "body_char_count": len(body),
            "token_metrics": estimate_tokens_rough(text),
            "frontmatter": fm,
        },
        sup_cov,
        [],
    )


def _scan_skills_in_root(root_path: Path, tier: int, source_kind: str) -> tuple[list[dict[str, Any]], str, list[str]]:
    """Scan a skill root for `SKILL.md` packages without following external symlink loops (§2, §5, §12)."""
    try:
        st_root = os.lstat(root_path)
    except FileNotFoundError:
        return [], COVERAGE_VERIFIED, []
    except OSError as exc:
        return [], COVERAGE_COULD_NOT_VERIFY, [f"Could not stat skill root {root_path}: {exc}"]

    if stat.S_ISLNK(st_root.st_mode):
        raw_target = os.readlink(root_path)
        return (
            [],
            COVERAGE_COULD_NOT_VERIFY,
            [f"Skill root {root_path} is a symlink (-> {raw_target}); external symlinked trees are not followed"],
        )
    if not stat.S_ISDIR(st_root.st_mode):
        return [], COVERAGE_COULD_NOT_VERIFY, [f"Skill root {root_path} is not a directory"]

    skills: list[dict[str, Any]] = []
    errors: list[str] = []
    coverage = COVERAGE_VERIFIED

    for dirpath, dirnames, filenames in os.walk(str(root_path), topdown=True, followlinks=False):
        has_skill_md = "SKILL.md" in filenames
        kept_dirs: list[str] = []
        for d in sorted(dirnames):
            if d in EXCLUDED_SKILL_DIRS or (has_skill_md and d in SKILL_SUPPORT_DIRS):
                continue
            d_full = os.path.join(dirpath, d)
            try:
                if stat.S_ISLNK(os.lstat(d_full).st_mode):
                    continue
            except OSError as exc:
                coverage = COVERAGE_COULD_NOT_VERIFY
                errors.append(f"Could not stat skill subdir {d_full}: {exc}")
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        if has_skill_md:
            pkg, pkg_cov, pkg_errs = _read_skill_package(root_path, dirpath, tier, source_kind)
            if pkg_cov != COVERAGE_VERIFIED:
                coverage = COVERAGE_COULD_NOT_VERIFY
            errors.extend(pkg_errs)
            if pkg is not None:
                skills.append(pkg)

    return skills, coverage, errors


def _assign_skill_precedence_and_flags(
    all_entries: list[dict[str, Any]],
    disabled_names: set[str],
    auto_load_names: list[str],
) -> None:
    by_name: dict[str, list[int]] = {}
    for idx, entry in enumerate(all_entries):
        by_name.setdefault(str(entry["name"]), []).append(idx)

    for name, idxs in by_name.items():
        min_tier = min(int(all_entries[i]["tier"]) for i in idxs)
        top_idxs = [i for i in idxs if int(all_entries[i]["tier"]) == min_tier]
        sha_set = {all_entries[j]["skill_md_sha256"] for j in top_idxs}
        ranked = sorted(top_idxs, key=lambda j: (len(Path(all_entries[j]["relative_path"]).parts), j))

        for i in idxs:
            if int(all_entries[i]["tier"]) > min_tier:
                all_entries[i]["status"] = "shadowed"
                all_entries[i]["load_name"] = None
            elif len(top_idxs) == 1:
                all_entries[i]["status"] = "unique"
                all_entries[i]["load_name"] = name
            elif len(sha_set) == 1:
                is_winner = i == ranked[0]
                all_entries[i]["status"] = "unique" if is_winner else "shadowed"
                all_entries[i]["load_name"] = name if is_winner else None
            else:
                all_entries[i]["status"] = "ambiguous"
                all_entries[i]["load_name"] = all_entries[i]["relative_path"]

    for entry in all_entries:
        candidates = {str(entry["name"])}
        if entry.get("load_name") is not None:
            candidates.add(str(entry["load_name"]))
        entry["disabled"] = bool(candidates & disabled_names)
        entry["auto_loaded"] = any(c in auto_load_names for c in candidates)


def resolve_profile_skills_facts(
    profile_name: str,
    profile_dir: Path | str,
    *,
    config: Mapping[str, Any] | None = None,
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Resolve skill search roots, shadowing, profile-carried vs effective available counts (§2, §3, §5)."""
    roots = resolve_profile_skill_roots(profile_dir, config=config, project_root=project_root)
    raw_skills_cfg = (config or {}).get("skills")
    skills_cfg: Mapping[str, Any] = raw_skills_cfg if isinstance(raw_skills_cfg, Mapping) else {}

    disabled_names = set(_normalize_str_list(skills_cfg.get("disabled"))) - ESSENTIAL_SKILLS
    auto_load_names = _normalize_str_list(skills_cfg.get("auto_load"))

    all_entries: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED
    errors: list[str] = []

    for r in roots:
        r_entries, r_cov, r_errs = _scan_skills_in_root(Path(r["path"]), int(r["tier"]), str(r["source_kind"]))
        if r_cov != COVERAGE_VERIFIED:
            coverage = COVERAGE_COULD_NOT_VERIFY
        errors.extend(r_errs)
        all_entries.extend(r_entries)

    _assign_skill_precedence_and_flags(all_entries, disabled_names, auto_load_names)

    return {
        "profile_name": profile_name,
        "coverage": coverage,
        "counting_definition": (
            "profile_carried_count = SKILL.md packages inside <profile>/skills; "
            "effective_available_count = non-shadowed, non-disabled skills across all configured search roots"
        ),
        "roots": roots,
        "profile_carried_count": sum(1 for e in all_entries if int(e["tier"]) == TIER_LOCAL),
        "effective_available_count": sum(1 for e in all_entries if e["status"] != "shadowed" and not e["disabled"]),
        "shadowed_count": sum(1 for e in all_entries if e["status"] == "shadowed"),
        "disabled_skill_names": sorted(disabled_names),
        "auto_load_skill_names": auto_load_names,
        "skills": all_entries,
        "errors": errors,
    }


def _scan_static_plugin_count(profile_dir: Path) -> tuple[int, str, list[dict[str, Any]]]:
    """Statically count plugin directories carrying `plugin.yaml` or `manifest.json` under `<profile>/plugins` (§3, §5)."""
    plugins_dir = profile_dir / "plugins"
    try:
        st = os.lstat(plugins_dir)
    except FileNotFoundError:
        return 0, COVERAGE_VERIFIED, []
    except OSError:
        return 0, COVERAGE_COULD_NOT_VERIFY, []

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return 0, COVERAGE_COULD_NOT_VERIFY, []

    try:
        with os.scandir(plugins_dir) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return 0, COVERAGE_COULD_NOT_VERIFY, []

    manifests: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED
    for entry in entries:
        if entry.name.startswith("."):
            continue
        try:
            est = entry.stat(follow_symlinks=False)
        except OSError:
            coverage = COVERAGE_COULD_NOT_VERIFY
            continue
        if not stat.S_ISDIR(est.st_mode) or stat.S_ISLNK(est.st_mode):
            continue
        entry_path = Path(entry.path)
        has_yaml = (entry_path / "plugin.yaml").is_file()
        has_dash = (entry_path / "dashboard" / "manifest.json").is_file()
        if has_yaml or has_dash:
            manifests.append({
                "name": entry.name,
                "path": entry.path,
                "has_plugin_yaml": has_yaml,
                "has_dashboard_manifest": has_dash,
            })

    return len(manifests), coverage, manifests


def _fallback_newest_mtime(profile_dir: Path) -> tuple[float | None, str | None, str]:
    """Compute fallback newest mtime across regular files under `<profile>/memories/` and `<profile>/sessions/` (§8, §13.5)."""
    newest_ns: int | None = None
    newest_source: str | None = None
    coverage = COVERAGE_VERIFIED

    for sub in ("memories", "sessions"):
        sub_path = profile_dir / sub
        try:
            st_sub = os.lstat(sub_path)
        except FileNotFoundError:
            continue
        except OSError:
            coverage = COVERAGE_COULD_NOT_VERIFY
            continue
        if stat.S_ISLNK(st_sub.st_mode) or not stat.S_ISDIR(st_sub.st_mode):
            coverage = COVERAGE_COULD_NOT_VERIFY
            continue

        for dirpath, dirnames, filenames in os.walk(str(sub_path), topdown=True, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
            for fname in sorted(filenames):
                fpath = os.path.join(dirpath, fname)
                try:
                    fst = os.lstat(fpath)
                except OSError:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    continue
                if stat.S_ISREG(fst.st_mode) and (newest_ns is None or int(fst.st_mtime_ns) > newest_ns):
                    newest_ns = int(fst.st_mtime_ns)
                    rel = os.path.relpath(fpath, str(profile_dir)).replace("\\", "/")
                    newest_source = f"mtime:{rel}"

    if newest_ns is None:
        return None, None, coverage
    return newest_ns / 1_000_000_000.0, newest_source, coverage


def collect_profile_last_use_evidence(profile_dir: Path | str) -> dict[str, Any]:
    """Collect time-independent last-use evidence for a profile (§2, §8, §12, §13.5)."""
    pdir = Path(profile_dir)
    session_ev: ProfileSessionEvidence = read_profile_session_evidence(pdir / "state.db")
    fallback_ts, fallback_src, fallback_cov = _fallback_newest_mtime(pdir)

    last_ts: float | None = None
    last_src: str | None = None
    coverage = COVERAGE_COULD_NOT_VERIFY

    if session_ev.newest_started_at is not None and not session_ev.changed_during_read:
        last_ts = float(session_ev.newest_started_at)
        last_src = "state_db.sessions.started_at"
        coverage = COVERAGE_VERIFIED
    elif fallback_ts is not None and not session_ev.changed_during_read and fallback_cov == COVERAGE_VERIFIED:
        last_ts = float(fallback_ts)
        last_src = fallback_src or "fallback_mtime"
        coverage = COVERAGE_VERIFIED

    return {
        "last_use_timestamp": last_ts,
        "last_use_source": last_src,
        "coverage": coverage,
        "session_evidence": session_ev.to_dict(),
        "fallback_mtime": fallback_ts,
        "fallback_source": fallback_src,
    }


def evaluate_profile_age_and_unused(
    *,
    profile_name: str,
    is_default: bool,
    is_active: bool,
    last_use_evidence: Mapping[str, Any],
    as_of: float | int,
    unused_threshold_days: int = 90,
) -> dict[str, Any]:
    """Evaluate age-derived unused classification from cached time-independent evidence (§8, §12, §13.5)."""
    raw_ts = last_use_evidence.get("last_use_timestamp")
    ev_cov = str(last_use_evidence.get("coverage") or COVERAGE_COULD_NOT_VERIFY)

    if raw_ts is None or ev_cov != COVERAGE_VERIFIED:
        return {
            "profile_name": profile_name,
            "as_of": float(as_of),
            "unused_threshold_days": int(unused_threshold_days),
            "last_use_timestamp": None,
            "last_use_source": None,
            "age_seconds": None,
            "age_days": None,
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "is_unused_beyond_threshold": None,
            "archive_candidate": False,
            "selected_by_default": False,
            "ineligible_reason": "last_use_could_not_verify",
        }

    ts = float(raw_ts)
    age_seconds = max(0.0, float(as_of) - ts)
    beyond_threshold = age_seconds > (float(unused_threshold_days) * 86400.0)

    if is_default:
        reason: str | None = "default_profile_never_archived"
    elif is_active:
        reason = "active_profile_never_archived"
    elif not beyond_threshold:
        reason = "within_active_threshold"
    else:
        reason = None

    return {
        "profile_name": profile_name,
        "as_of": float(as_of),
        "unused_threshold_days": int(unused_threshold_days),
        "last_use_timestamp": ts,
        "last_use_source": last_use_evidence.get("last_use_source"),
        "age_seconds": age_seconds,
        "age_days": round(age_seconds / 86400.0, 4),
        "coverage": COVERAGE_VERIFIED,
        "is_unused_beyond_threshold": beyond_threshold,
        "archive_candidate": reason is None,
        "selected_by_default": False,
        "ineligible_reason": reason,
    }


def _timestamp_desc_key(ts: Any) -> tuple[int, float]:
    if isinstance(ts, (int, float)):
        return (0, -float(ts))
    return (1, 0.0)


def _extract_profile_last_use(rec: Mapping[str, Any]) -> tuple[Any, str]:
    last_ev = rec.get("last_use_evidence")
    ts = last_ev.get("last_use_timestamp") if isinstance(last_ev, Mapping) else rec.get("last_use_timestamp")
    if isinstance(last_ev, Mapping) and last_ev.get("coverage") is not None:
        cov = str(last_ev.get("coverage"))
    else:
        cov = COVERAGE_VERIFIED if isinstance(ts, (int, float)) else COVERAGE_COULD_NOT_VERIFY
    return ts, cov


def _profile_rank_key(rec: Mapping[str, Any], active_profile: str) -> tuple[int, int, float, str]:
    name = str(rec.get("name") or "")
    is_active = 0 if (name == active_profile or bool(rec.get("is_active"))) else 1
    ts, _ = _extract_profile_last_use(rec)
    has_ts, neg_ts = _timestamp_desc_key(ts)
    return (is_active, has_ts, neg_ts, name)


def order_profile_units(
    profile_records: Sequence[Mapping[str, Any]],
    *,
    active_profile: str = "default",
) -> list[dict[str, Any]]:
    """Order profile units deterministically (§4): active first, newest last_use, lexical name."""
    return [dict(r) for r in sorted(profile_records, key=lambda rec: _profile_rank_key(rec, active_profile))]


def order_project_units(project_records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Order registered project units deterministically (§4): newest timestamp, lexical canonical_path."""
    def _sort_key(rec: Mapping[str, Any]) -> tuple[int, float, str]:
        cpath = str(rec.get("canonical_path") or rec.get("path") or "")
        ts = rec.get("last_use_timestamp")
        if ts is None:
            ts = rec.get("created_at")
        has_ts, neg_ts = _timestamp_desc_key(ts)
        return (has_ts, neg_ts, cpath)

    return [dict(r) for r in sorted(project_records, key=_sort_key)]


def choose_duplicate_survivor(
    duplicate_profiles: Sequence[Mapping[str, Any]],
    *,
    active_profile: str = "default",
) -> dict[str, Any]:
    """Select the survivor among whole-profile exact duplicates (§8, §13.5)."""
    if not duplicate_profiles:
        return {"survivor": None, "archive_candidates": [], "protected_non_survivors": []}

    ranked = sorted(duplicate_profiles, key=lambda prof: _profile_rank_key(prof, active_profile))
    survivor = str(ranked[0]["name"])
    archive_candidates: list[dict[str, Any]] = []
    protected_non_survivors: list[dict[str, Any]] = []

    for prof in ranked[1:]:
        name = str(prof.get("name") or "")
        ts, cov = _extract_profile_last_use(prof)
        if name == "default" or name == active_profile or bool(prof.get("is_active")):
            protected_non_survivors.append({"name": name, "reason": "active_or_default_never_archived"})
        elif cov != COVERAGE_VERIFIED or ts is None:
            protected_non_survivors.append({"name": name, "reason": "last_use_could_not_verify"})
        else:
            archive_candidates.append({
                "name": name,
                "survivor": survivor,
                "selected_by_default": False,
                "last_use_timestamp": float(ts),
            })

    return {
        "survivor": survivor,
        "archive_candidates": archive_candidates,
        "protected_non_survivors": protected_non_survivors,
    }


def _inspect_git_marker(root_abs: Path, dirpath: str) -> tuple[str, str | None, str | None]:
    git_entry = Path(dirpath) / ".git"
    git_kind = "unknown"
    gitdir_target: str | None = None
    try:
        gst = os.lstat(git_entry)
        if stat.S_ISLNK(gst.st_mode):
            git_kind = "symlink_git"
            gitdir_target = os.readlink(git_entry)
        elif stat.S_ISDIR(gst.st_mode):
            git_kind = "git_dir"
        elif stat.S_ISREG(gst.st_mode):
            git_kind = "worktree_pointer"
            rel_git = os.path.relpath(str(git_entry), str(root_abs)).replace("\\", "/")
            res = safe_read_regular_file(root_abs, rel_git, max_bytes=4096, retain_bytes=True)
            if res.content:
                lines = res.content.decode("utf-8", errors="replace").strip().splitlines()
                if lines and lines[0].lower().startswith("gitdir:"):
                    gitdir_target = lines[0].split(":", 1)[1].strip()
    except OSError as exc:
        return git_kind, gitdir_target, f"Could not inspect {git_entry}: {exc}"
    return git_kind, gitdir_target, None


def _registered_folder_keys(paths: Iterable[str]) -> tuple[set[str], set[tuple[int, int]], bool]:
    """Real paths and (device, inode) of registered project folders, and whether any could not be resolved.

    A registered folder that no longer exists matches nothing (as before). Never opens a file.
    """
    real_paths: set[str] = set()
    identities: set[tuple[int, int]] = set()
    unresolved = False
    for p in paths:
        absolute = str(_abs_path(p))
        real_paths.add(absolute)
        try:
            real = os.path.realpath(absolute, strict=True)
            st = os.stat(real)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, RuntimeError, ValueError):
            unresolved = True
            continue
        real_paths.add(real)
        identities.add((st.st_dev, st.st_ino))
    return real_paths, identities, unresolved


def _is_registered_folder(path: str, real_paths: set[str], identities: set[tuple[int, int]]) -> bool:
    if path in real_paths:
        return True
    try:
        if os.path.realpath(path, strict=True) in real_paths:
            return True
        st = os.stat(path)
    except (OSError, RuntimeError, ValueError):
        return False
    return (st.st_dev, st.st_ino) in identities


def discover_optional_root_repos(
    optional_root: Path | str,
    *,
    registered_canonical_paths: Iterable[str] = (),
    max_entries: int = 10_000,
) -> dict[str, Any]:
    """Discover repositories strictly downward from `optional_root` without running Git (§3)."""
    root_abs = _abs_path(optional_root)
    reg_set, reg_ids, reg_unresolved = _registered_folder_keys(registered_canonical_paths)

    try:
        st_root = os.lstat(root_abs)
    except OSError as exc:
        return {
            "optional_root": str(root_abs),
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "repos": [],
            "errors": [f"Could not stat optional root {root_abs}: {exc}"],
        }

    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        return {
            "optional_root": str(root_abs),
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "repos": [],
            "errors": [f"Optional root {root_abs} must be a non-symlink directory"],
        }

    repos: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED
    errors: list[str] = []
    visited = 0

    for dirpath, dirnames, filenames in os.walk(str(root_abs), topdown=True, followlinks=False):
        visited += 1
        if max_entries > 0 and visited > max_entries:
            coverage = COVERAGE_COULD_NOT_VERIFY
            errors.append(f"Optional root walk exceeded {max_entries} directories")
            break

        has_git_marker = ".git" in dirnames or ".git" in filenames
        kept_dirs: list[str] = []
        for d in sorted(dirnames):
            if d in _OPTIONAL_ROOT_PRUNED_DIRS:
                continue
            d_full = os.path.join(dirpath, d)
            try:
                dst = os.lstat(d_full)
                if not stat.S_ISLNK(dst.st_mode) and stat.S_ISDIR(dst.st_mode):
                    kept_dirs.append(d)
            except OSError as exc:
                coverage = COVERAGE_COULD_NOT_VERIFY
                errors.append(f"Could not stat {d_full}: {exc}")
        dirnames[:] = kept_dirs

        if has_git_marker:
            repo_abs = str(Path(dirpath))
            git_kind, gitdir_target, err = _inspect_git_marker(root_abs, dirpath)
            if err is not None:
                coverage = COVERAGE_COULD_NOT_VERIFY
                errors.append(err)
            is_reg = _is_registered_folder(repo_abs, reg_set, reg_ids)
            entry = {
                # Shown as the user spelled the root; matched by real path and identity.
                "path": repo_abs,
                "rel_to_optional_root": os.path.relpath(repo_abs, str(root_abs)).replace("\\", "/"),
                "git_kind": git_kind,
                "gitdir_target": gitdir_target,
                "registered": is_reg,
                "not_set_up_by_plugin": not is_reg,
                "scope": "full" if is_reg else "isolation_only",
            }
            if not is_reg and reg_unresolved:
                # A registered path could not be resolved, so it may be this folder.
                if not any(r.get("reason") == "unresolved" for r in repos):
                    errors.append("A registered project path could not be resolved")
                coverage = COVERAGE_COULD_NOT_VERIFY
                entry.update(registered=None, not_set_up_by_plugin=None,
                             coverage=COVERAGE_COULD_NOT_VERIFY, reason="unresolved")
            repos.append(entry)

    repos.sort(key=lambda r: r["path"])
    return {
        "optional_root": str(root_abs),
        "coverage": coverage,
        "repos": repos,
        "errors": errors,
    }


def _probe_context_file(base_dir: Path, rel_name: str, kind: str) -> tuple[dict[str, Any] | None, bool]:
    cand = base_dir / rel_name
    try:
        os.lstat(cand)
    except FileNotFoundError:
        return None, True
    except OSError as exc:
        return {
            "kind": kind,
            "path": str(cand),
            "rel_name": rel_name,
            "char_count": 0,
            "non_empty": False,
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "error": str(exc),
        }, False

    res = safe_read_regular_file(base_dir, rel_name, retain_bytes=True)
    if res.coverage != COVERAGE_VERIFIED or not res.stable or res.content is None:
        return {
            "kind": kind,
            "path": str(cand),
            "rel_name": rel_name,
            "char_count": 0,
            "non_empty": False,
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "error": res.error,
        }, False

    txt = res.content.decode("utf-8", errors="replace").strip()
    return {
        "kind": kind,
        "path": str(cand),
        "rel_name": rel_name,
        "char_count": len(txt),
        "utf8_bytes": len(txt.encode("utf-8", "replace")),
        "non_empty": bool(txt),
        "sha256": res.sha256,
        "coverage": COVERAGE_VERIFIED,
        "error": None,
        "_text": txt,
    }, True


CONTEXT_TRUNCATE_HEAD_RATIO = 0.7
CONTEXT_TRUNCATE_TAIL_RATIO = 0.2


def _exists_or_denied_facts(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _find_git_root_facts(start: Path) -> Path | None:
    """Nearest ancestor (or *start* itself) containing an existing `.git`, else None (`agent/prompt_builder.py:113-117`)."""
    current = start.resolve()
    return next((p for p in (current, *current.parents) if _exists_or_denied_facts(p / ".git")), None)


def _strip_yaml_frontmatter_facts(content: str) -> str:
    content = content.lstrip("\ufeff")
    end = content.find("\n---", 3) if content.startswith("---") else -1
    return (content[end + 4 :].lstrip("\n") or content) if end != -1 else content


def _omitted_headings_facts(content: str, start: int, end: int, limit: int = 15) -> list[str]:
    headings: list[str] = []
    offset = 0
    fenced = False
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced and start <= offset < end and re.match(r"#{1,6} \S", stripped):
            headings.append(stripped.lstrip("#").strip())
        offset += len(line)
    return headings[:limit] + (["..."] if len(headings) > limit else [])


def _truncate_context_text_facts(
    content: str,
    filename: str,
    max_chars: int,
    *,
    read_path: str | None = None,
) -> tuple[str, bool]:
    if max_chars <= 0 or len(content) <= max_chars:
        return content, False
    head_chars = int(max_chars * CONTEXT_TRUNCATE_HEAD_RATIO)
    tail_chars = int(max_chars * CONTEXT_TRUNCATE_TAIL_RATIO)
    omitted = _omitted_headings_facts(content, head_chars, len(content) - tail_chars)
    sections = f" Omitted sections: {'; '.join(omitted)}." if omitted else ""
    marker = (
        f"\n\n[...truncated {filename}: kept {head_chars}+{tail_chars} of {len(content)} chars. The middle is "
        f"omitted.{sections} If you need the full instructions, read the complete file with the read_file "
        f"tool: {read_path or filename}]\n\n"
    )
    rendered = content[:head_chars] + marker + (content[-tail_chars:] if tail_chars > 0 else "")
    return rendered, True


def _allocate_truncated_shares(
    active_files: list[dict[str, Any]], total_injected_chars: int
) -> None:
    """Allocate a truncated total in four-character shares, with remainder last."""
    n = len(active_files)
    per_share = ((total_injected_chars // n) // 4) * 4 if n > 1 else total_injected_chars
    allocated = 0
    for idx, d in enumerate(active_files):
        d["truncated"] = True
        if idx < n - 1:
            d["injected_chars"] = per_share
            allocated += per_share
        else:
            d["injected_chars"] = total_injected_chars - allocated


def _apply_single_context_accounting(
    d: dict[str, Any], body: str, filename: str, context_max_chars: int, f_path: Path
) -> int:
    """Mutate one file's accounting and return its injected size."""
    rendered, was_trunc = _truncate_context_text_facts(
        body, filename, context_max_chars, read_path=str(f_path)
    )
    d["truncated"] = was_trunc
    d["injected_chars"] = len(rendered) if was_trunc else int(d["char_count"])
    return d["injected_chars"]


def _apply_agents_chain_accounting(
    active_files: list[dict[str, Any]],
    context_max_chars: int,
    cwd_abs: Path | None,
) -> int:
    """Mutate active files' truncation accounting and return the injected chain size."""
    cwd_res = (cwd_abs if cwd_abs is not None else Path(active_files[-1]["path"]).parent).resolve()
    sections: list[str] = []
    per_file_trunc: list[bool] = []
    per_file_inj: list[int] = []
    for d in active_files:
        f_path = Path(d["path"]).resolve()
        label = f_path.name if f_path.parent == cwd_res else os.path.relpath(f_path, cwd_res)
        txt = str(d.get("_text") or "").removeprefix("\ufeff")
        body = f"## {label}\n\n{txt}"
        sec, s_trunc = _truncate_context_text_facts(
            body, label, context_max_chars, read_path=str(f_path)
        )
        sections.append(sec)
        per_file_trunc.append(s_trunc)
        per_file_inj.append(len(sec) if s_trunc else int(d["char_count"]))
    if len(active_files) == 1:
        active_files[0]["truncated"] = per_file_trunc[0]
        active_files[0]["injected_chars"] = per_file_inj[0]
        total_injected_chars = per_file_inj[0]
    else:
        joined = "\n\n".join(sections)
        chain_rendered, chain_trunc = _truncate_context_text_facts(
            joined,
            "AGENTS.md (directory chain)",
            context_max_chars,
            read_path=str(cwd_res / "AGENTS.md"),
        )
        if not chain_trunc:
            for d, s_trunc, s_inj in zip(active_files, per_file_trunc, per_file_inj):
                d["truncated"] = s_trunc
                d["injected_chars"] = s_inj
            total_injected_chars = sum(per_file_inj)
        else:
            total_injected_chars = len(chain_rendered)
            _allocate_truncated_shares(active_files, total_injected_chars)

    return total_injected_chars


def _apply_context_precedence(
    discovered: list[dict[str, Any]],
    context_max_chars: int,
    cwd_abs: Path | None = None,
) -> tuple[str | None, int]:
    winning_kind = next(
        (
            kind
            for kind in ("hermes_md", "agents_md", "claude_md", "cursorrules")
            if any(d["kind"] == kind and d["non_empty"] for d in discovered)
        ),
        None,
    )

    seen_agents_sha: set[str] = set()
    active_files: list[dict[str, Any]] = []
    for d in discovered:
        if winning_kind is not None and d["kind"] == winning_kind and d["non_empty"]:
            if winning_kind == "agents_md":
                sha = d.get("sha256")
                if sha and sha in seen_agents_sha:
                    d["injected"] = False
                    d["shadowed_reason"] = "duplicate_in_agents_chain"
                    d["injected_chars"] = 0
                    continue
                if sha:
                    seen_agents_sha.add(sha)
            d["injected"] = True
            d["shadowed_reason"] = None
            active_files.append(d)
        else:
            d["injected"] = False
            d["shadowed_reason"] = "empty_or_unreadable" if not d["non_empty"] else f"shadowed_by_{winning_kind}"
            d["injected_chars"] = 0

    total_injected_chars = 0
    if active_files and winning_kind == "hermes_md":
        d = active_files[0]
        f_path = Path(d["path"]).resolve()
        cwd_res = cwd_abs.resolve() if cwd_abs is not None else f_path.parent
        label = str(f_path.relative_to(cwd_res)) if f_path.is_relative_to(cwd_res) else f_path.name
        txt = _strip_yaml_frontmatter_facts(str(d.get("_text") or "")).removeprefix("\ufeff")
        body = f"## {label}\n\n{txt}"
        total_injected_chars = _apply_single_context_accounting(
            d, body, ".hermes.md", context_max_chars, f_path
        )
    elif active_files and winning_kind == "claude_md":
        d = active_files[0]
        f_path = Path(d["path"]).resolve()
        name = str(d.get("rel_name") or f_path.name)
        txt = str(d.get("_text") or "").removeprefix("\ufeff")
        body = f"## {name}\n\n{txt}"
        total_injected_chars = _apply_single_context_accounting(
            d, body, "CLAUDE.md", context_max_chars, f_path
        )
    elif active_files and winning_kind == "cursorrules":
        cwd_res = (cwd_abs if cwd_abs is not None else Path(active_files[0]["path"]).parent).resolve()
        cursorrules_content = "".join(
            f"## {d.get('rel_name') or Path(d['path']).name}\n\n{str(d.get('_text') or '').removeprefix(chr(0xfeff))}\n\n"
            for d in active_files
        )
        rendered, was_trunc = _truncate_context_text_facts(
            cursorrules_content,
            ".cursorrules",
            context_max_chars,
            read_path=str(cwd_res / ".cursorrules"),
        )
        if not was_trunc:
            for d in active_files:
                d["truncated"] = False
                d["injected_chars"] = int(d["char_count"])
            total_injected_chars = sum(d["injected_chars"] for d in active_files)
        else:
            total_injected_chars = len(rendered)
            _allocate_truncated_shares(active_files, total_injected_chars)
    elif active_files and winning_kind == "agents_md":
        total_injected_chars = _apply_agents_chain_accounting(active_files, context_max_chars, cwd_abs)

    for d in discovered:
        d.pop("_text", None)

    return winning_kind, total_injected_chars


def resolve_project_context_chain_facts(
    project_root: Path | str,
    *,
    cwd: Path | str | None = None,
    context_max_chars: int = 20_000,
) -> dict[str, Any]:
    """Statically resolve Hermes project-context files following `agent/prompt_builder.py:1580-1749` (§2, §3, §5)."""
    from .policy import credential_path, note_credential_skip

    proj_abs = _abs_path(project_root)
    cwd_abs = _abs_path(cwd) if cwd is not None else proj_abs
    cwd_resolved = cwd_abs.resolve()

    git_root = _find_git_root_facts(cwd_resolved)
    if git_root is None or git_root == cwd_resolved or not cwd_resolved.is_relative_to(git_root):
        dir_chain = [cwd_abs]
    else:
        try:
            rel_parts = cwd_abs.relative_to(git_root).parts
            dir_chain = [git_root] + [git_root.joinpath(*rel_parts[: i + 1]) for i in range(len(rel_parts))]
        except ValueError:
            rel_parts = cwd_resolved.relative_to(git_root).parts
            dir_chain = [git_root] + [git_root.joinpath(*rel_parts[: i + 1]) for i in range(len(rel_parts))]

    discovered: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED

    def _probe_and_record(base_dir: Path, rel_name: str, kind: str) -> dict[str, Any] | None:
        nonlocal coverage
        item, ok = _probe_context_file(base_dir, rel_name, kind)
        if not ok:
            coverage = COVERAGE_COULD_NOT_VERIFY
        if item is not None:
            discovered.append(item)
        return item

    for d in reversed(dir_chain):
        found_hermes = False
        for name in (".hermes.md", "HERMES.md"):
            item = _probe_and_record(d, name, "hermes_md")
            if item is not None:
                found_hermes = True
                break
        if found_hermes:
            break

    for d in dir_chain:
        for name in ("AGENTS.override.md", "AGENTS.md", "agents.md"):
            item = _probe_and_record(d, name, "agents_md")
            if item is not None and item["non_empty"]:
                break

    for name in ("CLAUDE.md", "claude.md"):
        item = _probe_and_record(cwd_abs, name, "claude_md")
        if item is not None and item["non_empty"]:
            break

    _probe_and_record(cwd_abs, ".cursorrules", "cursorrules")
    rules_dir = cwd_abs / ".cursor" / "rules"
    try:
        if credential_path(rules_dir):
            note_credential_skip(rules_dir)
            coverage = COVERAGE_COULD_NOT_VERIFY
        elif rules_dir.is_dir() and not os.path.islink(rules_dir):
            for entry in sorted(os.listdir(rules_dir)):
                if entry.endswith(".mdc"):
                    _probe_and_record(cwd_abs, f".cursor/rules/{entry}", "cursorrules")
    except OSError:
        coverage = COVERAGE_COULD_NOT_VERIFY

    winning_kind, total_injected_chars = _apply_context_precedence(discovered, context_max_chars, cwd_abs)
    return {
        "project_root": str(proj_abs),
        "cwd": str(cwd_abs),
        "coverage": coverage,
        "winning_kind": winning_kind,
        "total_injected_chars": total_injected_chars,
        "estimated_tokens": (total_injected_chars + 3) // CHARS_PER_TOKEN if total_injected_chars else 0,
        "files": discovered,
    }


def resolve_core_guidance_facts(
    *,
    config: Mapping[str, Any] | None = None,
    memory_enabled: bool = True,
    user_profile_enabled: bool = True,
    has_hermes_agent_skill_in_index: bool = True,
) -> dict[str, Any]:
    """Statically resolve core/model guidance contributions (`agent/system_prompt.py:559-587, 755-762`) (§2, §5, §13.4)."""
    cfg = config if isinstance(config, Mapping) else {}
    raw_agent = cfg.get("agent")
    agent_cfg: Mapping[str, Any] = raw_agent if isinstance(raw_agent, Mapping) else {}
    raw_model = cfg.get("model")
    if isinstance(raw_model, Mapping):
        model_name = str(raw_model.get("default") or raw_model.get("model") or "")
    elif isinstance(raw_model, str):
        model_name = raw_model.strip()
    else:
        model_name = ""

    help_text = (
        HERMES_AGENT_HELP_GUIDANCE
        if has_hermes_agent_skill_in_index
        else HERMES_AGENT_HELP_GUIDANCE_NO_SKILLS
    )
    parts: list[str] = [help_text]
    sections: list[str] = ["help_guidance"]

    if agent_cfg.get("task_completion_guidance", True) is not False:
        parts.append(TASK_COMPLETION_GUIDANCE)
        sections.append("task_completion_guidance")
    if agent_cfg.get("parallel_tool_call_guidance", True) is not False:
        parts.append(PARALLEL_TOOL_CALL_GUIDANCE)
        sections.append("parallel_tool_call_guidance")

    mem_guidance = _build_memory_guidance_facts(
        memory_enabled=memory_enabled,
        profile_enabled=user_profile_enabled,
        skill_manage_available=True,
    )
    tool_guidance_block = " ".join(g for g in (mem_guidance, SESSION_SEARCH_GUIDANCE, SKILLS_GUIDANCE) if g)
    if tool_guidance_block:
        parts.append(tool_guidance_block)
        sections.append("tool_guidance")

    parts.append(STEER_CHANNEL_NOTE)
    sections.append("steer_channel_note")

    if _model_gate_facts(agent_cfg.get("tool_use_enforcement", "auto"), model_name, TOOL_USE_ENFORCEMENT_MODELS):
        parts.append(TOOL_USE_ENFORCEMENT_GUIDANCE)
        sections.append("tool_use_enforcement_guidance")
        if any(g in model_name.lower() for g in ("gemini", "gemma")):
            parts.append(GOOGLE_MODEL_OPERATIONAL_GUIDANCE)
            sections.append("google_model_operational_guidance")

    if _model_gate_facts(agent_cfg.get("execution_guidance", "auto"), model_name, EXECUTION_GUIDANCE_MODELS):
        parts.append(OPENAI_MODEL_EXECUTION_GUIDANCE)
        sections.append("openai_model_execution_guidance")

    rendered = "\n\n".join(p.strip() for p in parts if p and p.strip())
    return {
        "coverage": COVERAGE_VERIFIED,
        "model": model_name,
        "sections": sections,
        "rendered_text": rendered,
        "token_metrics": estimate_tokens_rough(rendered),
    }


def observe_memory_path_references(
    memory_facts: Mapping[str, Any],
    *,
    home_dir: Path | str | None = None,
    accessible_roots: Sequence[Path | str] = (),
) -> dict[str, dict[str, Any]]:
    """Safely observe filesystem existence of paths referenced inside built-in memory entries (§5)."""
    home_str = str(_abs_path(home_dir)) if home_dir is not None else os.path.expanduser("~")
    acc_roots = [str(_abs_path(r)) for r in (accessible_roots or [home_str])]

    observations: dict[str, dict[str, Any]] = {}
    raw_files = memory_facts.get("files")
    files_map: Mapping[str, Any] = raw_files if isinstance(raw_files, Mapping) else {}
    for f_info in files_map.values():
        if not isinstance(f_info, Mapping):
            continue
        for entry in (f_info.get("entries") or ()):
            text = str(entry.get("text") if isinstance(entry, Mapping) else entry or "")
            for m in _MEMORY_PATH_REF_RE.finditer(text):
                raw_p = m.group("path").rstrip(".,;:!?)']\"")
                resolved_p = (
                    os.path.normpath(home_str.rstrip("/") + "/" + raw_p[2:])
                    if raw_p.startswith("~/")
                    else os.path.normpath(raw_p)
                )
                if resolved_p in observations:
                    continue
                if not any(resolved_p == r or resolved_p.startswith(r.rstrip("/") + "/") for r in acc_roots):
                    observations[resolved_p] = {
                        "exists": None,
                        "namespace_accessible": False,
                        "on_local_machine": True,
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "reason": "outside_accessible_namespace",
                    }
                    continue
                try:
                    os.lstat(resolved_p)
                    observations[resolved_p] = {
                        "exists": True,
                        "namespace_accessible": True,
                        "on_local_machine": True,
                        "coverage": COVERAGE_VERIFIED,
                    }
                except FileNotFoundError:
                    observations[resolved_p] = {
                        "exists": False,
                        "namespace_accessible": True,
                        "on_local_machine": True,
                        "coverage": COVERAGE_VERIFIED,
                    }
                except OSError as exc:
                    observations[resolved_p] = {
                        "exists": None,
                        "namespace_accessible": False,
                        "on_local_machine": True,
                        "coverage": COVERAGE_COULD_NOT_VERIFY,
                        "reason": str(exc),
                    }
    return observations


def _read_profile_config(pdir: Path) -> tuple[dict[str, Any], str | None]:
    cfg_res = safe_read_regular_file(pdir, "config.yaml", retain_bytes=True)
    if cfg_res.kind != "regular" or cfg_res.coverage != COVERAGE_VERIFIED or cfg_res.content is None:
        return {}, None
    try:
        config_dict = _parse_simple_yaml_mapping(cfg_res.content.decode("utf-8", errors="replace"))
    except (ValueError, ImportError, RecursionError):
        config_dict = {}
    return config_dict, cfg_res.sha256


def _read_profile_soul(pdir: Path) -> dict[str, Any]:
    soul_res = safe_read_regular_file(pdir, "SOUL.md", retain_bytes=True)
    soul_exists = soul_res.kind != "missing"
    soul_cov = (
        COVERAGE_VERIFIED
        if soul_res.kind in ("regular", "missing") and soul_res.coverage == COVERAGE_VERIFIED and soul_res.stable
        else COVERAGE_COULD_NOT_VERIFY
    )
    soul_text = (
        soul_res.content.decode("utf-8", errors="replace").strip()
        if soul_res.kind == "regular" and soul_res.coverage == COVERAGE_VERIFIED and soul_res.content
        else ""
    )
    return {
        "exists": soul_exists,
        "path": str(pdir / "SOUL.md"),
        "coverage": soul_cov,
        "stable": soul_res.stable,
        "raw_text": soul_text,
        "size_bytes": int(soul_res.size or 0),
        "error": soul_res.error,
    }


def _compute_static_prompt_base(
    soul_facts: Mapping[str, Any],
    config_dict: Mapping[str, Any],
    memory_facts: Mapping[str, Any],
    skills_facts: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    enabled_memories = [f for f in memory_facts["files"].values() if f.get("enabled")]
    index_skills = [
        s for s in skills_facts["skills"]
        if s.get("status") != "shadowed" and not s.get("disabled")
    ]
    active_auto_skills = [s for s in index_skills if s.get("auto_loaded")]

    enabled_mem_chars = sum(int(f["token_metrics"]["characters"]) for f in enabled_memories)
    enabled_mem_tokens = sum(int(f["token_metrics"]["estimated_tokens"]) for f in enabled_memories)
    auto_loaded_chars = sum(int(s["token_metrics"]["characters"]) for s in active_auto_skills)
    auto_loaded_tokens = sum(int(s["token_metrics"]["estimated_tokens"]) for s in active_auto_skills)

    skills_index_text = "\n".join(
        f"- {s.get('load_name') or s['name']}: {str(s.get('description') or '')[:60]}"
        for s in index_skills
    )
    has_hermes_skill = any((s.get("load_name") or s.get("name")) == "hermes-agent" for s in index_skills)
    core_guidance_facts = resolve_core_guidance_facts(
        config=config_dict,
        memory_enabled=bool(memory_facts["files"]["memory"]["enabled"]),
        user_profile_enabled=bool(memory_facts["files"]["user"]["enabled"]),
        has_hermes_agent_skill_in_index=has_hermes_skill,
    )
    core_guidance_chars = int(core_guidance_facts["token_metrics"]["characters"])
    core_guidance_tokens = int(core_guidance_facts["token_metrics"]["estimated_tokens"])

    soul_text = str(soul_facts.get("raw_text") or "")
    effective_identity_text = (
        soul_text
        if (soul_facts.get("exists") and soul_text and soul_facts.get("coverage") == COVERAGE_VERIFIED)
        else DEFAULT_AGENT_IDENTITY
    )
    soul_metrics = estimate_tokens_rough(effective_identity_text)
    index_metrics = estimate_tokens_rough(skills_index_text)

    static_prompt_base = {
        "soul_chars": soul_metrics["characters"],
        "core_guidance_chars": core_guidance_chars,
        "enabled_memory_chars": enabled_mem_chars,
        "auto_loaded_skill_chars": auto_loaded_chars,
        "skills_index_chars": index_metrics["characters"],
        "total_static_base_chars": (
            soul_metrics["characters"]
            + core_guidance_chars
            + enabled_mem_chars
            + auto_loaded_chars
            + index_metrics["characters"]
        ),
        "total_static_base_estimated_tokens": (
            soul_metrics["estimated_tokens"]
            + core_guidance_tokens
            + enabled_mem_tokens
            + auto_loaded_tokens
            + index_metrics["estimated_tokens"]
        ),
        "estimator_version": TOKEN_ESTIMATOR_VERSION,
        "dynamic_contributions": {
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "note": "Dynamic plugin sections, MCP tool schemas, live provider context, and runtime metadata cannot be verified statically.",
        },
    }
    return core_guidance_facts, static_prompt_base


@coherent_profile_capture
def collect_profile_unit_facts(
    *,
    profile_name: str,
    profile_dir: Path | str,
    is_default: bool,
    is_active: bool,
    descendant_profile_roots: Sequence[Path | str] = (),
    as_of: float | int | None = None,
    unused_threshold_days: int = 90,
    rule_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Collect the complete read-only fact pack and fingerprint manifest for a single profile unit (§2, §3, §4, §12, §13)."""
    pdir = _abs_path(profile_dir)
    config_dict, config_digest = _read_profile_config(pdir)
    soul_facts = _read_profile_soul(pdir)
    memory_facts = resolve_profile_memory_facts(profile_name, pdir, config=config_dict)
    skills_facts = resolve_profile_skills_facts(profile_name, pdir, config=config_dict)
    plugin_count, plugin_cov, plugin_manifests = _scan_static_plugin_count(pdir)
    last_use_ev = collect_profile_last_use_evidence(pdir)
    reg_snap = read_profile_registrations_readonly(profile_name, pdir)

    fp_manifest: TreeFingerprintManifest = build_tree_fingerprint_manifest(
        unit_kind="profile",
        unit_id=profile_name,
        root_path=pdir,
        expected_rel_paths=("config.yaml", "SOUL.md", "memories/MEMORY.md", "memories/USER.md", "skills"),
        descendant_profile_roots=descendant_profile_roots,
        db_row_digests={
            "hermes_state_sessions": last_use_ev["session_evidence"].get("row_digest"),
            "defuzz_place_registrations": reg_snap.row_digest,
        },
        config_digest=config_digest,
        rule_versions={"facts_adapter": FACTS_ADAPTER_VERSION, **(dict(rule_versions or {}))},
    )

    core_guidance_facts, static_prompt_base = _compute_static_prompt_base(
        soul_facts, config_dict, memory_facts, skills_facts
    )

    all_verified = (
        fp_manifest.stable
        and all(
            cov == COVERAGE_VERIFIED
            for cov in (
                fp_manifest.coverage,
                soul_facts["coverage"],
                memory_facts["coverage"],
                skills_facts["coverage"],
                plugin_cov,
                reg_snap.coverage,
            )
        )
    )
    unit_coverage = COVERAGE_VERIFIED if all_verified else COVERAGE_COULD_NOT_VERIFY

    age_eval = (
        evaluate_profile_age_and_unused(
            profile_name=profile_name,
            is_default=is_default,
            is_active=is_active,
            last_use_evidence=last_use_ev,
            as_of=as_of,
            unused_threshold_days=unused_threshold_days,
        )
        if as_of is not None
        else None
    )

    return {
        "unit_kind": "profile",
        "unit_id": profile_name,
        "name": profile_name,
        "path": str(pdir),
        "is_default": is_default,
        "is_active": is_active,
        "coverage": unit_coverage,
        "stable": fp_manifest.stable,
        "logical_bytes": fp_manifest.logical_bytes,
        "deduplicated_bytes": fp_manifest.deduplicated_bytes,
        "memory_bytes": memory_facts["memory_bytes"],
        "config": config_dict,
        "soul": soul_facts,
        "core_guidance": core_guidance_facts,
        "skill_counts": {
            "profile_carried": skills_facts["profile_carried_count"],
            "effective_available": skills_facts["effective_available_count"],
            "shadowed": skills_facts["shadowed_count"],
            "counting_definition": skills_facts["counting_definition"],
        },
        "plugin_counts": {
            "static_manifest_count": plugin_count,
            "counting_definition": "Directories under <profile>/plugins containing plugin.yaml or dashboard/manifest.json",
            "dynamic_plugins_coverage": COVERAGE_COULD_NOT_VERIFY,
        },
        "static_prompt_base": static_prompt_base,
        "last_use_evidence": last_use_ev,
        "age_evaluation": age_eval,
        "memory": memory_facts,
        "skills": skills_facts,
        "plugins": plugin_manifests,
        "registrations_snapshot": reg_snap.to_dict(),
        "fingerprint_manifest": fp_manifest.to_dict(),
    }


def collect_system_inventory_facts(
    *,
    as_of: float | int,
    unused_threshold_days: int = 90,
    optional_root: Path | str | None = None,
    list_profile_names_fn: Callable[[], list[str]] | None = None,
    get_profile_dir_fn: Callable[[str], Path] | None = None,
    active_profile: str | None = None,
    rule_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Collect the system-wide read-only inventory across all official profiles and unioned registrations (§2, §3, §4, §12, §13)."""
    enum_res = enumerate_profiles(
        list_profile_names_fn=list_profile_names_fn,
        get_profile_dir_fn=get_profile_dir_fn,
        active_profile=active_profile,
    )
    descendant_roots = [Path(p["path"]) for p in enum_res.profiles if p["name"] != "default"]

    profile_units: list[dict[str, Any]] = []
    reg_snapshots: list[ProfileRegistrationsSnapshot] = []
    for prof in enum_res.profiles:
        pname = str(prof["name"])
        p_facts = collect_profile_unit_facts(
            profile_name=pname,
            profile_dir=Path(prof["path"]),
            is_default=bool(prof["is_default"]),
            is_active=bool(prof["is_active"]),
            descendant_profile_roots=descendant_roots if pname == "default" else (),
            as_of=as_of,
            unused_threshold_days=unused_threshold_days,
            rule_versions=rule_versions,
        )
        profile_units.append(p_facts)
        reg_snapshots.append(ProfileRegistrationsSnapshot(**p_facts["registrations_snapshot"]))

    ordered_profiles = order_profile_units(profile_units, active_profile=enum_res.active_profile)
    unioned_regs = union_profile_registrations(reg_snapshots)
    ordered_projects = order_project_units(unioned_regs["project_units"])

    opt_discovery = (
        discover_optional_root_repos(
            optional_root,
            registered_canonical_paths=[p["canonical_path"] for p in ordered_projects],
        )
        if optional_root is not None
        else None
    )

    all_verified = (
        enum_res.coverage == COVERAGE_VERIFIED
        and unioned_regs["coverage"] == COVERAGE_VERIFIED
        and all(p["coverage"] == COVERAGE_VERIFIED for p in ordered_profiles)
        and (opt_discovery is None or opt_discovery["coverage"] == COVERAGE_VERIFIED)
    )
    return {
        "adapter_version": FACTS_ADAPTER_VERSION,
        "as_of": int(as_of),
        "unused_threshold_days": int(unused_threshold_days),
        "active_profile": enum_res.active_profile,
        "default_root": enum_res.default_root,
        "coverage": COVERAGE_VERIFIED if all_verified else COVERAGE_COULD_NOT_VERIFY,
        "enumeration": enum_res.to_dict(),
        "profile_units": ordered_profiles,
        "project_units": ordered_projects,
        "all_registration_records": unioned_regs["all_records"],
        "optional_root_discovery": opt_discovery,
        "findings": list(enum_res.findings) + list(unioned_regs["findings"]),
    }
