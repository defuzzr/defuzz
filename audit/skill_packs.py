"""Bounded, read-only skill pack cost, usage, bulk-install, and dead-weight audit.

Hermes source references (paths relative to the hermes-agent source tree):
- Skills index rendering: `agent/prompt_builder.py:1137-1151` (`_build_snapshot_entry`: category =
  "general" for a SKILL.md directly in the root, the folder name for `<root>/<skill>/SKILL.md`, else the
  path above the skill folder), `:1154-1165` (`_parse_skill_file`: platform/environment/app gates; any
  read error lists the skill with empty frontmatter), `:1284-1292` (`_label_visible_entries`),
  `:1295-1360` (`_render_skills_index`: rows, category lines, fixed header), `:1400-1452`
  (`hides`, `resolve_skill_catalog`, `is_disabled_entry`, unloadable note).
- On-disk snapshot `.skills_prompt_snapshot.json` (`version`, `manifest`, `skills[]` with
  `skill_name`, `category`, `frontmatter_name`, `rel` (v4+), `description`): `agent/prompt_builder.py:1082-1135`.
- Frontmatter parsing with key:value fallback: `agent/skill_utils.py:71-91`; platform gate and
  `PLATFORM_MAP`: `:22,94-118`; environment/app gates: `:167-206`; `ESSENTIAL_SKILLS` and
  `skills.disabled`: `:278-293`; `external_dirs`: `:340-368`; tiers `TIER_PROJECT, TIER_LOCAL,
  TIER_CREATE_DIR, TIER_EXTERNAL = range(4)`: `:405`; resolution: `:445-519`; conditions
  (`metadata.hermes`): `:728-743`; 60-char description clip: `:846-870`; walk/pruning: `:28-36,878-891`.
- Auto-loaded skills (`skills.auto_load`, body added to the stable prompt prefix every session):
  `agent/system_prompt.py:318-342,768`, `agent/skill_commands.py:1000-1028`.
- Usage sidecar `skills/.usage.json` keyed by skill name (`use_count`, `view_count`, `patch_count`,
  `last_used_at`, `last_viewed_at`, `last_patched_at`, `created_at`, `first_seen_at`):
  `tools/skill_usage.py:47-53,115-138,348-378,412-418,493-508`. A use is recorded by `bump_use` from a
  successful `skill_view` (`tools/skills_tool.py:776-780`), a slash-command/preload skill load
  (`agent/skill_commands.py:428-429`) and a cron job skill load (`cron/scheduler_prompt.py:248`).
- Skills Hub lock file (`skills/.hub/lock.json`, `installed.<name>.source`, `install_path`):
  `tools/skills_hub.py:63,322-370`.
- Bundled stock manifest (`skills/.bundled_manifest`, `name:md5` lines): `tools/skills_sync.py:38,113-130`.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from statistics import median
import sys
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

from .contract import make_component_envelope, make_finding
from .facts import _parse_simple_yaml_mapping
from .fingerprint import CredentialStoreNotOpened, _open_root_dir_fd, _walk_parent_dir_fds, open_checked, safe_read_regular_file
from .policy import credential_path
from .skill_hygiene import (
    CACHE_DIRS,
    EXCLUDED_SKILL_DIRS,
    MANIFEST,
    SKILL_SUPPORT_DIRS,
    _has_surrogate,
    _has_symlink_below,
)
from .vendor.profile_context import CHARS_PER_TOKEN, ESSENTIAL_SKILLS, SKILL_PROMPT_DESC_LIMIT

# Bounded traversal and read caps.
MAX_TREE_ENTRIES = 10_000
MAX_DEPTH = 16
MAX_SKILLS = 1_000
MAX_FILES_PER_SKILL = 256
MAX_FILE_BYTES = 1024 * 1024  # 1 MiB per metadata or SKILL.md read.
MAX_LICENSE_FILE_BYTES = 64 * 1024  # 64 KiB cap per LICENSE/NOTICE/COPYING file.
MAX_LICENSE_FILES = 5_000  # Max LICENSE/NOTICE/COPYING files hashed across the tree.
MAX_TOTAL_BYTES = 32 * 1024 * 1024  # 32 MiB aggregate read budget.
MAX_USAGE_ROWS = 10_000  # Max entries processed in .usage.json / lock.json / snapshot.
MAX_SECONDS = 10.0  # Cooperative wall-clock budget.
HEADER_PROBE_BYTES = 512  # Prefix bytes inspected to classify >1 MiB files.
MAX_LISTED = 10  # Every per-skill list in the output is capped at this many entries.

# Measured thresholds. index_chars is the length of the full rendered `## Skills` block (fixed header and
# footer of 1,188 characters plus rows and category lines); each figure below was checked against Hermes's own
# build_skills_system_prompt on Linux with the tool list unknown:
# - Upstream bundled skills (44 discovered, 39 listed): 4,311 rendered chars (2,684 name+description).
# - Upstream bundled + optional-skills (186 discovered, 180 listed): 15,189 rendered chars.
# - A home with a couple of hundred installed skills renders close to 20,000 chars; homes with a few
#   dozen skills stay in the low thousands.
# INDEX_SKILLS_THRESHOLD (150) is below the 180 listed when every official optional skill is installed, so
# that configuration is reported; a plain stock install (39-58 listed) never is.
# - Public 358-skill pack: 42,873 name+description chars (measured separately, far above the threshold).
INDEX_CHARS_THRESHOLD = 17_000
INDEX_SKILLS_THRESHOLD = 150
NEVER_USED_MIN_SKILLS = 20
NEVER_USED_SHARE_THRESHOLD = 0.70
BULK_GROUP_MIN_SKILLS = 20
BULK_REVIEW_MIN_SKILLS = 50
BULK_REVIEW_MAX_USED_SHARE = 0.10
MTIME_WINDOW_SECONDS = 120
LICENSE_COPIES_THRESHOLD = 50
LARGE_PAYLOAD_BYTES = 1024 * 1024  # 1 MiB non-text payload threshold.

SNAPSHOT_FILE = ".skills_prompt_snapshot.json"
CONFIG_FILE = "config.yaml"
USAGE_FILE = "skills/.usage.json"
HUB_LOCK_FILE = "skills/.hub/lock.json"

# agent/skill_utils.py:22 (PLATFORM_MAP) and :405 (tier numbers).
PLATFORM_MAP = {"macos": "darwin", "linux": "linux", "windows": "win32"}
TIER_LOCAL = 1
TIER_EXTERNAL = 3
# agent/skill_utils.py:737 (metadata.hermes keys whose effect depends on the session's tools/platform).
_CONDITION_KEYS = ("fallback_for_toolsets", "requires_toolsets", "fallback_for_tools", "requires_tools",
                   "session_platforms")
# agent/skill_utils.py:121-151,167-174: `environments:` tags with a detector; each is false in an ordinary
# desktop session (kanban needs a dispatcher worker or an opted-in toolset, docker a container, s6 the image).
# Unknown tags fail open. A skill whose tags are all known detectors is treated as hidden.
_DETECTED_ENVIRONMENTS = frozenset({"kanban", "docker", "s6"})
# tools/skill_usage.py:348-353 timestamp fields of a usage record.
_USAGE_TS_KEYS = ("created_at", "first_seen_at", "last_used_at", "last_viewed_at", "last_patched_at")

ALWAYS_LOAD_CUES: tuple[str, ...] = (
    "every session",
    "always load",
    "load first",
    "before anything",
)

NON_TEXT_CLASSES: tuple[str, ...] = (
    "image", "video", "audio", "archive", "model_weights", "executable_file", "document", "other",
)

FINDING_CONSEQUENCES: dict[str, str] = {
    "skill_packs.index_cost": (
        "The rendered skills index is above 17,000 characters or 150 listed skills and is sent with every "
        "request before any skill is opened; the character count is about the real size and an upper bound "
        "when listed skills depend on tools, apps or environments, and it does not include any skill body."
    ),
    "skill_packs.never_used": (
        "At least 70% of at least 20 non-stock skills with a usable observation window have zero recorded "
        "uses in skills/.usage.json; Hermes records a use only when a skill is loaded through skill_view, a "
        "slash command or a cron job, so this does not show reads by other means or use before recording began."
    ),
    "skill_packs.bulk_install": (
        "At least 20 non-stock skill folders share one install signal (identical license text, the same "
        "hub-lock source, or SKILL.md times within 2 minutes, which is a weak signal); this counts folders "
        "and does not show how or why they were installed."
    ),
    "skill_packs.stale_index_snapshot": (
        "The on-disk .skills_prompt_snapshot.json lists skill entries with no matching SKILL.md under skills/; "
        "Hermes rebuilds this cache when its manifest no longer matches, so this counts left-over cache "
        "entries and does not describe the current prompt."
    ),
    "skill_packs.always_on_skills": (
        "One or more non-stock skills are listed in skills.auto_load or carry an every-session cue in their "
        "frontmatter description; auto-loaded skills add their body to every session, while a description "
        "cue is wording only and does not show that the skill is loaded."
    ),
    "skill_packs.license_copies": (
        "More than 50 LICENSE, NOTICE or COPYING files inside skill folders share fewer distinct texts than "
        "files; this counts duplicated license files and does not show how the folders were installed."
    ),
    "skill_packs.could_not_verify": (
        "Skill pack usage or directory coverage could not be completely verified; missing usage records or "
        "bounded traversal cuts are not evidence of clean state or zero usage."
    ),
}

# agent/prompt_builder.py:1339-1358 fixed text around the index rows (default variant: tool list unknown,
# no compact categories, not a one-shot session).
_INDEX_HEADER = (
    "## Skills\n"
    "Before replying, scan the skills below. If a skill matches or is even partially relevant to your "
    "task, you MUST load it with skill_view(name) and follow its instructions. Err on the side of "
    "loading — it is always better to have context you don't need than to miss critical steps, pitfalls, "
    "or established workflows. Skills contain specialized knowledge — API endpoints, tool-specific "
    "commands, and proven workflows that outperform general-purpose approaches. Load the skill "
    "even if you think you could handle the task with basic tools like web_search or terminal. "
    "Skills also encode the user's preferred approach, conventions, and quality standards for tasks like "
    "code review, planning, and testing — load them even for tasks you already know how to do, because "
    "the skill defines how it should be done here.\n"
    "If a skill has issues, fix it with skill_manage(action='patch').\n"
    "After difficult/iterative tasks, offer to save as a skill. If a skill you loaded was missing steps, "
    "had wrong commands, or needed pitfalls you discovered, update it before finishing.\n"
    "\n"
    "<available_skills>\n"
)
_INDEX_FOOTER = (
    "</available_skills>\n\n"
    "Only proceed without loading a skill if genuinely none are relevant to the task."
)

_TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".txt", ".rst", ".csv", ".tsv", ".json", ".jsonl", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".xml", ".html", ".htm", ".css", ".svg",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".rb", ".go", ".rs", ".java", ".c", ".h", ".cpp",
    ".hpp", ".cs", ".swift", ".kt", ".sql", ".r", ".lua", ".pl", ".php",
})

_BINARY_EXTENSIONS: dict[str, str] = {
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image", ".webp": "image",
    ".bmp": "image", ".ico": "image", ".tiff": "image", ".mp4": "video", ".mov": "video",
    ".webm": "video", ".avi": "video", ".mkv": "video", ".mp3": "audio", ".wav": "audio",
    ".ogg": "audio", ".flac": "audio", ".m4a": "audio", ".pdf": "document", ".zip": "archive",
    ".tar": "archive", ".gz": "archive", ".tgz": "archive", ".bz2": "archive", ".xz": "archive",
    ".7z": "archive", ".rar": "archive", ".whl": "archive", ".jar": "archive", ".pyc": "executable_file",
    ".pyo": "executable_file", ".so": "executable_file", ".dylib": "executable_file", ".dll": "executable_file",
    ".exe": "executable_file", ".onnx": "model_weights", ".pt": "model_weights", ".pth": "model_weights",
    ".safetensors": "model_weights", ".gguf": "model_weights",
}

_LAST_WHITESPACE_RE = re.compile(r"\s\S*$")
_CLIP_TRAIL_RE = re.compile(r"[\s.,;:\-\u2013\u2014(/]+$")


def clip_skill_description(desc: str) -> str:
    """Exact copy of `agent/skill_utils.py:857-865` (60-char word-boundary clip)."""
    if len(desc) <= SKILL_PROMPT_DESC_LIMIT:
        return desc
    head = desc[: SKILL_PROMPT_DESC_LIMIT - 2]
    boundary = _LAST_WHITESPACE_RE.search(head)
    if not boundary or boundary.start() == 0:
        return desc[: SKILL_PROMPT_DESC_LIMIT - 3] + "..."
    return _CLIP_TRAIL_RE.sub("", head[: boundary.start()]) + "..."


def _normalize_description(frontmatter: Mapping[str, Any]) -> str:
    """`agent/skill_utils.py:851-854`."""
    raw_desc = frontmatter.get("description", "")
    return str(raw_desc).strip().strip("'\"") if raw_desc else ""


def _parse_frontmatter_like_hermes(content: str) -> tuple[dict[str, Any], str]:
    """`agent/skill_utils.py:71-91`: YAML mapping, else key:value line fallback on a YAML error."""
    content = content.removeprefix("\ufeff")
    end_match = re.search(r"\n---\s*\n", content[3:]) if content.startswith("---") else None
    if not end_match:
        return {}, content
    yaml_content = content[3: end_match.start() + 3]
    body = content[end_match.end() + 3:]
    try:
        parsed = _parse_simple_yaml_mapping(yaml_content)
        return (parsed if isinstance(parsed, dict) else {}), body
    except ValueError as exc:
        if str(exc) == "Audit YAML must be a mapping":
            return {}, body  # Hermes keeps {} for a non-mapping document (no fallback).
    except RecursionError:
        pass
    frontmatter: dict[str, Any] = {}
    for line in yaml_content.strip().split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            frontmatter[key.strip()] = value.strip()
    return frontmatter, body


def _platform_matches(platforms: Any, host: str) -> bool:
    """`agent/skill_utils.py:94-106` against an explicit host platform string."""
    if not platforms:
        return True
    if not isinstance(platforms, list):
        platforms = [platforms]
    for platform in platforms:
        normalized = str(platform).lower().strip()
        if host.startswith(PLATFORM_MAP.get(normalized, normalized)):
            return True
    return False


def _environment_hidden(frontmatter: Mapping[str, Any]) -> bool:
    """True when every `environments:` tag is a detected environment (hidden in an ordinary session)."""
    environments = frontmatter.get("environments")
    if not environments:
        return False
    tags = [str(e).lower().strip() for e in (environments if isinstance(environments, list) else [environments])]
    tags = [t for t in tags if t]
    return bool(tags) and all(t in _DETECTED_ENVIRONMENTS for t in tags)


def _runtime_gated(frontmatter: Mapping[str, Any]) -> bool:
    """True when visibility also depends on session facts a file audit cannot see
    (`environments`, `requires_apps`, `metadata.hermes` conditions; agent/skill_utils.py:167-206,728-743)."""
    if frontmatter.get("environments") or frontmatter.get("requires_apps"):
        return True
    metadata = frontmatter.get("metadata")
    hermes = metadata.get("hermes") if isinstance(metadata, dict) else None
    if isinstance(hermes, dict):
        return any(hermes.get(k) for k in _CONDITION_KEYS)
    return False


def _render_index(rows: Sequence[tuple[str, str, str]], unloadable: Sequence[str]) -> str:
    """`agent/prompt_builder.py:1295-1360` for `(category, load_name, clipped_description)` rows."""
    by_cat: dict[str, list[tuple[str, str]]] = {}
    for cat, name, desc in rows:
        by_cat.setdefault(cat or "general", []).append((name, desc))
    if not by_cat:
        return ""
    hidden_note = ""
    if unloadable:
        hidden_note = (f"\n(A copy of {', '.join(unloadable)} is not listed: it shares both its name and its path "
                       "with a different skill in the same skills directory tier (e.g. another external_dirs entry), "
                       "so skill_view cannot load it — rename one.)")
    lines: list[str] = []
    for category in sorted(by_cat):
        uniq: dict[str, str] = {}
        for name, desc in sorted(by_cat[category], key=lambda x: x[0]):
            uniq.setdefault(name, desc)
        indent = "  " if len(uniq) == 1 else "    "
        if len(uniq) > 1:
            lines.append(f"  {category}:")
        lines.extend(f"{indent}- {n}: {d}" if d else f"{indent}- {n}" for n, d in uniq.items())
    return _INDEX_HEADER + "\n".join(lines) + "\n" + _INDEX_FOOTER + hidden_note


def _parse_string_sequence(raw: Any) -> tuple[list[str], bool]:
    """Normalize a parameter sequence/string like `agent/skill_utils.py:296-314`."""
    import ast

    if raw is None:
        return [], True
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return [], True
        if s.startswith("["):
            try:
                parsed = ast.literal_eval(s)
            except (ValueError, SyntaxError):
                return [], False
            if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
                return [], False
            return [x.strip() for x in parsed if x.strip()], True
        return [s], True
    if isinstance(raw, (list, tuple, set, frozenset)):
        out: list[str] = []
        ok = True
        for item in raw:
            if isinstance(item, (str, os.PathLike)):
                s = os.fspath(item).strip()
                if s:
                    out.append(s)
            else:
                ok = False
        return out, ok
    return [], False


def _parse_iso_ts(raw: Any) -> datetime | None:
    """`tools/skill_usage.py:115-120` ISO-8601 parsing (naive = UTC)."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _latest_activity_dt(record: Mapping[str, Any]) -> datetime | None:
    """`tools/skill_usage.py:123-127` (`last_used_at`, `last_viewed_at`, `last_patched_at`)."""
    stamps = [dt for key in ("last_used_at", "last_viewed_at", "last_patched_at")
              if (dt := _parse_iso_ts(record.get(key))) is not None]
    return max(stamps) if stamps else None


def _non_negative_int(value: Any) -> tuple[int, bool]:
    """`tools/skill_usage.py:130-138` non-negative integer extraction (with a validity flag)."""
    if value is None:
        return 0, True
    if isinstance(value, bool):
        return 0, False
    if isinstance(value, int):
        return max(0, value), value >= 0
    if isinstance(value, str) and len(value) <= 32:
        try:
            parsed = int(value.strip())
            return max(0, parsed), parsed >= 0
        except ValueError:
            return 0, False
    return 0, False


def _is_license_filename(filename: str) -> bool:
    if filename.startswith("._"):
        return False
    upper = filename.upper()
    for prefix in ("LICENSE", "LICENCE", "NOTICE", "COPYING"):
        if upper == prefix or upper.startswith((prefix + ".", prefix + "-", prefix + "_")):
            return True
    return False


def _detect_payload_class(header: bytes, suffix: str) -> str | None:
    """One of NON_TEXT_CLASSES for a non-text payload, or None when the prefix looks like UTF-8 text."""
    magic: tuple[tuple[bytes, str], ...] = (
        (b"\x89PNG\r\n\x1a\n", "image"), (b"\xff\xd8\xff", "image"), (b"GIF87a", "image"), (b"GIF89a", "image"),
        (b"%PDF-", "document"), (b"PK\x03\x04", "archive"), (b"PK\x05\x06", "archive"), (b"PK\x07\x08", "archive"),
        (b"\x1f\x8b", "archive"), (b"BZh", "archive"), (b"\xfd7zXZ\x00", "archive"), (b"7z\xbc\xaf\x27\x1c", "archive"),
        (b"\x7fELF", "executable_file"), (b"\xfe\xed\xfa\xce", "executable_file"), (b"\xfe\xed\xfa\xcf", "executable_file"),
        (b"\xce\xfa\xed\xfe", "executable_file"), (b"\xcf\xfa\xed\xfe", "executable_file"), (b"\xca\xfe\xba\xbe", "executable_file"),
        (b"MZ", "executable_file"), (b"GGUF", "model_weights"), (b"OggS", "audio"), (b"fLaC", "audio"), (b"ID3", "audio"),
    )
    for prefix, label in magic:
        if header.startswith(prefix):
            return label
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image"
    if len(header) >= 8 and header[4:8] == b"ftyp":
        return "video"
    if suffix in _BINARY_EXTENSIONS:
        return _BINARY_EXTENSIONS[suffix]
    if b"\x00" in header:
        return "other"
    for trim in range(4):
        chunk = header[: len(header) - trim] if trim else header
        try:
            chunk.decode("utf-8")
            return None
        except UnicodeDecodeError:
            continue
    return "other"


def _read_prefix_bytes(root: Path, rel_path: str, max_prefix: int = HEADER_PROBE_BYTES) -> bytes | None:
    """Safely read up to `max_prefix` bytes from a regular non-symlink file below `root`."""
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        return None
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    o_nonblock = getattr(os, "O_NONBLOCK", 0)
    try:
        with _open_root_dir_fd(root) as (root_fd, _, _):
            with _walk_parent_dir_fds(root_fd, parts[:-1]) as parent_fd:
                leaf = parts[-1]
                st_pre = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISREG(st_pre.st_mode):
                    return None
                try:
                    fd = open_checked(leaf, os.O_RDONLY | o_nofollow | o_nonblock, dir_fd=parent_fd,
                                      full_path=os.path.abspath(root.joinpath(*parts)))
                except CredentialStoreNotOpened:
                    return None
                try:
                    st_open = os.fstat(fd)
                    if not stat.S_ISREG(st_open.st_mode) or (st_open.st_dev, st_open.st_ino) != (st_pre.st_dev, st_pre.st_ino):
                        return None
                    return os.read(fd, max_prefix)
                finally:
                    os.close(fd)
    except OSError:
        return None


def _nearest_rank_percentile(sorted_vals: Sequence[int], pct: float) -> int | None:
    if not sorted_vals:
        return None
    idx = min(len(sorted_vals) - 1, max(0, math.ceil(pct * len(sorted_vals)) - 1))
    return int(sorted_vals[idx])


def _year_month(dt: datetime | None) -> int | None:
    """Year and month as the integer YYYYMM (a number, so the report serializer keeps it unchanged)."""
    return dt.year * 100 + dt.month if dt is not None else None


def _finding(
    rule_id: str,
    rel_source_path: str,
    evidence: Mapping[str, Any],
    *,
    coverage: str = "verified",
    classification: str = "review_suggested",
) -> dict[str, Any]:
    # Every consequence is the rule's fixed sentence: persistence keeps only exact fixed sentences.
    return make_finding(
        rule_id=rule_id,
        classification=classification,
        coverage=coverage,
        affected_identities=[rel_source_path],
        source_paths=[rel_source_path],
        evidence=evidence,
        consequence=FINDING_CONSEQUENCES[rule_id],
    )


def _limits_out(limits: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in limits.items() if k != "truncated_by"}


def _thresholds() -> dict[str, Any]:
    return {
        "index_chars": INDEX_CHARS_THRESHOLD,
        "index_skills": INDEX_SKILLS_THRESHOLD,
        "never_used_min_skills": NEVER_USED_MIN_SKILLS,
        "never_used_share": NEVER_USED_SHARE_THRESHOLD,
        "bulk_group_min_skills": BULK_GROUP_MIN_SKILLS,
        "bulk_review_min_skills": BULK_REVIEW_MIN_SKILLS,
        "bulk_review_max_used_share": BULK_REVIEW_MAX_USED_SHARE,
        "mtime_window_seconds": MTIME_WINDOW_SECONDS,
        "license_copies": LICENSE_COPIES_THRESHOLD,
        "large_payload_bytes": LARGE_PAYLOAD_BYTES,
        "description_clip_chars": SKILL_PROMPT_DESC_LIMIT,
    }


def _empty_snapshot() -> dict[str, Any]:
    return {"present": False, "coverage": "not_applicable", "version": None, "skills_count": 0,
            "description_chars": 0, "stale_count": 0}


def _empty_section(*, status: str, coverage: str, reason: str | None, limits: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": status,
        "coverage": coverage,
        "reason": reason,
        "truncated_by": limits["truncated_by"],
        "index": {
            "loadable_skills": 0, "discovered_skills": 0, "stock_skills": 0, "non_stock_skills": 0,
            "disabled_skills_count": 0, "shadowed_skills_count": 0, "platform_excluded_count": 0,
            "runtime_gated_count": 0, "index_chars": 0, "name_chars": 0, "description_chars": 0,
            "estimated_tokens": 0, "snapshot": _empty_snapshot(),
        },
        "usage": {
            "present": False, "coverage": "could_not_verify", "reason": "usage_file_missing",
            "recording_since": None, "recording_until": None, "skills_evaluated": 0, "zero_use_count": None,
            "never_used_share": None, "zero_use_unverifiable_count": None, "non_stock_skills_evaluated": 0,
            "non_stock_zero_use_count": None, "non_stock_never_used_share": None, "top_used_counts": [],
            "days_since_last_use": None,
        },
        "bulk_installs": {"group_count": 0, "groups": [], "hub_lock_present": False, "hub_lock_entries": 0,
                          "hub_lock_missing_on_disk": 0},
        "dead_weight": {"license_files_count": 0, "identical_license_copies": 0, "distinct_license_texts": 0,
                        "license_bytes": 0, "non_text_over_1mb_count": 0, "non_text_over_1mb_bytes": 0,
                        "non_text_over_1mb_by_type": {}},
        "always_on": {"count": 0, "auto_loaded_count": 0, "description_cue_count": 0, "non_stock_count": 0,
                      "paths": []},
        "loaded_sizes": {"median_chars": None, "p90_chars": None, "max_chars": None, "top_10_largest": []},
        "limits": _limits_out(limits),
        "thresholds": _thresholds(),
    }


def _usage_age_buckets(
    loadable: Sequence[Mapping[str, Any]],
    states: Mapping[int, str],
    use_record: Callable[[Mapping[str, Any]], Mapping[str, Any] | None],
    last_dt: datetime,
) -> dict[str, int]:
    buckets = {"never": 0, "gt_90_days": 0, "days_30_to_90": 0, "lt_30_days": 0, "unverifiable": 0}
    for r in loadable:
        state = states[id(r)]
        if state == "zero":
            buckets["never"] += 1
            continue
        if state == "unverifiable":
            buckets["unverifiable"] += 1
            continue
        urec = use_record(r)
        latest = urec["latest"] if urec else None
        if latest is None:
            buckets["unverifiable"] += 1
            continue
        age_days = max(0.0, (last_dt - latest).total_seconds() / 86400.0)
        if age_days < 30.0:
            buckets["lt_30_days"] += 1
        elif age_days <= 90.0:
            buckets["days_30_to_90"] += 1
        else:
            buckets["gt_90_days"] += 1
    return buckets


def audit_skill_packs(
    profile_path: str | os.PathLike[str],
    *,
    disabled_skills: Iterable[str] | str | None = None,
    auto_load_skills: Iterable[str] | str | None = None,
    external_dirs: Iterable[str | os.PathLike[str]] | str | os.PathLike[str] | None = None,
    now: Any = None,
    clock: Callable[[], float] | None = None,
    host_platform: str | None = None,
) -> dict[str, Any]:
    """Measure skill index prompt cost, usage, bulk installs, dead weight, and always-on skills.

    `now` is accepted for signature compatibility and has no effect: every age is measured against the
    newest timestamp inside the usage file, so the output depends only on the home's contents.
    `host_platform` (default `sys.platform`) decides which `platforms:`-gated skills Hermes would list.
    `disabled_skills`, `auto_load_skills` and `external_dirs` default to None, meaning "read `skills.disabled`,
    `skills.auto_load` and `skills.external_dirs` from `<profile>/config.yaml`"; an explicit value (also `()`)
    overrides the config.
    """
    del now
    time_fn = clock if callable(clock) else time.monotonic
    start_clock = float(time_fn())
    deadline = start_clock + float(MAX_SECONDS)

    limits: dict[str, Any] = {
        "max_entries": MAX_TREE_ENTRIES,
        "max_depth": MAX_DEPTH,
        "max_skills": MAX_SKILLS,
        "max_files_per_skill": MAX_FILES_PER_SKILL,
        "max_file_bytes": MAX_FILE_BYTES,
        "max_license_file_bytes": MAX_LICENSE_FILE_BYTES,
        "max_license_files": MAX_LICENSE_FILES,
        "max_total_bytes": MAX_TOTAL_BYTES,
        "max_usage_rows": MAX_USAGE_ROWS,
        "max_seconds": MAX_SECONDS,
        "entries_walked": 0,
        "files_hashed": 0,
        "bytes_read": 0,
        "symlinks_skipped": 0,
        "credentials_skipped": 0,
        "external_dirs_skipped": 0,
        "cuts": 0,
        "truncated_by": None,
    }

    def note_cut(trunc_reason: str | None = None) -> None:
        limits["cuts"] += 1
        if trunc_reason and limits["truncated_by"] is None:
            limits["truncated_by"] = trunc_reason

    def expired() -> bool:
        if float(time_fn()) < deadline:
            return False
        if limits["truncated_by"] != "time_budget":
            note_cut("time_budget")
        return True

    def run_metrics() -> dict[str, Any]:
        # Run-dependent figures: returned beside the section, never inside it (the section is fingerprinted).
        return {"elapsed_ms": max(0, int(round((float(time_fn()) - start_clock) * 1000))),
                "time_budget_hit": limits["truncated_by"] == "time_budget"}

    def not_measured(with_finding: bool) -> dict[str, Any]:
        sec = _empty_section(status="not_measured", coverage="could_not_verify", reason="missing", limits=limits)
        findings = [_finding("skill_packs.could_not_verify", "skills", {"cuts": limits["cuts"], "reason": "missing"},
                             coverage="could_not_verify", classification="info")] if with_finding else []
        return make_component_envelope(findings=findings, coverage="could_not_verify",
                                       extra={"skill_packs": sec, "run_metrics": run_metrics()})

    try:
        root = Path(os.path.abspath(os.fspath(profile_path)))
    except (TypeError, ValueError):
        note_cut()
        return not_measured(True)

    try:
        st_root = os.lstat(root)
    except FileNotFoundError:
        return not_measured(False)
    except OSError:
        note_cut()
        return not_measured(True)

    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        if stat.S_ISLNK(st_root.st_mode):
            limits["symlinks_skipped"] += 1
        note_cut()
        return not_measured(True)

    if host_platform is None:
        host = sys.platform
    elif isinstance(host_platform, str) and host_platform.strip():
        host = host_platform.strip().lower()
    else:
        note_cut()
        host = sys.platform

    def read_bounded_file(path: Path, max_file_cap: int = MAX_FILE_BYTES) -> bytes | None:
        if expired():
            return None
        if credential_path(path):
            limits["credentials_skipped"] += 1
            note_cut()
            return None
        if _has_symlink_below(path, root):
            limits["symlinks_skipped"] += 1
            note_cut()
            return None
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError:
            note_cut()
            return None
        if stat.S_ISLNK(st.st_mode):
            limits["symlinks_skipped"] += 1
            note_cut()
            return None
        if not stat.S_ISREG(st.st_mode):
            note_cut()
            return None
        if st.st_size > max_file_cap:
            note_cut("max_file_bytes")
            return None
        remaining = MAX_TOTAL_BYTES - limits["bytes_read"]
        if remaining <= 0 or st.st_size > remaining:
            note_cut("max_total_bytes")
            return None
        rel = path.relative_to(root).as_posix()
        res = safe_read_regular_file(root, rel, max_bytes=min(max_file_cap, remaining))
        if res.coverage != "verified" or not res.stable or res.content is None:
            if res.bounded_exceeded:
                note_cut("max_file_bytes" if max_file_cap <= remaining else "max_total_bytes")
            else:
                note_cut()
            return None
        limits["bytes_read"] += len(res.content)
        return res.content

    # Config-derived inputs (`skills.disabled`, `skills.auto_load`, `skills.external_dirs`): read from
    # `<profile>/config.yaml` when the caller passes None, so the caller only needs `profile_path`.
    # Only these three keys are used; no other config value enters the output.
    skills_cfg: Mapping[str, Any] = {}
    if disabled_skills is None or auto_load_skills is None or external_dirs is None:
        cfg_path = root / CONFIG_FILE
        try:
            os.lstat(cfg_path)
            cfg_present = True
        except FileNotFoundError:
            cfg_present = False
        except OSError:
            cfg_present = False
            note_cut()
        if cfg_present:
            raw_cfg = read_bounded_file(cfg_path, MAX_FILE_BYTES)
            if raw_cfg is not None:
                try:
                    parsed_cfg = _parse_simple_yaml_mapping(raw_cfg.decode("utf-8-sig"), reject_duplicate_keys=True)
                    raw_skills_cfg = parsed_cfg.get("skills") if isinstance(parsed_cfg, dict) else None
                    if raw_skills_cfg is None:
                        skills_cfg = {}
                    elif isinstance(raw_skills_cfg, dict):
                        skills_cfg = raw_skills_cfg
                    else:
                        note_cut()
                except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
                    note_cut()

    def from_config(value: Any, key: str, *, scalar_list: bool = False) -> Any:
        if value is not None:
            return value
        raw = skills_cfg.get(key)
        if raw is None:
            return ()
        if isinstance(raw, str) and "${" in raw:
            note_cut()  # Hermes expands environment references; a file audit cannot.
            return ()
        if scalar_list and isinstance(raw, str):
            return [raw]  # agent/skill_utils.py:329-336 (_config_str_list): a string is one entry.
        return raw

    disabled_skills = from_config(disabled_skills, "disabled")
    auto_load_skills = from_config(auto_load_skills, "auto_load")
    external_dirs = from_config(external_dirs, "external_dirs", scalar_list=True)

    disabled_list, disabled_ok = _parse_string_sequence(disabled_skills)
    if not disabled_ok:
        note_cut()
    # agent/skill_utils.py:278,293: ESSENTIAL_SKILLS (`hermes-agent`) can never be disabled.
    disabled_set = set(disabled_list) - set(ESSENTIAL_SKILLS)

    auto_load_list, auto_ok = _parse_string_sequence(auto_load_skills)
    if not auto_ok:
        note_cut()
    auto_load_names = list(dict.fromkeys(auto_load_list))  # agent/skill_commands.py:997

    ext_raw_list, ext_ok = _parse_string_sequence(external_dirs)
    if not ext_ok:
        note_cut()

    skills_root = root / "skills"
    search_roots: list[tuple[int, Path]] = [(TIER_LOCAL, skills_root)]
    seen_roots: set[Path] = {skills_root}
    for ext_entry in ext_raw_list:
        if ".." in Path(ext_entry).parts or "~" in ext_entry or "$" in ext_entry or "\x00" in ext_entry:
            limits["external_dirs_skipped"] += 1
            note_cut()
            continue
        cand = Path(ext_entry)
        cand = Path(os.path.abspath(cand if cand.is_absolute() else (root / cand)))
        if not cand.is_relative_to(root) or cand == root:
            limits["external_dirs_skipped"] += 1
            note_cut()
            continue
        if credential_path(cand):
            limits["credentials_skipped"] += 1
            limits["external_dirs_skipped"] += 1
            note_cut()
            continue
        if _has_symlink_below(cand, root):
            limits["symlinks_skipped"] += 1
            limits["external_dirs_skipped"] += 1
            note_cut()
            continue
        if cand not in seen_roots:
            seen_roots.add(cand)
            search_roots.append((TIER_EXTERNAL, cand))

    any_skill_root_exists = False
    for _, sr in search_roots:
        try:
            st_sr = os.lstat(sr)
            if stat.S_ISLNK(st_sr.st_mode):
                limits["symlinks_skipped"] += 1
                note_cut()
            elif stat.S_ISDIR(st_sr.st_mode):
                any_skill_root_exists = True
        except FileNotFoundError:
            pass
        except OSError:
            note_cut()

    snap_exists = False
    try:
        st_snap = os.lstat(root / SNAPSHOT_FILE)
        snap_exists = True
        if stat.S_ISLNK(st_snap.st_mode):
            limits["symlinks_skipped"] += 1
            note_cut()
            snap_exists = False
    except FileNotFoundError:
        pass
    except OSError:
        note_cut()

    if not any_skill_root_exists and not snap_exists and limits["cuts"] == 0:
        return not_measured(False)

    # 1. Bundled manifest (`skills/.bundled_manifest`, tools/skills_sync.py:113-130).
    manifest_names: set[str] = set()
    manifest_path = root / MANIFEST
    try:
        os.lstat(manifest_path)
        bm_present = True
    except FileNotFoundError:
        bm_present = False
    except OSError:
        bm_present = False
        note_cut()
    if bm_present:
        raw_bm = read_bounded_file(manifest_path, MAX_FILE_BYTES)
        if raw_bm is not None:
            try:
                for line in raw_bm.decode("utf-8-sig").splitlines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if ":" in stripped:
                        m_name, _, m_hash = stripped.partition(":")
                        m_name, m_hash = m_name.strip(), m_hash.strip()
                        if not m_name or not re.fullmatch(r"[0-9a-f]{32}", m_hash):
                            note_cut()
                            continue
                        manifest_names.add(m_name)
                    else:
                        manifest_names.add(stripped)
            except UnicodeDecodeError:
                note_cut()

    # 2. Hub lock (`skills/.hub/lock.json`, tools/skills_hub.py:322-370). Only names, sources and
    # install paths are used internally; none of the lock's text is copied into the output.
    hub_lock_present = False
    hub_lock_entries = 0
    hub_by_rel: dict[str, str] = {}
    hub_by_name: dict[str, str] = {}
    hub_install_paths: list[tuple[str, str]] = []
    lock_path = root / HUB_LOCK_FILE
    try:
        os.lstat(lock_path)
        hub_lock_present = True
    except FileNotFoundError:
        hub_lock_present = False
    except OSError:
        note_cut()
    if hub_lock_present:
        raw_lock = read_bounded_file(lock_path, MAX_FILE_BYTES)
        if raw_lock is not None:
            try:
                lock_obj = json.loads(raw_lock.decode("utf-8-sig"))
                if not isinstance(lock_obj, dict) or not isinstance(lock_obj.get("installed"), dict):
                    raise ValueError("invalid lock structure")
                for idx_row, (k_name, entry_val) in enumerate(lock_obj["installed"].items()):
                    if idx_row >= MAX_USAGE_ROWS:
                        note_cut("max_usage_rows")
                        break
                    if not isinstance(entry_val, dict):
                        note_cut()
                        continue
                    src = str(entry_val.get("source") or "").strip() or "unknown"
                    inst_rel = str(entry_val.get("install_path") or "").strip().strip("/")
                    hub_lock_entries += 1
                    hub_by_name[str(k_name).strip()] = src
                    if inst_rel:
                        hub_by_rel[inst_rel] = src
                    hub_install_paths.append((str(k_name).strip(), inst_rel))
            except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
                note_cut()

    # 3. Discover skill packages (agent/skill_utils.py:878-891 pruning; symlinks are never followed here,
    # whereas Hermes follows them: every skipped symlink is a cut).
    discovered_packages: list[tuple[int, Path, Path, float]] = []
    visited_dirs: set[Path] = set()
    for tier, tier_root in search_roots:
        if expired():
            break
        try:
            st_tr = os.lstat(tier_root)
        except FileNotFoundError:
            continue
        except OSError:
            note_cut()
            continue
        if stat.S_ISLNK(st_tr.st_mode) or not stat.S_ISDIR(st_tr.st_mode):
            if stat.S_ISLNK(st_tr.st_mode):
                limits["symlinks_skipped"] += 1
            note_cut()
            continue
        stack: list[tuple[Path, int]] = [(tier_root, 0)]
        stop_walk = False
        while stack and not stop_walk:
            if expired():
                break
            cur_dir, depth = stack.pop()
            if cur_dir in visited_dirs:
                continue
            visited_dirs.add(cur_dir)
            if credential_path(cur_dir):
                limits["credentials_skipped"] += 1
                note_cut()
                continue
            if _has_symlink_below(cur_dir, root):
                limits["symlinks_skipped"] += 1
                note_cut()
                continue
            entries: list[os.DirEntry[str]] | None = []
            skill_md_mtime: float | None = None
            try:
                with os.scandir(cur_dir) as it:
                    for entry in it:
                        limits["entries_walked"] += 1
                        if limits["entries_walked"] > MAX_TREE_ENTRIES:
                            note_cut("max_entries")
                            entries = None
                            break
                        if entry.name == "SKILL.md" and not entry.is_symlink() and entry.is_file(follow_symlinks=False):
                            skill_md_mtime = float(entry.stat(follow_symlinks=False).st_mtime)
                        entries.append(entry)
            except OSError:
                note_cut()
                continue
            if entries is None:
                break
            has_skill_md = skill_md_mtime is not None
            if has_skill_md and cur_dir != tier_root:
                if len(discovered_packages) >= MAX_SKILLS:
                    note_cut("max_skills")
                    stop_walk = True
                    break
                discovered_packages.append((tier, tier_root, cur_dir, float(skill_md_mtime or 0.0)))
            subdirs_to_push: list[tuple[Path, int]] = []
            for entry in sorted(entries, key=lambda e: e.name):
                if _has_surrogate(entry.name):
                    note_cut()
                    continue
                if entry.name.startswith("._"):
                    continue
                entry_path = Path(entry.path)
                if credential_path(entry_path):
                    limits["credentials_skipped"] += 1
                    note_cut()
                    continue
                try:
                    if entry.is_symlink():
                        limits["symlinks_skipped"] += 1
                        note_cut()
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in EXCLUDED_SKILL_DIRS or entry.name in CACHE_DIRS:
                            continue
                        if has_skill_md and entry.name in SKILL_SUPPORT_DIRS:
                            continue
                        if depth + 1 > MAX_DEPTH:
                            note_cut("max_depth")
                            continue
                        subdirs_to_push.append((entry_path, depth + 1))
                    elif not entry.is_file(follow_symlinks=False):
                        note_cut()
                except OSError:
                    note_cut()
            for sub_item in reversed(subdirs_to_push):
                stack.append(sub_item)

    # 4. Inspect each discovered skill package.
    discovered_packages.sort(key=lambda item: (item[0], str(item[2])))
    pkg_dir_set = {item[2] for item in discovered_packages}
    skills_records: list[dict[str, Any]] = []
    license_file_count = 0
    license_total_bytes = 0
    license_hash_counts: dict[str, int] = {}
    non_text_over_1mb_count = 0
    non_text_over_1mb_bytes = 0
    non_text_by_type: dict[str, dict[str, int]] = {}

    for tier, tier_root, pkg_dir, md_mtime in discovered_packages:
        if expired():
            break
        md_path = pkg_dir / "SKILL.md"
        md_bytes = read_bounded_file(md_path, MAX_FILE_BYTES)
        if md_bytes is None:
            continue
        try:
            md_text = md_bytes.decode("utf-8-sig")
            fm, body = _parse_frontmatter_like_hermes(md_text)
        except UnicodeDecodeError:
            # agent/prompt_builder.py:1163-1165: an unreadable SKILL.md is listed with empty frontmatter.
            md_text = md_bytes.decode("utf-8", "replace")
            fm, body = {}, md_text

        rel_pkg = pkg_dir.relative_to(tier_root).as_posix()
        rel_parts = [p for p in rel_pkg.split("/") if p]
        folder_name = pkg_dir.name
        # agent/prompt_builder.py:1140-1145,1273-1274: frontmatter_name = str(fm.get("name", folder)).
        fm_name = str(fm.get("name", folder_name))
        entry_name = fm_name or folder_name
        description = clip_skill_description(_normalize_description(fm))
        # agent/prompt_builder.py:1141: parts are relative to the root and end with SKILL.md.
        md_parts = (*rel_parts, "SKILL.md")
        category = "general" if len(md_parts) < 2 else "/".join(md_parts[:-2]) if len(md_parts) > 2 else md_parts[0]
        platform_ok = _platform_matches(fm.get("platforms"), host) and not _environment_hidden(fm)
        raw_desc_lower = _normalize_description(fm).lower()

        is_local = tier == TIER_LOCAL
        is_stock = is_local and (rel_pkg in manifest_names or folder_name in manifest_names
                                 or entry_name in manifest_names)
        hub_source = (hub_by_rel.get(rel_pkg) or hub_by_name.get(entry_name)
                      or hub_by_name.get(folder_name)) if is_local else None

        nested_pkgs = {other for other in pkg_dir_set if other != pkg_dir and other.is_relative_to(pkg_dir)}
        pkg_stack: list[tuple[Path, int]] = [(pkg_dir, 0)]
        pkg_files_seen = 0
        pkg_license_hashes: set[str] = set()
        while pkg_stack:
            if expired():
                break
            c_dir, c_depth = pkg_stack.pop()
            if any(c_dir == np or c_dir.is_relative_to(np) for np in nested_pkgs):
                continue
            if credential_path(c_dir):
                limits["credentials_skipped"] += 1
                note_cut()
                continue
            if _has_symlink_below(c_dir, root):
                limits["symlinks_skipped"] += 1
                note_cut()
                continue
            c_entries: list[os.DirEntry[str]] | None = []
            try:
                with os.scandir(c_dir) as it:
                    for e in it:
                        limits["entries_walked"] += 1
                        if limits["entries_walked"] > MAX_TREE_ENTRIES:
                            note_cut("max_entries")
                            c_entries = None
                            break
                        c_entries.append(e)
            except OSError:
                note_cut()
                continue
            if c_entries is None:
                break
            sub_dirs: list[tuple[Path, int]] = []
            for e in sorted(c_entries, key=lambda x: x.name):
                if _has_surrogate(e.name):
                    note_cut()
                    continue
                if e.name.startswith("._"):
                    continue
                e_path = Path(e.path)
                if any(e_path == np or e_path.is_relative_to(np) for np in nested_pkgs):
                    continue
                if credential_path(e_path):
                    limits["credentials_skipped"] += 1
                    note_cut()
                    continue
                try:
                    if e.is_symlink():
                        limits["symlinks_skipped"] += 1
                        note_cut()
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name in EXCLUDED_SKILL_DIRS or e.name in CACHE_DIRS:
                            continue
                        if c_depth + 1 > MAX_DEPTH:
                            note_cut("max_depth")
                            continue
                        sub_dirs.append((e_path, c_depth + 1))
                    elif e.is_file(follow_symlinks=False):
                        if e_path == md_path:
                            continue
                        pkg_files_seen += 1
                        if pkg_files_seen > MAX_FILES_PER_SKILL:
                            note_cut("max_files_per_skill")
                            pkg_stack.clear()
                            break
                        f_size = int(e.stat(follow_symlinks=False).st_size)
                        if _is_license_filename(e.name):
                            if limits["files_hashed"] >= MAX_LICENSE_FILES:
                                note_cut("max_license_files")
                            else:
                                lic_bytes = read_bounded_file(e_path, MAX_LICENSE_FILE_BYTES)
                                if lic_bytes is not None:
                                    limits["files_hashed"] += 1
                                    lic_digest = hashlib.sha256(lic_bytes).hexdigest()
                                    pkg_license_hashes.add(lic_digest)
                                    license_file_count += 1
                                    license_total_bytes += f_size
                                    license_hash_counts[lic_digest] = license_hash_counts.get(lic_digest, 0) + 1
                        if f_size > LARGE_PAYLOAD_BYTES:
                            remaining = MAX_TOTAL_BYTES - limits["bytes_read"]
                            if remaining < HEADER_PROBE_BYTES:
                                note_cut("max_total_bytes")
                            else:
                                header = _read_prefix_bytes(root, e_path.relative_to(root).as_posix(), HEADER_PROBE_BYTES)
                                if header is None:
                                    note_cut()
                                else:
                                    limits["bytes_read"] += len(header)
                                    payload_class = _detect_payload_class(header, e_path.suffix.lower())
                                    if payload_class is not None:
                                        non_text_over_1mb_count += 1
                                        non_text_over_1mb_bytes += f_size
                                        bucket = non_text_by_type.setdefault(payload_class, {"count": 0, "bytes": 0})
                                        bucket["count"] += 1
                                        bucket["bytes"] += f_size
                    else:
                        note_cut()
                except OSError:
                    note_cut()
            for sd in reversed(sub_dirs):
                pkg_stack.append(sd)

        skills_records.append({
            "name": entry_name,
            "folder_name": folder_name,
            # Absolute path of the existing skill folder: the report serializer keeps it unchanged (no symlink
            # lies below the profile root here, so realpath only resolves the root's own ancestors).
            "abs_path": os.path.realpath(pkg_dir),
            "relative_path": rel_pkg,
            "rel_skill_md": f"{rel_pkg}/SKILL.md",
            "rank": len(md_parts),
            "category": category,
            "tier": tier,
            "root": str(tier_root),
            "sha": hashlib.sha256(md_bytes).hexdigest(),
            "description": description,
            "platform_ok": platform_ok,
            "runtime_gated": _runtime_gated(fm),
            "skill_md_chars": len(md_text),
            "is_stock": is_stock,
            "hub_source": hub_source,
            "mtime": md_mtime,
            "license_hashes": sorted(pkg_license_hashes),
            "always_load_cue": any(cue in raw_desc_lower for cue in ALWAYS_LOAD_CUES),
        })

    # 5. Resolution like agent/skill_utils.py:445-519 (resolve_skill_catalog / pick_skill_candidate).
    owners: dict[str, list[int]] = {}
    for i, rec in enumerate(skills_records):
        for alias in {rec["name"], rec["folder_name"], rec["relative_path"]}:
            owners.setdefault(alias, []).append(i)
    winner: dict[str, int | None] = {}
    for alias, idxs in owners.items():
        top = min(skills_records[j]["tier"] for j in idxs)
        contenders = [j for j in idxs if skills_records[j]["tier"] == top]
        won: int | None = contenders[0] if len(contenders) == 1 else None
        if (len(contenders) > 1 and len({skills_records[j]["root"] for j in contenders}) == 1
                and len({skills_records[j]["sha"] for j in contenders}) == 1):
            ranked = sorted(contenders, key=lambda j: skills_records[j]["rank"])
            if skills_records[ranked[0]]["rank"] != skills_records[ranked[1]]["rank"]:
                won = ranked[0]
        winner[alias] = won
    for i, rec in enumerate(skills_records):
        higher = [j for j in owners[rec["name"]] if skills_records[j]["tier"] < rec["tier"]]
        if higher or winner[rec["name"]] not in (None, i):
            rec["status"], rec["load_name"] = "shadowed", None
        elif winner[rec["name"]] == i:
            rec["status"], rec["load_name"] = "unique", rec["name"]
        else:
            rec["status"] = "ambiguous"
            rec["load_name"] = rec["relative_path"] if winner[rec["relative_path"]] == i else None
        # agent/prompt_builder.py:1400-1403,1432-1433: hidden by folder name, declared name or load_name.
        rec["disabled"] = bool({rec["folder_name"], rec["name"], rec["load_name"]} - {None} & disabled_set)
        rec["auto_loaded"] = (bool({rec["folder_name"], rec["name"], rec["load_name"]} - {None} & set(auto_load_names))
                              and not rec["disabled"] and rec["status"] != "shadowed")

    visible = [r for r in skills_records if r["platform_ok"] and r["status"] != "shadowed" and not r["disabled"]]
    loadable = [r for r in visible if r["load_name"]]
    unloadable = sorted({r["name"] for r in visible if not r["load_name"]})
    disabled_count = sum(1 for r in skills_records if r["disabled"])
    shadowed_count = sum(1 for r in skills_records if r["status"] == "shadowed")
    platform_excluded = sum(1 for r in skills_records
                            if not r["platform_ok"] and r["status"] != "shadowed" and not r["disabled"])
    runtime_gated = sum(1 for r in loadable if r["runtime_gated"])
    stock_loadable = [r for r in loadable if r["is_stock"]]
    non_stock_loadable = [r for r in loadable if not r["is_stock"]]

    rendered = _render_index([(r["category"], str(r["load_name"]), r["description"]) for r in loadable], unloadable)
    index_chars = len(rendered)
    listed: dict[tuple[str, str], str] = {}
    for r in loadable:
        listed.setdefault((r["category"], str(r["load_name"])), r["description"])
    name_chars = sum(len(n) for _, n in listed)
    desc_chars = sum(len(d) for d in listed.values())
    est_tokens = index_chars // CHARS_PER_TOKEN

    # Snapshot inspection (`.skills_prompt_snapshot.json`, agent/prompt_builder.py:1082-1135).
    snapshot_info = _empty_snapshot()
    if snap_exists:
        snapshot_info["present"] = True
        raw_snap = read_bounded_file(root / SNAPSHOT_FILE, MAX_FILE_BYTES)
        if raw_snap is None:
            snapshot_info["coverage"] = "could_not_verify"
        else:
            try:
                snap_obj = json.loads(raw_snap.decode("utf-8-sig"))
                if not isinstance(snap_obj, dict) or not isinstance(snap_obj.get("skills"), list):
                    raise ValueError("invalid snapshot")
                snap_ver = snap_obj.get("version")
                if not isinstance(snap_ver, int) or isinstance(snap_ver, bool):
                    raise ValueError("invalid snapshot version")
                local_rels = {r["rel_skill_md"] for r in skills_records if r["tier"] == TIER_LOCAL}
                local_names = {r["folder_name"] for r in skills_records if r["tier"] == TIER_LOCAL}
                stale_count = 0
                snap_desc_chars = 0
                snap_count = 0
                for idx_s, entry in enumerate(snap_obj["skills"]):
                    if idx_s >= MAX_USAGE_ROWS:
                        note_cut("max_usage_rows")
                        break
                    if not isinstance(entry, dict):
                        note_cut()
                        continue
                    snap_count += 1
                    s_folder = str(entry.get("skill_name") or "").strip()
                    s_cat = str(entry.get("category") or "").strip()
                    s_rel = str(entry.get("rel") or "").strip()
                    snap_desc_chars += len(clip_skill_description(str(entry.get("description") or "")))
                    if s_rel:
                        exists_on_disk = s_rel in local_rels
                    else:
                        inferred_rel = (f"{s_folder}/SKILL.md" if (not s_cat or s_cat == "general" or s_cat == s_folder)
                                        else f"{s_cat}/{s_folder}/SKILL.md")
                        exists_on_disk = inferred_rel in local_rels or (not s_cat and s_folder in local_names)
                    if not exists_on_disk:
                        stale_count += 1  # counted only: a stale entry has no file on disk to point at
                snapshot_info.update({
                    "coverage": "verified",
                    "version": snap_ver,
                    "skills_count": snap_count,
                    "description_chars": snap_desc_chars,
                    "stale_count": stale_count,
                })
            except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
                note_cut()
                snapshot_info["coverage"] = "could_not_verify"

    # Usage (`skills/.usage.json`, tools/skill_usage.py:47-53,348-378). Ages are measured against the newest
    # timestamp in the file, never against the clock.
    usage_path = root / USAGE_FILE
    usage_present = False
    try:
        st_u = os.lstat(usage_path)
        if stat.S_ISLNK(st_u.st_mode):
            limits["symlinks_skipped"] += 1
            note_cut()
        else:
            usage_present = True
    except FileNotFoundError:
        usage_present = False
    except OSError:
        note_cut()

    usage_map: dict[str, dict[str, Any]] = {}
    usage_coverage = "could_not_verify"
    usage_reason: str | None = "usage_file_missing" if not usage_present else None
    first_dt: datetime | None = None
    last_dt: datetime | None = None
    if usage_present:
        raw_usage = read_bounded_file(usage_path, MAX_FILE_BYTES)
        if raw_usage is None:
            usage_reason = "truncated" if limits["truncated_by"] else "usage_file_malformed"
        else:
            try:
                parsed_u = json.loads(raw_usage.decode("utf-8-sig"))
                if not isinstance(parsed_u, dict):
                    raise ValueError("usage root must be a JSON object")
                usage_rows_ok = True
                stamps: list[datetime] = []
                for idx_u, (ukey, uval) in enumerate(parsed_u.items()):
                    if idx_u >= MAX_USAGE_ROWS:
                        note_cut("max_usage_rows")
                        usage_rows_ok = False
                        break
                    if not isinstance(uval, dict):
                        note_cut()
                        usage_rows_ok = False
                        continue
                    ucount, u_ok = _non_negative_int(uval.get("use_count"))
                    if not u_ok:
                        note_cut()
                        usage_rows_ok = False
                    rec_stamps = [dt for k in _USAGE_TS_KEYS if (dt := _parse_iso_ts(uval.get(k))) is not None]
                    stamps.extend(rec_stamps)
                    usage_map[str(ukey)] = {
                        "use_count": ucount,
                        "latest": _latest_activity_dt(uval),
                        "own_start": min(rec_stamps) if rec_stamps else None,
                    }
                if stamps:
                    first_dt, last_dt = min(stamps), max(stamps)
                if not usage_rows_ok:
                    usage_reason = "truncated" if limits["truncated_by"] else "usage_file_malformed"
                elif last_dt is None:
                    usage_reason = "usage_file_no_timestamps"
                else:
                    usage_coverage = "verified"
                    usage_reason = None
            except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
                note_cut()
                usage_reason = "usage_file_malformed"

    def use_record(rec: Mapping[str, Any]) -> Mapping[str, Any] | None:
        return usage_map.get(rec["name"]) or usage_map.get(rec["folder_name"])

    def use_count(rec: Mapping[str, Any]) -> int:
        urec = use_record(rec)
        return int(urec["use_count"]) if urec else 0

    def zero_use_state(rec: Mapping[str, Any]) -> str:
        """'zero' when the usage file observed this skill, else 'unverifiable'. A skill is observed when it has
        its own record with a timestamp, or its SKILL.md time lies between the file's first and newest record."""
        urec = use_record(rec)
        if urec and urec["own_start"] is not None:
            return "zero"
        if first_dt is None or last_dt is None:
            return "unverifiable"
        if first_dt.timestamp() <= float(rec["mtime"]) <= last_dt.timestamp():
            return "zero"
        return "unverifiable"

    zero_use_count: int | None = None
    never_used_share: float | None = None
    unverifiable_count: int | None = None
    ns_evaluated = 0
    non_stock_zero_use_count: int | None = None
    non_stock_never_used_share: float | None = None
    days_buckets: dict[str, int] | None = None
    top_used_counts: list[dict[str, Any]] = []
    skills_evaluated = len(loadable)

    if usage_present and usage_map:
        # Usage keys are skill names; each entry points at the existing skill folder of that name, or carries
        # `path: null` when no such skill is on disk (the name itself is never output).
        by_alias: dict[str, str] = {}
        for r in sorted(skills_records, key=lambda r: (r["status"] == "shadowed", r["tier"], r["abs_path"])):
            for alias in (r["name"], r["folder_name"]):
                by_alias.setdefault(alias, r["abs_path"])
        ranked_uses = sorted(((k, int(v["use_count"])) for k, v in usage_map.items() if v["use_count"] > 0),
                             key=lambda kv: (-kv[1], kv[0]))[:MAX_LISTED]
        top_used_counts = [{"path": by_alias.get(k), "use_count": c} for k, c in ranked_uses]

    if usage_coverage == "verified" and last_dt is not None:
        states = {id(r): ("used" if use_count(r) > 0 else zero_use_state(r)) for r in loadable}
        unverifiable_count = sum(1 for s in states.values() if s == "unverifiable")
        zero_use_count = sum(1 for s in states.values() if s == "zero")
        skills_evaluated = len(loadable) - unverifiable_count
        never_used_share = round(zero_use_count / skills_evaluated, 4) if skills_evaluated else 0.0
        ns_eval = [r for r in non_stock_loadable if states[id(r)] != "unverifiable"]
        ns_evaluated = len(ns_eval)
        non_stock_zero_use_count = sum(1 for r in ns_eval if states[id(r)] == "zero")
        non_stock_never_used_share = round(non_stock_zero_use_count / ns_evaluated, 4) if ns_evaluated else 0.0
        days_buckets = _usage_age_buckets(loadable, states, use_record, last_dt)
    else:
        ns_evaluated = len(non_stock_loadable)

    # Bulk installs across non-stock skills, in priority order:
    # (i) identical LICENSE/NOTICE/COPYING hash -> (ii) hub-lock source -> (iii) SKILL.md times within 2 minutes.
    non_stock_all = [r for r in skills_records if not r["is_stock"]]
    claimed_paths: set[tuple[str, str]] = set()
    bulk_groups: list[dict[str, Any]] = []

    def key_of(r: Mapping[str, Any]) -> tuple[str, str]:
        return (r["root"], r["relative_path"])

    def make_bulk_group(signal: str, weak: bool, members: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        count = len(members)
        if usage_coverage == "verified":
            used: int | None = sum(1 for m in members if use_count(m) > 0)
            share: float | None = round(used / count, 4) if count else 0.0
        else:
            used, share = None, None
        return {"signal": signal, "weak_signal": weak, "skills_count": count, "used_skills_count": used,
                "used_share": share}

    by_lic_hash: dict[str, list[dict[str, Any]]] = {}
    for r in non_stock_all:
        for h in r["license_hashes"]:
            by_lic_hash.setdefault(h, []).append(r)
    for _, members in sorted(by_lic_hash.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        unclaimed = [m for m in members if key_of(m) not in claimed_paths]
        if len(unclaimed) >= BULK_GROUP_MIN_SKILLS:
            claimed_paths.update(key_of(m) for m in unclaimed)
            bulk_groups.append(make_bulk_group("license_hash", False, unclaimed))

    by_hub_src: dict[str, list[dict[str, Any]]] = {}
    for r in non_stock_all:
        if r["hub_source"] and key_of(r) not in claimed_paths:
            by_hub_src.setdefault(str(r["hub_source"]), []).append(r)
    for _, members in sorted(by_hub_src.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(members) >= BULK_GROUP_MIN_SKILLS:
            claimed_paths.update(key_of(m) for m in members)
            bulk_groups.append(make_bulk_group("hub_lock_source", False, members))

    remaining_mtime = sorted((r for r in non_stock_all if key_of(r) not in claimed_paths),
                             key=lambda r: (r["mtime"], r["root"], r["relative_path"]))
    while len(remaining_mtime) >= BULK_GROUP_MIN_SKILLS:
        best_window: list[dict[str, Any]] = []
        hi = 0
        for lo_i in range(len(remaining_mtime)):
            hi = max(hi, lo_i)
            while hi + 1 < len(remaining_mtime) and (
                    float(remaining_mtime[hi + 1]["mtime"]) - float(remaining_mtime[lo_i]["mtime"]) <= MTIME_WINDOW_SECONDS):
                hi += 1
            if hi - lo_i + 1 > len(best_window):
                best_window = remaining_mtime[lo_i: hi + 1]
        if len(best_window) < BULK_GROUP_MIN_SKILLS:
            break
        win_keys = {key_of(m) for m in best_window}
        claimed_paths.update(win_keys)
        bulk_groups.append(make_bulk_group("mtime_window_2m", True, best_window))
        remaining_mtime = [r for r in remaining_mtime if key_of(r) not in win_keys]

    local_rels_set = {r["relative_path"] for r in skills_records if r["tier"] == TIER_LOCAL}
    local_names_set = ({r["name"] for r in skills_records if r["tier"] == TIER_LOCAL}
                       | {r["folder_name"] for r in skills_records if r["tier"] == TIER_LOCAL})
    hub_missing_on_disk = sum(1 for k_name, inst_rel in hub_install_paths
                              if (inst_rel and inst_rel not in local_rels_set)
                              or (not inst_rel and k_name not in local_names_set))

    identical_license_copies = sum(c for c in license_hash_counts.values() if c >= 2)
    distinct_license_texts = len(license_hash_counts)

    # Always-on skills: skills.auto_load entries and frontmatter-description cues (never body text).
    auto_loaded = {r["abs_path"] for r in loadable if r["auto_loaded"]}
    cue_skills = {r["abs_path"] for r in loadable if r["always_load_cue"]}
    always_on_union = auto_loaded | cue_skills
    non_stock_paths = {r["abs_path"] for r in non_stock_loadable}
    non_stock_always_on = sorted(s for s in always_on_union if s in non_stock_paths)

    non_stock_sizes = sorted(r["skill_md_chars"] for r in non_stock_loadable)
    median_chars = int(round(median(non_stock_sizes))) if non_stock_sizes else None
    p90_chars = _nearest_rank_percentile(non_stock_sizes, 0.90)
    max_chars = max(non_stock_sizes) if non_stock_sizes else None
    top_10_largest = [{"path": r["abs_path"], "chars": r["skill_md_chars"]}
                      for r in sorted(non_stock_loadable, key=lambda r: (-r["skill_md_chars"], r["abs_path"]))[:MAX_LISTED]]

    findings: list[dict[str, Any]] = []
    cov_for_index = "could_not_verify" if limits["cuts"] > 0 else "verified"

    if index_chars > INDEX_CHARS_THRESHOLD or len(loadable) > INDEX_SKILLS_THRESHOLD:
        findings.append(_finding(
            "skill_packs.index_cost", "skills",
            {"skills": len(loadable), "chars": index_chars, "estimated_tokens": est_tokens,
             "runtime_gated_count": runtime_gated, "platform_excluded_count": platform_excluded},
            coverage=cov_for_index, classification="review_suggested",
        ))

    if (usage_coverage == "verified" and ns_evaluated >= NEVER_USED_MIN_SKILLS
            and non_stock_never_used_share is not None and non_stock_never_used_share >= NEVER_USED_SHARE_THRESHOLD):
        findings.append(_finding(
            "skill_packs.never_used", USAGE_FILE,
            {"skills": ns_evaluated, "zero_use_count": non_stock_zero_use_count,
             "never_used_share": non_stock_never_used_share,
             "unverifiable_count": sum(1 for r in non_stock_loadable
                                       if use_count(r) == 0 and zero_use_state(r) == "unverifiable")},
            coverage=cov_for_index, classification="review_suggested",
        ))

    for grp in bulk_groups[:MAX_LISTED]:
        is_review = (not grp["weak_signal"] and grp["skills_count"] >= BULK_REVIEW_MIN_SKILLS
                     and grp["used_share"] is not None and grp["used_share"] < BULK_REVIEW_MAX_USED_SHARE)
        bulk_ev: dict[str, Any] = {"signal": grp["signal"], "weak_signal": grp["weak_signal"],
                                   "skills": grp["skills_count"]}
        if grp["used_skills_count"] is not None:  # absent rather than null without verified usage
            bulk_ev.update(used_skills=grp["used_skills_count"], used_share=grp["used_share"])
        findings.append(_finding(
            "skill_packs.bulk_install", "skills", bulk_ev,
            coverage="verified" if (usage_coverage == "verified" and limits["cuts"] == 0) else "could_not_verify",
            classification="review_suggested" if is_review else "info",
        ))

    if snapshot_info["present"] and snapshot_info["coverage"] == "verified" and snapshot_info["stale_count"] > 0:
        findings.append(_finding(
            "skill_packs.stale_index_snapshot", SNAPSHOT_FILE,
            {"snapshot_version": snapshot_info["version"], "snapshot_skills": snapshot_info["skills_count"],
             "stale_entries": snapshot_info["stale_count"]},
            coverage=cov_for_index, classification="info",
        ))

    if non_stock_always_on:
        findings.append(_finding(
            "skill_packs.always_on_skills", "skills",
            {"count": len(non_stock_always_on),
             "auto_loaded_count": sum(1 for s in non_stock_always_on if s in auto_loaded),
             "description_cue_count": sum(1 for s in non_stock_always_on if s in cue_skills)},
            coverage=cov_for_index, classification="review_suggested",
        ))

    if license_file_count > LICENSE_COPIES_THRESHOLD and distinct_license_texts < license_file_count:
        findings.append(_finding(
            "skill_packs.license_copies", "skills",
            {"count": license_file_count, "distinct_texts": distinct_license_texts, "bytes": license_total_bytes},
            coverage=cov_for_index, classification="info",
        ))

    overall_unverified = (limits["cuts"] > 0 or usage_coverage != "verified"
                          or snapshot_info["coverage"] == "could_not_verify")
    overall_coverage = "could_not_verify" if overall_unverified else "verified"
    overall_reason: str | None = None
    if overall_unverified:
        if limits["truncated_by"] is not None:
            overall_reason = "truncated"
        elif usage_reason is not None:
            overall_reason = usage_reason
        else:
            overall_reason = "unverified_inputs"
        ev_unv: dict[str, Any] = {"cuts": limits["cuts"], "reason": overall_reason}
        if limits["truncated_by"] is not None:
            ev_unv["truncated_by"] = limits["truncated_by"]
        findings.append(_finding(
            "skill_packs.could_not_verify", USAGE_FILE if usage_reason == "usage_file_missing" else "skills",
            ev_unv, coverage="could_not_verify", classification="info",
        ))

    section: dict[str, Any] = {
        "status": "completed",
        "coverage": overall_coverage,
        "reason": overall_reason,
        "truncated_by": limits["truncated_by"],
        "index": {
            "loadable_skills": len(loadable),
            "discovered_skills": len(skills_records),
            "stock_skills": len(stock_loadable),
            "non_stock_skills": len(non_stock_loadable),
            "disabled_skills_count": disabled_count,
            "shadowed_skills_count": shadowed_count,
            "platform_excluded_count": platform_excluded,
            "runtime_gated_count": runtime_gated,
            "index_chars": index_chars,
            "name_chars": name_chars,
            "description_chars": desc_chars,
            "estimated_tokens": est_tokens,
            "snapshot": snapshot_info,
        },
        "usage": {
            "present": usage_present,
            "coverage": usage_coverage,
            "reason": usage_reason,
            "recording_since": _year_month(first_dt),
            "recording_until": _year_month(last_dt),
            "skills_evaluated": skills_evaluated,
            "zero_use_count": zero_use_count,
            "never_used_share": never_used_share,
            "zero_use_unverifiable_count": unverifiable_count,
            "non_stock_skills_evaluated": ns_evaluated,
            "non_stock_zero_use_count": non_stock_zero_use_count,
            "non_stock_never_used_share": non_stock_never_used_share,
            "top_used_counts": top_used_counts,
            "days_since_last_use": days_buckets,
        },
        "bulk_installs": {
            "group_count": len(bulk_groups),
            "groups": bulk_groups[:MAX_LISTED],
            "hub_lock_present": hub_lock_present,
            "hub_lock_entries": hub_lock_entries,
            "hub_lock_missing_on_disk": hub_missing_on_disk,
        },
        "dead_weight": {
            "license_files_count": license_file_count,
            "identical_license_copies": identical_license_copies,
            "distinct_license_texts": distinct_license_texts,
            "license_bytes": license_total_bytes,
            "non_text_over_1mb_count": non_text_over_1mb_count,
            "non_text_over_1mb_bytes": non_text_over_1mb_bytes,
            "non_text_over_1mb_by_type": {k: non_text_by_type[k] for k in NON_TEXT_CLASSES if k in non_text_by_type},
        },
        "always_on": {
            "count": len(always_on_union),
            "auto_loaded_count": len(auto_loaded),
            "description_cue_count": len(cue_skills),
            "non_stock_count": len(non_stock_always_on),
            "paths": non_stock_always_on[:MAX_LISTED],
        },
        "loaded_sizes": {
            "median_chars": median_chars,
            "p90_chars": p90_chars,
            "max_chars": max_chars,
            "top_10_largest": top_10_largest,
        },
        "limits": _limits_out(limits),
        "thresholds": _thresholds(),
    }
    return make_component_envelope(findings=findings, coverage=overall_coverage,
                                   extra={"skill_packs": section, "run_metrics": run_metrics()})
