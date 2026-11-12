"""Bounded, read-only audit of duplicated content across Hermes profiles.

Confirms Hermes profile layout and cache/memory paths from source:
- Named profiles live under `<hermes_home>/profiles/<name>/` (non-hidden directories;
  tombstones live under `profiles/.deleted/<name>` and staging dirs under
  `profiles/.<name>.staging-<pid>`): `hermes_constants.py:318,345-408`,
  `hermes_cli/profiles.py:40,287-297,480-497`, `hermes_cli/profiles_initialization.py:9-18`.
- Identity and memory files per profile: `SOUL.md` at profile root
  (`hermes_cli/profiles.py:43`, `hermes_cli/profiles_initialization.py:37,48`,
  `tui_gateway/methods_profiles.py:337,367`) and `memories/MEMORY.md`,
  `memories/USER.md` (`hermes_cli/profiles.py:46`, `tools/memory_tool.py:38-40`,
  `tools/memory_tool_store.py:303`). Root `MEMORY.md`/`USER.md` are only listed as profile artifacts in the
  export include list (`hermes_cli/profiles.py:264`); the source does not show Hermes reading memory there, so
  they are a secondary candidate used only when `memories/<file>` is absent.
- Per-profile databases: `state.db` (`hermes_state.py:181,204`,
  `hermes_state_guard.py:127-135`), `cron/executions.db`
  (`hermes_cli/data_cleanup_holders.py:97`), `projects.db`
  (`skills/autonomous-ai-agents/hermes-agent/references/projects-and-folders.md:9`).
- Per-profile regenerable caches: `skills/.hub/` including
  `skills/.hub/index-cache/hermes-index.json` (`tools/skills_hub.py:61-67`,
  `tools/skills_hub_search.py:31-33`), `models_dev_cache.json` and
  `models_dev_cache.etag` (`agent/models_dev.py:241,245`), and
  `provider_models_cache.json` / `provider_models_cache.json.lock`
  (`hermes_cli/models.py:1857-1859`, `hermes_cli/models_cache_lock.py:21-24`).
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager, suppress
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from statistics import median
import time
from typing import Any, Callable

from .contract import make_component_envelope, make_finding
from .fingerprint import CredentialStoreNotOpened, open_checked
from .policy import credential_path
from .readonly_db import open_session_sqlite_without_sidecar_creation

# Safety caps
MAX_ENTRIES = 300_000  # Maximum directory entries walked across profiles.
MAX_BYTES_HASHED = 2 * 1024 * 1024 * 1024  # 2 GiB cap on total hashed bytes.
MAX_FILES_HASHED = 20_000  # Maximum files hashed.
MAX_SECONDS = 30.0  # Cooperative wall-clock budget in seconds.
MAX_DEPTH = 64  # Maximum directory recursion depth below a profile root.
HASH_CHUNK_BYTES = 1024 * 1024  # 1 MiB read chunks with O_NOFOLLOW.
LARGE_FILE_MIN_BYTES = 1024 * 1024  # Files >= 1 MiB are hashed regardless of basename.
MAX_IDENTITY_FILE_BYTES = 256 * 1024  # 256 KiB cap per identity/memory text file.
MAX_IDENTITY_FILES = 200  # Maximum identity/memory files examined for near-clones.
TOP_DUPLICATE_GROUPS = 15  # Top duplicate groups reported by wasted bytes.
MAX_NAMES_LISTED = 50  # Profile path lists (profiles, empty/log-only/no-config, family members) list at most this many.
MAX_IDENTITY_ROWS_LISTED = 150  # cloned_identity.files lists at most this many rows (50 profiles x 3 kinds).

# The section names things only by the ABSOLUTE path of an existing folder: a profile folder
# `<home>/profiles/<name>` or a first-level folder inside one. The report serializer keeps such paths as is and
# turns every other free string into a per-run token, so no name, file name or label string is ever emitted.
# A profile (or first-level folder) whose name does not match this pattern is counted but never listed.
SAFE_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
# Fixed label for size-only rows (counts and sizes are separate keys of the same row).
SIZE_ONLY_OBSERVATION = "size_only_not_hashed"

# Stop conditions: once one of these is recorded no further work of that kind is attempted, and the
# reason is reported in `truncated_by` even if an exclusion (symlink, read error) was recorded first.
_STOP_REASONS = frozenset({"time_budget", "entries_limit", "files_hashed_limit", "bytes_hashed_limit"})

# Thresholds separate a few deliberately different profiles from many copied ones: copied profiles
# repeat the same binaries, caches and identity files, and abandoned ones are empty or hold only logs.
MIN_PROFILES_FOR_FINDINGS = 3  # Do not flag homes with 1 or 2 profiles.
MIN_REPEATED_BINARY_BYTES = 10 * 1024 * 1024  # 10 MiB binary threshold: above config and memory files, below typical bundled runtimes.
MIN_REPEATED_BINARY_PROFILES = 3  # At least 3 profiles sharing the identical binary.
IDENTICAL_FILES_WASTED_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100 MiB total wasted bytes: copies of large binaries or databases, not of text files.
CLONED_IDENTITY_MIN_PROFILES = 3  # At least 3 profiles sharing byte-identical identity/memory files.
CLONED_IDENTITY_SHARED_LINE_THRESHOLD = 0.5  # > 50% median shared-line share triggers cloned_identity_files.
PER_PROFILE_CACHE_BYTES_THRESHOLD = 50 * 1024 * 1024  # 50 MiB regenerable per-profile caches: above what a single active profile normally caches.
MIN_EMPTY_OR_LOG_ONLY_PROFILES = 5  # At least 5 empty or log-only profile directories: more than a few experiments leave behind.
MIN_FAMILY_PREFIX_LEN = 2  # Shared alphabetic prefix length >= 2 (e.g. qa, rx, zk).
MIN_FAMILY_MEMBERS = 3  # At least 3 members to form a profile family.

# Eligible basenames for hashing when file size < 1 MiB (plus *.db).
SMALL_HASH_BASENAMES: frozenset[str] = frozenset({
    "SOUL.md",
    "MEMORY.md",
    "USER.md",
    "AGENTS.md",
    "SKILL.md",
    "models_dev_cache.json",
})

# config.yaml can embed API keys (`model.api_key` for custom endpoints, hermes_cli/config.py:766-781), so this module treats it
# like a credential-bearing file: lstat size only, never opened or hashed, in profiles and in the main home.
_SIZE_ONLY_NAME_PREFIXES: tuple[str, ...] = ("config.yaml", "config.yml")


def _size_only_name(name: str) -> bool:
    low = name.casefold()
    return any(low == pre or low.startswith(pre + ".") or low.startswith(pre + "~") for pre in _SIZE_ONLY_NAME_PREFIXES)

# Identity and memory relative path candidates per profile: hermes_cli/profiles.py:43,46; tools/memory_tool.py:38-40.
# The root fallbacks come only from the export include list (hermes_cli/profiles.py:264), not from a memory reader.
IDENTITY_KIND_CANDIDATES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("SOUL.md", ("SOUL.md",)),
    ("MEMORY.md", ("memories/MEMORY.md", "MEMORY.md")),
    ("USER.md", ("memories/USER.md", "USER.md")),
)
# Kinds that drive the cloned_identity numbers and finding. SOUL.md is measured (by_kind) but excluded:
# Hermes seeds the same default SOUL.md into every new profile (hermes_cli/profiles_initialization.py:45-48,
# hermes_cli/default_soul.py:9), so identical SOUL.md files are the normal state of an untouched profile.
CLONED_IDENTITY_FINDING_KINDS: frozenset[str] = frozenset({"MEMORY.md", "USER.md"})

# Executable magic byte prefixes (ELF, Mach-O 32/64/fat, PE/MZ, WebAssembly, shebang).
_EXECUTABLE_MAGICS: tuple[bytes, ...] = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
    b"MZ",
    b"\x00asm",
    b"#!",
)

_DIGIT_SERIES_RE = re.compile(r"^([a-z][a-z0-9_-]*?)[-_]?(\d+)$")
_LEADING_ALPHA_RE = re.compile(r"^([a-z]+)")

# Every consequence is ONE fixed sentence (the persistence layer keeps only exact allowlisted sentences);
# the numbers behind each finding live in its `evidence`.
FINDING_CONSEQUENCES: dict[str, str] = {
    "profile_duplicates.repeated_binary": (
        "An executable file of at least 10 MiB is stored as byte-identical copies in at least three profiles; "
        "this measures duplicated disk bytes and does not show whether any profile runs it."
    ),
    "profile_duplicates.identical_files": (
        "Byte-identical non-credential files repeated across profiles take more than 100 MiB beyond one copy "
        "each, not counting regenerable caches; this measures redundant storage across profile directories and "
        "does not establish which profile copy is authoritative."
    ),
    "profile_duplicates.cloned_identity_files": (
        "Byte-identical MEMORY.md or USER.md files appear in at least three profiles, or more than half of the "
        "lines in the median memory file match other profiles; this measures matching content only and cannot "
        "tell which copy is the original or how the files came to match."
    ),
    "profile_duplicates.per_profile_caches": (
        "Regenerable hub and model catalog caches repeated across profile directories exceed 50 MiB; this "
        "measures disk space used by per-profile cache copies and does not show data corruption."
    ),
    "profile_duplicates.empty_profiles": (
        "At least five profile directories are completely empty or contain only log files; this counts folder "
        "contents and does not show whether a gateway still references them."
    ),
    "profile_duplicates.could_not_verify": (
        "Profile duplicate measurements hit a safety bound, symlink exclusion, or read error before all profile "
        "entries were verified; partial counts are retained and unverified regions are not claimed clean."
    ),
}


def _is_safe_name(name: str) -> bool:
    return bool(SAFE_PROFILE_NAME_RE.fullmatch(name))


@contextmanager
def _open_user_db(path: Path | str):
    """Delegate any SQLite access to the sidecar-free read-only opener (audit hygiene rule 6)."""
    with open_session_sqlite_without_sidecar_creation(path, timeout=0.1) as (conn, identity):
        yield conn, identity


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _has_symlink_below(path: Path, anchor: Path) -> bool:
    """True when `path` or any ancestor down to `anchor` is a symlink."""
    cur = path
    while True:
        try:
            if cur.is_symlink():
                return True
        except OSError:
            return True
        if cur == anchor or cur.parent == cur:
            return False
        cur = cur.parent


# Size-only (never opened) files are described by a class label, never by name or path. A suffixed copy
# (`.env.bak-1`, `config.yaml.bak-<date>`) keeps the class and sets `suffixed_copy`.
_SIZE_ONLY_CLASSES: tuple[tuple[str, str], ...] = (
    (".env", "env_file"),
    ("auth.json", "auth_json"),
    ("config.yaml", "config_yaml"),
    ("config.yml", "config_yaml"),
)
SIZE_ONLY_OTHER_CLASS = "credential_other"


def _size_only_class(name: str) -> tuple[str, bool]:
    low = name.casefold()
    for pre, label in _SIZE_ONLY_CLASSES:
        if low.startswith(pre):
            return label, len(low) > len(pre)
    return SIZE_ONLY_OTHER_CLASS, False


# File-kind labels for duplicate groups (the vocabulary replaces file names).
FILE_KINDS: tuple[str, ...] = (
    "hub_index_cache", "models_dev_cache", "provider_models_cache", "skill_md", "identity_md", "agents_md",
    "database", "executable_file", "large_file",
)


def _file_kind(rel_posix: str, is_exec: bool) -> str:
    cache_kind = _classify_cache_rel(rel_posix)
    if cache_kind is not None:
        return cache_kind
    name = PurePosixPath(rel_posix).name
    if name == "SKILL.md":
        return "skill_md"
    if name in ("SOUL.md", "MEMORY.md", "USER.md"):
        return "identity_md"
    if name == "AGENTS.md":
        return "agents_md"
    if name.endswith(".db"):
        return "database"
    return "executable_file" if is_exec else "large_file"


def _is_eligible_for_hash(name: str, size: int) -> bool:
    """True when a non-credential regular file is eligible for duplicate hashing."""
    if size <= 0:
        return False
    if _size_only_name(name):
        return False
    if size >= LARGE_FILE_MIN_BYTES:
        return True
    return name in SMALL_HASH_BASENAMES or name.endswith(".db")


def _open_for_read(path: Path) -> int:
    """Open read-only, no symlink follow, non-blocking; try O_NOATIME first so reads leave access times alone.

    O_NOATIME exists only on Linux and is refused (EPERM) for files the caller does not own; either way the file
    is then opened without it, so access times may change where O_NOATIME is unavailable. The opened file is
    re-checked against the declared credentials (CredentialStoreNotOpened, closed unread).
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        noatime = os.O_NOATIME  # type: ignore[attr-defined]
    except AttributeError:
        noatime = 0
    if noatime:
        try:
            return open_checked(str(path), flags | noatime)
        except PermissionError:
            pass
    return open_checked(str(path), flags)


def _is_executable_magic(head: bytes) -> bool:
    return any(head.startswith(magic) for magic in _EXECUTABLE_MAGICS)


def _classify_cache_rel(rel_posix: str) -> str | None:
    """Classify per-profile regenerable cache files confirmed in the Hermes source."""
    if rel_posix.startswith("skills/.hub/"):
        return "hub_index_cache"
    if rel_posix in ("models_dev_cache.json", "models_dev_cache.etag"):
        return "models_dev_cache"
    name = PurePosixPath(rel_posix).name
    if name.startswith("provider_models_cache"):
        return "provider_models_cache"
    return None


def _compute_profile_families(profile_names: list[str]) -> list[tuple[str, list[str]]]:
    """Group safe profile names by trailing digit series and by shared alphabetic prefix (len >= 2, >= 3 members).

    Returns `(kind, sorted member names)` pairs; the caller emits each member as its profile folder path, never a
    prefix or label string.
    """
    sorted_names = sorted(profile_names)
    families: list[tuple[str, list[str]]] = []

    # 1. Trailing digit series (e.g. t1..t4, node-01..node-05, worker-1..worker-3)
    digit_buckets: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for name in sorted_names:
        m = _DIGIT_SERIES_RE.match(name)
        if m:
            stem = m.group(1).rstrip("-_")
            if stem:
                digit_buckets[stem].append((int(m.group(2)), name))
    for _stem, members in sorted(digit_buckets.items()):
        distinct_nums = {item[0] for item in members}
        if len(members) >= MIN_FAMILY_MEMBERS and len(distinct_nums) >= MIN_FAMILY_MEMBERS:
            families.append(("digit_series", sorted(item[1] for item in members)))

    # 2. Shared alphabetic prefix of length >= 2 with >= 3 members (e.g. qa, rx, zk)
    delimited_buckets: dict[str, list[str]] = defaultdict(list)
    alpha_by_name: dict[str, str] = {}
    for name in sorted_names:
        m = _LEADING_ALPHA_RE.match(name)
        if not m:
            continue
        alpha = m.group(1)
        if len(alpha) < MIN_FAMILY_PREFIX_LEN:
            continue
        alpha_by_name[name] = alpha
        if len(name) == len(alpha) or name[len(alpha)] in "-_":
            delimited_buckets[alpha].append(name)

    assigned: set[str] = set()
    for _stem, members in sorted(delimited_buckets.items()):
        if len(members) >= MIN_FAMILY_MEMBERS:
            families.append(("alphabetic_prefix", sorted(members)))
            assigned.update(members)

    two_char_buckets: dict[str, list[str]] = defaultdict(list)
    for name, alpha in sorted(alpha_by_name.items()):
        if name not in assigned:
            two_char_buckets[alpha[:MIN_FAMILY_PREFIX_LEN]].append(name)
    for _prefix2, members in sorted(two_char_buckets.items()):
        if len(members) >= MIN_FAMILY_MEMBERS:
            families.append(("alphabetic_prefix", sorted(members)))

    families.sort(key=lambda item: (item[0], item[1]))
    return families


def _normalize_identity_lines(raw_bytes: bytes) -> list[bytes]:
    """Decode identity/memory text, split into lines/sentences, normalize whitespace & case, and hash each."""
    text = raw_bytes.decode("utf-8", errors="replace").replace("\x00", "")
    raw_lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(raw_lines) == 1:
        # Single-line prose: split on sentence boundaries if present
        segments = [s.strip() for s in re.split(r"(?<=[.!?])\s+", raw_lines[0]) if s.strip()]
    else:
        segments = raw_lines
    hashes: list[bytes] = []
    for seg in segments:
        norm = " ".join(seg.split()).casefold()
        if norm:
            hashes.append(hashlib.sha256(norm.encode("utf-8")).digest())
    return hashes


def _finding(
    rule_id: str,
    path: str | None,
    evidence: dict[str, Any],
    *,
    coverage: str = "verified",
    classification: str = "review_suggested",
) -> dict[str, Any]:
    # `path` is an existing absolute folder (kept as is by the report serializer) or None when the given root does
    # not exist as a real folder: a missing path would become a per-run token, so it is left out instead.
    return make_finding(
        rule_id=rule_id,
        classification=classification,
        coverage=coverage,
        affected_identities=[path] if path else [],
        source_paths=[path] if path else [],
        evidence=evidence,
        consequence=FINDING_CONSEQUENCES[rule_id],
    )


def _envelope(
    findings: list[dict[str, Any]], coverage: str, section: dict[str, Any], metrics: dict[str, Any]
) -> dict[str, Any]:
    """The wiring envelope: exactly section, findings, run_metrics, status and coverage.

    `run_metrics` holds the only run-dependent values and must be stored outside the fingerprinted report.
    """
    env = make_component_envelope(findings=findings, coverage=coverage)
    return {
        "profile_duplicates": section,
        "findings": env["findings"],
        "run_metrics": metrics,
        "status": env["status"],
        "coverage": env["coverage"],
    }


def _shared_line_share(pname: str, lhashes: list[bytes], n_other: int, line_sets_by_prof: dict[str, set[bytes]]) -> float:
    if not lhashes or n_other <= 0:
        return 0.0
    shared_count = 0
    for lh in lhashes:
        other_occurrences = sum(
            1 for other_p, other_set in line_sets_by_prof.items()
            if other_p != pname and lh in other_set
        )
        if other_occurrences * 2 >= n_other:
            shared_count += 1
    return round(shared_count / len(lhashes), 4)


def _summarize_identity_files(
    identity_raw_by_kind: dict[str, list[tuple[str, bytes, list[bytes]]]],
    profile_folder: Callable[[str], str | None],
) -> dict[str, Any]:
    """Summarize exact and line-level identity similarity across profiles."""
    identical_profiles_union: set[str] = set()
    by_kind_summary: dict[str, dict[str, Any]] = {}
    all_file_shares: list[float] = []
    per_profile_max_share: dict[str, float] = defaultdict(float)
    identity_file_rows: list[dict[str, Any]] = []

    for kind in ("SOUL.md", "MEMORY.md", "USER.md"):
        entries_k = identity_raw_by_kind[kind]
        by_fdigest: dict[bytes, list[str]] = defaultdict(list)
        for pname, fdigest, _ in entries_k:
            by_fdigest[fdigest].append(pname)

        group_sizes = sorted((len(profs) for profs in by_fdigest.values() if len(profs) >= 2), reverse=True)
        counts_for_finding = kind in CLONED_IDENTITY_FINDING_KINDS
        if counts_for_finding:
            for profs in by_fdigest.values():
                if len(profs) >= 2:
                    identical_profiles_union.update(profs)

        # Near-clones: for each file of this kind, share of its lines that also appear in >= half of the other profiles
        n_other = len(entries_k) - 1
        line_sets_by_prof = {pname: set(lhashes) for pname, _, lhashes in entries_k}
        kind_shares: list[float] = []
        for pname, _, lhashes in entries_k:
            share = _shared_line_share(pname, lhashes, n_other, line_sets_by_prof)
            kind_shares.append(share)
            if counts_for_finding:
                all_file_shares.append(share)
                if share > per_profile_max_share[pname]:
                    per_profile_max_share[pname] = share
            identity_file_rows.append({
                "path": profile_folder(pname),
                "file": kind,
                "line_count": len(lhashes),
                "shared_line_share": share,
            })

        by_kind_summary[kind] = {
            "profiles_with_file": len(entries_k),
            "identical_group_sizes": group_sizes,
            "identical_profiles_count": sum(group_sizes),
            "median_shared_line_share": round(float(median(kind_shares)), 4) if kind_shares else 0.0,
            "max_shared_line_share": round(float(max(kind_shares)), 4) if kind_shares else 0.0,
        }

    overall_median_share = round(float(median(all_file_shares)), 4) if all_file_shares else 0.0
    overall_max_share = round(float(max(all_file_shares)), 4) if all_file_shares else 0.0
    profiles_above_50pct = sum(
        1 for share in per_profile_max_share.values()
        if share > CLONED_IDENTITY_SHARED_LINE_THRESHOLD
    )
    identical_profiles_count = len(identical_profiles_union)

    return {
        "identical_profiles_count": identical_profiles_count,
        "median_shared_line_share": overall_median_share,
        "max_shared_line_share": overall_max_share,
        "profiles_above_50pct": profiles_above_50pct,
        "by_kind": by_kind_summary,
        "files_count": len(identity_file_rows),
        "files": [row for row in identity_file_rows if row["path"] is not None][:MAX_IDENTITY_ROWS_LISTED],
    }


def _profile_families_section(profile_rows: list[dict[str, Any]], folder_paths: Callable[[list[str]], list[str]]) -> dict[str, Any]:
    # Families are computed from safe names only, so a label never carries an unsafe name's characters.
    families = _compute_profile_families([r["name"] for r in profile_rows if _is_safe_name(r["name"])])
    return {
        "family_count": len(families),
        "families": [
            {"kind": kind, "member_count": len(members), "paths": folder_paths(members)}
            for kind, members in families[:MAX_NAMES_LISTED]
        ],
    }


def audit_profile_duplicates(
    profile_path: Path | str,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Measure duplicated binaries, files, caches, and identity/memory templates across profiles."""
    start_time = clock()
    deadline = start_time + MAX_SECONDS

    def run_metrics() -> dict[str, Any]:
        # The only wall-clock-derived values; everything outside `run_metrics` is a function of the home's bytes.
        return {"elapsed_ms": int(max(0.0, (clock() - start_time) * 1000.0))}
    root = Path(os.path.abspath(os.path.expanduser(os.fspath(profile_path))))

    limits: dict[str, Any] = {
        "max_entries": MAX_ENTRIES,
        "max_bytes_hashed": MAX_BYTES_HASHED,
        "max_files_hashed": MAX_FILES_HASHED,
        "max_seconds": MAX_SECONDS,
        "max_depth": MAX_DEPTH,
        "max_identity_file_bytes": MAX_IDENTITY_FILE_BYTES,
        "max_identity_files": MAX_IDENTITY_FILES,
        "entries_walked": 0,
        "files_hashed": 0,
        "bytes_hashed": 0,
        "identity_files_read": 0,
        "max_names_listed": MAX_NAMES_LISTED,
        "cuts": 0,
    }
    truncated_by: str | None = None
    cut_reasons: set[str] = set()
    stopped: set[str] = set()

    def record_cut(reason: str) -> None:
        nonlocal truncated_by
        limits["cuts"] += 1
        cut_reasons.add(reason)
        if reason in _STOP_REASONS:
            stopped.add(reason)
            if truncated_by is None or truncated_by not in _STOP_REASONS:
                truncated_by = reason
        elif truncated_by is None:
            truncated_by = reason

    def check_expired() -> bool:
        if "time_budget" in stopped:
            return True
        if clock() >= deadline:
            record_cut("time_budget")
            return True
        return False

    def hashing_stopped() -> bool:
        return bool(stopped & {"files_hashed_limit", "bytes_hashed_limit", "entries_limit"}) or check_expired()

    def not_measured(reason: str, identity: str | None = None) -> dict[str, Any]:
        finding = _finding(
            "profile_duplicates.could_not_verify",
            identity,
            {"cuts": 1, "reason": reason},
            coverage="could_not_verify",
            classification="info",
        )
        section = {
            "status": "not_measured",
            "coverage": "could_not_verify",
            "reason": reason,
            "truncated_by": None,
            "cut_reasons": [],
            "limits": {**limits, "cuts": 1},
        }
        return _envelope([finding], "could_not_verify", section, run_metrics())

    try:
        st_root = os.lstat(root)
    except FileNotFoundError:
        return not_measured("missing_profile_root")
    except OSError:
        return not_measured("unreadable_profile_root")

    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        return not_measured("invalid_profile_root")

    # Every emitted path is built from the resolved root, so the report serializer (which resolves paths) returns
    # each one unchanged. Nothing below the root is followed through a symlink.
    root = Path(os.path.realpath(root))
    profiles_dir = root / "profiles"
    if not os.path.lexists(profiles_dir) and root.parent.name == "profiles":
        # A named profile (`<home>/profiles/<name>`) was given instead of the Hermes home root: reporting
        # "0 profiles" would be wrong, so the section says it was not measured.
        return not_measured("named_profile_given", str(root))
    profile_dirs: list[Path] = []
    if os.path.lexists(profiles_dir):
        try:
            st_pdir = os.lstat(profiles_dir)
            if stat.S_ISLNK(st_pdir.st_mode) or not stat.S_ISDIR(st_pdir.st_mode):
                record_cut("symlink_or_non_dir_profiles_root")
            elif credential_path(profiles_dir):
                # The whole tree is classified credential-bearing (e.g. it sits below a `backups/` folder):
                # nothing below it is walked, and that is reported instead of an empty, clean result.
                record_cut("credential_root_refused")
            else:
                with os.scandir(profiles_dir) as it:
                    entries = sorted(it, key=lambda e: e.name)
                for entry in entries:
                    if check_expired():
                        break
                    if _has_surrogate(entry.name):
                        record_cut("invalid_encoding")
                        continue
                    # Hidden directories under profiles/ (.deleted tombstones, .staging-*) are internal markers.
                    if entry.name.startswith("."):
                        continue
                    limits["entries_walked"] += 1
                    if limits["entries_walked"] > MAX_ENTRIES:
                        record_cut("entries_limit")
                        break
                    try:
                        if entry.is_symlink():
                            record_cut("symlink_refused")
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            profile_dirs.append(Path(entry.path))
                        else:
                            record_cut("non_directory_profile_entry")
                    except OSError:
                        record_cut("stat_error")
        except OSError:
            record_cut("unreadable_profiles_dir")

    def profile_folder(pname: str) -> str | None:
        """Absolute path of an existing profile folder, or None for a name that is never listed."""
        return str(profiles_dir / pname) if _is_safe_name(pname) else None

    def folder_paths(names: list[str]) -> list[str]:
        return [p for p in (profile_folder(n) for n in names) if p is not None][:MAX_NAMES_LISTED]

    def _group_location(grouped: list[tuple[str, str, bool]]) -> str | None:
        """Where the copies live: the first-level folder inside the first member profile (sorted), or that profile
        folder for a file in its root; never deeper. Members with an unsafe profile or folder name are skipped."""
        for pname, rel_posix, _ in grouped:
            if not _is_safe_name(pname):
                continue
            parts = PurePosixPath(rel_posix).parts
            if len(parts) == 1:
                return str(profiles_dir / pname)
            if _is_safe_name(parts[0]):
                return str(profiles_dir / pname / parts[0])
        return None

    # (a) Walk each profile directory using os.scandir(follow_symlinks=False) & lstat
    profile_rows: list[dict[str, Any]] = []
    empty_profiles: list[str] = []
    log_only_profiles: list[str] = []
    no_config_profiles: list[str] = []
    profiles_total_bytes = 0
    profiles_total_files = 0

    # Candidate non-credential files for duplicate hashing: (prof_name, rel_posix, path, size)
    hash_candidates: list[tuple[str, str, Path, int]] = []
    # Credential / config.yaml size-only observations: (class, suffixed copy, at profile root, size) -> profile dirs
    cred_size_groups: dict[tuple[str, bool, bool, int], set[str]] = defaultdict(set)

    # (d) Per-profile cache accumulators
    hub_index_cache_bytes = 0
    models_dev_cache_bytes = 0
    provider_models_cache_bytes = 0
    profiles_with_caches: set[str] = set()
    hub_cache_profiles: set[str] = set()
    models_dev_cache_profiles: set[str] = set()
    provider_models_cache_profiles: set[str] = set()

    unsafe_profile_name_count = 0
    skipped_credential_dirs = 0
    for pdir in profile_dirs:
        if check_expired() or "entries_limit" in stopped:
            break
        pname = pdir.name  # internal only: the output names a profile by its folder path, and only if it is safe
        if not _is_safe_name(pname):
            unsafe_profile_name_count += 1
        file_count = 0
        size_bytes = 0
        has_config = False
        all_files_are_logs = True
        had_non_regular = False
        walk_incomplete = False  # an unreadable/too-deep directory: emptiness cannot be claimed

        stack: list[tuple[Path, int]] = [(pdir, 0)]
        while stack:
            if check_expired():
                break
            cur_dir, depth = stack.pop()
            if depth > MAX_DEPTH:
                record_cut("depth_limit")
                walk_incomplete = True
                continue
            try:
                if _has_symlink_below(cur_dir, root):
                    record_cut("symlink_refused")
                    continue
                with os.scandir(cur_dir) as it:
                    batch = sorted(it, key=lambda e: e.name)
            except OSError:
                record_cut("unreadable_directory")
                walk_incomplete = True
                continue

            for entry in batch:
                if check_expired():
                    break
                if _has_surrogate(entry.name):
                    record_cut("invalid_encoding")
                    continue
                limits["entries_walked"] += 1
                if limits["entries_walked"] > MAX_ENTRIES:
                    record_cut("entries_limit")
                    stack.clear()
                    break

                epath = Path(entry.path)
                rel_posix = epath.relative_to(pdir).as_posix()
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    record_cut("stat_error")
                    continue

                if stat.S_ISLNK(st.st_mode):
                    had_non_regular = True
                    record_cut("symlink_refused")
                    continue

                is_cred = credential_path(epath)
                if stat.S_ISDIR(st.st_mode):
                    if is_cred:
                        # Never traverse credential directories (mcp-tokens/, vault/, pairing/, etc.); the skip is
                        # counted so the report shows that these folders exist and were not measured.
                        skipped_credential_dirs += 1
                        continue
                    stack.append((epath, depth + 1))
                    continue

                if not stat.S_ISREG(st.st_mode):
                    had_non_regular = True
                    record_cut("special_file_refused")
                    continue

                fsize = int(st.st_size)
                file_count += 1
                size_bytes += fsize

                if rel_posix == "config.yaml":
                    has_config = True
                if not (rel_posix.startswith("logs/") or rel_posix.endswith(".log")):
                    all_files_are_logs = False

                cache_kind = _classify_cache_rel(rel_posix)
                if cache_kind is not None and fsize > 0:
                    profiles_with_caches.add(pdir.name)
                    if cache_kind == "hub_index_cache":
                        hub_index_cache_bytes += fsize
                        hub_cache_profiles.add(pdir.name)
                    elif cache_kind == "models_dev_cache":
                        models_dev_cache_bytes += fsize
                        models_dev_cache_profiles.add(pdir.name)
                    elif cache_kind == "provider_models_cache":
                        provider_models_cache_bytes += fsize
                        provider_models_cache_profiles.add(pdir.name)

                if is_cred or _size_only_name(entry.name):
                    # NEVER open or hash credential files or config.yaml; record lstat size-only observation.
                    if fsize > 0:
                        size_class, suffixed = _size_only_class(entry.name)
                        cred_size_groups[(size_class, suffixed, "/" not in rel_posix, fsize)].add(pdir.name)
                    continue

                if _is_eligible_for_hash(entry.name, fsize):
                    hash_candidates.append((pdir.name, rel_posix, epath, fsize))

        if stack or "time_budget" in stopped or "entries_limit" in stopped:
            walk_incomplete = True
        is_empty = file_count == 0 and not had_non_regular and not walk_incomplete
        is_logs_only = file_count > 0 and all_files_are_logs and not walk_incomplete
        if is_empty:
            empty_profiles.append(pname)
        if is_logs_only:
            log_only_profiles.append(pname)
        if not has_config and not walk_incomplete:
            no_config_profiles.append(pname)

        profiles_total_bytes += size_bytes
        profiles_total_files += file_count
        profile_rows.append({
            "name": pname,
            "file_count": file_count,
            "size_bytes": size_bytes,
            "empty": is_empty,
            "logs_only": is_logs_only,
            "has_config": has_config,
        })

    profile_count = len(profile_rows)

    # Check matching relative paths in the main home (for main-home-to-profile duplicate detection)
    # without scanning unrelated trees or opening credentials.
    main_candidates_by_size: dict[int, list[tuple[str, Path]]] = defaultdict(list)
    seen_main_rels: set[str] = set()
    for _, rel_posix, _, fsize in hash_candidates:
        if rel_posix in seen_main_rels:
            continue
        seen_main_rels.add(rel_posix)
        main_path = root.joinpath(*PurePosixPath(rel_posix).parts)
        try:
            if credential_path(main_path) or _size_only_name(main_path.name) or _has_symlink_below(main_path, root):
                continue
            st_main = os.lstat(main_path)
            if stat.S_ISREG(st_main.st_mode) and int(st_main.st_size) == fsize:
                main_candidates_by_size[fsize].append((rel_posix, main_path))
        except OSError:
            continue

    def stream_hash_file(path: Path, expected_size: int) -> tuple[str | None, bool]:
        """Read `path` with O_NOFOLLOW in 1 MiB chunks, enforcing file/byte/time caps."""
        if check_expired():
            return None, False
        if credential_path(path) or _size_only_name(path.name) or _has_symlink_below(path, root):
            record_cut("unsafe_or_symlink_path")
            return None, False
        if limits["files_hashed"] >= MAX_FILES_HASHED:
            record_cut("files_hashed_limit")
            return None, False
        if limits["bytes_hashed"] + expected_size > MAX_BYTES_HASHED:
            record_cut("bytes_hashed_limit")
            return None, False

        try:
            st_pre = os.lstat(path)
            if not stat.S_ISREG(st_pre.st_mode) or stat.S_ISLNK(st_pre.st_mode):
                record_cut("non_regular_file")
                return None, False
            fd = _open_for_read(path)
        except CredentialStoreNotOpened:
            record_cut("unsafe_or_symlink_path")
            return None, False
        except OSError:
            record_cut("read_error")
            return None, False

        hasher = hashlib.sha256()
        head = b""
        read_bytes = 0
        try:
            st_open = os.fstat(fd)
            if not stat.S_ISREG(st_open.st_mode) or (st_open.st_dev, st_open.st_ino) != (st_pre.st_dev, st_pre.st_ino):
                record_cut("inode_changed")
                return None, False
            while True:
                if check_expired():
                    return None, False
                chunk = os.read(fd, HASH_CHUNK_BYTES)
                if not chunk:
                    break
                if not head:
                    head = chunk[:8]
                read_bytes += len(chunk)
                if limits["bytes_hashed"] + read_bytes > MAX_BYTES_HASHED:
                    limits["bytes_hashed"] += read_bytes
                    record_cut("bytes_hashed_limit")
                    return None, False
                hasher.update(chunk)
        except OSError:
            record_cut("read_error")
            return None, False
        finally:
            with suppress(OSError):
                os.close(fd)

        limits["files_hashed"] += 1
        limits["bytes_hashed"] += read_bytes
        return hasher.hexdigest(), _is_executable_magic(head)

    # (b) Group candidates by size first; only hash sizes that occur in 2+ profiles (or profile + main home)
    by_size: dict[int, list[tuple[str, str, Path, int]]] = defaultdict(list)
    for item in hash_candidates:
        by_size[item[3]].append(item)

    # Sort sizes descending so large binaries/caches are hashed first
    duplicate_groups: list[dict[str, Any]] = []
    repeated_binary_groups: list[dict[str, Any]] = []

    for fsize in sorted(by_size.keys(), reverse=True):
        if hashing_stopped():
            break
        items = by_size[fsize]
        distinct_profs = {it[0] for it in items}
        main_matches = main_candidates_by_size.get(fsize, [])
        if len(distinct_profs) < 2 and not main_matches:
            continue

        # Hash profile items of this size
        by_digest: dict[str, list[tuple[str, str, bool]]] = defaultdict(list)
        for pname, rel_posix, epath, sz in items:
            digest, is_exec = stream_hash_file(epath, sz)
            if digest is None:
                if hashing_stopped():
                    break
                continue  # One unreadable file does not end the size bucket.
            by_digest[digest].append((pname, rel_posix, is_exec))

        # Hash matching main-home files of this size
        main_digests: set[str] = set()
        for _rel_posix, mpath in main_matches:
            if hashing_stopped():
                break
            mdigest, _ = stream_hash_file(mpath, fsize)
            if mdigest is not None:
                main_digests.add(mdigest)

        for digest, grouped in by_digest.items():
            grp_profs = {g[0] for g in grouped}
            in_main = digest in main_digests
            if len(grp_profs) >= 2:
                copies = len(grouped)
                profile_copies = len(grouped)
            elif len(grp_profs) == 1 and in_main and profile_count >= MIN_PROFILES_FOR_FINDINGS:
                copies = 2
                profile_copies = 1
            else:
                continue

            grouped.sort(key=lambda g: (g[0], g[1]))
            is_exec = grouped[0][2]
            file_kind = _file_kind(grouped[0][1], is_exec)
            # Do not flag or group bundled stock SKILL.md when there are fewer than 3 profiles
            if profile_count < MIN_PROFILES_FOR_FINDINGS and file_kind == "skill_md":
                continue

            wasted = (copies - 1) * fsize
            # Regenerable cache copies are reported under per_profile_caches and do not drive identical_files.
            is_cache_group = all(_classify_cache_rel(g[1]) is not None for g in grouped)
            group_row = {
                "location": _group_location(grouped),
                "file_kind": file_kind,
                "copies": copies,
                "profile_copies": profile_copies,
                "distinct_profiles": len(grp_profs),
                "in_main_home": in_main,
                "size_bytes": fsize,
                "wasted_bytes": wasted,
                "executable_magic": is_exec,
                "regenerable_cache": is_cache_group,
            }
            duplicate_groups.append(group_row)
            if (
                is_exec
                and fsize >= MIN_REPEATED_BINARY_BYTES
                and len(grp_profs) >= MIN_REPEATED_BINARY_PROFILES
            ):
                repeated_binary_groups.append(group_row)

    duplicate_groups.sort(
        key=lambda g: (-g["wasted_bytes"], -g["copies"], g["location"] or "", g["file_kind"], -g["size_bytes"])
    )
    top_duplicate_groups = duplicate_groups[:TOP_DUPLICATE_GROUPS]
    total_wasted_bytes = sum(g["wasted_bytes"] for g in duplicate_groups)
    wasted_bytes_including_main_home = sum(
        g["wasted_bytes"] + (g["size_bytes"] if g["in_main_home"] and g["profile_copies"] >= 2 else 0)
        for g in duplicate_groups
    )
    cache_duplicate_wasted_bytes = sum(g["wasted_bytes"] for g in duplicate_groups if g["regenerable_cache"])
    wasted_bytes_excluding_caches = total_wasted_bytes - cache_duplicate_wasted_bytes
    wasted_share = (
        round(total_wasted_bytes / profiles_total_bytes, 6)
        if profiles_total_bytes > 0
        else 0.0
    )

    skill_md_groups = [g for g in duplicate_groups if g["file_kind"] == "skill_md"]
    skill_md_duplicate_groups = len(skill_md_groups)
    skill_md_duplicate_copies = sum(g["copies"] for g in skill_md_groups)

    # Credential size-only observations (never opened or hashed)
    # Rows carry a class label and counts only: never a file name or a path to a credential-named file.
    credential_same_size_rows: list[dict[str, Any]] = []
    for (size_class, suffixed, at_root, fsize), pset in sorted(
        cred_size_groups.items(), key=lambda kv: (-len(kv[1]), kv[0][0], kv[0][1], kv[0][2], -kv[0][3])
    ):
        if len(pset) >= 2:
            cnt = len(pset)
            credential_same_size_rows.append({
                "file_kind": size_class,
                "suffixed_copy": suffixed,
                "at_profile_root": at_root,
                "profiles_count": cnt,
                "size_bytes": fsize,
                "hashed": False,
                "observation": SIZE_ONLY_OBSERVATION,
            })

    # (c) Cloned identity and memory files (SOUL.md, MEMORY.md, USER.md)
    # Read with O_NOFOLLOW, cap 256 KiB each, at most 200 files.
    identity_raw_by_kind: dict[str, list[tuple[str, bytes, list[bytes]]]] = {
        "SOUL.md": [],
        "MEMORY.md": [],
        "USER.md": [],
    }
    for pdir in profile_dirs:
        if check_expired():
            break
        pname = pdir.name  # internal key only; output rows use the safe display name
        for kind, rel_candidates in IDENTITY_KIND_CANDIDATES:
            chosen_path: Path | None = None
            for rel_cand in rel_candidates:
                cand = pdir.joinpath(*PurePosixPath(rel_cand).parts)
                if os.path.lexists(cand):
                    chosen_path = cand
                    break
            if chosen_path is None:
                continue
            if credential_path(chosen_path) or _has_symlink_below(chosen_path, root):
                record_cut("symlink_refused")
                continue
            try:
                st_id = os.lstat(chosen_path)
            except OSError:
                record_cut("stat_error")
                continue
            if stat.S_ISLNK(st_id.st_mode):
                record_cut("symlink_refused")
                continue
            if not stat.S_ISREG(st_id.st_mode):
                record_cut("non_regular_file")
                continue
            if st_id.st_size == 0:
                continue
            if st_id.st_size > MAX_IDENTITY_FILE_BYTES:
                record_cut("identity_file_bytes_limit")
                continue
            if limits["identity_files_read"] >= MAX_IDENTITY_FILES:
                record_cut("identity_files_limit")
                break

            try:
                fd = _open_for_read(chosen_path)
                try:
                    raw = os.read(fd, MAX_IDENTITY_FILE_BYTES + 1)
                finally:
                    with suppress(OSError):
                        os.close(fd)
            except CredentialStoreNotOpened:
                record_cut("symlink_refused")
                continue
            except OSError:
                record_cut("read_error")
                continue
            if len(raw) > MAX_IDENTITY_FILE_BYTES:
                record_cut("identity_file_bytes_limit")
                continue

            limits["identity_files_read"] += 1
            file_digest = hashlib.sha256(raw).digest()
            line_hashes = _normalize_identity_lines(raw)
            identity_raw_by_kind[kind].append((pname, file_digest, line_hashes))

    cloned_identity_section = _summarize_identity_files(identity_raw_by_kind, profile_folder)
    identical_profiles_count = cloned_identity_section["identical_profiles_count"]
    overall_median_share = cloned_identity_section["median_shared_line_share"]
    overall_max_share = cloned_identity_section["max_shared_line_share"]
    profiles_above_50pct = cloned_identity_section["profiles_above_50pct"]

    # (d) Per-profile caches summary
    total_cache_bytes = hub_index_cache_bytes + models_dev_cache_bytes + provider_models_cache_bytes
    per_profile_caches_section = {
        "total_bytes": total_cache_bytes,
        "hub_index_cache_bytes": hub_index_cache_bytes,
        "hub_index_cache_profiles": len(hub_cache_profiles),
        "models_dev_cache_bytes": models_dev_cache_bytes,
        "models_dev_cache_profiles": len(models_dev_cache_profiles),
        "provider_models_cache_bytes": provider_models_cache_bytes,
        "provider_models_cache_profiles": len(provider_models_cache_profiles),
        "profiles_with_caches": len(profiles_with_caches),
    }

    # (e) Profile families
    profile_families_section = _profile_families_section(profile_rows, folder_paths)

    # Findings evaluation (DO NOT FLAG homes with < 3 profiles)
    findings: list[dict[str, Any]] = []
    # Findings name the measured folder by its absolute path, like the other report sections (the report's path
    # rule keeps an existing absolute path as is); the section itself carries no path at all.
    target_path = str(profiles_dir) if profile_count > 0 else str(root)
    listed_profiles = [
        {"path": profile_folder(row["name"]), **{k: v for k, v in row.items() if k != "name"}}
        for row in profile_rows
        if _is_safe_name(row["name"])
    ][:MAX_NAMES_LISTED]

    if profile_count >= MIN_PROFILES_FOR_FINDINGS:
        if repeated_binary_groups:
            total_bin_copies = sum(g["copies"] for g in repeated_binary_groups)
            total_bin_wasted = sum(g["wasted_bytes"] for g in repeated_binary_groups)
            findings.append(_finding(
                "profile_duplicates.repeated_binary",
                target_path,
                {
                    "groups": len(repeated_binary_groups),
                    "copies": total_bin_copies,
                    "wasted_bytes": total_bin_wasted,
                    "bytes_wasted": total_bin_wasted,
                },
                classification="review_suggested",
            ))

        if wasted_bytes_excluding_caches > IDENTICAL_FILES_WASTED_BYTES_THRESHOLD:
            findings.append(_finding(
                "profile_duplicates.identical_files",
                target_path,
                {
                    "duplicate_groups": len(duplicate_groups),
                    "wasted_bytes": total_wasted_bytes,
                    "bytes_wasted": total_wasted_bytes,
                    "wasted_bytes_excluding_caches": wasted_bytes_excluding_caches,
                    "cache_duplicate_wasted_bytes": cache_duplicate_wasted_bytes,
                    "profiles_total_bytes": profiles_total_bytes,
                    "wasted_share": wasted_share,
                },
                classification="review_suggested",
            ))

        if (
            identical_profiles_count >= CLONED_IDENTITY_MIN_PROFILES
            or overall_median_share > CLONED_IDENTITY_SHARED_LINE_THRESHOLD
        ):
            affected_count = max(identical_profiles_count, profiles_above_50pct)
            findings.append(_finding(
                "profile_duplicates.cloned_identity_files",
                target_path,
                {
                    "affected_profiles": affected_count,
                    "identical_profiles": identical_profiles_count,
                    "profiles_above_50pct": profiles_above_50pct,
                    "median_shared_line_share": overall_median_share,
                    "max_shared_line_share": overall_max_share,
                },
                classification="review_suggested",
            ))

        if total_cache_bytes > PER_PROFILE_CACHE_BYTES_THRESHOLD:
            findings.append(_finding(
                "profile_duplicates.per_profile_caches",
                target_path,
                {
                    "total_bytes": total_cache_bytes,
                    "hub_index_cache_bytes": hub_index_cache_bytes,
                    "models_dev_cache_bytes": models_dev_cache_bytes,
                    "provider_models_cache_bytes": provider_models_cache_bytes,
                    "profiles_with_caches": len(profiles_with_caches),
                },
                classification="info",
            ))

        total_empty_or_log = len(empty_profiles) + len(log_only_profiles)
        if total_empty_or_log >= MIN_EMPTY_OR_LOG_ONLY_PROFILES:
            findings.append(_finding(
                "profile_duplicates.empty_profiles",
                target_path,
                {
                    "empty_profiles": len(empty_profiles),
                    "log_only_profiles": len(log_only_profiles),
                    "no_config_profiles": len(no_config_profiles),
                    "total_empty_or_log_only": total_empty_or_log,
                },
                classification="info",
            ))

    coverage = "could_not_verify" if limits["cuts"] > 0 else "verified"
    if coverage == "could_not_verify":
        findings.append(_finding(
            "profile_duplicates.could_not_verify",
            target_path,
            {
                "cuts": limits["cuts"],
                "truncated_by": truncated_by or "cut_or_exclusion",
                "reason": truncated_by or "cut_or_exclusion",
            },
            coverage="could_not_verify",
            classification="info",
        ))

    section: dict[str, Any] = {
        "status": "completed",
        "coverage": coverage,
        "truncated_by": truncated_by,
        "cut_reasons": sorted(cut_reasons),
        "profile_count": profile_count,
        "unsafe_profile_name_count": unsafe_profile_name_count,
        "skipped_credential_dirs": skipped_credential_dirs,
        "profiles_total_bytes": profiles_total_bytes,
        "profiles_total_files": profiles_total_files,
        "profiles": listed_profiles,
        "empty_profiles": {"count": len(empty_profiles), "paths": folder_paths(empty_profiles)},
        "log_only_profiles": {"count": len(log_only_profiles), "paths": folder_paths(log_only_profiles)},
        "no_config_profiles": {"count": len(no_config_profiles), "paths": folder_paths(no_config_profiles)},
        "duplicate_group_count": len(duplicate_groups),
        "top_duplicate_groups": top_duplicate_groups,
        "skill_md_duplicate_groups": skill_md_duplicate_groups,
        "skill_md_duplicate_copies": skill_md_duplicate_copies,
        "total_wasted_bytes": total_wasted_bytes,
        "wasted_bytes_including_main_home": wasted_bytes_including_main_home,
        "cache_duplicate_wasted_bytes": cache_duplicate_wasted_bytes,
        "wasted_bytes_excluding_caches": wasted_bytes_excluding_caches,
        "wasted_share_of_profiles": wasted_share,
        "credential_same_size_groups": credential_same_size_rows,
        "cloned_identity": cloned_identity_section,
        "per_profile_caches": per_profile_caches_section,
        "profile_families": profile_families_section,
        "limits": limits,
        "thresholds": {
            "min_profiles_for_findings": MIN_PROFILES_FOR_FINDINGS,
            "min_repeated_binary_bytes": MIN_REPEATED_BINARY_BYTES,
            "min_repeated_binary_profiles": MIN_REPEATED_BINARY_PROFILES,
            "identical_files_wasted_bytes": IDENTICAL_FILES_WASTED_BYTES_THRESHOLD,
            "cloned_identity_min_profiles": CLONED_IDENTITY_MIN_PROFILES,
            "cloned_identity_shared_line_share": CLONED_IDENTITY_SHARED_LINE_THRESHOLD,
            "per_profile_cache_bytes": PER_PROFILE_CACHE_BYTES_THRESHOLD,
            "min_empty_or_log_only_profiles": MIN_EMPTY_OR_LOG_ONLY_PROFILES,
            "min_family_prefix_len": MIN_FAMILY_PREFIX_LEN,
            "min_family_members": MIN_FAMILY_MEMBERS,
        },
    }
    return _envelope(findings, coverage, section, run_metrics())
