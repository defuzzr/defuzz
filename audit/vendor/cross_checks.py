# vendored module (origin: hermes_audit/cross_checks.py, from the author's audit toolkit; not published separately). Do not edit: change the origin and re-vendor.
"""System cross-checks audit component (100% Python stdlib, plain-data inputs).

Implements the 'System cross-checks' group from `hermes-adopt-audit-redesign.md` §5
(with §1, §2, §4, §6, §11, §12, §13 constraints):
- Nested repositories and `.git` worktree pointer files (`gitdir: ...`) without executing `git`.
  Nesting may be intentional: reports the isolation consequence (`info` / `review_suggested`)
  without declaring all nesting wrong. Broken worktree pointers and `.worktrees` nested inside
  another worktree or under a Hermes home are reported with their concrete consequence.
- Actual parent-context applicability along the real Hermes context-discovery chain
  (`.hermes.md` / `HERMES.md` -> `AGENTS.md` chain -> `CLAUDE.md` -> `.cursorrules`).
  Distinguishes when a parent repository's instructions actually inject into a nested project
  versus when they are shadowed or stopped by the child's own `.git` boundary.
- Cross-project symlinks and Python editable installs (`.pth` and `direct_url.json` static text
  supplied by the caller; never imported or executed).
- Memory -> project mapping overlap from caller-supplied plain data (`MemoryProjectMappingInput`),
  independent of `06c-profile`'s internal output shape.
- Exact duplicates with §5 distinctions:
  - Skill duplicates: byte-identical `SKILL.md` + supporting files + execution-relevant metadata
    (`platforms`, `environments`) -> cleanup-eligible (`proposed_cleanup_id`), vs
    whitespace-normalized matches -> `review_suggested` only, never cleanup-eligible.
  - Memory-entry duplicates across profiles: byte-identical entry text -> cleanup-eligible, vs
    whitespace-normalized matches -> `review_suggested` only.
  - Profile duplicates:
    - **Configuration match** (`memories/`, `skills/`, `config.yaml`, `SOUL.md` digest match) ->
      reported as `info` (`cross_checks.profile_configuration_match`), never as whole-profile
      exactness and never cleanup-eligible.
    - **Whole-profile exactness** (every owned region in the §12 ownership manifest matches
      byte-for-byte, including `sessions/` and `state.db`, with zero unreadable/excluded/special
      regions) -> feeds the archive-duplicate group action using the §13.5 survivor rule
      (active -> most recently used -> lexically first; never offer active, default, or
      `could_not_verify` last-use profiles; all candidates unticked by default).
  - Never follows external symlinks to claim identity.

Input TypedDicts (plain data produced by the caller):
```python
class MemoryProjectMappingInput(TypedDict, total=False):
    entry_id: str          # Stable identifier (e.g. "default:MEMORY.md:0")
    profile: str           # Owning profile name (optional if encoded in entry_id)
    file_path: str         # Source memory file path (optional)
    text: str              # Raw memory entry text
    paths: list[str]       # Referenced filesystem paths extracted by caller
    project_ids: list[str] # Mapped canonical project paths or IDs

class CrossChecksInput(TypedDict, total=False):
    coherent_manifest: dict[str, Any]         # Optional §4 coherent unit manifest status
    repos: list[dict[str, Any]]               # Discovered/registered repo descriptors
    parent_context_chains: list[dict[str, Any]]
    cross_links: list[dict[str, Any]]         # Symlink descriptors across projects/profiles
    editable_installs: list[dict[str, Any]]   # Static .pth / direct_url.json entries
    memory_mappings: list[MemoryProjectMappingInput]
    profile_units: list[dict[str, Any]]       # Profile unit facts / fingerprint manifests
    active_profile: str
```
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import urllib.parse
from typing import Any, Iterable, Mapping, Sequence, TypedDict

__all__ = [
    "COMPONENT_VERSION",
    "CrossChecksInput",
    "EMPTY_INPUT",
    "MemoryProjectMappingInput",
    "audit_cross_checks",
    "run",
]

COMPONENT_VERSION = "1.0.0"

CLASSIFICATION_WARNING = "warning"
CLASSIFICATION_REVIEW = "review_suggested"
CLASSIFICATION_INFO = "info"

COVERAGE_VERIFIED = "verified"
COVERAGE_COULD_NOT_VERIFY = "could_not_verify"
COVERAGE_NOT_INCLUDED = "not_included"

_CLASSIFICATION_RANK: dict[str, int] = {
    CLASSIFICATION_WARNING: 3,
    CLASSIFICATION_REVIEW: 2,
    CLASSIFICATION_INFO: 1,
}

_CLASSIFICATION_TO_LEGACY_SEVERITY: dict[str, str] = {
    CLASSIFICATION_WARNING: "warn",
    CLASSIFICATION_REVIEW: "warn",
    CLASSIFICATION_INFO: "info",
}

_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret|auth[_-]?token|credential)s?(?:$|_)"
)

_FORBIDDEN_EVIDENCE_KEYS: frozenset[str] = frozenset({
    "cmd",
    "command",
    "commands",
    "script",
    "shell_cmd",
    "executable_fix",
    "fix_cmd",
    "fix_command",
    "fix_script",
    "argv",
})


class MemoryProjectMappingInput(TypedDict, total=False):
    """Plain-data memory-to-project mapping item produced by the caller."""

    entry_id: str
    profile: str
    file_path: str
    text: str
    paths: list[str]
    project_ids: list[str]


class CrossChecksInput(TypedDict, total=False):
    """Plain-data input dictionary for `audit_cross_checks` / `run`."""

    coherent_manifest: Mapping[str, Any]
    repos: Sequence[Mapping[str, Any]]
    parent_context_chains: Sequence[Mapping[str, Any]]
    cross_links: Sequence[Mapping[str, Any]]
    editable_installs: Sequence[Mapping[str, Any]]
    memory_mappings: Sequence[MemoryProjectMappingInput]
    profile_units: Sequence[Mapping[str, Any]]
    active_profile: str


EMPTY_INPUT: dict[str, Any] = {
    "repos": [],
    "parent_context_chains": [],
    "cross_links": [],
    "editable_installs": [],
    "memory_mappings": [],
    "profile_units": [],
    "active_profile": "default",
}


def _as_seq(val: Any) -> Sequence[Any]:
    if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
        return val
    return ()


def _as_map(val: Any) -> Mapping[str, Any]:
    if isinstance(val, Mapping):
        return val
    return {}


def _norm_posix_path(raw: Any) -> str:
    """Normalize a path string lexically without touching the host filesystem."""
    s = str(raw or "").strip().replace("\\", "/")
    if not s:
        return ""
    is_unc = s.startswith("//") and not s.startswith("///")
    normed = posixpath.normpath(s)
    if is_unc and not normed.startswith("//"):
        normed = "/" + normed
    return normed.rstrip("/") if len(normed) > 1 else normed


def _is_strict_subpath(child: str, parent: str) -> bool:
    c = _norm_posix_path(child)
    p = _norm_posix_path(parent)
    if not c or not p or c == p:
        return False
    if p == "/":
        return c.startswith("/") and c != "/"
    return c.startswith(p + "/")


def _is_same_or_subpath(target: str, root: str) -> bool:
    t = _norm_posix_path(target)
    r = _norm_posix_path(root)
    if not t or not r:
        return False
    return t == r or _is_strict_subpath(t, r)


def _resolve_relative_posix(base_dir: str, rel_or_abs: str) -> str:
    raw = str(rel_or_abs or "").strip().replace("\\", "/")
    if not raw:
        return ""
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        return _norm_posix_path(raw)
    base = _norm_posix_path(base_dir)
    if not base:
        return _norm_posix_path(raw)
    return _norm_posix_path(f"{base}/{raw}")


def _file_url_to_path(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    raw_path = urllib.parse.unquote(parsed.path or "")
    if re.match(r"^/[A-Za-z]:/", raw_path):
        raw_path = raw_path[1:]
    return _norm_posix_path(raw_path)


def _sanitize_evidence(value: Any, *, _key_hint: str = "") -> Any:
    if callable(value):
        raise ValueError("Callable objects are forbidden in audit finding evidence")
    if _key_hint and _key_hint.lower() in _FORBIDDEN_EVIDENCE_KEYS:
        raise ValueError(f"Executable fix field {_key_hint!r} is forbidden inside finding evidence")
    if _key_hint and _SECRET_KEY_RE.search(_key_hint):
        return "<redacted>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in sorted(value.items(), key=lambda item: str(item[0])):
            k_str = str(k)
            if k_str.lower() in _FORBIDDEN_EVIDENCE_KEYS:
                raise ValueError(f"Executable fix field {k_str!r} is forbidden inside finding evidence")
            out[k_str] = _sanitize_evidence(v, _key_hint=k_str)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [_sanitize_evidence(item) for item in seq]
    return str(value)


def _normalize_source_paths(source_paths: Sequence[Mapping[str, Any] | str] | None) -> list[dict[str, Any]]:
    if not source_paths:
        return []
    out: list[dict[str, Any]] = []
    for entry in source_paths:
        if isinstance(entry, str):
            out.append({"path": entry, "start_line": None, "end_line": None})
        elif isinstance(entry, Mapping):
            p = str(entry.get("path") or "").strip()
            s_line = entry.get("start_line", entry.get("line"))
            e_line = entry.get("end_line", s_line)
            out.append({
                "path": p,
                "start_line": int(s_line) if isinstance(s_line, int) and s_line > 0 else None,
                "end_line": int(e_line) if isinstance(e_line, int) and e_line > 0 else None,
            })
        else:
            out.append({"path": str(entry), "start_line": None, "end_line": None})
    out.sort(
        key=lambda item: (
            item["path"],
            item["start_line"] if item["start_line"] is not None else -1,
            item["end_line"] if item["end_line"] is not None else -1,
        )
    )
    return out


def _make_finding(
    *,
    rule_id: str,
    classification: str,
    coverage: str = COVERAGE_VERIFIED,
    affected_identities: Sequence[str] = (),
    source_paths: Sequence[Mapping[str, Any] | str] = (),
    evidence: Mapping[str, Any] | None = None,
    consequence: str,
    limitations: str = "",
    proposed_cleanup_id: str | None = None,
    fix: str | None = None,
) -> dict[str, Any]:
    identities = sorted({str(x).strip() for x in affected_identities if str(x).strip()})
    paths = _normalize_source_paths(source_paths)
    clean_ev = _sanitize_evidence(dict(evidence) if evidence is not None else {})
    consequence_str = str(consequence).strip()
    limitations_str = str(limitations).strip()
    sev = _CLASSIFICATION_TO_LEGACY_SEVERITY.get(classification, "info")

    cleanup_id: str | None = None
    if proposed_cleanup_id is not None:
        cid = str(proposed_cleanup_id).strip()
        if cid:
            if any(ch in cid for ch in ("\n", "\r", ";", "|", "&", "`", "$(")):
                raise ValueError(f"Invalid proposed_cleanup_id: {proposed_cleanup_id!r}")
            cleanup_id = cid

    return {
        "id": str(rule_id).strip(),
        "classification": classification,
        "coverage": coverage,
        "affected_identities": identities,
        "source_paths": paths,
        "evidence": clean_ev,
        "consequence": consequence_str,
        "limitations": limitations_str,
        "proposed_cleanup_id": cleanup_id,
        "severity": sev,
        "detail": consequence_str,
        "fix": str(fix) if fix is not None else None,
    }


def _finding_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    cls_name = str(finding.get("classification") or CLASSIFICATION_INFO)
    rank = _CLASSIFICATION_RANK.get(cls_name, 0)
    identities = tuple(finding.get("affected_identities") or ())
    paths = tuple(
        (
            str(p.get("path") or ""),
            int(p["start_line"]) if isinstance(p.get("start_line"), int) else -1,
        )
        for p in (finding.get("source_paths") or ())
        if isinstance(p, Mapping)
    )
    return (
        -rank,
        str(finding.get("id") or ""),
        identities,
        paths,
        str(finding.get("consequence") or ""),
        str(finding.get("proposed_cleanup_id") or ""),
    )


def _parse_gitdir_pointer(git_file_content: str | None, explicit_target: str | None) -> str | None:
    if explicit_target is not None and str(explicit_target).strip():
        return str(explicit_target).strip()
    if not git_file_content:
        return None
    for raw_line in str(git_file_content).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("gitdir:"):
            target = line.split(":", 1)[1].strip()
            return target if target else None
        return None
    return None


def _derive_common_git_dir(repo_path: str, git_kind: str, resolved_gitdir: str | None) -> str | None:
    if git_kind == "git_dir":
        return _norm_posix_path(f"{repo_path}/.git")
    if not resolved_gitdir:
        return None
    norm = _norm_posix_path(resolved_gitdir)
    # Linked worktrees point to `<common_git_dir>/worktrees/<wt_name>`
    m_wt = re.match(r"^(.*?/\.git)/worktrees/[^/]+$", norm)
    if m_wt:
        return m_wt.group(1)
    # Submodules point to `<parent_git_dir>/modules/<sub_path>`
    return norm


def _is_submodule_gitdir(resolved_gitdir: str | None) -> bool:
    if not resolved_gitdir:
        return False
    parts = [p for p in _norm_posix_path(resolved_gitdir).split("/") if p]
    return "modules" in parts


def _check_nested_repos_and_worktrees(
    repos: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Inspect repo/worktree descriptors for nested repos and worktree pointer health without running git."""
    findings: list[dict[str, Any]] = []
    normalized_repos: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED

    for raw in repos:
        if not isinstance(raw, Mapping):
            continue
        rpath = _norm_posix_path(raw.get("path") or raw.get("canonical_path"))
        if not rpath:
            continue
        git_kind = str(raw.get("git_kind") or "git_dir").strip()
        raw_cov = str(raw.get("coverage") or COVERAGE_VERIFIED).strip()
        if raw_cov == COVERAGE_COULD_NOT_VERIFY or git_kind in ("unknown", "unreadable"):
            coverage = COVERAGE_COULD_NOT_VERIFY

        pointer_target = _parse_gitdir_pointer(
            raw.get("git_file_content") if isinstance(raw.get("git_file_content"), str) else None,
            raw.get("gitdir_target") if isinstance(raw.get("gitdir_target"), str) else None,
        )
        resolved_gitdir = (
            _resolve_relative_posix(rpath, pointer_target)
            if pointer_target is not None
            else None
        )
        common_git_dir = _derive_common_git_dir(rpath, git_kind, resolved_gitdir)
        is_submodule = bool(raw.get("is_submodule")) or _is_submodule_gitdir(resolved_gitdir)
        registered = bool(raw.get("registered", not raw.get("not_set_up_by_plugin", False)))
        target_exists = raw.get("gitdir_exists")
        if target_exists is not None:
            target_exists = bool(target_exists)

        entry = {
            "path": rpath,
            "git_kind": git_kind,
            "gitdir_target": pointer_target,
            "resolved_gitdir": resolved_gitdir,
            "common_git_dir": common_git_dir,
            "gitdir_exists": target_exists,
            "is_submodule": is_submodule,
            "registered": registered,
            "not_set_up_by_plugin": not registered,
            "coverage": raw_cov,
        }
        normalized_repos.append(entry)

        if git_kind == "symlink_git":
            coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="cross_checks.symlink_git_entry",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[rpath],
                    source_paths=[f"{rpath}/.git"],
                    evidence={
                        "git_kind": git_kind,
                        "gitdir_target": pointer_target,
                        "not_set_up_by_plugin": not registered,
                        "repo_path": rpath,
                    },
                    consequence=(
                        f"Repository {rpath} uses a symlinked .git entry; external symlink targets "
                        "are not followed during the static sweep."
                    ),
                    limitations="Static audit does not execute git or follow symlinked .git directories.",
                )
            )
        elif git_kind == "worktree_pointer":
            if not pointer_target:
                coverage = COVERAGE_COULD_NOT_VERIFY
                findings.append(
                    _make_finding(
                        rule_id="cross_checks.worktree_pointer_invalid",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_COULD_NOT_VERIFY,
                        affected_identities=[rpath],
                        source_paths=[f"{rpath}/.git"],
                        evidence={
                            "git_kind": git_kind,
                            "not_set_up_by_plugin": not registered,
                            "repo_path": rpath,
                        },
                        consequence=(
                            f"Worktree pointer file {rpath}/.git is missing a valid 'gitdir:' target, "
                            "leaving the checkout disconnected from its repository metadata."
                        ),
                        limitations="Inspected statically without running git.",
                    )
                )
            elif target_exists is False:
                findings.append(
                    _make_finding(
                        rule_id="cross_checks.worktree_pointer_broken",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[rpath],
                        source_paths=[f"{rpath}/.git"],
                        evidence={
                            "gitdir_target": pointer_target,
                            "not_set_up_by_plugin": not registered,
                            "repo_path": rpath,
                            "resolved_gitdir": resolved_gitdir,
                        },
                        consequence=(
                            f"Worktree pointer in {rpath}/.git points to missing gitdir {resolved_gitdir!r}; "
                            "git operations and worktree isolation in this directory will fail."
                        ),
                        limitations="Inspected statically without running git.",
                    )
                )

    normalized_repos.sort(key=lambda item: item["path"])

    # Detect nested repositories and nested worktrees
    for child in normalized_repos:
        cpath = child["path"]
        ancestors = [
            parent
            for parent in normalized_repos
            if _is_strict_subpath(cpath, parent["path"])
        ]
        if not ancestors:
            continue
        ancestors.sort(key=lambda item: len(item["path"]))
        nearest_parent = ancestors[-1]
        ppath = nearest_parent["path"]
        rel_inside = posixpath.relpath(cpath, ppath)
        rel_parts = [p for p in rel_inside.split("/") if p]

        # Standard `.worktrees/<name>` linked worktree belonging to its own parent repo
        is_in_worktrees_dir = ".worktrees" in rel_parts
        same_common = (
            child["common_git_dir"] is not None
            and nearest_parent["common_git_dir"] is not None
            and child["common_git_dir"] == nearest_parent["common_git_dir"]
        )

        # Grandchild worktree nested inside another worktree (`.worktrees/<a>/.worktrees/<b>`)
        worktree_segments = [p for p in cpath.split("/") if p == ".worktrees"]
        if len(worktree_segments) >= 2 or nearest_parent["git_kind"] == "worktree_pointer":
            findings.append(
                _make_finding(
                    rule_id="cross_checks.nested_worktree",
                    classification=CLASSIFICATION_WARNING,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[cpath, ppath],
                    source_paths=[f"{cpath}/.git", f"{ppath}/.git"],
                    evidence={
                        "child_git_kind": child["git_kind"],
                        "child_not_set_up_by_plugin": child["not_set_up_by_plugin"],
                        "child_repo": cpath,
                        "parent_repo": ppath,
                        "relative_path": rel_inside,
                    },
                    consequence=(
                        f"Worktree or repository {cpath} is nested inside worktree {ppath}; "
                        "subagent worktree cleanup or resets on the outer worktree can clobber inner work."
                    ),
                    limitations="Detected from .git directory/pointer layout without running git.",
                )
            )
            continue

        # Standard `<repo>/.worktrees/<wt>` linked to `<repo>/.git` is normal isolated worktree placement
        if (
            is_in_worktrees_dir
            and rel_parts[0] == ".worktrees"
            and child["git_kind"] == "worktree_pointer"
            and same_common
        ):
            continue

        if child["is_submodule"]:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.nested_repo",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[cpath, ppath],
                    source_paths=[f"{cpath}/.git", f"{ppath}/.git"],
                    evidence={
                        "child_git_kind": child["git_kind"],
                        "child_not_set_up_by_plugin": child["not_set_up_by_plugin"],
                        "child_repo": cpath,
                        "is_submodule": True,
                        "parent_repo": ppath,
                        "relative_path": rel_inside,
                    },
                    consequence=(
                        f"Submodule {cpath} is nested inside {ppath}. Nesting is intentional for submodules, "
                        "but sessions started in the child use the child's .git boundary for project context discovery."
                    ),
                    limitations="Static layout check only; does not verify submodule commit sync.",
                )
            )
        else:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.nested_repo",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[cpath, ppath],
                    source_paths=[f"{cpath}/.git", f"{ppath}/.git"],
                    evidence={
                        "All_ancestors": [a["path"] for a in ancestors],
                        "child_git_kind": child["git_kind"],
                        "child_not_set_up_by_plugin": child["not_set_up_by_plugin"],
                        "child_repo": cpath,
                        "is_submodule": False,
                        "parent_not_set_up_by_plugin": nearest_parent["not_set_up_by_plugin"],
                        "parent_repo": ppath,
                        "relative_path": rel_inside,
                    },
                    consequence=(
                        f"Repository {cpath} is nested inside parent repository {ppath} ({rel_inside}). "
                        "Nesting may be intentional, but inner .git boundaries stop parent context discovery "
                        "and outer git operations orbroad file searches may cross repository boundaries."
                    ),
                    limitations="Nesting may be intentional; static check shows the isolation consequence only.",
                )
            )

    return findings, normalized_repos, coverage


def _check_parent_context_applicability(
    chains: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Evaluate parent-instruction relationships along the real Hermes context-discovery chain (§2, §3, §5).

    Rules from `agent/prompt_builder.py:1580-1743`:
    - Hermes walks from `cwd` up to the nearest `.git` root (`git_root`) for `.hermes.md`/`HERMES.md`
      and from `git_root` down to `cwd` for the `AGENTS.md` chain.
    - If a registered project is a nested git repository (`has_own_git=True` at `project_root`),
      its own `.git` stops the upward walk: parent directories above `project_root` are NEVER walked
      by Hermes, even if they contain `AGENTS.md` or `.hermes.md`.
    - Conversely, if a registered project folder has NO `.git` of its own (`has_own_git=False`) and sits
      inside an ancestor git repository (`effective_git_root` above `project_root`), Hermes walks from
      `effective_git_root` down to `project_root`, so parent `AGENTS.md` or `.hermes.md` files DO apply
      unless shadowed by a higher-priority context type.
    """
    findings: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED

    for raw in chains:
        if not isinstance(raw, Mapping):
            continue
        proj_root = _norm_posix_path(raw.get("project_root") or raw.get("path"))
        if not proj_root:
            continue
        raw_cov = str(raw.get("coverage") or COVERAGE_VERIFIED).strip()
        if raw_cov == COVERAGE_COULD_NOT_VERIFY:
            coverage = COVERAGE_COULD_NOT_VERIFY

        has_own_git = bool(raw.get("has_own_git", True))
        eff_git_root = _norm_posix_path(raw.get("effective_git_root") or (proj_root if has_own_git else ""))
        winning_kind = raw.get("winning_kind")

        raw_files = _as_seq(raw.get("files"))
        raw_parent_files = _as_seq(raw.get("parent_context_files"))

        injected_parent_files: list[str] = []
        shadowed_parent_files: list[str] = []
        blocked_by_git_boundary_files: list[str] = []

        for f in raw_files:
            if not isinstance(f, Mapping):
                continue
            fpath = _norm_posix_path(f.get("path"))
            if not fpath:
                continue
            if f.get("coverage") == COVERAGE_COULD_NOT_VERIFY:
                coverage = COVERAGE_COULD_NOT_VERIFY
            # Check if this file lives in an ancestor directory above `proj_root`
            fdir = posixpath.dirname(fpath)
            if _is_strict_subpath(proj_root, fdir):
                if bool(f.get("injected")):
                    injected_parent_files.append(fpath)
                else:
                    shadowed_parent_files.append(fpath)

        for pf in raw_parent_files:
            if not isinstance(pf, Mapping):
                continue
            pf_path = _norm_posix_path(pf.get("path"))
            if not pf_path:
                continue
            if pf.get("coverage") == COVERAGE_COULD_NOT_VERIFY:
                coverage = COVERAGE_COULD_NOT_VERIFY
            pf_dir = posixpath.dirname(pf_path)
            if not _is_strict_subpath(proj_root, pf_dir):
                continue
            if has_own_git or (eff_git_root and _is_strict_subpath(eff_git_root, pf_dir)):
                blocked_by_git_boundary_files.append(pf_path)
            elif bool(pf.get("injected")):
                if pf_path not in injected_parent_files:
                    injected_parent_files.append(pf_path)
            else:
                if pf_path not in shadowed_parent_files:
                    shadowed_parent_files.append(pf_path)

        injected_parent_files.sort()
        shadowed_parent_files.sort()
        blocked_by_git_boundary_files.sort()

        summary = {
            "project_root": proj_root,
            "has_own_git": has_own_git,
            "effective_git_root": eff_git_root or None,
            "winning_kind": winning_kind,
            "injected_parent_files": injected_parent_files,
            "shadowed_parent_files": shadowed_parent_files,
            "blocked_by_git_boundary_files": blocked_by_git_boundary_files,
            "coverage": raw_cov,
        }
        summaries.append(summary)

        if injected_parent_files:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.parent_context_injected",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=raw_cov,
                    affected_identities=[proj_root],
                    source_paths=injected_parent_files,
                    evidence={
                        "effective_git_root": eff_git_root or None,
                        "injected_parent_files": injected_parent_files,
                        "project_root": proj_root,
                        "winning_kind": winning_kind,
                    },
                    consequence=(
                        f"Parent instructions ({', '.join(injected_parent_files)}) outside {proj_root} "
                        "are actively injected into sessions for this project along the Hermes git-root context chain."
                    ),
                    limitations="Static context-chain resolution based on current .git boundary and file precedence.",
                )
            )

        if blocked_by_git_boundary_files:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.parent_context_blocked_by_git_boundary",
                    classification=CLASSIFICATION_INFO,
                    coverage=raw_cov,
                    affected_identities=[proj_root],
                    source_paths=blocked_by_git_boundary_files,
                    evidence={
                        "blocked_parent_files": blocked_by_git_boundary_files,
                        "effective_git_root": eff_git_root or proj_root,
                        "project_root": proj_root,
                    },
                    consequence=(
                        f"Ancestor context files ({', '.join(blocked_by_git_boundary_files)}) above "
                        f"{proj_root} do not apply because Hermes stops context discovery at the child's .git boundary."
                    ),
                    limitations="Static context-chain resolution.",
                )
            )

        if shadowed_parent_files and not injected_parent_files:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.parent_context_shadowed",
                    classification=CLASSIFICATION_INFO,
                    coverage=raw_cov,
                    affected_identities=[proj_root],
                    source_paths=shadowed_parent_files,
                    evidence={
                        "project_root": proj_root,
                        "shadowed_parent_files": shadowed_parent_files,
                        "winning_kind": winning_kind,
                    },
                    consequence=(
                        f"Ancestor context files ({', '.join(shadowed_parent_files)}) are on the directory chain "
                        f"for {proj_root} but are shadowed by {winning_kind or 'higher-priority context files'}."
                    ),
                    limitations="Shadowed files contribute zero prompt characters.",
                )
            )

    summaries.sort(key=lambda item: item["project_root"])
    return findings, summaries, coverage


def _extract_paths_from_pth_text(pth_text: str, pth_dir: str) -> tuple[list[str], list[str]]:
    """Parse static `.pth` file lines without importing or executing `import ...` lines (§5).

    Returns `(resolved_paths, executable_import_lines)`.
    """
    paths: list[str] = []
    import_lines: list[str] = []
    for raw_line in str(pth_text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Python `site` module executes lines starting with `import ` or `import\t`:
        # we NEVER execute them, and we record them as dynamic/unverifiable path mutations if they lack static paths.
        if line.startswith(("import ", "import\t")):
            import_lines.append(line)
            # Also extract string literals that look like filesystem paths in `__editable__` finder lines
            for m in re.finditer(r"['\"]([^'\"]+)['\"]", line):
                cand = m.group(1).strip()
                if ("/" in cand or "\\" in cand) and not cand.startswith(("http://", "https://")):
                    paths.append(_resolve_relative_posix(pth_dir, cand))
            continue
        paths.append(_resolve_relative_posix(pth_dir, line))
    return sorted(set(p for p in paths if p)), import_lines


def _extract_paths_from_direct_url_json(raw_json: str) -> tuple[list[str], bool]:
    """Parse PEP 610 `direct_url.json` text for editable/local `file://` references."""
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return [], False
    if not isinstance(data, Mapping):
        return [], True
    url = str(data.get("url") or "").strip()
    if url.startswith("file://"):
        p = _file_url_to_path(url)
        return ([p] if p else []), True
    return [], True


def _check_cross_links_and_editable_installs(
    cross_links: Sequence[Mapping[str, Any]],
    editable_installs: Sequence[Mapping[str, Any]],
    known_project_roots: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Check cross-project symlinks and static `.pth` / `direct_url.json` editable references (§5)."""
    findings: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED
    sorted_projects = sorted({_norm_posix_path(p) for p in known_project_roots if _norm_posix_path(p)})

    def _owning_project(target_path: str) -> str | None:
        matches = [p for p in sorted_projects if _is_same_or_subpath(target_path, p)]
        if not matches:
            return None
        matches.sort(key=len)
        return matches[-1]

    # 1. Cross-project symlinks
    for raw_link in cross_links:
        if not isinstance(raw_link, Mapping):
            continue
        owner_root = _norm_posix_path(raw_link.get("project_root") or raw_link.get("owner_root") or raw_link.get("root"))
        link_path = _norm_posix_path(raw_link.get("link_path") or raw_link.get("path"))
        raw_target = str(raw_link.get("target") or raw_link.get("symlink_target") or "").strip()
        if not owner_root or not link_path:
            continue
        link_cov = str(raw_link.get("coverage") or COVERAGE_VERIFIED).strip()
        if link_cov == COVERAGE_COULD_NOT_VERIFY or not raw_target:
            coverage = COVERAGE_COULD_NOT_VERIFY

        resolved_target = _resolve_relative_posix(posixpath.dirname(link_path), raw_target) if raw_target else ""
        target_owner = _owning_project(resolved_target) if resolved_target else None

        if resolved_target and not _is_same_or_subpath(resolved_target, owner_root):
            affected = [owner_root]
            if target_owner and target_owner != owner_root:
                affected.append(target_owner)
            cls = CLASSIFICATION_WARNING if target_owner and target_owner != owner_root else CLASSIFICATION_REVIEW
            rec = {
                "kind": "symlink",
                "owner_root": owner_root,
                "source_path": link_path,
                "raw_target": raw_target,
                "resolved_target": resolved_target,
                "target_project": target_owner,
            }
            records.append(rec)
            findings.append(
                _make_finding(
                    rule_id="cross_checks.cross_project_symlink",
                    classification=cls,
                    coverage=link_cov,
                    affected_identities=affected,
                    source_paths=[link_path],
                    evidence=rec,
                    consequence=(
                        f"Symlink {link_path} inside {owner_root} points outside the project root "
                        f"to {resolved_target!r}"
                        + (f" (owned by project {target_owner})." if target_owner else ".")
                    ),
                    limitations="Symlink target inspected as link metadata without following external trees.",
                )
            )

    # 2. Editable installs (.pth / __editable__ / direct_url.json)
    for raw_ed in editable_installs:
        if not isinstance(raw_ed, Mapping):
            continue
        proj_root = _norm_posix_path(raw_ed.get("project_root") or raw_ed.get("owner_root"))
        file_path = _norm_posix_path(raw_ed.get("file_path") or raw_ed.get("path"))
        if not proj_root or not file_path:
            continue

        ed_cov = str(raw_ed.get("coverage") or COVERAGE_VERIFIED).strip()
        if ed_cov == COVERAGE_COULD_NOT_VERIFY:
            coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="cross_checks.editable_install_unreadable",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[proj_root],
                    source_paths=[file_path],
                    evidence={"file_path": file_path, "project_root": proj_root},
                    consequence=f"Editable install file {file_path} could not be safely read.",
                    limitations="Static .pth / direct_url.json inspection only.",
                )
            )
            continue

        pth_dir = posixpath.dirname(file_path)
        extracted_paths: list[str] = []
        import_hooks: list[str] = []

        if isinstance(raw_ed.get("target_paths"), Sequence):
            for tp in raw_ed["target_paths"]:
                norm_tp = _resolve_relative_posix(pth_dir, str(tp))
                if norm_tp:
                    extracted_paths.append(norm_tp)

        content_str = raw_ed.get("content") if isinstance(raw_ed.get("content"), str) else None
        if content_str is not None:
            if file_path.endswith("direct_url.json"):
                du_paths, ok = _extract_paths_from_direct_url_json(content_str)
                if not ok:
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    findings.append(
                        _make_finding(
                            rule_id="cross_checks.editable_install_unparseable",
                            classification=CLASSIFICATION_INFO,
                            coverage=COVERAGE_COULD_NOT_VERIFY,
                            affected_identities=[proj_root],
                            source_paths=[file_path],
                            evidence={"file_path": file_path, "project_root": proj_root},
                            consequence=f"Could not parse JSON in {file_path}.",
                            limitations="Malformed direct_url.json.",
                        )
                    )
                    continue
                extracted_paths.extend(du_paths)
            else:
                pth_paths, imp_lines = _extract_paths_from_pth_text(content_str, pth_dir)
                extracted_paths.extend(pth_paths)
                import_hooks.extend(imp_lines)

        extracted_paths = sorted(set(extracted_paths))
        if import_hooks and not extracted_paths:
            coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="cross_checks.editable_pth_dynamic_hook",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[proj_root],
                    source_paths=[file_path],
                    evidence={
                        "file_path": file_path,
                        "import_hook_count": len(import_hooks),
                        "project_root": proj_root,
                    },
                    consequence=(
                        f"Editable .pth file {file_path} contains executable 'import' hook lines "
                        "whose target paths cannot be determined without executing Python."
                    ),
                    limitations="Static .pth text is read, never imported or executed (§5).",
                )
            )
            continue

        outside_targets = [
            tp for tp in extracted_paths if not _is_same_or_subpath(tp, proj_root)
        ]
        if outside_targets:
            target_projects = sorted({
                tp_proj
                for tp in outside_targets
                if (tp_proj := _owning_project(tp)) is not None and tp_proj != proj_root
            })
            affected = [proj_root, *target_projects]
            rec = {
                "kind": "editable_install",
                "owner_root": proj_root,
                "source_path": file_path,
                "outside_targets": outside_targets,
                "target_projects": target_projects,
            }
            records.append(rec)
            findings.append(
                _make_finding(
                    rule_id="cross_checks.cross_project_editable_install",
                    classification=CLASSIFICATION_WARNING,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=affected,
                    source_paths=[file_path],
                    evidence=rec,
                    consequence=(
                        f"Environment file {file_path} in {proj_root} links to editable/external path(s) "
                        f"{', '.join(outside_targets)} outside {proj_root}; edits or imports in this "
                        "virtualenv cross project boundaries or reflect a relocated checkout."
                    ),
                    limitations="Static .pth / direct_url.json read only; never imported.",
                )
            )

    records.sort(key=lambda r: (r["kind"], r["owner_root"], r["source_path"]))
    return findings, records, coverage


def _check_memory_project_mapping_overlap(
    memory_mappings: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Check memory->project mapping overlap across entries and profiles (§5).

    Accepts plain-data list of `{entry_id, text, paths, project_ids}` (plus optional `profile`, `file_path`).
    Detects:
    - Single memory entry mapped to multiple distinct projects (`cross_checks.memory_entry_multi_project_overlap` -> warning).
    - Multiple profiles or multiple entries mapping conflicting/overlapping notes to the same project
      (`cross_checks.memory_project_overlap_across_profiles` / `cross_checks.memory_project_multiple_entries`).
    """
    findings: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED
    by_project: dict[str, list[dict[str, Any]]] = {}
    multi_project_entries: list[dict[str, Any]] = []

    for idx, raw in enumerate(memory_mappings):
        if not isinstance(raw, Mapping):
            continue
        entry_id = str(raw.get("entry_id") or f"entry_{idx}").strip()
        profile = str(raw.get("profile") or "").strip()
        if not profile and ":" in entry_id:
            profile = entry_id.split(":", 1)[0].strip()
        file_path = str(raw.get("file_path") or "").strip()
        text = str(raw.get("text") or "")
        raw_paths = _as_seq(raw.get("paths"))
        paths = sorted({_norm_posix_path(p) for p in raw_paths if _norm_posix_path(p)})
        raw_pids = _as_seq(raw.get("project_ids"))
        project_ids = sorted({str(pid).strip() for pid in raw_pids if str(pid).strip()})

        if raw.get("coverage") == COVERAGE_COULD_NOT_VERIFY:
            coverage = COVERAGE_COULD_NOT_VERIFY

        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        norm_entry = {
            "entry_id": entry_id,
            "profile": profile or "unknown",
            "file_path": file_path,
            "paths": paths,
            "project_ids": project_ids,
            "text_sha256": text_sha,
            "char_count": len(text),
        }

        if len(project_ids) > 1:
            multi_project_entries.append(norm_entry)
            affected = [ *project_ids ]
            if profile:
                affected.append(profile)
            findings.append(
                _make_finding(
                    rule_id="cross_checks.memory_entry_multi_project_overlap",
                    classification=CLASSIFICATION_WARNING,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=affected,
                    source_paths=[file_path] if file_path else (),
                    evidence={
                        "entry_id": entry_id,
                        "paths": paths,
                        "profile": profile or "unknown",
                        "project_ids": project_ids,
                        "text_sha256": text_sha,
                    },
                    consequence=(
                        f"Memory entry {entry_id!r} references multiple projects ({', '.join(project_ids)}), "
                        "causing cross-project instructions or paths to bleed into unrelated project sessions."
                    ),
                    limitations="Mapped from static path/project references in memory text.",
                )
            )

        for pid in project_ids:
            by_project.setdefault(pid, []).append(norm_entry)

    project_overlaps: list[dict[str, Any]] = []
    for pid in sorted(by_project.keys()):
        entries = sorted(by_project[pid], key=lambda e: (e["profile"], e["entry_id"]))
        if len(entries) < 2:
            continue
        profiles_involved = sorted({e["profile"] for e in entries if e["profile"]})
        entry_ids = [e["entry_id"] for e in entries]
        src_paths = [e["file_path"] for e in entries if e["file_path"]]
        overlap_item = {
            "project_id": pid,
            "profiles": profiles_involved,
            "entry_ids": entry_ids,
            "entry_count": len(entries),
        }
        project_overlaps.append(overlap_item)

        if len(profiles_involved) > 1:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.memory_project_overlap_across_profiles",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[pid, *profiles_involved],
                    source_paths=src_paths,
                    evidence=overlap_item,
                    consequence=(
                        f"Project {pid} is referenced by memory entries across {len(profiles_involved)} profiles "
                        f"({', '.join(profiles_involved)}); switching profiles can apply divergent project memories."
                    ),
                    limitations="Static mapping overlap across profiles.",
                )
            )
        else:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.memory_project_multiple_entries",
                    classification=CLASSIFICATION_REVIEW,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=[pid, *profiles_involved],
                    source_paths=src_paths,
                    evidence=overlap_item,
                    consequence=(
                        f"Project {pid} has {len(entries)} separate memory entries ({', '.join(entry_ids)}) "
                        "that may overlap or contradict each other."
                    ),
                    limitations="Static mapping overlap within profile memory.",
                )
            )

    return (
        findings,
        {
            "multi_project_entries": multi_project_entries,
            "project_overlaps": project_overlaps,
        },
        coverage,
    )


def _select_profile_survivor(
    profiles: Sequence[Mapping[str, Any]],
    *,
    active_profile: str = "default",
) -> dict[str, Any]:
    """Select the survivor among whole-profile exact duplicates per §8 & §13.5.

    - Survivor: active profile -> else most recently used -> else lexically first name.
    - Only non-survivors are archive candidates.
    - Cleanup NEVER offers the active profile, the default profile, or any profile whose
      last-use is `could_not_verify`.
    - All cleanup candidates are unticked by default (`selected_by_default=False`).
    """
    if not profiles:
        return {"survivor": None, "archive_candidates": [], "protected_non_survivors": []}

    def _rank_key(prof: Mapping[str, Any]) -> tuple[int, int, float, str]:
        name = str(prof.get("name") or prof.get("unit_id") or "")
        is_act = 0 if (name == active_profile or bool(prof.get("is_active"))) else 1
        last_ev = prof.get("last_use_evidence")
        ts = (
            last_ev.get("last_use_timestamp")
            if isinstance(last_ev, Mapping)
            else prof.get("last_use_timestamp")
        )
        has_ts = 0 if isinstance(ts, (int, float)) else 1
        neg_ts = -float(ts) if isinstance(ts, (int, float)) else 0.0
        return (is_act, has_ts, neg_ts, name)

    ranked = sorted(profiles, key=_rank_key)
    survivor = str(ranked[0].get("name") or ranked[0].get("unit_id") or "")
    archive_candidates: list[dict[str, Any]] = []
    protected_non_survivors: list[dict[str, Any]] = []

    for prof in ranked[1:]:
        name = str(prof.get("name") or prof.get("unit_id") or "")
        last_ev = prof.get("last_use_evidence")
        ts = (
            last_ev.get("last_use_timestamp")
            if isinstance(last_ev, Mapping)
            else prof.get("last_use_timestamp")
        )
        cov = (
            str(last_ev.get("coverage"))
            if isinstance(last_ev, Mapping) and last_ev.get("coverage") is not None
            else (COVERAGE_VERIFIED if isinstance(ts, (int, float)) else COVERAGE_COULD_NOT_VERIFY)
        )
        if name == "default" or name == active_profile or bool(prof.get("is_active")):
            protected_non_survivors.append({
                "name": name,
                "reason": "active_or_default_never_archived",
            })
        elif cov != COVERAGE_VERIFIED or not isinstance(ts, (int, float)):
            protected_non_survivors.append({
                "name": name,
                "reason": "last_use_could_not_verify",
            })
        else:
            cleanup_id = f"cleanup.archive_duplicate_profile.{name}"
            archive_candidates.append({
                "cleanup_id": cleanup_id,
                "fix_type": "archive_duplicate_profile",
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


def _skill_execution_package_digest(skill: Mapping[str, Any]) -> str | None:
    """Compute or return the canonical execution-relevant skill package digest (§5).

    Requires byte-identical `SKILL.md` (`skill_md_sha256`), byte-identical supporting files
    (`supporting_files_sha256`), and identical execution-relevant metadata (`platforms`, `environments`).
    Never follows external symlinks to claim identity.
    """
    if bool(skill.get("is_symlink")):
        return None
    md_sha = skill.get("skill_md_sha256")
    if not isinstance(md_sha, str) or not md_sha:
        return None
    support_raw = skill.get("supporting_files_sha256")
    support_map = (
        {str(k): str(v) for k, v in sorted(support_raw.items(), key=lambda x: str(x[0]))}
        if isinstance(support_raw, Mapping)
        else {}
    )
    fm = _as_map(skill.get("frontmatter"))
    platforms = skill.get("platforms", fm.get("platforms"))
    environments = skill.get("environments", fm.get("environments"))
    payload = {
        "skill_md_sha256": md_sha,
        "supporting_files": support_map,
        "platforms": platforms,
        "environments": environments,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _check_duplicates_and_profile_matches(
    profile_units: Sequence[Mapping[str, Any]],
    *,
    active_profile: str = "default",
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], str]:
    """Check exact vs whitespace-normalized duplicates for skills and memories, plus profile config vs whole-profile matches (§5, §8, §12, §13.5)."""
    findings: list[dict[str, Any]] = []
    cleanup_candidates: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED

    # 1. Collect skills across profile units (profile-owned local skills only for duplicate cleanup;
    # external/shared skill roots are reported by path so the same physical file isn't self-duplicated).
    skill_occ_by_path: dict[str, dict[str, Any]] = {}
    for p_unit in profile_units:
        if not isinstance(p_unit, Mapping):
            continue
        pname = str(p_unit.get("name") or p_unit.get("unit_id") or "").strip()
        if not pname:
            continue
        if p_unit.get("coverage") == COVERAGE_COULD_NOT_VERIFY or not bool(p_unit.get("stable", True)):
            coverage = COVERAGE_COULD_NOT_VERIFY

        skills_block = p_unit.get("skills")
        skills_list = (
            _as_seq(skills_block.get("skills"))
            if isinstance(skills_block, Mapping)
            else _as_seq(skills_block)
        )
        for sk in skills_list:
            if not isinstance(sk, Mapping):
                continue
            if bool(sk.get("is_symlink")):
                # §5: Do not follow external symlinks to claim identity
                continue
            sk_path = _norm_posix_path(sk.get("skill_md_path") or sk.get("path"))
            if not sk_path:
                continue
            pkg_digest = _skill_execution_package_digest(sk)
            ws_sha = str(sk.get("skill_md_ws_sha256") or "").strip() or None
            md_sha = str(sk.get("skill_md_sha256") or "").strip() or None
            if not pkg_digest and not ws_sha:
                continue
            tier = int(sk.get("tier", 1))
            source_kind = str(sk.get("source_kind") or ("profile_local" if tier == 1 else "external"))
            occ = skill_occ_by_path.get(sk_path)
            if occ is None:
                skill_occ_by_path[sk_path] = {
                    "name": str(sk.get("name") or posixpath.basename(posixpath.dirname(sk_path))),
                    "skill_md_path": sk_path,
                    "package_sha256": pkg_digest,
                    "skill_md_sha256": md_sha,
                    "skill_md_ws_sha256": ws_sha,
                    "supporting_files_sha256": dict(sk.get("supporting_files_sha256") or {})
                    if isinstance(sk.get("supporting_files_sha256"), Mapping)
                    else {},
                    "tier": tier,
                    "source_kind": source_kind,
                    "profiles": [pname],
                }
            else:
                if pname not in occ["profiles"]:
                    occ["profiles"].append(pname)
                    occ["profiles"].sort()

    # Group distinct skill occurrences by package_sha256 (byte-identical) and skill_md_ws_sha256 (whitespace-normalized)
    by_pkg_sha: dict[str, list[dict[str, Any]]] = {}
    by_ws_sha: dict[str, list[dict[str, Any]]] = {}
    for occ in sorted(skill_occ_by_path.values(), key=lambda x: x["skill_md_path"]):
        if occ["package_sha256"]:
            by_pkg_sha.setdefault(occ["package_sha256"], []).append(occ)
        if occ["skill_md_ws_sha256"]:
            by_ws_sha.setdefault(occ["skill_md_ws_sha256"], []).append(occ)

    exact_skill_duplicate_groups: list[dict[str, Any]] = []
    exact_matched_paths: set[str] = set()
    for pkg_sha, group in sorted(by_pkg_sha.items()):
        if len(group) < 2:
            continue
        for g in group:
            exact_matched_paths.add(g["skill_md_path"])
        paths = [g["skill_md_path"] for g in group]
        profiles_affected = sorted({p for g in group for p in g["profiles"]})
        cleanup_id = f"cleanup.skill_duplicate.{pkg_sha[:12]}"
        # Only profile-local copies outside the first survivor path are removable candidates
        removable_paths = [
            g["skill_md_path"]
            for g in group[1:]
            if g["source_kind"] == "profile_local"
        ]
        if removable_paths:
            cleanup_candidates.append({
                "cleanup_id": cleanup_id,
                "fix_type": "remove_duplicate_skill",
                "package_sha256": pkg_sha,
                "survivor_path": group[0]["skill_md_path"],
                "candidate_paths": removable_paths,
                "selected_by_default": False,
            })
        else:
            cleanup_id = None

        grp_info = {
            "skill_name": group[0]["name"],
            "package_sha256": pkg_sha,
            "paths": paths,
            "profiles": profiles_affected,
            "proposed_cleanup_id": cleanup_id,
        }
        exact_skill_duplicate_groups.append(grp_info)
        findings.append(
            _make_finding(
                rule_id="cross_checks.skill_duplicate_exact",
                classification=CLASSIFICATION_WARNING,
                coverage=COVERAGE_VERIFIED,
                affected_identities=profiles_affected or paths,
                source_paths=paths,
                evidence={
                    "package_sha256": pkg_sha,
                    "paths": paths,
                    "profiles": profiles_affected,
                    "skill_name": group[0]["name"],
                },
                consequence=(
                    f"Skill {group[0]['name']!r} has {len(group)} byte-identical copies "
                    "(matching SKILL.md, supporting files, and execution metadata)."
                ),
                limitations="Byte-identical package comparison across non-symlinked skill directories.",
                proposed_cleanup_id=cleanup_id,
            )
        )

    ws_skill_duplicate_groups: list[dict[str, Any]] = []
    for ws_sha, group in sorted(by_ws_sha.items()):
        if len(group) < 2:
            continue
        # If all members of this whitespace group already had identical package_sha256, skip redundant report
        pkg_shas = {g["package_sha256"] for g in group}
        if len(pkg_shas) == 1 and None not in pkg_shas:
            continue
        paths = [g["skill_md_path"] for g in group]
        profiles_affected = sorted({p for g in group for p in g["profiles"]})
        grp_info = {
            "skill_name": group[0]["name"],
            "skill_md_ws_sha256": ws_sha,
            "paths": paths,
            "profiles": profiles_affected,
        }
        ws_skill_duplicate_groups.append(grp_info)
        findings.append(
            _make_finding(
                rule_id="cross_checks.skill_duplicate_Near_or_metadata_diff",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_VERIFIED,
                affected_identities=profiles_affected or paths,
                source_paths=paths,
                evidence=grp_info,
                consequence=(
                    f"Skill {group[0]['name']!r} has {len(group)} copies with whitespace-normalized SKILL.md matches "
                    "or differing supporting files/metadata; review before consolidating."
                ),
                limitations="Whitespace-normalized or supporting-file-divergent skill matches are never auto-cleaned (§5).",
                proposed_cleanup_id=None,
            )
        )

    # 2. Cross-profile memory entry duplicates (byte-identical vs whitespace-normalized)
    mem_by_exact: dict[str, list[dict[str, Any]]] = {}
    mem_by_ws: dict[str, list[dict[str, Any]]] = {}
    for p_unit in profile_units:
        if not isinstance(p_unit, Mapping):
            continue
        pname = str(p_unit.get("name") or p_unit.get("unit_id") or "").strip()
        if not pname:
            continue
        mem_block = _as_map(p_unit.get("memory"))
        files_map = _as_map(mem_block.get("files"))
        for target_key, fmeta in sorted(files_map.items(), key=lambda x: str(x[0])):
            if not isinstance(fmeta, Mapping):
                continue
            if bool(fmeta.get("is_symlink")):
                # §2, §5: Do not follow symlinked memory files to claim duplicate identity; record symlink sharing if present
                findings.append(
                    _make_finding(
                        rule_id="cross_checks.memory_symlink_shared",
                        classification=CLASSIFICATION_REVIEW,
                        coverage=str(fmeta.get("coverage") or COVERAGE_VERIFIED),
                        affected_identities=[pname],
                        source_paths=[str(fmeta.get("path") or "")],
                        evidence={
                            "path": str(fmeta.get("path") or ""),
                            "profile": pname,
                            "symlink_target": fmeta.get("symlink_target"),
                            "target_key": str(target_key),
                        },
                        consequence=(
                            f"Profile {pname!r} memory file {fmeta.get('rel_path') or target_key} is a symlink "
                            f"(-> {fmeta.get('symlink_target')!r}); edits in one profile mutate the shared target."
                        ),
                        limitations="Symlinked memory files are excluded from automatic duplicate entry cleanup.",
                    )
                )
                continue
            fpath = str(fmeta.get("path") or "").strip()
            entries = _as_seq(fmeta.get("entries"))
            for ent in entries:
                if not isinstance(ent, Mapping):
                    continue
                idx = int(ent.get("index", 0))
                text = str(ent.get("text") or "")
                sha_exact = str(ent.get("sha256_exact") or (hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""))
                norm_ws = " ".join(text.split())
                sha_ws = str(ent.get("sha256_normalized_ws") or (hashlib.sha256(norm_ws.encode("utf-8")).hexdigest() if norm_ws else ""))
                if not sha_exact:
                    continue
                occ = {
                    "profile": pname,
                    "target": str(target_key),
                    "path": fpath,
                    "index": idx,
                    "sha256_exact": sha_exact,
                    "sha256_normalized_ws": sha_ws,
                    "char_count": int(ent.get("char_count", len(text))),
                }
                mem_by_exact.setdefault(sha_exact, []).append(occ)
                if sha_ws:
                    mem_by_ws.setdefault(sha_ws, []).append(occ)

    exact_memory_duplicates: list[dict[str, Any]] = []
    for sha_ex, group in sorted(mem_by_exact.items()):
        profiles_in_group = sorted({g["profile"] for g in group})
        if len(profiles_in_group) < 2:
            # Intra-profile memory duplicates are handled by `memory.py`; cross_checks focuses on cross-profile duplicates
            continue
        src_paths = sorted({g["path"] for g in group if g["path"]})
        cleanup_id = f"cleanup.cross_profile_memory_duplicate.{sha_ex[:12]}"
        cleanup_candidates.append({
            "cleanup_id": cleanup_id,
            "fix_type": "remove_duplicate_memory_entry",
            "sha256_exact": sha_ex,
            "occurrences": group,
            "selected_by_default": False,
        })
        dup_info = {
            "sha256_exact": sha_ex,
            "profiles": profiles_in_group,
            "occurrences": group,
            "proposed_cleanup_id": cleanup_id,
        }
        exact_memory_duplicates.append(dup_info)
        findings.append(
            _make_finding(
                rule_id="cross_checks.memory_duplicate_exact_across_profiles",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_VERIFIED,
                affected_identities=profiles_in_group,
                source_paths=src_paths,
                evidence={
                    "occurrences": group,
                    "profiles": profiles_in_group,
                    "sha256_exact": sha_ex,
                },
                consequence=(
                    f"Byte-identical memory entry appears across {len(profiles_in_group)} profiles "
                    f"({', '.join(profiles_in_group)})."
                ),
                limitations="Exact byte match across profiles.",
                proposed_cleanup_id=cleanup_id,
            )
        )

    ws_memory_duplicates: list[dict[str, Any]] = []
    for sha_ws, group in sorted(mem_by_ws.items()):
        profiles_in_group = sorted({g["profile"] for g in group})
        if len(profiles_in_group) < 2:
            continue
        exact_shas = {g["sha256_exact"] for g in group}
        if len(exact_shas) == 1:
            continue
        src_paths = sorted({g["path"] for g in group if g["path"]})
        dup_info = {
            "sha256_normalized_ws": sha_ws,
            "profiles": profiles_in_group,
            "occurrences": group,
        }
        ws_memory_duplicates.append(dup_info)
        findings.append(
            _make_finding(
                rule_id="cross_checks.memory_duplicate_whitespace_across_profiles",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_VERIFIED,
                affected_identities=profiles_in_group,
                source_paths=src_paths,
                evidence=dup_info,
                consequence=(
                    f"Memory entries across profiles ({', '.join(profiles_in_group)}) match after whitespace "
                    "normalization but differ in exact bytes."
                ),
                limitations="Whitespace-normalized matches are review suggested only and never cleanup-eligible (§5).",
                proposed_cleanup_id=None,
            )
        )

    # 3. Profile configuration match vs Whole-profile exactness (§5, §12, §13.5)
    by_config_digest: dict[str, list[Mapping[str, Any]]] = {}
    by_whole_digest: dict[str, list[Mapping[str, Any]]] = {}
    ineligible_whole_profiles: list[dict[str, Any]] = []

    for p_unit in profile_units:
        if not isinstance(p_unit, Mapping):
            continue
        pname = str(p_unit.get("name") or p_unit.get("unit_id") or "").strip()
        if not pname:
            continue
        fp_raw = p_unit.get("fingerprint_manifest")
        fp: Mapping[str, Any] = fp_raw if isinstance(fp_raw, Mapping) else p_unit
        cfg_digest = fp.get("configuration_match_digest")
        whole_digest = fp.get("whole_profile_digest")
        whole_eligible = bool(fp.get("whole_profile_exact_eligible", whole_digest is not None))
        unreadable = list(_as_seq(fp.get("unreadable_paths")))
        special = dict(_as_map(fp.get("special_files")))
        excluded = list(_as_seq(fp.get("excluded_audit_paths")))

        if not whole_eligible or unreadable or special:
            coverage = COVERAGE_COULD_NOT_VERIFY
            ineligible_whole_profiles.append({
                "profile": pname,
                "unreadable_paths": unreadable,
                "special_files": list(special.keys()),
                "excluded_audit_paths": excluded,
            })
            findings.append(
                _make_finding(
                    rule_id="cross_checks.profile_regions_unverified",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[pname],
                    source_paths=[str(p_unit.get("path") or fp.get("root_path") or pname)],
                    evidence={
                        "excluded_audit_paths": excluded,
                        "profile": pname,
                        "special_files": sorted(special.keys()),
                        "unreadable_paths": unreadable,
                    },
                    consequence=(
                        f"Profile {pname!r} has unreadable, special, or unstable regions; "
                        "whole-profile exactness cannot be verified for archive-duplicate cleanup."
                    ),
                    limitations="Whole-profile exactness requires all owned regions in the §12 manifest to be verified.",
                )
            )

        if isinstance(cfg_digest, str) and cfg_digest:
            by_config_digest.setdefault(cfg_digest, []).append(p_unit)
        if whole_eligible and isinstance(whole_digest, str) and whole_digest:
            by_whole_digest.setdefault(whole_digest, []).append(p_unit)

    whole_profile_duplicate_groups: list[dict[str, Any]] = []
    whole_matched_sets: set[tuple[str, ...]] = set()

    for w_digest, group in sorted(by_whole_digest.items()):
        if len(group) < 2:
            continue
        names = tuple(sorted(str(p.get("name") or p.get("unit_id") or "") for p in group))
        whole_matched_sets.add(names)
        survivor_info = _select_profile_survivor(group, active_profile=active_profile)
        cand_list = survivor_info["archive_candidates"]
        for c in cand_list:
            cleanup_candidates.append(c)
        group_cleanup_id = (
            f"cleanup.archive_duplicate_profile_group.{w_digest[:12]}"
            if cand_list
            else None
        )
        src_paths = sorted(
            str(p.get("path") or (p.get("fingerprint_manifest") or {}).get("root_path") or "")
            for p in group
            if str(p.get("path") or (p.get("fingerprint_manifest") or {}).get("root_path") or "")
        )
        grp_record = {
            "whole_profile_digest": w_digest,
            "profiles": list(names),
            "survivor": survivor_info["survivor"],
            "archive_candidates": cand_list,
            "protected_non_survivors": survivor_info["protected_non_survivors"],
            "proposed_cleanup_id": group_cleanup_id,
        }
        whole_profile_duplicate_groups.append(grp_record)
        findings.append(
            _make_finding(
                rule_id="cross_checks.whole_profile_exact_duplicate",
                classification=CLASSIFICATION_REVIEW,
                coverage=COVERAGE_VERIFIED,
                affected_identities=list(names),
                source_paths=src_paths,
                evidence={
                    "archive_candidates": cand_list,
                    "profiles": list(names),
                    "protected_non_survivors": survivor_info["protected_non_survivors"],
                    "survivor": survivor_info["survivor"],
                    "whole_profile_digest": w_digest,
                },
                consequence=(
                    f"Profiles {', '.join(names)} are byte-for-byte identical across all owned regions "
                    f"(survivor: {survivor_info['survivor']!r})."
                ),
                limitations="Only non-survivors with verified last-use (never active or default) are eligible for archiving.",
                proposed_cleanup_id=group_cleanup_id,
            )
        )

    config_match_groups: list[dict[str, Any]] = []
    for c_digest, group in sorted(by_config_digest.items()):
        if len(group) < 2:
            continue
        names = tuple(sorted(str(p.get("name") or p.get("unit_id") or "") for p in group))
        # Even if whole-profile matched, or if sessions/state differ, report configuration match distinctly when not identical to whole-profile match
        is_also_whole_exact = names in whole_matched_sets
        src_paths = sorted(
            str(p.get("path") or (p.get("fingerprint_manifest") or {}).get("root_path") or "")
            for p in group
            if str(p.get("path") or (p.get("fingerprint_manifest") or {}).get("root_path") or "")
        )
        cfg_record = {
            "configuration_match_digest": c_digest,
            "profiles": list(names),
            "whole_profile_exact": is_also_whole_exact,
        }
        config_match_groups.append(cfg_record)
        if not is_also_whole_exact:
            findings.append(
                _make_finding(
                    rule_id="cross_checks.profile_configuration_match",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_VERIFIED,
                    affected_identities=list(names),
                    source_paths=src_paths,
                    evidence=cfg_record,
                    consequence=(
                        f"Profiles {', '.join(names)} have identical configuration regions "
                        "(memories/, skills/, config.yaml, SOUL.md) but differ in sessions, state.db, or other owned regions."
                    ),
                    limitations="Configuration match alone never authorizes whole-profile duplicate archiving (§5).",
                    proposed_cleanup_id=None,
                )
            )

    summary = {
        "exact_skill_duplicate_groups": exact_skill_duplicate_groups,
        "whitespace_skill_duplicate_groups": ws_skill_duplicate_groups,
        "exact_memory_duplicates": exact_memory_duplicates,
        "whitespace_memory_duplicates": ws_memory_duplicates,
        "configuration_match_groups": config_match_groups,
        "whole_profile_duplicate_groups": whole_profile_duplicate_groups,
        "ineligible_whole_profiles": ineligible_whole_profiles,
    }
    return findings, summary, cleanup_candidates, coverage


def audit_cross_checks(inputs: CrossChecksInput | Mapping[str, Any]) -> dict[str, Any]:
    """Run all §5 System cross-checks over plain-data inputs.

    Returns the legacy component envelope (`ok`, `status`, `error`, `findings`) layered
    with `coverage`, `classification`, `cleanup_candidates`, and `summary` (where `coverage`
    and `classification` drive the product headline rather than legacy `ok`/`status`).
    """
    if not isinstance(inputs, Mapping):
        return {
            "ok": False,
            "status": "error",
            "error": f"inputs must be a Mapping, got {type(inputs).__name__}",
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "classification": CLASSIFICATION_INFO,
            "findings": [],
            "cleanup_candidates": [],
            "summary": {},
        }

    findings: list[dict[str, Any]] = []
    overall_coverage = COVERAGE_VERIFIED

    # 0. Check coherent manifest status (§4)
    coherent = inputs.get("coherent_manifest")
    if isinstance(coherent, Mapping):
        if not bool(coherent.get("coherent_complete", True)) or coherent.get("coverage") == COVERAGE_COULD_NOT_VERIFY:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            missing_units = list(coherent.get("missing_or_unfinished_units") or ())
            missing_ids = [
                f"{m.get('unit_kind', 'unit')}:{m.get('unit_id', '?')}"
                for m in missing_units
                if isinstance(m, Mapping)
            ]
            findings.append(
                _make_finding(
                    rule_id="cross_checks.incomplete_unit_manifest",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=missing_ids or ["system"],
                    evidence={
                        "manifest_digest": coherent.get("manifest_digest"),
                        "missing_or_unfinished_units": missing_units,
                    },
                    consequence=(
                        "System cross-checks ran with partial coverage because one or more units "
                        "were missing, unfinished, or unstable during the scan."
                    ),
                    limitations="Cross-checks never silently combine old and current snapshots (§4).",
                )
            )

    repos_in = _as_seq(inputs.get("repos"))
    chains_in = _as_seq(inputs.get("parent_context_chains"))
    links_in = _as_seq(inputs.get("cross_links"))
    editable_in = _as_seq(inputs.get("editable_installs"))
    mem_mappings_in = _as_seq(inputs.get("memory_mappings"))
    profile_units_in = _as_seq(inputs.get("profile_units"))
    active_profile = str(inputs.get("active_profile") or "default").strip() or "default"

    # 1. Nested repos & worktree pointers
    repo_findings, norm_repos, repo_cov = _check_nested_repos_and_worktrees(repos_in)
    findings.extend(repo_findings)
    if repo_cov == COVERAGE_COULD_NOT_VERIFY:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    # 2. Parent-context applicability along the real Hermes chain
    ctx_findings, ctx_summaries, ctx_cov = _check_parent_context_applicability(chains_in)
    findings.extend(ctx_findings)
    if ctx_cov == COVERAGE_COULD_NOT_VERIFY:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    # 3. Cross-project links & editable installs
    known_project_roots = [r["path"] for r in norm_repos] + [
        c["project_root"] for c in ctx_summaries
    ]
    link_findings, link_records, link_cov = _check_cross_links_and_editable_installs(
        links_in, editable_in, known_project_roots
    )
    findings.extend(link_findings)
    if link_cov == COVERAGE_COULD_NOT_VERIFY:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    # 4. Memory -> project mapping overlap
    mem_findings, mem_summary, mem_cov = _check_memory_project_mapping_overlap(mem_mappings_in)
    findings.extend(mem_findings)
    if mem_cov == COVERAGE_COULD_NOT_VERIFY:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    # 5. Exact duplicates & profile configuration match vs whole-profile exactness
    dup_findings, dup_summary, cleanup_candidates, dup_cov = _check_duplicates_and_profile_matches(
        profile_units_in, active_profile=active_profile
    )
    findings.extend(dup_findings)
    if dup_cov == COVERAGE_COULD_NOT_VERIFY:
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    findings.sort(key=_finding_sort_key)
    cleanup_candidates.sort(key=lambda c: str(c.get("cleanup_id") or ""))

    if any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in findings):
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    headline_cls = CLASSIFICATION_INFO
    best_rank = _CLASSIFICATION_RANK[headline_cls]
    for f in findings:
        r = _CLASSIFICATION_RANK.get(f["classification"], 1)
        if r > best_rank:
            headline_cls = f["classification"]
            best_rank = r

    has_legacy_error = any(f.get("severity") == "error" for f in findings)
    legacy_status = "fail" if has_legacy_error else "pass"

    return {
        "ok": legacy_status == "pass",
        "status": legacy_status,
        "error": None,
        "component_version": COMPONENT_VERSION,
        "coverage": overall_coverage,
        "classification": headline_cls,
        "findings": findings,
        "cleanup_candidates": cleanup_candidates,
        "summary": {
            "repos": norm_repos,
            "parent_context": ctx_summaries,
            "cross_links_and_editable": link_records,
            "memory_mapping_overlap": mem_summary,
            "duplicates": dup_summary,
        },
    }


def run(inputs: CrossChecksInput | Mapping[str, Any]) -> dict[str, Any]:
    """Standard component entry point (`run(inputs) -> dict`)."""
    return audit_cross_checks(inputs)
