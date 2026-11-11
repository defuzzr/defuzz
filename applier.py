"""Copy-only rule applier, Git baseline committer, and before/after verifier.

Invariants:
- Operates ONLY on the copy root; verifies source, staging, and copy roots are disjoint.
- Refuses worktree gitfiles, submodules, and git alternates (v1).
- Never deletes any file anywhere; retired or scratch paths move to _archive/.
- Rewrites copy-internal symlinks to relative paths (os.path.relpath).
- Writes ignore/LFS/secret policies, then commits original paths before structural moves.
- Records the adopted layout and plain-markdown AGENTS.md in a second commit.
- Stages only approved paths with literal pathspecs; verifies zero secret-flagged files are staged.
- Verifies SHA-256 integrity of every file from inventory after apply.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import tool_seed, toolchk
from .agents_md import DEFAULT_MAX_LINES, write_agents_md
from .rules import expand_rules, validate_rules_spec
from .safety import (
    PinnedFolder,
    SafetyError,
    _lexical_abs,
    assert_disjoint_roots,
    assert_not_live_hermes,
    assert_safe_root,
    run_git_hardened,
    safe_mkdirs,
    safe_rename,
    safe_write_bytes,
    safe_write_text,
    verify_nofollow_within_root,
)
from .scanner import UnsupportedGitLayoutError, _is_secret_filename, _sha256_nofollow, inspect_git_layout
from .state_store import record_project, state_db_path


def _merge_lines_preserving_existing(existing_text: str, new_lines: List[str], header: str) -> str:
    existing = [ln.rstrip("\r") for ln in existing_text.splitlines()]
    seen = {ln.strip() for ln in existing if ln.strip() and not ln.strip().startswith("#")}
    added = [ln for ln in new_lines if ln.strip() and ln.strip() not in seen]
    if not added:
        return existing_text if existing_text.endswith("\n") else existing_text + "\n"
    blocks: List[str] = [existing_text.rstrip("\n")] if existing_text.strip() else []
    blocks.extend([f"# {header}", *added])
    return "\n".join(blocks) + "\n"


def _read_existing_nofollow(root: Path, rel_path: str) -> str:
    target = verify_nofollow_within_root(root, rel_path)
    if not target.exists():
        return ""
    st = os.lstat(target)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SafetyError(f"Refusing non-regular file at {target}")
    return target.read_text(encoding="utf-8", errors="replace")


def _move_special_runtime_dirs(copy_root: Path, special_paths: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Move collapsed runtime directories (.hermes/scratch, .hermes/sessions, .worktrees) into _archive/."""
    archived: List[Dict[str, str]] = []
    candidates = [
        ".hermes/scratch", ".hermes/sessions", ".hermes/cache", ".hermes/logs", ".worktrees",
        *(item["path"] for item in special_paths if item.get("kind") == "nested_git"),
    ]
    for rel in dict.fromkeys(candidates):
        if (rel.startswith(".hermes/") and os.path.islink(copy_root / ".hermes")) or os.path.islink(copy_root / rel):
            continue
        src = verify_nofollow_within_root(copy_root, rel)
        if not os.path.lexists(src) or stat.S_ISLNK(os.lstat(src).st_mode):
            continue
        dest_rel = f"_archive/{rel}"
        dest = verify_nofollow_within_root(copy_root, dest_rel)
        if dest.exists():
            continue
        safe_rename(copy_root, rel, dest_rel)
        archived.append({"from": rel, "to": dest_rel})
    return archived


def _rewrite_internal_symlinks(copy_root: Path, expanded_links: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Rewrite internal-absolute (and moved internal-relative) symlinks to relative symlinks."""
    rewritten: List[Dict[str, str]] = []
    for ln in expanded_links:
        ln_class, new_target_rel = ln["link_class"], ln.get("new_target_rel")
        if ln_class not in ("internal-relative", "internal-absolute") or not new_target_rel:
            continue
        dest_rel = ln["dest_path"]
        link_full = copy_root / dest_rel
        try:
            if not stat.S_ISLNK(os.lstat(link_full).st_mode):
                continue
        except OSError:
            continue
        rel_target = os.path.relpath(str(copy_root / new_target_rel), str(link_full.parent)).replace("\\", "/")
        old_target = os.readlink(str(link_full))
        if old_target == rel_target:
            continue
        tmp_link = link_full.parent / f".adopt-link-tmp-{os.getpid()}"
        if os.path.lexists(tmp_link):
            raise SafetyError(f"Temporary symlink path already exists: {tmp_link}")
        os.symlink(rel_target, str(tmp_link))
        os.replace(str(tmp_link), str(link_full))
        rewritten.append({"path": dest_rel, "old_target": old_target, "new_target": rel_target, "link_class": ln_class})
    return rewritten


def _checked_git(copy_path: Path, args: Sequence[str]) -> Any:
    result = run_git_hardened(copy_path, args)
    if result.returncode:
        raise SafetyError(f"Git operation failed: {args[0]}")
    return result


def _git_index_paths(copy_path: Path) -> Set[str]:
    return {os.fsdecode(p) for p in _checked_git(copy_path, ["ls-files", "--cached", "-z"]).stdout.split(b"\0") if p}


def _commit_snapshot(copy_path: Path, secret_paths: Sequence[str], message: str) -> str:
    if _git_index_paths(copy_path).intersection(secret_paths):
        raise SafetyError("Refusing commit: secret-locked files in git index")
    head = run_git_hardened(copy_path, ["rev-parse", "--verify", "HEAD"])
    diff = run_git_hardened(copy_path, ["diff", "--cached", "--quiet"])
    if diff.returncode not in (0, 1):
        raise SafetyError("Cannot inspect staged changes")
    if head.returncode or diff.returncode:
        _checked_git(copy_path, ["commit", "--allow-empty", "-m", message])
    return _checked_git(copy_path, ["rev-parse", "--verify", "HEAD"]).stdout.decode().strip()


def _write_git_policy_files(copy_path: Path, plan: Dict[str, Any], inventory: Dict[str, Any]) -> List[str]:
    secret_paths = sorted(
        {f["dest_path"] for f in plan["files"] if f.get("secret_locked")}
        | {s["path"] for s in (inventory.get("secrets_flagged") or [])}
        | set(inventory.get("secret_files_left_behind") or [])
    )
    ignored_file_paths = sorted({f["dest_path"] for f in plan["files"] if f["git_policy"] == "ignore"})
    raw_ignores = ["_archive/", ".adopt/place-log.json", *plan["ignore_patterns"], *secret_paths, *ignored_file_paths]
    gitignore_additions = [
        pat for pat in dict.fromkeys(raw_ignores)
        if pat and "\n" not in pat and "\r" not in pat
    ]

    safe_write_text(
        copy_path,
        ".gitignore",
        _merge_lines_preserving_existing(
            _read_existing_nofollow(copy_path, ".gitignore"),
            gitignore_additions,
            "defuzz: secrets, caches, and archive exclusions",
        ),
        overwrite=True,
    )

    gitattr_additions: List[str] = [
        "* text=auto eol=lf",
        *(f"{lfs_pat} filter=lfs diff=lfs merge=lfs -text" for lfs_pat in plan["lfs_patterns"]),
    ]
    for f_entry in plan["files"]:
        if f_entry["git_policy"] == "lfs" and not f_entry.get("secret_locked"):
            _, ext = os.path.splitext(f_entry["dest_path"].lower())
            rule_line = f"{'*' + ext if ext else f_entry['dest_path']} filter=lfs diff=lfs merge=lfs -text"
            if rule_line not in gitattr_additions:
                gitattr_additions.append(rule_line)

    safe_write_text(
        copy_path,
        ".gitattributes",
        _merge_lines_preserving_existing(
            _read_existing_nofollow(copy_path, ".gitattributes"),
            gitattr_additions,
            "defuzz: line endings and LFS policies",
        ),
        overwrite=True,
    )
    return secret_paths


def _ensure_git_repo_and_identity(copy_path: Path, has_git: bool) -> None:
    if not has_git:
        if run_git_hardened(copy_path, ["init", "-b", "main"], allow_literal_pathspecs=False).returncode != 0:
            run_git_hardened(copy_path, ["init"], allow_literal_pathspecs=False)
    for key, default_val in (("user.name", "Hermes Adopt"), ("user.email", "defuzz@example.invalid")):
        proc = run_git_hardened(copy_path, ["config", "--get", key], allow_literal_pathspecs=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            run_git_hardened(copy_path, ["config", key, default_val], allow_literal_pathspecs=False)


def _stage_and_commit_baseline(
    copy_path: Path,
    plan: Dict[str, Any],
    inventory: Dict[str, Any],
    runtime_archived: List[Dict[str, str]],
    secret_paths: List[str],
) -> Tuple[str, List[str], List[Dict[str, str]]]:
    untracked_applied: List[str] = []
    tracked = _git_index_paths(copy_path)
    to_untrack: List[str] = []
    for entry in plan["files"]:
        src = entry["source_path"]
        if src in tracked and (entry.get("secret_locked") or entry["git_policy"] in ("ignore", "untrack")):
            to_untrack.append(src)
    for sp in secret_paths:
        if sp in tracked and sp not in to_untrack:
            to_untrack.append(sp)
    for src in to_untrack:
        _checked_git(copy_path, ["rm", "--cached", "-f", "--", src])
        untracked_applied.append(src)
    for archived in runtime_archived:
        paths = sorted(p for p in tracked if p == archived["from"] or p.startswith(archived["from"] + "/"))
        if paths:
            _checked_git(copy_path, ["rm", "--cached", "-f", "--", *paths])

    original_links = [
        dict(link, dest_path=link["path"], new_target_rel=link.get("target_rel"))
        for link in inventory.get("links", [])
    ]
    links_rewritten = _rewrite_internal_symlinks(copy_path, original_links)
    _checked_git(copy_path, ["add", "-f", "--", ".gitignore", ".gitattributes"])
    stageable = [
        f["source_path"] for f in plan["files"]
        if f["git_policy"] in ("track", "lfs") and not f.get("secret_locked") and not f.get("left_behind")
    ] + [
        ln["source_path"] for ln in plan["links"]
        if ln["link_class"] in ("internal-relative", "internal-absolute")
    ]
    for i in range(0, len(stageable), 100):
        _checked_git(copy_path, ["add", "-f", "--", *stageable[i : i + 100]])

    baseline_sha = _commit_snapshot(
        copy_path, secret_paths, "chore(adopt): baseline snapshot before structural moves"
    )
    return baseline_sha, untracked_applied, links_rewritten


def _apply_structural_moves(
    copy_path: Path,
    plan: Dict[str, Any],
    initial_links_rewritten: List[Dict[str, str]],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    moves_applied: List[Dict[str, str]] = []
    tracked = _git_index_paths(copy_path)
    for entry in plan["files"]:
        src, dst = entry["source_path"], entry["dest_path"]
        if src == dst:
            continue
        src_full = verify_nofollow_within_root(copy_path, src)
        dst_full = verify_nofollow_within_root(copy_path, dst)
        if not os.path.lexists(src_full):
            if entry.get("left_behind") or (entry.get("secret_locked") and _is_secret_filename(src)):
                continue
            raise SafetyError("Missing source or occupied move destination")
        if os.path.lexists(dst_full):
            raise SafetyError("Missing source or occupied move destination")
        safe_mkdirs(copy_path, os.path.dirname(dst) or ".")
        if src in tracked and entry["git_policy"] in ("track", "lfs") and entry["disposition"] != "archive":
            _checked_git(copy_path, ["mv", "--", src, dst])
        else:
            if src in tracked:
                _checked_git(copy_path, ["rm", "--cached", "-f", "--", src])
            safe_rename(copy_path, src, dst)
        moves_applied.append({
            "from": src, "to": dst, "disposition": entry["disposition"], "git_policy": entry["git_policy"],
        })

    rewritten_by_path = {link["path"]: link for link in initial_links_rewritten}
    for link in _rewrite_internal_symlinks(copy_path, plan["links"]):
        if link["path"] in rewritten_by_path:
            rewritten_by_path[link["path"]]["new_target"] = link["new_target"]
        else:
            rewritten_by_path[link["path"]] = link
    return moves_applied, list(rewritten_by_path.values())


def _seed_or_archive_tools_lock(copy_path: Path) -> Tuple[Any, Optional[str], Optional[str], List[str]]:
    existing_lock = copy_path / "TOOLS.lock"
    archived_tools_lock: Optional[str] = None
    had_regular_lock = False
    notes: List[str] = []
    if os.path.lexists(existing_lock):
        st_lock = os.lstat(existing_lock)
        if stat.S_ISLNK(st_lock.st_mode):
            notes.append("Refused to follow symlinked TOOLS.lock; treated as absent.")
        elif stat.S_ISREG(st_lock.st_mode):
            had_regular_lock = True

    try:
        seed_res = tool_seed.seed_lock(copy_path, event="adoption")
        for n in seed_res.get("notes") or []:
            if n not in notes:
                notes.append(n)
        if notes:
            seed_res["notes"] = list(notes)
        return seed_res, None, None, notes
    except toolchk.PreflightError as exc:
        skip_reason = str(exc.report.get("summary") or exc)
        if had_regular_lock and os.path.lexists(existing_lock):
            st_mal = os.lstat(existing_lock)
            if not stat.S_ISLNK(st_mal.st_mode) and stat.S_ISREG(st_mal.st_mode):
                ts_ns = time.time_ns()
                archive_rel = f"_archive/TOOLS.pre-adopt.{ts_ns}.lock"
                suffix_idx = 0
                while os.path.lexists(copy_path / archive_rel):
                    suffix_idx += 1
                    archive_rel = f"_archive/TOOLS.pre-adopt.{ts_ns}_{suffix_idx}.lock"
                safe_write_bytes(copy_path, archive_rel, existing_lock.read_bytes(), overwrite=False)
                archived_tools_lock = archive_rel
        return "skipped", skip_reason, archived_tools_lock, notes


def _verify_post_apply_integrity(
    copy_path: Path,
    plan: Dict[str, Any],
    archived_agents_md: Optional[str],
    archived_tools_lock: Optional[str],
) -> int:
    verified_files = 0
    for f_entry in plan["files"]:
        src_rel, dst_rel = f_entry["source_path"], f_entry["dest_path"]
        if src_rel in (".gitignore", ".gitattributes") or (src_rel == "TOOLS.lock" and not archived_tools_lock):
            verified_files += 1
            continue
        if src_rel == "TOOLS.lock" and archived_tools_lock:
            check_label, check_path = archived_tools_lock, copy_path / archived_tools_lock
        elif src_rel == "AGENTS.md" and archived_agents_md:
            check_label, check_path = dst_rel, copy_path / archived_agents_md
        else:
            check_label, check_path = dst_rel, copy_path / dst_rel

        if not os.path.lexists(check_path):
            if f_entry.get("left_behind"):
                continue
            raise SafetyError(f"Post-apply verification failed: missing file at {check_label}")
        # No recorded hash (secret-named files are never opened by the scan): presence only.
        expected_sha = f_entry.get("sha256")
        if expected_sha:
            actual_sha = _sha256_nofollow(check_path)
            if actual_sha != expected_sha:
                raise SafetyError(
                    f"Post-apply SHA-256 mismatch for {check_label}: expected {expected_sha}, got {actual_sha}"
                )
        verified_files += 1
    return verified_files


class ReportDestination:
    """An external report path, checked and its folder opened before any adoption work.

    The folder the person chose may be reached through their own links: it is pinned by
    identity (see safety.PinnedFolder) and kept open, so the final write cannot be redirected
    and cannot fail for a reason that was not already checked at the start.
    """

    def __init__(self, path: os.PathLike | str) -> None:
        self.path = _lexical_abs(path)
        assert_not_live_hermes(self.path, role="report_out")
        self.folder = PinnedFolder(self.path.parent, role="report_out")
        try:
            assert_not_live_hermes(self.folder.real / self.path.name, role="report_out")
            st: Optional[os.stat_result] = None
            if not self.folder.missing:
                try:
                    st = os.stat(self.path.name, dir_fd=self.folder.fd, follow_symlinks=False)
                except FileNotFoundError:
                    st = None
            if st is not None and stat.S_ISLNK(st.st_mode):
                raise SafetyError(f"Refusing to write the report through a symbolic link: {self.path}")
            if st is not None and not stat.S_ISREG(st.st_mode):
                raise SafetyError(f"Refusing to overwrite non-regular file: {self.path}")
        except BaseException:
            self.folder.close()
            raise

    def write(self, text: str) -> None:
        safe_write_text(self.path.parent, self.path.name, text, overwrite=True, base=self.folder)

    def close(self) -> None:
        self.folder.close()

    def __enter__(self) -> "ReportDestination":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def apply_rules_to_copy(
    copy_root: os.PathLike | str,
    inventory: Dict[str, Any],
    rules_spec: Dict[str, Any],
    *,
    source_root: Optional[os.PathLike | str] = None,
    staging_root: Optional[os.PathLike | str] = None,
    report_out_path: Any = None,
    agents_md_max_lines: int = DEFAULT_MAX_LINES,
    db_path: Optional[Path | str] = None,
    state_store: Optional[Any] = None,
    record_fn: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Expand folder rules, apply them to copy_root, create Git baseline, and verify integrity.

    report_out_path (a path or an open ReportDestination) is checked before any work starts.
    """
    kwargs: Dict[str, Any] = dict(
        source_root=source_root, staging_root=staging_root, agents_md_max_lines=agents_md_max_lines,
        db_path=db_path, state_store=state_store, record_fn=record_fn,
    )
    if report_out_path is None or isinstance(report_out_path, ReportDestination):
        return _apply_rules_to_copy(copy_root, inventory, rules_spec, report_dest=report_out_path, **kwargs)
    effective_source = source_root or inventory.get("source_root")
    assert_disjoint_roots(source=effective_source, staging=report_out_path, output=copy_root)
    with ReportDestination(report_out_path) as dest:
        return _apply_rules_to_copy(copy_root, inventory, rules_spec, report_dest=dest, **kwargs)


def _apply_rules_to_copy(
    copy_root: os.PathLike | str,
    inventory: Dict[str, Any],
    rules_spec: Dict[str, Any],
    *,
    source_root: Optional[os.PathLike | str] = None,
    staging_root: Optional[os.PathLike | str] = None,
    report_dest: Optional[ReportDestination] = None,
    agents_md_max_lines: int = DEFAULT_MAX_LINES,
    db_path: Optional[Path | str] = None,
    state_store: Optional[Any] = None,
    record_fn: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    started = time.monotonic()
    effective_source = source_root or inventory.get("source_root")
    assert_disjoint_roots(source=effective_source, staging=staging_root, output=copy_root)
    if report_dest is not None:
        assert_disjoint_roots(source=effective_source, staging=report_dest.path, output=copy_root)
        assert_disjoint_roots(source=effective_source, staging=report_dest.folder.real / report_dest.path.name, output=copy_root)
    copy_path = assert_safe_root(copy_root, role="output")
    if os.path.islink(copy_path) or not copy_path.is_dir():
        raise SafetyError(f"Copy root must be an existing non-symlink directory: {copy_path}")

    git_layout = inspect_git_layout(copy_path)
    if git_layout["layout_refused"]:
        raise UnsupportedGitLayoutError(git_layout["layout_refusal_reasons"])

    plan = expand_rules(inventory, rules_spec)
    validated_rules = validate_rules_spec(rules_spec, inventory)

    for folder in ("_inbox", "_archive", ".adopt", *(d["dir"] for d in plan["declared_dirs"])):
        safe_mkdirs(copy_path, folder)

    runtime_archived = _move_special_runtime_dirs(copy_path, inventory.get("special_paths") or [])
    secret_paths = _write_git_policy_files(copy_path, plan, inventory)
    _ensure_git_repo_and_identity(copy_path, git_layout["has_git"])

    baseline_commit_sha, untracked_applied, initial_links = _stage_and_commit_baseline(
        copy_path, plan, inventory, runtime_archived, secret_paths
    )
    moves_applied, links_rewritten = _apply_structural_moves(copy_path, plan, initial_links)

    existing_agents_path = copy_path / "AGENTS.md"
    archived_agents_md: Optional[str] = None
    if os.path.lexists(existing_agents_path):
        st = os.lstat(existing_agents_path)
        if not stat.S_ISLNK(st.st_mode) and stat.S_ISREG(st.st_mode):
            safe_write_bytes(
                copy_path, "_archive/AGENTS.pre-adopt.md", existing_agents_path.read_bytes(), overwrite=False
            )
            archived_agents_md = "_archive/AGENTS.pre-adopt.md"

    rules_payload = {
        "schema": 1,
        "schema_version": 1,
        "project_slug": plan["project_slug"],
        "declared_dirs": plan["declared_dirs"],
        "folder_rules": validated_rules["folder_rules"],
        "placement_rules": plan["placement_rules"],
        "ignore_patterns": plan["ignore_patterns"],
        "lfs_patterns": plan["lfs_patterns"],
        "local_only_branches": list((inventory.get("git") or {}).get("local_only_branches") or []),
        "agents_md_max_lines": agents_md_max_lines,
    }
    rules_text = json.dumps(rules_payload, indent=2, sort_keys=False) + "\n"
    safe_write_text(copy_path, ".adopt/rules.json", rules_text, overwrite=True)
    rules_hash = hashlib.sha256(rules_text.encode("utf-8")).hexdigest()

    from .componentize_settings import load as load_componentize_settings
    reserve_lines = 0
    try:
        if load_componentize_settings()["enabled_on_adopt"]:
            reserve_lines = 1
    except (OSError, TypeError, ValueError):
        pass
    agents_md_result = write_agents_md(copy_path, rules_payload, reserve_lines=reserve_lines)
    agents_md_text = (copy_path / "AGENTS.md").read_text(encoding="utf-8")

    tools_lock_status, tools_lock_skip_reason, archived_tools_lock, tools_lock_notes = (
        _seed_or_archive_tools_lock(copy_path)
    )
    if not os.path.lexists(copy_path / "_inbox/.gitkeep"):
        safe_write_text(copy_path, "_inbox/.gitkeep", "")

    from . import componentize_bridge
    componentize_survey = componentize_bridge.survey_after_apply(
        copy_path, agents_md_max_lines=agents_md_max_lines
    )
    agents_md_text = (copy_path / "AGENTS.md").read_text(encoding="utf-8")

    stage_generated = [".adopt/rules.json", *agents_md_result["paths"], "_inbox/.gitkeep"]
    if componentize_survey["status"] == "ok":
        stage_generated.append(".adopt/componentize-survey.json")
    if os.path.lexists(copy_path / "TOOLS.lock") and not os.path.islink(copy_path / "TOOLS.lock"):
        stage_generated.append("TOOLS.lock")
    _checked_git(copy_path, ["add", "-f", "--", *stage_generated])
    for link in plan["links"]:
        if link["link_class"] in ("internal-relative", "internal-absolute"):
            _checked_git(copy_path, ["add", "-f", "--", link["dest_path"]])
    adopted_commit_sha = _commit_snapshot(
        copy_path, secret_paths, "chore(adopt): apply folder rules and AGENTS.md"
    )

    verified_files = _verify_post_apply_integrity(copy_path, plan, archived_agents_md, archived_tools_lock)

    before_dirs = {k: v["file_count"] for k, v in (inventory.get("dir_summaries") or {}).items()}
    after_dirs: Dict[str, int] = {}
    for f_entry in plan["files"]:
        top = f_entry["dest_path"].split("/", 1)[0] if "/" in f_entry["dest_path"] else "."
        after_dirs[top] = after_dirs.get(top, 0) + 1

    left_behind_list = list(inventory.get("secret_files_left_behind") or [])
    report: Dict[str, Any] = {
        "schema": 1,
        "schema_version": 1,
        "project_slug": plan["project_slug"],
        "copy_root": str(copy_path),
        "source_root": str(effective_source) if effective_source else None,
        "apply_duration_ms": int((time.monotonic() - started) * 1000),
        "baseline_commit_sha": baseline_commit_sha,
        "adopted_commit_sha": adopted_commit_sha,
        "previous_head_sha": git_layout.get("head_sha"),
        "local_only_branches_preserved": git_layout.get("local_only_branches") or [],
        "counts": {
            "total_files_verified": verified_files,
            "moved": sum(1 for m in moves_applied if m["disposition"] == "move"),
            "archived": sum(1 for m in moves_applied if m["disposition"] == "archive"),
            "kept": sum(1 for f in plan["files"] if f["disposition"] == "keep" and not f.get("left_behind")),
            "runtime_dirs_archived": len(runtime_archived),
            "links_rewritten": len(links_rewritten),
            "secrets_locked_to_ignore": len(secret_paths),
            "untracked_from_index": len(untracked_applied),
        },
        "before_dir_counts": dict(sorted(before_dirs.items())),
        "after_dir_counts": dict(sorted(after_dirs.items())),
        "moves": moves_applied,
        "runtime_dirs_archived": runtime_archived,
        "links_rewritten": links_rewritten,
        "secret_files_left_behind": left_behind_list,
        "secret_files_left_behind_count": len(left_behind_list),
        "secrets_placeholders": [
            {"path": s["path"], "placeholder": s["placeholder"], "git_policy": "ignore"}
            for s in (inventory.get("secrets_flagged") or [])
        ],
        "archived_pre_adopt_agents_md": archived_agents_md,
        "archived_pre_adopt_tools_lock": archived_tools_lock,
        "tools_lock": tools_lock_status,
        "agents_md_lines": len(agents_md_text.splitlines()),
        "agents_md_files": agents_md_result["paths"],
        "agents_md_overflow": agents_md_result["overflow"],
    }
    if tools_lock_skip_reason is not None:
        report["reason"] = tools_lock_skip_reason
    if tools_lock_notes:
        report["tools_lock_notes"] = tools_lock_notes

    target_db = Path(db_path).expanduser() if db_path is not None else state_db_path()
    registered = False
    registration_error: Optional[str] = None
    effective_record_fn = (
        record_fn
        if record_fn is not None
        else (state_store.record_project if state_store is not None else record_project)
    )
    try:
        effective_record_fn(
            path=copy_path.resolve(),
            name=plan["project_slug"],
            slug=plan["project_slug"],
            template_id="adopted",
            answers={"building": "other", "layout": "single", "languages": []},
            hermes_project_id=None,
            db_path=target_db,
            rules_hash=rules_hash,
        )
        registered = True
    except Exception as exc:
        registration_error = str(exc) or type(exc).__name__

    report["registered"] = registered
    report["registration_error"] = registration_error
    report["rules_hash"] = rules_hash

    report_json = json.dumps(report, indent=2, sort_keys=False) + "\n"
    safe_write_text(copy_path, ".adopt/report.json", report_json, overwrite=True)
    if report_dest is not None:
        report_dest.write(report_json)

    return report
