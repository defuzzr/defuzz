"""Read-only hardened folder scanner for Project Defuzz.

Produces inventory.json from a COPY of a project folder:
- Hardened Git layout inspection; refuses worktree gitfiles, submodules, and git alternates (v1).
- Collapses untracked junk directories (node_modules, .venv, __pycache__, etc.) while preserving
  cache-named directories that contain tracked files (e.g. dist/ mixing assets and build output).
- Classifies symlinks without following them (internal-relative, internal-absolute, external).
- Sniffs secrets by filename and streamed text content without ever recording or printing secret values.
- Builds a redacted model_summary for the single LLM folder-rules call.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .safety import (
    SafetyError,
    _is_same_or_subpath,
    _lexical_abs,
    assert_disjoint_roots,
    assert_not_live_hermes,
    assert_safe_root,
    inspect_git_config_dir_refusals,
    run_git_hardened,
)
from .output_file import assert_output_path_safe, write_output_text


class UnsupportedGitLayoutError(SafetyError):
    """Raised when a scanned folder uses a v1-refused Git layout (gitfile, submodule, alternates)."""

    def __init__(self, reasons: List[Dict[str, str]]) -> None:
        self.reasons = reasons
        summary = "; ".join(f"{r['kind']} at {r['path']}: {r['detail']}" for r in reasons)
        super().__init__(f"Unsupported Git layout (v1 refusal): {summary}")


JUNK_DIR_NAMES: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "DerivedDataCache", "Intermediate", "Binaries", "Saved",
    "target", "dist", "build", ".next", ".godot", ".tox",
})

SPECIAL_TOP_DIRS: frozenset[str] = frozenset({".hermes", ".worktrees", "evidence", "Library"})

LFS_EXTENSIONS: frozenset[str] = frozenset({
    ".blend", ".fbx", ".glb", ".gltf", ".obj", ".usd", ".usda", ".usdc", ".usdz",
    ".uasset", ".umap", ".hip", ".hipnc", ".hiplc", ".exr", ".hdr", ".psd", ".xcf",
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".wav", ".ogg", ".flac",
    ".mp3", ".mp4", ".mov", ".webm", ".ttf", ".otf", ".woff", ".woff2",
    ".compiled", ".bin", ".pak", ".zip", ".tar", ".gz", ".7z",
})

SECRET_FILENAME_EXACT: frozenset[str] = frozenset({
    ".env", ".netrc", ".pgpass", ".npmrc", ".pypirc", "credentials",
    "credentials.json", "client_secret.json", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
})

SECRET_FILENAME_SAFE_SUFFIXES: Tuple[str, ...] = (
    ".example", ".sample", ".template", ".dist", ".schema",
)

SECRET_EXTENSIONS: frozenset[str] = frozenset({".pem", ".key", ".p12", ".pfx", ".keystore"})

# Regex patterns for secret sniffing in text files. Never capture or log the matched secret!
# Note: private key pattern avoids literal five-dash prefix so static scanners never confuse
# this detector regex with an embedded private key.
_SECRET_CONTENT_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("private_key_header", re.compile(r"BEGIN\s+(?:[A-Z0-9]+\s+)?PRIVATE\s+KEY")),
    (
        "token_prefix",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}"
            r"|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"
        ),
    ),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|password)"
            r"\s*[=:]\s*[\"']?(?!(?:YOUR_|CHANGE_ME|REPLACE_|EXAMPLE|NONE|NULL|TRUE|FALSE|<secret|\$\{)"
            r"|(?-i:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b)[A-Za-z0-9+/=_-]{24,}"
        ),
    ),
)

_PLAN_DOC_RE = re.compile(r"(?i)(?:^|/)(?:plan|plans|notes|handoff|roadmap|todo|adr|design)[^/]*\.md$")
_HERMES_RUNTIME_SUBDIRS = ("scratch", "sessions", "cache", "logs")


def _is_secret_filename(rel_path: str) -> bool:
    lower = os.path.basename(rel_path).lower()
    if lower.endswith(SECRET_FILENAME_SAFE_SUFFIXES):
        return False
    _, ext = os.path.splitext(lower)
    return lower in SECRET_FILENAME_EXACT or lower.startswith(".env.") or ext in SECRET_EXTENSIONS


def _sniff_file_for_secrets(full_path: Path) -> Tuple[bool, List[str], bool]:
    """Stream-sniff a regular file for secret patterns without storing any matched value.

    Returns (is_binary, reasons, complete).
    """
    reasons: List[str] = []
    try:
        fd = os.open(str(full_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False, ["unreadable_locked"], False

    try:
        with os.fdopen(fd, "rb") as fh:
            if b"\x00" in fh.read(8192):
                return True, [], True
            fh.seek(0)
            seen_kinds: Set[str] = set()
            for raw_line in fh:
                text_line = raw_line.decode("utf-8", errors="replace")
                for kind, pat in _SECRET_CONTENT_PATTERNS:
                    if kind not in seen_kinds and pat.search(text_line):
                        seen_kinds.add(kind)
                        reasons.append(kind)
    except OSError:
        return False, ["read_error"], False
    return False, reasons, True


def _sha256_nofollow(full_path: Path) -> Optional[str]:
    try:
        fd = os.open(str(full_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    h = hashlib.sha256()
    try:
        with os.fdopen(fd, "rb") as fh:
            while chunk := fh.read(65536):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _collapse_junk_dir_stats(full_dir: Path) -> Tuple[int, int]:
    """Count regular/symlink files and total bytes inside an untracked junk dir (no-follow)."""
    file_count = 0
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(str(full_dir), topdown=True, followlinks=False):
        keep_dirs: List[str] = []
        for d in dirnames:
            try:
                st = os.lstat(os.path.join(dirpath, d))
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                file_count += 1
                total_bytes += st.st_size
            else:
                keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for f in filenames:
            try:
                st = os.lstat(os.path.join(dirpath, f))
            except OSError:
                continue
            file_count += 1
            total_bytes += st.st_size
    return file_count, total_bytes


def _has_symlink_ancestor(copy_root: Path, target_rel: str) -> bool:
    cur = copy_root
    for part in Path(target_rel).parts[:-1]:
        cur = cur / part
        try:
            if stat.S_ISLNK(os.lstat(cur).st_mode):
                return True
        except OSError:
            break
    return False


def classify_symlink(
    copy_root: Path,
    link_full_path: Path,
    *,
    source_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Classify a symlink without following it outside copy_root.

    Classes:
    - internal-relative: relative link target that stays within copy_root
    - internal-absolute: absolute link target pointing inside copy_root (or source_root if given)
    - external: relative or absolute link target pointing outside copy_root / source_root
    """
    rel_link = os.path.relpath(str(link_full_path), str(copy_root)).replace("\\", "/")
    raw_target = os.readlink(str(link_full_path))

    if not os.path.isabs(raw_target):
        lexical_dest = Path(os.path.normpath(os.path.join(str(link_full_path.parent), raw_target)))
        if _is_same_or_subpath(lexical_dest, copy_root):
            target_rel = os.path.relpath(str(lexical_dest), str(copy_root)).replace("\\", "/")
            if not _has_symlink_ancestor(copy_root, target_rel):
                return {
                    "path": rel_link,
                    "raw_target": raw_target,
                    "link_class": "internal-relative",
                    "target_rel": target_rel,
                }
        return {"path": rel_link, "raw_target": raw_target, "link_class": "external", "target_rel": None}

    target_lex = Path(os.path.normpath(raw_target))
    for root in (copy_root, source_root):
        if root is not None and _is_same_or_subpath(target_lex, root):
            target_rel = os.path.relpath(str(target_lex), str(root)).replace("\\", "/")
            return {
                "path": rel_link,
                "raw_target": raw_target,
                "link_class": "internal-absolute",
                "target_rel": target_rel,
            }
    return {"path": rel_link, "raw_target": raw_target, "link_class": "external", "target_rel": None}


def _inspect_git_dir_entry(
    git_dir_full: Path,
    git_rel: str,
    rel_dir: str,
    refusals: List[Dict[str, str]],
    nested_repos: List[str],
) -> None:
    try:
        st = os.lstat(git_dir_full)
    except OSError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        refusals.append({
            "kind": "worktree_gitfile",
            "path": git_rel,
            "detail": ".git is a symlink, refused in v1",
        })
        return

    alt_file = git_dir_full / "objects" / "info" / "alternates"
    if alt_file.exists():
        try:
            alt_text = alt_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            alt_text = "unreadable"
        if any(ln.strip() and not ln.strip().startswith("#") for ln in alt_text.splitlines()):
            refusals.append({
                "kind": "git_alternates",
                "path": f"{git_rel}/objects/info/alternates",
                "detail": "Git object alternates present; shared object stores are refused in v1",
            })

    worktrees_dir = git_dir_full / "worktrees"
    if worktrees_dir.is_dir():
        try:
            entries = [e.name for e in worktrees_dir.iterdir()]
        except OSError:
            entries = ["unreadable"]
        if entries:
            refusals.append({
                "kind": "worktree_gitfile",
                "path": f"{git_rel}/worktrees",
                "detail": f"Linked worktrees metadata present ({len(entries)} entry/entries), refused in v1",
            })
    if rel_dir == ".":
        refusals.extend(inspect_git_config_dir_refusals(git_dir_full, git_rel))
    else:
        nested_repos.append(rel_dir)


def _scan_git_tree_refusals(copy_root: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    refusals: List[Dict[str, str]] = []
    nested_repos: List[str] = []
    for dirpath, dirnames, filenames in os.walk(str(copy_root), topdown=True, followlinks=False):
        rel_dir = os.path.relpath(dirpath, str(copy_root)).replace("\\", "/")
        prefix = "" if rel_dir == "." else f"{rel_dir}/"
        if ".git" in filenames:
            refusals.append({
                "kind": "worktree_gitfile",
                "path": f"{prefix}.git",
                "detail": ".git is a file (worktree gitfile or submodule gitdir pointer), refused in v1",
            })
        if ".gitmodules" in filenames or ".gitmodules" in dirnames:
            refusals.append({
                "kind": "submodule",
                "path": f"{prefix}.gitmodules",
                "detail": ".gitmodules present; submodules are refused in v1",
            })
        if ".git" in dirnames:
            _inspect_git_dir_entry(Path(dirpath) / ".git", f"{prefix}.git", rel_dir, refusals, nested_repos)
            dirnames.remove(".git")
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return refusals, nested_repos


def _inspect_git_index_and_status(
    copy_root: Path,
    refusals: List[Dict[str, str]],
) -> Tuple[Set[str], List[Dict[str, str]], Optional[str], Optional[str]]:
    tracked_files: Set[str] = set()
    dirty_paths: List[Dict[str, str]] = []
    head_sha: Optional[str] = None
    current_branch: Optional[str] = None

    stage_proc = run_git_hardened(copy_root, ["ls-files", "--stage", "-z"])
    if stage_proc.returncode == 0 and stage_proc.stdout:
        for entry in stage_proc.stdout.split(b"\x00"):
            if not entry:
                continue
            meta_and_path = entry.decode("utf-8", errors="replace").split("\t", 1)
            if len(meta_and_path) == 2:
                meta, path_str = meta_and_path
                if meta.split(" ", 1)[0] == "160000":
                    refusals.append({
                        "kind": "submodule",
                        "path": path_str,
                        "detail": "Submodule gitlink (mode 160000) in index, refused in v1",
                    })
                else:
                    tracked_files.add(path_str.replace("\\", "/"))

    if refusals:
        return tracked_files, dirty_paths, head_sha, current_branch

    head_proc = run_git_hardened(copy_root, ["rev-parse", "--verify", "HEAD"])
    if head_proc.returncode == 0:
        head_sha = head_proc.stdout.decode("utf-8", errors="replace").strip()

    br_proc = run_git_hardened(copy_root, ["symbolic-ref", "--short", "HEAD"])
    if br_proc.returncode == 0:
        current_branch = br_proc.stdout.decode("utf-8", errors="replace").strip()

    status_proc = run_git_hardened(copy_root, ["status", "--porcelain=v1", "-z", "-uall"])
    if status_proc.returncode == 0 and status_proc.stdout:
        tokens = status_proc.stdout.split(b"\x00")
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            idx += 1
            if not tok or len(tok) < 4:
                continue
            xy = tok[:2].decode("utf-8", errors="replace")
            path_str = tok[3:].decode("utf-8", errors="replace").replace("\\", "/")
            if xy[0] in ("R", "C") and idx < len(tokens):
                idx += 1  # consume rename source token
            dirty_paths.append({"status": xy, "path": path_str})

    return tracked_files, dirty_paths, head_sha, current_branch


def _inspect_git_remotes_and_branches(
    copy_root: Path,
) -> Tuple[Dict[str, str], List[Dict[str, str]], List[str]]:
    remotes: Dict[str, str] = {}
    branches: List[Dict[str, str]] = []
    local_only_branches: List[str] = []

    rem_proc = run_git_hardened(copy_root, ["remote", "-v"])
    if rem_proc.returncode == 0 and rem_proc.stdout:
        for line in rem_proc.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                remotes[parts[0]] = parts[1]

    refs_proc = run_git_hardened(
        copy_root,
        [
            "for-each-ref",
            "--format=%(refname)|%(refname:short)|%(objectname:short)|%(upstream:short)",
            "refs/heads",
            "refs/remotes",
        ],
    )
    local_heads: List[Dict[str, str]] = []
    if refs_proc.returncode == 0 and refs_proc.stdout:
        for line in refs_proc.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split("|")
            if len(parts) != 4:
                continue
            full_ref, ref_name, short_sha, upstream = parts
            if full_ref.endswith("/HEAD"):
                continue
            if full_ref.startswith("refs/heads/"):
                local_heads.append({"branch": ref_name, "sha": short_sha, "upstream": upstream})
            branches.append({"ref": ref_name, "sha": short_sha, "upstream": upstream})

    has_origin_or_upstream = bool(remotes.get("origin") or remotes.get("upstream"))
    for lh in local_heads:
        if not has_origin_or_upstream:
            local_only_branches.append(lh["branch"])
            continue
        contains_proc = run_git_hardened(
            copy_root,
            ["branch", "-r", "--contains", lh["sha"], "--list", "origin/*", "upstream/*"],
        )
        if not (
            contains_proc.returncode == 0
            and contains_proc.stdout.decode("utf-8", errors="replace").strip()
        ):
            local_only_branches.append(lh["branch"])

    return remotes, branches, local_only_branches


def inspect_git_layout(copy_root: Path) -> Dict[str, Any]:
    """Inspect Git metadata and enforce v1 layout refusals (gitfile, submodule, alternates)."""
    refusals, nested_repos = _scan_git_tree_refusals(copy_root)
    root_git = copy_root / ".git"
    has_git = root_git.is_dir() and not os.path.islink(root_git)
    tracked_files: Set[str] = set()
    dirty_paths: List[Dict[str, str]] = []
    branches: List[Dict[str, str]] = []
    remotes: Dict[str, str] = {}
    local_only_branches: List[str] = []
    head_sha: Optional[str] = None
    current_branch: Optional[str] = None

    if has_git and not refusals:
        tracked_files, dirty_paths, head_sha, current_branch = _inspect_git_index_and_status(copy_root, refusals)
        if not refusals:
            remotes, branches, local_only_branches = _inspect_git_remotes_and_branches(copy_root)

    return {
        "has_git": has_git,
        "head_sha": head_sha,
        "current_branch": current_branch,
        "tracked_files": sorted(tracked_files),
        "dirty_paths": dirty_paths,
        "remotes": remotes,
        "branches": branches,
        "local_only_branches": sorted(local_only_branches),
        "nested_repos": sorted(nested_repos),
        "layout_refused": bool(refusals),
        "layout_refusal_reasons": refusals,
    }


def _validate_scan_roots(
    folder_path: os.PathLike | str,
    source_root: Optional[os.PathLike | str],
    out_path: Optional[os.PathLike | str],
) -> Tuple[Path, Optional[Path], Optional[Path]]:
    copy_root = assert_safe_root(folder_path, role="copy")
    if os.path.islink(copy_root) or not copy_root.is_dir():
        raise SafetyError(f"Scan target must be an existing non-symlink directory: {copy_root}")

    src_lex: Optional[Path] = None
    if source_root is not None:
        src_lex = assert_disjoint_roots(source=source_root, output=copy_root)["source"]

    out_lex: Optional[Path] = None
    if out_path is not None:
        out_lex = _lexical_abs(out_path)
        assert_not_live_hermes(out_lex, role="inventory_out")
        if _is_same_or_subpath(out_lex, copy_root):
            raise SafetyError(
                f"Refusing to write inventory inside scanned copy ({out_lex} inside {copy_root}); "
                "adopt scan is strictly read-only on the scanned folder."
            )
        if src_lex is not None and _is_same_or_subpath(out_lex, src_lex):
            raise SafetyError(f"Refusing to write inventory inside source folder ({out_lex} inside {src_lex}).")
        assert_output_path_safe(out_lex, role="inventory_out", forbidden_roots=(copy_root, src_lex))
    return copy_root, src_lex, out_lex


def _classify_special_top_dir(
    dname: str,
    d_full: Path,
    d_rel: str,
    special_paths: List[Dict[str, Any]],
    kept_dirs: List[str],
) -> None:
    if dname == ".hermes":
        for sub in sorted(d_full.iterdir()) if d_full.is_dir() else []:
            sub_rel = f".hermes/{sub.name}"
            if sub.name == "plans":
                special_paths.append({
                    "path": sub_rel,
                    "kind": "hermes_plans",
                    "default_disposition": "keep_or_docs",
                })
            else:
                f_cnt, b_cnt = _collapse_junk_dir_stats(sub) if sub.is_dir() else (1, sub.lstat().st_size)
                special_paths.append({
                    "path": sub_rel,
                    "kind": "hermes_runtime",
                    "default_disposition": "archive",
                    "file_count": f_cnt,
                    "total_bytes": b_cnt,
                })
        kept_dirs.append(dname)
        return

    f_cnt, b_cnt = _collapse_junk_dir_stats(d_full)
    special_paths.append({
        "path": d_rel,
        "kind": f"special_{dname.lstrip('.')}",
        "default_disposition": "archive",
        "file_count": f_cnt,
        "total_bytes": b_cnt,
    })
    if dname != ".worktrees":
        kept_dirs.append(dname)


def _filter_walk_subdirs(
    copy_root: Path,
    src_lex: Optional[Path],
    dirpath: str,
    rel_dir: str,
    dirnames: List[str],
    tracked_set: Set[str],
    links: List[Dict[str, Any]],
    special_paths: List[Dict[str, Any]],
    junk_dirs: List[Dict[str, Any]],
    mixed_cache_dirs: List[Dict[str, Any]],
) -> List[str]:
    kept_dirs: List[str] = []
    for dname in dirnames:
        d_full = Path(dirpath) / dname
        d_rel = dname if not rel_dir else f"{rel_dir}/{dname}"
        try:
            st = os.lstat(d_full)
        except OSError:
            continue

        if stat.S_ISLNK(st.st_mode):
            links.append(classify_symlink(copy_root, d_full, source_root=src_lex))
            continue
        if dname == ".git":
            special_paths.append({"path": d_rel, "kind": "nested_git", "default_disposition": "archive"})
            continue
        if dname in SPECIAL_TOP_DIRS and not rel_dir:
            _classify_special_top_dir(dname, d_full, d_rel, special_paths, kept_dirs)
            continue
        if rel_dir == ".hermes" and dname in _HERMES_RUNTIME_SUBDIRS:
            continue
        if dname in JUNK_DIR_NAMES:
            prefix = d_rel.rstrip("/") + "/"
            t_count = sum(1 for t in tracked_set if t == d_rel or t.startswith(prefix))
            if t_count == 0:
                f_cnt, b_cnt = _collapse_junk_dir_stats(d_full)
                junk_dirs.append({
                    "path": d_rel,
                    "file_count": f_cnt,
                    "total_bytes": b_cnt,
                    "tracked_count": 0,
                })
                continue
            mixed_cache_dirs.append({
                "path": d_rel,
                "tracked_count": t_count,
                "reason": "cache-named directory contains tracked files; not collapsed as junk",
            })
        kept_dirs.append(dname)
    return kept_dirs


def _build_model_summary(
    copy_root: Path,
    files: List[Dict[str, Any]],
    serializable_dir_stats: Dict[str, Any],
    ext_histogram: Dict[str, int],
    junk_dirs: List[Dict[str, Any]],
    mixed_cache_dirs: List[Dict[str, Any]],
    special_paths: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
    secrets_flagged: List[Dict[str, Any]],
    lfs_candidates: List[Dict[str, Any]],
    plan_docs: List[str],
    git_info: Dict[str, Any],
) -> Dict[str, Any]:
    shallow_files = [
        {"path": f["path"], "size": f["size"], "tracked": f["tracked"], "secret": f["secret_placeholder"]}
        for f in files
        if f["path"].count("/") <= 1 and not f["path"].startswith(".hermes/scratch/")
    ][:120]
    return {
        "folder_name": copy_root.name,
        "total_regular_files": len(files),
        "total_regular_bytes": sum(f["size"] for f in files),
        "dir_summaries": serializable_dir_stats,
        "extension_histogram": dict(sorted(ext_histogram.items())),
        "junk_dirs": junk_dirs,
        "mixed_cache_dirs": mixed_cache_dirs,
        "special_paths": special_paths,
        "links": [
            {"path": ln["path"], "link_class": ln["link_class"], "target_rel": ln["target_rel"]}
            for ln in links
        ],
        "secrets_placeholders": [
            {"path": s["path"], "placeholder": s["placeholder"], "git_policy": "ignore"}
            for s in secrets_flagged
        ],
        "lfs_candidates": lfs_candidates[:50],
        "plan_docs": plan_docs[:50],
        "shallow_files": shallow_files,
        "git_summary": {
            "has_git": git_info["has_git"],
            "current_branch": git_info["current_branch"],
            "remotes": list(git_info["remotes"].keys()),
            "local_only_branches": git_info["local_only_branches"],
            "dirty_count": len(git_info["dirty_paths"]),
            "tracked_count": len(git_info["tracked_files"]),
        },
    }


def _discover_left_behind_secret_files(src_lex: Path, copy_root: Path) -> List[str]:
    """List secret-named regular files and symlinks in src_lex absent from copy_root (lstat only)."""
    if os.path.islink(src_lex) or not src_lex.is_dir():
        return []
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(str(src_lex), topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir_raw = os.path.relpath(dirpath, str(src_lex))
        rel_dir = "" if rel_dir_raw == "." else rel_dir_raw.replace("\\", "/")
        keep_dirs: List[str] = []
        for dname in dirnames:
            if dname == ".git":
                continue
            s_full = os.path.join(dirpath, dname)
            d_rel = dname if not rel_dir else f"{rel_dir}/{dname}"
            try:
                st = os.lstat(s_full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                if _is_secret_filename(d_rel) and not os.path.lexists(copy_root / d_rel):
                    found.append(d_rel)
                continue
            keep_dirs.append(dname)
        dirnames[:] = keep_dirs

        for fname in filenames:
            if fname == ".git":
                continue
            s_full = os.path.join(dirpath, fname)
            f_rel = fname if not rel_dir else f"{rel_dir}/{fname}"
            try:
                st = os.lstat(s_full)
            except OSError:
                continue
            if (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)) and _is_secret_filename(f_rel):
                if not os.path.lexists(copy_root / f_rel):
                    found.append(f_rel)
    return sorted(found)


def _flag_absent_secret_files(
    copy_root: Path,
    src_lex: Path | None,
    secret_files_left_behind: Sequence[str] | None,
    tracked_set: set[str],
    secrets_flagged: list[dict[str, Any]],
    secret_counter: int,
) -> list[str]:
    """Append placeholders for absent secrets, preserving scan numbering and order."""
    if secret_files_left_behind is not None:
        left_behind_list = sorted(
            {str(p).replace("\\", "/").strip("/") for p in secret_files_left_behind if str(p).strip("/")}
        )
    elif src_lex is not None:
        left_behind_list = _discover_left_behind_secret_files(src_lex, copy_root)
    else:
        left_behind_list = []

    flagged_paths: Set[str] = {s["path"] for s in secrets_flagged}
    absent_secret_paths: List[str] = list(left_behind_list)
    for t_rel in sorted(tracked_set):
        if _is_secret_filename(t_rel) and not os.path.lexists(copy_root / t_rel) and t_rel not in absent_secret_paths:
            absent_secret_paths.append(t_rel)
    for absent_rel in absent_secret_paths:
        if absent_rel in flagged_paths:
            continue
        secret_counter += 1
        secrets_flagged.append({
            "path": absent_rel,
            "placeholder": f"<secret-{secret_counter}>",
            "reasons": ["secret_filename"],
            "git_policy": "ignore",
            "left_behind": True,
        })
        flagged_paths.add(absent_rel)
    return left_behind_list


def scan_folder(
    folder_path: os.PathLike | str,
    *,
    source_root: Optional[os.PathLike | str] = None,
    out_path: Optional[os.PathLike | str] = None,
    refuse_unsupported: bool = True,
    secret_files_left_behind: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Perform a read-only inventory scan of a COPY folder.

    - Refuses if folder_path is a symlink or inside live ~/.hermes.
    - If source_root or out_path is given, verifies disjointness so the scanned folder is never mutated.
    - Refuses worktree gitfiles, submodules, and git alternates (v1).
    """
    started = time.monotonic()
    copy_root, src_lex, out_lex = _validate_scan_roots(folder_path, source_root, out_path)

    git_info = inspect_git_layout(copy_root)
    if git_info["layout_refused"] and refuse_unsupported:
        raise UnsupportedGitLayoutError(git_info["layout_refusal_reasons"])

    tracked_set: Set[str] = set(git_info["tracked_files"])
    files: List[Dict[str, Any]] = []
    empty_dirs: List[str] = []
    junk_dirs: List[Dict[str, Any]] = []
    mixed_cache_dirs: List[Dict[str, Any]] = []
    special_paths: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []
    secrets_flagged: List[Dict[str, Any]] = []
    lfs_candidates: List[Dict[str, Any]] = []
    plan_docs: List[str] = []
    hash_buckets: Dict[str, List[str]] = {}
    ext_histogram: Dict[str, int] = {}
    dir_stats: Dict[str, Dict[str, Any]] = {}
    secret_counter = 0

    for dirpath, dirnames, filenames in os.walk(str(copy_root), topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, str(copy_root)).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        if not rel_dir and ".git" in dirnames:
            dirnames.remove(".git")
        if not rel_dir and ".adopt" in dirnames and not os.path.islink(os.path.join(dirpath, ".adopt")):
            dirnames.remove(".adopt")  # Defuzz's own records from an earlier run, not project files

        dirnames[:] = _filter_walk_subdirs(
            copy_root, src_lex, dirpath, rel_dir, dirnames, tracked_set,
            links, special_paths, junk_dirs, mixed_cache_dirs,
        )
        if rel_dir and not dirnames and not filenames:
            empty_dirs.append(rel_dir)

        for fname in filenames:
            f_full = Path(dirpath) / fname
            f_rel = fname if not rel_dir else f"{rel_dir}/{fname}"
            try:
                st = os.lstat(f_full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                links.append(classify_symlink(copy_root, f_full, source_root=src_lex))
                continue
            if not stat.S_ISREG(st.st_mode):
                continue

            size = st.st_size
            mode_oct = oct(stat.S_IMODE(st.st_mode))
            is_tracked = f_rel in tracked_set
            _, ext = os.path.splitext(fname.lower())
            ext_key = ext or "<no_ext>"
            ext_histogram[ext_key] = ext_histogram.get(ext_key, 0) + 1

            top_bucket = f_rel.split("/", 1)[0] if "/" in f_rel else "."
            d_entry = dir_stats.setdefault(
                top_bucket,
                {"file_count": 0, "total_bytes": 0, "tracked_count": 0, "extensions": set()},
            )
            d_entry["file_count"] += 1
            d_entry["total_bytes"] += size
            if is_tracked:
                d_entry["tracked_count"] += 1
            d_entry["extensions"].add(ext_key)

            # A file that is secret by NAME is never opened: not sniffed, not hashed.
            secret_by_name = _is_secret_filename(f_rel)
            secret_reasons = ["secret_filename"] if secret_by_name else []
            if secret_by_name:
                is_binary = False
            else:
                is_binary, content_reasons, _complete = _sniff_file_for_secrets(f_full)
                secret_reasons.extend(content_reasons)

            placeholder: Optional[str] = None
            if secret_reasons:
                secret_counter += 1
                placeholder = f"<secret-{secret_counter}>"
                secrets_flagged.append({
                    "path": f_rel,
                    "placeholder": placeholder,
                    "reasons": sorted(set(secret_reasons)),
                    "git_policy": "ignore",
                })

            sha256 = None if secret_by_name else _sha256_nofollow(f_full)
            if sha256 and size > 0:
                hash_buckets.setdefault(sha256, []).append(f_rel)

            if ext in LFS_EXTENSIONS or (is_binary and size >= 100 * 1024):
                lfs_candidates.append({
                    "path": f_rel,
                    "size": size,
                    "ext": ext_key,
                    "tracked": is_tracked,
                })
            if _PLAN_DOC_RE.search(f_rel):
                plan_docs.append(f_rel)

            files.append({
                "path": f_rel,
                "size": size,
                "mode": mode_oct,
                "tracked": is_tracked,
                "is_binary": is_binary,
                "sha256": sha256,
                "secret_placeholder": placeholder,
            })

    left_behind_list = _flag_absent_secret_files(
        copy_root, src_lex, secret_files_left_behind, tracked_set, secrets_flagged, secret_counter,
    )

    duplicate_hashes = [
        {"sha256": h, "paths": sorted(paths)}
        for h, paths in sorted(hash_buckets.items())
        if len(paths) > 1
    ]
    serializable_dir_stats = {
        k: {
            "file_count": v["file_count"],
            "total_bytes": v["total_bytes"],
            "tracked_count": v["tracked_count"],
            "extensions": sorted(v["extensions"]),
        }
        for k, v in sorted(dir_stats.items())
    }
    model_summary = _build_model_summary(
        copy_root, files, serializable_dir_stats, ext_histogram, junk_dirs,
        mixed_cache_dirs, special_paths, links, secrets_flagged, lfs_candidates,
        plan_docs, git_info,
    )

    inventory: Dict[str, Any] = {
        "schema": 1,
        "copy_root": str(copy_root),
        "source_root": str(src_lex) if src_lex is not None else None,
        "scan_duration_ms": int((time.monotonic() - started) * 1000),
        "git": git_info,
        "files": files,
        "empty_dirs": sorted(empty_dirs),
        "junk_dirs": junk_dirs,
        "mixed_cache_dirs": mixed_cache_dirs,
        "special_paths": special_paths,
        "links": links,
        "secrets_flagged": secrets_flagged,
        "secret_files_left_behind": left_behind_list,
        "lfs_candidates": lfs_candidates,
        "plan_docs": sorted(plan_docs),
        "duplicate_hashes": duplicate_hashes,
        "extension_histogram": dict(sorted(ext_histogram.items())),
        "dir_summaries": serializable_dir_stats,
        "model_summary": model_summary,
    }
    if out_lex is not None:
        inventory_text = json.dumps(inventory, indent=2, sort_keys=False) + "\n"
        write_output_text(out_lex, inventory_text, role="inventory_out", forbidden_roots=(copy_root, src_lex))
    return inventory
