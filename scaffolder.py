"""Project template scaffolder: propose (stage, rename, options, tree), accept (check in staging, move, git init/commit, register, DB), and discard."""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, NoReturn, Optional, Tuple

from . import tool_seed, toolchk
from .child_env import CREDENTIALS_NOT_PASSED_NOTE, stripped_child_env
from .lint_env import LINT_OPTOUT_DEFAULTS, _kill_process_group
from .network_failure import NETWORK_REQUIRED_REASON, looks_like_network_failure, network_required_note
from .naming import (
    PrefixForms,
    forms_from_placeholder,
    folder_name,
    forms_from_slug,
    is_ascii_folder,
    is_binary,
    rename_path_parts,
    rename_text,
    slugify,
)
from .safety import (
    SafetyError,
    _is_same_or_subpath,
    _lexical_abs,
    GitUnavailableError,
    assert_not_live_hermes,
    ensure_git_available,
    run_git_hardened,
    safe_mkdirs,
    safe_write_bytes,
    verify_nofollow_within_root,
)
from .state_store import (
    get_template_options,
    record_project,
    record_template_options,
    save_answers,
)
from .placer import TRUST_MODE_DECLARED_ONLY, compute_rules_hash
from .templates import CheckSpec, OptionSpec, TemplateSpec, load_template, templates_root

_TREE_LINE_CAP = 400
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_GIT_AUTHOR_ARGS: Tuple[str, ...] = ("-c", "user.name=hermes-defuzz", "-c", "user.email=hermes-defuzz@localhost")
_STRIPPED_PYTHON_ENV_KEYS: Tuple[str, ...] = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX")
_BUILD_CACHE_DIR_NAMES: frozenset[str] = frozenset(
    {
        "target", "node_modules", "dist", "build", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", ".worktrees",
        ".tox", ".nox", ".turbo", ".next", ".nuxt", ".parcel-cache",
    }
)
_BUILD_CACHE_FILE_GLOBS: Tuple[str, ...] = ("*.tsbuildinfo", "*.pyc", "*.pyo", "*.pyd")


class ScaffoldError(RuntimeError):
    """Raised when scaffolding fails validation, safety checks, staging checks, git steps, or project registration."""

    def __init__(
        self,
        message: str,
        *,
        completed: Optional[List[Dict[str, Any]]] = None,
        output: str = "",
        stdout: str = "",
        stderr: str = "",
        returncode: Optional[int] = None,
        staging_dir: Optional[Path] = None,
        keep_staging: bool = False,
        cancelled: bool = False,
        reason: Optional[str] = None,
        report_error: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.completed: List[Dict[str, Any]] = list(completed) if completed else []
        self.output: str = output
        self.stdout: str = stdout
        self.stderr: str = stderr
        self.returncode: Optional[int] = returncode
        self.staging_dir: Optional[Path] = staging_dir
        self.keep_staging: bool = keep_staging
        self.cancelled: bool = cancelled
        self.reason: Optional[str] = reason
        self.report_error: Optional[str] = report_error


class ScaffoldTimeout(RuntimeError):
    """Raised when headless accept exceeds its wall-clock timeout."""

    def __init__(
        self,
        message: str = "Scaffold accept timed out",
        *,
        output: str = "",
        stdout: str = "",
        stderr: str = "",
        returncode: Optional[int] = None,
        staging_dir: Optional[Path] = None,
        keep_staging: bool = False,
        reason: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.output: str = output
        self.stdout: str = stdout
        self.stderr: str = stderr
        self.returncode: Optional[int] = returncode
        self.staging_dir: Optional[Path] = staging_dir
        self.keep_staging: bool = keep_staging
        self.reason: Optional[str] = reason


class ProjectRegistrationUnavailable(ScaffoldError):
    """The public project tool is absent; scaffolding may continue unregistered."""


# Templates whose own check was run in non-ASCII project folders and passed with the real
# tools. Every other template keeps the ASCII code identifier as its folder name.
UNICODE_FOLDER_TEMPLATES = frozenset({"cpp-golden", "dotnet-golden", "go-golden", "python-golden", "rust-golden", "ts-node-golden", "web-golden"})


def project_folder_name(template_id: str, layout: str, name: str, slug: str) -> str:
    """Folder name for a new project: the Unicode folder name where proven, else the identifier."""
    try:
        folder = folder_name(name)
    except ValueError:
        return slug
    if is_ascii_folder(folder) or layout not in ("mono", "single") or template_id not in UNICODE_FOLDER_TEMPLATES:
        return slug
    return folder


def folder_name_note(name: str, folder: str, *, proven: bool = True) -> str:
    """One plain sentence when the folder differs from a non-ASCII name; empty otherwise."""
    typed = " ".join(name.split())
    if typed.isascii() or folder == typed:
        return ""
    if folder.isascii() and not proven:
        return (
            f"The project folder will be named {folder!r}: this template is not yet tested "
            "with non-ASCII folder names."
        )
    return f"The project folder will be named {folder!r} (you typed {typed!r})."


@dataclass
class RepoPlan:
    """Staged repository plan with destination path and proposed relative tree."""

    name: str
    dest: Path
    staged: Path
    tree: List[str]
    locked_hashes: Dict[str, str] = field(default_factory=dict)
    check: Optional[CheckSpec] = None
    check_output: str = ""
    check_status: Optional[str] = None
    check_returncode: Optional[int] = None
    scaffold_rules_hash: Optional[str] = None
    # (nearest existing folder at or above dest.parent, its real path, st_dev, st_ino)
    dest_anchor: Optional[Tuple[str, str, int, int]] = None


@dataclass
class Proposal:
    """Scaffold proposal holding staged repositories, naming forms, options, and questionnaire answers."""

    template_id: str
    slug: str
    forms: PrefixForms
    repos: List[RepoPlan]
    staging_dir: Path
    answers: Dict[str, Any]
    skipped: List[str] = field(default_factory=list)
    display_name: str = ""
    locked: Tuple[str, ...] = ()
    plugin_commit: str = "unknown"
    needs: Tuple[str, ...] = ()
    options: Dict[str, str] = field(default_factory=dict)
    option_specs: Dict[str, OptionSpec] = field(default_factory=dict)
    placeholder: str = "tmpl_prefix"
    template_root: Optional[Path] = None
    folder: str = ""
    folder_note: str = ""


@dataclass
class AcceptResult:
    """Result of accepting a scaffold proposal across one or more repositories."""

    repos: List[Dict[str, Any]]
    answers_id: int
    options: Dict[str, str] = field(default_factory=dict)


def projects_root() -> Path:
    """Return the chosen projects folder via workspace_root (setting, then env var); raise if unset."""
    from .workspace_root import ensure_projects_root

    return ensure_projects_root(interactive=False, error_cls=ScaffoldError)


def _writable_stage_parent(preferred: Optional[str]) -> Optional[str]:
    """Keep TMPDIR when writable; otherwise (e.g. a read-only Hermes home) use the system temp folder."""
    if preferred is None or not os.path.isdir(preferred) or os.access(preferred, os.W_OK | os.X_OK):
        return preferred
    candidates = (
        [os.environ.get("TEMP"), os.environ.get("TMP")] if os.name == "nt" else ["/tmp", "/var/tmp", "/usr/tmp"]
    )
    for cand in candidates:
        if cand and cand != preferred and os.path.isdir(cand) and os.access(cand, os.W_OK | os.X_OK):
            return cand
    return preferred  # mkdtemp then fails and is reported as one plain line


def _check_not_live_hermes(path: os.PathLike[str] | str, role: str = "target") -> None:
    """Refuse paths inside active/custom/default Hermes home (except cache/scratch)."""
    try:
        assert_not_live_hermes(path, role=role)
    except SafetyError as exc:
        raise ScaffoldError(str(exc)) from exc


def _is_non_symlink_dir(path: Path) -> bool:
    return path.exists() and not os.path.islink(path) and path.is_dir()


def _is_non_symlink_file(path: Path) -> bool:
    return path.is_file() and not os.path.islink(path)


def _rel_posix(dirpath: str, root: Path, entry: str = "") -> str:
    rel_dir = os.path.relpath(dirpath, str(root))
    base = "" if rel_dir == "." else rel_dir.replace("\\", "/")
    if not entry:
        return base
    return f"{base}/{entry}" if base else entry


def _read_packed_ref(git_common_dir: Path, ref_name: str) -> Optional[str]:
    """Read ref_name from a git packed-refs file if present."""
    packed = git_common_dir / "packed-refs"
    try:
        if not _is_non_symlink_file(packed):
            return None
        lines = packed.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "^")):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[1] == ref_name and _HEX_SHA_RE.fullmatch(parts[0]):
            return parts[0].lower()
    return None


def _resolve_git_head_from_files(root: Path) -> Optional[str]:
    """Resolve git HEAD sha purely from .git files without invoking subprocesses."""
    dot_git = root / ".git"
    try:
        if os.path.islink(dot_git) or not dot_git.exists():
            return None
        if dot_git.is_file():
            raw_ptr = dot_git.read_text(encoding="utf-8", errors="replace").strip()
            if not raw_ptr.startswith("gitdir:"):
                return None
            git_dir = (root / raw_ptr[len("gitdir:") :].strip()).resolve()
        elif dot_git.is_dir():
            git_dir = dot_git
        else:
            return None

        commondir_file = git_dir / "commondir"
        if _is_non_symlink_file(commondir_file):
            common_rel = commondir_file.read_text(encoding="utf-8", errors="replace").strip()
            common_dir = (git_dir / common_rel).resolve() if common_rel else git_dir
        else:
            common_dir = git_dir

        current = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        for _ in range(8):
            if _HEX_SHA_RE.fullmatch(current):
                return current.lower()
            if not current.startswith("ref:"):
                return None
            ref_name = current[len("ref:") :].strip()
            if not ref_name or ".." in PurePosixPath(ref_name).parts:
                return None
            for base in (git_dir, common_dir):
                ref_file = base / ref_name
                if _is_non_symlink_file(ref_file):
                    current = ref_file.read_text(encoding="utf-8", errors="replace").strip()
                    break
            else:
                return _read_packed_ref(common_dir, ref_name)
    except OSError:
        return None
    return None


def resolve_plugin_commit(plugin_root: Optional[os.PathLike[str] | str] = None) -> str:
    """Resolve the git HEAD commit SHA of the plugin source, or 'unknown' when not a checkout."""
    root = _lexical_abs(plugin_root) if plugin_root is not None else Path(__file__).resolve().parent
    return _resolve_git_head_from_files(root) or "unknown"


def _matches_locked_glob(rel_posix: str, patterns: Sequence[str]) -> bool:
    """Return True if rel_posix matches any root-anchored locked glob pattern."""
    rel = rel_posix.strip("/")
    if not rel:
        return False
    p = PurePosixPath(rel)
    full_match = getattr(p, "full_match", None)
    for pat in patterns:
        norm_pat = pat.replace("\\", "/").strip("/")
        if not norm_pat:
            continue
        if callable(full_match):
            if full_match(norm_pat):
                return True
            if norm_pat.startswith("**/") and norm_pat[3:] and full_match(norm_pat[3:]):
                return True
            continue
        if "**" not in norm_pat:
            parts = p.parts
            pat_parts = PurePosixPath(norm_pat).parts
            if len(parts) == len(pat_parts) and all(
                fnmatch.fnmatchcase(seg, pseg) for seg, pseg in zip(parts, pat_parts)
            ):
                return True
        else:
            if fnmatch.fnmatchcase(rel, norm_pat):
                return True
            if norm_pat.startswith("**/") and norm_pat[3:] and fnmatch.fnmatchcase(rel, norm_pat[3:]):
                return True
    return False


def _matches_substitute_glob(rel_posix: str, patterns: Sequence[str]) -> bool:
    """Return True if rel_posix matches any glob pattern in patterns relative to repo root."""
    rel = rel_posix.strip("/")
    p = PurePosixPath(rel)
    for pat in patterns:
        norm_pat = pat.replace("\\", "/").strip("/")
        if not norm_pat:
            continue
        if p.match(norm_pat) or fnmatch.fnmatchcase(rel, norm_pat):
            return True
        if norm_pat.startswith("**/"):
            tail = norm_pat[3:]
            if tail and (p.match(tail) or fnmatch.fnmatchcase(rel, tail)):
                return True
    return False


def _compute_locked_hashes(repo_root: Path, locked_globs: Sequence[str]) -> Dict[str, str]:
    """Compute SHA-256 hex digests of every regular file in repo_root matching locked_globs."""
    if not locked_globs or not _is_non_symlink_dir(repo_root):
        return {}
    hashes: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(str(repo_root), topdown=True, followlinks=False):
        keep_dirs: List[str] = []
        for dname in sorted(dirnames):
            if dname == ".git":
                continue
            try:
                st = os.lstat(os.path.join(dirpath, dname))
            except OSError:
                continue
            if not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode):
                keep_dirs.append(dname)
        dirnames[:] = keep_dirs

        for fname in sorted(filenames):
            f_path = os.path.join(dirpath, fname)
            try:
                st = os.lstat(f_path)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            rel_f = _rel_posix(dirpath, repo_root, fname)
            if _matches_locked_glob(rel_f, locked_globs):
                try:
                    raw = Path(f_path).read_bytes()
                except OSError:
                    continue
                hashes[rel_f] = hashlib.sha256(raw).hexdigest()
    return dict(sorted(hashes.items()))


def _substitute_file_bytes(
    raw_bytes: bytes,
    rel_file: str,
    renamed_file_rel: str,
    substitute_in: Sequence[str],
    src_forms: PrefixForms,
    dst_forms: PrefixForms,
) -> bytes:
    """Apply prefix substitution to UTF-8 text files matching substitute_in globs."""
    if not (
        _matches_substitute_glob(rel_file, substitute_in)
        or _matches_substitute_glob(renamed_file_rel, substitute_in)
    ) or is_binary(raw_bytes):
        return raw_bytes
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes
    new_text = rename_text(text, src_forms, dst_forms)
    return new_text.encode("utf-8") if new_text != text else raw_bytes


def _stage_and_rename_repo(
    src_repo: Path,
    staged_repo: Path,
    src_forms: PrefixForms,
    dst_forms: PrefixForms,
    substitute_in: Sequence[str],
    skipped_out: Optional[List[str]] = None,
    repo_prefix: str = "",
) -> None:
    """Copy src_repo to staged_repo without following or copying symlinks, renaming paths and matching text files."""
    if not _is_non_symlink_dir(src_repo):
        raise ScaffoldError(f"Template repo source is not a valid directory: {src_repo}")
    if os.path.lexists(staged_repo):
        raise ScaffoldError(f"Staged repo directory already exists: {staged_repo}")

    staged_repo.mkdir(parents=True, exist_ok=False)
    seen_dest_dirs: Dict[str, str] = {}
    seen_dest_files: Dict[str, str] = {}

    def _record_skip(rel_entry: str) -> None:
        if skipped_out is not None:
            skipped_out.append(f"{repo_prefix}/{rel_entry}" if repo_prefix else rel_entry)

    def _ensure_staged_dir(rel_dir: str, mode_source: Optional[str] = None) -> None:
        try:
            verify_nofollow_within_root(staged_repo, rel_dir)
            dst_dir = safe_mkdirs(staged_repo, rel_dir)
        except SafetyError as exc:
            raise ScaffoldError(str(exc)) from exc
        if mode_source is not None:
            try:
                os.chmod(dst_dir, stat.S_IMODE(os.lstat(mode_source).st_mode))
            except OSError:
                pass

    for dirpath, dirnames, filenames in os.walk(str(src_repo), topdown=True, followlinks=False):
        rel_dir_posix = _rel_posix(dirpath, src_repo)
        if rel_dir_posix:
            _ensure_staged_dir(rename_path_parts(rel_dir_posix, src_forms, dst_forms), mode_source=dirpath)

        keep_dirs: List[str] = []
        for dname in sorted(dirnames):
            s_path = os.path.join(dirpath, dname)
            rel_entry = _rel_posix(dirpath, src_repo, dname)
            if dname == ".worktrees" or stat.S_ISLNK(os.lstat(s_path).st_mode):
                _record_skip(rel_entry)
                continue
            norm_dir = os.path.normpath(rename_path_parts(rel_entry, src_forms, dst_forms)).replace("\\", "/")
            if norm_dir in seen_dest_dirs and seen_dest_dirs[norm_dir] != rel_entry:
                raise ScaffoldError(
                    f"Renamed directory path collision in template repo: "
                    f"{seen_dest_dirs[norm_dir]!r} and {rel_entry!r} both map to {norm_dir!r}"
                )
            if norm_dir in seen_dest_files:
                raise ScaffoldError(
                    f"Renamed directory {rel_entry!r} -> {norm_dir!r} collides with file {seen_dest_files[norm_dir]!r}"
                )
            seen_dest_dirs[norm_dir] = rel_entry
            _ensure_staged_dir(norm_dir)
            keep_dirs.append(dname)
        dirnames[:] = keep_dirs

        for fname in sorted(filenames):
            s_path = os.path.join(dirpath, fname)
            rel_file = _rel_posix(dirpath, src_repo, fname)
            st = os.lstat(s_path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                _record_skip(rel_file)
                continue

            renamed_file_rel = rename_path_parts(rel_file, src_forms, dst_forms)
            norm_file = os.path.normpath(renamed_file_rel).replace("\\", "/")
            if norm_file in seen_dest_files:
                raise ScaffoldError(
                    f"Renamed file path collision in template repo: "
                    f"{seen_dest_files[norm_file]!r} and {rel_file!r} both map to {norm_file!r}"
                )
            if norm_file in seen_dest_dirs:
                raise ScaffoldError(
                    f"Renamed file {rel_file!r} -> {norm_file!r} collides with directory {seen_dest_dirs[norm_file]!r}"
                )
            seen_dest_files[norm_file] = rel_file

            try:
                target_check = verify_nofollow_within_root(staged_repo, norm_file)
            except SafetyError as exc:
                raise ScaffoldError(str(exc)) from exc
            if os.path.lexists(target_check):
                raise ScaffoldError(f"Destination file already exists in staging: {norm_file}")

            out_bytes = _substitute_file_bytes(
                Path(s_path).read_bytes(), rel_file, renamed_file_rel, substitute_in, src_forms, dst_forms
            )
            file_mode = stat.S_IMODE(st.st_mode)
            try:
                written = safe_write_bytes(staged_repo, norm_file, out_bytes, overwrite=False, mode=file_mode)
            except SafetyError as exc:
                raise ScaffoldError(str(exc)) from exc
            try:
                os.chmod(written, file_mode)
            except OSError:
                pass


def _resolve_template_options(
    option_specs: Mapping[str, OptionSpec],
    user_options: Optional[Mapping[str, Any]],
    *,
    template_id: str,
    db_path: Optional[Path | str] = None,
) -> Dict[str, str]:
    """Validate and resolve template option choices against OptionSpec definitions."""
    if not option_specs:
        if user_options:
            unknown = next(iter(user_options.keys()))
            raise ScaffoldError(
                f"Template {template_id!r} defines no options, but received option {unknown!r}"
            )
        return {}

    if user_options is not None:
        if not isinstance(user_options, Mapping):
            raise ScaffoldError("options must be a mapping of option_id -> choice")
        for opt_id, raw_choice in user_options.items():
            if opt_id not in option_specs:
                raise ScaffoldError(f"Unknown option {opt_id!r} for template {template_id!r}")
            spec = option_specs[opt_id]
            if not isinstance(raw_choice, str) or raw_choice not in spec.choices:
                raise ScaffoldError(
                    f"Invalid choice {raw_choice!r} for option {opt_id!r} in template {template_id!r}; "
                    f"must be one of {list(spec.choices)!r}"
                )

    saved_picks: Dict[str, str] = {}
    if db_path is not None and template_id:
        try:
            saved_picks = get_template_options(template_id, db_path=db_path)
        except Exception:
            saved_picks = {}

    resolved: Dict[str, str] = {}
    for opt_id, spec in option_specs.items():
        if user_options is not None and opt_id in user_options:
            resolved[opt_id] = str(user_options[opt_id])
        elif opt_id in saved_picks and saved_picks[opt_id] in spec.choices:
            resolved[opt_id] = saved_picks[opt_id]
        else:
            resolved[opt_id] = spec.default
    return resolved


def _line_ending(line: str) -> str:
    for ending in ("\r\n", "\n", "\r"):
        if line.endswith(ending):
            return ending
    return ""


def _rewrite_env_example_for_option(
    staged_repo: Path,
    opt_id: str,
    substituted_env_key: str,
    raw_env_key: str,
    choice: str,
) -> bool:
    """Rewrite the env_key=<choice> line in staged_repo/.env.example; return True if found and rewritten."""
    _ = opt_id
    try:
        env_path = verify_nofollow_within_root(staged_repo, ".env.example")
    except SafetyError as exc:
        raise ScaffoldError(str(exc)) from exc

    if not env_path.exists():
        return False
    if not _is_non_symlink_file(env_path):
        raise ScaffoldError(f".env.example in {staged_repo} is not a regular file")

    try:
        st = os.lstat(env_path)
        raw_text = env_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ScaffoldError(f"Failed to read .env.example in {staged_repo}: {exc}") from exc

    new_lines: List[str] = []
    matched = False
    for line in raw_text.splitlines(keepends=True):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue

        lhs, _rhs = line.split("=", 1)
        key_candidate = lhs.strip().removeprefix("export ").strip()
        if key_candidate in (substituted_env_key, raw_env_key):
            new_lines.append(f"{substituted_env_key}={choice}{_line_ending(line)}")
            matched = True
        else:
            new_lines.append(line)

    if not matched:
        return False

    updated_text = "".join(new_lines)
    if updated_text != raw_text:
        try:
            safe_write_bytes(
                staged_repo, ".env.example", updated_text.encode("utf-8"),
                overwrite=True, mode=stat.S_IMODE(st.st_mode),
            )
        except SafetyError as exc:
            raise ScaffoldError(str(exc)) from exc
    return True


def _apply_options_to_staged_repos(
    staged_repos: Sequence[Path],
    option_specs: Mapping[str, OptionSpec],
    resolved_options: Mapping[str, str],
    src_forms: PrefixForms,
    dst_forms: PrefixForms,
    *,
    template_id: str,
) -> None:
    """Apply resolved options to .env.example across staged repos; raise ScaffoldError if env_key is absent."""
    if not option_specs:
        return
    for opt_id, spec in option_specs.items():
        choice = resolved_options.get(opt_id, spec.default)
        if choice not in spec.choices:
            raise ScaffoldError(
                f"Invalid choice {choice!r} for option {opt_id!r} in template {template_id!r}"
            )
        substituted_env_key = rename_text(spec.env_key, src_forms, dst_forms)
        found_any = False
        for staged_repo in staged_repos:
            if _rewrite_env_example_for_option(
                staged_repo,
                opt_id,
                substituted_env_key,
                spec.env_key,
                choice,
            ):
                found_any = True
        if not found_any:
            raise ScaffoldError(
                f"Template {template_id!r} option {opt_id!r} requires env_key "
                f"{substituted_env_key!r} (from {spec.env_key!r}) in .env.example, but it was absent"
            )


def _build_proposed_tree(staged_repo: Path) -> List[str]:
    """Return sorted relative path entries (directories ending with '/'), capped at 400 lines total."""
    entries: List[str] = []
    for dirpath, dirnames, filenames in os.walk(str(staged_repo), topdown=True, followlinks=False):
        keep_dirs: List[str] = []
        for dname in dirnames:
            s_path = os.path.join(dirpath, dname)
            rel_d = _rel_posix(dirpath, staged_repo, dname)
            if stat.S_ISLNK(os.lstat(s_path).st_mode):
                entries.append(rel_d)
            else:
                entries.append(f"{rel_d}/")
                keep_dirs.append(dname)
        dirnames[:] = keep_dirs

        for fname in filenames:
            entries.append(_rel_posix(dirpath, staged_repo, fname))

    entries.sort()
    if len(entries) > _TREE_LINE_CAP:
        shown = _TREE_LINE_CAP - 1
        return entries[:shown] + [f"… {len(entries) - shown} more"]
    return entries


def _dest_anchor(dest: Path) -> Tuple[str, str, int, int]:
    """Identify the nearest existing folder at or above dest.parent (symlinks followed)."""
    anchor = _lexical_abs(dest).parent
    while True:
        try:
            st = os.stat(anchor)
        except FileNotFoundError:
            if anchor.parent == anchor:
                raise ScaffoldError(f"No existing folder above {dest}") from None
            anchor = anchor.parent
            continue
        except OSError as exc:
            raise ScaffoldError(f"Cannot read the projects folder {anchor}: {exc.strerror or exc}") from exc
        if not stat.S_ISDIR(st.st_mode):
            raise ScaffoldError(f"Not a folder: {anchor}")
        return (str(anchor), os.path.realpath(anchor), st.st_dev, st.st_ino)


def _changed_parent_error(dest: Path) -> ScaffoldError:
    return ScaffoldError(
        f"The projects folder for {dest} changed after the preview. Nothing was created. "
        "Run the command again to make a new preview."
    )


# --- Publishing the staged project: through folder handles, never by path --------------------
# The copy across filesystems is kit creation's handle copy (kit_scaffold._copy_tree_fd): one
# implementation, two callers.

_PUBLISH_DIR_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)
# The private folder a copy across filesystems is written into, next to the destination.
_MOVE_TMP_PREFIX = ".adopt-move-"


class _TreeChanged(Exception):
    """A folder or file being copied or removed is no longer the one that was listed."""


def _fd_identity(st: os.stat_result) -> Tuple[int, int]:
    return st.st_dev, st.st_ino


def _open_real_dir_nofollow(resolved: str) -> int:
    """Open an already-resolved absolute folder, refusing a symlink in any component."""
    fd = os.open(os.path.sep, _PUBLISH_DIR_FLAGS)
    try:
        for part in Path(resolved).parts[1:]:
            child = os.open(part, _PUBLISH_DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _fsync_dir(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:  # some filesystems cannot flush a folder; the files are flushed
        if exc.errno not in (errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL), errno.EBADF):
            raise


def _empty_dir_fd(fd: int) -> None:
    """Delete everything inside an open folder this run wrote, never following a link."""
    os.fchmod(fd, stat.S_IRWXU)
    with os.scandir(fd) as entries:
        names = [e.name for e in entries]
    for name in names:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            try:
                child = os.open(name, _PUBLISH_DIR_FLAGS, dir_fd=fd)
            except PermissionError:
                os.chmod(name, stat.S_IRWXU, dir_fd=fd)
                child = os.open(name, _PUBLISH_DIR_FLAGS, dir_fd=fd)
            try:
                if _fd_identity(os.fstat(child)) != _fd_identity(st):
                    raise _TreeChanged(name)
                _empty_dir_fd(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)


def _remove_tree_at(dir_fd: int, name: str, ident: Tuple[int, int], *, contents: bool = True) -> bool:
    """Remove the folder `name` below `dir_fd` while it is still the folder `ident`.

    With `contents`, everything inside goes too (only for a folder this run filled); without,
    only an empty folder is removed. True when it is gone.
    """
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or _fd_identity(st) != ident:
        return False
    try:
        if contents:
            fd = os.open(name, _PUBLISH_DIR_FLAGS, dir_fd=dir_fd)
            try:
                if _fd_identity(os.fstat(fd)) != ident:
                    return False
                _empty_dir_fd(fd)
            finally:
                os.close(fd)
        os.rmdir(name, dir_fd=dir_fd)
        return True
    except (OSError, _TreeChanged):
        return False


def _move_failure_reason(exc: BaseException) -> str:
    """The reason a move or copy failed, in plain words (never the raw error)."""
    if getattr(exc, "special_file", False):
        return f"it contains a special file (a socket, pipe or device), {getattr(exc, 'filename', '')}"
    if isinstance(exc, _TreeChanged):
        return "the staged project changed while it was being copied"
    if isinstance(exc, RecursionError):
        return "the project has too many nested folders"
    if isinstance(exc, OSError):
        code = exc.errno
        if code in (errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)):
            return "the destination drive is full (no space left)"
        if code in (errno.EACCES, errno.EPERM):
            return "permission was denied on the destination drive"
        if code == errno.EROFS:
            return "the destination drive is read-only"
        if code in (errno.EMFILE, errno.ENFILE):
            return "too many files are open (the project has too many nested folders)"
        if code == errno.ENAMETOOLONG:
            return "a file or folder name is too long for the destination drive"
        return f"the copy failed ({(exc.strerror or 'unknown error').lower()})"
    return "the copy failed"


def _publish_error(dest: Path, exc: BaseException) -> ScaffoldError:
    return ScaffoldError(f"Cannot move the project into {dest}: {_move_failure_reason(exc)}. Nothing was created.")


def _already_exists(dest: Path) -> ScaffoldError:
    return ScaffoldError(f"Destination already exists: {dest}")


_NAME_TAKEN = (errno.EEXIST, errno.ENOTEMPTY, errno.ENOTDIR, errno.EISDIR)


def _publish_staged_repo(plan: RepoPlan) -> None:
    """Move the staged repo into the folder pinned at preview time, through folder handles.

    The folder recorded above the destination at preview time is opened once without following
    links and checked on that handle; missing folders below it are created relative to it and
    the project is renamed with folder handles at both ends, so no path is looked up between a
    check and its use. The destination name is reserved first (an existing one is refused,
    never replaced). When the rename cannot cross filesystems (EXDEV) the project is copied by
    handle into a private `.adopt-move-<random>` folder in the destination's parent, flushed to
    disk, and renamed into place within that filesystem. A refusal before the project is in
    place removes what this run created (its copy, the reserved name, the folders it made) and
    leaves the staged project where it was; folders it could not remove are listed in the
    error's `created_dirs`.
    """
    dest = plan.dest
    pin = plan.dest_anchor
    if pin is None:
        raise _changed_parent_error(dest)
    anchor_lex, anchor_real, dev, ino = pin
    try:
        anchor_st = os.stat(anchor_lex)
    except OSError:
        raise _changed_parent_error(dest) from None
    if (anchor_st.st_dev, anchor_st.st_ino) != (dev, ino) or os.path.realpath(anchor_lex) != anchor_real:
        raise _changed_parent_error(dest)
    lex_parent = _lexical_abs(dest).parent
    try:
        rel_parts = lex_parent.relative_to(anchor_lex).parts
    except ValueError:
        raise _changed_parent_error(dest) from None
    cur_real = os.path.join(anchor_real, *rel_parts)
    name = dest.name
    staged = Path(plan.staged)
    staged_changed = ScaffoldError(f"The staged project {staged} changed after it was checked. Nothing was created.")
    fds: List[int] = []
    made: List[Tuple[int, str, Tuple[int, int], Path]] = []  # (parent handle, name, identity, path)
    in_place = False
    try:
        try:
            fd = _open_real_dir_nofollow(anchor_real)
        except OSError:
            raise _changed_parent_error(dest) from None
        fds.append(fd)
        if _fd_identity(os.fstat(fd)) != (dev, ino):
            raise _changed_parent_error(dest)
        written = Path(anchor_lex)
        for part in rel_parts:
            written = written / part
            created = False
            try:
                os.mkdir(part, dir_fd=fd)
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise _publish_error(dest, exc) from None
            ident: Optional[Tuple[int, int]] = None
            if created:
                try:
                    ident = _fd_identity(os.stat(part, dir_fd=fd, follow_symlinks=False))
                except OSError:
                    raise _changed_parent_error(dest) from None
                made.append((fd, part, ident, written))
            try:
                child = os.open(part, _PUBLISH_DIR_FLAGS, dir_fd=fd)
            except OSError:
                raise _changed_parent_error(dest) from None
            fds.append(child)
            if ident is not None and _fd_identity(os.fstat(child)) != ident:
                raise _changed_parent_error(dest)
            fd = child
        parent_fd = fd
        parent_ident = _fd_identity(os.fstat(parent_fd))

        def path_leads_here() -> bool:
            try:
                return os.path.realpath(lex_parent) == cur_real and _fd_identity(os.stat(cur_real)) == parent_ident
            except OSError:
                return False

        if not path_leads_here():
            raise _changed_parent_error(dest)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise _already_exists(dest)
        try:
            src_parent_fd = _open_real_dir_nofollow(os.path.realpath(staged.parent))
        except OSError:
            raise staged_changed from None
        fds.append(src_parent_fd)
        try:
            staged_st = os.stat(staged.name, dir_fd=src_parent_fd, follow_symlinks=False)
        except OSError:
            raise staged_changed from None
        if not stat.S_ISDIR(staged_st.st_mode):
            raise staged_changed

        def reserve() -> Tuple[int, int]:
            """Take the destination name with an empty folder: refused if anything is there."""
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                raise _already_exists(dest) from None
            except OSError as exc:
                raise _publish_error(dest, exc) from None
            return _fd_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))

        def rename_into(src_name: str, src_dir_fd: int) -> None:
            placeholder = reserve()
            try:
                if not path_leads_here():
                    raise _changed_parent_error(dest)
                os.rename(src_name, name, src_dir_fd=src_dir_fd, dst_dir_fd=parent_fd)
            except BaseException:
                _remove_tree_at(parent_fd, name, placeholder, contents=False)
                raise

        copied = False
        expected = _fd_identity(staged_st)
        try:
            rename_into(staged.name, src_parent_fd)
        except OSError as exc:
            if exc.errno in _NAME_TAKEN:
                raise _already_exists(dest) from None
            if exc.errno != errno.EXDEV:
                raise _publish_error(dest, exc) from None
            expected = _copy_staged_into(dest, parent_fd, src_parent_fd, staged.name, staged_st, rename_into)
            copied = True
        in_place = True
        try:
            landed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            moved_ok = stat.S_ISDIR(landed.st_mode) and _fd_identity(landed) == expected and path_leads_here()
        except OSError:
            moved_ok = False
        if moved_ok:
            if copied:  # the project is in place: only now delete the staged original
                _remove_tree_at(src_parent_fd, staged.name, _fd_identity(staged_st))
            return
        # The projects folder changed while the project went in: take it back out.
        if copied:
            undone = _remove_tree_at(parent_fd, name, expected)
        else:
            undone = False
            try:
                os.stat(staged.name, dir_fd=src_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    if _fd_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == expected:
                        os.rename(name, staged.name, src_dir_fd=parent_fd, dst_dir_fd=src_parent_fd)
                        undone = True
                except OSError:
                    undone = False
            except OSError:
                pass
        if undone:
            in_place = False
            raise ScaffoldError(
                f"The projects folder for {dest} changed while the project was being moved. Nothing was created. "
                "Run the command again to make a new preview."
            )
        moved = ScaffoldError(
            f"The projects folder for {dest} changed while the project was being moved. "
            f"Nothing was deleted. Check {cur_real} and remove anything you do not want."
        )
        moved.check_dir = Path(cur_real)  # type: ignore[attr-defined]
        moved.after_rename = True  # type: ignore[attr-defined]
        raise moved
    except BaseException as exc:
        if not in_place and made:
            left = _remove_made_folders(made)
            if left and not getattr(exc, "created_dirs", None):
                try:
                    exc.created_dirs = left  # type: ignore[attr-defined]
                except AttributeError:
                    pass
        raise
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _copy_staged_into(
    dest: Path,
    parent_fd: int,
    src_parent_fd: int,
    staged_name: str,
    staged_st: os.stat_result,
    rename_into: Callable[[str, int], None],
) -> Tuple[int, int]:
    """The move across filesystems: copy by handle into a private folder, then one rename.

    Returns the identity of the folder now at the destination. On any failure (including
    Ctrl-C) the private folder is deleted and nothing else is touched.
    """
    from . import kit_scaffold  # imported here: kit_scaffold imports this module

    tmp = _MOVE_TMP_PREFIX + secrets.token_hex(8)
    try:
        os.mkdir(tmp, 0o700, dir_fd=parent_fd)
        tmp_ident = _fd_identity(os.stat(tmp, dir_fd=parent_fd, follow_symlinks=False))
    except OSError as exc:
        raise _publish_error(dest, exc) from None
    try:
        s_fd = os.open(staged_name, _PUBLISH_DIR_FLAGS, dir_fd=src_parent_fd)
        try:
            if _fd_identity(os.fstat(s_fd)) != _fd_identity(staged_st):
                raise _TreeChanged(staged_name)
            t_fd = os.open(tmp, _PUBLISH_DIR_FLAGS, dir_fd=parent_fd)
            try:
                if _fd_identity(os.fstat(t_fd)) != tmp_ident:
                    raise _TreeChanged(tmp)
                kit_scaffold._copy_tree_fd(s_fd, t_fd)
                os.fchmod(t_fd, stat.S_IMODE(staged_st.st_mode))
                os.utime(t_fd, ns=(staged_st.st_atime_ns, staged_st.st_mtime_ns))
                _fsync_dir(t_fd)
            finally:
                os.close(t_fd)
        finally:
            os.close(s_fd)
        rename_into(tmp, parent_fd)
        _fsync_dir(parent_fd)
    except ScaffoldError:
        _remove_tree_at(parent_fd, tmp, tmp_ident)
        raise
    except OSError as exc:
        _remove_tree_at(parent_fd, tmp, tmp_ident)
        if exc.errno in _NAME_TAKEN and not getattr(exc, "special_file", False):
            raise _already_exists(dest) from None
        raise _publish_error(dest, exc) from None
    except (_TreeChanged, kit_scaffold._StageChanged):
        _remove_tree_at(parent_fd, tmp, tmp_ident)
        raise _publish_error(dest, _TreeChanged()) from None
    except RecursionError as exc:
        _remove_tree_at(parent_fd, tmp, tmp_ident)
        raise _publish_error(dest, exc) from None
    except BaseException:
        _remove_tree_at(parent_fd, tmp, tmp_ident)
        raise
    return tmp_ident


def _remove_made_folders(made: List[Tuple[int, str, Tuple[int, int], Path]]) -> List[Path]:
    """Remove the (empty) folders this publish created above the destination, deepest first.

    Returns the outermost ones that are still there (someone put something in them)."""
    left: List[Path] = []
    for parent_fd, part, ident, written in reversed(made):
        if _remove_tree_at(parent_fd, part, ident, contents=False):
            continue
        try:
            still = _fd_identity(os.stat(part, dir_fd=parent_fd, follow_symlinks=False)) == ident
        except OSError:
            still = False
        if still:
            left.append(written)
    return [p for p in left if not any(other != p and other in p.parents for other in left)]


def _landed_path(plan: RepoPlan) -> Path:
    """Where a moved project is: below the folder pinned at preview time, else the destination."""
    pin = plan.dest_anchor
    if pin is not None:
        try:
            rel = _lexical_abs(plan.dest).parent.relative_to(pin[0]).parts
            return Path(pin[1]).joinpath(*rel, plan.dest.name)
        except ValueError:
            pass
    return plan.dest


def _validate_single_path_component(value: str, label: str) -> str:
    """Validate that value is a non-empty single safe path component (no '/', '\\', '.', or '..')."""
    if not isinstance(value, str) or not value or value in (".", "..") or "/" in value or "\\" in value:
        raise ScaffoldError(f"Invalid {label} (must be a single safe path component): {value!r}")
    return value


def poly_dest_name(slug: str, repo_name: str, placeholder_forms: PrefixForms) -> str:
    """Compute the destination folder name for a repository in a poly-repo template."""
    _validate_single_path_component(slug, "project slug")
    _validate_single_path_component(repo_name, "template repo name")
    prefix = placeholder_forms.snake
    if repo_name == prefix:
        result = slug
    elif prefix and repo_name.startswith(f"{prefix}_"):
        remainder = repo_name[len(prefix) + 1 :].replace("_", "-").strip("-")
        if not remainder:
            raise ScaffoldError(f"Empty poly repo suffix in template repo name: {repo_name!r}")
        result = f"{slug}-{remainder}"
    else:
        try:
            kebab_repo = slugify(repo_name)
        except ValueError as exc:
            raise ScaffoldError(f"Invalid poly repo name {repo_name!r}: {exc}") from exc
        result = f"{slug}-{kebab_repo}"
    return _validate_single_path_component(result, "poly destination folder name")


def _generate_scaffold_context(
    root: Path,
    slug: str,
    *,
    template_rules: Optional[Mapping[str, Any]] = None,
) -> str:
    """Use shipped template rules (or deterministic fallback) without moving files; return rules.json hash."""
    from .agents_md import write_agents_md
    from .rules import build_deterministic_fallback_rules, validate_rules_spec
    from .scanner import scan_folder

    rules_path = verify_nofollow_within_root(root, ".adopt/rules.json")
    if rules_path.exists():
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
        validate_rules_spec(rules)
    else:
        inventory = scan_folder(root)
        if template_rules is not None:
            merged_raw: Dict[str, Any] = dict(template_rules)
            merged_raw["project_slug"] = slug
            merged_raw.setdefault("folder_rules", [])
            merged_raw.setdefault("ignore_patterns", [".adopt/place-log.json"])
            merged_raw.setdefault("lfs_patterns", [])
            try:
                rules = validate_rules_spec(merged_raw, inventory)
            except SafetyError as exc:
                raise ScaffoldError(f"Invalid template placement rules: {exc}") from exc
        else:
            rules = build_deterministic_fallback_rules(inventory)
            rules["project_slug"] = slug
        agents_path = verify_nofollow_within_root(root, "AGENTS.md")
        if agents_path.exists():
            saved = "docs/AGENTS.template.md"
            safe_write_bytes(root, saved, agents_path.read_bytes(), overwrite=False)
            docs = next((d for d in rules["declared_dirs"] if d["dir"] == "docs"), None)
            if docs is not None:
                docs["summary"] = f"Read {saved} for template instructions"
        safe_write_bytes(
            root, ".adopt/rules.json", (json.dumps(rules, indent=2) + "\n").encode("utf-8"), overwrite=False
        )
    write_agents_md(root, rules)
    return compute_rules_hash(root)


def _plan_repo_destinations(
    template: TemplateSpec,
    slug: str,
    src_forms: PrefixForms,
    dst_forms: PrefixForms,
    target_root: Path,
    folder: Optional[str] = None,
) -> List[tuple[str, str, Path, Optional[CheckSpec]]]:
    """Validate repo names and destination paths before creating staging directories."""
    repo_specs_and_dests: List[tuple[str, str, Path, Optional[CheckSpec]]] = []
    seen_dests: set[Path] = set()
    for repo_spec in template.repos:
        _validate_single_path_component(repo_spec.name, "template repo name")
        renamed_repo_name = rename_path_parts(repo_spec.name, src_forms, dst_forms)
        _validate_single_path_component(renamed_repo_name, "renamed repo name")
        dest_path = (
            target_root / (folder or slug)
            if template.layout in ("mono", "single")
            else target_root / poly_dest_name(slug, repo_spec.name, src_forms)
        )
        _check_not_live_hermes(dest_path, role="dest")
        if os.path.lexists(dest_path):
            raise ScaffoldError(f"Destination already exists: {dest_path}")
        if dest_path in seen_dests:
            raise ScaffoldError(f"Duplicate destination path in proposal: {dest_path}")
        seen_dests.add(dest_path)
        repo_specs_and_dests.append((repo_spec.name, renamed_repo_name, dest_path, repo_spec.check))
    return repo_specs_and_dests


def propose(
    template: TemplateSpec,
    name: str,
    answers: Mapping[str, Any],
    *,
    dest_root: Optional[os.PathLike[str] | str] = None,
    staging_parent: Optional[os.PathLike[str] | str] = None,
    options: Optional[Mapping[str, str]] = None,
    db_path: Optional[Path | str] = None,
) -> Proposal:
    """Stage template repositories with renamed prefix forms, apply options to .env.example, and compute tree."""
    if not hasattr(template, "options"):
        raise ScaffoldError("TemplateSpec is missing required 'options' attribute")

    try:
        slug = slugify(name)
        dst_forms = forms_from_slug(slug)
        src_forms = forms_from_placeholder(template.placeholder)
    except ValueError as exc:
        raise ScaffoldError(str(exc)) from exc
    _validate_single_path_component(slug, "project slug")
    folder = project_folder_name(template.id, template.layout, name, slug)
    _validate_single_path_component(folder, "project folder name")
    folder_note = folder_name_note(name, folder, proven=template.id in UNICODE_FOLDER_TEMPLATES)

    raw_user_options: Optional[Mapping[str, Any]] = options
    if raw_user_options is None and isinstance(answers.get("options"), Mapping):
        raw_user_options = answers["options"]

    option_specs_map: Dict[str, OptionSpec] = dict(template.options) if template.options else {}
    resolved_options = _resolve_template_options(
        option_specs_map, raw_user_options, template_id=template.id, db_path=db_path
    )

    target_root = _lexical_abs(dest_root) if dest_root is not None else _lexical_abs(projects_root())
    _check_not_live_hermes(target_root, role="dest_root")

    if staging_parent is not None:
        stage_base = _lexical_abs(staging_parent)
        _check_not_live_hermes(stage_base, role="staging_parent")
        stage_base.mkdir(parents=True, exist_ok=True)
        stage_parent_arg: Optional[str] = str(stage_base)
    else:
        stage_parent_arg = _writable_stage_parent(os.environ.get("TMPDIR") or None)

    repo_specs_and_dests = _plan_repo_destinations(template, slug, src_forms, dst_forms, target_root, folder)
    try:
        staging_dir = Path(tempfile.mkdtemp(prefix="adopt-scaffold-", dir=stage_parent_arg))
    except OSError as exc:
        where = stage_parent_arg or tempfile.gettempdir()
        raise ScaffoldError(
            f"Cannot create a staging folder in {where} ({exc.strerror or exc}); set TMPDIR to a writable folder"
        ) from exc
    skipped: List[str] = []
    try:
        staged_items: List[tuple[str, Path, Path, Optional[CheckSpec]]] = []
        multi_repo = len(repo_specs_and_dests) > 1
        for orig_repo_name, renamed_repo_name, dest_path, check_spec in repo_specs_and_dests:
            src_repo = _lexical_abs(template.root) / orig_repo_name
            try:
                staged_repo = verify_nofollow_within_root(staging_dir, renamed_repo_name)
            except SafetyError as exc:
                raise ScaffoldError(str(exc)) from exc
            _stage_and_rename_repo(
                src_repo=src_repo,
                staged_repo=staged_repo,
                src_forms=src_forms,
                dst_forms=dst_forms,
                substitute_in=template.substitute_in,
                skipped_out=skipped,
                repo_prefix=orig_repo_name if multi_repo else "",
            )
            staged_items.append((renamed_repo_name, dest_path, staged_repo, check_spec))

        if option_specs_map:
            _apply_options_to_staged_repos(
                [item[2] for item in staged_items],
                option_specs_map,
                resolved_options,
                src_forms,
                dst_forms,
                template_id=template.id,
            )

        plans = [
            RepoPlan(
                name=renamed_repo_name,
                dest=dest_path,
                staged=staged_repo,
                tree=_build_proposed_tree(staged_repo),
                locked_hashes=_compute_locked_hashes(staged_repo, template.locked),
                check=check_spec,
                dest_anchor=_dest_anchor(dest_path),
            )
            for renamed_repo_name, dest_path, staged_repo, check_spec in staged_items
        ]
    except BaseException:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    return Proposal(
        template_id=template.id,
        slug=slug,
        forms=dst_forms,
        repos=plans,
        staging_dir=staging_dir,
        answers=dict(answers),
        skipped=skipped,
        display_name=name.strip(),
        locked=tuple(template.locked),
        plugin_commit=resolve_plugin_commit(),
        needs=tuple(template.needs),
        options=dict(resolved_options),
        option_specs=option_specs_map,
        placeholder=template.placeholder,
        template_root=_lexical_abs(template.root),
        folder=folder,
        folder_note=folder_note,
    )


def default_project_create(name: str, path: str) -> str:
    """Discover and dispatch the public Desktop tool, or report an honest skip."""
    from .desktop_registration import RegistrationUnavailable, create_project

    try:
        return create_project(name, path)
    except RegistrationUnavailable as exc:
        raise ProjectRegistrationUnavailable(str(exc)) from exc


def discard(proposal: Proposal) -> None:
    """Remove the proposal's staging directory if it exists."""
    if proposal.staging_dir and os.path.lexists(proposal.staging_dir):
        shutil.rmtree(proposal.staging_dir, ignore_errors=True)


def _format_completed_note(completed: Sequence[Mapping[str, Any]]) -> str:
    """Format a suffix describing repositories already created/registered before failure."""
    if not completed:
        return ""
    paths = ", ".join(str(item.get("path", "")) for item in completed)
    return f" (already completed: {paths})"


def _raise_scaffold_error(
    message: str,
    completed: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    cause: Optional[BaseException] = None,
) -> NoReturn:
    """Raise ScaffoldError attaching any already-completed repo results and mentioning them in message."""
    comp_list = list(completed) if completed else []
    full_msg = f"{message}{_format_completed_note(comp_list)}"
    if cause is not None:
        raise ScaffoldError(full_msg, completed=comp_list) from cause
    raise ScaffoldError(full_msg, completed=comp_list)


def _check_deadline(
    clock: Callable[[], float],
    deadline: float,
    step: str,
    *,
    created_dirs: Optional[Sequence[Path]] = None,
    staging_dir: Optional[Path] = None,
    keep_staging: bool = False,
    output: str = "",
    stdout: str = "",
    stderr: str = "",
) -> float:
    """Raise ScaffoldTimeout if the monotonic clock has reached or passed deadline; return remaining seconds."""
    now = clock()
    if now >= deadline:
        note = f"; folders already created remain on disk: {', '.join(str(p) for p in created_dirs)}" if created_dirs else ""
        msg = f"Scaffold accept timed out ({step}{note})"
        if output:
            msg = f"{msg}\n{output}"
        raise ScaffoldTimeout(
            msg, output=output, stdout=stdout, stderr=stderr, staging_dir=staging_dir, keep_staging=keep_staging
        )
    return deadline - now


def _is_cancelled(cancel: Any) -> bool:
    """Return True if a cancellation token/event/callable indicates cancellation."""
    if cancel is None:
        return False
    if isinstance(cancel, bool):
        return cancel
    is_set_fn = getattr(cancel, "is_set", None)
    if callable(is_set_fn):
        return bool(is_set_fn())
    return bool(cancel()) if callable(cancel) else False


def _check_cancelled(
    cancel: Any,
    staging_dir: Path,
    *,
    step: str = "check",
    output: str = "",
    stdout: str = "",
    stderr: str = "",
    returncode: Optional[int] = None,
) -> None:
    """Raise ScaffoldError with cancelled=True and keep_staging=True when cancel is triggered."""
    if _is_cancelled(cancel):
        msg = f"Scaffold accept cancelled during {step}"
        if output:
            msg = f"{msg}:\n{output}"
        raise ScaffoldError(
            msg,
            output=output,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            staging_dir=staging_dir,
            keep_staging=True,
            cancelled=True,
        )


def _resolve_contained_check_cwd(staged_repo: Path, raw_cwd: str, *, staging_dir: Path) -> Path:
    """Resolve and verify that raw_cwd stays strictly inside staged_repo without symlink traversal."""
    if not isinstance(raw_cwd, str) or not raw_cwd.strip() or "\x00" in raw_cwd:
        raise ScaffoldError(f"Invalid check cwd {raw_cwd!r} in {staged_repo}", staging_dir=staging_dir, keep_staging=True)
    staged_lex = _lexical_abs(staged_repo)
    if not _is_non_symlink_dir(staged_lex):
        raise ScaffoldError(f"Staged repo is not a regular directory: {staged_lex}", staging_dir=staging_dir, keep_staging=True)

    cleaned = raw_cwd.strip()
    if cleaned == ".":
        return staged_lex

    norm = cleaned.replace("\\", "/")
    if (
        norm.startswith("/")
        or os.path.isabs(cleaned)
        or os.path.isabs(norm)
        or any(part in ("", ".", "..") for part in PurePosixPath(norm.strip("/")).parts)
    ):
        raise ScaffoldError(
            f"Check cwd {raw_cwd!r} escapes staged repository {staged_lex}", staging_dir=staging_dir, keep_staging=True
        )

    try:
        target_cwd = verify_nofollow_within_root(staged_lex, norm.strip("/"))
    except SafetyError as exc:
        raise ScaffoldError(
            f"Check cwd {raw_cwd!r} violates containment in {staged_lex}: {exc}",
            staging_dir=staging_dir,
            keep_staging=True,
        ) from exc

    if not _is_non_symlink_dir(target_cwd):
        raise ScaffoldError(
            f"Check cwd {raw_cwd!r} is not an existing non-symlink directory inside {staged_lex}",
            staging_dir=staging_dir,
            keep_staging=True,
        )

    if not _is_same_or_subpath(target_cwd.resolve(), staged_lex.resolve()):
        raise ScaffoldError(
            f"Check cwd {raw_cwd!r} resolves outside staged repository {staged_lex}",
            staging_dir=staging_dir,
            keep_staging=True,
        )
    return target_cwd


def _strip_build_caches(staged_repo: Path) -> None:
    """Remove build cache directories and artifacts (target/, node_modules/, dist/, etc.) from staged_repo."""
    if not _is_non_symlink_dir(staged_repo):
        return
    for dirpath, dirnames, filenames in os.walk(str(staged_repo), topdown=True, followlinks=False):
        keep_dirs: List[str] = []
        for dname in list(dirnames):
            full_d = os.path.join(dirpath, dname)
            if dname in _BUILD_CACHE_DIR_NAMES:
                try:
                    st = os.lstat(full_d)
                    if stat.S_ISLNK(st.st_mode):
                        os.unlink(full_d)
                    elif stat.S_ISDIR(st.st_mode):
                        shutil.rmtree(full_d, ignore_errors=True)
                except OSError:
                    pass
                continue
            keep_dirs.append(dname)
        dirnames[:] = keep_dirs

        for fname in filenames:
            if any(fnmatch.fnmatchcase(fname, pat) for pat in _BUILD_CACHE_FILE_GLOBS):
                try:
                    os.unlink(os.path.join(dirpath, fname))
                except OSError:
                    pass


def _decode_stream(stream: Any) -> str:
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream if isinstance(stream, str) else ""


def _combine_output(stdout: Any, stderr: Any) -> Tuple[str, str, str]:
    """Decode and combine subprocess stdout and stderr into (combined, stdout_str, stderr_str)."""
    out_str = _decode_stream(stdout)
    err_str = _decode_stream(stderr)
    parts = [p.strip() for p in (out_str, err_str) if p and p.strip()]
    return "\n".join(parts), out_str, err_str


def _run_git_step(
    git_fn: Callable[..., subprocess.CompletedProcess[bytes]],
    repo_dir: Path,
    args: Sequence[str],
    *,
    clock: Callable[[], float],
    deadline: float,
    step: str,
    created_dirs: Optional[Sequence[Path]] = None,
    completed: Optional[Sequence[Dict[str, Any]]] = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a single hardened git command within the remaining deadline."""
    remaining = _check_deadline(clock, deadline, step, created_dirs=created_dirs)
    timeout_int = max(1, int(remaining) + 1)
    try:
        proc = git_fn(repo_dir, args, timeout=timeout_int)
    except subprocess.TimeoutExpired as exc:
        note = f"; folders already created remain on disk: {', '.join(str(p) for p in created_dirs)}" if created_dirs else ""
        raise ScaffoldTimeout(f"Git command timed out during {step}: {' '.join(args)}{note}") from exc
    if proc.returncode != 0:
        detail = _decode_stream(proc.stderr).strip() or _decode_stream(proc.stdout).strip() or f"exit code {proc.returncode}"
        _raise_scaffold_error(
            f"git {' '.join(args)} failed in {repo_dir} (folder kept at {repo_dir}): {detail}",
            completed,
        )
    return proc


def _load_proposal_template_spec(proposal: Proposal) -> Optional[TemplateSpec]:
    if not proposal.template_id:
        return None
    try:
        candidate_dir = templates_root() / proposal.template_id
        if candidate_dir.is_dir():
            return load_template(candidate_dir)
    except Exception:
        pass
    return None


def _resolve_locked_globs_for_proposal(proposal: Proposal) -> Tuple[str, ...]:
    """Return locked globs from proposal or load them from the matching template.yaml if available."""
    if proposal.locked:
        return tuple(proposal.locked)
    spec = _load_proposal_template_spec(proposal)
    return tuple(spec.locked) if spec is not None else ()


def _resolve_option_specs_for_proposal(proposal: Proposal) -> Dict[str, OptionSpec]:
    """Return OptionSpec map from proposal or load it from the matching template.yaml if available."""
    if proposal.option_specs:
        return dict(proposal.option_specs)
    spec = _load_proposal_template_spec(proposal)
    return dict(spec.options) if spec is not None else {}


def _resolve_template_rules_for_proposal(proposal: Proposal) -> Optional[Dict[str, Any]]:
    """Load and substitute optional rules.json data from the template directory."""
    t_root = proposal.template_root
    if t_root is None:
        spec = _load_proposal_template_spec(proposal)
        if spec is not None:
            t_root = spec.root
    if t_root is None:
        return None
    rules_src = _lexical_abs(t_root) / "rules.json"
    if not os.path.lexists(rules_src):
        return None
    if not _is_non_symlink_file(rules_src):
        raise ScaffoldError(f"Template rules.json is not a regular file: {rules_src}")
    try:
        raw_text = rules_src.read_text(encoding="utf-8")
        src_forms = forms_from_placeholder(proposal.placeholder or "tmpl_prefix")
        substituted_text = rename_text(raw_text, src_forms, proposal.forms)
        parsed = json.loads(substituted_text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ScaffoldError(f"Invalid template rules.json in {t_root}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ScaffoldError(f"Template rules.json in {t_root} must be a JSON object")
    return parsed


def _first_plain_tool_line(report: Mapping[str, Any]) -> Optional[str]:
    """First blocked or probe-failed line written for the user (it ends with the setup hint), else None.

    Lines without the hint can carry raw command output, so they stay in the report only.
    """
    for key in ("blocked", "probe_failed"):
        lines = report.get(key)
        if isinstance(lines, Mapping):
            lines = list(lines.values())
        if not isinstance(lines, (list, tuple)):
            continue
        for line in lines:
            if (
                isinstance(line, str)
                and line.endswith(toolchk.SETUP_HINT)
                and len(line) <= 300
                and line.isprintable()
            ):
                return line
    return None


def _scaffold_preflight_error(
    proposal: Proposal, plan: RepoPlan, exc: Exception, *, seeding: bool = False,
) -> ScaffoldError:
    """Preserve diagnostic evidence; never downgrade a required gate to skipped."""
    reason = "seed-failed" if seeding else "preflight-failed"
    report = (
        dict(exc.report)
        if isinstance(exc, toolchk.PreflightError)
        else {"summary": str(exc) or type(exc).__name__, "tools": {}}
    )
    report.update(ok=False, reason=reason)
    report_error = None
    try:
        toolchk.record(report, plan.staged / ".adopt")
    except Exception:  # Diagnostics must not replace the classified gate failure.
        report_error = "report-write-failed"
    plan.check_status = "failed"
    message = f"Scaffold {reason}"
    if isinstance(exc, toolchk.PreflightError):
        tools = report.get("tools", {})
        if isinstance(tools, dict):
            names = [name for name in tools if isinstance(name, str) and _TOOL_NAME_RE.fullmatch(name)][:4]
            if names:
                message += f"; tools: {', '.join(names)}"
        if type(exc.code) is int and exc.code in {2, 3, 4}:
            message += f"; exit code {exc.code}"
        plain = _first_plain_tool_line(report)
        if plain:
            message += f". {plain}"
    if report_error:
        message += f"; {report_error}"
    return ScaffoldError(
        message, staging_dir=proposal.staging_dir, keep_staging=True, reason=reason, report_error=report_error
    )


def _preverify_accept_plans(
    proposal: Proposal, *, now_fn: Callable[[], float], deadline: float, cancel: Any,
) -> None:
    """Pre-verify all destinations are safe and absent, and all staged dirs + check cwds are valid."""
    for plan in proposal.repos:
        _check_cancelled(cancel, proposal.staging_dir, step=f"precheck {plan.name}")
        _check_deadline(now_fn, deadline, f"precheck {plan.name}", staging_dir=proposal.staging_dir, keep_staging=True)
        _check_not_live_hermes(plan.dest, role="dest")
        if os.path.lexists(plan.dest):
            raise ScaffoldError(f"Destination already exists: {plan.dest}")
        if not _is_non_symlink_dir(plan.staged):
            raise ScaffoldError(f"Staged directory missing for {plan.name}: {plan.staged}")
        if plan.dest_anchor is None:
            plan.dest_anchor = _dest_anchor(plan.dest)
        if plan.check is not None:
            _resolve_contained_check_cwd(plan.staged, plan.check.cwd, staging_dir=proposal.staging_dir)


def _refresh_proposal_options_on_accept(
    proposal: Proposal,
    options: Optional[Mapping[str, str]],
    option_specs: Mapping[str, OptionSpec],
    locked_globs: Sequence[str],
    db_path: Optional[Path | str],
) -> Dict[str, str]:
    """Resolve and apply any accept-time options overrides and recompute locked hashes."""
    effective_options: Dict[str, str] = dict(proposal.options)
    if options is None and not option_specs:
        return effective_options

    merged_input: Optional[Dict[str, Any]] = None
    if options is not None:
        if not isinstance(options, Mapping):
            raise ScaffoldError("options must be a mapping of option_id -> choice")
        merged_input = {**effective_options, **dict(options)}
    elif effective_options:
        merged_input = dict(effective_options)

    effective_options = _resolve_template_options(
        option_specs, merged_input, template_id=proposal.template_id, db_path=db_path if merged_input is None else None
    )
    if option_specs:
        src_forms = forms_from_placeholder(proposal.placeholder or "tmpl_prefix")
        _apply_options_to_staged_repos(
            [p.staged for p in proposal.repos],
            option_specs,
            effective_options,
            src_forms,
            proposal.forms,
            template_id=proposal.template_id,
        )
        if locked_globs:
            for plan in proposal.repos:
                plan.locked_hashes = _compute_locked_hashes(plan.staged, locked_globs)
    proposal.options = dict(effective_options)
    return effective_options


def _seed_and_verify_tools(proposal: Proposal, plan: RepoPlan) -> Dict[str, Any]:
    """Seed TOOLS.lock in staging and run toolchk.require before check execution."""
    had_adopt_dir = (plan.staged / ".adopt").exists()
    try:
        seed_summary = tool_seed.seed_lock(plan.staged, event="project creation", template_needs=proposal.needs)
        seeded_tools = sorted(
            set(seed_summary.get("added", []))
            | set(seed_summary.get("refreshed", []))
            | set(seed_summary.get("kept", []))
        )
    except ScaffoldTimeout:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _scaffold_preflight_error(proposal, plan, exc, seeding=True) from exc

    try:
        if seed_summary.get("probe_failed"):
            failures = seed_summary["probe_failed"]
            raise toolchk.PreflightError(
                3,
                {
                    "ok": False,
                    "summary": "preflight BLOCKED: probe failed at seeding",
                    "tools": {name: {"status": "probe-failed", "error": err} for name, err in failures.items()},
                    "probe_failed": failures,
                },
            )
        toolchk.require(list(seeded_tools), plan.staged, record_dir=plan.staged / ".adopt")
    except ScaffoldTimeout:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _scaffold_preflight_error(proposal, plan, exc) from exc

    if not had_adopt_dir and (plan.staged / ".adopt").is_dir():
        shutil.rmtree(plan.staged / ".adopt", ignore_errors=True)
    return seed_summary


def _run_staged_repo_check(
    proposal: Proposal,
    plan: RepoPlan,
    *,
    now_fn: Callable[[], float],
    deadline: float,
    cancel: Any,
    template_rules: Optional[Mapping[str, Any]] = None,
) -> Tuple[str, int, str]:
    """Execute optional prepare + check commands in staging within the shared deadline."""
    assert plan.check is not None
    check_cwd = _resolve_contained_check_cwd(plan.staged, plan.check.cwd, staging_dir=proposal.staging_dir)
    _check_cancelled(cancel, proposal.staging_dir, step=f"check {plan.name}")
    plan.scaffold_rules_hash = _generate_scaffold_context(
        plan.staged, _ascii_repo_name(proposal, plan), template_rules=template_rules
    )
    _check_deadline(now_fn, deadline, f"before check {plan.name}", staging_dir=proposal.staging_dir, keep_staging=True)

    command = plan.check.cmd
    try:
        commands = ([plan.check.prepare] if plan.check.prepare else []) + [plan.check.cmd]
        chk_proc = None
        # Shared policy (child_env.py): no HERMES_*, sudo/askpass, or credential-looking vars.
        check_env = stripped_child_env(extra_drop=_STRIPPED_PYTHON_ENV_KEYS)
        for key, value in LINT_OPTOUT_DEFAULTS.items():
            check_env.setdefault(key, value)
        for command in commands:
            _check_cancelled(cancel, proposal.staging_dir, step=f"check {plan.name}")
            remaining_check = _check_deadline(
                now_fn, deadline, f"check {plan.name}", staging_dir=proposal.staging_dir, keep_staging=True
            )
            chk_proc = _run_check_command(list(command), cwd=str(check_cwd), env=check_env,
                                          timeout=remaining_check, cancel=cancel)
            if chk_proc.returncode != 0:
                break
        assert chk_proc is not None
    except subprocess.TimeoutExpired as exc:
        combined, out_s, err_s = _combine_output(exc.stdout, exc.stderr)
        plan.check_output = combined
        plan.check_status = "timeout"
        msg = f"Check command {' '.join(command)} timed out in {plan.name}"
        if combined:
            msg = f"{msg}:\n{combined}"
        timeout_reason: Optional[str] = None
        if looks_like_network_failure(combined):
            timeout_reason = NETWORK_REQUIRED_REASON
            msg = f"{msg}\n{network_required_note(projects_untouched=_staging_outside_projects(proposal))}"
        raise ScaffoldTimeout(
            msg, output=combined, stdout=out_s, stderr=err_s, staging_dir=proposal.staging_dir, keep_staging=True,
            reason=timeout_reason,
        ) from exc
    except KeyboardInterrupt as exc:
        plan.check_status = "cancelled"
        raise ScaffoldError(
            f"Check command {' '.join(plan.check.cmd)} cancelled in {plan.name}",
            staging_dir=proposal.staging_dir,
            keep_staging=True,
            cancelled=True,
        ) from exc
    except OSError as exc:
        plan.check_output = str(exc)
        plan.check_status = "failed"
        plan.check_returncode = -1
        raise ScaffoldError(
            f"Check command {' '.join(command)} failed to execute in {plan.name}: {exc}",
            output=str(exc),
            returncode=-1,
            staging_dir=proposal.staging_dir,
            keep_staging=True,
        ) from exc

    combined, out_s, err_s = _combine_output(chk_proc.stdout, chk_proc.stderr)
    plan.check_output = combined
    plan.check_returncode = chk_proc.returncode

    _check_cancelled(
        cancel, proposal.staging_dir, step=f"check {plan.name}",
        output=combined, stdout=out_s, stderr=err_s, returncode=chk_proc.returncode,
    )

    if chk_proc.returncode != 0:
        plan.check_status = "failed"
        msg = f"Check command {' '.join(command)} failed with exit code {chk_proc.returncode} in {plan.name}"
        if combined:
            msg = f"{msg}:\n{combined}"
        msg = f"{msg}\n{CREDENTIALS_NOT_PASSED_NOTE}"
        reason: Optional[str] = None
        if looks_like_network_failure(combined):
            # Checks run in staging before any repo is moved, so the projects folder is untouched
            # unless the (kept) staging folder itself lives inside it.
            reason = NETWORK_REQUIRED_REASON
            untouched = _staging_outside_projects(proposal)
            msg = f"{msg}\n{network_required_note(projects_untouched=untouched)}"
        raise ScaffoldError(
            msg, output=combined, stdout=out_s, stderr=err_s,
            returncode=chk_proc.returncode, staging_dir=proposal.staging_dir, keep_staging=True,
            reason=reason,
        )

    _check_deadline(
        now_fn, deadline, f"after check {plan.name}", staging_dir=proposal.staging_dir,
        keep_staging=True, output=combined, stdout=out_s, stderr=err_s,
    )
    plan.check_status = "ok"
    return "ok", chk_proc.returncode, combined


_CHECK_POLL_S = 0.2  # how often a running check looks at the cancel hook


def _run_check_command(argv: List[str], *, cwd: str, env: Mapping[str, str], timeout: float,
                       cancel: Any) -> subprocess.CompletedProcess[str]:
    """Run one check command like subprocess.run(capture_output=True, text=True, timeout=...),
    in its own process group so the whole tree can be stopped.

    On timeout the group is stopped and TimeoutExpired is raised with the output so far; when
    `cancel` is set the group is stopped and KeyboardInterrupt is raised (reported as a
    cancelled check); any other interruption also stops the group before it goes on.
    """
    end = time.monotonic() + timeout
    proc = subprocess.Popen(
        argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **({} if os.name == "nt" else {"start_new_session": True}),
    )
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=max(0.0, min(_CHECK_POLL_S, end - time.monotonic())))
                return subprocess.CompletedProcess(argv, proc.returncode, out, err)
            except subprocess.TimeoutExpired:
                timed_out = time.monotonic() >= end
                if not timed_out and not _is_cancelled(cancel):
                    continue
            _kill_process_group(proc)
            try:
                out, err = proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:  # a grandchild outside the group still holds a pipe
                out, err = "", ""
            if timed_out:
                raise subprocess.TimeoutExpired(argv, timeout, output=out, stderr=err)
            raise KeyboardInterrupt  # handled by the caller as a cancelled check
    except BaseException:
        if proc.poll() is None:
            _kill_process_group(proc)
        raise
    finally:
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


def _report_progress(progress: Optional[Callable[[str], None]], phase: str) -> None:
    """Tell the caller which phase the accept is in; a failing hook never stops the accept."""
    if progress is not None:
        try:
            progress(phase)
        except Exception:
            pass


def _staging_outside_projects(proposal: Proposal) -> bool:
    """True when no destination exists yet and the staging folder is outside every destination parent."""
    try:
        stage = Path(proposal.staging_dir).resolve()
        for plan in proposal.repos:
            if os.path.lexists(plan.dest):
                return False
            parent = Path(plan.dest).parent.resolve()
            if stage == parent or parent in stage.parents:
                return False
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return True


def _init_and_commit_dest_repo(
    git: Callable[..., subprocess.CompletedProcess[bytes]],
    dest: Path,
    template_id: str,
    *,
    now_fn: Callable[[], float],
    deadline: float,
    created_dirs: Sequence[Path],
    accepted_repos: Sequence[Dict[str, Any]],
) -> str:
    """Initialize git repository at dest, configure local worktrees exclude, and create initial commit."""
    commit_msg = f"chore: scaffold from template {template_id}"
    _run_git_step(git, dest, ["init", "-q"], clock=now_fn, deadline=deadline, step="git init", created_dirs=created_dirs, completed=accepted_repos)
    exclude = dest / ".git" / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    existing_excludes = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    if ".worktrees/" not in existing_excludes.splitlines():
        prefix_nl = "\n" if existing_excludes and not existing_excludes.endswith("\n") else ""
        with exclude.open("a", encoding="utf-8") as stream:
            stream.write(f"{prefix_nl}.worktrees/\n")

    _run_git_step(git, dest, ["add", "-A"], clock=now_fn, deadline=deadline, step="git add", created_dirs=created_dirs, completed=accepted_repos)
    _run_git_step(
        git, dest, [*_GIT_AUTHOR_ARGS, "commit", "-q", "-m", commit_msg],
        clock=now_fn, deadline=deadline, step="git commit", created_dirs=created_dirs, completed=accepted_repos,
    )
    rev_proc = _run_git_step(
        git, dest, ["rev-parse", "HEAD"],
        clock=now_fn, deadline=deadline, step="git rev-parse", created_dirs=created_dirs, completed=accepted_repos,
    )
    return _decode_stream(rev_proc.stdout).strip()


def _ascii_repo_name(proposal: Proposal, plan: RepoPlan) -> str:
    """The repository's ASCII identifier, also when its folder has a Unicode name."""
    if proposal.folder and plan.dest.name == proposal.folder:
        return proposal.slug
    return plan.dest.name


def _registration_display_name(proposal: Proposal, plan: RepoPlan, multi_repo: bool) -> str:
    base_display = proposal.display_name or proposal.slug
    if not multi_repo or plan.dest.name == proposal.slug:
        return base_display
    slug_prefix = f"{proposal.slug}-"
    if plan.dest.name.startswith(slug_prefix):
        return f"{base_display} ({plan.dest.name[len(slug_prefix) :]})"
    return f"{base_display} ({plan.dest.name})"


def _attempt_project_registration(
    register: Callable[[str, str], str], reg_name: str, dest: Path,
) -> Tuple[str, Optional[str], str]:
    """Invoke register(reg_name, str(dest)) and return (status, failure_reason, hermes_project_id)."""
    registration_reason: Optional[str] = None
    registration_unavailable = False
    raw_reg: Any = None
    try:
        raw_reg = register(reg_name, str(dest))
        reg_data = json.loads(raw_reg) if isinstance(raw_reg, str) else raw_reg
    except ProjectRegistrationUnavailable as exc:
        registration_unavailable = True
        registration_reason = str(exc)
        reg_data = {}
    except Exception as exc:
        registration_reason = str(exc)
        reg_data = {}

    if registration_reason is None and (not isinstance(reg_data, dict) or not reg_data.get("success")):
        err_detail = reg_data.get("error") if isinstance(reg_data, dict) else f"unexpected response {raw_reg!r}"
        registration_reason = str(err_detail) if err_detail is not None else f"unexpected response {raw_reg!r}"
        reg_data = {}

    status = "skipped" if registration_unavailable else ("failed" if registration_reason is not None else "registered")
    hermes_project_id = str(reg_data.get("id") or "") if isinstance(reg_data, dict) else ""
    return status, registration_reason, hermes_project_id


def _run_optional_componentize_survey(accepted_repos: List[Dict[str, Any]]) -> None:
    """Run optional post-acceptance componentize survey without affecting scaffold success."""
    from . import componentize_bridge, componentize_settings

    try:
        survey_enabled = componentize_settings.load()["run_survey_on_new"]
    except Exception as exc:
        for repo in accepted_repos:
            repo["componentize"] = {"status": "skipped", "notice": f"componentize settings unavailable: {exc}"}
        return

    if not survey_enabled:
        return

    for repo in accepted_repos:
        root = Path(repo["path"])
        try:
            survey_result = componentize_bridge.survey_project(root)
            repo["componentize"] = dict(survey_result)
            if survey_result["status"] != "ok":
                repo["componentize"]["notice"] = "Optional componentize survey skipped; project creation succeeded."
                continue
            paths = [componentize_bridge.SURVEY_PATH]
            if verify_nofollow_within_root(root, "AGENTS.md").is_file():
                paths.append("AGENTS.md")
            try:
                run_git_hardened(root, ["add", "--", *paths], check=True)
                run_git_hardened(
                    root,
                    [*_GIT_AUTHOR_ARGS, "commit", "-q", "--only", "-m", "chore: record optional componentize survey", "--", *paths],
                    check=True,
                )
            except Exception:
                run_git_hardened(root, ["reset", "-q", "HEAD", "--", *paths], check=True)
                tracked = run_git_hardened(root, ["ls-files", "-z", "--", *paths], check=True).stdout
                tracked_paths = [p.decode() for p in tracked.split(b"\0") if p]
                if tracked_paths:
                    run_git_hardened(root, ["restore", "--source=HEAD", "--worktree", "--", *tracked_paths], check=True)
                run_git_hardened(root, ["clean", "-f", "--", *paths], check=True)
                raise
            repo["survey_commit"] = run_git_hardened(root, ["rev-parse", "HEAD"], check=True).stdout.decode().strip()
        except Exception as exc:
            repo["componentize"] = {
                "status": "skipped",
                "notice": f"Optional componentize survey incomplete: {exc}; project creation succeeded.",
            }


_AFTER_MOVE_NOTE = (
    "The project folder {path} was created and kept. Look at it, and delete it if you do not want it, "
    "before you try again."
)


def _mark_template_created(exc: BaseException, created_dirs: Sequence[Path]) -> BaseException:
    """Return the error to raise when accept stops after a project folder is in place.

    It carries `created_dirs` (callers read it) and says plainly that the folder exists; an
    unexpected error's own text is not shown.
    """
    paths = list(created_dirs)
    note = _AFTER_MOVE_NOTE.format(path=", ".join(str(p) for p in paths))
    if isinstance(exc, (ScaffoldError, ScaffoldTimeout)):
        message = str(exc).replace(" Nothing was created.", "").rstrip()
        exc.args = (f"{message} {note}",)
        out: BaseException = exc
    elif isinstance(exc, Exception):
        out = ScaffoldError(f"Stopped before the project was finished. {note}")
        out.__cause__ = exc
    else:  # KeyboardInterrupt and the like: keep the type, say what exists
        out = exc
    if not getattr(out, "created_dirs", None):
        try:
            out.created_dirs = paths  # type: ignore[attr-defined]
        except AttributeError:
            pass
    return out


def accept(
    proposal: Proposal,
    *,
    register: Callable[[str, str], str] = default_project_create,
    git: Callable[..., subprocess.CompletedProcess[bytes]] = run_git_hardened,
    db_path: Optional[Path | str] = None,
    timeout_s: float = 60.0,
    clock: Optional[Callable[[], float]] = None,
    plugin_root: Optional[os.PathLike[str] | str] = None,
    options: Optional[Mapping[str, str]] = None,
    cancel: Any = None,
    remember_options: bool = True,
    progress: Optional[Callable[[str], None]] = None,
) -> AcceptResult:
    """Run each repo's check in staging, then move to destination, git init + commit, register, and record in state DB.

    Any error after a project folder is in place (including Ctrl-C) carries `created_dirs`.
    `cancel` (polled, also while a check runs) stops the accept before anything is moved;
    `progress` is told the phase: 'prepare', 'check', 'move', 'register'.
    """
    created_dirs: List[Path] = []
    try:
        return _accept_template(
            proposal, register=register, git=git, db_path=db_path, timeout_s=timeout_s, clock=clock,
            plugin_root=plugin_root, options=options, cancel=cancel, remember_options=remember_options,
            created_dirs=created_dirs, progress=progress,
        )
    except BaseException as exc:
        if not created_dirs:
            raise
        out = _mark_template_created(exc, created_dirs)
        if out is exc:
            raise
        raise out from exc


def _accept_template(
    proposal: Proposal,
    *,
    register: Callable[[str, str], str] = default_project_create,
    git: Callable[..., subprocess.CompletedProcess[bytes]] = run_git_hardened,
    db_path: Optional[Path | str] = None,
    timeout_s: float = 60.0,
    clock: Optional[Callable[[], float]] = None,
    plugin_root: Optional[os.PathLike[str] | str] = None,
    options: Optional[Mapping[str, str]] = None,
    cancel: Any = None,
    remember_options: bool = True,
    created_dirs: List[Path],
    progress: Optional[Callable[[str], None]] = None,
) -> AcceptResult:
    """The body of `accept`; appends each project folder to `created_dirs` once it is in place."""
    now_fn = clock if clock is not None else time.monotonic
    deadline = now_fn() + float(timeout_s)

    if timeout_s <= 0:
        raise ScaffoldTimeout("Scaffold accept timeout_s must be positive", staging_dir=proposal.staging_dir, keep_staging=True)

    _check_cancelled(cancel, proposal.staging_dir, step="start")
    _check_deadline(now_fn, deadline, "start", staging_dir=proposal.staging_dir, keep_staging=True)
    _report_progress(progress, "prepare")

    if not proposal.repos:
        raise ScaffoldError("Proposal contains no repositories to accept")

    if git is run_git_hardened:
        # Git is needed after the project is moved into place; check it before anything runs.
        try:
            ensure_git_available()
        except GitUnavailableError as exc:
            raise ScaffoldError(f"{exc}. Nothing was created.", staging_dir=proposal.staging_dir) from exc

    _preverify_accept_plans(proposal, now_fn=now_fn, deadline=deadline, cancel=cancel)

    locked_globs = _resolve_locked_globs_for_proposal(proposal)
    option_specs = _resolve_option_specs_for_proposal(proposal)
    effective_options = _refresh_proposal_options_on_accept(proposal, options, option_specs, locked_globs, db_path)
    template_rules = _resolve_template_rules_for_proposal(proposal)

    staged_outcomes: List[Dict[str, Any]] = []
    for plan in proposal.repos:
        _check_cancelled(cancel, proposal.staging_dir, step=f"before check {plan.name}")
        _check_deadline(now_fn, deadline, f"before seed {plan.name}", staging_dir=proposal.staging_dir, keep_staging=True)
        seed_summary = _seed_and_verify_tools(proposal, plan)

        check_status: Optional[str] = None
        check_returncode: Optional[int] = None
        check_output: str = ""
        if plan.check is not None:
            _report_progress(progress, "check")
            check_status, check_returncode, check_output = _run_staged_repo_check(
                proposal,
                plan,
                now_fn=now_fn,
                deadline=deadline,
                cancel=cancel,
                template_rules=template_rules,
            )

        _strip_build_caches(plan.staged)
        if check_status != "ok":
            plan.scaffold_rules_hash = _generate_scaffold_context(
                plan.staged, _ascii_repo_name(proposal, plan), template_rules=template_rules
            )

        staged_outcomes.append(
            {
                "seed_summary": seed_summary,
                "check_status": check_status,
                "check_returncode": check_returncode,
                "check_output": check_output,
            }
        )

    accepted_repos: List[Dict[str, Any]] = []
    multi_repo = len(proposal.repos) > 1
    effective_plugin_commit = (
        resolve_plugin_commit(plugin_root)
        if plugin_root is not None
        else (
            proposal.plugin_commit
            if proposal.plugin_commit and proposal.plugin_commit != "unknown"
            else resolve_plugin_commit()
        )
    )
    substituted_prefix = proposal.forms.snake

    _check_cancelled(cancel, proposal.staging_dir, step="before move")
    _report_progress(progress, "move")  # from here on a cancel is too late
    for plan, outcome in zip(proposal.repos, staged_outcomes):
        _check_deadline(now_fn, deadline, f"before move {plan.name}", created_dirs=created_dirs)
        if os.path.lexists(plan.dest):
            _raise_scaffold_error(f"Destination already exists: {plan.dest}", accepted_repos)

        try:
            _publish_staged_repo(plan)
        except ScaffoldError as exc:
            # Folders the publish made above the destination and could not remove stay listed.
            created_dirs.extend(Path(p) for p in (getattr(exc, "created_dirs", None) or []))
            if getattr(exc, "after_rename", False) or not os.path.lexists(plan.staged):
                # it left staging (or a copy landed): it may be in place, or wherever the folder went
                landed = _landed_path(plan)
                check_dir = getattr(exc, "check_dir", None)
                if check_dir is not None and not os.path.lexists(landed):
                    # Not where it was expected: the message names the folder to check, and so
                    # does created_dirs (no "created and kept" claim about a path that is empty).
                    moved = ScaffoldError(f"{exc}{_format_completed_note(accepted_repos)}", completed=list(accepted_repos))
                    moved.created_dirs = [Path(check_dir)]  # type: ignore[attr-defined]
                    raise moved from exc
                created_dirs.append(landed)
            _raise_scaffold_error(str(exc), accepted_repos, cause=exc)
        created_dirs.append(plan.dest)

        seed_summary = outcome["seed_summary"]
        if isinstance(seed_summary, dict):
            seed_summary = {**seed_summary, "written": str(plan.dest / "TOOLS.lock")}
        check_status = outcome["check_status"]
        check_returncode = outcome["check_returncode"]
        check_output = outcome["check_output"]

        commit_sha = _init_and_commit_dest_repo(
            git, plan.dest, proposal.template_id,
            now_fn=now_fn, deadline=deadline, created_dirs=created_dirs, accepted_repos=accepted_repos,
        )

        _check_deadline(now_fn, deadline, f"before register {plan.name}", created_dirs=created_dirs)
        _report_progress(progress, "register")
        reg_name = _registration_display_name(proposal, plan, multi_repo)
        reg_status, registration_reason, hermes_project_id = _attempt_project_registration(register, reg_name, plan.dest)
        _check_deadline(now_fn, deadline, f"after register {plan.name}", created_dirs=created_dirs)

        locked_hashes = _compute_locked_hashes(plan.dest, locked_globs) if locked_globs else dict(plan.locked_hashes)
        try:
            current_rules_hash: Optional[str] = compute_rules_hash(plan.dest)
        except Exception:
            current_rules_hash = None
        verified_rules_hash = (
            current_rules_hash
            if plan.scaffold_rules_hash and current_rules_hash == plan.scaffold_rules_hash
            else None
        )
        try:
            record_project(
                path=plan.dest,
                name=reg_name,
                slug=_ascii_repo_name(proposal, plan),
                template_id=proposal.template_id,
                answers=proposal.answers,
                hermes_project_id=hermes_project_id,
                db_path=db_path,
                rules_hash=verified_rules_hash,
                plugin_commit=effective_plugin_commit,
                prefix=substituted_prefix,
                locked_hashes=locked_hashes,
                trust_mode=TRUST_MODE_DECLARED_ONLY if verified_rules_hash else None,
            )
        except Exception as exc:
            _raise_scaffold_error(
                "Could not save the new project in the project list.",
                accepted_repos,
                cause=exc,
            )
        _check_deadline(now_fn, deadline, f"after record_project {plan.name}", created_dirs=created_dirs)

        repo_entry: Dict[str, Any] = {
            "path": str(plan.dest),
            "registration": reg_status,
            "registration_result": {"registered": registration_reason is None, "reason": registration_reason},
            "registration_name": reg_name,
            "hermes_project_id": hermes_project_id,
            "commit": commit_sha,
            "template_id": proposal.template_id,
            "plugin_commit": effective_plugin_commit,
            "prefix": substituted_prefix,
            "locked_hashes": locked_hashes,
        }
        if registration_reason is not None:
            repo_entry["registration_reason"] = registration_reason
        if effective_options:
            repo_entry["options"] = dict(effective_options)
        if seed_summary is not None:
            repo_entry["tools_lock"] = seed_summary
        if check_status is not None:
            repo_entry["check"] = check_status
        if check_returncode is not None:
            repo_entry["returncode"] = check_returncode
            repo_entry["check_returncode"] = check_returncode
        if check_output:
            repo_entry["check_output"] = check_output
            repo_entry["output"] = check_output
        accepted_repos.append(repo_entry)

    answers_id = save_answers(proposal.answers, project_path=str(proposal.repos[0].dest), db_path=db_path)
    if remember_options and effective_options and proposal.template_id:
        record_template_options(proposal.template_id, effective_options, db_path=db_path)
    _check_deadline(now_fn, deadline, "after save_answers", created_dirs=created_dirs)

    discard(proposal)
    _run_optional_componentize_survey(accepted_repos)
    return AcceptResult(repos=accepted_repos, answers_id=answers_id, options=dict(effective_options))
