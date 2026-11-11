"""Projects folder setting, validation, resolution order, and first-run terminal prompt.

Invariants:
- Nothing is created or written on import or plugin registration.
- Validation never creates folders or files; the projects folder is created only when
  a project is actually accepted/created.
- Non-terminal runs never guess a default folder and never block waiting for input.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, List, Optional, Tuple, Type

from .safety import (
    SafetyError,
    _is_same_or_subpath,
    _lexical_abs,
    assert_safe_root,
    resolve_hermes_home,
)
from .structure_check import (
    INDEX_ASSET_DIRS,
    STATIC_CONTAINER_NAMES,
    _has_manifest,
    _markers_for,
)

PLUGIN_ID = "defuzz"
SETTING_KEY = "projects_root"
ENV_VAR = "HERMES_PROJECTS_ROOT"
DEFAULT_FOLDER_NAME = "Tools"

_UNSET = object()

SYSTEM_TREE_ROOTS: Tuple[str, ...] = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/opt",
    "/proc",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/usr",
)

NON_TERMINAL_UNSET_MESSAGE = (
    "No projects folder has been chosen yet. "
    "Run `hermes defuzz folder set ~/Tools` in your terminal to choose where new projects go "
    "(or pass `--root <folder>` or set `HERMES_PROJECTS_ROOT` for one command). "
    "Nothing was created."
)


class WorkspaceRootError(ValueError):
    """Raised when the projects folder has not been chosen or fails safety validation."""


@dataclass(frozen=True)
class ResolvedRoot:
    """Resolved projects folder state: `(path, source, message)`."""

    path: Optional[Path]
    source: str  # "cli" | "setting" | "env" | "unset"
    message: str = ""


def _effective_home(
    home: Optional[os.PathLike[str] | str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    if home is not None:
        raw_h = os.fspath(home).strip()
        if raw_h:
            return Path(os.path.abspath(raw_h))
    if env is not None:
        env_home = str(env.get("HOME") or env.get("USERPROFILE") or "").strip()
        if env_home:
            return Path(os.path.abspath(env_home))
    return _process_home()


def _process_home() -> Path:
    """Return this process's home folder; an empty HOME never becomes the filesystem root."""
    env_home = os.environ.get("HOME")
    if env_home is not None and env_home.strip():
        return Path(os.path.abspath(env_home.strip()))
    if os.name == "nt":
        expanded = os.path.expanduser("~")
        if expanded != "~":
            return Path(os.path.abspath(expanded))
    else:
        try:
            import pwd

            account_home = pwd.getpwuid(os.getuid()).pw_dir.strip()
        except (ImportError, KeyError, OSError):
            account_home = ""
        if account_home and os.path.isabs(account_home) and Path(account_home) != Path(account_home).parent:
            return Path(os.path.abspath(account_home))
    raise WorkspaceRootError(
        "Cannot find your home folder (HOME is empty or unset). "
        f"Set HOME, or set {ENV_VAR} to a full path."
    )


def default_projects_root(
    *,
    home: Optional[os.PathLike[str] | str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    """Return `<home>/Tools` without creating anything on disk."""
    return _effective_home(home=home, env=env) / DEFAULT_FOLDER_NAME


def _effective_hermes_home(
    ctx: Any = None,
    *,
    home: Optional[os.PathLike[str] | str] = None,
    hermes_home: Optional[os.PathLike[str] | str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    if hermes_home is not None:
        return Path(os.path.abspath(os.fspath(hermes_home)))
    if env is not None:
        raw_hh = str(env.get("HERMES_HOME") or "").strip()
        if raw_hh:
            eff_h = _effective_home(home=home, env=env)
            expanded = _expand_tilde(raw_hh, eff_h)
            return Path(os.path.abspath(expanded))
        return _effective_home(home=home, env=env) / ".hermes"
    return Path(os.path.abspath(os.fspath(resolve_hermes_home(ctx=ctx))))


def _expand_tilde(raw: str, eff_home: Path) -> str:
    if raw == "~":
        return str(eff_home)
    if raw.startswith("~/") or (os.name == "nt" and raw.startswith("~\\")):
        return os.path.join(str(eff_home), raw[2:])
    if raw.startswith("~"):
        expanded = os.path.expanduser(raw)
        if expanded.startswith("~"):
            raise WorkspaceRootError(
                f"Cannot expand home folder in {raw!r}. "
                f"Use a full path such as {eff_home / DEFAULT_FOLDER_NAME}."
            )
        return expanded
    return raw


def _protected_hermes_dirs(
    ctx: Any = None,
    *,
    eff_home: Path,
    eff_hermes_home: Path,
    use_process_env: bool,
) -> List[Path]:
    raw_dirs: List[Path] = [eff_hermes_home, eff_home / ".hermes"]
    if eff_hermes_home.parent.name == "profiles":
        raw_dirs.append(eff_hermes_home.parent.parent)
    if use_process_env:
        try:
            from hermes_constants import get_default_hermes_root, get_hermes_home

            raw_dirs.append(Path(get_hermes_home()))
            raw_dirs.append(Path(get_default_hermes_root()))
        except Exception:  # noqa: BLE001
            pass
        env_hh = os.environ.get("HERMES_HOME", "").strip()
        if env_hh:
            raw_dirs.append(Path(os.path.expanduser(env_hh)))

    out: List[Path] = []
    seen: set[str] = set()
    for d in raw_dirs:
        for variant in (_lexical_abs(d), Path(os.path.realpath(os.fspath(d)))):
            key = str(variant)
            if key not in seen:
                seen.add(key)
                out.append(variant)
    return out


def _is_system_folder(candidate: Path, eff_home: Path) -> bool:
    for root_str in SYSTEM_TREE_ROOTS:
        sys_lex = Path(root_str)
        if _is_same_or_subpath(candidate, sys_lex):
            return True
        try:
            sys_real = Path(os.path.realpath(root_str))
            if sys_real != Path("/") and _is_same_or_subpath(candidate, sys_real):
                return True
        except OSError:
            pass

    home_variants = {eff_home, Path(os.path.realpath(os.fspath(eff_home)))}
    root_home = Path("/root")
    if root_home not in home_variants and _is_same_or_subpath(candidate, root_home):
        return True

    for tmp_exact in ("/tmp", "/var/tmp"):
        tp = Path(tmp_exact)
        if candidate == tp:
            return True
        try:
            tp_real = Path(os.path.realpath(tmp_exact))
            if tp_real != Path("/") and candidate == tp_real:
                return True
        except OSError:
            pass

    for var_prefix in ("/var", "/private/var"):
        vp = Path(var_prefix)
        if _is_same_or_subpath(candidate, vp):
            # Allow OS temp subdirectories (e.g. /var/tmp/<subpath>, macOS /var/folders/<subpath>)
            # while refusing /var itself and system state (/var/lib, /var/log, /var/cache, etc.).
            for allowed_sub in (vp / "tmp", vp / "folders"):
                if candidate != allowed_sub and _is_same_or_subpath(candidate, allowed_sub):
                    return False
            return True

    return False


def _dir_project_markers(directory: Path) -> List[str]:
    """Return top-level project markers in `directory` using structure_check's rules (read-only)."""
    names_nondir: set[str] = set()
    dir_names: set[str] = set()
    has_git = False
    try:
        with os.scandir(directory) as it:
            for entry in it:
                name = entry.name
                if name == ".git":
                    has_git = True
                try:
                    is_link = entry.is_symlink()
                    is_dir = (not is_link) and entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if is_dir:
                    dir_names.add(name)
                else:
                    names_nondir.add(name)
    except OSError:
        return []

    markers = _markers_for(names_nondir, dir_names, has_git, True)
    if "pnpm-workspace.yaml" in names_nondir and "pnpm-workspace.yaml" not in markers:
        markers.append("pnpm-workspace.yaml")
    if ".adopt" in dir_names and os.path.lexists(directory / ".adopt" / "rules.json"):
        markers.append(".adopt/rules.json")
    if not _has_manifest(markers) and "index.html" in names_nondir:
        own_name = directory.name
        asset = next((d for d in INDEX_ASSET_DIRS if d in dir_names), None)
        if asset and own_name not in STATIC_CONTAINER_NAMES:
            markers.append(f"index.html+{asset}")
    markers.sort()
    return markers


def _check_not_inside_existing_project(
    lex_path: Path,
    real_path: Path,
    eff_home: Path,
    env: Optional[Mapping[str, str]] = None,
) -> None:
    eff_home_real = Path(os.path.realpath(os.fspath(eff_home)))
    raw_tmp = (
        str(env.get("TMPDIR") or "")
        if env is not None
        else os.environ.get("TMPDIR", "")
    ).strip()
    tmp_bounds: List[Path] = []
    if raw_tmp:
        tmp_bounds.extend([_lexical_abs(raw_tmp), Path(os.path.realpath(raw_tmp))])

    checked: set[str] = set()
    suggestion = eff_home / DEFAULT_FOLDER_NAME
    for cand in (lex_path, real_path):
        for ancestor in (cand, *cand.parents):
            if ancestor == Path("/") or ancestor.parent == ancestor:
                break
            if _is_same_or_subpath(eff_home, ancestor) or _is_same_or_subpath(eff_home_real, ancestor):
                break
            if any(
                _is_same_or_subpath(cand, tb) and _is_same_or_subpath(tb, ancestor)
                for tb in tmp_bounds
            ):
                break
            key = str(ancestor)
            if key in checked:
                continue
            checked.add(key)
            try:
                st = os.lstat(ancestor)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                continue
            markers = _dir_project_markers(ancestor)
            if markers:
                marker_desc = markers[0]
                if ancestor in (lex_path, real_path):
                    raise WorkspaceRootError(
                        f"Cannot use {lex_path} because it is already a project ({marker_desc} found). "
                        f"Choose a parent folder that holds separate projects, such as {suggestion}."
                    )
                raise WorkspaceRootError(
                    f"Cannot use {lex_path} because it is inside an existing project "
                    f"({ancestor}, which has {marker_desc}). "
                    f"Choose a separate folder such as {suggestion}."
                )


def _dir_is_writable(directory: Path) -> bool:
    try:
        st = os.stat(directory)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return False
    if hasattr(os, "geteuid") and os.geteuid() == 0 and (st.st_mode & 0o222) == 0:
        return False
    return os.access(directory, os.W_OK | os.X_OK)


def _check_creatable_and_writable(lex_path: Path, eff_home: Path) -> None:
    suggestion = eff_home / DEFAULT_FOLDER_NAME
    cur = lex_path
    while not os.path.lexists(cur):
        parent = cur.parent
        if parent == cur:
            raise WorkspaceRootError(
                f"Cannot create {lex_path}: no writable parent folder exists."
            )
        cur = parent

    if cur == lex_path:
        if os.path.islink(cur):
            raise WorkspaceRootError(
                f"Cannot use {lex_path} because it is a symbolic link. "
                "Choose the real folder instead."
            )
        if not cur.is_dir():
            raise WorkspaceRootError(
                f"Cannot use {lex_path} because a file already exists at that path."
            )
        if not _dir_is_writable(cur):
            raise WorkspaceRootError(
                f"Cannot use {lex_path} because that folder is not writable. "
                f"Check its permissions or choose a folder such as {suggestion}."
            )
        return

    if not cur.is_dir():
        raise WorkspaceRootError(
            f"Cannot create {lex_path} because {cur} is not a folder."
        )
    if not _dir_is_writable(cur):
        raise WorkspaceRootError(
            f"Cannot create {lex_path} because its parent folder ({cur}) is not writable."
        )


def validate_projects_root(
    raw_path: os.PathLike[str] | str,
    *,
    allow_relative: bool = False,
    source_label: str = "projects folder",
    ctx: Any = None,
    env: Optional[Mapping[str, str]] = None,
    home: Optional[os.PathLike[str] | str] = None,
    hermes_home: Optional[os.PathLike[str] | str] = None,
    cwd: Optional[os.PathLike[str] | str] = None,
) -> Path:
    """Validate `raw_path` without creating anything on disk; return normalized absolute Path."""
    if isinstance(raw_path, os.PathLike):
        raw_str = os.fspath(raw_path)
    elif isinstance(raw_path, str):
        raw_str = raw_path
    else:
        raise WorkspaceRootError("Choose a folder path (expected text path).")

    cleaned = raw_str.strip()
    if not cleaned:
        raise WorkspaceRootError("Choose a folder path (the value was empty).")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise WorkspaceRootError("Choose a normal folder path without control characters.")

    eff_home = _effective_home(home=home, env=env)
    suggestion = eff_home / DEFAULT_FOLDER_NAME
    expanded = _expand_tilde(cleaned, eff_home)

    if not os.path.isabs(expanded):
        if not allow_relative:
            raise WorkspaceRootError(
                f"The {source_label} {cleaned!r} must be a full path "
                f"(for example {suggestion})."
            )
        base_cwd = Path(cwd) if cwd is not None else Path.cwd()
        expanded = os.path.join(os.fspath(base_cwd), expanded)

    lex_path = Path(os.path.abspath(expanded))
    stripped_raw = expanded.rstrip("/" + os.sep) or expanded
    if os.path.islink(lex_path) or (stripped_raw and os.path.islink(stripped_raw)):
        raise WorkspaceRootError(
            f"Cannot use {lex_path} because it is a symbolic link. "
            "Choose the real folder instead."
        )

    real_path = Path(os.path.realpath(os.fspath(lex_path)))
    eff_home_real = Path(os.path.realpath(os.fspath(eff_home)))

    for cand in (lex_path, real_path):
        if cand == Path("/") or cand.parent == cand:
            raise WorkspaceRootError(
                f"Cannot use / as the projects folder. Choose a folder such as {suggestion}."
            )
        if cand in (eff_home, eff_home_real):
            raise WorkspaceRootError(
                f"Cannot use your home folder ({eff_home}) directly because it holds many unrelated files. "
                f"Choose a subfolder such as {suggestion}."
            )
        if _is_same_or_subpath(eff_home, cand) or _is_same_or_subpath(eff_home_real, cand):
            raise WorkspaceRootError(
                f"Cannot use {lex_path} because it contains your home folder. "
                f"Choose a subfolder such as {suggestion}."
            )

    use_process_env = home is None and hermes_home is None and env is None
    eff_hh = _effective_hermes_home(ctx=ctx, home=home, hermes_home=hermes_home, env=env)
    protected_hermes = _protected_hermes_dirs(
        ctx=ctx,
        eff_home=eff_home,
        eff_hermes_home=eff_hh,
        use_process_env=use_process_env,
    )
    for cand in (lex_path, real_path):
        for hh in protected_hermes:
            if _is_same_or_subpath(cand, hh):
                raise WorkspaceRootError(
                    f"Cannot put projects inside the Hermes settings folder ({hh}). "
                    f"Choose a separate folder such as {suggestion}."
                )

    if use_process_env:
        try:
            assert_safe_root(lex_path, role="projects_root", ctx=ctx, protected_roots=protected_hermes)
        except SafetyError as exc:
            raise WorkspaceRootError(str(exc)) from exc

    for cand in (lex_path, real_path):
        if _is_system_folder(cand, eff_home):
            raise WorkspaceRootError(
                f"Cannot use system folder {lex_path} as the projects folder. "
                f"Choose a folder in your home directory such as {suggestion}."
            )

    _check_not_inside_existing_project(lex_path, real_path, eff_home, env=env)
    _check_creatable_and_writable(lex_path, eff_home)
    return lex_path


def _extract_plugin_setting_from_mapping(config_doc: Any) -> Any:
    if not isinstance(config_doc, Mapping):
        return _UNSET
    plugins_map = config_doc.get("plugins")
    if not isinstance(plugins_map, Mapping):
        return _UNSET
    entries_map = plugins_map.get("entries")
    if not isinstance(entries_map, Mapping):
        return _UNSET
    entry = entries_map.get(PLUGIN_ID)
    if not isinstance(entry, Mapping):
        return _UNSET
    for section_name in ("settings", "config"):
        sec = entry.get(section_name)
        if isinstance(sec, Mapping) and SETTING_KEY in sec:
            return sec[SETTING_KEY]
    return _UNSET


def _read_saved_setting(
    ctx: Any = None,
    *,
    home: Optional[os.PathLike[str] | str] = None,
    hermes_home: Optional[os.PathLike[str] | str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Any:
    """Read `plugins.entries.defuzz.settings.projects_root` without creating any files or directories."""
    if ctx is not None and hasattr(ctx, "get_config"):
        val = ctx.get_config(SETTING_KEY, _UNSET)
        if val is not _UNSET:
            return val
        return None

    explicit_scope = hermes_home is not None or env is not None
    if not explicit_scope:
        try:
            from hermes_cli.config import read_raw_config_readonly

            raw_cfg = read_raw_config_readonly()
            val = _extract_plugin_setting_from_mapping(raw_cfg)
            return None if val is _UNSET else val
        except Exception:  # noqa: BLE001
            pass

    eff_hh = _effective_hermes_home(ctx=ctx, home=home, hermes_home=hermes_home, env=env)
    cfg_file = eff_hh / "config.yaml"
    if not cfg_file.is_file() or cfg_file.is_symlink():
        return None
    try:
        import yaml

        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8-sig"))
    except Exception:  # noqa: BLE001
        return None
    val = _extract_plugin_setting_from_mapping(data)
    return None if val is _UNSET else val


def _with_projects_root_in_doc(base_doc: Mapping[str, Any], value: str) -> dict[str, Any]:
    doc: dict[str, Any] = dict(base_doc)
    raw_plugins = doc.get("plugins")
    plugins_sec: dict[str, Any] = dict(raw_plugins) if isinstance(raw_plugins, Mapping) else {}
    raw_entries = plugins_sec.get("entries")
    entries_sec: dict[str, Any] = dict(raw_entries) if isinstance(raw_entries, Mapping) else {}
    raw_defuzz = entries_sec.get(PLUGIN_ID)
    defuzz_sec: dict[str, Any] = dict(raw_defuzz) if isinstance(raw_defuzz, Mapping) else {}
    raw_settings = defuzz_sec.get("settings")
    settings_sec: dict[str, Any] = dict(raw_settings) if isinstance(raw_settings, Mapping) else {}
    settings_sec[SETTING_KEY] = value
    defuzz_sec["settings"] = settings_sec
    entries_sec[PLUGIN_ID] = defuzz_sec
    plugins_sec["entries"] = entries_sec
    doc["plugins"] = plugins_sec
    return doc


def _write_setting_to_yaml_file(cfg_file: Path, value: str) -> None:
    import yaml

    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, Any] = {}
    if cfg_file.exists():
        if cfg_file.is_symlink():
            raise WorkspaceRootError(f"Refusing to write symlinked config file: {cfg_file}")
        raw_text = cfg_file.read_text(encoding="utf-8-sig")
        loaded = yaml.safe_load(raw_text) if raw_text.strip() else {}
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise WorkspaceRootError(f"Settings file {cfg_file} is not a YAML mapping.")
        existing = dict(loaded)

    updated = _with_projects_root_in_doc(existing, value)

    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(cfg_file.parent),
            prefix=".defuzz-cfg-",
            delete=False,
        ) as fh:
            tmp_path = fh.name
            yaml.safe_dump(updated, fh, sort_keys=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, cfg_file)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def set_projects_root(
    raw_path: os.PathLike[str] | str,
    *,
    ctx: Any = None,
    allow_relative: bool = False,
    env: Optional[Mapping[str, str]] = None,
    home: Optional[os.PathLike[str] | str] = None,
    hermes_home: Optional[os.PathLike[str] | str] = None,
    cwd: Optional[os.PathLike[str] | str] = None,
) -> Path:
    """Validate `raw_path` and persist its normalized absolute string in `projects_root`."""
    validated = validate_projects_root(
        raw_path,
        allow_relative=allow_relative,
        source_label="projects folder",
        ctx=ctx,
        env=env,
        home=home,
        hermes_home=hermes_home,
        cwd=cwd,
    )
    normalized = str(validated)

    if ctx is not None and hasattr(ctx, "set_config"):
        ctx.set_config(SETTING_KEY, normalized)
        return validated

    explicit_scope = hermes_home is not None or env is not None
    if not explicit_scope:
        try:
            from hermes_cli.config import (
                atomic_config_write,
                get_config_path,
                is_managed,
                require_readable_config_before_write,
            )

            if is_managed():
                raise WorkspaceRootError(
                    "Plugin settings cannot be changed in a managed Hermes installation."
                )
            cfg_path = get_config_path()
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            doc = _with_projects_root_in_doc(
                require_readable_config_before_write(cfg_path),
                normalized,
            )
            atomic_config_write(cfg_path, doc)
            return validated
        except WorkspaceRootError:
            raise
        except ImportError:
            pass
        except Exception as exc:  # noqa: BLE001
            raise WorkspaceRootError(f"Could not save projects folder setting: {exc}") from exc

    eff_hh = _effective_hermes_home(ctx=ctx, home=home, hermes_home=hermes_home, env=env)
    _write_setting_to_yaml_file(eff_hh / "config.yaml", normalized)
    return validated


def resolve_projects_root(
    ctx: Any = None,
    *,
    cli_root: Optional[os.PathLike[str] | str] = None,
    allow_cli_relative: bool = True,
    env: Optional[Mapping[str, str]] = None,
    home: Optional[os.PathLike[str] | str] = None,
    hermes_home: Optional[os.PathLike[str] | str] = None,
    cwd: Optional[os.PathLike[str] | str] = None,
) -> ResolvedRoot:
    """Pure resolution in order: (a) CLI `--root` -> (b) saved `projects_root` -> (c) `HERMES_PROJECTS_ROOT` -> (d) unset."""
    # (a) Explicit CLI --root / --dest-root argument
    if cli_root is not None:
        try:
            validated = validate_projects_root(
                cli_root,
                allow_relative=allow_cli_relative,
                source_label="--root path",
                ctx=ctx,
                env=env,
                home=home,
                hermes_home=hermes_home,
                cwd=cwd,
            )
            return ResolvedRoot(
                path=validated,
                source="cli",
                message=f"Projects folder: {validated} (from --root)",
            )
        except WorkspaceRootError as exc:
            return ResolvedRoot(path=None, source="cli", message=str(exc))

    # (b) Saved plugin setting `projects_root`
    saved = _read_saved_setting(ctx=ctx, home=home, hermes_home=hermes_home, env=env)
    if saved is not None and saved != "":
        if not isinstance(saved, str):
            eff_home = _effective_home(home=home, env=env)
            return ResolvedRoot(
                path=None,
                source="setting",
                message=(
                    f"The saved projects folder setting must be text "
                    f"(for example {eff_home / DEFAULT_FOLDER_NAME}). "
                    "Run `hermes defuzz folder set <path>` to fix it."
                ),
            )
        try:
            validated = validate_projects_root(
                saved,
                allow_relative=False,
                source_label="saved projects folder",
                ctx=ctx,
                env=env,
                home=home,
                hermes_home=hermes_home,
                cwd=cwd,
            )
            return ResolvedRoot(
                path=validated,
                source="setting",
                message=f"Projects folder: {validated} (saved setting)",
            )
        except WorkspaceRootError as exc:
            return ResolvedRoot(path=None, source="setting", message=str(exc))

    # (c) Environment variable `HERMES_PROJECTS_ROOT`
    eff_env: Mapping[str, str] = env if env is not None else os.environ
    env_raw = eff_env.get(ENV_VAR)
    if env_raw is not None and env_raw != "":
        try:
            validated = validate_projects_root(
                env_raw,
                allow_relative=False,
                source_label=ENV_VAR,
                ctx=ctx,
                env=env,
                home=home,
                hermes_home=hermes_home,
                cwd=cwd,
            )
            return ResolvedRoot(
                path=validated,
                source="env",
                message=f"Projects folder: {validated} (from {ENV_VAR})",
            )
        except WorkspaceRootError as exc:
            return ResolvedRoot(path=None, source="env", message=str(exc))

    # (d) Not chosen yet
    return ResolvedRoot(path=None, source="unset", message=NON_TERMINAL_UNSET_MESSAGE)


def is_interactive_terminal(
    stdin: Any = None,
    stdout: Any = None,
) -> bool:
    """Return True only when both input and output streams are attached to an interactive terminal."""
    in_s = sys.stdin if stdin is None else stdin
    out_s = sys.stdout if stdout is None else stdout
    in_tty = in_s is not None and bool(getattr(in_s, "isatty", lambda: False)())
    out_tty = out_s is not None and bool(getattr(out_s, "isatty", lambda: False)())
    return in_tty and out_tty


def format_first_run_prompt(default_dir: Path) -> str:
    """Format the one-sentence terminal prompt for choosing the projects folder."""
    return (
        "Choose the folder where Defuzz creates new projects "
        "(only new projects go here; nothing else on your machine is touched, "
        "and the folder is created when you create your first project) "
        f"[{default_dir}]: "
    )


def ensure_projects_root(
    *,
    ctx: Any = None,
    cli_root: Optional[os.PathLike[str] | str] = None,
    allow_cli_relative: bool = True,
    interactive: Optional[bool] = None,
    stdin: Any = None,
    stdout: Any = None,
    env: Optional[Mapping[str, str]] = None,
    home: Optional[os.PathLike[str] | str] = None,
    hermes_home: Optional[os.PathLike[str] | str] = None,
    cwd: Optional[os.PathLike[str] | str] = None,
    error_cls: Type[Exception] = WorkspaceRootError,
) -> Path:
    """Return the validated projects folder Path, prompting once in a terminal if unset."""
    resolved = resolve_projects_root(
        ctx=ctx,
        cli_root=cli_root,
        allow_cli_relative=allow_cli_relative,
        env=env,
        home=home,
        hermes_home=hermes_home,
        cwd=cwd,
    )
    if resolved.path is not None:
        return resolved.path
    if resolved.source != "unset":
        raise error_cls(resolved.message)

    in_stream = sys.stdin if stdin is None else stdin
    out_stream = sys.stdout if stdout is None else stdout
    can_prompt = (
        is_interactive_terminal(in_stream, out_stream)
        if interactive is None
        else (interactive and is_interactive_terminal(in_stream, out_stream))
    )
    if not can_prompt:
        raise error_cls(NON_TERMINAL_UNSET_MESSAGE)

    eff_home = _effective_home(home=home, env=env)
    default_dir = eff_home / DEFAULT_FOLDER_NAME
    out_stream.write(format_first_run_prompt(default_dir))
    out_stream.flush()

    raw_line = in_stream.readline()
    if raw_line == "":
        raise error_cls("No projects folder was chosen; nothing was saved or created.")

    typed = raw_line.strip()
    candidate_raw = str(default_dir) if not typed else typed

    try:
        expanded_preview = _expand_tilde(typed, eff_home) if typed else str(default_dir)
        was_relative = bool(typed) and not os.path.isabs(expanded_preview)
        validated = validate_projects_root(
            candidate_raw,
            allow_relative=True,
            source_label="projects folder",
            ctx=ctx,
            env=env,
            home=home,
            hermes_home=hermes_home,
            cwd=cwd,
        )
        if was_relative:
            out_stream.write(f"Resolved relative path to {validated}.\n")
            out_stream.flush()
        saved_path = set_projects_root(
            validated,
            ctx=ctx,
            allow_relative=False,
            env=env,
            home=home,
            hermes_home=hermes_home,
            cwd=cwd,
        )
    except WorkspaceRootError as exc:
        if error_cls is WorkspaceRootError:
            raise
        raise error_cls(str(exc)) from exc

    out_stream.write(f"Projects folder saved: {saved_path}\n")
    out_stream.flush()
    return saved_path
