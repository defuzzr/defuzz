"""Mandatory hash-verified user-space setup for external lint binaries and SDKs."""

from __future__ import annotations

import contextlib
import copy
import gzip
import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
import xml.sax.saxutils
import zipfile
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
import dataclasses
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from . import lint_env
from .lint_env import INSTALL_ROOT_REL, build_env, real_home, run, which
from . import setup_manifest as _setup_manifest
from .setup_manifest import (
    CSHARPIER,
    ITEMS,
    OFFICIAL_HOSTS,
    OFFICIAL_REDIRECT_HOSTS,
    Binary,
    Download,
    Package,
    SetupItem,
    _dl,
    current_platform,
    exe_name,
    total_size_mb,
)

try:
    from .lint_tools import WHEEL_PACKAGES
except Exception:  # noqa: BLE001 - optional sibling module import
    WHEEL_PACKAGES = {}

# taplo==0.9.3 and shellcheck-py==0.11.0.1 have no aarch64 wheels on PyPI
# (see plugin.yaml PEP 508 markers), so on ARM64 they are installed via the
# user-space binary setup tier from official GitHub releases.
ARM_BINARY_ITEMS: tuple[SetupItem, ...] = (
    SetupItem(
        name="taplo",
        kind="binary",
        version="0.9.3",
        homepage="https://taplo.tamasfe.dev/",
        size_mb=5,
        provides=("taplo",),
        skip_if_on_path=("taplo",),
        downloads={
            ("linux", "aarch64"): _dl(
                "https://github.com/tamasfe/taplo/releases/download/0.9.3/taplo-linux-aarch64.gz",
                "7c07379d3288fb5c26b1c29bbedec4f8d8f602d776bcc3a1578176733b6a857c",
                "gz",
                "taplo",
                source="computed",
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/tamasfe/taplo/releases/download/0.9.3/taplo-darwin-aarch64.gz",
                "39b84d62d6a47855b2c64148cde9c9ca5721bf422b8c9fe9c92776860badde5f",
                "gz",
                "taplo",
                source="computed",
            ),
        },
        post_install=(),
    ),
    SetupItem(
        name="shellcheck",
        kind="binary",
        version="0.11.0",
        homepage="https://github.com/koalaman/shellcheck",
        size_mb=10,
        provides=("shellcheck",),
        skip_if_on_path=("shellcheck",),
        downloads={
            ("linux", "aarch64"): _dl(
                "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.aarch64.tar.xz",
                "12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588",
                "tar.xz",
                "shellcheck",
                strip=1,
            ),
            ("darwin", "aarch64"): _dl(
                "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.darwin.aarch64.tar.xz",
                "56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79",
                "tar.xz",
                "shellcheck",
                strip=1,
            ),
        },
        post_install=(),
    ),
)
_ARM_BINARY_NAMES: frozenset[str] = frozenset({"taplo", "shellcheck"})
_ARM_WHEEL_KEYS: frozenset[str] = frozenset({"taplo", "shellcheck-py"})

try:
    from pm import lazy_installs_allowed as _hermes_lazy_installs_allowed
except Exception:  # noqa: BLE001 - optional Hermes helper; default True when unavailable
    _hermes_lazy_installs_allowed = None

try:
    from plugins.plugin_storage import plugin_data_dir as _hermes_plugin_data_dir
except Exception:  # noqa: BLE001 - optional Hermes helper
    _hermes_plugin_data_dir = None

_PLUGIN_NAME = "defuzz"
_USER_AGENT = "defuzz"  # the product name; downloads send "defuzz/<plugin version>"
_FETCH_TIMEOUT_S = 60
_POST_INSTALL_TIMEOUT_S = 1800
_CSHARPIER_VERSION = CSHARPIER.version
_CSHARPIER_VERIFY_TIMEOUT_S = 3
_CSHARPIER_VERSIONED_DIR_RE = re.compile(rf"^{re.escape(_CSHARPIER_VERSION)}-[0-9a-f]{{16}}\Z")
_CHUNK_SIZE = 65536
VERIFIED_BY_CHECKSUM = "verified by checksum"
_PLAN_PKG_DIR = "<verified-packages-dir>"
# NuGet packaging files that are not part of an installed PowerShell module.
_NUPKG_PACKAGING_TOP = frozenset({"_rels", "package", "[Content_Types].xml", ".signature.p7s"})
_VERSION_OUTPUT_RE = re.compile(
    r"(?<![\d.])(\d+\.\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?)(?![\d.])"
)


class SetupError(RuntimeError):
    """Raised when downloading, verifying, extracting, or installing a lint tool fails."""


class _CancelledError(Exception):
    """Internal signal raised when the caller's cancel event is set."""


@dataclass
class ItemStatus:
    """Installation status for a single manifest SetupItem on the target platform."""

    name: str
    kind: str
    version: str
    size_mb: int
    state: str


@dataclass
class SetupStatus:
    """Aggregate setup status across all manifest items and wheel binaries."""

    items: list[ItemStatus]
    complete: bool
    pending_mb: int
    platform: tuple[str, str]
    install_root: Path
    lazy_installs_allowed: bool
    wheels_missing: list[str]
    blocked_reason: str | None = None
    sources: list[dict[str, Any]] = dataclasses.field(default_factory=list)


@dataclass
class Progress:
    """Progress snapshot emitted to the caller callback during run_setup."""

    item: str
    step: str
    item_index: int
    item_count: int
    bytes_done: int
    bytes_total: int
    percent: float
    message: str


@dataclass
class SetupResult:
    """Final outcome of a run_setup execution."""

    ok: bool
    installed: list[str]
    skipped: list[str]
    failed: dict[str, str]
    error: str | None
    log: list[str]


def _eval_flag_or_callable(target: Any, default: bool = True) -> bool:
    """Evaluate a boolean flag or zero-arg callable, returning default on error."""
    if isinstance(target, bool):
        return target
    if callable(target):
        try:
            return bool(target())
        except Exception:
            return default
    return bool(target)


def lazy_installs_allowed() -> bool:
    """Return True if Hermes configuration permits lazy tool downloads and installs."""
    if _hermes_lazy_installs_allowed is None:
        return True
    if isinstance(_hermes_lazy_installs_allowed, bool):
        return _hermes_lazy_installs_allowed
    try:
        return bool(_hermes_lazy_installs_allowed())
    except Exception:
        return True


def _check_lazy_installs_allowed() -> bool:
    """Evaluate lazy_installs_allowed whether it is a callable or monkeypatched bool."""
    return _eval_flag_or_callable(lazy_installs_allowed, default=True)


def _active_items(
    items: Sequence[SetupItem] | None = None,
    plat: tuple[str, str] | None = None,
) -> Sequence[SetupItem]:
    """Return explicit items override, or lint_setup.ITEMS / setup_manifest.ITEMS (+ ARM binary tier on aarch64)."""
    if items is not None:
        return items
    base: Sequence[SetupItem] = ITEMS if ITEMS is not _setup_manifest.ITEMS else _setup_manifest.ITEMS
    if (
        base is _setup_manifest.ITEMS
        and isinstance(plat, tuple)
        and len(plat) == 2
        and plat[1] == "aarch64"
    ):
        existing_names = {it.name for it in base}
        extra = tuple(it for it in ARM_BINARY_ITEMS if it.name not in existing_names)
        if extra:
            return (*base, *extra)
    return base


def downloads_for(
    plat: tuple[str, str],
    items: Sequence[SetupItem] | None = None,
) -> list[tuple[SetupItem, Download]]:
    """Return ordered (SetupItem, Download) pairs available for plat."""
    return [
        (item, dl)
        for item in _active_items(items, plat=plat)
        if (dl := item.downloads.get(plat)) is not None
    ]


def _get_downloads(
    plat: tuple[str, str],
    items: Sequence[SetupItem] | None = None,
) -> list[tuple[SetupItem, Download]]:
    """Resolve (SetupItem, Download) pairs while honoring monkeypatched downloads_for or ITEMS."""
    if items is not None:
        return [(item, item.downloads[plat]) for item in items if plat in item.downloads]
    return downloads_for(plat)


def install_root(env: Mapping[str, str] | None = None) -> Path:
    """Return the explicitly isolated or legacy user-space installation root."""
    return lint_env.managed_install_root(env)


def default_cache_dir(env: Mapping[str, str] | None = None) -> Path:
    """Return the downloads cache directory under HERMES_HOME/plugin-data/defuzz/downloads."""
    if env is not None and env.get("HERMES_HOME"):
        return Path(env["HERMES_HOME"]).expanduser() / "plugin-data" / _PLUGIN_NAME / "downloads"
    if _hermes_plugin_data_dir is not None:
        with contextlib.suppress(Exception):
            return Path(_hermes_plugin_data_dir(_PLUGIN_NAME)) / "downloads"
    with contextlib.suppress(Exception):
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home()).expanduser() / "plugin-data" / _PLUGIN_NAME / "downloads"
    hermes_home = (env or {}).get("HERMES_HOME") or os.environ.get("HERMES_HOME", "~/.hermes")
    return Path(hermes_home).expanduser() / "plugin-data" / _PLUGIN_NAME / "downloads"


def _resolve_paths(env: Mapping[str, str] | None, paths: Mapping[str, Any]) -> tuple[Path, Path, Path, Path]:
    """Resolve (install_root, bin_dir, cache_dir, real_home) with test kwarg overrides."""
    r_home_override = paths.get("real_home") or paths.get("real_home_dir")
    r_home = Path(r_home_override) if r_home_override is not None else real_home(env)

    inst_override = paths.get("install_root")
    if inst_override is not None:
        inst_root = Path(inst_override)
    elif r_home_override is not None:
        inst_root = r_home / INSTALL_ROOT_REL
    else:
        inst_root = install_root(env)

    bin_override = paths.get("bin_dir")
    b_dir = Path(bin_override) if bin_override is not None else (inst_root / "bin")

    cache_override = paths.get("cache_dir")
    c_dir = Path(cache_override) if cache_override is not None else default_cache_dir(env)

    return inst_root, b_dir, c_dir, r_home


def _forbidden_install_roots(r_home: Path | None, env: Mapping[str, str] | None) -> set[Path]:
    """Return resolved realpaths that must never serve as install_root."""
    env_map = env or {}
    forbidden_raw: list[str | Path | None] = [
        r_home,
        Path("/home"),
        Path("/Users"),
        Path("/root"),
        os.environ.get("HOME"),
        os.environ.get("HERMES_REAL_HOME"),
        os.environ.get("USERPROFILE"),
        os.environ.get("HERMES_HOME"),
        env_map.get("HOME"),
        env_map.get("HERMES_REAL_HOME"),
        env_map.get("HERMES_HOME"),
    ]
    with contextlib.suppress(Exception):
        rh = real_home(env)
        forbidden_raw.extend((rh, rh / ".hermes"))
    with contextlib.suppress(Exception):
        forbidden_raw.extend((Path.home(), Path("~/.hermes").expanduser()))
    if r_home is not None:
        forbidden_raw.append(Path(r_home) / ".hermes")

    forbidden_real: set[Path] = set()
    for cand in forbidden_raw:
        if cand:
            with contextlib.suppress(Exception):
                forbidden_real.add(Path(os.path.realpath(Path(cand).expanduser())))
    return forbidden_real


def _assert_managed_path(
    p: Path,
    inst_root: Path,
    *,
    r_home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> None:
    """Ensure inst_root is a valid managed directory and p is strictly inside it."""
    inst_path = Path(inst_root).expanduser()
    target_path = Path(p).expanduser()
    root_real = Path(os.path.realpath(inst_path))

    non_anchor_parts = [pt for pt in root_real.parts if pt and pt != root_real.anchor]
    if not non_anchor_parts or root_real == Path(root_real.anchor):
        raise SetupError(f"unsafe install_root {inst_root!s}: cannot be filesystem root")
    if len(non_anchor_parts) < 3:
        raise SetupError(f"unsafe install_root {inst_root!s}: path depth must be >= 3")

    forbidden_names = ("home", "fake_home", "Users", ".hermes")
    if (
        root_real in _forbidden_install_roots(r_home, env)
        or root_real.name in forbidden_names
        or inst_path.name in forbidden_names
        or root_real.parent in (Path("/home"), Path("/Users"))
    ):
        raise SetupError(f"unsafe install_root {inst_root!s}: refuses home or HERMES_HOME directory")

    if target_path.name in ("", ".", ".."):
        raise SetupError(f"unsafe target path {p!s}: must be strictly inside {inst_root!s}")

    parent_real = Path(os.path.realpath(target_path.parent))
    lexical_target = parent_real / target_path.name
    if lexical_target == root_real or not lexical_target.is_relative_to(root_real):
        raise SetupError(f"path {p!s} is not strictly inside install_root {inst_root!s}")

    if not target_path.is_symlink():
        target_real = Path(os.path.realpath(target_path))
        if target_real == root_real or not target_real.is_relative_to(root_real):
            raise SetupError(f"resolved path {p!s} escapes install_root {inst_root!s}")


def _remove_managed_path(
    p: Path,
    inst_root: Path,
    *,
    r_home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> None:
    """Remove file/symlink/directory p only after verifying it is a managed path under inst_root."""
    _assert_managed_path(p, inst_root, r_home=r_home, env=env)
    if p.is_symlink() or p.is_file():
        p.unlink(missing_ok=True)
    elif p.exists():
        shutil.rmtree(p)


def _path_within_any(candidates: Sequence[Path], roots: Sequence[Path]) -> bool:
    """Return True if any candidate path equals or resides inside any root path."""
    return any(cand == root or cand.is_relative_to(root) for cand in candidates for root in roots)


def _migrate_legacy_rustup_bin(
    inst_root: Path,
    b_dir: Path,
    plat: tuple[str, str],
    *,
    r_home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> None:
    """Remove a stale legacy managed bin/rustup link pointing into the managed rustup install."""
    rust_dir = inst_root / "rustup"
    rust_roots = [Path(os.path.abspath(rust_dir)), Path(os.path.realpath(rust_dir))]
    candidates = list(dict.fromkeys([b_dir / "rustup", b_dir / exe_name("rustup", plat), b_dir / "rustup.exe"]))

    for cand in candidates:
        if not cand.is_symlink():
            continue
        raw_target = os.readlink(cand)
        resolved_lex = Path(os.path.abspath(os.path.join(str(cand.parent), raw_target)))
        resolved_real = Path(os.path.realpath(cand))
        if _path_within_any((resolved_lex, resolved_real), rust_roots):
            _remove_managed_path(cand, inst_root, r_home=r_home, env=env)


def _prepare_env(
    env: Mapping[str, str] | None,
    *,
    inst_root: Path,
    b_dir: Path,
    r_home: Path,
    paths: Mapping[str, Any],
) -> dict[str, str]:
    """Construct the effective tool environment, isolating PATH when test overrides are given."""
    has_path_override = any(k in paths for k in ("install_root", "bin_dir", "real_home", "real_home_dir"))
    explicit_path_in_env = env is not None and "PATH" in env

    base_input: dict[str, str] | None = dict(env) if env is not None else None
    if has_path_override:
        base_input = dict(env) if env is not None else {"PATH": ""}
        base_input.setdefault("HERMES_REAL_HOME", str(r_home))
        base_input.setdefault("HOME", str(r_home))

    eff = build_env(base_input)
    if has_path_override:
        lint_env._apply_toolchain_defaults(eff, r_home, inst_root, overwrite=True)

    if has_path_override or explicit_path_in_env:
        managed_dirs = lint_env._managed_path_dirs(inst_root, r_home, eff, bin_dir=b_dir, use_env_dotnet_root=False)
        existing_managed = [str(p) for p in managed_dirs if p.is_dir()]
        caller_path = (env or {}).get("PATH", "") if env is not None else ""
        caller_entries = [p for p in caller_path.split(os.pathsep) if p]
        eff["PATH"] = lint_env._dedupe_path_entries([*existing_managed, *caller_entries])

    return eff


def _marker_and_binaries_present(
    item: SetupItem,
    dl: Download,
    plat: tuple[str, str],
    item_install_dir: Path,
    b_dir: Path,
) -> bool:
    """Return True if the version marker and all declared binaries for item exist."""
    marker = item_install_dir / f".adopt-installed-{item.version}"
    if not marker.is_file():
        return False
    return all((b_dir / exe_name(b.name, plat)).is_file() for b in dl.binaries)


def _is_under_managed_dirs(exe_path: str, inst_root: Path, b_dir: Path) -> bool:
    """Return True if exe_path (lexically or via realpath) resides under inst_root or b_dir."""
    managed_roots = (
        Path(os.path.abspath(inst_root)),
        Path(os.path.realpath(inst_root)),
        Path(os.path.abspath(b_dir)),
        Path(os.path.realpath(b_dir)),
    )
    candidates = (Path(os.path.abspath(exe_path)), Path(os.path.realpath(exe_path)))
    return _path_within_any(candidates, managed_roots)


def _external_dotnet_path(
    plat: tuple[str, str],
    eff_env: Mapping[str, str],
    inst_root: Path,
    b_dir: Path,
) -> str | None:
    """Return the resolved absolute external PATH dotnet executable if one exists outside managed dirs."""
    is_win = plat[0] == "windows"
    found = which("dotnet", eff_env, is_windows=is_win)
    if found is not None and not _is_under_managed_dirs(found, inst_root, b_dir):
        return os.path.abspath(found)
    return None


def _verify_csharpier_binary(
    exe_path: Path | str,
    eff_env: Mapping[str, str],
    *,
    expected_version: str = _CSHARPIER_VERSION,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> tuple[bool, str | None]:
    """Run `<csharpier> --version` and verify it reports expected_version."""
    abs_exe = os.path.abspath(str(exe_path))
    if not Path(abs_exe).is_file():
        return False, f"csharpier binary not found at {abs_exe}"
    version, error = _probe_version_command(
        (abs_exe, "--version"),
        deadline=time.monotonic() + _CSHARPIER_VERIFY_TIMEOUT_S,
        timeout_s=_CSHARPIER_VERIFY_TIMEOUT_S,
        eff_env=eff_env,
        runner=runner,
    )
    if version != expected_version:
        detail = error or f"expected version {expected_version}, got {version!r}"
        return False, detail
    return True, None


def _is_csharpier_present(
    plat: tuple[str, str],
    eff_env: Mapping[str, str],
    b_dir: Path,
) -> bool:
    """Return True if a runnable, version-correct csharpier is present in managed bin_dir or on PATH."""
    seen: set[str] = set()
    managed_cs = b_dir / exe_name("csharpier", plat)
    if managed_cs.is_file():
        seen.add(os.path.realpath(managed_cs))
        ok, _ = _verify_csharpier_binary(managed_cs, eff_env)
        if ok:
            return True
    is_win = plat[0] == "windows"
    found = which("csharpier", eff_env, is_windows=is_win)
    if found is not None and os.path.realpath(found) not in seen:
        ok, _ = _verify_csharpier_binary(found, eff_env)
        if ok:
            return True
    return False


def _is_item_present(
    item: SetupItem,
    dl: Download,
    plat: tuple[str, str],
    eff_env: Mapping[str, str],
    item_install_dir: Path,
    b_dir: Path,
) -> bool:
    """Return True if item is satisfied via external skip_if_on_path or marker + binaries."""
    if item.name == "dotnet":
        inst_root = item_install_dir.parent
        has_dotnet = _marker_and_binaries_present(item, dl, plat, item_install_dir, b_dir) or (
            _external_dotnet_path(plat, eff_env, inst_root, b_dir) is not None
        )
        return has_dotnet and _is_csharpier_present(plat, eff_env, b_dir)
    if _marker_and_binaries_present(item, dl, plat, item_install_dir, b_dir):
        return True
    if not item.skip_if_on_path:
        return False
    is_win = plat[0] == "windows"
    inst_root = item_install_dir.parent
    for cmd in item.skip_if_on_path:
        found = which(cmd, eff_env, is_windows=is_win)
        if found is None or _is_under_managed_dirs(found, inst_root, b_dir):
            return False
    return True


def _missing_wheels(eff_env: Mapping[str, str], plat: tuple[str, str]) -> list[str]:
    """Return wheel binary names from lint_tools.WHEEL_PACKAGES not resolvable on PATH."""
    is_win = plat[0] == "windows"
    is_arm = len(plat) >= 2 and plat[1] == "aarch64"
    missing: list[str] = []
    seen: set[str] = set()
    for pkg_key, val in WHEEL_PACKAGES.items():
        if is_arm and pkg_key in _ARM_WHEEL_KEYS:
            continue
        names = (val,) if isinstance(val, str) else tuple(val)
        for name in names:
            if name not in seen:
                seen.add(name)
                if which(name, eff_env, is_windows=is_win) is None:
                    missing.append(name)
    return missing


def _format_blocked_reason(mb: int) -> str:
    """Return the user-facing explanation when security.allow_lazy_installs is false."""
    return (
        "security.allow_lazy_installs is false in config.yaml; the lint-tool setup "
        f"downloads ~{mb} MB of tools and SDKs into ~/.local/opt/defuzz and will "
        "not run until you set it to true or install the tools yourself."
    )


def status(
    platform: tuple[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    **paths: Any,
) -> SetupStatus:
    """Inspect current installation status of all manifest items and wheel binaries."""
    plat = platform if platform is not None else current_platform()
    inst_root, b_dir, _, r_home = _resolve_paths(env, paths)
    eff_env = _prepare_env(env, inst_root=inst_root, b_dir=b_dir, r_home=r_home, paths=paths)

    items_seq = _active_items(paths.get("items"), plat=plat)
    dl_map = {it.name: d for it, d in _get_downloads(plat, paths.get("items"))}

    item_statuses: list[ItemStatus] = []
    for item in items_seq:
        dl = dl_map.get(item.name) or item.downloads.get(plat)
        if dl is None:
            state = "unsupported"
        elif _is_item_present(item, dl, plat, eff_env, inst_root / item.name, b_dir):
            state = "present"
        else:
            state = "missing"
        item_statuses.append(
            ItemStatus(name=item.name, kind=item.kind, version=item.version, size_mb=item.size_mb, state=state)
        )

    pending_mb = sum(i.size_mb for i in item_statuses if i.state == "missing")
    complete = not any(i.state == "missing" for i in item_statuses)
    allowed = _check_lazy_installs_allowed()
    supported_mb = sum(i.size_mb for i in item_statuses if i.state != "unsupported")
    reason_mb = pending_mb if pending_mb > 0 else (supported_mb or total_size_mb(plat))
    blocked_reason = None if allowed else _format_blocked_reason(reason_mb)

    return SetupStatus(
        sources=download_sources(plat, paths.get("items")),
        items=item_statuses,
        complete=complete,
        pending_mb=pending_mb,
        platform=plat,
        install_root=inst_root,
        lazy_installs_allowed=allowed,
        wheels_missing=_missing_wheels(eff_env, plat),
        blocked_reason=blocked_reason,
    )


def _user_agent() -> str:
    """``defuzz/<version>`` from plugin.yaml; just ``defuzz`` when the version cannot be read."""
    try:
        import yaml

        manifest = yaml.safe_load(Path(__file__).with_name("plugin.yaml").read_text(encoding="utf-8"))
        version = str(manifest.get("version", "")).strip()
    except Exception:  # noqa: BLE001 - the header only names the plugin
        version = ""
    if version and re.fullmatch(r"[0-9A-Za-z.+-]{1,32}", version):
        return f"{_USER_AGENT}/{version}"
    return _USER_AGENT


def _read_wheel_ranges() -> tuple[dict[str, str], str | None]:
    """Parse each wheel package's version specifier (">=X,<Y" or "==X") from plugin.yaml."""
    ranges: dict[str, str] = {}
    try:
        import yaml

        manifest_text = Path(__file__).with_name("plugin.yaml").read_text(encoding="utf-8")
        manifest = yaml.safe_load(manifest_text)
        for requirement in manifest.get("python_dependencies", []):
            spec = requirement.split(";", 1)[0].strip()
            cut = min((i for i in (spec.find(op) for op in ("==", ">=", "<")) if i > 0), default=-1)
            if cut > 0:
                ranges[spec[:cut].strip()] = spec[cut:].replace(" ", "")
    except Exception as exc:
        return ranges, f"could not read wheel pins: {exc}"
    return ranges, None


def _read_wheel_pins() -> tuple[dict[str, str], str | None]:
    """Floor (or exact pin) of each wheel range: the version setup installs."""
    ranges, error = _read_wheel_ranges()
    pins = {}
    for package, spec in ranges.items():
        clause = next((c for c in spec.split(",") if c.startswith(("==", ">="))), "")
        pins[package] = clause[2:]
    return pins, error


def _numeric_version(text: str) -> tuple[int, ...] | None:
    """Dotted numeric release ("0.11.0.1"); local/pre-release suffixes are not accepted."""
    parts = text.split(".")
    return tuple(int(p) for p in parts) if parts and all(p.isdigit() for p in parts) else None


def version_in_range(installed: str, spec: str) -> bool:
    """True when `installed` satisfies every ">=", "<" and "==" clause of `spec`.

    Versions are compared numerically after zero-padding (6.1 > 6.0.3, 6.0.10 > 6.0.3).
    A binary that reports three or more parts is compared on those parts only, because
    wheel versions add a packaging revision the binary cannot report (hadolint 2.15.1
    comes from hadolint-py 2.15.1.3). Unparseable versions or clauses never satisfy.
    """
    have = _numeric_version(installed)
    clauses = [c for c in spec.replace(" ", "").split(",") if c]
    if have is None or not clauses:
        return False
    for clause in clauses:
        op = next((o for o in ("==", ">=", "<") if clause.startswith(o)), None)
        bound = _numeric_version(clause[len(op):]) if op else None
        if bound is None:
            return False
        if len(have) >= 3 and len(bound) > len(have):
            bound = bound[: len(have)]
        width = max(len(have), len(bound))
        a, b = have + (0,) * (width - len(have)), bound + (0,) * (width - len(bound))
        if not (a == b if op == "==" else a >= b if op == ">=" else a < b):
            return False
    return True


def _version_specs(
    items: Sequence[SetupItem] | None,
) -> list[tuple[Any, ...]]:
    """Build (name, expected_version, kind, size_mb, pin_error[, allowed_range]) probe specs."""
    active = _active_items(items, plat=current_platform())
    specs: list[tuple[Any, ...]] = [
        (item.name, item.version, item.kind, item.size_mb, None) for item in active
    ]
    if items is not None:
        return specs

    pins, pin_error = _read_wheel_pins()
    ranges, _ = _read_wheel_ranges()
    names = {spec[0] for spec in specs}
    for package, binaries in WHEEL_PACKAGES.items():
        for binary in ((binaries,) if isinstance(binaries, str) else binaries):
            if binary in names:
                continue
            error = pin_error
            version = None
            try:
                version = pins[package]
                if not version:
                    raise ValueError(f"empty pin for {package}")
            except Exception as exc:
                error = error or f"could not read wheel pin: {exc}"
            specs.append((binary, version, "wheel", 0, error, ranges.get(package)))
            names.add(binary)
    return specs


def _build_version_rows(
    specs: Sequence[tuple[Any, ...]],
    eff_env: Mapping[str, str],
) -> tuple[list[dict[str, Any]], dict[tuple[str, ...], list[dict[str, Any]]]]:
    """Resolve executables on PATH and group rows by unique version probe command."""
    rows: list[dict[str, Any]] = []
    probes: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for name, expected_version, kind, size_mb, pin_error, *allowed in specs:
        row: dict[str, Any] = {
            "name": name,
            "expected_version": expected_version,
            "version": expected_version,
            "kind": kind,
            "size_mb": size_mb,
            "state": "missing",
            "installed_version": None,
            "executable_path": None,
            "status": "missing",
        }
        if allowed and allowed[0]:
            row["allowed_versions"] = allowed[0]  # manifest range; status compares against it
        rows.append(row)
        try:
            command = {"glslang": "glslangValidator", "rust": "rustc"}.get(name, name)
            args = ("version",) if name == "go" else ("--version",)
            found = which(command, eff_env)
            if found:
                row.update(executable_path=os.path.abspath(found), state="present")
            if pin_error:
                row.update(status="could_not_verify", error=pin_error)
            elif found:
                probes.setdefault((row["executable_path"], *args), []).append(row)
        except Exception as exc:
            row.update(status="could_not_verify", error=f"version probe failed: {exc}")
    return rows, probes


def _probe_version_command(
    key: tuple[str, ...],
    *,
    deadline: float,
    timeout_s: float,
    eff_env: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> tuple[str | None, str | None]:
    """Execute a single version command and extract its semantic version string."""
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "version probe overall deadline exceeded"
        result = run(
            list(key),
            cwd=Path(__file__).resolve().parent,
            env=eff_env,
            timeout_s=min(timeout_s, remaining),  # type: ignore[arg-type]
            runner=runner,
        )
        if result.returncode:
            reason = (
                "version probe timed out"
                if result.returncode == lint_env.TIMEOUT_RC
                else f"version command exited {result.returncode}"
            )
            return None, reason
        match = _VERSION_OUTPUT_RE.search(result.stdout + "\n" + result.stderr)
        return (match.group(1), None) if match else (None, "unrecognized version output")
    except Exception as exc:
        return None, f"version probe failed: {exc}"


def installed_tool_versions(
    env: Mapping[str, str] | None = None,
    *,
    items: Sequence[SetupItem] | None = None,
    timeout_s: float = 3,
    overall_timeout_s: float = 5,
    max_workers: int = 4,
) -> list[dict[str, Any]]:
    """Probe manifest tools using lint's environment, never a project's lock.

    Run at most max_workers probes concurrently within overall_timeout_s.
    Cache only within this snapshot; subsequent requests must observe upgrades.
    SDK versions describe the SDK/manager, not unpinned bundled components.
    """
    deadline = time.monotonic() + max(0, overall_timeout_s)
    eff_env = build_env(env)
    eff_env["PATH"] = os.pathsep.join(
        entry for entry in eff_env.get("PATH", "").split(os.pathsep) if entry and os.path.isabs(entry)
    )
    rows, probes = _build_version_rows(_version_specs(items), eff_env)
    if not probes:
        return rows

    # Do not use the executor context manager: it waits for running jobs even
    # after the snapshot deadline. Workers never mutate returned rows.
    executor = ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(probes))))
    try:
        futures = {
            executor.submit(_probe_version_command, key, deadline=deadline, timeout_s=timeout_s, eff_env=eff_env): targets
            for key, targets in probes.items()
        }
        done, _ = wait(futures, timeout=max(0, deadline - time.monotonic()))
        for future, targets in futures.items():
            version, error = (
                future.result() if future in done else (None, "version probe overall deadline exceeded")
            )
            for row in targets:
                row["installed_version"] = version
                allowed = row.get("allowed_versions")
                row["status"] = (
                    "could_not_verify"
                    if version is None
                    else "match"
                    if (version_in_range(version, allowed) if allowed else version == row["expected_version"])
                    else "mismatch"
                )
                if error:
                    row["error"] = error
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return rows


def _check_cancel(cancel: threading.Event | None) -> None:
    """Raise _CancelledError when the caller's cancel event is set."""
    if cancel is not None and cancel.is_set():
        raise _CancelledError()


def _check_redirect_url(url: str) -> None:
    """Refuse a redirect hop that is not https on an official or official-CDN host."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in (OFFICIAL_HOSTS | OFFICIAL_REDIRECT_HOSTS):
        raise SetupError(f"refusing redirect to untrusted URL: {parsed.scheme}://{parsed.hostname}")


class _OfficialRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs on OFFICIAL_HOSTS or OFFICIAL_REDIRECT_HOSTS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102
        _check_redirect_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_url(req: urllib.request.Request) -> Any:
    """Open req with the redirect allowlist enforced on every hop."""
    opener = urllib.request.build_opener(_OfficialRedirectHandler())
    return opener.open(req, timeout=_FETCH_TIMEOUT_S)


def _default_fetch(url: str, dest: Path, on_bytes: Callable[[int, int], None]) -> None:
    """Stream url over HTTPS into dest via a temporary .part file."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in OFFICIAL_HOSTS:
        raise SetupError(f"refusing download from untrusted URL: {url}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    part_path = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": _user_agent()})
    try:
        with _open_url(req) as resp:
            final_url = resp.geturl() if hasattr(resp, "geturl") else url
            if final_url and final_url != url:
                _check_redirect_url(final_url)
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            with open(part_path, "wb") as fh:
                while chunk := resp.read(_CHUNK_SIZE):
                    fh.write(chunk)
                    done += len(chunk)
                    on_bytes(done, total)
        part_path.replace(dest)
    except _CancelledError:
        part_path.unlink(missing_ok=True)
        raise
    except SetupError:
        part_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        part_path.unlink(missing_ok=True)
        raise SetupError(f"download failed for {url}: {exc}") from exc


def _verify_checksum(
    file_path: Path,
    *,
    url: str,
    expected_hash: str,
    hash_algo: str,
    cancel: threading.Event | None,
) -> None:
    """Verify file_path digest matches expected_hash or delete file and raise SetupError."""
    if not file_path.is_file():
        raise SetupError(f"downloaded file missing for {url}: {file_path}")
    try:
        hasher = hashlib.new(hash_algo)
    except ValueError as exc:
        file_path.unlink(missing_ok=True)
        raise SetupError(f"unsupported hash algorithm {hash_algo!r} for {url}") from exc

    with open(file_path, "rb") as fh:
        while True:
            _check_cancel(cancel)
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)

    actual = hasher.hexdigest().lower()
    expected = expected_hash.lower()
    if actual != expected:
        file_path.unlink(missing_ok=True)
        raise SetupError(f"checksum mismatch for {url}: expected {expected} got {actual}")


def _validate_and_strip_member_path(raw_name: str, strip_components: int, extract_root: Path) -> str | None:
    """Validate an archive member path against traversal and apply strip_components."""
    if not raw_name:
        return None
    if raw_name.startswith(("/", "\\")):
        raise SetupError(f"unsafe absolute path in archive: {raw_name!r}")

    raw_segments = raw_name.replace("\\", "/").split("/")
    if ".." in raw_segments:
        raise SetupError(f"unsafe path traversal in archive member: {raw_name!r}")

    parts = [p for p in raw_segments if p and p != "."]
    if not parts:
        return None
    if ":" in parts[0]:
        raise SetupError(f"unsafe drive path in archive member: {raw_name!r}")
    if len(parts) <= strip_components:
        return None

    rel_parts = parts[strip_components:]
    if any(":" in part for part in rel_parts):
        raise SetupError(f"unsafe drive path in archive member: {raw_name!r}")

    rel_path = "/".join(rel_parts)
    dest_real = Path(os.path.realpath(extract_root))
    target_path = extract_root / rel_path
    parent_real = Path(os.path.realpath(target_path.parent))
    target_real = Path(os.path.realpath(target_path))
    if not parent_real.is_relative_to(dest_real) or not target_real.is_relative_to(dest_real):
        raise SetupError(f"archive member escapes extraction directory: {raw_name!r}")
    return rel_path


def _assert_member_within_root(
    target_path: Path,
    dest_real: Path,
    member_name: str,
    *,
    escape_prefix: str,
    archive_label: str,
) -> None:
    """Verify target_path and its parent resolve within dest_real and target is not a symlink."""
    parent_real = Path(os.path.realpath(target_path.parent))
    target_real = Path(os.path.realpath(target_path))
    if not parent_real.is_relative_to(dest_real) or not target_real.is_relative_to(dest_real):
        raise SetupError(f"{escape_prefix} member destination escapes root: {member_name!r}")
    if target_path.is_symlink():
        raise SetupError(f"refusing to overwrite symlink in {archive_label} archive: {member_name!r}")


def _ensure_executable_mode(target_path: Path, mode: int) -> None:
    """Add 0o755 permissions on POSIX when archive member mode has any execute bit."""
    if os.name != "nt" and (mode & 0o111) and target_path.is_file():
        with contextlib.suppress(OSError):
            target_path.chmod(target_path.stat().st_mode | 0o755)


def _verify_extracted_symlinks(extracted_symlinks: Sequence[Path], dest_real: Path, archive_label: str) -> None:
    """Verify all extracted symlinks resolve inside dest_real after full extraction."""
    for sym_path in extracted_symlinks:
        if not Path(os.path.realpath(sym_path)).is_relative_to(dest_real):
            raise SetupError(f"unsafe symlink chain escaping {archive_label} root: {sym_path.name!r}")


def _validate_tar_symlink(linkname: str, extract_root: Path, rel_path: str, dest_real: Path) -> None:
    """Reject absolute or root-escaping tar symlink targets."""
    if (
        not linkname
        or os.path.isabs(linkname)
        or linkname.startswith(("/", "\\"))
        or ":" in linkname.replace("\\", "/").split("/")[0]
    ):
        raise SetupError(f"unsafe absolute symlink in tar archive: {linkname!r}")
    resolved_sym = Path(os.path.realpath(os.path.join(str(extract_root), os.path.dirname(rel_path), linkname)))
    if not resolved_sym.is_relative_to(dest_real):
        raise SetupError(f"unsafe symlink target in tar archive: {linkname!r}")


def _extract_tar(
    archive_path: Path,
    extract_root: Path,
    *,
    mode: str,
    strip_components: int,
    cancel: threading.Event | None,
    include: Sequence[str] = (),
) -> None:
    """Safely extract a tar.gz or tar.xz archive into extract_root (only `include` top dirs when given)."""
    dest_real = Path(os.path.realpath(extract_root))
    if getattr(tarfile, "data_filter", None) is None:
        raise SetupError(
            "This Python cannot unpack tar downloads safely. Use Python 3.11.4 or newer."
        )
    open_mode = "r:xz" if mode == "r:xz" else "r:gz"
    extracted_symlinks: list[Path] = []

    with tarfile.open(archive_path, mode=open_mode) as tf:
        for member in tf.getmembers():
            _check_cancel(cancel)
            if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                raise SetupError(f"unsafe special device member in tar archive: {member.name!r}")
            if member.islnk():
                raise SetupError(f"unsafe hardlink member in tar archive: {member.name!r}")

            rel_path = _validate_and_strip_member_path(member.name, strip_components, extract_root)
            if rel_path is None:
                continue
            if include and rel_path.split("/", 1)[0] not in include:
                continue

            member_copy = copy.copy(member)
            member_copy.name = rel_path
            target_path = extract_root / rel_path
            _assert_member_within_root(
                target_path, dest_real, member.name, escape_prefix="archive", archive_label="tar"
            )

            if member_copy.issym():
                _validate_tar_symlink(member_copy.linkname, extract_root, rel_path, dest_real)
                extracted_symlinks.append(target_path)

            orig_mode = member.mode
            try:
                tf.extract(member_copy, path=str(extract_root), set_attrs=True, filter="data")
            except Exception as exc:
                raise SetupError(f"unsafe tar member {member.name!r}: {exc}") from exc

            if member_copy.isfile():
                _ensure_executable_mode(target_path, orig_mode)

        _verify_extracted_symlinks(extracted_symlinks, dest_real, "tar")


def _extract_zip_symlink(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    target_path: Path,
    dest_real: Path,
) -> None:
    """Validate and materialize a Unix symlink entry from a zip archive."""
    if info.file_size > 4096:
        raise SetupError(f"oversized symlink target: {info.filename!r}")
    try:
        linkname = zf.read(info).decode("utf-8")
    except UnicodeError as exc:
        raise SetupError(f"invalid symlink target: {info.filename!r}") from exc
    if (
        not linkname
        or "\x00" in linkname
        or "\\" in linkname
        or os.path.isabs(linkname)
        or ":" in linkname.split("/")[0]
        or not Path(os.path.realpath(target_path.parent / linkname)).is_relative_to(dest_real)
    ):
        raise SetupError(f"unsafe symlink target in zip archive: {linkname!r}")
    target_path.symlink_to(linkname)


def _extract_zip(
    archive_path: Path,
    extract_root: Path,
    *,
    strip_components: int,
    cancel: threading.Event | None,
) -> None:
    """Safely extract a zip archive into extract_root."""
    extracted_symlinks: list[Path] = []
    dest_real = Path(os.path.realpath(extract_root))
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            _check_cancel(cancel)
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if (
                stat.S_ISFIFO(unix_mode)
                or stat.S_ISCHR(unix_mode)
                or stat.S_ISBLK(unix_mode)
                or stat.S_ISSOCK(unix_mode)
            ):
                raise SetupError(f"unsafe special file in zip archive: {info.filename!r}")

            is_dir_entry = info.is_dir() or info.filename.endswith(("/", "\\"))
            rel_path = _validate_and_strip_member_path(info.filename, strip_components, extract_root)
            if rel_path is None:
                continue

            target_path = extract_root / rel_path
            _assert_member_within_root(
                target_path, dest_real, info.filename, escape_prefix="zip", archive_label="zip"
            )

            if is_dir_entry:
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            if not Path(os.path.realpath(target_path.parent)).is_relative_to(dest_real):
                raise SetupError(f"zip member parent escapes root: {info.filename!r}")

            if stat.S_ISLNK(unix_mode):
                _extract_zip_symlink(zf, info, target_path, dest_real)
                extracted_symlinks.append(target_path)
                continue

            with zf.open(info, "r") as src_fh, open(target_path, "wb") as dst_fh:
                shutil.copyfileobj(src_fh, dst_fh)
            _ensure_executable_mode(target_path, unix_mode)

        _verify_extracted_symlinks(extracted_symlinks, dest_real, "zip")


def _extract_single_binaries(archive_path: Path, dl: Download, tmp_dir: Path, *, compressed: bool) -> None:
    """Copy or gunzip a single-binary artifact into tmp_dir for each declared Binary."""
    for b in dl.binaries:
        rel = _validate_and_strip_member_path(b.path, 0, tmp_dir)
        if not rel:
            raise SetupError(f"invalid binary destination path: {b.path!r}")
        dst_bin = tmp_dir / rel
        dst_bin.parent.mkdir(parents=True, exist_ok=True)
        if compressed:
            with gzip.open(archive_path, "rb") as src_fh, open(dst_bin, "wb") as dst_fh:
                shutil.copyfileobj(src_fh, dst_fh)
        else:
            shutil.copy2(archive_path, dst_bin)


def _atomic_replace_install_dir(
    tmp_dir: Path,
    item_install_dir: Path,
    inst_root: Path,
    *,
    r_home: Path | None,
    env: Mapping[str, str] | None,
) -> None:
    """Atomically swap tmp_dir into item_install_dir, restoring any previous install on error."""
    _assert_managed_path(item_install_dir, inst_root, r_home=r_home, env=env)
    backup_dir = item_install_dir.with_name(f"{item_install_dir.name}.old-{os.getpid()}")
    if backup_dir.exists() or backup_dir.is_symlink():
        _remove_managed_path(backup_dir, inst_root, r_home=r_home, env=env)

    had_old = False
    if item_install_dir.exists() or item_install_dir.is_symlink():
        os.replace(item_install_dir, backup_dir)
        had_old = True

    try:
        os.replace(tmp_dir, item_install_dir)
    except Exception:
        if had_old and (backup_dir.exists() or backup_dir.is_symlink()):
            with contextlib.suppress(Exception):
                os.replace(backup_dir, item_install_dir)
        raise

    if had_old and (backup_dir.exists() or backup_dir.is_symlink()):
        with contextlib.suppress(Exception):
            _remove_managed_path(backup_dir, inst_root, r_home=r_home, env=env)


def _merge_rust_components(root: Path, components: Sequence[str]) -> None:
    """Merge rust-installer component dirs under root into one prefix (what install.sh does).

    Each component lists its files in `<component>/manifest.in` as `file:<rel>` or
    `dir:<rel>`; they are moved to `<root>/<rel>`. Then the component dir is removed.
    """
    comp_set = set(components)
    for comp in components:
        cdir = root / comp
        if cdir.is_symlink() or not cdir.is_dir():
            raise SetupError(f"rust installer is missing component {comp!r}")
        manifest = cdir / "manifest.in"
        if manifest.is_symlink() or not manifest.is_file():
            raise SetupError(f"rust installer component {comp!r} has no manifest.in")
        for raw_line in manifest.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            kind, sep, rel = line.partition(":")
            if not sep or kind not in ("file", "dir"):
                raise SetupError(f"invalid manifest.in line in {comp!r}: {line!r}")
            rel_norm = _validate_and_strip_member_path(rel, 0, root)
            if rel_norm is None or rel_norm.split("/", 1)[0] in comp_set:
                raise SetupError(f"unsafe manifest.in path in {comp!r}: {rel!r}")
            src, dst = cdir / rel_norm, root / rel_norm
            if src.is_symlink() or not src.exists():
                raise SetupError(f"rust component {comp!r} lacks listed path {rel_norm!r}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            if kind == "file":
                if os.path.lexists(dst):
                    raise SetupError(f"rust components both provide {rel_norm!r}")
                os.replace(src, dst)
            elif os.path.lexists(dst):
                shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
            else:
                os.replace(src, dst)
        shutil.rmtree(cdir)


def _extract_nupkg(archive_path: Path, dest: Path, cancel: threading.Event | None) -> None:
    """Extract a .nupkg (zip) into dest: refuse traversal, absolute, drive, symlink and special members.

    NuGet packaging files (_rels/, package/, [Content_Types].xml, .signature.p7s,
    *.nuspec at the top level) are not extracted.
    """
    dest_real = Path(os.path.realpath(dest))
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            _check_cancel(cancel)
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                raise SetupError(f"refusing symlink member in package: {info.filename!r}")
            ftype = stat.S_IFMT(unix_mode)
            if ftype and ftype not in (stat.S_IFREG, stat.S_IFDIR):
                raise SetupError(f"refusing special member in package: {info.filename!r}")
            name = unquote(info.filename)
            rel_path = _validate_and_strip_member_path(name, 0, dest)
            if rel_path is None:
                continue
            top = rel_path.split("/", 1)[0]
            if top in _NUPKG_PACKAGING_TOP or ("/" not in rel_path and rel_path.lower().endswith(".nuspec")):
                continue
            target = dest / rel_path
            _assert_member_within_root(target, dest_real, info.filename, escape_prefix="package", archive_label="package")
            if info.is_dir() or name.endswith(("/", "\\")):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if not Path(os.path.realpath(target.parent)).is_relative_to(dest_real):
                raise SetupError(f"package member parent escapes root: {info.filename!r}")
            with zf.open(info, "r") as src_fh, open(target, "xb") as dst_fh:
                shutil.copyfileobj(src_fh, dst_fh)


def _nuget_config_text(source_dir: Path) -> str:
    """NuGet.config listing only source_dir (every inherited source cleared)."""
    value = xml.sax.saxutils.quoteattr(str(source_dir))
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<configuration>\n"
        "  <packageSources>\n"
        "    <clear />\n"
        f"    <add key=\"defuzz-verified\" value={value} />\n"
        "  </packageSources>\n"
        "  <auditSources>\n"
        "    <clear />\n"
        "  </auditSources>\n"
        "</configuration>\n"
    )


def _fetch_verified_packages(
    item: SetupItem,
    *,
    fetcher: Callable[[str, Path, Callable[[int, int], None]], None],
    c_dir: Path,
    inst_root: Path,
    r_home: Path,
    env: Mapping[str, str] | None,
    cancel: threading.Event | None,
) -> Path | None:
    """Download and checksum-verify item.packages into a fresh dir under inst_root.

    Returns the dir (with NuGet.config when a dotnet tool is staged), or None when
    the item has no packages. Any failure removes the dir and raises one SetupError line.
    """
    if not item.packages:
        return None
    inst_root.mkdir(parents=True, exist_ok=True)
    pkg_dir = Path(tempfile.mkdtemp(prefix=f".{item.name}-packages-", dir=str(inst_root)))
    try:
        for pkg in item.packages:
            _check_cancel(cancel)
            cached = c_dir / f"{item.name}-{pkg.name}-{pkg.version}-{pkg.filename}"
            c_dir.mkdir(parents=True, exist_ok=True)
            try:
                fetcher(pkg.url, cached, lambda _d, _t: _check_cancel(cancel))
                staged = pkg_dir / pkg.filename
                if cached.is_file():
                    shutil.copy2(cached, staged)
                try:
                    _verify_checksum(
                        staged, url=pkg.url, expected_hash=pkg.hash, hash_algo=pkg.hash_algo, cancel=cancel
                    )
                except SetupError:
                    cached.unlink(missing_ok=True)
                    raise
            except SetupError as exc:
                raise SetupError(f"{pkg.name} {pkg.version}: {exc}; nothing installed for {item.name}") from exc
        if any(pkg.kind == "dotnet-tool" for pkg in item.packages):
            (pkg_dir / "NuGet.config").write_text(_nuget_config_text(pkg_dir), encoding="utf-8")
        return pkg_dir
    except BaseException:
        with contextlib.suppress(Exception):
            _remove_managed_path(pkg_dir, inst_root, r_home=r_home, env=env)
        raise


def pwsh_modules_root(plat: tuple[str, str], r_home: Path) -> Path:
    """PowerShell 7 CurrentUser modules folder (the one `Install-Module -Scope CurrentUser` uses)."""
    if plat[0] == "windows":
        return r_home / "Documents" / "PowerShell" / "Modules"
    return r_home / ".local" / "share" / "powershell" / "Modules"


_PWSH_MODULE_MARKER = ".defuzz-installed"


def _install_pwsh_module(
    pkg: Package,
    nupkg_path: Path,
    plat: tuple[str, str],
    r_home: Path,
    cancel: threading.Event | None,
) -> str:
    """Extract a verified module .nupkg into <modules>/<name>/<version>; return a log line.

    A version folder Defuzz did not write (no marker) is left as it is.
    """
    module_dir = pwsh_modules_root(plat, r_home) / pkg.name
    final_dir = module_dir / pkg.version
    if final_dir.is_symlink():
        raise SetupError(f"refusing symlinked module folder {final_dir}")
    if final_dir.is_dir() and not (final_dir / _PWSH_MODULE_MARKER).is_file():
        return f"kept existing {pkg.name} {pkg.version} at {final_dir}"
    if module_dir.is_symlink():
        raise SetupError(f"refusing symlinked module folder {module_dir}")
    module_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix=".defuzz-tmp-", dir=str(module_dir)))
    old_dir: Path | None = None
    try:
        _extract_nupkg(nupkg_path, tmp_dir, cancel)
        if not (tmp_dir / f"{pkg.name}.psd1").is_file():
            raise SetupError(f"{pkg.name} {pkg.version}: package has no {pkg.name}.psd1")
        (tmp_dir / _PWSH_MODULE_MARKER).write_text(f"{pkg.name} {pkg.version} {pkg.hash_algo}:{pkg.hash}\n", encoding="utf-8")
        _check_cancel(cancel)
        if final_dir.is_dir():
            old_dir = module_dir / f".defuzz-old-{secrets.token_hex(8)}"
            os.replace(final_dir, old_dir)
        os.replace(tmp_dir, final_dir)
    except BaseException:
        if old_dir is not None and old_dir.is_dir() and not final_dir.exists():
            with contextlib.suppress(OSError):
                os.replace(old_dir, final_dir)
        with contextlib.suppress(Exception):
            shutil.rmtree(tmp_dir)
        raise
    if old_dir is not None:
        with contextlib.suppress(Exception):
            shutil.rmtree(old_dir)
    return f"installed {pkg.name} {pkg.version} into {final_dir}"


def _extract_artifact(
    archive_path: Path,
    dl: Download,
    item_install_dir: Path,
    inst_root: Path,
    cancel: threading.Event | None,
    *,
    r_home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> None:
    """Extract archive_path into a sibling temp dir and atomically replace item_install_dir."""
    _assert_managed_path(item_install_dir, inst_root, r_home=r_home, env=env)
    inst_root.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix=f".{item_install_dir.name}-tmp-", dir=str(inst_root)))
    try:
        if dl.archive in ("tar.gz", "tar.xz"):
            tar_mode = "r:xz" if dl.archive == "tar.xz" else "r:gz"
            _extract_tar(
                archive_path,
                tmp_dir,
                mode=tar_mode,
                strip_components=dl.strip_components,
                cancel=cancel,
                include=dl.include,
            )
        elif dl.archive == "zip":
            _extract_zip(archive_path, tmp_dir, strip_components=dl.strip_components, cancel=cancel)
        elif dl.archive in ("gz", "binary"):
            _extract_single_binaries(archive_path, dl, tmp_dir, compressed=(dl.archive == "gz"))
        else:
            raise SetupError(f"unsupported archive type: {dl.archive!r}")

        if dl.layout == "rust-components":
            _merge_rust_components(tmp_dir, dl.include)
        _check_cancel(cancel)
        _atomic_replace_install_dir(tmp_dir, item_install_dir, inst_root, r_home=r_home, env=env)
    except Exception:
        if tmp_dir.exists() or tmp_dir.is_symlink():
            with contextlib.suppress(Exception):
                _remove_managed_path(tmp_dir, inst_root, r_home=r_home, env=env)
        raise


def _prepare_extracted_binaries(item: SetupItem, dl: Download, item_install_dir: Path) -> None:
    """Verify declared binaries exist in item_install_dir and apply executable permissions."""
    for b in dl.binaries:
        src = item_install_dir / b.path
        if not src.is_file():
            raise SetupError(f"missing expected binary {b.path!r} in {item.name} archive")
        if dl.chmod and os.name != "nt":
            src.chmod(src.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _expose_binaries(
    item: SetupItem,
    dl: Download,
    plat: tuple[str, str],
    item_install_dir: Path,
    b_dir: Path,
) -> None:
    """Chmod extracted binaries and expose them in bin_dir via symlink (POSIX) or copy (Windows)."""
    _prepare_extracted_binaries(item, dl, item_install_dir)
    b_dir.mkdir(parents=True, exist_ok=True)
    is_win = plat[0] == "windows" or os.name == "nt"
    for b in dl.binaries:
        src = item_install_dir / b.path
        dst = b_dir / exe_name(b.name, plat)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        if is_win:
            shutil.copy2(src, dst)
        else:
            dst.symlink_to(src)


def _substitute_cmd(
    raw_cmd: Sequence[str],
    item_install_dir: Path,
    b_dir: Path,
    r_home: Path,
    *,
    external_dotnet: str | None = None,
    pkg_dir: Path | str | None = None,
) -> list[str]:
    """Substitute {install_dir}, {bin_dir}, {real_home} and {pkg_dir} placeholders in an argv tuple."""
    inst_str, bin_str, home_str = str(item_install_dir), str(b_dir), str(r_home)
    if pkg_dir is None and any("{pkg_dir}" in arg for arg in raw_cmd):
        raise SetupError("post_install needs verified packages ({pkg_dir}) but none were staged")
    pkg_str = str(pkg_dir) if pkg_dir is not None else ""
    substituted = [
        arg.replace("{install_dir}", inst_str)
        .replace("{bin_dir}", bin_str)
        .replace("{real_home}", home_str)
        .replace("{pkg_dir}", pkg_str)
        for arg in raw_cmd
    ]
    if external_dotnet is not None and raw_cmd and raw_cmd[0] == "{install_dir}/dotnet":
        substituted[0] = external_dotnet
    return substituted


def _post_install_env(
    item: SetupItem,
    eff_env: Mapping[str, str],
    item_install_dir: Path,
    b_dir: Path,
    r_home: Path,
    *,
    use_managed_dotnet_root: bool = True,
) -> dict[str, str]:
    """Build the subprocess environment for an item's post_install commands."""
    cmd_env = dict(eff_env)
    lint_env._apply_toolchain_defaults(cmd_env, r_home)

    if item.name == "rustup":
        cmd_env["RUSTUP_INIT_SKIP_PATH_CHECK"] = "yes"
    elif item.name == "dotnet":
        if use_managed_dotnet_root:
            cmd_env["DOTNET_ROOT"] = str(item_install_dir)
        cmd_env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        cmd_env["DOTNET_NOLOGO"] = "1"
        cmd_env["DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE"] = "1"

    path_entries = [p for p in cmd_env.get("PATH", "").split(os.pathsep) if p]
    if str(b_dir) not in path_entries:
        path_entries.insert(0, str(b_dir))
    cmd_env["PATH"] = os.pathsep.join(path_entries)
    return cmd_env


def _pid_is_alive(pid: int) -> bool:
    """Return True if a process with pid is currently alive."""
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _acquire_setup_lock(
    inst_root: Path,
    *,
    r_home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Acquire install_root/.adopt-setup.lock via O_CREAT|O_EXCL, recovering stale locks."""
    lock_path = inst_root / ".adopt-setup.lock"
    _assert_managed_path(lock_path, inst_root, r_home=r_home, env=env)
    _ensure_real_dir_chain(inst_root, inst_root)
    for _ in range(2):
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raw = ""
            with contextlib.suppress(Exception):
                raw = lock_path.read_text(encoding="utf-8").strip()
            holder_pid: int | None = None
            with contextlib.suppress(ValueError):
                holder_pid = int(raw)
            if holder_pid is not None and not _pid_is_alive(holder_pid):
                with contextlib.suppress(OSError):
                    lock_path.unlink(missing_ok=True)
                continue
            pid_label = str(holder_pid) if holder_pid is not None else (raw or "unknown")
            raise SetupError(f"setup already running (pid {pid_label})") from None
        try:
            os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
        finally:
            os.close(fd)
        return lock_path
    raise SetupError("setup already running (pid unknown)")


def _stage_verify_and_extract(
    dest_file: Path,
    item: SetupItem,
    dl: Download,
    idx: int,
    *,
    item_install_dir: Path,
    inst_root: Path,
    r_home: Path,
    env: Mapping[str, str] | None,
    cancel: threading.Event | None,
    emit: Callable[[SetupItem, int, str, int, int, float, str], None],
) -> int:
    """Copy downloaded archive to a staging directory, verify checksum, and extract."""
    inst_root.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=f".{item.name}-verify-", dir=str(inst_root)))
    try:
        verified_file = stage_dir / dest_file.name
        if dest_file.is_file():
            shutil.copy2(dest_file, verified_file)

        file_size = verified_file.stat().st_size if verified_file.is_file() else 0
        emit(item, idx, "verify", file_size, file_size, 0.75, f"Verifying {dl.hash_algo} checksum for {item.name}")
        try:
            _verify_checksum(
                verified_file, url=dl.url, expected_hash=dl.hash, hash_algo=dl.hash_algo, cancel=cancel
            )
        except SetupError:
            dest_file.unlink(missing_ok=True)
            raise

        _check_cancel(cancel)
        emit(item, idx, "extract", file_size, file_size, 0.85, f"Extracting {item.name} {item.version}")
        _extract_artifact(verified_file, dl, item_install_dir, inst_root, cancel, r_home=r_home, env=env)
        return file_size
    finally:
        if stage_dir.exists() or stage_dir.is_symlink():
            with contextlib.suppress(Exception):
                _remove_managed_path(stage_dir, inst_root, r_home=r_home, env=env)


def _ensure_real_dir_chain(target_dir: Path, inst_root: Path) -> None:
    """Ensure inst_root, its ancestors, and target_dir are real directories (never symlinks, checked via lstat)."""
    inst_abs = Path(os.path.abspath(Path(inst_root).expanduser()))
    target_abs = Path(os.path.abspath(Path(target_dir).expanduser()))
    if target_abs != inst_abs and not target_abs.is_relative_to(inst_abs):
        raise SetupError(f"path {target_dir!s} is not inside install_root {inst_root!s}")

    # Check all existing ancestors from filesystem root down to inst_abs with lstat.
    cur = Path(inst_abs.anchor)
    for part in inst_abs.parts[1:]:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            cur.mkdir(mode=0o755, exist_ok=False)
            st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise SetupError(f"refusing symlink or non-directory ancestor {cur!s}")

    # Ensure each component from inst_abs down to target_abs is a real directory.
    rel_parts = target_abs.relative_to(inst_abs).parts
    cur = inst_abs
    for part in rel_parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            cur.mkdir(mode=0o755, exist_ok=False)
            st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise SetupError(f"refusing symlink or non-directory managed path {cur!s}")


def _create_fresh_csharpier_version_dir(csharpier_root: Path, inst_root: Path) -> Path:
    """Create a fresh, never-existing <install_root>/csharpier/<ver>-<random> directory with exclusive mkdir."""
    _ensure_real_dir_chain(csharpier_root, inst_root)
    for _ in range(16):
        candidate = csharpier_root / f"{_CSHARPIER_VERSION}-{secrets.token_hex(8)}"
        try:
            os.lstat(candidate)
            continue
        except FileNotFoundError:
            pass
        candidate.mkdir(mode=0o755, exist_ok=False)
        st = os.lstat(candidate)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise SetupError(f"refusing symlinked versioned directory {candidate!s}")
        return candidate
    raise SetupError(f"could not allocate fresh versioned csharpier directory under {csharpier_root!s}")


def _cleanup_old_csharpier_version_dirs(
    csharpier_root: Path,
    active_dir: Path,
    b_dir: Path,
    plat: tuple[str, str],
) -> None:
    """Best-effort remove old csharpier/<ver>-<random> directories that are no longer the active link target."""
    with contextlib.suppress(Exception):
        root_st = os.lstat(csharpier_root)
        if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
            return
        active_abs = os.path.abspath(active_dir)
        published_link = b_dir / exe_name("csharpier", plat)
        link_target_dir: str | None = None
        with contextlib.suppress(OSError):
            if stat.S_ISLNK(os.lstat(published_link).st_mode):
                raw_target = os.readlink(published_link)
                resolved_target = os.path.abspath(os.path.join(str(published_link.parent), raw_target))
                link_target_dir = os.path.dirname(resolved_target)

        with os.scandir(csharpier_root) as it:
            for entry in it:
                if not _CSHARPIER_VERSIONED_DIR_RE.fullmatch(entry.name):
                    continue
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
                cand_abs = os.path.abspath(entry.path)
                if cand_abs == active_abs or (link_target_dir is not None and cand_abs == link_target_dir):
                    continue
                with contextlib.suppress(Exception):
                    shutil.rmtree(cand_abs)


def _publish_csharpier_symlink(
    versioned_cs: Path, b_dir: Path, inst_root: Path, plat: tuple[str, str], state: dict[str, Any] | None = None
) -> None:
    """Atomically publish <bin_dir>/csharpier via a single temp symlink + os.replace.

    ``state`` records what THIS invocation created (``created_bin``, ``tmp_link``) so rollback
    removes only its own artifacts.
    """
    state = {} if state is None else state
    bin_was_present = os.path.lexists(b_dir)
    if not bin_was_present:
        # Set before creation so an interrupt during/after mkdir still lets rollback remove it (if empty).
        state["bin_pending"] = True
    _ensure_real_dir_chain(b_dir, inst_root)
    if not bin_was_present and os.path.isdir(b_dir):
        state["created_bin"] = True
    dst_link = b_dir / exe_name("csharpier", plat)
    try:
        dst_st = os.lstat(dst_link)
        if stat.S_ISDIR(dst_st.st_mode) and not stat.S_ISLNK(dst_st.st_mode):
            raise SetupError(f"refusing to replace directory {dst_link!s} with csharpier symlink")
    except FileNotFoundError:
        pass
    tmp_link = b_dir / f".csharpier.tmp-{secrets.token_hex(8)}"
    our_target = os.path.abspath(versioned_cs)  # unique fresh versioned dir: identifies OUR link
    try:
        os.symlink(our_target, tmp_link)
        state["tmp_link"] = tmp_link
        state["tmp_target"] = our_target
        os.replace(tmp_link, dst_link)
    except BaseException:
        # Remove the temp link only if it is ours (points at our fresh versioned dir); a
        # pre-existing link that merely collides on the name is never touched.
        with contextlib.suppress(OSError):
            if stat.S_ISLNK(os.lstat(tmp_link).st_mode) and os.readlink(tmp_link) == our_target:
                os.unlink(tmp_link)
        raise


# Note: static symlink/non-directory rejection is enforced via lstat before writes/deletes; concurrent local TOCTOU directory swaps between check and use are out of scope (no dir-fd confinement).
def _run_dotnet_tool_only_install(
    item: SetupItem,
    idx: int,
    *,
    plat: tuple[str, str],
    ext_dotnet: str | None,
    eff_env: Mapping[str, str],
    item_install_dir: Path,
    inst_root: Path,
    b_dir: Path,
    r_home: Path,
    env: Mapping[str, str] | None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None,
    cancel: threading.Event | None,
    emit: Callable[[SetupItem, int, str, int, int, float, str], None],
    pkg_dir: Path | None = None,
) -> None:
    """Install csharpier into a fresh versioned dir under install_root, verify, and atomically symlink into b_dir."""
    csharpier_root, bin_existed = inst_root / "csharpier", os.path.lexists(b_dir)
    _assert_managed_path(b_dir, inst_root, r_home=r_home, env=env)
    _assert_managed_path(csharpier_root, inst_root, r_home=r_home, env=env)
    versioned_dir: Path | None = None
    published = False
    owned: dict[str, Any] = {}
    try:
        _ensure_real_dir_chain(csharpier_root, inst_root)
        _ensure_real_dir_chain(b_dir if bin_existed else inst_root, inst_root)
        _check_cancel(cancel)
        emit(item, idx, "post_install", 0, 0, 0.95, f"Running post-install for {item.name}")
        if not item.post_install:
            return
        versioned_dir = _create_fresh_csharpier_version_dir(csharpier_root, inst_root)
        use_managed_root = ext_dotnet is None
        cmd_env = _post_install_env(
            item, eff_env, item_install_dir, b_dir, r_home, use_managed_dotnet_root=use_managed_root
        )
        run_cwd = item_install_dir if (use_managed_root and item_install_dir.is_dir()) else versioned_dir
        for raw_cmd in item.post_install:
            _check_cancel(cancel)
            argv = _substitute_cmd(
                raw_cmd, item_install_dir, versioned_dir, r_home, external_dotnet=ext_dotnet, pkg_dir=pkg_dir
            )
            cp = run(argv, cwd=run_cwd, env=cmd_env, timeout_s=_POST_INSTALL_TIMEOUT_S, runner=runner)
            if cp.returncode != 0:
                tail = (cp.stderr or cp.stdout or "").strip()[-500:]
                raise SetupError(f"post_install failed for {item.name} (rc={cp.returncode}): {tail}")

        _check_cancel(cancel)
        versioned_cs = versioned_dir / exe_name("csharpier", plat)
        ok, err = _verify_csharpier_binary(
            versioned_cs, cmd_env, expected_version=_CSHARPIER_VERSION, runner=runner
        )
        if not ok:
            raise SetupError(f"csharpier verification failed after install: {err}")

        _check_cancel(cancel)
        _publish_csharpier_symlink(versioned_cs, b_dir, inst_root, plat, owned)
        published = True
    except BaseException:
        _rollback_csharpier_install(versioned_dir, b_dir, owned, plat, published=published)
        raise

    _cleanup_old_csharpier_version_dirs(csharpier_root, versioned_dir, b_dir, plat)


def _is_versioned_csharpier_published(
    versioned_dir: Path,
    b_dir: Path,
    plat: tuple[str, str],
) -> bool:
    """Return True if <b_dir>/csharpier resolves to versioned_dir (or if state cannot be safely determined)."""
    dst_link = b_dir / exe_name("csharpier", plat)
    ver_abs = os.path.abspath(versioned_dir)
    ver_cs_abs = os.path.abspath(versioned_dir / exe_name("csharpier", plat))
    try:
        st = os.lstat(dst_link)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        try:
            raw_target = os.readlink(dst_link)
        except OSError:
            return True
        resolved_target = os.path.abspath(os.path.join(str(dst_link.parent), raw_target))
        if resolved_target == ver_cs_abs or os.path.dirname(resolved_target) == ver_abs:
            return True
    try:
        return os.path.realpath(dst_link) == os.path.realpath(ver_cs_abs)
    except OSError:
        return True


def _rollback_csharpier_install(
    versioned_dir: Path | None,
    b_dir: Path,
    owned: Mapping[str, Any],
    plat: tuple[str, str],
    *,
    published: bool,
) -> None:
    """Remove only what this invocation created: its own temp link, unpublished versioned_dir, and a bin dir it created."""
    tmp_link, tmp_target = owned.get("tmp_link"), owned.get("tmp_target")
    if tmp_link is not None:
        with contextlib.suppress(OSError):
            if stat.S_ISLNK(os.lstat(tmp_link).st_mode) and os.readlink(tmp_link) == tmp_target:
                os.unlink(tmp_link)

    is_published = published or (
        versioned_dir is not None and _is_versioned_csharpier_published(versioned_dir, b_dir, plat)
    )
    if not is_published:
        if versioned_dir is not None:
            with contextlib.suppress(Exception):
                st = os.lstat(versioned_dir)
                if not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode):
                    shutil.rmtree(versioned_dir)
        if owned.get("created_bin") or owned.get("bin_pending"):
            # os.rmdir only succeeds on an empty dir, so content placed by others is never removed.
            with contextlib.suppress(OSError):
                st_b = os.lstat(b_dir)
                if not stat.S_ISLNK(st_b.st_mode) and stat.S_ISDIR(st_b.st_mode):
                    os.rmdir(b_dir)


def _finalize_item_install(
    item: SetupItem,
    dl: Download,
    idx: int,
    *,
    file_size: int,
    plat: tuple[str, str],
    eff_env: Mapping[str, str],
    item_install_dir: Path,
    inst_root: Path,
    b_dir: Path,
    r_home: Path,
    env: Mapping[str, str] | None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None,
    cancel: threading.Event | None,
    emit: Callable[[SetupItem, int, str, int, int, float, str], None],
    pkg_dir: Path | None = None,
) -> list[str]:
    """Run post_install commands, install verified packages, expose binaries, write version marker."""
    notes: list[str] = []
    try:
        _prepare_extracted_binaries(item, dl, item_install_dir)
        _check_cancel(cancel)
        emit(item, idx, "post_install", file_size, file_size, 0.95, f"Running post-install for {item.name}")
        if item.post_install:
            cmd_env = _post_install_env(item, eff_env, item_install_dir, b_dir, r_home)
            for raw_cmd in item.post_install:
                _check_cancel(cancel)
                argv = _substitute_cmd(raw_cmd, item_install_dir, b_dir, r_home, pkg_dir=pkg_dir)
                cp = run(argv, cwd=item_install_dir, env=cmd_env, timeout_s=_POST_INSTALL_TIMEOUT_S, runner=runner)
                if cp.returncode != 0:
                    tail = (cp.stderr or cp.stdout or "").strip()[-500:]
                    raise SetupError(f"post_install failed for {item.name} (rc={cp.returncode}): {tail}")

        for pkg in item.packages:
            if pkg.kind == "pwsh-module" and pkg_dir is not None:
                _check_cancel(cancel)
                notes.append(_install_pwsh_module(pkg, pkg_dir / pkg.filename, plat, r_home, cancel))

        _check_cancel(cancel)
        _expose_binaries(item, dl, plat, item_install_dir, b_dir)
        marker = item_install_dir / f".adopt-installed-{item.version}"
        marker.write_text(f"{item.name} {item.version}\n", encoding="utf-8")
    except BaseException:
        if item_install_dir.exists() or item_install_dir.is_symlink():
            with contextlib.suppress(Exception):
                _remove_managed_path(item_install_dir, inst_root, r_home=r_home, env=env)
        raise
    return notes


def _download_setup_artifact(
    item: SetupItem,
    dl: Download,
    idx: int,
    *,
    c_dir: Path,
    item_install_dir: Path,
    inst_root: Path,
    r_home: Path,
    env: Mapping[str, str] | None,
    cancel: threading.Event | None,
    fetcher: Callable[[str, Path, Callable[[int, int], None]], None],
    emit: Callable[[SetupItem, int, str, int, int, float, str], None],
) -> Path:
    """Download one main artifact and report its byte-level progress."""
    basename = PurePosixPath(urlparse(dl.url).path).name or item.name
    dest_file = c_dir / f"{item.name}-{item.version}-{basename}"
    _assert_managed_path(item_install_dir, inst_root, r_home=r_home, env=env)
    c_dir.mkdir(parents=True, exist_ok=True)
    emit(item, idx, "download", 0, 0, 0.05, f"Downloading {item.name} {item.version}")

    def _on_bytes(done: int, total: int, _item: SetupItem = item, _idx: int = idx) -> None:
        _check_cancel(cancel)
        frac = 0.7 * (done / total) if total > 0 else 0.35
        emit(
            _item,
            _idx,
            "download",
            done,
            total,
            min(0.7, max(0.05, frac)),
            f"Downloading {_item.name} {_item.version}",
        )

    fetcher(dl.url, dest_file, _on_bytes)
    _check_cancel(cancel)
    return dest_file


def run_setup(
    progress: Callable[[Progress], None] | None = None,
    *,
    platform: tuple[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    fetch: Callable[[str, Path, Callable[[int, int], None]], None] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    cancel: threading.Event | None = None,
    **paths: Any,
) -> SetupResult:
    """Download, verify, extract, link, and configure all missing manifest tools."""
    installed: list[str] = []
    skipped: list[str] = []
    failed: dict[str, str] = {}
    log: list[str] = []
    lock_path: Path | None = None

    try:
        plat = platform if platform is not None else current_platform()
        st = status(platform=plat, env=env, **paths)
        if not st.lazy_installs_allowed:
            reason = st.blocked_reason or _format_blocked_reason(st.pending_mb)
            return SetupResult(ok=False, installed=[], skipped=[], failed={}, error=reason, log=[reason])

        inst_root, b_dir, c_dir, r_home = _resolve_paths(env, paths)
        eff_env = _prepare_env(env, inst_root=inst_root, b_dir=b_dir, r_home=r_home, paths=paths)
        pairs = _get_downloads(plat, paths.get("items"))
        lock_path = _acquire_setup_lock(inst_root, r_home=r_home, env=env)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        log.append(f"setup failed: {msg}")
        return SetupResult(ok=False, installed=installed, skipped=skipped, failed=failed, error=msg, log=log)

    try:
        _migrate_legacy_rustup_bin(inst_root, b_dir, plat, r_home=r_home, env=env)
        fetcher = fetch if fetch is not None else _default_fetch
        item_count = len(pairs)
        total_mb = sum(max(item.size_mb, 1) for item, _ in pairs)
        completed_mb = 0

        def _emit(
            item: SetupItem,
            idx: int,
            step: str,
            bytes_done: int,
            bytes_total: int,
            item_fraction: float,
            message: str,
        ) -> None:
            if progress is None:
                return
            weight = max(item.size_mb, 1)
            if total_mb <= 0 or (step in ("done", "skipped") and idx == item_count - 1):
                pct = 100.0
            else:
                pct = round(min(100.0, ((completed_mb + weight * item_fraction) / total_mb) * 100.0), 2)
            try:
                progress(
                    Progress(
                        item=item.name,
                        step=step,
                        item_index=idx,
                        item_count=item_count,
                        bytes_done=bytes_done,
                        bytes_total=bytes_total,
                        percent=pct,
                        message=message,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log.append(f"progress callback error on {item.name} ({step}): {exc}")

        for idx, (item, dl) in enumerate(pairs):
            pkg_dir: Path | None = None
            try:
                _check_cancel(cancel)
                item_install_dir = inst_root / item.name
                if _is_item_present(item, dl, plat, eff_env, item_install_dir, b_dir):
                    skipped.append(item.name)
                    log.append(f"skipped {item.name} {item.version} (already present)")
                    _emit(item, idx, "skipped", 0, 0, 1.0, f"Skipped {item.name} {item.version} (already present)")
                    completed_mb += max(item.size_mb, 1)
                    continue

                if item.packages:
                    _emit(item, idx, "download", 0, 0, 0.02, f"Downloading and verifying packages for {item.name}")
                    pkg_dir = _fetch_verified_packages(
                        item, fetcher=fetcher, c_dir=c_dir, inst_root=inst_root, r_home=r_home, env=env, cancel=cancel
                    )

                ext_dotnet = (
                    _external_dotnet_path(plat, eff_env, inst_root, b_dir) if item.name == "dotnet" else None
                )
                has_managed_dotnet = item.name == "dotnet" and _marker_and_binaries_present(
                    item, dl, plat, item_install_dir, b_dir
                )
                if ext_dotnet is not None or has_managed_dotnet:
                    _run_dotnet_tool_only_install(
                        item,
                        idx,
                        plat=plat,
                        ext_dotnet=ext_dotnet,
                        eff_env=eff_env,
                        item_install_dir=item_install_dir,
                        inst_root=inst_root,
                        b_dir=b_dir,
                        r_home=r_home,
                        env=env,
                        runner=runner,
                        cancel=cancel,
                        emit=_emit,
                        pkg_dir=pkg_dir,
                    )
                    installed.append(item.name)
                    log.append(f"installed {item.name} {item.version}")
                    _emit(item, idx, "done", 0, 0, 1.0, f"Installed {item.name} {item.version}")
                    completed_mb += max(item.size_mb, 1)
                    continue

                dest_file = _download_setup_artifact(
                    item, dl, idx, c_dir=c_dir, item_install_dir=item_install_dir,
                    inst_root=inst_root, r_home=r_home, env=env, cancel=cancel,
                    fetcher=fetcher, emit=_emit,
                )

                file_size = _stage_verify_and_extract(
                    dest_file,
                    item,
                    dl,
                    idx,
                    item_install_dir=item_install_dir,
                    inst_root=inst_root,
                    r_home=r_home,
                    env=env,
                    cancel=cancel,
                    emit=_emit,
                )
                notes = _finalize_item_install(
                    item,
                    dl,
                    idx,
                    file_size=file_size,
                    plat=plat,
                    eff_env=eff_env,
                    item_install_dir=item_install_dir,
                    inst_root=inst_root,
                    b_dir=b_dir,
                    r_home=r_home,
                    env=env,
                    runner=runner,
                    cancel=cancel,
                    emit=_emit,
                    pkg_dir=pkg_dir,
                )
                log.extend(notes or [])

                installed.append(item.name)
                log.append(f"installed {item.name} {item.version}")
                _emit(item, idx, "done", file_size, file_size, 1.0, f"Installed {item.name} {item.version}")
                completed_mb += max(item.size_mb, 1)

            except _CancelledError:
                log.append("cancelled")
                return SetupResult(
                    ok=False, installed=installed, skipped=skipped, failed=failed, error="cancelled", log=log
                )
            except Exception as exc:  # noqa: BLE001 - fail closed on any per-item setup failure
                msg = str(exc)
                failed[item.name] = msg
                log.append(f"failed {item.name}: {msg}")
                return SetupResult(
                    ok=False, installed=installed, skipped=skipped, failed=failed, error=msg, log=log
                )
            finally:
                if pkg_dir is not None and (pkg_dir.exists() or pkg_dir.is_symlink()):
                    with contextlib.suppress(Exception):
                        _remove_managed_path(pkg_dir, inst_root, r_home=r_home, env=env)

        return SetupResult(ok=True, installed=installed, skipped=skipped, failed=failed, error=None, log=log)
    finally:
        if lock_path is not None:
            with contextlib.suppress(OSError):
                lock_path.unlink(missing_ok=True)


def headless_message(
    platform: tuple[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    **paths: Any,
) -> str:
    """Return the actionable setup message for non-interactive CLI and cron contexts."""
    plat = platform if platform is not None else current_platform()
    st = status(platform=plat, env=env, **paths)
    mb = st.pending_mb if st.pending_mb > 0 else total_size_mb(plat)
    return (
        "Lint-tool setup is pending. Open the Project Defuzz page in the Hermes desktop app "
        f"and run setup (~{mb} MB), or run `hermes defuzz setup-tools --yes` in a terminal."
    )


def _source_row(name: str, version: str, url: str, hash_val: str, hash_algo: str) -> dict[str, Any]:
    """One disclosed download: where it comes from and how it is checked."""
    return {
        "name": name,
        "version": version,
        "url": url,
        "host": urlparse(url).hostname or "",
        "hash_algo": hash_algo,
        "hash": hash_val,
        "verification": VERIFIED_BY_CHECKSUM,
    }


def _item_sources(item: SetupItem, dl: Download | None, *, include_main: bool = True) -> list[dict[str, Any]]:
    """Main artifact (when included) plus every pinned follow-up package for item."""
    rows: list[dict[str, Any]] = []
    if include_main and dl is not None:
        rows.append(_source_row(item.name, item.version, dl.url, dl.hash, dl.hash_algo))
    rows.extend(_source_row(p.name, p.version, p.url, p.hash, p.hash_algo) for p in item.packages)
    return rows


def download_sources(
    plat: tuple[str, str] | None = None,
    items: Sequence[SetupItem] | None = None,
) -> list[dict[str, Any]]:
    """Every file setup may download on plat, with its official URL and pinned checksum."""
    plat = plat if plat is not None else current_platform()
    rows: list[dict[str, Any]] = []
    for item, dl in _get_downloads(plat, items):
        rows.extend(_item_sources(item, dl))
    return rows


def _plan_row(
    *,
    name: str,
    kind: str,
    version: str,
    size_mb: int,
    url: str,
    hash_value: str,
    hash_algo: str,
    sources: list[dict[str, Any]],
    install_dir: str,
    post_install: list[str],
    post_install_argv: list[list[str]],
) -> dict[str, Any]:
    """Keep the consent-screen row schema common to both installation plans."""
    return {
        "name": name,
        "kind": kind,
        "version": version,
        "size_mb": size_mb,
        "url": url,
        "hash": hash_value,
        "hash_algo": hash_algo,
        "verification": VERIFIED_BY_CHECKSUM,
        "sources": sources,
        "install_dir": install_dir,
        "post_install": post_install,
        "post_install_argv": post_install_argv,
    }


def _csharpier_plan_row(
    item: SetupItem,
    dl: Download,
    plat: tuple[str, str],
    *,
    inst_root: Path,
    b_dir: Path,
    r_home: Path,
    ext_dotnet: str | None,
) -> dict[str, Any]:
    """Disclose the versioned CSharpier install and its atomic published link."""
    item_install_dir = inst_root / item.name
    csharpier_target_pattern = inst_root / "csharpier" / f"{_CSHARPIER_VERSION}-<random>"
    csharpier_exe = exe_name("csharpier", plat)
    published_link = b_dir / csharpier_exe
    versioned_binary = csharpier_target_pattern / csharpier_exe
    tool_only_substituted = [
        _substitute_cmd(
            cmd,
            item_install_dir,
            csharpier_target_pattern,
            r_home,
            external_dotnet=ext_dotnet,
            pkg_dir=_PLAN_PKG_DIR,
        )
        for cmd in item.post_install
    ]
    tool_sources = _item_sources(item, dl, include_main=False)
    first = tool_sources[0] if tool_sources else {}
    return _plan_row(
        name=item.name,
        kind=item.kind,
        version=_CSHARPIER_VERSION,
        size_mb=sum(p.size_mb for p in item.packages),
        url=first.get("url", ""),
        hash_value=first.get("hash", ""),
        hash_algo=first.get("hash_algo", ""),
        sources=tool_sources,
        install_dir=str(csharpier_target_pattern),
        post_install=[
            f"{' '.join(argv)} (symlink {published_link} -> {versioned_binary})"
            for argv in tool_only_substituted
        ],
        post_install_argv=tool_only_substituted,
    )


def _artifact_plan_row(
    item: SetupItem,
    dl: Download,
    plat: tuple[str, str],
    *,
    item_install_dir: Path,
    b_dir: Path,
    r_home: Path,
    ext_dotnet: str | None,
) -> dict[str, Any]:
    """Disclose an artifact and its post-install commands and module destinations."""
    substituted = [
        _substitute_cmd(
            cmd, item_install_dir, b_dir, r_home, external_dotnet=ext_dotnet, pkg_dir=_PLAN_PKG_DIR
        )
        for cmd in item.post_install
    ]
    post_lines = [" ".join(argv) for argv in substituted]
    for pkg in item.packages:
        if pkg.kind == "pwsh-module":
            post_lines.append(
                f"extract {pkg.filename} ({VERIFIED_BY_CHECKSUM}) into "
                f"{pwsh_modules_root(plat, r_home) / pkg.name / pkg.version}"
            )
    return _plan_row(
        name=item.name,
        kind=item.kind,
        version=item.version,
        size_mb=item.size_mb,
        url=dl.url,
        hash_value=dl.hash,
        hash_algo=dl.hash_algo,
        sources=_item_sources(item, dl),
        install_dir=str(item_install_dir),
        post_install=post_lines,
        post_install_argv=substituted,
    )


def describe_plan(
    platform: tuple[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    **paths: Any,
) -> list[dict[str, Any]]:
    """Return the consent-screen disclosure plan for all items on the target platform."""
    plat = platform if platform is not None else current_platform()
    inst_root, b_dir, _, r_home = _resolve_paths(env, paths)
    eff_env = _prepare_env(env, inst_root=inst_root, b_dir=b_dir, r_home=r_home, paths=paths)
    plan: list[dict[str, Any]] = []
    for item, dl in _get_downloads(plat, paths.get("items")):
        item_install_dir = inst_root / item.name
        ext_dotnet = (
            _external_dotnet_path(plat, eff_env, inst_root, b_dir) if item.name == "dotnet" else None
        )
        has_managed_dotnet = item.name == "dotnet" and _marker_and_binaries_present(
            item, dl, plat, item_install_dir, b_dir
        )
        tool_only = item.name == "dotnet" and (ext_dotnet is not None or has_managed_dotnet) and not _is_csharpier_present(
            plat, eff_env, b_dir
        )
        if tool_only:
            plan.append(_csharpier_plan_row(
                item, dl, plat, inst_root=inst_root, b_dir=b_dir, r_home=r_home, ext_dotnet=ext_dotnet
            ))
        else:
            plan.append(_artifact_plan_row(
                item, dl, plat, item_install_dir=item_install_dir,
                b_dir=b_dir, r_home=r_home, ext_dotnet=ext_dotnet,
            ))
    return plan
