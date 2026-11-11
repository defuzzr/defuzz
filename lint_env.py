"""Rich-PATH subprocess environment and executable resolution for the Defuzz plugin."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

try:
    from hermes_constants import get_real_home as _hermes_get_real_home
except Exception:  # noqa: BLE001 - optional Hermes helper; any import-time failure means "not available"
    _hermes_get_real_home = None

# Plugin-owned boundary: never inherit arbitrary credentials or interpreter hooks.
LINT_ENV_KEYS = frozenset({
    "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "SystemRoot", "WINDIR", "PATHEXT",
    "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "RUSTUP_HOME", "CARGO_HOME", "GOPATH", "GOROOT", "GOMODCACHE", "DOTNET_ROOT",
    # .NET runtime location for one CPU type, read by the app host before DOTNET_ROOT.
    "DOTNET_ROOT_ARM64", "DOTNET_ROOT_X64",
    "DOTNET_CLI_HOME",  # dotnet: folder used instead of HOME for its own user files.
    "DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_NOLOGO", "RUFF_CACHE_DIR",
})

# The user's own telemetry and network opt-outs for tools lint runs. Passed
# unchanged. None of these names holds a credential; values that embed one
# (a user:password@ part in a proxy URL) are dropped, see _OPTOUT_URL_KEYS.
LINT_OPTOUT_KEYS = frozenset({
    "POWERSHELL_TELEMETRY_OPTOUT",  # pwsh: 1/true stops start-up telemetry to Microsoft.
    "POWERSHELL_UPDATECHECK",  # pwsh: Off stops the new-version check over the network.
    "DOTNET_CLI_TELEMETRY_OPTOUT",  # dotnet: 1/true stops SDK telemetry.
    "DOTNET_NOLOGO",  # dotnet: hides the first-run banner.
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",  # dotnet: skips first-run set-up work.
    "GOFLAGS",  # go: default flags, for example -mod=mod or -mod=vendor.
    "GOPROXY",  # go: module proxy; off stops module downloads.
    "GOSUMDB",  # go: checksum database; off stops lookups at sum.golang.org.
    "GONOSUMDB",  # go: module patterns not checked against the checksum database.
    "GONOPROXY",  # go: module patterns not fetched through the proxy.
    "GOPRIVATE",  # go: private module patterns (no proxy, no checksum lookup).
    "GOTOOLCHAIN",  # go: local stops downloading a newer Go toolchain.
    "GOTELEMETRY",  # go: telemetry mode as the user set it (go telemetry off).
    "CARGO_NET_OFFLINE",  # cargo: true stops all network access.
    "DO_NOT_TRACK",  # general: 1 asks tools that honour it to send no telemetry.
})
LINT_ENV_KEYS = LINT_ENV_KEYS | LINT_OPTOUT_KEYS

# Values that are URLs; dropped when they carry a user name or password.
_OPTOUT_URL_KEYS = frozenset({"GOPROXY", "GOSUMDB"})

# Opt-outs Defuzz sets when the user did not: each only turns off telemetry,
# a banner or an update check, and never changes what a lint tool reports.
LINT_OPTOUT_DEFAULTS = {
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    "DOTNET_NOLOGO": "1",
    "POWERSHELL_TELEMETRY_OPTOUT": "1",
    "POWERSHELL_UPDATECHECK": "Off",
}


def _has_url_credentials(value: str) -> bool:
    """Return True when any URL in ``value`` has a user-info part (``user@host``)."""
    for part in value.replace(",", " ").replace("|", " ").split():
        _, sep, rest = part.partition("://")
        if sep and "@" in rest.split("/", 1)[0]:
            return True
    return False

# Where the .NET app host finds the runtime without DOTNET_ROOT (Linux and macOS,
# including the x64 folder on Apple silicon). A .NET found here needs no variable.
_DOTNET_DEFAULT_ROOTS = (
    "/usr/share/dotnet", "/usr/lib/dotnet", "/usr/lib64/dotnet",
    "/usr/local/share/dotnet", "/usr/local/share/dotnet/x64",
)
_DOTNET_ROOT_KEYS = ("DOTNET_ROOT", "DOTNET_ROOT_ARM64", "DOTNET_ROOT_X64")
# The app host's own words when it finds no runtime at all.
_DOTNET_RUNTIME_NOT_FOUND = "You must install .NET to run this application"

INSTALL_ROOT_REL = Path(".local/opt/defuzz")
TIMEOUT_RC = 124
_WINDOWS_SUFFIXES = (".cmd", ".exe", ".bat", "")


def _norm_path(raw: str | None) -> str:
    """Return a normalized absolute path string for comparison."""
    text = (raw or "").strip()
    if not text:
        return ""
    try:
        return os.path.normcase(os.path.abspath(os.path.expanduser(text)))
    except Exception:
        return os.path.normcase(text)


def _profile_home_str(env: Mapping[str, str] | None = None) -> str | None:
    """Return the <HERMES_HOME>/home path string if HERMES_HOME is configured."""
    hermes_home = (env or {}).get("HERMES_HOME") or os.environ.get("HERMES_HOME")
    if not hermes_home:
        return None
    return str(Path(hermes_home).expanduser() / "home")


def _candidate_home_dirs(lookup: Mapping[str, str]) -> list[str]:
    """Collect candidate OS home directory strings in priority order."""
    candidates = [
        str(lookup.get("HERMES_REAL_HOME") or os.environ.get("HERMES_REAL_HOME", "")).strip(),
        str(lookup.get("HOME") or os.environ.get("HOME", "")).strip(),
    ]
    with contextlib.suppress(Exception):
        import pwd

        candidates.append(pwd.getpwuid(os.getuid()).pw_dir.strip())
    candidates.append(str(lookup.get("USERPROFILE") or os.environ.get("USERPROFILE", "")).strip())
    expanded = os.path.expanduser("~")
    if expanded != "~":
        candidates.append(expanded)
    return candidates


def real_home(env: Mapping[str, str] | None = None) -> Path:
    """Return the OS user's real home directory, never <HERMES_HOME>/home."""
    env_dict = dict(env) if env is not None else None
    prof_norm = _norm_path(_profile_home_str(env_dict))

    if _hermes_get_real_home is not None:
        with contextlib.suppress(Exception):
            cand = str(_hermes_get_real_home(env_dict)).strip()
            if cand and (not prof_norm or _norm_path(cand) != prof_norm):
                return Path(cand)

    lookup = env_dict if env_dict is not None else os.environ
    for cand in _candidate_home_dirs(lookup):
        if cand and (not prof_norm or _norm_path(cand) != prof_norm):
            return Path(cand)

    with contextlib.suppress(Exception):
        return Path(tempfile.gettempdir())
    raise RuntimeError("Cannot resolve a user home or platform temporary directory")


def _dedupe_path_entries(entries: Iterable[str]) -> str:
    """Join non-empty PATH entries with os.pathsep, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for entry in entries:
        if not entry:
            continue
        key = os.path.normcase(entry) if os.name == "nt" else entry
        if key not in seen:
            seen.add(key)
            out.append(entry)
    return os.pathsep.join(out)


def managed_install_root(env: Mapping[str, str] | None = None) -> Path:
    """Resolve an explicit isolated tool root, or the legacy user-space default.

    DEFUZZ_INSTALL_ROOT is deployment configuration, not a child-process export.
    The setup writer still validates every managed target before any mutation.
    """
    source = os.environ if env is None else env
    override = source.get("DEFUZZ_INSTALL_ROOT", "").strip()
    if override:
        root = Path(override).expanduser()
        if not root.is_absolute():
            raise ValueError("DEFUZZ_INSTALL_ROOT must be an absolute path")
        return root
    return real_home(env) / INSTALL_ROOT_REL


def _apply_toolchain_defaults(
    run_env: dict[str, str],
    rhome: Path,
    install_root: Path | None = None,
    *,
    overwrite: bool = False,
) -> None:
    """Populate default RUSTUP_HOME, CARGO_HOME, GOPATH, and DOTNET_ROOT."""
    defaults = {
        "RUSTUP_HOME": str(rhome / ".rustup"),
        "CARGO_HOME": str(rhome / ".cargo"),
        "GOPATH": str(rhome / "go"),
    }
    if install_root is not None and (install_root / "dotnet").is_dir():
        defaults["DOTNET_ROOT"] = str(install_root / "dotnet")
    for key, val in defaults.items():
        if overwrite:
            run_env[key] = val
        else:
            run_env.setdefault(key, val)


def _managed_path_dirs(
    install_root: Path,
    rhome: Path,
    run_env: Mapping[str, str],
    *,
    bin_dir: Path | None = None,
    use_env_dotnet_root: bool = True,
) -> list[Path]:
    """Return ordered managed toolchain bin directories to prepend to PATH."""
    dotnet_root_val = run_env.get("DOTNET_ROOT") if use_env_dotnet_root else None
    return [
        bin_dir if bin_dir is not None else (install_root / "bin"),
        Path(run_env["CARGO_HOME"]) / "bin",
        Path(run_env["GOPATH"]) / "bin",
        install_root / "go" / "bin",
        Path(dotnet_root_val) if dotnet_root_val else (install_root / "dotnet"),
        rhome / ".dotnet" / "tools",
        install_root / "pwsh",
        rhome / ".local" / "bin",
    ]


def _resolve_side_python_bin(raw_base: Mapping[str, str]) -> Path | None:
    """Validate optional DEFUZZ_LINT_PYTHON virtualenv interpreter and return its bin dir."""
    side_python = raw_base.get("DEFUZZ_LINT_PYTHON", "").strip()
    if not side_python:
        return None
    interpreter = Path(side_python).expanduser()
    if not interpreter.is_absolute():
        raise ValueError("DEFUZZ_LINT_PYTHON must be an absolute path")
    if (
        not interpreter.is_file()
        or not os.access(interpreter, os.X_OK)
        or not (interpreter.parent.parent / "pyvenv.cfg").is_file()
    ):
        raise ValueError("DEFUZZ_LINT_PYTHON must name an installed virtualenv interpreter")
    return interpreter.parent


def _derived_dotnet_root(run_env: Mapping[str, str]) -> str | None:
    """Return the .NET install folder of the `dotnet` that PATH runs, when the app host needs it.

    Only when no DOTNET_ROOT variable is set. The real binary (links resolved)
    must sit in a folder with host/fxr, the marker of a .NET install, outside
    the default places. Anything else returns None: no guessing.
    """
    if any(run_env.get(key) for key in _DOTNET_ROOT_KEYS):
        return None
    found = which("dotnet", run_env)
    if not found or not os.path.isabs(found):
        return None
    try:
        real = Path(os.path.realpath(found))
        root = real.parent
        if not (real.is_file() and os.access(real, os.X_OK) and (root / "host" / "fxr").is_dir()):
            return None
    except OSError:
        return None
    if _norm_path(str(root)) in {_norm_path(p) for p in _DOTNET_DEFAULT_ROOTS}:
        return None
    return str(root)


def tool_start_failure_message(tool: str, stdout: str, stderr: str) -> str | None:
    """Return one plain line when a tool's output shows it could not start, else None."""
    if _DOTNET_RUNTIME_NOT_FOUND in f"{stdout}\n{stderr}":
        return (
            f"{tool} could not find the .NET runtime; "
            "set DOTNET_ROOT or install .NET in a default location"
        )
    return None


def build_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build a rich-PATH environment dictionary for running lint tools."""
    raw_base = dict(base if base is not None else os.environ)
    run_env = {key: value for key, value in raw_base.items() if key in LINT_ENV_KEYS}
    for key in _OPTOUT_URL_KEYS:
        if _has_url_credentials(run_env.get(key, "")):
            run_env.pop(key)

    rhome = real_home(raw_base)
    install_root = managed_install_root(raw_base)

    _apply_toolchain_defaults(run_env, rhome, install_root)
    for key, value in LINT_OPTOUT_DEFAULTS.items():
        run_env.setdefault(key, value)
    run_env.pop("PYTHONHOME", None)

    prepend_candidates = _managed_path_dirs(install_root, rhome, run_env)
    if sys.executable:
        prepend_candidates.append(Path(sys.executable).parent)

    side_bin = _resolve_side_python_bin(raw_base)
    if side_bin is not None:
        prepend_candidates.insert(0, side_bin)

    existing_prepend = [str(p) for p in prepend_candidates if p.is_dir()]
    current_entries = [p for p in run_env.get("PATH", "").split(os.pathsep) if p]
    run_env["PATH"] = _dedupe_path_entries([*existing_prepend, *current_entries])
    dotnet_root = _derived_dotnet_root(run_env)
    if dotnet_root:
        run_env["DOTNET_ROOT"] = dotnet_root
    return run_env


def which(
    name: str,
    env: Mapping[str, str],
    *,
    is_windows: bool | None = None,
) -> str | None:
    """Resolve an executable name against env['PATH'] with Windows wrapper priority."""
    win = (os.name == "nt") if is_windows is None else bool(is_windows)
    search_path = env.get("PATH")
    suffixes = _WINDOWS_SUFFIXES if win else ("",)
    for suffix in suffixes:
        found = shutil.which(f"{name}{suffix}", path=search_path)
        if found:
            return found
    return None


def resolve_binaries(
    names: Iterable[str],
    env: Mapping[str, str],
    *,
    is_windows: bool | None = None,
) -> dict[str, str | None]:
    """Resolve multiple binary names against env['PATH']."""
    return {name: which(name, env, is_windows=is_windows) for name in names}


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    """Terminate and, after 1s, force-kill the process group owned by proc."""
    if os.name == "nt":
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=1.0)
        return

    pgid: int | None = None
    with contextlib.suppress(Exception):
        pgid = os.getpgid(proc.pid)
    if pgid is None:
        pgid = proc.pid

    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(pgid, signal.SIGTERM)

    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            proc.poll()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            with contextlib.suppress(Exception):
                proc.wait(timeout=0.1)
            return
        except (PermissionError, OSError):
            break
        time.sleep(0.02)

    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(pgid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait(timeout=0.5)


def run(
    argv: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: int,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an arg-list command in a new process group with timeout teardown."""
    cmd = [str(a) for a in argv]
    if runner is not None:
        return runner(cmd, cwd=cwd, env=env, timeout_s=timeout_s)

    popen_kwargs: dict[str, object] = {
        "cwd": str(cwd),
        "env": dict(env),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "nt":
        create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if create_no_window:
            popen_kwargs["creationflags"] = create_no_window
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **popen_kwargs)  # type: ignore[arg-type]
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        with contextlib.suppress(Exception):
            proc.communicate(timeout=0.2)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=TIMEOUT_RC,
            stdout="",
            stderr=f"timeout after {timeout_s}s",
        )
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode if proc.returncode is not None else 0,
        stdout=stdout or "",
        stderr=stderr or "",
    )
