"""Late guard: platform capability flags must still hold their true values.

Several modules decide once, at import, whether the platform supports
descriptor-relative file calls (for example `os.open in os.supports_dir_fd`).
If a test imports or reloads one of them while it has replaced `os.open` with
a wrapper, the check sees the wrapper, the flag turns False, and every later
test in the same process fails with "os.open does not support dir_fd".

This file is named to run late. It recomputes each flag from the real
functions in the `posix` module and compares it with the value the loaded
module holds, so the next leak fails here with a clear message.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Dict, Tuple

import pytest

from tests import ensure_test_package

ensure_test_package()

if os.name != "posix":  # pragma: no cover - the plugin supports Linux and macOS only
    pytest.skip("capability flags are only defined on POSIX", allow_module_level=True)

import posix  # noqa: E402

_PKG = "hermes_plugins.defuzz"


def _in(name: str, *funcs: str) -> bool:
    supported = getattr(os, name, set())
    return all(getattr(posix, fn, None) in supported for fn in funcs)


def _has(*flags: str) -> bool:
    return all(getattr(os, flag, 0) for flag in flags)


def _fcntl_flock() -> bool:
    try:
        import fcntl
    except ImportError:
        return False
    return hasattr(fcntl, "flock")


# (module, attribute) -> how to compute the true value from the real functions.
_FLAGS: Dict[Tuple[str, str], Callable[[], bool]] = {
    ("audit.fingerprint", "_SUPPORTS_OPEN_DIR_FD"): lambda: _in("supports_dir_fd", "open"),
    ("audit.vendor.static_code", "_SUPPORTS_OPEN_DIR_FD"): lambda: _in("supports_dir_fd", "open"),
    ("audit.vendor.template_drift", "_SUPPORTS_OPEN_DIR_FD"): lambda: _in("supports_dir_fd", "open"),
    ("output_file", "_DIR_FD_SUPPORTED"): lambda: (
        _has("O_NOFOLLOW", "O_DIRECTORY")
        and _in("supports_dir_fd", "open", "mkdir", "stat", "rename", "unlink")
        and _in("supports_follow_symlinks", "stat")
    ),
    ("kit_scaffold", "_HANDLES_SUPPORTED"): lambda: (
        _has("O_NOFOLLOW", "O_DIRECTORY")
        and _in(
            "supports_dir_fd",
            "open", "mkdir", "stat", "rmdir", "unlink", "chmod", "rename", "readlink", "symlink",
        )
        and _in("supports_fd", "scandir")
        and hasattr(os, "fchmod")
    ),
    ("toolchk", "_DIR_FD_OK"): lambda: (
        _has("O_NOFOLLOW", "O_DIRECTORY") and _in("supports_dir_fd", "open", "mkdir", "rename", "unlink")
    ),
    ("state_store", "_SAFE_MIGRATION_CLEANUP"): lambda: (
        _fcntl_flock()
        and _has("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
        and _in("supports_dir_fd", "open", "stat", "unlink", "rmdir")
        and _in("supports_fd", "listdir")
        and _in("supports_follow_symlinks", "stat")
    ),
}


def poisoned_flags() -> list[str]:
    """Return `module.attr` for every loaded capability flag that no longer holds its true value."""
    bad = []
    for (sub, attr), truth in _FLAGS.items():
        mod = sys.modules.get(f"{_PKG}.{sub}")
        if mod is not None and getattr(mod, attr) != truth():
            bad.append(f"{_PKG}.{sub}.{attr}")
    return bad


_OS_FUNCS = ("open", "stat", "lstat", "mkdir", "rename", "unlink", "rmdir", "readlink", "symlink", "chmod", "listdir", "scandir")


def test_os_functions_are_not_left_wrapped() -> None:
    wrapped = [name for name in _OS_FUNCS if getattr(os, name, None) is not getattr(posix, name, None)]
    assert wrapped == [], f"os functions left replaced by an earlier test: {wrapped}"


@pytest.mark.parametrize("module_attr", sorted(_FLAGS), ids=lambda key: f"{key[0]}.{key[1]}")
def test_capability_flag_holds_its_true_value(module_attr: Tuple[str, str]) -> None:
    sub, attr = module_attr
    full = f"{_PKG}.{sub}"
    mod = sys.modules.get(full)
    if mod is None:
        pytest.skip(f"{full} was not imported in this run, so it cannot have leaked")
    assert getattr(mod, attr) == _FLAGS[module_attr](), (
        f"{full}.{attr} is {getattr(mod, attr)!r}: an earlier test imported or reloaded "
        "this module while an os function was wrapped, and did not restore it"
    )
