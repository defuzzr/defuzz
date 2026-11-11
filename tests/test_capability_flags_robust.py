"""Capability flags must not be fooled by a wrapped `os.open`.

Some modules decide once, at import, whether the platform can open files
relative to a folder handle. A wrapper installed on `os.open` (an audit-hook
library, a debugger, a tracing tool, a test spy) is not listed in
`os.supports_dir_fd`, so a naive `os.open in os.supports_dir_fd` check turns
False and the module silently uses a weaker fallback. Each case below imports
the module in a fresh interpreter with the os functions already wrapped, and
checks that the flag is still True and that the handle-based path is taken.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import REPO_ROOT

if not sys.platform.startswith("linux"):  # pragma: no cover - the check below is pinned for Linux
    pytest.skip("descriptor-relative calls are asserted on Linux only", allow_module_level=True)

_PRELUDE = textwrap.dedent(
    """
    import functools, json, os, sys
    CALLS = []

    def _wrap(name):
        real = getattr(os, name)

        @functools.wraps(real)
        def spy(*args, **kwargs):
            CALLS.append((name, any(k.endswith("dir_fd") and v is not None for k, v in kwargs.items())))
            return real(*args, **kwargs)

        setattr(os, name, spy)

    for _name in ("open", "stat", "lstat", "mkdir", "rename", "unlink", "rmdir",
                  "readlink", "symlink", "chmod", "listdir", "scandir"):
        _wrap(_name)

    sys.path.insert(0, os.getcwd())
    from tests import ensure_test_package
    ensure_test_package()
    """
)


def _run(tmp_path: Path, body: str) -> dict:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("HERMES")}
    env.update(HOME=str(home), TMPDIR=str(tmp_path), PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, "-B", "-c", _PRELUDE + textwrap.dedent(body)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_toolchk_keeps_the_handle_path_when_os_open_is_wrapped(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    out = _run(
        tmp_path,
        f"""
        import hermes_plugins.defuzz.toolchk as mod
        assert os.open is not getattr(__import__("posix"), "open")
        flag = mod._DIR_FD_OK
        CALLS.clear()
        mod.write_inside_nofollow({str(project / '.adopt')!r}, "preflight.json", b"{{}}")
        print(json.dumps({{"flag": flag, "calls": CALLS}}))
        """,
    )
    assert out["flag"] is True
    # The handle path opens the inner folder and the temporary file relative to a folder handle and
    # renames relative to it; the lstat fallback never passes a dir_fd.
    assert ["open", True] in out["calls"], out["calls"]
    assert ["rename", True] in out["calls"], out["calls"]
    assert (project / ".adopt" / "preflight.json").read_bytes() == b"{}"


def test_kit_scaffold_stages_through_a_folder_handle_when_os_open_is_wrapped(tmp_path: Path) -> None:
    target = tmp_path / "projects"
    target.mkdir()
    out = _run(
        tmp_path,
        f"""
        import hermes_plugins.defuzz.kit_scaffold as mod
        flag = mod._HANDLES_SUPPORTED
        CALLS.clear()
        path, stage = mod._make_kit_stage(__import__("pathlib").Path({str(target)!r}))
        print(json.dumps({{"flag": flag, "pinned": stage is not None, "path": str(path), "calls": CALLS}}))
        """,
    )
    assert out["flag"] is True
    assert out["pinned"] is True, "staging fell back to an unpinned temporary folder"
    assert ["mkdir", True] in out["calls"], out["calls"]
    assert Path(out["path"]).is_dir()


def test_audit_fingerprint_flag_survives_a_wrapped_os_open(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        """
        import hermes_plugins.defuzz.audit.fingerprint as mod
        mod._require_containment_support()
        print(json.dumps({"flag": mod._SUPPORTS_OPEN_DIR_FD}))
        """,
    )
    assert out["flag"] is True
