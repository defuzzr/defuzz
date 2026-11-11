"""A running template check can be stopped: cancel and timeout stop its whole process tree.

`accept` also reports its phases ('prepare', 'check', 'move', 'register') through `progress`.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError, ScaffoldTimeout, accept, propose  # noqa: E402
from hermes_plugins.defuzz.templates import CheckSpec, RepoSpec, TemplateSpec  # noqa: E402

POSIX = pytest.mark.skipif(os.name == "nt", reason="process groups are POSIX")


def _tree_cmd(pid_file: Path) -> list[str]:
    """A check that starts a grandchild, records its pid, then waits for a long time."""
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "time.sleep(60)\n"
    )
    return [sys.executable, "-c", code]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie waiting for its parent counts as stopped
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            return fh.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return True


def _wait_gone(pid: int, limit: float = 5.0) -> bool:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _wait_file(path: Path, limit: float = 10.0) -> int:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if path.is_file() and path.read_text(encoding="utf-8").strip():
            return int(path.read_text(encoding="utf-8"))
        time.sleep(0.02)
    raise AssertionError("the check did not start")


def _template(tmp_path: Path, cmd: list[str] | None) -> TemplateSpec:
    root = tmp_path / "tpl"
    repo = root / "tmpl_prefix"
    repo.mkdir(parents=True)
    (repo / "README.md").write_text("tmpl_prefix\n", encoding="utf-8")
    check = CheckSpec(cmd=tuple(cmd)) if cmd else None
    return TemplateSpec(
        id="mini", name="Mini", summary="Minimal template.", kind="lib", layout="mono",
        languages=("python",), engine=None, tags=(), needs=(), placeholder="tmpl_prefix",
        substitute_in=("**/*.md",), repos=(RepoSpec(name="tmpl_prefix", check=check),), root=root,
    )


def _propose(tmp_path: Path, cmd: list[str] | None):
    projects = tmp_path / "projects"
    projects.mkdir(parents=True)
    proposal = propose(_template(tmp_path, cmd), "Demo", {}, dest_root=projects,
                       staging_parent=tmp_path / "stage", db_path=tmp_path / "s.db")
    return projects, proposal


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "p1"})


@POSIX
def test_cancel_stops_the_running_check_and_its_children(tmp_path, monkeypatch):
    monkeypatch.setattr(scaffolder.toolchk, "require", lambda *a, **k: None)
    pid_file = tmp_path / "grandchild.pid"
    projects, proposal = _propose(tmp_path, _tree_cmd(pid_file))
    cancel = threading.Event()
    phases: list[str] = []

    def cancel_when_started() -> None:
        _wait_file(pid_file)
        cancel.set()

    threading.Thread(target=cancel_when_started, daemon=True).start()
    start = time.monotonic()
    with pytest.raises(ScaffoldError) as caught:
        accept(proposal, register=_register, db_path=tmp_path / "s.db", timeout_s=120,
               cancel=cancel, progress=phases.append)
    assert time.monotonic() - start < 15.0
    assert caught.value.cancelled is True and caught.value.keep_staging is True
    assert getattr(caught.value, "created_dirs", []) == []
    grandchild = int(pid_file.read_text(encoding="utf-8"))
    assert _wait_gone(grandchild), "the check's child process was left running"
    assert phases == ["prepare", "check"]
    assert list(projects.iterdir()) == []
    assert proposal.repos[0].staged.is_dir()


@POSIX
def test_timeout_stops_the_check_and_its_children(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    with pytest.raises(scaffolder.subprocess.TimeoutExpired):
        scaffolder._run_check_command(_tree_cmd(pid_file), cwd=str(tmp_path), env=dict(os.environ),
                                      timeout=1.5, cancel=None)
    assert _wait_gone(_wait_file(pid_file))


@POSIX
def test_an_interrupt_while_waiting_stops_the_check(tmp_path):
    pid_file = tmp_path / "grandchild.pid"

    def interrupt() -> bool:
        if pid_file.is_file() and pid_file.read_text(encoding="utf-8").strip():
            raise KeyboardInterrupt  # what Ctrl-C does to the waiting main thread
        return False

    with pytest.raises(KeyboardInterrupt):
        scaffolder._run_check_command(_tree_cmd(pid_file), cwd=str(tmp_path), env=dict(os.environ),
                                      timeout=60, cancel=interrupt)
    assert _wait_gone(_wait_file(pid_file))


def test_output_and_returncode_pass_through(tmp_path):
    argv = [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"]
    done = scaffolder._run_check_command(argv, cwd=str(tmp_path), env=dict(os.environ), timeout=30.0, cancel=None)
    assert (done.args, done.returncode, done.stdout, done.stderr) == (argv, 3, "out\n", "err\n")


def test_phases_on_success_and_timeout_message(tmp_path, monkeypatch):
    monkeypatch.setattr(scaffolder.toolchk, "require", lambda *a, **k: None)
    projects, proposal = _propose(tmp_path, [sys.executable, "-c", "print('ok')"])
    phases: list[str] = []
    accept(proposal, register=_register, db_path=tmp_path / "s.db", progress=phases.append)
    assert phases == ["prepare", "check", "move", "register"]
    assert (projects / "demo" / ".git").is_dir()

    _, slow = _propose(tmp_path / "b", [sys.executable, "-c", "import time; print('waiting', flush=True); time.sleep(30)"])
    with pytest.raises(ScaffoldTimeout) as caught:
        accept(slow, register=_register, db_path=tmp_path / "s2.db", timeout_s=2.0)
    assert "timed out" in str(caught.value) and "waiting" in caught.value.output


def test_a_failing_progress_hook_does_not_stop_the_accept(tmp_path):
    projects, proposal = _propose(tmp_path, None)

    def broken(_phase: str) -> None:
        raise RuntimeError("hook")

    accept(proposal, register=_register, db_path=tmp_path / "s.db", progress=broken)
    assert (projects / "demo").is_dir()

